using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using SharpSocks;

namespace SharpSocks.Agent
{
    public class Entry
    {
        static string _serverHost;
        static int _serverPort = 443;
        static string _password;
        static string _transport = "raw";
        static string _tlsFingerprint;
        static int _retryDelay = 5;
        static int _maxRetries = 5;
        static bool _verbose;

        static volatile TcpClient _serverClient;
        static volatile Stream _serverStream;
        static byte[] _sessionKey;
        static readonly object _writeLock = new object();
        static readonly ConcurrentDictionary<int, TunnelChannel> _channels =
            new ConcurrentDictionary<int, TunnelChannel>();
        static volatile bool _running = true;
        static bool _handlersRegistered;

        static void LogV(string msg)
        {
            if (_verbose)
                Console.WriteLine(msg);
        }

        public static void Execute(string[] args)
        {
            Run(args);
        }

        public static void Main(string[] args)
        {
            Run(args);
        }

        public static void Stop()
        {
            if (!_running) return;
            _running = false;
            try { _serverClient.Close(); } catch { }
            foreach (var kvp in _channels)
                try { kvp.Value.Target.Close(); } catch { }
        }

        static void Run(string[] args)
        {
            _running = true;
            _serverClient = null;
            _serverStream = null;
            _sessionKey = null;
            _channels.Clear();

            if (!ParseArgs(args))
                return;

            if (!_handlersRegistered)
            {
                Console.CancelKeyPress += delegate { Stop(); };
                AppDomain.CurrentDomain.ProcessExit += delegate { Stop(); };
                _handlersRegistered = true;
            }

            Console.WriteLine("SharpSocks agent");
            Console.WriteLine("server: " + _serverHost + ":" + _serverPort + " (" + _transport + ")");

            int attempts = 0;
            while (_running)
            {
                try
                {
                    ConnectAndRun();
                    attempts = 0;
                }
                catch (Exception ex)
                {
                    if (!_running) break;
                    Console.WriteLine("connection error: " + ex.Message);
                }

                CleanupChannels();

                if (!_running) break;

                attempts++;
                if (_maxRetries > 0 && attempts >= _maxRetries)
                {
                    Console.WriteLine("max retries reached, exiting");
                    break;
                }

                int delay = Math.Min(_retryDelay * attempts, 60);
                LogV("reconnecting in " + delay + "s...");
                for (int i = 0; i < delay * 10 && _running; i++)
                    Thread.Sleep(100);
            }
        }

        static bool ValidateServerCert(object sender, X509Certificate cert,
            X509Chain chain, SslPolicyErrors errors)
        {
            if (string.IsNullOrEmpty(_tlsFingerprint))
                return true;

            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(cert.GetRawCertData());
                string fp = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                string expected = _tlsFingerprint.Replace(":", "").Replace("-", "").ToLowerInvariant();
                return fp == expected;
            }
        }

        static void ConnectAndRun()
        {
            LogV("connecting to server...");

            _serverClient = new TcpClient();
            _serverClient.NoDelay = true;
            _serverClient.ReceiveBufferSize = Protocol.BufferSize;
            _serverClient.SendBufferSize = Protocol.BufferSize;
            _serverClient.Connect(_serverHost, _serverPort);

            Stream stream = _serverClient.GetStream();

            if (_transport == "tls")
            {
                var sslStream = new SslStream(stream, false, ValidateServerCert);
                sslStream.AuthenticateAsClient(_serverHost, null,
                    System.Security.Authentication.SslProtocols.Tls12, false);
                stream = sslStream;
                LogV("tls established");
            }

            _serverStream = stream;

            Console.WriteLine("connected to " + _serverClient.Client.RemoteEndPoint);

            if (!DoClientAuth())
            {
                Console.WriteLine("authentication failed");
                _serverClient.Close();
                return;
            }

            Console.WriteLine("authenticated");

            ServerReaderLoop();
        }

        static bool DoClientAuth()
        {
            try
            {
                Frame challenge = Protocol.ReadFrame(_serverStream);
                if (challenge.Type != FrameType.AuthChallenge)
                    return false;

                byte[] serverNonce = challenge.Payload;
                if (serverNonce.Length != Protocol.NonceSize)
                    return false;

                byte[] clientNonce = Protocol.GenerateNonce();

                byte[] combinedNonces = new byte[Protocol.NonceSize * 2];
                Buffer.BlockCopy(serverNonce, 0, combinedNonces, 0, Protocol.NonceSize);
                Buffer.BlockCopy(clientNonce, 0, combinedNonces, Protocol.NonceSize, Protocol.NonceSize);

                byte[] hmac = Protocol.ComputeHmac(
                    Encoding.UTF8.GetBytes(_password), combinedNonces);

                byte[] payload = new byte[Protocol.NonceSize + 32];
                Buffer.BlockCopy(clientNonce, 0, payload, 0, Protocol.NonceSize);
                Buffer.BlockCopy(hmac, 0, payload, Protocol.NonceSize, 32);

                Protocol.WriteFrame(_serverStream, new Frame(FrameType.AuthResponse, 0, payload));

                Frame result = Protocol.ReadFrame(_serverStream);
                if (result.Type != FrameType.AuthSuccess)
                    return false;

                _sessionKey = Protocol.DeriveKey(_password, serverNonce, clientNonce);
                return true;
            }
            catch (Exception ex)
            {
                LogV("auth error: " + ex.Message);
                return false;
            }
        }

        static void ServerReaderLoop()
        {
            try
            {
                while (_running)
                {
                    Frame frame = Protocol.ReadFrame(_serverStream, _sessionKey);

                    switch (frame.Type)
                    {
                        case FrameType.ChannelOpen:
                            HandleChannelOpen(frame);
                            break;

                        case FrameType.ChannelData:
                            HandleChannelData(frame);
                            break;

                        case FrameType.ChannelClose:
                            HandleChannelClose(frame);
                            break;

                        case FrameType.Keepalive:
                            SendToServer(new Frame(FrameType.KeepaliveAck, 0));
                            break;

                        case FrameType.KeepaliveAck:
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                if (_running)
                    LogV("server connection lost: " + ex.Message);
            }
        }

        static void HandleChannelOpen(Frame frame)
        {
            string host;
            int port;
            if (!Protocol.DecodeTarget(frame.Payload, out host, out port))
            {
                SendToServer(new Frame(FrameType.ChannelOpenFail, frame.ChannelId));
                return;
            }

            int channelId = frame.ChannelId;

            var t = new Thread(() => DoChannelConnect(channelId, host, port))
            {
                IsBackground = true,
                Name = "Tunnel-" + channelId
            };
            t.Start();
        }

        static void DoChannelConnect(int channelId, string host, int port)
        {
            TcpClient target = null;
            bool openAcked = false;
            try
            {
                target = new TcpClient();
                target.NoDelay = true;
                target.ReceiveBufferSize = Protocol.BufferSize;
                target.SendBufferSize = Protocol.BufferSize;

                var result = target.BeginConnect(host, port, null, null);
                bool connected = result.AsyncWaitHandle.WaitOne(15000);

                if (!connected || !target.Connected)
                {
                    LogV("channel " + channelId + " connect timeout -> " + host + ":" + port);
                    SendToServer(new Frame(FrameType.ChannelOpenFail, channelId));
                    try { target.Close(); } catch { }
                    return;
                }

                target.EndConnect(result);

                var channel = new TunnelChannel
                {
                    Id = channelId,
                    Target = target,
                    TargetStream = target.GetStream()
                };
                _channels[channelId] = channel;

                LogV("channel " + channelId + " connected -> " + host + ":" + port);
                SendToServer(new Frame(FrameType.ChannelOpenOk, channelId));
                openAcked = true;

                byte[] buf = new byte[Protocol.BufferSize];
                while (channel.Active && _running)
                {
                    int n = channel.TargetStream.Read(buf, 0, buf.Length);
                    if (n == 0) break;

                    byte[] data = new byte[n];
                    Buffer.BlockCopy(buf, 0, data, 0, n);
                    SendToServer(new Frame(FrameType.ChannelData, channelId, data));
                }
            }
            catch (Exception ex)
            {
                if (!openAcked)
                {
                    LogV("channel " + channelId + " connect failed: " + ex.Message);
                    try { SendToServer(new Frame(FrameType.ChannelOpenFail, channelId)); } catch { }
                }
            }
            finally
            {
                TunnelChannel ch;
                if (_channels.TryRemove(channelId, out ch))
                {
                    ch.Active = false;
                    try { ch.Target.Close(); } catch { }
                }
                else if (target != null)
                {
                    try { target.Close(); } catch { }
                }
                if (openAcked)
                    try { SendToServer(new Frame(FrameType.ChannelClose, channelId)); } catch { }
            }
        }

        static void HandleChannelData(Frame frame)
        {
            TunnelChannel ch;
            if (!_channels.TryGetValue(frame.ChannelId, out ch))
                return;

            if (!ch.Active) return;

            try
            {
                ch.TargetStream.Write(frame.Payload, 0, frame.Payload.Length);
                ch.TargetStream.Flush();
            }
            catch
            {
                CloseChannel(ch);
            }
        }

        static void HandleChannelClose(Frame frame)
        {
            TunnelChannel ch;
            if (!_channels.TryRemove(frame.ChannelId, out ch))
                return;
            ch.Active = false;
            try { ch.Target.Close(); } catch { }
        }

        static void SendToServer(Frame frame)
        {
            var stream = _serverStream;
            if (stream == null) return;
            Protocol.WriteFrame(stream, frame, _sessionKey, _writeLock);
        }

        static void CloseChannel(TunnelChannel ch)
        {
            ch.Active = false;
            try { ch.Target.Close(); } catch { }
            TunnelChannel removed;
            _channels.TryRemove(ch.Id, out removed);
        }

        static void CleanupChannels()
        {
            foreach (var kvp in _channels)
            {
                kvp.Value.Active = false;
                try { kvp.Value.Target.Close(); } catch { }
            }
            _channels.Clear();

            try { _serverClient.Close(); } catch { }
            _serverClient = null;
            _serverStream = null;
            _sessionKey = null;
        }

        static string NextArg(string[] args, ref int i)
        {
            if (++i >= args.Length)
                throw new ArgumentException(args[i - 1] + " requires a value");
            return args[i];
        }

        static bool ParseArgs(string[] args)
        {
            try
            {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--server":          _serverHost     = NextArg(args, ref i); break;
                    case "--port":            _serverPort     = int.Parse(NextArg(args, ref i)); break;
                    case "--agent-password":  _password       = NextArg(args, ref i); break;
                    case "--transport":       _transport      = NextArg(args, ref i); break;
                    case "--tls-fingerprint": _tlsFingerprint = NextArg(args, ref i); break;
                    case "--retry":           _retryDelay     = int.Parse(NextArg(args, ref i)); break;
                    case "--max-retries":     _maxRetries     = int.Parse(NextArg(args, ref i)); break;
                    case "--verbose":         _verbose        = true; break;
                    case "--help": case "-h":
                        PrintUsage();
                        return false;
                }
            }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return false;
            }

            if (string.IsNullOrEmpty(_serverHost) || string.IsNullOrEmpty(_password))
            {
                Console.Error.WriteLine("--server and --agent-password are required");
                PrintUsage();
                return false;
            }

            if (_transport != "raw" && _transport != "tls")
            {
                Console.Error.WriteLine("--transport must be raw or tls");
                return false;
            }

            return true;
        }

        static void PrintUsage()
        {
            string name = System.Reflection.Assembly.GetExecutingAssembly().GetName().Name;
            Console.WriteLine("usage: " + name + " [options]");
            Console.WriteLine("  --server <host>            server address (required)");
            Console.WriteLine("  --port <port>              server port (default: 443)");
            Console.WriteLine("  --agent-password <pass>    pre-shared password (required, must match server)");
            Console.WriteLine("  --transport <raw|tls>      transport mode (default: raw)");
            Console.WriteLine("  --tls-fingerprint <sha256> pin server cert by sha256 fingerprint (optional)");
            Console.WriteLine("  --retry <seconds>          base retry delay (default: 5)");
            Console.WriteLine("  --max-retries <n>          max reconnect attempts, 0=infinite (default: 5)");
            Console.WriteLine("  --verbose                  enable verbose logging");
        }
    }

    class TunnelChannel
    {
        public int Id;
        public TcpClient Target;
        public NetworkStream TargetStream;
        public volatile bool Active = true;
    }
}
