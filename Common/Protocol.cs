using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SharpSocks
{
    public enum FrameType : byte
    {
        AuthChallenge   = 0x01,
        AuthResponse    = 0x02,
        AuthSuccess     = 0x03,
        AuthFailure     = 0x04,
        ChannelOpen     = 0x10,
        ChannelOpenOk   = 0x11,
        ChannelOpenFail = 0x12,
        ChannelData     = 0x20,
        ChannelClose    = 0x21,
        Keepalive       = 0x30,
        KeepaliveAck    = 0x31
    }

    public class Frame
    {
        public FrameType Type;
        public int ChannelId;
        public byte[] Payload;

        public Frame() { }

        public Frame(FrameType type, int channelId, byte[] payload = null)
        {
            Type = type;
            ChannelId = channelId;
            Payload = payload ?? new byte[0];
        }
    }

    public static class Protocol
    {
        public const int HeaderSize = 9;
        public const int MaxPayloadSize = 1 * 1024 * 1024;
        public const int NonceSize = 32;
        public const int KeySize = 32;          // AES-256 key
        public const int MacSize = 32;          // HMAC-SHA256 tag
        public const int SessionKeySize = 64;   // 32 enc + 32 mac
        public const int IvSize = 16;
        public const int Pbkdf2Iterations = 10000;
        public const int BufferSize = 65536;

        public static void ReadExact(Stream stream, byte[] buffer, int offset, int count)
        {
            int total = 0;
            while (total < count)
            {
                int n = stream.Read(buffer, offset + total, count - total);
                if (n == 0)
                    throw new IOException("Connection closed by remote");
                total += n;
            }
        }

        public static Frame ReadFrame(Stream stream, byte[] sessionKey = null)
        {
            byte[] hdr = new byte[HeaderSize];
            ReadExact(stream, hdr, 0, HeaderSize);

            var f = new Frame();
            f.Type = (FrameType)hdr[0];
            f.ChannelId = ReadInt32BE(hdr, 1);
            int len = ReadInt32BE(hdr, 5);

            if (len < 0 || len > MaxPayloadSize)
                throw new InvalidDataException("Payload size out of range: " + len);

            if (sessionKey != null && len == 0)
                throw new CryptographicException("Received unprotected frame on encrypted channel");

            f.Payload = new byte[len];
            if (len > 0)
            {
                ReadExact(stream, f.Payload, 0, len);
                if (sessionKey != null)
                {
                    if (len < IvSize + 16 + MacSize)
                        throw new CryptographicException("Encrypted payload too short");

                    byte[] encKey = new byte[KeySize];
                    byte[] macKey = new byte[KeySize];
                    Buffer.BlockCopy(sessionKey, 0, encKey, 0, KeySize);
                    Buffer.BlockCopy(sessionKey, KeySize, macKey, 0, KeySize);

                    int encLen = len - MacSize;

                    // Verify: HMAC(macKey, header || IV || ciphertext)
                    byte[] receivedMac = new byte[MacSize];
                    Buffer.BlockCopy(f.Payload, encLen, receivedMac, 0, MacSize);

                    byte[] macInput = new byte[HeaderSize + encLen];
                    Buffer.BlockCopy(hdr, 0, macInput, 0, HeaderSize);
                    Buffer.BlockCopy(f.Payload, 0, macInput, HeaderSize, encLen);
                    byte[] expectedMac = ComputeHmac(macKey, macInput);

                    if (!ConstantTimeEquals(receivedMac, expectedMac))
                        throw new CryptographicException("Frame authentication failed");

                    // Decrypt AES-CBC
                    byte[] encrypted = new byte[encLen];
                    Buffer.BlockCopy(f.Payload, 0, encrypted, 0, encLen);
                    f.Payload = AesCbcDecrypt(encrypted, encKey);
                }
            }

            return f;
        }

        public static void WriteFrame(Stream stream, Frame frame, byte[] sessionKey = null, object writeLock = null)
        {
            byte[] payload = frame.Payload ?? new byte[0];
            byte[] packet;

            if (sessionKey != null)
            {
                byte[] encKey = new byte[KeySize];
                byte[] macKey = new byte[KeySize];
                Buffer.BlockCopy(sessionKey, 0, encKey, 0, KeySize);
                Buffer.BlockCopy(sessionKey, KeySize, macKey, 0, KeySize);

                // AES-CBC encrypt → IV || ciphertext
                byte[] encrypted = AesCbcEncrypt(payload, encKey);

                // Build header with final payload length (encrypted + MAC)
                byte[] hdr = new byte[HeaderSize];
                hdr[0] = (byte)frame.Type;
                WriteInt32BE(hdr, 1, frame.ChannelId);
                WriteInt32BE(hdr, 5, encrypted.Length + MacSize);

                // MAC covers header || IV || ciphertext (Encrypt-then-MAC with AAD)
                byte[] macInput = new byte[HeaderSize + encrypted.Length];
                Buffer.BlockCopy(hdr, 0, macInput, 0, HeaderSize);
                Buffer.BlockCopy(encrypted, 0, macInput, HeaderSize, encrypted.Length);
                byte[] mac = ComputeHmac(macKey, macInput);

                // Assemble: header || encrypted || MAC
                packet = new byte[HeaderSize + encrypted.Length + MacSize];
                Buffer.BlockCopy(hdr, 0, packet, 0, HeaderSize);
                Buffer.BlockCopy(encrypted, 0, packet, HeaderSize, encrypted.Length);
                Buffer.BlockCopy(mac, 0, packet, HeaderSize + encrypted.Length, MacSize);
            }
            else
            {
                // Plaintext (auth handshake or empty payload)
                packet = new byte[HeaderSize + payload.Length];
                packet[0] = (byte)frame.Type;
                WriteInt32BE(packet, 1, frame.ChannelId);
                WriteInt32BE(packet, 5, payload.Length);
                if (payload.Length > 0)
                    Buffer.BlockCopy(payload, 0, packet, HeaderSize, payload.Length);
            }

            if (writeLock != null)
            {
                lock (writeLock)
                {
                    stream.Write(packet, 0, packet.Length);
                    stream.Flush();
                }
            }
            else
            {
                stream.Write(packet, 0, packet.Length);
                stream.Flush();
            }
        }

        public static int ReadInt32BE(byte[] buf, int offset)
        {
            return (buf[offset] << 24) | (buf[offset + 1] << 16) |
                   (buf[offset + 2] << 8) | buf[offset + 3];
        }

        public static void WriteInt32BE(byte[] buf, int offset, int value)
        {
            buf[offset]     = (byte)(value >> 24);
            buf[offset + 1] = (byte)(value >> 16);
            buf[offset + 2] = (byte)(value >> 8);
            buf[offset + 3] = (byte)value;
        }

        public static byte[] GenerateNonce()
        {
            byte[] nonce = new byte[NonceSize];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(nonce);
            return nonce;
        }

        public static byte[] ComputeHmac(byte[] key, byte[] data)
        {
            using (var hmac = new HMACSHA256(key))
                return hmac.ComputeHash(data);
        }

        // Returns 64-byte session key: first 32 = AES enc key, last 32 = HMAC mac key
        public static byte[] DeriveKey(string password, byte[] serverNonce, byte[] clientNonce)
        {
            byte[] salt = new byte[serverNonce.Length + clientNonce.Length];
            Buffer.BlockCopy(serverNonce, 0, salt, 0, serverNonce.Length);
            Buffer.BlockCopy(clientNonce, 0, salt, serverNonce.Length, clientNonce.Length);

            return Pbkdf2Sha256(Encoding.UTF8.GetBytes(password), salt, Pbkdf2Iterations, SessionKeySize);
        }

        // PBKDF2-HMAC-SHA256 — .NET 4.5.2's Rfc2898DeriveBytes only supports SHA1
        public static byte[] Pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int keyLength)
        {
            int hashLen = 32;
            int blockCount = (keyLength + hashLen - 1) / hashLen;
            byte[] result = new byte[blockCount * hashLen];

            for (int block = 1; block <= blockCount; block++)
            {
                byte[] intBlock = new byte[4];
                WriteInt32BE(intBlock, 0, block);

                byte[] hmacInput = new byte[salt.Length + 4];
                Buffer.BlockCopy(salt, 0, hmacInput, 0, salt.Length);
                Buffer.BlockCopy(intBlock, 0, hmacInput, salt.Length, 4);

                byte[] u = ComputeHmac(password, hmacInput);
                byte[] t = (byte[])u.Clone();

                for (int i = 1; i < iterations; i++)
                {
                    u = ComputeHmac(password, u);
                    for (int j = 0; j < t.Length; j++)
                        t[j] ^= u[j];
                }

                Buffer.BlockCopy(t, 0, result, (block - 1) * hashLen, hashLen);
            }

            byte[] output = new byte[keyLength];
            Buffer.BlockCopy(result, 0, output, 0, keyLength);
            return output;
        }

        public static byte[] AesCbcEncrypt(byte[] data, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                byte[] encrypted;
                using (var enc = aes.CreateEncryptor())
                    encrypted = enc.TransformFinalBlock(data, 0, data.Length);

                byte[] result = new byte[IvSize + encrypted.Length];
                Buffer.BlockCopy(aes.IV, 0, result, 0, IvSize);
                Buffer.BlockCopy(encrypted, 0, result, IvSize, encrypted.Length);
                return result;
            }
        }

        public static byte[] AesCbcDecrypt(byte[] data, byte[] key)
        {
            if (data.Length < IvSize + 16)
                throw new CryptographicException("Ciphertext too short");

            byte[] iv = new byte[IvSize];
            Buffer.BlockCopy(data, 0, iv, 0, IvSize);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var dec = aes.CreateDecryptor())
                    return dec.TransformFinalBlock(data, IvSize, data.Length - IvSize);
            }
        }

        public static byte[] EncodeTarget(string host, int port)
        {
            return Encoding.UTF8.GetBytes(host + ":" + port);
        }

        public static bool DecodeTarget(byte[] data, out string host, out int port)
        {
            host = null;
            port = 0;
            string s = Encoding.UTF8.GetString(data);
            int idx = s.LastIndexOf(':');
            if (idx < 0) return false;
            host = s.Substring(0, idx);
            if (host.Length == 0) return false;
            if (!int.TryParse(s.Substring(idx + 1), out port)) return false;
            return port >= 1 && port <= 65535;
        }

        public static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
