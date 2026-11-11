"""
Probe the ps4debug brand string via raw TCP.
Wire format per debugger.rs:
  send: magic(4LE) + cmd(4LE) + bodylen(4LE) [+ body]
  recv status: 4LE uint32
  recv text: 4LE length, then <length> bytes
"""
import os
import socket
import struct
import sys

MAGIC = 0xFFAABBCC
CMD_VERSION = 0xBD000001
CMD_BRAND   = 0xBD000501
SUCCESS     = 0x80000000

HOST = os.environ.get("PS4_HOST", "192.168.86.29")
PORT = 744
TIMEOUT = 10

def send_packet(sock, cmd, body=b""):
    hdr = struct.pack("<III", MAGIC, cmd, len(body))
    sock.sendall(hdr + body)

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf

def recv_status(sock):
    raw = recv_exact(sock, 4)
    code = struct.unpack("<I", raw)[0]
    return code

def recv_text(sock):
    raw = recv_exact(sock, 4)
    length = struct.unpack("<I", raw)[0]
    if not (1 <= length <= 4096):
        raise ValueError(f"Implausible text length: {length}")
    data = recv_exact(sock, length)
    return data

def main():
    print(f"Connecting to {HOST}:{PORT}...")
    with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as sock:
        print("Connected.")

        # CMD_VERSION and CMD_BRAND respond with length-prefixed text only (no status prefix)
        # --- CMD_VERSION ---
        send_packet(sock, CMD_VERSION)
        version_bytes = recv_text(sock)
        version = version_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")
        print(f"Protocol version : {version!r}")

        # --- CMD_BRAND (0xBD000501) ---
        send_packet(sock, CMD_BRAND)
        brand_bytes = recv_text(sock)
        print(f"Brand raw bytes  : {brand_bytes!r}")
        parts = brand_bytes.split(b"\x00")
        brand = parts[0].decode("utf-8", errors="replace")
        capability = parts[1].decode("utf-8", errors="replace") if len(parts) > 1 else ""
        print(f"Brand            : {brand!r}")
        print(f"Capability       : {capability!r}")

        # --- CMD_FIRMWARE (0xBD000500): 2-byte LE u16 ---
        send_packet(sock, 0xBD000500)
        fw_raw = recv_exact(sock, 2)
        fw_enc = struct.unpack("<H", fw_raw)[0]
        fw_str = f"{fw_enc // 100}.{fw_enc % 100:02d}"
        print(f"Firmware encoded : {fw_enc} → {fw_str!r}")

        # --- CMD_PLATFORM (0xBD000502): 2-byte LE u16 ---
        send_packet(sock, 0xBD000502)
        plat_raw = recv_exact(sock, 2)
        platform = struct.unpack("<H", plat_raw)[0]
        print(f"Platform         : {platform} (4=PS4)")

if __name__ == "__main__":
    main()
