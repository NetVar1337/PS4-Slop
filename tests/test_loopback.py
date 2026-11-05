import contextlib
import json
import socket
import socketserver
import struct
import subprocess
import sys
import threading

from .support import ROOT, WorkbenchCase


def receive_exact(connection, length):
    content = bytearray()
    while len(content) < length:
        chunk = connection.recv(length - len(content))
        if not chunk:
            raise EOFError
        content.extend(chunk)
    return bytes(content)


@contextlib.contextmanager
def local_server(handler):
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        block_on_close = False

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            handler(self.request)

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class LoopbackTests(WorkbenchCase):
    def test_real_tcp_debugger_handshake_and_reads(self):
        seen = []
        failures = []

        def handle(connection):
            try:
                while True:
                    magic, command, length = struct.unpack("<III", receive_exact(connection, 12))
                    if magic != 0xFFAABBCC:
                        raise AssertionError("Bad packet magic")
                    body = receive_exact(connection, length)
                    seen.append((command, body))
                    if command == 0xBD000001:
                        response = b"\x03\x00\x00\x001.3"
                    elif command == 0xBD000501:
                        brand = b"ps4debug-NG by Pharaoh2k v1.3.4\x001.1"
                        response = struct.pack("<I", len(brand)) + brand
                    elif command == 0xBD000500:
                        response = b"\x78\x05"
                    elif command == 0xBD000502:
                        response = b"\x04\x00"
                    elif command == 0xBDAA0001:
                        response = b"\x00\x00\x00\x80" + struct.pack("<I32sI", 1, b"sample", 71)
                    elif command == 0xBDAA0002:
                        if body != struct.pack("<IQI", 71, 0x4000, 4):
                            raise AssertionError("Bad packed memory request")
                        response = b"\x00\x00\x00\x80test"
                    else:
                        raise AssertionError("Unexpected command")
                    for offset in range(0, len(response), 3):
                        connection.sendall(response[offset:offset + 3])
            except EOFError:
                pass
            except Exception as error:
                failures.append(error)

        with local_server(handle) as port:
            self.settings["ports"]["debug"] = port
            self.reload()
            try:
                self.assertEqual(self.workbench.debugger.processes(), [{"pid": 71, "name": "sample"}])
                self.assertEqual(self.workbench.debugger.read_memory(71, 0x4000, 4), b"test")
            finally:
                self.workbench.close()
        self.assertFalse(failures)
        self.assertEqual([command for command, _ in seen], [0xBD000001, 0xBD000501, 0xBD000500, 0xBD000502, 0xBDAA0001, 0xBDAA0002])

    def test_real_tcp_klog_capture_saves_raw_bytes(self):
        def handle(connection):
            connection.sendall(b"kernel log\n\xffbinary\n")

        with local_server(handle) as port:
            self.settings["ports"]["klog"] = port
            self.reload()
            result = self.workbench.console.capture_logs(1)
        self.assertEqual(self.workbench.store.read(result["path"]), b"kernel log\n\xffbinary\n")
        self.assertEqual(result["metadata"]["stop_reason"], "eof")

    def test_real_ftp_login_list_retr_and_verified_stor(self):
        files = {"/data/source": b"sample"}
        seen = []
        failures = []

        def handle(connection):
            passive = None
            stream = connection.makefile("rb")
            try:
                connection.sendall(b"220 Test FTP\r\n")
                while True:
                    line = stream.readline()
                    if not line:
                        break
                    command = line.decode().rstrip("\r\n")
                    seen.append(command)
                    verb, _, argument = command.partition(" ")
                    if verb == "USER":
                        connection.sendall(b"331 Password required\r\n")
                    elif verb == "PASS":
                        connection.sendall(b"230 Logged in\r\n")
                    elif verb == "TYPE":
                        connection.sendall(b"200 Type set\r\n")
                    elif verb == "PASV":
                        passive = socket.socket()
                        passive.bind(("127.0.0.1", 0))
                        passive.listen(1)
                        passive.settimeout(3)
                        port = passive.getsockname()[1]
                        connection.sendall(f"227 Entering Passive Mode (127,0,0,1,{port // 256},{port % 256})\r\n".encode())
                    elif verb in ("LIST", "RETR", "STOR"):
                        connection.sendall(b"150 Data connection\r\n")
                        data, _ = passive.accept()
                        data.settimeout(3)
                        with data:
                            if verb == "LIST":
                                data.sendall(b"-rw-r--r-- 1 root wheel 6 Jan 1 00:00 source\r\n")
                            elif verb == "RETR":
                                data.sendall(files[argument])
                            else:
                                output = bytearray()
                                while True:
                                    chunk = data.recv(8192)
                                    if not chunk:
                                        break
                                    output.extend(chunk)
                                files[argument] = bytes(output)
                        passive.close()
                        passive = None
                        connection.sendall(b"226 Transfer complete\r\n")
                    else:
                        connection.sendall(b"500 Unsupported\r\n")
            except Exception as error:
                failures.append(error)
            finally:
                stream.close()
                if passive:
                    passive.close()

        with local_server(handle) as port:
            self.settings["ports"]["ftp"] = port
            self.qualify("ftp_upload")
            listing = self.workbench.console.ftp_list("/data")
            self.assertEqual(len(listing["listing"]), 1)
            artifact = self.workbench.console.ftp_download("/data/source")
            self.assertEqual(self.workbench.store.read(artifact["path"]), b"sample")
            result = self.workbench.console.ftp_upload(artifact["path"], "/data/ps4-debugmcps/sample", artifact["sha256"])
            self.assertTrue(result["readback_verified"])
        self.assertFalse(failures)
        self.assertEqual(files["/data/ps4-debugmcps/sample"], b"sample")
        self.assertIn("STOR /data/ps4-debugmcps/sample", seen)

    def test_subprocess_mcp_stdio_end_to_end(self):
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "console_status", "arguments": {}}}
        ]
        process = subprocess.run([sys.executable, "-m", "ps4_workbench", "--profile", str(self.profile_path), "serve"],
                                 input="".join(json.dumps(message) + "\n" for message in messages),
                                 capture_output=True, text=True, cwd=ROOT, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, "")
        responses = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual([response["id"] for response in responses], [1, 2, 3])
        self.assertFalse(responses[2]["result"]["isError"])
        self.assertEqual(json.loads(responses[2]["result"]["content"][0]["text"])["compatibility"]["state"], "hardware_unverified")
