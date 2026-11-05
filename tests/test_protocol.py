import socket
import struct
from unittest.mock import Mock, patch

from ps4_workbench.config import WorkbenchError
from ps4_workbench.debugger import EVENT_SIZE, REGISTER_FORMAT, address_range, registers

from .support import FakeSocket, WorkbenchCase


def identity_response(firmware=1400, brand=b"ps4debug-NG by Pharaoh2k v1.3.4\x001.1", platform=4, protocol=b"1.3"):
    return struct.pack("<I", len(protocol)) + protocol + struct.pack("<I", len(brand)) + brand + struct.pack("<HH", firmware, platform)


OK = b"\x00\x00\x00\x80"


class ProtocolTests(WorkbenchCase):
    def connect(self, response, fragment=65536):
        stream = FakeSocket(response, fragment)
        mocked = patch("ps4_workbench.debugger.socket.create_connection", return_value=stream)
        mocked.start()
        self.addCleanup(mocked.stop)
        self.addCleanup(self.workbench.close)
        return stream

    def test_identity_decimal_firmware_and_exact_headers(self):
        stream = self.connect(identity_response() + OK, fragment=1)
        result = self.workbench.debugger.info()
        self.assertEqual(result["firmware"], "14.00")
        self.assertFalse(result["binary_hash_remotely_verified"])
        self.assertEqual(bytes(stream.sent), b"".join(struct.pack("<III", 0xFFAABBCC, command, 0)
                         for command in (0xBD000001, 0xBD000501, 0xBD000500, 0xBD000502, 0xBDAACC06)))

    def test_reject_documented_bcd_encoding_instead_of_guessing(self):
        stream = self.connect(identity_response(firmware=0x1400))
        with self.assertRaisesRegex(WorkbenchError, "firmware mismatch"):
            self.workbench.debugger.info()
        self.assertTrue(stream.closed)

    def test_reject_wrong_firmware(self):
        self.connect(identity_response(firmware=1202))
        with self.assertRaisesRegex(WorkbenchError, "firmware mismatch"):
            self.workbench.debugger.processes()

    def test_reject_unknown_protocol_before_extra_commands(self):
        stream = self.connect(identity_response(protocol=b"2.0"))
        with self.assertRaisesRegex(WorkbenchError, "protocol"):
            self.workbench.debugger.info()
        self.assertEqual(len(stream.sent), 12)

    def test_reject_legacy_brand(self):
        self.connect(identity_response(brand=b"ps4debug 1.3"))
        with self.assertRaisesRegex(WorkbenchError, "branding"):
            self.workbench.debugger.info()

    def test_reject_wrong_platform(self):
        self.connect(identity_response(platform=5))
        with self.assertRaisesRegex(WorkbenchError, "PS4"):
            self.workbench.debugger.info()

    def test_reject_oversized_identity(self):
        stream = self.connect(struct.pack("<I", 1048577))
        with self.assertRaisesRegex(WorkbenchError, "identity length"):
            self.workbench.debugger.info()
        self.assertTrue(stream.closed)

    def test_partial_eof_drops_connection(self):
        stream = self.connect(b"\x03\x00")
        with self.assertRaisesRegex(WorkbenchError, "disconnected"):
            self.workbench.debugger.info()
        self.assertTrue(stream.closed)

    def test_rejected_command_drops_connection(self):
        stream = self.connect(identity_response() + b"\x01\x00\x00\xf0")
        with self.assertRaisesRegex(WorkbenchError, "rejected"):
            self.workbench.debugger.processes()
        self.assertTrue(stream.closed)

    def test_process_list(self):
        self.connect(identity_response() + OK + struct.pack("<I32sI", 1, b"eboot.bin", 71), fragment=7)
        self.assertEqual(self.workbench.debugger.processes(), [{"name": "eboot.bin", "pid": 71}])

    def test_list_count_cap(self):
        stream = self.connect(identity_response() + OK + struct.pack("<I", 0xFFFFFFFF))
        with self.assertRaisesRegex(WorkbenchError, "entry count"):
            self.workbench.debugger.processes()
        self.assertTrue(stream.closed)

    def test_maps_wire_layout(self):
        self.connect(identity_response() + OK + struct.pack("<IQQQQ32s", 1, 0x4000, 0x5000, 0x1000, 5, b"module"))
        result = self.workbench.debugger.maps(71)
        self.assertEqual(result[0], {"start": 0x4000, "end": 0x5000, "offset": 0x1000, "protection": 5, "name": "module"})

    def test_memory_read_body_has_no_native_padding(self):
        stream = self.connect(identity_response() + OK + b"test")
        self.assertEqual(self.workbench.debugger.read_memory(71, 0x1122334455667788, 4), b"test")
        self.assertEqual(bytes(stream.sent[-28:]), struct.pack("<IIIIQI", 0xFFAABBCC, 0xBDAA0002, 16, 71, 0x1122334455667788, 4))

    def test_memory_bounds_before_connect(self):
        with patch("socket.create_connection") as connect:
            for length in (0, -1, self.profile.limit("memory_bytes") + 1, True):
                with self.assertRaises(WorkbenchError):
                    self.workbench.debugger.read_memory(1, 0, length)
            connect.assert_not_called()

    def test_uint64_overflow(self):
        with self.assertRaises(WorkbenchError):
            address_range(0xFFFFFFFFFFFFFFFF, 2, 2)

    def test_register_layout_matches_source_not_protocol_doc(self):
        self.assertEqual(struct.calcsize(REGISTER_FORMAT), 176)
        raw = bytearray(176)
        struct.pack_into("<Q", raw, 136, 0x1122334455667788)
        struct.pack_into("<Q", raw, 160, 0xFFEEDDCCBBAA)
        result = registers(raw)
        self.assertEqual(result["rip"], "0x1122334455667788")
        self.assertEqual(result["rsp"], "0xffeeddccbbaa")

    def test_get_registers_consumes_176_only(self):
        stream = self.connect(identity_response() + OK + bytes(176))
        self.workbench.debugger.attached_pid = 71
        self.assertEqual(self.workbench.debugger.get_registers(72)["rip"], "0x0")
        self.assertEqual(stream.response, b"")
        self.workbench.debugger.attached_pid = None

    def test_writes_denied_without_any_connection(self):
        with patch("socket.create_connection") as connect:
            with self.assertRaisesRegex(WorkbenchError, "Disabled"):
                self.workbench.debugger.write_memory(1, 0, b"a")
            connect.assert_not_called()

    def test_process_write_consumes_both_statuses(self):
        self.qualify("process_write")
        stream = self.connect(identity_response() + OK + OK)
        self.workbench.debugger.write_memory(71, 0x4000, b"new")
        self.assertEqual(bytes(stream.sent[-31:]), struct.pack("<IIIIQI", 0xFFAABBCC, 0xBDAA0003, 16, 71, 0x4000, 3) + b"new")
        self.assertEqual(stream.response, b"")

    def test_process_write_requires_verified_write_capability(self):
        self.qualify("process_write")
        stream = self.connect(identity_response(brand=b"ps4debug-NG by Pharaoh2k v1.3.4\x001.0"))
        with self.assertRaisesRegex(WorkbenchError, "capability"):
            self.workbench.debugger.write_memory(71, 0x4000, b"new")
        self.assertEqual(len(stream.sent), 48)

    def test_write_terminal_error_is_not_success(self):
        self.qualify("process_write")
        stream = self.connect(identity_response() + OK + b"\x01\x00\x00\xf0")
        with self.assertRaisesRegex(WorkbenchError, "rejected"):
            self.workbench.debugger.write_memory(71, 0x4000, b"new")
        self.assertTrue(stream.closed)

    def test_kernel_write_two_statuses(self):
        self.qualify("kernel_write")
        stream = self.connect(identity_response() + OK + OK)
        self.workbench.debugger.write_memory(0, 0xFFFFFFFF80001000, b"x", kernel=True)
        self.assertEqual(bytes(stream.sent[-25:]), struct.pack("<IIIQI", 0xFFAABBCC, 0xBDCC0003, 12, 0xFFFFFFFF80001000, 1) + b"x")

    def test_async_packets_handle_fragmentation_and_source_offsets(self):
        sender, receiver = socket.socketpair()
        self.addCleanup(sender.close)
        self.addCleanup(receiver.close)
        receiver.setblocking(False)
        debugger = self.workbench.debugger
        debugger.events = receiver
        debugger.attached_pid = 71
        event = bytearray(EVENT_SIZE)
        struct.pack_into("<II", event, 0, 72, 5)
        struct.pack_into("<Q", event, 48 + 136, 0x1234)
        sender.sendall(event[:100])
        self.assertEqual(debugger.poll_events(), [])
        sender.sendall(event[100:])
        result = debugger.poll_events()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["thread_id"], 72)
        self.assertEqual(result[0]["registers"]["rip"], "0x1234")
        debugger.attached_pid = None

    def test_watchpoint_encoding(self):
        self.qualify("debug_control")
        self.connect(identity_response() + OK)
        self.workbench.debugger.attached_pid = 71
        self.workbench.debugger.watchpoint(2, 0x4000, 4, "write")
        self.assertEqual(bytes(self.workbench.debugger.connection.sent[-24:]), struct.pack("<IIIIQ", 2, 1, 3, 1, 0x4000))
        self.workbench.debugger.attached_pid = None

    def test_attach_uses_network_order_callback_address(self):
        self.qualify("debug_control")
        stream = self.connect(identity_response() + OK)
        listener = Mock()
        event_socket = Mock()
        listener.accept.return_value = (event_socket, ("127.0.0.1", 10000))
        with patch("ps4_workbench.debugger.socket.socket", return_value=listener):
            self.workbench.debugger.attach(71, "192.168.86.10")
        listener.bind.assert_called_once_with(("192.168.86.10", 755))
        self.assertEqual(bytes(stream.sent[-8:]), b"\x47\x00\x00\x00\xc0\xa8\x56\x0a")
        self.workbench.debugger.attached_pid = None
