import socket
import threading
import xml.etree.ElementTree as ET
from unittest.mock import Mock

from ps4_workbench.client import BrokerClient
from ps4_workbench.config import WorkbenchError
from ps4_workbench.rsp import PacketDecoder, REGISTER_LAYOUT, RspServer, RspSession, TARGET_XML, frame, register_bytes

from .test_broker import BrokerCase


class PacketTests(BrokerCase):
    def test_packet_fragmentation_and_escaping(self):
        decoder = PacketDecoder()
        encoded = frame(b"test#$}*")
        self.assertEqual(decoder.feed(encoded[:4]), [])
        self.assertEqual(decoder.feed(encoded[4:]), [("packet", b"test#$}*")])

    def test_bad_checksum_does_not_produce_command(self):
        self.assertEqual(PacketDecoder().feed(b"$c#00"), [("bad_checksum", b"")])

    def test_decoder_handles_ack_interrupt_and_multiple_packets(self):
        result = PacketDecoder().feed(b"+\x03-" + frame(b"g") + frame(b"?"))
        self.assertEqual([kind for kind, _ in result], ["ack", "interrupt", "nak", "packet", "packet"])

    def test_oversized_packet_rejected(self):
        with self.assertRaises(WorkbenchError):
            PacketDecoder().feed(b"$" + b"A" * 16385)

    def test_target_description_matches_encoded_register_bytes(self):
        root = ET.fromstring(TARGET_XML)
        definitions = root.findall("feature/reg")
        self.assertEqual(len(definitions), len(REGISTER_LAYOUT))
        values = register_bytes({"rax": "0x1234", "rflags": "0x202"})
        self.assertTrue(values.startswith(b"3412000000000000"))
        self.assertEqual(len(values), sum(bits // 4 for _, bits in REGISTER_LAYOUT))
        self.assertIn(b"xxxxxxxx", values)


class SessionTests(BrokerCase):
    def session(self, url, observer=False, name="gdb"):
        return RspSession(BrokerClient(url, self.secret_path, name), 71, "127.0.0.1", observer)

    def attach_and_stop(self, session):
        self.assertIsNone(session.handle(b"?"))
        self.stop_event()
        self.assertEqual(session.poll_stop(), b"T05thread:48;")

    def test_attach_waits_for_actual_stop_instead_of_fabricating(self):
        with self.broker() as url:
            session = self.session(url)
            self.assertIsNone(session.handle(b"?"))
            self.assertIsNone(session.poll_stop())
            self.stop_event()
            self.assertEqual(session.poll_stop(), b"T05thread:48;")
            session.cleanup()

    def test_memory_registers_and_xml(self):
        with self.broker() as url:
            session = self.session(url)
            self.attach_and_stop(session)
            self.assertEqual(session.handle(b"m4000,4"), b"41414141")
            self.assertEqual(session.handle(b"p0"), b"3412000000000000")
            self.assertIn(b"memory-map", session.handle(b"qXfer:memory-map:read::0,1000"))
            self.assertIn(b"library-list-svr4", session.handle(b"qXfer:libraries-svr4:read::0,1000"))
            xml_reply = session.handle(b"qXfer:features:read:target.xml:0,1000")
            self.assertTrue(xml_reply.startswith(b"l<?xml"))
            self.assertIn(b'org.gnu.gdb.i386.sse', xml_reply)
            session.cleanup()

    def test_opt_in_allow_writes_enables_memory_and_register_writes(self):
        from unittest.mock import Mock
        self.workbench.memory_write = Mock(return_value={"verified": True})
        with self.broker() as url:
            session = RspSession(BrokerClient(url, self.secret_path, "gdb-rw"), 71, "127.0.0.1", allow_writes=True)
            self.attach_and_stop(session)
            self.assertEqual(session.handle(b"X4000,0:"), b"")
            self.assertEqual(session.handle(b"M4000,4:90909090"), b"OK")
            self.workbench.memory_write.assert_called_once_with(71, 0x4000, "90909090", "41414141")
            self.assertEqual(session.handle(b"k"), b"E01")
            session.cleanup()

    def test_mutating_rsp_packets_not_supported_are_rejected(self):
        with self.broker() as url:
            session = self.session(url)
            for packet in (b"M4000,1:ff", b"P0=00", b"G00", b"k", b"vKill;47", b"qRcmd,00"):
                self.assertEqual(session.handle(packet), b"E01")

    def test_observer_reads_same_session_but_cannot_control(self):
        with self.broker() as url:
            owner = self.session(url)
            self.attach_and_stop(owner)
            observer = self.session(url, observer=True, name="ghidra")
            self.assertEqual(observer.handle(b"?"), b"T05thread:48;")
            self.assertEqual(observer.handle(b"m4000,1"), b"41")
            with self.assertRaisesRegex(WorkbenchError, "Observer"):
                observer.handle(b"c")
            observer.cleanup()
            self.assertEqual(self.hub.state()["attached_pid"], 71)
            owner.cleanup()

    def test_continue_and_step_wait_for_real_events(self):
        with self.broker() as url:
            session = self.session(url)
            self.attach_and_stop(session)
            self.assertIsNone(session.handle(b"c"))
            self.assertEqual(self.hub.state()["execution_state"], "running")
            self.assertIsNone(session.poll_stop())
            self.stop_event()
            self.assertEqual(session.poll_stop(), b"T05thread:48;")
            self.assertIsNone(session.handle(b"s"))
            self.workbench.debugger.control.assert_called_with(action="step_thread", thread_id=72)
            session.cleanup()

    def test_breakpoint_slots_and_idempotent_removal(self):
        with self.broker() as url:
            session = self.session(url)
            self.attach_and_stop(session)
            self.assertEqual(session.handle(b"Z0,4000,1"), b"OK")
            self.assertEqual(session.handle(b"Z0,4000,1"), b"OK")
            self.assertEqual(self.workbench.debugger.breakpoint.call_count, 1)
            self.assertEqual(session.handle(b"z0,4000,1"), b"OK")
            self.assertEqual(session.handle(b"z0,4000,1"), b"OK")
            self.assertEqual(self.workbench.debugger.breakpoint.call_count, 2)
            session.cleanup()

    def test_attach_pid_must_match_explicit_configuration(self):
        with self.broker() as url:
            with self.assertRaisesRegex(WorkbenchError, "PID differs"):
                self.session(url).handle(b"vAttach;48")

    def test_real_rsp_socket_negotiation_and_detach(self):
        with self.broker() as url, RspServer(url, self.secret_path, 71, "127.0.0.1", port=0) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            try:
                with socket.create_connection(server.server_address, timeout=3) as connection:
                    decoder = PacketDecoder()

                    def exchange(command):
                        connection.sendall(frame(command))
                        while True:
                            for kind, payload in decoder.feed(connection.recv(16384)):
                                if kind == "packet":
                                    connection.sendall(b"+")
                                    return payload
                    self.assertIn(b"PacketSize=4000", exchange(b"qSupported"))
                    self.assertTrue(exchange(b"qXfer:features:read:target.xml:0,1000").startswith(b"l<?xml"))
                    self.assertEqual(exchange(b"M4000,1:ff"), b"E01")
                    self.assertEqual(exchange(b"D"), b"OK")
            finally:
                server.shutdown()
                thread.join(timeout=2)
