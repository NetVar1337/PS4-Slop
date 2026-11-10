# SPDX-License-Identifier: GPL-3.0-only

import http.client
import json
import threading

from ps4debug_ng import ui


class StubClient:
    """Minimal client satisfying _route's read paths."""

    def connect(self):
        pass

    def read_memory(self, pid, address, length):
        return bytes(range(length))

    def server_info(self):
        return {"branding": "stub", "firmware": "0.00"}

    def list_processes(self):
        return [{"pid": 1, "name": "SceStub"}]


def _serve():
    import http.server
    ui._client = None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ui._Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _req(conn, method, path, body=None):
    conn.request(method, path, body=json.dumps(body) if body is not None else None,
                 headers={"Content-Type": "application/json"} if body is not None else {})
    resp = conn.getresponse()
    raw = resp.read()
    return resp.status, raw


def test_page_and_routes():
    server, port = _serve()
    real_ctor = ui.Ps4DebugClient
    ui.Ps4DebugClient = lambda *a, **kw: StubClient()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port)

        status, body = _req(conn, "GET", "/")
        assert status == 200
        assert b"ps4debug-ng" in body

        status, _ = _req(conn, "GET", "/api/connect?host=stub")
        assert status == 200

        status, raw = _req(conn, "GET", "/api/read?pid=1&addr=0x1000&len=32")
        assert status == 200
        assert json.loads(raw)["hex"] == bytes(range(32)).hex()

        # mutating route without confirm is refused
        status, _ = _req(conn, "POST", "/api/write",
                         {"pid": 1, "address": "0x1000", "hex": "90"})
        assert status == 403

        # bad JSON is a 400, not a crash
        conn.request("POST", "/api/write", body="{bad",
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        assert resp.status == 400
        resp.read()
    finally:
        ui.Ps4DebugClient = real_ctor
        server.shutdown()
