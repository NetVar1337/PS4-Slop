"""HTTP client for the ps4-mcp broker (Rust, ``src/broker.rs``).

The broker owns the token file; this client only reads it.
"""
import json
import re
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from .config import WorkbenchError

MAX_RESPONSE = 8 * 1024 * 1024


def load_token(path):
    token = Path(path).resolve().read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise WorkbenchError("Broker token file must contain exactly 64 lowercase hex characters")
    return token


class BrokerClient:
    def __init__(self, url, token_path, client=None, timeout=150, expected_profile=None):
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username:
            raise WorkbenchError("Broker URL must be http://127.0.0.1:PORT, without credentials or paths")
        self.url = url.rstrip("/") + "/rpc"
        self.token = load_token(token_path)
        self.client = client or "client-" + uuid.uuid4().hex
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,96}", self.client):
            raise WorkbenchError("Invalid broker client identity")
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}))
        self.expected_profile = expected_profile
        state = self.state()
        self.expected_profile = state["profile_sha256"]

    def request(self, operation, **arguments):
        data = json.dumps({"operation": operation, "arguments": arguments,
                           "profile_sha256": self.expected_profile}, allow_nan=False).encode()
        request = Request(self.url, data=data, headers={"Authorization": "Bearer " + self.token,
                          "X-PS4-Client": self.client, "Content-Type": "application/json"}, method="POST")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                content = response.read(MAX_RESPONSE + 1)
        except HTTPError as error:
            try:
                message = json.loads(error.read(65536)).get("error", str(error))
            except ValueError:
                message = str(error)
            finally:
                error.close()
            raise WorkbenchError(message) from error
        except (URLError, OSError) as error:
            raise WorkbenchError("Broker connection failed; do not retry mutations automatically: " + str(error)) from error
        if len(content) > MAX_RESPONSE:
            raise WorkbenchError("Broker response exceeds 8 MiB")
        return json.loads(content)["result"]

    def call(self, name, **arguments):
        return self.request("call", name=name, arguments=arguments)

    def state(self):
        return self.request("state")

    def events(self, cursor=0, limit=64):
        return self.request("events", cursor=cursor, limit=limit)

    def release(self):
        return self.request("release")
