import json
import re
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from .broker import load_token
from .config import WorkbenchError


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
                content = response.read(8388609)
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
        if len(content) > 8388608:
            raise WorkbenchError("Broker response exceeds 8 MiB")
        return json.loads(content)["result"]

    def call(self, name, **arguments):
        return self.request("call", name=name, arguments=arguments)

    def state(self):
        return self.request("state")

    def events(self, cursor=0, limit=64):
        return self.request("events", cursor=cursor, limit=limit)

    def close(self):
        pass


class RemoteTool:
    def __init__(self, description):
        self.description = description

    def describe(self):
        return self.description


class RemoteRegistry:
    def __init__(self, client):
        self.client = client
        self.workbench = client
        self.cursor = 0
        self.descriptions = client.request("tools")
        self.descriptions.extend([
            {"name": "session_state", "description": "Shared session controller, attached process and event health.",
             "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
            {"name": "session_events", "description": "Replay shared events from this MCP client's cursor; never drains other clients' events.",
             "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
            {"name": "session_release", "description": "Release this client's control lease only after detachment or a failed attach; does not recover the console.",
             "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}}
        ])

    def available(self):
        return [RemoteTool(description) for description in self.descriptions]

    def call(self, name, arguments):
        if name in ("session_state", "session_events", "session_release"):
            if arguments != {}:
                raise WorkbenchError("Session observer tools take no arguments")
            if name == "session_state":
                return self.client.state()
            if name == "session_release":
                return self.client.request("release")
            result = self.client.events(self.cursor, limit=6)
            self.cursor = result["cursor"]
            return result
        return self.client.call(name, **arguments)
