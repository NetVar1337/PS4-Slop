import collections
import threading
import time
import uuid

from .config import WorkbenchError, require_integer


class AnalysisAgents:
    def __init__(self):
        self.lock = threading.RLock()
        self.agents = {}
        self.jobs = {}

    def status(self):
        with self.lock:
            now = time.monotonic()
            return {target: {"client": state["client"], "connected": now - state["last_seen"] < 30,
                             "program": state["program"]} for target, state in self.agents.items()}

    def register(self, client, target, program):
        if target not in ("ida", "ghidra", "binja", "iaito") or not isinstance(program, str) or len(program) > 2048:
            raise WorkbenchError("Register ida/ghidra/binja/iaito with a bounded program identity")
        with self.lock:
            previous = self.agents.get(target)
            if previous and previous["client"] != client and time.monotonic() - previous["last_seen"] < 30:
                raise WorkbenchError("An analysis agent is already registered for this target")
            self.agents[target] = {"client": client, "last_seen": time.monotonic(), "program": program,
                                   "queue": collections.deque()}
        return {"registered": target}

    def poll(self, client, target):
        with self.lock:
            state = self.agents.get(target)
            if not state or state["client"] != client:
                raise WorkbenchError("Register this analysis agent first")
            state["last_seen"] = time.monotonic()
            while state["queue"]:
                identifier = state["queue"].popleft()
                job = self.jobs.get(identifier)
                if job is not None:
                    return {"id": identifier, "operation": job["operation"], "arguments": job["arguments"]}
            return None

    def unregister(self, client, target):
        with self.lock:
            state = self.agents.get(target)
            if state is None:
                return {"unregistered": False}
            if state["client"] != client:
                raise WorkbenchError("Cannot unregister another analysis agent")
            del self.agents[target]
            for job in self.jobs.values():
                if job["agent"] == client:
                    job["error"] = "Analysis agent stopped"
                    job["done"].set()
            return {"unregistered": True}

    def complete(self, client, identifier, result=None, error=None):
        with self.lock:
            job = self.jobs.get(identifier)
            if job is None:
                return {"accepted": False, "reason": "expired_or_unknown_job"}
            if job["agent"] != client:
                raise WorkbenchError("Foreign analysis job")
            if job["done"].is_set():
                raise WorkbenchError("Analysis job already completed")
            job["result"], job["error"] = result, error
            job["done"].set()
        return {"accepted": True}

    def submit(self, target, operation, arguments, timeout=20):
        import re
        allowed_map = {
            "functions": {"offset", "limit", "filter"},
            "decompile": {"address"},
            "xrefs": {"address", "limit", "direction"},
            "disasm": {"address", "count"},
            "strings": {"offset", "limit", "filter", "min_length"},
            "imports": {"offset", "limit", "filter"},
            "rename": {"address", "name"},
            "comment": {"address", "text"},
        }
        if target not in ("ida", "ghidra", "binja", "iaito") or operation not in allowed_map:
            raise WorkbenchError("Unsupported static-analysis target or operation")
        if not isinstance(arguments, dict):
            raise WorkbenchError("Analysis arguments must be an object")
        allowed = allowed_map[operation]
        if set(arguments) - allowed:
            raise WorkbenchError("Unknown static-analysis arguments")
        if operation in ("decompile", "xrefs", "disasm", "rename", "comment"):
            from .tools import parse_address
            address = arguments.get("address")
            if not isinstance(address, str) or len(address) > 20:
                raise WorkbenchError("Supply a static database address string")
            parse_address(address)
        if "limit" in arguments:
            require_integer(arguments["limit"], "limit", 1, 100)
        if "offset" in arguments:
            require_integer(arguments["offset"], "offset", 0, 1000000)
        if "count" in arguments:
            require_integer(arguments["count"], "count", 1, 256)
        if "min_length" in arguments:
            require_integer(arguments["min_length"], "min_length", 1, 256)
        if "filter" in arguments:
            flt = arguments["filter"]
            if not isinstance(flt, str) or not (1 <= len(flt) <= 256):
                raise WorkbenchError("filter must be a string of length 1..256")
        if "direction" in arguments:
            if arguments["direction"] not in ("to", "from", "both"):
                raise WorkbenchError("direction must be one of to, from, both")
        if operation == "rename":
            name = arguments.get("name")
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.$@?:+-]{1,256}", name):
                raise WorkbenchError("Invalid symbol name for rename")
        if operation == "comment":
            text = arguments.get("text")
            if not isinstance(text, str) or len(text) > 2048 or "\x00" in text:
                raise WorkbenchError("Comment text out of bounds or contains NUL")
        with self.lock:
            state = self.agents.get(target)
            if not state or time.monotonic() - state["last_seen"] >= 30:
                raise WorkbenchError(f"No live {target} analysis agent; start it inside the application")
            if len(self.jobs) >= 32:
                raise WorkbenchError("Analysis job queue is full")
            identifier = uuid.uuid4().hex
            job = {"agent": state["client"], "operation": operation, "arguments": arguments,
                   "done": threading.Event(), "result": None, "error": None}
            self.jobs[identifier] = job
            state["queue"].append(identifier)
        try:
            if not job["done"].wait(timeout):
                raise WorkbenchError("Static-analysis job timed out; no automatic retry")
            if job["error"]:
                raise WorkbenchError(str(job["error"]))
            return job["result"]
        finally:
            with self.lock:
                self.jobs.pop(identifier, None)


class AnalysisWorker:
    def __init__(self, client, target, handler, program):
        self.client, self.target, self.handler, self.program = client, target, handler, program
        self.stopping = threading.Event()
        self.thread = None
        self.last_error = None

    def start(self):
        self.client.request("agent_register", target=self.target, program=self.program)

        def run():
            while not self.stopping.wait(0.2):
                try:
                    job = self.client.request("agent_poll", target=self.target)
                    if job is None:
                        continue
                    try:
                        result = self.handler(job["operation"], job["arguments"])
                        error = None
                    except Exception as exception:
                        result, error = None, str(exception)
                    completion = self.client.request("agent_result", identifier=job["id"], result=result, error=error)
                    if not completion["accepted"]:
                        self.last_error = "Analysis result arrived after job expiration"
                except Exception as exception:
                    self.last_error = str(exception)
                    self.stopping.set()
        self.thread = threading.Thread(target=run, name=self.target + "-analysis-agent", daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.stopping.set()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=0.1)
        try:
            self.client.request("agent_unregister", target=self.target)
        except Exception as error:
            self.last_error = str(error)
