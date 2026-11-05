from ..client import BrokerClient
from ..config import WorkbenchError, require_hash, require_integer


class LiveAnalysis:
    target = None

    def __init__(self, url, token_path):
        self.client = BrokerClient(url, token_path)
        self.cursor = self.client.state()["event_cursor"]
        self.worker = None
        self.expected_program_hash = None

    def events(self):
        result = self.client.events(self.cursor)
        self.cursor = result["cursor"]
        return result

    def read_live(self, pid, rva, runtime_base, length, module_sha256):
        require_hash(module_sha256, "module_sha256")
        require_integer(rva, "rva", 0, 0x7FFFFFFFFFFFFFFF)
        require_integer(runtime_base, "runtime_base", 0, 0xFFFFFFFFFFFFFFFF)
        require_integer(length, "length", 1, 8192)
        if self.input_hash() != module_sha256:
            raise WorkbenchError("Static input SHA-256 mismatch; refusing address correlation")
        result = self.client.call("memory_peek", pid=pid, address=hex(runtime_base + rva), length=length)
        content = bytes.fromhex(result["hex"])
        if len(content) != length:
            raise WorkbenchError("Short live read")
        return content

    def extract(self, remote_path):
        return self.client.call("ftp_download", path=remote_path)

    def payload(self, manifest, sha256):
        return self.client.call("payload_execute", manifest=manifest, sha256=sha256)

    def start_analysis(self):
        from ..agents import AnalysisWorker
        if self.worker is not None:
            raise WorkbenchError("Analysis agent already started")
        self.expected_program_hash = self.input_hash()
        self.worker = AnalysisWorker(self.client, self.target, self.analyze, self.expected_program_hash).start()
        return self.worker

    def close(self):
        if self.worker:
            self.worker.stop()


def clipped(text):
    text = str(text)
    return {"text": text[:32768], "truncated": len(text) > 32768}
