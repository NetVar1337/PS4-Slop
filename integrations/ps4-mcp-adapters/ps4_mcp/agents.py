"""Adapter-side job loop: registers with the Rust broker and serves static-analysis jobs."""
import threading


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
