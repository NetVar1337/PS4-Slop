"""Connect radare2/iaito to the PS4 workbench shared broker as an analysis agent.

Usage (needs r2 on PATH and the r2pipe package):

    python integrations/iaito/ps4_connect.py D:/dumps/eboot.bin

Environment:
    PS4_WORKBENCH_ROOT  repository root (default is this checkout)
    PS4_BROKER_URL      broker URL (default http://127.0.0.1:8765)
    PS4_IAITO_FILE      binary path when no argv[1] is given
"""

import os
import sys

repository = os.environ.get("PS4_WORKBENCH_ROOT", "C:/Users/Admin/Desktop/GithubProjects/PS4-DebugMCPs")
if repository not in sys.path:
    sys.path.insert(0, repository)

from ps4_workbench.adapters.iaito import IaitoWorkbench


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PS4_IAITO_FILE")
    if not path:
        raise SystemExit("usage: ps4_connect.py <binary>  (or set PS4_IAITO_FILE)")
    url = os.environ.get("PS4_BROKER_URL", "http://127.0.0.1:8765")
    token_path = os.path.join(repository, "profiles", "broker-token.local")
    ps4 = IaitoWorkbench(url, token_path, path)
    ps4.start_analysis()
    print("PS4 shared broker connected; iaito/r2 analysis agent registered for", path)
    print("No console attach or write performed. Ctrl-C / ps4.close() to stop.")
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        ps4.close()


if __name__ == "__main__":
    main()
