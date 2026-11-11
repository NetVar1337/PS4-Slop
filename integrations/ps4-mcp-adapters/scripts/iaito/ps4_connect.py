"""Connect radare2/iaito to the PS4-Slop MCP server as an analysis agent.

Usage (needs r2 on PATH and the r2pipe package):

    python integrations/ps4-mcp-adapters/scripts/iaito/ps4_connect.py D:/dumps/eboot.bin

Environment:
    PS4_SLOP_ROOT  adapter root (default is this checkout)
    PS4_SLOP_URL   MCP server URL (default http://127.0.0.1:8765)
    PS4_IAITO_FILE      binary path when no argv[1] is given
"""

import os
import sys

repository = os.environ.get("PS4_SLOP_ROOT") or os.environ.get("PS4_MCP_ROOT") or r"C:/Users/Admin/Desktop/GithubProjects/PS4-Slop/integrations/ps4-mcp-adapters"
if repository not in sys.path:
    sys.path.insert(0, repository)

from ps4_mcp.adapters.iaito import IaitoWorkbench


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PS4_IAITO_FILE")
    if not path:
        raise SystemExit("usage: ps4_connect.py <binary>  (or set PS4_IAITO_FILE)")
    url = os.environ.get("PS4_SLOP_URL") or os.environ.get("PS4_BROKER_URL", "http://127.0.0.1:8765")
    ps4 = IaitoWorkbench(url, None, path)
    ps4.start_analysis()
    print("PS4-Slop MCP server connected; iaito/r2 analysis agent registered for", path)
    print("No console attach or write performed. Ctrl-C / ps4.close() to stop.")
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        ps4.close()


if __name__ == "__main__":
    main()
