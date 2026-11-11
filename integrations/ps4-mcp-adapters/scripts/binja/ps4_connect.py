"""Connect Binary Ninja to the PS4-Slop MCP server as an analysis agent.

Run inside Binary Ninja's Python (plugin / Script Manager), where the open
BinaryView is the global `bv`:

    exec(open(r"C:/Users/Admin/Desktop/GithubProjects/PS4-Slop/integrations/ps4-mcp-adapters/scripts/binja/ps4_connect.py").read())

or headless with Binary Ninja's bundled Python:

    import binaryninja
    bv = binaryninja.load(r"D:/dumps/eboot.bin")
    exec(open(r"C:/Users/Admin/Desktop/GithubProjects/PS4-Slop/integrations/ps4-mcp-adapters/scripts/binja/ps4_connect.py").read())

Environment:
    PS4_SLOP_ROOT  adapter root (default: auto-detected)
    PS4_SLOP_URL   MCP server URL (default http://127.0.0.1:8765)
"""

import os
import sys
from pathlib import Path


def _repository_root():
    configured = os.environ.get("PS4_SLOP_ROOT") or os.environ.get("PS4_MCP_ROOT")
    if configured:
        root = Path(configured).expanduser().resolve()
        if (root / "ps4_mcp" / "adapters" / "binja.py").is_file():
            return root
        raise RuntimeError("PS4_SLOP_ROOT does not point at the ps4-mcp-adapters directory")
    candidates = [Path.cwd()]
    script = globals().get("__file__")
    if script:
        candidates.append(Path(script).resolve().parent)
    for candidate in candidates:
        for root in (candidate, *candidate.parents):
            if (root / "ps4_mcp" / "adapters" / "binja.py").is_file():
                return root
    raise RuntimeError(
        "Cannot locate the ps4_mcp adapters package; set PS4_SLOP_ROOT to the ps4-mcp-adapters directory"
    )

repository = str(_repository_root())
if repository not in sys.path:
    sys.path.insert(0, repository)

from ps4_mcp.adapters.binja import BinjaWorkbench


def connect(bv=None, url=None, token_path=None):
    url = url or os.environ.get("PS4_SLOP_URL") or os.environ.get("PS4_BROKER_URL", "http://127.0.0.1:8765")
    ps4 = BinjaWorkbench(url, token_path, bv=bv)
    ps4.start_analysis()
    return ps4


if "bv" in globals():
    ps4 = connect(bv)
    print("PS4-Slop MCP server connected; Binary Ninja analysis agent registered.")
    print("No console attach or write performed. Use ps4.client.call(...), ps4.events(), ps4.extract(path), ps4.refresh_shadow(..., apply=False).")
