"""Connect Binary Ninja to the PS4 workbench shared broker as an analysis agent.

Run inside Binary Ninja's Python (plugin / Script Manager), where the open
BinaryView is the global `bv`:

    exec(open(r"C:/Users/Admin/Desktop/GithubProjects/PS4-DebugMCPs/integrations/binja/ps4_connect.py").read())

or headless with Binary Ninja's bundled Python:

    import binaryninja
    bv = binaryninja.load(r"D:/dumps/eboot.bin")
    exec(open(r"C:/Users/Admin/Desktop/GithubProjects/PS4-DebugMCPs/integrations/binja/ps4_connect.py").read())

Environment:
    PS4_WORKBENCH_ROOT  repository root (default is this checkout)
    PS4_BROKER_URL      broker URL (default http://127.0.0.1:8765)
"""

import os
import sys
from pathlib import Path


def _repository_root():
    configured = os.environ.get("PS4_WORKBENCH_ROOT")
    if configured:
        root = Path(configured).expanduser().resolve()
        if (root / "ps4_workbench" / "adapters" / "binja.py").is_file():
            return root
        raise RuntimeError("PS4_WORKBENCH_ROOT does not point at a PS4-DebugMCPs checkout")
    candidates = [Path.cwd()]
    script = globals().get("__file__")
    if script:
        candidates.append(Path(script).resolve().parent)
    for candidate in candidates:
        for root in (candidate, *candidate.parents):
            if (root / "ps4_workbench" / "adapters" / "binja.py").is_file():
                return root
    raise RuntimeError(
        "Cannot locate PS4-DebugMCPs; set PS4_WORKBENCH_ROOT to the repository root"
    )

repository = str(_repository_root())
if repository not in sys.path:
    sys.path.insert(0, repository)

from ps4_workbench.adapters.binja import BinjaWorkbench


def connect(bv=None, url=None, token_path=None):
    url = url or os.environ.get("PS4_BROKER_URL", "http://127.0.0.1:8765")
    token_path = token_path or os.path.join(repository, "profiles", "broker-token.local")
    ps4 = BinjaWorkbench(url, token_path, bv=bv)
    ps4.start_analysis()
    return ps4


if "bv" in globals():
    ps4 = connect(bv)
    print("PS4 shared broker connected; Binary Ninja analysis agent registered.")
    print("No console attach or write performed. Use ps4.client.call(...), ps4.events(), ps4.extract(path), ps4.refresh_shadow(..., apply=False).")
