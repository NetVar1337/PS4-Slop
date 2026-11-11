import os
import sys


repository = os.environ.get("PS4_SLOP_ROOT") or os.environ.get("PS4_MCP_ROOT") or r"C:/Users/Admin/Desktop/GithubProjects/PS4-Slop/integrations/ps4-mcp-adapters"
if repository not in sys.path:
    sys.path.insert(0, repository)

from ps4_mcp.adapters.ghidra import GhidraWorkbench

try:
    plugin_tool = state.getTool()  # noqa: F821 - provided by the Ghidra script environment; None when headless
except NameError:
    plugin_tool = None

ps4 = GhidraWorkbench(currentProgram, os.environ.get("PS4_SLOP_URL", "http://127.0.0.1:8765"), None,
                      tool=plugin_tool)
ps4.start_analysis()
print("PS4-Slop MCP server connected; Ghidra static analysis agent registered. No console attach or write performed.")
print("Use ps4.client.call(...), ps4.events(), ps4.extract(path), and ps4.refresh_shadow(..., apply=False).")
