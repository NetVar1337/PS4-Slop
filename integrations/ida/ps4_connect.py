import os
import sys


repository = os.environ.get("PS4_WORKBENCH_ROOT", "C:/Users/Admin/Desktop/GithubProjects/PS4-DebugMCPs")
if repository not in sys.path:
    sys.path.insert(0, repository)

from ps4_workbench.adapters.ida import IDAWorkbench

ps4 = IDAWorkbench("http://127.0.0.1:8765", os.path.join(repository, "profiles", "broker-token.local"))
ps4.start_analysis()
print("PS4 shared broker connected; static analysis agent registered. No console attach or write performed.")
print("Use ps4.client.call(...), ps4.events(), ps4.extract(path), and ps4.refresh_shadow(..., apply=False).")
