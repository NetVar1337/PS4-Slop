# Per-build offset store

`project_export_offsets` with `archive: true` (or `ps4_mcp.ctl export-offsets
--archive`) writes each build's generated header and manifest here, keyed by
the module SHA-256:

```
offsets/<module_sha256[:16]>/offsets.hpp   generated C++ offset constants
offsets/<module_sha256[:16]>/offsets.json  ps4wb-offsets-v1 manifest
offsets/<module_sha256[:16]>/annotations.json  source annotations, when ported
```

These are research artifacts, not source code: regenerate them after every
binary update (`unreal_update` / `source_update` recipes port annotations
from the previous build's directory via `--annotations`). Never hand-edit the
generated files; `project_install` installs fresh copies into the registered
`generated_directory` (`src/generated` by default).
