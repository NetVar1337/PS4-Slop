#!/bin/sh
# setup-profile.sh — create profiles/ps4-1400.local.json from the safe template
# and optionally set the console host. Never contacts the console.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/profiles/ps4-1400.json"
DST="$ROOT/profiles/ps4-1400.local.json"
HOST=""
FORCE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        *) echo "usage: setup-profile.sh [--host 192.168.x.y] [--force]" >&2; exit 2 ;;
    esac
done
if [ -f "$DST" ] && [ "$FORCE" != 1 ]; then
    echo "$DST already exists; use --force to overwrite" >&2; exit 1
fi
cp "$SRC" "$DST"
if [ -n "$HOST" ]; then
    python3 - "$DST" "$HOST" <<'EOF'
import json, sys
path, host = sys.argv[1], sys.argv[2]
data = json.load(open(path))
data["host"] = host
json.dump(data, open(path, "w"), indent=2)
EOF
fi
cat <<'EOF'
[setup-profile] Local profile created. Next steps (see docs/QUALIFICATION.md):
  1. Record the REAL Afterglow commit / HEN build in profiles/ps4-1400.local.json.
  2. ps4-mcp --profile profiles/ps4-1400.local.json afterglow-verify --directory C:/path/to/afterglow-web
  3. Load ps4debug-NG manually, then: ps4-mcp --profile ... preflight --probe
  4. Enable only tested permissions, then: scripts/qualify-local.sh --evidence ... --attest I_TESTED_THIS_EXACT_CONFIGURATION --approve ...
EOF
