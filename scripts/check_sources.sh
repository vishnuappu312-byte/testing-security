#!/usr/bin/env bash
# Syntax-check all main/*.c files using ESP32 compile flags from build/compile_commands.json
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC_DB="$ROOT/build/compile_commands.json"

if [[ ! -f "$CC_DB" ]]; then
  echo "Run 'idf.py build' once to generate build/compile_commands.json"
  exit 1
fi

python3 - "$CC_DB" "$ROOT/main" <<'PY'
import json, subprocess, os, sys

cc_db, main_dir = sys.argv[1], sys.argv[2]
with open(cc_db) as f:
    cmds = json.load(f)
template = next(c["command"] for c in cmds if c["file"].endswith("web_server.c"))
base = template.split()
idx = base.index("-c")
prefix = base[:idx]
failed = []
for name in sorted(f for f in os.listdir(main_dir) if f.endswith(".c")):
    path = os.path.join(main_dir, name)
    r = subprocess.run(prefix + ["-fsyntax-only", path], capture_output=True, text=True)
    if r.returncode != 0:
        failed.append(name)
        print(f"FAIL {name}\n{r.stderr or r.stdout}")
    else:
        print(f"OK   {name}")
if failed:
    sys.exit(1)
print("All sources OK")
PY
