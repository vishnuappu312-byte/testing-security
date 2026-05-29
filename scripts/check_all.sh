#!/usr/bin/env bash
# Full project check: syntax + optional build. Exit 0 = no errors.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAIN="$ROOT/main"
CC_DB="$ROOT/build/compile_commands.json"
IDF_PY="${IDF_PYTHON:-/Users/vishnu/.espressif/python_env/idf4.4_py3.11_env/bin/python}"
IDF_PY="${IDF_PATH:-/Users/vishnu/esp/esp-idf-v4.4.7}"
IDF_SCRIPT="/Users/vishnu/.espressif/python_env/idf4.4_py3.11_env/bin/python"
IDF_TOOLS="/Users/vishnu/esp/esp-idf-v4.4.7/tools/idf.py"

echo "=== 1/3 Syntax check (all main/*.c) ==="
if [[ ! -f "$CC_DB" ]]; then
  echo "ERROR: Missing $CC_DB — run a build first."
  exit 1
fi
python3 - "$CC_DB" "$MAIN" <<'PY'
import json, subprocess, os, sys
cc_db, main_dir = sys.argv[1], sys.argv[2]
with open(cc_db) as f:
    cmds = json.load(f)
prefix = next(c["command"] for c in cmds if c["file"].endswith("web_server.c")).split()
prefix = prefix[:prefix.index("-c")]
failed = []
for name in sorted(f for f in os.listdir(main_dir) if f.endswith(".c")):
    path = os.path.join(main_dir, name)
    r = subprocess.run(prefix + ["-fsyntax-only", path], capture_output=True, text=True)
    if r.returncode:
        failed.append(name)
        print(f"FAIL {name}\n{r.stderr}")
    else:
        print(f"OK   {name}")
if failed:
    sys.exit(1)
PY

echo ""
echo "=== 2/3 CMakeLists vs source files ==="
python3 - "$MAIN/CMakeLists.txt" "$MAIN" <<'PY'
import re, os, sys
cmake, main = sys.argv[1], sys.argv[2]
text = open(cmake).read()
listed = set(re.findall(r'"([^"]+\.c)"', text))
disk = set(f for f in os.listdir(main) if f.endswith(".c"))
if listed != disk:
    print("ERROR: CMake SRCS mismatch")
    print("  only in CMake:", listed - disk)
    print("  only on disk:", disk - listed)
    sys.exit(1)
print(f"OK   {len(disk)} source files in CMakeLists.txt")
PY

echo ""
echo "=== 3/3 Full ESP-IDF build ==="
"$IDF_SCRIPT" "$IDF_TOOLS" -C "$ROOT" build
echo ""
echo "========================================="
echo "  ALL CHECKS PASSED — NO ERRORS"
echo "========================================="
