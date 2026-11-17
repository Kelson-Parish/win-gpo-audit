#!/usr/bin/env bash
# A Bash launcher; all collection and report rendering uses Python's standard library.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec /usr/bin/python3 -B "$script_dir/ubuntu_anomaly_audit.py" "$@"
