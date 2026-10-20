#!/bin/bash
# init-kibana.sh — install the Kibana alerting of LogSentinel (README.md section 9.2).
# `docker compose up -d` runs this script itself (service kibana-init, inside a Python image), once
# Kibana is healthy, and the `notifications` worker starts only after it has succeeded. By hand:
#   LOGSENTINEL_ES_HOST=http://localhost:9200 LOGSENTINEL_KIBANA_HOST=http://localhost:5601 \
#     bash scripts/init-kibana.sh
#
# It runs, in this order, the two setup scripts with --apply:
#   1. alerting_setup.py      the rule `ransomware-detections` (no action yet)
#   2. notification_setup.py  the notification policies/templates, the Index connector, and the
#                             one managed action that the rule needs to queue notices
# Both only create what is absent: a rule, connector, action, template or policy that exists and
# differs is refused (never updated or deleted), and notification_setup.py writes a verified backup
# of the public state to archives/backups/ before any remote write (it needs 5 GB free). So a
# second run is a no-op that reports `unchanged`. Status `blocked`, `ready` or `failed` fails the
# script: alerting without its rule or action must not look finished.
set -euo pipefail

LOGSENTINEL_ES_HOST="${LOGSENTINEL_ES_HOST:-http://localhost:9200}"
LOGSENTINEL_KIBANA_HOST="${LOGSENTINEL_KIBANA_HOST:-http://localhost:5601}"
DIR="$(dirname "$0")"
ATTEMPTS="${LOGSENTINEL_KIBANA_INIT_ATTEMPTS:-5}"
RETRY_SEC="${LOGSENTINEL_KIBANA_INIT_RETRY_SEC:-10}"

# apply <script name without .py> <accepted status>...
# Retries only a `failed` run (Kibana can report healthy a moment before its alerting API answers);
# any other status is a decision of the script that a retry cannot change.
apply() {
  local script="$1" out="" status attempt ok exit_code
  shift
  for attempt in $(seq 1 "${ATTEMPTS}"); do
    if out="$(python3 "${DIR}/${script}.py" \
      --es "${LOGSENTINEL_ES_HOST}" --kibana "${LOGSENTINEL_KIBANA_HOST}" --apply)"; then
      exit_code=0
    else
      exit_code=$?
    fi
    if ! status="$(printf '%s' "${out}" | python3 -c '
import json
import sys

try:
    report = json.load(sys.stdin)
    status = report["status"] if isinstance(report, dict) else None
    if not isinstance(status, str):
        raise ValueError("missing status")
except (KeyError, ValueError, TypeError):
    sys.exit(1)
print(status)
' 2>/dev/null)"; then
      echo "${script}: invalid or missing status report (exit ${exit_code})" >&2
      echo "${out}"
      return 1
    fi
    if [ "${status}" = "failed" ]; then
      echo "${script}: attempt ${attempt}/${ATTEMPTS} failed" >&2
      if [ "${attempt}" -lt "${ATTEMPTS}" ]; then
        sleep "${RETRY_SEC}"
      fi
      continue
    fi
    if [ "${exit_code}" -ne 0 ]; then
      echo "${script}: ${status} (exit ${exit_code})"
      echo "${out}"
      return 1
    fi
    for ok in "$@"; do
      if [ "${status}" = "${ok}" ]; then
        echo "${script}: ${status}"
        return 0
      fi
    done
    echo "${script}: ${status} (accepted: $*)"
    echo "${out}"
    return 1
  done
  echo "${out}"
  return 1
}

apply alerting_setup created unchanged
apply notification_setup applied unchanged
echo "kibana alerting is installed"
