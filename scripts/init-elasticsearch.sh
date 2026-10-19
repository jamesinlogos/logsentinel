#!/bin/bash
# init-elasticsearch.sh — install the LogSentinel Elasticsearch configuration.
# `docker compose up -d` runs this script itself (service elasticsearch-init, inside the
# Elasticsearch image), once Elasticsearch is healthy and before the Logstash pipelines start, so a
# new index always meets its template. Run it by hand after editing config/elasticsearch/ (it is
# safe to run again: every call is a PUT of the same resource). A changed index template or ILM
# policy applies to indices created afterwards.
#
# A resource is named after its file: config/elasticsearch/<kind>/<name>.json is installed as
# <name> (AGENTS.md section 11.8). The order matters: an index template refers to component
# templates, ILM policies and ingest pipelines, which must exist first.
set -euo pipefail

LOGSENTINEL_ES_HOST="${LOGSENTINEL_ES_HOST:-http://localhost:9200}"
CONFIG_DIR="$(dirname "$0")/../config/elasticsearch"
failed=0

# put_all <folder under config/elasticsearch> <API path of that kind of resource>
put_all() {
  local folder="$1" api="$2" file name response code
  for file in "${CONFIG_DIR}/${folder}"/*.json; do
    name="$(basename "${file}" .json)"
    echo "Installing ${folder}/${name}"
    response="$(curl -s --retry 5 --retry-delay 2 --retry-connrefused \
      -w $'\n%{http_code}' -X PUT "${LOGSENTINEL_ES_HOST}/${api}/${name}" \
      -H "Content-Type: application/json" --data-binary "@${file}")" || response=$'\n000'
    code="${response##*$'\n'}"
    if [ "${code}" = "200" ]; then
      echo " -> OK"
    else
      echo " -> FAILED (HTTP ${code}): ${response%$'\n'*}"
      failed=1
    fi
  done
}

put_all ingest-pipelines    "_ingest/pipeline"
put_all ilm-policies        "_ilm/policy"
put_all component-templates "_component_template"
put_all index-templates     "_index_template"

if [ "${failed}" -ne 0 ]; then
  echo "Some resources were not installed (is Elasticsearch healthy?)." >&2
  exit 1
fi
