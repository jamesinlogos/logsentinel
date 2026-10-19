#!/bin/bash
# healthcheck-all.sh — quick status check across the LogSentinel stack.
set -uo pipefail

# Git Bash rewrites /opt/... arguments of docker exec into Windows paths.
export MSYS_NO_PATHCONV=1

# Inside the broker container the INTERNAL listener is the one that answers
# (the EXTERNAL one advertises the host address of the Windows machine).
KAFKA_BIN=/opt/kafka/bin
BOOTSTRAP=localhost:29092

echo "== Docker container status =="
docker compose ps

echo
echo "== Kafka broker =="
docker exec logsentinel-kafka $KAFKA_BIN/kafka-broker-api-versions.sh \
  --bootstrap-server $BOOTSTRAP >/dev/null 2>&1 \
  && echo "  [OK] kafka reachable" || echo "  [FAIL] kafka not reachable"

echo
echo "== Elasticsearch cluster health =="
curl -sf http://localhost:9200/_cluster/health?pretty || echo "  [FAIL] elasticsearch not reachable"

echo
echo "== Elasticsearch indices (telemetry, detections, window scores, notifications) =="
curl -sf "http://localhost:9200/_cat/indices/windows-telemetry-*,ransomware-*?v&s=index&h=index,health,docs.count,store.size" \
  || echo "  [FAIL] could not list indices"

echo
echo "== Kibana status =="
curl -sf http://localhost:5601/api/status >/dev/null 2>&1 \
  && echo "  [OK] kibana reachable" || echo "  [FAIL] kibana not reachable"

echo
echo "== Kafka topics =="
docker exec logsentinel-kafka $KAFKA_BIN/kafka-topics.sh --list --bootstrap-server $BOOTSTRAP 2>/dev/null \
  || echo "  [FAIL] could not list topics"

echo
echo "== inference =="
if docker exec logsentinel-inference python -m inference.healthcheck >/dev/null 2>&1; then
  echo "  [OK] healthy"
else
  echo "  [FAIL] unhealthy (or not running)"
fi
docker exec logsentinel-inference python -m json.tool /tmp/inference.status.json 2>/dev/null \
  || echo "  [FAIL] no status file"

echo
echo "== notifications =="
if docker exec logsentinel-notifications python -m notifications --healthcheck >/dev/null 2>&1; then
  echo "  [OK] healthy"
else
  echo "  [FAIL] unhealthy (or not running)"
fi

echo
echo "== Consumer lag (sum over partitions; 'no offset' = nothing committed yet) =="
docker exec logsentinel-kafka $KAFKA_BIN/kafka-consumer-groups.sh \
  --bootstrap-server $BOOTSTRAP --describe --all-groups 2>/dev/null \
  | awk '$3 ~ /^[0-9]+$/ {
      k = $1 "  " $2; parts[k]++
      if ($6 ~ /^[0-9]+$/) lag[k] += $6; else nooff[k]++
    }
    END {
      for (k in parts) printf "  %-70s lag=%d  partitions=%d  no offset=%d\n", k, lag[k], parts[k], nooff[k]
    }' | sort
