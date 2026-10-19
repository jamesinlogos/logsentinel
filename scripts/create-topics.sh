#!/bin/bash
# create-topics.sh — create the Kafka topics used by LogSentinel.
# `docker compose up -d` runs this script itself (service kafka-init, inside the broker image), so
# the topics exist before Logstash, inference or sentinelcap start. Run it by hand only
# to re-create topics on a stack started some other way. Safe to run again (--if-not-exists).
set -euo pipefail

# Topic names come from .env (the file docker-compose.yml reads), with the defaults
# of README.md section 6, so a renamed topic is created under its new name.
# Only the LOGSENTINEL_TOPIC_* lines are read: .env is not a shell script (an unquoted
# "LOGSENTINEL_ES_JAVA_OPTS=-Xms1g -Xmx1g" would fail if it were sourced), and a variable
# already set in the environment wins, as it does for docker compose.
ENV_FILE="$(dirname "$0")/../.env"
if [ -f "${ENV_FILE}" ]; then
  while IFS='=' read -r key value; do
    value="${value%$'\r'}"  # a .env saved with Windows line endings
    if [ -z "${!key:-}" ]; then
      export "${key}=${value}"
    fi
  done < <(grep -E '^LOGSENTINEL_TOPIC_(RAW_TELEMETRY|NORMALIZED_TELEMETRY|DETECTIONS|WINDOW_SCORES)=' "${ENV_FILE}" || true)
fi
LOGSENTINEL_TOPIC_RAW_TELEMETRY="${LOGSENTINEL_TOPIC_RAW_TELEMETRY:-telemetry.windows.sysmon.raw}"
LOGSENTINEL_TOPIC_NORMALIZED_TELEMETRY="${LOGSENTINEL_TOPIC_NORMALIZED_TELEMETRY:-telemetry.windows.normalized}"
LOGSENTINEL_TOPIC_DETECTIONS="${LOGSENTINEL_TOPIC_DETECTIONS:-security.ransomware.detections}"
LOGSENTINEL_TOPIC_WINDOW_SCORES="${LOGSENTINEL_TOPIC_WINDOW_SCORES:-security.ransomware.window-scores}"

# Where kafka-topics.sh runs. By hand it runs inside the broker container through `docker exec`.
# The kafka-init service of docker-compose.yml is already inside the broker image, so it sets
# LOGSENTINEL_KAFKA_EXEC to the empty string and points the bootstrap at the INTERNAL listener.
KAFKA_EXEC="${LOGSENTINEL_KAFKA_EXEC-docker exec logsentinel-kafka}"
KAFKA_BIN="${LOGSENTINEL_KAFKA_BIN:-/opt/kafka/bin}"
BOOTSTRAP="${LOGSENTINEL_KAFKA_BOOTSTRAP:-localhost:9092}"

kafka_topics() {
  # KAFKA_EXEC is a command line (or empty) on purpose: it must split into words.
  # shellcheck disable=SC2086
  ${KAFKA_EXEC} "${KAFKA_BIN}/kafka-topics.sh" "$@"
}

create_topic() {
  local topic="$1"
  local partitions="$2"
  echo "Creating topic: ${topic} (partitions=${partitions})"
  kafka_topics \
    --create --if-not-exists \
    --topic "${topic}" \
    --partitions "${partitions}" \
    --replication-factor 1 \
    --bootstrap-server "${BOOTSTRAP}"
}

create_topic "${LOGSENTINEL_TOPIC_RAW_TELEMETRY}"           3
create_topic "${LOGSENTINEL_TOPIC_NORMALIZED_TELEMETRY}"    3
# 3 partitions: that is what the lab broker's topic has (measured with kafka-topics.sh --describe),
# and a partition count cannot be lowered. Keyed by host.id.
create_topic "${LOGSENTINEL_TOPIC_DETECTIONS}"              3
# One record per scored window, keyed by host.id: 3 partitions like the telemetry it derives from.
create_topic "${LOGSENTINEL_TOPIC_WINDOW_SCORES}"           3

echo
echo "Current topic list:"
kafka_topics --list --bootstrap-server "${BOOTSTRAP}"
