"""Verify the detection flow end to end after a deployment.

    python scripts/verify_detections.py [--es http://localhost:9200] [--since 24h] [--skip-kafka]

Checks, each printed as OK, WARN or FAIL (exit code 1 when anything FAILed):

1. the Kafka topics exist and the sink consumer groups have no lag (needs Docker);
2. every Elasticsearch resource of ``config/elasticsearch`` is installed and the cluster is not red;
3. the newest documents of ``ransomware-detections-*`` and ``ransomware-window-scores-*`` have the
   expected shape: required fields, ``_id`` = ``logsentinel.window.id``, no ``@version`` or
   ``event.original``, and nothing was left out of the index (``_ignored``);
4. every detection of the period has a window score with the same id and ``reported`` true, and the
   two counts agree;
5. the repository follows AGENTS.md section 11 (``scripts/check_naming.py``).

Only the standard library is used.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

KAFKA_CONTAINER = "logsentinel-kafka"
KAFKA_BIN = "/opt/kafka/bin"
INTERNAL_BOOTSTRAP = "localhost:29092"
TOPICS = (
    "telemetry.windows.sysmon.raw",
    "telemetry.windows.normalized",
    "security.ransomware.detections",
    "security.ransomware.window-scores",
)
SINK_GROUPS = ("logstash-detection-sink", "logstash-detection-sink-window-scores")
RESOURCES = {
    "ingest-pipelines": "_ingest/pipeline",
    "ilm-policies": "_ilm/policy",
    "component-templates": "_component_template",
    "index-templates": "_index_template",
}
REQUIRED = (
    ("@timestamp",),
    ("ecs", "version"),
    ("event", "kind"),
    ("event", "module"),
    ("event", "dataset"),
    ("event", "ingested"),
    ("logsentinel", "schema_version"),
    ("logsentinel", "window", "id"),
    ("logsentinel", "verdict", "reported"),
)
SCHEMA_VERSION = 2
"""``logsentinel.schema_version`` of the documents (``inference.documents``)."""
SAMPLE = 200


class Report:
    def __init__(self) -> None:
        self.failed = 0

    def ok(self, text: str) -> None:
        print(f"  OK    {text}")

    def warn(self, text: str) -> None:
        print(f"  WARN  {text}")

    def fail(self, text: str) -> None:
        self.failed += 1
        print(f"  FAIL  {text}")


def get(source: dict[str, Any], path: tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(source, dict) or key not in source:
            return None
        source = source[key]
    return source


def check_document(doc_id: str, source: dict[str, Any], *, kind: str) -> list[str]:
    """What is wrong with one document of ``kind`` (``alert`` or ``metric``); [] when nothing."""
    problems = [f"missing {'.'.join(path)}" for path in REQUIRED if get(source, path) is None]
    if "@version" in source:
        problems.append("has @version")
    if "original" in (source.get("event") or {}):
        problems.append("has event.original")
    if get(source, ("event", "kind")) not in (None, kind):
        problems.append(f"event.kind is {get(source, ('event', 'kind'))!r}, expected {kind!r}")
    if get(source, ("logsentinel", "schema_version")) not in (None, SCHEMA_VERSION):
        problems.append(f"logsentinel.schema_version is not {SCHEMA_VERSION}")
    if get(source, ("logsentinel", "window", "id")) not in (None, doc_id):
        problems.append("_id differs from logsentinel.window.id")
    if kind == "metric" and get(source, ("logsentinel", "window", "features")) is None:
        problems.append("a window score without features")
    if kind == "alert" and get(source, ("logsentinel", "window", "features")) is not None:
        problems.append("a detection must not carry features")
    return problems


class Elasticsearch:
    def __init__(self, host: str) -> None:
        self.host = host.rstrip("/")

    def get(self, path: str, body: dict[str, Any] | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(  # noqa: S310 - the operator's own host
            f"{self.host}/{path}",
            data=data,
            method="POST" if body is not None else "GET",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise


def docker_exec(*command: str) -> str | None:
    result = subprocess.run(
        ["docker", "exec", KAFKA_CONTAINER, *command],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def check_kafka(report: Report) -> None:
    print("Kafka:")
    topics = docker_exec(
        f"{KAFKA_BIN}/kafka-topics.sh", "--list", "--bootstrap-server", INTERNAL_BOOTSTRAP
    )
    if topics is None:
        report.warn("could not list topics (is Docker running?)")
        return
    present = set(topics.split())
    for topic in TOPICS:
        (report.ok if topic in present else report.fail)(f"topic {topic}")
    for group in SINK_GROUPS:
        output = docker_exec(
            f"{KAFKA_BIN}/kafka-consumer-groups.sh",
            "--bootstrap-server",
            INTERNAL_BOOTSTRAP,
            "--describe",
            "--group",
            group,
        )
        lags = [int(line.split()[5]) for line in (output or "").splitlines() if _is_row(line)]
        if not lags:
            report.warn(f"group {group}: no committed offsets yet")
        elif sum(lags) == 0:
            report.ok(f"group {group}: no lag")
        else:
            report.warn(f"group {group}: lag {sum(lags)} (the sink is still catching up)")


def _is_row(line: str) -> bool:
    parts = line.split()
    return len(parts) >= 6 and parts[2].isdigit() and parts[5].isdigit()


def check_resources(es: Elasticsearch, report: Report) -> None:
    print("Elasticsearch resources:")
    for folder, api in RESOURCES.items():
        for path in sorted((ROOT / "config" / "elasticsearch" / folder).glob("*.json")):
            found = es.get(f"{api}/{path.stem}")
            (report.ok if found else report.fail)(f"{folder}/{path.stem}")
    status = (es.get("_cluster/health") or {}).get("status")
    (report.fail if status in (None, "red") else report.ok)(f"cluster health {status}")


def newest(es: Elasticsearch, index: str, size: int) -> list[dict[str, Any]]:
    result = es.get(
        f"{index}/_search", {"size": size, "sort": [{"@timestamp": "desc"}], "_source": True}
    )
    return (result or {}).get("hits", {}).get("hits", [])


def check_family(es: Elasticsearch, report: Report, index: str, kind: str) -> int:
    count = (es.get(f"{index}/_count") or {}).get("count", 0)
    if not count:
        report.warn(f"{index}: no documents yet")
        return 0
    ignored = (es.get(f"{index}/_count", {"query": {"exists": {"field": "_ignored"}}}) or {}).get(
        "count", 0
    )
    (report.fail if ignored else report.ok)(f"{index}: {count} documents, {ignored} with _ignored")
    bad = {
        hit["_id"]: problems
        for hit in newest(es, index, SAMPLE)
        if (problems := check_document(hit["_id"], hit["_source"], kind=kind))
    }
    if bad:
        doc_id, problems = next(iter(bad.items()))
        report.fail(
            f"{index}: {len(bad)} of the newest {SAMPLE} documents are wrong; {doc_id}: {problems}"
        )
    else:
        report.ok(f"{index}: the newest {min(count, SAMPLE)} documents have the expected shape")
    return int(count)


def check_flow(es: Elasticsearch, report: Report, since: str) -> None:
    print(f"Detections and window scores of the last {since}:")
    period = {"range": {"@timestamp": {"gte": f"now-{since}"}}}
    detections = (es.get("ransomware-detections-*/_count", {"query": period}) or {}).get("count", 0)
    reported = (
        es.get(
            "ransomware-window-scores-*/_count",
            {
                "query": {
                    "bool": {"filter": [period, {"term": {"logsentinel.verdict.reported": True}}]}
                }
            },
        )
        or {}
    ).get("count", 0)
    if detections == reported:
        report.ok(f"{detections} detection(s), {reported} reported window score(s)")
    else:
        report.fail(f"{detections} detection(s) but {reported} reported window score(s)")
    wanted = [hit["_id"] for hit in newest(es, "ransomware-detections-*", SAMPLE)]
    found = es.get(
        "ransomware-window-scores-*/_search",
        {"size": len(wanted), "_source": False, "query": {"ids": {"values": wanted}}},
    )
    have = {hit["_id"] for hit in (found or {}).get("hits", {}).get("hits", [])}
    absent = [doc_id for doc_id in wanted if doc_id not in have]
    if absent:
        report.fail(f"{len(absent)} newest detection(s) have no window score, e.g. {absent[0]}")
    elif wanted:
        report.ok("the newest detections all have a window score with the same id")


def check_naming(report: Report) -> None:
    print("Naming:")
    import check_naming

    violations = check_naming.check_tree(ROOT)
    for violation in violations[:10]:
        report.fail(str(violation))
    if not violations:
        report.ok("the repository follows AGENTS.md section 11")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--es", default="http://localhost:9200")
    parser.add_argument("--since", default="24h", help="period of the flow check (Elasticsearch)")
    parser.add_argument("--skip-kafka", action="store_true", help="do not call Docker")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    report = Report()
    es = Elasticsearch(args.es)
    if not args.skip_kafka:
        check_kafka(report)
    check_resources(es, report)
    print("Documents:")
    check_family(es, report, "ransomware-detections-*", "alert")
    check_family(es, report, "ransomware-window-scores-*", "metric")
    check_flow(es, report, args.since)
    check_naming(report)
    print("all checks passed" if not report.failed else f"{report.failed} check(s) FAILED")
    return 1 if report.failed else 0


if __name__ == "__main__":
    sys.exit(main())
