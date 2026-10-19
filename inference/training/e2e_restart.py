"""End-to-end check on a real broker: kill -9 the service mid-stream, restart it, lose nothing.

    python -m training.e2e_restart --capture ../sentinelcap/captures/<run>/blackbasta/<hash> \
        --bootstrap 192.168.110.1:9092

What it does (inference/README.md section 9.2):
1. computes, without Kafka, the window ids of the uninterrupted stream (every window gives
   a window score, the reported ones also a detection);
2. creates its own input and output topics and consumer group (the lab topics
   are not touched) and sends the first 60% of the session;
3. runs ``python -m inference`` as a local process, kills it with SIGKILL once it
   has consumed that part, sends the rest and runs the service again, same group;
4. reads both output topics and checks that every reference id is there.

Suppression is off (``reemit_after_sec: 0``) so the comparison is about windows,
not about the reporting policy. Duplicates on the output topics are expected: the
restarted service re-reads the open windows and produces their records again
with the same ``logsentinel.window.id``. Exit code 0: nothing lost.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from confluent_kafka import Consumer, Producer
from confluent_kafka.admin import AdminClient, NewTopic

from inference.artifacts import load_artifacts, resolve_threshold
from inference.config import STATUS_PATH, load_config
from inference.events import decode, parse_event
from inference.pipeline import Pipeline

SERVICE_START_TIMEOUT_SEC = 60
COMMIT_WAIT_SEC = 7
"""auto.commit.interval.ms is 5 s: wait for the first commit before the kill."""
IDLE_FLUSH_MARGIN_SEC = 4
"""Wait this long after window.idle_flush_sec for the last pending windows to be emitted."""


def read_status() -> dict[str, Any]:
    try:
        status = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return status if isinstance(status, dict) else {}


def wait_for(predicate: Callable[[dict[str, Any]], bool], seconds: float) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if predicate(read_status()):
            return True
        time.sleep(0.5)
    return False


def reference_ids(
    lines: list[bytes], config_path: Path, artifacts_dir: Path
) -> tuple[set[str], set[str]]:
    """``(detection ids, window score ids)`` of the uninterrupted stream."""
    config = load_config(config_path)
    artifacts = load_artifacts(artifacts_dir, config.window)
    threshold = resolve_threshold(config.scoring, artifacts.model)
    pipeline = Pipeline(config, artifacts.model, threshold.value)
    emissions = []
    for offset, line in enumerate(lines):
        emissions += pipeline.process(parse_event(decode(line), 0, offset), float(offset))
    emissions += pipeline.drain()
    detections = {e.score.window_id for e in emissions if e.reported}
    return detections, {e.score.window_id for e in emissions}


def start_service(config_path: Path, cwd: Path) -> subprocess.Popen[str]:
    STATUS_PATH.unlink(missing_ok=True)
    env = {**os.environ, "INFERENCE_CONFIG": str(config_path)}
    return subprocess.Popen(
        [sys.executable, "-m", "inference"],
        cwd=cwd,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def read_output_ids(bootstrap: str, topic: str, tag: str) -> tuple[int, set[str]]:
    consumer = Consumer(
        {
            "bootstrap.servers": bootstrap,
            "group.id": f"e2e-reader-{tag}",
            "auto.offset.reset": "earliest",
        }
    )
    consumer.subscribe([topic])
    ids: set[str] = set()
    messages = idle = 0
    while idle < 6:
        message = consumer.poll(1.0)
        if message is None:
            idle += 1
        elif not message.error() and (value := message.value()) is not None:
            idle = 0
            messages += 1
            ids.add(json.loads(value)["logsentinel"]["window"]["id"])
    consumer.close()
    return messages, ids


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Kill -9 the service mid-stream; lose nothing.")
    parser.add_argument("--capture", type=Path, required=True, help="a sentinelcap session dir")
    parser.add_argument("--bootstrap", default="localhost:9092")
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    parser.add_argument("--cut", type=float, default=0.6, help="share sent before the kill")
    args = parser.parse_args(argv)

    cwd = Path.cwd()
    lines = [ln for ln in (args.capture / "session.jsonl").read_bytes().splitlines() if ln.strip()]
    tag = uuid.uuid4().hex[:8]
    topic_in, group = f"e2e.in.{tag}", f"e2e-{tag}"
    topic_detections, topic_scores = f"e2e.detections.{tag}", f"e2e.window-scores.{tag}"
    config_path = Path(tempfile.gettempdir()) / f"e2e-restart-{tag}.yaml"
    config_path.write_text(
        f"kafka:\n  bootstrap_servers: {args.bootstrap}\n  input_topic: {topic_in}\n"
        f"  detections_topic: {topic_detections}\n  window_scores_topic: {topic_scores}\n"
        f"  group_id: {group}\n  auto_offset_reset: earliest\n"
        f"scoring:\n  reemit_after_sec: 0\nartifacts_dir: {args.artifacts.resolve()}\n"
        "stats_interval_sec: 5\n",
        encoding="utf-8",
    )
    reference_detections, reference_scores = reference_ids(
        lines, config_path, args.artifacts.resolve()
    )
    print(
        f"{len(lines)} events; the uninterrupted stream gives {len(reference_scores)} window "
        f"scores, {len(reference_detections)} of them detections"
    )

    admin = AdminClient({"bootstrap.servers": args.bootstrap})
    new_topics = [NewTopic(name, 1, 1) for name in (topic_in, topic_detections, topic_scores)]
    for future in admin.create_topics(new_topics).values():
        future.result()
    producer = Producer({"bootstrap.servers": args.bootstrap, "acks": "all"})

    def send(chunk: list[bytes]) -> None:
        for line in chunk:
            producer.produce(topic_in, value=line, key=b"e2e-host")
        producer.flush(30)

    cut = int(len(lines) * args.cut)
    send(lines[:cut])
    first = start_service(config_path, cwd)
    if not wait_for(lambda s: s.get("consumed", 0) >= cut, SERVICE_START_TIMEOUT_SEC):
        print("the service did not consume the first part in time")
        first.kill()
        return 2
    time.sleep(COMMIT_WAIT_SEC)
    before = read_status()
    first.kill()  # SIGKILL: no flush, no shutdown path
    first.wait()
    print(
        f"killed after consumed={before.get('consumed')} produced={before.get('produced')} "
        f"acked={before.get('acked')}"
    )

    send(lines[cut:])
    second = start_service(config_path, cwd)
    remaining = len(lines) - cut
    wait_for(lambda s: s.get("consumed", 0) >= remaining, SERVICE_START_TIMEOUT_SEC)
    time.sleep(load_config(config_path).window.idle_flush_sec + IDLE_FLUSH_MARGIN_SEC)
    after = read_status()
    second.kill()
    second.wait()
    print(
        f"restarted: consumed={after.get('consumed')} "
        f"(replayed {after.get('consumed', 0) - remaining} events) produced={after.get('produced')}"
    )

    lost = 0
    for name, topic, reference in (
        ("detections", topic_detections, reference_detections),
        ("window scores", topic_scores, reference_scores),
    ):
        messages, delivered = read_output_ids(args.bootstrap, topic, f"{tag}-{name[:3]}")
        missing = reference - delivered
        lost += len(missing)
        print(
            f"{name}: {messages} messages, {len(delivered)} distinct ids; missing: {len(missing)}"
        )
    admin.delete_topics([topic_in, topic_detections, topic_scores])
    config_path.unlink(missing_ok=True)
    print("NOTHING LOST" if not lost else "RECORDS LOST")
    return 0 if not lost else 1


if __name__ == "__main__":
    raise SystemExit(main())
