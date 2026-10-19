"""End-to-end harness: replay one sentinelcap session into telemetry.windows.normalized.

    python -m training.replay_to_kafka <session dir or session.jsonl[.gz]> \
        [--bootstrap localhost:9092] [--topic telemetry.windows.normalized] [--realtime]

Messages are the original payloads, keyed by ``host.name`` like logstash
sink-inference, so a running service treats them as live telemetry of that host.
The service windows on ``@timestamp``: replay while the victim VM is not
sending, or its live events and the replayed ones interleave on one host.
``--realtime`` keeps the original gaps between events (capped at 5 s).
"""

from __future__ import annotations

import argparse
import gzip
import json
import time
from pathlib import Path

from confluent_kafka import Producer

from inference.events import parse_timestamp

MAX_GAP_SEC = 5.0


def session_file(path: Path) -> Path:
    if path.is_file():
        return path
    for name in ("session.jsonl", "session.jsonl.gz"):
        if (path / name).is_file():
            return path / name
    raise SystemExit(f"No session.jsonl in {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay a sentinelcap session into Kafka.")
    parser.add_argument("session", type=Path)
    parser.add_argument("--bootstrap", default="localhost:9092")
    parser.add_argument("--topic", default="telemetry.windows.normalized")
    parser.add_argument("--realtime", action="store_true")
    args = parser.parse_args(argv)

    path = session_file(args.session)
    producer = Producer({"bootstrap.servers": args.bootstrap, "acks": "all"})
    opener = gzip.open if path.suffix == ".gz" else open
    sent = 0
    previous: float | None = None
    with opener(path, "rt", encoding="utf-8") as lines:
        for line in lines:
            if not line.strip():
                continue
            doc = json.loads(line)
            if args.realtime:
                current = parse_timestamp(doc.get("@timestamp"))
                if previous is not None and current > previous:
                    time.sleep(min(current - previous, MAX_GAP_SEC))
                previous = current
            key = ((doc.get("host") or {}).get("name") or "").encode("utf-8")
            while True:
                try:
                    producer.produce(args.topic, value=line.rstrip("\n").encode("utf-8"), key=key)
                    break
                except BufferError:
                    producer.poll(0.5)
            producer.poll(0)
            sent += 1
    undelivered = producer.flush(30)
    print(f"Replayed {sent - undelivered}/{sent} events from {path} to {args.topic}")
    return 1 if undelivered else 0


if __name__ == "__main__":
    raise SystemExit(main())
