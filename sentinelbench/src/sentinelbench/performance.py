"""Lightweight performance probes (statistics.md §2.9, without chaos / backup)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from sentinelbench.clients.docker_exec import DockerExec
from sentinelbench.config import (
    INFERENCE_CONTAINER,
    LOGSTASH_CONTAINERS,
    StackEndpoints,
)
from sentinelbench.repo import find_logsentinel_root
from sentinelbench.timeutil import percentiles

OBSERVED_PEAK_EVENTS_PER_SEC = 1875.0


def probe_performance(
    endpoints: StackEndpoints,
    *,
    logsentinel_root: Path | None = None,
    sample_events: int = 5000,
    pipeline_repeats: int = 1,
) -> dict[str, Any]:
    docker = DockerExec(enabled=not endpoints.skip_docker)
    root = find_logsentinel_root(logsentinel_root)
    return {
        "ok": True,
        "docker_stats": _docker_stats(docker),
        "logstash_rate": _logstash_rate(docker),
        "inference_status_counters": _inference_counters(docker),
        "pipeline_throughput": _pipeline_throughput(
            root,
            docker=docker,
            sample_events=sample_events,
            repeats=pipeline_repeats,
        ),
        "reference": {
            "observed_peak_events_per_sec_lab": OBSERVED_PEAK_EVENTS_PER_SEC,
            "reported_inference_events_per_sec": 21200,
        },
    }


def _docker_stats(docker: DockerExec) -> dict[str, Any]:
    containers = [
        INFERENCE_CONTAINER,
        *LOGSTASH_CONTAINERS,
        "logsentinel-elasticsearch",
        "logsentinel-kafka",
        "logsentinel-notifications",
    ]
    import os
    import subprocess

    if not docker.enabled:
        return {"skipped": True}
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"
    try:
        result = subprocess.run(
            [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}",
                *containers,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
            env=env,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return {"error": str(exc)}
    if result.returncode != 0:
        return {"error": result.stderr.strip() or "docker stats failed"}
    rows = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            rows.append(
                {
                    "name": parts[0],
                    "cpu_percent": parts[1],
                    "mem_usage": parts[2],
                    "mem_percent": parts[3],
                }
            )
    return {"containers": rows}


def _logstash_rate(docker: DockerExec) -> dict[str, Any]:
    """Sample pipeline event counters twice and estimate events/s."""
    if not docker.enabled:
        return {"skipped": True}
    first = _logstash_snapshot(docker)
    time.sleep(2.0)
    second = _logstash_snapshot(docker)
    rates: dict[str, Any] = {}
    for container, pipes in first.items():
        later = second.get(container) or {}
        per_pipe = {}
        for name, start in pipes.items():
            end = later.get(name)
            if end is None:
                continue
            din = end["in"] - start["in"]
            dout = end["out"] - start["out"]
            dt = max(0.001, end["t"] - start["t"])
            per_pipe[name] = {
                "events_in_per_sec": round(din / dt, 3),
                "events_out_per_sec": round(dout / dt, 3),
                "delta_in": din,
                "delta_out": dout,
                "sample_sec": round(dt, 3),
            }
        rates[container] = per_pipe
    return {"sample_sec": 2.0, "services": rates}


def _logstash_snapshot(docker: DockerExec) -> dict[str, dict[str, dict[str, float]]]:
    out: dict[str, dict[str, dict[str, float]]] = {}
    now = time.monotonic()
    for container in LOGSTASH_CONTAINERS:
        payload = docker.exec_json(
            container, "curl", "-sf", "http://localhost:9600/_node/stats/pipelines"
        )
        pipes: dict[str, dict[str, float]] = {}
        for name, stats in ((payload or {}).get("pipelines") or {}).items():
            events = stats.get("events") or {}
            pipes[name] = {
                "in": float(events.get("in") or 0),
                "out": float(events.get("out") or 0),
                "t": now,
            }
        out[container] = pipes
    return out


def _inference_counters(docker: DockerExec) -> dict[str, Any]:
    status = docker.exec_json(
        INFERENCE_CONTAINER, "python", "-m", "json.tool", "/tmp/inference.status.json"
    )
    if status is None:
        return {"reachable": False}
    keys = (
        "consumed",
        "invalid",
        "late_events",
        "overflow_events",
        "windows",
        "early_windows",
        "detections",
        "produced",
        "acked",
        "delivery_errors",
        "sysmon_dropped",
    )
    return {"reachable": True, "counters": {key: status.get(key) for key in keys}}


def _pipeline_throughput(
    root: Path | None,
    *,
    docker: DockerExec,
    sample_events: int,
    repeats: int,
) -> dict[str, Any]:
    """Time Pipeline ingest: in-process, repo venv, then inference container."""
    reasons: list[str] = []
    if root is not None:
        fixture = root / "inference" / "tests" / "fixtures" / "sentinelcap-normalized-events.json"
        if fixture.is_file():
            direct = _pipeline_throughput_inprocess(root, fixture, sample_events, repeats)
            if not direct.get("skipped"):
                return direct
            reasons.append(str(direct.get("reason")))
            for candidate in (
                root / ".venv" / "Scripts" / "python.exe",
                root / ".venv" / "bin" / "python",
            ):
                if not candidate.is_file():
                    continue
                via_venv = _pipeline_throughput_subprocess(
                    candidate, root, fixture, sample_events, repeats
                )
                if not via_venv.get("skipped"):
                    via_venv["python"] = str(candidate)
                    via_venv["fallback_from"] = "; ".join(reasons)
                    return via_venv
                reasons.append(f"venv: {via_venv.get('reason')}")
        else:
            reasons.append(f"fixture missing: {fixture}")
    else:
        reasons.append("logsentinel root not found")
    via_docker = _pipeline_throughput_docker(docker, sample_events=sample_events, repeats=repeats)
    if not via_docker.get("skipped"):
        via_docker["fallback_from"] = "; ".join(reasons)
        return via_docker
    reasons.append(f"docker: {via_docker.get('reason')}")
    return {"skipped": True, "reason": "; ".join(reasons)}


def _pipeline_throughput_inprocess(
    root: Path, fixture: Path, sample_events: int, repeats: int
) -> dict[str, Any]:
    import sys

    inference_src = str(root / "inference" / "src")
    training_parent = str(root / "inference")
    for path in (inference_src, training_parent):
        if path not in sys.path:
            sys.path.insert(0, path)
    try:
        from inference.config import load_config  # type: ignore[import-not-found]
        from inference.events import (  # type: ignore[import-not-found]
            InvalidEventError,
            parse_event,
        )
        from inference.pipeline import Pipeline  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        return {"skipped": True, "reason": f"inference import failed: {exc}"}
    return _run_pipeline_bench(
        load_config=load_config,
        parse_event=parse_event,
        invalid_error=InvalidEventError,
        pipeline_cls=Pipeline,
        root=root,
        fixture=fixture,
        sample_events=sample_events,
        repeats=repeats,
    )


def _pipeline_bench_script(
    *,
    root_expr: str,
    fixture_expr: str,
    sample_events: int,
    repeats: int,
    note: str,
) -> str:
    import textwrap

    return textwrap.dedent(
        f"""
        import json, time, sys
        from pathlib import Path
        root = Path({root_expr})
        sys.path[:0] = [str(root / "inference" / "src"), str(root / "inference")]
        from inference.config import load_config
        from inference.events import parse_event
        from inference.pipeline import Pipeline
        fixture = Path({fixture_expr})
        raw = json.loads(fixture.read_text(encoding="utf-8"))
        parsed = []
        for doc in raw:
            try:
                parsed.append(parse_event(doc, partition=0, offset=len(parsed)))
            except Exception:
                pass
        if not parsed:
            print(json.dumps({{"skipped": True, "reason": "no parseable fixture events"}}))
            raise SystemExit(0)
        n = {int(sample_events)}
        stream = (parsed * ((n // len(parsed)) + 1))[:n]
        config = load_config(root / "inference" / "config.yaml")
        timings = []
        for _ in range({int(max(1, repeats))}):
            pipeline = Pipeline(config, None, threshold=0.6)
            t0 = time.perf_counter()
            mono = 0.0
            for event in stream:
                mono += 0.001
                pipeline.process(event, mono)
            timings.append((time.perf_counter() - t0) / len(stream) * 1e6)
        mean = sum(timings) / len(timings)
        eps = 1e6 / mean if mean else None
        print(json.dumps({{
            "skipped": False,
            "events": len(stream),
            "unique_fixture_events": len(parsed),
            "repeats": {int(max(1, repeats))},
            "microseconds_per_event": {{
                "count": float(len(timings)),
                "min": min(timings),
                "max": max(timings),
                "mean": mean,
                "p50": sorted(timings)[len(timings)//2],
            }},
            "events_per_sec": round(eps, 1) if eps else None,
            "vs_lab_peak": round(eps / {OBSERVED_PEAK_EVENTS_PER_SEC}, 2) if eps else None,
            "fixture": str(fixture),
            "note": {note!r},
        }}))
        """
    )


def _pipeline_throughput_subprocess(
    python: Path, root: Path, fixture: Path, sample_events: int, repeats: int
) -> dict[str, Any]:
    import subprocess

    script = _pipeline_bench_script(
        root_expr=repr(str(root)),
        fixture_expr=repr(str(fixture)),
        sample_events=sample_events,
        repeats=repeats,
        note="local Pipeline via repo venv; model=None (Phase 2 path)",
    )
    try:
        completed = subprocess.run(
            [str(python), "-c", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
            cwd=str(root / "inference"),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"skipped": True, "reason": str(exc)}
    if completed.returncode != 0:
        return {
            "skipped": True,
            "reason": (completed.stderr or completed.stdout or "venv pipeline failed")[-500:],
        }
    try:
        return json.loads(completed.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        return {"skipped": True, "reason": f"bad venv JSON: {exc}"}


def _pipeline_throughput_docker(
    docker: DockerExec, *, sample_events: int, repeats: int
) -> dict[str, Any]:
    """Run the bench inside ``logsentinel-inference`` (deps are present)."""
    if not docker.enabled:
        return {"skipped": True, "reason": "docker disabled"}
    n = int(sample_events)
    r = int(max(1, repeats))
    peak = OBSERVED_PEAK_EVENTS_PER_SEC
    # Written as a list of lines so braces are not doubled by an outer f-string.
    script = "\n".join(
        [
            "import json, time",
            "from inference.config import load_config",
            "from inference.events import parse_event",
            "from inference.pipeline import Pipeline",
            "base = {",
            "  '@timestamp': '2026-10-01T00:00:00.000Z',",
            "  'host': {'id': 'bench', 'name': 'bench'},",
            "  'event': {'code': '1'},",
            "  'process': {",
            "    'entity_id': 'e1', 'executable': 'C:\\\\a.exe',",
            "    'command_line': 'a', 'parent': {'entity_id': 'p'},",
            "  },",
            "}",
            f"n = {n}",
            "parsed = []",
            "for i in range(n):",
            "  doc = dict(base)",
            "  doc['@timestamp'] = (",
            "    '2026-10-01T00:%02d:%02d.%03dZ' % ((i // 60) % 60, i % 60, i % 1000)",
            "  )",
            "  proc = dict(base['process'])",
            "  proc['entity_id'] = 'e%d' % i",
            "  doc['process'] = proc",
            "  parsed.append(parse_event(doc, 0, i))",
            "config = load_config()",
            f"repeats = {r}",
            "timings = []",
            "for _ in range(repeats):",
            "  pipeline = Pipeline(config, None, threshold=0.6)",
            "  t0 = time.perf_counter()",
            "  mono = 0.0",
            "  for event in parsed:",
            "    mono += 0.001",
            "    pipeline.process(event, mono)",
            "  timings.append((time.perf_counter() - t0) / len(parsed) * 1e6)",
            "mean = sum(timings) / len(timings)",
            "eps = (1e6 / mean) if mean else None",
            "print(json.dumps({",
            "  'skipped': False,",
            "  'events': len(parsed),",
            "  'unique_fixture_events': len(parsed),",
            "  'repeats': repeats,",
            "  'microseconds_per_event': {",
            "    'count': float(len(timings)),",
            "    'min': min(timings),",
            "    'max': max(timings),",
            "    'mean': mean,",
            "    'p50': sorted(timings)[len(timings) // 2],",
            "  },",
            "  'events_per_sec': round(eps, 1) if eps else None,",
            f"  'vs_lab_peak': round(eps / {peak}, 2) if eps else None,",
            "  'fixture': 'synthetic-in-container',",
            "  'note': 'Pipeline inside logsentinel-inference; model=None',",
            "}))",
        ]
    )
    text = docker.exec(INFERENCE_CONTAINER, "python", "-c", script, timeout_sec=300)
    if text is None:
        # Capture stderr for diagnosis.
        import os
        import subprocess

        env = os.environ.copy()
        env["MSYS_NO_PATHCONV"] = "1"
        try:
            failed = subprocess.run(
                ["docker", "exec", INFERENCE_CONTAINER, "python", "-c", script],
                capture_output=True,
                text=True,
                check=False,
                timeout=300,
                env=env,
            )
            detail = (failed.stderr or failed.stdout or "")[-500:]
        except (OSError, subprocess.TimeoutExpired) as exc:
            detail = str(exc)
        return {"skipped": True, "reason": f"docker exec failed: {detail}"}
    try:
        return json.loads(text.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        return {"skipped": True, "reason": f"bad docker JSON: {exc}; out={text[:300]!r}"}


def _run_pipeline_bench(
    *,
    load_config: Any,
    parse_event: Any,
    invalid_error: type[BaseException],
    pipeline_cls: Any,
    root: Path,
    fixture: Path,
    sample_events: int,
    repeats: int,
) -> dict[str, Any]:
    try:
        raw_events = json.loads(fixture.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"skipped": True, "reason": str(exc)}
    if not isinstance(raw_events, list) or not raw_events:
        return {"skipped": True, "reason": "fixture is empty"}
    parsed = []
    for doc in raw_events:
        try:
            parsed.append(parse_event(doc, partition=0, offset=len(parsed)))
        except (invalid_error, Exception):
            continue
    if not parsed:
        return {"skipped": True, "reason": "no parseable fixture events"}
    stream: list[Any] = []
    while len(stream) < sample_events:
        stream.extend(parsed)
    stream = stream[:sample_events]
    config = load_config(root / "inference" / "config.yaml")
    timings_us: list[float] = []
    for _ in range(max(1, repeats)):
        pipeline = pipeline_cls(config, None, threshold=0.6)
        start = time.perf_counter()
        mono = 0.0
        for event in stream:
            mono += 0.001
            pipeline.process(event, mono)
        elapsed = time.perf_counter() - start
        timings_us.append((elapsed / len(stream)) * 1_000_000.0)
    mean_us = sum(timings_us) / len(timings_us)
    eps = 1_000_000.0 / mean_us if mean_us > 0 else None
    return {
        "skipped": False,
        "events": len(stream),
        "unique_fixture_events": len(parsed),
        "repeats": max(1, repeats),
        "microseconds_per_event": percentiles(timings_us),
        "events_per_sec": round(eps, 1) if eps else None,
        "vs_lab_peak": round(eps / OBSERVED_PEAK_EVENTS_PER_SEC, 2) if eps else None,
        "fixture": str(fixture),
        "note": "local Pipeline only (no Kafka/Logstash); model=None (Phase 2 path)",
    }
