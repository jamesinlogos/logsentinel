"""Command-line interface for SentinelBench.

Examples::

    sentinelbench query stack
    sentinelbench evaluate captures
    sentinelbench probe performance
    sentinelbench report
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from sentinelbench import __version__
from sentinelbench.captures import evaluate_captures
from sentinelbench.config import StackEndpoints
from sentinelbench.full_report import build_full_report
from sentinelbench.metrics.evaluate import evaluate_stack
from sentinelbench.performance import probe_performance
from sentinelbench.query_components import COMPONENT_QUERIES
from sentinelbench.report import render

COMPONENTS = ("stack", *COMPONENT_QUERIES.keys())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelbench",
        description=(
            "Query the LogSentinel stack and evaluate monitoring quality "
            "(live ops, offline captures, performance, combined report)."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    query = sub.add_parser("query", help="query one component or evaluate the live stack")
    query.add_argument("target", choices=COMPONENTS)
    _add_stack_flags(query)
    _add_output_flags(query)

    evaluate = sub.add_parser(
        "evaluate",
        help="offline capture metrics from evaluation.json (F2/MCC/AUC/TTFD/λ/CI)",
    )
    evaluate.add_argument(
        "target",
        choices=("captures",),
        help="evaluate labelled capture metrics",
    )
    evaluate.add_argument(
        "--evaluation-json",
        type=Path,
        default=None,
        help="path to evaluation.json (default: <repo>/inference/artifacts/evaluation.json)",
    )
    evaluate.add_argument(
        "--logsentinel-root",
        type=Path,
        default=None,
        help="LogSentinel repository root",
    )
    evaluate.add_argument(
        "--run-evaluate",
        action="store_true",
        help="run inference training.evaluate first (can take a long time)",
    )
    evaluate.add_argument(
        "--captures",
        type=Path,
        default=None,
        help="captures directory for --run-evaluate",
    )
    evaluate.add_argument(
        "--holdout",
        action="append",
        default=[],
        metavar="RUN",
        help="holdout run name for --run-evaluate (repeatable)",
    )
    _add_output_flags(evaluate)

    probe = sub.add_parser(
        "probe",
        help="performance probes (docker stats, Logstash rate, local Pipeline)",
    )
    probe.add_argument("target", choices=("performance",))
    _add_stack_flags(probe)
    probe.add_argument("--logsentinel-root", type=Path, default=None)
    probe.add_argument(
        "--sample-events",
        type=int,
        default=5000,
        help="events to feed the local Pipeline probe (default 5000)",
    )
    _add_output_flags(probe)

    report = sub.add_parser(
        "report",
        help="combined report mapped to statistics.md groups 1–9",
    )
    _add_stack_flags(report)
    report.add_argument("--evaluation-json", type=Path, default=None)
    report.add_argument("--logsentinel-root", type=Path, default=None)
    report.add_argument("--run-evaluate", action="store_true")
    report.add_argument("--skip-stack", action="store_true")
    report.add_argument("--skip-performance", action="store_true")
    report.add_argument("--sample-events", type=int, default=5000)
    _add_output_flags(report)
    return parser


def _add_output_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="write the report to PATH instead of stdout",
    )


def _add_stack_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--es", default="http://localhost:9200")
    parser.add_argument("--kibana", default="http://localhost:5601")
    parser.add_argument("--since", default="24h")
    parser.add_argument("--sample-size", type=int, default=200)
    parser.add_argument("--timeout-sec", type=float, default=60.0)
    parser.add_argument("--skip-docker", action="store_true")


def _endpoints(args: argparse.Namespace) -> StackEndpoints:
    return StackEndpoints(
        elasticsearch=getattr(args, "es", "http://localhost:9200"),
        kibana=getattr(args, "kibana", "http://localhost:5601"),
        since=getattr(args, "since", "24h"),
        sample_size=getattr(args, "sample_size", 200),
        timeout_sec=getattr(args, "timeout_sec", 60.0),
        skip_docker=getattr(args, "skip_docker", False),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

    if args.command == "query":
        return _cmd_query(args)
    if args.command == "evaluate":
        return _cmd_evaluate(args)
    if args.command == "probe":
        return _cmd_probe(args)
    if args.command == "report":
        return _cmd_report(args)
    parser.error(f"unknown command {args.command!r}")
    return 2


def _emit(text: str, output: Path | None) -> None:
    """Write rendered output to ``output`` or stdout; always ends with a newline."""
    body = text if text.endswith("\n") else text + "\n"
    if output is None:
        sys.stdout.write(body)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(body, encoding="utf-8", newline="\n")


def _cmd_query(args: argparse.Namespace) -> int:
    endpoints = _endpoints(args)
    if args.target == "stack":
        result = evaluate_stack(endpoints)
        _emit(render(result, fmt=args.format), args.output)
        return 0 if (result.get("summary") or {}).get("ok") else 1
    probe = COMPONENT_QUERIES[args.target]
    body = probe(endpoints)
    payload = {"component": args.target, "result": body} if args.format == "json" else body
    _emit(render(payload, fmt=args.format), args.output)
    return 1 if body.get("reachable") is False else 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    result = evaluate_captures(
        evaluation_json=args.evaluation_json,
        logsentinel_root=args.logsentinel_root,
        run_evaluate=args.run_evaluate,
        captures_dir=args.captures,
        holdout=list(args.holdout or []),
    )
    _emit(render(result, fmt=args.format, kind="captures"), args.output)
    return 0 if result.get("ok") else 1


def _cmd_probe(args: argparse.Namespace) -> int:
    result = probe_performance(
        _endpoints(args),
        logsentinel_root=args.logsentinel_root,
        sample_events=args.sample_events,
    )
    _emit(render(result, fmt=args.format, kind="performance"), args.output)
    return 0 if result.get("ok") else 1


def _cmd_report(args: argparse.Namespace) -> int:
    result = build_full_report(
        _endpoints(args),
        evaluation_json=args.evaluation_json,
        logsentinel_root=args.logsentinel_root,
        run_evaluate=args.run_evaluate,
        skip_stack=args.skip_stack,
        skip_performance=args.skip_performance,
        sample_events=args.sample_events,
    )
    _emit(render(result, fmt=args.format, kind="full_report"), args.output)
    return 0 if (result.get("summary") or {}).get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
