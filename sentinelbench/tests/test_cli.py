"""CLI wiring."""

from __future__ import annotations

from sentinelbench.cli import build_parser, main


def test_parser_accepts_stack_and_components() -> None:
    parser = build_parser()
    args = parser.parse_args(["query", "stack", "--since", "6h", "--format", "json"])
    assert args.target == "stack"
    assert args.since == "6h"
    assert args.format == "json"


def test_parser_evaluate_captures() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["evaluate", "captures", "--evaluation-json", "x.json", "--format", "json"]
    )
    assert args.command == "evaluate"
    assert args.target == "captures"


def test_parser_probe_and_report() -> None:
    parser = build_parser()
    probe = parser.parse_args(["probe", "performance", "--sample-events", "100"])
    assert probe.sample_events == 100
    report = parser.parse_args(["report", "--skip-stack", "--skip-performance"])
    assert report.skip_stack is True


def test_parser_output_flag() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["report", "--skip-performance", "--format", "json", "-o", "out/report.json"]
    )
    assert args.output is not None
    assert args.output.as_posix().endswith("out/report.json")


def test_emit_writes_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from sentinelbench.cli import _emit

    path = tmp_path / "nested" / "report.json"
    _emit('{"ok": true}', path)
    assert path.read_text(encoding="utf-8") == '{"ok": true}\n'


def test_main_rejects_unknown_via_argparse() -> None:
    parser = build_parser()
    try:
        parser.parse_args(["query", "postgres"])
        raised = False
    except SystemExit:
        raised = True
    assert raised


def test_version_flag() -> None:
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
