"""init-kibana.sh runs both setup scripts in order and fails unless alerting is really installed.

The two setup scripts are replaced by stubs that print chosen reports.
Nothing here talks to a stack.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "init-kibana.sh"
BASH = shutil.which("bash")
if os.name == "nt":
    git_bash = (
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Git" / "bin" / "bash.exe"
    )
    if git_bash.is_file():
        BASH = str(git_bash)
pytestmark = pytest.mark.skipif(BASH is None, reason="bash is required")


def stub(
    path: Path,
    statuses: list[str],
    exit_codes: list[int] | None = None,
    outputs: list[str] | None = None,
) -> None:
    """A setup script that logs its arguments and answers with the next status of the list."""
    if exit_codes is None:
        failure_statuses = {"failed", "blocked"} if path.stem == "alerting_setup" else {"failed"}
        exit_codes = [int(status in failure_statuses) for status in statuses]
    path.write_text(
        "import json, sys\n"
        f"name = {path.stem!r}\n"
        f"statuses, codes, outputs = {statuses!r}, {exit_codes!r}, {outputs!r}\n"
        "state = __file__ + '.count'\n"
        "try:\n"
        "    n = int(open(state).read())\n"
        "except OSError:\n"
        "    n = 0\n"
        "open(state, 'w').write(str(n + 1))\n"
        "open(__file__ + '.args', 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        "if outputs is None:\n"
        "    print(json.dumps({'status': statuses[min(n, len(statuses) - 1)]}, indent=2))\n"
        "else:\n"
        "    sys.stdout.write(outputs[min(n, len(outputs) - 1)])\n"
        "sys.exit(codes[min(n, len(codes) - 1)])\n",
        encoding="utf-8",
    )


def run(
    tmp_path: Path,
    alerting: list[str],
    notification: list[str],
    alerting_codes: list[int] | None = None,
    alerting_outputs: list[str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    folder = tmp_path / "scripts"
    folder.mkdir()
    shutil.copy(SCRIPT, folder / "init-kibana.sh")
    stub(folder / "alerting_setup.py", alerting, alerting_codes, alerting_outputs)
    stub(folder / "notification_setup.py", notification)
    environment = {
        **os.environ,
        "LOGSENTINEL_ES_HOST": "http://es.test:9200",
        "LOGSENTINEL_KIBANA_HOST": "http://kb.test:5601",
        "LOGSENTINEL_KIBANA_INIT_ATTEMPTS": "3",
        "LOGSENTINEL_KIBANA_INIT_RETRY_SEC": "0",
    }
    done = subprocess.run(
        [BASH or "bash", str(folder / "init-kibana.sh")],
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
        check=False,
    )
    return done, folder


def calls(folder: Path, name: str) -> list[str]:
    path = folder / f"{name}.py.args"
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def test_fresh_stack_creates_the_rule_then_attaches_the_notification(
    tmp_path: Path,
) -> None:
    done, folder = run(tmp_path, ["created"], ["applied"])

    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.index("alerting_setup: created") < done.stdout.index(
        "notification_setup: applied"
    )
    expected = "--es http://es.test:9200 --kibana http://kb.test:5601 --apply"
    assert calls(folder, "alerting_setup") == [expected]
    assert calls(folder, "notification_setup") == [expected]


def test_a_second_run_reports_unchanged_and_succeeds(tmp_path: Path) -> None:
    done, _ = run(tmp_path, ["unchanged"], ["unchanged"])

    assert done.returncode == 0
    assert "alerting_setup: unchanged" in done.stdout
    assert "notification_setup: unchanged" in done.stdout


@pytest.mark.parametrize(("status", "exit_code"), [("blocked", 1), ("ready", 0)])
def test_a_status_that_is_not_installed_fails_at_once_and_skips_the_notification(
    tmp_path: Path, status: str, exit_code: int
) -> None:
    done, folder = run(tmp_path, [status], ["applied"], alerting_codes=[exit_code])

    assert done.returncode == 1
    assert f"alerting_setup: {status}" in done.stdout
    assert len(calls(folder, "alerting_setup")) == 1  # a retry cannot change a decision
    assert calls(folder, "notification_setup") == []


def test_a_failed_run_is_retried_until_it_succeeds(tmp_path: Path) -> None:
    done, folder = run(
        tmp_path, ["failed", "failed", "created"], ["applied"], alerting_codes=[1, 1, 0]
    )

    assert done.returncode == 0, done.stdout + done.stderr
    assert len(calls(folder, "alerting_setup")) == 3
    assert "attempt 1/3 failed" in done.stderr


def test_a_blocked_report_after_a_failed_attempt_stops_retries(tmp_path: Path) -> None:
    done, folder = run(tmp_path, ["failed", "blocked", "created"], ["applied"])

    assert done.returncode == 1
    assert len(calls(folder, "alerting_setup")) == 2
    assert "alerting_setup: blocked" in done.stdout
    assert calls(folder, "notification_setup") == []


@pytest.mark.parametrize("output", ["", "not JSON"])
def test_a_missing_or_invalid_report_fails_without_retry(tmp_path: Path, output: str) -> None:
    done, folder = run(
        tmp_path,
        ["failed"],
        ["applied"],
        alerting_codes=[1],
        alerting_outputs=[output],
    )

    assert done.returncode == 1
    assert len(calls(folder, "alerting_setup")) == 1
    assert "invalid or missing status report (exit 1)" in done.stderr
    assert calls(folder, "notification_setup") == []


def test_a_run_that_keeps_failing_ends_with_its_report_and_exit_code_1(
    tmp_path: Path,
) -> None:
    done, folder = run(tmp_path, ["failed"], ["applied"], alerting_codes=[1])

    assert done.returncode == 1
    assert len(calls(folder, "alerting_setup")) == 3
    assert json.loads(done.stdout[done.stdout.index("{") :]) == {"status": "failed"}
    assert calls(folder, "notification_setup") == []


def test_the_notification_setup_failing_fails_the_whole_init(tmp_path: Path) -> None:
    done, _ = run(tmp_path, ["created"], ["blocked"])

    assert done.returncode == 1
    assert "alerting_setup: created" in done.stdout
    assert "notification_setup: blocked" in done.stdout
