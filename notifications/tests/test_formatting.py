"""Alert formatting contracts: parsing, escaping, Telegram size limit and email structure."""

from __future__ import annotations

import json
import re
import smtplib
from typing import Any

import pytest

from notifications import formatting, service


@pytest.fixture
def settings() -> service.Settings:
    return service.Settings(
        elasticsearch_url="http://elasticsearch:9200",
        telegram_bot_token="private-telegram-token",
        telegram_chat_id="private-chat",
        gmail_sender="sender@example.invalid",
        gmail_app_password="private-app-password",
        email_recipients=("recipient@example.invalid",),
    )


HEADER = (
    "LogSentinel: reported ransomware detection windows\n"
    "Rule: Ransomware detections\n"
    "Checked at (UTC): 2026-10-20T03:28:24.201Z\n"
    "Matching windows: {total}\n\n"
    "Examples (up to 10 windows; detections do not confirm infection):\n"
)
BLOCK = (
    "Host: {host}\nVerdict: {verdict}\nConfidence: {confidence}\nIndicators: {indicators}\n"
    "Window ID: {window}\nWindow end (UTC): 2026-10-20T03:28:{second:02d}.158Z\n"
)


def message(*blocks: dict[str, Any], total: int | None = None) -> str:
    body = "".join(
        BLOCK.format(
            host=b.get("host", "win-1"),
            verdict=b.get("verdict", "indicator_match"),
            confidence=b.get("confidence", "0.5482"),
            indicators=b.get("indicators", "shadow_copy_deletion,ransom_note_keyword"),
            window=b.get("window", "a" * 64),
            second=b.get("second", 5),
        )
        for b in blocks
    )
    return HEADER.format(total=len(blocks) if total is None else total) + body


def test_parse_reads_header_and_every_window() -> None:
    alert = formatting.parse_alert(
        message(
            {"verdict": "suspicious_ransomware_behavior", "confidence": "0.9138"},
            {"second": 4},
            total=7,
        )
    )

    assert alert is not None
    assert (alert.rule, alert.total, len(alert.windows)) == ("Ransomware detections", 7, 2)
    assert alert.windows[0].confidence == 0.9138
    assert alert.windows[0].indicators == ("shadow_copy_deletion", "ransom_note_keyword")
    assert alert.critical and alert.level == "CRITICAL"


def test_non_detection_messages_are_not_parsed() -> None:
    assert formatting.parse_alert("TEST: LogSentinel notification delivery check.") is None
    assert formatting.parse_alert("") is None
    assert formatting.parse_alert(HEADER.format(total="many")) is None


@pytest.mark.parametrize(
    "notice",
    [
        HEADER.format(total=1) + "Host: win-1\nVerdict: indicator_match\n",
        message({}, total=2) + "Host: win-2\nVerdict: indicator_match\n",
        HEADER.format(total=1)
        + "Host: \nVerdict: indicator_match\nWindow end (UTC): 2026-10-20T03:28:05Z\n",
        HEADER.format(total=1),
        message({"host": ""}),
        message({}).replace("Confidence: 0.5482\n", ""),
        message({}).replace("Indicators: shadow_copy_deletion,ransom_note_keyword\n", ""),
        message({}).replace("Window ID: " + "a" * 64 + "\n", ""),
        message({}).replace("Confidence: 0.5482\n", "Confidence: unknown\n"),
        message({}) + "Extra detail: preserve this\n",
        message({}) + "Preserve this unlabelled detail\n",
        message({}) + "Verdict: suspicious_ransomware_behavior\n",
    ],
)
def test_incomplete_example_uses_plain_text_fallback(notice: str) -> None:
    assert formatting.parse_alert(notice) is None


def test_indicator_only_alert_is_a_warning_and_strong_indicators_come_first() -> None:
    alert = formatting.parse_alert(
        message({"indicators": "ransom_note_keyword,cmd_burst,event_log_tamper"})
    )

    assert alert is not None and alert.level == "WARNING"
    assert alert.hosts[0].indicators[0] == "event_log_tamper"
    assert "🟠" in formatting.telegram_html(alert)


def test_partial_examples_do_not_claim_complete_severity_or_host_count() -> None:
    examples = ({"host": f"example-{index}"} for index in range(10))
    alert = formatting.parse_alert(message(*examples, total=11))
    assert alert is not None and alert.partial and not alert.critical

    assert alert.level == "ALERT"
    assert formatting.email_subject(alert) == (
        "[LogSentinel][ALERT] Ransomware indicators (11 windows)"
    )
    assert "severity of unseen windows is unknown" in formatting.email_text(alert)
    html = formatting.email_html(alert)
    assert ">Hosts in examples<br>" in html
    assert ">Hosts<br>" not in html
    assert "RANSOMWARE ALERT · ALERT" in formatting.telegram_html(alert)
    assert "11 (10 shown)" in formatting.telegram_html(alert)


def test_visible_critical_window_keeps_critical_severity_in_partial_notice() -> None:
    alert = formatting.parse_alert(message({"verdict": "suspicious_ransomware_behavior"}, total=11))
    assert alert is not None and alert.partial and alert.critical

    assert alert.level == "CRITICAL"
    assert "[CRITICAL]" in formatting.email_subject(alert)


def test_telegram_text_is_html_escaped() -> None:
    hostile = "<b>x</b>&<script>"
    alert = formatting.parse_alert(
        message({"host": hostile, "indicators": "<i>weird</i>", "window": "<a href=x>"})
    )
    assert alert is not None

    text = formatting.telegram_html(alert)

    assert hostile not in text and "<script>" not in text and "<a href" not in text
    assert "&lt;b&gt;x&lt;/b&gt;&amp;&lt;script&gt;" in text
    assert "&lt;i&gt;weird&lt;/i&gt;" in text.replace("Weird", "weird")


def test_telegram_stays_within_the_limit_and_keeps_tags_balanced() -> None:
    blocks = [{"host": f"host-{i:03d}-" + "h" * 100, "second": i % 60} for i in range(10)]
    alert = formatting.parse_alert(message(*blocks, total=500))
    assert alert is not None

    text = formatting.telegram_html(alert)

    assert len(text) <= formatting.TELEGRAM_LIMIT
    for tag in ("b", "i", "code"):
        assert text.count(f"<{tag}>") == text.count(f"</{tag}>")
    assert "more host(s) not shown" in text


def test_providers_send_formatted_telegram_and_email(
    settings: service.Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: dict[str, Any] = {}

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def read(self, *args: Any) -> bytes:
            return b'{"ok": true}'

    def open_request(request: Any, timeout: Any = None, **kwargs: Any) -> Response:
        sent["telegram"] = json.loads(request.data)
        return Response()

    class Smtp:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def __enter__(self) -> Smtp:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def login(self, *args: Any) -> None:
            pass

        def send_message(self, mail: Any, **kwargs: Any) -> dict[str, Any]:
            sent["mail"] = mail
            return {}

    monkeypatch.setattr("urllib.request.urlopen", open_request)
    monkeypatch.setattr(smtplib, "SMTP_SSL", Smtp)
    notice = message({"verdict": "suspicious_ransomware_behavior", "confidence": "0.9138"})

    providers = service.Providers(settings)
    providers.send("telegram", notice)
    providers.send("gmail", notice)

    assert sent["telegram"]["parse_mode"] == "HTML"
    assert "RANSOMWARE ALERT · CRITICAL" in sent["telegram"]["text"]
    mail = sent["mail"]
    assert mail["Subject"] == "[LogSentinel][CRITICAL] Ransomware indicators on win-1 (1 window)"
    assert mail.get_content_type() == "multipart/alternative"
    kinds = [part.get_content_type() for part in mail.iter_parts()]
    assert kinds == ["text/plain", "text/html"]
    html = mail.get_body(("html",)).get_content()
    assert "win-1" in html and "91.4%" in html and not re.search(r"<script", html, re.I)

    incomplete = HEADER.format(total=1) + "Host: win-1\nVerdict: indicator_match\n"
    providers.send("telegram", incomplete)
    providers.send("gmail", incomplete)
    assert sent["telegram"]["text"] == incomplete
    assert "parse_mode" not in sent["telegram"]
    fallback_mail = sent["mail"]
    assert fallback_mail.get_content_type() == "text/plain"
    assert fallback_mail.get_content().strip() == incomplete.strip()


def test_email_subject_cannot_be_split_across_lines() -> None:
    assert formatting.parse_alert(message({"host": "evil\r\nBcc: x@example.invalid"})) is None
    alert = formatting.Alert(
        rule="Ransomware detections",
        checked_at="2026-10-20T03:28:24.201Z",
        total=1,
        windows=(
            formatting.Window(
                host="evil\r\nBcc: x@example.invalid",
                verdict="indicator_match",
                confidence=0.5,
                indicators=(),
                window_id="a" * 64,
                end="2026-10-20T03:28:05Z",
            ),
        ),
    )

    subject = formatting.email_subject(alert)

    assert "\r" not in subject and "\n" not in subject
