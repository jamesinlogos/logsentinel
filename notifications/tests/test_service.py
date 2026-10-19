"""Notification delivery contracts using in-memory stores and providers only."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

import pytest

from notifications import service

ROOT = Path(__file__).resolve().parents[2]
CREATED = datetime(2026, 10, 19, 13, 0, tzinfo=UTC)


@pytest.fixture
def settings() -> service.Settings:
    return service.Settings(
        elasticsearch_url="http://elasticsearch:9200",
        telegram_bot_token="private-telegram-token",
        telegram_chat_id="private-chat",
        gmail_sender="sender@example.invalid",
        gmail_app_password="private-app-password",
        email_recipients=("recipient@example.invalid",),
        poll_sec=30,
        timeout_sec=15,
    )


def outbox_document(event_id: str = "rule:alert:20261019T130000Z") -> dict[str, Any]:
    return {
        "@timestamp": CREATED.isoformat(),
        "ecs": {"version": "8.0.0"},
        "event": {
            "id": event_id,
            "created": CREATED.isoformat(),
            "kind": "alert",
            "module": "logsentinel",
            "dataset": "logsentinel.notification",
        },
        "logsentinel": {"schema_version": 2},
        "message": "Ransomware detections: 12 total; examples: victim-host.",
    }


class MemoryStore:
    """Keep Elasticsearch request outcomes and receipt commits visible to tests."""

    def __init__(self, sources: list[dict[str, Any]] | None = None) -> None:
        self.sources = sources if sources is not None else [outbox_document()]
        self.receipts: dict[tuple[str, str], dict[str, Any]] = {}
        self.writes: list[dict[str, Any]] = []
        self.timeline: list[tuple[str, str]] = []
        self.searches: list[list[Any] | None] = []
        self.page_size = 100
        self.search_override: dict[str, Any] | None = None
        self.fail_writes = False

    def search_outbox(self, after: list[Any] | None = None) -> dict[str, Any]:
        self.searches.append(copy.deepcopy(after))
        if self.search_override is not None:
            return copy.deepcopy(self.search_override)
        hits = [
            {
                "_index": "ransomware-notifications-2026.10",
                "_id": str(index),
                "_source": copy.deepcopy(source),
                "sort": [source.get("@timestamp"), source.get("event", {}).get("id")],
            }
            for index, source in enumerate(self.sources)
        ]
        if after is not None:
            hits = [hit for hit in hits if hit["sort"] > after]
        return {
            "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "failed": 0},
            "hits": {
                "total": {"value": len(self.sources), "relation": "eq"},
                "hits": hits[: self.page_size],
            },
        }

    def get_receipt(self, index: str, identity: str) -> dict[str, Any] | None:
        return copy.deepcopy(self.receipts.get((index, identity)))

    def put_receipt(self, index: str, identity: str, document: dict[str, Any]) -> None:
        if self.fail_writes:
            raise service.StoreError("receipt store unavailable")
        self.receipts[index, identity] = copy.deepcopy(document)
        self.writes.append(copy.deepcopy(document))
        notification = document["logsentinel"]["notification"]
        self.timeline.append(("receipt", notification["channel"]))


class MemoryProviders:
    def __init__(self, timeline: list[tuple[str, str]] | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self.failures: dict[str, list[Exception]] = {}
        self.timeline = timeline if timeline is not None else []

    def send(self, channel: str, message: str) -> None:
        self.calls.append((channel, message))
        failures = self.failures.get(channel, [])
        if failures:
            raise failures.pop(0)
        self.timeline.append(("accepted", channel))


def worker(
    settings: service.Settings,
    store: MemoryStore,
    providers: MemoryProviders,
    now: datetime = CREATED,
) -> service.NotificationService:
    return service.NotificationService(settings, store=store, providers=providers, now=lambda: now)


def test_receipt_identity_uses_event_id_channel_and_creation_month() -> None:
    source = outbox_document()
    source["event"]["created"] = "2026-11-01T00:15:00+02:00"
    envelope = service.Envelope.from_document(source)

    index, identity = service.delivery_identity(envelope, "telegram")

    assert index == "ransomware-notification-deliveries-2026.10"
    assert identity == hashlib.sha256((source["event"]["id"] + "\0telegram").encode()).hexdigest()
    assert service.delivery_identity(envelope, "gmail")[1] != identity


def test_success_is_recorded_only_after_each_provider_accepts(settings: service.Settings) -> None:
    store = MemoryStore()
    providers = MemoryProviders(store.timeline)

    health = worker(settings, store, providers).poll()

    assert health["status"] == "healthy"
    assert {channel for channel, _ in providers.calls} == {"telegram", "gmail"}
    assert len(store.receipts) == 2
    for receipt in store.receipts.values():
        notification = receipt["logsentinel"]["notification"]
        channel = notification["channel"]
        assert notification["sent"] is True
        assert notification["attempts"] == 1
        assert "sent_at" in notification
        assert "retry_at" not in notification
        assert store.timeline.index(("accepted", channel)) < store.timeline.index(
            ("receipt", channel)
        )
        assert receipt["logsentinel"]["schema_version"] == 2
        assert receipt["event"]["dataset"] == "logsentinel.notification_delivery"
        assert receipt["event"]["kind"] == "state"
        assert receipt["event"]["module"] == "logsentinel"
        assert "message" not in receipt
        assert "private-" not in json.dumps(receipt)


def test_restarted_worker_skips_delivered_channels_and_duplicate_envelopes(
    settings: service.Settings,
) -> None:
    source = outbox_document()
    store = MemoryStore([source, copy.deepcopy(source)])
    providers = MemoryProviders()

    worker(settings, store, providers).poll()
    worker(settings, store, providers, CREATED + timedelta(hours=1)).poll()

    assert len(providers.calls) == 2
    assert len(store.writes) == 2


def test_failed_channel_retries_independently_without_resending_success(
    settings: service.Settings,
) -> None:
    store = MemoryStore()
    providers = MemoryProviders()
    providers.failures["gmail"] = [RuntimeError("smtp secret body")]

    first = worker(settings, store, providers).poll()
    pending = next(
        receipt["logsentinel"]["notification"]
        for receipt in store.receipts.values()
        if not receipt["logsentinel"]["notification"]["sent"]
    )
    retry_at = datetime.fromisoformat(pending["retry_at"].replace("Z", "+00:00"))

    assert first["status"] == "degraded"
    assert pending["attempts"] == 1
    assert "sent_at" not in pending
    assert retry_at > CREATED
    assert "smtp secret body" not in json.dumps(first)

    worker(settings, store, providers, retry_at - timedelta(microseconds=1)).poll()
    assert len(providers.calls) == 2

    second = worker(settings, store, providers, retry_at + timedelta(seconds=1)).poll()
    assert second["status"] == "healthy"
    assert [channel for channel, _ in providers.calls].count("telegram") == 1
    assert [channel for channel, _ in providers.calls].count("gmail") == 2
    assert all(r["logsentinel"]["notification"]["sent"] for r in store.receipts.values())


def test_repeated_failure_increases_retry_delay(settings: service.Settings) -> None:
    store = MemoryStore()
    providers = MemoryProviders()
    providers.failures["gmail"] = [RuntimeError("first"), RuntimeError("second")]
    worker(settings, store, providers).poll()
    first = next(
        r["logsentinel"]["notification"]
        for r in store.receipts.values()
        if r["logsentinel"]["notification"]["channel"] == "gmail"
    )
    retry = datetime.fromisoformat(first["retry_at"].replace("Z", "+00:00"))
    worker(settings, store, providers, retry).poll()
    second = next(
        r["logsentinel"]["notification"]
        for r in store.receipts.values()
        if r["logsentinel"]["notification"]["channel"] == "gmail"
    )
    next_retry = datetime.fromisoformat(second["retry_at"].replace("Z", "+00:00"))

    assert second["attempts"] == 2
    assert next_retry - retry > retry - CREATED


def test_pagination_continues_past_first_page(settings: service.Settings) -> None:
    store = MemoryStore([outbox_document("a"), outbox_document("b"), outbox_document("c")])
    store.page_size = 1
    providers = MemoryProviders()

    worker(settings, store, providers).poll()

    assert len(providers.calls) == 6
    assert store.searches[0] is None
    assert any(after == [CREATED.isoformat(), "b"] for after in store.searches)


@pytest.mark.parametrize("failure", ["timeout", "failed-shard", "missing-shard"])
def test_partial_search_never_sends_or_writes(settings: service.Settings, failure: str) -> None:
    store = MemoryStore()
    result = store.search_outbox()
    if failure == "timeout":
        result["timed_out"] = True
    elif failure == "failed-shard":
        result["_shards"]["failed"] = 1
    else:
        result["_shards"]["successful"] = 0
    store.search_override = result
    providers = MemoryProviders()

    with pytest.raises(service.StoreError):
        worker(settings, store, providers).poll()

    assert providers.calls == []
    assert store.writes == []


@pytest.mark.parametrize("field", ["id", "created", "message"])
def test_invalid_envelope_never_sends(settings: service.Settings, field: str) -> None:
    source = outbox_document()
    if field == "message":
        source["message"] = {"raw": "payload"}
    else:
        source["event"][field] = "" if field == "id" else "not-a-date"
    store = MemoryStore([source])
    providers = MemoryProviders()

    with pytest.raises(service.StoreError):
        worker(settings, store, providers).poll()

    assert providers.calls == []
    assert store.writes == []


def test_empty_outbox_is_healthy(settings: service.Settings) -> None:
    store = MemoryStore([])
    providers = MemoryProviders()

    assert worker(settings, store, providers).poll()["status"] == "healthy"
    assert providers.calls == []
    assert store.writes == []


def test_corrupt_success_receipt_does_not_skip_delivery_silently(
    settings: service.Settings,
) -> None:
    store = MemoryStore()
    providers = MemoryProviders()
    envelope = service.Envelope.from_document(outbox_document())
    identity = service.delivery_identity(envelope, "telegram")
    store.receipts[identity] = {
        "logsentinel": {
            "notification": {
                "id": "different-event",
                "channel": "telegram",
                "sent": True,
                "attempts": 1,
            }
        }
    }

    with pytest.raises(service.StoreError):
        worker(settings, store, providers).poll()

    assert providers.calls == []
    assert store.writes == []


def test_receipt_failure_after_acceptance_is_not_reported_as_delivered(
    settings: service.Settings,
) -> None:
    store = MemoryStore()
    store.fail_writes = True
    providers = MemoryProviders()

    with pytest.raises(service.StoreError):
        worker(settings, store, providers).poll()

    assert len(providers.calls) == 1
    assert store.receipts == {}


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("secret provider body and message"),
        HTTPError("https://api.telegram.org/botSECRET/sendMessage", 401, "SECRET", {}, None),
    ],
)
def test_error_metadata_never_contains_exception_message_or_url(error: Exception) -> None:
    safe = service.safe_error(error)

    assert safe["type"] == type(error).__name__
    assert "secret" not in json.dumps(safe).lower()
    assert "http" not in json.dumps(safe).lower().replace("httperror", "")


def test_failure_log_omits_credentials_provider_url_and_notification_body(
    settings: service.Settings, capsys: pytest.CaptureFixture[str]
) -> None:
    store = MemoryStore()
    providers = MemoryProviders()
    providers.failures["telegram"] = [
        HTTPError(
            "https://api.telegram.org/botprivate-telegram-token/sendMessage",
            401,
            "private-app-password: Ransomware detections: 12 total",
            {},
            None,
        )
    ]

    worker(settings, store, providers).poll()
    output = capsys.readouterr().out

    assert "private-" not in output
    assert "api.telegram.org" not in output
    assert "Ransomware detections" not in output
    assert json.loads(output)["error"]["code"] == 401


def mapped_fields() -> set[str]:
    """Fields of the detection mapping (``dynamic: false``: an unmapped field is not searchable)."""
    path = ROOT / "config/elasticsearch/component-templates/logsentinel-window-score.json"
    mappings = json.loads(path.read_text(encoding="utf-8"))["template"]["mappings"]

    def walk(node: dict[str, Any], prefix: str = "") -> set[str]:
        found: set[str] = set()
        for name, definition in node.get("properties", {}).items():
            if "type" in definition:
                found.add(prefix + name)
            found |= walk(definition, f"{prefix}{name}.")
        return found

    return walk(mappings)


def test_notice_and_rule_read_only_mapped_detection_fields() -> None:
    fields = mapped_fields()
    action_path = ROOT / "config/kibana/actions/ransomware-notifications.json"
    action = json.loads(action_path.read_text(encoding="utf-8"))
    message = action["params"]["documents"][0]["message"]
    used = set(re.findall(r"\{\{_source\.([a-z_.]+)\}\}", message))
    assert used
    assert used <= fields, sorted(used - fields)

    rule = json.loads(
        (ROOT / "config/kibana/rules/ransomware-detections.json").read_text(encoding="utf-8")
    )
    filters = json.loads(rule["params"]["esQuery"])["query"]["bool"]["filter"]
    queried = {name for item in filters for clause in item.values() for name in clause}
    assert queried <= fields, sorted(queried - fields)
    assert rule["params"]["timeField"] in fields


def test_compose_gives_the_worker_every_variable_it_requires() -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    block = text.split("\n  notifications:\n", 1)[1].split("\n\nnetworks:", 1)[0]
    names = re.findall(r"^\s+- (LOGSENTINEL_[A-Z0-9_]+)=", block, flags=re.MULTILINE)
    assert names
    environment = {
        name: "name@example.invalid" if name.endswith(("SENDER", "RECIPIENTS")) else "1"
        for name in names
    }
    environment["LOGSENTINEL_ES_HOST"] = "http://elasticsearch:9200"
    service.load_settings(environment)  # raises ConfigurationError when Compose omits one


def test_canonical_action_envelope_uses_formatted_message_and_shared_schema() -> None:
    path = ROOT / "config/kibana/actions/ransomware-notifications.json"
    action = json.loads(path.read_text(encoding="utf-8"))
    document = action["params"]["documents"][0]
    message = document.pop("message")

    assert document["logsentinel"]["schema_version"] == service.SCHEMA_VERSION == 2
    assert document["ecs"]["version"]
    assert document["event"]["dataset"] == "logsentinel.notification"
    assert document["event"]["id"] == "{{rule.id}}:{{alert.uuid}}:{{context.date}}"
    assert document["event"]["created"] == "{{context.date}}"
    assert "context.hits" not in json.dumps(document)
    assert "{{context.value}}" in message
    assert "{{#context.hits}}" in message
    assert "up to 10" in message
    assert "do not confirm infection" in message
    assert "_source.process.command_line" not in message


def test_configuration_defaults_and_rejects_secret_bearing_url() -> None:
    environment = {
        "LOGSENTINEL_TELEGRAM_BOT_TOKEN": "private-token",
        "LOGSENTINEL_TELEGRAM_CHAT_ID": "123",
        "LOGSENTINEL_GMAIL_SENDER": "sender@example.invalid",
        "LOGSENTINEL_GMAIL_APP_PASSWORD": "private-password",
        "LOGSENTINEL_EMAIL_RECIPIENTS": "one@example.invalid, two@example.invalid",
    }
    settings = service.load_settings(environment)
    assert settings.poll_sec == 30
    assert settings.timeout_sec == 15
    assert settings.email_recipients == ("one@example.invalid", "two@example.invalid")

    environment["LOGSENTINEL_ES_HOST"] = "http://user:private-url-password@host:9200"
    with pytest.raises(service.ConfigurationError) as failure:
        service.load_settings(environment)

    assert "private-" not in str(failure.value)


@pytest.mark.parametrize(
    ("status", "age_sec", "expected"),
    [("healthy", 1, 0), ("degraded", 1, 1), ("unhealthy", 1, 1), ("healthy", 121, 1)],
)
def test_healthcheck_requires_current_healthy_heartbeat(
    status: str,
    age_sec: int,
    expected: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from notifications import __main__ as command

    health_path = tmp_path / "health.json"
    health_path.write_text(
        json.dumps(
            {
                "status": status,
                "checked_at": service.timestamp(CREATED - timedelta(seconds=age_sec)),
                "max_age_sec": 120,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(command, "HEALTH_PATH", health_path)
    monkeypatch.setattr(command, "utc_now", lambda: CREATED)

    assert command.healthcheck() == expected


def test_provider_telegram_uses_verified_tls_plain_text_and_bounded_message(
    settings: service.Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Any, Any, dict[str, Any]]] = []

    class Response:
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def read(self, *args: Any) -> bytes:
            return b'{"ok": true, "result": {"message_id": 1}}'

    def open_request(request: Any, timeout: Any = None, **kwargs: Any) -> Response:
        calls.append((request, timeout, kwargs))
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", open_request)
    service.Providers(settings).send("telegram", "\U0001f512" * 5000)

    request, timeout, options = calls[0]
    payload = json.loads(request.data)
    assert request.get_method() == "POST"
    assert request.full_url.startswith("https://api.telegram.org/")
    assert payload["chat_id"] == settings.telegram_chat_id
    assert len(payload["text"]) <= 4096
    assert "parse_mode" not in payload
    assert timeout == settings.timeout_sec
    context = options.get("context")
    if context is not None:
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True


def test_provider_email_uses_verified_tls_and_authenticates_sender(
    settings: service.Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: dict[str, Any] = {}

    class Smtp:
        def __init__(self, host: str, port: int, **kwargs: Any) -> None:
            calls.update(host=host, port=port, **kwargs)

        def __enter__(self) -> Smtp:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def login(self, username: str, password: str) -> None:
            calls["login"] = (username, password)

        def send_message(self, message: Any, **kwargs: Any) -> dict[str, Any]:
            calls["message"] = message
            return {}

    monkeypatch.setattr("smtplib.SMTP_SSL", Smtp)
    service.Providers(settings).send("gmail", "Detection summary")

    assert calls["host"] == "smtp.gmail.com"
    assert calls["port"] == 465
    assert calls["login"] == (settings.gmail_sender, settings.gmail_app_password)
    assert calls["message"]["From"] == settings.gmail_sender
    assert calls["message"]["To"] == ", ".join(settings.email_recipients)
    assert calls["message"].get_content_type() == "text/plain"
    assert "Detection summary" in calls["message"].get_content()
    assert calls["context"].verify_mode == ssl.CERT_REQUIRED
    assert calls["context"].check_hostname is True
