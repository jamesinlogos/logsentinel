"""Standard-library delivery worker; imports never open sockets or read credentials."""

from __future__ import annotations

import hashlib
import json
import math
import os
import smtplib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import parseaddr
from typing import Any

from notifications import formatting

CHANNELS = ("telegram", "gmail")
SCHEMA_VERSION = 2


class ConfigurationError(RuntimeError):
    """Configuration is incomplete; the error names settings but never their values."""


class StoreError(RuntimeError):
    """Elasticsearch could not provide or persist complete, validated state."""


class DeliveryError(RuntimeError):
    """A provider returned an unsuccessful result, with a safe numeric status only."""

    def __init__(self, code: int | None = None) -> None:
        super().__init__("notification provider rejected delivery")
        self.code = code


def utc_now() -> datetime:
    return datetime.now(UTC)


def timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise StoreError("notification timestamp is invalid")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("timezone is required")
        return result.astimezone(UTC)
    except ValueError as exc:
        raise StoreError("notification timestamp is invalid") from exc


@dataclass(frozen=True)
class Settings:
    elasticsearch_url: str
    telegram_bot_token: str
    telegram_chat_id: str
    gmail_sender: str
    gmail_app_password: str
    email_recipients: tuple[str, ...]
    poll_sec: float = 30
    timeout_sec: float = 15


def load_settings(environment: Mapping[str, str] | None = None) -> Settings:
    environment = os.environ if environment is None else environment

    def required(name: str) -> str:
        key = f"LOGSENTINEL_{name}"
        value = environment.get(key, "").strip()
        if not value or "\r" in value or "\n" in value:
            raise ConfigurationError(f"set {key} to a nonempty value without line breaks")
        return value

    def duration(name: str, default: str) -> float:
        try:
            value = float(environment.get(f"LOGSENTINEL_NOTIFICATIONS_{name}", default))
        except ValueError as exc:
            raise ConfigurationError(f"invalid notifications {name.lower()}") from exc
        if not math.isfinite(value) or value <= 0:
            raise ConfigurationError(f"invalid notifications {name.lower()}")
        return value

    base = environment.get("LOGSENTINEL_ES_HOST", "http://elasticsearch:9200").rstrip("/")
    try:
        parsed = urllib.parse.urlsplit(base)
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("invalid Elasticsearch URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (port is not None and port < 1)
    ):
        raise ConfigurationError("use an http(s) Elasticsearch URL without credentials")
    sender = required("GMAIL_SENDER")
    recipients = tuple(part.strip() for part in required("EMAIL_RECIPIENTS").split(","))
    for address in (sender, *recipients):
        if not address or "@" not in address or parseaddr(address)[1] != address:
            raise ConfigurationError("use complete sender and recipient email addresses")
    return Settings(
        base,
        required("TELEGRAM_BOT_TOKEN"),
        required("TELEGRAM_CHAT_ID"),
        sender,
        required("GMAIL_APP_PASSWORD"),
        recipients,
        duration("POLL_SEC", "30"),
        duration("TIMEOUT_SEC", "15"),
    )


@dataclass(frozen=True)
class Envelope:
    event_id: str
    created: datetime
    message: str

    @classmethod
    def from_document(cls, source: Any) -> Envelope:
        event = source.get("event") if isinstance(source, dict) else None
        identifier = event.get("id") if isinstance(event, dict) else None
        message = source.get("message") if isinstance(source, dict) else None
        if (
            not isinstance(identifier, str)
            or not identifier.strip()
            or len(identifier) > 1024
            or not isinstance(message, str)
            or not message.strip()
        ):
            raise StoreError("outbox envelope requires event.id, event.created and message")
        created = event.get("created") if isinstance(event, dict) else None
        return cls(identifier, parse_timestamp(created), message)


def delivery_identity(envelope: Envelope, channel: str) -> tuple[str, str]:
    identifier = hashlib.sha256(f"{envelope.event_id}\0{channel}".encode()).hexdigest()
    return f"ransomware-notification-deliveries-{envelope.created:%Y.%m}", identifier


class Elasticsearch:
    """Read the outbox and read/write receipts; never write the outbox or source indices."""

    def __init__(self, settings: Settings) -> None:
        self.base = settings.elasticsearch_url
        self.timeout_sec = settings.timeout_sec

    def request(self, method: str, path: str, body: Any = None, *, missing: bool = False) -> Any:
        data = None if body is None else json.dumps(body, allow_nan=False).encode()
        request = urllib.request.Request(  # noqa: S310 - configured stack endpoint
            f"{self.base}{path}",
            data=data,
            method=method,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_sec) as response:  # noqa: S310
                result = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            if missing and exc.code == 404:
                return None
            raise StoreError(f"Elasticsearch HTTP {exc.code}") from exc
        except (OSError, ValueError) as exc:
            raise StoreError("Elasticsearch request failed") from exc
        if not isinstance(result, dict) or result.get("error"):
            raise StoreError("Elasticsearch response is invalid")
        return result

    def search_outbox(self, after: list[Any] | None) -> dict[str, Any]:
        body: dict[str, Any] = {
            "size": 200,
            "query": {"match_all": {}},
            "_source": ["event.id", "event.created", "message"],
            "sort": [{"@timestamp": "asc"}, {"event.id": "asc"}],
        }
        if after is not None:
            body["search_after"] = after
        return self.request(
            "GET",
            "/ransomware-notifications-*/_search?ignore_unavailable=true&allow_no_indices=true",
            body,
        )

    def get_receipt(self, index: str, identifier: str) -> dict[str, Any] | None:
        result = self.request("GET", f"/{index}/_doc/{identifier}", missing=True)
        if result is None:
            return None
        if result.get("found") is not True or not isinstance(result.get("_source"), dict):
            raise StoreError("receipt response is invalid")
        return result["_source"]

    def put_receipt(self, index: str, identifier: str, document: dict[str, Any]) -> None:
        result = self.request("PUT", f"/{index}/_doc/{identifier}", document)
        if result.get("result") not in {"created", "updated"}:
            raise StoreError("receipt write was not acknowledged")


class Providers:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def send(self, channel: str, message: str) -> None:
        if channel == "telegram":
            alert = formatting.parse_alert(message)
            body: dict[str, Any] = {"chat_id": self.settings.telegram_chat_id}
            if alert is None:
                body["text"] = message[:4096]
            else:
                body.update(
                    text=formatting.telegram_html(alert),
                    parse_mode="HTML",
                    disable_web_page_preview=True,
                )
            request = urllib.request.Request(
                f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage",
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=self.settings.timeout_sec) as response:
                result = json.loads(response.read())
            if not isinstance(result, dict) or result.get("ok") is not True:
                code = result.get("error_code") if isinstance(result, dict) else None
                raise DeliveryError(code if type(code) is int else None)
        elif channel == "gmail":
            mail = EmailMessage()
            mail["From"] = self.settings.gmail_sender
            mail["To"] = ", ".join(self.settings.email_recipients)
            alert = formatting.parse_alert(message)
            if alert is None:
                mail["Subject"] = "LogSentinel ransomware detection"
                mail.set_content(message)
            else:
                mail["Subject"] = formatting.email_subject(alert)
                mail.set_content(formatting.email_text(alert))
                mail.add_alternative(formatting.email_html(alert), subtype="html")
            with smtplib.SMTP_SSL(
                "smtp.gmail.com",
                465,
                timeout=self.settings.timeout_sec,
                context=ssl.create_default_context(),
            ) as smtp:
                smtp.login(self.settings.gmail_sender, self.settings.gmail_app_password)
                refused = smtp.send_message(mail)
                if refused:
                    raise DeliveryError()
        else:
            raise DeliveryError()


def safe_error(error: Exception) -> dict[str, Any]:
    result: dict[str, Any] = {"type": type(error).__name__}
    code = getattr(error, "code", getattr(error, "smtp_code", None))
    if type(code) is int:
        result["code"] = code
    return result


def emit(action: str, outcome: str, **fields: Any) -> None:
    print(
        json.dumps(
            {
                "@timestamp": timestamp(utc_now()),
                "service.name": "notifications",
                "event.action": action,
                "event.outcome": outcome,
                **fields,
            }
        ),
        flush=True,
    )


class NotificationService:
    def __init__(
        self,
        settings: Settings,
        *,
        store: Any = None,
        providers: Any = None,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        self.settings = settings
        self.store = Elasticsearch(settings) if store is None else store
        self.providers = Providers(settings) if providers is None else providers
        self.now = now

    def delivery(self, envelope: Envelope, channel: str) -> str:
        index, identifier = delivery_identity(envelope, channel)
        existing = self.store.get_receipt(index, identifier)
        attempts = 0
        if existing is not None:
            sentinel = existing.get("logsentinel", {})
            receipt = sentinel.get("notification", {}) if isinstance(sentinel, dict) else {}
            if (
                not isinstance(receipt, dict)
                or receipt.get("id") != envelope.event_id
                or receipt.get("channel") != channel
                or type(receipt.get("sent")) is not bool
                or type(receipt.get("attempts")) is not int
                or receipt["attempts"] < 1
            ):
                raise StoreError("stored notification receipt is invalid")
            if receipt["sent"]:
                return "already_sent"
            attempts = receipt["attempts"]
            if parse_timestamp(receipt.get("retry_at")) > self.now():
                return "pending"
        attempts += 1
        now = self.now()
        receipt = {"id": envelope.event_id, "channel": channel, "sent": False, "attempts": attempts}
        status = "sent"
        try:
            self.providers.send(channel, envelope.message)
            receipt.update(sent=True, sent_at=timestamp(now))
        except Exception as exc:
            status = "failed"
            delay_sec = min(900, 30 * 2 ** min(attempts - 1, 5))
            receipt["retry_at"] = timestamp(now + timedelta(seconds=delay_sec))
            emit(
                "notification_delivery",
                "failure",
                error=safe_error(exc),
                logsentinel={"notification": {"channel": channel}},
            )
        document = {
            "@timestamp": timestamp(now),
            "ecs": {"version": "8.0.0"},
            "event": {
                "kind": "state",
                "module": "logsentinel",
                "dataset": "logsentinel.notification_delivery",
                "id": identifier,
            },
            "logsentinel": {"schema_version": SCHEMA_VERSION, "notification": receipt},
        }
        self.store.put_receipt(index, identifier, document)
        return status

    def poll(self) -> dict[str, Any]:
        stats = dict.fromkeys(("queued", "sent", "already_sent", "pending", "failed"), 0)
        after = None
        while True:
            result = self.store.search_outbox(after)
            shards = result.get("_shards", {}) if isinstance(result, dict) else {}
            if (
                not isinstance(result, dict)
                or result.get("timed_out") is not False
                or result.get("terminated_early") is True
                or not isinstance(shards, dict)
                or type(shards.get("total")) is not int
                or shards["total"] < 0
                or shards.get("failed") != 0
                or shards.get("successful") != shards["total"]
            ):
                raise StoreError("outbox search was incomplete")
            result_hits = result.get("hits")
            hits = result_hits.get("hits") if isinstance(result_hits, dict) else None
            if not isinstance(hits, list):
                raise StoreError("outbox search hits are invalid")
            if not hits:
                break
            envelopes = []
            for hit in hits:
                if (
                    not isinstance(hit, dict)
                    or not isinstance(hit.get("sort"), list)
                    or len(hit["sort"]) != 2
                ):
                    raise StoreError("outbox search sort is invalid")
                envelopes.append(Envelope.from_document(hit.get("_source")))
            next_after = hits[-1]["sort"]
            if next_after == after:
                raise StoreError("outbox pagination did not advance")
            for envelope in envelopes:
                stats["queued"] += 1
                for channel in CHANNELS:
                    stats[self.delivery(envelope, channel)] += 1
            after = next_after
        return {
            "status": "degraded" if stats["pending"] or stats["failed"] else "healthy",
            "stats": stats,
        }
