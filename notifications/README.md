# LogSentinel notifications

Worker that sends the notices of the Kibana rule `ransomware-detections` to Telegram and Gmail. It reads no Kafka
topic, runs no model and never writes the detection, window-score or telemetry indices. Standard library only.

```
rule ─> Index connector ─> ransomware-notifications-YYYY.MM ─> notifications ─┬─> Telegram
        (README.md 9.2)             (envelopes)                                └─> Gmail (SMTP)
                                                                      │
                                       ransomware-notification-deliveries-YYYY.MM  (one receipt per envelope and channel)
```

A notice summarises the matching windows of one rule run (count plus up to 10 examples). A detection is a reported
window, not a confirmed infection, and windows overlap: do not add their activity up.

## Behaviour

* **Envelope**: a document of `ransomware-notifications-*` with `event.id`, `event.created` and `message`. A missing
  field aborts the poll with an error.
* **Format** (`formatting.py`): the worker parses the Kibana `message` (header lines plus one `Host:` block per example
  window) and renders it per channel: Telegram HTML (`parse_mode=HTML`, severity icon, per-host card, indicator list
  with MITRE ids, size-limited to 4096 characters by dropping detail, never by cutting a tag) and an email with a
  `[LogSentinel][CRITICAL|ALERT|WARNING]` subject, a plain-text part and an HTML part. Host-derived values are
  escaped. `CRITICAL` means an example is critical; `WARNING` applies only when every window is shown. `ALERT`
  means some windows are not shown and no example is critical, so their severity is unknown. A partial notice
  counts only hosts in its examples. A message with an incomplete `Host:` block or another layout mismatch
  uses the plain-text fallback, which caps Telegram at 4096 characters (including the TEST notice).
  Indicator labels, MITRE ids and descriptions live in `formatting.INDICATORS`.
* **Receipt**: `_id` = SHA-256 of `event.id`, NUL and the channel (`telegram`, `gmail`); index month = `event.created`
  (UTC). Fields: `logsentinel.notification.{id, channel, sent, attempts, retry_at, sent_at}`. A channel that was
  sent is never sent again; the other channel retries on its own.
* **Retry**: after a failed attempt the next one waits `30 s × 2^(attempts − 1)`, at most 900 s, without limit.
* **At-least-once**: the send and the receipt are not one transaction; a stop in between sends the envelope again.
  With several recipients a partial SMTP refusal also repeats the accepted ones.
* **Poll** (default every 30 s): reads all retained envelopes (pages of 200, sorted by `@timestamp`, `event.id`) and
  looks up their receipts. A timed-out or partial search aborts the poll; nothing is sent from it. Sized for lab
  volume. Run one instance only: receipts are not a lock.
* **Health**: each poll writes `/tmp/notifications-health.json`; `python -m notifications --healthcheck` exits 0 only
  for a current `healthy` heartbeat. `degraded` (a channel waits for a retry) and `unhealthy` (Elasticsearch error)
  report unhealthy. Incomplete configuration exits with code 2 (a restarting container, like `inference`).
* **Logs**: one JSON line per poll (`notification_poll`) and per failed delivery (`notification_delivery`) with the
  exception type and a numeric provider code only: never a token, URL, address or message body.

## Configuration

Compose reads `.env`; the container gets these variables (`docker-compose.yml`).

| Variable | Meaning |
|---|---|
| `LOGSENTINEL_ES_HOST` | Elasticsearch URL (`http://elasticsearch:9200`, set in Compose) |
| `LOGSENTINEL_TELEGRAM_BOT_TOKEN`, `LOGSENTINEL_TELEGRAM_CHAT_ID` | bot (BotFather) and the chat that opened it with `/start`; a group ID can be negative |
| `LOGSENTINEL_GMAIL_SENDER`, `LOGSENTINEL_GMAIL_APP_PASSWORD` | sending account and its [App Password](https://support.google.com/accounts/answer/185833) (2-Step Verification), without spaces; SMTP over TLS to `smtp.gmail.com:465` |
| `LOGSENTINEL_EMAIL_RECIPIENTS` | recipients, comma-separated |
| `LOGSENTINEL_NOTIFICATIONS_POLL_SEC`, `LOGSENTINEL_NOTIFICATIONS_TIMEOUT_SEC` | poll interval (30) and network timeout (15) |

Keep the values in `.env` only: not in documents, commands or logs. `docker compose config` prints them; use
`docker compose config --quiet`. The Telegram token is part of the API URL.

## Operation

```bash
docker compose build notifications     # builds only
docker compose up -d                   # starts the worker with the stack; it sends every envelope that has no receipt yet
docker compose exec notifications python -m notifications --healthcheck
python scripts/notification_test.py --enqueue   # ONE synthetic TEST notice to both channels (real messages)
python scripts/notification_test.py             # read its receipts, send nothing
```

`accepted` means both providers accepted the message, not that anyone read it. Installing the connector and action
in Kibana: `docker compose up -d` does it (service `kibana-init`, which this worker waits for); by hand, `README.md`
section 9.2. Starting the worker and sending a test need the user's consent
(`AGENTS.md` section 7). Two copies of the stack with the same credentials both send: stop the old one after a move.

## Checks

```bash
cd notifications
python -m pytest
python -m ruff check src tests && python -m ruff format --check src tests
python -m mypy
```

The tests use an in-memory store and providers; they send nothing and write to no stack.
