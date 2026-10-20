"""Turn the plain-text Kibana notice into a readable Telegram (HTML) and email (text + HTML) alert.

The Kibana action template stays unchanged: ``parse_alert`` reads its fixed layout (header lines,
then one ``Host:`` block per example window). A message that does not match that layout (for
example the synthetic TEST notice) returns ``None`` and the caller sends it as plain text, so a
format change in the template can degrade the look of a notice but never lose it.

Everything that comes from the monitored hosts (host names, window IDs, indicator names) is
HTML-escaped and length-capped before it reaches a message.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape

SUSPICIOUS = "suspicious_ransomware_behavior"
TELEGRAM_LIMIT = 4096
MAX_HOSTS_TELEGRAM = 5
MAX_FIELD = 128

# name: (label, MITRE ATT&CK technique ids, one-line meaning)
INDICATORS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "mass_note_drop": (
        "Mass ransom-note drop",
        ("T1486",),
        "Many note-like files created in a short time",
    ),
    "mass_file_replace": (
        "Mass file replacement",
        ("T1486",),
        "Many files rewritten or replaced (encryption pattern)",
    ),
    "shadow_copy_deletion": (
        "Shadow copy deletion",
        ("T1490",),
        "Volume shadow copies deleted, removing restore points",
    ),
    "recovery_disable": (
        "Recovery disabled",
        ("T1490",),
        "Windows recovery options switched off",
    ),
    "service_stop_burst": (
        "Service stop burst",
        ("T1489",),
        "Many services stopped in a short time",
    ),
    "event_log_tamper": (
        "Event log tampering",
        ("T1070.001", "T1562.002"),
        "Windows event logs cleared or logging disabled",
    ),
    "ransom_note_keyword": (
        "Ransom-note keyword",
        ("T1486",),
        "Created files match ransom-note keywords",
    ),
    "cmd_burst": (
        "Command burst",
        ("T1059.003",),
        "Burst of child processes started from one command shell",
    ),
    "run_key_persistence": (
        "Run-key persistence",
        ("T1547.001",),
        "Autostart registry key written",
    ),
    "lolbins_execution": (
        "LOLBin execution",
        ("T1218",),
        "Built-in Windows binaries used to run code",
    ),
    "security_policy_tamper": (
        "Security policy tampering",
        ("T1548.002", "T1562.001"),
        "Security settings changed",
    ),
    "remote_thread_injection": (
        "Remote thread injection",
        ("T1055",),
        "Thread created inside another process",
    ),
    "process_tampering": (
        "Process tampering",
        ("T1055",),
        "Process memory or image altered",
    ),
}

STRONG = frozenset(
    {
        "mass_note_drop",
        "mass_file_replace",
        "shadow_copy_deletion",
        "recovery_disable",
        "service_stop_burst",
        "event_log_tamper",
    }
)

VERDICTS = {
    SUSPICIOUS: "Suspicious ransomware behavior",
    "indicator_match": "Indicator match",
}


@dataclass(frozen=True)
class Window:
    host: str
    verdict: str
    confidence: float | None
    indicators: tuple[str, ...]
    window_id: str
    end: str


@dataclass(frozen=True)
class Alert:
    rule: str
    checked_at: str
    total: int
    windows: tuple[Window, ...]

    @property
    def critical(self) -> bool:
        return any(window.verdict == SUSPICIOUS for window in self.windows)

    @property
    def partial(self) -> bool:
        return len(self.windows) < self.total

    @property
    def level(self) -> str:
        if self.critical:
            return "CRITICAL"
        return "ALERT" if self.partial else "WARNING"

    @property
    def hosts(self) -> list[Host]:
        grouped: dict[str, list[Window]] = {}
        for window in self.windows:
            grouped.setdefault(window.host, []).append(window)
        hosts = [Host(name, tuple(items)) for name, items in grouped.items()]
        return sorted(hosts, key=lambda host: (not host.critical, -(host.confidence or 0)))


@dataclass(frozen=True)
class Host:
    name: str
    windows: tuple[Window, ...]

    @property
    def critical(self) -> bool:
        return any(window.verdict == SUSPICIOUS for window in self.windows)

    @property
    def confidence(self) -> float | None:
        values = [w.confidence for w in self.windows if w.confidence is not None]
        return max(values) if values else None

    @property
    def last_seen(self) -> str:
        return max((window.end for window in self.windows), default="")

    @property
    def top_window(self) -> Window:
        return max(self.windows, key=lambda window: window.confidence or 0)

    @property
    def indicators(self) -> list[str]:
        """Distinct indicators of all windows: strong ones first, then most frequent."""
        counts: dict[str, int] = {}
        for window in self.windows:
            for name in window.indicators:
                counts[name] = counts.get(name, 0) + 1
        return sorted(counts, key=lambda name: (name not in STRONG, -counts[name]))


# --------------------------------------------------------------------------- parsing

_FIELD = re.compile(r"^([A-Za-z][A-Za-z ()]*?):\s*(.*)$")
_HEADER_FIELDS = frozenset({"LogSentinel", "Rule", "Checked at (UTC)", "Matching windows"})
_BLOCK_FIELDS = frozenset(
    {"Host", "Verdict", "Confidence", "Indicators", "Window ID", "Window end (UTC)"}
)
_EXAMPLES_LINE = "Examples (up to 10 windows; detections do not confirm infection):"


def _number(value: str) -> float | None:
    try:
        result = float(value)
    except ValueError:
        return None
    return result if 0 <= result <= 1 else None


def parse_alert(message: str) -> Alert | None:
    """Return the structured alert, or ``None`` when ``message`` is not a detection notice."""
    header: dict[str, str] = {}
    blocks: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    has_examples_line = False
    for raw in message.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _FIELD.match(line)
        if match is None:
            if current is None and line == _EXAMPLES_LINE and not has_examples_line:
                has_examples_line = True
                continue
            return None
        key, value = match.group(1), match.group(2).strip()
        if key == "Host":
            if not has_examples_line:
                return None
            current = {}
            blocks.append(current)
        if current is not None:
            if key not in _BLOCK_FIELDS or key in current:
                return None
            current[key] = value
        else:
            if has_examples_line or key not in _HEADER_FIELDS or key in header:
                return None
            header[key] = value
    if header.get("LogSentinel") != "reported ransomware detection windows":
        return None
    if not has_examples_line:
        return None
    if not all(header.get(key) for key in ("Rule", "Checked at (UTC)", "Matching windows")):
        return None
    try:
        total = int(header["Matching windows"])
    except ValueError:
        return None
    if not blocks or not 0 < len(blocks) <= total:
        return None
    windows = []
    for block in blocks:
        if block.keys() != _BLOCK_FIELDS:
            return None
        if not all(block[key] for key in ("Host", "Verdict", "Window end (UTC)")):
            return None
        confidence = _number(block["Confidence"])
        if block["Confidence"] and confidence is None:
            return None
        indicators = tuple(
            name.strip()[:MAX_FIELD] for name in block["Indicators"].split(",") if name.strip()
        )
        windows.append(
            Window(
                host=block["Host"][:MAX_FIELD] or "unknown",
                verdict=block["Verdict"][:MAX_FIELD],
                confidence=confidence,
                indicators=indicators,
                window_id=block["Window ID"][:MAX_FIELD],
                end=block["Window end (UTC)"][:MAX_FIELD],
            )
        )
    return Alert(
        header["Rule"][:MAX_FIELD], header["Checked at (UTC)"][:MAX_FIELD], total, tuple(windows)
    )


# --------------------------------------------------------------------------- shared helpers


def _when(value: str, *, date: bool = True) -> str:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return value
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC" if date else "%H:%M:%S")


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _bar(value: float | None, cells: int = 10) -> str:
    filled = 0 if value is None else round(value * cells)
    return "█" * filled + "░" * (cells - filled)


def _indicator(name: str) -> tuple[str, tuple[str, ...], str]:
    known = INDICATORS.get(name)
    return known if known else (name.replace("_", " ").capitalize(), (), "")


def _verdict(name: str) -> str:
    return VERDICTS.get(name, name.replace("_", " ").capitalize())


def _headline(alert: Alert) -> str:
    if alert.critical:
        return "Suspicious ransomware behavior detected"
    if alert.partial:
        return "Ransomware indicators matched; severity of unseen windows is unknown"
    return "Ransomware indicators matched"


def _count_line(alert: Alert) -> str:
    shown = len(alert.windows)
    return f"{alert.total} ({shown} shown)" if shown < alert.total else str(alert.total)


DISCLAIMER = "A detection is a reported window, not a confirmed infection. Windows overlap."


# --------------------------------------------------------------------------- Telegram (HTML)


def _telegram(alert: Alert, hosts: int, windows: int) -> str:
    icon = "🔴" if alert.critical else "🔵" if alert.partial else "🟠"
    lines = [
        f"{icon} <b>RANSOMWARE ALERT · {alert.level}</b>",
        f"<i>{escape(_headline(alert))}</i>",
        "",
        f"🪟 <b>Matching windows:</b> {escape(_count_line(alert))}",
    ]
    ordered = alert.hosts
    for host in ordered[:hosts]:
        top = host.top_window
        lines += [
            "",
            f"🖥 <b>Host:</b> <code>{escape(host.name)}</code>",
            f"⚠️ <b>Verdict:</b> {escape(_verdict(top.verdict))}",
            f"📊 <b>Confidence:</b> {_percent(host.confidence)} "
            f"<code>{_bar(host.confidence)}</code>",
            f"🕒 <b>Last window:</b> {escape(_when(host.last_seen))}",
            "🔎 <b>Indicators</b>",
        ]
        for name in host.indicators:
            label, techniques, _ = _indicator(name)
            tag = f" <i>({escape(', '.join(techniques))})</i>" if techniques else ""
            lines.append(f"  • {escape(label)}{tag}")
        if top.window_id:
            lines.append(f"🆔 <b>Top window:</b> <code>{escape(top.window_id)}</code>")
        if windows and len(host.windows) > 1:
            lines.append("📋 <b>Windows</b>")
            for window in sorted(host.windows, key=lambda w: w.end, reverse=True)[:windows]:
                icon = "🔴" if window.verdict == SUSPICIOUS else "🟡"
                lines.append(
                    f"  {icon} <code>{escape(_when(window.end, date=False))}</code> · "
                    f"{_percent(window.confidence)} · {escape(_verdict(window.verdict))}"
                )
    if len(ordered) > hosts:
        lines += ["", f"➕ <i>{len(ordered) - hosts} more host(s) not shown</i>"]
    lines += [
        "",
        f"<i>Rule: {escape(alert.rule)} · Checked {escape(_when(alert.checked_at))}</i>",
        f"<i>{escape(DISCLAIMER)}</i>",
    ]
    return "\n".join(lines)


def telegram_html(alert: Alert) -> str:
    """Telegram HTML text; shrinks by dropping detail, never by cutting inside a tag."""
    for hosts, windows in (
        (MAX_HOSTS_TELEGRAM, 10),
        (MAX_HOSTS_TELEGRAM, 3),
        (MAX_HOSTS_TELEGRAM, 0),
        (2, 0),
        (1, 0),
        (0, 0),
    ):
        text = _telegram(alert, hosts, windows)
        if len(text) <= TELEGRAM_LIMIT:
            return text
    return text[:TELEGRAM_LIMIT]  # pragma: no cover - the (0, 0) form is a few hundred bytes


# --------------------------------------------------------------------------- Email


def email_subject(alert: Alert) -> str:
    hosts = alert.hosts
    if alert.partial:
        target = ""
    elif len(hosts) == 1:
        target = f"on {hosts[0].name}"
    elif hosts:
        target = f"on {len(hosts)} hosts"
    else:
        target = ""
    noun = "window" if alert.total == 1 else "windows"
    subject = f"[LogSentinel][{alert.level}] Ransomware indicators {target} ({alert.total} {noun})"
    return re.sub(r"\s+", " ", subject).strip()


def email_text(alert: Alert) -> str:
    lines = [
        f"LOGSENTINEL · RANSOMWARE ALERT · {alert.level}",
        _headline(alert),
        "=" * 60,
        f"Matching windows : {_count_line(alert)}",
        f"Rule             : {alert.rule}",
        f"Checked at       : {_when(alert.checked_at)}",
    ]
    for host in alert.hosts:
        top = host.top_window
        lines += [
            "",
            f"HOST  {host.name}",
            "-" * 60,
            f"Verdict    : {_verdict(top.verdict)}",
            f"Confidence : {_percent(host.confidence)}  {_bar(host.confidence)}",
            f"Last window: {_when(host.last_seen)}",
            "Indicators :",
        ]
        for name in host.indicators:
            label, techniques, meaning = _indicator(name)
            tag = f" [{', '.join(techniques)}]" if techniques else ""
            lines.append(f"  - {label}{tag}" + (f": {meaning}" if meaning else ""))
        lines.append("Windows    :")
        for window in sorted(host.windows, key=lambda w: w.end, reverse=True):
            lines.append(
                f"  {_when(window.end)}  {_verdict(window.verdict)}  "
                f"{_percent(window.confidence)}  id={window.window_id}"
            )
    lines += ["", "-" * 60, DISCLAIMER]
    return "\n".join(lines)


def _chip(text: str, background: str, color: str) -> str:
    return (
        f'<span style="display:inline-block;margin:0 6px 6px 0;padding:3px 10px;'
        f"border-radius:12px;background:{background};color:{color};"
        f'font-size:12px;font-weight:600;">{escape(text)}</span>'
    )


def email_html(alert: Alert) -> str:
    accent, soft, ink = (
        ("#b42318", "#fef3f2", "#7a271a")
        if alert.critical
        else (
            ("#175cd3", "#eff8ff", "#1849a9")
            if alert.partial
            else ("#b54708", "#fffaeb", "#7a2e0e")
        )
    )
    cell = "padding:6px 10px;border-bottom:1px solid #eaecf0;font-size:13px;vertical-align:top;"
    head = f"{cell}background:#f9fafb;color:#475467;font-weight:600;text-align:left;"
    cards = []
    for host in alert.hosts:
        top = host.top_window
        chips = "".join(_chip(_indicator(name)[0], soft, ink) for name in host.indicators)
        meanings = "".join(
            f'<li style="margin:2px 0;"><b>{escape(label)}</b>'
            + (f' <span style="color:#667085;">{escape(", ".join(tech))}</span>' if tech else "")
            + (f" — {escape(meaning)}" if meaning else "")
            + "</li>"
            for label, tech, meaning in (_indicator(name) for name in host.indicators)
        )
        pct = 0 if host.confidence is None else round(host.confidence * 100)
        rows = "".join(
            f'<tr><td style="{cell}">{escape(_when(w.end))}</td>'
            f'<td style="{cell}">{escape(_verdict(w.verdict))}</td>'
            f'<td style="{cell}">{_percent(w.confidence)}</td>'
            f'<td style="{cell}font-family:Consolas,Menlo,monospace;font-size:11px;'
            f'word-break:break-all;">{escape(w.window_id)}</td></tr>'
            for w in sorted(host.windows, key=lambda w: w.end, reverse=True)
        )
        cards.append(
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'style="border:1px solid #eaecf0;border-radius:8px;margin:0 0 16px;">'
            f'<tr><td style="padding:14px 16px;">'
            f'<div style="font-size:12px;color:#667085;text-transform:uppercase;'
            f'letter-spacing:.05em;">Host</div>'
            f'<div style="font-size:18px;font-weight:700;font-family:Consolas,Menlo,monospace;">'
            f"{escape(host.name)}</div>"
            f'<div style="margin:6px 0 10px;font-size:13px;color:#344054;">'
            f"{escape(_verdict(top.verdict))} · last window {escape(_when(host.last_seen))}</div>"
            f'<div style="font-size:12px;color:#667085;">'
            f"Confidence {_percent(host.confidence)}</div>"
            f'<div style="background:#eaecf0;border-radius:4px;height:8px;margin:4px 0 14px;">'
            f'<div style="background:{accent};width:{pct}%;height:8px;border-radius:4px;"></div>'
            f"</div>"
            f'<div style="font-size:12px;color:#667085;margin-bottom:6px;">Indicators</div>'
            f"<div>{chips}</div>"
            f'<ul style="margin:8px 0 14px;padding-left:18px;font-size:13px;color:#344054;">'
            f"{meanings}</ul>"
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'style="border:1px solid #eaecf0;border-collapse:collapse;">'
            f'<tr><th style="{head}">Window end</th><th style="{head}">Verdict</th>'
            f'<th style="{head}">Conf.</th><th style="{head}">Window ID</th></tr>'
            f"{rows}</table></td></tr></table>"
        )
    return (
        '<!doctype html><html><body style="margin:0;padding:0;background:#f2f4f7;'
        'font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#101828;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
        '<tr><td align="center" style="padding:24px 12px;">'
        '<table role="presentation" width="640" cellpadding="0" cellspacing="0" '
        'style="max-width:640px;width:100%;background:#ffffff;border-radius:10px;'
        'overflow:hidden;">'
        f'<tr><td style="background:{accent};padding:20px 24px;color:#ffffff;">'
        f'<div style="font-size:12px;letter-spacing:.08em;opacity:.85;">'
        f"LOGSENTINEL · RANSOMWARE ALERT</div>"
        f'<div style="font-size:22px;font-weight:700;margin-top:4px;">'
        f"{alert.level} — {escape(_headline(alert))}</div></td></tr>"
        '<tr><td style="padding:20px 24px 4px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="margin-bottom:16px;"><tr>'
        f'<td style="font-size:13px;color:#475467;">Matching windows<br>'
        f'<b style="font-size:20px;color:#101828;">{alert.total}</b></td>'
        f'<td style="font-size:13px;color:#475467;">'
        f"{'Hosts in examples' if alert.partial else 'Hosts'}<br>"
        f'<b style="font-size:20px;color:#101828;">{len(alert.hosts)}</b></td>'
        f'<td style="font-size:13px;color:#475467;">Checked at<br>'
        f'<b style="font-size:14px;color:#101828;">{escape(_when(alert.checked_at))}</b></td>'
        "</tr></table>"
        f"{''.join(cards)}"
        "</td></tr>"
        '<tr><td style="padding:12px 24px 20px;font-size:12px;color:#667085;'
        'border-top:1px solid #eaecf0;">'
        f"Rule: {escape(alert.rule)}<br>{escape(DISCLAIMER)}"
        "</td></tr></table></td></tr></table></body></html>"
    )
