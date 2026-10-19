"""Inspect or install the canonical ransomware Kibana rule, without replay or test documents.

    python scripts/alerting_setup.py
    python scripts/alerting_setup.py --apply --space default

Default mode reads health, licensing, rule configuration and exact detection counts only.
``--apply`` permits creating the absent stable rule id after every check succeeds. Existing
different rules are refused; nothing is updated or deleted. Neither mode changes the production
lookback to test historical data. A document-free report is saved to archives/kibana-alerting.json.
Standard library only, on Windows and Linux. No Docker, VM, Kafka or source-index writes.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dashboard_setup import DashboardError, endpoint, space_identifier, write_json

ROOT = Path(__file__).resolve().parent.parent
RULE_ID = "ransomware-detections"


class AlertHttp:
    """Accept object and array APIs; never include response bodies in diagnostics."""

    def __init__(self, base: str) -> None:
        self.base = base

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        allow_missing: bool = False,
    ) -> Any:
        headers = {"Accept": "application/json", "kbn-xsrf": "true"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, allow_nan=False).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - operator-selected local stack
            f"{self.base}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and allow_missing:
                return None
            raise DashboardError(f"{method} {path}: HTTP {exc.code}") from exc
        except (OSError, urllib.error.URLError) as exc:
            raise DashboardError(f"{method} {path}: connection failed") from exc
        except (ValueError, UnicodeError) as exc:
            raise DashboardError(f"{method} {path}: invalid JSON response") from exc


def load_rule(root: Path) -> dict[str, Any]:
    """Load the source-controlled request, not an exported object with credentials."""
    value = json.loads(
        (root / "config" / "kibana" / "rules" / f"{RULE_ID}.json").read_text(encoding="utf-8")
    )
    if not isinstance(value, dict) or value.get("rule_type_id") != ".es-query":
        raise DashboardError("expected the canonical .es-query rule definition")
    return value


def rule_matches(expected: dict[str, Any], actual: Any) -> bool:
    """Compare behavior, ignoring only server metadata and known optional defaults."""
    if not isinstance(actual, dict):
        return False
    defaults: dict[str, Any] = {
        "alert_delay": {"active": 1},
        "notify_when": None,
        "throttle": None,
        "mute_all": False,
    }
    keys = {"name", "rule_type_id", "consumer", "enabled", "schedule", "tags", "params", "actions"}
    keys.update(defaults)

    def normalized(value: dict[str, Any]) -> dict[str, Any]:
        result = {key: copy.deepcopy(value.get(key, defaults.get(key))) for key in keys}
        if isinstance(result["tags"], list):
            result["tags"] = sorted(result["tags"])
        params = result["params"]
        if isinstance(params, dict):
            parameter_defaults: dict[str, Any] = {
                "sourceFields": [],
                "aggField": None,
                "termField": None,
                "termSize": None,
            }
            for key, default in parameter_defaults.items():
                if params.get(key) == default:
                    params.pop(key, None)
            if isinstance(params.get("esQuery"), str):
                try:
                    params["esQuery"] = json.loads(params["esQuery"])
                except ValueError:
                    pass
        return result

    return normalized(expected) == normalized(actual)


def action_matches(expected: dict[str, Any], actual: Any) -> bool:
    """Ignore only generated action metadata and equivalent connector defaults."""
    if not isinstance(actual, dict) or actual.get("connector_type_id", ".index") != ".index":
        return False
    value = copy.deepcopy(actual)
    value.pop("uuid", None)
    value.pop("connector_type_id", None)
    if value.get("use_alert_data_for_template") is False:
        value.pop("use_alert_data_for_template")
    params = value.get("params")
    if isinstance(params, dict) and params.get("indexOverride") is None:
        params.pop("indexOverride", None)
    return bool(value == expected)


def installed_rule_matches(expected: dict[str, Any], actual: Any) -> bool:
    """Accept the separately installed, canonical notification action on the base rule."""
    if rule_matches(expected, actual):
        return True
    action_path = ROOT / "config" / "kibana" / "actions" / "ransomware-notifications.json"
    if expected.get("actions") != [] or not isinstance(actual, dict) or not action_path.is_file():
        return False
    try:
        action = json.loads(action_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DashboardError("cannot validate the managed notification action") from exc
    actions = actual.get("actions")
    if not isinstance(actions, list) or len(actions) != 1 or not action_matches(action, actions[0]):
        return False
    base = copy.deepcopy(actual)
    base["actions"] = []
    return rule_matches(expected, base)


def summarize_search(result: Any) -> dict[str, Any]:
    """Reject approximate, partial or malformed counts before a rule can be created."""
    if not isinstance(result, dict):
        raise DashboardError("detection query returned no result")
    shards = result.get("_shards", {})
    clusters = result.get("_clusters")
    if (
        result.get("error")
        or result.get("timed_out") is not False
        or not isinstance(shards, dict)
        or type(shards.get("total")) is not int
        or shards["total"] < 0
        or shards.get("failed") != 0
        or shards.get("successful") != shards["total"]
        or (
            clusters is not None
            and (
                not isinstance(clusters, dict)
                or any(clusters.get(key, 0) != 0 for key in ("failed", "partial", "skipped"))
            )
        )
    ):
        raise DashboardError("detection query was incomplete (timeout or partial shards)")
    hits = result.get("hits", {})
    total = hits.get("total", {}) if isinstance(hits, dict) else {}
    if (
        not isinstance(total, dict)
        or total.get("relation") != "eq"
        or type(total.get("value")) is not int
        or total["value"] < 0
    ):
        raise DashboardError("detection query did not return an exact count")
    count = total["value"]
    aggregates = result.get("aggregations", {})
    dates: list[str | None] = []
    for name in ("first", "last"):
        aggregate = aggregates.get(name, {}) if isinstance(aggregates, dict) else {}
        value = aggregate.get("value") if isinstance(aggregate, dict) else None
        if count == 0 and value is None:
            dates.append(None)
        elif value is not None and type(value) in (int, float) and math.isfinite(value):
            try:
                dates.append(datetime.fromtimestamp(value / 1000, UTC).isoformat())
            except (OverflowError, OSError, ValueError) as exc:
                raise DashboardError("detection date range is invalid") from exc
        else:
            raise DashboardError("detection query has no usable event.ingested range")
    first, last = dates
    if count and (first is None or last is None or first > last):
        raise DashboardError("detection date range is invalid")
    return {"count": count, "first_ingested": first, "last_ingested": last}


def detection_counts(es: AlertHttp, definition: dict[str, Any]) -> dict[str, Any]:
    """Use the rule's DSL with size zero; never request matching source documents."""
    params = definition["params"]
    source = json.loads(params["esQuery"])
    if not isinstance(source, dict) or not isinstance(source.get("query"), dict):
        raise DashboardError("rule DSL must contain a query object")
    index = params["index"]
    if (
        not isinstance(index, list)
        or not index
        or any(not isinstance(name, str) or any(char in name for char in "/?#") for name in index)
    ):
        raise DashboardError("rule index names are invalid")
    body: dict[str, Any] = {
        "size": 0,
        "track_total_hits": True,
        "query": source["query"],
        "aggs": {
            "first": {"min": {"field": "event.ingested"}},
            "last": {"max": {"field": "event.ingested"}},
        },
    }
    if "runtime_mappings" in source:
        body["runtime_mappings"] = source["runtime_mappings"]
    path = f"/{','.join(index)}/_search?ignore_unavailable=true&allow_no_indices=true"
    historical = summarize_search(es.request("GET", path, body))
    current_body = copy.deepcopy(body)
    lookback = f"{params['timeWindowSize']}{params['timeWindowUnit']}"
    current_body["query"] = {
        "bool": {
            "filter": [
                source["query"],
                {
                    "range": {params["timeField"]: {"gte": f"now-{lookback}", "lte": "now"}},
                },
            ]
        }
    }
    current = summarize_search(es.request("GET", path, current_body))
    return {
        "historical": historical,
        "current": current,
        "index": index,
        "time_field": params["timeField"],
        "lookback": lookback,
        "filter": source["query"],
        "interval": definition["schedule"]["interval"],
    }


def setup(
    es: AlertHttp,
    kibana: AlertHttp,
    definition: dict[str, Any],
    *,
    space: str = "default",
    apply: bool = False,
) -> dict[str, Any]:
    """Read all prerequisites before creating; report errors without leaking documents."""
    report: dict[str, Any] = {
        "created_utc": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        "rule_id": RULE_ID,
        "space": space,
        "apply": apply,
        "status": "failed",
    }
    prefix = "" if space == "default" else f"/s/{space}"
    path = f"{prefix}/api/alerting/rule/{RULE_ID}"
    try:
        health = kibana.request("GET", f"{prefix}/api/alerting/_health")
        if not isinstance(health, dict):
            raise DashboardError("alerting health response is invalid")
        report["health"] = {
            key: health.get(key)
            for key in (
                "is_sufficiently_secure",
                "has_permanent_encryption_key",
            )
        }
        types = kibana.request("GET", f"{prefix}/api/alerting/rule_types")
        licensed = isinstance(types, list) and any(
            isinstance(item, dict)
            and item.get("id") == definition["rule_type_id"]
            and item.get("enabled_in_license") is True
            for item in types
        )
        report["enabled_in_license"] = licensed
        report["query"] = detection_counts(es, definition)
        existing = kibana.request("GET", path, allow_missing=True)
        report["installed"] = existing is not None
        blockers = []
        if health.get("has_permanent_encryption_key") is not True:
            blockers.append("set a permanent xpack.encryptedSavedObjects.encryptionKey")
        if health.get("is_sufficiently_secure") is not True:
            blockers.append("Kibana reports alerting is not sufficiently secure")
        if not licensed:
            blockers.append(".es-query is unavailable or not enabled in the license")
        if existing is not None and not installed_rule_matches(definition, existing):
            blockers.append("existing rule differs; refusing to update or delete it")
        if blockers:
            report.update(status="blocked", errors=blockers)
        elif existing is not None:
            report["status"] = "unchanged"
        elif not apply:
            report["status"] = "ready"
        else:
            kibana.request("POST", path, definition)
            report["created"] = True
            if not rule_matches(definition, kibana.request("GET", path)):
                raise DashboardError("created rule read-back differs; inspect it before retrying")
            report.update(status="created", installed=True)
    except (DashboardError, KeyError, TypeError, ValueError) as exc:
        report.update(
            status="failed",
            errors=[
                str(exc)
                if isinstance(exc, DashboardError)
                else "invalid rule or API response structure"
            ],
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--es", type=endpoint, default="http://localhost:9200")
    parser.add_argument("--kibana", type=endpoint, default="http://localhost:5601")
    parser.add_argument("--space", type=space_identifier, default="default")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        report = setup(
            AlertHttp(args.es),
            AlertHttp(args.kibana),
            load_rule(ROOT),
            space=args.space,
            apply=args.apply,
        )
        destination = ROOT / "archives" / "kibana-alerting.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_json(destination, report)
    except (OSError, ValueError, DashboardError) as exc:
        print(f"Alerting setup failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return int(report["status"] in {"failed", "blocked"})


if __name__ == "__main__":
    raise SystemExit(main())
