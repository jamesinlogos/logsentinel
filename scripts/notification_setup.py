"""Preflight or attach the Basic-license notification queue to the existing Kibana rule.

    python scripts/notification_setup.py
    python scripts/notification_setup.py --apply

Default mode only reads configuration and APIs and writes a small local report. ``--apply``
creates missing notification policies/templates and the stable .index connector, then attaches
one canonical action. Existing differing resources/actions are refused. Previous public state
is backed up and verified before any remote write. No test documents or external messages.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from alerting_setup import RULE_ID, AlertHttp, action_matches, load_rule, rule_matches
from backup_project import MIN_FREE_BYTES, verify_backup
from dashboard_setup import DashboardError, endpoint, space_identifier, write_json

ROOT = Path(__file__).resolve().parent.parent
CONNECTOR_ID = "ransomware-notifications"
FAMILIES = ("ransomware-notifications", "ransomware-notification-deliveries")
UPDATE_FIELDS = (
    "name",
    "tags",
    "schedule",
    "params",
    "notify_when",
    "throttle",
    "alert_delay",
    "flapping",
    "artifacts",
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def definitions(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    """Load only the two explicitly managed notification families and secret-free connector."""
    base = root / "config"
    connector = load_json(base / "kibana" / "connectors" / f"{CONNECTOR_ID}.json")
    action = load_json(base / "kibana" / "actions" / f"{CONNECTOR_ID}.json")
    if (
        not isinstance(connector, dict)
        or connector.get("connector_type_id") != ".index"
        or connector.get("secrets", {}) != {}
        or not isinstance(connector.get("config"), dict)
        or not isinstance(action, dict)
        or action.get("id") != CONNECTOR_ID
        or action.get("group") != "query matched"
        or action.get("frequency")
        != {
            "summary": False,
            "notify_when": "onActiveAlert",
            "throttle": None,
        }
    ):
        raise DashboardError("expected the canonical secret-free .index notification definitions")
    resources = {}
    for directory, route in (
        ("ilm-policies", "_ilm/policy"),
        ("index-templates", "_index_template"),
    ):
        for name in FAMILIES:
            value = load_json(base / "elasticsearch" / directory / f"{name}.json")
            if not isinstance(value, dict):
                raise DashboardError("notification resource must be a JSON object")
            resources[f"/{route}/{name}"] = value
    return connector, action, resources


def checked_rule(base: dict[str, Any], action: dict[str, Any], actual: Any) -> bool:
    """Validate the base independently; return whether the sole managed action is attached."""
    if not isinstance(actual, dict):
        raise DashboardError("the existing ransomware detection rule is required")
    actions = actual.get("actions")
    attached = (
        isinstance(actions, list) and len(actions) == 1 and action_matches(action, actions[0])
    )
    if actions != [] and not attached:
        raise DashboardError("existing actions differ; refusing to replace or remove them")
    stripped = copy.deepcopy(actual)
    stripped["actions"] = []
    expected = copy.deepcopy(base)
    expected["actions"] = []
    if not rule_matches(expected, stripped):
        raise DashboardError(
            "the base detection rule differs; query and schedule must be preserved"
        )
    return attached


def connector_matches(expected: dict[str, Any], actual: Any) -> bool:
    if (
        not isinstance(actual, dict)
        or actual.get("is_preconfigured")
        or actual.get("is_system_action")
    ):
        return False

    def configuration(value: dict[str, Any]) -> Any:
        config = value.get("config")
        return (
            {"refresh": False, "executionTimeField": None, **config}
            if isinstance(config, dict)
            else None
        )

    return all(expected.get(key) == actual.get(key) for key in ("name", "connector_type_id")) and (
        configuration(expected) == configuration(actual)
    )


def resource_body(path: str, response: Any) -> dict[str, Any] | None:
    if response is None:
        return None
    name = path.rsplit("/", 1)[-1]
    try:
        if path.startswith("/_ilm/"):
            value = {"policy": response[name]["policy"]}
        else:
            entries = response["index_templates"]
            if len(entries) != 1 or entries[0]["name"] != name:
                raise ValueError
            value = entries[0]["index_template"]
        if not isinstance(value, dict):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise DashboardError(f"GET {path}: malformed resource response") from exc
    return value


def resource_matches(path: str, expected: dict[str, Any], actual: Any) -> bool:
    """Normalize observed Elasticsearch metadata, setting types and the ILM delete default."""
    if not isinstance(actual, dict):
        return False

    def normalized(source: dict[str, Any]) -> dict[str, Any]:
        value = copy.deepcopy(source)
        if path.startswith("/_ilm/"):
            for phase in value.get("policy", {}).get("phases", {}).values():
                delete = phase.get("actions", {}).get("delete")
                if isinstance(delete, dict) and delete.get("delete_searchable_snapshot", True):
                    delete.pop("delete_searchable_snapshot", None)
        else:
            for key in ("created_date_millis", "modified_date_millis"):
                value.pop(key, None)
            if value.get("composed_of") == []:
                value.pop("composed_of")
            settings = value.get("template", {}).get("settings")
            if isinstance(settings, dict):
                flat = {}

                def flatten(node: dict[str, Any], prefix: str = "") -> None:
                    for key, item in node.items():
                        full = f"{prefix}{key}"
                        if isinstance(item, dict):
                            flatten(item, f"{full}.")
                        else:
                            field = full if full.startswith("index.") else f"index.{full}"
                            flat[field] = str(item).lower() if isinstance(item, bool) else str(item)

                flatten(settings)
                value["template"]["settings"] = flat
        return value

    return normalized(expected) == normalized(actual)


def backup_state(root: Path, previous: dict[str, Any], desired: dict[str, Any]) -> Path:
    """Write a credential-free snapshot with the project's verifiable manifest format."""
    if shutil.disk_usage(root).free < MIN_FREE_BYTES:
        raise DashboardError("notification backup requires at least 5 GB free")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    directory = root / "archives" / "backups" / f"{stamp}-kibana-notifications"
    directory.mkdir(parents=True, exist_ok=False)
    manifest: dict[str, Any] = {"label": "kibana-notifications", "created_utc": stamp, "files": {}}
    for filename, value in (("previous-state.json", previous), ("desired-state.json", desired)):
        write_json(directory / filename, value)
        payload = (directory / filename).read_bytes()
        manifest["files"][filename] = {
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    write_json(directory / "MANIFEST.json", manifest)
    (directory / "SHA256SUMS").write_text(
        "".join(f"{info['sha256']}  {name}\n" for name, info in manifest["files"].items()),
        encoding="utf-8",
    )
    if verify_backup(directory):
        raise DashboardError("notification backup verification failed; no remote writes attempted")
    return directory


def setup(
    root: Path, es: AlertHttp, kibana: AlertHttp, *, space: str = "default", apply: bool = False
) -> dict[str, Any]:
    """Preflight every target before backing up, then create only absent resources."""
    report: dict[str, Any] = {
        "created_utc": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        "space": space,
        "apply": apply,
        "status": "failed",
        "rule_id": RULE_ID,
        "connector_id": CONNECTOR_ID,
        "applied": [],
    }
    prefix = "" if space == "default" else f"/s/{space}"
    connector_path = f"{prefix}/api/actions/connector/{CONNECTOR_ID}"
    rule_path = f"{prefix}/api/alerting/rule/{RULE_ID}"
    try:
        connector, action, resources = definitions(root)
        base = load_rule(root)
        health = kibana.request("GET", f"{prefix}/api/alerting/_health")
        types = kibana.request("GET", f"{prefix}/api/actions/connector_types")
        if not isinstance(health, dict) or not all(
            health.get(key) is True
            for key in (
                "has_permanent_encryption_key",
                "is_sufficiently_secure",
            )
        ):
            raise DashboardError("Kibana alerting health prerequisites are not satisfied")
        if not isinstance(types, list) or not any(
            isinstance(item, dict)
            and item.get("id") == ".index"
            and item.get("enabled_in_license") is True
            and item.get("enabled_in_config") is True
            for item in types
        ):
            raise DashboardError("the Basic .index connector is unavailable")
        current = kibana.request("GET", rule_path, allow_missing=True)
        attached = checked_rule(base, action, current)
        existing_connector = kibana.request("GET", connector_path, allow_missing=True)
        if existing_connector is not None and not connector_matches(connector, existing_connector):
            raise DashboardError("existing notification connector differs; refusing to replace it")
        previous_resources = {}
        missing = []
        for path, value in resources.items():
            previous_resources[path] = es.request("GET", path, allow_missing=True)
            actual = resource_body(path, previous_resources[path])
            if actual is None:
                missing.append(path)
            elif not resource_matches(path, value, actual):
                raise DashboardError(f"existing {path} differs; refusing to replace it")
        report.update(
            connector_installed=existing_connector is not None,
            action_attached=attached,
            missing_resources=missing,
        )
        if not missing and existing_connector is not None and attached:
            report["status"] = "unchanged"
        elif not apply:
            report["status"] = "ready"
        else:
            # Public GETs omit secrets; whitelist the writable state and identifying metadata.
            previous = {
                "space": space,
                "rule": {
                    key: current[key]
                    for key in (
                        *UPDATE_FIELDS,
                        "actions",
                        "id",
                        "rule_type_id",
                        "consumer",
                        "enabled",
                        "revision",
                    )
                    if key in current
                },
                "connector": None,
                "resources": previous_resources,
            }
            if existing_connector is not None:
                previous["connector"] = {
                    key: existing_connector[key]
                    for key in (
                        "id",
                        "name",
                        "connector_type_id",
                        "config",
                    )
                    if key in existing_connector
                }
            report["backup"] = str(
                backup_state(
                    root,
                    previous,
                    {
                        "space": space,
                        "connector": connector,
                        "action": action,
                        "resources": resources,
                    },
                )
            )
            for path in missing:
                es.request(
                    "PUT",
                    path + ("?create=true" if path.startswith("/_index_template/") else ""),
                    resources[path],
                )
                report["applied"].append(path)
                if not resource_matches(
                    path, resources[path], resource_body(path, es.request("GET", path))
                ):
                    raise DashboardError(f"{path}: read-back differs")
            if existing_connector is None:
                kibana.request("POST", connector_path, connector)
                report["applied"].append(connector_path)
                if not connector_matches(connector, kibana.request("GET", connector_path)):
                    raise DashboardError("notification connector read-back differs")
            if not attached:
                latest = kibana.request("GET", rule_path)
                if checked_rule(base, action, latest) or latest.get("revision") != current.get(
                    "revision"
                ):
                    raise DashboardError("rule changed during setup; inspect it before retrying")
                body = {key: copy.deepcopy(latest[key]) for key in UPDATE_FIELDS if key in latest}
                body["actions"] = [action]
                kibana.request("PUT", rule_path, body)
                report["applied"].append(rule_path)
                if not checked_rule(base, action, kibana.request("GET", rule_path)):
                    raise DashboardError("notification rule read-back has no managed action")
            report.update(
                status="applied",
                connector_installed=True,
                action_attached=True,
                missing_resources=[],
            )
    except (DashboardError, OSError, KeyError, TypeError, ValueError) as exc:
        report.update(
            status="failed",
            errors=[
                str(exc)
                if isinstance(exc, DashboardError)
                else "invalid configuration, backup or API response"
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
    report = setup(
        ROOT, AlertHttp(args.es), AlertHttp(args.kibana), space=args.space, apply=args.apply
    )
    destination = ROOT / "archives" / "kibana-notifications.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_json(destination, report)
    print(json.dumps(report, indent=2))
    return int(report["status"] == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
