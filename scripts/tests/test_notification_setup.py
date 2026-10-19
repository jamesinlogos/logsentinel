"""Exercise notification installation against mocked APIs; never send or alter a stack."""

from __future__ import annotations

import copy
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import notification_setup as notifications  # noqa: E402


class MemoryHttp:
    """Persist only the public objects managed by setup and record every request."""

    def __init__(self, *, kibana: bool, events: list[Any]) -> None:
        self.kibana = kibana
        self.events = events
        self.objects: dict[str, Any] = {}
        self.health = {"has_permanent_encryption_key": True, "is_sufficiently_secure": True}
        self.types = [{"id": ".index", "enabled_in_license": True, "enabled_in_config": True}]
        self.overrides: dict[tuple[str, str], Any] = {}
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        allow_missing: bool = False,
    ) -> Any:
        self.calls.append((method, path, copy.deepcopy(body)))
        self.events.append((method, path, copy.deepcopy(body)))
        if (method, path) in self.overrides:
            result = self.overrides[(method, path)]
            if isinstance(result, Exception):
                raise result
            return copy.deepcopy(result)
        if method == "GET":
            if path.endswith("/api/alerting/_health"):
                return copy.deepcopy(self.health)
            if path.endswith("/api/actions/connector_types"):
                return copy.deepcopy(self.types)
            if path not in self.objects:
                assert allow_missing, f"unexpected absent resource: {path}"
                return None
            value = copy.deepcopy(self.objects[path])
            if path.startswith("/_ilm/"):
                return {path.rsplit("/", 1)[-1]: {"policy": value["policy"], "version": 3}}
            if path.startswith("/_index_template/"):
                return {
                    "index_templates": [{"name": path.rsplit("/", 1)[-1], "index_template": value}]
                }
            return value
        assert method in {"POST", "PUT"}, f"unexpected mutation: {method} {path}"
        assert isinstance(body, dict)
        target = path.removesuffix("?create=true")
        if "/api/alerting/rule/" in target:
            self.objects[target].update(copy.deepcopy(body))
            self.objects[target]["revision"] += 1
        else:
            self.objects[target] = copy.deepcopy(body)
        return {"acknowledged": True}


@pytest.fixture
def project(tmp_path: Path) -> Path:
    source = Path(__file__).resolve().parents[2]
    paths = [
        "config/kibana/connectors/ransomware-notifications.json",
        "config/kibana/actions/ransomware-notifications.json",
        "config/kibana/rules/ransomware-detections.json",
        *[
            f"config/elasticsearch/{kind}/{family}.json"
            for kind in ("ilm-policies", "index-templates")
            for family in notifications.FAMILIES
        ],
    ]
    for name in paths:
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, destination)
    return tmp_path


@pytest.fixture
def clients(project: Path) -> tuple[MemoryHttp, MemoryHttp, list[Any]]:
    events: list[Any] = []
    es = MemoryHttp(kibana=False, events=events)
    kibana = MemoryHttp(kibana=True, events=events)
    base = notifications.load_rule(project)
    base.update(
        id=notifications.RULE_ID,
        revision=4,
        alert_delay={"active": 1},
        execution_status={"status": "ok"},
        created_by="operator",
    )
    kibana.objects[f"/api/alerting/rule/{notifications.RULE_ID}"] = base
    return es, kibana, events


def installed(project: Path, es: MemoryHttp, kibana: MemoryHttp) -> None:
    connector, action, resources = notifications.definitions(project)
    es.objects.update(copy.deepcopy(resources))
    kibana.objects[f"/api/actions/connector/{notifications.CONNECTOR_ID}"] = connector
    rule = kibana.objects[f"/api/alerting/rule/{notifications.RULE_ID}"]
    rule["actions"] = [action]


def only_reads(events: list[Any]) -> bool:
    return all(event[0] == "GET" for event in events)


def test_default_preflight_reports_missing_configuration_without_writes(
    project: Path,
    clients: tuple[MemoryHttp, MemoryHttp, list[Any]],
) -> None:
    es, kibana, events = clients
    report = notifications.setup(project, es, kibana)
    assert report["status"] == "ready"
    assert len(report["missing_resources"]) == 4
    assert report["connector_installed"] is False and report["action_attached"] is False
    assert only_reads(events)
    assert not (project / "archives").exists()


def test_installed_configuration_is_a_noop_even_when_apply_is_requested(
    project: Path,
    clients: tuple[MemoryHttp, MemoryHttp, list[Any]],
) -> None:
    es, kibana, events = clients
    installed(project, es, kibana)
    rule = kibana.objects[f"/api/alerting/rule/{notifications.RULE_ID}"]
    rule["actions"][0].update(uuid="server-assigned", connector_type_id=".index")
    report = notifications.setup(project, es, kibana, apply=True)
    assert report["status"] == "unchanged"
    assert report["missing_resources"] == [] and report["action_attached"] is True
    assert only_reads(events)
    assert not (project / "archives").exists()


@pytest.mark.parametrize("prerequisite", ["key", "secure", "license", "config", "missing-type"])
def test_unavailable_prerequisite_prevents_all_writes(
    project: Path,
    clients: tuple[MemoryHttp, MemoryHttp, list[Any]],
    prerequisite: str,
) -> None:
    es, kibana, events = clients
    if prerequisite == "key":
        kibana.health["has_permanent_encryption_key"] = False
    elif prerequisite == "secure":
        kibana.health["is_sufficiently_secure"] = False
    elif prerequisite == "missing-type":
        kibana.types = []
    else:
        kibana.types[0][f"enabled_in_{prerequisite}"] = False
    report = notifications.setup(project, es, kibana, apply=True)
    assert report["status"] == "failed"
    assert only_reads(events) and not es.calls


@pytest.mark.parametrize("drift", ["rule", "action", "connector", "policy", "template"])
def test_existing_drift_is_refused_before_backup_or_mutation(
    project: Path,
    clients: tuple[MemoryHttp, MemoryHttp, list[Any]],
    drift: str,
) -> None:
    es, kibana, events = clients
    installed(project, es, kibana)
    if drift == "rule":
        kibana.objects[f"/api/alerting/rule/{notifications.RULE_ID}"]["params"][
            "excludeHitsFromPreviousRun"
        ] = False
    elif drift == "action":
        kibana.objects[f"/api/alerting/rule/{notifications.RULE_ID}"]["actions"][0]["frequency"][
            "notify_when"
        ] = "onActionGroupChange"
    elif drift == "connector":
        kibana.objects[f"/api/actions/connector/{notifications.CONNECTOR_ID}"]["config"][
            "index"
        ] = "unexpected-destination"
    elif drift == "policy":
        es.objects["/_ilm/policy/ransomware-notifications"]["policy"]["phases"]["delete"][
            "min_age"
        ] = "1d"
    else:
        es.objects["/_index_template/ransomware-notifications"]["template"]["mappings"][
            "dynamic"
        ] = True
    report = notifications.setup(project, es, kibana, apply=True)
    assert report["status"] == "failed"
    assert "differs" in report["errors"][0] or "differ" in report["errors"][0]
    assert only_reads(events)
    assert not (project / "archives").exists()


def test_absent_detection_rule_is_refused_without_implicitly_creating_it(
    project: Path,
    clients: tuple[MemoryHttp, MemoryHttp, list[Any]],
) -> None:
    es, kibana, events = clients
    kibana.objects.clear()
    report = notifications.setup(project, es, kibana, apply=True)
    assert report["status"] == "failed" and "existing" in report["errors"][0]
    assert only_reads(events)


def test_apply_backs_up_before_mutations_and_preserves_live_rule_behavior(
    project: Path,
    clients: tuple[MemoryHttp, MemoryHttp, list[Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    es, kibana, events = clients
    rule_path = f"/api/alerting/rule/{notifications.RULE_ID}"
    before = copy.deepcopy(kibana.objects[rule_path])
    saved: list[dict[str, Any]] = []

    def backup(root: Path, previous: dict[str, Any], desired: dict[str, Any]) -> Path:
        assert root == project and only_reads(events)
        saved.extend([copy.deepcopy(previous), copy.deepcopy(desired)])
        events.append(("BACKUP", "verified", None))
        return project / "verified-backup"

    monkeypatch.setattr(notifications, "backup_state", backup)
    report = notifications.setup(project, es, kibana, apply=True)
    assert report["status"] == "applied"
    assert len(report["applied"]) == 6
    assert report["connector_installed"] is True and report["action_attached"] is True
    assert saved[0]["rule"]["params"] == before["params"]
    assert saved[0]["rule"]["actions"] == [] and saved[0]["connector"] is None
    assert all(value is None for value in saved[0]["resources"].values())
    backup_position = next(index for index, item in enumerate(events) if item[0] == "BACKUP")
    assert all(item[0] == "GET" for item in events[:backup_position])
    writes = [(method, path, body) for method, path, body in events if method in {"PUT", "POST"}]
    assert [method for method, _, _ in writes] == ["PUT", "PUT", "PUT", "PUT", "POST", "PUT"]
    assert all(path.endswith("?create=true") for _, path, _ in writes[2:4])
    update = writes[-1][2]
    assert update["params"] == before["params"] and update["schedule"] == before["schedule"]
    assert update["alert_delay"] == before["alert_delay"]
    assert (
        not {"id", "enabled", "revision", "consumer", "rule_type_id", "created_by"} & update.keys()
    )
    assert kibana.objects[rule_path]["execution_status"] == before["execution_status"]
    for index, (method, path, _) in enumerate(events):
        if method in {"PUT", "POST"}:
            assert events[index + 1][:2] == ("GET", path.removesuffix("?create=true"))
    assert sum(method == "GET" and path == rule_path for method, path, _ in events) == 3
    assert len([item for item in es.calls if item[0] == "GET"]) == 8


def test_backup_failure_stops_before_first_remote_write(
    project: Path,
    clients: tuple[MemoryHttp, MemoryHttp, list[Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    es, kibana, events = clients

    def fail_backup(*_args: Any) -> Path:
        raise notifications.DashboardError("backup verification failed")

    monkeypatch.setattr(notifications, "backup_state", fail_backup)
    report = notifications.setup(project, es, kibana, apply=True)
    assert report["status"] == "failed" and report["applied"] == []
    assert only_reads(events)


def test_partial_install_does_not_delete_resources_after_readback_failure(
    project: Path,
    clients: tuple[MemoryHttp, MemoryHttp, list[Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    es, kibana, events = clients
    monkeypatch.setattr(notifications, "backup_state", lambda *_args: project / "verified")
    policy_path = "/_ilm/policy/ransomware-notifications"
    original_request = es.request
    reads = 0

    def inconsistent_readback(method: str, path: str, body: Any = None, **kwargs: Any) -> Any:
        nonlocal reads
        response = original_request(method, path, body, **kwargs)
        if method == "GET" and path == policy_path:
            reads += 1
            if reads > 1:
                response["ransomware-notifications"]["policy"]["phases"]["delete"]["min_age"] = "1d"
        return response

    monkeypatch.setattr(es, "request", inconsistent_readback)
    report = notifications.setup(project, es, kibana, apply=True)
    assert report["status"] == "failed" and "read-back differs" in report["errors"][0]
    assert report["applied"] == [policy_path]
    assert [method for method, _, _ in events if method != "GET"] == ["PUT"]
    assert policy_path in es.objects


def test_rule_revision_change_is_refused_after_resource_creation(
    project: Path,
    clients: tuple[MemoryHttp, MemoryHttp, list[Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    es, kibana, events = clients
    monkeypatch.setattr(notifications, "backup_state", lambda *_args: project / "verified")
    rule_path = f"/api/alerting/rule/{notifications.RULE_ID}"
    original_request = kibana.request
    reads = 0

    def concurrent_change(method: str, path: str, body: Any = None, **kwargs: Any) -> Any:
        nonlocal reads
        response = original_request(method, path, body, **kwargs)
        if method == "GET" and path == rule_path:
            reads += 1
            if reads > 1:
                response["revision"] += 1
        return response

    monkeypatch.setattr(kibana, "request", concurrent_change)
    report = notifications.setup(project, es, kibana, apply=True)
    assert report["status"] == "failed" and "changed during setup" in report["errors"][0]
    assert len(report["applied"]) == 5
    assert not any(method == "PUT" and path == rule_path for method, path, _ in events)


def test_malformed_existing_resource_is_not_treated_as_absent(
    project: Path,
    clients: tuple[MemoryHttp, MemoryHttp, list[Any]],
) -> None:
    es, kibana, events = clients
    es.overrides[("GET", "/_ilm/policy/ransomware-notifications")] = {"unrelated": {}}
    report = notifications.setup(project, es, kibana, apply=True)
    assert report["status"] == "failed" and "malformed" in report["errors"][0]
    assert only_reads(events)


def test_connector_definition_with_secret_is_refused_before_api_requests(
    project: Path,
    clients: tuple[MemoryHttp, MemoryHttp, list[Any]],
) -> None:
    es, kibana, events = clients
    path = project / "config/kibana/connectors/ransomware-notifications.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["secrets"] = {"password": "test-only-secret"}
    path.write_text(json.dumps(value), encoding="utf-8")
    report = notifications.setup(project, es, kibana, apply=True)
    assert report["status"] == "failed" and events == []
    assert "test-only-secret" not in str(report)


def test_policy_server_defaults_are_ignored_but_retention_drift_is_not(project: Path) -> None:
    _, _, resources = notifications.definitions(project)
    path = "/_ilm/policy/ransomware-notifications"
    expected = resources[path]
    actual = copy.deepcopy(expected)
    actual["policy"]["phases"]["delete"]["actions"]["delete"]["delete_searchable_snapshot"] = True
    assert notifications.resource_matches(path, expected, actual)
    actual["policy"]["phases"]["delete"]["min_age"] = "1d"
    assert not notifications.resource_matches(path, expected, actual)


def test_template_numeric_settings_and_server_metadata_are_normalized(project: Path) -> None:
    _, _, resources = notifications.definitions(project)
    path = "/_index_template/ransomware-notifications"
    expected = resources[path]
    actual = copy.deepcopy(expected)
    settings = actual["template"]["settings"]["index"]
    settings["number_of_shards"] = str(settings["number_of_shards"])
    settings["number_of_replicas"] = str(settings["number_of_replicas"])
    actual.update(created_date_millis=1234, modified_date_millis=2345, composed_of=[])
    assert notifications.resource_matches(path, expected, actual)
    actual["template"]["settings"]["index"]["number_of_replicas"] = "2"
    assert not notifications.resource_matches(path, expected, actual)


def test_action_readback_normalizes_only_known_server_defaults(project: Path) -> None:
    _, action, _ = notifications.definitions(project)
    actual = copy.deepcopy(action)
    actual.update(uuid="generated", connector_type_id=".index", use_alert_data_for_template=False)
    actual["params"]["indexOverride"] = None
    assert notifications.action_matches(action, actual)
    actual["use_alert_data_for_template"] = True
    assert not notifications.action_matches(action, actual)
    actual["use_alert_data_for_template"] = False
    actual["params"]["indexOverride"] = "unexpected-index"
    assert not notifications.action_matches(action, actual)
