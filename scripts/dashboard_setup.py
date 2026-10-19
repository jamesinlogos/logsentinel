"""Plan or apply portable dashboards to Kibana (README.md section 9.1).

    python scripts/dashboard_setup.py
    python scripts/dashboard_setup.py --historical-range
    python scripts/dashboard_setup.py --apply --historical-range --space default

The default performs local validation and prints the planned requests without network access
or writes. ``--historical-range`` reads the existing Elasticsearch timestamp range; it changes
only the outgoing dashboard definitions. ``--apply`` explicitly permits Kibana dashboard writes
after all target ids have been checked and their previous definitions backed up locally.
No Docker, VM, Kafka or telemetry/index mutation is performed. Standard library only; Windows
and Linux use the same commands. Failed or partially completed runs never delete dashboards.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from verify_dashboards import PATTERNS, Report, verify_static

ROOT = Path(__file__).resolve().parent.parent
IDENTIFIER = re.compile(r"[a-z0-9_-]+")
VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


class DashboardError(RuntimeError):
    """A validation, preflight or deployment failure with no automatic deletion."""


def endpoint(value: str) -> str:
    """Validate a base URL without exposing embedded credentials in diagnostics."""
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise argparse.ArgumentTypeError(
            "use an http(s) URL without credentials, query or fragment"
        )
    try:
        _ = parsed.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid URL port") from exc
    return value.rstrip("/")


def space_identifier(value: str) -> str:
    """Accept a path-safe Kibana space id, never a title or URL path."""
    if not IDENTIFIER.fullmatch(value):
        raise argparse.ArgumentTypeError("space id must use lowercase letters, numbers, - or _")
    return value


class JsonHttp:
    """Small JSON client; errors omit response documents and credentials."""

    def __init__(self, base: str) -> None:
        self.base = base

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        allow_missing: bool = False,
    ) -> dict[str, Any] | None:
        headers = {"Accept": "application/json", "kbn-xsrf": "true"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, allow_nan=False).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - operator-selected stack URL
            f"{self.base}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                result = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and allow_missing:
                return None
            raise DashboardError(f"{method} {path}: HTTP {exc.code}") from exc
        except (OSError, urllib.error.URLError) as exc:
            raise DashboardError(
                f"{method} {path}: connection failed ({type(exc).__name__})"
            ) from exc
        except (ValueError, UnicodeError) as exc:
            raise DashboardError(f"{method} {path}: invalid JSON response") from exc
        if not isinstance(result, dict):
            raise DashboardError(f"{method} {path}: expected a JSON object")
        return result


def load_definitions(root: Path) -> dict[str, dict[str, Any]]:
    """Read canonical JSON bodies; filenames supply stable dashboard ids."""
    definitions: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "dashboard").glob("*.json")):
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", path.stem):
            raise DashboardError(f"dashboard filename must be kebab-case: {path.name}")
        definition = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(definition, dict) or not isinstance(definition.get("title"), str):
            raise DashboardError(f"{path.name}: expected a dashboard object with a title")
        definitions[path.stem] = definition
    if not definitions:
        raise DashboardError("no dashboard JSON definitions found")
    return definitions


def historical_range(es: JsonHttp) -> dict[str, str]:
    """Read all stored monitored data; include both endpoint timestamps in Kibana's range."""
    result = es.request(
        "GET",
        f"/{','.join(PATTERNS)}/_search?ignore_unavailable=true&allow_no_indices=true",
        {
            "size": 0,
            "aggs": {
                "first": {"min": {"field": "@timestamp"}},
                "last": {"max": {"field": "@timestamp"}},
            },
        },
    )
    shards = result.get("_shards") if result is not None else None
    if (
        result is None
        or result.get("error")
        or result.get("timed_out")
        or not isinstance(shards, dict)
        or type(shards.get("failed")) is not int
        or shards["failed"] != 0
    ):
        raise DashboardError("historical range query was incomplete")
    aggregations = result.get("aggregations", {})
    if not isinstance(aggregations, dict):
        raise DashboardError("historical range query has no date aggregations")
    first_aggregation = aggregations.get("first")
    last_aggregation = aggregations.get("last")
    first = first_aggregation.get("value") if isinstance(first_aggregation, dict) else None
    last = last_aggregation.get("value") if isinstance(last_aggregation, dict) else None
    if (
        not isinstance(first, (int, float))
        or not isinstance(last, (int, float))
        or not math.isfinite(first)
        or not math.isfinite(last)
        or first > last
    ):
        raise DashboardError("no usable @timestamp range in the stored monitoring indices")
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    try:
        start = epoch + timedelta(milliseconds=math.floor(first) - 1)
        end = epoch + timedelta(milliseconds=math.ceil(last) + 1)
    except OverflowError as exc:
        raise DashboardError("stored @timestamp range is outside supported dates") from exc
    return {
        "from": start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "to": end.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "mode": "absolute",
    }


def dashboard_path(dashboard_id: str, space: str) -> str:
    prefix = "" if space == "default" else f"/s/{space}"
    return f"{prefix}/api/dashboards/{dashboard_id}"


def kibana_version(kibana: JsonHttp) -> str:
    """Read the version even when Kibana redacts its public status response."""
    result = kibana.request("GET", "/api/status") or {}
    version_info = result.get("version")
    version = version_info.get("number", "") if isinstance(version_info, dict) else ""
    match = VERSION.match(version) if isinstance(version, str) else None
    if match is None:
        result = kibana.request("GET", "/api/stats?extended=true") or {}
        kibana_info = result.get("kibana")
        version = kibana_info.get("version", "") if isinstance(kibana_info, dict) else ""
        match = VERSION.match(version) if isinstance(version, str) else None
    if match is None or tuple(map(int, match.groups()[:2])) < (9, 5):
        raise DashboardError("portable Dashboard API requires Kibana 9.5 or later")
    return version


def definition_from_response(response: dict[str, Any]) -> dict[str, Any]:
    """Extract a Dashboard API definition, retaining the raw response separately for backup."""
    data = response.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("title"), str):
        raise DashboardError("Dashboard API response has no data.title")
    return data


def write_json(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def backup_definitions(
    root: Path,
    existing: dict[str, dict[str, Any] | None],
    definitions: dict[str, dict[str, Any]],
    *,
    kibana_url: str,
    space: str,
    version: str,
) -> tuple[Path, dict[str, Any]]:
    """Persist every preflight response and absent id before the first remote write."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    directory = root / "archives" / "backups" / f"{stamp}-dashboard-kibana"
    directory.mkdir(parents=True, exist_ok=False)
    checksums = []
    entries = []
    for dashboard_id, response in existing.items():
        entry: dict[str, Any] = {
            "id": dashboard_id,
            "title": definitions[dashboard_id]["title"],
            "existed": response is not None,
        }
        if response is not None:
            filename = f"{dashboard_id}.json"
            write_json(directory / filename, response)
            entry["backup_file"] = filename
            digest = hashlib.sha256((directory / filename).read_bytes()).hexdigest()
            checksums.append(f"{digest}  {filename}\n")
        entries.append(entry)
    manifest: dict[str, Any] = {
        "created_utc": stamp,
        "kibana_url": kibana_url,
        "kibana_version": version,
        "space": space,
        "dashboards": entries,
        "applied": [],
        "failed": [],
        "status": "backed_up",
    }
    write_json(directory / "MANIFEST.json", manifest)
    (directory / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
    return directory, manifest


def contains_definition(expected: Any, actual: Any) -> bool:
    """Verify requested values while allowing observed Dashboard API normalization.

    The Dashboard API removes ``query: {language: kql, expression: ''}`` from some visual
    configs and the root absolute ``time_range.mode`` when both endpoints are absolute dates.
    Populated queries, range endpoints, explicitly returned modes and ordered lists still compare.
    """
    return _contains_definition(expected, actual, ())


def _absolute_time_range(definition: dict[str, Any]) -> bool:
    if definition.get("mode") != "absolute":
        return False
    try:
        return all(
            datetime.fromisoformat(definition[key]).tzinfo is not None for key in ("from", "to")
        )
    except (KeyError, TypeError, ValueError):
        return False


def _contains_definition(expected: Any, actual: Any, path: tuple[str, ...]) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            (
                key not in actual
                and (
                    (key == "query" and value == {"language": "kql", "expression": ""})
                    or (
                        path == ("time_range",) and key == "mode" and _absolute_time_range(expected)
                    )
                )
            )
            or (key in actual and _contains_definition(value, actual[key], (*path, key)))
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(expected) == len(actual)
            and all(
                _contains_definition(first, second, (*path, str(index)))
                for index, (first, second) in enumerate(zip(expected, actual, strict=True))
            )
        )
    return bool(expected == actual)


def apply_definitions(
    root: Path,
    definitions: dict[str, dict[str, Any]],
    kibana: JsonHttp,
    space: str,
) -> int:
    """Preflight every id, back up, then stop and report at the first partial failure."""
    version = kibana_version(kibana)
    existing: dict[str, dict[str, Any] | None] = {}
    for dashboard_id, definition in definitions.items():
        response = kibana.request("GET", dashboard_path(dashboard_id, space), allow_missing=True)
        if (
            response is not None
            and definition_from_response(response)["title"] != definition["title"]
        ):
            raise DashboardError(f"{dashboard_id}: existing title differs; refusing to overwrite")
        existing[dashboard_id] = response
    directory, manifest = backup_definitions(
        root, existing, definitions, kibana_url=kibana.base, space=space, version=version
    )
    print(f"Backup: {directory}")
    for dashboard_id, definition in definitions.items():
        path = dashboard_path(dashboard_id, space)
        manifest["status"] = "applying"
        manifest["in_progress"] = dashboard_id
        write_json(directory / "MANIFEST.json", manifest)
        try:
            kibana.request("PUT", path, definition)
            response = kibana.request("GET", path)
            if response is None or not contains_definition(
                definition, definition_from_response(response)
            ):
                raise DashboardError(f"{dashboard_id}: saved definition differs from the request")
        except (DashboardError, OSError) as exc:
            manifest["failed"].append({"id": dashboard_id, "error": str(exc)})
            manifest["status"] = "partial_failure"
            write_json(directory / "MANIFEST.json", manifest)
            print(f"FAIL {exc}", file=sys.stderr)
            print(
                f"Applied and verified: {len(manifest['applied'])}/{len(definitions)}. "
                f"The failed id may have been written; inspect {directory / 'MANIFEST.json'}. "
                "Remaining requests were not attempted. No dashboard was deleted.",
                file=sys.stderr,
            )
            return 1
        manifest["applied"].append(dashboard_id)
        manifest.pop("in_progress", None)
        write_json(directory / "MANIFEST.json", manifest)
        print(f"OK {path} (saved and read back)")
    manifest["status"] = "complete"
    write_json(directory / "MANIFEST.json", manifest)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write Kibana dashboards after backup")
    parser.add_argument("--kibana", type=endpoint, default="http://localhost:5601")
    parser.add_argument("--es", type=endpoint, default="http://localhost:9200")
    parser.add_argument("--space", type=space_identifier, default="default")
    parser.add_argument(
        "--historical-range",
        action="store_true",
        help="read stored timestamps for the dashboard range",
    )
    args = parser.parse_args(argv)
    report = Report()
    verify_static(ROOT, report)
    if report.failed:
        return 1
    try:
        definitions = load_definitions(ROOT)
        if args.historical_range:
            period = historical_range(JsonHttp(args.es))
            definitions = copy.deepcopy(definitions)
            for definition in definitions.values():
                definition["time_range"] = period.copy()
            print(f"Historical range: {period['from']} to {period['to']} (request only)")
        for dashboard_id, definition in definitions.items():
            print(f"PLAN PUT {dashboard_path(dashboard_id, args.space)}: {definition['title']}")
        if not args.apply:
            print("Dry run complete. Add --apply to write these dashboards to Kibana.")
            return 0
        return apply_definitions(ROOT, definitions, JsonHttp(args.kibana), args.space)
    except (DashboardError, OSError, ValueError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
