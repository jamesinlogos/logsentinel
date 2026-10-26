"""Elasticsearch query helpers for index families used by LogSentinel."""

from __future__ import annotations

from typing import Any

from sentinelbench.clients.http import HttpClient, HttpError


class ElasticsearchClient:
    def __init__(self, host: str, *, timeout_sec: float = 60.0) -> None:
        self.http = HttpClient(host, timeout_sec=timeout_sec)

    def ping(self) -> dict[str, Any]:
        return self.http.request("GET", "/")

    def cluster_health(self) -> dict[str, Any]:
        return self.http.request("GET", "/_cluster/health")

    def cat_indices(self, pattern: str) -> str:
        path = (
            f"/_cat/indices/{pattern}?v&s=index"
            "&h=index,health,status,docs.count,store.size,pri.store.size"
        )
        result = self.http.request("GET", path)
        return result if isinstance(result, str) else str(result)

    def count(self, index: str, query: dict[str, Any] | None = None) -> int:
        body = {"query": query} if query is not None else None
        try:
            result = self.http.request("POST" if body else "GET", f"/{index}/_count", body=body)
        except HttpError as exc:
            if exc.status == 404:
                return 0
            raise
        return int((result or {}).get("count", 0))

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            result = self.http.request("POST", f"/{index}/_search", body=body)
        except HttpError as exc:
            if exc.status == 404:
                return {"hits": {"hits": [], "total": {"value": 0}}}
            raise
        return result or {"hits": {"hits": [], "total": {"value": 0}}}

    def period_query(self, since: str, *, field: str = "@timestamp") -> dict[str, Any]:
        return {"range": {field: {"gte": f"now-{since}"}}}
