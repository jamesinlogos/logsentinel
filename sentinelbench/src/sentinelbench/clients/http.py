"""Minimal JSON HTTP client (stdlib)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class HttpError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class HttpClient:
    def __init__(self, base_url: str, *, timeout_sec: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_sec = timeout_sec

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        url = path if path.startswith("http") else f"{self.base_url}/{path.lstrip('/')}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request_headers = {"Accept": "application/json"}
        if body is not None:
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(  # noqa: S310 — operator-configured lab host
            url,
            data=data,
            method=method,
            headers=request_headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_sec) as response:  # noqa: S310
                raw = response.read()
                if not raw:
                    return None
                content_type = response.headers.get("Content-Type", "")
                text = raw.decode("utf-8", errors="replace")
                if "json" in content_type or text[:1] in "{[":
                    return json.loads(text)
                return text
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise HttpError(
                f"{method} {url} -> HTTP {exc.code}: {detail}", status=exc.code
            ) from exc
        except urllib.error.URLError as exc:
            raise HttpError(f"{method} {url} failed: {exc.reason}") from exc
