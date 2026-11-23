"""Minimal HTTP helpers (stdlib only)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

USER_AGENT = "pkg-hunter/0.1 (malicious-package research; static analysis only)"


class NotFound(Exception):
    """The resource returned HTTP 404 (for PyPI, often: project already removed)."""


class TooLarge(Exception):
    """The response exceeded the configured size cap."""


def get(url: str, *, timeout: float = 30, max_bytes: int | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if max_bytes is None:
                return resp.read()
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise TooLarge(f"{url} is larger than {max_bytes} bytes")
            return data
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise NotFound(url) from exc
        raise


def get_json(url: str, **kwargs) -> dict:
    return json.loads(get(url, **kwargs))
