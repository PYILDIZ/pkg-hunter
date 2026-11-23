"""PyPI feeds and metadata."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import quote

from .http import get, get_json

FEEDS = {
    # Brand-new projects (first upload ever) - the highest-risk population.
    "new": "https://pypi.org/rss/packages.xml",
    # Latest releases of any project.
    "updates": "https://pypi.org/rss/updates.xml",
}

_PROJECT_LINK = re.compile(r"/project/([^/]+)/(?:([^/]+)/)?")


@dataclass(frozen=True)
class FeedItem:
    name: str
    version: str | None
    feed: str


def parse_feed(xml_bytes: bytes, feed: str) -> list[FeedItem]:
    root = ET.fromstring(xml_bytes)
    items: list[FeedItem] = []
    for item in root.iter("item"):
        m = _PROJECT_LINK.search(item.findtext("link") or "")
        if m:
            items.append(FeedItem(name=m.group(1), version=m.group(2), feed=feed))
    return items


def fetch_feed(feed: str) -> list[FeedItem]:
    return parse_feed(get(FEEDS[feed]), feed)


def normalize(name: str) -> str:
    """PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class Release:
    name: str
    version: str
    info: dict
    files: list[dict]
    release_count: int


def get_release(name: str, version: str | None = None) -> Release:
    """Fetch project metadata. Raises http.NotFound if the project is gone."""
    data = get_json(f"https://pypi.org/pypi/{quote(name)}/json")
    info = data["info"]
    releases = data.get("releases") or {}
    if version and version in releases:
        files = releases[version]
    else:
        version = info["version"]
        files = data.get("urls") or []
    return Release(
        name=info.get("name") or name,
        version=version,
        info=info,
        files=files,
        release_count=len(releases) or 1,
    )
