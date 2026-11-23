"""Download package artifacts into memory and read their files safely.

Nothing here writes package contents to disk or executes them. Archives are
opened from a BytesIO buffer and members are read with strict size limits, so
path-traversal entries, symlinks and decompression bombs can't hurt the host.
"""

from __future__ import annotations

import hashlib
import io
import posixpath
import tarfile
import zipfile
from dataclasses import dataclass
from typing import Iterator
from urllib.parse import urlparse

from .http import get

ALLOWED_HOSTS = {"files.pythonhosted.org"}
MAX_ARTIFACT_BYTES = 25 * 1024 * 1024   # skip artifacts bigger than this
MAX_MEMBER_BYTES = 1 * 1024 * 1024      # read at most this much of one file
MAX_MEMBERS = 5000                      # stop after this many archive entries
MAX_TOTAL_UNPACKED = 200 * 1024 * 1024  # decompression-bomb guard

# Files whose text content we scan. Everything else is only listed by name.
TEXT_SUFFIXES = (
    ".py", ".pyw", ".pth", ".cfg", ".toml",
    ".sh", ".bat", ".cmd", ".ps1", ".vbs", ".js",
)


@dataclass
class Member:
    path: str
    size: int
    content: bytes | None  # None when not a scanned file type or too large
    in_wheel: bool = False  # wheels never run setup.py; sdists never auto-run .pth

    @property
    def basename(self) -> str:
        return posixpath.basename(self.path)


def choose_artifacts(files: list[dict]) -> list[dict]:
    """Pick the sdist (install-time code lives here) and one wheel (.pth files)."""
    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
    wheels.sort(key=lambda f: ("none-any" not in f.get("filename", ""), f.get("size", 0)))
    return sdists[:1] + wheels[:1]


def download(file_info: dict) -> bytes:
    url = file_info["url"]
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError(f"refusing to download from unexpected host: {url}")
    data = get(url, max_bytes=MAX_ARTIFACT_BYTES, timeout=60)
    expected = (file_info.get("digests") or {}).get("sha256")
    if expected and hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"sha256 mismatch for {file_info.get('filename')}")
    return data


def _wanted(path: str) -> bool:
    return path.lower().endswith(TEXT_SUFFIXES)


def iter_members(filename: str, data: bytes) -> Iterator[Member]:
    lower = filename.lower()
    if lower.endswith((".whl", ".zip", ".egg")):
        in_wheel = lower.endswith((".whl", ".egg"))
        for m in _iter_zip(data):
            m.in_wheel = in_wheel
            yield m
    elif lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        yield from _iter_tar(data)


def _iter_zip(data: bytes) -> Iterator[Member]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        total = 0
        for i, info in enumerate(zf.infolist()):
            if i >= MAX_MEMBERS or total > MAX_TOTAL_UNPACKED:
                return
            if info.is_dir():
                continue
            content = None
            if _wanted(info.filename) and info.file_size <= MAX_MEMBER_BYTES:
                with zf.open(info) as fh:
                    content = fh.read(MAX_MEMBER_BYTES)
                total += len(content)
            yield Member(info.filename, info.file_size, content)


def _iter_tar(data: bytes) -> Iterator[Member]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        total = 0
        for i, m in enumerate(tf):
            if i >= MAX_MEMBERS or total > MAX_TOTAL_UNPACKED:
                return
            total += m.size
            if not m.isfile():  # skip symlinks, hardlinks, devices, dirs
                continue
            content = None
            if _wanted(m.name) and m.size <= MAX_MEMBER_BYTES:
                fh = tf.extractfile(m)  # file object in memory, not written to disk
                if fh is not None:
                    content = fh.read(MAX_MEMBER_BYTES)
            yield Member(m.name, m.size, content)
