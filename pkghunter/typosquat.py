"""Detect names that imitate popular PyPI packages."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from .http import get_json
from .pypi import normalize

TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
CACHE_MAX_AGE = 7 * 24 * 3600
TOP_N = 5000

# Used only if the download fails and there's no cache.
FALLBACK_TOP = [
    "boto3", "urllib3", "requests", "setuptools", "certifi", "numpy", "pandas",
    "charset-normalizer", "idna", "typing-extensions", "python-dateutil",
    "packaging", "six", "pyyaml", "cryptography", "pydantic", "attrs", "pip",
    "jinja2", "click", "colorama", "pillow", "matplotlib", "scipy", "flask",
    "django", "fastapi", "selenium", "beautifulsoup4", "openai", "anthropic",
    "tensorflow", "torch", "scikit-learn", "discord-py", "pycryptodome",
    "pytest", "rich", "tqdm", "httpx", "aiohttp", "websockets", "psutil",
]

PREFIXES = ("python-", "py-", "python", "py")
SUFFIXES = ("-python", "-py", "-dev", "-lib", "-sdk", "-api", "-tools", "-latest", "2", "3", "-v2")
HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("1", "l"), ("0", "o"), ("l", "i"))


@dataclass(frozen=True)
class Squat:
    target: str
    technique: str
    target_rank: int


def osa_distance(a: str, b: str) -> int:
    """Optimal-string-alignment distance (Levenshtein + adjacent transposition)."""
    if a == b:
        return 0
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = ca != cb
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


class TyposquatDetector:
    def __init__(self, popular: list[str]):
        self.popular = [normalize(p) for p in popular]
        self.rank = {p: i for i, p in enumerate(self.popular)}

    @classmethod
    def load(cls, cache_dir: Path) -> "TyposquatDetector":
        cache = cache_dir / "top_pypi.json"
        fresh = cache.exists() and time.time() - cache.stat().st_mtime < CACHE_MAX_AGE
        if not fresh:
            try:
                rows = get_json(TOP_URL)["rows"]
                names = [r["project"] for r in rows[:TOP_N]]
                cache_dir.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps(names), encoding="utf-8")
            except Exception:
                pass
        if cache.exists():
            return cls(json.loads(cache.read_text(encoding="utf-8")))
        return cls(FALLBACK_TOP)

    def check(self, name: str) -> Squat | None:
        n = normalize(name)
        if n in self.rank:
            return None  # it's the popular package itself

        hits: list[Squat] = []
        collapsed = n.replace("-", "")

        for p, rank in self.rank.items():
            if len(p) < 5:
                continue  # very short names produce mostly false positives
            if collapsed == p.replace("-", ""):
                hits.append(Squat(p, "separator change", rank))
            elif abs(len(n) - len(p)) <= 1 and osa_distance(n, p) == 1:
                hits.append(Squat(p, "one-character edit", rank))

        top1000 = {p for p, r in self.rank.items() if r < 1000 and len(p) >= 4}
        for pre in PREFIXES:
            if n.startswith(pre) and n[len(pre):] in top1000:
                p = n[len(pre):]
                hits.append(Squat(p, f"added prefix '{pre}'", self.rank[p]))
        for suf in SUFFIXES:
            if n.endswith(suf) and n[: -len(suf)] in top1000:
                p = n[: -len(suf)]
                hits.append(Squat(p, f"added suffix '{suf}'", self.rank[p]))
        for fake, real in HOMOGLYPHS:
            if fake in n:
                p = n.replace(fake, real)
                if p in self.rank and len(p) >= 4:
                    hits.append(Squat(p, f"lookalike '{fake}' for '{real}'", self.rank[p]))

        return min(hits, key=lambda s: s.target_rank) if hits else None
