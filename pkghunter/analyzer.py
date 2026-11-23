"""Combine metadata, name and code signals into one score and verdict."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import fetch
from .http import NotFound
from .pypi import Release, get_release
from .rules import CONTEXT_RULES, Finding, scan_member
from .typosquat import Squat, TyposquatDetector

SUSPICIOUS_AT = 25
MALICIOUS_AT = 60
STRONG_AT = 20  # a single finding at least this heavy "unlocks" context signals
# A lookalike name alone stays under SUSPICIOUS_AT: most near-miss names are
# innocent. It still shows in `watch` output, and with suspicious code it
# triggers the combo bonus.
SQUAT_WEIGHT = 20
COMBO_WEIGHT = 15


@dataclass
class ScanResult:
    name: str
    version: str | None
    verdict: str  # clean | suspicious | likely-malicious | removed | error
    score: float = 0
    findings: list[Finding] = field(default_factory=list)
    squat: Squat | None = None
    artifacts: list[str] = field(default_factory=list)
    files_scanned: int = 0
    feed: str | None = None
    error: str | None = None
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        d = dict(d)
        d["findings"] = [Finding(**f) for f in d.get("findings", [])]
        d["squat"] = Squat(**d["squat"]) if d.get("squat") else None
        return cls(**d)

    @property
    def url(self) -> str:
        return f"https://pypi.org/project/{self.name}/" + (f"{self.version}/" if self.version else "")


def metadata_findings(rel: Release) -> list[Finding]:
    info = rel.info
    out: list[Finding] = []
    if not info.get("home_page") and not info.get("project_urls"):
        out.append(Finding("NO_PROJECT_URLS", "no homepage or source repository link", 5, "<metadata>", 0, ""))
    if len((info.get("description") or "").strip()) < 20 and len((info.get("summary") or "").strip()) < 5:
        out.append(Finding("NO_DESCRIPTION", "empty description and summary", 5, "<metadata>", 0, ""))
    m = re.match(r"(\d+)", rel.version or "")
    if rel.release_count == 1 and m and int(m.group(1)) >= 50:
        out.append(Finding("INFLATED_VERSION", "first-ever release with an inflated version "
                           "(dependency-confusion trick)", 25, "<metadata>", 0, rel.version))
    return out


def score_findings(findings: list[Finding], squat: Squat | None) -> tuple[float, list[Finding]]:
    best: dict[str, Finding] = {}
    for f in findings:  # each rule counts once, at its strongest hit
        if f.rule not in best or f.weight > best[f.rule].weight:
            best[f.rule] = f
    kept = sorted(best.values(), key=lambda f: -f.weight)
    strong = any(f.weight >= STRONG_AT and f.rule not in CONTEXT_RULES for f in kept)
    if not strong:  # weak signals alone don't make a package suspicious
        kept = [f for f in kept if f.rule not in CONTEXT_RULES]
    code_score = sum(f.weight for f in kept if f.path != "<metadata>")
    score = sum(f.weight for f in kept)
    if squat:
        score += SQUAT_WEIGHT
        if code_score >= 15:
            kept.insert(0, Finding("SQUAT_WITH_CODE", "lookalike name AND suspicious code",
                                   COMBO_WEIGHT, "<combined>", 0, ""))
            score += COMBO_WEIGHT
    return score, kept


def verdict_for(score: float) -> str:
    if score >= MALICIOUS_AT:
        return "likely-malicious"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "clean"


def scan_release(rel: Release, artifacts: list[tuple[str, bytes]],
                 detector: TyposquatDetector, feed: str | None = None) -> ScanResult:
    """Pure analysis step (no network), so it can be unit-tested."""
    findings = metadata_findings(rel)
    files_scanned = 0
    for filename, data in artifacts:
        for member in fetch.iter_members(filename, data):
            if member.content is not None:
                files_scanned += 1
            findings.extend(scan_member(member))
    squat = detector.check(rel.name)
    score, kept = score_findings(findings, squat)
    return ScanResult(
        name=rel.name, version=rel.version, verdict=verdict_for(score), score=round(score, 1),
        findings=kept, squat=squat, artifacts=[a for a, _ in artifacts],
        files_scanned=files_scanned, feed=feed,
    )


def analyze(name: str, version: str | None, detector: TyposquatDetector,
            feed: str | None = None,
            already_seen: Callable[[str, str], bool] | None = None) -> ScanResult | None:
    """Fetch and scan one release. Returns None if `already_seen` says to skip it."""
    try:
        rel = get_release(name, version)
        if already_seen and already_seen(rel.name, rel.version):
            return None
    except NotFound:
        # Gone from PyPI between being published and being scanned:
        # usually means the admins already removed it as malware.
        return ScanResult(name=name, version=version, verdict="removed", feed=feed)
    except Exception as exc:
        return ScanResult(name=name, version=version, verdict="error", feed=feed, error=repr(exc))

    artifacts: list[tuple[str, bytes]] = []
    errors: list[str] = []
    for f in fetch.choose_artifacts(rel.files):
        try:
            artifacts.append((f["filename"], fetch.download(f)))
        except Exception as exc:
            errors.append(f"{f.get('filename')}: {exc!r}")

    try:
        result = scan_release(rel, artifacts, detector, feed)
    except Exception as exc:  # malformed archive etc.
        return ScanResult(name=rel.name, version=rel.version, verdict="error", feed=feed, error=repr(exc))
    if errors:
        result.error = "; ".join(errors)
    return result
