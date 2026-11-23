"""Command-line interface: scan | watch | report."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from . import pypi
from .analyzer import SUSPICIOUS_AT, analyze
from .report import detail, markdown, one_line
from .store import Store
from .typosquat import TyposquatDetector

DATA_DIR = Path.cwd() / "data"


def cmd_scan(args) -> int:
    detector = TyposquatDetector.load(DATA_DIR)
    result = analyze(args.name, args.version, detector)
    Store(DATA_DIR / "pkghunter.db").save(result)
    print(json.dumps(result.to_dict(), indent=2) if args.json else detail(result))
    return 0


def make_output(log_path: str | None) -> Callable[[str], None]:
    """Print to the console and, if asked, append timestamped lines to a log file."""
    log = None
    if log_path:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        log = open(log_path, "a", encoding="utf-8", buffering=1)

    def out(line: str) -> None:
        print(line, flush=True)
        if log and line.strip():
            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {line.strip()}\n")
    return out


def poll_once(store: Store, detector: TyposquatDetector, min_score: float,
              seen: set[tuple[str, str]], delay: float,
              out: Callable[[str], None] = print, workers: int = 4) -> tuple[int, int]:
    """One pass over the feeds. `seen` holds (lowercase name, version) already scanned."""
    items: list[pypi.FeedItem] = []
    for feed in pypi.FEEDS:
        try:
            items += pypi.fetch_feed(feed)
        except Exception as exc:
            out(f"[warn] could not read {feed} feed: {exc!r}")

    # Dedupe: one job per project, preferring the entry that names a version.
    jobs: dict[str, pypi.FeedItem] = {}
    for item in items:
        if item.version and (item.name.lower(), item.version) in seen:
            continue
        key = pypi.normalize(item.name)
        if key not in jobs or (item.version and not jobs[key].version):
            jobs[key] = item

    def is_seen(name: str, version: str) -> bool:
        return (name.lower(), version) in seen

    def work(item: pypi.FeedItem):
        try:
            return analyze(item.name, item.version, detector, feed=item.feed, already_seen=is_seen)
        finally:
            time.sleep(delay)  # be polite to PyPI

    scanned = flagged = 0
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        for fut in as_completed([pool.submit(work, it) for it in jobs.values()]):
            result = fut.result()
            if result is None:  # resolved to a release we've already scanned
                continue
            seen.add((result.name.lower(), result.version or ""))
            store.save(result)  # SQLite writes stay on the main thread
            scanned += 1
            if result.score >= min_score:
                flagged += 1
                out(one_line(result))
            elif result.verdict == "removed":
                out(one_line(result))
    except KeyboardInterrupt:
        # Don't wait for in-flight downloads; drop queued work and exit now.
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown()
    return scanned, flagged


def cmd_watch(args) -> int:
    out = make_output(args.log)
    store = Store(DATA_DIR / "pkghunter.db")
    detector = TyposquatDetector.load(DATA_DIR)
    out(f"Watching PyPI every {args.interval}s (popular-package list: {len(detector.popular)} names). Ctrl+C to stop.")
    print("Legend: !! likely-malicious  ! suspicious  x already removed from PyPI\n")
    seen = store.seen_keys()
    try:
        while True:
            try:
                scanned, flagged = poll_once(store, detector, args.min_score, seen, args.delay,
                                             out, args.workers)
                out(f"[{time.strftime('%m-%d %H:%M')}] scanned {scanned} new releases, {flagged} flagged")
            except Exception as exc:  # keep a multi-day run alive through odd failures
                out(f"[error] poll failed: {exc!r}")
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        out("Stopped.")
        os._exit(0)  # worker threads may still be mid-download; don't wait on them
    return 0


def cmd_report(args) -> int:
    store = Store(DATA_DIR / "pkghunter.db")
    results = [r for r in store.results(args.min_score) if r.verdict not in ("removed", "error")]
    text = markdown(results, store.verdict_counts())
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"Wrote {out} ({len(results)} flagged packages)")
    else:
        print(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    p = argparse.ArgumentParser(prog="pkghunter", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan one PyPI package")
    s.add_argument("name")
    s.add_argument("--version")
    s.add_argument("--json", action="store_true", help="print the raw result as JSON")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="poll PyPI feeds and scan every new release")
    w.add_argument("--interval", type=int, default=300, help="seconds between polls (default 300)")
    w.add_argument("--min-score", type=float, default=SUSPICIOUS_AT, help="print releases at or above this score")
    w.add_argument("--delay", type=float, default=0.5, help="pause after each package scan, per worker")
    w.add_argument("--workers", type=int, default=4, help="packages scanned in parallel (default 4)")
    w.add_argument("--once", action="store_true", help="poll a single time and exit")
    w.add_argument("--log", help="also append timestamped output to this file, e.g. data/watch.log")
    w.set_defaults(func=cmd_watch)

    r = sub.add_parser("report", help="write a Markdown report of flagged packages")
    r.add_argument("--min-score", type=float, default=SUSPICIOUS_AT)
    r.add_argument("--out", help="output file, e.g. reports/week1.md")
    r.set_defaults(func=cmd_report)

    args = p.parse_args(argv)
    return args.func(args)
