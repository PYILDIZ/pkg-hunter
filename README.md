# pkg-hunter

Watches PyPI in near-real time and flags newly published packages that look
malicious: typosquats of popular libraries, install-time code execution,
credential stealers, exfiltration to webhooks, and obfuscated payloads.

> **Safety model:** package files are downloaded **into memory** (from
> `files.pythonhosted.org` only, hash-verified) and read as text. Nothing is
> extracted to disk, installed, imported or executed. Symlinks are skipped and
> size limits guard against decompression bombs.

## Quick start

Python 3.10+, no dependencies.

```powershell
python -m pkghunter scan some-package              # scan one package (latest version)
python -m pkghunter scan some-package --version 1.0 --json
python -m pkghunter watch                          # poll PyPI every 5 min, scan every new release
python -m pkghunter watch --once                   # single pass, good for cron / CI
python -m pkghunter report --out reports/week1.md  # Markdown report with evidence + report drafts
```

Run these from the repo folder. `pip install -e .` also adds a `pkghunter`
command, if your Python `Scripts` folder is on PATH.

Results are stored in `data/pkghunter.db` (SQLite).

## How it works

```
PyPI RSS (new projects + updates)
        │
        ▼
 PyPI JSON API ──► metadata signals (no repo link, empty description,
        │                            inflated first version = dependency confusion)
        ▼
 sdist + one wheel, downloaded into memory, sha256-checked
        │
        ▼
 static rules on every .py/.pth/.sh/.ps1/... file  ──┐
 typosquat check against the top 5,000 PyPI names  ──┼──► weighted score ──► verdict
                                                     ┘
```

### Where code runs matters more than what it says

Every finding is weighted by **how likely that file is to execute on a victim's
machine**:

| Location | Multiplier | Why |
|---|---|---|
| sdist top-level `setup.py`, wheel-root `.pth` | ×1.5 | runs on `pip install` / every Python start-up |
| normal package code | ×1.0 | runs on import |
| bundled shell/JS scripts | ×0.5 | only runs if someone runs it |
| `tests/`, `docs/`, `examples/` | ×0.2 | not run by installers or importers |

Other false-positive controls:
- matches in comment lines are ignored
- credential-store references need **variety** (stealers target many stores at once; a single `.aws/credentials` mention is usually config handling)
- weak "context" signals (`dict(os.environ)`, `socket.gethostname()`, missing homepage) only add to a score when a strong signal is present
- loopback/private/documentation IPs and well-known installers (`astral.sh`, `sh.rustup.rs`, …) are allow-listed
- a lookalike name alone stays below the "suspicious" line, but it's shown in `watch` output as a watchlist and adds a bonus when combined with suspicious code

### Verdicts

| Score | Verdict |
|---|---|
| ≥ 60 | `likely-malicious` |
| ≥ 25 | `suspicious` (human triage queue) |
| < 25 | `clean` |
| — | `removed`: gone from PyPI before we scanned it (usually taken down as malware) |

### Detection rules

| Rule | Signal |
|---|---|
| `EXEC_DECODED` | `exec`/`eval` of base64/zlib/marshal/hex-decoded data |
| `MARSHAL_LOADS`, `CHR_CHAIN`, `HEX_BLOB`, `BASE64_BLOB` | obfuscation |
| `SETUP_NETWORK`, `SETUP_PROCESS`, `CMDCLASS_OVERRIDE` | install-time behaviour in `setup.py` |
| `PTH_EXEC` | `.pth` file with `import` (runs on every interpreter start) |
| `EXFIL_ENDPOINT` | Discord/Slack webhooks, Telegram bot API, webhook.site, OAST domains |
| `RAW_IP_URL`, `PASTE_OR_SHORTENER` | payload hosting |
| `CREDENTIAL_PATHS` | browser `Login Data`, crypto wallets, `.ssh/id_*`, `.aws/credentials`, Discord tokens |
| `DOWNLOAD_EXECUTE`, `PERSISTENCE` | `curl \| sh`, encoded PowerShell, `certutil`, Run keys, LaunchAgents |
| `BUNDLED_EXECUTABLE` | `.exe`/`.dll` shipped inside a Python package |
| `INFLATED_VERSION` | first-ever release numbered `99.0.0` (dependency-confusion trick) |
| typosquat | one-character edits, separator tricks, `py-`/`-dev` affixes, `rn`→`m` lookalikes |

## Tuning log

Every false positive below was a real, legitimate PyPI project. Each round
fixed a *class* of mistake, not a single package.

| Round | False "likely-malicious" | Root cause | Fix |
|---|---|---|---|
| 1 | 5 / 135 | hits in tests, comments, a nested `setup.py`, placeholder IPs (`1.2.3.4`, `203.0.113.x`) | weight by where code runs; ignore comments; only the sdist's top-level `setup.py` is install-time |
| 2 | 1 / ~150 | `curl … \| sh` inside a *help message*: "Install with `curl … \| sh`" | allow instruction phrasing and backtick-quoted commands |
| 3 | 1 / ~60 | credential paths in a docstring explaining a sandbox; Telegram bot integration | skip docstrings (via `ast`, parsed, never executed); exfil endpoint alone counts less; new `STEALER_COMBO` when credential theft and exfil share a file |
| 4 | 4 / 180 | **security tools**: regexes that *detect* `~/.ssh/id_rsa`, sets of PowerShell download cmdlets, "install hints" spanning lines | ignore regex literals; a download command in `.py` needs an execution sink (`subprocess`, `os.system`, `shell=True`…) within 5 lines |
| 5 | 1 / 132 | an AI-agent guard's domain **blocklist** (`("pastebin.com", "paste.ee", …)`) | 3+ bare quoted domains on a line = catalogue, not C2 |

The main lesson: **defensive code looks like offensive code.** Secret scanners,
agent sandboxes and EDR-style tools contain the same strings as stealers. What
separates them is *context*: whether the string is executed, where the file
runs, and whether credential access and exfiltration happen together.

## Reporting what you find

1. Read the evidence (`pkghunter report`) and confirm it by hand. A score is a lead, not proof.
2. Report it from the project's PyPI page (**Report project as malware**) using the generated report draft.
3. Never install a flagged package to "check". If you need dynamic analysis, use a disposable VM with no credentials on it.

## Roadmap

- [ ] Measure precision/recall against a labelled corpus of known-malicious packages (e.g. Datadog's public malicious-packages dataset), analysed in a VM
- [ ] AST-based rules (taint from `os.environ`/file reads to network sinks) instead of regex
- [ ] Version diffing: flag when a previously clean package suddenly gains install-time code
- [ ] npm support (`postinstall` scripts)
- [ ] Discord/Slack alerts and a scheduled GitHub Actions run that publishes daily reports

## Prior art

[GuardDog](https://github.com/DataDog/guarddog), [Socket](https://socket.dev),
[OSSF package-analysis](https://github.com/ossf/package-analysis). pkg-hunter is a
from-scratch learning project focused on install-time execution paths and
explainable scoring.

## Tests

```powershell
$env:PYTHONPATH = "$PWD;$PWD\tests"; python -m unittest discover -s tests -v
```

Test fixtures are inert text built in memory. No real malware is included.

## License

MIT
