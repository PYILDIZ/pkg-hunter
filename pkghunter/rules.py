"""Static detection rules applied to package file contents.

Each rule is a signal, not a verdict. Legitimate packages trip some of them
(e.g. a CLI that shells out), which is why scores combine many weak signals,
and why install-time files (setup.py, .pth) count extra: code there runs the
moment someone types `pip install`.
"""

from __future__ import annotations

import ast
import re
import warnings
from bisect import bisect_right
from dataclasses import dataclass
from typing import Callable

from .fetch import Member


def _parts(path: str) -> list[str]:
    return [p for p in path.replace("\\", "/").split("/") if p]


def _is_setup(m: Member) -> bool:
    # Only the top-level setup.py of an sdist ("name-1.0/setup.py") runs on install.
    parts = _parts(m.path)
    return not m.in_wheel and parts[-1] == "setup.py" and len(parts) <= 2


def _is_pth(m: Member) -> bool:
    return m.path.lower().endswith(".pth")


def is_install_time(m: Member) -> bool:
    # .pth files only auto-execute from the site-packages root (wheel root).
    return _is_setup(m) or (_is_pth(m) and m.in_wheel and len(_parts(m.path)) == 1)


_TEST_DIRS = {"tests", "test", "testing", "examples", "docs", "benchmarks"}


def is_test_or_docs(path: str) -> bool:
    parts = [p.lower() for p in _parts(path)]
    name = parts[-1]
    return (any(p in _TEST_DIRS for p in parts[:-1]) or name.startswith("test_")
            or name.endswith("_test.py") or name == "conftest.py")


def location_multiplier(m: Member) -> float:
    """Weight a hit by how likely that file is to run on a victim's machine."""
    if is_install_time(m):
        return 1.5   # runs during `pip install` / every interpreter start
    if is_test_or_docs(m.path):
        return 0.2   # tests and examples aren't run by installers or importers
    if not m.path.lower().endswith((".py", ".pyw", ".pth")):
        return 0.5   # bundled shell/JS scripts don't run unless someone runs them
    return 1.0


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    weight: int
    pattern: re.Pattern
    applies_to: Callable[[Member], bool] | None = None  # None = every scanned file
    # Real stealers hit many targets; one mention is usually docs or a check.
    needs_variety: bool = False
    # Hits on a line matching this are ignored (e.g. well-known installers).
    allow: re.Pattern | None = None
    # In .py files, only full weight if something nearby executes it.
    needs_sink: bool = False


@dataclass
class Finding:
    rule: str
    title: str
    weight: float
    path: str
    line: int
    snippet: str


def _r(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


RULES: list[Rule] = [
    # --- Payload execution / obfuscation -------------------------------------
    Rule("EXEC_DECODED", "exec/eval of a decoded or decompressed payload", 45,
         _r(r"\b(?:exec|eval)\s*\(\s*(?:\w+\.)*(?:b64decode|b32decode|b85decode|decompress|loads|fromhex|decode)\s*\(")),
    Rule("MARSHAL_LOADS", "marshal.loads (runs pre-compiled hidden bytecode)", 20,
         _r(r"\bmarshal\.loads\s*\(")),
    Rule("DYNAMIC_IMPORT", "__import__ of a sensitive module (hides imports from readers)", 8,
         _r(r"__import__\s*\(\s*['\"](?:os|subprocess|socket|base64|ctypes|zlib|marshal|builtins)['\"]")),
    Rule("CHR_CHAIN", "string built from chr() chains (obfuscation)", 25,
         _r(r"(?:chr\(\s*\d+\s*\)\s*\+\s*){6,}")),
    Rule("HEX_BLOB", "long hex-escaped string (obfuscated payload)", 15,
         _r(r"(?:\\x[0-9a-fA-F]{2}){40,}")),
    Rule("BASE64_BLOB", "long base64 string literal (possible embedded payload)", 15,
         _r(r"['\"][A-Za-z0-9+/]{300,}={0,2}['\"]")),

    # --- Install-time behaviour (setup.py / .pth only) -----------------------
    Rule("SETUP_NETWORK", "network access during install", 30,
         _r(r"\b(?:urllib\.request|urlopen|requests\.(?:get|post)|http\.client|socket\.socket|httpx\.|aiohttp\.)"),
         is_install_time),
    Rule("SETUP_PROCESS", "spawns processes during install", 25,
         _r(r"\b(?:subprocess\.(?:Popen|run|call|check_output|check_call)|os\.system|os\.popen|os\.startfile)\b"),
         is_install_time),
    Rule("CMDCLASS_OVERRIDE", "custom install command (code runs during pip install)", 15,
         _r(r"cmdclass\s*=\s*\{[^}]*['\"](?:install|develop|egg_info|bdist_wheel)['\"]", re.S),
         _is_setup),
    Rule("PTH_EXEC", ".pth file with code (runs on every Python start-up)", 20,
         _r(r"^\s*import\s", re.M), _is_pth),

    # --- Exfiltration / C2 --------------------------------------------------
    Rule("EXFIL_ENDPOINT", "known exfiltration endpoint (webhook / bot API / OAST)", 20,
         _r(r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services"
            r"|webhook\.site|pipedream\.net|requestbin|interact\.sh|burpcollaborator\.net"
            r"|\boast\.(?:fun|pro|live|site|online|me)\b|ngrok(?:-free)?\.(?:io|app)", re.I)),
    Rule("RAW_IP_URL", "URL pointing at a raw public IP address", 20,
         # excludes loopback, private (RFC 1918), link-local, documentation
         # ranges (RFC 5737) and the classic 1.2.3.4 placeholder
         _r(r"https?://(?!127\.|0\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\."
            r"|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|1\.2\.3\.4\b|1\.1\.1\.1\b|8\.8\.[48]\.[48]\b)"
            r"(?:\d{1,3}\.){3}\d{1,3}")),
    Rule("PASTE_OR_SHORTENER", "payload hosting / URL-shortener domain", 20,
         _r(r"pastebin\.com/raw|paste\.ee/r|transfer\.sh|rentry\.co|hastebin|bit\.ly/|tinyurl\.com/"
            r"|cdn\.discordapp\.com/attachments", re.I)),

    # --- Credential theft / host abuse ---------------------------------------
    # Deliberately moderate on its own: secret scanners and agent sandboxes
    # list these paths too. Paired with exfiltration it becomes STEALER_COMBO.
    Rule("CREDENTIAL_PATHS", "references browser, wallet or developer credential stores", 20,
         _r(r"Login Data|Local State|Web Data|Local Storage[/\\]+leveldb|\.ssh[/\\]+id_"
            r"|\.aws[/\\]+credentials|wallet\.dat|Telegram Desktop[/\\]+tdata|exodus\.wallet"
            r"|nkbihfbeogaeaoehlefnkodbefgpgknn|\.git-credentials|\.pypirc"),
         needs_variety=True),
    Rule("ENV_DUMP", "collects the entire environment (secrets, tokens)", 5,
         _r(r"dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)|json\.dumps\(\s*(?:dict\()?\s*os\.environ")),
    Rule("DOWNLOAD_EXECUTE", "download-and-execute pattern", 35,
         _r(r"powershell[^\n]{0,60}\s-(?:e|enc|encodedcommand)\s|certutil[^\n]{0,30}-urlcache"
            r"|(?:curl|wget)[^\n|]{0,200}\|\s*(?:ba)?sh\b"
            r"|(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,200}\|\s*(?:iex|Invoke-Expression)\b"
            r"|\bIEX\s*\(|\bmshta\s+https?:|bitsadmin\s+/transfer", re.I),
         # Ignore well-known installers, and commands written as instructions
         # for a human (help text / error messages): malware runs the command,
         # legitimate tools print it.
         allow=_r(r"https://(?:astral\.sh|claude\.ai/install|sh\.rustup\.rs|get\.docker\.com|bun\.sh"
                  r"|deno\.land|install\.python-poetry\.org|pyenv\.run|ollama\.com/install"
                  r"|raw\.githubusercontent\.com/(?:nvm-sh|Homebrew)/|get\.helm\.sh|deb\.nodesource\.com)"
                  r"|`[^`\n]*(?:curl|wget|powershell|iex)[^`\n]*`"
                  r"|\b(?:install(?:ed)?\s+(?:it\s+)?(?:with|via|using|by running)|to install|please run"
                  r"|you can run|then run|or run|\w*hint\w*\s*[=:])", re.I),
         needs_sink=True),
    Rule("PERSISTENCE", "persistence mechanism (autorun, scheduled task, shell rc)", 20,
         _r(r"CurrentVersion\\+Run|schtasks\s+/create|LaunchAgents|Startup\\+|>>\s*~?/?\.bashrc|crontab\s+-", re.I)),
    Rule("HOST_RECON", "collects host identity (user, hostname)", 5,
         _r(r"getpass\.getuser\(\)|socket\.gethostname\(\)|platform\.node\(\)|os\.getlogin\(\)")),
]

BINARY_SUFFIXES = (".exe", ".dll", ".scr", ".msi", ".bin")

# Weak signals: common in legitimate code. They only add to a score when at
# least one strong signal is present (see analyzer.score_findings).
CONTEXT_RULES = {"DYNAMIC_IMPORT", "ENV_DUMP", "HOST_RECON", "NO_PROJECT_URLS", "NO_DESCRIPTION"}

_COMMENT_PREFIXES = ("#", "//", "rem ", "::")


def _snippet(text: str, start: int) -> tuple[int, str]:
    line_no = text.count("\n", 0, start) + 1
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    line = text[line_start: line_end if line_end != -1 else len(text)].strip()
    if len(line) > 160:
        col = start - line_start
        line = "..." + line[max(0, col - 40): col + 100] + "..."
    printable = "".join(c if c.isprintable() else "?" for c in line)
    return line_no, printable


def scan_member(member: Member) -> list[Finding]:
    findings: list[Finding] = []
    if member.path.lower().endswith(BINARY_SUFFIXES):
        findings.append(Finding("BUNDLED_EXECUTABLE", "ships a Windows executable/binary blob",
                                20, member.path, 0, f"{member.size} bytes"))
    if member.content is None:
        return findings

    text = member.content.decode("utf-8", errors="replace")
    multiplier = location_multiplier(member)
    line_starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]
    prose_lines = _docstring_lines(text) if member.path.lower().endswith((".py", ".pyw")) else set()

    def ignored(rule: Rule, pos: int) -> bool:
        if bisect_right(line_starts, pos) in prose_lines or _in_comment(text, pos):
            return True
        line = _line_at(text, pos)
        if rule.id not in OBFUSCATION_RULES and _REGEX_LITERAL.search(line):
            return True  # a detection pattern, i.e. defensive code
        if rule.id in EXFIL_RULES and _DOMAIN_LIST.search(line):
            return True  # a catalogue of bare domains = blocklist, not a C2 URL
        return bool(rule.allow and rule.allow.search(line))

    full_strength: set[str] = set()
    for rule in RULES:
        if rule.applies_to and not rule.applies_to(member):
            continue
        hits = [m for m in rule.pattern.finditer(text) if not ignored(rule, m.start())]
        if not hits:
            continue
        weight = rule.weight * multiplier
        if rule.needs_variety and len({m.group(0).lower() for m in hits}) < 2:
            weight *= 0.3
        else:
            full_strength.add(rule.id)
        if rule.needs_sink and member.path.lower().endswith((".py", ".pyw")):
            executed = [m for m in hits if _near_sink(text, line_starts, m.start())]
            if executed:
                hits = executed
            else:
                weight *= 0.3  # mentioned (help text, constants), never executed
        line, snip = _snippet(text, hits[0].start())
        findings.append(Finding(rule.id, rule.title, round(weight, 1), member.path, line, snip))

    # A stealer reads credential stores AND ships data out from the same file.
    # Either alone is common in legitimate tools; together they're the tell.
    if "CREDENTIAL_PATHS" in full_strength and full_strength & EXFIL_RULES:
        findings.append(Finding("STEALER_COMBO", "credential theft and exfiltration in the same file",
                                round(30 * max(multiplier, 0.5), 1), member.path, 0, ""))
    return findings


EXFIL_RULES = {"EXFIL_ENDPOINT", "RAW_IP_URL", "PASTE_OR_SHORTENER"}
OBFUSCATION_RULES = {"EXEC_DECODED", "MARSHAL_LOADS", "CHR_CHAIN", "HEX_BLOB", "BASE64_BLOB"}

# Three or more quoted bare domains in a row: ("pastebin.com", "paste.ee", "rentry.co", ...)
_DOMAIN_LIST = re.compile(r"""(?:["'][\w-]+(?:\.[\w-]+)+["']\s*,\s*){2,}["'][\w-]+(?:\.[\w-]+)+["']""")

# A raw-string literal containing regex syntax: r"...(?:..." / r"\.ssh" / r"[^/]+"
_REGEX_LITERAL = re.compile(r"""\b[rR][bB]?(["'])(?=[^"'\n]*(?:\(\?|\\[.bdsw]|\[\^))""")


def _docstring_lines(source: str) -> set[int]:
    """Line numbers covered by docstrings and bare string 'comments'.

    ast.parse only parses; it never executes the code. Files that don't parse
    (Python 2, syntax tricks) simply get no docstring exemption.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # old code emits SyntaxWarnings on parse
            tree = ast.parse(source)
    except Exception:  # SyntaxError, RecursionError, MemoryError on hostile input...
        return set()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            lines.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return lines


_SINK = re.compile(r"subprocess\.|\bos\.(?:system|popen|exec\w*|spawn\w*)\b|\bPopen\(|shell\s*=\s*True"
                   r"|\bexec\(|\bcheck_output\(|\bcheck_call\(|\bpty\.spawn")
SINK_WINDOW = 5  # lines before/after a hit


def _near_sink(text: str, line_starts: list[int], pos: int) -> bool:
    line = bisect_right(line_starts, pos) - 1
    lo = line_starts[max(0, line - SINK_WINDOW)]
    hi_line = line + SINK_WINDOW + 1
    hi = line_starts[hi_line] if hi_line < len(line_starts) else len(text)
    return bool(_SINK.search(text, lo, hi))


def _line_at(text: str, pos: int) -> str:
    end = text.find("\n", pos)
    return text[text.rfind("\n", 0, pos) + 1: end if end != -1 else len(text)]


def _in_comment(text: str, pos: int) -> bool:
    line_start = text.rfind("\n", 0, pos) + 1
    return text[line_start:pos].lstrip().lower().startswith(_COMMENT_PREFIXES)
