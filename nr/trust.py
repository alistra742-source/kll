"""Repo trust check -- read a GitHub repository before you run anything from it.

Searching GitHub for an executor returns well over a thousand repositories and
almost none of them are software. Measured on 2026-09-29, the top hits were
repos created within the previous ten days whose entire contents were a
``README.md``, an ``index.html``, a ``button.svg`` and a ``preview.svg``; the
highest-starred of them shipped a single 53-byte Python file that printed a test
string. The download button points off-site, because that is where the payload
lives and GitHub's scanners only ever see the clean half.

None of that is visible from a repo's landing page. It *is* visible from the
repo's metadata, file manifest, and the bytes of the files it ships -- which is
what this module reads. It makes no network calls beyond GitHub's own read-only
API, downloads nothing for execution, and never runs what it fetches.

The output is a verdict plus the specific reasons behind it, so the user can
disagree with a signal rather than trust a score.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests

API = "https://api.github.com"
USER_AGENT = "NightRelay/1.0 repo-trust"

REQUEST_TIMEOUT = 15

# Native/binary source: what an actual injector has to be written in. A repo
# claiming to inject into a running process but shipping none of these is not
# doing the thing it says it does.
SOURCE_EXTS = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx",  # C / C++
    ".cs",                                              # C#
    ".rs",                                              # Rust
    ".asm", ".s", ".nasm",                              # assembly
    ".zig", ".go", ".d",                                # other native
    ".vcxproj", ".sln", ".cmake",                        # build systems
}

DOC_EXTS = {".md", ".txt", ".rst", ".svg", ".png", ".jpg", ".jpeg", ".gif"}

# Language names GitHub reports that mean real compiled/binary code.
NATIVE_LANGS = {
    "C", "C++", "C#", "Rust", "Assembly", "Zig", "D", "Go",
    "Objective-C", "Objective-C++",
}

# Files a landing-page repo ships and a real project does not.
MARKETING_NAMES = {"button.svg", "preview.svg", "download.svg", "banner.svg"}

# Scanner ceiling: read at most this many suspect files, this many bytes each.
MAX_SCAN_FILES = 8
MAX_SCAN_BYTES = 64 * 1024

# Patterns that only appear in text when someone is hiding what it does. Weighted
# because a single ``eval`` in a minified bundle is normal and a nested decoder
# loop is not.
OBFUSCATION_SIGNALS: list[tuple[str, int, str]] = [
    (r"atob\s*\(", 35, "base64 decoder (atob)"),
    (r"String\.fromCharCode\s*\(", 20, "charcode string assembly"),
    (r"\beval\s*\(", 25, "eval of a constructed string"),
    (r"\bunescape\s*\(", 30, "unescape decoder"),
    (r"document\.write\s*\(", 25, "document.write injection"),
    (r"[A-Za-z0-9+/]{160,}={0,2}", 30, "long base64 blob"),
    (r"(\\x[0-9a-fA-F]{2}){12,}", 25, "hex-escaped payload"),
    (r"\bActiveXObject\b", 20, "ActiveX (Windows shell object)"),
    (r"WScript\.Shell|Shell\.Application", 30, "Windows shell execution"),
    (r"\bIEX\b|Invoke-Expression", 25, "PowerShell expression execution"),
    (r"-EncodedCommand|-enc\s+[A-Za-z0-9+/]{40,}", 35, "encoded PowerShell command"),
    (r"\bcurl\b.*\|\s*(ba)?sh", 30, "pipe-to-shell download"),
]

# Hosts that are part of GitHub itself, so a link to them is not "off-site".
GITHUB_HOSTS = ("github.com", "githubusercontent.com", "github.io", "githubassets.com")

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_REPO_RE = re.compile(
    r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:$|[/#?])", re.I
)


# --------------------------------------------------------------------------- #
# Input
# --------------------------------------------------------------------------- #
def parse_repo(ref: str) -> tuple[str, str] | None:
    """Accept ``owner/name``, a clone URL, or any github.com URL."""
    ref = (ref or "").strip()
    if not ref:
        return None
    match = _REPO_RE.search(ref)
    if match:
        return match.group(1), match.group(2)
    parts = ref.strip("/").split("/")
    if len(parts) == 2 and all(p and p not in (".", "..") for p in parts):
        return parts[0], parts[1].removesuffix(".git")
    return None


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass
class Signal:
    """One concrete reason, with the number behind it."""

    weight: int
    text: str

    def to_dict(self) -> dict:
        return {"weight": self.weight, "text": self.text}


@dataclass
class Audit:
    ref: str
    ok: bool = False
    error: str = ""
    verdict: str = "unknown"
    maintenance: str = "unknown"
    score: int = 0
    signals: list[Signal] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    files: list[dict] = field(default_factory=list)
    offsite: list[str] = field(default_factory=list)
    manifest_read: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "ref": self.ref,
            "error": self.error,
            "verdict": self.verdict,
            "maintenance": self.maintenance,
            "score": self.score,
            "signals": [s.to_dict() for s in self.signals],
            "meta": self.meta,
            "files": self.files,
            "offsite": self.offsite,
            "manifest_read": self.manifest_read,
            "note": self.note,
        }


# --------------------------------------------------------------------------- #
# GitHub reads (metadata only -- nothing is downloaded for execution)
# --------------------------------------------------------------------------- #
def _api(path: str) -> tuple[Any, str]:
    """GET a GitHub API path. Returns (payload, error).

    The payload is returned as-is because GitHub mixes shapes: ``/repos/x/y``
    answers with an object and ``/repos/x/y/contents/`` answers with an array.
    Coercing arrays to ``{}`` here would silently erase every file-level signal.
    """
    url = path if path.startswith("http") else f"{API}{path}"
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/vnd.github+json",
            },
        )
    except requests.RequestException as exc:
        return {}, f"github unreachable: {exc.__class__.__name__}"

    if resp.status_code == 404:
        return {}, "repository not found (deleted, renamed, or private)"
    if resp.status_code in (403, 429):
        if "rate limit" in (resp.text or "").lower():
            return {}, "github rate limit reached -- try again in a minute"
        return {}, "github refused the request"
    if resp.status_code >= 400:
        return {}, f"github returned {resp.status_code}"
    try:
        data = resp.json()
    except ValueError:
        return {}, "github returned a non-JSON body"
    if not isinstance(data, (dict, list)):
        return {}, "github returned an unexpected body"
    return data, ""


def _raw(url: str) -> str:
    """Fetch a text file for *inspection only*. Never executed, never saved."""
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException:
        return ""
    if resp.status_code >= 400:
        return ""
    return resp.text[:MAX_SCAN_BYTES]


def _days_since(iso: str) -> int | None:
    if not iso:
        return None
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - when).total_seconds() // 86400))


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def _list_files(contents: Any) -> list[dict]:
    """Normalise a /contents response into {name, type, size, url}."""
    if isinstance(contents, dict):  # a single file, or a subdirectory
        entries = contents.get("entries") or [contents]
    elif isinstance(contents, list):
        entries = contents
    else:
        return []
    out: list[dict] = []
    for item in entries:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        out.append(
            {
                "name": str(item["name"]),
                "type": str(item.get("type") or "file"),
                "size": int(item.get("size") or 0),
                "download_url": str(item.get("download_url") or ""),
            }
        )
    return out


def _scan_text(text: str, where: str) -> tuple[list[Signal], list[str]]:
    """Look for decoder-loop obfuscation and off-site download links."""
    signals: list[Signal] = []
    offsite: list[str] = []
    if not text:
        return signals, offsite

    for pattern, weight, label in OBFUSCATION_SIGNALS:
        try:
            hits = re.findall(pattern, text, re.I)
        except re.error:
            continue
        if hits:
            signals.append(Signal(weight, f"{where}: {label}"))
            if weight >= 25:
                break  # one decoder loop is enough to make the point

    for raw in _URL_RE.findall(text):
        host = re.sub(r"^https?://", "", raw, flags=re.I).split("/")[0].lower()
        if any(host.endswith(h) for h in GITHUB_HOSTS):
            continue
        if host in ("127.0.0.1", "localhost"):
            continue
        if raw not in offsite:
            offsite.append(raw)
    return signals, offsite


def _verdict(score: int) -> str:
    if score >= 70:
        return "dangerous"
    if score >= 40:
        return "suspect"
    if score >= 20:
        return "caution"
    return "looks-genuine"


def audit(ref: str, deep: bool = True) -> dict:
    """Score a repository before the user trusts anything in it.

    ``deep`` reads the first few text files to look for obfuscation. Metadata
    alone catches most of the landing-page farm; the file scan catches the ones
    that do ship a redirector.
    """
    audit_state = Audit(ref=ref)
    parsed = parse_repo(ref)
    if not parsed:
        audit_state.error = "not a github repository reference (expected owner/name or a github URL)"
        return audit_state.to_dict()

    owner, name = parsed
    meta, err = _api(f"/repos/{owner}/{name}")
    if err:
        audit_state.error = err
        return audit_state.to_dict()
    if not isinstance(meta, dict):
        audit_state.error = "github returned an unexpected repository body"
        return audit_state.to_dict()

    audit_state.ok = True
    signals = audit_state.signals

    created_days = _days_since(meta.get("created_at") or "")
    pushed_days = _days_since(meta.get("pushed_at") or "")
    stars = int(meta.get("stargazers_count") or 0)
    forks = int(meta.get("forks_count") or 0)
    archived = bool(meta.get("archived"))
    language = meta.get("language") or ""
    size_kb = int(meta.get("size") or 0)
    created_iso = str(meta.get("created_at") or "")
    pushed_iso = str(meta.get("pushed_at") or "")

    audit_state.meta = {
        "full_name": meta.get("full_name") or f"{owner}/{name}",
        "description": meta.get("description") or "",
        "language": language,
        "stars": stars,
        "forks": forks,
        "archived": archived,
        "created": created_iso[:10],
        "pushed": pushed_iso[:10],
        "age_days": created_days,
        "stale_days": pushed_days,
        "size_kb": size_kb,
        "html_url": meta.get("html_url") or f"https://github.com/{owner}/{name}",
    }

    # -- metadata signals ------------------------------------------------ #
    # Staleness is its own axis. A project that was written honestly and then
    # abandoned is not malicious -- it is just dead, and worth saying so
    # separately rather than folding into the risk score.
    if archived:
        audit_state.maintenance = "archived"
    elif pushed_days is not None and pushed_days > 365:
        audit_state.maintenance = "stale"
    elif pushed_days is not None:
        audit_state.maintenance = "active"

    if created_days is not None and created_days < 90:
        signals.append(
            Signal(25, f"repository was created {created_days} day(s) ago")
        )

    # -- manifest ------------------------------------------------------- #
    if deep:
        contents, cerr = _api(f"/repos/{owner}/{name}/contents/")
        if cerr:
            # Never let an unread manifest look like a clean one. A zero-weight
            # signal keeps it visible in the report without moving the score.
            signals.append(Signal(0, f"could not read the file list: {cerr}"))
        else:
            audit_state.files = _list_files(contents)
            audit_state.manifest_read = True
    files = audit_state.files

    # Language bytes come from GitHub's own analysis rather than from guessing at
    # root filenames: a large project keeps its C in subdirectories, and a
    # root-only guess called torvalds/linux a repository with no native source.
    native_bytes: int | None = None
    if deep:
        langs, lerr = _api(f"/repos/{owner}/{name}/languages")
        if lerr or not isinstance(langs, dict):
            signals.append(Signal(0, "could not read the language breakdown"))
        else:
            native_bytes = sum(
                int(b or 0) for lang, b in langs.items() if lang in NATIVE_LANGS
            )
            audit_state.meta["languages"] = {
                k: int(v or 0)
                for k, v in sorted(langs.items(), key=lambda kv: -(kv[1] or 0))
            }

    # Everything below reads the root listing, which is only the whole picture for
    # a small repository. On a large one the root is directories plus a Makefile,
    # so size-based signals are gated on the repo actually being small.
    small_repo = 0 < size_kb < 2048

    code_bytes = 0
    doc_bytes = 0
    source_hits: list[str] = []
    marketing: list[str] = []
    scannable: list[dict] = []

    for entry in files:
        ext = ("." + entry["name"].rsplit(".", 1)[-1].lower()) if "." in entry["name"] else ""
        if entry["type"] != "file":
            continue
        if entry["name"].lower() in MARKETING_NAMES:
            marketing.append(entry["name"])
        if ext in SOURCE_EXTS:
            source_hits.append(entry["name"])
            code_bytes += entry["size"]
        elif ext in DOC_EXTS:
            doc_bytes += entry["size"]
        else:
            code_bytes += entry["size"]
        if ext in {".html", ".htm", ".js", ".mjs", ".py", ".ps1", ".bat", ".cmd", ".vbs", ".sh"}:
            scannable.append(entry)

    if files and native_bytes == 0 and not source_hits:
        signals.append(
            Signal(
                35,
                "ships no native source -- GitHub reports no C, C++, C#, Rust or "
                "assembly here, so nothing in this repository can inject into a "
                "running process",
            )
        )

    if files and small_repo:
        file_count = len([f for f in files if f["type"] == "file"])
        web_only = [
            f["name"]
            for f in files
            if f["type"] == "file"
            and f["name"].rsplit(".", 1)[-1].lower()
            in {"html", "htm", "js", "mjs", "css", "svg", "md", "txt"}
        ]
        if web_only and file_count and len(web_only) == file_count:
            signals.append(
                Signal(20, "repository contains only web pages and documents")
            )
        if code_bytes and code_bytes < 4096:
            signals.append(
                Signal(25, f"the repository's code is {code_bytes} byte(s) in total")
            )
        if marketing:
            signals.append(
                Signal(15, "ships landing-page assets: " + ", ".join(sorted(marketing)))
            )
        if doc_bytes and code_bytes and doc_bytes > code_bytes * 4:
            signals.append(
                Signal(15, f"documentation is {doc_bytes // max(code_bytes, 1)}x larger than the code")
            )
        if stars >= 20 and code_bytes < 4096:
            signals.append(
                Signal(
                    20,
                    f"{stars} stars on a repository with {code_bytes} byte(s) of code",
                )
            )

    # -- file contents -------------------------------------------------- #
    if deep and scannable:
        for entry in scannable[:MAX_SCAN_FILES]:
            url = entry.get("download_url") or ""
            if not url:
                continue
            text = _raw(url)
            found, offsite = _scan_text(text, entry["name"])
            signals.extend(found)
            for link in offsite:
                if link not in audit_state.offsite:
                    audit_state.offsite.append(link)

    if audit_state.offsite:
        signals.append(
            Signal(
                35,
                "downloads or links off GitHub: "
                + ", ".join(h for h in audit_state.offsite[:3]),
            )
        )

    # -- verdict -------------------------------------------------------- #
    deduped: list[Signal] = []
    seen: set[str] = set()
    for sig in signals:
        if sig.text in seen:
            continue
        seen.add(sig.text)
        deduped.append(sig)
    deduped.sort(key=lambda s: s.weight, reverse=True)

    audit_state.signals = deduped
    audit_state.score = min(100, sum(s.weight for s in deduped))
    audit_state.verdict = _verdict(audit_state.score)
    audit_state.note = _note(audit_state.verdict, audit_state.maintenance, pushed_days)
    return audit_state.to_dict()


def _note(verdict: str, maintenance: str, stale_days: int | None) -> str:
    if verdict == "dangerous":
        return (
            "Multiple independent signals point at a distribution page rather than "
            "a project. Do not download or run anything from here."
        )
    if verdict == "suspect":
        return (
            "This does not look like software that could do what it claims. Treat "
            "any download link as unverified."
        )
    if verdict == "caution":
        return "Some signals worth reading before you trust anything in this repository."
    if maintenance == "archived":
        return (
            "Looks like a genuinely written project, but it is archived by its owner "
            "and no longer maintained."
        )
    if maintenance == "stale":
        return (
            "Looks like a genuinely written project, but nothing has landed in "
            f"{stale_days or 0} days -- expect it to be out of date."
        )
    return (
        "No red flags found in the metadata or the files read. That is not a "
        "guarantee of safety."
    )
