"""Script library: search across popular Roblox script hubs.

Each hub gets a small adapter. Public APIs in this space change shape without
notice, so every parser is written defensively: it probes a list of plausible
key paths, tolerates missing fields, and never raises on an unexpected body.
Adding a new hub is a matter of dropping another ``Source`` into ``SOURCES`` --
or the user can register a custom URL template from the UI.
"""

from __future__ import annotations

import html
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import requests

from . import config

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

DEFAULT_TIMEOUT = 12



# --------------------------------------------------------------------------- #
# Tolerant extraction helpers
# --------------------------------------------------------------------------- #
def dig(node: Any, *paths: str, default: Any = None) -> Any:
    """Try dotted paths in order; return the first non-empty hit."""
    for path in paths:
        cur = node
        for part in path.split("."):
            if isinstance(cur, dict):
                if part not in cur:
                    cur = None
                    break
                cur = cur[part]
            elif isinstance(cur, list):
                try:
                    cur = cur[int(part)]
                except (ValueError, IndexError):
                    cur = None
                    break
            else:
                cur = None
                break
        if cur not in (None, "", [], {}):
            return cur
    return default


def as_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def find_list(node: Any, depth: int = 0) -> list[dict]:
    """Locate the first list-of-dicts that looks like a result set."""
    if depth > 4:
        return []
    if isinstance(node, list):
        dicts = [item for item in node if isinstance(item, dict)]
        if dicts:
            return dicts
        return []
    if isinstance(node, dict):
        # Prefer the keys hubs actually use.
        for key in ("scripts", "data", "results", "items", "posts", "hits"):
            if key in node:
                found = find_list(node[key], depth + 1)
                if found:
                    return found
        for key in ("result", "response", "payload"):
            if key in node:
                found = find_list(node[key], depth + 1)
                if found:
                    return found
        for value in node.values():
            if isinstance(value, (list, dict)):
                found = find_list(value, depth + 1)
                if found:
                    return found
    return []


# --------------------------------------------------------------------------- #
# Normalised record
# --------------------------------------------------------------------------- #
@dataclass
class Script:
    id: str
    title: str
    source: str
    source_label: str = ""
    game: str = ""
    description: str = ""
    code: str = ""
    views: int = 0
    likes: int = 0
    verified: bool = False
    patched: bool = False
    key_required: bool = False
    script_type: str = ""
    url: str = ""
    created: str = ""
    raw_url: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "source": self.source,
            "source_label": self.source_label or self.source,
            "game": self.game,
            "description": self.description,
            "code": self.code,
            "has_code": bool(self.code.strip()),
            "views": self.views,
            "likes": self.likes,
            "verified": self.verified,
            "patched": self.patched,
            "key_required": self.key_required,
            "script_type": self.script_type,
            "url": self.url,
            "raw_url": self.raw_url,
            "created": self.created,
        }


@dataclass
class Source:
    id: str
    label: str
    home: str
    search_url: str = ""
    parse: Callable[[Any, str, str], list[Script]] | None = None
    needs_key: bool = False
    note: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "home": self.home,
            "needs_key": self.needs_key,
            "note": self.note,
            "tags": self.tags,
            "builtin": self.parse is not None,
        }


# --------------------------------------------------------------------------- #
# Adapters
# --------------------------------------------------------------------------- #
def _scriptblox_search_url(query: str, page: int) -> str:
    base = "https://scriptblox.com/api/script/search"
    return f"{base}?q={requests.utils.quote(query)}&page={page}&max=20"


def _parse_scriptblox(body: Any, query: str, page: str = "1") -> list[Script]:
    out: list[Script] = []
    for item in find_list(body):
        title = str(dig(item, "title", "name", default="")).strip()
        if not title:
            continue
        slug = str(dig(item, "slug", "_id", "id", default="")).strip()
        out.append(
            Script(
                id=f"scriptblox:{slug or title}",
                title=title,
                source="scriptblox",
                source_label="ScriptBlox",
                game=str(dig(item, "game.name", "gameName", "game", default="") or ""),
                description=str(dig(item, "description", "desc", default="") or ""),
                code=str(dig(item, "script", "code", default="") or ""),
                views=as_int(dig(item, "views", "viewCount", default=0)),
                likes=as_int(dig(item, "likes", "likeCount", default=0)),
                verified=as_bool(dig(item, "verified", default=False)),
                patched=as_bool(dig(item, "patched", default=False)),
                key_required=as_bool(dig(item, "key", default=False)),
                script_type=str(dig(item, "scriptType", "type", default="") or ""),
                url=f"https://scriptblox.com/script/{slug}" if slug else "https://scriptblox.com",
                created=str(dig(item, "createdAt", "created_at", default="") or ""),
            )
        )
    return out


def _rscripts_search_url(query: str, page: int) -> str:
    return (
        "https://rscripts.net/api/v2/scripts"
        f"?page={page}&search={requests.utils.quote(query)}"
    )


def _parse_rscripts(body: Any, query: str, page: str = "1") -> list[Script]:
    out: list[Script] = []
    for item in find_list(body):
        title = str(dig(item, "title", "name", default="")).strip()
        if not title:
            continue
        slug = str(dig(item, "slug", "_id", "id", "scriptId", default="")).strip()
        raw = str(dig(item, "rawUrl", "raw_url", "downloadLink", default="") or "")
        code = str(dig(item, "script", "code", "content", default="") or "")
        out.append(
            Script(
                id=f"rscripts:{slug or title}",
                title=title,
                source="rscripts",
                source_label="Rscripts",
                game=str(dig(item, "game.name", "gameName", "game", default="") or ""),
                description=str(dig(item, "description", "desc", default="") or ""),
                code="" if raw and not code else code,
                raw_url=raw,
                views=as_int(dig(item, "views", "viewCount", default=0)),
                likes=as_int(dig(item, "likes", "likeCount", default=0)),
                verified=as_bool(dig(item, "verified", default=False)),
                patched=as_bool(dig(item, "patched", "isPatched", default=False)),
                key_required=as_bool(dig(item, "keySystem", "key", default=False)),
                url=f"https://rscripts.net/script/{slug}" if slug else "https://rscripts.net",
                created=str(dig(item, "createdAt", "created_at", default="") or ""),
            )
        )
    return out


SOURCES: dict[str, Source] = {
    "scriptblox": Source(
        id="scriptblox",
        label="ScriptBlox",
        home="https://scriptblox.com",
        search_url="https://scriptblox.com/api/script/search?q={q}&page={p}&max=20",
        parse=_parse_scriptblox,
        note="largest public hub; returns the full script body inline",
        tags=["api", "inline-code"],
    ),
    "rscripts": Source(
        id="rscripts",
        label="Rscripts",
        home="https://rscripts.net",
        search_url="https://rscripts.net/api/v2/scripts?page={p}&search={q}",
        parse=_parse_rscripts,
        note="hub with raw download links",
        tags=["api"],
    ),
}


def register_custom_source(
    label: str, url_template: str, source_id: str | None = None
) -> Source:
    """Register a user-supplied JSON endpoint. ``{q}`` and ``{p}`` are substituted."""
    sid = source_id or re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-") or "custom"
    src = Source(
        id=f"custom:{sid}",
        label=label or sid,
        home=url_template.split("?")[0],
        search_url=url_template,
        parse=None,  # generic normaliser
        note="custom source (generic JSON/HTML reader)",
        tags=["custom"],
    )
    return src


def _parse_generic(body: Any, source: Source, page: str = "1") -> list[Script]:
    """Best-effort reader for arbitrary JSON."""
    out: list[Script] = []
    for item in find_list(body):
        title = str(dig(item, "title", "name", "slug", default="")).strip()
        if not title:
            continue
        code = str(dig(item, "script", "code", "content", "source", default="") or "")
        raw = str(dig(item, "rawUrl", "raw_url", "raw", "downloadLink", default="") or "")
        link = str(dig(item, "url", "link", "pageUrl", default="") or "")
        out.append(
            Script(
                id=f"{source.id}:{dig(item, '_id', 'id', 'slug', default=title)}",
                title=title,
                source=source.id,
                source_label=source.label,
                game=str(dig(item, "game.name", "gameName", "game", default="") or ""),
                description=str(dig(item, "description", "desc", default="") or ""),
                code=code,
                raw_url=raw,
                url=link or source.home,
                views=as_int(dig(item, "views", "viewCount", default=0)),
                verified=as_bool(dig(item, "verified", default=False)),
                patched=as_bool(dig(item, "patched", default=False)),
                key_required=as_bool(dig(item, "key", "keySystem", default=False)),
            )
        )
    return out


def _parse_html(body: str, source: Source, query: str) -> list[Script]:
    """Fallback for pages with no JSON API: pull out titled links."""
    out: list[Script] = []
    seen: set[str] = set()
    pattern = re.compile(r"<a[^>]+href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
    for href, inner in pattern.findall(body or ""):
        text = html.unescape(re.sub(r"<[^>]+>", "", inner)).strip()
        if len(text) < 4 or len(text) > 120:
            continue
        if href.startswith("/"):
            href = source.home.rstrip("/") + href
        if not href.startswith("http") or href in seen:
            continue
        seen.add(href)
        out.append(
            Script(
                id=f"{source.id}:{href}",
                title=text,
                source=source.id,
                source_label=source.label,
                url=href,
                description="open the page to load the script body",
            )
        )
        if len(out) >= 40:
            break
    return out


# --------------------------------------------------------------------------- #
# Fetching
# --------------------------------------------------------------------------- #
_session = requests.Session()
_session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json, text/*"})
_session_lock = threading.Lock()


def http_get(url: str, timeout: float = DEFAULT_TIMEOUT) -> requests.Response:
    with _session_lock:
        return _session.get(url, timeout=timeout, allow_redirects=True)


def is_raw_url(url: str) -> bool:
    url = (url or "").lower()
    return any(
        token in url
        for token in (
            "pastebin.com/raw/",
            "raw.githubusercontent.com",
            "gist.githubusercontent.com",
            "/raw/",
            "hastebin",
            "rentry.co/",
        )
    )


def fetch_raw(url: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Fetch a raw script body from a paste/raw endpoint."""
    try:
        resp = http_get(url, timeout=timeout)
        if resp.status_code != 200:
            return ""
        text = resp.text
        if text.lstrip().startswith("<"):
            return ""
        return text.strip()
    except requests.RequestException:
        return ""


def search_one(
    source: Source, query: str, page: int = 1, limit: int = 24, timeout: float = DEFAULT_TIMEOUT
) -> dict:
    if not source.search_url:
        return {"source": source.id, "label": source.label, "results": [], "error": "no endpoint"}
    url = source.search_url.replace("{q}", requests.utils.quote(query)).replace("{p}", str(page))
    url = url.replace("{page}", str(page)).replace("{query}", requests.utils.quote(query))
    try:
        resp = http_get(url, timeout=timeout)
    except requests.RequestException as exc:
        return {"source": source.id, "label": source.label, "results": [], "error": str(exc)}

    if resp.status_code != 200:
        return {
            "source": source.id,
            "label": source.label,
            "results": [],
            "error": f"HTTP {resp.status_code}",
        }

    body = resp.text
    parser = source.parse or (lambda b, q, p=1: _parse_generic(b, source, p))
    results: list[Script] = []
    try:
        data = resp.json()
        results = parser(data, query, str(page))
    except ValueError:
        results = _parse_html(body, source, query)
    except Exception as exc:  # adapter bug should not kill the whole search
        return {"source": source.id, "label": source.label, "results": [], "error": f"parse: {exc}"}

    if not results and body.lstrip().startswith("<"):
        results = _parse_html(body, source, query)

    return {
        "source": source.id,
        "label": source.label,
        "results": [s.to_dict() for s in results[:limit]],
        "error": "",
        "url": url,
    }


def search(
    query: str,
    source_ids: list[str] | None = None,
    page: int = 1,
    limit: int = 24,
    custom: list[dict] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """Search every requested hub concurrently and merge the results."""
    wanted = source_ids or list(SOURCES)
    sources: list[Source] = []
    for sid in wanted:
        if sid in SOURCES:
            sources.append(SOURCES[sid])
    for entry in custom or []:
        if entry.get("enabled", True) and entry.get("url") and entry.get("label"):
            sources.append(register_custom_source(entry["label"], entry["url"], entry.get("id")))

    started = time.time()
    blocks: list[dict] = []
    if sources:
        with ThreadPoolExecutor(max_workers=min(8, len(sources))) as pool:
            futures = {
                pool.submit(search_one, src, query, page, limit, timeout): src for src in sources
            }
            for future in as_completed(futures):
                try:
                    blocks.append(future.result())
                except Exception as exc:
                    src = futures[future]
                    blocks.append(
                        {"source": src.id, "label": src.label, "results": [], "error": str(exc)}
                    )

    order = {src.id: idx for idx, src in enumerate(sources)}
    blocks.sort(key=lambda b: order.get(b["source"], 99))

    merged: list[dict] = []
    seen: set[str] = set()
    for block in blocks:
        for item in block.get("results", []):
            key = (item.get("title") or "").strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            merged.append(item)

    return {
        "query": query,
        "page": page,
        "elapsed_ms": int((time.time() - started) * 1000),
        "count": len(merged),
        "results": merged,
        "sources": blocks,
    }


def resolve_code(result: dict, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Get the actual script body for a result, fetching it if necessary."""
    code = (result.get("code") or "").strip()
    if code:
        return code
    raw = result.get("raw_url") or ""
    if raw and is_raw_url(raw):
        fetched = fetch_raw(raw, timeout=timeout)
        if fetched:
            return fetched
    page = result.get("url") or ""
    if page:
        try:
            resp = http_get(page, timeout=timeout)
            if resp.status_code == 200:
                if is_raw_url(page):
                    return resp.text.strip()
                match = re.search(r"\b(?:loadstring|getgenv|game\s*:\s*GetService)\b", resp.text)
                if match:
                    snippet = _extract_code_block(resp.text)
                    if snippet:
                        return snippet
        except requests.RequestException:
            return ""
    return ""


def _extract_code_block(body: str) -> str:
    """Pull the largest <pre>/<code> block out of a page."""
    blocks = re.findall(r"<(?:pre|code)[^>]*>(.*?)</(?:pre|code)>", body or "", re.I | re.S)
    best = ""
    for block in blocks:
        text = html.unescape(re.sub(r"<[^>]+>", "", block))
        if len(text.strip()) > len(best.strip()):
            best = text
    return best.strip()


# --------------------------------------------------------------------------- #
# Local library
# --------------------------------------------------------------------------- #
class LocalLibrary:
    """Scripts the user saves locally; encrypted-at-rest is overkill but we do
    keep them out of the working directory."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or config.scripts_dir()
        self._lock = threading.Lock()

    def _path(self, name: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._ -]+", "_", name).strip(" .") or "script"
        if not safe.lower().endswith(".lua"):
            safe += ".lua"
        return self.root / safe

    def save(self, name: str, code: str, meta: dict | None = None) -> dict:
        with self._lock:
            path = self._path(name)
            path.write_text(code, "utf-8")
            index = self._index()
            index[path.name] = {
                "name": path.name,
                "title": name,
                "saved": time.strftime("%Y-%m-%d %H:%M:%S"),
                "bytes": len(code.encode("utf-8")),
                "meta": meta or {},
            }
            self._write_index(index)
            return {"ok": True, "path": str(path), "name": path.name}

    def list(self) -> list[dict]:
        index = self._index()
        out: list[dict] = []
        for path in sorted(self.root.glob("*.lua")):
            meta = index.get(path.name, {})
            out.append(
                {
                    "name": path.name,
                    "title": meta.get("title", path.stem),
                    "saved": meta.get("saved", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(path.stat().st_mtime))),
                    "bytes": path.stat().st_size,
                    "meta": meta.get("meta", {}),
                }
            )
        out.sort(key=lambda item: item["saved"], reverse=True)
        return out

    def read(self, name: str) -> str:
        path = self.root / name
        if not path.is_file() or path.parent != self.root:
            return ""
        try:
            return path.read_text("utf-8")
        except OSError:
            return ""

    def delete(self, name: str) -> dict:
        path = self.root / name
        if not path.is_file() or path.parent != self.root:
            return {"ok": False, "message": "not found"}
        config.shred(path)
        index = self._index()
        index.pop(name, None)
        self._write_index(index)
        return {"ok": True, "message": f"shredded {name}"}

    def _index(self) -> dict:
        path = self.root / "index.json"
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text("utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write_index(self, data: dict) -> None:
        try:
            (self.root / "index.json").write_text(json.dumps(data, indent=2), "utf-8")
        except OSError:
            pass
