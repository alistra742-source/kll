"""DeepSeek client: official API key, or the web endpoint via a user token."""

from __future__ import annotations

import base64
import json
import threading
import time
from typing import Iterator

import requests

from . import config, pow as pow_solver

API_BASE = "https://api.deepseek.com"
WEB_BASE = "https://chat.deepseek.com"

# The singular path is the API. The plural form only exists as the SPA route and
# returns the HTML shell with HTTP 200, which is an easy way to fool yourself.
CHAT_PATH = "/api/v0/chat/completion"
SESSION_PATH = "/api/v0/chat_session/create"
POW_PATH = "/api/v0/chat/create_pow_challenge"

API_MODELS = ["deepseek-chat", "deepseek-reasoner"]

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


class DeepSeekError(RuntimeError):
    pass


def verify(secret: str, kind: str = "token", timeout: float = 20.0) -> dict:
    """Check a credential against DeepSeek before storing it.

    ``kind`` is ``token`` (a browser session token from chat.deepseek.com) or
    ``api_key``. Returns ``{ok, message, account, kind}``.
    """
    secret = (secret or "").strip()
    if not secret:
        return {"ok": False, "message": "nothing entered", "account": "", "kind": kind}

    if kind == "api_key":
        try:
            resp = requests.get(
                f"{API_BASE}/models",
                headers={"Authorization": f"Bearer {secret}", "Accept": "application/json"},
                timeout=timeout,
            )
        except requests.RequestException as exc:
            return {"ok": False, "message": f"network error: {exc}", "account": "", "kind": kind}
        if resp.status_code == 200:
            try:
                models = [m.get("id", "") for m in resp.json().get("data", [])]
            except ValueError:
                models = []
            return {
                "ok": True,
                "message": "api key accepted" + (f" ({', '.join(models)})" if models else ""),
                "account": "api key",
                "kind": kind,
            }
        if resp.status_code == 401:
            return {"ok": False, "message": "that api key was rejected (401)", "account": "", "kind": kind}
        return {
            "ok": False,
            "message": f"HTTP {resp.status_code}: {resp.text[:160]}",
            "account": "",
            "kind": kind,
        }

    # session token: ask DeepSeek who we are
    for path in ("/api/v0/users/current", "/api/v0/user/current"):
        try:
            resp = requests.get(
                WEB_BASE + path, headers=_web_headers(secret), timeout=timeout
            )
        except requests.RequestException as exc:
            return {"ok": False, "message": f"network error: {exc}", "account": "", "kind": kind}
        if resp.status_code == 401 or resp.status_code == 403:
            return {
                "ok": False,
                "message": (
                    f"{resp.status_code}: that token was rejected or has expired. "
                    "Copy a fresh one from chat.deepseek.com."
                ),
                "account": "",
                "kind": kind,
            }
        if resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        if _dig(data, "code", default=None) not in (None, 0):
            continue
        account = str(
            _dig(
                data,
                "data.biz_data.email",
                "data.biz_data.phone_number",
                "data.biz_data.name",
                "data.email",
                "data.id",
                default="",
            )
            or ""
        )
        return {
            "ok": True,
            "message": "session token accepted" + (f" — {account}" if account else ""),
            "account": account,
            "kind": kind,
        }
    return {
        "ok": False,
        "message": "DeepSeek did not accept that token",
        "account": "",
        "kind": kind,
    }


def _dig(node, *paths, default=None):
    for path in paths:
        cur = node
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
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


def mode(vault=None) -> str:
    """Session token wins: it is what the app asks for first."""
    v = vault or config.vault()
    if v.has("deepseek_user_token"):
        return "web"
    if v.has("deepseek_api_key"):
        return "api"
    return "unconfigured"


def status() -> dict:
    v = config.vault()
    return {
        "mode": mode(v),
        "models": API_MODELS,
        "has_api_key": v.has("deepseek_api_key"),
        "has_token": v.has("deepseek_user_token"),
        "secrets": v.masked(),
    }


# --------------------------------------------------------------------------- #
# Web-token mode helpers
# --------------------------------------------------------------------------- #
class _Cache:
    lock = threading.Lock()
    challenge: dict | None = None
    session_id: str | None = None


def _web_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": UA,
        "Accept": "*/*",
        "Origin": WEB_BASE,
        "Referer": f"{WEB_BASE}/",
        "x-app-version": "20241129.1",
        "x-client-platform": "web",
        "x-client-version": "1.0.0",
    }


def solve_challenge(challenge: dict, timeout: float = 45.0) -> int:
    """Solve a DeepSeekHashV1 challenge into a nonce."""
    nonce = pow_solver.solve(
        str(challenge.get("challenge", "")),
        str(challenge.get("salt", "")),
        int(challenge.get("expire_at", 0) or 0),
        int(challenge.get("difficulty", 0) or 0),
        timeout=timeout,
    )
    if nonce is None:
        raise DeepSeekError(
            "could not solve the proof-of-work challenge within the nonce range"
        )
    return nonce


def _pow_header(token: str, challenge: dict, nonce: int) -> str:
    payload = {
        "algorithm": challenge.get("algorithm", "DeepSeekHashV1"),
        "challenge": challenge.get("challenge", ""),
        "salt": challenge.get("salt", ""),
        "answer": nonce,
        "signature": challenge.get("signature", ""),
        "target_path": challenge.get("target_path", CHAT_PATH),
    }
    return base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode()


def fetch_challenge(token: str, timeout: float = 20.0) -> dict:
    """Ask DeepSeek for a fresh challenge. These are single-use, never cached."""
    try:
        resp = requests.post(
            WEB_BASE + POW_PATH,
            json={"target_path": CHAT_PATH},
            headers=_web_headers(token),
            timeout=timeout,
        )
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        raise DeepSeekError(f"pow challenge request failed: {exc}") from exc

    biz = _dig(data, "data.biz_data", "biz_data", default={}) or {}
    challenge = biz.get("challenge") if isinstance(biz, dict) else None
    if not isinstance(challenge, dict) or not challenge.get("challenge"):
        reason = _dig(data, "data.biz_msg", "biz_msg", default="") or resp.text[:120]
        raise DeepSeekError(f"pow challenge rejected: {reason}")
    challenge.setdefault("target_path", CHAT_PATH)
    return challenge


def _get_pow(token: str) -> str:
    """Fresh challenge, solved, packed into the header value."""
    challenge = fetch_challenge(token)
    return _pow_header(token, challenge, solve_challenge(challenge))


def _web_session(token: str) -> str:
    with _Cache.lock:
        if _Cache.session_id:
            return _Cache.session_id
    resp = requests.post(
        WEB_BASE + SESSION_PATH,
        json={},
        headers=_web_headers(token),
        timeout=20,
    )
    try:
        data = resp.json()
    except ValueError:
        raise DeepSeekError(f"session create returned non-JSON ({resp.status_code})")
    session = str(_dig(data, "data.biz_data.id", "data.id", "biz_data.id", default="") or "")
    if not session:
        raise DeepSeekError(f"could not create a chat session: {resp.text[:200]}")
    with _Cache.lock:
        _Cache.session_id = session
    return session


class WebStreamParser:
    """Decode DeepSeek's streaming patch protocol.

    The stream is not plain deltas. It carries JSON-Patch-like operations:

        {"v": {"response": {... "fragments": [{"content": "N"}]}}}   snapshot
        {"p": "response/fragments/-1/content", "o": "APPEND", "v": "IGHT"}
        {"v": "RE"}                        continuation of the last APPEND
        {"p": "response", "o": "BATCH", "v": [ ...nested ops... ]}

    plus `event:` lines and session/token bookkeeping to ignore. This walks that
    and hands back the newly appended text (and reasoning, for reasoner models).
    """

    def __init__(self) -> None:
        self._last_path = ""
        self._snapshot_done = False

    @staticmethod
    def _is_reasoning(path: str) -> bool:
        return "thinking" in (path or "") or "/cot/" in (path or "")

    def feed(self, payload) -> list[tuple[str, str]]:
        """Return [(kind, text)] where kind is 'text' or 'reasoning'."""
        out: list[tuple[str, str]] = []
        node = payload.get("v") if isinstance(payload, dict) else None

        if isinstance(node, dict):
            if self._snapshot_done:
                return out
            self._snapshot_done = True
            fragments = _dig(node, "response.fragments", default=None)
            if isinstance(fragments, list):
                for fragment in fragments:
                    if not isinstance(fragment, dict):
                        continue
                    kind = (
                        "reasoning"
                        if str(fragment.get("type", "")).upper().startswith("THINK")
                        else "text"
                    )
                    content = fragment.get("content") or fragment.get("thinking_content")
                    if content:
                        out.append((kind, str(content)))
            return out

        path = str(payload.get("p") or "")
        op = str(payload.get("o") or "")

        if op == "BATCH" and isinstance(node, list):
            for item in node:
                if isinstance(item, dict):
                    out.extend(self.feed(item))
            return out

        if not path and isinstance(node, str):
            # continuation of whichever path the last operation touched
            if self._last_path:
                kind = "reasoning" if self._is_reasoning(self._last_path) else "text"
                out.append((kind, node))
            return out

        if op in ("APPEND", "ADD") and isinstance(node, str):
            self._last_path = path
            kind = "reasoning" if self._is_reasoning(path) else "text"
            out.append((kind, node))
            return out

        return out


def reset_session() -> None:
    with _Cache.lock:
        _Cache.session_id = None
        _Cache.challenge = None


# --------------------------------------------------------------------------- #
# Streaming
# --------------------------------------------------------------------------- #
def stream(
    messages: list[dict],
    model: str | None = None,
    temperature: float = 0.35,
    timeout: float = 120.0,
    force_mode: str | None = None,
) -> Iterator[dict]:
    """Yield {'type': 'text'|'error'|'done'|'reasoning', ...} events."""
    v = config.vault()
    chosen = force_mode or mode(v)
    if chosen == "api":
        yield from _stream_api(messages, model, temperature, timeout, v.get("deepseek_api_key"))
    elif chosen == "web":
        yield from _stream_web(messages, model, temperature, timeout, v.get("deepseek_user_token"))
    else:
        yield {"type": "error", "text": "No DeepSeek credentials. Add an API key in Settings."}


def _stream_api(
    messages: list[dict],
    model: str | None,
    temperature: float,
    timeout: float,
    key: str,
) -> Iterator[dict]:
    model = model or "deepseek-chat"
    if model not in API_MODELS:
        model = "deepseek-chat"
    body = {
        "model": model,
        "messages": messages,
        "stream": True,
        "temperature": float(temperature),
    }
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    try:
        resp = requests.post(
            f"{API_BASE}/chat/completions",
            json=body,
            headers=headers,
            stream=True,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        yield {"type": "error", "text": f"network error: {exc}"}
        return

    if resp.status_code != 200:
        detail = resp.text[:300]
        if resp.status_code == 401:
            detail = "401 unauthorized -- the API key was rejected"
        yield {"type": "error", "text": f"HTTP {resp.status_code}: {detail}"}
        return

    for raw in resp.iter_lines(decode_unicode=False):
        if not raw:
            continue
        line = raw.decode("utf-8", "replace").strip()
        if not line.startswith("data:"):
            continue
        chunk = line[5:].strip()
        if chunk == "[DONE]":
            break
        try:
            payload = json.loads(chunk)
        except ValueError:
            continue
        delta = _dig(payload, "choices.0.delta", default={}) or {}
        reasoning = delta.get("reasoning_content") or delta.get("reasoning")
        if reasoning:
            yield {"type": "reasoning", "text": str(reasoning)}
        text = delta.get("content")
        if text:
            yield {"type": "text", "text": str(text)}
        usage = payload.get("usage")
        if usage:
            yield {"type": "usage", "usage": usage}
    yield {"type": "done"}


def _stream_web(
    messages: list[dict],
    model: str | None,
    temperature: float,
    timeout: float,
    token: str,
) -> Iterator[dict]:
    prompt = _flatten(messages)
    thinking = bool((model or "").endswith("reasoner"))

    # Challenges are single-use, so every request gets its own. Solving takes
    # about a second on four cores, so tell the caller what the wait is for.
    yield {"type": "status", "text": "solving proof of work"}
    try:
        challenge = fetch_challenge(token)
        nonce = solve_challenge(challenge)
        session = _web_session(token)
    except DeepSeekError as exc:
        yield {"type": "error", "text": str(exc)}
        return

    body = {
        "chat_session_id": session,
        "parent_message_id": None,
        "model_type": "reasoner" if thinking else "default",
        "prompt": prompt,
        "ref_file_ids": [],
        "thinking_enabled": thinking,
        "search_enabled": False,
    }
    headers = _web_headers(token)
    headers["x-ds-pow-response"] = _pow_header(token, challenge, nonce)

    try:
        resp = requests.post(
            WEB_BASE + CHAT_PATH, json=body, headers=headers, stream=True, timeout=timeout
        )
    except requests.RequestException as exc:
        yield {"type": "error", "text": f"network error: {exc}"}
        return

    if resp.status_code in (401, 403):
        yield {
            "type": "error",
            "text": (
                f"{resp.status_code}: the session token was rejected or has expired. "
                "Copy a fresh one from chat.deepseek.com."
            ),
        }
        return
    if resp.status_code != 200:
        yield {"type": "error", "text": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        return

    parser = WebStreamParser()
    for raw in resp.iter_lines(decode_unicode=False):
        if not raw:
            continue
        line = raw.decode("utf-8", "replace").strip()
        if not line or line.startswith("event:"):
            continue
        if line.startswith("data:"):
            line = line[5:].strip()
        if not line or line == "[DONE]":
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("code") not in (None, 0):
            yield {"type": "error", "text": str(payload.get("msg") or payload)}
            return
        for kind, text in parser.feed(payload):
            if text:
                yield {"type": kind, "text": text}
    yield {"type": "done"}


def _flatten(messages: list[dict]) -> str:
    parts: list[str] = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system":
            parts.append(f"[instructions]\n{content}")
        elif role == "assistant":
            parts.append(f"[previous answer]\n{content}")
        else:
            parts.append(content)
    return "\n\n".join(parts).strip()


def ask(messages: list[dict], model: str | None = None, temperature: float = 0.35) -> str:
    """Blocking convenience call used by the script-generation shortcut."""
    out: list[str] = []
    for event in stream(messages, model=model, temperature=temperature):
        if event["type"] == "text":
            out.append(event["text"])
        elif event["type"] == "error":
            raise DeepSeekError(event["text"])
    return "".join(out)
