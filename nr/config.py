"""Paths, settings store and the DPAPI secret vault.

Everything NightRelay persists lives under ``%LOCALAPPDATA%\\NightRelay``.
Secrets (API keys, tokens, passwords) never touch disk in cleartext: they are
wrapped with the Windows Data Protection API, which keys the ciphertext to the
logged-in Windows account.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wintypes
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

APP_NAME = "NightRelay"

# Secrets are stored under this key; listing them here keeps the vault tidy and
# lets the UI mask them consistently.
SECRET_KEYS = (
    "deepseek_api_key",
    "deepseek_user_token",
    "executor_token",
    "license_key",
)


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
def frozen() -> bool:
    """True when running from a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False))


def resource_dir() -> Path:
    """Directory holding bundled read-only assets (ui/, presets/)."""
    if frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


def install_dir() -> Path:
    """Directory holding the executable / source checkout."""
    if frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    """Writable per-user directory. Honours NIGHTRELAY_HOME for portable runs."""
    override = os.environ.get("NIGHTRELAY_HOME")
    if override:
        base = Path(override)
    else:
        local = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
        base = Path(local) / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def runtime_dir() -> Path:
    """Scratch space for staging files during a session."""
    d = data_dir() / "runtime"
    d.mkdir(parents=True, exist_ok=True)
    return d


def staging_dir() -> Path:
    """Randomised staging directory the injector drops payloads into.

    A fresh name per launch keeps the on-disk footprint from becoming a stable
    signature, and the whole directory is shredded on exit.
    """
    d = runtime_dir() / f"cache-{secrets.token_hex(6)}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def backup_dir() -> Path:
    d = data_dir() / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def scripts_dir() -> Path:
    d = data_dir() / "scripts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def settings_path() -> Path:
    return data_dir() / "settings.json"


def history_path() -> Path:
    return data_dir() / "history.json"


def log_path() -> Path:
    return data_dir() / "nightrelay.log"


# --------------------------------------------------------------------------- #
# DPAPI
# --------------------------------------------------------------------------- #
class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _make_blob(data: bytes) -> tuple[_DataBlob, Any]:
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def dpapi_available() -> bool:
    return os.name == "nt"


def dpapi_encrypt(data: bytes) -> bytes:
    """Encrypt for the current Windows user. Raises OSError on failure."""
    if not dpapi_available():
        raise OSError("DPAPI is only available on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    in_blob, _keep = _make_blob(data)
    out_blob = _DataBlob()
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptProtectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def dpapi_decrypt(data: bytes) -> bytes:
    if not dpapi_available():
        raise OSError("DPAPI is only available on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    in_blob, _keep = _make_blob(data)
    out_blob = _DataBlob()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptUnprotectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


class SecretVault:
    """Small encrypted key/value store.

    Payloads are DPAPI-wrapped when available. If DPAPI is unavailable the value
    falls back to an obfuscated (XOR + base64) form so nothing is ever stored as
    readable plaintext -- weaker, but never accidentally greppable.
    """

    _XOR_SEED = b"NightRelay::vault::v1"

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or (data_dir() / "vault.bin")
        self._lock = threading.Lock()
        self._cache: dict[str, str] = {}
        self._dirty = False
        self._load()

    # -- persistence ------------------------------------------------------- #
    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = self._path.read_bytes()
        except OSError:
            return
        if not raw:
            return
        payload: dict[str, str] | None = None
        if raw[:4] == b"NRDP":
            try:
                payload = json.loads(dpapi_decrypt(raw[4:]).decode("utf-8"))
            except Exception:
                payload = None
        if payload is None and raw[:4] == b"NROB":
            try:
                payload = json.loads(self._deobfuscate(raw[4:]).decode("utf-8"))
            except Exception:
                payload = None
        if isinstance(payload, dict):
            self._cache = {str(k): str(v) for k, v in payload.items() if v}

    def _write(self) -> None:
        blob = json.dumps(self._cache).encode("utf-8")
        try:
            body = b"NRDP" + dpapi_encrypt(blob)
        except Exception:
            body = b"NROB" + self._deobfuscate(blob)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_bytes(body)
        try:
            os.replace(tmp, self._path)
        except OSError:
            self._path.write_bytes(body)
            tmp.unlink(missing_ok=True)
        self._harden(self._path)

    @classmethod
    def _deobfuscate(cls, data: bytes) -> bytes:
        seed = cls._XOR_SEED
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ seed[i % len(seed)]
        return bytes(out)

    @staticmethod
    def _harden(path: Path) -> None:
        """Mark the file hidden so it does not sit visible in Explorer."""
        try:
            if os.name == "nt":
                FILE_ATTRIBUTE_HIDDEN = 0x02
                cur = ctypes.windll.kernel32.GetFileAttributesW(str(path))
                if cur != -1:
                    ctypes.windll.kernel32.SetFileAttributesW(
                        str(path), cur | FILE_ATTRIBUTE_HIDDEN
                    )
        except Exception:
            pass

    # -- api --------------------------------------------------------------- #
    def get(self, key: str, default: str = "") -> str:
        with self._lock:
            return self._cache.get(key, default)

    def set(self, key: str, value: str) -> None:
        with self._lock:
            if value:
                self._cache[key] = value
            else:
                self._cache.pop(key, None)
            self._dirty = True
            self._write()

    def clear(self, key: str) -> None:
        self.set(key, "")

    def has(self, key: str) -> bool:
        return bool(self.get(key))

    def masked(self) -> dict[str, str]:
        """Secrets in display form: never the full value."""
        out: dict[str, str] = {}
        for key in SECRET_KEYS:
            val = self.get(key)
            if not val:
                out[key] = ""
            elif len(val) <= 8:
                out[key] = "*" * len(val)
            else:
                out[key] = f"{val[:4]}{'*' * 8}{val[-4:]}"
        return out

    def flush(self) -> None:
        with self._lock:
            if self._dirty:
                self._write()
                self._dirty = False


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
DEFAULT_SETTINGS: dict[str, Any] = {
    "fps": {
        # The Frame cap tab is a single switch, so "on" means uncapped.
        "target": 999,
        "unlock": False,
        "telemetry_off": False,
        "extra_flags": {},
    },
    "library": {
        "sources": ["scriptblox", "rscripts"],
        "custom_sources": [],
        "max_results": 24,
    },
    "ai": {
        "model": "deepseek-chat",
        "mode": "auto",
        "system_prompt": (
            "You are the scripting assistant embedded in NightRelay, a Windows "
            "Roblox script relay. Write clean, self-contained Luau that runs in "
            "an executor environment. Prefer GUI-aware, defensive code: guard "
            "every service lookup, never assume a service exists, clean up "
            "connections, and put the whole entry point behind a pcall. When you "
            "emit a script, output it in a single fenced lua block with no "
            "commentary inside the fence."
        ),
        "temperature": 0.35,
    },
    "executor": {
        "backend": "auto",
        "dll_path": "",
        # The executor payload (payload/nr_executor.dll) the app loads and drives.
        "payload_dll": "",
        "external_url": "",
        "pipe_name": "",
        "autoexec_dir": "",
        "bridge_port": 8792,
        "loader_timeout": 20,
        "auto_attach": True,
        "stay_attached": True,
        "wipe_buffer": True,
        "shred_on_exit": True,
    },
    "ui": {
        "accent": "violet",
        "randomize_title": False,
        "panic_hotkey": True,
        "confirm_execute": True,
    },
    "server": {
        "port": 8791,
        "bind": "127.0.0.1",
    },
    "stealth": {
        # Break up timing and footprint so the app does not read as automation.
        "humanize": True,
        # Path to the kernel-mode PE mapper used by the BYOVD path.
        "mapper_path": "",
        # Prefer BYOVD over the service/driver path when loading the driver.
        "prefer_byovd": False,
    },
    "roblox": {
        # Release the single-instance lock before launching so more than one
        # client can run at once (the "multiple games" behaviour).
        "multi_instance": False,
        # Re-release the lock on every launch rather than only when asked.
        "auto_release_lock": True,
    },
    "license": {
        # Gate the app on a valid key. Sellers flip this off for their own build.
        "required": True,
        # Optional server-side check. Empty means fully offline (signed keys only).
        "url": "",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Settings:
    """Thread-safe JSON settings with an atomic write."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or settings_path()
        self._lock = threading.RLock()
        self._data = json.loads(json.dumps(DEFAULT_SETTINGS))
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(raw, dict):
            self._data = _deep_merge(DEFAULT_SETTINGS, raw)

    def save(self) -> None:
        with self._lock:
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2), "utf-8")
            try:
                os.replace(tmp, self._path)
            except OSError:
                self._path.write_text(json.dumps(self._data, indent=2), "utf-8")
                tmp.unlink(missing_ok=True)

    def all(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._data))

    def section(self, name: str) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._data.get(name, {})))

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted: str, value: Any, persist: bool = True) -> None:
        with self._lock:
            parts = dotted.split(".")
            node = self._data
            for part in parts[:-1]:
                nxt = node.get(part)
                if not isinstance(nxt, dict):
                    nxt = {}
                    node[part] = nxt
                node = nxt
            node[parts[-1]] = value
            if persist:
                self.save()

    def update(self, patch: dict[str, Any], persist: bool = True) -> None:
        with self._lock:
            self._data = _deep_merge(self._data, patch)
            if persist:
                self.save()


# --------------------------------------------------------------------------- #
# Shredding
# --------------------------------------------------------------------------- #
def shred(path: Path, passes: int = 2) -> None:
    """Overwrite then delete. Best-effort: SSD wear-levelling can defeat this."""
    try:
        if not path.exists():
            return
        if path.is_file():
            size = path.stat().st_size
            if size:
                with open(path, "r+b", buffering=0) as fh:
                    for _ in range(max(1, passes)):
                        fh.seek(0)
                        remaining = size
                        while remaining > 0:
                            chunk = min(remaining, 1 << 20)
                            fh.write(os.urandom(chunk))
                            remaining -= chunk
                        fh.flush()
                        os.fsync(fh.fileno())
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
    except OSError:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def shred_tree(root: Path) -> int:
    """Shred every file inside a directory, then remove the directory."""
    removed = 0
    if not root.exists():
        return 0
    for child in list(root.rglob("*")):
        if child.is_file():
            shred(child)
            removed += 1
    shutil.rmtree(root, ignore_errors=True)
    return removed


# --------------------------------------------------------------------------- #
# Singleton Vault / Settings
# --------------------------------------------------------------------------- #
_settings_instance: Settings | None = None
_vault_instance: SecretVault | None = None
_singleton_lock = threading.Lock()


def settings() -> Settings:
    global _settings_instance
    if _settings_instance is None:
        with _singleton_lock:
            if _settings_instance is None:
                _settings_instance = Settings()
    return _settings_instance


def vault() -> SecretVault:
    global _vault_instance
    if _vault_instance is None:
        with _singleton_lock:
            if _vault_instance is None:
                _vault_instance = SecretVault()
    return _vault_instance


def uptime_stamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")
