"""Roblox frame-cap control.

There are two doors into Roblox's frame limiter and only one of them is open:

1. **Fast flags** -- ``ClientAppSettings.json``. Roblox ships a local
   *denylist*: certain flags are loaded from its CDN but explicitly refuse to be
   overridden on disk. The client logs the refusal as
   ``Denied local configuration for: <flag>``. On build 0.740.x that list
   includes ``DFIntTaskSchedulerTargetFps`` and the telemetry switches, so
   writing them is a no-op. We still write the file (it is harmless, and builds
   without the denylist will honour it) but we never pretend it did the work.

2. **The in-app setting** -- ``FramerateCap`` inside
   ``%LOCALAPPDATA%\\Roblox\\GlobalBasicSettings_13.xml``. This is the value the
   in-game FPS slider writes, it is read on startup, and it is not denylisted.
   This is the lever that actually moves the cap.

Roblox rewrites ``GlobalBasicSettings_13.xml`` when the client exits, so the cap
has to be set while the client is closed -- otherwise the running client will
overwrite it from its in-memory copy. :func:`apply` reports that condition rather
than silently losing the change.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import threading
import time
from pathlib import Path

from . import config, roblox

FILE_ATTRIBUTE_READONLY = 0x01
FILE_ATTRIBUTE_HIDDEN = 0x02

CAP_SETTING = "FramerateCap"
FPS_FLAG = "DFIntTaskSchedulerTargetFps"

# Flags NightRelay would like to set, most of which Roblox currently refuses.
TELEMETRY_FLAGS: dict[str, int] = {
    "FFlagDebugDisableTelemetryEphemeralCounter": 1,
    "FFlagDebugDisableTelemetryEphemeralStat": 1,
    "FFlagDebugDisableTelemetryEventIngest": 1,
    "FFlagDebugDisableTelemetryPoint": 1,
    "FFlagDebugDisableTelemetryV2Counter": 1,
    "FFlagDebugDisableTelemetryV2Event": 1,
    "FFlagDebugDisableTelemetryV2Stat": 1,
}

FPS_PRESETS = [
    {"value": 120, "label": "120", "note": "typical high-refresh laptop panel"},
    {"value": 144, "label": "144", "note": "standard high-refresh monitor"},
    {"value": 240, "label": "240", "note": "ceiling of the in-app slider"},
    {"value": 360, "label": "360", "note": "fast esports panels"},
    {"value": 999, "label": "999", "note": "effectively uncapped"},
]

MAX_SANE_FPS = 1000


# --------------------------------------------------------------------------- #
# File attributes
# --------------------------------------------------------------------------- #
def _set_attr(path: Path, flag: int, on: bool) -> None:
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs == -1:
            return
        attrs = (attrs | flag) if on else (attrs & ~flag)
        ctypes.windll.kernel32.SetFileAttributesW(str(path), attrs)
    except Exception:
        pass


def _is_readonly(path: Path) -> bool:
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        return attrs != -1 and bool(attrs & FILE_ATTRIBUTE_READONLY)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Roblox's own settings file
# --------------------------------------------------------------------------- #
def global_settings_files() -> list[Path]:
    local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    root = Path(local) / "Roblox"
    if not root.is_dir():
        return []
    return [
        root / "GlobalBasicSettings_13.xml",
        root / "GlobalBasicSettings_13_Studio.xml",
    ]


def read_cap() -> dict:
    """Current FramerateCap per settings file."""
    out: dict[str, int | None] = {}
    for path in global_settings_files():
        if not path.is_file():
            continue
        try:
            text = path.read_text("utf-8", errors="replace")
        except OSError:
            continue
        match = re.search(rf'<int name="{CAP_SETTING}">\s*(\d+)\s*</int>', text)
        out[path.name] = int(match.group(1)) if match else None
    return out


def set_cap(value: int) -> dict:
    """Write FramerateCap into Roblox's global settings.

    Refuses to touch the file while a client is running, because the client
    overwrites it from memory on exit and the change would vanish.
    """
    value = max(0, min(int(value), MAX_SANE_FPS))
    if roblox.find_roblox(include_studio=False):
        return {
            "ok": False,
            "blocked": True,
            "message": (
                "Roblox is running. It rewrites GlobalBasicSettings_13.xml when it "
                "closes, so the cap has to be set with the client shut down."
            ),
            "value": value,
            "written": [],
        }

    written: list[str] = []
    errors: list[str] = []
    for path in global_settings_files():
        if not path.is_file():
            continue
        try:
            text = path.read_text("utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        backup = config.backup_dir() / f"{path.name}-{time.strftime('%Y%m%d-%H%M%S')}.bak"
        try:
            backup.write_text(text, "utf-8")
        except OSError:
            pass

        pattern = rf'<int name="{CAP_SETTING}">\s*\d+\s*</int>'
        if re.search(pattern, text):
            text = re.sub(pattern, f'<int name="{CAP_SETTING}">{value}</int>', text)
        else:
            # Inject alongside the other int Properties.
            anchor = '<Properties>\n'
            if anchor not in text:
                errors.append(f"{path.name}: unexpected layout")
                continue
            text = text.replace(
                anchor, f'{anchor}\t\t\t<int name="{CAP_SETTING}">{value}</int>\n', 1
            )

        try:
            _set_attr(path, FILE_ATTRIBUTE_READONLY, False)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(text, "utf-8")
            os.replace(tmp, path)
            _set_attr(path, FILE_ATTRIBUTE_HIDDEN, False)
            written.append(str(path))
        except OSError as exc:
            errors.append(f"{path.name}: {exc}")

    return {
        "ok": bool(written),
        "blocked": False,
        "value": value,
        "written": written,
        "errors": errors,
        "message": (
            f"frame cap set to {value} — start Roblox to pick it up"
            if written
            else "could not write Roblox's settings file"
        ),
    }


def restore_cap() -> dict:
    """Put FramerateCap back to Roblox's default of 60."""
    value = 60
    if roblox.find_roblox(include_studio=False):
        return {
            "ok": False,
            "message": "close Roblox first — it will overwrite the file on exit",
        }
    restored: list[str] = []
    for path in global_settings_files():
        if not path.is_file():
            continue
        try:
            text = path.read_text("utf-8", errors="replace")
            text = re.sub(rf'<int name="{CAP_SETTING}">\s*\d+\s*</int>', f'<int name="{CAP_SETTING}">60</int>', text)
            _set_attr(path, FILE_ATTRIBUTE_READONLY, False)
            path.write_text(text, "utf-8")
            restored.append(str(path))
        except OSError:
            continue
    return {"ok": bool(restored), "value": value, "restored": restored,
            "message": f"frame cap returned to {value}"}


# --------------------------------------------------------------------------- #
# Fast-flag file (kept, but honestly reported)
# --------------------------------------------------------------------------- #
def settings_file(version: Path) -> Path:
    return roblox.client_settings_dir(version) / "ClientAppSettings.json"


def read_current(version: Path | None = None) -> dict:
    versions = [version] if version else roblox.player_versions()
    for ver in versions:
        path = settings_file(ver)
        if path.is_file():
            try:
                data = json.loads(path.read_text("utf-8-sig"))
                if isinstance(data, dict):
                    return data
            except (OSError, ValueError):
                continue
    return {}


def denied_flags() -> list[str]:
    """Flags the running client explicitly refused to take from disk.

    Roblox logs one warning per refused flag; this reads the newest client log.
    """
    log = roblox.newest_log()
    if not log:
        return []
    try:
        tail = log.read_bytes()[-800_000:].decode("utf-8", "replace")
    except OSError:
        return []
    found = re.findall(r"Denied local configuration for:\s*(\S+)", tail)
    seen: list[str] = []
    for flag in found:
        if flag not in seen:
            seen.append(flag)
    return seen


def write_flag_file(
    target_fps: int = 240, telemetry_off: bool = True, extra_flags: dict | None = None
) -> dict:
    payload: dict = {}
    if telemetry_off:
        payload.update(TELEMETRY_FLAGS)
    payload[FPS_FLAG] = max(0, min(int(target_fps), MAX_SANE_FPS))
    for key, value in (extra_flags or {}).items():
        if str(key).strip():
            payload[str(key).strip()] = value

    written: list[str] = []
    errors: list[str] = []
    for version in roblox.player_versions():
        directory = roblox.client_settings_dir(version)
        path = settings_file(version)
        existing: dict = {}
        try:
            directory.mkdir(parents=True, exist_ok=True)
            if path.is_file():
                parsed = json.loads(path.read_text("utf-8-sig"))
                if isinstance(parsed, dict):
                    existing = parsed
        except (OSError, ValueError):
            existing = {}
        try:
            _set_attr(path, FILE_ATTRIBUTE_READONLY, False)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps({**existing, **payload}, indent=2), "utf-8")
            os.replace(tmp, path)
            _set_attr(path, FILE_ATTRIBUTE_READONLY, True)
            _set_attr(path, FILE_ATTRIBUTE_HIDDEN, True)
            written.append(str(path))
        except OSError as exc:
            errors.append(f"{version.name}: {exc}")
    return {"ok": bool(written), "written": written, "errors": errors, "payload": payload}


def clear_flag_file() -> dict:
    cleared: list[str] = []
    for version in roblox.player_versions():
        path = settings_file(version)
        if not path.is_file():
            continue
        try:
            _set_attr(path, FILE_ATTRIBUTE_READONLY, False)
            _set_attr(path, FILE_ATTRIBUTE_HIDDEN, False)
            raw = json.loads(path.read_text("utf-8-sig"))
        except (OSError, ValueError):
            continue
        if not isinstance(raw, dict):
            continue
        for flag in TELEMETRY_FLAGS:
            raw.pop(flag, None)
        raw.pop(FPS_FLAG, None)
        try:
            if raw:
                path.write_text(json.dumps(raw, indent=2), "utf-8")
            else:
                path.unlink(missing_ok=True)
            cleared.append(str(path))
        except OSError:
            continue
    return {"ok": True, "cleared": cleared}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def status() -> dict:
    caps = read_cap()
    client_cap = caps.get("GlobalBasicSettings_13.xml")
    denied = denied_flags()
    running = bool(roblox.find_roblox(include_studio=False))
    return {
        "installed": roblox.roblox_installed(),
        "versions": [d.name for d in roblox.player_versions()],
        "unlock": unlock_enabled(),
        "target": int(config.settings().get("fps.target", UNLOCK_FPS) or UNLOCK_FPS),
        "default_fps": DEFAULT_FPS,
        "watcher": watcher_state(),
        "cap": client_cap,
        "caps": caps,
        "flag_file_value": read_current().get(FPS_FLAG),
        "flag_written": bool(read_current()),
        "running": running,
        "can_apply": not running,
        "denied_flags": denied,
        "fflags_denied": FPS_FLAG in denied,
        "telemetry_denied": all(f in denied for f in TELEMETRY_FLAGS),
        "settings_files": [str(p) for p in global_settings_files() if p.is_file()],
        "presets": FPS_PRESETS,
        "cap_setting": CAP_SETTING,
        "flag_name": FPS_FLAG,
        "max_sane": MAX_SANE_FPS,
    }


def apply_fps(target_fps: int = 240) -> dict:
    """Set the frame cap through the door that is actually open."""
    cap_result = set_cap(target_fps)
    denied = denied_flags()

    if cap_result.get("blocked"):
        # Leave the flag file alone too: a half-applied change is more
        # confusing than none, and this build ignores the flag anyway.
        return {
            "ok": False,
            "blocked": True,
            "message": cap_result["message"],
            "cap": cap_result,
            "flags": {"ok": False, "written": [], "skipped": "cap could not be set"},
            "denied_flags": denied,
        }

    flag_result = write_flag_file(target_fps=target_fps, telemetry_off=False)

    note = ""
    if FPS_FLAG in denied:
        note = (
            " Roblox is refusing local FFlag overrides on this build, so the cap "
            "came from its own settings file instead."
        )
    return {
        "ok": cap_result["ok"],
        "blocked": False,
        "value": cap_result["value"],
        "message": cap_result["message"] + note,
        "cap": cap_result,
        "flags": flag_result,
        "denied_flags": denied,
    }


def apply_telemetry(off: bool = True) -> dict:
    """Write (or clear) the telemetry FFlags."""
    if not off:
        return {"ok": True, **clear_flag_file(), "message": "telemetry flags cleared"}
    result = write_flag_file(target_fps=read_current().get(FPS_FLAG, 240) or 240, telemetry_off=True)
    denied = denied_flags()
    message = f"wrote {len(result['written'])} flag file(s)"
    if TELEMETRY_FLAGS and all(f in denied for f in TELEMETRY_FLAGS):
        message += " — but this Roblox build denies every one of them"
    return {"ok": result["ok"], "message": message, "denied_flags": denied, **result}


# --------------------------------------------------------------------------- #
# Single on/off switch
# --------------------------------------------------------------------------- #
UNLOCK_FPS = 999     # effectively uncapped
DEFAULT_FPS = 60     # Roblox's own default

_watcher: threading.Thread | None = None
_watcher_stop = threading.Event()


def unlock_enabled() -> bool:
    return bool(config.settings().get("fps.unlock", False))


def set_unlock(enabled: bool, target: int | None = None) -> dict:
    """The one switch behind the Frame cap tab.

    Enabled means "as high as the setting allows". Roblox only reads the value at
    startup and rewrites the file on exit, so if a client is running the change
    is armed rather than applied -- :func:`ensure_unlocked` finishes the job as
    soon as the client closes.
    """
    # There is no number to pick: on means uncapped. `target` stays as an
    # override for scripting, not for the interface.
    settings = config.settings()
    target = int(target or UNLOCK_FPS)
    settings.update({"fps": {"unlock": bool(enabled), "target": target}})

    if not enabled:
        result = restore_cap()
        clear_flag_file()
        if not result.get("ok"):
            return {
                "ok": True,
                "enabled": False,
                "armed": True,
                "cap": read_cap().get("GlobalBasicSettings_13.xml"),
                "message": (
                    "armed — Roblox is open, so the default limit will be restored "
                    "automatically the moment it closes."
                ),
            }
        return {
            "ok": True,
            "enabled": False,
            "armed": False,
            "cap": DEFAULT_FPS,
            "message": "frame rate returned to Roblox's default",
        }

    applied = set_cap(target)
    if applied.get("blocked"):
        return {
            "ok": True,
            "enabled": True,
            "armed": True,
            "cap": read_cap().get("GlobalBasicSettings_13.xml"),
            "message": (
                "armed — Roblox is open, so the cap will be raised automatically "
                "the moment it closes. Nothing else for you to do."
            ),
        }
    return {
        "ok": bool(applied.get("ok")),
        "enabled": True,
        "armed": False,
        "cap": applied.get("value"),
        "message": (
            f"uncapped to {applied.get('value')} — start Roblox to pick it up"
            if applied.get("ok")
            else applied.get("message", "could not write the setting")
        ),
    }


def ensure_unlocked() -> dict | None:
    """Called by the watcher: land the switch's state once Roblox is closed.

    One switch two ways. Turning the cap up is the point, but turning it back
    down has to survive the same rewrite, so the watcher enforces whichever
    state the switch is in.
    """
    if roblox.find_roblox(include_studio=False):
        return None
    current = read_cap().get("GlobalBasicSettings_13.xml")
    if unlock_enabled():
        target = int(config.settings().get("fps.target", UNLOCK_FPS) or UNLOCK_FPS)
        if current == target:
            return None
        result = set_cap(target)
        if result.get("ok"):
            return {"ok": True, "cap": target, "message": f"frame cap raised: {target}"}
        return None
    if current in (None, DEFAULT_FPS):
        return None
    result = set_cap(DEFAULT_FPS)
    if result.get("ok"):
        return {"ok": True, "cap": DEFAULT_FPS, "message": "frame cap returned to default"}
    return None


def watcher_state() -> dict:
    return {
        "running": bool(_watcher and _watcher.is_alive()),
        "enabled": unlock_enabled(),
        "target": int(config.settings().get("fps.target", UNLOCK_FPS) or UNLOCK_FPS),
    }


def start_watcher(interval: float = 4.0) -> None:
    """Background thread that lands an armed frame-cap change.

    Without this the user has to close Roblox, open the app, toggle, and relaunch
    in exactly the right order. With it, flipping the switch is the whole job.
    """
    global _watcher
    if _watcher and _watcher.is_alive():
        return
    _watcher_stop.clear()

    def loop() -> None:
        while not _watcher_stop.wait(interval):
            try:
                landed = ensure_unlocked()
                if landed:
                    from . import server as _server  # local import avoids a cycle

                    _server.log(landed["message"], "ok")
            except Exception:
                continue

    _watcher = threading.Thread(target=loop, name="nr-fps-watcher", daemon=True)
    _watcher.start()


def stop_watcher() -> None:
    _watcher_stop.set()


def delete_all_backups() -> dict:
    backups = list(config.backup_dir().glob("*"))
    for path in backups:
        config.shred(path)
    return {"ok": True, "message": f"shredded {len(backups)} backup(s)", "count": len(backups)}
