"""Roblox process discovery and lifecycle.

Everything here talks to ``kernel32``/``user32`` directly through ``ctypes``.
Handle-returning calls declare ``c_void_p`` restypes -- on 64-bit Windows the
default ``c_int`` return would silently truncate handles to 32 bits and every
later call would fail with an obscure "invalid handle" error.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config

PLAYER_EXE = "RobloxPlayerBeta.exe"
STUDIO_EXE = "RobloxStudioBeta.exe"
CRASH_HANDLER = "RobloxCrashHandler.exe"

SINGLETON_MUTEX = "ROBLOX_singletonMutex"
SINGLETON_EVENT = "ROBLOX_singletonEvent"

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

# --- constants ------------------------------------------------------------- #
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
PROCESS_DUP_HANDLE = 0x0040
PROCESS_ALL_ACCESS = 0x1F0FFF

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04

SECURITY_IMPERSONATION = 2
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
SE_DEBUG_NAME = "SeDebugPrivilege"

DUPLICATE_CLOSE_SOURCE = 0x00000001
DUPLICATE_SAME_ACCESS = 0x00000002

SystemExtendedHandleInformation = 64

# --- ctypes prototypes ----------------------------------------------------- #
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

kernel32.GetCurrentProcess.restype = ctypes.c_void_p
kernel32.GetCurrentProcess.argtypes = []

kernel32.GetModuleHandleW.restype = ctypes.c_void_p
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]

kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.VirtualAllocEx.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    wintypes.DWORD,
    wintypes.DWORD,
]

kernel32.VirtualFreeEx.restype = wintypes.BOOL
kernel32.VirtualFreeEx.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    wintypes.DWORD,
]

kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

kernel32.CreateRemoteThread.restype = ctypes.c_void_p
kernel32.CreateRemoteThread.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
]

kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wintypes.DWORD]

kernel32.GetExitCodeThread.restype = wintypes.BOOL
kernel32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]

kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]

kernel32.OpenProcessToken.restype = wintypes.BOOL
kernel32.OpenProcessToken.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]

kernel32.GetCurrentProcessId.restype = wintypes.DWORD
kernel32.GetCurrentProcessId.argtypes = []

kernel32.IsWow64Process.restype = wintypes.BOOL
kernel32.IsWow64Process.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL)]

kernel32.DuplicateHandle.restype = wintypes.BOOL
kernel32.DuplicateHandle.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]

kernel32.LocalFree.restype = ctypes.c_void_p
kernel32.LocalFree.argtypes = [ctypes.c_void_p]

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.OpenProcessToken.argtypes = [
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p),
]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
advapi32.LookupPrivilegeValueW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
advapi32.AdjustTokenPrivileges.argtypes = [
    ctypes.c_void_p,
    wintypes.BOOL,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


# --------------------------------------------------------------------------- #
# Process enumeration
# --------------------------------------------------------------------------- #
def list_processes() -> list[tuple[int, str]]:
    """[(pid, exe_name)] for every process we can see."""
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE or not snapshot:
        return []
    out: list[tuple[int, str]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
        while ok:
            out.append((int(entry.th32ProcessID), str(entry.szExeFile)))
            ok = kernel32.Process32NextW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(snapshot))
    return out


def process_path(pid: int) -> str:
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if kernel32.QueryFullProcessImageNameW(
            ctypes.c_void_p(handle), 0, buf, ctypes.byref(size)
        ):
            return buf.value
        return ""
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def process_memory_mb(pid: int) -> float:
    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return 0.0
    try:
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        if psapi.GetProcessMemoryInfo(
            ctypes.c_void_p(handle), ctypes.byref(counters), counters.cb
        ):
            return round(counters.WorkingSetSize / (1024 * 1024), 1)
        return 0.0
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def window_titles() -> dict[int, str]:
    """pid -> visible top-level window title."""
    titles: dict[int, str] = {}
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.c_void_p, wintypes.LPARAM)

    def _cb(hwnd, _lparam):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(ctypes.c_void_p(hwnd), ctypes.byref(pid))
        if user32.IsWindowVisible(ctypes.c_void_p(hwnd)):
            length = user32.GetWindowTextLengthW(ctypes.c_void_p(hwnd))
            if length:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(ctypes.c_void_p(hwnd), buf, length + 1)
                if buf.value.strip():
                    titles.setdefault(int(pid.value), buf.value.strip())
        return True

    try:
        user32.EnumWindows(WNDENUMPROC(_cb), 0)
    except Exception:
        pass
    return titles


@dataclass
class RobloxProcess:
    pid: int
    name: str
    path: str = ""
    title: str = ""
    memory_mb: float = 0.0

    @property
    def version(self) -> str:
        if not self.path:
            return ""
        parent = Path(self.path).parent.name
        return parent if parent.startswith("version-") else ""

    @property
    def label(self) -> str:
        return self.title or self.name

    @property
    def is_studio(self) -> bool:
        return self.name.lower() == STUDIO_EXE.lower()

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "path": self.path,
            "title": self.title,
            "memory_mb": self.memory_mb,
            "version": self.version,
            "is_studio": self.name.lower() == STUDIO_EXE.lower(),
        }


def find_roblox(include_studio: bool = True) -> list[RobloxProcess]:
    """Every live Roblox client (and optionally Studio) process."""
    wanted = {PLAYER_EXE.lower()}
    if include_studio:
        wanted.add(STUDIO_EXE.lower())
    procs = [(pid, name) for pid, name in list_processes() if name.lower() in wanted]
    titles = window_titles()
    out: list[RobloxProcess] = []
    for pid, name in procs:
        out.append(
            RobloxProcess(
                pid=pid,
                name=name,
                path=process_path(pid),
                title=titles.get(pid, ""),
                memory_mb=process_memory_mb(pid),
            )
        )
    out.sort(key=lambda p: p.pid)
    return out


def find_client() -> RobloxProcess | None:
    """Newest/most-recently-used Roblox client, preferring ones with a window."""
    clients = [p for p in find_roblox(include_studio=False)]
    if not clients:
        return None
    titled = [p for p in clients if p.title]
    return (titled or clients)[-1]


# --------------------------------------------------------------------------- #
# Version folders
# --------------------------------------------------------------------------- #
def versions_root() -> Path:
    local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(local) / "Roblox" / "Versions"


def version_dirs() -> list[Path]:
    root = versions_root()
    if not root.is_dir():
        return []
    dirs = [d for d in root.iterdir() if d.is_dir() and d.name.startswith("version-")]
    dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return dirs


def player_versions() -> list[Path]:
    """Version folders that actually contain a client binary."""
    return [d for d in version_dirs() if (d / PLAYER_EXE).is_file()]


def newest_player_version() -> Path | None:
    versions = player_versions()
    return versions[0] if versions else None


def client_settings_dir(version: Path) -> Path:
    return version / "ClientSettings"


def roblox_installed() -> bool:
    return bool(player_versions())


def local_storage() -> Path:
    local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(local) / "Roblox" / "LocalStorage"


def logs_root() -> Path:
    local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(local) / "Roblox" / "logs"


def newest_log() -> Path | None:
    root = logs_root()
    if not root.is_dir():
        return None
    logs = [p for p in root.glob("*Player*.log") if p.is_file()]
    if not logs:
        return None
    logs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return logs[0]


# --------------------------------------------------------------------------- #
# Identity -- who is signed in to the installed client
# --------------------------------------------------------------------------- #
def identity() -> dict:
    """Read the signed-in account straight from Roblox's own app storage.

    ``appStorage.json`` is written by the client itself, so this is the real
    logged-in account rather than an inference. Everything here is read-only.
    """
    out = {
        "available": False,
        "username": "",
        "display_name": "",
        "user_id": "",
        "age_bracket": "",
        "previous": [],
        "source": "",
    }
    path = local_storage() / "appStorage.json"
    if not path.is_file():
        return out
    try:
        data = json.loads(path.read_text("utf-8-sig", errors="replace"))
    except (OSError, ValueError):
        return out
    if not isinstance(data, dict):
        return out

    out["username"] = str(data.get("Username", "") or "")
    out["display_name"] = str(data.get("DisplayName", "") or out["username"])
    out["user_id"] = str(data.get("UserId", "") or "")
    out["source"] = str(path)

    blob = data.get("PlayerHydrationBlob")
    if isinstance(blob, str) and blob.strip().startswith("{"):
        try:
            parsed = json.loads(blob)
            out["age_bracket"] = str(parsed.get("ageBracket", "") or "")
        except ValueError:
            pass

    previous = data.get("PreviousAccountsList")
    if isinstance(previous, str) and previous.strip().startswith("{"):
        try:
            parsed = json.loads(previous)
            if isinstance(parsed, dict):
                for uid, entry in parsed.items():
                    if isinstance(entry, dict) and entry.get("username"):
                        out["previous"].append(
                            {"user_id": str(uid), "username": str(entry["username"])}
                        )
        except ValueError:
            pass

    out["available"] = bool(out["username"])
    return out


def place_from_log() -> dict:
    """Last place the client joined, scraped from its own log."""
    log = newest_log()
    if not log:
        return {}
    try:
        tail = log.read_bytes()[-400_000:].decode("utf-8", "replace")
    except OSError:
        return {}
    import re

    ids = re.findall(r"place (\d+)", tail)
    universe = re.findall(r"universeId[=\" :]+(\d+)", tail)
    if not ids and not universe:
        return {}
    return {
        "place_id": ids[-1] if ids else "",
        "universe_id": universe[-1] if universe else "",
        "log": str(log),
    }


# --------------------------------------------------------------------------- #
# Privileges
# --------------------------------------------------------------------------- #
def enable_debug_privilege() -> bool:
    """Turn on SeDebugPrivilege so we can touch processes we do not own."""
    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        return False
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(
            token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None
        )
        return ctypes.get_last_error() == 0
    finally:
        kernel32.CloseHandle(token)


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _is_wow64(handle: int) -> bool:
    flag = wintypes.BOOL()
    if kernel32.IsWow64Process(ctypes.c_void_p(handle), ctypes.byref(flag)):
        return bool(flag.value)
    return False


def same_architecture(pid: int) -> bool | None:
    """Compare bitness of a target process with our own interpreter."""
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        target_32 = _is_wow64(handle)
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
    us = kernel32.GetCurrentProcess()
    ours_32 = _is_wow64(us)
    return target_32 == ours_32


# --------------------------------------------------------------------------- #
# Multi-instance
# --------------------------------------------------------------------------- #
class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


class _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("HandleValue", ctypes.c_void_p),
        ("GrantedAccess", wintypes.DWORD),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


def _handle_table() -> list[_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX]:
    """Snapshot every handle on the system via NtQuerySystemInformation."""
    ntdll.NtQuerySystemInformation.restype = ctypes.c_long
    size = 1 << 22
    for _ in range(8):
        buf = ctypes.create_string_buffer(size)
        needed = wintypes.ULONG()
        status = ntdll.NtQuerySystemInformation(
            SystemExtendedHandleInformation, buf, size, ctypes.byref(needed)
        )
        if status == 0:
            count = ctypes.c_size_t.from_buffer(buf).value
            entry_size = ctypes.sizeof(_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
            base = ctypes.sizeof(ctypes.c_size_t) * 2
            entries = []
            for i in range(count):
                offset = base + i * entry_size
                if offset + entry_size > size:
                    break
                entries.append(
                    _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_buffer(buf, offset)
                )
            return entries
        size *= 2
    return []


def _close_mutex_in(pid: int, handle_value: int) -> bool:
    """Close a handle inside another process by duplication.

    ``DUPLICATE_CLOSE_SOURCE`` makes the kernel drop the source reference, so
    once we close our copy the object's refcount can fall to zero and the named
    mutex disappears -- which is what lets a second client start.
    """
    target = kernel32.OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if not target:
        return False
    ours = ctypes.c_void_p()
    try:
        ok = kernel32.DuplicateHandle(
            ctypes.c_void_p(target),
            ctypes.c_void_p(handle_value),
            kernel32.GetCurrentProcess(),
            ctypes.byref(ours),
            0,
            False,
            DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
        )
        return bool(ok)
    finally:
        if ours:
            kernel32.CloseHandle(ours)
        kernel32.CloseHandle(ctypes.c_void_p(target))


def break_singleton(verbose: bool = True) -> dict:
    """Destroy Roblox's single-instance mutex so a second client can launch.

    This walks the system handle table looking for the singleton object held by
    a running Roblox client. It needs SeDebugPrivilege (run NightRelay as
    administrator if the status comes back 'denied').
    """
    result = {"ok": False, "broken": 0, "message": "", "elevated": is_elevated()}
    enable_debug_privilege()
    clients = {p.pid for p in find_roblox(include_studio=False)}
    if not clients:
        result["message"] = "no Roblox client is running to release the lock from"
        return result

    entries = _handle_table()
    if not entries:
        result["message"] = "could not read the system handle table"
        return result

    # Rebuild the mutex name in each Roblox process so we can match by name.
    names = {SINGLETON_MUTEX.lower(), SINGLETON_EVENT.lower()}
    suspects: list[tuple[int, int]] = []
    for entry in entries:
        pid = int(entry.UniqueProcessId or 0)
        if pid in clients:
            suspects.append((pid, int(entry.HandleValue or 0)))

    if not suspects:
        result["message"] = "no candidate handles found in Roblox"
        return result

    # Resolving every handle name is expensive; close candidates in bulk. Roblox
    # clients hold few mutexes, so the collateral is negligible and any handle we
    # cannot touch simply fails.
    broken = 0
    for pid, handle in suspects:
        name = _handle_name(pid, handle)
        if name and name.lower() in names:
            if _close_mutex_in(pid, handle):
                broken += 1
    result["broken"] = broken
    result["ok"] = broken > 0
    if broken:
        result["message"] = f"released {broken} instance lock(s)"
    else:
        result["message"] = (
            "no singleton lock found -- it may already be released, or Roblox is "
            "running elevated and NightRelay is not"
        )
    return result


def _handle_name(pid: int, handle_value: int) -> str:
    """Best-effort name lookup for a (pid, handle). Empty when unknown."""
    target = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
    if not target:
        return ""
    ours = ctypes.c_void_p()
    try:
        if not kernel32.DuplicateHandle(
            ctypes.c_void_p(target),
            ctypes.c_void_p(handle_value),
            kernel32.GetCurrentProcess(),
            ctypes.byref(ours),
            0,
            False,
            DUPLICATE_SAME_ACCESS,
        ):
            return ""
        return _object_name(ours)
    finally:
        if ours:
            kernel32.CloseHandle(ours)
        kernel32.CloseHandle(ctypes.c_void_p(target))


def _object_name(handle: ctypes.c_void_p) -> str:
    ntdll.NtQueryObject.restype = ctypes.c_long
    buf = ctypes.create_string_buffer(4096)
    ret_len = wintypes.ULONG()
    status = ntdll.NtQueryObject(
        handle, 1, buf, ctypes.sizeof(buf), ctypes.byref(ret_len)
    )
    if status != 0:
        return ""
    us = _UNICODE_STRING.from_buffer(buf)
    if not us.Length or not us.Buffer:
        return ""
    try:
        return ctypes.wstring_at(us.Buffer, us.Length // 2)
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Launch / kill
# --------------------------------------------------------------------------- #
def launch(
    place_url: str = "",
    version: Path | None = None,
    multi_instance: bool = False,
    extra_args: list[str] | None = None,
) -> dict:
    """Start a Roblox client.

    ``place_url`` is a roblox.com share link (``roblox.com/games/...``); Roblox's
    own protocol handler is used for that case so join tickets are negotiated by
    the official launcher path.
    """
    args: list[str] = []
    if multi_instance:
        break_singleton()
    if extra_args:
        args.extend(extra_args)

    if place_url:
        if not place_url.lower().startswith(("roblox://", "http")):
            place_url = "https://www.roblox.com/games/" + place_url.strip("/")
        if place_url.lower().startswith("http"):
            place_url = "roblox://experiences/start?placeId=" + _place_id(place_url)
        try:
            os.startfile(place_url)  # noqa: S606 - protocol handler
            return {"ok": True, "message": "handed the join link to Roblox", "pid": None}
        except OSError as exc:
            return {"ok": False, "message": f"protocol handler failed: {exc}", "pid": None}

    exe = (version or newest_player_version())
    if not exe:
        return {"ok": False, "message": "Roblox is not installed", "pid": None}
    exe_path = exe / PLAYER_EXE if exe.is_dir() else exe
    if not Path(exe_path).is_file():
        return {"ok": False, "message": f"missing {exe_path}", "pid": None}
    try:
        proc = subprocess.Popen(
            [str(exe_path), *args],
            cwd=str(Path(exe_path).parent),
            close_fds=True,
            creationflags=0x00000008 | 0x08000000,  # DETACHED_PROCESS | NO_WINDOW
        )
    except OSError as exc:
        return {"ok": False, "message": f"launch failed: {exc}", "pid": None}
    return {"ok": True, "message": f"launched {PLAYER_EXE}", "pid": proc.pid}


def _place_id(url: str) -> str:
    import re

    match = re.search(r"/(?:games|game)/(\d+)", url) or re.search(r"placeId=(\d+)", url)
    return match.group(1) if match else ""


def kill_all(include_crash_handler: bool = True) -> dict:
    targets = list(find_roblox(include_studio=True))
    names = {CRASH_HANDLER.lower()} if include_crash_handler else set()
    for pid, name in list_processes():
        if name.lower() in names:
            targets.append(RobloxProcess(pid=pid, name=name))
    killed = 0
    for proc in targets:
        handle = kernel32.OpenProcess(0x0001, False, proc.pid)  # PROCESS_TERMINATE
        if not handle:
            continue
        try:
            if kernel32.TerminateProcess(ctypes.c_void_p(handle), 0):
                killed += 1
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
    return {"ok": True, "killed": killed, "message": f"terminated {killed} process(es)"}


def wait_for_client(timeout: float = 30.0, poll: float = 0.5) -> RobloxProcess | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        client = find_client()
        if client:
            return client
        time.sleep(poll)
    return None


@dataclass
class Manager:
    """Small facade the server layer talks to."""

    last_error: str = ""
    cache: dict = field(default_factory=dict)

    def status(self) -> dict:
        clients = find_roblox(include_studio=False)
        studios = [p for p in find_roblox(include_studio=True) if p.is_studio]
        return {
            "installed": roblox_installed(),
            "versions_root": str(versions_root()),
            "versions": [d.name for d in player_versions()],
            "clients": [p.to_dict() for p in clients],
            "studio": [p.to_dict() for p in studios],
            "running": bool(clients),
            "identity": identity(),
            "elevated": is_elevated(),
            "data_dir": str(config.data_dir()),
        }
