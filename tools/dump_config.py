"""Find the addresses the payload needs, and write nr_executor.cfg.

The payload (``payload/nr_executor.c``) calls into the client's Luau at fixed
addresses that move every Roblox build. This tool finds them by byte signature,
verifies each hit before trusting it, and writes the config file the DLL reads.

Signatures live in ``tools/signatures.json`` and are the part that has to be
updated per build. A signature is only accepted if it matches the expected number
of times -- a pattern that suddenly matches 40 places, or zero, is reported as
stale rather than written, because a wrong address here is a crash inside
somebody's client.

Memory is read through the NightRelay kernel driver when it is loaded (no handle
on the client), and falls back to a plain process handle otherwise, so this is
usable for testing before the driver path is set up.

    python tools/dump_config.py                 # scan + write cfg
    python tools/dump_config.py --check         # report, write nothing
    python tools/dump_config.py --pid 1234
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wintypes
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nr import km, roblox  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SIGNATURES = Path(__file__).resolve().parent / "signatures.json"
CFG_OUT = ROOT / "payload" / "nr_executor.cfg"

# What the payload requires. A signature for each key must resolve, or the
# payload refuses to run (that is deliberate -- see nr_executor.c load).
REQUIRED_KEYS = ("hook_target", "lua_newthread", "lua_settop", "luau_load", "lua_pcall")


# --------------------------------------------------------------------------- #
# memory access -- driver when present, handle otherwise
# --------------------------------------------------------------------------- #
class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

roblox.kernel32.Module32FirstW.restype = wintypes.BOOL
roblox.kernel32.Module32FirstW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
roblox.kernel32.Module32NextW.restype = wintypes.BOOL
roblox.kernel32.Module32NextW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]


class Reader:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.via = ""
        self._drv = None
        self._handle = None
        self._open()

    def _open(self) -> None:
        drv = km.driver()
        if drv.open() and drv.attach(self.pid):
            self._drv = drv
            self.via = "kernel driver"
            return
        rights = roblox.PROCESS_QUERY_LIMITED_INFORMATION | roblox.PROCESS_VM_READ
        handle = roblox.kernel32.OpenProcess(rights, False, self.pid)
        if handle:
            self._handle = handle
            self.via = "process handle"
            return
        raise RuntimeError("could not open the client for reading")

    def base(self, module: str) -> tuple[int, int] | None:
        if self._drv:
            return self._drv.get_base(module)

        # Handle path: walk the process's module list by name. Returns the same
        # (base, size) shape as the driver, so callers do not branch on which
        # reader is in use.
        snap = roblox.kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid
        )
        if not snap or snap == roblox.INVALID_HANDLE_VALUE:
            return None
        try:
            entry = MODULEENTRY32W()
            entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
            ok = roblox.kernel32.Module32FirstW(
                ctypes.c_void_p(snap), ctypes.byref(entry)
            )
            while ok:
                if entry.szModule.lower() == module.lower():
                    return int(entry.modBaseAddr or 0), int(entry.modBaseSize or 0)
                ok = roblox.kernel32.Module32NextW(
                    ctypes.c_void_p(snap), ctypes.byref(entry)
                )
        finally:
            roblox.kernel32.CloseHandle(ctypes.c_void_p(snap))
        return None

    def read(self, address: int, size: int) -> bytes | None:
        if self._drv:
            return self._drv.read(address, size)
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        ok = roblox.kernel32.ReadProcessMemory(
            ctypes.c_void_p(self._handle),
            ctypes.c_void_p(address),
            ctypes.cast(buf, ctypes.c_void_p),
            size,
            ctypes.byref(got),
        )
        return buf.raw[: got.value] if ok else None


# --------------------------------------------------------------------------- #
# signature parsing + scanning
# --------------------------------------------------------------------------- #
def parse_pattern(text: str) -> tuple[bytes, bytes]:
    """'48 89 5C 24 ?? 57' -> (bytes, mask) with 0x00 marking wildcards."""
    tokens = re.split(r"\s+", text.strip())
    pattern = bytearray()
    mask = bytearray()
    for token in tokens:
        if token in ("?", "??"):
            pattern.append(0)
            mask.append(0)
        else:
            pattern.append(int(token, 16))
            mask.append(0xFF)
    return bytes(pattern), bytes(mask)


def _matches_at(data: bytes, offset: int, pattern: bytes, mask: bytes) -> bool:
    for i, byte in enumerate(pattern):
        if data[offset + i] != byte and mask[i] == 0xFF:
            return False
    return True


def find_all(reader: Reader, base: int, size: int, pattern: bytes, mask: bytes,
             limit: int = 64) -> list[int]:
    """Addresses in [base, base+size) where the pattern matches."""
    hits: list[int] = []
    chunk = 4 << 20
    overlap = len(pattern) - 1
    address = base
    while address < base + size and len(hits) < limit:
        want = min(chunk, base + size - address)
        data = reader.read(address, want)
        if data:
            last = len(data) - len(pattern)
            i = 0
            while i <= last:
                if _matches_at(data, i, pattern, mask):
                    hits.append(address + i)
                    if len(hits) >= limit:
                        break
                i += 1
        address += want - overlap
    return hits


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def load_signatures() -> dict:
    if not SIGNATURES.is_file():
        return {}
    try:
        data = json.loads(SIGNATURES.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        print(f"  ! signatures.json is unreadable: {exc}")
        return {}
    return {k: v for k, v in data.items() if not k.startswith("_")}


def dump(pid: int, write: bool = True) -> dict:
    reader = Reader(pid)
    print(f"reader: {reader.via}, pid {pid}")

    got = reader.base(roblox.PLAYER_EXE)
    if not got:
        print(f"  ! {roblox.PLAYER_EXE} not found in the process")
        return {}
    base, size = got
    print(f"module: {roblox.PLAYER_EXE} at 0x{base:X} ({size // 0x1000} KiB)")

    signatures = load_signatures()
    if not signatures:
        print("  ! no signatures -- fill tools/signatures.json for this build")
        return {}

    resolved: dict[str, int] = {}
    for name, spec in signatures.items():
        pattern, mask = parse_pattern(str(spec.get("pattern", "")))
        if not pattern:
            print(f"  - {name}: no pattern")
            continue
        expect = int(spec.get("expect", 1))
        add = int(spec.get("offset", 0))
        hits = find_all(reader, base, size, pattern, mask, limit=expect + 2)

        if len(hits) == expect:
            resolved[name] = hits[0] + add
            print(f"  + {name}: 0x{resolved[name]:X}  ({len(hits)} hit(s))")
        elif not hits:
            print(f"  - {name}: no match -- signature is stale for this build")
        else:
            print(f"  - {name}: {len(hits)} matches, expected {expect} -- ambiguous, rejected")

    missing = [k for k in REQUIRED_KEYS if k not in resolved]
    if missing:
        print("\nnot written: " + ", ".join(missing) + " unresolved")
        print("the payload refuses to run without every address -- that is by design")
        return resolved

    lines = [f"{name}={value:x}" for name, value in sorted(resolved.items())]
    lines.append("hook_len=14")
    lines.append("settle_ms=8000")
    body = "\n".join(lines) + "\n"

    print("\n" + body)
    if write:
        CFG_OUT.parent.mkdir(parents=True, exist_ok=True)
        CFG_OUT.write_text(body, "utf-8")
        print(f"wrote {CFG_OUT}")
    return resolved


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="dump_config", description=__doc__)
    parser.add_argument("--pid", type=int, default=0)
    parser.add_argument("--check", action="store_true", help="report only, write nothing")
    args = parser.parse_args(argv)

    pid = args.pid
    if not pid:
        client = roblox.find_client()
        if not client:
            print("no Roblox client is running")
            return 1
        pid = client.pid

    dump(pid, write=not args.check)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
