"""Find the Luau virtual machine inside a running client, from outside.

This is the data half of the Lua hook. Nothing here disassembles anything: the
client's memory is readable, so the VM is located structurally -- interned
strings are found by their bytes, validated against the TString header, and then
the table that references them is found by scanning for pointers.

Why structural rather than by signature: a code signature has to be re-derived
for every client build, and a wrong one calls into the middle of a function. The
layout of an interned string and of a table changes far less often than offsets
do, and every hit here is checked before it is reported.

Luau object layout (x64), the parts this module relies on:

    TString    next(8) tt(1) marked(1) shrunk(1) pad(3-5) hash(4) len(4) data[]
    TValue     value(8) tt(1)
    TKey       value(8) tt(1) next(4)

Only ``len`` and ``tt`` are used to accept a string, and both are checked
against what was actually found, so a candidate that does not match is dropped
rather than reported.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import struct
from dataclasses import dataclass

from . import roblox

kernel32 = roblox.kernel32

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x00000100
PAGE_NOACCESS = 0x00000001
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

# Luau type tags we care about.
LUA_TSTRING = 5
LUA_TTABLE = 6
LUA_TFUNCTION = 7

CHUNK = 8 << 20  # read the address space in 8 MiB windows

kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
]


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD),
    ]


@dataclass
class Region:
    base: int
    size: int
    protect: int
    type: int

    def readable(self) -> bool:
        if self.protect & PAGE_GUARD:
            return False
        if self.protect & PAGE_NOACCESS:
            return False
        # Compare the masked protection bits, not a bool of them: bool(x) is True,
        # and True == 1 is not in this tuple, so wrapping it rejects everything.
        # WRITECOPY and EXECUTE_WRITECOPY matter as much as READWRITE here --
        # copy-on-write image sections are where most mapped game data sits.
        return (self.protect & 0xFF) in (0x02, 0x04, 0x08, 0x20, 0x40, 0x80)


def regions(handle: int, only_private: bool = False) -> list[Region]:
    """Committed, readable regions of the target, in address order."""
    out: list[Region] = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION64()
    while True:
        written = kernel32.VirtualQueryEx(
            ctypes.c_void_p(handle),
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if not written:
            break
        base = int(mbi.BaseAddress)
        size = int(mbi.RegionSize)
        if size == 0:
            break
        if mbi.State == MEM_COMMIT:
            region = Region(base, size, int(mbi.Protect), int(mbi.Type))
            if region.readable() and (not only_private or region.type == MEM_PRIVATE):
                out.append(region)
        address = base + size
        if address > (1 << 47):
            break
    return out


def read(handle: int, address: int, size: int) -> bytes | None:
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if not kernel32.ReadProcessMemory(
        ctypes.c_void_p(handle),
        ctypes.c_void_p(address),
        ctypes.cast(buf, ctypes.c_void_p),
        size,
        ctypes.byref(got),
    ):
        return None
    return buf.raw[: got.value]


def find_bytes(
    handle: int, needle: bytes, regions_list: list[Region], limit: int = 64
) -> list[int]:
    """Every address where ``needle`` appears, up to ``limit`` hits."""
    hits: list[int] = []
    for region in regions_list:
        offset = 0
        while offset < region.size:
            want = min(CHUNK, region.size - offset)
            address = region.base + offset
            data = read(handle, address, want)
            if data:
                start = 0
                while True:
                    at = data.find(needle, start)
                    if at < 0:
                        break
                    hits.append(address + at)
                    if len(hits) >= limit:
                        return hits
                    start = at + 1
            offset += want
    return hits


@dataclass
class TString:
    base: int          # address of the TString object
    data: int          # address of its characters
    length: int
    hash: int
    tag: int

    def to_dict(self) -> dict:
        return {
            "base": hex(self.base),
            "data": hex(self.data),
            "length": self.length,
            "hash": hex(self.hash),
            "tag": self.tag,
        }


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def validate_tstring(handle: int, text_address: int, length: int) -> TString | None:
    """Confirm the bytes at ``text_address`` really are an interned TString.

    Walks back over the plausible header window and requires a length field that
    matches exactly, a string type tag, and the terminator where it should be.
    A string that does not line up is not reported.
    """
    window = 40
    begin = text_address - window
    if begin < 0x10000:
        return None
    data = read(handle, begin, window + length + 1)
    if data is None or len(data) < window + length + 1:
        return None
    at = window  # offset of the string text within the window
    if data[at + length] != 0:
        return None  # not NUL-terminated where a TString would be

    # The same text lives in several places: Roblox's length-prefixed reflection
    # blobs (where a name appears as a substring of a longer name) and, actually,
    # the Lua interning table. Anchor on the length field but do not assume where
    # in the header it sits -- the header has changed between builds, and pinning
    # an offset finds nothing at all when it moves.
    for len_off in range(at - 32, at):
        if len_off < 4 or _u32(data, len_off) != length:
            continue
        # A real TString carries a heap pointer first (its GC chain) and a string
        # type tag before the length. Both must be present, which is what
        # separates the interning table from a reflection blob.
        for tag_off in range(max(0, len_off - 20), len_off):
            if data[tag_off] != LUA_TSTRING:
                continue
            head_off = tag_off - 8
            if head_off < 0:
                continue
            chain = struct.unpack_from("<Q", data, head_off)[0]
            if not (0x10000 < chain < 0x7FFFFFFFFFFF):
                continue
            hash_off = len_off - 4
            hash_value = _u32(data, hash_off) if hash_off >= 0 else 0
            return TString(
                base=begin + tag_off,
                data=text_address,
                length=length,
                hash=hash_value,
                tag=LUA_TSTRING,
            )
    return None


def find_tstrings(
    handle: int, names: list[str], regions_list: list[Region] | None = None
) -> dict[str, TString | None]:
    """Locate the interned TString for each name, if it is in memory."""
    regions_list = regions_list if regions_list is not None else regions(handle, only_private=True)
    found: dict[str, TString | None] = {}
    for name in names:
        needle = name.encode("ascii") + b"\x00"
        hit: TString | None = None
        for address in find_bytes(handle, needle, regions_list, limit=24):
            candidate = validate_tstring(handle, address, len(name))
            if candidate is not None:
                hit = candidate
                break
        found[name] = hit
    return found


def find_references(
    handle: int, targets: list[int], regions_list: list[Region], limit_per: int = 8
) -> list[tuple[int, int]]:
    """Addresses holding a pointer to any of ``targets`` (address, target)."""
    out: list[tuple[int, int]] = []
    if not targets:
        return out
    needles = {struct.pack("<Q", t): t for t in targets}
    counts = {t: 0 for t in targets}
    for region in regions_list:
        offset = 0
        while offset < region.size:
            want = min(CHUNK, region.size - offset)
            address = region.base + offset
            data = read(handle, address, want)
            if data:
                for needle, target in needles.items():
                    if counts[target] >= limit_per:
                        continue
                    start = 0
                    while True:
                        at = data.find(needle, start)
                        if at < 0:
                            break
                        out.append((address + at, target))
                        counts[target] += 1
                        if counts[target] >= limit_per:
                            break
                        start = at + 1
            offset += want
    return out
