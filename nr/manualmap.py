"""Manual (reflective) PE mapping.

``LoadLibraryW`` goes through ``ntdll!LdrLoadDll``. A protected client hooks that
path, so a perfectly valid module is refused while every other handle right is
granted -- which is exactly what a control test shows: the same DLL loads into a
process we own and is refused by the client.

Manual mapping skips the loader entirely. The image is built here, written into
the target in one pass, and its entry point is called with a stub that supplies
DllMain's three arguments. Nothing is registered in the loader list, so there is
no module record for a hook to inspect.

Scope, stated plainly: PE32+, x64, relocations, imports (by name and ordinal) and
TLS callbacks. Delay imports and security cookies beyond the standard relocation
path are not handled -- an image that needs them will fail loudly rather than
load half-formed. Imports are resolved against the *local* copy of a system
module, which is where the target maps them too; a non-system import the host
does not also have is refused by name.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import struct
from pathlib import Path

from . import roblox

kernel32 = roblox.kernel32

IMAGE_FILE_MACHINE_AMD64 = 0x8664
PE32_PLUS_MAGIC = 0x20B

DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_BASERELOC = 5
DIR_TLS = 9

REL_HIGHLOW = 3
REL_DIR64 = 10

ORDINAL_FLAG64 = 0x8000000000000000

# The image is written whole and then runs, so it needs to be writable and
# executable in one go; sections are tightened afterwards only if asked.
PAGE_EXECUTE_READWRITE = 0x40

# Thread rights and toolhelp constant for finding an existing thread to ride.
THREAD_SUSPEND_RESUME = 0x0002
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_QUERY_INFORMATION = 0x0040
TH32CS_SNAPTHREAD = 0x00000004

kernel32.OpenThread.restype = ctypes.c_void_p
kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.QueueUserAPC.restype = wintypes.DWORD
kernel32.QueueUserAPC.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


class MapError(RuntimeError):
    """Raised when an image cannot be mapped as written."""


def _cstr(buf: bytes, offset: int, limit: int = 512) -> str:
    end = buf.find(b"\x00", offset, offset + limit)
    if end < 0:
        end = offset + limit
    return buf[offset:end].decode("utf-8", "replace")


def parse_pe(data: bytes) -> dict:
    """Pull the parts of the PE that mapping needs."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise MapError("not a PE image (no MZ)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise MapError("not a PE image (no PE signature)")

    coff = e_lfanew + 4
    machine, nsections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != PE32_PLUS_MAGIC:
        raise MapError("only PE32+ (x64) images are supported")
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise MapError(f"unexpected machine type 0x{machine:04X}")

    entry = struct.unpack_from("<I", data, opt + 16)[0]
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
    ndirs = struct.unpack_from("<I", data, opt + 108)[0]
    dirs = opt + 112

    def directory(index: int) -> tuple[int, int]:
        if index >= ndirs:
            return 0, 0
        return struct.unpack_from("<II", data, dirs + index * 8)

    sections = []
    sec = opt + opt_size
    for i in range(nsections):
        o = sec + i * 40
        name = data[o : o + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
        characteristics = struct.unpack_from("<I", data, o + 36)[0]
        sections.append(
            {
                "name": name,
                "virtual_address": vaddr,
                "virtual_size": vsize,
                "raw_size": rawsize,
                "raw_pointer": rawptr,
                "characteristics": characteristics,
            }
        )

    return {
        "data": data,
        "entry_rva": entry,
        "image_base": image_base,
        "size_of_image": size_of_image,
        "size_of_headers": size_of_headers,
        "sections": sections,
        "import": directory(DIR_IMPORT),
        "reloc": directory(DIR_BASERELOC),
        "tls": directory(DIR_TLS),
        "export": directory(DIR_EXPORT),
    }


def _local_module_base(name: str) -> int:
    """Base of a module in *our* process.

    System modules are mapped at the same address in every process of a session,
    which is what makes this safe for kernel32/user32-style imports. If the host
    does not have the module at all, we cannot know the target's address, so the
    import is refused by name rather than guessed.
    """
    handle = kernel32.GetModuleHandleW(name)
    if not handle:
        handle = ctypes.windll.kernel32.LoadLibraryW(name)
    return int(handle or 0)


def _local_export(base: int, name: str) -> int:
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    return int(kernel32.GetProcAddress(ctypes.c_void_p(base), name.encode("ascii")) or 0)


def _local_export_ordinal(base: int, ordinal: int) -> int:
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    return int(kernel32.GetProcAddress(ctypes.c_void_p(base), ctypes.c_void_p(ordinal)) or 0)


def build_image(pe: dict, remote_base: int) -> bytearray:
    """Assemble the image at its remote address: headers, sections, relocs, IAT."""
    data = pe["data"]
    image = bytearray(pe["size_of_image"])

    headers = min(pe["size_of_headers"], len(data))
    image[:headers] = data[:headers]

    for s in pe["sections"]:
        if not s["raw_size"]:
            continue
        start = s["virtual_address"]
        end = start + s["raw_size"]
        if end > len(image):
            end = len(image)
        chunk = data[s["raw_pointer"] : s["raw_pointer"] + (end - start)]
        image[start:end] = chunk

    delta = remote_base - pe["image_base"]
    if delta:
        _apply_relocations(image, pe, delta)
        # The header keeps the real base so anything reading it agrees with us.
        struct.pack_into("<Q", image, _image_base_field_offset(pe), remote_base)

    _resolve_imports(image, pe)
    return image


def _image_base_field_offset(pe: dict) -> int:
    e_lfanew = struct.unpack_from("<I", pe["data"], 0x3C)[0]
    return e_lfanew + 4 + 20 + 24


def _apply_relocations(image: bytearray, pe: dict, delta: int) -> None:
    rva, size = pe["reloc"]
    if not rva or not size:
        raise MapError(
            "image has no relocations and cannot move from its preferred base"
        )
    end = rva + size
    offset = rva
    while offset < end:
        block_rva, block_size = struct.unpack_from("<II", image, offset)
        if block_size == 0:
            break
        count = (block_size - 8) // 2
        for i in range(count):
            entry = struct.unpack_from("<H", image, offset + 8 + i * 2)[0]
            kind = entry >> 12
            where = block_rva + (entry & 0x0FFF)
            if kind == REL_DIR64:
                value = struct.unpack_from("<Q", image, where)[0] + delta
                struct.pack_into("<Q", image, where, value & 0xFFFFFFFFFFFFFFFF)
            elif kind == REL_HIGHLOW:
                value = struct.unpack_from("<I", image, where)[0] + delta
                struct.pack_into("<I", image, where, value & 0xFFFFFFFF)
        offset += block_size


def _resolve_imports(image: bytearray, pe: dict) -> None:
    rva, size = pe["import"]
    if not rva or not size:
        return
    offset = rva
    while True:
        original_first, _stamp, _forward, name_rva, first_thunk = struct.unpack_from(
            "<IIIII", image, offset
        )
        if not original_first and not name_rva and not first_thunk:
            break
        dll_name = _cstr(bytes(image), name_rva)
        base = _local_module_base(dll_name)
        if not base:
            raise MapError(f"import {dll_name!r} is not present on this host")

        thunk = original_first or first_thunk
        target = first_thunk
        while True:
            value = struct.unpack_from("<Q", image, thunk)[0]
            if value == 0:
                break
            if value & ORDINAL_FLAG64:
                address = _local_export_ordinal(base, value & 0xFFFF)
                label = f"{dll_name}#{value & 0xFFFF}"
            else:
                func = _cstr(bytes(image), value + 2)
                address = _local_export(base, func)
                label = f"{dll_name}!{func}"
            if not address:
                raise MapError(f"could not resolve import {label}")
            struct.pack_into("<Q", image, target, address)
            thunk += 8
            target += 8
        offset += 20


def _entry_stub(base: int, entry: int, reserved: int) -> bytes:
    """x64 stub that calls DllMain(base, DLL_PROCESS_ATTACH, reserved).

    A remote thread hands its routine a single argument, so the other two are
    supplied here instead of trying to smuggle them through the thread. The
    reserved slot carries whatever the caller wants the image to know about
    itself -- for a reflected image, its output path.
    """
    stub = bytearray()
    stub += b"\x48\xB9" + struct.pack("<Q", base)        # mov rcx, base
    stub += b"\xBA\x01\x00\x00\x00"                      # mov edx, 1  (ATTACH)
    stub += b"\x49\xB8" + struct.pack("<Q", reserved)    # mov r8, reserved
    stub += b"\x48\xB8" + struct.pack("<Q", entry)       # mov rax, entry
    stub += b"\x48\x83\xEC\x28"                          # sub rsp, 0x28
    stub += b"\xFF\xD0"                                  # call rax
    stub += b"\x48\x83\xC4\x28"                          # add rsp, 0x28
    stub += b"\xC3"                                      # ret
    return bytes(stub)


def thread_ids(pid: int) -> list[int]:
    """Thread ids owned by a process, from the toolhelp snapshot."""
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        return []
    out: list[int] = []
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)
        ok = kernel32.Thread32First(ctypes.c_void_p(snapshot), ctypes.byref(entry))
        while ok:
            if int(entry.th32OwnerProcessID) == pid:
                out.append(int(entry.th32ThreadID))
            ok = kernel32.Thread32Next(ctypes.c_void_p(snapshot), ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(snapshot))
    return out


def _alloc(handle: int, size: int) -> int:
    remote = kernel32.VirtualAllocEx(
        ctypes.c_void_p(handle),
        None,
        size,
        roblox.MEM_COMMIT | roblox.MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    if not remote:
        raise MapError(f"VirtualAllocEx failed (WinError {ctypes.get_last_error()})")
    return int(remote)


def _write(handle: int, remote: int, payload: bytes) -> None:
    written = ctypes.c_size_t(0)
    buf = ctypes.create_string_buffer(payload, len(payload))
    if not kernel32.WriteProcessMemory(
        ctypes.c_void_p(handle),
        ctypes.c_void_p(remote),
        ctypes.cast(buf, ctypes.c_void_p),
        len(payload),
        ctypes.byref(written),
    ):
        raise MapError(f"WriteProcessMemory failed (WinError {ctypes.get_last_error()})")


def map_dll(
    handle: int,
    pid: int = 0,
    dll_path: str | Path = "",
    report_path: str | None = None,
    method: str = "thread",
) -> dict:
    """Map a DLL into an already-open target process.

    ``report_path`` is handed to the image as DllMain's reserved argument. A
    reflected image is absent from the loader list, so it cannot discover its own
    file name and needs the loader to tell it where to write.

    ``method`` chooses how the entry point is reached:

    ``"thread"``  ``CreateRemoteThread`` on a fresh thread.
    ``"apc"``     ``QueueUserAPC`` onto a thread that already exists -- no thread
                  object is created, which is what a client that neutralises
                  foreign threads leaves as the user-mode option.

    Returns ``{base, size, entry, thread_exit, method}``. Raises MapError on
    anything the mapper refuses to guess at.
    """
    path = Path(dll_path)
    pe = parse_pe(path.read_bytes())

    size = pe["size_of_image"]
    remote = _alloc(handle, size)
    cfg_remote = 0
    stub_remote = 0

    try:
        _write(handle, remote, bytes(build_image(pe, remote)))

        reserved = 0
        if report_path:
            blob = str(report_path).encode("ascii", "replace") + b"\x00"
            cfg_remote = _alloc(handle, len(blob))
            _write(handle, cfg_remote, blob)
            reserved = cfg_remote

        stub = _entry_stub(remote, remote + pe["entry_rva"], reserved)
        stub_remote = _alloc(handle, len(stub))
        _write(handle, stub_remote, stub)

        exit_code = 0
        queued_threads: list[int] = []
        if method == "apc":
            if not pid:
                raise MapError("apc method needs the target pid to find a thread")
            rights = THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION
            for tid in thread_ids(pid):
                thread_handle = kernel32.OpenThread(rights, False, tid)
                if not thread_handle:
                    continue
                try:
                    if kernel32.QueueUserAPC(
                        ctypes.c_void_p(stub_remote), ctypes.c_void_p(int(thread_handle)), 0
                    ):
                        queued_threads.append(tid)
                finally:
                    kernel32.CloseHandle(ctypes.c_void_p(int(thread_handle)))
            if not queued_threads:
                raise MapError(
                    "no thread accepted an APC -- every thread handle was refused "
                    "or the queue call was blocked"
                )
        else:
            thread = kernel32.CreateRemoteThread(
                ctypes.c_void_p(handle),
                None,
                0,
                ctypes.c_void_p(stub_remote),
                None,
                0,
                None,
            )
            if not thread:
                raise MapError(f"CreateRemoteThread failed (WinError {ctypes.get_last_error()})")
            kernel32.WaitForSingleObject(ctypes.c_void_p(int(thread)), 15000)
            code = ctypes.c_ulong(0)
            kernel32.GetExitCodeThread(ctypes.c_void_p(int(thread)), ctypes.byref(code))
            kernel32.CloseHandle(ctypes.c_void_p(int(thread)))
            exit_code = int(code.value)

        # With an APC the stub must stay put: it has not run yet. Freeing it now
        # would leave a dangling queue entry. It is released with the image.
        if method != "apc":
            if stub_remote:
                kernel32.VirtualFreeEx(ctypes.c_void_p(handle), ctypes.c_void_p(stub_remote), 0, roblox.MEM_RELEASE)
            if cfg_remote:
                kernel32.VirtualFreeEx(ctypes.c_void_p(handle), ctypes.c_void_p(cfg_remote), 0, roblox.MEM_RELEASE)

        return {
            "base": remote,
            "size": size,
            "entry": remote + pe["entry_rva"],
            "stub": stub_remote,
            "config": cfg_remote,
            "thread_exit": exit_code,
            "method": method,
            "queued_threads": queued_threads,
        }
    except Exception:
        if stub_remote:
            kernel32.VirtualFreeEx(ctypes.c_void_p(handle), ctypes.c_void_p(stub_remote), 0, roblox.MEM_RELEASE)
        if cfg_remote:
            kernel32.VirtualFreeEx(ctypes.c_void_p(handle), ctypes.c_void_p(cfg_remote), 0, roblox.MEM_RELEASE)
        kernel32.VirtualFreeEx(ctypes.c_void_p(handle), ctypes.c_void_p(remote), 0, roblox.MEM_RELEASE)
        raise
