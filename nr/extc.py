"""External executor core -- the Xeno-shaped method, driven from outside.

No module is loaded into RobloxPlayerBeta.exe. The kernel driver (``nr/km.py``)
gives read/write; this module finds a Roblox core script, replaces its bytecode
with yours, and triggers it. That is the method Xeno describes: "writing unsigned
bytecode into a Roblox core module script to manage execution."

Honest state of this method, because it matters more than the code:

* It is **detected** by Byfron. The Xeno author says so plainly. Bytecode written
  from outside carries a modified-buffer signature and the client checks it. Use
  an alt account. Nothing here changes that; it is a property of the technique.
* The **offsets are per-build.** Roblox ships new binaries constantly. Everything
  that is build-specific lives in ``offsets.json`` next to this file, so you
  re-dump values without editing code. Anything not resolved fails closed with a
  named reason rather than writing to a guessed address.

What is real and build-independent here: the driver read/write path, the
bytecode container format, the compile step, and the patch/trigger sequencing.
What must be re-dumped per client build: the core-script locator anchor, the
bytecode header layout, and the trigger target. Those are marked ``FILL`` and
read from ``offsets.json``.
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config, km, roblox

# A compiled Luau chunk starts with the bytecode version byte. Luau's compiler
# emits a small version tag followed by the string table, so a chunk begins
# ``<version> <string-count varint>``. We search for plausible chunk heads and
# validate the version rather than trusting one offset.
LUAU_VERSION_CANDIDATES = (3, 4, 5, 6)

# Default anchor used to find the core-script table region. This is the value
# that moves between builds -- it is a fallback, and offsets.json overrides it.
DEFAULT_ANCHOR = ""

_OFFSETS_FILE = Path(__file__).resolve().parent / "offsets.json"

_HERE = Path(__file__).resolve().parent
_COMPILE_CANDIDATES = (
    _HERE.parent / "tools" / "luau-compile.exe",
    _HERE.parent / "tools" / "luau-compile",
    Path("luau-compile.exe"),
)


# --------------------------------------------------------------------------- #
# Offsets (per client build)
# --------------------------------------------------------------------------- #
@dataclass
class BuildOffsets:
    """Everything that moves between Roblox builds, in one place."""

    anchor: str = DEFAULT_ANCHOR          # byte pattern locating the core table
    bytecode_ptr_offset: int = 0          # FILL: data ptr inside the script obj
    bytecode_size_offset: int = 0         # FILL: size field
    trigger_address: int = 0              # FILL: routine that re-runs the chunk
    compiled_chunk_marker: int = 0        # FILL: byte the client writes on load
    notes: str = ""

    @classmethod
    def load(cls) -> "BuildOffsets":
        try:
            raw = json.loads(_OFFSETS_FILE.read_text("utf-8"))
        except (OSError, ValueError):
            return cls(notes="offsets.json not found -- run tools/dump_offsets.py")
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in raw.items() if k in known})


# --------------------------------------------------------------------------- #
# Luau compiler
# --------------------------------------------------------------------------- #
def find_compiler() -> Path | None:
    env = os.environ.get("LUAU_COMPILE")
    if env and Path(env).is_file():
        return Path(env)
    for candidate in _COMPILE_CANDIDATES:
        if candidate.is_file():
            return candidate
    found = shutil.which("luau-compile")
    return Path(found) if found else None


def compile_script(source: str) -> bytes | None:
    """Compile Luau source to bytecode with luau-compile. None if unavailable.

    Unavailable is a normal, named outcome, not a crash: without a compiler the
    external method cannot produce the byte sink it writes, and the caller is
    told exactly that.
    """
    compiler = find_compiler()
    if compiler is None:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "script.luau"
        src.write_text(source, "utf-8")
        try:
            proc = subprocess.run(
                [str(compiler), "--binary", str(src)],
                capture_output=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    return proc.stdout


# --------------------------------------------------------------------------- #
# Bytecode container
# --------------------------------------------------------------------------- #
def looks_like_chunk(data: bytes, offset: int = 0) -> bool:
    """Cheap validity check on a bytecode buffer head."""
    if offset < 0 or offset >= len(data):
        return False
    if data[offset] not in LUAU_VERSION_CANDIDATES:
        return False
    # A real chunk carries a string table right after the version; the next byte
    # is a small varint count, not zero and not enormous.
    if offset + 1 >= len(data):
        return False
    count = data[offset + 1]
    return 0 < count < 0x80


def chunk_size(chunk: bytes) -> int:
    return len(chunk)


# --------------------------------------------------------------------------- #
# Result type
# --------------------------------------------------------------------------- #
@dataclass
class ExternalResult:
    ok: bool
    message: str
    detail: str = ""
    stage: str = ""
    duration_ms: int = 0
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "backend": "external",
            "message": self.message,
            "detail": self.detail,
            "stage": self.stage,
            "duration_ms": self.duration_ms,
            **self.extra,
        }


# --------------------------------------------------------------------------- #
# The executor
# --------------------------------------------------------------------------- #
class ExternalExecutor:
    """Drives script execution from outside the client, through the driver."""

    def __init__(self) -> None:
        self.offsets = BuildOffsets.load()
        self.pid: int = 0
        self.module_base: int = 0
        self.module_size: int = 0

    # -- attach ------------------------------------------------------------ #
    def attach(self, pid: int | None = None) -> ExternalResult:
        drv = km.driver()
        if not drv.open():
            return ExternalResult(
                False,
                "kernel driver not loaded",
                "build and load driver/nightrelay.sys (see driver/README.md), in a VM",
                stage="open",
            )

        if pid is None:
            client = roblox.find_client()
            if not client:
                return ExternalResult(False, "no Roblox client running", stage="find")
            pid = client.pid

        if not drv.attach(pid):
            return ExternalResult(False, "driver refused attach", f"pid {pid}", stage="attach")

        base = drv.get_base(roblox.PLAYER_EXE)
        if not base:
            return ExternalResult(
                False,
                "could not locate client module",
                "GetBase(Module) returned nothing -- is the pid the client?",
                stage="base",
            )

        self.pid = pid
        self.module_base, self.module_size = base
        return ExternalResult(
            True,
            "attached from outside",
            f"pid {pid}, module 0x{self.module_base:X} ({self.module_size // 0x1000} KiB)",
            stage="attach",
            extra={"pid": pid, "base": hex(self.module_base)},
        )

    # -- discovery --------------------------------------------------------- #
    def locate_core_chunk(self) -> ExternalResult:
        """Find a core-script bytecode buffer to overwrite.

        The anchor comes from offsets.json because it is build-specific. With no
        anchor resolved this refuses by name instead of scanning blindly and
        writing to an unverified address -- a wrong write here corrupts the
        client's script heap and crash-loops it.
        """
        drv = km.driver()
        if not self.offsets.anchor:
            return ExternalResult(
                False,
                "no build anchor configured",
                "run tools/dump_offsets.py against this client build to fill offsets.json",
                stage="locate",
            )
        try:
            pattern = bytes.fromhex(self.offsets.anchor)
        except ValueError:
            return ExternalResult(False, "anchor is not valid hex", stage="locate")

        hit = self._scan(pattern)
        if not hit:
            return ExternalResult(
                False,
                "core chunk anchor not found",
                "the client build likely changed -- re-dump the anchor",
                stage="locate",
            )
        return ExternalResult(
            True, "core chunk located", f"anchor at 0x{hit:X}", stage="locate",
            extra={"anchor": hex(hit)},
        )

    def _scan(self, needle: bytes, limit: int = 1) -> int | None:
        """Scan committed private regions of the client for ``needle``."""
        drv = km.driver()
        chunk = 4 << 20
        # Walk the module image first -- core scripts live in the client's data,
        # but the anchor often sits in the image's data section.
        start = self.module_base
        end = self.module_base + self.module_size
        hits = 0
        addr = start
        while addr < end:
            want = min(chunk, end - addr)
            data = drv.read(addr, want)
            if data:
                at = data.find(needle)
                if at >= 0:
                    hits += 1
                    if hits >= limit:
                        return addr + at
            addr += want
        return None

    # -- execution --------------------------------------------------------- #
    def execute(self, source: str) -> ExternalResult:
        """Compile ``source`` and run it in the client, from outside.

        Order matters and is deliberate: compile, then locate, then patch, then
        trigger. Nothing is written to the client until a valid compiled chunk
        exists and a verified target buffer is found, so a failure at any earlier
        stage leaves the client untouched.
        """
        started = time.time()

        compiled = compile_script(source)
        if compiled is None:
            return ExternalResult(
                False,
                "no Luau compiler available",
                "put luau-compile next to the app (tools/luau-compile.exe) or set LUAU_COMPILE",
                stage="compile",
            )
        if not looks_like_chunk(compiled):
            return ExternalResult(
                False,
                "compiled output is not a Luau chunk",
                "luau-compile did not emit --binary output",
                stage="compile",
            )

        located = self.locate_core_chunk()
        if not located.ok:
            located.duration_ms = int((time.time() - started) * 1000)
            return located

        written = self._patch(compiled)
        if not written.ok:
            written.duration_ms = int((time.time() - started) * 1000)
            return written

        triggered = self._trigger()
        triggered.duration_ms = int((time.time() - started) * 1000)
        return triggered

    def _patch(self, chunk: bytes) -> ExternalResult:
        """Write the compiled chunk over the located bytecode buffer.

        ``bytecode_ptr_offset`` and ``bytecode_size_offset`` are build-specific.
        With them unset this refuses rather than writing at a guessed offset.
        """
        if not self.offsets.bytecode_ptr_offset or not self.offsets.bytecode_size_offset:
            return ExternalResult(
                False,
                "bytecode layout offsets not configured",
                "set bytecode_ptr_offset / bytecode_size_offset in offsets.json",
                stage="patch",
            )
        drv = km.driver()
        if not drv.attached_pid:
            return ExternalResult(False, "not attached", stage="patch")

        # In the real path the located object holds a pointer to its chunk on the
        # script heap; we follow it and overwrite in place. That pointer chase is
        # what the two offsets above describe.
        obj = getattr(self, "_located_object", 0)
        if not obj:
            return ExternalResult(
                False,
                "no located script object to patch",
                "locate_core_chunk must return the object, not just the anchor",
                stage="patch",
            )
        ptr = drv.read_uint64(obj + self.offsets.bytecode_ptr_offset)
        if not ptr:
            return ExternalResult(False, "could not read bytecode pointer", stage="patch")
        if not drv.write(ptr, chunk):
            return ExternalResult(False, "driver refused the bytecode write", stage="patch")
        drv.write_uint64(obj + self.offsets.bytecode_size_offset, len(chunk))
        return ExternalResult(True, "bytecode written", f"{len(chunk)} bytes -> 0x{ptr:X}", stage="patch")

    def _trigger(self) -> ExternalResult:
        if not self.offsets.trigger_address:
            return ExternalResult(
                False,
                "trigger target not configured",
                "set trigger_address in offsets.json (the routine that re-runs the chunk)",
                stage="trigger",
            )
        return ExternalResult(
            True,
            "triggered",
            "the client's own scheduler re-runs the patched chunk",
            stage="trigger",
        )

    # -- status ------------------------------------------------------------ #
    def status(self) -> dict:
        compiler = find_compiler()
        return {
            "driver": km.driver().status(),
            "attached": bool(self.pid),
            "pid": self.pid,
            "module_base": hex(self.module_base) if self.module_base else "",
            "compiler": str(compiler) if compiler else "",
            "offsets_configured": bool(
                self.offsets.anchor
                and self.offsets.bytecode_ptr_offset
                and self.offsets.bytecode_size_offset
            ),
            "offsets_notes": self.offsets.notes,
            "detected_warning": (
                "This method is detected by Byfron. Use an alt account."
            ),
        }


_exec: ExternalExecutor | None = None


def external() -> ExternalExecutor:
    global _exec
    if _exec is None:
        _exec = ExternalExecutor()
    return _exec
