"""BYOVD -- load our driver with no certificate.

The problem: a self-signed driver needs test signing (reboot, watermark, Secure
Boot off). A Microsoft-signed driver needs an EV certificate. BYOVD sidesteps
both by loading a driver Microsoft *already signed in the past* and using its
known vulnerability to map our unsigned driver into the kernel.

The heavy lifting -- building the target image in kernel memory, fixing
relocations, resolving imports against ntoskrnl, calling the entry point -- is a
kernel-mode PE loader, and the reference implementation everyone uses is
**kdmapper**. Rewriting that here would produce a worse, untested copy of a
mature tool. So this module *orchestrates*: it manages the vulnerable driver's
lifecycle, drives a mapper, and cleans up. Point ``mapper`` at a kdmapper build
(or a maintained fork) and the rest is handled.

Detection is the honest trade and it is stated plainly: anti-cheats blocklist
known vulnerable drivers by hash and by name. The list below will age; when a
driver gets blocked the answer is to swap in another signed vulnerable driver,
not to change this code. That is a maintenance treadmill, not a bug.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import config


@dataclass
class VulnerableDriver:
    """A signed driver with a known memory primitive.

    ``path`` is where the .sys lives on disk. These are distributed by their
    hardware vendors, not by us -- you obtain the signed binary and point this at
    it. ``device`` is the symbolic link it exposes for its IOCTLs.
    """

    name: str                 # the driver's service name
    path: str = ""            # on-disk .sys
    device: str = ""          # \\.\<name> for its IOCTLs
    primitive: str = ""       # what it gives us: "arb read/write", "map phys", ...
    notes: str = ""


# Known-signed vulnerable drivers, as service definitions only. These are the
# families that have been used this way for years. They get blockedlist, so this
# is a starting set, not a guarantee -- add your own as needed.
KNOWN_VULN_DRIVERS: tuple[VulnerableDriver, ...] = (
    VulnerableDriver(
        name="iqvw64e",
        device=r"\\.\Nal",
        primitive="arbitrary physical read/write via NalIoControl",
        notes="Intel network adapter diagnostic. The classic kdmapper target; widely blocklisted.",
    ),
    VulnerableDriver(
        name="gdrv",
        device=r"\\.\GIO",
        primitive="arbitrary physical memory read/write",
        notes="Gigabyte 'GigabyteDriver'. Blocklisted by most modern anti-cheats.",
    ),
    VulnerableDriver(
        name="AsIO3",
        device=r"\\.\AsIO3",
        primitive="arbitrary physical memory read/write",
        notes="ASUS hardware access driver.",
    ),
)


# --------------------------------------------------------------------------- #
# Vulnerable driver lifecycle (needs admin)
# --------------------------------------------------------------------------- #
def _run(args: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=40, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def vuln_driver_loaded(spec: VulnerableDriver) -> bool:
    code, out = _run(["sc", "query", spec.name])
    return code == 0 and "RUNNING" in out.upper()


def start_vuln_driver(spec: VulnerableDriver) -> tuple[bool, str]:
    """Register and start the signed vulnerable driver as a service.

    It is signed by its vendor, so it loads without test signing -- which is the
    entire reason this path exists. Fails closed: if it does not reach RUNNING,
    the caller gets a reason, never a soft success.
    """
    if not spec.path or not Path(spec.path).is_file():
        return False, f"no signed binary for {spec.name} -- point spec.path at the .sys"

    if vuln_driver_loaded(spec):
        return True, f"{spec.name} already running"

    code, out = _run(
        ["sc", "create", spec.name, "type=", "kernel", "binPath=", str(spec.path)]
    )
    if code != 0 and "already exists" not in out.lower():
        return False, f"sc create failed: {out.strip()[:160]}"

    code, out = _run(["sc", "start", spec.name])
    if code != 0 or not vuln_driver_loaded(spec):
        return False, f"sc start failed: {out.strip()[:160]}"
    return True, f"{spec.name} running"


def stop_vuln_driver(spec: VulnerableDriver) -> None:
    """Stop and remove it, returning the machine to its previous state."""
    _run(["sc", "stop", spec.name])
    _run(["sc", "delete", spec.name])


# --------------------------------------------------------------------------- #
# Mapper
# --------------------------------------------------------------------------- #
def find_mapper() -> Path | None:
    """Locate the kernel-mode PE mapper (kdmapper or equivalent)."""
    env = config.settings().get("stealth.mapper_path", "")
    if env and Path(env).is_file():
        return Path(env)
    for candidate in (
        config.install_dir() / "tools" / "kdmapper.exe",
        config.install_dir() / "bin" / "kdmapper.exe",
        Path.cwd() / "kdmapper.exe",
    ):
        if candidate.is_file():
            return candidate
    return None


def map_driver(sys_path: str, mapper: Path, vuln: VulnerableDriver) -> tuple[bool, str]:
    """Run the mapper to load our driver through the vulnerable one."""
    if not Path(sys_path).is_file():
        return False, f"driver not found: {sys_path}"

    # kdmapper takes the driver path and does the rest; some forks take the
    # vulnerable driver's device as an argument. Pass it when it is known.
    args = [str(mapper), str(sys_path)]
    if vuln.device:
        args += ["--device", vuln.device]

    code, out = _run(args)
    tail = out.strip().splitlines()[-3:] if out.strip() else []
    if code != 0:
        return False, "mapper failed: " + " | ".join(tail)[:200]
    return True, "mapper reported success: " + " | ".join(tail)[:200]


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def load(sys_path: str) -> dict:
    """Full BYOVD sequence: vulnerable driver up -> map ours -> clean up.

    Order matters. The vulnerable driver is removed again as soon as the map
    completes, so the machine is left with only our driver running and no vendor
    driver sitting in the service list for a scanner to notice.
    """
    mapper = find_mapper()
    if mapper is None:
        return {
            "ok": False,
            "stage": "mapper",
            "message": "no mapper found",
            "detail": "place kdmapper.exe in tools/ or set stealth.mapper_path",
        }

    last = ""
    for spec in KNOWN_VULN_DRIVERS:
        started, detail = start_vuln_driver(spec)
        if not started:
            last = f"{spec.name}: {detail}"
            continue

        try:
            ok, mapped = map_driver(sys_path, mapper, spec)
        finally:
            stop_vuln_driver(spec)

        if ok:
            return {
                "ok": True,
                "stage": "mapped",
                "vulnerable_driver": spec.name,
                "message": "driver mapped through a signed vulnerable driver",
                "detail": mapped,
            }
        last = f"{spec.name}: {mapped}"

    return {
        "ok": False,
        "stage": "map",
        "message": "no vulnerable driver worked -- they may all be blocklisted",
        "detail": last,
    }


def status() -> dict:
    mapper = find_mapper()
    return {
        "mapper": str(mapper) if mapper else "",
        "mapper_ready": mapper is not None,
        "candidates": [
            {"name": s.name, "loaded": vuln_driver_loaded(s), "primitive": s.primitive}
            for s in KNOWN_VULN_DRIVERS
        ],
        "notes": "vulnerable drivers are blocklisted over time; swap when one stops working",
    }
