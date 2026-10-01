"""First-run setup.

The app ships a self-signed driver and its public certificate. For Windows to
load that driver, two machine-level things have to be true:

  1. the certificate is trusted -- installed into ``Root`` and
     ``TrustedPublisher``, so the signature validates;
  2. test signing is on -- which is the mode that permits a self-signed driver
     to load at all.

Both need administrator rights and test signing only takes effect **after a
restart**, so the honest flow the user sees is:

    setup runs -> "restart your PC to finish setup" -> reboot -> everything works

This module does that: it does the machine changes, records that a restart is
pending, and reports clearly. It never claims the driver is loadable before the
reboot has actually happened -- a false "ready" is worse than an honest "restart
needed".
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
from pathlib import Path

from . import config

CERT_SUBJECT = "NightRelay"
MARKER_NAME = "setup_pending.json"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _run(args: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args, capture_output=True, timeout=timeout, check=False, text=True
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate() -> bool:
    """Re-launch this process elevated. True if the prompt was accepted."""
    try:
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        return int(rc) > 32
    except Exception:
        return False


def _marker_path() -> Path:
    return config.data_dir() / MARKER_NAME


# --------------------------------------------------------------------------- #
# machine state
# --------------------------------------------------------------------------- #
def secure_boot_enabled() -> bool | None:
    """Secure Boot blocks test signing. None when it cannot be read."""
    try:
        import winreg  # noqa: PLC0415 - Windows only

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        ) as key:
            return bool(winreg.QueryValueEx(key, "UEFISecureBootEnabled")[0])
    except Exception:
        # No key at all usually means a legacy BIOS boot -- Secure Boot is off.
        return False


def test_signing_enabled() -> bool:
    code, out = _run(["bcdedit", "/enum", "{current}"])
    if code != 0:
        return False
    for line in out.splitlines():
        low = line.lower()
        if "testsigning" in low:
            return "yes" in low
    return False


def cert_installed() -> bool:
    """True when our certificate is trusted for driver signatures."""
    for store in ("Root", "TrustedPublisher"):
        code, out = _run(["certutil", "-store", store])
        if code == 0 and CERT_SUBJECT.lower() in out.lower():
            continue
        return False
    return True


def find_cert() -> Path | None:
    """Locate the shipped public certificate next to the app or driver."""
    candidates = (
        config.resource_dir() / "driver" / "nightrelay.cer",
        config.install_dir() / "driver" / "nightrelay.cer",
        config.install_dir() / "nightrelay.cer",
        Path.cwd() / "nightrelay.cer",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


# --------------------------------------------------------------------------- #
# restart tracking
# --------------------------------------------------------------------------- #
def _write_marker() -> None:
    try:
        _marker_path().write_text(str(int(time.time())), "utf-8")
    except OSError:
        pass


def restart_pending() -> bool:
    """True when we asked for test signing but have not rebooted since."""
    if test_signing_enabled():
        # Already active -- either we rebooted, or it was on beforehand.
        return False
    if not _marker_path().is_file():
        return False
    try:
        marked = int(_marker_path().read_text("utf-8").strip() or "0")
    except (OSError, ValueError):
        return False
    # Uptime is shorter than the time since we wrote the marker => not rebooted.
    uptime = time.monotonic()
    boot_epoch = time.time() - uptime
    return boot_epoch < marked


def _clear_marker() -> None:
    try:
        _marker_path().unlink(missing_ok=True)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# status + provisioning
# --------------------------------------------------------------------------- #
def status() -> dict:
    secure = secure_boot_enabled()
    signing = test_signing_enabled()
    cert = cert_installed()
    pending = restart_pending()
    ordered = bool(signing and cert)
    return {
        "admin": is_admin(),
        "secure_boot": secure,
        "test_signing": signing,
        "cert_installed": cert,
        "certificate": str(find_cert() or ""),
        "restart_pending": pending,
        "ready": ordered and not pending,
        "message": (
            "ready -- driver can load"
            if ordered and not pending
            else "restart your PC to finish setup"
            if pending
            else "setup has not been run"
        ),
    }


def provision() -> dict:
    """Do the machine changes. Returns a status dict with a clear next step."""
    if os.name != "nt":
        return {"ok": False, "message": "setup is Windows-only"}

    if not is_admin():
        return {
            "ok": False,
            "needs_admin": True,
            "message": "administrator rights are required to finish setup",
        }

    if secure_boot_enabled():
        # Test signing cannot be enabled while Secure Boot is active, and Secure
        # Boot is a firmware setting -- we cannot change it from here. Report it
        # plainly rather than pretending the setup succeeded.
        return {
            "ok": False,
            "secure_boot": True,
            "message": (
                "Secure Boot is enabled, so test signing cannot be turned on. "
                "Disable Secure Boot in BIOS, or use the driver-signing path."
            ),
        }

    cer = find_cert()
    if not cer:
        return {"ok": False, "message": "no certificate found to install (nightrelay.cer)"}

    steps: list[str] = []

    for store in ("Root", "TrustedPublisher"):
        code, out = _run(["certutil", "-addstore", "-f", store, str(cer)])
        steps.append(f"{store}: {'ok' if code == 0 else out.strip()[:80]}")

    code, out = _run(["bcdedit", "/set", "testsigning", "on"])
    steps.append(f"testsigning: {'ok' if code == 0 else out.strip()[:80]}")

    _write_marker()

    after = status()
    after.update(
        {
            "ok": True,
            "steps": steps,
            "message": "restart your PC to finish setup",
        }
    )
    return after


def finalize_if_rebooted() -> None:
    """Clear the pending marker once a reboot has actually applied the change."""
    if test_signing_enabled() and not restart_pending():
        _clear_marker()
