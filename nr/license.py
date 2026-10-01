"""Licensing: hardware-bound, signed keys.

Selling an executor means two things: keys you can mint, and a lock that survives
being copied to another PC. This module does both, offline.

Design, and the honest trade-offs:

* **Signed, not stored.** A key is ``NR-<payload>-<sig>``. The payload carries the
  tier and an expiry; the signature is an HMAC over the payload with a secret
  baked into the app. The app only ever *verifies* -- minting is done by the
  seller's keygen (``python -m nr.license keygen``). That is what makes keys
  unforgeable without the secret.

* **The secret lives in the binary.** This is the standard model for cheap
  executors and it is not strong: anyone who pulls the string out of the exe can
  mint keys. It stops casual sharing, which is all most sellers need. If you want
  it to actually hold, move verification to your server (see ``validate_online``)
  and ship no secret at all.

* **HWID-bound with a wildcard option.** A key can be locked to the first machine
  that activates it (default) or left free (``HWID=*``). The activation is cached
  in the vault, so a bound key does not re-bind on every launch.

Rotate ``_SECRET`` before you sell anything, and never commit a real one.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import config

# --- seller secret ----------------------------------------------------------- #
# CHANGE THIS before selling. Anyone who reads it out of the exe can mint keys.
_SECRET = b"nightrelay::change-me-before-you-sell::v1"

KEY_PREFIX = "NR"
_HWID_WILDCARD = "*"
_VALID_TIERS = ("trial", "standard", "premium", "lifetime")


# --------------------------------------------------------------------------- #
# Hardware id
# --------------------------------------------------------------------------- #
def _machine_guid() -> str:
    """Windows MachineGuid -- stable per install, survives most hardware changes."""
    try:
        import winreg  # noqa: PLC0415 - Windows only

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
        ) as key:
            return str(winreg.QueryValueEx(key, "MachineGuid")[0])
    except Exception:
        return ""


def _volume_serial() -> str:
    """Serial of the system volume, as a second signal."""
    try:
        root = os.environ.get("SystemDrive", "C:") + "\\"
        serial = ctypes.c_ulong(0)
        ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root),
            None,
            0,
            ctypes.byref(serial),
            None,
            None,
            None,
            0,
        )
        return hex(serial.value)
    except Exception:
        return ""


def hwid() -> str:
    """Short, stable, non-reversible hardware id (16 chars)."""
    material = f"{_machine_guid()}|{_volume_serial()}".encode("utf-8")
    digest = hashlib.sha256(material).digest()
    return base64.b32encode(digest)[:16].decode("ascii")


# --------------------------------------------------------------------------- #
# Key format
# --------------------------------------------------------------------------- #
@dataclass
class License:
    valid: bool
    tier: str = ""
    expires: int = 0          # unix seconds; 0 == never
    hwid_bound: str = ""      # "" == wildcard
    reason: str = ""
    source: str = ""          # "offline" | "online" | "cache"

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "tier": self.tier,
            "expires": self.expires,
            "expires_in_days": self.days_left(),
            "hwid_bound": self.hwid_bound,
            "reason": self.reason,
            "source": self.source,
        }

    def days_left(self) -> int:
        if not self.expires:
            return -1  # never expires
        return max(0, (self.expires - int(time.time())) // 86400)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _sign(payload: str) -> str:
    mac = hmac.new(_SECRET, payload.encode("ascii"), hashlib.sha256).digest()
    return _b64e(mac[:9])  # 72 bits is plenty for an offline key


def make_key(tier: str, days: int = 30, hwid_bind: str = _HWID_WILDCARD) -> str:
    """Mint a key. Seller-side only -- do not call this from the shipped app."""
    if tier not in _VALID_TIERS:
        raise ValueError(f"tier must be one of {_VALID_TIERS}")
    expires = 0 if days <= 0 else int(time.time()) + days * 86400
    payload = json.dumps(
        {"t": tier, "e": expires, "h": hwid_bind}, separators=(",", ":")
    )
    encoded = _b64e(payload.encode("utf-8"))
    return f"{KEY_PREFIX}-{encoded}-{_sign(encoded)}"


def parse_key(key: str) -> License:
    """Verify a key's signature and expiry. Does not check hardware."""
    key = (key or "").strip()
    parts = key.split("-")
    if len(parts) != 3 or parts[0] != KEY_PREFIX:
        return License(False, reason="malformed key")

    encoded, sig = parts[1], parts[2]
    expected = _sign(encoded)
    if not hmac.compare_digest(sig, expected):
        return License(False, reason="bad signature")

    try:
        payload = json.loads(_b64d(encoded).decode("utf-8"))
    except (ValueError, KeyError):
        return License(False, reason="unreadable payload")

    tier = str(payload.get("t", ""))
    expires = int(payload.get("e", 0))
    bound = str(payload.get("h", _HWID_WILDCARD))

    if tier not in _VALID_TIERS:
        return License(False, reason="unknown tier")
    if expires and expires < int(time.time()):
        return License(False, tier=tier, expires=expires, reason="expired")
    if bound not in (_HWID_WILDCARD, hwid()):
        return License(False, tier=tier, expires=expires, hwid_bound=bound,
                       reason="bound to another machine")

    return License(True, tier=tier, expires=expires, hwid_bound=bound,
                   reason="ok", source="offline")


# --------------------------------------------------------------------------- #
# Activation (bind on first use, cache in the vault)
# --------------------------------------------------------------------------- #
def activate(key: str, online_url: str = "") -> License:
    """Validate a key, bind it to this machine if it is a wildcard, and cache it."""
    lic = parse_key(key)
    if not lic.valid:
        return lic

    # A wildcard key re-signs itself bound to this hwid would require the secret
    # on the client; instead we record the binding locally and enforce it here.
    record = {"key": key, "hwid": hwid(), "at": int(time.time())}
    if lic.hwid_bound == _HWID_WILDCARD:
        bound = config.vault().get("license_binding", "")
        if bound and bound != hwid():
            return License(False, tier=lic.tier, reason="key already used on another machine")
        config.vault().set("license_binding", hwid())
        record["bound"] = hwid()

    if online_url:
        online = validate_online(key, lic, online_url)
        if not online.valid:
            return online
        lic = online

    config.vault().set("license_key", key)
    config.vault().set("license_record", json.dumps(record))
    config.vault().flush()
    return lic


def validate_online(key: str, offline: License, url: str) -> License:
    """Server-side check. The seller runs the endpoint; the client only asks.

    Expected reply: ``{"valid": true, "tier": "...", "expires": <unix or 0>}``.
    Anything else (network error, 4xx, bad JSON) is a refusal -- never a soft
    pass, or a dead server would unlock the product.
    """
    body = json.dumps({"key": key, "hwid": hwid(), "tier": offline.tier}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return License(False, tier=offline.tier, reason=f"server unreachable: {exc}")

    if not data.get("valid"):
        return License(False, tier=offline.tier, reason=str(data.get("reason") or "rejected"))
    return License(
        True,
        tier=str(data.get("tier") or offline.tier),
        expires=int(data.get("expires") or offline.expires),
        hwid_bound=hwid(),
        reason="ok",
        source="online",
    )


def cached() -> License:
    """Re-validate the last activated key from the vault, offline."""
    key = config.vault().get("license_key", "")
    if not key:
        return License(False, reason="no key")
    return parse_key(key)


def required() -> bool:
    """Whether the app should gate on a license at all (sellers can turn it off)."""
    return bool(config.settings().get("license.required", True))


# --------------------------------------------------------------------------- #
# Seller CLI -- mint keys from the command line
# --------------------------------------------------------------------------- #
def _cli(argv: list[str]) -> int:
    if not argv or argv[0] != "keygen":
        print("usage: python -m nr.license keygen <tier> <days> [<hwid|*>]")
        print("       tiers: " + ", ".join(_VALID_TIERS))
        return 1
    tier = argv[1] if len(argv) > 1 else "standard"
    days = int(argv[2]) if len(argv) > 2 else 30
    bind = argv[3] if len(argv) > 3 else _HWID_WILDCARD
    print(make_key(tier, days, bind))
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(_cli(sys.argv[1:]))
