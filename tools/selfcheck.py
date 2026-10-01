"""One-command stack check.

Answers "is everything wired" without launching the client or the driver. It
imports every module, confirms the expected files exist, checks the HTTP routes
the UI depends on, and validates the settings the app reads at boot.

    python tools/selfcheck.py

Exit code is 0 when everything is in place and 1 when something is missing, so
it works as a gate before packaging a release.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PASS = "  ok  "
FAIL = " FAIL "
WARN = " warn "

failures: list[str] = []
warnings: list[str] = []


def check(label: str, ok: bool, why: str = "", warn_only: bool = False) -> None:
    mark = PASS if ok else (WARN if warn_only else FAIL)
    print(f"[{mark}] {label}" + (f" -- {why}" if why and not ok else ""))
    if not ok:
        (warnings if warn_only else failures).append(label)


def check_imports() -> None:
    print("\n== modules ==")
    modules = [
        "nr", "nr.config", "nr.km", "nr.inject", "nr.extc", "nr.payload",
        "nr.byovd", "nr.humanize", "nr.license", "nr.setup", "nr.executor",
        "nr.roblox", "nr.fflags", "nr.library", "nr.trust", "nr.deepseek",
        "nr.discovery", "nr.luavm", "nr.manualmap", "nr.server",
    ]
    for name in modules:
        try:
            importlib.import_module(name)
            check(f"import {name}", True)
        except Exception as exc:  # noqa: BLE001 - the message is the result
            check(f"import {name}", False, f"{type(exc).__name__}: {exc}")


def check_files() -> None:
    print("\n== files ==")
    required = [
        "nightrelay.py",
        "ui/index.html",
        "driver/nightrelay_drv.c",
        "driver/nr_stealth.c",
        "driver/nightrelay.h",
        "driver/nightrelay.inf",
        "driver/build_driver.bat",
        "driver/package_driver.bat",
        "driver/sign_dev.ps1",
        "payload/nr_executor.c",
        "payload/build_executor.bat",
        "tools/dump_config.py",
        "tools/signatures.json",
        "nr/offsets.json",
    ]
    for rel in required:
        path = ROOT / rel
        check(rel, path.is_file(), "missing")


def check_routes() -> None:
    print("\n== http routes ==")
    try:
        from nr import server
    except Exception as exc:  # noqa: BLE001
        check("create_app", False, str(exc))
        return
    app = server.create_app()
    rules = {r.rule for r in app.url_map.iter_rules()}
    for rule in (
        "/api/state",
        "/api/executor",
        "/api/executor/external",
        "/api/executor/external/attach",
        "/api/executor/external/execute",
        "/api/license",
        "/api/license/activate",
        "/api/setup",
        "/api/setup/run",
        "/api/loader",
        "/api/loader/byovd",
        "/api/roblox/launch",
        "/api/roblox/multi-instance",
        "/api/execute",
    ):
        check(f"route {rule}", rule in rules)
    # The removed loader-bridge surface must stay gone.
    stale = [r for r in rules if "bridge" in r]
    check("no stale bridge routes", not stale, ", ".join(stale))


def check_settings() -> None:
    print("\n== settings ==")
    from nr import config

    for key in (
        "executor.backend",
        "executor.payload_dll",
        "stealth.humanize",
        "stealth.mapper_path",
        "roblox.multi_instance",
        "license.required",
    ):
        value = config.settings().get(key, "__missing__")
        check(f"setting {key}", value != "__missing__")


def check_offline_pieces() -> None:
    print("\n== offline pieces ==")
    from nr import extc, license, byovd

    check("luau compiler present", extc.find_compiler() is not None,
          "place luau-compile in tools/ (needed to run scripts)", warn_only=True)
    check("license keygen works", bool(license.make_key("trial", 1)))
    check("hwid readable", bool(license.hwid()))
    check("byovd candidates", len(byovd.KNOWN_VULN_DRIVERS) > 0)
    check("mapper present", byovd.find_mapper() is not None,
          "place kdmapper in tools/ (needed for the BYOVD path)", warn_only=True)
    offsets = extc.external().offsets
    check("build offsets filled",
          bool(offsets.anchor and offsets.bytecode_ptr_offset),
          "nr/offsets.json is empty -- run tools/dump_config.py against a client",
          warn_only=True)


def main() -> int:
    check_imports()
    check_files()
    check_routes()
    check_settings()
    check_offline_pieces()

    print("\n" + "=" * 48)
    if failures:
        print(f"FAILED: {len(failures)} item(s)")
        for item in failures:
            print(f"  - {item}")
    else:
        print("all required pieces present")
    if warnings:
        print(f"\n{len(warnings)} warning(s) -- these need real-world values:")
        for item in warnings:
            print(f"  ~ {item}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
