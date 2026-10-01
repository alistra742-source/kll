"""Probe a live client for its Luau structures, from outside.

Run this against a client with a place actually loaded:

    python tools/lua_probe.py
    python tools/lua_probe.py --names print game workspace Instance --dump

It reports, in order:

  1. the readable address space it can see,
  2. whether each requested global exists as an interned TString,
  3. for ``--dump``, the raw bytes around each string hit, so the layout can be
     read off the process instead of assumed.

That last part matters. A structural scan is only as good as its idea of the
layout, and reading the bytes is how you find out you had it wrong. A hit that
does not look like a TString is not a TString.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nr import executor, luavm, roblox  # noqa: E402

DEFAULT_NAMES = ["print", "game", "workspace", "Instance", "tostring", "pcall", "game"]


def dump_around(handle: int, address: int, before: int = 32, after: int = 16) -> None:
    data = luavm.read(handle, address - before, before + after)
    if not data:
        print("      (unreadable)")
        return
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        marker = "   <-- text" if off <= before < off + 16 else ""
        print(f"      {chunk.hex(' ')}{marker}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="probe a client for Luau structures")
    parser.add_argument("--names", nargs="*", default=None)
    parser.add_argument("--dump", action="store_true", help="show bytes around each hit")
    parser.add_argument("--pid", type=int, default=0)
    args = parser.parse_args(argv)

    clients = roblox.find_roblox(include_studio=False)
    if not clients:
        print("no Roblox client is running")
        return 1
    client = next((c for c in clients if c.pid == args.pid), clients[-1])
    print(f"client pid {client.pid}  build {client.version}  {client.memory_mb} MB")

    place = roblox.place_from_log()
    print(f"last place: {place or 'none -- the client may be sitting at the menu'}")
    if not place:
        print(
            "  warning: with no place joined there may be no game Lua state yet.\n"
            "  join an experience, then run this again."
        )

    handle = executor.executor().injector._open(
        client.pid, executor.PROBE_RIGHTS | roblox.PROCESS_VM_READ
    )
    if not handle:
        print("could not open the client for reading")
        return 1

    started = time.time()
    regions = luavm.regions(handle)
    total = sum(r.size for r in regions)
    print(f"\nreadable: {len(regions)} region(s), {total / 1e9:.2f} GB ({time.time() - started:.1f}s)")

    names = args.names or DEFAULT_NAMES
    started = time.time()
    found = luavm.find_tstrings(handle, names, regions)
    print(f"TString scan: {time.time() - started:.1f}s")

    hits = 0
    for name, ts in found.items():
        if ts is None:
            print(f"  {name:12} not found")
            continue
        hits += 1
        print(f"  {name:12} base={hex(ts.base)} data={hex(ts.data)} len={ts.length} hash={hex(ts.hash)}")
        if args.dump:
            dump_around(handle, ts.data, 32, 16)

    print(f"\n{hits}/{len(names)} interned string(s) located")
    if hits == 0:
        print(
            "No interned strings found. Check that a place is loaded and that the\n"
            "TString layout in nr/luavm.py matches this build -- rerun with --dump\n"
            "on a string you know exists to read the real layout."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
