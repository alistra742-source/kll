"""Inspect the installed Roblox client binary -- the starting point for offsets.

This does not derive the Luau signatures; that needs a disassembler and iterative
verification against a running client. What it does is remove the boilerplate
before that work: it finds the newest installed client, reads its PE headers, and
reports the facts you need to start from -- image base, sections, whether the
image is relocatable, and the revision, which changes every patch and is what
tells you when a signature set is stale.

    python tools/inspect_client.py
    python tools/inspect_client.py --exe "C:\\path\\to\\RobloxPlayerBeta.exe"

Everything here is read-only on a file. It never launches or touches a client.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nr import roblox  # noqa: E402


def sha256_of(path: Path, limit: int = 0) -> str:
    digest = hashlib.sha256()
    read = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            read += len(chunk)
            if limit and read >= limit:
                break
    return digest.hexdigest()


def report(exe: Path) -> int:
    if not exe.is_file():
        print(f"not found: {exe}")
        return 1

    try:
        import pefile  # noqa: PLC0415
    except ImportError:
        print("pefile is required: pip install pefile")
        return 1

    print(f"file       : {exe}")
    print(f"size       : {exe.stat().st_size / (1024 * 1024):.1f} MiB")
    print(f"sha256     : {sha256_of(exe)}")

    pe = pefile.PE(str(exe), fast_load=True)
    try:
        machine = pe.FILE_HEADER.Machine
        print(f"machine    : {hex(machine)} "
              f"({'x64' if machine == 0x8664 else 'x86' if machine == 0x14C else 'unknown'})")
        print(f"image base : {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"entrypoint : {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"timestamp  : {pe.FILE_HEADER.TimeDateStamp} "
              f"({__import__('time').strftime('%Y-%m-%d', __import__('time').gmtime(pe.FILE_HEADER.TimeDateStamp))})")
        print(f"relocs     : {'present' if pe.OPTIONAL_HEADER.DllCharacteristics & 0x40 else 'stripped (fixed image)'}")
        print(f"ASLR       : {'yes' if pe.OPTIONAL_HEADER.DllCharacteristics & 0x40 else 'no'}")

        print("\nsections:")
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", "replace")
            print(
                f"  {name:8} va {hex(section.VirtualAddress):>10} "
                f"vsize {hex(section.Misc_VirtualSize):>10} "
                f"raw {hex(section.SizeOfRawData):>10} "
                f"chars {hex(section.Characteristics)}"
            )

        # The .text section is where every signature will be searched.
        text = next((s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"), None)
        if text:
            print(f"\n.text window to search: 0x{text.VirtualAddress:X} .. "
                  f"0x{text.VirtualAddress + text.Misc_VirtualSize:X} "
                  f"({text.Misc_VirtualSize // 0x1000} KiB)")
    finally:
        pe.close()

    print(
        "\nnext: this is the image to reverse for signatures.json.\n"
        "      Luau is statically linked, so find the functions by their code (x64dbg),\n"
        "      not by an export table, then fill tools/signatures.json and run\n"
        "      python tools/dump_config.py --check against a live client."
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="inspect_client", description=__doc__)
    parser.add_argument("--exe", default="")
    args = parser.parse_args(argv)

    if args.exe:
        return report(Path(args.exe))

    versions = roblox.player_versions()
    if not versions:
        print("no installed Roblox client found")
        return 1
    # player_versions() is newest-first.
    return report(versions[0] / roblox.PLAYER_EXE)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
