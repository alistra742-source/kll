"""Identify DeepSeekHashV1's exact Keccak variant.

DeepSeek's proof-of-work is a preimage search: find the nonce where

    Keccak-256(f"{salt}_{expire_at}_{nonce}") == challenge

The published notes claim 23 rounds instead of the standard 24, which would
explain why a standard Keccak scan over the whole nonce range finds nothing.

This script verifies that against a known-good vector published alongside a
clean-room reimplementation:

    salt      6c3a962c828dd81d7d69
    expire_at 1780227446451
    nonce     86022
    challenge 34d4c336676aa2e83c3308148e12ba8bc5e77ccb2fc12eeea1046e20c4c64eec
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MASK64 = (1 << 64) - 1

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# rho offsets indexed [x][y]
ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

RATE = 136  # bytes for a 256-bit digest


def _rol(value: int, amount: int) -> int:
    amount &= 63
    if amount == 0:
        return value
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def keccak_f(state, rounds: int, rc_offset: int = 0):
    for rnd in range(rounds):
        # theta: C[x] is the XOR of column x, i.e. across y
        c = [
            state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
            for x in range(5)
        ]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            dx = d[x]
            for y in range(5):
                state[x][y] ^= dx

        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(state[x][y], ROT[x][y])

        for x in range(5):
            x1 = b[(x + 1) % 5]
            x2 = b[(x + 2) % 5]
            col = b[x]
            for y in range(5):
                state[x][y] = col[y] ^ (~x1[y] & x2[y]) & MASK64

        state[0][0] ^= RC[(rc_offset + rnd) % 24]
    return state


def keccak(message: bytes, rounds: int = 24, pad: int = 0x01, rc_offset: int = 0) -> str:
    """Keccak-256 with a configurable round count, padding byte and RC start."""
    data = bytearray(message)
    data.append(pad)
    while len(data) % RATE != 0:
        data.append(0x00)
    data[-1] |= 0x80

    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(data), RATE):
        block = data[offset:offset + RATE]
        for i in range(RATE // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            state[i % 5][i // 5] ^= lane
        keccak_f(state, rounds, rc_offset)

    out = b"".join(
        state[i % 5][i // 5].to_bytes(8, "little") for i in range(4)
    )
    return out.hex()


GOLD = {
    "salt": "6c3a962c828dd81d7d69",
    "expire_at": 1780227446451,
    "nonce": 86022,
    "challenge": "34d4c336676aa2e83c3308148e12ba8bc5e77ccb2fc12eeea1046e20c4c64eec",
}


def main() -> int:
    print("=" * 74)
    print("step 1: validate the pure-python Keccak against pycryptodome (24 rounds)")
    print("=" * 74)
    try:
        from Crypto.Hash import keccak as pyc_keccak

        mismatches = 0
        for probe in (b"", b"abc", b"a" * 100, b"a" * 136, b"a" * 137, b"The quick brown fox"):
            h = pyc_keccak.new(digest_bits=256)
            h.update(probe)
            if h.hexdigest() != keccak(probe):
                mismatches += 1
                print(f"  MISMATCH for {probe[:20]!r}")
        print(f"  checked 6 inputs, mismatches: {mismatches}")
        if mismatches:
            print("  -> implementation is broken; stopping")
            return 1
        print("  -> pure-python keccak(24, 0x01) is correct")
    except ImportError:
        print("  pycryptodome unavailable; skipping cross-check")

    print()
    print("=" * 74)
    print("step 2: which variant reproduces the published golden answer?")
    print("=" * 74)
    message = f"{GOLD['salt']}_{GOLD['expire_at']}_{GOLD['nonce']}".encode()
    print(f"  input string: {message.decode()}")
    print(f"  challenge:    {GOLD['challenge']}")
    print()

    variants = [
        ("24 rounds, keccak padding 0x01", dict(rounds=24, pad=0x01, rc_offset=0)),
        ("24 rounds, sha3   padding 0x06", dict(rounds=24, pad=0x06, rc_offset=0)),
        ("23 rounds, rc[0..22], pad 0x01", dict(rounds=23, pad=0x01, rc_offset=0)),
        ("23 rounds, rc[1..23], pad 0x01", dict(rounds=23, pad=0x01, rc_offset=1)),
        ("23 rounds, rc[0..22], pad 0x06", dict(rounds=23, pad=0x06, rc_offset=0)),
        ("23 rounds, rc[1..23], pad 0x06", dict(rounds=23, pad=0x06, rc_offset=1)),
        ("22 rounds, rc[0..21], pad 0x01", dict(rounds=22, pad=0x01, rc_offset=0)),
        ("20 rounds, rc[0..19], pad 0x01", dict(rounds=20, pad=0x01, rc_offset=0)),
        ("16 rounds, rc[0..15], pad 0x01", dict(rounds=16, pad=0x01, rc_offset=0)),
        ("12 rounds, rc[0..11], pad 0x01", dict(rounds=12, pad=0x01, rc_offset=0)),
    ]

    winners = []
    for label, kwargs in variants:
        got = keccak(message, **kwargs)
        hit = got == GOLD["challenge"]
        if hit:
            winners.append(label)
        print(f"  {'*** MATCH ***' if hit else 'no match    '}  {label:34s} {got[:24]}")

    print()
    if winners:
        print(f"RESULT: {winners[0]}")
        print("       use that configuration for the solver")
    else:
        print("RESULT: no variant matched. The input format must differ.")
        print("       try: salt+challenge+nonce, salt+expire_at+nonce, etc.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
