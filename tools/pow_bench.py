"""Compare numpy Keccak layouts to find the fastest permutation.

The first vectorised attempt benchmarked at 69k hashes/sec using per-lane loops;
folding steps into whole-array ops on a (5,5,B) buffer was *slower* because the
axis-0 rolls copy with a huge stride. This compares a few candidate layouts and
a threaded variant so the choice is measured rather than assumed.
"""

from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nr.pow import RC, ROT, RATE  # noqa: E402

ROUNDS, RC_OFFSET, PAD = 23, 1, 0x06


def tables():
    """Per-source-lane rotation amounts and the pi destination map, both flat."""
    left = np.zeros(25, dtype=np.uint64)
    right = np.zeros(25, dtype=np.uint64)
    zero = np.zeros(25, dtype=bool)
    for x in range(5):
        for y in range(5):
            i = x * 5 + y
            amount = ROT[x][y]
            if amount == 0:
                zero[i] = True
            else:
                left[i] = amount
                right[i] = 64 - amount
    perm = np.zeros(25, dtype=np.int64)
    for x in range(5):
        for y in range(5):
            perm[y * 5 + (2 * x + 3 * y) % 5] = x * 5 + y
    # chi neighbours along x, precomputed as flat gathers
    next_x = np.array([((x + 1) % 5) * 5 + y for x in range(5) for y in range(5)])
    next2_x = np.array([((x + 2) % 5) * 5 + y for x in range(5) for y in range(5)])
    return left, right, zero, perm, next_x, next2_x


LEFT, RIGHT, ZERO, PERM, NX1, NX2 = tables()


# --------------------------------------------------------------------------- #
# layout A: (25, B) flat
# --------------------------------------------------------------------------- #
def permute_flat(state):
    """state: (25, B) uint64, in place."""
    for rnd in range(ROUNDS):
        # theta over (5, B) views
        c = state[0:5] ^ state[5:10] ^ state[10:15] ^ state[15:20] ^ state[20:25]
        d = np.roll(c, 1, axis=0) ^ np.roll(c, -1, axis=0)[[1, 2, 3, 4, 0]] if False else None
        # explicit: d[x] = c[x-1] ^ rotl(c[x+1], 1)
        cp = np.empty_like(c)
        cp[0] = c[4]
        cp[1:] = c[:4]
        cn = np.empty_like(c)
        cn[:4] = c[1:]
        cn[4] = c[0]
        d = cp ^ ((cn << np.uint64(1)) | (cn >> np.uint64(63)))
        state[:] = state ^ np.repeat(d, 5, axis=0)

        # rho + pi
        rot = (state << LEFT[:, None]) | (state >> RIGHT[:, None])
        if ZERO.any():
            rot[ZERO] = state[ZERO]
        state[:] = rot[PERM]

        # chi
        b = state
        state[:] = b ^ (~b[NX1] & b[NX2])

        state[0] ^= np.uint64(RC[(RC_OFFSET + rnd) % 24])
    return state


# --------------------------------------------------------------------------- #
# layout B: per-lane loops on (5,5,B) -- the original
# --------------------------------------------------------------------------- #
def permute_lanes(state):
    batch = state.shape[2]
    for rnd in range(ROUNDS):
        c = state[:, 0] ^ state[:, 1] ^ state[:, 2] ^ state[:, 3] ^ state[:, 4]
        d = np.roll(c, 1, axis=0) ^ (
            (np.roll(c, -1, axis=0) << np.uint64(1))
            | (np.roll(c, -1, axis=0) >> np.uint64(63))
        )
        state ^= d[:, None, :]
        b = np.empty_like(state)
        for x in range(5):
            for y in range(5):
                amount = ROT[x][y]
                src = state[x, y]
                b[y, (2 * x + 3 * y) % 5] = (
                    src if amount == 0
                    else (src << np.uint64(amount)) | (src >> np.uint64(64 - amount))
                )
        for x in range(5):
            x1 = b[(x + 1) % 5]
            x2 = b[(x + 2) % 5]
            col = b[x]
            for y in range(5):
                state[x, y] = col[y] ^ (~x1[y] & x2[y])
        state[0, 0] ^= np.uint64(RC[(RC_OFFSET + rnd) % 24])
    return state


def build_states(prefix: bytes, nonces, batch_first: bool):
    count = len(nonces)
    width = len(str(int(nonces[-1])))
    ended = len(prefix) + width
    buf = np.zeros((count, RATE), dtype=np.uint8)
    buf[:, : len(prefix)] = np.frombuffer(prefix, dtype=np.uint8)
    powers = 10 ** np.arange(width - 1, -1, -1, dtype=np.int64)
    digits = (np.asarray(nonces, dtype=np.int64)[:, None] // powers) % 10
    buf[:, len(prefix):ended] = (digits + 0x30).astype(np.uint8)
    buf[:, ended] = PAD
    buf[:, -1] |= 0x80
    lanes = buf.view(np.uint64).reshape(count, RATE // 8)

    if batch_first:
        state = np.zeros((25, count), dtype=np.uint64)
        for i in range(RATE // 8):
            state[(i % 5) * 5 + (i // 5)] = lanes[:, i]
    else:
        state = np.zeros((5, 5, count), dtype=np.uint64)
        for i in range(RATE // 8):
            state[i % 5, i // 5] = lanes[:, i]
    return state


def flatten_out(state, batch_first: bool):
    if batch_first:
        return state[[0, 5, 10, 15]].T.copy()
    return np.stack([state[0, 0], state[1, 0], state[2, 0], state[3, 0]], axis=1)


def time_it(fn, n=3):
    best = 1e9
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def main() -> int:
    prefix = b"6c3a962c828dd81d7d69_1780227446451_"
    print(f"cpus: {__import__('os').cpu_count()}\n")
    print(f"{'layout':>10} {'batch':>7} {'ms':>9} {'hashes/sec':>12}")
    print("-" * 42)

    for label, permute, batch_first in (
        ("flat(25,B)", permute_flat, True),
        ("lanes(5,5,B)", permute_lanes, False),
    ):
        for batch in (4096, 16384, 65536):
            nonces = np.arange(0, batch, dtype=np.int64)
            state = build_states(prefix, nonces, batch_first)

            def run():
                s = state.copy()
                permute(s)
                flatten_out(s, batch_first)

            secs = time_it(run, 3)
            print(f"{label:>10} {batch:>7} {secs*1000:>9.1f} {int(batch/secs):>12,}")

    print()
    print("=== threaded check: does numpy release the GIL here? ===")
    batch = 16384
    nonces = np.arange(0, batch, dtype=np.int64)
    state = build_states(prefix, nonces, False)
    secs = time_it(lambda: permute_lanes(state.copy()), 3)
    single = batch / secs
    print(f"1 thread : {int(single):>9,} hashes/sec")

    def worker(count):
        for _ in range(count):
            permute_lanes(build_states(prefix, nonces, False))

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(worker, [2, 2, 2, 2]))
    dt = time.perf_counter() - t0
    print(f"4 threads: {int(batch*8/dt):>9,} hashes/sec  ({dt:.2f}s for 8 batches)")
    print(f"           scaling x{((batch*8)/dt)/single:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
