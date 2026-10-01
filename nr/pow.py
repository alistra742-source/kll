"""DeepSeek proof-of-work solver.

DeepSeek gates ``/api/v0/chat/completion`` behind a header carrying a solved
challenge. The task is a preimage search: find the nonce where

    DeepSeekHashV1(f"{salt}_{expire_at}_{nonce}") == challenge

with ``nonce`` in ``[0, difficulty]`` (144000 on every challenge seen so far).

``DeepSeekHashV1`` is *not* standard Keccak-256. Two deviations were established
empirically against a published golden vector -- salt ``6c3a962c828dd81d7d69``,
expire_at ``1780227446451``, nonce ``86022``, digest
``34d4c336676aa2e83c3308148e12ba8bc5e77ccb2fc12eeea1046e20c4c64eec``:

* **23 rounds, using round constants 1..23** rather than the standard 24 rounds
  starting at constant 0.
* **SHA-3 padding (0x06)** rather than the original Keccak padding (0x01).

Brute force is the only way to solve it. Scalar CPython manages ~600 hashes per
second -- two to four minutes per message. The state is therefore vectorised so
one numpy batch permutes thousands of nonces at once, and the search is split
across threads (numpy releases the GIL for these array ops), reaching roughly
100k hashes/second: about a second for the worst case.

``tools/pow_lab.py`` re-derives the variant from the golden vector; run it if
DeepSeek ever rotates the algorithm. ``tools/pow_bench.py`` is the layout
benchmark that chose the current memory layout.
"""

from __future__ import annotations

import os
import threading
import time

MASK64 = (1 << 64) - 1
RATE = 136  # bytes absorbed per permutation for a 256-bit digest

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

ROUNDS = 23
RC_OFFSET = 1
PAD = 0x06

BATCH = 16384
MAX_THREADS = 8

GOLDEN = {
    "salt": "6c3a962c828dd81d7d69",
    "expire_at": 1780227446451,
    "nonce": 86022,
    "challenge": "34d4c336676aa2e83c3308148e12ba8bc5e77ccb2fc12eeea1046e20c4c64eec",
}


# --------------------------------------------------------------------------- #
# Scalar reference
# --------------------------------------------------------------------------- #
def _rol(value: int, amount: int) -> int:
    amount &= 63
    if amount == 0:
        return value
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def _permute_scalar(state, rounds: int = ROUNDS, rc_offset: int = RC_OFFSET):
    for rnd in range(rounds):
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


def keccak_hash(message: bytes) -> str:
    """Scalar DeepSeekHashV1 digest. Slow; verification and fallback only."""
    data = bytearray(message)
    data.append(PAD)
    while len(data) % RATE != 0:
        data.append(0x00)
    data[-1] |= 0x80

    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(data), RATE):
        block = data[offset:offset + RATE]
        for i in range(RATE // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _permute_scalar(state)

    return b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4)).hex()


# --------------------------------------------------------------------------- #
# Vectorised cores
# --------------------------------------------------------------------------- #
_np = None
_np_tried = False


def _numpy():
    global _np, _np_tried
    if not _np_tried:
        _np_tried = True
        try:
            import numpy  # noqa: PLC0415

            _np = numpy
        except ImportError:
            _np = None
    return _np


def _rotl(v, amount: int):
    np = _np
    if amount == 0:
        return v
    return (v << np.uint64(amount)) | (v >> np.uint64(64 - amount))


def _permute_batch(state, rounds: int = ROUNDS, rc_offset: int = RC_OFFSET):
    """Permute a (5, 5, batch) uint64 buffer in place.

    Each lane is a contiguous column, so the whole rotation step runs on
    contiguous slices. Folding these into whole-array operations was measured to
    be about 2.5x slower (axis-0 rolls copy with a batch-sized stride), which is
    why this keeps the explicit lane loops.
    """
    np = _np
    for rnd in range(rounds):
        c = state[:, 0] ^ state[:, 1] ^ state[:, 2] ^ state[:, 3] ^ state[:, 4]
        cn = np.roll(c, -1, axis=0)
        d = np.roll(c, 1, axis=0) ^ (
            (cn << np.uint64(1)) | (cn >> np.uint64(63))
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

        state[0, 0] ^= np.uint64(RC[(rc_offset + rnd) % 24])
    return state


def _digest_batch(prefix: bytes, nonces, target: bytes):
    """Hash a batch of nonces; return the nonce whose digest equals `target`."""
    np = _numpy()
    count = len(nonces)
    width = len(str(int(nonces[-1])))
    ended = len(prefix) + width
    if ended > RATE - 1:
        raise ValueError("message no longer fits in one absorb block")

    buf = np.zeros((count, RATE), dtype=np.uint8)
    buf[:, :len(prefix)] = np.frombuffer(prefix, dtype=np.uint8)
    powers = 10 ** np.arange(width - 1, -1, -1, dtype=np.int64)
    digits = (np.asarray(nonces, dtype=np.int64)[:, None] // powers) % 10
    buf[:, len(prefix):ended] = (digits + 0x30).astype(np.uint8)
    buf[:, ended] = PAD
    buf[:, -1] |= 0x80

    lanes = buf.view(np.uint64).reshape(count, RATE // 8)

    state = np.zeros((5, 5, count), dtype=np.uint64)
    for i in range(RATE // 8):
        state[i % 5, i // 5] = lanes[:, i]

    _permute_batch(state)

    out = np.empty((count, 4), dtype=np.uint64)
    for i in range(4):
        out[:, i] = state[i % 5, i // 5]
    digest = out.view(np.uint8).reshape(count, 32)

    hits = np.flatnonzero(
        np.all(digest == np.frombuffer(target, dtype=np.uint8), axis=1)
    )
    if hits.size:
        return int(nonces[int(hits[0])])
    return None


# --------------------------------------------------------------------------- #
# Search
# --------------------------------------------------------------------------- #
def _digit_spans(lo: int, hi: int):
    """Split [lo, hi) so each span holds nonces of a single digit width."""
    for width in range(1, len(str(hi)) + 1):
        a = 0 if width == 1 else 10 ** (width - 1)
        b = 10 ** width
        start, stop = max(lo, a), min(hi, b)
        if start < stop:
            yield start, stop


def solve(
    challenge_hex: str,
    salt: str,
    expire_at: int,
    difficulty: int,
    timeout: float = 45.0,
    threads: int | None = None,
) -> int | None:
    """Find the nonce, or None if the range is exhausted or we run out of time."""
    np = _numpy()
    top = int(difficulty)
    prefix = f"{salt}_{expire_at}_".encode()
    target = bytes.fromhex(challenge_hex)

    if np is None:
        return _solve_scalar(prefix, target, top, timeout)

    workers = threads or max(1, min(MAX_THREADS, (os.cpu_count() or 2)))
    deadline = time.time() + timeout
    found: list[int] = []
    stop = threading.Event()
    lock = threading.Lock()

    def scan(lo: int, hi: int) -> None:
        for span_lo, span_hi in _digit_spans(lo, hi):
            for start in range(span_lo, span_hi, BATCH):
                if stop.is_set() or time.time() > deadline:
                    return
                batch = np.arange(start, min(start + BATCH, span_hi), dtype=np.int64)
                hit = _digest_batch(prefix, batch, target)
                if hit is not None:
                    with lock:
                        found.append(hit)
                    stop.set()
                    return

    step = max(1, (top + 1) // workers)
    ranges = []
    for lo in range(0, top + 1, step):
        ranges.append((lo, min(lo + step, top + 1)))
    if not ranges:
        return None

    if workers == 1 or len(ranges) == 1:
        scan(*ranges[0])
    else:
        pool = [
            threading.Thread(target=scan, args=rng, daemon=True) for rng in ranges
        ]
        for worker in pool:
            worker.start()
        for worker in pool:
            worker.join(timeout=max(1.0, deadline - time.time() + 2))

    return min(found) if found else None


def _solve_scalar(prefix: bytes, target: bytes, difficulty: int, timeout: float):
    deadline = time.time() + timeout
    want = target.hex()
    for nonce in range(difficulty + 1):
        if keccak_hash(prefix + str(nonce).encode()) == want:
            return nonce
        if nonce % 256 == 0 and time.time() > deadline:
            return None
    return None


def benchmark(batch: int = BATCH) -> dict:
    np = _numpy()
    if np is None:
        return {"available": False, "backend": "scalar"}
    prefix = b"6c3a962c828dd81d7d69_1780227446451_"
    nonces = np.arange(0, batch, dtype=np.int64)
    _digest_batch(prefix, nonces, bytes(32))
    started = time.time()
    _digest_batch(prefix, nonces, bytes(32))
    elapsed = max(time.time() - started, 1e-9)
    return {
        "available": True,
        "backend": "numpy",
        "batch": batch,
        "seconds": round(elapsed, 4),
        "per_second": int(batch / elapsed),
        "cpus": os.cpu_count(),
    }


def selftest() -> bool:
    """Check the scalar core against the published golden vector."""
    message = f"{GOLDEN['salt']}_{GOLDEN['expire_at']}_{GOLDEN['nonce']}".encode()
    return keccak_hash(message) == GOLDEN["challenge"]


def solve_golden() -> bool:
    """Full end-to-end check: the solver must recover the published nonce."""
    nonce = solve(
        GOLDEN["challenge"], GOLDEN["salt"], GOLDEN["expire_at"], 144000, timeout=60
    )
    return nonce == GOLDEN["nonce"]


if __name__ == "__main__":  # pragma: no cover - manual diagnostic
    print("scalar golden vector :", "PASS" if selftest() else "FAIL")
    print("throughput           :", benchmark())
    print("full solve (expect 86022):", solve_golden())
