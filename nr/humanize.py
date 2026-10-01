"""Humanization: the difference between "ran instantly, every time, in 3 ms" and
something that looks like a person using a computer.

Anti-cheat does not only look at what a tool does; it looks at how it does it.
Perfectly regular timing, operations that fire the instant a process appears,
temp files with fixed names, and identical byte patterns every launch are all
signatures of automation. This module is the small set of habits that break
those up, so nothing about NightRelay looks like a machine.

None of this hides what the tool *does* -- it removes the statistical tells a
scanner keys on. Applied at the points where the app touches Roblox.
"""

from __future__ import annotations

import os
import random
import secrets
import shutil
import time
from pathlib import Path

from . import config

# Deliberately not uniform: humans click, pause, and click again. The ranges are
# wide enough that the distribution is not a single spike a threshold can catch.
_SETTLE_MIN_MS = 700
_SETTLE_MAX_MS = 2600


def jitter(base_ms: int, spread: float = 0.35) -> int:
    """A wait near ``base_ms``, varying by ``spread`` in both directions."""
    low = int(base_ms * (1.0 - spread))
    high = int(base_ms * (1.0 + spread))
    return random.randint(max(0, low), max(1, high))


def settle(reason: str = "") -> None:
    """Pause before touching a freshly-started client.

    The client does heavy work for a few seconds after launch, and every
    injector that fires immediately shows up as a spike right there. A person
    waiting for the game to appear does not act in the same millisecond.
    """
    del reason  # kept for call-site clarity; the pause is what matters
    time.sleep(jitter(random.randint(_SETTLE_MIN_MS, _SETTLE_MAX_MS)) / 1000.0)


def breathe() -> None:
    """A short human-scale beat between operations."""
    time.sleep(random.uniform(0.12, 0.5))


def staged_delay(steps: int) -> list[float]:
    """A sequence of pauses for a multi-step action, so the steps are not spaced
    uniformly."""
    return [random.uniform(0.08, 0.35) for _ in range(steps)]


def temp_dir() -> Path:
    """A fresh, randomly-named scratch directory for this run.

    A fixed scratch path is a stable on-disk signature; a random one is not.
    Registered under the app's runtime dir so the existing shredder still
    cleans it up.
    """
    d = config.runtime_dir() / f"tmp-{secrets.token_hex(4)}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def strip_metadata(path: Path) -> None:
    """Remove the Mark-of-the-Web alternate stream from a staged artefact.

    Windows tags downloaded files with ``:Zone.Identifier``; a staged file that
    still carries it is trivially identifiable as newly-downloaded. Removing the
    stream is the point -- it must never touch the file's own content.
    """
    for stream in (":Zone.Identifier", ":Zone.Identifier:$DATA"):
        try:
            os.remove(str(path) + stream)
        except OSError:
            pass


def scrub(path: Path) -> None:
    """Overwrite then remove a staged artefact."""
    try:
        if path.is_file():
            size = path.stat().st_size
            if size:
                with open(path, "r+b", buffering=0) as fh:
                    fh.write(os.urandom(size))
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass


def random_name(prefix: str = "", suffix: str = "") -> str:
    """A non-obvious name, for windows or bridge identities that would otherwise
    be a constant string a scanner can match."""
    return f"{prefix}{secrets.token_hex(3)}{suffix}"


def ok() -> bool:
    """Whether humanization is enabled (it can be turned off for profiling)."""
    return bool(config.settings().get("stealth.humanize", True))
