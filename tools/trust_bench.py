"""Prove the repo trust check separates real projects from distribution pages.

The fixtures are real repositories, read on 2026-09-29, with their state recorded
in the assertions below. They are ground truth rather than invented cases: the
first two are landing pages from the executor search results, the third is the
only genuinely written open-source executor in those results, and the fourth is
a control that must not be flagged.

Run this after touching nr/trust.py. It needs network access to GitHub's
read-only API; when that is rate limited it says so and skips rather than
failing, because a rate limit is not a bug in the auditor.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nr import trust  # noqa: E402

# (ref, expected verdict, expected maintenance, why this case exists)
CASES = [
    (
        "LavenderChancellor/Delta-Executor-PC",
        "dangerous",
        None,
        "top search hit, 52 stars, whole repo is a 53-byte print statement",
    ),
    (
        "JESS105-osso/Luna-Update-v3.6",
        "dangerous",
        None,
        "44 stars, ships only a landing page with an obfuscated redirector",
    ),
    (
        "nwvh/neverwhere",
        "looks-genuine",
        "archived",
        "real C# source, but archived since 2023 -- dead, not malicious",
    ),
    (
        "torvalds/linux",
        "looks-genuine",
        "active",
        "control: a real, maintained project must not be flagged",
    ),
]


def main() -> int:
    ok = True
    skipped = False

    for ref, want_verdict, want_maint, why in CASES:
        result = trust.audit(ref)

        if not result["ok"]:
            error = result["error"]
            if "rate limit" in error or "unreachable" in error:
                print(f"SKIP {ref}: {error}")
                skipped = True
                continue
            print(f"FAIL {ref}: audit itself failed -- {error}")
            ok = False
            continue

        verdict = result["verdict"]
        maint = result["maintenance"]
        flag = "ok  " if verdict == want_verdict else "FAIL"
        if verdict != want_verdict:
            ok = False
        print(f"{flag} {ref}")
        print(f"       want {want_verdict}, got {verdict} (score {result['score']}, {maint})")
        print(f"       {why}")
        for sig in result["signals"][:4]:
            print(f"         - [{sig['weight']}] {sig['text']}")

        # The manifest read used to fail silently: GitHub's /contents/ answers
        # with an array, which an earlier version coerced to {} -- so every
        # file-level signal vanished and landing pages scored as merely new.
        # Assert the read happened, or the verdict is not trustworthy.
        if not result.get("manifest_read"):
            print("       FAIL: the file list was never read -- verdict is not trustworthy")
            ok = False

        if want_maint is not None and maint != want_maint:
            print(f"       FAIL: maintenance want {want_maint}, got {maint}")
            ok = False

    # A landing page must never come back clean, and a control must never be
    # flagged -- the two failure directions are not symmetric. A false alarm on
    # a real project costs the user a good tool; a miss costs them the machine.
    print()
    if skipped:
        print("(some cases skipped -- github rate limited this run)")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
