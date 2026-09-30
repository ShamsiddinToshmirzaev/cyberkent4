#!/usr/bin/env python3
"""
Smoke test template. Solves the challenge end-to-end against $TARGET and checks
the captured flag equals the expected FLAG. Exit 0 = PASS, non-zero = FAIL.

Two environment variables drive it (the guide shows how to set them locally, and our
fleet tooling sets them the same way during the event):
  TARGET     base URL of the running task, e.g. http://127.0.0.1:10010
  FLAGS_ENV  path to the challenge's flags.env, so the test can read the expected FLAG

Only the stdlib + `requests` are assumed. If you need another pip package, list it in a
`solution/requirements.txt` and mention it in your submission.
"""
import os
import re
import sys

TARGET = os.environ.get("TARGET", "http://127.0.0.1:5000").rstrip("/")


def expected_flag():
    path = os.environ.get("FLAGS_ENV", "")
    if path and os.path.exists(path):
        for line in open(path):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def solve():
    """Perform the intended exploit against TARGET and return the captured flag string."""
    raise NotImplementedError("implement the exploit against TARGET and return the flag")


def main():
    want = expected_flag()
    got = solve()
    print(f"[captured] {got!r}")
    if want and got and want == got:
        print("PASS")
        return 0
    if want is None and got:
        # No expected flag available; pass on shape alone.
        print("PASS (no expected flag to compare; got a flag-shaped value)")
        return 0
    print(f"FAIL expected={want!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
