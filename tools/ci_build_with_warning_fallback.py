"""Keep the strict build verdict while salvaging builds stopped by MSVC /WX.

Exit 0: the strict build succeeded.
Exit 2: the strict build failed on C2220, but a diagnostic-only /WX- build succeeded.
Exit 1: the strict build failed and no usable fallback build was obtained.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys


WARNING_AS_ERROR = re.compile(r"\berror\s+C2220\b", re.IGNORECASE)


def run(command: list[str], environment: dict[str, str]) -> tuple[int, bool]:
    try:
        process = subprocess.Popen(
            command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace", bufsize=1,
        )
    except OSError as error:
        print(f"Unable to start build: {error}", file=sys.stderr, flush=True)
        return 1, False

    saw_c2220 = False
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="", flush=True)
        saw_c2220 |= bool(WARNING_AS_ERROR.search(line))
    process.stdout.close()
    return process.wait(), saw_c2220


def main(command: list[str]) -> int:
    if not command:
        print("Usage: ci_build_with_warning_fallback.py <build command> [args...]", file=sys.stderr)
        return 1

    environment = os.environ.copy()
    strict_status, saw_c2220 = run(command, environment)
    if strict_status == 0:
        return 0
    if not saw_c2220:
        print("Strict build failed without MSVC C2220; no warning-only fallback will run.", flush=True)
        return 1

    previous_cl = environment.get("_CL_", "")
    if re.search(r"(?:^|\s)/link(?:\s|$)", previous_cl, re.IGNORECASE):
        print("Cannot safely append /WX- after /link in _CL_; skipping fallback.", file=sys.stderr)
        return 1
    environment["_CL_"] = (previous_cl + " /WX-").strip()
    print("Strict /WX build failed; attempting a /WX- build for diagnostic artifacts. CI remains failed.", flush=True)
    fallback_status, _ = run(command, environment)
    if fallback_status != 0:
        print("The diagnostic build also failed; only outputs actually produced can be uploaded.", flush=True)
        return 1
    print("Diagnostic build succeeded; the original strict failure is retained.", flush=True)
    return 2


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    raise SystemExit(main(sys.argv[1:]))
