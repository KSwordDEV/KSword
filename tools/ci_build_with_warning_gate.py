"""Build once without /WX, then fail CI if the completed build emitted warnings.

Exit 0: build completed without warnings.
Exit 2: build completed and produced outputs, but warnings make CI fail.
Exit 1: the build itself failed.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from xml.sax.saxutils import quoteattr


WARNING = re.compile(r"\bwarning(?:\s+[A-Z]+\d+)?\s*:|^CMake Warning\b", re.IGNORECASE)
WX_OPTION = re.compile(r"^[/-]WX(?::\S+|-)?$", re.IGNORECASE)
WX_ENV_OPTION = re.compile(r"(?<!\S)[/-]WX(?::\S+|-)?(?=\s|$)", re.IGNORECASE)
IMPORT_OPTION = re.compile(r"^[/-](?:p|property):ForceImportBeforeCppTargets=(.*)$", re.IGNORECASE)
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PROPS = Path(__file__).resolve().with_name("ci_msvc_warnings.props")


def run(command: list[str], environment: dict[str, str]) -> tuple[int, bool]:
    try:
        process = subprocess.Popen(
            command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace", bufsize=1,
        )
    except OSError as error:
        print(f"Unable to start build: {error}", file=sys.stderr, flush=True)
        return 1, False

    saw_warning = False
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="", flush=True)
        saw_warning |= bool(WARNING.search(ANSI.sub("", line)))
    process.stdout.close()
    return process.wait(), saw_warning


def main(command: list[str]) -> int:
    if not command:
        print("Usage: ci_build_with_warning_gate.py <build command> [args...]", file=sys.stderr)
        return 1

    environment = os.environ.copy()
    environment["VSLANG"] = "1033"
    imports = []
    for variable in list(environment):
        if variable.casefold() == "forceimportbeforecpptargets":
            if environment[variable]:
                imports.append(environment[variable])
            del environment[variable]
    arguments = [command[0]]
    for argument in command[1:]:
        match = IMPORT_OPTION.match(argument)
        if match:
            imports.append(match.group(1).strip('"'))
        elif not WX_OPTION.match(argument):
            arguments.append(argument)
    for variable in ("CL", "_CL_", "LINK", "_LINK_"):
        if variable in environment:
            environment[variable] = WX_ENV_OPTION.sub("", environment[variable]).strip()

    # MSBuild project and per-file metadata must be changed before CL is run;
    # appending /WX- would itself generate command-line override warnings.
    with tempfile.TemporaryDirectory(prefix="ksword-ci-warnings-") as directory:
        chained = Path(directory) / "ci-warnings.props"
        imports = [path for path in imports if Path(path).resolve() != PROPS]
        imports.append(str(PROPS))
        chained.write_text(
            '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n'
            + "".join(f"  <Import Project={quoteattr(path)} />\n" for path in imports)
            + "</Project>\n", encoding="utf-8",
        )
        environment["ForceImportBeforeCppTargets"] = str(chained)
        status, saw_warning = run(arguments, environment)

    if status != 0:
        print("Build failed; outputs already produced can still be uploaded.", flush=True)
        return 1
    if saw_warning:
        print("Build completed with warnings. Outputs are retained; CI remains failed.", flush=True)
        return 2
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    raise SystemExit(main(sys.argv[1:]))
