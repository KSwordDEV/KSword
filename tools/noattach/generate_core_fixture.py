"""Compile production no-attach control/exit code against a deterministic VMCS shim.

Only platform includes are removed. The functions under test are the actual
driver sources, rather than another implementation of their state machine.
This fixture does not execute VMX or establish hardware acceptance.
"""
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[2]
output = Path(sys.argv[1]).resolve()
if not output.is_relative_to(root):
    raise ValueError("Fixture output must stay inside the repository")
module = root / "KswordARKDriver/src/features/hvm"
parts = ['#include "kernel_shim.h"\n']
for filename in ("hvm_noattach.h", "hvm_noattach_breakpoints.c", "hvm_noattach_commands.c", "hvm_noattach_boundary.c", "hvm_noattach_exit.c"):
    path = module / filename
    text = path.read_text(encoding="utf-8-sig")
    text = re.sub(r"^\s*#include[^\n]*$", "", text, flags=re.M)
    text = text.replace("#pragma once", "")
    parts.append(f'\n#line 1 "{path.as_posix()}"\n{text}\n')
parts.append('#include "core_tests.cpp"\n')
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text("".join(parts), encoding="utf-8")
print("NOATTACH_PRODUCTION_FIXTURE=" + str(output))
