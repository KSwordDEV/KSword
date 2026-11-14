"""Assemble the actual ordinary-driver context/event/DR code for safe tests."""
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[2]
output = Path(sys.argv[1]).resolve()
if not output.is_relative_to(root):
    raise ValueError('Output must remain in the repository')
source = root / 'KswordARKDriver/src/features/kernel_noattach'
parts = ['#include "kernel_event_shim.h"\n']
for name in ['kernel_noattach.h', 'kernel_noattach_context.c', 'kernel_noattach_breakpoints.c', 'kernel_noattach_events.c']:
    text = (source / name).read_text(encoding='utf-8-sig')
    text = re.sub(r'^\s*#include[^\n]*$', '', text, flags=re.M).replace('#pragma once', '')
    parts.append(f'\n#line 1 "{(source / name).as_posix()}"\n{text}\n')
parts.append('#include "kernel_event_tests.cpp"\n')
output.write_text(''.join(parts), encoding='utf-8')
