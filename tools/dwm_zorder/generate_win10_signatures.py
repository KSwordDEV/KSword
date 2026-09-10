"""Reviewed Windows 10 19041 x64 family, including every hot/cold function fragment.

Used by generate_signature_model.py. This generator never loads a system DLL.
The primary Win10 ZOrder body contains the list/visual insertion operation; its
inlined VisualCollection code sends indexed insert/reorder commands through the
CVisualProxy channel (rather than the Windows 11 AddVisual proxy).
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import capstone as cs
import pefile

FIXTURES = [
    ("19041.546", "c50f0da088d6190133cf3ac058b5bd944ebc1bbf897a69bf2249185bf90c9516"),
    ("19041.6157", "112bec755a113da2c65893a915a8e6e75b522ec15ef0e0633111ea608dc87731"),
    ("19041.6456", "24cf447ec886c3b0711f1a346e8c3347b847f04f45b6655f659411eb31f9fb37"),
]
NODES = [
    ("FindWindow", "CWindowList", "FindWindowDataByHwnd"),
    ("DesktopList", "CWindowList", "GetWindowListForDesktop"),
    ("ZOrder", "CWindowList", "ZOrder"),
    ("UpdateScene", "CWindowList", "UpdateScene"),
    ("DestroyWindow", "CWindowList", "DestroyWindow"),
    ("SyncedData", "CWindowList", "GetSyncedWindowData"),
    ("PrecedingVisual", "CWindowList", "FindPrecedingVisibleWindowVisual"),
    ("InsertRelative", "VisualCollection", "InsertRelative"),
    ("ProxyInsert", "CVisualProxy", "InsertChildAt"),
    ("WindowListCtor", "CWindowList", "CWindowList"),
    ("BandChange", "CWindowList", "ZorderBandChange"),
]


def fixture_patterns(directory: Path, version: str, expected_hash: str):
    from generate_signature_model import symbol, global_symbol, section_kind
    path = directory / version / "uDWM.dll"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError(f"unreviewed Win10 fixture: {path}")
    pe = pefile.PE(data=raw)
    fixed = pe.VS_FIXEDFILEINFO[0]
    if f"{fixed.FileVersionLS >> 16}.{fixed.FileVersionLS & 65535}" != version:
        raise ValueError(f"fixture version label disagrees with PE resource: {path}")
    syms = json.loads((path.parent / "publics.json").read_text(encoding="utf-8"))
    rvas = {node: symbol(syms, cls, method) for node, cls, method in NODES}
    reverse = {rva: node for node, rva in rvas.items()}
    bindings = {
        global_symbol(syms, "CDesktopManager::s_pDesktopManagerInstance", "?s_pDesktopManagerInstance@CDesktopManager@@"): "DesktopManager",
        global_symbol(syms, "CDesktopManager::s_csDwmInstance", "?s_csDwmInstance@CDesktopManager@@"): "CriticalSection",
        global_symbol(syms, "CWindowList::`vftable'", "??_7CWindowList@@6B@"): "Vtable",
    }
    imports = {x.address - pe.OPTIONAL_HEADER.ImageBase: x.name.decode("ascii")
               for desc in pe.DIRECTORY_ENTRY_IMPORT for x in desc.imports if x.name}
    entries = {e.struct.BeginAddress: e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION}

    def owner(begin, end, unwind, depth=0):
        if depth >= 16 or begin not in entries:
            raise ValueError("invalid chained unwind owner")
        record = entries[begin]
        if (record.EndAddress, record.UnwindData) != (end, unwind):
            raise ValueError("chained unwind record differs from the exception table")
        header = pe.get_data(unwind, 4)
        if header[0] >> 3 & 4:
            return owner(*struct.unpack("<III", pe.get_data(unwind + 4 + ((header[2] + 1) & ~1) * 2, 12)), depth + 1)
        return begin

    ranges = {}
    for f in entries.values():
        ranges.setdefault(owner(f.BeginAddress, f.EndAddress, f.UnwindData), []).append((f.BeginAddress, f.EndAddress))
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    decoder.detail = True
    patterns, evidence, edges = [], {}, set()
    for node, _, _ in NODES:
        start = rvas[node]
        parts = sorted(ranges[start], key=lambda p: (p[0] != start, p[0]))
        if not 1 <= len(parts) <= 64:
            raise ValueError(f"unbounded fragment count: {node}")
        fragments, bodies = [], []
        for index, (begin, end) in enumerate(parts):
            code = pe.get_data(begin, end - begin).rstrip(b"\xcc")
            if not 1 <= len(code) <= 8192:
                raise ValueError(f"unbounded fragment: {node}:{index}")
            instructions = list(decoder.disasm(code, begin))
            if sum(i.size for i in instructions) != len(code):
                raise ValueError(f"incomplete fragment decoding: {node}:{index}")
            mask, refs = bytearray(b"\xff" * len(code)), []
            bodies.append(code)
            for ins in instructions:
                for op in ins.operands:
                    target = None
                    if op.type == cs.x86.X86_OP_MEM and op.mem.base == cs.x86.X86_REG_RIP:
                        target = ins.address + ins.size + op.mem.disp
                        at, width = ins.disp_offset, ins.disp_size
                    elif op.type == cs.x86.X86_OP_IMM and (ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP)):
                        if begin <= op.imm < begin + len(code):
                            continue
                        target, at, width = op.imm, ins.imm_offset, ins.imm_size
                    if target is None:
                        continue
                    if width not in (1, 4):
                        raise ValueError("unsupported relative operand")
                    local = next((i for i, (lo, hi) in enumerate(parts) if lo <= target < hi), 65535)
                    local_offset = target - parts[local][0] if local != 65535 else 0
                    role = reverse.get(target, "Count") if local == 65535 else "Count"
                    refs.append((ins.address - begin + at, ins.address - begin + ins.size,
                                 section_kind(pe, target), role, bindings.get(target, "None"), imports.get(target),
                                 local, local_offset, width))
                    if role != "Count":
                        edges.add((node, role))
                    offset = ins.address - begin + at
                    mask[offset:offset + width] = bytes(width)
            fragments.append((bytes(b & m for b, m in zip(code, mask)), bytes(mask), tuple(refs)))
        evidence[node] = bodies
        patterns.append((node, tuple(fragments)))

    def require(node, *choices):
        if not any(bytes.fromhex(h) in body for h in choices for body in evidence[node]):
            raise ValueError(f"Win10 ABI/direction evidence changed: {node}: {choices}")

    require("FindWindow", "48 39 78 28") # HWND; Flink traversal.
    require("FindWindow", "48 8d 71 08") # Same desktop map as the list query.
    require("FindWindow", "48 8d 48 50") # Same list head within each desktop entry.
    require("DesktopList", "48 83 c1 08")
    require("DesktopList", "48 83 c0 50")
    require("SyncedData", "48 89 73 18") # IDwmWindow.
    require("SyncedData", "48 89 43 28") # HWND.
    # DestroyWindow inlines GetSyncedWindowData on these Win10 builds.
    require("DestroyWindow", "48 8b 40 08")
    require("DestroyWindow", "48 8b 4b 18")
    require("DestroyWindow", "48 89 01 48 89 48 08")
    require("BandChange", "89 47 70")
    require("PrecedingVisual", "48 8b 52 78")
    require("PrecedingVisual", "48 8b 7f 08") # Blink, toward the lower visual.
    require("PrecedingVisual", "48 8b 8f 80 01 00 00")
    require("ZOrder", "48 8b 42 78")
    require("ZOrder", "48 89 08 48 89 58 08 48 89 41 08 48 89 03",
            "48 89 08 48 89 70 08 48 89 41 08 48 89 06") # RBX/RSI lower anchor; insert AFTER.
    require("ZOrder", "41 b1 01 c6 44 24 20 01") # InsertRelative(after=true, send=true).
    require("ZOrder", "48 8b 5b 08", "48 8b 76 08") # Invisible reference falls back along Blink.
    require("InsertRelative", "41 0f b6 d9") # Preserve insert-after boolean in EBX.
    require("InsertRelative", "03 df") # Index = reference index + insert-after.
    require("InsertRelative", "4d 8d 04 d9") # Store child at computed index.
    require("InsertRelative", "44 8b cb") # Same index passed to channel.
    require("InsertRelative", "48 8b 80 c0 01 00 00") # InsertChildAt channel slot.
    require("InsertRelative", "48 8b 80 c8 01 00 00") # Move existing child to index.
    require("ProxyInsert", "45 8b d0")
    require("ProxyInsert", "45 8b ca")
    require("ProxyInsert", "48 8b 80 c0 01 00 00")
    for edge in [("ZOrder", "SyncedData"),
                 ("ZOrder", "InsertRelative"), ("PrecedingVisual", "DesktopList")]:
        if edge not in edges:
            raise ValueError(f"Win10 ordering call graph changed: {edge}")
    print(f"REVIEWED_WIN10_FIXTURE={version} FUNCTIONS={len(patterns)} FRAGMENTS={sum(len(p[1]) for p in patterns)}")
    return patterns


def generate(corpus: Path, output: Path):
    from generate_signature_model import cpp_bytes
    patterns = []
    for version, sha in FIXTURES:
        for pattern in fixture_patterns(corpus, version, sha):
            if pattern not in patterns:
                patterns.append(pattern)
    out = ['// Generated by tools/dwm_zorder/generate_signature_model.py; do not edit bytes by hand.',
           '// Reviewed Windows 10 19041 x64 family; every owned hot/cold fragment is validated.',
           '#pragma once\n#include "RuntimeResolver.h"\nnamespace ks::dwm_order::runtime::win10_signatures\n{',
           'inline constexpr Layout kLayout{0x18, 0x28, 0x70, 0x78, 0x180};']
    for i, (node, fragments) in enumerate(patterns):
        out.append(f'// {node}')
        for j, (code, mask, refs) in enumerate(fragments):
            name = f'{i}_{j}'
            out.extend([f'inline constexpr unsigned char kBytes{name}[] = {{\n{cpp_bytes(code)}\n}};',
                        f'inline constexpr unsigned char kMask{name}[] = {{\n{cpp_bytes(mask)}\n}};'])
            if refs:
                out.append(f'inline constexpr Reference kRefs{name}[] = {{')
                for at, nxt, section, dest, binding, imp, local, off, width in refs:
                    out.append(f'    {{{at}, {nxt}, Section::{section}, Node::{dest}, Binding::{binding}, {json.dumps(imp) if imp else "nullptr"}, {local}, {off}, {width}}},')
                out.append('};')
        if len(fragments) > 1:
            out.append(f'inline constexpr Fragment kFragments{i}[] = {{')
            for j, (code, _, refs) in enumerate(fragments[1:], 1):
                out.append(f'    {{kBytes{i}_{j}, kMask{i}_{j}, {len(code)}, {"kRefs"+str(i)+"_"+str(j) if refs else "nullptr"}, {len(refs)}}},')
            out.append('};')
    out.append('inline constexpr Pattern kPatterns[] = {')
    for i, (node, fragments) in enumerate(patterns):
        code, _, refs = fragments[0]
        out.append(f'    {{Node::{node}, kBytes{i}_0, kMask{i}_0, {len(code)}, {"kRefs"+str(i)+"_0" if refs else "nullptr"}, {len(refs)}, {"kFragments"+str(i) if len(fragments)>1 else "nullptr"}, {len(fragments)-1}}},')
    out.extend(['};', '}', ''])
    output.write_text('\n'.join(out), encoding='utf-8')
    print(f'WIN10_SIGNATURE_VARIANTS={len(patterns)} OUTPUT={output}')
