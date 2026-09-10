"""Generate reviewed Windows 10/11 ABI signature families from exact PE/PDB fixtures.

This is an offline developer tool (pefile + capstone); neither Python nor PDBs
are needed by the agent. The selected function bodies retain field accesses,
argument flow, list direction, conditional branches and virtual call slots.
Only external rel32 / RIP displacements are masked, with typed reference checks.
Adding an ABI family requires reviewing its layout and ordering contract here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

import capstone as cs
import pefile

ROOT = Path(__file__).resolve().parents[2]
NODES = [
    ("FindWindow", "CWindowList", "FindWindowDataByHwnd"),
    ("DesktopList", "CWindowList", "GetWindowListForDesktopCanFail"),
    ("ZOrder", "CWindowList", "ZOrder"),
    ("UpdateScene", "CWindowList", "UpdateScene"),
    ("DestroyWindow", "CWindowList", "DestroyWindow"),
    ("SyncedData", "CWindowList", "GetSyncedWindowData"),
    ("Reevaluate", "CWindowList", "ReevaluateAutoParenting"),
    ("InsertTree", "CWindowList", "InsertIntoVisualTree"),
    ("PrecedingVisual", "CWindowList", "FindPrecedingVisibleWindowVisual"),
    ("InsertAfter", "CContainerVisual", "InsertChildAfter"),
    ("InsertRelative", "VisualCollection", "InsertRelative"),
    ("SendLink", "VisualCollection", "SendLinkVisualCommand"),
    ("ProxyInsert", "CContainerVisualProxy", "InsertChild"),
    ("WindowListCtor", "CWindowList", "CWindowList"),
    ("BandChange", "CWindowList", "ZorderBandChange"),
]
FIXTURES = [
    ("26100.9022", "cd922128568c413ac76aa5b373485f8be7b824e1acf65e1039f2aa6dbfd5d2fb"),
    ("26100.1", "8f6860b1d4d84af9eab60517eb9a55abcca306bf9650821096e8d46203553909"),
    ("26100.2454", "000f7eef3436e6abd350b1898a6e5570d084945ded5f7a8dc802aa8fb5e928e7"),
    ("26100.1591", "254d95d70300d86e831420d5635d27ebe3600eb684fd649639381d9dc45d268d"),
    ("26100.4061", "7c66d938817fde0326aeee0805fca90f01209624ef387dde9172cad55f15c645"),
    ("26100.4343", "194af585dbf9f35edaf15437edc4b50db2c72ee0b09f7342d25fa2227165b8b1"),
    ("26100.5074", "3ecec64daf3db07f58d726db74f6175e89a17581758eb0226c1be89d91e2da70"),
    ("26100.7705", "19462e0e4e9bfe34a0af27e6474913aad73503a76de41ab6b46516ac17b657ce"),
    ("26100.7920", "5e71c8007e61c26ffb92c2fec9475465e0550b80f0c08e817dd42feb37b049ab"),
    ("26100.9278", "3360935b0b39574e948757027066a1f1b8548815142f25527e0559ba4bd9e9af"),
    ("26100.3037", "a5a2d641a52e725278fb6f1f95660fc0b6b7690f17e1cfc66f6bc1bcc0cbe3fb"),
]


def symbol(symbols, cls, method):
    decorated = f"?{method}@{cls}@@" if method != cls else f"??0{cls}@@"
    matches = {s["rva"] for s in symbols if s["name"] == f"{cls}::{method}"
               or s["name"].startswith(decorated)}
    if len(matches) != 1:
        raise ValueError(f"non-unique public symbol: {cls}::{method}: {matches}")
    return matches.pop()


def global_symbol(symbols, plain, prefix):
    matches = {s["rva"] for s in symbols if s["name"] == plain or s["name"].startswith(prefix)}
    if len(matches) != 1:
        raise ValueError(f"non-unique global: {plain}: {matches}")
    return matches.pop()


def section_kind(pe, rva):
    s = pe.get_section_by_rva(rva)
    if s is None:
        raise ValueError(f"reference outside sections: {rva:#x}")
    return "Code" if s.Characteristics & 0x20000000 else "Writable" if s.Characteristics & 0x80000000 else "ReadOnly"


def fixture_patterns(directory, version, expected_hash):
    image = directory / version / "uDWM.dll"
    data = image.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError(f"unreviewed fixture: {image}")
    publics = image.parent / "publics.json"
    if version == "26100.9022" and not publics.exists():
        publics = ROOT / ".deps/symbols/uDWM.pdb/0B64C1D1F2048615FC50D28401BCBB931/publics.json"
    syms = json.loads(publics.read_text(encoding="utf-8"))
    pe = pefile.PE(data=data)
    fixed = pe.VS_FIXEDFILEINFO[0]
    if f"{fixed.FileVersionLS >> 16}.{fixed.FileVersionLS & 65535}" != version:
        raise ValueError(f"fixture version label disagrees with PE resource: {image}")
    rvas = {node: symbol(syms, cls, method) for node, cls, method in NODES}
    reverse = {rva: node for node, rva in rvas.items()}
    bindings = {
        global_symbol(syms, "CDesktopManager::s_pDesktopManagerInstance", "?s_pDesktopManagerInstance@CDesktopManager@@"): "DesktopManager",
        global_symbol(syms, "CDesktopManager::s_csDwmInstance", "?s_csDwmInstance@CDesktopManager@@"): "CriticalSection",
        global_symbol(syms, "CWindowList::`vftable'", "??_7CWindowList@@6B@"): "Vtable",
    }
    imports = {x.address - pe.OPTIONAL_HEADER.ImageBase: x.name.decode("ascii")
               for desc in pe.DIRECTORY_ENTRY_IMPORT for x in desc.imports if x.name}
    functions = {e.struct.BeginAddress for e in pe.DIRECTORY_ENTRY_EXCEPTION}
    def owner(begin, end, unwind, depth=0):
        if depth >= 16:
            raise ValueError("cyclic chained unwind record")
        header = pe.get_data(unwind, 4)
        if header[0] >> 3 & 4:
            parent = unwind + 4 + ((header[2] + 1) & ~1) * 2
            return owner(*struct.unpack("<III", pe.get_data(parent, 12)), depth + 1)
        return begin
    extents = {}
    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        f = entry.struct
        root = owner(f.BeginAddress, f.EndAddress, f.UnwindData)
        extents[root] = max(extents.get(root, 0), f.EndAddress)
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    decoder.detail = True
    patterns = []
    evidence = {}
    for node, _, _ in NODES:
        start = rvas[node]
        if start not in functions:
            raise ValueError(f"function lacks unwind entry: {node}")
        # Public symbols may omit adjacent thunks. PE chained unwind records
        # describe the actual function and its split blocks without guessing.
        end = extents[start]
        code = pe.get_data(start, end - start).rstrip(b"\xcc")
        if not 20 <= len(code) <= 8192:
            raise ValueError(f"unbounded function: {node}: {len(code)}")
        instructions = list(decoder.disasm(code, start))
        if sum(i.size for i in instructions) != len(code):
            raise ValueError(f"incomplete decoding: {node}")
        mask = bytearray(b"\xff" * len(code))
        refs = []
        evidence[node] = instructions
        for ins in instructions:
            for op in ins.operands:
                at = ins.address - start
                target = None
                if op.type == cs.x86.X86_OP_MEM and op.mem.base == cs.x86.X86_REG_RIP:
                    target = ins.address + ins.size + op.mem.disp
                    offset, size = ins.disp_offset, ins.disp_size
                elif (op.type == cs.x86.X86_OP_IMM and (ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP))
                      and not start <= op.imm < start + len(code)):
                    target = op.imm
                    offset, size = ins.imm_offset, ins.imm_size
                if target is None:
                    continue
                if size != 4:
                    raise ValueError(f"external non-rel32 branch: {node} {ins.address:#x}")
                mask[at + offset:at + offset + 4] = b"\0" * 4
                refs.append((at + offset, at + ins.size, section_kind(pe, target),
                             reverse.get(target, "Count"), bindings.get(target, "None"), imports.get(target)))
        # No untyped wildcard bytes: every masked displacement has a reference.
        patterns.append((node, code, bytes(mask), tuple(refs)))

    def require(node, hex_bytes):
        raw = bytes.fromhex(hex_bytes)
        if raw not in b"".join(i.bytes for i in evidence[node]):
            raise ValueError(f"ABI/direction evidence changed: {node}: {hex_bytes}")

    def require_any(node, *hex_bytes):
        body = b"".join(i.bytes for i in evidence[node])
        if not any(bytes.fromhex(value) in body for value in hex_bytes):
            raise ValueError(f"ABI/direction evidence changed: {node}: {hex_bytes}")

    # Reviewed CWindowData layout and ABI. These bytes remain unmasked at runtime.
    require("FindWindow", "48 39 58 28")
    # Earlier serviced images store through the just-returned RAX; RBX is its
    # saved alias. Both instruction sequences were inspected with exact PDBs.
    require_any("SyncedData", "48 89 7b 18", "48 89 78 18")
    require("SyncedData", "48 89 43 28")
    require("ZOrder", "48 8b 92 88 00 00 00")
    require("BandChange", "89 83 80 00 00 00")
    require("PrecedingVisual", "48 8b 47 08")
    require("PrecedingVisual", "48 8b 88 b8 01 00 00")
    require("ZOrder", "4c 89 01 48 89 41 08 49 89 48 08 48 89 08")
    require("InsertAfter", "41 b1 01")
    require("ProxyInsert", "45 8b c2 48 8b 80 80 00 00 00")
    edges = {(p[0], r[3]) for p in patterns for r in p[3] if r[3] != "Count"}
    for edge in [("ZOrder", "DesktopList"), ("ZOrder", "SyncedData"), ("DestroyWindow", "SyncedData"),
                 ("ZOrder", "Reevaluate"), ("Reevaluate", "InsertTree"), ("InsertTree", "PrecedingVisual"),
                 ("InsertTree", "InsertAfter"), ("InsertAfter", "InsertRelative"),
                 ("InsertRelative", "SendLink"), ("SendLink", "ProxyInsert")]:
        if edge not in edges:
            raise ValueError(f"ordering call graph changed: {edge}")
    print(f"REVIEWED_FIXTURE={version} FUNCTIONS={len(patterns)} REFERENCES={sum(len(p[3]) for p in patterns)}")
    return patterns


def cpp_bytes(data):
    return "\n".join("    " + ",".join(f"0x{b:02x}" for b in data[i:i+24]) + "," for i in range(0, len(data), 24))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=ROOT / ".deps/dwm-zorder-corpus")
    parser.add_argument("--output", type=Path, default=ROOT / "DwmZOrderAgent/RuntimeSignatures.h")
    args = parser.parse_args()
    patterns = []
    for version, sha in FIXTURES:
        for pattern in fixture_patterns(args.corpus, version, sha):
            # Relocation bytes are irrelevant and zeroed for deduplication.
            node, code, mask, refs = pattern
            normalized = bytes(b & m for b, m in zip(code, mask))
            item = (node, normalized, mask, refs)
            if item not in patterns:
                patterns.append(item)
    out = ["// Generated by tools/dwm_zorder/generate_signature_model.py; do not edit bytes by hand.",
           "// Reviewed 24H2 x64 ABI; build, timestamp, PDB identity and RVAs are not match gates.",
           '#pragma once\n#include "RuntimeResolver.h"\nnamespace ks::dwm_order::runtime::signatures\n{',
           "inline constexpr Layout kLayout{0x18, 0x28, 0x80, 0x88, 0x1b8};"]
    for index, (node, code, mask, refs) in enumerate(patterns):
        out += [f"// {node}", f"inline constexpr unsigned char kBytes{index}[] = {{\n{cpp_bytes(code)}\n}};",
                f"inline constexpr unsigned char kMask{index}[] = {{\n{cpp_bytes(mask)}\n}};",
                f"inline constexpr Reference kRefs{index}[] = {{"]
        for at, nxt, section, dest, binding, imp in refs:
            out.append(f'    {{{at}, {nxt}, Section::{section}, Node::{dest}, Binding::{binding}, {json.dumps(imp) if imp else "nullptr"}}},')
        out.append("};")
    out.append("inline constexpr Pattern kPatterns[] = {")
    for index, (node, code, _, refs) in enumerate(patterns):
        out.append(f"    {{Node::{node}, kBytes{index}, kMask{index}, {len(code)}, kRefs{index}, {len(refs)}}},")
    out += ["};", "}", ""]
    args.output.write_text("\n".join(out), encoding="utf-8")
    print(f"UNIQUE_SIGNATURE_VARIANTS={len(patterns)} OUTPUT={args.output}")
    from generate_win10_signatures import generate
    generate(args.corpus, args.output.with_name("RuntimeWin10Signatures.h"))


if __name__ == "__main__":
    main()
