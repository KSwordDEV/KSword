"""Read-only checks of the exact uDWM image addressed by RuntimeProfile.h.

Uses only Python's standard library. This never opens a process or loads a DLL.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import struct
import uuid


class Image:
    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not a PE image")
        self.nt = struct.unpack_from("<I", data, 0x3C)[0]
        if data[self.nt:self.nt + 4] != b"PE\0\0":
            raise ValueError("invalid PE signature")
        self.machine, count, self.timestamp = struct.unpack_from("<HHI", data, self.nt + 4)
        opt_size = struct.unpack_from("<H", data, self.nt + 20)[0]
        opt = self.nt + 24
        if self.machine != 0x8664 or struct.unpack_from("<H", data, opt)[0] != 0x20B:
            raise ValueError("expected an AMD64 PE32+ image")
        self.base = struct.unpack_from("<Q", data, opt + 24)[0]
        self.image_size = struct.unpack_from("<I", data, opt + 56)[0]
        self.sections = []
        for index in range(count):
            at = opt + opt_size + index * 40
            virtual_size, va, raw_size, raw = struct.unpack_from("<IIII", data, at + 8)
            self.sections.append((va, virtual_size, raw, raw_size))
        self.codeview = []
        self.guard_targets = {}
        self.guard_flags = 0
        self.guard_metadata = {}
        load_rva, load_size = struct.unpack_from("<II", data, opt + 112 + 10 * 8)
        if load_rva and load_size >= 148:
            config = self.read(load_rva, 148)
            table, count, self.guard_flags = struct.unpack_from("<QQI", config, 128)
            stride = 4 + ((self.guard_flags >> 28) & 15)
            if count > len(data) // stride:
                raise ValueError("invalid GFIDS table size")
            for index in range(count):
                at = table - self.base + index * stride
                entry = self.read(at, stride)
                rva = struct.unpack_from("<I", entry)[0]
                self.guard_targets[rva] = entry[4] if stride > 4 else 0
                if stride > 4:
                    self.guard_metadata[rva] = self.offset(at + 4, 1)
        debug_rva, debug_size = struct.unpack_from("<II", data, opt + 112 + 6 * 8)
        if debug_rva:
            for index in range(debug_size // 28):
                entry = self.read(debug_rva + index * 28, 28)
                kind, size, rva = struct.unpack_from("<III", entry, 12)
                if kind == 2 and size >= 24:
                    cv = self.read(rva, size)
                    if cv[:4] == b"RSDS":
                        self.codeview.append((rva, cv[4:20], struct.unpack_from("<I", cv, 20)[0]))

    def offset(self, rva: int, size: int) -> int:
        for va, _, raw, raw_size in self.sections:
            if va <= rva and rva + size <= va + raw_size:
                offset = raw + rva - va
                if offset + size <= len(self.data):
                    return offset
        raise ValueError(f"RVA is outside file-backed sections: {rva:#x}")

    def read(self, rva: int, size: int) -> bytes:
        offset = self.offset(rva, size)
        return self.data[offset:offset + size]


def load_profile(path: Path) -> tuple[dict[str, int], bytes, list[tuple[str, bytes]], list[tuple[str, bytes]]]:
    source = path.read_text(encoding="utf-8-sig")
    constants = {name: int(value, 0) for name, value in
                 re.findall(r"\b(k\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;", source)}
    guid_source = re.search(r"kPdbGuid\{(.*?)\};", source, re.S)
    if not guid_source:
        raise ValueError("missing profile GUID")
    guid_parts = [int(value, 0) for value in re.findall(r"0x[0-9a-fA-F]+|\d+", guid_source[1])]
    guid = struct.pack("<IHH8B", *guid_parts)
    def read_signatures(name: str) -> list[tuple[str, bytes]]:
        block = re.search(r"\b" + name + r"\[\]\s*=\s*\{(.*?)\n\s*\};", source, re.S)
        if not block:
            raise ValueError(f"missing signature block: {name}")
        return [(key, bytes(int(value.strip(), 0) for value in values.split(",")))
                for key, values in re.findall(r"\{(k\w+),\s*\{([^}]+)\}\}", block[1])]
    signatures = read_signatures("kSignatures")
    order_semantics = read_signatures("kOrderSemantics")
    if len(signatures) != 5:
        raise ValueError("expected five ABI entry signatures")
    if len(order_semantics) != 4:
        raise ValueError("expected four native ordering semantics signatures")
    return constants, guid, signatures, order_semantics


def verify(image: Image, profile: tuple) -> list[str]:
    constants, guid, signatures, order_semantics = profile
    errors = []
    if image.timestamp != constants["kTimestamp"]:
        errors.append("PE timestamp differs")
    if image.image_size != constants["kImageSize"]:
        errors.append("PE image size differs")
    if not any(g == guid and age == constants["kPdbAge"] for _, g, age in image.codeview):
        errors.append("PDB GUID/Age differs")
    for name, expected in signatures:
        if image.read(constants[name], len(expected)) != expected:
            errors.append(f"function entry differs: {name}")
    for name, expected in order_semantics:
        if image.read(constants[name], len(expected)) != expected:
            errors.append(f"native ordering semantics differ: {name}")
    for slot, function in [("kDestroySlot", "kDestroyWindow"), ("kZOrderSlot", "kZOrder"), ("kUpdateSlot", "kUpdateScene")]:
        address = struct.unpack("<Q", image.read(constants["kVtable"] + constants[slot] * 8, 8))[0]
        if address != image.base + constants[function]:
            errors.append(f"vtable entry differs: {slot}")
        if image.guard_targets.get(constants[function], 1) & 1:
            errors.append(f"virtual method is not a valid CFG target: {function}")
    for function in ("kFindWindow", "kDesktopList"):
        if constants[function] in image.guard_targets:
            errors.append(f"direct-only helper CFG metadata differs: {function}")
    if image.guard_flags & 0x500 != 0x500:
        errors.append("CFG instrumentation/table flags are missing")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, default=Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/udwm.dll")
    parser.add_argument("--profile", type=Path, default=root / "DwmZOrderAgent/RuntimeProfile.h")
    parser.add_argument("--self-test", action="store_true", help="also reject corrupted identity, code, vtable and CFG fixtures")
    args = parser.parse_args()
    image = Image(args.image.read_bytes())
    profile = load_profile(args.profile)
    errors = verify(image, profile)
    for error in errors:
        print("MISMATCH=" + error)
    if errors:
        return 1
    if args.self_test:
        constants, _, signatures, order_semantics = profile
        offsets = [image.nt + 8, image.offset(image.codeview[0][0], 24) + 4,
                   image.offset(constants[signatures[0][0]], 16),
                   image.offset(constants["kVtable"] + constants["kUpdateSlot"] * 8, 8),
                   image.guard_metadata[constants["kZOrder"]]]
        offsets.extend(image.offset(constants[name], len(expected)) for name, expected in order_semantics)
        for offset in offsets:
            data = bytearray(image.data)
            data[offset] ^= 1
            if not verify(Image(bytes(data)), profile):
                raise AssertionError("a corrupted fixture was accepted")
        print(f"NEGATIVE_FIXTURES_REJECTED={len(offsets)}")
    print("PROFILE_MATCH=True")
    print("PDB_GUID=" + str(uuid.UUID(bytes_le=profile[1])))
    print("FUNCTION_SIGNATURES_MATCHED=5")
    print("ORDER_SEMANTICS_MATCHED=4")
    print("VTABLE_SLOTS_MATCHED=3")
    print("CFG_DIRECT_ONLY_QUERIES=2")
    print("CFG_VALID_VIRTUAL_TARGETS=3")
    print("IMAGE_SHA256=" + hashlib.sha256(image.data).hexdigest())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        raise SystemExit(str(error)) from error
