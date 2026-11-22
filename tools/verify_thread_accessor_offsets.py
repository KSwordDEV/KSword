"""在磁盘内核的四个只读 getter 中独立定位字段，再与精确 PDB 样本比较。"""

import argparse
import hashlib
import json
from pathlib import Path
import re

import capstone
from capstone import x86_const as x86
import pefile


# 只识别有公开 getter 且返回值能独立对照的字段；不猜测 KernelStack。
ACCESSORS = {
    "PsGetThreadProcess": ("_KTHREAD.Process", x86.X86_REG_RCX),
    "IoGetInitialStack": ("_KTHREAD.InitialStack", x86.X86_REG_RAX),
    "PsGetCurrentThreadStackBase": ("_KTHREAD.StackBase", x86.X86_REG_RAX),
    "PsGetCurrentThreadStackLimit": ("_KTHREAD.StackLimit", x86.X86_REG_RAX),
}


def match_load(instruction, base, segment=0):
    """识别 mov rax,[segment:base+disp]；不匹配返回 None，零位移不作错误判定。"""
    ops = instruction.operands  # 解码器返回的操作数列表。
    if instruction.id != x86.X86_INS_MOV or len(ops) != 2:
        return None
    dest, source = ops  # 只允许 RAX 和一个 64 位内存源操作数。
    if dest.type != x86.X86_OP_REG or dest.reg != x86.X86_REG_RAX or source.type != x86.X86_OP_MEM:
        return None
    address = source.mem  # 显式查段、基址、变址，避免把不同寻址模式当直接读取。
    if source.size != 8 or (address.segment, address.base, address.index) != (segment, base, 0):
        return None
    return address.disp


def locate(decoder, image, export, base):
    """从单个 x64 PE 导出定位无分支 getter；返回字段位移，未知形态返回 None。"""
    if export is None or export.forwarder:
        return None
    section = image.get_section_by_rva(export.address)  # 仅从可执行节读取指令。
    if section is None or not section.Characteristics & 0x20000000:
        return None
    start = export.address - section.VirtualAddress  # 当前导出在节中的偏移。
    length = min(32, section.SizeOfRawData - start)  # 不跨节，不跟随其他函数。
    if length <= 0:
        return None
    instructions = list(decoder.disasm(image.get_data(export.address, length), export.address, 3))
    if base == x86.X86_REG_RAX:
        if not instructions or match_load(instructions[0], 0, x86.X86_REG_GS) != 0x188:
            return None
        instructions = instructions[1:]
    if len(instructions) < 2 or instructions[1].bytes != b"\xc3":
        return None
    return match_load(instructions[0], base)


def verify_profile(decoder, root, row, profile):
    """核验报告中的单个 PE；返回不匹配或无法定位的数量。"""
    version = row["corpusVersion"]  # 样本记录的完整磁盘 PE 版本。
    if not re.fullmatch(r"\d+(?:\.\d+){3}", version):
        raise ValueError("Invalid PE version in the report")
    relative = Path(row["path"])  # 仅接受报告中的标准语料库对象路径。
    digest = relative.parent.name  # 父目录即磁盘 PE 内容的 SHA256。
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or relative != Path(
        "pe-store", "amd64", "ntoskrnl.exe", f"ntoskrnl.exe.{version}", digest, "ntoskrnl.exe"
    ):
        raise ValueError("Invalid corpus PE path or SHA256")
    path = root / relative  # 只读指定 corpus，不按相邻版本猜布局。
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            raise ValueError(f"PE SHA256 mismatch for {version}")

    failed = 0  # 单项未知和不匹配均不能当成功。
    with pefile.PE(str(path), fast_load=True) as image:
        if image.FILE_HEADER.Machine != 0x8664:
            raise ValueError(f"Non-x64 PE for {version}")
        image.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        exports = {symbol.name: symbol for symbol in image.DIRECTORY_ENTRY_EXPORT.symbols}  # 同一 PE 的实际导出。
        for name, (field, base) in ACCESSORS.items():
            candidate = locate(decoder, image, exports.get(name.encode("ascii")), base)  # 指令独立定位。
            member = profile["members"].get(field, {})  # 从 PDB 提取的独立对照元数据。
            expected = member.get("offsetBytes") if member.get("sizeBytes") == 8 else None
            type_size = profile["typeSizes"]["_KTHREAD"]  # 确保读数不出对象范围。
            if candidate is None or not 0 <= candidate <= type_size - 8:
                status = "unresolved"
            else:
                status = "matched" if candidate == expected else "mismatch"
            failed += status != "matched"
            print(f"{version} {field}: accessor={candidate!r} pdb={expected!r} {status}")
    return failed


def main():
    """接收正式 PE/PDB 样本索引和语料库根，只输出离线核验结果。"""
    parser = argparse.ArgumentParser(description=__doc__)  # 两种显式固定来源。
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True, help="selected.json from the corpus exporter")
    options = parser.parse_args()  # 操作员选择的只读源。
    report = json.loads(options.report.read_text(encoding="utf-8-sig"))  # 离线符号样本。
    if not report.get("scanFinished") or report.get("fullCorpusScope") or not report.get("images"):
        parser.error("A completed selected.json with at least one PE is required")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)  # x64 操作数解码器。
    decoder.detail = True
    failed = 0  # 缺少精确配对也计为失败，而不是悄悄跳过。
    for row in report["images"]:
        profile = report["byPdbKey"].get(row.get("key"), {})  # 与 PE 的 GUID 和 DBI Age 配对。
        if not profile.get("exactPair") or "typeSizes" not in profile:
            print(f"{row['corpusVersion']}: exact typed profile unavailable")
            failed += 1
        else:
            failed += verify_profile(decoder, options.corpus_root, row, profile)
    return int(failed != 0)


if __name__ == "__main__":
    raise SystemExit(main())
