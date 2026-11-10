"""Replay the actual KeSetTimerEx encoding instructions without kernel execution.

Only the prefix ending at the KTIMER.Dpc store is executed in Unicorn. Calls
and CR8 accesses are mocked; no copied kernel instruction executes on the host.
Synthetic keys replace image data. This checks the production decoder against
the PE implementation rather than another handwritten encoding formula.
"""

import argparse
from pathlib import Path
import struct

import capstone
import pefile
import unicorn
from unicorn import x86_const as x86


def replay(image: Path, destination: Path) -> None:
    pe = pefile.PE(str(image))
    if pe.FILE_HEADER.Machine != 0x8664:
        raise ValueError("An amd64 kernel image is required")
    symbol = next(s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b"KeSetTimerEx")
    base = pe.OPTIONAL_HEADER.ImageBase
    size = (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
    engine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    engine.mem_map(base, size)
    engine.mem_write(base, pe.get_memory_mapped_image())
    stack = 0x10000000
    timer = 0x20000000
    gs = 0x30000000
    engine.mem_map(stack, 0x10000)
    engine.mem_map(timer, 0x10000)
    engine.mem_map(gs, 0x10000)
    engine.reg_write(x86.UC_X86_REG_GS_BASE, gs)
    engine.mem_write(gs + 0x20, struct.pack("<Q", gs + 0x1000))
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    start = base + symbol.address
    # Restrict execution to the export's real PE function range.
    function = next(e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION
                    if e.struct.BeginAddress <= symbol.address < e.struct.EndAddress)
    end = base + function.EndAddress
    key_addresses = []
    for instruction in decoder.disasm(pe.get_data(symbol.address, min(128, end - start)), start):
        if instruction.mnemonic.startswith("mov") and len(instruction.operands) == 2:
            target = instruction.operands[1]
            if target.type == capstone.CS_OP_MEM and target.size == 8 and target.mem.base == capstone.x86.X86_REG_RIP:
                key_addresses.append(instruction.address + instruction.size + target.mem.disp)
    if len(key_addresses) != 2 or key_addresses[0] == key_addresses[1]:
        raise ValueError("This replay requires two RIP-relative 64-bit key loads in the export prefix")
    # Independent synthetic boot parameters, including a nonzero rotation.
    for address, value in zip(key_addresses, (0x123456789ABCDE17, 0xFEDCBA9876543210)):
        engine.mem_write(address, struct.pack("<Q", value))
    samples = []
    current_timer = timer
    stored = False

    def on_code(uc, address, length, _):
        if not start <= address < end:
            raise ValueError(f"Replay left the bounded export at {address:#x}")
        instruction = next(decoder.disasm(bytes(uc.mem_read(address, length)), address))
        if instruction.mnemonic == "call":
            # Timer unlink/checking helpers run after the encoding computation.
            # The first helper prepares a valid long-due probe and must report success.
            uc.reg_write(x86.UC_X86_REG_RAX, 1)
            uc.reg_write(x86.UC_X86_REG_RIP, address + length)
        elif "cr8" in instruction.op_str:
            if instruction.operands[0].type == capstone.CS_OP_REG and instruction.operands[0].reg != capstone.x86.X86_REG_CR8:
                register_name = instruction.reg_name(instruction.operands[0].reg).upper()
                uc.reg_write(getattr(x86, "UC_X86_REG_" + register_name), 0)
            uc.reg_write(x86.UC_X86_REG_RIP, address + length)

    def on_write(uc, _, address, length, value, __):
        nonlocal stored
        if address == current_timer + 0x30 and length == 8:
            samples.append((current_timer, value & ((1 << 64) - 1), current_dpc))
            stored = True
            uc.emu_stop()

    engine.hook_add(unicorn.UC_HOOK_CODE, on_code)
    engine.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write)
    for current_timer in (timer, timer + 0xC0):
        for current_dpc in (0, 0xFFFF800020000040, 0xFFFF800020000080):
            engine.mem_write(current_timer, bytes(0x40))
            engine.reg_write(x86.UC_X86_REG_RSP, stack + 0x8008)
            engine.reg_write(x86.UC_X86_REG_RCX, current_timer)
            engine.reg_write(x86.UC_X86_REG_RDX, (-6000000000) & ((1 << 64) - 1))
            engine.reg_write(x86.UC_X86_REG_R8, 0)
            engine.reg_write(x86.UC_X86_REG_R9, current_dpc)
            stored = False
            engine.emu_start(start, end, count=256)
            if not stored:
                raise ValueError("Bounded replay did not reach the KTIMER.Dpc store")
    destination.write_bytes(b"".join(struct.pack("<QQQ", *sample) for sample in samples))
    version = pe.VS_FIXEDFILEINFO[0]
    print(f"Kernel PE replay: version={version.FileVersionMS >> 16}.{version.FileVersionMS & 65535}."
          f"{version.FileVersionLS >> 16}.{version.FileVersionLS & 65535} "
          f"KeSetTimerEx={symbol.address:#x} samples={len(samples)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    replay(args.kernel_image, args.output)
