"""Read exact-image Microsoft symbols and disassemble candidate exception entries.

This is an offline inspection tool. It never attaches to a target, writes a
kernel, or turns a symbol match into automatic runtime approval.
"""
from pathlib import Path
import ctypes as c
import json
import pefile
import capstone

root = Path(__file__).resolve().parents[2]
folder = root / '.codex-build-logs/noattach-r0'
image = folder / 'ntoskrnl.exe'
identity = json.loads((folder / 'pdb-identity.json').read_text())
pdb = root / '.deps/symbols' / identity['pdb'] / identity['key'] / identity['pdb']
assert pdb.is_file(), 'Resolve this exact PDB first; no cross-build fallback'
debugger = Path(r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64')
library = c.WinDLL(str(debugger / 'dbghelp.dll'), use_last_error=True, winmode=0x1100)
kernel = c.WinDLL('kernel32', use_last_error=True)
kernel.GetCurrentProcess.restype = c.c_void_p
process = kernel.GetCurrentProcess()

class Symbol(c.Structure):
    _fields_ = [('SizeOfStruct', c.c_uint32), ('TypeIndex', c.c_uint32), ('Reserved', c.c_uint64 * 2),
                ('Index', c.c_uint32), ('Size', c.c_uint32), ('ModBase', c.c_uint64), ('Flags', c.c_uint32),
                ('Value', c.c_uint64), ('Address', c.c_uint64), ('Register', c.c_uint32), ('Scope', c.c_uint32),
                ('Tag', c.c_uint32), ('NameLen', c.c_uint32), ('MaxNameLen', c.c_uint32), ('Name', c.c_char * 1)]

library.SymSetOptions.argtypes = [c.c_uint32]
library.SymInitializeW.argtypes = [c.c_void_p, c.c_wchar_p, c.c_int]
library.SymInitializeW.restype = c.c_int
library.SymLoadModuleExW.argtypes = [c.c_void_p,c.c_void_p,c.c_wchar_p,c.c_wchar_p,c.c_uint64,c.c_uint32,c.c_void_p,c.c_uint32]
library.SymLoadModuleExW.restype = c.c_uint64
library.SymFromName.argtypes = [c.c_void_p,c.c_char_p,c.POINTER(Symbol)]
library.SymFromName.restype = c.c_int
library.SymCleanup.argtypes = [c.c_void_p]
library.SymSetOptions(0x2 | 0x4 | 0x200 | 0x400)
assert library.SymInitializeW(process, str(pdb.parent), 0), c.get_last_error()
base = library.SymLoadModuleExW(process, None, str(image), 'nt', identity['imageBase'], identity['imageSize'], None, 0)
assert base, c.get_last_error()
pe = pefile.PE(str(image))
disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
disassembler.detail = True
results = {'identity': identity, 'symbols': {}}
try:
    names = ['KiDispatchException', 'KeContextFromKframes', 'KeContextToKframes', 'PsSuspendThread', 'PsResumeThread',
             'KdTrap', 'KdpStub', 'KdpTrap', 'KiDebugRoutine', 'KdpDebugRoutineSelect']
    for name in names:
        buffer = c.create_string_buffer(c.sizeof(Symbol) + 512)
        symbol = c.cast(buffer, c.POINTER(Symbol))
        symbol.contents.SizeOfStruct = c.sizeof(Symbol)
        symbol.contents.MaxNameLen = 512
        if not library.SymFromName(process, ('nt!' + name).encode(), symbol):
            results['symbols'][name] = {'error': c.get_last_error()}
            continue
        address = symbol.contents.Address
        rva = address - base
        instructions = []
        for instruction in disassembler.disasm(pe.get_data(rva, 160), address):
            instructions.append({'rva': instruction.address - base, 'bytes': instruction.bytes.hex(),
                                 'mnemonic': instruction.mnemonic, 'operands': instruction.op_str})
            if len(instructions) >= 24: break
        before = pe.get_data(max(0, rva - 32), 32).hex()
        item = {'rva': rva, 'size': symbol.contents.Size, 'before': before, 'instructions': instructions}
        results['symbols'][name] = item
        print(name, hex(rva), 'size', symbol.contents.Size)
        if name in names[:5]:
            for instruction in instructions[:12]: print(' ',hex(instruction['rva']),instruction['bytes'],instruction['mnemonic'],instruction['operands'])
    (folder / 'kernel-symbols.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
finally:
    library.SymCleanup(process)
