"""Read-only ABI checks against the actual built CE and Titan DLLs.

Only offline schema discovery is called. No device is opened and no target or
Windows debug session is created. Titan's independent API must work with no
native Titan dependency installed beside the tested proxy.
"""
from pathlib import Path
import ctypes as c

root = Path(__file__).resolve().parents[2]

class Call(c.Structure):
    _fields_ = [("version", c.c_uint32), ("size", c.c_uint32), ("command", c.c_uint32), ("reserved", c.c_uint32),
                ("input", c.c_uint64), ("output", c.c_uint64), ("inputBytes", c.c_uint32), ("outputBytes", c.c_uint32),
                ("error", c.c_uint32), ("bytesReturned", c.c_uint32)]

class Layout(c.Structure):
    _fields_ = [(name, c.c_uint32) for name in ("version", "command", "inputBytes", "outputBytes", "protocol", "reserved")]

assert c.sizeof(Call) == 48 and c.sizeof(Layout) == 24
checks = 0
for relative in ("CheatEnginePlugin/x64/Release/KswordCheatEnginePlugin.dll", "TitanEnginePlugin/x64/Release/TitanEngine.dll"):
    dll = c.WinDLL(str(root / relative))
    invoke = dll.KSwordDebuggerCall
    invoke.argtypes = [c.POINTER(Call)]
    invoke.restype = c.c_uint32
    for command, protocol in [(33, 2), (34, 1)]:
        requested = c.c_uint32(command)
        actual = Layout()
        packet = Call(1, 48, 3, 0, c.addressof(requested), c.addressof(actual), 4, 24, 0, 0)
        assert invoke(c.byref(packet)) == 0 and packet.error == 0 and packet.bytesReturned == 24
        assert (actual.version, actual.command, actual.inputBytes, actual.outputBytes, actual.protocol) == (1, command, 232, 480, protocol)
        checks += 2
        packet.outputBytes = 23
        assert invoke(c.byref(packet)) == 122 and packet.bytesReturned == 0
        packet.outputBytes = 24; packet.version = 99
        assert invoke(c.byref(packet)) == 1306
        checks += 2
        print("PASS offline no-attach ABI:", relative, command, protocol)
print("NOATTACH_API_PASS checks=" + str(checks) + " (no device or debug attachment)")
