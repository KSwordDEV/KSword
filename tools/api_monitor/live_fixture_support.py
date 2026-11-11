"""Isolated, owned x64 fixture process and read-only observer for the real Release Agent."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
ARCHITECTURE = os.environ.get("KSWORD_APIMON_ARCH", "x64")
AGENT = Path(os.environ.get("KSWORD_APIMON_AGENT", ROOT / f"Ksword5.1/x64/Release/APIMonitor_{ARCHITECTURE}.dll"))
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                              wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel.CreateFileW.restype = wintypes.HANDLE
kernel.PeekNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
kernel.PeekNamedPipe.restype = wintypes.BOOL
kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                           ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
kernel.ReadFile.restype = wintypes.BOOL
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
kernel.CloseHandle.restype = wintypes.BOOL
INVALID = ctypes.c_void_p(-1).value


class Packet(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("version", ctypes.c_uint32),
                ("pid", ctypes.c_uint32), ("tid", ctypes.c_uint32), ("timestamp", ctypes.c_uint64),
                ("category", ctypes.c_uint32), ("result", ctypes.c_int32),
                ("module", ctypes.c_wchar * 32), ("api", ctypes.c_wchar * 64),
                ("detail", ctypes.c_wchar * 320), ("result_kind", ctypes.c_uint32),
                ("kind", ctypes.c_uint32), ("api_id", ctypes.c_uint32),
                ("state", ctypes.c_uint32), ("hook_kind", ctypes.c_uint32),
                ("index", ctypes.c_uint32), ("count", ctypes.c_uint32),
                ("session", ctypes.c_uint64), ("operation", ctypes.c_uint64),
                ("revision", ctypes.c_uint64), ("address", ctypes.c_uint64),
                ("sha256", ctypes.c_char * 65)]


assert ctypes.sizeof(Packet) == 1000


def session_identity(text):
    value = 14695981039346656037
    encoded = text.encode("utf-16-le")
    for index in range(0, len(encoded), 2):
        value ^= int.from_bytes(encoded[index:index + 2], "little")
        value = value * 1099511628211 & 0xFFFFFFFFFFFFFFFF
    return value or 1


class LiveFixture:
    def __init__(self, source, configuration=None, *, agent=AGENT, compiler_environment=None, injector=None, link_arguments=()):
        self.agent = Path(agent)
        if not self.agent.exists():
            raise RuntimeError(f"build {ARCHITECTURE} Release Agent first")
        self.temporary = tempfile.TemporaryDirectory(prefix="ksword_apimon_live_")
        self.directory = Path(self.temporary.name)
        cpp = self.directory / "fixture.cpp"
        cpp.write_text(source, encoding="utf-8")
        compiler = shutil.which("cl", path=compiler_environment["PATH"]) if compiler_environment else "cl"
        subprocess.run([compiler, "/nologo", "/EHsc", "/std:c++17", "/utf-8", "/MT",
                        str(cpp), "/Fe:" + str(self.directory / "fixture.exe"),
                        "/Fo:" + str(self.directory / "fixture.obj"), "/link", "Ws2_32.lib", "Ole32.lib", *link_arguments], check=True,
                       env=compiler_environment)
        self.process = subprocess.Popen([str(self.directory / "fixture.exe"), str(self.agent)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.pid = int(self.process.stdout.readline().decode().strip())
        self.session_text = "fixture-" + uuid.uuid4().hex
        self.session = session_identity(self.session_text)
        session_directory = Path(os.environ.get("WINDIR", "C:/Windows")) / "Temp" / "KswordApiMon"
        session_directory.mkdir(exist_ok=True)
        self.config = session_directory / f"config_{self.pid}.ini"
        self.stop = session_directory / f"stop_{self.pid}.flag"
        assert not self.config.exists() and not self.stop.exists(), "unexpected PID collision"
        self.write_config(configuration or {})
        self.handle = None
        self.bytes = bytearray()
        self.events = []
        self.snapshots = []
        self.pending_snapshot = None
        try:
            if injector is None:
                self.command("L")
            else:
                injector(self.pid, self.agent)
            self.connect()
        except BaseException:
            if self.handle not in (None, INVALID):kernel.CloseHandle(self.handle)
            self.process.kill();self.process.wait(timeout=5)
            self.config.unlink(missing_ok=True);self.stop.unlink(missing_ok=True)
            self.temporary.cleanup()
            raise

    def connect(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            self.handle = kernel.CreateFileW(f"\\\\.\\pipe\\KswordApiMon_{self.pid}", 0x80000000,
                                             0, None, 3, 0, None)
            if self.handle != INVALID:
                break
            if self.process.poll() is not None:
                raise RuntimeError(f"fixture exited: {self.process.returncode}, {self.process.stderr.read()!r}")
            time.sleep(0.02)
        else:
            raise TimeoutError("Agent pipe did not appear")

    def restart(self, configuration):
        self.stop.write_text("stop")
        self.wait_for(lambda f: any(e.api == "HooksRemoved" for e in f.events), timeout=30)
        kernel.CloseHandle(self.handle)
        self.handle = None
        self.session_text = "fixture-" + uuid.uuid4().hex
        self.session = session_identity(self.session_text)
        self.bytes.clear()
        self.events.clear()
        self.snapshots.clear()
        self.pending_snapshot = None
        self.write_config(configuration)
        self.stop.unlink()
        self.connect()

    def write_config(self, overrides):
        values = {"pid": self.pid, "pipe_name": f"\\\\.\\pipe\\KswordApiMon_{self.pid}",
                  "session_id": self.session_text, "agent_dll_path": str(self.agent), "stop_flag_path": str(self.stop),
                  "enable_file": 1, "enable_registry": 0, "enable_network": 0,
                  "enable_process": 0, "enable_loader": 0, "enable_clipboard": 0,
                  "enable_raw_fallback": 0, "auto_inject_child": 0, "detail_limit": 319}
        values.update(overrides)
        self.config.write_text("[monitor]\r\n" + "".join(f"{key}={value}\r\n" for key, value in values.items()), encoding="utf-16")

    def command(self, command):
        self.process.stdin.write((command + "\n").encode())
        self.process.stdin.flush()

    def pump(self):
        available = wintypes.DWORD()
        if not kernel.PeekNamedPipe(self.handle, None, 0, None, ctypes.byref(available), None):
            return False
        if not available.value:
            return True
        chunk = ctypes.create_string_buffer(min(available.value, 64000))
        received = wintypes.DWORD()
        if not kernel.ReadFile(self.handle, chunk, len(chunk), ctypes.byref(received), None):
            return False
        self.bytes.extend(chunk.raw[:received.value])
        while len(self.bytes) >= ctypes.sizeof(Packet):
            packet = Packet.from_buffer_copy(self.bytes[:ctypes.sizeof(Packet)])
            del self.bytes[:ctypes.sizeof(Packet)]
            assert packet.size == ctypes.sizeof(Packet) and packet.version == 0x20261003
            assert packet.pid == self.pid and packet.session == self.session
            if packet.kind == 16:
                self.pending_snapshot = (packet.revision, packet.count, [])
            elif packet.kind == 17:
                assert self.pending_snapshot is not None
                revision, count, rows = self.pending_snapshot
                assert packet.revision == revision and packet.count == count and packet.index == len(rows)
                rows.append(packet)
            elif packet.kind == 18:
                revision, count, rows = self.pending_snapshot
                assert packet.revision == revision and packet.count == count and packet.index == count and len(rows) == count
                self.snapshots.append((revision, rows))
                self.pending_snapshot = None
            else:
                self.events.append(packet)
        return True

    def wait_for(self, condition, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            if condition(self):
                return
            if self.process.poll() is not None:
                raise RuntimeError(f"fixture exited: {self.process.returncode}, {self.process.stderr.read()!r}")
            time.sleep(0.01)
        last = [(event.api, event.detail) for event in self.events[-4:]]
        reasons=[(r.api,r.state,r.detail) for r in self.snapshots[-1][1] if r.detail] if self.snapshots else []
        raise TimeoutError(f"fixture condition not met; last events={last}; coverage={reasons[-12:]}; installed_reasons={[r for r in reasons if r[1] in (0,1)]}; revision={self.snapshots[-1][0] if self.snapshots else 0}; connected={self.pump()}")

    def close(self):
        try:
            if self.process.poll() is None:
                self.stop.write_text("stop")
                self.wait_for(lambda f: any(e.api == "HooksRemoved" for e in f.events), timeout=30)
        finally:
            if self.handle is not None and self.handle != INVALID:
                kernel.CloseHandle(self.handle)
            if self.process.poll() is None:
                self.command("Q")
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            self.config.unlink(missing_ok=True)
            self.stop.unlink(missing_ok=True)
            self.temporary.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
