"""API 转移参数源端正式验证：真实 Release Agent + 自有父子夹具。

父进程加载正式 Agent DLL（LoadLibrary，配置/管道方式复用 live_fixture_support 的
既有约定），对自有子进程执行 WriteProcessMemory / NtWriteVirtualMemory /
CreateRemoteThread / NtCreateThreadEx 的成功、失败、null 输出与部分写用例，
并核对 1000 字节包、AAIP1 结构字段、原返回/LastError/NTSTATUS、QPC、输入句柄、
definitionSHA、短 detailLimit 不截断结构字段、普通事件不带 marker。
不注入其他用户进程；不操作 GUI；不加载驱动。

用法：python -B run_api_transfer_live.py x64|x86
"""
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]
RELEASE = ROOT / "Ksword5.1" / "x64" / "Release"
LOG_DIR = ROOT / ".codex-build-logs" / "api-transfer-producer"
MARKER = 0x49505631
AAIP_PREFIX = "AAIP1|"
AAIP_VALUE_COUNT = 14
AAIP_TEXT_LENGTH = len(AAIP_PREFIX) + AAIP_VALUE_COUNT * 16 + AAIP_VALUE_COUNT - 1  # 243
FLAG_ACTOR = 1 << 0
FLAG_TARGET = 1 << 1
FLAG_THREAD = 1 << 2
FLAG_COMPLETED = 1 << 3
FLAG_ADDRESS = 1 << 4
FLAG_START = 1 << 5
FLAG_STABLE = 1 << 6
STATUS_PARTIAL_COPY = 0x8000000D
STATUS_ACCESS_DENIED = 0xC0000005
STATUS_INVALID_HANDLE = 0xC0000008
INJECTION_APIS = ("WriteProcessMemory", "NtWriteVirtualMemory", "CreateRemoteThread",
                  "NtCreateThreadEx")
EXPECTED_PER_API = {"WriteProcessMemory": 5, "NtWriteVirtualMemory": 5,
                    "CreateRemoteThread": 2, "NtCreateThreadEx": 2}
kernel = ctypes.WinDLL("kernel32", use_last_error=True)


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

for name, args, restype in [
    ("CreateFileW", [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                     wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE),
    ("PeekNamedPipe", [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                       ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p], wintypes.BOOL),
    ("ReadFile", [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                  ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p], wintypes.BOOL),
    ("CloseHandle", [wintypes.HANDLE], wintypes.BOOL),
    ("OpenProcess", [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
    ("GetProcessTimes", [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
                         ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
                         ctypes.POINTER(wintypes.FILETIME)], wintypes.BOOL),
    ("CreateToolhelp32Snapshot", [wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE),
    ("Thread32First", [wintypes.HANDLE, ctypes.c_void_p], wintypes.BOOL),
    ("Thread32Next", [wintypes.HANDLE, ctypes.c_void_p], wintypes.BOOL),
]:
    function = getattr(kernel, name)
    function.argtypes = args
    function.restype = restype

INVALID = ctypes.c_void_p(-1).value
QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 3


def module_base_size(pid, name_suffix):
    """在目标进程内枚举模块，返回 (base, size) 或 None（用于核对 Hook 安装地址）。"""
    handle = kernel.OpenProcess(0x0400 | PROCESS_VM_READ, False, pid)  # QUERY_INFORMATION|VM_READ
    if not handle or handle == INVALID:
        return None
    needed = wintypes.DWORD()
    result = None
    if kernel.K32EnumProcessModulesEx(handle, None, 0, ctypes.byref(needed), LIST_MODULES_ALL):
        count = needed.value // ctypes.sizeof(wintypes.HMODULE)
        array = (wintypes.HMODULE * count)()
        if kernel.K32EnumProcessModulesEx(handle, array, ctypes.sizeof(array),
                                          ctypes.byref(needed), LIST_MODULES_ALL):
            name_buffer = ctypes.create_unicode_buffer(512)
            for module in array:
                kernel.K32GetModuleFileNameExW(handle, module, name_buffer, 512)
                if name_buffer.value.lower().endswith(name_suffix):
                    info = MODULEINFO()
                    if kernel.K32GetModuleInformation(handle, module, ctypes.byref(info),
                                                      ctypes.sizeof(info)):
                        result = (ctypes.cast(module, ctypes.c_void_p).value, info.SizeOfImage)
                    break
    kernel.CloseHandle(handle)
    return result


def remote_read(handle, address, size):
    buffer = (ctypes.c_ubyte * size)()
    got = ctypes.c_size_t()
    if not kernel.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size,
                                    ctypes.byref(got)):
        return None
    return bytes(buffer)


for name, args, restype in [
    ("ReadProcessMemory", [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                           ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)], wintypes.BOOL),
    ("K32EnumProcessModulesEx", [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), wintypes.DWORD], wintypes.BOOL),
    ("K32GetModuleFileNameExW", [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR,
                                 wintypes.DWORD], wintypes.DWORD),
    ("K32GetModuleInformation", [wintypes.HANDLE, wintypes.HMODULE, ctypes.c_void_p,
                                 wintypes.DWORD], wintypes.BOOL),
]:
    function = getattr(kernel, name)
    function.argtypes = args
    function.restype = restype


def export_rva_from_file(dll_path, export_name):
    """解析 PE 文件导出表，返回指定导出的 RVA（跨架构核对安装地址用）。"""
    import struct
    data = open(dll_path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    section_count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    directory = optional + (96 if magic == 0x10B else 112)
    export_rva, _ = struct.unpack_from("<II", data, directory)
    section_table = optional + optional_size
    sections = []
    for index in range(section_count):
        base = section_table + index * 40
        virtual_size = struct.unpack_from("<I", data, base + 8)[0]
        virtual_address = struct.unpack_from("<I", data, base + 12)[0]
        raw_size = struct.unpack_from("<I", data, base + 16)[0]
        raw_pointer = struct.unpack_from("<I", data, base + 20)[0]
        sections.append((virtual_address, max(virtual_size, raw_size), raw_pointer))

    def to_offset(value):
        for virtual_address, span, raw_pointer in sections:
            if virtual_address <= value < virtual_address + span:
                return value - virtual_address + raw_pointer
        return None

    export_offset = to_offset(export_rva)
    name_count = struct.unpack_from("<I", data, export_offset + 24)[0]
    names_rva = struct.unpack_from("<I", data, export_offset + 32)[0]
    functions_rva = struct.unpack_from("<I", data, export_offset + 28)[0]
    ordinals_rva = struct.unpack_from("<I", data, export_offset + 36)[0]
    names_offset = to_offset(names_rva)
    functions_offset = to_offset(functions_rva)
    ordinals_offset = to_offset(ordinals_rva)
    for index in range(name_count):
        name_offset = to_offset(struct.unpack_from("<I", data, names_offset + index * 4)[0])
        name = data[name_offset:data.index(b"\x00", name_offset)].decode("ascii")
        if name == export_name:
            ordinal = struct.unpack_from("<H", data, ordinals_offset + index * 2)[0]
            return struct.unpack_from("<I", data, functions_offset + ordinal * 4)[0]
    return None


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wintypes.DWORD),
                ("EntryPoint", ctypes.c_void_p)]


def session_identity(text):
    value = 14695981039346656037
    encoded = text.encode("utf-16-le")
    for index in range(0, len(encoded), 2):
        value ^= int.from_bytes(encoded[index:index + 2], "little")
        value = value * 1099511628211 & 0xFFFFFFFFFFFFFFFF
    return value or 1


def signed(value):
    return value - 0x100000000 if value >= 0x80000000 else value


def process_creation_file_time(pid):
    handle = kernel.OpenProcess(QUERY_LIMITED_INFORMATION, False, pid)
    if not handle or handle == INVALID:
        return None
    created, exited, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
    ok = kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                ctypes.byref(kernel_time), ctypes.byref(user_time))
    kernel.CloseHandle(handle)
    if not ok:
        return None
    return (created.dwHighDateTime << 32) | created.dwLowDateTime


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD), ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", wintypes.DWORD)]


def child_thread_ids(pid):
    snapshot = kernel.CreateToolhelp32Snapshot(4, 0)  # TH32CS_SNAPTHREAD
    if snapshot == INVALID:
        return set()
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    result = set()
    if kernel.Thread32First(snapshot, ctypes.byref(entry)):
        while True:
            if entry.th32OwnerProcessID == pid:
                result.add(entry.th32ThreadID)
            if not kernel.Thread32Next(snapshot, ctypes.byref(entry)):
                break
    kernel.CloseHandle(snapshot)
    return result


def decode_aaip(text):
    """按 shared/evidence/ApiInjectionFields.h 的固定格式解码，返回 dict 或 None。"""
    if len(text) != AAIP_TEXT_LENGTH or not text.startswith(AAIP_PREFIX):
        return None
    raw = text[len(AAIP_PREFIX):].split("|")
    if len(raw) != AAIP_VALUE_COUNT or any(len(item) != 16 for item in raw):
        return None
    if any(not set(item) <= set("0123456789abcdef") for item in raw):
        return None
    values = [int(item, 16) for item in raw]
    fields = ("operation", "flags", "actorCreationFileTime", "targetPid", "targetCreationFileTime",
              "targetTid", "targetThreadCreationFileTime", "address", "requestedBytes",
              "completedBytes", "startAddress", "enterQpc", "returnQpc", "inputHandle")
    result = dict(zip(fields, values))
    if result["operation"] not in (1, 2) or result["flags"] & ~0x7F:
        return None
    if result["targetPid"] > 0xFFFFFFFF or result["targetTid"] > 0xFFFFFFFF:
        return None
    if not result["enterQpc"] or result["returnQpc"] < result["enterQpc"]:
        return None
    return result


class LiveRun:
    def __init__(self, architecture):
        self.architecture = architecture
        suffix = "64" if architecture == "x64" else "32"
        self.fixture = RELEASE / f"ApiTransferValidationFixture{suffix}.exe"
        self.agent = RELEASE / f"APIMonitor_{architecture}.dll"
        assert self.fixture.exists() and self.agent.exists()
        self.expected_sha = hashlib.sha256(
            (ROOT / "APIMonitor_x64" / "api_monitor_definitions.json").read_bytes()).hexdigest()
        self.session_text = "apitransfer-" + uuid.uuid4().hex
        self.session = session_identity(self.session_text)
        self.process = subprocess.Popen(
            [str(self.fixture), "parent"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        header = self.process.stdout.readline().decode().strip()
        assert header.startswith("PID "), f"unexpected fixture header: {header!r}"
        self.pid = int(header.split()[1])
        self.session_directory = Path(os.environ.get("WINDIR", "C:/Windows")) / "Temp" / "KswordApiMon"
        self.session_directory.mkdir(exist_ok=True)
        self.config = self.session_directory / f"config_{self.pid}.ini"
        self.stop = self.session_directory / f"stop_{self.pid}.flag"
        assert not self.config.exists() and not self.stop.exists(), "unexpected PID collision"
        self.handle = None
        self.bytes = bytearray()
        self.events = []
        self.rows = []
        self.pending = None
        self.consumed = {}
        self.failures = []
        self.checks = 0

    def check(self, condition, name):
        self.checks += 1
        if not condition:
            self.failures.append(name)
            print(f"FAIL {name}")
        else:
            print(f"PASS {name}")
        return bool(condition)

    def write_config(self):
        values = {"pid": self.pid, "pipe_name": f"\\\\.\\pipe\\KswordApiMon_{self.pid}",
                  "session_id": self.session_text, "agent_dll_path": str(self.agent),
                  "stop_flag_path": str(self.stop), "enable_file": 0, "enable_registry": 0,
                  "enable_network": 0, "enable_process": 0, "enable_memory": 1,
                  "enable_thread": 1, "enable_service": 0, "enable_security": 0,
                  "enable_crypto": 0, "enable_com": 0, "enable_window": 0, "enable_gui": 0,
                  "enable_loader": 0, "enable_clipboard": 0, "enable_raw_fallback": 0,
                  "auto_inject_child": 0, "detail_limit": 64}
        self.config.write_text("[monitor]\r\n" + "".join(
            f"{key}={value}\r\n" for key, value in values.items()), encoding="utf-16")

    def command(self, command):
        self.current_command = command
        self.process.stdin.write((command + "\n").encode())
        self.process.stdin.flush()

    def response(self, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"fixture exited: {self.process.returncode}")
            line = self.process.stdout.readline()
            if line:
                return line.decode().strip()
        raise TimeoutError("fixture response timeout")

    def connect(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            self.handle = kernel.CreateFileW(f"\\\\.\\pipe\\KswordApiMon_{self.pid}", 0x80000000,
                                             0, None, 3, 0, None)
            if self.handle != INVALID:
                return
            if self.process.poll() is not None:
                raise RuntimeError(f"fixture exited: {self.process.returncode}")
            time.sleep(0.02)
        raise TimeoutError("Agent pipe did not appear")

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
            assert packet.size == 1000 and packet.version == 0x20261003, "packet header"
            assert packet.pid == self.pid and packet.session == self.session, "packet identity"
            assert packet.sha256.decode().rstrip("\x00") == self.expected_sha, "definition SHA"
            if packet.kind == 16:
                self.pending = [packet.revision, packet.count, []]
            elif packet.kind == 17:
                assert self.pending is not None and packet.revision == self.pending[0]
                assert packet.index == len(self.pending[2])
                self.pending[2].append(packet)
            elif packet.kind == 18:
                assert self.pending is not None and packet.index == packet.count
                assert len(self.pending[2]) == packet.count
                self.rows = self.pending[2]
                self.pending = None
            else:
                self.events.append(packet)
        return True

    def wait_event(self, api, module, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            matches = [e for e in self.events if e.kind == 0 and e.api == api and e.module == module]
            if len(matches) > self.consumed.get((api, module), 0):
                self.consumed[(api, module)] = len(matches)
                return matches[-1]
            if self.process.poll() is not None:
                raise RuntimeError(f"fixture exited: {self.process.returncode}")
            time.sleep(0.01)
        raise TimeoutError(f"event {module}.{api} not received; tail={[(e.api, e.result) for e in self.events[-6:]]}")

    def set_baseline(self):
        """子进程已就绪后记录注入 API 的既有事件数（spawn 期间的事件不算本次命令）。"""
        self.pump()
        self.baseline_event_index = len(self.events)
        for api in list(INJECTION_APIS) + ["CreateRemoteThreadEx"]:
            matches = [e for e in self.events
                       if e.kind == 0 and e.api == api]
            self.consumed[(api, "KernelBase")] = max(
                self.consumed.get((api, "KernelBase"), 0),
                len([e for e in matches if e.module == "KernelBase"]))
            self.consumed[(api, "ntdll")] = max(
                self.consumed.get((api, "ntdll"), 0),
                len([e for e in matches if e.module == "ntdll"]))

    def wait_event_any(self, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            found = [event for event in self.events if predicate(event)]
            if found:
                return found[-1]
            if self.process.poll() is not None:
                raise RuntimeError(f"fixture exited: {self.process.returncode}")
            time.sleep(0.01)
        raise TimeoutError("event not received")

    def wait_coverage(self, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            if self.rows:
                return
            if self.process.poll() is not None:
                raise RuntimeError(f"fixture exited: {self.process.returncode}")
            time.sleep(0.05)
        raise TimeoutError("coverage snapshot not received")

    def close(self):
        try:
            if self.handle not in (None, INVALID):
                kernel.CloseHandle(self.handle)
        finally:
            if self.process.poll() is None:
                self.command("Q")
                try:
                    self.process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            self.config.unlink(missing_ok=True)
            self.stop.unlink(missing_ok=True)

    def expect_fields(self, event, *, operation, address=None, requested=None, completed=None,
                      completed_present=True, target_expected, thread_expected,
                      input_handle=None, expect_result, expect_return):
        fields = decode_aaip(event.detail)
        if not self.check(fields is not None, f"{event.api}: aaip_decodes"):
            return None
        self.check(len(event.detail) == AAIP_TEXT_LENGTH and event.state == MARKER,
                   f"{event.api}: marker_and_full_text_under_short_detail_limit")
        self.check(fields["operation"] == operation, f"{event.api}: operation")
        if operation == 1:
            self.check(bool(fields["flags"] & FLAG_ADDRESS) and fields["address"] == address
                       and fields["requestedBytes"] == requested,
                       f"{event.api}: address_and_requested")
            if completed_present:
                self.check(bool(fields["flags"] & FLAG_COMPLETED)
                           and fields["completedBytes"] == completed,
                           f"{event.api}: completed_length")
            else:
                self.check(not fields["flags"] & FLAG_COMPLETED and fields["completedBytes"] == 0,
                           f"{event.api}: no_completed_length")
        else:
            self.check(bool(fields["flags"] & FLAG_START) and fields["startAddress"] == address,
                       f"{event.api}: start_address")
            self.check(not fields["flags"] & FLAG_ADDRESS and fields["requestedBytes"] == 0,
                       f"{event.api}: no_write_fields")
        self.check(bool(fields["flags"] & FLAG_ACTOR) and fields["actorCreationFileTime"] > 0,
                   f"{event.api}: actor_identity")
        if target_expected:
            self.check(bool(fields["flags"] & FLAG_TARGET)
                       and fields["targetPid"] == self.child_pid
                       and fields["targetCreationFileTime"] == self.child_creation,
                       f"{event.api}: target_identity")
            self.check(bool(fields["flags"] & FLAG_STABLE), f"{event.api}: target_stable")
        else:
            self.check(not fields["flags"] & (FLAG_TARGET | FLAG_STABLE),
                       f"{event.api}: no_target_identity")
        if thread_expected:
            self.check(bool(fields["flags"] & FLAG_THREAD)
                       and fields["targetTid"] > 0
                       and fields["targetThreadCreationFileTime"] > 0,
                       f"{event.api}: thread_identity_real_tid")
        else:
            self.check(not fields["flags"] & FLAG_THREAD and fields["targetTid"] == 0,
                       f"{event.api}: no_thread_identity")
        self.check(event.result == expect_result, f"{event.api}: original_result_code")
        self.check(event.address == expect_return, f"{event.api}: return_bits")
        if input_handle is not None:
            self.check(fields["inputHandle"] == input_handle, f"{event.api}: input_handle")
        else:
            self.check(fields["inputHandle"] != 0, f"{event.api}: input_handle_nonzero")
        self.check(fields["enterQpc"] > 0 and fields["returnQpc"] >= fields["enterQpc"],
                   f"{event.api}: qpc_order")
        return fields


def run(architecture):
    state = LiveRun(architecture)
    result = {"architecture": architecture, "agent": str(state.agent),
              "agent_sha256": hashlib.sha256(state.agent.read_bytes()).hexdigest(),
              "fixture_sha256": hashlib.sha256(state.fixture.read_bytes()).hexdigest(),
              "definition_sha256": state.expected_sha, "detail_limit_chars": 64}
    try:
        state.write_config()
        state.command("L " + str(state.agent))
        loaded = state.response()
        assert loaded == "LOADED", f"agent load failed: {loaded}"
        state.connect()
        state.wait_coverage()
        installed = {row.api: row.state for row in state.rows}
        for api in INJECTION_APIS:
            state.check(installed.get(api) == 0, f"coverage_installed:{api}")
        result["coverage_revision"] = int(state.rows[0].revision)

        state.command("S")
        parts = state.response().split()
        assert parts[0] == "CHILD" and len(parts) == 7, f"unexpected CHILD line: {parts!r}"
        state.child_pid = int(parts[1])
        child_base = int(parts[2])
        proc_rva = int(parts[3])
        buffer = int(parts[5])
        region = int(parts[6])
        state.child_creation = process_creation_file_time(state.child_pid)
        state.check(state.child_creation not in (None, 0), "child_creation_file_time")
        result["child_pid"] = state.child_pid

        state.command("O")
        open_line = state.response().split()
        assert open_line[0] == "OPEN"
        handle_op = int(open_line[1])
        handle_limited = int(open_line[2])
        state.set_baseline()

        # --- NtCreateThreadEx 成功（自有导出例程，真实线程身份） ---
        state.command("R")
        status = int(state.response().split()[2])
        state.child_threads = child_thread_ids(state.child_pid)
        event = state.wait_event("NtCreateThreadEx", "ntdll")
        fields = state.expect_fields(
            event, operation=2, address=child_base + proc_rva, target_expected=True,
            thread_expected=True, input_handle=handle_op,
            expect_result=signed(status), expect_return=status)
        result["ntcte_target_tid"] = fields["targetTid"] if fields else None

        # --- CreateRemoteThread 成功（产品修复后：Hook 安装在 kernel32!CreateRemoteThread
        # 公共真实入口，真实外层事件携带完整 AAIP1 结构；包身份仍为 KernelBase/CreateRemoteThread） ---
        state.command("r")
        crt = state.response().split()
        assert crt[2] == "1", f"CreateRemoteThread unexpected result: {crt}"
        crt_tid = int(crt[4])
        crt_handle = int(crt[5])
        event = state.wait_event("CreateRemoteThread", "KernelBase")
        fields = state.expect_fields(
            event, operation=2, address=child_base + proc_rva, target_expected=True,
            thread_expected=True, input_handle=handle_op, expect_result=0,
            expect_return=crt_handle)
        if fields:
            state.check(fields["targetTid"] == crt_tid,
                        "CreateRemoteThread: reported_tid_matches_event")
        result["crt_reported_tid"] = crt_tid
        result["crt_return_handle"] = crt_handle

        # --- WriteProcessMemory 成功 ---
        state.command("w")
        assert state.response().split()[2] == "1"
        event = state.wait_event("WriteProcessMemory", "KernelBase")
        state.expect_fields(
            event, operation=1, address=buffer + 0x100, requested=256, completed=256,
            target_expected=True, thread_expected=False, input_handle=handle_op,
            expect_result=0, expect_return=1)

        # --- NtWriteVirtualMemory 成功 ---
        state.command("W")
        assert state.response().split()[2] == "0"
        event = state.wait_event("NtWriteVirtualMemory", "ntdll")
        state.expect_fields(
            event, operation=1, address=buffer + 0x300, requested=128, completed=128,
            target_expected=True, thread_expected=False, input_handle=handle_op,
            expect_result=0, expect_return=0)

        # --- WriteProcessMemory 成功但 null 输出长度 ---
        state.command("n")
        assert state.response().split()[2] == "1"
        event = state.wait_event("WriteProcessMemory", "KernelBase")
        state.expect_fields(
            event, operation=1, address=buffer + 0x400, requested=64, completed_present=False,
            target_expected=True, thread_expected=False, input_handle=handle_op,
            expect_result=0, expect_return=1)

        # --- NtWriteVirtualMemory 成功但 null 输出长度 ---
        state.command("N")
        assert state.response().split()[2] == "0"
        event = state.wait_event("NtWriteVirtualMemory", "ntdll")
        state.expect_fields(
            event, operation=1, address=buffer + 0x500, requested=64, completed_present=False,
            target_expected=True, thread_expected=False, input_handle=handle_op,
            expect_result=0, expect_return=0)

        # --- WriteProcessMemory 跨未提交页失败 ERROR_PARTIAL_COPY ---
        state.command("m")
        wpm_error = int(state.response().split()[3])
        event = state.wait_event("WriteProcessMemory", "KernelBase")
        state.expect_fields(
            event, operation=1, address=region + 0x800, requested=8192, completed_present=False,
            target_expected=True, thread_expected=False, input_handle=handle_op,
            expect_result=wpm_error, expect_return=0)
        state.check(wpm_error == 299, "WriteProcessMemory: partial_copy_error_299")

        # --- NtWriteVirtualMemory 部分写 STATUS_PARTIAL_COPY ---
        state.command("M")
        assert int(state.response().split()[2]) == signed(STATUS_PARTIAL_COPY)
        event = state.wait_event("NtWriteVirtualMemory", "ntdll")
        state.expect_fields(
            event, operation=1, address=region + 0x800, requested=8192, completed_present=False,
            target_expected=True, thread_expected=False, input_handle=handle_op,
            expect_result=signed(STATUS_PARTIAL_COPY), expect_return=STATUS_PARTIAL_COPY)

        # --- 仅 VM_WRITE 句柄：WriteProcessMemory 失败 ERROR_ACCESS_DENIED。
        # 句柄无 PROCESS_QUERY_LIMITED_INFORMATION，目标身份查询失败必须保留未知。
        state.command("p")
        denied_error = int(state.response().split()[3])
        event = state.wait_event("WriteProcessMemory", "KernelBase")
        state.expect_fields(
            event, operation=1, address=buffer + 0x800, requested=16, completed_present=False,
            target_expected=False, thread_expected=False, input_handle=handle_limited,
            expect_result=denied_error, expect_return=0)
        state.check(denied_error == 5, "WriteProcessMemory: access_denied_5")

        # --- 仅 VM_WRITE 句柄：NtWriteVirtualMemory 成功（内核只要求 VM_WRITE）。
        # 成功输出长度有效，但目标身份查询失败必须保留未知、不得补值。
        state.command("P")
        assert int(state.response().split()[2]) == 0
        event = state.wait_event("NtWriteVirtualMemory", "ntdll")
        state.expect_fields(
            event, operation=1, address=buffer + 0x900, requested=16, completed=16,
            target_expected=False, thread_expected=False, input_handle=handle_limited,
            expect_result=0, expect_return=0)

        # --- 已关闭句柄：WriteProcessMemory 失败（无目标身份） ---
        state.command("c")
        closed_error = int(state.response().split()[3])
        event = state.wait_event("WriteProcessMemory", "KernelBase")
        state.expect_fields(
            event, operation=1, address=buffer + 0x600, requested=32, completed_present=False,
            target_expected=False, thread_expected=False, input_handle=None,
            expect_result=closed_error, expect_return=0)
        state.check(closed_error == 6, "WriteProcessMemory: invalid_handle_6")

        # --- 已关闭句柄：NtWriteVirtualMemory 失败 STATUS_INVALID_HANDLE ---
        state.command("C")
        assert int(state.response().split()[2]) == signed(STATUS_INVALID_HANDLE)
        event = state.wait_event("NtWriteVirtualMemory", "ntdll")
        state.expect_fields(
            event, operation=1, address=buffer + 0x700, requested=32, completed_present=False,
            target_expected=False, thread_expected=False, input_handle=None,
            expect_result=signed(STATUS_INVALID_HANDLE), expect_return=STATUS_INVALID_HANDLE)

        # --- CreateRemoteThread 无效句柄（非伪句柄）：真实外层 AAIP 失败事件，
        #     无目标/线程身份（完整未知语义）、原返回位 0、LastError 6 ---
        state.command("t")
        crt_parts = state.response().split()
        assert crt_parts[2] == "0", f"CreateRemoteThread unexpected result: {crt_parts}"
        crt_error = int(crt_parts[3])
        event = state.wait_event("CreateRemoteThread", "KernelBase")
        state.expect_fields(
            event, operation=2, address=0x1000, target_expected=False, thread_expected=False,
            input_handle=0x1234, expect_result=crt_error, expect_return=0)
        state.check(crt_error == 6, "CreateRemoteThread: invalid_handle_6")

        # --- NtCreateThreadEx 无效句柄（非伪句柄）：失败 NTSTATUS 原样保留进事件 ---
        state.command("T")
        status = int(state.response().split()[2])
        state.check(status < 0, "NtCreateThreadEx: invalid_handle_status_negative")
        event = state.wait_event("NtCreateThreadEx", "ntdll")
        state.expect_fields(
            event, operation=2, address=0x1000, target_expected=False, thread_expected=False,
            input_handle=0x1234, expect_result=status,
            expect_return=status & 0xFFFFFFFF)

        # --- 自有导出线程实际执行 + 目标缓冲真实写入 + 普通 ReadProcessMemory 事件 ---
        state.command("v")
        verify_line = state.response().split()
        if verify_line[0] == "CRASH" or verify_line[0] != "V":
            raise RuntimeError(f"verify command failed, fixture raw line: {verify_line}")
        counter = int(verify_line[1])
        pattern_ok = int(verify_line[3])
        state.check(counter >= 2 and pattern_ok == 1,
                    "remote_threads_executed_and_pattern_written")
        result["remote_thread_counter"] = counter
        read_event = state.wait_event("ReadProcessMemory", "KernelBase")
        state.check(read_event.state != MARKER and not read_event.detail.startswith(AAIP_PREFIX),
                    "normal_event_without_marker")
        state.check(len(read_event.detail) <= 64,
                    "normal_event_detail_truncated_by_short_limit")

        state.command("x")
        assert state.response() == "CLOSED"

        # --- 事件计数与 marker 语义（仅统计 baseline 之后的命令事件） ---
        # 产品修复后 CreateRemoteThread 走真实外层 AAIP 事件；外层 CRT 触发时嵌套的
        # CreateRemoteThreadEx / NtCreateThreadEx 必须被重入保护旁路，不得出现重复业务包。
        post = state.events[getattr(state, "baseline_event_index", 0):]
        injection_events = [e for e in post if e.kind == 0 and e.api in INJECTION_APIS]
        crt_raw_events = [e for e in post if e.kind == 0 and e.api == "CreateRemoteThreadEx"]
        normal_events = [e for e in post
                         if e.kind == 0 and e.api not in INJECTION_APIS
                         and e.api != "CreateRemoteThreadEx"]
        per_api = {}
        for e in injection_events:
            per_api[e.api] = per_api.get(e.api, 0) + 1
        expected = {"WriteProcessMemory": 5, "NtWriteVirtualMemory": 5,
                    "CreateRemoteThread": 2, "NtCreateThreadEx": 2}
        state.check(per_api == expected, "four_apis_aaip_expected_counts_no_nested_duplicates")
        state.check(len(crt_raw_events) == 0,
                    "no_nested_create_remote_thread_ex_raw_packets")
        state.check(all(e.state != MARKER and not e.detail.startswith(AAIP_PREFIX)
                        for e in crt_raw_events + normal_events),
                    "all_normal_events_without_marker")
        state.check(all(row.state != MARKER for row in state.rows),
                    "all_coverage_rows_without_marker")

        # --- 安装入口地址核对：CreateRemoteThread 覆盖行 hookAddress 必须落在夹具进程
        #     kernel32.dll 模块范围内，且 RVA 等于 kernel32!CreateRemoteThread 导出 RVA，
        #     实测入口字节为 Hook 补丁（jmp 系）。---
        rows_by_api = {row.api: row for row in state.rows}
        crt_row = rows_by_api.get("CreateRemoteThread")
        if state.check(crt_row is not None, "coverage_row:CreateRemoteThread"):
                kernel32 = module_base_size(state.pid, "kernel32.dll")
                if state.check(kernel32 is not None, "fixture_kernel32_enumerated"):
                    base, size = kernel32
                    # 与夹具同架构的 kernel32 导出 RVA 从磁盘 PE 解析，
                    # 避免 64 位校验进程解析 32 位夹具模块时架构不匹配。
                    disk_kernel32 = ("C:/Windows/System32/kernel32.dll" if architecture == "x64"
                                     else "C:/Windows/SysWOW64/kernel32.dll")
                    rva = export_rva_from_file(disk_kernel32, "CreateRemoteThread")
                    state.check(rva is not None, "kernel32_export_rva_resolved")
                    if rva is None:
                        rva = -1
                installed = int(crt_row.address)
                state.check(base <= installed < base + size,
                            "coverage_install_address_within_fixture_kernel32")
                state.check(installed - base == rva,
                            "coverage_install_address_matches_kernel32_create_remote_thread_rva")
                result["coverage"] = {"create_remote_thread": {
                    "hook_address": installed, "kernel32_base_fixture": base,
                    "kernel32_size": size, "create_remote_thread_rva": rva}}
                fixture_handle = kernel.OpenProcess(
                    QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, state.pid)
                if fixture_handle and fixture_handle != INVALID:
                    patch = remote_read(fixture_handle, installed, 16)
                    kernel.CloseHandle(fixture_handle)
                    if patch is not None:
                        result["coverage"]["create_remote_thread"]["entry_bytes"] = patch.hex(" ")
                        state.check(patch[0] in (0xE9, 0xEB, 0xCC) or patch[:2] in (b"\xff\x25",),
                                    "coverage_install_entry_patched_with_jump")
        result["event_counts"] = per_api
        result["crt_raw_event_count"] = len(crt_raw_events)
        result["normal_event_count"] = len(normal_events)
        result["events"] = [{"api": e.api, "module": e.module, "kind": e.kind,
                             "result": e.result, "state": e.state, "detail": e.detail[:48]}
                            for e in state.events]
    except BaseException as error:
        result["error"] = repr(error)
        result["in_flight_command"] = getattr(state, "current_command", None)
        result["fixture_returncode"] = state.process.poll()
        result["checks"] = state.checks
        result["failures"] = list(state.failures)
        result["events"] = [{"api": e.api, "module": e.module, "kind": e.kind,
                             "result": e.result, "state": e.state, "detail": e.detail[:80]}
                            for e in state.events]
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        (LOG_DIR / f"api_transfer_live_{architecture}.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        raise
    finally:
        state.close()
    state.check(state.process.returncode == 0, "fixture_exit_code_zero")
    result["checks"] = state.checks
    result["failures"] = state.failures
    result["passed"] = state.checks - len(state.failures)
    result["status"] = "PASS" if not state.failures else "FAIL"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    out = LOG_DIR / f"api_transfer_live_{architecture}.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"RESULT {architecture}: {result['status']} passed={result['passed']}/{state.checks}")
    return 0 if not state.failures else 1


if __name__ == "__main__":
    architecture = sys.argv[1] if len(sys.argv) > 1 else "x64"
    assert architecture in ("x64", "x86")
    sys.exit(run(architecture))
