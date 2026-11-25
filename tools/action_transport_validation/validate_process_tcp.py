"""R3 IPv4 TCP deletion against one exact self-created loopback client only.

No firewall, adapter, SSH, driver, external endpoint or product code is changed.
The second self-owned connection is an independent non-target control channel.
"""

from __future__ import annotations

import contextlib
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import sys
import time


class TcpOwnerRow(ctypes.Structure):
    _fields_ = [(name, wintypes.DWORD) for name in (
        "state", "local_address", "local_port", "remote_address", "remote_port", "pid"
    )]


class TcpRow(ctypes.Structure):
    _fields_ = TcpOwnerRow._fields_[:5]


def tcp_table() -> list[TcpOwnerRow]:
    """Copy the IPv4 owner table; never mutate a row while enumerating."""
    api = ctypes.WinDLL("iphlpapi", use_last_error=True).GetExtendedTcpTable
    api.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
                    wintypes.BOOL, wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    api.restype = wintypes.DWORD
    size = wintypes.DWORD(0)
    status = api(None, ctypes.byref(size), False, socket.AF_INET, 5, 0)
    if status != 122:  # ERROR_INSUFFICIENT_BUFFER
        raise OSError(status, "GetExtendedTcpTable size query")
    for _ in range(4):
        buffer = ctypes.create_string_buffer(size.value)
        status = api(buffer, ctypes.byref(size), False, socket.AF_INET, 5, 0)
        if status == 122:
            continue
        if status:
            raise OSError(status, "GetExtendedTcpTable")
        count = struct.unpack_from("<I", buffer.raw)[0]
        row_size = ctypes.sizeof(TcpOwnerRow)
        if 4 + count * row_size > len(buffer):
            raise ValueError("TCP table row count exceeds returned buffer")
        return [TcpOwnerRow.from_buffer_copy(buffer, 4 + i * row_size)
                for i in range(count)]
    raise RuntimeError("TCP table changed size in all four attempts")


def endpoints(row: TcpOwnerRow) -> tuple[tuple[str, int], tuple[str, int]]:
    return (
        (socket.inet_ntoa(struct.pack("<I", row.local_address)),
         socket.ntohs(row.local_port & 0xFFFF)),
        (socket.inet_ntoa(struct.pack("<I", row.remote_address)),
         socket.ntohs(row.remote_port & 0xFFFF)),
    )


def process_creation(process_handle: int) -> int:
    api = ctypes.WinDLL("kernel32", use_last_error=True).GetProcessTimes
    api.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    api.restype = wintypes.BOOL
    values = [wintypes.FILETIME() for _ in range(4)]
    if not api(process_handle, *(ctypes.byref(value) for value in values)):
        raise ctypes.WinError(ctypes.get_last_error())
    return values[0].dwLowDateTime | (values[0].dwHighDateTime << 32)


def client(port: int) -> int:
    """Benign client: observe real disconnection, then establish a fresh socket."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=8) as first:
            first.sendall(b"READY")
            try:
                while True:
                    message = receive_exact(first, 4)
                    if message == b"PING":
                        first.sendall(b"PONG")
                    elif message == b"STOP":
                        print("TARGET_PERMISSION_NEGATIVE_CLEAN_EXIT", flush=True)
                        return 0
                    elif message == b"":
                        break
                    else:
                        return 11
                reason = "eof"
            except ConnectionResetError:
                reason = "reset"
        print("TARGET_DISCONNECTED reason=" + reason, flush=True)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as second:
            second.sendall(b"RECONNECTED")
            if receive_exact(second, 4) != b"PING":
                return 12
            second.sendall(b"PONG")
        return 0
    except Exception as error:
        print("CLIENT_FAILURE " + repr(error), flush=True)
        return 13


def receive_exact(peer: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        piece = peer.recv(count - len(result))
        if not piece:
            break
        result.extend(piece)
    return bytes(result)


def validate() -> int:
    root = Path(__file__).resolve().parents[2]
    logs = root / ".codex-build-logs/behavior-planning"
    logs.mkdir(parents=True, exist_ok=True)
    records: list[str] = []
    assertions = 0
    failures = 0
    child = None
    child_output = ""
    creation = None
    deletion_status = None
    selected = None
    emergency_cleanup = False
    result = "FAIL"
    elevated = False
    permission_negative_passed = False
    positive_delete_tested = False

    def record(line: str) -> None:
        records.append(line)
        print(line, flush=True)

    def check(condition: bool, name: str) -> None:
        nonlocal assertions, failures
        assertions += int(condition)
        failures += int(not condition)
        record("ASSERT " + ("PASS " if condition else "FAIL ") + name)
        if not condition:
            raise AssertionError(name)

    try:
        check(os.name == "nt", "windows_r3_environment")
        is_admin = ctypes.WinDLL("shell32", use_last_error=True).IsUserAnAdmin
        is_admin.argtypes = []
        is_admin.restype = wintypes.BOOL
        elevated = bool(is_admin())
        record(f"TOKEN elevated={int(elevated)}")
        with contextlib.ExitStack() as resources:
            listener = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            listener.bind(("127.0.0.1", 0))
            listener.listen(3)
            listener.settimeout(5)
            port = listener.getsockname()[1]
            child = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()),
                                      "--client", str(port)], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True)
            creation = process_creation(int(child._handle))
            first = resources.enter_context(listener.accept()[0])
            first.settimeout(3)
            check(receive_exact(first, 5) == b"READY", "self_child_loopback_connection_established")
            target_local = first.getpeername()
            target_remote = first.getsockname()
            # Independent self-owned non-target channel, never passed to SetTcpEntry.
            control = resources.enter_context(socket.create_connection(("127.0.0.1", port), timeout=3))
            control_peer = resources.enter_context(listener.accept()[0])
            control_peer.settimeout(3)
            control.sendall(b"BEFORE")
            check(receive_exact(control_peer, 6) == b"BEFORE", "non_target_channel_operates_before_deletion")
            matches = [row for row in tcp_table() if row.pid == child.pid and row.state == 5
                       and endpoints(row) == (target_local, target_remote)]
            check(len(matches) == 1, "exact_child_pid_and_four_tuple_select_one_established_row")
            selected = {"pid": child.pid, "creationFileTime": creation,
                        "local": target_local, "remote": target_remote}
            record("SELECTED " + json.dumps(selected))
            # Re-read immediately before mutation; pinned Popen process handle fixes identity.
            check(child.poll() is None and process_creation(int(child._handle)) == creation,
                  "exact_child_still_alive_with_same_creation_identity")
            fresh = [row for row in tcp_table() if row.pid == child.pid and row.state == 5
                     and endpoints(row) == (target_local, target_remote)]
            check(len(fresh) == 1, "connection_owner_and_tuple_revalidated_before_delete")
            row = fresh[0]
            request = TcpRow(12, row.local_address, row.local_port,
                             row.remote_address, row.remote_port)
            api = ctypes.WinDLL("iphlpapi", use_last_error=True).SetTcpEntry
            api.argtypes = [ctypes.POINTER(TcpRow)]
            api.restype = wintypes.DWORD
            deletion_status = api(ctypes.byref(request))
            record(f"SET_TCP_ENTRY status={deletion_status} elevated={int(elevated)}")
            if not elevated and deletion_status in (5, 317):
                check(True, "non_elevated_delete_rejected_with_documented_permission_status")
                remaining = [item for item in tcp_table() if item.pid == child.pid and item.state == 5
                             and endpoints(item) == (target_local, target_remote)]
                check(len(remaining) == 1, "permission_denial_preserves_original_target_connection")
                first.sendall(b"PING")
                check(receive_exact(first, 4) == b"PONG", "target_channel_remains_usable_after_permission_denial")
                control.sendall(b"AFTER")
                check(receive_exact(control_peer, 5) == b"AFTER", "non_target_channel_survives_permission_denial")
                control_peer.sendall(b"ALIVE")
                check(receive_exact(control, 5) == b"ALIVE", "non_target_channel_remains_bidirectional_after_denial")
                first.sendall(b"STOP")
                child_output = child.communicate(timeout=3)[0]
                record(child_output.rstrip())
                check(child.returncode == 0 and "TARGET_PERMISSION_NEGATIVE_CLEAN_EXIT" in child_output,
                      "permission_negative_child_exits_normally_without_termination")
                permission_negative_passed = True
                result = "BLOCKED_PERMISSION"
                return 2
            positive_delete_tested = True
            check(deletion_status == 0, "r3_set_tcp_entry_deletes_only_selected_ipv4_tcp_row")
            try:
                target_closed = first.recv(1) == b""
            except ConnectionResetError:
                target_closed = True
            check(target_closed, "server_observes_target_connection_eof_or_reset")
            control.sendall(b"AFTER")
            check(receive_exact(control_peer, 5) == b"AFTER", "non_target_channel_survives_target_deletion")
            control_peer.sendall(b"ALIVE")
            check(receive_exact(control, 5) == b"ALIVE", "non_target_channel_remains_bidirectional")
            second = resources.enter_context(listener.accept()[0])
            second.settimeout(3)
            check(receive_exact(second, 11) == b"RECONNECTED" and child.poll() is None,
                  "same_target_process_can_establish_new_connection_after_one_shot_delete")
            second.sendall(b"PING")
            check(receive_exact(second, 4) == b"PONG", "new_target_connection_is_usable_not_continuously_blocked")
            child_output = child.communicate(timeout=3)[0]
            record(child_output.rstrip())
            check(child.returncode == 0 and "TARGET_DISCONNECTED reason=" in child_output,
                  "exact_child_confirms_disconnect_and_exits_zero")
            result = "PASS"
    except Exception as error:
        record("ERROR " + repr(error))
    finally:
        if child is not None and child.poll() is None:
            emergency_cleanup = True
            child.kill()
            child_output = child.communicate(timeout=3)[0]
            record("EMERGENCY_CHILD_CLEANUP " + child_output.rstrip())
        if emergency_cleanup:
            result = "FAIL"
        record(f"RESULT={result} assertionsPassed={assertions} assertionsFailed={failures}")
        (logs / "action-analyze-process-tcp-run.log").write_text("\n".join(records) + "\n", encoding="utf-8")
        metadata = {
            "recordedAtUnix": time.time(), "result": result, "os": platform.platform(),
            "scope": "R3 IP Helper exact self-child IPv4 loopback TCP deletion; independent self-owned control channel, no SSH/network rules or product validation",
            "assertionsPassed": assertions, "assertionsFailed": failures,
            "elevated": elevated, "permissionNegativeControlPassed": permission_negative_passed,
            "positiveDeleteTested": positive_delete_tested,
            "setTcpEntryStatus": deletion_status, "selectedConnection": selected,
            "childPid": child.pid if child else None,
            "childExit": child.returncode if child else None,
            "childExited": child is None or child.poll() is not None,
            "emergencyCleanup": emergency_cleanup,
            "continuousIsolationTested": False, "ipv6DeletionTested": False,
            "udpDeletionTested": False, "actualSshConnectionTouched": False,
            "source": str(Path(__file__).relative_to(root)),
            "sourceSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "pythonExecutable": sys.executable, "configurationFilesCreated": 0,
            "runtimeCopiesCreated": 0,
        }
        (logs / "action-analyze-process-tcp-metadata.json").write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0 if result == "PASS" else 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--client":
        raise SystemExit(client(int(sys.argv[2])))
    raise SystemExit(validate())
