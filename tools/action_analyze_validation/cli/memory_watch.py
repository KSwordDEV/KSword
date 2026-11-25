"""Exercise the official R3 memory command against an owned non-executable buffer."""

import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time


ROOT = Path(__file__).resolve().parents[3]
CLI = ROOT / "Ksword5.1/x64/Release/KswordCLI.exe"
REPORT = ROOT / ".codex-build-logs/action-analyze-memory-watch-report.json"
FILETIME_EPOCH = 116444736000000000


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def target():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    kernel.VirtualAlloc.restype = ctypes.c_void_p
    kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
    creation, exit_time, kernel_time, user_time = [wintypes.FILETIME() for _ in range(4)]
    check(kernel.GetProcessTimes(kernel.GetCurrentProcess(), ctypes.byref(creation), ctypes.byref(exit_time),
                                 ctypes.byref(kernel_time), ctypes.byref(user_time)), "GetProcessTimes failed")
    address = kernel.VirtualAlloc(None, 4096, 0x3000, 0x04)
    check(address, "VirtualAlloc failed")
    emit = lambda **obj: print(json.dumps(obj), flush=True)
    try:
        emit(address=hex(address), creation=(creation.dwHighDateTime << 32) | creation.dwLowDateTime)
        for op in sys.stdin:
            if op.strip() == "write":
                ctypes.memmove(address + 3, b"abc", 3)
                ctypes.memmove(address + 11, b"d", 1)
                emit(operation="write", ranges=[[3, 3], [11, 1]], utc100ns=time.time_ns() // 100 + FILETIME_EPOCH)
            elif op.strip() == "protect":
                prior = wintypes.DWORD()
                check(kernel.VirtualProtect(address, 4096, 0x01, ctypes.byref(prior)), "VirtualProtect failed")
                emit(operation="protect", previousProtection=prior.value)
            elif op.strip() == "exit":
                return
            else:
                raise ValueError(op)
    finally:
        check(kernel.VirtualFree(address, 0, 0x8000), "VirtualFree failed")


def read_records(stream, output):
    for line in stream:
        output.put(line)
    output.put(None)


def read_record(output):
    line = output.get(timeout=10)
    check(line is not None, "Sample closed its output early")
    return json.loads(line)


def analyze(cli_args, action=None):
    with subprocess.Popen([str(CLI), *cli_args], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        try:
            if action:
                time.sleep(1)
                action()
            out, err = proc.communicate(timeout=15)
            check(out, f"CLI returned no result (exit {proc.returncode}): {err.decode(errors='replace')}")
            return {"exitCode": proc.returncode, "reply": json.loads(out)}
        finally:
            if proc.poll() is None:
                proc.kill()


def validate(report, proc, messages):
    seed = read_record(messages)
    report["sample"] = {"pid": proc.pid, **seed}

    def commands(creation=None, samples=4, interval=70):
        identity = seed["creation"] if creation is None else creation
        return ["analyze", "memory", "watch", "--backend", "r3", "--json", "--pid", str(proc.pid),
                "--creation-time", str(identity), "--address", seed["address"], "--size", "32",
                "--samples", str(samples), "--interval-ms", str(interval)]

    def operation(op):
        proc.stdin.write(op + "\n")
        proc.stdin.flush()
        receipt = read_record(messages)
        check(receipt["operation"] == op, "Sample command receipt mismatch")
        report["sample"][op] = receipt

    def capture(name, expected_code, *args, **kwargs):
        run = analyze(*args, **kwargs)
        report[name] = run
        check(run["exitCode"] == expected_code, f"{name} returned {run['exitCode']}")
        check(run["reply"]["backend"] == "r3", f"{name} reports a different backend")
        data = run["reply"]["data"]
        check(int(data["observedCreationTime100ns"]) == seed["creation"], f"{name} identity mismatch")
        return data

    stable = capture("unchanged", 0, commands())
    check(stable["complete"] and stable["observations"][0]["difference"] is None, "Missing baseline")
    check(all(int(row["difference"]["changedByteCount"]) == 0 for row in stable["observations"][1:]),
          "Unchanged buffer reported a difference")

    mismatch = capture("wrongCreationTime", 3, commands(creation=seed["creation"] + 1))
    check(int(mismatch["readSamples"]) == 0 and mismatch["win32Error"] == 87, "Wrong identity was not rejected")

    change = capture("changed", 0, commands(samples=24, interval=125), action=lambda: operation("write"))
    rows = change["observations"]
    diffs = [i for i, row in enumerate(rows) if row["difference"] and int(row["difference"]["changedByteCount"])]
    check(change["complete"] and len(rows) == 24 and len(diffs) == 1, "Expected one transition across 24 reads")
    i = diffs[0]
    diff = rows[i]["difference"]
    check(int(diff["changedByteCount"]) == 4 and int(diff["omittedRangeCount"]) == 0, "Incorrect difference counts")
    ranges = [(int(item["offset"]), int(item["length"])) for item in diff["ranges"]]
    check(ranges == [(3, 3), (11, 1)], f"Incorrect difference ranges: {ranges}")
    write_time = report["sample"]["write"]["utc100ns"]
    check(int(rows[i - 1]["readEndUtc100ns"]) <= write_time <= int(rows[i]["readEndUtc100ns"]),
          "Independent write receipt is outside the observed transition")

    partial = capture("protectionChanged", 6, commands(samples=24, interval=125), action=lambda: operation("protect"))
    check(not partial["complete"] and 0 < int(partial["readSamples"]) < 24 and partial["win32Error"] == 487,
          "Unreadable mapping did not preserve the verified prefix")


def main():
    report = {"cli": str(CLI), "sha256": hashlib.sha256(CLI.read_bytes()).hexdigest(), "passed": False}
    REPORT.parent.mkdir(exist_ok=True)
    try:
        with subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--target"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8") as proc:
            messages = queue.Queue()
            reader = threading.Thread(target=read_records, args=(proc.stdout, messages), daemon=True)
            reader.start()
            try:
                validate(report, proc, messages)
                proc.stdin.write("exit\n")
                proc.stdin.flush()
                check(proc.wait(timeout=10) == 0, "Sample did not cleanly release its buffer and exit")
                report["passed"] = True
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)
                report["sampleExitCode"] = proc.returncode
                reader.join(timeout=2)
    finally:
        REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(REPORT)
    print("PASS bounded R3 memory observations: unchanged, identity mismatch, exact ranges, unreadable mapping prefix")


if __name__ == "__main__":
    if sys.argv[1:] == ["--target"]:
        target()
    else:
        main()
