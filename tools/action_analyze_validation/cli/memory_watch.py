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
THREAD_REPORT = ROOT / ".codex-build-logs/action-analyze-memory-watch-threads-report.json"
COMBINED_REPORT = ROOT / ".codex-build-logs/action-analyze-memory-watch-combined-report.json"
FILETIME_EPOCH = 116444736000000000


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def target():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetCurrentThread.restype = wintypes.HANDLE
    kernel.GetThreadTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
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
    worker = None
    worker_done = threading.Event()
    worker_identity = queue.Queue()

    def wait_as_worker():
        created, exited, kernel_used, user_used = [wintypes.FILETIME() for _ in range(4)]
        known = kernel.GetThreadTimes(kernel.GetCurrentThread(), ctypes.byref(created), ctypes.byref(exited),
                                      ctypes.byref(kernel_used), ctypes.byref(user_used))
        creation_time = (created.dwHighDateTime << 32) | created.dwLowDateTime if known else 0
        worker_identity.put((threading.get_native_id(), creation_time))
        worker_done.wait(10)

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
            elif op.strip() == "restore":
                prior = wintypes.DWORD()
                check(kernel.VirtualProtect(address, 4096, 0x04, ctypes.byref(prior)), "Restore PAGE_READWRITE failed")
                emit(operation="restore", previousProtection=prior.value)
            elif op.strip() == "thread-start":
                check(worker is None, "Worker already started")
                worker = threading.Thread(target=wait_as_worker, daemon=True)
                worker.start()
                tid, created = worker_identity.get(timeout=5)
                check(created, "Worker GetThreadTimes failed")
                emit(operation="thread-start", tid=tid, creation=created)
            elif op.strip() == "thread-end":
                check(worker is not None and worker.is_alive(), "No live worker to join")
                worker_done.set()
                worker.join(timeout=5)
                check(not worker.is_alive(), "Worker did not exit")
                emit(operation="thread-end", tid=worker.native_id)
            elif op.strip() == "exit":
                emit(operation="exit")
                return
            else:
                raise ValueError(op)
    finally:
        if worker is not None:
            worker_done.set()
            worker.join(timeout=5)
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


def verify_difference(rows, write_time):
    """核对夹具自写的唯一差异，返回首次读到差异的采样下标。"""
    diffs = [i for i, row in enumerate(rows) if row["difference"] and int(row["difference"]["changedByteCount"])]
    check(len(diffs) == 1, "Expected exactly one byte transition")
    i = diffs[0]
    diff = rows[i]["difference"]
    check(int(diff["changedByteCount"]) == 4 and int(diff["omittedRangeCount"]) == 0, "Incorrect difference counts")
    ranges = [(int(item["offset"]), int(item["length"])) for item in diff["ranges"]]
    check(ranges == [(3, 3), (11, 1)], f"Incorrect difference ranges: {ranges}")
    check(i > 0 and int(rows[i - 1]["readEndUtc100ns"]) <= write_time <= int(rows[i]["readEndUtc100ns"]),
          "Independent write receipt is outside the observed transition")
    return i


def validate(report, proc, messages, threads_only, combined):
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

    if threads_only or combined:
        check(mismatch["observations"] == [] and mismatch["threadObservation"]["targetStatus"] == "identity-mismatch",
              "Wrong process generation produced observations")

        def exercise_worker():
            if combined:
                operation("write")  # 夹具主线程先写，观察线程生命周期不用于归因。
                time.sleep(0.5)
            operation("thread-start")
            time.sleep(1)
            operation("thread-end")

        threaded = capture("startedAndExitedThread", 0, commands(samples=32, interval=125), action=exercise_worker)
        rows = threaded["observations"]
        check(len(rows) == 32 and threaded["threadObservation"]["targetStatus"] == "alive", "Missing full owned capture")
        check(all(row["threadObservation"]["snapshotStatus"] == "complete" for row in rows), "Incomplete thread snapshot")
        if not combined:
            check(all(int(row["difference"]["changedByteCount"]) == 0 for row in rows[1:]), "Worker changed sampled bytes")
        worker_key = report["sample"]["thread-start"]
        observed = [(row["ordinal"], event) for row in rows for event in row["threadObservation"]["events"]
                    if event["tid"] == worker_key["tid"] and event["creationTime100ns"] is not None and
                    int(event["creationTime100ns"]) == worker_key["creation"]]
        check([event["status"] for _, event in observed] == ["newly-observed", "exited"],
              f"Unexpected worker observations: {observed}")
        first, last = (index for index, _ in observed)
        baseline_time = int(rows[0]["threadObservation"]["snapshotEndUtc100ns"])
        first_seen_time = int(rows[first]["threadObservation"]["snapshotEndUtc100ns"])
        check(0 < first < last and baseline_time < worker_key["creation"] <= first_seen_time,
              "Independent worker creation time is outside the observed interval")
        if combined:
            changed = verify_difference(rows, report["sample"]["write"]["utc100ns"])
            check(changed < first, "Byte observation must precede the new worker observation")
            report["coordinates"] = {"byteChange": changed, "workerObserved": first, "workerExited": last}
            print(f"MEMORY_WATCH_COMBINED_COORDINATES={changed},{first},{last} WORKER={worker_key['tid']}:{worker_key['creation']}")

        exited = capture("targetExited", 6, commands(samples=32, interval=125), action=lambda: operation("exit"))
        check(exited["threadObservation"]["targetStatus"] == "exited" and not exited["complete"] and
              0 < int(exited["readSamples"]) < 32, "Target exit did not preserve the sampled prefix")
        return

    change = capture("changed", 0, commands(samples=24, interval=125), action=lambda: operation("write"))
    rows = change["observations"]
    check(change["complete"] and len(rows) == 24, "Expected all 24 reads")
    verify_difference(rows, report["sample"]["write"]["utc100ns"])

    partial = capture("protectionChanged", 6, commands(samples=24, interval=125), action=lambda: operation("protect"))
    check(not partial["complete"] and 0 < int(partial["readSamples"]) < 24 and partial["win32Error"] == 487,
          "Unreadable mapping did not preserve the verified prefix")


def main(threads_only=False, combined=False):
    report = {"cli": str(CLI), "sha256": hashlib.sha256(CLI.read_bytes()).hexdigest(), "passed": False}
    report_path = COMBINED_REPORT if combined else THREAD_REPORT if threads_only else REPORT
    report_path.parent.mkdir(exist_ok=True)
    try:
        with subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--target"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8") as proc:
            messages = queue.Queue()
            reader = threading.Thread(target=read_records, args=(proc.stdout, messages), daemon=True)
            reader.start()
            try:
                validate(report, proc, messages, threads_only, combined)
                if not (threads_only or combined):
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
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(report_path)
    if combined:
        print("MEMORY_WATCH_COMBINED=PASS")
    elif threads_only:
        print("PASS bounded R3 thread observations: process identity, worker observed/exited, unchanged bytes, process exit prefix")
    else:
        print("PASS bounded R3 memory observations: unchanged, identity mismatch, exact ranges, unreadable mapping prefix")


if __name__ == "__main__":
    if sys.argv[1:] == ["--target"]:
        target()
    elif sys.argv[1:] == ["--threads-only"]:
        main(threads_only=True)
    elif sys.argv[1:] == ["--combined"]:
        main(combined=True)
    else:
        main()
