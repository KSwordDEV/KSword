"""用自有工作线程验证正式 CLI，不加载驱动，不创建编译或运行副本。"""

import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import threading
from ctypes import wintypes


def get_creation_time(function, handle):
    """传入 Get*Times API 和原对象句柄，返回整数 FILETIME。"""
    function.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    function.restype = wintypes.BOOL
    times = [wintypes.FILETIME() for _ in range(4)]  # 创建、退出、内核、用户时间。
    if not function(handle, *(ctypes.byref(value) for value in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime


def run_stack(exe, identity, backend=None, *extra):
    """对指定身份发出单次 CLI 请求，返回进程退出码及 JSON。"""
    args = [str(exe), "process", "thread", "stack", "query", *identity, "--json"]  # CLI 参数。
    if backend is not None:
        args.extend(("--backend", backend))
    run = subprocess.run([*args, *extra], capture_output=True, timeout=30)  # 有界执行与完整回执。
    raw = run.stdout  # 支持宽字符 CRT 的 UTF-8 或 UTF-16 重定向。
    encoding = "utf-16-le" if b"\x00" in raw[:16] else "utf-8-sig"
    try:
        return run.returncode, json.loads(raw.decode(encoding).lstrip("\ufeff"))
    except (ValueError, UnicodeError) as error:
        raise AssertionError((run.returncode, raw, run.stderr)) from error


def verify(exe, expect_r0):
    """同时校验自动默认 R3、明确 R0、身份失败及采样后能正常退出。"""
    api = ctypes.WinDLL("kernel32", use_last_error=True)  # 本机 Win32 接口。
    api.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenThread.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.GetCurrentProcess.restype = wintypes.HANDLE
    release = threading.Event()  # 唯一工作线程退出开关。
    worker = threading.Thread(target=release.wait, daemon=True)  # 只采样本测试对象。
    worker.start()
    handle = api.OpenThread(0x0800, False, worker.native_id)  # THREAD_QUERY_LIMITED_INFORMATION。
    try:
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        created = get_creation_time(api.GetThreadTimes, handle)  # 工作线程真实创建时间。
        process_created = get_creation_time(api.GetProcessTimes, api.GetCurrentProcess())  # 当前进程身份。
        identity = [  # 固定 PID/TID 与两种创建时间。
            "--pid", str(os.getpid()), "--tid", str(worker.native_id),
            "--creation-time", str(process_created), "--thread-creation-time", str(created),
        ]
        for backend in (None, "r3"):
            code, reply = run_stack(exe, identity, backend)  # 默认和显式请求各验一次。
            detail = reply["data"]  # R3 回执必须有真实指令地址并成功恢复。
            assert code in (0, 6) and reply["backend"] == "r3", reply
            assert detail["previousSuspendCount"] == 0 and detail["resumeWin32Error"] == 0, reply
            assert detail["targetAlive"] and any(int(frame["address"], 16) for frame in detail["frames"]), reply
            print(f"PASS {backend or 'default R3'}: {len(detail['frames'])} frames; resumed")

        wrong_identity = [*identity[:-1], str(created + 1)]  # 只改变创建时间。
        code, reply = run_stack(exe, wrong_identity, "r0")
        assert code == 3 and reply["data"]["requestAttempted"] is False, reply
        code, reply = run_stack(exe, identity, "r0", "--limit", "1")
        assert code == 1, reply  # 不允许把 R3 的帧数参数用于线索查询。

        code, reply = run_stack(exe, identity, "r0")  # 不加载驱动，只观测现场。
        detail = reply["data"]  # 无论有无地址，R0 回执不得冒充调用栈。
        assert reply["backend"] == "r0" and detail["frames"] == [], reply
        expected = {"either": (2, 5, 6), "unavailable": (2, 5), "clues": (6,)}  # 按验收现场约束。
        assert code in expected[expect_r0], reply
        if code == 6:
            assert detail["trust"] == "unverified_clue" and detail["identityMatched"] and detail["targetAlive"], reply
            assert any(detail[name] for name in ("kernelStack", "initialStack", "stackBase", "stackLimit")), reply
        else:
            assert detail["trust"] == "unavailable", reply
        print(f"PASS R0: exit={code}, trust={detail['trust']}, frames=0; stale identity and frame-limit rejected")
    finally:
        if handle:
            api.CloseHandle(handle)
        release.set()  # 无副作用地收回原测试工作线程。
        worker.join(timeout=5)
        assert not worker.is_alive(), "Fixture was not able to exit after capture"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)  # 正式 CLI 可执行文件及可选 R0 预期。
    parser.add_argument("exe", type=Path)
    parser.add_argument("--expect-r0", choices=("either", "unavailable", "clues"), default="either")
    options = parser.parse_args()  # 不创建测试 EXE 或改动服务。
    verify(options.exe.resolve(strict=True), options.expect_r0)
