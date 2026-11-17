"""通过真实主程序右键菜单操作自有 detached 夹具；不选择或注入用户进程。"""
from __future__ import annotations

import argparse
import ctypes
import json
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # 唯一仓库根目录。
sys.path.insert(0, str(ROOT / "tools/ksword_mcp"))
from winpipe import BridgeClient  # noqa: E402


class ProbeState(ctypes.Structure):
    """与 C++ 夹具固定宽度回执一致；每一项都是实际目标线程观察。"""
    _fields_ = [(name, wintypes.DWORD) for name in
                ("console", "win32_io", "c_input", "cpp_good", "observed")]


def settle(client: BridgeClient, response: dict) -> None:
    """输入已排队响应，等待原生事件已派发；不将其作为后端完成证据。"""
    operation = response["data"]["operation_id"]  # 本次桥操作身份。
    deadline = time.monotonic() + 8  # GUI 事件完成预算。
    while time.monotonic() < deadline:
        state = client.call("operation_status", {"operation_id": operation})["data"]["state"]
        if state == "dispatched":
            return
        assert state not in ("failed", "interrupted", "cancelled"), state
        time.sleep(.03)
    raise AssertionError("GUI dispatch timed out")


def main() -> None:
    """输入现有主程序 PID 和夹具 EXE；输出真实菜单触发及输出回读结果。"""
    parser = argparse.ArgumentParser(description=__doc__)  # 明确指定已启动的 GUI。
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    api = ctypes.WinDLL("kernel32", use_last_error=True)  # 本次夹具的通信接口。
    signatures = {
        "CreateFileMappingW": ([wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR], wintypes.HANDLE),
        "MapViewOfFile": ([wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                           wintypes.DWORD, ctypes.c_size_t], ctypes.c_void_p),
        "CreateEventW": ([ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR], wintypes.HANDLE),
        "SetEvent": ([wintypes.HANDLE], wintypes.BOOL),
        "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
        "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        "UnmapViewOfFile": ([ctypes.c_void_p], wintypes.BOOL),
    }  # 使用精确句柄/指针类型，避免 x64 默认整型截断。
    for name, (parameters, result) in signatures.items():
        getattr(api, name).argtypes = parameters
        getattr(api, name).restype = result
    name = "Local\\KSwordConsoleLive-" + str(time.time_ns())  # 独占测试命名对象。
    mapping = api.CreateFileMappingW(wintypes.HANDLE(-1), None, 4, 0, ctypes.sizeof(ProbeState), name)
    address = api.MapViewOfFile(mapping, 0xF001F, 0, 0, ctypes.sizeof(ProbeState))
    assert address
    state = ProbeState.from_address(address)  # 目标更新后的共享回执。
    events = {key: api.CreateEventW(None, key == "stop", False, name + "-" + key)
              for key in ("ready", "request", "done", "stop")}  # 与 C++ 夹具协议对应。
    startup = subprocess.STARTUPINFO()  # 不显示测试控制台，但保留真实控制台语义。
    startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    process = subprocess.Popen([str(args.fixture.resolve()), "--child", name],
                               creationflags=subprocess.DETACHED_PROCESS, startupinfo=startup)
    client = BridgeClient(args.pid)  # 仅连接用户指定的真实 KSword 实例。
    original_search = ""  # 结束时恢复列表原搜索草稿。
    search = None  # 延迟绑定可见搜索框，失败时也能安全清理子进程。
    try:
        assert api.WaitForSingleObject(events["ready"], 10000) == 0
        client.call("open_page", {"page_id": "ksDock_process", "confirmed": True})
        nodes = client.call("snapshot", {"page_id": "ksDock_process", "max_nodes": 550, "depth": 14})["data"]["nodes"]
        search = next(n for n in nodes if n.get("visible") and n.get("class") == "QLineEdit"
                      and "PID" in n.get("placeholder", ""))
        table = next(n for n in nodes if n.get("visible") and n.get("class") == "QTableView")
        pause = next(n for n in nodes if n.get("visible") and n.get("description", "").startswith("暂停周期"))
        resume = next(n for n in nodes if n.get("visible") and n.get("description", "").startswith("开始周期"))
        original_search = search.get("value", "")
        settle(client, client.call("set_field", {"object_id": search["id"], "value": str(process.pid), "confirmed": True}))
        settle(client, client.call("action", {"object_id": resume["id"], "action": "press", "confirmed": True}))
        deadline = time.monotonic() + 10  # 等待正常异步枚举把自有目标加入列表。
        while time.monotonic() < deadline:
            data = client.call("read_table", {"object_id": table["id"], "row_count": 5, "column_count": 2})["data"]
            if any(str(row[1]) == str(process.pid) for row in data["rows"]):
                break
            time.sleep(.15)
        settle(client, client.call("action", {"object_id": pause["id"], "action": "press", "confirmed": True}))
        data = client.call("read_table", {"object_id": table["id"], "row_count": 5, "column_count": 2})["data"]
        row = next(index for index, values in enumerate(data["rows"]) if str(values[1]) == str(process.pid))
        settle(client, client.call("select_row", {"object_id": table["id"], "row": row,
                                                   "revision": data["revision"], "confirmed": True}))
        client.call("action", {"object_id": table["id"], "action": "show_menu", "confirmed": True})
        time.sleep(.15)  # 菜单 exec 已进入，下一次 snapshot 从真实 popup 开始。
        nodes = client.call("snapshot", {"max_nodes": 300, "depth": 5})["data"]["nodes"]
        action = next(n for n in nodes if n.get("name") == "强开控制台")
        assert action["enabled"] and action["visible"] and action["description"]
        settle(client, client.call("action", {"object_id": action["id"], "action": "press", "confirmed": True}))
        deadline = time.monotonic() + 12  # 后端异步完成以目标业务线程回读为准。
        while time.monotonic() < deadline:
            api.SetEvent(events["request"])
            assert api.WaitForSingleObject(events["done"], 3000) == 0
            if state.console and state.cpp_good and state.observed == 0x1FF:
                break
            time.sleep(.1)
        assert state.console and state.win32_io and state.c_input and state.cpp_good
        assert state.observed == 0x1FF, hex(state.observed)
        print(json.dumps({"LIVE_PROCESS_MENU": "PASS", "gui_pid": args.pid, "target_pid": process.pid,
                          "target": args.fixture.name, "actual_output_mask": hex(state.observed)}, ensure_ascii=False))
    finally:
        # 无论业务断言结果如何，唯一自有目标通过协议正常退出；不结束其它进程。
        api.SetEvent(events["stop"])
        process.wait(timeout=10)
        if search:
            settle(client, client.call("set_field", {"object_id": search["id"], "value": original_search, "confirmed": True}))
        api.UnmapViewOfFile(address)
        for handle in (*events.values(), mapping):
            api.CloseHandle(handle)


if __name__ == "__main__":
    main()
