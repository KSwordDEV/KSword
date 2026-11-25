"""通过正式 Qt 主程序验证自有进程的实时分析与停止回执。"""
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]  # 仓库与正式 Release 的定位基准。
RELEASE = ROOT / "Ksword5.1/x64/Release"
SAMPLE = RELEASE / "ActionAnalyzeQtPreviewValidation.bin"  # 固定、自有进程的测试文件。
sys.path.insert(0, str(ROOT / "tools/ksword_mcp"))
from ksword_mcp.protocol import BridgeError
from ksword_mcp.winpipe import BridgeClient


def sample():
    """读写父进程独占创建的文件并计算摘要，标准输入关闭后退出。"""
    import threading

    stop = threading.Event()  # 父进程可以随时结束工作负载。
    reader = threading.Thread(target=lambda: (sys.stdin.buffer.read(), stop.set()), daemon=True)
    reader.start()
    block = bytes(256 * 1024)  # 反复覆盖同一自有文件，不扩大占用。
    with SAMPLE.open("r+b", buffering=0) as stream:
        while not stop.wait(.05):
            stream.seek(0)
            stream.write(block)
            stream.seek(0)
            actual = stream.read(len(block))  # 本轮持有的读回数据。
            assert actual == block
            cpu_deadline = time.process_time() + .015  # 在区间内产生可由进程计数辨认的 CPU 时间。
            while time.process_time() < cpu_deadline:
                hashlib.sha256(actual).digest()


def until(probe, satisfied, timeout=12):
    """重复回读实际状态，超时打印最后一次诊断。"""
    deadline = time.monotonic() + timeout
    last = None  # 保留最后有效回读或暂时错误。
    while time.monotonic() < deadline:
        try:
            last = probe()
            if satisfied(last):
                return last
        except BridgeError as error:
            last = str(error)
        time.sleep(.15)
    raise AssertionError(f"Timed out: {str(last)[:600]}")


def dispatch(client, method, **params):
    """提交一次动作并等待原生派发，业务成效由调用方自行回读。"""
    answer = client.call(method, params)
    if answer["status"] == "accepted":
        operation = answer["data"]["operation_id"]
        until(lambda: client.call("operation_status", {"operation_id": operation})["data"],
              lambda reply: reply["state"] == "dispatched", timeout=4)
    return answer["data"]


def unique(nodes, predicate):
    """要求匹配唯一，错误时只列匹配数量，避免误操作其它页。"""
    matches = [node for node in nodes if predicate(node)]
    assert len(matches) == 1, f"Expected one matching object, found {len(matches)}"
    return matches[0]


def open_overview(client):
    """沿实际监控目录打开行为分析，返回总览控件查询函数。"""
    until(lambda: client.call("hello", {}), lambda reply: reply["status"] == "ok", timeout=35)
    pages = client.call("pages", {})["data"]["pages"]  # 只根据真实目录定位监控 Dock。
    monitor = unique(pages, lambda page: page["title"] in {"监控", "Monitor"})
    page_id = monitor["id"]
    monitor_root = dispatch(client, "open_page", page_id=page_id)["root_id"]

    def snapshot(root_id, depth=12):
        return client.call("snapshot", {"root_id": root_id, "max_nodes": 1200,
                                        "depth": depth})["data"]["nodes"]

    tabs = unique(snapshot(monitor_root, 2), lambda node: node["type"] == "tab_widget" and
                  any(title in {"行为分析", "Action Analysis", "ActionAnalyze", "Behavior Analysis"}
                      for title in node["tabs"]))
    names = {"行为分析", "Action Analysis", "ActionAnalyze", "Behavior Analysis"}
    tab_index = next(index for index, title in enumerate(tabs["tabs"]) if title in names)
    dispatch(client, "set_field", object_id=tabs["id"], value=tab_index, confirmed=True)
    # 从可见子页向下读取，避免监控 Dock 的其它模型耗尽快照节点预算。
    stack = unique(snapshot(tabs["id"], 1), lambda node: node["class"] == "QStackedWidget")
    visible_page = unique(snapshot(stack["id"], 1), lambda node: node["visible"] and
                          node["parent_id"] == stack["id"])

    def nodes():
        return snapshot(visible_page["id"])

    active = until(nodes, lambda rows: any(node["visible"] and
                   node["object_name"] == "action_analyze_target_pid" for node in rows))
    print("NAVIGATION=Monitor/ActionAnalyze/Overview", flush=True)
    return nodes, active


def verify(client, target_pid):
    """核验两次有效区间、停止以及改用无效目标后的结果保留。"""
    nodes, active = open_overview(client)

    # 所有动作限定在工作台已显示的控件。ETW 权限与活动分析分别回读。
    target = unique(active, lambda node: node["visible"] and node["object_name"] == "action_analyze_target_pid")
    start = unique(active, lambda node: node["visible"] and node["object_name"] == "action_analyze_start")
    stop = unique(active, lambda node: node["visible"] and node["object_name"] == "action_analyze_stop")
    provider = unique(active, lambda node: node["visible"] and node["object_name"] == "action_analyze_etw_provider")
    views = [node for node in active if node["visible"] and node["class"] == "QTableView"]

    def table(view, parent_rows=None):
        """读取事件列表或详情里的指定分组，保留原始行与修订。"""
        return client.call("read_table", {"object_id": view["id"], "row_count": 32,
                                          "column_count": 12, "parent_rows": parent_rows or []})["data"]

    # 结果表和详情表可能共存，通过业务表头确认实际模型。
    result = unique(views, lambda view: {"PID", "TID"} <= set(table(view)["headers"]))
    assert provider["value"] == "", "The default preset must work without ETW permissions"
    dispatch(client, "set_field", object_id=target["id"], value=str(target_pid), confirmed=True)
    dispatch(client, "action", object_id=start["id"], action="press", confirmed=True)
    captured = until(lambda: table(result), lambda data:
                     sum("进程活动分析" in row for row in data["rows"]) >= 2)
    pid_index = captured["headers"].index("PID")
    assert all(str(row[pid_index]) == str(target_pid) for row in captured["rows"] if "进程活动分析" in row)
    dispatch(client, "action", object_id=stop["id"], action="press", confirmed=True)
    def status():
        """读取各子页共用的固定状态栏。"""
        return unique(nodes(), lambda node: node["object_name"] == "action_analyze_session_status")["name"]

    receipt = until(status, lambda text: text.startswith("监控已停止"))
    stopped = table(result)  # 停止后使用稳定的模型修订，避免选择变化混淆样本。
    prior = stopped["rows"]
    row_index = next(index for index, row in enumerate(prior) if "进程活动分析" in row)
    dispatch(client, "select_row", object_id=result["id"], row=row_index,
             revision=stopped["revision"], confirmed=True)

    def fields():
        """从可见字段模型寻找当前记录，逐项回读共享详情。"""
        for tree in nodes():
            if tree["visible"] and tree["type"] == "item_view" and tree["id"] != result["id"]:
                rows = table(tree)["rows"]  # 直接投影可能省去只有一项的分组。
                flat = {row[0]: row[1] for row in rows if len(row) >= 2}
                if "区间写 I/O 字节" in flat:
                    return flat
                for index, row in enumerate(rows):
                    if row and row[0] == "进程活动分析":
                        return {field[0]: field[1] for field in table(tree, [index])["rows"]}
        return {}

    try:
        detail = until(fields, lambda values: "区间写 I/O 字节" in values, timeout=5)
    except AssertionError:
        # 失败时只回读本页的字段模型，定位布局或桥接差异。
        for node in nodes():
            if node["type"] == "item_view":
                print(json.dumps({"class": node["class"], "visible": node["visible"], "name": node["name"],
                                  "rows": table(node)["rows"]}, ensure_ascii=False), flush=True)
        raise
    assert int(detail["PID"]) == target_pid and int(detail["进程创建时间（FILETIME）"]) > 0
    print(json.dumps({"pid": target_pid, "receipt": receipt, "rows": prior, "detail": detail},
                     ensure_ascii=False), flush=True)
    assert int(detail["统计区间（毫秒）"]) >= 1000 and float(detail["区间 CPU 时间（毫秒）"]) > 0
    assert int(detail["区间读 I/O 字节"]) >= 262144 and int(detail["区间写 I/O 字节"]) >= 262144

    # 4,294,967,295 保留低位，无法作为 Windows 用户进程目标。
    dispatch(client, "set_field", object_id=target["id"], value="4294967295", confirmed=True)
    dispatch(client, "action", object_id=start["id"], action="press", confirmed=True)
    until(status, lambda text: "OpenProcess/GetProcessTimes" in text)
    assert table(result)["rows"] == prior, "Previous result changed after invalid target"

    # 验证已启用 ETW 的独立回执。当前权限可能允许采集，也可能返回真实错误。
    dispatch(client, "set_field", object_id=target["id"], value=str(target_pid), confirmed=True)
    dispatch(client, "set_field", object_id=provider["id"], value="{EDD08927-9CC4-4E65-B970-C2560FB5C289}",
             confirmed=True)
    dispatch(client, "action", object_id=start["id"], action="press", confirmed=True)
    coverage = until(status, lambda text: "ETW 采集中" in text or "ETW 不可用" in text)
    until(lambda: table(result), lambda data: data["rows"] and data["rows"][0][0] != prior[0][0]
          and any("进程活动分析" in row for row in data["rows"]))
    dispatch(client, "action", object_id=stop["id"], action="press", confirmed=True)
    etw_receipt = until(status, lambda text: text.startswith("监控已停止"))
    if "ETW 不可用" in coverage:
        assert "ETW 来源受限" in etw_receipt
    print(json.dumps({"coverage": coverage, "receipt": etw_receipt}, ensure_ascii=False), flush=True)
    print("LIVE_PREVIEW=PASS", flush=True)


def close_gui(gui):
    """只向测试子进程的顶层窗口请求关闭，失败时用原句柄收尾。"""
    if gui.poll() is not None:
        return
    user = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]

    @callback_type
    def close_window(window, unused):
        owner = wintypes.DWORD()  # 窗口必须属于真实测试子进程。
        user.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == gui.pid:
            user.PostMessageW(window, 0x0010, 0, 0)
        return True

    user.EnumWindows(close_window, 0)
    try:
        gui.wait(8)
    except subprocess.TimeoutExpired:
        gui.terminate()
        gui.wait(5)


def main():
    """使用正式目录的配置和程序，所有测试进程退出后逐字节恢复原配置。"""
    exe = RELEASE / "Ksword5.1.exe"
    settings = RELEASE / "Style/appearance_settings.json"
    original = settings.read_bytes()  # 不创建配置备份副本，原字节随测试持有。
    draft = json.loads(original.decode("utf-8-sig"))
    draft.update(startup_auto_request_admin=False, startup_auto_install_r0_driver=False,
                 startup_scale_recommend_prompt_disabled=True, dump_auto_check_enabled=False,
                 ui_language="zh-CN", startup_default_tab_key="welcome", theme_mode="light",
                 detail_display_scheme="right")
    gui = None  # 只收尾本测试创建的子进程。
    target = None
    with SAMPLE.open("xb"):
        pass
    try:
        settings.write_text(json.dumps(draft, ensure_ascii=False), encoding="utf-8")
        target = subprocess.Popen([sys.executable, "-B", __file__, "--sample"], stdin=subprocess.PIPE,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        gui = subprocess.Popen([str(exe), "--mcp", "--mcp-no-auto-elevation"], cwd=RELEASE,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with exe.open("rb") as image:
            print(f"GUI_PID={gui.pid} SHA256={hashlib.file_digest(image, 'sha256').hexdigest()}", flush=True)
        verify(BridgeClient(gui.pid), target.pid)
    finally:
        try:
            if gui is not None:
                close_gui(gui)
                print(f"GUI_EXIT={gui.returncode}", flush=True)
            if target is not None:
                target.stdin.close()
                try:
                    target.wait(5)
                except subprocess.TimeoutExpired:
                    target.terminate()
                    target.wait(5)
                print(f"TARGET_EXIT={target.returncode}", flush=True)
        finally:
            settings.write_bytes(original)
            SAMPLE.unlink()
            assert settings.read_bytes() == original and not SAMPLE.exists()
            print("SETTINGS_RESTORED=True SAMPLE_REMOVED=True", flush=True)


if __name__ == "__main__":
    sample() if sys.argv[1:] == ["--sample"] else main()
