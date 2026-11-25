"""通过正式 Qt 核验全局断点入口和活采样期间的归档工具条。"""

import subprocess
import sys

import win32con
import win32gui
import win32process

from archive_api_preview import TITLE, fixture_directory, import_fixture, open_project, read_table, test_window
from isolated_desktop import test_windows
from live_preview import dispatch, unique, until


def floating_window(pid):
    """返回本次 Qt 进程可见的浮动工具条句柄，未出现时返回零。"""
    windows = []  # 只接纳当前测试进程的同名原生辅助窗。

    def inspect(hwnd, _):
        """将符合窗口标题、可见性与所有权的句柄加入结果。"""
        if (win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd) == "行为分析工具条"
                and win32process.GetWindowThreadProcessId(hwnd)[1] == pid):
            windows.append(hwnd)
        return True

    for window in test_windows():
        inspect(window, None)
    assert len(windows) <= 1, windows
    return windows[0] if windows else 0


def verify(client, manifest, archived_id, pid):
    """用同一项目的旧档和自有进程核对入口、草稿、状态以及结果切换。"""
    nodes = open_project(client, manifest)  # 真实监控 Dock 下的工作台快照。

    def control(name):
        """使用稳定对象名返回唯一工具条控件。"""
        return unique(nodes(), lambda node: node["object_name"] == name)

    def press(node):
        """派发一次真实按钮动作，调用方另行验证业务回执。"""
        assert node["visible"] and node["enabled"], node
        dispatch(client, "action", object_id=node["id"], action="press", confirmed=True)

    def named(title):
        """按当前语言定位仅在当前页显示的动作。"""
        return unique(nodes(), lambda node: node["visible"] and node["name"] == title)

    def field(placeholder):
        """按桥接回读的输入提示定位当前页字段。"""
        return unique(nodes(), lambda node: node["visible"] and node.get("placeholder") == placeholder)

    def tab(title):
        """通过实际页签选择，不使用独立页面实例。"""
        tabs = control("action_analyze_tabs")  # 工作台唯一页签控件。
        dispatch(client, "set_field", object_id=tabs["id"], value=tabs["tabs"].index(title), confirmed=True)

    def table(headers):
        """用业务表头区分当前页的表格和详情字段视图。"""
        return unique(nodes(), lambda node: node["visible"] and node["class"] == "QTableView"
                      and headers <= set(read_table(client, node)["headers"]))

    def status():
        """返回跨页签共用的真实监控回执。"""
        return control("action_analyze_session_status")["name"]

    # 图标动作必须打开已登记的全局断点页，并保留同一张列表和未提交草稿。
    press(until(lambda: control("action_analyze_new_scan"), lambda node: node["enabled"]))
    press(control("action_analyze_open_breakpoints"))
    module = field("输入文件名，例如示例.exe")  # 表单定位依据为可见输入提示。
    location = field("例如 0x1234")  # 当前定位方式默认是 RVA。
    for line, value in ((module, "owned-example.exe"), (location, "20")):
        dispatch(client, "set_field", object_id=line["id"], value=value, confirmed=True)
    press(named("加入草稿"))
    drafts = table({"模块文件名", "断点位置"})  # 断点定义与原生绑定是两个状态。
    row = read_table(client, drafts)["rows"]
    assert len(row) == 1 and row[0][:2] == ["owned-example.exe", "RVA 0x20"], row
    dispatch(client, "set_field", object_id=module["id"], value="pending.exe", confirmed=True)
    tab("总览")
    press(control("action_analyze_open_breakpoints"))
    assert field("输入文件名，例如示例.exe")["value"] == "pending.exe"
    assert read_table(client, drafts)["rows"] == row
    print("QT_GLOBAL_BREAKPOINT_ENTRY_AND_DRAFT=PASS", flush=True)

    # 在同一会话中读取旧档，核对后台继续处理，返回后只发布活采样的行。
    tab("总览")
    target = control("action_analyze_target_pid")  # 测试脚本实际启动的合作进程。
    dispatch(client, "set_field", object_id=target["id"], value=str(pid), confirmed=True)
    press(control("action_analyze_start"))
    until(status, lambda text: text.startswith("正在监控"))
    events = table({"PID", "TID", "事件"})  # 实时与归档共用的事件模型。
    live = until(lambda: read_table(client, events), lambda data: len(data["rows"]) >= 2)

    # 浮出后同一组按钮继续派发动作。原生窗口验证置顶、标题区拖动命中和关闭归位。
    pinned = control("action_analyze_float_actions")  # 拖动前后应保持相同对象身份。
    stop = control("action_analyze_stop")
    press(pinned)
    tool = until(lambda: floating_window(client.pid), bool)
    assert win32gui.GetWindowLong(tool, win32con.GWL_EXSTYLE) & win32con.WS_EX_TOPMOST
    left, top, right, _ = win32gui.GetWindowRect(tool)  # 只操作本次创建的浮窗。
    _, content = win32gui.ClientToScreen(tool, (0, 0))  # 标题区结束处。
    middle = (left + right) // 2  # 标题中央避开关闭按钮和边框。
    assert any(win32gui.SendMessage(tool, win32con.WM_NCHITTEST, 0,
                                   (middle & 0xFFFF) | ((y & 0xFFFF) << 16)) == win32con.HTCAPTION
               for y in range(top, content))
    win32gui.SetWindowPos(tool, 0, left, top - 12 if top > 20 else top + 12, 0, 0,
                          win32con.SWP_NOACTIVATE | win32con.SWP_NOSIZE | win32con.SWP_NOZORDER)
    moved = win32gui.GetWindowRect(tool)[:2]  # 工具条保留本次会话最后位置。
    assert moved != (left, top)
    assert control("action_analyze_stop")["id"] == stop["id"]
    press(control("action_analyze_open_breakpoints"))
    assert field("输入文件名，例如示例.exe")["value"] == "pending.exe"
    assert floating_window(client.pid) == tool
    win32gui.PostMessage(tool, win32con.WM_CLOSE, 0, 0)
    until(lambda: floating_window(client.pid), lambda hwnd: hwnd == 0)
    tab("总览")
    assert control("action_analyze_float_actions")["id"] == pinned["id"]
    print("QT_FLOAT_TOOLBAR=PASS TOPMOST=True NATIVE_CAPTION=True CLOSE_REDOCK=True BUTTON_IDENTITIES_RETAINED=True", flush=True)

    # 目录选择按归档 UUID 解析，避开本次后台注册的新采样。
    tab("项目与采样")
    catalog = table({"采样名称"})
    saved = until(lambda: read_table(client, catalog), lambda data: any(archived_id in row for row in data["rows"]))
    index = next(i for i, row in enumerate(saved["rows"]) if archived_id in row and TITLE in row)
    dispatch(client, "select_row", object_id=catalog["id"], row=index, revision=saved["revision"], confirmed=True)
    press(until(lambda: control("action_analyze_sample_archive"), lambda node: node["enabled"]))
    archived = until(lambda: read_table(client, events), lambda data: any("WriteProcessMemory" in row for row in data["rows"]))
    assert len(archived["rows"]) == 5 and status().startswith("正在监控")
    press(control("action_analyze_follow_live"))
    current = until(lambda: read_table(client, events),
                    lambda data: len(data["rows"]) > len(live["rows"]) and not any("WriteProcessMemory" in row for row in data["rows"]))
    assert all(str(row[current["headers"].index("PID")]) == str(pid) for row in current["rows"])
    press(control("action_analyze_float_actions"))
    tool = until(lambda: floating_window(client.pid), bool)
    assert win32gui.GetWindowRect(tool)[:2] == moved
    press(control("action_analyze_stop"))
    receipt = until(status, lambda text: text.startswith("监控已停止"))
    assert not control("action_analyze_stop")["enabled"]
    press(control("action_analyze_float_actions"))
    until(lambda: floating_window(client.pid), lambda hwnd: hwnd == 0)
    print(f"QT_ARCHIVE_LIVE_TOOLBAR=PASS ARCHIVE_ROWS=5 LIVE_ROWS={len(current['rows'])} {receipt}", flush=True)


def main():
    """在固定测试目录构造归档，以本脚本独占的目标运行正式窗口。"""
    with fixture_directory() as directory:
        manifest, segment, _ = import_fixture(directory)  # 复用已核验的五类合成档案。
        archived_id = segment.parents[1].name  # 目录已登记样本，而非文件名猜测。
        with test_window() as client:
            with subprocess.Popen([sys.executable, "-B", "-c", "import sys; sys.stdin.buffer.read()"],
                                  stdin=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW) as target:
                try:
                    verify(client, manifest, archived_id, target.pid)
                finally:
                    # 只关闭父进程自己创建的输入；目标自行退出。
                    target.stdin.close()
                    assert target.wait(timeout=6) == 0


if __name__ == "__main__":
    main()
