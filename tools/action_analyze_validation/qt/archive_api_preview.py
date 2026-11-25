"""通过正式 Qt 窗口回放 CLI 导入的合成 API 归档。"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
from shutil import rmtree
import subprocess
import sys

from live_preview import ROOT, RELEASE, BridgeClient, close_gui, dispatch, open_workspace, unique, until

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
from api_evidence import EXE, TIMEOUT, archive_line, cli, packet
from project_v1 import raise_walk_error, regular_identity


SCRATCH = RELEASE / "action-analyze-qt-api-validation"  # 本次独占的固定 Release 测试目录。
TITLE = "Qt API archive validation"  # 项目目录中唯一的导入采样标题。
PREVIEW = "API 原包前缀（十六进制）"  # 共享详情中的字节字段。
UNKNOWN = "目标身份、实际写入范围、执行和归因未知。"  # 归档线索的证据限制。


def check_location(path, *, untracked=False):
    """核对固定 Release 路径，无返回值。删除测试文件之前要求 untracked。"""
    assert path.is_relative_to(RELEASE), path
    for ancestor in reversed(path.parents):
        if ancestor.is_relative_to(ROOT):
            regular_identity(ancestor)
    if os.path.lexists(path):
        regular_identity(path)
        assert path.resolve(strict=True) == path, path
    if untracked:
        tracked = subprocess.check_output(
            ["git", "ls-files", "-z", "--", path.relative_to(ROOT).as_posix()], cwd=ROOT, timeout=TIMEOUT
        )  # 只检查即将删除的固定路径。
        assert not tracked, path


@contextmanager
def fixture_directory(scratch=SCRATCH):
    """提供本进程独占的固定目录，确认身份及 Git 状态后清理。"""
    check_location(scratch, untracked=True)
    scratch.mkdir(exist_ok=False)
    identity = regular_identity(scratch)  # 防止清理时误删替换后的目录。
    try:
        yield scratch
    finally:
        check_location(scratch, untracked=True)
        assert regular_identity(scratch) == identity
        for parent, dirs, files in os.walk(scratch, followlinks=False, onerror=raise_walk_error):
            for name in dirs + files:
                regular_identity(Path(parent) / name)
        rmtree(scratch)
        assert not os.path.lexists(scratch)
        print(f"FIXTURE_REMOVED={scratch}", flush=True)


def import_fixture(directory):
    """用 CLI 创建和导入固定目录的离线夹具，返回清单、原始段及读回线索。"""
    project = directory / "project"  # CLI 专用空项目。
    result = subprocess.run(
        [EXE, "analyze", "session"], input=f'project create "{project}" Fixture\nquit\n'.encode(),
        capture_output=True, timeout=TIMEOUT, check=True,
    )  # 仅调用离线项目命令。
    manifest = project / "project.ksaproj"  # 真实窗口使用的清单。
    assert manifest.is_file(), result.stdout

    # 复用 CLI 合成包构造器。数据记录仅描述调用，不调用其 API。
    cases = [
        ("", "CreateRemoteThreadEx", packet("Other", "CreateRemoteThreadEx", 9), {}),
        ("memory-write", "WriteProcessMemory", packet("KernelBase", "WriteProcessMemory", 8, 0x52545631, status=299),
         {"processCreation100ns": "134400565183024180"}),
        ("apc-queue", "NtQueueApcThread", packet("NTDLL.DLL", "NtQueueApcThread", 9, result_kind=1), {}),
        ("", "NtWriteVirtualMemory", packet("ntdll", "NtWriteVirtualMemory", 9), {}),
        ("thread-create", "CreateRemoteThreadEx", packet("Kernel32.dll", "CreateRemoteThreadEx", 9, 0x52545631, returned=20), {}),
        ("thread-context", "SetThreadContext", packet("KernelBase", "SetThreadContext", 9), {}),
        ("section-map", "NtMapViewOfSection", packet("ntdll", "NtMapViewOfSection", 8), {}),
    ]
    source = directory / "events.jsonl"  # 合成的原始归档和导入后原字节基线。
    original = b"".join(archive_line(i, wire, **extra) for i, (_, _, wire, extra) in enumerate(cases, 1))
    source.write_bytes(original)
    receipt = cli("import", "--archive", source, "--project", project, "--title", TITLE)
    assert (receipt["status"], receipt["sourceRows"], receipt["clueRows"], receipt["coverage"]) == (
        "readback-verified", "7", "5", "unknown"
    ), receipt
    assert source.read_bytes() == original
    sample = receipt["sampleId"]  # 从实际导入回执绑定唯一采样。
    replay = cli("replay", "--project", project, "--sample", sample, "--packet", "1")
    expected = [(str(i), family, name, wire.hex()) for i, (family, name, wire, _) in enumerate(cases, 1) if family]
    rows = replay["rows"]  # 正式 CLI 对同一 Stored 段的完整回读。
    assert [(row["sourceSequence"], row["family"], row["api"], row["packet"]) for row in rows] == expected, rows
    assert all(row[key] is None for row in rows for key in ("targetIdentity", "completedWriteBytes", "executed", "attribution"))
    segment = project / "samples" / sample / "raw/00000000000000000001.ksaseg"  # 仅可变更本试验段。
    with EXE.open("rb") as image:
        print(f"CLI_SHA256={hashlib.file_digest(image, 'sha256').hexdigest()}", flush=True)
    print(f"CLI_SOURCE_ROWS={receipt['sourceRows']} CLI_CLUES={len(rows)} SAMPLE={sample}", flush=True)
    return manifest, segment, rows


@contextmanager
def test_window(theme="light"):
    """启动正式 Qt 并提供本次 PID 的桥接客户端，退出后恢复外观和停靠布局。"""
    from isolated_desktop import launch_gui, require_isolated_desktop

    require_isolated_desktop()
    # 主程序退出会写回布局，并可能停止已运行的驱动。已有实例或驱动活动时暂停验收。
    idle = subprocess.run(
        ["pwsh", "-NoProfile", "-Command",
         "if ((Get-Process -Name 'Ksword5.1' -ErrorAction SilentlyContinue) -or "
         "(Get-Service -Name 'KswordARK' -ErrorAction SilentlyContinue | Where-Object Status -ne Stopped)) { exit 1 }"],
        timeout=TIMEOUT,
    )
    assert idle.returncode == 0, "须在没有现有主程序、没有活动 KSwordARK 服务时运行窗口验收"
    executable = RELEASE / "Ksword5.1.exe"  # 已完成正式构建的唯一目标。
    settings = RELEASE / "Style/appearance_settings.json"  # 外观配置含启动与权限选项。
    layout = RELEASE / "config/ksword_ads_layout.bin"  # 主程序退出会写回停靠布局。
    originals = {}  # 在内存保存两个配置的原有字节或缺失状态。
    for path in (settings, layout):
        present = os.path.lexists(path)
        check_location(path, untracked=not present)
        originals[path] = path.read_bytes() if present else None

    draft = json.loads(originals[settings].decode("utf-8-sig")) if originals[settings] is not None else {}
    draft.update(startup_auto_request_admin=False, startup_auto_install_r0_driver=False,
                 startup_scale_recommend_prompt_disabled=True, dump_auto_check_enabled=False, mcp_auto_start=False,
                 ui_language="zh-CN", startup_default_tab_key="welcome", theme_mode=theme, detail_display_scheme="right")
    environment = dict(os.environ, QT_QPA_PLATFORM="windows:dialogs=none")  # 使用实际的 Qt 文件选择器。
    gui = None  # 只操作本脚本创建的子进程及其窗口。
    try:
        settings.write_text(json.dumps(draft, ensure_ascii=False), encoding="utf-8")
        gui = launch_gui([executable, "--mcp", "--mcp-no-auto-elevation"], cwd=RELEASE, env=environment)
        with executable.open("rb") as image:
            print(f"GUI_PID={gui.pid} THEME={theme} QT_SHA256={hashlib.file_digest(image, 'sha256').hexdigest()}", flush=True)
        yield BridgeClient(gui.pid)
    finally:
        try:
            if gui is not None:
                close_gui(gui)
                print(f"GUI_EXIT={gui.returncode}", flush=True)
        finally:
            # 进程收尾失败时也核对退出状态，避免窗口稍后再写回测试配置。
            assert gui is None or gui.poll() is not None, "窗口仍在运行，无法安全覆盖配置"
            for path, original in originals.items():
                check_location(path, untracked=original is None)
                if original is None:
                    path.unlink(missing_ok=True)
                    assert not os.path.lexists(path)
                else:
                    if not path.exists() or path.read_bytes() != original:
                        path.write_bytes(original)
                    assert path.read_bytes() == original
        print("APPEARANCE_AND_ADS_LAYOUT_RESTORED=True", flush=True)
        assert gui is None or gui.returncode == 0, "正式窗口未正常退出"


def read_table(client, view, parent_rows=()):
    """读取指定视图及可选父行，返回桥接结果的表头、行和修订。"""
    return client.call("read_table", {"object_id": view["id"], "row_count": 24, "column_count": 12,
                                      "parent_rows": list(parent_rows)})["data"]


def choose_project_path(client, button, path):
    """提交实际文件对话框，既适用于创建目录也适用于打开项目清单。"""
    reply = client.call("action", {"object_id": button["id"], "action": "press", "confirmed": True})
    assert reply["status"] == "accepted", reply

    def dialog():
        """从当前 Qt 模态根返回可用文件选择控件。"""
        return client.call("snapshot", {"max_nodes": 200, "depth": 8})["data"]["nodes"]

    controls = until(dialog, lambda result: result and result[0]["class"] == "QFileDialog")
    file_name = unique(controls, lambda n: n["visible"] and n["object_name"] == "fileNameEdit")
    dispatch(client, "set_field", object_id=file_name["id"], value=str(path), submit=True, confirmed=True)


def open_project(client, manifest):
    """沿正式窗口导航打开项目，返回工作台快照读取函数。"""
    nodes, active = open_workspace(client)
    button = unique(active, lambda n: n["visible"] and n["type"] == "button" and n["name"] == "打开行为分析项目")
    choose_project_path(client, button, manifest)
    return nodes


def open_project_sample(client, manifest, sample, *, title=TITLE, clue=None):
    """沿真实目录打开 manifest 中指定采样，返回工作台快照读取函数。"""
    nodes = open_project(client, manifest)
    tabs = unique(nodes(), lambda n: n["object_name"] == "action_analyze_tabs")
    dispatch(client, "set_field", object_id=tabs["id"], value=tabs["tabs"].index("项目与采样"), confirmed=True)

    # 通过目录真实表头和 UUID 绑定所选采样，不依赖首行或当前焦点。
    tables = [n for n in nodes() if n["visible"] and n["class"] == "QTableView"]
    catalog = unique(tables, lambda n: "采样名称" in read_table(client, n)["headers"])
    model = until(lambda: read_table(client, catalog), lambda data: any(sample in row for row in data["rows"]))
    row_index = next(index for index, row in enumerate(model["rows"]) if sample in row and title in row)
    dispatch(client, "select_row", object_id=catalog["id"], row=row_index, revision=model["revision"], confirmed=True)
    launch = until(lambda: unique(nodes(), lambda n: n["object_name"] == "action_analyze_sample_archive"),
                    lambda n: n["visible"] and n["enabled"])
    if title == TITLE:
        # 检查选择已经触发分析，归档总览仍未打开。
        def analysis_groups():
            """从当前可见报告收集分类分区以及证据坐标。"""
            values = set()  # 卡片模式的无障碍标签和共享字段模型提供同一内容。
            for view in nodes():
                if not view["visible"]:
                    continue
                values.add(view["name"])
                if view["type"] != "item_view" or view["id"] == catalog["id"]:
                    continue
                for index, row in enumerate(read_table(client, view)["rows"]):
                    values.update(str(cell) for cell in row)
                    if row and row[0] in {"归档分类流程", "敏感 API 线索"}:
                        for entry in read_table(client, view, [index])["rows"]:
                            values.update(str(cell) for cell in entry)
            return values

        groups = until(analysis_groups, lambda values: any("敏感 API 线索" == value for value in values))
        assert "归档分类流程" in groups and all(not node["visible"] for node in nodes()
                                                if node["object_name"] == "action_analyze_target_pid"), groups
        print(f"QT_SAMPLE_ANALYSIS_ON_SELECTION=PASS SAMPLE={sample}", flush=True)
    if clue is not None:
        picker = unique(nodes(), lambda n: n["object_name"] == "action_analyze_sample_clue")  # 当前采样的定位选项。
        assert picker["visible"] and picker["enabled"], picker
        dispatch(client, "set_field", object_id=picker["id"], value=clue, confirmed=True)
    dispatch(client, "action", object_id=launch["id"], action="press", confirmed=True)
    return nodes


def verify_window(client, manifest, segment, expected):
    """核对真实表格、共享详情、显示筛选以及自有归档坏尾的原位恢复。"""
    sample = segment.parents[1].name  # 同一 Stored 样本的 ID。
    nodes = open_project_sample(client, manifest, sample, clue=1)

    def status_has(text):
        """根据当前可见标签检查回执中的指定文本。"""
        return any(n["visible"] and text in n["name"] for n in nodes())

    until(lambda: status_has("已核验 5 条归档 API 线索。覆盖范围未知。"), bool)
    assert status_has("归档项目和采样 ID 均匹配。")
    tables = [n for n in nodes() if n["visible"] and n["class"] == "QTableView"]
    table = unique(tables, lambda n: {"PID", "TID", "事件"} <= set(read_table(client, n)["headers"]))
    full = read_table(client, table)  # 列表恢复时比较同一批行。
    columns = tuple(full["headers"].index(name) for name in ("事件", "PID", "TID"))
    assert sorted(tuple(str(row[column]) for column in columns) for row in full["rows"]) == sorted(
        (row["api"], str(row["pid"]), str(row["tid"])) for row in expected
    ), full

    def details():
        """返回可见共享详情中的当前线索字段与说明。"""
        for view in nodes():
            if not view["visible"] or view["type"] != "item_view" or view["id"] == table["id"]:
                continue
            root = read_table(client, view)["rows"]  # 单组可展平或保留父节点。
            for index, row in enumerate(root):
                if row and row[0] == "归档 API 线索":
                    root = read_table(client, view, [index])["rows"]
                    break
            fields = {str(row[0]): str(row[1]) for row in root if len(row) >= 2}
            if PREVIEW in fields:
                return fields, any(UNKNOWN in row for row in root)
        return {}, False

    # 选中一个早于最新项的线索，进入总览后对照采样、原始记录和来源行号。
    selected = expected[0]  # 导入回执给出的第一个已核验线索。
    fields, _ = until(details, lambda value: value[0].get("事件") == selected["api"])
    assert (fields["采样 ID"], fields["记录序号"], fields["源归档行号"]) == (
        sample, selected["rawSequence"], selected["sourceSequence"]), fields
    print(f"QT_SAMPLE_TRACE_TO_RECORD=PASS RAW={fields['记录序号']}", flush=True)

    # 逐行对照 CLI 保存的原包、原始坐标、来源头及证据限制。
    for row in reversed(expected):
        index = next(i for i, cells in enumerate(full["rows"]) if cells[columns[0]] == row["api"])
        dispatch(client, "select_row", object_id=table["id"], row=index, revision=full["revision"], confirmed=True)
        fields, unknown = until(details, lambda value: value[0].get("事件") == row["api"])
        assert unknown, fields
        assert fields["采样 ID"] == sample and int(fields["文件偏移（字节）"]) > 0, fields
        for field, key in (("线索类别", "family"), ("记录序号", "rawSequence"), ("源归档行号", "sourceSequence"),
                           ("FILETIME", "time100ns"), ("来源头 PID", "pid"), ("来源头 TID", "tid")):
            assert fields[field] == str(row[key]), (field, fields, row)
        assert fields[PREVIEW] == bytes.fromhex(row["packet"])[:64].hex(" "), fields
        if row["archivedCallerCreation100ns"] is not None:
            assert fields["来源声明的调用方创建时间"] == row["archivedCallerCreation100ns"], fields
        else:
            assert fields["来源声明的调用方创建时间"] in {"未知", "—"}, fields
        print(f"QT_CLUE={row['family']} RAW={row['rawSequence']} SOURCE={row['sourceSequence']} PREVIEW_BYTES=64", flush=True)

    # API 开关可用，ETW 开关不可用。用关键字隐去选择并验证显示范围回退。
    api = unique(nodes(), lambda n: n["visible"] and n["class"] == "QCheckBox" and n["name"] == "API")
    etw = unique(nodes(), lambda n: n["visible"] and n["class"] == "QCheckBox" and n["name"] == "ETW")
    keyword = unique(nodes(), lambda n: n["visible"] and n["name"] == "记录关键字")
    assert api["enabled"] and not etw["enabled"]
    dispatch(client, "set_field", object_id=api["id"], value=True, confirmed=True)
    assert read_table(client, table)["rows"] == full["rows"]
    dispatch(client, "set_field", object_id=keyword["id"], value="section-map", confirmed=True)
    visible = until(lambda: read_table(client, table)["rows"], lambda rows: len(rows) == 1)
    assert visible[0][columns[0]] == "NtMapViewOfSection"
    assert details()[0].get("事件") == expected[0]["api"]
    dispatch(client, "set_field", object_id=keyword["id"], value="", confirmed=True)
    dispatch(client, "set_field", object_id=api["id"], value=False, confirmed=True)
    until(lambda: read_table(client, table)["rows"], lambda rows: rows == full["rows"])
    before = details()  # 用当前详情与表行检测坏尾是否覆盖已显示的有效结果。
    assert before[0].get("事件") == expected[0]["api"] and before[1]
    print("QT_FILTER_ROWS=5,1,5 SELECTION_RETAINED=True", flush=True)

    retry = unique(nodes(), lambda n: n["visible"] and n["name"] == "重新读取归档")
    clean = segment.read_bytes()  # 仅对本次自有归档截掉终段的最后一字节。
    try:
        segment.write_bytes(clean[:-1])
        dispatch(client, "action", object_id=retry["id"], action="press", confirmed=True)
        until(lambda: status_has("仍显示上次提交的结果。"), bool)
        assert status_has("归档尾部不完整。") or status_has("归档封装或记录校验失败。")
        assert read_table(client, table)["rows"] == full["rows"] and details() == before
    finally:
        segment.write_bytes(clean)
    dispatch(client, "action", object_id=retry["id"], action="press", confirmed=True)
    until(lambda: status_has("归档已读至文件末尾。"), bool)
    assert read_table(client, table)["rows"] == full["rows"] and details() == before
    print("QT_BAD_TAIL_REJECTED=True QT_RETRY_RESTORED=True", flush=True)


def main():
    """从统一 Release 启动正式 CLI 与 Qt，完成回放和清理后打印通过回执。"""
    arguments = sys.argv[1:]  # 独立桌面启动器转发的可选主题参数。
    assert arguments in ([], ["--dark"]), arguments
    with fixture_directory() as directory:
        manifest, segment, expected = import_fixture(directory)
        with test_window("dark" if arguments else "light") as client:
            verify_window(client, manifest, segment, expected)
    print("QT_API_REPLAY=PASS", flush=True)


if __name__ == "__main__":
    main()
