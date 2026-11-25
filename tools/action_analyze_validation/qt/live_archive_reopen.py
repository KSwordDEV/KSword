"""在正式 Qt 中采集自有进程，重启产品后从项目页回放同一次采样。"""
import json
from pathlib import Path
import sys

from archive_api_preview import (
    choose_project_path, fixture_directory, open_project_sample, read_table, test_window,
)
from live_etw import Child, PROVIDER, decode_raw
from live_preview import RELEASE, dispatch, open_workspace, unique, until

SCRATCH = RELEASE / "ActionAnalyzeQtLiveArchiveValidation"  # 固定且由本测试独占的正式 Release 子目录。
TERMINAL_STATUS = "已验证 Qt 原始归档和终止记录。"  # 回放成功文本。
PREFIX_STATUS = "已验证 Qt 原始归档前缀。"  # 缺少终止段时的状态文本。


def visible(nodes, name):
    """根据现有控件的稳定对象名查找可见对象。"""
    return unique(nodes(), lambda n: n["visible"] and n["object_name"] == name)


def status_has(nodes, text):
    """检查状态文案是否确实出现在真实窗口。"""
    return any(n["visible"] and text in n["name"] for n in nodes())


def verify_breakpoint_definition(client, nodes, *, save=False):
    """核对正式项目中的离线定义，首次运行时明确保存。"""
    tabs = visible(nodes, "action_analyze_tabs")
    dispatch(client, "action", object_id=visible(nodes, "action_analyze_open_breakpoints")["id"],
             action="press", confirmed=True)
    if save:
        for placeholder, value in (("输入文件名，例如示例.exe", "owned-example.exe"), ("例如 0x1234", "20")):
            line = unique(nodes(), lambda n: n["visible"] and n.get("placeholder") == placeholder)
            dispatch(client, "set_field", object_id=line["id"], value=value, confirmed=True)
        for name in ("加入草稿", "保存项目断点"):
            button = unique(nodes(), lambda n: n["visible"] and n["name"] == name)
            assert button["enabled"], button
            dispatch(client, "action", object_id=button["id"], action="press", confirmed=True)
        until(lambda: status_has(nodes, "已保存项目断点。"), bool)
    table = unique(nodes(), lambda n: n["visible"] and n["class"] == "QTableView"
                   and {"模块文件名", "断点位置"} <= set(read_table(client, n)["headers"]))
    assert [row[:2] for row in read_table(client, table)["rows"]] == [["owned-example.exe", "RVA 0x20"]]
    assert status_has(nodes, "原生断点状态：未绑定。")
    dispatch(client, "set_field", object_id=tabs["id"], value=tabs["tabs"].index("总览"), confirmed=True)


def capture(client, manifest, producer, identity):
    """从正式入口开始和停止采样，返回落盘段和来源回执。"""
    nodes, _ = open_workspace(client)  # 新实例应直接进入项目目录。
    create = visible(nodes, "action_analyze_create_project")  # 同一工具带在空态提供创建入口。
    new_scan = visible(nodes, "action_analyze_new_scan")  # 绑定以前不会扫描任意目标。
    assert create["enabled"] and not new_scan["enabled"]
    assert not any(n["visible"] for n in nodes() if n["object_name"] == "action_analyze_target_pid")
    choose_project_path(client, create, manifest.parent)
    until(lambda: status_has(nodes, "项目目录已读取，尚无采样。"), bool)
    assert manifest.is_file() and visible(nodes, "action_analyze_new_scan")["enabled"]
    dispatch(client, "action", object_id=new_scan["id"], action="press", confirmed=True)
    print("QT_DEFAULT_PROJECT_CREATE_AND_NEW_SCAN=PASS", flush=True)
    verify_breakpoint_definition(client, nodes, save=True)
    revision = json.loads(manifest.read_bytes())["currentRevisionId"]  # 首次写入发布的定义所属修订。
    for name, value in (("action_analyze_target_pid", str(identity["pid"])),
                        ("action_analyze_etw_provider", "{" + str(PROVIDER) + "}")):
        dispatch(client, "set_field", object_id=visible(nodes, name)["id"], value=value, confirmed=True)
    dispatch(client, "action", object_id=visible(nodes, "action_analyze_start")["id"], action="press", confirmed=True)

    def session_status():
        """读取采集和归档共用的实际回执。"""
        return visible(nodes, "action_analyze_session_status")["name"]

    coverage = until(session_status, lambda s: "ETW 采集中" in s or "ETW 不可用" in s)
    if "ETW 采集中" in coverage:
        producer.send("write")  # 自有样本发出 12 个带内容的事件，Qt 后端只保存这些事件的头。
        assert producer.next()["operations"] == 12
    until(session_status, lambda s: "已核验 2 个原始段" in s, timeout=25)
    archive = visible(nodes, "action_analyze_open_capture_archive")  # 工具条按采集实例打开已核验前缀。
    assert archive["enabled"]
    dispatch(client, "action", object_id=archive["id"], action="press", confirmed=True)
    until(lambda: status_has(nodes, PREFIX_STATUS), bool)
    assert session_status().startswith("正在监控")
    dispatch(client, "action", object_id=visible(nodes, "action_analyze_stop")["id"], action="press", confirmed=True)
    receipt = until(session_status, lambda s: s.startswith("监控已停止") and "归档已收尾" in s)
    dispatch(client, "action", object_id=archive["id"], action="press", confirmed=True)
    until(lambda: status_has(nodes, TERMINAL_STATUS), bool)
    sample = unique(list((manifest.parent / "samples").iterdir()), lambda path: path.is_dir())
    snapshot_path = unique(list((sample / "snapshots").glob("*.json")), lambda path: path.is_file())
    frozen = json.loads(snapshot_path.read_bytes())  # 直接核对采样冻结的配置，不从当前项目补写。
    assert frozen["revisionId"] == revision, frozen
    definitions = frozen["config"]["breakpointDefinitions"]
    assert len(definitions) == 1 and definitions[0]["breakpointDefinitionId"], definitions
    print(f"QT_BREAKPOINT_SAVED_AND_FROZEN=PASS REVISION={revision}", flush=True)
    segments = sorted((sample / "raw").glob("*.ksaseg"))  # 只读取刚登记的自有采样。
    assert len(segments) >= 3 and not (sample / "records").exists() and not (sample / "checkpoints").exists()
    print(json.dumps({"coverage": coverage, "receipt": receipt, "sample": sample.name,
                      "segments": len(segments)}, ensure_ascii=False), flush=True)

    # 复用同一项目的扫描入口开始第二轮，旧采样及其文件仍可定位。
    dispatch(client, "action", object_id=new_scan["id"], action="press", confirmed=True)
    provider = visible(nodes, "action_analyze_etw_provider")  # 第二轮只需进程区间证据。
    dispatch(client, "set_field", object_id=provider["id"], value="", confirmed=True)
    dispatch(client, "action", object_id=visible(nodes, "action_analyze_start")["id"], action="press", confirmed=True)
    until(session_status, lambda text: text.startswith("正在监控") and "已核验 1 个原始段" in text)
    dispatch(client, "action", object_id=visible(nodes, "action_analyze_stop")["id"], action="press", confirmed=True)
    until(session_status, lambda text: text.startswith("监控已停止") and "归档已收尾" in text)
    samples = list((manifest.parent / "samples").iterdir())  # 公开样本目录中的两个独立身份。
    assert len(samples) == 2 and sample in samples and all(path.is_file() for path in segments)
    tabs = visible(nodes, "action_analyze_tabs")  # 在本轮仍使用同一项目工作台。
    dispatch(client, "set_field", object_id=tabs["id"], value=tabs["tabs"].index("项目与采样"), confirmed=True)
    catalog = unique(nodes(), lambda n: n["visible"] and n["class"] == "QTableView"
                     and "采样名称" in read_table(client, n)["headers"])
    present = until(lambda: read_table(client, catalog), lambda model: len(model["rows"]) == 2)
    assert {row[present["headers"].index("采样 ID")] for row in present["rows"]} == {entry.name for entry in samples}
    print("QT_TWO_SCANS_ONE_PROJECT=PASS", flush=True)
    return segments, "ETW 采集中" in coverage


def inspect_raw(segments, etw_active, identity):
    """独立解析正式 Qt 写入的 Stored 原字节，核对归档坐标与终止记录。"""
    observations = []  # 仅保存实际观测与其原始段号和封装序号。
    raw_sequence = 1  # 封装序号从 1 跨段连续。
    terminal = None  # 终止记录必须为末段唯一记录。
    for ordinal, path in enumerate(segments, 1):
        assert path.name == f"{ordinal:020d}.ksaseg"
        records, _ = decode_raw(path, raw_sequence)
        assert records
        for metadata, inline in records:
            assert not inline and int(metadata["headerPid"]) == identity["pid"] and terminal is None
            kind = metadata["kind"]
            if kind == "qt-live-end-v1":
                assert ordinal == len(segments) and len(records) == 1
                terminal = metadata
            else:
                assert kind in {"qt-etw-header-v1", "qt-process-activity-v1"}, metadata
                observations.append((ordinal, raw_sequence, metadata))
            raw_sequence += 1
    assert terminal and terminal["reason"] == "requested"
    assert terminal["creationFileTime"] == identity["creationFileTime"]
    assert int(terminal["observed"]) - int(terminal["archiveQueueDropped"]) == len(observations)
    assert len({ordinal for ordinal, _, _ in observations}) >= 2
    headers = sum(metadata["kind"] == "qt-etw-header-v1" for _, _, metadata in observations)
    assert (headers == 12) if etw_active else (headers == 0), headers
    print(f"QT_STORED_OBSERVATIONS={len(observations)} QT_STORED_ETW_HEADERS={headers}", flush=True)
    return observations, headers


def verify_window(client, manifest, segments, observations, headers, pid):
    """用新产品进程回读项目，验证中间前缀、完整回放、详情和坏段重试。"""
    terminal = segments[-1]  # 短暂移走终止段以验证单独的中间前缀反馈。
    final_bytes = terminal.read_bytes()
    terminal.unlink()
    try:
        nodes = open_project_sample(client, manifest, segments[0].parents[1].name, title=f"PID {pid}")
        until(lambda: status_has(nodes, PREFIX_STATUS), bool)
        assert status_has(nodes, "归档尚未发布有效终段。")
        assert status_has(nodes, f"已验证至第 {len(segments) - 1} 段。")
    finally:
        terminal.write_bytes(final_bytes)
    table = unique([n for n in nodes() if n["visible"] and n["class"] == "QTableView"],
                   lambda n: {"PID", "TID", "事件"} <= set(read_table(client, n)["headers"]))
    retry = unique(nodes(), lambda n: n["visible"] and n["name"] == "重新读取归档")
    verify_breakpoint_definition(client, nodes)
    print("QT_BREAKPOINT_DEFINITIONS_REOPEN=PASS", flush=True)

    def reread(text):
        """使用同一已冻结采样的原位重读按钮等待本次解析的回执。"""
        dispatch(client, "action", object_id=retry["id"], action="press", confirmed=True)
        until(lambda: status_has(nodes, text), bool)

    reread(TERMINAL_STATUS)
    assert status_has(nodes, f"已验证至第 {len(segments)} 段。")
    assert status_has(nodes, f"已验证 {len(observations) + 1} 条归档记录。")
    assert not status_has(nodes, "已验证项目检查点。")
    etw = unique(nodes(), lambda n: n["visible"] and n["name"] == "ETW" and n["class"] == "QCheckBox")
    assert etw["enabled"] == bool(headers)
    if headers:
        dispatch(client, "set_field", object_id=etw["id"], value=True, confirmed=True)
    full = until(lambda: read_table(client, table), lambda m: len(m["rows"]) == min(24, headers or len(observations)))
    dispatch(client, "select_row", object_id=table["id"], row=0, revision=full["revision"], confirmed=True)

    def details():
        """读取共享字段详情，兼容单节展平与树形展示。"""
        for view in nodes():
            if not view["visible"] or view["type"] != "item_view" or view["id"] == table["id"]:
                continue
            rows = read_table(client, view)["rows"]
            for index, row in enumerate(rows):
                if row and row[0] in {"归档记录", "进程活动分析"}:
                    rows = read_table(client, view, [index])["rows"]
                    break
            fields = {str(row[0]): str(row[1]) for row in rows if len(row) >= 2}
            if "原采集序号" in fields:
                return fields, any("此记录仅保存 ETW 报头，未采集载荷。" in row for row in rows)
        return {}, False

    prior = until(details, lambda view: bool(view[0]))
    fields, header_note = prior
    ordinal, sequence, record = next(row for row in observations if row[1] == int(fields["记录序号"]))
    assert fields["归档段号"] == str(ordinal) and fields["原采集序号"] == record["liveSequence"]
    assert fields["采样 ID"] == segments[0].parents[1].name and int(fields["文件偏移（字节）"]) > 0
    if headers:
        assert header_note and fields["FILETIME"] == record["fileTime"] and fields["来源头 PID"] == str(pid)
        assert "ETW 原始载荷字节数" not in fields and "ETW 字节预览（十六进制）" not in fields
    else:
        assert fields["进程创建时间（FILETIME）"] == record["creationFileTime"]

    middle = segments[1]  # 只修改自有夹具的第二段，破坏其完整文件边界。
    original = middle.read_bytes()
    try:
        middle.write_bytes(original + b"tail")
        reread("第 2 段校验失败。")
        assert status_has(nodes, "已验证至第 1 段。") and status_has(nodes, "仍显示上次提交的结果。")
        assert read_table(client, table)["rows"] == full["rows"] and details() == prior
    finally:
        middle.write_bytes(original)
    reread(TERMINAL_STATUS)
    assert read_table(client, table)["rows"] == full["rows"] and details() == prior
    print(f"QT_RAW_PREFIX=PASS QT_RAW_BAD_MIDDLE_RETRY=PASS SELECTED_RAW_SEQUENCE={sequence}", flush=True)


def main():
    """在固定夹具目录运行两个正式 Qt 进程和一个自有遥测进程。"""
    with fixture_directory(SCRATCH) as directory:
        manifest = directory / "project" / "project.ksaproj"  # 创建操作在正式窗口发起。
        script = Path(__file__).resolve().parents[1] / "cli/live_etw.py"
        producer = Child([sys.executable, "-B", script, "--sample", directory / "sample.bin"])
        try:
            identity = producer.next()  # 自有进程直接回读的 PID 和创建时间。
            assert identity["pid"] == producer.process.pid
            with test_window() as client:
                segments, etw_active = capture(client, manifest, producer, identity)
            producer.send("exit")
            assert producer.process.wait(timeout=8) == 0
        finally:
            producer.stop()
        observations, headers = inspect_raw(segments, etw_active, identity)
        with test_window() as client:
            verify_window(client, manifest, segments, observations, headers, identity["pid"])
    print(f"QT_LIVE_ARCHIVE_REOPEN=PASS NATIVE_ETW_HEADERS={headers}", flush=True)


if __name__ == "__main__":
    main()
