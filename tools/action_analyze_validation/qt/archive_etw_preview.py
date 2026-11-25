"""在正式 Qt 工作台中打开同一个 CLI ETW 段，核对筛选与共享详情。"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from live_preview import RELEASE, BridgeClient, close_gui, dispatch, open_overview, unique, until

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
from live_etw import run


def preview(segment, first_event):
    """只操作本次启动的 Qt 窗口，并恢复原有外观配置字节。"""
    executable = RELEASE / "Ksword5.1.exe"
    settings = RELEASE / "Style/appearance_settings.json"
    assert not settings.is_symlink()
    original = settings.read_bytes()  # 测试前的正式配置。
    draft = json.loads(original.decode("utf-8-sig"))
    draft.update(startup_auto_request_admin=False, startup_auto_install_r0_driver=False,
                 startup_scale_recommend_prompt_disabled=True, dump_auto_check_enabled=False,
                 ui_language="zh-CN", startup_default_tab_key="welcome", theme_mode="light",
                 detail_display_scheme="right")
    gui = None
    try:
        settings.write_text(json.dumps(draft, ensure_ascii=False), encoding="utf-8")
        # 使用 Qt 窗口文件选择器，避免系统文件对话框跨进程可访问性差异。
        environment = dict(os.environ, QT_QPA_PLATFORM="windows:dialogs=none")
        gui = subprocess.Popen([executable, "--mcp", "--mcp-no-auto-elevation"], cwd=RELEASE, env=environment,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        client = BridgeClient(gui.pid)
        nodes, active = open_overview(client)
        def dialog():
            return client.call("snapshot", {"max_nodes": 200, "depth": 8})["data"]["nodes"]

        def choose(button, path):
            """按实际按钮打开模态选择器，并通过文件名输入框确认。"""
            response = client.call("action", {"object_id": button["id"], "action": "press", "confirmed": True})
            assert response["status"] == "accepted", response
            controls = until(dialog, lambda result: result and result[0]["class"] == "QFileDialog")
            name = unique(controls, lambda n: n["visible"] and n["object_name"] == "fileNameEdit")
            dispatch(client, "set_field", object_id=name["id"], value=str(path), submit=True, confirmed=True)

        # 真实项目目录路由，与直接打开独立文件使用同一总览。
        open_project = unique(active, lambda n: n["visible"] and n["type"] == "button" and n["name"] == "打开行为分析项目")
        choose(open_project, segment.parents[3] / "project.ksaproj")
        tab_view = unique(nodes(), lambda n: n["object_name"] == "action_analyze_tabs")
        catalog_index = tab_view["tabs"].index("项目与采样")
        dispatch(client, "set_field", object_id=tab_view["id"], value=catalog_index, confirmed=True)

        def read(view, parent_rows=None):
            return client.call("read_table", {"object_id": view["id"], "row_count": 30, "column_count": 12,
                                              "parent_rows": parent_rows or []})["data"]

        catalog = unique([n for n in nodes() if n["visible"] and n["class"] == "QTableView"],
                         lambda n: "采样名称" in read(n)["headers"])
        samples = until(lambda: read(catalog), lambda value: any(segment.parents[1].name in row for row in value["rows"]))
        sample_index = next(index for index, row in enumerate(samples["rows"]) if segment.parents[1].name in row)
        dispatch(client, "select_row", object_id=catalog["id"], row=sample_index,
                 revision=samples["revision"], confirmed=True)
        sample_action = until(lambda: unique(nodes(), lambda n: n["object_name"] == "action_analyze_sample_archive"),
                              lambda n: n["enabled"] and n["visible"])
        dispatch(client, "action", object_id=sample_action["id"], action="press", confirmed=True)

        # 以实际表头选择列表，记录筛选前后再恢复的真实可见行数。
        table = unique([n for n in nodes() if n["visible"] and n["class"] == "QTableView"],
                       lambda n: {"PID", "TID"} <= set(read(n)["headers"]))
        full = until(lambda: read(table), lambda value: len(value["rows"]) == 14)
        etw = unique(nodes(), lambda n: n["visible"] and n["type"] == "button" and n["name"] == "ETW")
        assert etw["enabled"]
        dispatch(client, "set_field", object_id=etw["id"], value=True, confirmed=True)
        filtered = until(lambda: read(table), lambda value: len(value["rows"]) == 12)
        assert all(any(str(cell).startswith("ETW 事件 ") for cell in row) for row in filtered["rows"])
        dispatch(client, "select_row", object_id=table["id"], row=0, revision=filtered["revision"], confirmed=True)

        def selected_fields():
            """读取真实详情模型，兼容共享组件省略单组标题的呈现。"""
            for view in nodes():
                if not view["visible"] or view["type"] != "item_view" or view["id"] == table["id"]:
                    continue
                rows = read(view)["rows"]
                fields = {row[0]: row[1] for row in rows if len(row) >= 2}
                if "ETW 字节预览（十六进制）" in fields:
                    return fields
                for index, row in enumerate(rows):
                    if row and row[0] == "归档记录":
                        return {field[0]: field[1] for field in read(view, [index])["rows"]}
            return {}

        fields = until(selected_fields, lambda value: "ETW 字节预览（十六进制）" in value)
        metadata, payload = first_event  # 独立检查器从该段读回的首条真实事件。
        assert fields["ETW 字节预览（十六进制）"] == payload.hex(" ")
        assert fields["ETW 来源代次"] == metadata["sourceEpoch"]
        assert str(fields["来源头 PID"]) == str(metadata["headerPid"])
        dispatch(client, "set_field", object_id=etw["id"], value=False, confirmed=True)
        restored = until(lambda: read(table), lambda value: value["rows"] == full["rows"])
        assert selected_fields() == fields
        assert any(n["visible"] and n["name"] == "归档项目和采样 ID 均匹配。" for n in nodes())

        # 用同一测试项目中另一条完整段验证错采样拒绝和同一请求的原位重试。
        other = next(path for path in segment.parents[2].glob("*/raw/*.ksaseg") if path != segment)
        original_archive = segment.read_bytes()  # 测试项目仍由 CLI 夹具统一清理。
        retry = unique(nodes(), lambda n: n["visible"] and n["name"] == "重新读取归档")

        def status_has(text):
            return any(n["visible"] and text in n["name"] for n in nodes())

        assert status_has("已验证项目检查点。")
        try:
            segment.write_bytes(other.read_bytes())
            dispatch(client, "action", object_id=retry["id"], action="press", confirmed=True)
            until(lambda: status_has("无法验证项目检查点或其引用的归档数据。"), bool)
            assert status_has("仍显示上次提交的结果。")
            assert read(table)["rows"] == full["rows"] and selected_fields() == fields
        finally:
            segment.write_bytes(original_archive)
        dispatch(client, "action", object_id=retry["id"], action="press", confirmed=True)
        until(lambda: status_has("已验证项目检查点。"), bool)
        assert read(table)["rows"] == full["rows"] and selected_fields() == fields

        # 标记存在时，两个流的尾部都不参与回放。标记缺失时，明确呈现旧档回退。
        records = segment.parents[1] / "records" / segment.name
        marker = segment.parents[1] / "checkpoints/00000000000000000001.json"
        records_bytes = records.read_bytes()  # 已发布的 Coverage 段。
        marker_bytes = marker.read_bytes()  # 用于恢复本次夹具的原始标记。
        prefix_text = f"已校验前缀 {len(original_archive)} / {len(original_archive) + 4} 字节。"
        try:
            segment.write_bytes(original_archive + b"tail")
            records.write_bytes(records_bytes + b"tail")
            dispatch(client, "action", object_id=retry["id"], action="press", confirmed=True)
            until(lambda: status_has(prefix_text), bool)
            assert status_has("已验证项目检查点。")
            assert read(table)["rows"] == full["rows"] and selected_fields() == fields
        finally:
            segment.write_bytes(original_archive)
            records.write_bytes(records_bytes)
        try:
            records.unlink()
            dispatch(client, "action", object_id=retry["id"], action="press", confirmed=True)
            until(lambda: status_has("无法验证项目检查点或其引用的归档数据。"), bool)
            assert status_has("仍显示上次提交的结果。")
            assert read(table)["rows"] == full["rows"] and selected_fields() == fields
        finally:
            records.write_bytes(records_bytes)
        try:
            marker.unlink()
            dispatch(client, "action", object_id=retry["id"], action="press", confirmed=True)
            until(lambda: status_has("该归档没有已发布的检查点。"), bool)
            assert read(table)["rows"] == full["rows"] and selected_fields() == fields
        finally:
            marker.write_bytes(marker_bytes)
        dispatch(client, "action", object_id=retry["id"], action="press", confirmed=True)
        until(lambda: status_has("已验证项目检查点。"), bool)
        print(json.dumps({"qtSha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "rows": len(restored["rows"]),
                          "filtered": len(filtered["rows"]), "detail": fields}, ensure_ascii=False), flush=True)
        print("QT_ETW_REPLAY=PASS", flush=True)
        print("QT_WRONG_SAMPLE_RETRY=PASS", flush=True)
        print("QT_CHECKPOINT_TAIL_AND_LEGACY=PASS", flush=True)
    finally:
        try:
            if gui:
                close_gui(gui)
                print(f"GUI_EXIT={gui.returncode}", flush=True)
        finally:
            settings.write_bytes(original)
            assert settings.read_bytes() == original
            print("SETTINGS_RESTORED=True", flush=True)


if __name__ == "__main__":
    run(inspect_gui=preview)
