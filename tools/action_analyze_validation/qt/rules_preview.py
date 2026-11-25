"""用正式 Qt 桥核验合成规则草稿和同一份 Stored API 归档。"""

import json
from pathlib import Path

from archive_api_preview import RELEASE, fixture_directory, import_fixture, test_window
from live_preview import dispatch, open_overview, unique, until


SCRATCH = RELEASE / "action-analyze-qt-rules-validation"  # 规则验证独占的固定目录。
VALIDATE = "校验规则"  # 检查草稿结构与谓词，不运行回放。
REPLAY = "回放合成事件"  # 运行当前草稿输入的合成事件。
PRESETS = "运行归档预置"  # 回放显式选择的离线段，显示两组汇总和五类观测。
STALE = "当前草稿已变化，以下为上次检查的结果。"  # 回执仍属于早先冻结的检查。
ARCHIVE_ERROR = "归档预置失败："  # 错误独立于最近成功回执。


class RulesPage:
    """在已启动的正式窗口中定位规则页，通过其控件发起操作并读回真实状态。"""

    def __init__(self, client):
        """接受本次正式窗口的桥接客户端，通过工作台切换至规则子页。"""
        self.client = client  # 已绑定本测试创建的窗口 PID。
        self.nodes, active = open_overview(client)  # 沿用监控 Dock 的目录导航。
        tabs = unique(active, lambda node: node["object_name"] == "action_analyze_tabs")
        dispatch(client, "set_field", object_id=tabs["id"], value=tabs["tabs"].index("行为规则"), confirmed=True)
        until(self.nodes, lambda rows: any(node["visible"] and node["object_name"] == "ks_behavior_rule_editor"
                                           for node in rows))
        print("NAVIGATION=Monitor/ActionAnalyze/Rules", flush=True)

    def button(self, title):
        """按中文标题返回当前可见的真实操作按钮。"""
        return unique(self.nodes(), lambda node: node["visible"] and node["type"] == "button" and node["name"] == title)

    def read_text(self, node):
        """从桥接节点读取测试规模内的完整正文，返回原始多行文本。"""
        result = self.client.call("read_text", {"object_id": node["id"], "length": 8192})["data"]
        assert not result["truncated"], node
        return result["text"]

    def label(self, prefix):
        """返回以指定前缀开头的可见标签全文，未出现时返回空串。"""
        matches = [node for node in self.nodes() if node["visible"] and node["type"] == "label"
                   and node["name"].startswith(prefix)]  # 只在工作台子树中定位。
        assert len(matches) <= 1, matches
        return self.read_text(matches[0]) if matches else ""

    def editor(self):
        """返回当前规则草稿编辑核心的桥接节点。"""
        return unique(self.nodes(), lambda node: node["visible"] and node["object_name"] == "ks_behavior_rule_editor")

    def receipt(self):
        """通过共享代码编辑器的真实只读输入控件返回完整回执。"""
        wrapper = unique(self.nodes(), lambda node: node["visible"] and
                         node["object_name"] == "ks_behavior_rule_receipt")
        children = self.client.call("snapshot", {"root_id": wrapper["id"], "max_nodes": 120,
                                                 "depth": 4})["data"]["nodes"]
        editor = unique(children, lambda node: node["visible"] and node["object_name"] == "code_editor_text")
        assert editor["read_only"], editor
        return self.read_text(editor)

    def edit(self, text):
        """按原编辑路径写入规则草稿，再用桥接确认正文。"""
        editor = self.editor()  # 编辑路径会触发页面真实的修改代次和脏标记。
        assert not editor["read_only"], editor
        dispatch(self.client, "set_field", object_id=editor["id"], value=text, confirmed=True)
        assert self.read_text(editor) == text

    def check(self, title, predicate):
        """按下校验或回放按钮，等待正文满足断言条件并返回完整回执。"""
        button = self.button(title)
        assert button["enabled"], button
        dispatch(self.client, "action", object_id=button["id"], action="press", confirmed=True)
        receipt = until(self.receipt, predicate)  # 异步提交的业务结果独立于按钮派发。
        until(lambda: self.button(title), lambda node: node["enabled"])
        return receipt

    def select_file(self, title, path):
        """经指定按钮打开正式 Qt 文件选择器，只提交固定目录中的夹具文件。"""
        button = self.button(title)
        assert button["enabled"] and path.is_file() and path.is_relative_to(SCRATCH), (button, path)
        # 文件选择进入嵌套事件循环，提交文件后再等待原按钮派发结束。
        reply = self.client.call("action", {"object_id": button["id"], "action": "press", "confirmed": True})
        assert reply["status"] == "accepted", reply
        operation = reply["data"]["operation_id"]

        def dialog_nodes():
            """返回当前活动窗口的桥接快照，等待标准文件选择器成为根。"""
            return self.client.call("snapshot", {"max_nodes": 200, "depth": 8})["data"]["nodes"]

        nodes = until(dialog_nodes, lambda value: value and value[0]["class"] == "QFileDialog")
        field = unique(nodes, lambda node: node["visible"] and node["object_name"] == "fileNameEdit")
        dispatch(self.client, "set_field", object_id=field["id"], value=str(path), submit=True, confirmed=True)
        until(lambda: self.client.call("operation_status", {"operation_id": operation})["data"],
              lambda state: state["state"] == "dispatched")
        until(lambda: self.button(title), lambda node: node["enabled"])


def verify_predicates(page, directory):
    """回放默认、新式和旧式谓词，返回已打开的旧草稿路径及其磁盘基线。"""
    default = json.loads(page.read_text(page.editor()))  # 正式窗口提供的可执行默认草稿。
    assert isinstance(default["step"]["predicate"], str) and default["anchor"]["predicate"] is True
    validated = page.check(VALIDATE, lambda text: "规则校验通过。" in text)
    assert "合成事件：3 条" in validated and "锚点窗口" not in validated, validated
    assert page.label(f"{VALIDATE} · ").splitlines()[1] == "未绑定文件"
    baseline = page.check(REPLAY, lambda text: "锚点窗口：3 个" in text)
    anchors = [line for line in baseline.splitlines() if line.startswith("锚点 ")]
    assert anchors == ["锚点 0：未知", "锚点 1：命中", "锚点 2：命中"], baseline
    assert "步骤证据：0, 1" in baseline and "predicate-unknown" in baseline, baseline

    # 同一数据用旧字段对象配旧布尔锚点，逐行比对命中、未知及证据。
    legacy = default | {"step": default["step"] | {
        "predicate": {"field": "source.headerPid", "operator": "eq", "value": "42"},
    }}
    path = directory / "legacy.aarules.json"  # 显式绑定路径，后续草稿修改留在内存。
    original = json.dumps(legacy, indent=2).encode("utf-8")
    path.write_bytes(original)
    page.select_file("打开规则草稿", path)
    assert Path(page.label("已打开草稿：").removeprefix("已打开草稿：")) == path
    assert page.read_text(page.editor()).encode("utf-8") == original
    # 先产生独立的校验回执，避免把遗留的相同回放正文误作本次完成。
    validated = page.check(VALIDATE, lambda text: "规则校验通过。" in text and "锚点窗口" not in text)
    assert "合成事件：3 条" in validated, validated
    assert page.check(REPLAY, lambda text: "锚点窗口：3 个" in text) == baseline
    identity = page.label(f"{REPLAY} · ")  # 最近提交的动作、时间和来源路径。
    assert Path(identity.splitlines()[1]) == path and STALE not in identity, identity

    # 新谓词覆盖逐字字符串、函数、否定及优先级。错误结合会让锚点消失。
    expression = r'Text.Contains(event.sampleId, @"-") && !(source.headerPid != 0x2au64)'
    modern = legacy | {
        "step": legacy["step"] | {"predicate": expression},
        "anchor": legacy["anchor"] | {"predicate": "true || false && false"},
    }
    page.edit(json.dumps(modern, indent=2))
    assert page.label(f"{REPLAY} · ") == f"{identity}\n{STALE}"
    assert page.receipt() == baseline and path.read_bytes() == original
    page.check(VALIDATE, lambda text: "规则校验通过。" in text and "锚点窗口" not in text)
    assert page.check(REPLAY, lambda text: "锚点窗口：3 个" in text) == baseline
    assert STALE not in page.label(f"{REPLAY} · ")
    print("QT_RULE_PREDICATES=PASS LEGACY_BOOLEAN_AND_OBJECT=True ANCHORS=3 DRAFT_RECEIPT_STALE=True", flush=True)
    return path, original, modern


def verify_diagnostics(page, modern):
    """提交三种失败谓词，核对错误码、JSON 路径和解码后的 UTF-8 坐标。"""
    cases = (  # 断言片段标出诊断起点，长度分别落在原始词元、数字或 EOF。
        ('true ||\n Text.Equals(event.sampleId, "汉") || missing.field', "unknown-field", "missing.field"),
        ("source.headerPid == 18446744073709551616u64", "expression-u64-overflow", "18446744073709551616u64"),
        ("(true || false", "expression-expected-close-paren", ""),
    )
    for expression, code, token in cases:
        draft = modern | {"step": modern["step"] | {"predicate": expression}}
        text = json.dumps(draft, ensure_ascii=False, indent=2)  # 保留多字节字符，JSON 仍转义换行。
        prefix = expression[:expression.index(token)] if token else expression
        offset = len(prefix.encode("utf-8"))  # 按解码后的表达式计算，而非外层 JSON。
        line = prefix.count("\n") + 1
        column = len(prefix.rsplit("\n", 1)[-1].encode("utf-8")) + 1
        length = len(token.encode("utf-8"))
        diagnostic = f"规则检查失败：{code}"  # 按稳定诊断码等待此次异步回执。
        page.edit(text)
        receipt = page.check(REPLAY, lambda value: diagnostic in value)
        assert receipt.splitlines() == [
            f"规则 ID：{draft['ruleId']}", diagnostic, "JSON 路径：/step/predicate",
            f"谓词位置：第 {line} 行，第 {column} 字节列（偏移 {offset}，长度 {length}）",
        ], receipt
        assert page.read_text(page.editor()) == text
    print("QT_RULE_DIAGNOSTICS=PASS CASES=3 UTF8_BYTE_LOCATIONS=True", flush=True)


def verify_presets(page, manifest, segment, rows, draft_path, draft_bytes, modern):
    """核对两组汇总、五类细分和坐标，以及坏尾与草稿编辑后的回执保留。"""
    families = {  # 每条回执须保留汇总 ID、对应细分 ID 及 CLI 回读的原始坐标。
        "memory-write": "memory-operation", "section-map": "memory-operation",
        "apc-queue": "thread-control", "thread-create": "thread-control", "thread-context": "thread-control",
    }
    assert sorted(row["family"] for row in rows) == sorted(families), rows  # 夹具包含五个不同类别各一条。
    project_id = json.loads(manifest.read_bytes())["projectId"]
    sample_id = segment.parents[1].name  # 复用 CLI 实际导入采样 ID。
    expected = [
        f"项目 {project_id} · 采样 {sample_id}",
        "已分析最近 5 条，共验证 5 条归档线索。命中 5 条。",
        "汇总：内存操作 2 条 · 线程控制 3 条",
        "细分：内存写入 1 条 · 节映射 1 条 · 线程创建 1 条 · 线程上下文修改 1 条 · APC 入队 1 条",
        "以下为 API 观测。目标身份、调用效果和采集覆盖未知。",
    ]
    for row in rows:
        group_id = f"ksword.api.{families[row['family']]}-observed.v1"  # 原有汇总 ID。
        category_id = f"ksword.api.{row['family']}-observed.v1"  # 当前观测的细分预置 ID。
        expected.append(
            f"段内序号 {row['rawSequence']} · 源行 {row['sourceSequence']} · {row['api']} · {group_id} · {category_id}"
        )

    # 好档来源来自真实 Stored 段。负控只截断独立副本，原段用于恢复重试。
    clean = segment.read_bytes()
    damaged = draft_path.parent / "bad-tail.ksaseg"
    damaged.write_bytes(clean[:-1])
    page.select_file(PRESETS, segment)
    receipt = page.receipt()
    assert receipt.splitlines() == expected, receipt
    origin = page.label(f"{PRESETS} · ")
    assert Path(origin.splitlines()[1]) == segment and STALE not in origin, origin

    # 编辑未保存草稿时，归档回执仍属于该采样与原始路径。
    edited = json.dumps(modern | {"ruleId": "qt.pending-rules"}, indent=2)
    page.edit(edited)
    draft_label = page.label(draft_path.as_posix()) or page.label(str(draft_path))
    suffix = "（有未保存的修改）"
    assert draft_label.endswith(suffix) and Path(draft_label.removesuffix(suffix)) == draft_path, draft_label
    assert page.label(f"{PRESETS} · ") == origin and page.receipt() == receipt

    page.select_file(PRESETS, damaged)
    failure = until(lambda: page.label(ARCHIVE_ERROR), bool)
    failed_path, code = failure.splitlines()  # 失败归属与已保留回执属于两个文件。
    assert Path(failed_path.removeprefix(ARCHIVE_ERROR)) == damaged, failure
    assert code in {"archive-truncated", "archive-invalid"}, failure
    assert page.label(f"{PRESETS} · ") == origin and page.receipt() == receipt
    assert page.read_text(page.editor()) == edited and draft_path.read_bytes() == draft_bytes

    # 重试提交新的归档回执后，显式回放仍使用当前内存草稿和原规则文件路径。
    page.select_file(PRESETS, segment)
    assert not page.label(ARCHIVE_ERROR)
    assert page.receipt() == receipt and segment.read_bytes() == clean
    restored = page.label(f"{PRESETS} · ")
    assert Path(restored.splitlines()[1]) == segment and restored != origin, restored
    assert page.read_text(page.editor()) == edited and draft_path.read_bytes() == draft_bytes
    assert (page.label(draft_path.as_posix()) or page.label(str(draft_path))) == draft_label
    replayed = page.check(REPLAY, lambda value: value.startswith("规则 ID：qt.pending-rules\n"))
    assert "锚点窗口：3 个" in replayed, replayed
    draft_origin = page.label(f"{REPLAY} · ")
    assert Path(draft_origin.splitlines()[1]) == draft_path and STALE not in draft_origin, draft_origin
    assert draft_path.read_bytes() == draft_bytes
    print(f"QT_RULE_PRESETS=PASS GROUPS=2 CATEGORIES=5 ROWS=5 BAD_TAIL={code} RETRY=True ARCHIVE_DRAFT_INDEPENDENT=True",
          flush=True)


def main():
    """从统一 Release 运行正式 CLI 和 Qt，退出、恢复配置并清理后报告验收。"""
    with fixture_directory(SCRATCH) as directory:
        manifest, segment, rows = import_fixture(directory)  # CLI 生成并核验合成归档的真实项目和段。
        with test_window() as client:
            page = RulesPage(client)
            draft_path, draft_bytes, modern = verify_predicates(page, directory)
            verify_diagnostics(page, modern)
            verify_presets(page, manifest, segment, rows, draft_path, draft_bytes, modern)
    print("QT_RULES_PREVIEW=PASS", flush=True)


if __name__ == "__main__":
    main()
