"""在非输入桌面从同一份合成采样核对正式 CLI、Qt 和 Light 的行为释义。"""

import hashlib
from pathlib import Path
import sys

# 先载入 Light 启动助手，避免与 Qt 目录内的同名模块冲突。
from archive_etw_preview import RELEASE, con, gui, preview, text, wait_for
from api_rule_profile import behavior_rule, display_summary
from isolated_desktop import require_isolated_desktop
from passive_api_session import owned_project_path, run

# 复用 Qt 已有窗口配置恢复、项目选择及控件回读。
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'qt'))
from archive_api_preview import dispatch, open_project, read_table, test_window, unique, until
from live_passive_api import press, select_tab, subtree, wait_visible


GROUP_RULE = 'ksword.api.memory-operation-observed.v1'  # 汇总观测分类。
WRITE_RULE = 'ksword.api.memory-write-observed.v1'  # 即使无返回标记也须保留细分观测。
BEHAVIOR_RULE = 'ksword.behavior.memory-write-access-denied-return.v1'  # 仅有显式返回标记时命中。
EVIDENCE = 'reported-api-return'  # 报告的 API 返回，不代表真实写入效果。
CASES = (  # 元素依次为段号、原包序号、来源行号、是否预期出现释义。
    (1, 2, 1, False), (1, 3, 2, True), (2, 5, 3, False),
    (2, 6, 4, False), (3, 8, 5, False), (3, 9, 6, True),
)
POSITIVE = CASES[-1]  # 跨段末条，有返回标记及拒绝状态码。
NEGATIVE = CASES[2]  # 状态码同为 5，但没有返回标记。


def verify_qt(client, manifest, sample):
    """用窗口桥打开传入清单，选中指定采样并核对可见报告；失败时抛出断言。"""
    nodes = open_project(client, manifest)  # 本次工作台的节点快照读取入口。
    select_tab(client, nodes, '项目与采样')
    tables = [node for node in nodes() if node['visible'] and node['class'] == 'QTableView']  # 当前页表格。
    catalog = unique(tables, lambda node: '采样名称' in read_table(client, node)['headers'])  # 采样目录。
    listing = until(  # 等待当前路径加载完成，取得行与同一模型修订。
        lambda: read_table(client, catalog), lambda model: any(sample in row for row in model['rows']),
    )
    index = unique(list(enumerate(listing['rows'])), lambda entry: sample in entry[1])[0]  # 目录的采样 UUID 行。
    dispatch(client, 'select_row', object_id=catalog['id'], row=index, revision=listing['revision'], confirmed=True)

    # 走正式规则回放按钮，再以只读编辑器为证据源，不从磁盘替代窗口回执。
    button = wait_visible(nodes, 'action_analyze_sample_rule_replay', lambda node: node['enabled'])
    press(client, button)
    wrapper = wait_visible(nodes, 'ks_behavior_rule_receipt')  # 可见的规则报告容器。
    editor = wait_visible(lambda: subtree(client, wrapper, depth=4, max_nodes=120), 'code_editor_text')
    assert editor['read_only'], editor

    def read_report():
        """从已绑定的编辑器回读本次完整小报告，返回正文。"""
        receipt = client.call('read_text', {'object_id': editor['id'], 'length': 8192})['data']
        assert not receipt['truncated'], receipt
        return receipt['text']

    report = until(read_report, lambda value: sample in value and '命中 6 条。' in value)
    assert '已核验采样归档至终段 raw/4。' in report and '采集覆盖未知' in report, report
    summary = display_summary(behavior_rule(BEHAVIOR_RULE))  # 两端共享的规则库释义。
    expected = []  # 按原始坐标逐条比对，避免正例释义串到同码无标记的负例。
    for segment, raw, source, explained in CASES:
        line = f'raw/{segment} #{raw} · 源行 {source} · WriteProcessMemory · {GROUP_RULE} · {WRITE_RULE}'
        if explained:
            line += f' · {BEHAVIOR_RULE} · {EVIDENCE} · {summary}'
        expected.append(line)
    assert [line for line in report.splitlines() if line.startswith('raw/')] == expected, report


def verify_light(first_segment, sample, packets):
    """从首段定位同一项目和采样，逐条核对 Light 正负例详情；窗口退出由助手负责。"""
    summary = display_summary(behavior_rule(BEHAVIOR_RULE))  # 源码规则库提供的界面释义。
    binary = RELEASE / 'KswordARKLight.exe'  # 正式 Release 产物，记录本次受测文件身份。
    with binary.open('rb') as image:
        print(f'LIGHT_SHA256={hashlib.file_digest(image, "sha256").hexdigest()}', flush=True)

    def check_replay(_process, _page, records, detail, status, api, replay, _retry, item_count):
        """接收已按 UUID 选中采样的窗口控件，点击回放并检查两个实际选中行。"""
        wait_for('Light first segment preview', lambda: item_count() == 3
                 and f'选中采样预览 · 采样：{sample}' in text(detail))
        gui.SendMessage(replay, con.BM_CLICK, 0, 0)
        wait_for('Light committed API replay', lambda: '终态检查点已验证' in text(status)
                 and f'当前归档 · 采样：{sample}' in text(detail))
        assert gui.IsWindowEnabled(api), text(status)
        gui.SendMessage(api, con.BM_CLICK, 0, 0)
        assert item_count() == len(CASES), text(status)

        def check_selected(case):
            """根据传入坐标等待选中行详情并检查分类、原包前缀和释义字段；不返回结果。"""
            segment, raw, source, explained = case  # 同一证据的三个坐标及预期释义状态。
            source_line = f'源归档行号：{source}'  # 回读该条见证，不能仅依据按键成功判定。

            def selected_details():
                """源行发布后返回该记录详情，否则返回空串继续等待。"""
                value = text(detail)  # 只读取一次窗口控件，确保源行与返回正文属于同一快照。
                return value if source_line in value.splitlines() else ''

            details = wait_for(f'Light selected raw/{segment} #{raw}, source {source}', selected_details)
            assert all(value in details for value in (
                f'当前归档 · 采样：{sample}', f'未解析候选 · raw/{segment} #{raw}',
                f'归档记录序号：{raw} ', f'所属段号：{segment} ', 'WriteProcessMemory',
                f'规则 ID（汇总）：{GROUP_RULE}', f'规则 ID（细分）：{WRITE_RULE}',
                '采集覆盖：未知', packets[source - 1][:128].hex(' '),
            )), details
            lines = details.splitlines()  # 界面专有字段，不能与包内文本混淆。
            if explained:
                assert {f'行为规则 ID：{BEHAVIOR_RULE}', f'证据级别：{EVIDENCE}', summary} <= set(lines), details
            else:
                assert not any(line.startswith(('行为规则 ID：', '证据级别：')) for line in lines), details
                assert all(value not in details for value in (BEHAVIOR_RULE, EVIDENCE, summary)), details

        # 先读带释义的末条，再切到同状态码的负例，确认旧释义不会随选择残留。
        gui.SendMessage(records, con.WM_KEYDOWN, con.VK_END, 0)
        check_selected(POSITIVE)
        gui.SendMessage(records, con.WM_KEYDOWN, con.VK_HOME, 0)
        for _ in range(NEGATIVE[2] - 1):
            gui.SendMessage(records, con.WM_KEYDOWN, con.VK_DOWN, 0)
        check_selected(NEGATIVE)

    preview(first_segment, check_project_replay=check_replay)


def main():
    """在已有独占 Release 目录生成项目，两端串行消费；清理后才输出总 PASS。"""
    require_isolated_desktop()
    with owned_project_path() as project:
        sample, segments, _, packets = run(project, behavior=True)  # CLI 已对账正负例并移除源 JSONL。
        with test_window() as client:
            verify_qt(client, project / 'project.ksaproj', sample)
        print(f'QT_API_BEHAVIOR_EXPLANATION=PASS SAMPLE={sample} RAW=3#9 SOURCE=6 NEGATIVE=2#5:3', flush=True)
        verify_light(segments[0], sample, packets)
        print(f'LIGHT_API_BEHAVIOR_EXPLANATION=PASS SAMPLE={sample} RAW=3#9 SOURCE=6 NEGATIVE=2#5:3', flush=True)
    print(f'THREE_CLIENT_API_BEHAVIOR_REPLAY=PASS SAMPLE={sample}', flush=True)


if __name__ == '__main__':
    main()
