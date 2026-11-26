"""在正式 Qt 中按发布水位回放 CLI 创建的自有合成 API 归档。"""

from archive_api_preview import (
    RELEASE, PREVIEW, dispatch, fixture_directory, open_project_sample,
    read_table, test_window, unique, until,
)
from passive_api_session import run


# 本脚本只创建和修改固定夹具目录下的归档及检查点。
SCRATCH = RELEASE / 'action-analyze-qt-api-follow-validation'


def verify_window(client, manifest, sample, segments, markers, packets):
    """先打开有缺口的采样，再验证损坏回执、恢复、筛选和偏移锚点。"""
    saved_marker = markers[1].read_bytes()  # 第二段发布标记的原始字节。
    markers[1].unlink()
    try:
        nodes = open_project_sample(client, manifest, sample, title='Passive API fixture')

        def status_has(text):
            """检查当前工作台可见的状态文字。"""
            return any(node['visible'] and text in node['name'] for node in nodes())

        # 首次读取遇到中间缺标记时，只展示连续核验的首段。
        until(lambda: status_has('已核验 2 条源归档记录。覆盖范围未知。'), bool)
        assert status_has('已验证至第 1 段。')
        views = [node for node in nodes() if node['visible'] and node['class'] == 'QTableView']  # 排除共用表头语义的辅助视图。
        table = unique(views, lambda view: {'PID', 'TID', '事件'} <= set(read_table(client, view)['headers']))
        api = unique(nodes(), lambda node: node['visible'] and node['class'] == 'QCheckBox' and node['name'] == 'API')
        assert api['enabled'], api
        dispatch(client, 'set_field', object_id=api['id'], value=True, confirmed=True)
        assert len(read_table(client, table)['rows']) == 2
    finally:
        markers[1].write_bytes(saved_marker)

    retry = unique(nodes(), lambda node: node['visible'] and node['name'] == '重新读取归档')

    def reload():
        """沿正式窗口动作重新读取同一个采样。"""
        dispatch(client, 'action', object_id=retry['id'], action='press', confirmed=True)

    # 截断第三段后，前两段可用。恢复后，已提交端点以外的字节不影响终段发布。
    third = segments[2].read_bytes()  # 本次试验自有的第三段。
    try:
        segments[2].write_bytes(third[:-1])
        reload()
        until(lambda: status_has('第 3 段校验失败。'), bool)
        assert status_has('已验证至第 2 段。')
        assert len(read_table(client, table)['rows']) == 4
        segments[2].write_bytes(third + b'uncommitted-tail')
        reload()
        until(lambda: status_has('已验证至第 4 段。'), bool)
    finally:
        segments[2].write_bytes(third)

    full = read_table(client, table)  # API 筛选后的六条数据，计划和终止记录处于原始流中。
    assert len(full['rows']) == 6 and status_has('已核验 6 条源归档记录。覆盖范围未知。'), full

    def selected_fields():
        """读取目前选中的结构化 API 详情。"""
        for view in nodes():
            if not view['visible'] or view['type'] != 'item_view' or view['id'] == table['id']:
                continue
            rows = read_table(client, view)['rows']  # 允许随共享详情布局以分组或平铺呈现。
            for index, row in enumerate(rows):
                if row and row[0] == '归档 API 线索':
                    rows = read_table(client, view, [index])['rows']
                    break
            fields = {str(row[0]): str(row[1]) for row in rows if len(row) >= 2}
            if PREVIEW in fields:
                return fields
        return {}

    # 展开实际关系区并核对根分组以及当前采样的末次叶项。
    toggle = unique(nodes(), lambda node: node['visible'] and node['object_name'] == 'aa_archive_relation_toggle')
    dispatch(client, 'action', object_id=toggle['id'], action='press', confirmed=True)
    visible_tree = until(nodes, lambda values: any(node['visible'] and node['object_name'] == 'aa_archive_relation_tree'
                                                  for node in values))
    tree = unique(visible_tree, lambda node: node['visible'] and node['object_name'] == 'aa_archive_relation_tree')
    groups = read_table(client, tree)['rows']  # 读模型而不是根据表格行推断树内容。
    assert any('未解析候选（6）' in row for row in groups), groups
    leaves = read_table(client, tree, [0])['rows']
    assert len(leaves) == 6 and any('raw/3 #9' in str(row[0]) for row in leaves), leaves
    print(f'QT_RELATION_GROUP=PASS SAMPLE={sample} RAW=3#9', flush=True)

    # 现有桥只能选行，不能触发树叶的 Enter／双击；以下通过表格对账，不算关系定位。
    dispatch(client, 'select_row', object_id=table['id'], row=5, revision=full['revision'], confirmed=True)
    fields = until(selected_fields, lambda value: value.get('源归档行号') == '6')
    assert (fields['采样 ID'], fields['记录序号'], fields[PREVIEW]) == (sample, '9', packets[-1][:64].hex(' ')), fields
    # 底部证据标签应使用同一归档行的段号与序号。
    until(lambda: status_has('未解析候选 · raw/3 #9'), bool)
    with segments[2].open('rb') as raw:
        raw.seek(int(fields['文件偏移（字节）']) + 16)
        assert int.from_bytes(raw.read(8), 'little') == 9
    print(f'QT_API_FOLLOW_REPLAY=PASS SAMPLE={sample} API_ROWS=2/4/6 RAW=9 SOURCE=6', flush=True)

    # 从同一采样目录执行规则回放，用真实只读报告对账完整见证行。
    tabs = unique(nodes(), lambda node: node['object_name'] == 'action_analyze_tabs')
    dispatch(client, 'set_field', object_id=tabs['id'], value=tabs['tabs'].index('项目与采样'), confirmed=True)
    replay = until(lambda: unique(nodes(), lambda node: node['object_name'] == 'action_analyze_sample_rule_replay'),
                   lambda node: node['visible'] and node['enabled'])
    dispatch(client, 'action', object_id=replay['id'], action='press', confirmed=True)
    wrapper = until(nodes, lambda values: any(node['visible'] and node['object_name'] == 'ks_behavior_rule_receipt'
                                              for node in values))
    report_view = unique(wrapper, lambda node: node['visible'] and node['object_name'] == 'ks_behavior_rule_receipt')
    editors = client.call('snapshot', {'root_id': report_view['id'], 'max_nodes': 120, 'depth': 4})['data']['nodes']
    editor = unique(editors, lambda node: node['visible'] and node['object_name'] == 'code_editor_text')

    def receipt():
        """返回规则工作台当前实际显示的同一报告。"""
        return client.call('read_text', {'object_id': editor['id'], 'length': 8192})['data']['text']

    expected = ('raw/3 #9 · 源行 6 · WriteProcessMemory · ksword.api.memory-operation-observed.v1'
                ' · ksword.api.memory-write-observed.v1')
    report = until(receipt, lambda value: expected in value)
    assert sample in report and '采集覆盖未知' in report, report
    print(f'QT_PROJECT_RULE_REPLAY=PASS SAMPLE={sample} RAW=3#9 SOURCE=6', flush=True)


def main():
    """从固定 Release 运行三段跟随和一段终态的桌面回归。"""
    with fixture_directory(SCRATCH) as directory:
        project = directory / 'project'  # CLI 和正式 Qt 共用同一个采样根。
        sample, segments, markers, packets = run(project)
        with test_window() as client:
            verify_window(client, project / 'project.ksaproj', sample, segments, markers, packets)


if __name__ == '__main__':
    main()
