"""在本次真实Qt归档窗口验证行为根、原叶坐标与Enter定位；不创建项目或采集。"""

import win32con
import win32gui
import win32process

from live_passive_api import dispatch, read_table, unique, until, visible
from isolated_desktop import require_isolated_desktop, test_windows
from relationship_activation import InputUnavailable, post_click, post_key, uia_probe
from support import BEHAVIOR, EVIDENCE, screenshot, write_json
from api_rule_profile import behavior_rule, display_summary


def verify_tree(client, nodes, sample, history, directory):
    """输入已打开同sample归档；使用原桥接读模型和原生键盘路径返回实际详情回执。"""
    require_isolated_desktop()
    api = unique(nodes(), lambda node: node['visible'] and node['class'] == 'QCheckBox' and node['name'] == 'API')
    dispatch(client, 'set_field', object_id=api['id'], value=True, confirmed=True)
    toggle = visible(nodes, 'aa_archive_relation_toggle')
    dispatch(client, 'set_field', object_id=toggle['id'], value=True, confirmed=True)
    tree = visible(nodes, 'aa_archive_relation_tree')
    roots = read_table(client, tree)
    group, = (index for index, row in enumerate(roots['rows']) if row and row[0].startswith('行为命中（当前窗口 '))
    segment, raw, source = history[-1]['coordinate']  # 与主采集终态历史中的最新条目对账。
    expected = f'raw/{segment} #{raw} · 来源序号 {source} · {BEHAVIOR} · {EVIDENCE} · {display_summary(behavior_rule(BEHAVIOR))}'
    leaf_index = None
    offset = 0  # 行数可能超过桥接单次200行预算，保持原模型全局下标。
    while True:
        page = client.call('read_table', {'object_id': tree['id'], 'parent_rows': [group],
            'row_start': offset, 'row_count': 200, 'column_count': 1})['data']
        matches = [offset + index for index, row in enumerate(page['rows']) if row == [expected]]
        if matches:
            leaf_index, = matches
            break
        offset += len(page['rows'])
        if not page['rows'] or offset >= page['row_total']:
            raise AssertionError(('行为树缺少同一主采集历史原叶', expected, roots))
    table = unique(nodes(), lambda node: node['visible'] and node['class'] == 'QTableView'
                   and {'PID', 'TID', '事件'} <= set(read_table(client, node)['headers']))
    model = read_table(client, table)
    dispatch(client, 'select_row', object_id=table['id'], row=0, revision=model['revision'], confirmed=True)
    dispatch(client, 'select_row', object_id=tree['id'], parent_rows=[group], row=leaf_index,
             revision=page['revision'], confirmed=True)
    windows = [hwnd for hwnd in test_windows() if win32process.GetWindowThreadProcessId(hwnd)[1] == client.pid
               and win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd).startswith('Qt')
               and not win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE) & win32con.WS_EX_TOOLWINDOW]
    if len(windows) != 1:
        raise InputUnavailable(('独立桌面Qt主窗匹配数', len(windows)))
    hwnd, = windows
    location = uia_probe(directory, hwnd, model, expected)  # 复用既有只读UIA坐标工具。
    post_click(client.pid, hwnd, location['point'])
    selected = uia_probe(directory, hwnd, model, expected)
    if not selected['leaf_selected']:
        raise InputUnavailable('行为叶未取得真实树选区，Enter未执行')
    post_key(client.pid, hwnd, win32con.VK_RETURN)

    def details():
        values = {}  # 从当前可见共享字段模型按组读取，所有值仍来自同一规范详情源。
        for view in nodes():
            if not view['visible'] or view['type'] != 'item_view' or view['id'] in (tree['id'], table['id']):
                continue
            rows = read_table(client, view)['rows']
            for index, row in enumerate(rows):
                if row and row[0] in {'归档记录', '归档 API 线索', '行为规则命中（当前窗口）'}:
                    children = read_table(client, view, [index])['rows']
                    values.update({str(item[0]): str(item[1]) for item in children if len(item) >= 2})
                elif len(row) >= 2:
                    values[str(row[0])] = str(row[1])
        return values

    fields = until(details, lambda value: value.get('记录序号') == str(raw) and value.get('行为规则 ID') == BEHAVIOR)
    assert (fields['采样 ID'], fields['归档段号'], fields['证据级别'], fields['行为释义']) == (
        sample, str(segment), EVIDENCE, display_summary(behavior_rule(BEHAVIOR))), fields
    source_value = next((fields[key] for key in ('合作流水号（非 JSONL 行号）', '合作流水号', '原采集序号') if key in fields), None)
    assert source_value == str(source), fields
    write_json(directory, 'archive-behavior-tree', {'root': roots['rows'][group], 'leaf': expected,
               'leafIndex': leaf_index, 'coordinate': [segment, raw, source], 'enter': True, 'details': fields})
    screenshot(client.pid, directory, 'archive-behavior-tree')
    return {'root': roots['rows'][group][0], 'coordinate': [segment, raw, source], 'enter': True}
