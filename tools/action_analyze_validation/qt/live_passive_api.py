"""在正式 Qt 非输入桌面回归自有合成 API JSONL 的分段跟随和项目回放。"""

from pathlib import Path
from uuid import UUID

from archive_api_preview import (
    RELEASE, choose_project_path, dispatch, fixture_directory, open_project, read_table, test_window, unique, until,
)
from api_rule_profile import behavior_rule, display_summary
from isolated_desktop import require_isolated_desktop
from live_etw import decode_raw
from passive_api_session import CREATION, SESSION_ID, make_rows
from smoke import invoke


SCRATCH = RELEASE / 'action-analyze-qt-live-passive-api-validation'  # 本轮独占的固定目录。
RULE_ID = 'ksword.api.memory-write-observed.v1'  # 合成内存写入观测的细分预置。
COORDINATES = [(1, 2, 1), (1, 3, 2), (2, 5, 3), (2, 6, 4)]  # 段号、全局原包序号、来源行。


def visible(nodes, name):
    """按稳定对象名返回当前工作台实际可见的唯一节点。"""
    return unique(nodes(), lambda item: item['visible'] and item['object_name'] == name)


def wait_visible(nodes, name, ready=bool):
    """用现有有界等待取得可见且满足 ready 的实名节点；超时报告该控件。"""
    def matches():
        """每次重新读取指定控件，保留当时的可见状态和值供诊断。"""
        return [item for item in nodes() if item['object_name'] == name]

    def published(items):
        """控件未发布时继续等待；同名可见控件不允许误选。"""
        shown = [item for item in items if item['visible']]
        assert len(shown) <= 1, (name, shown)
        return bool(shown) and ready(shown[0])

    try:
        items = until(matches, published)
    except AssertionError as error:
        raise AssertionError(f'{name}: {error}') from error
    return unique(items, lambda item: item['visible'])


def subtree(client, root, *, depth, max_nodes):
    """以已登记的控件为根读有界快照，返回该子树节点。"""
    return client.call('snapshot', {'root_id': root['id'], 'max_nodes': max_nodes, 'depth': depth})['data']['nodes']


def press(client, button):
    """触发真实可用按钮；业务成效由调用方独立回读。"""
    assert button['enabled'], button
    dispatch(client, 'action', object_id=button['id'], action='press', confirmed=True)


def select_tab(client, nodes, title):
    """通过工作台导航切换到指定页签。"""
    tabs = visible(nodes, 'action_analyze_tabs')  # 原有子页导航，不直接构造页面。
    dispatch(client, 'set_field', object_id=tabs['id'], value=tabs['tabs'].index(title), confirmed=True)


def capture(client, overview_nodes, source, second_batch):
    """通过实际文件选择和开始／停止按钮完成两批跟随，返回采样 ID。"""
    toggle = visible(overview_nodes, 'action_analyze_api_capture')  # 只进入 API 来源页，不使用通用监控入口。
    assert toggle['checked'] is False, toggle
    press(client, toggle)
    # 路径框在滚动视口和表单组内，比固定动作带更深。先证明新草稿路径为空且只读。
    path_name = 'action_analyze_api_path'
    original = wait_visible(overview_nodes, path_name)
    assert original['type'] == 'line_edit' and original['read_only'] and original['value'] == '', original
    pane = visible(overview_nodes, 'action_analyze_api_receipt')  # 共享结构化字段视图的结果根。
    browse = wait_visible(overview_nodes, 'action_analyze_api_browse', lambda item: item['enabled'])
    choose_project_path(client, browse, source)

    # 派发 Enter 不等于 chooseFile 已返回。模态期间快照会被拒，until 会继续回读。
    def chosen_source(item):
        """只接受同一只读输入框中由选择器回填的独占文件路径。"""
        return (item['id'] == original['id'] and item['read_only']
                and bool(item['value']) and Path(item['value']) == source)

    wait_visible(overview_nodes, path_name, chosen_source)
    print('QT_PASSIVE_API_SOURCE_SELECTED=PASS READ_ONLY=True', flush=True)

    for suffix, value in (('pid', '42'), ('creation', CREATION), ('session', str(SESSION_ID))):
        field = visible(overview_nodes, 'action_analyze_api_' + suffix)  # 文件内合成身份，不解析实际进程。
        dispatch(client, 'set_field', object_id=field['id'], value=value, confirmed=True)

    def status():
        """回读跟随窗实际显示的状态，不读取内部所有者。"""
        return visible(overview_nodes, 'action_analyze_api_status')['name']

    def receipt():
        """只读取此窗回执下的可见字段模型，返回字段名和值。"""
        children = subtree(client, pane, depth=6, max_nodes=120)
        tables = [item for item in children if item['visible'] and item['type'] == 'item_view']
        if not tables:
            return {}  # 共享字段树的第一份投影可能尚未发布。
        table, = tables  # 回执子树只允许一个可见字段模型。
        groups = read_table(client, table)['rows']
        rows = list(groups)  # 保留共享视图可能直接投影到根的键值行。
        for index, row in enumerate(groups):
            if row and row[0] in {'API JSONL 来源', 'API 规则回执'}:
                rows.extend(read_table(client, table, [index])['rows'])
        return {str(row[0]): str(row[1]) for row in rows if len(row) >= 2}

    def check_watermark(count, segment, coordinate):
        """等待已提交的窗口回执并核对规则和原包水位，返回字段。"""
        fields = until(receipt, lambda values: values.get('已核验段号') == str(segment)
                       and values.get('已归档原包') == str(count)
                       and values.get('已提交命中行') == str(count))  # 不把未提交读入量算成命中量。
        assert fields['已核验来源行'] == str(count) and fields['最近命中的规则'] == RULE_ID, fields
        assert fields['命中坐标（段 / 原包 / 来源行）'] == coordinate, fields
        return fields

    # 由窗口证明首段提交后才追加。第二批末次坐标必须来自另一段。
    press(client, visible(overview_nodes, 'action_analyze_api_start'))
    until(status, lambda text: text == '正在跟随 API JSONL · 已归档 2 行 · 规则命中 2 行')
    first = check_watermark(2, 1, '1 / 3 / 2')  # 第一批真实回执。
    # 首批末条有显式失败返回，释义必须绑定已提交坐标。
    behavior_id = 'ksword.behavior.memory-write-access-denied-return.v1'  # 夹具独立指定的预期规则。
    explanation = {'行为规则 ID': behavior_id, '证据级别': 'reported-api-return',
                   '行为释义': display_summary(behavior_rule(behavior_id))}
    assert explanation.items() <= first.items(), first
    sample = first['采样 ID']  # 后续窗口和文件回查都绑定这一个样本。
    assert str(UUID(sample)) == sample, first
    assert (first['来源 PID'], first['进程创建 FILETIME'], first['来源会话 ID']) == ('42', CREATION, str(SESSION_ID)), first
    with source.open('ab') as stream:
        written = stream.write(second_batch)  # 只追加至本次独占的合成文件。
        assert written == len(second_batch)
    until(status, lambda text: text == '正在跟随 API JSONL · 已归档 4 行 · 规则命中 4 行')
    second = check_watermark(4, 2, '2 / 6 / 4')  # 最后一次分类缺明确返回证据。
    assert second['采样 ID'] == sample and not (explanation.keys() & second.keys()), second
    print(f'QT_LIVE_API_BEHAVIOR=PASS SAMPLE={sample} POSITIVE=1#3:2 CLEARED=2#6:4', flush=True)
    print(f'QT_PASSIVE_API_ONLINE=PASS SAMPLE={sample} ROWS=2/4 RULES=2/4 RAW=2#6', flush=True)

    # 等停止动作交还项目后删除输入，确保离线回放只能依赖已提交的归档。
    press(client, visible(overview_nodes, 'action_analyze_api_stop'))
    until(status, lambda text: text == 'API JSONL 跟随已停止 · 已归档 4 行 · 规则命中 4 行')
    final = check_watermark(4, 3, '2 / 6 / 4')  # 终段不应把末次规则坐标迁移到终段。
    assert final['采样 ID'] == sample and final['来源状态'] == '已读到本次停止边界', final
    assert not (explanation.keys() & final.keys()), final
    assert not visible(overview_nodes, 'action_analyze_api_stop')['enabled']
    source.unlink()
    return sample


def verify_replay(client, nodes, overview_nodes, sample):
    """用本次回执打开已核验归档，再从同项目目录回放规则。"""
    archive = wait_visible(overview_nodes, 'action_analyze_api_archive', lambda item: item['enabled'])
    press(client, archive)

    def archive_labels():
        """只回读总览实际可见的归档标签，超时保留状态及计数。"""
        return [item['name'] for item in overview_nodes() if item['visible'] and item['type'] == 'label']

    labels = until(archive_labels, lambda texts: any('已验证至第 3 段。' in text for text in texts))
    assert any('已验证 API 跟随归档检查点。' in text for text in labels), labels
    assert any('已核验 4 条源归档记录。覆盖范围未知。' in text for text in labels), labels
    items = overview_nodes()  # 本次已核验的证据页，不再从工作台默认深度找表格。
    api = unique(items, lambda item: item['visible'] and item['class'] == 'QCheckBox' and item['name'] == 'API')
    assert api['enabled'], api
    dispatch(client, 'set_field', object_id=api['id'], value=True, confirmed=True)
    views = [item for item in items if item['visible'] and item['class'] == 'QTableView']  # 排除详情树。
    table = unique(views, lambda item: {'PID', 'TID', '事件'} <= set(read_table(client, item)['headers']))
    data = read_table(client, table)  # 同一归档可见的四条 API 原包对应行。
    assert len(data['rows']) == 4 and all('WriteProcessMemory' in row for row in data['rows']), data

    # 项目页以采样 UUID 选择，避免使用碰巧已高亮的其它行。
    select_tab(client, nodes, '项目与采样')
    views = [item for item in nodes() if item['visible'] and item['class'] == 'QTableView']
    catalog = unique(views, lambda item: '采样名称' in read_table(client, item)['headers'])
    listing = until(lambda: read_table(client, catalog), lambda model: any(sample in row for row in model['rows']))
    index = next(number for number, row in enumerate(listing['rows']) if sample in row)  # 当前目录修订中的采样行。
    dispatch(client, 'select_row', object_id=catalog['id'], row=index, revision=listing['revision'], confirmed=True)
    button = wait_visible(nodes, 'action_analyze_sample_rule_replay', lambda item: item['enabled'])
    press(client, button)
    wrapper = wait_visible(nodes, 'ks_behavior_rule_receipt')  # 真实规则页切换后才读取编辑器。
    editor = wait_visible(lambda: subtree(client, wrapper, depth=4, max_nodes=120), 'code_editor_text')
    assert editor['read_only'], editor

    def report_text():
        """读取规则页当前报告，且要求本次小报告不被截断。"""
        report = client.call('read_text', {'object_id': editor['id'], 'length': 8192})['data']
        assert not report['truncated'], report
        return report['text']

    report = until(report_text, lambda text: sample in text and '命中 4 条。' in text)  # 等后台核验结果发布。
    assert '已核验采样归档至终段 raw/3。' in report and '采集覆盖未知' in report, report
    assert '已分析最近 4 条，共验证 4 条归档线索。命中 4 条。' in report, report
    hits = [line for line in report.splitlines() if line.startswith('raw/')]  # 回放中的全部四条原始见证。
    assert hits == [f'raw/{segment} #{raw} · 源行 {source} · WriteProcessMemory · '
                    f'ksword.api.memory-operation-observed.v1 · {RULE_ID}'
                    for segment, raw, source in COORDINATES], report
    print(f'QT_PASSIVE_API_OFFLINE=PASS SAMPLE={sample} ROWS=4 RULES=4 RAW=2#6', flush=True)


def verify_bytes(project, sample, packets):
    """按正式回放的三个已核验段独立解码，并逐字节比对原始合成包。"""
    raw_dir = project / 'samples' / sample / 'raw'  # 已由上述窗口回放绑定的自有采样。
    segments = sorted(raw_dir.glob('*.ksaseg'))  # 正式 Qt 写出的两批和终段。
    assert [path.name for path in segments] == [f'{i:020d}.ksaseg' for i in (1, 2, 3)], segments
    actual = []  # 保存经独立解码获得的坐标和完整原包。
    sequence = 1  # 全采样 Stored 序号连续，段首计划同样占序号。
    for ordinal, path in enumerate(segments, 1):
        records, _ = decode_raw(path, sequence)  # 复用项目里的独立 Stored 解码器。
        assert records[0][0]['kind'] == 'api-archive-follow-plan-v1' and not records[0][1]
        for offset, (metadata, packet) in enumerate(records):
            if metadata['kind'] == 'api-archive-packet-v1':
                actual.append(((ordinal, sequence + offset, int(metadata['sourceSequence'])), packet))
        sequence += len(records)
    terminal, payload = records[-1]  # 末记录为本次显式停止的终态。
    assert terminal['kind'] == 'api-archive-follow-end-v1' and terminal['stopReason'] == 'requested' and not payload, terminal
    assert terminal['source']['cutoffReached'], terminal
    assert [coordinate for coordinate, _ in actual] == COORDINATES, actual
    assert [packet for _, packet in actual] == packets, 'stored API packets differ from synthetic input'


def main():
    """在固定 Release 内创建一个自有项目，退出产品并清理后才打印通过。"""
    require_isolated_desktop()
    with fixture_directory(SCRATCH) as directory:
        project = directory / 'project'  # 正式离线 CLI 仅建立空项目，不发起采集。
        command = f'project create "{project}" "Qt passive API fixture"\nquit\n'.encode('utf-8')
        stdout, stderr = invoke(('analyze', 'session', '--backend', 'offline'), command, label='create owned project')
        manifest = project / 'project.ksaproj'  # Qt 的实际项目打开入口。
        assert not stderr and b'error:' not in stdout and manifest.is_file(), (stdout, stderr)
        packets, rows = make_rows(behavior=True)  # 只使用前四条合成字节，不执行记录内的 API。
        source = directory / 'synthetic-events.jsonl'  # 不接受外部输入路径。
        with source.open('xb') as stream:
            stream.write(b''.join(rows[:2]))
        with test_window() as client:
            nodes = open_project(client, manifest)
            until(nodes, lambda items: any(item['visible'] and '项目目录已读取，尚无采样。' in item['name'] for item in items))
            select_tab(client, nodes, '总览')
            overview = wait_visible(nodes, 'action_analyze_overview')  # 用稳定总览根限定快照范围。

            def overview_nodes():
                """从总览读到共享滚动表单、固定操作区和归档结果。"""
                return subtree(client, overview, depth=16, max_nodes=800)

            sample = capture(client, overview_nodes, source, b''.join(rows[2:4]))
            verify_replay(client, nodes, overview_nodes, sample)
        verify_bytes(project, sample, packets[:4])
    print(f'QT_LIVE_PASSIVE_API=PASS SAMPLE={sample} SEGMENTS=3 PACKETS=4 SOURCE_REMOVED=True', flush=True)


if __name__ == '__main__':
    main()
