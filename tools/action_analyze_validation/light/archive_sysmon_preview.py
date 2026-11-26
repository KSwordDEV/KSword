"""在独立桌面核对正式 Qt、Light 对同一合成 Sysmon 项目的回放。"""

from pathlib import Path
import sys

from archive_etw_preview import con, gui, preview, text, wait_for

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'qt'))
from archive_api_preview import open_project_sample, read_table, test_window
from live_preview import dispatch, unique, until


TARGET_GUID = '11111111-1111-4111-8111-111111111111'  # 原生存储夹具写入的合成目标。
EVENT_ID = '73'  # 原生日志记录号独立于 Stored 序号 2。


def verify_qt(manifest, sample, title, offset=None):
    """从 Qt 项目页按采样身份打开回放，检查空档或唯一记录的详情。"""
    with test_window() as client:
        nodes = open_project_sample(client, manifest, sample, title=title)

        def visible_text(value):
            """只接受业务窗口中真实可见的状态标签。"""
            return any(node['visible'] and value in node['name'] for node in nodes())

        until(lambda: visible_text('已核验 Sysmon Event 8 v2 归档。'), bool)
        if offset is None:
            until(lambda: visible_text('已核验归档中没有匹配的 Sysmon Event 8 v2 记录。'), bool)
            print(f'QT_SYSMON_EMPTY=PASS SAMPLE={sample}', flush=True)
            return

        # 唯一观察行不包含计划和结束记录。通过正式选择动作打开共享详情。
        table = unique(nodes(), lambda node: node['visible'] and node['class'] == 'QTableView'
                       and {'PID', 'TID', '事件'} <= set(read_table(client, node)['headers']))
        model = until(lambda: read_table(client, table), lambda data: data['row_total'] == 1)
        assert any(f'事件记录号 {EVENT_ID}' in str(cell) for cell in model['rows'][0]), model
        dispatch(client, 'select_row', object_id=table['id'], row=0, revision=model['revision'], confirmed=True)

        def detail_fields():
            """从同一共享字段视图读取来源与归档坐标，支持分区和展平。"""
            for view in nodes():
                if not view['visible'] or view['type'] != 'item_view' or view['id'] == table['id']:
                    continue
                root = read_table(client, view)['rows']
                rows = list(root)
                for index, row in enumerate(root):
                    if row and row[0] in {'归档 Sysmon Event 8 v2', '原始归档坐标'}:
                        rows.extend(read_table(client, view, [index])['rows'])
                fields = {str(row[0]): str(row[1]) for row in rows if len(row) >= 2}
                if fields.get('采样 ID') == sample and '事件记录号' in fields:
                    return fields
            return {}

        details = until(detail_fields, bool)
        expected = {'事件记录号': EVENT_ID, '目标进程 GUID': TARGET_GUID, '归档段号': 'raw/1',
                    '记录序号': '2', '文件偏移（字节）': str(offset)}
        assert all(details.get(key) == value for key, value in expected.items()), details
        print(f'QT_SYSMON_REPLAY=PASS SAMPLE={sample} RAW=1#2 OFFSET={offset}', flush=True)


def verify_light(segment, offset=None):
    """经 Light 的正式项目回放读取同一已提交采样和原始偏移。"""
    sample = segment.parents[1].name

    def check(_process, _page, records, detail, status, _api, replay, _retry, count):
        """等待正式回放取代选择预览，再分别验证空结果和已选行。"""
        gui.SendMessage(replay, con.BM_CLICK, 0, 0)
        wait_for('Light Sysmon project replay', lambda: 'Sysmon 检查点已核验' in text(status)
                 and '当前归档' in text(detail))
        if offset is None:
            assert count() == 0 and '已核验的归档中没有匹配记录。' in text(detail), text(detail)
            print(f'LIGHT_SYSMON_EMPTY=PASS SAMPLE={sample}', flush=True)
            return

        assert count() == 1, text(status)
        gui.SendMessage(records, con.WM_KEYDOWN, con.VK_HOME, 0)
        report = wait_for('Light Sysmon observation detail', lambda: text(detail)
                          if f'EventRecordID {EVENT_ID}' in text(detail) else '')
        expected = (sample, TARGET_GUID, '归档记录序号：2 ', '所属段号：1 ',
                    f'文件字节偏移：{offset}\r\n', '未观测实际执行或内存写入', '采集覆盖：未知')
        assert all(value in report for value in expected), report
        print(f'LIGHT_SYSMON_REPLAY=PASS SAMPLE={sample} RAW=1#2 OFFSET={offset}', flush=True)

    preview(segment, check_project_replay=check)


def main():
    """只读回放显式指定的两个合成采样；各窗口由现有夹具恢复配置。"""
    project, positive, empty, offset = sys.argv[1:]
    root = Path(project).resolve(strict=True)
    manifest = root / 'project.ksaproj'
    for sample, title, expected_offset in ((positive, 'Synthetic Sysmon Event 8', int(offset)),
                                           (empty, 'Synthetic Sysmon exhausted without a match', None)):
        segment = root / 'samples' / sample / 'raw/00000000000000000001.ksaseg'
        if expected_offset is not None:
            with segment.open('rb') as raw:
                raw.seek(expected_offset + 16)  # Stored 记录头中的实际序号，为两端回执提供独立对账。
                assert int.from_bytes(raw.read(8), 'little') == 2
        verify_qt(manifest, sample, title, expected_offset)
        verify_light(segment, expected_offset)


if __name__ == '__main__':
    main()
