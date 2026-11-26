"""与 Qt 串行回放同一 CLI 持久化 API 采样。"""

from ctypes import addressof, create_unicode_buffer
from pathlib import Path
import sys

from archive_etw_preview import SEND, con, control, gui, preview, text, wait_for

# 复用真正的 CLI 写入回归和 Qt 工作台回读，两个窗口串行启动。
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'qt'))
from archive_api_follow_preview import SCRATCH, fixture_directory, run, test_window, verify_window


def verify_light(segments, markers, sample, packets):
    """通过正常文件选择、采样选择和回放动作校验首段及连续前缀。"""
    original_marker = markers[1].read_bytes()  # 恢复时必须使用原始发布标记。
    original_third = segments[2].read_bytes()  # 仅在本轮独占的测试目录中截断第三段。

    def check(_process, page, records, detail, status, api, replay, retry, item_count):
        """接收已有 Light 窗口控件，检查显示行数及原始文件的证据坐标。"""
        wait_for('Light verified first API segment', lambda: item_count() == 3 and sample in text(detail))
        assert gui.IsWindowEnabled(api), text(status)
        gui.SendMessage(api, con.BM_CLICK, 0, 0)
        assert item_count() == 2

        # 第一次完整读取时第二段尚未发布，第三段即使存在也不能展示。
        markers[1].unlink()
        try:
            gui.SendMessage(replay, con.BM_CLICK, 0, 0)
            wait_for('Light second API checkpoint pending', lambda: '第 2 段检查点尚未发布' in text(status))
            assert item_count() == 2
        finally:
            markers[1].write_bytes(original_marker)

        try:
            segments[2].write_bytes(original_third[:-1])
            gui.SendMessage(retry, con.BM_CLICK, 0, 0)
            wait_for('Light third API checkpoint invalid', lambda: '第 3 段核验失败' in text(status))
            assert item_count() == 4
            segments[2].write_bytes(original_third + b'uncommitted-tail')
            gui.SendMessage(retry, con.BM_CLICK, 0, 0)
            wait_for('Light API final checkpoint', lambda: '终态检查点已验证' in text(status) and item_count() == 6)
        finally:
            segments[2].write_bytes(original_third)

        # 先从普通表格定位首项，再用真实的分组和组内选择器跳到末项。
        family, locate, group_record = (control(page, identifier) for identifier in (58323, 58324, 58325))
        gui.SendMessage(records, con.WM_KEYDOWN, con.VK_HOME, 0)
        assert gui.IsWindowVisible(family) and gui.IsWindowVisible(group_record)
        gui.SendMessage(family, con.WM_KEYDOWN, con.VK_DOWN, 0)
        assert gui.SendMessage(group_record, con.CB_GETCOUNT, 0, 0) == 7
        selection = gui.SendMessage(group_record, con.CB_GETCURSEL, 0, 0)
        assert selection > 0 and 'raw/3 #9' in text(group_record, con.CB_GETLBTEXT, selection)
        gui.SendMessage(locate, con.WM_KEYDOWN, con.VK_RETURN, 0)
        wait_for('Light group record located', lambda: '源归档行号：6\r\n' in text(detail))
        print(f'LIGHT_RELATION_LOCATE=PASS SAMPLE={sample} RAW=3#9', flush=True)

        # 沿用原表键盘操作和字节核对，确认关系入口没有改写原始记录身份。
        gui.SendMessage(records, con.WM_KEYDOWN, con.VK_END, 0)
        fields = wait_for('Light final API packet', lambda: text(detail) if '源归档行号：6\r\n' in text(detail) else '')
        assert all(part in fields for part in (sample, '所属段号：3 ', '归档记录序号：9 ', packets[-1][:128].hex(' '))), fields
        # 详情复用底部证据标签，窄窗中仍应保留同一坐标。
        assert '未解析候选 · raw/3 #9\r\n' in fields, fields
        # 两个规则 ID 与原始行位于同一条已核验详情。
        assert all(value in fields for value in ('ksword.api.memory-operation-observed.v1',
                                                 'ksword.api.memory-write-observed.v1', '采集覆盖：未知')), fields
        offset = int(fields.split('文件字节偏移：', 1)[1].split('\r\n', 1)[0])  # 当前证据的物理记录起点。
        with segments[2].open('rb') as archive:
            archive.seek(offset + 16)
            assert int.from_bytes(archive.read(8), 'little') == 9
        print(f'LIGHT_API_FOLLOW_REPLAY=PASS SAMPLE={sample} API_ROWS=2/4/6 RAW=9 SOURCE=6', flush=True)
        print(f'LIGHT_PROJECT_RULE_REPLAY=PASS SAMPLE={sample} RAW=3#9 SOURCE=6', flush=True)

        filter_edit = control(page, 58304)  # 原生表格关键字框。

        def set_filter(query):
            """向本窗口筛选框写入关键字，触发正常重筛，不返回结果。"""
            value = create_unicode_buffer(query)  # 同步消息返回前保留 UTF-16 缓冲。
            assert SEND(filter_edit, con.WM_SETTEXT, 0, addressof(value)), query

        def selected_row():
            """返回原生表第一条选中行的可见索引，未选中则返回 -1。"""
            return gui.SendMessage(records, 0x100C, -1, 0x0002)  # LVM_GETNEXTITEM / LVNI_SELECTED

        # 关键字 8 只留下同段的前一条，确保定位动作需要改变详情并清除旧高亮。
        set_filter('8')
        assert item_count() == 1 and selected_row() == -1, text(status)
        gui.SendMessage(records, con.WM_KEYDOWN, con.VK_HOME, 0)
        wait_for('Light other visible API packet selected', lambda: selected_row() == 0 and
                 '未解析候选 · raw/3 #8\r\n' in text(detail) and '源归档行号：5\r\n' in text(detail))

        # 组内选择仍为 #9；用定位按钮实际切换详情，不能靠清除筛选绕过隐藏行。
        gui.SendMessage(locate, con.WM_KEYDOWN, con.VK_RETURN, 0)
        wait_for('Light hidden relation record located', lambda: text(detail) == fields)
        assert (text(filter_edit), item_count(), selected_row()) == ('8', 1, -1), text(status)
        assert '已选记录被筛掉' in text(status), text(status)
        set_filter('')
        assert (item_count(), selected_row(), text(detail)) == (6, 5, fields), text(status)
        print(f'LIGHT_RELATION_FILTERED_LOCATE=PASS SAMPLE={sample} FROM=3#8 RAW=3#9 SOURCE=6', flush=True)

    preview(segments[0], check_project_replay=check)


def main():
    """生成同一夹具，完成 CLI、Qt、Light 三端核对并清理固定目录。"""
    with fixture_directory(SCRATCH) as directory:
        project = directory / 'project'  # 本次所有修改仅发生在这一合成项目。
        sample, segments, markers, packets = run(project)
        with test_window() as client:
            verify_window(client, project / 'project.ksaproj', sample, segments, markers, packets)
        verify_light(segments, markers, sample, packets)


if __name__ == '__main__':
    main()
