"""与 Qt 串行回放同一 CLI 持久化 API 采样。"""

from pathlib import Path
import sys

from archive_etw_preview import con, gui, preview, text, wait_for

# 复用真正的 CLI 写入回归和 Qt 工作台回读，两个窗口串行启动。
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'qt'))
from archive_api_follow_preview import SCRATCH, fixture_directory, run, test_window, verify_window


def verify_light(segments, markers, sample, packets):
    """通过正常文件选择、采样选择和回放动作校验首段及连续前缀。"""
    original_marker = markers[1].read_bytes()  # 恢复时必须使用原始发布标记。
    original_third = segments[2].read_bytes()  # 仅在本轮独占的测试目录中截断第三段。

    def check(_process, _page, records, detail, status, api, replay, retry, item_count):
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

        # API 筛选下 End 定位最后一个源包，按显示偏移独立回读 Stored 序号。
        gui.SendMessage(records, con.WM_KEYDOWN, con.VK_END, 0)
        fields = wait_for('Light final API packet', lambda: text(detail) if '源归档行号：6\r\n' in text(detail) else '')
        assert all(part in fields for part in (sample, '所属段号：3 ', '归档记录序号：9 ', packets[-1][:128].hex(' '))), fields
        offset = int(fields.split('文件字节偏移：', 1)[1].split('\r\n', 1)[0])  # 当前证据的物理记录起点。
        with segments[2].open('rb') as archive:
            archive.seek(offset + 16)
            assert int.from_bytes(archive.read(8), 'little') == 9
        print(f'LIGHT_API_FOLLOW_REPLAY=PASS SAMPLE={sample} API_ROWS=2/4/6 RAW=9 SOURCE=6', flush=True)

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
