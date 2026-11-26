"""Verify the official Light project replay using the shared synthetic network archive."""

import hashlib
from pathlib import Path
import re
from struct import unpack
import sys
from uuid import UUID

from archive_etw_preview import RELEASE, con, gui, preview, require_isolated_desktop, text, wait_for

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'qt'))
from archive_network_preview import BLOCK_HEADER_BYTES, LARGE_PAYLOAD, PAYLOAD, fixture_directory, native_fixture, verify_cli


SCRATCH = RELEASE / 'action-analyze-light-network-validation'
RECORD_HEADER_BYTES = 32


def verify_record(archive, details, sequence, block, expected, record_offset=None, payload_offset=None):
    """Bind both offsets reported by Light to the same Stored raw record and its inline bytes."""
    match = re.search(rf'^归档记录序号：{sequence} +所属段号：1 +块号：{block} +文件字节偏移：(\d+)$',
                      details, re.MULTILINE)
    assert match, details
    offset = int(match[1])
    assert record_offset is None or offset == record_offset, (offset, record_offset)
    archive.seek(offset)
    total, kind, version, _, body_size, stored_sequence = unpack('<IHHIIQ', archive.read(24))
    assert (kind, version, stored_sequence, total) == (3, 1, sequence, RECORD_HEADER_BYTES + body_size), details
    archive.seek(offset + RECORD_HEADER_BYTES)
    metadata_size, = unpack('<I', archive.read(4))
    inline_offset = archive.tell() + metadata_size
    assert body_size - 4 - metadata_size == len(expected), details

    _, marker, displayed = details.partition('通信字节预览：')
    if not expected:
        assert not marker, details
        return offset

    preview_size = min(256, len(expected))
    heading, *lines = displayed.splitlines()
    assert heading == f'{preview_size} / {len(expected)} B    文件字节偏移：{inline_offset}', details
    assert payload_offset is None or inline_offset == payload_offset, details
    shortened = lines[-1] == '[字节预览截断]'
    assert shortened == (preview_size < len(expected)), details
    archive.seek(inline_offset)
    actual = archive.read(len(expected))
    assert actual == expected and bytes.fromhex(' '.join(lines[:-1] if shortened else lines)) == actual[:preview_size], details
    return offset


def verify_light(segment, first_end, large_offset):
    """Open the CLI project and select the three raw rows using the actual Light list control."""
    sample = segment.parents[1].name
    offsets = {}

    def check(_process, _page, records, detail, status, _api, replay, _retry, item_count):
        gui.SendMessage(replay, con.BM_CLICK, 0, 0)
        wait_for('Light loaded the synthetic project raw segment', lambda: item_count() == 9
                 and '当前归档' in text(status) and '未发布终态检查点 · 仅查看 raw 段' in text(status)
                 and f'帧前缀 {segment.stat().st_size} / {segment.stat().st_size} B' in text(status))

        def select(sequence):
            gui.SendMessage(records, con.WM_KEYDOWN, con.VK_HOME, 0)
            for _ in range(sequence - 1):
                gui.SendMessage(records, con.WM_KEYDOWN, con.VK_DOWN, 0)
            selected = wait_for(f'Light selected raw/1 #{sequence}', lambda: text(detail)
                                if f'归档记录序号：{sequence} ' in text(detail) else '')
            assert f'当前归档 · 采样：{sample}' in selected, selected
            return selected.replace('\r\n', '\n')

        with segment.open('rb') as archive:
            metadata = select(1)
            assert all(value in metadata for value in ('TCP/IPv4 出站 · 198.51.100.12:443', '源端点：192.0.2.8:0',
                       '目的端点：198.51.100.12:443', '通信字节：仅元数据', '归档保留：0')), metadata
            offsets[1] = verify_record(archive, metadata, 1, 1, b'', 96 + BLOCK_HEADER_BYTES)

            partial = select(4)
            assert all(value in partial for value in ('UDP/IPv6 入站 · [2001:db8::12]:端口未知',
                       '源端点：[2001:db8::12]:端口未知', '目的端点：[2001:db8::1]:53', '通信字节：已归档字节（截断）',
                       '原始长度：10    生产端保留：7    归档保留：7    来源声明截断')), partial
            offsets[4] = verify_record(archive, partial, 4, 1, PAYLOAD)
            assert offsets[1] < offsets[4] < first_end

            complete = select(8)
            assert '通信字节：完整字节已归档' in complete, complete
            assert '原始长度：300    生产端保留：300    归档保留：300' in complete, complete
            assert '来源声明截断' not in complete, complete
            offsets[8] = verify_record(archive, complete, 8, 2, LARGE_PAYLOAD, first_end + BLOCK_HEADER_BYTES, large_offset)

    preview(segment, check_project_replay=check)
    return offsets


def main():
    require_isolated_desktop()
    original, first_end, large_offset = native_fixture()
    damaged = bytearray(original)
    damaged[large_offset] ^= 1  # Existing Qt/CLI fixture requires a synthetic second-block negative control.
    with fixture_directory(SCRATCH) as directory:
        verify_cli(directory, original, damaged, first_end)
        segment, = (directory / 'network-project' / 'samples').glob('*/raw/00000000000000000001.ksaseg')
        before = segment.read_bytes()
        sample = segment.parents[1].name
        assert str(UUID(bytes=before[48:64])) == sample, segment
        offsets = verify_light(segment, first_end, large_offset)
        assert segment.read_bytes() == before, segment
        segment_sha = hashlib.sha256(before).hexdigest()
        light_sha = hashlib.sha256((RELEASE / 'KswordARKLight.exe').read_bytes()).hexdigest()
    print(f'LIGHT_NETWORK_PROJECT_REPLAY=PASS SAMPLE={sample} RAW=1#1,1#4,1#8 '
          f'RECORD_OFFSETS={offsets[1]},{offsets[4]},{offsets[8]} BYTES=0/7/300 PREVIEW=256 '
          f'SEGMENT_SHA256={segment_sha} LIGHT_SHA256={light_sha}', flush=True)


if __name__ == '__main__':
    main()
