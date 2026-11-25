"""用正式 CLI 验证显式授权的本地合成归档跟随、原包与停止边界。"""

from contextlib import ExitStack
import hashlib
import json
import struct
import time

from api_evidence import archive_line, packet
from continuous_etw import cleanup_child, shutdown
from live_etw import CLI, call, controller, decode_raw
from project_v1 import owned_project_path


CREATION = '134400565183024180'  # 合成归档中声明的调用方创建时间。
SESSION_ID = 1234  # packet() 写入相同的原包会话字段。


def make_rows():
    """返回六条相互可辨的原始包及其生产形状 JSONL，不执行包内描述。"""
    packets = []  # 用时间戳区分包，验证归档顺序时比较完整字节。
    rows = []  # 同一个文件按三批追加的六个已换行记录。
    for sequence in range(1, 7):
        wire = bytearray(packet('KernelBase', 'WriteProcessMemory', 8))  # 被动分类所需的固定长度测试包。
        struct.pack_into('<Q', wire, 16, int(CREATION) + sequence)
        packets.append(bytes(wire))
        rows.append(archive_line(sequence, wire, pid=42, processCreation100ns=CREATION))
    return packets, rows


def wait_for_segment(directory, ordinal):
    """等待后台提交段出现在固定测试目录；等待期间不发送任何 CLI 请求。"""
    path = directory / f'{ordinal:020d}.ksaseg'  # 只查看本轮采样对应的段文件。
    deadline = time.monotonic() + 10  # 子进程失败时有限退出。
    while not path.is_file() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert path.is_file(), path


def run(project):
    """创建专用项目，逐包核对连续提交、截止回执和停后不跟随。"""
    packets, rows = make_rows()  # 同一文件的原始输入与预期包。
    source = project.parent / 'events.jsonl'  # 只使用项目夹具所在的固定目录。
    with source.open('xb') as stream:
        stream.write(b''.join(rows[:2]))
    with ExitStack() as children:
        cli = controller('r3')  # 正式 CLI，仅跟随文件，不打开目标进程。
        children.callback(cleanup_child, cli)
        created = call(cli, 'create', 'project.create', {'path': str(project),
                       'settings': {'title': 'Passive API regression', 'notes': ''}})
        identity = {'projectId': created['projectId']}  # 所有后续操作保留同一个已打开项目。
        settings = created['settings'] | {'breakpointDefinitions': []}  # 显式扩展项目格式，空集合不携带停点意图。
        saved = call(cli, 'save', 'project.save', identity | {'expectedRevisionId': created['revisionId'],
                     'settings': settings})
        assert saved['settings'] == settings and saved['revisionId'] != created['revisionId'], saved
        revision = {'expected': {'revisionId': saved['revisionId']}}  # 冻结创建采样时的扩展修订。
        api = {'path': str(source), 'sessionIdentity': str(SESSION_ID), 'authorized': True}  # 显式输入授权。
        options = dict(identity, title='Passive API fixture', pid=42, creationFileTime=CREATION, apiArchive=api)
        call(cli, 'denied', 'session.open', options | {'apiArchive': api | {'authorized': False}},
             error='source-not-authorized', **revision)
        opened = call(cli, 'open', 'session.open', options, **revision)  # 本次活会话回执。
        assert opened['capture'] == 'active' and opened['plan']['durationMs'] == 0, opened
        owner = {'session': opened['session']}  # 停止与关闭只提交给本次会话。
        sample = project / 'samples' / opened['sampleId']  # 实际采样根目录。
        raw = sample / 'raw'  # 输入原包的已写段。

        # 查询完全空闲时提交三批，其后再检查当前状态和尾读终点。
        wait_for_segment(raw, 1)
        for ordinal, batch in ((2, rows[2:4]), (3, rows[4:])):
            with source.open('ab') as stream:
                stream.write(b''.join(batch))
            wait_for_segment(raw, ordinal)
        active = call(cli, 'status', 'session.query', {}, **owner)  # 以这一代次发起显式停止。
        stopped = call(cli, 'stop', 'session.stop', {}, expected={'stateRevision': active['stateRevision']}, **owner)
        assert stopped['capture'] == 'stopped' and stopped['stopReason'] == 'requested', stopped
        assert stopped['archive']['recordedRows'] == stopped['source']['validatedRows'] == '6', stopped
        assert stopped['source']['cutoffBytes'] == str(sum(map(len, rows))) and stopped['source']['cutoffReached'], stopped
        assert stopped['source']['coverage'] == 'unknown' and stopped['source']['writerReceipt'] is None, stopped

        # 停止后的源文件可继续追加；之前提交的项目段及其水位保持不变。
        segments = sorted(raw.glob('*.ksaseg'))  # 原始记录的生产封装。
        assert len(segments) == int(stopped['archive']['segmentOrdinal']) == 4, segments
        with source.open('ab') as stream:
            stream.write(archive_line(7, packets[-1], pid=42, processCreation100ns=CREATION))
        assert call(cli, 'status-after-stop', 'session.query', {}, **owner)['archive'] == stopped['archive']
        assert call(cli, 'close', 'session.close', {}, expected={'stateRevision': stopped['stateRevision']}, **owner)['closed']
        frozen = call(cli, 'frozen', 'sample.query', identity | {'sampleId': opened['sampleId']})  # 回读采样描述及冻结设置。
        assert frozen['frozenSettings'] == settings and frozen['revisionId'] == saved['revisionId'], frozen
        assert shutdown(cli) == 0

        recorded = []  # 由磁盘独立解码出的原包，按项目全局封装序号拼接。
        sequence = 1  # 下一段首次出现的连续封装序号。
        for path in segments:
            decoded, _ = decode_raw(path, sequence)
            sequence += len(decoded)
            assert decoded[0][0] == opened['plan'] and decoded[0][1] == b''
            recorded.extend((metadata['sourceSequence'], wire) for metadata, wire in decoded
                            if metadata['kind'] == 'api-archive-packet-v1')
        assert recorded == [(str(index), wire) for index, wire in enumerate(packets, 1)]
        assert decoded[-1][0]['kind'] == 'api-archive-follow-end-v1'
        print(json.dumps({'cliSha256': hashlib.sha256(CLI.read_bytes()).hexdigest(),
                          'sampleId': opened['sampleId'], 'segments': len(segments), 'rows': len(recorded),
                          'cutoffBytes': stopped['source']['cutoffBytes']}), flush=True)


if __name__ == '__main__':
    with owned_project_path() as project:
        run(project)
    print('CLI_PASSIVE_API_SESSION=PASS', flush=True)
