"""用正式 CLI 的 REPL 验证自有合成 JSONL 缩短后保留已提交证据。"""

from contextlib import ExitStack
import json

from continuous_etw import cleanup_child
from live_etw import CLI, Child, decode_raw, read_repl
from passive_api_session import CREATION, SESSION_ID, make_rows, wait_for_segment
from project_v1 import owned_project_path
from smoke import artifact_sha, invoke


def repl(child, command):
    """向自启 CLI 写入一条人工命令并返回其业务回执。"""
    child.send(command)
    return read_repl(child)


def follow(project, source, prefix):
    """在一个 REPL 会话内跟随并缩短自有输入，返回已提交及终态回执。"""
    with ExitStack() as cleanup:
        # 持有唯一创建的文件句柄，缩短同一文件而不是替换路径。
        fixture = cleanup.enter_context(source.open('x+b'))
        written = fixture.write(prefix)  # 已写入的两条合成记录总字节数。
        assert written == len(prefix)
        fixture.flush()
        # r3 仅用于开放 API 文件跟随入口；42 是合成声明，不查询实际进程。
        child = Child([CLI, 'analyze', 'session', '--input', 'repl', '--output', 'text', '--backend', 'r3'])
        cleanup.callback(cleanup_child, child)
        created = repl(child, f'project create "{project}" "Passive API REPL regression"')  # 唯一写入项目。
        opened = repl(child, f'open 42 {CREATION} api={SESSION_ID} "{source}" authorized "Synthetic source"')  # 文件跟随回执。
        assert opened['capture'] == 'active' and opened['projectId'] == created['projectId'], opened
        assert opened['source']['kind'] == 'passive-api-archive' and opened['plan']['checkpointRequired'], opened
        assert opened['plan']['durationMs'] == 0, opened
        sample = project / 'samples' / opened['sampleId']  # 本次 REPL 新建的采样。

        # 只有检查点和对应 status 都确认提交后才改变输入；固定前两条普通 API 包。
        wait_for_segment(sample / 'checkpoints', 1)
        committed = repl(child, 'status')  # 截短前的可信规则、段号和首次定位。
        assert committed['session'] == opened['session'] and committed['capture'] == 'active', committed
        assert committed['archive']['status'] == 'raw-verified', committed
        assert (committed['archive']['segmentOrdinal'], committed['archive']['recordedRows']) == ('1', '2'), committed
        assert committed['source']['state'] == 'at-tail' and committed['source']['visibleBytes'] == str(len(prefix)), committed
        assert committed['source']['diagnosis']['producerConnection'] == 'unknown', committed
        assert committed['readiness'] == {
            'state': 'observed', 'hooksInstalledSourceSequence': None,
            'firstRaw': {'segmentOrdinal': '1', 'rawSequence': '2', 'sourceSequence': '1'},
        }, committed
        rules = committed['rules']  # 已提交的规则计数和末次命中坐标。
        assert (rules['presetSet'], rules['profile'], rules['state'], rules['coverage'], rules['matchedRows']) == (
            'ksword.api.behavior-presets.v1', 'by-category', 'ready', 'unknown', '2'), rules
        assert rules['latest'] == {'ruleId': 'ksword.api.memory-write-observed.v1', 'segmentOrdinal': '1',
                                  'rawSequence': '3', 'sourceSequence': '2'}, rules

        # 让读取器自行发现它已看到的文件长度变小，不用 stop 制造中断表象。
        shortened = len(prefix) - 1  # 去掉已提交第二行的末尾换行。
        fixture.truncate(shortened)
        fixture.flush()
        wait_for_segment(sample / 'checkpoints', 2)  # 不发送命令，等终段自动发布。
        terminal = repl(child, 'status')  # 同一 REPL 返回的终态。
        assert (terminal['capture'], terminal['stopReason']) == ('partial', 'source-unavailable'), terminal
        assert terminal['session'] == committed['session'] and terminal['rules'] == rules, terminal
        assert terminal['readiness'] == (committed['readiness'] | {'state': 'source-interrupted'}), terminal
        report = terminal['source']  # 文件中断与生产方连接是两套状态。
        assert (report['state'], report['visibleBytes'], report['validatedRows'], report['coverage']) == (
            'source-changed', str(shortened), '2', 'unknown'), report
        assert not report['cutoffReached'] and report['writerReceipt'] is None, report
        assert report['diagnosis']['input'] == 'source-changed', report
        assert report['diagnosis']['producerConnection'] == 'unknown', report
        assert terminal['archive']['status'] == 'raw-verified', terminal
        assert (terminal['archive']['segmentOrdinal'], terminal['archive']['recordedRows']) == ('2', '2'), terminal

        # 已中断的 stop 不改写原因或归档；显式 close 后可在 CLI 仍活着时删除源文件。
        assert repl(child, 'stop') == terminal
        closed = repl(child, 'close')  # 当前采样的关闭回执。
        assert closed['closed'] and closed['session'] == committed['session'], closed
        fixture.close()
        source.unlink()
        assert repl(child, 'project close')['closed']
        child.send('quit')
        assert child.next_line().strip() == 'Closing controller'
        assert child.next_line().strip() == 'Session closed: shutdown'
        exit_code = child.process.wait(timeout=10)  # 显式关闭后的 REPL 进程退出码。
        assert exit_code == 0, exit_code
        print(f'REPL_EXIT={exit_code} SOURCE_REMOVED=True', flush=True)
        return committed, terminal


def verify_readback(project, packets, committed, terminal):
    """源文件已删除后，只读重开项目规则并核对首段原包。"""
    sample = terminal['sampleId']  # 只访问本轮 REPL 返回的采样。
    stdout, stderr = invoke(('analyze', 'replay-api-rules', '--backend', 'offline', '--project', str(project),
                              '--sample', sample, '--profile', 'by-category', '--json'), label='offline rule readback')
    assert not stderr, stderr
    replay = json.loads(stdout)['data']  # 正式离线规则回放的已核验结果。
    assert (replay['status'], replay['sampleId'], replay['profile'], replay['evaluatedClueRows']) == (
        'readback-verified', sample, 'by-category', committed['rules']['matchedRows']), replay
    # 归档可完整回查，但终段必须仍记录来源中断，不能冒充正常截止。
    coverage = replay['coverage']  # 回查两段的校验范围与终态。
    assert coverage['terminalVerified'] and coverage['verifiedSegments'] == '2', coverage
    assert coverage['verifiedPacketRows'] == '2' and coverage['collection'] == 'unknown', coverage
    assert coverage['followEnd'] == {'reason': 'source-unavailable', 'sourceState': 'source-changed',
                                    'cutoffReached': False, 'partialLineBytes': '0'}, coverage
    matches = [(hit['raw']['segment'], hit['raw']['sequence'], hit['sourceSequence'], hit['ruleId'])
               for hit in replay['matches']]  # 两条规则各自对应的原始坐标。
    rule_id = committed['rules']['latest']['ruleId']  # 中断前记录的真实末次命中规则。
    assert matches == [('1', '2', '1', rule_id), ('1', '3', '2', rule_id)], matches

    raw = project / 'samples' / sample / 'raw' / '00000000000000000001.ksaseg'  # 同一采样的首个已提交段。
    rows, _ = decode_raw(raw)  # 从磁盘独立解码并校验原始序号连续性。
    assert len(rows) == 3 and rows[0] == (committed['plan'], b''), rows[0]
    assert [meta['sourceSequence'] for meta, _ in rows[1:]] == ['1', '2'], rows[1:]
    assert [packet for _, packet in rows[1:]] == packets, 'committed raw packets changed'


def main():
    """复用固定 Release 夹具目录，运行一轮并在清理后报告结果。"""
    with owned_project_path() as project:
        packets, lines = make_rows()  # 只用已有生成器的前两条合成记录。
        source = project.parent / 'passive-repl-synthetic.jsonl'  # 无参数可指向真实归档。
        committed, terminal = follow(project, source, b''.join(lines[:2]))
        verify_readback(project, packets[:2], committed, terminal)
    print(f'PASSIVE_API_REPL=PASS SAMPLE={terminal["sampleId"]} CLI_SHA256={artifact_sha()} '
          'READINESS=source-interrupted SOURCE=source-changed PRODUCER=unknown RULES=2 RAW=1#2,1#3', flush=True)


if __name__ == '__main__':
    main()
