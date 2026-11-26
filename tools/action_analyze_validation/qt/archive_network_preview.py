"""在正式 Qt 归档总览中回读既有的合成网络 Stored 夹具。"""

import hashlib
import json
import os
import subprocess
from contextlib import ExitStack
from runpy import run_path
from uuid import UUID

from archive_api_preview import check_location, choose_project_path, fixture_directory, read_table, test_window
from continuous_etw import cleanup_child, shutdown
from isolated_desktop import require_isolated_desktop
from live_etw import call, controller
from live_preview import RELEASE, ROOT, dispatch, open_overview, unique, until
from project_v1 import regular_identity
from smoke import SCHEMAS, artifact_sha, contract, invoke


SCRATCH = RELEASE / "action-analyze-qt-network-validation"  # 一次回读独占的固定资料目录。
NATIVE = RELEASE / "KswordARKLightStoredEvidenceValidation.exe"  # 现有原生写入及读回夹具。
NATIVE_OUTPUT = ROOT / "KswordARKLight/x64/Release/ActionAnalyzeTests"  # 现有项目的固定 IntDir 父目录。
PAYLOAD = bytes.fromhex("00 ff 80 0e 00 4b 53")  # 原生夹具定义的短通信字节。
LARGE_PAYLOAD = PAYLOAD + b"\x5d" * (300 - len(PAYLOAD))  # 预览界限外也有真实归档字节。
PREVIEW = "通信字节预览（十六进制）"  # 共享详情字段名。
BLOCK_HEADER_BYTES = 80  # Stored v1 块头长度，CRC 故障坐标指向块体起点。


def native_fixture():
    """调用现有离线夹具，返回完整段、首块结束位置和长载荷字节起点。"""
    check_location(NATIVE)
    for ancestor in (*reversed(NATIVE_OUTPUT.parents), NATIVE_OUTPUT):  # 防止固定测试目录重定向。
        if ancestor.is_relative_to(ROOT):
            regular_identity(ancestor)
    owned = NATIVE_OUTPUT / "network-replay-fixture"  # 原生夹具内部独占创建和清理的位置。
    assert not os.path.lexists(owned), owned
    tracked = subprocess.check_output(  # 核对原生夹具即将清理的位置。
        ["git", "ls-files", "-z", "--", owned.relative_to(ROOT).as_posix()], cwd=ROOT, timeout=10
    )
    assert not tracked, owned
    # 仅为本次子进程启用夹具 stdout 导出，复用已有文件写入和断言。
    result = subprocess.run(
        [NATIVE, "--network-fixture", NATIVE_OUTPUT], cwd=RELEASE,
        env={**os.environ, "KSWORD_ACTION_ANALYZE_EMIT_NETWORK_FIXTURE": "1"},
        capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert not os.path.lexists(owned), owned
    lines = result.stdout.decode("ascii").splitlines()  # 导出前已经核对档案及坏 CRC 的前缀。
    prefix = "NETWORK_FIXTURE="  # 与专用原生夹具的 stdout 边界一致。
    dump = [line[len(prefix):] for line in lines if line.startswith(prefix)]
    assert len(dump) == 1, "缺少网络夹具字节导出，请重新构建 StoredEvidenceValidation.vcxproj"
    first, offset, encoded = dump[0].split()  # 原生读回交付的文档地址夹具坐标及字节。
    data = bytes.fromhex(encoded)
    first_end, large_offset = int(first), int(offset)
    assert 96 < first_end < large_offset < len(data)
    assert data[large_offset:large_offset + len(LARGE_PAYLOAD)] == LARGE_PAYLOAD
    return data, first_end, large_offset


def select_details(client, nodes, table, model, sequence):
    """按夹具的实际顺序选一行，返回归档坐标和网络详情字段。"""
    dispatch(client, "select_row", object_id=table["id"], row=sequence - 1,
             revision=model["revision"], confirmed=True)

    def fields():
        """从当前可见的共享详情模型读取字段，等待所选记录。"""
        for view in nodes():  # 跳过结果表和隐藏模型。
            if not view["visible"] or view["type"] != "item_view" or view["id"] == table["id"]:
                continue
            rows = read_table(client, view)["rows"]  # 兼容根字段和分组字段。
            merged = list(rows)
            for index, row in enumerate(rows):  # 两个分区共享同一选中记录。
                if row and row[0] in {"归档记录", "网络证据"}:
                    merged.extend(read_table(client, view, [index])["rows"])
            values = {str(row[0]): str(row[1]) for row in merged if len(row) >= 2}
            if values.get("记录序号") == str(sequence) and "归档载荷状态" in values:
                return values
        return {}

    return until(fields, bool)


def check_payload(path, fields, expected):
    """从窗口报告的文件偏移直接读出所有保留字节，并核对预览与记录序号。"""
    record = int(fields["文件偏移（字节）"])  # Stored 记录头起点。
    offset = int(fields["归档字节起点"])  # 实际通信字节起点。
    count = int(fields["预览字节数"])  # Qt 只展示至多 256 字节。
    assert count == min(256, len(expected)) and int(fields["归档保留字节数"]) == len(expected), fields
    with path.open("rb") as archive:
        archive.seek(record + 16)  # Stored v1 记录序号位于头内第 16 字节。
        assert int.from_bytes(archive.read(8), "little") == int(fields["记录序号"]), fields
        archive.seek(offset)
        actual = archive.read(len(expected))  # 包括界面预览范围以外的内容。
    assert actual == expected and bytes.fromhex(fields[PREVIEW]) == actual[:count], fields


def verify_window(client, complete, truncated, corrupt, original, first_end, large_offset):
    """以同一正式窗口从独立段入口对照完整、截断和 CRC 故障三份文件。"""
    nodes, active = open_overview(client)  # 监控 → 行为分析 → 总览。
    button = unique(active, lambda node: node["visible"] and node["name"] == "打开归档段")
    table = unique(active, lambda node: node["visible"] and node["class"] == "QTableView"
                   and {"PID", "TID", "事件"} <= set(read_table(client, node)["headers"]))

    def open_segment(path, message, end, rows, failure_offset=None):
        """从真实文件选择器提交路径，等待完整业务状态及可见表模型。"""
        choose_project_path(client, button, path)
        prefix = f"已校验前缀 {end} / {path.stat().st_size} 字节。"  # 状态必须回读真实文件范围。
        status_parts = [message, prefix]  # 失败时还需验证具体停止位置。
        if failure_offset is not None:
            status_parts.append(f"停止位置：{failure_offset} 字节。")
        until(lambda: any(node["visible"] and all(part in node["name"] for part in status_parts)
                          for node in nodes()), bool)
        return until(lambda: read_table(client, table), lambda model: model["row_total"] == rows)

    full = open_segment(complete, "归档已读至文件末尾。", len(original), 9)
    event = full["headers"].index("事件")  # 终止记录不应伪装成网络流。
    assert [row[event] for row in full["rows"]].count("网络通信记录") == 8, full
    metadata = select_details(client, nodes, table, full, 1)
    expected = {  # 首行只有元数据，归档 PID／进程创建时间和端口零均来自合成观测。
        "采样 ID": str(UUID(bytes=original[48:64])), "归档段号": "1", "协议": "TCP", "方向": "出站",
        "源端点": "192.0.2.8:0", "目的端点": "198.51.100.12:443", "进程 PID": "175",
        "归档中的进程创建时间（FILETIME）": str(0x1000020000400), "进程对象 ID": "27",
        "接收 QPC": "0", "归档载荷状态": "仅网络元数据", "归档保留字节数": "0",
        "事件来源": "ETW（归档声明，来源未验证）",
    }
    assert all(metadata.get(key) == value for key, value in expected.items()), metadata
    assert PREVIEW not in metadata and "归档字节起点" not in metadata

    captured = select_details(client, nodes, table, full, 2)  # 相同端点下存在真实短载荷的独立记录。
    assert captured["归档载荷状态"] == "已保留完整通信字节", captured
    check_payload(complete, captured, PAYLOAD)
    partial = select_details(client, nodes, table, full, 4)  # 来源截断与界面预览上限是不同状态。
    assert (partial["协议"], partial["方向"], partial["源端点"], partial["目的端点"]) == (
        "UDP", "入站", "2001:db8::12", "[2001:db8::1]:53"
    ), partial
    assert partial["归档载荷状态"] == "已保留部分通信字节" and partial["原始通信长度（字节）"] == "10", partial
    check_payload(complete, partial, PAYLOAD)

    limited = select_details(client, nodes, table, full, 8)  # 完整保存 300 字节，窗口展示 256 字节。
    assert limited["归档载荷状态"] == "已保留完整通信字节", limited
    assert int(limited["归档字节起点"]) == large_offset, limited
    check_payload(complete, limited, LARGE_PAYLOAD)

    # 使用不同路径提交两个故障副本，使窗口显示新文件的已校验前缀。
    failures = (
        (truncated, "归档尾部不完整。", truncated.stat().st_size),
        (corrupt, "归档封装或记录校验失败。", first_end + BLOCK_HEADER_BYTES),
    )
    for path, message, offset in failures:  # 两种故障共享首个完整块。
        prefix = open_segment(path, message, first_end, 7, offset)
        assert prefix["rows"] == full["rows"][:7], prefix
        fields = select_details(client, nodes, table, prefix, 4)
        assert fields == partial, fields
        check_payload(path, fields, PAYLOAD)


def verify_cli(directory, original, damaged, first_end):
    """把同一份合成段加入正式项目，核对完整字节、末块边界及错误坐标。"""
    crc32c = run_path(str(SCHEMAS / 'check_base_v1.py'))['crc32c']  # 独立 Stored CRC 实现。
    envelope, methods = contract()  # 使用正式方法响应 schema 校验完整字段。
    schema = 'https://ksword.invalid/schemas/action_analyze/' + methods['archive.inspect']['resultSchema']
    validator = envelope.evolve(schema={'$ref': schema})
    project = directory / 'network-project'  # 由正式 CLI 登记的专用项目。

    with ExitStack() as children:
        cli = controller('offline')  # 不启动实时来源或读取其他项目。
        children.callback(cleanup_child, cli)
        created = call(cli, 'create-network-project', 'project.create', {'path': str(project),
                       'settings': {'title': 'Network archive validation', 'notes': ''}})
        sample = call(cli, 'create-network-sample', 'sample.create', {'projectId': created['projectId'],
                      'expectedRevisionId': created['revisionId'], 'title': 'Synthetic network archive'})
        identity = {'projectId': created['projectId'], 'sampleId': sample['sampleId']}
        raw = project / 'samples' / sample['sampleId'] / 'raw'  # 文件名由项目规则固定。
        raw.mkdir(exist_ok=True)

        # 仅重建归档段头中的项目、采样、段号和段头 CRC。正文及坏块保持原样。
        for ordinal, source in enumerate((original, damaged), 1):
            data = bytearray(source)
            data[24:32] = ordinal.to_bytes(8, 'little')
            data[32:48] = UUID(identity['projectId']).bytes
            data[48:64] = UUID(identity['sampleId']).bytes
            data[92:96] = crc32c(data[:92]).to_bytes(4, 'little')
            with (raw / f'{ordinal:020d}.ksaseg').open('xb') as stream:
                stream.write(data)

        def inspect(label, ordinal, sequence, offset, error=None):
            params = identity | {'stream': 'raw', 'ordinal': str(ordinal), 'view': 'network',
                                 'recordSequence': str(sequence), 'recordOffset': str(offset)}
            result = call(cli, label, 'archive.inspect', params, error=error)
            if error is None:
                validator.validate(result)
            return result

        first_record = 96 + BLOCK_HEADER_BYTES  # 第一个块的首条记录。
        long_record = first_end + BLOCK_HEADER_BYTES  # 第二块首个原始网络流。
        complete = inspect('network-complete', 1, 8, long_record)
        assert bytes.fromhex(complete['bytesHex']) == LARGE_PAYLOAD, complete
        assert complete['metadata']['capturedLength'] == '300' and complete['metadata']['direction'] == '1', complete
        assert complete['sourceTrust'] == 'recorded-declaration' and complete['metadata']['family'] == '6', complete
        metadata = inspect('network-verified-first-block', 2, 1, first_record)
        assert metadata['bytesHex'] == '' and metadata['verifiedBlockEnd'] == str(first_end), metadata
        assert metadata['metadata']['destinationAddress'] == 'c633640c' and metadata['metadata']['direction'] == '2', metadata
        inspect('network-invalid-pair', 1, 8, first_record, error='invalid-params')
        inspect('network-unreadable-block', 2, 8, long_record, error='project-corrupt')
        inspect('network-missing-record', 1, 99, long_record + 1, error='project-data-not-found')
        inspect('network-offset-before-records', 1, 1, first_record - 1, error='invalid-params')
        assert shutdown(cli) == 0

    # 重开同一项目，验证 REPL 参数与 JSONL 返回相同的记录和字节。
    commands = (f'project open "{project}"\n'
                f'archive inspect {identity["sampleId"]} raw 1 network 8 {long_record}\nquit\n')
    stdout, stderr = invoke(('analyze', 'session', '--backend', 'offline'), commands.encode('utf-8'),
                            label='Archive network REPL')
    replies = [json.loads(line) for line in stdout.decode('utf-8').splitlines() if line.startswith('{')]
    assert not stderr and len(replies) == 2 and replies[1] == complete, (stdout, stderr)
    print(f"CLI_NETWORK_ARCHIVE_REPLAY=PASS BYTES=300 SAMPLE={identity['sampleId']} CLI_SHA256={artifact_sha()}", flush=True)


def main():
    """只在隔离桌面运行，清理三份固定夹具后给出正式窗口回执。"""
    require_isolated_desktop()
    original, first_end, large_offset = native_fixture()  # 已核验的原始段及物理坐标。
    damaged = bytearray(original)  # 损坏第二块内一个实际通信字节，保留原 CRC。
    damaged[large_offset] ^= 1
    cutoff = large_offset + len(LARGE_PAYLOAD) - 1  # 在第二块载荷最后一字节前物理截断。
    with fixture_directory(SCRATCH) as directory:
        verify_cli(directory, original, damaged, first_end)
        complete = directory / "complete.ksaseg"  # 一次运行独占的三份候选文件。
        truncated = directory / "truncated.ksaseg"
        corrupt = directory / "corrupt.ksaseg"
        copies = {complete: original, truncated: original[:cutoff], corrupt: bytes(damaged)}
        for path, data in copies.items():  # 文件必须由本轮创建，不能覆盖任何已有归档。
            with path.open("xb") as stream:
                stream.write(data)
        with test_window() as client:  # 共享运行前检查和窗口设置恢复。
            verify_window(client, complete, truncated, corrupt, original, first_end, large_offset)
        assert all(path.read_bytes() == data for path, data in copies.items())
    print(f"QT_NETWORK_ARCHIVE_REPLAY=PASS ROWS=9/7/7 PREFIX_BYTES={first_end} "
          f"SEGMENT_SHA256={hashlib.sha256(original).hexdigest()}", flush=True)


if __name__ == "__main__":
    main()
