"""只读独立核对在线栈JSON与各来源原始响应；文件自洽不等于独立证明采集来源。"""

import argparse
import hashlib
import json
from pathlib import Path
import struct


def require(condition, message):
    """条件不成立即拒绝证据，不修改回执或推导替代帧。"""
    if not condition:
        raise ValueError(message)


def verify(packet, target, thread):
    """输入原始 CLI 包与独立夹具身份；返回逐字节一致性摘要，不连接设备。"""
    data = packet['data']
    wire = bytes.fromhex(data['wireResponse'])
    if len(wire) == 792:
        from verify_live_saved_thread_stack import verify_saved
        return verify_saved(packet, target, thread)
    require(len(wire) == 680, 'fixed response size')
    size, version, status, result, source, flags, pid, tid = struct.unpack_from('<8I', wire)
    process_time, thread_time, thread_object, process_object = struct.unpack_from('<4Q', wire, 32)
    current_pid, current_tid = struct.unpack_from('<2I', wire, 64)
    current_thread, current_process, current_process_time, current_thread_time = struct.unpack_from('<4Q', wire, 72)
    request_time, queued_time, start, end, qpc, frequency = struct.unpack_from('<6Q', wire, 104)
    count, limit, irql, timeout = struct.unpack_from('<4I', wire, 152)
    addresses = struct.unpack_from('<64Q', wire, 168)
    require((size, version) == (680, 2) and flags & ~0x3bf == 0, 'protocol version or unknown flags')
    require((pid, tid, process_time, thread_time) == (
        target['pid'], thread['tid'], int(target['processCreationTime']), int(thread['creationTime'])),
        'frozen target identity differs from independent fixture')
    require(data['target']['pid'] == pid and data['tid'] == tid and data['targetAliveAtReadback'], 'JSON target')
    require(flags & 1 and thread_object >= 0xffff800000000000 and process_object >= 0xffff800000000000,
            'held kernel object identity')
    require(0 < limit <= 64 and 0 < timeout <= 5000 and count <= limit, 'capture budgets')
    require(not any(addresses[count:]), 'unused frame tail is nonzero')
    require(data['frameCount'] == count and len(data['frames']) == count, 'JSON frame count')
    require([int(frame['address'], 16) for frame in data['frames']] == list(addresses[:count]),
            'JSON changed frame addresses or order')
    require(data['ntStatus'].lower() == hex(status), 'JSON status differs from wire')
    for name, bit in [('identityVerified', 1), ('queued', 2), ('executedInTarget', 4),
                      ('ownApcCancelled', 0x100), ('retirementVerified', 0x200)]:
        require(data[name] == bool(flags & bit), f'JSON flag {name}')
    require(data['complete'] is False and data['originalStackCompleteness'] == 'unknown', 'unproven completeness')
    require(data['frameProjection'] == 'shared_gui_cli_verified_capture', 'production shared path')
    require(int(data['requestTime100ns']) == request_time and request_time > 0, 'request timestamp')
    if flags & 2:
        require(queued_time >= request_time and flags & 0x200, 'queued APC lacks timestamp or retirement')
    else:
        require(queued_time == 0 and not flags & (0x100 | 0x200), 'unqueued request claims cancellation/retirement')
    if count:
        require((status, result, source, irql) == (0, 1, 1, 1) and flags & 0x21f == 0x21f,
                'frames without target APC execution proof')
        require((current_pid, current_tid, current_thread, current_process, current_process_time, current_thread_time) ==
                (pid, tid, thread_object, process_object, process_time, thread_time), 'executing identity differs')
        require(queued_time <= start <= end and qpc > 0 and frequency > 0 and not flags & 0x100,
                'execution timing or impossible cancellation')
        require(int(data['captureStartTime100ns']) == start and int(data['captureEndTime100ns']) == end,
                'JSON execution timestamps')
        require(all(0xffff800000000000 <= address < 0xffffffffffffffff for address in addresses[:count]),
                'non-kernel address in frame chain')
        require(data['availability'] == 'partial' and data['source'] == 'target_normal_apc' and data['live'],
                'JSON source differs from real frame source')
        for frame in data['frames']:
            # 模块/PDB 缺失时生产代码必须保留裸地址；注释不可用不能反过来否认已经取得的真实帧。
            require(not frame['module'] or int(frame['moduleBase'], 16) <= int(frame['address'], 16), 'invalid module base')
            require(not frame['localPdbMatched'] or bool(frame['module'] and frame['symbol']), 'matched PDB without module/symbol')
    else:
        require(source == 0 and not any(wire[64:104] + wire[120:152]) and irql == 0,
                'unexecuted response exposes execution evidence')
        require(not data['live'] and data['source'] == 'none' and not data['captureStartTime100ns'], 'JSON fake execution')
        if result == 4:
            require(status == 0xc00000bb and not flags & 2 and data['availability'] == 'lifetime_unavailable',
                    'lifetime refusal queued or returned wrong status')
        elif result == 3:
            require(status == 0x102 and flags & 0x303 == 0x303 and data['availability'] == 'timeout',
                    'timeout lacks actual own cancellation and retirement')
        else:
            require(result == 0 and status in (0x80000011, 0xc0000056), 'unexpected no-frame lifecycle result')
            if status == 0x80000011:
                require(not flags & 2, 'busy response queued an APC')
            else:
                require(flags & 0x303 == 0x303, 'shutdown lacks own cancellation and retirement')
    return {'pid': pid, 'tid': tid, 'frameCount': count, 'ntStatus': hex(status), 'result': result,
            'flags': hex(flags), 'matchedSymbolFrames': sum(bool(frame['localPdbMatched']) for frame in data['frames']),
            'evidenceConsistencyVerified': True, 'acquisitionIndependentlyProven': False}


def verify_exit(packet, target, trigger):
    """独立核对原始 CLI 的退出竞争证据；允许退出路径实际投递，不冒充未执行的 rundown。"""
    data = packet['data']
    wire = bytes.fromhex(data['outputHex'])
    require(data['transportSuccess'] and data['bytesReturned'] == len(wire) == 680, 'exit transport size')
    size, version, status, result, source, flags, pid, tid = struct.unpack_from('<8I', wire)
    process_time, thread_time, thread_object, process_object = struct.unpack_from('<4Q', wire, 32)
    request_time, queued, start, end, qpc, frequency = struct.unpack_from('<6Q', wire, 104)
    count, limit, irql, timeout = struct.unpack_from('<4I', wire, 152)
    addresses = struct.unpack_from('<64Q', wire, 168)
    thread = target['dormant']
    require((size, version) == (680, 2) and flags & ~0x3bf == 0 and flags & 0x203 == 0x203, 'exit protocol and retirement')
    require((pid, tid, process_time, thread_time) == (target['pid'], thread['tid'],
            int(target['processCreationTime']), int(thread['creationTime'])), 'exit frozen identity')
    require(thread_object >= 0xffff800000000000 and process_object >= 0xffff800000000000, 'exit held objects')
    require(0 < request_time <= queued <= trigger and 0 < limit <= 64 and timeout == 5000, 'exit ordering/budgets')
    require(count <= limit and not any(addresses[count:]), 'exit frame budget/tail')
    if status == 0xc000004b:
        require(result == source == count == irql == 0 and flags & ~0x303 == 0 and
                not any(wire[64:104] + wire[120:152]), 'unexecuted exit has execution evidence')
        mode = 'unexecuted_target_exit'
    else:
        require((status, result, source, irql) == (0, 1, 1, 1) and flags & 0x31f == 0x21f and count > 0,
                'exit execution flags')
        current_pid, current_tid = struct.unpack_from('<2I', wire, 64)
        current = struct.unpack_from('<4Q', wire, 72)
        require((current_pid, current_tid) == (pid, tid) and current ==
                (thread_object, process_object, process_time, thread_time), 'exit actual execution identity')
        require(trigger <= start <= end and qpc > 0 and frequency > 0 and
                all(0xffff800000000000 <= address < 0xffffffffffffffff for address in addresses[:count]),
                'exit execution timing/frames')
        mode = 'target_apc_executed_during_exit'
    return {'pid': pid, 'tid': tid, 'frameCount': count, 'ntStatus': hex(status), 'mode': mode,
            'evidenceConsistencyVerified': True, 'acquisitionIndependentlyProven': False}


def main():
    """逐个核对实际套件事件中保存的在线采集回执，输出新报告且禁止覆盖已有证据。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    load = lambda name: json.loads((args.receipts / name).read_text(encoding='utf-8-sig'))
    suite, target = load('suite.json'), load('fixture-ready.json')
    reports = []
    for event in suite['events']:
        packet = load(event['receipt'])
        if event['name'] == 'dormant-stack-inflight-exit':
            report = verify_exit(packet, load('exit-fixture-ready.json'), int(suite['stackInFlightTargetExitTrigger100ns']))
        elif event['name'] in ('driver-saved-wrong-identity', 'saved-target-exit', 'saved-after-target-exit', 'saved-inflight-scm-stop'):
            from verify_live_saved_thread_stack import verify_saved_raw
            identity = load('saved-exit-ready.json') if event['name'] in ('saved-target-exit', 'saved-after-target-exit') else target
            thread = identity['wait'] if event['name'] == 'driver-saved-wrong-identity' else identity['dormant']
            report = verify_saved_raw(packet, identity, thread, event['name'] == 'driver-saved-wrong-identity', event['name'] == 'saved-after-target-exit')
        elif packet.get('command') == 'process thread stack capture':
            tid = packet['data']['tid']
            threads = [value for value in target.values() if isinstance(value, dict) and value.get('tid') == tid]
            require(len(threads) == 1, 'receipt does not map to exactly one independently observed owned thread')
            report = verify(packet, target, threads[0])
        else:
            continue
        path = args.receipts / event['receipt']
        reports.append({**report, 'receipt': str(path), 'receiptSha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    require(bool(reports), 'no capture receipts were verified')
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump({'source': str(args.receipts), 'captures': reports}, stream, ensure_ascii=False, indent=2)
    print(f'INDEPENDENT_LIVE_STACK_WIRE_CONSISTENCY=PASS captures={len(reports)}; acquisition proof requires deployment records')


if __name__ == '__main__':
    main()
