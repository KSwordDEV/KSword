"""独立核对792字节保存上下文栈回执；不访问驱动，不以文件自洽替代采集来源证明。"""

import struct


def require(condition, message):
    """拒绝单个不一致，不修复证据或补造帧。"""
    if not condition:
        raise ValueError(message)


def kernel(address):
    """仅判断协议支持的x64规范内核数值范围，不解引用地址。"""
    return 0xffff800000000000 <= address < 0xffffffffffffffff


def decode_saved(wire, target, thread, mismatch=False, exited=False):
    """独立解包固定wire，并与夹具保存的真实身份对照；返回可供JSON继续交叉检查的事实。"""
    require(len(wire) == 792, 'saved response size')
    size, version, status, result, source, flags, pid, tid = struct.unpack_from('<8I', wire)
    process_time, thread_time, thread_object, process_object = struct.unpack_from('<4Q', wire, 32)
    requested, queued, start, end, qpc, frequency = struct.unpack_from('<6Q', wire, 104)
    count, limit, irql, timeout = struct.unpack_from('<4I', wire, 152)
    addresses = struct.unpack_from('<64Q', wire, 168)
    (saved, initial_ip, initial_sp, low, high, terminal_ip, terminal_sp, image,
     copied, state, processors, stop, stamp, image_size, guid, age, cs) = struct.unpack_from('<8Q6I16s2I', wire, 680)
    require((size, version) == (792, 1) and flags & ~0xc31 == 0, 'saved version or unknown flags')
    require((pid, tid) == (target['pid'], thread['tid']), 'saved PID/TID differs from independent fixture')
    require(not any(wire[64:104]) and queued == 0, 'saved source forged APC execution/queue evidence')
    require(requested > 0 and 0 < limit <= 64 and 0 < timeout <= 5000 and count <= limit, 'saved budgets/time')
    require(not any(addresses[count:]) and all(kernel(value) for value in addresses[:count]), 'saved frame address/tail')
    if mismatch:
        require((status, result, source, flags, count) == (0xc000022d, 2, 0, 0, 0), 'wrong-instance request was not rejected')
        require(not any(wire[32:104] + wire[120:152] + wire[680:]), 'wrong-instance request exposed object/stack evidence')
    elif exited:
        require(source == flags == count == 0 and status in (0xc000000b, 0xc000004b, 0xc0000225),
                'saved exited identity returned stale frames or was reused')
        require(not any(wire[32:104] + wire[120:152] + wire[680:]), 'saved exited lookup exposed stale object/stack evidence')
    else:
        require(flags & 1 and kernel(thread_object) and kernel(process_object), 'saved held objects')
        require((process_time, thread_time) == (int(target['processCreationTime']), int(thread['creationTime'])),
                'saved creation identity differs from independent fixture')
    complete = result == 5
    if source == 2:
        require(flags & 0x401 == 0x401 and irql == 2, 'saved frames lack rendezvous proof')
        require(requested <= start <= end and qpc > 0 and frequency > 0, 'saved copy timestamps')
        profiles = {
            (3986539294, 17063936): (bytes.fromhex('2dda23f98e237c7ce180b962b19a3781'), 0x3fbf96),
            (2952155935, 21299200): (bytes.fromhex('fec661b69972161d0fe37c48b8bc5470'), 0x6b97b6),
        }
        require((stamp, image_size) in profiles, 'saved unknown exact kernel')
        exact_guid, return_rva = profiles[(stamp, image_size)]
        require(age == 1 and guid == exact_guid and kernel(image), 'saved exact RSDS identity')
        require(kernel(low) and kernel(saved) and low <= saved < high and high - low <= 65536 and
                copied == high - saved and copied >= 0x180 and saved % 8 == 0, 'saved full copy bounds')
        require(initial_ip == image + return_rva and initial_sp == saved + 0x40, 'saved exact switch-frame origin')
        require(0 < processors <= 64 and state in (1, 3, 5, 7, 8), 'saved processor/state evidence')
        require(count > 0 and status == 0 and addresses[0] == initial_ip, 'saved first frame/status')
        if complete:
            require(flags == 0xc01 and stop == 1 and cs & 3 == 3, 'saved completion lacks machine-frame evidence')
            require(0x1000 <= terminal_ip < 0x0000800000000000 and 0x1000 <= terminal_sp < 0x0000800000000000,
                    'saved terminal user RIP/RSP')
        else:
            require(result == 1 and flags & 0x10 and not flags & 0x800 and stop in (2, 3, 4, 5), 'saved partial semantics')
            require(bool(flags & 0x20) == (stop == 2) and (stop != 2 or count == limit), 'saved frame-budget truncation')
    else:
        require(source == count == 0 and flags & ~1 == 0 and result in (0, 2) and status & 0x80000000,
                'saved unavailable response fabricated frames/success')
    return {'pid': pid, 'tid': tid, 'frameCount': count, 'ntStatus': hex(status), 'result': result,
            'flags': hex(flags), 'complete': complete, 'source': source, 'requested': requested,
            'start': start, 'end': end, 'irql': irql, 'addresses': addresses[:count],
            'savedContext': {'savedKernelStack': saved, 'initialInstructionPointer': initial_ip,
                'initialStackPointer': initial_sp, 'stackLow': low, 'stackHigh': high,
                'terminalInstructionPointer': terminal_ip, 'terminalStackPointer': terminal_sp,
                'terminalCodeSegment': cs, 'snapshotByteCount': copied, 'processorCount': processors,
                'threadState': state, 'unwindStop': stop},
            'evidenceConsistencyVerified': True, 'acquisitionIndependentlyProven': False}


def verify_saved(packet, target, thread):
    """逐项对照生产GUI/CLI共用投影的JSON与原始保存上下文wire，不依赖生产验证器。"""
    data = packet['data']
    facts = decode_saved(bytes.fromhex(data['wireResponse']), target, thread)
    require(data['target']['pid'] == facts['pid'] and data['tid'] == facts['tid'] and data['targetAliveAtReadback'], 'saved JSON target')
    require(data['frameProjection'] == 'shared_gui_cli_verified_capture' and data['requestedMethod'] in ('saved', 'auto') and
            int(data['ioctlFunction'], 16) == 0x8d7, 'saved production shared path/method')
    require(data['identityVerified'] and not any(data[key] for key in ('queued', 'executedInTarget', 'ownApcCancelled', 'retirementVerified')),
            'saved JSON forged APC guarantees')
    count = facts['frameCount']
    require(data['frameCount'] == len(data['frames']) == count and
            [int(frame['address'], 16) for frame in data['frames']] == list(facts['addresses']), 'saved JSON frame chain differs')
    require(data['ntStatus'].lower() == facts['ntStatus'] and int(data['requestTime100ns']) == facts['requested'], 'saved JSON status/request time')
    require(data['complete'] == facts['complete'] and data['originalStackCompleteness'] ==
            ('kernel_chain_to_user_machine_frame' if facts['complete'] else 'unknown'), 'saved JSON completeness differs')
    for key, value in facts['savedContext'].items():
        actual = data['savedContext'][key]
        require((int(actual, 16) if isinstance(actual, str) else actual) == value, f'saved JSON field {key}')
    if count:
        require(data['live'] and data['source'] == 'target_saved_context' and data['availability'] ==
                ('complete' if facts['complete'] else 'partial'), 'saved JSON availability/source')
        require(int(data['captureStartTime100ns']) == facts['start'] and int(data['captureEndTime100ns']) == facts['end'] and
                data['captureIrql'] == facts['irql'], 'saved JSON copy times/IRQL')
    else:
        require(not data['live'] and data['source'] == 'none', 'saved unavailable JSON source')
    for frame in data['frames']:
        require(not frame['module'] or int(frame['moduleBase'], 16) <= int(frame['address'], 16), 'saved module base')
        require(not frame['localPdbMatched'] or bool(frame['module'] and frame['symbol']), 'saved unmatched symbol evidence')
    return {key: value for key, value in facts.items() if key not in ('addresses',)}


def verify_saved_raw(packet, target, thread, mismatch=False, exited=False):
    """核对独立原始IOCTL回执，明确区分错误实例拒绝与目标退出/排空的零帧事实。"""
    data = packet['data']
    require(data['transportSuccess'] and data['bytesReturned'] == 792, 'saved raw transport')
    facts = decode_saved(bytes.fromhex(data['outputHex']), target, thread, mismatch, exited)
    return {key: value for key, value in facts.items() if key not in ('addresses',)}
