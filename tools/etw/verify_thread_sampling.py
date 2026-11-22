"""Verify offline StackWalk/SampledProfile evidence from one tracerpt -of XML -lr -rts dump."""

import argparse
from collections import Counter
from dataclasses import dataclass
import json
import ntpath
import re
import sys
import xml.etree.ElementTree as ET


EVENT = "{http://schemas.microsoft.com/win/2004/08/events/event}"
TRACE = "{http://schemas.microsoft.com/win/2004/08/events/trace}"
STACK = "def2fe46-7bd6-4b80-bd94-f57fe20d0ce3"
PERF = "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"
IMAGE = "2cb15d1d-5fc1-11d2-abe1-00a0c911f518"
MAX_ID = 0xFFFFFFFE  # 排除事件头及载荷可能使用的全 1 哨兵。
MAX_U64 = (1 << 64) - 1
MAX_KEYS = 100_000
MAX_IMAGE_RECORDS = 4096
UINT_TEXT = re.compile(r"(?:[0-9]{1,20}|0[xX][0-9a-fA-F]{1,16})\Z")
FRAME_NAME = re.compile(r"Stack[1-9][0-9]*\Z")


def uint(value, maximum=MAX_U64):
    value = (value or "").strip()
    if not UINT_TEXT.fullmatch(value):
        return None
    number = int(value, 16 if value[:2].lower() == "0x" else 10)
    return number if number <= maximum else None


def records(source):
    # 由 tracerpt 的根元素直接承载 Event；消费后移除节点而非留下空节点。
    depth = 0
    root = None
    for action, node in ET.iterparse(source, events=("start", "end")):
        if action == "start":
            depth += 1
            if depth == 1:
                if node.tag not in ("Events", EVENT + "Events", TRACE + "Events"):
                    raise ValueError("expected a tracerpt Events document")
                root = node
            continue
        if depth == 2:
            if node.tag == EVENT + "Event":
                system = node.find(EVENT + "System")
                if system is not None:
                    guid = node.findtext(f"{TRACE}ExtendedTracingInfo/{TRACE}EventGuid", "")
                    guid = guid.strip().strip("{}").lower()
                    if guid in (STACK, PERF, IMAGE):
                        opcode = uint(system.findtext(EVENT + "Opcode"), 255)
                        version = uint(system.findtext(EVENT + "Version"), 255)
                        time = system.find(EVENT + "TimeCreated")
                        execution = system.find(EVENT + "Execution")
                        qpc = uint(time.get("RawTime")) if time is not None else None
                        cpu = uint(execution.get("ProcessorID"), 0xFFFE) if execution is not None else None
                        fields = {}
                        for datum in node.findall(f"{EVENT}EventData/{EVENT}Data"):
                            name = datum.get("Name")
                            if name:
                                # 同名标量不允许后值覆盖；缺失或冲突不得推断。
                                fields[name] = datum.text if name not in fields else None
                        yield guid, opcode, version, qpc, cpu, fields
            root.remove(node)
            node.clear()
        depth -= 1


def kernel_interval(source, start, end):
    """只接受整个夹具窗口内无冲突的同一段 ntoskrnl 映像证据。"""
    ranges, loaded = set(), set()
    rundown = False
    count = 0
    for guid, opcode, version, qpc, _, data in records(source):
        if guid != IMAGE or ntpath.basename(data.get("FileName") or "").lower() != "ntoskrnl.exe":
            continue
        count += 1
        if count > MAX_IMAGE_RECORDS:
            raise ValueError("too many ntoskrnl image records")
        base, size = uint(data.get("ImageBase")), uint(data.get("ImageSize"))
        owner = uint(data.get("ProcessId"), MAX_ID)
        if (version != 3 or opcode not in (2, 3, 4, 10) or qpc is None or
                owner not in (0, 4) or not base or not size or base + size > MAX_U64 + 1):
            return None, "unsupported_or_incomplete_image_metadata"
        interval = (base, base + size)
        ranges.add(interval)
        # 3/4 是初始/结束枚举，不是装载/卸载。发生变更时不向前或向后猜测。
        if opcode == 2 or (opcode == 10 and start < qpc <= end):
            return None, "image_lifetime_not_stable"
        if opcode == 10 and qpc <= start:
            loaded.add(interval)
        if opcode == 3 and qpc <= start:
            rundown = True
        if opcode == 4 and qpc >= end:
            rundown = True
    if not ranges:
        return None, "no_ntoskrnl_image_record"
    if len(ranges) != 1:
        return None, "conflicting_ntoskrnl_intervals"
    interval = next(iter(ranges))
    if interval not in loaded and not rundown:
        return None, "image_lifetime_not_established"
    return interval, "recorded"


@dataclass(slots=True)
class Candidates:
    fixture_stacks: int = 0
    competing_stacks: int = 0
    fixture_samples: int = 0
    unknown_samples: int = 0
    kernel_depth: int = 0


def analyze(source, pid, tid, start, end):
    if not (0 < pid <= MAX_ID and 0 < tid <= MAX_ID and 0 < start < end <= MAX_U64):
        raise ValueError("expected positive PID/TID and an increasing QPC interval")
    interval, module_status = kernel_interval(source, start, end)
    source.seek(0)
    keys = {}
    # 键的 TID 在筛选阶段已固定；此处只保留时间、CPU 和各侧计数，不保留帧地址。
    counts = Counter({name: 0 for name in (
        "fixture_stack_records", "stacks_with_ntoskrnl_frames", "max_ntoskrnl_depth",
        "fixture_sample_records", "matched_pairs", "matched_pairs_with_ntoskrnl_frames",
        "max_matched_ntoskrnl_depth", "unmatched_stack_records", "unmatched_sample_records",
        "ambiguous_keys", "ambiguous_stack_records", "ambiguous_sample_records",
        "same_tid_other_pid_stacks", "malformed_stack_records", "malformed_sample_records",
        "unkeyed_fixture_stacks", "unkeyed_fixture_samples",
    )})
    for guid, opcode, version, qpc, cpu, data in records(source):
        is_stack = guid == STACK and opcode == 32
        if not is_stack and not (guid == PERF and opcode == 46):
            continue
        subject_tid = uint(data.get("StackThread" if is_stack else "ThreadId"), MAX_ID)
        if subject_tid is not None and subject_tid != tid:
            continue
        if is_stack:
            # 栈事件本身的记录时间不是触发事件的时间；只能使用载荷的 EventTimeStamp。
            qpc = uint(data.get("EventTimeStamp"))
            subject_pid = uint(data.get("StackProcess"), MAX_ID)
        if qpc is not None and not start <= qpc <= end:
            continue
        is_fixture = version == 2 and subject_tid == tid
        if is_stack:
            is_fixture = is_fixture and subject_pid == pid
            if subject_tid == tid and subject_pid not in (None, pid):
                counts["same_tid_other_pid_stacks"] += 1
        group = "stack" if is_stack else "sample"
        if version != 2 or subject_tid is None or qpc is None or cpu is None or (is_stack and subject_pid is None):
            counts[f"malformed_{group}_records"] += 1
        if is_fixture and qpc is not None:
            counts[f"fixture_{group}_records"] += 1
            if cpu is None:
                counts[f"unkeyed_fixture_{group}s"] += 1
        if qpc is None:
            continue
        depth = 0
        if is_stack and is_fixture and interval is not None:
            lo, hi = interval
            depth = sum(lo <= frame < hi for name, value in data.items()
                        if FRAME_NAME.fullmatch(name) and (frame := uint(value)))
            if depth:
                counts["stacks_with_ntoskrnl_frames"] += 1
                counts["max_ntoskrnl_depth"] = max(counts["max_ntoskrnl_depth"], depth)
        # 缺失 CPU 的同一时刻记录可能与任一 CPU 上的同 TID 记录冲突。
        key = (qpc, cpu)
        if key not in keys:
            if len(keys) >= MAX_KEYS:
                raise ValueError("correlation key limit exceeded; select a smaller QPC interval")
            keys[key] = Candidates()
        candidate = keys[key]
        if is_stack and is_fixture:
            candidate.fixture_stacks += 1
            candidate.kernel_depth = max(candidate.kernel_depth, depth)
        elif is_stack:
            candidate.competing_stacks += 1
        elif is_fixture:
            candidate.fixture_samples += 1
        else:
            candidate.unknown_samples += 1

    for (qpc, cpu), candidate in keys.items():
        stacks, samples = candidate.fixture_stacks, candidate.fixture_samples
        if cpu is None or not (stacks or samples):
            continue
        if (stacks > 1 or samples > 1 or candidate.competing_stacks or candidate.unknown_samples
                or (qpc, None) in keys):
            counts["ambiguous_keys"] += 1
            counts["ambiguous_stack_records"] += stacks
            counts["ambiguous_sample_records"] += samples
        elif stacks == samples == 1:
            counts["matched_pairs"] += 1
            if candidate.kernel_depth:
                counts["matched_pairs_with_ntoskrnl_frames"] += 1
                counts["max_matched_ntoskrnl_depth"] = max(
                    counts["max_matched_ntoskrnl_depth"], candidate.kernel_depth)
        else:
            counts["unmatched_stack_records"] += stacks
            counts["unmatched_sample_records"] += samples

    return {
        "fixture": {"pid": pid, "tid": tid, "start_qpc": start, "end_qpc": end},
        "ntoskrnl_interval_status": module_status,
        "status": "verified" if counts["matched_pairs_with_ntoskrnl_frames"] else "no_verified_kernel_samples",
        "counts": dict(counts),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "Supply an inclusive QPC interval from one fixture lifetime on the machine that recorded the trace. "
        "Do not combine unrelated trace sessions. Exit 0: verified kernel sample; 1: input error; "
        "2: insufficient evidence. This is not a live stack backend or a trace-completeness check."
    ))
    parser.add_argument("xml", help="tracerpt XML file (not ETL)")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--tid", type=int, required=True)
    parser.add_argument("--start-qpc", type=int, required=True)
    parser.add_argument("--end-qpc", type=int, required=True)
    args = parser.parse_args()
    try:
        with open(args.xml, "rb") as source:
            result = analyze(source, args.pid, args.tid, args.start_qpc, args.end_qpc)
    except (OSError, ValueError, ET.ParseError) as error:
        print(f"verify_thread_sampling: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "verified" else 2


if __name__ == "__main__":
    sys.exit(main())
