"""合成边界回归；真实 tracerpt 重放单独验收，不纳入测试数据。"""

import io
from unittest import TestCase, main, mock
from xml.sax.saxutils import escape

import verify_thread_sampling as tool


def event(guid, version, opcode, raw, cpu, **data):
    # 故意使用与目标相同的事件头身份；缺少载荷时仍不得关联。
    time = f'RawTime="{raw}"' if raw is not None else 'SystemTime="2026-11-21T00:00:00Z"'
    processor = f'ProcessorID="{cpu}"' if cpu is not None else ""
    payload = "".join(f'<Data Name="{name}">{escape(str(value))}</Data>'
                      for name, value in data.items() if value is not None)
    return (f'<Event xmlns="{tool.EVENT[1:-1]}"><System><Version>{version}</Version>'
            f'<Opcode>{opcode}</Opcode><TimeCreated {time}/>'
            f'<Execution ProcessID="10" ThreadID="20" {processor}/></System>'
            f'<EventData>{payload}</EventData>'
            f'<ExtendedTracingInfo xmlns="{tool.TRACE[1:-1]}"><EventGuid>{{{guid}}}</EventGuid>'
            f'</ExtendedTracingInfo></Event>')


def image(opcode=4, raw=400, base="0xFFFFF80000000000", owner=0):
    return event(tool.IMAGE, 3, opcode, raw, 0, ProcessId=owner,
                 FileName=r"\Device\Volume\Windows\System32\NTOSKRNL.EXE",
                 ImageBase=base, ImageSize="0x1000")


def stack(qpc=101, cpu=3, pid="0xA", tid="   20", version=2):
    return event(tool.STACK, version, 32, 145, cpu, StackProcess=pid, StackThread=tid,
                 EventTimeStamp=qpc, Stack1="0xFFFFF80000000000", Stack2="0xFFFFF80000000FFF",
                 Stack3="0xFFFFF80000001000", Stack4="0xFFFFF90000100000", Stack5="0x0")


def sample(qpc=101, cpu=3, tid=20):
    return event(tool.PERF, 2, 46, qpc, cpu, ThreadId=tid)


def analyze(*events):
    # 使用 UTF-16 BOM 模拟 tracerpt 的 Windows XML 输出。
    xml = ('<?xml version="1.0" encoding="UTF-16"?><Events>' + "".join(events) + "</Events>")
    return tool.analyze(io.BytesIO(xml.encode("utf-16")), 10, 20, 100, 200)


class ThreadSamplingTest(TestCase):
    def test_exact_match_and_half_open_kernel_image(self):
        result = analyze(sample(), stack(), image())
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["counts"]["matched_pairs_with_ntoskrnl_frames"], 1)
        self.assertEqual(result["counts"]["max_matched_ntoskrnl_depth"], 2)
        self.assertEqual(result["counts"]["unmatched_stack_records"], 0)

    def test_same_cpu_time_and_tid_required(self):
        counts = analyze(image(), stack(), sample(qpc=102), sample(cpu=4), sample(tid=21),
                         stack(qpc=201), sample(qpc=99))["counts"]
        self.assertEqual(counts["fixture_stack_records"], 1)
        self.assertEqual(counts["fixture_sample_records"], 2)
        self.assertEqual(counts["matched_pairs"], 0)
        self.assertEqual(counts["unmatched_stack_records"], 1)
        self.assertEqual(counts["unmatched_sample_records"], 2)

    def test_duplicate_and_competing_records_never_resolve(self):
        for competitor in (stack(), sample(), stack(pid=11), stack(version=3),
                           sample(tid=None), stack(tid=None), sample(cpu=None), stack(cpu=None)):
            with self.subTest(competitor=competitor):
                counts = analyze(image(), stack(), sample(), competitor)["counts"]
                self.assertEqual(counts["ambiguous_keys"], 1)
                self.assertEqual(counts["matched_pairs"], 0)

    def test_missing_payload_and_raw_time_never_use_event_header(self):
        counts = analyze(image(), stack(pid=None), stack(qpc=None), stack(qpc=103),
                         sample(), sample(qpc=None), sample(tid=None))["counts"]
        self.assertEqual(counts["fixture_stack_records"], 1)
        self.assertEqual(counts["fixture_sample_records"], 1)
        self.assertEqual(counts["matched_pairs"], 0)
        self.assertEqual(counts["malformed_stack_records"], 2)
        self.assertEqual(counts["malformed_sample_records"], 2)

    def test_kernel_metadata_cannot_be_inferred_from_address_or_header(self):
        for evidence, status in (
            ((), "no_ntoskrnl_image_record"),
            ((image(owner=None),), "unsupported_or_incomplete_image_metadata"),
            ((image(4, 105),), "image_lifetime_not_established"),
            ((image(), image(2, 103)), "image_lifetime_not_stable"),
            ((image(), image(base="0xFFFFF80000100000")), "conflicting_ntoskrnl_intervals"),
        ):
            with self.subTest(status=status):
                result = analyze(stack(), sample(), *evidence)
                self.assertEqual(result["ntoskrnl_interval_status"], status)
                self.assertEqual(result["counts"]["matched_pairs"], 1)
                self.assertEqual(result["counts"]["matched_pairs_with_ntoskrnl_frames"], 0)
                self.assertEqual(result["status"], "no_verified_kernel_samples")

    def test_correlation_cap_rejects_instead_of_dropping_keys(self):
        with mock.patch.object(tool, "MAX_KEYS", 1):
            with self.assertRaisesRegex(ValueError, "key limit"):
                analyze(image(), stack(), sample(qpc=102))


if __name__ == "__main__":
    main()
