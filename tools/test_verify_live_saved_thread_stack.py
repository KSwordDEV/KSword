"""保存上下文独立核验器的合成变异回归；不访问驱动，不提供现场采集结论。"""

from copy import deepcopy
import struct
import unittest

from verify_live_saved_thread_stack import verify_saved, verify_saved_raw


class SavedWireVerifierTests(unittest.TestCase):
    def setUp(self):
        """构造明确标为合成的完整内核链协议，不复用生产验证器或实际回执作为预期。"""
        self.target = {'pid': 123, 'processCreationTime': '1001'}
        self.thread = {'tid': 456, 'creationTime': '1002'}
        self.wire = bytearray(792)
        base, saved = 0xfffff80010000000, 0xffffa00000001000
        struct.pack_into('<8I', self.wire, 0, 792, 1, 0, 5, 2, 0xc01, 123, 456)
        struct.pack_into('<4Q', self.wire, 32, 1001, 1002, 0xffff800000001000, 0xffff800000002000)
        struct.pack_into('<6Q', self.wire, 104, 1100, 0, 1200, 1201, 20, 10000000)
        struct.pack_into('<4I', self.wire, 152, 1, 64, 2, 5000)
        struct.pack_into('<Q', self.wire, 168, base + 0x3fbf96)
        struct.pack_into('<8Q6I16s2I', self.wire, 680, saved, base + 0x3fbf96, saved + 0x40,
                         saved, saved + 0x2000, 0x7ff612341000, 0x123450000, base,
                         0x2000, 5, 4, 1, 3986539294, 17063936,
                         bytes.fromhex('2dda23f98e237c7ce180b962b19a3781'), 1, 0x33)
        self.packet = {'data': {
            'target': {'pid': 123}, 'tid': 456, 'targetAliveAtReadback': True,
            'frameCount': 1, 'frames': [{'address': hex(base + 0x3fbf96), 'module': '', 'moduleBase': '0x0',
                                      'symbol': '', 'localPdbMatched': False}],
            'ntStatus': '0x0', 'identityVerified': True, 'queued': False, 'executedInTarget': False,
            'ownApcCancelled': False, 'retirementVerified': False, 'complete': True,
            'originalStackCompleteness': 'kernel_chain_to_user_machine_frame',
            'frameProjection': 'shared_gui_cli_verified_capture', 'requestedMethod': 'saved', 'ioctlFunction': '0x8d7',
            'requestTime100ns': '1100', 'captureStartTime100ns': '1200', 'captureEndTime100ns': '1201',
            'captureIrql': 2, 'availability': 'complete', 'source': 'target_saved_context', 'live': True,
            'savedContext': {'savedKernelStack': hex(saved), 'initialInstructionPointer': hex(base + 0x3fbf96),
                'initialStackPointer': hex(saved + 0x40), 'stackLow': hex(saved), 'stackHigh': hex(saved + 0x2000),
                'terminalInstructionPointer': '0x7ff612341000', 'terminalStackPointer': '0x123450000',
                'terminalCodeSegment': '0x33', 'snapshotByteCount': 0x2000, 'processorCount': 4,
                'threadState': 5, 'unwindStop': 1}}}

    def checked(self, wire=None, packet=None):
        """只替换明确传入的一侧，确保JSON和wire不会被无意一同修正。"""
        candidate = deepcopy(self.packet if packet is None else packet)
        candidate['data']['wireResponse'] = (self.wire if wire is None else wire).hex()
        return verify_saved(candidate, self.target, self.thread)

    def test_complete_raw_addresses_do_not_require_symbols(self):
        self.assertTrue(self.checked()['complete'])

    def test_wire_mutations(self):
        """分别拒绝协议、身份、边界、复制长度和机器帧证据篡改。"""
        for offset, fmt, value in [(4, 'I', 2), (20, 'I', 0xc03), (40, 'Q', 1003),
                                  (64, 'I', 123), (160, 'I', 1), (176, 'Q', 1),
                                  (688, 'Q', 0xfffff80010000000), (704, 'Q', 0),
                                  (744, 'I', 0x1000), (748, 'I', 2), (752, 'I', 0),
                                  (764, 'I', 1), (784, 'I', 2), (788, 'I', 0x10)]:
            with self.subTest(offset=offset):
                wire = bytearray(self.wire)
                struct.pack_into('<' + fmt, wire, offset, value)
                with self.assertRaises(ValueError):
                    self.checked(wire)

    def test_json_mutations(self):
        for key, value in [('complete', False), ('queued', True), ('source', 'target_normal_apc'),
                           ('originalStackCompleteness', 'unknown'), ('ioctlFunction', '0x8d6')]:
            with self.subTest(key=key):
                packet = deepcopy(self.packet)
                packet['data'][key] = value
                with self.assertRaises(ValueError):
                    self.checked(packet=packet)

    def test_frame_limit_is_partial(self):
        wire = bytearray(self.wire)
        struct.pack_into('<I', wire, 12, 1)
        struct.pack_into('<I', wire, 20, 0x431)
        struct.pack_into('<I', wire, 156, 1)
        struct.pack_into('<I', wire, 756, 2)
        struct.pack_into('<I', wire, 788, 0)
        packet = deepcopy(self.packet)
        packet['data'].update(complete=False, availability='partial', originalStackCompleteness='unknown')
        packet['data']['savedContext'].update(unwindStop=2, terminalCodeSegment='0x0')
        self.assertFalse(self.checked(wire, packet)['complete'])
        struct.pack_into('<I', wire, 20, 0xc31)
        with self.assertRaises(ValueError):
            self.checked(wire, packet)

    def test_exited_identity_refusal_does_not_need_held_objects(self):
        wire = bytearray(792)
        struct.pack_into('<8I', wire, 0, 792, 1, 0xc000000b, 0, 0, 0, 123, 456)
        struct.pack_into('<Q', wire, 104, 1500)
        struct.pack_into('<4I', wire, 152, 0, 64, 0, 5000)
        packet = {'data': {'transportSuccess': True, 'bytesReturned': 792, 'outputHex': wire.hex()}}
        self.assertEqual(verify_saved_raw(packet, self.target, self.thread, exited=True)['frameCount'], 0)
        with self.assertRaises(ValueError):
            verify_saved_raw(packet, self.target, self.thread)


if __name__ == '__main__':
    unittest.main()
