"""在线栈独立核验器的合成变异测试；不访问驱动，不当作 VM 采集证据。"""

from copy import deepcopy
import struct
import unittest

from verify_live_thread_stack import verify, verify_exit


class WireVerifierTests(unittest.TestCase):
    def setUp(self):
        """构造明确标为合成的固定响应，只用于证明篡改会被核验器拒绝。"""
        self.target = {'pid': 123, 'processCreationTime': '1001'}
        self.thread = {'tid': 456, 'creationTime': '1002'}
        self.target['dormant'] = self.thread
        self.wire = bytearray(680)
        struct.pack_into('<8I', self.wire, 0, 680, 2, 0, 1, 1, 0x21f, 123, 456)
        objects = (0xffff800000001000, 0xffff800000002000)
        struct.pack_into('<4Q', self.wire, 32, 1001, 1002, *objects)
        struct.pack_into('<2I', self.wire, 64, 123, 456)
        struct.pack_into('<4Q', self.wire, 72, *objects, 1001, 1002)
        struct.pack_into('<6Q', self.wire, 104, 1100, 1101, 1200, 1201, 20, 10000000)
        struct.pack_into('<4I', self.wire, 152, 1, 64, 1, 5000)
        struct.pack_into('<Q', self.wire, 168, 0xffff800000003000)
        self.packet = {'data': {
            'target': {'pid': 123}, 'tid': 456, 'targetAliveAtReadback': True,
            'frameCount': 1, 'frames': [{'address': '0xffff800000003000', 'module': '', 'moduleBase': '0x0',
                                      'symbol': '', 'localPdbMatched': False}],
            'ntStatus': '0x0', 'identityVerified': True, 'queued': True, 'executedInTarget': True,
            'ownApcCancelled': False, 'retirementVerified': True, 'complete': False,
            'originalStackCompleteness': 'unknown', 'frameProjection': 'shared_gui_cli_verified_capture',
            'requestTime100ns': '1100', 'captureStartTime100ns': '1200', 'captureEndTime100ns': '1201',
            'availability': 'partial', 'source': 'target_normal_apc', 'live': True}}

    def checked(self, wire=None, packet=None):
        """仅替换传入的原始字节；JSON 仍独立保留，防止两边一起被测试无意改成一致。"""
        candidate = deepcopy(packet or self.packet)
        candidate['data']['wireResponse'] = (wire or self.wire).hex()
        return verify(candidate, self.target, self.thread)

    def test_raw_frames_do_not_need_symbols(self):
        self.assertTrue(self.checked()['evidenceConsistencyVerified'])

    def test_json_cannot_replace_frames(self):
        packet = deepcopy(self.packet)
        packet['data']['frames'][0]['address'] = '0xffff800000004000'
        with self.assertRaises(ValueError):
            self.checked(packet=packet)

    def test_mutated_wire_facts_rejected(self):
        for offset, fmt, value in [(4, 'I', 1), (20, 'I', 0x21f | 0x400), (20, 'I', 0x11f),
                                   (40, 'Q', 1003), (68, 'I', 457), (160, 'I', 2), (176, 'Q', 1)]:
            with self.subTest(offset=offset, value=value):
                wire = bytearray(self.wire)
                struct.pack_into('<' + fmt, wire, offset, value)
                with self.assertRaises(ValueError):
                    self.checked(wire)

    def test_timeout_needs_real_cancellation(self):
        wire = bytearray(self.wire)
        wire[64:104] = bytes(40)
        wire[120:152] = bytes(32)
        wire[168:] = bytes(512)
        struct.pack_into('<4I', wire, 8, 0x102, 3, 0, 0x303)
        struct.pack_into('<I', wire, 152, 0)
        struct.pack_into('<I', wire, 160, 0)
        packet = deepcopy(self.packet)
        packet['data'].update(ntStatus='0x102', frameCount=0, frames=[], executedInTarget=False,
                              ownApcCancelled=True, source='none', live=False, availability='timeout',
                              captureStartTime100ns=None, captureEndTime100ns=None)
        self.assertTrue(self.checked(wire, packet)['evidenceConsistencyVerified'])
        struct.pack_into('<I', wire, 20, 0x203)
        with self.assertRaises(ValueError):
            self.checked(wire, packet)

    def test_exit_execution_must_follow_trigger(self):
        packet = {'data': {'outputHex': self.wire.hex(), 'transportSuccess': True, 'bytesReturned': 680}}
        self.assertEqual(verify_exit(packet, self.target, 1150)['mode'], 'target_apc_executed_during_exit')
        with self.assertRaises(ValueError):
            verify_exit(packet, self.target, 1300)


if __name__ == '__main__':
    unittest.main()
