"""Run with Volatility 3 on PYTHONPATH. Fixtures contain binary pages, not report rows."""
import importlib.util
import pathlib
import struct
import unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "Ksword5.1/Ksword5.1/forensics/kswordobjects.py"
spec = importlib.util.spec_from_file_location("kswordobjects", PLUGIN)
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)
bitmap_spec = importlib.util.spec_from_file_location("kswordbitmap", PLUGIN.with_name("kswordbitmap.py"))
bitmap = importlib.util.module_from_spec(bitmap_spec)
bitmap_spec.loader.exec_module(bitmap)


class CapturedPages:
    def __init__(self):
        self.pages = {}

    def table(self, pa, entries):
        page = bytearray(4096)
        for slot, entry in entries.items():
            struct.pack_into("<Q", page, slot * 8, entry)
        self.pages[pa] = bytes(page)

    def read(self, pa, size):
        if pa not in self.pages or size != 4096:
            raise plugin.exceptions.InvalidAddressException("capture", pa)
        return self.pages[pa]


class PageEvidence(unittest.TestCase):
    def setUp(self):
        self.ram = CapturedPages()
        self.ram.table(0x1000, {0: 0x2007, 300: 0x2007, 400: 0x1003})
        self.ram.table(0x2000, {1: 0x3007, 2: 0x40000087})
        self.ram.table(0x3000, {3: 0x4007, 4: 0x800087})
        self.ram.table(0x4000, {5: 0x11007, 6: 0x12340})

    def test_all_levels_and_large_pages(self):
        slots = dict(plugin.PageWalk(self.ram.read).slots(0x1000))
        digest, pages, software, gaps, tables, example = slots[0]
        self.assertEqual((pages, software, gaps, tables), (1 + 512 + 262144, 1, 0, 3))
        self.assertEqual(example, ((1 << 30) + (3 << 21) + (5 << 12), 0x11000, 4096))
        self.assertEqual(slots[300][0], digest)
        self.assertEqual(slots[400][0], b"self")

    def test_permissions_and_hardware_churn(self):
        def signature():
            return dict(plugin.PageWalk(self.ram.read).slots(0x1000, 256))[300][0]
        original = signature()
        self.ram.table(0x4000, {5: 0x11067, 6: 0x12340})
        self.assertEqual(original, signature())  # A/D do not change the mapping.
        self.ram.table(0x4000, {5: (1 << 63) | 0x11067, 6: 0x12340})
        self.assertNotEqual(original, signature())
        self.ram.table(0x4000, {5: 0x25007, 6: 0x12340})
        self.assertNotEqual(original, signature())
        self.ram.table(0x4000, {5: 0x11007, 6: 0x12340})
        self.ram.table(0x1000, {300: 0x2005})  # writable disabled at PML4.
        self.assertNotEqual(original, signature())

    def test_holes_and_reserved_entries(self):
        del self.ram.pages[0x4000]
        self.ram.table(0x3000, {3: 0x4007, 4: 0x802087})  # misaligned large leaf
        slots = dict(plugin.PageWalk(self.ram.read).slots(0x1000))
        self.assertEqual(slots[0][3], 2)
        self.assertEqual(slots[0][1], 262144)
        self.ram.table(0x1000, {300: 0x2087})
        self.assertEqual(dict(plugin.PageWalk(self.ram.read).slots(0x1000))[300][3], 1)

    def test_type6_bitmap_file_and_physical_extents(self):
        segments = bitmap.bitmap_segments(bytes([0b10000110, 0b1]), 9, 4, 0x3000, 0x8000)
        self.assertEqual(segments, [(0x1000, 0x3000, 8192, 8192), (0x7000, 0x5000, 8192, 8192)])
        with self.assertRaises(ValueError):
            bitmap.bitmap_segments(bytes([1, 0x80]), 9, 2, 0x3000, 0x8000)
        with self.assertRaises(ValueError):
            bitmap.bitmap_segments(bytes([0xFF]), 8, 1, 0x3000, 0xB000)
        with self.assertRaises(ValueError):
            bitmap.bitmap_segments(bytes([0xFF]), 8, 8, 0x3000, 0x7000)

    def test_tagless_object(self):
        offsets = (32, 40, 48, 80, 104, 112, 0)
        pos, data = 128, bytearray(512)
        data[pos] = 3
        struct.pack_into("<QQQQ", data, pos + 32, 908, 0x4010, 0xFFFF800000003000, 0xFFFF800000005000)
        data[pos + 80:pos + 85] = b"thing"
        struct.pack_into("<Q", data, pos + 104, 133000000000000000)
        self.assertNotIn(b"Proc", data)
        expect = list(plugin.candidate_offsets(bytes(data), 0x1000, offsets, 120))
        self.assertEqual((expect[0][0], expect[0][1], expect[0][2]), (0x1080, 908, 0x4000))
        self.assertEqual(list(plugin.candidate_offsets(bytes(data), 0x1001, offsets, 120)), [])
        struct.pack_into("<Q", data, pos + 112, 130000000000000000)  # exit earlier than create
        self.assertEqual(list(plugin.candidate_offsets(bytes(data), 0x1000, offsets, 120)), [])

    def test_reverse_pfn_uses_table_frame_and_pte_slot(self):
        pteva = 0xFFFF000000000000 | 480 << 39 | 3 << 30 | 0x138
        table = bytearray(4096)
        struct.pack_into("<Q", table, 0x138, (12345 << 12) | 7)
        state, physical_pte, value = plugin.reverse_leaf(10, pteva, 480, lambda pa: table if pa == 40960 else None)
        self.assertEqual((state, physical_pte, (value & plugin.PHYSICAL) >> 12), ("leaf", 40960+0x138, 12345))
        self.assertEqual(plugin.reverse_leaf(10, pteva, 480, lambda pa: None)[0], "pte_page_missing")
        self.assertEqual(plugin.reverse_leaf(10, pteva, 480, lambda pa: bytes(4096))[0], "pte_not_present")
        pde = (pteva & ~(511 << 30)) | 480 << 30
        self.assertEqual(plugin.reverse_leaf(10, pde, 480, lambda pa: table)[0], "not_leaf")


class ReadyChain(unittest.TestCase):
    def make(self, broken=False):
        ctx = object.__new__(plugin.KswordObjects)
        ctx.mask = (1 << 48) - 1
        head = SimpleNamespace(vol=SimpleNamespace(offset=0x1000), Flink=0x3080, Blink=0x3080)
        element = SimpleNamespace(Flink=0x1000, Blink=0x9000 if broken else 0x1000)
        thread = SimpleNamespace(vol=SimpleNamespace(offset=0x3000))
        offsets = {"_ETHREAD": 0, "_KTHREAD": 0x80}
        ctx.kernel = SimpleNamespace(
            get_type=lambda name: SimpleNamespace(relative_child_offset=lambda member: offsets[name]),
            object=lambda typ, offset, absolute: {("_LIST_ENTRY", 0x3080): element, ("_ETHREAD", 0x3000): thread}[(typ, offset)])
        return ctx, head, thread

    def test_correct_and_broken_chains(self):
        ctx, head, thread = self.make()
        self.assertEqual(list(ctx.linked_threads(head)), [thread])
        ctx, head, _ = self.make(True)
        with self.assertRaisesRegex(ValueError, "backward"):
            list(ctx.linked_threads(head))


if __name__ == "__main__":
    unittest.main()
