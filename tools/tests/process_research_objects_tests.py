"""Run with Volatility 3 on PYTHONPATH. Fixtures contain binary pages, not report rows."""
import importlib.util
import pathlib
import struct
import unittest
from collections import Counter
from types import SimpleNamespace
from unittest.mock import patch

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

    def test_executable_kernel_leaves_and_range_subtraction(self):
        # A user PML4 slot, an NX ancestor and a non-first NX leaf must all be excluded.
        self.ram.table(0x1000, {0: 0x2007, 300: 0x2003, 310: (1 << 63) | 0x2003})
        self.ram.table(0x4000, {5: 0x11007, 6: (1 << 63) | 0xAB007, 7: 0xCC007})
        counts = Counter()
        rows = list(plugin.PageWalk(self.ram.read).executable_leaves(0x1000, counts))
        self.assertEqual([(p,s) for _,p,s,_ in rows], [(0x11000,4096),(0xCC000,4096),(0x800000,2<<20),(0x40000000,1<<30)])
        self.assertTrue(all(va >> 48 == 0xFFFF and perms == 2 for va,_,_,perms in rows))
        # A module in the middle of a large leaf must split the candidate on BOTH sides.
        va = rows[2][0]
        index = plugin.Extents([(va+4096,va+8192),(va+8192,va+12288)])
        self.assertEqual(list(index.gaps(va,va+(2<<20))),[(va,va+4096),(va+12288,va+(2<<20))])
        self.assertEqual(index.covered(va,va+(2<<20)),8192)
        self.assertEqual(index.covered(va+6144,va+10240),4096)

    def test_kernel_walk_gaps_and_budget(self):
        del self.ram.pages[0x4000]
        stats = Counter()
        list(plugin.PageWalk(self.ram.read).executable_leaves(0x1000, stats))
        self.assertGreater(stats["missing tables"],0)
        stats = Counter()
        list(plugin.PageWalk(self.ram.read).executable_leaves(0x1000, stats, table_budget=1))
        self.assertEqual(stats["budget"],1)


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


class ControlAreaEvidence(unittest.TestCase):
    def test_verified_reverse_index_preserves_instances_and_unreadable_scope(self):
        # Raw synthetic kernel pages contain two nonprivate VADs in different processes
        # that reference one ControlArea, a private short VAD and an uncaptured backlink.
        class Type:
            def __init__(self, size=8, bits=None, **fields):
                self.size, self.fields = size, fields
                self.vol = {} if bits is None else dict(start_bit=0, end_bit=bits)

            def child_template(self, name):
                return self.fields[name][1]

            def relative_child_offset(self, name):
                return self.fields[name][0]

        q, d, b = Type(), Type(4), Type(1)
        short = Type(64, VadNode=(0, Type(24, Left=(0,q), Right=(8,q), ParentValue=(16,q))),
                     StartingVpn=(32,d), EndingVpn=(36,d), StartingVpnHigh=(40,b), EndingVpnHigh=(41,b),
                     u=(48,Type(4,VadFlags=(0,Type(4,PrivateMemory=(0,Type(4,1)))))))
        ca = Type(24,Segment=(0,q),NumberOfMappedViews=(8,q),
                  FilePointer=(16,Type(8,Value=(0,q),RefCnt=(0,Type(8,4)))))
        types = {"_MMVAD_SHORT":short, "_MMVAD":Type(72,Core=(0,short),Subsection=(64,q)),
                 "_SUBSECTION":Type(8,ControlArea=(0,q)), "_CONTROL_AREA":ca, "_SEGMENT":Type(8,ControlArea=(0,q))}
        base = 0xFFFF812345670000
        mem = bytearray(4096)
        areas, segment, sub = base+0x800, base+0x900, base+0xA00
        struct.pack_into("<QQQ",mem,0x800,segment,2,0)
        struct.pack_into("<Q",mem,0x900,areas)
        struct.pack_into("<Q",mem,0xA00,areas)
        procs = []
        for i,(off,kind,subaddr) in enumerate(((0,0,sub),(0x100,0,sub),(0x200,1,0),(0x300,0,base+0x1100),(0x400,0,0))):
            struct.pack_into("<II",mem,off+32,0x20+i*0x10,0x23+i*0x10)
            struct.pack_into("<I",mem,off+48,kind)
            struct.pack_into("<Q",mem,off+64,subaddr)
            procs.append(SimpleNamespace(UniqueProcessId=4*(i+1),vol=SimpleNamespace(offset=base+0xD00+32*i),
                                         VadRoot=SimpleNamespace(Root=base+off),VadCount=1,has_member=lambda _: True,
                                         CreateTime=SimpleNamespace(QuadPart=2**54+i)))

        def read(va,length):
            if va != base or length != 4096:
                raise plugin.exceptions.InvalidAddressException("mock",va)
            return bytes(mem)

        ctx = object.__new__(plugin.KswordObjects)
        ctx._context = SimpleNamespace(symbol_space=None)
        ctx.kernel = SimpleNamespace(get_type=types.__getitem__)
        ctx.mask = 2**64-1
        ctx.kmem = SimpleNamespace(read=read,canonicalize=lambda x: x)
        ctx.processes = lambda: iter(procs)
        ctx.gaps, ctx.count = Counter(), 0
        with patch.object(plugin,"image_name",lambda p: f"P{p.UniqueProcessId}"):
            rows = list(ctx.control_area_owners())
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0][1][3],hex(areas))
        self.assertIn("observed process instances=2",rows[0][1][4])
        self.assertIn(f"FILETIME={2**54+1}",rows[0][1][4])
        self.assertIn("FileObject=0x0",rows[0][1][4])
        self.assertIn("'null subsections': 1",ctx.summary)
        self.assertIn("'private VADs': 1",ctx.summary)
        self.assertIn("'unverified nodes/links': 1",ctx.summary)
        self.assertTrue(all(ctx.gaps))

        struct.pack_into("<Q",mem,0x900,areas+8)
        ctx.gaps,ctx.count=Counter(),0
        with patch.object(plugin,"image_name",lambda p: str(p.UniqueProcessId)):
            self.assertEqual(list(ctx.control_area_owners()),[])
        self.assertTrue(any("back-reference" in reason for reason in ctx.gaps))


if __name__ == "__main__":
    unittest.main()
