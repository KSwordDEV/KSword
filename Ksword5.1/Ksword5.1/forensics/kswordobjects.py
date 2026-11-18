"""Read-only Windows x64 object, scheduler and hardware PTE evidence for KSword."""
import hashlib
import bisect
import re
import struct
from collections import Counter
from functools import lru_cache

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import templates, utility
from volatility3.plugins.windows import desktops, handles, modules, pslist, psscan, thrdscan


PAGE = 4096
PHYSICAL = 0x000FFFFFFFFFF000
U64 = (1 << 64) - 1
ERR = (exceptions.InvalidAddressException, exceptions.SymbolError, AttributeError, ValueError, TypeError)
U64S = struct.Struct("<512Q")


def kernel_pointer(value):
    return int(value) >= 0xFFFF800000000000 and int(value) % 8 == 0


def process_id(process):
    return int(process.UniqueProcessId)


def image_name(process):
    return str(utility.array_to_string(process.ImageFileName))


def dtb(process):
    return int(process.Pcb.DirectoryTableBase) & PHYSICAL


def field_reader(space, template, *path):
    """Compile the matching ISF's offsets and bit positions once per scan."""
    offset = 0
    for member in path:
        offset += template.relative_child_offset(member)
        template = template.child_template(member)
        if isinstance(template, templates.ReferenceTemplate):
            template = space.get_type(template.vol.type_name)
    size = template.size
    lo = template.vol.get("start_bit", 0)
    hi = template.vol.get("end_bit", size * 8)
    if not (1 <= size <= 8 and 0 <= lo < hi <= size * 8):
        raise ValueError(f"unsupported PFN field layout for {path}")
    return lambda row: (int.from_bytes(row[offset:offset + size], "little") >> lo) & ((1 << (hi - lo)) - 1)


def reverse_leaf(frame, pte_va, self_slot, read_page):
    """Return a hardware leaf's reference using its PFN DB owning-table link."""
    if (not frame or not kernel_pointer(pte_va) or (pte_va >> 39) & 511 != self_slot or
            (pte_va >> 30) & 511 == self_slot):
        return "not_leaf", 0, None
    pa = (frame << 12) | (pte_va & 4095)
    page = read_page(frame << 12)
    if page is None:
        return "pte_page_missing", pa, None
    value = struct.unpack_from("<Q", page, pte_va & 4095)[0]
    if not value & 1:
        return "pte_not_present", pa, value
    return "leaf", pa, value


def candidate_offsets(data, base, offsets, size):
    """Structural prefilter only. No object name or pool-tag signature is used."""
    pid_at, dtb_at, threads_at, name_at, created_at, exited_at, type_at = offsets
    for hit in re.finditer(b"\x03", data):  # ProcessObject in the dispatcher header.
        at = hit.start() - type_at
        if at < 0 or (base + at) % 16 or at + size > len(data):
            continue
        pid = struct.unpack_from("<Q", data, at + pid_at)[0]
        root = struct.unpack_from("<Q", data, at + dtb_at)[0]
        if not pid or pid > 0xFFFFFFFF or pid % 4 or not root & PHYSICAL or root >> 52:
            continue
        flink, blink = struct.unpack_from("<QQ", data, at + threads_at)
        if not kernel_pointer(flink) or not kernel_pointer(blink):
            continue
        name = data[at + name_at:at + name_at + 15].split(b"\x00", 1)[0]
        if not name or any(c < 32 for c in name):
            continue
        created = struct.unpack_from("<Q", data, at + created_at)[0]
        exited = struct.unpack_from("<Q", data, at + exited_at)[0]
        if pid != 4 and not (125911584000000000 <= created <= 265046774400000000):
            continue
        if exited and (exited < created or exited > 265046774400000000):
            continue
        yield base + at, pid, root & PHYSICAL, name.decode("ascii", "backslashreplace"), created, exited


class PageWalk:
    """Hash actual VA order, effective permissions, page size and physical targets.

    Cache shared subtrees across processes; nonresident Windows software PTEs are counted
    separately and never interpreted as resident frames. A missing table changes coverage.
    """
    def __init__(self, read):
        self.read = read
        # Instance-local caches release all references when this one method finishes.
        self.table = lru_cache(maxsize=8192)(self._table)
        self.summarize = lru_cache(maxsize=32768)(self._summarize)

    def _table(self, physical):
        return U64S.unpack(self.read(physical, PAGE))

    def _summarize(self, level, physical, permissions):
        signature = hashlib.sha256()
        pages = software = missing = tables = 0
        first = None
        try:
            entries = self.table(physical)
        except (exceptions.InvalidAddressException, ValueError, struct.error):
            return b"", 0, 0, 1, 0, None
        tables += 1
        for slot, entry in enumerate(entries):
            if not entry & 1:
                software += int(entry != 0)
                continue
            target = entry & PHYSICAL
            effective = permissions & ((entry & 6) | (0 if entry >> 63 else 8))
            span = 1 << (9 * (level - 1))
            offset = slot * span * PAGE
            if level == 1 or (level in (2, 3) and entry & 0x80):
                # PAT is bit 12 on large mappings, bit 7 on ordinary PTEs.
                if level > 1 and (target & (span * PAGE - 1) & ~0x1000):
                    missing += 1
                    continue
                target &= ~(span * PAGE - 1)
                signature.update(struct.pack("<HBBQ", slot, level, effective, target))
                pages += span
                if first is None:
                    first = offset, target, span * PAGE
            else:
                child, resident, inactive, gaps, visited, sample = self.summarize(level - 1, target, effective)
                if resident or gaps:
                    signature.update(struct.pack("<HB", slot, level) + child)
                pages += resident
                software += inactive
                missing += gaps
                tables += visited
                if first is None and sample:
                    first = offset + sample[0], sample[1], sample[2]
        return signature.digest(), pages, software, missing, tables, first

    def slots(self, root, start=0, normalize_recursive=True):
        for slot, entry in enumerate(self.table(root)):
            if slot < start or not entry & 1:
                continue
            target = entry & PHYSICAL
            # Recursive aliases describe this root's page tables, not divergent kernel code.
            # Retain their existence and position without treating each process's root PFN as a difference.
            if normalize_recursive and target == root:
                yield slot, (b"self", 0, 0, 0, 0, None)
            elif entry & 0x80:  # PS is reserved at PML4.
                yield slot, (b"", 0, 0, 1, 0, None)
            else:
                perms = (entry & 6) | (0 if entry >> 63 else 8)
                yield slot, self.summarize(3, target, perms)


class KswordObjects(interfaces.plugins.PluginInterface):
    """Inspect symbol-matched process objects, per-CPU scheduler state and page mappings."""
    _required_framework_version = (2, 6, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name="kernel", description="Windows x64 kernel", architectures=["Intel64"]),
            requirements.IntRequirement(name="method", description="KSword detection method number"),
        ]

    def row(self, pid, name, address, detail):
        self.count += 1
        return 0, ("", str(pid) if pid is not None else "", name, hex(address) if address else "", detail)

    def gap(self, detail):
        message = str(detail)[:220]
        if len(self.gaps) >= 32 and message not in self.gaps:
            message = "other unreadable objects or unsupported fields"
        self.gaps[message] += 1

    def processes(self):
        count = 0
        for proc in pslist.PsList.list_processes(self.context, self.config["kernel"]):
            count += 1
            yield proc
        if not count:
            self.gap("active process reference unavailable")

    def physical_scan(self):
        proc = self.kernel.get_type("_EPROCESS")
        kproc = self.kernel.get_type("_KPROCESS")
        body = proc.relative_child_offset("Pcb")
        offsets = (proc.relative_child_offset("UniqueProcessId"), body + kproc.relative_child_offset("DirectoryTableBase"),
                   proc.relative_child_offset("ThreadListHead"), proc.relative_child_offset("ImageFileName"),
                   proc.relative_child_offset("CreateTime"), proc.relative_child_offset("ExitTime"),
                   body + kproc.relative_child_offset("Header") + self.kernel.get_type("_DISPATCHER_HEADER").relative_child_offset("Type"))
        size = max(offsets[0] + 8, offsets[1] + 8, offsets[2] + 16, offsets[3] + 15,
                   offsets[4] + 8, offsets[5] + 8, offsets[6] + 1)
        layer = self.phys
        lo, end = layer.minimum_address, layer.maximum_address + 1
        ranges = ((lo, end - lo),)
        if isinstance(layer, interfaces.layers.TranslationLayerInterface):
            ranges = ((start, length) for start, length, *_ in layer.mapping(lo, end - lo, ignore_errors=True))
        examined = with_root = without_root = 0
        system_pa = None
        system_seen = False
        try:
            address = self.kernel.object("pointer", offset=self.kernel.get_symbol("PsInitialSystemProcess").address)
            system_pa = next(iter(self.kmem.mapping(int(address) & self.mask, 1)))[2]
        except ERR + (StopIteration,):
            self.gap("unable to locate known System process for scan calibration")
        # Coalesce adjacent logical physical segments (their backing file offsets may differ).
        def joined():
            a = b = None
            for start, length in ranges:
                if length <= 0:
                    continue
                if b == start:
                    b += length
                else:
                    if a is not None:
                        yield a, b
                    a, b = start, start + length
            if a is not None:
                yield a, b
        for start, finish in joined():
            for pos in range(start, finish, 1 << 20):
                n = min(1 << 20, finish - pos)
                try:
                    data = layer.read(pos, min(n + size - 1, finish - pos))
                except exceptions.InvalidAddressException:
                    self.gap("unreadable captured physical extent")
                    continue
                examined += n
                for address, pid, root, name, created, exited in candidate_offsets(data, pos, offsets, size):
                    if address >= pos + n:
                        continue
                    try:
                        top = U64S.unpack(layer.read(root, PAGE))
                        present = sum(bool(x & 1 and not x & 0x80) for x in top[256:])
                    except exceptions.InvalidAddressException:
                        self.gap("candidate page root missing")
                        without_root += 1
                        yield self.row(pid, name, address, f"structural candidate only; DTB={root:#x} is not captured; creation={created}; exit={exited}")
                        continue
                    if present:
                        with_root += 1
                        system_seen |= address == system_pa and pid == 4
                        yield self.row(pid, name, address, f"physical object candidate; DTB={root:#x}; kernel slots={present}; creation={created}; exit={exited}")
        self.summary = f"captured physical bytes={examined}; with root={with_root}; root not captured={without_root}; tag-independent contiguous structural candidates"
        if not examined:
            self.gap("no captured physical ranges")
        if system_pa is not None and not system_seen:
            self.gap("known System object was not recovered from this capture")

    def reverse_pfns(self):
        typ = self.kernel.get_type("_MMPFN")
        stride = typ.size
        def field(*path):
            return field_reader(self.context.symbol_space, typ, *path)
        location = field("u3", "e1", "PageLocation")
        prototype = field("u4", "PrototypePte")
        frame = field("u4", "PteFrame")
        pte_address = field("PteAddress")
        u4 = self.context.symbol_space.get_type(typ.child_template("u4").vol.type_name)
        exists = field("u4", "PfnExists") if u4.has_member("PfnExists") else None
        active = self.kernel.get_enumeration("_MMLISTS").vol.choices["ActiveAndValid"]
        if not (0 < stride <= PAGE):
            raise ValueError("invalid PFN entry size")
        def pointer(symbol):
            address = self.kernel.get_symbol(symbol).address
            return int(self.kernel.object("pointer", offset=address)) & self.mask
        database = pointer("MmPfnDatabase")
        if not database:
            raise ValueError("PFN database unavailable")
        root = int(self.kmem.config["page_map_offset"]) & PHYSICAL
        slots = [i for i, value in enumerate(U64S.unpack(self.phys.read(root, PAGE)))
                 if i >= 256 and value & 1 and not value & 0x84 and value & PHYSICAL == root]
        if len(slots) != 1:
            raise ValueError("cannot validate the unique supervisor PTE self-map on this machine")
        desc = self.kernel.object("_PHYSICAL_MEMORY_DESCRIPTOR", offset=pointer("MmPhysicalMemoryBlock"), absolute=True)
        nruns = int(desc.NumberOfRuns)
        if not 0 < nruns <= 4096:
            raise ValueError("invalid physical run count")
        runs = desc.Run
        runs.count = nruns
        extent = sorted((int(run.BasePage), int(run.PageCount)) for run in runs)
        end = 0
        for first, count in extent:
            if not count or first < end or first + count > 1 << 40 or database + (first + count)*stride > self.mask + 1:
                raise ValueError("invalid physical RAM run")
            end = first + count
        if sum(n for _, n in extent) != int(desc.NumberOfPages):
            raise ValueError("physical RAM runs do not reconcile with NumberOfPages")

        def pagereader(layer, cap):
            @lru_cache(maxsize=cap)
            def read_page(address):
                try:
                    return layer.read(address, PAGE)
                except exceptions.InvalidAddressException:
                    return None
            return read_page
        virtual_page = pagereader(self.kmem, 16)
        physical_page = pagereader(self.phys, 2048)
        @lru_cache(maxsize=4096)
        def kernel_translation(page_va):
            try:
                mapped = next(iter(self.kmem.mapping(page_va & self.mask, 1)))
                return mapped[2] if mapped[4] == self.phys.name else None
            except (exceptions.InvalidAddressException, StopIteration):
                return None
        stats = Counter()
        for first, count in extent:
            for pfn in range(first, first + count):
                stats["RAM PFNs"] += 1
                va = database + pfn * stride
                page = virtual_page(va & ~(PAGE-1))
                if page is None:
                    stats["PFN record missing"] += 1
                    continue
                start = va & (PAGE-1)
                record = page[start:start+stride]
                if len(record) != stride:
                    following = virtual_page((va & ~(PAGE-1)) + PAGE)
                    if following is None:
                        stats["PFN record missing"] += 1
                        continue
                    record += following[:stride-len(record)]
                if (exists and not exists(record)) or location(record) != active:
                    stats["outside active PFN scope"] += 1
                    continue
                if prototype(record):
                    stats["prototype excluded"] += 1
                    continue
                pteva, table = pte_address(record), frame(record)
                state, pa, value = reverse_leaf(table, pteva, slots[0], physical_page)
                if state != "leaf":
                    stats[state] += 1
                    continue
                translated = (value & PHYSICAL) >> 12
                if translated == pfn:
                    verdict = "matching"
                elif kernel_translation(pteva & ~(PAGE-1)) == table << 12:
                    verdict = "different (PTE address confirmed in captured kernel root)"
                else:
                    verdict = "different (PTE address space unverified)"
                stats[verdict] += 1
                if stats[verdict] <= (6 if verdict == "matching" else 64):
                    yield self.row(None, "", va, f"{verdict}; PFN={pfn:#x}; PteAddress={pteva:#x}; PteFrame={table:#x}; physical PTE={pa:#x}; hardware value={value:#x}; referenced PFN={translated:#x}")
        if (stats["PFN record missing"] or stats["pte_page_missing"] or stats["pte_not_present"] or
                stats["not_leaf"] or stats["different (PTE address space unverified)"]):
            self.gap("some RAM PFN records, referenced PTE pages or leaf semantics were unavailable")
        self.summary = f"RAM runs={nruns}; self-map slot={slots[0]}; {dict(stats)}; samples: up to 6 matches and 64 per difference class; mapping differences are not process identities"

    def object_checks(self, method):
        name = self.config["kernel"]
        index = handles.Handles.get_type_map(self.context, name) if method == 12 else {}
        cookie = handles.Handles.find_cookie(self.context, name) if method == 12 else None
        if method == 12 and (not index or cookie is None):
            raise ValueError("object type map or ObHeaderCookie unavailable")
        seen = set()
        def candidates():
            for proc in self.processes():
                seen.add(proc.vol.offset)
                yield proc, "active"
            for proc in psscan.PsScan.scan_processes(self.context, name):
                if proc.vol.layer_name != self.kernel.layer_name:
                    try:
                        proc = psscan.PsScan.virtual_process_from_physical(self.context, name, proc)
                    except ERR as exc:
                        self.gap(exc)
                        continue
                    if proc is None:
                        self.gap("unable to bind physical process candidate to a virtual object header")
                        continue
                if proc.vol.offset not in seen:
                    seen.add(proc.vol.offset)
                    yield proc, "pool-only candidate"
        for proc, source in candidates():
            try:
                pid, image = process_id(proc), image_name(proc)
                if method == 12:
                    header = proc.get_object_header()
                    typ = header.get_object_type(index, cookie)
                    if not typ:
                        self.gap("object type index did not resolve")
                    yield self.row(pid, image, proc.vol.offset,
                                   f"{source}; header={header.vol.offset:#x}; type={typ}; expected=Process; plausible header={header.is_valid()}; pointer count={int(header.PointerCount)}")
                else:
                    root = dtb(proc)
                    try:
                        top = U64S.unpack(self.phys.read(root, PAGE)) if root else ()
                        slots = sum(x & 1 for x in top)
                    except exceptions.InvalidAddressException:
                        slots = "uncaptured"
                        self.gap("process root not captured")
                    yield self.row(pid, image, proc.vol.offset,
                                   f"{source}; structure valid={proc.is_valid()}; DTB={root:#x}; present PML4 slots={slots}; created={proc.get_create_time()}; exit={proc.get_exit_time()}")
            except ERR as exc:
                self.gap(exc)

    def tables(self, method):
        walker = PageWalk(self.phys.read)
        processes = list(self.processes())
        reference = None
        if method == 30:
            system = next((p for p in processes if process_id(p) == 4), None)
            if system is None:
                raise ValueError("System process unavailable as kernel reference")
            reference = dict(walker.slots(dtb(system), 256))
            if not reference:
                raise ValueError("System kernel root has no present upper-half entries")
        for proc in processes:
            try:
                pid, image, root = process_id(proc), image_name(proc), dtb(proc)
                if not root:
                    self.gap("missing process DTB")
                    continue
                slots = dict(walker.slots(root, 256 if method == 30 else 0, normalize_recursive=method == 30))
                bad = sum(v[3] for v in slots.values())
                if bad:
                    self.gap(f"PID {pid}: unreadable/reserved page tables={bad}")
                if method == 30:
                    differences, unknown = [], []
                    for slot in sorted(reference.keys() | slots.keys()):
                        left, right = reference.get(slot), slots.get(slot)
                        if (left and left[3]) or (right and right[3]):
                            unknown.append(slot)
                        elif (left[0] if left and (left[1] or left[0] == b"self") else None) != (
                                right[0] if right and (right[1] or right[0] == b"self") else None):
                            differences.append(slot)
                    if unknown:
                        self.gap("one or both kernel mappings have unreadable tables")
                    yield self.row(pid, image, root, f"kernel DTB compared with PID 4; different slots={differences}; unreadable={unknown}; session-specific mappings may differ")
                else:
                    footprint = hashlib.sha256()
                    pages = sw = traversed = 0
                    sample = None
                    for slot, value in slots.items():
                        footprint.update(struct.pack("<H", slot) + value[0])
                        pages += value[1]
                        sw += value[2]
                        traversed += value[4]
                        if sample is None and value[5]:
                            off, pa, length = value[5]
                            va = (slot << 39) + off
                            if slot >= 256:
                                va |= 0xFFFF000000000000
                            sample = f"{va:#x}->{pa:#x}/{length:#x}"
                    yield self.row(pid, image, root, f"4-level hardware-present mappings: 4-KiB equivalents={pages}; table visits={traversed}; software entries={sw}; unreadable={bad}; SHA256={footprint.hexdigest()}; example={sample}; recursive aliases included")
            except ERR as exc:
                self.gap(exc)

    def pool_threads(self):
        count = 0
        for thread in thrdscan.ThrdScan.scan_threads(self.context, self.config["kernel"]):
            count += 1
            yield thread
        if not count:
            self.gap("no ETHREAD pool objects recovered from capture")

    def gui_threads(self):
        attached = 0
        for desktop, station, session, name, image, pid in desktops.Desktops.list_desktops(
                self.context, self.config_path, self.config["kernel"]):
            attached += 1
            yield self.row(int(pid), str(image), int(desktop),
                           f"session={session}; window station={station}; desktop={name}; desktop thread association")
        if not attached:
            self.gap("no desktop-to-thread links were observable")
        related = 0
        for thread in self.pool_threads():
            try:
                gui = int(thread.Tcb.Win32Thread)
                if not gui:
                    continue
                owner = thread.owning_process()
                related += 1
                yield self.row(process_id(owner), image_name(owner), thread.vol.offset,
                               f"ETHREAD TID={int(thread.Cid.UniqueThread)}; Win32Thread={gui:#x}; owner session={owner.get_session_id()}; desktop not inferred")
            except ERR as exc:
                self.gap(exc)
        self.summary = f"desktop thread links={attached}; nonnull GUI-thread pointers={related}"

    def thread_evidence(self, method):
        ranges = []
        if method == 16:
            for mod in modules.Modules.list_modules(self.context, self.config["kernel"]):
                try:
                    ranges.append((int(mod.DllBase) & self.mask, int(mod.SizeOfImage), str(mod.BaseDllName.String)))
                except ERR as exc:
                    self.gap(exc)
            if not ranges:
                raise ValueError("loaded-module reference for stack pointer classification unavailable")
            ranges.sort()
        for thread in self.pool_threads():
            try:
                owner = thread.owning_process()
                pid, tid = process_id(owner), int(thread.Cid.UniqueThread)
                cid = int(thread.Cid.UniqueProcess)
                if method == 8:
                    yield self.row(pid, image_name(owner), thread.vol.offset,
                                   f"ETHREAD pool; TID={tid}; Cid.UniqueProcess={cid}; owner={owner.vol.offset:#x}; owner PID={pid}; matches={cid == pid}")
                elif method == 15:
                    if int(thread.Tcb.State) != 5:  # Waiting
                        continue
                    yield self.row(pid, image_name(owner), thread.vol.offset,
                                   f"ETHREAD pool; TID={tid}; State=Waiting; WaitReason={int(thread.Tcb.WaitReason)}; Cid.PID={cid}; owner={owner.vol.offset:#x}")
                else:
                    tcb = thread.Tcb
                    low, top, sp = int(tcb.StackLimit), int(tcb.StackBase), int(tcb.KernelStack)
                    if not (low and low <= sp < top and top - low <= 2 * 1024 * 1024 and sp % 8 == 0):
                        self.gap("swapped, missing or inconsistent kernel stack bounds")
                        continue
                    matches, captured, matched = [], 0, 0
                    for start in range(sp & ~(PAGE - 1), top, PAGE):
                        a, b = max(start, sp), min(start + PAGE, top)
                        try:
                            data = self.kmem.read(a, b - a)
                        except exceptions.InvalidAddressException:
                            self.gap("kernel stack page not captured")
                            continue
                        captured += len(data)
                        for (word,) in struct.iter_unpack("<Q", data[:len(data) // 8 * 8]):
                            if word >> 48 != 0xFFFF:
                                continue
                            ptr = word & self.mask
                            i = self._range_index(ranges, ptr)
                            if i >= 0 and ptr < ranges[i][0] + ranges[i][1]:
                                matched += 1
                                if len(matches) < 8:
                                    matches.append(f"{ranges[i][2]}+{ptr-ranges[i][0]:#x}")
                    yield self.row(pid, image_name(owner), thread.vol.offset,
                                   f"TID={tid}; stack={sp:#x}..{top:#x}; read={captured}/{top-sp}; module-range words={matched}; samples={matches}; values are not unwound frames")
            except ERR as exc:
                self.gap(exc)

    @staticmethod
    def _range_index(ranges, address):
        # Ranges are sorted by base. Comparing tuples avoids materializing all bases per stack word.
        return bisect.bisect_right(ranges, (address, U64, "")) - 1

    def processors(self):
        """Read pointer array with individual CPU error accounting (one missing CPU must not hide the rest)."""
        count = int(self.kernel.object("unsigned int", offset=self.kernel.get_symbol("KeNumberProcessors").address))
        if not 0 < count <= 4096:
            raise ValueError(f"invalid KeNumberProcessors={count}")
        array = self.kernel.object("array", offset=self.kernel.get_symbol("KiProcessorBlock").address,
                                   count=count, subtype=self.kernel.get_type("pointer"))
        for index in range(count):
            try:
                ptr = int(array[index]) & self.mask
                if not ptr:
                    self.gap(f"CPU {index} missing KPRCB")
                    continue
                yield index, self.kernel.object("_KPRCB", offset=ptr, absolute=True)
            except ERR as exc:
                self.gap(exc)

    def linked_threads(self, head):
        """Walk one dispatcher LIST_ENTRY with reciprocal links and true sentinel termination."""
        tcb_offset = self.kernel.get_type("_ETHREAD").relative_child_offset("Tcb")
        link_offset = self.kernel.get_type("_KTHREAD").relative_child_offset("WaitListEntry")
        sentinel = head.vol.offset & self.mask
        prev, cur = sentinel, int(head.Flink) & self.mask
        seen = set()
        while cur != sentinel:
            if not cur or cur in seen or len(seen) >= 65536:
                raise ValueError("ready-list link cycle, null or node limit")
            seen.add(cur)
            link = self.kernel.object("_LIST_ENTRY", offset=cur, absolute=True)
            if int(link.Blink) & self.mask != prev:
                raise ValueError("ready-list backward link does not match predecessor")
            yield self.kernel.object("_ETHREAD", offset=cur-link_offset-tcb_offset, absolute=True)
            prev, cur = cur, int(link.Flink) & self.mask
        if int(head.Blink) & self.mask != prev:
            raise ValueError("ready-list tail does not point to predecessor")

    def ready_queues(self, prcb, visited):
        queues = []
        if prcb.has_member("DispatcherReadyListHead"):
            queues.append(prcb.DispatcherReadyListHead)
        for member in ("SharedReadyQueue", "LocalSharedReadyQueue"):
            if not prcb.has_member(member):
                continue
            try:
                queue = prcb.member(member)
                if hasattr(queue, "dereference"):
                    if not int(queue):
                        continue
                    queue = queue.dereference()
                if queue.has_member("ReadyListHead"):
                    queues.append(queue.ReadyListHead)
            except ERR as exc:
                self.gap(exc)
        if not queues:
            self.gap("no symbol-supported dispatcher ready-list array")
        for array in queues:
            if array.vol.offset in visited:
                continue
            visited.add(array.vol.offset)
            if not 0 < len(array) <= 64:
                self.gap("invalid number of dispatcher priority lists")
                continue
            for priority, head in enumerate(array):
                try:
                    for thread in self.linked_threads(head):
                        yield priority, thread
                except ERR as exc:
                    self.gap(exc)

    def physical_identity(self, thread):
        if thread.vol.layer_name == self.phys.name:
            return thread.vol.offset
        layer = self.context.layers[thread.vol.layer_name]
        for _, _, target, _, target_layer in layer.mapping(thread.vol.offset, 1):
            if target_layer == self.phys.name:
                return target
        raise ValueError("no comparable physical ETHREAD identity")

    def scheduler(self, method):
        current = {}
        ready = {}
        visited = set()
        cpus_seen = 0
        for cpu, prcb in self.processors():
            cpus_seen += 1
            if method in (13, 18, 21):
                try:
                    obj = int(prcb.CurrentThread) & self.mask
                    if not obj:
                        raise ValueError(f"CPU {cpu} has no current thread pointer")
                    obj -= self.kernel.get_type("_ETHREAD").relative_child_offset("Tcb")
                    thread = self.kernel.object("_ETHREAD", offset=obj, absolute=True)
                    owner = thread.owning_process()
                    tid, pid, name = int(thread.Cid.UniqueThread), process_id(owner), image_name(owner)
                    if method == 13:
                        yield self.row(pid, name, obj,
                                       f"CPU={cpu}; PRCB={prcb.vol.offset:#x}; CurrentThread TID={tid}; Cid.PID={int(thread.Cid.UniqueProcess)}; owner={owner.vol.offset:#x}")
                    elif method == 21:
                        saved = int(prcb.ProcessorState.SpecialRegisters.Cr3) & PHYSICAL
                        if not saved:
                            self.gap(f"CPU {cpu} has no saved CR3")
                            continue
                        attached = thread.Tcb.ApcState.Process.dereference().cast("_EPROCESS")
                        kernel = dtb(attached)
                        user = int(attached.Pcb.UserDirectoryTableBase) & PHYSICAL if attached.Pcb.has_member("UserDirectoryTableBase") else 0
                        yield self.row(process_id(attached), image_name(attached), obj,
                                       f"CPU={cpu}; TID={tid}; owner PID={pid}; saved CR3={saved:#x}; attached kernel DTB={kernel:#x}; user DTB={user:#x}; matches={saved in (user,kernel)}; saved-register timing unknown")
                    else:
                        key = self.physical_identity(thread)
                        current.setdefault(key, [pid, tid, name, []])[3].append(cpu)
                except ERR as exc:
                    self.gap(exc)
            if method in (14, 18):
                for priority, thread in self.ready_queues(prcb, visited):
                    try:
                        owner = thread.owning_process()
                        tid, pid, name = int(thread.Cid.UniqueThread), process_id(owner), image_name(owner)
                        if method == 14:
                            yield self.row(pid, name, thread.vol.offset,
                                           f"queue observed via CPU={cpu}; priority={priority}; TID={tid}; KTHREAD State={int(thread.Tcb.State)}; owner={owner.vol.offset:#x}")
                        else:
                            key = self.physical_identity(thread)
                            ready.setdefault(key, [pid, tid, name, []])[3].append((cpu, priority))
                    except ERR as exc:
                        self.gap(exc)
        self.summary = f"CPU records={cpus_seen}; distinct ready-queue arrays={len(visited)}"
        if method != 18:
            return
        observed = set(current) | set(ready)
        pooled = set()
        for thread in self.pool_threads():
            try:
                key = self.physical_identity(thread)
                if key in observed:
                    pooled.add(key)
            except ERR as exc:
                self.gap(exc)
        if not observed:
            self.gap("no attributable scheduler observations")
        for key in sorted(observed):
            pid, tid, name, _ = (current.get(key) or ready[key])
            cpus = current[key][3] if key in current else []
            queues = ready[key][3] if key in ready else []
            yield self.row(pid, name, key, f"physical ETHREAD; TID={tid}; running CPUs={cpus}; ready queues={queues}; pool hit={key in pooled}; absence is capture-dependent")

    def _generator(self):
        self.count = 0
        self.gaps = Counter()
        self.summary = ""
        status = "complete"
        try:
            self.kernel = self.context.modules[self.config["kernel"]]
            self.kmem = self.context.layers[self.kernel.layer_name]
            self.mask = self.kmem.address_mask
            self.phys = self.context.layers[self.kmem.config["memory_layer"]]
            method = self.config["method"]
            if method == 3:
                yield from self.physical_scan()
            elif method in (5, 12):
                yield from self.object_checks(method)
            elif method in (8, 15, 16):
                yield from self.thread_evidence(method)
            elif method in (13, 14, 18, 21):
                yield from self.scheduler(method)
            elif method in (23, 30):
                yield from self.tables(method)
            elif method == 25:
                yield from self.reverse_pfns()
            elif method == 11:
                yield from self.gui_threads()
            else:
                raise ValueError("unsupported research method")
            if self.gaps:
                status = "partial"
        except ERR + (KeyError, IndexError, struct.error) as exc:
            status = "partial" if self.count else "unavailable"
            self.gap(exc)
        defects = "; ".join(f"{n} x {text}" for text, n in self.gaps.most_common(8))
        detail = f"observations={self.count}; {self.summary}; {defects}"
        yield 0, (status, "", "", "", detail)

    def run(self):
        return renderers.TreeGrid([("Status", str), ("PID", str), ("Name", str), ("Address", str), ("Detail", str)],
                                  self._generator())
