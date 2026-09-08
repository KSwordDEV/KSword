/*++

Module Name:

    hvm_internal.h

Abstract:

    Defines the private HVM runtime shared by lifecycle, EPT, resident VMX,
    nested-VMX, eVMCS, and event modules.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_runtime.h"
/* KSW_HVM_ACTIVE_CONTROLS is embedded in the runtime below. */
#include "hvm_vmcs.h"

/* Define the architectural page size used by VMX and EPT structures. */
#define KSW_HVM_PAGE_BYTES 0x1000ULL
/* Define the large EPT leaf size used by the baseline identity map. */
#define KSW_HVM_LARGE_PAGE_BYTES 0x200000ULL
/* Define the byte span covered by one EPT page-directory. */
#define KSW_HVM_ONE_GIB 0x40000000ULL
/* Define the byte span covered by one EPT PML4 entry. */
#define KSW_HVM_ONE_512_GIB 0x8000000000ULL
/* Bound the identity map to a deliberate eight-TiB research window. */
#define KSW_HVM_MAX_PML4_ENTRIES 16UL
/* Bound the number of simultaneously split two-MiB EPT leaves. */
#define KSW_HVM_MAX_EPT_SPLITS 256UL

/*
 * Bound the EPT execution domains reachable through the EPTP list.
 *
 * The architectural list holds 512 entries, but every entry is an interface
 * published to unprivileged guest code - VMFUNC performs no CPL check - so
 * the useful bound is "as few as the feature needs", not "as many as fit".
 */
#define KSW_HVM_MAX_EPT_DOMAINS 8UL
/* Bound the private paging structures one domain may fork copy-on-write. */
#define KSW_HVM_MAX_DOMAIN_PRIVATE_TABLES 16UL
/* Reserve ledger space for every domain root plus its private tables. */
#define KSW_HVM_MAX_DOMAIN_PAGES \
    (KSW_HVM_MAX_EPT_DOMAINS * (1UL + KSW_HVM_MAX_DOMAIN_PRIVATE_TABLES))
/* Reserve enough allocation-ledger entries for sparse tables and splits. */
#define KSW_HVM_MAX_EPT_PAGES \
    (1UL + KSW_HVM_MAX_PML4_ENTRIES + \
        (KSW_HVM_MAX_PML4_ENTRIES * 512UL) + \
        KSW_HVM_MAX_EPT_SPLITS + \
        KSW_HVM_MAX_DOMAIN_PAGES)
/* Bound every physical address accepted by the EPT backend. */
#define KSW_HVM_MAX_MAPPED_PHYSICAL \
    (KSW_HVM_ONE_512_GIB * KSW_HVM_MAX_PML4_ENTRIES)
/* Bound one per-processor resident VM-exit stack. */
#define KSW_HVM_RESIDENT_HOST_STACK_BYTES 0x8000UL
/* Sample soak residency often enough to catch a short-lived collapse. */
#define KSW_HVM_SOAK_SLICE_MILLISECONDS 50UL

/* Name the VMX feature-control model-specific register. */
#define KSW_IA32_FEATURE_CONTROL 0x3AUL
/* Name the VMX basic capability model-specific register. */
#define KSW_IA32_VMX_BASIC 0x480UL
/* Name the VMX CR0 required-one model-specific register. */
#define KSW_IA32_VMX_CR0_FIXED0 0x486UL
/* Name the VMX CR0 allowed-one model-specific register. */
#define KSW_IA32_VMX_CR0_FIXED1 0x487UL
/* Name the VMX CR4 required-one model-specific register. */
#define KSW_IA32_VMX_CR4_FIXED0 0x488UL
/* Name the VMX CR4 allowed-one model-specific register. */
#define KSW_IA32_VMX_CR4_FIXED1 0x489UL
/* Name the secondary processor-control capability register. */
#define KSW_IA32_VMX_PROCBASED_CTLS2 0x48BUL
/* Name the legacy primary processor-control capability register. */
#define KSW_IA32_VMX_PROCBASED_CTLS 0x482UL
/* Name the true primary processor-control capability register. */
#define KSW_IA32_VMX_TRUE_PROCBASED_CTLS 0x48EUL
/* Name the EPT and VPID capability model-specific register. */
#define KSW_IA32_VMX_EPT_VPID_CAP 0x48CUL
/* Name the VM-function capability model-specific register. */
#define KSW_IA32_VMX_VMFUNC 0x491UL
/* Name the Hyper-V VP-assist-page model-specific register. */
#define KSW_HV_X64_MSR_VP_ASSIST_PAGE 0x40000073UL

/* Identify the CR4 bit that enables VMX instructions. */
#define KSW_CR4_VMXE (1ULL << 13)

/* Define the EPT read permission bit. */
#define KSW_EPT_READ 0x1ULL
/* Define the EPT write permission bit. */
#define KSW_EPT_WRITE 0x2ULL
/* Define the EPT execute permission bit. */
#define KSW_EPT_EXECUTE 0x4ULL
/* Define the EPT memory-type field shift. */
#define KSW_EPT_MEMORY_TYPE_SHIFT 3UL
/* Define the EPT large-page marker. */
#define KSW_EPT_LARGE_PAGE (1ULL << 7)

/*
 * Suppress-#VE.  The architectural default is inverted: a leaf with this bit
 * CLEAR is convertible, so once "EPT-violation #VE" is enabled every such page
 * reflects its EPT violations into the guest.  The guest here is the running
 * Windows, whose IDT[20] is not prepared for a #VE we invented, and the result
 * is #GP -> #DF -> triple fault.
 *
 * Every leaf this driver installs therefore carries the bit, whether or not
 * #VE is enabled - when the control is off the processor ignores it, so the
 * safe default costs nothing.  Only intermediate entries omit it, because the
 * architecture ignores bit 63 on entries that point at another EPT structure.
 */
#define KSW_EPT_SUPPRESS_VE (1ULL << 63)
/* Define the physical-address portion of an EPT entry. */
#define KSW_EPT_PHYSICAL_MASK 0x000FFFFFFFFFF000ULL

/*
 * Virtualization-exception information area.  When the processor converts an
 * EPT violation into a #VE it writes this structure, and it reads the busy
 * field FIRST to decide whether to convert at all: a non-zero busy field means
 * the guest has not consumed the previous exception, so the processor delivers
 * an ordinary EPT-violation VM exit instead of a second #VE.
 *
 * That is the second safety layer here.  The first is suppress-#VE on every
 * leaf; this one latches busy at allocation and never clears it, so even a
 * page that somehow became convertible degrades to the exit path this driver
 * already handles rather than to a fault Windows has no IDT[20] for.  A guest
 * that genuinely wants #VE has to clear busy itself, from inside its own
 * handler - which is exactly the handshake the architecture intends.
 */
#define KSW_VE_INFO_OFFSET_REASON 0UL
#define KSW_VE_INFO_OFFSET_BUSY 4UL
#define KSW_VE_INFO_OFFSET_QUALIFICATION 8UL
#define KSW_VE_INFO_OFFSET_GUEST_LINEAR 16UL
#define KSW_VE_INFO_OFFSET_GUEST_PHYSICAL 24UL
#define KSW_VE_INFO_OFFSET_EPTP_INDEX 32UL
/* Define the architectural "not consumed yet" value for the busy field. */
#define KSW_VE_INFO_BUSY 0xFFFFFFFFUL

/* Identify four-level EPT page-walk capability. */
#define KSW_EPT_CAP_PAGE_WALK_4 (1ULL << 6)
/* Identify EPT execute-only leaf translation capability. */
#define KSW_EPT_CAP_EXECUTE_ONLY (1ULL << 0)
/* Identify write-back EPT memory-type capability. */
#define KSW_EPT_CAP_WB (1ULL << 14)
/* Identify two-MiB EPT leaf capability. */
#define KSW_EPT_CAP_2MB (1ULL << 16)
/* Identify INVEPT instruction capability. */
#define KSW_EPT_CAP_INVEPT (1ULL << 20)
/* Identify EPT accessed-and-dirty capability. */
#define KSW_EPT_CAP_AD (1ULL << 21)
/* Identify single-context INVEPT capability. */
#define KSW_EPT_CAP_INVEPT_SINGLE (1ULL << 25)
/* Identify all-context INVEPT capability. */
#define KSW_EPT_CAP_INVEPT_ALL (1ULL << 26)
/* Identify VPID capability. */
#define KSW_EPT_CAP_VPID (1ULL << 32)

/* Bound the variable-MTRR snapshot to the architectural low-byte count. */
#define KSW_HVM_MAX_VARIABLE_MTRRS 32UL

/* Describe one processor-owned VMXON and VMCS allocation pair. */
typedef struct _KSW_HVM_CPU_RESOURCE
{
    /* Preserve the protocol-visible processor state. */
    KSWORD_ARK_HVM_CPU_ROW Row;
    /* Retain the processor-owned VMXON virtual address. */
    PVOID VmxonVirtual;
    /* Retain the processor-owned VMXON physical address. */
    PHYSICAL_ADDRESS VmxonPhysical;
    /* Retain the processor-owned VMCS virtual address. */
    PVOID VmcsVirtual;
    /* Retain the processor-owned VMCS physical address. */
    PHYSICAL_ADDRESS VmcsPhysical;
    /* Retain the processor-owned #VE information-area virtual address. */
    PVOID VeInfoVirtual;
    /* Retain the processor-owned #VE information-area physical address. */
    PHYSICAL_ADDRESS VeInfoPhysical;
    /*
     * How many exits this processor took, per Intel basic exit reason.
     *
     * The driver already reports a total exit count and the *last* reason, and
     * neither answers the question that actually comes up while diagnosing:
     * where do the exits go.  Reading "lastExitReason 18" a hundred times does
     * not distinguish VMCALL being 99% of the traffic from VMCALL being rare
     * and merely last.
     *
     * The event ring cannot answer it either.  One ring is shared by every
     * processor, so at exit rates in the tens of thousands per second its
     * writers collide and it discards - measured on 2 vCPU: 1024 slots,
     * 17071 dropped publications in a single run.  A ring that discards most of
     * what it is handed is evidence of nothing.  A ring records the last N
     * exits; this records the shape of all of them, which is what the ring was
     * being asked for and could not deliver.
     *
     * This array cannot drop.  It belongs to one processor, so it has exactly
     * one writer and needs no interlocked access, no slot ownership and no
     * failure path.
     *
     * Held here, on the resource, rather than on the resident VCPU context:
     * the VCPU contexts are released and zeroed when residency stops, which
     * would discard the histogram at exactly the moment someone goes looking
     * for it.  The resource outlives residency, so a soak's exit shape is still
     * readable after the soak ends.
     *
     * Indexed by basic exit reason, sized past every reason Intel currently
     * defines; a reason at or beyond the bound is counted nowhere rather than
     * folded into a neighbour.  ULONG, so a processor sustaining ten thousand
     * exits a second wraps after about five days - acceptable for a diagnostic
     * counter, and the protocol widens to 64 bits before summing.
     */
    ULONG ExitReasonCount[KSWORD_ARK_HVM_EXIT_REASON_SLOTS];
} KSW_HVM_CPU_RESOURCE;

/* Track one contiguous page allocated for an EPT hierarchy. */
typedef struct _KSW_HVM_EPT_PAGE
{
    /* Retain the kernel virtual address used for cleanup. */
    PVOID VirtualAddress;
    /* Retain the physical address encoded into a parent EPT entry. */
    PHYSICAL_ADDRESS PhysicalAddress;
} KSW_HVM_EPT_PAGE;

/* Describe one variable MTRR range after mask decoding. */
typedef struct _KSW_HVM_MTRR_RANGE
{
    /* Retain the inclusive physical base of the MTRR range. */
    ULONGLONG Base;
    /* Retain the exclusive physical end of the MTRR range. */
    ULONGLONG End;
    /* Retain the Intel memory-type encoding. */
    UCHAR Type;
    /* Record whether the architectural valid bit was present. */
    UCHAR Valid;
    /* Keep the structure naturally aligned without undefined padding data. */
    USHORT Reserved;
} KSW_HVM_MTRR_RANGE;

/* Preserve an immutable MTRR snapshot used while building EPT leaves. */
typedef struct _KSW_HVM_MTRR_STATE
{
    /* Record whether MTRRs are globally enabled. */
    BOOLEAN Enabled;
    /* Record whether fixed-range MTRRs are enabled. */
    BOOLEAN FixedEnabled;
    /* Retain the default Intel memory-type encoding. */
    UCHAR DefaultType;
    /* Retain the number of valid variable-range records. */
    UCHAR VariableCount;
    /* Retain all architecturally discoverable fixed-range type bytes. */
    UCHAR FixedTypes[88];
    /* Retain the decoded variable MTRR records. */
    KSW_HVM_MTRR_RANGE Variable[KSW_HVM_MAX_VARIABLE_MTRRS];
} KSW_HVM_MTRR_STATE;

/*
 * Track one paging structure a domain forked from the shared hierarchy.
 *
 * Domains share the default view's tables until they need to differ, so the
 * common case costs one page: the domain's own PML4.  A restriction touching
 * one two-MiB leaf costs two more, the PDPT and PD on the path to it.
 */
typedef struct _KSW_HVM_DOMAIN_PRIVATE_TABLE
{
    /* Retain the PML4 slot this table sits under. */
    ULONG Pml4Index;
    /* Retain the PDPT slot, or MAXULONG when this table IS the PDPT. */
    ULONG PdptIndex;
    /* Retain the writable mapping used to edit and free the table. */
    PVOID Virtual;
    /* Retain the physical address published into the parent entry. */
    PHYSICAL_ADDRESS Physical;
} KSW_HVM_DOMAIN_PRIVATE_TABLE;

/* Describe one EPT execution domain reachable through the EPTP list. */
typedef struct _KSW_HVM_EPT_DOMAIN
{
    /* Record whether the slot holds a live domain. */
    BOOLEAN Active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[3];
    /* Retain the number of forked private tables. */
    ULONG PrivateTableCount;
    /* Retain this domain's own root table. */
    PVOID Pml4Virtual;
    /* Retain the root physical address encoded into the EPT pointer. */
    PHYSICAL_ADDRESS Pml4Physical;
    /* Retain the EPT pointer published into the EPTP list. */
    ULONGLONG EptPointer;
    /* Own every copy-on-write paging structure this domain forked. */
    KSW_HVM_DOMAIN_PRIVATE_TABLE
        PrivateTables[KSW_HVM_MAX_DOMAIN_PRIVATE_TABLES];
} KSW_HVM_EPT_DOMAIN;

/* Describe one active protocol-visible EPT rule. */
typedef struct _KSW_HVM_EPT_RULE_SLOT
{
    /* Record whether the slot contains an active rule. */
    BOOLEAN Active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[3];
    /* Retain the stable protocol-visible rule identifier. */
    ULONG RuleId;
    /* Retain the permissions removed from each target page. */
    ULONG DeniedAccess;
    /* Retain the rule behavior flags. */
    ULONG Flags;
    /* Retain the first page-aligned guest physical address. */
    ULONGLONG PhysicalAddress;
    /* Retain the number of covered four-KiB pages. */
    ULONGLONG PageCount;
} KSW_HVM_EPT_RULE_SLOT;

/* Track one two-MiB EPT leaf that was split into four-KiB entries. */
typedef struct _KSW_HVM_EPT_SPLIT
{
    /* Record whether the split ledger slot is active. */
    BOOLEAN Active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[7];
    /* Retain the aligned guest physical base represented by the page table. */
    ULONGLONG PhysicalBase;
    /* Retain the writable virtual address of the page table. */
    PVOID PageTable;
    /* Retain the page-table physical address encoded into the parent PDE. */
    PHYSICAL_ADDRESS PageTablePhysical;
    /* Retain the writable parent PDE address for merge and invalidation. */
    volatile ULONGLONG* ParentEntry;
    /* Retain the original two-MiB identity leaf. */
    ULONGLONG OriginalEntry;
} KSW_HVM_EPT_SPLIT;

/*
 * Describe one installed EPT split view.  The leaf alternates between two
 * values: the primary one the view keeps installed, and the secondary one that
 * services the access the primary deliberately forbids.  Restoration reuses the
 * allow-once transient machinery, so a view flip is a monitor-trap step.
 */
typedef struct _KSW_HVM_EPT_VIEW_SLOT
{
    /* Record whether the slot holds an installed view. */
    BOOLEAN Active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[3];
    /* Retain the stable protocol-visible view identifier. */
    ULONG ViewId;
    /* Retain the kind that decides which access is served by the shadow. */
    ULONG Kind;
    /* Retain the view behavior flags. */
    ULONG Flags;
    /* Retain the page-aligned guest physical address the view covers. */
    ULONGLONG PhysicalAddress;
    /* Own the shadow page that backs the redirected access. */
    PVOID ShadowVirtual;
    /* Retain the shadow physical address encoded into the secondary value. */
    PHYSICAL_ADDRESS ShadowPhysical;
    /* Reference the writable four-KiB leaf entry this view flips. */
    volatile ULONGLONG* Entry;
    /* Preserve the leaf value that existed before installation. */
    ULONGLONG OriginalEntry;
    /* Preserve the steady-state value the view keeps installed. */
    ULONGLONG PrimaryEntry;
    /* Preserve the value used while the redirected access is serviced. */
    ULONGLONG SecondaryEntry;
    /* Count how often the leaf flipped to the secondary value. */
    volatile LONG64 FlipCount;
    /*
     * Which secondary EPT hierarchy backs this view, or 0 when none does.
     *
     * Zero is the base index, which is exactly the right encoding for "this
     * view is served by the write-leaf + monitor-trap backend": that backend
     * never leaves the base hierarchy, so "no hierarchy of its own" and "runs
     * on the base" are the same statement rather than two that could disagree.
     */
    ULONG EptSwitchIndex;
    /* Keep the structure's tail explicitly initialized. */
    ULONG Reserved1;
} KSW_HVM_EPT_VIEW_SLOT;

/* 一条 R-1 进程处置的完整驱动侧状态。 */
typedef struct _KSW_HVM_PROCESS_SLOT
{
    /* 非零表示本槽在用。 */
    BOOLEAN InUse;
    /* 保持后面的成员自然对齐。 */
    UCHAR Reserved0[3];
    /* 下达时的 PID，只用于回报；判据是 DirectoryBase。 */
    ULONG ProcessId;
    /* OP_FREEZE 或 OP_TERMINATE。 */
    ULONG Disposition;
    /*
     * 本条占用的受限层次序号（1..LeafCapacity），0 是基座、永远不会出现在这里。
     *
     * 层次的叶把目标页写成不可执行，其余与基座共享，所以这套层次只有"那一页不
     * 能执行"这一个差别。
     */
    ULONG HierarchyIndex;
    /* 目标地址空间，低位的 PCID 与标志已掩掉。 */
    ULONGLONG DirectoryBase;
    /* 被拒绝执行的页的客户物理地址，已按页对齐。 */
    ULONGLONG GuestPhysicalAddress;
    /* 下达时给出的客户线性地址，用来回溯这一页是怎么选出来的。 */
    ULONGLONG GuestLinearAddress;
    /* 本条拦下过多少次执行。冻结下会持续增长，那就是自旋的证据。 */
    volatile LONG64 InterceptCount;
} KSW_HVM_PROCESS_SLOT;

/*
 * Root-to-leaf pages one secondary EPT hierarchy copies.
 *
 * Written as a literal here rather than pulled from the shared arithmetic
 * header, which is nearly two thousand lines of static __inline helpers that
 * every translation unit including this file would then carry.  The literal
 * is not a second source of truth: hvm_ept_switch.c asserts at compile time
 * that it equals KSWORD_ARK_HVM_EPTSW_PATH_PAGES, so a change on either side
 * breaks the build instead of silently disagreeing.
 */
#define KSW_HVM_EPTSW_PATH_PAGES 4UL

/* Own one secondary EPT hierarchy: the copied path plus its bookkeeping. */
typedef struct _KSW_HVM_EPTSW_HIERARCHY
{
    /* Record whether this record describes a built hierarchy. */
    BOOLEAN Active;
    /* Keep the 64-bit members naturally aligned. */
    UCHAR Reserved0[7];
    /*
     * Retain the EPT pointer this hierarchy is loaded with.  Derived from the
     * base pointer by replacing only the root address, never composed from
     * constants: composing would give the memory type, the walk length and
     * the accessed/dirty bit a second source of truth, and a derived pointer
     * is accepted by VM entry exactly when the base one is.
     */
    ULONGLONG EptPointer;
    /* Retain the guest-physical page this hierarchy relaxes. */
    ULONGLONG LeafPhysical;
    /* Retain the value that leaf carries inside this hierarchy. */
    ULONGLONG SecondaryEntry;
    /* Retain the base value, so a return to base can be verified. */
    ULONGLONG PrimaryEntry;
    /* Retain the copied pages, indexed by level (0 = PML4 ... 3 = PT). */
    PVOID Level[KSW_HVM_EPTSW_PATH_PAGES];
} KSW_HVM_EPTSW_HIERARCHY;

/*
 * Own every secondary hierarchy this runtime may switch to.
 *
 * Index 0 is the base - every leaf at its primary value, byte for byte the
 * steady state that exists today - and index k means leaf k-1, and only leaf
 * k-1, is relaxed.  "Is any leaf relaxed" is therefore exactly "is the index
 * non-zero", with deliberately no second boolean to keep in step.
 */
typedef struct _KSW_HVM_EPTSW
{
    /* Record whether the page pool exists and the ledger is consistent. */
    BOOLEAN Active;
    /* Keep the 32-bit members naturally aligned. */
    UCHAR Reserved0[3];
    /* Ledger length: the base plus one per leaf, i.e. LeafCapacity + 1. */
    ULONG HierarchyCount;
    /* Bound the flippable leaves this runtime admits. */
    ULONG LeafCapacity;
    /* Count the hierarchies actually built, never above LeafCapacity. */
    ULONG BuiltCount;
    /*
     * Record i owns pool pages [i*PATH_PAGES, (i+1)*PATH_PAGES) - a fixed
     * slice, not a bump allocation.  A cursor would make releasing one
     * hierarchy either leak its pages or fragment the pool, and a view can be
     * removed and re-added in any order.  Fixed slices make release exact and
     * reuse free, at the cost of reserving the whole pool up front - which is
     * 512 KiB total and independent of the processor count.
     */
    ULONG Reserved2;
    /*
     * One allocation backs every hierarchy.  A per-table allocator would make
     * a fragmented machine fail a start half-way through, and would put a
     * PASSIVE_LEVEL-only free on a teardown path a power callback can reach.
     */
    PUCHAR PageBlock;
    /* Count the pages in the pool: LeafCapacity * KSW_HVM_EPTSW_PATH_PAGES. */
    ULONG PageCount;
    /* Keep the trailing pointer array naturally aligned. */
    ULONG Reserved1;
    /* One record per leaf; array index k-1 is hierarchy index k. */
    KSW_HVM_EPTSW_HIERARCHY Hierarchies[KSWORD_ARK_HVM_MAX_VIEWS];
    /*
     * Flat pointer ledger indexed by hierarchy index: slot 0 is the base and
     * slot k is leaf k-1's hierarchy, zero while unbuilt.
     *
     * Kept alongside the records rather than derived from them on each exit
     * because the switch planner takes a contiguous table and its own length,
     * and refuses a length that is not exactly "base plus one per leaf".  A
     * short table would be indexed past its end and would read whatever sits
     * after it - quite possibly a stale pointer that still looks valid, which
     * the processor would then be loaded with.
     */
    ULONGLONG Eptp[KSWORD_ARK_HVM_MAX_VIEWS + 1UL];
} KSW_HVM_EPTSW;

/* Describe one installed MSR policy and the bitmap hole it owns. */
typedef struct _KSW_HVM_MSR_POLICY_SLOT
{
    /* Record whether the slot holds an installed policy. */
    BOOLEAN Active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[3];
    /* Retain the stable protocol-visible policy identifier. */
    ULONG PolicyId;
    /* Retain the intercepted architectural MSR index. */
    ULONG MsrIndex;
    /* Retain which of read and write this policy intercepts. */
    ULONG Access;
    /* Retain the action applied to an intercepted access. */
    ULONG Action;
    /* Keep the following value naturally aligned. */
    ULONG Reserved1;
    /* Retain the value returned by a faked read. */
    ULONGLONG FakeValue;
    /* Count how often the dispatcher applied this policy. */
    volatile LONG64 HitCount;
} KSW_HVM_MSR_POLICY_SLOT;

/* Own the serialized HVM capability, lifecycle, EPT, and telemetry state. */
typedef struct _KSW_HVM_RUNTIME
{
    /* Serialize PASSIVE_LEVEL lifecycle and protocol operations. */
    EX_PUSH_LOCK Lock;
    /* Publish whether runtime initialization completed. */
    BOOLEAN Initialized;
    /* Publish whether one serialized control operation is executing. */
    BOOLEAN Busy;
    /* Keep explicit padding initialized for stable crash-dump inspection. */
    USHORT Reserved0;
    /*
     * Publish protocol-visible lifecycle flags.
     *
     * Mutate this ONLY through KswordARKHvmStateSet / KswordARKHvmStateClear
     * below.  Two writers reach it and they cannot share a lock: every
     * lifecycle path holds the runtime push lock, while the power callback
     * deliberately does not take it - blocking there would let a VMX window
     * cross the S0 boundary, which is the one thing that callback exists to
     * prevent, and it bugchecks rather than wait (see its DEVICE_BUSY branch).
     * So the synchronization has to live in the word itself.  A single plain
     * read-modify-write anywhere can drop the FAULTED and ROLLBACK_REQUIRED
     * the callback just set, and those are fail-closed markers.
     */
    volatile LONG StateFlags;
    /* Publish the generation used for compare-before control requests. */
    ULONG Generation;
    /* Publish the stable query status. */
    ULONG QueryStatus;
    /* Preserve the last authoritative NTSTATUS. */
    NTSTATUS LastStatus;
    /* Preserve the number of enumerated processors. */
    ULONG ProcessorCount;
    /* Preserve the number of allocated processor resource pairs. */
    ULONG PreparedProcessorCount;
    /* Preserve the number of successful VMXON/VMXOFF tests. */
    ULONG SelfTestPassedProcessorCount;
    /* Publish the number of processors currently in VMX non-root mode. */
    volatile LONG ResidentProcessorCount;
    /* Publish resident-lifecycle implementation maturity. */
    ULONG ResidentImplementation;
    /* Publish EPT-rule implementation maturity. */
    ULONG EptImplementation;
    /* Publish nested-VMX implementation maturity. */
    ULONG NestedImplementation;
    /* Publish eVMCS implementation maturity. */
    ULONG EvmcsImplementation;
    /* Publish the current nested-VMX state. */
    ULONG NestedState;
    /*
     * Count refused L2 launches.  NestedState alone cannot carry this: it is
     * reset to DISPATCH_READY on the next VMXOFF, so the evidence that another
     * hypervisor tried to start a VM under us disappears before any poll can
     * see it.  Monotonic, never reset while the driver is loaded.
     */
    volatile LONG NestedL2LaunchRefusedCount;
    /* Publish the current eVMCS state. */
    ULONG EvmcsState;
    /* Publish the TLFS eVMCS version discovered from CPUID. */
    USHORT EvmcsVersion;
    /* Keep explicit padding initialized for deterministic snapshots. */
    USHORT Reserved1;
    /* Publish TLFS partition and VP-assist ownership evidence. */
    ULONG EvmcsFlags;
    /* Preserve the current VP-assist-page MSR value when readable. */
    ULONGLONG EvmcsVpAssistMsr;
    /* Preserve the number of active EPT rules. */
    ULONG EptRuleCount;
    /* Preserve the number of allocated EPT table pages. */
    ULONG EptPageCount;
    /* Preserve the number of populated EPT PML4 entries. */
    ULONG EptPml4Entries;
    /* Preserve the number of populated EPT PDPT entries. */
    ULONG EptPdptEntries;
    /* Preserve the number of populated two-MiB EPT leaves. */
    ULONG EptLargePageEntries;
    /* Preserve decoded protocol capability flags. */
    ULONGLONG FeatureFlags;
    /* Preserve IA32_VMX_BASIC evidence. */
    ULONGLONG VmxBasic;
    /*
     * IA32_VMX_MISC.  Cached because the HLT exit path needs bit 6 - whether
     * the halt activity state is supported - and reading the MSR there would
     * mean an MSR access per idle tick, which the hypervisor beneath us is
     * free to intercept.
     */
    ULONGLONG VmxMisc;
    /*
     * Page-directory base the VM-exit handler runs on, captured from the
     * System process.
     *
     * HOST_CR3 cannot be the CR3 that happens to be live while the VMCS is
     * configured: residency is armed through KeIpiGenericCall from the thread
     * that issued the IOCTL, so that CR3 belongs to the requesting user-mode
     * process.  Once residency outlives that process - which it now does, since
     * HLT no longer devirtualizes - its top-level page table is freed and
     * zeroed, and the next VM exit loads a CR3 that cannot translate HOST_RIP.
     * The resulting #PF cannot read the IDT either, so it escalates to #DF and
     * then to a triple fault: the virtual machine simply resets, with no
     * bugcheck and no dump.  That fingerprint is indistinguishable from the
     * silent hang this whole investigation started from.
     *
     * The System process never exits while the driver is loaded, so its
     * top-level page table is the only base that stays valid for the entire
     * life of residency.
     */
    ULONGLONG HostCr3;
    /* Preserve IA32_VMX_EPT_VPID_CAP evidence. */
    ULONGLONG VmxEptVpidCapabilities;
    /*
     * What was actually written into the VMCS execution-control fields, and the
     * capability MSR each one was adjusted against.
     *
     * Recorded because "which exits does this machine take" and "which of them
     * did we ask for" are different questions, and until now the second one
     * could only be answered by reading the source and reasoning about it.
     * The exit histogram made the gap concrete: HLT is the single largest exit
     * reason on the nested target, while resident mode requests no HLT exiting
     * at all - so either the outer hypervisor forces the bit through the
     * allowed-0 half of the capability MSR, or the control is being computed
     * wrongly, and reasoning cannot tell those apart.
     *
     * Kept as the adjusted result rather than the request: the request is a
     * compile-time constant anyone can read, whereas the value the processor
     * actually enforces is the one that explains the exits.  A bit set here
     * that the request did not ask for is, by construction, one the capability
     * MSR made mandatory.
     *
     * Written once per residency start, from the processor that configures the
     * VMCS; every processor computes the same values from the same MSRs.
     */
    KSW_HVM_ACTIVE_CONTROLS ActiveControls;
    /*
     * Nonzero while the exit path should execute a batch of throwaway VMREADs
     * on every exit.
     *
     * Measurement only.  Published on the runtime rather than kept in the
     * resident module's own flags because the exit dispatcher cannot see those,
     * and reading it costs one load on a path that is about to do far more work
     * than that by construction.
     */
    volatile LONG VmreadBenchArmed;
    /*
     * 武装时每次退出要跑多少遍。由请求给出，已夹在上限内。
     *
     * 与 VmreadBenchArmed 分开两个字段而不是"0 表示关闭"：关闭与次数是两件事，
     * 合成一个值就没法表达"武装了但请求给的是 0（用默认）"，而那正是最常用的
     * 调用形式。
     */
    volatile LONG VmreadBenchIterations;
    /*
     * 非零时把普通退出也逐条写进事件环；默认零，只留四类证据事件。
     *
     * 和上面两个字段同样放在 runtime 上：退出派发器看不见常驻模块自己的标志位，
     * 而这一个必须在**每次**退出的发布点被读到。
     */
    volatile LONG TraceRoutineExits;
    /* Preserve IA32_VMX_VMFUNC evidence; bit 0 is EPTP switching. */
    ULONGLONG VmFunctionCapabilities;
    /* Retain the 512-entry EPTP list published to VMFUNC. */
    PVOID EptpListVirtual;
    /* Retain the EPTP list physical address written into the VMCS. */
    PHYSICAL_ADDRESS EptpListPhysical;
    /* Own every EPT execution domain; slot zero is the default view. */
    KSW_HVM_EPT_DOMAIN EptDomains[KSW_HVM_MAX_EPT_DOMAINS];
    /* Preserve IA32_FEATURE_CONTROL evidence. */
    ULONGLONG FeatureControl;
    /* Preserve IA32_VMX_CR0_FIXED0 evidence. */
    ULONGLONG Cr0Fixed0;
    /* Preserve IA32_VMX_CR0_FIXED1 evidence. */
    ULONGLONG Cr0Fixed1;
    /* Preserve IA32_VMX_CR4_FIXED0 evidence. */
    ULONGLONG Cr4Fixed0;
    /* Preserve IA32_VMX_CR4_FIXED1 evidence. */
    ULONGLONG Cr4Fixed1;
    /* Preserve the active EPT pointer. */
    ULONGLONG EptPointer;
    /* Preserve the number of identity-mapped RAM bytes. */
    ULONGLONG MappedRamBytes;
    /* Preserve the exclusive upper physical mapping boundary. */
    ULONGLONG HighestMappedPhysicalAddress;
    /* Preserve a monotonic VM-exit count. */
    volatile LONG64 VmExitCount;
    /* Preserve the last VM-exit qualification. */
    volatile LONG64 LastExitQualification;
    /* Preserve the last guest instruction pointer. */
    volatile LONG64 LastGuestRip;
    /* Preserve the last guest stack pointer. */
    volatile LONG64 LastGuestRsp;
    /* Preserve the last basic VM-exit reason. */
    volatile LONG LastExitReason;
    /* Preserve the last VM-exit instruction length. */
    volatile LONG LastExitInstructionLength;
    /* Preserve the last VM-instruction error. */
    volatile LONG LastVmInstructionError;
    /* Preserve the group of the last one-shot launch. */
    USHORT LastLaunchProcessorGroup;
    /* Preserve the group-relative CPU of the last one-shot launch. */
    UCHAR LastLaunchProcessorNumber;
    /* Preserve whether the last one-shot launch was nested. */
    UCHAR LastLaunchWasNested;
    /* Preserve the processor vendor string. */
    CHAR CpuVendor[KSWORD_ARK_HVM_VENDOR_CHARS];
    /* Preserve the hypervisor vendor string. */
    CHAR HypervisorVendor[KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS];
    /* Own every per-processor VMX resource pair. */
    KSW_HVM_CPU_RESOURCE Processors[KSWORD_ARK_HVM_MAX_PROCESSORS];
    /* Track every EPT allocation exactly once. */
    KSW_HVM_EPT_PAGE EptPages[KSW_HVM_MAX_EPT_PAGES];
    /* Own the shared MSR-bitmap page that keeps resident MSR access native. */
    PVOID MsrBitmapVirtual;
    /* Retain the MSR-bitmap physical address written into every VMCS. */
    PHYSICAL_ADDRESS MsrBitmapPhysical;
    /* Retain the EPT PML4 virtual address. */
    PVOID EptPml4;
    /* Retain each sparse EPT PDPT virtual address. */
    PVOID EptPdpt[KSW_HVM_MAX_PML4_ENTRIES];
    /* Retain each sparse EPT page-directory virtual address. */
    PVOID EptPd[KSW_HVM_MAX_PML4_ENTRIES][512];
    /* Retain the immutable MTRR snapshot used to type EPT leaves. */
    KSW_HVM_MTRR_STATE Mtrr;
    /* Retain every protocol-visible EPT rule. */
    KSW_HVM_EPT_RULE_SLOT EptRules[KSWORD_ARK_HVM_MAX_EPT_RULES];
    /* Retain every split two-MiB EPT leaf. */
    KSW_HVM_EPT_SPLIT EptSplits[KSW_HVM_MAX_EPT_SPLITS];
    /* Retain every installed EPT split view. */
    KSW_HVM_EPT_VIEW_SLOT EptViews[KSWORD_ARK_HVM_MAX_VIEWS];
    /*
     * Secondary EPT hierarchies for the EPTP-switching split-view backend.
     *
     * Reserved at prepare only when EptpSwitchArmed is TRUE, and zeroed
     * otherwise, so an unarmed runtime carries the storage but never a page.
     */
    KSW_HVM_EPTSW EptSwitch;
    /* 每条 R-1 进程处置。表只在常驻停着时被改，退出路径不加锁读。 */
    KSW_HVM_PROCESS_SLOT ProcessDispositions[KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS];
    /* 表里当前有多少条。 */
    ULONG ProcessDispositionCount;
    /* Preserve the number of installed EPT split views. */
    ULONG EptViewCount;
    /* Preserve the next view identifier handed out by the view backend. */
    ULONG EptViewNextId;
    /* Retain every installed MSR policy. */
    KSW_HVM_MSR_POLICY_SLOT MsrPolicies[KSWORD_ARK_HVM_MAX_MSR_POLICIES];
    /* Preserve the number of installed MSR policies. */
    ULONG MsrPolicyCount;
    /* Preserve the next policy identifier handed out by the MSR backend. */
    ULONG MsrPolicyNextId;
    /* Publish the control-register policy flags currently configured. */
    ULONG CrPolicyFlags;
    /* Retain the CR0 bits the guest must not change. */
    ULONGLONG CrPolicyCr0PinnedMask;
    /* Retain the CR4 bits the guest must not change. */
    ULONGLONG CrPolicyCr4PinnedMask;
    /* Preserve the CR0 value captured when the policy was installed. */
    ULONGLONG CrPolicyCr0PinnedValue;
    /* Preserve the CR4 value captured when the policy was installed. */
    ULONGLONG CrPolicyCr4PinnedValue;
    /* Count refused guest writes to pinned control-register bits. */
    volatile LONG64 CrPolicyRefusedWriteCount;
    /* Count observed address-space switches. */
    volatile LONG64 CrPolicyCr3SwitchCount;
    /* Count intercepted debug-register accesses. */
    volatile LONG64 CrPolicyDebugAccessCount;
    /* Protect only the resident-transition phase and idle-event state. */
    KSPIN_LOCK ResidentTransitionStateLock;
    /* Wake wait-capable transition contenders after the current owner exits. */
    KEVENT ResidentTransitionIdleEvent;
    /* Publish whether one VMX transition phase currently owns the runtime. */
    volatile LONG ResidentTransitionActive;
    /* Reference this image's driver object for the unload interlock. */
    PDRIVER_OBJECT DriverObject;
    /* Preserve the exact KMDF-installed unload entry while residency is active. */
    PDRIVER_UNLOAD OriginalDriverUnload;
    /* Reference the system-defined power-state callback object. */
    PCALLBACK_OBJECT PowerStateCallbackObject;
    /* Own the power-state callback registration. */
    PVOID PowerStateCallbackRegistration;
    /* Own the processor-add veto callback registration. */
    PVOID ProcessorChangeRegistration;
    /* Publish host-stack construction so a power callback never frees it. */
    volatile LONG ResidentContextPreparing;
    /* Publish 0=idle, 1=leaving S0, 2=resumed while context prep drains. */
    volatile LONG PowerTransitionPending;
    /* Increment once whenever the power manager begins leaving S0. */
    volatile LONG PowerTransitionGeneration;
    /* Publish whether DriverUnload is currently removed from DriverObject. */
    volatile LONG UnloadGuardArmed;
    /*
     * Ask every still-resident processor to leave VMX after one of them failed
     * closed.
     *
     * KswordARKHvmResidentDeactivateCurrent devirtualizes **one current**
     * processor, and the IPI rendezvous that could reach the others cannot be
     * issued from a VM-exit handler: that code runs in VMX root at an
     * indeterminate IRQL.  So a fail-closed exit used to leave the box half
     * devirtualized - one processor back on bare metal while the others kept
     * running in VMX non-root on a hierarchy whose leaves the fault had just
     * been about.  On one processor "devirtualize the current one" and "stop
     * everything" are indistinguishable, which is why this survived until the
     * target was given a second virtual processor.
     *
     * Measured 2026-09-07 (2 vCPU, probe-xonly): one strict EPT rule hit,
     * residentProcessorCount went 2 -> 1 and stayed there.
     *
     * Deliberately NOT the per-VCPU StopRequested flag.  That one is consumed
     * by the private stop hypercall (hvm_exit.c:641-652) and its exit advances
     * RIP past the VMCALL; honouring it at the top of the dispatcher would make
     * that same VMCALL re-execute natively and #UD.  The two mechanisms need
     * different instruction-length semantics, so they get different flags.
     *
     * Set by the failing processor before it leaves VMX, consumed by every
     * other processor at the top of its next VM exit, cleared when residency
     * starts.  Exits are frequent enough that convergence is immediate in
     * practice (a short resident window measured 91082 of them).
     */
    volatile LONG ResidentFaultStopRequested;
    /* Fail-closed resident lifecycle gate, enabled only after all guards bind. */
    BOOLEAN ResidentStartAllowed;
    /*
     * Record whether this runtime may hand out per-processor EPT hierarchies.
     * Capability-derived, so it is evidence and must be destroyed alongside
     * the other pre-suspend evidence on an S0 transition.
     */
    BOOLEAN LocalEptArmed;
    /*
     * Record whether this runtime uses the EPTP-switching split-view backend
     * instead of the write-leaf + monitor-trap one.  Capability-derived like
     * LocalEptArmed, so it is evidence and must be destroyed alongside the
     * other pre-suspend evidence on an S0 transition.
     *
     * FALSE is the existing behaviour in full: every run-time path keeps
     * asking the MTF backend, and the only cost of the feature being off is
     * this one BOOLEAN load.
     */
    BOOLEAN EptpSwitchArmed;
    /*
     * Record whether the hypervisor underneath us identifies itself with the
     * TLFS Hv#1 interface signature (CPUID 0x40000001 EAX == 'Hv#1').
     *
     * HYPERVISOR_PRESENT alone is the generic CPUID.1:ECX[31] bit and says
     * nothing about whose ABI is in force, but the hypercall forwarding stub
     * hard-codes the Hv#1 register contract - it passes RCX/RDX/R8/XMM0-5 and
     * destroys RAX with its unserviced sentinel.  Under an outer hypervisor
     * with a different contract RAX is a live input, so forwarding there would
     * corrupt the call rather than relay it.  Gating on this keeps that from
     * happening, and it cannot cost a legitimate call: Windows only builds a
     * hypercall page after it sees this same signature, so a guest that does
     * not present Hv#1 never issues the hypercalls this gate refuses.
     */
    BOOLEAN HypervisorInterfaceIsHv1;
    /* Keep the tail deterministic for crash-dump inspection. */
    UCHAR Reserved2[5];
} KSW_HVM_RUNTIME;

/*
 * The only two ways StateFlags may be mutated.  See the field's own comment for
 * why a plain read-modify-write is not safe anywhere, including under the lock.
 */
static __forceinline VOID
KswordARKHvmStateSet(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG Bits
    )
{
    /* Publish the requested lifecycle bits without losing a concurrent set. */
    (VOID)InterlockedOr(&Runtime->StateFlags, (LONG)Bits);
}

static __forceinline VOID
KswordARKHvmStateClear(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG Bits
    )
{
    /* Retire the requested lifecycle bits without losing a concurrent set. */
    (VOID)InterlockedAnd(&Runtime->StateFlags, (LONG)~Bits);
}

EXTERN_C_START

/*
 * Serialize VMX transition phases without holding a spin lock across VMX or
 * all-processor rendezvous work.  At IRQL <= APC_LEVEL contenders wait on the
 * preallocated event.  A DISPATCH_LEVEL callback never spins behind an owner;
 * it receives STATUS_DEVICE_BUSY so the power path can fail closed.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS
KswordARKHvmAcquireResidentTransition(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Release one transition phase and wake every wait-capable contender. */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KswordARKHvmReleaseResidentTransition(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Allocate one zeroed EPT page and record it in the runtime ledger. */
PVOID
KswordARKHvmAllocateEptPageLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Out_ PHYSICAL_ADDRESS* PhysicalAddress
    );

/* Return the process-wide HVM runtime for nonblocking VM-exit telemetry. */
KSW_HVM_RUNTIME*
KswordARKHvmGetRuntime(
    VOID
    );

/* Remove the exact captured KMDF unload entry before resident VMX entry. */
NTSTATUS
KswordARKHvmArmUnloadGuard(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Restore the captured unload entry after every resident CPU completed VMXOFF. */
NTSTATUS
KswordARKHvmDisarmUnloadGuard(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Invalidate pre-sleep VMX evidence before reopening resident start. */
VOID
KswordARKHvmInvalidatePowerResumeEvidence(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

EXTERN_C_END
