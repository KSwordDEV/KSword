/* PASSIVE_LEVEL ownership plus VMEXIT-safe, RAM-only physical operand access. */
#include "hvm_svm_nested_runtime.h"
#include "../../platform/pool_compat.h"

/* Validate full operands against the retained, immutable RAM inventory. */
BOOLEAN KswordSvmNestedRamRange(const KSW_SVM_NESTED* Nested, ULONGLONG Address, ULONG Bytes)
{
    /* Walk the trusted Windows inventory, never guest-supplied intervals. */
    ULONG index;
    /* Word reads and whole-page commits must fit without unsigned subtraction underflow. */
    if (!Nested || !Nested->Outer || !Bytes || (Address & 7ULL) ||
        Bytes > Nested->Outer->Limit || Address > Nested->Outer->Limit - Bytes || !Nested->Outer->Ranges) { return FALSE; }
    /* The inventory was validated before any CPU entered SVM. */
    for (index = 0; Nested->Outer->Ranges[index].NumberOfBytes.QuadPart; ++index) {
        /* Decode a validated nonnegative interval. */
        ULONGLONG low = (ULONGLONG)Nested->Outer->Ranges[index].BaseAddress.QuadPart;
        /* The builder already checked addition against the physical-address limit. */
        ULONGLONG high = low + (ULONGLONG)Nested->Outer->Ranges[index].NumberOfBytes.QuadPart;
        /* No MMIO/unknown hole is mapped with the window's RAM cache attributes. */
        if (Bytes <= high - low && Address >= low && Address <= high - Bytes) { return TRUE; }
    }
    /* Unclassified physical memory is not an admissible table operand. */
    return FALSE;
}

/* Each physical mapping is opened and closed within one callback. */
int KswordSvmNestedRead(void* Context, KSW_SVM_U64 Address, KSW_SVM_U64* Value)
{
    /* CPU ownership is held by the current SVM host loop. */
    KSW_SVM_NESTED* nested = (KSW_SVM_NESTED*)Context;
    /* Never return or retain the transient mapping pointer. */
    volatile VOID* mapped = NULL;
    /* RAM validation precedes window mapping. */
    if (!KswordSvmNestedRamRange(nested, Address, 8) ||
        KswordARKHvmPhysWindowMap(nested->Window, Address, 8, &mapped) != KSW_HVM_PHYS_WINDOW_OK) { return 0; }
    /* Aligned x64 word access does not fabricate a value on mapping failure. */
    *Value = *(volatile ULONGLONG*)mapped;
    /* Every successful map has exactly one unmap before another callback. */
    KswordARKHvmPhysWindowUnmap(nested->Window);
    /* The caller receives one complete source word. */
    return 1;
}

/* Publish A/D without overwriting a concurrent frame/permission change. */
int KswordSvmNestedCompareOr(void* Context, KSW_SVM_U64 Address,
    KSW_SVM_U64 Expected, KSW_SVM_U64 Bits)
{
    /* This is the same per-CPU window used by reads. */
    KSW_SVM_NESTED* nested = (KSW_SVM_NESTED*)Context;
    /* The mapping exists only during this atomic operation. */
    volatile VOID* mapped = NULL;
    /* Preserve the actual compare-exchange observation. */
    LONG64 observed;
    /* This callback may alter only the architectural Accessed/Dirty bits. */
    if ((Bits & ~0x60ULL) || !KswordSvmNestedRamRange(nested, Address, 8) ||
        KswordARKHvmPhysWindowMap(nested->Window, Address, 8, &mapped) != KSW_HVM_PHYS_WINDOW_OK) { return 0; }
    /* LOCK CMPXCHG is nonblocking and does not acquire a kernel spinlock. */
    observed = InterlockedCompareExchange64((volatile LONG64*)mapped, (LONG64)(Expected | Bits), (LONG64)Expected);
    /* Drop the mapping even when a competing writer changed the slot. */
    KswordARKHvmPhysWindowUnmap(nested->Window);
    /* A mismatch forces a new walk; the competing value is never overwritten. */
    return (ULONGLONG)observed == Expected;
}

/* Release only after the backend has proved complete native return on every CPU. */
VOID KswordSvmNestedRelease(KSW_SVM_CPU* Cpu)
{
    /* Partial preparation is cleaned through the same allocation ledger. */
    KSW_SVM_NESTED* nested = Cpu->Nested;
    /* Every descriptor starts zero. */
    ULONG index;
    /* No allocation was acquired for an ordinary baseline prepare. */
    if (!nested) { return; }
    /* Retain everything if the owner could still issue a nested VMRUN. */
    if (KswordSvmNestedBusy(Cpu)) { return; }
    /* Reverse the complete allocation set, including unused shadow pages. */
    for (index = KSW_NSVM_PROBE_PAGES; index != 0;) {
        /* Descend through the allocation ledger, not hardware pointers. */
        --index;
        /* Free every successfully allocated page exactly once. */
        if (nested->Pages[index].Words) { MmFreeContiguousMemory(nested->Pages[index].Words); }
    }
    /* The private inner stack is ordinary nonpaged NX memory. */
    if (nested->Stack) { ExFreePoolWithTag(nested->Stack, 'pSvK'); }
    /* Hardware permission maps remain owned until the inner CPU is native. */
    if (nested->MergedMaps) { MmFreeContiguousMemory(nested->MergedMaps); }
    /* One contiguous allocation owns both operand and virtual HSAVE pages. */
    if (nested->Operand) { MmFreeContiguousMemory(nested->Operand); }
    /* Drop CPU-local snapshots last. */
    ExFreePoolWithTag(nested, 'pSvK');
    /* Prevent reuse after teardown. */
    Cpu->Nested = NULL;
}

/* Called after the shared NPT has a complete physical range inventory. */
NTSTATUS KswordSvmNestedPrepare(KSW_SVM_CPU* Cpu, ULONG Index)
{
    /* Keep cleanup ownership visible before allocating child resources. */
    KSW_SVM_NESTED* nested;
    /* Bound hardware pages to the same address width as the outer backend. */
    PHYSICAL_ADDRESS highest;
    /* Validate both subranges without trusting allocator alignment implicitly. */
    ULONGLONG mapBase;
    /* Populate the fixed-capacity pool without runtime allocation. */
    ULONG page;
    /* Current backend lifetime holds the shared NPT throughout this preparation. */
    KSW_SVM_STATE* state = Cpu->Runtime->BackendContext;
    /* Do not replace an existing owner. */
    if (Cpu->Nested) { return STATUS_ALREADY_REGISTERED; }
    /* Allocate snapshots/ledger from nonpaged memory. */
    nested = KswordARKAllocateNonPagedPool(sizeof(*nested), 'pSvK');
    /* No ownership can be published on allocation failure. */
    if (!nested) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* Null pointers make all partial failure paths releasable. */
    RtlZeroMemory(nested, sizeof(*nested));
    /* Publish allocation ownership, not executable readiness. */
    Cpu->Nested = nested;
    /* Borrow the verified CPU-local window for the driver's lifetime. */
    nested->Window = KswordARKHvmPhysWindowForProcessor(Index);
    /* Borrow the backend lifetime's immutable outer map. */
    nested->Outer = &state->Npt;
    /* All virtual CPUs share one translated VMCB ownership domain. */
    nested->Owners = &state->NestedOwners;
    /* Stable Windows topology identity, independent of sparse hardware APIC IDs. */
    nested->CpuIdentity = ((ULONG)Cpu->Resource->Row.processorGroup << 16) | Cpu->Resource->Row.processorNumber;
    /* Refuse to execute without the physical access/cache admission mechanism. */
    if (!nested->Window || !state->Npt.Ranges) { return STATUS_NOT_SUPPORTED; }
    /* Highest representable host physical byte. */
    highest.QuadPart = (LONGLONG)(state->Npt.Limit - 1);
    /* VMCB12 and virtual HSAVE are adjacent only for the bounded assembly probe. */
    nested->Operand = MmAllocateContiguousMemory(8192, highest);
    /* Independent merged maps ensure L1 cannot weaken or overwrite L0's maps. */
    nested->MergedMaps = MmAllocateContiguousMemory(KSW_NSVM_MSRPM_BYTES + KSW_NSVM_IOPM_BYTES, highest);
    /* The inner test has a full private kernel-sized stack. */
    nested->Stack = KswordARKAllocateNonPagedPool(KSW_SVM_STACK_BYTES, 'pSvK');
    /* Leave acquired pointers in the release ledger. */
    if (!nested->Operand || !nested->MergedMaps || !nested->Stack) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* Resolve the entire combined allocation before entering the exit loop. */
    nested->MergedMapsPa = (ULONGLONG)MmGetPhysicalAddress(nested->MergedMaps).QuadPart;
    /* Hardware requires page alignment even though guest permission bases ignore low bits. */
    if ((nested->MergedMapsPa & 4095ULL) ||
        !KswSvmNestedMapAddress(nested->MergedMapsPa, KSW_NSVM_MSRPM_BYTES, Cpu->Caps.PhysicalBits, &mapBase) ||
        !KswSvmNestedMapAddress(nested->MergedMapsPa + KSW_NSVM_MSRPM_BYTES,
            KSW_NSVM_IOPM_BYTES, Cpu->Caps.PhysicalBits, &mapBase)) { return STATUS_DATA_ERROR; }
    /* Resolve the operand identity only at PASSIVE_LEVEL. */
    nested->OperandPa = (ULONGLONG)MmGetPhysicalAddress(nested->Operand).QuadPart;
    /* Every shadow table must be independently aligned/physically contiguous. */
    for (page = 0; page < KSW_NSVM_PROBE_PAGES; ++page) {
        /* Keep each allocation in the ledger before deriving its address. */
        nested->Pages[page].Words = MmAllocateContiguousMemory(4096, highest);
        /* A partial pool cannot admit nested execution. */
        if (!nested->Pages[page].Words) { return STATUS_INSUFFICIENT_RESOURCES; }
        /* Pre-resolve every hardware pointer used by the exit handler. */
        nested->Pages[page].Physical = (ULONGLONG)MmGetPhysicalAddress(nested->Pages[page].Words).QuadPart;
    }
    /* The portable builder validates alignment, duplicate ownership and address width. */
    if (KswSvmNestedShadowInitialize(&nested->Shadow, nested->Pages, KSW_NSVM_PROBE_PAGES,
        Cpu->Caps.PhysicalBits) != KSW_NSHADOW_OK) { return STATUS_DATA_ERROR; }
    /* No SVM instruction has executed yet. */
    return STATUS_SUCCESS;
}
