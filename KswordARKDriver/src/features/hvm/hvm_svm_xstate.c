/* XSETBV admission never expands the nonpaged save area after prepare. */
#include "hvm_svm_xstate.h"

/* Reject combinations which hardware would fault on before assembly executes XSETBV. */
int KswSvmXcr0MaskValid(KSW_SVM_U64 Mask)
{
    /* x87 must stay enabled; unknown components need their own dependencies and storage. */
    if (!(Mask & 1ULL) || (Mask & ~KSW_SVM_XCR0_IMPLEMENTED)) { return 0; }
    /* AVX state requires SSE state. */
    if ((Mask & 4ULL) && !(Mask & 2ULL)) { return 0; }
    /* Opmask, ZMM_Hi256 and Hi16_ZMM form one group and require AVX/SSE. */
    if ((Mask & 0xe0ULL) && ((Mask & 0xe0ULL) != 0xe0ULL || (Mask & 6ULL) != 6ULL)) { return 0; }
    /* The supported subset is now safe to use with a preallocated fixed save mask. */
    return 1;
}

/* Caller preserves the faulting RIP for any nonzero result. */
unsigned KswSvmXcr0Write(KSW_SVM_U64 Prepared, KSW_SVM_U64 Cr4, unsigned Cpl,
    unsigned Index, KSW_SVM_U64 Value, KSW_SVM_U64* Current)
{
    /* Invalid monitor policy is not an architectural guest fault. */
    if (!Current || !KswSvmXcr0MaskValid(Prepared)) { return KSW_SVM_XCR_UNSUPPORTED; }
    /* Without CR4.OSXSAVE the instruction is unavailable even at CPL0. */
    if (!(Cr4 & (1ULL << 18))) { return KSW_SVM_XCR_UD; }
    /* Only ring zero may write the only implemented extended control register. */
    if (Cpl || Index) { return KSW_SVM_XCR_GP; }
    /* Prepared components are the storage ceiling, not all host CPUID-supported components. */
    if ((Value & ~Prepared) || !KswSvmXcr0MaskValid(Value)) { return KSW_SVM_XCR_GP; }
    /* Hardware switching occurs in assembly only after root C has finished. */
    *Current = Value;
    /* No allocation, CPUID, MSR write or SIMD state mutation occurs here. */
    return KSW_SVM_XCR_OK;
}

/* Only CET_U is part of the existing supervisor save/restore implementation. */
unsigned KswSvmXssWrite(KSW_SVM_U64 Prepared, unsigned Features, unsigned Cpl,
    KSW_SVM_U64 Value, KSW_SVM_U64* Current)
{
    /* Other XSS components require their own host-state and restore support. */
    if (!Current || (Prepared & ~(1ULL << 11))) { return KSW_SVM_XCR_UNSUPPORTED; }
    /* Unimplemented MSR access, privilege violation or unallocated components raise #GP. */
    if (!(Features & 8U) || Cpl || (Value & ~Prepared)) { return KSW_SVM_XCR_GP; }
    /* Assembly switches the real register after C completes, preserving the root save format. */
    *Current = Value;
    /* Zero is legal; it does not disable CET controls or erase their current contents. */
    return KSW_SVM_XCR_OK;
}

/* Compute standard or compacted size with bounded arithmetic over captured geometry. */
static unsigned KswSvmXstateSize(const KSW_SVM_XSTATE_LAYOUT* Layout, KSW_SVM_U64 Mask, unsigned Compact)
{
    /* Legacy x87/SSE area plus the architectural XSAVE header. */
    unsigned size = 576, bit;
    /* Components zero and one always reside in the fixed legacy area. */
    for (bit = 2; bit < 64; ++bit) {
        /* Disabled components do not contribute to current virtual allocation size. */
        if (Mask & (1ULL << bit)) {
            /* Captured sizes have already been bounded to the backend's 64-KiB ceiling. */
            unsigned bytes = Layout->Component[bit][0], offset;
            /* Supervisor components use compacted layout only. */
            if (!Compact && (Layout->Component[bit][2] & 1U)) { return 0; }
            /* Compact alignment is a per-component architectural property. */
            offset = Compact ? ((Layout->Component[bit][2] & 2U) ? (size + 63U) & ~63U : size) : Layout->Component[bit][1];
            /* A zero or overflowing component is missing evidence, never an empty component. */
            if (!bytes || offset > 65536U || bytes > 65536U - offset) { return 0; }
            /* Standard components may have gaps; compact components are packed in bit order. */
            if (offset + bytes > size) { size = offset + bytes; }
        }
    }
    /* All arithmetic has stayed within the allocated architectural bound. */
    return size;
}

/* PASSIVE/pinned collection; the portable callback allows later offline geometry fixtures. */
int KswSvmXstateLayoutCapture(KSW_SVM_XSTATE_LAYOUT* Layout, KSW_SVM_U64 User,
    KSW_SVM_U64 Supervisor, unsigned Capacity, unsigned Compacted,
    KSW_SVM_CPUID_READ Read, void* Context)
{
    /* Failures leave no usable published layout even after an earlier successful capture. */
    unsigned r[4], bit, other, size;
    /* Caller owns fixed storage; this routine never allocates. */
    if (!Layout) { return 0; }
    /* Consumers require this final publication flag. */
    Layout->Ready = 0;
    /* This virtual CPU contract matches the admitted state management implementation. */
    if (!Read || !KswSvmXcr0MaskValid(User) || (Supervisor & ~(1ULL << 11)) ||
        Capacity < 576 || Capacity > 65536 || Compacted > 1 || (Supervisor && !Compacted)) { return 0; }
    /* CPUID evidence must contain every prepared user bit. */
    Read(Context, 0xd, 0, r);
    /* EDX:EAX enumerates XCR0-supported components. */
    if (User & ~(((KSW_SVM_U64)r[3] << 32) | r[0])) { return 0; }
    /* Supervisor enumeration is independent of the user bitmap. */
    Read(Context, 0xd, 1, r);
    /* Never emulate a save instruction family absent from the underlying CPU. */
    Layout->Features = r[0] & 0xfU;
    /* EDX:ECX enumerates XSS components, and XSAVES is mandatory when XSS is nonzero. */
    if ((Supervisor && !(r[0] & 8U)) || (Compacted && !(r[0] & 8U)) ||
        (Supervisor & ~(((KSW_SVM_U64)r[3] << 32) | r[2]))) { return 0; }
    /* Retain only prepared components, irrespective of wider physical enumeration. */
    Layout->User = User; Layout->Supervisor = Supervisor;
    /* Copy supported extended-component descriptors without root-time CPUID calls. */
    for (bit = 2; bit < 64; ++bit) {
        /* Absent components are not exposed by the virtual CPUID operation below. */
        if (!((User | Supervisor) & (1ULL << bit))) { continue; }
        /* The current processor supplies the standard offset and compact-alignment property. */
        Read(Context, 0xd, bit, Layout->Component[bit]);
        /* Only known supervisor/alignment flags are admitted; reserved output stays zero. */
        if (!Layout->Component[bit][0] || Layout->Component[bit][0] > 65536 ||
            (Layout->Component[bit][2] & ~3U) || Layout->Component[bit][3] ||
            ((Layout->Component[bit][2] & 1U) != ((Supervisor & (1ULL << bit)) ? 1U : 0U))) { return 0; }
        /* Standard user components may not overlap the header or another user's storage. */
        if (User & (1ULL << bit)) {
            /* Validate before addition; hardware/outer hypervisor CPUID is still input evidence. */
            unsigned start = Layout->Component[bit][1], bytes = Layout->Component[bit][0];
            /* Fixed legacy state and the header must remain intact. */
            if (start < 576 || start > 65536 || bytes > 65536 - start) { return 0; }
            /* Compare only descriptors already captured in this pass. */
            for (other = 2; other < bit; ++other) {
                /* Unsupported or supervisor-managed records have no standard user extent. */
                if (!(User & (1ULL << other))) { continue; }
                /* Non-overlap is required even if the active root uses compacted saves. */
                if (start < Layout->Component[other][1] + Layout->Component[other][0] &&
                    Layout->Component[other][1] < start + bytes) { return 0; }
            }
        }
    }
    /* Check exactly the fixed full-mask format used by the root assembly. */
    size = KswSvmXstateSize(Layout, User | (Compacted ? Supervisor : 0), Compacted);
    /* No future guest transition can increase this admitted allocation ceiling. */
    if (!size || size > Capacity) { return 0; }
    /* Publication is CPU-local during prepare; no executing CPU can yet consume this image. */
    Layout->Ready = 1;
    /* The descriptor is now usable without any privileged operation. */
    return 1;
}

/* Current enablement, not root CPUID side effects, determines the guest-reported sizes. */
int KswSvmXstateCpuid(const KSW_SVM_XSTATE_LAYOUT* Layout, KSW_SVM_U64 Xcr0,
    KSW_SVM_U64 Xss, unsigned Subleaf, unsigned Words[4])
{
    /* Never return stale host register values on unsupported subleafs. */
    unsigned i;
    /* The output is optional only on a rejected call. */
    if (!Words) { return 0; }
    /* Architectural unsupported subleafs read as zero. */
    for (i = 0; i < 4; ++i) { Words[i] = 0; }
    /* Invalid software masks cannot make CPUID advertise an unsafe save area. */
    if (!Layout || !Layout->Ready || !KswSvmXcr0MaskValid(Xcr0) ||
        (Xcr0 & ~Layout->User) || (Xss & ~Layout->Supervisor)) { return 0; }
    /* Base leaf reports current standard size and maximum supported standard size separately. */
    if (Subleaf == 0) {
        /* Preserve the architectural 64-bit user-component bitmap. */
        Words[0] = (unsigned)Layout->User; Words[3] = (unsigned)(Layout->User >> 32);
        /* XSS is excluded from the standard XSAVE area. */
        Words[1] = KswSvmXstateSize(Layout, Xcr0, 0); Words[2] = KswSvmXstateSize(Layout, Layout->User, 0);
        /* Missing geometry is a monitor failure, not a zero-sized guest buffer. */
        return Words[1] != 0 && Words[2] != 0;
    }
    /* Extended leaf reports implemented save families and current compacted size. */
    if (Subleaf == 1) {
        /* Keep hardware instruction-family support independent of currently enabled components. */
        Words[0] = Layout->Features;
        /* EBX is meaningful with XSAVEC or XSAVES support. */
        if (Layout->Features & 0xaU) { Words[1] = KswSvmXstateSize(Layout, Xcr0 | Xss, 1); }
        /* The supervisor support bitmap is not replaced by the current XSS value. */
        Words[2] = (unsigned)Layout->Supervisor; Words[3] = (unsigned)(Layout->Supervisor >> 32);
        /* Size arithmetic was validated at capture and only subsets are accepted. */
        return !(Layout->Features & 0xaU) || Words[1] != 0;
    }
    /* Out-of-range shifts must not wrap and expose unrelated CPUID component metadata. */
    if (Subleaf < 64 && ((Layout->User | Layout->Supervisor) & (1ULL << Subleaf))) {
        /* Layout offsets are hardware ABI, not guest-mask-dependent compacted offsets. */
        for (i = 0; i < 4; ++i) { Words[i] = Layout->Component[Subleaf][i]; }
    }
    /* Unsupported component subleafs return the zeroed record above. */
    return 1;
}
