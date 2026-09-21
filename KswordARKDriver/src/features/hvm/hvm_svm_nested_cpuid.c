/* Filter unsupported control/state families before a virtual VMM decides to enable them. */
#include "hvm_svm_nested_cpuid.h"

/* No CPUID query writes host state or reads a guest-controlled physical address. */
int KswSvmNestedCpuid(const KSW_NSVM_CPUID_POLICY* Policy, KSW_SVM_U64 GuestCr4,
    KSW_SVM_U64 GuestXcr0, KSW_SVM_U64 GuestXss, unsigned Leaf, unsigned Subleaf,
    unsigned Words[4])
{
    /* Current enablement and maximum supported state are independent notions. */
    KSW_SVM_U64 user;
    /* Missing descriptors must fail before dereferencing a callback. */
    if (!Policy || !Policy->Xstate || !Policy->Xstate->Ready || !Words) { return 0; }
    /* Public SVM cannot be enabled without the NPT/NRIP prerequisites of the actual backend. */
    if (Policy->ExposeSvm && ((Policy->SvmFeatures & 9U) != 9U || Policy->AsidCount < 2)) { return 0; }
    /* Leaf D sizes must never come from root's temporarily restored enablement. */
    if (Leaf == 0xdU) { return KswSvmXstateCpuid(Policy->Xstate, GuestXcr0, GuestXss, Subleaf, Words); }
    /* Other leafs preserve hardware/outer topology unless a specific unsupported feature is removed. */
    if (!Policy->Read) { return 0; }
    /* The callback executes on the frozen processor, not another worker's affinity. */
    Policy->Read(Policy->Context, Leaf, Subleaf, Words);
    /* Base instruction families may only depend on exposed, preallocated components. */
    user = Policy->Xstate->User;
    /* OSXSAVE is determined by this guest's CR4, not the root execution mode. */
    if (Leaf == 1) {
        /* Clear then derive the single dynamic feature bit. */
        Words[2] &= ~(1U << 27);
        /* XSAVE hardware remains exposed even when the guest has not enabled it yet. */
        if (GuestCr4 & (1ULL << 18)) { Words[2] |= 1U << 27; }
        /* AVX/FMA/F16C must not be advertised when their extended state cannot be enabled. */
        if ((user & 6ULL) != 6ULL) { Words[2] &= ~((1U << 28) | (1U << 12) | (1U << 29)); }
        /* PCID instruction semantics require CR4.PCIDE support in VMCB admission. */
        if (!(Policy->Cr4Supported & (1ULL << 17))) { Words[2] &= ~(1U << 17); }
    }
    /* Baseline structured features are explicit; unsupported future subleafs are hidden. */
    if (Leaf == 7) {
        /* Avoid forwarding new architectural state features for which no save contract exists. */
        if (Subleaf) { Words[0] = Words[1] = Words[2] = Words[3] = 0; return 1; }
        /* No higher structured subleaf is part of this initial virtual contract. */
        Words[0] = 0;
        /* AVX2 needs user SSE and AVX state support. */
        if ((user & 6ULL) != 6ULL) { Words[1] &= ~(1U << 5); }
        /* AVX-512 instruction families require all three additional state components. */
        if ((user & 0xe7ULL) != 0xe7ULL) {
            /* AVX512F/DQ/IFMA/PF/ER/CD/BW/VL. */
            Words[1] &= ~0xdc230000U;
            /* AVX512VBMI/VBMI2/VNNI/BITALG/VPOPCNTDQ. */
            Words[2] &= ~((1U << 1) | (1U << 6) | (1U << 11) | (1U << 12) | (1U << 14));
            /* AVX512_4VNNIW/4FMAPS/VP2INTERSECT/FP16. */
            Words[3] &= ~((1U << 2) | (1U << 3) | (1U << 8) | (1U << 23));
        }
        /* PKU/OSPKE/LA57/PKS need state or paging formats not admitted by this backend. */
        Words[2] &= ~((1U << 3) | (1U << 4) | (1U << 16) | (1U << 31));
        /* UINTR and supervisor CET IBT lack supported root/native continuations. */
        Words[3] &= ~((1U << 5) | (1U << 20));
        /* MPX and AMX need components absent from the prepared virtual XCR0 contract. */
        Words[1] &= ~(1U << 14);
        /* AMX_BF16/TILE/INT8 cannot be exposed with no tile-state save storage. */
        Words[3] &= ~((1U << 22) | (1U << 24) | (1U << 25));
        /* User CET exposure requires its already allocated supervisor save component. */
        if (!(Policy->Xstate->Supervisor & (1ULL << 11))) { Words[2] &= ~(1U << 7); }
        /* Advertise only controls admitted by the virtual CR4 contract. */
        if (!(Policy->Cr4Supported & (1ULL << 16))) { Words[1] &= ~1U; }
        /* SMEP controls supervisor execution protection. */
        if (!(Policy->Cr4Supported & (1ULL << 20))) { Words[1] &= ~(1U << 7); }
        /* SMAP controls supervisor data access. */
        if (!(Policy->Cr4Supported & (1ULL << 21))) { Words[1] &= ~(1U << 20); }
        /* UMIP requires CR4.UMIP to remain a valid guest control bit. */
        if (!(Policy->Cr4Supported & (1ULL << 11))) { Words[2] &= ~(1U << 2); }
    }
    /* The SVM bit is public only for the level whose complete execution backend is enabled. */
    if (Leaf == 0x80000001U) {
        /* Clear raw physical/outer ownership before adding virtual software support. */
        Words[2] &= ~4U;
        /* SVM support is meaningful only with a nonzero usable virtual ASID namespace. */
        if (Policy->ExposeSvm && Policy->AsidCount >= 2) { Words[2] |= 4U; }
        /* AMD's XOP/FMA4 also require AVX-managed upper-vector state. */
        if ((user & 6ULL) != 6ULL) { Words[2] &= ~((1U << 11) | (1U << 16)); }
    }
    /* SVM capability leaf never exposes clean bits, AVIC, VGIF, SEV or an unimplemented extension. */
    if (Leaf == 0x8000000aU) {
        /* A hidden SVM implementation has no usable feature leaf. */
        if (!Policy->ExposeSvm || Policy->AsidCount < 2) { Words[0] = Words[1] = Words[2] = Words[3] = 0; }
        /* All enabled features also require underlying CPU support. */
        else { Words[0] = 1; Words[1] = Policy->AsidCount; Words[2] = 0; Words[3] = Policy->SvmFeatures & KSW_NSVM_CPUID_SVM_FEATURES; }
    }
    /* Nested operand and NPT validation use exactly this virtual physical-width contract. */
    if (Leaf == 0x80000008U) {
        /* Four-level translations admit a forty-eight-bit linear address space. */
        if (Policy->PhysicalBits < 32 || Policy->PhysicalBits > 48) { return 0; }
        /* Preserve unrelated feature registers and clear the guest-physical-width extension field. */
        Words[0] = (Words[0] & 0xff000000U) | (48U << 8) | Policy->PhysicalBits;
    }
    /* Memory encryption is not a virtual feature of this unencrypted NPT implementation. */
    if (Leaf == 0x8000001fU) { Words[0] = Words[1] = Words[2] = Words[3] = 0; }
    /* Hypervisor vendor and topology leaves were preserved by the raw callback. */
    return 1;
}
