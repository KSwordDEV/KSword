/* AMD APM volume 2, SVM control/save area encodings; no Windows dependencies. */
#pragma once
#include <stddef.h>

/* Keep architectural widths independent of the compiler's long model. */
typedef unsigned long long KSW_SVM_U64;
/* VMCB segment records are exactly sixteen bytes. */
typedef struct _KSW_SVM_SEGMENT {
    /* Architectural selector. */
    unsigned short selector;
    /* AMD attributes, not Intel VMCS access-right encoding. */
    unsigned short attributes;
    /* Expanded segment limit. */
    unsigned int limit;
    /* Linear segment/table base. */
    KSW_SVM_U64 base;
} KSW_SVM_SEGMENT;

/* Byte-addressed hardware page avoids implementation-defined C bit fields. */
typedef struct _KSW_SVM_VMCB {
    /* Control area occupies offsets 000h..3ffh. */
    unsigned char control[0x400];
    /* Save area and architecturally reserved tail fill one page. */
    unsigned char state[0xc00];
} KSW_SVM_VMCB;
/* Fail compilation if a host/compiler changes either hardware layout. */
typedef char KSW_SVM_ASSERT_PAGE[(sizeof(KSW_SVM_VMCB) == 4096) ? 1 : -1];
/* Assert the state-area anchor used by assembly. */
typedef char KSW_SVM_ASSERT_STATE[(offsetof(KSW_SVM_VMCB, state) == 0x400) ? 1 : -1];
/* Assert the descriptor encoding size. */
typedef char KSW_SVM_ASSERT_SEGMENT[(sizeof(KSW_SVM_SEGMENT) == 16) ? 1 : -1];

/* EFER controls availability of SVM instructions. */
#define KSW_SVM_MSR_EFER 0xc0000080U
/* Firmware SVM configuration is never modified. */
#define KSW_SVM_MSR_VM_CR 0xc0010114U
/* Per-processor host state-save ownership. */
#define KSW_SVM_MSR_HSAVE 0xc0010117U
/* CET supervisor controls are separate from the XSS-managed user state. */
#define KSW_SVM_MSR_S_CET 0x6a2U
/* Interrupt shadow-stack table is switched by VMRUN, not XSAVES. */
#define KSW_SVM_MSR_ISST 0x6a8U
/* Only the user CET supervisor-state component is supported in this revision. */
#define KSW_SVM_XSS_CET_U (1ULL << 11)
/* Other CR4 extensions still lack a complete native-return contract. */
#define KSW_SVM_UNSUPPORTED_CR4 ((1ULL << 12) | (1ULL << 24) | (1ULL << 25))
/* The only EFER bit owned by this backend. */
#define KSW_SVM_EFER_SVME (1ULL << 12)
/* CPUID exit. */
#define KSW_SVM_EXIT_CPUID 0x72ULL
/* INVLPGA is a miscellaneous-vector-1 exit; 86h belongs to SKINIT. */
#define KSW_SVM_EXIT_INVLPGA 0x7aULL
/* Secure-init is never implemented by the nested backend. */
#define KSW_SVM_EXIT_SKINIT 0x86ULL
/* MSR exit; EXITINFO1 distinguishes read/write. */
#define KSW_SVM_EXIT_MSR 0x7cULL
/* First SVM instruction exit. */
#define KSW_SVM_EXIT_VMRUN 0x80ULL
/* Private hypercall exit. */
#define KSW_SVM_EXIT_VMMCALL 0x81ULL
/* Nested page fault exit. */
#define KSW_SVM_EXIT_NPF 0x400ULL
/* VMRUN rejects an invalid control/save image with this raw value. */
#define KSW_SVM_EXIT_INVALID (~0ULL)
/* Private stop/query signature, checked together with CPL and instruction. */
#define KSW_SVM_CALL_SIGNATURE 0x4b535753564d3031ULL
/* STOP hypercall operation. */
#define KSW_SVM_CALL_STOP 1ULL
/* QUERY hypercall operation. */
#define KSW_SVM_CALL_QUERY 2ULL
/* Diagnostic self-test CPUID leaf. */
#define KSW_SVM_TEST_LEAF 0x4b535753U

/* Architectural control offsets. */
#define KSW_VMCB_MISC1 0x00cU
#define KSW_VMCB_MISC2 0x010U
#define KSW_VMCB_IOPM 0x040U
#define KSW_VMCB_MSRPM 0x048U
#define KSW_VMCB_ASID 0x058U
#define KSW_VMCB_TLB 0x05cU
#define KSW_VMCB_INTCTL 0x060U
#define KSW_VMCB_EXITCODE 0x070U
#define KSW_VMCB_EXITINFO1 0x078U
#define KSW_VMCB_EXITINFO2 0x080U
#define KSW_VMCB_EXITINTINFO 0x088U
#define KSW_VMCB_NP 0x090U
#define KSW_VMCB_EVENT 0x0a8U
#define KSW_VMCB_NCR3 0x0b0U
#define KSW_VMCB_CLEAN 0x0c0U
#define KSW_VMCB_NRIP 0x0c8U
/* Architectural save-area offsets. */
#define KSW_VMCB_ES 0x400U
#define KSW_VMCB_CS 0x410U
#define KSW_VMCB_SS 0x420U
#define KSW_VMCB_DS 0x430U
#define KSW_VMCB_FS 0x440U
#define KSW_VMCB_GS 0x450U
#define KSW_VMCB_GDTR 0x460U
#define KSW_VMCB_LDTR 0x470U
#define KSW_VMCB_IDTR 0x480U
#define KSW_VMCB_TR 0x490U
#define KSW_VMCB_CPL 0x4cbU
#define KSW_VMCB_EFER 0x4d0U
#define KSW_VMCB_CR4 0x548U
#define KSW_VMCB_CR3 0x550U
#define KSW_VMCB_CR0 0x558U
#define KSW_VMCB_DR7 0x560U
#define KSW_VMCB_DR6 0x568U
#define KSW_VMCB_RFLAGS 0x570U
#define KSW_VMCB_RIP 0x578U
#define KSW_VMCB_RSP 0x5d8U
#define KSW_VMCB_S_CET 0x5e0U
#define KSW_VMCB_SSP 0x5e8U
#define KSW_VMCB_ISST 0x5f0U
#define KSW_VMCB_RAX 0x5f8U
#define KSW_VMCB_STAR 0x600U
#define KSW_VMCB_LSTAR 0x608U
#define KSW_VMCB_CSTAR 0x610U
#define KSW_VMCB_SFMASK 0x618U
#define KSW_VMCB_KERNEL_GS 0x620U
#define KSW_VMCB_SYSENTER_CS 0x628U
#define KSW_VMCB_SYSENTER_ESP 0x630U
#define KSW_VMCB_SYSENTER_EIP 0x638U
#define KSW_VMCB_CR2 0x640U
#define KSW_VMCB_PAT 0x668U
#define KSW_VMCB_DEBUGCTL 0x670U

/* XSAVES handles CET_U; kernel shadow-stack continuations remain unimplemented. */
static __inline unsigned int KswSvmUserCetValid(KSW_SVM_U64 cr4, KSW_SVM_U64 xcr0,
    KSW_SVM_U64 xss, unsigned int xsaveFeatures, unsigned int cetPresent, KSW_SVM_U64 scet)
{
    /* LA57/PKS/UINTR and XCR0-managed CET are outside this save-area contract. */
    if ((cr4 & KSW_SVM_UNSUPPORTED_CR4) || (xcr0 & (3ULL << 11))) { return 0; }
    /* Never execute on a private host stack with supervisor CET enabled. */
    if (scet || (xss & ~KSW_SVM_XSS_CET_U)) { return 0; }
    /* Enabling CR4.CET or CET_U requires enumerated, readable CET registers. */
    if (((cr4 & (1ULL << 23)) || xss) && !cetPresent) { return 0; }
    /* A nonzero XSS requires the compacted XSAVES/XRSTORS instruction family. */
    return !xss || (xsaveFeatures & 8U) != 0;
}

/* Idempotent writes cannot change the prepared cache or XSTATE/return contract. */
static __inline unsigned int KswSvmStateMsrWriteAllowed(unsigned int msr,
    KSW_SVM_U64 value, KSW_SVM_U64 pat, KSW_SVM_U64 xss)
{
    /* PAT retains the NPT cache interpretation. */
    if (msr == 0x277U) { return value == pat; }
    /* XSS cannot add, remove, or reinterpret compacted state components. */
    if (msr == 0xda0U) { return value == xss; }
    /* Supervisor CET must remain disabled for synthetic native returns. */
    return msr == KSW_SVM_MSR_S_CET && value == 0;
}

/* Read aligned architectural words; offsets above are multiples of eight. */
static __inline KSW_SVM_U64 KswSvmRead64(const KSW_SVM_VMCB* v, unsigned int offset)
{
    /* The page remains owned by the current CPU while executing. */
    return *(const KSW_SVM_U64*)((const unsigned char*)v + offset);
}
/* Write architectural words without relying on compiler bitfield layout. */
static __inline void KswSvmWrite64(KSW_SVM_VMCB* v, unsigned int offset, KSW_SVM_U64 value)
{
    /* Every caller uses a documented, aligned VMCB offset. */
    *(KSW_SVM_U64*)((unsigned char*)v + offset) = value;
}
/* Write a control dword such as intercepts or ASID. */
static __inline void KswSvmWrite32(KSW_SVM_VMCB* v, unsigned int offset, unsigned int value)
{
    /* Control dwords must not overwrite the adjacent field. */
    *(unsigned int*)((unsigned char*)v + offset) = value;
}
/* Return MSRPM bit offset, or an invalid sentinel outside the three ranges. */
static __inline unsigned int KswSvmMsrpmBit(unsigned int msr, unsigned int write)
{
    /* Low architectural MSRs occupy the first 2 KiB. */
    if (msr <= 0x1fffU) { return msr * 2U + (write & 1U); }
    /* Long-mode architectural MSRs occupy the second 2 KiB. */
    if (msr >= 0xc0000000U && msr <= 0xc0001fffU) { return 0x4000U + (msr - 0xc0000000U) * 2U + (write & 1U); }
    /* AMD implementation MSRs occupy the third 2 KiB. */
    if (msr >= 0xc0010000U && msr <= 0xc0011fffU) { return 0x8000U + (msr - 0xc0010000U) * 2U + (write & 1U); }
    /* Unrepresented MSRs are architecturally intercepted. */
    return 0xffffffffU;
}
/* NPT leaf base includes alignment and the actual physical-address width. */
static __inline KSW_SVM_U64 KswNptAddressMask(unsigned int bits)
{
    /* This initial four-level backend deliberately excludes >48-bit GPA. */
    return bits >= 32U && bits <= 48U ? ((1ULL << bits) - 1ULL) & ~0xfffULL : 0ULL;
}

/* Pure instruction completion validation shared with host tests. */
static __inline unsigned int KswSvmNextRipValid(KSW_SVM_U64 rip, KSW_SVM_U64 next)
{
    /* No wraparound or zero-length instruction may advance guest execution. */
    return next > rip && next - rip <= 15ULL;
}
/* A rendezvous participant must be present once and reach the required ownership state. */
static __inline unsigned int KswSvmParticipantValid(unsigned int seen, unsigned int active, unsigned int start)
{
    /* Equal totals cannot hide a duplicate or missing processor. */
    return seen == 1U && (active != 0U) == (start != 0U);
}
/* Build AMD leaf flags independently of Intel EPT encodings. */
static __inline KSW_SVM_U64 KswNptLeafFlags(unsigned int level, unsigned int pat)
{
    /* Reject unsupported sizes/cache indices instead of truncating their bits. */
    if (level < 1U || level > 3U || pat > 7U) { return 0ULL; }
    /* AMD Present/RW/US, PWT/PCD, PAT and optional PS. */
    return 7ULL | ((KSW_SVM_U64)(pat & 3U) << 3) |
        ((KSW_SVM_U64)(pat >> 2) << (level == 1U ? 7 : 12)) | (level == 1U ? 0ULL : 0x80ULL);
}

/* Reserve ASID zero and reject an empty/malformed ASID namespace. */
static __inline unsigned int KswSvmAsidValid(unsigned int count, unsigned int asid)
{
    /* The reported count is exclusive, not the highest allocatable ASID. */
    return asid != 0U && asid < count;
}
/* Only the two baseline injected exceptions are supported. */
static __inline KSW_SVM_U64 KswSvmExceptionEvent(unsigned int vector)
{
    /* Preserve reserved bits as zero; #GP carries a valid zero error code. */
    return vector == 6U || vector == 13U ? vector | (3ULL << 8) | (1ULL << 31) | (vector == 13U ? 1ULL << 11 : 0ULL) : 0ULL;
}
/* CPUID emulation hides only the unimplemented inner SVM contract. */
static __inline void KswSvmFilterCpuid(unsigned int leaf, int result[4])
{
    /* Preserve all unrelated extended feature bits. */
    if (leaf == 0x80000001U) { result[2] &= ~4; }
    /* The SVM feature leaf must agree with the hidden SVM feature bit. */
    if (leaf == 0x8000000aU) { result[0] = result[1] = result[2] = result[3] = 0; }
}
