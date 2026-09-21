/* The private IDT is prepared from trusted host state, never an L1/L2 operand. */
#include "hvm_svm_nmi.h"

/* Explicit byte stores avoid packed, unaligned integer member accesses. */
static void KswSvmNmiStore(unsigned char* Bytes, KSW_SVM_U64 Value, unsigned Size)
{
    /* Size is a compile-time bounded hardware field width at every call site. */
    unsigned index;
    /* AMD descriptor registers and gates use little-endian byte order. */
    for (index = 0; index < Size; ++index) { Bytes[index] = (unsigned char)(Value >> (index * 8)); }
}

/* Initialization is processor-pinned and the source must remain a trusted root descriptor. */
int KswordSvmNmiInitialize(KSW_SVM_NMI_CAPTURE* Capture, const unsigned char* TrustedIdtr,
    unsigned short CodeSelector)
{
    /* IDTR layout is a two-byte limit followed by an eight-byte base. */
    KSW_SVM_U64 base = 0, handler;
    /* Preserve all other host exception gates while replacing the temporary NMI gate. */
    unsigned limit, index;
    /* A live acknowledgement window must never have its IDT or counter reinitialized. */
    if (!Capture || !TrustedIdtr || Capture->Armed || !CodeSelector || (CodeSelector & 7U)) { return 0; }
    /* Reject partial tables before reading the vector-two entry. */
    limit = (unsigned)TrustedIdtr[0] | ((unsigned)TrustedIdtr[1] << 8);
    /* Only the architectural 256-entry long-mode table is representable. */
    if (limit < 47 || limit > 4095) { return 0; }
    /* Decode the trusted address without aliasing an unaligned pointer. */
    for (index = 0; index < 8; ++index) { base |= (KSW_SVM_U64)TrustedIdtr[index + 2] << (index * 8); }
    /* Host execution is four-level, 64-bit kernel mode; null/user/wrapping tables are invalid. */
    if (base < 0xffff800000000000ULL || base > ~0ULL - limit) { return 0; }
    /* Clear readiness before mutating any table byte. */
    Capture->Ready = 0; Capture->Count = 0;
    /* Copy only the trusted table's actual limit, never the unverified remainder of its page. */
    for (index = 0; index <= limit; ++index) { Capture->Table[index] = ((const unsigned char*)(size_t)base)[index]; }
    /* Reserved/padding bytes are deterministic and cannot leak old allocation data. */
    for (index = limit + 1; index < sizeof(Capture->Table); ++index) { Capture->Table[index] = 0; }
    /* Both descriptors are private; hardware never writes them. */
    for (index = 0; index < 16; ++index) { Capture->OriginalIdtr[index] = Capture->CaptureIdtr[index] = 0; }
    /* Preserve the exact identity to recheck immediately before the acknowledgement window. */
    for (index = 0; index < 10; ++index) { Capture->OriginalIdtr[index] = TrustedIdtr[index]; }
    /* The temporary table has the same valid vector range as the original. */
    KswSvmNmiStore(Capture->CaptureIdtr, limit, 2);
    /* This owned nonpageable buffer must remain allocated until all CPUs are native. */
    KswSvmNmiStore(Capture->CaptureIdtr + 2, (KSW_SVM_U64)(size_t)Capture->Table, 8);
    /* Use current kernel CS and the existing private host stack, never guest IST/GDT state. */
    handler = (KSW_SVM_U64)(size_t)KswordSvmAsmCaptureNmi;
    /* Gate low offset and trusted code selector. */
    KswSvmNmiStore(Capture->Table + 32, handler & 0xffffULL, 2);
    /* RPL=0, GDT selector was checked above. */
    KswSvmNmiStore(Capture->Table + 34, CodeSelector, 2);
    /* IST=0 avoids using the interrupted Windows thread's NMI stack for this leaf. */
    Capture->Table[36] = 0; Capture->Table[37] = 0x8e;
    /* Complete the canonical 64-bit leaf address. */
    KswSvmNmiStore(Capture->Table + 38, (handler >> 16) & 0xffffULL, 2);
    /* Long-mode gates have a separate high offset dword. */
    KswSvmNmiStore(Capture->Table + 40, handler >> 32, 4);
    /* Reserved gate dword must be zero. */
    KswSvmNmiStore(Capture->Table + 44, 0, 4);
    /* Caller publishes this CPU's prepared resource only after initialization returns. */
    Capture->Ready = 1; return 1;
}
