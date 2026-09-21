/* Root-only, bounded NMI acknowledgement. Does not invoke Windows interrupt handlers. */
#pragma once
#include "hvm_svm_arch.h"
/* Keep this descriptor independent of Windows packing and MASM structure definitions. */
typedef struct _KSW_SVM_NMI_CAPTURE {
    /* 00/04: assembly records every acknowledgement while the private gate is installed. */
    volatile unsigned Count, Armed;
    /* 08/18: ten-byte IDTR operands reside in sixteen-byte buffers. */
    unsigned char OriginalIdtr[16], CaptureIdtr[16];
    /* 28: ready is published only after the complete private IDT has been populated. */
    unsigned Ready, Reserved;
    /* 30: copied trusted root table, with only vector two replaced. */
    unsigned char Table[4096];
} KSW_SVM_NMI_CAPTURE;
/* Assembly offsets fail at compile time rather than silently corrupting an interrupt table. */
typedef char KSW_NMI_ASSERT_ORIGINAL[(offsetof(KSW_SVM_NMI_CAPTURE, OriginalIdtr) == 8) ? 1 : -1];
typedef char KSW_NMI_ASSERT_CAPTURE[(offsetof(KSW_SVM_NMI_CAPTURE, CaptureIdtr) == 24) ? 1 : -1];
typedef char KSW_NMI_ASSERT_READY[(offsetof(KSW_SVM_NMI_CAPTURE, Ready) == 40) ? 1 : -1];
typedef char KSW_NMI_ASSERT_TABLE[(offsetof(KSW_SVM_NMI_CAPTURE, Table) == 48) ? 1 : -1];
/* TrustedIdtr must describe this CPU's already readable nonpageable Windows root table.
   Call before entering root; no guest-controlled descriptor is accepted here. */
int KswordSvmNmiInitialize(KSW_SVM_NMI_CAPTURE* Capture, const unsigned char* TrustedIdtr,
    unsigned short CodeSelector);
/* Requires SVM root, GIF=0, IF=0, host GS/CR3/XSTATE, private host stack, supervisor CET=0.
   Returns one only for exactly one captured NMI; Count retains all other outcomes.
   Returns with original IDTR restored, GIF=0, IF unchanged (still zero). No Windows C callback. */
unsigned KswordSvmAsmAcknowledgeNmi(KSW_SVM_NMI_CAPTURE* Capture);
/* Only the private, temporarily installed vector-two gate may enter this leaf. */
void KswordSvmAsmCaptureNmi(void);
