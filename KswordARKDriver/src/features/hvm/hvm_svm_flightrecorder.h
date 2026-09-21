/* Passive observations only; the caller supplies owned VMCBs and serializes publication. */
#pragma once
#include "hvm_svm_arch.h"
#include "../../../../shared/driver/KswordArkHvmFlightRecorder.h"
void KswSvmFlightRecord(KSWORD_HVM_FLIGHT_RECORDER* Flight, const KSW_SVM_VMCB* Current,
    unsigned Kind, unsigned Phase, unsigned Action, unsigned Generation,
    KSW_SVM_U64 Tsc, KSW_SVM_U64 OperandPa, KSW_SVM_U64 LeaseToken);
void KswSvmFlightLatch(KSWORD_HVM_FLIGHT_RECORDER* Flight, const KSW_SVM_VMCB* Current,
    const KSW_SVM_VMCB* Vmcb12, unsigned Reason, unsigned Timing);
