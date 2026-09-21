/* Exercise the actual production recorder without issuing any SVM instruction. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_flightrecorder.h"
static KSWORD_HVM_FLIGHT_RECORDER flight, frozen;
static KSW_SVM_VMCB current, operand;
int main(void)
{
    unsigned i;
    assert(sizeof(current) == KSW_HVM_FLIGHT_PAGE_BYTES);
    assert(sizeof(KSWORD_HVM_FLIGHT_ROW) == 128);
    memset(&operand, 0x5a, sizeof(operand));
    for (i = 0; i < 100; ++i) {
        KswSvmWrite64(&current, KSW_VMCB_RIP, 0xffff800000000000ULL + i);
        KswSvmWrite64(&current, KSW_VMCB_EXITCODE, 0x400);
        KswSvmFlightRecord(&flight, &current, KSW_HVM_FLIGHT_EXIT, 1, 0, 11, i, 0x12345000, 7);
    }
    assert(!flight.latched && flight.count == 32 && flight.next == 4 && flight.total == 100);
    assert(flight.rows[flight.next].ordinal == 69);
    KswSvmWrite64(&current, KSW_VMCB_EXITCODE, 0x7f);
    KswSvmWrite64(&current, KSW_VMCB_EXITINFO1, 0xfedcba9876543210ULL);
    KswSvmFlightRecord(&flight, &current, KSW_HVM_FLIGHT_EXIT, 1, 0, 11, 100, 0x12345000, 7);
    KswSvmFlightLatch(&flight, &current, &operand, KSW_HVM_FLIGHT_SHUTDOWN, 1);
    assert(flight.latched && flight.vmcb12Valid && flight.reason == KSW_HVM_FLIGHT_SHUTDOWN);
    assert(!memcmp(flight.currentVmcb, &current, sizeof(current)));
    assert(!memcmp(flight.vmcb12, &operand, sizeof(operand)));
    frozen = flight;
    memset(&current, 0xcc, sizeof(current));
    for (i = 0; i < 1000; ++i) {
        KswSvmFlightRecord(&flight, &current, KSW_HVM_FLIGHT_ENTRY, 0, 5, 12, i, 0, 0);
        KswSvmFlightLatch(&flight, &current, NULL, KSW_HVM_FLIGHT_INTERNAL, 2);
    }
    assert(!memcmp(&flight, &frozen, sizeof(flight)));
    memset(&flight, 0, sizeof(flight));
    KswSvmFlightLatch(&flight, &current, NULL, KSW_HVM_FLIGHT_INTERNAL, 2);
    assert(flight.latched && !flight.vmcb12Valid && flight.captureTiming == 2);
    for (i = 0; i < sizeof(flight.vmcb12); ++i) { assert(!flight.vmcb12[i]); }
    memset(&flight, 0, sizeof(flight));
    KswSvmFlightLatch(&flight, NULL, &operand, KSW_HVM_FLIGHT_INVALID, 1);
    assert(!flight.latched);
    flight.total = ~0ULL;
    KswSvmFlightRecord(&flight, &current, KSW_HVM_FLIGHT_EXIT, 1, 0, 13, 0, 0, 0);
    assert(flight.total == ~0ULL && flight.count == 1);
    puts("PASS flight recorder: wrap, terminal pages, first-wins, stop activity, missing operand, saturation");
    return 0;
}
