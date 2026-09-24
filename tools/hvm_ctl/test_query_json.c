/* Exercise the production formatter without opening a device or executing IOCTLs. */
#include <windows.h>
#include <string.h>
#include "../../shared/driver/KswordArkHvmIoctl.h"
#include "../../shared/driver/KswordArkHvmMetricsIoctl.h"
static unsigned metricsFailure;

static BOOL WINAPI FakeDeviceIoControl(HANDLE device, DWORD code, LPVOID input,
    DWORD inputSize, LPVOID output, DWORD outputSize, LPDWORD returned,
    LPOVERLAPPED overlapped)
{
    KSWORD_ARK_QUERY_HVM_RESPONSE* response = (KSWORD_ARK_QUERY_HVM_RESPONSE*)output;
    (void)device; (void)code; (void)input; (void)inputSize; (void)overlapped;
    if (code == IOCTL_KSWORD_ARK_HVM_METRICS) {
        KSWORD_ARK_HVM_METRICS_RESPONSE* metrics = (KSWORD_ARK_HVM_METRICS_RESPONSE*)output;
        KSWORD_ARK_HVM_SVM_METRICS* cpu;
        if (outputSize != sizeof(*metrics)) { return FALSE; }
        memset(metrics, 0, sizeof(*metrics));
        metrics->version = KSWORD_ARK_HVM_METRICS_VERSION;
        if (metricsFailure == 1) { metrics->version = 7; }
        metrics->size = sizeof(*metrics);
        metrics->backend = 2;
        metrics->svmProcessorCount = 1;
        metrics->qpcFrequency = 10000000;
        cpu = &metrics->svmProcessors[0];
        cpu->nestedProbeValid = 1;
        cpu->nestedProbeSequence = 2;
        cpu->nestedProbeEntries = 1;
        cpu->nestedProbeReflections = 1;
        cpu->nestedProbeFaults = 7;
        cpu->nestedProbeExit = 0xFEDCBA9876543210ULL;
        cpu->nestedProbeMarker = 0x4B534E31ULL;
        cpu->general.valid = 1;
        cpu->general.sequence = 0x100000002ULL;
        cpu->general.preparedEntries = 13;
        cpu->general.hardwareExits = 12;
        cpu->general.nptCache.lookups = 0x100000010ULL;
        cpu->general.nptCache.hits = 0x10000000aULL;
        cpu->general.nptCache.resets = 5;
        cpu->general.nptCache.resetFailures = 1;
        cpu->general.nptCache.reasons[KSW_HVM_NPT_CACHE_OWNER] = 4;
        cpu->general.nptCache.reasons[KSW_HVM_NPT_CACHE_KEY_BASE + 4] = 2;
        cpu->general.nptCache.lastMissMask = (1U << KSW_HVM_NPT_CACHE_OWNER);
        cpu->general.invlpgaCount = 8; cpu->general.shadowEpoch = 0x100000003ULL;
        cpu->general.exitCode = 0xFEDCBA9876543210ULL;
        cpu->hotspots.valid = 1;
        cpu->hotspots.sequence = 0x100000002ULL;
        cpu->hotspots.levels[0].msrUsed = 1;
        cpu->hotspots.levels[0].msrs[0].number = 0xc0000080UL;
        cpu->hotspots.levels[0].msrs[0].reads = 0x100000003ULL;
        cpu->hotspots.levels[1].npf = 99;
        cpu->flight.coherent = 1;
        cpu->flight.latched = 1;
        cpu->flight.reason = 1;
        cpu->flight.captureTiming = 1;
        cpu->flight.vmcb12Valid = 1;
        cpu->flight.total = 0x100000003ULL;
        cpu->flight.count = 2;
        cpu->flight.next = 1;
        cpu->flight.rows[31].ordinal = 0x100000002ULL;
        cpu->flight.rows[0].ordinal = 0x100000003ULL;
        cpu->flight.rows[0].exitCode = 0xFEDCBA9876543210ULL;
        cpu->flight.vmcb12[4095] = 0xA5;
        cpu->flight.currentVmcb[0] = 0x5A;
        *returned = sizeof(*metrics);
        if (metricsFailure == 2) { *returned -= 8; }
        return TRUE;
    }
    if (outputSize != sizeof(*response)) { return FALSE; }
    memset(response, 0, sizeof(*response));
    response->backend = 2;
    response->slatType = 2;
    response->svmCapabilities.asidCount = 64;
    response->svmCapabilities.rejectReason = KSWORD_ARK_SVM_REJECT_CR4;
    response->svmCapabilities.stateValidMask = 31;
    response->svmCapabilities.cpuid1Ecx = 0x0C000000;
    response->svmCapabilities.xsaveFeatures = 8;
    response->svmCapabilities.cr4 = 0x800000;
    response->svmCapabilities.xcr0 = 7;
    response->svmCapabilities.xss = 0x800;
    *returned = sizeof(*response);
    return TRUE;
}

#include "HvmCommandCatalog.c"
#define DeviceIoControl FakeDeviceIoControl
#include "HvmCommandEngine.c"
#undef DeviceIoControl

int main(int argc, char** argv)
{
    if (argc == 2 && strcmp(argv[1], "metrics-old") == 0) { metricsFailure = 1; return DoMetrics(NULL, 1); }
    if (argc == 2 && strcmp(argv[1], "metrics-short") == 0) { metricsFailure = 2; return DoMetrics(NULL, 1); }
    if (argc == 3 && strcmp(argv[1], "--json") == 0) {
        if (strcmp(argv[2], "metrics") == 0) { return DoMetrics(NULL, 1); }
        if (strcmp(argv[2], "status") == 0) { return DoQuery(NULL, 1); }
        return 2;
    }
    if (argc > 1 && strcmp(argv[1], "metrics") == 0) { return DoMetrics(NULL, 1); }
    if (argc == 1 || strcmp(argv[1], "strings") != 0) { return DoQuery(NULL, 1); }
    KswordHvmPrintJsonString("没有拒绝过\"\\\n\t\xf0\x9f\x98\x80");
    putchar('\n');
    KswordHvmPrintJsonString("\xff\xe8");
    putchar('\n');
    return 0;
}
