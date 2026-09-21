/* Exercise the production formatter without opening a device or executing IOCTLs. */
#include <windows.h>
#include <string.h>
#include "../../shared/driver/KswordArkHvmIoctl.h"
#include "../../shared/driver/KswordArkHvmMetricsIoctl.h"

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
        cpu->general.exitCode = 0xFEDCBA9876543210ULL;
        *returned = sizeof(*metrics);
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
    if (argc > 1 && strcmp(argv[1], "metrics") == 0) { return DoMetrics(NULL, 1); }
    if (argc == 1 || strcmp(argv[1], "strings") != 0) { return DoQuery(NULL, 1); }
    KswordHvmPrintJsonString("没有拒绝过\"\\\n\t\xf0\x9f\x98\x80");
    putchar('\n');
    KswordHvmPrintJsonString("\xff\xe8");
    putchar('\n');
    return 0;
}
