#pragma once
#include "ArkDriverClient.h"
#include "../../../shared/driver/KswordArkPfnIoctl.h"
#include <array>

namespace ksword::ark {
// This collector's imported native layouts and PFN units are explicitly
// x64/4 KiB. An emulated x64 process does not establish the native kernel ABI.
constexpr bool pfnNativeLayoutSupported(unsigned short architecture, unsigned long systemPageBytes)
{
    return sizeof(void*) == 8 && architecture == PROCESSOR_ARCHITECTURE_AMD64 && systemPageBytes == 4096;
}
// Passive provenance for the most recent public PFN operation. Both paths call
// the same Memory Manager Superfetch provider; this is not independent evidence.
struct PfnNativeAttempt {
    unsigned long informationClass = 0, abiVersion = 0;
    long status = 0;
    bool invoked = false;
};
struct PfnQueryTrace {
    std::array<PfnNativeAttempt, 2> nativeAttempts{};
    unsigned nativeAttemptCount = 0;
    unsigned long driverOperation = 0;
    long driverStatus = 0, driverTransportStatus = 0;
    bool driverAvailable = false, driverInvoked = false;
};
enum class PfnBackend { Auto, NativeOnly, DriverOnly };
// Native query first; the driver supplies the same bounded identity ABI when
// Windows denies the user-mode query. A thread-local token is restored on exit.
class PfnQueryClient final {
public:
    explicit PfnQueryClient(PfnBackend backend = PfnBackend::Auto);
    ~PfnQueryClient();
    PfnQueryClient(const PfnQueryClient&) = delete;
    PfnQueryClient& operator=(const PfnQueryClient&) = delete;
    long ranges(std::vector<KSWORD_ARK_PFN_RANGE>& result);
    long owners(std::vector<KSWORD_ARK_PFN_OWNER>& result);
    long pages(std::uint64_t first, std::uint32_t count, std::vector<KSWORD_ARK_PFN_IDENTITY>& result);
    long identities(const std::vector<std::uint64_t>& pfns, std::vector<KSWORD_ARK_PFN_IDENTITY>& result);
    bool mappingAvailable();
    long mappings(std::uint32_t pid, std::uint64_t created, const std::vector<std::uint64_t>& addresses,
        std::vector<KSWORD_ARK_PFN_MAPPING>& result);
    std::uint64_t nativeBatches = 0;
    std::uint64_t driverBatches = 0;
    const PfnQueryTrace& lastTrace() const { return m_trace; }
private:
    long nativeQuery(unsigned long kind, void* buffer, unsigned long bytes) const;
    long driverQuery(unsigned long kind, std::uint64_t first, std::uint32_t count,
        void* records, unsigned long capacity, unsigned long stride, unsigned long& returned,
        const std::vector<std::uint64_t>* pfns = nullptr);
    DriverClient m_client;
    DriverHandle m_driver;
    HANDLE m_previousToken = nullptr;
    bool m_impersonating = false;
    bool m_driverPages = false;
    bool m_nativeLayoutSupported = false;
    PfnBackend m_backend = PfnBackend::Auto;
    mutable PfnQueryTrace m_trace;
};
}
