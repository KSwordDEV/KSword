#include "ArkDriverPfn.h"
#include "../../../third_party/systeminformer_dyn/PfnNative.h"
#include <algorithm>
#include <cstddef>
#include <cstring>

namespace ksword::ark {
namespace {
constexpr long unsupported = static_cast<long>(0xC00000BBUL);
constexpr long invalidData = static_cast<long>(0xC000003EUL);
static_assert(sizeof(KSW_PF_IDENTITY) == sizeof(KSWORD_ARK_PFN_IDENTITY));
static_assert(offsetof(KSW_PF_QUERY, Pages) == 192);
static_assert(sizeof(KSW_PF_PRIVATE_INFO) == 96);
}

PfnQueryClient::PfnQueryClient(PfnBackend backend) : m_backend(backend)
{
    // Check the native kernel before token changes or either query route.
    // Native/R0 provenance cannot make an unsupported architecture compatible.
    SYSTEM_INFO nativeSystem{};
    GetNativeSystemInfo(&nativeSystem);
    m_nativeLayoutSupported = pfnNativeLayoutSupported(nativeSystem.wProcessorArchitecture, nativeSystem.dwPageSize);
    if (!m_nativeLayoutSupported || m_backend == PfnBackend::DriverOnly) { return; }
    // Enable required privileges on a temporary impersonation token, never on
    // the GUI process token or another worker's token.
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_IMPERSONATE, TRUE, &m_previousToken)
        && GetLastError() != ERROR_NO_TOKEN) { return; }
    if (!ImpersonateSelf(SecurityImpersonation)) { return; }
    m_impersonating = true;
    HANDLE token = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, TRUE, &token)) {
        for (const wchar_t* name : { SE_PROF_SINGLE_PROCESS_NAME, SE_DEBUG_NAME }) {
            TOKEN_PRIVILEGES privileges{};
            privileges.PrivilegeCount = 1;
            if (LookupPrivilegeValueW(nullptr, name, &privileges.Privileges[0].Luid)) {
                privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
            }
        }
        CloseHandle(token);
    }
}

PfnQueryClient::~PfnQueryClient()
{
    if (m_impersonating) {
        if (m_previousToken) { SetThreadToken(nullptr, m_previousToken); }
        else { RevertToSelf(); }
    }
    if (m_previousToken) { CloseHandle(m_previousToken); }
}

long PfnQueryClient::nativeQuery(unsigned long kind, void* buffer, unsigned long bytes) const
{
    using Query = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    const auto query = m_nativeLayoutSupported
        ? reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation")) : nullptr;
    unsigned long abiVersion = 0;
    if (buffer && bytes >= sizeof(abiVersion)) { std::memcpy(&abiVersion, buffer, sizeof(abiVersion)); }
    KSW_PF_SUPERFETCH info{};
    info.Version = 45;
    info.Magic = 0x6B756843;
    info.InfoClass = kind;
    info.Buffer = buffer;
    info.Length = bytes;
    const long status = query ? query(79, &info, sizeof(info), nullptr) : unsupported;
    if (m_trace.nativeAttemptCount < m_trace.nativeAttempts.size()) {
        auto& attempt = m_trace.nativeAttempts[m_trace.nativeAttemptCount++];
        attempt.informationClass = kind;
        attempt.abiVersion = abiVersion;
        attempt.status = status;
        attempt.invoked = query != nullptr;
    }
    return status;
}

long PfnQueryClient::driverQuery(unsigned long kind, std::uint64_t first, std::uint32_t count,
    void* records, unsigned long capacity, unsigned long stride, unsigned long& returned,
    const std::vector<std::uint64_t>* pfns)
{
    returned = 0;
    m_trace.driverOperation = kind;
    auto finish = [&](long status) { m_trace.driverStatus = status; return status; };
    if (!m_nativeLayoutSupported) { return finish(unsupported); }
    if (!m_driver.isValid()) { m_driver = m_client.openSilently(); }
    m_trace.driverAvailable = m_driver.isValid();
    if (!m_driver.isValid()) { return finish(unsupported); }
    KSWORD_ARK_PFN_REQUEST request{KSWORD_ARK_PFN_VERSION, kind, count, 0, first};
    std::vector<std::uint64_t> input;
    if (pfns) {
        input.resize(sizeof(request) / sizeof(std::uint64_t) + pfns->size());
        std::memcpy(input.data(), &request, sizeof(request));
        std::copy(pfns->begin(), pfns->end(), input.begin() + sizeof(request) / sizeof(std::uint64_t));
    }
    const std::size_t bytes = sizeof(KSWORD_ARK_PFN_RESPONSE) + static_cast<std::size_t>(capacity) * stride;
    std::vector<std::uint64_t> storage((bytes + 7) / 8);
    auto io = m_client.deviceIoControl(IOCTL_KSWORD_ARK_QUERY_PFN_BATCH,
        pfns ? static_cast<void*>(input.data()) : static_cast<void*>(&request),
        pfns ? static_cast<ULONG>(input.size() * sizeof(std::uint64_t)) : static_cast<ULONG>(sizeof(request)),
        storage.data(), static_cast<unsigned long>(bytes), &m_driver);
    m_trace.driverInvoked = true;
    m_trace.driverTransportStatus = io.ntStatus;
    if (!io.ok) { return finish(io.ntStatus < 0 ? io.ntStatus : unsupported); }
    const auto* response = reinterpret_cast<const KSWORD_ARK_PFN_RESPONSE*>(storage.data());
    if (io.bytesReturned < sizeof(*response) || response->version != KSWORD_ARK_PFN_VERSION
        || response->operation != kind || response->count > capacity
        || io.bytesReturned < sizeof(*response) + static_cast<std::size_t>(response->count) * stride) { return finish(invalidData); }
    if (response->nativeStatus < 0) { return finish(response->nativeStatus); }
    returned = response->count;
    std::memcpy(records, response + 1, static_cast<std::size_t>(returned) * stride);
    ++driverBatches;
    return finish(response->nativeStatus);
}

long PfnQueryClient::ranges(std::vector<KSWORD_ARK_PFN_RANGE>& result)
{
    m_trace = {};
    result.clear();
    if (m_backend == PfnBackend::DriverOnly) {
        result.resize(KSWORD_ARK_PFN_MAX_RANGES);
        unsigned long count = 0;
        const long status = driverQuery(KSWORD_ARK_PFN_RANGES, 0, 0, result.data(), KSWORD_ARK_PFN_MAX_RANGES, sizeof(result[0]), count);
        result.resize(count);
        return status;
    }
    const auto bytes = static_cast<unsigned long>(offsetof(KSW_PF_RANGES_V2, Ranges)
        + KSWORD_ARK_PFN_MAX_RANGES * sizeof(KSW_PF_RANGE));
    std::vector<std::uint64_t> storage((bytes + 7) / 8);
    auto* query = reinterpret_cast<KSW_PF_RANGES_V2*>(storage.data());
    query->Version = 2;
    long status = nativeQuery(17, query, bytes);
    if (status >= 0 && query->Count > 0 && query->Count <= KSWORD_ARK_PFN_MAX_RANGES) {
        for (SIZE_T i = 0; i < query->Count; ++i) { result.push_back({query->Ranges[i].Base, query->Ranges[i].Count}); }
        ++nativeBatches;
        return status;
    }
    // Older systems support range ABI v1 (two ULONGs before the same records).
    std::fill(storage.begin(), storage.end(), 0);
    auto* fields = reinterpret_cast<ULONG*>(storage.data());
    fields[0] = 1;
    status = nativeQuery(17, fields, bytes);
    if (status >= 0 && fields[1] > 0 && fields[1] <= KSWORD_ARK_PFN_MAX_RANGES) {
        const auto* ranges = reinterpret_cast<const KSW_PF_RANGE*>(fields + 2);
        for (ULONG i = 0; i < fields[1]; ++i) { result.push_back({ranges[i].Base, ranges[i].Count}); }
        ++nativeBatches;
        return status;
    }
    result.resize(KSWORD_ARK_PFN_MAX_RANGES);
    unsigned long count = 0;
    const long nativeStatus = status < 0 ? status : invalidData;
    if (m_backend == PfnBackend::NativeOnly) { result.clear(); return nativeStatus; }
    const long driverStatus = driverQuery(KSWORD_ARK_PFN_RANGES, 0, 0, result.data(), KSWORD_ARK_PFN_MAX_RANGES, sizeof(result[0]), count);
    result.resize(count);
    // An absent/old driver must not hide the original privilege or ABI error.
    return driverStatus == unsupported ? nativeStatus : driverStatus;
}

long PfnQueryClient::owners(std::vector<KSWORD_ARK_PFN_OWNER>& result)
{
    m_trace = {};
    result.clear();
    if (m_backend == PfnBackend::DriverOnly) {
        result.resize(KSWORD_ARK_PFN_MAX_OWNERS);
        unsigned long count = 0;
        const long status = driverQuery(KSWORD_ARK_PFN_OWNERS, 0, 0, result.data(), KSWORD_ARK_PFN_MAX_OWNERS, sizeof(result[0]), count);
        result.resize(count);
        return status;
    }
    const auto bytes = static_cast<unsigned long>(offsetof(KSW_PF_PRIVATE_QUERY, Sources)
        + KSWORD_ARK_PFN_MAX_OWNERS * sizeof(KSW_PF_PRIVATE_INFO));
    std::vector<std::uint64_t> storage((bytes + 7) / 8);
    auto* query = reinterpret_cast<KSW_PF_PRIVATE_QUERY*>(storage.data());
    query->Version = 8;
    query->Count = KSWORD_ARK_PFN_MAX_OWNERS;
    long status = nativeQuery(8, query, bytes);
    if (status >= 0 && query->Count <= KSWORD_ARK_PFN_MAX_OWNERS) {
        for (ULONG i = 0; i < query->Count; ++i) {
            const auto& source = query->Sources[i];
            if (source.Source.Type != 2) { continue; }
            KSWORD_ARK_PFN_OWNER owner{};
            owner.processKey = reinterpret_cast<ULONG_PTR>(source.EProcess) & 0xFFFFFFFFFFFFULL;
            owner.processId = source.Source.ProcessId;
            owner.sessionId = source.SessionId;
            std::memcpy(owner.imageName, source.ImageName, sizeof(owner.imageName));
            result.push_back(owner);
        }
        ++nativeBatches;
        return status;
    }
    result.resize(KSWORD_ARK_PFN_MAX_OWNERS);
    unsigned long count = 0;
    const long nativeStatus = status < 0 ? status : invalidData;
    if (m_backend == PfnBackend::NativeOnly) { result.clear(); return nativeStatus; }
    const long driverStatus = driverQuery(KSWORD_ARK_PFN_OWNERS, 0, 0, result.data(), KSWORD_ARK_PFN_MAX_OWNERS, sizeof(result[0]), count);
    result.resize(count);
    return driverStatus == unsupported ? nativeStatus : driverStatus;
}

long PfnQueryClient::pages(std::uint64_t first, std::uint32_t count, std::vector<KSWORD_ARK_PFN_IDENTITY>& result)
{
    m_trace = {};
    result.clear();
    if (count == 0 || count > KSWORD_ARK_PFN_MAX_PAGES || first > (1ULL << 40) - count) { return invalidData; }
    long status = unsupported;
    if (!m_driverPages && m_backend != PfnBackend::DriverOnly) {
        const auto bytes = static_cast<unsigned long>(offsetof(KSW_PF_QUERY, Pages) + count * sizeof(KSW_PF_IDENTITY));
        std::vector<std::uint64_t> storage((bytes + 7) / 8);
        auto* query = reinterpret_cast<KSW_PF_QUERY*>(storage.data());
        query->Version = 1;
        query->Count = count;
        for (std::uint32_t i = 0; i < count; ++i) { query->Pages[i] = {~0ULL, first + i, 0}; }
        status = nativeQuery(6, query, bytes);
        if (status >= 0 && query->Count == count) {
            result.resize(count);
            std::memcpy(result.data(), query->Pages, count * sizeof(KSW_PF_IDENTITY));
            ++nativeBatches;
        }
    }
    if (result.empty() && m_backend == PfnBackend::NativeOnly) { return status < 0 ? status : invalidData; }
    if (result.empty()) {
        result.resize(count);
        unsigned long returned = 0;
        const long driverStatus = driverQuery(KSWORD_ARK_PFN_PAGES, first, count,
            result.data(), count, sizeof(result[0]), returned);
        result.resize(returned);
        if (driverStatus >= 0) { m_driverPages = true; status = driverStatus; }
        else if (m_driverPages || driverStatus != unsupported) { status = driverStatus; }
    }
    if (status < 0) { result.clear(); return status; }
    if (result.size() != count) { result.clear(); return invalidData; }
    for (std::uint32_t i = 0; i < count; ++i) {
        if (result[i].pfn != first + i) { result.clear(); return invalidData; }
    }
    return status;
}

long PfnQueryClient::identities(const std::vector<std::uint64_t>& pfns, std::vector<KSWORD_ARK_PFN_IDENTITY>& result)
{
    m_trace = {};
    result.clear();
    if (pfns.empty() || pfns.size() > KSWORD_ARK_PFN_MAX_PAGES
        || std::any_of(pfns.begin(), pfns.end(), [](auto pfn) { return pfn >= (1ULL << 40); })) { return invalidData; }
    const auto count = static_cast<ULONG>(pfns.size());
    const auto bytes = static_cast<ULONG>(offsetof(KSW_PF_QUERY, Pages) + count * sizeof(KSW_PF_IDENTITY));
    std::vector<std::uint64_t> storage((bytes + 7) / 8);
    auto* query = reinterpret_cast<KSW_PF_QUERY*>(storage.data());
    query->Version = 1;
    query->Count = count;
    for (ULONG i = 0; i < count; ++i) { query->Pages[i] = {~0ULL, pfns[i], 0}; }
    long status = (m_driverPages || m_backend == PfnBackend::DriverOnly) ? unsupported : nativeQuery(6, query, bytes);
    if (status >= 0 && query->Count == count) {
        result.resize(count);
        std::memcpy(result.data(), query->Pages, count * sizeof(KSW_PF_IDENTITY));
        ++nativeBatches;
    } else if (m_backend == PfnBackend::NativeOnly) {
        return status < 0 ? status : invalidData;
    } else {
        result.resize(count);
        unsigned long returned = 0;
        status = driverQuery(KSWORD_ARK_PFN_IDENTITIES, 0, count, result.data(), count, sizeof(result[0]), returned, &pfns);
        result.resize(returned);
    }
    if (status < 0) { result.clear(); return status; }
    if (result.size() != count) { result.clear(); return invalidData; }
    for (ULONG i = 0; i < count; ++i) {
        if (result[i].pfn != pfns[i]) { result.clear(); return invalidData; }
    }
    return status;
}

bool PfnQueryClient::mappingAvailable()
{
    if (!m_nativeLayoutSupported || m_backend == PfnBackend::NativeOnly) { return false; }
    if (!m_driver.isValid()) { m_driver = m_client.openSilently(); }
    return m_driver.isValid();
}

long PfnQueryClient::mappings(std::uint32_t pid, std::uint64_t created,
    const std::vector<std::uint64_t>& addresses, std::vector<KSWORD_ARK_PFN_MAPPING>& result)
{
    m_trace = {};
    result.clear();
    if (pid == 0 || created == 0 || addresses.empty() || addresses.size() > KSWORD_ARK_PFN_MAX_MAPPINGS) { return invalidData; }
    m_trace.driverAvailable = mappingAvailable();
    if (!m_trace.driverAvailable) { m_trace.driverStatus = unsupported; return unsupported; }
    KSWORD_ARK_PFN_MAPPING_REQUEST request{};
    request.version = KSWORD_ARK_PFN_VERSION;
    request.processId = pid;
    request.count = static_cast<ULONG>(addresses.size());
    request.createTime = created;
    std::copy(addresses.begin(), addresses.end(), request.addresses);
    KSWORD_ARK_PFN_MAPPING_RESPONSE response{};
    auto io = m_client.deviceIoControl(IOCTL_KSWORD_ARK_QUERY_PFN_MAPPINGS, &request, sizeof(request),
        &response, sizeof(response), &m_driver);
    m_trace.driverInvoked = true;
    m_trace.driverTransportStatus = io.ntStatus;
    if (!io.ok) { m_trace.driverStatus = io.ntStatus < 0 ? io.ntStatus : unsupported; return m_trace.driverStatus; }
    if (io.bytesReturned != sizeof(response) || response.version != KSWORD_ARK_PFN_VERSION
        || response.count == 0 || response.count > addresses.size()) { m_trace.driverStatus = invalidData; return invalidData; }
    result.assign(response.entries, response.entries + response.count);
    m_trace.driverStatus = 0;
    return 0;
}
}
