#include "DriverMemoryClient.h"

#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <string>

namespace Ksword::Features::Memory {
namespace {

// MemoryReadStatusText maps the shared driver read status into stable UI text.
// Input is KSWORD_ARK_MEMORY_READ_STATUS_* from shared/driver; output is a short
// label that supplements ArkDriverClient's transport diagnostic message.
const wchar_t* MemoryReadStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_MEMORY_READ_STATUS_OK: return L"OK";
    case KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY: return L"Partial copy";
    case KSWORD_ARK_MEMORY_READ_STATUS_PROCESS_LOOKUP_FAILED: return L"Process lookup failed";
    case KSWORD_ARK_MEMORY_READ_STATUS_COPY_FAILED: return L"Copy failed";
    case KSWORD_ARK_MEMORY_READ_STATUS_RANGE_REJECTED: return L"Range rejected";
    case KSWORD_ARK_MEMORY_READ_STATUS_BUFFER_TOO_SMALL: return L"Buffer too small";
    case KSWORD_ARK_MEMORY_READ_STATUS_ZERO_FILLED: return L"Zero-filled unreadable";
    case KSWORD_ARK_MEMORY_READ_STATUS_UNAVAILABLE:
    default:
        return L"Unavailable";
    }
}

// MemoryWriteStatusText maps the shared driver write status into stable UI
// text. Input is KSWORD_ARK_MEMORY_WRITE_STATUS_*; output is a short label.
const wchar_t* MemoryWriteStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_MEMORY_WRITE_STATUS_OK: return L"OK";
    case KSWORD_ARK_MEMORY_WRITE_STATUS_PARTIAL_COPY: return L"Partial copy";
    case KSWORD_ARK_MEMORY_WRITE_STATUS_PROCESS_LOOKUP_FAILED: return L"Process lookup failed";
    case KSWORD_ARK_MEMORY_WRITE_STATUS_COPY_FAILED: return L"Copy failed";
    case KSWORD_ARK_MEMORY_WRITE_STATUS_RANGE_REJECTED: return L"Range rejected";
    case KSWORD_ARK_MEMORY_WRITE_STATUS_BUFFER_TOO_SMALL: return L"Buffer too small";
    case KSWORD_ARK_MEMORY_WRITE_STATUS_ACCESS_DENIED: return L"Access denied";
    case KSWORD_ARK_MEMORY_WRITE_STATUS_FORCE_REQUIRED: return L"Force required";
    case KSWORD_ARK_MEMORY_WRITE_STATUS_UNAVAILABLE:
    default:
        return L"Unavailable";
    }
}

// NarrowToWide converts ArkDriverClient's narrow diagnostic messages into the
// Win32-light UI's UTF-16 status text. Input is ASCII/UTF-8-like diagnostic
// text; processing widens byte-for-byte because current client messages are
// English diagnostics; output is displayable UTF-16 text.
std::wstring NarrowToWide(const std::string& text) {
    std::wstring wide;
    wide.reserve(text.size());
    for (const unsigned char ch : text) {
        wide.push_back(static_cast<wchar_t>(ch));
    }
    return wide;
}

// FormatReadStatus creates the final read status line. Inputs are the original
// request and ArkDriverClient result; processing combines Win32, NT, protocol
// and byte-count fields; output is shown in the memory page status box.
std::wstring FormatReadStatus(
    const DriverMemoryReadRequest& request,
    const ksword::ark::VirtualMemoryReadResult& driverResult) {
    std::wostringstream stream;
    stream << L"R0 read "
           << (driverResult.io.ok ? L"transport OK" : L"transport failed")
           << L"; protocol=" << MemoryReadStatusText(driverResult.readStatus)
           << L"; pid=" << request.processId
           << L"; address=0x" << std::hex << std::uppercase << request.address
           << std::dec
           << L"; requested=" << request.length
           << L"; bytesRead=" << driverResult.bytesRead
           << L"; win32=" << driverResult.io.win32Error
           << L"; nt=0x" << std::hex << static_cast<unsigned long>(driverResult.copyStatus)
           << L"; fields=0x" << driverResult.fieldFlags
           << L"; " << NarrowToWide(driverResult.io.message);
    return stream.str();
}

// FormatWriteStatus creates the final write status line. Inputs are the request
// and ArkDriverClient result; processing combines transport/protocol/byte
// counts; output is shown in the memory page status box.
std::wstring FormatWriteStatus(
    const DriverMemoryWriteRequest& request,
    const ksword::ark::VirtualMemoryWriteResult& driverResult) {
    std::wostringstream stream;
    stream << L"R0 write "
           << (driverResult.io.ok ? L"transport OK" : L"transport failed")
           << L"; protocol=" << MemoryWriteStatusText(driverResult.writeStatus)
           << L"; pid=" << request.processId
           << L"; address=0x" << std::hex << std::uppercase << request.address
           << std::dec
           << L"; requested=" << request.bytes.size()
           << L"; bytesWritten=" << driverResult.bytesWritten
           << L"; win32=" << driverResult.io.win32Error
           << L"; nt=0x" << std::hex << static_cast<unsigned long>(driverResult.copyStatus)
           << L"; fields=0x" << driverResult.fieldFlags
           << L"; " << NarrowToWide(driverResult.io.message);
    return stream.str();
}

std::wstring FormatAddress(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

bool IsExactRead(const DriverMemoryReadResult& result, const std::vector<std::uint8_t>& expected) {
    return result.success && result.protocolStatus == KSWORD_ARK_MEMORY_READ_STATUS_OK &&
        result.bytes.size() == expected.size() && std::equal(result.bytes.cbegin(), result.bytes.cend(), expected.cbegin());
}

bool IsExactWrite(const DriverMemoryWriteResult& result, const std::size_t expectedBytes) {
    return result.success && result.protocolStatus == KSWORD_ARK_MEMORY_WRITE_STATUS_OK &&
        result.bytesWritten == expectedBytes;
}

bool IsCancellationRequested(const DriverMemoryWritebackCancellation* cancellation) noexcept {
    return cancellation != nullptr && cancellation->isCancellationRequested();
}

// IssueDriverRequest holds the shared issuance gate across both the last
// cancellation check and one blocking driver operation. Page destruction first
// publishes cancellation, then takes the same gate to wait for any in-flight
// request; it cannot race a new request into existence after destruction.
template <typename Result, typename Request>
bool IssueDriverRequest(const DriverMemoryWritebackCancellation* cancellation, Result& result, Request request) {
    if (cancellation == nullptr) {
        result = request();
        return true;
    }
    const std::unique_lock<std::mutex> issuanceLock = cancellation->lockIssuanceGate();
    if (cancellation->isCancellationRequested()) {
        return false;
    }
    result = request();
    return true;
}

void SetWritebackFailure(DriverMemoryWritebackResult& result,
    const std::uint64_t address,
    const std::wstring& message) {
    result.success = false;
    result.failedAddress = address;
    result.statusText = message;
}

void SetWritebackCancelled(DriverMemoryWritebackResult& result,
    const std::uint64_t address,
    const std::wstring& detail) {
    result.cancelled = true;
    SetWritebackFailure(result, address,
        L"差异写回已取消；目标内存可能已有已完成或未完全确认的写入，请重新读取后再预览。\r\n" + detail);
}

// MakeReadValidationError returns a failed local result before any IOCTL is
// sent. Input is the user request and message; output is a consistent UI result.
DriverMemoryReadResult MakeReadValidationError(const DriverMemoryReadRequest& request, const std::wstring& message) {
    DriverMemoryReadResult result;
    result.success = false;
    result.win32Error = ERROR_INVALID_PARAMETER;
    result.statusText = message + L" Requested " + std::to_wstring(request.length) + L" byte(s).";
    return result;
}

// MakeWriteValidationError returns a failed local result before any IOCTL is
// sent. Input is the user request and message; output is a consistent UI result.
DriverMemoryWriteResult MakeWriteValidationError(const DriverMemoryWriteRequest& request, const std::wstring& message) {
    DriverMemoryWriteResult result;
    result.success = false;
    result.win32Error = ERROR_INVALID_PARAMETER;
    result.bytesWritten = 0;
    result.statusText = message + L" Payload " + std::to_wstring(request.bytes.size()) + L" byte(s).";
    return result;
}

} // namespace

void DriverMemoryWritebackCancellation::cancel() {
    cancelled_.store(true, std::memory_order_release);
    // Publishing cancellation before waiting closes the handoff race: a worker
    // that releases an earlier request cannot acquire the gate for a new IOCTL.
    const std::scoped_lock issuanceLock(issuanceGate_);
    (void)issuanceLock;
}

bool DriverMemoryWritebackCancellation::isCancellationRequested() const noexcept {
    return cancelled_.load(std::memory_order_acquire);
}

std::unique_lock<std::mutex> DriverMemoryWritebackCancellation::lockIssuanceGate() const {
    return std::unique_lock<std::mutex>(issuanceGate_);
}

DriverMemoryClient::DriverMemoryClient() = default;

DriverMemoryClient::~DriverMemoryClient() = default;

DriverMemoryReadResult DriverMemoryClient::ReadMemory(const DriverMemoryReadRequest& request) {
    if (request.processId == 0 || request.length == 0) {
        return MakeReadValidationError(request, L"PID and length must be non-zero.");
    }
    if (request.length > KSWORD_ARK_MEMORY_READ_MAX_BYTES) {
        return MakeReadValidationError(request, L"Read length exceeds shared driver limit.");
    }

    const ksword::ark::DriverClient client;
    const ksword::ark::VirtualMemoryReadResult driverResult = client.readVirtualMemory(
        static_cast<std::uint32_t>(request.processId),
        request.address,
        static_cast<std::uint32_t>(request.length),
        0);

    DriverMemoryReadResult result;
    result.success = driverResult.io.ok &&
        (driverResult.readStatus == KSWORD_ARK_MEMORY_READ_STATUS_OK ||
            driverResult.readStatus == KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY) &&
        !driverResult.data.empty();
    result.win32Error = driverResult.io.win32Error;
    result.protocolStatus = driverResult.readStatus;
    result.copyStatus = static_cast<std::uint32_t>(driverResult.copyStatus);
    result.fieldFlags = driverResult.fieldFlags;
    result.bytes = driverResult.data;
    result.statusText = FormatReadStatus(request, driverResult);
    return result;
}

DriverMemoryWriteResult DriverMemoryClient::WriteMemory(const DriverMemoryWriteRequest& request, const bool forceWrite) {
    if (request.processId == 0 || request.bytes.empty()) {
        return MakeWriteValidationError(request, L"PID and payload must be non-zero.");
    }
    if (request.bytes.size() > KSWORD_ARK_MEMORY_WRITE_MAX_BYTES) {
        return MakeWriteValidationError(request, L"Write payload exceeds shared driver limit.");
    }

    const ksword::ark::DriverClient client;
    std::uint32_t writeFlags = KSWORD_ARK_MEMORY_WRITE_FLAG_UI_CONFIRMED;
    if (forceWrite) {
        writeFlags |= KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE;
    }
    const ksword::ark::VirtualMemoryWriteResult driverResult = client.writeVirtualMemory(
        static_cast<std::uint32_t>(request.processId),
        request.address,
        request.bytes,
        writeFlags);

    DriverMemoryWriteResult result;
    result.success = driverResult.io.ok &&
        (driverResult.writeStatus == KSWORD_ARK_MEMORY_WRITE_STATUS_OK ||
            driverResult.writeStatus == KSWORD_ARK_MEMORY_WRITE_STATUS_PARTIAL_COPY) &&
        driverResult.bytesWritten > 0;
    result.win32Error = driverResult.io.win32Error;
    result.protocolStatus = driverResult.writeStatus;
    result.copyStatus = static_cast<std::uint32_t>(driverResult.copyStatus);
    result.fieldFlags = driverResult.fieldFlags;
    result.bytesWritten = driverResult.bytesWritten;
    result.statusText = FormatWriteStatus(request, driverResult);
    return result;
}

DriverMemoryWritebackResult DriverMemoryClient::ApplyWritePlan(
    const MemoryWritePlan& plan,
    const bool forceWrite,
    const DriverMemoryWritebackCancellation* cancellation,
    const std::size_t firstPendingBlock) {
    DriverMemoryWritebackResult result{};
    result.totalBlocks = plan.blocks.size();
    if (IsCancellationRequested(cancellation)) {
        SetWritebackCancelled(result, plan.baseAddress, L"尚未开始发送驱动请求。");
        return result;
    }

    std::wstring validationError;
    if (!ValidateMemoryWritePlan(plan, validationError)) {
        SetWritebackFailure(result, plan.baseAddress, L"差异写回计划无效：" + validationError);
        return result;
    }
    if (plan.desiredSnapshotBytes.size() > KSWORD_ARK_MEMORY_READ_MAX_BYTES) {
        SetWritebackFailure(result, plan.baseAddress, L"差异写回快照超过共享读取上限。");
        return result;
    }
    if (plan.blocks.empty()) {
        if (firstPendingBlock != 0U) {
            SetWritebackFailure(result, plan.baseAddress, L"空差异计划不接受续写位置。");
            return result;
        }
        result.success = true;
        result.statusText = L"差异计划没有变化字节，未发送写入请求。";
        return result;
    }
    if (firstPendingBlock >= plan.blocks.size()) {
        SetWritebackFailure(result, plan.baseAddress, L"差异写回续写位置超出计划范围。");
        return result;
    }

    // A normal-write prefix may have been verified before a user spends time in
    // the separate FORCE confirmation dialog. Re-read that prefix now rather
    // than trusting the old verification: if it changed, do not risk applying
    // FORCE to a suffix of a no-longer-coherent snapshot.
    std::size_t recheckedPrefixBytes = 0U;
    for (std::size_t blockIndex = 0U; blockIndex < firstPendingBlock; ++blockIndex) {
        const MemoryWriteBlock& block = plan.blocks[blockIndex];
        if (IsCancellationRequested(cancellation)) {
            SetWritebackCancelled(result, block.address, L"未继续复核已验证前缀或发送剩余块请求。");
            return result;
        }
        const DriverMemoryReadRequest prefixRequest{
            static_cast<DWORD>(plan.processId), block.address, block.desiredAfter.size() };
        DriverMemoryReadResult prefixResult;
        if (!IssueDriverRequest(cancellation, prefixResult, [&] { return ReadMemory(prefixRequest); })) {
            SetWritebackCancelled(result, block.address, L"取消已生效，未继续复核已验证前缀。");
            return result;
        }
        if (IsCancellationRequested(cancellation)) {
            SetWritebackCancelled(result, block.address, L"已验证前缀复读已返回，未继续发送剩余块请求。");
            return result;
        }
        if (!IsExactRead(prefixResult, block.desiredAfter)) {
            SetWritebackFailure(result, block.address,
                L"FORCE 续写已停止：此前已验证的普通写入块发生变化，需重新读取并预览。\r\n" + prefixResult.statusText);
            return result;
        }
        recheckedPrefixBytes += block.desiredAfter.size();
    }

    for (std::size_t blockIndex = firstPendingBlock; blockIndex < plan.blocks.size(); ++blockIndex) {
        const MemoryWriteBlock& block = plan.blocks[blockIndex];
        if (IsCancellationRequested(cancellation)) {
            SetWritebackCancelled(result, block.address, L"未继续发送后续块请求。");
            return result;
        }
        if (block.desiredAfter.size() > KSWORD_ARK_MEMORY_WRITE_MAX_BYTES) {
            SetWritebackFailure(result, block.address, L"差异块超过共享写入上限。");
            return result;
        }

        const DriverMemoryReadRequest preflightRequest{
            static_cast<DWORD>(plan.processId), block.address, block.expectedBefore.size() };
        DriverMemoryReadResult preflightResult;
        if (!IssueDriverRequest(cancellation, preflightResult, [&] { return ReadMemory(preflightRequest); })) {
            SetWritebackCancelled(result, block.address, L"取消已生效，未继续发送写前复读请求。");
            return result;
        }
        if (IsCancellationRequested(cancellation)) {
            SetWritebackCancelled(result, block.address, L"写前复读已返回，未继续发送写入请求。");
            return result;
        }
        if (!IsExactRead(preflightResult, block.expectedBefore)) {
            SetWritebackFailure(result, block.address,
                L"差异写回已停止：写前读取与原始快照不一致，需重新读取并预览。\r\n" + preflightResult.statusText);
            return result;
        }

        DriverMemoryWriteRequest writeRequest{};
        writeRequest.processId = static_cast<DWORD>(plan.processId);
        writeRequest.address = block.address;
        writeRequest.bytes = block.desiredAfter;
        if (IsCancellationRequested(cancellation)) {
            SetWritebackCancelled(result, block.address, L"写前复读一致，但已取消，未继续发送写入请求。");
            return result;
        }
        DriverMemoryWriteResult writeResult;
        if (!IssueDriverRequest(cancellation, writeResult, [&] { return WriteMemory(writeRequest, forceWrite); })) {
            SetWritebackCancelled(result, block.address, L"取消已生效，未继续发送写入请求。");
            return result;
        }
        result.requestedBytes += block.desiredAfter.size();
        result.bytesWritten += writeResult.bytesWritten;
        if (IsCancellationRequested(cancellation)) {
            SetWritebackCancelled(result, block.address,
                L"最后一个写入请求已返回，未继续验证或发送后续块请求。\r\n" + writeResult.statusText);
            return result;
        }
        if (!IsExactWrite(writeResult, block.desiredAfter.size())) {
            if (!forceWrite && writeResult.protocolStatus == KSWORD_ARK_MEMORY_WRITE_STATUS_FORCE_REQUIRED &&
                writeResult.bytesWritten == 0U) {
                result.forceRequired = true;
                result.forceRequiredBlockIndex = blockIndex;
                SetWritebackFailure(result, block.address,
                    result.verifiedBlocks == 0U
                        ? L"驱动要求 FORCE 才能写入此快照；本次和累计均未报告写入字节。\r\n" + writeResult.statusText
                        : L"驱动要求 FORCE 才能继续剩余差异块；此前块已逐块验证，当前拒绝块未报告写入字节。\r\n" + writeResult.statusText);
            } else {
                SetWritebackFailure(result, block.address,
                    L"差异写回已停止：写入未完整成功，未继续后续块。\r\n" + writeResult.statusText);
            }
            return result;
        }

        const DriverMemoryReadRequest verificationRequest{
            static_cast<DWORD>(plan.processId), block.address, block.desiredAfter.size() };
        if (IsCancellationRequested(cancellation)) {
            SetWritebackCancelled(result, block.address, L"写入已成功返回，未继续发送写后验证请求。");
            return result;
        }
        DriverMemoryReadResult verificationResult;
        if (!IssueDriverRequest(cancellation, verificationResult, [&] { return ReadMemory(verificationRequest); })) {
            SetWritebackCancelled(result, block.address, L"取消已生效，未继续发送写后验证请求。");
            return result;
        }
        if (IsCancellationRequested(cancellation)) {
            SetWritebackCancelled(result, block.address, L"写后验证已返回，未继续发送后续块请求。");
            return result;
        }
        if (!IsExactRead(verificationResult, block.desiredAfter)) {
            SetWritebackFailure(result, block.address,
                L"差异写回已停止：写后读取未精确匹配目标字节，未继续后续块。\r\n" + verificationResult.statusText);
            return result;
        }
        ++result.verifiedBlocks;
    }

    const DriverMemoryReadRequest finalReadRequest{
        static_cast<DWORD>(plan.processId), plan.baseAddress, plan.desiredSnapshotBytes.size() };
    if (IsCancellationRequested(cancellation)) {
        SetWritebackCancelled(result, plan.baseAddress, L"未发送完整快照复读请求。");
        return result;
    }
    if (!IssueDriverRequest(cancellation, result.finalReadResult, [&] { return ReadMemory(finalReadRequest); })) {
        SetWritebackCancelled(result, plan.baseAddress, L"取消已生效，未继续发送完整快照复读请求。");
        return result;
    }
    if (IsCancellationRequested(cancellation)) {
        SetWritebackCancelled(result, plan.baseAddress, L"完整快照复读已返回，未将结果作为新的快照基线。");
        return result;
    }
    if (!IsExactRead(result.finalReadResult, plan.desiredSnapshotBytes)) {
        SetWritebackFailure(result, plan.baseAddress,
            L"差异块均已验证，但完整快照复读未精确匹配；未更新快照基线。\r\n" + result.finalReadResult.statusText);
        return result;
    }

    result.success = true;
    if (firstPendingBlock == 0U) {
        result.statusText = L"差异写回完成：已验证 " + std::to_wstring(result.verifiedBlocks) + L" 个块、" +
            std::to_wstring(result.bytesWritten) + L" 字节；完整快照复读一致。目标=" + FormatAddress(plan.baseAddress) + L"。";
    } else {
        result.statusText = L"差异写回续写完成：已复核前缀 " + std::to_wstring(firstPendingBlock) + L" 个块、" +
            std::to_wstring(recheckedPrefixBytes) + L" 字节；本次已验证 " + std::to_wstring(result.verifiedBlocks) +
            L" 个 FORCE 块、" + std::to_wstring(result.bytesWritten) +
            L" 字节；完整快照复读一致。目标=" + FormatAddress(plan.baseAddress) + L"。";
    }
    return result;
}

} // namespace Ksword::Features::Memory
