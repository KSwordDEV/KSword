// Exercise the production DriverClient parser with controlled transport replies.
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include <cstddef>
#include <cstring>
#include <iostream>

namespace {
    enum class Reply { Success, CloseFailure, ResumeFailure, Truncated, WrongVersion, TransportFailure, OldEnum, NewEnum };
    Reply reply = Reply::Success;
    unsigned calls = 0;
    bool packetValid = true;
    constexpr std::uint32_t targetPid = 0x70000U;
    constexpr std::uint64_t creationTime = 0x123456781234ULL;
    constexpr std::uint64_t objectAddress = 0xFFFF800012345678ULL;
    constexpr long failureStatus = static_cast<long>(static_cast<std::int32_t>(0xC0000008U));
    unsigned failures = 0;
    void check(bool condition, const char* description) {
        if (!condition) { std::cerr << "FAIL: " << description << '\n'; ++failures; }
    }
}

namespace ksword::ark {
    IoResult DriverClient::deviceIoControl(unsigned long code, void* input, unsigned long inputBytes,
        void* output, unsigned long outputBytes, DriverHandle*) const {
        ++calls;
        IoResult io{};
        if (reply == Reply::TransportFailure) { io.win32Error = ERROR_INVALID_FUNCTION; return io; }
        io.ok = true;
        if (code == IOCTL_KSWORD_ARK_CLOSE_HANDLE) {
            const auto& request = *static_cast<const KSWORD_ARK_CLOSE_HANDLE_REQUEST*>(input);
            packetValid = packetValid && inputBytes == sizeof(request) && outputBytes == sizeof(KSWORD_ARK_CLOSE_HANDLE_RESPONSE)
                && request.size == sizeof(request) && request.version == KSWORD_ARK_CLOSE_HANDLE_VERSION
                && request.flags == KSWORD_ARK_CLOSE_HANDLE_FLAG_UI_CONFIRMED && request.processId == targetPid
                && request.handleValue == 0x100 && request.expectedCreateTime100ns == creationTime
                && request.expectedObjectAddress == objectAddress;
            auto& response = *static_cast<KSWORD_ARK_CLOSE_HANDLE_RESPONSE*>(output);
            response.size = sizeof(response);
            response.version = reply == Reply::WrongVersion ? 999U : KSWORD_ARK_CLOSE_HANDLE_VERSION;
            response.closeStatus = reply == Reply::CloseFailure ? failureStatus : 0;
            response.resumeStatus = reply == Reply::ResumeFailure ? failureStatus : 0;
            io.bytesReturned = reply == Reply::Truncated ? sizeof(response) - 1U : sizeof(response);
        }
        else if (code == IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES) {
            auto& response = *static_cast<KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE*>(output);
            response.version = KSWORD_ARK_HANDLE_PROTOCOL_VERSION;
            response.processId = targetPid;
            response.totalCount = response.returnedCount = 1;
            response.entrySize = static_cast<unsigned long>(reply == Reply::OldEnum
                ? KSWORD_ARK_HANDLE_ENTRY_LEGACY_SIZE : sizeof(KSWORD_ARK_HANDLE_ENTRY));
            response.entries[0].processId = targetPid;
            response.entries[0].handleValue = 0x100;
            response.entries[0].objectAddress = objectAddress;
            response.entries[0].processCreationTime100ns = creationTime;
            io.bytesReturned = static_cast<unsigned long>(offsetof(KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE, entries)) + response.entrySize;
        }
        return io;
    }
}

int main() {
    const ksword::ark::DriverClient client;
    const auto close = [&]() { return client.closeHandle(targetPid, 0x100, creationTime, objectAddress); };
    check(close().ok && packetValid, "exact close identity/confirmation packet");
    reply = Reply::CloseFailure;
    check(!close().ok && close().ntStatus == failureStatus, "semantic close failure");
    reply = Reply::ResumeFailure;
    const auto recovery = close();
    check(!recovery.ok && recovery.ntStatus == 0 && recovery.message.find("handle closed") != std::string::npos,
        "close success with failed recovery stays distinguishable");
    const auto detailed = client.closeHandleDetailed(targetPid, 0x100, creationTime, objectAddress);
    check(detailed.responseValid && detailed.closeStatus == 0 && detailed.resumeStatus == failureStatus,
        "structured close and failed recovery statuses remain separate");
    reply = Reply::Truncated;
    check(!close().ok, "reject truncated receipt");
    check(!client.closeHandleDetailed(targetPid, 0x100, creationTime, objectAddress).responseValid,
        "truncated receipt cannot publish fabricated statuses");
    reply = Reply::WrongVersion;
    check(!close().ok, "reject incompatible receipt");
    reply = Reply::TransportFailure;
    check(!close().ok && close().win32Error == ERROR_INVALID_FUNCTION, "old driver refusal has no fallback");
    const unsigned before = calls;
    check(!client.closeHandle(4, 0x100, creationTime, objectAddress).ok, "reject System");
    check(!client.closeHandle(GetCurrentProcessId(), 0x100, creationTime, objectAddress).ok, "reject caller");
    check(!client.closeHandle(targetPid, 0, creationTime, objectAddress).ok, "reject zero handle");
    check(!client.closeHandle(targetPid, 0x80000000ULL, creationTime, objectAddress).ok, "reject kernel handle");
    check(!client.closeHandle(targetPid, 0xFFFFFFFFFFFFFFFFULL, creationTime, objectAddress).ok, "reject pseudo handle");
    check(!client.closeHandle(targetPid, 0x100, 0, objectAddress).ok, "require owner identity");
    check(!client.closeHandle(targetPid, 0x100, creationTime, 0).ok, "require object identity");
    check(before == calls, "invalid targets never reach transport");
    reply = Reply::OldEnum;
    const auto oldRows = client.enumerateProcessHandles(targetPid);
    check(oldRows.io.ok && oldRows.entries.size() == 1 && oldRows.entries[0].processCreationTime100ns == 0,
        "old entry layout accepted without reading beyond returned data");
    reply = Reply::NewEnum;
    const auto newRows = client.enumerateProcessHandles(targetPid);
    check(newRows.io.ok && newRows.entries.size() == 1 && newRows.entries[0].processCreationTime100ns == creationTime,
        "R0 enumeration carries the actual owner creation time");
    if (failures) { return 1; }
    std::cout << "Handle close client regressions passed\n";
    return 0;
}
