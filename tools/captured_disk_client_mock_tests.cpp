// 真实Client封装搭配纯内存deviceIoControl，不链接真实设备访问实现。
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include <algorithm>
#include <cstring>
#include <iostream>

namespace
{
    enum class Mode { Good, OldDriver, Unsupported, SourceChanged, Partial, Version, Size, Backend, Status, NtFailure, Truncated, Oversized };
    Mode mode = Mode::Good; // 模拟驱动回执，不调用任何Windows设备API。
    unsigned checks = 0;
    unsigned calls = 0;
    std::vector<std::uint8_t> packet; // 保存Client实际发送的唯一请求。
    void require(bool condition, const char* message)
    {
        ++checks;
        if (!condition) { std::cerr << "FAIL " << message << '\n'; std::exit(1); }
    }
}

namespace ksword::ark
{
    // 只替换运输层，调用方、协议打包与回执验证都使用本轮生产实现。
    IoResult DriverClient::deviceIoControl(unsigned long code, void* input, unsigned long inputBytes,
        void* output, unsigned long outputBytes, DriverHandle*) const
    {
        ++calls;
        packet.assign(static_cast<std::uint8_t*>(input), static_cast<std::uint8_t*>(input) + inputBytes);
        IoResult io;
        io.ok = true;
        unsigned long length = 0;
        if (code == IOCTL_KSWORD_ARK_READ_RAW_DISK)
        {
            require(inputBytes == sizeof(KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST), "captured read packet is exactly 56 bytes");
            const auto& request = *static_cast<KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST*>(input);
            require(request.version == KSWORD_ARK_RAW_DISK_CAPTURED_READ_VERSION && request.size == inputBytes,
                "read V2 version and declared size are preserved");
            length = request.length;
            require(outputBytes == KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE + length, "read response allocation is bounded");
            auto* response = static_cast<KSWORD_ARK_RAW_DISK_READ_RESPONSE*>(output);
            response->version = 1;
            response->size = outputBytes;
            response->backendUsed = request.backend;
            response->logicalSectorSize = 512;
            response->bytesTransferred = length;
            io.bytesReturned = outputBytes;
            for (unsigned long index = 0; index < length; ++index) response->data[index] = std::uint8_t(index % 251);
            if (mode == Mode::Version) response->version = 2;
            if (mode == Mode::Size) --response->size;
            if (mode == Mode::Backend) ++response->backendUsed;
            if (mode == Mode::Status) response->status = KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED;
            if (mode == Mode::NtFailure) response->lastStatus = -1;
            if (mode == Mode::Partial) --response->bytesTransferred;
            if (mode == Mode::Truncated) io.bytesReturned = 31;
            if (mode == Mode::Oversized) ++io.bytesReturned;
            if (mode == Mode::OldDriver || mode == Mode::Unsupported || mode == Mode::SourceChanged)
            {
                io.ok = false;
                io.win32Error = mode == Mode::OldDriver ? ERROR_INVALID_PARAMETER : ERROR_NOT_SUPPORTED;
                response->size = 32;
                response->bytesTransferred = 0;
                response->status = mode == Mode::OldDriver ? KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST
                    : mode == Mode::SourceChanged ? KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED
                    : KSWORD_ARK_RAW_DISK_STATUS_NOT_SUPPORTED;
                io.bytesReturned = 32;
            }
        }
        else
        {
            require(code == IOCTL_KSWORD_ARK_WRITE_RAW_DISK, "only the existing write IOCTL is used");
            const auto& request = *static_cast<KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST*>(input);
            length = request.length;
            require(inputBytes == 56 + 2 * length && request.size == inputBytes && request.version == 2,
                "V2 write contains exactly original plus replacement after the 56-byte header");
            auto* response = static_cast<KSWORD_ARK_RAW_DISK_WRITE_RESPONSE*>(output);
            *response = {};
            response->version = 1;
            response->size = sizeof(*response);
            response->backendUsed = request.backend;
            response->bytesTransferred = length;
            io.bytesReturned = outputBytes;
            if (mode == Mode::Version) response->version = 2;
            if (mode == Mode::Size) --response->size;
            if (mode == Mode::Backend) ++response->backendUsed;
            if (mode == Mode::Status) response->status = KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED;
            if (mode == Mode::NtFailure) response->lastStatus = -1;
            if (mode == Mode::Partial) --response->bytesTransferred;
            if (mode == Mode::Truncated) io.bytesReturned = 31;
            if (mode == Mode::Oversized) ++io.bytesReturned;
            if (mode == Mode::OldDriver || mode == Mode::Unsupported || mode == Mode::SourceChanged)
            {
                io.ok = false;
                io.win32Error = ERROR_NOT_SUPPORTED;
                response->status = mode == Mode::SourceChanged ? KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED
                    : KSWORD_ARK_RAW_DISK_STATUS_NOT_SUPPORTED;
            }
        }
        return io;
    }
}

int main()
{
    using namespace ksword::ark;
    DriverClient client;
    std::array<std::uint8_t, 16> guid{};
    for (std::size_t index = 0; index < guid.size(); ++index) guid[index] = std::uint8_t(index + 1);
    const std::vector<std::uint8_t> original(512, 0x13);
    const std::vector<std::uint8_t> replacement(512, 0x73);
    const std::uint64_t offset = 1ULL << 40;
    auto read = client.readCapturedRawDisk(7, 2, offset, 512, guid, 1);
    require(read.io.ok && read.bytes.size() == 512 && read.bytes.back() == std::uint8_t(511 % 251), "complete read publishes real returned bytes");
    const auto* readPacket = reinterpret_cast<const KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST*>(packet.data());
    require(readPacket->diskNumber == 7 && readPacket->backend == 2 && readPacket->offset == offset
        && readPacket->flags == 1 && std::memcmp(readPacket->expectedDeviceGuid, guid.data(), 16) == 0,
        "captured read preserves full offset, backend, flags and native GUID bytes");
    const auto written = client.writeCapturedRawDisk(7, 3, offset, original, replacement, guid, 2);
    require(written.io.ok && written.response.bytesTransferred == 512, "complete write receipt is accepted");
    const auto* writePacket = reinterpret_cast<const KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST*>(packet.data());
    require(writePacket->offset == offset && writePacket->flags == 2 && writePacket->confirmationToken == KSWORD_ARK_RAW_DISK_CONFIRMATION_TOKEN
        && std::memcmp(writePacket->expectedDeviceGuid, guid.data(), 16) == 0
        && std::memcmp(writePacket->data, original.data(), 512) == 0
        && std::memcmp(writePacket->data + 512, replacement.data(), 512) == 0, "write packet preserves native identity and both complete payloads");
    for (const auto invalid : {Mode::Partial, Mode::Version, Mode::Size, Mode::Backend,
        Mode::Status, Mode::NtFailure, Mode::Truncated, Mode::Oversized})
    {
        mode = invalid;
        const auto before = calls;
        read = client.readCapturedRawDisk(0, 1, 0, 512, guid);
        require(!read.io.ok && read.bytes.empty() && calls == before + 1, "malformed read receipt never publishes evidence or retries");
        const auto write = client.writeCapturedRawDisk(0, 1, 0, original, replacement, guid, 2);
        require(!write.io.ok && calls == before + 2, "malformed write receipt cannot become successful or trigger fallback");
    }
    mode = Mode::OldDriver;
    read = client.readCapturedRawDisk(0, 1, 0, 512, guid);
    require(!read.io.ok && read.unsupported && read.bytes.empty(), "old driver V2 rejection is reported as unsupported without fallback");
    mode = Mode::Unsupported;
    read = client.readCapturedRawDisk(0, 1, 0, 512, guid);
    require(!read.io.ok && read.unsupported, "native identity capability rejection is distinguishable");
    mode = Mode::SourceChanged;
    read = client.readCapturedRawDisk(0, 1, 0, 512, guid);
    require(!read.io.ok && !read.unsupported && read.status == KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED
        && read.bytes.empty(), "source changed cannot be classified as fallback-compatible unsupported");
    const auto changedWrite = client.writeCapturedRawDisk(0, 1, 0, original, replacement, guid, 2);
    require(!changedWrite.io.ok && !changedWrite.unsupported
        && changedWrite.response.status == KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED,
        "write source change remains distinct from missing protocol support");
    mode = Mode::Good;
    const auto before = calls;
    const std::array<std::uint8_t, 16> zeroGuid{};
    require(!client.readCapturedRawDisk(0, 1, 0, 512, zeroGuid).io.ok, "zero read identity is rejected locally");
    require(!client.readCapturedRawDisk(0, 1, 0, 0, guid).io.ok, "zero read length is rejected locally");
    require(!client.readCapturedRawDisk(0, 1, UINT64_MAX, 512, guid).io.ok, "wrapping read range is rejected locally");
    require(!client.writeCapturedRawDisk(0, 1, 0, original, replacement, zeroGuid, 2).io.ok, "zero write identity is rejected locally");
    require(!client.writeCapturedRawDisk(0, 1, 0, original, {0x44}, guid, 2).io.ok, "unequal write payload lengths are rejected locally");
    require(!client.writeCapturedRawDisk(0, 1, UINT64_MAX, original, replacement, guid, 2).io.ok, "wrapping write range is rejected locally");
    require(calls == before, "invalid input never reaches even the mocked transport");
    std::cout << "captured_disk_client_mock_tests: " << checks << " checks, 0 failures\n";
}
