#include "DiskEditorBackend.h"
#include "DiskCaptureTransaction.h"
#include "../../ArkDriverClient/ArkDriverClient.h"
#include <Windows.h>
#include <winioctl.h>
#include <QUuid>
#include <array>
#include <cstring>

namespace
{
    // GUID 转换共用同一原生布局，避免读写两端各自维护不同端序。
    bool nativeCaptureGuid(const QString& text, std::array<std::uint8_t, 16>& bytes)
    {
        const QUuid expected(text);
        if (expected.isNull()) return false;
        const GUID native = expected;
        static_assert(sizeof(native) == 16);
        std::memcpy(bytes.data(), &native, bytes.size());
        return true;
    }
}

namespace ks::misc
{
    // queryCaptureIdentity：只查询系统存储设备标识，不读取/修改扇区。
    // GUID 缺失时允许宿主展示已读取证据，但拒绝建立可写基线。
    bool DiskEditorBackend::queryCaptureIdentity(const DiskDeviceInfo& source,
        QString& identity, QString& error)
    {
        identity.clear();
        error.clear();
        if (source.diskIndex < 0 || source.devicePath != QStringLiteral("\\\\.\\PhysicalDrive%1").arg(source.diskIndex))
        {
            error = QStringLiteral("磁盘捕获来源无效。");
            return false;
        }
        const auto path = source.devicePath.toStdWString(); // path：唯一允许的冻结设备路径。
        const HANDLE handle = ::CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            error = QStringLiteral("无法核验磁盘设备身份，Win32=%1。").arg(::GetLastError());
            return false;
        }

        STORAGE_DEVICE_NUMBER_EX number{}; // number：系统设备号及 GUID。
        DWORD returned = 0; // returned：实际输出长度，禁止接受不完整结构。
        const BOOL queried = ::DeviceIoControl(handle, IOCTL_STORAGE_GET_DEVICE_NUMBER_EX,
            nullptr, 0, &number, sizeof(number), &returned, nullptr);
        const DWORD queryError = queried ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(handle);
        const QUuid guid(number.DeviceGuid); // guid：硬件或当前附加实例的唯一身份。
        if (!queried || returned < sizeof(number) || number.Version < sizeof(number) ||
            number.Size < sizeof(number) || number.DeviceType != FILE_DEVICE_DISK ||
            number.DeviceNumber != static_cast<DWORD>(source.diskIndex) || guid.isNull())
        {
            error = QStringLiteral("无法核验磁盘设备 GUID，缓冲仅供查看，Win32=%1。").arg(queryError);
            return false;
        }
        identity = guid.toString(QUuid::WithoutBraces);
        return true;
    }

    bool DiskEditorBackend::writeCapturedBytesWithBackend(const DiskCapturedRange& captured,
        const QByteArray& replacement, const unsigned long callerFlags, QString& error)
    {
        error.clear();
        std::array<std::uint8_t, 16> nativeGuid{}; // nativeGuid：读取时取得的完整系统 GUID。
        if (!nativeCaptureGuid(captured.deviceIdentity, nativeGuid) || captured.source.diskIndex < 0 || captured.original.isEmpty() ||
            captured.original.size() > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES ||
            replacement.size() != captured.original.size())
        {
            error = QStringLiteral("捕获写回请求无效，未执行写入。");
            return false;
        }
        const auto* original = reinterpret_cast<const std::uint8_t*>(captured.original.constData());
        const auto* modified = reinterpret_cast<const std::uint8_t*>(replacement.constData());
        const std::vector<std::uint8_t> before(original, original + captured.original.size());
        const std::vector<std::uint8_t> after(modified, modified + replacement.size());
        const auto result = ksword::ark::DriverClient().writeCapturedRawDisk(
            static_cast<unsigned long>(captured.source.diskIndex), captured.backend, captured.offset,
            before, after, nativeGuid, callerFlags);
        if (!result.io.ok || result.response.status != KSWORD_ARK_RAW_DISK_STATUS_OK ||
            result.response.bytesTransferred != static_cast<unsigned long>(replacement.size()))
        {
            error = QStringLiteral("捕获磁盘写入验证失败或驱动不支持；未降级。协议状态=%1，NTSTATUS=0x%2，Win32=%3。")
                .arg(result.response.status)
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(result.io.ntStatus)), 8, 16, QChar('0'))
                .arg(result.io.win32Error);
            return false;
        }
        return true;
    }

    bool DiskEditorBackend::readCapturedBytesWithBackend(const DiskCapturedRange& captured,
        const std::uint32_t length, QByteArray& bytes, bool& unsupported, QString& error)
    {
        bytes.clear();
        unsupported = false;
        error.clear();
        std::array<std::uint8_t, 16> nativeGuid{};
        if (!nativeCaptureGuid(captured.deviceIdentity, nativeGuid) || captured.source.diskIndex < 0 ||
            !length || length > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES)
        {
            error = QStringLiteral("捕获读取请求无效，未取得字节。");
            return false;
        }
        const auto result = ksword::ark::DriverClient().readCapturedRawDisk(
            static_cast<unsigned long>(captured.source.diskIndex), captured.backend, captured.offset,
            length, nativeGuid, captured.backend == KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
                ? 0UL : KSWORD_ARK_RAW_DISK_FLAG_ALLOW_SYSTEM_DISK_READ);
        if (!result.io.ok || result.status != KSWORD_ARK_RAW_DISK_STATUS_OK || result.bytes.size() != length)
        {
            unsupported = result.unsupported;
            error = QStringLiteral("捕获磁盘读取验证失败，协议状态=%1，NTSTATUS=0x%2，Win32=%3。")
                .arg(result.status)
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(result.io.ntStatus)), 8, 16, QChar('0'))
                .arg(result.io.win32Error);
            return false;
        }
        bytes = QByteArray(reinterpret_cast<const char*>(result.bytes.data()), static_cast<qsizetype>(result.bytes.size()));
        return true;
    }
}
