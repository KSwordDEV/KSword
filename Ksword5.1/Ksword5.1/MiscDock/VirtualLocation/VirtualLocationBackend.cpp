#include "VirtualLocationBackend.h"

#include "../../ArkDriverClient/ArkDriverClient.h"

#include <QByteArray>
#include <QLatin1Char>
#include <QStringList>

#include <Windows.h>
#include <winsvc.h>

#include <cmath>
#include <cstring>
#include <vector>

// WinRT ABI 头只提供接口声明与 IID，Geolocator 的激活走运行时动态解析的
// combase.dll 导出，因此本文件不额外链接 runtimeobject.lib。
#include <windows.foundation.h>
#include <windows.devices.geolocation.h>
#include <wrl/client.h>

namespace
{
    using Microsoft::WRL::ComPtr;

    // kDefaultLocationKeyPath：
    // - lfsvc 的“默认位置”落点。该键的 ACL 只放行 SYSTEM 与 lfsvc 服务账户，
    //   管理员进程用 Advapi32 打开通常也会 ERROR_ACCESS_DENIED，所以要备好 R0 通道。
    const wchar_t* const kDefaultLocationSubKey =
        L"SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration\\DefaultLocation";
    const wchar_t* const kDefaultLocationKernelPath =
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration\\DefaultLocation";

    // kSensorPolicySubKey：
    // - 位置相关组策略落点，用来关掉 Windows 自带的网络定位提供程序。
    const wchar_t* const kSensorPolicySubKey =
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors";
    const wchar_t* const kSensorPolicyKernelPath =
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors";

    // kConsentStoreSubKey：
    // - 系统“位置访问”总开关，Allow / Deny。
    const wchar_t* const kConsentStoreSubKey =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location";

    // kLatitudeValueName 等：
    // - Windows 地图应用写默认位置时使用的值名，类型是十进制 REG_SZ。
    const wchar_t* const kLatitudeValueName = L"Latitude";
    const wchar_t* const kLongitudeValueName = L"Longitude";
    const wchar_t* const kAltitudeValueName = L"Altitude";
    const wchar_t* const kErrorRadiusValueName = L"ErrorRadius";
    const wchar_t* const kAltitudeAccuracyValueName = L"AltitudeAccuracy";
    const wchar_t* const kProviderPolicyValueName = L"DisableWindowsLocationProvider";
    const wchar_t* const kLocationPolicyValueName = L"DisableLocation";

    // RawValue：
    // - 作用：一个注册表值的类型加原始字节，两条通道读出来后统一成这个形状。
    struct RawValue
    {
        bool found = false;                // found：值是否存在。
        DWORD type = REG_NONE;             // type：REG_* 类型。
        std::vector<unsigned char> bytes;  // bytes：原始数据。
    };

    // driverAvailable：
    // - 作用：探测 KswordARK 设备能否打开，决定是否值得走 R0 通道；
    // - 返回：true 表示驱动在线。
    bool driverAvailable()
    {
        const ksword::ark::DriverClient client;
        ksword::ark::DriverHandle handle = client.open(GENERIC_READ | GENERIC_WRITE);
        return handle.isValid();
    }

    // win32ErrorText：
    // - 输入 errorCode：GetLastError 返回值；
    // - 作用：把 Win32 错误码格式化成“代码 + 系统描述”；
    // - 返回：单行文本，取不到描述时只返回代码。
    QString win32ErrorText(const DWORD errorCode)
    {
        LPWSTR buffer = nullptr;
        const DWORD length = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&buffer),
            0,
            nullptr);
        QString message;
        if (length != 0 && buffer != nullptr) {
            message = QString::fromWCharArray(buffer, static_cast<int>(length)).trimmed();
        }
        if (buffer != nullptr) {
            ::LocalFree(buffer);
        }
        if (message.isEmpty()) {
            return QStringLiteral("Win32=%1").arg(static_cast<unsigned long>(errorCode));
        }
        return QStringLiteral("Win32=%1 %2")
            .arg(static_cast<unsigned long>(errorCode))
            .arg(message);
    }

    // readValueViaWin32：
    // - 输入 subKey/valueName：HKLM 下的子键与值名；
    // - 作用：用 Advapi32 读一个值；
    // - 输出 lastErrorOut：失败时的 Win32 错误码；
    // - 返回：RawValue；found 为 false 时看 lastErrorOut。
    RawValue readValueViaWin32(
        const wchar_t* const subKey,
        const wchar_t* const valueName,
        DWORD* const lastErrorOut)
    {
        RawValue value;
        if (lastErrorOut != nullptr) {
            *lastErrorOut = ERROR_SUCCESS;
        }

        HKEY keyHandle = nullptr;
        LSTATUS status = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subKey,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &keyHandle);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return value;
        }

        DWORD valueType = REG_NONE;
        DWORD dataBytes = 0;
        status = ::RegQueryValueExW(keyHandle, valueName, nullptr, &valueType, nullptr, &dataBytes);
        if (status != ERROR_SUCCESS) {
            ::RegCloseKey(keyHandle);
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return value;
        }

        std::vector<unsigned char> buffer(dataBytes == 0 ? 1U : dataBytes, 0U);
        DWORD readBytes = dataBytes;
        status = ::RegQueryValueExW(
            keyHandle,
            valueName,
            nullptr,
            &valueType,
            buffer.data(),
            &readBytes);
        ::RegCloseKey(keyHandle);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return value;
        }

        buffer.resize(readBytes);
        value.found = true;
        value.type = valueType;
        value.bytes = std::move(buffer);
        return value;
    }

    // readValueViaDriver：
    // - 输入 kernelPath/valueName：内核形式键路径与值名；
    // - 作用：通过 KswordARK R0 注册表 IOCTL 读一个值，绕开 R3 的 ACL 拒绝；
    // - 返回：RawValue；found 为 false 表示驱动不在线、键不存在或读失败。
    RawValue readValueViaDriver(
        const wchar_t* const kernelPath,
        const wchar_t* const valueName)
    {
        RawValue value;
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryReadResult result =
            client.readRegistryValue(kernelPath, valueName);
        if (!result.io.ok ||
            result.status != KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS) {
            return value;
        }
        value.found = true;
        value.type = static_cast<DWORD>(result.valueType);
        value.bytes.assign(result.data.begin(), result.data.end());
        return value;
    }

    // registryTypeName：
    // - 输入 type：REG_* 类型；
    // - 作用：转成 UI 可读的类型名；
    // - 返回：类型名文本，未知类型返回十进制编号。
    QString registryTypeName(const DWORD type)
    {
        switch (type) {
        case REG_SZ:
            return QStringLiteral("REG_SZ");
        case REG_EXPAND_SZ:
            return QStringLiteral("REG_EXPAND_SZ");
        case REG_MULTI_SZ:
            return QStringLiteral("REG_MULTI_SZ");
        case REG_DWORD:
            return QStringLiteral("REG_DWORD");
        case REG_QWORD:
            return QStringLiteral("REG_QWORD");
        case REG_BINARY:
            return QStringLiteral("REG_BINARY");
        case REG_NONE:
            return QStringLiteral("REG_NONE");
        default:
            break;
        }
        return QStringLiteral("REG_%1").arg(static_cast<unsigned long>(type));
    }

    // stringFromRawValue：
    // - 输入 value：已读到的原始值；
    // - 作用：把字符串类型的值转成 QString，其余类型返回空串；
    // - 返回：去掉尾部 NUL 的文本。
    QString stringFromRawValue(const RawValue& value)
    {
        if (value.type != REG_SZ &&
            value.type != REG_EXPAND_SZ &&
            value.type != REG_MULTI_SZ) {
            return QString();
        }
        if (value.bytes.size() < sizeof(wchar_t)) {
            return QString();
        }
        const int characterCount =
            static_cast<int>(value.bytes.size() / sizeof(wchar_t));
        QString text = QString::fromWCharArray(
            reinterpret_cast<const wchar_t*>(value.bytes.data()),
            characterCount);
        const int terminatorIndex = text.indexOf(QChar(u'\0'));
        if (terminatorIndex >= 0) {
            text.truncate(terminatorIndex);
        }
        return text;
    }

    // integerFromRawValue：
    // - 输入 value：已读到的原始值；
    // - 作用：读出 REG_DWORD / REG_QWORD 的整数；
    // - 输出 valueOut：解析结果；
    // - 返回：true 表示类型匹配且长度足够。
    bool integerFromRawValue(const RawValue& value, unsigned long long* const valueOut)
    {
        if (valueOut == nullptr) {
            return false;
        }
        if (value.type == REG_DWORD && value.bytes.size() >= sizeof(quint32)) {
            quint32 raw = 0U;
            std::memcpy(&raw, value.bytes.data(), sizeof(raw));
            *valueOut = raw;
            return true;
        }
        if (value.type == REG_QWORD && value.bytes.size() >= sizeof(quint64)) {
            quint64 raw = 0U;
            std::memcpy(&raw, value.bytes.data(), sizeof(raw));
            *valueOut = raw;
            return true;
        }
        return false;
    }

    // doubleFromRawValue：
    // - 输入 value：已读到的原始值；plausibleLimit：合理绝对值上限，用于挑选解释方式；
    // - 作用：Windows 地图写的是十进制 REG_SZ，但不排除有工具写成 8 字节二进制，
    //   因此字符串、整数、IEEE754 位模式三种解释依次尝试；
    // - 输出 valueOut：解析出的数值；
    // - 返回：true 表示解析成功。
    bool doubleFromRawValue(
        const RawValue& value,
        const double plausibleLimit,
        double* const valueOut)
    {
        if (valueOut == nullptr || !value.found) {
            return false;
        }

        const QString text = stringFromRawValue(value);
        if (!text.isEmpty()) {
            bool converted = false;
            const double parsed = text.trimmed().toDouble(&converted);
            if (converted) {
                *valueOut = parsed;
                return true;
            }
            return false;
        }

        if ((value.type == REG_QWORD || value.type == REG_BINARY) &&
            value.bytes.size() >= sizeof(double)) {
            double asDouble = 0.0;
            std::memcpy(&asDouble, value.bytes.data(), sizeof(asDouble));
            if (std::isfinite(asDouble) && std::fabs(asDouble) <= plausibleLimit) {
                *valueOut = asDouble;
                return true;
            }
        }

        unsigned long long asInteger = 0U;
        if (integerFromRawValue(value, &asInteger)) {
            *valueOut = static_cast<double>(asInteger);
            return true;
        }
        return false;
    }

    // previewTextFromRawValue：
    // - 输入 value：已读到的原始值；
    // - 作用：给 UI 的原始清单生成一行可读内容，二进制类型退化为十六进制；
    // - 返回：预览文本。
    QString previewTextFromRawValue(const RawValue& value)
    {
        const QString text = stringFromRawValue(value);
        if (!text.isEmpty()) {
            return text;
        }
        unsigned long long asInteger = 0U;
        if (integerFromRawValue(value, &asInteger)) {
            return QStringLiteral("%1").arg(asInteger);
        }
        const QByteArray rawBytes(
            reinterpret_cast<const char*>(value.bytes.data()),
            static_cast<int>(value.bytes.size()));
        return QString::fromLatin1(rawBytes.toHex(' ').toUpper());
    }

    // writeStringValueViaWin32：
    // - 输入 subKey/valueName/text：HKLM 子键、值名与要写入的十进制文本；
    // - 作用：建键（已存在则打开）后写入 REG_SZ；
    // - 输出 lastErrorOut：失败时的 Win32 错误码；
    // - 返回：true 表示写入成功。
    bool writeStringValueViaWin32(
        const wchar_t* const subKey,
        const wchar_t* const valueName,
        const QString& text,
        DWORD* const lastErrorOut)
    {
        if (lastErrorOut != nullptr) {
            *lastErrorOut = ERROR_SUCCESS;
        }
        HKEY keyHandle = nullptr;
        DWORD disposition = 0;
        LSTATUS status = ::RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subKey,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            nullptr,
            &keyHandle,
            &disposition);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return false;
        }

        const std::wstring payload = text.toStdWString();
        status = ::RegSetValueExW(
            keyHandle,
            valueName,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(payload.c_str()),
            static_cast<DWORD>((payload.size() + 1U) * sizeof(wchar_t)));
        ::RegCloseKey(keyHandle);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return false;
        }
        return true;
    }

    // writeDwordValueViaWin32：
    // - 输入 subKey/valueName/data：HKLM 子键、值名与 32 位数据；
    // - 作用：建键后写入 REG_DWORD；
    // - 输出 lastErrorOut：失败时的 Win32 错误码；
    // - 返回：true 表示写入成功。
    bool writeDwordValueViaWin32(
        const wchar_t* const subKey,
        const wchar_t* const valueName,
        const DWORD data,
        DWORD* const lastErrorOut)
    {
        if (lastErrorOut != nullptr) {
            *lastErrorOut = ERROR_SUCCESS;
        }
        HKEY keyHandle = nullptr;
        DWORD disposition = 0;
        LSTATUS status = ::RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subKey,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            nullptr,
            &keyHandle,
            &disposition);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return false;
        }
        status = ::RegSetValueExW(
            keyHandle,
            valueName,
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(&data),
            sizeof(data));
        ::RegCloseKey(keyHandle);
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return false;
        }
        return true;
    }

    // deleteValueViaWin32：
    // - 输入 subKey/valueName：HKLM 子键与值名；
    // - 作用：删除一个值；值本来就不存在按成功处理；
    // - 输出 lastErrorOut：失败时的 Win32 错误码；
    // - 返回：true 表示删除后该值确实不存在。
    bool deleteValueViaWin32(
        const wchar_t* const subKey,
        const wchar_t* const valueName,
        DWORD* const lastErrorOut)
    {
        if (lastErrorOut != nullptr) {
            *lastErrorOut = ERROR_SUCCESS;
        }
        HKEY keyHandle = nullptr;
        LSTATUS status = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subKey,
            0,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            &keyHandle);
        if (status == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        if (status != ERROR_SUCCESS) {
            if (lastErrorOut != nullptr) {
                *lastErrorOut = static_cast<DWORD>(status);
            }
            return false;
        }
        status = ::RegDeleteValueW(keyHandle, valueName);
        ::RegCloseKey(keyHandle);
        if (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        if (lastErrorOut != nullptr) {
            *lastErrorOut = static_cast<DWORD>(status);
        }
        return false;
    }

    // driverOperationSucceeded：
    // - 输入 result：R0 写操作响应；
    // - 作用：统一判定成功；
    // - 返回：通信成功且聚合状态为 SUCCESS。
    bool driverOperationSucceeded(const ksword::ark::RegistryOperationResult& result)
    {
        return result.io.ok &&
            result.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
    }

    // writeStringValueViaDriver：
    // - 输入 kernelPath/valueName/text：内核键路径、值名与十进制文本；
    // - 作用：R0 建键并写入 REG_SZ，数据带尾部 NUL；
    // - 返回：true 表示写入成功。
    bool writeStringValueViaDriver(
        const wchar_t* const kernelPath,
        const wchar_t* const valueName,
        const QString& text)
    {
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryOperationResult createResult =
            client.createRegistryKey(kernelPath);
        const bool keyReady = driverOperationSucceeded(createResult) ||
            (createResult.io.ok &&
             createResult.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_ALREADY_EXISTS);
        if (!keyReady) {
            return false;
        }

        const std::wstring payload = text.toStdWString();
        const auto* const firstByte =
            reinterpret_cast<const std::uint8_t*>(payload.c_str());
        const std::vector<std::uint8_t> data(
            firstByte,
            firstByte + (payload.size() + 1U) * sizeof(wchar_t));
        return driverOperationSucceeded(
            client.setRegistryValue(kernelPath, valueName, REG_SZ, data));
    }

    // writeDwordValueViaDriver：
    // - 输入 kernelPath/valueName/data：内核键路径、值名与 32 位数据；
    // - 作用：R0 建键并写入 REG_DWORD；
    // - 返回：true 表示写入成功。
    bool writeDwordValueViaDriver(
        const wchar_t* const kernelPath,
        const wchar_t* const valueName,
        const std::uint32_t data)
    {
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryOperationResult createResult =
            client.createRegistryKey(kernelPath);
        const bool keyReady = driverOperationSucceeded(createResult) ||
            (createResult.io.ok &&
             createResult.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_ALREADY_EXISTS);
        if (!keyReady) {
            return false;
        }
        const auto* const firstByte = reinterpret_cast<const std::uint8_t*>(&data);
        const std::vector<std::uint8_t> payload(firstByte, firstByte + sizeof(data));
        return driverOperationSucceeded(
            client.setRegistryValue(kernelPath, valueName, REG_DWORD, payload));
    }

    // deleteValueViaDriver：
    // - 输入 kernelPath/valueName：内核键路径与值名；
    // - 作用：R0 删除一个值，值不存在按成功处理；
    // - 返回：true 表示删除后该值确实不存在。
    bool deleteValueViaDriver(
        const wchar_t* const kernelPath,
        const wchar_t* const valueName)
    {
        const ksword::ark::DriverClient client;
        const ksword::ark::RegistryOperationResult result =
            client.deleteRegistryValue(kernelPath, valueName);
        if (driverOperationSucceeded(result)) {
            return true;
        }
        return result.io.ok &&
            result.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_NOT_FOUND;
    }
}

namespace
{
    // ===================== 坐标系换算 =====================
    // GCJ-02 是在 WGS-84 上叠加的非公开偏移，业界通用做法是用下面这组经验多项式
    // 近似正变换，再用迭代逼近做反变换。BD-09 在 GCJ-02 之上还有一层固定极坐标偏移。

    constexpr double kPi = 3.1415926535897932384626;
    constexpr double kSemiMajorAxis = 6378245.0;            // 克拉索夫斯基椭球长半轴，单位米。
    constexpr double kEccentricitySquared = 0.00669342162296594323; // 第一偏心率平方。
    constexpr double kBaiduFactor = kPi * 3000.0 / 180.0;   // BD-09 偏移使用的角频率。

    // outOfChina：
    // - 输入 latitude/longitude：WGS-84 或 GCJ-02 坐标；
    // - 作用：粗判是否落在中国大陆偏移生效范围外；
    // - 返回：true 表示三套坐标系可视为等价。
    bool outOfChina(const double latitude, const double longitude)
    {
        return longitude < 72.004 || longitude > 137.8347 ||
            latitude < 0.8293 || latitude > 55.8271;
    }

    // transformLatitudeOffset / transformLongitudeOffset：
    // - 输入 x/y：相对基准点的经纬度差；
    // - 作用：GCJ-02 经验偏移多项式；
    // - 返回：未做椭球修正的中间量。
    double transformLatitudeOffset(const double x, const double y)
    {
        double result = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y +
            0.2 * std::sqrt(std::fabs(x));
        result += (20.0 * std::sin(6.0 * x * kPi) + 20.0 * std::sin(2.0 * x * kPi)) * 2.0 / 3.0;
        result += (20.0 * std::sin(y * kPi) + 40.0 * std::sin(y / 3.0 * kPi)) * 2.0 / 3.0;
        result += (160.0 * std::sin(y / 12.0 * kPi) + 320.0 * std::sin(y * kPi / 30.0)) * 2.0 / 3.0;
        return result;
    }

    double transformLongitudeOffset(const double x, const double y)
    {
        double result = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y +
            0.1 * std::sqrt(std::fabs(x));
        result += (20.0 * std::sin(6.0 * x * kPi) + 20.0 * std::sin(2.0 * x * kPi)) * 2.0 / 3.0;
        result += (20.0 * std::sin(x * kPi) + 40.0 * std::sin(x / 3.0 * kPi)) * 2.0 / 3.0;
        result += (150.0 * std::sin(x / 12.0 * kPi) + 300.0 * std::sin(x / 30.0 * kPi)) * 2.0 / 3.0;
        return result;
    }

    // wgs84ToGcj02：
    // - 输入 wgsLatitude/wgsLongitude：WGS-84 坐标；
    // - 输出 gcjLatitudeOut/gcjLongitudeOut：GCJ-02 坐标；
    // - 返回：无。境外坐标原样透传。
    void wgs84ToGcj02(
        const double wgsLatitude,
        const double wgsLongitude,
        double* const gcjLatitudeOut,
        double* const gcjLongitudeOut)
    {
        if (outOfChina(wgsLatitude, wgsLongitude)) {
            *gcjLatitudeOut = wgsLatitude;
            *gcjLongitudeOut = wgsLongitude;
            return;
        }
        double latitudeOffset =
            transformLatitudeOffset(wgsLongitude - 105.0, wgsLatitude - 35.0);
        double longitudeOffset =
            transformLongitudeOffset(wgsLongitude - 105.0, wgsLatitude - 35.0);
        const double radianLatitude = wgsLatitude / 180.0 * kPi;
        double magic = std::sin(radianLatitude);
        magic = 1.0 - kEccentricitySquared * magic * magic;
        const double squareRootMagic = std::sqrt(magic);
        latitudeOffset = (latitudeOffset * 180.0) /
            ((kSemiMajorAxis * (1.0 - kEccentricitySquared)) / (magic * squareRootMagic) * kPi);
        longitudeOffset = (longitudeOffset * 180.0) /
            (kSemiMajorAxis / squareRootMagic * std::cos(radianLatitude) * kPi);
        *gcjLatitudeOut = wgsLatitude + latitudeOffset;
        *gcjLongitudeOut = wgsLongitude + longitudeOffset;
    }

    // gcj02ToWgs84：
    // - 输入 gcjLatitude/gcjLongitude：GCJ-02 坐标；
    // - 输出 wgsLatitudeOut/wgsLongitudeOut：WGS-84 坐标；
    // - 作用：正变换没有闭式反解，用不动点迭代把残差压到亚厘米；
    // - 返回：无。
    void gcj02ToWgs84(
        const double gcjLatitude,
        const double gcjLongitude,
        double* const wgsLatitudeOut,
        double* const wgsLongitudeOut)
    {
        if (outOfChina(gcjLatitude, gcjLongitude)) {
            *wgsLatitudeOut = gcjLatitude;
            *wgsLongitudeOut = gcjLongitude;
            return;
        }
        double guessLatitude = gcjLatitude;
        double guessLongitude = gcjLongitude;
        for (int iteration = 0; iteration < 12; ++iteration) {
            double forwardLatitude = 0.0;
            double forwardLongitude = 0.0;
            wgs84ToGcj02(guessLatitude, guessLongitude, &forwardLatitude, &forwardLongitude);
            const double latitudeResidual = gcjLatitude - forwardLatitude;
            const double longitudeResidual = gcjLongitude - forwardLongitude;
            guessLatitude += latitudeResidual;
            guessLongitude += longitudeResidual;
            if (std::fabs(latitudeResidual) < 1e-9 && std::fabs(longitudeResidual) < 1e-9) {
                break;
            }
        }
        *wgsLatitudeOut = guessLatitude;
        *wgsLongitudeOut = guessLongitude;
    }

    // gcj02ToBd09 / bd09ToGcj02：
    // - 作用：百度在 GCJ-02 之上的固定极坐标偏移，正反变换都是闭式；
    // - 返回：无。
    void gcj02ToBd09(
        const double gcjLatitude,
        const double gcjLongitude,
        double* const bdLatitudeOut,
        double* const bdLongitudeOut)
    {
        const double radius =
            std::sqrt(gcjLongitude * gcjLongitude + gcjLatitude * gcjLatitude) +
            0.00002 * std::sin(gcjLatitude * kBaiduFactor);
        const double theta = std::atan2(gcjLatitude, gcjLongitude) +
            0.000003 * std::cos(gcjLongitude * kBaiduFactor);
        *bdLongitudeOut = radius * std::cos(theta) + 0.0065;
        *bdLatitudeOut = radius * std::sin(theta) + 0.006;
    }

    void bd09ToGcj02(
        const double bdLatitude,
        const double bdLongitude,
        double* const gcjLatitudeOut,
        double* const gcjLongitudeOut)
    {
        const double x = bdLongitude - 0.0065;
        const double y = bdLatitude - 0.006;
        const double radius = std::sqrt(x * x + y * y) - 0.00002 * std::sin(y * kBaiduFactor);
        const double theta = std::atan2(y, x) - 0.000003 * std::cos(x * kBaiduFactor);
        *gcjLongitudeOut = radius * std::cos(theta);
        *gcjLatitudeOut = radius * std::sin(theta);
    }
}

namespace
{
    // ===================== WinRT 实况定位 =====================
    // 只用到 combase.dll 的四个导出，全部运行时解析，避免为一个可选功能
    // 给整个主程序引入 runtimeobject.lib 静态依赖。

    using RoInitializeFn = HRESULT(WINAPI*)(int);
    using RoUninitializeFn = void(WINAPI*)();
    using RoActivateInstanceFn = HRESULT(WINAPI*)(HSTRING, IInspectable**);
    using WindowsCreateStringFn = HRESULT(WINAPI*)(PCNZWCH, UINT32, HSTRING*);
    using WindowsDeleteStringFn = HRESULT(WINAPI*)(HSTRING);

    // ComBaseApi：
    // - 作用：一次性解析 combase.dll 的定位相关导出；
    // - 说明：combase.dll 是系统常驻模块，这里不 FreeLibrary。
    struct ComBaseApi
    {
        RoInitializeFn roInitialize = nullptr;
        RoUninitializeFn roUninitialize = nullptr;
        RoActivateInstanceFn roActivateInstance = nullptr;
        WindowsCreateStringFn windowsCreateString = nullptr;
        WindowsDeleteStringFn windowsDeleteString = nullptr;

        bool isComplete() const
        {
            return roInitialize != nullptr && roUninitialize != nullptr &&
                roActivateInstance != nullptr && windowsCreateString != nullptr &&
                windowsDeleteString != nullptr;
        }
    };

    // loadComBaseApi：
    // - 作用：解析并缓存 combase.dll 导出；
    // - 返回：解析结果，isComplete 为 false 时不要继续调用 WinRT。
    const ComBaseApi& loadComBaseApi()
    {
        static const ComBaseApi api = []() {
            ComBaseApi resolved;
            const HMODULE moduleHandle = ::GetModuleHandleW(L"combase.dll") != nullptr
                ? ::GetModuleHandleW(L"combase.dll")
                : ::LoadLibraryW(L"combase.dll");
            if (moduleHandle == nullptr) {
                return resolved;
            }
            resolved.roInitialize = reinterpret_cast<RoInitializeFn>(
                reinterpret_cast<void*>(::GetProcAddress(moduleHandle, "RoInitialize")));
            resolved.roUninitialize = reinterpret_cast<RoUninitializeFn>(
                reinterpret_cast<void*>(::GetProcAddress(moduleHandle, "RoUninitialize")));
            resolved.roActivateInstance = reinterpret_cast<RoActivateInstanceFn>(
                reinterpret_cast<void*>(::GetProcAddress(moduleHandle, "RoActivateInstance")));
            resolved.windowsCreateString = reinterpret_cast<WindowsCreateStringFn>(
                reinterpret_cast<void*>(::GetProcAddress(moduleHandle, "WindowsCreateString")));
            resolved.windowsDeleteString = reinterpret_cast<WindowsDeleteStringFn>(
                reinterpret_cast<void*>(::GetProcAddress(moduleHandle, "WindowsDeleteString")));
            return resolved;
        }();
        return api;
    }

    // positionSourceText：
    // - 输入 source：WinRT 报告的定位来源；
    // - 作用：翻译成用户能对照的说明，Default 正是“默认位置生效”的证据；
    // - 返回：来源文本。
    QString positionSourceText(
        const ABI::Windows::Devices::Geolocation::PositionSource source)
    {
        using ABI::Windows::Devices::Geolocation::PositionSource;
        switch (source) {
        case PositionSource::PositionSource_Cellular:
            return QStringLiteral("蜂窝网络");
        case PositionSource::PositionSource_Satellite:
            return QStringLiteral("卫星");
        case PositionSource::PositionSource_WiFi:
            return QStringLiteral("WiFi");
        case PositionSource::PositionSource_IPAddress:
            return QStringLiteral("IP 地址");
        case PositionSource::PositionSource_Unknown:
            return QStringLiteral("未知来源");
        case PositionSource::PositionSource_Default:
            return QStringLiteral("默认位置");
        case PositionSource::PositionSource_Obfuscated:
            return QStringLiteral("已模糊化");
        default:
            break;
        }
        return QStringLiteral("未识别来源");
    }
}

namespace ks::misc::virtual_location
{
    QString defaultLocationKeyPath()
    {
        return QStringLiteral("HKLM\\%1").arg(QString::fromWCharArray(kDefaultLocationSubKey));
    }

    QString sensorPolicyKeyPath()
    {
        return QStringLiteral("HKLM\\%1").arg(QString::fromWCharArray(kSensorPolicySubKey));
    }

    DefaultLocationSnapshot readDefaultLocation()
    {
        DefaultLocationSnapshot snapshot;

        struct ValueSpec
        {
            const wchar_t* name;   // name：注册表值名。
            double limit;          // limit：合理绝对值上限，供二进制解释判定。
            double* target;        // target：解析结果落点。
            bool required;         // required：是否属于“默认位置已设置”的判定条件。
        };
        const ValueSpec valueSpecs[] = {
            { kLatitudeValueName, 90.0, &snapshot.coordinate.latitude, true },
            { kLongitudeValueName, 180.0, &snapshot.coordinate.longitude, true },
            { kAltitudeValueName, 100000.0, &snapshot.coordinate.altitude, false },
            { kErrorRadiusValueName, 1.0e7, &snapshot.coordinate.errorRadiusMeters, false },
            { kAltitudeAccuracyValueName, 1.0e7, &snapshot.coordinate.altitudeAccuracyMeters, false },
        };

        DWORD firstWin32Error = ERROR_SUCCESS;
        bool anyWin32Success = false;
        bool anyDriverSuccess = false;
        int requiredHitCount = 0;

        for (const ValueSpec& spec : valueSpecs) {
            DWORD lastError = ERROR_SUCCESS;
            RawValue value = readValueViaWin32(kDefaultLocationSubKey, spec.name, &lastError);
            bool fromDriver = false;
            if (value.found) {
                anyWin32Success = true;
            }
            else {
                if (firstWin32Error == ERROR_SUCCESS) {
                    firstWin32Error = lastError;
                }
                // “尚未设置默认位置”时整个键会不存在。这是页面的正常初始状态，
                // 不应为五个候选值逐个请求 R0，更不能把 NOT_FOUND 放大成日志告警。
                // 只有 R3 确实无法访问已有键（例如 lfsvc ACL 拒绝）时才回退驱动。
                if (lastError != ERROR_FILE_NOT_FOUND &&
                    lastError != ERROR_PATH_NOT_FOUND) {
                    value = readValueViaDriver(kDefaultLocationKernelPath, spec.name);
                    fromDriver = value.found;
                    if (value.found) {
                        anyDriverSuccess = true;
                    }
                }
            }
            if (!value.found) {
                continue;
            }

            snapshot.rawValueLines.append(
                QStringLiteral("%1 (%2) = %3    [%4]")
                    .arg(QString::fromWCharArray(spec.name))
                    .arg(registryTypeName(value.type))
                    .arg(previewTextFromRawValue(value))
                    .arg(fromDriver ? QStringLiteral("R0") : QStringLiteral("R3")));

            double parsed = 0.0;
            if (doubleFromRawValue(value, spec.limit, &parsed)) {
                *spec.target = parsed;
                if (spec.required) {
                    ++requiredHitCount;
                }
            }
        }

        snapshot.readable = anyWin32Success || anyDriverSuccess;
        snapshot.backend = anyDriverSuccess
            ? RegistryBackend::Driver
            : (anyWin32Success ? RegistryBackend::Win32 : RegistryBackend::None);
        snapshot.present = requiredHitCount == 2;

        if (!snapshot.readable) {
            // 读不到分两种：键根本没有默认位置（正常），或者两条通道都被挡住。
            // 用 R3 的错误码区分：ACCESS_DENIED 说明键在但读不了，需要驱动。
            if (firstWin32Error == ERROR_FILE_NOT_FOUND ||
                firstWin32Error == ERROR_PATH_NOT_FOUND) {
                snapshot.readable = true;
                snapshot.backend = RegistryBackend::Win32;
                snapshot.present = false;
            }
            else if (firstWin32Error == ERROR_ACCESS_DENIED && !driverAvailable()) {
                snapshot.failureText = QStringLiteral(
                    "该键的 ACL 只放行 SYSTEM 与位置服务本身，R3 读取被拒绝；"
                    "请加载 KswordARK 驱动后重试。");
            }
            else {
                snapshot.failureText = win32ErrorText(firstWin32Error);
            }
        }
        return snapshot;
    }

    OperationResult applyDefaultLocation(const GeoCoordinate& coordinate)
    {
        OperationResult result;

        struct WriteSpec
        {
            const wchar_t* name; // name：注册表值名。
            double value;        // value：要写入的数值。
        };
        const WriteSpec writeSpecs[] = {
            { kLatitudeValueName, coordinate.latitude },
            { kLongitudeValueName, coordinate.longitude },
            { kAltitudeValueName, coordinate.altitude },
            { kErrorRadiusValueName, coordinate.errorRadiusMeters },
            { kAltitudeAccuracyValueName, coordinate.altitudeAccuracyMeters },
        };

        bool usedDriver = false;
        DWORD firstWin32Error = ERROR_SUCCESS;
        for (const WriteSpec& spec : writeSpecs) {
            // Windows 地图写入的就是不带千分位、点号做小数点的十进制串，
            // 这里固定用 C 语言环境格式化，避免跟随界面语言写出逗号小数点。
            const QString text = QString::number(spec.value, 'f', 8);
            DWORD lastError = ERROR_SUCCESS;
            if (writeStringValueViaWin32(kDefaultLocationSubKey, spec.name, text, &lastError)) {
                continue;
            }
            if (firstWin32Error == ERROR_SUCCESS) {
                firstWin32Error = lastError;
            }
            if (!writeStringValueViaDriver(kDefaultLocationKernelPath, spec.name, text)) {
                result.ok = false;
                result.backend = RegistryBackend::None;
                result.detailText = driverAvailable()
                    ? QStringLiteral("写入 %1 失败：R3 %2；R0 注册表 IOCTL 同样失败。")
                        .arg(QString::fromWCharArray(spec.name))
                        .arg(win32ErrorText(lastError))
                    : QStringLiteral("写入 %1 失败：R3 %2；KswordARK 驱动未加载，没有回退通道。")
                        .arg(QString::fromWCharArray(spec.name))
                        .arg(win32ErrorText(lastError));
                return result;
            }
            usedDriver = true;
        }

        result.ok = true;
        result.backend = usedDriver ? RegistryBackend::Driver : RegistryBackend::Win32;
        return result;
    }

    OperationResult clearDefaultLocation()
    {
        OperationResult result;
        const wchar_t* const valueNames[] = {
            kLatitudeValueName,
            kLongitudeValueName,
            kAltitudeValueName,
            kErrorRadiusValueName,
            kAltitudeAccuracyValueName,
        };

        bool usedDriver = false;
        for (const wchar_t* const valueName : valueNames) {
            DWORD lastError = ERROR_SUCCESS;
            if (deleteValueViaWin32(kDefaultLocationSubKey, valueName, &lastError)) {
                continue;
            }
            if (!deleteValueViaDriver(kDefaultLocationKernelPath, valueName)) {
                result.ok = false;
                result.backend = RegistryBackend::None;
                result.detailText =
                    QStringLiteral("删除 %1 失败：R3 %2；R0 通道也没有完成删除。")
                        .arg(QString::fromWCharArray(valueName))
                        .arg(win32ErrorText(lastError));
                return result;
            }
            usedDriver = true;
        }

        result.ok = true;
        result.backend = usedDriver ? RegistryBackend::Driver : RegistryBackend::Win32;
        return result;
    }

    ServiceSnapshot readServiceSnapshot()
    {
        ServiceSnapshot snapshot;

        const SC_HANDLE managerHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (managerHandle != nullptr) {
            const SC_HANDLE serviceHandle =
                ::OpenServiceW(managerHandle, L"lfsvc", SERVICE_QUERY_STATUS);
            if (serviceHandle != nullptr) {
                SERVICE_STATUS_PROCESS statusProcess{};
                DWORD bytesNeeded = 0;
                if (::QueryServiceStatusEx(
                        serviceHandle,
                        SC_STATUS_PROCESS_INFO,
                        reinterpret_cast<LPBYTE>(&statusProcess),
                        sizeof(statusProcess),
                        &bytesNeeded) != FALSE) {
                    snapshot.serviceQueryOk = true;
                    snapshot.serviceRunning =
                        statusProcess.dwCurrentState == SERVICE_RUNNING;
                    switch (statusProcess.dwCurrentState) {
                    case SERVICE_RUNNING:
                        snapshot.serviceStateText = QStringLiteral("正在运行");
                        break;
                    case SERVICE_STOPPED:
                        snapshot.serviceStateText = QStringLiteral("已停止（按需触发启动）");
                        break;
                    case SERVICE_START_PENDING:
                        snapshot.serviceStateText = QStringLiteral("正在启动");
                        break;
                    case SERVICE_STOP_PENDING:
                        snapshot.serviceStateText = QStringLiteral("正在停止");
                        break;
                    default:
                        snapshot.serviceStateText = QStringLiteral("状态 %1")
                            .arg(static_cast<unsigned long>(statusProcess.dwCurrentState));
                        break;
                    }
                }
                ::CloseServiceHandle(serviceHandle);
            }
            ::CloseServiceHandle(managerHandle);
        }
        if (!snapshot.serviceQueryOk) {
            snapshot.serviceStateText = QStringLiteral("无法查询位置服务状态");
        }

        DWORD lastError = ERROR_SUCCESS;
        const RawValue consentValue =
            readValueViaWin32(kConsentStoreSubKey, L"Value", &lastError);
        if (consentValue.found) {
            snapshot.consentReadable = true;
            snapshot.locationAllowed =
                stringFromRawValue(consentValue).compare(
                    QStringLiteral("Allow"), Qt::CaseInsensitive) == 0;
        }

        const std::wstring nonPackagedSubKey =
            std::wstring(kConsentStoreSubKey) + L"\\NonPackaged";
        const RawValue nonPackagedValue =
            readValueViaWin32(nonPackagedSubKey.c_str(), L"Value", &lastError);
        // NonPackaged 子键缺省不带 Value；此时桌面应用跟随系统总开关。
        snapshot.desktopAppAllowed = nonPackagedValue.found
            ? stringFromRawValue(nonPackagedValue).compare(
                  QStringLiteral("Allow"), Qt::CaseInsensitive) == 0
            : snapshot.locationAllowed;

        QStringList policyLines;
        const RawValue providerPolicy =
            readValueViaWin32(kSensorPolicySubKey, kProviderPolicyValueName, &lastError);
        if (providerPolicy.found) {
            unsigned long long providerFlag = 0U;
            integerFromRawValue(providerPolicy, &providerFlag);
            snapshot.providerDisabledByPolicy = providerFlag != 0U;
            policyLines.append(
                QStringLiteral("DisableWindowsLocationProvider = %1").arg(providerFlag));
        }
        const RawValue locationPolicy =
            readValueViaWin32(kSensorPolicySubKey, kLocationPolicyValueName, &lastError);
        if (locationPolicy.found) {
            unsigned long long locationFlag = 0U;
            integerFromRawValue(locationPolicy, &locationFlag);
            snapshot.locationDisabledByPolicy = locationFlag != 0U;
            policyLines.append(QStringLiteral("DisableLocation = %1").arg(locationFlag));
        }
        snapshot.policyDetailText = policyLines.isEmpty()
            ? QStringLiteral("未设置位置相关组策略")
            : policyLines.join(QStringLiteral("；"));
        return snapshot;
    }

    OperationResult setLocationProviderDisabled(const bool disabled)
    {
        OperationResult result;
        DWORD lastError = ERROR_SUCCESS;

        if (disabled) {
            if (writeDwordValueViaWin32(
                    kSensorPolicySubKey, kProviderPolicyValueName, 1UL, &lastError)) {
                result.ok = true;
                result.backend = RegistryBackend::Win32;
                return result;
            }
            if (writeDwordValueViaDriver(
                    kSensorPolicyKernelPath, kProviderPolicyValueName, 1U)) {
                result.ok = true;
                result.backend = RegistryBackend::Driver;
                return result;
            }
            result.detailText =
                QStringLiteral("写入组策略失败：R3 %1；R0 通道也没有完成写入。")
                    .arg(win32ErrorText(lastError));
            return result;
        }

        if (deleteValueViaWin32(kSensorPolicySubKey, kProviderPolicyValueName, &lastError)) {
            result.ok = true;
            result.backend = RegistryBackend::Win32;
            return result;
        }
        if (deleteValueViaDriver(kSensorPolicyKernelPath, kProviderPolicyValueName)) {
            result.ok = true;
            result.backend = RegistryBackend::Driver;
            return result;
        }
        result.detailText =
            QStringLiteral("删除组策略失败：R3 %1；R0 通道也没有完成删除。")
                .arg(win32ErrorText(lastError));
        return result;
    }

    OperationResult restartLocationService()
    {
        OperationResult result;
        const SC_HANDLE managerHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (managerHandle == nullptr) {
            result.detailText = QStringLiteral("打开服务控制管理器失败：%1")
                .arg(win32ErrorText(::GetLastError()));
            return result;
        }

        const SC_HANDLE serviceHandle = ::OpenServiceW(
            managerHandle, L"lfsvc", SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (serviceHandle == nullptr) {
            const DWORD errorCode = ::GetLastError();
            ::CloseServiceHandle(managerHandle);
            result.detailText = QStringLiteral("打开位置服务失败：%1")
                .arg(win32ErrorText(errorCode));
            return result;
        }

        SERVICE_STATUS serviceStatus{};
        if (::ControlService(serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus) != FALSE) {
            result.ok = true;
        }
        else {
            const DWORD errorCode = ::GetLastError();
            // 服务本来就没在跑时 ControlService 会返回 NOT_ACTIVE，这跟“已经停下”等价。
            result.ok = errorCode == ERROR_SERVICE_NOT_ACTIVE;
            if (!result.ok) {
                result.detailText = QStringLiteral("停止位置服务失败：%1")
                    .arg(win32ErrorText(errorCode));
            }
        }
        ::CloseServiceHandle(serviceHandle);
        ::CloseServiceHandle(managerHandle);
        return result;
    }

    LiveFixResult queryLiveFix(const unsigned long timeoutMilliseconds)
    {
        using namespace ABI::Windows::Foundation;
        using namespace ABI::Windows::Devices::Geolocation;

        LiveFixResult result;
        const ComBaseApi& api = loadComBaseApi();
        if (!api.isComplete()) {
            result.failureText = QStringLiteral("当前系统缺少 WinRT 定位入口，无法读取实况坐标。");
            return result;
        }

        // 该函数被后台线程调用，套间干净，按 MTA 初始化即可；
        // 若线程已被初始化成别的套间，RoInitialize 返回 RPC_E_CHANGED_MODE，沿用现状继续。
        const HRESULT initializeResult = api.roInitialize(1 /* RO_INIT_MULTITHREADED */);
        const bool shouldUninitialize =
            SUCCEEDED(initializeResult) || initializeResult == S_FALSE;
        if (FAILED(initializeResult) && initializeResult != RPC_E_CHANGED_MODE) {
            result.failureText = QStringLiteral("初始化 WinRT 失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(initializeResult), 8, 16, QLatin1Char('0'));
            return result;
        }

        /*
         * 必须用作用域守卫而不是在每个 return 前手工调用：本函数里的 ComPtr 都是
         * 函数作用域对象，手工 finalize 会让 RoUninitialize 先于它们析构执行，
         * 即在套间拆掉之后才 Release 接口。超时路径尤其危险——Cancel 之后请求仍在飞，
         * 拆套间会切断该线程上的 RPC 连接，再去 Release 跨进程的 IAsyncOperation
         * 就可能访问违例，而这里是 detach 线程，崩溃即整进程崩溃。
         * 守卫声明在所有 ComPtr 之前，局部对象逆序析构，于是 Release 一定先发生。
         */
        struct RoApartmentScope
        {
            const ComBaseApi* api = nullptr;
            bool active = false;
            ~RoApartmentScope()
            {
                if (active && api != nullptr) {
                    api->roUninitialize();
                }
            }
        } roApartmentScope{ &api, shouldUninitialize };

        HSTRING classId = nullptr;
        const wchar_t* const className = L"Windows.Devices.Geolocation.Geolocator";
        HRESULT hr = api.windowsCreateString(
            className, static_cast<UINT32>(::wcslen(className)), &classId);
        if (FAILED(hr)) {
            result.failureText = QStringLiteral("创建 WinRT 类名失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        ComPtr<IInspectable> inspectable;
        hr = api.roActivateInstance(classId, inspectable.GetAddressOf());
        api.windowsDeleteString(classId);
        if (FAILED(hr) || inspectable == nullptr) {
            result.failureText = QStringLiteral(
                "激活 Geolocator 失败：HRESULT=0x%1。位置服务被关闭或桌面应用未获授权时会出现这个错误。")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        ComPtr<IGeolocator> geolocator;
        hr = inspectable.As(&geolocator);
        if (FAILED(hr) || geolocator == nullptr) {
            result.failureText = QStringLiteral("获取 IGeolocator 失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }
        (void)geolocator->put_DesiredAccuracy(PositionAccuracy::PositionAccuracy_High);

        ComPtr<IAsyncOperation<Geoposition*>> operation;
        hr = geolocator->GetGeopositionAsync(operation.GetAddressOf());
        if (FAILED(hr) || operation == nullptr) {
            result.failureText = QStringLiteral("发起定位请求失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        ComPtr<IAsyncInfo> asyncInfo;
        hr = operation.As(&asyncInfo);
        if (FAILED(hr) || asyncInfo == nullptr) {
            result.failureText = QStringLiteral("获取 IAsyncInfo 失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        // 轮询而不是挂完成回调：回调要落在支持自由线程封送的对象上，
        // 而这里已经处在专用后台线程里，直接自旋等待更简单也更好取消。
        const ULONGLONG deadlineTick = ::GetTickCount64() + timeoutMilliseconds;
        AsyncStatus asyncStatus = AsyncStatus::Started;
        while (true) {
            if (FAILED(asyncInfo->get_Status(&asyncStatus))) {
                break;
            }
            if (asyncStatus != AsyncStatus::Started) {
                break;
            }
            if (::GetTickCount64() >= deadlineTick) {
                (void)asyncInfo->Cancel();
                result.failureText = QStringLiteral("定位请求超时，系统在限定时间内没有返回坐标。");
                return result;
            }
            ::Sleep(50);
        }

        if (asyncStatus != AsyncStatus::Completed) {
            HRESULT errorCode = S_OK;
            (void)asyncInfo->get_ErrorCode(&errorCode);
            result.failureText = QStringLiteral("定位请求未完成：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(errorCode), 8, 16, QLatin1Char('0'));
            return result;
        }

        ComPtr<IGeoposition> geoposition;
        hr = operation->GetResults(geoposition.GetAddressOf());
        if (FAILED(hr) || geoposition == nullptr) {
            result.failureText = QStringLiteral("读取定位结果失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        ComPtr<IGeocoordinate> geocoordinate;
        hr = geoposition->get_Coordinate(geocoordinate.GetAddressOf());
        if (FAILED(hr) || geocoordinate == nullptr) {
            result.failureText = QStringLiteral("读取坐标失败：HRESULT=0x%1")
                .arg(static_cast<unsigned long>(hr), 8, 16, QLatin1Char('0'));
            return result;
        }

        // 经纬度只从 IGeocoordinateWithPoint 取，避开 IGeocoordinate 上已废弃的
        // get_Latitude / get_Longitude。
        ComPtr<IGeocoordinateWithPoint> coordinateWithPoint;
        if (SUCCEEDED(geocoordinate.As(&coordinateWithPoint)) &&
            coordinateWithPoint != nullptr) {
            ComPtr<IGeopoint> geopoint;
            if (SUCCEEDED(coordinateWithPoint->get_Point(geopoint.GetAddressOf())) &&
                geopoint != nullptr) {
                BasicGeoposition basicPosition{};
                if (SUCCEEDED(geopoint->get_Position(&basicPosition))) {
                    result.coordinate.latitude = basicPosition.Latitude;
                    result.coordinate.longitude = basicPosition.Longitude;
                    result.coordinate.altitude = basicPosition.Altitude;
                    result.ok = true;
                }
            }
        }
        if (!result.ok) {
            result.failureText = QStringLiteral("系统返回的定位结果里没有可用的经纬度。");
            return result;
        }

        DOUBLE accuracy = 0.0;
        if (SUCCEEDED(geocoordinate->get_Accuracy(&accuracy))) {
            result.coordinate.errorRadiusMeters = accuracy;
        }
        ComPtr<IReference<double>> altitudeAccuracy;
        if (SUCCEEDED(geocoordinate->get_AltitudeAccuracy(altitudeAccuracy.GetAddressOf())) &&
            altitudeAccuracy != nullptr) {
            DOUBLE altitudeAccuracyValue = 0.0;
            if (SUCCEEDED(altitudeAccuracy->get_Value(&altitudeAccuracyValue))) {
                result.coordinate.altitudeAccuracyMeters = altitudeAccuracyValue;
            }
        }

        ComPtr<IGeocoordinateWithPositionData> coordinateWithPositionData;
        if (SUCCEEDED(geocoordinate.As(&coordinateWithPositionData)) &&
            coordinateWithPositionData != nullptr) {
            PositionSource source = PositionSource::PositionSource_Unknown;
            if (SUCCEEDED(coordinateWithPositionData->get_PositionSource(&source))) {
                result.sourceText = positionSourceText(source);
            }
        }
        if (result.sourceText.isEmpty()) {
            result.sourceText = QStringLiteral("未知来源");
        }

        return result;
    }

    GeoCoordinate convertCoordinate(
        const GeoCoordinate& source,
        const CoordinateSystem from,
        const CoordinateSystem to)
    {
        GeoCoordinate converted = source;
        if (from == to) {
            return converted;
        }

        // 统一先归到 GCJ-02 这个中间态，再从中间态走到目标坐标系。
        double gcjLatitude = source.latitude;
        double gcjLongitude = source.longitude;
        switch (from) {
        case CoordinateSystem::Wgs84:
            wgs84ToGcj02(source.latitude, source.longitude, &gcjLatitude, &gcjLongitude);
            break;
        case CoordinateSystem::Bd09:
            bd09ToGcj02(source.latitude, source.longitude, &gcjLatitude, &gcjLongitude);
            break;
        case CoordinateSystem::Gcj02:
        default:
            break;
        }

        switch (to) {
        case CoordinateSystem::Wgs84:
            gcj02ToWgs84(gcjLatitude, gcjLongitude, &converted.latitude, &converted.longitude);
            break;
        case CoordinateSystem::Bd09:
            gcj02ToBd09(gcjLatitude, gcjLongitude, &converted.latitude, &converted.longitude);
            break;
        case CoordinateSystem::Gcj02:
        default:
            converted.latitude = gcjLatitude;
            converted.longitude = gcjLongitude;
            break;
        }
        return converted;
    }

    const PresetLocation* presetLocations(int* const countOut)
    {
        // 坐标一律是 WGS-84；面板上选择别的坐标系时会先换算再回填输入框。
        static const PresetLocation presets[] = {
            { "misc.virtual_location.preset.beijing", "北京 天安门", 39.909187, 116.397451, 44.0 },
            { "misc.virtual_location.preset.shanghai", "上海 外滩", 31.239703, 121.484899, 4.0 },
            { "misc.virtual_location.preset.guangzhou", "广州 塔", 23.106414, 113.318977, 11.0 },
            { "misc.virtual_location.preset.shenzhen", "深圳 平安金融中心", 22.536970, 114.048262, 5.0 },
            { "misc.virtual_location.preset.chengdu", "成都 天府广场", 30.657378, 104.061981, 500.0 },
            { "misc.virtual_location.preset.hongkong", "香港 维多利亚港", 22.293321, 114.171387, 5.0 },
            { "misc.virtual_location.preset.taipei", "台北 101", 25.033551, 121.561028, 10.0 },
            { "misc.virtual_location.preset.tokyo", "东京 塔", 35.658580, 139.745433, 15.0 },
            { "misc.virtual_location.preset.singapore", "新加坡 滨海湾", 1.283404, 103.860530, 5.0 },
            { "misc.virtual_location.preset.london", "伦敦 大本钟", 51.500729, -0.124625, 11.0 },
            { "misc.virtual_location.preset.newyork", "纽约 时代广场", 40.758896, -73.985130, 10.0 },
            { "misc.virtual_location.preset.sanfrancisco", "旧金山 金门大桥", 37.819929, -122.478255, 67.0 },
        };
        if (countOut != nullptr) {
            *countOut = static_cast<int>(sizeof(presets) / sizeof(presets[0]));
        }
        return presets;
    }
}
