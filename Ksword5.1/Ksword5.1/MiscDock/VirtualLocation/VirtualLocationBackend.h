#pragma once

// ============================================================
// VirtualLocationBackend.h
// 作用：
// 1) 读写 Windows 位置服务的“默认位置”（lfsvc DefaultLocation）注册表；
// 2) R3 打不开该键（其 ACL 只放行 SYSTEM 与 lfsvc）时自动回退到 KswordARK R0 注册表 IOCTL；
// 3) 汇总位置服务运行状态、隐私开关与组策略，判断虚拟坐标是否真的会被采纳；
// 4) 通过 WinRT Geolocator 读一次系统实际返回的定位，用于应用前后对照；
// 5) 提供 WGS-84 / GCJ-02 / BD-09 坐标互转，方便直接粘贴国内地图坐标。
//
// 本文件只做数据与系统访问，不含任何 QWidget 依赖；UI 在 VirtualLocationPage 中。
// ============================================================

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVector>

namespace ks::misc::virtual_location
{
    // CoordinateSystem：
    // - 作用：标记一组经纬度所属的大地坐标系；
    // - Wgs84 是 Windows 位置服务与 GPS 使用的原始坐标系，写注册表前一律先转成它。
    enum class CoordinateSystem
    {
        Wgs84 = 0,  // Wgs84：国际标准坐标，Windows 定位 API 直接使用。
        Gcj02 = 1,  // Gcj02：国测局加密坐标，高德/腾讯地图取到的坐标。
        Bd09 = 2    // Bd09：百度在 GCJ-02 之上再次偏移的坐标。
    };

    // RegistryBackend：
    // - 作用：记录某次注册表访问最终走通的通道，UI 据此告诉用户是谁完成了操作。
    enum class RegistryBackend
    {
        None = 0,    // None：两条通道都没走通。
        Win32 = 1,   // Win32：R3 Advapi32 直接完成。
        Driver = 2   // Driver：R3 被 ACL 拒绝后由 KswordARK R0 完成。
    };

    // GeoCoordinate：
    // - 作用：一组定位读数；除经纬度外的字段允许为 0，表示系统没有给出该分量。
    struct GeoCoordinate
    {
        double latitude = 0.0;               // latitude：纬度，单位度，北正南负。
        double longitude = 0.0;              // longitude：经度，单位度，东正西负。
        double altitude = 0.0;               // altitude：海拔，单位米。
        double errorRadiusMeters = 0.0;      // errorRadiusMeters：水平误差半径，单位米。
        double altitudeAccuracyMeters = 0.0; // altitudeAccuracyMeters：垂直误差，单位米。
    };

    // 原始字节是注册表属性的唯一数据源；可读预览由消费者按需生成。
    struct DefaultLocationValue
    {
        QString name;
        quint32 type = 0;
        QByteArray bytes;
        RegistryBackend backend = RegistryBackend::None;
    };

    QString registryValueTypeText(quint32 type);
    QString registryValuePreview(const DefaultLocationValue& value);

    // DefaultLocationSnapshot：
    // - 作用：一次“默认位置”注册表读取的完整结果，含原始值清单以便用户核对。
    struct DefaultLocationSnapshot
    {
        bool readable = false;          // readable：是否成功打开并读完该键。
        bool present = false;           // present：键里是否已经写着可用的经纬度。
        RegistryBackend backend = RegistryBackend::None; // backend：本次读取走通的通道。
        GeoCoordinate coordinate;       // coordinate：解析出的坐标，present 为 false 时无意义。
        QVector<DefaultLocationValue> values; // 保留各值名、类型、完整字节和实际读取通道。
        QString failureText;            // failureText：readable 为 false 时的失败原因。
    };

    // ServiceSnapshot：
    // - 作用：判断“虚拟坐标能否生效”所需的全部环境状态。
    struct ServiceSnapshot
    {
        bool serviceQueryOk = false;      // serviceQueryOk：是否成功查询到 lfsvc 服务。
        bool serviceRunning = false;      // serviceRunning：位置服务当前是否在运行。
        QString serviceStateText;         // serviceStateText：服务状态的可读描述。
        bool consentReadable = false;     // consentReadable：系统位置总开关是否读到。
        bool locationAllowed = false;     // locationAllowed：系统位置总开关是否为 Allow。
        bool desktopAppAllowed = false;   // desktopAppAllowed：桌面应用（NonPackaged）是否被放行。
        bool providerDisabledByPolicy = false; // providerDisabledByPolicy：组策略是否禁用了 Windows 位置提供程序。
        bool locationDisabledByPolicy = false; // locationDisabledByPolicy：组策略是否整体关闭了定位。
        QString policyDetailText;         // policyDetailText：策略项的原样取值描述。
    };

    // LiveFixResult：
    // - 作用：向 WinRT Geolocator 要一次定位的结果。
    struct LiveFixResult
    {
        bool ok = false;             // ok：是否拿到坐标。
        GeoCoordinate coordinate;    // coordinate：系统返回的坐标，ok 为 false 时无意义。
        QString sourceText;          // sourceText：定位来源（卫星 / 蜂窝 / WiFi / IP / 默认位置）。
        QString failureText;         // failureText：ok 为 false 时的失败原因。
    };

    // OperationResult：
    // - 作用：一次写操作的统一结果。
    struct OperationResult
    {
        bool ok = false;                                  // ok：操作是否成功。
        RegistryBackend backend = RegistryBackend::None;  // backend：成功时走通的通道。
        QString detailText;                               // detailText：失败原因或成功补充说明。
    };

    // defaultLocationKeyPath：
    // - 作用：返回“默认位置”所在的 HKLM 键路径，UI 直接显示给用户；
    // - 返回：不带尾部反斜杠的完整路径文本。
    QString defaultLocationKeyPath();

    // sensorPolicyKeyPath：
    // - 作用：返回位置相关组策略键路径；
    // - 返回：不带尾部反斜杠的完整路径文本。
    QString sensorPolicyKeyPath();

    // readDefaultLocation：
    // - 作用：读取当前系统默认位置；先试 R3，被拒后自动改走 R0；
    // - 返回：快照；readable 为 false 时看 failureText。
    DefaultLocationSnapshot readDefaultLocation();

    // applyDefaultLocation：
    // - 输入 coordinate：已经换算到 WGS-84 的坐标；
    // - 作用：建键并写入 Latitude / Longitude / Altitude / ErrorRadius / AltitudeAccuracy；
    // - 返回：OperationResult；ok 为 true 表示五个值都写成功。
    OperationResult applyDefaultLocation(const GeoCoordinate& coordinate);

    // clearDefaultLocation：
    // - 作用：删除默认位置的五个值，把系统恢复成“没有设置默认位置”；
    // - 返回：OperationResult；键本身不删，避免动到 lfsvc 自己维护的其他子项。
    OperationResult clearDefaultLocation();

    // readServiceSnapshot：
    // - 作用：查询 lfsvc 状态、隐私开关与组策略；全部只读；
    // - 返回：ServiceSnapshot，任一项读不到都以对应的 *Readable 标志表示。
    ServiceSnapshot readServiceSnapshot();

    // setLocationProviderDisabled：
    // - 输入 disabled：true 写入 DisableWindowsLocationProvider=1，false 删除该值；
    // - 作用：关掉 Windows 自带的网络定位提供程序，逼定位调用回落到默认位置；
    // - 返回：OperationResult。这一项影响全系统，调用方必须先向用户确认。
    OperationResult setLocationProviderDisabled(bool disabled);

    // restartLocationService：
    // - 作用：停止 lfsvc 让它丢掉进程内的位置缓存；服务本身是触发启动的，下次有应用请求会自动拉起；
    // - 返回：OperationResult；ok 为 true 表示服务已停止或本来就没在运行。
    OperationResult restartLocationService();

    // queryLiveFix：
    // - 输入 timeoutMilliseconds：等待 WinRT 异步定位的上限；
    // - 作用：在调用线程内同步向 Geolocator 要一次定位，用于确认虚拟坐标是否被采纳；
    // - 返回：LiveFixResult。该函数会阻塞，必须在后台线程调用。
    LiveFixResult queryLiveFix(unsigned long timeoutMilliseconds);

    // convertCoordinate：
    // - 输入 source：源坐标；from/to：源与目标坐标系；
    // - 作用：在 WGS-84 / GCJ-02 / BD-09 之间换算，只改经纬度，其余分量原样保留；
    // - 返回：目标坐标系下的坐标。中国大陆之外三系等价，直接返回原值。
    GeoCoordinate convertCoordinate(
        const GeoCoordinate& source,
        CoordinateSystem from,
        CoordinateSystem to);

    // PresetLocation：
    // - 作用：预设坐标点，经纬度一律以 WGS-84 记录。
    struct PresetLocation
    {
        const char* nameKey;   // nameKey：i18n 语义键。
        const char* nameText;  // nameText：中文名称，同时充当英文缺失时的兜底。
        double latitude;       // latitude：WGS-84 纬度。
        double longitude;      // longitude：WGS-84 经度。
        double altitude;       // altitude：参考海拔，单位米。
    };

    // presetLocations：
    // - 作用：返回内置预设点表与其长度；
    // - 输出 countOut：表长；
    // - 返回：静态只读数组首地址。
    const PresetLocation* presetLocations(int* countOut);
}
