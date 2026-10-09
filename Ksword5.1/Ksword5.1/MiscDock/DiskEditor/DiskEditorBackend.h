#pragma once

// ============================================================
// DiskEditorBackend.h
// 作用：
// 1) 封装磁盘枚举、分区布局读取、扇区读取和扇区写回；
// 2) 让 DiskEditorTab 不直接散落 CreateFile/DeviceIoControl 调用；
// 3) 后续如需切换为 KswordARK 驱动读写，可集中替换本文件实现。
// ============================================================

#include "DiskEditorModels.h"

#include <QByteArray>
#include <QString>
#include <QVariantMap>

#include <cstdint>
#include <vector>

namespace ks::misc
{
    struct DiskCapturedRange;
    // DiskEditorBackend 说明：
    // - 输入：物理磁盘路径、偏移、长度和字节缓冲；
    // - 处理逻辑：使用 Win32 API 读取布局与指定范围；
    // - 返回行为：所有失败通过 bool=false 和 errorTextOut 反馈。
    class DiskEditorBackend final
    {
    public:
        // queryCaptureIdentity：冻结路径必须仍对应系统设备 GUID；缺失身份不能写回旧缓存。
        static bool queryCaptureIdentity(const DiskDeviceInfo& source, QString& identity, QString& error);
        // 捕获写回使用 V2 驱动请求：在实际打开的同一设备实例验证 GUID 与原字节。
        // 旧驱动或后端不支持时拒绝，绝不回退到按磁盘号直接写入的 V1 请求。
        static bool writeCapturedBytesWithBackend(const DiskCapturedRange& captured,
            const QByteArray& replacement, unsigned long callerFlags, QString& error);
        // 捕获读取在实际设备实例验证同一 GUID；unsupported 只供显式只读兼容决策。
        static bool readCapturedBytesWithBackend(const DiskCapturedRange& captured,
            std::uint32_t length, QByteArray& bytes, bool& unsupported, QString& error);

        // enumerateDisks：
        // - 枚举 PhysicalDrive0..N 并补充分区布局；
        // - disksOut 接收磁盘快照；
        // - errorTextOut 在完全失败时给出诊断；
        // - 返回 true 表示至少成功枚举到一个磁盘或可展示错误磁盘项。
        static bool enumerateDisks(
            std::vector<DiskDeviceInfo>& disksOut,
            QString& errorTextOut);

        // readBytes：
        // - 从物理磁盘指定偏移读取字节；
        // - devicePath 为 \\.\PhysicalDriveN；
        // - offsetBytes 为绝对字节偏移；
        // - bytesToRead 为读取长度；
        // - bytesOut 接收读取结果；
        // - errorTextOut 返回失败原因；
        // - 返回 true 表示读取成功。
        static bool readBytes(
            const QString& devicePath,
            std::uint64_t offsetBytes,
            std::uint32_t bytesToRead,
            QByteArray& bytesOut,
            QString& errorTextOut);

        // readBytesWithBackend：
        // - 使用选定 R0 磁盘后端读取，backend 对应三层协议值；
        // - 后端 1 在旧驱动不可用时允许回退到现有 Windows 存储栈；
        // - 后端 2/3 绝不隐式降级，确保用户看到的访问层与实际一致。
        static bool readBytesWithBackend(
            int diskIndex,
            unsigned long backend,
            std::uint64_t offsetBytes,
            std::uint32_t bytesToRead,
            QByteArray& bytesOut,
            QString& errorTextOut);

        // writeBytes：
        // - 向物理磁盘指定偏移写入字节；
        // - requireSectorAligned 为 true 时强制偏移和长度按扇区对齐；
        // - bytesPerSector 为逻辑扇区大小；
        // - errorTextOut 返回失败原因；
        // - 返回 true 表示写入成功。
        static bool writeBytes(
            const QString& devicePath,
            std::uint64_t offsetBytes,
            const QByteArray& bytes,
            std::uint32_t bytesPerSector,
            bool requireSectorAligned,
            QString& errorTextOut);

        // writeBytesWithBackend：
        // - 通过 ArkDriverClient 写入选定后端；
        // - callerFlags 必须来自已完成的 UI 风险确认；
        // - 所有后端均执行 R0 安全策略、系统盘和扇区边界复核。
        static bool writeBytesWithBackend(
            int diskIndex,
            unsigned long backend,
            std::uint64_t offsetBytes,
            const QByteArray& bytes,
            unsigned long callerFlags,
            QString& errorTextOut);

        // queryVolumeMappings：
        // - 枚举 Windows 卷并用 extent 匹配当前磁盘；
        // - diskIndex 为 PhysicalDriveN 中的 N；
        // - 返回值使用 QVariantMap，避免基础后端依赖高级 UI 模型；
        // - errorTextOut 返回非致命诊断。
        static std::vector<QVariantMap> queryVolumeMappings(
            int diskIndex,
            QString& errorTextOut);

        // queryHealthItems：
        // - 查询设备基础能力、缓存、TRIM、SMART/NVMe 可用性等只读信息；
        // - devicePath 为物理磁盘路径；
        // - 返回值使用 QVariantMap，键包含 category/name/value/detail/severity；
        // - errorTextOut 返回非致命诊断。
        static std::vector<QVariantMap> queryHealthItems(
            const QString& devicePath,
            QString& errorTextOut);

        // formatBytes：
        // - 把字节数格式化为用户可读容量；
        // - bytes 为原始字节数；
        // - 返回容量文本。
        static QString formatBytes(std::uint64_t bytes);

        // partitionStyleText：
        // - 把 DiskPartitionStyle 转为 UI 文本；
        // - style 为样式枚举；
        // - 返回 RAW/MBR/GPT/未知。
        static QString partitionStyleText(DiskPartitionStyle style);
    };
}
