#pragma once

#include "DiskEditorModels.h"
#include <QByteArray>
#include <QString>
#include <cstdint>
#include <functional>
#include <optional>

namespace ks::misc
{
    // DiskCapturedRange：冻结读取来源、设备身份、访问层、偏移和真实原字节。
    // generation 只属于当前页面的读取代次，不能跨切盘、切后端或重新枚举复用。
    struct DiskCapturedRange
    {
        DiskDeviceInfo source;                 // source：读取时选中的设备快照。
        QString deviceIdentity;                // deviceIdentity：系统返回的设备 GUID，空值仅允许展示。
        unsigned long backend = 0;             // backend：读取时明确选择的后端。
        std::uint64_t generation = 0;          // generation：宿主来源/读取代次。
        std::uint64_t offset = 0;              // offset：捕获起点，写回不能重新读取地址输入框。
        QByteArray original;                   // original：实际读到的基线，不是用户修改后的缓冲。
    };

    // CapturedDiskMatches：只比较冻结来源；实际设备身份由后端在写前/写后独立复核。
    // 输入为捕获记录和当前选择，返回是否仍属于同一次来源。
    bool CapturedDiskMatches(const DiskCapturedRange& captured, const DiskDeviceInfo& selected,
        unsigned long backend, std::uint64_t generation);

    // DiskWritePorts：共享事务使用的可注入端口，测试只提供内存实现。
    // identity 输出设备 GUID；read 输出完整真实字节；write 保留宿主已确认的后端参数。
    struct DiskWritePorts
    {
        std::function<bool(QString&, QString&)> identity;
        std::function<bool(QByteArray&, QString&)> read;
        std::function<bool(const QByteArray&, QString&)> write;
    };

    // DiskWriteReceipt：success 只有来源、原字节及最终回读全部一致时为真。
    // writeAttempted 表示已经调用写入端口，失败不能继续信任旧基线。
    struct DiskWriteReceipt
    {
        bool success = false;                  // success：最终验证成功。
        bool writeAttempted = false;           // writeAttempted：写入可能已部分生效。
        QByteArray observed;                   // observed：成功后的实际回读字节。
        QString error;                         // error：失败阶段及后端诊断。
    };

    // ApplyCapturedDiskWrite：身份复核 → 原字节核对 → 写入 → 回读 → 再次身份复核。
    // 没有设备身份、长度/范围不符、目标被外部修改时均拒绝调用写端口。
    DiskWriteReceipt ApplyCapturedDiskWrite(const DiskCapturedRange& captured,
        const QByteArray& replacement, const DiskWritePorts& ports);
}
