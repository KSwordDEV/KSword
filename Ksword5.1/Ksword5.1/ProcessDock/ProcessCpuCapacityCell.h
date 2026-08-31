#pragma once

#include "../ksword/process/process_cpu_core_etw_monitor.h"

#include <QFontMetrics>
#include <QList>
#include <QMetaType>
#include <QModelIndex>
#include <QPoint>
#include <QSize>
#include <QString>
#include <QStyleOptionViewItem>

#include <cstdint>
#include <memory>

class QPainter;

namespace ks::ui
{
    // ProcessCpuUsageSnapshotPtr：所有进程行共享同一轮只读 ETW 快照，避免复制 PID×核心矩阵。
    using ProcessCpuUsageSnapshotPtr =
        std::shared_ptr<const ks::process::CpuCoreUsageSnapshot>;

    // 两个角色把共享快照和目标 PID 集合交给自绘代理。
    // 调用方只返回轻量 shared_ptr/PID 列表，不为任何进程或核心创建 QWidget。
    inline constexpr int ProcessCpuUsageSnapshotRole = Qt::UserRole + 207;
    inline constexpr int ProcessCpuProcessIdsRole = Qt::UserRole + 208;

    // ProcessCpuCapacityCellSizeHint 作用：计算独立“CPU核心”列全部真实逻辑核心扇形的首选尺寸。
    // 调用方式：进程表模型处理 Qt::SizeHintRole 时调用；入参为表格字体和逻辑处理器数量。
    // 返回值：可交给列宽自适应器的 QSize，不访问采样器、线程句柄或进程句柄。
    QSize ProcessCpuCapacityCellSizeHint(
        const QFontMetrics& fontMetrics,
        std::uint32_t logicalProcessorCount);

    // HasProcessCpuCapacityCellData 作用：判断模型索引是否携带有效共享快照和目标 PID。
    // 调用方式：QStyledItemDelegate::paint 在默认绘制前调用；入参为当前模型索引。
    // 返回值：true 表示可画逐核心单元格，false 表示继续使用 Qt 普通单元格绘制。
    bool HasProcessCpuCapacityCellData(const QModelIndex& index);

    // PaintProcessCpuCapacityCell 作用：在独立列绘制每个真实逻辑 CPU 的占用扇形。
    // 调用方式：代理先 initStyleOption，再传入绘图器、完整样式选项和模型索引。
    // 返回行为：只绘制当前可见单元格；ETW 不完整时画灰色失效态，不伪装为 0%。
    void PaintProcessCpuCapacityCell(
        QPainter* painter,
        const QStyleOptionViewItem& option,
        const QModelIndex& index);

    // ProcessCpuCapacityToolTipText 作用：按鼠标位置生成目标逻辑 CPU 的真实占用提示。
    // 调用方式：代理 helpEvent 传入样式选项、模型索引和视口坐标；只做只读索引计算。
    // 返回值：命中核心扇形时返回说明文本，否则返回空字符串交回默认 tooltip 路径。
    QString ProcessCpuCapacityToolTipText(
        const QStyleOptionViewItem& option,
        const QModelIndex& index,
        const QPoint& viewportPosition);
}

Q_DECLARE_METATYPE(ks::ui::ProcessCpuUsageSnapshotPtr)
