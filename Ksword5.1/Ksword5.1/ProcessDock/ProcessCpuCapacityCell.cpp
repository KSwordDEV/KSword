#include "ProcessCpuCapacityCell.h"

#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QColor>
#include <QIcon>
#include <QPainter>
#include <QStyle>
#include <QVariant>
#include <QWidget>

#include <algorithm>
#include <cmath>
#include <vector>

namespace
{
    // 单元格固定几何：数值刷新不改变列宽，每个真实逻辑 CPU 保留一个紧凑扇形槽。
    constexpr int CpuCellHorizontalMargin = 6;
    constexpr int CpuSlotMaximumSide = 14;
    constexpr int CpuSlotMinimumSide = 10;
    constexpr int CpuSlotGap = 2;

    // CpuSlotPaintValue：把一次核心采样的数值和可信状态绑定，防止缺失样本被误画成 0%。
    struct CpuSlotPaintValue
    {
        double percent = 0.0; // percent：当前进程在该真实逻辑 CPU 上的区间占用。
        bool sampleReady = false; // sampleReady：false 时必须绘制灰色失效态。
    };

    // blendCpuColor 作用：按比例在线性 RGB 空间混合两个主题语义色。
    // 调用方式：cpuLoadColor 分段生成蓝、绿、黄、红占用色；比例会自动限幅。
    // 返回值：不透明 QColor，不修改 QApplication palette 或全局主题状态。
    QColor blendCpuColor(const QColor& startColor, const QColor& endColor, const double ratio)
    {
        // safeRatio：保护浮点误差，保证每个 RGB 通道始终落在 0~255。
        const double safeRatio = std::clamp(ratio, 0.0, 1.0);
        const auto blendChannel = [safeRatio](const int startValue, const int endValue) -> int
        {
            return static_cast<int>(std::lround(
                static_cast<double>(startValue) +
                static_cast<double>(endValue - startValue) * safeRatio));
        };

        return QColor(
            blendChannel(startColor.red(), endColor.red()),
            blendChannel(startColor.green(), endColor.green()),
            blendChannel(startColor.blue(), endColor.blue()),
            255);
    }

    // cpuLoadColor 作用：把一个真实逻辑 CPU 的 0~100% 占用映射为主题前景色。
    // 调用方式：每个有效核心槽绘制扇形前调用；输入为已经限幅到 0~1 的比例。
    // 返回值：低占用蓝色、中占用绿色/黄色、高占用红色。
    QColor cpuLoadColor(const double loadRatio)
    {
        const double safeLoadRatio = std::clamp(loadRatio, 0.0, 1.0);
        if (safeLoadRatio <= 0.30)
        {
            return blendCpuColor(
                KswordTheme::PrimaryBlueColor,
                KswordTheme::SuccessColor(),
                safeLoadRatio / 0.30);
        }
        if (safeLoadRatio <= 0.70)
        {
            return blendCpuColor(
                KswordTheme::SuccessColor(),
                KswordTheme::WarningColor(),
                (safeLoadRatio - 0.30) / 0.40);
        }
        return blendCpuColor(
            KswordTheme::WarningColor(),
            KswordTheme::ErrorColor(),
            (safeLoadRatio - 0.70) / 0.30);
    }

    // cpuSnapshotFromIndex 作用：从模型角色恢复本轮共享 ETW 快照。
    // 调用方式：绘制、命中测试和 tooltip 共用；输入为 CPU 列模型索引。
    // 返回值：有效只读 shared_ptr，角色缺失时返回空指针。
    ks::ui::ProcessCpuUsageSnapshotPtr cpuSnapshotFromIndex(const QModelIndex& index)
    {
        if (!index.isValid())
        {
            return {};
        }
        return index.data(ks::ui::ProcessCpuUsageSnapshotRole)
            .value<ks::ui::ProcessCpuUsageSnapshotPtr>();
    }

    // cpuProcessIdsFromIndex 作用：读取 CPU核心单元格绑定的一个或多个真实 PID。
    // 调用方式：真实进程行返回单元素列表，应用聚合行返回其全部存活成员 PID。
    // 返回值：至少包含一个 PID 时为 true；PID 0 仍作为合法成员保留全核心布局。
    bool cpuProcessIdsFromIndex(
        const QModelIndex& index,
        QList<std::uint32_t>* const processIdsOut)
    {
        if (!index.isValid() || processIdsOut == nullptr)
        {
            return false;
        }

        const QVariant processIdsValue =
            index.data(ks::ui::ProcessCpuProcessIdsRole);
        if (!processIdsValue.canConvert<QList<std::uint32_t>>())
        {
            return false;
        }

        *processIdsOut = processIdsValue.value<QList<std::uint32_t>>();
        return !processIdsOut->isEmpty();
    }

    // cpuSlotSide 作用：按当前行高计算 10~14px 的扇形槽边长。
    // 调用方式：绘制和鼠标命中测试必须使用同一结果，避免 tooltip 指向相邻核心。
    // 返回值：适配当前 DPI/行高的整数像素边长。
    int cpuSlotSide(const QRect& contentRect)
    {
        return std::clamp(
            contentRect.height() - 6,
            CpuSlotMinimumSide,
            CpuSlotMaximumSide);
    }

    // cpuSlotRect 作用：计算指定全局逻辑处理器索引对应的小扇形槽位置。
    // 调用方式：调用方先获得 contentRect/slotSide，再按 processorIndex 逐槽调用。
    // 返回值：与绘制和 tooltip 完全一致的视口坐标矩形。
    QRect cpuSlotRect(
        const QRect& contentRect,
        const int slotSide,
        const std::size_t processorIndex)
    {
        const int slotsLeft = contentRect.left();
        const int slotTop = contentRect.center().y() - slotSide / 2;
        const int slotLeft = slotsLeft +
            static_cast<int>(processorIndex) * (slotSide + CpuSlotGap);
        return QRect(slotLeft, slotTop, slotSide, slotSide);
    }

    // processUsageSeriesList 作用：一次性定位目标 PID 集合的逐核心序列。
    // 调用方式：一个单元格开始绘制或 tooltip 命中前调用，后续各核心不再重复查哈希表。
    // 返回值：只保存本轮实际运行过的序列；无序列成员仍按可信 0% 处理。
    std::vector<const ks::process::CpuCoreUsageSeries*> processUsageSeriesList(
        const ks::process::CpuCoreUsageSnapshot& snapshot,
        const QList<std::uint32_t>& processIds)
    {
        std::vector<const ks::process::CpuCoreUsageSeries*> usageSeriesList;
        usageSeriesList.reserve(static_cast<std::size_t>(processIds.size()));
        for (const std::uint32_t processId : processIds)
        {
            const auto processUsageIt = snapshot.processUsageByPid.find(processId);
            if (processUsageIt != snapshot.processUsageByPid.end())
            {
                usageSeriesList.push_back(&processUsageIt->second);
            }
        }
        return usageSeriesList;
    }

    // cpuSlotPaintValue 作用：读取并汇总某真实逻辑 CPU 上的可信区间占用。
    // 调用方式：传入一次查得的 PID 序列集合和处理器索引；应用父行会逐成员求和。
    // 返回值：成员本轮均未运行时为可信 0%；样本失效时不可用；总值限制在 100%。
    CpuSlotPaintValue cpuSlotPaintValue(
        const ks::process::CpuCoreUsageSnapshot& snapshot,
        const std::vector<const ks::process::CpuCoreUsageSeries*>& usageSeriesList,
        const std::size_t processorIndex)
    {
        CpuSlotPaintValue value;
        value.sampleReady =
            snapshot.monitorRunning &&
            snapshot.sampleReady &&
            !snapshot.dataLossDetected &&
            processorIndex < snapshot.sampleReadyByProcessor.size() &&
            snapshot.sampleReadyByProcessor[processorIndex];
        if (!value.sampleReady)
        {
            return value;
        }

        double aggregatePercent = 0.0;
        for (const ks::process::CpuCoreUsageSeries* const usageSeries : usageSeriesList)
        {
            if (usageSeries == nullptr ||
                processorIndex >= usageSeries->percentByProcessor.size() ||
                (processorIndex < usageSeries->sampleReadyByProcessor.size() &&
                    !usageSeries->sampleReadyByProcessor[processorIndex]))
            {
                value.sampleReady = false;
                return value;
            }
            aggregatePercent += usageSeries->percentByProcessor[processorIndex];
        }

        value.percent = std::clamp(aggregatePercent, 0.0, 100.0);
        return value;
    }

    // drawCpuCoreSlot 作用：绘制一个无方框、无圆环描边的独立逐核心扇形图。
    // 调用方式：调用方已统一启用抗锯齿并保存 painter 状态；此函数不重复 save/restore。
    // 返回行为：中性圆底表示空闲部分，彩色扇区表示占用；失效样本只叠加灰色细斜线。
    void drawCpuCoreSlot(
        QPainter* const painter,
        const QRect& slotRect,
        const CpuSlotPaintValue& value)
    {
        if (painter == nullptr || !slotRect.isValid())
        {
            return;
        }

        // pieRect：直接使用槽位主体作为扇形，不再绘制外层圆角方框或蓝色圆环。
        const QRectF pieRect = QRectF(slotRect).adjusted(1.0, 1.0, -1.0, -1.0);
        const QColor idleColor = KswordTheme::WithAlpha(
            KswordTheme::SurfaceMutedColor(),
            KswordTheme::IsDarkModeEnabled() ? 65 : 85);
        painter->setPen(Qt::NoPen);
        painter->setBrush(idleColor);
        painter->drawEllipse(pieRect);

        if (!value.sampleReady)
        {
            // 无效样本不使用彩色轮廓，仅在中性圆底上绘制一条克制的斜线。
            const QColor unavailableColor = KswordTheme::WithAlpha(
                KswordTheme::TextDisabledColor(),
                185);
            painter->setPen(QPen(unavailableColor, 1.0, Qt::SolidLine, Qt::RoundCap));
            painter->drawLine(
                pieRect.topLeft() + QPointF(1.5, 1.5),
                pieRect.bottomRight() - QPointF(1.5, 1.5));
            return;
        }

        const double loadRatio = std::clamp(value.percent / 100.0, 0.0, 1.0);
        if (loadRatio <= 0.0)
        {
            return;
        }

        painter->setPen(Qt::NoPen);
        painter->setBrush(cpuLoadColor(loadRatio));
        if (loadRatio >= 0.9995)
        {
            painter->drawEllipse(pieRect);
            return;
        }
        painter->drawPie(
            pieRect,
            90 * 16,
            -static_cast<int>(std::lround(loadRatio * 360.0 * 16.0)));
    }
}

QSize ks::ui::ProcessCpuCapacityCellSizeHint(
    const QFontMetrics& fontMetrics,
    const std::uint32_t logicalProcessorCount)
{
    // 逻辑处理器数量设置防御性上限，避免异常系统返回值造成整数溢出。
    const int safeProcessorCount = static_cast<int>(std::min<std::uint32_t>(
        logicalProcessorCount,
        4096U));
    const int slotWidth = safeProcessorCount > 0
        ? safeProcessorCount * CpuSlotMaximumSide +
            (safeProcessorCount - 1) * CpuSlotGap
        : 0;
    const int widthValue = CpuCellHorizontalMargin * 2 + slotWidth;
    const int heightValue = std::max(fontMetrics.height() + 6, CpuSlotMaximumSide + 6);
    return QSize(widthValue, heightValue);
}

bool ks::ui::HasProcessCpuCapacityCellData(const QModelIndex& index)
{
    QList<std::uint32_t> processIds;
    const ProcessCpuUsageSnapshotPtr snapshot = cpuSnapshotFromIndex(index);
    return snapshot != nullptr && cpuProcessIdsFromIndex(index, &processIds);
}

void ks::ui::PaintProcessCpuCapacityCell(
    QPainter* const painter,
    const QStyleOptionViewItem& option,
    const QModelIndex& index)
{
    QList<std::uint32_t> processIds;
    const ProcessCpuUsageSnapshotPtr snapshot = cpuSnapshotFromIndex(index);
    if (painter == nullptr || !option.rect.isValid() || snapshot == nullptr ||
        !cpuProcessIdsFromIndex(index, &processIds))
    {
        return;
    }

    // 先让当前 Qt 样式绘制模型背景，保留新增/退出/高占用行底色和交互状态。
    QStyleOptionViewItem backgroundOption(option);
    backgroundOption.text.clear();
    backgroundOption.icon = QIcon();
    const QWidget* viewWidget = option.widget;
    QStyle* viewStyle = viewWidget != nullptr ? viewWidget->style() : QApplication::style();
    if (viewStyle != nullptr)
    {
        viewStyle->drawControl(
            QStyle::CE_ItemViewItem,
            &backgroundOption,
            painter,
            viewWidget);
    }

    const QRect contentRect = option.rect.adjusted(
        CpuCellHorizontalMargin,
        1,
        -CpuCellHorizontalMargin,
        -1);
    painter->save();

    // 只遍历当前 painter 裁剪区实际可见的核心槽，高核心数机器不会为屏幕外扇形付绘制成本。
    painter->setRenderHint(QPainter::Antialiasing, true);
    const int slotSide = cpuSlotSide(contentRect);
    const QRectF visiblePaintRect = painter->hasClipping()
        ? painter->clipBoundingRect()
        : QRectF(option.rect);
    const std::size_t processorCount = snapshot->processors.size();
    const std::vector<const ks::process::CpuCoreUsageSeries*> usageSeriesList =
        processUsageSeriesList(*snapshot, processIds);
    const int slotStride = slotSide + CpuSlotGap;
    const int slotsLeft = contentRect.left();
    const int firstVisibleOffset = std::max(
        0,
        static_cast<int>(std::floor(
            (visiblePaintRect.left() - slotsLeft - slotSide) /
            static_cast<double>(slotStride))));
    const std::size_t firstVisibleProcessor = std::min<std::size_t>(
        processorCount,
        static_cast<std::size_t>(firstVisibleOffset));
    for (std::size_t processorIndex = firstVisibleProcessor;
        processorIndex < processorCount;
        ++processorIndex)
    {
        const QRect slotRect = cpuSlotRect(
            contentRect,
            slotSide,
            processorIndex);
        if (slotRect.right() < visiblePaintRect.left())
        {
            continue;
        }
        if (slotRect.left() > visiblePaintRect.right())
        {
            break;
        }

        drawCpuCoreSlot(
            painter,
            slotRect,
            cpuSlotPaintValue(*snapshot, usageSeriesList, processorIndex));
    }
    painter->restore();
}

QString ks::ui::ProcessCpuCapacityToolTipText(
    const QStyleOptionViewItem& option,
    const QModelIndex& index,
    const QPoint& viewportPosition)
{
    QList<std::uint32_t> processIds;
    const ProcessCpuUsageSnapshotPtr snapshot = cpuSnapshotFromIndex(index);
    if (snapshot == nullptr || !cpuProcessIdsFromIndex(index, &processIds))
    {
        return {};
    }

    const QRect contentRect = option.rect.adjusted(
        CpuCellHorizontalMargin,
        1,
        -CpuCellHorizontalMargin,
        -1);
    const int slotSide = cpuSlotSide(contentRect);
    const int slotStride = slotSide + CpuSlotGap;
    const int slotsLeft = contentRect.left();
    const int relativeX = viewportPosition.x() - slotsLeft;
    if (relativeX < 0 || slotStride <= 0)
    {
        return {};
    }

    const std::size_t processorIndex = static_cast<std::size_t>(relativeX / slotStride);
    if (processorIndex >= snapshot->processors.size())
    {
        return {};
    }
    const QRect slotRect = cpuSlotRect(
        contentRect,
        slotSide,
        processorIndex);
    if (!slotRect.contains(viewportPosition))
    {
        return {}; // 鼠标位于两个扇形之间的间隙时不弹出误导提示。
    }

    const std::vector<const ks::process::CpuCoreUsageSeries*> usageSeriesList =
        processUsageSeriesList(*snapshot, processIds);
    const ks::process::EtwLogicalProcessorCoordinate& coordinate =
        snapshot->processors[processorIndex];
    const CpuSlotPaintValue value = cpuSlotPaintValue(
        *snapshot,
        usageSeriesList,
        processorIndex);
    if (!value.sampleReady)
    {
        return ks::i18n::contextText(
            QStringLiteral("process.table.cell.cpu_core_unavailable"),
            QStringLiteral("逻辑 CPU %1（组 %2 / 编号 %3）：本轮采样不可用"))
            .arg(coordinate.processorIndex)
            .arg(coordinate.group)
            .arg(coordinate.number);
    }

    return ks::i18n::contextText(
        QStringLiteral("process.table.cell.cpu_core_tooltip"),
        QStringLiteral("逻辑 CPU %1（组 %2 / 编号 %3）：%4%"))
        .arg(coordinate.processorIndex)
        .arg(coordinate.group)
        .arg(coordinate.number)
        .arg(value.percent, 0, 'f', 2);
}
