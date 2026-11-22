#include "ThreadStackWindow.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/SegmentedControl.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QDateTime>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QTimeZone>
#include <QTreeWidget>

namespace
{
    // 输入本次内核 FILETIME，返回 UTC 采样时刻；无时刻时显示缺失而不是 UI 当前时间。
    QString CaptureTime(const std::uint64_t value)
    {
        constexpr std::uint64_t epoch = 116444736000000000ULL; // Windows 与 Unix 纪元差，单位 100ns。
        return value >= epoch ? QDateTime::fromMSecsSinceEpoch(static_cast<qint64>((value - epoch) / 10000),
            QTimeZone::UTC).toString(Qt::ISODateWithMs) : QStringLiteral("—");
    }
}

QString ThreadStackWindow::describeKernelCapture(const CaptureResult& result) const
{
    const auto& verified = result.kernel; // 与当前帧表绑定的唯一采集操作。
    const auto& capture = verified.capture; // 传输成功和业务采集成功必须分别判断。
    const auto& packet = capture.response; // 只有 io.ok 时才可以把字段解释为可信回执。
    QString reason; // 在页面上直接说明为什么没有帧，避免只写到全局日志。
    if (capture.io.win32Error == ERROR_UNHANDLED_EXCEPTION)
    {
        reason = ks::i18n::displayText(QStringLiteral("线程调用栈捕获失败")); // 工作线程异常不等于未访问过驱动。
    }
    else if (!verified.identityVerified)
    {
        reason = ks::i18n::displayText(QStringLiteral("冻结的进程或线程身份不可用，未访问驱动"));
    }
    else if (!capture.io.ok)
    {
        reason = ks::i18n::displayText(capture.unsupported ?
            QStringLiteral("当前驱动不支持在线采集协议") : QStringLiteral("在线采集设备或协议查询失败"));
    }
    else if (!verified.targetAliveAtReadback)
    {
        reason = ks::i18n::displayText(QStringLiteral("目标已退出，未采用迟到帧"));
    }
    else if (packet.result == KSWORD_ARK_THREAD_STACK_RESULT_LIFETIME_UNAVAILABLE)
    {
        reason = ks::i18n::displayText(QStringLiteral("当前内核缺少合法取消或回调退休能力，入队前拒绝采集"));
    }
    else if (packet.result == KSWORD_ARK_THREAD_STACK_RESULT_TIMEOUT)
    {
        reason = ks::i18n::displayText(QStringLiteral("目标 APC 投递等待超时，未取得调用帧"));
    }
    else if (packet.result == KSWORD_ARK_THREAD_STACK_RESULT_IDENTITY_MISMATCH)
    {
        reason = ks::i18n::displayText(QStringLiteral("驱动复核目标身份不符，未取得调用帧"));
    }
    else if (verified.usedSavedContext && !result.frames.empty())
    {
        reason = packet.result == KSWORD_ARK_STACK_SNAPSHOT_COMPLETE ?
            ks::i18n::displayText(QStringLiteral("目标原始内核链已展开至用户态边界：%1 帧，%2 ms"))
                .arg(static_cast<qulonglong>(result.frames.size())).arg(result.elapsedMs) :
            ks::i18n::displayText(QStringLiteral("目标保存上下文仅部分展开：%1 帧；停止原因 %2"))
                .arg(static_cast<qulonglong>(result.frames.size())).arg(verified.saved.response.unwindStop);
    }
    else if (verified.usedSavedContext)
    {
        reason = ks::i18n::displayText(QStringLiteral("未取得稳定的目标保存栈；停止原因 %1"))
            .arg(verified.saved.response.unwindStop);
    }
    else if (!result.frames.empty())
    {
        reason = ks::i18n::displayText(QStringLiteral("APC 时态部分内核栈：%1 帧，%2 ms；不是投递前完整调用栈"))
            .arg(static_cast<qulonglong>(result.frames.size())).arg(result.elapsedMs);
    }
    else
    {
        reason = ks::i18n::displayText(QStringLiteral("未取得目标线程的在线内核帧"));
    }
    return QStringLiteral("R0 · %1 · Win32 %2 / NTSTATUS 0x%3").arg(reason).arg(capture.io.win32Error)
        .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(capture.io.ntStatus)), 8, 16, QLatin1Char('0'));
}

void ThreadStackWindow::updateBoundaryText()
{
    if (!m_queriedKernel)
    {
        m_boundaryLabel->setText(QStringLiteral("R3 · UserStack=0x%1 - 0x%2 · TEB=0x%3")
            .arg(m_target.userStackLimit, 0, 16).arg(m_target.userStackBase, 0, 16).arg(m_target.tebBaseAddress, 0, 16));
        return;
    }
    const auto& packet = m_kernelCapture.capture.response; // 时间与标志来自同一次已校验回执。
    QString text = ks::i18n::displayText(m_kernelCapture.usedSavedContext ?
        QStringLiteral("采集方式：全处理器会合复制目标保存上下文，不向目标投递 APC") :
        QStringLiteral("在线来源：目标线程普通内核 APC；未混入 R3、转储、ETW 或栈边界线索"));
    if (m_kernelCapture.capture.io.ok && packet.captureStartTime100ns)
    {
        if (m_kernelCapture.usedSavedContext)
        {
            const auto& saved = m_kernelCapture.saved.response; // 副本范围与终点来自同一独立端点回执。
            text += QLatin1Char('\n') + ks::i18n::displayText(QStringLiteral("采样区间 %1 → %2（UTC）；IRQL %3；%4 个处理器；副本 %5 字节；停止原因 %6"))
                .arg(CaptureTime(packet.captureStartTime100ns), CaptureTime(packet.captureEndTime100ns)).arg(packet.captureIrql)
                .arg(saved.processorCount).arg(saved.snapshotByteCount).arg(saved.unwindStop);
        }
        else
        {
            text += QLatin1Char('\n') + ks::i18n::displayText(QStringLiteral("采样区间 %1 → %2（UTC）；IRQL %3；退休标志 %4；截断标志 %5"))
                .arg(CaptureTime(packet.captureStartTime100ns), CaptureTime(packet.captureEndTime100ns)).arg(packet.captureIrql)
                .arg((packet.flags & KSWORD_ARK_THREAD_STACK_FLAG_RETIREMENT_VERIFIED) != 0)
                .arg((packet.flags & KSWORD_ARK_THREAD_STACK_FLAG_FRAME_LIMIT) != 0);
        }
    }
    text += QLatin1Char('\n') + ks::i18n::displayText(QStringLiteral("符号仅在本地 PE/PDB 精确匹配时显示；模块来自前后快照，不是加载中映像身份的独立证明"));
    m_boundaryLabel->setText(text);
}

void ThreadStackWindow::initializeColumnViews()
{
    auto* group = new QWidget(this); // 互补列组共享底板，不改变帧模型、顺序和导出内容。
    auto* layout = new QHBoxLayout(group); // 紧贴 A/B 分段由共享组件接管外观。
    auto* viewA = new QPushButton(QStringLiteral("A"), group); // 地址与函数链概览。
    auto* viewB = new QPushButton(QStringLiteral("B"), group); // 地址、偏移与采样模式诊断。
    viewA->setToolTip(QStringLiteral("概览：地址、模块和符号"));
    viewB->setToolTip(QStringLiteral("诊断：地址、偏移和采样模式"));
    viewA->setCheckable(true);
    viewB->setCheckable(true);
    layout->addWidget(viewA);
    layout->addWidget(viewB);
    ks::ui::InstallSegmentedButtons(layout, {viewA, viewB});
    m_toolbarLayout->insertWidget(2, group);
    ks::ui::NormalizeToolbarRow(m_toolbarLayout);

    // 输入预设编号，仅修改显隐；手动自定义会取消两侧着色，不假装仍属于某个预设。
    const auto apply = [this, viewA, viewB](const bool overview)
    {
        m_frameTable->setColumnHidden(static_cast<int>(StackColumn::Module), !overview);
        m_frameTable->setColumnHidden(static_cast<int>(StackColumn::Symbol), !overview);
        m_frameTable->setColumnHidden(static_cast<int>(StackColumn::Offset), overview);
        m_frameTable->setColumnHidden(static_cast<int>(StackColumn::Mode), overview);
        viewA->setChecked(overview);
        viewB->setChecked(!overview);
        applyAdaptiveColumnWidths();
    };
    connect(viewA, &QPushButton::clicked, this, [apply]() { apply(true); });
    connect(viewB, &QPushButton::clicked, this, [apply]() { apply(false); });
    auto* header = m_frameTable->header(); // 保留原生列宽与表头身份，追加逐列选择菜单。
    header->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(header, &QHeaderView::customContextMenuRequested, this, [this, header, viewA, viewB](const QPoint& point)
    {
        QMenu menu(this); // 明确不透明背景和各文字状态，不继承父级透明样式。
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        for (int column = 0; column < static_cast<int>(StackColumn::Count); ++column)
        {
            auto* action = menu.addAction(m_frameTable->headerItem()->text(column)); // 当前列显隐选择。
            action->setCheckable(true);
            action->setChecked(!m_frameTable->isColumnHidden(column));
            connect(action, &QAction::triggered, &menu, [this, viewA, viewB, column](const bool visible)
            {
                m_frameTable->setColumnHidden(column, !visible);
                viewA->setChecked(false);
                viewB->setChecked(false);
                applyAdaptiveColumnWidths();
            });
        }
        menu.exec(header->mapToGlobal(point));
    });
    apply(true);
}
