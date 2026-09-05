// MainWindow.Kvm.cpp
//
// 标题栏权限按钮排里 KVM（KSwordVM，R-1 层）按钮的全部行为。
//
// 拆分理由与 KernelHvmTab 分片一致：MainWindow.cpp 已经承担了窗口、Dock、
// 权限、驱动服务等多条主线，KVM 的状态机、菜单与后台查询自成一块，混进去只会
// 让两边都更难读。
//
// 三条硬性约束：
// - 状态查询与所有控制命令都是阻塞 IOCTL，一律走后台线程，UI 线程只做展示；
// - 进入 VMX non-root 会改变全机 CPU 状态，属于高风险操作，必须走统一确认；
// - 写权限默认关闭。关闭时 KVM 只做观测，任何 R-1 改写入口都不出现在菜单里。

#include "MainWindow.h"

#include "Framework/DestructiveActionConfirmation.h"
#include "Internationalization/LanguageManager.h"
#include "UI/KvmControl.h"
#include "UI/KvmCrPolicyDialog.h"
#include "UI/KvmEventDialog.h"
#include "UI/KvmMemoryDialog.h"
#include "UI/KvmMsrPolicyDialog.h"
#include "UI/KvmViewDialog.h"
#include "theme.h"

#include <QAction>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>

#include <thread>
#include <utility>

namespace
{
    // KVM 按钮的三态样式。
    //
    // 与 R0 的二态不同：KVM 多一个"驱动在、但硬件门没过"的不可用态，
    // 这一态必须一眼可辨，否则用户会反复点一个永远不会生效的按钮。
    QString buildKvmButtonStyle(const bool residentActive, const bool available)
    {
        const QString backgroundColor = residentActive
            ? KswordTheme::PrimaryBlueHex
            : KswordTheme::SurfaceHex();
        // 非激活态的强调色文字要先对 Surface 校准，否则高亮度强调色会糊在底上。
        const QString textColor = residentActive
            ? KswordTheme::OnAccentHex()
            : (available
                ? KswordTheme::AccentButtonTextHex()
                : KswordTheme::TextSecondaryHex());
        const QString borderColor = available
            ? KswordTheme::PrimaryBlueBorderHex
            : KswordTheme::BorderHex();
        const QString hoverColor = residentActive
            ? KswordTheme::PrimaryBlueSolidHoverHex()
            : KswordTheme::PrimaryBlueSubtleHex();
        const QString hoverTextColor = residentActive
            ? KswordTheme::OnAccentHex()
            : KswordTheme::TextPrimaryColorHex();
        return QStringLiteral(
            "QPushButton {"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:2px 8px;"
            "  font-weight:600;"
            "}"
            "QPushButton:hover {"
            "  background:%4;"
            "  color:%5;"
            "  border:1px solid %4;"
            "}"
            "QPushButton:pressed {"
            "  background:%6;"
            "  color:%5;"
            "}"
            "QPushButton:disabled {"
            "  color:%7;"
            "}")
            .arg(backgroundColor)
            .arg(textColor)
            .arg(borderColor)
            .arg(hoverColor)
            .arg(hoverTextColor)
            .arg(KswordTheme::PrimaryBluePressedHex)
            .arg(KswordTheme::TextSecondaryHex());
    }
}

void MainWindow::applyKvmButtonState()
{
    if (m_kvmStatusButton == nullptr)
    {
        return;
    }
    m_kvmStatusButton->setStyleSheet(
        buildKvmButtonStyle(m_kvmResidentActive, m_kvmAvailable));
    // 操作进行中禁用按钮：常驻切换与保持自检都会独占驱动侧状态锁。
    m_kvmStatusButton->setEnabled(!m_kvmOperationRunning);
    if (m_kvmOperationRunning)
    {
        m_kvmStatusButton->setToolTip(
            ks::i18n::sourceText(QStringLiteral("KVM 操作进行中...")));
        return;
    }
    m_kvmStatusButton->setToolTip(m_kvmTooltip.isEmpty()
        ? ks::i18n::sourceText(QStringLiteral("KVM：KSwordVM 硬件虚拟化（R-1）常驻状态。左键启动或停止常驻，右键打开 R-1 能力菜单。"))
        : m_kvmTooltip);
}

void MainWindow::refreshKvmStatusAsync()
{
    // 合并并发查询：权限按钮刷新是周期性的，堆积请求只会拖慢驱动。
    if (m_kvmQueryInFlight || m_kvmOperationRunning)
    {
        return;
    }
    m_kvmQueryInFlight = true;
    QPointer<MainWindow> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmState state = ksword::kvm::queryState();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, state]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->m_kvmQueryInFlight = false;
                safeThis->m_kvmResidentActive = state.residentActive;
                safeThis->m_kvmAvailable =
                    state.availability == ksword::kvm::KvmAvailability::Available ||
                    state.availability == ksword::kvm::KvmAvailability::NotPrepared;
                safeThis->m_kvmFaulted = state.faulted;
                safeThis->m_kvmGeneration = state.generation;
                safeThis->m_kvmTooltip = state.detail;
                safeThis->applyKvmButtonState();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::handleKvmStatusButtonClicked()
{
    if (m_kvmOperationRunning)
    {
        return;
    }
    if (!m_r0DriverServiceRunning)
    {
        QMessageBox::information(
            this,
            QStringLiteral("KVM"),
            ks::i18n::sourceText(QStringLiteral(
                "KswordARK 驱动未运行。请先点击 R0 启动驱动服务。")));
        return;
    }
    if (m_kvmFaulted)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("KVM"),
            ks::i18n::sourceText(QStringLiteral(
                "KVM 处于故障或待回滚状态。请先在右键菜单中执行“重置故障状态”。")));
        return;
    }
    if (!m_kvmResidentActive && !m_kvmAvailable)
    {
        // 不可用的具体原因由后台快照写进 tooltip，这里原样呈现而不是给通用文案。
        QMessageBox::information(
            this,
            QStringLiteral("KVM"),
            m_kvmTooltip.isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("当前硬件或系统状态不支持 KVM 常驻。"))
                : m_kvmTooltip);
        return;
    }

    const bool stopping = m_kvmResidentActive;
    if (!stopping)
    {
        // 进入 VMX non-root 会改变全部逻辑处理器的运行模式，走统一高风险确认。
        const bool confirmed = ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmStartResident"),
            ks::i18n::sourceText(QStringLiteral("启动 KSwordVM 常驻")),
            ks::i18n::sourceText(QStringLiteral("本机全部逻辑处理器")),
            ks::i18n::sourceText(QStringLiteral("所有逻辑处理器将进入 VMX non-root 运行。与 Hyper-V/VBS 冲突、驱动异常或电源转换失败都可能导致系统不稳定或蓝屏。首次使用建议先执行“常驻保持自检”。")));
        if (!confirmed)
        {
            return;
        }
    }

    m_kvmOperationRunning = true;
    applyKvmButtonState();
    QPointer<MainWindow> safeThis(this);
    const unsigned long generation = m_kvmGeneration;
    std::thread([safeThis, stopping, generation]() {
        const ksword::kvm::KvmCommandResult result = stopping
            ? ksword::kvm::stopResident(generation)
            : ksword::kvm::startResident(generation);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->m_kvmOperationRunning = false;
                safeThis->applyKvmButtonState();
                if (!result.ok)
                {
                    QMessageBox::warning(
                        safeThis,
                        QStringLiteral("KVM"),
                        result.message);
                }
                safeThis->refreshKvmStatusAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::runKvmSoak(const unsigned long milliseconds)
{
    if (m_kvmOperationRunning)
    {
        return;
    }
    // 自检期间同样会让全部处理器进入 non-root，风险与直接启动常驻一致。
    const bool confirmed = ks::ui::confirmDestructiveAction(
        this,
        QStringLiteral("KvmSoak"),
        ks::i18n::sourceText(QStringLiteral("KSwordVM 常驻保持自检")),
        ks::i18n::sourceText(QStringLiteral("本机全部逻辑处理器")),
        ks::i18n::sourceText(QStringLiteral("全部逻辑处理器会进入 VMX non-root 并保持数秒后自动退出。期间任何未被处理的 VM-exit 都会被记录为掉核，与 Hyper-V/VBS 冲突时可能导致系统不稳定。")));
    if (!confirmed)
    {
        return;
    }

    m_kvmOperationRunning = true;
    applyKvmButtonState();
    QPointer<MainWindow> safeThis(this);
    const unsigned long generation = m_kvmGeneration;
    std::thread([safeThis, generation, milliseconds]() {
        const ksword::kvm::KvmCommandResult result =
            ksword::kvm::runSoak(generation, milliseconds);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->m_kvmOperationRunning = false;
                safeThis->applyKvmButtonState();
                // 自检结论无论成败都要呈现：它是常驻可用性的唯一直接证据。
                if (result.ok)
                {
                    QMessageBox::information(
                        safeThis,
                        QStringLiteral("KVM"),
                        result.message);
                }
                else
                {
                    QMessageBox::warning(
                        safeThis,
                        QStringLiteral("KVM"),
                        result.message);
                }
                safeThis->refreshKvmStatusAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::runKvmFaultReset()
{
    if (m_kvmOperationRunning)
    {
        return;
    }
    m_kvmOperationRunning = true;
    applyKvmButtonState();
    QPointer<MainWindow> safeThis(this);
    const unsigned long generation = m_kvmGeneration;
    std::thread([safeThis, generation]() {
        const ksword::kvm::KvmCommandResult result =
            ksword::kvm::resetFault(generation);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->m_kvmOperationRunning = false;
                safeThis->applyKvmButtonState();
                if (!result.ok)
                {
                    QMessageBox::warning(
                        safeThis,
                        QStringLiteral("KVM"),
                        result.message);
                }
                safeThis->refreshKvmStatusAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::showKvmMenu(const QPoint& globalPosition)
{
    QMenu menu(this);

    // 常驻开关与左键一致，放进菜单只是为了让能力集中可见。
    QAction* const toggleAction = menu.addAction(m_kvmResidentActive
        ? ks::i18n::sourceText(QStringLiteral("停止常驻"))
        : ks::i18n::sourceText(QStringLiteral("启动常驻")));
    toggleAction->setEnabled(!m_kvmOperationRunning &&
        (m_kvmResidentActive || m_kvmAvailable));
    connect(toggleAction, &QAction::triggered, this, [this]() {
        handleKvmStatusButtonClicked();
    });

    // 保持自检是唯一能证明"常驻活得下来"的手段：进出一次只证明转换本身没问题。
    QAction* const soakAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("常驻保持自检（5 秒）")));
    soakAction->setEnabled(!m_kvmOperationRunning &&
        !m_kvmResidentActive &&
        m_kvmAvailable);
    connect(soakAction, &QAction::triggered, this, [this]() {
        runKvmSoak(5000);
    });

    menu.addSeparator();

    // 嵌套模式：外层有 hypervisor 时（虚拟机内、或裸机开着 VBS/HVCI）唯一能跑起来的
    // 方式。不改写任何系统状态，所以不走高风险确认，但要说清代价。
    QAction* const nestedAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("允许嵌套运行（作为 L1）")));
    nestedAction->setCheckable(true);
    nestedAction->setChecked(ksword::kvm::isNestedAllowed());
    nestedAction->setToolTip(ks::i18n::sourceText(QStringLiteral("在虚拟机内或开着 VBS/HVCI 的机器上，KSwordVM 只能作为 L1 运行：每条 VMX 操作都由外层 hypervisor 模拟，性能明显下降，可用能力也只剩外层愿意暴露的那部分。")));
    connect(nestedAction, &QAction::triggered, this, [this](const bool checked) {
        ksword::kvm::setNestedAllowed(checked);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    menu.addSeparator();

    // 写权限门：关闭时 KVM 只做观测，所有 R-1 改写能力都不可用。
    QAction* const writeAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("允许 R-1 写操作")));
    writeAction->setCheckable(true);
    writeAction->setChecked(ksword::kvm::isWriteAccessEnabled());
    connect(writeAction, &QAction::triggered, this, [this](const bool checked) {
        if (!checked)
        {
            ksword::kvm::setWriteAccessEnabled(false);
            applyKvmButtonState();
            refreshKvmStatusAsync();
            return;
        }
        // 打开写权限等于解锁一整类可改写系统状态的能力，必须显式确认一次。
        const bool confirmed = ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmWriteAccess"),
            ks::i18n::sourceText(QStringLiteral("开启 KSwordVM 写权限")),
            ks::i18n::sourceText(QStringLiteral("本机物理内存与 EPT 映射")),
            ks::i18n::sourceText(QStringLiteral("开启后 KVM 的 R-1 改写能力（EPT 强制权限、隐蔽 Hook、内存隐藏、物理内存写入）将可用。这些操作绕过内核层保护，误用会直接损坏运行中的系统。")));
        ksword::kvm::setWriteAccessEnabled(confirmed);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    // R-1 内存面板不要求常驻：私有页表窗口在驱动加载时就已建立。
    QAction* const memoryAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("R-1 内存操作...")));
    memoryAction->setEnabled(m_r0DriverServiceRunning);
    connect(memoryAction, &QAction::triggered, this, [this]() {
        // 无父窗口模态：内存面板要能和主界面并排使用。
        KvmMemoryDialog* const dialog = new KvmMemoryDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->show();
    });

    // EPT 视图同样不要求常驻：它是安装在 EPT 上的，常驻期间反而不能改。
    QAction* const viewAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("EPT 分离视图（隐蔽 Hook / 内存隐藏）...")));
    viewAction->setEnabled(m_r0DriverServiceRunning);
    connect(viewAction, &QAction::triggered, this, [this]() {
        KvmViewDialog* const dialog = new KvmViewDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->show();
    });

    // MSR 策略同样在未常驻时配置：位图是活的硬件状态，常驻期间不能改。
    QAction* const msrAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("MSR 策略...")));
    msrAction->setEnabled(m_r0DriverServiceRunning);
    connect(msrAction, &QAction::triggered, this, [this]() {
        KvmMsrPolicyDialog* const dialog = new KvmMsrPolicyDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->show();
    });

    // 控制寄存器策略同样在建 VMCS 时消费，必须在常驻启动前配置。
    QAction* const crAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("控制寄存器策略...")));
    crAction->setEnabled(m_r0DriverServiceRunning);
    connect(crAction, &QAction::triggered, this, [this]() {
        KvmCrPolicyDialog* const dialog = new KvmCrPolicyDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->show();
    });

    // 事件流是只读的，任何时候都能看——它是上面几项能力唯一的实时证据。
    QAction* const eventAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("事件流...")));
    eventAction->setEnabled(m_r0DriverServiceRunning);
    connect(eventAction, &QAction::triggered, this, [this]() {
        KvmEventDialog* const dialog = new KvmEventDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->show();
    });

    menu.addSeparator();

    // 故障重置只清可恢复标记，常驻中会被驱动拒绝。
    QAction* const resetAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("重置故障状态")));
    resetAction->setEnabled(!m_kvmOperationRunning && m_kvmFaulted);
    connect(resetAction, &QAction::triggered, this, [this]() {
        runKvmFaultReset();
    });

    menu.exec(globalPosition);
}
