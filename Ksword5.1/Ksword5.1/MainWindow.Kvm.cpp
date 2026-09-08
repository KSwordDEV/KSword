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
#include "UI/KvmDomainDialog.h"
#include "UI/KvmHookWizard.h"
#include "UI/KvmViewDialog.h"
#include "UI/KvmWriteAccessGate.h"
#include "theme.h"

#include <QAction>
#include <QDialog>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>

#include <thread>
#include <utility>

namespace
{
    /*
     * KVM 按钮的显示状态：**一个**有序状态，不是两个独立布尔量。
     *
     * 原先背景色编码"常驻是否激活"、边框与文字色编码"能力是否可用"，两个通道
     * 各自独立取值，于是能画出自相矛盾的组合——出故障时背景说"正在跑"、边框
     * 说"不可用"；更糟的是 NotPrepared 被算成"可用"，一个还没准备的驱动被画成
     * 有能力的样子，而提示文字同时在说它没准备。看的人只能二选一地相信。
     *
     * 改成单一状态之后，"按钮长什么样"与"现在能不能点、点了会发生什么"是同一
     * 件事的两种说法，不可能互相打架。
     */
    enum class KvmButtonState
    {
        Unavailable,   // 硬件门没过、驱动没起、或外层 hypervisor 占着。
        Faulted,       // 有故障或待回滚，点之前必须先重置。
        NotPrepared,   // 能力齐备但资源没准备，点一下会先准备再常驻。
        Ready,         // 已准备、未常驻，点一下启动常驻。
        Resident       // 正在常驻，点一下停止。
    };

    /*
     * 优先级是有意的：先答"能不能用"，再答"现在处于哪一步"。
     *
     * 故障排在常驻之前，因为故障态下即使还有处理器在常驻，用户要做的第一件事
     * 也是重置而不是停止——把它画成普通的"正在跑"会把这一步藏起来。
     */
    KvmButtonState resolveKvmButtonState(
        const ksword::kvm::KvmAvailability availability,
        const bool residentActive,
        const bool faulted)
    {
        if (availability != ksword::kvm::KvmAvailability::Available &&
            availability != ksword::kvm::KvmAvailability::NotPrepared &&
            availability != ksword::kvm::KvmAvailability::Faulted)
        {
            return KvmButtonState::Unavailable;
        }
        if (faulted || availability == ksword::kvm::KvmAvailability::Faulted)
        {
            return KvmButtonState::Faulted;
        }
        if (residentActive)
        {
            return KvmButtonState::Resident;
        }
        if (availability == ksword::kvm::KvmAvailability::NotPrepared)
        {
            return KvmButtonState::NotPrepared;
        }
        return KvmButtonState::Ready;
    }

    QString buildKvmButtonStyle(const KvmButtonState state)
    {
        const bool residentActive = state == KvmButtonState::Resident;
        // 只有 Ready 与 Resident 是"这一刻真的可以按预期工作"。
        // NotPrepared 画成弱可用：能点，但点了要先走一步准备。
        const bool available = state == KvmButtonState::Ready ||
            state == KvmButtonState::Resident ||
            state == KvmButtonState::NotPrepared;
        const QString backgroundColor = residentActive
            ? KswordTheme::PrimaryBlueHex
            : KswordTheme::SurfaceHex();
        /*
         * 故障单独一种颜色，不与"不可用"合流。
         *
         * 两者要人做的事完全不同：故障是点一下重置就能继续，不可用是这台机器
         * 或这套配置根本走不通。画成同一个灰色，一次可恢复的故障会被读成"换台
         * 机器吧"，而那正好是最贵的误读。
         */
        const bool faulted = state == KvmButtonState::Faulted;
        // 非激活态的强调色文字要先对 Surface 校准，否则高亮度强调色会糊在底上。
        const QString textColor = residentActive
            ? KswordTheme::OnAccentHex()
            : (faulted
                ? KswordTheme::WarningHex()
                : (available
                    ? KswordTheme::AccentButtonTextHex()
                    : KswordTheme::TextSecondaryHex()));
        const QString borderColor = faulted
            ? KswordTheme::WarningHex()
            : (available
                ? KswordTheme::PrimaryBlueBorderHex
                : KswordTheme::BorderHex());
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

KvmDock* MainWindow::createKvmDockContent()
{
    auto* const dockContent = new KvmDock(this);
    dockContent->setActionHandler([this](const KvmDock::Action action) {
        handleKvmDockAction(action);
    });
    return dockContent;
}

void MainWindow::handleKvmDockAction(const KvmDock::Action action)
{
    // 这一层只做分派。每一条都落到右键菜单用的同一个实现上，包括那几处
    // confirmDestructiveAction 高危确认——两个入口因此不可能走出两套口径。
    const auto showKvmDialog = [](QDialog* const dialog) {
        // 无父窗口模态：R-1 面板要能和主界面并排使用，与右键菜单一致。
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->show();
    };

    switch (action)
    {
    case KvmDock::Action::ToggleResident:
        handleKvmStatusButtonClicked();
        return;
    case KvmDock::Action::Soak:
        runKvmSoak(5000);
        return;
    case KvmDock::Action::PrepareResources:
        runKvmPrepare();
        return;
    case KvmDock::Action::ReleaseResources:
        runKvmRelease();
        return;
    case KvmDock::Action::ResetFault:
        runKvmFaultReset();
        return;
    case KvmDock::Action::OpenHookWizard:
        // 向导自己管非模态生命周期与 WA_DeleteOnClose（openWizard 的契约），
        // 所以这一条不走 showKvmDialog —— 走了会重复设置属性并多一层 show。
        ks::ui::KvmHookWizard::openWizard(this);
        return;
    case KvmDock::Action::OpenViewDialog:
        showKvmDialog(new KvmViewDialog(this));
        return;
    case KvmDock::Action::OpenDomainDialog:
        showKvmDialog(new KvmDomainDialog(this));
        return;
    case KvmDock::Action::OpenMsrPolicyDialog:
        showKvmDialog(new KvmMsrPolicyDialog(this));
        return;
    case KvmDock::Action::OpenCrPolicyDialog:
        showKvmDialog(new KvmCrPolicyDialog(this));
        return;
    case KvmDock::Action::OpenMemoryDialog:
        showKvmDialog(new KvmMemoryDialog(this));
        return;
    case KvmDock::Action::OpenEventDialog:
        showKvmDialog(new KvmEventDialog(this));
        return;
    }
}

void MainWindow::applyKvmButtonState()
{
    // KVM 页的状态轮询看不到"命令正在跑"这件事：命令期间驱动侧状态锁被独占，
    // 查询只会排在它后面。只能由发起命令的这一侧推过去。
    if (m_kvmWidget != nullptr)
    {
        m_kvmWidget->setOperationRunning(m_kvmOperationRunning);
    }
    if (m_kvmStatusButton == nullptr)
    {
        return;
    }
    m_kvmStatusButton->setStyleSheet(
        buildKvmButtonStyle(resolveKvmButtonState(
            m_kvmAvailability,
            m_kvmResidentActive,
            m_kvmFaulted)));
    // 操作进行中禁用按钮：常驻切换与保持自检都会独占驱动侧状态锁。
    m_kvmStatusButton->setEnabled(!m_kvmOperationRunning);
    /*
     * 提示文字跟随显示名。
     *
     * 这里原先写死 "KVM"，于是设置里把显示名换成 HVM 或 R-1 之后，按钮文字改了
     * 而提示还在自称 KVM——同一个控件的两处文本各叫各的名字。
     */
    const QString hvmName = ks::settings::hvmDisplayNameLabel(
        m_currentAppearanceSettings.hvmDisplayName);
    if (m_kvmOperationRunning)
    {
        m_kvmStatusButton->setToolTip(
            ks::i18n::sourceText(QStringLiteral("%1 操作进行中...")).arg(hvmName));
        return;
    }
    m_kvmStatusButton->setToolTip(m_kvmTooltip.isEmpty()
        ? ks::i18n::sourceText(QStringLiteral("%1：KSwordVM 硬件虚拟化（R-1）常驻状态。左键启动或停止常驻，右键打开 R-1 能力菜单。")).arg(hvmName)
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
                /*
                 * 保留完整的可用性取值，不再压成一个布尔量。
                 *
                 * 压扁是矛盾的来源：NotPrepared 被并进"可用"，于是没准备过的
                 * 驱动画成有能力的样子；Faulted 被并进"不可用"，于是一次可重置
                 * 的故障和"这机器不支持"长得一样。按钮状态现在从这个原值算。
                 */
                safeThis->m_kvmAvailability = state.availability;
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

void MainWindow::runKvmPrepare()
{
    if (m_kvmOperationRunning)
    {
        return;
    }
    m_kvmOperationRunning = true;
    applyKvmButtonState();
    QPointer<MainWindow> safeThis(this);
    std::thread([safeThis]() {
        // ensurePrepared 会按需 PREPARE + SELF_TEST，已就绪时直接返回成功。
        // 它**不**进入常驻 —— 那正是这个入口存在的理由。
        const ksword::kvm::KvmCommandResult result =
            ksword::kvm::ensurePrepared();
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
                else
                {
                    QMessageBox::information(
                        safeThis,
                        QStringLiteral("KVM"),
                        ks::i18n::sourceText(QStringLiteral("资源已准备，尚未进入常驻。现在是安装分离视图 / MSR 策略 / CR 策略 / 执行域的窗口期 —— 启动常驻之后这几张表就不可变了。")));
                }
                safeThis->refreshKvmStatusAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::runKvmRelease()
{
    if (m_kvmOperationRunning)
    {
        return;
    }
    // 释放资源会丢掉已装的视图/策略/域，所以走高危确认。
    const bool confirmed = ks::ui::confirmDestructiveAction(
        this,
        QStringLiteral("KvmReleaseResources"),
        ks::i18n::sourceText(QStringLiteral("释放 KVM 资源")),
        ks::i18n::sourceText(QStringLiteral("本机全部逻辑处理器")),
        ks::i18n::sourceText(QStringLiteral("将释放全部每处理器资源与 EPT 层次。已安装的分离视图、MSR 策略、CR 策略与执行域会一并消失，叶项与权限恢复原状。改过后端选择或每处理器私有 EPT 时需要这一步：那些选择只在准备资源时被消费。")));
    if (!confirmed)
    {
        return;
    }
    m_kvmOperationRunning = true;
    applyKvmButtonState();
    QPointer<MainWindow> safeThis(this);
    const unsigned long generation = m_kvmGeneration;
    std::thread([safeThis, generation]() {
        const ksword::kvm::KvmCommandResult result =
            ksword::kvm::releaseResources(generation);
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

    // 「准备资源」与「释放资源」必须在这里，否则这个菜单有一条必然踩中的死路。
    //
    // 视图 / MSR / CR / 域四个面板都要求资源已准备。而这个菜单原本能做的只有
    // 「启动常驻」—— 它会在同一次调用里准备完资源**紧接着进入常驻**，于是四个
    // 面板立刻从「尚未准备」变成「常驻期间不能改」。中间那个唯一可用的窗口期
    // 在这里按不出来，用户只能在另一个 Dock 的另一个页里找到它，而两边此前
    // 没有任何交叉引用。
    //
    // 「释放资源」同时是让后端开关生效的唯一途径：后端在 PREPARE 时选定，
    // 而 ensurePrepared 在资源已就绪时不会重发 PREPARE。
    QAction* const prepareAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("准备资源（不进入常驻）")));
    prepareAction->setEnabled(!m_kvmOperationRunning &&
        !m_kvmResidentActive &&
        m_kvmAvailable);
    // 一条 sourceText 必须是**一个不拆行的字面量**：相邻字符串拼接会被
    // i18n 提取器当成多个独立词条，于是语言包里多出几条永远匹配不上的碎片。
    prepareAction->setToolTip(ks::i18n::sourceText(QStringLiteral("分配每处理器资源并建立 EPT，但不进入常驻。分离视图、MSR 策略、CR 策略与执行域都必须在这一步之后、启动常驻之前安装 —— 常驻期间这几张表都是不可变的。")));
    connect(prepareAction, &QAction::triggered, this, [this]() {
        runKvmPrepare();
    });

    QAction* const releaseAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("释放资源")));
    releaseAction->setEnabled(!m_kvmOperationRunning &&
        !m_kvmResidentActive &&
        m_kvmAvailable);
    releaseAction->setToolTip(ks::i18n::sourceText(QStringLiteral("释放全部可逆资源，回到未准备状态。改过分离视图后端或每处理器私有 EPT 之后必须走这一步 —— 那两个选择只在准备资源时被消费，已准备的运行时改开关不会生效。")));
    connect(releaseAction, &QAction::triggered, this, [this]() {
        runKvmRelease();
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

    // 私有 EPT：不放开能力，只是让已有的视图/授权在多核上安全，所以不走
    // 高风险确认——真正危险的是视图本身，那由写权限门管。
    QAction* const localEptAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("每处理器私有 EPT（多核可用视图）")));
    localEptAction->setCheckable(true);
    localEptAction->setChecked(ksword::kvm::isLocalEptEnabled());
    localEptAction->setToolTip(ks::i18n::sourceText(QStringLiteral("给每个处理器一份私有 EPT 层次，翻转只落在取到 exit 的那个处理器上。打开后才能在多核机器上安装 EPT 视图；关着时视图仍然只能在单核拓扑安装。与 VMFUNC、嵌套 VMX 互斥，且每核要多花若干页。")));
    connect(localEptAction, &QAction::triggered, this, [this, localEptAction](const bool checked) {
        // 互斥不是偏好而是驱动的硬拒绝：与 EPTP 切换后端同时请求会在任何
        // 分配之前被判 INVALID_REQUEST。这里拦下来并说明原因，比让用户攒出
        // 一个必然失败的组合再去猜协议状态码强。
        if (checked && ksword::kvm::isEptpSwitchEnabled())
        {
            localEptAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("私有 EPT 与 EPTP 切换后端互斥")),
                ks::i18n::sourceText(QStringLiteral("EPTP 切换后端靠在多份 EPT 层次之间换 EPTP 来做视图，私有 EPT 则要给每个处理器各自一份层次，两者对层次的用法冲突，驱动会在分配任何资源之前拒绝同时请求。请先关掉「EPT 分离视图用 EPTP 切换后端」。")));
            return;
        }
        ksword::kvm::setLocalEptEnabled(checked);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    // EPTP 切换后端：这一项选的不是"要不要一个能力"，而是"用哪套机器装视图"。
    // 关掉时行为与默认后端逐字节相同，所以不走高风险确认。选它的唯一理由是
    // 默认后端要 Monitor Trap Flag，而嵌套 Hyper-V 客户机拿不到 MTF。
    QAction* const eptpSwitchAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("EPT 分离视图用 EPTP 切换后端")));
    eptpSwitchAction->setCheckable(true);
    eptpSwitchAction->setChecked(ksword::kvm::isEptpSwitchEnabled());
    eptpSwitchAction->setToolTip(ks::i18n::sourceText(QStringLiteral("默认后端是「写 EPT 叶 + 用 Monitor Trap Flag 单步一条指令 + 写回去」，它要求处理器提供 Monitor Trap Flag。EPTP 切换后端换成在两份层次之间切 EPTP，只要 execute-only EPT 叶，既不要 MTF 也不要 VMFUNC。差别不是性能而是能力：嵌套 Hyper-V 客户机拿不到 MTF，那种机器上只有这套后端能装上视图。与私有 EPT、VMFUNC 互斥。这一位只随准备资源发出，改完要重新准备才生效。")));
    connect(eptpSwitchAction, &QAction::triggered, this, [this, eptpSwitchAction](const bool checked) {
        if (!checked)
        {
            ksword::kvm::setEptpSwitchEnabled(false);
            applyKvmButtonState();
            refreshKvmStatusAsync();
            return;
        }
        if (ksword::kvm::isLocalEptEnabled() || ksword::kvm::isVmFuncEnabled())
        {
            eptpSwitchAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("EPTP 切换后端与私有 EPT、VMFUNC 互斥")),
                ks::i18n::sourceText(QStringLiteral("EPTP 切换后端要在多份 EPT 层次之间换 EPTP：私有 EPT 要给每个处理器各自一份层次，VMFUNC 又要所有处理器共享同一份 EPTP list，两者都与它冲突。驱动会在分配任何资源之前拒绝同时请求。请先关掉「每处理器私有 EPT」与「武装 VMFUNC 视图切换」。")));
            return;
        }
        ksword::kvm::setEptpSwitchEnabled(true);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

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
        //
        // 确认文案与 suppressionKey 只存在于 KvmWriteAccessGate 一处：向导的预检
        // 也要能就地开启，两个入口各拼一遍的话，勾过「不再提示」的用户会在另一个
        // 入口被重新弹一次，而两处文案只要差一个字就再也说不清用户同意过什么。
        (void)ks::ui::requestKvmWriteAccess(this);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    // #VE 反射：本模块唯一一个「配错就是当场蓝屏」的开关，门禁因此比写权限更多。
    // guest 就是正在跑的这台 Windows，它的 IDT[20] 没有 #VE 处理程序。
    QAction* const veAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("武装 #VE 反射（危险）")));
    veAction->setCheckable(true);
    veAction->setChecked(ksword::kvm::isVeEnabled());
    veAction->setToolTip(ks::i18n::sourceText(QStringLiteral("把 EPT violation 反射成 guest 的 #VE（向量 20）。驱动侧有两道独立保险：所有 EPT 叶项都带 suppress-#VE，每 CPU 的信息区分配时即锁 busy。两道都在时，控制位开着也投递不出 #VE。本开关不持久化，重启客户端即回到关闭。")));
    connect(veAction, &QAction::triggered, this, [this, veAction](const bool checked) {
        if (!checked)
        {
            ksword::kvm::setVeEnabled(false);
            applyKvmButtonState();
            refreshKvmStatusAsync();
            return;
        }
        // 门禁一：裸机宿主机上不给开。#VE 配错的代价是整台机器立刻重启，
        // 唯一可以承受这个代价的地方是虚拟机里。
        if (!ksword::kvm::isNestedAllowed())
        {
            veAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("#VE 需要先进入嵌套模式")),
                ks::i18n::sourceText(QStringLiteral("#VE 只能在嵌套模式下武装，也就是只能在虚拟机里。配错的代价是整台机器立刻 triple fault 重启，这个代价只有虚拟机承受得起。请先打开「允许嵌套运行（作为 L1）」。")));
            return;
        }
        // 门禁二：写权限是前置，#VE 属于会改变 guest 可见行为的一类能力。
        if (!ksword::kvm::isWriteAccessEnabled())
        {
            veAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("#VE 需要先开启写权限")),
                ks::i18n::sourceText(QStringLiteral("武装 #VE 会改变 guest 可见的异常行为，属于写权限门管辖的范围。请先打开「允许 R-1 写操作」。")));
            return;
        }
        // 门禁三：标准高风险确认。
        const bool confirmed = ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmEnableVe"),
            ks::i18n::sourceText(QStringLiteral("武装 #VE 反射")),
            ks::i18n::sourceText(QStringLiteral("当前虚拟机的运行中内核")),
            ks::i18n::sourceText(QStringLiteral("#VE 把 EPT violation 变成 guest 内部的 20 号异常。这里的 guest 就是正在跑的这个 Windows，它没有 #VE 处理程序，真投递一次就是 #GP 转 #DF 转 triple fault，虚拟机当场重启且不会留下崩溃转储。")));
        if (!confirmed)
        {
            veAction->setChecked(false);
            return;
        }
        // 门禁四：最后一次，默认落在取消上。
        const auto answer = QMessageBox::warning(
            this,
            ks::i18n::sourceText(QStringLiteral("确认武装 #VE")),
            ks::i18n::sourceText(QStringLiteral("武装后驱动仍有两道保险挡着实际投递：所有 EPT 叶项都带 suppress-#VE，每 CPU 的信息区出厂即锁 busy。因此这一步得到的是「控制位已武装」，不是「#VE 已生效」。要真的收到 #VE，还需要在 guest 里装好处理程序、清掉 busy、再把目标页显式设为可转换——那三步本客户端不提供。确定要武装吗？")),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel);
        const bool armed = answer == QMessageBox::Yes;
        veAction->setChecked(armed);
        ksword::kvm::setVeEnabled(armed);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    // VMFUNC：不会蓝屏，但会把 EPTP list 里的每个域发布给任意 ring 3 线程。
    QAction* const vmFuncAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("武装 VMFUNC 视图切换")));
    vmFuncAction->setCheckable(true);
    vmFuncAction->setChecked(ksword::kvm::isVmFuncEnabled());
    vmFuncAction->setToolTip(ks::i18n::sourceText(QStringLiteral("武装后 guest 用一条 VMFUNC 就能在 EPTP list 的域之间切换，不产生 VM exit，驱动也收不到通知。VMFUNC 不做 CPL 检查，所以任意进程的任意 ring 3 线程都能切。这不是提权路径（域只能被拿掉权限），但确实是驱动观测不到的状态切换。本开关不持久化。")));
    connect(vmFuncAction, &QAction::triggered, this, [this, vmFuncAction](const bool checked) {
        if (!checked)
        {
            ksword::kvm::setVmFuncEnabled(false);
            applyKvmButtonState();
            refreshKvmStatusAsync();
            return;
        }
        // 与私有 EPT 同样的互斥：VMFUNC 要所有处理器共享同一份 EPTP list，
        // 而 EPTP 切换后端要在多份层次之间换 EPTP，驱动会直接拒绝这个组合。
        if (ksword::kvm::isEptpSwitchEnabled())
        {
            vmFuncAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("VMFUNC 与 EPTP 切换后端互斥")),
                ks::i18n::sourceText(QStringLiteral("VMFUNC 要求所有处理器共享同一份 EPTP list，而 EPTP 切换后端要在多份 EPT 层次之间换 EPTP，驱动会在分配任何资源之前拒绝同时请求。请先关掉「EPT 分离视图用 EPTP 切换后端」。")));
            return;
        }
        // 写权限前置：武装一个 guest 可见的切换接口属于改变系统行为。
        if (!ksword::kvm::isWriteAccessEnabled())
        {
            vmFuncAction->setChecked(false);
            QMessageBox::warning(
                this,
                ks::i18n::sourceText(QStringLiteral("VMFUNC 需要先开启写权限")),
                ks::i18n::sourceText(QStringLiteral("武装 VMFUNC 会让 guest 获得一个驱动观测不到的视图切换能力，属于写权限门管辖的范围。请先打开「允许 R-1 写操作」。")));
            return;
        }
        const bool confirmed = ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("KvmEnableVmFunc"),
            ks::i18n::sourceText(QStringLiteral("武装 VMFUNC 视图切换")),
            ks::i18n::sourceText(QStringLiteral("EPTP list 中的全部执行域")),
            ks::i18n::sourceText(QStringLiteral("VMFUNC 不做 CPL 检查：武装之后，任意进程里的任意用户态线程都能用一条指令切换当前使用的 EPT 视图，不产生 VM exit，驱动也不会被通知。域只能被拿掉权限，所以切过去拿不到新的访问权，但这仍然是一个你观测不到的状态变化。")));
        vmFuncAction->setChecked(confirmed);
        ksword::kvm::setVmFuncEnabled(confirmed);
        applyKvmButtonState();
        refreshKvmStatusAsync();
    });

    menu.addSeparator();

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

    // 执行域面板：域是默认视图的分叉，只能被拿掉权限，不能被加权限。
    QAction* const domainAction = menu.addAction(
        ks::i18n::sourceText(QStringLiteral("EPT 执行域（VMFUNC 可切换）...")));
    domainAction->setEnabled(m_r0DriverServiceRunning);
    connect(domainAction, &QAction::triggered, this, [this]() {
        KvmDomainDialog* const dialog = new KvmDomainDialog(this);
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
