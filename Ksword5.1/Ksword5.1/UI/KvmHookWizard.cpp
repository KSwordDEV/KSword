// NOMINMAX 必须排在任何一个 include 之前：下面几个项目头会级联引入 Windows.h，
// 等到那时候再定义就晚了，min/max 宏一旦进来就会把 std:: 里的同名模板打断。
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "KvmHookWizard.h"

#include "KvmControl.h"
#include "ThemeStatusRole.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Internationalization/LanguageManager.h"
#include "../KernelDock/KernelThreadAuditTab.h"

#include <QComboBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QStringList>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

// 排练页要 VirtualAlloc / VirtualLock / VirtualFree。
#include <Windows.h>

#include <thread>
#include <vector>

// 这一份实现负责向导骨架、第 1 步（选目标）与第 4 步（安装）。
// 第 2 步在 KvmHookWizard.Patch.cpp，第 3/5 步在 KvmHookWizard.Verify.cpp，
// 分工见 KvmHookWizard.h 文件头那一段契约。

namespace
{
    // 目标物理地址上界。驱动只查「页对齐」和「小于这个数」两条
    // （hvm_ept_view.c:288-295 比的是 KSW_HVM_MAX_MAPPED_PHYSICAL =
    //  KSW_HVM_ONE_512_GIB * KSW_HVM_MAX_PML4_ENTRIES = 0x8000000000 * 16）。
    // 客户端先查一遍是为了把拒绝理由说清楚，不是为了替驱动做判定。
    constexpr quint64 kMaxTargetPhysical = 0x80000000000ULL;

    // 一页的字节数。取算术层的常量而不是自己写 4096，是为了让两处永远相等。
    constexpr qsizetype kPageBytes =
        static_cast<qsizetype>(Ksword::Evidence::kPatchPageBytes);

    // 排练页里写的标记字节。VirtualAlloc 给出的页是清零的，所以整页里只有
    // 这一个非零字节 —— 基线读回来之后一眼就能认出读到的是不是这一页。
    constexpr unsigned char kRehearsalMarkerByte = 0xA5U;

    // hexText：统一的十六进制回显形式，四个只读读数标签共用。
    QString hexText(const quint64 value)
    {
        return QStringLiteral("0x%1").arg(value, 0, 16);
    }

    // parseHexQuint64：解析输入框里的十六进制数，容忍 0x 前缀与前后空白。
    // 空串不算错，只是「还没填」，所以由调用方先自己判空。
    bool parseHexQuint64(const QString& text, quint64* const valueOut)
    {
        QString compact = text.trimmed();
        if (compact.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            compact = compact.mid(2);
        }
        if (compact.isEmpty())
        {
            return false;
        }
        bool converted = false;
        const qulonglong value = compact.toULongLong(&converted, 16);
        if (!converted)
        {
            return false;
        }
        *valueOut = static_cast<quint64>(value);
        return true;
    }

    // makeMonospace：把只读的字节/地址回显控件切成等宽字体。
    // 地址是要被人逐位核对的，比例字体下这件事做不了。
    void makeMonospace(QWidget* const widget)
    {
        if (widget == nullptr)
        {
            return;
        }
        widget->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    }
}

namespace ks::ui
{
    QString describeHookTargetSource(const KvmHookTargetSource source)
    {
        switch (source)
        {
        case KvmHookTargetSource::ModuleOffset:
            return ks::i18n::sourceText(
                QStringLiteral("模块 + 偏移"));
        case KvmHookTargetSource::KernelVa:
            return ks::i18n::sourceText(
                QStringLiteral("裸内核虚拟地址"));
        case KvmHookTargetSource::RawPa:
            return ks::i18n::sourceText(
                QStringLiteral("裸物理地址"));
        case KvmHookTargetSource::Rehearsal:
            return ks::i18n::sourceText(
                QStringLiteral("排练（本进程自有页）"));
        default:
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("未知入口"));
    }

    // =====================================================================
    // 生命周期
    // =====================================================================

    KvmHookWizard::KvmHookWizard(QWidget* const parent)
        : QDialog(parent)
    {
        setWindowTitle(ks::i18n::sourceText(
            QStringLiteral("KVM HOOK 视图安装向导")));
        setObjectName(QStringLiteral("KvmHookWizard"));
        buildUi();
        goToStep(Step::Target);
    }

    KvmHookWizard::~KvmHookWizard()
    {
        // 顺序不可换：排练页的物理帧一旦还给系统就会被别的东西拿去用，而那条
        // 视图仍然指着那个帧 —— 那时被重定向去执行影子页的将是一段与我们毫无
        // 关系的代码。所以先撤视图，撤不掉就宁可把这一页泄漏掉。
        bool viewRemoved = true;
        if (m_plan.installed
            && m_plan.installedViewId != 0
            && m_plan.targetSource == KvmHookTargetSource::Rehearsal)
        {
            // 这是本文件里唯一一处在 UI 线程上发 IOCTL 的地方。对话框正在析构，
            // 没有别的线程能替它做这件事，而把一页仍挂着视图的内存还给系统，
            // 比在这里阻塞一次要坏得多。
            const ksword::kvm::KvmViewResult removal =
                ksword::kvm::removeView(m_plan.installedViewId);
            viewRemoved = removal.ok;
        }
        if (viewRemoved)
        {
            releaseRehearsalPage();
        }
    }

    void KvmHookWizard::openWizard(QWidget* const parent)
    {
        // 只留一份。两份向导同时开着会各自分配一页排练页、各自持有一条视图，
        // 而析构顺序决定了谁先撤视图谁先还页 —— 那是一个没有理由去承担的竞态。
        // QPointer 而不是裸指针：窗口自己 WA_DeleteOnClose 之后这里要能看见。
        static QPointer<KvmHookWizard> openedWizard;
        if (!openedWizard.isNull())
        {
            openedWizard->show();
            openedWizard->raise();
            openedWizard->activateWindow();
            return;
        }

        KvmHookWizard* const wizard = new KvmHookWizard(parent);
        // 非模态：预检那一屏经常要一边看向导一边去别的面板改状态（开写权限门、
        // 停常驻），模态会把这条路堵死。
        wizard->setAttribute(Qt::WA_DeleteOnClose, true);
        openedWizard = wizard;
        wizard->show();
        wizard->raise();
        wizard->activateWindow();
    }

    // =====================================================================
    // 骨架与导航
    // =====================================================================

    void KvmHookWizard::buildUi()
    {
        QVBoxLayout* const rootLayout = new QVBoxLayout(this);

        m_stepTitleLabel = new QLabel(QString(), this);
        m_stepTitleLabel->setWordWrap(true);
        rootLayout->addWidget(m_stepTitleLabel);

        m_stepHintLabel = new QLabel(QString(), this);
        m_stepHintLabel->setWordWrap(true);
        rootLayout->addWidget(m_stepHintLabel);

        m_pageStack = new QStackedWidget(this);
        // 五页按 Step 顺序塞进去，下标与 Step 一一对应；第 2 步的控件由
        // KvmHookWizard.Patch.cpp 建，第 3/5 步的由 KvmHookWizard.Verify.cpp 建。
        m_pageStack->addWidget(buildTargetPage());
        m_pageStack->addWidget(buildPatchPage());
        m_pageStack->addWidget(buildPreflightPage());
        m_pageStack->addWidget(buildInstallPage());
        m_pageStack->addWidget(buildVerifyPage());
        rootLayout->addWidget(m_pageStack, 1);

        QFrame* const separator = new QFrame(this);
        separator->setFrameShape(QFrame::HLine);
        separator->setFrameShadow(QFrame::Sunken);
        rootLayout->addWidget(separator);

        m_statusLabel = new QLabel(QString(), this);
        m_statusLabel->setWordWrap(true);
        rootLayout->addWidget(m_statusLabel);

        QHBoxLayout* const navigationLayout = new QHBoxLayout();
        m_backButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("上一步")), this);
        m_nextButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("下一步")), this);
        m_closeButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("关闭")), this);
        navigationLayout->addWidget(m_backButton);
        navigationLayout->addWidget(m_nextButton);
        navigationLayout->addStretch(1);
        navigationLayout->addWidget(m_closeButton);
        rootLayout->addLayout(navigationLayout);

        connect(m_backButton, &QPushButton::clicked, this, [this]() {
            const int previous = static_cast<int>(m_currentStep) - 1;
            if (previous >= 0)
            {
                goToStep(static_cast<Step>(previous));
            }
        });
        connect(m_nextButton, &QPushButton::clicked, this, [this]() {
            QString reason;
            if (!canLeaveStep(m_currentStep, &reason))
            {
                setStatusText(reason, KvmCheckVerdict::Fail);
                return;
            }
            const int next = static_cast<int>(m_currentStep) + 1;
            if (next < static_cast<int>(Step::Count))
            {
                goToStep(static_cast<Step>(next));
            }
        });
        connect(m_closeButton, &QPushButton::clicked, this, [this]() {
            close();
        });

        resize(940, 720);
    }

    void KvmHookWizard::goToStep(const Step step)
    {
        const int index = static_cast<int>(step);
        if (index < 0 || index >= static_cast<int>(Step::Count))
        {
            return;
        }
        m_currentStep = step;
        if (m_pageStack != nullptr)
        {
            m_pageStack->setCurrentIndex(index);
        }

        QString title;
        QString hint;
        switch (step)
        {
        case Step::Target:
            title = ks::i18n::sourceText(
                QStringLiteral("第 1 步 / 共 5 步：指定目标页"));
            hint = ks::i18n::sourceText(
                QStringLiteral("四个入口最终都收敛到同一条归一化管线：先算出虚拟地址，再翻译成物理地址，最后拆成页基址与页内偏移。以前这三步在用户脑子里，算错了驱动也不会报错。"));
            break;
        case Step::Patch:
            title = ks::i18n::sourceText(
                QStringLiteral("第 2 步 / 共 5 步：编补丁"));
            hint = ks::i18n::sourceText(
                QStringLiteral("HOOK 的影子页才是被执行的那一份，所以它必须是「原页 4096 字节 + 你的改动」，补丁区间以外每个字节都要与原页逐位相同。"));
            break;
        case Step::Preflight:
            title = ks::i18n::sourceText(
                QStringLiteral("第 3 步 / 共 5 步：预检"));
            hint = ks::i18n::sourceText(
                QStringLiteral("这一屏只转述驱动侧的前置条件与本层的几何检查，它不放宽任何一条，也不替驱动发明新的检查。"));
            break;
        case Step::Install:
            title = ks::i18n::sourceText(
                QStringLiteral("第 4 步 / 共 5 步：安装"));
            hint = ks::i18n::sourceText(
                QStringLiteral("安装前会重读一次目标页并与第 2 步冻结的基线逐字节比对，比对不过就中止，不是提示一下继续装。"));
            break;
        case Step::Verify:
            title = ks::i18n::sourceText(
                QStringLiteral("第 5 步 / 共 5 步：校验"));
            hint = ks::i18n::sourceText(
                QStringLiteral("装上了与生效了是两件事。这一屏把能读回来的读数原样摆出来，读不到的如实写成「没有读数」，不涂成通过也不涂成失败。"));
            break;
        default:
            break;
        }
        if (m_stepTitleLabel != nullptr)
        {
            m_stepTitleLabel->setText(title);
        }
        if (m_stepHintLabel != nullptr)
        {
            m_stepHintLabel->setText(hint);
        }

        updateNavigationState();
        // 「进入这一步要做什么」只有这一个分派点。
        enterStep(step);
    }

    void KvmHookWizard::enterStep(const Step step)
    {
        switch (step)
        {
        case Step::Target:
            // 模块列表只在第一次进来时枚举一次：它走 R3 的
            // NtQuerySystemInformation，不便宜，也不会在向导开着的这几分钟里变。
            if (m_modules.isEmpty() && !m_moduleQueryInFlight)
            {
                refreshModuleList();
            }
            updateTargetReadout();
            break;
        case Step::Patch:
            // 基线不完整就抓一次。目标变了的时候 applyTargetResolve 会把
            // baselinePage 清掉，所以「目标变了」在这里表现为基线不完整。
            if (!m_plan.baselineIsComplete())
            {
                startBaselineCapture();
            }
            else
            {
                updatePatchEnabledState();
            }
            break;
        case Step::Preflight:
            startPreflightRefresh();
            break;
        case Step::Install:
            if (m_installSummaryView != nullptr)
            {
                m_installSummaryView->setPlainText(buildInstallSummaryText());
            }
            break;
        case Step::Verify:
            startVerifyStatic();
            break;
        default:
            break;
        }
    }

    bool KvmHookWizard::canLeaveStep(
        const Step step,
        QString* const reasonOut) const
    {
        const auto refuse = [reasonOut](const QString& reason) {
            if (reasonOut != nullptr)
            {
                *reasonOut = reason;
            }
            return false;
        };

        switch (step)
        {
        case Step::Target:
            if (!m_plan.resolved)
            {
                return refuse(ks::i18n::sourceText(
                    QStringLiteral("目标还没有归一化成功：下一步要用的是页基址，没有它就没有可装的东西。")));
            }
            return true;
        case Step::Patch:
            if (!m_plan.baselineIsComplete())
            {
                return refuse(ks::i18n::sourceText(
                    QStringLiteral("基线页不是完整的 4096 字节：残缺的基线拼出来的影子页会在被执行的那一页里留一段零。")));
            }
            if (m_plan.patchIsEmpty())
            {
                return refuse(ks::i18n::sourceText(
                    QStringLiteral("补丁为空：空补丁产出的影子页与原页逐位相同，装上去什么都不改变却会让人以为补丁生效了。")));
            }
            if (m_plan.classifyPatchGeometry()
                != Ksword::Evidence::CrossPageClassification::InPage)
            {
                return refuse(ks::i18n::sourceText(
                    QStringLiteral("补丁跨过了页尾：一条视图恰好覆盖一页，协议里没有页数，跨页在两种后端下都必须直接拒绝。")));
            }
            return true;
        case Step::Preflight:
            if (m_preflightRows.isEmpty())
            {
                return refuse(ks::i18n::sourceText(
                    QStringLiteral("预检还没有读到任何读数：先刷新一次再往下走。")));
            }
            if (hasBlockingPreflightFailure())
            {
                return refuse(ks::i18n::sourceText(
                    QStringLiteral("预检里还有拦截性的判据没有通过：「不知道」同样挡住下一步，因为它不等于「可以装」。")));
            }
            return true;
        case Step::Install:
            if (!m_plan.installed)
            {
                return refuse(ks::i18n::sourceText(
                    QStringLiteral("还没有安装成功：第 5 步校验的是这一条已安装视图，没装上就没有可校验的对象。")));
            }
            return true;
        case Step::Verify:
            return refuse(ks::i18n::sourceText(
                QStringLiteral("这已经是最后一步。")));
        default:
            break;
        }
        return true;
    }

    void KvmHookWizard::updateNavigationState()
    {
        if (m_backButton != nullptr)
        {
            m_backButton->setEnabled(
                !m_busy && m_currentStep != Step::Target);
        }
        if (m_nextButton != nullptr)
        {
            QString reason;
            const bool allowed =
                !m_busy
                && m_currentStep != Step::Verify
                && canLeaveStep(m_currentStep, &reason);
            m_nextButton->setEnabled(allowed);
            m_nextButton->setToolTip(allowed ? QString() : reason);
        }
        if (m_closeButton != nullptr)
        {
            m_closeButton->setEnabled(true);
        }
    }

    void KvmHookWizard::setBusy(const bool busy)
    {
        m_busy = busy;
        updateNavigationState();
        if (m_moduleReloadButton != nullptr)
        {
            m_moduleReloadButton->setEnabled(!busy && !m_moduleQueryInFlight);
        }
        if (m_rehearsalAllocButton != nullptr)
        {
            m_rehearsalAllocButton->setEnabled(
                !busy && m_rehearsalPage == nullptr);
        }
        if (m_installButton != nullptr)
        {
            m_installButton->setEnabled(!busy && !m_installInFlight);
        }
        if (m_preflightRefreshButton != nullptr)
        {
            m_preflightRefreshButton->setEnabled(!busy);
        }
        if (m_verifyRefreshButton != nullptr)
        {
            m_verifyRefreshButton->setEnabled(!busy);
        }
        if (m_verifyResidentButton != nullptr)
        {
            m_verifyResidentButton->setEnabled(!busy);
        }
        // 第 2 步的可用性规则不止「忙不忙」一条，所以交回给它自己算。
        if (m_shadowEditor != nullptr)
        {
            updatePatchEnabledState();
        }
    }

    void KvmHookWizard::setStatusText(
        const QString& text,
        const KvmCheckVerdict verdict)
    {
        if (m_statusLabel == nullptr)
        {
            return;
        }
        m_statusLabel->setText(text);
        ApplyStatusRole(m_statusLabel, checkVerdictStatusRole(verdict));
    }

    void KvmHookWizard::failBackTo(
        const Step step,
        const QString& reason,
        const unsigned long protocolStatus,
        const long lastStatus)
    {
        // 两级失败码原样附在文案后面：message 一旦成句就丢掉了「失败发生在哪一
        // 步」，而同一个 protocolStatus 会由多个分支产生，只有配上 lastStatus
        // 才分得开。人拿着这两个数才能去驱动里对分支。
        const QString detail = ks::i18n::sourceText(
            QStringLiteral("%1（协议状态 %2，NTSTATUS 0x%3）"))
            .arg(reason)
            .arg(protocolStatus)
            .arg(static_cast<quint32>(lastStatus), 8, 16, QLatin1Char('0'));
        if (m_installStatusLabel != nullptr)
        {
            m_installStatusLabel->setText(detail);
            ApplyStatusRole(m_installStatusLabel, StatusRole::Error);
        }
        // 先切页再写状态行：goToStep 会分派目标步骤的刷新，而那些刷新也写这一行。
        // 反过来写的话，这条失败原因会被目标步骤的「正在刷新...」当场盖掉。
        goToStep(step);
        setStatusText(detail, KvmCheckVerdict::Fail);
    }

    KvmHookWizard::Step KvmHookWizard::stepForViewFailure(
        const unsigned long protocolStatus,
        const long lastStatus)
    {
        // lastStatus 在这里不参与选步：能被它分开的两条来源（正在常驻 /
        // 拓扑与能力不满足）落在同一屏上。它由 failBackTo 原样带过去，
        // 让那一屏自己去指是哪一行 —— 这正是两级失败码要一起传的理由。
        (void)lastStatus;
        switch (protocolStatus)
        {
        case KSWORD_ARK_HVM_VIEW_STATUS_OK:
            // 零既是「成功」也是「客户端就把它拒了、根本没发 IOCTL」。走到这里
            // 的只可能是后者（调用方保证 ok 为假），而客户端侧的拒绝理由只有两条：
            // 写权限门关着、影子页长度不对。前者是预检的第一行。
            return Step::Preflight;
        case KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST:
            // 驱动只查页对齐与 8 TiB 上界两条，两条都属于目标几何。
            return Step::Target;
        case KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED:
            // 与安全策略无关：这是 FORCE/确认位的形状问题，重来一次即可。
            return Step::Install;
        case KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED:
        case KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL:
        case KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED:
        case KSWORD_ARK_HVM_VIEW_STATUS_EXECUTE_ONLY_UNSUPPORTED:
        case KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED:
            return Step::Preflight;
        case KSWORD_ARK_HVM_VIEW_STATUS_NOT_FOUND:
            // ADD 路径上拿到 NOT_FOUND 说明这一页在基座层次里没有映射，
            // 那是目标选错了，不是前置条件的问题。
            return Step::Target;
        case KSWORD_ARK_HVM_VIEW_STATUS_LEAF_CONFLICT:
            // 这一页上已经有别的视图。要么换一页，要么先去视图面板腾位置，
            // 两条路都从重选目标开始。
            return Step::Target;
        case KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE:
            // 这一个协议状态有两条来源：正在常驻（lastStatus = STATUS_DEVICE_BUSY
            // 0x80000011）与拓扑/能力不满足（STATUS_NOT_SUPPORTED 0xC00000BB）。
            // 两条在预检那一屏里各有自己的一行（NotResident 与 Topology），
            // 所以退回同一步；分得开它们的是 lastStatus，而它由 failBackTo
            // 原样带到那一屏上，不靠这里拿字符串去猜。
            return Step::Preflight;
        default:
            break;
        }
        return Step::Preflight;
    }

    // =====================================================================
    // 第 1 步：选目标
    // =====================================================================

    QWidget* KvmHookWizard::buildTargetPage()
    {
        QWidget* const page = new QWidget(this);
        QVBoxLayout* const pageLayout = new QVBoxLayout(page);

        QFormLayout* const sourceForm = new QFormLayout();
        m_sourceBox = new QComboBox(page);
        m_sourceBox->addItem(
            describeHookTargetSource(KvmHookTargetSource::ModuleOffset),
            static_cast<int>(KvmHookTargetSource::ModuleOffset));
        m_sourceBox->addItem(
            describeHookTargetSource(KvmHookTargetSource::KernelVa),
            static_cast<int>(KvmHookTargetSource::KernelVa));
        m_sourceBox->addItem(
            describeHookTargetSource(KvmHookTargetSource::RawPa),
            static_cast<int>(KvmHookTargetSource::RawPa));
        m_sourceBox->addItem(
            describeHookTargetSource(KvmHookTargetSource::Rehearsal),
            static_cast<int>(KvmHookTargetSource::Rehearsal));
        sourceForm->addRow(
            ks::i18n::sourceText(QStringLiteral("目标入口")),
            m_sourceBox);
        pageLayout->addLayout(sourceForm);

        m_sourceStack = new QStackedWidget(page);

        // ---- 入口一：模块 + 偏移 ----
        QWidget* const modulePage = new QWidget(m_sourceStack);
        QVBoxLayout* const moduleLayout = new QVBoxLayout(modulePage);
        QFormLayout* const moduleForm = new QFormLayout();
        QWidget* const moduleRow = new QWidget(modulePage);
        QHBoxLayout* const moduleRowLayout = new QHBoxLayout(moduleRow);
        moduleRowLayout->setContentsMargins(0, 0, 0, 0);
        m_moduleBox = new QComboBox(moduleRow);
        m_moduleReloadButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("重新枚举")), moduleRow);
        moduleRowLayout->addWidget(m_moduleBox, 1);
        moduleRowLayout->addWidget(m_moduleReloadButton);
        moduleForm->addRow(
            ks::i18n::sourceText(QStringLiteral("内核模块")),
            moduleRow);
        m_moduleOffsetEdit = new QLineEdit(modulePage);
        m_moduleOffsetEdit->setPlaceholderText(QStringLiteral("0x1234"));
        makeMonospace(m_moduleOffsetEdit);
        moduleForm->addRow(
            ks::i18n::sourceText(QStringLiteral("模块内偏移（十六进制）")),
            m_moduleOffsetEdit);
        moduleLayout->addLayout(moduleForm);

        m_moduleRangeLabel = new QLabel(QString(), modulePage);
        m_moduleRangeLabel->setWordWrap(true);
        moduleLayout->addWidget(m_moduleRangeLabel);

        QLabel* const moduleNoteLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("模块表走 R3 的 NtQuerySystemInformation，不依赖驱动，因此被摘链的驱动不会出现在这个下拉里 —— 这里选不到某个模块，不等于系统里没有它。")),
            modulePage);
        moduleNoteLabel->setWordWrap(true);
        ApplyStatusRole(moduleNoteLabel, StatusRole::Info);
        moduleLayout->addWidget(moduleNoteLabel);
        moduleLayout->addStretch(1);
        m_sourceStack->addWidget(modulePage);

        // ---- 入口二：裸内核虚拟地址 ----
        QWidget* const kernelVaPage = new QWidget(m_sourceStack);
        QVBoxLayout* const kernelVaLayout = new QVBoxLayout(kernelVaPage);
        QFormLayout* const kernelVaForm = new QFormLayout();
        m_kernelVaEdit = new QLineEdit(kernelVaPage);
        m_kernelVaEdit->setPlaceholderText(QStringLiteral("0xFFFFF80000000000"));
        makeMonospace(m_kernelVaEdit);
        kernelVaForm->addRow(
            ks::i18n::sourceText(QStringLiteral("内核虚拟地址（十六进制）")),
            m_kernelVaEdit);
        kernelVaLayout->addLayout(kernelVaForm);
        QLabel* const kernelVaNoteLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("这条入口不做归属校验，只做翻译：地址抄错一位仍然会翻译成功，只是翻到了别的一页。")),
            kernelVaPage);
        kernelVaNoteLabel->setWordWrap(true);
        ApplyStatusRole(kernelVaNoteLabel, StatusRole::Warning);
        kernelVaLayout->addWidget(kernelVaNoteLabel);
        kernelVaLayout->addStretch(1);
        m_sourceStack->addWidget(kernelVaPage);

        // ---- 入口三：裸物理地址 ----
        QWidget* const rawPaPage = new QWidget(m_sourceStack);
        QVBoxLayout* const rawPaLayout = new QVBoxLayout(rawPaPage);
        QFormLayout* const rawPaForm = new QFormLayout();
        m_rawPaEdit = new QLineEdit(rawPaPage);
        m_rawPaEdit->setPlaceholderText(QStringLiteral("0x1000"));
        makeMonospace(m_rawPaEdit);
        rawPaForm->addRow(
            ks::i18n::sourceText(QStringLiteral("物理地址（十六进制，跳过翻译）")),
            m_rawPaEdit);
        rawPaLayout->addLayout(rawPaForm);
        QLabel* const rawPaWarningLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("驱动对这条路径只校验页对齐与小于 8 TiB 两条，既不校验目标页是不是 RAM，也不校验它归谁。填错的结果是视图静默安装成功，然后对一页毫不相干的物理内存做执行重定向。")),
            rawPaPage);
        rawPaWarningLabel->setWordWrap(true);
        ApplyStatusRole(rawPaWarningLabel, StatusRole::Error);
        rawPaLayout->addWidget(rawPaWarningLabel);
        QLabel* const rawPaJumpLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("这条入口拿不到虚拟地址，所以第 2 步的近跳与绝对跳模板在这里没有可信的源地址，会被停用。")),
            rawPaPage);
        rawPaJumpLabel->setWordWrap(true);
        ApplyStatusRole(rawPaJumpLabel, StatusRole::Info);
        rawPaLayout->addWidget(rawPaJumpLabel);
        rawPaLayout->addStretch(1);
        m_sourceStack->addWidget(rawPaPage);

        // ---- 入口四：排练 ----
        QWidget* const rehearsalPage = new QWidget(m_sourceStack);
        QVBoxLayout* const rehearsalLayout = new QVBoxLayout(rehearsalPage);
        QLabel* const rehearsalIntroLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("排练把目标换成本进程自己分配并锁住的一页，后面四步与真实目标逐条一致。它回答的是一个别处回答不了的问题：这一趟走完没生效，到底是整条编排有 bug，还是装上了但没生效 —— 在动内核之前把这两件事分开。")),
            rehearsalPage);
        rehearsalIntroLabel->setWordWrap(true);
        rehearsalLayout->addWidget(rehearsalIntroLabel);

        m_rehearsalAllocButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("分配并锁住一页排练页")),
            rehearsalPage);
        rehearsalLayout->addWidget(m_rehearsalAllocButton);

        m_rehearsalLabel = new QLabel(QString(), rehearsalPage);
        m_rehearsalLabel->setWordWrap(true);
        makeMonospace(m_rehearsalLabel);
        rehearsalLayout->addWidget(m_rehearsalLabel);

        QLabel* const rehearsalNoteLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("分配之后会先写一个标记字节再 VirtualLock：没有驻留的页翻译出来的帧随时会换人，而接下来要往那个帧上挂视图。这一页在向导关闭时释放，且必须在移除视图之后。")),
            rehearsalPage);
        rehearsalNoteLabel->setWordWrap(true);
        ApplyStatusRole(rehearsalNoteLabel, StatusRole::Info);
        rehearsalLayout->addWidget(rehearsalNoteLabel);
        rehearsalLayout->addStretch(1);
        m_sourceStack->addWidget(rehearsalPage);

        pageLayout->addWidget(m_sourceStack);

        // ---- 归一化管线的四个产物 ----
        QGroupBox* const readoutGroup = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("归一化结果")), page);
        QFormLayout* const readoutForm = new QFormLayout(readoutGroup);
        m_readoutVaLabel = new QLabel(QString(), readoutGroup);
        m_readoutFullPaLabel = new QLabel(QString(), readoutGroup);
        m_readoutPageBaseLabel = new QLabel(QString(), readoutGroup);
        m_readoutPageOffsetLabel = new QLabel(QString(), readoutGroup);
        makeMonospace(m_readoutVaLabel);
        makeMonospace(m_readoutFullPaLabel);
        makeMonospace(m_readoutPageBaseLabel);
        makeMonospace(m_readoutPageOffsetLabel);
        readoutForm->addRow(
            ks::i18n::sourceText(QStringLiteral("虚拟地址")),
            m_readoutVaLabel);
        readoutForm->addRow(
            ks::i18n::sourceText(QStringLiteral("完整物理地址（含页内偏移）")),
            m_readoutFullPaLabel);
        readoutForm->addRow(
            ks::i18n::sourceText(QStringLiteral("页基址（安装用的就是它）")),
            m_readoutPageBaseLabel);
        readoutForm->addRow(
            ks::i18n::sourceText(QStringLiteral("页内偏移")),
            m_readoutPageOffsetLabel);
        pageLayout->addWidget(readoutGroup);

        QLabel* const cr3NoteLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("这里不需要填 CR3：翻译时页目录基址恒传 0，表示驱动用 __readcr3()，而内核地址在任何进程的页表里都能解析；排练页的目标就在本进程用户空间里，调用线程正好也在这个进程。")),
            page);
        cr3NoteLabel->setWordWrap(true);
        ApplyStatusRole(cr3NoteLabel, StatusRole::Info);
        pageLayout->addWidget(cr3NoteLabel);

        m_targetStatusLabel = new QLabel(QString(), page);
        m_targetStatusLabel->setWordWrap(true);
        pageLayout->addWidget(m_targetStatusLabel);
        pageLayout->addStretch(1);

        // 防抖定时器属于第 1 步，所以在第 1 步的 build 里建。
        m_targetDebounce = new QTimer(this);
        m_targetDebounce->setSingleShot(true);
        m_targetDebounce->setInterval(kInputDebounceMilliseconds);
        connect(m_targetDebounce, &QTimer::timeout, this, [this]() {
            startTargetResolve();
        });

        connect(
            m_sourceBox,
            &QComboBox::currentIndexChanged,
            this,
            [this](int) { onTargetSourceChanged(); });
        connect(
            m_moduleBox,
            &QComboBox::currentIndexChanged,
            this,
            [this](int) { scheduleTargetResolve(); });
        connect(m_moduleReloadButton, &QPushButton::clicked, this, [this]() {
            refreshModuleList();
        });
        connect(m_moduleOffsetEdit, &QLineEdit::textChanged, this, [this]() {
            scheduleTargetResolve();
        });
        connect(m_kernelVaEdit, &QLineEdit::textChanged, this, [this]() {
            scheduleTargetResolve();
        });
        connect(m_rawPaEdit, &QLineEdit::textChanged, this, [this]() {
            scheduleTargetResolve();
        });
        connect(m_rehearsalAllocButton, &QPushButton::clicked, this, [this]() {
            if (allocateRehearsalPage())
            {
                scheduleTargetResolve();
            }
        });

        // 默认停在排练：它是唯一一个可以在不冒险的前提下走完五步的入口，
        // 也与 KvmHookPlan::targetSource 的默认值一致。
        m_sourceBox->setCurrentIndex(
            static_cast<int>(KvmHookTargetSource::Rehearsal));
        m_sourceStack->setCurrentIndex(
            static_cast<int>(KvmHookTargetSource::Rehearsal));
        return page;
    }

    void KvmHookWizard::onTargetSourceChanged()
    {
        if (m_sourceBox == nullptr)
        {
            return;
        }
        const int index = m_sourceBox->currentIndex();
        if (index < 0)
        {
            return;
        }
        const KvmHookTargetSource source =
            static_cast<KvmHookTargetSource>(index);
        if (m_sourceStack != nullptr)
        {
            m_sourceStack->setCurrentIndex(index);
        }

        // 属于旧入口的字段一律清干净：留着旧值会让第 4 步的摘要显示一个用户
        // 已经不再选择的目标，而摘要正是安装前唯一一次复核的机会。
        m_plan.targetSource = source;
        m_plan.moduleName.clear();
        m_plan.moduleBase = 0;
        m_plan.imageSize = 0;
        m_plan.offset = 0;
        m_plan.virtualAddress = 0;
        m_plan.fullPhysicalAddress = 0;
        m_plan.pageBasePhysical = 0;
        m_plan.pageOffset = 0;
        m_plan.resolved = false;
        // 基线与补丁是上一个目标那一页的字节，换了目标就不再是任何东西的基线。
        m_plan.baselinePage.clear();
        m_plan.patchBytes.clear();
        // 序号在这里就要作废：换入口之后到防抖到点之前有一段空窗，上一个入口那次
        // 翻译要是正好在这段空窗里飞回来，序号还相等，就会把旧入口的页几何写进
        // 新入口的计划里。
        ++m_targetResolveSequence;

        updateTargetReadout();
        updateNavigationState();
        scheduleTargetResolve();
    }

    void KvmHookWizard::scheduleTargetResolve()
    {
        if (m_targetDebounce == nullptr)
        {
            startTargetResolve();
            return;
        }
        // 每敲一个字符发一次阻塞 IOCTL 会把 UI 拖垮，所以先攒一下。
        m_targetDebounce->start();
    }

    void KvmHookWizard::startTargetResolve()
    {
        if (m_targetResolveInFlight)
        {
            // 单飞：在飞的那一条回来时会重新排一次防抖，不叠发。
            if (m_targetDebounce != nullptr)
            {
                m_targetDebounce->start();
            }
            return;
        }

        const KvmHookTargetSource source = m_plan.targetSource;
        quint64 virtualAddress = 0;
        quint64 rawPhysicalAddress = 0;

        switch (source)
        {
        case KvmHookTargetSource::ModuleOffset:
        {
            const int moduleIndex =
                (m_moduleBox != nullptr) ? m_moduleBox->currentIndex() : -1;
            if (moduleIndex < 0 || moduleIndex >= m_modules.size())
            {
                m_plan.resolved = false;
                updateTargetReadout();
                if (m_targetStatusLabel != nullptr)
                {
                    m_targetStatusLabel->setText(ks::i18n::sourceText(
                        QStringLiteral("还没有选择模块。")));
                    ApplyStatusRole(m_targetStatusLabel, StatusRole::Idle);
                }
                updateNavigationState();
                return;
            }
            const KvmHookModuleChoice& choice = m_modules.at(moduleIndex);
            quint64 offset = 0;
            const QString offsetText = (m_moduleOffsetEdit != nullptr)
                ? m_moduleOffsetEdit->text()
                : QString();
            if (!parseHexQuint64(offsetText, &offset))
            {
                m_plan.resolved = false;
                updateTargetReadout();
                if (m_targetStatusLabel != nullptr)
                {
                    m_targetStatusLabel->setText(ks::i18n::sourceText(
                        QStringLiteral("模块内偏移不是合法的十六进制数。")));
                    ApplyStatusRole(m_targetStatusLabel, StatusRole::Error);
                }
                updateNavigationState();
                return;
            }
            // 本地夹一遍上界，不满足就当场拒绝且不发 IOCTL：这是四个入口里
            // 唯一一个能防住「地址抄错一位」的入口，夹不住就白选了。
            if (choice.imageSize == 0 || offset >= choice.imageSize)
            {
                m_plan.resolved = false;
                m_plan.offset = offset;
                updateTargetReadout();
                if (m_targetStatusLabel != nullptr)
                {
                    m_targetStatusLabel->setText(ks::i18n::sourceText(
                        QStringLiteral("偏移 %1 超出了模块 %2 的映像大小 %3，已在本地拒绝，没有发起翻译。"))
                        .arg(hexText(offset))
                        .arg(choice.name)
                        .arg(hexText(choice.imageSize)));
                    ApplyStatusRole(m_targetStatusLabel, StatusRole::Error);
                }
                updateNavigationState();
                return;
            }
            m_plan.moduleName = choice.name;
            m_plan.moduleBase = choice.baseAddress;
            m_plan.imageSize = choice.imageSize;
            m_plan.offset = offset;
            virtualAddress = choice.baseAddress + offset;
            break;
        }
        case KvmHookTargetSource::KernelVa:
        {
            const QString text =
                (m_kernelVaEdit != nullptr) ? m_kernelVaEdit->text() : QString();
            if (!parseHexQuint64(text, &virtualAddress))
            {
                m_plan.resolved = false;
                updateTargetReadout();
                if (m_targetStatusLabel != nullptr)
                {
                    m_targetStatusLabel->setText(ks::i18n::sourceText(
                        QStringLiteral("内核虚拟地址不是合法的十六进制数。")));
                    ApplyStatusRole(m_targetStatusLabel, StatusRole::Error);
                }
                updateNavigationState();
                return;
            }
            break;
        }
        case KvmHookTargetSource::RawPa:
        {
            const QString text =
                (m_rawPaEdit != nullptr) ? m_rawPaEdit->text() : QString();
            if (!parseHexQuint64(text, &rawPhysicalAddress))
            {
                m_plan.resolved = false;
                updateTargetReadout();
                if (m_targetStatusLabel != nullptr)
                {
                    m_targetStatusLabel->setText(ks::i18n::sourceText(
                        QStringLiteral("物理地址不是合法的十六进制数。")));
                    ApplyStatusRole(m_targetStatusLabel, StatusRole::Error);
                }
                updateNavigationState();
                return;
            }
            break;
        }
        case KvmHookTargetSource::Rehearsal:
        {
            if (m_rehearsalPage == nullptr)
            {
                m_plan.resolved = false;
                updateTargetReadout();
                if (m_targetStatusLabel != nullptr)
                {
                    m_targetStatusLabel->setText(ks::i18n::sourceText(
                        QStringLiteral("还没有分配排练页。")));
                    ApplyStatusRole(m_targetStatusLabel, StatusRole::Idle);
                }
                updateNavigationState();
                return;
            }
            virtualAddress =
                static_cast<quint64>(reinterpret_cast<quintptr>(m_rehearsalPage));
            break;
        }
        default:
            break;
        }

        m_plan.virtualAddress = virtualAddress;
        m_targetResolveInFlight = true;
        ++m_targetResolveSequence;
        const quint64 sequence = m_targetResolveSequence;
        if (m_targetStatusLabel != nullptr)
        {
            // 等待期间也要有一帧可用的界面：只换文字，不禁用输入框，
            // 否则用户会在自己敲字的过程中被反复夺走焦点。
            m_targetStatusLabel->setText(ks::i18n::sourceText(
                QStringLiteral("正在翻译目标地址...")));
            ApplyStatusRole(m_targetStatusLabel, StatusRole::Info);
        }

        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, sequence, source, virtualAddress,
                     rawPhysicalAddress]() {
            const KvmHookTargetResolution resolution = resolveTargetBlocking(
                source, virtualAddress, rawPhysicalAddress);
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, sequence, resolution]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyTargetResolve(sequence, resolution);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::applyTargetResolve(
        const quint64 sequence,
        const KvmHookTargetResolution& resolution)
    {
        // 单飞标志要先清：同一时刻最多只有一条在飞，所以任何一次回来都对应它。
        // 放在序号判断之后清的话，一次被作废的结果会把这个标志永远留在真，
        // 之后所有翻译都发不出去。
        m_targetResolveInFlight = false;
        if (sequence != m_targetResolveSequence)
        {
            // 已经被后续输入作废的旧地址。落地它会让页几何与输入框对不上，
            // 而那正是这条流程要消灭的那类错误。
            return;
        }

        const quint64 previousPageBase = m_plan.pageBasePhysical;
        m_plan.virtualAddress = resolution.virtualAddress;
        m_plan.fullPhysicalAddress = resolution.fullPhysicalAddress;
        m_plan.pageBasePhysical = resolution.pageBasePhysical;
        m_plan.pageOffset = resolution.pageOffset;
        m_plan.resolved = resolution.ok;
        if (m_plan.pageBasePhysical != previousPageBase)
        {
            // 换了页就换了基线。留着上一页的字节，第 2 步会拿它当底稿去拼影子页，
            // 而那一页正是被处理器执行的那一份。
            m_plan.baselinePage.clear();
            m_plan.patchBytes.clear();
        }

        updateTargetReadout();
        if (m_targetStatusLabel != nullptr)
        {
            m_targetStatusLabel->setText(resolution.message);
            ApplyStatusRole(
                m_targetStatusLabel,
                resolution.ok ? StatusRole::Success : StatusRole::Error);
        }
        updateNavigationState();
    }

    KvmHookTargetResolution KvmHookWizard::resolveTargetBlocking(
        const KvmHookTargetSource source,
        const quint64 virtualAddress,
        const quint64 rawPhysicalAddress)
    {
        KvmHookTargetResolution resolution;

        if (source == KvmHookTargetSource::RawPa)
        {
            // 这条路径没有虚拟地址，也没有翻译这一步：用户给的就是物理地址。
            resolution.virtualAddress = 0;
            resolution.fullPhysicalAddress = rawPhysicalAddress;
            resolution.pageBasePhysical = rawPhysicalAddress & ~0xFFFULL;
            resolution.pageOffset =
                static_cast<quint32>(rawPhysicalAddress & 0xFFFULL);
            if (resolution.pageBasePhysical >= kMaxTargetPhysical)
            {
                resolution.ok = false;
                resolution.message = ks::i18n::sourceText(
                    QStringLiteral("页基址 %1 不小于 8 TiB，驱动会直接拒绝这一条。"))
                    .arg(hexText(resolution.pageBasePhysical));
                return resolution;
            }
            resolution.ok = true;
            resolution.message = ks::i18n::sourceText(
                QStringLiteral("已按裸物理地址取页几何，没有做任何翻译，也没有校验这一页是不是 RAM、归谁。"));
            return resolution;
        }

        if (virtualAddress == 0ULL)
        {
            resolution.ok = false;
            resolution.message = ks::i18n::sourceText(
                QStringLiteral("还没有得到有效的虚拟地址。"));
            return resolution;
        }

        // 页目录基址恒传 0：驱动会用 __readcr3()，内核地址在任何进程页表里都能
        // 解析，排练页则本来就在调用线程所在的这个进程里。
        const ksword::kvm::KvmMemoryResult translated =
            ksword::kvm::translate(0ULL, virtualAddress);
        resolution.virtualAddress = virtualAddress;
        resolution.usedDirectWindow = translated.usedDirectWindow;
        if (!translated.ok)
        {
            resolution.ok = false;
            resolution.message = translated.message;
            return resolution;
        }

        resolution.fullPhysicalAddress = translated.physicalAddress;
        resolution.pageBasePhysical = translated.physicalAddress & ~0xFFFULL;
        resolution.pageOffset =
            static_cast<quint32>(translated.physicalAddress & 0xFFFULL);

        // 自洽性检查：页内偏移在翻译前后必须一致。不一致说明翻译自相矛盾，
        // 这时候拿到的页基址不可信，宁可当场拒绝也不要往下走。
        const quint32 virtualPageOffset =
            static_cast<quint32>(virtualAddress & 0xFFFULL);
        if (resolution.pageOffset != virtualPageOffset)
        {
            resolution.ok = false;
            resolution.message = ks::i18n::sourceText(
                QStringLiteral("翻译自相矛盾：虚拟地址的页内偏移是 %1，返回的物理地址的页内偏移却是 %2，这一条已拒绝。"))
                .arg(hexText(virtualPageOffset))
                .arg(hexText(resolution.pageOffset));
            return resolution;
        }
        if (resolution.pageBasePhysical >= kMaxTargetPhysical)
        {
            resolution.ok = false;
            resolution.message = ks::i18n::sourceText(
                QStringLiteral("页基址 %1 不小于 8 TiB，驱动会直接拒绝这一条。"))
                .arg(hexText(resolution.pageBasePhysical));
            return resolution;
        }

        resolution.ok = true;
        resolution.message = resolution.usedDirectWindow
            ? ks::i18n::sourceText(
                QStringLiteral("翻译成功，走的是私有页表窗口。"))
            : ks::i18n::sourceText(
                QStringLiteral("翻译成功，但退化到了 MmCopyMemory 路径：仍然能翻译，只是不再规避内核层 Hook。这是一个读数，不是失败。"));
        return resolution;
    }

    void KvmHookWizard::refreshModuleList()
    {
        if (m_moduleQueryInFlight)
        {
            return;
        }
        m_moduleQueryInFlight = true;
        ++m_moduleQuerySequence;
        const quint64 sequence = m_moduleQuerySequence;
        if (m_moduleReloadButton != nullptr)
        {
            m_moduleReloadButton->setEnabled(false);
        }

        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, sequence]() {
            // 走 R3 的 NtQuerySystemInformation，不依赖驱动，可在任意线程调用。
            KernelThreadAuditTab::ModuleQueryStatus status =
                KernelThreadAuditTab::ModuleQueryStatus::Ok;
            long nativeStatus = 0;
            unsigned long requiredBytes = 0;
            const std::vector<KernelThreadAuditTab::ModuleRecord> records =
                KernelThreadAuditTab::queryKernelModules(
                    &status, &nativeStatus, &requiredBytes);

            // 在后台线程里就投影成值层结构，UI 线程只搬一份可拷贝的数据。
            QVector<KvmHookModuleChoice> choices;
            choices.reserve(static_cast<qsizetype>(records.size()));
            for (const auto& record : records)
            {
                if (record.baseAddress == 0)
                {
                    continue;
                }
                KvmHookModuleChoice choice;
                choice.name = record.name;
                choice.path = record.path;
                choice.baseAddress = static_cast<quint64>(record.baseAddress);
                // imageSize 在这里就升到 64 位：「基址 + 偏移」用 32 位去比会把
                // 一个越界的偏移算成看起来合法的地址。
                choice.imageSize = static_cast<quint64>(record.imageSize);
                choice.kernelImage = record.kernelImage;
                choices.append(choice);
            }
            const bool ok =
                status == KernelThreadAuditTab::ModuleQueryStatus::Ok;

            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, sequence, choices, ok]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    // 同上：单飞标志先清，否则一次被作废的枚举会把它锁在真。
                    safeThis->m_moduleQueryInFlight = false;
                    if (sequence != safeThis->m_moduleQuerySequence)
                    {
                        return;
                    }
                    if (safeThis->m_moduleReloadButton != nullptr)
                    {
                        safeThis->m_moduleReloadButton->setEnabled(
                            !safeThis->m_busy);
                    }
                    safeThis->m_modules = choices;
                    if (safeThis->m_moduleBox != nullptr)
                    {
                        const QSignalBlocker blocker(safeThis->m_moduleBox);
                        safeThis->m_moduleBox->clear();
                        for (const auto& choice : safeThis->m_modules)
                        {
                            safeThis->m_moduleBox->addItem(
                                QStringLiteral("%1  %2")
                                    .arg(choice.name)
                                    .arg(hexText(choice.baseAddress)));
                        }
                    }
                    if (safeThis->m_moduleRangeLabel != nullptr)
                    {
                        safeThis->m_moduleRangeLabel->setText(ok
                            ? ks::i18n::sourceText(
                                QStringLiteral("已枚举 %1 个内核模块。"))
                                .arg(choices.size())
                            : ks::i18n::sourceText(
                                QStringLiteral("内核模块枚举失败：这一屏拿不到模块表，不代表系统里没有模块。")));
                        ApplyStatusRole(
                            safeThis->m_moduleRangeLabel,
                            ok ? StatusRole::Info : StatusRole::Error);
                    }
                    if (safeThis->m_plan.targetSource
                        == KvmHookTargetSource::ModuleOffset)
                    {
                        safeThis->scheduleTargetResolve();
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::updateTargetReadout()
    {
        if (m_readoutVaLabel != nullptr)
        {
            m_readoutVaLabel->setText(
                m_plan.targetSource == KvmHookTargetSource::RawPa
                    ? ks::i18n::sourceText(
                        QStringLiteral("本入口没有虚拟地址"))
                    : hexText(m_plan.virtualAddress));
        }
        if (m_readoutFullPaLabel != nullptr)
        {
            m_readoutFullPaLabel->setText(hexText(m_plan.fullPhysicalAddress));
        }
        if (m_readoutPageBaseLabel != nullptr)
        {
            m_readoutPageBaseLabel->setText(hexText(m_plan.pageBasePhysical));
        }
        if (m_readoutPageOffsetLabel != nullptr)
        {
            m_readoutPageOffsetLabel->setText(
                QStringLiteral("%1 (%2)")
                    .arg(hexText(m_plan.pageOffset))
                    .arg(m_plan.pageOffset));
        }
        if (m_moduleRangeLabel != nullptr
            && m_plan.targetSource == KvmHookTargetSource::ModuleOffset
            && m_plan.imageSize != 0)
        {
            m_moduleRangeLabel->setText(ks::i18n::sourceText(
                QStringLiteral("模块 %1 的地址区间是 %2 .. %3，偏移必须小于 %4。"))
                .arg(m_plan.moduleName)
                .arg(hexText(m_plan.moduleBase))
                .arg(hexText(m_plan.moduleBase + m_plan.imageSize))
                .arg(hexText(m_plan.imageSize)));
            ApplyStatusRole(m_moduleRangeLabel, StatusRole::Info);
        }
    }

    bool KvmHookWizard::allocateRehearsalPage()
    {
        if (m_rehearsalPage != nullptr)
        {
            return true;
        }
        // VirtualAlloc 给出的地址天然 4 KiB 对齐，所以排练入口不需要额外做页对齐。
        void* const page = ::VirtualAlloc(
            nullptr,
            static_cast<SIZE_T>(kPageBytes),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);
        if (page == nullptr)
        {
            if (m_rehearsalLabel != nullptr)
            {
                m_rehearsalLabel->setText(ks::i18n::sourceText(
                    QStringLiteral("排练页分配失败：Win32 错误 %1。"))
                    .arg(::GetLastError()));
                ApplyStatusRole(m_rehearsalLabel, StatusRole::Error);
            }
            return false;
        }

        // 顺序不可换：先写一个字节让页真正落到一个物理帧上，再 VirtualLock
        // 把它钉住。没有驻留的页翻译出来的帧随时会换人，而接下来要往那个帧上
        // 挂 EPT 视图 —— 帧换了人，视图就挂在别人身上了。
        static_cast<volatile unsigned char*>(page)[0] = kRehearsalMarkerByte;
        const BOOL locked =
            ::VirtualLock(page, static_cast<SIZE_T>(kPageBytes));
        m_rehearsalPage = page;

        if (m_rehearsalLabel != nullptr)
        {
            const quint64 address =
                static_cast<quint64>(reinterpret_cast<quintptr>(page));
            m_rehearsalLabel->setText(locked
                ? ks::i18n::sourceText(
                    QStringLiteral("排练页已分配并锁定：虚拟地址 %1，偏移 0 处写入了标记字节 0xA5，其余字节由 VirtualAlloc 清零。"))
                    .arg(hexText(address))
                : ks::i18n::sourceText(
                    QStringLiteral("排练页已分配，但 VirtualLock 失败（Win32 错误 %1）：这一页的物理帧随时可能换人，翻译到的页基址不可信。"))
                    .arg(::GetLastError()));
            ApplyStatusRole(
                m_rehearsalLabel,
                locked ? StatusRole::Success : StatusRole::Warning);
        }
        if (m_rehearsalAllocButton != nullptr)
        {
            m_rehearsalAllocButton->setEnabled(false);
        }
        return true;
    }

    void KvmHookWizard::releaseRehearsalPage()
    {
        if (m_rehearsalPage == nullptr)
        {
            return;
        }
        (void)::VirtualUnlock(m_rehearsalPage, static_cast<SIZE_T>(kPageBytes));
        (void)::VirtualFree(m_rehearsalPage, 0, MEM_RELEASE);
        m_rehearsalPage = nullptr;
    }

    // =====================================================================
    // 第 4 步：安装
    // =====================================================================

    QWidget* KvmHookWizard::buildInstallPage()
    {
        QWidget* const page = new QWidget(this);
        QVBoxLayout* const pageLayout = new QVBoxLayout(page);

        m_installSummaryView = new QPlainTextEdit(page);
        m_installSummaryView->setReadOnly(true);
        makeMonospace(m_installSummaryView);
        pageLayout->addWidget(m_installSummaryView, 1);

        QLabel* const riskLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("HOOK 不是安全边界。稳态下对这一页的读写走真实页且被显式授予，不会触发任何事件。能把 hypervisor 打退的是：落进单指令翻转窗口内的访问、与已有翻转重叠、以及同一条指令取指跨两张视图页。")),
            page);
        riskLabel->setWordWrap(true);
        ApplyStatusRole(riskLabel, StatusRole::Error);
        pageLayout->addWidget(riskLabel);

        QLabel* const windowLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("安装前会重读一次目标页做 TOCTOU 比对，这把窗口收窄到了一次 IOCTL，但不为零 —— 对一页活着的内核代码，这个窗口关不掉。")),
            page);
        windowLabel->setWordWrap(true);
        ApplyStatusRole(windowLabel, StatusRole::Warning);
        pageLayout->addWidget(windowLabel);

        m_installButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("确认并安装这条 HOOK 视图")),
            page);
        pageLayout->addWidget(m_installButton);

        m_installStatusLabel = new QLabel(QString(), page);
        m_installStatusLabel->setWordWrap(true);
        pageLayout->addWidget(m_installStatusLabel);

        connect(m_installButton, &QPushButton::clicked, this, [this]() {
            startInstall();
        });
        return page;
    }

    QString KvmHookWizard::buildInstallSummaryText() const
    {
        QStringList lines;
        lines << ks::i18n::sourceText(
            QStringLiteral("视图类型：HOOK（协议值 2）—— 读写走真实页，执行走影子页。"));
        lines << ks::i18n::sourceText(QStringLiteral("目标入口：%1"))
            .arg(describeHookTargetSource(m_plan.targetSource));
        if (m_plan.targetSource == KvmHookTargetSource::ModuleOffset)
        {
            lines << ks::i18n::sourceText(
                QStringLiteral("模块：%1，基址 %2，映像大小 %3，模块内偏移 %4"))
                .arg(m_plan.moduleName)
                .arg(hexText(m_plan.moduleBase))
                .arg(hexText(m_plan.imageSize))
                .arg(hexText(m_plan.offset));
        }
        lines << ks::i18n::sourceText(QStringLiteral("虚拟地址：%1"))
            .arg(m_plan.targetSource == KvmHookTargetSource::RawPa
                ? ks::i18n::sourceText(QStringLiteral("本入口没有虚拟地址"))
                : hexText(m_plan.virtualAddress));
        lines << ks::i18n::sourceText(
            QStringLiteral("完整物理地址（含页内偏移）：%1"))
            .arg(hexText(m_plan.fullPhysicalAddress));
        lines << ks::i18n::sourceText(QStringLiteral("目标物理页（安装用的就是它）：%1"))
            .arg(hexText(m_plan.pageBasePhysical));
        lines << ks::i18n::sourceText(QStringLiteral("页内偏移：%1"))
            .arg(hexText(m_plan.pageOffset));
        lines << ks::i18n::sourceText(
            QStringLiteral("影子来源：调用方提供的整页内容（Explicit，恰好 %1 字节）"))
            .arg(kPageBytes);
        lines << ks::i18n::sourceText(
            QStringLiteral("补丁：从页内偏移 %1 起，共 %2 字节，止于偏移 %3"))
            .arg(hexText(m_plan.pageOffset))
            .arg(m_plan.patchLength())
            .arg(hexText(m_plan.patchEndOffset()));
        lines << ks::i18n::sourceText(
            QStringLiteral("稳态叶权限：真页 | 读 | 写，不给执行 —— 所以稳态下对这一页的读写不产生任何 violation。"));
        lines << ks::i18n::sourceText(
            QStringLiteral("翻转态叶权限：影子页 | 执行；处理器缺 execute-only 能力时驱动会静默补上读权限。"));
        lines << ks::i18n::sourceText(
            QStringLiteral("补丁几何：%1"))
            .arg(m_plan.classifyPatchGeometry()
                    == Ksword::Evidence::CrossPageClassification::InPage
                ? ks::i18n::sourceText(QStringLiteral("完全落在这一页内"))
                : ks::i18n::sourceText(QStringLiteral("越过了页尾，必须拒绝")));
        lines << ks::i18n::sourceText(
            QStringLiteral("HOOK 不是安全边界，失败即放行：翻转窗口里指令长度为 0 时处理器会重执行并读到真页。"));
        return lines.join(QStringLiteral("\n"));
    }

    void KvmHookWizard::startInstall()
    {
        if (m_busy || m_installInFlight)
        {
            return;
        }
        if (!m_plan.resolved)
        {
            failBackTo(
                Step::Target,
                ks::i18n::sourceText(
                    QStringLiteral("目标还没有归一化成功，没有可装的页基址。")),
                0,
                0);
            return;
        }
        if (!m_plan.baselineIsComplete() || m_plan.patchIsEmpty())
        {
            failBackTo(
                Step::Patch,
                ks::i18n::sourceText(
                    QStringLiteral("基线不完整或补丁为空，成品影子页拼不出来。")),
                0,
                0);
            return;
        }

        QString composeFailure;
        const QByteArray shadowPage =
            m_plan.composedShadowPage(&composeFailure);
        if (shadowPage.size() != kPageBytes)
        {
            // 半成品页不能往下走：seed 是 Explicit，驱动会把这一页整份拷进影子帧，
            // 而影子帧正是被执行的那一份。
            failBackTo(
                Step::Patch,
                composeFailure.isEmpty()
                    ? ks::i18n::sourceText(
                        QStringLiteral("成品影子页拼不出完整的一页，已中止安装。"))
                    : composeFailure,
                0,
                0);
            return;
        }

        // 确认在 UI 线程弹，弹完才起后台线程。
        const QString actionTitle = ks::i18n::sourceText(
            QStringLiteral("安装一条 HOOK EPT 分离视图"));
        const QString targetDescription = ks::i18n::sourceText(
            QStringLiteral("目标物理页 %1（入口：%2），影子页由基线页 %3 字节加上 %4 字节补丁现拼，补丁从页内偏移 %5 起。"))
            .arg(hexText(m_plan.pageBasePhysical))
            .arg(describeHookTargetSource(m_plan.targetSource))
            .arg(kPageBytes)
            .arg(m_plan.patchLength())
            .arg(hexText(m_plan.pageOffset));
        const QString riskDescription = ks::i18n::sourceText(
            QStringLiteral("这是 UI 上补的一道要人来点的门，它不是协议确认：客户端仍然无条件替你置上 UI_CONFIRMED 与确认令牌，驱动侧那道协议门在这条路径上本来就是自动满足的。HOOK 也不是安全边界 —— 稳态下对这一页的读写走真实页并被显式授予，不产生任何事件。"));
        if (!ks::ui::confirmDestructiveAction(
                this,
                QStringLiteral("KvmHookInstall"),
                actionTitle,
                targetDescription,
                riskDescription))
        {
            setStatusText(
                ks::i18n::sourceText(QStringLiteral("已取消，没有发起安装。")),
                KvmCheckVerdict::NoReading);
            return;
        }

        m_installInFlight = true;
        setBusy(true);
        if (m_installStatusLabel != nullptr)
        {
            m_installStatusLabel->setText(ks::i18n::sourceText(
                QStringLiteral("正在重读目标页并比对基线...")));
            ApplyStatusRole(m_installStatusLabel, StatusRole::Info);
        }

        const quint64 pageBase = m_plan.pageBasePhysical;
        const QByteArray baseline = m_plan.baselinePage;
        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, pageBase, baseline, shadowPage]() {
            const InstallOutcome outcome =
                performInstallBlocking(pageBase, baseline, shadowPage);
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, outcome]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyInstallOutcome(outcome);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    KvmHookWizard::InstallOutcome KvmHookWizard::performInstallBlocking(
        const quint64 pageBasePhysical,
        const QByteArray& baselinePage,
        const QByteArray& shadowPage)
    {
        InstallOutcome outcome;

        // 1) 重读目标页。从第 2 步抓基线到这里可能过了几分钟。
        outcome.freshPage = readTargetPage(pageBasePhysical, &outcome.rereadFailure);
        outcome.rereadOk =
            outcome.freshPage.size() == kPageBytes;
        if (!outcome.rereadOk)
        {
            return outcome;
        }

        // 2) 与冻结的基线逐字节比对。不同就停下 —— 我们拼出来的影子页里含的是
        //    过期的原字节，而影子页正是被执行的那一份。
        outcome.baselineMatches = (outcome.freshPage == baselinePage);
        if (!outcome.baselineMatches)
        {
            return outcome;
        }

        // 3) 比对通过意味着重读回来的字节与基线逐位相同，所以「把补丁应用到刚读
        //    回来的字节上」与调用方传进来的这一页是同一份，不需要再拼一次。
        outcome.addAttempted = true;
        outcome.addResult = ksword::kvm::addView(
            KSWORD_ARK_HVM_VIEW_KIND_HOOK,
            pageBasePhysical,
            ksword::kvm::KvmViewShadowSeed::Explicit,
            shadowPage);
        if (!outcome.addResult.ok)
        {
            return outcome;
        }

        // 4) 立刻回读一次：ADD 的响应里没有 shadowPhysicalAddress。
        outcome.listAfter = ksword::kvm::listViews();
        return outcome;
    }

    void KvmHookWizard::applyInstallOutcome(const InstallOutcome& outcome)
    {
        m_installInFlight = false;
        setBusy(false);

        if (!outcome.rereadOk)
        {
            failBackTo(
                Step::Patch,
                ks::i18n::sourceText(
                    QStringLiteral("安装前重读目标页失败，没有发起安装：%1"))
                    .arg(outcome.rereadFailure),
                0,
                0);
            return;
        }

        if (!outcome.baselineMatches)
        {
            // 列出变了的偏移。只说「变了」等于让人自己再去查一遍。
            QStringList changed;
            // 用 qMin 而不是 std::min：Windows.h 在某些包含顺序下会带进 min 宏，
            // 那个宏会把 std::min( 展开成一段语法上不成立的东西。
            const qsizetype length =
                qMin(outcome.freshPage.size(), m_plan.baselinePage.size());
            for (qsizetype index = 0; index < length; ++index)
            {
                if (outcome.freshPage.at(index) != m_plan.baselinePage.at(index))
                {
                    if (changed.size() >= 32)
                    {
                        changed << ks::i18n::sourceText(
                            QStringLiteral("...（还有更多，只列前 32 处）"));
                        break;
                    }
                    const uint oldByte = static_cast<uint>(
                        static_cast<quint8>(m_plan.baselinePage.at(index)));
                    const uint newByte = static_cast<uint>(
                        static_cast<quint8>(outcome.freshPage.at(index)));
                    changed << QStringLiteral("+0x%1: %2 -> %3")
                        .arg(static_cast<quint64>(index), 3, 16,
                             QLatin1Char('0'))
                        .arg(oldByte, 2, 16, QLatin1Char('0'))
                        .arg(newByte, 2, 16, QLatin1Char('0'));
                }
            }
            if (m_installSummaryView != nullptr)
            {
                m_installSummaryView->setPlainText(
                    ks::i18n::sourceText(
                        QStringLiteral("目标页在抓基线之后被改过，已中止安装。变化的页内偏移："))
                    + QStringLiteral("\n")
                    + changed.join(QStringLiteral("\n")));
            }
            // 拿重读回来的这一页当新基线，用户回第 2 步重编补丁即可，
            // 不必从第 1 步重来，也不用再读一遍。
            m_plan.baselinePage = outcome.freshPage;
            if (m_shadowEditor != nullptr)
            {
                revertPatch();
            }
            failBackTo(
                Step::Patch,
                ks::i18n::sourceText(
                    QStringLiteral("目标页在抓基线之后被改过，已中止安装：影子页里含的会是过期的原字节，而影子页正是被执行的那一份。")),
                0,
                0);
            return;
        }

        if (!outcome.addAttempted)
        {
            failBackTo(
                Step::Preflight,
                ks::i18n::sourceText(
                    QStringLiteral("安装请求没有发出，卡在重读或比对这一步。")),
                0,
                0);
            return;
        }

        if (!outcome.addResult.ok)
        {
            const Step target = stepForViewFailure(
                outcome.addResult.protocolStatus,
                outcome.addResult.lastStatus);
            failBackTo(
                target,
                outcome.addResult.message,
                outcome.addResult.protocolStatus,
                outcome.addResult.lastStatus);
            return;
        }

        m_plan.installedViewId = outcome.addResult.viewId;
        m_plan.installed = true;
        m_plan.shadowPhysicalAddress = 0;
        for (const auto& entry : outcome.listAfter.views)
        {
            if (entry.viewId == m_plan.installedViewId)
            {
                m_plan.shadowPhysicalAddress = entry.shadowPhysicalAddress;
                break;
            }
        }

        const QString summary = ks::i18n::sourceText(
            QStringLiteral("已安装视图 %1：目标物理页 %2，影子物理页 %3。注意这只说明驱动接受了请求，那张叶到底改了没有要看第 5 步的读数。"))
            .arg(m_plan.installedViewId)
            .arg(hexText(m_plan.pageBasePhysical))
            .arg(m_plan.shadowPhysicalAddress != 0
                ? hexText(m_plan.shadowPhysicalAddress)
                : ks::i18n::sourceText(QStringLiteral("回读没拿到")));
        if (m_installStatusLabel != nullptr)
        {
            m_installStatusLabel->setText(summary);
            ApplyStatusRole(m_installStatusLabel, StatusRole::Success);
        }
        // 与 failBackTo 同一个理由：先切页再写状态行，否则第 5 步的取数会把
        // 这条摘要当场盖掉。
        goToStep(Step::Verify);
        setStatusText(summary, KvmCheckVerdict::Pass);
    }
}
