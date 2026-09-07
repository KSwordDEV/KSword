// KvmHookWizard.Verify.cpp：第 3 步（预检）与第 5 步（装后校验）。
//
// 这两步是同一件事的两端：装之前把驱动会拒绝的理由逐条摆出来，装之后把「到底
// 生效了没有」这个问题拆成几条各自能被证伪的读数。它们共用一张四列表
// （判据 / 当前读数 / 结论 / 修复），列语义因此不会走散：
// 第 2 列只许写读到了什么（带数字与状态位），第 3 列才是结论。
//
// 为什么每条判据都是三态：
//   「目标函数在观察窗口内没被执行过」既不是通过也不是失败；「EPTP 切换后端下
//   flipCount 恒为 0」也不是失败。只有两态的话这些读数会被强行涂成红或绿，
//   而两种涂法都是在说谎。所以 NoReading 取中性色，并且必须说清为什么没有读数。
//
// 【本文件不写 m_plan】计划的每一段各有唯一的写者（见 KvmHookPlan.h 的分节），
// 这里只读。

#include "KvmHookWizard.h"

#include "KvmControl.h"
#include "KvmEptLeafProbe.h"
#include "KvmViewDialog.h"
#include "KvmWriteAccessGate.h"
#include "ThemeStatusRole.h"
#include "../Internationalization/LanguageManager.h"

#include <QAbstractItemView>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <thread>

namespace
{
    // 驱动接受的物理地址上界：KSW_HVM_MAX_MAPPED_PHYSICAL
    // = 512 GiB * 16 个 PML4 项 = 8 TiB（hvm_internal.h:54-56），
    // 安装时与页对齐一起被查（hvm_ept_view.c:288-295）。
    // 客户端复述它是为了把拒绝提前到预检，而不是等驱动回一个 INVALID_REQUEST。
    constexpr quint64 kMaxMappedPhysical = 0x80000000000ULL;

    // 常驻观察的轮询间隔。1 秒既跟得上人手动触发目标函数，
    // 又不至于把驱动侧状态锁打满。
    constexpr int kResidentPollIntervalMs = 1000;

    // hex64：地址一律按 0x 十六进制回显。这是数值格式不是译文，不进词条。
    QString hex64(const quint64 value)
    {
        return QStringLiteral("0x%1").arg(value, 0, 16);
    }

    // flagText：状态位按它在协议里的名字回显 true/false。
    // 刻意不译成「是/否」：读数列要能和驱动侧字段名逐字对上。
    QString flagText(const bool value)
    {
        return value ? QStringLiteral("true") : QStringLiteral("false");
    }

    // makeRow：拼一行四列。参数顺序与列序一致，避免在调用点写错列。
    ks::ui::KvmCheckRow makeRow(
        const int criterionId,
        const QString& criterion,
        const QString& reading,
        const ks::ui::KvmCheckVerdict verdict,
        const QString& conclusion,
        const ks::ui::KvmCheckRemedy remedy,
        const QString& remedyLabel,
        const bool blocking)
    {
        ks::ui::KvmCheckRow row;
        row.criterionId = criterionId;
        row.criterion = criterion;
        row.reading = reading;
        row.verdict = verdict;
        row.conclusion = conclusion;
        row.remedy = remedy;
        row.remedyLabel = remedyLabel;
        row.blocking = blocking;
        return row;
    }

    // findInstalledView：在一次 LIST 结果里按 viewId 找那条视图。
    // 找不到返回 nullptr —— 调用点必须区分「表里没有」和「表读失败」，
    // 前者是 Fail，后者是 NoReading。
    const ksword::kvm::KvmViewEntry* findInstalledView(
        const ksword::kvm::KvmViewResult& views,
        const unsigned long viewId)
    {
        if (viewId == 0UL)
        {
            return nullptr;
        }
        for (const ksword::kvm::KvmViewEntry& entry : views.views)
        {
            if (entry.viewId == viewId)
            {
                return &entry;
            }
        }
        return nullptr;
    }

    // firstDifferenceOffset：两页字节的第一处差异下标；完全相同返回 -1。
    // 长度不同也算差异，返回较短的那个长度处。
    qsizetype firstDifferenceOffset(
        const QByteArray& left,
        const QByteArray& right)
    {
        const qsizetype shared = qMin(left.size(), right.size());
        for (qsizetype index = 0; index < shared; ++index)
        {
            if (left.at(index) != right.at(index))
            {
                return index;
            }
        }
        return left.size() == right.size() ? -1 : shared;
    }
}

namespace ks::ui
{
    QString describeCheckVerdict(const KvmCheckVerdict verdict)
    {
        switch (verdict)
        {
        case KvmCheckVerdict::Pass:
            return ks::i18n::sourceText(QStringLiteral("通过"));
        case KvmCheckVerdict::Fail:
            return ks::i18n::sourceText(QStringLiteral("未通过"));
        case KvmCheckVerdict::NoReading:
            break;
        }
        // 「无读数」必须与「未通过」在字面上就分得开：它是一个独立的结论，
        // 不是失败的委婉说法。
        return ks::i18n::sourceText(QStringLiteral("无读数"));
    }

    StatusRole checkVerdictStatusRole(const KvmCheckVerdict verdict)
    {
        switch (verdict)
        {
        case KvmCheckVerdict::Pass:
            return StatusRole::Success;
        case KvmCheckVerdict::Fail:
            return StatusRole::Error;
        case KvmCheckVerdict::NoReading:
            break;
        }
        // 中性色是硬约定：涂红会让一条「没有读数」看起来像失败，
        // 涂绿会让它看起来像通过，而它两者都不是。
        return StatusRole::Idle;
    }

    // =====================================================================
    // 第 3 步：预检
    // =====================================================================

    QWidget* KvmHookWizard::buildPreflightPage()
    {
        QWidget* const page = new QWidget(this);
        QVBoxLayout* const layout = new QVBoxLayout(page);

        QLabel* const hintLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("这一页把驱动安装视图时逐条检查的前置条件读回来。第 2 列是实测读数，第 3 列才是结论；带修复按钮的那几条能就地处理，没有按钮的那几条只能解释，本向导不提供任何绕过驱动前置检查的路径。")),
            page);
        hintLabel->setWordWrap(true);
        layout->addWidget(hintLabel);

        m_preflightTable = new QTableWidget(0, 4, page);
        m_preflightTable->setHorizontalHeaderLabels(QStringList()
            << ks::i18n::sourceText(QStringLiteral("判据"))
            << ks::i18n::sourceText(QStringLiteral("当前读数"))
            << ks::i18n::sourceText(QStringLiteral("结论"))
            << ks::i18n::sourceText(QStringLiteral("修复")));
        m_preflightTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_preflightTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_preflightTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_preflightTable->verticalHeader()->setVisible(false);
        m_preflightTable->horizontalHeader()->setSectionResizeMode(
            1,
            QHeaderView::Stretch);
        layout->addWidget(m_preflightTable, 1);

        QHBoxLayout* const buttonLayout = new QHBoxLayout();
        m_preflightRefreshButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("重新预检")),
            page);
        buttonLayout->addWidget(m_preflightRefreshButton);
        buttonLayout->addStretch(1);
        layout->addLayout(buttonLayout);

        m_preflightStatusLabel = new QLabel(QString(), page);
        m_preflightStatusLabel->setWordWrap(true);
        layout->addWidget(m_preflightStatusLabel);

        connect(m_preflightRefreshButton, &QPushButton::clicked, this, [this]() {
            startPreflightRefresh();
        });
        // 防抖定时器由骨架持有。它可能还没被建出来（构造顺序由 [W] 决定），
        // 所以这里只在存在时接线，schedulePreflightRefresh 里另有退化分支。
        if (m_preflightDebounce != nullptr)
        {
            m_preflightDebounce->setSingleShot(true);
            connect(m_preflightDebounce, &QTimer::timeout, this, [this]() {
                startPreflightRefresh();
            });
        }
        return page;
    }

    void KvmHookWizard::schedulePreflightRefresh()
    {
        if (m_preflightDebounce == nullptr)
        {
            // 没有定时器时退化成立即刷新：宁可多发一次 IOCTL，
            // 也不要出现一个点了没反应的按钮。
            startPreflightRefresh();
            return;
        }
        m_preflightDebounce->setSingleShot(true);
        m_preflightDebounce->start(kInputDebounceMilliseconds);
    }

    void KvmHookWizard::startPreflightRefresh()
    {
        if (m_preflightInFlight)
        {
            return;
        }
        m_preflightInFlight = true;
        // 序号必须在发起时就取：回来的顺序不保证与发出的顺序一致。
        const quint64 sequence = ++m_preflightSequence;
        setBusy(true);
        if (m_preflightStatusLabel != nullptr)
        {
            m_preflightStatusLabel->setText(ks::i18n::sourceText(
                QStringLiteral("正在读取驱动状态与已装视图……")));
            ApplyStatusRole(m_preflightStatusLabel, StatusRole::Info);
        }

        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, sequence]() {
            // QUERY + LIST 都是阻塞 IOCTL，必须在这条后台线程里跑完。
            const PreflightSnapshot snapshot = collectPreflightSnapshot();
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, sequence, snapshot]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyPreflightResult(sequence, snapshot);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::applyPreflightResult(
        const quint64 sequence,
        const PreflightSnapshot& snapshot)
    {
        // 单飞标志无论序号是否过期都要清，否则一次被丢弃的读数会把入口永久卡住。
        m_preflightInFlight = false;
        setBusy(false);
        if (sequence != m_preflightSequence)
        {
            // 已经被后续刷新作废的旧读数：落地它会让表格与当前计划对不上。
            return;
        }

        m_preflightRows = buildPreflightRows(snapshot, m_plan);
        fillCheckTable(m_preflightTable, m_preflightRows);

        int failCount = 0;
        int noReadingCount = 0;
        for (const KvmCheckRow& row : m_preflightRows)
        {
            if (row.verdict == KvmCheckVerdict::Fail)
            {
                ++failCount;
            }
            else if (row.verdict == KvmCheckVerdict::NoReading)
            {
                ++noReadingCount;
            }
        }
        if (m_preflightStatusLabel != nullptr)
        {
            const bool blocked = hasBlockingPreflightFailure();
            m_preflightStatusLabel->setText(
                ks::i18n::sourceText(QStringLiteral("共 %1 条判据：未通过 %2 条，无读数 %3 条。%4"))
                    .arg(m_preflightRows.size())
                    .arg(failCount)
                    .arg(noReadingCount)
                    .arg(blocked
                        ? ks::i18n::sourceText(QStringLiteral("仍有阻塞项没有通过，现在不能进入安装步骤。"))
                        : ks::i18n::sourceText(QStringLiteral("阻塞项都已通过，可以进入安装步骤。"))));
            ApplyStatusRole(
                m_preflightStatusLabel,
                blocked ? StatusRole::Warning : StatusRole::Success);
        }
        // 阻塞状态变了，下一步按钮要跟着变。
        updateNavigationState();
    }

    KvmHookWizard::PreflightSnapshot KvmHookWizard::collectPreflightSnapshot()
    {
        PreflightSnapshot snapshot;
        // 两个读数必须来自同一时刻：分两次取会出现「状态说未常驻、视图表却是
        // 常驻期间的旧值」这种自相矛盾的一屏。
        snapshot.state = ksword::kvm::queryState();
        // queryState 永远返回一个结构体，驱动没跑时由 availability 承载这件事，
        // 所以 stateValid 记录的是「这次调用回来了」，不是「驱动可用」。
        snapshot.stateValid = true;

        const ksword::kvm::KvmViewResult views = ksword::kvm::listViews();
        snapshot.viewsOk = views.ok;
        snapshot.viewCount = views.ok ? views.viewCount : 0UL;
        snapshot.viewsMessage = views.message;
        return snapshot;
    }

    QVector<KvmCheckRow> KvmHookWizard::buildPreflightRows(
        const PreflightSnapshot& snapshot,
        const KvmHookPlan& plan)
    {
        QVector<KvmCheckRow> rows;
        rows.reserve(static_cast<int>(KvmHookPreflightCriterion::Count));

        const ksword::kvm::KvmState& state = snapshot.state;

        // ---- 0. R-1 写权限门 ----
        const bool writeAllowed = ksword::kvm::isWriteAccessEnabled();
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::WriteAccessGate),
            ks::i18n::sourceText(QStringLiteral("R-1 写权限门已开启")),
            ks::i18n::sourceText(QStringLiteral("写权限门（客户端侧）= %1"))
                .arg(flagText(writeAllowed)),
            writeAllowed ? KvmCheckVerdict::Pass : KvmCheckVerdict::Fail,
            writeAllowed
                ? ks::i18n::sourceText(QStringLiteral("客户端侧这道门是开的。驱动侧另外还要确认令牌与 FILE_WRITE_ACCESS，那两道不在这里判。"))
                : ks::i18n::sourceText(QStringLiteral("关闭时安装视图的请求在客户端就被拒，根本不会发出 IOCTL。")),
            writeAllowed ? KvmCheckRemedy::None : KvmCheckRemedy::EnableWriteAccess,
            ks::i18n::sourceText(QStringLiteral("开启写权限")),
            true));

        // ---- 1. 资源已准备 ----
        // 「驱动在不在跑」由 availability 承载，和 resourcesReady 摆在同一行：
        // 分两行会让用户在驱动没起来时看到两条互相重复的红。
        const bool driverRunning =
            state.availability != ksword::kvm::KvmAvailability::DriverNotRunning;
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::ResourcesPrepared),
            ks::i18n::sourceText(QStringLiteral("驱动在跑且资源已准备（PREPARE 已执行、未 TEARDOWN）")),
            ks::i18n::sourceText(QStringLiteral("availability=%1；resourcesReady=%2；generation=%3；faulted=%4"))
                .arg(ksword::kvm::describeAvailability(state.availability))
                .arg(flagText(state.resourcesReady))
                .arg(state.generation)
                .arg(flagText(state.faulted)),
            state.resourcesReady ? KvmCheckVerdict::Pass : KvmCheckVerdict::Fail,
            state.resourcesReady
                ? ks::i18n::sourceText(QStringLiteral("资源在位。现在正是安装分离视图的窗口期——启动常驻之后视图表就不可变了。"))
                : (driverRunning
                    ? ks::i18n::sourceText(QStringLiteral("资源未准备，驱动会直接拒绝安装。准备资源要在标题栏 KVM 菜单里做，本向导不自己发 PREPARE。"))
                    : ks::i18n::sourceText(QStringLiteral("KswordARK 驱动未运行，先点 R0 启动驱动服务，其余判据在此之前都读不到真值。"))),
            state.resourcesReady ? KvmCheckRemedy::None : KvmCheckRemedy::PrepareResources,
            ks::i18n::sourceText(QStringLiteral("去 KVM 菜单准备资源")),
            true));

        // ---- 2. 未常驻 ----
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::NotResident),
            ks::i18n::sourceText(QStringLiteral("未常驻：常驻期间驱动拒绝改动视图表")),
            ks::i18n::sourceText(QStringLiteral("residentActive=%1；residentProcessorCount=%2 / 逻辑处理器 %3；nestedResident=%4"))
                .arg(flagText(state.residentActive))
                .arg(state.residentProcessorCount)
                .arg(state.processorCount)
                .arg(flagText(state.nestedResident)),
            state.residentActive ? KvmCheckVerdict::Fail : KvmCheckVerdict::Pass,
            state.residentActive
                ? ks::i18n::sourceText(QStringLiteral("常驻中的 VM exit 不取 PASSIVE_LEVEL 锁就读视图表，所以驱动在还有处理器处于 non-root 时把整张表连同每张叶和每页影子都锁成不可变（hvm_ept_view.c:948-966）。停止常驻要在标题栏 KVM 菜单或内核 Dock 的 HVM 页里做。"))
                : ks::i18n::sourceText(QStringLiteral("没有处理器处于 non-root，视图表此刻可改。")),
            state.residentActive ? KvmCheckRemedy::StopResident : KvmCheckRemedy::None,
            ks::i18n::sourceText(QStringLiteral("去 KVM 菜单停止常驻")),
            true));

        // ---- 3. EPT 层次已建好 ----
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::EptReady),
            ks::i18n::sourceText(QStringLiteral("EPT 层次已建好（安装视图的第一道硬门）")),
            ks::i18n::sourceText(QStringLiteral("eptReady=%1；eptPointer=%2；eptRulesReady=%3；eptRuleCount=%4"))
                .arg(flagText(state.eptReady))
                .arg(hex64(state.eptPointer))
                .arg(flagText(state.eptRulesReady))
                .arg(state.eptRuleCount),
            state.eptReady ? KvmCheckVerdict::Pass : KvmCheckVerdict::Fail,
            state.eptReady
                ? ks::i18n::sourceText(QStringLiteral("层次在位，驱动这一道检查会过（hvm_ept_view.c:614-622）。"))
                : ks::i18n::sourceText(QStringLiteral("缺 STATE_EPT_READY 时驱动回 NOT_PREPARED / STATUS_DEVICE_NOT_READY（hvm_ept_view.c:614-622）。层次由 PREPARE 建，去 KVM 菜单准备资源。")),
            state.eptReady ? KvmCheckRemedy::None : KvmCheckRemedy::PrepareResources,
            ks::i18n::sourceText(QStringLiteral("去 KVM 菜单准备资源")),
            true));

        // ---- 4. 拓扑：单核或私有 EPT 已武装 ----
        //
        // 这一条在多核机上**没有出路**，所以它挂的按钮只解释不修复。
        const bool localEptRequested = ksword::kvm::isLocalEptEnabled();
        const bool topologyOk = state.processorCount == 1UL || state.localEptArmed;
        QString topologyConclusion;
        if (topologyOk)
        {
            topologyConclusion = state.localEptArmed
                ? ks::i18n::sourceText(QStringLiteral("私有 EPT 已武装：翻转只落在取到 exit 的那个处理器上，多核也能安装。"))
                : ks::i18n::sourceText(QStringLiteral("单处理器拓扑：翻转窗口不会被别的处理器看到，驱动这一条会过（hvm_ept_view.c:687-695）。"));
            if (localEptRequested && !state.localEptArmed)
            {
                // 单核也会被这条链路打死：startResident 把 isLocalEptEnabled()
                // 原样传进 START_RESIDENT（KvmControl.cpp:523），
                // 而 LocalEptArmed 恒假会让驱动以「处理器不支持」拒绝启动。
                topologyConclusion += QStringLiteral(" ");
                topologyConclusion += ks::i18n::sourceText(QStringLiteral("注意：私有 EPT 持久化开关是打开的但没有武装，而启动常驻会把这个请求原样发给驱动（KvmControl.cpp:523），于是常驻会以「处理器不支持」被拒——在单核机上也一样。第 5 步 B 段要观察翻转的话，先在 KVM 菜单里把这个开关关掉。"));
            }
        }
        else
        {
            topologyConclusion = ks::i18n::sourceText(QStringLiteral("多核且私有 EPT 未武装：驱动回 MULTIPROCESSOR_UNSAFE / STATUS_NOT_SUPPORTED（hvm_ept_view.c:687-695）。而武装它需要 PREPARE 带 ENABLE_LOCAL_EPT——那个标志确实会被 PREPARE 读取并置位（hvm_runtime.c:1573-1582），却不在 PREPARE 的 allowedFlags 白名单里（hvm_runtime.c:2682-2685），驱动自己的注释把这件事称为 standing defect（hvm_runtime.c:2674-2681）。所以这一条在多核机上通过协议不可达，本向导不提供任何假装是出路的按钮。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::Topology),
            ks::i18n::sourceText(QStringLiteral("拓扑：单处理器，或每处理器私有 EPT 已武装")),
            ks::i18n::sourceText(QStringLiteral("逻辑处理器 %1；localEptArmed=%2；私有 EPT 持久化开关=%3；eptpSwitchArmed=%4"))
                .arg(state.processorCount)
                .arg(flagText(state.localEptArmed))
                .arg(flagText(localEptRequested))
                .arg(flagText(state.eptpSwitchArmed)),
            topologyOk ? KvmCheckVerdict::Pass : KvmCheckVerdict::Fail,
            topologyConclusion,
            topologyOk
                ? KvmCheckRemedy::None
                : KvmCheckRemedy::ExplainLocalEptUnreachable,
            ks::i18n::sourceText(QStringLiteral("为什么多核上没有出路")),
            true));

        // ---- 5. 单上下文 INVEPT ----
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::InveptSingle),
            ks::i18n::sourceText(QStringLiteral("处理器支持单上下文 INVEPT（两套后端都要）")),
            ks::i18n::sourceText(QStringLiteral("inveptSingleReady=%1"))
                .arg(flagText(state.inveptSingleReady)),
            state.inveptSingleReady ? KvmCheckVerdict::Pass : KvmCheckVerdict::Fail,
            state.inveptSingleReady
                ? ks::i18n::sourceText(QStringLiteral("无论写回叶项还是切 EPTP，都得把按旧值建出来的翻译丢掉，这条能力在位。"))
                : ks::i18n::sourceText(QStringLiteral("这是处理器能力，客户端修不了：这台机器装不了分离视图。")),
            KvmCheckRemedy::None,
            QString(),
            true));

        // ---- 6. 后端能力 ----
        //
        // 必须先看 eptpSwitchArmed 再决定看哪一位：单看 monitorTrapFlagReady
        // 会把嵌套 Hyper-V 客户机误判成无解，而那恰恰是切换后端存在的理由。
        KvmCheckVerdict backendVerdict = KvmCheckVerdict::Pass;
        QString backendConclusion;
        KvmCheckRemedy backendRemedy = KvmCheckRemedy::None;
        if (state.eptpSwitchArmed)
        {
            backendConclusion = ks::i18n::sourceText(QStringLiteral("已武装 EPTP 切换后端：它不需要 Monitor Trap Flag，只需要 execute-only EPT 叶。而 execute-only 这一位由驱动在安装时判定，客户端没有对应的状态位可读——所以本行只证明后端选择这一关过了，不代表安装一定成功。"));
        }
        else if (state.monitorTrapFlagReady)
        {
            backendConclusion = ks::i18n::sourceText(QStringLiteral("默认后端（写叶 + Monitor Trap Flag 单步一条指令 + 写回），MTF 在位。"));
        }
        else
        {
            backendVerdict = KvmCheckVerdict::Fail;
            if (state.eptpSwitchingAvailable)
            {
                backendConclusion = ks::i18n::sourceText(QStringLiteral("默认后端要 Monitor Trap Flag，这台机器没有（嵌套 Hyper-V 客户机就拿不到它）。处理器提供 VM function 0，所以改用 EPTP 切换后端是可行的：这一位只随 PREPARE 发出，要先在 KVM 菜单里打开开关，再释放资源并重新准备才会生效。"));
                backendRemedy = KvmCheckRemedy::SwitchToEptpBackend;
            }
            else
            {
                backendConclusion = ks::i18n::sourceText(QStringLiteral("默认后端要 Monitor Trap Flag，这台机器没有；而处理器也不提供 VM function 0，所以换成 EPTP 切换后端同样走不通。这是硬件能力，客户端修不了。"));
            }
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::Backend),
            ks::i18n::sourceText(QStringLiteral("后端能力：默认后端看 Monitor Trap Flag，EPTP 切换后端看 execute-only")),
            ks::i18n::sourceText(QStringLiteral("eptpSwitchArmed=%1；monitorTrapFlagReady=%2；eptpSwitchingAvailable=%3"))
                .arg(flagText(state.eptpSwitchArmed))
                .arg(flagText(state.monitorTrapFlagReady))
                .arg(flagText(state.eptpSwitchingAvailable)),
            backendVerdict,
            backendConclusion,
            backendRemedy,
            ks::i18n::sourceText(QStringLiteral("改用 EPTP 切换后端")),
            true));

        // ---- 7. 视图表容量 ----
        //
        // 【只是部分可预检】这里只数得到条数：本步的快照没有带回条目清单，
        // 所以「目标页是不是已经被某条已装视图占用」在这一层判不了。那类冲突
        // 与「目标页被某条 EPT 规则区间覆盖」一样（KvmControl 也没有列举规则的
        // 接口），都要到安装时才会以 LEAF_CONFLICT 暴露出来。
        KvmCheckVerdict capacityVerdict = KvmCheckVerdict::Pass;
        QString capacityConclusion;
        KvmCheckRemedy capacityRemedy = KvmCheckRemedy::None;
        if (!snapshot.viewsOk)
        {
            capacityVerdict = KvmCheckVerdict::NoReading;
            capacityConclusion = ks::i18n::sourceText(QStringLiteral("读不到视图表，因此不知道还有没有位置。「不知道」不是「可以装」，所以这一条同样挡住下一步。"));
        }
        else if (snapshot.viewCount >= KSWORD_ARK_HVM_MAX_VIEWS)
        {
            capacityVerdict = KvmCheckVerdict::Fail;
            capacityConclusion = ks::i18n::sourceText(QStringLiteral("视图表已满，必须先移除一条才能再装。"));
            capacityRemedy = KvmCheckRemedy::OpenViewPanel;
        }
        else
        {
            capacityConclusion = ks::i18n::sourceText(QStringLiteral("表里还有位置。注意这一条只数了条数：目标页是否已被某条已装视图占用、或被某条 EPT 规则区间覆盖，本预检都看不到——那两种冲突会在安装时以 LEAF_CONFLICT 暴露。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::ViewTableCapacity),
            ks::i18n::sourceText(QStringLiteral("视图表还有位置（上限 32 条）")),
            ks::i18n::sourceText(QStringLiteral("已装视图 %1 条 / 上限 %2；LIST 结果=%3%4"))
                .arg(snapshot.viewCount)
                .arg(static_cast<unsigned long>(KSWORD_ARK_HVM_MAX_VIEWS))
                .arg(flagText(snapshot.viewsOk))
                .arg(snapshot.viewsMessage.isEmpty()
                    ? QString()
                    : QStringLiteral("；%1").arg(snapshot.viewsMessage)),
            capacityVerdict,
            capacityConclusion,
            capacityRemedy,
            ks::i18n::sourceText(QStringLiteral("打开视图面板")),
            true));

        // ---- 8. 目标页几何 ----
        KvmCheckVerdict geometryVerdict = KvmCheckVerdict::Pass;
        QString geometryConclusion;
        if (!plan.resolved)
        {
            geometryVerdict = KvmCheckVerdict::NoReading;
            geometryConclusion = ks::i18n::sourceText(QStringLiteral("目标还没有解析成功，pageBasePhysical 不可信。回第 1 步把目标定下来。"));
        }
        else if (!plan.pageIsAligned())
        {
            geometryVerdict = KvmCheckVerdict::Fail;
            geometryConclusion = ks::i18n::sourceText(QStringLiteral("目标物理页没有页对齐，驱动会回 INVALID_REQUEST（hvm_ept_view.c:288-295）。"));
        }
        else if (plan.pageBasePhysical >= kMaxMappedPhysical)
        {
            geometryVerdict = KvmCheckVerdict::Fail;
            geometryConclusion = ks::i18n::sourceText(QStringLiteral("目标物理页超出 EPT 后端接受的 8 TiB 窗口，驱动会回 INVALID_REQUEST（hvm_ept_view.c:288-295）。"));
        }
        else
        {
            geometryConclusion = ks::i18n::sourceText(QStringLiteral("页对齐且在 8 TiB 窗口内。请注意驱动**只**查这两条：它不查目标页是不是 RAM，也不查这一页归谁——地址算错的后果是给一页无关内存挂上 HOOK，而且全程不会有人报错。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::TargetPageGeometry),
            ks::i18n::sourceText(QStringLiteral("目标页几何：页对齐且小于 8 TiB")),
            ks::i18n::sourceText(QStringLiteral("resolved=%1；virtualAddress=%2；fullPhysicalAddress=%3；pageBasePhysical=%4；pageOffset=%5"))
                .arg(flagText(plan.resolved))
                .arg(hex64(plan.virtualAddress))
                .arg(hex64(plan.fullPhysicalAddress))
                .arg(hex64(plan.pageBasePhysical))
                .arg(hex64(plan.pageOffset)),
            geometryVerdict,
            geometryConclusion,
            geometryVerdict == KvmCheckVerdict::Pass
                ? KvmCheckRemedy::None
                : KvmCheckRemedy::ReturnToTargetStep,
            ks::i18n::sourceText(QStringLiteral("回第 1 步改目标")),
            true));

        // ---- 9. 补丁几何 ----
        const Ksword::Evidence::CrossPageClassification classification =
            plan.classifyPatchGeometry();
        const bool crossesPage =
            classification == Ksword::Evidence::CrossPageClassification::CrossesPage;
        KvmCheckVerdict patchVerdict = KvmCheckVerdict::Pass;
        QString patchConclusion;
        if (plan.patchIsEmpty())
        {
            patchVerdict = KvmCheckVerdict::Fail;
            patchConclusion = ks::i18n::sourceText(QStringLiteral("补丁是空的。空补丁拼出来的影子页与原页逐位相同，装上去什么都不改变，却会让人以为补丁生效了。"));
        }
        else if (crossesPage)
        {
            patchVerdict = KvmCheckVerdict::Fail;
            patchConclusion = ks::i18n::sourceText(QStringLiteral("补丁越过了页尾。一条视图恰好覆盖一页，协议里没有 PageCount；把跨页补丁拆成两条视图会让两页的翻转彼此独立，中间任何一次退出都可能让 guest 执行到半条指令。所以两种后端下这都是 fail-closed，直接拒绝，不拆。"));
        }
        else
        {
            patchConclusion = ks::i18n::sourceText(QStringLiteral("补丁完整落在这一页内。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::PatchGeometry),
            ks::i18n::sourceText(QStringLiteral("补丁几何：非空且完整落在这一页内")),
            ks::i18n::sourceText(QStringLiteral("页内起点=%1；长度=%2 字节；终点=%3；跨页判定=%4"))
                .arg(hex64(plan.pageOffset))
                .arg(plan.patchLength())
                .arg(hex64(plan.patchEndOffset()))
                .arg(crossesPage
                    ? ks::i18n::sourceText(QStringLiteral("跨页"))
                    : ks::i18n::sourceText(QStringLiteral("页内"))),
            patchVerdict,
            patchConclusion,
            patchVerdict == KvmCheckVerdict::Pass
                ? KvmCheckRemedy::None
                : KvmCheckRemedy::ReturnToPatchStep,
            ks::i18n::sourceText(QStringLiteral("回第 2 步改补丁")),
            true));

        // ---- 10. 基线页完整 ----
        const bool baselineOk = plan.baselineIsComplete();
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::BaselineComplete),
            ks::i18n::sourceText(QStringLiteral("基线页完整：恰好 4096 字节")),
            ks::i18n::sourceText(QStringLiteral("基线页 %1 字节 / %2"))
                .arg(plan.baselinePage.size())
                .arg(static_cast<int>(Ksword::Evidence::kPatchPageBytes)),
            baselineOk ? KvmCheckVerdict::Pass : KvmCheckVerdict::Fail,
            baselineOk
                ? ks::i18n::sourceText(QStringLiteral("整页都在。影子页的底稿与第 4 步的 TOCTOU 比对用的都是它。"))
                : ks::i18n::sourceText(QStringLiteral("基线不是完整一页。分片读少一片，拼出来的影子页里就会有一段零字节——而影子页正是被执行的那一份。")),
            baselineOk ? KvmCheckRemedy::None : KvmCheckRemedy::RecaptureBaseline,
            ks::i18n::sourceText(QStringLiteral("重新抓基线")),
            true));

        return rows;
    }

    void KvmHookWizard::runPreflightRemedy(const KvmCheckRemedy remedy)
    {
        switch (remedy)
        {
        case KvmCheckRemedy::None:
            return;

        case KvmCheckRemedy::EnableWriteAccess:
            // 统一入口：确认文案与 suppressionKey 只存在于 KvmWriteAccessGate 一份。
            (void)ks::ui::requestKvmWriteAccess(this);
            schedulePreflightRefresh();
            return;

        case KvmCheckRemedy::PrepareResources:
            // 刻意不在这里直接调 ensurePrepared：主窗口用自己的一把操作互斥
            // 串行化全部 KVM 控制命令，对话框绕过它就会出现 dock 与 dialog
            // 同时对驱动状态锁下命令。这里只把人送到那个入口。
            QMessageBox::information(
                this,
                ks::i18n::sourceText(QStringLiteral("准备 KVM 资源")),
                ks::i18n::sourceText(QStringLiteral("请在标题栏 KVM 按钮的右键菜单里执行「准备资源」。本向导不自己发 PREPARE：主窗口用一把操作互斥串行化全部 KVM 控制命令，对话框绕过它会让两处同时对驱动状态锁发命令。准备完回到这一页点「重新预检」。")));
            schedulePreflightRefresh();
            return;

        case KvmCheckRemedy::StopResident:
            QMessageBox::information(
                this,
                ks::i18n::sourceText(QStringLiteral("停止 KVM 常驻")),
                ks::i18n::sourceText(QStringLiteral("请在标题栏 KVM 按钮或内核 Dock 的 HVM 页里停止常驻。理由与准备资源相同：控制命令统一走主窗口的操作互斥。停止之后回到这一页点「重新预检」。")));
            schedulePreflightRefresh();
            return;

        case KvmCheckRemedy::SwitchToEptpBackend:
            QMessageBox::information(
                this,
                ks::i18n::sourceText(QStringLiteral("改用 EPTP 切换后端")),
                ks::i18n::sourceText(QStringLiteral("后端只在 PREPARE 时选定，所以要三步：先在标题栏 KVM 菜单里打开「EPTP 切换后端」，再执行「释放资源」，最后重新执行「准备资源」。只改开关而不重新准备资源不会生效，状态里的 eptpSwitchArmed 会一直是 false。")));
            schedulePreflightRefresh();
            return;

        case KvmCheckRemedy::OpenViewPanel:
        {
            // 视图面板是移除已装视图的现成入口，不在向导里重造一个。
            KvmViewDialog* const dialog = new KvmViewDialog(this);
            dialog->setAttribute(Qt::WA_DeleteOnClose);
            dialog->show();
            return;
        }

        case KvmCheckRemedy::ReturnToTargetStep:
            goToStep(Step::Target);
            return;

        case KvmCheckRemedy::ReturnToPatchStep:
            goToStep(Step::Patch);
            return;

        case KvmCheckRemedy::RecaptureBaseline:
            goToStep(Step::Patch);
            // 显式再抓一次：进入第 2 步的自动抓取是有条件的，而点这个按钮
            // 的人要的就是「无条件重来一次」。抓取自身是单飞的，不会叠发。
            startBaselineCapture();
            return;

        case KvmCheckRemedy::ExplainLocalEptUnreachable:
            // 只解释，不修复。放一个点了没用的「启用私有 EPT」按钮比不放更坏。
            QMessageBox::information(
                this,
                ks::i18n::sourceText(QStringLiteral("多核上为什么装不了分离视图")),
                ks::i18n::sourceText(QStringLiteral("驱动要求 ProcessorCount == 1 或 LocalEptArmed（hvm_ept_view.c:687-695），因为在共享层次上翻转一张叶的窗口对每个处理器都可见。而 LocalEptArmed 通过协议不可达：ENABLE_LOCAL_EPT 确实会被 PREPARE 读取并置位（hvm_runtime.c:1573-1582），但它不在 PREPARE 的 allowedFlags 白名单里（hvm_runtime.c:2682-2685），带上它的请求在进入那段代码之前就被判成非法；驱动自己在 hvm_runtime.c:2674-2681 的注释里把这件事称为 standing defect。所以这台机器上没有出路，本向导不给你一个假装能修好它的按钮。要走完流程可以改用排练目标，并在单处理器拓扑下验证。")));
            return;

        case KvmCheckRemedy::ExplainNotMeasured:
            QMessageBox::information(
                this,
                ks::i18n::sourceText(QStringLiteral("这一条为什么恒为「无读数」")),
                ks::i18n::sourceText(QStringLiteral("路线图原文：只验了 CLOAK（读被重定向）。HOOK 方向（执行被重定向到影子）未实测。而且当时未对已知函数下 hook，用的是探针自己分配的一页匿名内存。所以「执行真的落到影子页上」这件事本项目没有实测过，这一行只能是无读数——把它标成通过就是在说一句没有证据的话。另外提醒一句：CLOAK/HOOK 不是安全边界，失败即放行（InstructionLength = 0 时处理器会重执行并读到真页）。")));
            return;
        }
    }

    bool KvmHookWizard::hasBlockingPreflightFailure() const
    {
        if (m_preflightRows.isEmpty())
        {
            // 还没有跑过预检 = 没有读数 = 不知道。「不知道」不是「可以装」。
            return true;
        }
        for (const KvmCheckRow& row : m_preflightRows)
        {
            // NoReading 同样挡住：blocking 的判据没有读数时，我们并不知道
            // 驱动会不会拒绝，而这正是不能往下走的理由。
            if (row.blocking && row.verdict != KvmCheckVerdict::Pass)
            {
                return true;
            }
        }
        return false;
    }

    // =====================================================================
    // 第 5 步：装后校验
    // =====================================================================

    QWidget* KvmHookWizard::buildVerifyPage()
    {
        QWidget* const page = new QWidget(this);
        QVBoxLayout* const layout = new QVBoxLayout(page);

        QLabel* const hintLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("A 段这四条读数在未常驻时就能拿到。其中只有基座叶回读那一条能在 EPT 层面把「没生效」证伪，其余三条是记账性读数——它们证明驱动接受并记住了这条视图，不证明处理器看到的翻译变了。")),
            page);
        hintLabel->setWordWrap(true);
        layout->addWidget(hintLabel);

        m_verifyStaticTable = new QTableWidget(0, 4, page);
        m_verifyStaticTable->setHorizontalHeaderLabels(QStringList()
            << ks::i18n::sourceText(QStringLiteral("判据"))
            << ks::i18n::sourceText(QStringLiteral("当前读数"))
            << ks::i18n::sourceText(QStringLiteral("结论"))
            << ks::i18n::sourceText(QStringLiteral("修复")));
        m_verifyStaticTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_verifyStaticTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_verifyStaticTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_verifyStaticTable->verticalHeader()->setVisible(false);
        m_verifyStaticTable->horizontalHeader()->setSectionResizeMode(
            1,
            QHeaderView::Stretch);
        layout->addWidget(m_verifyStaticTable, 1);

        QHBoxLayout* const staticButtonLayout = new QHBoxLayout();
        m_verifyRefreshButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("重新校验 A 段")),
            page);
        staticButtonLayout->addWidget(m_verifyRefreshButton);
        staticButtonLayout->addStretch(1);
        layout->addLayout(staticButtonLayout);

        // ---- B 段：默认折叠 ----
        m_verifyResidentGroup = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("B 段：启动常驻并观察（可选，勾选展开）")),
            page);
        m_verifyResidentGroup->setCheckable(true);
        m_verifyResidentGroup->setChecked(false);
        QVBoxLayout* const groupLayout = new QVBoxLayout(m_verifyResidentGroup);

        // 折叠靠隐藏这一层容器：勾选框本身只负责禁用子控件，
        // 而 B 段默认摊开只会制造焦虑——三条里有两条在常见配置下注定没有读数。
        QWidget* const residentBody = new QWidget(m_verifyResidentGroup);
        QVBoxLayout* const bodyLayout = new QVBoxLayout(residentBody);
        bodyLayout->setContentsMargins(0, 0, 0, 0);

        QLabel* const residentWarningLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("常驻期间请不要在别的面板里读这一页。内核基线比对、反汇编、内存 Dock 去读它都会落进翻转窗口，并可能触发 fail-closed 退虚拟化，本向导管不住那些面板。")),
            residentBody);
        residentWarningLabel->setWordWrap(true);
        ApplyStatusRole(residentWarningLabel, StatusRole::Warning);
        bodyLayout->addWidget(residentWarningLabel);

        QLabel* const residentHintLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("常驻请在标题栏 KVM 按钮里自己启动，然后由你自己去触发目标函数，本页每秒读一次计数与事件环。本向导刻意不提供「自动触发目标函数」的动作：从用户态触发已知会带着 ring 3 的 RSP/RIP 在 ring 0 返回并蓝屏。")),
            residentBody);
        residentHintLabel->setWordWrap(true);
        bodyLayout->addWidget(residentHintLabel);

        m_verifyResidentTable = new QTableWidget(0, 4, residentBody);
        m_verifyResidentTable->setHorizontalHeaderLabels(QStringList()
            << ks::i18n::sourceText(QStringLiteral("判据"))
            << ks::i18n::sourceText(QStringLiteral("当前读数"))
            << ks::i18n::sourceText(QStringLiteral("结论"))
            << ks::i18n::sourceText(QStringLiteral("修复")));
        m_verifyResidentTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_verifyResidentTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_verifyResidentTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_verifyResidentTable->verticalHeader()->setVisible(false);
        m_verifyResidentTable->horizontalHeader()->setSectionResizeMode(
            1,
            QHeaderView::Stretch);
        bodyLayout->addWidget(m_verifyResidentTable, 1);

        m_verifyResidentButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("开始每秒观察")),
            residentBody);
        m_verifyResidentButton->setCheckable(true);
        bodyLayout->addWidget(m_verifyResidentButton);

        groupLayout->addWidget(residentBody);
        residentBody->setVisible(false);
        layout->addWidget(m_verifyResidentGroup);

        m_verifyStatusLabel = new QLabel(QString(), page);
        m_verifyStatusLabel->setWordWrap(true);
        layout->addWidget(m_verifyStatusLabel);

        // 轮询定时器不进头文件：它的起停点全在下面这三个 lambda 里，
        // 而它作为本页的子对象随对话框一起析构。
        QTimer* const pollTimer = new QTimer(this);
        pollTimer->setInterval(kResidentPollIntervalMs);
        connect(pollTimer, &QTimer::timeout, this, [this]() {
            startVerifyResident();
        });

        connect(m_verifyRefreshButton, &QPushButton::clicked, this, [this]() {
            startVerifyStatic();
        });
        connect(
            m_verifyResidentButton,
            &QPushButton::toggled,
            this,
            [this, pollTimer](const bool observing) {
                if (observing)
                {
                    m_verifyResidentButton->setText(ks::i18n::sourceText(
                        QStringLiteral("停止观察")));
                    pollTimer->start();
                    // 立刻取一次，不让人对着一张空表等满一秒。
                    startVerifyResident();
                    return;
                }
                m_verifyResidentButton->setText(ks::i18n::sourceText(
                    QStringLiteral("开始每秒观察")));
                pollTimer->stop();
            });
        connect(
            m_verifyResidentGroup,
            &QGroupBox::toggled,
            this,
            [this, residentBody, pollTimer](const bool expanded) {
                residentBody->setVisible(expanded);
                if (!expanded)
                {
                    // 收起来就必须停：折叠着的分组在背后打 IOCTL 是最难查的
                    // 一类「机器怎么自己动了」。
                    pollTimer->stop();
                    if (m_verifyResidentButton != nullptr)
                    {
                        m_verifyResidentButton->setChecked(false);
                    }
                }
            });
        return page;
    }

    void KvmHookWizard::startVerifyStatic()
    {
        if (m_verifyStaticInFlight)
        {
            return;
        }
        if (!m_plan.installed)
        {
            if (m_verifyStatusLabel != nullptr)
            {
                m_verifyStatusLabel->setText(ks::i18n::sourceText(
                    QStringLiteral("还没有装上视图，A 段没有可读的对象。")));
                ApplyStatusRole(m_verifyStatusLabel, StatusRole::Idle);
            }
            return;
        }
        m_verifyStaticInFlight = true;
        const quint64 sequence = ++m_verifyStaticSequence;
        const quint64 pageBase = m_plan.pageBasePhysical;
        setBusy(true);
        if (m_verifyStatusLabel != nullptr)
        {
            m_verifyStatusLabel->setText(ks::i18n::sourceText(
                QStringLiteral("正在读取状态、视图表、目标页与基座 EPT 叶……")));
            ApplyStatusRole(m_verifyStatusLabel, StatusRole::Info);
        }

        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, sequence, pageBase]() {
            const VerifyStaticSnapshot snapshot =
                collectVerifyStaticSnapshot(pageBase);
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, sequence, snapshot]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyVerifyStatic(sequence, snapshot);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::applyVerifyStatic(
        const quint64 sequence,
        const VerifyStaticSnapshot& snapshot)
    {
        m_verifyStaticInFlight = false;
        setBusy(false);
        if (sequence != m_verifyStaticSequence)
        {
            return;
        }

        m_verifyStaticRows = buildVerifyStaticRows(snapshot, m_plan);
        fillCheckTable(m_verifyStaticTable, m_verifyStaticRows);

        int failCount = 0;
        int noReadingCount = 0;
        for (const KvmCheckRow& row : m_verifyStaticRows)
        {
            if (row.verdict == KvmCheckVerdict::Fail)
            {
                ++failCount;
            }
            else if (row.verdict == KvmCheckVerdict::NoReading)
            {
                ++noReadingCount;
            }
        }
        if (m_verifyStatusLabel != nullptr)
        {
            m_verifyStatusLabel->setText(
                ks::i18n::sourceText(QStringLiteral("A 段 %1 条：未通过 %2 条，无读数 %3 条。这四条都不能证明「执行真的被重定向到影子页」——那件事本项目未实测。"))
                    .arg(m_verifyStaticRows.size())
                    .arg(failCount)
                    .arg(noReadingCount));
            ApplyStatusRole(
                m_verifyStatusLabel,
                failCount > 0 ? StatusRole::Error : StatusRole::Info);
        }
    }

    KvmHookWizard::VerifyStaticSnapshot KvmHookWizard::collectVerifyStaticSnapshot(
        const quint64 pageBasePhysical)
    {
        VerifyStaticSnapshot snapshot;
        snapshot.state = ksword::kvm::queryState();
        snapshot.stateValid = true;
        snapshot.views = ksword::kvm::listViews();
        // 真页重读走的是与抓基线同一个函数，两边因此不会出现两套分片逻辑。
        QString failure;
        snapshot.rereadPage = readTargetPage(pageBasePhysical, &failure);
        snapshot.rereadFailure = failure;
        // 叶回读放在最后：它自己会再取一次 QUERY 拿 eptPointer，
        // 那一次比上面这次晚，盲区标注取它自己带回来的两位。
        snapshot.leaf = readBaseEptLeaf(pageBasePhysical);
        return snapshot;
    }

    QVector<KvmCheckRow> KvmHookWizard::buildVerifyStaticRows(
        const VerifyStaticSnapshot& snapshot,
        const KvmHookPlan& plan)
    {
        QVector<KvmCheckRow> rows;
        rows.reserve(static_cast<int>(KvmHookVerifyCriterion::Count));

        const ksword::kvm::KvmViewEntry* const entry =
            findInstalledView(snapshot.views, plan.installedViewId);

        // ---- 0. 视图在表里 ----
        KvmCheckVerdict presentVerdict = KvmCheckVerdict::Pass;
        QString presentConclusion;
        if (!snapshot.views.ok)
        {
            presentVerdict = KvmCheckVerdict::NoReading;
            presentConclusion = ks::i18n::sourceText(QStringLiteral("视图表读不回来，所以不知道这条视图还在不在。"));
        }
        else if (entry == nullptr)
        {
            presentVerdict = KvmCheckVerdict::Fail;
            presentConclusion = ks::i18n::sourceText(QStringLiteral("表里没有这个编号：视图已经不在了（可能被别的面板移除，或资源被释放过）。"));
        }
        else if (entry->kind != KSWORD_ARK_HVM_VIEW_KIND_HOOK
            || entry->physicalAddress != plan.pageBasePhysical)
        {
            presentVerdict = KvmCheckVerdict::Fail;
            presentConclusion = ks::i18n::sourceText(QStringLiteral("编号对上了，但类型或目标物理页与本次安装的不一致——这个编号现在指的不是我们装的那条视图。"));
        }
        else
        {
            presentConclusion = ks::i18n::sourceText(QStringLiteral("驱动接受了这条视图并把它记在表里。请注意这**只**证明记账：它不证明 EPT 层面生效，那要靠下面的叶回读。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookVerifyCriterion::ViewPresent),
            ks::i18n::sourceText(QStringLiteral("视图在表里，且类型与目标物理页一致")),
            ks::i18n::sourceText(QStringLiteral("期望 viewId=%1，kind=%2（HOOK），physicalAddress=%3；表里读到 %4；LIST 结果=%5"))
                .arg(plan.installedViewId)
                .arg(static_cast<unsigned long>(KSWORD_ARK_HVM_VIEW_KIND_HOOK))
                .arg(hex64(plan.pageBasePhysical))
                .arg(entry == nullptr
                    ? ks::i18n::sourceText(QStringLiteral("（没有这个编号）"))
                    : ks::i18n::sourceText(QStringLiteral("kind=%1，physicalAddress=%2，shadowPhysicalAddress=%3，flipCount=%4"))
                        .arg(entry->kind)
                        .arg(hex64(entry->physicalAddress))
                        .arg(hex64(entry->shadowPhysicalAddress))
                        .arg(entry->flipCount))
                .arg(flagText(snapshot.views.ok)),
            presentVerdict,
            presentConclusion,
            KvmCheckRemedy::None,
            QString(),
            false));

        // ---- 1. 影子页与真页是两个帧 ----
        const quint64 shadowPhysical = entry != nullptr
            ? entry->shadowPhysicalAddress
            : plan.shadowPhysicalAddress;
        KvmCheckVerdict shadowVerdict = KvmCheckVerdict::Pass;
        QString shadowConclusion;
        if (!snapshot.views.ok || entry == nullptr)
        {
            shadowVerdict = KvmCheckVerdict::NoReading;
            shadowConclusion = ks::i18n::sourceText(QStringLiteral("表里没有这条视图，影子页地址无从核对。"));
        }
        else if (shadowPhysical == 0ULL || shadowPhysical == plan.pageBasePhysical)
        {
            shadowVerdict = KvmCheckVerdict::Fail;
            shadowConclusion = ks::i18n::sourceText(QStringLiteral("影子页地址为零或与真页相同：那样翻转过去执行的还是原来那一页，补丁不可能生效。"));
        }
        else
        {
            shadowConclusion = ks::i18n::sourceText(QStringLiteral("驱动为这条视图分配了一个独立的帧。注意本行只比地址：影子页里的 4096 字节是不是我们提交的那一份，这一段快照没有带回来，所以那件事在这里**没有被验证**。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookVerifyCriterion::ShadowDistinct),
            ks::i18n::sourceText(QStringLiteral("影子页地址非零且不等于真页")),
            ks::i18n::sourceText(QStringLiteral("shadowPhysicalAddress=%1；真页 pageBasePhysical=%2；安装时记下的影子地址=%3"))
                .arg(hex64(shadowPhysical))
                .arg(hex64(plan.pageBasePhysical))
                .arg(hex64(plan.shadowPhysicalAddress)),
            shadowVerdict,
            shadowConclusion,
            KvmCheckRemedy::None,
            QString(),
            false));

        // ---- 2. 真页未被改动 ----
        KvmCheckVerdict realVerdict = KvmCheckVerdict::Pass;
        QString realReadingDetail;
        QString realConclusion;
        if (snapshot.rereadPage.isEmpty())
        {
            realVerdict = KvmCheckVerdict::NoReading;
            realReadingDetail = snapshot.rereadFailure.isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("（重读没有返回任何字节）"))
                : snapshot.rereadFailure;
            realConclusion = ks::i18n::sourceText(QStringLiteral("目标页这次读不回来，所以不知道它有没有被改过。"));
        }
        else if (!plan.baselineIsComplete())
        {
            realVerdict = KvmCheckVerdict::NoReading;
            realReadingDetail = ks::i18n::sourceText(QStringLiteral("（基线页不完整，没有可比对的基准）"));
            realConclusion = ks::i18n::sourceText(QStringLiteral("基线不是完整一页，比对没有基准。"));
        }
        else
        {
            const qsizetype difference =
                firstDifferenceOffset(snapshot.rereadPage, plan.baselinePage);
            if (difference < 0)
            {
                realReadingDetail = ks::i18n::sourceText(QStringLiteral("与基线逐字节相同"));
                realConclusion = ks::i18n::sourceText(QStringLiteral("真页没有被改动。这是一条**记账性读数，不是 EPT 事实**：addView 全程只写影子（hvm_ept_view.c:360-418），本来就不该碰真页。它的价值在于给「移除视图之后真页能复原」留下前半段证据。"));
            }
            else
            {
                realVerdict = KvmCheckVerdict::Fail;
                realReadingDetail = ks::i18n::sourceText(QStringLiteral("第一处不同在页内偏移 %1"))
                    .arg(hex64(static_cast<quint64>(difference)));
                realConclusion = ks::i18n::sourceText(QStringLiteral("真页与基线不同。HOOK 不改真页，所以是**别的东西**动过它——在弄清是什么之前不要继续，我们拼进影子页的原字节可能已经过期。"));
            }
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookVerifyCriterion::RealPageUnchanged),
            ks::i18n::sourceText(QStringLiteral("真页与基线逐字节相同")),
            ks::i18n::sourceText(QStringLiteral("重读 %1 字节；基线 %2 字节；比对结果=%3"))
                .arg(snapshot.rereadPage.size())
                .arg(plan.baselinePage.size())
                .arg(realReadingDetail),
            realVerdict,
            realConclusion,
            realVerdict == KvmCheckVerdict::Fail
                ? KvmCheckRemedy::RecaptureBaseline
                : KvmCheckRemedy::None,
            ks::i18n::sourceText(QStringLiteral("重新抓基线")),
            false));

        // ---- 3. 基座 EPT 叶回读 ----
        //
        // 稳态 primary 叶 = 真页 | READ | WRITE，**不给 X**（hvm_ept_view.c:178-180）。
        //
        // 判据是四项一起比：reachedLeaf、R=1、W=1、X=0，外加**帧地址 == 目标页基址**。
        // 只比 X 是不够的 —— primary 是一个完整的常量值，比其中一位等于允许其余几位
        // 任意取值；而权限三位全对、帧却指向别处时，那三位是一个关于错误对象的正确读数。
        // 极性一旦在某个后端上反转（primary 改泊影子侧），这里期望的**帧**和**三位**
        // 要一起改，别再只改一个 X。
        const EptLeafProbeResult& leaf = snapshot.leaf;
        const QString leafReading =
            ks::i18n::sourceText(QStringLiteral("eptPointer=%1；走到第 %2 级（%3）；叶项=%4；R=%5 W=%6 X=%7；帧=%8；largePage=%9；suppressVe=%10；localEptArmed=%11；eptpSwitchArmed=%12"))
                .arg(hex64(leaf.eptPointer))
                .arg(leaf.walkedLevels)
                .arg(leaf.leafLevel >= 0
                    ? eptLeafLevelName(leaf.leafLevel)
                    : ks::i18n::sourceText(QStringLiteral("未走到叶")))
                .arg(hex64(leaf.leafEntry))
                .arg(leaf.readable ? 1 : 0)
                .arg(leaf.writable ? 1 : 0)
                .arg(leaf.executable ? 1 : 0)
                .arg(hex64(leaf.leafFrameAddress))
                .arg(flagText(leaf.largePage))
                .arg(flagText(leaf.suppressVe))
                .arg(flagText(leaf.localEptArmed))
                .arg(flagText(leaf.eptpSwitchArmed));

        KvmCheckVerdict leafVerdict = KvmCheckVerdict::Pass;
        QString leafConclusion;
        // 两份状态位取并集：探针自带的那两位与本次快照的那两位来自两次 QUERY，
        // 任何一次说「挂在别的树上」都足以让这条读数失去意义。
        // 往「无读数」的方向偏是安全的方向，往「通过」的方向偏不是。
        if (leaf.localEptArmed || leaf.eptpSwitchArmed
            || snapshot.state.localEptArmed || snapshot.state.eptpSwitchArmed)
        {
            // 盲区必须随读数一起呈现，否则这条判据会变成又一条假判据。
            leafVerdict = KvmCheckVerdict::NoReading;
            leafConclusion = ks::i18n::sourceText(QStringLiteral("本读数描述的是**基座**层次，不描述正在跑的那个处理器：私有 EPT 与 EPTP 切换后端实际装载的是从基座分叉出去的另一棵树，本探针一个字节也读不到它。所以这里既不能算通过也不能算失败。"));
        }
        else if (!leaf.ok)
        {
            leafVerdict = KvmCheckVerdict::NoReading;
            leafConclusion = leaf.message.isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("走表没有完成，拿不到叶项。"))
                : leaf.message;
        }
        else if (leaf.unmapped || !leaf.reachedLeaf)
        {
            leafVerdict = KvmCheckVerdict::Fail;
            leafConclusion = ks::i18n::sourceText(QStringLiteral("基座里这一页没有映射到叶。装了 HOOK 的页必须有一张能被翻转的叶项，走表被截断说明这一页不是我们以为的那一页。"));
        }
        else if (leaf.executable || !leaf.readable || !leaf.writable)
        {
            // 三位一起判，不是只判 X。
            //
            // 判据名写的是「R=1 W=1 X=0」，早先的实现却只断言了 X —— 一张
            // R=0 W=0 X=0 的叶（比如被别的机制改成了全禁）会从这里拿到绿勾。
            // 三位是一个整体：primary 值是 真页|READ|WRITE 这**一个**常量，
            // 任何一位对不上都说明落在叶上的不是它。
            leafVerdict = KvmCheckVerdict::Fail;
            leafConclusion = ks::i18n::sourceText(QStringLiteral("叶项的权限三位与 HOOK 稳态的 primary 值对不上。primary 是真页 | READ | WRITE 且不给 X（hvm_ept_view.c:178-180），期望 R=1 W=1 X=0；上面「当前读数」里的实际三位就是证据。"));
        }
        else if (leaf.leafFrameAddress != plan.pageBasePhysical)
        {
            // 权限对了不等于指向对了。
            //
            // HOOK 的 primary 值里那一帧是**真页**，addView 全程不改真页
            // （hvm_ept_view.c:360-418 只碰影子）。所以帧地址必须仍然等于目标页基址。
            // 不等于说明这张叶已经被翻到别处，或者我们走表走到了另一页 ——
            // 两种都会让上面那三位变成一个关于错误对象的正确读数。
            leafVerdict = KvmCheckVerdict::Fail;
            leafConclusion = ks::i18n::sourceText(QStringLiteral("叶项的权限三位对得上，但它指向的物理帧不是目标页。HOOK 的 primary 值指向真页本身，安装过程从不改写真页，所以帧地址应当仍等于目标页基址；对不上意味着这张叶描述的不是我们以为的那一页。"));
        }
        else
        {
            leafConclusion = ks::i18n::sourceText(QStringLiteral("叶项是真页 | R | W 且不可执行，帧地址也仍是目标页基址，与 HOOK 稳态的 primary 值一致（hvm_ept_view.c:178-180）。这是四条里唯一一条能被 EPT 层面的错误证伪的读数。它仍然不证明执行会落到影子页上——那件事本项目未实测。"));
        }
        if (leaf.largePage && leafVerdict != KvmCheckVerdict::NoReading)
        {
            leafConclusion += QStringLiteral(" ");
            leafConclusion += ks::i18n::sourceText(QStringLiteral("另外这张叶是大页，它管的不止目标这一页，改它会影响整段范围。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookVerifyCriterion::BaseEptLeafNotExecutable),
            ks::i18n::sourceText(QStringLiteral("基座 EPT 叶回读：R=1 W=1 X=0")),
            leafReading,
            leafVerdict,
            leafConclusion,
            KvmCheckRemedy::None,
            QString(),
            false));

        return rows;
    }

    void KvmHookWizard::startVerifyResident()
    {
        if (m_verifyResidentInFlight || m_busy)
        {
            return;
        }
        if (!m_plan.installed)
        {
            return;
        }
        m_verifyResidentInFlight = true;
        const quint64 sequence = ++m_verifyResidentSequence;
        const unsigned long long cursor = m_eventCursor;

        // 这条路径每秒跑一次，刻意不进忙碌态：把导航按钮每秒禁用一次
        // 会让整个对话框在观察期间没法用。
        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, sequence, cursor]() {
            const VerifyResidentSnapshot snapshot =
                collectVerifyResidentSnapshot(cursor);
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, sequence, snapshot]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyVerifyResident(sequence, snapshot);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::applyVerifyResident(
        const quint64 sequence,
        const VerifyResidentSnapshot& snapshot)
    {
        m_verifyResidentInFlight = false;
        if (sequence != m_verifyResidentSequence)
        {
            return;
        }

        // 事件是消费型读数：游标推进之后，上一轮读到的那几条再也读不回来。
        if (snapshot.events.ok && snapshot.events.newestSequence > m_eventCursor)
        {
            m_eventCursor = snapshot.events.newestSequence;
        }

        QVector<KvmCheckRow> rows = buildVerifyResidentRows(snapshot, m_plan);
        const int eventIndex =
            static_cast<int>(KvmHookResidentCriterion::FlipEventObserved);
        if (eventIndex < rows.size()
            && eventIndex < m_verifyResidentRows.size()
            && m_verifyResidentRows.at(eventIndex).verdict == KvmCheckVerdict::Pass
            && rows.at(eventIndex).verdict != KvmCheckVerdict::Pass)
        {
            // 上一轮已经看到过这条视图的翻转事件。因为游标已经推过去了，
            // 这一轮读不到它并不代表它没发生过——保留上一轮的结论，
            // 否则一条真实的读数会在下一秒被自己抹掉。
            KvmCheckRow sticky = m_verifyResidentRows.at(eventIndex);
            sticky.conclusion = sticky.conclusion + QStringLiteral(" ")
                + ks::i18n::sourceText(QStringLiteral("（本行来自本次观察中较早的一次轮询：事件环是消费型的，游标推进之后旧事件读不回来。）"));
            rows[eventIndex] = sticky;
        }
        m_verifyResidentRows = rows;
        fillCheckTable(m_verifyResidentTable, m_verifyResidentRows);

        if (m_verifyStatusLabel != nullptr)
        {
            const ksword::kvm::KvmState& state = snapshot.state;
            QString text =
                ks::i18n::sourceText(QStringLiteral("常驻存活：residentActive=%1；residentProcessorCount=%2 / 逻辑处理器 %3；vmExitCount=%4"))
                    .arg(flagText(state.residentActive))
                    .arg(state.residentProcessorCount)
                    .arg(state.processorCount)
                    .arg(state.vmExitCount);
            StatusRole role = state.residentActive
                ? StatusRole::Info
                : StatusRole::Idle;
            if (!state.residentActive || state.residentProcessorCount == 0UL)
            {
                role = StatusRole::Warning;
                text += QStringLiteral(" ");
                text += ks::i18n::sourceText(QStringLiteral("如果刚才还在常驻，那么发生过 fail-closed 退虚拟化。按代码最可能的三种成因：上一次翻转还没恢复就又来一次（hvm_ept_view.c:832-838）、取到的访问方向与视图不符（:843-858）、或者这条视图在切换后端里不可表示（hvm_ept_switch.c:519-526）。本向导不会自动重装——重装会把现场盖掉。"));
            }
            m_verifyStatusLabel->setText(text);
            ApplyStatusRole(m_verifyStatusLabel, role);
        }
    }

    KvmHookWizard::VerifyResidentSnapshot KvmHookWizard::collectVerifyResidentSnapshot(
        const unsigned long long afterSequence)
    {
        VerifyResidentSnapshot snapshot;
        snapshot.state = ksword::kvm::queryState();
        snapshot.stateValid = true;
        snapshot.views = ksword::kvm::listViews();
        // clear 传 false：清环会把别的面板正在消费的事件一起抹掉。
        snapshot.events = ksword::kvm::readEvents(afterSequence, false);
        return snapshot;
    }

    QVector<KvmCheckRow> KvmHookWizard::buildVerifyResidentRows(
        const VerifyResidentSnapshot& snapshot,
        const KvmHookPlan& plan)
    {
        QVector<KvmCheckRow> rows;
        rows.reserve(static_cast<int>(KvmHookResidentCriterion::Count));

        const ksword::kvm::KvmViewEntry* const entry =
            findInstalledView(snapshot.views, plan.installedViewId);
        const unsigned long long flipCount =
            entry != nullptr ? entry->flipCount : 0ULL;

        // ---- 0. 翻转计数 ----
        //
        // 必须先看后端：唯一的递增点在 hvm_ept_view.c:903，而 EPTP 切换后端
        // 在 :821 就提前 return 了，根本走不到那里。
        KvmCheckVerdict flipVerdict = KvmCheckVerdict::NoReading;
        QString flipReading;
        QString flipConclusion;
        if (snapshot.state.eptpSwitchArmed)
        {
            flipReading =
                ks::i18n::sourceText(QStringLiteral("eptpSwitchArmed=true（EPTP 切换后端）；flipCount=%1（本后端不产生此计数）"))
                    .arg(flipCount);
            flipConclusion = ks::i18n::sourceText(QStringLiteral("本后端不产生这个计数：唯一的递增点在 hvm_ept_view.c:903，而切换后端在 :821 就提前返回了。所以这里恒为 0，**既不是失败也不代表没生效**——这一条在本后端下换成下面的事件环来看。"));
        }
        else if (entry == nullptr)
        {
            flipReading = ks::i18n::sourceText(QStringLiteral("eptpSwitchArmed=false（默认后端）；表里没有 viewId=%1"))
                .arg(plan.installedViewId);
            flipConclusion = ks::i18n::sourceText(QStringLiteral("视图表里读不到这条视图，拿不到它的计数。"));
        }
        else if (flipCount > 0ULL)
        {
            flipVerdict = KvmCheckVerdict::Pass;
            flipReading = ks::i18n::sourceText(QStringLiteral("eptpSwitchArmed=false（默认后端）；flipCount=%1"))
                .arg(flipCount);
            flipConclusion = ks::i18n::sourceText(QStringLiteral("这一页至少被翻转过一次：处理器为它取过 EPT 违例，驱动装上了影子叶并单步了一条指令。它证明翻转机制在跑，仍然不证明执行落到了影子页上。"));
        }
        else
        {
            flipReading = ks::i18n::sourceText(QStringLiteral("eptpSwitchArmed=false（默认后端）；flipCount=0"));
            flipConclusion = ks::i18n::sourceText(QStringLiteral("观察窗口内这一页没有被碰过。这是**无读数**，不是失败：目标函数还没被执行，或者常驻还没起来。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookResidentCriterion::FlipCount),
            ks::i18n::sourceText(QStringLiteral("翻转计数从 0 变正（仅默认后端产生）")),
            flipReading,
            flipVerdict,
            flipConclusion,
            KvmCheckRemedy::None,
            QString(),
            false));

        // ---- 1. 事件环里出现过这条视图的翻转 ----
        int matchedEvents = 0;
        for (const ksword::kvm::KvmEventEntry& event : snapshot.events.events)
        {
            // ruleId 对视图翻转承载的就是 viewId：两者共用这一列。
            if (event.type == KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION
                && event.ruleId == plan.installedViewId
                && plan.installedViewId != 0UL)
            {
                ++matchedEvents;
            }
        }
        KvmCheckVerdict eventVerdict = KvmCheckVerdict::NoReading;
        QString eventConclusion;
        if (!snapshot.events.ok)
        {
            eventConclusion = snapshot.events.message.isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("事件环读不回来。"))
                : snapshot.events.message;
        }
        else if (matchedEvents > 0)
        {
            eventVerdict = KvmCheckVerdict::Pass;
            eventConclusion = ks::i18n::sourceText(QStringLiteral("事件环里有这条视图的 EPT 违例：这一页在观察窗口内确实被访问并触发了翻转。它是 EPTP 切换后端下唯一的翻转证据。"));
        }
        else
        {
            eventConclusion = ks::i18n::sourceText(QStringLiteral("事件环里没有这条视图的翻转事件。这是**无读数**：目标函数在观察窗口内没有被执行过，既不是成功也不是失败。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookResidentCriterion::FlipEventObserved),
            ks::i18n::sourceText(QStringLiteral("事件环里出现过 ruleId 等于本视图编号的 EPT 违例")),
            ks::i18n::sourceText(QStringLiteral("本次读回 %1 条事件（其中匹配 viewId=%2 的 EPT 违例 %3 条）；droppedRows=%4；availableRows=%5；newestSequence=%6；读取结果=%7"))
                .arg(snapshot.events.events.size())
                .arg(plan.installedViewId)
                .arg(matchedEvents)
                .arg(snapshot.events.droppedRows)
                .arg(snapshot.events.availableRows)
                .arg(snapshot.events.newestSequence)
                .arg(flagText(snapshot.events.ok)),
            eventVerdict,
            eventConclusion,
            KvmCheckRemedy::None,
            QString(),
            false));

        // ---- 2. 执行是否真的被重定向 ----
        //
        // 恒为无读数。路线图原文如此，不许改成"已验证"。
        rows.append(makeRow(
            static_cast<int>(KvmHookResidentCriterion::ExecutionRedirected),
            ks::i18n::sourceText(QStringLiteral("执行被重定向到影子页")),
            ks::i18n::sourceText(QStringLiteral("本项目未实测：没有任何一条读数能回答这个问题")),
            KvmCheckVerdict::NoReading,
            ks::i18n::sourceText(QStringLiteral("路线图原文：只验了 CLOAK（读被重定向）。HOOK 方向（执行被重定向到影子）未实测。上面两条只能说明这一页被访问过并触发了翻转，说不出被重定向过去执行的是哪一份字节。")),
            KvmCheckRemedy::ExplainNotMeasured,
            ks::i18n::sourceText(QStringLiteral("为什么没有读数")),
            false));

        return rows;
    }

    void KvmHookWizard::fillCheckTable(
        QTableWidget* const table,
        const QVector<KvmCheckRow>& rows)
    {
        if (table == nullptr)
        {
            return;
        }
        // 先清空再重建：直接改行数会把上一批留下的单元格控件（第 4 列的按钮）
        // 挂在新的一行上，那样按钮会执行上一批的修复动作。
        table->setRowCount(0);
        table->setRowCount(rows.size());

        // 第 4 列的按钮要回调到对话框本体。fillCheckTable 是静态的，
        // 所以从表格自己所在的窗口取回实例——这时控件树已经建完。
        KvmHookWizard* const wizard =
            qobject_cast<KvmHookWizard*>(table->window());

        for (int row = 0; row < rows.size(); ++row)
        {
            const KvmCheckRow& data = rows.at(row);

            QTableWidgetItem* const criterionItem =
                new QTableWidgetItem(data.criterion);
            criterionItem->setToolTip(data.criterion);
            table->setItem(row, 0, criterionItem);

            // 第 2 列只写读到了什么，第 3 列才是结论 —— 三张表共用这套列语义。
            QTableWidgetItem* const readingItem =
                new QTableWidgetItem(data.reading);
            readingItem->setToolTip(data.reading);
            table->setItem(row, 1, readingItem);

            // 结论列用 QLabel 承载，才能吃到全局样式块里的语义状态色：
            // QTableWidgetItem 不是控件，ApplyStatusRole 对它无效。
            QLabel* const verdictLabel = new QLabel(
                describeCheckVerdict(data.verdict),
                table);
            verdictLabel->setToolTip(data.conclusion);
            verdictLabel->setWordWrap(true);
            verdictLabel->setMargin(4);
            ApplyStatusRole(verdictLabel, checkVerdictStatusRole(data.verdict));
            table->setCellWidget(row, 2, verdictLabel);

            if (data.remedy != KvmCheckRemedy::None && wizard != nullptr)
            {
                QPushButton* const remedyButton = new QPushButton(
                    data.remedyLabel,
                    table);
                remedyButton->setToolTip(data.conclusion);
                const KvmCheckRemedy remedy = data.remedy;
                connect(
                    remedyButton,
                    &QPushButton::clicked,
                    wizard,
                    [wizard, remedy]() {
                        wizard->runPreflightRemedy(remedy);
                    });
                table->setCellWidget(row, 3, remedyButton);
            }
        }
        table->resizeRowsToContents();
    }
}
