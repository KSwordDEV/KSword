#include "../UI/StructuredFieldView.h"
#include "TamperDetectionPage.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/CodeEditorWidget.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/AdaptivePageScroll.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"
#include "../../../shared/evidence/NumericTextParse.h"
#include "../../../shared/evidence/PeImageMap.h"

#include <QFile>

#include <QCheckBox>
#include <QComboBox>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QSpinBox>
#include <QSplitter>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <memory>

// ============================================================
// TamperDetectionPage.cpp
// 作用：采集多条读取路径的字节、交给 shared/evidence 的判定层、展示结论。
// 本文件不含任何判定逻辑——判定错了不会报错、只会安静地说"干净"，所以那部分
// 必须待在能被离线穷举测试覆盖的地方。
// ============================================================

using namespace Ksword::Evidence;

namespace ksword::memory_dock
{
    namespace
    {
        // 逐页比对。粒度取一页：DDMA 一次传输就是一页，用更小的粒度只会让磁盘
        // 往返次数成倍增加而不增加任何判据。
        constexpr std::uint64_t kPageBytes = 4096ULL;

        // 扫描上限的缺省值。DDMA 每页要做"备份扇区→写→读→还原"四次磁盘往返，
        // 页数乘轮数直接决定耗时，所以必须有一个保守的缺省值和一个显式上限，
        // 而不是让用户一不小心提交一个跑十分钟的请求。
        constexpr int kDefaultMaxPages = 64;
        constexpr int kHardMaxPages = 1024;

        // ScanOutcome：工作线程的产出。
        struct ScanOutcome
        {
            std::vector<TamperPageResult> results;
            QString abortReason;   // 非空表示整轮没跑完，原因要如实带回界面。
        };

        // collectOnePage：对一页做一轮采样。
        //
        // 物理地址由调用方翻译好再传进来，且**只翻译一次**：R0 物理读与 DDMA 读
        // 必须落在同一个物理页上。若在这里各自翻译，两次翻译之间的任何变化都会
        // 被算成内容差异——那是个凭空的读数，而且恰好长得像我们要找的东西。
        TamperRound collectOneRound(
            const TamperScanRequest& request,
            const ksword::ark::DriverClient& client,
            const Ksword::Evidence::PeImageMap& diskImageMap,
            const std::uint64_t virtualAddress,
            const std::uint64_t physicalAddress,
            const bool physicalValid)
        {
            TamperRound round;

            const auto pushSample = [&round](
                const TamperReadPath path,
                const ksword::memory_backend::AccessOutcome& outcome)
            {
                TamperViewSample sample;
                sample.path = path;
                if (outcome.ok)
                {
                    sample.status = TamperSampleStatus::Read;
                    sample.bytes.assign(
                        reinterpret_cast<const std::uint8_t*>(outcome.data.constData()),
                        reinterpret_cast<const std::uint8_t*>(outcome.data.constData())
                            + outcome.data.size());
                }
                else
                {
                    sample.status = TamperSampleStatus::Failed;
                    sample.failureText = outcome.failureText.toStdString();
                }
                round.views.push_back(std::move(sample));
            };

            const auto pushUnavailable = [&round](
                const TamperReadPath path, const QString& reason)
            {
                TamperViewSample sample;
                sample.path = path;
                sample.status = TamperSampleStatus::Unavailable;
                sample.failureText = reason.toStdString();
                round.views.push_back(std::move(sample));
            };

            if (request.useUserMode)
            {
                pushSample(
                    TamperReadPath::UserModeVirtual,
                    ksword::memory_backend::readVirtual(
                        ksword::memory_backend::MemoryAccessBackend::UserMode,
                        request.ddmaSession,
                        request.processId,
                        virtualAddress,
                        kPageBytes));
            }
            if (request.useKernelVirtual)
            {
                pushSample(
                    TamperReadPath::KernelVirtual,
                    ksword::memory_backend::readVirtual(
                        ksword::memory_backend::MemoryAccessBackend::StandardDriver,
                        request.ddmaSession,
                        request.processId,
                        virtualAddress,
                        kPageBytes));
            }
            if (request.useKernelPhysical)
            {
                if (!physicalValid)
                {
                    pushUnavailable(
                        TamperReadPath::KernelPhysical,
                        QStringLiteral("该页的虚拟地址翻译不出物理地址"));
                }
                else
                {
                    pushSample(
                        TamperReadPath::KernelPhysical,
                        ksword::memory_backend::readPhysical(
                            ksword::memory_backend::MemoryAccessBackend::StandardDriver,
                            request.ddmaSession,
                            physicalAddress,
                            kPageBytes));
                }
            }
            // HVM 走虚拟地址而不是物理地址：它的独立性来自"不调内存管理器例程"，
            // 那条性质在虚拟地址读上才成立且才有对比意义——与 R0 虚拟读比对，分歧
            // 说明 MmCopyVirtualMemory 被挂了钩。
            if (request.useHvm)
            {
                pushSample(
                    TamperReadPath::HvmPrivateWindow,
                    ksword::memory_backend::readVirtual(
                        ksword::memory_backend::MemoryAccessBackend::Hvm,
                        request.ddmaSession,
                        request.processId,
                        virtualAddress,
                        kPageBytes));
            }
            if (request.useDma)
            {
                if (!physicalValid)
                {
                    pushUnavailable(
                        TamperReadPath::DmaPhysical,
                        QStringLiteral("该页的虚拟地址翻译不出物理地址"));
                }
                else
                {
                    pushSample(
                        TamperReadPath::DmaPhysical,
                        ksword::memory_backend::readPhysical(
                            ksword::memory_backend::MemoryAccessBackend::Ddma,
                            request.ddmaSession,
                            physicalAddress,
                            kPageBytes));
                }
            }

            // 节对象干净页：内存管理器自己持有的那份"这个映像本来该是什么样"，
            // 与磁盘文件是两个**互相独立**的来源。文件被一起改掉时它还在，
            // 所以两条静态参考都留着，不用其中一条顶替另一条。
            if (request.useImageSection)
            {
                TamperViewSample sample;
                sample.path = TamperReadPath::ImageSectionClean;
                const ksword::ark::ImageSectionPagesResult sectionResult =
                    client.readImageSectionPages(
                        request.processId,
                        virtualAddress,
                        virtualAddress + kPageBytes,
                        0ULL,
                        1UL,
                        KSWORD_ARK_INJECTION_SECTION_FLAG_INCLUDE_BYTES);
                if (!sectionResult.io.ok)
                {
                    sample.status = TamperSampleStatus::Failed;
                    sample.failureText = sectionResult.io.message;
                }
                else if (sectionResult.entries.empty()
                    || !sectionResult.entries.front().valid()
                    || !sectionResult.entries.front().bytesPresent()
                    || sectionResult.pageBytes.size() < kPageBytes)
                {
                    // 原型 PTE 不在架构有效形式上（transition / pagefile 编码）时驱动
                    // 只报"未驻留"而不去解码，也不会把页读进来。那是覆盖缺口，
                    // 不是"这一页和参考一致"。
                    sample.status = TamperSampleStatus::OutOfCoverage;
                    sample.failureText = "节对象未给出该页的干净字节（原型 PTE 未驻留或不可解码）";
                }
                else
                {
                    sample.status = TamperSampleStatus::Read;
                    sample.bytes.assign(
                        sectionResult.pageBytes.begin(),
                        sectionResult.pageBytes.begin() + static_cast<std::ptrdiff_t>(kPageBytes));
                }
                round.views.push_back(std::move(sample));
            }

            // 磁盘映像：按**当前加载基址**归一化之后再取。同一份文件在不同基址上
            // 的字节并不相同（重定位），拿文件原样去比，每一次正常加载都会被报成
            // 一大片差异。归一化、零填充区与不可比较区的判定全部复用 PeImageMap，
            // 本文件不自己解析 PE。
            if (request.useOnDiskImage)
            {
                TamperViewSample sample;
                sample.path = TamperReadPath::OnDiskImage;
                if (!diskImageMap.valid())
                {
                    sample.status = TamperSampleStatus::Unavailable;
                    sample.failureText = std::string("磁盘映像不可用：")
                        + Ksword::Evidence::PeParseStatusName(diskImageMap.status);
                }
                else if (virtualAddress < request.moduleBaseAddress)
                {
                    sample.status = TamperSampleStatus::OutOfCoverage;
                    sample.failureText = "该页在模块基址之前，不属于这个映像";
                }
                else
                {
                    const std::uint64_t rva64 = virtualAddress - request.moduleBaseAddress;
                    std::vector<std::uint8_t> normalized;
                    if (rva64 > 0xFFFFFFFFULL
                        || !Ksword::Evidence::ReadNormalizedBytes(
                            diskImageMap,
                            static_cast<std::uint32_t>(rva64),
                            static_cast<std::uint32_t>(kPageBytes),
                            normalized))
                    {
                        // ReadNormalizedBytes 返回 false 的含义是"这段没有文件字节
                        // 支撑，或落在不可比较范围里"——零填充区、节间隙、畸形节、
                        // 不支持的重定位都在此列。它**不是**"没有差异"。
                        sample.status = TamperSampleStatus::OutOfCoverage;
                        sample.failureText = "该页在磁盘映像里没有可比较的字节支撑（零填充区、节间隙或不可归一化范围）";
                    }
                    else
                    {
                        sample.status = TamperSampleStatus::Read;
                        sample.bytes = std::move(normalized);
                    }
                }
                round.views.push_back(std::move(sample));
            }
            return round;
        }

        // runScan：在工作线程里跑完整轮扫描。不触碰任何 Qt 控件。
        ScanOutcome runScan(const TamperScanRequest& request)
        {
            ScanOutcome outcome;
            const ksword::ark::DriverClient client;

            // 磁盘映像**整轮只解析一次**：它是静态的，每页重读一次文件只会让一次
            // 扫描多出成百上千次磁盘 I/O，而且中途文件被替换还会让前后几页的参考
            // 不是同一份。解析放在工作线程里，主线程不受影响。
            Ksword::Evidence::PeImageMap diskImageMap;
            if (request.useOnDiskImage)
            {
                QFile imageFile(request.moduleFilePath);
                if (!imageFile.open(QIODevice::ReadOnly))
                {
                    outcome.abortReason = QStringLiteral("打不开模块文件 %1：%2")
                        .arg(request.moduleFilePath)
                        .arg(imageFile.errorString());
                }
                else
                {
                    const QByteArray fileBytes = imageFile.readAll();
                    diskImageMap = Ksword::Evidence::BuildPeImageMap(
                        reinterpret_cast<const std::uint8_t*>(fileBytes.constData()),
                        static_cast<std::size_t>(fileBytes.size()),
                        request.moduleBaseAddress);
                }
            }

            for (std::uint64_t pageIndex = 0; pageIndex < request.pageCount; ++pageIndex)
            {
                TamperPageResult pageResult;
                pageResult.virtualAddress = request.startAddress + pageIndex * kPageBytes;

                // 翻译一次，本页的两条物理读共用。
                const ksword::ark::VirtualAddressTranslateResult translation =
                    client.translateVirtualAddress(
                        request.processId, pageResult.virtualAddress, 0UL);
                if (translation.io.ok && translation.resolved)
                {
                    pageResult.physicalAddress = translation.physicalAddress;
                    pageResult.physicalAddressValid = true;
                }
                else
                {
                    pageResult.translateFailureText = translation.io.ok
                        ? QStringLiteral("驱动未返回物理地址，该页可能未驻留")
                        : QString::fromStdString(translation.io.message);
                }

                std::vector<TamperRound> rounds;
                rounds.reserve(static_cast<std::size_t>(request.roundCount));
                for (int round = 0; round < request.roundCount; ++round)
                {
                    rounds.push_back(collectOneRound(
                        request,
                        client,
                        diskImageMap,
                        pageResult.virtualAddress,
                        pageResult.physicalAddress,
                        pageResult.physicalAddressValid));
                }
                pageResult.finding = AnalyzeTamperRounds(rounds);
                outcome.results.push_back(std::move(pageResult));
            }
            return outcome;
        }

        // verdictColorHex：结论的语义色。无法判定用警告色而不是中性色——
        // 它和"没问题"必须在一眼之内区分开，那正是这一整页最容易被读错的地方。
        QString verdictColorHex(const TamperVerdict verdict)
        {
            switch (verdict)
            {
            case TamperVerdict::Consistent:
                return KswordTheme::SuccessHex();
            case TamperVerdict::CpuViewRedirected:
            case TamperVerdict::UnexplainedDisagreement:
                return KswordTheme::ErrorHex();
            case TamperVerdict::UserModeViewDiffers:
            case TamperVerdict::LiveDiffersFromReference:
                return KswordTheme::WarningHex();
            case TamperVerdict::Inconclusive:
                break;
            }
            return KswordTheme::WarningHex();
        }
    }

    TamperDetectionPage::TamperDetectionPage(QWidget* const parent)
        : QWidget(parent)
    {
        buildUi();
        wireSignals();
        refreshChannelAvailability();
        updateRunButtonState();
    }

    TamperDetectionPage::~TamperDetectionPage() = default;

    void TamperDetectionPage::buildUi()
    {
        // 页面自带内部滚动壳：七个读取路径复选框排成一行时最小宽度接近一千像素，
        // 窄 Dock 下在页内横向/纵向滚动，不再把整个内存 Dock 撑宽或撑高。
        // 根布局建在壳的内容容器上。
        QVBoxLayout* rootLayout = new QVBoxLayout(ks::ui::EnablePageInnerScroll(this));
        rootLayout->setContentsMargins(8, 8, 8, 8);
        rootLayout->setSpacing(8);

        QLabel* introLabel = new QLabel(this);
        introLabel->setWordWrap(true);
        introLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        introLabel->setText(QStringLiteral("对同一段内存同时走多条相互独立的读取路径，逐页互比。R3 / R0 虚拟 / R0 物理都经过 CPU 的地址翻译，会被 SLAT / EPT 一起影响；DDMA 走磁盘控制器的总线主控 DMA，不经过 CPU 页表。CPU 侧与 DMA 侧对同一物理页给出不同答案，就是内存被重定向的直接证据——这类隐藏用“内存 vs 磁盘映像”的比对抓不到，因为影子页里放的正是磁盘上那份原始字节。"));
        rootLayout->addWidget(introLabel);

        QGridLayout* formLayout = new QGridLayout();
        formLayout->setHorizontalSpacing(8);
        formLayout->setVerticalSpacing(6);

        formLayout->addWidget(new QLabel(QStringLiteral("扫描目标"), this), 0, 0);
        m_targetCombo = new QComboBox(this);
        m_targetCombo->setToolTip(QStringLiteral("选择要检查的模块，或选“自定义范围”后在右侧填写起始地址。"));
        formLayout->addWidget(m_targetCombo, 0, 1);

        m_rangeStartEdit = new QLineEdit(this);
        m_rangeStartEdit->setPlaceholderText(QStringLiteral("起始地址，默认十六进制"));
        m_rangeStartEdit->setClearButtonEnabled(true);
        formLayout->addWidget(m_rangeStartEdit, 0, 2);

        formLayout->addWidget(new QLabel(QStringLiteral("最多扫描页数"), this), 0, 3);
        m_maxPageSpin = new QSpinBox(this);
        m_maxPageSpin->setRange(1, kHardMaxPages);
        m_maxPageSpin->setValue(kDefaultMaxPages);
        m_maxPageSpin->setToolTip(QStringLiteral("DDMA 每页要做四次磁盘往返（备份扇区→写→读→还原），页数乘轮数直接决定耗时。先用小范围定位，再扩大。"));
        formLayout->addWidget(m_maxPageSpin, 0, 4);

        formLayout->addWidget(new QLabel(QStringLiteral("采样轮数"), this), 1, 0);
        m_roundSpin = new QSpinBox(this);
        m_roundSpin->setRange(2, 10);
        m_roundSpin->setValue(3);
        m_roundSpin->setToolTip(QStringLiteral("一轮无法把篡改和采样窗口内的正常写入分开，所以最少两轮。只有每一轮都不一致才会升为结论。"));
        formLayout->addWidget(m_roundSpin, 1, 1);

        QHBoxLayout* pathLayout = new QHBoxLayout();
        pathLayout->setContentsMargins(0, 0, 0, 0);
        pathLayout->setSpacing(10);
        m_useUserModeCheck = new QCheckBox(QStringLiteral("R3 用户态读"), this);
        m_useKernelVirtualCheck = new QCheckBox(QStringLiteral("R0 虚拟地址读"), this);
        m_useKernelPhysicalCheck = new QCheckBox(QStringLiteral("R0 物理地址读"), this);
        m_useHvmCheck = new QCheckBox(QStringLiteral("HVM 私有页表窗口"), this);
        m_useDmaCheck = new QCheckBox(QStringLiteral("DDMA 物理读"), this);
        m_useUserModeCheck->setChecked(true);
        m_useKernelVirtualCheck->setChecked(true);
        m_useKernelPhysicalCheck->setChecked(true);
        m_useHvmCheck->setChecked(true);
        m_useDmaCheck->setChecked(true);
        m_useDmaCheck->setToolTip(QStringLiteral("唯一一条不经过 CPU 页表的路径。去掉它之后，剩下的几条会被同一个隐藏者一起骗过，这一页就只能抓到普通补丁了。"));
        m_useImageSectionCheck = new QCheckBox(QStringLiteral("节对象干净页"), this);
        m_useOnDiskImageCheck = new QCheckBox(QStringLiteral("磁盘映像"), this);
        m_useImageSectionCheck->setToolTip(QStringLiteral("内存管理器自己持有的那份“这个映像本来该是什么样”，与磁盘文件是两个互相独立的来源：文件被一起改掉时它还在。仅对已映射的映像页有效。"));
        m_useOnDiskImageCheck->setToolTip(QStringLiteral("模块文件按当前加载基址归一化后的字节。只有选中具体模块时可用（自定义范围没有对应的文件与基址）。零填充区、节间隙和不可归一化的范围会如实报成“不覆盖”，不会补 00 参与比较。"));
        pathLayout->addWidget(m_useUserModeCheck);
        pathLayout->addWidget(m_useKernelVirtualCheck);
        pathLayout->addWidget(m_useKernelPhysicalCheck);
        pathLayout->addWidget(m_useHvmCheck);
        pathLayout->addWidget(m_useDmaCheck);
        pathLayout->addWidget(m_useImageSectionCheck);
        pathLayout->addWidget(m_useOnDiskImageCheck);
        pathLayout->addStretch(1);
        formLayout->addLayout(pathLayout, 1, 2, 1, 3);

        rootLayout->addLayout(formLayout);

        QHBoxLayout* actionLayout = new QHBoxLayout();
        actionLayout->setContentsMargins(0, 0, 0, 0);
        actionLayout->setSpacing(8);
        m_runButton = new QPushButton(QStringLiteral("开始交叉检查"), this);
        actionLayout->addWidget(m_runButton);
        m_channelHintLabel = new QLabel(this);
        m_channelHintLabel->setWordWrap(true);
        actionLayout->addWidget(m_channelHintLabel, 1);
        ks::ui::NormalizeToolbarRow(actionLayout);
        rootLayout->addLayout(actionLayout);

        m_statusLabel = new QLabel(QStringLiteral("尚未执行。"), this);
        m_statusLabel->setWordWrap(true);
        m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        rootLayout->addWidget(m_statusLabel);

        QSplitter* splitter = new QSplitter(Qt::Vertical, this);

        m_resultTable = new ks::ui::VisibleTableWidget(splitter);
        // 独立篡改结论需保留证据快照，不能按参数选择器隐藏。
        ks::ui::SetTableActionBarMode(m_resultTable, ks::ui::TableActionBarMode::Full);
        m_resultTable->setColumnCount(5);
        m_resultTable->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("虚拟地址"),
            QStringLiteral("物理地址"),
            QStringLiteral("结论"),
            QStringLiteral("分歧对数"),
            QStringLiteral("说明") });
        m_resultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_resultTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_resultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_resultTable->setAlternatingRowColors(true);
        m_resultTable->verticalHeader()->setVisible(false);
        m_resultTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
        splitter->addWidget(m_resultTable);

        m_detailText = new ks::ui::StructuredFieldView(splitter);

        m_detailText->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("选中上方任意一行查看该页每条路径的状态与逐对分歧。")));
        splitter->addWidget(m_detailText);

        splitter->setStretchFactor(0, 3);
        splitter->setStretchFactor(1, 2);
        rootLayout->addWidget(splitter, 1);
    }

    void TamperDetectionPage::wireSignals()
    {
        connect(m_runButton, &QPushButton::clicked, this, [this]() { startScan(); });
        connect(m_resultTable, &QTableWidget::itemSelectionChanged, this,
            [this]() { renderSelectedDetail(); });
        connect(m_targetCombo, &QComboBox::currentIndexChanged, this,
            [this](int) { updateRunButtonState(); });
        const auto pathToggled = [this](bool) { updateRunButtonState(); };
        connect(m_useUserModeCheck, &QCheckBox::toggled, this, pathToggled);
        connect(m_useKernelVirtualCheck, &QCheckBox::toggled, this, pathToggled);
        connect(m_useKernelPhysicalCheck, &QCheckBox::toggled, this, pathToggled);
        connect(m_useHvmCheck, &QCheckBox::toggled, this, pathToggled);
        connect(m_useDmaCheck, &QCheckBox::toggled, this, pathToggled);
        connect(m_useImageSectionCheck, &QCheckBox::toggled, this, pathToggled);
        connect(m_useOnDiskImageCheck, &QCheckBox::toggled, this, pathToggled);
    }

    void TamperDetectionPage::setAttachedProcess(
        const std::uint32_t processId, const QString& processName)
    {
        m_attachedPid = processId;
        m_attachedProcessName = processName;
        updateRunButtonState();
    }

    void TamperDetectionPage::setModuleCandidates(const std::vector<ModuleCandidate>& candidates)
    {
        m_moduleCandidates = candidates;
        const QString previousText = m_targetCombo->currentText();
        {
            const QSignalBlocker blocker(m_targetCombo);
            m_targetCombo->clear();
            m_targetCombo->addItem(QStringLiteral("自定义范围"), QVariant::fromValue(-1));
            for (int index = 0; index < static_cast<int>(candidates.size()); ++index)
            {
                m_targetCombo->addItem(candidates[static_cast<std::size_t>(index)].displayText, index);
            }
            const int restoredIndex = m_targetCombo->findText(previousText);
            m_targetCombo->setCurrentIndex(restoredIndex >= 0 ? restoredIndex : 0);
        }
        updateRunButtonState();
    }

    void TamperDetectionPage::refreshChannelAvailability()
    {
        QString reason;
        const bool ddmaUsable = ksword::memory_backend::isDdmaUsable(
            ksword::memory_backend::currentDdmaSession(), &reason);
        m_useDmaCheck->setEnabled(ddmaUsable);

        // HVM 的可用性与 DDMA 无关，单独问一次。窗口没标定出来时这条通道
        // 仍会返回数据（回退 MmCopyMemory），但那时它与 R0 不再独立——
        // 两者一致就不能用来排除内存管理器被挂钩，所以判为不可用而不是
        // 让它带着一个悄悄失效的性质继续参与比对。
        QString hvmReason;
        const bool hvmUsable = ksword::memory_backend::isHvmMemoryUsable(&hvmReason);
        m_useHvmCheck->setEnabled(hvmUsable);
        if (!hvmUsable)
        {
            m_useHvmCheck->setChecked(false);
            m_useHvmCheck->setToolTip(hvmReason);
        }
        else
        {
            m_useHvmCheck->setToolTip(QStringLiteral("改写自有页表项指向目标帧，整条路径不调用文档化的内存管理器例程。它同样受 SLAT / EPT 约束，与 R0 分歧说明的是内存管理器被挂了钩，不是重定向。"));
        }
        if (ddmaUsable)
        {
            m_channelHintLabel->setText(QStringLiteral("DDMA 通道就绪，本页可以判定 SLAT / EPT 级别的重定向。"));
            m_channelHintLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::SuccessHex()));
        }
        else
        {
            // 这里必须说清楚"少了 DDMA 会少掉哪一类结论"，而不是只说它不可用。
            // 否则用户会以为没有 DDMA 时这一页照样能回答同一个问题。
            m_useDmaCheck->setChecked(false);
            m_channelHintLabel->setText(
                QStringLiteral("DDMA 暂不可用：%1。没有这条路径时，其余几条都经过 CPU 页表、会被同一个隐藏者一起骗过，本页只能发现普通补丁，无法判定 SLAT / EPT 重定向。").arg(reason));
            m_channelHintLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
        }
        updateRunButtonState();
    }

    void TamperDetectionPage::updateRunButtonState()
    {
        // 磁盘映像需要文件路径与加载基址，"自定义范围"两样都没有。这里直接置灰
        // 并说明理由，而不是让它跑完之后报一堆"不覆盖"——那样用户会以为是
        // 归一化出了问题。
        const int targetIndex = m_targetCombo->currentData().toInt();
        const bool moduleSelected =
            targetIndex >= 0 && targetIndex < static_cast<int>(m_moduleCandidates.size());
        m_useOnDiskImageCheck->setEnabled(moduleSelected);
        if (!moduleSelected)
        {
            m_useOnDiskImageCheck->setChecked(false);
        }

        int selectedPathCount = 0;
        selectedPathCount += m_useUserModeCheck->isChecked() ? 1 : 0;
        selectedPathCount += m_useKernelVirtualCheck->isChecked() ? 1 : 0;
        selectedPathCount += m_useKernelPhysicalCheck->isChecked() ? 1 : 0;
        selectedPathCount += (m_useHvmCheck->isEnabled() && m_useHvmCheck->isChecked()) ? 1 : 0;
        selectedPathCount += (m_useDmaCheck->isEnabled() && m_useDmaCheck->isChecked()) ? 1 : 0;
        selectedPathCount += m_useImageSectionCheck->isChecked() ? 1 : 0;
        selectedPathCount += (m_useOnDiskImageCheck->isEnabled()
            && m_useOnDiskImageCheck->isChecked()) ? 1 : 0;

        const bool ready = (m_attachedPid != 0) && (selectedPathCount >= 2) && !m_scanInFlight;
        m_runButton->setEnabled(ready);
        if (m_attachedPid == 0)
        {
            m_runButton->setToolTip(QStringLiteral("请先在顶部附加一个进程。"));
        }
        else if (selectedPathCount < 2)
        {
            m_runButton->setToolTip(QStringLiteral("至少要勾选两条路径才能互比。一条路径无从比对。"));
        }
        else
        {
            m_runButton->setToolTip(QStringLiteral("对选中范围逐页采样并互比。"));
        }
    }

    bool TamperDetectionPage::parseScanRange(
        std::uint64_t& startOut, std::uint64_t& pageCountOut, QString& errorOut) const
    {
        const int targetIndex = m_targetCombo->currentData().toInt();
        const std::uint64_t maxPages = static_cast<std::uint64_t>(m_maxPageSpin->value());

        if (targetIndex >= 0 && targetIndex < static_cast<int>(m_moduleCandidates.size()))
        {
            const ModuleCandidate& candidate =
                m_moduleCandidates[static_cast<std::size_t>(targetIndex)];
            startOut = candidate.baseAddress & ~(kPageBytes - 1ULL);
            const std::uint64_t modulePages =
                (candidate.sizeBytes + kPageBytes - 1ULL) / kPageBytes;
            pageCountOut = (std::min)(maxPages, (std::max)(std::uint64_t{1}, modulePages));
            return true;
        }

        const auto parsed = ksword::evidence::ParseNumericText(
            m_rangeStartEdit->text().trimmed().toStdString(),
            ksword::evidence::NumericTextDefaultRadix::Hexadecimal);
        if (!parsed.ok)
        {
            errorOut = QStringLiteral("起始地址解析失败。无前缀按十六进制解释，也可写 0x 前缀。");
            return false;
        }
        startOut = parsed.value & ~(kPageBytes - 1ULL);
        pageCountOut = maxPages;
        return true;
    }

    void TamperDetectionPage::startScan()
    {
        if (m_scanInFlight)
        {
            return;
        }

        TamperScanRequest request;
        QString rangeError;
        if (!parseScanRange(request.startAddress, request.pageCount, rangeError))
        {
            m_statusLabel->setText(rangeError);
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
            return;
        }

        request.processId = m_attachedPid;
        request.roundCount = m_roundSpin->value();
        request.useUserMode = m_useUserModeCheck->isChecked();
        request.useKernelVirtual = m_useKernelVirtualCheck->isChecked();
        request.useKernelPhysical = m_useKernelPhysicalCheck->isChecked();
        request.useHvm = m_useHvmCheck->isEnabled() && m_useHvmCheck->isChecked();
        request.useDma = m_useDmaCheck->isEnabled() && m_useDmaCheck->isChecked();
        request.useImageSection = m_useImageSectionCheck->isChecked();
        request.useOnDiskImage =
            m_useOnDiskImageCheck->isEnabled() && m_useOnDiskImageCheck->isChecked();
        const int selectedTargetIndex = m_targetCombo->currentData().toInt();
        if (selectedTargetIndex >= 0
            && selectedTargetIndex < static_cast<int>(m_moduleCandidates.size()))
        {
            const ModuleCandidate& candidate =
                m_moduleCandidates[static_cast<std::size_t>(selectedTargetIndex)];
            request.moduleBaseAddress = candidate.baseAddress;
            request.moduleFilePath = candidate.filePath;
        }
        // 会话按值拷进请求：工作线程跑的过程中 DDMA 页可能被改配置，读引用会拿到
        // 半新半旧的组合，而那意味着这一轮里前后几页用的不是同一块暂存扇区。
        request.ddmaSession = ksword::memory_backend::currentDdmaSession();

        m_scanInFlight = true;
        ++m_scanGeneration;
        const std::uint64_t generation = m_scanGeneration;
        updateRunButtonState();
        m_statusLabel->setText(QStringLiteral("正在采样：%1 页 × %2 轮…")
            .arg(request.pageCount)
            .arg(request.roundCount));
        m_statusLabel->setStyleSheet(
            QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));

        QPointer<TamperDetectionPage> guardedSelf(this);
        QRunnable* const task = QRunnable::create([guardedSelf, request, generation]() {
            const ScanOutcome outcome = runScan(request);
            const auto sharedResults =
                std::make_shared<std::vector<TamperPageResult>>(outcome.results);
            const QString abortReason = outcome.abortReason;
            QTimer::singleShot(0, QCoreApplication::instance(),
                [guardedSelf, sharedResults, abortReason, generation]() {
                    if (guardedSelf == nullptr)
                    {
                        return;
                    }
                    // 代次过期说明期间又发起了一轮，旧结果直接丢弃：把它贴上去会
                    // 让界面显示的范围与用户刚刚提交的不是同一个。
                    if (guardedSelf->m_scanGeneration != generation)
                    {
                        return;
                    }
                    guardedSelf->m_scanInFlight = false;
                    guardedSelf->applyScanResults(*sharedResults);
                    if (!abortReason.isEmpty())
                    {
                        // 整轮没跑完时原因必须盖在汇总之上：汇总里那句"一致 N"
                        // 在这种情况下是拿缺了一条参考的结果算出来的。
                        guardedSelf->m_statusLabel->setText(
                            QStringLiteral("%1 %2")
                                .arg(abortReason)
                                .arg(guardedSelf->m_statusLabel->text()));
                        guardedSelf->m_statusLabel->setStyleSheet(
                            QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
                    }
                    guardedSelf->updateRunButtonState();
                });
            });
        task->setAutoDelete(true);
        QThreadPool::globalInstance()->start(task);
    }

    void TamperDetectionPage::applyScanResults(const std::vector<TamperPageResult>& results)
    {
        m_results = results;
        m_resultTable->setRowCount(static_cast<int>(results.size()));

        int redirectedCount = 0;
        int inconclusiveCount = 0;
        int consistentCount = 0;
        int otherFindingCount = 0;

        for (int row = 0; row < static_cast<int>(results.size()); ++row)
        {
            const TamperPageResult& pageResult = results[static_cast<std::size_t>(row)];
            const TamperVerdict verdict = pageResult.finding.verdict;
            switch (verdict)
            {
            case TamperVerdict::CpuViewRedirected: ++redirectedCount; break;
            case TamperVerdict::Inconclusive: ++inconclusiveCount; break;
            case TamperVerdict::Consistent: ++consistentCount; break;
            default: ++otherFindingCount; break;
            }

            m_resultTable->setItem(row, 0, new QTableWidgetItem(
                QStringLiteral("0x%1").arg(pageResult.virtualAddress, 16, 16, QChar('0'))
                    .toUpper().replace(QStringLiteral("0X"), QStringLiteral("0x"))));
            m_resultTable->setItem(row, 1, new QTableWidgetItem(
                pageResult.physicalAddressValid
                    ? QStringLiteral("0x%1").arg(pageResult.physicalAddress, 12, 16, QChar('0'))
                          .toUpper().replace(QStringLiteral("0X"), QStringLiteral("0x"))
                    : QStringLiteral("-")));

            QTableWidgetItem* const verdictItem =
                new QTableWidgetItem(QString::fromUtf8(TamperVerdictName(verdict)));
            verdictItem->setForeground(QColor(verdictColorHex(verdict)));
            m_resultTable->setItem(row, 2, verdictItem);

            m_resultTable->setItem(row, 3, new QTableWidgetItem(
                QString::number(pageResult.finding.disagreements.size())));

            QString noteText = QString::fromStdString(pageResult.finding.inconclusiveReason);
            if (noteText.isEmpty() && !pageResult.translateFailureText.isEmpty())
            {
                noteText = pageResult.translateFailureText;
            }
            if (noteText.isEmpty() && verdict == TamperVerdict::CpuViewRedirected)
            {
                noteText = pageResult.finding.cpuMatchesStaticReference
                    ? QStringLiteral("CPU 侧与静态参考一致、DMA 侧不同：隐藏者正在给 CPU 看原始字节")
                    : QStringLiteral("CPU 侧与 DMA 侧持续不一致");
            }
            m_resultTable->setItem(row, 4, new QTableWidgetItem(noteText));
        }
        m_resultTable->resizeColumnsToContents();
        m_resultTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);

        // 汇总里把"无法判定"单独列出来，而且不能和"一致"并排读成同一类好结果：
        // 它的含义是这一页没被检查到，不是这一页没问题。
        QString summary = QStringLiteral("共 %1 页：一致 %2，重定向 %3，其它差异 %4，无法判定 %5。")
            .arg(results.size())
            .arg(consistentCount)
            .arg(redirectedCount)
            .arg(otherFindingCount)
            .arg(inconclusiveCount);
        if (redirectedCount > 0)
        {
            summary += QStringLiteral(" 存在 CPU 视图被重定向的页——这是 SLAT / EPT 级别隐藏的直接证据，请逐页查看明细。");
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::ErrorHex()));
        }
        else if (inconclusiveCount > 0)
        {
            summary += QStringLiteral(" 无法判定的页不代表干净，只代表没能在这些页上取到足够的可比对读数。");
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
        }
        else
        {
            m_statusLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::SuccessHex()));
        }
        m_statusLabel->setText(summary);

        if (!results.empty())
        {
            m_resultTable->selectRow(0);
        }
        renderSelectedDetail();
    }

    void TamperDetectionPage::renderSelectedDetail()
    {
        const int row = m_resultTable->currentRow();
        if (row < 0 || row >= static_cast<int>(m_results.size()))
        {
            m_detailText->setDocument({});
            return;
        }
        const TamperPageResult& pageResult = m_results[static_cast<std::size_t>(row)];
        const TamperFinding& finding = pageResult.finding;

        ks::ui::FieldDocument lines;
        lines.field(QStringLiteral("虚拟地址"), QStringLiteral("0x%1").arg(pageResult.virtualAddress, 16, 16, QChar('0')).toUpper());
        lines.field(QStringLiteral("结论"), QString::fromUtf8(TamperVerdictName(finding.verdict)), true);
        lines.field(QStringLiteral("可比对轮数"), QString::number(finding.comparableRoundCount));
        if (!finding.inconclusiveReason.empty()) lines.field(QStringLiteral("未能判定的原因"), QString::fromStdString(finding.inconclusiveReason), true);
        lines.section(QStringLiteral("各路径最后一轮的状态"));
        for (const TamperViewSample& sample : finding.lastRoundStatus) {
            lines.field(QString::fromUtf8(TamperReadPathName(sample.path)), QString::fromUtf8(TamperSampleStatusName(sample.status)), true);
            if (!sample.failureText.empty()) lines.note(QString::fromStdString(sample.failureText));
        }
        if (finding.disagreements.empty()) lines.note(QStringLiteral("未观察到任何一对路径之间的字节差异。"));
        else for (const TamperDisagreement& disagreement : finding.disagreements) {
            lines.section(QStringLiteral("%1 ↔ %2").arg(QString::fromUtf8(TamperReadPathName(disagreement.left)), QString::fromUtf8(TamperReadPathName(disagreement.right))));
            lines.field(QStringLiteral("不一致轮数 / 可比对轮数"), QStringLiteral("%1 / %2").arg(disagreement.disagreeingRounds).arg(disagreement.comparableRounds));
            lines.field(QStringLiteral("首个不同的页内偏移"), QStringLiteral("0x%1").arg(disagreement.firstDifferingOffset, 0, 16).toUpper());
            lines.field(QStringLiteral("两侧字节"), QStringLiteral("%1 / %2").arg(disagreement.leftByte, 2, 16, QChar('0')).arg(disagreement.rightByte, 2, 16, QChar('0')).toUpper());
            lines.field(QStringLiteral("不同字节数量"), QString::number(disagreement.differingByteCount));
        }
        m_detailText->setDocument(lines);
    }
}
