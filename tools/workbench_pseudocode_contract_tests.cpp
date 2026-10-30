#include "workbench_pseudocode_contract_tests.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchPseudocodeView.h"
#include "../Ksword5.1/Ksword5.1/UI/CodeTextEdit.h"
#include "../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEvent>
#include <QLineEdit>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QProgressBar>
#include <QTest>
#include <QToolButton>
#include <QtEndian>
#include <algorithm>
#include <cstdio>
#include <limits>

namespace
{
    // MaskedProvider：只给合成窗口，不依赖任何真实目标；掩码能独立模拟异步与不可读。
    class MaskedProvider final : public ks::ui::IWorkbenchBytesProvider
    {
    public:
        std::uint64_t base = 0x1000; // 合成证据的起始地址。
        std::vector<std::uint8_t> bytes{0xb8, 0x2a, 0, 0, 0, 0xc3};
        std::vector<std::uint8_t> mask = std::vector<std::uint8_t>(6, 1);
        bool available = true;      // 整个来源当前是否可取。
        bool malformed = false;     // 模拟适配器长度错误。
        mutable std::uint64_t largestRequest = 0; // 断言共享页遵守单次缓存拷贝上限。
        std::uint64_t maximumFetchBytes = 65536;
        ks::ui::WorkbenchByteWindow FetchWindow(std::uint64_t address, std::uint64_t length) const override
        {
            ks::ui::WorkbenchByteWindow result;
            result.address = address;
            largestRequest = std::max(largestRequest, length);
            if (length > maximumFetchBytes || !available || address < base || address - base > bytes.size()
                || length > bytes.size() - (address - base)) return result;
            const auto offset = static_cast<std::size_t>(address - base);
            result.ok = true;
            result.bytes.assign(bytes.begin() + offset, bytes.begin() + offset + static_cast<std::size_t>(length));
            result.validMask.assign(mask.begin() + offset, mask.begin() + offset + static_cast<std::size_t>(length));
            if (malformed && !result.validMask.empty()) result.validMask.pop_back();
            return result;
        }
        int AddressBits() const override { return 64; }
        bool HasPreviousRead() const override { return false; }
    };

    // DrainBackend：无效后端目录只触发配置错误，不创建任何分析进程。
    void DrainBackend(ks::ui::WorkbenchPseudocodeView& page)
    {
        // RAW planning starts on QTimer(0), before the backend has a running bit.
        // Observe the page's whole operation rather than only an already-started JVM.
        auto* cancel = page.findChild<QPushButton*>(QStringLiteral("memory_decompile_cancel"));
        QElapsedTimer deadline;
        deadline.start();
        do
        {
            QApplication::processEvents();
            if (!page.decompiler()->isRunning() && cancel && !cancel->isEnabled()) return;
            QTest::qWait(2);
        } while (deadline.elapsed() < 3000);
    }

    // WaitFor：等待真实 queued Qt 回调，禁止用固定延时假定后端阶段已派发。
    bool WaitFor(const std::function<bool()>& completed, const int timeoutMs = 1000)
    {
        QElapsedTimer deadline; // 本测试允许的单调等待预算。
        deadline.start();
        while (!completed() && deadline.elapsed() < timeoutMs)
        {
            QTest::qWait(2);
        }
        return completed();
    }

    // ProgressEventProbe：只在实际 Show/Hide 边界执行一次动作；删除 watched 后
    // 必须吞掉本次事件，不能让 QObject 继续向已经销毁的对象派发事件。
    class ProgressEventProbe final : public QObject
    {
    public:
        ProgressEventProbe(const QEvent::Type eventType, std::function<void()> action)
            : type_(eventType), action_(std::move(action))
        {
        }

        int calls() const noexcept { return calls_; }

    protected:
        bool eventFilter(QObject* watched, QEvent* incoming) override
        {
            if (!armed_ || incoming->type() != type_) return false;
            armed_ = false;
            ++calls_;
            const QPointer<QObject> alive(watched); // 回调可以销毁整个所属 C 页面。
            action_();
            return alive.isNull();
        }

    private:
        QEvent::Type type_;                 // 只观察指定的真实控件事件。
        std::function<void()> action_;     // 一次换源、重入或销毁动作。
        bool armed_ = true;                // 重入派发不得重复执行同一个动作。
        int calls_ = 0;                    // 防止事件未触发也被判为通过。
    };

    // PrepareProgressPage：真实 C 页面与真实后端，固定失败目录避免创建分析进程。
    void PrepareProgressPage(ks::ui::WorkbenchPseudocodeView& page, MaskedProvider& provider,
        const ks::ui::WorkbenchPseudocodeContext& context)
    {
        page.setBytesProvider(&provider);
        page.setContext(context);
        page.findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"))->setText(
            QDir::current().filePath(QStringLiteral(".codex-build-logs/not-a-ghidra-runtime")));
        page.resize(850, 480);
        page.show();
        QApplication::processEvents();
    }

    // Exercise the public C-page state machine using actual RAW control flow.
    // The invalid backend directory prevents Java or target-process access.
    void CheckRawPlanningContracts(const std::function<void(bool, const char*)>& require)
    {
        using namespace ks::ui;
        const auto contextFor = [](const MaskedProvider& provider) {
            WorkbenchPseudocodeContext context;
            context.sourceIdentity = QStringLiteral("raw-planner-ui-contract");
            context.revision = 1;
            context.contentRevision = 1;
            context.baseAddress = context.selectedAddress = provider.base;
            context.length = provider.bytes.size();
            return context;
        };
        const auto configure = [](WorkbenchPseudocodeView& page, MaskedProvider& provider,
            const WorkbenchPseudocodeContext& context) {
            page.setBytesProvider(&provider);
            page.setContext(context);
            page.findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"))->setText(
                QDir::current().filePath(QStringLiteral(".codex-build-logs/not-a-ghidra-runtime")));
        };
        const auto codeResult = [](const std::uint64_t entry) {
            DecompilerResult result;
            result.success = true;
            result.code = QStringLiteral("int raw_fixture(void) { return 42; }");
            result.functionName = QStringLiteral("raw_fixture");
            result.functionAddress = entry;
            result.lineAddresses = {entry};
            result.lineAddressValid = {true};
            return result;
        };
        {
            MaskedProvider provider;
            provider.base = 0; // A zero candidate is valid, distinct from empty/unknown.
            auto context = contextFor(provider);
            context.selectedAddress = 5; // RET is an interior instruction of the candidate.
            WorkbenchPseudocodeView page;
            configure(page, provider, context);
            auto* entry = page.findChild<QLineEdit*>(QStringLiteral("memory_pseudocode_entry"));
            require(entry != nullptr, "C RAW page exposes its explicit candidate-entry input");
            unsigned starts = 0;
            QObject::connect(page.decompiler(), &GhidraDecompiler::runningChanged, &page,
                [&](bool running) { if (running) ++starts; });
            entry->setText(QStringLiteral("0x0"));
            page.startDecompilation();
            DrainBackend(page);
            emit page.decompiler()->finished(codeResult(0));
            require(starts == 1 && !page.editor()->toPlainText().isEmpty(),
                "C candidate address zero can recover a function containing an interior selected instruction");
            provider.bytes.resize(32, 0xcc);
            provider.mask.resize(32, 1);
            context.length = provider.bytes.size();
            context.selectedAddress = 16;
            page.setContext(context);
            page.startDecompilation(); DrainBackend(page);
            require(starts == 1 && page.editor()->toPlainText().isEmpty(),
                "C a declared entry cannot claim an unrelated selected address belongs to its function");
            entry->setText(QStringLiteral("not-an-address"));
            page.startDecompilation();
            DrainBackend(page);
            require(starts == 1 && page.editor()->toPlainText().isEmpty(),
                "C invalid candidate literals are rejected before backend startup");
        }
        {
            MaskedProvider provider;
            WorkbenchPseudocodeView page;
            auto context = contextFor(provider);
            configure(page, provider, context);
            unsigned starts = 0, requests = 0;
            QObject::connect(page.decompiler(), &GhidraDecompiler::runningChanged, &page,
                [&](bool running) { if (running) ++starts; });
            QObject::connect(&page, &WorkbenchPseudocodeView::windowRequested, &page,
                [&](quint64, quint64) { ++requests; });
            provider.mask[5] = 2;
            page.startDecompilation();
            require(WaitFor([&]() { return requests == 1; }), "C RAW pending operation reaches one real host read");
            page.refreshView(); page.refreshView();
            QApplication::processEvents();
            require(requests == 1 && starts == 0, "C RAW pending refreshes preserve the planner without duplicate reads");
            page.setSourceRevisions(context.revision, context.contentRevision + 1);
            provider.mask[5] = 1;
            page.refreshView();
            QApplication::processEvents();
            require(starts == 0, "C content-authority changes cancel a pending plan before its late page arrives");
            ++context.contentRevision;
            page.setContext(context);
            page.startDecompilation(); DrainBackend(page);
            emit page.decompiler()->finished(codeResult(provider.base));
            require(!page.editor()->toPlainText().isEmpty(), "C new content authority may start a fresh plan");
            page.setSourceRevisions(context.revision + 1, context.contentRevision);
            emit page.decompiler()->finished(codeResult(provider.base));
            require(page.editor()->toPlainText().isEmpty(), "C source-authority changes reject late completed code");
        }
        {
            MaskedProvider provider;
            provider.bytes.assign(3 * 4096, 0xcc);
            provider.mask.assign(provider.bytes.size(), 1);
            provider.bytes[0] = 0xe9;
            qToLittleEndian<qint32>(8192 - 5, provider.bytes.data() + 1);
            const std::vector<std::uint8_t> returned{0xb8, 0x2a, 0, 0, 0, 0xc3};
            std::copy(returned.begin(), returned.end(), provider.bytes.begin() + 8192);
            std::fill(provider.mask.begin() + 4096, provider.mask.begin() + 8192, 0);
            WorkbenchPseudocodeView page;
            configure(page, provider, contextFor(provider));
            unsigned starts = 0;
            QObject::connect(page.decompiler(), &GhidraDecompiler::runningChanged, &page,
                [&](bool running) { if (running) ++starts; });
            page.startDecompilation(); DrainBackend(page);
            emit page.decompiler()->finished(codeResult(provider.base));
            require(starts == 1 && !page.editor()->toPlainText().isEmpty(),
                "C RAW follows a real jump across an unreadable hole without demanding the gap bytes");
            qToLittleEndian<qint32>(4096 - 5, provider.bytes.data() + 1);
            page.setContext(contextFor(provider));
            page.startDecompilation(); DrainBackend(page);
            require(starts == 1 && page.editor()->toPlainText().isEmpty(),
                "C RAW rejects a reachable branch target inside an unreadable page");
        }
        {
            MaskedProvider provider;
            provider.bytes = {0xff, 0xe0}; // JMP RAX has unknown control flow.
            provider.mask.assign(2, 1);
            WorkbenchPseudocodeView page;
            configure(page, provider, contextFor(provider));
            unsigned starts = 0;
            QObject::connect(page.decompiler(), &GhidraDecompiler::runningChanged, &page,
                [&](bool running) { if (running) ++starts; });
            page.startDecompilation(); DrainBackend(page);
            require(starts == 0 && page.editor()->toPlainText().isEmpty(),
                "C RAW unresolved indirect jumps do not publish apparently complete code");
        }
        {
            MaskedProvider provider;
            provider.bytes.assign(8192, 0xcc);
            provider.mask.assign(provider.bytes.size(), 1);
            provider.bytes[0] = 0x8b; provider.bytes[1] = 0x05; // MOV EAX,[RIP+constant]
            qToLittleEndian<qint32>(4096 - 6, provider.bytes.data() + 2);
            provider.bytes[6] = 0xc3;
            qToLittleEndian<quint32>(42, provider.bytes.data() + 4096);
            WorkbenchPseudocodeView page;
            configure(page, provider, contextFor(provider));
            page.startDecompilation(); DrainBackend(page);
            emit page.decompiler()->finished(codeResult(provider.base));
            require(!page.editor()->toPlainText().isEmpty(), "C RAW static RIP-relative data is part of the frozen evidence");
            provider.bytes[4096] ^= 1;
            page.refreshView();
            require(page.editor()->toPlainText().isEmpty(), "C changes to a used constant invalidate the result");
        }
    }
}

void RunWorkbenchPseudocodeContractTests(const std::function<void(bool, const char*)>& require)
{
    using namespace ks::ui;
    MaskedProvider provider;
    WorkbenchPseudocodeView page;
    page.setBytesProvider(&provider);
    WorkbenchPseudocodeContext context;
    context.sourceIdentity = QStringLiteral("synthetic-C-source");
    context.revision = 1;
    context.baseAddress = provider.base;
    context.length = provider.bytes.size();
    context.selectedAddress = provider.base;
    page.setContext(context);
    page.findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"))->setText(
        QDir::current().filePath(QStringLiteral(".codex-build-logs/not-a-ghidra-runtime")));
    unsigned starts = 0;       // 实际后端启动入口触发次数，不把空白编辑器当拒绝证据。
    unsigned requested = 0;    // 唯一的异步读取请求数。
    QObject::connect(page.decompiler(), &GhidraDecompiler::runningChanged, &page,
        [&](bool running) { if (running) ++starts; });
    QObject::connect(&page, &WorkbenchPseudocodeView::windowRequested, &page,
        [&](quint64 address, quint64 length) {
            ++requested;
            require(address >= context.baseAddress && address - context.baseAddress < context.length
                && length && length <= context.length - (address - context.baseAddress),
                "C loading request stays in the captured analysis bounds");
        });

    // 掩码 0、错误长度和未知掩码都不能被补零或误解为有效证据。
    for (const auto invalid : {std::uint8_t{0}, std::uint8_t{3}, std::uint8_t{255}})
    {
        provider.mask[5] = invalid;
        page.startDecompilation();
        DrainBackend(page);
        require(starts == 0 && requested == 0, "C backend never starts on unavailable or unknown-mask bytes");
    }
    provider.mask[5] = 1;
    provider.malformed = true;
    page.startDecompilation();
    DrainBackend(page);
    require(starts == 0 && requested == 0, "C backend rejects a malformed validity-mask length");
    provider.malformed = false;
    provider.mask[5] = 2;
    page.startDecompilation();
    const bool pendingReached = WaitFor([&]() { return requested == 1; });
    if (!pendingReached)
    {
        const auto* diagnostic = page.findChild<QLabel*>(QStringLiteral("memory_pseudocode_status"));
        std::fprintf(stderr, "RAW_PENDING requests=%u starts=%u largestFetch=%llu status=%s\n", requested, starts,
            static_cast<unsigned long long>(provider.largestRequest), diagnostic ? diagnostic->text().toUtf8().constData() : "<none>");
    }
    require(pendingReached, "C pending RAW work reaches its asynchronous host read request");
    page.refreshView();
    page.refreshView();
    require(starts == 0 && requested == 1, "C loading waits without repeated I/O requests or decoding pending bytes");
    // 用户可见的等待读取也是分析流程，必须有活动指示而不是只有不可变化的状态句。
    auto* activity = page.findChild<QProgressBar*>(QStringLiteral("memory_pseudocode_progress"));
    require(activity != nullptr, "C analysis has an observable progress control");
    require(activity && !activity->isHidden() && activity->minimum() == 0 && activity->maximum() == 0,
        "C waiting bytes shows indeterminate activity without inventing a percentage");
    auto* progressLabel = page.findChild<QLabel*>(QStringLiteral("memory_pseudocode_progress_label"));
    const QString initialProgress = progressLabel ? progressLabel->text() : QString();
    // 250ms 阶段定时器会有调度误差，等待真实整秒变化，不能假定1100ms时已过下一tick。
    const bool elapsedUpdated = WaitFor([&]() {
        return progressLabel && progressLabel->text() != initialProgress;
    }, 2500);
    require(elapsedUpdated && requested == 1,
        "C waiting progress updates elapsed time without starting extra reads");
    provider.mask[5] = 1;
    page.refreshView();
    DrainBackend(page);
    require(starts == 1 && !page.decompiler()->isRunning(), "C pending analysis resumes exactly once after every byte is valid");
    require(activity && activity->isHidden(), "C failed startup stops its progress activity");

    // 合成结果只用于检查 UI 接收票据，真实 Ghidra JSON/进程由既有后端夹具验证。
    DecompilerResult result;
    result.success = true;
    result.code = QStringLiteral("int synthetic_function() { return 7; }");
    result.functionName = QStringLiteral("synthetic_function");
    result.functionAddress = provider.base;
    result.lineAddresses = {provider.base};
    result.lineAddressValid = {true};
    emit page.decompiler()->finished(result);
    require(page.editor()->toPlainText() == result.code, "C view accepts a result matching the frozen identity and bytes");
    std::optional<quint64> located;
    QObject::connect(&page, &WorkbenchPseudocodeView::requestHexLocate, &page,
        [&](quint64 address) { located = address; });
    page.findChild<QPushButton*>(QStringLiteral("memory_pseudocode_locate_hex"))->click();
    require(located == provider.base, "C line navigation uses the same valid source address");
    provider.bytes[3] ^= 1;
    page.refreshView();
    emit page.decompiler()->finished(result);
    require(page.editor()->toPlainText().isEmpty(), "C input edits invalidate the result and suppress late backend delivery");
    page.startDecompilation();
    DrainBackend(page);
    ++context.revision;
    page.setContext(context);
    emit page.decompiler()->finished(result);
    require(page.editor()->toPlainText().isEmpty(), "C source generation changes suppress late results even for identical addresses");

    // 范围回绕和选点越界必须在取字节或后端启动前拒绝。
    const auto beforeBounds = starts;
    context.baseAddress = UINT64_MAX - 1;
    context.selectedAddress = context.baseAddress;
    context.length = 4;
    page.setContext(context);
    page.startDecompilation();
    context.baseAddress = provider.base;
    context.length = provider.bytes.size();
    context.selectedAddress = provider.base + provider.bytes.size();
    page.setContext(context);
    page.startDecompilation();
    require(starts == beforeBounds && requested == 1, "C analysis rejects overflowing ranges and the exclusive end address");
    context.selectedAddress = provider.base;
    context.maximumWindowBytes = 8;
    provider.bytes.resize(32, 0xcc);
    provider.mask.resize(32, 1);
    context.length = provider.bytes.size();
    provider.maximumFetchBytes = 8;
    provider.largestRequest = 0;
    page.setContext(context);
    page.startDecompilation();
    DrainBackend(page);
    require(starts == beforeBounds + 1 && provider.largestRequest <= 8,
        "C per-fetch capacity limits a copy without rejecting a valid function");

    // A real control-flow edge reaches code beyond 64 KiB; unrelated middle
    // pages must not enter the frozen input or invalidate its result.
    provider.maximumFetchBytes = 65536;
    provider.largestRequest = 0;
    provider.bytes.assign(2 * 65536 + 6, 0xcc);
    provider.bytes[0] = 0xe9;
    qToLittleEndian<qint32>(2 * 65536 - 5, provider.bytes.data() + 1);
    const std::vector<std::uint8_t> tail{0xb8, 0x2a, 0, 0, 0, 0xc3};
    std::copy(tail.begin(), tail.end(), provider.bytes.begin() + 2 * 65536);
    provider.mask.assign(provider.bytes.size(), 1);
    context.length = provider.bytes.size();
    context.maximumWindowBytes = 0;
    page.setContext(context);
    page.startDecompilation();
    DrainBackend(page);
    emit page.decompiler()->finished(result);
    require(starts == beforeBounds + 2 && provider.largestRequest <= 65536
        && page.editor()->toPlainText() == result.code,
        "C RAW analysis reaches a real far branch within the provider per-fetch capacity");
    provider.bytes[65536] ^= 1;
    page.refreshView();
    require(page.editor()->toPlainText() == result.code,
        "C unrelated uncaptured middle-page changes do not invalidate the sparse input");
    provider.bytes.back() ^= 1;
    page.refreshView();
    require(page.editor()->toPlainText().isEmpty(), "C result verification includes edits in the last snapshot chunk");
    provider.bytes = {0xb8, 0x2a, 0, 0, 0, 0xc3};
    provider.mask.assign(provider.bytes.size(), 1);
    context.length = provider.bytes.size();

    CheckRawPlanningContracts(require);

    // 文件偏移与 VA 单义映射；零填充、虚拟尾部和重叠节都没有可定位的文件字节。
    auto image = std::make_shared<std::vector<std::uint8_t>>(0x100, 0x90);
    FileAnalysisRegion region;
    region.fileOffset = 0x20;
    region.fileSize = 0x20;
    region.rva = 0x1000;
    region.virtualSize = 0x80;
    page.setFileAnalysisContext(image, 0x180000000ULL, {region});
    require(page.fileOffsetToVirtualAddress(0x25) == 0x180001005ULL
        && page.virtualAddressToFileOffset(0x180001005ULL) == 0x25,
        "C PE mapping keeps 64-bit image VAs distinct from source file offsets");
    require(!page.fileOffsetToVirtualAddress(0x45) && !page.virtualAddressToFileOffset(0x180001025ULL),
        "C PE mapping excludes file gaps and the virtual-only section tail");
    page.setFileAnalysisContext(image, 0x180000000ULL, {region, region});
    require(!page.fileOffsetToVirtualAddress(0x25) && !page.virtualAddressToFileOffset(0x180001005ULL),
        "C PE mapping rejects ambiguous overlapping sections");
    region.rva = UINT64_MAX;
    page.setFileAnalysisContext(image, UINT64_MAX - 1, {region});
    require(!page.fileOffsetToVirtualAddress(0x25), "C PE mapping rejects invalid or overflowing RVAs");
    page.openFindPanel();
    require(page.findChild<QWidget*>(QStringLiteral("code_editor_find_panel")) != nullptr,
        "C view reuses the project editor find UI");

    // 活动进度使用真实 C 页状态机；阶段、无效单位、结束后迟到通知都不可伪造结果。
    WorkbenchPseudocodeView progressPage;
    context.baseAddress = provider.base;
    context.selectedAddress = provider.base;
    context.addressBits = 64;
    context.addressKind = SnapshotAddressKind::MemoryAddress;
    context.maximumWindowBytes = 0;
    progressPage.setBytesProvider(&provider);
    progressPage.setContext(context);
    progressPage.findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"))->setText(
        QDir::current().filePath(QStringLiteral(".codex-build-logs/not-a-ghidra-runtime")));
    auto* phaseBar = progressPage.findChild<QProgressBar*>(QStringLiteral("memory_pseudocode_progress"));
    auto* phaseLabel = progressPage.findChild<QLabel*>(QStringLiteral("memory_pseudocode_progress_label"));
    bool checkedPhases = false;
    QObject::connect(progressPage.decompiler(), &GhidraDecompiler::runningChanged, &progressPage, [&](bool running) {
    if (!running || checkedPhases) return;
    checkedPhases = true; // The queued RAW planner has now produced a genuine backend ticket.
    emit progressPage.decompiler()->progressChanged({DecompilerStage::Analyzing, -1, -1});
    const QString analyzing = phaseLabel ? phaseLabel->text() : QString();
    require(phaseBar && !phaseBar->isHidden() && phaseBar->maximum() == 0,
        "C runtime analysis remains indeterminate when no genuine total exists");
    emit progressPage.decompiler()->progressChanged({DecompilerStage::Rendering, 9, 4});
    require(phaseLabel && phaseLabel->text() == analyzing,
        "C invalid progress units cannot advance a phase or fabricate completion");
    emit progressPage.decompiler()->progressChanged({DecompilerStage::Rendering, 2, 4});
    require(phaseBar && phaseBar->maximum() == 4 && phaseBar->value() == 2,
        "C rendering shows its real completed line count");
    const QString rendering = phaseLabel ? phaseLabel->text() : QString();
    emit progressPage.decompiler()->progressChanged({DecompilerStage::Analyzing, -1, -1});
    emit progressPage.decompiler()->progressChanged({DecompilerStage::Rendering, 1, 4});
    require(phaseLabel && phaseLabel->text() == rendering && phaseBar->value() == 2,
        "C delayed progress cannot move backwards within or between phases");
    progressPage.findChild<QPushButton*>(QStringLiteral("memory_decompile_cancel"))->click();
    emit progressPage.decompiler()->progressChanged({DecompilerStage::Rendering, 4, 4});
    require(phaseBar && phaseBar->isHidden(), "C cancellation ignores late progress and stops the activity");
    });
    progressPage.startDecompilation();
    require(WaitFor([&]() { return checkedPhases; }), "C queued RAW planning reaches the real backend phase observer");
    DrainBackend(progressPage);

    // 外部进度观察者关闭宿主后，不应留下耗时定时器或让后端继续写入旧页面。
    QPointer<WorkbenchPseudocodeView> closeOnProgress = new WorkbenchPseudocodeView;
    closeOnProgress->setBytesProvider(&provider);
    closeOnProgress->setContext(context);
    closeOnProgress->findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"))->setText(
        QDir::current().filePath(QStringLiteral(".codex-build-logs/not-a-ghidra-runtime")));
    QObject::connect(closeOnProgress->decompiler(), &GhidraDecompiler::progressChanged, qApp,
        [closeOnProgress](const DecompilerProgress&) { delete closeOnProgress.data(); });
    closeOnProgress->startDecompilation();
    require(WaitFor([&]() { return closeOnProgress.isNull(); }),
        "C page may close when the queued real backend launch publishes progress");

    // 等待读页回调可以关闭页面；refreshView 必须在回调返回后停止访问销毁对象。
    provider.mask[5] = 2;
    QPointer<WorkbenchPseudocodeView> retiring = new WorkbenchPseudocodeView;
    context.maximumWindowBytes = 0;
    retiring->setBytesProvider(&provider);
    retiring->setContext(context);
    QObject::connect(retiring, &WorkbenchPseudocodeView::windowRequested, qApp,
        [retiring](quint64, quint64) { delete retiring.data(); });
    retiring->startDecompilation();
    require(WaitFor([&]() { return retiring.isNull(); }), "C page permits its host to close it from the queued pending-window callback");

    RunWorkbenchPseudocodeProgressReentryTests(require);
}

// RunWorkbenchPseudocodeProgressReentryTests：实际 Qt 事件/信号的独立探针。
// caseName 为空执行全部；独立 runner 可逐进程运行单个销毁探针定位原生崩溃。
void RunWorkbenchPseudocodeProgressReentryTests(
    const std::function<void(bool, const char*)>& require, const QString& caseName)
{
    using namespace ks::ui;
    MaskedProvider provider; // 合成字节；任何测试都不接触进程、驱动或剪贴板。
    WorkbenchPseudocodeContext context;
    context.sourceIdentity = QStringLiteral("synthetic-progress-reentry-source");
    context.revision = 1;
    context.baseAddress = provider.base;
    context.selectedAddress = provider.base;
    context.length = provider.bytes.size();
    const auto selected = [&caseName](const char* name) {
        return caseName.isEmpty() || caseName == QString::fromLatin1(name);
    };

    // Show 回调改变来源但不销毁页面：旧 beginProgress 不可重新显示活动条。
    if (selected("show-context"))
    {
        provider.mask[5] = 2;
        WorkbenchPseudocodeView page;
        PrepareProgressPage(page, provider, context);
        auto* bar = page.findChild<QProgressBar*>(QStringLiteral("memory_pseudocode_progress"));
        auto* label = page.findChild<QLabel*>(QStringLiteral("memory_pseudocode_progress_label"));
        unsigned requests = 0; // 换源后的旧请求也不能重新发起读取。
        QObject::connect(&page, &WorkbenchPseudocodeView::windowRequested, &page,
            [&](quint64, quint64) { ++requests; });
        ProgressEventProbe probe(QEvent::Show, [&]() {
            auto changed = context;
            ++changed.revision;
            page.setContext(changed);
        });
        label->installEventFilter(&probe);
        page.startDecompilation();
        require(WaitFor([&]() { return probe.calls() == 1; }) && bar->isHidden() && label->isHidden() && requests == 0,
            "C progress Show source change cannot revive old activity or an old byte request");
    }

    // Show 回调直接销毁页面：显示 setter 返回后的真实事件仍允许该生命周期动作。
    if (selected("show-delete"))
    {
        provider.mask[5] = 2;
        QPointer<WorkbenchPseudocodeView> page = new WorkbenchPseudocodeView;
        PrepareProgressPage(*page, provider, context);
        auto* label = page->findChild<QLabel*>(QStringLiteral("memory_pseudocode_progress_label"));
        ProgressEventProbe probe(QEvent::Show, [page]() { delete page.data(); });
        label->installEventFilter(&probe);
        page->startDecompilation();
        require(WaitFor([&]() { return probe.calls() == 1; }) && page.isNull(),
            "C progress Show observer may destroy the page after its native visibility update returns");
    }

    // Hide 回调销毁整个页面：取消必须在原生 hide 返回后停止访问该页面。
    if (selected("hide-delete"))
    {
        provider.mask[5] = 2;
        QPointer<WorkbenchPseudocodeView> page = new WorkbenchPseudocodeView;
        PrepareProgressPage(*page, provider, context);
        page->startDecompilation();
        auto* bar = page->findChild<QProgressBar*>(QStringLiteral("memory_pseudocode_progress"));
        ProgressEventProbe probe(QEvent::Hide, [page]() { delete page.data(); });
        bar->installEventFilter(&probe);
        page->findChild<QPushButton*>(QStringLiteral("memory_decompile_cancel"))->click();
        require(probe.calls() == 1 && page.isNull(),
            "C waiting cancellation may destroy the page from its real progress Hide event");
    }

    // Hide 回调换源并开始新请求：旧取消不能隐藏新标签或覆盖新请求的状态。
    if (selected("hide-new-request"))
    {
        provider.mask[5] = 2;
        WorkbenchPseudocodeView page;
        PrepareProgressPage(page, provider, context);
        unsigned requests = 0; // 新旧各只有一个宿主读取请求。
        QObject::connect(&page, &WorkbenchPseudocodeView::windowRequested, &page,
            [&](quint64, quint64) { ++requests; });
        page.startDecompilation();
        require(WaitFor([&]() { return requests == 1; }), "C original queued read is pending before Hide reentry");
        auto* bar = page.findChild<QProgressBar*>(QStringLiteral("memory_pseudocode_progress"));
        auto* label = page.findChild<QLabel*>(QStringLiteral("memory_pseudocode_progress_label"));
        ProgressEventProbe probe(QEvent::Hide, [&]() {
            auto changed = context;
            ++changed.revision;
            page.setContext(changed);
            page.startDecompilation();
        });
        bar->installEventFilter(&probe);
        page.findChild<QPushButton*>(QStringLiteral("memory_decompile_cancel"))->click();
        const auto* status = page.findChild<QLabel*>(QStringLiteral("memory_pseudocode_status"));
        require(WaitFor([&]() { return requests == 2; }) && probe.calls() == 1 && !bar->isHidden() && !label->isHidden()
            && status && !status->text().isEmpty(),
            "C progress Hide reentry retains the newer pending request and its visible progress label");
    }

    // Qt valueChanged 回调销毁页面；探针针对原生控件调用栈，而非私有方法模拟。
    if (selected("value-delete"))
    {
        provider.mask[5] = 1;
        QPointer<WorkbenchPseudocodeView> page = new WorkbenchPseudocodeView;
        PrepareProgressPage(*page, provider, context);
        auto* bar = page->findChild<QProgressBar*>(QStringLiteral("memory_pseudocode_progress"));
        unsigned calls = 0; // 确认真实有界进度信号已派发。
        QObject::connect(bar, &QProgressBar::valueChanged, qApp, [&, page](int value) {
            if (value != 2) return;
            ++calls;
            delete page.data();
        });
        QObject::connect(page->decompiler(), &GhidraDecompiler::runningChanged, qApp, [page](bool running) {
            if (running && page) emit page->decompiler()->progressChanged({DecompilerStage::Rendering, 2, 4});
        });
        page->startDecompilation();
        require(WaitFor([&]() { return calls == 1; }) && page.isNull(),
            "C real progress valueChanged may destroy the page without resuming its native update stack");
    }

    // valueChanged 改来源：旧刷新不可在新来源上继续绘制旧阶段或接收旧结果。
    if (selected("value-context"))
    {
        provider.mask[5] = 1;
        WorkbenchPseudocodeView page;
        PrepareProgressPage(page, provider, context);
        auto* bar = page.findChild<QProgressBar*>(QStringLiteral("memory_pseudocode_progress"));
        auto* label = page.findChild<QLabel*>(QStringLiteral("memory_pseudocode_progress_label"));
        unsigned calls = 0; // 一次实际 valueChanged 换源。
        QObject::connect(bar, &QProgressBar::valueChanged, &page, [&](int value) {
            if (value != 2) return;
            ++calls;
            auto changed = context;
            ++changed.revision;
            page.setContext(changed);
        });
        bool injected = false;
        QObject::connect(page.decompiler(), &GhidraDecompiler::runningChanged, &page, [&](bool running) {
            if (!running || injected) return;
            injected = true;
            emit page.decompiler()->progressChanged({DecompilerStage::Rendering, 2, 4});
            emit page.decompiler()->progressChanged({DecompilerStage::Rendering, 4, 4});
        });
        page.startDecompilation();
        require(WaitFor([&]() { return calls == 1; }) && bar->isHidden() && label->isHidden(),
            "C real progress valueChanged source change suppresses the old update and late phase");
        DrainBackend(page);
    }

    // 使用后端真实 running 状态；无效路径的 queued launch 仍未创建分析进程。
    if (selected("cancel-running"))
    {
        provider.mask[5] = 1;
        WorkbenchPseudocodeView page;
        PrepareProgressPage(page, provider, context);
        auto* bar = page.findChild<QProgressBar*>(QStringLiteral("memory_pseudocode_progress"));
        auto* label = page.findChild<QLabel*>(QStringLiteral("memory_pseudocode_progress_label"));
        bool canceledRunning = false;
        QObject::connect(page.decompiler(), &GhidraDecompiler::runningChanged, &page, [&](bool running) {
            if (!running || canceledRunning) return;
            canceledRunning = true;
            require(page.decompiler()->isRunning(), "C queued backend request is truly running before cancellation");
            page.findChild<QPushButton*>(QStringLiteral("memory_decompile_cancel"))->click();
            emit page.decompiler()->progressChanged({DecompilerStage::Rendering, 4, 4});
        });
        page.startDecompilation();
        require(WaitFor([&]() { return canceledRunning; }), "C cancellation observes the genuinely queued backend start");
        require(bar->isHidden() && label->isHidden(),
            "C cancellation immediately stops activity and rejects phases before asynchronous completion");
        DrainBackend(page);
        require(!page.decompiler()->isRunning() && bar->isHidden(),
            "C cancelled queued launch completes once without reviving its progress");
    }
}
