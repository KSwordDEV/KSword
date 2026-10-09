// ============================================================
// wpJ6_tests.Nav.cpp
// 作用：地址条"切换并跳转"（N4，不静默切换范围）；前进后退栈 64 项；
//       Wave 3 复核新增：身份变化后后退栈不留幽灵记录（修复缺陷 4）、右键
//       "写入/还原此处 int3"按状态二选一且结果可见（修复缺陷 2）。
// ============================================================

#include "wpJ6_common.h"

#include <QAction>
#include <QApplication>
#include <QMenu>
#include <QScrollBar>

#include <algorithm>
#include <cstdio>
#include <utility>

namespace wpj6_test
{
    namespace
    {
        // ScopedMappedRegion：让夹具复现真实模块的高地址映射；测试结束恢复共享端口，
        // 不访问目标进程。应先构造本对象、后构造 Harness，使异步读取先随 Harness 收尾。
        class ScopedMappedRegion final
        {
        public:
            explicit ScopedMappedRegion(std::uint64_t regionBase)
                : backing_(ConfigureSharedOnce().backing)
            {
                std::lock_guard<std::mutex> guard(backing_->mutex);
                oldBase_ = backing_->base;
                oldBytes_ = std::move(backing_->bytes);
                backing_->base = regionBase;
                backing_->bytes.assign(32U * 4096U, 0x90U);
                // 首字节与后续填充区别开，核对选中地址没有偏移到最后一行附近。
                backing_->bytes.front() = 0x4DU;
            }

            ~ScopedMappedRegion()
            {
                std::lock_guard<std::mutex> guard(backing_->mutex);
                backing_->base = oldBase_;
                backing_->bytes = std::move(oldBytes_);
            }

        private:
            std::shared_ptr<FakeMemoryBacking> backing_; // 正式注入的假端口后备存储。
            std::uint64_t oldBase_ = 0;                  // 其余测试原有的起点。
            std::vector<std::uint8_t> oldBytes_;        // 其余测试原有的字节。
        };
    }

    // TestOpenMappedRegionStartsAtFirstVisibleRow：完整装配复现“前面问号、地址在末行”。
    // 初次打开、已显示后另开区域，以及文本/C 页往返均保留显式打开的首行。
    void TestOpenMappedRegionStartsAtFirstVisibleRow()
    {
        constexpr std::uint64_t mappedBase = 0x00007FFE6E5B0000ULL;
        ScopedMappedRegion mappedRegion(mappedBase);
        Harness harness;
        harness.AttachProcess();
        harness.view->resize(1100, 650);
        harness.view->show();
        PumpFor(30);

        auto* const pane = harness.view->hexPaneForTest();
        auto* const canvas = pane->canvas();
        ks::ui::NavRequest request;
        request.address = mappedBase;
        request.selectLength = 64;
        WPJ6_CHECK(harness.view->openAt(request) == ks::ui::NavStatus::Ok);
        WPJ6_CHECK(WaitForStageable(pane, mappedBase));
        WPJ6_CHECK(pane->insertionAddress() == mappedBase);
        WPJ6_CHECK(pane->selectionStart() == mappedBase);
        const auto selected = canvas->selectedRange();
        WPJ6_CHECK(selected && selected->last == mappedBase + 63ULL);
        const std::uint64_t expectedRow = mappedBase / static_cast<std::uint64_t>(canvas->bytesPerRow());
        WPJ6_CHECK_NOTE(canvas->firstVisibleRow() == expectedRow,
            QStringLiteral("模块起点应在首行，目标行=%1，实际首行=%2")
                .arg(expectedRow).arg(canvas->firstVisibleRow()));
        WPJ6_CHECK(canvas->cellStateAt(mappedBase).hasValue);
        WPJ6_CHECK(canvas->cellStateAt(mappedBase).value == 0x4DU);
        // 起点之前确实无映射；保持真实未知状态，不能以填零隐藏问号来让测试通过。
        WPJ6_CHECK(!canvas->cellStateAt(mappedBase - 1ULL).hasValue);

        auto* const pages = harness.view->subTabStackForTest();
        for (const int page : {2, 4})
        {
            pages->setCurrentIndex(page);
            PumpFor(30);
            pages->setCurrentIndex(0);
            PumpFor(30);
            WPJ6_CHECK(pane->insertionAddress() == mappedBase);
            WPJ6_CHECK(canvas->firstVisibleRow() == expectedRow);
        }

        // 同一目标的另一次显式打开也从所请求的地址开始，不继承旧视口的末行对齐。
        request.address = mappedBase + 0x10000ULL;
        WPJ6_CHECK(harness.view->openAt(request) == ks::ui::NavStatus::Ok);
        WPJ6_CHECK(WaitForStageable(pane, request.address));
        WPJ6_CHECK(canvas->firstVisibleRow() == request.address
            / static_cast<std::uint64_t>(canvas->bytesPerRow()));

        // 夹具也直接验证内部导航的原有居中参数：打开政策不会覆盖调用方明确对齐。
        const std::uint64_t contextAddress = request.address + 0x2000ULL;
        WPJ6_CHECK(canvas->scrollToAddress(contextAddress, ks::ui::HexCanvas::ScrollAlign::Center));
        WPJ6_CHECK(canvas->firstVisibleRow() < contextAddress
            / static_cast<std::uint64_t>(canvas->bytesPerRow()));
        const std::uint64_t contextFirstRow = canvas->firstVisibleRow();
        WPJ6_CHECK(pane->jumpTo(contextAddress));
        WPJ6_CHECK(canvas->firstVisibleRow() == contextFirstRow);

        // 懒加载 Dock 在显示之前就收到打开请求；布局/行宽重新计算不能把目标推下屏。
        Harness hiddenHarness;
        hiddenHarness.AttachProcess();
        request.address = mappedBase;
        WPJ6_CHECK(hiddenHarness.view->openAt(request) == ks::ui::NavStatus::Ok);
        hiddenHarness.view->resize(1000, 500);
        hiddenHarness.view->show();
        PumpFor(30);
        auto* const hiddenPane = hiddenHarness.view->hexPaneForTest();
        auto* const hiddenCanvas = hiddenPane->canvas();
        WPJ6_CHECK(WaitForStageable(hiddenPane, mappedBase));
        WPJ6_CHECK(hiddenCanvas->firstVisibleRow() == mappedBase
            / static_cast<std::uint64_t>(hiddenCanvas->bytesPerRow()));
        hiddenHarness.view->resize(900, 700);
        PumpFor(30);
        WPJ6_CHECK(hiddenCanvas->firstVisibleRow() == mappedBase
            / static_cast<std::uint64_t>(hiddenCanvas->bytesPerRow()));
    }

    // TestInitialModuleFollowReturnsHexAtTop：没有显式打开请求、恢复在子页再附加时，
    // 使用真正 WorkbenchTarget 模块枚举挑高地址主模块；回 HEX 仍以模块起点为首行。
    void TestInitialModuleFollowReturnsHexAtTop()
    {
        constexpr std::uint64_t mappedBase = 0x00007FFE6E5B0000ULL;
        ScopedMappedRegion mappedRegion(mappedBase);
        for (const int page : {1, 2, 4})
        {
            Harness harness;
            auto* const services = LastFakeServices();
            WPJ6_CHECK(services != nullptr);
            if (!services) return;
            ks::ui::ModuleEnumResult modules;
            modules.ok = true;
            ksword::memwb::ModuleRecord primary;
            primary.name = "main.exe";
            primary.fullPath = "C:\\fixture\\main.exe";
            primary.base = mappedBase;
            primary.size = 32U * 4096U;
            modules.records.push_back(primary);
            services->SetProcessModulesResult(4242, modules);

            // 子页先于附加恢复，覆盖模块目录异步就绪后的初始定位，不触发反编译。
            harness.view->resize(1000, 600);
            harness.view->show();
            auto* const pages = harness.view->subTabStackForTest();
            pages->setCurrentIndex(page);
            harness.AttachProcess();
            auto* const pane = harness.view->hexPaneForTest();
            WPJ6_CHECK(PumpUntil([&]() { return pane->insertionAddress() == mappedBase; }, 2000));
            pages->setCurrentIndex(0);
            WPJ6_CHECK(WaitForStageable(pane, mappedBase));
            auto* const canvas = pane->canvas();
            WPJ6_CHECK(canvas->firstVisibleRow() == mappedBase
                / static_cast<std::uint64_t>(canvas->bytesPerRow()));
            WPJ6_CHECK(canvas->cellStateAt(mappedBase).value == 0x4DU);
        }
    }

    // TestExplicitOpenRevealsHorizontalCell：固定 64 字节行、窄窗且用户已横滚，
    // 显式打开起点仍需在两轴可见；纵向首行政策不能丢掉旧键盘路径的横向补偿。
    void TestExplicitOpenRevealsHorizontalCell()
    {
        Harness harness;
        harness.AttachProcess();
        harness.view->resize(430, 540);
        harness.view->show();
        PumpFor(30);
        auto* const pane = harness.view->hexPaneForTest();
        auto* const canvas = pane->canvas();
        canvas->setAutoBytesPerRow(false);
        WPJ6_CHECK(canvas->setBytesPerRow(64));
        PumpFor(30);
        WPJ6_CHECK(canvas->horizontalScrollBar()->maximum() > 0);
        canvas->horizontalScrollBar()->setValue(canvas->horizontalScrollBar()->maximum());

        ks::ui::NavRequest request;
        request.address = 0x4000ULL;
        WPJ6_CHECK(harness.view->openAt(request) == ks::ui::NavStatus::Ok);
        const QRect firstCell = canvas->cellRect(request.address, ks::ui::HexCanvas::ActivePane::Hex);
        WPJ6_CHECK(firstCell.left() >= 0 && firstCell.right() < canvas->viewport()->width());
        WPJ6_CHECK(canvas->firstVisibleRow() == request.address / 64ULL);

        // 右侧列起点同样必须可见，不能简单把横滚条总归零来“修好”首列。
        canvas->horizontalScrollBar()->setValue(0);
        request.address += 48ULL;
        WPJ6_CHECK(harness.view->openAt(request) == ks::ui::NavStatus::Ok);
        const QRect lastCell = canvas->cellRect(request.address, ks::ui::HexCanvas::ActivePane::Hex);
        WPJ6_CHECK(lastCell.left() >= 0 && lastCell.right() < canvas->viewport()->width());
        WPJ6_CHECK(canvas->firstVisibleRow() == request.address / 64ULL);
    }

    // TestPureScrollSurvivesBrowseRoundTrip：只滚动、没有移动 caret，子页返回不能
    // 用老 caret 把真实浏览位置抢回；显式跨页定位仍由 jumpTo 负责。
    void TestPureScrollSurvivesBrowseRoundTrip()
    {
        Harness harness;
        harness.AttachProcess();
        harness.view->resize(1000, 600);
        harness.view->show();
        PumpFor(30);
        auto* const pane = harness.view->hexPaneForTest();
        auto* const canvas = pane->canvas();
        ks::ui::NavRequest request;
        request.address = 0x1000ULL;
        WPJ6_CHECK(harness.view->openAt(request) == ks::ui::NavStatus::Ok);
        WPJ6_CHECK(WaitForStageable(pane, request.address));

        auto* const pages = harness.view->subTabStackForTest();
        for (const int page : {2, 4})
        {
            canvas->setFirstVisibleRow(canvas->firstVisibleRow() + 200ULL);
            const std::uint64_t scrolledRow = canvas->firstVisibleRow();
            const std::uint64_t caretBefore = canvas->caretAddress();
            WPJ6_CHECK(scrolledRow > caretBefore / static_cast<std::uint64_t>(canvas->bytesPerRow()));
            pages->setCurrentIndex(page);
            PumpFor(50);
            pages->setCurrentIndex(0);
            PumpFor(30);
            WPJ6_CHECK(canvas->caretAddress() == caretBefore);
            WPJ6_CHECK_NOTE(canvas->firstVisibleRow() == scrolledRow,
                QStringLiteral("仅滚动后切页往返须保留首行 %1，实际 %2")
                    .arg(scrolledRow).arg(canvas->firstVisibleRow()));
        }
    }

    // TestSelectionSignalCanDestroyPane：真实 QObject 同步通知中删除 pane，验证
    // 画布内部及上层 jumpTo 原调用栈都停下，不能继续向已析构对象发 caretMoved。
    void TestSelectionSignalCanDestroyPane()
    {
        std::printf("HEX_SELECTION_DELETE_PROBE_BEGIN\n");
        std::fflush(stdout);
        auto pane = std::make_unique<ks::ui::WorkbenchHexPane>();
        pane->setAddressSpace(0, 0xFFFFULL, "selection-delete-fixture");
        auto* const canvas = pane->canvas();
        const QPointer<ks::ui::WorkbenchHexPane> paneAlive(pane.get());
        const QPointer<ks::ui::HexCanvas> canvasAlive(canvas);
        QObject::connect(canvas, &ks::ui::HexCanvas::selectionChanged, qApp,
            [&pane](bool, quint64, quint64) { pane.reset(); });
        auto* const rawPane = pane.get();
        const bool jumped = rawPane->jumpTo(0x4000ULL, 64, ks::ui::HexCanvas::ScrollAlign::Top);
        WPJ6_CHECK(!jumped);
        WPJ6_CHECK(!paneAlive && !canvasAlive);
        WPJ6_CHECK(!pane);
    }

    // TestSpaceNotificationCanDestroyPane：安装/清空地址空间的通知同样允许删页面；
    // 内层停止后，安装空间或容器的外层原调用栈也必须停止。
    void TestSpaceNotificationCanDestroyPane(const QString& mode)
    {
        std::printf("HEX_SPACE_DELETE_PROBE_BEGIN\n");
        std::fflush(stdout);
        auto pane = std::make_unique<ks::ui::WorkbenchHexPane>();
        pane->setAddressSpace(0, 0xFFFFULL, "space-delete-original");
        // 排空初始内容通知，避免旧实现碰到已释放的“已排队=true”后恰好短路，
        // 掩盖外层安装/清空栈继续访问已析构 QObject 的问题。
        PumpFor(10);
        auto* const canvas = pane->canvas();
        const QPointer<ks::ui::WorkbenchHexPane> paneAlive(pane.get());
        if (mode == QStringLiteral("--hex-review-space-visible-delete"))
            QObject::connect(canvas, &ks::ui::HexCanvas::visibleRangeChanged, qApp,
                [&pane](quint64, quint64) { pane.reset(); });
        else
            QObject::connect(canvas, &ks::ui::HexCanvas::selectionChanged, qApp,
                [&pane](bool, quint64, quint64) { pane.reset(); });

        auto* const rawPane = pane.get();
        if (mode == QStringLiteral("--hex-review-space-clear-delete")) rawPane->clearAddressSpace();
        else rawPane->setAddressSpace(0x1000ULL, 0xFFFFULL, "space-delete-replacement");
        WPJ6_CHECK(!paneAlive);
        WPJ6_CHECK(!pane);
    }

    // TestSourceReplacementStopsOldJump：对象仍活着的清空/同地址换源不能绕过保护，
    // 后到的新目标保留自己的起点，旧 caret 通知和旧导航后半程都作废。
    void TestSourceReplacementStopsOldJump(bool clearSource)
    {
        ks::ui::WorkbenchHexPane pane;
        pane.setAddressSpace(0, 0xFFFFULL, "source-reentry-original");
        auto* const canvas = pane.canvas();
        const std::uint64_t originalRevision = canvas->sourceRevision();
        bool replaced = false;
        std::vector<quint64> reportedCarets;
        QObject::connect(canvas, &ks::ui::HexCanvas::caretMoved, qApp,
            [&reportedCarets](quint64 address) { reportedCarets.push_back(address); });
        QObject::connect(canvas, &ks::ui::HexCanvas::selectionChanged, qApp,
            [&pane, &replaced, clearSource](bool, quint64, quint64) {
                if (replaced) return;
                replaced = true;
                if (clearSource) pane.clearAddressSpace();
                else pane.setAddressSpace(0, 0xFFFFULL, "source-reentry-replacement");
            });
        const bool jumped = pane.jumpTo(0x4000ULL, 64, ks::ui::HexCanvas::ScrollAlign::Top);
        WPJ6_CHECK(replaced && canvas->sourceRevision() != originalRevision);
        WPJ6_CHECK(!jumped);
        WPJ6_CHECK(pane.insertionAddress() == 0);
        WPJ6_CHECK(std::none_of(reportedCarets.begin(), reportedCarets.end(),
            [](quint64 address) { return address == 0x4000ULL || address == 0x403FULL; }));
        WPJ6_CHECK(canvas->addressSpaceRange().has_value() != clearSource);
    }

    // TestReentrantNavigationWins：选区通知同步发起新导航，新导航拥有最终选区/视口，
    // 旧请求不能恢复执行；来源相同也需检查导航代次。
    void TestReentrantNavigationWins(bool sameEndpoint = false)
    {
        ks::ui::WorkbenchHexPane pane;
        pane.setAddressSpace(0, 0xFFFFULL, "navigation-reentry");
        auto* const canvas = pane.canvas();
        bool navigated = false;
        bool innerAccepted = false;
        const std::uint64_t innerAddress = sameEndpoint ? 0x403FULL : 0x8000ULL;
        const std::uint64_t innerLength = sameEndpoint ? 1ULL : 8ULL;
        std::vector<quint64> reportedCarets;
        QObject::connect(canvas, &ks::ui::HexCanvas::caretMoved, qApp,
            [&reportedCarets](quint64 address) { reportedCarets.push_back(address); });
        QObject::connect(canvas, &ks::ui::HexCanvas::selectionChanged, qApp,
            [&pane, &navigated, &innerAccepted, innerAddress, innerLength](bool, quint64, quint64) {
                if (navigated) return;
                navigated = true;
                innerAccepted = pane.jumpTo(innerAddress, innerLength, ks::ui::HexCanvas::ScrollAlign::Top);
            });
        const bool jumped = pane.jumpTo(0x4000ULL, 64, ks::ui::HexCanvas::ScrollAlign::Top);
        WPJ6_CHECK(navigated && innerAccepted);
        WPJ6_CHECK(!jumped);
        WPJ6_CHECK(pane.insertionAddress() == innerAddress);
        const auto selected = canvas->selectedRange();
        WPJ6_CHECK(selected && selected->first == innerAddress && selected->last == innerAddress + innerLength - 1ULL);
        WPJ6_CHECK(std::none_of(reportedCarets.begin(), reportedCarets.end(),
            [sameEndpoint](quint64 address) { return address == 0x4000ULL || (!sameEndpoint && address == 0x403FULL); }));
    }

    // TestNavigationDuringSpaceInstallKeepsNewIdentity：空间票据和导航票据分开，
    // 新空间通知中发起的导航保留其选区，而安装外层仍为同一新源完成身份/基线设置。
    void TestNavigationDuringSpaceInstallKeepsNewIdentity()
    {
        ks::ui::WorkbenchHexPane pane;
        pane.setAddressSpace(0, 0xFFFFULL, "install-original");
        auto* const canvas = pane.canvas();
        bool navigated = false;
        bool accepted = false;
        QObject::connect(canvas, &ks::ui::HexCanvas::selectionChanged, qApp,
            [&pane, &navigated, &accepted](bool, quint64, quint64) {
                if (navigated) return;
                navigated = true;
                accepted = pane.jumpTo(0x9000ULL, 8, ks::ui::HexCanvas::ScrollAlign::Top);
            });
        pane.setAddressSpace(0x1000ULL, 0xFFFFULL, "install-replacement");
        WPJ6_CHECK(navigated && accepted);
        WPJ6_CHECK(pane.insertionAddress() == 0x9000ULL);
        WPJ6_CHECK(pane.overlay().IdentityKey() == "install-replacement");
        const auto selected = canvas->selectedRange();
        WPJ6_CHECK(selected && selected->first == 0x9000ULL && selected->last == 0x9007ULL);
    }

    // TestAutoFitNotificationCanDestroyPane：寻找真实宽视口的地址位数临界点，
    // 由高位空间安装触发 auto-fit 内层重排，再在真实可见范围通知中删除页面。
    void TestAutoFitNotificationCanDestroyPane()
    {
        constexpr std::uint64_t highBase = 0xFFFF800000001000ULL;
        auto pane = std::make_unique<ks::ui::WorkbenchHexPane>();
        pane->setAddressSpace(0, 0xFFFFULL, "autofit-delete-low");
        pane->show();
        auto* const canvas = pane->canvas();
        canvas->setAutoBytesPerRow(true);
        bool found = false;
        int lowRows = 0;
        for (int width = 450; width <= 2000; width += 8)
        {
            pane->resize(width, 500);
            PumpFor(1);
            pane->setAddressSpace(0, 0xFFFFULL, "autofit-delete-low");
            lowRows = canvas->bytesPerRow();
            pane->setAddressSpace(highBase, highBase + 0xFFFFULL, "autofit-delete-high");
            if (lowRows >= 32 && lowRows != canvas->bytesPerRow())
            {
                found = true;
                break;
            }
        }
        WPJ6_CHECK(found);
        if (!found) return;
        pane->setAddressSpace(0, 0xFFFFULL, "autofit-delete-low");
        PumpFor(10);
        const QPointer<ks::ui::WorkbenchHexPane> alive(pane.get());
        QObject::connect(canvas, &ks::ui::HexCanvas::visibleRangeChanged, qApp,
            [&pane](quint64, quint64) { pane.reset(); });
        std::printf("HEX_AUTOFIT_DELETE_PROBE_BEGIN lowWidth=%d\n", lowRows);
        std::fflush(stdout);
        pane->setAddressSpace(highBase, highBase + 0xFFFFULL, "autofit-delete-final");
        WPJ6_CHECK(!alive && !pane);
    }

    // 自动重排通知换源后，新来源必须按自己的地址位数选档，且重排锁能继续工作。
    void TestAutoFitSourceReplacementReflows()
    {
        constexpr std::uint64_t highBase = 0xFFFF800000001000ULL;
        ks::ui::WorkbenchHexPane pane;
        pane.setAddressSpace(0, 0xFFFFULL, "autofit-replace-low");
        pane.show();
        auto* const canvas = pane.canvas();
        canvas->setAutoBytesPerRow(true);
        bool found = false;
        int lowRows = 0;
        int highRows = 0;
        // 寻找真实几何边界，不硬编码系统字体或滚动条宽度。
        for (int width = 450; width <= 2000; width += 8)
        {
            pane.resize(width, 500);
            PumpFor(1);
            pane.setAddressSpace(0, 0xFFFFULL, "autofit-replace-low");
            lowRows = canvas->bytesPerRow();
            pane.setAddressSpace(highBase, highBase + 0xFFFFULL, "autofit-replace-high");
            highRows = canvas->bytesPerRow();
            if (lowRows >= 32 && lowRows != highRows)
            {
                found = true;
                break;
            }
        }
        WPJ6_CHECK(found);
        if (!found) return;
        pane.setAddressSpace(0, 0xFFFFULL, "autofit-replace-low");
        PumpFor(10);
        bool replaced = false; // 回调只换一次来源，不能以无限重入掩盖界面收尾。
        QObject::connect(canvas, &ks::ui::HexCanvas::visibleRangeChanged, &pane,
            [&](quint64 first, quint64) {
                if (replaced || first < highBase || canvas->bytesPerRow() != highRows) return;
                replaced = true;
                pane.setAddressSpace(0, 0xFFFFULL, "autofit-replace-new-low");
            });
        pane.setAddressSpace(highBase, highBase + 0xFFFFULL, "autofit-replace-trigger");
        PumpFor(20);
        WPJ6_CHECK(replaced);
        const auto bounds = canvas->addressSpaceRange();
        WPJ6_CHECK(bounds && bounds->first == 0);
        WPJ6_CHECK(canvas->isAutoBytesPerRow() && canvas->bytesPerRow() == lowRows);
        pane.setAddressSpace(highBase, highBase + 0xFFFFULL, "autofit-replace-next-high");
        WPJ6_CHECK(canvas->bytesPerRow() == highRows);
    }

    // TestNativeBarRangeCanDestroyPane：原生 setRange 的信号里删页面，必须等原生
    // setter 返回后再派发实际改变，避免 native/private 及上层原调用栈继续访问。
    void TestNativeBarRangeCanDestroyPane(bool horizontal)
    {
        auto pane = std::make_unique<ks::ui::WorkbenchHexPane>();
        pane->setAddressSpace(0, 0xFFFULL, "bar-delete-original");
        pane->resize(450, 500);
        pane->show();
        PumpFor(10);
        auto* const canvas = pane->canvas();
        canvas->setAutoBytesPerRow(false);
        WPJ6_CHECK(canvas->setBytesPerRow(16));
        auto* const bar = horizontal ? canvas->horizontalScrollBar() : canvas->verticalScrollBar();
        const QPointer<ks::ui::WorkbenchHexPane> alive(pane.get());
        QObject::connect(bar, &QScrollBar::rangeChanged, qApp,
            [&pane](int, int) { pane.reset(); });
        std::printf("HEX_NATIVE_BAR_DELETE_PROBE_BEGIN horizontal=%d\n", int(horizontal));
        std::fflush(stdout);
        if (horizontal) canvas->setBytesPerRow(64);
        else pane->setAddressSpace(0, 0xFFFFULL, "bar-delete-replacement");
        WPJ6_CHECK(!alive && !pane);
    }

    // 独立模式在负对照时逐个启动，销毁探针即使崩溃也不吞掉其他定位证据。
    void RunHexViewportReviewTests(const QString& mode)
    {
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-horizontal"))
            TestExplicitOpenRevealsHorizontalCell();
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-browse"))
            TestPureScrollSurvivesBrowseRoundTrip();
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-delete"))
            TestSelectionSignalCanDestroyPane();
        for (const QString& deletion : {QStringLiteral("--hex-review-space-delete"),
            QStringLiteral("--hex-review-space-visible-delete"), QStringLiteral("--hex-review-space-clear-delete")})
            if (mode.isEmpty() || mode == deletion) TestSpaceNotificationCanDestroyPane(deletion);
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-source-clear"))
            TestSourceReplacementStopsOldJump(true);
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-source-replace"))
            TestSourceReplacementStopsOldJump(false);
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-reentrant-nav"))
            TestReentrantNavigationWins();
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-reentrant-same-position"))
            TestReentrantNavigationWins(true);
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-install-navigation"))
            TestNavigationDuringSpaceInstallKeepsNewIdentity();
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-autofit-delete"))
            TestAutoFitNotificationCanDestroyPane();
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-autofit-replace"))
            TestAutoFitSourceReplacementReflows();
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-bar-vertical-delete"))
            TestNativeBarRangeCanDestroyPane(false);
        if (mode.isEmpty() || mode == QStringLiteral("--hex-review-bar-horizontal-delete"))
            TestNativeBarRangeCanDestroyPane(true);
    }

    // TestNeedsScopeSwitchShowsRerouteButtonAndJumpsOnClick：进程范围下跳转到
    // 内核半区地址应返回 NeedsScopeSwitch、不静默切换范围，"切换并跳转"按钮
    // 出现；点击后才真正切换并跳转。
    void TestNeedsScopeSwitchShowsRerouteButtonAndJumpsOnClick()
    {
        Harness harness;
        harness.AttachProcess();
        PumpUntil([&]() { return true; }, 10);

        auto* reroute = harness.view->rerouteButtonForTest();
        WPJ6_CHECK(reroute != nullptr);
        if (reroute != nullptr)
        {
            WPJ6_CHECK(reroute->isHidden());
        }

        ks::ui::NavRequest request;
        request.scope = ksword::memwb::Scope::ProcessVirtual;
        request.address = 0xFFFFF78000001000ULL;
        const auto status = harness.view->openAt(request);
        WPJ6_CHECK(status == ks::ui::NavStatus::NeedsScopeSwitch);
        WPJ6_CHECK_NOTE(
            harness.view->target().session().scope == ksword::memwb::Scope::ProcessVirtual,
            QStringLiteral("NeedsScopeSwitch 不应静默切换范围"));
        WPJ6_CHECK(reroute != nullptr && !reroute->isHidden());

        if (reroute != nullptr)
        {
            emit reroute->clicked();
        }
        WPJ6_CHECK(harness.view->target().session().scope == ksword::memwb::Scope::KernelVirtual);
        WPJ6_CHECK(reroute != nullptr && reroute->isHidden());
    }

    // TestBackForwardStackCapAt64：连续跳转 70 次不同地址，后退栈容量应封顶
    // 在 64 项（最旧的被丢弃），后退到底之后再前进应该能回到最近跳转的位置。
    void TestBackForwardStackCapAt64()
    {
        Harness harness;
        harness.AttachProcess();
        PumpUntil([&]() { return true; }, 10);

        auto* pane = harness.view->hexPaneForTest();
        WPJ6_CHECK(WaitForStageable(pane, 0x10ULL));

        for (int i = 0; i < 70; ++i)
        {
            ks::ui::NavRequest request;
            request.scope = ksword::memwb::Scope::ProcessVirtual;
            request.address = 0x10ULL + static_cast<std::uint64_t>(i);
            const auto status = harness.view->openAt(request);
            WPJ6_CHECK(status == ks::ui::NavStatus::Ok);
        }
        WPJ6_CHECK_NOTE(
            harness.view->backStackForTest().size() == 64U,
            QStringLiteral("后退栈应封顶 64 项，实际 %1").arg(harness.view->backStackForTest().size()));

        // 点击后退按钮：当前地址（最后一次跳转的目标）应压入前进栈，插入点
        // 回到后退栈的最后一项。
        const std::uint64_t currentAddress = pane->insertionAddress();
        const std::uint64_t expectedBack = harness.view->backStackForTest().back();
        // 独立核对栈顶确实是"倒数第二次跳转的真实目标地址"（0x10+68），不能只
        // 拿 expectedBack 跟自己比——那样如果 pushBackStackEntry 把错误的值
        // （例如恒为 0）压进了栈，下面两处比较会拿同一个错误值互相对照，
        // 测不出问题。连续跳转的地址是已知的等差序列，这里用它独立算出
        // 应该存在栈顶的真值。
        WPJ6_CHECK_NOTE(
            expectedBack == currentAddress - 1ULL,
            QStringLiteral("后退栈顶应是上一次跳转的真实地址 0x%1，实际 0x%2")
                .arg(currentAddress - 1ULL, 0, 16)
                .arg(expectedBack, 0, 16));
        auto* backButton = harness.view->backButtonForTest();
        WPJ6_CHECK(backButton != nullptr);
        if (backButton != nullptr)
        {
            emit backButton->clicked();
        }
        WPJ6_CHECK(pane->insertionAddress() == expectedBack);
        WPJ6_CHECK_NOTE(
            !harness.view->forwardStackForTest().empty() &&
                harness.view->forwardStackForTest().back() == currentAddress,
            QStringLiteral("后退应把原地址压入前进栈"));

        // 再点前进：应该回到后退之前的地址。
        auto* forwardButton = harness.view->forwardButtonForTest();
        WPJ6_CHECK(forwardButton != nullptr);
        if (forwardButton != nullptr)
        {
            emit forwardButton->clicked();
        }
        WPJ6_CHECK(pane->insertionAddress() == currentAddress);
    }

    // TestForwardClickNoOpWhenStackEmpty / TestBackClickNoOpWhenStackEmpty：
    // 前进栈/后退栈为空时点对应按钮必须是安全的空操作——这是
    // onGoForwardRequested/onGoBackRequested 用 "||" 而不是 "&&" 组合"栈空
    // 或画布为空"两个早退条件这条不变式最常见的真实触发场景（刚附加、还
    // 没做过任何导航就点"前进"/"后退"）；如果误改成 "&&"，栈空但画布非空
    // 时会从空容器 back()/pop_back()，是未定义行为。TestBackForwardStackCapAt64
    // 只在两个栈都已经有内容之后点按钮，测不出"恰好只有一个栈为空"这个分支。
    void TestForwardClickNoOpWhenStackEmpty()
    {
        Harness harness;
        harness.AttachProcess();
        PumpUntil([&]() { return true; }, 10);

        auto* pane = harness.view->hexPaneForTest();
        WPJ6_CHECK(WaitForStageable(pane, 0x60ULL));
        pane->jumpTo(0x60ULL);

        WPJ6_CHECK(harness.view->forwardStackForTest().empty());
        const std::uint64_t before = pane->insertionAddress();

        auto* forwardButton = harness.view->forwardButtonForTest();
        WPJ6_CHECK(forwardButton != nullptr);
        if (forwardButton != nullptr)
        {
            emit forwardButton->clicked();
        }
        WPJ6_CHECK_NOTE(
            pane->insertionAddress() == before,
            QStringLiteral("前进栈为空时点前进不应改变当前位置"));
    }

    void TestBackClickNoOpWhenStackEmpty()
    {
        Harness harness;
        harness.AttachProcess();
        PumpUntil([&]() { return true; }, 10);

        auto* pane = harness.view->hexPaneForTest();
        WPJ6_CHECK(WaitForStageable(pane, 0x64ULL));
        pane->jumpTo(0x64ULL);

        WPJ6_CHECK(harness.view->backStackForTest().empty());
        const std::uint64_t before = pane->insertionAddress();

        auto* backButton = harness.view->backButtonForTest();
        WPJ6_CHECK(backButton != nullptr);
        if (backButton != nullptr)
        {
            emit backButton->clicked();
        }
        WPJ6_CHECK_NOTE(
            pane->insertionAddress() == before,
            QStringLiteral("后退栈为空时点后退不应改变当前位置"));
    }

    // TestIdentityChangeClearsBackStackWithoutGhost（修复缺陷 4，并入审核报告
    // wpJ6/wave3 的 P5 探针）：同目标内先攒几条后退栈记录，再触发一次身份
    // 变化类导航（"切换并跳转"到内核范围）；修复前的缺陷是 openAt 在
    // requestIdentity 之后才读 hexPane_->insertionAddress() 当"旧地址"压栈，
    // 读到的已经是身份变化重置后的新地址空间起点（幽灵地址），导致
    // handleIdentityChange 刚清空的栈又多出一条不属于新目标的记录。
    void TestIdentityChangeClearsBackStackWithoutGhost()
    {
        Harness harness;
        harness.AttachProcess();
        PumpUntil([&]() { return true; }, 10);

        WPJ6_CHECK(WaitForStageable(harness.view->hexPaneForTest(), 0x80ULL));

        ks::ui::NavRequest first;
        first.scope = ksword::memwb::Scope::ProcessVirtual;
        first.address = 0x80ULL;
        WPJ6_CHECK(harness.view->openAt(first) == ks::ui::NavStatus::Ok);

        ks::ui::NavRequest second;
        second.scope = ksword::memwb::Scope::ProcessVirtual;
        second.address = 0x90ULL;
        WPJ6_CHECK(harness.view->openAt(second) == ks::ui::NavStatus::Ok);
        WPJ6_CHECK_NOTE(
            !harness.view->backStackForTest().empty(),
            QStringLiteral("同目标内跳转后应有后退栈记录（后续身份变化要清空它）"));

        ks::ui::NavRequest kernelRequest;
        kernelRequest.scope = ksword::memwb::Scope::ProcessVirtual;
        kernelRequest.address = 0xFFFFF78000002000ULL;
        WPJ6_CHECK(harness.view->openAt(kernelRequest) == ks::ui::NavStatus::NeedsScopeSwitch);

        auto* reroute = harness.view->rerouteButtonForTest();
        WPJ6_CHECK(reroute != nullptr);
        if (reroute != nullptr)
        {
            emit reroute->clicked();
        }
        WPJ6_CHECK(harness.view->target().session().scope == ksword::memwb::Scope::KernelVirtual);

        WPJ6_CHECK_NOTE(
            harness.view->backStackForTest().empty(),
            QStringLiteral("身份变化后后退栈应清空，实际剩 %1 项（幽灵记录：0x%2）")
                .arg(harness.view->backStackForTest().size())
                .arg(harness.view->backStackForTest().empty() ? 0ULL : harness.view->backStackForTest().back(), 0, 16));
        WPJ6_CHECK(harness.view->forwardStackForTest().empty());
    }

    // TestInt3ContextMenuTogglesInstallAndRestore（修复缺陷 2）：右键"写入/
    // 还原此处 int3"必须按当前状态二选一（原实现永远只 Install、从不
    // Restore，结果被直接丢弃），菜单文字随状态变化，结果经状态条可见。
    // 用 HexCanvas::buildContextMenu 直接构造菜单（与 wpJ5_tests.Wiring.cpp
    // 的 TestEditRejectedAndContextMenuForwarding 同一手法），走的是生产代码
    // 的真实信号链（WorkbenchHexPane::contextMenuAboutToShow →
    // MemoryWorkbenchView::onHexPaneContextMenuAboutToShow），不是绕过接线
    // 直接调用私有方法。
    void TestInt3ContextMenuTogglesInstallAndRestore()
    {
        Harness harness;
        harness.AttachProcess();
        PumpUntil([&]() { return true; }, 10);

        auto* pane = harness.view->hexPaneForTest();
        auto* statusBar = harness.view->statusBarForTest();
        WPJ6_CHECK(statusBar != nullptr);
        const std::uint64_t address = 0xB0ULL;
        WPJ6_CHECK(WaitForStageable(pane, address));

        auto findToggleAction = [](QMenu* menu) -> QAction* {
            if (menu == nullptr)
            {
                return nullptr;
            }
            for (auto* action : menu->actions())
            {
                if (action->text().contains(QStringLiteral("int3")))
                {
                    return action;
                }
            }
            return nullptr;
        };

        // 第一次：当前目标在该地址没有补丁 -> 菜单项应显示"写入"。
        {
            QMenu* menu = pane->canvas()->buildContextMenu(address, true);
            WPJ6_CHECK(menu != nullptr);
            QAction* toggle = findToggleAction(menu);
            WPJ6_CHECK(toggle != nullptr);
            if (toggle != nullptr)
            {
                WPJ6_CHECK_NOTE(
                    toggle->text() == QStringLiteral("写入 int3 补丁"),
                    QStringLiteral("首次对该地址应显示「写入」，实际文字=%1").arg(toggle->text()));
                emit toggle->triggered();
            }
            delete menu;
        }
        WPJ6_CHECK_NOTE(
            statusBar != nullptr && statusBar->summaryText().contains(QStringLiteral("已写入 int3")),
            QStringLiteral("写入成功后状态条应可见反馈，实际=%1")
                .arg(statusBar != nullptr ? statusBar->summaryText() : QString()));

        // 第二次：该地址已有待还原条目 -> 菜单项应变成"还原"，触发后真的调用
        // Restore（而不是原实现那样永远 Install、对已安装地址报 Duplicate）。
        {
            QMenu* menu = pane->canvas()->buildContextMenu(address, true);
            WPJ6_CHECK(menu != nullptr);
            QAction* toggle = findToggleAction(menu);
            WPJ6_CHECK(toggle != nullptr);
            if (toggle != nullptr)
            {
                WPJ6_CHECK_NOTE(
                    toggle->text() == QStringLiteral("还原 int3 补丁"),
                    QStringLiteral("已有待还原条目时应显示「还原」，实际文字=%1").arg(toggle->text()));
                emit toggle->triggered();
            }
            delete menu;
        }
        WPJ6_CHECK_NOTE(
            statusBar != nullptr && statusBar->summaryText().contains(QStringLiteral("已还原")),
            QStringLiteral("还原成功后状态条应可见反馈，实际=%1")
                .arg(statusBar != nullptr ? statusBar->summaryText() : QString()));

        // 第三次：已经还原，账本里不再有该条目 -> 菜单项应回到"写入"。
        {
            QMenu* menu = pane->canvas()->buildContextMenu(address, true);
            QAction* toggle = findToggleAction(menu);
            WPJ6_CHECK_NOTE(
                toggle != nullptr && toggle->text() == QStringLiteral("写入 int3 补丁"),
                QStringLiteral("还原之后再次打开菜单应回到「写入」"));
            delete menu;
        }
    }

    void RunNavTests()
    {
        TestOpenMappedRegionStartsAtFirstVisibleRow();
        TestInitialModuleFollowReturnsHexAtTop();
        RunHexViewportReviewTests(QString());
        TestNeedsScopeSwitchShowsRerouteButtonAndJumpsOnClick();
        TestBackForwardStackCapAt64();
        TestForwardClickNoOpWhenStackEmpty();
        TestBackClickNoOpWhenStackEmpty();
        TestIdentityChangeClearsBackStackWithoutGhost();
        TestInt3ContextMenuTogglesInstallAndRestore();
    }
}
