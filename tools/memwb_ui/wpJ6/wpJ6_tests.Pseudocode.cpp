// C 页导航专项：验证正式请求构造，不访问目标进程或启动 Java/Ghidra。
#include "wpJ6_common.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchPseudocodeView.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchHexPane.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchTarget.h"
#include <QLineEdit>

namespace wpj6_test
{
    namespace
    {
        // CRequestProvider：记录 C 实际消费的冻结窗口，始终只返回内存夹具。
        class CRequestProvider final : public ks::ui::IWorkbenchBytesProvider
        {
        public:
            mutable std::vector<std::uint64_t> starts; // C 请求首地址，不以界面标签代替请求断言。
            ks::ui::WorkbenchByteWindow FetchWindow(std::uint64_t address, std::uint64_t length) const override
            {
                starts.push_back(address);
                ks::ui::WorkbenchByteWindow window;
                window.ok = length <= 65536;
                window.address = address;
                if (window.ok)
                {
                    window.bytes.assign(static_cast<std::size_t>(length), 0x90);
                    window.validMask.assign(static_cast<std::size_t>(length), 1);
                }
                return window;
            }
            int AddressBits() const override { return 64; }
            bool HasPreviousRead() const override { return false; }
        };

        // 历史导航必须在没有数据回填的同一可见窗口内仍更新 C 输入；身份恢复也走同一判断。
        void TestPseudocodeSameWindowNavigationAndRestore()
        {
            CRequestProvider provider; // 在 Harness 之前声明，保证其比子页晚销毁。
            Harness harness;
            harness.AttachProcess();
            auto* view = harness.view.get();
            view->resize(1000, 700);
            view->show();
            const auto navigate = [&](std::uint64_t at) {
                ks::ui::NavRequest request;
                request.address = at;
                request.selectLength = 1;
                request.focusView = false;
                (void)view->openAt(request);
                (void)WaitForStageable(view->hexPaneForTest(), at);
                PumpFor(80);
            };
            navigate(0x2000);
            navigate(0x2010);
            view->subTabStackForTest()->setCurrentIndex(4);
            PumpFor(60);
            auto* code = qobject_cast<ks::ui::WorkbenchPseudocodeView*>(view->subTabStackForTest()->widget(4));
            WPJ6_CHECK(code != nullptr);
            if (!code) return;
            code->setBytesProvider(&provider);
            auto* directory = code->findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"));
            WPJ6_CHECK(directory != nullptr);
            if (!directory) return;
            // 显式不存在的运行时使后台在启动进程前退出，本测试只验证正式请求构造。
            directory->setText(QStringLiteral(".codex-build-logs/missing-ghidra-regression-fixture"));
            provider.starts.clear();
            code->startDecompilation();
            PumpFor(20);
            WPJ6_CHECK(!provider.starts.empty() && provider.starts.front() == 0x2010ULL);
            view->backButtonForTest()->click();
            provider.starts.clear();
            code->startDecompilation();
            PumpFor(20);
            WPJ6_CHECK_NOTE(!provider.starts.empty() && provider.starts.front() == 0x2000ULL,
                QStringLiteral("同窗口后退必须同步 C 实际分析窗口到 0x2000"));
            view->forwardButtonForTest()->click();
            provider.starts.clear();
            code->startDecompilation();
            PumpFor(20);
            WPJ6_CHECK_NOTE(!provider.starts.empty() && provider.starts.front() == 0x2010ULL,
                QStringLiteral("同窗口前进必须同步 C 实际分析窗口到 0x2010"));
            code->setBytesProvider(nullptr);
            view->hide();

            CRequestProvider restoredProvider;
            Harness restored;
            auto* services = LastFakeServices();
            WPJ6_CHECK(services != nullptr);
            if (!services) return;
            ks::ui::ModuleEnumResult modules;
            modules.ok = true;
            ksword::memwb::ModuleRecord primary;
            primary.name = "main.exe";
            primary.fullPath = "C:\\fixture\\main.exe";
            primary.base = 0x4000;
            primary.size = 0x2000;
            modules.records.push_back(primary);
            services->SetProcessModulesResult(4242, modules);
            restored.view->subTabStackForTest()->setCurrentIndex(4);
            restored.AttachProcess();
            PumpFor(250);
            auto* restoredCode = qobject_cast<ks::ui::WorkbenchPseudocodeView*>(restored.view->subTabStackForTest()->widget(4));
            WPJ6_CHECK(restoredCode != nullptr);
            if (!restoredCode) return;
            restoredCode->setBytesProvider(&restoredProvider);
            auto* restoredDirectory = restoredCode->findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"));
            WPJ6_CHECK(restoredDirectory != nullptr);
            if (!restoredDirectory) return;
            restoredDirectory->setText(QStringLiteral(".codex-build-logs/missing-ghidra-regression-fixture"));
            restoredProvider.starts.clear();
            restoredCode->startDecompilation();
            PumpFor(20);
            WPJ6_CHECK_NOTE(!restoredProvider.starts.empty() && restoredProvider.starts.front() == 0x4000ULL,
                QStringLiteral("恢复在 C 页再附加目标必须同步初始模块的实际分析位置"));
            restoredCode->setBytesProvider(nullptr);
        }
    }
    // 由主 SubPages 组调用，同窗导航不需要读取新的字节回填来纠正 C 页。
    void RunPseudocodeNavigationTests()
    {
        TestPseudocodeSameWindowNavigationAndRestore();
    }
}
