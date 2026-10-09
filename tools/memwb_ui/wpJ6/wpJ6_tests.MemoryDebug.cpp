// 独立内存调试模式专项回归：内存均为假端口，进程锚点仅使用自身与自有短寿命子进程。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "wpJ6_common.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchDisasmView.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexCanvas.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexViewWidgets.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchSettings.h"

#include <QAction>
#include <QMenu>
#include <QShortcut>
#include <string>

namespace wpj6_test
{
    namespace
    {
        // StageOne：在共享假内存中暂存一个字节，用于关闭守卫及退出后的事务测试。
        bool StageOne(Harness& harness, const std::uint64_t address)
        {
            harness.view->writeControllerForTest()->requestModeSwitch(ksword::memwb::WriteMode::StagedThenApply);
            if (harness.view->showDisassemblyAt(address) != ks::ui::NavStatus::Ok
                || !WaitForStageable(harness.view->hexPaneForTest(), address))
            {
                return false;
            }
            return harness.view->hexPaneForTest()->canvas()->stageBytes(address, QByteArray(1, '\x5a'));
        }

        // OwnWorker：只启动本夹具的工作进程；析构等待自然退出并关闭自己的句柄。
        struct OwnWorker
        {
            PROCESS_INFORMATION process{}; // 仅本类启动的进程与初始线程句柄。
            bool Start()
            {
                wchar_t path[MAX_PATH]{};
                if (::GetModuleFileNameW(nullptr, path, MAX_PATH) == 0)
                {
                    return false;
                }
                std::wstring command = L"\"" + std::wstring(path) + L"\" --memory-debug-worker";
                STARTUPINFOW startup{};
                startup.cb = sizeof(startup);
                return ::CreateProcessW(path, command.data(), nullptr, nullptr, FALSE,
                    CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE;
            }
            ~OwnWorker()
            {
                if (process.hProcess)
                {
                    (void)::WaitForSingleObject(process.hProcess, 5000);
                    ::CloseHandle(process.hThread);
                    ::CloseHandle(process.hProcess);
                }
            }
        };
    }

    void RunMemoryDebugTests()
    {
        // 默认工作台保持原模式、范围控件和 int3 可用，不被新 API 的存在改变。
        {
            Harness normal;
            WPJ6_CHECK(!normal.view->isMemoryDebugMode());
            WPJ6_CHECK(!normal.view->sessionBarForTest()->scopeSegmented()->isHidden());
            WPJ6_CHECK(!normal.view->int3PanelForTest()->isHidden());
            WPJ6_CHECK(normal.view->target().policy().allowFollowDock);
        }
        {
            // 旧工作台保存了内核/R0/HEX 时，新页初始化仍必须使用进程/R3/反汇编。
            using namespace ks::ui::workbench_settings;
            const auto oldScope = LoadScope();
            const auto oldChannel = LoadChannelForScope(0);
            const auto oldTab = LoadSubTab();
            SaveScope(static_cast<std::uint32_t>(ksword::memwb::Scope::KernelVirtual));
            SaveChannelForScope(0, static_cast<std::uint32_t>(ksword::memwb::Channel::StandardDriver));
            SaveSubTab(0);
            Harness persisted;
            WPJ6_CHECK(persisted.view->setMemoryDebugMode(true));
            persisted.view->loadSettings();
            WPJ6_CHECK(persisted.view->target().session().scope == ksword::memwb::Scope::ProcessVirtual);
            WPJ6_CHECK(persisted.view->target().session().channel == ksword::memwb::Channel::UserMode);
            WPJ6_CHECK(persisted.view->subTabStackForTest()->currentIndex() == 1);
            SaveScope(oldScope);
            SaveChannelForScope(0, oldChannel);
            SaveSubTab(oldTab);
        }
        {
            Harness harness;
            auto& view = *harness.view;
            WPJ6_CHECK(view.setMemoryDebugMode(true));
            WPJ6_CHECK(view.isMemoryDebugMode());
            WPJ6_CHECK(view.target().session().scope == ksword::memwb::Scope::ProcessVirtual);
            WPJ6_CHECK(view.target().session().channel == ksword::memwb::Channel::UserMode);
            WPJ6_CHECK(view.subTabStackForTest()->currentIndex() == 1);
            WPJ6_CHECK(view.sessionBarForTest()->scopeSegmented()->isHidden());
            WPJ6_CHECK(view.int3PanelForTest()->isHidden() && !view.int3PanelForTest()->isEnabled());
            WPJ6_CHECK(!view.target().requestScope(ksword::memwb::Scope::KernelVirtual));
            WPJ6_CHECK(!view.target().requestFollowDock());
            WPJ6_CHECK(view.showDisassemblyAt(0x1800) == ks::ui::NavStatus::NeedsAttach);
            bool foundTarget = false;
            for (auto* button : view.sessionBarForTest()->findChildren<QToolButton*>())
            {
                if (button->toolTip() == QStringLiteral("选择进程"))
                {
                    foundTarget = button->text() == QStringLiteral("未选择进程");
                }
            }
            WPJ6_CHECK(foundTarget);

            // 只锚定夹具自身，读取仍由 FakeMemoryIoPort 完成；Dock 事件不能换目标。
            WPJ6_CHECK(view.target().requestPin(::GetCurrentProcessId()));
            const auto selected = view.target().capture();
            harness.AttachProcess(4242, 12);
            view.target().onDockDetached();
            WPJ6_CHECK(ksword::memwb::SameTarget(view.target().session(), selected.session));
            WPJ6_CHECK(!view.target().wouldChangeOnDockAttach());
            WPJ6_CHECK(view.showDisassemblyAt(0x1800) == ks::ui::NavStatus::Ok);
            auto* disasm = qobject_cast<ks::ui::WorkbenchDisasmView*>(view.subTabStackForTest()->widget(1));
            WPJ6_CHECK(disasm && disasm->hasAnchor() && disasm->anchorAddress() == 0x1800);
            WPJ6_CHECK(view.focusAddress() == std::optional<std::uint64_t>(0x1800));

            // 菜单与快捷键不能安装 int3；普通 HEX/反汇编/地址簿菜单仍可产生。
            QMenu menu;
            view.hexPaneForTest()->contextMenuAboutToShow(&menu, 0x1800, true);
            for (auto* action : menu.actions())
            {
                WPJ6_CHECK(!action->text().contains(QStringLiteral("int3")));
            }
            const auto writesBefore = ConfigureSharedOnce().backing->writeCallCount;
            for (auto* shortcut : view.findChildren<QShortcut*>())
            {
                if (shortcut->key() == QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_P))
                {
                    QMetaObject::invokeMethod(shortcut, "activated", Qt::DirectConnection);
                }
            }
            WPJ6_CHECK(ConfigureSharedOnce().backing->writeCallCount == writesBefore);

            // 取消关闭保留身份、待写补丁与代次；丢弃后清会话而不回到 Dock。
            WPJ6_CHECK(StageOne(harness, 0x1800));
            const auto staged = view.target().capture();
            harness.prompter->leaveWithPendingDecision = ksword::memwb::ModeSwitchDecision::Cancel;
            WPJ6_CHECK(!view.clearMemoryDebugTarget());
            WPJ6_CHECK(ksword::memwb::SameTarget(view.target().session(), staged.session));
            WPJ6_CHECK(!view.target().isStale(staged.rev));
            WPJ6_CHECK(view.hexPaneForTest()->overlay().HasPendingPatches());
            harness.prompter->leaveWithPendingDecision = ksword::memwb::ModeSwitchDecision::DiscardThenSwitch;
            WPJ6_CHECK(view.clearMemoryDebugTarget());
            WPJ6_CHECK(view.target().session().pid == 0U);
            WPJ6_CHECK(view.target().followMode() == ksword::memwb::MemoryTargetTracker::Follow::Pinned);
            WPJ6_CHECK(view.target().isStale(staged.rev));
            WPJ6_CHECK(!view.hexPaneForTest()->overlay().HasPendingPatches());
        }

        // 目标退出只使用自有工作进程；确认后保留旧内容而拒绝实际读写端口调用。
        {
            Harness harness;
            OwnWorker worker;
            const bool started = worker.Start();
            WPJ6_CHECK(started);
            if (!started) return;
            WPJ6_CHECK(harness.view->setMemoryDebugMode(true));
            WPJ6_CHECK(harness.view->target().requestPin(worker.process.dwProcessId));
            WPJ6_CHECK(StageOne(harness, 0x2800));
            WPJ6_CHECK(::WaitForSingleObject(worker.process.hProcess, 5000) == WAIT_OBJECT_0);
            harness.view->target().checkLiveness();
            WPJ6_CHECK(harness.view->target().livenessState() == ks::ui::LivenessState::Exited);
            const auto& backing = ConfigureSharedOnce().backing;
            const auto reads = backing->readCallCount;
            const auto writes = backing->writeCallCount;
            WPJ6_CHECK(harness.view->showDisassemblyAt(0x2800) == ks::ui::NavStatus::TargetGone);
            (void)harness.view->writeControllerForTest()->commitPendingNow();
            PumpFor(120);
            WPJ6_CHECK(backing->readCallCount == reads);
            WPJ6_CHECK(backing->writeCallCount == writes);
            WPJ6_CHECK(harness.view->hexPaneForTest()->overlay().HasPendingPatches());
            WPJ6_CHECK(harness.view->target().session().pid == worker.process.dwProcessId);
            harness.prompter->leaveWithPendingDecision = ksword::memwb::ModeSwitchDecision::DiscardThenSwitch;
            WPJ6_CHECK(harness.view->clearMemoryDebugTarget());
        }
    }
}
