#include "wpG_common.h"

// ============================================================
// wpG_tests.Review2.cpp
// 作用：第二轮独立审核补测，并入默认夹具（不再是只存在于审核目录的临时文件）。
// - 普通断言（RunReview2Tests 前半）：回注里第一遍幸存的几个真缺口 + 新变异
//   幸存体对应的加强断言，当前实现上全部必须通过。
// - RunDefectTests：对应第二轮报告确认的新缺陷 N1-N7，已在本轮全部修复，断言
//   直接并入默认运行（不再靠 R2_DEFECTS 环境变量开关——任务书明确要求"DEFECT
//   类用例修复后必须转绿并并入默认运行"）。
// - RunN2I18nSmokeTest：第二轮修复新增，核对 N2（en-US 运行期自绘控件/模板拼接
//   文本的翻译）。必须是本文件、乃至整个 main() 里最后一个被调用的测试——它会
//   把进程级单例 LanguageManager 切到 en-US 且不会切回去（后面没有任何代码需要
//   再看见中文），任何排在它之后的断言都不能再假定控件文字是中文。
// ============================================================

#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexViewWidgets.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchActions.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchMessages.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchSessionBar.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchSettings.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchStringWriteDialog.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WriteModeSwitch.h"
#include "../../../Ksword5.1/Ksword5.1/UI/ThemeStatusRole.h"
#include "../../../Ksword5.1/Ksword5.1/theme.h"
#include "../../../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"

#include "../../../shared/evidence/memory_workbench/MemoryWritePolicy.h"

#include <QApplication>
#include <QCheckBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFontMetrics>
#include <QIcon>
#include <QKeyEvent>
#include <QLabel>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QShortcut>
#include <QThread>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <array>

namespace wpg_test
{
    using ksword::memwb::ApprovalAnswer;
    using ksword::memwb::ApprovalRequest;
    using ksword::memwb::Channel;
    using ksword::memwb::GateReason;
    using ksword::memwb::GateVerdict;
    using ksword::memwb::MemoryWritePolicy;
    using ksword::memwb::ModeSwitchDecision;
    using ksword::memwb::Scope;
    using ksword::memwb::SessionError;
    using ksword::memwb::UiConfirmRequest;
    using ksword::memwb::WriteMode;
    namespace wm = ks::ui::workbench_messages;
    namespace ws = ks::ui::workbench_settings;

    namespace
    {
        // Pump：跑 ms 毫秒事件循环（含零延时定时器）。S4 的"下一事件循环重同步"必须靠它才能观察到。
        void Pump(const int ms)
        {
            QElapsedTimer timer;
            timer.start();
            while (timer.elapsed() < ms)
            {
                QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
                QThread::msleep(5);
            }
        }

        std::array<GateVerdict, 4> AllOk()
        {
            std::array<GateVerdict, 4> verdicts{};
            for (GateVerdict& verdict : verdicts) { verdict = GateVerdict{ true, GateReason::None }; }
            return verdicts;
        }

        // ---- S4：请求之后下一事件循环把显示重新同步回真正生效的值 ----
        void RunS4ResyncTest()
        {
            ks::ui::WorkbenchSessionBar bar;
            bar.show();
            bar.setChannelVerdicts(AllOk());
            bar.scopeSegmented()->setCurrentIndex(1);                 // 宿主不处理 = 拒绝
            WPG_CHECK(bar.currentScope() == Scope::ProcessVirtual);   // 请求不代表生效
            WPG_CHECK(bar.scopeSegmented()->currentIndex() == 1);     // 分段控件自己先翻了
            Pump(40);
            WPG_CHECK(bar.scopeSegmented()->currentIndex() == 0);     // 下一轮循环被拨回
            bar.channelSegmented()->setCurrentIndex(1);
            Pump(40);
            WPG_CHECK(bar.channelSegmented()->currentIndex() == 0);

            QMetaObject::Connection conn = QObject::connect(&bar, &ks::ui::WorkbenchSessionBar::scopeRequested,
                [&bar](const Scope scope) { bar.setScope(scope); });   // 宿主同步接受
            bar.scopeSegmented()->setCurrentIndex(2);
            Pump(40);
            WPG_CHECK(bar.currentScope() == Scope::Physical && bar.scopeSegmented()->currentIndex() == 2);
            QObject::disconnect(conn);

            conn = QObject::connect(&bar, &ks::ui::WorkbenchSessionBar::scopeRequested,
                [&bar](const Scope) { bar.setScope(Scope::KernelVirtual); });   // 宿主把请求改成别的值
            bar.scopeSegmented()->setCurrentIndex(0);
            Pump(40);
            WPG_CHECK(bar.currentScope() == Scope::KernelVirtual && bar.scopeSegmented()->currentIndex() == 1);
            QObject::disconnect(conn);
        }

        // ---- B14 第二处：当前选中的通道范围不支持时必须报红说明原因（不替用户换通道） ----
        void RunUnsupportedCurrentChannelTest()
        {
            ks::ui::WorkbenchSessionBar bar;
            bar.show();
            bar.setChannelVerdicts(AllOk());
            bar.setScope(Scope::KernelVirtual);
            bar.setChannel(Channel::UserMode);                         // R3 不支持内核范围
            WPG_CHECK(bar.currentChannel() == Channel::UserMode);      // 不替用户换
            WPG_CHECK(!bar.channelWarningText().isEmpty());
            WPG_CHECK_NOTE(bar.channelWarningText().contains(QStringLiteral("只支持进程范围")), bar.channelWarningText());
            WPG_CHECK(!bar.channelSegmented()->isSegmentEnabled(0));
        }

        // ---- 真实 QMessageBox：点具体按钮的映射（原夹具只测默认/Esc 即"取消"那一支） ----
        struct ClickProbe
        {
            bool seen = false;
            QTimer inspectTimer;
            QTimer guardTimer;
        };

        void ArmClick(ClickProbe* probe, const QString& buttonText, const bool tickCheckBox)
        {
            probe->inspectTimer.setSingleShot(true);
            probe->guardTimer.setSingleShot(true);
            QObject::connect(&probe->inspectTimer, &QTimer::timeout, [probe, buttonText, tickCheckBox]() {
                QMessageBox* box = qobject_cast<QMessageBox*>(QApplication::activeModalWidget());
                if (box == nullptr) { return; }
                probe->seen = true;
                if (tickCheckBox && box->checkBox() != nullptr) { box->checkBox()->setChecked(true); }
                for (QAbstractButton* button : box->buttons())
                {
                    if (button->text() == buttonText) { button->click(); return; }
                }
            });
            QObject::connect(&probe->guardTimer, &QTimer::timeout, []() {
                for (QWidget* widget : QApplication::topLevelWidgets())
                {
                    if (qobject_cast<QMessageBox*>(widget) != nullptr && widget->isVisible()) { widget->close(); }
                }
            });
            probe->inspectTimer.start(250);
            probe->guardTimer.start(1500);
        }

        void RunRealDialogClickMappingTest()
        {
            ks::ui::WorkbenchConfirmations conf(nullptr);
            ApprovalRequest approval;
            approval.blockIndex = 0;
            approval.blocksTotal = 3;
            approval.address = 0x1000;
            approval.length = 4;
            {
                ClickProbe probe;
                ArmClick(&probe, wm::ApprovalThisBlockOnlyButtonText(), false);
                WPG_CHECK(conf.ConfirmApproval(approval) == ApprovalAnswer::ThisBlockOnly);
                WPG_CHECK(probe.seen);
            }
            {
                ClickProbe probe;
                ArmClick(&probe, wm::ApprovalRestOfBatchButtonText(), false);
                WPG_CHECK(conf.ConfirmApproval(approval) == ApprovalAnswer::RestOfBatch);
            }
            {
                ClickProbe probe;
                ArmClick(&probe, wm::ApplyThenSwitchButtonText(), false);
                WPG_CHECK(conf.PromptModeSwitch(WriteMode::StagedThenApply, WriteMode::Immediate, 12, 3) == ModeSwitchDecision::ApplyThenSwitch);
            }
            {
                ClickProbe probe;
                ArmClick(&probe, wm::DiscardThenSwitchButtonText(), false);
                WPG_CHECK(conf.PromptModeSwitch(WriteMode::StagedThenApply, WriteMode::Immediate, 12, 3) == ModeSwitchDecision::DiscardThenSwitch);
            }
            {
                MemoryWritePolicy policy;
                ks::ui::WorkbenchConfirmations withPolicy(nullptr, &policy);
                withPolicy.SetCurrentContext(WriteMode::Immediate, Scope::KernelVirtual, Channel::StandardDriver);
                UiConfirmRequest request;
                request.blocksTotal = 1;
                request.bytesTotal = 4;
                ClickProbe probe;
                ArmClick(&probe, wm::UiConfirmAcceptButtonText(), true);       // 同意并勾选"本次运行不再询问"
                WPG_CHECK(withPolicy.ConfirmUi(request));
                WPG_CHECK(policy.IsRemembered(Scope::KernelVirtual, Channel::StandardDriver));
            }
        }

        // ---- S9：父窗口先于确认接口销毁，弹框不得用悬空父指针 ----
        void RunDanglingParentTest()
        {
            auto* parent = new QWidget();
            ks::ui::WorkbenchConfirmations conf(parent);
            delete parent;
            ClickProbe probe;
            ArmClick(&probe, wm::ModeSwitchCancelButtonText(), false);
            WPG_CHECK(conf.PromptModeSwitch(WriteMode::StagedThenApply, WriteMode::Immediate, 1, 1) == ModeSwitchDecision::Cancel);
            WPG_CHECK(probe.seen);
        }

        // ---- 正文内容：每个参数都要钉住（原夹具只断言了默认的 R3/进程 或 R0/内核 一组） ----
        void RunBodyContentTest()
        {
            UiConfirmRequest request;
            request.blocksTotal = 2;
            request.bytesTotal = 6;
            const QString ui = wm::UiConfirmBody(request, Scope::Physical, Channel::Ddma, QStringLiteral("chrome.exe · PID 4242"));
            WPG_CHECK_NOTE(ui.contains(QStringLiteral("通道：DDMA · 范围：物理")), ui);
            WPG_CHECK_NOTE(ui.contains(QStringLiteral("将写入 2 个差异块（共 6 字节）到 chrome.exe · PID 4242")), ui);

            ApprovalRequest approval;
            approval.blockIndex = 1;
            approval.blocksTotal = 3;
            approval.address = 0x7ffe0000;
            approval.length = 4;
            approval.backendText = "drv says no";
            const QString body = wm::ApprovalDialogBody(approval, Scope::KernelVirtual, Channel::Hvm, QStringLiteral("x.exe"));
            WPG_CHECK_NOTE(body.contains(QStringLiteral("通道：HVM · 范围：内核")), body);
            WPG_CHECK_NOTE(body.contains(QStringLiteral("目标：x.exe")), body);
            WPG_CHECK_NOTE(body.contains(QStringLiteral("块 2/3")), body);
            WPG_CHECK_NOTE(body.contains(QStringLiteral("起始地址=0x7ffe0000")), body);
            WPG_CHECK_NOTE(body.contains(QStringLiteral("长度=4 字节")), body);
            WPG_CHECK_NOTE(body.contains(QStringLiteral("drv says no")), body);

            // 用户可控的目标描述含 %N：必须原样出现，不得被后续占位符替换吃掉（S6）。
            const QString hostile = QStringLiteral("a%4b%6c%8.exe");
            WPG_CHECK(wm::ApprovalDialogBody(approval, Scope::ProcessVirtual, Channel::UserMode, hostile).contains(hostile));
            WPG_CHECK(wm::UiConfirmBody(request, Scope::ProcessVirtual, Channel::UserMode, QStringLiteral("a%2b%5.exe")).contains(QStringLiteral("a%2b%5.exe")));
            const QString chip = wm::TargetChipAttachedText(QStringLiteral("a%2b%3.exe"), 7, 64, true);
            WPG_CHECK_NOTE(chip == QStringLiteral("a%2b%3.exe · PID 7 · x64 · 可读写"), chip);

            WPG_CHECK(wm::PendingPatchesText(12, 3) == QStringLiteral("12 字节待写入（3 处）"));
            const QString mode = wm::ModeSwitchDialogBody(12, 3, WriteMode::Immediate);
            WPG_CHECK_NOTE(mode.contains(QStringLiteral("12 个字节（3 处）")) && mode.contains(QStringLiteral("立即写入")), mode);

            wm::ReadFailureContext context;
            context.channelName = QStringLiteral("R0");
            context.address = 0x1000;
            context.pid = 5;
            context.regionQueryOk = true;
            context.regionSummary = QStringLiteral("MEM_FREE");
            context.regionIsFree = true;
            context.sameNameProcessCount = 2;
            context.processName = QStringLiteral("x%1y.exe");
            context.isLowAddressGuard = true;
            context.rawFailureText = QStringLiteral("raw %2 %3");
            const QString explain = wm::ExplainReadFailure(context);
            WPG_CHECK_NOTE(explain.contains(QStringLiteral("地址=0x1000（PID 5）")), explain);
            WPG_CHECK_NOTE(explain.contains(QStringLiteral("低 64 KB")), explain);
            WPG_CHECK_NOTE(explain.contains(QStringLiteral("x%1y.exe")) && explain.contains(QStringLiteral("raw %2 %3")), explain);

            WPG_CHECK(wm::Translate(SessionError::NeedsPid).contains(QStringLiteral("需要一个目标进程号")));
            WPG_CHECK(wm::Translate(SessionError::PidMustBeZero).contains(QStringLiteral("不该携带进程号")));
            WPG_CHECK(wm::TargetChipNoProcessText(Scope::KernelVirtual).contains(QStringLiteral("内核")));
            WPG_CHECK(wm::TargetChipNoProcessText(Scope::Physical).contains(QStringLiteral("物理")));
            WPG_CHECK(wm::TargetChipNoProcessText(Scope::ProcessVirtual).isEmpty());
        }

        // ---- 状态条：分隔符/tooltip/保护徽章/建议重读/省略宽度 ----
        void RunStatusBarDetailTest()
        {
            ks::ui::WorkbenchStatusBar sb(std::make_unique<FakeDiagnosticsHost>());
            sb.resize(900, 100);
            sb.show();
            const auto visibleSeparators = [&sb]() {
                int n = 0;
                for (QLabel* label : sb.findChildren<QLabel*>())
                {
                    if (label->text() == QStringLiteral("|") && !label->isHidden()) { ++n; }
                }
                return n;
            };
            sb.setReadResultText(QStringLiteral("已读 8/16 字节"), false);
            sb.setWriteResultText(QStringLiteral("写入失败。"));
            WPG_CHECK(visibleSeparators() == 1);                       // 只有读取+写入两段：只该有一根竖线
            sb.setChannelScopeText(QStringLiteral("R0 · 进程"));
            sb.setWindowRangeText(QStringLiteral("0x1000..0x2000"));
            WPG_CHECK(visibleSeparators() == 3);
            for (QLabel* label : sb.findChildren<QLabel*>())
            {
                if (label->text() == QStringLiteral("R0 · 进程")) { WPG_CHECK(label->toolTip() == label->text()); }
            }

            sb.setProtection(QStringLiteral("RWX"), ks::ui::StatusRole::Warning);
            bool foundBadge = false;
            for (QLabel* label : sb.findChildren<QLabel*>())
            {
                if (label->text() == QStringLiteral("RWX"))
                {
                    foundBadge = true;
                    WPG_CHECK(label->property(ks::ui::kStatusRoleProperty).toString() == QStringLiteral("warning"));
                }
            }
            WPG_CHECK(foundBadge);

            QLabel* reread = nullptr;
            for (QLabel* label : sb.findChildren<QLabel*>())
            {
                if (label->text() == wm::NeedsRereadHintText()) { reread = label; }
            }
            WPG_CHECK(reread != nullptr);
            if (reread != nullptr)
            {
                WPG_CHECK(reread->isHidden());
                sb.setNeedsReread(true);
                WPG_CHECK(!reread->isHidden());
                int rereads = 0;
                QObject::connect(&sb, &ks::ui::WorkbenchStatusBar::rereadRequested, [&rereads]() { ++rereads; });
                QMouseEvent release(QEvent::MouseButtonRelease, QPointF(2, 2), QPointF(2, 2),
                    Qt::LeftButton, Qt::NoButton, Qt::NoModifier);
                QCoreApplication::sendEvent(reread, &release);
                WPG_CHECK(rereads == 1);
                sb.setNeedsReread(false);
                WPG_CHECK(reread->isHidden());
            }

            // 省略后的写入结果文字不得比标签自己还宽（容差 12px：估算是粗算）。
            for (const int width : { 500, 700 })
            {
                ks::ui::WorkbenchStatusBar narrow(std::make_unique<FakeDiagnosticsHost>());
                narrow.setChannelScopeText(QStringLiteral("R0 · 进程"));
                narrow.setWriteResultText(QStringLiteral("写入失败。 已写入 8 字节（2 块）。 (verify mismatch on block 2 of 3, retry later or discard the staged patches)"));
                narrow.resize(width, 60);
                narrow.show();
                Pump(40);
                for (QLabel* label : narrow.findChildren<QLabel*>())
                {
                    if (label->isHidden() || !label->text().startsWith(QStringLiteral("写入失败"))) { continue; }
                    const int textPx = QFontMetrics(label->font()).horizontalAdvance(label->text());
                    WPG_CHECK_NOTE(textPx <= label->width() + 12,
                        QStringLiteral("width=%1 textPx=%2 labelWidth=%3").arg(width).arg(textPx).arg(label->width()));
                }
            }
        }

        // ---- 会话条：✓/✗ 钮信号、消息条种类 ----
        void RunSessionBarSignalsTest()
        {
            ks::ui::WorkbenchSessionBar bar;
            bar.show();
            int applies = 0;
            int discards = 0;
            QObject::connect(&bar, &ks::ui::WorkbenchSessionBar::applyRequested, [&applies]() { ++applies; });
            QObject::connect(&bar, &ks::ui::WorkbenchSessionBar::discardRequested, [&discards]() { ++discards; });
            bar.setPendingPatches(12, 3);
            for (QToolButton* button : bar.findChildren<QToolButton*>())
            {
                if (button->toolTip() == wm::ApplyButtonTooltip()) { button->click(); }
            }
            WPG_CHECK(applies == 1 && discards == 0);
            for (QToolButton* button : bar.findChildren<QToolButton*>())
            {
                if (button->toolTip() == wm::DiscardButtonTooltip()) { button->click(); }
            }
            WPG_CHECK(applies == 1 && discards == 1);

            std::array<GateVerdict, 4> verdicts = AllOk();
            verdicts[2] = GateVerdict{ true, GateReason::ProbeNotDone };   // HVM 可用但未知
            verdicts[1] = GateVerdict{ false, GateReason::DriverNotLoaded };
            bar.setChannelVerdicts(verdicts);
            const auto warningKind = [&bar]() {
                for (QWidget* widget : bar.findChildren<QWidget*>())
                {
                    if (auto* label = dynamic_cast<ks::ui::HexViewMessageLabel*>(widget)) { return static_cast<int>(label->kind()); }
                }
                return -1;
            };
            bar.setChannel(Channel::Hvm);
            WPG_CHECK(warningKind() == static_cast<int>(ks::ui::HexViewMessageLabel::Kind::Warning));   // 未知=警告色
            bar.setChannel(Channel::StandardDriver);
            WPG_CHECK(warningKind() == static_cast<int>(ks::ui::HexViewMessageLabel::Kind::Error));      // 不可用=错误色

            ks::ui::WriteModeSwitch sw;                                // 空格键处理后必须 accept（否则事件继续冒泡）
            sw.show();
            QKeyEvent space(QEvent::KeyPress, Qt::Key_Space, Qt::NoModifier);
            space.setAccepted(false);
            QCoreApplication::sendEvent(&sw, &space);
            WPG_CHECK(space.isAccepted());
        }

        // ---- 动作表：图标别名逐项钉住、Count 越界回退 ----
        void RunActionsDetailTest()
        {
            struct Expected { ks::ui::WorkbenchActionId id; const char* alias; };
            const Expected table[] = {
                { ks::ui::WorkbenchActionId::GoBack, "file_nav_back" },
                { ks::ui::WorkbenchActionId::GoForward, "file_nav_forward" },
                { ks::ui::WorkbenchActionId::Reread, "process_refresh" },
                { ks::ui::WorkbenchActionId::ApplyPending, "service_apply" },
                { ks::ui::WorkbenchActionId::DiscardPending, "log_clear" },
                { ks::ui::WorkbenchActionId::AddToAddressBook, "memwb_bookmark_add" },
                { ks::ui::WorkbenchActionId::ToggleSidebar, "memwb_bookmarks" },
                { ks::ui::WorkbenchActionId::ToggleInt3Patch, "disk_tools" },
                { ks::ui::WorkbenchActionId::SwitchTabHex, "memwb_tab_hex" },
                { ks::ui::WorkbenchActionId::SwitchTabDisasm, "memwb_tab_disasm" },
                { ks::ui::WorkbenchActionId::SwitchTabText, "memwb_tab_text" },
                { ks::ui::WorkbenchActionId::SwitchTabCompare, "memwb_tab_compare" },
            };
            for (const Expected& row : table)
            {
                const auto& spec = ks::ui::WorkbenchActionSpecFor(row.id);
                WPG_CHECK_NOTE(spec.iconAlias == QString::fromLatin1(row.alias), spec.iconAlias);
                WPG_CHECK(!QIcon(QStringLiteral(":/Icon/%1.svg").arg(spec.iconAlias)).isNull());
            }
            // 越界 id 的回退约定：WorkbenchActionSpecFor 本身仍是"退回表中最后一项
            // （Esc）的说明，不得读到数组外"的轻量访问器（供诊断/文案查询用）；但
            // CreateWorkbenchShortcut/CreateWorkbenchAlternateShortcut 不能借用这个
            // 兜底去真的注册出一个 Esc 快捷键（N5，见 RunDefectTests）。
            const auto& fallback = ks::ui::WorkbenchActionSpecFor(ks::ui::WorkbenchActionId::Count);
            const auto& esc = ks::ui::WorkbenchActionSpecFor(ks::ui::WorkbenchActionId::EscapeOrCancel);
            WPG_CHECK(fallback.tooltip == esc.tooltip && fallback.shortcut == esc.shortcut);
        }

        // ---- 设置：合法最大值/按范围分键往返 ----
        void RunSettingsRoundTripTest()
        {
            QCoreApplication::setOrganizationName(QStringLiteral("wpGgap2"));
            QCoreApplication::setApplicationName(QStringLiteral("wpGgap2"));
            QSettings::setDefaultFormat(QSettings::IniFormat);
            QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, QDir::tempPath() + QStringLiteral("/wpg-settings2"));
            { QSettings settings; settings.clear(); }
            ws::SaveScope(2);
            WPG_CHECK(ws::LoadScope() == 2U);
            ws::SaveWriteMode(1);
            WPG_CHECK(ws::LoadWriteMode() == 1U);
            ws::SaveChannelForScope(0, 2);        // 进程=HVM
            ws::SaveChannelForScope(1, 2);        // 内核=HVM
            ws::SaveChannelForScope(2, 0);        // 物理=R3（与默认 R0 不同，也与内核键不同）
            WPG_CHECK(ws::LoadChannelForScope(0) == 2U);
            WPG_CHECK(ws::LoadChannelForScope(1) == 2U);
            WPG_CHECK(ws::LoadChannelForScope(2) == 0U);
            // 本轮自补变异 wpGN2-07 实测揭出的缺口：上面三行刚好两个范围都存了
            // 同一个值 2（HVM），process 的键若被错接到 kernel 的键，往返结果仍然
            // 原样读回 2，这条已有断言看不出来。这里换成三个范围存三个互不相同的
            // 值，任何一对键互相指错都会在某一侧读出"串台"的另一个值。
            ws::SaveChannelForScope(0, 0);        // 进程=R3
            ws::SaveChannelForScope(1, 1);        // 内核=R0
            ws::SaveChannelForScope(2, 2);        // 物理=HVM
            WPG_CHECK_NOTE(ws::LoadChannelForScope(0) == 0U, QStringLiteral("process key must not alias kernel/physical"));
            WPG_CHECK_NOTE(ws::LoadChannelForScope(1) == 1U, QStringLiteral("kernel key must not alias process/physical"));
            WPG_CHECK_NOTE(ws::LoadChannelForScope(2) == 2U, QStringLiteral("physical key must not alias process/kernel"));
            ws::SaveSidebarWidth(120);
            WPG_CHECK(ws::LoadSidebarWidth() == 120);
            ws::SaveSidebarWidth(119);
            WPG_CHECK(ws::LoadSidebarWidth() == 300);
            { QSettings settings; settings.clear(); }
        }

        // ---- 字符串对话框：默认值、预览状态色 ----
        void RunDialogDetailTest()
        {
            ks::ui::WorkbenchStringWriteDialog dlg;
            WPG_CHECK(dlg.encoding() == ks::ui::WorkbenchStringWriteDialog::Encoding::Utf8);
            WPG_CHECK(!dlg.appendNul());
            QLabel* preview = dlg.findChild<QLabel*>();
            WPG_CHECK(preview != nullptr);
            if (preview == nullptr) { return; }
            dlg.setText(QStringLiteral("Ab"));
            WPG_CHECK(preview->property(ks::ui::kStatusRoleProperty).toString().isEmpty());
            QString lone;
            lone += QChar(0xD800);                                      // 任何代码页都表示不了
            dlg.setEncoding(ks::ui::WorkbenchStringWriteDialog::Encoding::Ansi);
            dlg.setText(lone);
            WPG_CHECK(preview->property(ks::ui::kStatusRoleProperty).toString() == QStringLiteral("error"));
            dlg.setText(QStringLiteral("Ab"));
            WPG_CHECK(preview->property(ks::ui::kStatusRoleProperty).toString().isEmpty());
        }

        // ================= 第二轮新缺陷（已修复，断言并入默认运行）=================
        class WrapHost final : public ks::ui::IWorkbenchDiagnosticsHost
        {
        public:
            WrapHost() { m_edit = new QPlainTextEdit(); m_edit->setLineWrapMode(QPlainTextEdit::NoWrap); }
            ~WrapHost() override { delete m_edit; }
            QWidget* HostWidget() override { return m_edit; }
            void SetDiagnosticsText(const QString& text) override { m_documentActive = false; m_edit->setPlainText(text); }
            void SetDiagnosticsDocument(const ks::ui::FieldDocument& document) override { m_document = document; m_documentActive = true; }
            QString DiagnosticsText() const override { return m_documentActive ? m_document.toPlainText(true) : m_edit->toPlainText(); }
            void SetWrapEnabled(const bool wrap) override { m_edit->setLineWrapMode(wrap ? QPlainTextEdit::WidgetWidth : QPlainTextEdit::NoWrap); }
            bool IsWrap() const { return m_edit->lineWrapMode() == QPlainTextEdit::WidgetWidth; }
        private:
            QPlainTextEdit* m_edit = nullptr;
            ks::ui::FieldDocument m_document;
            bool m_documentActive = false;
        };

        void RunDefectTests()
        {
            // N1：三段摘要标签在真实布局里不得塌成 0 宽。
            {
                ks::ui::WorkbenchStatusBar sb(std::make_unique<FakeDiagnosticsHost>());
                sb.resize(1100, 60);
                sb.show();
                sb.setChannelScopeText(QStringLiteral("R0 · 进程"));
                sb.setReadResultText(QStringLiteral("已读 4096/4096 字节"), false);
                sb.setWindowRangeText(QStringLiteral("0x00007FF6_1000..0x00007FF6_2000"));
                sb.setWriteResultText(QStringLiteral("写入失败。"));
                Pump(60);
                for (QLabel* label : sb.findChildren<QLabel*>())
                {
                    if (label->isHidden() || label->text().isEmpty() || label->text() == QStringLiteral("|")) { continue; }
                    if (label->text().contains(QStringLiteral("暂存")) || label->text().contains(QStringLiteral("读-改-写"))) { continue; }
                    const int need = QFontMetrics(label->font()).horizontalAdvance(label->text());
                    WPG_CHECK_NOTE(label->width() >= need,
                        QStringLiteral("N1 text='%1' width=%2 need=%3").arg(label->text()).arg(label->width()).arg(need));
                }
            }
            // N3：应用级样式表存在时，ANSI 有损预览仍应是错误色。
            {
                qApp->setStyleSheet(ks::ui::BuildStatusRoleStyleRules());
                ks::ui::WorkbenchStringWriteDialog dlg;
                dlg.show();
                dlg.setEncoding(ks::ui::WorkbenchStringWriteDialog::Encoding::Ansi);
                QString lone;
                lone += QChar(0xD800);
                dlg.setText(lone);
                Pump(60);
                QLabel* preview = dlg.findChild<QLabel*>();
                WPG_CHECK(preview != nullptr);
                if (preview != nullptr)
                {
                    WPG_CHECK_NOTE(preview->palette().color(QPalette::WindowText) == KswordTheme::ErrorColor(),
                        QStringLiteral("N3 preview color=%1").arg(preview->palette().color(QPalette::WindowText).name()));
                }
                qApp->setStyleSheet(QString());
            }
            // N4：换行勾选的初值必须与宿主真实状态一致。
            {
                auto host = std::make_unique<WrapHost>();
                WrapHost* raw = host.get();
                ks::ui::WorkbenchStatusBar sb(std::move(host));
                QCheckBox* wrap = sb.findChild<QCheckBox*>();
                WPG_CHECK(wrap != nullptr);
                if (wrap != nullptr) { WPG_CHECK_NOTE(wrap->isChecked() == raw->IsWrap(), QStringLiteral("N4")); }
            }
            // N5：越界 id 不得注册出 Esc 快捷键。
            {
                QWidget host;
                WPG_CHECK_NOTE(ks::ui::CreateWorkbenchShortcut(ks::ui::WorkbenchActionId::Count, &host) == nullptr, QStringLiteral("N5"));
                WPG_CHECK_NOTE(ks::ui::CreateWorkbenchAlternateShortcut(ks::ui::WorkbenchActionId::Count, &host) == nullptr, QStringLiteral("N5 alt"));
            }
            // N7：主题切换后目标 chip 的文字色必须自己跟上（changeEvent 里监听的 ApplicationPaletteChange
            // 不会被 QWidget 转给 changeEvent，那条分支是死代码；应监听 PaletteChange）。
            // 先把主题状态拨回一个确定的浅色基线：本测试可能跑在 RunShotsTests
            // 切换过深色主题之后，Qt 的 QApplication::setPalette 对"新旧完全相同的
            // 调色板"是空操作、不会派发任何 PaletteChange——必须先确认发生了一次
            // 真实的"不同"切换，才能验证事件链路本身。
            {
                KswordTheme::SetDarkModeEnabled(false);
                ApplyTheme(false);
                Pump(30);

                ks::ui::WorkbenchSessionBar bar;
                bar.show();
                bar.setTargetInfo(true, QStringLiteral("a.exe"), 7, 64, true);
                QToolButton* chip = nullptr;
                for (QToolButton* button : bar.findChildren<QToolButton*>())
                {
                    // 目标 chip = 带文字的 QToolButton，但写入模式胶囊的两个半边现在也带文字（即时/暂存），要排除。
                    if (!button->text().isEmpty() && qobject_cast<ks::ui::WriteModeSwitch*>(button->parentWidget()) == nullptr) { chip = button; }
                }
                WPG_CHECK(chip != nullptr);
                if (chip != nullptr)
                {
                    WPG_CHECK_NOTE(chip->palette().color(QPalette::ButtonText) == KswordTheme::TextPrimaryColor(),
                        QStringLiteral("N7 baseline chip color=%1 expected=%2")
                            .arg(chip->palette().color(QPalette::ButtonText).name(), KswordTheme::TextPrimaryColor().name()));
                    KswordTheme::SetDarkModeEnabled(true);
                    ApplyTheme(true);
                    Pump(30);
                    WPG_CHECK_NOTE(chip->palette().color(QPalette::ButtonText) == KswordTheme::TextPrimaryColor(),
                        QStringLiteral("N7 chip color=%1 expected=%2")
                            .arg(chip->palette().color(QPalette::ButtonText).name(), KswordTheme::TextPrimaryColor().name()));
                    KswordTheme::SetDarkModeEnabled(false);
                    ApplyTheme(false);
                    Pump(30);
                }
            }
            // N6：全新会话条（还没喂判据）不得显示"当前范围/通道组合无效"红字。
            {
                ks::ui::WorkbenchSessionBar bar;
                bar.show();
                WPG_CHECK_NOTE(bar.channelWarningText().isEmpty(), QStringLiteral("N6 text='%1'").arg(bar.channelWarningText()));
            }
        }

        // ================= N2（第二轮修复新增）：en-US 运行期翻译 smoke test =================
        // 必须整个 main() 的最后一组断言——initialize("en-US") 之后进程里再也不会
        // 切回中文，任何排在它之后的代码都不能再假定界面文字是中文（截图、其它
        // 测试……）。
        void RunN2I18nSmokeTest()
        {
            QString initError;
            const bool initialized = ks::i18n::LanguageManager::instance().initialize(QStringLiteral("en-US"), &initError);
            WPG_CHECK_NOTE(initialized, QStringLiteral("N2 LanguageManager::initialize failed: %1").arg(initError));
            if (!initialized)
            {
                return;
            }

            // 会话条：自绘分段控件的段文字/tooltip，经源头 sourceText 翻译。
            ks::ui::WorkbenchSessionBar bar;
            bar.show();
            std::array<GateVerdict, 4> verdicts = AllOk();
            verdicts[1] = GateVerdict{ false, GateReason::DriverNotLoaded };
            bar.setChannelVerdicts(verdicts);
            bar.setChannel(Channel::StandardDriver);
            const QString scopeLabel = bar.scopeSegmented()->labelAt(static_cast<int>(Scope::ProcessVirtual));
            WPG_CHECK_NOTE(scopeLabel == QStringLiteral("Process"), scopeLabel);
            const QString warning = bar.channelWarningText();
            WPG_CHECK_NOTE(!warning.contains(QStringLiteral("驱动未加载")), warning);
            WPG_CHECK_NOTE(warning.contains(QStringLiteral("not loaded"), Qt::CaseInsensitive), warning);

            // 目标 chip：模板本身不翻译（纯占位符骨架），但"可读写/只读"参数要翻译；
            // 进程名绝不翻译。
            bar.setTargetInfo(true, QStringLiteral("a.exe"), 7, 64, true);
            QToolButton* chip = nullptr;
            for (QToolButton* button : bar.findChildren<QToolButton*>())
            {
                // 目标 chip = 带文字的 QToolButton，但写入模式胶囊的两个半边现在也带文字（即时/暂存），要排除。
                if (!button->text().isEmpty() && qobject_cast<ks::ui::WriteModeSwitch*>(button->parentWidget()) == nullptr) { chip = button; }
            }
            WPG_CHECK(chip != nullptr);
            if (chip != nullptr)
            {
                WPG_CHECK_NOTE(chip->text() == QStringLiteral("a.exe · PID 7 · x64 · Read/write"), chip->text());
            }

            // 内核/物理范围不需要进程：中性提示文字已有语言包词条，翻译要生效；
            // tooltip 这个新字符串还没有语言包词条（由汇合步骤补），这里只断言
            // S-e 的行为本身——不需要进程时的 tooltip 必须与"需要进程"那一支不同，
            // 不再暗示"点击能选进程"，不断言具体英文译文。
            bar.setScope(Scope::KernelVirtual);
            Pump(60);
            for (QToolButton* button : bar.findChildren<QToolButton*>())
            {
                // 排除写入模式胶囊的两个半边（它们现在也带文字）：这里只核对目标 chip。
                if (!button->text().isEmpty() && qobject_cast<ks::ui::WriteModeSwitch*>(button->parentWidget()) == nullptr)
                {
                    WPG_CHECK_NOTE(button->text() == QStringLiteral("No process needed (kernel)"), button->text());
                    WPG_CHECK_NOTE(
                        button->toolTip() != QStringLiteral("Current target; click the process bar above to select or attach"),
                        button->toolTip());
                }
            }
        }
    }

    void RunReview2Tests()
    {
        RunS4ResyncTest();
        RunUnsupportedCurrentChannelTest();
        RunRealDialogClickMappingTest();
        RunDanglingParentTest();
        RunBodyContentTest();
        RunStatusBarDetailTest();
        RunSessionBarSignalsTest();
        RunActionsDetailTest();
        RunSettingsRoundTripTest();
        RunDialogDetailTest();
        RunDefectTests();
        RunN2I18nSmokeTest();
    }
}
