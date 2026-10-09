#include "wpG_common.h"

// ============================================================
// wpG_tests.Gaps2.cpp
// 作用：wpG_tests.Gaps.cpp 的续篇——单文件 ≤700 行的限制下，把 T7-T13 与 S1/B12/
// B11 相关的"缺口测试"放在这里；两个文件共用 wpG_common.h 的设施，互不依赖
// 彼此的匿名命名空间符号。main() 依次调用 RunGapTests() 与 RunGapTests2()。
// ============================================================

#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexViewWidgets.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchActions.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchMessages.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchSessionBar.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchSettings.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchStringWriteDialog.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WriteModeSwitch.h"

#include <QCheckBox>
#include <QDir>
#include <QKeyEvent>
#include <QLabel>
#include <QPushButton>
#include <QSettings>
#include <QShortcut>
#include <QToolButton>
#include <QVBoxLayout>

#include <array>
#include <vector>

namespace wpg_test
{
    using ksword::memwb::Channel;
    using ksword::memwb::GateReason;
    using ksword::memwb::GateVerdict;
    using ksword::memwb::IoReadStatus;
    using ksword::memwb::ModeSwitchStatus;
    using ksword::memwb::Scope;
    using ksword::memwb::SessionError;
    using ksword::memwb::StageStatus;
    using ksword::memwb::WriteMode;

    namespace
    {
        // ---- T7（M18/M19，及 B6/S10）：设置读写；ini 重定向到临时目录 ----
        void RunSettingsTest()
        {
            QCoreApplication::setOrganizationName(QStringLiteral("wpGgap"));
            QCoreApplication::setApplicationName(QStringLiteral("wpGgap"));
            QSettings::setDefaultFormat(QSettings::IniFormat);
            QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, QDir::tempPath() + QStringLiteral("/wpg-settings"));
            { QSettings settings; settings.clear(); }
            namespace ws = ks::ui::workbench_settings;
            WPG_CHECK(ws::LoadScope() == 0U && ws::LoadWriteMode() == 0U);
            WPG_CHECK(ws::LoadChannelForScope(0) == 0U && ws::LoadChannelForScope(1) == 1U && ws::LoadChannelForScope(2) == 1U);
            WPG_CHECK(ws::LoadSidebarWidth() == 300 && ws::LoadBytesPerRow() == 16 && ws::LoadLiveIntervalMs() == 1000);
            WPG_CHECK(ws::LoadAddrBookKind() == -1);
            ws::SaveSubTab(4);                                        // C 伪代码页是新的合法上界。
            WPG_CHECK(ws::LoadSubTab() == 4);
            ws::SaveSubTab(5);                                        // 越界退回默认。
            WPG_CHECK(ws::LoadSubTab() == 0);
            ws::SaveLiveIntervalMs(200);
            WPG_CHECK(ws::LoadLiveIntervalMs() == 200);
            ws::SaveLiveIntervalMs(199);
            WPG_CHECK(ws::LoadLiveIntervalMs() == 1000);
            {
                QSettings settings;                                   // 布尔："true"/"1" 为真，其余为假
                settings.setValue(QStringLiteral("memwb/workbench/liveRefresh"), QStringLiteral("1"));
                settings.setValue(QStringLiteral("memwb/workbench/sidebarVisible"), QStringLiteral("true"));
                settings.setValue(QStringLiteral("memwb/workbench/diagExpanded"), QStringLiteral("yes"));
            }
            WPG_CHECK(ws::LoadLiveRefresh());
            WPG_CHECK(ws::LoadSidebarVisible());
            WPG_CHECK(!ws::LoadDiagExpanded());
            QStringList many;
            for (int i = 0; i < 25; ++i) { many << QStringLiteral("0x%1").arg(i); }
            const QStringList pushed = ws::PushAddrHistory(many, QStringLiteral("0x3"));   // 去重提前 + 截断 20
            WPG_CHECK(pushed.size() == ws::kAddrHistoryLimit);
            WPG_CHECK(pushed.first() == QStringLiteral("0x3") && pushed.count(QStringLiteral("0x3")) == 1);
            {
                QSettings settings;                                   // B6：非法值一律退回默认
                settings.setValue(QStringLiteral("memwb/workbench/scope"), 7);
                settings.setValue(QStringLiteral("memwb/workbench/writeMode"), 5);
                settings.setValue(QStringLiteral("memwb/workbench/bytesPerRow"), 7);
                settings.setValue(QStringLiteral("memwb/workbench/groupSize"), 3);
                settings.setValue(QStringLiteral("memwb/workbench/channel/physical"), 3);   // DDMA 不得当默认
                settings.setValue(QStringLiteral("memwb/workbench/sidebarWidth"), 1);
            }
            WPG_CHECK(ws::LoadScope() == 0U);
            WPG_CHECK(ws::LoadWriteMode() == 0U);
            WPG_CHECK(ws::LoadBytesPerRow() == 16);
            WPG_CHECK(ws::LoadGroupSize() == 1);
            WPG_CHECK(ws::LoadChannelForScope(2) == 1U);
            WPG_CHECK(ws::LoadSidebarWidth() == 300);
            for (const int allowed : {8, 16, 32, 48, 64})           // 允许集合内的每个值都必须能原样读回
            {
                QSettings settings;
                settings.setValue(QStringLiteral("memwb/workbench/bytesPerRow"), allowed);
                WPG_CHECK_NOTE(ws::LoadBytesPerRow() == allowed, QStringLiteral("allowed=%1").arg(allowed));
            }
            for (const int allowed : {1, 2, 4, 8})
            {
                QSettings settings;
                settings.setValue(QStringLiteral("memwb/workbench/groupSize"), allowed);
                WPG_CHECK_NOTE(ws::LoadGroupSize() == allowed, QStringLiteral("allowed=%1").arg(allowed));
            }
        }

        // ---- T8（M17，及 B7/B13/S2/S7）：动作表 ----
        void RunActionsTest()
        {
            QWidget host;
            const int count = static_cast<int>(ks::ui::WorkbenchActionId::Count);
            QStringList keys;
            for (int i = 0; i < count; ++i)
            {
                const auto id = static_cast<ks::ui::WorkbenchActionId>(i);
                const auto& spec = ks::ui::WorkbenchActionSpecFor(id);
                WPG_CHECK(!spec.shortcut.isEmpty() && !spec.tooltip.isEmpty());
                keys << spec.shortcut.toString();
                QShortcut* shortcut = ks::ui::CreateWorkbenchShortcut(id, &host);
                if (id == ks::ui::WorkbenchActionId::EscapeOrCancel)
                {
                    // S2：Esc 故意不注册成常驻快捷键，避免抢子控件自己的 Esc 处理。
                    WPG_CHECK(shortcut == nullptr);
                }
                else
                {
                    WPG_CHECK(shortcut != nullptr && shortcut->context() == Qt::WidgetWithChildrenShortcut);
                }
            }
            WPG_CHECK(keys.removeDuplicates() == 0);
            WPG_CHECK(ks::ui::CreateWorkbenchShortcut(ks::ui::WorkbenchActionId::Undo, nullptr) == nullptr);

            // B7：Redo 的候补键 Ctrl+Shift+Z 必须能通过专门的函数建出来，且键序列
            // 与 tooltip 文案承诺的一致。
            QShortcut* redoAlt = ks::ui::CreateWorkbenchAlternateShortcut(ks::ui::WorkbenchActionId::Redo, &host);
            WPG_CHECK(redoAlt != nullptr);
            WPG_CHECK(redoAlt->key() == QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_Z));
            WPG_CHECK(redoAlt->context() == Qt::WidgetWithChildrenShortcut);

            // S7：ApplyPending 的候补键是小键盘 Ctrl+Enter（Key_Enter），不是
            // Ctrl+Key_Return 本身（那是主快捷键）。
            QShortcut* applyAlt = ks::ui::CreateWorkbenchAlternateShortcut(ks::ui::WorkbenchActionId::ApplyPending, &host);
            WPG_CHECK(applyAlt != nullptr);
            WPG_CHECK(applyAlt->key() == QKeySequence(Qt::CTRL | Qt::Key_Enter));

            // 没有候补键的动作（例如 Undo）必须返回空指针，不能随便给一个假键。
            WPG_CHECK(ks::ui::CreateWorkbenchAlternateShortcut(ks::ui::WorkbenchActionId::Undo, &host) == nullptr);
            WPG_CHECK(ks::ui::CreateWorkbenchAlternateShortcut(ks::ui::WorkbenchActionId::EscapeOrCancel, &host) == nullptr);
            WPG_CHECK(ks::ui::CreateWorkbenchAlternateShortcut(ks::ui::WorkbenchActionId::Redo, nullptr) == nullptr);
        }

        // ---- T9（M20/M21，及 B1/B10）：字符串写入对话框 ----
        void RunStringDialogTest()
        {
            ks::ui::WorkbenchStringWriteDialog dlg;
            using Enc = ks::ui::WorkbenchStringWriteDialog::Encoding;
            const auto findOkButton = [&dlg]() {
                for (QPushButton* button : dlg.findChildren<QPushButton*>())
                {
                    if (button->text() == ks::ui::workbench_messages::StringWriteOkButtonText()) { return button; }
                }
                return static_cast<QPushButton*>(nullptr);
            };
            QPushButton* okButton = findOkButton();
            WPG_CHECK(okButton != nullptr);

            dlg.setText(QStringLiteral("Ab"));
            dlg.setAppendNul(false);
            dlg.setEncoding(Enc::Utf8);
            WPG_CHECK(dlg.resultBytes() == QByteArray("Ab", 2));
            WPG_CHECK(okButton->isEnabled());                         // 非空、无损 -> 可点"写入"
            dlg.setEncoding(Enc::Utf16Le);
            WPG_CHECK(dlg.resultBytes() == QByteArray("A\0b\0", 4));
            dlg.setAppendNul(true);                                   // UTF-16LE 的结束符是 2 字节
            WPG_CHECK(dlg.resultBytes() == QByteArray("A\0b\0\0\0", 6));
            dlg.setEncoding(Enc::Utf8);
            WPG_CHECK(dlg.resultBytes() == QByteArray("Ab\0", 3));
            dlg.setEncoding(Enc::Ansi);
            WPG_CHECK(dlg.resultBytes() == QByteArray("Ab\0", 3));     // 纯 ASCII 在任何 ANSI 代码页都无损
            WPG_CHECK(dlg.previewText().contains(QStringLiteral("3")));
            dlg.setAppendNul(false);                                  // 非 BMP：代理对小端 3D D8 00 DE；UTF-8 四字节
            dlg.setText(QStringLiteral("😀"));
            dlg.setEncoding(Enc::Utf16Le);
            WPG_CHECK(dlg.resultBytes() == QByteArray("\x3D\xD8\x00\xDE", 4));
            dlg.setEncoding(Enc::Utf8);
            WPG_CHECK(dlg.resultBytes() == QByteArray("\xF0\x9F\x98\x80", 4));
            WPG_CHECK(dlg.previewText().contains(QStringLiteral("4")));

            // B1：往返校验本身要跟着"本机 ANSI 代码页到底是什么"走——大多数机器上
            // 单/双字节代码页（GBK/CP1252/Shift-JIS…）都表示不了非 BMP 表情符号，
            // 但少数机器把系统 ANSI 代码页设成了 UTF-8（Windows"Beta: 使用 Unicode
            // UTF-8"选项，CP_ACP=65001），这种机器上任何字符的往返都无损，不是
            // 缺陷。断言必须先问一遍"这台机器上到底有损没有"，不能假设固定结果，
            // 否则在 UTF-8-ANSI 的机器上会把一个正确实现误判成失败（已实测踩过）。
            dlg.setEncoding(Enc::Ansi);
            const bool emojiLossyHere =
                (QString::fromLocal8Bit(QStringLiteral("😀").toLocal8Bit()) != QStringLiteral("😀"));
            if (emojiLossyHere)
            {
                WPG_CHECK(dlg.resultBytes().isEmpty());
                WPG_CHECK(dlg.previewText() == ks::ui::workbench_messages::StringWriteAnsiLossyText());
                WPG_CHECK_NOTE(!findOkButton()->isEnabled(), QStringLiteral("ANSI 有损时写入按钮必须禁用"));
            }
            else
            {
                // 本机 ANSI 代码页恰好是 UTF-8 全集：任何字符都无损，不得被误判成
                // 有损（resultBytes 必须原样等于 toLocal8Bit 的结果，按钮仍可点）。
                WPG_CHECK(!dlg.resultBytes().isEmpty());
                WPG_CHECK(findOkButton()->isEnabled());
            }
            // 补一个不依赖本机代码页的有损用例：孤立的高位代理（没有配对的低位
            // 代理）是不合法的 UTF-16，任何编码（包括 UTF-8 全集的 ANSI 代码页）
            // 都表示不了一个"合法字符"，往返必然有损——这条断言在任何机器上都
            // 该成立，不必像表情符号那样分支讨论。
            QString loneSurrogate;
            loneSurrogate += QChar(0xD800);
            dlg.setText(loneSurrogate);
            WPG_CHECK(dlg.resultBytes().isEmpty());
            WPG_CHECK(dlg.previewText() == ks::ui::workbench_messages::StringWriteAnsiLossyText());

            dlg.setText(QString());                                   // B10：空内容不能点"写入"
            dlg.setEncoding(Enc::Utf8);
            dlg.setAppendNul(false);
            WPG_CHECK(dlg.resultBytes().isEmpty());
            WPG_CHECK(!findOkButton()->isEnabled());
            dlg.setText(QStringLiteral("x"));                         // 恢复非空文本后按钮要能重新可点
            WPG_CHECK(findOkButton()->isEnabled());
        }

        // ---- T10（M22/M24/M33）：写入模式胶囊 + 会话条请求信号的参数 ----
        void RunModeSwitchAndSignalsTest()
        {
            ks::ui::WriteModeSwitch sw;
            sw.show();
            int count = 0;
            WriteMode last = WriteMode::Immediate;
            QObject::connect(&sw, &ks::ui::WriteModeSwitch::modeToggleRequested, [&count, &last](WriteMode mode) { ++count; last = mode; });
            const QList<QToolButton*> buttons = sw.findChildren<QToolButton*>();
            WPG_CHECK(buttons.size() == 2);
            buttons[0]->click();                                      // 点当前已高亮的一半：不是切换请求
            WPG_CHECK(count == 0);
            buttons[1]->click();
            WPG_CHECK(count == 1 && last == WriteMode::StagedThenApply);
            WPG_CHECK(sw.mode() == WriteMode::Immediate);             // 请求不代表生效
            QKeyEvent space(QEvent::KeyPress, Qt::Key_Space, Qt::NoModifier);
            QCoreApplication::sendEvent(&sw, &space);
            WPG_CHECK(count == 2 && last == WriteMode::StagedThenApply);
            sw.setMode(WriteMode::StagedThenApply);
            QCoreApplication::sendEvent(&sw, &space);
            WPG_CHECK(count == 3 && last == WriteMode::Immediate);

            ks::ui::WorkbenchSessionBar bar;
            bar.show();
            std::vector<WriteMode> modes;
            std::vector<Scope> scopes;
            QObject::connect(&bar, &ks::ui::WorkbenchSessionBar::modeRequested, [&modes](WriteMode mode) { modes.push_back(mode); });
            QObject::connect(&bar, &ks::ui::WorkbenchSessionBar::scopeRequested, [&scopes](Scope scope) { scopes.push_back(scope); });
            bar.writeModeSwitch()->findChildren<QToolButton*>()[1]->click();
            WPG_CHECK(modes.size() == 1 && modes[0] == WriteMode::StagedThenApply);
            bar.scopeSegmented()->setCurrentIndex(2);
            WPG_CHECK(scopes.size() == 1 && scopes[0] == Scope::Physical);
            bar.scopeSegmented()->setCurrentIndex(1);
            WPG_CHECK(scopes.size() == 2 && scopes[1] == Scope::KernelVirtual);
        }

        // ---- T11（M30/M31，及 B3）：目标 chip 文案 / 待写入区 ----
        void RunChipAndPendingTest()
        {
            ks::ui::WorkbenchSessionBar bar;
            bar.show();
            int pickRequests = 0;
            QObject::connect(&bar, &ks::ui::WorkbenchSessionBar::pickTargetRequested, [&pickRequests]() { ++pickRequests; });
            const auto findChip = [&bar]() {
                for (QToolButton* button : bar.findChildren<QToolButton*>())
                {
                    // 目标 chip = 带文字的 QToolButton，但写入模式胶囊的两个半边现在也带文字（即时/暂存），要排除。
                    if (!button->text().isEmpty() && qobject_cast<ks::ui::WriteModeSwitch*>(button->parentWidget()) == nullptr) { return button; }
                }
                return static_cast<QToolButton*>(nullptr);
            };
            bar.setTargetInfo(true, QStringLiteral("a.exe"), 7, 32, false);
            WPG_CHECK(findChip()->text().contains(QStringLiteral("a.exe"))
                && findChip()->text().contains(QStringLiteral("只读"))
                && findChip()->text().contains(QStringLiteral("x32")));
            bar.setTargetInfo(true, QStringLiteral("a.exe"), 7, 64, true);
            WPG_CHECK(findChip()->text().contains(QStringLiteral("可读写")));
            bar.setTargetInfo(false, QString(), 0, 64, false);
            WPG_CHECK(findChip()->text().contains(QStringLiteral("未附加")));
            findChip()->click();
            WPG_CHECK(pickRequests == 1);                             // 进程范围点击仍正常发请求

            QWidget* pending = nullptr;                               // 待写入区：字节数为 0 才隐藏（块数不是判据）
            for (QToolButton* button : bar.findChildren<QToolButton*>())
            {
                if (button->toolTip().contains(QStringLiteral("丢弃"))) { pending = button; }
            }
            WPG_CHECK(pending != nullptr);
            bar.setPendingPatches(0, 3);
            WPG_CHECK(!pending->isVisible());
            bar.setPendingPatches(12, 0);
            WPG_CHECK(pending->isVisible());
            bar.setPendingPatches(0, 0);
            WPG_CHECK(!pending->isVisible());

            bar.setScope(Scope::KernelVirtual);                       // B3：内核范围不需要进程
            WPG_CHECK(!findChip()->text().contains(QStringLiteral("未附加")));
            WPG_CHECK(findChip()->text() == ks::ui::workbench_messages::TargetChipNoProcessText(Scope::KernelVirtual));
            findChip()->click();                                      // 点击不该发出"选进程"请求
            WPG_CHECK(pickRequests == 1);

            bar.setScope(Scope::Physical);
            WPG_CHECK(findChip()->text() == ks::ui::workbench_messages::TargetChipNoProcessText(Scope::Physical));
            bar.setScope(Scope::ProcessVirtual);                      // 切回进程范围要恢复原来的附加文案
            WPG_CHECK(findChip()->text().contains(QStringLiteral("未附加")));
            findChip()->click();
            WPG_CHECK(pickRequests == 2);
        }

        // ---- T12（B14，已修）：setScope 后旧判据不得让不支持的通道看起来可用 ----
        void RunStaleVerdictAfterScopeTest()
        {
            ks::ui::WorkbenchSessionBar bar;
            bar.show();
            std::array<GateVerdict, 4> allOk{};
            for (GateVerdict& verdict : allOk) { verdict = GateVerdict{ true, GateReason::None }; }
            bar.setChannelVerdicts(allOk);
            bar.setScope(Scope::KernelVirtual);                       // 调用方尚未喂新判据
            WPG_CHECK(!bar.channelSegmented()->isSegmentEnabled(0));  // R3 在内核范围不支持
            bar.setScope(Scope::ProcessVirtual);                      // 切回去，旧判据必须原样还在
            WPG_CHECK(bar.channelSegmented()->isSegmentEnabled(0));   // 不能被 B14 的兜底永久污染
        }

        // ---- T13（B4/S1，已修）：状态条最小宽度不得棘轮式变大 ----
        void RunStatusBarRatchetTest()
        {
            QWidget host;
            auto* layout = new QVBoxLayout(&host);
            auto* statusBar = new ks::ui::WorkbenchStatusBar(std::make_unique<FakeDiagnosticsHost>(), &host);
            statusBar->setChannelScopeText(QStringLiteral("R0 · 进程"));
            statusBar->setReadResultText(QStringLiteral("已读 4096/4096 字节"), false);
            statusBar->setWindowRangeText(QStringLiteral("0x00007FF6_1000..0x00007FF6_2000"));
            statusBar->setWriteResultText(QStringLiteral("已写入并回读确认。 已写入 96 字节（3 块）。 (verify mismatch on block 2 of 3, retry later or discard the staged patches)"));
            layout->addWidget(statusBar);
            host.resize(360, 160);
            host.show();
            QCoreApplication::processEvents();
            host.resize(1200, 160);
            QCoreApplication::processEvents();
            host.resize(300, 160);
            QCoreApplication::processEvents();
            WPG_CHECK(host.width() <= 340);
        }

        // ---- S1：摘要四段必须是各自独立的 QLabel（原文一字不差），不是拼接后的
        // 一整条字符串——运行期整句翻译按控件逐一匹配，拼接字符串匹配不到任何
        // 已登记词条 ----
        void RunSummarySegmentLabelsTest()
        {
            auto statusBar = std::make_unique<ks::ui::WorkbenchStatusBar>(std::make_unique<FakeDiagnosticsHost>());
            statusBar->resize(900, 90);
            statusBar->show();
            statusBar->setChannelScopeText(QStringLiteral("R0 · 进程"));
            statusBar->setReadResultText(QStringLiteral("已读 4096/4096 字节"), false);
            statusBar->setWindowRangeText(QStringLiteral("0x1000..0x2000"));
            int exactMatches = 0;
            for (QLabel* label : statusBar->findChildren<QLabel*>())
            {
                if (label->text() == QStringLiteral("R0 · 进程")
                    || label->text() == QStringLiteral("已读 4096/4096 字节")
                    || label->text() == QStringLiteral("0x1000..0x2000"))
                {
                    ++exactMatches;
                }
            }
            WPG_CHECK_NOTE(exactMatches == 3, QStringLiteral("应有三个独立 QLabel 各自持有一段原文"));
            // 整条拼接字符串不应该作为任何单个 QLabel 的 text()（那正是旧缺陷的形状）。
            bool foundConcatenated = false;
            for (QLabel* label : statusBar->findChildren<QLabel*>())
            {
                if (label->text().contains(QStringLiteral("进程")) && label->text().contains(QStringLiteral("0x1000")))
                {
                    foundConcatenated = true;
                }
            }
            WPG_CHECK(!foundConcatenated);
        }

        // ---- B12：诊断抽屉"自动换行"勾选框必须真的接到 SetWrapEnabled ----
        void RunDiagnosticsWrapTest()
        {
            auto host = std::make_unique<FakeDiagnosticsHost>();
            FakeDiagnosticsHost* rawHost = host.get();
            ks::ui::WorkbenchStatusBar statusBar(std::move(host));
            statusBar.show();
            WPG_CHECK(rawHost->IsWrapEnabled());                      // 默认勾选=换行
            QCheckBox* wrapCheckBox = nullptr;
            for (QCheckBox* checkBox : statusBar.findChildren<QCheckBox*>())
            {
                if (checkBox->text() == ks::ui::workbench_messages::DiagnosticsWrapCheckboxText()) { wrapCheckBox = checkBox; }
            }
            WPG_CHECK(wrapCheckBox != nullptr);
            wrapCheckBox->setChecked(false);
            WPG_CHECK(!rawHost->IsWrapEnabled());
            wrapCheckBox->setChecked(true);
            WPG_CHECK(rawHost->IsWrapEnabled());
        }

        // ---- B11：文案映射枚举全覆盖（IoReadStatus/SessionError/ModeSwitchStatus/
        // StageStatus 各自非空且互不相同；GateReason 越界也不得返回空串）----
        void RunMessageEnumCoverageTest()
        {
            const IoReadStatus ioStatuses[] = {
                IoReadStatus::Ok, IoReadStatus::Partial, IoReadStatus::Unreadable, IoReadStatus::Failed,
            };
            QStringList ioSeen;
            for (const IoReadStatus status : ioStatuses)
            {
                const QString text = ks::ui::workbench_messages::Translate(status);
                WPG_CHECK(!text.isEmpty() && !ioSeen.contains(text));
                ioSeen << text;
            }
            // Failed 与 Unreadable 的语义不同（通道自身失败 vs 目标本身不可读），
            // 文案绝不能共用同一句。
            WPG_CHECK(ks::ui::workbench_messages::Translate(IoReadStatus::Failed)
                != ks::ui::workbench_messages::Translate(IoReadStatus::Unreadable));

            const SessionError sessionErrors[] = {
                SessionError::NeedsPid, SessionError::PidMustBeZero, SessionError::BadAddressBits,
                SessionError::BadScope, SessionError::BadChannel,
            };
            QStringList sessionSeen;
            WPG_CHECK(ks::ui::workbench_messages::Translate(SessionError::None).isEmpty());
            for (const SessionError error : sessionErrors)
            {
                const QString text = ks::ui::workbench_messages::Translate(error);
                WPG_CHECK(!text.isEmpty() && !sessionSeen.contains(text));
                sessionSeen << text;
            }

            const ModeSwitchStatus modeStatuses[] = {
                ModeSwitchStatus::Switched, ModeSwitchStatus::NeedsDecision, ModeSwitchStatus::Cancelled,
                ModeSwitchStatus::ApplyFailed, ModeSwitchStatus::NoPendingSwitch, ModeSwitchStatus::Busy,
            };
            QStringList modeSeen;
            for (const ModeSwitchStatus status : modeStatuses)
            {
                const QString text = ks::ui::workbench_messages::Translate(status);
                WPG_CHECK(!text.isEmpty() && !modeSeen.contains(text));
                modeSeen << text;
            }

            const StageStatus stageStatuses[] = {
                StageStatus::Ok, StageStatus::Empty, StageStatus::AddressOverflow,
                StageStatus::OutOfWindow, StageStatus::UnreadBytes, StageStatus::TooLarge,
            };
            QStringList stageSeen;
            for (const StageStatus status : stageStatuses)
            {
                const QString text = ks::ui::workbench_messages::Translate(status);
                WPG_CHECK(!text.isEmpty() && !stageSeen.contains(text));
                stageSeen << text;
            }

            // GateReason：0..7 是合法值，8 故意越界——必须带代码的兜底句，不是空串。
            QStringList gateSeen;
            for (quint32 raw = 0; raw <= 8; ++raw)
            {
                const GateVerdict verdict{ false, static_cast<GateReason>(raw) };
                const QString text = ks::ui::workbench_messages::ChannelUnavailableReason(Channel::StandardDriver, verdict);
                if (raw == static_cast<quint32>(GateReason::None))
                {
                    continue;   // None 配 available=false 不是真实组合，跳过（verdict.available 恒假时不会是 None）
                }
                WPG_CHECK_NOTE(!text.isEmpty(), QStringLiteral("GateReason raw=%1 不得返回空串").arg(raw));
                if (raw == 8)
                {
                    WPG_CHECK_NOTE(text.contains(QStringLiteral("代码")), text);
                }
                WPG_CHECK_NOTE(!gateSeen.contains(text), text);   // 互不相同，防复制粘贴漏改
                gateSeen << text;
            }
        }

    }

    void RunGapTests2()
    {
        RunSettingsTest();
        RunActionsTest();
        RunStringDialogTest();
        RunModeSwitchAndSignalsTest();
        RunChipAndPendingTest();
        RunStaleVerdictAfterScopeTest();
        RunStatusBarRatchetTest();
        RunSummarySegmentLabelsTest();
        RunDiagnosticsWrapTest();
        RunMessageEnumCoverageTest();
    }
}
