#include "wpG_common.h"

// ============================================================
// wpG_tests.StatusBar.cpp
// 作用：验证 WorkbenchStatusBar 的 chip 持久化规则（不变式 14）与
// WorkbenchMessages::Translate(CommitOutcome)/CommitReportSummary 的文案覆盖。
// ============================================================

#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchMessages.h"

namespace wpg_test
{
    using ksword::memwb::CommitOutcome;
    using ksword::memwb::CommitReport;

    void RunStatusBarTests()
    {
        auto host = std::make_unique<FakeDiagnosticsHost>();
        ks::ui::WorkbenchStatusBar statusBar(std::move(host));
        statusBar.resize(700, 90);
        statusBar.show(); // 同 SessionBar 测试：isVisible() 需要整条祖先链真的 show() 过。

        // —— 不变式 14：暂存扇区脏 chip 一旦出现过，后续报告"干净"也不会自动消失 ——
        WPG_CHECK(!statusBar.isScratchAreaDirtyChipVisible());
        statusBar.reportScratchAreaDirty(true);
        WPG_CHECK(statusBar.isScratchAreaDirtyChipVisible());
        statusBar.reportScratchAreaDirty(false); // 这一次干净，但 chip 必须仍然显示
        WPG_CHECK(statusBar.isScratchAreaDirtyChipVisible());
        // 成功也要显示：即便本次写入是 Committed，脏旗标仍然保留。
        statusBar.setWriteResultText(ks::ui::workbench_messages::Translate(CommitOutcome::Committed));
        WPG_CHECK(statusBar.isScratchAreaDirtyChipVisible());
        statusBar.acknowledgeScratchAreaDirty(); // 只有点 × 才消
        WPG_CHECK(!statusBar.isScratchAreaDirtyChipVisible());
        statusBar.reportScratchAreaDirty(true); // 确认后可以再次出现
        WPG_CHECK(statusBar.isScratchAreaDirtyChipVisible());

        // —— 读-改-写窗口 chip：不常驻，只反映最近一次 ——
        statusBar.setReadModifyWriteWindow(true);
        WPG_CHECK(statusBar.isReadModifyWriteWindowChipVisible());
        statusBar.setReadModifyWriteWindow(false);
        WPG_CHECK(!statusBar.isReadModifyWriteWindowChipVisible());

        // —— 诊断抽屉：错误时自动展开，文本原样可读回 ——
        WPG_CHECK(!statusBar.isDrawerExpanded());
        statusBar.setDiagnosticsText(QStringLiteral("示例诊断文本：地址越界"), true);
        WPG_CHECK(statusBar.isDrawerExpanded());
        WPG_CHECK(statusBar.diagnosticsText() == QStringLiteral("示例诊断文本：地址越界"));
        ks::ui::FieldDocument document;
        document.field(QStringLiteral("地址"), QStringLiteral("raw_%2:[x]\nvalue"));
        statusBar.setDiagnosticsDocument(document, true);
        WPG_CHECK(statusBar.diagnosticsText() == document.toPlainText(true));
        statusBar.setDiagnosticsText(QStringLiteral("后续原始诊断"), false);
        WPG_CHECK(statusBar.diagnosticsText() == QStringLiteral("后续原始诊断"));
        statusBar.setDrawerExpanded(false);
        WPG_CHECK(!statusBar.isDrawerExpanded());

        // —— 摘要拼接：五段按顺序、空段跳过 ——
        statusBar.setChannelScopeText(QStringLiteral("R0 · 进程"));
        statusBar.setReadResultText(QStringLiteral("已读 4096/4096 字节"), false);
        statusBar.setWindowRangeText(QStringLiteral("0x1000..0x2000"));
        const QString summary = statusBar.summaryText();
        WPG_CHECK(summary.contains(QStringLiteral("R0 · 进程")));
        WPG_CHECK(summary.contains(QStringLiteral("0x1000..0x2000")));

        // —— CommitOutcome 枚举逐项都有非空文案，且互不相同（防止复制粘贴漏改）——
        const CommitOutcome outcomes[] = {
            CommitOutcome::NoChange, CommitOutcome::Committed, CommitOutcome::UserCancelled,
            CommitOutcome::Stale, CommitOutcome::TargetChanged, CommitOutcome::ApprovalDenied,
            CommitOutcome::WriteFailed, CommitOutcome::VerifyMismatch, CommitOutcome::InvalidSession,
            CommitOutcome::Busy,
        };
        QStringList seen;
        for (const CommitOutcome outcome : outcomes)
        {
            const QString text = ks::ui::workbench_messages::Translate(outcome);
            WPG_CHECK_NOTE(!text.isEmpty(), QStringLiteral("outcome=%1").arg(static_cast<int>(outcome)));
            WPG_CHECK_NOTE(!seen.contains(text), text);
            seen << text;
        }

        // —— CommitReportSummary：Committed 带块数/字节数；NoChange 不带 ——
        CommitReport committed;
        committed.outcome = CommitOutcome::Committed;
        committed.blocksWritten = 3;
        committed.bytesWritten = 96;
        const QString committedText = ks::ui::workbench_messages::CommitReportSummary(committed);
        WPG_CHECK(committedText.contains(QStringLiteral("96")));
        WPG_CHECK(committedText.contains(QStringLiteral("3")));

        CommitReport noChange;
        noChange.outcome = CommitOutcome::NoChange;
        const QString noChangeText = ks::ui::workbench_messages::CommitReportSummary(noChange);
        WPG_CHECK(!noChangeText.contains(QStringLiteral("块")));
    }
}
