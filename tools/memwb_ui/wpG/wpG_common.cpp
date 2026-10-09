#include "wpG_common.h"

// ============================================================
// wpG_common.cpp
// 作用：见头文件。FakeByteStore 的切片逻辑只服务"整块覆盖在 readBytes 范围内"
// 的简单场景，够夹具用；真实端口的分块/二分策略属于 WP-C，不在本文件复刻。
// ============================================================

#include "../../../Ksword5.1/Ksword5.1/theme.h"

#include <QApplication>
#include <QColor>
#include <QPalette>
#include <QPlainTextEdit>

#include <algorithm>
#include <cstdio>

namespace wpg_test
{
    int g_checks = 0;
    int g_failures = 0;

    void Report(const bool ok, const char* expression, const char* file, int line, const QString& note)
    {
        ++g_checks;
        if (ok)
        {
            return;
        }
        ++g_failures;
        std::fprintf(
            stderr, "[FAIL] %s:%d  %s%s\n", file, line, expression,
            note.isEmpty() ? "" : qPrintable(QStringLiteral("  (%1)").arg(note)));
    }

    void ApplyTheme(const bool dark)
    {
        // 先切 KswordTheme 的深浅状态：控件 paint 里现取的静态颜色访问器
        // （TextPrimaryColor 等）读的是它，不是 QPalette。只改调色板会让深色截图里
        // 出现"深色字画在深色底上"的假象（主会话审核时发现，其它夹具都有这一行）。
        KswordTheme::SetDarkModeEnabled(dark);
        QPalette palette = QApplication::palette();
        if (dark)
        {
            palette.setColor(QPalette::Window, QColor(32, 32, 36));
            palette.setColor(QPalette::WindowText, QColor(230, 230, 232));
            palette.setColor(QPalette::Base, QColor(24, 24, 28));
            palette.setColor(QPalette::AlternateBase, QColor(40, 40, 44));
            palette.setColor(QPalette::Text, QColor(230, 230, 232));
            palette.setColor(QPalette::Button, QColor(44, 44, 48));
            palette.setColor(QPalette::ButtonText, QColor(230, 230, 232));
            palette.setColor(QPalette::Highlight, QColor(64, 128, 222));
            palette.setColor(QPalette::HighlightedText, QColor(255, 255, 255));
            palette.setColor(QPalette::PlaceholderText, QColor(140, 140, 146));
            palette.setColor(QPalette::Disabled, QPalette::WindowText, QColor(120, 120, 124));
            palette.setColor(QPalette::Disabled, QPalette::Text, QColor(120, 120, 124));
            palette.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(120, 120, 124));
        }
        else
        {
            palette.setColor(QPalette::Window, QColor(244, 244, 246));
            palette.setColor(QPalette::WindowText, QColor(24, 24, 28));
            palette.setColor(QPalette::Base, QColor(255, 255, 255));
            palette.setColor(QPalette::AlternateBase, QColor(238, 238, 240));
            palette.setColor(QPalette::Text, QColor(24, 24, 28));
            palette.setColor(QPalette::Button, QColor(236, 236, 238));
            palette.setColor(QPalette::ButtonText, QColor(24, 24, 28));
            palette.setColor(QPalette::Highlight, QColor(32, 108, 212));
            palette.setColor(QPalette::HighlightedText, QColor(255, 255, 255));
            palette.setColor(QPalette::PlaceholderText, QColor(120, 120, 124));
            palette.setColor(QPalette::Disabled, QPalette::WindowText, QColor(170, 170, 174));
            palette.setColor(QPalette::Disabled, QPalette::Text, QColor(170, 170, 174));
            palette.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(170, 170, 174));
        }
        qApp->setPalette(palette);
    }

    QImage GrabImage(QWidget& widget)
    {
        return widget.grab().toImage().convertToFormat(QImage::Format_ARGB32);
    }

    bool FakeConfirmPrompter::PromptUiConfirm(
        const ksword::memwb::UiConfirmRequest& request,
        const ksword::memwb::Scope scope,
        const ksword::memwb::Channel channel,
        const QString& targetDescription,
        const bool offerDontAskAgain,
        bool& dontAskAgainChecked)
    {
        ++uiConfirmCalls;
        lastOfferDontAskAgain = offerDontAskAgain;
        lastUiConfirmRequest = request;
        lastUiConfirmScope = scope;
        lastUiConfirmChannel = channel;
        lastUiConfirmTargetDescription = targetDescription;
        dontAskAgainChecked = false;
        if (uiConfirmAnswers.empty())
        {
            return false;
        }
        const bool answer = uiConfirmAnswers.front();
        uiConfirmAnswers.erase(uiConfirmAnswers.begin());
        if (answer && !uiConfirmDontAskAgain.empty())
        {
            dontAskAgainChecked = uiConfirmDontAskAgain.front();
            uiConfirmDontAskAgain.erase(uiConfirmDontAskAgain.begin());
        }
        return answer;
    }

    ksword::memwb::ApprovalAnswer FakeConfirmPrompter::PromptApproval(
        const ksword::memwb::ApprovalRequest& request,
        const ksword::memwb::Scope scope,
        const ksword::memwb::Channel channel,
        const QString& targetDescription,
        const bool offerRestOfBatch)
    {
        ++approvalCalls;
        lastOfferRestOfBatch = offerRestOfBatch;
        lastApprovalRequest = request;
        lastApprovalScope = scope;
        lastApprovalChannel = channel;
        lastApprovalTargetDescription = targetDescription;
        if (approvalAnswers.empty())
        {
            return ksword::memwb::ApprovalAnswer::Deny;
        }
        const ksword::memwb::ApprovalAnswer answer = approvalAnswers.front();
        approvalAnswers.erase(approvalAnswers.begin());
        return answer;
    }

    ksword::memwb::ModeSwitchDecision FakeConfirmPrompter::PromptModeSwitch(
        ksword::memwb::WriteMode /*fromMode*/,
        ksword::memwb::WriteMode /*toMode*/,
        std::uint64_t /*pendingBytes*/,
        std::uint64_t /*pendingBlocks*/)
    {
        ++modeSwitchCalls;
        if (modeSwitchAnswers.empty())
        {
            return ksword::memwb::ModeSwitchDecision::Cancel;
        }
        const ksword::memwb::ModeSwitchDecision decision = modeSwitchAnswers.front();
        modeSwitchAnswers.erase(modeSwitchAnswers.begin());
        return decision;
    }

    ksword::memwb::ModeSwitchDecision FakeConfirmPrompter::PromptLeaveWithPending(
        const std::uint64_t pendingBytes, const std::uint64_t pendingBlocks, const QString& reasonText)
    {
        ++leaveWithPendingCalls;
        lastLeaveWithPendingBytes = pendingBytes;
        lastLeaveWithPendingBlocks = pendingBlocks;
        lastLeaveWithPendingReasonText = reasonText;
        if (leaveWithPendingAnswers.empty())
        {
            return ksword::memwb::ModeSwitchDecision::Cancel;
        }
        const ksword::memwb::ModeSwitchDecision decision = leaveWithPendingAnswers.front();
        leaveWithPendingAnswers.erase(leaveWithPendingAnswers.begin());
        return decision;
    }

    ksword::memwb::AccessResult FakeByteStore::Read(const std::uint64_t address, const std::uint64_t length)
    {
        ksword::memwb::AccessResult result;
        if (address < baseAddress || address + length > baseAddress + readBytes.size())
        {
            result.ok = false;
            result.failureText = "address out of fake store range";
            return result;
        }
        const std::size_t offset = static_cast<std::size_t>(address - baseAddress);
        result.ok = true;
        result.data.assign(
            readBytes.begin() + static_cast<std::ptrdiff_t>(offset),
            readBytes.begin() + static_cast<std::ptrdiff_t>(offset + length));
        result.bytesDone = length;
        return result;
    }

    ksword::memwb::AccessResult FakeByteStore::Write(
        const std::uint64_t address, const std::vector<std::uint8_t>& bytes, const bool explicitApproval)
    {
        ++writeCalls;
        ksword::memwb::AccessResult result;
        if (nextWriteNeedsApproval && !explicitApproval)
        {
            nextWriteNeedsApproval = false;
            result.ok = false;
            result.needsExplicitApproval = true;
            result.failureText = "fake backend requires explicit approval";
            return result;
        }
        if (failNextWrite)
        {
            failNextWrite = false;
            result.ok = false;
            result.failureText = "fake backend forced failure";
            return result;
        }
        if (address < baseAddress || address + bytes.size() > baseAddress + readBytes.size())
        {
            result.ok = false;
            result.failureText = "address out of fake store range";
            return result;
        }
        const std::size_t offset = static_cast<std::size_t>(address - baseAddress);
        std::copy(bytes.begin(), bytes.end(), readBytes.begin() + static_cast<std::ptrdiff_t>(offset));
        result.ok = true;
        result.bytesDone = bytes.size();
        return result;
    }

    void NullAuditSink::Record(const ksword::memwb::AuditRecord& /*record*/)
    {
        ++recordCalls;
    }

    FakeDiagnosticsHost::FakeDiagnosticsHost(QWidget* parent)
    {
        m_edit = new QPlainTextEdit(parent);
        m_edit->setReadOnly(true);
    }

    QWidget* FakeDiagnosticsHost::HostWidget()
    {
        return m_edit;
    }

    void FakeDiagnosticsHost::SetDiagnosticsText(const QString& text)
    {
        m_documentActive = false;
        m_edit->setPlainText(text);
    }

    void FakeDiagnosticsHost::SetDiagnosticsDocument(const ks::ui::FieldDocument& document)
    {
        m_document = document;
        m_documentActive = true;
    }

    QString FakeDiagnosticsHost::DiagnosticsText() const
    {
        return m_documentActive ? m_document.toPlainText(true) : m_edit->toPlainText();
    }

    void FakeDiagnosticsHost::SetWrapEnabled(const bool wrap)
    {
        m_edit->setLineWrapMode(wrap ? QPlainTextEdit::WidgetWidth : QPlainTextEdit::NoWrap);
    }

    bool FakeDiagnosticsHost::IsWrapEnabled() const
    {
        return m_edit->lineWrapMode() == QPlainTextEdit::WidgetWidth;
    }
}
