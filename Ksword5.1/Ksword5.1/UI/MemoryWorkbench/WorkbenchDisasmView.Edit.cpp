// WorkbenchDisasmView.Edit.cpp
// 作用：行内编辑委托（双击/F2/Enter 进入，Enter 编译提交，失败不关编辑框）与右键
// "汇编编辑"共用 AssemblyPreviewDialog 的覆盖长度、NOP 填充和边界校验，
// 本宿主提供自己的覆盖预算与提交信号。
// 两条路径最终都只发 stageRequested 信号，本文件不直接写任何内存。

#include "WorkbenchDisasmView.h"
#include "AssemblyPreviewDialog.h"
#include "../CodeTextEdit.h"
#include "MemoryRowCanvas.h"

#include "HexCanvasFormat.h"

#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"

#include <QCheckBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QScreen>
#include <QSpinBox>
#include <QTimer>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <functional>

namespace ks::ui
{
    void WorkbenchDisasmView::beginSelectedInstructionEdit() { beginRowEdit(m_canvas->selectedRow()); }
    void WorkbenchDisasmView::beginRowEdit(int index)
    {
        if (!m_editable || m_editingActive || !m_model->rowAt(index)) return;
        const auto row = *m_model->rowAt(index);
        if (!row.decoded || row.bytes.isEmpty()) return;
        m_canvas->setSelectedRow(index);
        auto* editor = new QLineEdit(m_canvas->viewport());
        m_inlineEditor = editor;
        editor->setObjectName(QStringLiteral("ksMemwbDisasmInlineEditor"));
        editor->setFont(m_canvas->font());
        const QString original = (row.mnemonic + QLatin1Char(' ') + row.operands).trimmed();
        editor->setText(original);
        editor->setProperty("ksOriginalSource", original);
        editor->setProperty("ksAddress", QVariant::fromValue<qulonglong>(row.address));
        editor->setProperty("ksOldBytes", row.bytes);
        editor->setProperty("ksX64", isX64());
        editor->setProperty("ks_edit_context_revision", QVariant::fromValue<qulonglong>(m_editContextRevision));
        editor->setGeometry(m_canvas->contentRect(index));
        editor->installEventFilter(this);
        m_editingActive = true;
        editor->show(); editor->setFocus(); editor->selectAll();
        connect(editor, &QLineEdit::returnPressed, this, &WorkbenchDisasmView::commitInlineEdit);
    }
    void WorkbenchDisasmView::cancelInlineEdit()
    {
        QLineEdit* editor = m_inlineEditor;
        m_inlineEditor = nullptr;
        m_editingActive = false;
        if (editor) { editor->removeEventFilter(this); editor->hide(); editor->deleteLater(); }
        hideInlineEditError();
        m_canvas->setFocus();
        if (m_refreshPending) { m_refreshPending = false; rebuildRowsNow(); }
    }
    void WorkbenchDisasmView::commitInlineEdit()
    {
        QLineEdit* editor = m_inlineEditor;
        if (!editor) return;
            const QString source = editor->text().trimmed();
            const QString originalSource = editor->property("ksOriginalSource").toString();
            if (source == originalSource)
            {
                // D1：文本一字未改，直接关闭编辑框，不编译、不比较字节、不发信号。
                hideInlineEditError();
                cancelInlineEdit(); return;
            }
            if (!m_assembleOne)
            {
                showInlineEditError(editor->geometry(), QStringLiteral("未设置汇编后端，无法编译。")); return;
            }
            const std::uint64_t address = editor->property("ksAddress").toULongLong();
            const QByteArray oldBytes = editor->property("ksOldBytes").toByteArray();
            const bool x64 = editor->property("ksX64").toBool();
            // 会话复用同一 provider、架构或权限变化时，旧编辑器冻结的地址不能被新目标继承。
            const std::uint64_t editRevision = editor->property("ks_edit_context_revision").toULongLong();
            if (!m_editable || m_provider == nullptr || editRevision != m_editContextRevision || x64 != isX64())
            {
                const QString error = QStringLiteral("数据已刷新，原指令不再位于当前视图，已取消本次汇编编辑。");
                showInlineEditError(editor->geometry(), error);
                return;
            }
            // 编辑期间实时重读可能已更新基线。逐字节复核原指令，防止按旧指令长度覆盖新代码。
            const WorkbenchByteWindow currentWindow = m_provider->FetchWindow(address, static_cast<std::uint64_t>(oldBytes.size()));
            bool originalBytesMatch = currentWindow.ok && currentWindow.address == address
                && currentWindow.bytes.size() >= static_cast<std::size_t>(oldBytes.size())
                && currentWindow.validMask.size() >= static_cast<std::size_t>(oldBytes.size());
            for (qsizetype i = 0; originalBytesMatch && i < oldBytes.size(); ++i)
            {
                const std::size_t index = static_cast<std::size_t>(i);
                originalBytesMatch = currentWindow.validMask[index] == 1
                    && currentWindow.bytes[index] == static_cast<std::uint8_t>(oldBytes[i]);
            }
            if (!originalBytesMatch)
            {
                const QString error = QStringLiteral("数据已刷新，原指令不再位于当前视图，已取消本次汇编编辑。");
                showInlineEditError(editor->geometry(), error);
                return;
            }
            const WorkbenchAssembleResult result = m_assembleOne(source, address, x64);
            if (!result.success)
            {
                showInlineEditError(editor->geometry(), result.error);
                return;
            }
            // 行内只接受一条完整指令：先复核未填充的机器码，不能把多条指令或尾部残片
            // 当成一条短指令补 NOP；右键汇编编辑仍使用自己的多行预览与边界校验。
            // decodedInstruction：按编辑开始时冻结的真实地址和架构解出的首条指令。
            std::optional<DecodedRow> decodedInstruction;
            if (m_decodeOne && !result.bytes.isEmpty())
            {
                decodedInstruction = m_decodeOne(
                    reinterpret_cast<const std::uint8_t*>(result.bytes.constData()),
                    static_cast<std::size_t>(result.bytes.size()), address, x64);
            }
            if (!decodedInstruction.has_value() || !decodedInstruction->decoded
                || decodedInstruction->bytes != result.bytes)
            {
                const QString error = ks::i18n::sourceText(QStringLiteral(
                    "行内编辑只接受一条完整指令；多行汇编请使用右键汇编编辑。"));
                showInlineEditError(editor->geometry(), error);
                return;
            }
            if (result.bytes.size() > oldBytes.size())
            {
                const QString error = QStringLiteral("新指令为 %1 字节，超出原指令的 %2 字节；请使用右键"
                    "“汇编编辑”并明确调整覆盖长度。").arg(result.bytes.size()).arg(oldBytes.size());
                showInlineEditError(editor->geometry(), error);
                return;
            }
            // 较短的新指令用 NOP 补满原指令长度，保持后续指令的边界不变（不变式 10）。
            QByteArray payload = result.bytes;
            payload.append(QByteArray(oldBytes.size() - payload.size(), static_cast<char>(0x90)));
            hideInlineEditError();
            // D1 后半：文本变了，但编译后的字节跟原字节逐位相同（例如换了一种写法但编码
            // 一样），同样不算真正的修改，不发信号——否则宿主会把"没有变化"的补丁也暂存。
            cancelInlineEdit();
            if (payload != oldBytes) emit stageRequested(address, payload);

    }
    void WorkbenchDisasmView::showInlineEditError(const QRect& rect, const QString& message)
    {
        m_inlineError->setText(ks::i18n::displayText(message));
        m_inlineError->setGeometry(rect.left(), std::min(rect.bottom()+2, std::max(0, m_canvas->viewport()->height()-m_inlineError->sizeHint().height())), rect.width(), m_inlineError->sizeHint().height());
        m_inlineError->show(); m_inlineError->raise();
    }
    void WorkbenchDisasmView::hideInlineEditError() { m_inlineError->hide(); }

    void WorkbenchDisasmView::showAssemblyPreviewDialog(const DecodedRow& expectedRow)
    {
        if (!m_editable || m_provider == nullptr || !m_decodeOne || !m_assembleOne)
        {
            return;
        }
        int matchedRow = -1;
        for (int i = 0; i < m_model->rowCount(); ++i)
        {
            const std::optional<DecodedRow> candidate = m_model->rowAt(i);
            if (candidate.has_value() && candidate->address == expectedRow.address)
            {
                matchedRow = i;
                break;
            }
        }
        const std::optional<DecodedRow> current = matchedRow >= 0 ? m_model->rowAt(matchedRow) : std::nullopt;
        if (!current.has_value() || current->bytes != expectedRow.bytes)
        {
            m_status->setText(QStringLiteral("数据已刷新，原指令不再位于当前视图，已取消本次汇编编辑。"));
            emit statusMessage(m_status->text());
            return;
        }
        const std::uint64_t address = current->address;
        const bool x64 = isX64();
        const std::uint64_t editRevision = m_editContextRevision; // 冻结宿主身份，即使 provider 地址不变也可检测切换

        // 拉一段足够长的窗口用于边界扫描（右键编辑很少需要覆盖超过这个范围）。
        const WorkbenchByteWindow window = m_provider->FetchWindow(address, 4096);
        if (!window.ok || window.address != address) return;
        // 可疑点 4：防御性 min 夹取，避免 validMask 与 bytes 长度不一致时越界读。
        const std::size_t effectiveLength = std::min(window.bytes.size(), window.validMask.size());
        std::size_t validLength = 0;
        while (validLength < effectiveLength && window.validMask[validLength] == 1)
        {
            ++validLength;
        }
        if (validLength == 0)
        {
            return;
        }
        const QByteArray snapshot(reinterpret_cast<const char*>(window.bytes.data()), static_cast<qsizetype>(validLength));

        // 实时宿主保留 256 字节覆盖限额和事务暂存语义，所有预览组件与边界规则共用。
        AssemblyPreviewInput input;
        input.address = address;
        input.x64 = x64;
        input.snapshot = snapshot;
        input.initialSource = (current->mnemonic + QLatin1Char(' ') + current->operands).trimmed();
        input.initialSpan = static_cast<int>(current->bytes.size());
        input.maximumSpan = 256;
        input.dialogName = QStringLiteral("ksMemwbAssemblyDialog");
        input.sourceName = QStringLiteral("ksMemwbAssemblySource");
        input.previewName = QStringLiteral("ksMemwbAssemblyPreview");
        input.stageCaption = QStringLiteral("填入暂存");
        input.hint = QStringLiteral("每行一条 Intel 指令。数字默认十六进制，十进制用 0d 前缀；覆盖长度须包含完整指令；编译只生成预览，确认无误后点“填入暂存”，由外层写事务统一写入。");
        input.completion = QStringLiteral("预览完成：%1 字节；点“填入暂存”交给外层写事务。");
        const QPointer<WorkbenchDisasmView> self(this);
        const QByteArray payload = RunAssemblyPreviewDialog(this, input, m_assembleOne, m_decodeOne);
        if (!self || payload.isEmpty()) return;
        // exec 允许自动附加/分离、改通道与实时重读；QPointer 只能证明对象仍活着，
        // 不能证明旧预览仍属于当前目标。先检查身份/架构/权限，再复核整个覆盖范围。
        bool snapshotMatches = m_editable && m_provider != nullptr
            && editRevision == m_editContextRevision && x64 == isX64();
        if (snapshotMatches)
        {
            const WorkbenchByteWindow currentWindow = m_provider->FetchWindow(address, static_cast<std::uint64_t>(payload.size()));
            snapshotMatches = currentWindow.ok && currentWindow.address == address
                && currentWindow.bytes.size() >= static_cast<std::size_t>(payload.size())
                && currentWindow.validMask.size() >= static_cast<std::size_t>(payload.size())
                && snapshot.size() >= payload.size();
            for (qsizetype i = 0; snapshotMatches && i < payload.size(); ++i)
            {
                const std::size_t index = static_cast<std::size_t>(i);
                snapshotMatches = currentWindow.validMask[index] == 1
                    && currentWindow.bytes[index] == static_cast<std::uint8_t>(snapshot[i]);
            }
        }
        if (!snapshotMatches)
        {
            m_status->setText(QStringLiteral("数据已刷新，原指令不再位于当前视图，已取消本次汇编编辑。"));
            emit statusMessage(m_status->text());
            return;
        }
        emit stageRequested(address, payload);
    }
}
