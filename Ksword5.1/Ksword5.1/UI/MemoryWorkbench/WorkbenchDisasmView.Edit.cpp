// WorkbenchDisasmView.Edit.cpp
// 作用：行内编辑委托（双击/F2/Enter 进入，Enter 编译提交，失败不关编辑框）与右键
// "汇编编辑"预览对话框（内核流程参考旧 MemoryEditorWidget.cpp:821-937，本页用自己的类重写，
// 不依赖旧控件；覆盖长度/NOP 填充/边界校验三条规则原样保留，即不变式 10）。
// 两条路径最终都只发 stageRequested 信号，本文件不直接写任何内存。

#include "WorkbenchDisasmView.h"
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
    namespace
    {
        void sizeDialogResponsively(QDialog* dialog, const QSize& preferred, const QSize& minimum, QWidget* anchor)
        {
            const QScreen* screen = (anchor != nullptr && anchor->screen() != nullptr) ? anchor->screen() : QGuiApplication::primaryScreen();
            const QRect available = screen != nullptr ? screen->availableGeometry() : QRect(0, 0, 1280, 800);
            const QSize bounded(
                std::min(preferred.width(), std::max(minimum.width(), available.width() - 80)),
                std::min(preferred.height(), std::max(minimum.height(), available.height() - 80)));
            dialog->setMinimumSize(minimum);
            dialog->resize(bounded);
        }

    }

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

        // 可疑点 9：堆分配 + WA_DeleteOnClose，不再用栈上 QDialog——如果 exec() 的嵌套事件
        // 循环期间 this（父窗口）被销毁，Qt 会先同步销毁子对象（包括这个对话框），exec()
        // 据此退出；用 QPointer<WorkbenchDisasmView> 自guard，退出后先判空再访问 this 的
        // 任何成员，不解引用悬空指针。
        auto* dialog = new QDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setObjectName(QStringLiteral("ksMemwbAssemblyDialog"));
        // 显式设置不透明背景样式：父容器若用了透明/特殊样式，弹窗默认样式可能继承出黑底黑字。
        dialog->setStyleSheet(KswordTheme::OpaqueDialogStyle(dialog->objectName()));
        dialog->setWindowTitle(QStringLiteral("汇编编辑"));
        auto* layout = new QVBoxLayout(dialog);
        auto* form = new QFormLayout;
        form->addRow(QStringLiteral("起始地址"), new QLabel(hexcanvas_format::FormatAddress(address, 16), dialog));
        form->addRow(QStringLiteral("指令架构"), new QLabel(x64 ? QStringLiteral("x64") : QStringLiteral("x86"), dialog));
        auto* span = new QSpinBox(dialog);
        span->setRange(1, static_cast<int>(std::min<qsizetype>(snapshot.size(), 256)));
        span->setValue(static_cast<int>(std::max<qsizetype>(1, current->bytes.size())));
        form->addRow(QStringLiteral("覆盖长度（字节）"), span);
        auto* pad = new QCheckBox(QStringLiteral("用 NOP 填充剩余覆盖空间"), dialog);
        pad->setChecked(true);
        form->addRow(pad);
        layout->addLayout(form);

        auto* hint = new QLabel(QStringLiteral(
            "每行一条 Intel 指令。数字默认十六进制，十进制用 0d 前缀；覆盖长度须包含完整指令；"
            "编译只生成预览，确认无误后点“填入暂存”，由外层写事务统一写入。"), dialog);
        hint->setWordWrap(true);
        layout->addWidget(hint);

        auto* source = new CodeTextEdit(dialog);
        source->setObjectName(QStringLiteral("ksMemwbAssemblySource"));
        source->setPlainText((current->mnemonic + QLatin1Char(' ') + current->operands).trimmed());
        layout->addWidget(source, 1);

        auto* preview = new CodeTextEdit(dialog);
        preview->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
        preview->setObjectName(QStringLiteral("ksMemwbAssemblyPreview"));
        preview->setReadOnly(true);
        preview->setFont(source->font());
        layout->addWidget(preview, 1);

        auto* status = new QLabel(dialog);
        status->setWordWrap(true);
        layout->addWidget(status);

        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, dialog);
        auto* compile = buttons->addButton(QStringLiteral("编译并预览"), QDialogButtonBox::ActionRole);
        auto* stage = buttons->addButton(QStringLiteral("填入暂存"), QDialogButtonBox::AcceptRole);
        stage->setEnabled(false);
        layout->addWidget(buttons);

        // payload 仍然是本函数的局部变量、按引用捕获进 lambda——dialog->exec() 同步阻塞，
        // 函数返回前 payload 一直在作用域内有效；WA_DeleteOnClose 只在 exec() 返回、dialog
        // 隐藏之后才触发 deleteLater，不会在 exec() 运行期间提前把 dialog 连带它的信号
        // 连接一起销毁，所以这里的按引用捕获跟堆分配与否无关，仍然安全。
        QByteArray payload;
        const auto invalidate = [=, &payload]() {
            payload.clear();
            stage->setEnabled(false);
            preview->clear();
            status->clear();
        };
        connect(source, &QPlainTextEdit::textChanged, dialog, invalidate);
        connect(span, &QSpinBox::valueChanged, dialog, invalidate);
        connect(pad, &QCheckBox::toggled, dialog, invalidate);

        connect(compile, &QPushButton::clicked, dialog, [=, &payload, this]() {
            invalidate();
            const WorkbenchAssembleResult result = m_assembleOne(source->toPlainText(), address, x64);
            if (!result.success)
            {
                // D6：用后端给出的真实出错行号，不再恒为"第 1 行"（行内编辑路径仍然是单行
                // 源码，不走这里，不受影响）；errorLine<=0（旧后端/夹具假后端没给）时按
                // 第 1 行显示，不展示"第 0 行"这种没有意义的数字。
                status->setText(QStringLiteral("第 %1 行：%2").arg(result.errorLine > 0 ? result.errorLine : 1).arg(result.error));
                return;
            }
            if (result.bytes.isEmpty() || result.bytes.size() > span->value())
            {
                status->setText(QStringLiteral("机器码为 %1 字节，超出覆盖长度 %2；请明确扩大覆盖范围后重新预览。")
                    .arg(result.bytes.size()).arg(span->value()));
                return;
            }
            // 边界校验（不变式 10）：覆盖长度必须恰好落在完整旧指令边界上，不能截断。
            const std::vector<std::uint8_t> boundaryBytes(
                reinterpret_cast<const std::uint8_t*>(snapshot.constData()),
                reinterpret_cast<const std::uint8_t*>(snapshot.constData()) + std::min<qsizetype>(snapshot.size(), span->value() + 15));
            const QVector<DecodedRow> oldRows = DecodeWindowResynced(boundaryBytes, address, m_decodeOne, 65536, x64);
            qsizetype boundary = 0;
            bool boundaryOk = false;
            for (const DecodedRow& decodedRow : oldRows)
            {
                if (!decodedRow.decoded)
                {
                    status->setText(QStringLiteral("覆盖范围包含无法解码的字节；请调整范围或使用十六进制编辑。"));
                    return;
                }
                boundary += decodedRow.bytes.size();
                if (boundary >= span->value())
                {
                    boundaryOk = boundary == span->value();
                    break;
                }
            }
            if (!boundaryOk)
            {
                status->setText(QStringLiteral("覆盖长度截断了原指令，请选择完整指令边界（下一边界为 %1 字节）。").arg(boundary));
                return;
            }
            if (!pad->isChecked() && result.bytes.size() != span->value())
            {
                status->setText(QStringLiteral("关闭 NOP 填充时，机器码长度必须等于覆盖长度。"));
                return;
            }
            payload = result.bytes;
            payload.append(QByteArray(span->value() - payload.size(), static_cast<char>(0x90)));
            QString text = QStringLiteral("原始：%1\n替换：%2\n")
                .arg(hexcanvas_format::FormatHexText(snapshot.left(span->value()))).arg(hexcanvas_format::FormatHexText(payload));
            const std::vector<std::uint8_t> payloadBytes(
                reinterpret_cast<const std::uint8_t*>(payload.constData()),
                reinterpret_cast<const std::uint8_t*>(payload.constData()) + payload.size());
            const QVector<DecodedRow> newRows = DecodeWindowResynced(payloadBytes, address, m_decodeOne, 65536, x64);
            for (const DecodedRow& decodedRow : newRows)
            {
                text += hexcanvas_format::FormatAddress(decodedRow.address, 16) + QStringLiteral("  ")
                    + hexcanvas_format::FormatHexText(decodedRow.bytes) + QStringLiteral("  ")
                    + decodedRow.mnemonic + QLatin1Char(' ') + decodedRow.operands + QLatin1Char('\n');
            }
            preview->setPlainText(text);
            status->setText(QStringLiteral("预览完成：%1 字节；点“填入暂存”交给外层写事务。").arg(payload.size()));
            stage->setEnabled(true);
        });
        connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
        connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);

        sizeDialogResponsively(dialog, QSize(760, 620), QSize(480, 360), this);
        const QPointer<WorkbenchDisasmView> self(this);
        const QPointer<QDialog> dialogGuard(dialog);
        const int result = dialog->exec();
        if (dialogGuard) delete dialogGuard.data();
        if (!self)
        {
            // this 已经在 exec() 期间被销毁：dialog 作为它的子对象也已经/正在被销毁，
            // 不能再访问 m_status、不能再 emit 本对象的信号。
            return;
        }
        if (result != QDialog::Accepted || payload.isEmpty())
        {
            return;
        }
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
