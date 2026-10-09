#include "AssemblyPreviewDialog.h"
#include "HexCanvasFormat.h"
#include "../CodeEditorWidget.h"
#include "../CodeTextEdit.h"
#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"
#include <QCheckBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGuiApplication>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QScreen>
#include <QSpinBox>
#include <QVBoxLayout>
#include <algorithm>

namespace ks::ui
{
    // BuildAssemblyPreview：先校验尺寸和旧指令边界，再生成只读预览，失败不保留半成品。
    AssemblyPreviewResult BuildAssemblyPreview(const AssemblyPreviewInput& input, int span,
        bool padWithNop, const WorkbenchAssembleResult& assembled, const DecodeOneFn& decode)
    {
        AssemblyPreviewResult result; // 所有错误出口统一返回空载荷。
        if (!assembled.success)
        {
            result.error = ks::i18n::sourceText(QStringLiteral("第 %1 行：%2"))
                .arg(std::max(1, assembled.errorLine)).arg(assembled.error);
            return result;
        }
        if (!decode || span < 1 || span > input.maximumSpan || span > input.snapshot.size()
            || static_cast<std::uint64_t>(span - 1) > UINT64_MAX - input.address
            || assembled.bytes.isEmpty() || assembled.bytes.size() > span)
        {
            result.error = ks::i18n::sourceText(QStringLiteral("机器码为 %1 字节，超出覆盖长度 %2；请明确扩大覆盖范围后重新预览。"))
                .arg(assembled.bytes.size()).arg(span);
            return result;
        }

        // 边界扫描使用实际地址/架构；额外 15 字节只帮助识别末条，不计入可覆盖长度。
        qsizetype boundary = 0; // 当前扫描到的完整旧指令终点。
        while (boundary < span)
        {
            const auto available = static_cast<std::size_t>(input.snapshot.size() - boundary);
            const auto* bytes = reinterpret_cast<const std::uint8_t*>(input.snapshot.constData()) + boundary;
            const auto at = input.address + static_cast<std::uint64_t>(boundary);
            const auto row = decode(bytes, available, at, input.x64);
            if (!row || !row->decoded || row->address != at || row->bytes.isEmpty()
                || static_cast<std::size_t>(row->bytes.size()) > available
                || row->bytes.size() > 15 || input.snapshot.mid(boundary, row->bytes.size()) != row->bytes)
            {
                result.error = ks::i18n::sourceText(QStringLiteral("覆盖范围包含无法解码的字节；请调整范围或使用十六进制编辑。"));
                return result;
            }
            boundary += row->bytes.size();
        }
        if (boundary != span)
        {
            result.error = ks::i18n::sourceText(QStringLiteral("覆盖长度截断了原指令，请选择完整指令边界（下一边界为 %1 字节）。"))
                .arg(boundary);
            return result;
        }
        if (!padWithNop && assembled.bytes.size() != span)
        {
            result.error = ks::i18n::sourceText(QStringLiteral("关闭 NOP 填充时，机器码长度必须等于覆盖长度。"));
            return result;
        }

        // 两个宿主共用一种补齐与显示，仍由宿主决定“缓存”或“事务暂存”的后续行为。
        result.payload = assembled.bytes;
        result.payload.append(QByteArray(span - result.payload.size(), static_cast<char>(0x90)));
        result.text = ks::i18n::sourceText(QStringLiteral("原始：%1\n替换：%2\n"))
            .arg(hexcanvas_format::FormatHexText(input.snapshot.left(span)))
            .arg(hexcanvas_format::FormatHexText(result.payload));
        const auto* begin = reinterpret_cast<const std::uint8_t*>(result.payload.constData());
        const std::vector<std::uint8_t> payloadBytes(begin, begin + result.payload.size());
        const auto rows = DecodeWindowResynced(payloadBytes, input.address, decode, 65536, input.x64);
        for (const auto& row : rows)
        {
            result.text += hexcanvas_format::FormatAddress(row.address, 16) + QStringLiteral("  ")
                + hexcanvas_format::FormatHexText(row.bytes) + QStringLiteral("  ")
                + row.mnemonic + QLatin1Char(' ') + row.operands + QLatin1Char('\n');
        }
        return result;
    }

    // RunAssemblyPreviewDialog：只创建共享 UI 和内存载荷；父窗口销毁时 QPointer 阻止访问失效对象。
    QByteArray RunAssemblyPreviewDialog(QWidget* parent, const AssemblyPreviewInput& input,
        const AssembleOneFn& assemble, const DecodeOneFn& decode)
    {
        if (!parent || !assemble || !decode || input.snapshot.isEmpty() || input.maximumSpan < 1) return {};
        QPointer<QDialog> dialog = new QDialog(parent); // 子对象由模态结束或父对象销毁回收。
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setObjectName(input.dialogName);
        dialog->setStyleSheet(KswordTheme::OpaqueDialogStyle(input.dialogName));
        dialog->setWindowTitle(ks::i18n::sourceText(QStringLiteral("汇编编辑")));
        auto* layout = new QVBoxLayout(dialog);
        auto* form = new QFormLayout;
        form->addRow(ks::i18n::sourceText(QStringLiteral("起始地址")),
            new QLabel(hexcanvas_format::FormatAddress(input.address, 16), dialog));
        form->addRow(ks::i18n::sourceText(QStringLiteral("指令架构")),
            new QLabel(input.x64 ? QStringLiteral("x64") : QStringLiteral("x86"), dialog));
        auto* span = new QSpinBox(dialog); // 范围上限必须由冻结字节和宿主政策共同约束。
        span->setRange(1, static_cast<int>(std::min<qsizetype>(input.snapshot.size(), input.maximumSpan)));
        span->setValue(std::clamp(input.initialSpan, span->minimum(), span->maximum()));
        form->addRow(ks::i18n::sourceText(QStringLiteral("覆盖长度（字节）")), span);
        auto* pad = new QCheckBox(ks::i18n::sourceText(QStringLiteral("用 NOP 填充剩余覆盖空间")), dialog);
        pad->setChecked(true);
        form->addRow(pad);
        layout->addLayout(form);
        auto* hint = new QLabel(ks::i18n::sourceText(input.hint), dialog);
        hint->setWordWrap(true);
        layout->addWidget(hint);

        // 汇编输入与预览同样接入项目正式外壳；源码/机器码都是 raw，绝不解析成报告结构。
        auto* source = new CodeEditorWidget(dialog);
        source->setRawText(input.initialSource);
        auto* sourceCore = dynamic_cast<CodeTextEdit*>(source->findChild<QPlainTextEdit*>(QStringLiteral("code_editor_text")));
        auto* preview = new CodeEditorWidget(dialog);
        preview->setReadOnly(true);
        auto* previewCore = dynamic_cast<CodeTextEdit*>(preview->findChild<QPlainTextEdit*>(QStringLiteral("code_editor_text")));
        if (!sourceCore || !previewCore)
        {
            delete dialog.data();
            return {};
        }
        sourceCore->setObjectName(input.sourceName);
        sourceCore->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::Cpp);
        previewCore->setObjectName(input.previewName);
        previewCore->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
        layout->addWidget(source, 1);
        layout->addWidget(preview, 1);
        auto* status = new QLabel(dialog);
        status->setWordWrap(true);
        layout->addWidget(status);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, dialog);
        auto* compile = buttons->addButton(ks::i18n::sourceText(QStringLiteral("编译并预览")), QDialogButtonBox::ActionRole);
        auto* stage = buttons->addButton(ks::i18n::sourceText(input.stageCaption), QDialogButtonBox::AcceptRole);
        compile->setToolTip(ks::i18n::sourceText(QStringLiteral("编译并预览")));
        stage->setToolTip(ks::i18n::sourceText(input.stageCaption));
        stage->setEnabled(false);
        layout->addWidget(buttons);

        // 局部载荷仅活到 exec 返回；返回前销毁弹窗，断开所有按引用捕获的回调。
        QByteArray payload;
        const auto invalidate = [=, &payload]() {
            payload.clear();
            if (!dialog) return;
            stage->setEnabled(false);
            preview->setRawText({});
            if (!dialog) return;
            status->clear();
        };
        QObject::connect(sourceCore, &QPlainTextEdit::textChanged, dialog.data(), invalidate);
        QObject::connect(span, &QSpinBox::valueChanged, dialog.data(), invalidate);
        QObject::connect(pad, &QCheckBox::toggled, dialog.data(), invalidate);
        QObject::connect(compile, &QPushButton::clicked, dialog.data(), [=, &payload]() {
            invalidate();
            // 两个后端都是同步纯编译；生命周期检查覆盖可能发生的嵌套 UI 回调。
            if (!dialog) return;
            const auto compiled = assemble(source->text(), input.address, input.x64);
            if (!dialog) return;
            const auto result = BuildAssemblyPreview(input, span->value(), pad->isChecked(), compiled, decode);
            if (!dialog) return;
            if (!result.error.isEmpty())
            {
                status->setText(result.error);
                return;
            }
            payload = result.payload;
            preview->setRawText(result.text);
            if (!dialog) return;
            status->setText(ks::i18n::sourceText(input.completion).arg(payload.size()));
            stage->setEnabled(true);
        });
        QObject::connect(buttons, &QDialogButtonBox::accepted, dialog.data(), &QDialog::accept);
        QObject::connect(buttons, &QDialogButtonBox::rejected, dialog.data(), &QDialog::reject);
        const QScreen* screen = parent->screen() ? parent->screen() : QGuiApplication::primaryScreen();
        const QRect available = screen ? screen->availableGeometry() : QRect(0, 0, 1280, 800);
        dialog->setMinimumSize(480, 360);
        dialog->resize(std::min(760, std::max(480, available.width() - 80)),
            std::min(620, std::max(360, available.height() - 80)));
        const int answer = dialog->exec();
        if (dialog) delete dialog.data();
        return answer == QDialog::Accepted ? payload : QByteArray{};
    }
}
