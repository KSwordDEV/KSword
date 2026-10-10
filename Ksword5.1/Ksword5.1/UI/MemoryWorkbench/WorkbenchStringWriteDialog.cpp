#include "WorkbenchStringWriteDialog.h"

// ============================================================
// WorkbenchStringWriteDialog.cpp
// 作用：见头文件。编码规则：ANSI 用 QString::toLocal8Bit()（本机 ANSI 代码页，
// 中文 Windows 下通常是 GBK/936），并用"编码后再解码回来是否等于原文本"的往返
// 校验判定是否有损（B1——QStringEncoder::hasError() 对 Latin-1/本机代码页的
// 替换字符不会置位，实测验证过，不能拿它当判据）；有损时 resultBytes() 直接
// 返回空，绝不允许用 '?' 悄悄顶替用户想写的字节。UTF-8 用 QString::toUtf8；
// UTF-16LE 用 Qt 原生存储顺序（小端）逐字符拆成两字节。
// ============================================================

#include "WorkbenchMessages.h"

#include "../../theme.h"
#include "../ThemeStatusRole.h"
#include "../SecondaryPageLayout.h"
#include "../../Internationalization/LanguageManager.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace ks::ui
{
    namespace
    {
        // EncodeAnsi：按本机 ANSI 代码页编码（B1）。lossyOut 非空时传出"往返校验"
        // 结果——QString::fromLocal8Bit(编码结果) 若不等于原文本，说明原文本里有
        // 本机代码页表示不了的字符，Qt 会在编码阶段悄悄替换成 '?'；调用方据此判定
        // 整段编码不可信，不能把这段替换过的字节当成"已写入文本对应的真实字节"。
        QByteArray EncodeAnsi(const QString& text, bool* lossyOut)
        {
            const QByteArray encoded = text.toLocal8Bit();
            if (lossyOut != nullptr)
            {
                *lossyOut = (QString::fromLocal8Bit(encoded) != text);
            }
            return encoded;
        }

        // EncodeUtf16Le：逐个 QChar 按小端拆成两字节，不经过 BOM。
        QByteArray EncodeUtf16Le(const QString& text)
        {
            QByteArray bytes;
            bytes.reserve(text.size() * 2);
            for (const QChar ch : text)
            {
                const ushort code = ch.unicode();
                bytes.append(static_cast<char>(code & 0xFF));
                bytes.append(static_cast<char>((code >> 8) & 0xFF));
            }
            return bytes;
        }
    }

    WorkbenchStringWriteDialog::WorkbenchStringWriteDialog(QWidget* parent)
        : QDialog(parent)
    {
        setWindowTitle(workbench_messages::StringWriteDialogTitle());
        StyleSecondaryWindow(this);

        auto* layout = new QVBoxLayout(this);
        StyleSecondaryContentLayout(layout);
        auto* form = new QFormLayout(); // 输入和编码保持同列，避免无标签控件难以辨认。

        m_textEdit = new QLineEdit(this);
        m_textEdit->setPlaceholderText(workbench_messages::StringWriteInputPlaceholder());
        form->addRow(ks::i18n::sourceText(QStringLiteral("内容")), m_textEdit);

        m_encodingCombo = new QComboBox(this);
        m_encodingCombo->addItem(workbench_messages::StringWriteEncodingLabel(0));
        m_encodingCombo->addItem(workbench_messages::StringWriteEncodingLabel(1));
        m_encodingCombo->addItem(workbench_messages::StringWriteEncodingLabel(2));
        m_encodingCombo->setCurrentIndex(static_cast<int>(Encoding::Utf8));
        form->addRow(ks::i18n::sourceText(QStringLiteral("编码")), m_encodingCombo);

        m_appendNulCheckBox = new QCheckBox(workbench_messages::StringWriteNulCheckboxText(), this);
        form->addRow(QString(), m_appendNulCheckBox);
        StyleSecondaryForm(form, 100);
        layout->addLayout(form);

        m_previewLabel = new QLabel(this);
        m_previewLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_previewLabel->setWordWrap(true);
        // 状态标签只走 ApplyStatusRole，窗口主题不覆盖正常/错误语义色。
        layout->addWidget(m_previewLabel);
        layout->addStretch(1);

        auto* buttonBox = new QDialogButtonBox(this);
        m_okButton = buttonBox->addButton(
            workbench_messages::StringWriteOkButtonText(), QDialogButtonBox::AcceptRole);
        m_cancelButton = buttonBox->addButton(
            workbench_messages::StringWriteCancelButtonText(), QDialogButtonBox::RejectRole);
        connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
        layout->addWidget(buttonBox);
        StyleSecondaryButtonBox(buttonBox);
        resize(560, 240);

        connect(m_textEdit, &QLineEdit::textChanged, this, &WorkbenchStringWriteDialog::refreshPreview);
        connect(m_encodingCombo, &QComboBox::currentIndexChanged, this, &WorkbenchStringWriteDialog::refreshPreview);
        connect(m_appendNulCheckBox, &QCheckBox::toggled, this, &WorkbenchStringWriteDialog::refreshPreview);

        refreshPreview();
    }

    QString WorkbenchStringWriteDialog::text() const
    {
        return m_textEdit->text();
    }

    void WorkbenchStringWriteDialog::setText(const QString& text)
    {
        m_textEdit->setText(text);
    }

    WorkbenchStringWriteDialog::Encoding WorkbenchStringWriteDialog::encoding() const
    {
        return static_cast<Encoding>(m_encodingCombo->currentIndex());
    }

    void WorkbenchStringWriteDialog::setEncoding(const Encoding encoding)
    {
        m_encodingCombo->setCurrentIndex(static_cast<int>(encoding));
    }

    bool WorkbenchStringWriteDialog::appendNul() const
    {
        return m_appendNulCheckBox->isChecked();
    }

    void WorkbenchStringWriteDialog::setAppendNul(const bool appendNul)
    {
        m_appendNulCheckBox->setChecked(appendNul);
    }

    bool WorkbenchStringWriteDialog::isAnsiLossy() const
    {
        if (encoding() != Encoding::Ansi)
        {
            return false;
        }
        bool lossy = false;
        EncodeAnsi(text(), &lossy);
        return lossy;
    }

    QByteArray WorkbenchStringWriteDialog::resultBytes() const
    {
        // B1：ANSI 有损时绝不编码出任何字节——调用方（右键菜单/画布的"写入字符串"
        // 入口）必须拿到一个空结果，不能拿到一段看似合法但其实是 '?' 替换出来的
        // 假数据去写目标内存。
        if (isAnsiLossy())
        {
            return QByteArray();
        }
        QByteArray bytes;
        switch (encoding())
        {
        case Encoding::Ansi:
            bytes = EncodeAnsi(text(), nullptr);
            break;
        case Encoding::Utf8:
            bytes = text().toUtf8();
            break;
        case Encoding::Utf16Le:
            bytes = EncodeUtf16Le(text());
            break;
        }
        if (appendNul())
        {
            // UTF-16LE 的结束符是两个字节的 0x0000；其余两种编码是单字节 0x00。
            bytes.append(encoding() == Encoding::Utf16Le ? 2 : 1, '\0');
        }
        return bytes;
    }

    QString WorkbenchStringWriteDialog::previewText() const
    {
        if (isAnsiLossy())
        {
            // B1：红字说明，不是"将写入 N 字节"——有损状态下根本不会写入任何字节。
            return workbench_messages::StringWriteAnsiLossyText();
        }
        return workbench_messages::StringWritePreviewText(static_cast<quint64>(resultBytes().size()));
    }

    void WorkbenchStringWriteDialog::refreshPreview()
    {
        const bool lossy = isAnsiLossy();
        m_previewLabel->setText(previewText());
        // 预览区的状态色走 ApplyStatusRole（项目统一规范），有损时标红，否则清空
        // 状态标记回落到继承色。
        ApplyStatusRole(m_previewLabel, lossy ? StatusRole::Error : StatusRole::None);
        // B10：空文本（或有损 ANSI）都不能点"写入"——resultBytes() 为空时，不管是
        // "用户什么都没输"还是"ANSI 编码不出来"，写入目标都没有意义。
        m_okButton->setEnabled(!lossy && !resultBytes().isEmpty());
    }
}
