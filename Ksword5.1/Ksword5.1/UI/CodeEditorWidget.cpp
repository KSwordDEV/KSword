#include "CodeEditorWidget.h"
#include "FieldTreePresenter.h"
#include "CodeTextEdit.h"
#include "CodeEditorFileSession.h"

// ============================================================
// CodeEditorWidget.cpp
// 作用：
// - 实现“即时窗口”可复用代码编辑器；
// - 提供行号、括号高亮、查找替换、跳转行、文本文件读写。
// ============================================================

#include "ReportStructuredView.h"

#include "../theme.h"
#include "../Internationalization/LanguageManager.h"

#include <QBuffer>
#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QMenu>
#include <QAction>
#include <QGridLayout>
#include <QPointer>
#include <QFileDialog>
#include <QFontDatabase>
#include <QFrame>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLabel>
#include <QLineEdit>
#include <QMimeData>
#include <QPaintEvent>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPixmap>
#include <QResizeEvent>
#include <QScrollBar>
#include <QShortcut>
#include <QSize>
#include <QSvgRenderer>
#include <QSyntaxHighlighter>
#include <QTextBlock>
#include <QTextDocument>
#include <QTextStream>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <QXmlStreamReader>
#include <QXmlStreamWriter>
#include <QStringConverter>

#include <algorithm>

namespace
{
    // g_preferStructuredReportView 作用：
    // - 记住用户最近一次在“结构视图 / 原始文本”之间的选择，之后新出现的报告沿用同一选择；
    // - 只在进程内有效、不落盘：这是“这次排查我想怎么看”，不是需要长期保存的偏好；
    // - 默认结构视图：详情报告本来就是字段清单，逐条看比读整段文本快。
    bool g_preferStructuredReportView = true;

    // localizeReportValueCore：翻译报告字段值；复合权限/标志按竖线逐项翻译。
    QString localizeReportValueCore(const QString& valueCore)
    {
        const QString localizedWholeValue = ks::i18n::displayText(valueCore);
        if (localizedWholeValue != valueCore || !valueCore.contains(QLatin1Char('|')))
        {
            return localizedWholeValue;
        }

        QStringList valueParts = valueCore.split(QLatin1Char('|'), Qt::KeepEmptyParts);
        bool anyPartChanged = false;
        for (QString& valuePart : valueParts)
        {
            qsizetype startIndex = 0;
            while (startIndex < valuePart.size() && valuePart.at(startIndex).isSpace())
            {
                ++startIndex;
            }
            qsizetype endIndex = valuePart.size();
            while (endIndex > startIndex && valuePart.at(endIndex - 1).isSpace())
            {
                --endIndex;
            }

            const QString partCore = valuePart.mid(startIndex, endIndex - startIndex);
            const QString localizedPartCore = ks::i18n::displayText(partCore);
            if (localizedPartCore == partCore)
            {
                continue;
            }
            valuePart = valuePart.left(startIndex) + localizedPartCore + valuePart.mid(endIndex);
            anyPartChanged = true;
        }
        return anyPartChanged ? valueParts.join(QLatin1Char('|')) : valueCore;
    }

    // localizeEmbeddedReportValue：翻译“标签: 动态状态”中的状态值。
    // 模板翻译会原样保留 %1 捕获内容；这里仅处理冒号后的可翻译状态，路径和哈希会自然保持不变。
    QString localizeEmbeddedReportValue(const QString& sourceLine, const QString& localizedLine)
    {
        const bool hasNewline = sourceLine.endsWith(QLatin1Char('\n'));
        const bool localizedHasNewline = localizedLine.endsWith(QLatin1Char('\n'));
        const QString sourceBody = hasNewline ? sourceLine.chopped(1) : sourceLine;
        QString localizedBody = localizedHasNewline ? localizedLine.chopped(1) : localizedLine;

        qsizetype separatorIndex = sourceBody.indexOf(QLatin1Char(':'));
        const qsizetype fullWidthSeparatorIndex = sourceBody.indexOf(QChar(0xFF1A));
        if (separatorIndex < 0 ||
            (fullWidthSeparatorIndex >= 0 && fullWidthSeparatorIndex < separatorIndex))
        {
            separatorIndex = fullWidthSeparatorIndex;
        }
        if (separatorIndex < 0)
        {
            return localizedLine;
        }

        const QString sourceValue = sourceBody.mid(separatorIndex + 1);
        qsizetype valueStart = 0;
        while (valueStart < sourceValue.size() && sourceValue.at(valueStart).isSpace())
        {
            ++valueStart;
        }
        qsizetype valueEnd = sourceValue.size();
        while (valueEnd > valueStart && sourceValue.at(valueEnd - 1).isSpace())
        {
            --valueEnd;
        }
        const QString valueCore = sourceValue.mid(valueStart, valueEnd - valueStart);
        const QString localizedValueCore = localizeReportValueCore(valueCore);
        if (valueCore.isEmpty() || localizedValueCore == valueCore || !localizedBody.endsWith(sourceValue))
        {
            return localizedLine;
        }

        localizedBody.chop(sourceValue.size());
        localizedBody += sourceValue.left(valueStart);
        localizedBody += localizedValueCore;
        localizedBody += sourceValue.mid(valueEnd);
        return hasNewline ? localizedBody + QLatin1Char('\n') : localizedBody;
    }

    // localizeGeneratedReport：只处理应用生成报告的逐行模板。
    // 路径、哈希、证书内容等动态值由占位符原样保留；用户文件正文不会调用此函数。
    QString localizeGeneratedReport(const QString& sourceText)
    {
        QString localizedText;
        localizedText.reserve(sourceText.size());

        qsizetype lineStart = 0;
        while (lineStart < sourceText.size())
        {
            const qsizetype newlineIndex = sourceText.indexOf(QLatin1Char('\n'), lineStart);
            const bool hasNewline = newlineIndex >= 0;
            const qsizetype lineLength = hasNewline
                ? (newlineIndex - lineStart + 1)
                : (sourceText.size() - lineStart);
            const QString sourceLine = sourceText.mid(lineStart, lineLength);
            QString localizedLine = ks::i18n::displayText(sourceLine);
            if (localizedLine == sourceLine && hasNewline)
            {
                localizedLine = ks::i18n::displayText(sourceLine.left(sourceLine.size() - 1));
                localizedLine += QLatin1Char('\n');
            }
            localizedLine = localizeEmbeddedReportValue(sourceLine, localizedLine);
            localizedText += localizedLine;
            lineStart += lineLength;
        }
        return localizedText;
    }

    // buildToolButtonStyle：
    // - 统一工具按钮样式，去掉边框让图标本体更突出；
    // - hover/pressed 仅保留轻量底色反馈，避免 SVG 被边框吃掉。
    QString buildToolButtonStyle()
    {
        return QStringLiteral(
            "QToolButton{"
            "  border:none;"
            "  border-radius:4px;"
            "  padding:1px;"
            "  background:transparent;"
            "  color:%1;"
            "}"
            "QToolButton:hover{"
            "  background:palette(alternate-base);"
            "  color:palette(text);"
            "}"
            "QToolButton:pressed,QToolButton:checked:pressed{"
            "  background:%3;"
            "  color:%5;"
            "}"
            "QToolButton:checked{"
            "  background:%2;"
            "  color:%4;"
            "}")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::ThemeColorName(KswordTheme::PrimaryAccentColor()))
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue, -14, -40))
            .arg(KswordTheme::OnAccentHex())
            .arg(KswordTheme::OnAccentHex(
                KswordTheme::AccentColor(KswordTheme::AccentRole::Blue, -14, -40)));
    }

    // buildFloatingSwitchStyle：
    // - 内容区右上角悬浮切换下拉框的样式；
    // - 它压在正文之上，必须自带不透明底色和边框，否则叠在属性表行或报告文字上会看不清；
    // - 下拉列表同样要显式给底色：弹出面板是独立窗口，不会继承这里的背景；
    // - 颜色全部走 palette(...) 形式的 token，主题切换时跟着变，不做快照。
    QString buildFloatingSwitchStyle()
    {
        return QStringLiteral(
            "QComboBox{"
            "  border:1px solid %1;"
            "  border-radius:6px;"
            "  padding:4px 8px;"
            "  background:%2;"
            "  color:%3;"
            "}"
            "QComboBox:hover{"
            "  border:1px solid %4;"
            "}"
            "QComboBox QAbstractItemView{"
            "  border:1px solid %1;"
            "  background:%2;"
            "  color:%3;"
            "  selection-background-color:%4;"
            "  selection-color:%5;"
            "}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    // buildInputStyle：
    // - 统一输入框样式，适配深浅色。
    QString buildInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %1;border-radius:3px;padding:2px 6px;background:transparent;/* %2 */color:%3;}"
            "QLineEdit:focus{border:1px solid %4;}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex);
    }

    // buildToolbarSvgIcon：
    // - 从 SVG 资源生成工具栏图标；
    // - 分别生成普通、悬停、禁用和选中配色，避免图标与强调背景同色。
    QIcon buildToolbarSvgIcon(const QString& resourcePath, const QToolButton* button,
        const QSize& iconSize = QSize(22, 22))
    {
        QSvgRenderer renderer(resourcePath);
        if (!renderer.isValid())
        {
            return QIcon(resourcePath);
        }

        QPixmap iconPixmap(iconSize);
        iconPixmap.fill(Qt::transparent);

        QPainter painter(&iconPixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        renderer.render(&painter, QRectF(0, 0, iconSize.width(), iconSize.height()));
        painter.end();

        QIcon icon;
        const auto addColoredPixmap = [&](const QColor& color, QIcon::Mode mode, QIcon::State state)
        {
            QPixmap coloredPixmap = iconPixmap;
            QPainter colorPainter(&coloredPixmap);
            colorPainter.setCompositionMode(QPainter::CompositionMode_SourceIn);
            colorPainter.fillRect(coloredPixmap.rect(), color);
            colorPainter.end();
            icon.addPixmap(coloredPixmap, mode, state);
        };
        // Normal 按钮透明；可见底色来自父面板，不能用 QSS 改写的按钮 Base。
        const QWidget* parentSurface = button != nullptr ? button->parentWidget() : nullptr;
        const QPalette::ColorRole surfaceRole = parentSurface != nullptr
            && parentSurface->objectName() == QStringLiteral("code_editor_find_panel")
            ? QPalette::AlternateBase : QPalette::Base;
        const QColor surface = parentSurface != nullptr
            ? parentSurface->palette().color(surfaceRole) : KswordTheme::SurfaceColor();
        const QColor checkedBackground = KswordTheme::PrimaryAccentColor();
        const QColor pressedBackground = KswordTheme::AccentColor(KswordTheme::AccentRole::Blue, -14, -40);
        const bool pressed = button != nullptr && button->isDown();
        // Active同时覆盖悬停和按下；键盘按下时Qt可能仍请求Normal，按实际down状态补齐。
        const QColor activeForeground = pressed
            ? KswordTheme::ControlGlyphColor(pressedBackground)
            : KswordTheme::ControlGlyphColor(button && button->isChecked()
                ? checkedBackground : (button ? button->palette().color(QPalette::AlternateBase) : surface));
        for (QIcon::State state : { QIcon::Off, QIcon::On })
        {
            const QColor normalBackground = pressed ? pressedBackground
                : (state == QIcon::On ? checkedBackground : surface);
            addColoredPixmap(KswordTheme::ControlGlyphColor(normalBackground), QIcon::Normal, state);
            addColoredPixmap(activeForeground, QIcon::Active, state);
            addColoredPixmap(activeForeground, QIcon::Selected, state);
            addColoredPixmap(KswordTheme::ControlGlyphColor(surface, true), QIcon::Disabled, state);
        }
        return icon;
    }

    // 排队读取最终调色板：Qt 的按下/释放和 QSS polish 可能先经过瞬时背景。
    void queueToolbarGlyphRefresh(QToolButton* button)
    {
        const QPointer<QToolButton> guardedButton(button); // 动态属性通知也可同步销毁按钮。
        if (guardedButton.isNull() || guardedButton->property("ksword_editor_glyph_refresh_pending").toBool())
        {
            return;
        }
        guardedButton->setProperty("ksword_editor_glyph_refresh_pending", true);
        if (guardedButton.isNull())
        {
            return;
        }
        QTimer::singleShot(0, guardedButton.data(), [guardedButton]()
        {
            if (guardedButton.isNull())
            {
                return;
            }
            guardedButton->setProperty("ksword_editor_glyph_refresh_pending", false);
            if (guardedButton.isNull())
            {
                return;
            }
            const QString path = guardedButton->property("ksword_editor_icon_path").toString();
            if (!path.isEmpty())
            {
                guardedButton->setProperty("ksword_editor_glyph_down", guardedButton->isDown());
                if (guardedButton.isNull())
                {
                    return;
                }
                guardedButton->setIcon(buildToolbarSvgIcon(path, guardedButton.data()));
            }
        });
    }

    // FileDecodeResult：
    // - 承载文本文件解码结果和会话元数据。
    struct FileDecodeResult
    {
        QString text;
        QStringConverter::Encoding encoding = QStringConverter::Utf8;
        bool hasBom = false;
        QString lineEndingText = QStringLiteral("\n");
        bool success = false;
    };

    // readAllTextWithEncoding：
    // - 按指定编码读取完整文本。
    QString readAllTextWithEncoding(const QByteArray& rawBytes, const QStringConverter::Encoding encoding)
    {
        QBuffer byteBuffer;
        byteBuffer.setData(rawBytes);
        if (!byteBuffer.open(QIODevice::ReadOnly))
        {
            return QString();
        }

        QTextStream textStream(&byteBuffer);
        textStream.setEncoding(encoding);
        return textStream.readAll();
    }

    // detectDominantLineEnding：
    // - 统计文本主导换行风格。
    QString detectDominantLineEnding(const QString& textValue)
    {
        int crlfCount = 0;
        int lfCount = 0;
        int crCount = 0;

        for (int index = 0; index < textValue.size(); ++index)
        {
            const QChar currentChar = textValue.at(index);
            if (currentChar == QChar('\r'))
            {
                if ((index + 1) < textValue.size() && textValue.at(index + 1) == QChar('\n'))
                {
                    ++crlfCount;
                    ++index;
                }
                else
                {
                    ++crCount;
                }
            }
            else if (currentChar == QChar('\n'))
            {
                ++lfCount;
            }
        }

        if (crlfCount >= lfCount && crlfCount >= crCount)
        {
            return QStringLiteral("\r\n");
        }
        if (lfCount >= crCount)
        {
            return QStringLiteral("\n");
        }
        return QStringLiteral("\r");
    }

    // normalizeLineEndingForSaving：
    // - 写回文件前统一换行风格，避免混合换行持续扩散。
    QString normalizeLineEndingForSaving(const QString& textValue, const QString& lineEndingText)
    {
        QString normalizedText = textValue;
        normalizedText.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
        normalizedText.replace(QChar('\r'), QChar('\n'));

        if (lineEndingText == QStringLiteral("\r\n"))
        {
            return normalizedText.replace(QStringLiteral("\n"), QStringLiteral("\r\n"));
        }
        if (lineEndingText == QStringLiteral("\r"))
        {
            return normalizedText.replace(QChar('\n'), QChar('\r'));
        }
        return normalizedText;
    }

    // buildEncodingDisplayText：
    // - 转换编码展示文案（含 BOM 标记）。
    QString buildEncodingDisplayText(const QStringConverter::Encoding encoding, const bool hasBom)
    {
        QString encodingName = QStringLiteral("UTF-8");
        switch (encoding)
        {
        case QStringConverter::Utf8:
            encodingName = QStringLiteral("UTF-8");
            break;
        case QStringConverter::Utf16LE:
            encodingName = QStringLiteral("UTF-16 LE");
            break;
        case QStringConverter::Utf16BE:
            encodingName = QStringLiteral("UTF-16 BE");
            break;
        case QStringConverter::System:
            encodingName = QStringLiteral("本地编码");
            break;
        default:
            encodingName = QStringLiteral("UTF-8");
            break;
        }

        if (hasBom)
        {
            encodingName += QStringLiteral(" BOM");
        }
        return encodingName;
    }

    // stripKnownBom：
    // - 移除常见 BOM 头并返回是否命中。
    QByteArray stripKnownBom(const QByteArray& fileBytes, bool* hadBomOut)
    {
        QByteArray payload = fileBytes;
        bool hadBom = false;
        if (payload.startsWith("\xEF\xBB\xBF"))
        {
            payload.remove(0, 3);
            hadBom = true;
        }
        else if (payload.size() >= 2
            && static_cast<unsigned char>(payload.at(0)) == 0xFF
            && static_cast<unsigned char>(payload.at(1)) == 0xFE)
        {
            payload.remove(0, 2);
            hadBom = true;
        }
        else if (payload.size() >= 2
            && static_cast<unsigned char>(payload.at(0)) == 0xFE
            && static_cast<unsigned char>(payload.at(1)) == 0xFF)
        {
            payload.remove(0, 2);
            hadBom = true;
        }

        if (hadBomOut != nullptr)
        {
            *hadBomOut = hadBom;
        }
        return payload;
    }

    // decodeTextFileBytesAuto：
    // - 自动识别 BOM / UTF-8 / 本地编码。
    FileDecodeResult decodeTextFileBytesAuto(const QByteArray& fileBytes)
    {
        code_editor_file_session::FileSessionMetadata metadata;
        FileDecodeResult result;
        result.text = code_editor_file_session::decodeTextFileBytes(fileBytes, &metadata);
        result.success = metadata.validFromFile;
        result.encoding = metadata.encoding;
        result.hasBom = metadata.hasBom;
        result.lineEndingText = metadata.lineEndingText;
        return result;
    }

    // decodeTextFileBytesForced：
    // - 以调用方指定编码读取文本。
    FileDecodeResult decodeTextFileBytesForced(const QByteArray& fileBytes, QStringConverter::Encoding forcedEncoding)
    {
        FileDecodeResult result;
        result.success = true;
        result.encoding = forcedEncoding;

        bool hadBom = false;
        const QByteArray payload = stripKnownBom(fileBytes, &hadBom);
        result.hasBom = hadBom;

        switch (forcedEncoding)
        {
        case QStringConverter::Utf8:
            result.text = QString::fromUtf8(payload);
            break;
        case QStringConverter::Utf16LE:
            result.text = readAllTextWithEncoding(payload, QStringConverter::Utf16LE);
            break;
        case QStringConverter::Utf16BE:
            result.text = readAllTextWithEncoding(payload, QStringConverter::Utf16BE);
            break;
        case QStringConverter::System:
            result.text = QString::fromLocal8Bit(payload);
            break;
        default:
            result.encoding = QStringConverter::Utf8;
            result.text = QString::fromUtf8(payload);
            break;
        }

        result.lineEndingText = detectDominantLineEnding(result.text);
        return result;
    }

    // tryFormatJsonText：
    // - 尝试识别并格式化 JSON。
    bool tryFormatJsonText(const QString& inputText, QString* formattedTextOut)
    {
        const QString trimmedText = inputText.trimmed();
        if (trimmedText.size() < 2)
        {
            return false;
        }

        const QChar firstChar = trimmedText.front();
        const QChar lastChar = trimmedText.back();
        const bool looksLikeJson =
            (firstChar == QChar('{') && lastChar == QChar('}'))
            || (firstChar == QChar('[') && lastChar == QChar(']'));
        if (!looksLikeJson)
        {
            return false;
        }

        QJsonParseError parseError;
        const QJsonDocument jsonDocument = QJsonDocument::fromJson(trimmedText.toUtf8(), &parseError);
        if (parseError.error != QJsonParseError::NoError || jsonDocument.isNull())
        {
            return false;
        }

        QString formattedText = QString::fromUtf8(jsonDocument.toJson(QJsonDocument::Indented));
        if (formattedText.endsWith(QChar('\n')))
        {
            formattedText.chop(1);
        }

        if (formattedTextOut != nullptr)
        {
            *formattedTextOut = formattedText;
        }
        return true;
    }

    // tryFormatXmlText：
    // - 尝试识别并格式化 XML。
    bool tryFormatXmlText(const QString& inputText, QString* formattedTextOut)
    {
        const QString trimmedText = inputText.trimmed();
        if (trimmedText.size() < 3 || !trimmedText.startsWith(QChar('<')) || !trimmedText.endsWith(QChar('>')))
        {
            return false;
        }
        if (!trimmedText.contains(QStringLiteral("</"))
            && !trimmedText.contains(QStringLiteral("/>"))
            && !trimmedText.startsWith(QStringLiteral("<?xml")))
        {
            return false;
        }

        QXmlStreamReader xmlReader(trimmedText);
        QString formattedXmlText;
        QXmlStreamWriter xmlWriter(&formattedXmlText);
        xmlWriter.setAutoFormatting(true);
        xmlWriter.setAutoFormattingIndent(2);

        while (!xmlReader.atEnd())
        {
            xmlReader.readNext();
            if (xmlReader.tokenType() == QXmlStreamReader::Invalid)
            {
                break;
            }
            xmlWriter.writeCurrentToken(xmlReader);
        }

        if (xmlReader.hasError())
        {
            return false;
        }

        if (formattedTextOut != nullptr)
        {
            *formattedTextOut = formattedXmlText;
        }
        return true;
    }

    // autoFormatStructuredText：
    // - 默认自动格式化 JSON / XML。
    QString autoFormatStructuredText(const QString& inputText, QString* detectedKindOut)
    {
        if (detectedKindOut != nullptr)
        {
            detectedKindOut->clear();
        }

        // 超大文本跳过结构化格式化，优先保证编辑器交互流畅。
        constexpr int kAutoFormatMaxChars = 2 * 1024 * 1024;
        if (inputText.size() > kAutoFormatMaxChars)
        {
            return inputText;
        }

        QString formattedText;
        if (tryFormatJsonText(inputText, &formattedText))
        {
            if (detectedKindOut != nullptr)
            {
                *detectedKindOut = QStringLiteral("JSON");
            }
            return formattedText;
        }

        if (tryFormatXmlText(inputText, &formattedText))
        {
            if (detectedKindOut != nullptr)
            {
                *detectedKindOut = QStringLiteral("XML");
            }
            return formattedText;
        }

        return inputText;
    }
}

namespace ks::ui
{
    QString LocalizeGeneratedReport(const QString& sourceText)
    {
        return localizeGeneratedReport(sourceText);
    }
}

CodeEditorWidget::CodeEditorWidget(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
    applyThemeStyle();
    refreshReadOnlyUiState();
    updateStatusText();
}

CodeEditorWidget::~CodeEditorWidget()
{
    // 析构防护：
    // - 输入：Qt 父子销毁链触发析构；
    // - 处理：先标记销毁中，再断开编辑器发往本组件的状态刷新信号；
    // - 返回：无返回值，子控件仍由 Qt 父子机制回收。
    m_destroying = true;
    if (m_editor != nullptr)
    {
        QObject::disconnect(m_editor, nullptr, this, nullptr);
    }
}

QString CodeEditorWidget::text() const
{
    if (m_readOnlyMode && m_reportTextActive) return m_reportOriginalText;
    return (m_editor == nullptr) ? QString() : m_editor->toPlainText();
}

void CodeEditorWidget::setText(const QString& plainText)
{
    if (m_readOnlyMode)
    {
        setLocalizedText(plainText);
        return;
    }

    setRawText(plainText);
}

void CodeEditorWidget::setRawText(const QString& plainText)
{
    m_localizedSourceText.clear();
    m_localizedRawSuffix.clear();
    m_localizedTextActive = false;
    m_reportTextActive = false;
    m_reportOriginalText.clear();
    if (m_editor == nullptr)
    {
        return;
    }

    const QPointer<CodeEditorWidget> self(this);
    m_editor->setPlainText(plainText);
    if (!self) return;
    resetFileSessionMetadata();
    updateStructuredReportView();
    updateStatusText();
}

void CodeEditorWidget::setReportText(const QString& reportText, const bool preserveScroll)
{
    m_localizedSourceText.clear();
    m_localizedRawSuffix.clear();
    m_localizedTextActive = false;
    m_reportTextActive = true;
    m_reportOriginalText = reportText;
    if (m_editor == nullptr) return;
    const int vertical = m_editor->verticalScrollBar()->value();
    const int horizontal = m_editor->horizontalScrollBar()->value();
    const QPointer<CodeEditorWidget> self(this);
    m_editor->setPlainText(reportText);
    if (!self) return;
    resetFileSessionMetadata();
    updateStructuredReportView();
    updateStatusText();
    if (preserveScroll)
    {
        m_editor->verticalScrollBar()->setValue(vertical);
        m_editor->horizontalScrollBar()->setValue(horizontal);
    }
}

void CodeEditorWidget::setStructuredContentWidget(QWidget* contentWidget)
{
    if (m_structuredContent == contentWidget || contentWidget == this ||
        contentWidget == m_editor || contentWidget == m_structuredView ||
        (contentWidget != nullptr && contentWidget->isAncestorOf(this))) return;
    if (m_structuredContent != nullptr)
    {
        QWidget* previous = m_structuredContent.data();
        QObject::disconnect(previous, nullptr, this, nullptr);
        m_structuredContent.clear();
        m_viewStack->removeWidget(previous);
        previous->deleteLater();
    }
    if (contentWidget != nullptr)
    {
        m_viewStack->addWidget(contentWidget);
        m_structuredContent = contentWidget;
        connect(contentWidget, &QObject::destroyed, this, [this]() {
            m_structuredContent.clear();
            if (!m_destroying) updateStructuredReportView();
        });
    }
    updateStructuredReportView();
}

void CodeEditorWidget::appendReportText(const QString& reportText)
{
    const QString previous = text();
    m_localizedSourceText.clear();
    m_localizedRawSuffix.clear();
    m_localizedTextActive = false;
    m_reportTextActive = true;
    m_reportOriginalText = previous.isEmpty() ? reportText : previous + QLatin1Char('\n') + reportText;
    const QPointer<CodeEditorWidget> self(this);
    m_editor->appendPlainText(reportText);
    if (!self) return;
    resetFileSessionMetadata();
    updateStructuredReportView();
}

void CodeEditorWidget::setPlaceholderText(const QString& placeholder)
{
    m_editor->setPlaceholderText(placeholder);
}

void CodeEditorWidget::appendRawText(const QString& rawText, const bool autoScroll)
{
    // 退出报告缓存后只增量追加文档，避免逐行 setPlainText 丢失选择和撤销历史。
    m_localizedSourceText.clear();
    m_localizedRawSuffix.clear();
    m_localizedTextActive = false;
    m_reportTextActive = false;
    m_reportOriginalText.clear();
    const int vertical = m_editor->verticalScrollBar()->value();
    const int horizontal = m_editor->horizontalScrollBar()->value();
    const bool atBottom = vertical >= m_editor->verticalScrollBar()->maximum();
    const QPointer<CodeEditorWidget> guard(this);
    m_editor->appendPlainText(rawText);
    if (!guard) return;
    resetFileSessionMetadata();
    updateStructuredReportView();
    m_editor->verticalScrollBar()->setValue(autoScroll && atBottom
        ? m_editor->verticalScrollBar()->maximum() : vertical);
    m_editor->horizontalScrollBar()->setValue(horizontal);
}

void CodeEditorWidget::setMaximumBlockCount(const int count)
{
    // 容量限制只服务原文日志，明确清除完整报告缓存，防止复制出已被裁剪的旧正文。
    m_localizedSourceText.clear();
    m_localizedRawSuffix.clear();
    m_localizedTextActive = false;
    m_reportTextActive = false;
    m_reportOriginalText.clear();
    m_editor->document()->setMaximumBlockCount(std::max(0, count));
    updateStructuredReportView();
    resetFileSessionMetadata();
}

void CodeEditorWidget::replaceRawText(const QString& rawText, const bool followTailIfAtBottom)
{
    // 主题/语言触发整批日志重建时只维护 viewport，不重翻译后端返回内容。
    const int vertical = m_editor->verticalScrollBar()->value();
    const int horizontal = m_editor->horizontalScrollBar()->value();
    const bool atBottom = vertical >= m_editor->verticalScrollBar()->maximum();
    const QPointer<CodeEditorWidget> guard(this);
    setRawText(rawText);
    if (!guard) return;
    m_editor->verticalScrollBar()->setValue(followTailIfAtBottom && atBottom
        ? m_editor->verticalScrollBar()->maximum() : vertical);
    m_editor->horizontalScrollBar()->setValue(horizontal);
}

int CodeEditorWidget::maximumBlockCount() const
{
    return m_editor->document()->maximumBlockCount();
}

void CodeEditorWidget::clear()
{
    setRawText(QString());
}

void CodeEditorWidget::setLocalizedText(const QString& sourceText)
{
    m_localizedSourceText = sourceText;
    m_localizedRawSuffix.clear();
    m_localizedTextActive = true;
    m_reportTextActive = true;
    if (m_editor == nullptr)
    {
        return;
    }

    const QPointer<CodeEditorWidget> self(this);
    m_reportOriginalText = localizeGeneratedReport(m_localizedSourceText) + m_localizedRawSuffix;
    m_editor->setPlainText(m_reportOriginalText);
    if (!self) return;
    resetFileSessionMetadata();
    updateStructuredReportView();
    updateStatusText();
}

void CodeEditorWidget::setLocalizedTextWithRawSuffix(
    const QString& sourceText,
    const QString& rawSuffix)
{
    m_localizedSourceText = sourceText;
    m_localizedRawSuffix = rawSuffix;
    m_localizedTextActive = true;
    m_reportTextActive = true;
    if (m_editor == nullptr)
    {
        return;
    }

    const QPointer<CodeEditorWidget> self(this);
    m_reportOriginalText = localizeGeneratedReport(m_localizedSourceText) + m_localizedRawSuffix;
    m_editor->setPlainText(m_reportOriginalText);
    if (!self) return;
    resetFileSessionMetadata();
    updateStructuredReportView();
    updateStatusText();
}

void CodeEditorWidget::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (!m_destroying && m_editor != nullptr && event != nullptr &&
        (event->type() == QEvent::PaletteChange || event->type() == QEvent::ApplicationPaletteChange))
    {
        if (!m_themeRefreshPending)
        {
            m_themeRefreshPending = true;
            QTimer::singleShot(0, this, [this]()
            {
                if (!m_destroying) applyThemeStyle();
                m_themeRefreshPending = false;
            });
        }
    }
    if (event == nullptr || event->type() != QEvent::LanguageChange ||
        !m_localizedTextActive || m_editor == nullptr)
    {
        return;
    }

    const int verticalScrollValue = m_editor->verticalScrollBar()->value();
    const int horizontalScrollValue = m_editor->horizontalScrollBar()->value();
    const QPointer<CodeEditorWidget> self(this);
    m_reportOriginalText = localizeGeneratedReport(m_localizedSourceText) + m_localizedRawSuffix;
    m_editor->setPlainText(m_reportOriginalText);
    if (!self) return;
    m_editor->verticalScrollBar()->setValue(verticalScrollValue);
    m_editor->horizontalScrollBar()->setValue(horizontalScrollValue);
    updateStatusText();
}

QString CodeEditorWidget::currentFilePath() const
{
    return m_currentFilePath;
}

void CodeEditorWidget::setCurrentFilePath(const QString& filePath)
{
    m_currentFilePath = filePath;
    updateStatusText();
}

void CodeEditorWidget::setReadOnly(const bool readOnly)
{
    if (m_readOnlyMode == readOnly)
    {
        return;
    }

    m_readOnlyMode = readOnly;
    if (!readOnly)
    {
        m_reportTextActive = false;
        m_reportOriginalText.clear();
        m_localizedTextActive = false;
        m_localizedSourceText.clear();
        m_localizedRawSuffix.clear();
    }
    refreshReadOnlyUiState();
    updateStatusText();
}

bool CodeEditorWidget::isReadOnly() const
{
    return m_readOnlyMode;
}

void CodeEditorWidget::setWordWrapEnabled(const bool enabled)
{
    m_editor->setLineWrapMode(enabled ? QPlainTextEdit::WidgetWidth : QPlainTextEdit::NoWrap);
    refreshActionButtonState();
}

bool CodeEditorWidget::wordWrapEnabled() const
{
    return m_editor->lineWrapMode() != QPlainTextEdit::NoWrap;
}

void CodeEditorWidget::setStructuredReportViewEnabled(const bool enabled)
{
    if (m_structuredViewEnabled == enabled)
    {
        return;
    }

    m_structuredViewEnabled = enabled;
    updateStructuredReportView();
}

QString CodeEditorWidget::currentEncodingDisplayText() const
{
    return m_fileSessionAvailable
        ? buildEncodingDisplayText(m_fileEncoding, m_fileHasBom)
        : QStringLiteral("未知");
}

bool CodeEditorWidget::openLocalFile(const QString& filePath)
{
    return loadLocalFile(filePath, false, QStringConverter::Utf8);
}

bool CodeEditorWidget::openLocalFileWithEncoding(const QString& filePath, const QStringConverter::Encoding encoding)
{
    return loadLocalFile(filePath, true, encoding);
}

bool CodeEditorWidget::reopenCurrentFileWithEncoding(const QStringConverter::Encoding encoding)
{
    if (m_currentFilePath.trimmed().isEmpty())
    {
        m_statusLabel->setText(QStringLiteral("重开失败：当前无文件路径。"));
        return false;
    }

    return loadLocalFile(m_currentFilePath, true, encoding);
}

void CodeEditorWidget::initializeUi()
{
    setObjectName(QStringLiteral("code_editor"));
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(0, 0, 0, 0);
    m_rootLayout->setSizeConstraint(QLayout::SetNoConstraint);
    m_rootLayout->setSpacing(0);
    m_toolbarWidget = new QWidget(this);
    m_toolbarWidget->setObjectName(QStringLiteral("code_editor_toolbar"));
    m_toolbarWidget->setMinimumWidth(0);
    m_toolbarWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_toolbarWidget->installEventFilter(this);
    m_toolbarLayout = new QHBoxLayout(m_toolbarWidget);
    m_toolbarLayout->setContentsMargins(8, 5, 8, 5);
    m_toolbarLayout->setSpacing(3);
    auto buildButton = [this](const QString& iconPath, const QString& tip) {
        auto* button = new QToolButton(m_toolbarWidget);
        button->setObjectName(QFileInfo(iconPath).baseName().replace(QStringLiteral("codeeditor_"), QStringLiteral("code_editor_")));
        button->setProperty("ksword_editor_icon_path", iconPath);
        button->setProperty("ksword_theme_icon_managed", true);
        const auto refreshIcon = [button, iconPath]() {
            button->setProperty("ksword_editor_glyph_down", button->isDown());
            button->setIcon(buildToolbarSvgIcon(iconPath, button));
        };
        connect(button, &QToolButton::pressed, button, refreshIcon);
        connect(button, &QToolButton::released, button, refreshIcon);
        connect(button, &QToolButton::toggled, button, refreshIcon);
        button->installEventFilter(this);
        refreshIcon();
        KswordTheme::ApplyCompactIconButtonMetrics(button);
        button->setToolTip(tip);
        button->setAutoRaise(true);
        button->setFocusPolicy(Qt::NoFocus);
        return button;
    };
    m_newButton = buildButton(QStringLiteral(":/Icon/codeeditor_new.svg"), QStringLiteral("新建 Ctrl+N"));
    m_openButton = buildButton(QStringLiteral(":/Icon/codeeditor_open.svg"), QStringLiteral("打开 Ctrl+O"));
    m_saveButton = buildButton(QStringLiteral(":/Icon/codeeditor_save.svg"), QStringLiteral("保存 Ctrl+S"));
    m_saveAsButton = buildButton(QStringLiteral(":/Icon/codeeditor_save_as.svg"), QStringLiteral("另存为 Ctrl+Shift+S"));
    m_undoButton = buildButton(QStringLiteral(":/Icon/codeeditor_undo.svg"), QStringLiteral("撤销 Ctrl+Z"));
    m_redoButton = buildButton(QStringLiteral(":/Icon/codeeditor_redo.svg"), QStringLiteral("重做 Ctrl+Y"));
    m_cutButton = buildButton(QStringLiteral(":/Icon/codeeditor_cut.svg"), QStringLiteral("剪切 Ctrl+X"));
    m_copyButton = buildButton(QStringLiteral(":/Icon/codeeditor_copy.svg"), QStringLiteral("复制 Ctrl+C"));
    m_pasteButton = buildButton(QStringLiteral(":/Icon/codeeditor_paste.svg"), QStringLiteral("粘贴 Ctrl+V"));
    m_findButton = buildButton(QStringLiteral(":/Icon/codeeditor_find.svg"), QStringLiteral("查找 Ctrl+F"));
    m_replaceButton = buildButton(QStringLiteral(":/Icon/codeeditor_replace.svg"), QStringLiteral("替换 Ctrl+H"));
    m_gotoButton = buildButton(QStringLiteral(":/Icon/codeeditor_goto.svg"), QStringLiteral("跳转行 Ctrl+G"));
    m_wrapButton = buildButton(QStringLiteral(":/Icon/codeeditor_wrap.svg"), QStringLiteral("切换自动换行"));
    m_wrapButton->setCheckable(true);
    m_fileLabel = new QLabel(this);
    m_fileLabel->setObjectName(QStringLiteral("code_editor_file"));
    m_fileLabel->installEventFilter(this);
    m_fileLabel->setTextFormat(Qt::PlainText);
    m_fileLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_toolbarLayout->addWidget(m_fileLabel, 1);
    for (auto* button : {m_openButton, m_saveButton, m_undoButton, m_redoButton, m_copyButton, m_findButton, m_replaceButton, m_wrapButton})
        m_toolbarLayout->addWidget(button);
    for (auto* button : {m_newButton, m_saveAsButton, m_cutButton, m_pasteButton, m_gotoButton}) button->hide();
    m_languageCombo = new QComboBox(m_toolbarWidget);
    m_languageCombo->setObjectName(QStringLiteral("code_editor_language"));
    m_languageCombo->addItems({QStringLiteral("自动"), QStringLiteral("纯文本"), QStringLiteral("JSON"),
        QStringLiteral("XML"), QStringLiteral("C/C++"), QStringLiteral("INI"), QStringLiteral("Shell")});
    m_languageCombo->setToolTip(QStringLiteral("语法高亮语言；切换不会改写正文。"));
    m_languageCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_languageCombo->setMinimumContentsLength(5);
    m_toolbarLayout->addWidget(m_languageCombo);
    m_moreButton = new QToolButton(m_toolbarWidget);
    m_moreButton->setObjectName(QStringLiteral("code_editor_more"));
    m_moreButton->setText(QStringLiteral("⋯"));
    m_moreButton->setToolTip(QStringLiteral("更多编辑操作"));
    KswordTheme::ApplyCompactIconButtonMetrics(m_moreButton);
    m_moreButton->setPopupMode(QToolButton::InstantPopup);
    auto* menu = new QMenu(m_moreButton);
    for (auto* button : {m_newButton, m_openButton, m_saveButton, m_saveAsButton, m_undoButton, m_redoButton,
        m_cutButton, m_copyButton, m_pasteButton, m_findButton, m_replaceButton, m_gotoButton, m_wrapButton}) {
        auto* action = menu->addAction(button->toolTip());
        action->setCheckable(button->isCheckable());
        connect(action, &QAction::triggered, button, &QToolButton::click);
        connect(menu, &QMenu::aboutToShow, action, [this, action, button]() {
            action->setText(button->toolTip());
            action->setIcon(button->icon());
            action->setEnabled(button->isEnabled());
            action->setChecked(button->isChecked());
            action->setVisible(!m_readOnlyMode || button == m_copyButton || button == m_findButton
                || button == m_gotoButton || button == m_wrapButton);
        });
    }
    menu->addSeparator();
    auto* syntaxMenu = menu->addMenu(QStringLiteral("语法高亮"));
    for (int index = 0; index < m_languageCombo->count(); ++index)
    {
        auto* action = syntaxMenu->addAction(m_languageCombo->itemText(index));
        action->setCheckable(true);
        connect(action, &QAction::triggered, this, [this, index]() { m_languageCombo->setCurrentIndex(index); });
        connect(syntaxMenu, &QMenu::aboutToShow, action, [this, action, index]() {
            action->setText(m_languageCombo->itemText(index));
            action->setChecked(m_languageCombo->currentIndex() == index);
        });
    }
    m_formatAction = menu->addAction(QStringLiteral("格式化 JSON / XML"));
    connect(menu, &QMenu::aboutToShow, m_formatAction, [this]() { m_formatAction->setVisible(!m_readOnlyMode); });
    connect(m_formatAction, &QAction::triggered, this, &CodeEditorWidget::formatDocument);
    m_whitespaceAction = menu->addAction(QStringLiteral("显示空白字符"));
    m_whitespaceAction->setCheckable(true);
    connect(m_whitespaceAction, &QAction::toggled, this, [this](bool visible) { m_editor->setWhitespaceVisible(visible); });
    m_moreButton->setMenu(menu);
    m_toolbarLayout->addWidget(m_moreButton);
    m_rootLayout->addWidget(m_toolbarWidget);

    m_findPanel = new QWidget(this);
    m_findPanel->setObjectName(QStringLiteral("code_editor_find_panel"));
    m_findPanel->setMinimumWidth(0);
    m_findPanel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    auto* findRows = new QVBoxLayout(m_findPanel);
    findRows->setContentsMargins(8, 5, 8, 5);
    findRows->setSpacing(4);
    m_findLayout = new QHBoxLayout;
    m_findLayout->setSpacing(3);
    findRows->addLayout(m_findLayout);
    m_findEdit = new QLineEdit(m_findPanel);
    m_findEdit->setObjectName(QStringLiteral("code_editor_find"));
    m_findEdit->setPlaceholderText(QStringLiteral("查找"));
    m_findEdit->setMinimumWidth(30);
    m_matchCaseButton = new QToolButton(m_findPanel);
    m_matchCaseButton->setObjectName(QStringLiteral("code_editor_match_case"));
    m_matchCaseButton->setText(QStringLiteral("Aa"));
    m_matchCaseButton->setToolTip(QStringLiteral("区分大小写"));
    m_matchCaseButton->setCheckable(true);
    m_wholeWordButton = new QToolButton(m_findPanel);
    m_wholeWordButton->setObjectName(QStringLiteral("code_editor_whole_word"));
    m_wholeWordButton->setText(QStringLiteral("W"));
    m_wholeWordButton->setToolTip(QStringLiteral("全词匹配"));
    m_wholeWordButton->setCheckable(true);
    m_findPrevButton = new QToolButton(m_findPanel);
    m_findPrevButton->setText(QStringLiteral("↑"));
    m_findPrevButton->setToolTip(QStringLiteral("向上查找上一个匹配项"));
    m_findNextButton = new QToolButton(m_findPanel);
    m_findNextButton->setText(QStringLiteral("↓"));
    m_findNextButton->setToolTip(QStringLiteral("向下查找下一个匹配项"));
    m_findCloseButton = new QToolButton(m_findPanel);
    m_findCloseButton->setText(QStringLiteral("×"));
    m_findCloseButton->setToolTip(QStringLiteral("关闭查找替换栏"));
    m_findResultLabel = new QLabel(m_findPanel);
    m_findResultLabel->setObjectName(QStringLiteral("code_editor_find_result"));
    m_findResultLabel->setTextFormat(Qt::PlainText);
    m_findResultLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_findLayout->addWidget(m_findEdit, 1);
    for (auto* button : {m_matchCaseButton, m_wholeWordButton, m_findPrevButton, m_findNextButton, m_findCloseButton}) m_findLayout->addWidget(button);
    m_findLayout->addWidget(m_findResultLabel);
    m_replaceRow = new QWidget(m_findPanel);
    auto* replaceLayout = new QHBoxLayout(m_replaceRow);
    replaceLayout->setContentsMargins(0, 0, 0, 0);
    replaceLayout->setSpacing(3);
    m_replaceEdit = new QLineEdit(m_replaceRow);
    m_replaceEdit->setObjectName(QStringLiteral("code_editor_replace"));
    m_replaceEdit->setPlaceholderText(QStringLiteral("替换为"));
    m_replaceEdit->setMinimumWidth(30);
    m_replaceOneButton = new QToolButton(m_replaceRow);
    m_replaceOneButton->setText(QStringLiteral("替换"));
    m_replaceOneButton->setToolTip(QStringLiteral("替换当前这一处匹配，并跳到下一处"));
    m_replaceAllButton = new QToolButton(m_replaceRow);
    m_replaceAllButton->setObjectName(QStringLiteral("code_editor_replace_all"));
    m_replaceAllButton->setText(QStringLiteral("全部替换"));
    m_replaceAllButton->setToolTip(QStringLiteral("一次性替换文中所有匹配项"));
    replaceLayout->addWidget(m_replaceEdit, 1);
    replaceLayout->addWidget(m_replaceOneButton);
    replaceLayout->addWidget(m_replaceAllButton);
    findRows->addWidget(m_replaceRow);
    m_replaceRow->hide();
    m_findPanel->hide();
    m_rootLayout->addWidget(m_findPanel);
    m_gotoPanel = new QWidget(this);
    m_gotoLayout = new QHBoxLayout(m_gotoPanel);
    m_gotoLayout->setContentsMargins(8, 5, 8, 5);
    m_gotoLayout->setSpacing(4);
    m_gotoLineEdit = new QLineEdit(m_gotoPanel);
    m_gotoLineEdit->setObjectName(QStringLiteral("code_editor_goto_input"));
    m_gotoLineEdit->setPlaceholderText(QStringLiteral("行号(从1开始)"));
    m_gotoApplyButton = new QToolButton(m_gotoPanel);
    m_gotoApplyButton->setText(QStringLiteral("执行"));
    m_gotoCloseButton = new QToolButton(m_gotoPanel);
    m_gotoCloseButton->setText(QStringLiteral("×"));
    m_gotoCloseButton->setToolTip(QStringLiteral("关闭跳转行栏"));
    m_gotoLayout->addWidget(new QLabel(QStringLiteral("跳转行:"), m_gotoPanel));
    m_gotoLayout->addWidget(m_gotoLineEdit, 1);
    m_gotoLayout->addWidget(m_gotoApplyButton);
    m_gotoLayout->addWidget(m_gotoCloseButton);
    m_gotoPanel->hide();
    m_rootLayout->addWidget(m_gotoPanel);
    m_editor = new CodeTextEdit(this);
    m_editor->setObjectName(QStringLiteral("code_editor_text"));
    m_editor->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    m_editor->setPlaceholderText(QStringLiteral("输入文本或打开文件，支持语法高亮、查找替换与行跳转。"));
    m_viewStack = new QStackedWidget(this);
    m_viewStack->setMinimumSize(0, 0);
    m_viewStack->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    m_structuredView = new ks::ui::ReportStructuredView(m_viewStack);
    m_viewStack->addWidget(m_editor);
    m_viewStack->addWidget(m_structuredView);
    m_rootLayout->addWidget(m_viewStack, 1);
    m_structuredCombo = new QComboBox(m_toolbarWidget);
    m_structuredCombo->setObjectName(QStringLiteral("code_editor_structure"));
    m_structuredCombo->addItems({QStringLiteral("结构视图"), QStringLiteral("原始文本")});
    m_structuredCombo->setToolTip(QStringLiteral("在结构视图与原始文本之间切换：结构视图按字段和表格解析当前报告，原始文本保留完整报告便于全文检索和整段复制"));
    m_toolbarLayout->insertWidget(1, m_structuredCombo);
    m_structuredCombo->hide();
    m_statusWidget = new QWidget(this);
    m_statusWidget->setObjectName(QStringLiteral("code_editor_footer"));
    m_statusWidget->setMinimumWidth(0);
    m_statusWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    auto* statusLayout = new QHBoxLayout(m_statusWidget);
    statusLayout->setContentsMargins(10, 4, 10, 4);
    statusLayout->setSpacing(12);
    const auto label = [this](const QString& name) {
        auto* value = new QLabel(m_statusWidget);
        value->setObjectName(name);
        value->setTextFormat(Qt::PlainText);
        value->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        return value;
    };
    m_positionLabel = label(QStringLiteral("code_editor_position"));
    m_documentLabel = label(QStringLiteral("code_editor_length"));
    m_modeLabel = label(QStringLiteral("code_editor_mode"));
    m_encodingLabel = label(QStringLiteral("code_editor_encoding"));
    m_statusLabel = label(QStringLiteral("code_editor_status"));
    m_statusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    for (auto* item : {m_positionLabel, m_documentLabel, m_modeLabel, m_encodingLabel}) statusLayout->addWidget(item);
    statusLayout->addWidget(m_statusLabel, 1);
    m_rootLayout->addWidget(m_statusWidget);
}

void CodeEditorWidget::initializeConnections()
{
    connect(m_languageCombo, &QComboBox::currentIndexChanged, this, [this](int index) {
        m_editor->setSyntaxLanguage(static_cast<CodeTextEdit::SyntaxLanguage>(index));
    });
    connect(m_findEdit, &QLineEdit::textChanged, this, &CodeEditorWidget::updateFindHighlights);
    connect(m_matchCaseButton, &QToolButton::toggled, this, &CodeEditorWidget::updateFindHighlights);
    connect(m_wholeWordButton, &QToolButton::toggled, this, &CodeEditorWidget::updateFindHighlights);
    connect(m_editor->document(), &QTextDocument::modificationChanged, this, [this]() { updateStatusText(); });
    connect(m_newButton, &QToolButton::clicked, this, [this]()
        {
            if (m_readOnlyMode)
            {
                return;
            }
            m_localizedSourceText.clear();
            m_localizedRawSuffix.clear();
            m_localizedTextActive = false;
            m_reportTextActive = false;
            const QPointer<CodeEditorWidget> self(this);
            m_editor->clear();
            if (!self) return;
            m_currentFilePath.clear();
            resetFileSessionMetadata();
            updateStatusText();
        });

    connect(m_openButton, &QToolButton::clicked, this, [this]()
        {
            openTextFile();
        });

    connect(m_saveButton, &QToolButton::clicked, this, [this]()
        {
            saveTextFile(false);
        });

    connect(m_saveAsButton, &QToolButton::clicked, this, [this]()
        {
            saveTextFile(true);
        });

    connect(m_undoButton, &QToolButton::clicked, m_editor, &QPlainTextEdit::undo);
    connect(m_redoButton, &QToolButton::clicked, m_editor, &QPlainTextEdit::redo);
    connect(m_cutButton, &QToolButton::clicked, m_editor, &QPlainTextEdit::cut);
    connect(m_copyButton, &QToolButton::clicked, this, [this]()
        {
            copyCurrentView();
        });
    connect(m_pasteButton, &QToolButton::clicked, m_editor, &QPlainTextEdit::paste);

    connect(m_findButton, &QToolButton::clicked, this, [this]()
        {
            openFindReplacePanel(false);
        });

    connect(m_replaceButton, &QToolButton::clicked, this, [this]()
        {
            openFindReplacePanel(true);
        });

    connect(m_gotoButton, &QToolButton::clicked, this, [this]()
        {
            openGotoPanel();
        });

    connect(m_wrapButton, &QToolButton::clicked, this, [this]()
        {
            activateTextView();
            const bool enableWrap = (m_editor->lineWrapMode() == QPlainTextEdit::NoWrap);
            m_editor->setLineWrapMode(enableWrap ? QPlainTextEdit::WidgetWidth : QPlainTextEdit::NoWrap);
            refreshActionButtonState();
        });

    connect(m_findPrevButton, &QToolButton::clicked, this, [this]()
        {
            findByDirection(false);
        });

    connect(m_findNextButton, &QToolButton::clicked, this, [this]()
        {
            findByDirection(true);
        });

    connect(m_replaceOneButton, &QToolButton::clicked, this, [this]()
        {
            replaceCurrentSelection();
        });

    connect(m_replaceAllButton, &QToolButton::clicked, this, [this]()
        {
            const int replacedCount = replaceAllMatches();
            m_statusLabel->setText(QStringLiteral("替换完成：%1 处。").arg(replacedCount));
        });

    connect(m_findCloseButton, &QToolButton::clicked, this, [this]()
        {
            m_findPanel->setVisible(false);
            m_editor->setExternalExtraSelections({});
        });

    connect(m_findEdit, &QLineEdit::returnPressed, this, [this]()
        {
            findByDirection(true);
        });

    connect(m_gotoApplyButton, &QToolButton::clicked, this, [this]()
        {
            jumpToInputLine();
        });

    connect(m_gotoCloseButton, &QToolButton::clicked, this, [this]()
        {
            m_gotoPanel->setVisible(false);
        });

    connect(m_gotoLineEdit, &QLineEdit::returnPressed, this, [this]()
        {
            jumpToInputLine();
        });

    connect(m_editor, &QPlainTextEdit::cursorPositionChanged, this, [this]()
        {
            updateStatusText();
        });

    connect(m_editor, &QPlainTextEdit::textChanged, this, [this]()
        {
            updateStatusText();
            updateStructuredReportView();
            updateFindHighlights();
            // A consumer may close the owner. Notify after Qt's native document
            // update has returned, coalescing bursts into the latest contents.
            if (!m_contentNotificationPending)
            {
                m_contentNotificationPending = true;
                QTimer::singleShot(0, this, [this]() {
                    m_contentNotificationPending = false;
                    const QString contents = text();
                    emit contentChanged(contents);
                });
            }
        });

    connect(m_editor, &QPlainTextEdit::undoAvailable, this, [this](bool) { refreshActionButtonState(); });
    connect(m_editor, &QPlainTextEdit::redoAvailable, this, [this](bool) { refreshActionButtonState(); });
    connect(m_editor, &QPlainTextEdit::copyAvailable, this, [this](bool) { refreshActionButtonState(); });
    connect(QApplication::clipboard(), &QClipboard::dataChanged, this, [this]() { refreshActionButtonState(); });

    connect(m_structuredCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
        [this](const int selectedIndex)
        {
            if (m_destroying || m_viewStack == nullptr || m_structuredView == nullptr)
            {
                return;
            }
            // All report pages use 0 = structured, 1 = original text.
            const bool structuredSelected = selectedIndex == 0 && m_readOnlyMode &&
                m_reportTextActive && m_structuredViewEnabled &&
                (m_structuredContent != nullptr || m_structuredView->hasStructure());
            // 选择记在进程内：这是“这次排查我想怎么看”，不是需要长期保存的偏好。
            g_preferStructuredReportView = structuredSelected;
            m_viewStack->setCurrentWidget(structuredSelected
                ? structuredContentWidget()
                : static_cast<QWidget*>(m_editor));
            if (structuredSelected) closeInlinePanels();
            refreshActionButtonState();
            // 换页后滚动条可能出现或消失，右边距要重算。
            positionStructuredSwitch();
        });

    new QShortcut(QKeySequence::Find, this, [this]()
        {
            openFindReplacePanel(false);
        });

    new QShortcut(QKeySequence::Replace, this, [this]()
        {
            openFindReplacePanel(true);
        });

    new QShortcut(QKeySequence(QStringLiteral("Ctrl+G")), this, [this]()
        {
            openGotoPanel();
        });

    new QShortcut(QKeySequence::FindNext, this, [this]()
        {
            findByDirection(true);
        });

    new QShortcut(QKeySequence::FindPrevious, this, [this]()
        {
            findByDirection(false);
        });

    new QShortcut(QKeySequence::Save, this, [this]()
        {
            saveTextFile(false);
        });

    new QShortcut(QKeySequence::Open, this, [this]()
        {
            openTextFile();
        });

    new QShortcut(QKeySequence::New, this, [this]()
        {
            m_newButton->click();
        });

    new QShortcut(QKeySequence::SaveAs, this, [this]() { m_saveAsButton->click(); });
    new QShortcut(QKeySequence::Copy, this, [this]() { m_copyButton->click(); });
    // 每个 Dock 可能有多个编辑器；窗口级快捷键会冲突，必须限定到当前编辑器。
    for (QShortcut* shortcut : findChildren<QShortcut*>(QString(), Qt::FindDirectChildrenOnly))
    {
        shortcut->setContext(Qt::WidgetWithChildrenShortcut);
    }
}

void CodeEditorWidget::applyThemeStyle()
{
    const QString toolStyle = buildToolButtonStyle();
    const QString inputStyle = buildInputStyle();

    const QList<QToolButton*> buttonList{
        m_newButton,m_openButton,m_saveButton,m_saveAsButton,m_undoButton,m_redoButton,m_cutButton,m_copyButton,m_pasteButton,
        m_findButton,m_replaceButton,m_gotoButton,m_wrapButton,m_findPrevButton,m_findNextButton,m_replaceOneButton,m_replaceAllButton,
        m_findCloseButton,m_gotoApplyButton,m_gotoCloseButton,m_matchCaseButton,m_wholeWordButton,m_moreButton
    };
    for (QToolButton* button : buttonList)
    {
        if (button != nullptr)
        {
            if (button->styleSheet() != toolStyle) button->setStyleSheet(toolStyle);
        }
    }

    // 结构/文本切换参与工具栏布局，复用同一主题下拉框样式。
    if (m_structuredCombo != nullptr)
    {
        const QString comboStyle = buildFloatingSwitchStyle();
        if (m_structuredCombo->styleSheet() != comboStyle) m_structuredCombo->setStyleSheet(comboStyle);
    }

    for (QLineEdit* input : { m_findEdit, m_replaceEdit, m_gotoLineEdit })
    {
        if (input->styleSheet() != inputStyle) input->setStyleSheet(inputStyle);
    }
    m_toolbarWidget->setStyleSheet(QStringLiteral(
        "QWidget#code_editor_toolbar { background:palette(base); border-bottom:1px solid palette(mid); }"));
    m_statusWidget->setStyleSheet(QStringLiteral(
        "QWidget#code_editor_footer { background:palette(alternate-base); border-top:1px solid palette(mid); }"
        "QWidget#code_editor_footer QLabel { color:palette(text); }"));
    m_findPanel->setStyleSheet(QStringLiteral(
        "QWidget#code_editor_find_panel { background:palette(alternate-base); border-bottom:1px solid palette(mid); }"));
    m_languageCombo->setStyleSheet(buildFloatingSwitchStyle());
    // 父/子样式全部安装后再读按钮背景，避免缓存上一阶段的对比色。
    for (QToolButton* button : buttonList)
    {
        if (button == nullptr)
        {
            continue;
        }
        button->ensurePolished();
        const QString iconPath = button->property("ksword_editor_icon_path").toString();
        if (!iconPath.isEmpty())
        {
            button->setProperty("ksword_editor_glyph_down", button->isDown());
            button->setIcon(buildToolbarSvgIcon(iconPath, button));
        }
    }
    updateFindHighlights();
}

void CodeEditorWidget::refreshReadOnlyUiState()
{
    if (m_editor != nullptr)
    {
        m_editor->setReadOnly(m_readOnlyMode);
    }

    // 写入类按钮：只读模式下统一禁用。
    if (m_newButton != nullptr) m_newButton->setEnabled(!m_readOnlyMode);
    if (m_openButton != nullptr) m_openButton->setEnabled(!m_readOnlyMode);
    if (m_saveButton != nullptr) m_saveButton->setEnabled(!m_readOnlyMode);
    if (m_saveAsButton != nullptr) m_saveAsButton->setEnabled(!m_readOnlyMode);
    if (m_replaceButton != nullptr) m_replaceButton->setEnabled(!m_readOnlyMode);
    if (m_replaceOneButton != nullptr) m_replaceOneButton->setEnabled(!m_readOnlyMode);
    if (m_replaceAllButton != nullptr) m_replaceAllButton->setEnabled(!m_readOnlyMode);

    // 只读模式下隐藏替换输入，保留查找与跳转能力。
    if (m_readOnlyMode)
    {
        m_replaceEdit->setVisible(false);
        m_replaceOneButton->setVisible(false);
        m_replaceAllButton->setVisible(false);
    }

    // 页面常在写完文本之后才置只读，这里补一次判定，避免结构视图入口被漏掉。
    updateStructuredReportView();
    updateToolbarLayout();
    m_formatAction->setEnabled(!m_readOnlyMode);
}

void CodeEditorWidget::refreshActionButtonState()
{
    if (m_destroying || m_editor == nullptr) return;
    const bool editable = !m_readOnlyMode;
    const bool selected = m_editor->textCursor().hasSelection();
    m_undoButton->setEnabled(editable && m_editor->document()->isUndoAvailable());
    m_redoButton->setEnabled(editable && m_editor->document()->isRedoAvailable());
    m_cutButton->setEnabled(editable && selected);
    m_copyButton->setEnabled(m_viewStack->currentWidget() != m_editor || selected);
    const QMimeData* clipboardData = QApplication::clipboard()->mimeData();
    m_pasteButton->setEnabled(editable && clipboardData != nullptr && clipboardData->hasText());
    m_wrapButton->setChecked(m_editor->lineWrapMode() != QPlainTextEdit::NoWrap);
}

void CodeEditorWidget::activateTextView()
{
    if (m_viewStack->currentWidget() != m_editor)
    {
        m_structuredCombo->setCurrentIndex(1);
    }
}

QWidget* CodeEditorWidget::structuredContentWidget() const
{
    return m_structuredContent != nullptr ? m_structuredContent.data() : m_structuredView;
}

void CodeEditorWidget::copyCurrentView()
{
    QApplication::clipboard()->setText(copyTextForCurrentView());
}

QString CodeEditorWidget::copyTextForCurrentView() const
{
    QWidget* current = m_viewStack->currentWidget();
    if (current == m_editor) return m_editor->textCursor().selectedText().replace(QChar::ParagraphSeparator, QLatin1Char('\n'));
    if (current == m_structuredView) return m_structuredView->selectionOrReportText();
    // typed 字段树和解析报告共用同一复制器；无选区时保留完整报告原文。
    auto* view = qobject_cast<QAbstractItemView*>(current);
    if (view == nullptr) view = current->findChild<QAbstractItemView*>();
    return ks::ui::StructuredCopyText(view);
}

bool CodeEditorWidget::eventFilter(QObject* watchedObject, QEvent* eventObject)
{
    const QPointer<CodeEditorWidget> self(this); // 新的属性刷新步骤可能同步关闭宿主。
    // 释放/失焦取消按下后即使按钮隐藏也补刷，不能只等可见控件的 Paint。
    if (!m_destroying && eventObject != nullptr
        && (eventObject->type() == QEvent::PaletteChange || eventObject->type() == QEvent::StyleChange
            || eventObject->type() == QEvent::MouseButtonRelease || eventObject->type() == QEvent::FocusOut))
    {
        if (auto* button = qobject_cast<QToolButton*>(watchedObject))
        {
            if (!button->property("ksword_editor_icon_path").toString().isEmpty())
            {
                queueToolbarGlyphRefresh(button);
                if (self.isNull())
                {
                    return true;
                }
            }
        }
        else if (watchedObject == m_toolbarWidget
            && (eventObject->type() == QEvent::PaletteChange || eventObject->type() == QEvent::StyleChange))
        {
            // 透明按钮的实际父表面变化也要补刷，不能只依赖按钮自身的 Base。
            for (QToolButton* toolbarButton : m_toolbarWidget->findChildren<QToolButton*>(QString(), Qt::FindDirectChildrenOnly))
            {
                if (!toolbarButton->property("ksword_editor_icon_path").toString().isEmpty())
                {
                    queueToolbarGlyphRefresh(toolbarButton);
                    if (self.isNull())
                    {
                        return true;
                    }
                }
            }
        }
    }
    // setDown(false)、失焦等取消路径未必发released；绘制前只在down改变时修正Normal图标。
    if (!m_destroying && eventObject != nullptr && eventObject->type() == QEvent::Paint)
    {
        if (auto* button = qobject_cast<QToolButton*>(watchedObject))
        {
            const QString path = button->property("ksword_editor_icon_path").toString();
            if (!path.isEmpty() && button->property("ksword_editor_glyph_down").toBool() != button->isDown())
            {
                button->setProperty("ksword_editor_glyph_down", button->isDown());
                button->setIcon(buildToolbarSvgIcon(path, button));
            }
        }
    }
    if (!m_destroying &&
        (watchedObject == m_viewStack || watchedObject == m_toolbarWidget || watchedObject == m_fileLabel) &&
        eventObject != nullptr &&
        (eventObject->type() == QEvent::Resize || eventObject->type() == QEvent::Show))
    {
        positionStructuredSwitch();
    }
    return QWidget::eventFilter(watchedObject, eventObject);
}

void CodeEditorWidget::positionStructuredSwitch()
{
    // The switch participates in layout and never covers a report or text row.
    updateToolbarLayout();
}

void CodeEditorWidget::updateToolbarLayout()
{
    if (m_destroying || !m_toolbarWidget || !m_editor || !m_fileLabel || !m_viewStack
        || !m_documentLabel || !m_encodingLabel || !m_replaceRow || !m_languageCombo) return;
    const int width = m_toolbarWidget->width();
    const bool compact = width < 620;
    const bool tiny = width < 420;
    for (auto* button : {m_openButton, m_saveButton, m_undoButton, m_redoButton})
        button->setVisible(!m_readOnlyMode && !compact);
    m_replaceButton->setVisible(!m_readOnlyMode && !tiny);
    m_languageCombo->setVisible(!tiny && m_viewStack->currentWidget() == m_editor);
    m_documentLabel->setVisible(!tiny);
    m_encodingLabel->setVisible(!compact);
    m_replaceRow->setVisible(m_replaceEnabled && !m_readOnlyMode);
    const QString title = m_currentFilePath.isEmpty()
        ? (m_readOnlyMode ? QStringLiteral("文本查看") : QStringLiteral("未命名"))
        : QFileInfo(m_currentFilePath).fileName();
    const QString dirtyTitle = title + (m_editor->document()->isModified() && !m_readOnlyMode ? QStringLiteral(" *") : QString());
    m_fileLabel->setText(m_fileLabel->fontMetrics().elidedText(dirtyTitle, Qt::ElideMiddle, std::max(0, m_fileLabel->width())));
    m_fileLabel->setToolTip(m_currentFilePath.isEmpty() ? title : m_currentFilePath);
}

void CodeEditorWidget::formatDocument()
{
    if (m_readOnlyMode) return;
    const QString before = m_editor->toPlainText();
    const QString formatted = applyStructuredAutoFormatIfNeeded(before);
    if (before == formatted) return;
    QTextCursor cursor(m_editor->document());
    cursor.beginEditBlock();
    cursor.select(QTextCursor::Document);
    cursor.insertText(formatted);
    cursor.endEditBlock();
}

void CodeEditorWidget::updateStructuredReportView()
{
    if (m_destroying ||
        m_editor == nullptr ||
        m_viewStack == nullptr ||
        m_structuredView == nullptr ||
        m_structuredCombo == nullptr)
    {
        return;
    }

    // 只有只读报告才解析：用户正在编辑的文件、原始日志和字节视图一律保持纯文本。
    if (!m_structuredViewEnabled || !m_readOnlyMode || !m_reportTextActive)
    {
        m_structuredView->setReportText(QString());
        m_structuredCombo->hide();
        m_viewStack->setCurrentWidget(m_editor);
        updateToolbarLayout();
        refreshActionButtonState();
        return;
    }
    const QString currentText = text();
    if (m_structuredContent != nullptr)
    {
        // typed 字段只共享复制策略，原文仍由其真实采集宿主提供，不再次解析节点。
        auto views = m_structuredContent->findChildren<QAbstractItemView*>();
        if (auto* rootView = qobject_cast<QAbstractItemView*>(m_structuredContent.data())) views.prepend(rootView);
        for (auto* view : views) ks::ui::SetStructuredCopyFallback(view, currentText);
    }
    const bool eligible =
        m_structuredViewEnabled && m_readOnlyMode && !currentText.trimmed().isEmpty();
    const bool structured = eligible && (m_structuredContent != nullptr || m_structuredView->setReportText(currentText));

    m_structuredCombo->setVisible(structured);
    if (!structured)
    {
        m_viewStack->setCurrentWidget(m_editor);
        refreshActionButtonState();
        return;
    }

    // 这里是程序按记忆恢复视图，不是用户选择；阻断信号避免把状态又写回全局偏好。
    const QSignalBlocker switchSignalBlocker(m_structuredCombo);
    m_structuredCombo->setCurrentIndex(g_preferStructuredReportView ? 0 : 1);
    m_viewStack->setCurrentWidget(g_preferStructuredReportView
        ? structuredContentWidget()
        : static_cast<QWidget*>(m_editor));
    positionStructuredSwitch();
    refreshActionButtonState();
}

void CodeEditorWidget::openFindReplacePanel(const bool replaceEnabled)
{
    activateTextView();
    const bool effectiveReplaceEnabled = replaceEnabled && !m_readOnlyMode;
    m_replaceEnabled = effectiveReplaceEnabled;
    m_findPanel->setVisible(true);
    m_gotoPanel->setVisible(false);
    m_replaceRow->setVisible(effectiveReplaceEnabled);
    m_replaceEdit->setVisible(effectiveReplaceEnabled);
    m_replaceOneButton->setVisible(effectiveReplaceEnabled);
    m_replaceAllButton->setVisible(effectiveReplaceEnabled);
    m_findEdit->setFocus(Qt::ShortcutFocusReason);
    m_findEdit->selectAll();
    updateFindHighlights();
}

void CodeEditorWidget::openGotoPanel()
{
    activateTextView();
    m_findPanel->setVisible(false);
    m_gotoPanel->setVisible(true);
    m_gotoLineEdit->setFocus(Qt::ShortcutFocusReason);
    m_gotoLineEdit->selectAll();
}

void CodeEditorWidget::closeInlinePanels()
{
    m_findPanel->setVisible(false);
    m_gotoPanel->setVisible(false);
    m_editor->setExternalExtraSelections({});
}

void CodeEditorWidget::updateFindHighlights()
{
    if (m_destroying || !m_editor || !m_findResultLabel) return;
    QList<QTextEdit::ExtraSelection> selections;
    const QString key = m_findEdit->text();
    const bool bounded = m_editor->document()->characterCount() <= 2 * 1024 * 1024;
    if (!key.isEmpty() && m_findPanel->isVisible() && bounded)
    {
        QTextDocument::FindFlags flags;
        if (m_matchCaseButton->isChecked()) flags |= QTextDocument::FindCaseSensitively;
        if (m_wholeWordButton->isChecked()) flags |= QTextDocument::FindWholeWords;
        QTextCursor cursor(m_editor->document());
        for (int count = 0; count < 500; ++count)
        {
            cursor = m_editor->document()->find(key, cursor, flags);
            if (cursor.isNull()) break;
            QTextEdit::ExtraSelection selection;
            selection.cursor = cursor;
            const QColor background = KswordTheme::BlendColors(m_editor->palette().color(QPalette::Base),
                m_editor->palette().color(QPalette::Highlight), 28);
            selection.format.setBackground(background);
            selection.format.setForeground(KswordTheme::EnsureTextContrast(
                m_editor->palette().color(QPalette::Text), background));
            selections.push_back(selection);
        }
    }
    m_editor->setExternalExtraSelections(selections);
    m_findResultLabel->setText(key.isEmpty() ? QString()
        : !bounded ? QStringLiteral("按需查找")
        : selections.size() >= 500 ? QStringLiteral("500+") : QString::number(selections.size()));
}

void CodeEditorWidget::updateStatusText()
{
    if (m_destroying || !m_editor || !m_statusLabel) return;
    const QTextCursor cursor = m_editor->textCursor();
    m_positionLabel->setText(ks::i18n::sourceText(QStringLiteral("行 %1  |  列 %2"))
        .arg(cursor.blockNumber() + 1).arg(cursor.positionInBlock() + 1));
    const int chars = std::max(0, m_editor->document()->characterCount() - 1);
    m_documentLabel->setText(cursor.hasSelection()
        ? ks::i18n::sourceText(QStringLiteral("选中 %1 / %2 字符")).arg(cursor.selectionEnd() - cursor.selectionStart()).arg(chars)
        : ks::i18n::sourceText(QStringLiteral("%1 字符")).arg(chars));
    m_modeLabel->setText(ks::i18n::sourceText(m_readOnlyMode ? QStringLiteral("只读") : QStringLiteral("可编辑")));
    m_encodingLabel->setText(m_fileSessionAvailable
        ? currentEncodingDisplayText() + QStringLiteral(" · ") + (m_fileLineEnding == QStringLiteral("\r\n") ? QStringLiteral("CRLF")
            : m_fileLineEnding == QStringLiteral("\r") ? QStringLiteral("CR") : QStringLiteral("LF"))
        : QStringLiteral("Unicode"));
    updateToolbarLayout();
}

bool CodeEditorWidget::findByDirection(const bool forward)
{
    activateTextView();
    const QString keyText = m_findEdit->text();
    if (keyText.isEmpty())
    {
        m_statusLabel->setText(QStringLiteral("查找失败：请输入查找内容。"));
        return false;
    }

    QTextDocument::FindFlags flags;
    if (!forward) flags |= QTextDocument::FindBackward;
    if (m_matchCaseButton->isChecked()) flags |= QTextDocument::FindCaseSensitively;
    if (m_wholeWordButton->isChecked()) flags |= QTextDocument::FindWholeWords;

    bool found = m_editor->find(keyText, flags);
    if (!found)
    {
        QTextCursor cursor = m_editor->textCursor();
        cursor.movePosition(forward ? QTextCursor::Start : QTextCursor::End);
        m_editor->setTextCursor(cursor);
        found = m_editor->find(keyText, flags);
    }

    m_statusLabel->setText(found
        ? QStringLiteral("查找成功：%1").arg(keyText)
        : QStringLiteral("查找结束：未找到 %1").arg(keyText));
    return found;
}

void CodeEditorWidget::replaceCurrentSelection()
{
    if (m_readOnlyMode)
    {
        return;
    }

    const QString findText = m_findEdit->text();
    if (findText.isEmpty())
    {
        m_statusLabel->setText(QStringLiteral("替换失败：查找文本为空。"));
        return;
    }

    QTextCursor cursor = m_editor->textCursor();
    QTextDocument::FindFlags flags;
    if (m_matchCaseButton->isChecked()) flags |= QTextDocument::FindCaseSensitively;
    if (m_wholeWordButton->isChecked()) flags |= QTextDocument::FindWholeWords;
    QTextCursor query(m_editor->document());
    query.setPosition(cursor.selectionStart());
    const QTextCursor verified = m_editor->document()->find(findText, query, flags);
    if (!cursor.hasSelection() || verified.isNull() || verified.selectionStart() != cursor.selectionStart()
        || verified.selectionEnd() != cursor.selectionEnd())
    {
        if (!findByDirection(true))
        {
            return;
        }
        cursor = m_editor->textCursor();
    }

    cursor.insertText(m_replaceEdit->text());
    m_editor->setTextCursor(cursor);
    m_statusLabel->setText(QStringLiteral("已替换当前命中。"));
    findByDirection(true);
}

int CodeEditorWidget::replaceAllMatches()
{
    if (m_readOnlyMode)
    {
        return 0;
    }

    const QString findText = m_findEdit->text();
    if (findText.isEmpty())
    {
        return 0;
    }

    const QString replaceText = m_replaceEdit->text();
    QTextCursor backupCursor = m_editor->textCursor();
    QTextCursor headCursor = m_editor->textCursor();
    headCursor.movePosition(QTextCursor::Start);
    m_editor->setTextCursor(headCursor);

    int hitCount = 0;
    headCursor.beginEditBlock();
    QTextDocument::FindFlags flags;
    if (m_matchCaseButton->isChecked()) flags |= QTextDocument::FindCaseSensitively;
    if (m_wholeWordButton->isChecked()) flags |= QTextDocument::FindWholeWords;
    while (m_editor->find(findText, flags))
    {
        QTextCursor hitCursor = m_editor->textCursor();
        hitCursor.insertText(replaceText);
        ++hitCount;
    }
    headCursor.endEditBlock();

    m_editor->setTextCursor(backupCursor);
    return hitCount;
}

void CodeEditorWidget::jumpToInputLine()
{
    bool parseOk = false;
    const int lineNumber = m_gotoLineEdit->text().trimmed().toInt(&parseOk, 10);
    if (!parseOk)
    {
        m_statusLabel->setText(QStringLiteral("跳转失败：行号格式无效。"));
        return;
    }

    if (!m_editor->gotoLine(lineNumber))
    {
        m_statusLabel->setText(QStringLiteral("跳转失败：行号越界。"));
        return;
    }

    m_gotoPanel->setVisible(false);
    m_statusLabel->setText(QStringLiteral("已跳转到第 %1 行。").arg(lineNumber));
}

void CodeEditorWidget::openTextFile()
{
    if (m_readOnlyMode)
    {
        return;
    }

    const QPointer<CodeEditorWidget> self(this);
    const QString filePath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("打开文本"),
        QString(),
        QStringLiteral("Text Files (*.txt *.log *.ini *.json *.xml *.cpp *.h *.py);;All Files (*.*)"));

    if (!self || m_readOnlyMode || filePath.trimmed().isEmpty())
    {
        return;
    }

    openLocalFile(filePath);
}

bool CodeEditorWidget::loadLocalFile(
    const QString& filePath,
    const bool forceEncoding,
    const QStringConverter::Encoding forcedEncoding)
{
    const QString normalizedPath = filePath.trimmed();
    if (normalizedPath.isEmpty())
    {
        m_statusLabel->setText(QStringLiteral("打开失败：文件路径为空。"));
        return false;
    }

    QFile inputFile(normalizedPath);
    if (!inputFile.open(QIODevice::ReadOnly))
    {
        m_statusLabel->setText(QStringLiteral("打开失败：无法读取文件。"));
        return false;
    }

    const QByteArray fileBytes = inputFile.readAll();
    if (inputFile.error() != QFileDevice::NoError)
    {
        m_statusLabel->setText(QStringLiteral("打开失败：无法读取文件。"));
        return false;
    }
    inputFile.close();

    const FileDecodeResult decodeResult = forceEncoding
        ? decodeTextFileBytesForced(fileBytes, forcedEncoding)
        : decodeTextFileBytesAuto(fileBytes);

    if (!decodeResult.success)
    {
        m_statusLabel->setText(QStringLiteral("打开失败：解码失败。"));
        return false;
    }

    const QString displayText = decodeResult.text;
    m_localizedSourceText.clear();
    m_localizedRawSuffix.clear();
    m_localizedTextActive = false;
    m_reportTextActive = false;
    const QPointer<CodeEditorWidget> self(this);
    m_editor->setPlainText(displayText);
    if (!self) return false;

    m_currentFilePath = normalizedPath;
    m_fileEncoding = decodeResult.encoding;
    m_fileHasBom = decodeResult.hasBom;
    m_fileLineEnding = decodeResult.lineEndingText;
    m_fileSessionAvailable = true;

    const QString autoFormatHint;
    m_editor->document()->setModified(false);
    updateStatusText();
    m_statusLabel->setText(QStringLiteral("打开成功：%1（%2%3）")
        .arg(normalizedPath)
        .arg(currentEncodingDisplayText())
        .arg(autoFormatHint));
    return true;
}

void CodeEditorWidget::saveTextFile(const bool forceSaveAs)
{
    if (m_readOnlyMode)
    {
        return;
    }

    QString targetPath = m_currentFilePath;
    if (forceSaveAs || targetPath.trimmed().isEmpty())
    {
        const QPointer<CodeEditorWidget> self(this);
        targetPath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("保存文本"),
            targetPath.trimmed().isEmpty() ? QStringLiteral("immediate.txt") : targetPath,
            QStringLiteral("Text Files (*.txt *.log *.ini *.json *.xml *.cpp *.h *.py);;All Files (*.*)"));
        if (!self || m_readOnlyMode) return;
    }

    if (targetPath.trimmed().isEmpty())
    {
        return;
    }

    QSaveFile outputFile(targetPath);
    if (!outputFile.open(QIODevice::WriteOnly))
    {
        m_statusLabel->setText(QStringLiteral("保存失败：无法写入文件。"));
        return;
    }

    const QStringConverter::Encoding targetEncoding = m_fileSessionAvailable
        ? m_fileEncoding
        : QStringConverter::Utf8;
    const bool targetHasBom = m_fileSessionAvailable ? m_fileHasBom : false;
    const QString targetLineEnding = m_fileLineEnding.isEmpty()
        ? detectDominantLineEnding(m_editor->toPlainText())
        : m_fileLineEnding;
    const QString normalizedText = normalizeLineEndingForSaving(m_editor->toPlainText(), targetLineEnding);

    QTextStream outputStream(&outputFile);
    outputStream.setEncoding(targetEncoding);
    outputStream.setGenerateByteOrderMark(targetHasBom);
    outputStream << normalizedText;
    outputStream.flush();
    if (outputStream.status() != QTextStream::Ok || !outputFile.commit())
    {
        m_statusLabel->setText(QStringLiteral("保存失败：无法写入文件。"));
        return;
    }
    m_editor->document()->setModified(false);

    m_currentFilePath = targetPath;
    m_fileEncoding = targetEncoding;
    m_fileHasBom = targetHasBom;
    m_fileLineEnding = targetLineEnding;
    m_fileSessionAvailable = true;
    updateStatusText();
    m_statusLabel->setText(QStringLiteral("保存成功：%1（%2）").arg(targetPath, currentEncodingDisplayText()));
}

void CodeEditorWidget::resetFileSessionMetadata()
{
    m_fileEncoding = QStringConverter::Utf8;
    m_fileHasBom = false;
    m_fileLineEnding = QStringLiteral("\n");
    m_fileSessionAvailable = false;
}

QString CodeEditorWidget::applyStructuredAutoFormatIfNeeded(const QString& inputText, QString* detectedKindOut) const
{
    return autoFormatStructuredText(inputText, detectedKindOut);
}
