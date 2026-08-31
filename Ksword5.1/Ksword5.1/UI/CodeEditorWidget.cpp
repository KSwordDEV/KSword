#include "CodeEditorWidget.h"

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
#include <QComboBox>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFontDatabase>
#include <QFrame>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLabel>
#include <QLineEdit>
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
            "  background:%2;"
            "  color:%4;"
            "}"
            "QToolButton:pressed{"
            "  background:%3;"
            "  color:%4;"
            "}")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue, -14, -40))
            .arg(KswordTheme::OnAccentDynamicHex());
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
    // - 统一用主题蓝着色，避免深色模式下图标发黑看不清。
    QIcon buildToolbarSvgIcon(const QString& resourcePath, const QSize& iconSize = QSize(22, 22))
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
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(iconPixmap.rect(), KswordTheme::PrimaryBlueColor);
        painter.end();

        return QIcon(iconPixmap);
    }

    // isOpenBracket：
    // - 判断字符是否是左括号。
    bool isOpenBracket(const QChar ch)
    {
        return ch == QChar('(') || ch == QChar('[') || ch == QChar('{');
    }

    // isCloseBracket：
    // - 判断字符是否是右括号。
    bool isCloseBracket(const QChar ch)
    {
        return ch == QChar(')') || ch == QChar(']') || ch == QChar('}');
    }

    // pairBracket：
    // - 返回匹配括号字符。
    QChar pairBracket(const QChar ch)
    {
        if (ch == QChar('('))
        {
            return QChar(')');
        }
        if (ch == QChar('['))
        {
            return QChar(']');
        }
        if (ch == QChar('{'))
        {
            return QChar('}');
        }
        if (ch == QChar(')'))
        {
            return QChar('(');
        }
        if (ch == QChar(']'))
        {
            return QChar('[');
        }
        if (ch == QChar('}'))
        {
            return QChar('{');
        }
        return QChar();
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
        FileDecodeResult result;
        result.success = true;

        if (fileBytes.startsWith("\xEF\xBB\xBF"))
        {
            result.encoding = QStringConverter::Utf8;
            result.hasBom = true;
            result.text = QString::fromUtf8(fileBytes.constData() + 3, fileBytes.size() - 3);
        }
        else if (fileBytes.size() >= 2
            && static_cast<unsigned char>(fileBytes.at(0)) == 0xFF
            && static_cast<unsigned char>(fileBytes.at(1)) == 0xFE)
        {
            result.encoding = QStringConverter::Utf16LE;
            result.hasBom = true;
            result.text = readAllTextWithEncoding(fileBytes.mid(2), QStringConverter::Utf16LE);
        }
        else if (fileBytes.size() >= 2
            && static_cast<unsigned char>(fileBytes.at(0)) == 0xFE
            && static_cast<unsigned char>(fileBytes.at(1)) == 0xFF)
        {
            result.encoding = QStringConverter::Utf16BE;
            result.hasBom = true;
            result.text = readAllTextWithEncoding(fileBytes.mid(2), QStringConverter::Utf16BE);
        }
        else
        {
            const QString utf8Text = QString::fromUtf8(fileBytes);
            if (!fileBytes.isEmpty() && utf8Text.contains(QChar::ReplacementCharacter))
            {
                result.encoding = QStringConverter::System;
                result.hasBom = false;
                result.text = QString::fromLocal8Bit(fileBytes);
            }
            else
            {
                result.encoding = QStringConverter::Utf8;
                result.hasBom = false;
                result.text = utf8Text;
            }
        }

        result.lineEndingText = detectDominantLineEnding(result.text);
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

class BracketHighlighter final : public QSyntaxHighlighter
{
public:
    // 构造函数：绑定目标文本文档。
    explicit BracketHighlighter(QTextDocument* document)
        : QSyntaxHighlighter(document)
    {
    }

protected:
    // highlightBlock：按括号类型设置颜色。
    void highlightBlock(const QString& text) override
    {
        QTextCharFormat roundFormat;
        roundFormat.setForeground(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue, 22, -4));

        QTextCharFormat squareFormat;
        squareFormat.setForeground(KswordTheme::AccentColor(KswordTheme::AccentRole::Green, 42, 16));

        QTextCharFormat braceFormat;
        braceFormat.setForeground(KswordTheme::AccentColor(KswordTheme::AccentRole::Orange, 38, 12));

        for (int index = 0; index < text.size(); ++index)
        {
            const QChar ch = text.at(index);
            if (ch == QChar('(') || ch == QChar(')'))
            {
                setFormat(index, 1, roundFormat);
                continue;
            }
            if (ch == QChar('[') || ch == QChar(']'))
            {
                setFormat(index, 1, squareFormat);
                continue;
            }
            if (ch == QChar('{') || ch == QChar('}'))
            {
                setFormat(index, 1, braceFormat);
            }
        }
    }
};

class CodeTextEdit;

class LineNumberArea final : public QWidget
{
public:
    // 构造函数：保存主编辑器指针。
    explicit LineNumberArea(CodeTextEdit* owner);

    // sizeHint：返回行号区域宽度。
    QSize sizeHint() const override;

protected:
    // paintEvent：转发给主编辑器统一绘制。
    void paintEvent(QPaintEvent* event) override;

private:
    // m_owner：主代码编辑器。
    CodeTextEdit* m_owner = nullptr;
};

class CodeTextEdit final : public QPlainTextEdit
{
public:
    // 构造函数：初始化行号、字体和括号匹配高亮。
    explicit CodeTextEdit(QWidget* parent = nullptr)
        : QPlainTextEdit(parent)
    {
        QFont fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        // 系统等宽字体缺少中文字形时 Windows 会回退到宋体，显式指定雅黑承接中文。
        fixedFont.setFamilies(QStringList{ fixedFont.family(), QStringLiteral("Microsoft YaHei UI") });
        fixedFont.setPointSize(std::max(12, fixedFont.pointSize()));
        setFont(fixedFont);
        setTabStopDistance(QFontMetricsF(fixedFont).horizontalAdvance(QChar(' ')) * 4.0);
        setLineWrapMode(QPlainTextEdit::WidgetWidth);
        setFrameShape(QFrame::NoFrame);

        m_lineNumberArea = new LineNumberArea(this);
        m_bracketHighlighter = new BracketHighlighter(document());

        connect(this, &QPlainTextEdit::blockCountChanged, this, [this](int)
            {
                setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
            });

        connect(this, &QPlainTextEdit::updateRequest, this, [this](const QRect& rect, int deltaY)
            {
                if (deltaY != 0)
                {
                    m_lineNumberArea->scroll(0, deltaY);
                }
                else
                {
                    m_lineNumberArea->update(0, rect.y(), m_lineNumberArea->width(), rect.height());
                }
                if (rect.contains(viewport()->rect()))
                {
                    setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
                }
            });

        connect(this, &QPlainTextEdit::cursorPositionChanged, this, [this]()
            {
                refreshExtraSelections();
            });

        connect(this, &QPlainTextEdit::textChanged, this, [this]()
            {
                refreshExtraSelections();
            });

        setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
        refreshExtraSelections();
    }

    // 析构函数：释放括号高亮对象。
    ~CodeTextEdit() override
    {
        delete m_bracketHighlighter;
        m_bracketHighlighter = nullptr;
    }

    // lineNumberAreaWidth：按文档行数计算行号宽度。
    int lineNumberAreaWidth() const
    {
        int digits = 1;
        int maxLines = std::max(1, blockCount());
        while (maxLines >= 10)
        {
            maxLines /= 10;
            ++digits;
        }
        return 8 + fontMetrics().horizontalAdvance(QChar('9')) * digits;
    }

    // paintLineNumberArea：绘制可视区域行号。
    void paintLineNumberArea(QPaintEvent* event)
    {
        QPainter painter(m_lineNumberArea);
        painter.fillRect(event->rect(), KswordTheme::SurfaceMutedColor());

        QTextBlock block = firstVisibleBlock();
        int blockNumber = block.blockNumber();
        int top = static_cast<int>(blockBoundingGeometry(block).translated(contentOffset()).top());
        int bottom = top + static_cast<int>(blockBoundingRect(block).height());

        while (block.isValid() && top <= event->rect().bottom())
        {
            if (block.isVisible() && bottom >= event->rect().top())
            {
                painter.setPen(KswordTheme::TextSecondaryColor());
                painter.drawText(
                    0,
                    top,
                    m_lineNumberArea->width() - 4,
                    fontMetrics().height(),
                    Qt::AlignRight,
                    QString::number(blockNumber + 1));
            }

            block = block.next();
            top = bottom;
            bottom = top + static_cast<int>(blockBoundingRect(block).height());
            ++blockNumber;
        }
    }

    // gotoLine：跳转到指定 1 基行号。
    bool gotoLine(int oneBasedLine)
    {
        if (oneBasedLine <= 0)
        {
            return false;
        }

        const QTextBlock block = document()->findBlockByLineNumber(oneBasedLine - 1);
        if (!block.isValid())
        {
            return false;
        }

        QTextCursor cursor(document());
        cursor.setPosition(block.position());
        setTextCursor(cursor);
        centerCursor();
        return true;
    }

protected:
    // resizeEvent：窗口变化时同步行号区域几何。
    void resizeEvent(QResizeEvent* event) override
    {
        QPlainTextEdit::resizeEvent(event);
        const QRect rect = contentsRect();
        m_lineNumberArea->setGeometry(rect.left(), rect.top(), lineNumberAreaWidth(), rect.height());
    }

private:
    // refreshExtraSelections：当前行和括号匹配高亮。
    void refreshExtraSelections()
    {
        QList<QTextEdit::ExtraSelection> extraSelections;

        QTextEdit::ExtraSelection lineSelection;
        lineSelection.cursor = textCursor();
        lineSelection.cursor.clearSelection();
        lineSelection.format.setProperty(QTextFormat::FullWidthSelection, true);
        lineSelection.format.setBackground(KswordTheme::PrimaryBlueSubtleColor());
        extraSelections.push_back(lineSelection);

        const QString allText = toPlainText();
        if (!allText.isEmpty())
        {
            int bracketPos = -1;
            QChar bracketCh;
            const int cursorPos = textCursor().position();

            if (cursorPos > 0 && (isOpenBracket(allText.at(cursorPos - 1)) || isCloseBracket(allText.at(cursorPos - 1))))
            {
                bracketPos = cursorPos - 1;
                bracketCh = allText.at(bracketPos);
            }
            else if (cursorPos < allText.size() && (isOpenBracket(allText.at(cursorPos)) || isCloseBracket(allText.at(cursorPos))))
            {
                bracketPos = cursorPos;
                bracketCh = allText.at(bracketPos);
            }

            if (bracketPos >= 0)
            {
                int pairPos = -1;
                const QChar pairCh = pairBracket(bracketCh);
                if (isOpenBracket(bracketCh))
                {
                    int depth = 0;
                    for (int i = bracketPos; i < allText.size(); ++i)
                    {
                        if (allText.at(i) == bracketCh) ++depth;
                        if (allText.at(i) == pairCh) --depth;
                        if (depth == 0)
                        {
                            pairPos = i;
                            break;
                        }
                    }
                }
                else
                {
                    int depth = 0;
                    for (int i = bracketPos; i >= 0; --i)
                    {
                        if (allText.at(i) == bracketCh) ++depth;
                        if (allText.at(i) == pairCh) --depth;
                        if (depth == 0)
                        {
                            pairPos = i;
                            break;
                        }
                    }
                }

                auto appendBracketSelection = [this, &extraSelections](int pos, const QColor& bg)
                    {
                        QTextEdit::ExtraSelection sel;
                        sel.cursor = textCursor();
                        sel.cursor.setPosition(pos);
                        sel.cursor.movePosition(QTextCursor::NextCharacter, QTextCursor::KeepAnchor);
                        sel.format.setForeground(KswordTheme::OnAccentColor());
                        sel.format.setBackground(bg);
                        extraSelections.push_back(sel);
                    };

                const QColor matchedBg = KswordTheme::EditorSelectionColor();
                appendBracketSelection(bracketPos, pairPos >= 0 ? matchedBg : KswordTheme::ErrorColor());
                if (pairPos >= 0)
                {
                    appendBracketSelection(pairPos, matchedBg);
                }
            }
        }

        setExtraSelections(extraSelections);
    }

private:
    // m_lineNumberArea：行号区域。
    QWidget* m_lineNumberArea = nullptr;

    // m_bracketHighlighter：括号着色器。
    BracketHighlighter* m_bracketHighlighter = nullptr;

    friend class LineNumberArea;
};

QSize LineNumberArea::sizeHint() const
{
    if (m_owner == nullptr)
    {
        return QSize(0, 0);
    }
    return QSize(m_owner->lineNumberAreaWidth(), 0);
}

LineNumberArea::LineNumberArea(CodeTextEdit* owner)
    : QWidget(owner)
    , m_owner(owner)
{
}

void LineNumberArea::paintEvent(QPaintEvent* event)
{
    if (m_owner != nullptr)
    {
        m_owner->paintLineNumberArea(event);
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
    if (m_editor == nullptr)
    {
        return;
    }

    m_editor->setPlainText(applyStructuredAutoFormatIfNeeded(plainText));
    resetFileSessionMetadata();
    updateStatusText();
}

void CodeEditorWidget::setLocalizedText(const QString& sourceText)
{
    m_localizedSourceText = sourceText;
    m_localizedRawSuffix.clear();
    m_localizedTextActive = true;
    if (m_editor == nullptr)
    {
        return;
    }

    m_editor->setPlainText(applyStructuredAutoFormatIfNeeded(
        localizeGeneratedReport(m_localizedSourceText) + m_localizedRawSuffix));
    resetFileSessionMetadata();
    updateStatusText();
}

void CodeEditorWidget::setLocalizedTextWithRawSuffix(
    const QString& sourceText,
    const QString& rawSuffix)
{
    m_localizedSourceText = sourceText;
    m_localizedRawSuffix = rawSuffix;
    m_localizedTextActive = true;
    if (m_editor == nullptr)
    {
        return;
    }

    m_editor->setPlainText(applyStructuredAutoFormatIfNeeded(
        localizeGeneratedReport(m_localizedSourceText) + m_localizedRawSuffix));
    resetFileSessionMetadata();
    updateStatusText();
}

void CodeEditorWidget::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr || event->type() != QEvent::LanguageChange ||
        !m_localizedTextActive || m_editor == nullptr)
    {
        return;
    }

    const int verticalScrollValue = m_editor->verticalScrollBar()->value();
    const int horizontalScrollValue = m_editor->horizontalScrollBar()->value();
    m_editor->setPlainText(applyStructuredAutoFormatIfNeeded(
        localizeGeneratedReport(m_localizedSourceText) + m_localizedRawSuffix));
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
    refreshReadOnlyUiState();
    updateStatusText();
}

bool CodeEditorWidget::isReadOnly() const
{
    return m_readOnlyMode;
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
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(0, 0, 0, 0);
    m_rootLayout->setSpacing(6);

    m_toolbarWidget = new QWidget(this);
    m_toolbarLayout = new QHBoxLayout(m_toolbarWidget);
    m_toolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolbarLayout->setSpacing(4);

    // buildButton：
    // - 统一构建工具按钮；
    // - 所有按钮图标固定来自 qrc 的 SVG 图标库。
    auto buildButton = [this](const QString& iconPath, const QString& tip) -> QToolButton*
        {
            QToolButton* button = new QToolButton(m_toolbarWidget);
            button->setIcon(buildToolbarSvgIcon(iconPath));
            button->setIconSize(QSize(22, 22));
            button->setToolTip(tip);
            button->setAutoRaise(true);
            button->setFixedSize(24, 24);
            return button;
        };

    // 工具栏图标语义映射：
    // - 与功能一一对应，避免使用 MainLogo 造成误导。
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

    m_toolbarLayout->addWidget(m_newButton);
    m_toolbarLayout->addWidget(m_openButton);
    m_toolbarLayout->addWidget(m_saveButton);
    m_toolbarLayout->addWidget(m_saveAsButton);
    m_toolbarLayout->addSpacing(4);
    m_toolbarLayout->addWidget(m_undoButton);
    m_toolbarLayout->addWidget(m_redoButton);
    m_toolbarLayout->addWidget(m_cutButton);
    m_toolbarLayout->addWidget(m_copyButton);
    m_toolbarLayout->addWidget(m_pasteButton);
    m_toolbarLayout->addSpacing(4);
    m_toolbarLayout->addWidget(m_findButton);
    m_toolbarLayout->addWidget(m_replaceButton);
    m_toolbarLayout->addWidget(m_gotoButton);
    m_toolbarLayout->addWidget(m_wrapButton);
    m_toolbarLayout->addStretch(1);
    m_rootLayout->addWidget(m_toolbarWidget);

    m_findPanel = new QWidget(this);
    m_findLayout = new QHBoxLayout(m_findPanel);
    m_findLayout->setContentsMargins(0, 0, 0, 0);
    m_findLayout->setSpacing(4);

    m_findEdit = new QLineEdit(m_findPanel);
    m_findEdit->setPlaceholderText(QStringLiteral("查找"));
    m_replaceEdit = new QLineEdit(m_findPanel);
    m_replaceEdit->setPlaceholderText(QStringLiteral("替换为"));

    m_findPrevButton = new QToolButton(m_findPanel);
    m_findPrevButton->setText(QStringLiteral("↑"));
    m_findPrevButton->setToolTip(QStringLiteral("向上查找上一个匹配项"));
    m_findNextButton = new QToolButton(m_findPanel);
    m_findNextButton->setText(QStringLiteral("↓"));
    m_findNextButton->setToolTip(QStringLiteral("向下查找下一个匹配项"));
    m_replaceOneButton = new QToolButton(m_findPanel);
    m_replaceOneButton->setText(QStringLiteral("替换"));
    m_replaceOneButton->setToolTip(QStringLiteral("替换当前这一处匹配，并跳到下一处"));
    m_replaceAllButton = new QToolButton(m_findPanel);
    m_replaceAllButton->setText(QStringLiteral("全部"));
    m_replaceAllButton->setToolTip(QStringLiteral("一次性替换文中所有匹配项"));
    m_findCloseButton = new QToolButton(m_findPanel);
    m_findCloseButton->setText(QStringLiteral("关闭"));
    m_findCloseButton->setToolTip(QStringLiteral("关闭查找替换栏"));

    m_findLayout->addWidget(m_findEdit, 1);
    m_findLayout->addWidget(m_replaceEdit, 1);
    m_findLayout->addWidget(m_findPrevButton);
    m_findLayout->addWidget(m_findNextButton);
    m_findLayout->addWidget(m_replaceOneButton);
    m_findLayout->addWidget(m_replaceAllButton);
    m_findLayout->addWidget(m_findCloseButton);
    m_findPanel->setVisible(false);
    m_rootLayout->addWidget(m_findPanel);

    m_gotoPanel = new QWidget(this);
    m_gotoLayout = new QHBoxLayout(m_gotoPanel);
    m_gotoLayout->setContentsMargins(0, 0, 0, 0);
    m_gotoLayout->setSpacing(4);
    m_gotoLineEdit = new QLineEdit(m_gotoPanel);
    m_gotoLineEdit->setPlaceholderText(QStringLiteral("行号(从1开始)"));
    m_gotoApplyButton = new QToolButton(m_gotoPanel);
    m_gotoApplyButton->setText(QStringLiteral("执行"));
    m_gotoApplyButton->setToolTip(QStringLiteral("跳转到左侧输入的行号"));
    m_gotoCloseButton = new QToolButton(m_gotoPanel);
    m_gotoCloseButton->setText(QStringLiteral("关闭"));
    m_gotoCloseButton->setToolTip(QStringLiteral("关闭跳转行栏"));
    m_gotoLayout->addWidget(new QLabel(QStringLiteral("跳转行:"), m_gotoPanel));
    m_gotoLayout->addWidget(m_gotoLineEdit, 1);
    m_gotoLayout->addWidget(m_gotoApplyButton);
    m_gotoLayout->addWidget(m_gotoCloseButton);
    m_gotoPanel->setVisible(false);
    m_rootLayout->addWidget(m_gotoPanel);

    m_editor = new CodeTextEdit(this);
    m_editor->setPlaceholderText(QStringLiteral("即时窗口：支持行号、括号匹配、查找替换、跳转行。"));

    // 纯文本与结构视图叠在同一位置：切换只换页，不改变外层布局和分隔器比例。
    m_viewStack = new QStackedWidget(this);
    m_structuredView = new ks::ui::ReportStructuredView(m_viewStack);
    m_viewStack->addWidget(m_editor);
    m_viewStack->addWidget(m_structuredView);
    m_viewStack->setCurrentWidget(m_editor);
    m_rootLayout->addWidget(m_viewStack, 1);

    // 切换控件浮在内容区右上角，而不是混在顶部那排编辑动作里：
    // 它切的是“这块内容怎么看”，和新建/保存/剪贴板不是一类操作，放在内容自己的角上更好找。
    // 用下拉框而不是按钮：两个选项都摆在明面上，当前在哪一边、还能切到哪一边一眼看全，
    // 也和文件常规页那套切换框保持同一种形态。控件不进布局，由 positionStructuredSwitch 贴角。
    m_structuredCombo = new QComboBox(m_viewStack);
    m_structuredCombo->addItem(QStringLiteral("结构视图"));
    m_structuredCombo->addItem(QStringLiteral("原始文本"));
    m_structuredCombo->setCursor(Qt::PointingHandCursor);
    m_structuredCombo->setToolTip(
        QStringLiteral("在结构视图与原始文本之间切换：结构视图按字段和表格解析当前报告，原始文本保留完整报告便于全文检索和整段复制"));
    // 悬浮控件压在正文之上，必须自带不透明底色和边框，否则叠在属性表行上会看不清。
    m_structuredCombo->setStyleSheet(buildFloatingSwitchStyle());
    // 入口默认隐藏：只有内容确实是可解析的只读报告时才由 updateStructuredReportView 放出来。
    m_structuredCombo->setVisible(false);
    // m_viewStack 换页或改尺寸时都要重新贴角，事件过滤器比逐页 connect 省事也更不易漏。
    m_viewStack->installEventFilter(this);

    m_statusLabel = new QLabel(QStringLiteral("就绪。"), this);
    m_rootLayout->addWidget(m_statusLabel);
}

void CodeEditorWidget::initializeConnections()
{
    connect(m_newButton, &QToolButton::clicked, this, [this]()
        {
            if (m_readOnlyMode)
            {
                return;
            }
            m_editor->clear();
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
    connect(m_copyButton, &QToolButton::clicked, m_editor, &QPlainTextEdit::copy);
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
            const bool enableWrap = (m_editor->lineWrapMode() == QPlainTextEdit::NoWrap);
            m_editor->setLineWrapMode(enableWrap ? QPlainTextEdit::WidgetWidth : QPlainTextEdit::NoWrap);
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
            emit contentChanged(text());
        });

    connect(m_structuredCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
        [this](const int selectedIndex)
        {
            if (m_destroying || m_viewStack == nullptr || m_structuredView == nullptr)
            {
                return;
            }
            // 索引与文件常规页那套切换框保持一致：0 = 结构视图，1 = 原始文本。
            const bool structuredSelected = selectedIndex == 0;
            // 选择记在进程内：这是“这次排查我想怎么看”，不是需要长期保存的偏好。
            g_preferStructuredReportView = structuredSelected;
            m_viewStack->setCurrentWidget(structuredSelected
                ? static_cast<QWidget*>(m_structuredView)
                : static_cast<QWidget*>(m_editor));
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
}

void CodeEditorWidget::applyThemeStyle()
{
    const QString toolStyle = buildToolButtonStyle();
    const QString inputStyle = buildInputStyle();

    const QList<QToolButton*> buttonList{
        m_newButton,m_openButton,m_saveButton,m_saveAsButton,m_undoButton,m_redoButton,m_cutButton,m_copyButton,m_pasteButton,
        m_findButton,m_replaceButton,m_gotoButton,m_wrapButton,m_findPrevButton,m_findNextButton,m_replaceOneButton,m_replaceAllButton,
        m_findCloseButton,m_gotoApplyButton,m_gotoCloseButton
    };
    for (QToolButton* button : buttonList)
    {
        if (button != nullptr)
        {
            button->setStyleSheet(toolStyle);
        }
    }

    // 悬浮切换框不在上面那批里：它压在正文之上，用的是自带底色和边框的另一套样式。
    if (m_structuredCombo != nullptr)
    {
        m_structuredCombo->setStyleSheet(buildFloatingSwitchStyle());
    }

    m_findEdit->setStyleSheet(inputStyle);
    m_replaceEdit->setStyleSheet(inputStyle);
    m_gotoLineEdit->setStyleSheet(inputStyle);
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
    if (m_undoButton != nullptr) m_undoButton->setEnabled(!m_readOnlyMode);
    if (m_redoButton != nullptr) m_redoButton->setEnabled(!m_readOnlyMode);
    if (m_cutButton != nullptr) m_cutButton->setEnabled(!m_readOnlyMode);
    if (m_pasteButton != nullptr) m_pasteButton->setEnabled(!m_readOnlyMode);
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
}

bool CodeEditorWidget::eventFilter(QObject* watchedObject, QEvent* eventObject)
{
    if (!m_destroying &&
        watchedObject == m_viewStack &&
        eventObject != nullptr &&
        (eventObject->type() == QEvent::Resize || eventObject->type() == QEvent::Show))
    {
        positionStructuredSwitch();
    }
    return QWidget::eventFilter(watchedObject, eventObject);
}

void CodeEditorWidget::positionStructuredSwitch()
{
    if (m_destroying || m_structuredCombo == nullptr || m_viewStack == nullptr)
    {
        return;
    }

    // 右边距要避开当前页可见的垂直滚动条：压在滚动条上会让拖动条变成误点区。
    int rightMargin = 12;
    const QWidget* currentPage = m_viewStack->currentWidget();
    if (currentPage == m_editor && m_editor != nullptr &&
        m_editor->verticalScrollBar() != nullptr &&
        m_editor->verticalScrollBar()->isVisible())
    {
        rightMargin += m_editor->verticalScrollBar()->width();
    }
    else if (currentPage == m_structuredView && m_structuredView != nullptr)
    {
        rightMargin += m_structuredView->verticalScrollBarWidth();
    }

    const QSize switchSize = m_structuredCombo->sizeHint();
    m_structuredCombo->setGeometry(
        m_viewStack->width() - switchSize.width() - rightMargin,
        10,
        switchSize.width(),
        switchSize.height());
    m_structuredCombo->raise();
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
    const QString currentText = m_editor->toPlainText();
    const bool eligible =
        m_structuredViewEnabled && m_readOnlyMode && !currentText.trimmed().isEmpty();
    const bool structured = eligible && m_structuredView->setReportText(currentText);

    m_structuredCombo->setVisible(structured);
    if (!structured)
    {
        m_viewStack->setCurrentWidget(m_editor);
        return;
    }

    // 这里是程序按记忆恢复视图，不是用户选择；阻断信号避免把状态又写回全局偏好。
    const QSignalBlocker switchSignalBlocker(m_structuredCombo);
    m_structuredCombo->setCurrentIndex(g_preferStructuredReportView ? 0 : 1);
    m_viewStack->setCurrentWidget(g_preferStructuredReportView
        ? static_cast<QWidget*>(m_structuredView)
        : static_cast<QWidget*>(m_editor));
    positionStructuredSwitch();
}

void CodeEditorWidget::openFindReplacePanel(const bool replaceEnabled)
{
    const bool effectiveReplaceEnabled = replaceEnabled && !m_readOnlyMode;
    m_replaceEnabled = effectiveReplaceEnabled;
    m_findPanel->setVisible(true);
    m_gotoPanel->setVisible(false);
    m_replaceEdit->setVisible(effectiveReplaceEnabled);
    m_replaceOneButton->setVisible(effectiveReplaceEnabled);
    m_replaceAllButton->setVisible(effectiveReplaceEnabled);
    m_findEdit->setFocus(Qt::ShortcutFocusReason);
    m_findEdit->selectAll();
}

void CodeEditorWidget::openGotoPanel()
{
    m_findPanel->setVisible(false);
    m_gotoPanel->setVisible(true);
    m_gotoLineEdit->setFocus(Qt::ShortcutFocusReason);
    m_gotoLineEdit->selectAll();
}

void CodeEditorWidget::closeInlinePanels()
{
    m_findPanel->setVisible(false);
    m_gotoPanel->setVisible(false);
}

void CodeEditorWidget::updateStatusText()
{
    // 退出保护：
    // - MainWindow 析构期间 QPlainTextEdit 可能仍发出 cursor/textChanged；
    // - 此时 m_editor 或 m_statusLabel 已经进入 Qt 子对象析构链，继续取 cursor/setText 会触发断点异常；
    // - 销毁期或关键子控件为空时直接跳过，正常运行期行为不变。
    if (m_destroying || m_editor == nullptr || m_statusLabel == nullptr)
    {
        return;
    }

    const QTextCursor cursor = m_editor->textCursor();
    const QString fileName = m_currentFilePath.trimmed().isEmpty() ? QStringLiteral("<未命名>") : m_currentFilePath;
    m_statusLabel->setText(QStringLiteral("行:%1 列:%2 字符:%3 文件:%4 模式:%5 编码:%6")
        .arg(cursor.blockNumber() + 1)
        .arg(cursor.positionInBlock() + 1)
        .arg(m_editor->toPlainText().size())
        .arg(fileName)
        .arg(m_readOnlyMode ? QStringLiteral("只读") : QStringLiteral("可编辑"))
        .arg(currentEncodingDisplayText()));
}

bool CodeEditorWidget::findByDirection(const bool forward)
{
    const QString keyText = m_findEdit->text();
    if (keyText.isEmpty())
    {
        m_statusLabel->setText(QStringLiteral("查找失败：请输入查找内容。"));
        return false;
    }

    QTextDocument::FindFlags flags;
    if (!forward) flags |= QTextDocument::FindBackward;

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
    if (!cursor.hasSelection() || cursor.selectedText() != findText)
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
    while (m_editor->find(findText))
    {
        QTextCursor hitCursor = m_editor->textCursor();
        hitCursor.insertText(replaceText);
        ++hitCount;
    }

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

    const QString filePath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("打开文本"),
        QString(),
        QStringLiteral("Text Files (*.txt *.log *.ini *.json *.xml *.cpp *.h *.py);;All Files (*.*)"));

    if (filePath.trimmed().isEmpty())
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
    inputFile.close();

    const FileDecodeResult decodeResult = forceEncoding
        ? decodeTextFileBytesForced(fileBytes, forcedEncoding)
        : decodeTextFileBytesAuto(fileBytes);

    if (!decodeResult.success)
    {
        m_statusLabel->setText(QStringLiteral("打开失败：解码失败。"));
        return false;
    }

    QString detectedKind;
    const QString displayText = applyStructuredAutoFormatIfNeeded(decodeResult.text, &detectedKind);
    m_editor->setPlainText(displayText);

    m_currentFilePath = normalizedPath;
    m_fileEncoding = decodeResult.encoding;
    m_fileHasBom = decodeResult.hasBom;
    m_fileLineEnding = decodeResult.lineEndingText;
    m_fileSessionAvailable = true;

    const QString autoFormatHint = detectedKind.isEmpty()
        ? QString()
        : QStringLiteral("，已自动格式化%1").arg(detectedKind);
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
        targetPath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("保存文本"),
            targetPath.trimmed().isEmpty() ? QStringLiteral("immediate.txt") : targetPath,
            QStringLiteral("Text Files (*.txt *.log *.ini *.json *.xml *.cpp *.h *.py);;All Files (*.*)"));
    }

    if (targetPath.trimmed().isEmpty())
    {
        return;
    }

    QFile outputFile(targetPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
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
    outputFile.close();

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
