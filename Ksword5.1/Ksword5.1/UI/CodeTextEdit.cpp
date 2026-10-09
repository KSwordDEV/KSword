#include "CodeTextEdit.h"
#include "../theme.h"

#include <QEvent>
#include <QApplication>
#include <QFontDatabase>
#include <QFontInfo>
#include <QFrame>
#include <QKeyEvent>
#include <QPaintEvent>
#include <QPainter>
#include <QPointer>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSyntaxHighlighter>
#include <QTextBlock>
#include <QTextDocument>
#include <QTextOption>
#include <QTimer>
#include <algorithm>
#include <array>

namespace
{
    using Language = CodeTextEdit::SyntaxLanguage;
    constexpr int kIndentWidth = 4;
    constexpr int kDetectionCharacters = 16 * 1024;
    constexpr int kHighlightCharactersPerBlock = 64 * 1024;
    constexpr int kBracketScanCharacters = 128 * 1024;

    // 点/像素单位一致时保留准确倍率，宿主混用单位时按同一屏幕的实际像素换算。
    double fontSizeScale(const QFont& current, const QFont& application)
    {
        if (current.pointSizeF() > 0 && application.pointSizeF() > 0)
            return current.pointSizeF() / application.pointSizeF();
        if (current.pixelSize() > 0 && application.pixelSize() > 0)
            return static_cast<double>(current.pixelSize()) / application.pixelSize();
        const int basePixels = QFontInfo(application).pixelSize();
        return basePixels > 0 ? static_cast<double>(QFontInfo(current).pixelSize()) / basePixels : 1.0;
    }

    bool isOpenBracket(QChar ch)
    {
        return ch == QLatin1Char('(') || ch == QLatin1Char('[') || ch == QLatin1Char('{');
    }
    bool isCloseBracket(QChar ch)
    {
        return ch == QLatin1Char(')') || ch == QLatin1Char(']') || ch == QLatin1Char('}');
    }
    QChar pairBracket(QChar ch)
    {
        switch (ch.unicode())
        {
        case '(': return QLatin1Char(')');
        case '[': return QLatin1Char(']');
        case '{': return QLatin1Char('}');
        case ')': return QLatin1Char('(');
        case ']': return QLatin1Char('[');
        case '}': return QLatin1Char('{');
        default: return {};
        }
    }
    QString documentSample(QTextDocument* document)
    {
        QTextCursor sample(document);
        sample.setPosition(std::min(kDetectionCharacters, std::max(0, document->characterCount() - 1)), QTextCursor::KeepAnchor);
        return sample.selectedText().replace(QChar::ParagraphSeparator, QLatin1Char('\n')).trimmed();
    }
    Language detectLanguage(QTextDocument* document)
    {
        const QString sample = documentSample(document);
        static const QRegularExpression iniSection(QStringLiteral("(?:^|\\n)\\s*\\[[^\\]\\r\\n]+\\]\\s*(?:\\n|$)"));
        static const QRegularExpression iniEntry(QStringLiteral("(?:^|\\n)\\s*[A-Za-z_][A-Za-z0-9_.-]*\\s*="));
        static const QRegularExpression cpp(QStringLiteral("(?:^|\\n)\\s*(?:#\\s*(?:include|pragma|define)|(?:class|struct|namespace|template)\\b|(?:void|int|bool|auto|constexpr)\\b[^\\n]*[({;])"));
        static const QRegularExpression shell(QStringLiteral("(?:^|\\n)\\s*(?:#!|param\\s*\\(|\\$[A-Za-z_][A-Za-z0-9_]*\\s*=|function\\s+[A-Za-z_])"), QRegularExpression::CaseInsensitiveOption);
        static const QRegularExpression xml(QStringLiteral("^<(?:\\?xml\\b|!--|[A-Za-z_:][^>]*>)"));
        if (iniSection.match(sample).hasMatch()) return Language::Ini;
        if (sample.startsWith(QLatin1Char('{')) || sample.startsWith(QLatin1Char('['))) return Language::Json;
        if (xml.match(sample).hasMatch()) return Language::Xml;
        if (cpp.match(sample).hasMatch()) return Language::Cpp;
        if (shell.match(sample).hasMatch()) return Language::Shell;
        if (iniEntry.match(sample).hasMatch()) return Language::Ini;
        return Language::PlainText;
    }

    struct BracketToken { int offset; QChar character; };
    struct CodeBlockData final : QTextBlockUserData
    {
        QVector<BracketToken> brackets;
        int coveredLength = 0;
        bool fullyScanned = true;
    };

    struct EditorColors
    {
        QColor base;
        QColor gutter;
        QColor gutterText;
        QColor currentNumber;
        QColor divider;
        QColor currentLine;
        QColor bracket;
        QColor bracketError;
        QTextCharFormat keyword;
        QTextCharFormat string;
        QTextCharFormat number;
        QTextCharFormat comment;
        QTextCharFormat tag;
        QTextCharFormat attribute;
        QTextCharFormat directive;
    };

    EditorColors colorsFor(const QPalette& palette)
    {
        EditorColors colors;
        colors.base = palette.color(QPalette::Base);
        const QColor text = palette.color(QPalette::Text);
        const QColor accent = palette.color(QPalette::Highlight);
        colors.gutter = KswordTheme::BlendColors(colors.base, palette.color(QPalette::Window), 100);
        colors.gutterText = KswordTheme::EnsureTextContrast(KswordTheme::BlendColors(text, colors.gutter, 110), colors.gutter);
        colors.currentNumber = KswordTheme::EnsureTextContrast(accent, colors.gutter);
        colors.divider = KswordTheme::BlendColors(text, colors.gutter, 218);
        colors.currentLine = KswordTheme::BlendColors(colors.base, accent, 18);
        colors.bracket = KswordTheme::BlendColors(colors.base, accent, 65);
        colors.bracketError = KswordTheme::BlendColors(colors.base, KswordTheme::ErrorColor(), 65);
        const std::array<QColor, 2> backgrounds{colors.base, colors.currentLine};
        const auto foreground = [&](const QColor& candidate) {
            return KswordTheme::EnsureTextContrastForBackgrounds(candidate, backgrounds.data(), static_cast<int>(backgrounds.size()));
        };
        colors.keyword.setForeground(foreground(KswordTheme::AccentColor(KswordTheme::AccentRole::Purple)));
        colors.string.setForeground(foreground(KswordTheme::AccentColor(KswordTheme::AccentRole::Green)));
        colors.number.setForeground(foreground(KswordTheme::AccentColor(KswordTheme::AccentRole::Orange)));
        colors.comment.setForeground(foreground(KswordTheme::BlendColors(text, colors.base, 100)));
        colors.comment.setFontItalic(true);
        colors.tag.setForeground(foreground(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue)));
        colors.attribute.setForeground(foreground(KswordTheme::AccentColor(KswordTheme::AccentRole::Cyan)));
        colors.directive.setForeground(foreground(KswordTheme::AccentColor(KswordTheme::AccentRole::Teal)));
        return colors;
    }
}

// A lexical painter, not a parser. Very long logical lines have bounded work;
// unknown tails stay ordinary text and never supply guessed bracket matches.
class CodeSyntaxHighlighter final : public QSyntaxHighlighter
{
public:
    explicit CodeSyntaxHighlighter(QTextDocument* document) : QSyntaxHighlighter(document) {}
    void setLanguage(Language language) { m_language = language; }
    void setColors(const EditorColors& colors) { m_colors = colors; }

protected:
    void highlightBlock(const QString& text) override
    {
        auto* data = new CodeBlockData;
        setCurrentBlockState(0);
        const int limit = static_cast<int>(std::min<qsizetype>(text.size(), kHighlightCharactersPerBlock));
        data->coveredLength = limit;
        data->fullyScanned = limit == text.size();
        const bool code = m_language != Language::PlainText;
        const bool cpp = m_language == Language::Cpp;
        const bool shell = m_language == Language::Shell;
        const bool xml = m_language == Language::Xml;
        int at = 0;
        bool insideTag = xml && previousBlockState() == 4;
        const auto starts = [&](int position, QLatin1String token) {
            return position + token.size() <= limit && QStringView(text).mid(position, token.size()) == token;
        };
        const auto commentEnd = [&](int begin, QLatin1String delimiter, int state) {
            const qsizetype found = QStringView(text).first(limit).indexOf(delimiter, begin);
            const int end = found < 0 ? limit : static_cast<int>(found + delimiter.size());
            setFormat(begin, end - begin, m_colors.comment);
            if (found < 0) setCurrentBlockState(state);
            return end;
        };
        if (code && previousBlockState() == 1 && cpp) at = commentEnd(0, QLatin1String("*/"), 1);
        else if (code && previousBlockState() == 2 && xml) at = commentEnd(0, QLatin1String("-->"), 2);
        else if (code && previousBlockState() == 3 && shell) at = commentEnd(0, QLatin1String("#>"), 3);
        static const QRegularExpression cppKeyword(QStringLiteral("^(?:alignas|alignof|asm|auto|bool|break|case|catch|char|class|concept|const|constexpr|consteval|constinit|continue|co_await|co_return|co_yield|decltype|default|delete|do|double|else|enum|explicit|extern|false|float|for|friend|if|inline|int|long|mutable|namespace|new|noexcept|nullptr|operator|private|protected|public|register|requires|return|short|signed|sizeof|static|static_assert|struct|switch|template|this|thread_local|throw|true|try|typedef|typename|union|unsigned|using|virtual|void|volatile|wchar_t|while)$"));
        static const QRegularExpression shellKeyword(QStringLiteral("^(?:begin|break|case|catch|continue|do|done|else|elseif|end|esac|exit|fi|for|foreach|function|if|in|param|return|switch|then|throw|trap|try|until|while)$"), QRegularExpression::CaseInsensitiveOption);
        static const QRegularExpression literal(QStringLiteral("^(?:true|false|null)$"));
        while (at < limit)
        {
            if (code && cpp && starts(at, QLatin1String("//")))
            {
                setFormat(at, limit - at, m_colors.comment); break;
            }
            if (code && ((cpp && starts(at, QLatin1String("/*")))
                || (xml && starts(at, QLatin1String("<!--")))
                || (shell && starts(at, QLatin1String("<#")))))
            {
                at = cpp ? commentEnd(at, QLatin1String("*/"), 1)
                    : xml ? commentEnd(at, QLatin1String("-->"), 2)
                    : commentEnd(at, QLatin1String("#>"), 3);
                continue;
            }
            const QChar ch = text.at(at);
            if (code && (shell || m_language == Language::Ini) && (ch == QLatin1Char('#')
                || (m_language == Language::Ini && ch == QLatin1Char(';'))))
            {
                setFormat(at, limit - at, m_colors.comment); break;
            }
            if (code && cpp && ch == QLatin1Char('#') && text.left(at).trimmed().isEmpty())
            {
                setFormat(at, limit - at, m_colors.directive); break;
            }
            if (code && (ch == QLatin1Char('"') || (ch == QLatin1Char('\'') && m_language != Language::Json)))
            {
                const int begin = at++;
                while (at < limit)
                {
                    if (text.at(at) == QLatin1Char('\\') && !xml) { at = std::min(limit, at + 2); continue; }
                    if (text.at(at++) == ch) break;
                }
                int next = at;
                while (next < limit && text.at(next).isSpace()) ++next;
                setFormat(begin, at - begin, m_language == Language::Json && next < limit && text.at(next) == QLatin1Char(':')
                    ? m_colors.attribute : m_colors.string);
                continue;
            }
            if (xml && ch == QLatin1Char('<')) { insideTag = true; ++at; continue; }
            if (xml && ch == QLatin1Char('>')) { insideTag = false; ++at; continue; }
            if (code && shell && ch == QLatin1Char('$'))
            {
                const int begin = at++;
                while (at < limit && (text.at(at).isLetterOrNumber() || text.at(at) == QLatin1Char('_') || text.at(at) == QLatin1Char(':'))) ++at;
                setFormat(begin, at - begin, m_colors.attribute); continue;
            }
            if (code && ch.isDigit())
            {
                const int begin = at++;
                while (at < limit && (text.at(at).isLetterOrNumber() || text.at(at) == QLatin1Char('.') || text.at(at) == QLatin1Char('_'))) ++at;
                setFormat(begin, at - begin, m_colors.number); continue;
            }
            if (code && (ch.isLetter() || ch == QLatin1Char('_')))
            {
                const int begin = at++;
                while (at < limit && (text.at(at).isLetterOrNumber() || text.at(at) == QLatin1Char('_') || (xml && (text.at(at) == QLatin1Char(':') || text.at(at) == QLatin1Char('-'))))) ++at;
                const QString word = text.mid(begin, at - begin);
                if (cpp && cppKeyword.match(word).hasMatch()) setFormat(begin, at - begin, m_colors.keyword);
                else if (shell && shellKeyword.match(word).hasMatch()) setFormat(begin, at - begin, m_colors.keyword);
                else if (m_language == Language::Json && literal.match(word).hasMatch()) setFormat(begin, at - begin, m_colors.keyword);
                else if (xml && insideTag)
                {
                    int next = at; while (next < limit && text.at(next).isSpace()) ++next;
                    setFormat(begin, at - begin, next < limit && text.at(next) == QLatin1Char('=') ? m_colors.attribute : m_colors.tag);
                }
                else if (m_language == Language::Ini)
                {
                    int next = at; while (next < limit && text.at(next).isSpace()) ++next;
                    if (next < limit && text.at(next) == QLatin1Char('=')) setFormat(begin, at - begin, m_colors.attribute);
                }
                continue;
            }
            if (isOpenBracket(ch) || isCloseBracket(ch))
            {
                data->brackets.push_back({at, ch});
                if (m_language == Language::Ini && ch == QLatin1Char('['))
                {
                    const qsizetype end = QStringView(text).first(limit).indexOf(QLatin1Char(']'), at + 1);
                    if (end >= 0) setFormat(at, static_cast<int>(end) - at + 1, m_colors.tag);
                }
            }
            ++at;
        }
        if (insideTag && currentBlockState() == 0) setCurrentBlockState(4);
        setCurrentBlockUserData(data);
    }

private:
    Language m_language = Language::PlainText;
    EditorColors m_colors;
};

class CodeLineNumberArea final : public QWidget
{
public:
    explicit CodeLineNumberArea(CodeTextEdit* editor) : QWidget(editor), m_editor(editor)
    {
        setObjectName(QStringLiteral("code_editor_gutter"));
        setAttribute(Qt::WA_OpaquePaintEvent);
    }
    QSize sizeHint() const override { return QSize(m_editor->lineNumberAreaWidth(), 0); }
protected:
    void paintEvent(QPaintEvent* event) override { m_editor->paintLineNumberArea(event); }
private:
    CodeTextEdit* m_editor;
};

CodeTextEdit::CodeTextEdit(QWidget* parent) : QPlainTextEdit(parent)
{
    m_applicationFont = QApplication::font();
    setProperty("ksword_preserve_custom_font", true);
    const QFont fixedFont = editorFont();
    setFont(fixedFont);
    setTabStopDistance(QFontMetricsF(fixedFont).horizontalAdvance(QLatin1Char(' ')) * kIndentWidth);
    // Bare QPlainTextEdit hosts historically wrap unless they opt out.
    setLineWrapMode(QPlainTextEdit::WidgetWidth);
    setFrameShape(QFrame::NoFrame);
    // Frame formatting is undoable. Establish it once, then use widget viewport
    // padding for later compact/comfortable presentation changes.
    document()->setDocumentMargin(0.0);
    m_lineNumberArea = new CodeLineNumberArea(this);
    m_syntaxHighlighter = new CodeSyntaxHighlighter(document());
    m_extraSelectionTimer = new QTimer(this);
    m_extraSelectionTimer->setSingleShot(true);
    m_extraSelectionTimer->setInterval(18);
    connect(m_extraSelectionTimer, &QTimer::timeout, this, [this] { refreshExtraSelections(); });
    connect(this, &QPlainTextEdit::blockCountChanged, this, [this](int) { updateGutterGeometry(); });
    connect(this, &QPlainTextEdit::updateRequest, this, [this](const QRect& rect, int deltaY) {
        if (deltaY) m_lineNumberArea->update();
        else m_lineNumberArea->update(0, rect.y() + (m_compactMode ? 2 : 10), m_lineNumberArea->width(), rect.height());
        if (rect.contains(viewport()->rect())) updateGutterGeometry();
    });
    connect(this, &QPlainTextEdit::cursorPositionChanged, this, [this] {
        scheduleRefreshExtraSelections(); m_lineNumberArea->update();
    });
    connect(this, &QPlainTextEdit::textChanged, this, [this] {
        scheduleRefreshExtraSelections();
        if (m_syntaxLanguage == Language::Auto) scheduleSyntaxRefresh();
    });
    updateGutterGeometry();
    refreshThemeColors();
    m_fontSizeScale = fontSizeScale(font(), m_applicationFont);
    m_fontTrackingReady = true;
    qApp->installEventFilter(this);
    // No real content exists yet. Discard only decoration setup history here;
    // subsequent language/theme/compact changes never clear user undo history.
    document()->clearUndoRedoStacks();
    document()->setModified(false);
}

CodeTextEdit::~CodeTextEdit()
{
    // Removing formatting during destruction is not a source edit. Suppress
    // notifications while modal owners still have input-invalidating slots.
    const QSignalBlocker editorSignals(this);
    const QSignalBlocker documentSignals(document());
    delete m_syntaxHighlighter;
    m_syntaxHighlighter = nullptr;
}

QFont CodeTextEdit::editorFont()
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    const QFont inherited = QApplication::font();
    if (inherited.pointSizeF() > 0) font.setPointSizeF(inherited.pointSizeF());
    else if (inherited.pixelSize() > 0) font.setPixelSize(inherited.pixelSize());
    font.setFamilies(QStringList{QStringLiteral("Consolas"), QStringLiteral("Cascadia Mono"),
        font.family(), QStringLiteral("Microsoft YaHei UI")});
    return font;
}

void CodeTextEdit::setSyntaxLanguage(SyntaxLanguage language)
{
    if (m_syntaxLanguage == language) return;
    m_syntaxLanguage = language;
    if (language == Language::Auto) scheduleSyntaxRefresh();
    else
    {
        m_syntaxRefreshPending = false;
        m_effectiveSyntaxLanguage = language;
        static_cast<CodeSyntaxHighlighter*>(m_syntaxHighlighter)->setLanguage(language);
        refreshThemeColors();
    }
}

CodeTextEdit::SyntaxLanguage CodeTextEdit::effectiveSyntaxLanguage() const
{
    return m_syntaxLanguage == Language::Auto && m_syntaxRefreshPending
        ? detectLanguage(document()) : m_effectiveSyntaxLanguage;
}

void CodeTextEdit::scheduleSyntaxRefresh()
{
    if (m_syntaxRefreshPending) return;
    m_syntaxRefreshPending = true;
    QTimer::singleShot(0, this, [this] {
        if (!m_syntaxRefreshPending) return;
        m_syntaxRefreshPending = false; refreshSyntaxLanguage();
    });
}

void CodeTextEdit::refreshSyntaxLanguage()
{
    const auto language = m_syntaxLanguage == Language::Auto ? detectLanguage(document()) : m_syntaxLanguage;
    if (language == m_effectiveSyntaxLanguage) return;
    m_effectiveSyntaxLanguage = language;
    static_cast<CodeSyntaxHighlighter*>(m_syntaxHighlighter)->setLanguage(language);
    refreshThemeColors();
}

void CodeTextEdit::refreshThemeColors()
{
    m_themeRefreshPending = false;
    if (!m_syntaxHighlighter) return;
    const bool modified = document()->isModified();
    const QSignalBlocker editorSignals(this);
    const QSignalBlocker documentSignals(document());
    static_cast<CodeSyntaxHighlighter*>(m_syntaxHighlighter)->setColors(colorsFor(palette()));
    m_syntaxHighlighter->rehighlight();
    document()->setModified(modified);
    refreshExtraSelections();
    if (m_lineNumberArea) m_lineNumberArea->update();
    viewport()->update();
}

void CodeTextEdit::setWhitespaceVisible(bool visible)
{
    if (m_whitespaceVisible == visible) return;
    m_whitespaceVisible = visible;
    const bool modified = document()->isModified();
    const QSignalBlocker editorSignals(this);
    const QSignalBlocker documentSignals(document());
    QTextOption option = document()->defaultTextOption();
    auto flags = option.flags();
    flags.setFlag(QTextOption::ShowTabsAndSpaces, visible);
    flags.setFlag(QTextOption::ShowLineAndParagraphSeparators, visible);
    option.setFlags(flags); document()->setDefaultTextOption(option);
    document()->setModified(modified); viewport()->update();
}

void CodeTextEdit::setLineNumbersVisible(bool visible)
{
    if (m_lineNumbersVisible == visible) return;
    m_lineNumbersVisible = visible;
    m_lineNumberArea->setVisible(visible);
    updateGutterGeometry();
}

void CodeTextEdit::setCompactMode(bool compact)
{
    if (m_compactMode == compact) return;
    m_compactMode = compact;
    const bool modified = document()->isModified();
    const QSignalBlocker editorSignals(this);
    const QSignalBlocker documentSignals(document());
    updateGutterGeometry();
    document()->setModified(modified);
    viewport()->update();
}

int CodeTextEdit::lineNumberAreaWidth() const
{
    if (!m_lineNumbersVisible) return 0;
    const int digits = std::max(2, static_cast<int>(QString::number(std::max(1, blockCount())).size()));
    return 22 + fontMetrics().horizontalAdvance(QLatin1Char('9')) * digits;
}

void CodeTextEdit::updateGutterGeometry()
{
    if (!m_lineNumberArea) return;
    const int width = lineNumberAreaWidth();
    const int inset = m_compactMode ? 2 : 10;
    setViewportMargins(width + inset, inset, inset, inset);
    const QRect rect = contentsRect();
    m_lineNumberArea->setGeometry(rect.left(), rect.top(), width, rect.height());
}

void CodeTextEdit::paintLineNumberArea(QPaintEvent* event)
{
    const auto colors = colorsFor(palette());
    QPainter painter(m_lineNumberArea);
    painter.fillRect(event->rect(), colors.gutter);
    painter.setPen(colors.divider);
    painter.drawLine(m_lineNumberArea->width() - 1, event->rect().top(), m_lineNumberArea->width() - 1, event->rect().bottom());
    QTextBlock block = firstVisibleBlock();
    const int current = textCursor().blockNumber();
    QFont numberFont = font();
    if (numberFont.pointSizeF() > 8.0) numberFont.setPointSizeF(std::max(8.0, numberFont.pointSizeF() - 1.0));
    const int inset = m_compactMode ? 2 : 10;
    painter.setClipRect(QRect(0, inset, m_lineNumberArea->width(), std::max(0, m_lineNumberArea->height() - inset * 2)));
    int top = qRound(blockBoundingGeometry(block).translated(contentOffset()).top()) + inset;
    while (block.isValid() && top <= event->rect().bottom())
    {
        const int height = qRound(blockBoundingRect(block).height());
        if (block.isVisible() && top + height >= event->rect().top())
        {
            const bool active = block.blockNumber() == current;
            numberFont.setBold(active); painter.setFont(numberFont);
            painter.setPen(active ? colors.currentNumber : colors.gutterText);
            painter.drawText(5, top, m_lineNumberArea->width() - 14, fontMetrics().height(), Qt::AlignRight | Qt::AlignVCenter, QString::number(block.blockNumber() + 1));
            if (active) painter.fillRect(3, top + 3, 2, std::max(3, fontMetrics().height() - 6), colors.currentNumber);
        }
        top += height; block = block.next();
    }
}

bool CodeTextEdit::gotoLine(int oneBasedLine)
{
    if (oneBasedLine <= 0) return false;
    const QTextBlock block = document()->findBlockByLineNumber(oneBasedLine - 1);
    if (!block.isValid()) return false;
    QTextCursor cursor(document()); cursor.setPosition(block.position());
    const QPointer<CodeTextEdit> self(this);
    setTextCursor(cursor);
    if (!self) return false;
    centerCursor(); return true;
}

void CodeTextEdit::setExternalExtraSelections(const QList<QTextEdit::ExtraSelection>& selections)
{
    m_externalExtraSelections = selections; scheduleRefreshExtraSelections();
}

void CodeTextEdit::resizeEvent(QResizeEvent* event)
{
    QPlainTextEdit::resizeEvent(event); updateGutterGeometry();
}

void CodeTextEdit::changeEvent(QEvent* event)
{
    QPlainTextEdit::changeEvent(event);
    if (!event) return;
    if (event->type() == QEvent::FontChange)
    {
        // 外部 setFont 是宿主明确的字体/缩放政策；全局字体正在变化时不把旧字号当新倍率。
        if (m_fontTrackingReady && !m_updatingApplicationFont)
        {
            if (QApplication::font() == m_applicationFont) m_fontSizeScale = fontSizeScale(font(), m_applicationFont);
            else scheduleApplicationFontRefresh();
        }
        setTabStopDistance(QFontMetricsF(font()).horizontalAdvance(QLatin1Char(' ')) * kIndentWidth);
        updateGutterGeometry();
    }
    if (event->type() == QEvent::ApplicationFontChange) scheduleApplicationFontRefresh();
    if ((event->type() == QEvent::PaletteChange || event->type() == QEvent::ApplicationPaletteChange) && !m_themeRefreshPending)
    {
        m_themeRefreshPending = true;
        QTimer::singleShot(0, this, [this] {
            if (m_themeRefreshPending) refreshThemeColors();
        });
    }
}

bool CodeTextEdit::eventFilter(QObject* source, QEvent* event)
{
    if (source == qApp && event != nullptr &&
        (event->type() == QEvent::ApplicationFontChange || event->type() == QEvent::FontChange))
        scheduleApplicationFontRefresh();
    return QPlainTextEdit::eventFilter(source, event);
}

void CodeTextEdit::scheduleApplicationFontRefresh()
{
    if (!m_fontTrackingReady || m_applicationFontRefreshPending) return;
    m_fontBeforeApplicationChange = font();
    m_applicationFontRefreshPending = true;
    QTimer::singleShot(0, this, [this]()
    {
        m_applicationFontRefreshPending = false;
        const QFont application = QApplication::font();
        QFont updated = font();
        // 合并全局通知期间的显式宿主调整，字体族/粗细/斜体始终沿用当前正式字体。
        if (updated != m_fontBeforeApplicationChange)
            m_fontSizeScale = fontSizeScale(updated, application);
        m_applicationFont = application;
        if (application.pointSizeF() > 0) updated.setPointSizeF(application.pointSizeF() * m_fontSizeScale);
        else if (application.pixelSize() > 0)
            updated.setPixelSize(std::max(1, qRound(application.pixelSize() * m_fontSizeScale)));
        if (updated == font()) return;
        const int vertical = verticalScrollBar()->value();
        const int horizontal = horizontalScrollBar()->value();
        m_updatingApplicationFont = true;
        const QPointer<CodeTextEdit> guard(this);
        setFont(updated);
        if (!guard) return;
        m_updatingApplicationFont = false;
        verticalScrollBar()->setValue(vertical);
        horizontalScrollBar()->setValue(horizontal);
    });
}

void CodeTextEdit::scheduleRefreshExtraSelections()
{
    // Do not postpone forever when a log appends faster than the timer period.
    if (m_extraSelectionTimer && !m_extraSelectionTimer->isActive()) m_extraSelectionTimer->start();
}

bool CodeTextEdit::isCodeBracket(int position) const
{
    const QTextBlock block = document()->findBlock(position);
    const auto* data = dynamic_cast<CodeBlockData*>(block.userData());
    if (!data) return false;
    const int offset = position - block.position();
    return std::any_of(data->brackets.cbegin(), data->brackets.cend(), [&](const BracketToken& token) { return token.offset == offset; });
}

int CodeTextEdit::findBracketPair(int bracketPos, QChar bracketCh) const
{
    QTextBlock block = document()->findBlock(bracketPos);
    const int direction = isOpenBracket(bracketCh) ? 1 : -1;
    QVector<QChar> stack;
    while (block.isValid())
    {
        const auto* data = dynamic_cast<CodeBlockData*>(block.userData());
        if (!data) return -1;
        if (direction < 0 && !data->fullyScanned && bracketPos >= block.position() + data->coveredLength) return -1;
        const auto visit = [&](const BracketToken& token) {
            const int position = block.position() + token.offset;
            if ((direction > 0 && position < bracketPos) || (direction < 0 && position > bracketPos)) return -2;
            if (std::abs(position - bracketPos) > kBracketScanCharacters) return -1;
            if (direction > 0 ? isOpenBracket(token.character) : isCloseBracket(token.character)) stack.push_back(token.character);
            else
            {
                if (stack.isEmpty() || pairBracket(stack.back()) != token.character) return -1;
                stack.pop_back();
                if (stack.isEmpty()) return position;
            }
            return -2;
        };
        if (direction > 0)
        {
            for (const auto& token : data->brackets) { const int result = visit(token); if (result >= -1) return result; }
            if (!data->fullyScanned) return -1;
        }
        else
        {
            for (auto token = data->brackets.crbegin(); token != data->brackets.crend(); ++token) { const int result = visit(*token); if (result >= -1) return result; }
        }
        block = direction > 0 ? block.next() : block.previous();
        if (block.isValid() && std::abs(block.position() - bracketPos) > kBracketScanCharacters) break;
    }
    return -1;
}

void CodeTextEdit::refreshExtraSelections()
{
    const auto colors = colorsFor(palette());
    QList<QTextEdit::ExtraSelection> selections;
    QTextEdit::ExtraSelection line;
    line.cursor = textCursor(); line.cursor.clearSelection();
    line.format.setProperty(QTextFormat::FullWidthSelection, true);
    line.format.setBackground(colors.currentLine); selections.push_back(line);
    const int position = textCursor().position();
    int bracketPos = -1;
    if (position > 0 && isCodeBracket(position - 1)) bracketPos = position - 1;
    else if (position < document()->characterCount() - 1 && isCodeBracket(position)) bracketPos = position;
    if (bracketPos >= 0 && !textCursor().hasSelection())
    {
        const int match = findBracketPair(bracketPos, document()->characterAt(bracketPos));
        const auto append = [&](int at, QColor background) {
            QTextEdit::ExtraSelection bracket;
            bracket.cursor = QTextCursor(document()); bracket.cursor.setPosition(at);
            bracket.cursor.movePosition(QTextCursor::NextCharacter, QTextCursor::KeepAnchor);
            bracket.format.setBackground(background);
            bracket.format.setForeground(KswordTheme::EnsureTextContrast(palette().color(QPalette::Text), background));
            selections.push_back(bracket);
        };
        append(bracketPos, match >= 0 ? colors.bracket : colors.bracketError);
        if (match >= 0) append(match, colors.bracket);
    }
    // Search/host highlights take precedence over quiet line/bracket feedback.
    selections.append(m_externalExtraSelections);
    setExtraSelections(selections);
}

void CodeTextEdit::indentSelection(bool backwards)
{
    if (isReadOnly()) return;
    const QPointer<CodeTextEdit> self(this);
    QTextCursor original = textCursor();
    if (!backwards && !original.hasSelection())
    {
        original.beginEditBlock();
        original.insertText(QString(kIndentWidth - original.positionInBlock() % kIndentWidth, QLatin1Char(' ')));
        if (!self) return;
        original.endEditBlock();
        if (self) setTextCursor(original);
        return;
    }
    QTextBlock first = document()->findBlock(original.selectionStart());
    QTextBlock last = document()->findBlock(original.selectionEnd());
    if (original.hasSelection() && original.selectionEnd() == last.position()) last = last.previous();
    QVector<int> positions;
    for (QTextBlock block = first; block.isValid() && block.position() <= last.position(); block = block.next()) positions.push_back(block.position());
    QTextCursor edit(document()); edit.beginEditBlock();
    for (auto at = positions.crbegin(); at != positions.crend(); ++at)
    {
        edit.setPosition(*at);
        if (!backwards) edit.insertText(QString(kIndentWidth, QLatin1Char(' ')));
        else
        {
            int count = document()->characterAt(*at) == QLatin1Char('\t') ? 1 : 0;
            if (!count) while (count < kIndentWidth && document()->characterAt(*at + count) == QLatin1Char(' ')) ++count;
            if (count) { edit.setPosition(*at + count, QTextCursor::KeepAnchor); edit.removeSelectedText(); }
        }
        if (!self) return;
    }
    edit.endEditBlock();
    if (self) setTextCursor(original);
}

void CodeTextEdit::keyPressEvent(QKeyEvent* event)
{
    const bool indentKey = event->key() == Qt::Key_Tab || event->key() == Qt::Key_Backtab;
    if (indentKey && !isReadOnly() && !(event->modifiers() & (Qt::ControlModifier | Qt::AltModifier | Qt::MetaModifier)))
    {
        indentSelection(event->key() == Qt::Key_Backtab || event->modifiers().testFlag(Qt::ShiftModifier));
        event->accept(); return;
    }
    QPlainTextEdit::keyPressEvent(event);
}
