#include "WorkbenchTextView.h"
#include "MemoryRowCanvas.h"
#include "WorkbenchTextCodePages.h"
#include "../FlowLayout.h"
#include "../StructuredFieldView.h"
#include "../TypedSyntaxDocument.h"
#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QEvent>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPointer>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QToolButton>
#include <QVBoxLayout>
#include <algorithm>
#include <limits>

namespace ks::ui
{
    namespace
    {
        using ksword::memwb::TextGlyph;
        using ksword::memwb::TextGlyphKind;
        QString EncodingName(const WorkbenchTextView::Encoding encoding)
        {
            using Encoding = WorkbenchTextView::Encoding;
            switch (encoding)
            {
            case Encoding::Ansi: return ks::i18n::sourceText(QStringLiteral("系统 ANSI"));
            case Encoding::Utf8: return QStringLiteral("UTF-8");
            case Encoding::Utf16LE: return QStringLiteral("UTF-16 LE");
            case Encoding::Utf16BE: return QStringLiteral("UTF-16 BE");
            case Encoding::Gbk: return QStringLiteral("GBK");
            case Encoding::Gb18030: return QStringLiteral("GB18030");
            case Encoding::Big5: return QStringLiteral("Big5");
            case Encoding::Ascii: return QStringLiteral("ASCII");
            case Encoding::Auto: return ks::i18n::sourceText(QStringLiteral("自动（BOM 优先）"));
            }
            return QStringLiteral("UTF-8");
        }
        QString GlyphText(const TextGlyph& glyph, bool showControls = true)
        {
            switch (glyph.kind)
            {
            case TextGlyphKind::Bom: return showControls ? QStringLiteral("⟨BOM⟩") : QStringLiteral(" ");
            case TextGlyphKind::Invalid: return QString(QChar(0xFFFDU));
            case TextGlyphKind::Unreadable: return QString(QChar(0x00D7U));
            case TextGlyphKind::Loading: return QString(QChar(0x00B7U));
            case TextGlyphKind::Incomplete: return QString(QChar(0x2026U));
            case TextGlyphKind::Character: break;
            }
            if (!showControls)
            {
                const auto category = QChar::category(static_cast<char32_t>(glyph.scalar));
                if (glyph.scalar == 9) return QStringLiteral("    ");
                if (category == QChar::Other_Control || category == QChar::Other_Format
                    || category == QChar::Separator_Line || category == QChar::Separator_Paragraph) return QStringLiteral(" ");
            }
            if (glyph.scalar == 0) return QStringLiteral("\\0");
            if (glyph.scalar == 9) return QStringLiteral("⇥");
            if (glyph.scalar == 10) return QStringLiteral("↵");
            if (glyph.scalar == 13) return QStringLiteral("␍");
            const auto category = QChar::category(static_cast<char32_t>(glyph.scalar));
            if (category == QChar::Other_Control || category == QChar::Other_Format
                || category == QChar::Separator_Line || category == QChar::Separator_Paragraph)
                return QStringLiteral("⟨U+%1⟩").arg(QString::number(glyph.scalar, 16).toUpper().rightJustified(4, QLatin1Char('0')));
            const char32_t scalar = static_cast<char32_t>(glyph.scalar);
            return QString::fromUcs4(&scalar, 1);
        }
        MemoryTokenRole GlyphRole(const TextGlyph& glyph)
        {
            if (glyph.kind == TextGlyphKind::Invalid) return MemoryTokenRole::Invalid;
            return glyph.kind == TextGlyphKind::Character ? MemoryTokenRole::Plain : MemoryTokenRole::Comment;
        }
        QString RawGlyphText(const TextGlyph& glyph)
        {
            if (glyph.kind != TextGlyphKind::Character && glyph.kind != TextGlyphKind::Bom) return GlyphText(glyph);
            const char32_t scalar = static_cast<char32_t>(glyph.scalar);
            return QString::fromUcs4(&scalar, 1);
        }
    }

    QString DecodeTextChunkForTest(const std::vector<std::uint8_t>& bytes,
        const std::vector<std::uint8_t>& validMask, const WorkbenchTextView::Encoding encoding,
        const bool oddLeadingByte)
    {
        ksword::memwb::TextDecodeOptions options;
        options.encoding = encoding;
        options.oddLeadingByte = oddLeadingByte;
        options.codePageDecoder = DecodeWorkbenchCodePage;
        const auto result = ksword::memwb::DecodeMemoryText(bytes, validMask, options);
        QString text;
        for (const auto& glyph : result.glyphs) text += GlyphText(glyph);
        return text;
    }

    WorkbenchTextView::WorkbenchTextView(QWidget* parent) : QWidget(parent)
    {
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(4);
        auto* bar = new QWidget(this);
        auto* flow = new FlowLayout(bar, 4, 4, 4);
        flow->addWidget(new QLabel(QStringLiteral("编码："), bar));
        m_encodingCombo = new QComboBox(bar);
        m_encodingCombo->setObjectName(QStringLiteral("ksMemwbTextEncodingCombo"));
        for (int value = 0; value <= static_cast<int>(Encoding::Auto); ++value)
            m_encodingCombo->addItem(EncodingName(static_cast<Encoding>(value)), value);
        m_encodingCombo->setToolTip(QStringLiteral("手动选择优先；自动模式识别窗口起点的 BOM，否则使用 UTF-8。编码切换不修改原始字节。"));
        flow->addWidget(m_encodingCombo);
        m_structureCombo = new QComboBox(bar);
        m_structureCombo->setObjectName(QStringLiteral("ksMemwbTextStructureCombo"));
        m_structureCombo->addItems({QStringLiteral("原始文本"), QStringLiteral("结构视图")});
        m_structureCombo->setToolTip(QStringLiteral("结构视图仅解析当前已完整读取窗口中的 JSON 或 XML；不修改原始字节。"));
        flow->addWidget(m_structureCombo);
        m_bytesToggle = new QCheckBox(QStringLiteral("显示字节"), bar);
        m_bytesToggle->setChecked(true);
        m_bytesToggle->setToolTip(QStringLiteral("收起左侧字节列，为右侧文本留出更多空间"));
        flow->addWidget(m_bytesToggle);
        m_wrapToggle = new QCheckBox(QStringLiteral("自动换行"), bar);
        flow->addWidget(m_wrapToggle);
        m_controlToggle = new QCheckBox(QStringLiteral("控制字符"), bar);
        m_controlToggle->setChecked(true);
        m_controlToggle->setToolTip(QStringLiteral("显示控制字符的标记；关闭后用空白显示，复制仍保留原始文本"));
        flow->addWidget(m_controlToggle);
        m_findEdit = new QLineEdit(bar);
        m_findEdit->setObjectName(QStringLiteral("ksMemwbTextFind"));
        m_findEdit->setPlaceholderText(QStringLiteral("查找文本"));
        m_findEdit->setMaximumWidth(180);
        m_findEdit->setToolTip(QStringLiteral("在当前已读取文本中查找；Enter 查找下一处，Ctrl+F 聚焦"));
        flow->addWidget(m_findEdit);
        auto* find = new QToolButton(bar);
        find->setText(QStringLiteral("下一处"));
        find->setToolTip(QStringLiteral("查找下一处文本，并选中对应的原始字节"));
        flow->addWidget(find);
        layout->addWidget(bar);
        m_canvas = new MemoryRowCanvas(this);
        m_canvas->setObjectName(QStringLiteral("ksMemwbTextCanvas"));
        m_canvas->setTextPriority(true);
        m_canvas->setContentTitle(QStringLiteral("文本"));
        m_canvas->installEventFilter(this);
        m_findEdit->installEventFilter(this);
        m_viewStack = new QStackedWidget(this);
        m_viewStack->addWidget(m_canvas);
        m_structuredView = new StructuredFieldView(m_viewStack);
        m_structuredView->setPresentation(StructuredFieldView::Presentation::Tree);
        m_structuredView->setObjectName(QStringLiteral("ksMemwbTextStructuredView"));
        m_viewStack->addWidget(m_structuredView);
        m_structuredView->installEventFilter(this);
        for (QWidget* child : m_structuredView->findChildren<QWidget*>()) child->installEventFilter(this);
        layout->addWidget(m_viewStack, 1);
        connect(m_structureCombo, &QComboBox::currentIndexChanged, this, [this](const int index) {
            m_viewStack->setCurrentWidget(index == 1 && !m_structuredView->document().isEmpty()
                ? static_cast<QWidget*>(m_structuredView) : static_cast<QWidget*>(m_canvas));
        });
        connect(m_controlToggle, &QCheckBox::toggled, this, [this] { rebuildText(); });
        m_status = new QLabel(this);
        m_status->setObjectName(QStringLiteral("ksMemwbTextStatus"));
        m_status->setWordWrap(true);
        layout->addWidget(m_status);
        connect(m_encodingCombo, &QComboBox::currentIndexChanged, this, [this](const int index) {
            setEncoding(static_cast<Encoding>(m_encodingCombo->itemData(index).toInt()));
        });
        connect(m_bytesToggle, &QCheckBox::toggled, m_canvas, &MemoryRowCanvas::setBytesVisible);
        connect(m_wrapToggle, &QCheckBox::toggled, m_canvas, &MemoryRowCanvas::setWrapContent);
        connect(m_findEdit, &QLineEdit::returnPressed, this, &WorkbenchTextView::findNext);
        connect(m_findEdit, &QLineEdit::textChanged, this, [this]() { m_findOffset = 0; });
        connect(find, &QToolButton::clicked, this, &WorkbenchTextView::findNext);
        connect(m_canvas, &MemoryRowCanvas::selectionChanged, this, &WorkbenchTextView::selectionChanged);
        connect(m_canvas, &MemoryRowCanvas::requestMore, this, &WorkbenchTextView::browseMore);
        connect(m_canvas, &MemoryRowCanvas::contextMenuRequested, this, &WorkbenchTextView::showContextMenu);
        rebuildText();
    }
    void WorkbenchTextView::setBytesProvider(IWorkbenchBytesProvider* provider)
    {
        if (m_provider != provider) { m_canvas->cancelPendingNavigation(); m_requestedAddress.reset(); m_requestOutstanding = false; m_browseBackStack.clear(); }
        m_provider = provider;
        rebuildText();
    }
    void WorkbenchTextView::setWindow(const std::uint64_t address, const std::uint64_t length)
    {
        const bool browsing = m_requestedAddress.has_value() && *m_requestedAddress == address;
        const bool sameAddress = m_hasWindow && address == m_address;
        if (!sameAddress && !browsing)
        {
            m_canvas->cancelPendingNavigation();
            m_browseBackStack.clear();
            m_keepBrowseViewport = false;
            m_decodeOrigin = address;
            m_effectiveEncoding = m_encoding == Encoding::Auto ? Encoding::Utf8 : m_encoding;
            m_bomDetected = false;
        }
        m_address = address;
        m_length = std::min<std::uint64_t>(length, kMaxWindowBytes);
        m_hasWindow = true;
        m_requestedAddress.reset();
        m_requestOutstanding = false;
        rebuildText();
    }
    void WorkbenchTextView::reset()
    {
        m_canvas->cancelPendingNavigation();
        m_browseBackStack.clear();
        m_address = 0; m_length = 0; m_decodeOrigin = 0;
        m_hasWindow = false; m_requestOutstanding = false; m_bomDetected = false;
        m_keepBrowseViewport = false;
        m_requestedAddress.reset();
        rebuildText();
    }
    void WorkbenchTextView::setBytesPerRow(const int bytesPerRow)
    {
        if (bytesPerRow < 1 || bytesPerRow > 4096 || bytesPerRow == m_bytesPerRow) return;
        m_bytesPerRow = bytesPerRow;
        rebuildText();
    }
    int WorkbenchTextView::bytesPerRow() const { return m_bytesPerRow; }
    void WorkbenchTextView::setEncoding(const Encoding encoding)
    {
        if (static_cast<int>(encoding) < 0 || static_cast<int>(encoding) > static_cast<int>(Encoding::Auto) || encoding == m_encoding) return;
        m_encoding = encoding;
        m_effectiveEncoding = encoding == Encoding::Auto ? Encoding::Utf8 : encoding;
        m_bomDetected = false;
        m_decodeOrigin = m_address;
        const QSignalBlocker blocker(m_encodingCombo);
        m_encodingCombo->setCurrentIndex(m_encodingCombo->findData(static_cast<int>(encoding)));
        rebuildText();
    }
    WorkbenchTextView::Encoding WorkbenchTextView::encoding() const { return m_encoding; }
    WorkbenchTextView::Encoding WorkbenchTextView::effectiveEncoding() const { return m_effectiveEncoding; }
    bool WorkbenchTextView::hasBom() const { return m_bomDetected; }
    void WorkbenchTextView::setAddressBits(const int bits) { m_addressBits = bits > 32 ? 64 : 32; m_canvas->setAddressBits(m_addressBits); }
    void WorkbenchTextView::setAddressBounds(const std::uint64_t first, const std::uint64_t last)
    {
        if (first <= last) m_addressBounds = std::make_pair(first, last);
        else m_addressBounds.reset();
        m_requestOutstanding = false;
    }
    void WorkbenchTextView::setAddressRange(const std::uint64_t base, const std::uint64_t length)
    {
        if (length && length - 1 <= std::numeric_limits<std::uint64_t>::max() - base)
            setAddressBounds(base, base + length - 1);
        else clearAddressBounds();
    }
    void WorkbenchTextView::clearAddressBounds() { m_addressBounds.reset(); m_requestOutstanding = false; }
    void WorkbenchTextView::setBytesVisible(const bool visible) { m_bytesToggle->setChecked(visible); }
    bool WorkbenchTextView::bytesVisible() const { return m_canvas->bytesVisible(); }
    void WorkbenchTextView::setWrapText(const bool wrap) { m_wrapToggle->setChecked(wrap); }
    bool WorkbenchTextView::wrapText() const { return m_canvas->wrapContent(); }
    void WorkbenchTextView::setControlCharactersVisible(bool visible) { m_controlToggle->setChecked(visible); }
    bool WorkbenchTextView::controlCharactersVisible() const { return m_controlToggle->isChecked(); }
    void WorkbenchTextView::refreshView() { rebuildText(); }
    MemoryRowCanvas* WorkbenchTextView::canvas() const { return m_canvas; }
    std::optional<std::pair<std::uint64_t, std::uint64_t>> WorkbenchTextView::selectedByteRange() const { return m_canvas->selectedRange(); }
    QString WorkbenchTextView::renderedText() const { return m_renderedText; }
    QString WorkbenchTextView::selectedDecodedText() const
    {
        QString text;
        const auto range = m_canvas->selectedRange();
        if (!range) return text;
        for (const auto& span : m_searchSpans)
            if (span.address <= range->second && span.address + span.byteLength - 1 >= range->first)
                text += m_flatText.mid(span.start, span.length);
        return text;
    }
    QString WorkbenchTextView::copyTextForCurrentView() const
    {
        if (m_viewStack->currentWidget() != m_structuredView) return selectedDecodedText();
        const QString selected = m_structuredView->selectedText();
        return selected.isEmpty() ? m_flatText : selected;
    }
    std::uint64_t WorkbenchTextView::windowAddress() const { return m_address; }
    std::uint64_t WorkbenchTextView::windowLength() const { return m_length; }
    QSize WorkbenchTextView::minimumSizeHint() const { return QSize(1, 1); }
    void WorkbenchTextView::setStatus(const QString& text) { m_status->setText(ks::i18n::sourceText(text)); }

    void WorkbenchTextView::rebuildText()
    {
        if (m_provider == nullptr || !m_hasWindow)
        {
            m_renderedText.clear(); m_flatText.clear(); m_searchSpans.clear(); m_canvas->setRows({}, false);
            updateStructuredView(false);
            setStatus(m_provider == nullptr ? QStringLiteral("尚未接入数据源。") : QStringLiteral("尚未定位；跟随十六进制页的当前窗口。"));
            return;
        }
        // The lookahead completes a scalar starting before the display cut.
        const bool utf16 = m_effectiveEncoding == Encoding::Utf16LE || m_effectiveEncoding == Encoding::Utf16BE;
        const bool utf8 = m_effectiveEncoding == Encoding::Utf8;
        std::uint64_t back = m_address != m_decodeOrigin && (utf16 || utf8)
            ? std::min<std::uint64_t>(m_address, utf16 ? 4U : 3U) : 0U;
        if (m_addressBounds && m_address >= m_addressBounds->first) back = std::min(back, m_address - m_addressBounds->first);
        else if (m_address >= m_decodeOrigin) back = std::min(back, m_address - m_decodeOrigin);
        const std::uint64_t fetchAddress = m_address - back;
        const std::uint64_t desiredLength = m_length + back + 4U;
        const std::uint64_t distance = std::numeric_limits<std::uint64_t>::max() - fetchAddress;
        const std::uint64_t fetchLength = desiredLength - 1 <= distance ? desiredLength : distance + 1;
        const WorkbenchByteWindow window = m_provider->FetchWindow(fetchAddress, fetchLength);
        if (!window.ok || window.bytes.empty())
        {
            m_requestOutstanding = false;
            m_requestedAddress.reset();
            m_renderedText.clear(); m_flatText.clear(); m_searchSpans.clear(); m_canvas->setRows({}, true);
            updateStructuredView(false);
            setStatus(ks::i18n::sourceText(QStringLiteral("0x%1 超出已读取窗口。"))
                .arg(QString::number(m_address, 16).toUpper().rightJustified(16, QLatin1Char('0'))));
            return;
        }
        const std::size_t available = std::min(window.bytes.size(), window.validMask.size());
        const std::vector<std::uint8_t> bytes(window.bytes.begin(), window.bytes.begin() + static_cast<std::ptrdiff_t>(available));
        const std::vector<std::uint8_t> states(window.validMask.begin(), window.validMask.begin() + static_cast<std::ptrdiff_t>(available));
        if (m_requestOutstanding && back < states.size() && states[static_cast<std::size_t>(back)] != 2U)
        {
            m_requestOutstanding = false;
            m_requestedAddress.reset();
        }
        ksword::memwb::TextDecodeOptions options;
        options.encoding = m_encoding == Encoding::Auto && m_address != m_decodeOrigin ? m_effectiveEncoding : m_encoding;
        options.codePageDecoder = DecodeWorkbenchCodePage;
        options.oddLeadingByte = ((fetchAddress - m_decodeOrigin) & 1U) != 0;
        options.recognizeBom = fetchAddress == m_decodeOrigin;
        const auto decoded = ksword::memwb::DecodeMemoryText(bytes, states, options);
        m_effectiveEncoding = decoded.effectiveEncoding;
        if (fetchAddress == m_decodeOrigin) m_bomDetected = decoded.bomDetected;
        QVector<MemoryDisplayRow> rows;
        QString rendered;
        QString flat;
        std::vector<SearchSpan> searchSpans;
        const std::size_t displayStart = static_cast<std::size_t>(back);
        const std::size_t displayLength = std::min<std::size_t>(available, static_cast<std::size_t>(m_length + back));
        std::uint64_t expectedLength = m_length;
        if (m_addressBounds && m_address >= m_addressBounds->first && m_address <= m_addressBounds->second &&
            expectedLength > 0 && expectedLength - 1 > m_addressBounds->second - m_address)
            expectedLength = m_addressBounds->second - m_address + 1;
        bool completeDecode = available >= displayStart + expectedLength;
        MemoryDisplayRow row;
        std::size_t rowStart = 0;
        std::size_t rowEnd = 0;
        const auto finishRow = [&]() {
            if (rowEnd <= rowStart) return;
            row.address = fetchAddress + rowStart;
            row.bytes = QByteArray(reinterpret_cast<const char*>(bytes.data() + rowStart), static_cast<qsizetype>(rowEnd - rowStart));
            for (std::size_t offset = rowStart; offset < rowEnd; ++offset)
            {
                row.validMask.push_back(states[offset]);
                row.changeKinds.push_back(offset < window.changeKinds.size() ? window.changeKinds[offset] : ksword::memwb::ByteChangeKind::Unchanged);
            }
            if (!rows.isEmpty()) rendered += QLatin1Char('\n');
            for (const auto& token : row.tokens) rendered += token.text;
            rows.push_back(std::move(row));
            row = MemoryDisplayRow{};
            rowStart = rowEnd;
        };
        for (const auto& glyph : decoded.glyphs)
        {
            if (glyph.offset + glyph.byteLength <= displayStart) continue;
            if (glyph.offset >= displayLength) break;
            if (glyph.kind != TextGlyphKind::Character && glyph.kind != TextGlyphKind::Bom)
                completeDecode = false;
            if (rows.isEmpty() && row.tokens.isEmpty()) { rowStart = glyph.offset; rowEnd = rowStart; }
            if (rowEnd > rowStart)
            {
                const std::uint64_t rowAddress = fetchAddress + rowStart;
                const std::size_t rowBudget = static_cast<std::size_t>(m_bytesPerRow)
                    - static_cast<std::size_t>(rowAddress % static_cast<std::uint64_t>(m_bytesPerRow));
                if (glyph.offset >= rowStart + rowBudget) finishRow();
            }
            const QString text = GlyphText(glyph, m_controlToggle->isChecked());
            const QString rawText = RawGlyphText(glyph);
            row.tokens.push_back({text, fetchAddress + glyph.offset, glyph.byteLength, GlyphRole(glyph)});
            searchSpans.push_back({flat.size(), rawText.size(), fetchAddress + glyph.offset, glyph.byteLength});
            flat += rawText;
            rowEnd = glyph.offset + glyph.byteLength;
        }
        finishRow();
        const bool preserve = m_keepBrowseViewport || (!m_canvas->rows().isEmpty() && !rows.isEmpty()
            && m_canvas->rows().front().address == rows.front().address);
        m_renderedText = std::move(rendered);
        m_flatText = std::move(flat);
        m_searchSpans = std::move(searchSpans);
        m_canvas->setRows(std::move(rows), preserve);
        updateStructuredView(completeDecode);
        setStatus(ks::i18n::sourceText(QStringLiteral("0x%1 起 %2 字节（%3）；字符选择对应完整原始字节。"))
            .arg(QString::number(m_address, 16).toUpper().rightJustified(16, QLatin1Char('0')))
            .arg(displayLength >= displayStart ? displayLength - displayStart : 0).arg(EncodingName(m_effectiveEncoding)));
    }

    void WorkbenchTextView::updateStructuredView(const bool completeDecode)
    {
        const auto parsed = completeDecode ? ParseTypedSyntaxDocument(m_flatText) : std::nullopt;
        const bool structured = parsed.has_value();
        m_structuredView->setDocument(structured ? parsed->fields : FieldDocument{});
        if (!structured)
        {
            activateOriginalView();
        }
        m_structureCombo->setEnabled(structured);
        m_structureCombo->setToolTip(ks::i18n::sourceText(structured
            ? QStringLiteral("结构视图仅解析当前已完整读取窗口中的 JSON 或 XML；不修改原始字节。")
            : completeDecode ? QStringLiteral("当前文本没有可解析结构，或超过结构视图限制。")
                : QStringLiteral("当前窗口存在未读取、无效或不完整字符，结构视图不可用。")));
    }

    void WorkbenchTextView::activateOriginalView()
    {
        m_structureCombo->setCurrentIndex(0);
        m_viewStack->setCurrentWidget(m_canvas);
    }

    void WorkbenchTextView::browseMore(const int direction, const int lines)
    {
        if (!m_hasWindow || m_requestOutstanding || direction == 0) return;
        const std::uint64_t delta = static_cast<std::uint64_t>(std::max(1, lines)) * static_cast<std::uint64_t>(m_bytesPerRow);
        std::uint64_t next = direction < 0 ? m_address - std::min(m_address, delta)
            : m_address + std::min(std::numeric_limits<std::uint64_t>::max() - m_address, delta);
        const auto bounds = m_addressBounds.value_or(std::make_pair(std::uint64_t{0},
            m_addressBits == 32 ? std::uint64_t{0xFFFFFFFFU} : std::numeric_limits<std::uint64_t>::max()));
        next = std::clamp(next, bounds.first, bounds.second);
        if (next == m_address) return;
        if (direction > 0)
        {
            if (const auto visible = m_canvas->addressForVisualLine(std::max(1, lines)); visible && *visible > m_address)
                next = *visible;
            for (const auto& span : m_searchSpans)
                if (span.address >= next) { next = span.address; break; }
            for (int line = 0; line < std::max(1, lines); ++line)
                if (const auto previous = m_canvas->addressForVisualLine(line); previous && *previous < next)
                    if (m_browseBackStack.empty() || m_browseBackStack.back() != *previous) m_browseBackStack.push_back(*previous);
            if (m_browseBackStack.size() > 128) m_browseBackStack.erase(m_browseBackStack.begin(), m_browseBackStack.end() - 128);
        }
        else
        {
            for (int line = 0; line < std::max(1, lines) && !m_browseBackStack.empty(); ++line)
            {
                const auto previous = m_browseBackStack.back();
                m_browseBackStack.pop_back();
                if (previous < m_address) next = previous;
            }
            if (m_effectiveEncoding == Encoding::Utf16LE || m_effectiveEncoding == Encoding::Utf16BE)
                if (((next - m_decodeOrigin) & 1U) != 0 && next > bounds.first) --next;
        }
        next = std::clamp(next, bounds.first, bounds.second);
        if (next == m_address) return;
        m_requestOutstanding = true;
        m_keepBrowseViewport = true;
        m_requestedAddress = next;
        m_address = next;
        m_length = std::max<std::uint64_t>(m_length, 4096U);
        // The workbench host only prepares shared pages; this view owns the
        // browse anchor. Snapshot hosts may synchronously refeed setWindow.
        const QPointer<WorkbenchTextView> self(this);
        emit windowRequested(next, m_length);
        if (self) rebuildText();
    }
    void WorkbenchTextView::openFind() { activateOriginalView(); m_findEdit->setFocus(); m_findEdit->selectAll(); }
    void WorkbenchTextView::findNext() { findMatch(false); }
    void WorkbenchTextView::findPrevious() { findMatch(true); }
    void WorkbenchTextView::findMatch(bool backwards)
    {
        activateOriginalView();
        const QString needle = m_findEdit->text();
        if (needle.isEmpty()) return;
        const auto from = m_findOffset > 0 ? m_findOffset - needle.size() - 1 : -1;
        qsizetype found = backwards ? m_flatText.lastIndexOf(needle, from, Qt::CaseSensitive)
            : m_flatText.indexOf(needle, m_findOffset, Qt::CaseSensitive);
        if (found < 0) found = backwards ? m_flatText.lastIndexOf(needle, -1, Qt::CaseSensitive)
            : m_flatText.indexOf(needle, 0, Qt::CaseSensitive);
        if (found < 0) { setStatus(QStringLiteral("当前已读取文本中未找到匹配。")); return; }
        const qsizetype end = found + needle.size();
        std::optional<std::uint64_t> first;
        std::uint64_t last = 0;
        for (const auto& span : m_searchSpans)
        {
            if (span.start + span.length <= found || span.start >= end) continue;
            if (!first.has_value()) first = span.address;
            last = span.address + span.byteLength - 1;
        }
        if (first.has_value()) m_canvas->selectRange(*first, last);
        m_findOffset = end;
    }
    bool WorkbenchTextView::eventFilter(QObject* watched, QEvent* event)
    {
        const auto* widget = qobject_cast<QWidget*>(watched);
        const bool structuredChild = widget != nullptr && m_structuredView != nullptr
            && (widget == m_structuredView || m_structuredView->isAncestorOf(widget));
        if ((watched == m_canvas || watched == m_findEdit || structuredChild) && event->type() == QEvent::ShortcutOverride)
        {
            const auto* key = static_cast<QKeyEvent*>(event);
            if ((key->key() == Qt::Key_F && key->modifiers() == Qt::ControlModifier) || key->key() == Qt::Key_F3
                || ((watched == m_canvas || structuredChild) && key->key() == Qt::Key_C && (key->modifiers() & Qt::ControlModifier)))
            { event->accept(); return true; }
        }
        if ((watched == m_canvas || watched == m_findEdit || structuredChild) && event->type() == QEvent::KeyPress)
        {
            const auto* key = static_cast<QKeyEvent*>(event);
            if (key->key() == Qt::Key_F && key->modifiers() == Qt::ControlModifier)
            { openFind(); return true; }
            if (key->key() == Qt::Key_F3) { if (key->modifiers() & Qt::ShiftModifier) findPrevious(); else findNext(); return true; }
            if (watched == m_canvas && key->key() == Qt::Key_C && key->modifiers() == Qt::ControlModifier)
            { QApplication::clipboard()->setText(selectedDecodedText()); return true; }
            if (structuredChild && key->key() == Qt::Key_C && key->modifiers() == Qt::ControlModifier)
            { QApplication::clipboard()->setText(copyTextForCurrentView()); return true; }
        }
        return QWidget::eventFilter(watched, event);
    }
    bool WorkbenchTextView::event(QEvent* event)
    {
        if (event->type() == QEvent::ShortcutOverride || event->type() == QEvent::KeyPress)
        {
            const auto* key = static_cast<QKeyEvent*>(event);
            const bool find = key->key() == Qt::Key_F && key->modifiers() == Qt::ControlModifier;
            const bool next = key->key() == Qt::Key_F3;
            const bool copy = key->key() == Qt::Key_C && key->modifiers() == Qt::ControlModifier;
            if (find || next || copy)
            {
                event->accept();
                if (event->type() == QEvent::KeyPress)
                {
                    if (find) openFind();
                    else if (next) { if (key->modifiers() & Qt::ShiftModifier) findPrevious(); else findNext(); }
                    else QApplication::clipboard()->setText(copyTextForCurrentView());
                }
                return true;
            }
        }
        return QWidget::event(event);
    }
    void WorkbenchTextView::showContextMenu(const QPoint& point)
    {
        const auto address = m_canvas->addressAt(point);
        if (!address.has_value()) return;
        if (!m_canvas->selectedRange().has_value()
            || *address < m_canvas->selectedRange()->first || *address > m_canvas->selectedRange()->second)
            m_canvas->selectRange(*address, *address, false);
        const QString text = selectedDecodedText();
        bool complete = false;
        const QByteArray bytes = m_canvas->selectedBytes(&complete);
        auto* menu = new QMenu(this);
        menu->setStyleSheet(KswordTheme::ContextMenuStyle());
        auto* copyText = menu->addAction(QStringLiteral("复制文本"));
        auto* copyBytes = menu->addAction(QStringLiteral("复制原始字节"));
        copyBytes->setEnabled(complete);
        auto* copyAddress = menu->addAction(QStringLiteral("复制地址"));
        auto* locate = menu->addAction(QStringLiteral("在十六进制视图中定位"));
        const QPointer<WorkbenchTextView> self(this);
        emit contextMenuAboutToShow(menu, *address, complete);
        if (!self) return;
        QAction* selected = menu->exec(m_canvas->viewport()->mapToGlobal(point));
        if (!self) return;
        menu->deleteLater();
        if (selected == copyText) QApplication::clipboard()->setText(text);
        else if (selected == copyBytes && complete) QApplication::clipboard()->setText(QString::fromLatin1(bytes.toHex(' ').toUpper()));
        else if (selected == copyAddress) QApplication::clipboard()->setText(QStringLiteral("0x%1").arg(QString::number(*address, 16).toUpper()));
        else if (selected == locate) emit requestHexLocate(*address);
    }
}
