#pragma once

#include "WorkbenchDisasmView.h"
#include "../../../../shared/evidence/memory_workbench/MemoryTextDecode.h"
#include <QWidget>
#include <QString>
#include <optional>
#include <vector>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QMenu;
class QStackedWidget;

namespace ks::ui
{
    class MemoryRowCanvas;
    class StructuredFieldView;

    // Read-only address-backed text on the same row canvas as disassembly.
    // Decode first, then lay out rows: display boundaries never split a scalar.
    class WorkbenchTextView final : public QWidget
    {
        Q_OBJECT
    public:
        using Encoding = ksword::memwb::MemoryTextEncoding;
        explicit WorkbenchTextView(QWidget* parent = nullptr);
        void setBytesProvider(IWorkbenchBytesProvider* provider);
        void setWindow(std::uint64_t address, std::uint64_t length);
        void reset();
        void setBytesPerRow(int bytesPerRow);
        int bytesPerRow() const;
        void setEncoding(Encoding encoding);
        Encoding encoding() const;
        Encoding effectiveEncoding() const;
        bool hasBom() const;
        void setAddressBits(int bits);
        void setAddressBounds(std::uint64_t first, std::uint64_t last);
        void setAddressRange(std::uint64_t base, std::uint64_t length);
        void clearAddressBounds();
        void setBytesVisible(bool visible);
        bool bytesVisible() const;
        void setWrapText(bool wrap);
        bool wrapText() const;
        void setControlCharactersVisible(bool visible);
        bool controlCharactersVisible() const;
        void refreshView();
        void openFind();
        void findPrevious();
        MemoryRowCanvas* canvas() const;
        std::optional<std::pair<std::uint64_t, std::uint64_t>> selectedByteRange() const;
        QString renderedText() const;
        QString selectedDecodedText() const;
        QString copyTextForCurrentView() const;
        std::uint64_t windowAddress() const;
        std::uint64_t windowLength() const;
        QSize minimumSizeHint() const override;
    signals:
        void selectionChanged(quint64 first, quint64 last);
        // The owner alone performs I/O and refeeds the prepared shared window.
        void windowRequested(quint64 address, quint64 length);
        void contextMenuAboutToShow(QMenu* menu, quint64 address, bool hasByte);
        void requestHexLocate(quint64 address);
    protected:
        bool event(QEvent* event) override;
        bool eventFilter(QObject* watched, QEvent* event) override;
    private:
        static constexpr std::uint64_t kMaxWindowBytes = 1024ULL * 1024ULL;
        struct SearchSpan { qsizetype start; qsizetype length; std::uint64_t address; std::uint64_t byteLength; };
        void rebuildText();
        void browseMore(int direction, int lines);
        void showContextMenu(const QPoint& point);
        void findNext();
        void findMatch(bool backwards);
        void setStatus(const QString& text);
        void updateStructuredView(bool completeDecode);
        void activateOriginalView();
        IWorkbenchBytesProvider* m_provider = nullptr;
        QComboBox* m_encodingCombo = nullptr;
        QComboBox* m_structureCombo = nullptr;
        QStackedWidget* m_viewStack = nullptr;
        StructuredFieldView* m_structuredView = nullptr;
        QCheckBox* m_bytesToggle = nullptr;
        QCheckBox* m_wrapToggle = nullptr;
        QCheckBox* m_controlToggle = nullptr;
        QLineEdit* m_findEdit = nullptr;
        QLabel* m_status = nullptr;
        MemoryRowCanvas* m_canvas = nullptr;
        QString m_renderedText;
        QString m_flatText;
        std::vector<SearchSpan> m_searchSpans;
        qsizetype m_findOffset = 0;
        std::uint64_t m_address = 0;
        std::uint64_t m_length = 0;
        std::uint64_t m_decodeOrigin = 0;
        std::optional<std::uint64_t> m_requestedAddress;
        std::optional<std::pair<std::uint64_t, std::uint64_t>> m_addressBounds;
        std::vector<std::uint64_t> m_browseBackStack;
        bool m_hasWindow = false;
        bool m_bomDetected = false;
        bool m_requestOutstanding = false;
        bool m_keepBrowseViewport = false;
        int m_bytesPerRow = 16;
        int m_addressBits = 64;
        Encoding m_encoding = Encoding::Ansi;
        Encoding m_effectiveEncoding = Encoding::Ansi;
    };

    QString DecodeTextChunkForTest(const std::vector<std::uint8_t>& bytes,
        const std::vector<std::uint8_t>& validMask, WorkbenchTextView::Encoding encoding,
        bool oddLeadingByte = false);
}
