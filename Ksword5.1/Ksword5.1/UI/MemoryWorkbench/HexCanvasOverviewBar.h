#pragma once

// A cache-only overview beside the existing vertical scrollbar. All positions
// are HexViewport projected rows; the native scrollbar remains the scroll owner.
#include "HexCanvas.h"
#include "../../theme.h"
#include "../../Internationalization/LanguageManager.h"
#include <QImage>
#include <QMouseEvent>
#include <QPainter>
#include <QPointer>
#include <QScrollBar>
#include <QWheelEvent>
#include <algorithm>
#include <cmath>

namespace ks::ui
{
    class HexCanvasOverviewBar final : public QWidget
    {
    public:
        static constexpr int kWidth = 25; // Professional viewport rail, logical pixels.
        explicit HexCanvasOverviewBar(HexCanvas* canvas) : QWidget(canvas), canvas_(canvas), bar_(canvas->verticalScrollBar())
        {
            setObjectName(QStringLiteral("memwb_hex_overview"));
            setAttribute(Qt::WA_OpaquePaintEvent);
            setAccessibleName(ks::i18n::sourceText(QStringLiteral("内存概览")));
            setToolTip(ks::i18n::sourceText(QStringLiteral("白色表示未知；已读字节显示淡主题色，非零字节更深，可显示 ASCII 字符越多颜色越深。点击定位，拖动滚动。")));
        }

        QRectF stripRect() const { return QRectF(1, 1, std::max(0, width() - 2), std::max(0, height() - 2)); }
        std::uint64_t rowAtPixel(int y) const
        {
            if (!canvas_->m_hasSpace) return 0;
            const auto strip = stripRect();
            const int extent = std::max(1, static_cast<int>(strip.height()));
            const int pixel = std::clamp(y - static_cast<int>(strip.top()), 0, extent - 1);
            return std::min(canvas_->m_viewport.OverviewRowAt(static_cast<std::uint32_t>(pixel), static_cast<std::uint32_t>(extent)),
                canvas_->m_viewport.RowCount() - 1);
        }
        qreal rowPosition(std::uint64_t row) const
        {
            const auto rows = canvas_->m_hasSpace ? canvas_->m_viewport.RowCount() : 0;
            const auto strip = stripRect();
            return strip.top() + (rows ? static_cast<qreal>(static_cast<long double>(std::min(row, rows)) / rows) * strip.height() : 0);
        }
        QRectF viewportOutline() const
        {
            if (!canvas_->m_hasSpace) return {};
            const auto rows = canvas_->m_viewport.RowCount();
            const auto first = std::min(canvas_->m_firstRow, rows - 1);
            const auto end = first + std::min(canvas_->fullVisibleRows(), rows - first);
            const auto strip = stripRect();
            if (strip.isEmpty()) return {};
            const qreal height = std::min(strip.height(), std::max<qreal>(2, rowPosition(end) - rowPosition(first)));
            const qreal top = std::clamp(rowPosition(first), strip.top(), strip.bottom() - height);
            return QRectF(0.5, top, width() - 1.0, height);
        }
        qreal caretPosition() const
        {
            if (!canvas_->m_hasSpace) return -1;
            const auto row = canvas_->m_viewport.RowOfAddress(canvas_->caretAddress());
            if (!row) return -1;
            return (rowPosition(*row) + rowPosition(*row + 1)) / 2;
        }
        std::uint64_t summaryBuildCount() const { return summaryBuilds_; }

    protected:
        void paintEvent(QPaintEvent*) override
        {
            prepareImage();
            QPainter painter(this);
            painter.drawImage(QPoint(0,0), image_);
            if (!canvas_->m_hasSpace) return;
            // Neutral double outline stays legible on white, tinted and dark segments.
            const auto outline = viewportOutline();
            const auto ink = KswordTheme::EnsureTextContrast(KswordTheme::TextPrimaryColor(), Qt::white, 4.5);
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(ink, 2)); painter.drawRect(outline);
            painter.setPen(QPen(Qt::white, 1)); painter.drawRect(outline);
            const auto caret = caretPosition();
            if (caret >= 0) {
                painter.setPen(QPen(ink, 3)); painter.drawLine(QPointF(0, caret), QPointF(3, caret));
                painter.setPen(QPen(Qt::white, 1)); painter.drawLine(QPointF(0, caret), QPointF(3, caret));
            }
        }
        void mousePressEvent(QMouseEvent* event) override
        {
            if (event->button() != Qt::LeftButton || !canvas_->m_hasSpace || !bar_) { event->ignore(); return; }
            const auto row = rowAtPixel(static_cast<int>(event->position().y()));
            dragOffset_ = viewportOutline().contains(event->position())
                ? row - std::min(row, canvas_->m_firstRow) : canvas_->fullVisibleRows() / 2;
            dragRevision_ = canvas_->sourceRevision();
            dragging_ = true;
            const QPointer<HexCanvasOverviewBar> alive(this);
            bar_->setSliderDown(true);
            if (alive) canvas_->scrollOverviewToRow(row - std::min(row, dragOffset_));
            event->accept();
        }
        void mouseMoveEvent(QMouseEvent* event) override
        {
            if (!dragging_) { event->ignore(); return; }
            if (canvas_->sourceRevision() != dragRevision_) { stopDrag(); event->accept(); return; }
            const auto row = rowAtPixel(static_cast<int>(event->position().y()));
            canvas_->scrollOverviewToRow(row - std::min(row, dragOffset_));
            event->accept();
        }
        void mouseReleaseEvent(QMouseEvent* event) override
        {
            if (event->button() == Qt::LeftButton && dragging_) { stopDrag(); event->accept(); }
            else event->ignore();
        }
        void hideEvent(QHideEvent*) override { stopDrag(); }
        void wheelEvent(QWheelEvent* event) override { canvas_->wheelEvent(event); }

    private:
        void stopDrag()
        {
            if (!dragging_) return;
            dragging_ = false;
            if (bar_) bar_->setSliderDown(false);
        }
        void prepareImage()
        {
            const auto& model = canvas_->m_viewport;
            const auto rows = canvas_->m_hasSpace ? model.RowCount() : 0;
            const auto dpr = devicePixelRatioF();
            const auto physical = QSize(std::max(1, qRound(width() * dpr)), std::max(1, qRound(height() * dpr)));
            const auto strip = stripRect();
            const int left = std::clamp(qRound(strip.left() * dpr), 0, physical.width());
            const int right = std::clamp(qRound(strip.right() * dpr), left, physical.width());
            const int top = std::clamp(qRound(strip.top() * dpr), 0, physical.height());
            const int bottom = std::clamp(qRound(strip.bottom() * dpr), top, physical.height());
            const bool dataChanged = source_ != model.SourceRevision() || content_ != model.OverviewRevision()
                || folds_ != model.FoldRevision() || rows_ != rows || rowWidth_ != model.BytesPerRow()
                || physical_ != physical || dpr_ != dpr;
            if (dataChanged) {
                source_ = model.SourceRevision(); content_ = model.OverviewRevision(); folds_ = model.FoldRevision();
                rows_ = rows; rowWidth_ = model.BytesPerRow(); physical_ = physical;
                bins_ = rows ? model.OverviewBins(static_cast<std::size_t>(bottom - top)) : std::vector<Bin>{};
                ++summaryBuilds_;
            }
            const auto base = KswordTheme::EnsureTextContrast(KswordTheme::SurfaceMutedColor(), Qt::white, 3.0);
            const auto accent = KswordTheme::PrimaryAccentColor();
            if (!dataChanged && !image_.isNull() && base_ == base && accent_ == accent && dpr_ == dpr) return;
            base_ = base; accent_ = accent; dpr_ = dpr;
            image_ = QImage(physical, QImage::Format_ARGB32_Premultiplied);
            if (image_.isNull()) return;
            image_.setDevicePixelRatio(dpr);
            image_.fill(base);
            // Pixel-aligned vertical tiles share the same content extent as
            // clicks. Fractional antialiasing between bins would leak adjacent
            // read colors into white unknown bins (especially after eviction).
            const auto white = QColor(Qt::white).rgba();
            for (int y = top; y < bottom; ++y) {
                auto* line = reinterpret_cast<QRgb*>(image_.scanLine(y));
                std::fill(line + left, line + right, white);
            }
            if (bins_.empty() || right == left) return;
            for (std::size_t index = 0; index < bins_.size(); ++index) {
                const auto& bin = bins_[index];
                const auto count = static_cast<int>(bins_.size());
                const int y0 = top + static_cast<int>((static_cast<std::int64_t>(index) * (bottom - top) + count - 1) / count);
                const int y1 = top + static_cast<int>((static_cast<std::int64_t>(index + 1) * (bottom - top) + count - 1) / count);
                if (!bin.readBytes) continue;
                const auto known = bin.totalBytes > 0 ? std::clamp(static_cast<double>(bin.readBytes) / bin.totalBytes, 0.0, 1.0) : 0.0;
                const double knownWidth = (right - left) * known;
                const int whole = std::clamp(static_cast<int>(knownWidth), 0, right - left);
                // Leave headroom for readable text instead of saturating ordinary
                // binary data. Density is measured only among accepted read bytes;
                // the rest of this bin keeps its separate white coverage.
                const auto alpha = 0.12 + 0.16 * static_cast<double>(bin.nonZeroBytes) / static_cast<double>(bin.readBytes)
                    + 0.42 * static_cast<double>(bin.asciiBytes) / static_cast<double>(bin.readBytes);
                const auto tint = KswordTheme::BlendColors(Qt::white, accent, qRound(alpha * 255));
                const auto edge = KswordTheme::BlendColors(Qt::white, tint, qRound((knownWidth - whole) * 255));
                for (int y = y0; y < y1; ++y) {
                    auto* line = reinterpret_cast<QRgb*>(image_.scanLine(y)) + left;
                    std::fill(line, line + whole, tint.rgba());
                    if (whole < right - left) line[whole] = edge.rgba();
                }
            }
        }
        using Bin = ksword::memwb::HexViewport::OverviewBin;
        HexCanvas* canvas_;
        QPointer<QScrollBar> bar_;
        bool dragging_ = false;
        std::uint64_t dragOffset_ = 0, dragRevision_ = 0;
        std::uint64_t source_ = UINT64_MAX, content_ = UINT64_MAX, folds_ = UINT64_MAX, rows_ = UINT64_MAX;
        std::uint32_t rowWidth_ = 0;
        QSize physical_;
        qreal dpr_ = 0;
        QColor base_, accent_;
        QImage image_;
        std::vector<Bin> bins_;
        std::uint64_t summaryBuilds_ = 0;
    };
}
