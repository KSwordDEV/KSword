#include "BinaryOverviewBar.h"
#include "../Internationalization/LanguageManager.h"
#include "../ksword/scanner/binary_layout.h"
#include "../theme.h"
#include <QHelpEvent>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPolygonF>
#include <QToolTip>
#include <algorithm>

namespace ks::ui
{
    namespace
    {
        QString text(const char* key, const char* fallback)
        {
            return ks::i18n::text(QString::fromLatin1(key), QString::fromUtf8(fallback));
        }
        QString hex(const std::uint64_t value)
        {
            return QStringLiteral("0x%1").arg(value, 0, 16).toUpper();
        }
        QColor regionColor(const ks::scanner::BinaryRegionKind kind)
        {
            using Kind = ks::scanner::BinaryRegionKind;
            using Accent = KswordTheme::AccentRole;
            switch (kind)
            {
            case Kind::Headers: return KswordTheme::AccentColor(Accent::Slate);
            case Kind::Code: return KswordTheme::AccentColor(Accent::Blue);
            case Kind::Data: return KswordTheme::AccentColor(Accent::Green);
            case Kind::Resources: return KswordTheme::AccentColor(Accent::Purple);
            case Kind::Overlay: return KswordTheme::AccentColor(Accent::Orange);
            default: return KswordTheme::SurfaceMutedColor();
            }
        }
        QString regionName(const ks::scanner::BinaryMappedRegion& region)
        {
            if (region.kind == ks::scanner::BinaryRegionKind::Headers)
                return text("scanner.analysis.headers", "文件头");
            if (region.kind == ks::scanner::BinaryRegionKind::Overlay)
                return text("scanner.analysis.overlay", "尾部附加数据");
            return QString::fromUtf8(region.name.data(), static_cast<qsizetype>(region.name.size()));
        }
    }

    BinaryOverviewBar::BinaryOverviewBar(QWidget* parent) : QWidget(parent)
    {
        setObjectName(QStringLiteral("binary_overview_bar"));
        setFocusPolicy(Qt::StrongFocus);
        setCursor(Qt::PointingHandCursor);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        setAccessibleName(text("scanner.analysis.overview", "文件区段总览"));
    }
    QSize BinaryOverviewBar::sizeHint() const { return QSize(480, 34); }
    QSize BinaryOverviewBar::minimumSizeHint() const { return QSize(0, 34); }
    void BinaryOverviewBar::setLayout(std::shared_ptr<const ks::scanner::BinaryScanResult> layout)
    {
        m_layout = std::move(layout);
        m_currentOffset = 0;
        update();
    }
    void BinaryOverviewBar::setCurrentOffset(const std::uint64_t offset)
    {
        if (!m_layout || m_layout->fileSize == 0) return;
        m_currentOffset = std::min(offset, m_layout->fileSize - 1);
        update();
    }
    std::uint64_t BinaryOverviewBar::offsetAt(const int x) const
    {
        if (!m_layout || m_layout->fileSize == 0 || width() < 3) return 0;
        const auto fraction = static_cast<double>(std::clamp(x - 1, 0, width() - 2)) /
            static_cast<double>(width() - 2);
        return std::min(static_cast<std::uint64_t>(fraction * static_cast<double>(m_layout->fileSize)),
            m_layout->fileSize - 1);
    }
    void BinaryOverviewBar::paintEvent(QPaintEvent*)
    {
        QPainter painter(this);
        const QRectF area(1, 5, std::max(0, width() - 2), std::max(0, height() - 10));
        painter.fillRect(area, KswordTheme::SurfaceMutedColor());
        if (m_layout && m_layout->fileSize != 0)
        {
            const auto scale = area.width() / static_cast<double>(m_layout->fileSize);
            for (const auto& region : m_layout->mappedRegions)
            {
                if (region.fileSize == 0 || region.fileOffset >= m_layout->fileSize) continue;
                const auto length = std::min(region.fileSize, m_layout->fileSize - region.fileOffset);
                const QRectF segment(area.left() + static_cast<double>(region.fileOffset) * scale,
                    area.top(), static_cast<double>(length) * scale, area.height());
                const auto color = regionColor(region.kind);
                painter.fillRect(segment, color);
                painter.setPen(KswordTheme::EnsureTextContrast(KswordTheme::TextPrimaryColor(), color));
                if (segment.width() > 24)
                    painter.drawText(segment.adjusted(4, 0, -4, 0), Qt::AlignCenter,
                        fontMetrics().elidedText(regionName(region), Qt::ElideRight,
                            static_cast<int>(segment.width()) - 8));
            }
            const double markerX = area.left() + static_cast<double>(m_currentOffset) * scale;
            painter.setPen(QPen(KswordTheme::SurfaceColor(), 3));
            painter.drawLine(QPointF(markerX, 1), QPointF(markerX, height() - 1));
            painter.setPen(QPen(KswordTheme::TextPrimaryColor(), 1));
            painter.drawLine(QPointF(markerX, 1), QPointF(markerX, height() - 1));
            painter.setBrush(KswordTheme::TextPrimaryColor());
            painter.drawPolygon(QPolygonF{ QPointF(markerX - 4, 0), QPointF(markerX + 4, 0), QPointF(markerX, 5) });
        }
        painter.setPen(QPen(hasFocus() ? KswordTheme::PrimaryAccentColor() : KswordTheme::BorderColor(), 1));
        painter.setBrush(Qt::NoBrush);
        painter.drawRect(area);
    }
    QString BinaryOverviewBar::tooltipAt(const std::uint64_t offset) const
    {
        if (!m_layout) return {};
        QString name = text("scanner.analysis.unmapped", "未映射数据");
        QString detail;
        for (const auto& region : m_layout->mappedRegions)
        {
            if (offset < region.fileOffset || offset - region.fileOffset >= region.fileSize) continue;
            name = regionName(region);
            detail = text("scanner.analysis.range", "文件范围：%1 – %2（%3 字节）")
                .arg(hex(region.fileOffset), hex(region.fileOffset + region.fileSize - 1))
                .arg(region.fileSize);
            if (region.kind != ks::scanner::BinaryRegionKind::Headers && region.mapped)
            {
                QString permissions;
                if ((region.characteristics & 0x40000000U) != 0) permissions += QLatin1Char('R');
                if ((region.characteristics & 0x80000000U) != 0) permissions += QLatin1Char('W');
                if ((region.characteristics & 0x20000000U) != 0) permissions += QLatin1Char('X');
                detail += QLatin1Char('\n') + text("scanner.analysis.permissions_entropy", "权限：%1 · 熵：%2")
                    .arg(permissions.isEmpty() ? QStringLiteral("—") : permissions)
                    .arg(region.entropy, 0, 'f', 4);
                detail += QLatin1Char('\n') + text("scanner.analysis.virtual_size", "虚拟大小：%1 字节")
                    .arg(region.virtualSize);
            }
            break;
        }
        QString result = name + QLatin1Char('\n') + text("scanner.analysis.offset", "文件偏移：%1").arg(hex(offset));
        const auto rva = ks::scanner::FileOffsetToRva(*m_layout, offset);
        const auto va = ks::scanner::FileOffsetToVa(*m_layout, offset);
        if (rva && va) result += QStringLiteral("\nRVA: %1 · VA: %2").arg(hex(*rva), hex(*va));
        if (!detail.isEmpty()) result += QLatin1Char('\n') + detail;
        return result;
    }
    void BinaryOverviewBar::activate(const std::uint64_t offset)
    {
        if (!m_layout || m_layout->fileSize == 0) return;
        setCurrentOffset(offset);
        if (offsetActivated) offsetActivated(m_currentOffset);
    }
    void BinaryOverviewBar::mousePressEvent(QMouseEvent* event)
    {
        if (event->button() == Qt::LeftButton)
        {
            setFocus(Qt::MouseFocusReason);
            activate(offsetAt(static_cast<int>(event->position().x())));
            event->accept();
            return;
        }
        QWidget::mousePressEvent(event);
    }
    void BinaryOverviewBar::keyPressEvent(QKeyEvent* event)
    {
        if (!m_layout || m_layout->fileSize == 0) return QWidget::keyPressEvent(event);
        auto offset = m_currentOffset;
        const auto step = event->key() == Qt::Key_PageUp || event->key() == Qt::Key_PageDown ? 4096ULL : 16ULL;
        switch (event->key())
        {
        case Qt::Key_Left: case Qt::Key_PageUp: offset -= std::min<std::uint64_t>(offset, step); break;
        case Qt::Key_Right: case Qt::Key_PageDown: offset += std::min<std::uint64_t>(m_layout->fileSize - 1 - offset, step); break;
        case Qt::Key_Home: offset = 0; break;
        case Qt::Key_End: offset = m_layout->fileSize - 1; break;
        default: return QWidget::keyPressEvent(event);
        }
        activate(offset);
        event->accept();
    }
    bool BinaryOverviewBar::event(QEvent* event)
    {
        if (event->type() == QEvent::ToolTip)
        {
            const auto* help = static_cast<QHelpEvent*>(event);
            const auto plain = tooltipAt(offsetAt(help->pos().x()));
            QToolTip::showText(help->globalPos(), QStringLiteral("<qt>%1</qt>")
                .arg(plain.toHtmlEscaped().replace(QLatin1Char('\n'), QStringLiteral("<br/>"))), this);
            return true;
        }
        if (event->type() == QEvent::PaletteChange || event->type() == QEvent::ApplicationPaletteChange)
            update();
        return QWidget::event(event);
    }
}
