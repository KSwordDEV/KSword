// HexViewWidgets.Text.cpp
// 作用：HexViewWidgets.h 里"文字型"三个控件的实现：
//   HexViewSegmented（分段按钮）、HexViewMessageLabel（单行消息）、HexViewStatusBar（状态条）。
// 图标按钮与条带底板在 HexViewWidgets.cpp。
// 约定：自绘颜色每次绘制读取；分段页签与普通内容 Tab 共用低对比填充、主题下划线及可读文字。

#include "HexViewWidgets.h"

#include "HexViewFormat.h"

#include "../../theme.h"
#include "../FlatButtonTheme.h"

#include <QEvent>
#include <QFontMetrics>
#include <QHelpEvent>
#include <QHoverEvent>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPen>
#include <QToolTip>

#include <algorithm>

namespace ks::ui
{
    namespace
    {
        // kSegmentPadding：分段按钮每段文字左右各留的内边距（像素）。
        constexpr int kSegmentPadding = 12;
    }

    // ========================= HexViewSegmented =========================

    // 构造：至少一段；Tab 可达但点击不抢焦点；开启悬停跟踪。
    HexViewSegmented::HexViewSegmented(const QStringList& labels, QWidget* parent)
        : QWidget(parent)
        , m_labels(labels.isEmpty() ? QStringList{ QString() } : labels)
    {
        // m_tips、m_disabledTips 与 m_labels 等长，初始都没有提示；m_enabled 初始每一段都可用。
        for (int index = 0; index < m_labels.size(); ++index)
        {
            m_tips.push_back(QString());
            m_disabledTips.push_back(QString());
            m_enabled.push_back(true);
        }
        setAttribute(Qt::WA_Hover, true);
        setFocusPolicy(Qt::TabFocus);
        setCursor(Qt::PointingHandCursor);
        setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    }

    // 设置某段常规提示（禁用期间不显示，重新启用后恢复）。
    void HexViewSegmented::setSegmentToolTip(int index, const QString& tip)
    {
        if (index < 0 || index >= m_tips.size())
        {
            return;
        }
        m_tips[index] = tip;
    }

    // 读取某段此刻实际显示的提示：禁用且给了原因就是原因，否则是常规提示。
    QString HexViewSegmented::segmentToolTip(int index) const
    {
        if (index < 0 || index >= m_tips.size())
        {
            return QString();
        }
        if (!m_enabled[index] && !m_disabledTips[index].isEmpty())
        {
            return m_disabledTips[index];
        }
        return m_tips[index];
    }

    // 启用或禁用某一段：只记状态与原因并重绘，不碰当前段、不发信号。
    void HexViewSegmented::setSegmentEnabled(int index, bool enabled, const QString& tooltipWhenDisabled)
    {
        if (index < 0 || index >= m_enabled.size())
        {
            return;
        }

        // newReason：禁用时记录调用方给的原因；启用时清空，避免下次禁用沿用陈旧原因。
        const QString newReason = enabled ? QString() : tooltipWhenDisabled;
        if (m_enabled[index] == enabled && m_disabledTips[index] == newReason)
        {
            return;
        }
        m_enabled[index] = enabled;
        m_disabledTips[index] = newReason;

        // 状态变化后光标可能该换（鼠标正停在这一段上），并重绘灰/非灰外观。
        refreshHoverCursor();
        update();
    }

    // 某段是否可用。
    bool HexViewSegmented::isSegmentEnabled(int index) const
    {
        if (index < 0 || index >= m_enabled.size())
        {
            return false;
        }
        return m_enabled[index];
    }

    // 沿 step 方向找下一个可用段，不回绕。
    int HexViewSegmented::nextEnabledIndex(int from, int step) const
    {
        for (int index = from + step; index >= 0 && index < m_enabled.size(); index += step)
        {
            if (m_enabled[index])
            {
                return index;
            }
        }
        return -1;
    }

    // 按悬停段切换光标：禁用段是箭头，其余保持构造时设定的手形。
    void HexViewSegmented::refreshHoverCursor()
    {
        const bool overDisabled = m_hover >= 0 && m_hover < m_enabled.size() && !m_enabled[m_hover];
        setCursor(overDisabled ? Qt::ArrowCursor : Qt::PointingHandCursor);
    }

    // 当前段。
    int HexViewSegmented::currentIndex() const
    {
        return m_current;
    }

    // 切换当前段：越界忽略，值没变不发信号。
    void HexViewSegmented::setCurrentIndex(int index)
    {
        if (index < 0 || index >= m_labels.size() || index == m_current)
        {
            return;
        }
        m_current = index;
        update();
        emit currentIndexChanged(index);
    }

    // 段数。
    int HexViewSegmented::count() const
    {
        return static_cast<int>(m_labels.size());
    }

    // 某段文字。
    QString HexViewSegmented::labelAt(int index) const
    {
        if (index < 0 || index >= m_labels.size())
        {
            return QString();
        }
        return m_labels[index];
    }

    // 某段矩形：各段紧挨着，宽度 = 文字宽度 + 两侧内边距；高度铺满控件。
    QRect HexViewSegmented::segmentRect(int index) const
    {
        if (index < 0 || index >= m_labels.size())
        {
            return QRect();
        }
        const QFontMetrics metrics(font());
        int left = 0;
        for (int current = 0; current < index; ++current)
        {
            left += metrics.horizontalAdvance(m_labels[current]) + kSegmentPadding * 2;
        }
        const int width = metrics.horizontalAdvance(m_labels[index]) + kSegmentPadding * 2;
        return QRect(left, 0, width, height());
    }

    // 建议尺寸：所有段宽度之和，高度随字体。
    QSize HexViewSegmented::sizeHint() const
    {
        const QFontMetrics metrics(font());
        int width = 0;
        for (const QString& label : m_labels)
        {
            width += metrics.horizontalAdvance(label) + kSegmentPadding * 2;
        }
        return QSize(width, std::max(28, metrics.height() + 12));
    }

    // 命中测试：返回包含该点的段下标。
    int HexViewSegmented::indexAt(const QPoint& pos) const
    {
        for (int index = 0; index < m_labels.size(); ++index)
        {
            if (segmentRect(index).contains(pos))
            {
                return index;
            }
        }
        return -1;
    }

    // 绘制：保留容器表面；选中底色只混入少量主题色，并以底部细线明确当前页。
    void HexViewSegmented::paintEvent(QPaintEvent* event)
    {
        Q_UNUSED(event);
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);

        // 分段本身没有 QAbstractButton，显式以 Flat 外观调用同一纯状态配方。
        // Base 来自真实父条带的表面，不读取生产中代表强调色的 Button 角色。
        const QPalette colors = parentWidget() != nullptr ? parentWidget()->palette() : palette();
        const FlatButtonStateColors normalColors = FlatButtonColorsForState(
            colors, FlatButtonTone::Neutral, FlatButtonAppearance::Flat, FlatButtonState::Normal);
        const QRectF outer = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
        const QColor accent = KswordTheme::ControlAccentColor(); // 页签强调来自当前主题。
        const QColor selectedBackground = KswordTheme::BlendColors(normalColors.background, accent, 38);
        const QColor hoverBackground = KswordTheme::BlendColors(normalColors.background, accent, 18);
        painter.setPen(Qt::NoPen);
        painter.setBrush(normalColors.background); // 容器保留原表面底，各段常态不重复覆盖它。
        painter.drawRoundedRect(outer, 5.0, 5.0);

        // 逐段画底与文字：先裁剪到外框圆角，避免首尾段的底色溢出圆角。
        QPainterPath clip;
        clip.addRoundedRect(outer, 5.0, 5.0);
        painter.save();
        painter.setClipPath(clip);
        for (int index = 0; index < m_labels.size(); ++index)
        {
            const QRect segment = segmentRect(index);
            const bool selected = (index == m_current);
            // segmentEnabled：这一段是否可用；整个控件被禁用或这一段被单独禁用，都按"禁用段"绘制。
            const bool segmentEnabled = isEnabled() && m_enabled[index];
            // 禁用段不画悬停高亮：它点不了，高亮会误导成"可点"。
            const bool hovered = (index == m_hover) && segmentEnabled;

            // 禁用段继续使用共享禁用文字，正常/悬停/选中都按实际填充校准对比度。
            const QColor background = segmentEnabled && selected ? selectedBackground
                : segmentEnabled && hovered ? hoverBackground : normalColors.background;
            const FlatButtonStateColors disabledColors = FlatButtonColorsForState(
                colors, FlatButtonTone::Neutral, FlatButtonAppearance::Flat, FlatButtonState::Disabled);
            if (segmentEnabled && (selected || hovered))
            {
                painter.fillRect(segment, background);
            }
            if (segmentEnabled && selected)
            {
                // 下划线与外框共享同一裁剪边界，首尾选中不会在圆角外溢出或错位。
                const QRectF underline(segment.left(), outer.bottom() - 2.0, segment.width(), 2.0);
                painter.fillRect(underline, accent);
            }
            painter.setPen(segmentEnabled
                ? KswordTheme::EnsureTextContrast(KswordTheme::TextPrimaryColor(), background, 4.5)
                : disabledColors.foreground);
            painter.drawText(segment, Qt::AlignCenter, m_labels[index]);
        }
        painter.restore();

        // 只调整自绘层次；点击命中、禁用段及键盘索引仍沿用原路由。

    }

    // 鼠标点击：命中某段就切换到它。
    void HexViewSegmented::mousePressEvent(QMouseEvent* event)
    {
        if (event->button() == Qt::LeftButton)
        {
            const int index = indexAt(event->position().toPoint());
            if (index >= 0)
            {
                // 禁用段：吞掉这次点击（不切换，也不交给父控件），原因由悬停提示说明。
                if (m_enabled[index])
                {
                    setCurrentIndex(index);
                }
                event->accept();
                return;
            }
        }
        QWidget::mousePressEvent(event);
    }

    // 键盘：左右方向键在"可用的段"之间移动（跳过禁用段，不回绕）。
    void HexViewSegmented::keyPressEvent(QKeyEvent* event)
    {
        if (event->key() == Qt::Key_Left || event->key() == Qt::Key_Right)
        {
            // step：按键方向；target：该方向上的下一个可用段，找不到就保持当前段不动。
            const int step = (event->key() == Qt::Key_Left) ? -1 : 1;
            const int target = nextEnabledIndex(m_current, step);
            if (target >= 0)
            {
                setCurrentIndex(target);
            }
            event->accept();
            return;
        }
        QWidget::keyPressEvent(event);
    }

    // 事件：逐段悬停提示与悬停段跟踪。
    bool HexViewSegmented::event(QEvent* event)
    {
        if (event->type() == QEvent::ToolTip)
        {
            // 提示只对"有提示文字的段"弹出，位置跟随该段。
            const QHelpEvent* helpEvent = static_cast<QHelpEvent*>(event);
            // shownTip：该段此刻该显示的提示（禁用段是原因，其余是常规提示）。
            const int index = indexAt(helpEvent->pos());
            const QString shownTip = segmentToolTip(index);
            if (index >= 0 && !shownTip.isEmpty())
            {
                QToolTip::showText(
                    helpEvent->globalPos(),
                    hexview_format::PlainToolTip(shownTip),
                    this,
                    segmentRect(index));
            }
            else
            {
                QToolTip::hideText();
            }
            event->accept();
            return true;
        }
        if (event->type() == QEvent::HoverMove || event->type() == QEvent::HoverEnter)
        {
            const QHoverEvent* hoverEvent = static_cast<QHoverEvent*>(event);
            const int index = indexAt(hoverEvent->position().toPoint());
            if (index != m_hover)
            {
                m_hover = index;
                // 悬停段变了：禁用段上光标变箭头，离开后恢复手形。
                refreshHoverCursor();
                update();
            }
        }
        else if (event->type() == QEvent::HoverLeave)
        {
            if (m_hover != -1)
            {
                m_hover = -1;
                refreshHoverCursor();
                update();
            }
        }
        return QWidget::event(event);
    }

    // ========================= HexViewMessageLabel =========================

    // 构造：固定一行高度，宽度由布局决定。
    HexViewMessageLabel::HexViewMessageLabel(QWidget* parent)
        : QWidget(parent)
    {
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }

    // 设置消息：空文本等同清除；全文同步为悬停提示（纯文本转义）。
    void HexViewMessageLabel::setMessage(Kind kind, const QString& text)
    {
        if (text.isEmpty())
        {
            clearMessage();
            return;
        }
        if (m_kind == kind && m_text == text)
        {
            return;
        }
        m_kind = kind;
        m_text = text;
        setToolTip(hexview_format::PlainToolTip(text));
        update();
    }

    // 清除消息。
    void HexViewMessageLabel::clearMessage()
    {
        if (m_text.isEmpty())
        {
            return;
        }
        m_kind = Kind::Hint;
        m_text.clear();
        setToolTip(QString());
        update();
    }

    // 消息文字。
    QString HexViewMessageLabel::text() const
    {
        return m_text;
    }

    // 消息种类。
    HexViewMessageLabel::Kind HexViewMessageLabel::kind() const
    {
        return m_kind;
    }

    // 建议尺寸：一行文字高度；宽度给一个够放短句的初值。
    QSize HexViewMessageLabel::sizeHint() const
    {
        const QFontMetrics metrics(font());
        return QSize(metrics.averageCharWidth() * 24, std::max(22, metrics.height() + 6));
    }

    // 最小尺寸：宽度很小，允许被布局压缩（超出部分省略）。
    QSize HexViewMessageLabel::minimumSizeHint() const
    {
        const QFontMetrics metrics(font());
        return QSize(metrics.averageCharWidth() * 6, std::max(22, metrics.height() + 6));
    }

    // 绘制：背景不画（露出条带底色），文字按种类取色并右省略。
    void HexViewMessageLabel::paintEvent(QPaintEvent* event)
    {
        Q_UNUSED(event);
        if (m_text.isEmpty())
        {
            return;
        }
        QPainter painter(this);

        // 文字色：对条带底色（SurfaceAlt）做对比度校准，语义色保证可读。
        const QColor background = KswordTheme::SurfaceAltColor();
        QColor ink = KswordTheme::TextSecondaryColor();
        switch (m_kind)
        {
        case Kind::Hint:
            ink = KswordTheme::TextSecondaryColor();
            break;
        case Kind::Info:
            ink = KswordTheme::TextPrimaryColor();
            break;
        case Kind::Warning:
            ink = KswordTheme::EnsureTextContrast(KswordTheme::WarningColor(), background);
            break;
        case Kind::Error:
            ink = KswordTheme::EnsureTextContrast(KswordTheme::ErrorColor(), background);
            break;
        }
        painter.setFont(font());
        painter.setPen(ink);
        const QFontMetrics metrics(font());
        painter.drawText(
            rect().adjusted(2, 0, -2, 0),
            Qt::AlignVCenter | Qt::AlignLeft,
            metrics.elidedText(m_text, Qt::ElideRight, std::max(0, width() - 4)));
    }

    // ========================= HexViewStatusBar =========================

    // 构造：边线画在上沿，高度固定一行。
    HexViewStatusBar::HexViewStatusBar(QWidget* parent)
        : HexViewBarFrame(Edge::Top, parent)
    {
    }

    // 三段文字的设置与读取：与旧值相同不重绘，变化后同步悬停提示。
    void HexViewStatusBar::setCaretText(const QString& text)
    {
        if (m_caretText == text)
        {
            return;
        }
        m_caretText = text;
        refreshToolTip();
        update();
    }

    void HexViewStatusBar::setSelectionText(const QString& text)
    {
        if (m_selectionText == text)
        {
            return;
        }
        m_selectionText = text;
        refreshToolTip();
        update();
    }

    void HexViewStatusBar::setRangeText(const QString& text)
    {
        if (m_rangeText == text)
        {
            return;
        }
        m_rangeText = text;
        refreshToolTip();
        update();
    }

    QString HexViewStatusBar::caretText() const
    {
        return m_caretText;
    }

    QString HexViewStatusBar::selectionText() const
    {
        return m_selectionText;
    }

    QString HexViewStatusBar::rangeText() const
    {
        return m_rangeText;
    }

    // 显示瞬时消息：空文本等同清除。
    void HexViewStatusBar::setMessage(Kind kind, const QString& text)
    {
        if (text.isEmpty())
        {
            clearMessage();
            return;
        }
        m_messageKind = kind;
        m_message = text;
        refreshToolTip();
        update();
    }

    // 清除瞬时消息。
    void HexViewStatusBar::clearMessage()
    {
        if (m_message.isEmpty())
        {
            return;
        }
        m_message.clear();
        m_messageKind = Kind::Info;
        refreshToolTip();
        update();
    }

    // 是否有瞬时消息。
    bool HexViewStatusBar::hasMessage() const
    {
        return !m_message.isEmpty();
    }

    // 瞬时消息文字。
    QString HexViewStatusBar::messageText() const
    {
        return m_message;
    }

    // 瞬时消息种类。
    HexViewStatusBar::Kind HexViewStatusBar::messageKind() const
    {
        return m_messageKind;
    }

    // 建议尺寸：一行文字高度加内边距。
    QSize HexViewStatusBar::sizeHint() const
    {
        return QSize(160, std::max(22, QFontMetrics(font()).height() + 8));
    }

    // 悬停提示：有消息时是消息全文，否则是三段合并文字。
    void HexViewStatusBar::refreshToolTip()
    {
        if (!m_message.isEmpty())
        {
            setToolTip(hexview_format::PlainToolTip(m_message));
            return;
        }
        QStringList parts;
        for (const QString& part : { m_caretText, m_selectionText, m_rangeText })
        {
            if (!part.isEmpty())
            {
                parts.push_back(part);
            }
        }
        setToolTip(hexview_format::PlainToolTip(parts.join(QChar(u'\n'))));
    }

    // 绘制：底板 + 三段或瞬时消息。
    void HexViewStatusBar::paintEvent(QPaintEvent* event)
    {
        Q_UNUSED(event);
        QPainter painter(this);

        // 底色用表面色（与解释器面板的状态条一致），上沿一条边线。
        const QColor surface = KswordTheme::SurfaceColor();
        painter.fillRect(rect(), surface);
        painter.setPen(KswordTheme::BorderColor());
        painter.drawLine(0, 0, width(), 0);
        painter.setFont(font());
        const QFontMetrics metrics(font());
        const QRect textArea(10, 1, std::max(0, width() - 16), std::max(0, height() - 1));

        // 瞬时消息：替换三段；左侧色条表示种类；文字右省略。
        if (!m_message.isEmpty())
        {
            QColor ink = KswordTheme::TextPrimaryColor();
            QColor bar = KswordTheme::PrimaryAccentColor();
            if (m_messageKind == Kind::Error)
            {
                ink = KswordTheme::EnsureTextContrast(KswordTheme::ErrorColor(), surface);
                bar = ink;
            }
            else if (m_messageKind == Kind::Warning)
            {
                ink = KswordTheme::EnsureTextContrast(KswordTheme::WarningColor(), surface);
                bar = ink;
            }
            painter.fillRect(QRect(0, 1, 3, height() - 1), bar);
            painter.setPen(ink);
            painter.drawText(
                textArea,
                Qt::AlignVCenter | Qt::AlignLeft,
                metrics.elidedText(m_message, Qt::ElideRight, textArea.width()));
            return;
        }

        // 三段：依次排开，段间用竖线分隔；最后一段（范围）吃掉剩余宽度并中间省略。
        const QColor primary = KswordTheme::TextPrimaryColor();
        const QColor secondary = KswordTheme::TextSecondaryColor();
        const QColor separator = KswordTheme::BorderColor();
        int x = textArea.left();
        const QStringList segments{ m_caretText, m_selectionText, m_rangeText };
        for (int index = 0; index < segments.size(); ++index)
        {
            const QString& segment = segments[index];
            if (segment.isEmpty())
            {
                continue;
            }
            const int remaining = textArea.right() - x + 1;
            if (remaining <= 8)
            {
                break;
            }
            const QString shown = metrics.elidedText(segment, Qt::ElideMiddle, remaining);
            painter.setPen(index == 0 ? primary : secondary);
            painter.drawText(
                QRect(x, textArea.top(), remaining, textArea.height()),
                Qt::AlignVCenter | Qt::AlignLeft,
                shown);
            x += metrics.horizontalAdvance(shown) + 12;

            // 分隔线：画在段后面（最后一段之后不画，由下一段是否存在决定）。
            if (index + 1 < segments.size())
            {
                painter.setPen(separator);
                painter.drawLine(x - 6, textArea.top() + 4, x - 6, textArea.bottom() - 3);
            }
        }
    }
}
