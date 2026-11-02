#include "WinAPIParameterEditor.h"
#include "../UI/FlowLayout.h"
#include "../UI/SegmentedControl.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/ThemeStatusRole.h"
#include "../theme.h"
#include <QCoreApplication>
#include <QEvent>
#include <QApplication>
#include <QDir>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTabBar>
#include <QToolButton>
#include <QMouseEvent>
#include <QTimer>
#include <QVBoxLayout>
#include <QScrollArea>
#include <QScrollBar>
#include <QPainter>
#include <QStyleOption>
#include <QStyle>

using namespace ks::monitor;
namespace {
class AllocationTabBar final : public QTabBar
{
public:
    using QTabBar::QTabBar;
    std::function<void(int)> removeClicked;
    std::function<void()> dragFinished;
protected:
    QRect visibleTabRect(int index) const {
        return tabRect(index);
    }
    QSize minimumTabSizeHint(int index) const override { return tabSizeHint(index); }
    QSize tabSizeHint(int index) const override {
        const auto data = tabData(index);
        const int width = data.metaType().id() == QMetaType::QVariantList ? data.toList().value(0).toInt() : data.toInt();
        return QSize(std::max(1, width), std::max(30, fontMetrics().height() + 12));
    }
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this); painter.setRenderHint(QPainter::Antialiasing);
        for (int i = 0; i < count(); ++i) {
            const QRect area = visibleTabRect(i); if (!area.intersects(rect())) continue;
            const bool hover = isEnabled() && i == m_hover;
            painter.setPen(Qt::NoPen);
            const QColor background = hover ? KswordTheme::SurfaceMutedColor() : KswordTheme::SurfaceAltColor();
            painter.setBrush(background);
            painter.drawRoundedRect(QRectF(area.adjusted(2, 1, -2, -1)), 5, 5);
            const QColor textColor = palette().color(isEnabled() ? QPalette::Active : QPalette::Disabled, QPalette::ButtonText);
            painter.setPen(KswordTheme::EnsureTextContrast(textColor, background));
            painter.drawText(area.adjusted(4, 0, -4, 0), Qt::AlignCenter, fontMetrics().elidedText(tabText(i), Qt::ElideRight, std::max(0, area.width() - 8)));
            QStyleOptionTab option; initStyleOption(&option, i);
            if (hasFocus() && i == currentIndex() && (option.state & QStyle::State_KeyboardFocusChange)) {
                QStyleOptionFocusRect focus; focus.initFrom(this); focus.rect = area.adjusted(4, 4, -4, -4);
                style()->drawPrimitive(QStyle::PE_FrameFocusRect, &focus, &painter, this);
            }
        }
    }
    void mousePressEvent(QMouseEvent* event) override {
        m_press = event->position().toPoint(); m_index = event->button() == Qt::LeftButton ? tabAt(m_press) : -1; m_dragged = false;
        if (m_index >= 0 && !visibleTabRect(m_index).contains(m_press)) { m_index = -1; event->ignore(); return; }
        QTabBar::mousePressEvent(event);
    }
    void mouseMoveEvent(QMouseEvent* event) override {
        int hover = tabAt(event->position().toPoint());
        if (hover >= 0 && !visibleTabRect(hover).contains(event->position().toPoint())) hover = -1;
        if (hover != m_hover) { m_hover = hover; update(); }
        if (m_index >= 0 && (event->position().toPoint() - m_press).manhattanLength() >= QApplication::startDragDistance()) m_dragged = true;
        QTabBar::mouseMoveEvent(event);
    }
    void leaveEvent(QEvent* event) override { m_hover = -1; update(); QTabBar::leaveEvent(event); }
    void mouseReleaseEvent(QMouseEvent* event) override {
        const int index = m_index; m_index = -1;
        const bool click = event->button() == Qt::LeftButton && index >= 0
            && !m_dragged && (event->position().toPoint() - m_press).manhattanLength() < QApplication::startDragDistance()
            && tabAt(event->position().toPoint()) == index && visibleTabRect(index).contains(event->position().toPoint());
        QTabBar::mouseReleaseEvent(event);
        if (click && removeClicked) removeClicked(index);
        else if (dragFinished) dragFinished();
    }
private:
    QPoint m_press; int m_index = -1; int m_hover = -1; bool m_dragged = false;
};
class AllocationRemainder final : public QLabel {
public: using QLabel::QLabel;
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this); painter.setRenderHint(QPainter::Antialiasing);
        const QColor background = KswordTheme::SurfaceAltColor();
        painter.setPen(Qt::NoPen); painter.setBrush(background);
        painter.drawRoundedRect(QRectF(rect().adjusted(2, 1, -2, -1)), 5, 5);
        painter.setPen(KswordTheme::EnsureTextContrast(palette().color(QPalette::ButtonText), background));
        painter.drawText(rect().adjusted(4, 0, -4, 0), Qt::AlignCenter, fontMetrics().elidedText(text(), Qt::ElideRight, std::max(0, width() - 8)));
    }
};
}
WinAPIParameterEditor::WinAPIParameterEditor(QWidget* parent)
    : QWidget(parent), m_rules(QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("config/winapi-param.cfg")))
{
    m_validConfig = m_rules.load();
    auto* layout = new QVBoxLayout(this); layout->setContentsMargins(0, 0, 0, 0); layout->setSpacing(6);
    auto* modeRow = new QHBoxLayout(); modeRow->setContentsMargins(0, 0, 0, 0);
    m_parameterMode = new QToolButton(this); m_parameterMode->setText(QStringLiteral("按函数参数")); m_parameterMode->setCheckable(true); m_parameterMode->setAutoExclusive(true);
    m_byteMode = new QToolButton(this); m_byteMode->setText(QStringLiteral("按连续字节")); m_byteMode->setCheckable(true); m_byteMode->setAutoExclusive(true);
    m_parameterMode->setToolTip(QStringLiteral("原始槽位不一定是有效参数；x86 快速调用的参数可能位于寄存器。"));
    m_byteMode->setToolTip(QStringLiteral("连续字节由已采集槽位按小端拼接，不读取指针指向的内存。"));
    modeRow->addWidget(m_parameterMode); modeRow->addWidget(m_byteMode);
    ks::ui::InstallSegmentedButtons(modeRow, {m_parameterMode, m_byteMode});
    modeRow->addStretch(1); layout->addLayout(modeRow);
    auto* actions = new ks::ui::FlowLayout(nullptr, 0, 8, 8); m_typeActions = actions;
    auto* prefix = new QLabel(QStringLiteral("分配"), this); prefix->setProperty("ks_type_role", -2); actions->addWidget(prefix);
    const auto addType = [this, actions](const QString& label, RawParameterType type) {
        auto* button = new QPushButton(label, this); button->setProperty("ks_type_id", static_cast<int>(type)); m_addButtons.push_back(button); actions->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this, type]() {
            auto next = m_rule; next.allocations.push_back({type, m_byteCount->value()}); persist(std::move(next));
        });
    };
    addType(QStringLiteral("char"), RawParameterType::Char);
    addType(QStringLiteral("uchar"), RawParameterType::UChar);
    addType(QStringLiteral("short"), RawParameterType::Short);
    addType(QStringLiteral("ushort"), RawParameterType::UShort);
    addType(QStringLiteral("int"), RawParameterType::Int);
    addType(QStringLiteral("uint"), RawParameterType::UInt);
    addType(QStringLiteral("long"), RawParameterType::Long);
    addType(QStringLiteral("ulong"), RawParameterType::ULong);
    addType(QStringLiteral("int64"), RawParameterType::LongLong);
    addType(QStringLiteral("uint64"), RawParameterType::ULongLong);
    addType(QStringLiteral("bool"), RawParameterType::Bool);
    addType(QStringLiteral("BOOL"), RawParameterType::WinBool);
    addType(QStringLiteral("wchar_t"), RawParameterType::WChar);
    addType(QStringLiteral("BYTE"), RawParameterType::WinByte);
    addType(QStringLiteral("WORD"), RawParameterType::WinWord);
    addType(QStringLiteral("DWORD"), RawParameterType::WinDword);
    addType(QStringLiteral("float"), RawParameterType::Float);
    addType(QStringLiteral("double"), RawParameterType::Double);
    addType(QStringLiteral("ptr"), RawParameterType::Pointer);
    addType(QStringLiteral("HANDLE"), RawParameterType::Handle);
    addType(QStringLiteral("size_t"), RawParameterType::SizeT);
    addType(QStringLiteral("byte[]"), RawParameterType::Bytes);
    m_byteCount = new QSpinBox(this); m_byteCount->setRange(1, 1024); m_byteCount->setValue(1);
    m_byteCount->setProperty("ks_type_role", -1);
    m_byteCount->setToolTip(QStringLiteral("数组长度")); actions->addWidget(m_byteCount);
    auto* undo = new QPushButton(QStringLiteral("撤销末尾分配"), this); undo->setProperty("ks_type_role", 2); m_addButtons.push_back(undo); actions->addWidget(undo);
    connect(undo, &QPushButton::clicked, this, [this]() { if (!m_rule.allocations.isEmpty()) { auto next = m_rule; next.allocations.removeLast(); persist(std::move(next)); } });
    ks::ui::NormalizeToolbarLayout(actions); layout->addLayout(actions);
    connect(m_byteCount, &QSpinBox::valueChanged, this, [this]() {
        QTimer::singleShot(0, this, [this]() { reorderTypeButtons(m_orderedSlotWidth); });
    });
    m_allocationScroll = new QScrollArea(this); m_allocationScroll->setWidgetResizable(false); m_allocationScroll->setFrameShape(QFrame::NoFrame);
    m_allocationScroll->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff); m_allocationScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_allocationScroll->setMinimumWidth(0); m_allocationScroll->viewport()->installEventFilter(this);
    m_allocationContent = new QWidget(m_allocationScroll); auto* allocationLayout = new QHBoxLayout(m_allocationContent);
    allocationLayout->setContentsMargins(0, 0, 0, 0); allocationLayout->setSpacing(0);
    auto* allocationBar = new AllocationTabBar(m_allocationContent); m_allocations = allocationBar;
    m_allocations->setMovable(true); m_allocations->setExpanding(false); m_allocations->setUsesScrollButtons(false); m_allocations->setMouseTracking(true);
    m_allocations->setToolTip(QStringLiteral("点击取消分配，拖动调整顺序")); allocationLayout->addWidget(m_allocations);
    m_remainder = new AllocationRemainder(m_allocationContent); allocationLayout->addWidget(m_remainder);
    m_allocationScroll->setWidget(m_allocationContent); layout->addWidget(m_allocationScroll);
    m_status = new QLabel(this); m_status->setWordWrap(true); layout->addWidget(m_status);
    connect(m_parameterMode, &QToolButton::clicked, this, [this]() { auto next = m_rule; next.mode = RawDecodeMode::Parameters; persist(std::move(next)); });
    connect(m_byteMode, &QToolButton::clicked, this, [this]() { auto next = m_rule; next.mode = RawDecodeMode::Bytes; persist(std::move(next)); });
    allocationBar->removeClicked = [this](int index) {
        if (index < 0 || index >= m_rule.allocations.size()) return;
        auto next = m_rule; next.allocations.removeAt(index); persist(std::move(next));
    };
    connect(m_allocations, &QTabBar::tabMoved, this, [this](int from, int to) {
        if (from < 0 || to < 0 || from >= m_rule.allocations.size() || to >= m_rule.allocations.size()) return;
        if (!m_dragDirty) { m_dragOriginal = m_rule; m_dragDirty = true; }
        m_rule.allocations.move(from, to);
    });
    allocationBar->dragFinished = [this]() {
        if (!m_dragDirty) return;
        const auto next = m_rule; const auto identity = m_key;
        m_rule = m_dragOriginal; m_dragDirty = false;
        QTimer::singleShot(0, this, [this, next, identity]() { if (m_key == identity) persist(next); });
    };
    reorderTypeButtons(8); rebuild();
}
void WinAPIParameterEditor::reorderTypeButtons(int slotWidth)
{
    if (!m_typeActions || !m_byteCount) return;
    slotWidth = slotWidth == 4 ? 4 : 8;
    if (m_orderedSlotWidth == slotWidth && m_orderedByteCount == m_byteCount->value()) return;
    m_orderedSlotWidth = slotWidth; m_orderedByteCount = m_byteCount->value();
    QList<QLayoutItem*> items; while (auto* item = m_typeActions->takeAt(0)) items.push_back(item);
    const auto width = [slotWidth, this](QLayoutItem* item) {
        const auto* widget = item->widget(); if (!widget) return 0;
        const auto role = widget->property("ks_type_role");
        if (role.isValid()) {
            if (role.toInt() < 0) return role.toInt();
            return role.toInt() == 1 ? m_byteCount->value() : 0x7fffffff;
        }
        const auto type = static_cast<RawParameterType>(widget->property("ks_type_id").toInt());
        return RawParameterWidth({type, m_byteCount->value()}, slotWidth);
    };
    std::stable_sort(items.begin(), items.end(), [&](QLayoutItem* a, QLayoutItem* b) { return width(a) < width(b); });
    for (auto* item : items) m_typeActions->addItem(item);
    m_typeActions->invalidate();
}
void WinAPIParameterEditor::setRecord(WinAPIEventRef record)
{
    const QString previousKey = m_key;
    m_record = std::move(record); m_key.clear();
    if (m_record) {
        const QString name = m_record->value.apiText; const int separator = name.indexOf(QChar('!'));
        if (separator > 0 && separator < name.size() - 1 && ParseRawParameterData(m_record->value.detailText).slotBytes)
            m_key = WinAPIParameterRules::key(name.left(separator), name.mid(separator + 1));
    }
    const auto raw = m_record ? ParseRawParameterData(m_record->value.detailText) : RawParameterData{};
    reorderTypeButtons(raw.slotBytes);
    if (m_dragDirty && m_key == previousKey) return;
    m_dragDirty = false;
    m_rule = m_key.isEmpty() ? RawParameterRule{} : m_rules.rule(m_key);
    rebuild();
}
RawDecodeResult WinAPIParameterEditor::decoded() const
{
    return m_record ? DecodeRawParameters(ParseRawParameterData(m_record->value.detailText), m_rule.allocations, m_rule.mode) : RawDecodeResult{};
}
void WinAPIParameterEditor::persist(RawParameterRule next)
{
    if (!m_validConfig || m_key.isEmpty()) return;
    if (!m_rules.saveRule(m_key, next)) {
        rebuild();
        m_status->setText(QStringLiteral("参数规则保存失败，请检查 config 目录权限。"));
        ks::ui::ApplyStatusRole(m_status, ks::ui::StatusRole::Error); return;
    }
    m_rule = std::move(next); rebuild(); if (changed) changed();
}
void WinAPIParameterEditor::rebuild()
{
    const QSignalBlocker tabsBlock(m_allocations), parameterBlock(m_parameterMode), byteBlock(m_byteMode);
    m_parameterMode->setChecked(m_rule.mode == RawDecodeMode::Parameters); m_byteMode->setChecked(m_rule.mode == RawDecodeMode::Bytes);
    while (m_allocations->count()) m_allocations->removeTab(0);
    for (const auto& item : m_rule.allocations) {
        QString name;
        switch (item.type) {
        case RawParameterType::Int: name = QStringLiteral("int"); break;
        case RawParameterType::Char: name = QStringLiteral("char"); break;
        case RawParameterType::Bool: name = QStringLiteral("bool"); break;
        case RawParameterType::LongLong: name = QStringLiteral("int64"); break;
        case RawParameterType::UChar: name = QStringLiteral("uchar"); break;
        case RawParameterType::Short: name = QStringLiteral("short"); break;
        case RawParameterType::UShort: name = QStringLiteral("ushort"); break;
        case RawParameterType::UInt: name = QStringLiteral("uint"); break;
        case RawParameterType::ULongLong: name = QStringLiteral("uint64"); break;
        case RawParameterType::Float: name = QStringLiteral("float"); break;
        case RawParameterType::Double: name = QStringLiteral("double"); break;
        case RawParameterType::Pointer: name = QStringLiteral("ptr"); break;
        case RawParameterType::WChar: name = QStringLiteral("wchar_t"); break;
        case RawParameterType::WinBool: name = QStringLiteral("BOOL"); break;
        case RawParameterType::Long: name = QStringLiteral("long"); break;
        case RawParameterType::ULong: name = QStringLiteral("ulong"); break;
        case RawParameterType::WinByte: name = QStringLiteral("BYTE"); break;
        case RawParameterType::WinWord: name = QStringLiteral("WORD"); break;
        case RawParameterType::WinDword: name = QStringLiteral("DWORD"); break;
        case RawParameterType::Handle: name = QStringLiteral("HANDLE"); break;
        case RawParameterType::SizeT: name = QStringLiteral("size_t"); break;
        case RawParameterType::Bytes: name = QStringLiteral("byte[%1]").arg(item.length); break;
        }
        if (item.type != RawParameterType::Bytes && item.length > 1) name += QStringLiteral("[%1]").arg(item.length);
        m_allocations->addTab(name);
    }
    resizeAllocationBar();
    const bool enabled = m_validConfig && !m_key.isEmpty();
    m_parameterMode->setEnabled(enabled); m_byteMode->setEnabled(enabled);
    m_byteCount->setEnabled(enabled); m_allocations->setEnabled(enabled);
    for (auto* button : m_addButtons) button->setEnabled(enabled);
    m_status->setText(m_validConfig ? QStringLiteral("点击取消分配，拖动调整顺序") : QStringLiteral("参数规则文件无法读取，已停用编辑以保护原文件。"));
    ks::ui::ApplyStatusRole(m_status, m_validConfig ? ks::ui::StatusRole::Idle : ks::ui::StatusRole::Error);
}

bool WinAPIParameterEditor::eventFilter(QObject* watched, QEvent* event)
{
    if (m_allocationScroll && watched == m_allocationScroll->viewport() && event->type() == QEvent::Resize)
        resizeAllocationBar();
    return QWidget::eventFilter(watched, event);
}
void WinAPIParameterEditor::resizeAllocationBar()
{
    if (!m_allocationScroll || !m_allocations || !m_remainder || !m_allocationContent) return;
    const auto raw = m_record ? ParseRawParameterData(m_record->value.detailText) : RawParameterData{};
    const int slot = raw.slotBytes == 4 ? 4 : 8;
    QVector<int> weights, minimums;
    for (int i = 0; i < m_rule.allocations.size(); ++i) {
        const int bytes = RawParameterWidth(m_rule.allocations[i], slot);
        // Display the type's actual size; ABI padding still applies to decoding.
        weights.push_back(std::max(1, bytes));
        minimums.push_back(m_allocations->fontMetrics().horizontalAdvance(m_allocations->tabText(i)) + 16);
    }
    const auto decodedData = decoded();
    const int remainingBytes = static_cast<int>(decodedData.unallocated.size());
    const QString remainingLabel = QStringLiteral("byte[%1]").arg(remainingBytes);
    if (remainingBytes > 0) {
        weights.push_back(remainingBytes);
        minimums.push_back(m_remainder->fontMetrics().horizontalAdvance(remainingLabel) + 16);
    }
    const int available = std::max(0, m_allocationScroll->viewport()->width());
    const auto widths = FitRawAllocationWidths(weights, minimums, available);
    const int barHeight = std::max(30, m_allocations->fontMetrics().height() + 12);
    int allocatedWidth = 0;
    for (int i = 0; i < m_allocations->count(); ++i) {
        m_allocations->setTabData(i, widths.value(i));
        const bool availableData = i < decodedData.values.size() && decodedData.values[i].available;
        m_allocations->setTabToolTip(i, availableData ? m_allocations->tabText(i)
            : m_allocations->tabText(i) + QStringLiteral(" — ") + QStringLiteral("数据不足"));
        allocatedWidth += widths.value(i);
    }
    const int remainingWidth = remainingBytes > 0 ? widths.value(m_allocations->count()) : 0;
    // QTabBar caches tab geometries when data changes. Force it to recalculate
    // with the new per-tab hints even when the overall width did not change.
    m_allocations->setFixedWidth(0);
    m_allocations->setFixedSize(allocatedWidth, barHeight);
    m_remainder->setText(remainingLabel);
    m_remainder->setFixedSize(remainingWidth, barHeight); m_remainder->setVisible(remainingWidth > 0);
    m_allocationContent->setFixedSize(allocatedWidth + remainingWidth, barHeight);
    const int scrollHeight = allocatedWidth + remainingWidth > available
        ? m_allocationScroll->horizontalScrollBar()->sizeHint().height() : 0;
    m_allocationScroll->setFixedHeight(barHeight + scrollHeight);
}
