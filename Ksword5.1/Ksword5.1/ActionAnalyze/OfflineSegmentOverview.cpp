#include "OfflineSegmentOverview.h"
#include "LiveEtwCapture.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/FlowLayout.h"
#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ResultTableHost.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QAbstractTableModel>
#include <QCheckBox>
#include <QEvent>
#include <QFocusEvent>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMouseEvent>
#include <QPainter>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSplitter>
#include <QVBoxLayout>
#include <algorithm>
#include <functional>
#include <limits>

namespace ks::action_analyze
{
namespace
{
    using ks::i18n::sourceText;

    // 创建可复制的普通文本标签，归档路径始终按文本显示。
    QLabel* EvidenceLabel(QWidget* parent)
    {
        auto* label = new QLabel(parent); // 状态或来源说明。
        label->setWordWrap(true);
        label->setTextFormat(Qt::PlainText);
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        return label;
    }

    // 为明确无来源的字段返回缺失标记，保留合法的零值。
    template<class Number>
    QString EvidenceNumber(const std::optional<Number>& value)
    {
        return value ? QString::number(static_cast<qulonglong>(*value)) : QStringLiteral("—");
    }

    // 用记录正文的种类编号，或用记录头的实际类型标识一行。
    QString RowLabel(const SegmentRow& row)
    {
        if (row.archivedApi)
        {
            return row.archivedApi->api;
        }
        if (row.liveEtw)
        {
            return sourceText(QStringLiteral("ETW 事件 %1 / v%2")).arg(row.liveEtw->eventId).arg(row.liveEtw->version);
        }
        if (row.liveProcess)
        {
            return sourceText(QStringLiteral("进程活动分析"));
        }
        if (row.network)
        {
            return sourceText(QStringLiteral("网络通信记录"));
        }
        if (row.eventKind)
        {
            return sourceText(QStringLiteral("事件种类 %1")).arg(*row.eventKind);
        }
        if (row.type == 3 && row.version == 1 && row.decoded)
        {
            return sourceText(QStringLiteral("原始记录"));
        }
        return sourceText(QStringLiteral("未解释记录 %1 / v%2")).arg(row.type).arg(row.version);
    }

    // 只接受十进制 u64。空输入表示该端点未限定。
    bool ParseBound(const QString& text, std::optional<quint64>& bound)
    {
        if (text.isEmpty())
        {
            bound.reset();
            return true;
        }
        for (const auto character : text) // 检查每个输入字符，拒绝符号和非十进制格式。
        {
            if (character < u'0' || character > u'9')
            {
                return false;
            }
        }
        bool valid = false; // Qt 返回的转换与溢出结果。
        bound = text.toULongLong(&valid);
        return valid;
    }

    // 仅用真实字段匹配关键字，缺失占位符不属于归档内容。
    template<class Number>
    bool MatchesNumber(const std::optional<Number>& value, const QString& keyword)
    {
        return value && EvidenceNumber(value).contains(keyword);
    }

    // 映射文件回执；失败位置由调用者附在文本后。
    QString EndText(SegmentEnd result)
    {
        switch (result)
        {
        case SegmentEnd::Complete:
            return sourceText(QStringLiteral("归档已读至文件末尾。"));
        case SegmentEnd::Truncated:
            return sourceText(QStringLiteral("归档尾部不完整。"));
        case SegmentEnd::Invalid:
            return sourceText(QStringLiteral("归档封装或记录校验失败。"));
        case SegmentEnd::Unsupported:
            return sourceText(QStringLiteral("归档版本、编码或必需记录不受支持。"));
        case SegmentEnd::PreviewLimit:
            return sourceText(QStringLiteral("已达到离线预览上限。"));
        case SegmentEnd::Canceled:
            return sourceText(QStringLiteral("已取消读取。"));
        case SegmentEnd::Unavailable:
            return sourceText(QStringLiteral("无法读取归档文件。"));
        case SegmentEnd::WrongSample:
            return sourceText(QStringLiteral("归档文件与所选项目或采样不匹配。"));
        case SegmentEnd::InvalidCheckpoint:
            return sourceText(QStringLiteral("无法验证项目检查点或其引用的归档数据。"));
        case SegmentEnd::IncompleteSample:
            return sourceText(QStringLiteral("归档尚未发布有效终段。"));
        }
        return {};
    }
}

// 表格只保存归档行索引。共享引用使过滤和换代无需复制原始数据。
class SegmentTableModel final : public QAbstractTableModel
{
public:
    using QAbstractTableModel::QAbstractTableModel;

    // model 接收展平的真实行，根层返回当前结果的行数及固定列数。
    int rowCount(const QModelIndex& parent = {}) const override
    {
        return parent.isValid() ? 0 : static_cast<int>(m_indices.size());
    }

    int columnCount(const QModelIndex& parent = {}) const override
    {
        return parent.isValid() ? 0 : 5;
    }

    // 将指定单元格映射到冻结行。进程列只显示真正可证实的名称。
    QVariant data(const QModelIndex& index, int role) const override
    {
        const auto* row = at(index.row()); // 该视图行对应的归档记录。
        if (!index.isValid() || !row || role != Qt::DisplayRole)
        {
            return {};
        }
        switch (index.column())
        {
        case 0:
            return EvidenceNumber(row->receiveQpc);
        case 1:
            return EvidenceNumber(row->pid);
        case 2:
            return EvidenceNumber(row->tid);
        case 3:
            return QStringLiteral("—");
        case 4:
            return RowLabel(*row);
        default:
            return {};
        }
    }

    // 给 Qt 返回表头文本。轴列准确注明此段内使用的时钟域。
    QVariant headerData(int section, Qt::Orientation direction, int role) const override
    {
        if (direction == Qt::Horizontal && role == Qt::DisplayRole)
        {
            switch (section)
            {
            case 0:
                return sourceText(QStringLiteral("接收 QPC"));
            case 1:
                return QStringLiteral("PID");
            case 2:
                return QStringLiteral("TID");
            case 3:
                return sourceText(QStringLiteral("进程"));
            case 4:
                return sourceText(QStringLiteral("事件"));
            }
        }
        return QAbstractTableModel::headerData(section, direction, role);
    }

    // 通过模型事务替换可见索引；调用方在提交后恢复原锚点。
    void replace(std::shared_ptr<const SegmentSnapshot> snapshot, QList<qsizetype> indices)
    {
        beginResetModel();
        m_snapshot = std::move(snapshot);
        m_indices = std::move(indices);
        endResetModel();
    }

    // 返回视图行绑定的记录，超出当前范围时返回 nullptr。
    const SegmentRow* at(int row) const
    {
        return m_snapshot && row >= 0 && row < m_indices.size() ? &m_snapshot->rows.at(m_indices.at(row)) : nullptr;
    }

    // 在显示范围内按段内稳定序号定位行，找不到返回无效索引。
    QModelIndex locate(quint64 sequence) const
    {
        for (int row = 0; row < rowCount(); ++row) // 只遍历受配额限制的视图行。
        {
            if (at(row)->sequence == sequence)
            {
                return index(row, 0);
            }
        }
        return {};
    }

    // 语言变更仅通知表头与可见行文案，保持当前模型和选择。
    void retranslate()
    {
        emit headerDataChanged(Qt::Horizontal, 0, 4);
        if (rowCount())
        {
            emit dataChanged(index(0, 4), index(rowCount() - 1, 4), {Qt::DisplayRole});
        }
    }

private:
    std::shared_ptr<const SegmentSnapshot> m_snapshot; // 归档的整份只读投影。
    QList<qsizetype> m_indices; // 当前显示的源行号，按段内记录顺序。
};

// 以真实 QPC 为纵轴，类别或确知的网络记录为泳道。无 QPC 的记录在表中访问。
class SegmentWaterfall final : public QWidget
{
public:
    // 使用原生焦点和当前面板 palette，输入回调只影响本页显示。
    explicit SegmentWaterfall(QWidget* parent) : QWidget(parent)
    {
        setFocusPolicy(Qt::StrongFocus);
        setMinimumHeight(105);
        setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    }

    // 更新段内稳定刻度、可见记录与实际类别，保留表格同一个选中锚。
    void setRows(const SegmentSnapshot* segment, const SegmentTableModel& model,
        std::optional<quint64> selected)
    {
        m_rows.clear();
        m_lanes.clear();
        m_min.reset();
        m_max.reset();
        m_selected = selected;
        for (const auto& row : segment->rows) // 轴范围来自整份预览，过滤不重定位轴。
        {
            if (row.receiveQpc && (row.category || row.network || row.liveEtw || row.liveProcess))
            {
                const quint64 time = *row.receiveQpc; // 记录内的真实接收时间。
                m_min = m_min ? std::min(*m_min, time) : time;
                m_max = m_max ? std::max(*m_max, time) : time;
                m_lanes.append(laneKey(row));
            }
        }
        std::sort(m_lanes.begin(), m_lanes.end());
        m_lanes.erase(std::unique(m_lanes.begin(), m_lanes.end()), m_lanes.end());
        for (int index = 0; index < model.rowCount(); ++index) // 保持过滤范围与表一致。
        {
            const auto* row = model.at(index); // 该表行在 segment 中保持有效。
            if (row->receiveQpc && (row->category || row->network || row->liveEtw || row->liveProcess))
            {
                m_rows.append({*row->receiveQpc, laneKey(*row), row->sequence});
            }
        }
        // 同 tick 按段内序号排列，键盘逐记录定位时不会跳步。
        std::stable_sort(m_rows.begin(), m_rows.end(), [](const Mark& left, const Mark& right) {
            return left.time < right.time;
        });
        setEnabled(m_min.has_value());
        update();
    }

    // 表格选中后只重画同一记录，保持原 QPC 轴和可见窗口。
    void setSelected(std::optional<quint64> sequence)
    {
        m_selected = sequence;
        update();
    }

    // 拖动期间不得替换用于像素到时间转换的轴范围。
    bool isDragging() const { return m_dragging; }

    std::function<void(quint64)> pick; // 点击或键盘定位后的稳定序号。
    std::function<void(quint64, std::optional<quint64>)> range; // 半开 [起点, 终点) 回调。

protected:
    // 绘制固定刻度与时间点，聚合显示仅限制可见泳道数。
    void paintEvent(QPaintEvent*) override
    {
        QPainter painter(this); // 当前面板的绘制上下文。
        if (!m_min)
        {
            return;
        }
        const auto ink = palette().color(QPalette::Text); // 继承窗口文字角色。
        const auto accent = palette().color(QPalette::Highlight); // 主题强调色。
        const auto axis = plot(); // 留出首末原始 tick 的标签位置。
        painter.setPen(ink);
        painter.drawText(rect().adjusted(0, 0, 0, -3), Qt::AlignLeft | Qt::AlignTop, QString::number(*m_min));
        painter.drawText(rect().adjusted(0, 3, 0, 0), Qt::AlignLeft | Qt::AlignBottom, QString::number(*m_max));
        if (m_dragging)
        {
            QColor fill = accent; // 范围草稿使用半透明主题强调色。
            fill.setAlpha(50);
            const QRect band(QPoint(axis.left(), m_origin.y()), QPoint(axis.right(), m_cursor.y()));
            painter.fillRect(band.normalized().intersected(axis), fill);
        }
        painter.setPen(palette().color(QPalette::Mid));
        for (int lane = 0; lane < laneCount(); ++lane) // 固定泳道仅为显示引导。
        {
            const int x = laneX(lane); // 此泳道的水平坐标。
            painter.drawLine(x, axis.top(), x, axis.bottom());
        }
        std::optional<QPoint> selected; // 选中点最后绘制，避免同 tick 覆盖。
        for (const auto& row : m_rows)
        {
            const auto position = markPosition(row); // 真实 QPC 和类别映射。
            if (m_selected == row.sequence)
            {
                selected = position;
            }
            painter.setPen(QPen(ink, 2));
            painter.drawLine(position.x() - 3, position.y(), position.x() + 3, position.y());
        }
        if (selected)
        {
            painter.setPen(QPen(accent, 2));
            painter.drawEllipse(*selected, 5, 5);
        }
        if (hasFocus() && m_keyboardFocus)
        {
            painter.setPen(QPen(ink, 1, Qt::DotLine));
            painter.drawRect(rect().adjusted(0, 0, -1, -1));
        }
    }

    // 开始显示范围草稿，鼠标只在有效数据的绘图区捕获输入。
    void mousePressEvent(QMouseEvent* event) override
    {
        m_keyboardFocus = false;
        if (m_min && event->button() == Qt::LeftButton && plot().contains(event->position().toPoint()))
        {
            m_cursor = m_origin = event->position().toPoint();
            m_dragging = true;
            update();
        }
    }

    // 拖动只预览，限制纵向位置在段的轴范围内。
    void mouseMoveEvent(QMouseEvent* event) override
    {
        if (m_dragging)
        {
            m_cursor.setY(std::clamp(event->position().toPoint().y(), plot().top(), plot().bottom()));
            update();
        }
    }

    // 点按选择最近可见记录，拖动同时支持正向及反向且提交半开区间。
    void mouseReleaseEvent(QMouseEvent* event) override
    {
        if (!m_dragging || event->button() != Qt::LeftButton)
        {
            return;
        }
        mouseMoveEvent(event);
        m_dragging = false;
        if (std::abs(m_origin.y() - m_cursor.y()) >= 4)
        {
            emitRange(tick(m_origin.y()), tick(m_cursor.y()));
        }
        else if (pick)
        {
            const auto closest = std::min_element(m_rows.cbegin(), m_rows.cend(), [this](const Mark& left, const Mark& right) {
                return (markPosition(left) - m_origin).manhattanLength() < (markPosition(right) - m_origin).manhattanLength();
            });
            if (closest != m_rows.cend() && (markPosition(*closest) - m_origin).manhattanLength() <= 12)
            {
                pick(closest->sequence);
            }
        }
        update();
    }

    // 方向键逐条访问记录，Shift 扩选，以 Enter 提交；Esc 只取消草稿。
    void keyPressEvent(QKeyEvent* event) override
    {
        m_keyboardFocus = true;
        const auto current = std::find_if(m_rows.cbegin(), m_rows.cend(), [this](const Mark& mark) {
            return m_selected == mark.sequence;
        });
        if (event->key() == Qt::Key_Escape)
        {
            m_dragging = false;
            m_keyAnchor.reset();
        }
        else if (event->key() == Qt::Key_Return && m_keyAnchor && current != m_rows.cend())
        {
            emitRange(*m_keyAnchor, current->time);
            m_keyAnchor.reset();
        }
        else if (m_rows.isEmpty() || (event->key() != Qt::Key_Up && event->key() != Qt::Key_Down))
        {
            QWidget::keyPressEvent(event);
            return;
        }
        else
        {
            const bool down = event->key() == Qt::Key_Down; // 纵轴方向。
            const auto row = current == m_rows.cend() ? 0 : current - m_rows.cbegin(); // 当前时间行。
            if ((event->modifiers() & Qt::ShiftModifier) && !m_keyAnchor)
            {
                m_keyAnchor = m_rows.at(row).time;
            }
            if (!(event->modifiers() & Qt::ShiftModifier))
            {
                m_keyAnchor.reset();
            }
            const auto next = current == m_rows.cend() ? 0 : std::clamp<qsizetype>(row + (down ? 1 : -1), 0, m_rows.size() - 1);
            if (pick)
            {
                pick(m_rows.at(next).sequence);
            }
        }
        update();
    }

    // 键盘进入时绘出焦点，鼠标点击不显示额外焦点矩形。
    void focusInEvent(QFocusEvent* event) override
    {
        m_keyboardFocus = event->reason() != Qt::MouseFocusReason;
        QWidget::focusInEvent(event);
        update();
    }

private:
    struct Mark
    {
        quint64 time; // 接收 QPC tick。
        int lane; // 原类别编号或网络记录的独立可视泳道。
        quint64 sequence; // 可回到表格的记录序号。
    };

    // 只给网络记录一个显示位置，负值不会与归档的无符号类别编号相撞。
    static int laneKey(const SegmentRow& row)
    {
        if (row.liveEtw)
        {
            return -2;
        }
        if (row.liveProcess)
        {
            return -3;
        }
        return row.category ? static_cast<int>(*row.category) : -1;
    }

    // 返回扣除两个 tick 标签后的绘图区，或当前折叠尺寸。
    QRect plot() const
    {
        const int inset = fontMetrics().height() + 4; // 每端保留一个标签的自然高度。
        return rect().adjusted(7, inset, -7, -inset);
    }

    // 多于八类时共享最后一条泳道，类别过滤仍独立。
    int laneCount() const
    {
        return static_cast<int>(std::min<qsizetype>(8, m_lanes.size()));
    }

    // 计算指定泳道的中心。
    int laneX(int lane) const
    {
        return plot().left() + (2 * lane + 1) * plot().width() / (2 * std::max(1, laneCount()));
    }

    // 将归档记录映射到纵向时间及横向泳道；仅显示比例使用浮点。
    QPoint markPosition(const Mark& mark) const
    {
        const auto lane = std::lower_bound(m_lanes.cbegin(), m_lanes.cend(), mark.lane) - m_lanes.cbegin();
        const auto fraction = *m_min == *m_max ? 0.5 : static_cast<double>(mark.time - *m_min) / (*m_max - *m_min);
        return {laneX(std::min<int>(static_cast<int>(lane), laneCount() - 1)),
            plot().top() + qRound(fraction * std::max(0, plot().height() - 1))};
    }

    // 将拖动边界吸附到真实记录或轴端点，返回精确 u64 tick。
    quint64 tick(int y) const
    {
        quint64 result = y - plot().top() <= plot().bottom() - y ? *m_min : *m_max; // 最近轴端。
        int distance = std::min(y - plot().top(), plot().bottom() - y); // 端点像素距离。
        for (const auto& mark : m_rows)
        {
            const int delta = std::abs(markPosition(mark).y() - y); // 与候选真实记录的距离。
            if (delta < distance)
            {
                result = mark.time;
                distance = delta;
            }
        }
        return result;
    }

    // 范围包含两端命中的 tick，再转换成用户可编辑的半开区间。
    void emitRange(quint64 first, quint64 last)
    {
        const auto [low, high] = std::minmax(first, last); // 顺拖与倒拖得到相同范围。
        if (range)
        {
            range(low, high == std::numeric_limits<quint64>::max() ? std::nullopt : std::optional{high + 1});
        }
    }

    QList<Mark> m_rows; // 可见且有有效时间和类别的记录。
    QList<int> m_lanes; // 有真实时间的类别及网络记录，按泳道编号顺序。
    std::optional<quint64> m_min; // 整段预览的最小可信 tick。
    std::optional<quint64> m_max; // 整段预览的最大可信 tick。
    std::optional<quint64> m_selected; // 表与瀑布共用的选择身份。
    std::optional<quint64> m_keyAnchor; // 键盘范围的草稿起点。
    QPoint m_origin; // 鼠标拖动起点。
    QPoint m_cursor; // 鼠标拖动当前点。
    bool m_dragging = false; // 正在预览鼠标范围。
    bool m_keyboardFocus = false; // 焦点矩形只用于键盘输入。
};

// 将项目上下文之外的独立段读取、过滤与详情放在现有总览页内。
OfflineSegmentOverview::OfflineSegmentOverview(QWidget* parent) : QWidget(parent)
{
    m_read = new ks::ui::AsyncOperation(this);
    auto* layout = new QVBoxLayout(this); // 外层页框统一提供边距。
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);

    // 上排保留输入及归档操作，第二排的会话动作可以独立浮出。
    auto* header = new QWidget(this); // 采集参数与归档读入保持在总览。
    auto* controls = new ks::ui::FlowLayout(header, 8, 8, 6); // 随窗口宽度换行。
    ks::ui::StylePrimaryToolbar(header);
    m_open = new QPushButton(header);
    ks::ui::SetThemeButtonIcon(m_open, QIcon(QStringLiteral(":/Icon/process_open_folder.svg")));
    m_retry = new QPushButton(header);
    KswordTheme::ApplyStandardIconButtonMetrics(m_retry);
    ks::ui::SetThemeButtonIcon(m_retry, QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    m_cancel = new QPushButton(header);
    KswordTheme::ApplyStandardIconButtonMetrics(m_cancel);
    ks::ui::SetThemeButtonIcon(m_cancel, QIcon(QStringLiteral(":/Icon/process_stop.svg")));
    layout->addWidget(header);
    layout->addWidget(createActionToolbar());
    auto* actions = static_cast<ks::ui::FlowLayout*>(m_actionStrip->layout()); // 工具条创建的共享流式布局。
    createLiveControls(controls, actions);
    actions->addWidget(m_floatActions);
    controls->addWidget(m_open);
    controls->addWidget(m_retry);
    controls->addWidget(m_cancel);
    ks::ui::NormalizeToolbarLayout(controls);
    ks::ui::NormalizeToolbarLayout(actions);
    m_identity = EvidenceLabel(this);
    m_context = EvidenceLabel(this);
    m_status = EvidenceLabel(this);
    layout->addWidget(m_identity);
    layout->addWidget(m_context);
    layout->addWidget(m_status);

    // 下方用共享面板承载瀑布及证据表，详情分隔条可由用户调整。
    auto* vertical = new QSplitter(Qt::Vertical, this); // 上区记录，下区详情。
    auto* upper = new QSplitter(Qt::Horizontal, vertical); // 左瀑布与右表。
    upper->setChildrenCollapsible(false);
    auto* sidebar = new QWidget(upper); // 瀑布与实际类别所在的窄栏。
    auto* filter = new QVBoxLayout(sidebar); // 不压缩多选列表的内部滚动区。
    filter->setContentsMargins(8, 8, 8, 8);
    ks::ui::StylePrimaryContentPanel(sidebar, false);
    m_categoryLabel = new QLabel(sidebar);
    ks::ui::StylePrimarySectionTitle(m_categoryLabel);
    m_categories = new QListWidget(sidebar);
    m_categories->setSelectionMode(QAbstractItemView::MultiSelection);
    m_categories->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_categories->setMaximumHeight(96);
    m_categoryLabel->setBuddy(m_categories);
    filter->addWidget(m_categoryLabel);
    filter->addWidget(m_categories);
    m_timeLabel = EvidenceLabel(sidebar);
    filter->addWidget(m_timeLabel);
    m_waterfall = new SegmentWaterfall(sidebar);
    m_waterfall->setEnabled(false);
    filter->addWidget(m_waterfall, 1);

    // 时间端点由独立草稿输入明确提交，输入键和拖动共用同一过滤路径。
    auto* tablePane = new QWidget(upper); // 事件行、时间工具、当前过滤回执。
    auto* tableLayout = new QVBoxLayout(tablePane); // 保持工具与表左右对齐。
    tableLayout->setContentsMargins(0, 0, 0, 0);
    tableLayout->setSpacing(6);
    auto* quickBand = new QWidget(tablePane); // 高频筛选与附加条件入口。
    auto* quickTools = new ks::ui::FlowLayout(quickBand, 8, 8, 6); // 保留窄窗换行。
    ks::ui::StylePrimaryToolbar(quickBand);
    m_keyword = new QLineEdit(quickBand);
    m_keyword->setMaxLength(128);
    ks::ui::StyleSearchField(m_keyword);
    // 独立段的来源仅为记录声明，保留相应入口并明确未取得验证资格。
    m_apiSource = new QCheckBox(quickBand);
    m_etwSource = new QCheckBox(quickBand);
    m_apiSource->setEnabled(false);
    m_etwSource->setEnabled(false);
    m_more = new QPushButton(quickBand);
    m_more->setCheckable(true);
    m_clear = new QPushButton(quickBand);
    quickTools->addExpandingWidget(m_keyword, 155);
    quickTools->addWidget(m_apiSource);
    quickTools->addWidget(m_etwSource);
    quickTools->addWidget(m_more);
    quickTools->addWidget(m_clear);
    ks::ui::NormalizeToolbarLayout(quickTools);
    tableLayout->addWidget(quickBand);

    auto* timeBand = new QWidget(tablePane); // 时间范围工具带。
    m_timeBand = timeBand;
    auto* timeTools = new ks::ui::FlowLayout(timeBand, 8, 8, 6); // 小窗口分行。
    ks::ui::StylePrimaryToolbar(timeBand);
    m_start = new QLineEdit(timeBand);
    m_end = new QLineEdit(timeBand);
    m_startLabel = new QLabel(timeBand);
    m_endLabel = new QLabel(timeBand);
    m_startLabel->setBuddy(m_start);
    m_endLabel->setBuddy(m_end);
    m_apply = new QPushButton(timeBand);
    m_reset = new QPushButton(timeBand);
    for (auto* input : {m_start, m_end}) // 20 位无符号端点，宽度由字体度量。
    {
        input->setMaximumWidth(input->fontMetrics().horizontalAdvance(QString(20, u'0')) + 28);
    }
    timeTools->addWidget(m_startLabel);
    timeTools->addWidget(m_start);
    timeTools->addWidget(m_endLabel);
    timeTools->addWidget(m_end);
    timeTools->addWidget(m_apply);
    timeTools->addWidget(m_reset);
    ks::ui::NormalizeToolbarLayout(timeTools);
    tableLayout->addWidget(timeBand);
    timeBand->hide();
    m_filterStatus = EvidenceLabel(tablePane);
    tableLayout->addWidget(m_filterStatus);

    // 结果表走共享复制和导出，当前过滤后的显示模型是唯一可导出行集。
    m_table = new ks::ui::TableActionTableView(tablePane);
    m_model = new SegmentTableModel(m_table);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->verticalHeader()->hide();
    m_host = ks::ui::ResultTableHost::ensure(m_table);
    ks::ui::ResultTableCapabilities capabilities; // 有限记录不提供快照对比。
    capabilities.headerClickSorting = false;
    capabilities.actionBar = ks::ui::TableActionBarMode::Compact;
    m_host->bindModel(m_model, {{0, QStringLiteral("receive_qpc")}, {1, QStringLiteral("pid")},
        {2, QStringLiteral("tid")}, {3, QStringLiteral("process")}, {4, QStringLiteral("event")}}, capabilities);
    tableLayout->addWidget(m_table, 1);
    upper->setStretchFactor(0, 0);
    upper->setStretchFactor(1, 1);
    upper->setSizes({190, 680});
    vertical->addWidget(upper);

    // 关系来自未接入的字典解析；底部只放可证实的当前记录字段。
    auto* detailsPane = new QWidget(vertical); // 详情来源说明和规范字段文档。
    auto* detailsLayout = new QVBoxLayout(detailsPane); // 单一滚动责任在共享详情内。
    detailsLayout->setContentsMargins(0, 0, 0, 0);
    m_graphStatus = EvidenceLabel(detailsPane);
    detailsLayout->addWidget(m_graphStatus);
    m_details = new ks::ui::StructuredFieldView(detailsPane);
    m_details->setValueModelProjection();
    m_details->setHiddenProjectionDeferred();
    detailsLayout->addWidget(m_details, 1);
    vertical->addWidget(detailsPane);
    vertical->setSizes({390, 170});
    vertical->setStretchFactor(0, 3);
    vertical->setStretchFactor(1, 1);
    layout->addWidget(vertical, 1);
    layout->addWidget(createObjectEvidence(this));
    ks::ui::DetailLayoutRegistry::registerStructuredHost(m_table, m_details, this, vertical, upper, detailsPane);

    // 绑定归档专用动作，焦点留在用户当前使用的控件。
    connect(m_open, &QPushButton::clicked, this, &OfflineSegmentOverview::chooseSegment);
    connect(m_retry, &QPushButton::clicked, this, [this]() {
        openSegment(m_lastPath, m_lastSampleRequest, m_lastClue ? &*m_lastClue : nullptr);
    });
    connect(m_cancel, &QPushButton::clicked, this, &OfflineSegmentOverview::cancelRead);
    connect(m_apiSource, &QCheckBox::toggled, this, &OfflineSegmentOverview::applyFilters);
    connect(m_etwSource, &QCheckBox::toggled, this, &OfflineSegmentOverview::applyFilters);
    connect(m_keyword, &QLineEdit::textChanged, this, &OfflineSegmentOverview::applyFilters);
    connect(m_more, &QPushButton::toggled, m_timeBand, &QWidget::setVisible);
    connect(m_clear, &QPushButton::clicked, this, &OfflineSegmentOverview::clearFilters);
    connect(m_apply, &QPushButton::clicked, this, &OfflineSegmentOverview::applyTimeRange);
    connect(m_start, &QLineEdit::returnPressed, this, &OfflineSegmentOverview::applyTimeRange);
    connect(m_end, &QLineEdit::returnPressed, this, &OfflineSegmentOverview::applyTimeRange);
    connect(m_reset, &QPushButton::clicked, this, [this]() {
        m_start->clear();
        m_end->clear();
        applyTimeRange();
    });
    connect(m_categories, &QListWidget::itemSelectionChanged, this, [this]() {
        m_filterCategories.clear();
        for (const auto* item : m_categories->selectedItems())
        {
            m_filterCategories.insert(static_cast<quint16>(item->data(Qt::UserRole).toUInt()));
        }
        applyFilters();
    });

    // 表、时间轴和详情用同一个段内稳定序号。
    connect(m_table->selectionModel(), &QItemSelectionModel::currentChanged, this,
        [this](const QModelIndex& current, const QModelIndex&) {
            const auto* row = m_model->at(current.row()); // 当前真正存在的表行。
            if (!m_updatingSelection && row)
            {
                pauseLiveView();
                selectSequence(row->sequence, false);
            }
        });
    m_waterfall->pick = [this](quint64 sequence) {
        pauseLiveView();
        selectSequence(sequence, true);
    };
    m_waterfall->range = [this](quint64 low, std::optional<quint64> high) {
        m_start->setText(QString::number(low));
        m_end->setText(high ? QString::number(*high) : QString());
        applyTimeRange();
    };
    updateText();
    updateDetails();
}

// 关闭异步回投门禁，线程持有的请求与本窗生命周期无关。
OfflineSegmentOverview::~OfflineSegmentOverview()
{
    m_read->close();
    // 工作线程保留原生采集所有者，页面不等待 ETW 停止。
    if (m_live)
    {
        m_live->requestStop();
    }
    m_liveOperation->close();
}

// 冻结当前目录作为下次采样草稿，既有实时采样和结果不重新归属。
void OfflineSegmentOverview::setProjectContext(const ProjectSnapshot& project, const QString& sampleId,
    const QString& sampleStatus)
{
    m_projectManifest = project.manifestPath;
    m_projectRevision = project.revisionId;
    m_projectId = project.id;
    m_sampleId = sampleId;
    m_sampleStatus = sampleStatus;
    updateText();
}

// 从其它标签返回时立即补读最新投影，暂停的历史窗口继续原样保留。
void OfflineSegmentOverview::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    refreshLive();
}

// 只暂停实时窗口，不停止目标查询、来源或归档。未接管的旧表不影响新采样。
void OfflineSegmentOverview::pauseLiveView()
{
    if (m_snapshot && m_snapshot->live)
    {
        m_followingLive = false;
        updateLiveControls();
    }
}

// 界面投影回调不得在鼠标时间范围草稿期间重定位轴。
bool OfflineSegmentOverview::liveViewInteracting() const
{
    return m_waterfall->isDragging();
}

// 遇到语言变更时刷新固定文本，保留冻结数据与 Time 草稿。
void OfflineSegmentOverview::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange && m_model)
    {
        m_model->retranslate();
        if (m_snapshot)
        {
            applyFilters();
        }
        else
        {
            updateText();
            updateDetails();
        }
        // 按新语言的按钮自然宽度调整当前浮窗，保留它的拖动位置。
        fitFloatingActionToolbar();
    }
}

// 清空关键字、类别与时间；一次发布结果并恢复选择锚点。
void OfflineSegmentOverview::clearFilters()
{
    const QSignalBlocker keywordGuard(m_keyword); // 批量更新后统一刷新。
    const QSignalBlocker categoryGuard(m_categories); // 保留类别列表及键盘焦点。
    const QSignalBlocker etwGuard(m_etwSource); // 一次性应用来源条件。
    m_keyword->clear();
    m_etwSource->setChecked(false);
    m_categories->clearSelection();
    m_filterCategories.clear();
    m_objectFilter.reset();
    m_start->clear();
    m_end->clear();
    applyTimeRange();
}

// 只列出真实出现的类别，重读时保留选择并允许空相交结果。
void OfflineSegmentOverview::fillCategories(bool preserve)
{
    QSet<quint16> unique; // 本次投影存在的类别。
    for (const auto& row : m_snapshot->rows)
    {
        if (row.category)
        {
            unique.insert(*row.category);
        }
    }
    if (preserve)
    {
        unique.unite(m_filterCategories);
    }
    auto numbers = unique.values(); // 按线上编号排序，便于键盘定位。
    std::sort(numbers.begin(), numbers.end());
    const QSignalBlocker guard(m_categories); // 重建条目期间不重复过滤。
    m_categories->clear();
    for (const auto number : numbers)
    {
        auto* item = new QListWidgetItem(QString::number(number), m_categories); // 真实类别号。
        item->setData(Qt::UserRole, number);
        item->setSelected(m_filterCategories.contains(number));
    }
}

// 数字草稿没有通过验证时，原结果和有效时间范围保持原样。
void OfflineSegmentOverview::applyTimeRange()
{
    if (!m_snapshot)
    {
        return;
    }
    std::optional<quint64> low; // 草稿的包含起始端点。
    std::optional<quint64> high; // 草稿的不包含结束端点。
    m_invalidRange = !ParseBound(m_start->text(), low) || !ParseBound(m_end->text(), high)
        || (low && high && *low >= *high);
    if (m_invalidRange)
    {
        updateText();
        return;
    }
    if (low || high)
    {
        pauseLiveView();
    }
    m_lower = low;
    m_upper = high;
    applyFilters();
}

// 当前范围只改变显示。未记录 QPC 的行只在无时间限制时出现。
void OfflineSegmentOverview::applyFilters()
{
    if (!m_snapshot)
    {
        return;
    }
    QList<qsizetype> visible; // 当前匹配的源行序号。
    visible.reserve(m_snapshot->rows.size());
    const auto keyword = m_keyword->text().trimmed(); // 实际应用的关键字。
    const bool showApi = m_apiSource->isChecked() && m_snapshot->hasArchivedApi; // 只匹配已核对的 API 行。
    const bool showEtw = m_etwSource->isChecked() && (m_snapshot->live || m_snapshot->hasArchivedEtw); // 活动和归档共用 ETW 条件。
    for (qsizetype index = 0; index < m_snapshot->rows.size(); ++index)
    {
        const auto& row = m_snapshot->rows.at(index); // 阻止未知字段误匹配过滤。
        if ((showApi || showEtw) && !(showApi && row.archivedApi) && !(showEtw && row.liveEtw))
        {
            continue;
        }
        if (m_objectFilter && !RowReferencesObject(row, *m_objectFilter))
        {
            continue;
        }
        if (!m_filterCategories.isEmpty() && (!row.category || !m_filterCategories.contains(*row.category)))
        {
            continue;
        }
        if ((m_lower && (!row.receiveQpc || *row.receiveQpc < *m_lower)) ||
            (m_upper && (!row.receiveQpc || *row.receiveQpc >= *m_upper)))
        {
            continue;
        }
        // 关键字只匹配可见归档字段及详情中的编号，缺值不进入搜索。
        if (!keyword.isEmpty() && !RowLabel(row).contains(keyword, Qt::CaseInsensitive)
            && !QString::number(row.sequence).contains(keyword) && !MatchesNumber(row.ordinal, keyword)
            && !MatchesNumber(row.category, keyword) && !MatchesNumber(row.receiveQpc, keyword)
            && !MatchesNumber(row.pid, keyword) && !MatchesNumber(row.tid, keyword)
            && !(row.network && matchesNetworkKeyword(*row.network, keyword))
            && !(row.archivedApi && row.archivedApi->family.contains(keyword, Qt::CaseInsensitive))
            && !(row.liveEtw && row.liveEtw->provider.contains(keyword, Qt::CaseInsensitive)))
        {
            continue;
        }
        visible.append(index);
    }

    // 恢复匹配的选中行。过滤掉的选择继续锚定原证据。
    m_updatingSelection = true;
    m_model->replace(m_snapshot, std::move(visible));
    m_waterfall->setRows(m_snapshot.get(), *m_model, m_sequence);
    if (m_sequence)
    {
        selectSequence(*m_sequence, false);
    }
    m_updatingSelection = false;
    updateText();
    updateDetails();
}

// 发布实际段内序号。显示中的记录可同步选中但不会改变控件焦点。
void OfflineSegmentOverview::selectSequence(quint64 sequence, bool scrollTable)
{
    m_sequence = sequence;
    m_waterfall->setSelected(sequence);
    const auto found = m_model->locate(sequence); // 可能因过滤暂不显示。
    if (!m_updatingSelection && m_snapshot && m_snapshot->live && found.isValid())
    {
        const auto* row = m_model->at(found.row()); // 原始所选记录的值快照，不受滚动淘汰影响。
        m_selectedLiveRow = *row;
    }
    if (found.isValid() && m_table->currentIndex().row() != found.row())
    {
        const bool wasUpdating = m_updatingSelection; // 保留外层模型事务的门禁。
        m_updatingSelection = true;
        m_table->selectionModel()->setCurrentIndex(found, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        m_updatingSelection = wasUpdating;
    }
    if (found.isValid() && scrollTable)
    {
        m_table->scrollTo(found);
    }
    if (!m_updatingSelection)
    {
        updateDetails();
    }
}

// 维持文件身份、最近回执、有效结果数量和查询草稿的清晰区分。
void OfflineSegmentOverview::updateText()
{
    using ks::ui::StatusRole;
    const bool live = m_snapshot && m_snapshot->live; // 决定实际来源标签与可用动作。
    updateLiveControls();
    m_open->setText(sourceText(QStringLiteral("打开归档段")));
    m_open->setToolTip(sourceText(QStringLiteral("选择 Stored v1 归档段并只读打开。")));
    m_retry->setAccessibleName(sourceText(QStringLiteral("重新读取归档")));
    m_retry->setToolTip(m_lastPath.isEmpty() ? m_open->toolTip()
        : sourceText(QStringLiteral("重新读取归档：%1")).arg(m_lastPath));
    m_retry->setEnabled(!m_lastPath.isEmpty() && !m_reading && !m_liveBusy && !m_liveRecovery);
    m_cancel->setAccessibleName(sourceText(QStringLiteral("取消读取")));
    m_cancel->setToolTip(m_cancel->accessibleName());
    m_cancel->setEnabled(m_reading);
    m_categoryLabel->setText(sourceText(QStringLiteral("类别编号")));
    m_categories->setAccessibleName(m_categoryLabel->text());
    m_categories->setToolTip(sourceText(QStringLiteral("可选多个类别；未选择时显示所有类别。")));
    m_categories->setEnabled(m_categories->count() > 0);
    m_startLabel->setText(sourceText(QStringLiteral("起点（含）")));
    m_endLabel->setText(sourceText(QStringLiteral("终点（不含）")));
    m_apply->setText(sourceText(QStringLiteral("应用时间范围")));
    m_apply->setToolTip(sourceText(QStringLiteral("按接收 QPC 应用时间范围，留空表示不限。")));
    m_reset->setText(sourceText(QStringLiteral("清除时间范围")));
    m_reset->setToolTip(sourceText(QStringLiteral("清除时间限制，保留类别选择。")));
    m_keyword->setAccessibleName(sourceText(QStringLiteral("记录关键字")));
    m_keyword->setPlaceholderText(sourceText(QStringLiteral("筛选事件或网络端点")));
    m_keyword->setToolTip(sourceText(QStringLiteral("只匹配已显示的归档字段。")));
    m_keyword->setEnabled(m_snapshot && !m_snapshot->rows.isEmpty());
    // 根据实际回读的来源启用独立筛选。来源分类不改变已归档的任何行。
    m_apiSource->setText(QStringLiteral("API"));
    m_etwSource->setText(QStringLiteral("ETW"));
    const auto sourceUnavailable = sourceText(QStringLiteral("独立归档段缺少已验证的 API／ETW 来源绑定。")); // 来源条件不可用的原因。
    const bool archivedApi = m_snapshot && m_snapshot->hasArchivedApi; // 归档来源验证成功时才允许 API 筛选。
    m_apiSource->setEnabled(archivedApi);
    m_apiSource->setToolTip(archivedApi ? sourceText(QStringLiteral("只显示归档 API 线索。")) : sourceUnavailable);
    const bool archivedEtw = m_snapshot && m_snapshot->hasArchivedEtw; // 来源字段通过正文检查。
    m_etwSource->setEnabled(live || archivedEtw);
    m_etwSource->setToolTip(live ? sourceText(QStringLiteral("按已启用的 ETW 来源筛选。"))
        : archivedEtw ? sourceText(QStringLiteral("只显示可识别的归档 ETW 记录。")) : sourceUnavailable);
    m_more->setText(sourceText(QStringLiteral("时间筛选")));
    m_more->setToolTip(sourceText(QStringLiteral("展开或收起接收 QPC 的范围输入。")));
    m_clear->setText(sourceText(QStringLiteral("清除筛选")));
    m_clear->setToolTip(sourceText(QStringLiteral("清除所有显示筛选并保留当前记录。")));
    m_clear->setEnabled(m_snapshot && !m_snapshot->rows.isEmpty());

    // 只对确实具有 QPC 记录的段提供时间过滤。
    const bool hasTime = m_snapshot && std::any_of(m_snapshot->rows.cbegin(), m_snapshot->rows.cend(),
        [](const SegmentRow& row) { return row.receiveQpc.has_value(); });
    for (auto* input : {m_start, m_end})
    {
        input->setEnabled(hasTime);
    }
    m_apply->setEnabled(hasTime);
    m_reset->setEnabled(hasTime);
    m_more->setEnabled(hasTime);
    m_timeLabel->setText(hasTime ? sourceText(QStringLiteral("接收 QPC（原始刻度）"))
        : sourceText(QStringLiteral("无可用的接收 QPC。")));
    m_waterfall->setAccessibleName(sourceText(QStringLiteral("归档时间瀑布")));
    m_waterfall->setToolTip(sourceText(QStringLiteral("上下键选中记录。按住 Shift 扩选，Enter 应用时间范围。")));
    m_graphStatus->setText(live || archivedEtw ? sourceText(QStringLiteral("ETW 报头 PID／TID 表示记录上下文。"))
        : sourceText(QStringLiteral("图中只显示归档记录直接引用的对象。")));

    // 显示实际段头身份，与项目目录仅做 UUID 对照。
    m_identity->setVisible(m_snapshot != nullptr);
    m_context->setVisible(m_snapshot && !live);
    if (live)
    {
        m_identity->setText(m_snapshot->projectId.isEmpty()
            ? sourceText(QStringLiteral("实时采样 %1 · 未归档")).arg(m_snapshot->sampleId)
            : sourceText(QStringLiteral("实时采样 %1 · 项目 %2")).arg(m_snapshot->sampleId, m_snapshot->projectId));
    }
    else if (m_snapshot)
    {
        m_identity->setText(sourceText(QStringLiteral("%1 · 项目 %2 · 采样 %3 · 流 %4 · 段 %5"))
            .arg(m_snapshot->path, m_snapshot->projectId, m_snapshot->sampleId,
                QString::number(m_snapshot->stream), QString::number(m_snapshot->ordinal)));
        QString match; // 实际项目和采样身份的结果。
        if (m_projectId.isEmpty())
        {
            match = sourceText(QStringLiteral("独立归档：尚未打开项目。"));
        }
        else if (m_snapshot->projectId != m_projectId || (!m_sampleId.isEmpty() && m_snapshot->sampleId != m_sampleId))
        {
            match = sourceText(QStringLiteral("归档与当前项目或采样不匹配。"));
        }
        else if (m_sampleId.isEmpty())
        {
            match = sourceText(QStringLiteral("归档项目 ID 匹配；尚未选择采样。"));
        }
        else
        {
            match = sourceText(QStringLiteral("归档项目和采样 ID 均匹配。"));
        }
        m_context->setText(match);
    }

    // 读失败仍明确列出本次请求路径，首读前显示项目页传来的场景提示。
    QString status; // 本次归档读取说明。
    StatusRole role = StatusRole::Idle; // 共享主题回执颜色。
    if (m_reading)
    {
        status = sourceText(QStringLiteral("正在读取归档：%1")).arg(m_lastPath);
        role = StatusRole::Info;
    }
    else if (m_lastPath.isEmpty() || (live && m_latestPublished))
    {
        status = live ? QString() : m_sampleStatus;
    }
    else if (m_latestPublished)
    {
        // 终态水位可能早于物理文件末尾，状态分别报告检查点和实际预览范围。
        const bool verified = m_snapshot->checkpoint == SegmentCheckpoint::Verified; // 原始流与记录流均已复核。
        const bool qtRaw = m_snapshot->checkpoint == SegmentCheckpoint::QtRawVerified; // 本端只保存 raw 流。
        if (verified)
        {
            status = sourceText(QStringLiteral("已验证项目检查点。"));
        }
        else if (qtRaw)
        {
            status = m_latestEnd == SegmentEnd::Complete ? sourceText(QStringLiteral("已验证 Qt 原始归档和终止记录。"))
                : sourceText(QStringLiteral("已验证 Qt 原始归档前缀。"));
        }
        else if (m_snapshot->checkpoint == SegmentCheckpoint::ApiRawVerified)
        {
            status = sourceText(QStringLiteral("已验证 API 跟随归档检查点。"));
        }
        if (status.isEmpty() || m_latestEnd != SegmentEnd::Complete)
        {
            if (!status.isEmpty())
            {
                status += u' ';
            }
            status += EndText(m_latestEnd);
        }
        status += u' ' + sourceText(QStringLiteral("已校验前缀 %1 / %2 字节。"))
            .arg(m_snapshot->prefixBytes).arg(m_snapshot->fileBytes);
        if (m_snapshot->checkpoint == SegmentCheckpoint::Unpublished)
        {
            status += u' ' + sourceText(QStringLiteral("该归档没有已发布的检查点。"));
        }
        role = m_latestEnd == SegmentEnd::Complete ? StatusRole::Success : StatusRole::Warning;
    }
    else
    {
        const auto endText = m_latestLegacyApi ? sourceText(QStringLiteral("旧 API 跟随归档没有持久提交标记。"))
            : EndText(m_latestEnd); // 项目路径中的旧 API 跟随档只显示未发布回执。
        status = sourceText(QStringLiteral("%1 · %2")).arg(m_lastPath, endText);
        role = m_latestEnd == SegmentEnd::Canceled ? StatusRole::Idle : StatusRole::Error;
        if (m_snapshot)
        {
            status += u' ' + sourceText(QStringLiteral("仍显示上次提交的结果。"));
        }
    }
    if (!live && !m_reading && !m_lastPath.isEmpty())
    {
        // 失败回执使用当前读取的段号，即使表格继续显示上一份完整结果。
        if (m_latestVerifiedOrdinal)
        {
            status += u' ' + sourceText(QStringLiteral("已验证至第 %1 段。")).arg(m_latestVerifiedOrdinal);
        }
        if (m_latestFailedOrdinal)
        {
            status += u' ' + sourceText(QStringLiteral("第 %1 段校验失败。")).arg(m_latestFailedOrdinal);
        }
        if (m_latestOffset && m_latestEnd != SegmentEnd::Complete)
        {
            status += u' ' + sourceText(QStringLiteral("停止位置：%1 字节。")).arg(m_latestOffset);
        }
        if (m_clueMissing)
        {
            status += u' ' + sourceText(QStringLiteral("本次回放未核验到所选线索。"));
            role = StatusRole::Warning;
        }
    }
    m_status->setVisible(!status.isEmpty());
    m_status->setText(status);
    ks::ui::ApplyStatusRole(m_status, role);

    // 区别零记录、无匹配以及错误草稿；导出沿用实际显示范围。
    QString counts; // 当前可见与读取到的记录数量。
    if (m_snapshot)
    {
        counts = m_snapshot->rows.isEmpty() ? (live ? sourceText(QStringLiteral("本次尚无可显示记录。"))
            : sourceText(QStringLiteral("已读取空归档段。")))
            : sourceText(QStringLiteral("显示及导出范围：%1 / %2 条预览记录。"))
                .arg(m_model->rowCount()).arg(m_snapshot->rows.size());
        if (!m_snapshot->rows.isEmpty() && m_model->rowCount() == 0)
        {
            counts += u' ' + sourceText(QStringLiteral("没有记录符合当前筛选。"));
        }
        if (live && m_snapshot->liveRevision > static_cast<quint64>(m_snapshot->rows.size()))
        {
            counts += u' ' + sourceText(QStringLiteral("实时窗口已滚动移出 %1 条旧记录。"))
                .arg(m_snapshot->liveRevision - static_cast<quint64>(m_snapshot->rows.size()));
        }
        if (m_lower || m_upper)
        {
            counts += u' ' + sourceText(QStringLiteral("接收 QPC 范围 [%1, %2)。"))
                .arg(EvidenceNumber(m_lower), EvidenceNumber(m_upper));
        }
        if (!m_filterCategories.isEmpty())
        {
            counts += u' ' + sourceText(QStringLiteral("已选 %1 个类别。")).arg(m_filterCategories.size());
        }
        if (m_objectFilter)
        {
            counts += u' ' + objectFilterSummary();
        }
        if (m_snapshot->apiFollowSourceRows)
        {
            counts += u' ' + sourceText(QStringLiteral("已核验 %1 条源归档记录。覆盖范围未知。"))
                .arg(*m_snapshot->apiFollowSourceRows);
        }
        else if (archivedApi)
        {
            counts += u' ' + sourceText(QStringLiteral("已核验 %1 条归档 API 线索。覆盖范围未知。")).arg(m_snapshot->verifiedRows);
        }
        else if (!live && m_snapshot->lastVerifiedOrdinal)
        {
            counts += u' ' + sourceText(QStringLiteral("已验证 %1 条归档记录。")).arg(m_snapshot->verifiedRows);
        }
        else if (!live && !archivedEtw && !m_snapshot->rows.isEmpty())
        {
            counts += u' ' + sourceUnavailable;
        }
        if (m_snapshot->qtArchiveDropped.value_or(0) != 0)
        {
            counts += u' ' + sourceText(QStringLiteral("归档队列丢弃 %1 条观测。")).arg(*m_snapshot->qtArchiveDropped);
        }
    }
    if (m_invalidRange)
    {
        counts += u' ' + sourceText(QStringLiteral("请输入有效的无符号时间刻度，终点必须大于起点。"));
    }
    m_filterStatus->setText(counts.trimmed());
    ks::ui::ApplyStatusRole(m_filterStatus, m_invalidRange ? StatusRole::Warning : StatusRole::Idle);
}

// 用一个结构化文档呈现记录、可用字段、原始引用及其解析边界。
void OfflineSegmentOverview::updateDetails()
{
    ks::ui::FieldDocument document; // 详情、查找和导出共享的真实字段。
    document.title = m_snapshot && m_snapshot->live ? QStringLiteral("记录详情") : QStringLiteral("归档记录详情");
    if (m_snapshot && m_sequence)
    {
        const auto current = std::find_if(m_snapshot->rows.cbegin(), m_snapshot->rows.cend(), [this](const SegmentRow& row) {
            return row.sequence == *m_sequence;
        });
        // 实时窗口淘汰已选记录后保留该记录及详情，不自动选邻行。
        const auto* selected = current != m_snapshot->rows.cend() ? &*current
            : m_selectedLiveRow && m_selectedLiveRow->sequence == *m_sequence ? &*m_selectedLiveRow : nullptr;
        if (selected)
        {
            updateObjectEvidence(selected);
            if (!m_model->locate(*m_sequence).isValid())
            {
                document.note(QStringLiteral("所选记录当前不在显示范围内。"));
            }
            if (selected->archivedApi)
            {
                // 归档座标与调用方头字段可复制。目标身份和实际执行情况仍没有证据。
                const auto& clue = *selected->archivedApi; // 当前已核验的 API 线索。
                document.section(QStringLiteral("归档 API 线索"))
                    .field(QStringLiteral("采样 ID"), m_snapshot->sampleId)
                    .field(QStringLiteral("归档段号"), QString::number(selected->segmentOrdinal))
                    .field(QStringLiteral("记录序号"), QString::number(selected->sequence))
                    .field(QStringLiteral("文件偏移（字节）"), QString::number(selected->offset))
                    .field(QStringLiteral("事件"), clue.api)
                    .field(QStringLiteral("线索类别"), clue.family)
                    .field(QStringLiteral("源归档行号"), QString::number(clue.sourceSequence))
                    .field(QStringLiteral("FILETIME"), QString::number(clue.time))
                    .field(QStringLiteral("来源头 PID"), EvidenceNumber(selected->pid))
                    .field(QStringLiteral("来源头 TID"), EvidenceNumber(selected->tid))
                    .field(QStringLiteral("来源声明的调用方创建时间"), EvidenceNumber(clue.callerCreation))
                    .field(QStringLiteral("API 原包前缀（十六进制）"), QString::fromLatin1(clue.preview.toHex(' ')))
                    .note(QStringLiteral("目标身份、实际写入范围、执行和归因未知。"));
                m_details->setDocument(document);
                return;
            }
            if (selected->liveEtw)
            {
                const auto& header = *selected->liveEtw; // 原始描述符字段和记录上下文。
                document.section(m_snapshot->live ? QStringLiteral("实时事件") : QStringLiteral("归档记录"))
                    .field(QStringLiteral("采样 ID"), m_snapshot->sampleId)
                    .field(QStringLiteral("记录序号"), QString::number(selected->sequence))
                    .field(QStringLiteral("ETW Provider GUID"), header.provider)
                    .field(QStringLiteral("FILETIME"), QString::number(header.fileTime))
                    .field(QStringLiteral("事件"), RowLabel(*selected))
                    .field(QStringLiteral("Opcode"), QString::number(header.opcode))
                    .field(QStringLiteral("接收 QPC"), EvidenceNumber(selected->receiveQpc))
                    .field(QStringLiteral("来源头 PID"), EvidenceNumber(selected->pid))
                    .field(QStringLiteral("来源头 TID"), EvidenceNumber(selected->tid));
                if (!m_snapshot->live)
                {
                    document.field(QStringLiteral("归档段号"), QString::number(selected->segmentOrdinal))
                        .field(QStringLiteral("文件偏移（字节）"), QString::number(selected->offset));
                }
                if (selected->liveSourceSequence)
                {
                    document.field(QStringLiteral("原采集序号"), QString::number(*selected->liveSourceSequence))
                        .note(QStringLiteral("此记录仅保存 ETW 报头，未采集载荷。"));
                }
                if (selected->archivedEtw)
                {
                    const auto& payload = *selected->archivedEtw; // 归档声明与实际内联数据分开显示。
                    document.field(QStringLiteral("ETW 来源代次"), payload.sourceEpoch)
                        .field(QStringLiteral("接收 QPC 频率（Hz）"), EvidenceNumber(payload.qpcFrequencyHz))
                        .field(QStringLiteral("ETW 原始载荷字节数"), QString::number(payload.originalBytes))
                        .field(QStringLiteral("归档保留字节数"), QString::number(payload.storedBytes))
                        .field(QStringLiteral("预览字节数"), QString::number(payload.preview.size()));
                    if (!payload.preview.isEmpty())
                    {
                        document.field(QStringLiteral("ETW 字节预览（十六进制）"),
                            QString::fromLatin1(payload.preview.toHex(' ')));
                    }
                    if (payload.malformed)
                    {
                        document.note(QStringLiteral("采集端报告 ETW 载荷异常。"));
                    }
                }
                m_details->setDocument(document);
                return;
            }
            if (selected->liveProcess)
            {
                const auto& analysis = *selected->liveProcess; // 同一个原进程对象的活动区间。
                document.section(QStringLiteral("进程活动分析"))
                    .field(QStringLiteral("采样 ID"), m_snapshot->sampleId)
                    .field(QStringLiteral("PID"), EvidenceNumber(selected->pid))
                    .field(QStringLiteral("进程创建时间（FILETIME）"), QString::number(analysis.creationTime))
                    .field(QStringLiteral("统计区间（毫秒）"), QString::number(analysis.elapsedMs))
                    .field(QStringLiteral("区间 CPU 时间（毫秒）"), QString::number(analysis.cpu100ns / 10000.0, 'f', 3))
                    .field(QStringLiteral("区间读 I/O 字节"), EvidenceNumber(analysis.readBytes))
                    .field(QStringLiteral("区间写 I/O 字节"), EvidenceNumber(analysis.writeBytes));
                if (selected->liveSourceSequence)
                {
                    // 归档重开保持原观测序号和实际文件坐标，实时详情仍沿用原字段。
                    document.field(QStringLiteral("归档段号"), QString::number(selected->segmentOrdinal))
                        .field(QStringLiteral("记录序号"), QString::number(selected->sequence))
                        .field(QStringLiteral("原采集序号"), QString::number(*selected->liveSourceSequence))
                        .field(QStringLiteral("文件偏移（字节）"), QString::number(selected->offset))
                        .field(QStringLiteral("接收 QPC"), EvidenceNumber(selected->receiveQpc));
                }
                m_details->setDocument(document);
                return;
            }
            document.section(QStringLiteral("归档记录"))
                .field(QStringLiteral("采样 ID"), m_snapshot->sampleId)
                .field(QStringLiteral("归档段号"), QString::number(selected->segmentOrdinal))
                .field(QStringLiteral("记录序号"), QString::number(selected->sequence))
                .field(QStringLiteral("文件偏移（字节）"), QString::number(selected->offset))
                .field(QStringLiteral("正文长度（字节）"), QString::number(selected->payloadBytes))
                .field(QStringLiteral("事件"), RowLabel(*selected))
                .field(QStringLiteral("类别编号"), EvidenceNumber(selected->category))
                .field(QStringLiteral("接收 QPC"), EvidenceNumber(selected->receiveQpc));
            if (selected->ordinal)
            {
                document.field(QStringLiteral("事件序号"), EvidenceNumber(selected->ordinal))
                    .field(QStringLiteral("来源头 PID"), EvidenceNumber(selected->pid))
                    .field(QStringLiteral("来源头 TID"), EvidenceNumber(selected->tid));
                document.section(QStringLiteral("未解析引用"))
                    .field(QStringLiteral("来源字典 ID"), EvidenceNumber(selected->sourceId))
                    .field(QStringLiteral("进程对象 ID"), EvidenceNumber(selected->actorId))
                    .field(QStringLiteral("目标进程对象 ID"), EvidenceNumber(selected->targetId))
                    .field(QStringLiteral("线程对象 ID"), EvidenceNumber(selected->threadId));
            }
            if (selected->network)
            {
                appendNetworkEvidence(document, *selected->network);
            }
            m_details->setDocument(document);
            return;
        }
    }
    updateObjectEvidence(nullptr);
    document.note(QStringLiteral("选择记录以查看字段与引用。"));
    m_details->setDocument(document);
}
}
