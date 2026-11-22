#include "../Framework.h"
#include "ThreadSettingsInline.h"
#include "ThreadSettingsR3.h"
#include "ThreadStackWindow.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ThemeAccentIcon.h"
#include "../theme.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QSignalBlocker>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QStyledItemDelegate>
#include <QTimer>
#include <QToolButton>
#include <QTreeView>
#include <array>

namespace
{
    using namespace ks::threadsettings;

    // 取公开 API 的返回值，不把 R3 设置映射为某个私有成员。
    const Value& fieldValue(const Snapshot& snapshot, Field field)
    {
        return field == Field::Priority ? snapshot.priority : snapshot.priorityBoost;
    }

    // 为允许的公开优先级常量提供稳定顺序；最高只到 THREAD_PRIORITY_HIGHEST。
    constexpr std::array<int, 6> kPriorities{-15, -2, -1, 0, 1, 2};
    constexpr int kValueColumn = 4; // 树的最后一列，也是唯一允许嵌入操作的列。
    constexpr int kInlineModeRole = Qt::UserRole + 28; // 只控制绘制，DisplayRole 始终是实际值。
    enum InlineMode { Browse = 1, EditValue }; // 0 表示该行不使用内联控件。

    // 继续由 Qt 绘制同一个主题行；浏览时给右侧图标留白，编辑时不在输入框后重复绘制。
    class ValueDelegate final : public QStyledItemDelegate
    {
    public:
        using QStyledItemDelegate::QStyledItemDelegate;

    protected:
        // 输入末列项与待绘样式；只调整显示文本，不修改选择底色或源数据。
        void initStyleOption(QStyleOptionViewItem* option, const QModelIndex& index) const override
        {
            QStyledItemDelegate::initStyleOption(option, index);
            const int mode = index.data(kInlineModeRole).toInt(); // 当前行的控件模式。
            if (mode == EditValue)
            {
                option->text.clear();
            }
            else if (mode == Browse)
            {
                // 28 px 紧凑按钮加两侧边距；默认主题文字边距也一并预留。
                constexpr int reservedWidth = 40;
                option->text = option->fontMetrics.elidedText(option->text, option->textElideMode,
                    qMax(0, option->rect.width() - reservedWidth));
            }
        }
    };

    // 返回供显示、搜索和复制共用的已确认值文案；未知数值保留原样。
    QString valueText(Field field, int value)
    {
        if (field == Field::PriorityBoost)
        {
            return ks::i18n::displayText(value ? QStringLiteral("允许动态提升") : QStringLiteral("禁止动态提升"));
        }
        QString level; // 描述相对进程优先级类别的线程设置，不是实时调度优先级。
        switch (value)
        {
        case -15: level = QStringLiteral("空闲"); break;
        case -2: level = QStringLiteral("最低优先级"); break;
        case -1: level = QStringLiteral("低于正常"); break;
        case 0: level = QStringLiteral("普通"); break;
        case 1: level = QStringLiteral("高于正常"); break;
        case 2: level = QStringLiteral("最高优先级"); break;
        case 15: level = QStringLiteral("时间关键"); break;
        default: return QString::number(value);
        }
        return QStringLiteral("%1 (%2)").arg(ks::i18n::displayText(level)).arg(value);
    }

    // 创建共享主题的紧凑图标按钮，输入为宿主、SVG 资源、原始提示和按钮语义。
    QToolButton* tool(QWidget* parent, const char* resource, const QString& label,
        ks::ui::FlatButtonTone tone = ks::ui::FlatButtonTone::Neutral)
    {
        auto* button = new QToolButton(parent); // 由行控件或外部工具带负责销毁。
        button->setToolTip(ks::i18n::displayText(label));
        button->setAccessibleName(button->toolTip());
        KswordTheme::ApplyCompactIconButtonMetrics(button);
        ks::ui::ApplyFlatButtonTheme(button, tone, ks::ui::FlatButtonAppearance::Flat);
        ks::ui::SetThemeButtonIcon(button, QIcon(QLatin1String(resource)));
        return button;
    }

    // 每个可用的叶子只有一组控件；草稿由控制器持有，不随搜索隐藏的控件销毁。
    class InlineCell final : public QWidget
    {
    public:
        // 输入字段类型与视口父对象；仅构造控件和选项，不执行任何操作。
        InlineCell(Field field, QWidget* parent) : QWidget(parent)
        {
            auto* row = new QHBoxLayout(this); // 由单元格几何约束，只占最后一列。
            row->setContentsMargins(4, 0, 4, 0);
            row->setSpacing(4);
            gap = new QWidget(this);
            gap->setAttribute(Qt::WA_TransparentForMouseEvents);
            row->addWidget(gap, 1);
            choice = new QComboBox(this);
            choice->setMinimumContentsLength(1);
            choice->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
            choice->setAccessibleName(ks::i18n::displayText(field == Field::Priority
                ? QStringLiteral("线程优先级") : QStringLiteral("动态优先级提升")));
            choice->setToolTip(choice->accessibleName());
            row->addWidget(choice, 1);

            // 下拉框仅列出有效候选，不接受任意整数或未知内核状态。
            if (field == Field::Priority)
            {
                for (const int value : kPriorities)
                {
                    choice->addItem(valueText(field, value), value);
                }
            }
            else
            {
                choice->addItem(valueText(field, 0), 0);
                choice->addItem(valueText(field, 1), 1);
            }
            edit = tool(this, ":/Icon/rxpf_write.svg", QStringLiteral("编辑值"));
            apply = tool(this, ":/Icon/service_apply.svg", QStringLiteral("提交此项修改"), ks::ui::FlatButtonTone::Accent);
            cancel = tool(this, ":/Icon/titlebar_close.svg", QStringLiteral("放弃此项修改"));
            row->addWidget(edit);
            row->addWidget(apply);
            row->addWidget(cancel);
        }

        QWidget* gap = nullptr; // 浏览时留出原树绘制的值，按钮贴右。
        QComboBox* choice = nullptr; // 草稿的受限候选列表。
        QToolButton* edit = nullptr; // 开启草稿，不触发调用。
        QToolButton* apply = nullptr; // 仅显式点击才提交。
        QToolButton* cancel = nullptr; // 放弃草稿，不调用 setter。
    };

    class InlineSettings final : public QObject
    {
    public:
        // 输入现有视图、模型及冻结的线程身份，挂上公开 API 分组；视图负责本控制器寿命。
        InlineSettings(QTreeView& view, QStandardItemModel& model, QSortFilterProxyModel& proxy, Identity identity)
            : QObject(&view), m_view(view), m_proxy(proxy), m_identity(identity), m_operation(this)
        {
            // 所有 DisplayRole 都留在原树模型中，复制与搜索不读取控件或未提交值。
            m_group = append(*model.invisibleRootItem(), ks::i18n::displayText(QStringLiteral("R3 线程设置")),
                QStringLiteral("Win32"));
            m_values[0] = append(*m_group, ks::i18n::displayText(QStringLiteral("线程优先级")), QStringLiteral("int"));
            m_values[1] = append(*m_group, ks::i18n::displayText(QStringLiteral("动态优先级提升")), QStringLiteral("BOOL"));
            view.setItemDelegateForColumn(kValueColumn, new ValueDelegate(&view));
            m_refresh = tool(&view, ":/Icon/process_refresh.svg", QStringLiteral("刷新 R3 线程设置"));
            connect(m_refresh, &QToolButton::clicked, this, [this]() { refresh(); });
            connect(&proxy, &QAbstractItemModel::rowsInserted, this, [this]() { scheduleWidgets(); });
            view.expand(proxy.mapFromSource(m_group->index()));
            refresh();
        }

        // 先关闭后台投递门禁，再由 QObject 清理控件连接。
        ~InlineSettings() override
        {
            m_operation.close();
        }

        // 把独立刷新动作交给详情页现有工具带，不改变 R0 刷新的含义。
        QToolButton* refreshButton() const { return m_refresh; }

    private:
        // 在给定父项添加五列逻辑行；返回第 0 列，用于定位该行及子项。
        static QStandardItem* append(QStandardItem& parent, const QString& label, const QString& type)
        {
            const QString empty = QStringLiteral("—"); // R3 API 无内核偏移或字段地址。
            auto* first = new QStandardItem(empty); // 模型在 appendRow 后接管。
            parent.appendRow({first, new QStandardItem(empty), new QStandardItem(label),
                new QStandardItem(type), new QStandardItem(empty)});
            return first;
        }

        // 行号固定对应单一公开设置；不按模型行位置或搜索顺序识别字段。
        static Field fieldAt(int slot) { return slot == 0 ? Field::Priority : Field::PriorityBoost; }

        // 使用源模型取最后一列的项；输入缀属行的首项。
        static QStandardItem* last(QStandardItem* first)
        {
            return first->parent() ? first->parent()->child(first->row(), kValueColumn)
                : first->model()->item(first->row(), kValueColumn);
        }

        // 合并代理插入事件，等树视图处理完索引后补齐可见的两个单元格。
        void scheduleWidgets()
        {
            if (m_widgetsQueued)
            {
                return;
            }
            m_widgetsQueued = true;
            QTimer::singleShot(0, this, [this]()
            {
                m_widgetsQueued = false;
                syncWidgets();
            });
        }

        // 只为通过过滤且可写的字段装按钮；提交中与草稿状态从控制器恢复。
        void syncWidgets()
        {
            m_refresh->setEnabled(!m_busy && m_draftSlot < 0);
            for (int slot = 0; slot < static_cast<int>(m_values.size()); ++slot)
            {
                const auto field = fieldAt(slot); // 后端字段枚举与模型行独立。
                const auto& current = fieldValue(m_snapshot, field); // 当前已确认值和普通访问权限。
                auto* item = last(m_values[slot]); // 源项在搜索时不会被销毁。
                const bool editing = m_draftSlot == slot; // 刷新和过滤不覆盖尚未提交的草稿。
                const int mode = editing ? EditValue : current.value && current.writable ? Browse : 0;
                item->setData(mode, kInlineModeRole);
                const auto index = m_proxy.mapFromSource(item->index()); // 过滤后的末列。
                if (!index.isValid())
                {
                    continue;
                }
                auto* cell = static_cast<InlineCell*>(m_view.indexWidget(index)); // 只有本控制器安装行控件。
                if (mode == 0)
                {
                    if (cell)
                    {
                        m_view.setIndexWidget(index, nullptr);
                    }
                    continue;
                }
                if (!cell)
                {
                    cell = new InlineCell(field, m_view.viewport());
                    bindCell(*cell, slot);
                    m_view.setIndexWidget(index, cell);
                }

                // 浏览态用树的原生文本绘制；编辑态用原生下拉与右侧 ✓/×。
                cell->gap->setVisible(!editing);
                cell->choice->setVisible(editing);
                cell->choice->setEnabled(!m_busy);
                cell->edit->setVisible(!editing);
                cell->edit->setEnabled(!m_busy && m_draftSlot < 0);
                cell->apply->setVisible(editing);
                cell->apply->setEnabled(editing && !m_busy && m_desired && m_desired != current.value);
                cell->cancel->setVisible(editing);
                cell->cancel->setEnabled(editing && !m_busy);
                if (editing)
                {
                    const QSignalBlocker blocked(cell->choice); // 投影恢复不视为用户改值。
                    cell->choice->setCurrentIndex(m_desired ? cell->choice->findData(*m_desired) : -1);
                }
            }
        }

        // 将本单元格的输入与明确的开始、取消、提交三类动作接到控制器。
        void bindCell(InlineCell& cell, int slot)
        {
            connect(cell.edit, &QToolButton::clicked, &cell, [this, &cell, slot]()
            {
                if (m_busy || m_draftSlot >= 0)
                {
                    return;
                }
                m_draftSlot = slot;
                m_desired = fieldValue(m_snapshot, fieldAt(slot)).value;
                syncWidgets();
                cell.choice->setFocus(Qt::OtherFocusReason);
            });
            connect(cell.choice, &QComboBox::currentIndexChanged, &cell, [this, &cell, slot](int index)
            {
                if (!m_busy && slot == m_draftSlot && index >= 0)
                {
                    m_desired = cell.choice->itemData(index).toInt();
                    syncWidgets();
                }
            });
            connect(cell.cancel, &QToolButton::clicked, &cell, [this, slot]()
            {
                if (!m_busy && slot == m_draftSlot)
                {
                    clearDraft();
                    syncWidgets();
                }
            });
            connect(cell.apply, &QToolButton::clicked, &cell, [this, slot]() { submit(slot); });
        }

        // 清除本地草稿；不会读取或更改线程。
        void clearDraft()
        {
            m_draftSlot = -1;
            m_desired.reset();
        }

        // 将公开字段快照投影到最后一列；一项不可用不会吞掉另一项。
        void publish(const Snapshot& snapshot, const QString& status, unsigned long error = 0)
        {
            m_snapshot = snapshot;
            auto* summary = last(m_group); // R3 状态与 R0 状态单独展示。
            const auto detail = error ? QStringLiteral("%1 · Win32 %2").arg(status).arg(error) : status;
            summary->setText(detail);
            summary->setToolTip(detail);
            for (int slot = 0; slot < static_cast<int>(m_values.size()); ++slot)
            {
                const auto field = fieldAt(slot); // 源数据固定按字段访问。
                const auto& current = fieldValue(snapshot, field); // 每行自己的读取证据与权限。
                auto* item = last(m_values[slot]); // 搜索和复制所见的已提交值。
                const auto text = current.value ? valueText(field, *current.value)
                    : ks::i18n::displayText(QStringLiteral("不可用"));
                item->setText(text);
                const auto hint = current.value && !current.writable
                    ? ks::i18n::displayText(QStringLiteral("当前权限只允许读取此项")) : text;
                item->setToolTip(current.error ? QStringLiteral("%1 · Win32 %2").arg(hint).arg(current.error) : hint);
                item->setSizeHint(current.writable ? QSize(0, 30) : QSize());
            }
            syncWidgets();
        }

        // 异步读取公开设置，无写操作；正在编辑时保留草稿而不刷新。
        void refresh()
        {
            if (m_busy || m_draftSlot >= 0)
            {
                return;
            }
            m_busy = true;
            last(m_group)->setText(ks::i18n::displayText(QStringLiteral("正在读取线程字段…")));
            syncWidgets();
            m_operation.submit<Identity, Snapshot>(m_identity,
                [](const Identity& identity, const ks::ui::AsyncOperationToken&) { return Query(identity); },
                [this](const Snapshot& result, std::uint64_t)
                {
                    m_busy = false;
                    const bool allRead = result.priority.value && result.priorityBoost.value; // 区分完整和部分读数。
                    const auto message = result.identityError ? QStringLiteral("无法复核线程身份")
                        : allRead ? QStringLiteral("字段读取成功") : QStringLiteral("部分字段不可用");
                    publish(result, ks::i18n::displayText(message), result.identityError);
                    return true;
                }, [this](std::exception_ptr) { unexpected(false); });
        }

        // 仅提交被点击的这一字段，预期值来自编辑开始的同一份冻结快照。
        void submit(int slot)
        {
            if (m_busy || m_draftSlot != slot || !m_desired)
            {
                return;
            }
            const auto field = fieldAt(slot); // 按允许列表选择固定的公开 setter。
            const auto& current = fieldValue(m_snapshot, field); // 预期值只来自最近一次已确认的回读。
            if (!current.value || !current.writable || m_desired == current.value)
            {
                return;
            }
            const Edit request{m_identity, field, *current.value, *m_desired}; // worker 不持任何 UI、地址或偏移。
            m_busy = true;
            last(m_group)->setText(ks::i18n::displayText(QStringLiteral("正在提交并回读…")));
            syncWidgets();
            const auto ticket = m_operation.submitTransaction<Edit, Receipt>(request, Apply,
                [this, request](const Receipt& result, std::uint64_t)
                {
                    finishEdit(request, result);
                    return true;
                }, [this](std::exception_ptr) { unexpected(true); });
            if (!ticket)
            {
                m_busy = false;
                last(m_group)->setText(ks::i18n::displayText(QStringLiteral("未提交，可重试")));
                syncWidgets();
            }
        }

        // 只用后端回执更新已确认值；setter 失败但基线未变时保留草稿以便重试。
        void finishEdit(const Edit& request, const Receipt& result)
        {
            m_busy = false;
            QString message; // 独立区分成功、冲突、失败及无法证实结果。
            switch (result.status)
            {
            case Status::Applied: message = QStringLiteral("已修改，回读一致"); break;
            case Status::Conflict: message = QStringLiteral("原值已变化，本次未写入"); break;
            case Status::Unavailable: message = QStringLiteral("目标或设置不可用，本次未写入"); break;
            case Status::Failed: message = QStringLiteral("系统拒绝修改"); break;
            case Status::Unverified: message = QStringLiteral("已请求修改，但未能确认结果"); break;
            }
            const auto& current = fieldValue(result.snapshot, request.field); // 底层报告的原对象最新状态。
            if (!(result.status == Status::Failed && current.writable && current.value == request.expected))
            {
                clearDraft();
            }
            const auto slot = request.field == Field::Priority ? 0 : 1; // 让回执指出究竟是哪一项。
            const auto label = m_values[slot]->index().siblingAtColumn(2).data().toString(); // 对应字段名称。
            publish(result.snapshot, QStringLiteral("%1 · %2").arg(label, ks::i18n::displayText(message)), result.error);
        }

        // 没有可信回执时不保留旧值为事实，恢复 R3 刷新入口。
        void unexpected(bool write)
        {
            m_busy = false;
            clearDraft();
            publish({}, ks::i18n::displayText(write ? QStringLiteral("已请求修改，但未能确认结果")
                : QStringLiteral("字段查询未完成")));
        }

        QTreeView& m_view; // 现有字段树及行控件宿主。
        QSortFilterProxyModel& m_proxy; // 页面唯一搜索代理。
        const Identity m_identity; // 列表上冻结的 PID/TID 和创建时间。
        ks::ui::AsyncOperation m_operation; // 单在途查询或提交，不合并写事务。
        QStandardItem* m_group = nullptr; // R3 独立根项，不参加 R0 刷新的重建。
        std::array<QStandardItem*, 2> m_values{}; // 两个受支持项目的源模型行。
        QToolButton* m_refresh = nullptr; // 独立公开设置刷新按钮。
        Snapshot m_snapshot{}; // 冻结的原对象实际设置，用于显示和写前比对。
        std::optional<int> m_desired; // 草稿，永不进入搜索、复制或已读值。
        int m_draftSlot = -1; // 同时只编辑一行；负数为浏览态。
        bool m_busy = false; // 异步操作中禁用二次写和刷新。
        bool m_widgetsQueued = false; // 一次代理过滤只排队恢复一轮按钮。
    };
}

QToolButton* AddInlineThreadSettings(QTreeView& view, QStandardItemModel& model,
    QSortFilterProxyModel& proxy, const ThreadStackTarget& target)
{
    const Identity identity{target.processId, target.threadId, target.processCreationTime100ns,
        target.threadCreationTime100ns}; // 只复制后端核验所需的身份字段。
    auto* settings = new InlineSettings(view, model, proxy, identity); // 视图销毁时关闭回执投递。
    return settings->refreshButton();
}
