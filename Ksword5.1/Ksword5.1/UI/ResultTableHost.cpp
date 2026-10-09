#include "ResultTableHost.h"
#include "TableInteractionSupport.h"
#include "TableSearchSupport.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QSet>
#include <QTableView>
#include <QTableWidget>
#include <QTimer>

#include <utility>

namespace
{
    constexpr char kHostName[] = "ksword_result_table_host";
}

namespace ks::ui
{
    ResultTableHost::ResultTableHost(QTableView* view)
        : QObject(view)
        , m_view(view)
    {
        // 宿主只有视图级生命周期，不读取驱动，不获取业务快照。
        setObjectName(QLatin1String(kHostName));
    }

    ResultTableHost* ResultTableHost::ensure(QTableView* view)
    {
        if (view == nullptr)
        {
            return nullptr;
        }
        for (QObject* const child : view->children())
        {
            if (child->objectName() == QLatin1String(kHostName))
            {
                return static_cast<ResultTableHost*>(child);
            }
        }
        return new ResultTableHost(view);
    }

    bool ResultTableHost::bindModel(
        QAbstractItemModel* model,
        const QList<ResultTableColumn>& columns,
        const ResultTableCapabilities& capabilities)
    {
        if (m_view.isNull() || model == nullptr || columns.isEmpty())
        {
            return false;
        }
        // QTableWidget 拥有不可替换的内部模型，只接受它本身的模型。
        if (qobject_cast<QTableWidget*>(m_view.data()) != nullptr && m_view->model() != model)
        {
            return false;
        }
        QSet<int> columnIndexes;      // 检测同一逻辑列是否重复声明。
        QSet<QString> columnIds;      // 检测业务稳定键是否重复声明。
        for (const ResultTableColumn& column : columns)
        {
            if (column.modelColumn < 0 || column.modelColumn >= model->columnCount()
                || column.stableId.isEmpty() || columnIndexes.contains(column.modelColumn)
                || columnIds.contains(column.stableId))
            {
                return false;
            }
            columnIndexes.insert(column.modelColumn);
            columnIds.insert(column.stableId);
        }
        // 先完整校验再换绑；QTableWidget 已有模型不调用 setModel，保留业务缓存约定。
        m_columns = columns;
        m_capabilities = capabilities;
        m_explicitColumns = true;
        if (m_view->model() != model)
        {
            PrepareTableSearchModelChange(m_view.data());
            m_view->setModel(model);
        }
        refresh();
        return true;
    }

    void ResultTableHost::refresh()
    {
        if (m_refreshing || m_view.isNull() || m_view->model() == nullptr)
        {
            return;
        }
        m_refreshing = true;
        observeModel(m_view->model());
        if (!m_explicitColumns)
        {
            // 存量动态表按逻辑列号登记兼容身份，业务接入后可替换为显式稳定键。
            m_columns.clear();
            for (int column = 0; column < m_model->columnCount(); ++column)
            {
                m_columns.append({column, QString::number(column)});
            }
        }
        ConfigureResultTableInteractions(m_view.data(), m_capabilities);
        m_refreshing = false;
    }

    // 模型结构由宿主观察；冻结、排序和搜索继续使用各自已有控制器。
    void ResultTableHost::observeModel(QAbstractItemModel* model)
    {
        if (m_model == model)
        {
            return;
        }
        for (const QMetaObject::Connection& connection : m_modelConnections)
        {
            QObject::disconnect(connection);
        }
        m_modelConnections.clear();
        m_model = model;
        RefreshTableSearchModelBinding(m_view.data());
        if (model == nullptr)
        {
            return;
        }
        const auto changed = [this]() { scheduleRefresh(); };
        m_modelConnections.append(connect(model, &QAbstractItemModel::modelReset, this, changed));
        m_modelConnections.append(connect(model, &QAbstractItemModel::columnsInserted, this, changed));
        m_modelConnections.append(connect(model, &QAbstractItemModel::columnsRemoved, this, changed));
    }

    void ResultTableHost::scheduleRefresh()
    {
        if (m_refreshScheduled)
        {
            return;
        }
        m_refreshScheduled = true;
        QTimer::singleShot(0, this, [this]()
        {
            m_refreshScheduled = false;
            refresh();
        });
    }

    QTableView* ResultTableHost::view() const
    {
        return m_view.data();
    }

    QAbstractItemModel* ResultTableHost::model() const
    {
        return m_model.data();
    }

    // 列身份只取业务键，不因主题、翻译或表头拖动发生变化。
    QString ResultTableHost::stableColumnId(const int modelColumn) const
    {
        for (const ResultTableColumn& column : m_columns)
        {
            if (column.modelColumn == modelColumn)
            {
                return column.stableId;
            }
        }
        return {};
    }

    bool ResultTableHost::hasExplicitColumns() const
    {
        return m_explicitColumns;
    }

    const ResultTableCapabilities& ResultTableHost::capabilities() const
    {
        return m_capabilities;
    }

    QList<QAbstractItemView*> ResultTableHost::groupViews(const QList<ResultTableHost*>& hosts)
    {
        QList<QAbstractItemView*> views;
        views.reserve(hosts.size());
        for (ResultTableHost* const host : hosts)
        {
            if (host != nullptr && host->view() != nullptr)
            {
                views.append(host->view());
            }
        }
        return views;
    }

    bool ResultTableHost::isGroupCommitBlocked(const QList<ResultTableHost*>& hosts)
    {
        UiCommitCoordinator* const coordinator = UiCommitCoordinator::forApplication();
        return coordinator != nullptr && coordinator->isBlocked(groupViews(hosts));
    }

    bool ResultTableHost::deferGroupIfBlocked(
        QObject* owner,
        const QString& key,
        const QList<ResultTableHost*>& hosts,
        std::function<void()> action)
    {
        UiCommitCoordinator* const coordinator = UiCommitCoordinator::forApplication();
        return coordinator != nullptr && coordinator->deferIfBlocked(
            owner, key, groupViews(hosts), std::move(action));
    }

    UiCommitSubmission ResultTableHost::submitGroup(
        QObject* owner,
        const QString& key,
        const QList<ResultTableHost*>& hosts,
        std::function<void()> action)
    {
        // 组提交不可静默缩小目标集合；缺少任一宿主时拒绝整份原子更新。
        if (hosts.isEmpty())
        {
            return UiCommitSubmission::Rejected;
        }
        for (ResultTableHost* const host : hosts)
        {
            if (host == nullptr || host->view() == nullptr)
            {
                return UiCommitSubmission::Rejected;
            }
        }
        UiCommitCoordinator* const coordinator = UiCommitCoordinator::forApplication();
        if (coordinator == nullptr)
        {
            return UiCommitSubmission::Rejected;
        }
        return coordinator->submit(owner, key, groupViews(hosts), std::move(action));
    }
}
