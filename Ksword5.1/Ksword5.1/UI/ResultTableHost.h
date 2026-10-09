#pragma once

// 结果表宿主显式声明模型、稳定列身份和交互能力，存量全局发现仍可接入。
#include "UiCommitCoordinator.h"
#include "VisibleTableWidget.h"

#include <QList>
#include <QObject>
#include <QPointer>
#include <QString>

#include <functional>
#include <optional>

class QAbstractItemModel;
class QEvent;
class QTableView;

namespace ks::ui
{
    struct ResultTableColumn
    {
        int modelColumn = -1; // 模型中的逻辑列号，视觉移动不改变其身份。
        QString stableId;     // 业务稳定键，不使用可能切换语言的表头文本。
    };

    // 空 optional 表示保留页面已有显式开关，避免全局接入覆盖专业视图例外。
    struct ResultTableCapabilities
    {
        bool normalizeHeader = true;                  // 是否应用统一表头基线。
        std::optional<bool> headerClickSorting;        // 一次性点击排序的显式策略。
        std::optional<TableActionBarMode> actionBar;   // 复用现有完整/紧凑/隐藏操作条。
    };

    class ResultTableHost final : public QObject
    {
    public:
        // ensure 返回目标视图唯一宿主，以视图为 Qt 父对象，不转移业务模型所有权。
        static ResultTableHost* ensure(QTableView* view);

        // 显式绑定模型和列定义；无效/重复列身份返回 false，不改变原视图。
        bool bindModel(
            QAbstractItemModel* model,
            const QList<ResultTableColumn>& columns,
            const ResultTableCapabilities& capabilities = {});

        // 全局动态接入使用当前模型；显示、模型换绑时刷新已有交互，不重复创建条。
        void refresh();
        QTableView* view() const;
        QAbstractItemModel* model() const;
        QString stableColumnId(int modelColumn) const;
        bool hasExplicitColumns() const;
        const ResultTableCapabilities& capabilities() const;

        // 多表组共享一次提交屏障；任一表菜单打开时整份快照一起延迟。
        static bool isGroupCommitBlocked(const QList<ResultTableHost*>& hosts);
        static bool deferGroupIfBlocked(
            QObject* owner,
            const QString& key,
            const QList<ResultTableHost*>& hosts,
            std::function<void()> action);
        // 新业务直接提交完整快照，不必手写先检查屏障再递归回投的模板。
        static UiCommitSubmission submitGroup(
            QObject* owner,
            const QString& key,
            const QList<ResultTableHost*>& hosts,
            std::function<void()> action);

    private:
        explicit ResultTableHost(QTableView* view);
        void observeModel(QAbstractItemModel* model);
        void scheduleRefresh();
        static QList<QAbstractItemView*> groupViews(const QList<ResultTableHost*>& hosts);

        QPointer<QTableView> m_view;                // 展示结果的原视图。
        QPointer<QAbstractItemModel> m_model;       // 当前绑定模型，保持业务所有权。
        QList<ResultTableColumn> m_columns;        // 逻辑列到稳定键的显式映射。
        ResultTableCapabilities m_capabilities;    // 页面声明的能力或存量默认值。
        bool m_explicitColumns = false;            // 是否使用业务定义而非兼容列号。
        bool m_refreshing = false;                 // 防止 QSS/属性变化造成同步重入。
        bool m_refreshScheduled = false;           // 合并模型结构变化的 queued 更新。
        QList<QMetaObject::Connection> m_modelConnections; // 换绑时明确断开旧模型信号。
    };
}
