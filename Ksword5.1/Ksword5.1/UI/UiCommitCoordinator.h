#pragma once

// UI 提交协调器只管理交互屏障和刷新生命周期，不持有业务数据或模型。
#include <QList>
#include <QMetaObject>
#include <QObject>
#include <QPointer>
#include <QSet>
#include <QString>
#include <QVector>

#include <functional>

class QApplication;
class QAbstractItemView;
class QEvent;

namespace ks::ui
{
    // 可替换的物理输入探针供离屏回归使用；未提供时读取真实左 Ctrl/下拉弹层。
    struct UiCommitInteractionProbes
    {
        std::function<bool()> leftCtrlHeld;   // 左 Ctrl 是否仍按住。
        std::function<bool()> comboPopupOpen; // 下拉弹层是否仍占用输入。
    };

    // 提交结果区分无效调用、当前完成和已缓存，便于业务显式安排快照提交。
    enum class UiCommitSubmission
    {
        Rejected,
        Executed,
        Deferred
    };

    class UiCommitCoordinator final : public QObject
    {
    public:
        // 以 application 管理生命周期并观察释放事件；探针仅影响物理输入判据。
        explicit UiCommitCoordinator(
            QApplication* application,
            UiCommitInteractionProbes probes = {});
        ~UiCommitCoordinator() override;

        // 返回应用唯一协调器；必须在 GUI 线程调用，空应用返回 nullptr。
        static UiCommitCoordinator* forApplication(QApplication* application = nullptr);

        // 任一目标菜单打开或物理输入屏障存在时返回 true。
        bool isBlocked(const QList<QAbstractItemView*>& views) const;

        // 兼容旧接口：仅在阻塞时接管 action；false 时由调用者立即提交。
        // 同 owner/key 的新提交取代旧提交，包括解除屏障后的立即提交。
        bool deferIfBlocked(
            QObject* owner,
            const QString& key,
            const QList<QAbstractItemView*>& views,
            std::function<void()> action);

        // 新接口在未阻塞时直接执行；阻塞时只保留同键最后一份原子提交。
        UiCommitSubmission submit(
            QObject* owner,
            const QString& key,
            const QList<QAbstractItemView*>& views,
            std::function<void()> action);

        // 菜单开始增加深度，结束延至外层事件循环，避免业务 action 仍使用旧行。
        void beginContextMenu(QAbstractItemView* view);
        void endContextMenu(QAbstractItemView* view);

        // 释放事件合并调度一次复查；flush 每次执行前再次确认所有目标仍存活。
        void notifyInteractionEnded();
        void flush();
        qsizetype pendingCount() const;

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override;

    private:
        // 一条待提交记录是一组视图的原子更新，不拆分 TCP/UDP 等关联结果。
        struct PendingCommit
        {
            QPointer<QObject> owner;                    // 回调生命周期所有者。
            QString key;                              // 所有者内部去重键。
            QList<QPointer<QAbstractItemView>> views;  // 本次原子更新的目标集合。
            std::function<void()> action;             // 最新快照对应的提交动作。
        };

        bool inputBlocked() const;
        bool deferChecked(
            QObject* owner,
            const QString& key,
            const QList<QAbstractItemView*>& views,
            std::function<void()>& action);
        bool pendingBlocked(const PendingCommit& pending) const;
        bool targetsAlive(const PendingCommit& pending) const;
        void removeMatching(QObject* owner, const QString& key);
        void watchOwner(QObject* owner);

        QPointer<QApplication> m_application;      // 安装事件过滤器的应用。
        UiCommitInteractionProbes m_probes;        // 输入判据，默认读取真实状态。
        QVector<PendingCommit> m_pending;          // 最新到达顺序的待提交队列。
        QSet<QObject*> m_watchedOwners;            // 已建立销毁回调的所有者。
        bool m_flushScheduled = false;            // 防止重复安排空闲回投。
        bool m_flushing = false;                   // 防止嵌套事件循环重复遍历队列。
    };
}
