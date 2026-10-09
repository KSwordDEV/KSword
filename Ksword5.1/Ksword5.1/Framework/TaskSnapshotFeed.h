#pragma once

#include "../Framework.h"

#include <QColor>
#include <QObject>
#include <QPointer>
#include <QString>
#include <functional>

class QTimer;

namespace ks::ui
{
    // TaskSnapshotFeed：应用级唯一任务快照发布器，两个显示端消费同一不可变版本。
    // subscribe 必须在 UI 线程调用；receiver 销毁后不再回调，不访问后台业务对象。
    class TaskSnapshotFeed final : public QObject
    {
    public:
        using Snapshot = std::shared_ptr<const kProgressSnapshot>;
        using Consumer = std::function<void(const Snapshot&)>;

        static TaskSnapshotFeed& instance(); // QApplication 持有，随应用销毁。
        void subscribe(QObject* receiver, Consumer consumer); // 首次立即发布，之后仅修订改变时发布。
        Snapshot current() const; // 返回最近共享版本，不再次复制任务集合。
        void refreshNow(); // 定时器和设置切换都走同一刷新入口。

    private:
        explicit TaskSnapshotFeed(QObject* parent);

        struct Subscription
        {
            QPointer<QObject> receiver; // 订阅者寿命门禁，只在 UI 线程读取。
            Consumer consumer;         // 业务不持有此对象，发布只更新视图。
        };

        QTimer* m_timer = nullptr;      // 两视图共用的 100 ms 采样器。
        Snapshot m_snapshot;           // 修订号和任务记录来自同一把核心锁。
        std::vector<Subscription> m_subscriptions; // 死亡订阅者在下一次发布前摘除。
        bool m_publishing = false;     // 消费者重入时不能让新版本先于本轮旧版本发布。
        bool m_refreshRequested = false; // 重入刷新合并到本轮结束后的 queued 回投。
    };

    // TaskStateText/TaskStateColor：两个任务视图共用翻译与主题语义，旧完成无成功配色。
    QString TaskStateText(kProgressState state);
    QColor TaskStateColor(kProgressState state);
}
