#include "TaskSnapshotFeed.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QCoreApplication>
#include <QThread>
#include <QTimer>
#include <algorithm>

namespace ks::ui
{
    TaskSnapshotFeed& TaskSnapshotFeed::instance()
    {
        // QPointer 随 QApplication 的子对象析构清空，离屏夹具重建应用也不会借旧对象。
        static QPointer<TaskSnapshotFeed> feed;
        if (feed == nullptr)
        {
            feed = new TaskSnapshotFeed(QCoreApplication::instance());
        }
        return *feed;
    }

    TaskSnapshotFeed::TaskSnapshotFeed(QObject* const parent)
        : QObject(parent), m_snapshot(kPro.SnapshotWithRevision())
    {
        // 只保留一处任务轮询；日志过期和通知布局仍由通知端自己的定时器负责。
        m_timer = new QTimer(this);
        m_timer->setInterval(100);
        connect(m_timer, &QTimer::timeout, this, [this]() { refreshNow(); });
        m_timer->start();
    }

    void TaskSnapshotFeed::subscribe(QObject* const receiver, Consumer consumer)
    {
        // UI 订阅者与发布器同线程，禁止把 QObject 生命周期检查搬到工作线程。
        if (receiver == nullptr || !consumer || receiver->thread() != thread() ||
            QThread::currentThread() != thread())
        {
            return;
        }
        // 刷新会执行已有消费者，它们可能同步销毁准备订阅的 receiver 或整个 feed。
        const QPointer<TaskSnapshotFeed> self(this);
        const QPointer<QObject> guardedReceiver(receiver);
        refreshNow();
        if (self.isNull() || guardedReceiver.isNull())
        {
            return;
        }
        m_subscriptions.push_back({ receiver, std::move(consumer) });
        // 首发用局部副本，回调内新增订阅导致 vector 扩容也不移动正在执行的 callable。
        const Consumer firstConsumer = m_subscriptions.back().consumer;
        const Snapshot firstSnapshot = m_snapshot; // 首发回调不能借可被重入刷新的成员引用。
        firstConsumer(firstSnapshot);
    }

    TaskSnapshotFeed::Snapshot TaskSnapshotFeed::current() const
    {
        return m_snapshot;
    }

    void TaskSnapshotFeed::refreshNow()
    {
        // 消费者可能修改任务并再次请求发布；当前订阅表必须先完整消费同一版。
        if (m_publishing)
        {
            m_refreshRequested = true;
            return;
        }
        kPro.expireVisibleTerminals();
        const Snapshot snapshot = kPro.SnapshotWithRevision(); // 两视图共享此版，不分别拷贝。
        // 无任务变化时也摘掉死亡订阅者，空页面反复打开/关闭不会累积回调对象。
        m_subscriptions.erase(std::remove_if(m_subscriptions.begin(), m_subscriptions.end(),
            [](const Subscription& subscription) { return subscription.receiver.isNull(); }),
            m_subscriptions.end());
        if (snapshot == m_snapshot)
        {
            return;
        }
        m_snapshot = snapshot;
        // 复制订阅表允许回调里创建或销毁其他视图；本次仍只提交同一个快照版本。
        const auto subscriptions = m_subscriptions;
        m_publishing = true;
        for (const Subscription& subscription : subscriptions)
        {
            if (subscription.receiver != nullptr)
            {
                const QPointer<TaskSnapshotFeed> self(this); // 宿主应用可被消费者同步关闭。
                subscription.consumer(snapshot);
                if (self.isNull())
                {
                    return;
                }
            }
        }
        m_publishing = false;
        if (m_refreshRequested)
        {
            m_refreshRequested = false;
            QTimer::singleShot(0, this, [this]() { refreshNow(); });
        }
    }

    QString TaskStateText(const kProgressState state)
    {
        // 状态来自数据枚举，文案仅负责展示，不能反向解析步骤文字猜测结果。
        switch (state)
        {
        case kProgressState::Running:
            return ks::i18n::contextText(QStringLiteral("progress.state.running"), QStringLiteral("进行中"));
        case kProgressState::Waiting:
            return ks::i18n::contextText(QStringLiteral("progress.state.waiting"), QStringLiteral("等待选择"));
        case kProgressState::LegacyCompleted:
            return ks::i18n::contextText(QStringLiteral("progress.state.completed"), QStringLiteral("已结束（结果未指定）"));
        case kProgressState::Success:
            return ks::i18n::contextText(QStringLiteral("progress.state.success"), QStringLiteral("已完成"));
        case kProgressState::Failure:
            return ks::i18n::contextText(QStringLiteral("progress.state.failure"), QStringLiteral("失败"));
        case kProgressState::Canceled:
            return ks::i18n::contextText(QStringLiteral("progress.state.canceled"), QStringLiteral("已取消"));
        }
        return QString();
    }

    QColor TaskStateColor(const kProgressState state)
    {
        switch (state)
        {
        case kProgressState::Success: return KswordTheme::SuccessColor();
        case kProgressState::Failure: return KswordTheme::ErrorColor();
        case kProgressState::Waiting: return KswordTheme::WarningColor();
        case kProgressState::Canceled:
        case kProgressState::LegacyCompleted: return KswordTheme::TextSecondaryColor();
        case kProgressState::Running: return KswordTheme::PrimaryAccentColor();
        }
        return KswordTheme::TextPrimaryColor();
    }
}
