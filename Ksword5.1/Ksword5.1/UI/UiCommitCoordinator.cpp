#include "UiCommitCoordinator.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QComboBox>
#include <QEvent>
#include <QKeyEvent>
#include <QTimer>
#include <QWidget>

#include <algorithm>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    // 保留已有属性名，使菜单状态与存量表格代码的观察结果一致。
    constexpr char kMenuDepthProperty[] = "KSWORD_TABLE_CONTEXT_MENU_DEPTH";
    constexpr char kCoordinatorName[] = "ksword_ui_commit_coordinator";

    bool realLeftCtrlHeld()
    {
        return (::GetAsyncKeyState(VK_LCONTROL) & 0x8000) != 0;
    }

    // Qt 下拉列表位于独立 Popup，父控件用于区分下拉列表与业务 QMenu。
    bool realComboPopupOpen()
    {
        QWidget* const popup = QApplication::activePopupWidget();
        return popup != nullptr && qobject_cast<QComboBox*>(popup->parentWidget()) != nullptr;
    }
}

namespace ks::ui
{
    UiCommitCoordinator::UiCommitCoordinator(
        QApplication* application,
        UiCommitInteractionProbes probes)
        : QObject(application)
        , m_application(application)
        , m_probes(std::move(probes))
    {
        // 默认探针保持只检测左 Ctrl 的已有产品行为，右 Ctrl 不阻塞刷新。
        if (!m_probes.leftCtrlHeld)
        {
            m_probes.leftCtrlHeld = realLeftCtrlHeld;
        }
        if (!m_probes.comboPopupOpen)
        {
            m_probes.comboPopupOpen = realComboPopupOpen;
        }
        if (application != nullptr)
        {
            application->installEventFilter(this);
        }
    }

    UiCommitCoordinator::~UiCommitCoordinator()
    {
        // Qt 清理事件过滤器和所有 queued 回调；释放快照捕获，不再执行提交。
        if (!m_application.isNull())
        {
            m_application->removeEventFilter(this);
        }
    }

    UiCommitCoordinator* UiCommitCoordinator::forApplication(QApplication* application)
    {
        if (application == nullptr)
        {
            application = qobject_cast<QApplication*>(QCoreApplication::instance());
        }
        if (application == nullptr)
        {
            return nullptr;
        }
        // 不使用进程静态裸指针；QApplication 重建后得到新的生命周期对象。
        for (QObject* const child : application->children())
        {
            if (child->objectName() == QLatin1String(kCoordinatorName))
            {
                return static_cast<UiCommitCoordinator*>(child);
            }
        }
        auto* const coordinator = new UiCommitCoordinator(application);
        coordinator->setObjectName(QLatin1String(kCoordinatorName));
        return coordinator;
    }

    bool UiCommitCoordinator::inputBlocked() const
    {
        return m_probes.leftCtrlHeld() || m_probes.comboPopupOpen();
    }

    bool UiCommitCoordinator::isBlocked(const QList<QAbstractItemView*>& views) const
    {
        if (inputBlocked())
        {
            return true;
        }
        return std::any_of(views.cbegin(), views.cend(), [](const QAbstractItemView* view)
        {
            return view != nullptr && view->property(kMenuDepthProperty).toInt() > 0;
        });
    }

    // 屏障解除时仍以完整目标集合复查，任一目标销毁意味着原子提交不可执行。
    bool UiCommitCoordinator::targetsAlive(const PendingCommit& pending) const
    {
        return !pending.owner.isNull() && std::all_of(
            pending.views.cbegin(), pending.views.cend(), [](const auto& view)
            {
                return !view.isNull();
            });
    }

    bool UiCommitCoordinator::pendingBlocked(const PendingCommit& pending) const
    {
        QList<QAbstractItemView*> views;
        views.reserve(pending.views.size());
        for (const auto& view : pending.views)
        {
            views.append(view.data());
        }
        return isBlocked(views);
    }

    void UiCommitCoordinator::removeMatching(QObject* owner, const QString& key)
    {
        m_pending.erase(std::remove_if(m_pending.begin(), m_pending.end(),
            [owner, &key](const PendingCommit& pending)
            {
                return pending.owner.data() == owner && pending.key == key;
            }), m_pending.end());
    }

    // 立即释放被销毁页面的捕获快照，避免下拉菜单长期开启时保留大块数据。
    void UiCommitCoordinator::watchOwner(QObject* owner)
    {
        if (m_watchedOwners.contains(owner))
        {
            return;
        }
        m_watchedOwners.insert(owner);
        connect(owner, &QObject::destroyed, this, [this, owner]()
        {
            m_watchedOwners.remove(owner);
            m_pending.erase(std::remove_if(m_pending.begin(), m_pending.end(),
                [](const PendingCommit& pending)
                {
                    return pending.owner.isNull();
                }), m_pending.end());
        });
    }

    bool UiCommitCoordinator::deferIfBlocked(
        QObject* owner,
        const QString& key,
        const QList<QAbstractItemView*>& views,
        std::function<void()> action)
    {
        return deferChecked(owner, key, views, action);
    }

    // 同一次输入状态只查询一次；未阻塞时保留 action，避免两次探针间松键丢提交。
    bool UiCommitCoordinator::deferChecked(
        QObject* owner,
        const QString& key,
        const QList<QAbstractItemView*>& views,
        std::function<void()>& action)
    {
        if (owner == nullptr || key.isEmpty() || !action)
        {
            return false;
        }
        // 先淘汰同键旧提交。松开 Ctrl 后先收到新快照时，旧快照不可随后覆盖它。
        removeMatching(owner, key);
        if (!isBlocked(views))
        {
            if (!m_pending.isEmpty())
            {
                notifyInteractionEnded();
            }
            return false;
        }
        PendingCommit pending;
        pending.owner = owner;
        pending.key = key;
        pending.action = std::move(action);
        for (QAbstractItemView* const view : views)
        {
            if (view != nullptr)
            {
                pending.views.append(view);
            }
        }
        watchOwner(owner);
        m_pending.append(std::move(pending));
        return true;
    }

    UiCommitSubmission UiCommitCoordinator::submit(
        QObject* owner,
        const QString& key,
        const QList<QAbstractItemView*>& views,
        std::function<void()> action)
    {
        if (owner == nullptr || key.isEmpty() || !action)
        {
            return UiCommitSubmission::Rejected;
        }
        // 屏障检测与动作接管共用一次判断，只有缓存路径移动捕获快照。
        if (deferChecked(owner, key, views, action))
        {
            return UiCommitSubmission::Deferred;
        }
        action();
        return UiCommitSubmission::Executed;
    }

    void UiCommitCoordinator::beginContextMenu(QAbstractItemView* view)
    {
        if (view != nullptr)
        {
            view->setProperty(kMenuDepthProperty, view->property(kMenuDepthProperty).toInt() + 1);
        }
    }

    void UiCommitCoordinator::endContextMenu(QAbstractItemView* view)
    {
        const QPointer<QAbstractItemView> guardedView(view);
        // Hide 位于 QMenu::exec 返回之前，延后才能保护原 action 捕获的行身份。
        QTimer::singleShot(0, this, [this, guardedView]()
        {
            if (!guardedView.isNull())
            {
                guardedView->setProperty(kMenuDepthProperty,
                    std::max(0, guardedView->property(kMenuDepthProperty).toInt() - 1));
            }
            flush();
        });
    }

    void UiCommitCoordinator::notifyInteractionEnded()
    {
        if (m_flushScheduled || m_pending.isEmpty())
        {
            return;
        }
        m_flushScheduled = true;
        QTimer::singleShot(0, this, [this]()
        {
            m_flushScheduled = false;
            flush();
        });
    }

    void UiCommitCoordinator::flush()
    {
        if (m_flushing)
        {
            return;
        }
        m_flushing = true;
        for (qsizetype index = 0; index < m_pending.size();)
        {
            if (!targetsAlive(m_pending.at(index)))
            {
                m_pending.removeAt(index);
                continue;
            }
            if (pendingBlocked(m_pending.at(index)))
            {
                ++index;
                continue;
            }
            // 移出记录后才执行用户代码，重入改变队列不会留下悬空引用。
            PendingCommit pending = std::move(m_pending[index]);
            m_pending.removeAt(index);
            const QPointer<UiCommitCoordinator> self(this);
            pending.action();
            // 回调可能关闭整个应用或销毁协调器，不再访问已释放的成员。
            if (self.isNull())
            {
                return;
            }
            index = 0;
        }
        m_flushing = false;
    }

    qsizetype UiCommitCoordinator::pendingCount() const
    {
        return m_pending.size();
    }

    bool UiCommitCoordinator::eventFilter(QObject* watched, QEvent* event)
    {
        if (event != nullptr)
        {
            // 只把释放事件作为调度提示，flush 始终重查真实左 Ctrl 状态。
            if (event->type() == QEvent::KeyRelease)
            {
                const auto* const key = static_cast<QKeyEvent*>(event);
                if (key->key() == Qt::Key_Control && !key->isAutoRepeat())
                {
                    notifyInteractionEnded();
                }
            }
            else if (event->type() == QEvent::Hide)
            {
                QWidget* const hidden = qobject_cast<QWidget*>(watched);
                if (hidden != nullptr && qobject_cast<QComboBox*>(hidden->parentWidget()) != nullptr)
                {
                    notifyInteractionEnded();
                }
            }
        }
        return QObject::eventFilter(watched, event);
    }
}
