#include "../Framework.h"
#include "NotificationCardManager.h"

#include <algorithm>  // std::find_if
#include <cmath>      // std::isfinite
#include <utility>    // std::move

#include <QApplication> // QApplication::instance
#include <QCoreApplication> // QCoreApplication::instance
#include <QEventLoop> // 非模态选项窗口等待结果时保持 UI 事件处理
#include <QGuiApplication>
#include <QMessageBox>  // 阻塞式按钮选择对话框
#include <QMetaObject>  // invokeMethod
#include <QObject>      // qobject_cast
#include <QPushButton>  // QMessageBox::addButton 返回按钮类型
#include <QThread>      // 判断当前线程是否 UI 线程
#include <QScreen>
#include <QWindow>

#include <atomic>
#include <chrono> // 终态展示使用单调时钟，系统时间调整不会延长卡片寿命。

namespace
{
    std::atomic_uint g_nonModalOptionDialogSequence{ 0 };
    constexpr std::size_t kMaximumTerminalTaskHistory = 256U;
    constexpr std::uint64_t kTerminalPresentationDurationMs = 4000U;

    // steadyMilliseconds：单调时钟毫秒，仅用于比较终态卡片展示期限。
    std::uint64_t steadyMilliseconds()
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    // findTaskByPidMutable 作用：
    // - 在可写任务容器中按 PID 查找任务迭代器。
    // 参数 tasks：任务容器（可写）。
    // 参数 pid：目标 PID。
    // 返回值：找到则返回对应迭代器，否则返回 end()。
    std::vector<kProgressTask>::iterator findTaskByPidMutable(
        std::vector<kProgressTask>& tasks,
        const int pid)
    {
        return std::find_if(
            tasks.begin(),
            tasks.end(),
            [pid](const kProgressTask& taskItem) { return taskItem.pid == pid; });
    }

    // showOptionsDialogOnUiThread 作用：
    // - 在 UI 线程创建并执行阻塞式选项对话框；
    // - 返回用户点击的是第几个按钮（从 1 开始）。
    // 参数 prompt：提示文本。
    // 参数 options：按钮文本数组。
    // 返回值：
    // - 1..N 表示用户选择；
    // - 0 表示关闭窗口或没有选择。
    int showOptionsDialogNonModalOnUiThread(
        const std::string& prompt,
        const std::vector<std::string>& options)
    {
        QMessageBox optionDialog(ks::ui::notificationCardHostWindow());
        optionDialog.setWindowTitle(QStringLiteral("任务操作"));
        optionDialog.setIcon(QMessageBox::Question);
        optionDialog.setText(QString::fromUtf8(prompt.c_str()));
        optionDialog.setWindowModality(Qt::NonModal);
        optionDialog.setModal(false);

        std::vector<QAbstractButton*> buttonHandles;
        buttonHandles.reserve(options.size());
        for (const std::string& optionText : options)
        {
            QAbstractButton* optionButton = optionDialog.addButton(
                QString::fromUtf8(optionText.c_str()),
                QMessageBox::ActionRole);
            buttonHandles.push_back(optionButton);
        }

        int selectedIndex = 0;
        QEventLoop resultLoop;
        QObject::connect(&optionDialog, &QMessageBox::finished, &resultLoop, [&]() {
            QAbstractButton* clickedButton = optionDialog.clickedButton();
            for (std::size_t index = 0; index < buttonHandles.size(); ++index)
            {
                if (buttonHandles[index] == clickedButton)
                {
                    selectedIndex = static_cast<int>(index + 1);
                    break;
                }
            }
            resultLoop.quit();
        });

        optionDialog.show();
        QScreen* targetScreen = nullptr;
        QWidget* hostWindow = ks::ui::notificationCardHostWindow();
        if (hostWindow != nullptr)
        {
            targetScreen = QGuiApplication::screenAt(hostWindow->frameGeometry().center());
            if (targetScreen == nullptr && hostWindow->windowHandle() != nullptr)
            {
                targetScreen = hostWindow->windowHandle()->screen();
            }
        }
        if (targetScreen == nullptr)
        {
            targetScreen = QGuiApplication::primaryScreen();
        }
        if (targetScreen != nullptr)
        {
            const QRect availableRect = targetScreen->availableGeometry();
            const unsigned int sequence = g_nonModalOptionDialogSequence.fetch_add(1);
            const int offset = static_cast<int>(sequence % 8U) * 26;
            optionDialog.move(
                availableRect.center() - QPoint(optionDialog.width() / 2, optionDialog.height() / 2)
                + QPoint(offset, offset));
        }
        optionDialog.raise();
        resultLoop.exec();
        return selectedIndex;
    }

    int showOptionsDialogOnUiThread(
        const int pid,
        const std::string& prompt,
        const std::vector<std::string>& options)
    {
        // 无选项直接返回 0，避免弹出空对话框。
        if (options.empty())
        {
            return 0;
        }

        if (ks::ui::isProgressTaskNotificationOverflowed(pid))
        {
            // 溢出任务使用非模态窗口：调用方仍拿到原有同步返回值，主 UI 则继续处理事件。
            return showOptionsDialogNonModalOnUiThread(prompt, options);
        }

        QMessageBox optionDialog;
        optionDialog.setWindowTitle(QStringLiteral("任务操作"));
        optionDialog.setIcon(QMessageBox::Question);
        optionDialog.setText(QString::fromUtf8(prompt.c_str()));

        // 把选项按顺序追加为按钮，并记录映射关系。
        std::vector<QAbstractButton*> buttonHandles;
        buttonHandles.reserve(options.size());
        for (const std::string& optionText : options)
        {
            QAbstractButton* optionButton = optionDialog.addButton(
                QString::fromUtf8(optionText.c_str()),
                QMessageBox::ActionRole);
            buttonHandles.push_back(optionButton);
        }

        // 阻塞执行，直到用户点某个按钮或关闭窗口。
        optionDialog.exec();
        QAbstractButton* clickedButton = optionDialog.clickedButton();
        if (clickedButton == nullptr)
        {
            return 0;
        }

        // 把按钮指针反查回 1-based 序号。
        for (std::size_t index = 0; index < buttonHandles.size(); ++index)
        {
            if (buttonHandles[index] == clickedButton)
            {
                return static_cast<int>(index + 1);
            }
        }
        return 0;
    }
} // namespace

// 全局进度管理器定义（extern 声明位于 Framework.h）。
kProgress kPro;

kProgress::kProgress() = default;

kProgress::~kProgress()
{
    // 管理器可能是离屏夹具或嵌入宿主的局部对象，不能留下悬空 this 回调。
    for (const auto& ownerConnection : m_ownerConnections)
    {
        QObject::disconnect(ownerConnection.second);
    }
}

int kProgress::add(const std::string& taskName, const std::string& stepName)
{
    return addInternal(nullptr, taskName, stepName, false);
}

int kProgress::add(
    QObject* const owner,
    const std::string& taskName,
    const std::string& stepName)
{
    return addInternal(owner, taskName, stepName, false);
}

int kProgress::addReusable(
    QObject* const owner,
    const std::string& taskName,
    const std::string& stepName)
{
    return addInternal(owner, taskName, stepName, true);
}

int kProgress::addInternal(
    QObject* const owner,
    const std::string& taskName,
    const std::string& stepName,
    const bool retainedForReuse)
{
    int newPid = 0;
    bool shouldBindOwner = false;

    // owner 必须在自身线程仍存活时登记，避免 connect 与析构在两个线程竞态借用 QObject。
    if (owner != nullptr && owner->thread() != QThread::currentThread())
    {
        return 0;
    }

    {
        std::lock_guard<std::mutex> lockGuard(m_mutex);

        // 同一 owner 的同名可复用任务只有一个槽；再次登记不清空在途状态。
        if (retainedForReuse && owner != nullptr)
        {
            for (const kProgressTask& existing : m_tasks)
            {
                const auto ownerIterator = m_taskOwners.find(existing.pid);
                if (existing.retainedForReuse && existing.taskName == taskName &&
                    ownerIterator != m_taskOwners.end() && ownerIterator->second == owner)
                {
                    return existing.pid;
                }
            }
        }

        // 分配 PID，并创建初始任务对象。
        newPid = m_nextPid++;
        kProgressTask newTask;
        newTask.pid = newPid;
        newTask.taskName = taskName;
        newTask.stepName = stepName;
        newTask.stepCode = 0;
        newTask.progress = 0.0f;
        newTask.hiddenInList = false;
        newTask.hideProgressBarTemporarily = false;
        newTask.retainedForReuse = retainedForReuse;

        // 追加到容器并递增修订号，驱动 UI 刷新。
        m_tasks.push_back(std::move(newTask));
        if (owner != nullptr)
        {
            m_taskOwners.emplace(newPid, owner);
            shouldBindOwner = m_boundOwners.insert(owner).second;
        }
        ++m_revision;
    }

    if (shouldBindOwner)
    {
        // 同一 owner 只连接一次；回调批量删除该页面创建的全部任务。
        const QMetaObject::Connection ownerDestroyedConnection = QObject::connect(
            owner,
            &QObject::destroyed,
            [this, owner](QObject*)
            {
                removeTasksOwnedBy(owner);
            });
        if (!ownerDestroyedConnection)
        {
            // owner 已无法建立生命周期绑定时，不保留无法自动回收的任务。
            removeTasksOwnedBy(owner);
        }
        else
        {
            std::lock_guard<std::mutex> lockGuard(m_mutex);
            m_ownerConnections.emplace(owner, ownerDestroyedConnection);
        }
    }

    return newPid;
}

void kProgress::set(const int pid, const std::string& stepName, const int stepCode, const float progressValue)
{
    setInternal(pid, 0, false, stepName, stepCode, progressValue);
}

void kProgress::set(const int pid, const std::uint64_t generation,
    const std::string& stepName, const int stepCode, const float progressValue)
{
    setInternal(pid, generation, true, stepName, stepCode, progressValue);
}

void kProgress::setInternal(const int pid, const std::uint64_t generation, const bool guarded,
    const std::string& stepName, const int stepCode, const float progressValue)
{
    std::lock_guard<std::mutex> lockGuard(m_mutex);

    // 查找目标任务，找不到则静默返回，避免中断业务流程。
    const auto taskIterator = findTaskByPidMutable(m_tasks, pid);
    if (taskIterator == m_tasks.end())
    {
        return;
    }

    // 新接口必须匹配轮次；显式开启的任务拒绝无轮次旧结果。
    if ((guarded && generation != taskIterator->generation) ||
        (!guarded && taskIterator->generationGuarded))
    {
        return;
    }
    const float normalized = normalizeProgress(progressValue);
    if (IsProgressTerminal(taskIterator->state))
    {
        // 一次任务与带令牌更新不会复活终态；旧复用周期保留原有 set(<100%) 行为。
        if (guarded || !taskIterator->retainedForReuse || normalized >= 1.0f ||
            taskIterator->state != kProgressState::LegacyCompleted)
        {
            return;
        }
        ++taskIterator->generation;
    }
    if (taskIterator->stepName == stepName && taskIterator->stepCode == stepCode &&
        taskIterator->progress == normalized && !IsProgressTerminal(taskIterator->state))
    {
        return;
    }

    // 更新步骤文本、业务状态码与进度值。
    taskIterator->stepName = stepName;
    taskIterator->stepCode = stepCode;
    taskIterator->progress = normalized;
    // 等待选项时后台仍可更新已完成比例；Waiting 只由本轮对话框关闭或终态解除。
    const bool wasWaiting = taskIterator->state == kProgressState::Waiting;
    taskIterator->state = normalized >= 1.0f ? kProgressState::LegacyCompleted
        : (wasWaiting ? kProgressState::Waiting : kProgressState::Running);
    taskIterator->visibleUntilMs = 0;

    // 当进度到 1.0 时隐藏卡片（满足“完成后隐藏”需求）。
    taskIterator->hiddenInList = (taskIterator->progress >= 1.0f);

    // 完成状态下不再需要临时隐藏逻辑，统一复位。
    if (taskIterator->hiddenInList)
    {
        taskIterator->hideProgressBarTemporarily = false;
    }

    // 数据变更后递增修订号，通知 UI 重绘。
    ++m_revision;

    if (taskIterator->hiddenInList)
    {
        pruneTerminalHistoryLocked();
    }
}

bool kProgress::finish(const int pid, const kProgressState state,
    const std::string& stepName, const int stepCode)
{
    return finishInternal(pid, 0, false, state, stepName, stepCode);
}

bool kProgress::finish(const int pid, const std::uint64_t generation, const kProgressState state,
    const std::string& stepName, const int stepCode)
{
    return finishInternal(pid, generation, true, state, stepName, stepCode);
}

bool kProgress::finishInternal(const int pid, const std::uint64_t generation, const bool guarded,
    const kProgressState state, const std::string& stepName, const int stepCode)
{
    // 只有明确结果可以使用 finish；LegacyCompleted 专供兼容旧百分比调用。
    if (state != kProgressState::Success && state != kProgressState::Failure &&
        state != kProgressState::Canceled)
    {
        return false;
    }
    std::lock_guard<std::mutex> lockGuard(m_mutex);
    const auto task = findTaskByPidMutable(m_tasks, pid);
    if (task == m_tasks.end() || IsProgressTerminal(task->state) ||
        (guarded && generation != task->generation) || (!guarded && task->generationGuarded))
    {
        return false;
    }
    // 失败和取消不伪装成 100% 成功；状态决定终态，进度只表示实际执行比例。
    task->state = state;
    task->stepName = stepName;
    task->stepCode = stepCode;
    if (state == kProgressState::Success)
    {
        task->progress = 1.0f;
    }
    task->hiddenInList = false;
    task->hideProgressBarTemporarily = true;
    task->visibleUntilMs = steadyMilliseconds() + kTerminalPresentationDurationMs;
    ++m_revision;
    pruneTerminalHistoryLocked();
    return true;
}

std::uint64_t kProgress::beginCycle(const int pid, const std::string& stepName)
{
    std::lock_guard<std::mutex> lockGuard(m_mutex);
    const auto task = findTaskByPidMutable(m_tasks, pid);
    if (task == m_tasks.end() || !task->retainedForReuse)
    {
        return 0;
    }
    // 调用方保存本次令牌；上一轮 set/finish、选项恢复均无法覆盖此轮。
    ++task->generation;
    task->generationGuarded = true;
    task->state = kProgressState::Running;
    task->stepName = stepName;
    task->stepCode = 0;
    task->progress = 0;
    task->hiddenInList = false;
    task->hideProgressBarTemporarily = false;
    task->visibleUntilMs = 0;
    ++m_revision;
    return task->generation;
}

void kProgress::expireVisibleTerminals()
{
    const std::uint64_t now = steadyMilliseconds(); // 当前单调时间，不借用 QWidget。
    std::lock_guard<std::mutex> lockGuard(m_mutex);
    bool changed = false;
    for (kProgressTask& task : m_tasks)
    {
        if (!task.hiddenInList && IsProgressTerminal(task.state) &&
            task.visibleUntilMs != 0 && task.visibleUntilMs <= now)
        {
            task.hiddenInList = true;
            changed = true;
        }
    }
    if (changed)
    {
        ++m_revision;
    }
}

int kProgress::UI(const int pid, const std::string& prompt, const std::vector<std::string>& options)
{
    // 选项等待和恢复绑定本轮令牌；嵌套事件循环里重启的任务不会被旧选择覆盖。
    std::uint64_t generation = 0;
    const auto snapshot = SnapshotWithRevision();
    for (const kProgressTask& task : snapshot->tasks)
    {
        if (task.pid == pid && !IsProgressTerminal(task.state))
        {
            generation = task.generation;
            break;
        }
    }
    if (generation == 0)
    {
        return 0;
    }
    // 弹框前先临时隐藏目标任务进度条。
    setProgressBarHiddenForUi(pid, true, generation);

    // 通过 Qt 应用对象拿到 UI 线程上下文。
    QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
    if (appInstance == nullptr)
    {
        // 无 QApplication 时无法弹窗，恢复进度条并返回 0。
        setProgressBarHiddenForUi(pid, false, generation);
        return 0;
    }

    int selectedIndex = 0;

    // 若当前就是 UI 线程，直接弹框；否则阻塞调用到 UI 线程执行。
    if (QThread::currentThread() == appInstance->thread())
    {
        selectedIndex = showOptionsDialogOnUiThread(pid, prompt, options);
    }
    else
    {
        QMetaObject::invokeMethod(
            appInstance,
            [&selectedIndex, &prompt, &options, pid]()
            {
                selectedIndex = showOptionsDialogOnUiThread(pid, prompt, options);
            },
            Qt::BlockingQueuedConnection);
    }

    // 弹框结束后恢复进度条显示状态。
    setProgressBarHiddenForUi(pid, false, generation);
    return selectedIndex;
}

std::vector<kProgressTask> kProgress::Snapshot() const
{
    return SnapshotWithRevision()->tasks;
}

std::shared_ptr<const kProgressSnapshot> kProgress::SnapshotWithRevision() const
{
    std::lock_guard<std::mutex> lockGuard(m_mutex);
    // 相同 revision 返回同一不可变副本；不会出现先读取修订号、再拿到另一版 tasks。
    if (!m_sharedSnapshot || m_sharedSnapshot->revision != m_revision)
    {
        auto snapshot = std::make_shared<kProgressSnapshot>();
        snapshot->revision = m_revision;
        snapshot->tasks = m_tasks;
        m_sharedSnapshot = std::move(snapshot);
    }
    return m_sharedSnapshot;
}

std::size_t kProgress::Revision() const
{
    std::lock_guard<std::mutex> lockGuard(m_mutex);
    return m_revision;
}

float kProgress::normalizeProgress(const float rawProgress)
{
    // 非有限值直接按 0 处理，避免 NaN/Inf 污染 UI。
    if (!std::isfinite(rawProgress))
    {
        return 0.0f;
    }

    // 兼容两种输入格式：
    // 1) 0~1   ：比例格式；
    // 2) 0~100 ：百分比格式（如 70.0f）。
    float normalizedValue = rawProgress;
    if (normalizedValue > 1.0f)
    {
        normalizedValue /= 100.0f;
    }

    // 进度钳制到 [0,1] 区间，确保进度条安全显示。
    if (normalizedValue < 0.0f)
    {
        normalizedValue = 0.0f;
    }
    if (normalizedValue > 1.0f)
    {
        normalizedValue = 1.0f;
    }
    return normalizedValue;
}

void kProgress::pruneTerminalHistoryLocked()
{
    const std::size_t terminalTaskCount = static_cast<std::size_t>(std::count_if(
        m_tasks.cbegin(),
        m_tasks.cend(),
        [](const kProgressTask& taskItem)
        {
            return IsProgressTerminal(taskItem.state) && !taskItem.retainedForReuse;
        }));
    if (terminalTaskCount <= kMaximumTerminalTaskHistory)
    {
        return;
    }

    std::size_t tasksToRemove = terminalTaskCount - kMaximumTerminalTaskHistory;
    m_tasks.erase(
        std::remove_if(
            m_tasks.begin(),
            m_tasks.end(),
            [this, &tasksToRemove](const kProgressTask& taskItem)
            {
                if (tasksToRemove == 0U ||
                    !IsProgressTerminal(taskItem.state) ||
                    taskItem.retainedForReuse)
                {
                    return false;
                }
                --tasksToRemove;
                m_taskOwners.erase(taskItem.pid);
                return true;
            }),
        m_tasks.end());
}

void kProgress::removeTasksOwnedBy(QObject* const owner)
{
    if (owner == nullptr)
    {
        return;
    }

    std::lock_guard<std::mutex> lockGuard(m_mutex);
    const std::size_t previousTaskCount = m_tasks.size();
    m_tasks.erase(
        std::remove_if(
            m_tasks.begin(),
            m_tasks.end(),
            [this, owner](const kProgressTask& taskItem)
            {
                const auto ownerIterator = m_taskOwners.find(taskItem.pid);
                if (ownerIterator == m_taskOwners.end() || ownerIterator->second != owner)
                {
                    return false;
                }
                m_taskOwners.erase(ownerIterator);
                return true;
            }),
        m_tasks.end());
    m_boundOwners.erase(owner);
    m_ownerConnections.erase(owner);

    if (m_tasks.size() != previousTaskCount)
    {
        ++m_revision;
    }
}

void kProgress::setProgressBarHiddenForUi(const int pid, const bool hidden, const std::uint64_t generation)
{
    std::lock_guard<std::mutex> lockGuard(m_mutex);

    // 查找 PID 对应任务，若不存在则直接返回。
    const auto taskIterator = findTaskByPidMutable(m_tasks, pid);
    if (taskIterator == m_tasks.end() || taskIterator->generation != generation ||
        IsProgressTerminal(taskIterator->state))
    {
        return;
    }

    // 卡片已因完成而隐藏时，无需再处理“进度条临时隐藏”状态。
    if (taskIterator->hiddenInList)
    {
        return;
    }

    // 仅在状态真正变化时递增修订号，避免无意义刷新。
    if (taskIterator->hideProgressBarTemporarily != hidden)
    {
        taskIterator->hideProgressBarTemporarily = hidden;
        taskIterator->state = hidden ? kProgressState::Waiting : kProgressState::Running;
        ++m_revision;
    }
}
