#include "BackgroundTaskRegistry.h"
#include "../Internationalization/LanguageManager.h"

#include <QCoreApplication>
#include <QDir>
#include <QEvent>
#include <QSettings>
#include <QThread>
#include <QTimer>
#include <algorithm>
#include <qt_windows.h>

namespace
{
    QPointer<ks::ui::BackgroundTaskRegistry> applicationRegistry;
    std::uint64_t fileTimeValue(const FILETIME& value)
    {
        return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
    }
    ks::ui::TaskCpuReading readThreadCpu()
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user)) return {};
        return {fileTimeValue(kernel) + fileTimeValue(user), true};
    }
    ks::ui::TaskCpuReading readProcessCpu()
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return {};
        return {fileTimeValue(kernel) + fileTimeValue(user), true};
    }
}

namespace ks::ui
{
    QString BackgroundTaskRegistry::defaultSettingsPath()
    {
        return QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("config/runtime-controls.ini"));
    }

    BackgroundTaskRegistry& BackgroundTaskRegistry::instance()
    {
        if (!applicationRegistry) applicationRegistry = new BackgroundTaskRegistry(QCoreApplication::instance());
        return *applicationRegistry;
    }

    BackgroundTaskRegistry::BackgroundTaskRegistry(QObject* parent, QString settingsPath)
        : QObject(parent), m_settingsPath(settingsPath.isEmpty() ? defaultSettingsPath() : std::move(settingsPath))
    {
    }

    BackgroundTaskRegistry::~BackgroundTaskRegistry() { stopCpuAnalysis(); }

    void BackgroundTaskRegistry::startCpuAnalysis()
    {
        stopCpuAnalysis();
        m_cpuSession = std::make_shared<TaskCpuSession>(&readThreadCpu);
        for (auto& entry : m_entries)
            entry.cpu = entry.timer ? std::make_shared<TaskCpuCounter>(m_cpuSession) : TaskCpuToken{};
        m_processBaseline = readProcessCpu();
        m_cpuCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
        m_cpuStarted = std::chrono::steady_clock::now();
        m_frozenCpu = {};
        if (this == applicationRegistry) s_cpuEnabled.store(true, std::memory_order_relaxed);
    }

    BackgroundTaskRegistry::CpuAnalysis BackgroundTaskRegistry::cpuAnalysis() const
    {
        if (!m_cpuSession || !m_cpuSession->enabled.load(std::memory_order_relaxed)) return m_frozenCpu;
        CpuAnalysis result;
        result.started = result.active = true;
        result.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - m_cpuStarted).count();
        const auto current = readProcessCpu();
        result.processAvailable = m_processBaseline.valid && current.valid && m_cpuCount != 0
            && GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) == m_cpuCount
            && current.time100ns >= m_processBaseline.time100ns && result.seconds > 0;
        if (result.processAvailable)
        {
            result.processCpuMs = static_cast<double>(current.time100ns - m_processBaseline.time100ns) / 10000.0;
            result.processCpuPercent = result.processCpuMs / (result.seconds * 10.0 * m_cpuCount);
        }
        return result;
    }

    void BackgroundTaskRegistry::stopCpuAnalysis()
    {
        if (!m_cpuSession || !m_cpuSession->enabled.load(std::memory_order_relaxed)) return;
        m_frozenCpu = cpuAnalysis();
        m_frozenCpu.active = false;
        m_cpuSession->stop();
        if (this == applicationRegistry) s_cpuEnabled.store(false, std::memory_order_relaxed);
    }

    TaskCpuToken BackgroundTaskRegistry::cpuToken(const QString& id) const
    {
        const auto it = m_entries.constFind(id);
        return it == m_entries.cend() ? TaskCpuToken{} : it->cpu;
    }

    TaskCpuToken BackgroundTaskRegistry::cpuTokenForEvent(QObject* receiver, QEvent* event)
    {
        // notify can run on worker threads. The registry is read only by its GUI owner.
        if (!event || event->type() != QEvent::Timer || !qApp || QThread::currentThread() != qApp->thread()
            || !applicationRegistry || !cpuAnalysisEnabled()) return {};
        const auto key = applicationRegistry->m_timerIds.constFind(receiver);
        if (key == applicationRegistry->m_timerIds.cend()) return {};
        const auto it = applicationRegistry->m_entries.constFind(*key);
        if (it == applicationRegistry->m_entries.cend() || !it->timer || it->value.paused
            || it->timer->timerId() != static_cast<QTimerEvent*>(event)->timerId()) return {};
        return it->cpu;
    }

    bool BackgroundTaskRegistry::addTimer(const QString& requestedId, const QString& title, const QString& group,
        QTimer* timer, Policy policy)
    {
        QString id = requestedId;
        if (!timer || id.isEmpty() || timer->thread() != thread() || QThread::currentThread() != thread()
            || timer->isSingleShot() || policy.minimumIntervalMs < 1
            || policy.maximumIntervalMs < policy.minimumIntervalMs)
            return false;
        if (m_timerIds.contains(timer)) return m_timerIds.value(timer).section(QLatin1Char('/'), 0, 0) == requestedId;
        if (m_entries.contains(id) && !m_entries[id].owner) m_entries.remove(id);
        if (policy.allowMultipleInstances) id += QLatin1Char('/') + QString::number(++m_instanceSerial);
        else if (m_entries.contains(id))
        {
            timer->stop();
            timer->installEventFilter(this);
            if (!m_rejectedTimers.contains(timer))
            {
                m_rejectedTimers.insert(timer);
                connect(timer, &QObject::destroyed, this, [this, timer]() { m_rejectedTimers.remove(timer); });
            }
            return false;
        }
        m_rejectedTimers.remove(timer);
        Entry entry;
        entry.timer = timer;
        if (m_cpuSession && m_cpuSession->enabled.load(std::memory_order_relaxed))
            entry.cpu = std::make_shared<TaskCpuCounter>(m_cpuSession);
        entry.owner = timer;
        entry.policy = std::move(policy);
        entry.value.id = id;
        const quint64 generation = entry.generation = ++m_instanceSerial;
        entry.value.title = title;
        entry.value.group = group;
        entry.value.defaultIntervalMs = timer->interval();
        entry.value.minimumIntervalMs = entry.policy.minimumIntervalMs;
        entry.value.maximumIntervalMs = entry.policy.maximumIntervalMs;
        entry.value.canPause = entry.policy.canPause;
        entry.value.canChangeInterval = entry.policy.canChangeInterval;
        entry.value.restriction = entry.policy.restriction;
        if (entry.policy.canChangeInterval && !entry.policy.allowMultipleInstances)
        {
            QSettings settings(m_settingsPath, QSettings::IniFormat);
            const int interval = settings.value(QStringLiteral("polling/") + id, 0).toInt();
            if (interval >= entry.policy.minimumIntervalMs && interval <= entry.policy.maximumIntervalMs)
            {
                entry.overrideIntervalMs = interval;
                timer->setInterval(interval);
            }
        }
        m_entries.insert(id, std::move(entry));
        m_timerIds.insert(timer, id);
        timer->installEventFilter(this);
        connect(timer, &QTimer::timeout, this, [this, id]() {
            auto it = m_entries.find(id);
            if (it == m_entries.end()) return;
            ++it->value.dispatches;
            it->value.lastDispatch = QDateTime::currentDateTimeUtc();
        });
        connect(timer, &QObject::destroyed, this, [this, id, timer, generation]() {
            m_timerIds.remove(timer);
            if (m_entries.contains(id) && m_entries[id].generation == generation) m_entries.remove(id);
        });
        return true;
    }

    bool BackgroundTaskRegistry::addExternal(const QString& id, const QString& title, const QString& group,
        QObject* owner, External binding, const QString& restriction)
    {
        if (!owner || id.isEmpty() || owner->thread() != thread() || QThread::currentThread() != thread()
            || m_entries.contains(id) || !binding.running) return false;
        Entry entry;
        const quint64 generation = entry.generation = ++m_instanceSerial;
        entry.owner = owner;
        entry.value.id = id;
        entry.value.title = title;
        entry.value.group = group;
        entry.value.canPause = static_cast<bool>(binding.pause) && static_cast<bool>(binding.paused);
        entry.value.restriction = restriction;
        entry.policy.canPause = entry.value.canPause;
        entry.policy.canChangeInterval = false;
        entry.policy.restriction = restriction;
        entry.external = std::move(binding);
        m_entries.insert(id, std::move(entry));
        connect(owner, &QObject::destroyed, this, [this, id, generation]() {
            if (m_entries.contains(id) && m_entries[id].generation == generation) m_entries.remove(id);
        });
        return true;
    }

    QVector<BackgroundTaskRegistry::Snapshot> BackgroundTaskRegistry::snapshot() const
    {
        QVector<Snapshot> rows;
        rows.reserve(m_entries.size());
        for (const Entry& entry : m_entries)
        {
            if (!entry.owner) continue;
            Snapshot row = entry.value;
            row.cpuSupported = !entry.timer.isNull();
            if (entry.cpu)
            {
                row.cpu = entry.cpu->snapshot();
                row.cpuInFlight = entry.cpu->inFlight.load(std::memory_order_relaxed);
            }
            if (entry.timer)
            {
                row.intervalMs = entry.overrideIntervalMs ? entry.overrideIntervalMs : entry.timer->interval();
                row.active = entry.timer->isActive() && !row.paused;
            }
            else
            {
                row.active = entry.external.running();
                row.paused = entry.external.paused && entry.external.paused();
            }
            row.inFlight = entry.policy.inFlight && entry.policy.inFlight();
            rows.push_back(std::move(row));
        }
        std::sort(rows.begin(), rows.end(), [](const Snapshot& a, const Snapshot& b) { return a.id < b.id; });
        return rows;
    }

    bool BackgroundTaskRegistry::fail(QString* error, const QString& message) const
    {
        if (error) *error = message;
        return false;
    }

    bool BackgroundTaskRegistry::setPaused(const QString& id, bool paused, QString* error)
    {
        auto it = m_entries.find(id);
        if (it == m_entries.end() || !it->owner)
            return fail(error, ks::i18n::sourceText(QStringLiteral("任务已结束或不再可用。")));
        if (!it->policy.canPause)
            return fail(error, ks::i18n::displayText(it->policy.restriction));
        if (!it->timer)
        {
            if (!it->external.running()) return fail(error, ks::i18n::sourceText(QStringLiteral("任务当前未运行。")));
            const External external = it->external;
            const QPointer<QObject> owner = it->owner;
            if (external.paused() == paused) return true;
            if (!external.pause(paused) || !owner || external.paused() != paused)
                return fail(error, ks::i18n::sourceText(QStringLiteral("任务未接受状态变更，请在所属页面检查依赖。")));
            return true;
        }
        if (it->value.paused == paused) return true;
        it->value.paused = paused;
        if (paused)
        {
            it->resumeActive = it->timer->isActive();
            it->timer->stop();
        }
        else if (it->resumeActive && (!it->policy.eligible || it->policy.eligible()))
        {
            it->timer->start();
        }
        return true;
    }

    bool BackgroundTaskRegistry::setInterval(const QString& id, int milliseconds, QString* error)
    {
        auto it = m_entries.find(id);
        if (it == m_entries.end() || !it->owner)
            return fail(error, ks::i18n::sourceText(QStringLiteral("任务已结束或不再可用。")));
        if (!it->policy.canChangeInterval)
            return fail(error, ks::i18n::displayText(it->policy.restriction));
        if (milliseconds < it->policy.minimumIntervalMs || milliseconds > it->policy.maximumIntervalMs)
            return fail(error, ks::i18n::sourceText(QStringLiteral("间隔必须在 %1 至 %2 毫秒之间。"))
                .arg(it->policy.minimumIntervalMs).arg(it->policy.maximumIntervalMs));
        if (!it->policy.allowMultipleInstances)
        {
            QSettings settings(m_settingsPath, QSettings::IniFormat);
            const QString key = QStringLiteral("polling/") + id;
            const bool hadSetting = settings.contains(key);
            const QVariant previous = settings.value(key);
            if (milliseconds == it->value.defaultIntervalMs) settings.remove(key);
            else settings.setValue(key, milliseconds);
            settings.sync();
            if (settings.status() != QSettings::NoError)
            {
                if (hadSetting) settings.setValue(key, previous); else settings.remove(key);
                return fail(error, ks::i18n::sourceText(QStringLiteral("无法保存设置，请检查配置目录的写入权限。")));
            }
        }
        it->overrideIntervalMs = milliseconds == it->value.defaultIntervalMs ? 0 : milliseconds;
        it->timer->setInterval(milliseconds);
        return true;
    }

    bool BackgroundTaskRegistry::restoreDefault(const QString& id, QString* error)
    {
        auto it = m_entries.constFind(id);
        if (it == m_entries.cend())
            return fail(error, ks::i18n::sourceText(QStringLiteral("任务已结束或不再可用。")));
        return setInterval(id, it->value.defaultIntervalMs, error);
    }

    bool BackgroundTaskRegistry::isPaused(const QString& id) const
    {
        auto it = m_entries.constFind(id);
        return it != m_entries.cend() && (it->external.paused ? it->external.paused() : it->value.paused);
    }

    bool BackgroundTaskRegistry::eventFilter(QObject* object, QEvent* event)
    {
        if (event->type() == QEvent::Timer)
        {
            if (m_rejectedTimers.contains(object))
            {
                static_cast<QTimer*>(object)->stop();
                return true;
            }
            auto key = m_timerIds.constFind(object);
            if (key != m_timerIds.cend())
            {
                auto it = m_entries.find(*key);
                if (it != m_entries.end() && it->timer)
                {
                    if (it->value.paused)
                    {
                        it->resumeActive = true;
                        it->timer->stop();
                        return true;
                    }
                    if (it->overrideIntervalMs && it->timer->interval() != it->overrideIntervalMs)
                        it->timer->setInterval(it->overrideIntervalMs);
                }
            }
        }
        return QObject::eventFilter(object, event);
    }
}
