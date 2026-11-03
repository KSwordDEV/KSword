#pragma once

#include "WinAPISessionBackend.h"
#include "../UI/AsyncCleanupRegistry.h"
#include "../../../shared/ApiMonitorCallerSnapshot.h"
#include <QElapsedTimer>
#include <QObject>
#include <QTimer>
#include <functional>
#include <memory>
#include <thread>

// Only the currently selected event is submitted. The callback and timer live
// on the owner thread; the resolver never calls Qt or borrows a QWidget.
class WinAPICallerSnapshotAdapter final : public QObject
{
public:
    using Snapshot = ks::winapi_monitor::CallerSnapshot;
    using Resolver = ks::winapi_monitor::CallerSnapshotResolver;
    using Finished = std::function<void(const WinAPIEventRef&, const Snapshot&)>;
    enum class SelectResult { Started, Unsupported, Busy, Stopped };

    explicit WinAPICallerSnapshotAdapter(QObject* parent = nullptr) : QObject(parent)
    {
        m_timer.setInterval(50);
        connect(&m_timer, &QTimer::timeout, this, [this] { poll(); });
    }
    ~WinAPICallerSnapshotAdapter() override
    {
        m_timer.stop(); m_current.reset(); retireResolver();
    }
    Finished finished;

    SelectResult select(const WinAPIEventRef& record)
    {
        m_timer.stop(); m_current.reset(); ++m_requestId;
        if (!record || !record->generation || !record->sequence || !record->value.sourcePid
            || !record->value.sourceCreationTime100ns) { retireResolver(); return SelectResult::Unsupported; }
        const auto address = rawCallerAddress(record->value.detailText);
        if (!address) { retireResolver(); return SelectResult::Unsupported; }
        m_pending = {record->generation, record->sequence, record->value.sourcePid,
            record->value.sourceCreationTime100ns, address, m_requestId};
        m_current = record; m_elapsed.start();
        if (!m_retiring.expired()) { m_waitingForCleanup = true; m_timer.start(); return SelectResult::Started; }
        if (!ensureResolver()) { m_current.reset(); return SelectResult::Stopped; }
        // Discard completed old selections without touching event objects.
        (void)m_resolver->drain();
        const auto status = m_resolver->submit(m_pending);
        if (status == Resolver::SubmitStatus::Full || status == Resolver::SubmitStatus::ResourceFailure) {
            m_current.reset(); retireResolver(); return SelectResult::Busy;
        }
        if (status != Resolver::SubmitStatus::Accepted) {
            m_current.reset(); retireResolver(); return SelectResult::Stopped;
        }
        m_waitingForCleanup = false; m_timer.start();
        return SelectResult::Started;
    }

private:
    static std::uint64_t rawCallerAddress(const QString& detail)
    {
        const int marker = detail.indexOf(QStringLiteral(" caller=0x"));
        const int raw = detail.indexOf(QStringLiteral(" strongTyped=0 params=raw"));
        if (marker < 0 || raw <= marker) return 0;
        const int begin = marker + 8; // includes the 0x prefix
        int end = begin + 2;
        while (end < raw) {
            const auto c = detail.at(end);
            if (!((c >= QLatin1Char('0') && c <= QLatin1Char('9'))
                || (c >= QLatin1Char('a') && c <= QLatin1Char('f'))
                || (c >= QLatin1Char('A') && c <= QLatin1Char('F')))) return 0;
            ++end;
        }
        if (end != raw || end == begin + 2) return 0;
        bool ok = false;
        const auto value = detail.mid(begin, end - begin).toULongLong(&ok, 16);
        return ok ? value : 0;
    }
    bool ensureResolver()
    {
        if (m_resolver) return true;
        try {
            auto resolver = std::make_shared<Resolver>();
            std::weak_ptr<Resolver> weak = resolver;
            auto lease = ks::ui::AsyncCleanupRegistry::global().acquire([weak] {
                if (auto owner = weak.lock()) owner->requestStop();
            });
            if (!lease) { resolver->stop(); return false; }
            m_resolver = std::move(resolver); m_lease = std::move(lease);
            return true;
        } catch (...) { return false; }
    }
    void retireResolver()
    {
        auto resolver = std::move(m_resolver);
        auto lease = std::move(m_lease);
        if (!resolver) return;
        m_retiring = resolver;
        resolver->requestStop();
        // No UI join: one in-flight OS query can finish on a tracked cleanup thread.
        try { std::thread([resolver, lease] { resolver->stop(); }).detach(); }
        catch (...) { resolver->stop(); }
    }
    void finishFailure(DWORD error)
    {
        m_timer.stop(); auto current = std::move(m_current);
        retireResolver();
        Snapshot result; result.request = m_pending; result.status = ks::winapi_monitor::CallerSnapshotStatus::QueryFailed;
        result.win32Error = error;
        auto callback = finished; if (callback) callback(current, result);
    }
    void poll()
    {
        if (!m_current) { m_timer.stop(); return; }
        if (m_elapsed.elapsed() >= 5000) { finishFailure(ERROR_TIMEOUT); return; }
        if (m_waitingForCleanup) {
            if (!m_retiring.expired()) return;
            if (!ensureResolver()) { finishFailure(ERROR_CANCELLED); return; }
            const auto status = m_resolver->submit(m_pending);
            if (status != Resolver::SubmitStatus::Accepted) { finishFailure(ERROR_NOT_ENOUGH_MEMORY); return; }
            m_waitingForCleanup = false;
        }
        if (!m_resolver || m_resolver->isStopping()) { finishFailure(ERROR_CANCELLED); return; }
        try {
            for (const auto& value : m_resolver->drain()) {
                const auto& key = value.request;
                if (key.generation != m_pending.generation || key.sequence != m_pending.sequence
                    || key.requestId != m_pending.requestId || key.pid != m_pending.pid
                    || key.creationTime100ns != m_pending.creationTime100ns || key.address != m_pending.address) continue;
                m_timer.stop(); auto current = std::move(m_current);
                retireResolver();
                auto callback = finished; if (callback) callback(current, value);
                return; // callback may destroy this adapter
            }
        } catch (...) {
            // A bounded retry protects the GUI from allocation failures.
        }
    }
    QTimer m_timer;
    QElapsedTimer m_elapsed;
    std::shared_ptr<Resolver> m_resolver;
    std::weak_ptr<Resolver> m_retiring; // at most one in-flight cleanup per adapter
    std::shared_ptr<ks::ui::AsyncCleanupRegistry::Lease> m_lease;
    WinAPIEventRef m_current;
    ks::winapi_monitor::CallerSnapshotRequest m_pending;
    std::uint64_t m_requestId = 0;
    bool m_waitingForCleanup = false;
};
