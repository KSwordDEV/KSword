#pragma once

#include "WinAPISessionBackend.h"
#include "../UI/AsyncOperation.h"
#include "../../../shared/ApiMonitorStackSnapshot.h"
#include "../../../shared/ApiMonitorExportSnapshot.h"
#include <QObject>
#include <array>
#include <chrono>
#include <functional>
#include <thread>
#include <vector>

// One selected event at a time. Remote queries, resolver shutdown and joins
// occur on the AsyncOperation worker, never on the owning GUI thread.
class WinAPIStackSnapshotAdapter final : public QObject
{
public:
    using Frame = ks::winapi_monitor::StackFrameSnapshot;
    using Finished = std::function<void(const WinAPIEventRef&, const std::vector<Frame>&)>;
    explicit WinAPIStackSnapshotAdapter(QObject* parent = nullptr)
        : QObject(parent), m_operation(new ks::ui::AsyncOperation(this)) {}
    ~WinAPIStackSnapshotAdapter() override { m_operation->close(); }
    Finished finished;

    bool select(const WinAPIEventRef& record)
    {
        m_operation->cancel(); m_current.reset();
        if (!record || !record->generation || !record->sequence || !record->value.sourcePid
            || !record->value.sourceCreationTime100ns || record->value.capturedCallStack.isEmpty()) return false;
        Request request;
        request.generation = record->generation; request.sequence = record->sequence;
        request.pid = record->value.sourcePid; request.creation = record->value.sourceCreationTime100ns;
        const auto lines = record->value.capturedCallStack.split(QLatin1Char('\n'));
        if (lines.isEmpty() || lines.size() > static_cast<qsizetype>(request.addresses.size())) return false;
        for (qsizetype i = 0; i < lines.size(); ++i) {
            const QString prefix = QStringLiteral("#%1 0x").arg(i);
            if (!lines[i].startsWith(prefix)) return false;
            const QString hex = lines[i].mid(prefix.size());
            if (hex.isEmpty() || hex.size() > 16) return false;
            for (const auto c : hex) if (!((c >= QLatin1Char('0') && c <= QLatin1Char('9'))
                || (c >= QLatin1Char('a') && c <= QLatin1Char('f')) || (c >= QLatin1Char('A') && c <= QLatin1Char('F')))) return false;
            bool ok = false; const auto address = hex.toULongLong(&ok, 16);
            if (!ok || !address) return false;
            request.addresses[request.count++] = address;
        }
        m_current = record;
        const auto accepted = m_operation->submit<Request, std::vector<Frame>>(request,
            [](const Request& input, const ks::ui::AsyncOperationToken& token) {
                ks::winapi_monitor::CallerSnapshotResolver resolver;
                ks::winapi_monitor::StackSnapshotBatch batch(resolver);
                if (!batch.start(input.generation, input.sequence, input.pid, input.creation,
                    std::span<const std::uint64_t>(input.addresses.data(), input.count))) return std::vector<Frame>{};
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
                while (batch.pending() && !token.isCanceled() && std::chrono::steady_clock::now() < deadline) {
                    batch.poll();
                    if (batch.pending()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
                batch.poll();
                const auto frames = batch.frames();
                std::vector<Frame> result(frames.begin(), frames.end());
                for (auto& frame : result) {
                    if (token.isCanceled() || std::chrono::steady_clock::now() >= deadline) break;
                    const auto symbol = ks::winapi_monitor::QueryNearestExport(input.pid, input.creation, frame);
                    if (!symbol.available) continue;
                    frame.nearestExportName = symbol.name;
                    frame.nearestExportDisplacement = symbol.displacement;
                    frame.nearestExportObservedTime100ns = symbol.observedTime100ns;
                }
                return result;
            },
            [this, record](const std::vector<Frame>& frames, std::uint64_t) {
                if (m_current == record && finished) finished(record, frames);
                return true;
            },
            [](std::exception_ptr) {});
        if (!accepted) { m_current.reset(); return false; }
        return true;
    }
private:
    struct Request {
        std::uint64_t generation = 0, sequence = 0, creation = 0;
        std::uint32_t pid = 0;
        std::array<std::uint64_t, ks::winapi_monitor::kStackSnapshotMaximum> addresses{};
        std::size_t count = 0;
    };
    ks::ui::AsyncOperation* m_operation;
    WinAPIEventRef m_current;
};
