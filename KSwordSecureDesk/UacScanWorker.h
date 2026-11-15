#pragma once

#include "UacDesk.h"

class QWinEventNotifier;

// Only values and handles owned by the isolated collector. Never borrows a
// window, monitor, stack cancellation flag, or the ETW singleton.
struct UacScanCancellation
{
    HANDLE stop = nullptr;
    HANDLE parent = nullptr;

    bool canceled() const
    {
        return (stop && WaitForSingleObject(stop, 0) != WAIT_TIMEOUT) ||
               (parent && WaitForSingleObject(parent, 0) != WAIT_TIMEOUT);
    }
};

struct UacScanResult
{
    UacApplicationIdentity identity;
    ProcessActionState actionState;
};

UacScanResult collectUacScan(DWORD companionPid, const UacScanOriginHint& originHint,
    const UacScanCancellation& budget);
int runUacScanCollector(const QStringList& args);

// Qt-thread controller. The native owner contains only an exact child process,
// its private job and inherited anonymous IPC; destruction never joins COM or
// waits for a provider. The child has no ETW/session ownership or action API.
class UacScanWorker final : public QObject
{
public:
    explicit UacScanWorker(QObject* parent = nullptr);
    ~UacScanWorker() override;
    bool busy() const { return m_busy; }
    bool request(const UacScanOriginHint& originHint, std::function<void(UacScanResult)> completed);
    void close();

private:
    struct NativeOwner;
    struct Startup;
    static std::unique_ptr<NativeOwner> createNative(const QString& executable,
        const std::atomic_bool& closed);
    bool start();
    void collectStartup();
    void sendRequest();
    void finish(bool success);
    void discardProcess();

    std::unique_ptr<NativeOwner> m_native;
    std::shared_ptr<Startup> m_startup;
    QTimer m_startPoll;
    std::unique_ptr<QWinEventNotifier> m_ready;
    std::unique_ptr<QWinEventNotifier> m_exited;
    std::function<void(UacScanResult)> m_completed;
    UacScanOriginHint m_originHint;
    quint64 m_sequence = 0;
    quint64 m_retryAfterMs = 0;
    bool m_busy = false;
    bool m_closed = false;
};
