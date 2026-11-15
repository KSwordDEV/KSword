#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <evntcons.h>
#include <evntrace.h>
#include <QDateTime>
#include <QFileInfo>
#include <QIcon>
#include <QMainWindow>
#include <QMutex>
#include <QObject>
#include <QQueue>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVector>

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <thread>

// Diagnostics are disabled in every configuration; arguments are not evaluated.
#define KSWORD_UAC_DIAGNOSTIC_LOG(...) ((void)0)

class QLabel;
class QEvent;
class QMouseEvent;
class QPushButton;
class UacScanWorker;
struct UacScanCancellation;

struct ProcessIdentity
{
    DWORD pid = 0;
    DWORD parentPid = 0;
    DWORD sessionId = 0;
    quint64 creationTime = 0;
    QString imagePath;
    QString commandLine;
    QString fileDescription;

    bool isValid() const { return pid != 0 && creationTime != 0 && !imagePath.isEmpty(); }
};

struct UacApplicationIdentity
{
    HWND consentWindow = nullptr;
    QRect windowRect;
    QString displayName;
    QString publisher;
    QString imagePath;
    QString matchText;
    QString evidence;
    quint64 observedAtMs = 0;
    bool exact = false;
    bool isUac = false;
};

struct UacOriginEvidence
{
    ProcessIdentity origin;
    QString targetPath;
    DWORD consentPid = 0;
    DWORD appInfoPid = 0;
    DWORD bufferLength = 0;
    quintptr requestAddress = 0;
    DWORD originPidOffset = 0;
    DWORD targetPathOffset = 0;
    quint64 observedAtMs = 0;

    bool isValid() const
    {
        return origin.isValid() && consentPid != 0 && appInfoPid != 0 &&
               bufferLength >= 0x70 && requestAddress != 0;
    }
};

struct ProcessActionState
{
    ProcessIdentity origin;
    bool originResolved = false;
    QIcon originIcon;
    QString launchChain;
    QString integrityLevel;
    QString elevationType;
    QString startTime;
    QString runDuration;
    QString originSignature;
    QString targetSignature;
    ProcessIdentity target;
    bool unique = false;
    bool protectedProcess = true;
    QString reason;
};

struct UacScanOriginHint
{
    bool monitorRunning = false;
    DWORD consentPid = 0;
    quint64 discoveredAtMs = 0;
};

class ProcessInspector final
{
public:
    static bool query(DWORD pid, ProcessIdentity& identity, DWORD desiredAccess = PROCESS_QUERY_LIMITED_INFORMATION);
    static bool queryCommandLine(DWORD pid, QString& commandLine);
    static bool identityStillMatches(const ProcessIdentity& expected);
    static bool isProtectedName(const QString& imagePath);
    static bool suspend(const ProcessIdentity& expected, QString& error);
    static bool resume(const ProcessIdentity& expected, QString& error);
    static bool terminate(const ProcessIdentity& expected, QString& error);
    static QString fileName(const QString& path);

private:
    static bool queryCommandLine(HANDLE process, QString& commandLine);
};

class PrivilegeStage final
{
public:
    static bool isProcessElevated();
    static bool isSystem();
    static bool hasUiAccess();
    static bool launchAdminStage(const QString& executable, const QStringList& args, QString& error);
    static bool launchSystemStage(const QString& executable, const QStringList& args, const QString& desktop,
                                  DWORD targetSession, QString& error);
    static QString currentDesktopName();
    static DWORD currentSessionId();
};

class UacEventMonitor final : public QObject
{
public:
    explicit UacEventMonitor(QObject* parent = nullptr);
    ~UacEventMonitor() override;

    void start();
    void stop();
    bool etwAvailable() const { return m_etwAvailable.load(); }
    UacScanOriginHint scanOriginHint() const
    {
        return {m_running.load(), m_consentPid.load(), m_lastConsentDiscoveryMs.load()};
    }
    std::optional<ProcessIdentity> takeUacOrigin(DWORD sessionId, quint64 uacObservedAtMs,
                                                  const QString& targetPath);

    std::function<void()> onDesktopChanged;

private:
    struct EventItem
    {
        GUID provider{};
        DWORD eventId = 0;
        USHORT task = 0;
        UCHAR opcode = 0;
        DWORD pid = 0;
        HWND hwnd = nullptr;
        quint64 eventTimeMs = 0;
    };

    static void WINAPI winEventCallback(HWINEVENTHOOK hook, DWORD event, HWND hwnd, LONG objectId,
                                        LONG childId, DWORD eventThreadId, DWORD eventTime);
    static void WINAPI etwEventCallback(PEVENT_RECORD record);
    static void etwEventCallbackImpl(PEVENT_RECORD record);
    void observeAlpc(bool receive, DWORD pid, DWORD tid, ULONG messageId, quint64 eventTimeMs);
    void startEtw();
    void startAlpcEtw();
    void stopEtw();
    void stopAlpcEtw();
    void consumeEvents();
    void pushEvent(const EventItem& item);

    QTimer m_consumeTimer;
    HWINEVENTHOOK m_winEventHook = nullptr;
    HWINEVENTHOOK m_objectEventHook = nullptr;
    QMutex m_queueMutex;
    QQueue<EventItem> m_events;
    struct AlpcSendItem
    {
        ULONG messageId = 0;
        DWORD pid = 0;
        DWORD tid = 0;
        quint64 eventTimeMs = 0;
        quint64 observedAtMs = 0;
    };
    struct UacOriginItem
    {
        ULONG messageId = 0;
        DWORD clientPid = 0;
        DWORD clientTid = 0;
        DWORD appInfoPid = 0;
        quint64 eventTimeMs = 0;
        quint64 observedAtMs = 0;
    };
    QMutex m_alpcMutex;
    QQueue<AlpcSendItem> m_alpcSends;
    QQueue<UacOriginItem> m_uacOrigins;
    std::atomic<DWORD> m_appInfoPid{0};
    std::atomic<DWORD> m_consentPid{0};
    std::atomic<quint64> m_lastConsentDiscoveryMs{0};
    quint64 m_lastAppInfoPidRefreshMs = 0;
    std::atomic_bool m_running{false};
    std::atomic_bool m_etwStop{false};
    std::thread m_etwThread;
    ULONG64 m_traceSession = 0;
    std::atomic<TRACEHANDLE> m_traceHandle{0};
    QString m_traceName;
    std::thread m_alpcThread;
    std::atomic_bool m_alpcStop{false};
    std::atomic<ULONG64> m_alpcSession{0};
    std::atomic<TRACEHANDLE> m_alpcTraceHandle{0};
    std::atomic<ULONG> m_alpcLastStatus{ERROR_SUCCESS};
    QString m_alpcTraceName;
    std::atomic_bool m_etwAvailable{false};
};

class UacWindowScanner final
{
public:
    static UacApplicationIdentity scan(const UacScanCancellation* cancel = nullptr);
    static BOOL CALLBACK enumChildProc(HWND hwnd, LPARAM lParam);

private:
    static BOOL CALLBACK enumWindowProc(HWND hwnd, LPARAM lParam);
    static QString readUiAutomationName(HWND hwnd, const UacScanCancellation* cancel);
};

class UacDeskWindow final : public QMainWindow
{
public:
    explicit UacDeskWindow(QWidget* parent = nullptr);
    ~UacDeskWindow() override;

    bool setParentWatch(HANDLE processHandle, quint64 creationTime);
    void setInitialStatus(const QString& status);
    void notifyUacActivity();
    void refreshNow();
    void refreshAppearance();

private:
    void refreshUacState();
    void applyScanResult(const UacApplicationIdentity& identity, const ProcessActionState& actionState);
    void adjustToContent();
    void repositionBesideUac(const UacApplicationIdentity& identity);
    void updateButtons();
    void showStatus(const QString& status, bool error = false);
    void launchMainOnSecureDesktop();
    void launchPowerShellOnSecureDesktop();
    void runProcessAction(int action);
    bool eventFilter(QObject* watched, QEvent* event) override;
    void changeEvent(QEvent* event) override;

    QWidget* m_brandHeader = nullptr;
    QLabel* m_originIconLabel = nullptr;
    QLabel* m_identityLabel = nullptr;
    QLabel* m_processLabel = nullptr;
    QPushButton* m_suspendButton = nullptr;
    QPushButton* m_terminateButton = nullptr;
    QPushButton* m_powerShellButton = nullptr;
    QPushButton* m_launchMainButton = nullptr;
    QTimer m_refreshTimer;
    QWidget* m_dragHandle = nullptr;
    bool m_dragging = false;
    QPoint m_dragOffset;
    HWND m_positionedUacWindow = nullptr;
    std::atomic_bool m_scanStop{false};
    std::atomic<quint64> m_scanGeneration{0};
    std::unique_ptr<UacScanWorker> m_scanWorker;
    std::atomic_bool m_actionRunning{false};
    std::atomic_bool m_launchRunning{false};
    std::thread m_actionThread;
    std::thread m_launchThread;
    std::thread m_parentWatchThread;
    quint64 m_fastPollUntilMs = 0;
    HANDLE m_parentProcess = nullptr;
    HANDLE m_parentWatchStop = nullptr;
    ProcessActionState m_actionState;
    UacApplicationIdentity m_identity;
};

QString formatFileTime(quint64 fileTime);
quint64 processCreationTime(HANDLE process);
QString quoteArgument(const QString& value);
