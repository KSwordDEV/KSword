#include "../UI/StructuredFieldView.h"
#pragma once

// ============================================================
// DirectKernelCallMonitorWidget.h
// 作用：
// 1) 为“监控”模块提供“直接内核调用”标签页；
// 2) 基于 Windows ETW System Syscall Provider 采集系统调用事件；
// 3) 通过 ntdll/win32u 导出桩解析 syscall 编号到 Nt*/Zw*/NtUser*/NtGdi* 名称；
// 4) 提供 PID 限定、实时筛选、暂停、导出和详情查看能力。
// ============================================================

#include "../Framework.h"
#include "../../../shared/evidence/SyscallCorrelation.h"
#include "../../../shared/evidence/SyscallEvidence.h"

#include <QWidget>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>
#include <vector>

class QPoint;
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class QVBoxLayout;
struct _EVENT_RECORD;
struct _EVENT_TRACE_LOGFILEW;

class DirectKernelCallMonitorWidget final : public QWidget
{
public:
    explicit DirectKernelCallMonitorWidget(QWidget* parent = nullptr);
    ~DirectKernelCallMonitorWidget() override;

public:
    enum EventColumn
    {
        EventColumnTime100ns = 0,
        EventColumnPidTid,
        EventColumnProcess,
        EventColumnSyscallNumber,
        EventColumnServiceName,
        EventColumnVerdict,
        EventColumnCallAddress,
        EventColumnEventName,
        EventColumnDetail,
        EventColumnCount
    };

    struct SyscallMapEntry
    {
        std::uint32_t syscallNumber = 0;
        QString serviceName;
        QString sourceModule;
    };

    struct ModuleRange
    {
        std::uint64_t startAddress = 0;
        std::uint64_t endAddress = 0;
        QString moduleName;
        QString imagePath;
    };

    // ProcessIdentityCacheEntry：
    // - 作用：限制高频 ETW 事件对同一 PID 重复打开进程句柄；
    // - 调用方式：processNameForPid 每秒最多重新验证一次创建时间；
    // - 返回行为：缓存展示名、创建时间和最近验证时间，不主动访问系统。
    struct ProcessIdentityCacheEntry
    {
        QString processText; // processText：捕获时显示的进程名称与 PID。
        std::uint64_t creationTime100ns = 0U; // creationTime100ns：与 PID 共同组成历史事件 identity。
        std::chrono::steady_clock::time_point lastValidationTime{}; // lastValidationTime：最近一次身份查询时间。
    };

    struct CapturedEventRow
    {
        QString time100nsText;
        std::uint64_t eventTime100ns = 0;
        std::uint64_t kernelServiceAddress = 0;
        std::uint8_t pointerSize = 8;
        std::uint32_t pid = 0;
        std::uint64_t processCreationTime100ns = 0U; // processCreationTime100ns：事件发生时对应进程实例的创建时间。
        std::uint32_t tid = 0;
        QString pidTidText;
        QString processText;
        std::uint32_t syscallNumber = 0;
        bool hasSyscallNumber = false;
        QString syscallNumberText;
        QString serviceName;
        QString verdictText;
        std::uint64_t callAddress = 0;
        QString callAddressText;
        QString eventName;
        QString detailText;
        ks::ui::FieldDocument detailDocument;
        QString globalSearchText;
    };

    struct FrameInspection
    {
        ks::evidence::syscall::FrameEvidence evidence;
        QString moduleText;
        std::uint64_t creationTime100ns = 0;
        std::chrono::steady_clock::time_point sampledAt{};
        std::shared_ptr<void> processOwner;
        bool readable = false;
    };

private:
    void initializeUi();
    void initializeConnections();
    void reloadSyscallMap();
    void startCapture();
    void stopCapture();
    void stopCaptureInternal(bool waitForThread);
    bool stopOwnedSession();
    void setCapturePaused(bool paused);
    void updateActionState();
    void updateStatusLabel();
    void flushPendingRows();
    void appendEventRow(const CapturedEventRow& rowValue);
    void scheduleFilterApply();
    void applyFilter();
    void clearFilter();
    void exportVisibleRowsToTsv();
    void showEventContextMenu(const QPoint& position);
    void openEventDetailViewerForRow(int rowIndex);

    static void WINAPI eventRecordCallback(struct _EVENT_RECORD* eventRecordPtr);
    static ULONG WINAPI bufferCallback(struct _EVENT_TRACE_LOGFILEW* traceLogFile);
    void enqueueEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr);
    void publishCorrelatedRows(std::vector<ks::evidence::syscall::Correlator<CapturedEventRow>::Output> outputs);
    void analyzeUserStack(CapturedEventRow& row, const std::vector<std::uint64_t>& frames);
    void enqueueRow(CapturedEventRow row);
    void synchronizeCaptureInterval();
    CapturedEventRow buildRowFromRecord(const struct _EVENT_RECORD* eventRecordPtr);
    QString serviceNameForNumber(std::uint32_t syscallNumber) const;
    // processNameForPid 作用：
    // - 查询或复用 PID 对应的名称，并同步返回进程创建时间；
    // - 入参 pid：ETW 事件携带的 PID；
    // - 出参 creationTime100nsOut：用于历史跳转校验的创建时间；
    // - 返回：带 PID 的进程展示文本。
    QString processNameForPid(
        std::uint32_t pid,
        std::uint64_t* creationTime100nsOut);
    QString moduleNameForAddress(std::uint32_t pid, std::uint64_t addressValue);
    void refreshModuleRangesForPid(std::uint32_t pid);
    std::set<std::uint32_t> parsePidSet(const QString& text) const;
    bool shouldCapturePid(std::uint32_t pid) const;

private:
    QVBoxLayout* m_rootLayout = nullptr;
    QWidget* m_controlPanel = nullptr;
    QLineEdit* m_targetPidEdit = nullptr;
    QCheckBox* m_globalCaptureCheck = nullptr;
    QCheckBox* m_resolveAddressCheck = nullptr;
    QSpinBox* m_maxRowsSpin = nullptr;
    QSpinBox* m_bufferSizeSpin = nullptr;
    QPushButton* m_reloadMapButton = nullptr;
    QPushButton* m_startButton = nullptr;
    QPushButton* m_stopButton = nullptr;
    QPushButton* m_pauseButton = nullptr;
    QPushButton* m_clearButton = nullptr;
    QPushButton* m_exportButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    QLabel* m_mapStatusLabel = nullptr;

    QWidget* m_filterPanel = nullptr;
    QLineEdit* m_processFilterEdit = nullptr;
    QLineEdit* m_serviceFilterEdit = nullptr;
    QLineEdit* m_detailFilterEdit = nullptr;
    QLineEdit* m_globalFilterEdit = nullptr;
    QCheckBox* m_regexCheck = nullptr;
    QCheckBox* m_caseCheck = nullptr;
    QCheckBox* m_invertCheck = nullptr;
    QCheckBox* m_keepBottomCheck = nullptr;
    QPushButton* m_clearFilterButton = nullptr;
    QLabel* m_filterStatusLabel = nullptr;
    QTableWidget* m_eventTable = nullptr;
    QTimer* m_uiUpdateTimer = nullptr;
    QTimer* m_filterDebounceTimer = nullptr;

    std::unordered_map<std::uint32_t, SyscallMapEntry> m_syscallMap;
    mutable std::mutex m_syscallMapMutex;
    std::unordered_map<std::uint32_t, ProcessIdentityCacheEntry> m_processNameCache; // PID 到限时验证身份的缓存。
    std::unordered_map<std::uint32_t, std::vector<ModuleRange>> m_moduleRangeCache;
    std::unordered_map<std::uint32_t, std::chrono::steady_clock::time_point> m_moduleRefreshTimes;
    std::map<std::pair<std::uint32_t, std::uint64_t>, FrameInspection> m_frameInspectionCache;
    std::mutex m_cacheMutex;
    // Only the ProcessTrace consumer touches the correlation cache.
    ks::evidence::syscall::Correlator<CapturedEventRow> m_stackCorrelator;
    std::uint64_t m_qpcOrigin = 0;
    std::uint64_t m_filetimeOrigin = 0;
    std::uint64_t m_qpcFrequency = 1;
    std::atomic<ULONG> m_stackEnableStatus{ ERROR_SUCCESS };
    std::atomic<ULONG> m_startTraceStatus{ ERROR_SUCCESS };
    std::atomic<ULONG> m_openTraceStatus{ ERROR_SUCCESS };
    std::atomic<ULONG> m_processTraceStatus{ ERROR_SUCCESS };
    std::atomic<ULONG> m_sessionStopStatus{ ERROR_SUCCESS };
    std::atomic<std::uint64_t> m_etwEventsLost{ 0 };
    std::atomic<std::uint64_t> m_etwBuffersLost{ 0 };
    std::atomic<std::uint64_t> m_stackMatched{ 0 };
    std::atomic<std::uint64_t> m_stackMissing{ 0 };
    std::atomic<std::uint64_t> m_stackConflicts{ 0 };
    std::atomic<std::uint64_t> m_stackCapacityEvicted{ 0 };
    std::chrono::steady_clock::time_point m_lastTraceStatsQuery{};
    std::atomic<std::uint64_t> m_captureIntervalGeneration{ 0 };
    std::uint64_t m_consumerIntervalGeneration = 0;
    static constexpr std::size_t kPendingRowCapacity = 24000;
    static constexpr std::size_t kUiFlushRowLimit = 160;
    static constexpr int kUiFlushBudgetMs = 4;
    static constexpr int kProcessIdentityValidationIntervalMs = 1000; // 同一 PID 身份重新验证间隔，兼顾 PID 复用与 ETW 吞吐。

    std::deque<CapturedEventRow> m_pendingRows;
    std::mutex m_pendingMutex;
    std::size_t m_pendingDroppedRows = 0;
    std::set<std::uint32_t> m_capturePidSet;
    mutable std::mutex m_captureConfigMutex;

    std::atomic_bool m_captureRunning{ false };
    std::atomic_bool m_capturePaused{ false };
    std::atomic_bool m_captureStopFlag{ false };
    std::atomic_bool m_captureAllProcesses{ false };
    std::atomic_bool m_resolveCallAddress{ true };
    std::unique_ptr<std::thread> m_captureThread;
    std::atomic<std::uint64_t> m_sessionHandle{ 0 };
    std::atomic<std::uint64_t> m_traceHandle{ 0 };
    QString m_sessionName;
    int m_captureProgressPid = 0;
    bool m_filterActive = false;
};

