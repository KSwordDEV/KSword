#pragma once

// System-thread management and exact-build, read-only Ex work-queue evidence.

#include "../Framework.h"
#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

#include <cstdint>
#include <vector>

#include "../UI/StructuredFieldView.h"
class QEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class KernelThreadAuditTab final : public QWidget
{
public:
    enum class Mode
    {
        SystemThreads,
        WorkQueueThreads
    };

    explicit KernelThreadAuditTab(Mode mode, QWidget* parent = nullptr);
    void requestRefresh();

    // ModuleQueryStatus：
    // - 作用：描述内核模块枚举的结果状态，供调用方区分“真的没有模块”和“查询失败”；
    // - Ok：枚举成功，返回的模块列表可信；
    // - ApiUnavailable：拿不到 ntdll!NtQuerySystemInformation，能力不可用；
    // - LengthQueryFailed：预查询长度失败或长度超出安全上限，未发起正式查询；
    // - SnapshotFailed：正式查询失败或返回数据不足以解析出模块头。
    enum class ModuleQueryStatus : std::uint32_t
    {
        Ok,
        ApiUnavailable,
        LengthQueryFailed,
        SnapshotFailed
    };

    // ModuleRecord：
    // - 作用：描述一个已加载内核模块的定位信息，用于把内核地址归属到具体驱动；
    // - name：模块文件名（不含目录），路径解析失败时回退取路径末段；
    // - path：模块完整路径（系统返回的原始路径形式）；
    // - baseAddress：模块映像基址，0 表示无效记录；
    // - imageSize：模块映像大小（字节），与基址一起构成地址归属区间；
    // - kernelImage：true 表示该模块是内核主映像（枚举结果中的首个模块）。
    struct ModuleRecord
    {
        QString name;
        QString path;
        std::uint64_t baseAddress = 0;
        std::uint32_t imageSize = 0;
        bool kernelImage = false;
    };

    // queryKernelModules：
    // - 作用：枚举当前系统已加载的内核模块，供地址归属与驱动定位复用；
    // - 说明：走 R3 的 NtQuerySystemInformation，不依赖驱动，可在任意线程调用；
    // - 出参 queryStatusOut：可空，写入本次枚举的状态码（见 ModuleQueryStatus）；
    // - 出参 nativeStatusOut：可空，写入最后一次原生调用返回的 NTSTATUS；
    // - 出参 requiredBytesOut：可空，写入预查询得到的所需缓冲区字节数；
    // - 返回：按系统枚举顺序排列的模块列表；失败时返回空列表，具体原因看 queryStatusOut。
    static std::vector<ModuleRecord> queryKernelModules(
        ModuleQueryStatus* queryStatusOut,
        long* nativeStatusOut,
        unsigned long* requiredBytesOut);

    // findOwnerModule：
    // - 作用：在模块列表中查找包含指定内核地址的宿主模块；
    // - 入参 modules：queryKernelModules 返回的模块列表；
    // - 入参 address：待归属的内核地址，传 0 视为无效直接判未命中；
    // - 出参 matchedOut：可空，true=命中宿主模块，false=未命中；
    // - 返回：命中时返回该模块记录；未命中返回默认构造的空记录（baseAddress 为 0）。
    static ModuleRecord findOwnerModule(
        const std::vector<ModuleRecord>& modules,
        std::uint64_t address,
        bool* matchedOut);

protected:
    void changeEvent(QEvent* event) override;

private:
    enum class Column
    {
        ThreadId = 0,
        EThread,
        Category,
        QueueType,
        NodePriority,
        WorkQueueAddress,
        State,
        WaitReason,
        StartRoutine,
        Parameter,
        Module,
        ModuleBase,
        ModulePath,
        R0Status,
        Protection,
        Count
    };

    enum class ViewPreset
    {
        Overview,
        Evidence,
        Custom
    };

    enum class ProtectionKind : std::uint32_t
    {
        UnknownModule,
        KernelImage,
        MissingThreadIdentity,
        BestEffortR0Recheck,
        ReadOnlyWorkQueueEvidence
    };

    enum SnapshotDiagnosticFlag : std::uint32_t
    {
        DiagnosticNone = 0U,
        DiagnosticR3EnumerationEmpty = 1U << 0U,
        DiagnosticR0ThreadUnavailable = 1U << 1U,
        DiagnosticModuleUnavailable = 1U << 2U,
        DiagnosticWorkQueueTransportFailed = 1U << 3U,
        DiagnosticWorkQueueUnsupported = 1U << 4U,
        DiagnosticWorkQueuePartial = 1U << 5U
    };

    struct ThreadRow
    {
        std::uint32_t threadId = 0;
        std::uint64_t createTime100ns = 0;
        std::uint64_t startAddress = 0;
        std::uint64_t queueAddress = 0;
        std::uint64_t workItemAddress = 0;
        std::uint64_t parameterAddress = 0;
        std::uint64_t threadObject = 0;
        int priority = 0;
        int basePriority = 0;
        std::uint32_t state = 0;
        std::uint32_t waitReason = 0;
        std::uint32_t r0Flags = 0;
        std::uint32_t r0FieldFlags = 0;
        std::uint32_t r0Status = 0;
        std::uint32_t workQueueRowKind = 0;
        std::uint32_t queueType = 0;
        std::uint32_t queuePriorityIndex = 0;
        std::uint32_t nodeIndex = 0;
        std::uint32_t workQueueFlags = 0;
        std::uint32_t workQueueStatus = 0;
        ModuleRecord module;
        bool moduleResolved = false;
        bool workerKnown = false;
        bool activeWorker = false;
        bool protectedTarget = true;
        ProtectionKind protectionKind = ProtectionKind::UnknownModule;
    };

    struct Snapshot
    {
        std::vector<ThreadRow> rows;
        std::uint32_t diagnosticFlags = DiagnosticNone;
        unsigned long r0Win32Error = ERROR_SUCCESS;
        ModuleQueryStatus moduleQueryStatus = ModuleQueryStatus::Ok;
        long moduleNativeStatus = 0;
        unsigned long moduleRequiredBytes = 0;
        std::uint32_t workQueueQueryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED;
        std::uint32_t workQueueStatusFlags = 0;
        std::uint32_t workQueueTotalCount = 0;
        std::uint32_t workQueueNodeCount = 0;
        std::uint32_t workQueueQueuesVisited = 0;
        std::uint32_t workQueueCorruptCount = 0;
        std::uint32_t workQueueReadFailureCount = 0;
        std::uint32_t workQueueReferenceFailureCount = 0;
        long workQueueLastStatus = 0;
        bool usedNtQuery = false;
        bool r0Available = false;
    };

    void initializeUi();
    void applyTranslatedText();
    void applySnapshot(const Snapshot& snapshot);
    void rebuildTable();
    void updateDetail();
    void applyColumnPreset(ViewPreset preset);
    void updatePresetButtons();
    void showHeaderMenu(const QPoint& localPosition);
    void showRowMenu(const QPoint& localPosition);
    void runControlAction(unsigned long action);
    void runControlAction(const ThreadRow& row, unsigned long action);
    const ThreadRow* selectedRow() const;
    int selectedSourceIndex() const;

    static Snapshot collectSnapshot(Mode mode);
    static QString stateText(std::uint32_t stateValue);
    static QString waitReasonText(std::uint32_t waitReasonValue);
    static QString r0StatusText(std::uint32_t statusValue);
    static QString addressText(std::uint64_t addressValue);
    static QString pointerText(std::uint64_t addressValue);
    static QString protectionReasonText(ProtectionKind protectionKind);
    static QString queueTypeText(std::uint32_t queueType);
    static QString workQueueEntryStatusText(std::uint32_t status);
    static QString snapshotDiagnosticText(const Snapshot& snapshot, Mode mode);

    Mode m_mode = Mode::SystemThreads;
    ViewPreset m_viewPreset = ViewPreset::Overview;
    QLineEdit* m_filterEdit = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_suspendButton = nullptr;
    QPushButton* m_resumeButton = nullptr;
    QPushButton* m_terminateButton = nullptr;
    QPushButton* m_overviewButton = nullptr;
    QPushButton* m_evidenceButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTableWidget* m_table = nullptr;
    ks::ui::StructuredFieldView* m_detailEditor = nullptr;
    std::vector<ThreadRow> m_rows;
    bool m_refreshRunning = false;
    std::uint64_t m_refreshTicket = 0;
};
