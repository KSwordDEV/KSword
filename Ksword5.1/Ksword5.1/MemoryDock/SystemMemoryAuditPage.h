#pragma once

// ============================================================
// SystemMemoryAuditPage.h
// 作用：
// 1) 从系统全局视角审计实际驻留的物理内存，而不是只罗列普通进程；
// 2) 同时展示进程私有驻留、内核池标签、Big Pool 与页面链表；
// 3) 明确展示尚不能由稳定快照接口唯一归属的物理内存余量。
// ============================================================

#include "MemoryAccessBackend.h"
#include "../../../shared/evidence/MemorySnapshotAccounting.h"

#include <QHash>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

class QCheckBox;
class QComboBox;
class QEvent;
class QLabel;
class QLineEdit;
class CodeEditorWidget;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTabWidget;
class QTimer;
class QTreeWidget;
class PhysicalPageAttributionPage;
class HyperVMemoryPage;
class MemoryAttributionChart;
namespace ksword::pfn { struct Scan; }

class SystemMemoryAuditPage final : public QWidget
{
public:
    explicit SystemMemoryAuditPage(QWidget* parent = nullptr);

    // refreshSnapshot：重新采集整机内存快照并刷新全部审计视图。
    void refreshSnapshot();
    std::function<void(const QString&)> openModuleDetails;

    // setDdmaSessionProvider：
    // - 作用：注入 DDMA 会话读取入口，让本页的"DDMA 复核"按钮能拿到当前通道配置；
    // - 参数 provider：返回常量引用的取值函数，由 MemoryDock 在 DDMA 页构建后注册；
    // - 说明：本页不持有也不修改 DDMA 配置，只读。未注册时复核入口保持禁用。
    void setDdmaSessionProvider(
        std::function<const ksword::memory_backend::DdmaSession&()> provider);

    // refreshDdmaCrossCheckState：
    // - 作用：按当前会话可用性刷新复核入口的启用状态与提示；
    // - 说明：DDMA 会话由别的页面维护，会话一变就必须回调这里，否则会留下一个
    //   点下去必然失败的按钮。因此它是 public 的外部刷新入口。
    void refreshDdmaCrossCheckState();

protected:
    void changeEvent(QEvent* event) override;

private:
    struct ProcessRow
    {
        std::uint64_t identity = 0;
        std::uint32_t pid = 0;
        std::uint32_t sessionId = 0;
        QString name;
        std::uint64_t privateResidentBytes = 0;
        std::uint64_t workingSetBytes = 0;
        std::uint64_t sharedResidentReferenceBytes = 0;
        std::uint64_t privateCommitBytes = 0;
        std::uint64_t pagedPoolQuotaBytes = 0;
        std::uint64_t nonPagedPoolQuotaBytes = 0;
        std::uint32_t hardFaultCount = 0;
        std::int64_t privateResidentDeltaBytes = 0;
    };

    struct PoolTagRow
    {
        std::uint32_t tag = 0;
        QString tagText;
        std::uint64_t pagedBytes = 0;
        std::uint64_t nonPagedBytes = 0;
        std::uint64_t pagedOutstanding = 0;
        std::uint64_t nonPagedOutstanding = 0;
        std::int64_t totalDeltaBytes = 0;
    };

    struct BigPoolRow
    {
        std::uint64_t identity = 0;
        std::uint64_t virtualAddress = 0;
        std::uint64_t sizeBytes = 0;
        std::uint32_t tag = 0;
        QString tagText;
        bool nonPaged = false;
        std::int64_t sizeDeltaBytes = 0;
    };

    struct TagMetadata
    {
        QString source;
        QString description;
    };

    using UserMemoryKind = ksword::memoryaudit::ResidentKind;

    struct UserResidencyRow
    {
        std::uint32_t pid = 0;
        QString processName;
        UserMemoryKind kind = UserMemoryKind::Unknown;
        QString backingPath;
        bool backingPathQueryAttempted = false;
        std::uint32_t backingPathStatus = 0;
        bool backingRegionKnown = false;
        std::uint32_t backingRegionStatus = 0;
        std::uint64_t residentReferenceBytes = 0;
        std::uint64_t privateResidentBytes = 0;
        std::uint64_t shareableResidentBytes = 0;
        std::uint64_t sharedResidentReferenceBytes = 0;
        std::uint64_t proportionalResidentBytes = 0;
    };

    struct UserResidencyScan
    {
        QString sampledAt;
        QStringList errors;
        std::uint32_t processCount = 0;
        std::uint32_t accessibleProcessCount = 0;
        std::uint32_t inaccessibleProcessCount = 0;
        std::uint64_t residentReferenceBytes = 0;
        std::uint64_t privateResidentBytes = 0;
        std::uint64_t sharedResidentReferenceBytes = 0;
        std::uint64_t proportionalResidentBytes = 0;
        std::vector<UserResidencyRow> rows;
    };

    struct SnapshotError
    {
        QString sourceText;
        QString argument;
    };

    struct Snapshot
    {
        QString sampledAt;
        QStringList errors;
        std::vector<SnapshotError> pendingErrors;
        std::uint64_t pageSize = 4096;

        std::uint64_t installedPhysicalBytes = 0;
        bool installedPhysicalValid = false;
        std::uint32_t installedPhysicalStatus = 0;
        bool usablePhysicalValid = false;
        QString usablePhysicalSource;
        ksword::memoryaudit::ReservedEstimate reserved;
        std::uint64_t totalPhysicalBytes = 0;
        std::uint64_t availableBytes = 0;
        std::uint64_t residentAvailableBytes = 0;
        std::uint64_t inUseBytes = 0;
        ksword::memoryaudit::SystemCommit commit;
        bool sharedCommittedValid = false;
        std::uint64_t sharedCommittedBytes = 0;

        bool memoryListAvailable = false;
        std::uint64_t zeroBytes = 0;
        std::uint64_t freeBytes = 0;
        std::uint64_t modifiedBytes = 0;
        std::uint64_t modifiedNoWriteBytes = 0;
        std::uint64_t modifiedPageFileBytes = 0;
        std::uint64_t badBytes = 0;
        std::array<std::uint64_t, 8> standbyBytes{};
        std::array<std::uint64_t, 8> repurposedBytes{};

        bool performanceAvailable = false;
        std::uint64_t pagedPoolCommittedBytes = 0;
        std::uint64_t nonPagedPoolBytes = 0;
        std::uint64_t pagedPoolResidentBytes = 0;
        std::uint64_t systemCodeResidentBytes = 0;
        std::uint64_t systemDriverResidentBytes = 0;
        std::uint64_t systemCacheResidentBytes = 0;
        std::uint64_t mdlAllocatedBytes = 0;
        std::uint64_t pfnDatabaseCommittedBytes = 0;
        std::uint64_t systemPageTableCommittedBytes = 0;
        std::uint64_t contiguousAllocatedBytes = 0;
        std::uint64_t broadSystemCacheBytes = 0;

        std::uint64_t processPrivateResidentBytes = 0;
        std::uint64_t processWorkingSetReferenceBytes = 0;
        std::uint64_t processSharedResidentReferenceBytes = 0;
        std::uint64_t processPrivateCommitBytes = 0;
        std::uint64_t processPagedPoolQuotaBytes = 0;
        std::uint64_t processNonPagedPoolQuotaBytes = 0;
        std::vector<ProcessRow> processes;

        std::uint64_t poolTagPagedBytes = 0;
        std::uint64_t poolTagNonPagedBytes = 0;
        std::vector<PoolTagRow> poolTags;
        std::vector<BigPoolRow> bigPool;

        std::uint64_t identifiedResidentLowerBoundBytes = 0;
        std::uint64_t unattributedResidentBytes = 0;
        std::uint64_t overAccountedResidentBytes = 0;
    };

    void initializeUi();
    void initializeConnections();
    void retranslateUi();
    // applyThemedStyle：集中下发依赖主题 token 的样式（摘要卡片外壳、卡片标题与数值）。
    // 构造期调用一次，changeEvent 收到调色板变化时再调一次。
    void applyThemedStyle();
    // updateSummaryTiles：把当前快照写进 6 格摘要卡片下行的数值文本。
    void updateSummaryTiles();
    bool usePfnOverview() const;
    void applyPfnOverview(const std::shared_ptr<ksword::pfn::Scan>& scan);
    void scheduleCurrentDetailViewRebuild();
    void rebuildCurrentDetailView();
    void applySnapshot(Snapshot snapshot, std::uint64_t ticket);
    void startUserResidencyScan();
    void applyUserResidencyScan(UserResidencyScan scan, std::uint64_t ticket);
    void rebuildOverview();
    void rebuildUserResidencyTable();
    void rebuildProcessTable();
    void rebuildPoolTagTable();
    void rebuildBigPoolTable();
    void updateDetails();
    void updateStatus();
    void loadPoolTagMetadata();

    // runDdmaCrossCheck：
    // - 作用：对用户给定的物理页，分别用标准通道和 DDMA 各读一页并逐字节比对；
    // - 处理逻辑：两侧任何一侧读失败都只报"无法比对"，不下一致/不一致的结论；
    // - 说明：两者不一致正是"这一页被 SLAT 重定向或隐藏"的直接证据，而这正是
    //   本页"无法归属的驻留内存"一栏最需要的第二个视角。
    void runDdmaCrossCheck();

    static Snapshot collectSnapshot();
    static UserResidencyScan collectUserResidency(const std::vector<ProcessRow>& processes, std::uint64_t pageSize);
    static QString formatBytes(std::uint64_t bytes);
    static QString formatDelta(std::int64_t bytes);
    static QString formatPercent(std::uint64_t bytes, std::uint64_t totalBytes);

private:
    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_userResidencyScanButton = nullptr;
    QPushButton* m_pfnScanButton = nullptr;
    PhysicalPageAttributionPage* m_pfnPage = nullptr;
    HyperVMemoryPage* m_hyperVPage = nullptr;
    MemoryAttributionChart* m_snapshotChart = nullptr;
    QComboBox* m_overviewSource = nullptr;
    QLabel* m_overviewSample = nullptr;
    std::shared_ptr<const ksword::pfn::Scan> m_pfnOverviewScan;
    bool m_pfnOverviewAttemptFailed = false;
    QCheckBox* m_autoRefreshCheck = nullptr;
    QSpinBox* m_intervalSpin = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QLabel* m_totalLabel = nullptr;
    QLabel* m_installedLabel = nullptr;
    QLabel* m_inUseLabel = nullptr;
    QLabel* m_availableLabel = nullptr;
    QLabel* m_commitLabel = nullptr;
    QLabel* m_unattributedLabel = nullptr;
    QTabWidget* m_detailTabs = nullptr;
    QTreeWidget* m_overviewTree = nullptr;
    QTableWidget* m_userResidencyTable = nullptr;
    QTableWidget* m_processTable = nullptr;
    QTableWidget* m_poolTagTable = nullptr;
    QTableWidget* m_bigPoolTable = nullptr;
    CodeEditorWidget* m_detailText = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTimer* m_autoRefreshTimer = nullptr;

    // DDMA 复核入口。本页只读 DDMA 会话，配置仍然只在 DDMA 子页上做。
    QLineEdit* m_ddmaCrossCheckAddressEdit = nullptr;
    QPushButton* m_ddmaCrossCheckButton = nullptr;
    QLabel* m_ddmaCrossCheckResultLabel = nullptr;
    std::function<const ksword::memory_backend::DdmaSession&()> m_ddmaSessionProvider;

    Snapshot m_snapshot;
    UserResidencyScan m_userResidencyScan;
    bool m_hasSnapshot = false;
    bool m_refreshing = false;
    bool m_startUserResidencyScanAfterSnapshot = false;
    bool m_detailViewRebuildScheduled = false;
    bool m_overviewDirty = true;
    bool m_userResidencyTableDirty = true;
    bool m_processTableDirty = true;
    bool m_poolTagTableDirty = true;
    bool m_bigPoolTableDirty = true;
    QHash<std::uint64_t, std::uint64_t> m_previousProcessPrivateBytes;
    QHash<std::uint32_t, std::uint64_t> m_previousPoolTagBytes;
    QHash<std::uint64_t, std::uint64_t> m_previousBigPoolBytes;
    QHash<QString, std::uint64_t> m_previousSummaryBytes;
    QHash<QString, std::int64_t> m_summaryDeltaBytes;
    QHash<std::uint32_t, TagMetadata> m_poolTagMetadata;
    QString m_poolTagMetadataSource;
    QString m_lastSnapshotWarningSignature;
    std::atomic<std::uint64_t> m_snapshotRefreshTicket{ 0 };
    std::atomic<std::uint64_t> m_userResidencyScanTicket{ 0 };
    std::atomic_bool m_userResidencyScanInProgress{ false };
};
