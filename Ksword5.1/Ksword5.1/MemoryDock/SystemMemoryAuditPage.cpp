#include "../UI/MemoryPageNavigationSchema.h"
#include "../UI/StructuredFieldView.h"
#include "SystemMemoryAuditPage.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/ThemeBinding.h"
#include "PhysicalPageAttributionPage.h"
#include "HyperVMemoryPage.h"
#include "MemoryAttributionChart.h"

#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include "../UI/AdaptivePageScroll.h" // ks::ui::EnablePageInnerScroll：页面内部滚动壳。
// 表格交互与可视化表格基类：提供数值排序单元格、全局操作条与冻结行列能力。
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/MetricAreaWindow.h"
#include "../UI/FlowLayout.h"
#include "../UI/PageControlStyle.h"
#include "../ksword/log/log.h"
#include "MemoryAccessBackend.h"

#include <QAbstractItemView>
#include <QAbstractTableModel>
#include <QThreadPool>
#include <QShowEvent>
#include <QScrollBar>
#include <QItemSelectionModel>
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TableRowFilterSupport.h"
#include <QHBoxLayout>
#include <QCoreApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFrame>
#include <QFutureWatcher>
#include <QPromise>
#include <QGridLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QList>
#include <QPointer>
#include <QPushButton>
#include <QSizePolicy>
#include <QSpinBox>
#include <QSplitter>
#include <QTableWidget>
#include <QTabWidget>
#include <QTimer>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <exception>
#include <cmath>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#pragma comment(lib, "Psapi.lib")

class AuditTableModel final : public QAbstractTableModel {
public:
    using Resolver = std::function<QVariant(std::size_t, int, int)>;
    explicit AuditTableModel(QObject* parent) : QAbstractTableModel(parent) {}
    std::function<void(int, Qt::SortOrder)> requestSort;
    void setHeaders(QStringList value) { const bool changed = value.size() != headers.size(); const QPointer<AuditTableModel> alive(this); if (changed) { beginResetModel(); if (!alive) { return; } } headers = std::move(value); if (changed) { endResetModel(); } else if (!headers.isEmpty()) { emit headerDataChanged(Qt::Horizontal, 0, headers.size() - 1); } }
    void publish(std::shared_ptr<const std::vector<std::size_t>> value, Resolver resolve) {
        const QPointer<AuditTableModel> alive(this); beginResetModel(); if (!alive) { return; } rows = std::move(value); resolver = std::move(resolve); endResetModel();
    }
    int rowCount(const QModelIndex& parent = {}) const override { return parent.isValid() || !rows ? 0 : static_cast<int>(rows->size()); }
    int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : headers.size(); }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        return orientation == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 && section < headers.size() ? QVariant(headers[section]) : QVariant();
    }
    QVariant data(const QModelIndex& index, int role) const override {
        if (!index.isValid() || index.row() < 0 || index.row() >= rowCount() || index.column() < 0 || index.column() >= columnCount() || !resolver) { return {}; }
        return resolver((*rows)[static_cast<std::size_t>(index.row())], index.column(), role);
    }
    Qt::ItemFlags flags(const QModelIndex& index) const override { return index.isValid() ? Qt::ItemIsEnabled | Qt::ItemIsSelectable : Qt::NoItemFlags; }
    void sort(int column, Qt::SortOrder order) override { if (requestSort) { requestSort(column, order); } }
    void refreshColors(int first, int last) { if (first >= 0 && last >= first && last < rowCount()) { emit dataChanged(index(first, 0), index(last, columnCount() - 1), {Qt::ForegroundRole}); } }
private:
    QStringList headers;
    std::shared_ptr<const std::vector<std::size_t>> rows;
    Resolver resolver;
};
class AuditTableView final : public ks::ui::TableActionTableView {
public:
    explicit AuditTableView(QWidget* parent) : TableActionTableView(parent) { auditModel = new AuditTableModel(this); setModel(auditModel); }
    AuditTableModel* auditModel;
    int rowCount() const { return auditModel->rowCount(); }
    void setHorizontalHeaderLabels(QStringList headers) { auditModel->setHeaders(std::move(headers)); }
};

namespace
{
    using NtQuerySystemInformationFunction = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

    constexpr ULONG kSystemPerformanceInformation = 2;
    constexpr ULONG kSystemProcessInformation = 5;
    constexpr ULONG kSystemPoolTagInformation = 22;
    constexpr ULONG kSystemBigPoolInformation = 66;
    constexpr ULONG kSystemMemoryListInformation = 80;
    constexpr ULONG kSystemMemoryUsageInformation = 181;
    constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
    constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023UL);
    constexpr std::size_t kMaximumNativeQueryBytes = 128ULL * 1024ULL * 1024ULL;
    constexpr std::size_t kMaximumWorkingSetQueryBytes = 512ULL * 1024ULL * 1024ULL;

    struct NativeUnicodeString
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    };

    struct NativeSystemProcessInformation
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        ULONGLONG WorkingSetPrivateSize;
        ULONG HardFaultCount;
        ULONG NumberOfThreadsHighWatermark;
        ULONGLONG CycleTime;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        NativeUnicodeString ImageName;
        LONG BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR UniqueProcessKey;
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
    };

    struct NativeSystemPoolTag
    {
        union
        {
            UCHAR Tag[4];
            ULONG TagUlong;
        };
        ULONG PagedAllocs;
        ULONG PagedFrees;
        SIZE_T PagedUsed;
        ULONG NonPagedAllocs;
        ULONG NonPagedFrees;
        SIZE_T NonPagedUsed;
    };

    struct NativeSystemPoolTagInformation
    {
        ULONG Count;
        NativeSystemPoolTag TagInfo[1];
    };

    struct NativeSystemBigPoolEntry
    {
        ULONG_PTR VirtualAddressAndFlags;
        SIZE_T SizeInBytes;
        union
        {
            UCHAR Tag[4];
            ULONG TagUlong;
        };
    };

    struct NativeSystemBigPoolInformation
    {
        ULONG Count;
        NativeSystemBigPoolEntry AllocatedInfo[1];
    };

    struct NativeSystemMemoryListInformation
    {
        SIZE_T ZeroPageCount;
        SIZE_T FreePageCount;
        SIZE_T ModifiedPageCount;
        SIZE_T ModifiedNoWritePageCount;
        SIZE_T BadPageCount;
        SIZE_T PageCountByPriority[8];
        SIZE_T RepurposedPagesByPriority[8];
        SIZE_T ModifiedPageCountPageFile;
    };

    struct NativeSystemMemoryUsageInformation
    {
        ULONGLONG TotalPhysicalBytes;
        ULONGLONG AvailableBytes;
        LONGLONG ResidentAvailableBytes;
        ULONGLONG CommittedBytes;
        ULONGLONG SharedCommittedBytes;
        ULONGLONG CommitLimitBytes;
        ULONGLONG PeakCommitmentBytes;
    };

    // This layout is stable through ResidentSystemDriverPage. Newer optional fields
    // are read only when NtQuerySystemInformation reports enough returned bytes.
    // Reference: System Informer PHNT ntexapi.h, SYSTEM_PERFORMANCE_INFORMATION.
    struct NativeSystemPerformanceInformation
    {
        LARGE_INTEGER IdleProcessTime;
        LARGE_INTEGER IoReadTransferCount;
        LARGE_INTEGER IoWriteTransferCount;
        LARGE_INTEGER IoOtherTransferCount;
        ULONG IoReadOperationCount;
        ULONG IoWriteOperationCount;
        ULONG IoOtherOperationCount;
        ULONG AvailablePages;
        ULONG CommittedPages;
        ULONG CommitLimit;
        ULONG PeakCommitment;
        ULONG PageFaultCount;
        ULONG CopyOnWriteCount;
        ULONG TransitionCount;
        ULONG CacheTransitionCount;
        ULONG DemandZeroCount;
        ULONG PageReadCount;
        ULONG PageReadIoCount;
        ULONG CacheReadCount;
        ULONG CacheIoCount;
        ULONG DirtyPagesWriteCount;
        ULONG DirtyWriteIoCount;
        ULONG MappedPagesWriteCount;
        ULONG MappedWriteIoCount;
        ULONG PagedPoolPages;
        ULONG NonPagedPoolPages;
        ULONG PagedPoolAllocs;
        ULONG PagedPoolFrees;
        ULONG NonPagedPoolAllocs;
        ULONG NonPagedPoolFrees;
        ULONG FreeSystemPtes;
        ULONG ResidentSystemCodePage;
        ULONG TotalSystemDriverPages;
        ULONG TotalSystemCodePages;
        ULONG NonPagedPoolLookasideHits;
        ULONG PagedPoolLookasideHits;
        ULONG AvailablePagedPoolPages;
        ULONG ResidentSystemCachePage;
        ULONG ResidentPagedPoolPage;
        ULONG ResidentSystemDriverPage;
        ULONG CcFastReadNoWait;
        ULONG CcFastReadWait;
        ULONG CcFastReadResourceMiss;
        ULONG CcFastReadNotPossible;
        ULONG CcFastMdlReadNoWait;
        ULONG CcFastMdlReadWait;
        ULONG CcFastMdlReadResourceMiss;
        ULONG CcFastMdlReadNotPossible;
        ULONG CcMapDataNoWait;
        ULONG CcMapDataWait;
        ULONG CcMapDataNoWaitMiss;
        ULONG CcMapDataWaitMiss;
        ULONG CcPinMappedDataCount;
        ULONG CcPinReadNoWait;
        ULONG CcPinReadWait;
        ULONG CcPinReadNoWaitMiss;
        ULONG CcPinReadWaitMiss;
        ULONG CcCopyReadNoWait;
        ULONG CcCopyReadWait;
        ULONG CcCopyReadNoWaitMiss;
        ULONG CcCopyReadWaitMiss;
        ULONG CcMdlReadNoWait;
        ULONG CcMdlReadWait;
        ULONG CcMdlReadNoWaitMiss;
        ULONG CcMdlReadWaitMiss;
        ULONG CcReadAheadIos;
        ULONG CcLazyWriteIos;
        ULONG CcLazyWritePages;
        ULONG CcDataFlushes;
        ULONG CcDataPages;
        ULONG ContextSwitches;
        ULONG FirstLevelTbFills;
        ULONG SecondLevelTbFills;
        ULONG SystemCalls;
        ULONGLONG CcTotalDirtyPages;
        ULONGLONG CcDirtyPageThreshold;
        LONGLONG ResidentAvailablePages;
        ULONGLONG SharedCommittedPages;
        ULONGLONG MdlPagesAllocated;
        ULONGLONG PfnDatabaseCommittedPages;
        ULONGLONG SystemPageTableCommittedPages;
        ULONGLONG ContiguousPagesAllocated;
    };

    // SummaryTileTitle 作用：
    // - 描述一格摘要卡片上行小标题的 objectName 与英文源文案；
    // - objectName 供语言切换后按 findChild 回查重译（标题是局部控件，不占成员变量）；
    // - sourceText 交给 localized() 走语言包的 source_translations。
    struct SummaryTileTitle
    {
        const char* objectName;
        const char* sourceText;
    };

    // kSummaryTileTitles 作用：
    // - 按网格摆放顺序给出 6 格摘要卡片的小标题；
    // - 顺序必须与 initializeUi 中的数值标签数组严格一一对应，否则标题会串格；
    // - 构建与重译共用同一份表，避免两处文案写歪。
    constexpr std::array<SummaryTileTitle, 6> kSummaryTileTitles{ {
        { "kswordMemoryAuditTileTitleInstalled", "Installed RAM" },
        { "kswordMemoryAuditTileTitleUsable", "Windows usable" },
        { "kswordMemoryAuditTileTitleInUse", "In use" },
        { "kswordMemoryAuditTileTitleAvailable", "Available" },
        { "kswordMemoryAuditTileTitleCommit", "Commit" },
        { "kswordMemoryAuditTileTitleUnattributed", "Snapshot remainder" }
    } };

    // summaryTileObjectName 作用：
    // - 返回摘要卡片外壳统一使用的 objectName；
    // - 无入参；返回值同时被样式表选择器和 findChildren 使用，保证两处不会写歪。
    QString summaryTileObjectName()
    {
        return QStringLiteral("kswordMemoryAuditSummaryTile");
    }

    NtQuerySystemInformationFunction resolveNtQuerySystemInformation()
    {
        static const auto function = reinterpret_cast<NtQuerySystemInformationFunction>(
            ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        return function;
    }

    bool nativeSuccess(const LONG status)
    {
        return status >= 0;
    }

    QString statusHex(const LONG status)
    {
        return QStringLiteral("0x%1").arg(static_cast<quint32>(status), 8, 16, QLatin1Char('0')).toUpper();
    }

    bool queryVariableSystemInformation(
        const NtQuerySystemInformationFunction queryFunction,
        const ULONG informationClass,
        std::vector<std::byte>& bufferOut,
        LONG& statusOut)
    {
        bufferOut.clear();
        if (queryFunction == nullptr)
        {
            statusOut = static_cast<LONG>(0xC0000002UL);
            return false;
        }

        ULONG requiredBytes = 0;
        statusOut = queryFunction(informationClass, nullptr, 0, &requiredBytes);
        std::size_t bufferBytes = std::max<std::size_t>(requiredBytes, 64ULL * 1024ULL);
        for (int attempt = 0; attempt < 8 && bufferBytes <= kMaximumNativeQueryBytes; ++attempt)
        {
            bufferOut.assign(bufferBytes, std::byte{});
            ULONG returnedBytes = 0;
            statusOut = queryFunction(
                informationClass,
                bufferOut.data(),
                static_cast<ULONG>(bufferOut.size()),
                &returnedBytes);
            if (nativeSuccess(statusOut))
            {
                if (returnedBytes > 0 && returnedBytes <= bufferOut.size())
                {
                    bufferOut.resize(returnedBytes);
                }
                return true;
            }
            if (statusOut != kStatusInfoLengthMismatch && statusOut != kStatusBufferTooSmall)
            {
                bufferOut.clear();
                return false;
            }
            const std::size_t requestedBytes = returnedBytes > bufferOut.size()
                ? static_cast<std::size_t>(returnedBytes)
                : bufferOut.size() * 2ULL;
            bufferBytes = std::min<std::size_t>(
                std::max<std::size_t>(requestedBytes, bufferOut.size() + 64ULL * 1024ULL),
                kMaximumNativeQueryBytes + 1ULL);
        }
        bufferOut.clear();
        return false;
    }

    QString printableTag(const UCHAR tag[4])
    {
        char text[5]{};
        for (int index = 0; index < 4; ++index)
        {
            const unsigned char value = tag[index];
            text[index] = (value >= 0x20 && value <= 0x7E) ? static_cast<char>(value) : '.';
        }
        return QString::fromLatin1(text, 4);
    }

    std::uint64_t multiplyPages(const std::uint64_t pages, const std::uint64_t pageSize)
    {
        if (pageSize == 0 || pages > (std::numeric_limits<std::uint64_t>::max)() / pageSize)
        {
            return (std::numeric_limits<std::uint64_t>::max)();
        }
        return pages * pageSize;
    }

    QString localized(const char* sourceText)
    {
        return ks::i18n::packedSourceText(QString::fromUtf8(sourceText));
    }

    QString commitEvidence(const ksword::memoryaudit::SystemCommit& commit)
    {
        using ksword::memoryaudit::CommitSource;
        const QString source = commit.source == CommitSource::PerformanceInfo
            ? QStringLiteral("GetPerformanceInfo")
            : (commit.source == CommitSource::NativeMemoryUsage
                ? QStringLiteral("SystemMemoryUsageInformation") : localized("Unavailable"));
        return localized("System commit source: %1 | GetPerformanceInfo Win32: %2 | Native status: %3")
            .arg(source)
            .arg(commit.publicAttempted ? QString::number(commit.publicStatus) : localized("Not queried"))
            .arg(commit.nativeAttempted ? statusHex(commit.nativeStatus) : localized("Not queried"));
    }

    class ScopedHandle final
    {
    public:
        explicit ScopedHandle(HANDLE handle = nullptr)
            : m_handle(handle)
        {
        }

        ~ScopedHandle()
        {
            if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(m_handle);
            }
        }

        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;

        HANDLE get() const
        {
            return m_handle;
        }

        explicit operator bool() const
        {
            return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
        }

    private:
        HANDLE m_handle = nullptr;
    };

    bool queryProcessWorkingSet(
        HANDLE processHandle,
        const std::uint64_t estimatedWorkingSetBytes,
        const std::uint64_t pageSize,
        std::vector<PSAPI_WORKING_SET_BLOCK>& blocksOut)
    {
        blocksOut.clear();
        if (processHandle == nullptr || pageSize == 0)
        {
            return false;
        }

        const std::size_t headerBytes = offsetof(PSAPI_WORKING_SET_INFORMATION, WorkingSetInfo);
        const std::uint64_t estimatedPages = estimatedWorkingSetBytes / pageSize;
        std::size_t bufferBytes = headerBytes + static_cast<std::size_t>(
            std::min<std::uint64_t>(estimatedPages + 2048ULL, kMaximumWorkingSetQueryBytes / sizeof(PSAPI_WORKING_SET_BLOCK)))
            * sizeof(PSAPI_WORKING_SET_BLOCK);
        bufferBytes = std::max<std::size_t>(bufferBytes, 256ULL * 1024ULL);

        for (int attempt = 0; attempt < 8 && bufferBytes <= kMaximumWorkingSetQueryBytes; ++attempt)
        {
            std::vector<std::byte> buffer(bufferBytes, std::byte{});
            if (::QueryWorkingSet(processHandle, buffer.data(), static_cast<DWORD>(buffer.size())) != FALSE)
            {
                const auto* const information =
                    reinterpret_cast<const PSAPI_WORKING_SET_INFORMATION*>(buffer.data());
                const std::size_t capacity = (buffer.size() - headerBytes) / sizeof(PSAPI_WORKING_SET_BLOCK);
                const std::size_t count = std::min<std::size_t>(information->NumberOfEntries, capacity);
                blocksOut.assign(information->WorkingSetInfo, information->WorkingSetInfo + count);
                return true;
            }

            if (::GetLastError() != ERROR_BAD_LENGTH || bufferBytes == kMaximumWorkingSetQueryBytes)
            {
                return false;
            }
            bufferBytes = std::min<std::size_t>(bufferBytes * 2ULL, kMaximumWorkingSetQueryBytes);
        }
        return false;
    }

    struct MappedPathObservation
    {
        QString path;
        std::uint32_t status = 0;
        bool regionKnown = false;
        std::uint32_t regionStatus = ERROR_CALL_NOT_IMPLEMENTED;
        ksword::memoryaudit::BackingProof proof = ksword::memoryaudit::BackingProof::Unresolved;
    };

    // Documented WIN32_MEMORY_REGION_INFORMATION ABI. SDKs gated below RS1 do
    // not expose its names; this private mirror avoids changing the application
    // OS target or importing an API unavailable on older Windows installations.
    struct PublicMemoryRegionInformation
    {
        PVOID AllocationBase;
        ULONG AllocationProtect;
        ULONG Private : 1;
        ULONG MappedDataFile : 1;
        ULONG MappedImage : 1;
        ULONG MappedPageFile : 1;
        ULONG MappedPhysical : 1;
        ULONG DirectMapped : 1;
        ULONG Reserved : 26;
        SIZE_T RegionSize;
        SIZE_T CommitSize;
    };
    static_assert(offsetof(PublicMemoryRegionInformation, RegionSize) == (sizeof(void*) == 8 ? 16 : 12));
    static_assert(sizeof(PublicMemoryRegionInformation) == (sizeof(void*) == 8 ? 32 : 20));

    MappedPathObservation queryMappedBacking(HANDLE processHandle, const void* address, const MEMORY_BASIC_INFORMATION& region)
    {
        MappedPathObservation observation;
        using RegionQuery = BOOL(WINAPI*)(HANDLE, const VOID*, int, PVOID, SIZE_T, PSIZE_T);
        static const auto queryRegion = [] {
            auto function = reinterpret_cast<RegionQuery>(::GetProcAddress(
                ::GetModuleHandleW(L"kernel32.dll"), "QueryVirtualMemoryInformation"));
            if (!function)
            {
                const HMODULE memoryApi = ::LoadLibraryExW(L"api-ms-win-core-memory-l1-1-4.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
                if (memoryApi) { function = reinterpret_cast<RegionQuery>(::GetProcAddress(memoryApi, "QueryVirtualMemoryInformation")); }
            }
            return function;
        }();
        if (queryRegion)
        {
            PublicMemoryRegionInformation information{};
            SIZE_T returned = 0;
            ::SetLastError(ERROR_SUCCESS);
            constexpr int memoryRegionInfo = 0;
            const bool success = queryRegion(processHandle, address, memoryRegionInfo, &information, sizeof(information), &returned) != FALSE;
            observation.regionStatus = success ? ERROR_SUCCESS : ::GetLastError();
            const auto allocation = reinterpret_cast<std::uintptr_t>(information.AllocationBase);
            const auto virtualAddress = reinterpret_cast<std::uintptr_t>(address);
            const bool complete = success && returned == sizeof(information)
                && information.AllocationBase == region.AllocationBase
                && information.AllocationProtect == region.AllocationProtect
                && information.RegionSize && virtualAddress >= allocation
                && virtualAddress - allocation < information.RegionSize
                && information.CommitSize <= information.RegionSize && information.Reserved == 0;
            if (complete)
            {
                observation.regionKnown = true;
                using ksword::memoryaudit::BackingProof;
                // Named documented flags establish backing; a missing path
                // establishes only the failed path observation.
                if (region.Type == MEM_MAPPED && information.MappedPageFile && !information.MappedDataFile
                    && !information.MappedImage && !information.MappedPhysical && !information.Private && !information.DirectMapped)
                {
                    observation.proof = BackingProof::Pagefile;
                }
                else if (region.Type == MEM_MAPPED && information.MappedDataFile && !information.MappedPageFile
                    && !information.MappedImage && !information.MappedPhysical && !information.Private)
                {
                    observation.proof = BackingProof::DataFile;
                }
                else if (region.Type == MEM_IMAGE && information.MappedImage) { observation.proof = BackingProof::Image; }
                else if (information.MappedPhysical) { observation.proof = BackingProof::Physical; }
            }
            else if (success) { observation.regionStatus = ERROR_INVALID_DATA; }
        }
        return observation;
    }

    MappedPathObservation mappedFilePath(HANDLE processHandle, const void* address, const MEMORY_BASIC_INFORMATION& region)
    {
        auto observation = queryMappedBacking(processHandle, address, region);
        const auto confirmBacking = [&] {
            MEMORY_BASIC_INFORMATION afterRegion{};
            ::SetLastError(ERROR_SUCCESS);
            if (::VirtualQueryEx(processHandle, address, &afterRegion, sizeof(afterRegion)) != sizeof(afterRegion))
            {
                observation.regionKnown = false;
                observation.regionStatus = ::GetLastError();
                observation.proof = ksword::memoryaudit::BackingProof::Unresolved;
                observation.path.clear();
                observation.status = observation.regionStatus;
                return;
            }
            const auto after = queryMappedBacking(processHandle, address, afterRegion);
            const bool regionChanged = afterRegion.AllocationBase != region.AllocationBase || afterRegion.Type != region.Type
                || afterRegion.AllocationProtect != region.AllocationProtect || afterRegion.BaseAddress != region.BaseAddress
                || afterRegion.RegionSize != region.RegionSize || afterRegion.State != region.State;
            if (regionChanged || !observation.regionKnown || !after.regionKnown || observation.proof != after.proof)
            {
                observation.regionKnown = false;
                observation.regionStatus = after.regionStatus ? after.regionStatus : ERROR_INVALID_DATA;
                observation.proof = ksword::memoryaudit::BackingProof::Unresolved;
                if (regionChanged) { observation.path.clear(); observation.status = ERROR_INVALID_DATA; }
            }
        };
        std::wstring buffer(32768, L'\0');
        ::SetLastError(ERROR_SUCCESS);
        const DWORD length = ::GetMappedFileNameW(
            processHandle,
            const_cast<void*>(address),
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        const auto outcome = ksword::memoryaudit::mappedPathOutcome(length, buffer.size(), ::GetLastError());
        if (!outcome.valid)
        {
            observation.status = outcome.error;
            confirmBacking();
            return observation;
        }
        buffer.resize(length);
        QString path = QString::fromStdWString(buffer);

        static const std::vector<std::pair<QString, QString>> deviceMappings = []() {
            std::vector<std::pair<QString, QString>> mappings;
            for (wchar_t driveLetter = L'A'; driveLetter <= L'Z'; ++driveLetter)
            {
                const wchar_t driveName[]{ driveLetter, L':', L'\0' };
                std::wstring deviceBuffer(32768, L'\0');
                const DWORD deviceLength = ::QueryDosDeviceW(
                    driveName,
                    deviceBuffer.data(),
                    static_cast<DWORD>(deviceBuffer.size()));
                if (deviceLength != 0)
                {
                    mappings.emplace_back(
                        QString::fromWCharArray(deviceBuffer.c_str()),
                        QString::fromWCharArray(driveName));
                }
            }
            return mappings;
        }();
        for (const auto& [devicePrefix, driveName] : deviceMappings)
        {
            if (path.startsWith(devicePrefix, Qt::CaseInsensitive))
            {
                path = driveName + path.mid(devicePrefix.size());
                break;
            }
        }
        observation.path = QDir::toNativeSeparators(path);
        confirmBacking();
        if (!observation.path.isEmpty() && observation.proof == ksword::memoryaudit::BackingProof::Pagefile)
        {
            observation.path.clear();
            observation.status = ERROR_INVALID_DATA;
            observation.regionKnown = false;
            observation.regionStatus = ERROR_INVALID_DATA;
            observation.proof = ksword::memoryaudit::BackingProof::Unresolved;
        }
        return observation;
    }

    void configureTable(AuditTableView* table, const QStringList& headers)
    {
        table->setHorizontalHeaderLabels(headers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setStretchLastSection(true);
        table->horizontalHeader()->setDefaultSectionSize(128);
        ks::ui::SetTableColumnAutoFitEnabled(table, false);
        // All four business filters live in immutable model indices; no direct row-hide writer remains.
        ks::ui::SetTableRowFilterBusinessOwnership(table, ks::ui::TableRowFilterBusinessOwnership::ExclusiveSharedIdentity);
    }


}

struct SystemMemoryAuditPage::ProjectionData {
    AuditKind kind;
    Snapshot snapshot;
    UserResidencyScan residency;
    QHash<std::uint32_t, TagMetadata> metadata;
    ks::i18n::SourceTextSnapshot language;
    std::shared_ptr<std::vector<std::size_t>> rows = valueStorage<std::vector<std::size_t>>();
    int selectedRow = -1;
};
struct SystemMemoryAuditPage::ProjectionJob {
    std::atomic_bool done{false}, cancel{false};
    AuditKind kind;
    std::uint64_t version = 0;
    int sortColumn = 0;
    Qt::SortOrder sortOrder = Qt::DescendingOrder;
    QString filter, selectedKey;
    std::shared_ptr<ProjectionData> result;
    bool failed = false;
};
struct SystemMemoryAuditPage::MetricAreaJob {
    std::atomic_bool done{false}, cancel{false};
    AuditKind kind;
    std::shared_ptr<const ProjectionData> projection;
    int mode = 0, column = 0;
    QStringList labels;
    std::vector<ks::ui::MetricAreaNode> nodes;
    bool failed = false;
};
struct SystemMemoryAuditPage::SnapshotJob {
    std::atomic_bool done{false};
    std::uint64_t ticket = 0;
    std::shared_ptr<Snapshot> result;
    bool failed = false;
};
struct SystemMemoryAuditPage::ResidencyJob {
    std::atomic_bool done{false};
    std::uint64_t ticket = 0;
    std::shared_ptr<UserResidencyScan> result;
    bool failed = false;
};
void SystemMemoryAuditPage::retireValue(std::function<void()> destroy)
{
    // Only immutable values enter this queue; GUI models and widgets stay on their owner.
    try { QThreadPool::globalInstance()->start([destroy] { destroy(); }); }
    catch (...) { if (destroy) { destroy(); } }
}
SystemMemoryAuditPage::~SystemMemoryAuditPage()
{
    if (m_projectionJob) { m_projectionJob->cancel.store(true); }
    for (const auto& job : m_metricAreaJobs) if (job) job->cancel.store(true);
}
void SystemMemoryAuditPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    rebuildCurrentDetailView();
}

SystemMemoryAuditPage::SystemMemoryAuditPage(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    loadPoolTagMetadata();
    initializeConnections();
    m_startUserResidencyScanAfterSnapshot = true;
    refreshSnapshot();
}

void SystemMemoryAuditPage::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr)
    {
        return;
    }

    // 调色板变化（主题切换、跟随系统深浅色）时重新下发依赖 token 的样式。
    // 表格里的增量列用的是快照 QColor，只能靠重建行才能换色，所以顺带打脏。
    if (event->type() == QEvent::ApplicationPaletteChange ||
        event->type() == QEvent::PaletteChange)
    {
        applyThemedStyle();
        if (m_statusLabel != nullptr)
        {
            updateStatus();
        }
        if (m_hasSnapshot)
        {
            m_overviewDirty = true;
            for (AuditTableView* table : {m_userResidencyTable, m_processTable, m_poolTagTable, m_bigPoolTable}) {
                if (!table || !table->isVisible()) { continue; }
                const int first = qMax(0, table->rowAt(0));
                const int last = table->rowAt(table->viewport()->height() - 1);
                table->auditModel->refreshColors(first, last < 0 ? qMin(table->auditModel->rowCount() - 1, first + 256) : last);
            }
            scheduleCurrentDetailViewRebuild();
        }
        return;
    }

    if (event->type() != QEvent::LanguageChange)
    {
        return;
    }

    retranslateUi();
    invalidateTableProjections();
    if (m_hasSnapshot)
    {
        m_overviewDirty = true;
        m_userResidencyTableDirty = true;
        m_processTableDirty = true;
        m_poolTagTableDirty = true;
        m_bigPoolTableDirty = true;
        scheduleCurrentDetailViewRebuild();
        updateDetails();
        updateStatus();
    }
}

void SystemMemoryAuditPage::initializeUi()
{
    // 页面自带内部滚动壳：摘要卡片、分页表格、说明区叠起来比 Dock 高得多，
    // 放不下时在页内滚动，而不是把整个内存 Dock 撑高。根布局建在壳的内容容器上，
    // 下面以 this 为父的控件会在加入布局时被重新挂到内容容器下。
    QVBoxLayout* const rootLayout = new QVBoxLayout(ks::ui::EnablePageInnerScroll(this));
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    // 摘要卡片与结果页签局部连组，下面独立的 DDMA 复核与状态行保留原间距。
    auto* const resultGroup = new QWidget(this);
    auto* const resultLayout = new QVBoxLayout(resultGroup);
    resultLayout->setContentsMargins(0, 0, 0, 0);
    resultLayout->setSpacing(0);
    rootLayout->addWidget(resultGroup, 1);
    auto* const resultHeader = new QWidget(resultGroup);
    auto* const headerLayout = new QVBoxLayout(resultHeader);
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(6);

    // 快照与深度扫描属于全页操作，以轻底面区分下面的摘要与分项数据。
    QWidget* const snapshotToolbar = new QWidget(this);
    ks::ui::StylePrimaryToolbar(snapshotToolbar);
    auto* const controls = new ks::ui::FlowLayout(snapshotToolbar, 0, 8, 6);
    controls->setContentsMargins(8, 4, 8, 4);
    // 刷新按钮：整机内存快照的手动采集入口，沿用全局刷新图标别名。
    m_refreshButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")), localized("Refresh snapshot"), this);
    m_refreshButton->setToolTip(localized("Re-collect the whole-machine physical memory snapshot."));
    // 深度扫描按钮：逐进程遍历工作集属于耗时采集类操作，用 log_track 图标。
    m_userResidencyScanButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/log_track.svg")), localized("Deep scan user-mode residency"), this);
    m_userResidencyScanButton->setToolTip(
        localized("Walk every accessible process working set and attribute resident pages to their backing."));
    m_autoRefreshCheck = new QCheckBox(localized("Auto refresh"), this);
    m_autoRefreshCheck->setChecked(true);
    m_intervalSpin = new QSpinBox(this);
    m_intervalSpin->setRange(1, 60);
    m_intervalSpin->setValue(2);
    m_intervalSpin->setSuffix(localized(" s"));
    m_filterEdit = new QLineEdit(this);
    // 内存归属结果树的现有本地过滤，不影响深度扫描或数值输入。
    ks::ui::StyleSearchField(m_filterEdit);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setPlaceholderText(localized("Filter process, category, file, tag, or address"));
    controls->addWidget(m_refreshButton);
    controls->addWidget(m_userResidencyScanButton);
    m_pfnScanButton = new QPushButton(localized("PFN deep attribution"), this);
    controls->addWidget(m_pfnScanButton);
    m_metricAreaButton = new QPushButton(ks::i18n::sourceText(QStringLiteral("矩形面积视图")), this);
    m_metricAreaButton->setObjectName(QStringLiteral("memory_audit_metric_area"));
    m_metricAreaButton->setEnabled(false);
    controls->addWidget(m_metricAreaButton);
    controls->addWidget(m_autoRefreshCheck);
    controls->addWidget(m_intervalSpin);
    controls->addExpandingWidget(m_filterEdit, 220);
    for (auto* control : std::array<QWidget*, 7>{m_refreshButton, m_userResidencyScanButton, m_pfnScanButton,
        m_metricAreaButton, m_autoRefreshCheck, m_intervalSpin, m_filterEdit}) ks::ui::NormalizeToolbarControl(control);
    ks::ui::ApplyFlatButtonTheme(m_refreshButton, ks::ui::FlatButtonTone::Accent);
    ks::ui::ApplyFlatButtonTheme(m_userResidencyScanButton, ks::ui::FlatButtonTone::Neutral);
    ks::ui::ApplyFlatButtonTheme(m_pfnScanButton, ks::ui::FlatButtonTone::Neutral);
    headerLayout->addWidget(snapshotToolbar);

    QGridLayout* const summaryLayout = new QGridLayout();
    // 数值卡片保持紧凑，只提高横向组间留白，便于比较同一行的指标。
    summaryLayout->setHorizontalSpacing(10);
    summaryLayout->setVerticalSpacing(6);
    m_installedLabel = new QLabel(this);
    m_totalLabel = new QLabel(this);
    m_inUseLabel = new QLabel(this);
    m_availableLabel = new QLabel(this);
    m_commitLabel = new QLabel(this);
    m_unattributedLabel = new QLabel(this);
    // 数值标签顺序必须与 kSummaryTileTitles 一一对应，否则标题会挂到别人的数值上。
    const std::array<QLabel*, 6> summaryLabels{
        m_installedLabel, m_totalLabel, m_inUseLabel,
        m_availableLabel, m_commitLabel, m_unattributedLabel
    };

    // buildSummaryTile 作用：
    // - 把一格摘要包装成“上行小标题 + 下行大数值”的卡片，替换原来只有一圈细边框的裸标签；
    // - 入参 valueLabel 为已创建好的数值标签（复用既有成员，不新增成员变量）；
    // - 入参 titleEntry 提供该格的小标题 objectName 与英文源文案；
    // - 返回可直接放进网格的卡片外壳，卡片与内部两行的配色统一由 applyThemedStyle 下发。
    const auto buildSummaryTile = [this](
        QLabel* const valueLabel,
        const SummaryTileTitle& titleEntry) {
        QFrame* const tile = new QFrame(this);
        tile->setObjectName(summaryTileObjectName());
        tile->setFrameShape(QFrame::NoFrame);
        QVBoxLayout* const tileLayout = new QVBoxLayout(tile);
        // 内边距交给样式表的 padding，这里保持 0，避免与 QSS 叠加成双倍留白。
        tileLayout->setContentsMargins(0, 0, 0, 0);
        tileLayout->setSpacing(2);

        QLabel* const titleLabel = new QLabel(localized(titleEntry.sourceText), tile);
        titleLabel->setObjectName(QString::fromLatin1(titleEntry.objectName));
        valueLabel->setParent(tile);
        valueLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        // 首帧还没有快照，先占一个短横线，避免卡片高度在第一次刷新时跳变。
        valueLabel->setText(QStringLiteral("-"));
        tileLayout->addWidget(titleLabel);
        tileLayout->addWidget(valueLabel);
        return tile;
    };

    for (std::size_t index = 0; index < summaryLabels.size(); ++index)
    {
        QFrame* const tile = buildSummaryTile(summaryLabels[index], kSummaryTileTitles[index]);
        summaryLayout->addWidget(
            tile,
            static_cast<int>(index / 3),
            static_cast<int>(index % 3));
    }
    summaryLayout->setColumnStretch(0, 1);
    summaryLayout->setColumnStretch(1, 1);
    summaryLayout->setColumnStretch(2, 1);
    headerLayout->addLayout(summaryLayout);
    resultLayout->addWidget(resultHeader);

    m_detailTabs = new QTabWidget(this);
    ks::ui::StyleJoinedResultTabs(m_detailTabs, resultHeader);

    QWidget* const overviewPage = new QWidget(m_detailTabs);
    QVBoxLayout* const overviewLayout = new QVBoxLayout(overviewPage);
    overviewLayout->setContentsMargins(0, 0, 0, 0);
    auto* const overviewControls = new QHBoxLayout();
    m_overviewSource = new QComboBox(overviewPage);
    ks::ui::StylePrimaryCombo(m_overviewSource);
    m_overviewSource->addItem(localized("Fast snapshot"));
    overviewControls->addWidget(m_overviewSource);
    m_overviewSample = new QLabel(overviewPage);
    m_overviewSample->setWordWrap(true);
    m_overviewSample->setTextInteractionFlags(Qt::TextSelectableByMouse);
    overviewControls->addWidget(m_overviewSample, 1);
    ks::ui::NormalizeToolbarRow(overviewControls);
    overviewLayout->addLayout(overviewControls);
    m_snapshotChart = new MemoryAttributionChart(overviewPage);
    m_snapshotChart->selected = [this](int use) {
        const bool pfn = usePfnOverview();
        m_detailTabs->setCurrentWidget(m_pfnPage);
        if (!m_pfnOverviewScan) { m_pfnPage->startScan(); }
        else if (pfn) { m_pfnPage->focusCategory(use); }
    };
    overviewLayout->addWidget(m_snapshotChart);
    m_overviewTree = new QTreeWidget(overviewPage);
    m_overviewTree->setColumnCount(6);
    m_overviewTree->setHeaderLabels(QStringList{
        localized("Memory source"), localized("Bytes"), localized("RAM %"),
        localized("Delta"), localized("Accounting role"), localized("Interpretation")
    });
    m_overviewTree->setRootIsDecorated(true);
    m_overviewTree->setAlternatingRowColors(true);
    m_overviewTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_overviewTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_overviewTree->header()->setStretchLastSection(true);
    overviewLayout->addWidget(m_overviewTree);

    QWidget* const userResidencyPage = new QWidget(m_detailTabs);
    QVBoxLayout* const userResidencyLayout = new QVBoxLayout(userResidencyPage);
    userResidencyLayout->setContentsMargins(0, 0, 0, 0);
    // 四张表统一改用 VisibleTableWidget：它在表头上方预留全局操作条，并支持冻结行列。
    m_userResidencyTable = new AuditTableView(userResidencyPage);
    // 驻留、进程与内核池均为重复采集的主证据，保留可比较的快照栏。
    ks::ui::SetTableActionBarMode(m_userResidencyTable, ks::ui::TableActionBarMode::Full);
    configureTable(m_userResidencyTable, QStringList{
        localized("Process"), localized("PID"), localized("Resident kind"),
        localized("Backing / owner evidence"), localized("Resident references"),
        localized("Private resident"), localized("Shareable refs"),
        localized("Shared refs"), localized("Proportional estimate")
    });
    userResidencyLayout->addWidget(m_userResidencyTable);

    QWidget* const processPage = new QWidget(m_detailTabs);
    QVBoxLayout* const processLayout = new QVBoxLayout(processPage);
    processLayout->setContentsMargins(0, 0, 0, 0);
    m_processTable = new AuditTableView(processPage);
    ks::ui::SetTableActionBarMode(m_processTable, ks::ui::TableActionBarMode::Full);
    configureTable(m_processTable, QStringList{
        localized("Process"), localized("PID"), localized("Session"),
        localized("Private resident"), localized("Working set"), localized("Shared WS refs"),
        localized("Private commit"), localized("Paged quota"), localized("Nonpaged quota"),
        localized("Hard faults"), localized("Private delta")
    });
    processLayout->addWidget(m_processTable);

    QWidget* const poolPage = new QWidget(m_detailTabs);
    QVBoxLayout* const poolLayout = new QVBoxLayout(poolPage);
    poolLayout->setContentsMargins(0, 0, 0, 0);
    m_poolTagTable = new AuditTableView(poolPage);
    ks::ui::SetTableActionBarMode(m_poolTagTable, ks::ui::TableActionBarMode::Full);
    configureTable(m_poolTagTable, QStringList{
        localized("Tag"), localized("Paged bytes"), localized("Nonpaged bytes"),
        localized("Total bytes"), localized("Delta"), localized("Paged outstanding"),
        localized("Nonpaged outstanding"), localized("Source"), localized("Description")
    });
    poolLayout->addWidget(m_poolTagTable);

    QWidget* const bigPoolPage = new QWidget(m_detailTabs);
    QVBoxLayout* const bigPoolLayout = new QVBoxLayout(bigPoolPage);
    bigPoolLayout->setContentsMargins(0, 0, 0, 0);
    m_bigPoolTable = new AuditTableView(bigPoolPage);
    ks::ui::SetTableActionBarMode(m_bigPoolTable, ks::ui::TableActionBarMode::Full);
    configureTable(m_bigPoolTable, QStringList{
        localized("Tag"), localized("Virtual address"), localized("Size"),
        localized("Pool type"), localized("Delta"), localized("Source"), localized("Description")
    });
    bigPoolLayout->addWidget(m_bigPoolTable);

    m_detailTabs->addTab(overviewPage, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 0));
    m_detailTabs->addTab(userResidencyPage, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 1));
    m_detailTabs->addTab(processPage, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 2));
    m_detailTabs->addTab(poolPage, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 3));
    m_detailTabs->addTab(bigPoolPage, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 4));
    m_pfnPage = new PhysicalPageAttributionPage(m_detailTabs);
    m_pfnPage->openModuleDetails = [this](const QString& path) {
        const auto handler = openModuleDetails;
        if (handler) { handler(path); }
    };
    m_detailTabs->addTab(m_pfnPage, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 5));
    m_hyperVPage = new HyperVMemoryPage(m_detailTabs);
    m_hyperVPage->metricAreaStateChanged = [this] { updateMetricAreaAction(); };
    m_detailTabs->addTab(m_hyperVPage, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 6));
    m_pfnPage->snapshotReady = [this](const std::shared_ptr<ksword::pfn::Scan>& scan) {
        m_hyperVPage->setPfnContext(scan);
        applyPfnOverview(scan);
        updateMetricAreaAction();
    };
    ks::i18n::LanguageManager::instance().bindTab(
        m_detailTabs, overviewPage, QStringLiteral("memory.audit.tab.distribution"), QStringLiteral("物理内存分布"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_detailTabs, userResidencyPage, QStringLiteral("memory.audit.tab.user_residency"), QStringLiteral("用户态驻留"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_detailTabs, processPage, QStringLiteral("memory.audit.tab.processes"), QStringLiteral("内核进程快照"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_detailTabs, poolPage, QStringLiteral("memory.audit.tab.pool_tags"), QStringLiteral("Pool 标签"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_detailTabs, bigPoolPage, QStringLiteral("memory.audit.tab.big_pool"), QStringLiteral("Big Pool 分配"));

    m_detailText = new ks::ui::StructuredFieldView(this);



    // 详情说明区不再被 setMaximumHeight 钉死：Tab 与说明文本装进纵向分割器，
    // 用户可以自行把说明区拖大来读完整段结论。
    QSplitter* const detailSplitter = new QSplitter(Qt::Vertical, this);
    detailSplitter->setObjectName(QStringLiteral("kswordMemoryAuditDetailSplitter"));
    detailSplitter->setChildrenCollapsible(false);
    detailSplitter->addWidget(m_detailTabs);
    detailSplitter->addWidget(m_detailText);
    detailSplitter->setStretchFactor(0, 3);
    detailSplitter->setStretchFactor(1, 2);
    // 只给 stretchFactor 而不给初值时，首帧两块都会按 sizeHint 之外的 0 高度参与分配，
    // 说明区会塌成一条线；这里必须同时给一组初始尺寸。
    detailSplitter->setSizes(QList<int>{ 420, 160 });
    resultLayout->addWidget(detailSplitter, 1);

    // DDMA 复核条：本页统计的是"标准通道看到的物理内存"，被 SLAT 重定向的页在
    // 这里只会表现为一段说不清归属的余量。用 DDMA 对同一页再读一次，是唯一能在
    // 本页内直接验证"这段内存是不是被藏起来了"的手段。
    {
        QWidget* const ddmaRow = new QWidget(this);
        QHBoxLayout* const ddmaLayout = new QHBoxLayout(ddmaRow);
        ddmaLayout->setContentsMargins(0, 0, 0, 0);
        ddmaLayout->setSpacing(6);

        m_ddmaCrossCheckAddressEdit = new QLineEdit(ddmaRow);
        ks::ui::StyleStandaloneInput(m_ddmaCrossCheckAddressEdit); // 明确的物理地址字段补齐输入层。
        m_ddmaCrossCheckAddressEdit->setPlaceholderText(
            localized("Physical page address, e.g. 0x1000"));
        m_ddmaCrossCheckAddressEdit->setClearButtonEnabled(true);

        m_ddmaCrossCheckButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/file_find.svg")),
            localized("Cross-check with DDMA"),
            ddmaRow);
        m_ddmaCrossCheckButton->setEnabled(false);

        m_ddmaCrossCheckResultLabel = new QLabel(ddmaRow);
        m_ddmaCrossCheckResultLabel->setWordWrap(true);
        m_ddmaCrossCheckResultLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);

        ddmaLayout->addWidget(new QLabel(localized("DDMA cross-check"), ddmaRow));
        ddmaLayout->addWidget(m_ddmaCrossCheckAddressEdit);
        ddmaLayout->addWidget(m_ddmaCrossCheckButton);
        ddmaLayout->addWidget(m_ddmaCrossCheckResultLabel, 1);
        ks::ui::NormalizeToolbarRow(ddmaLayout);
        rootLayout->addWidget(ddmaRow);
    }

    m_statusLabel = new QLabel(this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setMinimumWidth(0);
    m_statusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rootLayout->addWidget(m_statusLabel);

    m_autoRefreshTimer = new QTimer(this);
    m_autoRefreshTimer->setInterval(m_intervalSpin->value() * 1000);
    m_autoRefreshTimer->start();

    // 首次下发主题样式；之后由 changeEvent 的调色板分支重下发。
    applyThemedStyle();
}

// applyThemedStyle 作用：
// - 把本页所有依赖主题 token 的样式集中在一处下发：摘要卡片外壳、卡片小标题与大数值；
// - 构造期调用一次，主题切换/系统深浅色切换时由 changeEvent 再调一次，
//   否则快照型颜色会停在旧主题上；
// - 无入参；无返回值；控件尚未创建时静默返回，容忍构造早期到达的调色板事件。
void SystemMemoryAuditPage::applyThemedStyle()
{
    // 卡片外壳：底色 + 1px 边框 + 4px 圆角 + 8px 内边距，让 6 格摘要读起来是卡片而不是输入框。
    const QString tileStyle = QStringLiteral(
        "QFrame#%1{background:%2;border:1px solid %3;border-radius:4px;padding:8px;}")
        .arg(summaryTileObjectName(), KswordTheme::SurfaceAltHex(), KswordTheme::BorderHex());
    const QList<QFrame*> tiles = findChildren<QFrame*>(summaryTileObjectName());
    for (QFrame* const tile : tiles)
    {
        tile->setStyleSheet(tileStyle);
    }

    // 上行小标题：次级文字色 + 12px，压在大数值之上做层次。
    const QString titleStyle = QStringLiteral("QLabel{color:%1;font-size:12px;}")
        .arg(KswordTheme::TextSecondaryHex());
    for (const SummaryTileTitle& titleEntry : kSummaryTileTitles)
    {
        QLabel* const titleLabel = findChild<QLabel*>(QString::fromLatin1(titleEntry.objectName));
        if (titleLabel != nullptr)
        {
            titleLabel->setStyleSheet(titleStyle);
        }
    }

    // 下行大数值：主文字色 + 16px + 700 字重，是这一格真正要被读到的信息。
    const QString valueStyle = QStringLiteral("QLabel{color:%1;font-size:16px;font-weight:700;}")
        .arg(KswordTheme::TextPrimaryHex());
    const std::array<QLabel*, 6> summaryLabels{
        m_installedLabel, m_totalLabel, m_inUseLabel,
        m_availableLabel, m_commitLabel, m_unattributedLabel
    };
    for (QLabel* const valueLabel : summaryLabels)
    {
        if (valueLabel != nullptr)
        {
            valueLabel->setStyleSheet(valueStyle);
        }
    }
}

// updateSummaryTiles 作用：
// - 把当前快照写进 6 格摘要卡片的下行数值，标题固定在上行由 retranslateUi 维护；
// - 采集完成与语言切换后都走这一个入口，避免两处各写一遍导致文案不一致；
// - 无入参；无返回值；尚未拿到快照或控件未建时静默返回。
bool SystemMemoryAuditPage::usePfnOverview() const
{
    return m_detailTabs && m_detailTabs->currentIndex() == 0 &&
        m_overviewSource->currentIndex() == 1 && m_pfnOverviewScan &&
        m_pfnOverviewScan->accounting.expected && m_pfnOverviewScan->accounting.reconciles();
}

void SystemMemoryAuditPage::applyPfnOverview(const std::shared_ptr<ksword::pfn::Scan>& scan)
{
    // Preserve the last usable ledger after an unavailable rerun. Its own time
    // and coverage remain visible; never subtract it from a newer quick sample.
    m_pfnOverviewAttemptFailed = !scan || !scan->accounting.expected || scan->resourceFailure || !scan->accounting.valid || !scan->accounting.reconciles();
    if (!m_pfnOverviewAttemptFailed)
    {
        m_pfnOverviewScan = scan;
        if (m_overviewSource->count() == 1) { m_overviewSource->addItem(localized("Latest PFN ledger")); }
        m_overviewSource->setCurrentIndex(1);
    }
    m_overviewDirty = true;
    updateSummaryTiles();
    scheduleCurrentDetailViewRebuild();
    updateDetails();
}

void SystemMemoryAuditPage::updateSummaryTiles()
{
    if (m_installedLabel == nullptr || (!m_hasSnapshot && !usePfnOverview()))
    {
        return;
    }

    const bool pfn = usePfnOverview();
    for (std::size_t i = 0; i < kSummaryTileTitles.size(); ++i)
    {
        if (auto* title = findChild<QLabel*>(QString::fromLatin1(kSummaryTileTitles[i].objectName)))
        {
            const char* source = kSummaryTileTitles[i].sourceText;
            if (pfn && i == 1) { source = "NT RAM"; }
            if (pfn && i == 4) { source = "Commit (quick snapshot)"; }
            if (pfn && i == 5) { source = "Unknown / coverage gap"; }
            title->setText(localized(source));
        }
    }
    if (pfn)
    {
        using namespace ksword::pfn;
        const auto& scan = *m_pfnOverviewScan;
        const auto& counts = scan.accounting;
        const auto total = counts.expected * pageBytes;
        std::uint64_t inUse = 0;
        std::vector<MemoryAttributionChart::Segment> segments;
        for (std::size_t i = 0; i < useCount; ++i)
        {
            const auto amount = counts.inUse(static_cast<Use>(i)) * pageBytes;
            inUse += amount;
            if (amount) { segments.push_back({PhysicalPageAttributionPage::classificationName(static_cast<Use>(i)), amount, static_cast<int>(i)}); }
        }
        if (counts.availablePages) { segments.push_back({localized("Available"), counts.availablePages * pageBytes, 17}); }
        if (counts.bad()) { segments.push_back({localized("Bad"), counts.bad() * pageBytes, -1}); }
        if (counts.unreadable) { segments.push_back({localized("Query failed"), counts.unreadable * pageBytes, -2}); }
        if (counts.notScanned()) { segments.push_back({localized("Not scanned"), counts.notScanned() * pageBytes, -3}); }
        m_installedLabel->setText(scan.installed ? formatBytes(scan.installed) : localized("Unavailable"));
        m_totalLabel->setText(formatBytes(total));
        m_inUseLabel->setText(QStringLiteral("%1 (%2)").arg(formatBytes(inUse), formatPercent(inUse, total)));
        m_availableLabel->setText(QStringLiteral("%1 (%2)").arg(formatBytes(counts.availablePages * pageBytes), formatPercent(counts.availablePages * pageBytes, total)));
        m_commitLabel->setText(m_hasSnapshot && m_snapshot.commit.valid
            ? QStringLiteral("%1 / %2").arg(formatBytes(m_snapshot.commit.bytes), formatBytes(m_snapshot.commit.limit)) : localized("Unavailable"));
        m_commitLabel->setToolTip(localized("Quick snapshot sampled at %1").arg(m_snapshot.sampledAt)
            + QStringLiteral("\n") + commitEvidence(m_snapshot.commit));
        m_unattributedLabel->setText(QStringLiteral("%1 / %2").arg(formatBytes(counts.inUse(Use::Unknown) * pageBytes), formatBytes((counts.unreadable + counts.notScanned()) * pageBytes)));
        m_snapshotChart->setSegments(std::move(segments), localized("One physical page, one category. Click a category to inspect PFNs."));
        QString source = localized("PFN interval %1 to %2 | valid coverage %3%")
            .arg(scan.started, scan.finished).arg(100.0 * static_cast<double>(counts.valid) / static_cast<double>(counts.expected), 0, 'f', 2);
        source += QStringLiteral(" | ") + localized("Known use, owner unresolved: %1")
            .arg(formatBytes(scan.ownerCoverage.knownInUseUnresolved() * pageBytes));
        if (!scan.semanticsValidated) { source += QStringLiteral(" | ") + localized("Classification semantics have not been validated on this Windows build."); }
        if (!scan.complete) { source += QStringLiteral(" | ") + localized("Partial / unavailable"); }
        if (scan.rangesChanged) { source += QStringLiteral(" | ") + localized("RAM ranges changed or could not be rechecked; treat this scan as partial."); }
        if (m_pfnOverviewAttemptFailed) { source += QStringLiteral(" | ") + localized("Latest PFN attempt failed; showing the previous ledger."); }
        m_overviewSample->setText(source);
        return;
    }
    m_overviewSample->setText(localized("Quick snapshot sampled at %1").arg(m_snapshot.sampledAt));
    m_commitLabel->setToolTip(commitEvidence(m_snapshot.commit));
    m_installedLabel->setText(m_snapshot.installedPhysicalValid ? formatBytes(m_snapshot.installedPhysicalBytes) : localized("Unavailable"));
    m_totalLabel->setText(formatBytes(m_snapshot.totalPhysicalBytes));
    // 下面三格是“绝对值 + 占比/上限”的组合，模板只有括号和斜杠，不需要进语言包。
    m_inUseLabel->setText(QStringLiteral("%1 (%2)").arg(
        formatBytes(m_snapshot.inUseBytes),
        formatPercent(m_snapshot.inUseBytes, m_snapshot.totalPhysicalBytes)));
    m_availableLabel->setText(QStringLiteral("%1 (%2)").arg(
        formatBytes(m_snapshot.availableBytes),
        formatPercent(m_snapshot.availableBytes, m_snapshot.totalPhysicalBytes)));
    m_commitLabel->setText(m_snapshot.commit.valid ? QStringLiteral("%1 / %2").arg(
        formatBytes(m_snapshot.commit.bytes),
        formatBytes(m_snapshot.commit.limit)) : localized("Unavailable"));
    m_unattributedLabel->setText(QStringLiteral("%1 (%2)").arg(
        formatBytes(m_snapshot.unattributedResidentBytes),
        formatPercent(m_snapshot.unattributedResidentBytes, m_snapshot.totalPhysicalBytes)));
    if (m_snapshotChart != nullptr)
    {
        m_snapshotChart->setSegments({
            { localized("Available"), m_snapshot.availableBytes, 17 },
            { localized("Process private"), m_snapshot.processPrivateResidentBytes, 0 },
            { localized("Nonpaged pool"), m_snapshot.nonPagedPoolBytes, 5 },
            { localized("Paged pool resident"), m_snapshot.pagedPoolResidentBytes, 4 },
            { localized("Kernel / driver resident"), m_snapshot.systemCodeResidentBytes + m_snapshot.systemDriverResidentBytes, 12 },
            { localized("Modified pages"), m_snapshot.modifiedBytes + m_snapshot.modifiedNoWriteBytes, 7 },
            { localized("Snapshot remainder"), m_snapshot.unattributedResidentBytes, -1 }
        }, localized("Fast snapshot estimate. Click to open physical-page attribution."));
    }
}

void SystemMemoryAuditPage::initializeConnections()
{
    connect(m_metricAreaButton, &QPushButton::clicked, this, [this] { openMetricAreaView(); });
    m_projectionDebounce = new QTimer(this); m_projectionDebounce->setSingleShot(true); m_projectionDebounce->setInterval(120);
    connect(m_projectionDebounce, &QTimer::timeout, this, [this] { rebuildCurrentDetailView(); });
    m_jobsTimer = new QTimer(this); m_jobsTimer->setInterval(30);
    connect(m_jobsTimer, &QTimer::timeout, this, [this] { pollJobs(); });
    const std::array<AuditTableView*, 4> tables{m_userResidencyTable, m_processTable, m_poolTagTable, m_bigPoolTable};
    for (int kind = 0; kind < 4; ++kind) {
        tables[kind]->horizontalHeader()->setSortIndicator(m_sortColumns[kind], m_sortOrders[kind]);
        tables[kind]->auditModel->requestSort = [this, kind](int column, Qt::SortOrder order) {
            if (m_sortColumns[kind] == column && m_sortOrders[kind] == order) { return; }
            m_sortColumns[kind] = column; m_sortOrders[kind] = order; ++m_projectionVersions[kind]; m_readyProjections[kind].reset();
            if (m_projectionJob) { m_projectionJob->cancel.store(true); }
            m_projectionDebounce->start();
        };
    }
    connect(m_overviewSource, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        m_overviewDirty = true;
        updateSummaryTiles();
        scheduleCurrentDetailViewRebuild();
        updateDetails();
        updateMetricAreaAction();
    });
    connect(m_pfnScanButton, &QPushButton::clicked, this, [this]() {
        m_detailTabs->setCurrentWidget(m_pfnPage);
        m_pfnPage->startScan();
    });
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        m_startUserResidencyScanAfterSnapshot = true;
        refreshSnapshot();
        });
    connect(m_userResidencyScanButton, &QPushButton::clicked, this, [this]() {
        startUserResidencyScan();
        });
    connect(m_autoRefreshCheck, &QCheckBox::toggled, this, [this](const bool checked) {
        if (checked)
        {
            m_autoRefreshTimer->start(m_intervalSpin->value() * 1000);
        }
        else
        {
            m_autoRefreshTimer->stop();
        }
        });
    connect(m_intervalSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](const int seconds) {
        m_autoRefreshTimer->setInterval(seconds * 1000);
        });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this]() {
        invalidateTableProjections();
        m_projectionDebounce->start();
        m_userResidencyTableDirty = true;
        m_processTableDirty = true;
        m_poolTagTableDirty = true;
        m_bigPoolTableDirty = true;
        scheduleCurrentDetailViewRebuild();
        updateStatus();
        });
    connect(m_autoRefreshTimer, &QTimer::timeout, this, [this]() {
        // An explicitly enabled sampler continues when only its projection is hidden.
        refreshSnapshot();
    });
    connect(m_detailTabs, &QTabWidget::currentChanged, this, [this]() {
        if (m_openMetricAreaWhenPublished >= 0 && m_detailTabs->currentIndex() != m_openMetricAreaWhenPublished + 1)
            m_openMetricAreaWhenPublished = -1;
        const bool showSnapshot = m_detailTabs->currentWidget() != m_pfnPage && m_detailTabs->currentWidget() != m_hyperVPage;
        m_detailText->setVisible(showSnapshot);
        m_statusLabel->setVisible(showSnapshot);
        for (QLabel* value : { m_installedLabel, m_totalLabel, m_inUseLabel, m_availableLabel, m_commitLabel, m_unattributedLabel })
        {
            value->parentWidget()->setVisible(showSnapshot);
        }
        rebuildCurrentDetailView();
        updateSummaryTiles();
        updateDetails();
        updateMetricAreaAction();
    });
    connect(m_ddmaCrossCheckButton, &QPushButton::clicked, this, [this]() {
        runDdmaCrossCheck();
        });
    connect(m_ddmaCrossCheckAddressEdit, &QLineEdit::returnPressed, this, [this]() {
        runDdmaCrossCheck();
        });
}

void SystemMemoryAuditPage::setDdmaSessionProvider(
    std::function<const ksword::memory_backend::DdmaSession&()> provider)
{
    m_ddmaSessionProvider = std::move(provider);
    refreshDdmaCrossCheckState();
}

void SystemMemoryAuditPage::refreshDdmaCrossCheckState()
{
    if (m_ddmaCrossCheckButton == nullptr)
    {
        return;
    }
    if (!m_ddmaSessionProvider)
    {
        m_ddmaCrossCheckButton->setEnabled(false);
        m_ddmaCrossCheckButton->setToolTip(localized("DDMA channel is not available in this view."));
        return;
    }

    QString reason;
    const bool usable =
        ksword::memory_backend::isDdmaUsable(m_ddmaSessionProvider(), &reason);
    m_ddmaCrossCheckButton->setEnabled(usable && !m_ddmaCrossCheckBusy);
    m_ddmaCrossCheckButton->setToolTip(usable
        ? localized("Read the same physical page through both backends and compare byte by byte.")
        : reason);
}

void SystemMemoryAuditPage::runDdmaCrossCheck()
{
    if (m_ddmaCrossCheckBusy || m_ddmaCrossCheckResultLabel == nullptr || m_ddmaCrossCheckAddressEdit == nullptr)
    {
        return;
    }
    if (!m_ddmaSessionProvider)
    {
        m_ddmaCrossCheckResultLabel->setText(
            localized("DDMA channel is not available in this view."));
        return;
    }

    const QString addressText = m_ddmaCrossCheckAddressEdit->text().trimmed();
    bool converted = false;
    std::uint64_t physicalAddress = 0ULL;
    if (addressText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        physicalAddress = addressText.mid(2).toULongLong(&converted, 16);
    }
    else
    {
        physicalAddress = addressText.toULongLong(&converted, 16);
    }
    if (!converted)
    {
        m_ddmaCrossCheckResultLabel->setText(
            localized("Physical address could not be parsed; use hexadecimal, e.g. 0x1000."));
        m_ddmaCrossCheckResultLabel->setStyleSheet(
            QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
        return;
    }

    // 复核固定比一整页，两个后端读同一段才有可比性。粒度取自后端门面，
    // 本编译单元不需要为一个常量去包含驱动协议头。
    const std::uint64_t transferBytes =
        static_cast<std::uint64_t>(ksword::memory_backend::ddmaTransferBytes());
    const std::uint64_t pageBase = physicalAddress & ~(transferBytes - 1ULL);
    const auto session = m_ddmaSessionProvider();
    const auto generation = ksword::memory_backend::ddmaSessionGeneration();
    const auto ticket = ++m_ddmaCrossCheckTicket;
    struct CrossCheckResult
    {
        ksword::memory_backend::AccessOutcome standard;
        ksword::memory_backend::AccessOutcome ddma;
    };
    auto promise = std::make_shared<QPromise<CrossCheckResult>>();
    auto* const watcher = new QFutureWatcher<CrossCheckResult>(this);
    watcher->setFuture(promise->future());
    m_ddmaCrossCheckBusy = true;
    refreshDdmaCrossCheckState();
    m_ddmaCrossCheckResultLabel->clear();
    connect(watcher, &QFutureWatcher<CrossCheckResult>::finished, this,
        [this, watcher, ticket, generation, pageBase, transferBytes]() {
        const auto result = watcher->result();
        watcher->deleteLater();
        if (ticket != m_ddmaCrossCheckTicket)
        {
            return;
        }
        m_ddmaCrossCheckBusy = false;
        refreshDdmaCrossCheckState();
        // A result belongs to the frozen disk/scratch session, never a new one.
        if (generation != ksword::memory_backend::ddmaSessionGeneration())
        {
            return;
        }
        const auto& standardOutcome = result.standard;
        const auto& ddmaOutcome = result.ddma;

        // 任何一侧读失败都不能下"一致/不一致"的结论，只能说没法比。
        if (!standardOutcome.ok || !ddmaOutcome.ok || standardOutcome.partial || ddmaOutcome.partial
            || standardOutcome.data.size() != static_cast<qsizetype>(transferBytes)
            || ddmaOutcome.data.size() != static_cast<qsizetype>(transferBytes) || ddmaOutcome.scratchDirty)
        {
            const QString detail = ddmaOutcome.scratchDirty
                ? QStringLiteral("DDMA scratch sectors could not be restored; further DDMA operations are unsafe.")
                : ((!standardOutcome.ok || standardOutcome.partial || standardOutcome.data.size() != static_cast<qsizetype>(transferBytes))
                    ? standardOutcome.failureText : ddmaOutcome.failureText);
            m_ddmaCrossCheckResultLabel->setText(
                QStringLiteral("%1 %2").arg(localized("Cannot compare:")).arg(detail.isEmpty()
                ? localized("DDMA transaction returned incomplete data.") : detail));
            m_ddmaCrossCheckResultLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
            return;
        }

        const qsizetype compareLength =
            std::min<qsizetype>(standardOutcome.data.size(), ddmaOutcome.data.size());
        qsizetype diffCount = 0;
        for (qsizetype index = 0; index < compareLength; ++index)
        {
            if (standardOutcome.data[index] != ddmaOutcome.data[index])
            {
                ++diffCount;
            }
        }

        if (diffCount == 0)
        {
            m_ddmaCrossCheckResultLabel->setText(
                QStringLiteral("0x%1: %2")
                    .arg(pageBase, 0, 16)
                    .arg(localized("both backends returned identical bytes; no redirection observed.")));
            m_ddmaCrossCheckResultLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::SuccessHex()));
        }
        else
        {
            m_ddmaCrossCheckResultLabel->setText(
                QStringLiteral("0x%1: %2/%3 %4")
                    .arg(pageBase, 0, 16)
                    .arg(diffCount)
                    .arg(compareLength)
                    .arg(localized(
                        "bytes differ. The standard channel is subject to SLAT; DDMA is not. "
                        "This usually means the page is redirected or hidden by a hypervisor.")));
            m_ddmaCrossCheckResultLabel->setStyleSheet(
                QStringLiteral("color:%1;").arg(KswordTheme::WarningHex()));
        }
    });
    promise->start();
    CrossCheckResult rejected;
    bool accepted = false;
    try
    {
        accepted = ksword::memory_backend::submitDdmaTransaction(
        [promise, session, generation, pageBase, transferBytes]() {
        CrossCheckResult result;
        // A queued request may become obsolete before it starts. Once started,
        // the complete standard/DDMA pair runs to completion (including restore).
        if (generation == ksword::memory_backend::ddmaSessionGeneration())
        {
            try
            {
                result.standard = ksword::memory_backend::readPhysical(
                    ksword::memory_backend::MemoryAccessBackend::StandardDriver,
                    session, pageBase, transferBytes);
                result.ddma = ksword::memory_backend::readPhysical(
                    ksword::memory_backend::MemoryAccessBackend::Ddma,
                    session, pageBase, transferBytes);
            }
            catch (const std::exception& error)
            {
                result.standard.failureText = QString::fromUtf8(error.what());
            }
            catch (...)
            {
                result.standard.failureText = QStringLiteral("DDMA transaction failed unexpectedly.");
            }
        }
        promise->addResult(std::move(result));
        promise->finish();
    });
    }
    catch (const std::exception& error)
    {
        rejected.standard.failureText = QString::fromUtf8(error.what());
    }
    catch (...)
    {
        rejected.standard.failureText = QStringLiteral("DDMA transaction failed unexpectedly.");
    }
    if (!accepted)
    {
        if (rejected.standard.failureText.isEmpty())
        {
            rejected.standard.failureText = QStringLiteral("DDMA transaction queue is full; wait for the current operation and retry.");
        }
        promise->addResult(std::move(rejected));
        promise->finish();
    }

}

void SystemMemoryAuditPage::retranslateUi()
{
    m_metricAreaButton->setText(ks::i18n::sourceText(QStringLiteral("矩形面积视图")));
    updateMetricAreaAction();
    for (int kind = 0; kind < 4; ++kind) refreshMetricAreaView(static_cast<AuditKind>(kind));
    m_overviewSource->setItemText(0, localized("Fast snapshot"));
    if (m_overviewSource->count() > 1) { m_overviewSource->setItemText(1, localized("Latest PFN ledger")); }
    m_pfnScanButton->setText(localized("PFN deep attribution"));
    m_refreshButton->setText(localized("Refresh snapshot"));
    m_refreshButton->setToolTip(localized("Re-collect the whole-machine physical memory snapshot."));
    m_userResidencyScanButton->setText(localized("Deep scan user-mode residency"));
    m_userResidencyScanButton->setToolTip(
        localized("Walk every accessible process working set and attribute resident pages to their backing."));
    m_autoRefreshCheck->setText(localized("Auto refresh"));
    m_intervalSpin->setSuffix(localized(" s"));
    m_filterEdit->setPlaceholderText(localized("Filter process, category, file, tag, or address"));

    m_overviewTree->setHeaderLabels(QStringList{
        localized("Memory source"), localized("Bytes"), localized("RAM %"),
        localized("Delta"), localized("Accounting role"), localized("Interpretation")
    });
    m_userResidencyTable->setHorizontalHeaderLabels(QStringList{
        localized("Process"), localized("PID"), localized("Resident kind"),
        localized("Backing / owner evidence"), localized("Resident references"),
        localized("Private resident"), localized("Shareable refs"),
        localized("Shared refs"), localized("Proportional estimate")
    });
    m_processTable->setHorizontalHeaderLabels(QStringList{
        localized("Process"), localized("PID"), localized("Session"),
        localized("Private resident"), localized("Working set"), localized("Shared WS refs"),
        localized("Private commit"), localized("Paged quota"), localized("Nonpaged quota"),
        localized("Hard faults"), localized("Private delta")
    });
    m_poolTagTable->setHorizontalHeaderLabels(QStringList{
        localized("Tag"), localized("Paged bytes"), localized("Nonpaged bytes"),
        localized("Total bytes"), localized("Delta"), localized("Paged outstanding"),
        localized("Nonpaged outstanding"), localized("Source"), localized("Description")
    });
    m_bigPoolTable->setHorizontalHeaderLabels(QStringList{
        localized("Tag"), localized("Virtual address"), localized("Size"),
        localized("Pool type"), localized("Delta"), localized("Source"), localized("Description")
    });

    m_detailTabs->setTabText(0, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 0));
    m_detailTabs->setTabText(1, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 1));
    m_detailTabs->setTabText(2, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 2));
    m_detailTabs->setTabText(3, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 3));
    m_detailTabs->setTabText(4, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 4));
    m_detailTabs->setTabText(5, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 5));
    m_detailTabs->setTabText(6, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::Audit, 6));

    // 摘要卡片的上行小标题是局部控件，按 objectName 回查后逐格重译。
    for (const SummaryTileTitle& titleEntry : kSummaryTileTitles)
    {
        QLabel* const titleLabel = findChild<QLabel*>(QString::fromLatin1(titleEntry.objectName));
        if (titleLabel != nullptr)
        {
            titleLabel->setText(localized(titleEntry.sourceText));
        }
    }
    updateSummaryTiles();
}

void SystemMemoryAuditPage::refreshSnapshot()
{
    if (m_refreshing) { return; }
    m_refreshing = true;
    const auto job = std::make_shared<SnapshotJob>(); job->ticket = m_snapshotRefreshTicket.fetch_add(1) + 1;
    m_snapshotJob = job; m_jobsTimer->start();
    const auto previous = m_previousDelta; const bool hasPrevious = m_hasSnapshot;
    m_refreshButton->setEnabled(false); m_statusLabel->setText(localized("Collecting system memory evidence..."));
    try { std::thread([job, previous, hasPrevious] {
        try {
            auto result = valueStorage<Snapshot>(); *result = collectSnapshot();
            prepareSnapshotDelta(*result, previous, hasPrevious); job->result = std::move(result);
        } catch (...) { job->failed = true; }
        job->done.store(true);
    }).detach(); } catch (...) { job->failed = true; job->done.store(true); }
}
void SystemMemoryAuditPage::prepareSnapshotDelta(Snapshot& snapshot, const std::shared_ptr<DeltaIndex>& previous, const bool hasPrevious)
{
    for (ProcessRow& row : *snapshot.processes) {
        const auto before = hasPrevious ? previous->process.value(row.identity, row.privateResidentBytes) : row.privateResidentBytes;
        row.privateResidentDeltaBytes = static_cast<std::int64_t>(row.privateResidentBytes) - static_cast<std::int64_t>(before);
        snapshot.deltaIndex->process.insert(row.identity, row.privateResidentBytes);
    }
    for (PoolTagRow& row : *snapshot.poolTags) {
        const auto total = row.pagedBytes + row.nonPagedBytes;
        const auto before = hasPrevious ? previous->pool.value(row.tag, total) : total;
        row.totalDeltaBytes = static_cast<std::int64_t>(total) - static_cast<std::int64_t>(before);
        snapshot.deltaIndex->pool.insert(row.tag, total);
    }
    for (BigPoolRow& row : *snapshot.bigPool) {
        const auto before = hasPrevious ? previous->bigPool.value(row.identity, row.sizeBytes) : row.sizeBytes;
        row.sizeDeltaBytes = static_cast<std::int64_t>(row.sizeBytes) - static_cast<std::int64_t>(before);
        snapshot.deltaIndex->bigPool.insert(row.identity, row.sizeBytes);
    }
}

void SystemMemoryAuditPage::applySnapshot(Snapshot snapshot, const std::uint64_t ticket)
{
    if (ticket != m_snapshotRefreshTicket.load())
    {
        return;
    }

    m_summaryDeltaBytes.clear();
    snapshot.errors.clear();
    for (const SnapshotError& error : snapshot.pendingErrors)
    {
        QString errorText = ks::i18n::packedSourceText(error.sourceText);
        if (!error.argument.isNull())
        {
            errorText = errorText.arg(error.argument);
        }
        snapshot.errors << errorText;
    }
    snapshot.pendingErrors.clear();

    const QHash<QString, std::uint64_t> currentSummary{
        { QStringLiteral("in_use"), snapshot.inUseBytes },
        { QStringLiteral("available"), snapshot.availableBytes },
        { QStringLiteral("process_private"), snapshot.processPrivateResidentBytes },
        { QStringLiteral("nonpaged_pool"), snapshot.nonPagedPoolBytes },
        { QStringLiteral("paged_pool_resident"), snapshot.pagedPoolResidentBytes },
        { QStringLiteral("system_code"), snapshot.systemCodeResidentBytes },
        { QStringLiteral("system_driver"), snapshot.systemDriverResidentBytes },
        { QStringLiteral("modified"), snapshot.modifiedBytes + snapshot.modifiedNoWriteBytes },
        { QStringLiteral("unattributed"), snapshot.unattributedResidentBytes }
    };
    for (auto iterator = currentSummary.constBegin(); iterator != currentSummary.constEnd(); ++iterator)
    {
        const std::uint64_t previous = m_hasSnapshot
            ? m_previousSummaryBytes.value(iterator.key(), iterator.value())
            : iterator.value();
        m_summaryDeltaBytes.insert(
            iterator.key(),
            static_cast<std::int64_t>(iterator.value()) - static_cast<std::int64_t>(previous));
    }
    m_previousSummaryBytes = currentSummary;

    m_previousDelta = snapshot.deltaIndex;
    invalidateTableProjections();

    m_snapshot = std::move(snapshot);
    m_hyperVPage->setSnapshotContext(m_snapshot.sampledAt, m_snapshot.unattributedResidentBytes);
    const QString warningSignature = m_snapshot.errors.join(QChar(0x1F));
    if (!warningSignature.isEmpty() &&
        warningSignature != m_lastSnapshotWarningSignature)
    {
        m_lastSnapshotWarningSignature = warningSignature;
        kLogEvent warningEvent;
        warn << warningEvent
            << "[SystemMemoryAuditPage] snapshot completed with warnings, warningCount="
            << m_snapshot.errors.size()
            << ", details="
            << m_snapshot.errors.join(QStringLiteral("; ")).toStdString()
            << eol;
    }
    else if (warningSignature.isEmpty())
    {
        // 清除后允许同一问题未来再次出现时重新产生一次 Warn 通知。
        m_lastSnapshotWarningSignature.clear();
    }
    m_hasSnapshot = true;
    updateSummaryTiles();
    m_overviewDirty = true;
    m_processTableDirty = true;
    m_poolTagTableDirty = true;
    m_bigPoolTableDirty = true;
    m_refreshButton->setEnabled(true);
    m_refreshing = false;
    scheduleCurrentDetailViewRebuild();
    updateDetails();
    updateStatus();

    if (m_startUserResidencyScanAfterSnapshot)
    {
        m_startUserResidencyScanAfterSnapshot = false;
        startUserResidencyScan();
    }
}

void SystemMemoryAuditPage::startUserResidencyScan()
{
    if (m_userResidencyScanInProgress.exchange(true)) { return; }
    const auto job = std::make_shared<ResidencyJob>(); job->ticket = m_userResidencyScanTicket.fetch_add(1) + 1;
    m_residencyJob = job; m_jobsTimer->start();
    const auto processes = m_snapshot.processes; const auto pageSize = m_snapshot.pageSize;
    m_userResidencyScanButton->setEnabled(false); m_userResidencyScanButton->setText(localized("Scanning user-mode residency...")); updateStatus();
    try { std::thread([job, processes, pageSize] {
        try { auto result = valueStorage<UserResidencyScan>(); *result = collectUserResidency(*processes, pageSize); job->result = std::move(result); }
        catch (...) { job->failed = true; }
        job->done.store(true);
    }).detach(); } catch (...) { job->failed = true; job->done.store(true); }
}

void SystemMemoryAuditPage::applyUserResidencyScan(UserResidencyScan scan, const std::uint64_t ticket)
{
    if (ticket != m_userResidencyScanTicket.load())
    {
        return;
    }

    m_userResidencyScan = std::move(scan);
    invalidateTableProjections();
    if (!m_userResidencyScan.errors.isEmpty())
    {
        kLogEvent warningEvent;
        warn << warningEvent
            << "[SystemMemoryAuditPage] user residency scan completed with warnings, warningCount="
            << m_userResidencyScan.errors.size()
            << ", details="
            << m_userResidencyScan.errors.join(QStringLiteral("; ")).toStdString()
            << eol;
    }
    m_userResidencyScanInProgress.store(false);
    m_userResidencyScanButton->setEnabled(true);
    m_userResidencyScanButton->setText(localized("Deep scan user-mode residency"));
    m_userResidencyTableDirty = true;
    m_overviewDirty = true;
    scheduleCurrentDetailViewRebuild();
    updateDetails();
    updateStatus();
}

void SystemMemoryAuditPage::scheduleCurrentDetailViewRebuild()
{
    if (m_detailViewRebuildScheduled)
    {
        return;
    }

    m_detailViewRebuildScheduled = true;
    QTimer::singleShot(0, this, [this]() {
        m_detailViewRebuildScheduled = false;
        rebuildCurrentDetailView();
    });
}

void SystemMemoryAuditPage::rebuildCurrentDetailView()
{
    if (!isVisible()) { return; }
    switch (m_detailTabs->currentIndex())
    {
    case 0:
        if (m_overviewDirty)
        {
            rebuildOverview();
            m_overviewDirty = false;
        }
        break;
    case 1:
        rebuildUserResidencyTable();
        break;
    case 2:
        rebuildProcessTable();
        break;
    case 3:
        rebuildPoolTagTable();
        break;
    case 4:
        rebuildBigPoolTable();
        break;
    default:
        break;
    }
}

void SystemMemoryAuditPage::rebuildOverview()
{
    m_overviewTree->setUpdatesEnabled(false);
    m_overviewTree->clear();
    const bool pfn = usePfnOverview();
    const std::uint64_t denominator = pfn
        ? m_pfnOverviewScan->accounting.expected * ksword::pfn::pageBytes
        : m_snapshot.totalPhysicalBytes;

    const auto addRow = [this, denominator](
        QTreeWidgetItem* parent,
        const QString& name,
        const std::uint64_t bytes,
        const std::int64_t delta,
        const QString& role,
        const QString& interpretation) {
        QTreeWidgetItem* const item = parent != nullptr
            ? new QTreeWidgetItem(parent)
            : new QTreeWidgetItem(m_overviewTree);
        item->setText(0, name);
        item->setText(1, formatBytes(bytes));
        item->setText(2, formatPercent(bytes, denominator));
        item->setText(3, formatDelta(delta));
        item->setText(4, role);
        item->setText(5, interpretation);
        item->setTextAlignment(1, Qt::AlignRight | Qt::AlignVCenter);
        item->setTextAlignment(2, Qt::AlignRight | Qt::AlignVCenter);
        item->setTextAlignment(3, Qt::AlignRight | Qt::AlignVCenter);
        if (delta != 0)
        {
            item->setForeground(3, delta > 0
                ? KswordTheme::ErrorColor()
                : KswordTheme::SuccessColor());
        }
        return item;
    };

    if (pfn)
    {
        using namespace ksword::pfn;
        const auto& counts = m_pfnOverviewScan->accounting;
        auto* const physical = addRow(nullptr, localized("NT RAM"), denominator, 0,
            localized("Exact partition"), localized("One physical page, one category. Click a category to inspect PFNs."));
        std::uint64_t inUse = 0;
        for (std::size_t i = 0; i < useCount; ++i) { inUse += counts.inUse(static_cast<Use>(i)); }
        auto* const used = addRow(physical, localized("In use"), inUse * pageBytes, 0,
            localized("Exact partition"), localized("Active, modified and transition PFNs from this collection interval."));
        auto* const known = addRow(used, localized("Attributed in use"), (inUse - counts.inUse(Use::Unknown)) * pageBytes, 0,
            localized("Exact partition"), localized("Known physical-page uses; a missing owner name does not make the use unknown."));
        for (std::size_t i = 0; i < useCount; ++i)
        {
            const auto use = static_cast<Use>(i);
            const auto amount = counts.inUse(use);
            if (!amount && use != Use::Unknown) { continue; }
            const auto& states = counts.byUseAndState[i];
            auto* const category = addRow(use == Use::Unknown ? used : known,
                PhysicalPageAttributionPage::classificationName(use), amount * pageBytes, 0,
                localized("Exact partition"), localized("Active %1 | Modified %2 | Modified no-write %3 | Transition %4")
                    .arg(formatBytes(states[6] * pageBytes), formatBytes(states[3] * pageBytes),
                        formatBytes(states[4] * pageBytes), formatBytes(states[7] * pageBytes)));
            if (use == Use::Unknown) { category->setForeground(0, KswordTheme::WarningColor()); }
            std::vector<const Group*> groups;
            for (const auto& group : m_pfnOverviewScan->groups)
            {
                if (group.use == use && group.pages) { groups.push_back(&group); }
            }
            std::sort(groups.begin(), groups.end(), [](const Group* a, const Group* b) { return a->pages > b->pages; });
            const std::size_t visible = std::min<std::size_t>(8, groups.size());
            std::uint64_t shown = 0;
            for (std::size_t j = 0; j < visible; ++j)
            {
                const auto& group = *groups[j];
                QString name = group.name.isEmpty() ? (group.key ? QStringLiteral("0x%1").arg(group.key, 0, 16) : localized("Unavailable")) : group.name;
                if (group.pid) { name += QStringLiteral(" [PID %1]").arg(group.pid); }
                const QString ownerEvidence = group.pid
                    ? localized("Owner seen before / after: %1 / %2").arg(group.ownerSeenBefore ? localized("Yes") : localized("No"), group.ownerSeenAfter ? localized("Yes") : localized("No"))
                    : localized("Backing / owner evidence");
                addRow(category, name, group.pages * pageBytes, 0,
                    localized("Backing subset"), ownerEvidence);
                shown += group.pages;
            }
            if (amount > shown)
            {
                addRow(category, localized("Other backing identities"), (amount - shown) * pageBytes, 0,
                    localized("Backing subset"), localized("Open physical-page attribution for the full collected owner list."));
            }
        }
        addRow(physical, localized("Available"), counts.availablePages * pageBytes, 0,
            localized("Exact partition"), localized("Standby, free, and zeroed pages available to satisfy demand."));
        addRow(physical, localized("Bad"), counts.bad() * pageBytes, 0,
            localized("Exact partition"), localized("Bad pages retained separately from usable in-use RAM."));
        addRow(physical, localized("Query failed"), counts.unreadable * pageBytes, 0,
            localized("Coverage gap"), localized("No valid identity was returned for these pages; their use remains unverified."));
        addRow(physical, localized("Not scanned"), counts.notScanned() * pageBytes, 0,
            localized("Coverage gap"), localized("Pages left unqueried after cancellation, budget or source failure."));
        auto* const coverage = addRow(nullptr, localized("Coverage diagnostics"), 0, 0,
            localized("Do not add"), localized("Consumer coverage is a separate dimension from physical-page use."));
        addRow(coverage, localized("Known use, owner unresolved"),
            m_pfnOverviewScan->ownerCoverage.knownInUseUnresolved() * pageBytes, 0,
            localized("Coverage, not another category"),
            localized("These in-use pages already have a known use, but no directly verified consumer. They remain inside their physical categories."));
        m_overviewTree->expandToDepth(2);
        for (int column = 0; column < 5; ++column) { m_overviewTree->resizeColumnToContents(column); }
        m_overviewTree->setUpdatesEnabled(true);
        return;
    }

    QTreeWidgetItem* const installed = addRow(
        nullptr, localized("Installed physical RAM"), m_snapshot.installedPhysicalBytes, 0,
        localized("Firmware-reported boundary"), localized("SMBIOS installed RAM; GetPhysicallyInstalledSystemMemory Win32 status: %1")
            .arg(m_snapshot.installedPhysicalStatus));
    if (!m_snapshot.installedPhysicalValid) { installed->setText(1, localized("Unavailable")); installed->setText(2, localized("Unavailable")); }
    auto* const reserved = addRow(installed, localized("Reserved / unavailable estimate"), m_snapshot.reserved.bytes, 0,
        localized("Aggregate estimate"),
        localized("Installed minus Windows usable RAM; this aggregate does not identify firmware, devices, or an owner. Usable source: %1")
            .arg(m_snapshot.usablePhysicalSource.isEmpty() ? localized("Unavailable") : m_snapshot.usablePhysicalSource));
    if (!m_snapshot.reserved.valid) { reserved->setText(1, localized("Unavailable")); reserved->setText(2, localized("Unavailable")); }
    QTreeWidgetItem* const physical = addRow(
        installed, localized("Windows usable physical RAM"), m_snapshot.totalPhysicalBytes, 0,
        localized("Exact partition"), localized("The physical-memory denominator exposed by the Windows memory manager."));
    addRow(physical, localized("In use"), m_snapshot.inUseBytes,
        m_summaryDeltaBytes.value(QStringLiteral("in_use")), localized("Exact partition"),
        localized("Physical RAM that is not currently available for immediate reuse."));
    addRow(physical, localized("Available"), m_snapshot.availableBytes,
        m_summaryDeltaBytes.value(QStringLiteral("available")), localized("Exact partition"),
        localized("Standby, free, and zeroed pages available to satisfy demand."));

    QTreeWidgetItem* const quickAccounting = addRow(nullptr, localized("In-use accounting"), m_snapshot.inUseBytes, 0,
        localized("Snapshot estimate"), localized("Counters are sampled separately; use the PFN ledger for a disjoint physical-page partition."));
    QTreeWidgetItem* const identified = addRow(
        quickAccounting, localized("Snapshot category sum"), m_snapshot.identifiedResidentLowerBoundBytes, 0,
        localized("Additive lower bound"),
        localized("Non-overlapping categories that can be safely added without counting shared working sets twice."));
    addRow(identified, localized("Process private resident"), m_snapshot.processPrivateResidentBytes,
        m_summaryDeltaBytes.value(QStringLiteral("process_private")), localized("Additive"),
        localized("Private physical pages from the kernel process snapshot, including protected and system processes."));
    addRow(identified, localized("Nonpaged pool"), m_snapshot.nonPagedPoolBytes,
        m_summaryDeltaBytes.value(QStringLiteral("nonpaged_pool")), localized("Additive"),
        localized("Kernel and driver allocations that cannot be paged out."));
    addRow(identified, localized("Paged pool resident"), m_snapshot.pagedPoolResidentBytes,
        m_summaryDeltaBytes.value(QStringLiteral("paged_pool_resident")), localized("Additive"),
        localized("The resident subset of pageable kernel pool."));
    addRow(identified, localized("Kernel code resident"), m_snapshot.systemCodeResidentBytes,
        m_summaryDeltaBytes.value(QStringLiteral("system_code")), localized("Additive"),
        localized("Resident operating-system code pages."));
    addRow(identified, localized("Driver code resident"), m_snapshot.systemDriverResidentBytes,
        m_summaryDeltaBytes.value(QStringLiteral("system_driver")), localized("Additive"),
        localized("Resident loaded-driver code pages."));
    addRow(identified, localized("Modified page lists"),
        m_snapshot.modifiedBytes + m_snapshot.modifiedNoWriteBytes,
        m_summaryDeltaBytes.value(QStringLiteral("modified")), localized("Additive"),
        localized("Dirty transition pages that still occupy RAM and are not immediately reusable."));
    QTreeWidgetItem* const residual = addRow(
        quickAccounting, localized("Snapshot remainder"), m_snapshot.unattributedResidentBytes,
        m_summaryDeltaBytes.value(QStringLiteral("unattributed")), localized("Explicit remainder"),
        localized("Shared/image pages, page tables, kernel stacks, locked pages, compression, secure memory, and other categories not uniquely attributable here."));
    residual->setForeground(0, KswordTheme::WarningColor());
    residual->setForeground(1, KswordTheme::WarningColor());
    if (m_snapshot.overAccountedResidentBytes)
    {
        auto* const excess = addRow(quickAccounting, localized("Counters exceed sampled in-use RAM"), m_snapshot.overAccountedResidentBytes, 0,
            localized("Sampling discrepancy"), localized("A zero remainder here does not prove full attribution; sampled counters exceed the physical in-use total."));
        excess->setForeground(0, KswordTheme::WarningColor());
    }

    if (m_snapshot.memoryListAvailable)
    {
        std::uint64_t standbyTotal = 0;
        for (const std::uint64_t bytes : m_snapshot.standbyBytes)
        {
            standbyTotal += bytes;
        }
        QTreeWidgetItem* const lists = addRow(
            nullptr, localized("Physical page lists"),
            m_snapshot.zeroBytes + m_snapshot.freeBytes + standbyTotal +
                m_snapshot.modifiedBytes + m_snapshot.modifiedNoWriteBytes + m_snapshot.badBytes,
            0, localized("Page-state evidence"),
            localized("A page-list view; some rows are available while modified pages remain in use."));
        addRow(lists, localized("Standby total"), standbyTotal, 0, localized("Available"),
            localized("Cached pages split by memory priority and reclaimable under pressure."));
        for (int priority = 0; priority < static_cast<int>(m_snapshot.standbyBytes.size()); ++priority)
        {
            addRow(lists,
                localized("Standby priority %1").arg(priority),
                m_snapshot.standbyBytes[priority], 0, localized("Available"),
                localized("Priority-specific standby pages."));
        }
        addRow(lists, localized("Free"), m_snapshot.freeBytes, 0, localized("Available"),
            localized("Free pages that have not yet been zeroed."));
        addRow(lists, localized("Zeroed"), m_snapshot.zeroBytes, 0, localized("Available"),
            localized("Zero-filled pages ready for immediate allocation."));
        addRow(lists, localized("Modified"), m_snapshot.modifiedBytes, 0, localized("In use"),
            localized("Dirty pages waiting for writeback or another backing-store action."));
        addRow(lists, localized("Modified no-write"), m_snapshot.modifiedNoWriteBytes, 0, localized("In use"),
            localized("Modified pages owned by a no-write memory manager path."));
        addRow(lists, localized("Bad pages"), m_snapshot.badBytes, 0, localized("Unavailable"),
            localized("Physical pages retired because they cannot be used safely."));
    }

    QTreeWidgetItem* const overlap = addRow(
        nullptr, localized("Overlapping and commit evidence"), 0, 0,
        localized("Do not add"),
        localized("These counters explain pressure or sharing but overlap the physical accounting above."));
    addRow(overlap, localized("All process working-set references"), m_snapshot.processWorkingSetReferenceBytes, 0,
        localized("Overlapping"), localized("Shared pages may appear in multiple process working sets."));
    addRow(overlap, localized("Shared process WS references"), m_snapshot.processSharedResidentReferenceBytes, 0,
        localized("Overlapping"), localized("Working-set references beyond private resident pages; not unique physical bytes."));
    addRow(overlap, localized("User-mode mapped resident references"), m_userResidencyScan.residentReferenceBytes, 0,
        localized("Overlapping"),
        localized("Deep-scan references grouped by process, private allocation, image, and mapped-file backing."));
    addRow(overlap, localized("User-mode proportional resident estimate"), m_userResidencyScan.proportionalResidentBytes, 0,
        localized("Estimate, do not add"),
        localized("Each shared page reference is divided by the observed share count, which is capped by Windows and is not a PFN identity."));
    addRow(overlap, localized("System cache resident"), m_snapshot.systemCacheResidentBytes, 0,
        localized("Overlapping"), localized("Resident cache pages can overlap shared or file-backed mappings."));
    addRow(overlap, localized("Broad system cache"), m_snapshot.broadSystemCacheBytes, 0,
        localized("Overlapping"), localized("Includes cache plus shareable standby and modified pages on supported systems."));
    addRow(overlap, localized("Paged pool committed"), m_snapshot.pagedPoolCommittedBytes, 0,
        localized("Commit, not residency"), localized("Pageable pool bytes can reside in RAM or backing storage."));
    addRow(overlap, localized("Process private commit"), m_snapshot.processPrivateCommitBytes, 0,
        localized("Commit, not residency"), localized("Private committed virtual memory can be in RAM or the page file."));
    auto* const systemCommit = addRow(overlap, localized("System commit"), m_snapshot.commit.bytes, 0,
        localized("Commit, not residency"), commitEvidence(m_snapshot.commit));
    if (!m_snapshot.commit.valid) { systemCommit->setText(1, localized("Unavailable")); systemCommit->setText(2, localized("Unavailable")); }
    auto* const sharedCommit = addRow(overlap, localized("Shared committed"), m_snapshot.sharedCommittedBytes, 0,
        localized("Commit, not residency"), localized("System-wide shared commitment."));
    if (!m_snapshot.sharedCommittedValid) { sharedCommit->setText(1, localized("Unavailable")); sharedCommit->setText(2, localized("Unavailable")); }
    if (m_snapshot.mdlAllocatedBytes != 0 || m_snapshot.pfnDatabaseCommittedBytes != 0 ||
        m_snapshot.systemPageTableCommittedBytes != 0 || m_snapshot.contiguousAllocatedBytes != 0)
    {
        addRow(overlap, localized("MDL pages"), m_snapshot.mdlAllocatedBytes, 0,
            localized("Potentially overlapping"), localized("Pages represented by MDLs; may also belong to a process or I/O cache."));
        addRow(overlap, localized("PFN database committed"), m_snapshot.pfnDatabaseCommittedBytes, 0,
            localized("Kernel metadata"), localized("Memory-manager metadata used to track physical pages."));
        addRow(overlap, localized("System page tables committed"), m_snapshot.systemPageTableCommittedBytes, 0,
            localized("Kernel metadata"), localized("Commit used for system page-table structures."));
        addRow(overlap, localized("Contiguous pages allocated"), m_snapshot.contiguousAllocatedBytes, 0,
            localized("Potentially overlapping"), localized("Physically contiguous allocations, often used by drivers or DMA paths."));
    }

    m_overviewTree->expandToDepth(1);
    for (int column = 0; column < 5; ++column)
    {
        m_overviewTree->resizeColumnToContents(column);
    }
    m_overviewTree->setUpdatesEnabled(true);
}

void SystemMemoryAuditPage::rebuildUserResidencyTable() { requestTableProjection(AuditKind::UserResidency); }
void SystemMemoryAuditPage::rebuildProcessTable() { requestTableProjection(AuditKind::Processes); }
void SystemMemoryAuditPage::rebuildPoolTagTable() { requestTableProjection(AuditKind::PoolTags); }
void SystemMemoryAuditPage::rebuildBigPoolTable() { requestTableProjection(AuditKind::BigPool); }

void SystemMemoryAuditPage::updateDetails()
{
    QString text;
    if (m_detailTabs->currentIndex() == 0)
    {
        text = usePfnOverview() ? localized(
            "The PFN ledger replaces snapshot estimates with unique physical-page classifications. Unknown use, failed queries and unscanned pages remain separate. Missing process or file names do not change a known use. This collection has its own time and is not combined with newer quick counters.") : localized(
            "The quick remainder can include shared/image pages, page tables, kernel stacks, locked pages and other unmeasured uses. Run PFN deep attribution to classify unique physical pages. Hardware reservations are outside Windows usable RAM; overlapping cache, commitment and Hyper-V counters are not subtracted from this remainder.");
    }
    else if (m_detailTabs->currentIndex() == 1)
    {
        text = localized(
            "The user-mode deep scan groups resident references by virtual region and backing evidence. A failed file-path query leaves the mapped backing unresolved; it does not prove a pagefile-backed section. The working-set Shared bit preserves private COW copies. Shared pages remain attached to each observed mapper; proportional bytes are an estimate, not unique PFNs.");
    }
    else if (m_detailTabs->currentIndex() == 2)
    {
        text = localized(
            "Processes come from the kernel SystemProcessInformation snapshot, not a Toolhelp visible-process list. Private resident is additive; total working set and shared WS references are diagnostic because shared physical pages can appear in more than one process.");
    }
    else if (m_detailTabs->currentIndex() == 3)
    {
        text = localized(
            "Pool tags follow the PoolMonX principle and report allocation/frees plus bytes by four-byte tag. Nonpaged bytes are resident; paged bytes are pageable commitment. A tag identifies an allocator convention, not cryptographic ownership, so source metadata is evidence rather than proof.");
    }
    else
    {
        text = localized(
            "Big Pool lists individual page-sized or larger kernel allocations. The low address bit encodes nonpaged state and is removed before display. These rows are already included in pool totals and must not be added again to physical usage.");
    }
    ks::ui::FieldDocument document;
    document.note(text);
    if (!m_poolTagMetadataSource.isEmpty())
    {
        document.field(QStringLiteral("Pool tag metadata"), QDir::toNativeSeparators(m_poolTagMetadataSource));
    }
    else
    {
        document.note(localized("Pool tag metadata was not found; tag bytes and usage remain valid, but source descriptions are unavailable."));
    }
    m_detailText->setDocument(document);
}

void SystemMemoryAuditPage::updateStatus()
{
    const QString filter = m_filterEdit->text().trimmed();
    QString text = localized("Sample %1 | processes %2/%3 | pool tags %4/%5 | Big Pool %6/%7")
        .arg(m_snapshot.sampledAt)
        .arg(m_processTable->rowCount())
        .arg(m_snapshot.processes->size())
        .arg(m_poolTagTable->rowCount())
        .arg(m_snapshot.poolTags->size())
        .arg(m_bigPoolTable->rowCount())
        .arg(m_snapshot.bigPool->size());
    if (m_userResidencyScanInProgress.load())
    {
        text += localized(" | user residency: scanning");
    }
    else if (!m_userResidencyScan.sampledAt.isEmpty())
    {
        text += localized(" | user residency %1: processes %2/%3, rows %4")
            .arg(m_userResidencyScan.sampledAt)
            .arg(m_userResidencyScan.accessibleProcessCount)
            .arg(m_userResidencyScan.processCount)
            .arg(m_userResidencyTable->rowCount());
    }
    if (!filter.isEmpty())
    {
        text += localized(" | filter: %1").arg(filter);
    }
    const bool hasWarnings = !m_snapshot.errors.isEmpty() || !m_userResidencyScan.errors.isEmpty();
    if (!m_snapshot.errors.isEmpty())
    {
        text += localized(" | partial evidence warnings: %1 (details in log)")
            .arg(m_snapshot.errors.size());
    }
    if (!m_userResidencyScan.errors.isEmpty())
    {
        text += localized(" | user-scan warnings: %1 (details in log)")
            .arg(m_userResidencyScan.errors.size());
    }
    m_statusLabel->setStyleSheet(hasWarnings
        ? QStringLiteral("color: %1;").arg(KswordTheme::WarningHex())
        : QString());
    m_statusLabel->setText(text);
}

void SystemMemoryAuditPage::loadPoolTagMetadata()
{
    QStringList candidates;
    const QString programFilesX86 = qEnvironmentVariable("ProgramFiles(x86)");
    const QString programFiles = qEnvironmentVariable("ProgramFiles");
    if (!programFilesX86.isEmpty())
    {
        candidates << QDir(programFilesX86).filePath(QStringLiteral("Windows Kits/10/Debuggers/x64/triage/pooltag.txt"));
        candidates << QDir(programFilesX86).filePath(QStringLiteral("Windows Kits/10/Debuggers/x86/triage/pooltag.txt"));
    }
    if (!programFiles.isEmpty())
    {
        candidates << QDir(programFiles).filePath(QStringLiteral("Windows Kits/10/Debuggers/x64/triage/pooltag.txt"));
    }
    candidates << QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("pooltag.txt"));

    QFile file;
    for (const QString& candidate : std::as_const(candidates))
    {
        file.setFileName(candidate);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            m_poolTagMetadataSource = candidate;
            break;
        }
    }
    if (!file.isOpen())
    {
        return;
    }

    while (!file.atEnd())
    {
        const QByteArray rawLine = file.readLine();
        if (rawLine.size() < 4 || rawLine.startsWith("//") || rawLine.startsWith("rem"))
        {
            continue;
        }
        std::uint32_t tag = 0;
        std::memcpy(&tag, rawLine.constData(), sizeof(tag));
        const QString line = QString::fromLocal8Bit(rawLine).trimmed();
        const int firstDash = line.indexOf(QLatin1Char('-'), 4);
        if (firstDash < 0)
        {
            continue;
        }
        const int secondDash = line.indexOf(QLatin1Char('-'), firstDash + 1);
        TagMetadata metadata;
        metadata.source = secondDash >= 0
            ? line.mid(firstDash + 1, secondDash - firstDash - 1).trimmed()
            : line.mid(firstDash + 1).trimmed();
        if (secondDash >= 0)
        {
            metadata.description = line.mid(secondDash + 1).trimmed();
        }
        if (!metadata.source.isEmpty() || !metadata.description.isEmpty())
        {
            m_poolTagMetadata.insert(tag, std::move(metadata));
        }
    }
}

SystemMemoryAuditPage::UserResidencyScan SystemMemoryAuditPage::collectUserResidency(
    const std::vector<ProcessRow>& processes,
    const std::uint64_t pageSize)
{
    UserResidencyScan scan;
    scan.sampledAt = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    if (pageSize == 0)
    {
        scan.errors << QStringLiteral("invalid-page-size");
        return scan;
    }

    QHash<QString, int> rowIndexByKey;
    for (const ProcessRow& process : processes)
    {
        if (process.pid == 0)
        {
            continue;
        }
        ++scan.processCount;

        ScopedHandle processHandle(::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            process.pid));
        if (!processHandle)
        {
            ++scan.inaccessibleProcessCount;
            continue;
        }

        std::vector<PSAPI_WORKING_SET_BLOCK> workingSetBlocks;
        if (!queryProcessWorkingSet(
                processHandle.get(),
                process.workingSetBytes,
                pageSize,
                workingSetBlocks))
        {
            ++scan.inaccessibleProcessCount;
            continue;
        }
        ++scan.accessibleProcessCount;

        MEMORY_BASIC_INFORMATION region{};
        std::uintptr_t regionBegin = 0;
        std::uintptr_t regionEnd = 0;
        QHash<quintptr, MappedPathObservation> mappedPathByAllocationBase;

        for (const PSAPI_WORKING_SET_BLOCK& block : workingSetBlocks)
        {
            if (block.VirtualPage > (std::numeric_limits<std::uintptr_t>::max)() / pageSize)
            {
                continue;
            }
            const std::uintptr_t virtualAddress =
                static_cast<std::uintptr_t>(block.VirtualPage * pageSize);
            if (virtualAddress < regionBegin || virtualAddress >= regionEnd)
            {
                std::memset(&region, 0, sizeof(region));
                if (::VirtualQueryEx(
                        processHandle.get(),
                        reinterpret_cast<const void*>(virtualAddress),
                        &region,
                        sizeof(region)) != sizeof(region))
                {
                    regionBegin = virtualAddress;
                    regionEnd = virtualAddress + static_cast<std::uintptr_t>(pageSize);
                    region.Type = 0;
                    region.AllocationBase = nullptr;
                }
                else
                {
                    regionBegin = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
                    const std::uintptr_t regionSize = static_cast<std::uintptr_t>(region.RegionSize);
                    regionEnd = regionSize > (std::numeric_limits<std::uintptr_t>::max)() - regionBegin
                        ? (std::numeric_limits<std::uintptr_t>::max)()
                        : regionBegin + regionSize;
                }
            }

            UserMemoryKind kind = UserMemoryKind::Unknown;
            QString backingKey = QStringLiteral(":unknown");
            bool pathQueryAttempted = false;
            std::uint32_t pathStatus = 0;
            bool backingRegionKnown = false;
            std::uint32_t backingRegionStatus = 0;
            if (region.Type == MEM_PRIVATE)
            {
                kind = UserMemoryKind::Private;
                backingKey = QStringLiteral(":private");
            }
            else if (region.Type == MEM_IMAGE || region.Type == MEM_MAPPED)
            {
                const quintptr allocationBase = reinterpret_cast<quintptr>(region.AllocationBase);
                auto observed = mappedPathByAllocationBase.constFind(allocationBase);
                if (observed == mappedPathByAllocationBase.constEnd())
                {
                    mappedPathByAllocationBase.insert(allocationBase,
                        mappedFilePath(processHandle.get(), reinterpret_cast<const void*>(virtualAddress), region));
                    observed = mappedPathByAllocationBase.constFind(allocationBase);
                }
                const auto& observation = observed.value();
                pathQueryAttempted = true;
                pathStatus = observation.status;
                backingRegionKnown = observation.regionKnown;
                backingRegionStatus = observation.regionStatus;
                kind = ksword::memoryaudit::classifyResident(
                    region.Type == MEM_IMAGE ? ksword::memoryaudit::RegionKind::Image : ksword::memoryaudit::RegionKind::Mapped,
                    block.Shared != 0, !observation.path.isEmpty(), observation.proof);
                backingKey = observation.path.isEmpty()
                    ? (region.Type == MEM_IMAGE ? QStringLiteral(":image") : QStringLiteral(":mapped-unknown")) : observation.path;
                if (observation.path.isEmpty() && observation.proof == ksword::memoryaudit::BackingProof::Pagefile) { backingKey = QStringLiteral(":pagefile"); }
                if (observation.path.isEmpty() && observation.proof == ksword::memoryaudit::BackingProof::DataFile) { backingKey = QStringLiteral(":file-path-unavailable"); }
            }

            const QString aggregationKey = QStringLiteral("%1\x1f%2\x1f%3\x1f%4\x1f%5\x1f%6")
                .arg(process.pid)
                .arg(static_cast<int>(kind))
                .arg(backingKey)
                .arg(pathStatus).arg(backingRegionStatus).arg(backingRegionKnown);
            int rowIndex = rowIndexByKey.value(aggregationKey, -1);
            if (rowIndex < 0)
            {
                UserResidencyRow row;
                row.pid = process.pid;
                row.processName = process.name;
                row.kind = kind;
                row.backingPath = backingKey;
                row.backingPathQueryAttempted = pathQueryAttempted;
                row.backingPathStatus = pathStatus;
                row.backingRegionKnown = backingRegionKnown;
                row.backingRegionStatus = backingRegionStatus;
                scan.rows->push_back(std::move(row));
                rowIndex = static_cast<int>(scan.rows->size() - 1);
                rowIndexByKey.insert(aggregationKey, rowIndex);
            }

            UserResidencyRow& row = (*scan.rows)[static_cast<std::size_t>(rowIndex)];
            row.residentReferenceBytes += pageSize;
            scan.residentReferenceBytes += pageSize;

            if (block.Shared == 0)
            {
                row.privateResidentBytes += pageSize;
                scan.privateResidentBytes += pageSize;
            }
            if (block.Shared != 0)
            {
                row.shareableResidentBytes += pageSize;
            }
            if (block.ShareCount > 1)
            {
                row.sharedResidentReferenceBytes += pageSize;
                scan.sharedResidentReferenceBytes += pageSize;
            }

            const std::uint64_t divisor = block.ShareCount > 1
                ? static_cast<std::uint64_t>(block.ShareCount)
                : 1ULL;
            const std::uint64_t proportionalBytes = pageSize / divisor;
            row.proportionalResidentBytes += proportionalBytes;
            scan.proportionalResidentBytes += proportionalBytes;
        }
    }

    std::sort(
        scan.rows->begin(),
        scan.rows->end(),
        [](const UserResidencyRow& left, const UserResidencyRow& right) {
            if (left.residentReferenceBytes != right.residentReferenceBytes)
            {
                return left.residentReferenceBytes > right.residentReferenceBytes;
            }
            if (left.pid != right.pid)
            {
                return left.pid < right.pid;
            }
            return left.backingPath.compare(right.backingPath, Qt::CaseInsensitive) < 0;
        });
    return scan;
}

SystemMemoryAuditPage::Snapshot SystemMemoryAuditPage::collectSnapshot()
{
    Snapshot snapshot;
    snapshot.sampledAt = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));

    SYSTEM_INFO systemInfo{};
    ::GetSystemInfo(&systemInfo);
    snapshot.pageSize = systemInfo.dwPageSize != 0 ? systemInfo.dwPageSize : 4096;

    ULONGLONG installedKilobytes = 0;
    const bool installedSucceeded = ::GetPhysicallyInstalledSystemMemory(&installedKilobytes) != FALSE;
    snapshot.installedPhysicalStatus = installedSucceeded ? ERROR_SUCCESS : ::GetLastError();
    if (installedSucceeded && installedKilobytes &&
        installedKilobytes <= (std::numeric_limits<std::uint64_t>::max)() / 1024ULL)
    {
        snapshot.installedPhysicalBytes = installedKilobytes * 1024ULL;
        snapshot.installedPhysicalValid = true;
    }
    else if (installedSucceeded)
    {
        snapshot.installedPhysicalStatus = ERROR_INVALID_DATA;
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus))
    {
        snapshot.totalPhysicalBytes = memoryStatus.ullTotalPhys;
        snapshot.availableBytes = memoryStatus.ullAvailPhys;
        snapshot.usablePhysicalValid = true;
        snapshot.usablePhysicalSource = QStringLiteral("GlobalMemoryStatusEx");
        // MEMORYSTATUSEX pagefile fields can be constrained by this process or
        // its job. They are never a source for the system commitment ledger.
    }
    else
    {
        snapshot.pendingErrors.push_back({ QStringLiteral("GlobalMemoryStatusEx failed"), {} });
    }

    PERFORMANCE_INFORMATION publicPerformance{};
    publicPerformance.cb = sizeof(publicPerformance);
    const bool publicSucceeded = ::GetPerformanceInfo(&publicPerformance, sizeof(publicPerformance)) != FALSE;
    const DWORD publicError = publicSucceeded ? ERROR_SUCCESS : ::GetLastError();
    snapshot.commit.recordPublic(publicSucceeded, publicError, publicPerformance.CommitTotal,
        publicPerformance.CommitLimit, publicPerformance.CommitPeak, publicPerformance.PageSize);
    if (publicSucceeded)
    {
        const std::uint64_t publicPageSize = publicPerformance.PageSize != 0
            ? static_cast<std::uint64_t>(publicPerformance.PageSize)
            : snapshot.pageSize;
        snapshot.pageSize = publicPageSize;
        snapshot.pagedPoolCommittedBytes = multiplyPages(publicPerformance.KernelPaged, publicPageSize);
        snapshot.nonPagedPoolBytes = multiplyPages(publicPerformance.KernelNonpaged, publicPageSize);
        snapshot.broadSystemCacheBytes = multiplyPages(publicPerformance.SystemCache, publicPageSize);
        if (!snapshot.usablePhysicalValid)
        {
            snapshot.totalPhysicalBytes = multiplyPages(publicPerformance.PhysicalTotal, publicPageSize);
            snapshot.availableBytes = multiplyPages(publicPerformance.PhysicalAvailable, publicPageSize);
            snapshot.usablePhysicalValid = true;
            snapshot.usablePhysicalSource = QStringLiteral("GetPerformanceInfo");
        }
    }
    else
    {
        snapshot.pendingErrors.push_back({ QStringLiteral("GetPerformanceInfo failed"), {} });
    }

    const NtQuerySystemInformationFunction queryFunction = resolveNtQuerySystemInformation();
    if (queryFunction == nullptr)
    {
        snapshot.pendingErrors.push_back({ QStringLiteral("NtQuerySystemInformation is unavailable"), {} });
    }

    if (queryFunction != nullptr)
    {
        NativeSystemMemoryUsageInformation memoryUsage{};
        ULONG returnedBytes = 0;
        const LONG status = queryFunction(
            kSystemMemoryUsageInformation,
            &memoryUsage,
            sizeof(memoryUsage),
            &returnedBytes);
        snapshot.commit.recordNative(static_cast<std::int32_t>(status), returnedBytes, sizeof(memoryUsage),
            memoryUsage.CommittedBytes, memoryUsage.CommitLimitBytes, memoryUsage.PeakCommitmentBytes);
        if (nativeSuccess(status) && returnedBytes == sizeof(memoryUsage))
        {
            snapshot.totalPhysicalBytes = memoryUsage.TotalPhysicalBytes;
            snapshot.availableBytes = memoryUsage.AvailableBytes;
            snapshot.usablePhysicalValid = true;
            snapshot.usablePhysicalSource = QStringLiteral("SystemMemoryUsageInformation");
            snapshot.residentAvailableBytes = memoryUsage.ResidentAvailableBytes > 0
                ? static_cast<std::uint64_t>(memoryUsage.ResidentAvailableBytes)
                : 0;
            snapshot.sharedCommittedBytes = memoryUsage.SharedCommittedBytes;
            snapshot.sharedCommittedValid = true;
        }

        NativeSystemMemoryListInformation memoryList{};
        returnedBytes = 0;
        const LONG memoryListStatus = queryFunction(
            kSystemMemoryListInformation,
            &memoryList,
            sizeof(memoryList),
            &returnedBytes);
        if (nativeSuccess(memoryListStatus))
        {
            snapshot.memoryListAvailable = true;
            snapshot.zeroBytes = multiplyPages(memoryList.ZeroPageCount, snapshot.pageSize);
            snapshot.freeBytes = multiplyPages(memoryList.FreePageCount, snapshot.pageSize);
            snapshot.modifiedBytes = multiplyPages(memoryList.ModifiedPageCount, snapshot.pageSize);
            snapshot.modifiedNoWriteBytes = multiplyPages(memoryList.ModifiedNoWritePageCount, snapshot.pageSize);
            snapshot.badBytes = multiplyPages(memoryList.BadPageCount, snapshot.pageSize);
            snapshot.modifiedPageFileBytes = multiplyPages(memoryList.ModifiedPageCountPageFile, snapshot.pageSize);
            for (std::size_t index = 0; index < snapshot.standbyBytes.size(); ++index)
            {
                snapshot.standbyBytes[index] = multiplyPages(memoryList.PageCountByPriority[index], snapshot.pageSize);
                snapshot.repurposedBytes[index] = multiplyPages(memoryList.RepurposedPagesByPriority[index], snapshot.pageSize);
            }
        }
        else
        {
            snapshot.pendingErrors.push_back({ QStringLiteral("Memory page-list query failed (%1)"), statusHex(memoryListStatus) });
        }

        std::array<std::byte, 1024> performanceBuffer{};
        returnedBytes = 0;
        const LONG performanceStatus = queryFunction(
            kSystemPerformanceInformation,
            performanceBuffer.data(),
            static_cast<ULONG>(performanceBuffer.size()),
            &returnedBytes);
        constexpr std::size_t requiredPerformanceBytes =
            offsetof(NativeSystemPerformanceInformation, ResidentSystemDriverPage) + sizeof(ULONG);
        if (nativeSuccess(performanceStatus) &&
            (returnedBytes == 0 || returnedBytes >= requiredPerformanceBytes))
        {
            snapshot.performanceAvailable = true;
            const auto* const performance = reinterpret_cast<const NativeSystemPerformanceInformation*>(performanceBuffer.data());
            snapshot.pagedPoolCommittedBytes = multiplyPages(performance->PagedPoolPages, snapshot.pageSize);
            snapshot.nonPagedPoolBytes = multiplyPages(performance->NonPagedPoolPages, snapshot.pageSize);
            snapshot.pagedPoolResidentBytes = multiplyPages(performance->ResidentPagedPoolPage, snapshot.pageSize);
            snapshot.systemCodeResidentBytes = multiplyPages(performance->ResidentSystemCodePage, snapshot.pageSize);
            snapshot.systemDriverResidentBytes = multiplyPages(performance->ResidentSystemDriverPage, snapshot.pageSize);
            snapshot.systemCacheResidentBytes = multiplyPages(performance->ResidentSystemCachePage, snapshot.pageSize);
            if (returnedBytes >= offsetof(NativeSystemPerformanceInformation, MdlPagesAllocated) + sizeof(ULONGLONG))
            {
                snapshot.mdlAllocatedBytes = multiplyPages(performance->MdlPagesAllocated, snapshot.pageSize);
            }
            if (returnedBytes >= offsetof(NativeSystemPerformanceInformation, PfnDatabaseCommittedPages) + sizeof(ULONGLONG))
            {
                snapshot.pfnDatabaseCommittedBytes = multiplyPages(performance->PfnDatabaseCommittedPages, snapshot.pageSize);
            }
            if (returnedBytes >= offsetof(NativeSystemPerformanceInformation, SystemPageTableCommittedPages) + sizeof(ULONGLONG))
            {
                snapshot.systemPageTableCommittedBytes = multiplyPages(performance->SystemPageTableCommittedPages, snapshot.pageSize);
            }
            if (returnedBytes >= offsetof(NativeSystemPerformanceInformation, ContiguousPagesAllocated) + sizeof(ULONGLONG))
            {
                snapshot.contiguousAllocatedBytes = multiplyPages(performance->ContiguousPagesAllocated, snapshot.pageSize);
            }
        }
        else
        {
            snapshot.pendingErrors.push_back({ QStringLiteral("System performance query failed (%1)"), statusHex(performanceStatus) });
        }

        std::vector<std::byte> processBuffer;
        LONG processStatus = 0;
        if (queryVariableSystemInformation(queryFunction, kSystemProcessInformation, processBuffer, processStatus))
        {
            std::size_t offset = 0;
            while (offset + sizeof(NativeSystemProcessInformation) <= processBuffer.size())
            {
                const auto* const process = reinterpret_cast<const NativeSystemProcessInformation*>(processBuffer.data() + offset);
                ProcessRow row;
                row.pid = static_cast<std::uint32_t>(reinterpret_cast<ULONG_PTR>(process->UniqueProcessId));
                row.sessionId = process->SessionId;
                row.privateResidentBytes = process->WorkingSetPrivateSize;
                row.workingSetBytes = process->WorkingSetSize;
                row.sharedResidentReferenceBytes = row.workingSetBytes > row.privateResidentBytes
                    ? row.workingSetBytes - row.privateResidentBytes
                    : 0;
                row.privateCommitBytes = process->PrivatePageCount;
                row.pagedPoolQuotaBytes = process->QuotaPagedPoolUsage;
                row.nonPagedPoolQuotaBytes = process->QuotaNonPagedPoolUsage;
                row.hardFaultCount = process->HardFaultCount;
                row.identity = (static_cast<std::uint64_t>(row.pid) << 32) ^
                    static_cast<std::uint64_t>(process->CreateTime.QuadPart);

                const auto bufferStart = reinterpret_cast<std::uintptr_t>(processBuffer.data());
                const auto bufferEnd = bufferStart + processBuffer.size();
                const auto nameStart = reinterpret_cast<std::uintptr_t>(process->ImageName.Buffer);
                const auto nameEnd = nameStart + process->ImageName.Length;
                if (process->ImageName.Buffer != nullptr &&
                    process->ImageName.Length % sizeof(wchar_t) == 0 &&
                    nameStart >= bufferStart && nameEnd >= nameStart && nameEnd <= bufferEnd)
                {
                    row.name = QString::fromWCharArray(
                        process->ImageName.Buffer,
                        process->ImageName.Length / sizeof(wchar_t));
                }
                if (row.name.isEmpty())
                {
                    row.name = row.pid == 0 ? QStringLiteral("[Idle]")
                        : row.pid == 4 ? QStringLiteral("System")
                        : QStringLiteral("[unnamed]");
                }

                snapshot.processPrivateResidentBytes += row.privateResidentBytes;
                snapshot.processWorkingSetReferenceBytes += row.workingSetBytes;
                snapshot.processSharedResidentReferenceBytes += row.sharedResidentReferenceBytes;
                snapshot.processPrivateCommitBytes += row.privateCommitBytes;
                snapshot.processPagedPoolQuotaBytes += row.pagedPoolQuotaBytes;
                snapshot.processNonPagedPoolQuotaBytes += row.nonPagedPoolQuotaBytes;
                snapshot.processes->push_back(std::move(row));

                if (process->NextEntryOffset == 0)
                {
                    break;
                }
                if (process->NextEntryOffset < sizeof(NativeSystemProcessInformation) ||
                    process->NextEntryOffset > processBuffer.size() - offset)
                {
                    snapshot.pendingErrors.push_back({ QStringLiteral("Kernel process snapshot contained an invalid next-entry offset"), {} });
                    break;
                }
                offset += process->NextEntryOffset;
            }
            std::sort(snapshot.processes->begin(), snapshot.processes->end(), [](const ProcessRow& left, const ProcessRow& right) {
                return left.privateResidentBytes > right.privateResidentBytes;
                });
        }
        else
        {
            snapshot.pendingErrors.push_back({ QStringLiteral("Kernel process snapshot failed (%1)"), statusHex(processStatus) });
        }

        std::vector<std::byte> poolTagBuffer;
        LONG poolTagStatus = 0;
        if (queryVariableSystemInformation(queryFunction, kSystemPoolTagInformation, poolTagBuffer, poolTagStatus) &&
            poolTagBuffer.size() >= offsetof(NativeSystemPoolTagInformation, TagInfo))
        {
            const auto* const information = reinterpret_cast<const NativeSystemPoolTagInformation*>(poolTagBuffer.data());
            const std::size_t maximumCount =
                (poolTagBuffer.size() - offsetof(NativeSystemPoolTagInformation, TagInfo)) / sizeof(NativeSystemPoolTag);
            const std::size_t count = std::min<std::size_t>(information->Count, maximumCount);
            snapshot.poolTags->reserve(count);
            for (std::size_t index = 0; index < count; ++index)
            {
                const NativeSystemPoolTag& nativeRow = information->TagInfo[index];
                PoolTagRow row;
                row.tag = nativeRow.TagUlong;
                row.tagText = printableTag(nativeRow.Tag);
                row.pagedBytes = nativeRow.PagedUsed;
                row.nonPagedBytes = nativeRow.NonPagedUsed;
                row.pagedOutstanding = nativeRow.PagedAllocs >= nativeRow.PagedFrees
                    ? static_cast<std::uint64_t>(nativeRow.PagedAllocs - nativeRow.PagedFrees)
                    : 0;
                row.nonPagedOutstanding = nativeRow.NonPagedAllocs >= nativeRow.NonPagedFrees
                    ? static_cast<std::uint64_t>(nativeRow.NonPagedAllocs - nativeRow.NonPagedFrees)
                    : 0;
                snapshot.poolTagPagedBytes += row.pagedBytes;
                snapshot.poolTagNonPagedBytes += row.nonPagedBytes;
                snapshot.poolTags->push_back(std::move(row));
            }
            std::sort(snapshot.poolTags->begin(), snapshot.poolTags->end(), [](const PoolTagRow& left, const PoolTagRow& right) {
                return left.pagedBytes + left.nonPagedBytes > right.pagedBytes + right.nonPagedBytes;
                });
        }
        else
        {
            snapshot.pendingErrors.push_back({ QStringLiteral("Pool-tag query failed (%1)"), statusHex(poolTagStatus) });
        }

        std::vector<std::byte> bigPoolBuffer;
        LONG bigPoolStatus = 0;
        if (queryVariableSystemInformation(queryFunction, kSystemBigPoolInformation, bigPoolBuffer, bigPoolStatus) &&
            bigPoolBuffer.size() >= offsetof(NativeSystemBigPoolInformation, AllocatedInfo))
        {
            const auto* const information = reinterpret_cast<const NativeSystemBigPoolInformation*>(bigPoolBuffer.data());
            const std::size_t maximumCount =
                (bigPoolBuffer.size() - offsetof(NativeSystemBigPoolInformation, AllocatedInfo)) / sizeof(NativeSystemBigPoolEntry);
            const std::size_t count = std::min<std::size_t>(information->Count, maximumCount);
            snapshot.bigPool->reserve(count);
            for (std::size_t index = 0; index < count; ++index)
            {
                const NativeSystemBigPoolEntry& nativeRow = information->AllocatedInfo[index];
                BigPoolRow row;
                row.nonPaged = (nativeRow.VirtualAddressAndFlags & 1ULL) != 0;
                row.virtualAddress = nativeRow.VirtualAddressAndFlags & ~1ULL;
                row.sizeBytes = nativeRow.SizeInBytes;
                row.tag = nativeRow.TagUlong;
                row.tagText = printableTag(nativeRow.Tag);
                row.identity = row.virtualAddress ^ (static_cast<std::uint64_t>(row.tag) << 32);
                snapshot.bigPool->push_back(std::move(row));
            }
            std::sort(snapshot.bigPool->begin(), snapshot.bigPool->end(), [](const BigPoolRow& left, const BigPoolRow& right) {
                return left.sizeBytes > right.sizeBytes;
                });
        }
        else
        {
            snapshot.pendingErrors.push_back({ QStringLiteral("Big Pool query failed (%1)"), statusHex(bigPoolStatus) });
        }
    }

    snapshot.inUseBytes = snapshot.totalPhysicalBytes >= snapshot.availableBytes
        ? snapshot.totalPhysicalBytes - snapshot.availableBytes
        : 0;
    const std::uint64_t modifiedInUseBytes = snapshot.modifiedBytes + snapshot.modifiedNoWriteBytes;
    const std::array<std::uint64_t, 6> additiveComponents{
        snapshot.processPrivateResidentBytes,
        snapshot.nonPagedPoolBytes,
        snapshot.pagedPoolResidentBytes,
        snapshot.systemCodeResidentBytes,
        snapshot.systemDriverResidentBytes,
        modifiedInUseBytes
    };
    for (const std::uint64_t component : additiveComponents)
    {
        if (snapshot.identifiedResidentLowerBoundBytes >
            (std::numeric_limits<std::uint64_t>::max)() - component)
        {
            snapshot.identifiedResidentLowerBoundBytes = (std::numeric_limits<std::uint64_t>::max)();
            break;
        }
        snapshot.identifiedResidentLowerBoundBytes += component;
    }
    snapshot.reserved = ksword::memoryaudit::reservedEstimate(snapshot.installedPhysicalValid,
        snapshot.usablePhysicalValid, snapshot.installedPhysicalBytes, snapshot.totalPhysicalBytes);
    if (!snapshot.commit.valid)
    {
        snapshot.pendingErrors.push_back({QStringLiteral("System commit is unavailable (%1)"),
            QStringLiteral("Win32 %1 / NT %2").arg(snapshot.commit.publicStatus)
                .arg(snapshot.commit.nativeAttempted ? statusHex(snapshot.commit.nativeStatus) : QStringLiteral("not-queried"))});
    }

    snapshot.unattributedResidentBytes = snapshot.inUseBytes > snapshot.identifiedResidentLowerBoundBytes
        ? snapshot.inUseBytes - snapshot.identifiedResidentLowerBoundBytes
        : 0;
    snapshot.overAccountedResidentBytes = snapshot.identifiedResidentLowerBoundBytes > snapshot.inUseBytes
        ? snapshot.identifiedResidentLowerBoundBytes - snapshot.inUseBytes
        : 0;
    return snapshot;
}

QString SystemMemoryAuditPage::formatBytes(const std::uint64_t bytes)
{
    constexpr double kib = 1024.0;
    constexpr double mib = kib * 1024.0;
    constexpr double gib = mib * 1024.0;
    const double value = static_cast<double>(bytes);
    if (value >= gib)
    {
        return QStringLiteral("%1 GiB").arg(value / gib, 0, 'f', 2);
    }
    if (value >= mib)
    {
        return QStringLiteral("%1 MiB").arg(value / mib, 0, 'f', 2);
    }
    if (value >= kib)
    {
        return QStringLiteral("%1 KiB").arg(value / kib, 0, 'f', 2);
    }
    return QStringLiteral("%1 B").arg(bytes);
}

QString SystemMemoryAuditPage::formatDelta(const std::int64_t bytes)
{
    if (bytes == 0)
    {
        return QStringLiteral("0 B");
    }
    const bool positive = bytes > 0;
    const std::uint64_t magnitude = positive
        ? static_cast<std::uint64_t>(bytes)
        : static_cast<std::uint64_t>(-(bytes + 1)) + 1ULL;
    return QStringLiteral("%1%2").arg(positive ? QStringLiteral("+") : QStringLiteral("-"), formatBytes(magnitude));
}

QString SystemMemoryAuditPage::formatPercent(const std::uint64_t bytes, const std::uint64_t totalBytes)
{
    if (totalBytes == 0)
    {
        return QStringLiteral("-");
    }
    return QStringLiteral("%1%").arg(
        static_cast<double>(bytes) * 100.0 / static_cast<double>(totalBytes), 0, 'f', 2);
}

namespace {
constexpr int AuditIdentityRole = Qt::UserRole + 1902;
int compareAuditValues(const QVariant& left, const QVariant& right)
{
    if (left.metaType().id() == QMetaType::QString) { return QString::compare(left.toString(), right.toString(), Qt::CaseInsensitive); }
    if (left.metaType().id() == QMetaType::LongLong) { const auto a = left.toLongLong(), b = right.toLongLong(); return a < b ? -1 : a > b ? 1 : 0; }
    const auto a = left.toULongLong(), b = right.toULongLong(); return a < b ? -1 : a > b ? 1 : 0;
}
}

QString SystemMemoryAuditPage::projectionRowKey(const ProjectionData& data, const std::size_t index)
{
    switch (data.kind) {
    case AuditKind::Processes: return QString::number((*data.snapshot.processes)[index].identity);
    case AuditKind::PoolTags: return QString::number((*data.snapshot.poolTags)[index].tag);
    case AuditKind::BigPool: return QString::number((*data.snapshot.bigPool)[index].identity);
    default: {
        const auto& row = (*data.residency.rows)[index];
        return QString::number(row.pid) + QLatin1Char(':') + QString::number(static_cast<int>(row.kind)) + QLatin1Char(':')
            + QString::number(row.backingPath.size()) + QLatin1Char(':') + row.backingPath + QLatin1Char(':')
            + QString::number(row.backingPathStatus) + QLatin1Char(':') + QString::number(row.backingRegionStatus)
            + QLatin1Char(':') + QString::number(row.backingRegionKnown);
    }
    }
}

QVariant SystemMemoryAuditPage::projectionCell(const ProjectionData& data, const std::size_t index, const int column, const int role)
{
    if (role == AuditIdentityRole) { return projectionRowKey(data, index); }
    const auto label = [&](const char* source) { return data.language.packedSourceText(QString::fromUtf8(source)); };
    std::int64_t delta = 0;
    const int deltaColumn = data.kind == AuditKind::Processes ? 10 : 4;
    if (data.kind == AuditKind::Processes) { delta = (*data.snapshot.processes)[index].privateResidentDeltaBytes; }
    else if (data.kind == AuditKind::PoolTags) { delta = (*data.snapshot.poolTags)[index].totalDeltaBytes; }
    else if (data.kind == AuditKind::BigPool) { delta = (*data.snapshot.bigPool)[index].sizeDeltaBytes; }
    if (role == Qt::ForegroundRole) {
        if (data.kind != AuditKind::UserResidency && column == deltaColumn && delta) {
            return QBrush(delta > 0 ? KswordTheme::ErrorColor() : KswordTheme::SuccessColor());
        }
        return {};
    }
    if (role != Qt::DisplayRole && role != Qt::ToolTipRole && role != ks::ui::NumericSortRole) { return {}; }
    const bool numeric = role == ks::ui::NumericSortRole;
    const auto bytes = [&](std::uint64_t value) -> QVariant { return numeric ? QVariant::fromValue<qulonglong>(value) : QVariant(formatBytes(value)); };
    const auto count = [&](std::uint64_t value) -> QVariant { return numeric ? QVariant::fromValue<qulonglong>(value) : QVariant(QString::number(value)); };
    const auto signedBytes = [&](std::int64_t value) -> QVariant { return numeric ? QVariant::fromValue<qlonglong>(value) : QVariant(formatDelta(value)); };
    if (data.kind == AuditKind::Processes) {
        const auto& row = (*data.snapshot.processes)[index];
        switch (column) {
        case 0: return row.name;
        case 1: return count(row.pid);
        case 2: return count(row.sessionId);
        case 3: return bytes(row.privateResidentBytes);
        case 4: return bytes(row.workingSetBytes);
        case 5: return bytes(row.sharedResidentReferenceBytes);
        case 6: return bytes(row.privateCommitBytes);
        case 7: return bytes(row.pagedPoolQuotaBytes);
        case 8: return bytes(row.nonPagedPoolQuotaBytes);
        case 9: return count(row.hardFaultCount);
        case 10: return signedBytes(row.privateResidentDeltaBytes);
        default: return {};
        }
    }
    if (data.kind == AuditKind::PoolTags) {
        const auto& row = (*data.snapshot.poolTags)[index];
        const auto metadata = data.metadata.value(row.tag);
        switch (column) {
        case 0: return row.tagText;
        case 1: return bytes(row.pagedBytes);
        case 2: return bytes(row.nonPagedBytes);
        case 3: return bytes(row.pagedBytes + row.nonPagedBytes);
        case 4: return signedBytes(row.totalDeltaBytes);
        case 5: return count(row.pagedOutstanding);
        case 6: return count(row.nonPagedOutstanding);
        case 7: return metadata.source;
        case 8: return metadata.description;
        default: return {};
        }
    }
    if (data.kind == AuditKind::BigPool) {
        const auto& row = (*data.snapshot.bigPool)[index];
        const auto metadata = data.metadata.value(row.tag);
        switch (column) {
        case 0: return row.tagText;
        case 1: return numeric ? QVariant::fromValue<qulonglong>(row.virtualAddress) : QVariant(QStringLiteral("0x%1").arg(row.virtualAddress, 16, 16, QLatin1Char('0')).toUpper());
        case 2: return bytes(row.sizeBytes);
        case 3: return row.nonPaged ? label("Nonpaged") : label("Paged");
        case 4: return signedBytes(row.sizeDeltaBytes);
        case 5: return metadata.source;
        case 6: return metadata.description;
        default: return {};
        }
    }
    const auto& row = (*data.residency.rows)[index];
    const char* category = "Unknown mapping";
    switch (row.kind) {
    case UserMemoryKind::Private: category = "Private anonymous"; break;
    case UserMemoryKind::PrivateMappedCopy: category = "Private mapped copy"; break;
    case UserMemoryKind::Image: category = "Mapped image"; break;
    case UserMemoryKind::MappedFile: category = "Mapped file"; break;
    case UserMemoryKind::PagefileSection: category = "Pagefile-backed section"; break;
    case UserMemoryKind::MappedBackingUnknown: category = "Mapped backing unresolved"; break;
    default: break;
    }
    if (role == Qt::ToolTipRole && column == 3 && row.backingPathQueryAttempted) {
        return label("GetMappedFileNameW Win32: %1 | MemoryRegionInfo Win32: %2 | region metadata available: %3")
            .arg(row.backingPathStatus).arg(row.backingRegionStatus).arg(row.backingRegionKnown ? label("Yes") : label("No"));
    }
    switch (column) {
    case 0: return row.processName;
    case 1: return count(row.pid);
    case 2: return label(category);
    case 3:
        if (row.backingPath == QStringLiteral(":private")) { return label("Private allocation owned by this process"); }
        if (row.backingPath == QStringLiteral(":mapped-unknown")) { return label("Mapped backing unresolved; path query Win32 status: %1").arg(row.backingPathStatus); }
        if (row.backingPath == QStringLiteral(":pagefile")) { return label("Pagefile backing observed with MemoryRegionInfo.MappedPageFile"); }
        if (row.backingPath == QStringLiteral(":file-path-unavailable")) { return label("Data-file backing observed; path query Win32 status: %1").arg(row.backingPathStatus); }
        if (row.backingPath == QStringLiteral(":image")) { return label("Mapped image path unavailable"); }
        if (row.backingPath == QStringLiteral(":unknown")) { return label("Virtual region type unavailable"); }
        return row.backingPath;
    case 4: return bytes(row.residentReferenceBytes);
    case 5: return bytes(row.privateResidentBytes);
    case 6: return bytes(row.shareableResidentBytes);
    case 7: return bytes(row.sharedResidentReferenceBytes);
    case 8: return bytes(row.proportionalResidentBytes);
    default: return {};
    }
}

QString SystemMemoryAuditPage::projectionSearch(const ProjectionData& data, const std::size_t row)
{
    const auto text = [&](int column) { return projectionCell(data, row, column, Qt::DisplayRole).toString(); };
    switch (data.kind) {
    case AuditKind::Processes: return QStringLiteral("%1 %2 %3").arg(text(0), text(1), text(2));
    case AuditKind::PoolTags: return QStringLiteral("%1 %2 %3").arg(text(0), text(7), text(8));
    case AuditKind::BigPool: return QStringLiteral("%1 %2 %3 %4 %5").arg(text(0), text(1), text(3), text(5), text(6));
    default: return QStringLiteral("%1 %2 %3 %4").arg(text(0), text(1), text(2), text(3));
    }
}

void SystemMemoryAuditPage::buildProjection(const std::shared_ptr<ProjectionJob>& job)
{
    try {
        auto& data = *job->result;
        const auto count = data.kind == AuditKind::Processes ? data.snapshot.processes->size()
            : data.kind == AuditKind::PoolTags ? data.snapshot.poolTags->size()
            : data.kind == AuditKind::BigPool ? data.snapshot.bigPool->size() : data.residency.rows->size();
        struct SortRow { std::size_t source; QVariant key; };
        std::vector<SortRow> sorted;
        sorted.reserve(count);
        std::size_t selected = std::numeric_limits<std::size_t>::max();
        for (std::size_t row = 0; row < count; ++row) {
            if ((row & 63U) == 0 && job->cancel.load()) { job->done.store(true); return; }
            if (!job->filter.isEmpty() && !projectionSearch(data, row).contains(job->filter, Qt::CaseInsensitive)) { continue; }
            if (!job->selectedKey.isEmpty() && projectionRowKey(data, row) == job->selectedKey) { selected = row; }
            sorted.push_back({row, projectionCell(data, row, job->sortColumn, ks::ui::NumericSortRole)});
        }
        std::stable_sort(sorted.begin(), sorted.end(), [&](const auto& left, const auto& right) {
            const int comparison = compareAuditValues(left.key, right.key);
            return comparison == 0 ? left.source < right.source : job->sortOrder == Qt::AscendingOrder ? comparison < 0 : comparison > 0;
        });
        if (!job->cancel.load()) {
            data.rows->reserve(sorted.size());
            for (const auto& row : sorted) {
                if (row.source == selected) { data.selectedRow = static_cast<int>(data.rows->size()); }
                data.rows->push_back(row.source);
            }
        }
    } catch (...) { job->failed = true; }
    job->done.store(true);
}

void SystemMemoryAuditPage::invalidateTableProjections()
{
    for (auto& version : m_projectionVersions) { ++version; }
    for (auto& ready : m_readyProjections) { ready.reset(); }
    if (m_projectionJob) { m_projectionJob->cancel.store(true); }
    const int index = m_detailTabs ? m_detailTabs->currentIndex() - 1 : -1;
    if (index >= 0 && index < 4 && isVisible()) {
        const std::array<AuditTableView*, 4> tables{m_userResidencyTable, m_processTable, m_poolTagTable, m_bigPoolTable};
        tables[index]->setEnabled(false);
        m_statusLabel->setText(localized("Updating memory table..."));
    }
    updateMetricAreaAction();
    for (int kind = 0; kind < 4; ++kind) {
        if (m_metricAreaWindows[kind]) m_metricAreaWindows[kind]->updateState(
            localized("Memory table is updating; this view retains the last committed results."));
    }
}

void SystemMemoryAuditPage::updateMetricAreaAction()
{
    if (!m_metricAreaButton || !m_detailTabs) return;
    if (m_detailTabs->currentIndex() == 0) {
        m_metricAreaButton->setEnabled(usePfnOverview() ? m_pfnPage && m_pfnPage->hasMetricAreaData() : m_hasSnapshot);
        m_metricAreaButton->setToolTip(usePfnOverview()
            ? localized("Visualize in-use physical pages by process from the current PFN ledger.")
            : localized("Open the process memory table from the current snapshot and visualize it without collecting again."));
        return;
    }
    if (m_hyperVPage && m_detailTabs->currentWidget() == m_hyperVPage) {
        m_metricAreaButton->setEnabled(m_hyperVPage->hasMetricAreaData());
        m_metricAreaButton->setToolTip(localized("Visualize the current quantitative Hyper-V table without collecting again."));
        return;
    }
    if (m_pfnPage && m_detailTabs->currentWidget() == m_pfnPage) {
        m_metricAreaButton->setEnabled(m_pfnPage->hasMetricAreaData());
        m_metricAreaButton->setToolTip(m_pfnPage->hasMetricAreaData()
            ? localized("Visualize the published PFN ledger without starting another scan.")
            : localized("Run PFN deep attribution before opening its area view."));
        return;
    }
    const int kind = m_detailTabs->currentIndex() - 1;
    const bool supported = kind >= 0 && kind < 4;
    const bool ready = supported && m_metricAreaProjections[kind]
        && m_publishedVersions[kind] == m_projectionVersions[kind];
    m_metricAreaButton->setEnabled(ready);
    m_metricAreaButton->setToolTip(!supported
        ? localized("Select user residency, processes, pool tags, or Big Pool to visualize its committed table.")
        : !ready ? localized("Wait for the current memory table to finish loading before opening its area view.")
        : localized("Visualize the current filtered memory table without starting another scan."));
}

void SystemMemoryAuditPage::openMetricAreaView()
{
    if (m_detailTabs->currentIndex() == 0) {
        if (usePfnOverview() && m_pfnPage && m_pfnPage->hasMetricAreaData()) { m_pfnPage->openMetricAreaView(0); return; }
        if (!m_hasSnapshot) return;
        m_openMetricAreaWhenPublished = 1;
        m_detailTabs->setCurrentIndex(2);
        rebuildCurrentDetailView();
        if (m_openMetricAreaWhenPublished == 1 && m_metricAreaProjections[1] && m_publishedVersions[1] == m_projectionVersions[1]) {
            m_openMetricAreaWhenPublished = -1; openMetricAreaView();
        }
        return;
    }
    if (m_hyperVPage && m_detailTabs->currentWidget() == m_hyperVPage) { m_hyperVPage->openMetricAreaView(); return; }
    if (m_pfnPage && m_detailTabs->currentWidget() == m_pfnPage) { m_pfnPage->openMetricAreaView(); return; }
    const int kind = m_detailTabs->currentIndex() - 1;
    if (kind < 0 || kind >= 4 || !m_metricAreaProjections[kind]
        || m_publishedVersions[kind] != m_projectionVersions[kind]) return;
    if (!m_metricAreaWindows[kind]) {
        auto* window = new ks::ui::MetricAreaWindow(this);
        window->setObjectName(QStringLiteral("memory_audit_metric_area_") + QString::number(kind));
        m_metricAreaWindows[kind] = window;
        m_metricAreaPresentedModes[kind] = -1;
        const QPointer<SystemMemoryAuditPage> owner(this);
        window->modeChanged = [owner, kind](int) {
            if (owner) owner->refreshMetricAreaView(static_cast<AuditKind>(kind));
        };
        window->appearanceChanged = [owner, kind] {
            if (owner) owner->refreshMetricAreaView(static_cast<AuditKind>(kind));
        };
    }
    refreshMetricAreaView(static_cast<AuditKind>(kind));
    if (const auto window = m_metricAreaWindows[kind]) {
        window->show(); window->raise(); window->activateWindow();
    }
}

void SystemMemoryAuditPage::refreshMetricAreaView(const AuditKind kind)
{
    const auto slot = static_cast<std::size_t>(kind);
    const auto window = m_metricAreaWindows[slot];
    const auto projection = m_metricAreaProjections[slot];
    if (!window || !projection) return;
    const std::array<AuditTableView*, 4> tables{m_userResidencyTable, m_processTable, m_poolTagTable, m_bigPoolTable};
    auto* const table = tables[slot];
    // Every choice is an explicit quantitative column; addresses, PID/session,
    // names and status codes are never interpreted as areas.
    static const std::array<std::vector<int>, 4> columns{{
        {5, 8, 4, 6, 7}, {3, 4, 5, 6, 7, 8, 9, 10}, {3, 1, 2, 5, 6, 4}, {2, 4}
    }};
    QStringList labels;
    for (const int column : columns[slot]) labels.append(table->model()->headerData(column, Qt::Horizontal).toString());
    const int mode = qBound(0, window->currentMode(), static_cast<int>(columns[slot].size()) - 1);
    window->setModes(labels, mode);
    const int column = columns[slot][static_cast<std::size_t>(mode)];
    window->setSubject(localized("All memory entries"), localized("Memory source"),
        kind == AuditKind::PoolTags ? QString() : kind == AuditKind::BigPool ? localized("Virtual address") : QStringLiteral("PID"),
        localized("Click a block to inspect its memory-table row; double-click zooms in. Areas use the selected metric; zero values do not receive artificial area."));
    // Palette/show notifications only repaint the existing immutable view.
    // Reformat all rows only for a new committed source, metric or language.
    if (!m_metricAreaJobs[slot] && m_metricAreaPresentedProjections[slot].lock() == projection && m_metricAreaPresentedModes[slot] == mode
        && m_metricAreaPresentedLabels[slot] == labels) return;
    if (m_metricAreaJobs[slot]) {
        const auto& pending = m_metricAreaJobs[slot];
        if (pending->projection == projection && pending->mode == mode && pending->labels == labels) return;
        pending->cancel.store(true);
    }
    const auto job = valueStorage<MetricAreaJob>();
    job->kind = kind; job->projection = projection; job->mode = mode; job->column = column; job->labels = labels;
    m_metricAreaJobs[slot] = job;
    window->updateState(localized("Preparing the area view from the last committed memory table..."));
    m_jobsTimer->start();
    try { std::thread([job] { buildMetricAreaView(job); }).detach(); }
    catch (...) { job->failed = true; job->done.store(true); }
}

void SystemMemoryAuditPage::buildMetricAreaView(const std::shared_ptr<MetricAreaJob>& job)
{
    try {
    const auto& projection = job->projection;
    const auto kind = job->kind;
    const auto column = job->column;
    job->nodes.reserve(projection->rows->size());
    for (const auto row : *projection->rows) {
        if (job->cancel.load()) break;
        ks::ui::MetricAreaNode node;
        node.key = projectionRowKey(*projection, row);
        node.name = projectionCell(*projection, row, 0, Qt::DisplayRole).toString();
        node.identity = kind == AuditKind::PoolTags ? node.name
            : projectionCell(*projection, row, 1, Qt::DisplayRole).toString();
        const auto value = projectionCell(*projection, row, column, ks::ui::NumericSortRole);
        const double weight = value.toDouble();
        node.known = value.isValid() && std::isfinite(weight);
        node.weight = node.known ? std::fabs(weight) : 0;
        node.value = projectionCell(*projection, row, column, Qt::DisplayRole).toString();
        node.tooltip = projectionSearch(*projection, row) + QLatin1Char('\n') + job->labels[job->mode] + QStringLiteral(": ") + node.value;
        if (kind == AuditKind::UserResidency) {
            node.name += QStringLiteral(" · ") + projectionCell(*projection, row, 2, Qt::DisplayRole).toString();
            node.name += QStringLiteral(" · ") + projectionCell(*projection, row, 3, Qt::DisplayRole).toString();
        }
        // The source rows are disjoint records, with no synthetic subtotal
        // leaves. Shared references remain references, never unique bytes.
        job->nodes.push_back(std::move(node));
    }
    } catch (...) { job->failed = true; }
    job->done.store(true);
}

void SystemMemoryAuditPage::publishMetricAreaView(const std::shared_ptr<MetricAreaJob>& job)
{
    const auto kind = job->kind;
    const auto slot = static_cast<std::size_t>(kind);
    const auto window = m_metricAreaWindows[slot];
    const auto projection = job->projection;
    if (!window || job->cancel.load() || m_metricAreaProjections[slot] != projection || window->currentMode() != job->mode) return;
    if (job->failed) {
        window->updateState(localized("Memory area view preparation failed; the previous view is retained. Change the metric or refresh the table to retry."));
        return;
    }
    const auto column = job->column;
    const QString sampledAt = kind == AuditKind::UserResidency ? projection->residency.sampledAt : projection->snapshot.sampledAt;
    QString state = localized("Committed memory-table results | Snapshot %1 | Entries %2")
        .arg(sampledAt).arg(projection->rows->size());
    if (kind == AuditKind::UserResidency) {
        state += QStringLiteral("\n") + localized("Resident references and proportional estimates are not unique physical memory. Accessible processes: %1; inaccessible: %2; scan warnings: %3.")
            .arg(projection->residency.accessibleProcessCount).arg(projection->residency.inaccessibleProcessCount).arg(projection->residency.errors.size());
    } else if (kind == AuditKind::PoolTags) {
        state += QStringLiteral("\n") + localized("Paged-pool bytes are commitments; outstanding allocations are counts, not resident bytes.");
    } else if (kind == AuditKind::Processes) {
        state += QStringLiteral("\n") + localized("Working sets may share pages; commit and quota metrics are not unique resident memory.");
    }
    if ((kind == AuditKind::Processes && column == 10) || (kind == AuditKind::PoolTags && column == 4)
        || (kind == AuditKind::BigPool && column == 4)) state += QStringLiteral("\n")
            + localized("Area uses the absolute change; the displayed value retains its sign.");
    if (m_publishedVersions[slot] != m_projectionVersions[slot]) state += QStringLiteral("\n")
        + localized("Memory table is updating; this view retains the last committed results.");
    const QPointer<SystemMemoryAuditPage> owner(this);
    window->setPresentation(job->labels[job->mode], state, std::move(job->nodes));
    if (!owner || !window) return;
    m_metricAreaPresentedProjections[slot] = projection;
    m_metricAreaPresentedModes[slot] = job->mode;
    m_metricAreaPresentedLabels[slot] = job->labels;
    window->itemActivated = [owner, projection, kind](const QString& key) {
        if (!owner) return;
        const auto index = static_cast<std::size_t>(kind);
        if (owner->m_metricAreaProjections[index] != projection || owner->m_publishedVersions[index] != owner->m_projectionVersions[index]) return;
        const std::array<AuditTableView*, 4> views{owner->m_userResidencyTable, owner->m_processTable, owner->m_poolTagTable, owner->m_bigPoolTable};
        for (std::size_t row = 0; row < projection->rows->size(); ++row) {
            if (projectionRowKey(*projection, (*projection->rows)[row]) != key) continue;
            owner->m_detailTabs->setCurrentIndex(static_cast<int>(index) + 1);
            if (!owner) return;
            const auto target = views[index]->model()->index(static_cast<int>(row), 0);
            views[index]->setCurrentIndex(target); views[index]->scrollTo(target); owner->updateDetails();
            return;
        }
    };
}

void SystemMemoryAuditPage::requestTableProjection(const AuditKind kind)
{
    if (!isVisible() || (m_projectionDebounce && m_projectionDebounce->isActive())) { return; }
    const auto index = static_cast<std::size_t>(kind);
    const auto version = m_projectionVersions[index];
    if (m_publishedVersions[index] == version || m_failedVersions[index] == version) { return; }
    if (m_readyProjections[index]) {
        auto ready = std::move(m_readyProjections[index]);
        publishTableProjection(ready, version); return;
    }
    if (m_projectionJob) {
        if (m_projectionJob->kind != kind || m_projectionJob->version != version) { m_projectionJob->cancel.store(true); }
        return;
    }
    const std::array<AuditTableView*, 4> tables{m_userResidencyTable, m_processTable, m_poolTagTable, m_bigPoolTable};
    auto* table = tables[index];
    const auto job = std::make_shared<ProjectionJob>(); job->kind = kind; job->version = version;
    job->sortColumn = m_sortColumns[index]; job->sortOrder = m_sortOrders[index]; job->filter = m_filterEdit->text().trimmed();
    job->selectedKey = table->currentIndex().data(AuditIdentityRole).toString();
    job->result = valueStorage<ProjectionData>();
    job->result->kind = kind; job->result->snapshot = m_snapshot; job->result->residency = m_userResidencyScan;
    job->result->metadata = m_poolTagMetadata; job->result->language = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
    m_projectionJob = job; m_jobsTimer->start();
    table->setEnabled(false); m_statusLabel->setText(localized("Updating memory table..."));
    try { std::thread([job] { buildProjection(job); }).detach(); }
    catch (...) { job->failed = true; job->done.store(true); }
}

void SystemMemoryAuditPage::publishTableProjection(const std::shared_ptr<ProjectionData>& projection, const std::uint64_t version)
{
    const auto kind = static_cast<std::size_t>(projection->kind);
    if (!isVisible() || m_detailTabs->currentIndex() != static_cast<int>(kind) + 1 || m_projectionVersions[kind] != version) { return; }
    const std::array<AuditTableView*, 4> tables{m_userResidencyTable, m_processTable, m_poolTagTable, m_bigPoolTable};
    const QPointer<SystemMemoryAuditPage> owner(this);
    const QPointer<AuditTableView> table(tables[kind]);
    const int scroll = table->verticalScrollBar()->value();
    table->auditModel->publish(projection->rows, [projection](std::size_t row, int column, int role) { return projectionCell(*projection, row, column, role); });
    if (!owner || !table || m_projectionVersions[kind] != version || m_detailTabs->currentIndex() != static_cast<int>(kind) + 1) { return; }
    m_publishedVersions[kind] = version;
    table->setEnabled(true);
    if (!owner || !table || m_projectionVersions[kind] != version) { return; }
    if (projection->selectedRow >= 0) { table->setCurrentIndex(table->auditModel->index(projection->selectedRow, 0)); }
    if (!owner || !table || m_projectionVersions[kind] != version) { return; }
    table->verticalScrollBar()->setValue(scroll);
    if (owner) {
        m_metricAreaProjections[kind] = projection;
        refreshMetricAreaView(projection->kind);
        updateMetricAreaAction(); updateStatus();
        if (m_openMetricAreaWhenPublished == static_cast<int>(kind)) {
            m_openMetricAreaWhenPublished = -1; openMetricAreaView();
        }
    }
}

void SystemMemoryAuditPage::pollJobs()
{
    const QPointer<SystemMemoryAuditPage> owner(this);
    for (auto& pending : m_metricAreaJobs) {
        if (!pending || !pending->done.load()) continue;
        const auto ready = std::move(pending);
        publishMetricAreaView(ready);
        if (!owner) return;
    }
    if (m_snapshotJob && m_snapshotJob->done.load()) {
        const auto job = std::move(m_snapshotJob);
        if (job->failed || !job->result) {
            m_refreshing = false; m_refreshButton->setEnabled(true);
            m_statusLabel->setText(localized("System memory evidence worker failed"));
        } else { applySnapshot(std::move(*job->result), job->ticket); }
        if (!owner) { return; }
    }
    if (m_residencyJob && m_residencyJob->done.load()) {
        const auto job = std::move(m_residencyJob);
        if (job->failed || !job->result) {
            m_userResidencyScanInProgress.store(false); m_userResidencyScanButton->setEnabled(true);
            m_userResidencyScanButton->setText(localized("Deep scan user-mode residency"));
            m_statusLabel->setText(localized("User-mode residency worker failed"));
        } else { applyUserResidencyScan(std::move(*job->result), job->ticket); }
        if (!owner) { return; }
    }
    if (m_projectionJob && m_projectionJob->done.load()) {
        const auto job = std::move(m_projectionJob);
        const auto kind = static_cast<std::size_t>(job->kind);
        if (!job->cancel.load() && job->version == m_projectionVersions[kind]) {
            if (job->failed) {
                if (m_openMetricAreaWhenPublished == static_cast<int>(kind)) m_openMetricAreaWhenPublished = -1;
                m_failedVersions[kind] = job->version;
                m_statusLabel->setText(localized("Memory table projection failed"));
                const std::array<AuditTableView*, 4> tables{m_userResidencyTable, m_processTable, m_poolTagTable, m_bigPoolTable};
                tables[kind]->setEnabled(true);
            } else { m_readyProjections[kind] = job->result; }
        }
    }
    if (owner && isVisible()) { rebuildCurrentDetailView(); }
    const bool areaBusy = std::any_of(m_metricAreaJobs.cbegin(), m_metricAreaJobs.cend(), [](const auto& job) { return bool(job); });
    if (owner && !m_snapshotJob && !m_residencyJob && !m_projectionJob && !areaBusy) { m_jobsTimer->stop(); }
}
