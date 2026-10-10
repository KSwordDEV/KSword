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
#include "../UI/PageControlStyle.h"
#include "../ksword/log/log.h"
#include "MemoryAccessBackend.h"

#include <QAbstractItemView>
#include <QHBoxLayout>
#include <QCoreApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFrame>
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
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#pragma comment(lib, "Psapi.lib")

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

    void configureTable(QTableWidget* table, const QStringList& headers)
    {
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setStretchLastSection(true);
    }

    QTableWidgetItem* textItem(const QString& text)
    {
        return new QTableWidgetItem(text);
    }

    // numericItem 作用：
    // - 生成一格“显示文本随便写、排序按真实数值”的单元格，供地址/大小/页数/计数列使用；
    // - 入参 text 为界面文本（十六进制、KiB/MiB 均可），value 为参与排序的无符号真实值；
    // - 返回新建的单元格，所有权随 setItem 交给表格。
    QTableWidgetItem* numericItem(const QString& text, const qulonglong value)
    {
        return new ks::ui::NumericTableItem(text, value);
    }

    // signedNumericItem 作用：
    // - numericItem 的有符号版本，专供可正可负的增量列（Delta）使用；
    // - 入参 text 为带正负号的显示文本，value 为参与排序的有符号真实值；
    // - 返回新建的单元格；不能改用无符号重载，否则负增量会被排到最大端。
    QTableWidgetItem* signedNumericItem(const QString& text, const qlonglong value)
    {
        return new ks::ui::NumericTableItem(text, value);
    }

    void applyDeltaColor(QTableWidgetItem* item, const std::int64_t delta)
    {
        if (item == nullptr || delta == 0)
        {
            return;
        }
        item->setForeground(delta > 0
            ? KswordTheme::ErrorColor()
            : KswordTheme::SuccessColor());
    }
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
            m_userResidencyTableDirty = true;
            m_processTableDirty = true;
            m_poolTagTableDirty = true;
            m_bigPoolTableDirty = true;
            scheduleCurrentDetailViewRebuild();
        }
        return;
    }

    if (event->type() != QEvent::LanguageChange)
    {
        return;
    }

    retranslateUi();
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

    // 快照与深度扫描属于全页操作，以轻底面区分下面的摘要与分项数据。
    QWidget* const snapshotToolbar = new QWidget(this);
    ks::ui::StylePrimaryToolbar(snapshotToolbar);
    QHBoxLayout* const controls = new QHBoxLayout(snapshotToolbar);
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
    controls->addWidget(m_autoRefreshCheck);
    controls->addWidget(m_intervalSpin);
    controls->addWidget(m_filterEdit, 1);
    ks::ui::NormalizeToolbarRow(controls);
    ks::ui::ApplyFlatButtonTheme(m_refreshButton, ks::ui::FlatButtonTone::Accent);
    ks::ui::ApplyFlatButtonTheme(m_userResidencyScanButton, ks::ui::FlatButtonTone::Neutral);
    ks::ui::ApplyFlatButtonTheme(m_pfnScanButton, ks::ui::FlatButtonTone::Neutral);
    rootLayout->addWidget(snapshotToolbar);

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
    rootLayout->addLayout(summaryLayout);

    m_detailTabs = new QTabWidget(this);
    ks::ui::StylePageTabs(m_detailTabs);

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
    m_userResidencyTable = new ks::ui::VisibleTableWidget(userResidencyPage);
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
    m_processTable = new ks::ui::VisibleTableWidget(processPage);
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
    m_poolTagTable = new ks::ui::VisibleTableWidget(poolPage);
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
    m_bigPoolTable = new ks::ui::VisibleTableWidget(bigPoolPage);
    ks::ui::SetTableActionBarMode(m_bigPoolTable, ks::ui::TableActionBarMode::Full);
    configureTable(m_bigPoolTable, QStringList{
        localized("Tag"), localized("Virtual address"), localized("Size"),
        localized("Pool type"), localized("Delta"), localized("Source"), localized("Description")
    });
    bigPoolLayout->addWidget(m_bigPoolTable);

    m_detailTabs->addTab(overviewPage, localized("Physical distribution"));
    m_detailTabs->addTab(userResidencyPage, localized("User-mode residency"));
    m_detailTabs->addTab(processPage, localized("Kernel process snapshot"));
    m_detailTabs->addTab(poolPage, localized("Pool tags"));
    m_detailTabs->addTab(bigPoolPage, localized("Big Pool allocations"));
    m_pfnPage = new PhysicalPageAttributionPage(m_detailTabs);
    m_pfnPage->openModuleDetails = [this](const QString& path) {
        const auto handler = openModuleDetails;
        if (handler) { handler(path); }
    };
    m_detailTabs->addTab(m_pfnPage, localized("Physical page attribution"));
    m_hyperVPage = new HyperVMemoryPage(m_detailTabs);
    m_detailTabs->addTab(m_hyperVPage, localized("Hyper-V / host memory"));
    m_pfnPage->snapshotReady = [this](const std::shared_ptr<ksword::pfn::Scan>& scan) {
        m_hyperVPage->setPfnContext(scan);
        applyPfnOverview(scan);
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
    rootLayout->addWidget(detailSplitter, 1);

    // DDMA 复核条：本页统计的是"标准通道看到的物理内存"，被 SLAT 重定向的页在
    // 这里只会表现为一段说不清归属的余量。用 DDMA 对同一页再读一次，是唯一能在
    // 本页内直接验证"这段内存是不是被藏起来了"的手段。
    {
        QWidget* const ddmaRow = new QWidget(this);
        QHBoxLayout* const ddmaLayout = new QHBoxLayout(ddmaRow);
        ddmaLayout->setContentsMargins(0, 0, 0, 0);
        ddmaLayout->setSpacing(6);

        m_ddmaCrossCheckAddressEdit = new QLineEdit(ddmaRow);
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
    connect(m_overviewSource, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        m_overviewDirty = true;
        updateSummaryTiles();
        scheduleCurrentDetailViewRebuild();
        updateDetails();
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
        m_userResidencyTableDirty = true;
        m_processTableDirty = true;
        m_poolTagTableDirty = true;
        m_bigPoolTableDirty = true;
        scheduleCurrentDetailViewRebuild();
        updateStatus();
        });
    connect(m_autoRefreshTimer, &QTimer::timeout, this, [this]() {
        if (isVisible() && m_detailTabs->currentWidget() != m_pfnPage && m_detailTabs->currentWidget() != m_hyperVPage)
        {
            refreshSnapshot();
        }
        });
    connect(m_detailTabs, &QTabWidget::currentChanged, this, [this]() {
        const bool showSnapshot = m_detailTabs->currentWidget() != m_pfnPage && m_detailTabs->currentWidget() != m_hyperVPage;
        m_detailText->setVisible(showSnapshot);
        m_statusLabel->setVisible(showSnapshot);
        for (QLabel* value : { m_installedLabel, m_totalLabel, m_inUseLabel, m_availableLabel, m_commitLabel, m_unattributedLabel })
        {
            value->parentWidget()->setVisible(showSnapshot);
        }
        scheduleCurrentDetailViewRebuild();
        updateSummaryTiles();
        updateDetails();
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
    m_ddmaCrossCheckButton->setEnabled(usable);
    m_ddmaCrossCheckButton->setToolTip(usable
        ? localized("Read the same physical page through both backends and compare byte by byte.")
        : reason);
}

void SystemMemoryAuditPage::runDdmaCrossCheck()
{
    if (m_ddmaCrossCheckResultLabel == nullptr || m_ddmaCrossCheckAddressEdit == nullptr)
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
    const ksword::memory_backend::DdmaSession& session = m_ddmaSessionProvider();

    const ksword::memory_backend::AccessOutcome standardOutcome =
        ksword::memory_backend::readPhysical(
            ksword::memory_backend::MemoryAccessBackend::StandardDriver,
            session,
            pageBase,
            transferBytes);
    const ksword::memory_backend::AccessOutcome ddmaOutcome =
        ksword::memory_backend::readPhysical(
            ksword::memory_backend::MemoryAccessBackend::Ddma,
            session,
            pageBase,
            transferBytes);

    // 任何一侧读失败都不能下"一致/不一致"的结论，只能说没法比。
    if (!standardOutcome.ok || !ddmaOutcome.ok)
    {
        const QString detail = !standardOutcome.ok
            ? standardOutcome.failureText
            : ddmaOutcome.failureText;
        m_ddmaCrossCheckResultLabel->setText(
            QStringLiteral("%1 %2").arg(localized("Cannot compare:")).arg(detail));
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
}

void SystemMemoryAuditPage::retranslateUi()
{
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

    m_detailTabs->setTabText(0, localized("Physical distribution"));
    m_detailTabs->setTabText(1, localized("User-mode residency"));
    m_detailTabs->setTabText(2, localized("Kernel process snapshot"));
    m_detailTabs->setTabText(3, localized("Pool tags"));
    m_detailTabs->setTabText(4, localized("Big Pool allocations"));
    m_detailTabs->setTabText(5, localized("Physical page attribution"));
    m_detailTabs->setTabText(6, localized("Hyper-V / host memory"));

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
    if (m_refreshing)
    {
        return;
    }
    m_refreshing = true;
    const std::uint64_t ticket = m_snapshotRefreshTicket.fetch_add(1) + 1;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setText(localized("Collecting system memory evidence..."));

    const QPointer<SystemMemoryAuditPage> guardedPage(this);
    std::thread([guardedPage, ticket]() mutable {
        Snapshot snapshot = collectSnapshot();
        if (guardedPage.isNull())
        {
            return;
        }

        QMetaObject::invokeMethod(
            guardedPage.data(),
            [guardedPage, ticket, snapshot = std::move(snapshot)]() mutable {
                if (!guardedPage.isNull())
                {
                    guardedPage->applySnapshot(std::move(snapshot), ticket);
                }
            },
            Qt::QueuedConnection);
    }).detach();
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

    QHash<std::uint64_t, std::uint64_t> currentProcessBytes;
    for (ProcessRow& row : snapshot.processes)
    {
        const std::uint64_t previous = m_hasSnapshot
            ? m_previousProcessPrivateBytes.value(row.identity, row.privateResidentBytes)
            : row.privateResidentBytes;
        row.privateResidentDeltaBytes =
            static_cast<std::int64_t>(row.privateResidentBytes) - static_cast<std::int64_t>(previous);
        currentProcessBytes.insert(row.identity, row.privateResidentBytes);
    }
    m_previousProcessPrivateBytes = std::move(currentProcessBytes);

    QHash<std::uint32_t, std::uint64_t> currentPoolBytes;
    for (PoolTagRow& row : snapshot.poolTags)
    {
        const std::uint64_t total = row.pagedBytes + row.nonPagedBytes;
        const std::uint64_t previous = m_hasSnapshot
            ? m_previousPoolTagBytes.value(row.tag, total)
            : total;
        row.totalDeltaBytes = static_cast<std::int64_t>(total) - static_cast<std::int64_t>(previous);
        currentPoolBytes.insert(row.tag, total);
    }
    m_previousPoolTagBytes = std::move(currentPoolBytes);

    QHash<std::uint64_t, std::uint64_t> currentBigPoolBytes;
    for (BigPoolRow& row : snapshot.bigPool)
    {
        const std::uint64_t previous = m_hasSnapshot
            ? m_previousBigPoolBytes.value(row.identity, row.sizeBytes)
            : row.sizeBytes;
        row.sizeDeltaBytes = static_cast<std::int64_t>(row.sizeBytes) - static_cast<std::int64_t>(previous);
        currentBigPoolBytes.insert(row.identity, row.sizeBytes);
    }
    m_previousBigPoolBytes = std::move(currentBigPoolBytes);

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
    if (m_userResidencyScanInProgress.exchange(true))
    {
        return;
    }

    const std::uint64_t ticket = m_userResidencyScanTicket.fetch_add(1) + 1;
    const std::vector<ProcessRow> processes = m_snapshot.processes;
    const std::uint64_t pageSize = m_snapshot.pageSize;
    m_userResidencyScanButton->setEnabled(false);
    m_userResidencyScanButton->setText(localized("Scanning user-mode residency..."));
    updateStatus();

    const QPointer<SystemMemoryAuditPage> guardedPage(this);
    std::thread([guardedPage, ticket, processes, pageSize]() mutable {
        UserResidencyScan scan = collectUserResidency(processes, pageSize);
        if (guardedPage.isNull())
        {
            return;
        }

        QMetaObject::invokeMethod(
            guardedPage.data(),
            [guardedPage, ticket, scan = std::move(scan)]() mutable {
                if (!guardedPage.isNull())
                {
                    guardedPage->applyUserResidencyScan(std::move(scan), ticket);
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void SystemMemoryAuditPage::applyUserResidencyScan(UserResidencyScan scan, const std::uint64_t ticket)
{
    if (ticket != m_userResidencyScanTicket.load())
    {
        return;
    }

    m_userResidencyScan = std::move(scan);
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
        if (m_userResidencyTableDirty)
        {
            rebuildUserResidencyTable();
            m_userResidencyTableDirty = false;
        }
        break;
    case 2:
        if (m_processTableDirty)
        {
            rebuildProcessTable();
            m_processTableDirty = false;
        }
        break;
    case 3:
        if (m_poolTagTableDirty)
        {
            rebuildPoolTagTable();
            m_poolTagTableDirty = false;
        }
        break;
    case 4:
        if (m_bigPoolTableDirty)
        {
            rebuildBigPoolTable();
            m_bigPoolTableDirty = false;
        }
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

void SystemMemoryAuditPage::rebuildUserResidencyTable()
{
    const QString filter = m_filterEdit->text().trimmed();
    m_userResidencyTable->setSortingEnabled(false);
    m_userResidencyTable->setRowCount(0);

    const auto kindText = [](const UserMemoryKind kind) {
        switch (kind)
        {
        case UserMemoryKind::Private:
            return localized("Private anonymous");
        case UserMemoryKind::PrivateMappedCopy:
            return localized("Private mapped copy");
        case UserMemoryKind::Image:
            return localized("Mapped image");
        case UserMemoryKind::MappedFile:
            return localized("Mapped file");
        case UserMemoryKind::PagefileSection:
            return localized("Pagefile-backed section");
        case UserMemoryKind::MappedBackingUnknown:
            return localized("Mapped backing unresolved");
        default:
            return localized("Unknown mapping");
        }
    };

    for (const UserResidencyRow& row : m_userResidencyScan.rows)
    {
        const QString category = kindText(row.kind);
        QString backingEvidence = row.backingPath;
        if (backingEvidence == QStringLiteral(":private"))
        {
            backingEvidence = localized("Private allocation owned by this process");
        }
        else if (backingEvidence == QStringLiteral(":mapped-unknown"))
        {
            backingEvidence = localized("Mapped backing unresolved; path query Win32 status: %1").arg(row.backingPathStatus);
        }
        else if (backingEvidence == QStringLiteral(":pagefile"))
        {
            backingEvidence = localized("Pagefile backing observed with MemoryRegionInfo.MappedPageFile");
        }
        else if (backingEvidence == QStringLiteral(":file-path-unavailable"))
        {
            backingEvidence = localized("Data-file backing observed; path query Win32 status: %1").arg(row.backingPathStatus);
        }
        else if (backingEvidence == QStringLiteral(":image"))
        {
            backingEvidence = localized("Mapped image path unavailable");
        }
        else if (backingEvidence == QStringLiteral(":unknown"))
        {
            backingEvidence = localized("Virtual region type unavailable");
        }
        const QString searchable = QStringLiteral("%1 %2 %3 %4")
            .arg(row.processName)
            .arg(row.pid)
            .arg(category, backingEvidence);
        if (!filter.isEmpty() && !searchable.contains(filter, Qt::CaseInsensitive))
        {
            continue;
        }

        const int rowIndex = m_userResidencyTable->rowCount();
        m_userResidencyTable->insertRow(rowIndex);
        m_userResidencyTable->setItem(rowIndex, 0, textItem(row.processName));
        m_userResidencyTable->setItem(rowIndex, 1, numericItem(QString::number(row.pid), row.pid));
        m_userResidencyTable->setItem(rowIndex, 2, textItem(category));
        m_userResidencyTable->setItem(rowIndex, 3, textItem(backingEvidence));
        if (row.backingPathQueryAttempted)
        {
            m_userResidencyTable->item(rowIndex, 3)->setToolTip(localized("GetMappedFileNameW Win32: %1 | MemoryRegionInfo Win32: %2 | region metadata available: %3")
                .arg(row.backingPathStatus).arg(row.backingRegionStatus)
                .arg(row.backingRegionKnown ? localized("Yes") : localized("No")));
        }
        m_userResidencyTable->setItem(rowIndex, 4, numericItem(
            formatBytes(row.residentReferenceBytes), static_cast<qulonglong>(row.residentReferenceBytes)));
        m_userResidencyTable->setItem(rowIndex, 5, numericItem(
            formatBytes(row.privateResidentBytes), static_cast<qulonglong>(row.privateResidentBytes)));
        m_userResidencyTable->setItem(rowIndex, 6, numericItem(
            formatBytes(row.shareableResidentBytes), static_cast<qulonglong>(row.shareableResidentBytes)));
        m_userResidencyTable->setItem(rowIndex, 7, numericItem(
            formatBytes(row.sharedResidentReferenceBytes), static_cast<qulonglong>(row.sharedResidentReferenceBytes)));
        m_userResidencyTable->setItem(rowIndex, 8, numericItem(
            formatBytes(row.proportionalResidentBytes), static_cast<qulonglong>(row.proportionalResidentBytes)));
    }

    m_userResidencyTable->setSortingEnabled(true);
    m_userResidencyTable->sortItems(4, Qt::DescendingOrder);
    m_userResidencyTable->resizeColumnsToContents();
    m_userResidencyTable->horizontalHeader()->setStretchLastSection(false);
    m_userResidencyTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
}

void SystemMemoryAuditPage::rebuildProcessTable()
{
    const QString filter = m_filterEdit->text().trimmed();
    m_processTable->setSortingEnabled(false);
    m_processTable->setRowCount(0);
    for (const ProcessRow& row : m_snapshot.processes)
    {
        const QString searchable = QStringLiteral("%1 %2 %3")
            .arg(row.name)
            .arg(row.pid)
            .arg(row.sessionId);
        if (!filter.isEmpty() && !searchable.contains(filter, Qt::CaseInsensitive))
        {
            continue;
        }
        const int rowIndex = m_processTable->rowCount();
        m_processTable->insertRow(rowIndex);
        m_processTable->setItem(rowIndex, 0, textItem(row.name));
        m_processTable->setItem(rowIndex, 1, numericItem(QString::number(row.pid), row.pid));
        m_processTable->setItem(rowIndex, 2, numericItem(QString::number(row.sessionId), row.sessionId));
        m_processTable->setItem(rowIndex, 3, numericItem(formatBytes(row.privateResidentBytes), static_cast<qulonglong>(row.privateResidentBytes)));
        m_processTable->setItem(rowIndex, 4, numericItem(formatBytes(row.workingSetBytes), static_cast<qulonglong>(row.workingSetBytes)));
        m_processTable->setItem(rowIndex, 5, numericItem(formatBytes(row.sharedResidentReferenceBytes), static_cast<qulonglong>(row.sharedResidentReferenceBytes)));
        m_processTable->setItem(rowIndex, 6, numericItem(formatBytes(row.privateCommitBytes), static_cast<qulonglong>(row.privateCommitBytes)));
        m_processTable->setItem(rowIndex, 7, numericItem(formatBytes(row.pagedPoolQuotaBytes), static_cast<qulonglong>(row.pagedPoolQuotaBytes)));
        m_processTable->setItem(rowIndex, 8, numericItem(formatBytes(row.nonPagedPoolQuotaBytes), static_cast<qulonglong>(row.nonPagedPoolQuotaBytes)));
        m_processTable->setItem(rowIndex, 9, numericItem(QString::number(row.hardFaultCount), row.hardFaultCount));
        QTableWidgetItem* const deltaItem = signedNumericItem(
            formatDelta(row.privateResidentDeltaBytes),
            static_cast<qlonglong>(row.privateResidentDeltaBytes));
        applyDeltaColor(deltaItem, row.privateResidentDeltaBytes);
        m_processTable->setItem(rowIndex, 10, deltaItem);
    }
    m_processTable->setSortingEnabled(true);
    m_processTable->sortItems(3, Qt::DescendingOrder);
    m_processTable->resizeColumnsToContents();
    m_processTable->horizontalHeader()->setStretchLastSection(true);
}

void SystemMemoryAuditPage::rebuildPoolTagTable()
{
    const QString filter = m_filterEdit->text().trimmed();
    m_poolTagTable->setSortingEnabled(false);
    m_poolTagTable->setRowCount(0);
    for (const PoolTagRow& row : m_snapshot.poolTags)
    {
        const TagMetadata metadata = m_poolTagMetadata.value(row.tag);
        const QString searchable = QStringLiteral("%1 %2 %3")
            .arg(row.tagText, metadata.source, metadata.description);
        if (!filter.isEmpty() && !searchable.contains(filter, Qt::CaseInsensitive))
        {
            continue;
        }
        const std::uint64_t total = row.pagedBytes + row.nonPagedBytes;
        const int rowIndex = m_poolTagTable->rowCount();
        m_poolTagTable->insertRow(rowIndex);
        m_poolTagTable->setItem(rowIndex, 0, textItem(row.tagText));
        m_poolTagTable->setItem(rowIndex, 1, numericItem(formatBytes(row.pagedBytes), static_cast<qulonglong>(row.pagedBytes)));
        m_poolTagTable->setItem(rowIndex, 2, numericItem(formatBytes(row.nonPagedBytes), static_cast<qulonglong>(row.nonPagedBytes)));
        m_poolTagTable->setItem(rowIndex, 3, numericItem(formatBytes(total), static_cast<qulonglong>(total)));
        QTableWidgetItem* const deltaItem = signedNumericItem(
            formatDelta(row.totalDeltaBytes),
            static_cast<qlonglong>(row.totalDeltaBytes));
        applyDeltaColor(deltaItem, row.totalDeltaBytes);
        m_poolTagTable->setItem(rowIndex, 4, deltaItem);
        m_poolTagTable->setItem(rowIndex, 5, numericItem(QString::number(row.pagedOutstanding), static_cast<qulonglong>(row.pagedOutstanding)));
        m_poolTagTable->setItem(rowIndex, 6, numericItem(QString::number(row.nonPagedOutstanding), static_cast<qulonglong>(row.nonPagedOutstanding)));
        m_poolTagTable->setItem(rowIndex, 7, textItem(metadata.source));
        m_poolTagTable->setItem(rowIndex, 8, textItem(metadata.description));
    }
    m_poolTagTable->setSortingEnabled(true);
    m_poolTagTable->sortItems(3, Qt::DescendingOrder);
    m_poolTagTable->resizeColumnsToContents();
    m_poolTagTable->horizontalHeader()->setStretchLastSection(true);
}

void SystemMemoryAuditPage::rebuildBigPoolTable()
{
    const QString filter = m_filterEdit->text().trimmed();
    m_bigPoolTable->setSortingEnabled(false);
    m_bigPoolTable->setRowCount(0);
    for (const BigPoolRow& row : m_snapshot.bigPool)
    {
        const TagMetadata metadata = m_poolTagMetadata.value(row.tag);
        const QString addressText = QStringLiteral("0x%1").arg(row.virtualAddress, 16, 16, QLatin1Char('0')).toUpper();
        const QString poolType = row.nonPaged ? localized("Nonpaged") : localized("Paged");
        const QString searchable = QStringLiteral("%1 %2 %3 %4 %5")
            .arg(row.tagText, addressText, poolType, metadata.source, metadata.description);
        if (!filter.isEmpty() && !searchable.contains(filter, Qt::CaseInsensitive))
        {
            continue;
        }
        const int rowIndex = m_bigPoolTable->rowCount();
        m_bigPoolTable->insertRow(rowIndex);
        m_bigPoolTable->setItem(rowIndex, 0, textItem(row.tagText));
        m_bigPoolTable->setItem(rowIndex, 1, numericItem(addressText, static_cast<qulonglong>(row.virtualAddress)));
        m_bigPoolTable->setItem(rowIndex, 2, numericItem(formatBytes(row.sizeBytes), static_cast<qulonglong>(row.sizeBytes)));
        m_bigPoolTable->setItem(rowIndex, 3, textItem(poolType));
        QTableWidgetItem* const deltaItem = signedNumericItem(
            formatDelta(row.sizeDeltaBytes),
            static_cast<qlonglong>(row.sizeDeltaBytes));
        applyDeltaColor(deltaItem, row.sizeDeltaBytes);
        m_bigPoolTable->setItem(rowIndex, 4, deltaItem);
        m_bigPoolTable->setItem(rowIndex, 5, textItem(metadata.source));
        m_bigPoolTable->setItem(rowIndex, 6, textItem(metadata.description));
    }
    m_bigPoolTable->setSortingEnabled(true);
    m_bigPoolTable->sortItems(2, Qt::DescendingOrder);
    m_bigPoolTable->resizeColumnsToContents();
    m_bigPoolTable->horizontalHeader()->setStretchLastSection(true);
}

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
        .arg(m_snapshot.processes.size())
        .arg(m_poolTagTable->rowCount())
        .arg(m_snapshot.poolTags.size())
        .arg(m_bigPoolTable->rowCount())
        .arg(m_snapshot.bigPool.size());
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
                scan.rows.push_back(std::move(row));
                rowIndex = static_cast<int>(scan.rows.size() - 1);
                rowIndexByKey.insert(aggregationKey, rowIndex);
            }

            UserResidencyRow& row = scan.rows[static_cast<std::size_t>(rowIndex)];
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
        scan.rows.begin(),
        scan.rows.end(),
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
                snapshot.processes.push_back(std::move(row));

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
            std::sort(snapshot.processes.begin(), snapshot.processes.end(), [](const ProcessRow& left, const ProcessRow& right) {
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
            snapshot.poolTags.reserve(count);
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
                snapshot.poolTags.push_back(std::move(row));
            }
            std::sort(snapshot.poolTags.begin(), snapshot.poolTags.end(), [](const PoolTagRow& left, const PoolTagRow& right) {
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
            snapshot.bigPool.reserve(count);
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
                snapshot.bigPool.push_back(std::move(row));
            }
            std::sort(snapshot.bigPool.begin(), snapshot.bigPool.end(), [](const BigPoolRow& left, const BigPoolRow& right) {
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
