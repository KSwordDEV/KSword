#include "DiskMonitorStoragePanel.h"
#include "DiskMonitorStorageLeaseCoordinator.h"

#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QBrush>
#include <QColor>
#include <QHeaderView>
#include <QPointer>
#include <QSet>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>
#include <cwchar>
#include <iterator>
#include <limits>
#include <memory>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>

struct DiskMonitorStoragePerformanceState
{
    using Lease = disk_monitor_storage_lease::Lease;
    using LeasePointer = disk_monitor_storage_lease::LeasePointer;

    // leaseByVolumeGuid：只保存当前面板正在采样的 active lease；
    // 全局协调器同时持有同一 shared_ptr，负责按卷唯一和退役 quarantine。
    QHash<QString, LeasePointer> leaseByVolumeGuid;
};

namespace
{
    constexpr int kStorageColumnDrive = 0;          // kStorageColumnDrive：卷根目录列。
    constexpr int kStorageColumnLabel = 1;          // kStorageColumnLabel：卷标列。
    constexpr int kStorageColumnFileSystem = 2;     // kStorageColumnFileSystem：文件系统列。
    constexpr int kStorageColumnActiveTime = 3;     // kStorageColumnActiveTime：活动时间百分比列。
    constexpr int kStorageColumnAvailable = 4;      // kStorageColumnAvailable：可用空间列。
    constexpr int kStorageColumnTotal = 5;          // kStorageColumnTotal：总空间列。
    constexpr int kStorageColumnReadRate = 6;       // kStorageColumnReadRate：读取速率列。
    constexpr int kStorageColumnWriteRate = 7;      // kStorageColumnWriteRate：写入速率列。
    constexpr int kStorageColumnResponse = 8;       // kStorageColumnResponse：平均响应时间列。
    constexpr int kStorageColumnQueueDepth = 9;     // kStorageColumnQueueDepth：队列深度列。
    constexpr int kStorageColumnCount = 10;         // kStorageColumnCount：存储表总列数。

    std::uint64_t nonNegativeLargeInteger(const LARGE_INTEGER value)
    {
        // nonNegativeLargeInteger：
        // - 输入：Windows 磁盘性能 LARGE_INTEGER；
        // - 返回：负值按 0 处理，避免转换为极大的无符号数。
        return value.QuadPart > 0
            ? static_cast<std::uint64_t>(value.QuadPart)
            : 0U;
    }

    bool samplingShouldStop(const std::atomic_bool* stopRequested)
    {
        return stopRequested != nullptr &&
            stopRequested->load(std::memory_order_acquire);
    }

    QString storageManagerName(const DISK_PERFORMANCE& performance)
    {
        int characterCount = 0;
        while (characterCount < static_cast<int>(std::size(performance.StorageManagerName)) &&
               performance.StorageManagerName[characterCount] != L'\0')
        {
            ++characterCount;
        }
        return QString::fromWCharArray(
            performance.StorageManagerName,
            characterCount).trimmed();
    }

    QString normalizedVolumeGuidName(const QString& volumeGuidName)
    {
        QString normalizedName = volumeGuidName.trimmed();
        normalizedName.replace(QLatin1Char('/'), QLatin1Char('\\'));
        return normalizedName.toUpper();
    }

    bool hasStorageManagerIdentity(
        const std::array<std::uint16_t, 8>& managerIdentity)
    {
        return std::any_of(
            managerIdentity.cbegin(),
            managerIdentity.cend(),
            [](const std::uint16_t character)
            {
                return character != 0U;
            });
    }

    QString storageManagerIdentityKey(
        const std::array<std::uint16_t, 8>& managerIdentity)
    {
        QString key;
        key.reserve(static_cast<int>(managerIdentity.size() * 4U));
        for (const std::uint16_t character : managerIdentity)
        {
            key.append(
                QString::number(character, 16)
                    .rightJustified(4, QLatin1Char('0')));
        }
        return key;
    }

    QString storageIdentityKey(
        const QString& volumeGuidName,
        const std::uint32_t volumeSerialNumber,
        const std::array<std::uint16_t, 8>& managerIdentity,
        const std::uint32_t storageDeviceNumber)
    {
        if (volumeGuidName.isEmpty() ||
            !hasStorageManagerIdentity(managerIdentity))
        {
            return {};
        }

        return QStringLiteral("%1|%2|%3|%4")
            .arg(normalizedVolumeGuidName(volumeGuidName))
            .arg(
                QString::number(volumeSerialNumber, 16)
                    .rightJustified(8, QLatin1Char('0')))
            .arg(storageManagerIdentityKey(
                managerIdentity))
            .arg(storageDeviceNumber);
    }

    QString storageIdentityKey(const DiskMonitorStorageSample& sample)
    {
        if (!sample.volumeSerialAvailable ||
            !sample.performanceAvailable)
        {
            return {};
        }
        return storageIdentityKey(
            sample.volumeGuidName,
            sample.volumeSerialNumber,
            sample.storageManagerIdentity,
            sample.storageDeviceNumber);
    }

    QString storageIdentityKey(
        const DiskMonitorStoragePerformanceState::Lease& lease)
    {
        return storageIdentityKey(
            lease.volumeGuidName,
            lease.volumeSerialNumber,
            lease.storageManagerIdentity,
            lease.storageDeviceNumber);
    }

    bool counter32Delta(
        const std::uint32_t currentValue,
        const std::uint32_t previousValue,
        std::uint64_t* deltaOut)
    {
        if (deltaOut == nullptr)
        {
            return false;
        }
        if (currentValue >= previousValue)
        {
            *deltaOut =
                static_cast<std::uint64_t>(currentValue) -
                static_cast<std::uint64_t>(previousValue);
            return true;
        }

        // 只有落在 32 位计数器边界两侧才视为自然回绕；其它下降属于 epoch 重置。
        constexpr std::uint32_t kWrapHighWatermark = 0xf0000000U;
        constexpr std::uint32_t kWrapLowWatermark = 0x0fffffffU;
        if (previousValue >= kWrapHighWatermark &&
            currentValue <= kWrapLowWatermark)
        {
            *deltaOut =
                (static_cast<std::uint64_t>(
                    std::numeric_limits<std::uint32_t>::max()) + 1U) -
                static_cast<std::uint64_t>(previousValue) +
                static_cast<std::uint64_t>(currentValue);
            return true;
        }
        return false;
    }

    void populatePerformanceSample(
        const DISK_PERFORMANCE& performance,
        const std::uint64_t sampleTickMs,
        DiskMonitorStorageSample* sample)
    {
        if (sample == nullptr)
        {
            return;
        }

        sample->sampleTickMs = sampleTickMs;
        sample->bytesRead = nonNegativeLargeInteger(performance.BytesRead);
        sample->bytesWritten = nonNegativeLargeInteger(performance.BytesWritten);
        sample->readCount = performance.ReadCount;
        sample->writeCount = performance.WriteCount;
        sample->readTime100ns = nonNegativeLargeInteger(performance.ReadTime);
        sample->writeTime100ns = nonNegativeLargeInteger(performance.WriteTime);
        sample->idleTime100ns = nonNegativeLargeInteger(performance.IdleTime);
        sample->queryTime100ns = nonNegativeLargeInteger(performance.QueryTime);
        sample->storageDeviceNumber = performance.StorageDeviceNumber;
        sample->storageManagerName = storageManagerName(performance);
        for (std::size_t managerIndex = 0U;
             managerIndex < sample->storageManagerIdentity.size();
             ++managerIndex)
        {
            sample->storageManagerIdentity[managerIndex] =
                static_cast<std::uint16_t>(
                    performance.StorageManagerName[managerIndex]);
        }
        sample->queueDepth = performance.QueueDepth;
    }

    bool performanceIdentityMatches(
        const DiskMonitorStoragePerformanceState::Lease& lease,
        const DiskMonitorStorageSample& sample)
    {
        return sample.volumeSerialAvailable &&
            lease.volumeSerialNumber == sample.volumeSerialNumber &&
            lease.storageDeviceNumber == sample.storageDeviceNumber &&
            lease.storageManagerIdentity ==
                sample.storageManagerIdentity;
    }

    bool performanceIdentityComplete(
        const DiskMonitorStorageSample& sample)
    {
        return !sample.volumeGuidName.isEmpty() &&
            sample.volumeSerialAvailable &&
            hasStorageManagerIdentity(sample.storageManagerIdentity);
    }

    bool isImmediateLeaseRetirementError(const DWORD errorCode)
    {
        switch (errorCode)
        {
        case ERROR_INVALID_HANDLE:
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_INVALID_DRIVE:
        case ERROR_NOT_READY:
        case ERROR_GEN_FAILURE:
        case ERROR_DEV_NOT_EXIST:
        case ERROR_NO_SUCH_DEVICE:
        case ERROR_DEVICE_NOT_CONNECTED:
        case ERROR_DEVICE_REMOVED:
        case ERROR_NO_MEDIA_IN_DRIVE:
        case ERROR_MEDIA_CHANGED:
        case ERROR_INVALID_FUNCTION:
            return true;
        default:
            return false;
        }
    }

    void clearPerformanceSample(DiskMonitorStorageSample* sample)
    {
        if (sample == nullptr)
        {
            return;
        }
        sample->storageManagerName.clear();
        sample->storageManagerIdentity.fill(0U);
        sample->sampleTickMs = 0U;
        sample->bytesRead = 0U;
        sample->bytesWritten = 0U;
        sample->readCount = 0U;
        sample->writeCount = 0U;
        sample->readTime100ns = 0U;
        sample->writeTime100ns = 0U;
        sample->idleTime100ns = 0U;
        sample->queryTime100ns = 0U;
        sample->storageDeviceNumber = 0U;
        sample->queueDepth = 0U;
        sample->performanceError = ERROR_SUCCESS;
        sample->performanceAvailable = false;
        sample->baselinePending = false;
    }

    QTableWidgetItem* createStorageItem(
        const QString& text,
        const double numericValue = std::numeric_limits<double>::quiet_NaN())
    {
        // createStorageItem：
        // - 输入：显示文本和可选数值；
        // - 返回：只读表格单元格；数值写入 UserRole 以支持正确排序。
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        if (std::isfinite(numericValue))
        {
            item->setData(Qt::UserRole, numericValue);
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        }
        return item;
    }
}

DiskMonitorStoragePanel::DiskMonitorStoragePanel(QWidget* parent)
    : QWidget(parent),
      m_performanceState(
          std::make_unique<DiskMonitorStoragePerformanceState>())
{
    // 存储区仅负责表格展示；采样由 DiskMonitorPage 的既有后台线程统一调度，
    // 避免硬件页增加另一组定时器并与页面销毁发生竞争。
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    m_table = new ks::ui::VisibleTableWidget(this);
    // 小型卷性能摘要嵌入监控页，复制导出留在右键菜单，避免重复工具条。
    ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::None);
    m_table->setColumnCount(kStorageColumnCount);
    m_table->setHorizontalHeaderLabels({
        QStringLiteral("驱动器"),
        QStringLiteral("卷标"),
        QStringLiteral("文件系统"),
        QStringLiteral("活动时间"),
        QStringLiteral("可用空间"),
        QStringLiteral("总空间"),
        QStringLiteral("读(字节/秒)"),
        QStringLiteral("写(字节/秒)"),
        QStringLiteral("响应时间(ms)"),
        QStringLiteral("队列长度")
        });
    m_table->setAlternatingRowColors(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSortingEnabled(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(24);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(kStorageColumnLabel, QHeaderView::Stretch);
    m_table->setStyleSheet(QStringLiteral(
        "QTableWidget{background:transparent;border:1px solid %1;}"
        "QHeaderView::section{background:%2;color:%3;border:0;border-right:1px solid %1;"
        "border-bottom:1px solid %1;padding:5px 7px;font-weight:600;}")
        .arg(KswordTheme::BorderHex())
        .arg(KswordTheme::SurfaceAltHex())
        .arg(KswordTheme::TextPrimaryHex()));
    rootLayout->addWidget(m_table, 1);

    m_summaryText = QStringLiteral("存储：等待首轮采样");
}

DiskMonitorStoragePanel::~DiskMonitorStoragePanel()
{
    retirePerformanceCountersAsync(
        QStringLiteral("storage-panel-destructor"));
}

void DiskMonitorStoragePanel::retirePerformanceCountersAsync(
    const QString& reason)
{
    if (m_performanceState == nullptr)
    {
        return;
    }

    for (auto leaseIterator =
             m_performanceState->leaseByVolumeGuid.begin();
         leaseIterator !=
             m_performanceState->leaseByVolumeGuid.end();)
    {
        // activeLease：shared_ptr 由协调器和面板共同持有；
        // retireLeaseAsync 只切换状态、唤醒 worker，不在调用线程执行 OFF。
        const DiskMonitorStoragePerformanceState::LeasePointer activeLease =
            leaseIterator.value();
        if (disk_monitor_storage_lease::retireLeaseAsync(
                activeLease,
                reason))
        {
            leaseIterator =
                m_performanceState->leaseByVolumeGuid.erase(
                    leaseIterator);
            continue;
        }
        ++leaseIterator;
    }
}

DiskMonitorStorageBatch DiskMonitorStoragePanel::collectSamples(
    const std::atomic_bool* stopRequested)
{
    DiskMonitorStorageBatch sampleBatch;
    std::vector<DiskMonitorStorageSample>& sampleList =
        sampleBatch.sampleList;
    if (m_performanceState == nullptr)
    {
        sampleBatch.enumerationError = ERROR_INVALID_HANDLE;
        return sampleBatch;
    }
    if (samplingShouldStop(stopRequested))
    {
        sampleBatch.enumerationError = ERROR_OPERATION_ABORTED;
        return sampleBatch;
    }

    // 先让 Windows 返回多字符串缓冲区长度，再一次性读取所有逻辑卷根目录。
    SetLastError(ERROR_SUCCESS);
    const DWORD requiredCharacterCount = GetLogicalDriveStringsW(0U, nullptr);
    if (requiredCharacterCount == 0U)
    {
        const DWORD errorCode = GetLastError();
        sampleBatch.enumerationError =
            errorCode != ERROR_SUCCESS
            ? errorCode
            : ERROR_GEN_FAILURE;
        return sampleBatch;
    }
    std::vector<wchar_t> driveBuffer(
        static_cast<std::size_t>(requiredCharacterCount) + 1U,
        L'\0');
    const DWORD copiedCharacterCount = GetLogicalDriveStringsW(
        static_cast<DWORD>(driveBuffer.size()),
        driveBuffer.data());
    if (copiedCharacterCount == 0U ||
        static_cast<std::size_t>(copiedCharacterCount) >= driveBuffer.size())
    {
        const DWORD errorCode = GetLastError();
        sampleBatch.enumerationError =
            errorCode != ERROR_SUCCESS
            ? errorCode
            : ERROR_INSUFFICIENT_BUFFER;
        return sampleBatch;
    }

    QSet<QString> seenVolumeGuidSet;
    auto retireActiveLease =
        [
            this,
            &sampleBatch
        ](
            auto leaseIterator,
            const QString& reason) -> bool
    {
        const DiskMonitorStoragePerformanceState::LeasePointer activeLease =
            leaseIterator.value();
        const QString invalidatedIdentity =
            activeLease != nullptr
            ? storageIdentityKey(*activeLease)
            : QString();
        if (!invalidatedIdentity.isEmpty() &&
            !sampleBatch.invalidatedBaselineKeys.contains(
                invalidatedIdentity))
        {
            sampleBatch.invalidatedBaselineKeys.append(
                invalidatedIdentity);
        }

        if (!disk_monitor_storage_lease::retireLeaseAsync(
                activeLease,
                reason))
        {
            return false;
        }
        m_performanceState->leaseByVolumeGuid.erase(leaseIterator);
        return true;
    };

    // 仅枚举固定卷；网络盘和可移动介质可能在后台查询时长时间阻塞，
    // 与资源监视器的本机磁盘审计目标也不一致。
    const wchar_t* driveRootPointer = driveBuffer.data();
    while (driveRootPointer != nullptr && *driveRootPointer != L'\0')
    {
        const std::size_t driveRootLength = std::wcslen(driveRootPointer);
        if (driveRootLength == 0U)
        {
            break;
        }
        if (samplingShouldStop(stopRequested))
        {
            break;
        }

        if (GetDriveTypeW(driveRootPointer) == DRIVE_FIXED)
        {
            DiskMonitorStorageSample sample;
            sample.driveRoot = QString::fromWCharArray(driveRootPointer);

            wchar_t volumeGuidBuffer[MAX_PATH + 1]{};
            if (GetVolumeNameForVolumeMountPointW(
                driveRootPointer,
                volumeGuidBuffer,
                static_cast<DWORD>(std::size(volumeGuidBuffer))))
            {
                sample.volumeGuidName =
                    normalizedVolumeGuidName(
                        QString::fromWCharArray(volumeGuidBuffer));
            }
            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            // 同一个卷可能有多个盘符/挂载点。按卷 GUID 只查询和汇总一次，
            // 避免重复增加性能引用及双重计算吞吐。
            if (!sample.volumeGuidName.isEmpty() &&
                seenVolumeGuidSet.contains(sample.volumeGuidName))
            {
                driveRootPointer += driveRootLength + 1U;
                continue;
            }
            if (!sample.volumeGuidName.isEmpty())
            {
                seenVolumeGuidSet.insert(sample.volumeGuidName);
            }

            ULARGE_INTEGER availableBytes{};
            ULARGE_INTEGER totalBytes{};
            ULARGE_INTEGER totalFreeBytes{};
            if (GetDiskFreeSpaceExW(
                driveRootPointer,
                &availableBytes,
                &totalBytes,
                &totalFreeBytes))
            {
                sample.availableBytes = availableBytes.QuadPart;
                sample.totalBytes = totalBytes.QuadPart;
                sample.capacityAvailable = true;
            }
            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            // 卷标和文件系统只用于展示；卷序列号参与稳定身份，
            // 因此本调用失败时本轮不建立性能基线。
            wchar_t volumeLabelBuffer[MAX_PATH + 1]{};
            wchar_t fileSystemBuffer[MAX_PATH + 1]{};
            DWORD volumeSerialNumber = 0U;
            if (GetVolumeInformationW(
                driveRootPointer,
                volumeLabelBuffer,
                static_cast<DWORD>(std::size(volumeLabelBuffer)),
                &volumeSerialNumber,
                nullptr,
                nullptr,
                fileSystemBuffer,
                static_cast<DWORD>(std::size(fileSystemBuffer))))
            {
                sample.volumeLabel = QString::fromWCharArray(volumeLabelBuffer);
                sample.fileSystemName = QString::fromWCharArray(fileSystemBuffer);
                sample.volumeSerialNumber = volumeSerialNumber;
                sample.volumeSerialAvailable = true;
            }
            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            // IOCTL_DISK_PERFORMANCE 每次成功调用都会增加一个启用引用。
            // 会话为每个卷保留一个 anchor；后续查询完成后立即 OFF 一次，
            // 使采样间隔内始终只有本页面持有的一个引用。
            const QString volumeGuidKey =
                normalizedVolumeGuidName(sample.volumeGuidName);
            bool mayOpenNewLease =
                !volumeGuidKey.isEmpty() &&
                sample.volumeSerialAvailable;
            auto leaseIterator =
                m_performanceState->leaseByVolumeGuid.find(volumeGuidKey);
            if (leaseIterator !=
                m_performanceState->leaseByVolumeGuid.end())
            {
                mayOpenNewLease = false;
                DiskMonitorStoragePerformanceState::Lease& lease =
                    *leaseIterator.value();
                const bool primaryIdentityMatches =
                    lease.volumeHandle != INVALID_HANDLE_VALUE &&
                    normalizedVolumeGuidName(lease.volumeGuidName) ==
                        volumeGuidKey &&
                    sample.volumeSerialAvailable &&
                    lease.volumeSerialNumber ==
                        sample.volumeSerialNumber;
                if (!primaryIdentityMatches)
                {
                    const bool retirementQueued = retireActiveLease(
                        leaseIterator,
                        QStringLiteral(
                            "primary-guid-or-volume-serial-changed"));
                    if (!retirementQueued)
                    {
                        sample.performanceError = ERROR_GEN_FAILURE;
                    }
                }
                else
                {
                    DISK_PERFORMANCE performance{};
                    DWORD returnedBytes = 0U;
                    const BOOL queryOk = DeviceIoControl(
                        lease.volumeHandle,
                        IOCTL_DISK_PERFORMANCE,
                        nullptr,
                        0U,
                        &performance,
                        static_cast<DWORD>(sizeof(performance)),
                        &returnedBytes,
                        nullptr);
                    const std::uint64_t sampleTickMs = GetTickCount64();
                    if (queryOk)
                    {
                        ++lease.ownedEnableReferenceCount;
                        lease.lastQueryError = ERROR_SUCCESS;
                        lease.consecutiveQueryFailureCount = 0U;
                        const bool completeResult =
                            returnedBytes >=
                            static_cast<DWORD>(sizeof(performance));
                        if (completeResult)
                        {
                            populatePerformanceSample(
                                performance,
                                sampleTickMs,
                                &sample);
                        }

                        // 无论返回长度是否有效，成功 IOCTL 都已增加引用。
                        DWORD balanceError = ERROR_SUCCESS;
                        const bool balancedQueryReference =
                            disk_monitor_storage_lease::turnOffOneReference(
                                &lease,
                                &balanceError);
                        const bool secondaryIdentityMatches =
                            completeResult &&
                            performanceIdentityComplete(sample) &&
                            performanceIdentityMatches(lease, sample);
                        if (completeResult &&
                            balancedQueryReference &&
                            secondaryIdentityMatches)
                        {
                            sample.performanceAvailable = true;
                        }
                        else
                        {
                            sample.performanceError =
                                !completeResult
                                ? ERROR_INVALID_DATA
                                : (!balancedQueryReference
                                    ? balanceError
                                    : ERROR_INVALID_DATA);
                            if (!balancedQueryReference)
                            {
                                lease.lastQueryError = balanceError;
                                ++lease.consecutiveQueryFailureCount;
                            }
                            const bool retirementQueued = retireActiveLease(
                                leaseIterator,
                                !balancedQueryReference
                                ? QStringLiteral(
                                    "query-reference-off-failed")
                                : QStringLiteral(
                                    "secondary-manager-or-device-changed"));
                            if (!retirementQueued)
                            {
                                sample.performanceError =
                                    ERROR_GEN_FAILURE;
                            }
                        }
                    }
                    else
                    {
                        const DWORD queryError = GetLastError();
                        sample.performanceError = queryError;
                        lease.lastQueryError = queryError;
                        ++lease.consecutiveQueryFailureCount;

                        const bool stopCancellation =
                            samplingShouldStop(stopRequested) &&
                            queryError == ERROR_OPERATION_ABORTED;
                        const bool retireFailedLease =
                            stopCancellation ||
                            isImmediateLeaseRetirementError(queryError) ||
                            lease.consecutiveQueryFailureCount >= 2U;
                        if (retireFailedLease)
                        {
                            const bool retirementQueued = retireActiveLease(
                                leaseIterator,
                                stopCancellation
                                ? QStringLiteral(
                                    "sampling-cancelled")
                                : QStringLiteral(
                                    "query-failure-threshold"));
                            if (!retirementQueued)
                            {
                                sample.performanceError =
                                    ERROR_GEN_FAILURE;
                            }
                        }
                    }
                }
            }

            if (mayOpenNewLease &&
                !samplingShouldStop(stopRequested))
            {
                clearPerformanceSample(&sample);
                // newLease：协调器先原子占用卷槽位；active 或 retiring
                // 任一状态已存在时返回空，从源头阻止 1 Hz 重复开句柄。
                const DiskMonitorStoragePerformanceState::LeasePointer newLease =
                    disk_monitor_storage_lease::tryAcquireActiveLease(
                        volumeGuidKey);
                if (newLease == nullptr)
                {
                    sample.performanceError = ERROR_RETRY;
                }
                else
                {
                    newLease->volumeSerialNumber =
                        sample.volumeSerialNumber;
                    QString volumeDevicePath = sample.volumeGuidName;
                    while (volumeDevicePath.endsWith(
                        QLatin1Char('\\')))
                    {
                        volumeDevicePath.chop(1);
                    }
                    newLease->volumeHandle = CreateFileW(
                        reinterpret_cast<LPCWSTR>(
                            volumeDevicePath.utf16()),
                        0U,
                        FILE_SHARE_READ |
                            FILE_SHARE_WRITE |
                            FILE_SHARE_DELETE,
                        nullptr,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        nullptr);

                    if (newLease->volumeHandle !=
                        INVALID_HANDLE_VALUE)
                    {
                        DISK_PERFORMANCE performance{};
                        DWORD returnedBytes = 0U;
                        const BOOL queryOk = DeviceIoControl(
                            newLease->volumeHandle,
                            IOCTL_DISK_PERFORMANCE,
                            nullptr,
                            0U,
                            &performance,
                            static_cast<DWORD>(
                                sizeof(performance)),
                            &returnedBytes,
                            nullptr);
                        const std::uint64_t sampleTickMs =
                            GetTickCount64();
                        if (queryOk)
                        {
                            newLease->ownedEnableReferenceCount = 1U;
                            const bool completeResult =
                                returnedBytes >=
                                static_cast<DWORD>(
                                    sizeof(performance));
                            if (completeResult)
                            {
                                populatePerformanceSample(
                                    performance,
                                    sampleTickMs,
                                    &sample);
                                newLease->storageDeviceNumber =
                                    sample.storageDeviceNumber;
                                newLease->storageManagerName =
                                    sample.storageManagerName;
                                newLease->storageManagerIdentity =
                                    sample.storageManagerIdentity;
                                if (performanceIdentityComplete(
                                    sample))
                                {
                                    sample.performanceAvailable =
                                        true;
                                    sample.baselinePending = true;
                                    m_performanceState->
                                        leaseByVolumeGuid.insert(
                                            volumeGuidKey,
                                            newLease);
                                }
                                else
                                {
                                    sample.performanceError =
                                        ERROR_INVALID_DATA;
                                    if (!disk_monitor_storage_lease::
                                            retireLeaseAsync(
                                                newLease,
                                                QStringLiteral(
                                                    "initial-identity-incomplete")))
                                    {
                                        sample.performanceError =
                                            ERROR_GEN_FAILURE;
                                        m_performanceState->
                                            leaseByVolumeGuid.insert(
                                                volumeGuidKey,
                                                newLease);
                                    }
                                }
                            }
                            else
                            {
                                sample.performanceError =
                                    ERROR_INVALID_DATA;
                                if (!disk_monitor_storage_lease::
                                        retireLeaseAsync(
                                            newLease,
                                            QStringLiteral(
                                                "initial-query-short-result")))
                                {
                                    sample.performanceError =
                                        ERROR_GEN_FAILURE;
                                    m_performanceState->
                                        leaseByVolumeGuid.insert(
                                            volumeGuidKey,
                                            newLease);
                                }
                            }
                        }
                        else
                        {
                            sample.performanceError = GetLastError();
                            CloseHandle(newLease->volumeHandle);
                            newLease->volumeHandle =
                                INVALID_HANDLE_VALUE;
                            disk_monitor_storage_lease::
                                releaseUnusedActiveLease(newLease);
                        }
                    }
                    else
                    {
                        sample.performanceError = GetLastError();
                        disk_monitor_storage_lease::
                            releaseUnusedActiveLease(newLease);
                    }
                }
            }

            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            if (sample.performanceAvailable)
            {
                // 性能身份必须完整；无法确认身份时仅保留容量信息。
                sample.performanceAvailable =
                    !storageIdentityKey(sample).isEmpty();
            }

            if (!sample.performanceAvailable)
            {
                sample.sampleTickMs = 0U;
            }
            sampleList.push_back(std::move(sample));
        }
        driveRootPointer += driveRootLength + 1U;
    }

    if (samplingShouldStop(stopRequested))
    {
        sampleBatch.enumerationError = ERROR_OPERATION_ABORTED;
    }
    else
    {
        sampleBatch.enumerationSucceeded = true;
        sampleBatch.enumerationError = ERROR_SUCCESS;

        // 本轮未出现的卷已卸载/移除；从 active map 移交给唯一 worker。
        // OFF 未清零期间同 GUID 保持 quarantine，不允许重新打开 lease。
        for (auto leaseIterator =
                 m_performanceState->leaseByVolumeGuid.begin();
             leaseIterator !=
                 m_performanceState->leaseByVolumeGuid.end();)
        {
            auto currentLeaseIterator = leaseIterator;
            ++leaseIterator;
            if (!seenVolumeGuidSet.contains(
                currentLeaseIterator.key()))
            {
                retireActiveLease(
                    currentLeaseIterator,
                    QStringLiteral("volume-no-longer-enumerated"));
            }
        }
    }

    std::sort(
        sampleList.begin(),
        sampleList.end(),
        [](const DiskMonitorStorageSample& left, const DiskMonitorStorageSample& right)
        {
            return left.driveRoot.compare(right.driveRoot, Qt::CaseInsensitive) < 0;
        });

    sampleBatch.fixedVolumeCount =
        static_cast<int>(sampleList.size());
    for (const DiskMonitorStorageSample& sample : sampleList)
    {
        if (sample.performanceAvailable)
        {
            ++sampleBatch.performanceAvailableCount;
        }
        if (sample.baselinePending)
        {
            ++sampleBatch.baselinePendingCount;
        }
    }
    sampleBatch.failedPerformanceCount =
        sampleBatch.fixedVolumeCount -
        sampleBatch.performanceAvailableCount;
    return sampleBatch;
}

void DiskMonitorStoragePanel::applySamples(
    DiskMonitorStorageBatch sampleBatch)
{
    if (m_table == nullptr)
    {
        return;
    }

    if (ks::ui::IsTableUiCommitBlockedByContextMenu({m_table}))
    {
        const QPointer<DiskMonitorStoragePanel> safeThis(this);
        ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("disk-monitor-storage-snapshot-apply"),
            {m_table},
            [safeThis, sampleBatch = std::move(sampleBatch)]() mutable
            {
                if (!safeThis.isNull())
                {
                    safeThis->applySamples(std::move(sampleBatch));
                }
            });
        return;
    }

    for (const QString& invalidatedBaseline :
         sampleBatch.invalidatedBaselineKeys)
    {
        m_baselineByIdentity.remove(invalidatedBaseline);
    }

    std::vector<DiskMonitorStorageSample>& sampleList =
        sampleBatch.sampleList;
    const QSignalBlocker tableSignalBlocker(m_table);
    const bool sortingWasEnabled = m_table->isSortingEnabled();
    m_table->setSortingEnabled(false);
    m_table->clearSpans();
    m_table->setRowCount(static_cast<int>(sampleList.size()));

    double highestActivePercent = 0.0;
    double totalReadRate = 0.0;
    double totalWriteRate = 0.0;
    int validRateSampleCount = 0;
    int baselinePendingCount = 0;
    QHash<QString, StorageBaseline> nextBaselineByIdentity;

    for (std::size_t sampleIndex = 0U;
         sampleIndex < sampleList.size();
         ++sampleIndex)
    {
        const DiskMonitorStorageSample& sample = sampleList[sampleIndex];
        const QString baselineKey = storageIdentityKey(sample);
        const auto baselineIterator =
            m_baselineByIdentity.constFind(baselineKey);

        double readRate = 0.0;
        double writeRate = 0.0;
        double activePercent = 0.0;
        double responseTimeMs = 0.0;
        bool rateAvailable = false;
        bool responseTimeAvailable = false;
        if (!baselineKey.isEmpty() &&
            baselineIterator != m_baselineByIdentity.constEnd() &&
            baselineIterator->performanceAvailable &&
            sample.performanceAvailable &&
            sample.sampleTickMs > baselineIterator->sampleTickMs)
        {
            std::uint64_t readOperationDelta = 0U;
            std::uint64_t writeOperationDelta = 0U;
            const bool cumulativeEpochContinues =
                sample.bytesRead >= baselineIterator->bytesRead &&
                sample.bytesWritten >= baselineIterator->bytesWritten &&
                sample.readTime100ns >=
                    baselineIterator->readTime100ns &&
                sample.writeTime100ns >=
                    baselineIterator->writeTime100ns &&
                sample.idleTime100ns >=
                    baselineIterator->idleTime100ns &&
                sample.queryTime100ns >
                    baselineIterator->queryTime100ns &&
                counter32Delta(
                    sample.readCount,
                    baselineIterator->readCount,
                    &readOperationDelta) &&
                counter32Delta(
                    sample.writeCount,
                    baselineIterator->writeCount,
                    &writeOperationDelta);

            if (cumulativeEpochContinues)
            {
                const std::uint64_t elapsedMs =
                    sample.sampleTickMs -
                    baselineIterator->sampleTickMs;
                const std::uint64_t queryDelta =
                    sample.queryTime100ns -
                    baselineIterator->queryTime100ns;
                const std::uint64_t monotonicDelta100ns =
                    elapsedMs <=
                        std::numeric_limits<std::uint64_t>::max() / 10000U
                    ? elapsedMs * 10000U
                    : std::numeric_limits<std::uint64_t>::max();

                // QueryTime 是系统时间戳。与 IOCTL 附近的单调间隔明显
                // 不一致时，视为系统调时/计数器 epoch 变化并重建基线。
                const bool queryIntervalConsistent =
                    queryDelta > 0U &&
                    monotonicDelta100ns > 0U &&
                    queryDelta >= monotonicDelta100ns / 4U &&
                    queryDelta <=
                        (monotonicDelta100ns <=
                             std::numeric_limits<std::uint64_t>::max() / 4U
                             ? monotonicDelta100ns * 4U
                             : std::numeric_limits<std::uint64_t>::max());
                if (queryIntervalConsistent)
                {
                    const double elapsedSeconds =
                        static_cast<double>(elapsedMs) / 1000.0;
                    readRate =
                        static_cast<double>(
                            sample.bytesRead -
                            baselineIterator->bytesRead) /
                        elapsedSeconds;
                    writeRate =
                        static_cast<double>(
                            sample.bytesWritten -
                            baselineIterator->bytesWritten) /
                        elapsedSeconds;

                    const std::uint64_t idleDelta =
                        sample.idleTime100ns -
                        baselineIterator->idleTime100ns;
                    const std::uint64_t busyDelta =
                        queryDelta > idleDelta
                        ? queryDelta - idleDelta
                        : 0U;
                    activePercent = std::clamp(
                        static_cast<double>(busyDelta) * 100.0 /
                        static_cast<double>(queryDelta),
                        0.0,
                        100.0);

                    const std::uint64_t operationDelta =
                        readOperationDelta + writeOperationDelta;
                    const std::uint64_t operationTimeDelta =
                        (sample.readTime100ns -
                         baselineIterator->readTime100ns) +
                        (sample.writeTime100ns -
                         baselineIterator->writeTime100ns);
                    if (operationDelta > 0U)
                    {
                        responseTimeMs =
                            static_cast<double>(operationTimeDelta) /
                            static_cast<double>(operationDelta) /
                            10000.0;
                        responseTimeAvailable = true;
                    }
                    rateAvailable = true;
                    ++validRateSampleCount;
                }
            }
        }

        // 身份完整且本轮性能值有效时才刷新整组基线。
        if (!baselineKey.isEmpty() && sample.performanceAvailable)
        {
            StorageBaseline nextBaseline;
            nextBaseline.sampleTickMs = sample.sampleTickMs;
            nextBaseline.bytesRead = sample.bytesRead;
            nextBaseline.bytesWritten = sample.bytesWritten;
            nextBaseline.readCount = sample.readCount;
            nextBaseline.writeCount = sample.writeCount;
            nextBaseline.readTime100ns = sample.readTime100ns;
            nextBaseline.writeTime100ns = sample.writeTime100ns;
            nextBaseline.idleTime100ns = sample.idleTime100ns;
            nextBaseline.queryTime100ns = sample.queryTime100ns;
            nextBaseline.performanceAvailable = true;
            nextBaselineByIdentity.insert(baselineKey, nextBaseline);
        }
        if (sample.performanceAvailable && !rateAvailable)
        {
            ++baselinePendingCount;
        }

        const int rowIndex = static_cast<int>(sampleIndex);
        m_table->setItem(
            rowIndex,
            kStorageColumnDrive,
            createStorageItem(sample.driveRoot));
        m_table->setItem(
            rowIndex,
            kStorageColumnLabel,
            createStorageItem(
                sample.volumeLabel.isEmpty()
                    ? QStringLiteral("-")
                    : sample.volumeLabel));
        m_table->setItem(
            rowIndex,
            kStorageColumnFileSystem,
            createStorageItem(
                sample.fileSystemName.isEmpty()
                    ? QStringLiteral("-")
                    : sample.fileSystemName));
        m_table->setItem(
            rowIndex,
            kStorageColumnActiveTime,
            createStorageItem(
                rateAvailable
                    ? QStringLiteral("%1%").arg(activePercent, 0, 'f', 1)
                    : QStringLiteral("N/A"),
                rateAvailable
                    ? activePercent
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnAvailable,
            createStorageItem(
                sample.capacityAvailable
                    ? formatBytes(static_cast<double>(sample.availableBytes))
                    : QStringLiteral("N/A"),
                sample.capacityAvailable
                    ? static_cast<double>(sample.availableBytes)
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnTotal,
            createStorageItem(
                sample.capacityAvailable
                    ? formatBytes(static_cast<double>(sample.totalBytes))
                    : QStringLiteral("N/A"),
                sample.capacityAvailable
                    ? static_cast<double>(sample.totalBytes)
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnReadRate,
            createStorageItem(
                rateAvailable ? formatRate(readRate) : QStringLiteral("N/A"),
                rateAvailable
                    ? readRate
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnWriteRate,
            createStorageItem(
                rateAvailable ? formatRate(writeRate) : QStringLiteral("N/A"),
                rateAvailable
                    ? writeRate
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnResponse,
            createStorageItem(
                responseTimeAvailable
                    ? QStringLiteral("%1").arg(responseTimeMs, 0, 'f', 2)
                    : QStringLiteral("N/A"),
                responseTimeAvailable
                    ? responseTimeMs
                    : std::numeric_limits<double>::quiet_NaN()));
        m_table->setItem(
            rowIndex,
            kStorageColumnQueueDepth,
            createStorageItem(
                sample.performanceAvailable
                    ? QString::number(sample.queueDepth)
                    : QStringLiteral("N/A"),
                sample.performanceAvailable
                    ? static_cast<double>(sample.queueDepth)
                    : std::numeric_limits<double>::quiet_NaN()));

        if (rateAvailable)
        {
            highestActivePercent =
                std::max(highestActivePercent, activePercent);
            totalReadRate += readRate;
            totalWriteRate += writeRate;
        }
    }

    sampleBatch.baselinePendingCount = baselinePendingCount;
    m_baselineByIdentity = std::move(nextBaselineByIdentity);
    if (!sampleBatch.enumerationSucceeded)
    {
        if (sampleList.empty())
        {
            m_table->setRowCount(1);
            m_table->setItem(
                0,
                kStorageColumnDrive,
                createStorageItem(
                    QStringLiteral("存储枚举失败，错误码：%1")
                        .arg(sampleBatch.enumerationError)));
            m_table->setSpan(
                0,
                kStorageColumnDrive,
                1,
                kStorageColumnCount);
        }
        m_summaryText = QStringLiteral(
            "存储：枚举未完成（错误 %1）    已取得性能：%2    等待基线：%3    采集失败：%4    汇总：N/A")
            .arg(sampleBatch.enumerationError)
            .arg(sampleBatch.performanceAvailableCount)
            .arg(sampleBatch.baselinePendingCount)
            .arg(sampleBatch.failedPerformanceCount);
    }
    else if (sampleBatch.fixedVolumeCount == 0)
    {
        m_table->setRowCount(1);
        m_table->setItem(
            0,
            kStorageColumnDrive,
            createStorageItem(QStringLiteral("未发现可用的本机固定卷")));
        m_table->setSpan(0, kStorageColumnDrive, 1, kStorageColumnCount);
        m_summaryText = QStringLiteral("存储：未发现可用固定卷");
    }
    else if (validRateSampleCount ==
                 sampleBatch.fixedVolumeCount &&
             sampleBatch.baselinePendingCount == 0 &&
             sampleBatch.failedPerformanceCount == 0)
    {
        m_summaryText = QStringLiteral(
            "存储：%1 个卷    最高活动时间：%2%    总吞吐：%3")
            .arg(sampleBatch.fixedVolumeCount)
            .arg(highestActivePercent, 0, 'f', 1)
            .arg(formatRate(totalReadRate + totalWriteRate));
    }
    else
    {
        const QString activeSummary =
            validRateSampleCount > 0
            ? QStringLiteral("%1%").arg(
                highestActivePercent,
                0,
                'f',
                1)
            : QStringLiteral("N/A");
        const QString throughputSummary =
            validRateSampleCount > 0
            ? formatRate(totalReadRate + totalWriteRate)
            : QStringLiteral("N/A");
        m_summaryText = QStringLiteral(
            "存储：有效 %1/%2 个卷（部分）    等待基线：%3    采集失败：%4    有效卷最高活动：%5    有效卷总吞吐：%6")
            .arg(validRateSampleCount)
            .arg(sampleBatch.fixedVolumeCount)
            .arg(sampleBatch.baselinePendingCount)
            .arg(sampleBatch.failedPerformanceCount)
            .arg(activeSummary)
            .arg(throughputSummary);
    }
    m_table->setSortingEnabled(sortingWasEnabled);
}

QString DiskMonitorStoragePanel::summaryText() const
{
    return m_summaryText;
}

QString DiskMonitorStoragePanel::formatBytes(const double byteCount)
{
    static const QStringList unitList = {
        QStringLiteral("B"),
        QStringLiteral("KB"),
        QStringLiteral("MB"),
        QStringLiteral("GB"),
        QStringLiteral("TB")
    };
    double displayValue = std::max(0.0, byteCount);
    int unitIndex = 0;
    while (displayValue >= 1024.0 && unitIndex + 1 < unitList.size())
    {
        displayValue /= 1024.0;
        ++unitIndex;
    }
    const int precision = unitIndex == 0 ? 0 : (displayValue >= 100.0 ? 0 : 1);
    return QStringLiteral("%1 %2")
        .arg(displayValue, 0, 'f', precision)
        .arg(unitList[unitIndex]);
}

QString DiskMonitorStoragePanel::formatRate(const double bytesPerSecond)
{
    return QStringLiteral("%1/s").arg(formatBytes(bytesPerSecond));
}
