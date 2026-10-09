#include "MemoryDock.Internal.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/X64DbgNavigation.h"
#include "../UI/MemoryWorkbench/WorkbenchTarget.h" // AcquireAnchorForPid：与工作台锚点同一取法读进程创建时间。

#include <QCoreApplication>
#include <QImage>
#include <QPixmap>
#include <QRunnable>
#include <QSaveFile>
#include <QSet>
#include <QThread> // QThread::idealThreadCount：CPU 占用率的分母要按逻辑核数归一化。
#include <QVector>

#include <algorithm> // std::clamp / std::max：占用率夹取与核数下界。
#include <functional>
#include <memory>
#include <utility>

#include <Shellapi.h>

#pragma comment(lib, "Shell32.lib")

// 说明：由原聚合式实现迁移为独立 .cpp，成员函数实现保持原样。
using namespace ksword::memory_dock_internal;

// ============================================================
// MemoryDock.ProcessRegion.cpp
// 作用：
// - 负责进程列表、模块列表、内存区域枚举与过滤展示。
// - 聚焦“附加目标与地址空间概览”能力。
// ============================================================

namespace
{
    // processRegionTableRowText 作用：
    // - 输入：MemoryDock 进程/区域等普通表格和行号；
    // - 处理：按列顺序读取整行文本，隐藏列也保留，方便复制 PID/Session 上下文；
    // - 返回：TSV 文本，行无效时返回空字符串。
    QString processRegionTableRowText(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return QString();
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        return fields.join(QLatin1Char('\t'));
    }

    // copyProcessRegionTableRow 作用：
    // - 输入：目标表格和行号；
    // - 处理：把整行 TSV 写入系统剪贴板；
    // - 返回：无，剪贴板不可用或行无效时直接返回。
    void copyProcessRegionTableRow(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const QString rowText = processRegionTableRowText(table, rowIndex);
        if (!rowText.isEmpty())
        {
            QApplication::clipboard()->setText(rowText);
        }
    }

    // ============================================================
    // 异步刷新状态寄存
    // 说明：本轮改造不扩充 MemoryDock.h 的成员，刷新代次/在途标记全部寄存在
    // MemoryDock 对象自身的动态属性上。动态属性只在 UI 线程读写，且随控件析构
    // 一起释放，不会像“按实例地址索引的文件级静态表”那样泄漏或串号。
    // ============================================================

    // 进程列表刷新代次：每提交一次后台枚举自增一次，回投结果按它淘汰过期快照。
    constexpr const char* kProcessRefreshGenerationProperty = "kswordMemoryProcessRefreshGeneration";
    // 进程列表刷新是否在途：在途期间新请求只合并成待办，不叠加第二次 Toolhelp 快照。
    constexpr const char* kProcessRefreshInFlightProperty = "kswordMemoryProcessRefreshInFlight";
    // 进程列表是否存在待补刷新，以及该待补请求是否要求保留当前选择。
    constexpr const char* kProcessRefreshPendingProperty = "kswordMemoryProcessRefreshPending";
    constexpr const char* kProcessRefreshPendingKeepSelectionProperty =
        "kswordMemoryProcessRefreshPendingKeepSelection";
    // 跨页跳转登记的待定位 PID：进程表由异步结果重建，定位只能等回填后再做。
    constexpr const char* kProcessFocusPendingPidProperty = "kswordMemoryProcessFocusPendingPid";
    // 区域枚举是否在途，以及是否存在待补的区域刷新请求。
    constexpr const char* kRegionRefreshInFlightProperty = "kswordMemoryRegionRefreshInFlight";
    constexpr const char* kRegionRefreshPendingProperty = "kswordMemoryRegionRefreshPending";
    // 本次区域刷新是否由附加流程发起：附加按钮必须立即还控制权，禁止同步遍历地址空间。
    constexpr const char* kRegionRefreshFromAttachProperty = "kswordMemoryRegionRefreshFromAttach";
    constexpr const char* kProcessDumpInFlightProperty = "ksword_memory_process_dump_in_flight";

    // 图标路径角色：进程表第 0 列与模块树路径列都用它记录图标来源路径，
    // 后台提取完成后按路径反查需要刷新的行。UserRole/UserRole+1 已被其它数据占用。
    constexpr int kIconPathItemRole = Qt::UserRole + 2;

    // readBoolProperty 作用：
    // - 输入：属性宿主对象与属性名；
    // - 处理：读取布尔动态属性，属性未设置时按 false 处理；
    // - 返回：属性当前布尔值。
    bool readBoolProperty(const QObject* const propertyOwner, const char* const propertyName)
    {
        return propertyOwner != nullptr && propertyOwner->property(propertyName).toBool();
    }

    // bumpGenerationProperty 作用：
    // - 输入：属性宿主对象与代次属性名；
    // - 处理：把代次自增一次并写回，只允许 UI 线程调用；
    // - 返回：本次请求应携带的新代次。
    quint64 bumpGenerationProperty(QObject* const propertyOwner, const char* const propertyName)
    {
        const quint64 nextGeneration = propertyOwner->property(propertyName).toULongLong() + 1ULL;
        propertyOwner->setProperty(propertyName, QVariant::fromValue(nextGeneration));
        return nextGeneration;
    }

    // ============================================================
    // 图标异步解析
    // 说明：QIcon/QPixmap/QFileIconProvider 只能在 UI 线程使用，工作线程一律
    // 只产出可跨线程搬运的 QImage，落地成 QIcon 与写回表格都回到 UI 线程执行。
    // ============================================================

    // pathIconCache 作用：
    // - 输入：无；
    // - 处理：提供按绝对路径索引的图标缓存，只允许 UI 线程访问；
    // - 返回：进程与模块共用的缓存引用。
    QHash<QString, QIcon>& pathIconCache()
    {
        static QHash<QString, QIcon> iconCacheByPath;
        return iconCacheByPath;
    }

    // IconApplyCallback：图标落地后在 UI 线程执行的回写动作（入参为路径与已构造图标）。
    using IconApplyCallback = std::function<void(const QString&, const QIcon&)>;

    // pathIconWaiterTable 作用：
    // - 输入：无；
    // - 处理：记录每个在途路径的回写等待者，同路径的重复请求只追加等待者，
    //   不重复向 Shell 发起查询（多个 MemoryDock 实例共存时同样成立）；
    // - 返回：等待表引用，只允许 UI 线程访问。
    QHash<QString, QVector<IconApplyCallback>>& pathIconWaiterTable()
    {
        static QHash<QString, QVector<IconApplyCallback>> waiterTableByPath;
        return waiterTableByPath;
    }

    // fallbackPathIcon 作用：
    // - 输入：无；
    // - 处理：提供图标尚未解析或解析失败时使用的占位图标；
    // - 返回：共享占位图标引用。
    const QIcon& fallbackPathIcon()
    {
        static const QIcon placeholderIcon(QStringLiteral(":/Icon/process_main.svg"));
        return placeholderIcon;
    }

    // extractShellIconImageFromPath 作用：
    // - 输入：可执行文件或模块的绝对路径；
    // - 处理：在工作线程向 Windows Shell 查询小图标并复制成独立位图；
    // - 返回：解析成功返回 QImage，失败返回空 QImage。
    QImage extractShellIconImageFromPath(const QString& absolutePath)
    {
        // shellFileInfo 持有 Shell 分配的 HICON，转换成 QImage 后必须显式销毁。
        SHFILEINFOW shellFileInfo{};
        const DWORD_PTR shellQueryResult = ::SHGetFileInfoW(
            reinterpret_cast<const wchar_t*>(absolutePath.utf16()),
            0,
            &shellFileInfo,
            sizeof(shellFileInfo),
            SHGFI_ICON | SHGFI_SMALLICON);
        if (shellQueryResult == 0 || shellFileInfo.hIcon == nullptr)
        {
            return QImage();
        }

        QImage iconImage = QImage::fromHICON(shellFileInfo.hIcon);
        ::DestroyIcon(shellFileInfo.hIcon);
        return iconImage;
    }

    // lookupCachedPathIcon 作用：
    // - 输入：绝对路径；
    // - 处理：只查缓存，绝不触发任何磁盘或 Shell 查询，保证建表阶段零阻塞；
    // - 返回：命中返回缓存图标，未命中返回占位图标。
    QIcon lookupCachedPathIcon(const QString& absolutePath)
    {
        const QString normalizedPath = absolutePath.trimmed();
        if (normalizedPath.isEmpty())
        {
            return fallbackPathIcon();
        }

        const auto cachedIt = pathIconCache().constFind(normalizedPath);
        if (cachedIt != pathIconCache().constEnd())
        {
            return cachedIt.value();
        }
        return fallbackPathIcon();
    }

    // queuePathIconExtraction 作用：
    // - 输入：绝对路径与图标落地后的 UI 线程回写动作；
    // - 处理：缓存未命中时提交线程池任务做 Shell 查询，同路径并发请求合并成一个任务；
    // - 返回：无，回写动作只会在 UI 线程被调用一次。
    void queuePathIconExtraction(const QString& absolutePath, IconApplyCallback applyIconOnUiThread)
    {
        const QString normalizedPath = absolutePath.trimmed();
        if (normalizedPath.isEmpty() || pathIconCache().contains(normalizedPath))
        {
            return;
        }

        auto waiterIt = pathIconWaiterTable().find(normalizedPath);
        if (waiterIt != pathIconWaiterTable().end())
        {
            waiterIt.value().push_back(std::move(applyIconOnUiThread));
            return;
        }
        pathIconWaiterTable().insert(
            normalizedPath,
            QVector<IconApplyCallback>{ std::move(applyIconOnUiThread) });

        QRunnable* const extractionTask = QRunnable::create([normalizedPath]() {
            QImage iconImage = extractShellIconImageFromPath(normalizedPath);
            QCoreApplication* const appInstance = QCoreApplication::instance();
            if (appInstance == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                appInstance,
                [normalizedPath, iconImage = std::move(iconImage)]() mutable {
                    // QPixmap/QIcon 构造推迟到这里，确保只发生在 UI 线程。
                    QIcon resolvedIcon = fallbackPathIcon();
                    if (!iconImage.isNull())
                    {
                        const QPixmap iconPixmap = QPixmap::fromImage(iconImage);
                        if (!iconPixmap.isNull())
                        {
                            resolvedIcon = QIcon(iconPixmap);
                        }
                    }
                    pathIconCache().insert(normalizedPath, resolvedIcon);

                    const QVector<IconApplyCallback> waiterList =
                        pathIconWaiterTable().take(normalizedPath);
                    for (const IconApplyCallback& waiterCallback : waiterList)
                    {
                        waiterCallback(normalizedPath, resolvedIcon);
                    }
                },
                Qt::QueuedConnection);
            });
        extractionTask->setAutoDelete(true);
        QThreadPool::globalInstance()->start(extractionTask);
    }

    // applyIconToProcessTableRows 作用：
    // - 输入：进程表、图标对应的映像路径与已构造好的图标；
    // - 处理：进程表允许排序，行号与缓存下标不再等价，只能按路径逐行反查回写；
    // - 返回：无。
    void applyIconToProcessTableRows(
        QTableWidget* const processTable,
        const QString& imagePath,
        const QIcon& resolvedIcon)
    {
        if (processTable == nullptr)
        {
            return;
        }

        for (int rowIndex = 0; rowIndex < processTable->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* const processNameItem = processTable->item(rowIndex, 0);
            if (processNameItem != nullptr &&
                processNameItem->data(kIconPathItemRole).toString() == imagePath)
            {
                processNameItem->setIcon(resolvedIcon);
            }
        }
    }

    // applyIconToModuleTreeRows 作用：
    // - 输入：模块树、路径列下标、图标对应的模块路径与已构造好的图标；
    // - 处理：按路径反查所有匹配节点并回写图标，不重建整棵树；
    // - 返回：无。
    void applyIconToModuleTreeRows(
        QTreeWidget* const moduleTree,
        const int pathColumnIndex,
        const QString& modulePath,
        const QIcon& resolvedIcon)
    {
        if (moduleTree == nullptr)
        {
            return;
        }

        for (int itemIndex = 0; itemIndex < moduleTree->topLevelItemCount(); ++itemIndex)
        {
            QTreeWidgetItem* const rowItem = moduleTree->topLevelItem(itemIndex);
            if (rowItem != nullptr &&
                rowItem->data(pathColumnIndex, kIconPathItemRole).toString() == modulePath)
            {
                rowItem->setIcon(pathColumnIndex, resolvedIcon);
            }
        }
    }

    // selectProcessRowByPid 作用：
    // - 输入：进程表、进程下拉框与目标 PID；
    // - 处理：定位目标行并滚动到可视区域，同时把下拉框切到同一目标（值未变化时不重设，
    //   避免多触发一次 currentIndexChanged 引起的模块重复枚举）；
    // - 返回：进程表命中并选中时返回 true。
    bool selectProcessRowByPid(
        QTableWidget* const processTable,
        QComboBox* const processCombo,
        const std::uint32_t pid)
    {
        bool rowSelected = false;
        if (processTable != nullptr)
        {
            for (int rowIndex = 0; rowIndex < processTable->rowCount(); ++rowIndex)
            {
                QTableWidgetItem* const pidItem = processTable->item(rowIndex, 1);
                if (pidItem == nullptr || pidItem->text().toUInt() != pid)
                {
                    continue;
                }
                processTable->selectRow(rowIndex);
                processTable->scrollToItem(pidItem, QAbstractItemView::PositionAtCenter);
                rowSelected = true;
                break;
            }
        }

        if (processCombo != nullptr)
        {
            const int comboIndex =
                processCombo->findData(QVariant::fromValue(static_cast<uint>(pid)), Qt::UserRole);
            if (comboIndex >= 0 && comboIndex != processCombo->currentIndex())
            {
                processCombo->setCurrentIndex(comboIndex);
            }
        }
        return rowSelected;
    }

    // ============================================================
    // 后台采集数据结构
    // 说明：MemoryDock::ProcessEntry / RegionEntry 都是私有嵌套类型，无法出现在
    // 文件级函数签名里，这里用等价的纯值类型承载采集结果，回到 UI 线程后再转换。
    // ============================================================

    // ProcessSnapshotRow 作用：
    // - 保存后台线程采集到的单个进程信息，字段全部是值类型，可安全跨线程搬运。
    struct ProcessSnapshotRow
    {
        std::uint32_t pid = 0;          // 进程 PID。
        std::uint32_t sessionId = 0;    // 会话 ID。
        QString processName;            // 进程名（Toolhelp 快照给出的映像文件名）。
        QString imagePath;              // 映像完整路径，供图标解析使用（可能为空）。
        double workingSetMB = 0.0;      // 工作集大小（MB），查询失败时保持 0。
        // CPU 占用没法一次采样得出，只能靠两次采样之间的增量。这里只带回本次的
        // 累计 CPU 时间与它是否取到，占用率由 UI 线程与上一轮相减算出。
        std::uint64_t cpuTime100ns = 0; // 内核态 + 用户态累计时间，单位 100ns。
        std::uint64_t creationTime100ns = 0; // Bind address navigation to this snapshot's process object.
        bool cpuTimeValid = false;      // 取不到时间的进程（权限不足、已退出）保持 false。
    };

    // kProcessNumericSortRole：数值排序键。
    constexpr int kProcessNumericSortRole = Qt::UserRole + 50;
    constexpr int kProcessCreationTimeRole = Qt::UserRole + 51;

    // NumericSortTableItem 作用：
    // - 显示带单位的文本，排序按藏在角色里的裸数值。
    //
    // 为什么必须自定义：QTableWidgetItem 的默认 operator< 比的是 **DisplayRole**，
    // 也就是带单位的那串文本，按字典序排。于是 "10.00%" 会排在 "9.00%" 前面、
    // "100.0 MB" 排在 "9.0 MB" 前面。工作集正是用来从一堆同名进程里挑出主进程的
    // 那一列，排错了这一列就完全失去意义，而且排错了不会报任何错。
    class NumericSortTableItem final : public QTableWidgetItem
    {
    public:
        NumericSortTableItem(const QString& displayText, const double sortValue)
        {
            setData(Qt::DisplayRole, displayText);
            setData(kProcessNumericSortRole, sortValue);
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            const QVariant leftValue = data(kProcessNumericSortRole);
            const QVariant rightValue = other.data(kProcessNumericSortRole);
            if (leftValue.isValid() && rightValue.isValid())
            {
                return leftValue.toDouble() < rightValue.toDouble();
            }
            return QTableWidgetItem::operator<(other);
        }
    };

    // ProcessSnapshotResult 作用：
    // - 保存一次进程枚举的完整结果与失败原因，由 UI 线程决定是否弹出提示。
    struct ProcessSnapshotResult
    {
        bool snapshotCreated = false;       // CreateToolhelp32Snapshot 是否成功。
        bool enumerationStarted = false;    // Process32FirstW 是否成功。
        std::uint32_t lastErrorCode = 0;    // 失败时的 Win32 错误码。
        std::vector<ProcessSnapshotRow> rows; // 按 PID 升序排列的进程快照。
        // 采样时刻，单位 100ns，与 cpuTime100ns 同一量纲。CPU 占用率 =
        // CPU 时间增量 / (墙上时间增量 × 逻辑核数)，分母必须用这个时刻算，
        // 不能用"刷新间隔"这种名义值——刷新被推迟或提前时名义值就不成立了。
        std::uint64_t sampleTime100ns = 0;
    };

    // collectProcessSnapshotRows 作用：
    // - 输入：无；
    // - 处理：在工作线程完成 Toolhelp 快照、会话查询、工作集查询与映像路径解析，
    //   全程不触碰任何 Qt 控件；
    // - 返回：按 PID 升序排序的采集结果（含失败原因）。
    ProcessSnapshotResult collectProcessSnapshotRows()
    {
        ProcessSnapshotResult snapshotResult;

        // 进程枚举按需求使用 Toolhelp 快照接口。
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            snapshotResult.lastErrorCode = static_cast<std::uint32_t>(::GetLastError());
            return snapshotResult;
        }
        snapshotResult.snapshotCreated = true;

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(snapshotHandle, &processEntry) == FALSE)
        {
            snapshotResult.lastErrorCode = static_cast<std::uint32_t>(::GetLastError());
            ::CloseHandle(snapshotHandle);
            return snapshotResult;
        }
        snapshotResult.enumerationStarted = true;

        do
        {
            ProcessSnapshotRow snapshotRow;
            snapshotRow.pid = static_cast<std::uint32_t>(processEntry.th32ProcessID);
            snapshotRow.processName = QString::fromWCharArray(processEntry.szExeFile);

            DWORD sessionId = 0;
            if (::ProcessIdToSessionId(toDwordPid(snapshotRow.pid), &sessionId) != FALSE)
            {
                snapshotRow.sessionId = static_cast<std::uint32_t>(sessionId);
            }

            // 尝试读取工作集大小：失败则保持 0，不影响主流程。
            HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE,
                toDwordPid(snapshotRow.pid));
            if (processHandle != nullptr)
            {
                PROCESS_MEMORY_COUNTERS_EX memoryCounter{};
                if (::GetProcessMemoryInfo(
                    processHandle,
                    reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryCounter),
                    sizeof(memoryCounter)) != FALSE)
                {
                    snapshotRow.workingSetMB =
                        static_cast<double>(memoryCounter.WorkingSetSize) / (1024.0 * 1024.0);
                }

                // 顺便在同一个句柄上取 CPU 累计时间：这里已经有
                // PROCESS_QUERY_LIMITED_INFORMATION，不必为它再开一次进程。
                FILETIME creationTime{};
                FILETIME exitTime{};
                FILETIME kernelTime{};
                FILETIME userTime{};
                if (::GetProcessTimes(
                    processHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE)
                {
                    const auto toU64 = [](const FILETIME& fileTime) {
                        return (static_cast<std::uint64_t>(fileTime.dwHighDateTime) << 32)
                            | static_cast<std::uint64_t>(fileTime.dwLowDateTime);
                    };
                    snapshotRow.creationTime100ns = toU64(creationTime);
                    snapshotRow.cpuTime100ns = toU64(kernelTime) + toU64(userTime);
                    snapshotRow.cpuTimeValid = true;
                }
                ::CloseHandle(processHandle);
            }

            // 映像路径解析内部还会再打开一次进程句柄，因此同样留在后台线程完成。
            snapshotRow.imagePath =
                QString::fromStdString(ks::process::QueryProcessPathByPid(snapshotRow.pid));

            snapshotResult.rows.push_back(std::move(snapshotRow));
        } while (::Process32NextW(snapshotHandle, &processEntry) != FALSE);
        ::CloseHandle(snapshotHandle);

        // 采样时刻取在遍历**之后**：整轮遍历本身要花时间，取在前面会让分母比
        // 实际观察窗口短，算出来的占用率偏高。取在后面则偏低一点点，宁可偏低。
        FILETIME sampleFileTime{};
        ::GetSystemTimeAsFileTime(&sampleFileTime);
        snapshotResult.sampleTime100ns =
            (static_cast<std::uint64_t>(sampleFileTime.dwHighDateTime) << 32)
            | static_cast<std::uint64_t>(sampleFileTime.dwLowDateTime);

        // 为了稳定展示顺序，这里按 PID 升序排序。
        std::sort(
            snapshotResult.rows.begin(),
            snapshotResult.rows.end(),
            [](const ProcessSnapshotRow& left, const ProcessSnapshotRow& right) {
                return left.pid < right.pid;
            });
        return snapshotResult;
    }

    // RegionSnapshotRow 作用：
    // - 保存后台线程采集到的单个虚拟内存区域，字段全部是值类型，可安全跨线程搬运。
    struct RegionSnapshotRow
    {
        std::uint64_t baseAddress = 0;  // 区域起始地址。
        std::uint64_t regionSize = 0;   // 区域大小（字节）。
        std::uint32_t protect = 0;      // 保护属性位（PAGE_*）。
        std::uint32_t state = 0;        // 状态（MEM_COMMIT / MEM_RESERVE / MEM_FREE）。
        std::uint32_t type = 0;         // 类型（MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE）。
        QString mappedFilePath;         // 映射文件路径（如果可获取）。
    };

    // collectVirtualMemoryRegionRows 作用：
    // - 输入：目标进程句柄（调用方保证遍历期间句柄一直有效）；
    // - 处理：从用户地址空间下限遍历到上限，IMAGE/MAPPED 区域附带解析映射文件路径，
    //   全程无 Qt 控件访问，可直接在线程池任务里执行；
    // - 返回：区域快照数组，地址空间不可读时返回空数组。
    std::vector<RegionSnapshotRow> collectVirtualMemoryRegionRows(const HANDLE processHandle)
    {
        std::vector<RegionSnapshotRow> regionRows;
        if (processHandle == nullptr)
        {
            return regionRows;
        }

        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);
        const std::uint64_t minAddress =
            reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const std::uint64_t maxAddress =
            reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);

        std::uint64_t currentAddress = minAddress;
        while (currentAddress < maxAddress)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            const SIZE_T querySize = ::VirtualQueryEx(
                processHandle,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(currentAddress)),
                &mbi,
                sizeof(mbi));
            if (querySize != sizeof(mbi))
            {
                break;
            }

            RegionSnapshotRow regionRow{};
            regionRow.baseAddress = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            regionRow.regionSize = static_cast<std::uint64_t>(mbi.RegionSize);
            regionRow.protect = static_cast<std::uint32_t>(mbi.Protect);
            regionRow.state = static_cast<std::uint32_t>(mbi.State);
            regionRow.type = static_cast<std::uint32_t>(mbi.Type);

            // IMAGE/MAPPED 区域尽量解析映射文件路径，便于用户定位模块。
            if (regionRow.state == MEM_COMMIT &&
                (regionRow.type == MEM_IMAGE || regionRow.type == MEM_MAPPED))
            {
                wchar_t mappedPath[MAX_PATH] = {};
                const DWORD length = ::GetMappedFileNameW(
                    processHandle,
                    mbi.BaseAddress,
                    mappedPath,
                    static_cast<DWORD>(std::size(mappedPath)));
                if (length > 0)
                {
                    regionRow.mappedFilePath =
                        QString::fromWCharArray(mappedPath, static_cast<int>(length));
                }
            }

            regionRows.push_back(std::move(regionRow));
            if (mbi.RegionSize == 0)
            {
                break;
            }

            const std::uint64_t nextAddress =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) +
                static_cast<std::uint64_t>(mbi.RegionSize);
            if (nextAddress <= currentAddress)
            {
                break;
            }
            currentAddress = nextAddress;
        }
        return regionRows;
    }

    // reportRegionEnumerateFailure 作用：
    // - 输入：承载对话框的父窗口与枚举失败文本；
    // - 处理：输出失败日志，优先走权限恢复提示，未被处理时退回普通告警框；
    // - 返回：无。同步兜底路径与异步回投路径共用同一套提示，避免行为分叉。
    void reportRegionEnumerateFailure(QWidget* const parentWidget, const QString& errorText)
    {
        kLogEvent regionEnumerateFailEvent;
        err << regionEnumerateFailEvent
            << "[MemoryDock] refreshMemoryRegionList: 枚举区域失败, error="
            << errorText.toStdString()
            << eol;

        // privilegePromptHandled：记录区域枚举失败是否已由权限恢复提示处理。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            parentWidget,
            QStringLiteral("枚举进程内存区域"),
            errorText);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(parentWidget, "区域刷新", errorText);
        }
    }
}

bool MemoryDock::isComboPopupVisible(QComboBox* const comboBox) const
{
    if (comboBox == nullptr)
    {
        return false;
    }
    // 进程组合框从 showPopup() 进入前置位，
    // 所以 qScrollEffect 暂时隐藏 QComboBoxPrivateContainer 时也不会误放行。
    if (comboBox == m_processCombo)
    {
        return m_processComboPopupLifecycleActive;
    }

    // 为非受保护子类保留无副作用兜底；不要调用 view()，它会惰性创建私有弹层。
    QWidget* const activePopupWidget = QApplication::activePopupWidget();
    return activePopupWidget != nullptr &&
        (activePopupWidget == comboBox || comboBox->isAncestorOf(activePopupWidget));
}

bool MemoryDock::isProcessComboPopupOpen()
{
    // 进程缓存回填不能在进程选择器弹层仍展开时提交。
    return isComboPopupVisible(m_processCombo);
}

bool MemoryDock::deferCommitWhileProcessComboPopupOpen(std::function<void()> commitAction)
{
    if (!commitAction)
    {
        return false;
    }
    if (!isProcessComboPopupOpen())
    {
        return false;
    }

    // 弹层展开时清空并重填下拉框会让弹层保持鼠标抓取而内容失效，
    // 表现就是“点了下拉框之后整个界面点不动”。这里只保留最新一次提交。
    kLogEvent deferCommitEvent;
    info << deferCommitEvent
        << "[MemoryDock] 进程下拉框展开中，推迟本轮进程列表提交。"
        << eol;
    m_processComboDeferredCommit = std::move(commitAction);
    return true;
}

void MemoryDock::flushProcessComboDeferredCommit()
{
    if (isProcessComboPopupOpen())
    {
        // 弹层又被打开，继续等待下一次收起。
        return;
    }

    if (!m_processComboDeferredCommit)
    {
        return;
    }

    std::function<void()> commitAction;
    commitAction.swap(m_processComboDeferredCommit);

    kLogEvent flushCommitEvent;
    info << flushCommitEvent
        << "[MemoryDock] 进程下拉框已收起，回投被推迟的进程列表提交。"
        << eol;
    // 完整进程快照提交一次完成列表与当前选择的回填。
    commitAction();
}

void MemoryDock::refreshProcessList(const bool keepSelection)
{
    // 输出刷新入口日志，记录是否尝试保留上次选择。
    kLogEvent refreshProcessStartEvent;
    info << refreshProcessStartEvent
        << "[MemoryDock] refreshProcessList: 开始刷新进程列表, keepSelection="
        << (keepSelection ? "true" : "false")
        << eol;

    // 兜底：弹层已收起但 Hide 回投丢失时，被推迟的旧提交在这里先落地，
    // 否则在途标记会一直挂着，进程列表再也不会更新。
    flushProcessComboDeferredCommit();

    // 已有枚举在途时不再叠加第二次 Toolhelp 快照：进程详情页一次 Tab 点击会连调两次，
    // 后到的请求合并成一个待办，等在途结果落地后再补一轮。
    if (readBoolProperty(this, kProcessRefreshInFlightProperty))
    {
        setProperty(kProcessRefreshPendingProperty, true);
        setProperty(kProcessRefreshPendingKeepSelectionProperty, keepSelection);
        return;
    }

    // 刷新前记录当前选择 PID，刷新后尽量恢复体验。
    std::uint32_t previousPid = 0;
    if (keepSelection)
    {
        const int index = m_processCombo->currentIndex();
        if (index >= 0)
        {
            previousPid = static_cast<std::uint32_t>(m_processCombo->itemData(index, Qt::UserRole).toUInt());
        }
    }

    // m_processCache 不在这里清空：清空到回填之间会让下拉框/R0 读写页读到空缓存，
    // 缓存与表格统一在回投后的提交阶段一次性替换。
    setProperty(kProcessRefreshInFlightProperty, true);
    const quint64 requestGeneration = bumpGenerationProperty(this, kProcessRefreshGenerationProperty);
    const QPointer<MemoryDock> guardedSelf(this);

    QRunnable* const refreshProcessTask = QRunnable::create([guardedSelf, requestGeneration, previousPid]() {
        // 后台线程只做纯数据采集：Toolhelp 快照、句柄查询、映像路径解析都不触碰 Qt 控件。
        ProcessSnapshotResult snapshotResult = collectProcessSnapshotRows();

        QCoreApplication* const appInstance = QCoreApplication::instance();
        if (appInstance == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(
            appInstance,
            [guardedSelf, requestGeneration, previousPid, snapshotResult = std::move(snapshotResult)]() mutable {
                if (guardedSelf == nullptr)
                {
                    return;
                }
                MemoryDock* const resultDock = guardedSelf.data();

                // 代次过期说明期间又发起了新一轮枚举，旧快照直接丢弃。
                if (resultDock->property(kProcessRefreshGenerationProperty).toULongLong() != requestGeneration)
                {
                    return;
                }

                if (!snapshotResult.snapshotCreated)
                {
                    kLogEvent snapshotFailEvent;
                    err << snapshotFailEvent
                        << "[MemoryDock] refreshProcessList: CreateToolhelp32Snapshot 失败, error="
                        << snapshotResult.lastErrorCode
                        << eol;
                    resultDock->setProperty(kProcessRefreshInFlightProperty, false);
                    resultDock->setProperty(kProcessRefreshPendingProperty, false);
                    QMessageBox::warning(resultDock, "进程刷新", "CreateToolhelp32Snapshot 失败。");
                    return;
                }
                if (!snapshotResult.enumerationStarted)
                {
                    kLogEvent processFirstFailEvent;
                    err << processFirstFailEvent
                        << "[MemoryDock] refreshProcessList: Process32FirstW 失败, error="
                        << snapshotResult.lastErrorCode
                        << eol;
                    resultDock->setProperty(kProcessRefreshInFlightProperty, false);
                    resultDock->setProperty(kProcessRefreshPendingProperty, false);
                    return;
                }

                const auto snapshotRows =
                    std::make_shared<std::vector<ProcessSnapshotRow>>(std::move(snapshotResult.rows));
                const std::uint64_t snapshotSampleTime = snapshotResult.sampleTime100ns;
                auto commitProcessSnapshot =
                    [guardedSelf, requestGeneration, previousPid, snapshotRows, snapshotSampleTime]() {
                    if (guardedSelf == nullptr)
                    {
                        return;
                    }
                    MemoryDock* const commitDock = guardedSelf.data();
                    if (commitDock->property(kProcessRefreshGenerationProperty).toULongLong() != requestGeneration)
                    {
                        return;
                    }

                    // 逻辑核数：占用率的分母要乘上它，否则一个跑满单核的进程在
                    // 16 核机器上会被算成 100%，而任务管理器给的是 6.25%，两边对不上。
                    const int logicalCoreCount =
                        (std::max)(1, QThread::idealThreadCount());

                    // 缓存与表格一次性替换，避免中途被其它页读到半成品。
                    commitDock->m_processCache.clear();
                    commitDock->m_processCache.reserve(snapshotRows->size());
                    QHash<std::uint32_t, ProcessCpuSample> freshCpuSamples;
                    freshCpuSamples.reserve(static_cast<int>(snapshotRows->size()));
                    for (const ProcessSnapshotRow& snapshotRow : *snapshotRows)
                    {
                        ProcessEntry entry{};
                        entry.pid = snapshotRow.pid;
                        entry.sessionId = snapshotRow.sessionId;
                        entry.processName = snapshotRow.processName;
                        entry.workingSetMB = snapshotRow.workingSetMB;

                        if (snapshotRow.cpuTimeValid)
                        {
                            freshCpuSamples.insert(
                                snapshotRow.pid,
                                ProcessCpuSample{
                                    snapshotRow.cpuTime100ns, snapshotSampleTime });

                            const auto previous =
                                commitDock->m_previousCpuSamples.constFind(snapshotRow.pid);
                            if (previous != commitDock->m_previousCpuSamples.constEnd()
                                && snapshotSampleTime > previous->sampleTime100ns
                                && snapshotRow.cpuTime100ns >= previous->cpuTime100ns)
                            {
                                // PID 会被系统回收：同一个 PID 的新进程 CPU 时间
                                // 从 0 重新开始，于是增量为负。上面那条 >= 判据把
                                // 这种情况挡掉，宁可这一轮显示"-"也不报一个假数。
                                const double cpuDelta = static_cast<double>(
                                    snapshotRow.cpuTime100ns - previous->cpuTime100ns);
                                const double wallDelta = static_cast<double>(
                                    snapshotSampleTime - previous->sampleTime100ns);
                                const double percent =
                                    (cpuDelta / (wallDelta * logicalCoreCount)) * 100.0;
                                // 采样窗口两端的取数不是同一瞬间完成的，极端情况下
                                // 算出来可能略微越界，夹一下再显示。
                                entry.cpuPercent = std::clamp(percent, 0.0, 100.0);
                                entry.cpuPercentValid = true;
                            }
                        }
                        commitDock->m_processCache.push_back(std::move(entry));
                    }
                    // 整表替换而不是逐条更新：已退出的进程必须随之消失，否则它的
                    // 采样会一直留着，等 PID 被复用时和新进程的时间相减。
                    commitDock->m_previousCpuSamples = std::move(freshCpuSamples);

                    // 先重建进程表。
                    QTableWidget* const processTable = commitDock->m_processTable;
                    processTable->setSortingEnabled(false);
                    processTable->setRowCount(static_cast<int>(snapshotRows->size()));
                    for (int row = 0; row < static_cast<int>(commitDock->m_processCache.size()); ++row)
                    {
                        // 缓存与快照行一一对应（同一份采集结果按同一顺序转换），
                        // 映像路径只保存在快照行里，仅用于图标解析。
                        const ProcessEntry& entry = commitDock->m_processCache[static_cast<std::size_t>(row)];
                        // 图标键统一用去空白后的路径，和后台提取任务、回写比对保持同一份文本。
                        const QString imagePath =
                            (*snapshotRows)[static_cast<std::size_t>(row)].imagePath.trimmed();

                        // 进程名前附加图标：缓存命中直接用，未命中先给占位图，
                        // Shell 查询在线程池完成后按路径回填对应单元格。
                        QTableWidgetItem* const processNameItem = new QTableWidgetItem(entry.processName);
                        processNameItem->setData(kIconPathItemRole, imagePath);
                        processNameItem->setData(kProcessCreationTimeRole,
                            QVariant::fromValue<qulonglong>((*snapshotRows)[static_cast<std::size_t>(row)].creationTime100ns));
                        processNameItem->setIcon(lookupCachedPathIcon(imagePath));
                        processTable->setItem(row, 0, processNameItem);

                        // PID / 会话 / CPU / 工作集四列一律用 NumericSortTableItem，
                        // 显示带单位的文本、排序按裸数值（理由见该类的注释）。
                        const auto makeNumericItem =
                            [](const QString& displayText, const double sortValue) {
                                return new NumericSortTableItem(displayText, sortValue);
                            };

                        processTable->setItem(row, 1, makeNumericItem(
                            QString::number(entry.pid), static_cast<double>(entry.pid)));
                        processTable->setItem(row, 2, makeNumericItem(
                            QString::number(entry.sessionId), static_cast<double>(entry.sessionId)));
                        // CPU 取不到时显示 "-" 而不是 0.00%：首次刷新、刚启动的进程、
                        // 权限不足取不到 CPU 时间，这三种都是"还不知道"，跟"空闲"
                        // 是两回事，显示成 0% 等于报了一个我们没有的读数。
                        processTable->setItem(row, 3, makeNumericItem(
                            entry.cpuPercentValid
                                ? (QString::number(entry.cpuPercent, 'f', 2) + "%")
                                : QStringLiteral("-"),
                            entry.cpuPercentValid ? entry.cpuPercent : -1.0));
                        processTable->setItem(row, 4, makeNumericItem(
                            QString("%1 MB").arg(entry.workingSetMB, 0, 'f', 1),
                            entry.workingSetMB));
                    }
                    processTable->setSortingEnabled(true);

                    // 刷新出来的新行默认全是可见的，必须立刻按当前关键字重新过滤
                    // 一遍。少了这一步，过滤框里留着关键字、列表却在下一次刷新后
                    // 悄悄变回全量——而用户并不会察觉自己看的已经不是过滤结果。
                    commitDock->applyProcessTableFilter();

                    // 未命中缓存的映像路径统一提交后台提取，回调只改对应单元格图标，不重建整表。
                    QSet<QString> queuedIconPaths;
                    for (const ProcessSnapshotRow& snapshotRow : *snapshotRows)
                    {
                        const QString imagePath = snapshotRow.imagePath.trimmed();
                        if (imagePath.isEmpty() || queuedIconPaths.contains(imagePath))
                        {
                            continue;
                        }
                        queuedIconPaths.insert(imagePath);
                        queuePathIconExtraction(
                            imagePath,
                            [guardedSelf](const QString& resolvedPath, const QIcon& resolvedIcon) {
                                if (guardedSelf == nullptr)
                                {
                                    return;
                                }
                                applyIconToProcessTableRows(
                                    guardedSelf->m_processTable,
                                    resolvedPath,
                                    resolvedIcon);
                            });
                    }

                    // 再同步重建顶部下拉框。
                    commitDock->updateProcessComboFromCache();

                    // 尝试恢复之前选中 PID。
                    if (previousPid != 0)
                    {
                        for (int comboIndex = 0; comboIndex < commitDock->m_processCombo->count(); ++comboIndex)
                        {
                            if (commitDock->m_processCombo->itemData(comboIndex, Qt::UserRole).toUInt() == previousPid)
                            {
                                commitDock->m_processCombo->setCurrentIndex(comboIndex);
                                break;
                            }
                        }
                    }

                    // 跨页跳转（focusProcessForOperations）登记的目标行只能等列表回填后再定位。
                    const std::uint32_t pendingFocusPid = static_cast<std::uint32_t>(
                        commitDock->property(kProcessFocusPendingPidProperty).toUInt());
                    if (pendingFocusPid != 0)
                    {
                        commitDock->setProperty(kProcessFocusPendingPidProperty, 0U);
                        selectProcessRowByPid(
                            commitDock->m_processTable,
                            commitDock->m_processCombo,
                            pendingFocusPid);
                    }

                    // 输出刷新结束日志，记录本轮进程总数与恢复 PID。
                    kLogEvent refreshProcessFinishEvent;
                    info << refreshProcessFinishEvent
                        << "[MemoryDock] refreshProcessList: 刷新完成, processCount="
                        << commitDock->m_processCache.size()
                        << ", previousPid="
                        << previousPid
                        << eol;

                    // 本轮结束后释放在途标记，并把合并下来的待办请求补一轮。
                    commitDock->setProperty(kProcessRefreshInFlightProperty, false);
                    if (commitDock->property(kProcessRefreshPendingProperty).toBool())
                    {
                        const bool pendingKeepSelection =
                            commitDock->property(kProcessRefreshPendingKeepSelectionProperty).toBool();
                        commitDock->setProperty(kProcessRefreshPendingProperty, false);
                        commitDock->refreshProcessList(pendingKeepSelection);
                    }
                };

                // 顶部进程下拉框展开时先缓存本次提交：正在展开的弹层被清空重填后
                // 会继续抓着鼠标，用户会看到整个界面卡住。
                if (resultDock->deferCommitWhileProcessComboPopupOpen(commitProcessSnapshot))
                {
                    return;
                }

                // 右键菜单打开时先缓存本次提交，避免把用户正在操作的行整表换掉。
                if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                        resultDock,
                        QStringLiteral("memory-process-list-snapshot-apply"),
                        {resultDock->m_processTable},
                        commitProcessSnapshot))
                {
                    return;
                }
                commitProcessSnapshot();
            },
            Qt::QueuedConnection);
        });
    refreshProcessTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshProcessTask);
}

void MemoryDock::syncTamperDetectionTargets()
{
    if (m_tamperDetectionPage == nullptr)
    {
        return;
    }
    m_tamperDetectionPage->setAttachedProcess(m_attachedPid, m_attachedProcessName);

    // 模块列表转成"可扫描目标"。只传基址和大小：篡改检测页不需要知道签名、
    // 入口点之类的东西，多传一份就会多一处需要同步的状态。
    std::vector<ksword::memory_dock::TamperDetectionPage::ModuleCandidate> candidates;
    candidates.reserve(m_moduleCache.size());
    for (const ModuleEntry& module : m_moduleCache)
    {
        ksword::memory_dock::TamperDetectionPage::ModuleCandidate candidate;
        candidate.displayText = QString("%1  (%2 KB)")
            .arg(module.moduleName)
            .arg(module.sizeBytes / 1024ULL);
        // 磁盘映像那条参考路径要按加载基址归一化文件字节，所以完整路径必须带过去。
        candidate.filePath = module.fullPath;
        candidate.baseAddress = module.baseAddress;
        candidate.sizeBytes = module.sizeBytes;
        candidates.push_back(std::move(candidate));
    }
    m_tamperDetectionPage->setModuleCandidates(candidates);
}

void MemoryDock::applyProcessTableFilter()
{
    if (m_processTable == nullptr)
    {
        return;
    }
    const QString keyword = (m_processFilterEdit != nullptr)
        ? m_processFilterEdit->text().trimmed()
        : QString();

    int shownRows = 0;
    const int totalRows = m_processTable->rowCount();
    for (int row = 0; row < totalRows; ++row)
    {
        bool matched = keyword.isEmpty();
        if (!matched)
        {
            // 进程名与 PID 任一命中即算命中：用户手里可能只有其中一个。
            const QTableWidgetItem* const nameItem = m_processTable->item(row, 0);
            const QTableWidgetItem* const pidItem = m_processTable->item(row, 1);
            matched =
                (nameItem != nullptr && nameItem->text().contains(keyword, Qt::CaseInsensitive))
                || (pidItem != nullptr && pidItem->text().contains(keyword, Qt::CaseInsensitive));
        }
        m_processTable->setRowHidden(row, !matched);
        if (matched)
        {
            ++shownRows;
        }
    }

    if (m_processCountLabel != nullptr)
    {
        m_processCountLabel->setText(keyword.isEmpty()
            ? QString("共 %1 个进程").arg(totalRows)
            : QString("显示 %1 / 共 %2").arg(shownRows).arg(totalRows));
    }
}

void MemoryDock::updateProcessComboFromCache()
{
    // 下拉框重建入口日志：记录缓存规模。
    kLogEvent comboUpdateEvent;
    dbg << comboUpdateEvent
        << "[MemoryDock] updateProcessComboFromCache: 重建下拉框, cacheSize="
        << m_processCache.size()
        << eol;

    // 下拉框重建期间阻断信号，防止反复触发模块刷新。
    QSignalBlocker blocker(m_processCombo);
    m_processCombo->clear();

    // 同名进程有几个：像 QQ 这种一开就是十个同名进程的程序，光看名字选不出
    // 目标，选错之后的表现是"地址读不到"，而读取代码其实完全正常——排查会被
    // 整个带偏到内存读取上去。所以同名时把工作集也显示出来：主进程和辅助进程
    // 的内存量差一两个数量级，一眼就能分开。
    QHash<QString, int> nameCount;
    for (const ProcessEntry& entry : m_processCache)
    {
        nameCount[entry.processName] += 1;
    }

    for (const ProcessEntry& entry : m_processCache)
    {
        QString text = QString("%1 [PID:%2]").arg(entry.processName).arg(entry.pid);
        if (nameCount.value(entry.processName) > 1)
        {
            text += QString(" · %1 MB · 同名 %2 个")
                .arg(entry.workingSetMB, 0, 'f', 0)
                .arg(nameCount.value(entry.processName));
        }
        m_processCombo->addItem(text, QVariant::fromValue(static_cast<uint>(entry.pid)));
        const int row = m_processCombo->count() - 1;
        m_processCombo->setItemData(row, entry.processName, Qt::UserRole + 1);
    }

    // 当前附加 PID 还存在时，默认选中它。
    bool selectedAttachedProcess = false;
    if (m_attachedPid != 0)
    {
        for (int comboIndex = 0; comboIndex < m_processCombo->count(); ++comboIndex)
        {
            if (m_processCombo->itemData(comboIndex, Qt::UserRole).toUInt() == m_attachedPid)
            {
                m_processCombo->setCurrentIndex(comboIndex);
                selectedAttachedProcess = true;
                break;
            }
        }
    }
    if (!selectedAttachedProcess && m_processCombo->count() > 0)
    {
        m_processCombo->setCurrentIndex(0);
    }

}

void MemoryDock::rebuildModuleTableFromCache()
{
    // 仅用缓存重绘模块表：该路径不会触发 Win32 枚举，适合输入过滤时高频调用。
    const QString filterText = (m_moduleFilterEdit == nullptr) ? QString() : m_moduleFilterEdit->text().trimmed();
    std::vector<const ModuleEntry*> filteredModules;
    filteredModules.reserve(m_moduleCache.size());
    for (const ModuleEntry& entry : m_moduleCache)
    {
        if (!filterText.isEmpty() &&
            !entry.moduleName.contains(filterText, Qt::CaseInsensitive) &&
            !entry.fullPath.contains(filterText, Qt::CaseInsensitive))
        {
            continue;
        }
        filteredModules.push_back(&entry);
    }

    // 批量更新期间关闭绘制和信号，减少重排开销并避免多余回调。
    m_moduleTable->setUpdatesEnabled(false);
    const QSignalBlocker tableBlocker(m_moduleTable);
    m_moduleTable->clear();

    // 图标按路径缓存：未命中时只放占位图并记录来源路径，绝不在这里同步问 Shell。
    // 模块动辄上百个，冷缓存时逐个 QFileIconProvider 查询会把首帧和过滤输入一起拖住。
    const int modulePathColumnIndex = toModuleTreeColumnIndex(ModuleTreeColumn::Path);
    for (const ModuleEntry* moduleEntryPtr : filteredModules)
    {
        const ModuleEntry& entry = *moduleEntryPtr;
        QTreeWidgetItem* rowItem = new QTreeWidgetItem();
        rowItem->setText(toModuleTreeColumnIndex(ModuleTreeColumn::Path), entry.fullPath);
        rowItem->setText(toModuleTreeColumnIndex(ModuleTreeColumn::Size), formatSize(entry.sizeBytes));
        rowItem->setText(toModuleTreeColumnIndex(ModuleTreeColumn::Signature), entry.signatureState);
        rowItem->setText(
            toModuleTreeColumnIndex(ModuleTreeColumn::EntryOffset),
            QString("0x%1").arg(entry.entryPointOffset, 0, 16).toUpper());
        rowItem->setText(toModuleTreeColumnIndex(ModuleTreeColumn::State), entry.runningState);
        rowItem->setText(toModuleTreeColumnIndex(ModuleTreeColumn::ThreadId), entry.threadIdText);
        // 图标键统一用去空白后的路径，和后台提取任务、回写比对保持同一份文本。
        const QString moduleIconPath = entry.fullPath.trimmed();
        rowItem->setIcon(modulePathColumnIndex, lookupCachedPathIcon(moduleIconPath));
        rowItem->setData(modulePathColumnIndex, kIconPathItemRole, moduleIconPath);

        // 保存基址与线程 ID，供双击跳转和右键动作反查。
        rowItem->setData(
            toModuleTreeColumnIndex(ModuleTreeColumn::Path),
            Qt::UserRole,
            QVariant::fromValue<qulonglong>(entry.baseAddress));
        rowItem->setData(
            toModuleTreeColumnIndex(ModuleTreeColumn::Path),
            Qt::UserRole + 1,
            QVariant::fromValue(entry.representativeThreadId));

        // 签名列颜色策略：可信绿、未知灰、不可信红。
        if (entry.signatureTrusted)
        {
            rowItem->setForeground(
                toModuleTreeColumnIndex(ModuleTreeColumn::Signature),
                KswordTheme::SuccessColor());
        }
        else if (entry.signatureState.compare("Pending", Qt::CaseInsensitive) == 0 ||
            entry.signatureState.compare("Unknown", Qt::CaseInsensitive) == 0)
        {
            rowItem->setForeground(
                toModuleTreeColumnIndex(ModuleTreeColumn::Signature),
                KswordTheme::TextSecondaryColor());
        }
        else
        {
            rowItem->setForeground(
                toModuleTreeColumnIndex(ModuleTreeColumn::Signature),
                KswordTheme::ErrorColor());
        }

        m_moduleTable->addTopLevelItem(rowItem);
    }

    // 排序仍按路径列执行，和原先交互习惯保持一致。
    m_moduleTable->sortItems(modulePathColumnIndex, Qt::AscendingOrder);
    m_moduleTable->setUpdatesEnabled(true);

    // 未命中缓存的模块路径统一提交线程池提取图标，回调只改对应节点，不重建整棵树。
    const QPointer<MemoryDock> guardedSelf(this);
    QSet<QString> queuedIconPaths;
    for (const ModuleEntry* moduleEntryPtr : filteredModules)
    {
        const QString modulePath = moduleEntryPtr->fullPath.trimmed();
        if (modulePath.isEmpty() || queuedIconPaths.contains(modulePath))
        {
            continue;
        }
        queuedIconPaths.insert(modulePath);
        queuePathIconExtraction(
            modulePath,
            [guardedSelf, modulePathColumnIndex](const QString& resolvedPath, const QIcon& resolvedIcon) {
                if (guardedSelf == nullptr)
                {
                    return;
                }
                applyIconToModuleTreeRows(
                    guardedSelf->m_moduleTable,
                    modulePathColumnIndex,
                    resolvedPath,
                    resolvedIcon);
            });
    }

    // 重绘结束日志：用于确认过滤后可见数量。
    kLogEvent rebuildModuleTableEvent;
    dbg << rebuildModuleTableEvent
        << "[MemoryDock] rebuildModuleTableFromCache: 完成, cacheCount="
        << m_moduleCache.size()
        << ", visibleCount="
        << filteredModules.size()
        << ", filterText="
        << filterText.toStdString()
        << eol;
}

bool MemoryDock::refreshModuleListForPid(const std::uint32_t pid)
{
    // 模块刷新改为异步，避免签名校验和模块枚举阻塞主线程。
    kLogEvent refreshModuleStartEvent;
    info << refreshModuleStartEvent
        << "[MemoryDock] refreshModuleListForPid: 请求刷新模块, pid="
        << pid
        << eol;

    if (pid == 0)
    {
        // pid 为 0 表示当前无有效目标，直接清空缓存和表格。
        m_moduleCache.clear();
        m_moduleCachePid = 0U;
        m_moduleCacheCreateTime = 0U;
        rebuildModuleTableFromCache();
        if (m_moduleStatusLabel != nullptr)
        {
            m_moduleStatusLabel->setText("● 未选择有效进程");
            m_moduleStatusLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
        }
        return false;
    }

    // 每次请求生成一个递增 ticket；旧任务回调时会被丢弃。
    const std::uint64_t refreshTicket = m_moduleRefreshTicket.fetch_add(1) + 1;
    const bool includeSignatureCheck =
        (m_moduleSignatureCheck != nullptr) && m_moduleSignatureCheck->isChecked();
    m_moduleRefreshInProgress.store(true);

    // 刷新期间更新状态栏并临时禁用按钮，避免用户误以为点击无效而反复触发。
    if (m_moduleRefreshButton != nullptr)
    {
        m_moduleRefreshButton->setEnabled(false);
    }
    if (m_moduleStatusLabel != nullptr)
    {
        m_moduleStatusLabel->setText(
            QString("● 正在刷新模块(PID=%1, 签名校验=%2)...")
            .arg(pid)
            .arg(includeSignatureCheck ? "开启" : "关闭"));
        m_moduleStatusLabel->setStyleSheet(
            QStringLiteral("color:%1; font-weight:700;").arg(KswordTheme::PrimaryBlueHex));
    }

    // 使用 QPointer 守护 this，避免窗口销毁后异步回调访问悬空对象。
    // 枚举走全局线程池而不是裸 detach 线程：连续切换进程时并发被池上限挡住，
    // 不会因为每次切换都新建一条线程把系统拖垮。
    const QPointer<MemoryDock> selfGuard(this);
    QRunnable* const refreshModuleTask = QRunnable::create(
        [selfGuard, pid, includeSignatureCheck, refreshTicket]() {
        if (selfGuard == nullptr)
        {
            return;
        }

        // 后台线程仅执行耗时枚举和数据转换，不直接操作任何 Qt 控件。
        // 先读一次目标进程的创建时间（与工作台锚点同一取法，取不到为 0）：缓存落地后它与 pid 一起
        // 记在 m_moduleCachePid / m_moduleCacheCreateTime，供模块表预览"未附加的进程"时核对进程实例。
        const ks::ui::AnchorInfo creationAnchor = ks::ui::AcquireAnchorForPid(pid);
        const std::uint64_t moduleCreateTime = creationAnchor.createTime100ns;
        ks::ui::ReleaseAnchorHandle(creationAnchor.handle);

        const auto refreshStartTime = std::chrono::steady_clock::now();
        const ks::process::ProcessModuleSnapshot moduleSnapshot =
            ks::process::EnumerateProcessModulesAndThreads(pid, includeSignatureCheck);

        std::vector<ModuleEntry> moduleCache;
        moduleCache.reserve(moduleSnapshot.modules.size());
        for (const ks::process::ProcessModuleRecord& moduleRecord : moduleSnapshot.modules)
        {
            ModuleEntry entry{};
            entry.fullPath = QString::fromStdString(moduleRecord.modulePath);
            entry.moduleName = QFileInfo(entry.fullPath).fileName();
            entry.baseAddress = moduleRecord.moduleBaseAddress;
            entry.sizeBytes = moduleRecord.moduleSizeBytes;
            entry.signatureState = QString::fromStdString(moduleRecord.signatureState);
            entry.signatureTrusted = moduleRecord.signatureTrusted;
            entry.entryPointOffset = moduleRecord.entryPointRva;
            entry.runningState = QString::fromStdString(moduleRecord.runningState);
            entry.threadIdText = QString::fromStdString(moduleRecord.threadIdText);
            entry.representativeThreadId = moduleRecord.representativeThreadId;
            moduleCache.push_back(std::move(entry));
        }
        std::sort(moduleCache.begin(), moduleCache.end(), [](const ModuleEntry& left, const ModuleEntry& right) {
            return left.baseAddress < right.baseAddress;
            });

        const std::uint64_t elapsedMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - refreshStartTime).count());
        const std::size_t moduleCount = moduleSnapshot.modules.size();
        const std::size_t threadCount = moduleSnapshot.threads.size();
        const QString diagnosticText = QString::fromStdString(moduleSnapshot.diagnosticText).trimmed();

        // 结果回到主线程落地，确保 Qt 视图更新线程安全。
        QMetaObject::invokeMethod(selfGuard.data(), [selfGuard,
            pid,
            moduleCreateTime,
            includeSignatureCheck,
            refreshTicket,
            elapsedMs,
            moduleCount,
            threadCount,
            diagnosticText,
            moduleCache = std::move(moduleCache)]() mutable {
                if (selfGuard == nullptr)
                {
                    return;
                }

                // 如果 ticket 已过期，说明用户又发起了新刷新，旧结果直接丢弃。
                if (refreshTicket < selfGuard->m_moduleRefreshTicket.load())
                {
                    kLogEvent staleModuleEvent;
                    dbg << staleModuleEvent
                        << "[MemoryDock] refreshModuleListForPid: 丢弃过期模块结果, ticket="
                        << refreshTicket
                        << ", latestTicket="
                        << selfGuard->m_moduleRefreshTicket.load()
                        << eol;
                    return;
                }

                auto moduleCacheSnapshot =
                    std::make_shared<std::vector<ModuleEntry>>(std::move(moduleCache));
                auto commitModuleSnapshot = [
                    selfGuard,
                    pid,
                    moduleCreateTime,
                    includeSignatureCheck,
                    refreshTicket,
                    elapsedMs,
                    moduleCount,
                    threadCount,
                    diagnosticText,
                    moduleCacheSnapshot]() mutable
                {
                    if (selfGuard == nullptr ||
                        refreshTicket < selfGuard->m_moduleRefreshTicket.load())
                    {
                        return;
                    }

                    // 缓存和树必须原子落地；菜单打开时不能先换缓存再保留旧节点。
                    selfGuard->m_moduleCache = std::move(*moduleCacheSnapshot);
                    selfGuard->m_moduleCachePid = pid;
                    selfGuard->m_moduleCacheCreateTime = moduleCreateTime;
                    selfGuard->rebuildModuleTableFromCache();
                    selfGuard->syncTamperDetectionTargets();

                    selfGuard->m_moduleRefreshInProgress.store(false);
                    if (selfGuard->m_moduleRefreshButton != nullptr)
                    {
                        selfGuard->m_moduleRefreshButton->setEnabled(true);
                    }

                    if (selfGuard->m_moduleStatusLabel != nullptr)
                    {
                        QString statusText = QString("● %1 ms | 模块:%2 线程:%3 显示:%4")
                            .arg(elapsedMs)
                            .arg(moduleCount)
                            .arg(threadCount)
                            .arg(selfGuard->m_moduleTable->topLevelItemCount());
                        if (!diagnosticText.isEmpty())
                        {
                            statusText += QStringLiteral(
                                " | 存在诊断；详情已写入日志。");
                        }
                        selfGuard->m_moduleStatusLabel->setText(statusText);
                        selfGuard->m_moduleStatusLabel->setStyleSheet(
                            QStringLiteral("color:%1; font-weight:%2;")
                                .arg(moduleCount == 0
                                    ? KswordTheme::ErrorColor().name(QColor::HexRgb)
                                    : KswordTheme::SuccessColor().name(QColor::HexRgb))
                                .arg(moduleCount == 0 ? 700 : 600));
                    }

                    kLogEvent refreshModuleFinishEvent;
                    info << refreshModuleFinishEvent
                        << "[MemoryDock] refreshModuleListForPid: 刷新完成, pid="
                        << pid
                        << ", elapsedMs="
                        << elapsedMs
                        << ", moduleCount="
                        << moduleCount
                        << ", threadCount="
                        << threadCount
                        << ", visibleCount="
                        << selfGuard->m_moduleTable->topLevelItemCount()
                        << ", includeSignatureCheck="
                        << (includeSignatureCheck ? "true" : "false")
                        << ", diagnostic="
                        << diagnosticText.toStdString()
                        << eol;
                };

                if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                        selfGuard.data(),
                        QStringLiteral("memory-process-modules-snapshot-apply"),
                        {selfGuard->m_moduleTable},
                        commitModuleSnapshot))
                {
                    return;
                }
                commitModuleSnapshot();
            }, Qt::QueuedConnection);
        });
    refreshModuleTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshModuleTask);

    return true;
}

bool MemoryDock::attachToProcess(
    const std::uint32_t pid,
    const QString& processName,
    const bool showMessage)
{
    // 附加入口日志：记录目标 PID 与是否弹窗反馈。
    kLogEvent attachStartEvent;
    info << attachStartEvent
        << "[MemoryDock] attachToProcess: 开始附加, pid="
        << pid
        << ", processName="
        << processName.toStdString()
        << ", showMessage="
        << (showMessage ? "true" : "false")
        << eol;

    // 暂存补丁与 int3 的目标变更确认统一交给工作台离开守卫。
    if (!workbenchAllowsProcessChange())
    {
        return false;
    }
    // 附加前先清理旧进程上下文，避免残留句柄。
    detachProcess();

    // 首选读写权限，满足写内存/断点能力。
    HANDLE processHandle = ::OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE,
        toDwordPid(pid));
    if (processHandle == nullptr)
    {
        // 失败时回退只读权限，至少保证浏览能力。
        processHandle = ::OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            FALSE,
            toDwordPid(pid));
        if (processHandle == nullptr)
        {
            const DWORD openError = ::GetLastError();
            kLogEvent attachOpenFailEvent;
            err << attachOpenFailEvent
                << "[MemoryDock] attachToProcess: 读写+只读权限均失败, pid="
                << pid
                << ", error="
                << openError
                << eol;
            if (showMessage)
            {
                if (openError == ERROR_ACCESS_DENIED)
                {
                    (void)ks::ui::requestAdministratorRestartForFeature(
                        this,
                        QStringLiteral("附加进程内存"));
                }
                else
                {
                    QMessageBox::warning(
                        this,
                        "附加失败",
                        "OpenProcess 失败，目标进程可能已退出或不可访问。");
                }
            }
            updateStatusBarText();
            return false;
        }
        m_canReadWriteMemory = false;
        kLogEvent attachReadonlyEvent;
        warn << attachReadonlyEvent
            << "[MemoryDock] attachToProcess: 退化为只读句柄, pid="
            << pid
            << eol;
    }
    else
    {
        m_canReadWriteMemory = true;
        kLogEvent attachReadWriteEvent;
        info << attachReadWriteEvent
            << "[MemoryDock] attachToProcess: 获取到可读写句柄, pid="
            << pid
            << eol;
    }

    m_attachedProcessHandle = processHandle;
    m_attachedPid = pid;
    m_attachedProcessName = processName;
    updateStatusBarText();
    syncTamperDetectionTargets();

    // 句柄、PID、名称与读写标志都已就位：通知内存工作台目标已附加（视图未创建时是空操作）。
    workbenchOnAttached();

    // 附加后立即刷新模块与区域，减少下一步等待。两者都在后台执行，
    // 附加按钮点下去之后界面立刻可用，不会因为目标进程地址空间庞大而白屏。
    refreshModuleListForPid(pid);

    // 附加路径显式要求区域枚举走异步分支：此刻区域缓存必然为空（detachProcess 已清空），
    // 若不打这个标记就会落到“缓存为空时同步遍历”的兜底分支上，重新把 UI 卡住。
    setProperty(kRegionRefreshFromAttachProperty, true);
    refreshMemoryRegionList(true);

    if (showMessage)
    {
        QMessageBox::information(
            this,
            "附加成功",
            QString("已附加到 %1 (PID=%2)\n读写状态: %3")
            .arg(processName)
            .arg(pid)
            .arg(m_canReadWriteMemory ? "可读可写" : "只读"));
    }

    // 附加结束日志：记录最终状态。
    kLogEvent attachFinishEvent;
    info << attachFinishEvent
        << "[MemoryDock] attachToProcess: 附加完成, pid="
        << pid
        << ", canReadWrite="
        << (m_canReadWriteMemory ? "true" : "false")
        << eol;
    return true;
}

void MemoryDock::focusProcessForOperations(const std::uint32_t pid, const bool showMessage)
{
    // 从进程 Dock 跳转：刷新进程列表，定位目标行并切换到“进程与模块/内存区域”操作上下文。
    if (pid == 0)
    {
        return;
    }

    // 进程列表刷新已改为异步，附加不能再等表格重建完成。进程名优先取现有缓存，
    // 缓存未命中时只做一次映像路径查询（单个进程句柄，代价可忽略）。
    QString processName;
    for (const ProcessEntry& entry : m_processCache)
    {
        if (entry.pid == pid)
        {
            processName = entry.processName.trimmed();
            break;
        }
    }
    if (processName.isEmpty())
    {
        const QString imagePath = QString::fromStdString(ks::process::QueryProcessPathByPid(pid));
        processName = QFileInfo(imagePath).fileName().trimmed();
    }
    if (processName.isEmpty())
    {
        processName = QStringLiteral("PID_%1").arg(pid);
    }

    // 目标行定位登记成待办：本轮异步刷新回填进程表后由提交阶段完成选中与滚动。
    setProperty(kProcessFocusPendingPidProperty, static_cast<uint>(pid));
    refreshProcessList(true);

    // 当前表里已经存在该进程时立即定位，不必等异步结果回来。
    (void)selectProcessRowByPid(m_processTable, m_processCombo, pid);

    attachToProcess(pid, processName, showMessage);
    if (m_tabWidget != nullptr && m_tabRegions != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_tabRegions);
    }
}

void MemoryDock::focusProcessForSearch(const std::uint32_t pid, const bool showMessage)
{
    // 搜索页需要有效进程句柄和最新区域缓存，先复用标准附加流程，再切到搜索页。
    focusProcessForOperations(pid, showMessage);
    if (m_attachedPid == pid && m_tabWidget != nullptr && m_tabSearch != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_tabSearch);
    }
}

void MemoryDock::setProcessDetailMemoryScope()
{
    // 进程详情只需要针对当前 PID 的基础内存分析入口。
    // 其余断点、R0 读写、内核扫描和证据页保留在独立内存 Dock，避免内嵌窗口成为完整副本。
    if (m_tabWidget == nullptr)
    {
        return;
    }

    // 内嵌实例：内存工作台视图以内嵌模式创建（恒跟随本 Dock、禁内核/物理、不落盘设置）。
    m_workbenchEmbedded = true;

    applyProcessDetailTabVisibility();

    if (m_tabRegions != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_tabRegions);
    }
}

void MemoryDock::applyProcessDetailTabVisibility()
{
    // 内嵌实例固定提供进程与模块、内存区域、内存搜索和统一工作台。
    if (m_tabWidget == nullptr)
    {
        return;
    }
    for (int tabIndex = 0; tabIndex < m_tabWidget->count(); ++tabIndex)
    {
        QWidget* const tabPage = m_tabWidget->widget(tabIndex);
        const bool visibleInProcessDetail =
            tabPage == m_tabProcessModule ||
            tabPage == m_tabRegions ||
            tabPage == m_tabSearch ||
            tabPage == m_tabWorkbench;
        m_tabWidget->setTabVisible(tabIndex, visibleInProcessDetail);
    }
}

void MemoryDock::detachProcess()
{
    // 分离入口日志：记录旧 PID 便于追踪。
    kLogEvent detachStartEvent;
    info << detachStartEvent
        << "[MemoryDock] detachProcess: 开始分离, oldPid="
        << m_attachedPid
        << eol;

    // 句柄仍然有效的最后时点：先让内存工作台处理"目标即将分离"（int3 补丁的未经提示安全网
    // 需要在句柄关闭之前还原；视图未创建时是空操作）。
    workbenchOnAboutToDetach();

    // 先取消并等待所有扫描协调线程退出，再关闭进程句柄，
    // 防止后台 ReadProcessMemory 使用已关闭或已复用的 HANDLE。
    cancelAndWaitForMemoryScanTasks();

    // 先使所有基于旧附加上下文的异步快照失效。PTE/证据任务持有的是复制句柄，
    // 可以安全完成系统调用，但其结果不得再写回新的附加进程。
    m_processAttachmentGeneration.fetch_add(1U);

    // 区域枚举的在途/待补标记与附加上下文绑定：不在这里复位，重新附加时会被上一轮
    // 任务遗留的在途标记挡住，新目标永远等不到区域列表。旧任务回投时会先比对代次，
    // 发现上下文已变就整段放弃，不会再回来碰这组标记。
    setProperty(kRegionRefreshInFlightProperty, false);
    setProperty(kRegionRefreshPendingProperty, false);
    setProperty(kRegionRefreshFromAttachProperty, false);

    m_processPteTranslateRefreshTicket.fetch_add(1U);
    m_processMemoryEvidenceRefreshTicket.fetch_add(1U);
    m_processPteTranslateRefreshInProgress.store(false);
    m_processMemoryEvidenceRefreshInProgress.store(false);
    if (m_processPteTranslateRefreshButton != nullptr)
    {
        m_processPteTranslateRefreshButton->setEnabled(true);
    }
    if (m_processMemoryEvidenceRefreshButton != nullptr)
    {
        m_processMemoryEvidenceRefreshButton->setEnabled(true);
    }

    // 同步抬高模块刷新 ticket，确保旧的异步模块回调不会覆盖“已分离”状态。
    m_moduleRefreshTicket.fetch_add(1);
    m_moduleRefreshInProgress.store(false);
    if (m_moduleRefreshButton != nullptr)
    {
        m_moduleRefreshButton->setEnabled(true);
    }

    if (m_attachedProcessHandle != nullptr)
    {
        ::CloseHandle(m_attachedProcessHandle);
        m_attachedProcessHandle = nullptr;
    }

    m_attachedPid = 0;
    m_attachedProcessName.clear();
    m_canReadWriteMemory = false;

    // 分离时清理依赖上下文的数据缓存。
    m_moduleCache.clear();
    m_moduleCachePid = 0U;
    m_moduleCacheCreateTime = 0U;
    m_regionCache.clear();
    m_searchResultCache.clear();
    m_searchResultVisibleCount = 0;
    m_processPteTranslateCache.clear();
    m_processPteTranslateVisibleCount = 0;
    m_processMemoryEvidenceCache.clear();
    m_processMemoryEvidenceVisibleCount = 0;

    // 清理表格展示，避免用户误操作旧数据。
    m_moduleTable->clear();
    if (m_moduleStatusLabel != nullptr)
    {
        m_moduleStatusLabel->setText("● 未附加进程");
        m_moduleStatusLabel->setStyleSheet(
            QStringLiteral("color:%1; font-weight:600;")
                .arg(KswordTheme::TextSecondaryColor().name(QColor::HexRgb)));
    }
    m_regionTable->setRowCount(0);
    m_searchResultTable->setRowCount(0);
    if (m_processPteTranslateTable != nullptr)
    {
        m_processPteTranslateTable->setRowCount(0);
    }
    if (m_processMemoryEvidenceTable != nullptr)
    {
        m_processMemoryEvidenceTable->setRowCount(0);
    }
    if (m_processPteTranslateStatusLabel != nullptr)
    {
        m_processPteTranslateStatusLabel->setText(QStringLiteral("状态：请先附加进程。"));
    }
    if (m_processMemoryEvidenceStatusLabel != nullptr)
    {
        m_processMemoryEvidenceStatusLabel->setText(QStringLiteral("状态：请先附加进程。"));
    }

    updateStatusBarText();

    // 旧上下文已全部清零：通知内存工作台分离完成（视图未创建时是空操作）。
    workbenchOnDetached();

    // 分离结束日志：确认缓存已清空。
    kLogEvent detachFinishEvent;
    info << detachFinishEvent
        << "[MemoryDock] detachProcess: 分离完成，缓存与表格已重置。"
        << eol;
}

std::shared_ptr<void> MemoryDock::duplicateAttachedProcessHandleForWorker(
    std::uint32_t* const errorCodeOut) const
{
    // 后台任务不得借用 m_attachedProcessHandle：分离/重新附加会关闭它，且 Windows
    // 可能立即把相同数值分配给别的内核对象。独立复制句柄把系统调用生命周期与 UI 解耦。
    if (errorCodeOut != nullptr)
    {
        *errorCodeOut = ERROR_SUCCESS;
    }

    if (m_attachedProcessHandle == nullptr)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_INVALID_HANDLE;
        }
        return {};
    }

    HANDLE duplicatedHandle = nullptr;
    if (::DuplicateHandle(
            ::GetCurrentProcess(),
            m_attachedProcessHandle,
            ::GetCurrentProcess(),
            &duplicatedHandle,
            0U,
            FALSE,
            DUPLICATE_SAME_ACCESS) == FALSE)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = static_cast<std::uint32_t>(::GetLastError());
        }
        return {};
    }

    return std::shared_ptr<void>(duplicatedHandle, [](void* const rawHandle) {
        if (rawHandle != nullptr)
        {
            ::CloseHandle(static_cast<HANDLE>(rawHandle));
        }
    });
}

HANDLE MemoryDock::openProcessHandleForRead(const std::uint32_t pid, QString* const errorTextOut) const
{
    // 读取句柄日志：用于诊断权限不足问题。
    kLogEvent openReadHandleEvent;
    dbg << openReadHandleEvent
        << "[MemoryDock] openProcessHandleForRead: pid="
        << pid
        << eol;

    HANDLE processHandle = ::OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        toDwordPid(pid));
    if (processHandle == nullptr && errorTextOut != nullptr)
    {
        *errorTextOut = QString("OpenProcess 失败，错误码=%1").arg(::GetLastError());
        kLogEvent openReadHandleFailEvent;
        warn << openReadHandleFailEvent
            << "[MemoryDock] openProcessHandleForRead: 打开失败, pid="
            << pid
            << ", error="
            << ::GetLastError()
            << eol;
    }
    return processHandle;
}

void MemoryDock::showProcessTableContextMenu(const QPoint& localPosition)
{
    // 右键入口日志：记录触发位置，便于诊断菜单行为。
    kLogEvent contextMenuEvent;
    dbg << contextMenuEvent
        << "[MemoryDock] showProcessTableContextMenu: x="
        << localPosition.x()
        << ", y="
        << localPosition.y()
        << eol;

    if (m_processTable == nullptr)
    {
        return;
    }

    const QModelIndex index = m_processTable->indexAt(localPosition);
    if (!index.isValid())
    {
        return;
    }

    const int row = index.row();
    const QTableWidgetItem* pidItem = m_processTable->item(row, 1);
    const QTableWidgetItem* nameItem = m_processTable->item(row, 0);
    if (pidItem == nullptr || nameItem == nullptr)
    {
        return;
    }

    bool pidOk = false;
    const std::uint32_t pid = pidItem->text().toUInt(&pidOk);
    if (!pidOk || pid == 0)
    {
        return;
    }
    const QString processName = nameItem->text().trimmed();
    m_processTable->setCurrentCell(row, index.column());

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* attachAction = contextMenu.addAction(
        QIcon(":/Icon/process_start.svg"),
        QStringLiteral("附加进程"));
    QAction* dumpAction = contextMenu.addAction(
        QIcon(":/Icon/process_details.svg"),
        QStringLiteral("Dump内存到文件"));
    QAction* copyRowAction = contextMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制当前行"));

    const auto creationTime100ns = nameItem->data(kProcessCreationTimeRole).toULongLong();
    if (creationTime100ns != 0)
        ks::ui::x64dbg_navigation::AddAction(&contextMenu, this,
            {pid, creationTime100ns, 0, ks::ui::x64dbg_navigation::View::Disassembly});

    QAction* selectedAction = contextMenu.exec(m_processTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == attachAction)
    {
        attachToProcess(pid, processName, true);
        return;
    }

    if (selectedAction == dumpAction)
    {
        requestDumpProcessMemoryByPid(pid, processName);
        return;
    }

    if (selectedAction == copyRowAction)
    {
        copyProcessRegionTableRow(m_processTable, row);
        kLogEvent copyProcessRowEvent;
        dbg << copyProcessRowEvent
            << "[MemoryDock] 进程表右键复制当前行, row="
            << row
            << ", pid="
            << pid
            << eol;
    }
}

void MemoryDock::requestDumpProcessMemoryByPid(const std::uint32_t pid, const QString& processName)
{
    if (readBoolProperty(this, kProcessDumpInFlightProperty))
    {
        QMessageBox::information(this, QStringLiteral("导出进程内存"),
            QStringLiteral("已有进程内存导出正在进行，请等待完成。"));
        return;
    }

    // Dump 请求日志：记录 PID 与进程名，便于后续审计。
    kLogEvent dumpRequestEvent;
    info << dumpRequestEvent
        << "[MemoryDock] requestDumpProcessMemoryByPid: pid="
        << pid
        << ", processName="
        << processName.toStdString()
        << eol;

    // 保留选中 PID 对应的进程对象，模态选择期间退出也不会串到复用后的 PID。
    const HANDLE targetHandle = ::OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
        FALSE, toDwordPid(pid));
    if (targetHandle == nullptr)
    {
        const QString errorText = QStringLiteral("OpenProcess 失败, error=%1").arg(::GetLastError());
        if (!ks::ui::promptForPrivilegeFailure(this, QStringLiteral("导出进程内存"), errorText))
        {
            QMessageBox::warning(this, QStringLiteral("Dump失败"), errorText);
        }
        return;
    }
    const std::shared_ptr<void> targetProcess(targetHandle, [](void* handle) { ::CloseHandle(handle); });
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (::GetProcessTimes(targetHandle, &creation, &exit, &kernel, &user) == FALSE)
    {
        QMessageBox::warning(this, QStringLiteral("Dump失败"),
            QStringLiteral("无法读取目标进程创建时间，error=%1。").arg(::GetLastError()));
        return;
    }
    const std::uint64_t creationTime =
        (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U) | creation.dwLowDateTime;

    using ksword::memory_backend::MemoryAccessBackend;
    const QStringList backendNames{
        ks::i18n::sourceText(ksword::memory_backend::backendDisplayName(MemoryAccessBackend::UserMode)),
        ks::i18n::sourceText(ksword::memory_backend::backendDisplayName(MemoryAccessBackend::StandardDriver)),
        ks::i18n::sourceText(ksword::memory_backend::backendDisplayName(MemoryAccessBackend::Hvm))
    };
    bool backendAccepted = false;
    const QString backendName = QInputDialog::getItem(this,
        QStringLiteral("导出进程内存"),
        QStringLiteral("选择本次导出的读取后端（区域由 Windows 查询；HVM 必须使用私有页表窗口）："),
        backendNames, 0, false, &backendAccepted);
    if (!backendAccepted)
    {
        return;
    }
    const int backendIndex = backendNames.indexOf(backendName);
    if (backendIndex < 0 || backendIndex > 2)
    {
        return;
    }
    const auto backend = static_cast<MemoryAccessBackend>(backendIndex);
    if (backend == MemoryAccessBackend::Hvm)
    {
        QString reason;
        if (!ksword::memory_backend::isHvmMemoryUsable(&reason))
        {
            QMessageBox::warning(this, QStringLiteral("Dump失败"), reason);
            return;
        }
    }

    const QString defaultFileName = QStringLiteral("%1_pid%2_%3.kmdump")
        .arg(processName.isEmpty() ? QStringLiteral("process") : processName)
        .arg(pid)
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));

    const QString outputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("保存进程内存Dump"),
        defaultFileName,
        QStringLiteral("Ksword Memory Dump (*.kmdump);;All Files (*.*)"));
    if (outputPath.trimmed().isEmpty())
    {
        return;
    }
    // 模态对话框可触发重入；此处再查一次，避免两个导出共享同一进度任务。
    if (readBoolProperty(this, kProcessDumpInFlightProperty))
    {
        return;
    }
    setProperty(kProcessDumpInFlightProperty, true);

    if (m_dumpMemoryProgressPid == 0)
    {
        m_dumpMemoryProgressPid = kPro.addReusable(this, "内存", "Dump进程内存");
    }
    kPro.set(m_dumpMemoryProgressPid, "准备读取内存区域", 0, 5.0f);
    const int progressPid = m_dumpMemoryProgressPid;

    QPointer<MemoryDock> guardThis(this);
    std::thread([guardThis, pid, processName, outputPath, targetProcess, creationTime,
        backend, backendName, progressPid]() {
        if (guardThis == nullptr)
        {
            return;
        }

        QString errorText;
        // 工作函数是 static：不会借用 Dock 控件或可被分离操作关闭的进程句柄。
        const bool dumpOk = MemoryDock::dumpProcessMemoryToFile(pid, targetProcess,
            creationTime, backend, outputPath, progressPid, errorText);
        QMetaObject::invokeMethod(qApp, [guardThis, dumpOk, pid, processName, outputPath,
            backendName, progressPid, errorText]() {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->setProperty(kProcessDumpInFlightProperty, false);

            if (dumpOk)
            {
                kPro.set(progressPid, "Dump完成", 0, 100.0f);

                kLogEvent dumpFinishEvent;
                info << dumpFinishEvent
                    << "[MemoryDock] Dump完成, pid="
                    << pid
                    << ", path="
                    << outputPath.toStdString()
                    << eol;

                QMessageBox::information(
                    guardThis,
                    QStringLiteral("Dump完成"),
                    QStringLiteral("进程 %1 (PID=%2) 内存已通过 %3 保存到：\n%4")
                    .arg(processName)
                    .arg(pid)
                    .arg(backendName)
                    .arg(outputPath));
            }
            else
            {
                kPro.set(progressPid, "Dump失败", 0, 100.0f);

                kLogEvent dumpFailEvent;
                err << dumpFailEvent
                    << "[MemoryDock] Dump失败, pid="
                    << pid
                    << ", error="
                    << errorText.toStdString()
                    << eol;

                // privilegePromptHandled：记录 Dump 失败是否已由权限恢复提示处理。
                const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    guardThis,
                    QStringLiteral("导出进程内存"),
                    errorText);
                if (!privilegePromptHandled)
                {
                    QMessageBox::warning(
                        guardThis,
                        QStringLiteral("Dump失败"),
                        QStringLiteral("进程 %1 (PID=%2) Dump失败：\n%3")
                        .arg(processName)
                        .arg(pid)
                        .arg(errorText));
                }
            }
        }, Qt::QueuedConnection);
    }).detach();
}

bool MemoryDock::dumpProcessMemoryToFile(
    const std::uint32_t pid,
    const std::shared_ptr<void>& targetProcess,
    const std::uint64_t creationTime,
    const ksword::memory_backend::MemoryAccessBackend backend,
    const QString& dumpFilePath,
    const int progressPid,
    QString& errorTextOut)
{
    errorTextOut.clear();

    using namespace ksword::memory_backend;
    if (backend != MemoryAccessBackend::UserMode
        && backend != MemoryAccessBackend::StandardDriver
        && backend != MemoryAccessBackend::Hvm)
    {
        errorTextOut = QStringLiteral("进程内存导出仅支持 R3、R0 或 HVM 后端。");
        return false;
    }
    const HANDLE processHandle = targetProcess.get();
    const auto identityCurrent = [processHandle, pid, creationTime]() {
        if (processHandle == nullptr || ::GetProcessId(processHandle) != toDwordPid(pid)
            || ::WaitForSingleObject(processHandle, 0) != WAIT_TIMEOUT)
        {
            return false;
        }
        FILETIME creation{}, exit{}, kernel{}, user{};
        if (::GetProcessTimes(processHandle, &creation, &exit, &kernel, &user) == FALSE)
        {
            return false;
        }
        return ((static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U)
            | creation.dwLowDateTime) == creationTime;
    };
    if (!identityCurrent())
    {
        errorTextOut = QStringLiteral("目标进程已退出或身份已改变，导出已取消。");
        return false;
    }

    // WOW64 目标的可查询上限可能低于宿主；非 LAA 目标的 2 GiB 上限还保留最后 64 KiB。
    // 不预截断范围，仍保留 VirtualQueryEx 可见的高位原生映射。
    BOOL targetIsWow64 = FALSE;
    const bool targetIsKnownWow64 =
        ::IsWow64Process(processHandle, &targetIsWow64) != FALSE && targetIsWow64 != FALSE;

    QSaveFile outputFile(dumpFilePath);
    outputFile.setDirectWriteFallback(false);
    if (!outputFile.open(QIODevice::WriteOnly))
    {
        errorTextOut = QStringLiteral("无法写入文件: %1").arg(dumpFilePath);
        return false;
    }
    const auto writeExact = [&outputFile, &errorTextOut](const char* bytes, const qint64 count) {
        if (outputFile.write(bytes, count) == count)
        {
            return true;
        }
        errorTextOut = QStringLiteral("转储文件写入失败：%1").arg(outputFile.errorString());
        return false;
    };

    // Dump 文件头结构：
    // - magic：文件签名；
    // - version：版本号（方便后续升级格式）；
    // - pid：目标进程 PID；
    // - timestamp100ns：创建时间戳；
    // - regionCount：成功写入的区域数量。
    struct DumpFileHeader final
    {
        char magic[8];
        std::uint32_t version = 1;
        std::uint32_t pid = 0;
        std::uint64_t timestamp100ns = 0;
        std::uint32_t regionCount = 0;
        std::uint32_t reserved = 0;
    };

    struct DumpRegionHeader final
    {
        std::uint64_t baseAddress = 0;
        std::uint64_t declaredRegionSize = 0;
        std::uint64_t dumpedBytes = 0;
        std::uint32_t protect = 0;
        std::uint32_t state = 0;
        std::uint32_t type = 0;
        std::uint32_t reserved = 0;
    };

    FILETIME fileTime{};
    ::GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER fileTimeValue{};
    fileTimeValue.LowPart = fileTime.dwLowDateTime;
    fileTimeValue.HighPart = fileTime.dwHighDateTime;

    DumpFileHeader fileHeader{};
    std::memcpy(fileHeader.magic, "KMDUMP1", 7);
    fileHeader.magic[7] = '\0';
    fileHeader.pid = pid;
    fileHeader.timestamp100ns = fileTimeValue.QuadPart;

    if (!writeExact(reinterpret_cast<const char*>(&fileHeader), static_cast<qint64>(sizeof(fileHeader))))
    {
        return false;
    }

    SYSTEM_INFO systemInfo{};
    ::GetSystemInfo(&systemInfo);
    const std::uint64_t minAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    const std::uint64_t maxAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    constexpr SIZE_T kChunkSize = KSWORD_ARK_MEMORY_READ_MAX_BYTES;
    const DdmaSession unusedDdmaSession{};

    std::uint64_t currentAddress = minAddress;
    std::uint32_t dumpedRegionCount = 0;
    while (currentAddress < maxAddress)
    {
        if (!identityCurrent())
        {
            errorTextOut = QStringLiteral("目标进程已退出或身份已改变，导出已取消。");
            return false;
        }
        MEMORY_BASIC_INFORMATION mbi{};
        const SIZE_T querySize = ::VirtualQueryEx(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(currentAddress)),
            &mbi,
            sizeof(mbi));
        if (querySize != sizeof(mbi))
        {
            const DWORD queryError = ::GetLastError();
            if (querySize == 0U && queryError == ERROR_INVALID_PARAMETER
                && targetIsKnownWow64 && currentAddress >= 0x7FFF0000ULL)
            {
                // 已连续到达至少非 LAA 的 32 位上限，INVALID_PARAMETER 表示超出目标最高地址。
                // 仍在提交前复核句柄身份；更低地址、短响应及其他查询错误继续取消导出。
                break;
            }
            errorTextOut = QStringLiteral("内存区域查询失败，地址=0x%1，error=%2。")
                .arg(currentAddress, 0, 16).arg(queryError);
            return false;
        }

        const std::uint64_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const std::uint64_t regionSize = static_cast<std::uint64_t>(mbi.RegionSize);
        if (regionSize == 0ULL || regionBase > currentAddress
            || regionSize > (std::numeric_limits<std::uint64_t>::max)() - regionBase
            || regionBase + regionSize <= currentAddress)
        {
            errorTextOut = QStringLiteral("内存区域范围无效，导出已取消。");
            return false;
        }

        if (mbi.State == MEM_COMMIT && isReadableProtect(static_cast<std::uint32_t>(mbi.Protect)))
        {
            DumpRegionHeader regionHeader{};
            regionHeader.baseAddress = regionBase;
            regionHeader.declaredRegionSize = regionSize;
            regionHeader.protect = static_cast<std::uint32_t>(mbi.Protect);
            regionHeader.state = static_cast<std::uint32_t>(mbi.State);
            regionHeader.type = static_cast<std::uint32_t>(mbi.Type);

            const qint64 headerPosition = outputFile.pos();
            if (!writeExact(reinterpret_cast<const char*>(&regionHeader), static_cast<qint64>(sizeof(regionHeader))))
            {
                return false;
            }

            std::uint64_t offsetInRegion = 0;
            std::uint64_t dumpedBytes = 0;
            while (offsetInRegion < regionSize)
            {
                const SIZE_T remainSize = static_cast<SIZE_T>(std::min<std::uint64_t>(regionSize - offsetInRegion, kChunkSize));
                if (!identityCurrent())
                {
                    errorTextOut = QStringLiteral("目标进程已退出或身份已改变，导出已取消。");
                    return false;
                }
                const AccessOutcome outcome = readVirtual(backend, unusedDdmaSession,
                    pid, regionBase + offsetInRegion, static_cast<std::uint64_t>(remainSize),
                    /*requireHvmDirectWindow*/ true);
                if (!identityCurrent())
                {
                    errorTextOut = QStringLiteral("目标进程已退出或身份已改变，导出已取消。");
                    return false;
                }
                if (!outcome.ok || outcome.partial || outcome.bytesDone != remainSize
                    || static_cast<std::uint64_t>(outcome.data.size()) != remainSize)
                {
                    errorTextOut = QStringLiteral("内存读取未完成，地址=0x%1，实际=%2/%3 字节。%4")
                        .arg(regionBase + offsetInRegion, 0, 16).arg(outcome.bytesDone)
                        .arg(static_cast<std::uint64_t>(remainSize)).arg(outcome.failureText);
                    return false;
                }
                if (!writeExact(outcome.data.constData(), outcome.data.size()))
                {
                    return false;
                }
                dumpedBytes += static_cast<std::uint64_t>(remainSize);
                offsetInRegion += static_cast<std::uint64_t>(remainSize);
            }

            regionHeader.dumpedBytes = dumpedBytes;
            const qint64 endPosition = outputFile.pos();
            if (!outputFile.seek(headerPosition)
                || !writeExact(reinterpret_cast<const char*>(&regionHeader), static_cast<qint64>(sizeof(regionHeader)))
                || !outputFile.seek(endPosition))
            {
                if (errorTextOut.isEmpty())
                {
                    errorTextOut = QStringLiteral("转储文件定位失败：%1").arg(outputFile.errorString());
                }
                return false;
            }

            if (dumpedBytes > 0)
            {
                ++dumpedRegionCount;
            }
        }

        const std::uint64_t totalRange = maxAddress - minAddress;
        if (totalRange > 0)
        {
            const float progressValue = static_cast<float>(
                std::min<std::uint64_t>(
                    95,
                    ((regionBase - minAddress) * 95ULL) / totalRange));
            kPro.set(progressPid, "读取并写入内存区域中", 0, progressValue);
        }

        const std::uint64_t nextAddress = regionBase + regionSize;
        currentAddress = nextAddress;
    }

    if (dumpedRegionCount == 0)
    {
        errorTextOut = QStringLiteral("未读取到可导出的有效区域。");
        return false;
    }
    if (!identityCurrent())
    {
        errorTextOut = QStringLiteral("目标进程已退出或身份已改变，导出已取消。");
        return false;
    }
    // 保留 KMDUMP1 布局；只有完整读取、所有文件写入成功才原子提交到目标路径。
    fileHeader.regionCount = dumpedRegionCount;
    if (!outputFile.seek(0)
        || !writeExact(reinterpret_cast<const char*>(&fileHeader), static_cast<qint64>(sizeof(fileHeader))))
    {
        if (errorTextOut.isEmpty())
        {
            errorTextOut = QStringLiteral("转储文件定位失败：%1").arg(outputFile.errorString());
        }
        return false;
    }
    if (!outputFile.commit())
    {
        errorTextOut = QStringLiteral("转储文件提交失败：%1").arg(outputFile.errorString());
        return false;
    }
    return true;
}

void MemoryDock::refreshMemoryRegionList(const bool forceRequery)
{
    // 区域刷新入口日志：记录是否强制重查。
    kLogEvent regionRefreshStartEvent;
    info << regionRefreshStartEvent
        << "[MemoryDock] refreshMemoryRegionList: 开始刷新区域, forceRequery="
        << (forceRequery ? "true" : "false")
        << ", attachedPid="
        << m_attachedPid
        << eol;

    // 附加流程打的“必须异步”标记只对本次调用有效，读到后立刻清掉。
    const bool requestedByAttach = readBoolProperty(this, kRegionRefreshFromAttachProperty);
    if (requestedByAttach)
    {
        setProperty(kRegionRefreshFromAttachProperty, false);
    }

    if (m_attachedProcessHandle == nullptr)
    {
        m_regionCache.clear();
        m_regionTable->setRowCount(0);
        return;
    }

    if (!forceRequery && !m_regionCache.empty())
    {
        // 缓存可用且未要求重查时只重新过滤，不再遍历地址空间。
        applyRegionFilterAndRebuildTable();

        // 区域刷新结束日志：记录缓存数量。
        kLogEvent regionCachedFinishEvent;
        info << regionCachedFinishEvent
            << "[MemoryDock] refreshMemoryRegionList: 刷新完成, regionCount="
            << m_regionCache.size()
            << eol;
        return;
    }

    // 已有枚举在途时只登记一次待补请求：区域遍历动辄数百毫秒，重复点击不该叠加任务。
    if (readBoolProperty(this, kRegionRefreshInFlightProperty))
    {
        setProperty(kRegionRefreshPendingProperty, true);
        return;
    }

    // asyncAllowed 说明：附加流程和“表里已经有数据”的重查一律异步。
    // 只有“缓存为空且没有在途任务”时保持同步 —— 那条路径上的调用方（扫描页收集
    // 扫描范围）在调用返回后立刻读 m_regionCache，异步会让它直接判定为无区域可扫。
    const bool asyncAllowed = requestedByAttach || !m_regionCache.empty();
    std::uint32_t duplicateError = ERROR_SUCCESS;
    const std::shared_ptr<void> processHandleLease =
        asyncAllowed ? duplicateAttachedProcessHandleForWorker(&duplicateError) : std::shared_ptr<void>();
    if (processHandleLease)
    {
        setProperty(kRegionRefreshInFlightProperty, true);

        // 附加上下文代次：分离或重新附加后旧快照不得再写回新目标。
        const std::uint64_t attachmentGeneration = m_processAttachmentGeneration.load();
        const QPointer<MemoryDock> guardedSelf(this);

        QRunnable* const enumerateRegionTask =
            QRunnable::create([guardedSelf, processHandleLease, attachmentGeneration]() {
                // 工作线程只做 VirtualQueryEx / GetMappedFileNameW 遍历，产出纯值类型行。
                std::vector<RegionSnapshotRow> regionRows =
                    collectVirtualMemoryRegionRows(static_cast<HANDLE>(processHandleLease.get()));

                QCoreApplication* const appInstance = QCoreApplication::instance();
                if (appInstance == nullptr)
                {
                    return;
                }

                QMetaObject::invokeMethod(
                    appInstance,
                    [guardedSelf, attachmentGeneration, regionRows = std::move(regionRows)]() mutable {
                        if (guardedSelf == nullptr)
                        {
                            return;
                        }
                        MemoryDock* const resultDock = guardedSelf.data();

                        // 附加上下文已变化（分离/重新附加）时旧快照直接丢弃。注意这里不能
                        // 顺手清在途标记：那组标记已经在 detachProcess 里复位并被新一轮
                        // 任务重新占用，旧任务再清一次会让新任务失去去重保护。
                        if (attachmentGeneration != resultDock->m_processAttachmentGeneration.load())
                        {
                            return;
                        }

                        if (regionRows.empty())
                        {
                            resultDock->setProperty(kRegionRefreshInFlightProperty, false);
                            resultDock->setProperty(kRegionRefreshPendingProperty, false);
                            reportRegionEnumerateFailure(
                                resultDock,
                                QStringLiteral("VirtualQueryEx 未返回有效区域。"));
                            return;
                        }

                        const auto regionRowsSnapshot =
                            std::make_shared<std::vector<RegionSnapshotRow>>(std::move(regionRows));
                        auto commitRegionSnapshot = [guardedSelf, attachmentGeneration, regionRowsSnapshot]() {
                            if (guardedSelf == nullptr)
                            {
                                return;
                            }
                            MemoryDock* const commitDock = guardedSelf.data();
                            if (attachmentGeneration != commitDock->m_processAttachmentGeneration.load())
                            {
                                return;
                            }

                            // 缓存与表格一次性替换，避免过滤动作读到半成品缓存。
                            commitDock->m_regionCache.clear();
                            commitDock->m_regionCache.reserve(regionRowsSnapshot->size());
                            for (const RegionSnapshotRow& regionRow : *regionRowsSnapshot)
                            {
                                RegionEntry entry{};
                                entry.baseAddress = regionRow.baseAddress;
                                entry.regionSize = regionRow.regionSize;
                                entry.protect = regionRow.protect;
                                entry.state = regionRow.state;
                                entry.type = regionRow.type;
                                entry.mappedFilePath = regionRow.mappedFilePath;
                                commitDock->m_regionCache.push_back(std::move(entry));
                            }
                            commitDock->applyRegionFilterAndRebuildTable();

                            // 区域刷新结束日志：记录缓存数量。
                            kLogEvent regionRefreshFinishEvent;
                            info << regionRefreshFinishEvent
                                << "[MemoryDock] refreshMemoryRegionList: 刷新完成, regionCount="
                                << commitDock->m_regionCache.size()
                                << eol;

                            // 在途标记留到提交阶段才释放：右键菜单打开时本次提交会被延后，
                            // 期间必须继续挡住新任务，否则旧提交会覆盖更新的结果。
                            commitDock->setProperty(kRegionRefreshInFlightProperty, false);

                            // 合并下来的待补请求在本轮落地后再补一次，避免结果落后于用户操作。
                            if (commitDock->property(kRegionRefreshPendingProperty).toBool())
                            {
                                commitDock->setProperty(kRegionRefreshPendingProperty, false);
                                commitDock->refreshMemoryRegionList(true);
                            }
                        };

                        // 右键菜单打开时先缓存本次提交，避免把用户正在操作的行整表换掉。
                        if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                                resultDock,
                                QStringLiteral("memory-region-list-snapshot-apply"),
                                {resultDock->m_regionTable},
                                commitRegionSnapshot))
                        {
                            return;
                        }
                        commitRegionSnapshot();
                    },
                    Qt::QueuedConnection);
                });
        enumerateRegionTask->setAutoDelete(true);
        QThreadPool::globalInstance()->start(enumerateRegionTask);
        return;
    }

    // 同步兜底：调用方需要立刻拿到区域缓存，或复制句柄失败（正常情况下不可达）。
    QString errorText;
    std::vector<RegionEntry> regionList;
    if (!enumerateMemoryRegionsByVirtualQuery(m_attachedProcessHandle, regionList, &errorText))
    {
        reportRegionEnumerateFailure(this, errorText);
        return;
    }
    m_regionCache = std::move(regionList);

    applyRegionFilterAndRebuildTable();

    // 区域刷新结束日志：记录缓存数量。
    kLogEvent regionRefreshFinishEvent;
    info << regionRefreshFinishEvent
        << "[MemoryDock] refreshMemoryRegionList: 刷新完成, regionCount="
        << m_regionCache.size()
        << eol;
}

bool MemoryDock::enumerateMemoryRegionsByVirtualQuery(
    HANDLE processHandle,
    std::vector<RegionEntry>& regionsOut,
    QString* const errorTextOut) const
{
    // VirtualQueryEx 枚举入口日志：输出句柄有效性说明。
    kLogEvent enumerateRegionStartEvent;
    dbg << enumerateRegionStartEvent
        << "[MemoryDock] enumerateMemoryRegionsByVirtualQuery: 开始遍历虚拟内存区域。"
        << eol;

    regionsOut.clear();

    // 实际遍历下沉到无 Qt 依赖的采集函数：同一段逻辑同时服务这里的同步兜底
    // 与 refreshMemoryRegionList 提交的线程池任务，避免两份实现慢慢走样。
    const std::vector<RegionSnapshotRow> regionRows = collectVirtualMemoryRegionRows(processHandle);
    regionsOut.reserve(regionRows.size());
    for (const RegionSnapshotRow& regionRow : regionRows)
    {
        RegionEntry entry{};
        entry.baseAddress = regionRow.baseAddress;
        entry.regionSize = regionRow.regionSize;
        entry.protect = regionRow.protect;
        entry.state = regionRow.state;
        entry.type = regionRow.type;
        entry.mappedFilePath = regionRow.mappedFilePath;
        regionsOut.push_back(std::move(entry));
    }

    if (regionsOut.empty())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = "VirtualQueryEx 未返回有效区域。";
        }
        kLogEvent enumerateRegionEmptyEvent;
        warn << enumerateRegionEmptyEvent
            << "[MemoryDock] enumerateMemoryRegionsByVirtualQuery: 枚举结果为空。"
            << eol;
        return false;
    }

    // 枚举结束日志：用于衡量目标进程地址空间复杂度。
    kLogEvent enumerateRegionFinishEvent;
    dbg << enumerateRegionFinishEvent
        << "[MemoryDock] enumerateMemoryRegionsByVirtualQuery: 完成, count="
        << regionsOut.size()
        << eol;
    return true;
}

void MemoryDock::applyRegionFilterAndRebuildTable()
{
    // 过滤入口日志：记录当前缓存规模与过滤开关状态。
    kLogEvent regionFilterStartEvent;
    dbg << regionFilterStartEvent
        << "[MemoryDock] applyRegionFilterAndRebuildTable: 开始过滤, cacheSize="
        << m_regionCache.size()
        << ", committedOnly="
        << (m_regionCommittedOnlyCheck->isChecked() ? "true" : "false")
        << ", imageOnly="
        << (m_regionImageOnlyCheck->isChecked() ? "true" : "false")
        << ", readableOnly="
        << (m_regionReadableOnlyCheck->isChecked() ? "true" : "false")
        << eol;

    // 关键字过滤：留空表示不筛，命中判据覆盖基址文本、保护属性与映射文件路径。
    const QString filterKeyword = (m_regionFilterEdit != nullptr)
        ? m_regionFilterEdit->text().trimmed()
        : QString();

    // 过滤条件组合：已提交 / IMAGE / 可读 / 关键字。
    std::vector<const RegionEntry*> filteredRegions;
    filteredRegions.reserve(m_regionCache.size());
    for (const RegionEntry& entry : m_regionCache)
    {
        if (m_regionCommittedOnlyCheck->isChecked() && entry.state != MEM_COMMIT)
        {
            continue;
        }
        if (m_regionImageOnlyCheck->isChecked() && entry.type != MEM_IMAGE)
        {
            continue;
        }
        if (m_regionReadableOnlyCheck->isChecked() && !isReadableProtect(entry.protect))
        {
            continue;
        }
        if (!filterKeyword.isEmpty())
        {
            const bool keywordMatched =
                formatAddress(entry.baseAddress).contains(filterKeyword, Qt::CaseInsensitive)
                || protectToText(entry.protect).contains(filterKeyword, Qt::CaseInsensitive)
                || entry.mappedFilePath.contains(filterKeyword, Qt::CaseInsensitive);
            if (!keywordMatched)
            {
                continue;
            }
        }
        filteredRegions.push_back(&entry);
    }

    m_regionTable->setSortingEnabled(false);
    m_regionTable->setRowCount(static_cast<int>(filteredRegions.size()));
    for (int row = 0; row < static_cast<int>(filteredRegions.size()); ++row)
    {
        const RegionEntry& entry = *filteredRegions[static_cast<std::size_t>(row)];
        // 列 0 和列 1 附带 UserRole 原始值，便于右键动作时可靠反查。
        //
        // 这里原先还写了 setData(Qt::EditRole, 原始数值)：QTableWidgetItem::setData
        // 内部把 EditRole 直接改写成 DisplayRole，于是 formatAddress()/formatSize()
        // 生成的“0x00007FF6…/4.00 MB”当场被裸十进制数覆盖——一个内核分析工具的
        // 内存区域表看不到十六进制地址。排序改由 NumericSortRole 承担，显示文本不再被动。
        QTableWidgetItem* baseItem = new ks::ui::NumericTableItem(
            formatAddress(entry.baseAddress),
            static_cast<qulonglong>(entry.baseAddress));
        baseItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(entry.baseAddress)));
        m_regionTable->setItem(row, 0, baseItem);

        QTableWidgetItem* sizeItem = new ks::ui::NumericTableItem(
            formatSize(entry.regionSize),
            static_cast<qulonglong>(entry.regionSize));
        sizeItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(entry.regionSize)));
        m_regionTable->setItem(row, 1, sizeItem);

        m_regionTable->setItem(row, 2, new QTableWidgetItem(protectToText(entry.protect)));
        m_regionTable->setItem(row, 3, new QTableWidgetItem(stateToText(entry.state)));
        m_regionTable->setItem(row, 4, new QTableWidgetItem(typeToText(entry.type)));
        m_regionTable->setItem(row, 5, new QTableWidgetItem(entry.mappedFilePath));
    }
    m_regionTable->setSortingEnabled(true);

    // 状态标签明确写出“显示了多少 / 一共多少”，避免用户把过滤结果误当成全部区域。
    if (m_regionStatusLabel != nullptr)
    {
        if (m_attachedPid == 0U)
        {
            m_regionStatusLabel->setText("未附加进程。");
        }
        else
        {
            m_regionStatusLabel->setText(
                QString("显示 %1 / 共 %2 个区域")
                    .arg(filteredRegions.size())
                    .arg(m_regionCache.size()));
        }
    }

    // 过滤结束日志：记录最终展示条目数。
    kLogEvent regionFilterFinishEvent;
    info << regionFilterFinishEvent
        << "[MemoryDock] applyRegionFilterAndRebuildTable: 完成, visibleCount="
        << filteredRegions.size()
        << eol;
}

