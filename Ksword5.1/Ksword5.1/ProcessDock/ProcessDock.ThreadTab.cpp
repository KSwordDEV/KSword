#include "ProcessDock.h"
#include "ThreadAffinityMenu.h"
#include "ThreadStackWindow.h"

#include "../Internationalization/LanguageManager.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/TableInteractionSupport.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QBrush>
#include <QChar>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QMessageBox>
#include <QPushButton>
#include <QRunnable>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QThreadPool>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <utility>

namespace
{
    // 线程页表头：强调线程基础身份、调度状态与时间统计。
    const QStringList ThreadTableHeaders{
        "TID",
        "PID",
        "进程",
        "类别",
        "启动地址",
        "Win32Start",
        "TEB",
        "UserStackBase",
        "UserStackLimit",
        "KernelStack",
        "KStackBase",
        "KStackLimit",
        "InitialStack",
        "ReadOps",
        "WriteOps",
        "OtherOps",
        "ReadBytes",
        "WriteBytes",
        "OtherBytes",
        "R0状态",
        "动态优先级",
        "基础优先级",
        "线程状态",
        "等待原因",
        "Kernel(ms)",
        "User(ms)",
        "CPU累计(ms)",
        "WaitTick",
        "上下文切换",
        "创建时间",
        "进程路径",
        "CPU占用"
    };

    // 线程页图标常量：统一从 qrc alias 读取，避免硬编码磁盘路径。
    constexpr const char* IconThreadTab = ":/Icon/process_threads.svg";
    constexpr const char* IconThreadRefresh = ":/Icon/process_refresh.svg";

    // ThreadIdentityKey：按 PID/TID 合并 R3 基础线程与 R0 KTHREAD 扩展。
    struct ThreadIdentityKey
    {
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;

        bool operator==(const ThreadIdentityKey& other) const noexcept
        {
            return processId == other.processId && threadId == other.threadId;
        }
    };

    // ThreadIdentityKeyHash：为 unordered_map 提供轻量哈希。
    struct ThreadIdentityKeyHash
    {
        std::size_t operator()(const ThreadIdentityKey& key) const noexcept
        {
            const std::uint64_t combined =
                (static_cast<std::uint64_t>(key.processId) << 32U) |
                static_cast<std::uint64_t>(key.threadId);
            return std::hash<std::uint64_t>{}(combined);
        }
    };

    // hexPointerText 作用：统一格式化地址；不可用地址按调用方要求显示 Unavailable。
    QString hexPointerText(const std::uint64_t addressValue, const bool zeroAsUnavailable)
    {
        if (zeroAsUnavailable && addressValue == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        // 补零到 16 位：表格按显示文本排序，不补零时 "0x7FF..." 会排在
        // "0xFFFF..." 之后、长短不一的地址也会乱序，与已补零的对象类型/
        // SSDT/内核 Hook 等页面表现相反。
        // toUpper 只作用于十六进制位，避免把前缀一起写成 "0X"。
        return QStringLiteral("0x%1")
            .arg(QString::number(static_cast<qulonglong>(addressValue), 16)
                     .rightJustified(16, QChar('0'))
                     .toUpper());
    }

    // threadR0StatusText 作用：把共享协议状态转换为线程表短文本。
    QString threadR0StatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_THREAD_R0_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_THREAD_R0_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_THREAD_R0_STATUS_DYNDATA_MISSING:
            return QStringLiteral("DynData missing");
        case KSWORD_ARK_THREAD_R0_STATUS_READ_FAILED:
            return QStringLiteral("Read failed");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // threadR0CrossViewStatusText 作用：
    // - 输入 threadRecord：R3 基础线程与 R0 线程扩展合并后的记录；
    // - 处理：优先呈现 cross-view 可疑状态，再回退普通 R0 字段读取状态；
    // - 返回：线程表“R0状态”列文本，R0-only 行明确标注 hidden suspect。
    QString threadR0CrossViewStatusText(const ks::process::SystemThreadRecord& threadRecord)
    {
        const bool hiddenFromActiveThreadList =
            (threadRecord.r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_HIDDEN_FROM_ACTIVE_THREAD_LIST) != 0U;
        const bool ownerProcessHidden =
            (threadRecord.r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_OWNER_PROCESS_HIDDEN) != 0U;

        if (threadRecord.isR0OnlyThread || hiddenFromActiveThreadList)
        {
            return ownerProcessHidden
                ? QStringLiteral("R0-only / hidden suspect / owner hidden")
                : QStringLiteral("R0-only / hidden suspect");
        }
        if (ownerProcessHidden)
        {
            return QStringLiteral("Owner process hidden");
        }
        return threadR0StatusText(threadRecord.r0ThreadStatus);
    }

    // isSystemThreadRecord：System 进程（固定 PID 4）承载 PsCreateSystemThread 创建的内核线程。
    bool isSystemThreadRecord(const ks::process::SystemThreadRecord& threadRecord)
    {
        return threadRecord.ownerPid == 4U;
    }

    // threadClassText：ActiveExWorker 的 present 位用于区分 false 与 DynData 不可用。
    QString threadClassText(const ks::process::SystemThreadRecord& threadRecord)
    {
        const bool workerKnown =
            (threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_ACTIVE_EX_WORKER_PRESENT) != 0U;
        const bool activeWorker =
            (threadRecord.r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_ACTIVE_EX_WORKER) != 0U;
        if (workerKnown && activeWorker)
        {
            return ks::i18n::contextText(
                QStringLiteral("process.thread.class.worker"),
                QStringLiteral("工作线程"));
        }
        if (isSystemThreadRecord(threadRecord))
        {
            return workerKnown
                ? ks::i18n::contextText(
                    QStringLiteral("process.thread.class.system"),
                    QStringLiteral("系统线程"))
                : ks::i18n::contextText(
                    QStringLiteral("process.thread.class.system_unknown"),
                    QStringLiteral("系统线程（Worker未知）"));
        }
        return workerKnown
            ? ks::i18n::contextText(
                QStringLiteral("process.thread.class.regular"),
                QStringLiteral("普通线程"))
            : ks::i18n::contextText(
                QStringLiteral("process.thread.class.regular_unknown"),
                QStringLiteral("普通线程（Worker未知）"));
    }

    // threadDynFieldSourceText 作用：
    // - 输入 sourceValue：KSW_DYN_FIELD_SOURCE_* 字段来源枚举；
    // - 处理：把 R0 返回的来源值转换为 tooltip 可读文本；
    // - 返回：稳定 UI 文本，未知值保留原始数字以便诊断协议漂移。
    QString threadDynFieldSourceText(const std::uint32_t sourceValue)
    {
        switch (sourceValue)
        {
        case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
            return QStringLiteral("System Informer DynData");
        case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("Runtime pattern");
        case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
            return QStringLiteral("Ksword extra table");
        case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        case KSW_DYN_FIELD_SOURCE_UNAVAILABLE:
            return QStringLiteral("Unavailable");
        default:
            return QStringLiteral("Unknown(%1)").arg(sourceValue);
        }
    }

    // threadIoMessageText 作用：
    // - 输入：ArkDriverClient 返回的线程枚举 io.message；
    // - 处理：把 DeviceIoControl/unsupported/capability/buffer 等底层文本转为人读说明；
    // - 返回：适合线程页状态栏、诊断文本和日志展示的短文本。
    QString threadIoMessageText(const QString& rawMessageText)
    {
        const QString trimmedText = rawMessageText.trimmed();
        if (trimmedText.isEmpty())
        {
            return QStringLiteral("驱动未返回额外说明。");
        }

        const QString lowerText = trimmedText.toLower();
        if (lowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return QStringLiteral("驱动线程枚举接口调用失败或当前驱动版本不匹配。");
        }
        if (lowerText.contains(QStringLiteral("unsupported")) ||
            lowerText.contains(QStringLiteral("not supported")) ||
            lowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return QStringLiteral("当前驱动暂不支持线程 cross-view / KTHREAD 扩展枚举。");
        }
        if (lowerText.contains(QStringLiteral("dyndata")) ||
            lowerText.contains(QStringLiteral("capability")))
        {
            return QStringLiteral("DynData 动态偏移能力未满足，线程 R0 扩展字段暂不可用。");
        }
        if (lowerText.contains(QStringLiteral("buffer")) &&
            (lowerText.contains(QStringLiteral("small")) || lowerText.contains(QStringLiteral("trunc"))))
        {
            return QStringLiteral("驱动返回缓冲区不足，线程枚举结果可能被截断。");
        }
        return trimmedText;
    }

    // threadIoMessageStdString 作用：
    // - 输入：ArkDriverClient 的 std::string 原始消息；
    // - 处理：复用 threadIoMessageText 归一化，再转回 UTF-8；
    // - 返回：兼容旧 diagnosticTextOut 拼接管线的 std::string。
    std::string threadIoMessageStdString(const std::string& rawMessageText)
    {
        return threadIoMessageText(QString::fromStdString(rawMessageText)).toStdString();
    }

    // threadR0DiagnosticText 作用：
    // - 选中线程或悬停 R0 状态列时展示字段来源与原始偏移；
    // - Phase 3 暂不新增详情页，先用状态栏/tooltip 暴露诊断信息。
    QString threadR0DiagnosticText(const ks::process::SystemThreadRecord& threadRecord)
    {
        auto offsetText = [](const std::uint32_t offsetValue) -> QString {
            if (offsetValue == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE)
            {
                return QStringLiteral("Unavailable");
            }
            return QStringLiteral("0x%1").arg(offsetValue, 0, 16).toUpper();
        };

        QStringList offsetParts;
        offsetParts
            << QStringLiteral("Initial=%1").arg(offsetText(threadRecord.r0KtInitialStackOffset))
            << QStringLiteral("StackLimit=%1").arg(offsetText(threadRecord.r0KtStackLimitOffset))
            << QStringLiteral("StackBase=%1").arg(offsetText(threadRecord.r0KtStackBaseOffset))
            << QStringLiteral("KernelStack=%1").arg(offsetText(threadRecord.r0KtKernelStackOffset))
            << QStringLiteral("ReadOps=%1").arg(offsetText(threadRecord.r0KtReadOperationCountOffset))
            << QStringLiteral("WriteOps=%1").arg(offsetText(threadRecord.r0KtWriteOperationCountOffset))
            << QStringLiteral("OtherOps=%1").arg(offsetText(threadRecord.r0KtOtherOperationCountOffset))
            << QStringLiteral("ReadBytes=%1").arg(offsetText(threadRecord.r0KtReadTransferCountOffset))
            << QStringLiteral("WriteBytes=%1").arg(offsetText(threadRecord.r0KtWriteTransferCountOffset))
            << QStringLiteral("OtherBytes=%1").arg(offsetText(threadRecord.r0KtOtherTransferCountOffset));

        return QStringLiteral("R0=%1 | Flags=0x%2 | StackSource=%3 | IoSource=%4 | Cap=0x%5 | Offsets: %6")
            .arg(threadR0CrossViewStatusText(threadRecord))
            .arg(static_cast<qulonglong>(threadRecord.r0ThreadFlags), 0, 16)
            .arg(threadDynFieldSourceText(threadRecord.r0StackFieldSource))
            .arg(threadDynFieldSourceText(threadRecord.r0IoFieldSource))
            .arg(static_cast<qulonglong>(threadRecord.r0ThreadDynDataCapabilityMask), 0, 16)
            .arg(offsetParts.join(QStringLiteral(", ")));
    }

    // mergeThreadR0Entry 作用：把 ArkDriverClient 解析后的 R0 行覆盖到 R3 线程记录中。
    void mergeThreadR0Entry(
        ks::process::SystemThreadRecord& threadRecord,
        const ksword::ark::ThreadEntry& r0Entry)
    {
        threadRecord.r0ThreadFlags = r0Entry.flags;
        threadRecord.r0ThreadFieldFlags = r0Entry.fieldFlags;
        threadRecord.r0ThreadStatus = r0Entry.r0Status;
        threadRecord.r0StackFieldSource = r0Entry.stackFieldSource;
        threadRecord.r0IoFieldSource = r0Entry.ioFieldSource;
        threadRecord.r0InitialStack = r0Entry.initialStack;
        threadRecord.r0StackLimit = r0Entry.stackLimit;
        threadRecord.r0StackBase = r0Entry.stackBase;
        threadRecord.r0KernelStack = r0Entry.kernelStack;
        threadRecord.r0ReadOperationCount = r0Entry.readOperationCount;
        threadRecord.r0WriteOperationCount = r0Entry.writeOperationCount;
        threadRecord.r0OtherOperationCount = r0Entry.otherOperationCount;
        threadRecord.r0ReadTransferCount = r0Entry.readTransferCount;
        threadRecord.r0WriteTransferCount = r0Entry.writeTransferCount;
        threadRecord.r0OtherTransferCount = r0Entry.otherTransferCount;
        threadRecord.r0KtInitialStackOffset = r0Entry.ktInitialStackOffset;
        threadRecord.r0KtStackLimitOffset = r0Entry.ktStackLimitOffset;
        threadRecord.r0KtStackBaseOffset = r0Entry.ktStackBaseOffset;
        threadRecord.r0KtKernelStackOffset = r0Entry.ktKernelStackOffset;
        threadRecord.r0KtReadOperationCountOffset = r0Entry.ktReadOperationCountOffset;
        threadRecord.r0KtWriteOperationCountOffset = r0Entry.ktWriteOperationCountOffset;
        threadRecord.r0KtOtherOperationCountOffset = r0Entry.ktOtherOperationCountOffset;
        threadRecord.r0KtReadTransferCountOffset = r0Entry.ktReadTransferCountOffset;
        threadRecord.r0KtWriteTransferCountOffset = r0Entry.ktWriteTransferCountOffset;
        threadRecord.r0KtOtherTransferCountOffset = r0Entry.ktOtherTransferCountOffset;
        threadRecord.r0ThreadDynDataCapabilityMask = r0Entry.dynDataCapabilityMask;
    }

    // mergeThreadR0Snapshot 作用：
    // - R3 基础线程列表一定先保留；
    // - 驱动缺失或 IOCTL 失败时仅追加诊断，不清空 R3 结果；
    // - 成功时按 PID/TID 合并 KTHREAD 栈字段和 I/O counter。
    bool mergeThreadR0Snapshot(
        std::vector<ks::process::SystemThreadRecord>& threadList,
        std::string* diagnosticTextOut)
    {
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::ThreadEnumResult r0Result =
            driverClient.enumerateThreads(
                KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL | KSWORD_ARK_ENUM_THREAD_FLAG_SCAN_CID_TABLE);
        if (!r0Result.io.ok)
        {
            if (diagnosticTextOut != nullptr)
            {
                if (!diagnosticTextOut->empty())
                {
                    *diagnosticTextOut += " | ";
                }
                *diagnosticTextOut += "R0 thread extension unavailable: " + threadIoMessageStdString(r0Result.io.message);
            }
            return false;
        }

        std::unordered_map<ThreadIdentityKey, const ksword::ark::ThreadEntry*, ThreadIdentityKeyHash> r0ByThread;
        r0ByThread.reserve(r0Result.entries.size());
        std::unordered_map<std::uint32_t, const ksword::ark::ThreadEntry*> r0OnlyByTid;
        for (const ksword::ark::ThreadEntry& r0Entry : r0Result.entries)
        {
            if (r0Entry.threadId == 0U)
            {
                continue;
            }
            r0ByThread.insert_or_assign(
                ThreadIdentityKey{ r0Entry.processId, r0Entry.threadId },
                &r0Entry);
            if ((r0Entry.flags & KSWORD_ARK_THREAD_FLAG_HIDDEN_FROM_ACTIVE_THREAD_LIST) != 0U)
            {
                r0OnlyByTid.insert_or_assign(r0Entry.threadId, &r0Entry);
            }
        }

        const std::size_t r3BaseThreadCount = threadList.size();
        std::size_t mergedCount = 0;
        for (ks::process::SystemThreadRecord& threadRecord : threadList)
        {
            const auto r0It = r0ByThread.find(ThreadIdentityKey{ threadRecord.ownerPid, threadRecord.threadId });
            if (r0It == r0ByThread.end() || r0It->second == nullptr)
            {
                continue;
            }
            mergeThreadR0Entry(threadRecord, *(r0It->second));
            ++mergedCount;
        }

        std::size_t appendedR0OnlyCount = 0;
        for (const auto& r0OnlyPair : r0OnlyByTid)
        {
            const ksword::ark::ThreadEntry* r0OnlyEntry = r0OnlyPair.second;
            if (r0OnlyEntry == nullptr)
            {
                continue;
            }

            const bool alreadyPresent = std::any_of(
                threadList.begin(),
                threadList.end(),
                [r0OnlyEntry](const ks::process::SystemThreadRecord& threadRecord)
                {
                    return threadRecord.threadId == r0OnlyEntry->threadId &&
                        threadRecord.ownerPid == r0OnlyEntry->processId;
                });
            if (alreadyPresent)
            {
                continue;
            }

            ks::process::SystemThreadRecord threadRecord{};
            threadRecord.threadId = r0OnlyEntry->threadId;
            threadRecord.ownerPid = r0OnlyEntry->processId;
            threadRecord.ownerProcessName = "Unknown";
            threadRecord.priority = std::numeric_limits<int>::min();
            threadRecord.basePriority = std::numeric_limits<int>::min();
            threadRecord.threadState = std::numeric_limits<std::uint32_t>::max();
            threadRecord.waitReason = std::numeric_limits<std::uint32_t>::max();
            threadRecord.r0ThreadFlags = r0OnlyEntry->flags;
            threadRecord.isR0OnlyThread = true;
            mergeThreadR0Entry(threadRecord, *r0OnlyEntry);
            threadList.push_back(std::move(threadRecord));
            ++appendedR0OnlyCount;
        }

        if (diagnosticTextOut != nullptr)
        {
            if (!diagnosticTextOut->empty())
            {
                *diagnosticTextOut += " | ";
            }
            std::ostringstream stream;
            stream << "R0 thread extension merged: " << mergedCount
                << "/" << r3BaseThreadCount
                << ", r0OnlyAppended=" << appendedR0OnlyCount
                << ", " << threadIoMessageStdString(r0Result.io.message);
            *diagnosticTextOut += stream.str();
        }
        return true;
    }

    // buildThreadButtonStyle 作用：
    // - 提供线程页按钮统一蓝色样式；
    // - 图标按钮和文字按钮共用同一套边框/悬停色逻辑。
    QString buildThreadButtonStyle(const bool iconOnlyButton)
    {
        const QString paddingText = iconOnlyButton ? QStringLiteral("4px") : QStringLiteral("4px 10px");
        return QStringLiteral(
            "QPushButton {"
            "  color: %1;"
            "  background: %6;"
            "  border: 1px solid %2;"
            "  border-radius: 3px;"
            "  padding: %5;"
            "}"
            "QPushButton:hover {"
            "  background: %3;"
            "  color: %7;"
            "  border: 1px solid %3;"
            "}"
            "QPushButton:pressed {"
            "  background: %4;"
            "  color: %7;"
            "}")
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue, 0, -26))
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue, -14, -40))
            .arg(paddingText)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    // buildThreadSearchStyle 作用：统一线程页搜索框边框与焦点色。
    QString buildThreadSearchStyle()
    {
        return QStringLiteral(
            "QLineEdit {"
            "  border: 1px solid %2;"
            "  border-radius: 3px;"
            "  background: %3;"
            "  color: %4;"
            "  padding: 3px 5px;"
            "}"
            "QLineEdit:focus {"
            "  border: 1px solid %1;"
            "}")
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    // buildThreadPresetButtonStyle：A/B 相邻按钮共用 checked 高亮，仅圆化外侧边角。
    QString buildThreadPresetButtonStyle(const bool leftButton)
    {
        const QString outerRadius = leftButton
            ? QStringLiteral("border-top-left-radius:3px;border-bottom-left-radius:3px;")
            : QStringLiteral("border-top-right-radius:3px;border-bottom-right-radius:3px;border-left:0px;");
        return QStringLiteral(
            "QPushButton{"
            "  min-width:27px;max-width:27px;min-height:26px;max-height:26px;"
            "  padding:0px;font-weight:700;"
            "  color:%1;background:%2;border:1px solid %3;"
            "  border-radius:0px;%4"
            "}"
            "QPushButton:hover:!checked{background:%5;color:%1;}"
            "QPushButton:checked{background:%6;color:%7;border-color:%6;}"
            "QPushButton:pressed{background:%8;color:%7;}")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex())
            .arg(outerRadius)
            .arg(KswordTheme::PrimaryBlueSubtleHex())
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::OnAccentDynamicHex())
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue, -10, -36));
    }
}

int ProcessDock::toThreadColumnIndex(const ThreadTableColumn column)
{
    return static_cast<int>(column);
}

void ProcessDock::initializeThreadPage()
{
    // 线程页结构：
    // 1) 顶部操作栏（刷新按钮 + 搜索框 + 状态）；
    // 2) 下方线程表格（支持排序、右键动作）。
    m_threadPage = new QWidget(this);
    m_threadPageLayout = new QVBoxLayout(m_threadPage);
    m_threadPageLayout->setContentsMargins(6, 6, 6, 6);
    m_threadPageLayout->setSpacing(6);

    // 顶部操作栏控件：全部采用图标按钮 + Tooltip。
    m_threadTopLayout = new QHBoxLayout();
    m_threadTopLayout->setContentsMargins(0, 0, 0, 0);
    m_threadTopLayout->setSpacing(8);

    m_threadRefreshButton = new QPushButton(QIcon(IconThreadRefresh), "", m_threadPage);
    KswordTheme::ApplyCompactIconButtonMetrics(m_threadRefreshButton);
    m_threadRefreshButton->setToolTip("刷新系统线程列表（优先 NtQuerySystemInformation）");
    m_threadRefreshButton->setStyleSheet(buildThreadButtonStyle(true));

    // A/B 按钮必须相邻：A 默认高亮，B 提供地址与 R0 诊断列。
    m_threadColumnPresetWidget = new QWidget(m_threadPage);
    m_threadColumnPresetLayout = new QHBoxLayout(m_threadColumnPresetWidget);
    m_threadColumnPresetLayout->setContentsMargins(0, 0, 0, 0);
    m_threadColumnPresetLayout->setSpacing(0);
    m_threadColumnPresetAButton = new QPushButton(QStringLiteral("A"), m_threadColumnPresetWidget);
    m_threadColumnPresetBButton = new QPushButton(QStringLiteral("B"), m_threadColumnPresetWidget);
    m_threadColumnPresetAButton->setCheckable(true);
    m_threadColumnPresetBButton->setCheckable(true);
    m_threadColumnPresetLayout->addWidget(m_threadColumnPresetAButton);
    m_threadColumnPresetLayout->addWidget(m_threadColumnPresetBButton);
    ks::i18n::LanguageManager::instance().bindToolTip(
        m_threadColumnPresetAButton,
        QStringLiteral("process.thread.columns.preset_a.tooltip"),
        QStringLiteral("线程列预设 A：调度概览"));
    ks::i18n::LanguageManager::instance().bindToolTip(
        m_threadColumnPresetBButton,
        QStringLiteral("process.thread.columns.preset_b.tooltip"),
        QStringLiteral("线程列预设 B：地址与 R0 诊断"));

    m_threadScopeCombo = new QComboBox(m_threadPage);
    m_threadScopeCombo->addItem(QStringLiteral("全部线程"), static_cast<int>(ThreadScopeFilter::All));
    m_threadScopeCombo->addItem(QStringLiteral("系统线程"), static_cast<int>(ThreadScopeFilter::System));
    m_threadScopeCombo->addItem(QStringLiteral("工作线程"), static_cast<int>(ThreadScopeFilter::Worker));
    ks::i18n::LanguageManager::instance().bindComboBoxItem(
        m_threadScopeCombo, 0, QStringLiteral("process.thread.scope.all"), QStringLiteral("全部线程"));
    ks::i18n::LanguageManager::instance().bindComboBoxItem(
        m_threadScopeCombo, 1, QStringLiteral("process.thread.scope.system"), QStringLiteral("系统线程"));
    ks::i18n::LanguageManager::instance().bindComboBoxItem(
        m_threadScopeCombo, 2, QStringLiteral("process.thread.scope.worker"), QStringLiteral("工作线程"));
    ks::i18n::LanguageManager::instance().bindToolTip(
        m_threadScopeCombo,
        QStringLiteral("process.thread.scope.tooltip"),
        QStringLiteral("按线程类别筛选；工作线程由 R0 DynData v4 的 _ETHREAD.ActiveExWorker 位识别"));
    m_threadScopeCombo->setMinimumWidth(112);

    m_threadSearchLineEdit = new QLineEdit(m_threadPage);
    m_threadSearchLineEdit->setClearButtonEnabled(true);
    m_threadSearchLineEdit->setPlaceholderText("搜索 TID / PID / 进程名 / 状态 / 启动地址");
    m_threadSearchLineEdit->setToolTip("过滤当前线程列表，不触发新的系统查询");
    m_threadSearchLineEdit->setStyleSheet(buildThreadSearchStyle());
    m_threadSearchLineEdit->setMaximumWidth(360);

    m_threadTopLayout->addWidget(m_threadRefreshButton);
    m_threadTopLayout->addWidget(m_threadColumnPresetWidget);
    m_threadTopLayout->addWidget(m_threadScopeCombo);
    m_threadTopLayout->addWidget(m_threadSearchLineEdit);
    m_threadTopLayout->addStretch(1);
    m_threadPageLayout->addLayout(m_threadTopLayout);

    // 线程表格初始化：使用 QTreeWidget 以支持首列图标与多列排序。
    m_threadTable = new QTreeWidget(m_threadPage);
    m_threadTable->setColumnCount(static_cast<int>(ThreadTableColumn::Count));
    m_threadTable->setHeaderLabels(ThreadTableHeaders);
    m_threadTable->setRootIsDecorated(false);
    m_threadTable->setItemsExpandable(false);
    m_threadTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_threadTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_threadTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_threadTable->setUniformRowHeights(true);
    m_threadTable->setAlternatingRowColors(true);
    m_threadTable->setSortingEnabled(true);
    m_threadTable->setContextMenuPolicy(Qt::CustomContextMenu);

    QHeaderView* threadHeaderView = m_threadTable->header();
    threadHeaderView->setSectionsMovable(true);
    threadHeaderView->setStretchLastSection(false);
    threadHeaderView->setContextMenuPolicy(Qt::CustomContextMenu);
    threadHeaderView->setStyleSheet(QStringLiteral(
        "QHeaderView::section {"
        "  color: %1;"
        "  background: transparent; /* %2 */"
        "  border: 1px solid %3;"
        "  padding: 4px;"
        "  font-weight: 600;"
        "}")
        .arg(KswordTheme::PrimaryBlueHex)
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::BorderHex()));

    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ThreadId), 90);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::OwnerPid), 90);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ProcessName), 240);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ThreadClass), 150);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::StartAddress), 140);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::Win32StartAddress), 140);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::TebBaseAddress), 140);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::UserStackBase), 140);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::UserStackLimit), 140);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::KernelStack), 140);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::KStackBase), 140);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::KStackLimit), 140);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::InitialStack), 140);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ReadOps), 100);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::WriteOps), 100);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::OtherOps), 100);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ReadBytes), 120);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::WriteBytes), 120);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::OtherBytes), 120);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ThreadR0Status), 130);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::Priority), 96);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::BasePriority), 96);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ThreadState), 140);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::WaitReason), 170);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::KernelTimeMs), 110);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::UserTimeMs), 110);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::CpuTimeMs), 120);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::WaitTimeTick), 110);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ContextSwitches), 120);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::CreateTime), 170);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ProcessPath), 360);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::CpuPercent), 105);

    // Issue #33 指定默认使用 A；此处在所有初始列宽设置完成后应用隐藏集合。
    applyThreadColumnLayout(ThreadColumnLayout::PresetA);

    m_threadPageLayout->addWidget(m_threadTable, 1);
    m_sideTabWidget->addTab(m_threadPage, blueTintedIcon(IconThreadTab), "线程列表");
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget,
        m_threadPage,
        QStringLiteral("process.tab.threads"),
        QStringLiteral("线程列表"));
    refreshSideTabIconContrast();
}

void ProcessDock::applyThreadColumnLayout(const ThreadColumnLayout layout)
{
    if (m_threadTable == nullptr || layout == ThreadColumnLayout::Custom)
    {
        m_threadColumnLayout = layout;
        updateThreadColumnPresetButtons();
        return;
    }

    static constexpr std::array<ThreadTableColumn, 10> PresetAColumns{
        ThreadTableColumn::ThreadId,
        ThreadTableColumn::OwnerPid,
        ThreadTableColumn::ProcessName,
        ThreadTableColumn::ThreadClass,
        ThreadTableColumn::Priority,
        ThreadTableColumn::ThreadState,
        ThreadTableColumn::WaitReason,
        ThreadTableColumn::CpuTimeMs,
        ThreadTableColumn::CpuPercent,
        ThreadTableColumn::ContextSwitches
    };
    static constexpr std::array<ThreadTableColumn, 9> PresetBColumns{
        ThreadTableColumn::ThreadId,
        ThreadTableColumn::OwnerPid,
        ThreadTableColumn::ProcessName,
        ThreadTableColumn::ThreadClass,
        ThreadTableColumn::StartAddress,
        ThreadTableColumn::Win32StartAddress,
        ThreadTableColumn::TebBaseAddress,
        ThreadTableColumn::KernelStack,
        ThreadTableColumn::ThreadR0Status
    };
    const auto columnIsVisible = [layout](const ThreadTableColumn column) {
        if (layout == ThreadColumnLayout::PresetA)
        {
            return std::find(PresetAColumns.cbegin(), PresetAColumns.cend(), column) !=
                PresetAColumns.cend();
        }
        return std::find(PresetBColumns.cbegin(), PresetBColumns.cend(), column) !=
            PresetBColumns.cend();
    };

    m_threadApplyingColumnLayout = true;
    for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::Count); ++columnIndex)
    {
        const ThreadTableColumn column = static_cast<ThreadTableColumn>(columnIndex);
        const bool visible = columnIsVisible(column);
        m_threadTable->setColumnHidden(columnIndex, !visible);
    }

    // 两套预设各自控制在约一屏宽度内，避免横向滚动才能看完核心信息。
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ThreadId), 78);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::OwnerPid), 78);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ProcessName), 180);
    m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ThreadClass), 140);
    if (layout == ThreadColumnLayout::PresetA)
    {
        m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::Priority), 88);
        m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ThreadState), 125);
        m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::WaitReason), 145);
        m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::CpuTimeMs), 105);
        m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::CpuPercent), 100);
        m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ContextSwitches), 115);
    }
    else
    {
        m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::StartAddress), 132);
        m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::Win32StartAddress), 132);
        m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::TebBaseAddress), 132);
        m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::KernelStack), 132);
        m_threadTable->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::ThreadR0Status), 130);
    }
    m_threadApplyingColumnLayout = false;
    m_threadColumnLayout = layout;
    updateThreadColumnPresetButtons();
}

void ProcessDock::clearThreadColumnPresetSelection()
{
    if (m_threadApplyingColumnLayout)
    {
        return;
    }
    m_threadColumnLayout = ThreadColumnLayout::Custom;
    updateThreadColumnPresetButtons();
}

void ProcessDock::updateThreadColumnPresetButtons()
{
    if (m_threadColumnPresetAButton == nullptr || m_threadColumnPresetBButton == nullptr)
    {
        return;
    }

    const QSignalBlocker presetABlocker(m_threadColumnPresetAButton);
    const QSignalBlocker presetBBlocker(m_threadColumnPresetBButton);
    m_threadColumnPresetAButton->setStyleSheet(buildThreadPresetButtonStyle(true));
    m_threadColumnPresetBButton->setStyleSheet(buildThreadPresetButtonStyle(false));
    m_threadColumnPresetAButton->setChecked(m_threadColumnLayout == ThreadColumnLayout::PresetA);
    m_threadColumnPresetBButton->setChecked(m_threadColumnLayout == ThreadColumnLayout::PresetB);
}

void ProcessDock::showThreadHeaderContextMenu(const QPoint& localPosition)
{
    if (m_threadTable == nullptr || m_threadTable->header() == nullptr)
    {
        return;
    }

    // 表头菜单显式使用不透明主题样式；每列均可独立显示/隐藏。
    QMenu columnMenu(m_threadTable);
    columnMenu.setStyleSheet(buildThreadContextMenuStyle());
    for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::Count); ++columnIndex)
    {
        QAction* columnAction = columnMenu.addAction(
            ks::i18n::displayText(ThreadTableHeaders.value(columnIndex)));
        columnAction->setCheckable(true);
        columnAction->setChecked(!m_threadTable->isColumnHidden(columnIndex));
        connect(columnAction, &QAction::toggled, &columnMenu, [this, columnIndex](const bool visible)
            {
                m_threadTable->setColumnHidden(columnIndex, !visible);
                clearThreadColumnPresetSelection();
            });
    }
    columnMenu.exec(m_threadTable->header()->mapToGlobal(localPosition));
}

void ProcessDock::initializeThreadPageConnections()
{
    // 刷新按钮：用户主动刷新线程列表，忽略监控开关。
    if (m_threadRefreshButton != nullptr)
    {
        connect(m_threadRefreshButton, &QPushButton::clicked, this, [this]() {
            requestAsyncThreadRefresh(true);
        });
    }

    // 搜索框：仅过滤当前缓存结果，不触发系统调用。
    if (m_threadSearchLineEdit != nullptr)
    {
        connect(m_threadSearchLineEdit, &QLineEdit::textChanged, this, [this](const QString&) {
            rebuildThreadTable();
        });
    }

    // 类别筛选：仅过滤当前线程快照，避免因切换筛选器重复请求 R0。
    if (m_threadScopeCombo != nullptr)
    {
        connect(m_threadScopeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
            rebuildThreadTable();
        });
    }

    if (m_threadColumnPresetAButton != nullptr)
    {
        connect(m_threadColumnPresetAButton, &QPushButton::clicked, this, [this]() {
            applyThreadColumnLayout(ThreadColumnLayout::PresetA);
        });
    }
    if (m_threadColumnPresetBButton != nullptr)
    {
        connect(m_threadColumnPresetBButton, &QPushButton::clicked, this, [this]() {
            applyThreadColumnLayout(ThreadColumnLayout::PresetB);
        });
    }

    // 线程表右键菜单：挂起/恢复/结束线程 + 转到进程详情。
    if (m_threadTable != nullptr)
    {
        connect(m_threadTable, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
            showThreadTableContextMenu(localPosition);
        });

        QHeaderView* threadHeader = m_threadTable->header();
        connect(threadHeader, &QHeaderView::customContextMenuRequested, this, [this](const QPoint& localPosition) {
            showThreadHeaderContextMenu(localPosition);
        });
        connect(threadHeader, &QHeaderView::sectionMoved, this, [this](int, int, int) {
            clearThreadColumnPresetSelection();
        });
        connect(threadHeader, &QHeaderView::sectionResized, this, [this](int, int, int) {
            clearThreadColumnPresetSelection();
        });
    }
}

void ProcessDock::requestAsyncThreadRefresh(const bool forceRefresh)
{
    if (m_threadTable == nullptr)
    {
        return;
    }

    // 非强制刷新时，遵守监控开关和菜单冻结规则。
    if (!forceRefresh)
    {
        if (!m_monitoringEnabled || m_threadContextMenuVisible)
        {
            return;
        }
    }

    // 并发保护：线程刷新同一时刻只允许一个后台任务。
    if (m_threadRefreshInProgress)
    {
        return;
    }

    m_threadRefreshInProgress = true;
    const std::uint64_t localTicket = ++m_threadRefreshTicket;
    auto previousThreadCounters = m_threadCounterSampleByIdentity;
    auto cpuCoreUsageSnapshot = m_latestCpuCoreUsageSnapshot;
    const std::uint32_t logicalCpuCount = m_logicalCpuCount;

    if (m_threadRefreshButton != nullptr)
    {
        m_threadRefreshButton->setEnabled(false);
    }

    {
        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 线程列表刷新开始, ticket=" << localTicket
            << ", force=" << (forceRefresh ? "true" : "false")
            << eol;
    }

    QPointer<ProcessDock> guardThis(this);
    QRunnable* backgroundTask = QRunnable::create([
        guardThis,
        localTicket,
        logicalCpuCount,
        previousThreadCounters = std::move(previousThreadCounters),
        cpuCoreUsageSnapshot = std::move(cpuCoreUsageSnapshot)]() mutable {
        bool usedNtQuery = false;
        std::string diagnosticText;
        std::vector<ks::process::SystemThreadRecord> threadList =
            ks::process::EnumerateSystemThreads(&usedNtQuery, &diagnosticText);
        const bool r0ThreadExtensionMerged = mergeThreadR0Snapshot(threadList, &diagnosticText);

        const std::uint64_t currentTick100ns = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count() / 100);
        auto nextThreadCounters =
            std::make_shared<std::unordered_map<std::string, ks::process::ThreadCounterSample>>();
        nextThreadCounters->reserve(threadList.size());
        for (ks::process::SystemThreadRecord& threadRecord : threadList)
        {
            const std::string identityKey = ks::process::BuildThreadIdentityKey(
                threadRecord.ownerPid,
                threadRecord.threadId,
                threadRecord.createTime100ns);
            const auto previousIt = previousThreadCounters.find(identityKey);
            ks::process::ThreadCounterSample nextSample{};
            ks::process::UpdateThreadCpuUsage(
                threadRecord,
                previousIt != previousThreadCounters.end() ? &previousIt->second : nullptr,
                nextSample,
                logicalCpuCount,
                currentTick100ns);
            nextThreadCounters->emplace(identityKey, nextSample);

            // CSwitch 区间可用时优先采用真实调度归因；无运行事件的存活线程按 0% 显示。
            if (cpuCoreUsageSnapshot != nullptr &&
                cpuCoreUsageSnapshot->monitorRunning &&
                cpuCoreUsageSnapshot->sampleReady &&
                !cpuCoreUsageSnapshot->dataLossDetected)
            {
                const auto coreUsageIt = cpuCoreUsageSnapshot->threadUsageByIdentity.find(
                    ks::process::BuildCpuThreadIdentity(threadRecord.ownerPid, threadRecord.threadId));
                threadRecord.cpuPercent = coreUsageIt != cpuCoreUsageSnapshot->threadUsageByIdentity.end()
                    ? coreUsageIt->second.coreEquivalentPercent
                    : 0.0;
                threadRecord.cpuUsageReady = true;
            }
        }

        auto deferredThreadList =
            std::make_shared<std::vector<ks::process::SystemThreadRecord>>(std::move(threadList));
        QMetaObject::invokeMethod(guardThis, [guardThis, localTicket, usedNtQuery, r0ThreadExtensionMerged, diagnosticText, deferredThreadList, nextThreadCounters]() {
            if (guardThis == nullptr)
            {
                return;
            }

            if (guardThis->m_threadRefreshTicket != localTicket)
            {
                guardThis->m_threadRefreshInProgress = false;
                if (guardThis->m_threadRefreshButton != nullptr)
                {
                    guardThis->m_threadRefreshButton->setEnabled(true);
                }
                return;
            }

            auto commit = [
                guardThis,
                localTicket,
                usedNtQuery,
                r0ThreadExtensionMerged,
                diagnosticText,
                deferredThreadList,
                nextThreadCounters]() mutable
            {
                if (guardThis == nullptr || guardThis->m_threadRefreshTicket != localTicket)
                {
                    return;
                }

                guardThis->m_threadRecordList = std::move(*deferredThreadList);
                guardThis->m_threadCounterSampleByIdentity = std::move(*nextThreadCounters);
                guardThis->m_threadDiagnosticText = diagnosticText;
                guardThis->rebuildThreadTable();

                {
                    kLogEvent logEvent;
                    info << logEvent
                        << "[ProcessDock] 线程列表刷新完成, ticket=" << localTicket
                        << ", count=" << guardThis->m_threadRecordList.size()
                        << ", usedNtQuery=" << (usedNtQuery ? "true" : "false")
                        << ", r0ThreadExtensionMerged=" << (r0ThreadExtensionMerged ? "true" : "false")
                        << ", diagnostic=" << guardThis->m_threadDiagnosticText
                        << eol;
                }

                guardThis->m_threadRefreshInProgress = false;
                if (guardThis->m_threadRefreshButton != nullptr)
                {
                    guardThis->m_threadRefreshButton->setEnabled(true);
                }
            };
            if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                    guardThis.data(),
                    QStringLiteral("process-thread-snapshot-apply"),
                    {guardThis->m_threadTable},
                    commit))
            {
                return;
            }
            commit();
        }, Qt::QueuedConnection);
    });
    backgroundTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(backgroundTask);
}

bool ProcessDock::threadRecordMatchesSearch(const ks::process::SystemThreadRecord& threadRecord) const
{
    if (m_threadSearchLineEdit == nullptr)
    {
        return true;
    }

    const QString searchText = m_threadSearchLineEdit->text().trimmed();
    if (searchText.isEmpty())
    {
        return true;
    }

    const QStringList searchableFields{
        QString::number(threadRecord.threadId),
        QString::number(threadRecord.ownerPid),
        QString::fromStdString(threadRecord.ownerProcessName),
        threadClassText(threadRecord),
        hexPointerText(threadRecord.startAddress, false),
        QString("0x%1").arg(static_cast<qulonglong>(threadRecord.win32StartAddress), 0, 16).toUpper(),
        QString("0x%1").arg(static_cast<qulonglong>(threadRecord.tebBaseAddress), 0, 16).toUpper(),
        QString("0x%1").arg(static_cast<qulonglong>(threadRecord.r0KernelStack), 0, 16).toUpper(),
        threadStateText(threadRecord.threadState),
        threadWaitReasonText(threadRecord.waitReason),
        threadR0CrossViewStatusText(threadRecord)
    };
    for (const QString& fieldText : searchableFields)
    {
        if (fieldText.contains(searchText, Qt::CaseInsensitive))
        {
            return true;
        }
    }

    return false;
}

bool ProcessDock::threadRecordMatchesScope(const ks::process::SystemThreadRecord& threadRecord) const
{
    if (m_threadScopeCombo == nullptr)
    {
        return true;
    }

    const ThreadScopeFilter scope = static_cast<ThreadScopeFilter>(
        m_threadScopeCombo->currentData().toInt());
    if (scope == ThreadScopeFilter::System)
    {
        return isSystemThreadRecord(threadRecord);
    }
    if (scope == ThreadScopeFilter::Worker)
    {
        return
            (threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_ACTIVE_EX_WORKER_PRESENT) != 0U &&
            (threadRecord.r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_ACTIVE_EX_WORKER) != 0U;
    }
    return true;
}

void ProcessDock::rebuildThreadTable()
{
    if (m_threadTable == nullptr)
    {
        return;
    }

    QSignalBlocker tableSignalBlocker(m_threadTable);
    m_threadTable->setSortingEnabled(false);
    m_threadTable->clear();

    // processRecordByPid 用途：按 PID 复用进程缓存中的路径与图标信息。
    std::unordered_map<std::uint32_t, const ks::process::ProcessRecord*> processRecordByPid;
    processRecordByPid.reserve(m_cacheByIdentity.size());
    for (const auto& cachePair : m_cacheByIdentity)
    {
        const ks::process::ProcessRecord& processRecord = cachePair.second.record;
        const auto pidIt = processRecordByPid.find(processRecord.pid);
        if (pidIt == processRecordByPid.end())
        {
            processRecordByPid.emplace(processRecord.pid, &processRecord);
            continue;
        }

        // 选择 imagePath 非空的一条，提升线程页进程图标命中率。
        if (pidIt->second != nullptr &&
            pidIt->second->imagePath.empty() &&
            !processRecord.imagePath.empty())
        {
            processRecordByPid[processRecord.pid] = &processRecord;
        }
    }

    // 逐行构建线程列表：
    // - 先按搜索词过滤；
    // - 再填充文本和图标；
    // - 最后写入 TID/PID 到 UserRole，供右键动作读取。
    for (const ks::process::SystemThreadRecord& threadRecord : m_threadRecordList)
    {
        if (!threadRecordMatchesScope(threadRecord) || !threadRecordMatchesSearch(threadRecord))
        {
            continue;
        }

        const auto processIt = processRecordByPid.find(threadRecord.ownerPid);

        QTreeWidgetItem* rowItem = new QTreeWidgetItem();
        for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::Count); ++columnIndex)
        {
            const ThreadTableColumn column = static_cast<ThreadTableColumn>(columnIndex);
            rowItem->setText(columnIndex, formatThreadColumnText(threadRecord, column));
        }

        // 进程列图标：优先使用进程缓存中的 imagePath，保证同进程图标可复用缓存。
        ks::process::ProcessRecord iconSourceRecord{};
        if (processIt != processRecordByPid.end() && processIt->second != nullptr)
        {
            iconSourceRecord = *(processIt->second);
            if (threadRecord.ownerProcessName.empty() || threadRecord.ownerProcessName == "Unknown")
            {
                rowItem->setText(
                    toThreadColumnIndex(ThreadTableColumn::ProcessName),
                    QString::fromStdString(iconSourceRecord.processName.empty() ? "Unknown" : iconSourceRecord.processName));
            }
        }
        else
        {
            iconSourceRecord.pid = threadRecord.ownerPid;
            iconSourceRecord.processName = threadRecord.ownerProcessName;
        }
        rowItem->setIcon(toThreadColumnIndex(ThreadTableColumn::ProcessName), resolveProcessIcon(iconSourceRecord));

        rowItem->setData(
            toThreadColumnIndex(ThreadTableColumn::ThreadId),
            Qt::UserRole,
            QVariant::fromValue(static_cast<qulonglong>(threadRecord.threadId)));
        rowItem->setData(
            toThreadColumnIndex(ThreadTableColumn::ThreadId),
            Qt::UserRole + 1,
            QVariant::fromValue(static_cast<qulonglong>(threadRecord.ownerPid)));
        rowItem->setToolTip(
            toThreadColumnIndex(ThreadTableColumn::ThreadR0Status),
            threadR0DiagnosticText(threadRecord));

        // R0-only 线程使用红色高亮，已终止线程使用灰色高亮；两者都只影响展示。
        if (threadRecord.isR0OnlyThread ||
            (threadRecord.r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_HIDDEN_FROM_ACTIVE_THREAD_LIST) != 0U)
        {
            const QColor suspectForeground = KswordTheme::ErrorColor();
            const QColor suspectBackground = KswordTheme::WithAlpha(
                KswordTheme::ErrorBackgroundColor(),
                KswordTheme::IsDarkModeEnabled() ? 140 : 255);
            for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::Count); ++columnIndex)
            {
                rowItem->setForeground(columnIndex, QBrush(suspectForeground));
                rowItem->setBackground(columnIndex, QBrush(suspectBackground));
            }
        }
        else if (threadRecord.threadState == 4)
        {
            for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::Count); ++columnIndex)
            {
                rowItem->setForeground(columnIndex, QBrush(KswordTheme::ExitedRowForegroundColor()));
            }
        }

        m_threadTable->addTopLevelItem(rowItem);
    }

    m_threadTable->setSortingEnabled(true);
    m_threadTable->sortItems(toThreadColumnIndex(ThreadTableColumn::OwnerPid), Qt::AscendingOrder);
}

QString ProcessDock::formatThreadColumnText(
    const ks::process::SystemThreadRecord& threadRecord,
    const ThreadTableColumn column) const
{
    switch (column)
    {
    case ThreadTableColumn::ThreadId:
        return QString::number(threadRecord.threadId);
    case ThreadTableColumn::OwnerPid:
        return QString::number(threadRecord.ownerPid);
    case ThreadTableColumn::ProcessName:
        return QString::fromStdString(threadRecord.ownerProcessName.empty() ? "Unknown" : threadRecord.ownerProcessName);
    case ThreadTableColumn::ThreadClass:
        return threadClassText(threadRecord);
    case ThreadTableColumn::StartAddress:
        return hexPointerText(threadRecord.startAddress, false);
    case ThreadTableColumn::Win32StartAddress:
        return hexPointerText(threadRecord.win32StartAddress, true);
    case ThreadTableColumn::TebBaseAddress:
        return hexPointerText(threadRecord.tebBaseAddress, true);
    case ThreadTableColumn::UserStackBase:
        return hexPointerText(threadRecord.stackBase, true);
    case ThreadTableColumn::UserStackLimit:
        return hexPointerText(threadRecord.stackLimit, true);
    case ThreadTableColumn::KernelStack:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_KERNEL_STACK_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return hexPointerText(threadRecord.r0KernelStack, true);
    case ThreadTableColumn::KStackBase:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_STACK_BASE_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return hexPointerText(threadRecord.r0StackBase, true);
    case ThreadTableColumn::KStackLimit:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_STACK_LIMIT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return hexPointerText(threadRecord.r0StackLimit, true);
    case ThreadTableColumn::InitialStack:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_INITIAL_STACK_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return hexPointerText(threadRecord.r0InitialStack, true);
    case ThreadTableColumn::ReadOps:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_READ_OPERATION_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0ReadOperationCount));
    case ThreadTableColumn::WriteOps:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_WRITE_OPERATION_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0WriteOperationCount));
    case ThreadTableColumn::OtherOps:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_OTHER_OPERATION_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0OtherOperationCount));
    case ThreadTableColumn::ReadBytes:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_READ_TRANSFER_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0ReadTransferCount));
    case ThreadTableColumn::WriteBytes:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_WRITE_TRANSFER_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0WriteTransferCount));
    case ThreadTableColumn::OtherBytes:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_OTHER_TRANSFER_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0OtherTransferCount));
    case ThreadTableColumn::ThreadR0Status:
        return threadR0CrossViewStatusText(threadRecord);
    case ThreadTableColumn::Priority:
        if (threadRecord.priority == std::numeric_limits<int>::min())
        {
            return QStringLiteral("N/A");
        }
        return QString::number(threadRecord.priority);
    case ThreadTableColumn::BasePriority:
        if (threadRecord.basePriority == std::numeric_limits<int>::min())
        {
            return QStringLiteral("N/A");
        }
        return QString::number(threadRecord.basePriority);
    case ThreadTableColumn::ThreadState:
        return threadStateText(threadRecord.threadState);
    case ThreadTableColumn::WaitReason:
        return threadWaitReasonText(threadRecord.waitReason);
    case ThreadTableColumn::KernelTimeMs:
        return QString::number(static_cast<double>(threadRecord.kernelTime100ns) / 10000.0, 'f', 2);
    case ThreadTableColumn::UserTimeMs:
        return QString::number(static_cast<double>(threadRecord.userTime100ns) / 10000.0, 'f', 2);
    case ThreadTableColumn::CpuTimeMs:
        return QString::number(
            static_cast<double>(threadRecord.kernelTime100ns + threadRecord.userTime100ns) / 10000.0,
            'f',
            2);
    case ThreadTableColumn::WaitTimeTick:
        return QString::number(threadRecord.waitTimeTick);
    case ThreadTableColumn::ContextSwitches:
        return QString::number(threadRecord.contextSwitchCount);
    case ThreadTableColumn::CreateTime:
        if (threadRecord.createTime100ns == 0)
        {
            return QStringLiteral("-");
        }
        return QString::fromStdString(ks::str::FileTime100nsToLocalText(threadRecord.createTime100ns));
    case ThreadTableColumn::ProcessPath:
    {
        for (const auto& cachePair : m_cacheByIdentity)
        {
            if (cachePair.second.record.pid == threadRecord.ownerPid &&
                !cachePair.second.record.imagePath.empty())
            {
                return QString::fromStdString(cachePair.second.record.imagePath);
            }
        }
        return QStringLiteral("-");
    }
    case ThreadTableColumn::CpuPercent:
        return threadRecord.cpuUsageReady
            ? QString::number(threadRecord.cpuPercent, 'f', 2) + QStringLiteral("%")
            : QStringLiteral("-");
    default:
        return QString();
    }
}

QString ProcessDock::threadStateText(const std::uint32_t stateValue) const
{
    if (stateValue == std::numeric_limits<std::uint32_t>::max())
    {
        return QStringLiteral("N/A");
    }

    switch (stateValue)
    {
    case 0: return QStringLiteral("Initialized(0)");
    case 1: return QStringLiteral("Ready(1)");
    case 2: return QStringLiteral("Running(2)");
    case 3: return QStringLiteral("Standby(3)");
    case 4: return QStringLiteral("Terminated(4)");
    case 5: return QStringLiteral("Waiting(5)");
    case 6: return QStringLiteral("Transition(6)");
    case 7: return QStringLiteral("DeferredReady(7)");
    case 8: return QStringLiteral("GateWait(8)");
    case 9: return QStringLiteral("WaitingForProcessInSwap(9)");
    default:
        return QString("Unknown(%1)").arg(stateValue);
    }
}

QString ProcessDock::threadWaitReasonText(const std::uint32_t waitReasonValue) const
{
    if (waitReasonValue == std::numeric_limits<std::uint32_t>::max())
    {
        return QStringLiteral("N/A");
    }

    switch (waitReasonValue)
    {
    case 0: return QStringLiteral("Executive(0)");
    case 1: return QStringLiteral("FreePage(1)");
    case 2: return QStringLiteral("PageIn(2)");
    case 3: return QStringLiteral("PoolAllocation(3)");
    case 4: return QStringLiteral("DelayExecution(4)");
    case 5: return QStringLiteral("Suspended(5)");
    case 6: return QStringLiteral("UserRequest(6)");
    case 7: return QStringLiteral("WrExecutive(7)");
    case 8: return QStringLiteral("WrFreePage(8)");
    case 9: return QStringLiteral("WrPageIn(9)");
    case 10: return QStringLiteral("WrPoolAllocation(10)");
    case 11: return QStringLiteral("WrDelayExecution(11)");
    case 12: return QStringLiteral("WrSuspended(12)");
    case 13: return QStringLiteral("WrUserRequest(13)");
    case 14: return QStringLiteral("WrEventPair(14)");
    case 15: return QStringLiteral("WrQueue(15)");
    case 16: return QStringLiteral("WrLpcReceive(16)");
    case 17: return QStringLiteral("WrLpcReply(17)");
    case 18: return QStringLiteral("WrVirtualMemory(18)");
    case 19: return QStringLiteral("WrPageOut(19)");
    case 20: return QStringLiteral("WrRendezvous(20)");
    case 21: return QStringLiteral("Spare2(21)");
    case 22: return QStringLiteral("Spare3(22)");
    case 23: return QStringLiteral("Spare4(23)");
    case 24: return QStringLiteral("Spare5(24)");
    case 25: return QStringLiteral("WrCalloutStack(25)");
    case 26: return QStringLiteral("WrKernel(26)");
    case 27: return QStringLiteral("WrResource(27)");
    case 28: return QStringLiteral("WrPushLock(28)");
    case 29: return QStringLiteral("WrMutex(29)");
    case 30: return QStringLiteral("WrQuantumEnd(30)");
    case 31: return QStringLiteral("WrDispatchInt(31)");
    case 32: return QStringLiteral("WrPreempted(32)");
    case 33: return QStringLiteral("WrYieldExecution(33)");
    case 34: return QStringLiteral("WrFastMutex(34)");
    case 35: return QStringLiteral("WrGuardedMutex(35)");
    case 36: return QStringLiteral("WrRundown(36)");
    case 37: return QStringLiteral("WrAlertByThreadId(37)");
    case 38: return QStringLiteral("WrDeferredPreempt(38)");
    case 39: return QStringLiteral("WrPhysicalFault(39)");
    case 40: return QStringLiteral("WrIoRing(40)");
    case 41: return QStringLiteral("WrMdlCache(41)");
    case 42: return QStringLiteral("WrRcu(42)");
    default:
        return QString("Unknown(%1)").arg(waitReasonValue);
    }
}

QString ProcessDock::buildThreadContextMenuStyle() const
{
    // 右键菜单高风险点处理：
    // - 明确写死深浅色下背景与文字颜色；
    // - 禁止依赖默认样式，避免浅色模式出现黑底黑字问题。
    const QString menuBackgroundColor = KswordTheme::SurfaceHex();
    const QString menuTextColor = KswordTheme::TextPrimaryHex();
    const QString menuBorderColor = KswordTheme::BorderHex();
    const QString menuDisabledColor = KswordTheme::TextDisabledColorHex();

    return QStringLiteral(
        "QMenu{"
        "  background:%1;"
        "  color:%2;"
        "  border:1px solid %3;"
        "}"
        "QMenu::item{"
        "  padding:4px 16px 4px 12px;"
        "  background:transparent;"
        "}"
        "QMenu::item:selected{"
        "  background:%4;"
        "  color:%6;"
        "}"
        "QMenu::item:disabled{"
        "  color:%5;"
        "  background:transparent;"
        "}"
        "QMenu::separator{"
        "  height:1px;"
        "  background:%3;"
        "  margin:2px 6px;"
        "}")
        .arg(menuBackgroundColor)
        .arg(menuTextColor)
        .arg(menuBorderColor)
        .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
        .arg(menuDisabledColor)
        .arg(KswordTheme::OnAccentDynamicHex());
}

void ProcessDock::bindThreadContextActionToItem(QTreeWidgetItem* clickedItem)
{
    clearThreadContextActionBinding();
    if (clickedItem == nullptr)
    {
        return;
    }

    m_threadContextActionTid = clickedItem->data(
        toThreadColumnIndex(ThreadTableColumn::ThreadId),
        Qt::UserRole).toULongLong();
    m_threadContextActionPid = clickedItem->data(
        toThreadColumnIndex(ThreadTableColumn::ThreadId),
        Qt::UserRole + 1).toULongLong();
}

void ProcessDock::clearThreadContextActionBinding()
{
    m_threadContextActionTid = 0;
    m_threadContextActionPid = 0;
    m_threadContextMenuVisible = false;
}

const ks::process::SystemThreadRecord* ProcessDock::selectedThreadRecord() const
{
    std::uint32_t targetTid = m_threadContextActionTid;
    std::uint32_t targetPid = m_threadContextActionPid;

    // 若右键绑定为空，则回退当前选中行（键盘触发时会走这里）。
    if ((targetTid == 0 || targetPid == 0) && m_threadTable != nullptr)
    {
        QTreeWidgetItem* currentItem = m_threadTable->currentItem();
        if (currentItem != nullptr)
        {
            targetTid = currentItem->data(
                toThreadColumnIndex(ThreadTableColumn::ThreadId),
                Qt::UserRole).toULongLong();
            targetPid = currentItem->data(
                toThreadColumnIndex(ThreadTableColumn::ThreadId),
                Qt::UserRole + 1).toULongLong();
        }
    }

    if (targetTid == 0 || targetPid == 0)
    {
        return nullptr;
    }

    for (const ks::process::SystemThreadRecord& threadRecord : m_threadRecordList)
    {
        if (threadRecord.threadId == targetTid && threadRecord.ownerPid == targetPid)
        {
            return &threadRecord;
        }
    }
    return nullptr;
}

void ProcessDock::showThreadTableContextMenu(const QPoint& localPosition)
{
    if (m_threadTable == nullptr)
    {
        return;
    }

    QTreeWidgetItem* clickedItem = m_threadTable->itemAt(localPosition);
    if (clickedItem == nullptr)
    {
        clearThreadContextActionBinding();
        return;
    }

    m_threadTable->setCurrentItem(clickedItem);
    const int clickedColumn = m_threadTable->columnAt(localPosition.x());
    if (clickedColumn >= 0)
    {
        m_threadTable->setCurrentItem(clickedItem, clickedColumn);
    }
    bindThreadContextActionToItem(clickedItem);

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(buildThreadContextMenuStyle());

    QAction* copyCellAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_copy_cell.svg"),
        "复制单元格");
    QAction* copyRowAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_copy_row.svg"),
        "复制行");
    contextMenu.addSeparator();
    QAction* detailAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_details.svg"),
        "转到进程详细信息");
    QAction* stackAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_threads.svg"),
        "查看调用栈");
    const ks::process::SystemThreadRecord* clickedThreadRecord = selectedThreadRecord();
    const bool clickedThreadIsR0Only =
        clickedThreadRecord != nullptr &&
        (clickedThreadRecord->isR0OnlyThread ||
            ((clickedThreadRecord->r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_HIDDEN_FROM_ACTIVE_THREAD_LIST) != 0U));
    QMenu* const affinityMenu = ks::process::addThreadAffinitySubMenu(
        &contextMenu,
        blueTintedIcon(":/Icon/process_priority.svg"),
        clickedThreadRecord != nullptr ? clickedThreadRecord->ownerPid : 0U,
        clickedThreadRecord != nullptr ? clickedThreadRecord->threadId : 0U,
        clickedThreadRecord != nullptr ? clickedThreadRecord->createTime100ns : 0U,
        buildThreadContextMenuStyle(),
        [this](const bool actionOk, const QString& resultText)
        {
            kLogEvent actionEvent;
            (actionOk ? info : err) << actionEvent
                << "[ProcessDock] thread affinity update: actionOk="
                << (actionOk ? "true" : "false")
                << ", detail="
                << resultText.toStdString()
                << eol;
            showActionResultMessage(
                ks::i18n::contextText(
                    QStringLiteral("process.thread.menu.affinity"),
                    QStringLiteral("线程亲和性")),
                actionOk,
                resultText.toStdString(),
                actionEvent);
            requestAsyncThreadRefresh(true);
        });
    QAction* suspendAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_suspend.svg"),
        "挂起线程");
    QAction* resumeAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_resume.svg"),
        "恢复线程");
    QAction* r0SuspendThreadAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_suspend.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.r0_suspend"),
            QStringLiteral("R0挂起线程")));
    QAction* r0ResumeThreadAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_resume.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.r0_resume"),
            QStringLiteral("R0恢复线程")));
    QAction* suspendDriverThreadAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_suspend.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_suspend"),
            QStringLiteral("ZwSuspendThread / NtSuspendThread（实验性）")));
    QAction* resumeDriverThreadAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_resume.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_resume"),
            QStringLiteral("ZwResumeThread / NtResumeThread（实验性）")));
    QMenu* terminateDriverThreadMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_terminate_experimental"),
            QStringLiteral("结束驱动线程（实验性原始 API）")));
    QAction* terminateDriverThreadPspAction = terminateDriverThreadMenu->addAction(
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_terminate.psp"),
            QStringLiteral("PspTerminateThreadByPointer（实验性/未文档化）")));
    QAction* terminateDriverThreadZwAction = terminateDriverThreadMenu->addAction(
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_terminate.zw"),
            QStringLiteral("ZwTerminateThread / NtTerminateThread（实验性）")));
    QAction* terminateDriverThreadNormalApcAction = terminateDriverThreadMenu->addAction(
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_terminate.normal_apc"),
            QStringLiteral("KeInsertQueueApc → Normal Kernel APC → PsTerminateSystemThread（实验性）")));
    QAction* terminateDriverThreadSpecialApcAction = terminateDriverThreadMenu->addAction(
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_terminate.special_apc"),
            QStringLiteral("KeInsertQueueApc → Special Kernel APC → Normal Kernel APC → PsTerminateSystemThread（实验性）")));
    terminateDriverThreadMenu->addSeparator();
    QAction* firmwareRebootAction = terminateDriverThreadMenu->addAction(
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.hal_return_to_firmware"),
            QStringLiteral("HalReturnToFirmware(HalRebootRoutine)（实验性/整机动作）")));
    QAction* terminateAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        "结束线程");
    QAction* r0TerminateThreadAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.r0_terminate"),
            QStringLiteral("R0结束线程")));

    const bool hasR0ThreadControlTarget =
        clickedThreadRecord != nullptr &&
        clickedThreadRecord->ownerPid > 4U &&
        clickedThreadRecord->threadId != 0U;
    const bool hasDriverThreadTarget =
        clickedThreadRecord != nullptr &&
        clickedThreadRecord->ownerPid == 4U &&
        clickedThreadRecord->threadId != 0U &&
        clickedThreadRecord->createTime100ns != 0ULL &&
        (clickedThreadRecord->startAddress != 0ULL ||
         clickedThreadRecord->win32StartAddress != 0ULL);
    r0SuspendThreadAction->setEnabled(hasR0ThreadControlTarget);
    r0ResumeThreadAction->setEnabled(hasR0ThreadControlTarget);
    r0TerminateThreadAction->setEnabled(hasR0ThreadControlTarget);
    suspendDriverThreadAction->setVisible(hasDriverThreadTarget);
    resumeDriverThreadAction->setVisible(hasDriverThreadTarget);
    terminateDriverThreadMenu->menuAction()->setVisible(hasDriverThreadTarget);
    if (clickedThreadIsR0Only)
    {
        // R0-only/CID-only 行不把 suspect TID 交给 R3 操作，但允许按已验证 PID/TID 走 R0 单线程结束。
        stackAction->setEnabled(false);
        suspendAction->setEnabled(false);
        resumeAction->setEnabled(false);
        terminateAction->setEnabled(false);
        stackAction->setToolTip(QStringLiteral("R0-only / hidden suspect 行只读展示，不执行线程操作。"));
        suspendAction->setToolTip(QStringLiteral("R0-only / hidden suspect 行只读展示，不执行线程操作。"));
        resumeAction->setToolTip(QStringLiteral("R0-only / hidden suspect 行只读展示，不执行线程操作。"));
        terminateAction->setToolTip(QStringLiteral("R0-only / hidden suspect 行只读展示，不执行线程操作。"));
        if (affinityMenu != nullptr)
        {
            affinityMenu->setEnabled(false);
            affinityMenu->setToolTip(ks::i18n::contextText(
                QStringLiteral("process.thread.menu.affinity.suspect.tooltip"),
                QStringLiteral("R0-only / hidden suspect 行不执行 R3 线程亲和性操作。")));
        }
        const QString r0ControlToolTip = ks::i18n::contextText(
            QStringLiteral("process.thread.r0_control.suspect.tooltip"),
            QStringLiteral("R0-only / hidden suspect 行可按 TID/PID 通过 R0 挂起或恢复指定线程。"));
        r0SuspendThreadAction->setToolTip(r0ControlToolTip);
        r0ResumeThreadAction->setToolTip(r0ControlToolTip);
        r0TerminateThreadAction->setToolTip(
            ks::i18n::contextText(
                QStringLiteral("process.thread.r0_terminate.suspect.tooltip"),
                QStringLiteral("R0-only / hidden suspect 行可按 TID/PID 结束指定线程。")));
    }

    m_threadContextMenuVisible = true;
    QAction* selectedAction = contextMenu.exec(m_threadTable->viewport()->mapToGlobal(localPosition));
    m_threadContextMenuVisible = false;
    if (selectedAction == nullptr)
    {
        clearThreadContextActionBinding();
        return;
    }

    {
        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 线程右键菜单执行动作: " << selectedAction->text().toStdString()
            << eol;
    }

    if (selectedAction == copyCellAction) { copyCurrentThreadCell(); }
    else if (selectedAction == copyRowAction) { copyCurrentThreadRow(); }
    else if (selectedAction == detailAction) { openThreadOwnerProcessDetails(); }
    else if (selectedAction == stackAction) { openThreadStackWindow(); }
    else if (selectedAction == suspendAction) { executeSuspendThreadAction(); }
    else if (selectedAction == resumeAction) { executeResumeThreadAction(); }
    else if (selectedAction == r0SuspendThreadAction) { executeR0SuspendThreadAction(); }
    else if (selectedAction == r0ResumeThreadAction) { executeR0ResumeThreadAction(); }
    else if (selectedAction == suspendDriverThreadAction) { executeSuspendDriverThreadAction(); }
    else if (selectedAction == resumeDriverThreadAction) { executeResumeDriverThreadAction(); }
    else if (selectedAction == terminateDriverThreadPspAction) { executeTerminateDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER); }
    else if (selectedAction == terminateDriverThreadZwAction) { executeTerminateDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT); }
    else if (selectedAction == terminateDriverThreadNormalApcAction) { executeTerminateDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC); }
    else if (selectedAction == terminateDriverThreadSpecialApcAction) { executeTerminateDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC); }
    else if (selectedAction == firmwareRebootAction) { executeExperimentalFirmwareRebootAction(); }
    else if (selectedAction == terminateAction) { executeTerminateThreadAction(); }
    else if (selectedAction == r0TerminateThreadAction) { executeR0TerminateThreadAction(); }

    clearThreadContextActionBinding();
}

void ProcessDock::copyCurrentThreadCell()
{
    if (m_threadTable == nullptr)
    {
        return;
    }

    QTreeWidgetItem* currentItem = m_threadTable->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }

    const int currentColumn = m_threadTable->currentColumn();
    if (currentColumn < 0)
    {
        return;
    }

    QApplication::clipboard()->setText(currentItem->text(currentColumn));
}

void ProcessDock::copyCurrentThreadRow()
{
    if (m_threadTable == nullptr)
    {
        return;
    }

    QTreeWidgetItem* currentItem = m_threadTable->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }

    QStringList rowFields;
    rowFields.reserve(static_cast<int>(ThreadTableColumn::Count));
    for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::Count); ++columnIndex)
    {
        rowFields.push_back(currentItem->text(columnIndex));
    }
    QApplication::clipboard()->setText(rowFields.join("\t"));
}

void ProcessDock::openThreadOwnerProcessDetails()
{
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr)
    {
        return;
    }

    kLogEvent actionEvent;
    if (threadRecord->ownerPid == 0)
    {
        const std::string detailText = "当前线程没有可用的所属进程 PID。";
        warn << actionEvent << "[ProcessDock] openThreadOwnerProcessDetails: ownerPid=0" << eol;
        showActionResultMessage("转到进程详细信息", false, detailText, actionEvent);
        return;
    }

    info << actionEvent
        << "[ProcessDock] openThreadOwnerProcessDetails: pid=" << threadRecord->ownerPid
        << ", tid=" << threadRecord->threadId
        << eol;
    openProcessDetailWindowByPid(threadRecord->ownerPid);
}

void ProcessDock::openThreadStackWindow()
{
    // Phase-8 调用栈入口：
    // - 从当前线程行构造 ThreadStackTarget；
    // - 用户态调用栈由 ThreadStackWindow 捕获；
    // - R0 KTHREAD 字段只作为内核栈边界诊断展示。
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr)
    {
        return;
    }

    ThreadStackTarget target{};
    target.processId = threadRecord->ownerPid;
    target.threadId = threadRecord->threadId;
    target.processName = QString::fromStdString(threadRecord->ownerProcessName);
    target.startAddress = threadRecord->startAddress;
    target.win32StartAddress = threadRecord->win32StartAddress;
    target.tebBaseAddress = threadRecord->tebBaseAddress;
    target.userStackBase = threadRecord->stackBase;
    target.userStackLimit = threadRecord->stackLimit;
    target.r0KernelStack = threadRecord->r0KernelStack;
    target.r0StackBase = threadRecord->r0StackBase;
    target.r0StackLimit = threadRecord->r0StackLimit;
    target.r0InitialStack = threadRecord->r0InitialStack;
    target.r0ThreadStatus = threadRecord->r0ThreadStatus;
    target.r0CapabilityMask = threadRecord->r0ThreadDynDataCapabilityMask;

    for (const auto& cachePair : m_cacheByIdentity)
    {
        if (cachePair.second.record.pid == threadRecord->ownerPid &&
            !cachePair.second.record.imagePath.empty())
        {
            target.processPath = QString::fromStdString(cachePair.second.record.imagePath);
            break;
        }
    }

    auto* stackWindow = new ThreadStackWindow(target, this);
    stackWindow->setAttribute(Qt::WA_DeleteOnClose, true);
    stackWindow->show();
    stackWindow->raise();
    stackWindow->activateWindow();

    kLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDock] openThreadStackWindow: pid=" << target.processId
        << ", tid=" << target.threadId
        << eol;
}

void ProcessDock::executeSuspendThreadAction()
{
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr)
    {
        return;
    }

    kLogEvent actionEvent;
    std::string detailText;
    const bool actionOk = ks::process::SuspendThreadIfIdentityMatches(
        threadRecord->threadId,
        threadRecord->ownerPid,
        threadRecord->createTime100ns,
        &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDock] executeSuspendThreadAction: tid=" << threadRecord->threadId
        << ", actionOk=" << (actionOk ? "true" : "false")
        << eol;
    showActionResultMessage("挂起线程", actionOk, detailText, actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeResumeThreadAction()
{
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr)
    {
        return;
    }

    kLogEvent actionEvent;
    std::string detailText;
    const bool actionOk = ks::process::ResumeThreadIfIdentityMatches(
        threadRecord->threadId,
        threadRecord->ownerPid,
        threadRecord->createTime100ns,
        &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDock] executeResumeThreadAction: tid=" << threadRecord->threadId
        << ", actionOk=" << (actionOk ? "true" : "false")
        << eol;
    showActionResultMessage("恢复线程", actionOk, detailText, actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeR0SuspendThreadAction()
{
    const ks::process::SystemThreadRecord* selectedThread = selectedThreadRecord();
    if (selectedThread == nullptr || selectedThread->ownerPid <= 4U ||
        selectedThread->threadId == 0U)
    {
        return;
    }
    const ks::process::SystemThreadRecord threadRecord = *selectedThread;

    const QMessageBox::StandardButton confirmation = QMessageBox::warning(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.confirm.title"),
            QStringLiteral("R0挂起线程")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.confirm.body"),
            QStringLiteral("将通过 R0 挂起 PID %2 的线程 %1。目标程序可能失去响应，是否继续？"))
            .arg(threadRecord.threadId)
            .arg(threadRecord.ownerPid),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmation != QMessageBox::Yes)
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.setThreadSuspended(
        threadRecord.threadId,
        threadRecord.ownerPid,
        true);
    const std::string detailText = threadIoMessageStdString(result.message);
    (result.ok ? info : err) << actionEvent
        << "[ProcessDock] executeR0SuspendThreadAction: pid="
        << threadRecord.ownerPid
        << ", tid="
        << threadRecord.threadId
        << ", actionOk="
        << (result.ok ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.result.title"),
            QStringLiteral("R0挂起线程")),
        result.ok,
        detailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeR0ResumeThreadAction()
{
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr || threadRecord->ownerPid <= 4U || threadRecord->threadId == 0U)
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.setThreadSuspended(
        threadRecord->threadId,
        threadRecord->ownerPid,
        false);
    const std::string detailText = threadIoMessageStdString(result.message);
    (result.ok ? info : err) << actionEvent
        << "[ProcessDock] executeR0ResumeThreadAction: pid="
        << threadRecord->ownerPid
        << ", tid="
        << threadRecord->threadId
        << ", actionOk="
        << (result.ok ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_resume.result.title"),
            QStringLiteral("R0恢复线程")),
        result.ok,
        detailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeSuspendDriverThreadAction()
{
    const ks::process::SystemThreadRecord* selectedThread = selectedThreadRecord();
    if (selectedThread == nullptr || selectedThread->ownerPid != 4U ||
        selectedThread->threadId == 0U || selectedThread->createTime100ns == 0ULL)
    {
        return;
    }
    // QMessageBox::critical enters a nested event loop. Preserve the complete
    // identity before opening it so an async table refresh cannot invalidate
    // the selected m_threadRecordList element or replace the requested target.
    const ks::process::SystemThreadRecord threadRecord = *selectedThread;
    const std::uint64_t startAddress = threadRecord.startAddress != 0ULL
        ? threadRecord.startAddress
        : threadRecord.win32StartAddress;
    if (startAddress == 0ULL)
    {
        return;
    }

    const QMessageBox::StandardButton confirmation = QMessageBox::critical(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_suspend.confirm.title"),
            QStringLiteral("挂起驱动线程")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_suspend.confirm.body"),
            QStringLiteral("即将挂起 System(PID 4) 的驱动线程 %1。此操作可能冻结磁盘、网络或安全组件，并可能导致系统死锁或蓝屏。仅在已保存工作且可强制重启时继续。"))
            .arg(threadRecord.threadId),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmation != QMessageBox::Yes)
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.controlDriverThread(
        threadRecord.threadId,
        startAddress,
        threadRecord.createTime100ns,
        KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND,
        KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE,
        true);
    const std::string detailText = threadIoMessageStdString(result.message);
    (result.ok ? info : err) << actionEvent
        << "[ProcessDock] executeSuspendDriverThreadAction: tid=" << threadRecord.threadId
        << ", start=0x" << std::hex << startAddress << std::dec
        << ", actionOk=" << (result.ok ? "true" : "false")
        << ", detail=" << detailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_suspend.result.title"),
            QStringLiteral("挂起驱动线程")),
        result.ok,
        detailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeResumeDriverThreadAction()
{
    const ks::process::SystemThreadRecord* selectedThread = selectedThreadRecord();
    if (selectedThread == nullptr || selectedThread->ownerPid != 4U ||
        selectedThread->threadId == 0U || selectedThread->createTime100ns == 0ULL)
    {
        return;
    }
    const ks::process::SystemThreadRecord threadRecord = *selectedThread;
    const std::uint64_t startAddress = threadRecord.startAddress != 0ULL
        ? threadRecord.startAddress
        : threadRecord.win32StartAddress;
    if (startAddress == 0ULL)
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.controlDriverThread(
        threadRecord.threadId,
        startAddress,
        threadRecord.createTime100ns,
        KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME,
        KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE,
        false);
    const std::string detailText = threadIoMessageStdString(result.message);
    (result.ok ? info : err) << actionEvent
        << "[ProcessDock] executeResumeDriverThreadAction: tid=" << threadRecord.threadId
        << ", start=0x" << std::hex << startAddress << std::dec
        << ", actionOk=" << (result.ok ? "true" : "false")
        << ", detail=" << detailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_resume.result.title"),
            QStringLiteral("恢复驱动线程")),
        result.ok,
        detailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeTerminateDriverThreadAction(const unsigned long terminateMethod)
{
    const ks::process::SystemThreadRecord* selectedThread = selectedThreadRecord();
    if (selectedThread == nullptr || selectedThread->ownerPid != 4U ||
        selectedThread->threadId == 0U || selectedThread->createTime100ns == 0ULL)
    {
        return;
    }
    // The two confirmation dialogs below both pump events. Keep the identity
    // tuple immutable across them and let R0 reject it if the live thread
    // changes before the action.
    const ks::process::SystemThreadRecord threadRecord = *selectedThread;
    const std::uint64_t startAddress = threadRecord.startAddress != 0ULL
        ? threadRecord.startAddress
        : threadRecord.win32StartAddress;
    if (startAddress == 0ULL)
    {
        return;
    }

    QString rawApiText;
    switch (terminateMethod)
    {
    case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER:
        rawApiText = QStringLiteral("PspTerminateThreadByPointer");
        break;
    case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT:
        rawApiText = QStringLiteral("ZwTerminateThread / NtTerminateThread");
        break;
    case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC:
        rawApiText = QStringLiteral("KeInsertQueueApc → Normal Kernel APC → PsTerminateSystemThread");
        break;
    case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC:
        rawApiText = QStringLiteral("KeInsertQueueApc → Special Kernel APC → Normal Kernel APC → PsTerminateSystemThread");
        break;
    default:
        return;
    }

    const QMessageBox::StandardButton confirmation = QMessageBox::critical(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_terminate.confirm.title"),
            QStringLiteral("强制结束驱动线程")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_terminate.confirm.body"),
            QStringLiteral("即将使用实验性原始 API“%2”结束 System(PID 4) 的驱动线程 %1。此操作不可撤销，可能立即造成数据损坏、系统死锁或蓝屏。APC 方法只表示成功排队，不保证送达或终止。仅在隔离测试环境并准备强制重启时继续。"))
            .arg(threadRecord.threadId)
            .arg(rawApiText),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmation != QMessageBox::Yes)
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.controlDriverThread(
        threadRecord.threadId,
        startAddress,
        threadRecord.createTime100ns,
        KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE,
        terminateMethod,
        true);
    const std::string detailText = threadIoMessageStdString(result.message);
    (result.ok ? info : err) << actionEvent
        << "[ProcessDock] executeTerminateDriverThreadAction: tid=" << threadRecord.threadId
        << ", start=0x" << std::hex << startAddress << std::dec
        << ", terminateMethod=" << terminateMethod
        << ", actionOk=" << (result.ok ? "true" : "false")
        << ", detail=" << detailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_terminate.result.title"),
            QStringLiteral("强制结束驱动线程")),
        result.ok,
        detailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeExperimentalFirmwareRebootAction()
{
    const QMessageBox::StandardButton firstConfirmation = QMessageBox::critical(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.confirm.title"),
            QStringLiteral("HalReturnToFirmware 实验性整机动作")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.confirm.body"),
            QStringLiteral("HalReturnToFirmware(HalRebootRoutine) 不是线程终止 API，而是不受支持的整机固件返回动作。它会绕过所选线程和进程保护，可能立即重启、丢失所有未保存数据，或在当前平台失败/崩溃。是否进入最终确认？")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (firstConfirmation != QMessageBox::Yes)
    {
        return;
    }
    const QMessageBox::StandardButton finalConfirmation = QMessageBox::critical(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.final.title"),
            QStringLiteral("最终确认：立即调用原始 API")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.final.body"),
            QStringLiteral("最后确认：立即调用 HalReturnToFirmware(HalRebootRoutine)。成功时系统不会返回本程序。")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (finalConfirmation != QMessageBox::Yes)
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.experimentalReturnToFirmware();
    const std::string detailText = threadIoMessageStdString(result.message);
    (result.ok ? warn : err) << actionEvent
        << "[ProcessDock] executeExperimentalFirmwareRebootAction: actionOk="
        << (result.ok ? "true" : "false")
        << ", detail=" << detailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.result.title"),
            QStringLiteral("HalReturnToFirmware 实验性整机动作")),
        result.ok,
        detailText,
        actionEvent);
}

void ProcessDock::executeTerminateThreadAction()
{
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr)
    {
        return;
    }

    kLogEvent actionEvent;
    std::string detailText;
    const bool actionOk = ks::process::TerminateThreadIfIdentityMatches(
        threadRecord->threadId,
        threadRecord->ownerPid,
        threadRecord->createTime100ns,
        &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDock] executeTerminateThreadAction: tid=" << threadRecord->threadId
        << ", actionOk=" << (actionOk ? "true" : "false")
        << eol;
    showActionResultMessage("结束线程", actionOk, detailText, actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeR0TerminateThreadAction()
{
    const ks::process::SystemThreadRecord* selectedThread = selectedThreadRecord();
    if (selectedThread == nullptr || selectedThread->ownerPid <= 4U ||
        selectedThread->threadId == 0U)
    {
        return;
    }
    const ks::process::SystemThreadRecord threadRecord = *selectedThread;

    const QMessageBox::StandardButton confirmation = QMessageBox::warning(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_terminate.confirm.title"),
            QStringLiteral("R0结束线程")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_terminate.confirm.body"),
            QStringLiteral("将通过 R0 结束 PID %2 的线程 %1。该操作不可撤销，是否继续？"))
            .arg(threadRecord.threadId)
            .arg(threadRecord.ownerPid),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmation != QMessageBox::Yes)
    {
        return;
    }

    kLogEvent actionEvent;
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::IoResult result = driverClient.terminateThread(
        threadRecord.threadId,
        threadRecord.ownerPid,
        static_cast<long>(0xC0000005u));
    const std::string detailText = threadIoMessageStdString(result.message);
    (result.ok ? info : err) << actionEvent
        << "[ProcessDock] executeR0TerminateThreadAction: pid="
        << threadRecord.ownerPid
        << ", tid="
        << threadRecord.threadId
        << ", actionOk="
        << (result.ok ? "true" : "false")
        << ", detail="
        << detailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_terminate.result.title"),
            QStringLiteral("R0结束线程")),
        result.ok,
        detailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}
