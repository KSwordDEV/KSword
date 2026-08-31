#include "ProcessDock.h"
#include "ProcessAffinityUtils.h"
#include "ProcessAffinityPersistence.h"
#include "ProcessCpuCapacityCell.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"

#include "../theme.h"
#include "ProcessDetailWindow.h"
#include "ProcessMessageHookWindow.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../UI/FlatTableModel.h"
#include "../UI/TableColumnAutoFit.h"
#include "../Internationalization/LanguageManager.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../ksword/network/network_process_etw_monitor.h"
#include "../ksword/process/ProcessImageDeleteGuard.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAbstractScrollArea>
#include <QApplication>
#include <QBrush>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCursor>
#include <QDateTime>
#include <QEasingCurve>
#include <QVariantAnimation>
#include <QDoubleSpinBox>
#include <QDir>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHelpEvent>
#include <QHBoxLayout>
#include <QItemSelection>
#include <QItemSelectionModel>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QList>
#include <QListView>
#include <QLocale>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPalette>
#include <QPlainTextEdit>
#include <QPointF>
#include <QPersistentModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QPixmap>
#include <QRectF>
#include <QRunnable>
#include <QResizeEvent>
#include <QScrollArea>
#include <QShortcut>
#include <QSettings>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QSortFilterProxyModel>
#include <QStyle>
#include <QStyleOptionSlider>
#include <QStyledItemDelegate>
#include <QSlider>
#include <QScrollBar>
#include <QSvgRenderer>
#include <QTabBar>
#include <QTableView>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QTextEdit>
#include <QThreadPool>
#include <QTimer>
#include <QToolTip>
#include <QStringList>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QToolButton>
#include <QWidgetAction>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <functional>
#include <limits>
#include <memory>
#include <sstream>
#include <set>
#include <string>
#include <thread>
#include <unordered_set>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>

#pragma comment(lib, "Advapi32.lib")

#ifndef SECURITY_MANDATORY_MEDIUM_PLUS_RID
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID (SECURITY_MANDATORY_MEDIUM_RID + 0x100UL)
#endif

#ifndef SECURITY_MANDATORY_PROTECTED_PROCESS_RID
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID 0x5000UL
#endif

#ifndef SE_GROUP_INTEGRITY
#define SE_GROUP_INTEGRITY 0x00000020L
#endif

namespace
{
    // 亲和性恢复失败后从 1 秒开始退避，避免短暂拒绝导致每轮刷新都重复打开句柄。
    constexpr std::uint32_t AffinityRestoreRetryBaseMilliseconds = 1000U;

    // 退避上限固定为 60 秒；达到上限后仍会继续重试，不会永久放弃该进程实例。
    constexpr std::uint32_t AffinityRestoreRetryMaximumMilliseconds = 60000U;

    // affinityRestoreRetryDelay 作用：
    // - 根据连续失败次数计算 1、2、4、8……秒的指数退避；
    // - 入参 consecutiveFailureCount：至少为 1 的连续失败次数；
    // - 返回：不超过 60 秒的下一次等待时长。
    std::chrono::milliseconds affinityRestoreRetryDelay(
        const std::uint32_t consecutiveFailureCount)
    {
        // exponent：限制左移位数，避免极端长生命周期进程触发整数溢出。
        const std::uint32_t exponent = std::min<std::uint32_t>(
            consecutiveFailureCount > 0U ? consecutiveFailureCount - 1U : 0U,
            6U);

        // scaledDelayMilliseconds：保存本轮指数增长后的毫秒值。
        const std::uint32_t scaledDelayMilliseconds =
            AffinityRestoreRetryBaseMilliseconds << exponent;

        // boundedDelayMilliseconds：将实际等待时间限制在明确的最大值内。
        const std::uint32_t boundedDelayMilliseconds = std::min(
            scaledDelayMilliseconds,
            AffinityRestoreRetryMaximumMilliseconds);
        return std::chrono::milliseconds(boundedDelayMilliseconds);
    }

    // 列标题文本常量，索引与 ProcessDock::TableColumn 一一对应。
    const QStringList ProcessTableHeaders{
        "进程名",
        "PID",
        "CPU",
        "内存",
        "磁盘",
        "GPU",
        "网络",
        "数字签名",
        "路径",
        "父进程",
        "命令行",
        "用户",
        "启动时间",
        "管理员",
        "PPL保护级别",
        "保护状态",
        "PPL",
        "句柄数",
        "HandleTable",
        "SectionObject",
        "R0状态",
        // ======== 任务管理器“详细信息”页对齐列 ========
        "程序包名称",
        "状态",
        "会话 ID",
        "作业对象 ID",
        "CPU 时间",
        "周期",
        "工作集(内存)",
        "峰值工作集(内存)",
        "工作集增量(内存)",
        "内存(活动的专用工作集)",
        "内存(专用工作集)",
        "内存(共享工作集)",
        "提交大小",
        "分页缓冲池",
        "非分页缓冲池",
        "页面错误",
        "页面错误增量",
        "基本优先级",
        "线程",
        "用户对象",
        "GDI 对象",
        "I/O 读取",
        "I/O 写入",
        "I/O 其他",
        "I/O 读取字节",
        "I/O 写入字节",
        "I/O 其他字节",
        "操作系统上下文",
        "平台",
        "UAC 虚拟化",
        "描述",
        "数据执行保护",
        "控制流保护",
        "硬件强制实施的堆栈保护",
        "企业上下文",
        "DPI 感知",
        "电源节流",
        "GPU 引擎",
        "专用 GPU 内存",
        "共享 GPU 内存",
        "类型",
        "CPU核心"
    };

    const char* const ProcessTableHeaderKeys[] = {
        "process.table.header.process_name",
        "process.table.header.pid",
        "process.table.header.cpu",
        "process.table.header.ram",
        "process.table.header.disk",
        "process.table.header.gpu",
        "process.table.header.net",
        "process.table.header.signature",
        "process.table.header.path",
        "process.table.header.parent",
        "process.table.header.command_line",
        "process.table.header.user",
        "process.table.header.start_time",
        "process.table.header.admin",
        "process.table.header.ppl_protection",
        "process.table.header.protection",
        "process.table.header.ppl",
        "process.table.header.handle_count",
        "process.table.header.handle_table",
        "process.table.header.section_object",
        "process.table.header.r0_status",
        // ======== 任务管理器“详细信息”页对齐列 ========
        "process.table.header.package_name",
        "process.table.header.status",
        "process.table.header.session_id",
        "process.table.header.job_object",
        "process.table.header.cpu_time",
        "process.table.header.cycle_time",
        "process.table.header.working_set",
        "process.table.header.peak_working_set",
        "process.table.header.working_set_delta",
        "process.table.header.active_private_working_set",
        "process.table.header.private_working_set",
        "process.table.header.shared_working_set",
        "process.table.header.commit_size",
        "process.table.header.paged_pool",
        "process.table.header.non_paged_pool",
        "process.table.header.page_faults",
        "process.table.header.page_fault_delta",
        "process.table.header.base_priority",
        "process.table.header.thread_count",
        "process.table.header.user_objects",
        "process.table.header.gdi_objects",
        "process.table.header.io_reads",
        "process.table.header.io_writes",
        "process.table.header.io_other",
        "process.table.header.io_read_bytes",
        "process.table.header.io_write_bytes",
        "process.table.header.io_other_bytes",
        "process.table.header.os_context",
        "process.table.header.platform",
        "process.table.header.uac_virtualization",
        "process.table.header.description",
        "process.table.header.dep",
        "process.table.header.cfg",
        "process.table.header.hardware_stack_protection",
        "process.table.header.enterprise_context",
        "process.table.header.dpi_awareness",
        "process.table.header.power_throttling",
        "process.table.header.gpu_engine",
        "process.table.header.gpu_dedicated_memory",
        "process.table.header.gpu_shared_memory",
        "process.table.header.process_type",
        "process.table.header.cpu_core"
    };

    // ProcessTableHeaderKeyCount：
    // - 供 initializeProcessTable 在运行时校验“表头数量 == TableColumn::Count”；
    // - TableColumn 是 ProcessDock 的私有嵌套枚举，无法在匿名命名空间内做编译期断言。
    constexpr std::size_t ProcessTableHeaderKeyCount =
        sizeof(ProcessTableHeaderKeys) / sizeof(ProcessTableHeaderKeys[0]);

    QString processContextText(const char* const key, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    }

    QString processContextText(const QString& key, const QString& sourceText)
    {
        return ks::i18n::contextText(key, sourceText);
    }

    QString translatedProcessHeader(const int section, const QString& sourceText)
    {
        if (section < 0 || section >= ProcessTableHeaders.size())
        {
            return sourceText;
        }
        const QString translatedBase = processContextText(ProcessTableHeaderKeys[section], ProcessTableHeaders.at(section));
        const QString sourceBase = ProcessTableHeaders.at(section);
        if (sourceText == sourceBase)
        {
            return translatedBase;
        }
        if (sourceText.startsWith(sourceBase + QChar(' ')))
        {
            return translatedBase + sourceText.mid(sourceBase.size());
        }
        return sourceText;
    }

    // ======== 任务管理器对齐列的取值格式化辅助 ========
    // 统一约定：
    // - 内存类列沿用任务管理器的“千字节 + 千位分隔符”写法（例如 12,345 K）；
    // - 计数类列使用带千位分隔符的整数；
    // - 字段未采集或系统不提供时显示 "-"，绝不用 0 冒充真实值。

    // ProcessColumnUnavailableText：未采集 / 不可用字段的统一占位符。
    const QString ProcessColumnUnavailableText = QStringLiteral("-");

    // processGroupedNumberText 作用：按当前区域设置给整数加千位分隔符。
    QString processGroupedNumberText(const std::uint64_t value)
    {
        return QLocale::system().toString(static_cast<qulonglong>(value));
    }

    // processGroupedSignedNumberText 作用：
    // - 输入：可能为负的增量值；
    // - 处理：正数补 "+"、负数补 "-"、零显示为 "0"，方便快速判断变化方向；
    // - 返回：带千位分隔符的带符号文本。
    QString processGroupedSignedNumberText(const std::int64_t value)
    {
        if (value == 0)
        {
            return QStringLiteral("0");
        }

        // 先取绝对值再补符号：直接对 INT64_MIN 取负会溢出，这里用无符号中转。
        const std::uint64_t magnitude = (value > 0)
            ? static_cast<std::uint64_t>(value)
            : (~static_cast<std::uint64_t>(value) + 1ULL);
        return (value > 0 ? QStringLiteral("+") : QStringLiteral("-")) + processGroupedNumberText(magnitude);
    }

    // processKilobyteText 作用：
    // - 把字节数换算为任务管理器风格的 "N K"；
    // - 向上取整到 1 KB，避免几百字节的真实占用被显示成 0 K。
    QString processKilobyteText(const std::uint64_t bytes)
    {
        const std::uint64_t kilobytes = (bytes == 0ULL) ? 0ULL : ((bytes + 1023ULL) / 1024ULL);
        return processGroupedNumberText(kilobytes) + QStringLiteral(" K");
    }

    // processSignedKilobyteText 作用：把带符号的字节增量换算成 "+N K" / "-N K"。
    QString processSignedKilobyteText(const std::int64_t deltaBytes)
    {
        if (deltaBytes == 0)
        {
            return QStringLiteral("0 K");
        }

        const std::uint64_t magnitude = (deltaBytes > 0)
            ? static_cast<std::uint64_t>(deltaBytes)
            : (~static_cast<std::uint64_t>(deltaBytes) + 1ULL);
        const std::uint64_t kilobytes = (magnitude + 1023ULL) / 1024ULL;
        return (deltaBytes > 0 ? QStringLiteral("+") : QStringLiteral("-"))
            + processGroupedNumberText(kilobytes)
            + QStringLiteral(" K");
    }

    // processMegabyteText 作用：GPU 显存列按任务管理器习惯显示为 MB。
    QString processMegabyteText(const std::uint64_t bytes)
    {
        return QString::number(static_cast<double>(bytes) / (1024.0 * 1024.0), 'f', 1)
            + QStringLiteral(" MB");
    }

    // processCpuTimeText 作用：把 100ns 单位的累计 CPU 时间格式化为 H:MM:SS。
    QString processCpuTimeText(const std::uint64_t cpuTime100ns)
    {
        const std::uint64_t totalSeconds = cpuTime100ns / 10000000ULL;
        const std::uint64_t hours = totalSeconds / 3600ULL;
        const std::uint64_t minutes = (totalSeconds / 60ULL) % 60ULL;
        const std::uint64_t seconds = totalSeconds % 60ULL;
        return QStringLiteral("%1:%2:%3")
            .arg(static_cast<qulonglong>(hours))
            .arg(static_cast<qulonglong>(minutes), 2, 10, QChar('0'))
            .arg(static_cast<qulonglong>(seconds), 2, 10, QChar('0'));
    }

    // processFeatureStateText 作用：
    // - 把 UAC 虚拟化 / 数据执行保护 / 控制流保护的三四态枚举转成展示文本；
    // - Unknown 表示尚未采集或查询被拒绝，统一显示占位符而不是“已禁用”。
    QString processFeatureStateText(const ks::process::ProcessFeatureState featureState)
    {
        switch (featureState)
        {
        case ks::process::ProcessFeatureState::NotAllowed:
            return processContextText("process.table.cell.feature_not_allowed", QStringLiteral("不允许"));
        case ks::process::ProcessFeatureState::Disabled:
            return processContextText("process.table.cell.feature_disabled", QStringLiteral("已禁用"));
        case ks::process::ProcessFeatureState::Enabled:
            return processContextText("process.table.cell.feature_enabled", QStringLiteral("已启用"));
        case ks::process::ProcessFeatureState::EnabledPermanent:
            return processContextText("process.table.cell.feature_enabled_permanent", QStringLiteral("已启用(永久)"));
        default:
            return ProcessColumnUnavailableText;
        }
    }

    // processDpiAwarenessText 作用：
    // - 把 DPI 感知级别转成任务管理器同款展示文本；
    // - Unknown 表示尚未采集或查询被拒绝，统一显示占位符。
    QString processDpiAwarenessText(const ks::process::ProcessDpiAwarenessLevel awarenessLevel)
    {
        switch (awarenessLevel)
        {
        case ks::process::ProcessDpiAwarenessLevel::Unaware:
            return processContextText("process.table.cell.dpi_unaware", QStringLiteral("无法识别"));
        case ks::process::ProcessDpiAwarenessLevel::UnawareGdiScaled:
            return processContextText("process.table.cell.dpi_unaware_gdi", QStringLiteral("无法识别(GDI 缩放)"));
        case ks::process::ProcessDpiAwarenessLevel::SystemAware:
            return processContextText("process.table.cell.dpi_system", QStringLiteral("系统"));
        case ks::process::ProcessDpiAwarenessLevel::PerMonitorAware:
            return processContextText("process.table.cell.dpi_per_monitor", QStringLiteral("每监视器"));
        case ks::process::ProcessDpiAwarenessLevel::PerMonitorAwareV2:
            return processContextText("process.table.cell.dpi_per_monitor_v2", QStringLiteral("每监视器(V2)"));
        default:
            return ProcessColumnUnavailableText;
        }
    }

    // processFeatureStateSortValue 作用：
    // - 为上述枚举提供稳定的数值排序键；
    // - Unknown 排在最前（-1），便于用户一眼找出未采集到的行。
    double processFeatureStateSortValue(const ks::process::ProcessFeatureState featureState)
    {
        return (featureState == ks::process::ProcessFeatureState::Unknown)
            ? -1.0
            : static_cast<double>(static_cast<int>(featureState));
    }

    // 常用图标路径常量（全部来自 qrc 的 /Icon 前缀资源）。
    constexpr const char* IconProcessMain = ":/Icon/process_main.svg";
    constexpr const char* IconRefresh = ":/Icon/process_refresh.svg";
    constexpr const char* IconStart = ":/Icon/process_start.svg";
    constexpr const char* IconPause = ":/Icon/process_pause.svg";
    constexpr const char* IconThreadTab = ":/Icon/process_threads.svg";
    constexpr const char* IconWindowPickerTarget = ":/Icon/window_picker_target.svg";

    struct ProcessIntegrityLevelPreset
    {
        DWORD rid;              // rid：S-1-16-* Mandatory Label 的最后一级 RID。
        const char* nameText;   // nameText：菜单与结果提示中的稳定英文名称。
        const char* detailText; // detailText：面向用户的中文说明。
    };

    const ProcessIntegrityLevelPreset ProcessIntegrityLevelPresets[] =
    {
        { SECURITY_MANDATORY_UNTRUSTED_RID, "Untrusted", "不受信任完整性" },
        { SECURITY_MANDATORY_LOW_RID, "Low", "低完整性" },
        { SECURITY_MANDATORY_MEDIUM_RID, "Medium", "中完整性" },
        { SECURITY_MANDATORY_MEDIUM_PLUS_RID, "MediumPlus", "中高完整性" },
        { SECURITY_MANDATORY_HIGH_RID, "High", "高完整性" },
        { SECURITY_MANDATORY_SYSTEM_RID, "System", "系统完整性" },
        { SECURITY_MANDATORY_PROTECTED_PROCESS_RID, "ProtectedProcess", "受保护进程完整性" }
    };

    constexpr QSize SideTabIconSize(22, 22);
    constexpr int ProcessTabMinHeightPx = 22;
    constexpr int ProcessNumericSortRole = Qt::UserRole + 200;
    constexpr int ProcessEfficiencyModeRole = Qt::UserRole + 201;
    constexpr int ProcessEfficiencyModeKnownRole = Qt::UserRole + 202;
    constexpr int ProcessTreeDepthRole = Qt::UserRole + 203;
    constexpr int ProcessRowKindRole = Qt::UserRole + 204;
    constexpr int ProcessExpandableRole = Qt::UserRole + 205;
    constexpr int ProcessExpandedRole = Qt::UserRole + 206;
    constexpr int ActivityMinimumIntervalMilliseconds = 500;
    constexpr int ActivityMaximumIntervalMilliseconds = 60000;
    // CSwitch 会话可以常驻，但 PID/TID×核心矩阵最多每秒结算一次，抑制高频刷新下的后台分配。
    constexpr int CpuCoreSnapshotMinimumIntervalMilliseconds = 1000;
    constexpr std::size_t ActivityMaximumSampleCount = 1800;
    constexpr qsizetype ActivityIconCacheMaximumCount = 8192;

    // formatProcessWin32Error 作用：
    // - 输入：stepText 表示失败步骤，errorCode 为 Win32 错误码；
    // - 处理：拼接稳定英文步骤名与十进制错误码，避免跨语言系统 FormatMessage 文本差异；
    // - 返回：可直接写入批量动作 detailText 的 UTF-8 字符串。
    std::string formatProcessWin32Error(const char* stepText, const DWORD errorCode)
    {
        std::ostringstream stream;
        stream << (stepText == nullptr ? "Win32 call" : stepText)
            << " failed, error=" << errorCode;
        return stream.str();
    }

    // ScopedProcessActionHandle：确保批量动作中的身份保持句柄在所有返回路径关闭。
    class ScopedProcessActionHandle final
    {
    public:
        explicit ScopedProcessActionHandle(HANDLE handleValue) : m_handle(handleValue) {}
        ~ScopedProcessActionHandle()
        {
            if (m_handle != nullptr)
            {
                ::CloseHandle(m_handle);
            }
        }
        ScopedProcessActionHandle(const ScopedProcessActionHandle&) = delete;
        ScopedProcessActionHandle& operator=(const ScopedProcessActionHandle&) = delete;
        bool valid() const { return m_handle != nullptr; }
    private:
        HANDLE m_handle = nullptr;
    };

    // acquireProcessActionIdentityHold：在一个进程句柄上读取创建时间，并将该句柄
    // 交给调用方保持至动作结束。根据 Windows 的 PID 生命周期，该持有期内 PID
    // 不会被复用为不同进程；身份不完整或不匹配时安全跳过动作。
    bool acquireProcessActionIdentityHold(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        HANDLE* const processHandleOut,
        std::string* const detailText)
    {
        if (processHandleOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = "process action identity output is null";
            }
            return false;
        }
        *processHandleOut = nullptr;
        if (pid == 0U || expectedCreationTime100ns == 0U)
        {
            if (detailText != nullptr)
            {
                *detailText = "process identity is unavailable; action skipped";
            }
            return false;
        }

        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (processHandle == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error(
                    "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)",
                    ::GetLastError());
            }
            return false;
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL queryOk = ::GetProcessTimes(
            processHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        const DWORD queryError = queryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        const std::uint64_t actualCreationTime100ns = queryOk != FALSE
            ? (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U) |
                static_cast<std::uint64_t>(creationTime.dwLowDateTime)
            : 0U;
        if (queryOk == FALSE ||
            actualCreationTime100ns == 0U ||
            actualCreationTime100ns != expectedCreationTime100ns)
        {
            ::CloseHandle(processHandle);
            if (detailText != nullptr)
            {
                *detailText = queryOk == FALSE
                    ? formatProcessWin32Error("GetProcessTimes", queryError)
                    : "process identity changed (PID was reused); action skipped";
            }
            return false;
        }

        *processHandleOut = processHandle;
        return true;
    }
    // enableProcessContextPrivilege 作用：
    // - 输入：privilegeName 为当前进程需要临时启用的特权名；
    // - 处理：打开当前进程 Token 并调用 AdjustTokenPrivileges；
    // - 返回：true 表示特权已成功启用；false 表示当前令牌不具备或启用失败。
    bool enableProcessContextPrivilege(const wchar_t* privilegeName)
    {
        if (privilegeName == nullptr)
        {
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            return false;
        }

        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, privilegeName, &privilegeLuid) == FALSE)
        {
            ::CloseHandle(tokenHandle);
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        const BOOL adjustOk = ::AdjustTokenPrivileges(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            sizeof(tokenPrivileges),
            nullptr,
            nullptr);
        const DWORD adjustError = ::GetLastError();
        ::CloseHandle(tokenHandle);
        return adjustOk != FALSE && adjustError == ERROR_SUCCESS;
    }

    // allocateMandatoryIntegritySid 作用：
    // - 输入：integrityRid 为 Mandatory Label RID，例如 Low/Medium/High；
    // - 处理：构造 S-1-16-integrityRid SID，调用方负责 FreeSid；
    // - 返回：成功时 true 并写入 sidOut；失败时 false 并输出 detailText。
    bool allocateMandatoryIntegritySid(
        const DWORD integrityRid,
        PSID* sidOut,
        std::string* detailText)
    {
        if (sidOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = "sidOut is null";
            }
            return false;
        }
        *sidOut = nullptr;

        SID_IDENTIFIER_AUTHORITY mandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
        if (::AllocateAndInitializeSid(
            &mandatoryLabelAuthority,
            1,
            integrityRid,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            sidOut) == FALSE)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("AllocateAndInitializeSid", ::GetLastError());
            }
            return false;
        }
        return true;
    }

    // processIntegrityNameFromRid 作用：
    // - 输入：Mandatory Label RID；
    // - 处理：优先匹配右键菜单预设，否则退化为 RID 十六进制文本；
    // - 返回：用于提示、日志、菜单 tooltip 的显示文本。
    QString processIntegrityNameFromRid(const DWORD integrityRid)
    {
        for (const ProcessIntegrityLevelPreset& preset : ProcessIntegrityLevelPresets)
        {
            if (preset.rid == integrityRid)
            {
                return QString::fromLatin1(preset.nameText);
            }
        }
        return QStringLiteral("RID=0x%1").arg(integrityRid, 0, 16).toUpper();
    }

    // queryProcessIntegrityRid 作用：
    // - 输入：pid 为目标进程 ID；
    // - 处理：打开进程 Token 并读取 TokenIntegrityLevel，解析 S-1-16-* 的最后一级 RID；
    // - 返回：成功时 true 并写入 ridOut；失败时 false 并输出 Win32 诊断文本。
    bool queryProcessIntegrityRid(
        const DWORD pid,
        DWORD* ridOut,
        std::string* detailText)
    {
        if (ridOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = "ridOut is null";
            }
            return false;
        }
        *ridOut = 0;

        (void)enableProcessContextPrivilege(SE_DEBUG_NAME);

        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (processHandle == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)", ::GetLastError());
            }
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            const DWORD openTokenError = ::GetLastError();
            ::CloseHandle(processHandle);
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("OpenProcessToken(TOKEN_QUERY)", openTokenError);
            }
            return false;
        }

        DWORD requiredLength = 0;
        (void)::GetTokenInformation(tokenHandle, TokenIntegrityLevel, nullptr, 0, &requiredLength);
        if (requiredLength == 0)
        {
            const DWORD lengthError = ::GetLastError();
            ::CloseHandle(tokenHandle);
            ::CloseHandle(processHandle);
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("GetTokenInformation(TokenIntegrityLevel length)", lengthError);
            }
            return false;
        }

        std::vector<BYTE> tokenBuffer(requiredLength);
        const BOOL queryOk = ::GetTokenInformation(
            tokenHandle,
            TokenIntegrityLevel,
            tokenBuffer.data(),
            requiredLength,
            &requiredLength);
        const DWORD queryError = ::GetLastError();
        ::CloseHandle(tokenHandle);
        ::CloseHandle(processHandle);
        if (queryOk == FALSE)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("GetTokenInformation(TokenIntegrityLevel)", queryError);
            }
            return false;
        }

        const TOKEN_MANDATORY_LABEL* mandatoryLabel =
            reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(tokenBuffer.data());
        if (mandatoryLabel->Label.Sid == nullptr ||
            ::IsValidSid(mandatoryLabel->Label.Sid) == FALSE ||
            *::GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) == 0)
        {
            if (detailText != nullptr)
            {
                *detailText = "TokenIntegrityLevel returned an invalid SID";
            }
            return false;
        }

        *ridOut = *::GetSidSubAuthority(
            mandatoryLabel->Label.Sid,
            static_cast<DWORD>(*::GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) - 1));
        return true;
    }

    // setProcessIntegrityLevelByPid 作用：
    // - 输入：pid 为目标进程，integrityRid 为目标 Mandatory Label RID；
    // - 处理：打开目标 Token，构造 TOKEN_MANDATORY_LABEL，并调用 SetTokenInformation；
    // - 返回：true 表示 API 接受写入；失败时 false 并输出具体步骤错误。
    bool setProcessIntegrityLevelByPid(
        const DWORD pid,
        const DWORD integrityRid,
        std::string* detailText)
    {
        (void)enableProcessContextPrivilege(SE_DEBUG_NAME);

        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (processHandle == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)", ::GetLastError());
            }
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            const DWORD openTokenError = ::GetLastError();
            ::CloseHandle(processHandle);
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("OpenProcessToken(TOKEN_ADJUST_DEFAULT)", openTokenError);
            }
            return false;
        }

        PSID integritySid = nullptr;
        if (!allocateMandatoryIntegritySid(integrityRid, &integritySid, detailText))
        {
            ::CloseHandle(tokenHandle);
            ::CloseHandle(processHandle);
            return false;
        }

        TOKEN_MANDATORY_LABEL mandatoryLabel{};
        mandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;
        mandatoryLabel.Label.Sid = integritySid;
        const DWORD informationLength =
            static_cast<DWORD>(sizeof(mandatoryLabel) + ::GetLengthSid(integritySid));
        const BOOL setOk = ::SetTokenInformation(
            tokenHandle,
            TokenIntegrityLevel,
            &mandatoryLabel,
            informationLength);
        const DWORD setError = ::GetLastError();
        ::FreeSid(integritySid);
        ::CloseHandle(tokenHandle);
        ::CloseHandle(processHandle);

        if (setOk == FALSE)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("SetTokenInformation(TokenIntegrityLevel)", setError);
            }
            return false;
        }

        if (detailText != nullptr)
        {
            std::ostringstream stream;
            stream << "pid=" << pid
                << ", integrity=" << processIntegrityNameFromRid(integrityRid).toStdString()
                << ", rid=0x" << std::hex << integrityRid;
            *detailText = stream.str();
        }
        return true;
    }

    // clampPercentValue 作用：
    // - 把所有图表输入值统一夹到 0~100；
    // - 折线图只绘制百分比，避免不同单位直接叠加造成误读。
    double clampPercentValue(const double percentValue)
    {
        if (!std::isfinite(percentValue))
        {
            return 0.0;
        }
        return std::clamp(percentValue, 0.0, 100.0);
    }

    // totalPhysicalMemoryMB 作用：
    // - 读取系统物理内存总量；
    // - 用于把进程工作集 MB 转换成百分比。
    double totalPhysicalMemoryMB()
    {
        MEMORYSTATUSEX memoryStatus{};
        memoryStatus.dwLength = sizeof(memoryStatus);
        if (::GlobalMemoryStatusEx(&memoryStatus) == FALSE || memoryStatus.ullTotalPhys == 0ULL)
        {
            return 0.0;
        }
        return static_cast<double>(memoryStatus.ullTotalPhys) / (1024.0 * 1024.0);
    }

    // processActivityMetricText 作用：
    // - 将活动图内部指标枚举映射为 UI 显示名称；
    // - 返回值用于按钮、图例和悬停快照。
    QString processActivityMetricText(const ProcessDock::ProcessActivityMetric metric)
    {
        switch (metric)
        {
        case ProcessDock::ProcessActivityMetric::Cpu:
            return QStringLiteral("CPU");
        case ProcessDock::ProcessActivityMetric::Memory:
            return processContextText("process.activity.metric.memory", QStringLiteral("内存"));
        case ProcessDock::ProcessActivityMetric::Disk:
            return processContextText("process.activity.metric.disk", QStringLiteral("磁盘"));
        case ProcessDock::ProcessActivityMetric::Network:
            return processContextText("process.activity.metric.network", QStringLiteral("网络"));
        case ProcessDock::ProcessActivityMetric::Gpu:
            return QStringLiteral("GPU");
        default:
            return processContextText("process.activity.metric.unknown", QStringLiteral("未知"));
        }
    }

    // processActivityMetricColor 作用：
    // - 固定每个指标的主题色，避免用户切换按钮后颜色漂移；
    // - alpha 由调用方根据柱形/图例场景再做调整。
    QColor processActivityMetricColor(const ProcessDock::ProcessActivityMetric metric)
    {
        switch (metric)
        {
        case ProcessDock::ProcessActivityMetric::Cpu:
            return KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Cpu);
        case ProcessDock::ProcessActivityMetric::Memory:
            return KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Memory);
        case ProcessDock::ProcessActivityMetric::Disk:
            return KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Disk);
        case ProcessDock::ProcessActivityMetric::Network:
            return KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Network);
        case ProcessDock::ProcessActivityMetric::Gpu:
            return KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Gpu);
        default:
            return KswordTheme::TextSecondaryColor();
        }
    }

    // processActivityMetricUnit 作用：
    // - 返回指标单位文本；
    // - 悬停快照和图表标题复用同一套单位。
    QString processActivityMetricUnit(const ProcessDock::ProcessActivityMetric metric)
    {
        switch (metric)
        {
        case ProcessDock::ProcessActivityMetric::Cpu:
        case ProcessDock::ProcessActivityMetric::Memory:
        case ProcessDock::ProcessActivityMetric::Disk:
        case ProcessDock::ProcessActivityMetric::Network:
        case ProcessDock::ProcessActivityMetric::Gpu:
            return QStringLiteral("%");
        default:
            return QString();
        }
    }

    // formatActivityElapsedText 作用：
    // - 将记录相对毫秒转换为紧凑时间轴标签；
    // - 小于 1 秒时保留 0.1s 精度，便于用户手动设置亚秒级打点时定位。
    QString formatActivityElapsedText(const std::uint64_t elapsedMs)
    {
        if (elapsedMs < 1000U)
        {
            return QStringLiteral("%1s").arg(static_cast<double>(elapsedMs) / 1000.0, 0, 'f', 1);
        }

        const std::uint64_t totalSeconds = elapsedMs / 1000U;
        const std::uint64_t hours = totalSeconds / 3600U;
        const std::uint64_t minutes = (totalSeconds / 60U) % 60U;
        const std::uint64_t seconds = totalSeconds % 60U;
        if (hours > 0U)
        {
            return QStringLiteral("%1:%2:%3")
                .arg(hours)
                .arg(minutes, 2, 10, QChar('0'))
                .arg(seconds, 2, 10, QChar('0'));
        }
        return QStringLiteral("%1:%2")
            .arg(minutes, 2, 10, QChar('0'))
            .arg(seconds, 2, 10, QChar('0'));
    }

    // activityMousePosition 作用：
    // - 兼容 Qt5/Qt6 的鼠标坐标 API；
    // - 返回值是控件本地坐标。
    QPoint activityMousePosition(const QMouseEvent* eventPointer)
    {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        return eventPointer != nullptr ? eventPointer->position().toPoint() : QPoint();
#else
        return eventPointer != nullptr ? eventPointer->pos() : QPoint();
#endif
    }

    // themeColorFromText 作用：
    // - KswordTheme 的部分颜色可能来自 palette(...) 表达式；
    // - 绘图只能使用 QColor，所以无法解析时返回调用方给出的兜底色。
    QColor themeColorFromText(const QString& colorText, const QColor& fallbackColor)
    {
        const QColor parsedColor(colorText);
        return parsedColor.isValid() ? parsedColor : fallbackColor;
    }

    class ProcessTableSortProxy final : public QSortFilterProxyModel
    {
    public:
        // 构造函数作用：
        // - 初始化进程列表专用排序代理；
        // - 默认动态排序关闭，避免每次 setRows 时逐行插入触发排序抖动。
        // 参数 parent：Qt 父对象。
        // 返回：无返回值。
        explicit ProcessTableSortProxy(QObject* parent = nullptr)
            : QSortFilterProxyModel(parent)
        {
            setDynamicSortFilter(false);
        }

        // setPreserveSourceOrder 作用：
        // - 树状显示时让代理按源模型行号排序，保留 buildDisplayOrder 生成的父子顺序；
        // - 列表/历史快照模式关闭该开关，继续使用数值排序键。
        // 参数 preserveSourceOrder：true=保留源顺序；false=按列排序。
        // 返回：无返回值。
        void setPreserveSourceOrder(const bool preserveSourceOrder)
        {
            m_preserveSourceOrder = preserveSourceOrder;
        }

        // setHeaderTexts 作用：
        // - 接收 ProcessDock 按当前可见行计算出的动态表头；
        // - 仅刷新横向表头，避免为“CPU 总和”等文本变化重置整张表；
        // - 返回：无返回值。
        void setHeaderTexts(QStringList headerTexts)
        {
            m_headerTexts = std::move(headerTexts);
            if (!m_headerTexts.isEmpty())
            {
                emit headerDataChanged(Qt::Horizontal, 0, m_headerTexts.size() - 1);
            }
        }

        // headerData 作用：
        // - 横向 DisplayRole 返回动态表头文本；
        // - 其它 role/orientation 保持 QSortFilterProxyModel 默认行为。
        QVariant headerData(const int section, const Qt::Orientation orientation, const int role) const override
        {
            if (orientation == Qt::Horizontal &&
                role == Qt::DisplayRole &&
                section >= 0 &&
                section < m_headerTexts.size())
            {
                return translatedProcessHeader(section, m_headerTexts.at(section));
            }
            return QSortFilterProxyModel::headerData(section, orientation, role);
        }

    protected:
        // lessThan 作用：
        // - 优先读取 ProcessNumericSortRole 的原始数值排序键；
        // - 数值相等或列没有数值键时，回退到展示文本的本地化比较；
        // - 返回 true 表示 left 应排在 right 前。
        bool lessThan(const QModelIndex& leftIndex, const QModelIndex& rightIndex) const override
        {
            if (!leftIndex.isValid() || !rightIndex.isValid())
            {
                return QSortFilterProxyModel::lessThan(leftIndex, rightIndex);
            }

            if (m_preserveSourceOrder)
            {
                return leftIndex.row() < rightIndex.row();
            }

            bool leftOk = false;
            bool rightOk = false;
            const double leftValue = sourceModel()->data(leftIndex, ProcessNumericSortRole).toDouble(&leftOk);
            const double rightValue = sourceModel()->data(rightIndex, ProcessNumericSortRole).toDouble(&rightOk);
            if (leftOk && rightOk && leftValue != rightValue)
            {
                return leftValue < rightValue;
            }
            if (leftOk && rightOk)
            {
                return sourceModel()
                    ->data(leftIndex, Qt::DisplayRole)
                    .toString()
                    .localeAwareCompare(sourceModel()->data(rightIndex, Qt::DisplayRole).toString()) < 0;
            }
            return QSortFilterProxyModel::lessThan(leftIndex, rightIndex);
        }

    private:
        QStringList m_headerTexts; // m_headerTexts：进程表当前横向表头文本快照。
        bool m_preserveSourceOrder = false; // m_preserveSourceOrder：树状模式下按源模型顺序返回。
    };

    // ProcessWindowPickerDragButton：
    // - 作用：复用窗口页“准星拖拽拾取”的输入模型；
    // - 按住按钮拖到任意窗口后松开，向宿主回调全局屏幕坐标；
    // - 只负责输入捕获，不直接读取 HWND/PID，避免 UI 控件承担业务逻辑。
    class ProcessWindowPickerDragButton final : public QPushButton
    {
    public:
        using ReleaseCallback = std::function<void(const QPoint&)>;

        // 构造函数：
        // - parent：Qt 父控件；
        // - 处理：启用鼠标追踪，允许拖拽过程中持续计算距离；
        // - 返回：无返回值。
        explicit ProcessWindowPickerDragButton(QWidget* parent = nullptr)
            : QPushButton(parent)
        {
            setMouseTracking(true);
        }

        // setReleaseCallback：
        // - callback：鼠标释放时接收全局坐标的函数；
        // - 处理：保存到成员变量，供 mouseReleaseEvent 调用；
        // - 返回：无返回值。
        void setReleaseCallback(ReleaseCallback callback)
        {
            m_releaseCallback = std::move(callback);
        }

    protected:
        // mousePressEvent：
        // - 输入：Qt 鼠标按下事件；
        // - 处理：记录左键起点并抓取鼠标，光标切换成准星；
        // - 返回：无返回值。
        void mousePressEvent(QMouseEvent* eventPointer) override
        {
            if (eventPointer != nullptr && eventPointer->button() == Qt::LeftButton)
            {
                m_dragTracking = true;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                m_pressGlobalPos = eventPointer->globalPosition().toPoint();
#else
                m_pressGlobalPos = eventPointer->globalPos();
#endif
                m_hasReachedDragThreshold = false;
                grabMouse(QCursor(Qt::CrossCursor));
            }
            QPushButton::mousePressEvent(eventPointer);
        }

        // mouseMoveEvent：
        // - 输入：Qt 鼠标移动事件；
        // - 处理：超过系统拖拽阈值后才允许释放触发，避免普通点击误拾取；
        // - 返回：无返回值。
        void mouseMoveEvent(QMouseEvent* eventPointer) override
        {
            if (m_dragTracking && eventPointer != nullptr)
            {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                const QPoint currentGlobalPos = eventPointer->globalPosition().toPoint();
#else
                const QPoint currentGlobalPos = eventPointer->globalPos();
#endif
                const int moveDistance = (currentGlobalPos - m_pressGlobalPos).manhattanLength();
                if (moveDistance >= QApplication::startDragDistance())
                {
                    m_hasReachedDragThreshold = true;
                }
            }
            QPushButton::mouseMoveEvent(eventPointer);
        }

        // mouseReleaseEvent：
        // - 输入：Qt 鼠标释放事件；
        // - 处理：释放鼠标抓取，并在有效拖拽时回调释放坐标；
        // - 返回：无返回值。
        void mouseReleaseEvent(QMouseEvent* eventPointer) override
        {
            const bool shouldDispatch =
                m_dragTracking &&
                m_hasReachedDragThreshold &&
                eventPointer != nullptr &&
                eventPointer->button() == Qt::LeftButton;

            if (m_dragTracking)
            {
                releaseMouse();
                m_dragTracking = false;
            }
            m_hasReachedDragThreshold = false;

            QPoint releaseGlobalPos;
            if (eventPointer != nullptr)
            {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
                releaseGlobalPos = eventPointer->globalPosition().toPoint();
#else
                releaseGlobalPos = eventPointer->globalPos();
#endif
            }

            QPushButton::mouseReleaseEvent(eventPointer);

            if (shouldDispatch && m_releaseCallback)
            {
                m_releaseCallback(releaseGlobalPos);
            }
        }

    private:
        bool m_dragTracking = false;             // m_dragTracking：当前是否处于准星拖拽链路。
        bool m_hasReachedDragThreshold = false;  // m_hasReachedDragThreshold：是否达到系统拖拽阈值。
        QPoint m_pressGlobalPos;                 // m_pressGlobalPos：左键按下时的全局坐标。
        ReleaseCallback m_releaseCallback;       // m_releaseCallback：释放后通知宿主处理 PID 过滤。
    };

}

class ProcessActivityChartWidget final : public QWidget
{
public:
    // 构造函数：
    // - ownerDock：提供样本、选择和指标开关；
    // - parent：Qt 父控件；
    // - 无返回值，初始化鼠标跟踪以支持悬停快照。
    explicit ProcessActivityChartWidget(ProcessDock* ownerDock, QWidget* parent = nullptr)
        : QWidget(parent)
        , m_ownerDock(ownerDock)
    {
        setMinimumHeight(120);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        setMouseTracking(true);
        setFocusPolicy(Qt::NoFocus);
        // 折线图不再自行铺底色，父级 Dock 背景图需要从图表空白区透出。
        setAutoFillBackground(false);
        setAttribute(Qt::WA_StyledBackground, false);
        setAttribute(Qt::WA_OpaquePaintEvent, false);
        m_seriesAnimation = new QVariantAnimation(this);
        m_seriesAnimation->setDuration(260);
        m_seriesAnimation->setEasingCurve(QEasingCurve::OutCubic);
        m_seriesAnimation->setStartValue(0.0);
        m_seriesAnimation->setEndValue(1.0);
        connect(m_seriesAnimation, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
            m_animationProgress = value.toDouble();
            update();
        });
    }

    // setFocusedSampleIndex：
    // - sampleIndex：时间轴当前定位的样本下标，-1 表示无焦点；
    // - 函数只更新绘制光标，不修改宿主滑块。
    void setFocusedSampleIndex(const int sampleIndex)
    {
        if (m_focusedSampleIndex == sampleIndex)
        {
            return;
        }
        m_focusedSampleIndex = sampleIndex;
        update();
    }

    void animateLatestSample(const bool historyWindowShifted)
    {
        if (m_ownerDock == nullptr || m_ownerDock->m_activitySamples.size() < 2U)
        {
            m_historyWindowShifted = false;
            m_animationProgress = 1.0;
            update();
            return;
        }
        m_historyWindowShifted = historyWindowShifted;
        m_animationProgress = 0.0;
        m_seriesAnimation->stop();
        m_seriesAnimation->start();
    }

protected:
    // event：
    // - 输入：Qt 通用事件，重点处理 ToolTip 事件；
    // - 处理：在提示即将显示时重新按当前鼠标位置计算最近样本；
    // - 返回：true 表示 tooltip 已由控件接管，false 表示交给 QWidget 默认处理。
    bool event(QEvent* eventPointer) override
    {
        if (eventPointer != nullptr && eventPointer->type() == QEvent::ToolTip)
        {
            QHelpEvent* helpEvent = static_cast<QHelpEvent*>(eventPointer);
            showSnapshotToolTipAtPosition(helpEvent->pos(), helpEvent->globalPos());
            eventPointer->accept();
            return true;
        }
        return QWidget::event(eventPointer);
    }

    // paintEvent：
    // - 以时间为横轴绘制多指标百分比折线图；
    // - 无返回值，所有数据都从宿主的有界样本缓存读取。
    void paintEvent(QPaintEvent* eventPointer) override
    {
        (void)eventPointer;

        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        // 背景保持透明：只绘制网格、边框和曲线，不用 Surface 色块覆盖 Dock 背景图。

        const QRectF plotRect = chartRect();
        const QColor borderColor = themeColorFromText(
            KswordTheme::BorderHex(),
            KswordTheme::BorderColor());
        const QColor textColor = themeColorFromText(
            KswordTheme::TextSecondaryHex(),
            KswordTheme::TextSecondaryColor());

        painter.setPen(QPen(borderColor, 1.0));
        painter.setBrush(Qt::NoBrush);
        painter.drawRect(plotRect);

        if (m_ownerDock == nullptr || m_ownerDock->m_activitySamples.empty())
        {
            painter.setPen(textColor);
            painter.drawText(
                plotRect,
                Qt::AlignCenter,
                processContextText("process.activity.empty", QStringLiteral("未开始刷新进程列表活动")));
            return;
        }

        std::vector<ProcessDock::ProcessActivityMetric> enabledMetrics = enabledMetricList();
        if (enabledMetrics.empty())
        {
            painter.setPen(textColor);
            painter.drawText(
                plotRect,
                Qt::AlignCenter,
                processContextText(
                    "process.activity.no_metric",
                    QStringLiteral("未选择任何指标，请勾选 CPU / 内存 / 磁盘 / 网络 / GPU")));
            return;
        }

        std::vector<std::string> selectionKeys = m_ownerDock->currentProcessActivitySelectionKeys();
        const std::unordered_set<std::string> selectionKeySet(
            selectionKeys.cbegin(),
            selectionKeys.cend());
        const MetricScale metricScale = calculateMetricScale(enabledMetrics, selectionKeySet);

        drawGrid(painter, plotRect, borderColor, textColor);
        drawLines(painter, plotRect, enabledMetrics, selectionKeySet, metricScale);
        drawLegend(painter, enabledMetrics, textColor);
        drawFocusLine(painter, plotRect);
    }

    // mouseMoveEvent：
    // - 将鼠标 X 坐标映射为最近样本；
    // - 通知宿主更新时间轴滑块与快照标签。
    void mouseMoveEvent(QMouseEvent* eventPointer) override
    {
        if (eventPointer == nullptr || m_ownerDock == nullptr || m_ownerDock->m_activitySamples.empty())
        {
            QWidget::mouseMoveEvent(eventPointer);
            return;
        }

        const int sampleIndex = sampleIndexAtX(activityMousePosition(eventPointer).x());
        if (sampleIndex >= 0)
        {
            const bool oldPinnedToLatest = m_ownerDock->m_activityTimelinePinnedToLatest;
            m_ownerDock->previewProcessActivitySnapshotForIndex(sampleIndex);
            m_ownerDock->m_activityTimelinePinnedToLatest = oldPinnedToLatest;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
            const QPoint globalPosition = eventPointer->globalPosition().toPoint();
#else
            const QPoint globalPosition = eventPointer->globalPos();
#endif
            showSnapshotToolTipAtPosition(activityMousePosition(eventPointer), globalPosition);
        }
        eventPointer->accept();
    }

    // mousePressEvent：
    // - 单击图表时将时间轴固定到对应历史样本；
    // - 若点击最右侧样本，则恢复“吸附最新”模式。
    void mousePressEvent(QMouseEvent* eventPointer) override
    {
        if (eventPointer == nullptr ||
            eventPointer->button() != Qt::LeftButton ||
            m_ownerDock == nullptr ||
            m_ownerDock->m_activitySamples.empty())
        {
            QWidget::mousePressEvent(eventPointer);
            return;
        }

        const int sampleIndex = sampleIndexAtX(activityMousePosition(eventPointer).x());
        if (sampleIndex >= 0)
        {
            // 图表本身现在就是唯一时间轴：
            // - 左键点击提交历史时刻；
            // - 提交会同步更新下方进程表到对应快照。
            m_ownerDock->commitProcessActivityTimelineIndex(sampleIndex);
            eventPointer->accept();
            return;
        }
        QWidget::mousePressEvent(eventPointer);
    }

    // leaveEvent：
    // - 鼠标离开图表后保留当前时间轴位置；
    // - 仅隐藏 tooltip，避免用户读下方快照时被清空。
    void leaveEvent(QEvent* eventPointer) override
    {
        QToolTip::hideText();
        QWidget::leaveEvent(eventPointer);
    }

private:
    // showSnapshotToolTipAtPosition：
    // - localPosition：图表本地坐标，用于映射最近样本；
    // - globalPosition：屏幕坐标，用于放置 tooltip；
    // - 返回：无；没有样本时主动隐藏，避免显示控件静态 tooltip。
    void showSnapshotToolTipAtPosition(const QPoint& localPosition, const QPoint& globalPosition)
    {
        if (m_ownerDock == nullptr || m_ownerDock->m_activitySamples.empty())
        {
            QToolTip::hideText();
            return;
        }

        const int sampleIndex = sampleIndexAtX(localPosition.x());
        if (sampleIndex < 0)
        {
            QToolTip::hideText();
            return;
        }

        const QRect toolTipRect(localPosition - QPoint(6, 6), QSize(12, 12));
        QToolTip::showText(
            globalPosition,
            m_ownerDock->buildProcessActivitySnapshotText(sampleIndex),
            this,
            toolTipRect);
    }

    // chartRect：
    // - 计算图表实际绘制区域；
    // - 给左侧刻度和底部时间标签预留固定空间。
    QRectF chartRect() const
    {
        return QRectF(rect()).adjusted(42.0, 8.0, -10.0, -24.0);
    }

    // enabledMetricList：
    // - 从宿主按钮状态读取当前可见指标；
    // - 返回顺序即折线绘制顺序。
    std::vector<ProcessDock::ProcessActivityMetric> enabledMetricList() const
    {
        std::vector<ProcessDock::ProcessActivityMetric> metricList;
        if (m_ownerDock == nullptr)
        {
            return metricList;
        }
        const ProcessDock::ProcessActivityMetric allMetrics[] = {
            ProcessDock::ProcessActivityMetric::Cpu,
            ProcessDock::ProcessActivityMetric::Memory,
            ProcessDock::ProcessActivityMetric::Disk,
            ProcessDock::ProcessActivityMetric::Network,
            ProcessDock::ProcessActivityMetric::Gpu
        };
        for (const ProcessDock::ProcessActivityMetric metric : allMetrics)
        {
            if (m_ownerDock->isProcessActivityMetricEnabled(metric))
            {
                metricList.push_back(metric);
            }
        }
        return metricList;
    }

    // MetricScale 作用：
    // - 保存折线图百分比归一化分母；
    // - 磁盘/网络使用当前历史窗口最大值作为 100%。
    struct MetricScale
    {
        double memoryDenominatorMB = 1.0;     // memoryDenominatorMB：物理内存总量或历史最大内存。
        double diskDenominatorMBps = 1.0;     // diskDenominatorMBps：历史最大磁盘吞吐。
        double networkDenominatorKBps = 1.0;  // networkDenominatorKBps：历史最大网络吞吐。
    };

    // sampleRawMetricValue：
    // - 读取某个采样点的原始单项指标；
    // - selectionKeySet 为空时返回总体聚合，否则通过哈希集合返回选中进程之和。
    double sampleRawMetricValue(
        const ProcessDock::ProcessActivitySample& sample,
        const ProcessDock::ProcessActivityMetric metric,
        const std::unordered_set<std::string>& selectionKeySet) const
    {
        if (selectionKeySet.empty())
        {
            switch (metric)
            {
            case ProcessDock::ProcessActivityMetric::Cpu:
                return sample.totalCpuPercent;
            case ProcessDock::ProcessActivityMetric::Memory:
                return sample.totalMemoryMB;
            case ProcessDock::ProcessActivityMetric::Disk:
                return sample.totalDiskMBps;
            case ProcessDock::ProcessActivityMetric::Network:
                return sample.totalNetKBps;
            case ProcessDock::ProcessActivityMetric::Gpu:
                return sample.totalGpuPercent;
            default:
                return 0.0;
            }
        }

        double value = 0.0;
        for (const ProcessDock::ProcessActivityProcessPoint& processPoint : sample.processes)
        {
            if (selectionKeySet.find(processPoint.identityKey) == selectionKeySet.end())
            {
                continue;
            }
            switch (metric)
            {
            case ProcessDock::ProcessActivityMetric::Cpu:
                value += processPoint.cpuPercent;
                break;
            case ProcessDock::ProcessActivityMetric::Memory:
                value += processPoint.workingSetMB;
                break;
            case ProcessDock::ProcessActivityMetric::Disk:
                value += processPoint.diskMBps;
                break;
            case ProcessDock::ProcessActivityMetric::Network:
                value += processPoint.netKBps;
                break;
            case ProcessDock::ProcessActivityMetric::Gpu:
                value += processPoint.gpuPercent;
                break;
            default:
                break;
            }
        }
        return value;
    }

    // calculateMetricScale：
    // - 每次绘制都重新扫描历史最大值；
    // - 当磁盘/网络出现新峰值时，本轮立刻重算百分比并重绘。
    MetricScale calculateMetricScale(
        const std::vector<ProcessDock::ProcessActivityMetric>& metricList,
        const std::unordered_set<std::string>& selectionKeySet) const
    {
        MetricScale scale{};
        if (m_ownerDock == nullptr)
        {
            return scale;
        }

        scale.memoryDenominatorMB = std::max(1.0, m_ownerDock->m_activityTotalPhysicalMemoryMB);
        double maxMemoryMB = 0.0;
        double maxDiskMBps = 0.0;
        double maxNetworkKBps = 0.0;
        for (const ProcessDock::ProcessActivitySample& sample : m_ownerDock->m_activitySamples)
        {
            maxMemoryMB = std::max(maxMemoryMB, sampleRawMetricValue(sample, ProcessDock::ProcessActivityMetric::Memory, selectionKeySet));
            maxDiskMBps = std::max(maxDiskMBps, sampleRawMetricValue(sample, ProcessDock::ProcessActivityMetric::Disk, selectionKeySet));
            maxNetworkKBps = std::max(maxNetworkKBps, sampleRawMetricValue(sample, ProcessDock::ProcessActivityMetric::Network, selectionKeySet));
        }
        if (scale.memoryDenominatorMB <= 1.0 && maxMemoryMB > 0.0)
        {
            scale.memoryDenominatorMB = maxMemoryMB;
        }
        scale.diskDenominatorMBps = std::max(1.0, maxDiskMBps);
        scale.networkDenominatorKBps = std::max(1.0, maxNetworkKBps);
        (void)metricList;
        return scale;
    }

    // samplePercentMetricValue：
    // - 把原始指标统一转换为百分比；
    // - 磁盘/网络按历史最大值归一化，CPU/GPU 天然是百分比。
    double samplePercentMetricValue(
        const ProcessDock::ProcessActivitySample& sample,
        const ProcessDock::ProcessActivityMetric metric,
        const std::unordered_set<std::string>& selectionKeySet,
        const MetricScale& scale) const
    {
        const double rawValue = sampleRawMetricValue(sample, metric, selectionKeySet);
        switch (metric)
        {
        case ProcessDock::ProcessActivityMetric::Cpu:
        case ProcessDock::ProcessActivityMetric::Gpu:
            return clampPercentValue(rawValue);
        case ProcessDock::ProcessActivityMetric::Memory:
            return clampPercentValue((rawValue / std::max(1.0, scale.memoryDenominatorMB)) * 100.0);
        case ProcessDock::ProcessActivityMetric::Disk:
            return clampPercentValue((rawValue / std::max(1.0, scale.diskDenominatorMBps)) * 100.0);
        case ProcessDock::ProcessActivityMetric::Network:
            return clampPercentValue((rawValue / std::max(1.0, scale.networkDenominatorKBps)) * 100.0);
        default:
            return 0.0;
        }
    }

    // sampleIndexAtX：
    // - 将鼠标横坐标映射为最近样本下标；
    // - 越界坐标会夹到首尾样本。
    int sampleIndexAtX(const int xValue) const
    {
        if (m_ownerDock == nullptr || m_ownerDock->m_activitySamples.empty())
        {
            return -1;
        }
        const QRectF plotRect = chartRect();
        if (plotRect.width() <= 1.0)
        {
            return -1;
        }
        const double ratio = std::clamp(
            (static_cast<double>(xValue) - plotRect.left()) / plotRect.width(),
            0.0,
            1.0);
        const std::size_t sampleCount = m_ownerDock->m_activitySamples.size();
        const int sampleIndex = static_cast<int>(std::llround(ratio * static_cast<double>(sampleCount - 1U)));
        return std::clamp(sampleIndex, 0, static_cast<int>(sampleCount) - 1);
    }

    // sampleIndexToX：
    // - 将样本下标映射为折线点 X；
    // - 绘制焦点线和时间标签复用该函数。
    double sampleIndexToX(const int sampleIndex, const QRectF& plotRect) const
    {
        if (m_ownerDock == nullptr || m_ownerDock->m_activitySamples.size() <= 1U)
        {
            return plotRect.left() + plotRect.width() * 0.5;
        }
        const double ratio = static_cast<double>(sampleIndex)
            / static_cast<double>(m_ownerDock->m_activitySamples.size() - 1U);
        return plotRect.left() + ratio * plotRect.width();
    }

    // animatedSampleIndexToX：
    // - 新点加入时把旧采样从上一横坐标平滑移动到目标横坐标；
    // - 历史满载时整窗左移，未满时旧点平滑压缩以给最右侧新点留出空间。
    double animatedSampleIndexToX(const int sampleIndex, const QRectF& plotRect) const
    {
        if (m_ownerDock == nullptr || m_ownerDock->m_activitySamples.size() <= 1U)
        {
            return plotRect.left() + plotRect.width() * 0.5;
        }
        const int sampleCount = static_cast<int>(m_ownerDock->m_activitySamples.size());
        const double targetRatio =
            static_cast<double>(sampleIndex) / static_cast<double>(sampleCount - 1);
        double startRatio = targetRatio;
        if (m_animationProgress < 1.0)
        {
            if (m_historyWindowShifted)
            {
                startRatio = sampleIndex + 1 < sampleCount
                    ? static_cast<double>(sampleIndex + 1) / static_cast<double>(sampleCount - 1)
                    : 1.0;
            }
            else if (sampleCount > 2)
            {
                startRatio = sampleIndex + 1 < sampleCount
                    ? static_cast<double>(sampleIndex) / static_cast<double>(sampleCount - 2)
                    : 1.0;
            }
        }
        const double ratio = startRatio + (targetRatio - startRatio) * m_animationProgress;
        return plotRect.left() + ratio * plotRect.width();
    }

    // drawGrid：
    // - 绘制弱网格、最大值标签和首尾时间；
    // - 不创建额外轴控件，降低 UI 成本。
    void drawGrid(
        QPainter& painter,
        const QRectF& plotRect,
        const QColor& borderColor,
        const QColor& textColor) const
    {
        painter.setPen(QPen(borderColor, 0.5));
        for (int i = 1; i <= 3; ++i)
        {
            const double yValue = plotRect.bottom() - plotRect.height() * static_cast<double>(i) / 4.0;
            painter.drawLine(QPointF(plotRect.left(), yValue), QPointF(plotRect.right(), yValue));
        }

        painter.setPen(textColor);
        painter.drawText(QRectF(2.0, plotRect.top() - 2.0, 38.0, 18.0), Qt::AlignRight | Qt::AlignVCenter,
            QStringLiteral("100%"));
        painter.drawText(QRectF(2.0, plotRect.center().y() - 9.0, 38.0, 18.0), Qt::AlignRight | Qt::AlignVCenter,
            QStringLiteral("50%"));
        painter.drawText(QRectF(2.0, plotRect.bottom() - 16.0, 38.0, 18.0), Qt::AlignRight | Qt::AlignVCenter,
            QStringLiteral("0%"));

        if (m_ownerDock != nullptr && !m_ownerDock->m_activitySamples.empty())
        {
            const ProcessDock::ProcessActivitySample& firstSample = m_ownerDock->m_activitySamples.front();
            const ProcessDock::ProcessActivitySample& lastSample = m_ownerDock->m_activitySamples.back();
            painter.drawText(QRectF(plotRect.left(), plotRect.bottom() + 3.0, 80.0, 18.0),
                Qt::AlignLeft | Qt::AlignVCenter,
                formatActivityElapsedText(firstSample.elapsedMs));
            painter.drawText(QRectF(plotRect.right() - 90.0, plotRect.bottom() + 3.0, 90.0, 18.0),
                Qt::AlignRight | Qt::AlignVCenter,
                formatActivityElapsedText(lastSample.elapsedMs));
        }
    }

    // drawLines：
    // - 绘制按时间排列的多指标折线；
    // - 所有指标已转为 0~100%，不同单位可以共用同一 Y 轴。
    void drawLines(
        QPainter& painter,
        const QRectF& plotRect,
        const std::vector<ProcessDock::ProcessActivityMetric>& metricList,
        const std::unordered_set<std::string>& selectionKeySet,
        const MetricScale& metricScale) const
    {
        if (m_ownerDock == nullptr || m_ownerDock->m_activitySamples.empty())
        {
            return;
        }

        const std::size_t sampleCount = m_ownerDock->m_activitySamples.size();
        const std::size_t maximumRenderedPointCount = static_cast<std::size_t>(
            std::max(2.0, std::floor(plotRect.width())));
        const std::size_t sampleStride = sampleCount > maximumRenderedPointCount
            ? std::max<std::size_t>(
                1U,
                ((sampleCount - 1U) + (maximumRenderedPointCount - 2U)) /
                    (maximumRenderedPointCount - 1U))
            : 1U;
        for (const ProcessDock::ProcessActivityMetric metric : metricList)
        {
            QPainterPath metricPath;
            bool hasPoint = false;
            std::vector<QPointF> pointList;
            pointList.reserve(std::min(sampleCount, maximumRenderedPointCount + 1U));
            const auto appendSamplePoint = [&](const std::size_t sampleIndex)
            {
                const ProcessDock::ProcessActivitySample& sample = m_ownerDock->m_activitySamples[sampleIndex];
                double percentValue = samplePercentMetricValue(sample, metric, selectionKeySet, metricScale);
                if (sampleIndex + 1U == sampleCount && sampleIndex > 0U && m_animationProgress < 1.0)
                {
                    const ProcessDock::ProcessActivitySample& previousSample = m_ownerDock->m_activitySamples[sampleIndex - 1U];
                    const double previousPercentValue = samplePercentMetricValue(previousSample, metric, selectionKeySet, metricScale);
                    percentValue = previousPercentValue + (percentValue - previousPercentValue) * m_animationProgress;
                }
                const double xValue = animatedSampleIndexToX(static_cast<int>(sampleIndex), plotRect);
                const double yValue = plotRect.bottom() - (percentValue / 100.0) * plotRect.height();
                const QPointF point(xValue, yValue);
                pointList.push_back(point);
                if (!hasPoint)
                {
                    metricPath.moveTo(point);
                    hasPoint = true;
                }
                else
                {
                    metricPath.lineTo(point);
                }
            };
            std::size_t lastRenderedSampleIndex = 0U;
            for (std::size_t sampleIndex = 0; sampleIndex < sampleCount; sampleIndex += sampleStride)
            {
                appendSamplePoint(sampleIndex);
                lastRenderedSampleIndex = sampleIndex;
            }
            if (lastRenderedSampleIndex != sampleCount - 1U)
            {
                appendSamplePoint(sampleCount - 1U);
            }

            QColor lineColor = processActivityMetricColor(metric);
            lineColor.setAlpha(230);
            // 折线只允许描边，不允许沿用上一条指标采样点留下的 brush。
            // Qt 的 drawPath 会同时 stroke 和 fill；如果 brush 未清空，开放折线路径会被隐式闭合填充。
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(lineColor, 2.0));
            painter.drawPath(metricPath);

            QColor pointColor = lineColor;
            pointColor.setAlpha(245);
            painter.setBrush(pointColor);
            painter.setPen(Qt::NoPen);
            const int pointStride = static_cast<int>(std::max<std::size_t>(1U, pointList.size() / 80U));
            for (std::size_t pointIndex = 0; pointIndex < pointList.size(); pointIndex += static_cast<std::size_t>(pointStride))
            {
                painter.drawEllipse(pointList[pointIndex], 2.2, 2.2);
            }
            // 采样点绘制会设置实心 brush，循环下一条折线前必须恢复为空画刷。
            painter.setBrush(Qt::NoBrush);
        }
    }

    // drawLegend：
    // - 在图表上沿绘制当前启用指标图例；
    // - 用户可据此确认按钮筛选后的折线颜色。
    void drawLegend(
        QPainter& painter,
        const std::vector<ProcessDock::ProcessActivityMetric>& metricList,
        const QColor& textColor) const
    {
        int xOffset = 48;
        const int yOffset = 4;
        painter.setPen(textColor);
        for (const ProcessDock::ProcessActivityMetric metric : metricList)
        {
            QColor color = processActivityMetricColor(metric);
            color.setAlpha(220);
            painter.fillRect(QRect(xOffset, yOffset + 4, 9, 9), color);
            painter.drawText(QRect(xOffset + 13, yOffset, 54, 18),
                Qt::AlignLeft | Qt::AlignVCenter,
                processActivityMetricText(metric));
            xOffset += 62;
        }
    }

    // drawFocusLine：
    // - 绘制时间轴当前定位样本的竖线；
    // - 该线由滑块或图表悬停共同驱动。
    void drawFocusLine(QPainter& painter, const QRectF& plotRect) const
    {
        if (m_ownerDock == nullptr || m_ownerDock->m_activitySamples.empty())
        {
            return;
        }
        const int safeIndex = std::clamp(
            m_focusedSampleIndex,
            0,
            static_cast<int>(m_ownerDock->m_activitySamples.size()) - 1);
        const double xValue = sampleIndexToX(safeIndex, plotRect);
        QColor lineColor = KswordTheme::PrimaryBlueColor;
        lineColor.setAlpha(230);
        painter.setPen(QPen(lineColor, 1.4));
        painter.drawLine(QPointF(xValue, plotRect.top()), QPointF(xValue, plotRect.bottom()));
    }

private:
    ProcessDock* m_ownerDock = nullptr; // m_ownerDock：宿主 ProcessDock，不拥有。
    int m_focusedSampleIndex = -1;      // m_focusedSampleIndex：当前时间轴定位样本。
    QVariantAnimation* m_seriesAnimation = nullptr; // m_seriesAnimation：最新采样点插值动画。
    double m_animationProgress = 1.0; // m_animationProgress：最新采样点动画进度。
    bool m_historyWindowShifted = false; // m_historyWindowShifted：本轮是否淘汰了最旧采样。
};

class ProcessActivityTimelineSlider final : public QSlider
{
public:
    // 构造函数：
    // - ownerDock：用于在悬停时读取历史快照；
    // - parent：Qt 父控件；
    // - 无返回值，启用鼠标追踪实现“移到那里展示快照”。
    explicit ProcessActivityTimelineSlider(ProcessDock* ownerDock, QWidget* parent = nullptr)
        : QSlider(Qt::Horizontal, parent)
        , m_ownerDock(ownerDock)
    {
        setMouseTracking(true);
        setFocusPolicy(Qt::StrongFocus);
    }

protected:
    // mouseMoveEvent：
    // - 鼠标悬停到时间轴任意位置时映射到对应样本；
    // - 不要求按下拖动也能展示快照。
    void mouseMoveEvent(QMouseEvent* eventPointer) override
    {
        if (eventPointer != nullptr && m_ownerDock != nullptr && !m_ownerDock->m_activitySamples.empty())
        {
            const int sampleIndex = valueAtPosition(activityMousePosition(eventPointer).x());
            // 悬停只更新快照提示，不改变滑块值，也不重绘下方进程表。
            const bool oldPinnedToLatest = m_ownerDock->m_activityTimelinePinnedToLatest;
            m_ownerDock->previewProcessActivitySnapshotForIndex(sampleIndex);
            m_ownerDock->m_activityTimelinePinnedToLatest = oldPinnedToLatest;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
            const QPoint globalPosition = eventPointer->globalPosition().toPoint();
#else
            const QPoint globalPosition = eventPointer->globalPos();
#endif
            QToolTip::showText(globalPosition, m_ownerDock->buildProcessActivitySnapshotText(sampleIndex), this);
        }
        QSlider::mouseMoveEvent(eventPointer);
    }

    // mousePressEvent：
    // - 单击时间轴即跳转到对应样本；
    // - 拖到最右侧后宿主会重新进入吸附最新模式。
    void mousePressEvent(QMouseEvent* eventPointer) override
    {
        if (eventPointer != nullptr && eventPointer->button() == Qt::LeftButton && maximum() >= minimum())
        {
            const int sampleIndex = valueAtPosition(activityMousePosition(eventPointer).x());
            setValue(sampleIndex);
            if (m_ownerDock != nullptr)
            {
                m_ownerDock->commitProcessActivityTimelineIndex(sampleIndex);
            }
            eventPointer->accept();
            return;
        }
        QSlider::mousePressEvent(eventPointer);
    }

    // leaveEvent：
    // - 鼠标离开后隐藏 tooltip；
    // - 当前选中的历史样本仍保留在下方快照标签中。
    void leaveEvent(QEvent* eventPointer) override
    {
        QToolTip::hideText();
        QSlider::leaveEvent(eventPointer);
    }

private:
    // valueAtPosition：
    // - 将本地 X 坐标映射到滑块范围；
    // - 返回值自动夹在 minimum/maximum 内。
    int valueAtPosition(const int xValue) const
    {
        const int rangeValue = maximum() - minimum();
        if (rangeValue <= 0 || width() <= 1)
        {
            return minimum();
        }
        const QStyleOptionSlider option = sliderOption();
        const QRect grooveRect = style()->subControlRect(QStyle::CC_Slider, &option, QStyle::SC_SliderGroove, this);
        const QRect handleRect = style()->subControlRect(QStyle::CC_Slider, &option, QStyle::SC_SliderHandle, this);
        const int sliderMin = grooveRect.left();
        const int sliderMax = grooveRect.right() - handleRect.width() + 1;
        if (sliderMax <= sliderMin)
        {
            const double fallbackRatio = std::clamp(
                static_cast<double>(xValue) / static_cast<double>(std::max(1, width() - 1)),
                0.0,
                1.0);
            return minimum() + static_cast<int>(std::llround(fallbackRatio * static_cast<double>(rangeValue)));
        }
        const double denominator = static_cast<double>(std::max(1, sliderMax - sliderMin));
        const double ratio = std::clamp(
            (static_cast<double>(xValue) - static_cast<double>(sliderMin)) / denominator,
            0.0,
            1.0);
        return minimum() + static_cast<int>(std::llround(ratio * static_cast<double>(rangeValue)));
    }

    // sliderOption：
    // - 构造当前 QSlider 样式选项；
    // - 用于准确获取 groove/handle 几何范围。
    QStyleOptionSlider sliderOption() const
    {
        QStyleOptionSlider option;
        initStyleOption(&option);
        return option;
    }

private:
    ProcessDock* m_ownerDock = nullptr; // m_ownerDock：宿主 ProcessDock，不拥有。
};

namespace
{
    // ProcessRowHighlightDelegate 作用：
    // - 接管进程表每个单元格的默认绘制；
    // - 保留新增/退出/内核差异行的原始底色；
    // - 把鼠标悬停和选中态从“整行填充”改成“整行描边”；
    // - 在“进程名”列右侧继续绘制效率模式绿叶，不新增表格列。
    class ProcessRowHighlightDelegate final : public QStyledItemDelegate
    {
    public:
        // 构造函数：
        // - tableView：被代理绘制的进程表视图；
        // - 处理：启用 viewport 鼠标追踪，记录当前悬停行；
        // - 返回：无返回值。
        explicit ProcessRowHighlightDelegate(
            QTableView* tableView,
            const int cpuCoreColumn)
            : QStyledItemDelegate(tableView)
            , m_tableView(tableView)
            , m_cpuCoreColumn(cpuCoreColumn)
        {
            if (m_tableView != nullptr && m_tableView->viewport() != nullptr)
            {
                m_tableView->setMouseTracking(true);
                m_tableView->viewport()->setMouseTracking(true);
                m_tableView->viewport()->installEventFilter(this);
            }
        }

        // eventFilter：
        // - 输入：进程表 viewport 的鼠标移动/离开事件；
        // - 处理：把鼠标所在单元格归一到行首索引，并触发表格重绘；
        // - 返回：false 表示不截断 Qt 原有表格交互。
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (m_tableView != nullptr &&
                watched == m_tableView->viewport() &&
                event != nullptr)
            {
                if (event->type() == QEvent::MouseMove)
                {
                    const QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
                    updateHoveredRowIndex(m_tableView->indexAt(activityMousePosition(mouseEvent)));
                }
                else if (event->type() == QEvent::Leave)
                {
                    updateHoveredRowIndex(QModelIndex());
                }
            }
            return QStyledItemDelegate::eventFilter(watched, event);
        }

        // paint：
        // - 输入：Qt 提供的绘图对象、单元格样式和模型索引；
        // - 处理：清除默认选中/悬停填充后绘制内容，再叠加行级边框；
        // - 返回：无返回值。
        void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            QStyleOptionViewItem itemOption(option);
            const bool rowSelected = (option.state & QStyle::State_Selected) != 0;
            const bool rowHovered = isHoveredRow(index);

            // 默认样式会用选中/悬停色整行填充，导致“退出进程灰色行”被覆盖；
            // 这里只取消交互态填充，保留 item background、前景色和图标绘制。
            itemOption.state &= ~QStyle::State_Selected;
            itemOption.state &= ~QStyle::State_MouseOver;
            itemOption.state &= ~QStyle::State_HasFocus;

            const bool customNameColumn =
                painter != nullptr &&
                index.isValid() &&
                index.column() == 0 &&
                index.data(ProcessTreeDepthRole).isValid();
            const bool drawEfficiencyLeaf =
                index.column() == 0 &&
                index.data(ProcessEfficiencyModeRole).toBool();
            const bool customCpuCapacityCell =
                painter != nullptr &&
                index.column() == m_cpuCoreColumn &&
                ks::ui::HasProcessCpuCapacityCellData(index);
            if (customNameColumn)
            {
                drawProcessNameCell(painter, itemOption, index, drawEfficiencyLeaf);
            }
            else if (customCpuCapacityCell)
            {
                // CPU 容量槽需要模型背景、前景色和字体；先初始化样式选项，再交给专用绘制器。
                QStyleOptionViewItem cpuCellOption(itemOption);
                initStyleOption(&cpuCellOption, index);
                cpuCellOption.state = itemOption.state;
                ks::ui::PaintProcessCpuCapacityCell(
                    painter,
                    cpuCellOption,
                    index);
            }
            else
            {
                if (drawEfficiencyLeaf)
                {
                    itemOption.rect.adjust(0, 0, -22, 0);
                }
                QStyledItemDelegate::paint(painter, itemOption, index);
            }

            if (painter == nullptr)
            {
                return;
            }

            if (drawEfficiencyLeaf)
            {
                painter->save();
                painter->setRenderHint(QPainter::Antialiasing, true);
                const int iconSize = std::min(16, std::max(10, option.rect.height() - 6));
                const QRect leafRect(
                    option.rect.right() - iconSize - 5,
                    option.rect.center().y() - iconSize / 2,
                    iconSize,
                    iconSize);
                const QColor leafColor = KswordTheme::SuccessColor();
                QPainterPath leafPath;
                leafPath.moveTo(leafRect.left() + leafRect.width() * 0.18, leafRect.center().y());
                leafPath.cubicTo(
                    leafRect.left() + leafRect.width() * 0.32,
                    leafRect.top() + leafRect.height() * 0.08,
                    leafRect.right() - leafRect.width() * 0.10,
                    leafRect.top() + leafRect.height() * 0.06,
                    leafRect.right() - leafRect.width() * 0.08,
                    leafRect.center().y());
                leafPath.cubicTo(
                    leafRect.right() - leafRect.width() * 0.10,
                    leafRect.bottom() - leafRect.height() * 0.08,
                    leafRect.left() + leafRect.width() * 0.30,
                    leafRect.bottom() - leafRect.height() * 0.05,
                    leafRect.left() + leafRect.width() * 0.18,
                    leafRect.center().y());
                painter->fillPath(leafPath, leafColor);
                painter->setPen(QPen(KswordTheme::WithAlpha(KswordTheme::OnAccentColor(), 210), 1.2));
                painter->drawLine(
                    QPointF(leafRect.left() + leafRect.width() * 0.28, leafRect.bottom() - leafRect.height() * 0.25),
                    QPointF(leafRect.right() - leafRect.width() * 0.20, leafRect.top() + leafRect.height() * 0.22));
                painter->restore();
            }

            if (rowSelected || rowHovered)
            {
                drawRowInteractionBorder(painter, option, index, rowSelected);
            }
        }

        // helpEvent：
        // - 输入：Qt tooltip 事件、表格视图、当前单元格几何和模型索引；
        // - 处理：鼠标命中逐核心小方框时显示该真实逻辑 CPU 的组号、编号和区间占用；
        // - 返回：true 表示已显示精确核心提示，否则交回默认 ToolTipRole 路径。
        bool helpEvent(
            QHelpEvent* const event,
            QAbstractItemView* const view,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) override
        {
            if (event != nullptr &&
                view != nullptr &&
                index.column() == m_cpuCoreColumn)
            {
                QStyleOptionViewItem cpuCellOption(option);
                initStyleOption(&cpuCellOption, index);
                const QString coreToolTip = ks::ui::ProcessCpuCapacityToolTipText(
                    cpuCellOption,
                    index,
                    event->pos());
                if (!coreToolTip.isEmpty())
                {
                    QToolTip::showText(
                        event->globalPos(),
                        coreToolTip,
                        view->viewport());
                    return true;
                }
            }
            return QStyledItemDelegate::helpEvent(event, view, option, index);
        }

    private:
        // drawProcessNameCell：
        // - 输入：Name 列模型索引、绘图状态，以及是否绘制效率模式叶子；
        // - 处理：先让 Qt 绘制背景，再按“虚线层级 -> 图标 -> 文本”手动绘制内容；
        // - 返回：无返回值，普通树状视图和友好视图共用这一表示层。
        void drawProcessNameCell(
            QPainter* painter,
            QStyleOptionViewItem itemOption,
            const QModelIndex& index,
            const bool drawEfficiencyLeaf) const
        {
            if (painter == nullptr || !index.isValid())
            {
                return;
            }

            QStyleOptionViewItem backgroundOption(itemOption);
            initStyleOption(&backgroundOption, index);
            backgroundOption.state = itemOption.state;
            backgroundOption.text.clear();
            backgroundOption.icon = QIcon();
            const QWidget* viewWidget = itemOption.widget;
            QStyle* viewStyle = viewWidget != nullptr ? viewWidget->style() : QApplication::style();
            if (viewStyle != nullptr)
            {
                viewStyle->drawControl(QStyle::CE_ItemViewItem, &backgroundOption, painter, viewWidget);
            }

            bool depthOk = false;
            const int depth = index.data(ProcessTreeDepthRole).toInt(&depthOk);
            const int safeDepth = depthOk ? std::max(0, depth) : 0;
            const int rowKind = index.data(ProcessRowKindRole).toInt();
            const bool expandable = index.data(ProcessExpandableRole).toBool();
            const bool expanded = index.data(ProcessExpandedRole).toBool();

            QRect contentRect = itemOption.rect.adjusted(6, 0, -6, 0);
            if (drawEfficiencyLeaf)
            {
                contentRect.adjust(0, 0, -22, 0);
            }

            const int levelWidth = 18;
            const int iconSize = std::min(18, std::max(12, itemOption.rect.height() - 6));
            const int iconTextGap = 6;
            const int treeAreaWidth = safeDepth * levelWidth;
            const QColor lineColor = KswordTheme::WithAlpha(KswordTheme::BorderStrongColor(), 165);

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, true);
            QPen treePen(lineColor, 1.0, Qt::DotLine, Qt::RoundCap);
            painter->setPen(treePen);

            const int centerY = contentRect.center().y();
            for (int level = 0; level < safeDepth; ++level)
            {
                const int x = contentRect.left() + level * levelWidth + levelWidth / 2;
                painter->drawLine(
                    QPoint(x, itemOption.rect.top() + 4),
                    QPoint(x, itemOption.rect.bottom() - 4));
                if (level + 1 == safeDepth)
                {
                    painter->drawLine(
                        QPoint(x, centerY),
                        QPoint(contentRect.left() + treeAreaWidth - 3, centerY));
                }
            }

            int cursorX = contentRect.left() + treeAreaWidth;
            if (expandable)
            {
                const QRect markerRect(
                    cursorX,
                    centerY - 7,
                    14,
                    14);
                painter->setPen(QPen(KswordTheme::PrimaryBlueColor, 1.2));
                painter->setBrush(Qt::NoBrush);
                const QPointF p1 = expanded
                    ? QPointF(markerRect.left() + 3.5, markerRect.top() + 5.0)
                    : QPointF(markerRect.left() + 5.0, markerRect.top() + 3.5);
                const QPointF p2 = expanded
                    ? QPointF(markerRect.center().x(), markerRect.bottom() - 4.0)
                    : QPointF(markerRect.right() - 4.0, markerRect.center().y());
                const QPointF p3 = expanded
                    ? QPointF(markerRect.right() - 3.5, markerRect.top() + 5.0)
                    : QPointF(markerRect.left() + 5.0, markerRect.bottom() - 3.5);
                QPainterPath markerPath;
                markerPath.moveTo(p1);
                markerPath.lineTo(p2);
                markerPath.lineTo(p3);
                painter->drawPath(markerPath);
                cursorX += markerRect.width() + 2;
            }

            const QIcon iconValue = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
            if (!iconValue.isNull())
            {
                const QRect iconRect(
                    cursorX,
                    centerY - iconSize / 2,
                    iconSize,
                    iconSize);
                iconValue.paint(painter, iconRect, Qt::AlignCenter, QIcon::Normal);
                cursorX += iconSize + iconTextGap;
            }
            else if (rowKind != 1)
            {
                cursorX += iconTextGap;
            }

            // Process names and cell values are data, not UI labels. Never
            // translate them through a global source-string table.
            const QString textValue = index.data(Qt::DisplayRole).toString();
            QRect textRect(
                cursorX,
                contentRect.top(),
                std::max(0, contentRect.right() - cursorX + 1),
                contentRect.height());
            QFont textFont = itemOption.font;
            if (index.data(Qt::FontRole).isValid())
            {
                textFont = qvariant_cast<QFont>(index.data(Qt::FontRole));
            }
            painter->setFont(textFont);
            const QVariant foregroundData = index.data(Qt::ForegroundRole);
            if (foregroundData.canConvert<QBrush>())
            {
                painter->setPen(qvariant_cast<QBrush>(foregroundData).color());
            }
            else
            {
                painter->setPen(itemOption.palette.color(QPalette::Text));
            }
            painter->drawText(
                textRect,
                Qt::AlignLeft | Qt::AlignVCenter,
                itemOption.fontMetrics.elidedText(textValue, Qt::ElideRight, textRect.width()));
            painter->restore();
        }

        // sameModelRow：
        // - 输入：两个持久模型索引；
        // - 处理：只比较 model/parent/row，不比较列；
        // - 返回：true 表示二者指向同一逻辑行。
        static bool sameModelRow(
            const QPersistentModelIndex& leftIndex,
            const QPersistentModelIndex& rightIndex)
        {
            if (!leftIndex.isValid() || !rightIndex.isValid())
            {
                return !leftIndex.isValid() && !rightIndex.isValid();
            }
            return leftIndex.model() == rightIndex.model() &&
                leftIndex.parent() == rightIndex.parent() &&
                leftIndex.row() == rightIndex.row();
        }

        // updateHoveredRowIndex：
        // - 输入：鼠标命中的任意列索引，空索引表示鼠标离开；
        // - 处理：归一到第 0 列后保存，确保整行所有列都能绘制边框；
        // - 返回：无返回值。
        void updateHoveredRowIndex(const QModelIndex& sourceIndex)
        {
            QPersistentModelIndex nextRowIndex;
            if (sourceIndex.isValid())
            {
                nextRowIndex = QPersistentModelIndex(sourceIndex.sibling(sourceIndex.row(), 0));
            }

            if (sameModelRow(m_hoveredRowIndex, nextRowIndex))
            {
                return;
            }
            m_hoveredRowIndex = nextRowIndex;

            // 行边框横跨多个列，简单重绘整个 viewport 可避免列宽/列顺序变化时残留边线。
            if (m_tableView != nullptr && m_tableView->viewport() != nullptr)
            {
                m_tableView->viewport()->update();
            }
        }

        // isHoveredRow：
        // - 输入：当前正在绘制的模型索引；
        // - 处理：与记录的悬停行按 model/parent/row 比较；
        // - 返回：true 表示当前单元格属于悬停行。
        bool isHoveredRow(const QModelIndex& index) const
        {
            if (!index.isValid() || !m_hoveredRowIndex.isValid())
            {
                return false;
            }
            return index.model() == m_hoveredRowIndex.model() &&
                index.parent() == m_hoveredRowIndex.parent() &&
                index.row() == m_hoveredRowIndex.row();
        }

        // drawRowInteractionBorder：
        // - 输入：当前单元格绘图上下文、样式选项、索引和是否选中；
        // - 处理：每个可见单元格绘制上下边线，首/末可见列补左右边线；
        // - 返回：无返回值。
        void drawRowInteractionBorder(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index,
            const bool rowSelected) const
        {
            if (painter == nullptr || m_tableView == nullptr || !index.isValid())
            {
                return;
            }

            QHeaderView* headerView = m_tableView->horizontalHeader();
            if (headerView == nullptr)
            {
                return;
            }

            int firstVisibleVisualIndex = std::numeric_limits<int>::max();
            int lastVisibleVisualIndex = std::numeric_limits<int>::min();
            const int columnCount = index.model() != nullptr
                ? index.model()->columnCount(index.parent())
                : 0;
            for (int columnIndex = 0; columnIndex < columnCount; ++columnIndex)
            {
                if (m_tableView->isColumnHidden(columnIndex))
                {
                    continue;
                }
                const int visualIndex = headerView->visualIndex(columnIndex);
                if (visualIndex < 0)
                {
                    continue;
                }
                firstVisibleVisualIndex = std::min(firstVisibleVisualIndex, visualIndex);
                lastVisibleVisualIndex = std::max(lastVisibleVisualIndex, visualIndex);
            }

            const int currentVisualIndex = headerView->visualIndex(index.column());
            if (currentVisualIndex < 0 ||
                firstVisibleVisualIndex == std::numeric_limits<int>::max() ||
                lastVisibleVisualIndex == std::numeric_limits<int>::min())
            {
                return;
            }

            QColor borderColor = KswordTheme::PrimaryBlueColor;
            borderColor.setAlpha(rowSelected ? 245 : 165);
            const QRect borderRect = option.rect.adjusted(0, 1, -1, -2);
            if (!borderRect.isValid())
            {
                return;
            }

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, false);
            painter->setBrush(Qt::NoBrush);
            painter->setPen(QPen(borderColor, rowSelected ? 3.0 : 1.4));
            painter->drawLine(borderRect.topLeft(), borderRect.topRight());
            painter->drawLine(borderRect.bottomLeft(), borderRect.bottomRight());
            if (currentVisualIndex == firstVisibleVisualIndex)
            {
                painter->drawLine(borderRect.topLeft(), borderRect.bottomLeft());
            }
            if (currentVisualIndex == lastVisibleVisualIndex)
            {
                painter->drawLine(borderRect.topRight(), borderRect.bottomRight());
            }
            painter->restore();
        }

        QPointer<QTableView> m_tableView;         // m_tableView：被代理的进程表，不拥有。
        int m_cpuCoreColumn = -1;                 // m_cpuCoreColumn：唯一允许解析逐核心共享快照的逻辑列。
        QPersistentModelIndex m_hoveredRowIndex; // m_hoveredRowIndex：当前鼠标悬停行的第 0 列索引。
    };

    // 当前 steady_clock 时间转 100ns（与 ks::process 差值计算规则保持一致）。
    std::uint64_t steadyNow100ns()
    {
        const auto nowDuration = std::chrono::steady_clock::now().time_since_epoch();
        const auto nowNanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(nowDuration).count();
        return static_cast<std::uint64_t>(nowNanoseconds / 100);
    }

    // 从策略下拉索引映射到 ks::process 策略枚举。
    ks::process::ProcessEnumStrategy toStrategy(const int strategyIndex)
    {
        switch (strategyIndex)
        {
        case 0:
            return ks::process::ProcessEnumStrategy::SnapshotProcess32;
        case 1:
            return ks::process::ProcessEnumStrategy::NtQuerySystemInfo;
        default:
            return ks::process::ProcessEnumStrategy::NtQuerySystemInfo;
        }
    }

    // 策略枚举转可读文本：用于刷新状态标签与详细日志输出。
    const char* strategyToText(const ks::process::ProcessEnumStrategy strategy)
    {
        switch (strategy)
        {
        case ks::process::ProcessEnumStrategy::SnapshotProcess32:
            return "Toolhelp Snapshot + Process32First/Next";
        case ks::process::ProcessEnumStrategy::NtQuerySystemInfo:
            return "NtQuerySystemInformation";
        case ks::process::ProcessEnumStrategy::Auto:
            return "Auto (NtQuery 优先, 失败回退 Toolhelp)";
        default:
            return "Unknown";
        }
    }

    // processDockIoMessageText：
    // - 输入：ArkDriverClient 返回给 ProcessDock 的原始 message 文本；
    // - 处理：将 DeviceIoControl/unsupported/DynData/buffer 等底层诊断转成用户可读提示；
    // - 返回：用于进程页状态串的中文说明，避免把 IOCTL 调试日志直接拼进 UI。
    QString processDockIoMessageText(const QString& rawMessageText)
    {
        const QString trimmedText = rawMessageText.trimmed();
        if (trimmedText.isEmpty())
        {
            return QStringLiteral("驱动未返回额外说明。");
        }

        const QString lowerText = trimmedText.toLower();
        if (lowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return QStringLiteral("驱动 IOCTL 调用失败或当前驱动版本不匹配。");
        }
        if (lowerText.contains(QStringLiteral("unsupported")) ||
            lowerText.contains(QStringLiteral("not supported")) ||
            lowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return QStringLiteral("当前驱动暂不支持该进程 DynData 查询入口。");
        }
        if (lowerText.contains(QStringLiteral("dyndata")) ||
            lowerText.contains(QStringLiteral("capability")))
        {
            return QStringLiteral("DynData 动态偏移能力未满足，请先刷新或应用 PDB profile。");
        }
        if (lowerText.contains(QStringLiteral("buffer")) &&
            (lowerText.contains(QStringLiteral("small")) || lowerText.contains(QStringLiteral("trunc"))))
        {
            return QStringLiteral("驱动返回缓冲区不足，结果可能被截断。");
        }
        return trimmedText;
    }

    // processDockIoMessageStdString：
    // - 输入：ArkDriverClient 返回的 std::string 原始消息；
    // - 处理：复用 ProcessDock 的友好化文本转换，并转回 UTF-8 std::string；
    // - 返回：可继续交给旧 detailTextOut 管线的可读说明。
    std::string processDockIoMessageStdString(const std::string& rawMessageText)
    {
        return processDockIoMessageText(QString::fromStdString(rawMessageText)).toStdString();
    }

    // isProcessR0ExtensionVisible 作用：
    // - 判断一行是否真正携带 R0 扩展字段；
    // - 全部 Unavailable 时 UI 会自动隐藏内核专属列，避免误导用户以为 R3 字段异常。
    bool isProcessR0ExtensionVisible(const ks::process::ProcessRecord& processRecord)
    {
        if (processRecord.r0Status != KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE)
        {
            return true;
        }

        return (processRecord.r0FieldFlags &
            (KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT |
                KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE |
                KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_VALUE_PRESENT |
                KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE |
                KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_VALUE_PRESENT)) != 0U;
    }

    // terminateProcessByR0Driver 作用：
    // - 通过 ArkDriverClient 发送“结束进程”IOCTL；
    // - Dock 不再直接打开 KswordARK 设备或调用 DeviceIoControl。
    bool terminateProcessByR0Driver(
        const std::uint32_t targetPid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (targetPid == 0U || targetPid <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult result = driverClient.terminateProcess(
            targetPid,
            static_cast<long>(0xC0000005u),
            expectedCreationTime100ns);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(result.message);
        }
        return result.ok;
    }

    // suspendProcessByR0Driver 作用：
    // - 通过 ArkDriverClient 发送“挂起进程”IOCTL；
    // - 保持旧 detailText 输出格式，降低 UI 行为变化。
    bool suspendProcessByR0Driver(const std::uint32_t targetPid, std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (targetPid == 0U || targetPid <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult result = driverClient.suspendProcess(targetPid);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(result.message);
        }
        return result.ok;
    }

    // setPplProtectionLevelByR0Driver 作用：
    // - 通过 ArkDriverClient 发送“设置 PPL 保护层级”IOCTL；
    // - protectionLevel 与 ProcessProtectionInformation 的单字节层级编码保持一致。
    bool setPplProtectionLevelByR0Driver(
        const std::uint32_t targetPid,
        const std::uint8_t protectionLevel,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (targetPid == 0U || targetPid <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult result = driverClient.setProcessProtection(targetPid, protectionLevel);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(result.message);
        }
        return result.ok;
    }

    bool shouldFallbackProcessIntegrityToR3(
        const ksword::ark::IoResult& io,
        const bool unsupported)
    {
        // 输入：ArkDriverClient 的通信结果和 unsupported 标记。
        // 处理：只把“驱动未装载/旧驱动无此 IOCTL”归类为 R3 fallback 条件。
        // 返回：true 表示可以尝试 R3；R0 已通信但语义失败时返回 false，避免掩盖内核 API 失败原因。
        if (io.ok)
        {
            return false;
        }
        if (unsupported)
        {
            return true;
        }

        return io.win32Error == ERROR_FILE_NOT_FOUND ||
            io.win32Error == ERROR_PATH_NOT_FOUND ||
            io.win32Error == ERROR_SERVICE_DOES_NOT_EXIST ||
            io.win32Error == ERROR_INVALID_FUNCTION ||
            io.win32Error == ERROR_NOT_SUPPORTED ||
            io.win32Error == ERROR_INVALID_PARAMETER;
    }

    bool setProcessIntegrityLevelByR0ThenR3(
        const DWORD pid,
        const DWORD integrityRid,
        std::string* const detailText)
    {
        // 输入：目标 PID 和 Mandatory Label RID。
        // 处理：先调用 R0 IOCTL；只有驱动不可用/旧驱动缺入口时才回退 R3 SetTokenInformation。
        // 返回：true 表示 R0 或 fallback R3 成功；false 时 detailText 保留 R0 语义失败或 R3 失败诊断。
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::ProcessIntegrityResult r0Result =
            driverClient.setProcessIntegrity(static_cast<std::uint32_t>(pid), integrityRid);
        const bool r0Applied = r0Result.io.ok &&
            r0Result.status == KSWORD_ARK_PROCESS_INTEGRITY_STATUS_APPLIED &&
            r0Result.lastStatus >= 0;
        if (r0Applied)
        {
            if (detailText != nullptr)
            {
                std::ostringstream stream;
                stream << "R0 ok: "
                    << processDockIoMessageStdString(r0Result.io.message);
                *detailText = stream.str();
            }
            return true;
        }

        if (shouldFallbackProcessIntegrityToR3(r0Result.io, r0Result.unsupported))
        {
            std::string r3DetailText;
            const bool r3Ok = setProcessIntegrityLevelByPid(pid, integrityRid, &r3DetailText);
            if (detailText != nullptr)
            {
                std::ostringstream stream;
                stream << "R0 unavailable/unsupported: "
                    << processDockIoMessageStdString(r0Result.io.message)
                    << " | R3 "
                    << (r3Ok ? "ok: " : "failed: ")
                    << (r3DetailText.empty() ? "no detail" : r3DetailText);
                *detailText = stream.str();
            }
            return r3Ok;
        }

        if (detailText != nullptr)
        {
            std::ostringstream stream;
            stream << "R0 failed: "
                << processDockIoMessageStdString(r0Result.io.message)
                << ", status=" << r0Result.status
                << ", nt=0x" << std::hex << static_cast<unsigned long>(r0Result.lastStatus)
                << ", win32=" << std::dec << r0Result.io.win32Error;
            *detailText = stream.str();
        }
        return false;
    }

    // activeProcessLinksDynDataDiagnostic 前置声明：
    // - 输入：已构造好的 DriverClient；
    // - 处理：在文件后半段定义的只读 DynData 诊断 helper；
    // - 返回：追加到隐藏动作失败详情中的诊断字符串。
    std::string activeProcessLinksDynDataDiagnostic(const ksword::ark::DriverClient& driverClient);

    bool setProcessVisibilityByR0Driver(
        const std::uint32_t targetPid,
        const unsigned long action,
        const unsigned long flags,
        std::string* const detailTextOut)
    {
        // 作用：调用 ArkDriverClient 执行 R0 进程可见性动作。
        // 处理：隐藏动作通过 flags 明确选择只改 PID、只断链或旧版双操作。
        // 返回：true 表示驱动接受并更新；false 表示 IOCTL 或 R0 状态失败。
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE &&
            (targetPid == 0U || targetPid <= 4U))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::ProcessVisibilityResult result =
            driverClient.setProcessVisibility(targetPid, action, flags);
        const bool actionSucceeded = result.io.ok &&
            result.lastStatus >= 0 &&
            (result.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN ||
                result.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_VISIBLE ||
                result.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_CLEARED);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(result.io.message);
            if (!actionSucceeded)
            {
                if (!detailTextOut->empty())
                {
                    *detailTextOut += " | ";
                }
                *detailTextOut += activeProcessLinksDynDataDiagnostic(driverClient);
            }
        }
        return actionSucceeded;
    }

    bool setProcessSpecialFlagsByR0Driver(
        const std::uint32_t targetPid,
        const unsigned long action,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const detailTextOut)
    {
        // 作用：封装 BreakOnTermination/APC 插入控制 IOCTL。
        // 返回：true 表示 R0 完成动作；false 表示 IOCTL 或 R0 状态失败。
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        if (targetPid == 0U || targetPid <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::ProcessSpecialFlagsResult result =
            driverClient.setProcessSpecialFlags(
                targetPid,
                action,
                0UL,
                expectedCreationTime100ns);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(result.io.message);
        }
        return result.io.ok &&
            result.lastStatus >= 0 &&
            result.status == KSWORD_ARK_PROCESS_SPECIAL_STATUS_APPLIED;
    }

    bool dkomProcessByR0Driver(
        const std::uint32_t targetPid,
        const unsigned long action,
        std::string* const detailTextOut)
    {
        // 作用：封装 PspCidTable DKOM 删除 IOCTL。
        // 返回：true 表示 R0 至少删除一个 CID entry。
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        if (targetPid == 0U || targetPid <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::ProcessDkomResult result =
            driverClient.dkomProcess(targetPid, action);
        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(result.io.message);
        }
        return result.io.ok &&
            result.lastStatus >= 0 &&
            result.status == KSWORD_ARK_PROCESS_DKOM_STATUS_REMOVED &&
            result.removedEntries > 0U;
    }

    // KernelProcessSnapshotEntry 作用：
    // - 承载 R0 枚举返回的一条进程快照；
    // - 仅保留 UI 对比所需字段（PID/父 PID/标志/短进程名）。
    struct KernelProcessSnapshotEntry
    {
        std::uint32_t processId = 0;
        std::uint32_t parentProcessId = 0;
        std::uint32_t flags = 0;
        std::uint32_t sessionId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t r0Status = KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE;
        std::uint32_t sessionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint8_t protection = 0;
        std::uint8_t signatureLevel = 0;
        std::uint8_t sectionSignatureLevel = 0;
        std::uint32_t protectionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t signatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t sectionSignatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t objectTableSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t sectionObjectSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t imagePathSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t protectionOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t signatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t sectionSignatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t objectTableOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t sectionObjectOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint64_t objectTableAddress = 0;
        std::uint64_t sectionObjectAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint64_t creationTime100ns = 0;
        std::string imageName;
        std::string imagePath;
    };

    // 内核专属记录使用固定创建时间种子，避免与 R3 常规 identity 发生冲突。
    constexpr std::uint64_t KernelOnlyCreationTimeSeed = 0xFFFFFFFF00000000ULL;

    // r0ActionExpectedCreationTime：真实创建时间交给驱动校验，旧驱动的合成占位值不参与对象身份判断。
    std::uint64_t r0ActionExpectedCreationTime(const ks::process::ProcessRecord& processRecord)
    {
        return processRecord.creationTime100ns >= KernelOnlyCreationTimeSeed
            ? 0ULL
            : processRecord.creationTime100ns;
    }

    QString processFieldSourceText(const std::uint32_t sourceValue)
    {
        // sourceValue 用途：共享协议中的字段来源枚举。
        // 返回值：面向 UI 的稳定可读文本。
        switch (sourceValue)
        {
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_PUBLIC_API:
            return QStringLiteral("Public API");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_SYSTEM_INFORMER_DYNDATA:
            return QStringLiteral("System Informer DynData");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("Runtime pattern");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // dynDataFieldSourceText 作用：
    // - 输入：QUERY_DYN_FIELDS 返回的 KSW_DYN_FIELD_SOURCE_* 来源值；
    // - 处理：转换为动作失败详情中可读的来源文本；
    // - 返回：PDB profile、System Informer、runtime pattern 或 Unavailable。
    QString dynDataFieldSourceText(const std::uint32_t sourceValue)
    {
        switch (sourceValue)
        {
        case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
            return QStringLiteral("System Informer");
        case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("Runtime pattern");
        case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
            return QStringLiteral("Ksword extra table");
        case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // dynDataOffsetPresent 作用：
    // - 输入：DynData 字段 flags 与 offset；
    // - 处理：同时检查 PRESENT bit 和不可用哨兵；
    // - 返回：true 表示该字段当前对 R0 可用。
    bool dynDataOffsetPresent(const std::uint32_t flags, const std::uint32_t offset)
    {
        return (flags & KSW_DYN_FIELD_FLAG_PRESENT) != 0U &&
            offset != 0xFFFFFFFFU &&
            offset != 0x0000FFFFU;
    }

    // dynDataOffsetText 作用：
    // - 输入：DynData 字段 offset；
    // - 处理：不可用哨兵显示 <不可用>，可用值同时展示 hex/decimal；
    // - 返回：动作详情中的偏移文本。
    QString dynDataOffsetText(const std::uint32_t offset)
    {
        if (offset == 0xFFFFFFFFU || offset == 0x0000FFFFU)
        {
            return QStringLiteral("<不可用>");
        }
        return QStringLiteral("0x%1 (%2)")
            .arg(offset, 8, 16, QChar('0'))
            .arg(offset)
            .toUpper();
    }

    // dynDataStatusFlagText 作用：
    // - 输入：QUERY_DYN_STATUS 返回的 KSW_DYN_STATUS_FLAG_* 位图；
    // - 处理：只列出对偏移应用链路有解释价值的 active/profile 标志；
    // - 返回：动作失败详情中可读的状态标志文本。
    QString dynDataStatusFlagText(const std::uint32_t statusFlags)
    {
        QStringList parts;
        if ((statusFlags & KSW_DYN_STATUS_FLAG_INITIALIZED) != 0U)
        {
            parts << QStringLiteral("Initialized");
        }
        if ((statusFlags & KSW_DYN_STATUS_FLAG_NTOS_ACTIVE) != 0U)
        {
            parts << QStringLiteral("NtosActive");
        }
        if ((statusFlags & KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE) != 0U)
        {
            parts << QStringLiteral("PdbProfileActive");
        }
        if ((statusFlags & KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE) != 0U)
        {
            parts << QStringLiteral("CallbackProfileActive");
        }
        return parts.isEmpty() ? QStringLiteral("None") : parts.join(QStringLiteral("|"));
    }

    // activeProcessLinksDynDataDiagnostic 作用：
    // - 输入：已打开的 DriverClient；
    // - 处理：只读查询 R0 DynData status 和字段表，定位 _EPROCESS.ActiveProcessLinks 是否已应用；
    // - 返回：一行诊断文本，供 R0 可见性动作失败时追加到 detailText。
    std::string activeProcessLinksDynDataDiagnostic(const ksword::ark::DriverClient& driverClient)
    {
        QStringList diagnosticParts;

        const ksword::ark::DynDataStatusResult statusResult = driverClient.queryDynDataStatus();
        if (statusResult.io.ok)
        {
            const QString statusFlagsText = QStringLiteral("0x%1")
                .arg(statusResult.statusFlags, 8, 16, QChar('0'))
                .toUpper();
            const QString capabilityText = QStringLiteral("0x%1")
                .arg(static_cast<qulonglong>(statusResult.capabilityMask), 16, 16, QChar('0'))
                .toUpper();
            const QString lastStatusText = QStringLiteral("0x%1")
                .arg(static_cast<std::uint32_t>(statusResult.lastStatus), 8, 16, QChar('0'))
                .toUpper();
            diagnosticParts << QStringLiteral(
                "DynDataStatus: flags=%1(%2), caps=%3, fields=%4, lastStatus=%5")
                .arg(statusFlagsText)
                .arg(dynDataStatusFlagText(statusResult.statusFlags))
                .arg(capabilityText)
                .arg(statusResult.fieldCount)
                .arg(lastStatusText);
            if ((statusResult.statusFlags & KSW_DYN_STATUS_FLAG_NTOS_ACTIVE) != 0U &&
                (statusResult.statusFlags & KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE) == 0U)
            {
                diagnosticParts << QStringLiteral("Hint: ntoskrnl DynData is active but PDB profile is not active; refresh Kernel/DynData to apply the v3 profile pack.");
            }
        }
        else
        {
            diagnosticParts << QStringLiteral("DynDataStatus unavailable: %1")
                .arg(processDockIoMessageText(QString::fromStdString(statusResult.io.message)));
        }

        const ksword::ark::DynDataFieldsResult fieldsResult = driverClient.queryDynDataFields();
        if (!fieldsResult.io.ok)
        {
            diagnosticParts << QStringLiteral("DynData ActiveProcessLinks unavailable: %1")
                .arg(processDockIoMessageText(QString::fromStdString(fieldsResult.io.message)));
            return diagnosticParts.join(QStringLiteral(" | ")).toStdString();
        }

        for (const ksword::ark::DynDataFieldEntry& entry : fieldsResult.entries)
        {
            if (entry.fieldId != KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS)
            {
                continue;
            }

            const bool present = dynDataOffsetPresent(entry.flags, entry.offset);
            const QString flagsText = QStringLiteral("0x%1")
                .arg(entry.flags, 8, 16, QChar('0'))
                .toUpper();
            const QString capabilityText = QStringLiteral("0x%1")
                .arg(static_cast<qulonglong>(entry.capabilityMask), 16, 16, QChar('0'))
                .toUpper();
            const QString diagnosticText = QStringLiteral(
                "DynData ActiveProcessLinks: present=%1, offset=%2, source=%3, flags=%4, capability=%5")
                .arg(present ? QStringLiteral("true") : QStringLiteral("false"))
                .arg(dynDataOffsetText(entry.offset))
                .arg(dynDataFieldSourceText(entry.source))
                .arg(flagsText)
                .arg(capabilityText);
            diagnosticParts << diagnosticText;
            return diagnosticParts.join(QStringLiteral(" | ")).toStdString();
        }

        diagnosticParts << QStringLiteral("DynData ActiveProcessLinks unavailable: field not returned by R0.");
        return diagnosticParts.join(QStringLiteral(" | ")).toStdString();
    }

    QString processR0StatusText(const std::uint32_t statusValue)
    {
        // statusValue 用途：R0 每行扩展信息的整体完成状态。
        // 返回值：短文本，直接用于表格列与详情页。
        switch (statusValue)
        {
        case KSWORD_ARK_PROCESS_R0_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_PROCESS_R0_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_PROCESS_R0_STATUS_DYNDATA_MISSING:
            return QStringLiteral("DynData missing");
        case KSWORD_ARK_PROCESS_R0_STATUS_READ_FAILED:
            return QStringLiteral("Read failed");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    QString byteHexText(const std::uint8_t byteValue)
    {
        // byteValue 用途：保护/签名等级原始单字节值。
        // 返回值：0xNN 格式，便于和内核原始字段对照。
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(byteValue), 2, 16, QChar('0'))
            .toUpper();
    }

    bool resolvePplSignatureLevelsForUi(
        const std::uint8_t protectionLevel,
        std::uint8_t* const signatureLevelOut,
        std::uint8_t* const sectionSignatureLevelOut)
    {
        // protectionLevel 用途：菜单传入的 PS_PROTECTION 原始字节。
        // 返回值：true 表示 UI 能预测驱动侧同步写入的签名级别。
        if (signatureLevelOut == nullptr || sectionSignatureLevelOut == nullptr)
        {
            return false;
        }

        const std::uint8_t signerType = (protectionLevel == 0U)
            ? static_cast<std::uint8_t>(0U)
            : static_cast<std::uint8_t>((protectionLevel & 0xF0U) >> 4U);
        switch (signerType)
        {
        case 0:
            *signatureLevelOut = 0x00U;
            *sectionSignatureLevelOut = 0x00U;
            return true;
        case 1:
            *signatureLevelOut = 0x04U;
            *sectionSignatureLevelOut = 0x04U;
            return true;
        case 2:
            *signatureLevelOut = 0x0BU;
            *sectionSignatureLevelOut = 0x06U;
            return true;
        case 3:
            *signatureLevelOut = 0x07U;
            *sectionSignatureLevelOut = 0x07U;
            return true;
        case 4:
            *signatureLevelOut = 0x0CU;
            *sectionSignatureLevelOut = 0x08U;
            return true;
        case 5:
            *signatureLevelOut = 0x0CU;
            *sectionSignatureLevelOut = 0x0CU;
            return true;
        case 6:
            *signatureLevelOut = 0x0EU;
            *sectionSignatureLevelOut = 0x0CU;
            return true;
        case 7:
            // WinSystem 与 WinTcb 共用一组签名级别，理由见驱动侧
            // KswordARKDriverResolveSignatureLevelsFromSigner。
            *signatureLevelOut = 0x0EU;
            *sectionSignatureLevelOut = 0x0CU;
            return true;
        case 8:
            *signatureLevelOut = 0x06U;
            *sectionSignatureLevelOut = 0x06U;
            return true;
        default:
            return false;
        }
    }

    QString pplMutationCapabilityText(const ks::process::ProcessRecord& processRecord)
    {
        // processRecord 用途：读取当前行的 DynData capability 与字段来源。
        // 返回值：二次确认框中的 capability/source 摘要。
        const bool capabilityPresent =
            (processRecord.r0DynDataCapabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) != 0U;
        const bool protectionOffsetPresent =
            processRecord.r0ProtectionOffset != KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE &&
            processRecord.r0SignatureLevelOffset != KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE &&
            processRecord.r0SectionSignatureLevelOffset != KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        return QStringLiteral("Capability: %1 | Offsets: %2 | Sources: Protection=%3, Signature=%4, SectionSignature=%5")
            .arg(capabilityPresent ? QStringLiteral("KSW_CAP_PROCESS_PROTECTION_PATCH present") : QStringLiteral("missing/unknown"))
            .arg(protectionOffsetPresent ? QStringLiteral("present") : QStringLiteral("missing/unknown"))
            .arg(processFieldSourceText(processRecord.r0ProtectionSource))
            .arg(processFieldSourceText(processRecord.r0SignatureLevelSource))
            .arg(processFieldSourceText(processRecord.r0SectionSignatureLevelSource));
    }

    QString pointerAvailabilityText(
        const bool available,
        const std::uint64_t addressValue,
        const std::uint32_t sourceValue)
    {
        // available 表示 offset/capability 是否可用；addressValue 是当前字段值。
        // 返回值含来源，方便用户判断 DynData 是否命中。
        if (!available)
        {
            return QStringLiteral("Unavailable (%1)").arg(processFieldSourceText(sourceValue));
        }
        if (addressValue == 0U)
        {
            return QStringLiteral("Available: null (%1)").arg(processFieldSourceText(sourceValue));
        }
        const QString addressText = QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(addressValue), 0, 16)
            .toUpper();
        return QStringLiteral("Available: 0x%1 (%2)")
            .arg(addressText.mid(2))
            .arg(processFieldSourceText(sourceValue));
    }

    // enumerateProcessesByR0Driver 作用：
    // - 仅在 KswordARK 控制设备已就绪时，通过 ArkDriverClient 获取内核侧进程列表；
    // - 驱动未加载的 R3 刷新不发送枚举 IOCTL，也不触发 R0 权限提示。
    // - 输出可用于“R3 列表 vs R0 列表”差异比对的数据。
    bool enumerateProcessesByR0Driver(
        std::vector<KernelProcessSnapshotEntry>* const processListOut,
        std::string* const detailTextOut)
    {
        if (processListOut == nullptr)
        {
            return false;
        }
        processListOut->clear();
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        const ksword::ark::DriverClient driverClient;
        ksword::ark::DriverHandle driverHandle = driverClient.openSilently();
        if (!driverHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "R0 driver device is not ready; kernel process comparison skipped";
            }
            return false;
        }

        const ksword::ark::ProcessEnumResult enumResult = driverClient.enumerateProcesses(
            KSWORD_ARK_ENUM_PROCESS_FLAG_SCAN_CID_TABLE,
            &driverHandle);
        if (!enumResult.io.ok)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = processDockIoMessageStdString(enumResult.io.message);
            }
            return false;
        }

        processListOut->reserve(enumResult.entries.size());
        for (const ksword::ark::ProcessEntry& entry : enumResult.entries)
        {
            KernelProcessSnapshotEntry processEntry{};
            processEntry.processId = entry.processId;
            processEntry.parentProcessId = entry.parentProcessId;
            processEntry.flags = entry.flags;
            processEntry.sessionId = entry.sessionId;
            processEntry.fieldFlags = entry.fieldFlags;
            processEntry.r0Status = entry.r0Status;
            processEntry.sessionSource = entry.sessionSource;
            processEntry.protection = entry.protection;
            processEntry.signatureLevel = entry.signatureLevel;
            processEntry.sectionSignatureLevel = entry.sectionSignatureLevel;
            processEntry.protectionSource = entry.protectionSource;
            processEntry.signatureLevelSource = entry.signatureLevelSource;
            processEntry.sectionSignatureLevelSource = entry.sectionSignatureLevelSource;
            processEntry.objectTableSource = entry.objectTableSource;
            processEntry.sectionObjectSource = entry.sectionObjectSource;
            processEntry.imagePathSource = entry.imagePathSource;
            processEntry.protectionOffset = entry.protectionOffset;
            processEntry.signatureLevelOffset = entry.signatureLevelOffset;
            processEntry.sectionSignatureLevelOffset = entry.sectionSignatureLevelOffset;
            processEntry.objectTableOffset = entry.objectTableOffset;
            processEntry.sectionObjectOffset = entry.sectionObjectOffset;
            processEntry.objectTableAddress = entry.objectTableAddress;
            processEntry.sectionObjectAddress = entry.sectionObjectAddress;
            processEntry.dynDataCapabilityMask = entry.dynDataCapabilityMask;
            processEntry.creationTime100ns = entry.creationTime100ns;
            processEntry.imageName = entry.imageName;
            processEntry.imagePath = entry.imagePath;
            processListOut->push_back(std::move(processEntry));
        }

        if (detailTextOut != nullptr)
        {
            *detailTextOut = processDockIoMessageStdString(enumResult.io.message);
        }
        return true;
    }

    // mergeKernelProcessExtension 作用：
    // - 把 R0 枚举得到的 Phase-2 EPROCESS 扩展字段合并到 R3 进程记录；
    // - 基础路径/命令行仍以用户态公开 API 为主，R0 路径仅作为补充诊断字段。
    void mergeKernelProcessExtension(
        ks::process::ProcessRecord& processRecord,
        const KernelProcessSnapshotEntry& kernelProcess)
    {
        processRecord.r0Flags = kernelProcess.flags;
        processRecord.r0FieldFlags = kernelProcess.fieldFlags;
        processRecord.r0Status = kernelProcess.r0Status;
        processRecord.r0DynDataCapabilityMask = kernelProcess.dynDataCapabilityMask;
        processRecord.r0ImagePath = kernelProcess.imagePath;

        if ((kernelProcess.fieldFlags & KSWORD_ARK_PROCESS_FIELD_SESSION_PRESENT) != 0U)
        {
            processRecord.sessionId = kernelProcess.sessionId;
        }

        processRecord.r0Protection = kernelProcess.protection;
        processRecord.r0SignatureLevel = kernelProcess.signatureLevel;
        processRecord.r0SectionSignatureLevel = kernelProcess.sectionSignatureLevel;
        processRecord.r0SessionSource = kernelProcess.sessionSource;
        processRecord.r0ImagePathSource = kernelProcess.imagePathSource;
        processRecord.r0ProtectionSource = kernelProcess.protectionSource;
        processRecord.r0SignatureLevelSource = kernelProcess.signatureLevelSource;
        processRecord.r0SectionSignatureLevelSource = kernelProcess.sectionSignatureLevelSource;
        processRecord.r0ObjectTableSource = kernelProcess.objectTableSource;
        processRecord.r0SectionObjectSource = kernelProcess.sectionObjectSource;
        processRecord.r0ProtectionOffset = kernelProcess.protectionOffset;
        processRecord.r0SignatureLevelOffset = kernelProcess.signatureLevelOffset;
        processRecord.r0SectionSignatureLevelOffset = kernelProcess.sectionSignatureLevelOffset;
        processRecord.r0ObjectTableOffset = kernelProcess.objectTableOffset;
        processRecord.r0SectionObjectOffset = kernelProcess.sectionObjectOffset;
        processRecord.r0ObjectTableAddress = kernelProcess.objectTableAddress;
        processRecord.r0SectionObjectAddress = kernelProcess.sectionObjectAddress;
    }

    bool enrichProcessRecordWithR0ExtensionByPid(
        ks::process::ProcessRecord& processRecord,
        std::string* const detailTextOut)
    {
        // processRecord 用途：调用方当前选中或即将打开详情的 R3 进程记录。
        // 返回值：true 表示已从 R0 枚举中找到同 PID 并合并 Phase-2 扩展字段。
        std::vector<KernelProcessSnapshotEntry> kernelProcessList;
        std::string queryDetailText;
        const bool queryOk = enumerateProcessesByR0Driver(&kernelProcessList, &queryDetailText);
        if (!queryOk)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = queryDetailText.empty()
                    ? std::string("query kernel process list failed")
                    : queryDetailText;
            }
            return false;
        }

        for (const KernelProcessSnapshotEntry& kernelProcess : kernelProcessList)
        {
            if (kernelProcess.processId != processRecord.pid)
            {
                continue;
            }

            mergeKernelProcessExtension(processRecord, kernelProcess);
            if (processRecord.processName.empty() && !kernelProcess.imageName.empty())
            {
                processRecord.processName = kernelProcess.imageName;
            }
            if (detailTextOut != nullptr)
            {
                *detailTextOut = queryDetailText;
            }
            return true;
        }

        if (detailTextOut != nullptr)
        {
            *detailTextOut = "target pid not returned by R0 process enumeration";
        }
        return false;
    }

    // isProcessPresentBySnapshot 作用：
    // - 通过 Toolhelp 进程快照判断目标 PID 当前是否仍存在；
    // - 用于“结束进程组合动作”每一步后的真实存活判定。
    // 调用方式：ProcessDock::executeTerminateProcessAction 内部循环调用。
    // 参数 targetPid：目标进程 PID。
    // 参数 queryOkOut：快照查询是否成功（可空）。
    // 返回值：true=进程仍存在（或查询失败时保守视为存在）；false=进程不存在。
    bool isProcessPresentBySnapshot(const std::uint32_t targetPid, bool* const queryOkOut)
    {
        if (queryOkOut != nullptr)
        {
            *queryOkOut = false;
        }

        // snapshotHandle 用途：承接系统进程快照句柄，供后续枚举 PID。
        const HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return true;
        }

        // processEntry 用途：逐条读取进程快照记录并比较 PID。
        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(snapshotHandle, &processEntry) == FALSE)
        {
            ::CloseHandle(snapshotHandle);
            return true;
        }

        // processPresent 用途：记录目标 PID 是否在当前快照里被命中。
        bool processPresent = false;
        do
        {
            if (processEntry.th32ProcessID == targetPid)
            {
                processPresent = true;
                break;
            }
        } while (::Process32NextW(snapshotHandle, &processEntry) != FALSE);

        ::CloseHandle(snapshotHandle);
        if (queryOkOut != nullptr)
        {
            *queryOkOut = true;
        }
        return processPresent;
    }

    // usageRatioToHighlightColor 作用：
    // - 按占用比例（0~1）返回主题蓝色透明高亮；
    // - 占用越高，alpha 越大，视觉上更“深”。
    QColor usageRatioToHighlightColor(double usageRatio)
    {
        usageRatio = std::clamp(usageRatio, 0.0, 1.0);
        const int alphaValue = static_cast<int>(24.0 + usageRatio * 146.0);
        QColor highlightColor = KswordTheme::PrimaryBlueColor;
        highlightColor.setAlpha(alphaValue);
        return highlightColor;
    }

    // hasDetailWindowSignificantChange 作用：
    // - 判断两轮进程记录是否存在“需要立刻同步到详情窗口”的显著变化；
    // - 通过阈值过滤掉轻微抖动，减少刷新期间 UI 卡顿。
    bool hasDetailWindowSignificantChange(
        const ks::process::ProcessRecord& oldRecord,
        const ks::process::ProcessRecord& newRecord)
    {
        if (oldRecord.pid != newRecord.pid ||
            oldRecord.creationTime100ns != newRecord.creationTime100ns)
        {
            return true;
        }

        if (std::fabs(oldRecord.cpuPercent - newRecord.cpuPercent) >= 4.0)
        {
            return true;
        }
        if (std::fabs(oldRecord.ramMB - newRecord.ramMB) >= 16.0)
        {
            return true;
        }
        if (std::fabs(oldRecord.diskMBps - newRecord.diskMBps) >= 1.0)
        {
            return true;
        }
        if (std::fabs(oldRecord.netKBps - newRecord.netKBps) >= 8.0)
        {
            return true;
        }
        if (std::fabs(oldRecord.gpuPercent - newRecord.gpuPercent) >= 5.0)
        {
            return true;
        }
        if (oldRecord.protectionLevelKnown != newRecord.protectionLevelKnown ||
            oldRecord.protectionLevel != newRecord.protectionLevel ||
            oldRecord.protectionLevelText != newRecord.protectionLevelText)
        {
            return true;
        }

        if (oldRecord.threadCount != newRecord.threadCount ||
            oldRecord.handleCount != newRecord.handleCount ||
            oldRecord.parentPid != newRecord.parentPid ||
            oldRecord.isAdmin != newRecord.isAdmin ||
            oldRecord.signatureTrusted != newRecord.signatureTrusted)
        {
            return true;
        }

        if (oldRecord.imagePath != newRecord.imagePath ||
            oldRecord.commandLine != newRecord.commandLine ||
            oldRecord.userName != newRecord.userName ||
            oldRecord.signatureState != newRecord.signatureState ||
            oldRecord.signaturePublisher != newRecord.signaturePublisher ||
            oldRecord.startTimeText != newRecord.startTimeText)
        {
            return true;
        }

        return false;
    }

    // 统一按钮蓝色样式，和现有主题风格保持一致。
    QString buildBlueButtonStyle(const bool iconOnlyButton)
    {
        // 图标按钮采用更紧凑 padding，避免出现多余空白。
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
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::PrimaryBlueBorderHex)
            .arg(KswordTheme::PrimaryBlueHoverHex)
            .arg(KswordTheme::PrimaryBluePressedHex)
            .arg(paddingText)
            .arg(KswordTheme::SurfaceHex())
            .arg(QStringLiteral("palette(highlighted-text)"));
    }

    // 下拉框主题描边样式，保持与按钮同色系。
    QString buildBlueComboBoxStyle()
    {
        return KswordTheme::ThemedComboBoxStyle();
    }

    // buildBlueComboBoxPopupViewStyle 作用：
    // - 给 QComboBox::view() 直接设置弹出列表样式；
    // - QComboBox 的 popup 是独立 item view，父级选择器在某些 Qt/Windows 主题下压不住白底；
    // - 返回：仅作用于 popup view 的 QSS，主框样式仍由 buildBlueComboBoxStyle 负责。
    QString buildBlueComboBoxPopupViewStyle()
    {
        return KswordTheme::ThemedComboBoxPopupViewStyle();
    }

    // applyBlueComboBoxRuntimeStyle 作用：
    // - 运行时同时设置 stylesheet 与 palette；
    // - 输入 comboBoxPointer 为进程页顶部的两个下拉框；
    // - 返回：无，直接修正主框与 popup view 的深色/浅色配色。
    void applyBlueComboBoxRuntimeStyle(QComboBox* comboBoxPointer)
    {
        if (comboBoxPointer == nullptr)
        {
            return;
        }

        const QString comboBackgroundColor = KswordTheme::SurfaceHex();
        const QString comboTextColor = KswordTheme::TextPrimaryHex();

        comboBoxPointer->setStyleSheet(buildBlueComboBoxStyle());

        QPalette comboPalette = comboBoxPointer->palette();
        comboPalette.setColor(QPalette::Base, QColor(comboBackgroundColor));
        comboPalette.setColor(QPalette::Window, QColor(comboBackgroundColor));
        comboPalette.setColor(QPalette::Button, QColor(comboBackgroundColor));
        comboPalette.setColor(QPalette::Text, QColor(comboTextColor));
        comboPalette.setColor(QPalette::ButtonText, QColor(comboTextColor));
        comboPalette.setColor(QPalette::Highlight, KswordTheme::ControlAccentColor());
        comboPalette.setColor(
            QPalette::HighlightedText,
            KswordTheme::MaximumContrastMonochromeColor(KswordTheme::ControlAccentColor()));
        comboBoxPointer->setPalette(comboPalette);

        QAbstractItemView* popupView = comboBoxPointer->view();
        if (popupView == nullptr)
        {
            return;
        }

        popupView->setPalette(comboPalette);
        popupView->setAutoFillBackground(true);
        popupView->setStyleSheet(buildBlueComboBoxPopupViewStyle());
        if (popupView->viewport() != nullptr)
        {
            popupView->viewport()->setAutoFillBackground(true);
            popupView->viewport()->setPalette(comboPalette);
            popupView->viewport()->setStyleSheet(QStringLiteral(
                "background:%1 !important;"
                "background-color:%1 !important;")
                .arg(comboBackgroundColor));
        }
    }

    // 统一“普通输入框”主题边框。
    QString buildBlueLineEditStyle()
    {
        return QStringLiteral(
            "QLineEdit, QPlainTextEdit, QTextEdit {"
            "  border: 1px solid %2;"
            "  border-radius: 3px;"
            "  background: %3;"
            "  color: %4;"
            "  padding: 3px 5px;"
            "}"
            "QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {"
            "  border: 1px solid %1;"
            "}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    // applyTransparentContainerStyle 作用：
    // - 仅把“创建进程”页中的容器类控件背景改成透明；
    // - 不影响输入框、按钮等已有主题样式。
    void applyTransparentContainerStyle(QWidget* widgetPointer)
    {
        if (widgetPointer == nullptr)
        {
            return;
        }

        widgetPointer->setAttribute(Qt::WA_StyledBackground, true);
        widgetPointer->setAutoFillBackground(false);
        widgetPointer->setStyleSheet(
            widgetPointer->styleSheet()
            + QStringLiteral("background:transparent;background-color:transparent;"));

        QAbstractScrollArea* scrollAreaPointer = qobject_cast<QAbstractScrollArea*>(widgetPointer);
        if (scrollAreaPointer == nullptr || scrollAreaPointer->viewport() == nullptr)
        {
            return;
        }

        scrollAreaPointer->viewport()->setAttribute(Qt::WA_StyledBackground, true);
        scrollAreaPointer->viewport()->setAutoFillBackground(false);
        scrollAreaPointer->viewport()->setStyleSheet(
            scrollAreaPointer->viewport()->styleSheet()
            + QStringLiteral("background:transparent;background-color:transparent;"));
    }

    // 完整令牌特权列表：复用进程模块维护的 Windows SDK Se*Privilege 目录。
    QStringList tokenPrivilegeNames()
    {
        QStringList privilegeNames;
        privilegeNames.reserve(static_cast<qsizetype>(ks::process::KnownTokenPrivilegeNames().size()));
        for (const std::string& privilegeName : ks::process::KnownTokenPrivilegeNames())
        {
            privilegeNames.push_back(QString::fromLatin1(privilegeName.c_str()));
        }
        return privilegeNames;
    }

    // BitmaskFlagDefinition 作用：
    // - 统一描述“复选框可勾选的位标志定义”；
    // - nameText：显示名称；
    // - value：该位标志对应的掩码值；
    // - descriptionText：鼠标悬停说明，帮助用户理解语义。
    struct BitmaskFlagDefinition
    {
        const char* nameText = "";            // 标志名（例如 CREATE_SUSPENDED）。
        std::uint32_t value = 0;              // 标志位掩码（DWORD）。
        const char* descriptionText = "";     // 标志用途说明文本。
    };

    // CreateProcess.dwCreationFlags 常用且可组合的位标志全集。
    const std::vector<BitmaskFlagDefinition> CreateProcessFlagDefinitions{
        { "DEBUG_PROCESS", 0x00000001U, "调试子进程和其后代进程。" },
        { "DEBUG_ONLY_THIS_PROCESS", 0x00000002U, "仅调试当前创建的子进程。" },
        { "CREATE_SUSPENDED", 0x00000004U, "主线程创建后先挂起。" },
        { "DETACHED_PROCESS", 0x00000008U, "控制台进程脱离父控制台。" },
        { "CREATE_NEW_CONSOLE", 0x00000010U, "为新进程分配新控制台窗口。" },
        { "NORMAL_PRIORITY_CLASS", 0x00000020U, "普通优先级类。" },
        { "IDLE_PRIORITY_CLASS", 0x00000040U, "空闲优先级类。" },
        { "HIGH_PRIORITY_CLASS", 0x00000080U, "高优先级类。" },
        { "REALTIME_PRIORITY_CLASS", 0x00000100U, "实时优先级类（高风险）。" },
        { "CREATE_NEW_PROCESS_GROUP", 0x00000200U, "创建新的进程组。" },
        { "CREATE_UNICODE_ENVIRONMENT", 0x00000400U, "环境块按 Unicode 传递。" },
        { "CREATE_SEPARATE_WOW_VDM", 0x00000800U, "16 位应用使用独立 WOW VDM。" },
        { "CREATE_SHARED_WOW_VDM", 0x00001000U, "16 位应用共享 WOW VDM。" },
        { "CREATE_FORCEDOS", 0x00002000U, "强制 DOS 兼容模式（历史选项）。" },
        { "BELOW_NORMAL_PRIORITY_CLASS", 0x00004000U, "低于普通优先级类。" },
        { "ABOVE_NORMAL_PRIORITY_CLASS", 0x00008000U, "高于普通优先级类。" },
        { "INHERIT_PARENT_AFFINITY", 0x00010000U, "继承父进程 CPU 亲和性。" },
        { "CREATE_PROTECTED_PROCESS", 0x00040000U, "创建受保护进程（受系统限制）。" },
        { "EXTENDED_STARTUPINFO_PRESENT", 0x00080000U, "启用 STARTUPINFOEX 扩展结构。" },
        { "PROCESS_MODE_BACKGROUND_BEGIN", 0x00100000U, "进入后台模式（I/O/CPU 降优先级）。" },
        { "PROCESS_MODE_BACKGROUND_END", 0x00200000U, "退出后台模式。" },
        { "CREATE_SECURE_PROCESS", 0x00400000U, "创建安全进程（受系统策略限制）。" },
        { "CREATE_BREAKAWAY_FROM_JOB", 0x01000000U, "允许脱离 Job 对象。" },
        { "CREATE_PRESERVE_CODE_AUTHZ_LEVEL", 0x02000000U, "保持代码授权级别。" },
        { "CREATE_DEFAULT_ERROR_MODE", 0x04000000U, "使用默认错误模式。" },
        { "CREATE_NO_WINDOW", 0x08000000U, "控制台进程不创建窗口。" },
        { "PROFILE_USER", 0x10000000U, "启用用户模式性能统计。" },
        { "PROFILE_KERNEL", 0x20000000U, "启用内核模式性能统计。" },
        { "PROFILE_SERVER", 0x40000000U, "启用服务器性能统计。" },
        { "CREATE_IGNORE_SYSTEM_DEFAULT", 0x80000000U, "忽略系统默认设置（较少使用）。" }
    };

    // STARTUPINFO.dwFlags 位标志全集。
    const std::vector<BitmaskFlagDefinition> StartupInfoFlagDefinitions{
        { "STARTF_USESHOWWINDOW", 0x00000001U, "启用 wShowWindow 字段。" },
        { "STARTF_USESIZE", 0x00000002U, "启用 dwXSize/dwYSize 字段。" },
        { "STARTF_USEPOSITION", 0x00000004U, "启用 dwX/dwY 字段。" },
        { "STARTF_USECOUNTCHARS", 0x00000008U, "启用控制台字符网格大小字段。" },
        { "STARTF_USEFILLATTRIBUTE", 0x00000010U, "启用 dwFillAttribute 字段。" },
        { "STARTF_RUNFULLSCREEN", 0x00000020U, "全屏模式启动（主要针对旧控制台）。" },
        { "STARTF_FORCEONFEEDBACK", 0x00000040U, "强制显示忙碌光标反馈。" },
        { "STARTF_FORCEOFFFEEDBACK", 0x00000080U, "关闭启动忙碌光标反馈。" },
        { "STARTF_USESTDHANDLES", 0x00000100U, "启用标准输入/输出/错误句柄字段。" },
        { "STARTF_USEHOTKEY", 0x00000200U, "启用热键字段（hStdInput 解释为 hotkey）。" },
        { "STARTF_TITLEISLINKNAME", 0x00000800U, "标题解释为 Shell 链接名。" },
        { "STARTF_TITLEISAPPID", 0x00001000U, "标题解释为 AppUserModelID。" },
        { "STARTF_PREVENTPINNING", 0x00002000U, "阻止任务栏固定（需 AppID）。" },
        { "STARTF_UNTRUSTEDSOURCE", 0x00008000U, "标记命令来源不可信。" },
        { "STARTF_HOLOGRAPHIC", 0x00040000U, "全息场景启动标记（特定平台）。" }
    };

    // STARTUPINFO.dwFillAttribute 控制台颜色/样式标志全集。
    const std::vector<BitmaskFlagDefinition> ConsoleFillAttributeDefinitions{
        { "FOREGROUND_BLUE", 0x0001U, "前景色：蓝。" },
        { "FOREGROUND_GREEN", 0x0002U, "前景色：绿。" },
        { "FOREGROUND_RED", 0x0004U, "前景色：红。" },
        { "FOREGROUND_INTENSITY", 0x0008U, "前景色高亮。" },
        { "BACKGROUND_BLUE", 0x0010U, "背景色：蓝。" },
        { "BACKGROUND_GREEN", 0x0020U, "背景色：绿。" },
        { "BACKGROUND_RED", 0x0040U, "背景色：红。" },
        { "BACKGROUND_INTENSITY", 0x0080U, "背景色高亮。" },
        { "COMMON_LVB_LEADING_BYTE", 0x0100U, "双字节字符前导字节标记。" },
        { "COMMON_LVB_TRAILING_BYTE", 0x0200U, "双字节字符后继字节标记。" },
        { "COMMON_LVB_GRID_HORIZONTAL", 0x0400U, "水平网格线。" },
        { "COMMON_LVB_GRID_LVERTICAL", 0x0800U, "左垂直网格线。" },
        { "COMMON_LVB_GRID_RVERTICAL", 0x1000U, "右垂直网格线。" },
        { "COMMON_LVB_REVERSE_VIDEO", 0x4000U, "反色显示。" },
        { "COMMON_LVB_UNDERSCORE", 0x8000U, "下划线显示。" }
    };

    // Token DesiredAccess 常用位标志全集（OpenProcessToken / DuplicateTokenEx 路径）。
    const std::vector<BitmaskFlagDefinition> TokenDesiredAccessDefinitions{
        { "TOKEN_ASSIGN_PRIMARY", 0x00000001U, "可把令牌分配给新进程主令牌。" },
        { "TOKEN_DUPLICATE", 0x00000002U, "可复制令牌。" },
        { "TOKEN_IMPERSONATE", 0x00000004U, "可模拟令牌。" },
        { "TOKEN_QUERY", 0x00000008U, "可查询令牌信息。" },
        { "TOKEN_QUERY_SOURCE", 0x00000010U, "可查询令牌来源。" },
        { "TOKEN_ADJUST_PRIVILEGES", 0x00000020U, "可调整令牌特权。" },
        { "TOKEN_ADJUST_GROUPS", 0x00000040U, "可调整令牌组。" },
        { "TOKEN_ADJUST_DEFAULT", 0x00000080U, "可调整默认 DACL/Owner 等。" },
        { "TOKEN_ADJUST_SESSIONID", 0x00000100U, "可调整会话 ID。" },
        { "DELETE", 0x00010000U, "标准删除权限。" },
        { "READ_CONTROL", 0x00020000U, "标准读取安全描述符权限。" },
        { "WRITE_DAC", 0x00040000U, "标准写 DACL 权限。" },
        { "WRITE_OWNER", 0x00080000U, "标准写 Owner 权限。" },
        { "ACCESS_SYSTEM_SECURITY", 0x01000000U, "访问 SACL 权限（高权限）。" },
        { "MAXIMUM_ALLOWED", 0x02000000U, "请求对象允许的最大权限。" },
        { "GENERIC_ALL", 0x10000000U, "通用全部权限映射。" },
        { "GENERIC_EXECUTE", 0x20000000U, "通用执行权限映射。" },
        { "GENERIC_WRITE", 0x40000000U, "通用写权限映射。" },
        { "GENERIC_READ", 0x80000000U, "通用读权限映射。" }
    };
}

ProcessDock::ProcessDock(QWidget* parent)
    : QWidget(parent)
{
    m_mainWindowActionReceiver = parent;

    // Processor Group 感知：ALL_PROCESSOR_GROUPS 覆盖超过 64 个逻辑处理器的系统。
    const DWORD activeProcessorCount = ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    m_logicalCpuCount = activeProcessorCount != 0
        ? static_cast<std::uint32_t>(activeProcessorCount)
        : std::max<std::uint32_t>(1, std::thread::hardware_concurrency());

    // Shell 图标解析可能阻塞磁盘或图标处理程序，使用独立线程池并限制并发数。
    // 至少保留两个工作线程以并行处理应用图标，上限八个避免短时间创建过多 Shell 查询。
    const int iconExtractionWorkerCount = std::clamp(static_cast<int>(m_logicalCpuCount), 2, 8);
    m_processIconExtractionPool.setMaxThreadCount(iconExtractionWorkerCount);
    m_processIconExtractionPool.setExpiryTimeout(1000);

    // 构造阶段按“UI -> 连接 -> 定时器 -> 首次刷新”顺序执行。
    m_activityTotalPhysicalMemoryMB = totalPhysicalMemoryMB();
    initializeUi();
    initializeConnections();
    initializeTimer();
    if (QApplication::instance() != nullptr)
    {
        QApplication::instance()->installEventFilter(this);
    }
    m_monitoringEnabled = false;
}

ProcessDock::~ProcessDock()
{
    // 使已运行任务的回传结果失效，并取消尚未开始的图标查询任务。
    // 线程池析构会等待已运行任务结束，任务只使用自己的路径副本，不再访问 Dock 成员。
    ++m_processIconExtractionGeneration;
    m_processIconExtractionPool.clear();
    m_processIconPathsInFlight.clear();

    // 析构阶段先停止内部 ETW 消费线程：
    // - 输入：无；
    // - 处理：请求 ProcessNetworkEtwMonitor 退出并等待线程 join；
    // - 返回：无，防止对象销毁后 ETW 回调继续访问成员。
    stopProcessNetworkTrafficCapture();
    stopCpuCoreUsageCapture();

    // 析构阶段主动解除全局事件过滤器，避免 QApplication 后续点击事件访问已销毁 Dock。
    if (QApplication::instance() != nullptr)
    {
        QApplication::instance()->removeEventFilter(this);
    }
}

QObject* ProcessDock::mainWindowActionReceiver() const
{
    if (m_mainWindowActionReceiver != nullptr)
    {
        return m_mainWindowActionReceiver.data();
    }
    return parent();
}

bool ProcessDock::invokeMainWindowPidSlot(const char* methodName, const std::uint32_t pid) const
{
    QObject* receiver = mainWindowActionReceiver();
    if (receiver == nullptr)
    {
        return false;
    }

    return QMetaObject::invokeMethod(
        receiver,
        methodName,
        Qt::QueuedConnection,
        Q_ARG(quint32, static_cast<quint32>(pid)));
}

void ProcessDock::ensureProcessNetworkTrafficCaptureStarted()
{
    // ensureProcessNetworkTrafficCaptureStarted：
    // - 输入：无；
    // - 处理：懒创建内部 ETW 累计器，后台仅按 PID 记录 TCP/UDP 收发字节；
    // - 返回：无。失败时不回退到 Raw Socket 方案，进程表沿用现有差分结果。
    if (m_processNetworkTrafficCaptureStarted)
    {
        return;
    }
    m_processNetworkTrafficCaptureStarted = true;

    if (m_processNetworkTrafficService == nullptr)
    {
        m_processNetworkTrafficService = std::make_unique<ks::network::ProcessNetworkEtwMonitor>();
    }

    const bool started = m_processNetworkTrafficService->Start();

    kLogEvent logEvent;
    (started ? info : warn) << logEvent
        << "[ProcessDock] 进程网络吞吐 ETW 采集器"
        << (started ? "启动成功" : "启动失败")
        << (started ? std::string() : (", detail=" + m_processNetworkTrafficService->LastErrorText()))
        << eol;
}

void ProcessDock::stopProcessNetworkTrafficCapture()
{
    // stopProcessNetworkTrafficCapture：
    // - 输入：无；
    // - 处理：停止内部 ETW 会话，避免暂停或析构后继续累计；
    // - 返回：无。
    if (m_processNetworkTrafficService != nullptr)
    {
        m_processNetworkTrafficService->Stop();
    }
    m_processNetworkTrafficCaptureStarted = false;
}

void ProcessDock::ensureCpuCoreUsageCaptureStarted()
{
    // 先记录期望状态：Stop 尚未完成时虽不能立刻启动，完成回调仍能据此恢复同一实例。
    m_cpuCoreUsageCaptureDesired->store(true, std::memory_order_release);
    // 同一个旧会话仍在异步 Stop/join 时禁止创建新实例，确保进程页始终最多一个 CSwitch 会话。
    if (m_cpuCoreUsageCaptureStarted || m_cpuCoreUsageStopInProgress)
    {
        return;
    }
    m_cpuCoreUsageCaptureStarted = true;
    if (m_cpuCoreUsageService == nullptr)
    {
        m_cpuCoreUsageService =
            std::make_shared<ks::process::ProcessCpuCoreEtwMonitor>();
    }

    // StartTrace/OpenTrace 只执行一次，但仍移到全局工作线程，避免 ETW 服务响应慢时阻塞 GUI。
    const std::shared_ptr<ks::process::ProcessCpuCoreEtwMonitor> cpuCoreService =
        m_cpuCoreUsageService;
    const std::shared_ptr<std::atomic_bool> captureDesired =
        m_cpuCoreUsageCaptureDesired;
    QRunnable* startTask = QRunnable::create([cpuCoreService, captureDesired]()
    {
        const bool started = cpuCoreService->Start();
        if (started && !captureDesired->load(std::memory_order_acquire))
        {
            // 用户在启动完成前已暂停时立即后台回收，避免短暂遗留无人消费的高频会话。
            cpuCoreService->Stop();
        }
        kLogEvent logEvent;
        (started ? info : warn) << logEvent
            << "[ProcessDock] 单系统会话 CSwitch 逐核心 CPU 采集器"
            << (started ? "启动成功" : "启动失败")
            << (started
                ? std::string()
                : (", detail=" + cpuCoreService->LastErrorText()))
            << eol;
    });
    startTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(startTask);
}

void ProcessDock::stopCpuCoreUsageCapture()
{
    // UI 立即释放最新矩阵；StopTrace + consumer join 交给后台执行，暂停按钮不会卡住界面。
    m_latestCpuCoreUsageSnapshot.reset();
    m_lastCpuCoreUsageSnapshotTime = {};
    m_cpuCoreUsageCaptureDesired->store(false, std::memory_order_release);
    if (m_processTable != nullptr && m_processTable->viewport() != nullptr)
    {
        // 暂停后立即清掉 CPU 列上一帧扇形，不等待滚动、曝光或下一次整表刷新。
        const int cpuColumn = toColumnIndex(TableColumn::CpuCore);
        const QRect cpuViewportRect(
            m_processTable->columnViewportPosition(cpuColumn),
            0,
            m_processTable->columnWidth(cpuColumn),
            m_processTable->viewport()->height());
        m_processTable->viewport()->update(
            cpuViewportRect.intersected(m_processTable->viewport()->rect()));
    }
    m_cpuCoreUsageCaptureStarted = false;
    if (m_cpuCoreUsageService == nullptr || m_cpuCoreUsageStopInProgress)
    {
        return;
    }

    m_cpuCoreUsageStopInProgress = true;
    // 始终保留并复用同一个 service 对象；Stop 完成后的恢复仍调用同一实例，绝不创建第二个会话。
    const std::shared_ptr<ks::process::ProcessCpuCoreEtwMonitor> cpuCoreService =
        m_cpuCoreUsageService;
    const QPointer<ProcessDock> safeThis(this);
    QRunnable* stopTask = QRunnable::create([safeThis, cpuCoreService]()
    {
        cpuCoreService->Stop();
        if (safeThis.isNull())
        {
            return;
        }

        QMetaObject::invokeMethod(
            safeThis,
            [safeThis]()
            {
                if (safeThis.isNull())
                {
                    return;
                }
                safeThis->m_cpuCoreUsageStopInProgress = false;
                if (safeThis->m_cpuCoreUsageCaptureDesired->load(std::memory_order_acquire))
                {
                    // 用户在 Stop 完成前已重新进入允许刷新状态时，此处恢复唯一系统级会话。
                    safeThis->ensureCpuCoreUsageCaptureStarted();
                }
            },
            Qt::QueuedConnection);
    });
    stopTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(stopTask);
}

void ProcessDock::syncCpuCoreUsageToDetailWindow(
    ProcessDetailWindow* const detailWindow,
    const ks::process::ProcessRecord& processRecord) const
{
    if (detailWindow == nullptr)
    {
        return;
    }

    ProcessDetailWindow::CpuCoreViewSample viewSample;
    viewSample.processSystemPercent = processRecord.cpuPercent;
    viewSample.processCoreEquivalentPercent = processRecord.cpuCorePercent;
    const std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> cpuCoreSnapshot =
        m_latestCpuCoreUsageSnapshot;
    if (cpuCoreSnapshot == nullptr)
    {
        viewSample.diagnosticText = ks::i18n::sourceText(
            QStringLiteral("CSwitch monitor has not started"));
        detailWindow->setCpuCoreViewSample(std::move(viewSample));
        return;
    }

    viewSample.monitorRunning = cpuCoreSnapshot->monitorRunning;
    viewSample.sampleReady = cpuCoreSnapshot->sampleReady;
    viewSample.dataLossDetected = cpuCoreSnapshot->dataLossDetected;
    viewSample.eventsLost = cpuCoreSnapshot->eventsLost;
    viewSample.contextSwitchEvents = cpuCoreSnapshot->contextSwitchEvents;
    viewSample.diagnosticText = ks::i18n::sourceText(
        QString::fromStdString(cpuCoreSnapshot->diagnosticText));

    const auto processUsageIt =
        cpuCoreSnapshot->processUsageByPid.find(processRecord.pid);
    const ks::process::CpuCoreUsageSeries* const processUsage =
        processUsageIt != cpuCoreSnapshot->processUsageByPid.end()
        ? &processUsageIt->second
        : nullptr;
    viewSample.processCores.reserve(cpuCoreSnapshot->processors.size());
    for (std::size_t processorIndex = 0;
         processorIndex < cpuCoreSnapshot->processors.size();
         ++processorIndex)
    {
        const ks::process::EtwLogicalProcessorCoordinate& coordinate =
            cpuCoreSnapshot->processors[processorIndex];
        ProcessDetailWindow::CpuCoreValue coreValue;
        coreValue.processorIndex = coordinate.processorIndex;
        coreValue.group = coordinate.group;
        coreValue.number = coordinate.number;
        coreValue.sampleReady =
            processorIndex < cpuCoreSnapshot->sampleReadyByProcessor.size() &&
            cpuCoreSnapshot->sampleReadyByProcessor[processorIndex];
        if (processUsage != nullptr &&
            processorIndex < processUsage->percentByProcessor.size())
        {
            coreValue.percent = processUsage->percentByProcessor[processorIndex];
        }
        viewSample.processCores.push_back(coreValue);
    }

    std::unordered_set<std::uint32_t> populatedThreadIds;
    populatedThreadIds.reserve(cpuCoreSnapshot->threadUsageByIdentity.size());
    for (const auto& threadUsagePair : cpuCoreSnapshot->threadUsageByIdentity)
    {
        const ks::process::CpuCoreUsageSeries& threadUsage = threadUsagePair.second;
        if (threadUsage.processId != processRecord.pid || threadUsage.threadId == 0)
        {
            continue;
        }

        ProcessDetailWindow::ThreadCpuCoreValue threadValue;
        threadValue.threadId = threadUsage.threadId;
        threadValue.cpuPercent = threadUsage.coreEquivalentPercent;
        threadValue.cores.reserve(viewSample.processCores.size());
        for (std::size_t processorIndex = 0;
             processorIndex < viewSample.processCores.size();
             ++processorIndex)
        {
            ProcessDetailWindow::CpuCoreValue coreValue = viewSample.processCores[processorIndex];
            coreValue.percent = processorIndex < threadUsage.percentByProcessor.size()
                ? threadUsage.percentByProcessor[processorIndex]
                : 0.0;
            threadValue.cores.push_back(coreValue);
        }
        viewSample.threads.push_back(std::move(threadValue));
        populatedThreadIds.insert(threadUsage.threadId);
    }

    // 生命周期 rundown 中已知但本区间未获调度的存活线程也保留为 0%，
    // 避免线程矩阵只列出“刚好运行过”的线程而让用户误以为线程已退出。
    for (const std::uint64_t identity : cpuCoreSnapshot->liveThreadIdentities)
    {
        const std::uint32_t processId = static_cast<std::uint32_t>(identity >> 32U);
        const std::uint32_t threadId = static_cast<std::uint32_t>(identity & 0xffffffffULL);
        if (processId != processRecord.pid ||
            threadId == 0 ||
            populatedThreadIds.find(threadId) != populatedThreadIds.end())
        {
            continue;
        }

        ProcessDetailWindow::ThreadCpuCoreValue threadValue;
        threadValue.threadId = threadId;
        threadValue.cores = viewSample.processCores;
        for (ProcessDetailWindow::CpuCoreValue& coreValue : threadValue.cores)
        {
            coreValue.percent = 0.0;
        }
        viewSample.threads.push_back(std::move(threadValue));
    }
    std::sort(
        viewSample.threads.begin(),
        viewSample.threads.end(),
        [](const ProcessDetailWindow::ThreadCpuCoreValue& left,
           const ProcessDetailWindow::ThreadCpuCoreValue& right)
        {
            if (left.cpuPercent != right.cpuPercent)
            {
                return left.cpuPercent > right.cpuPercent;
            }
            return left.threadId < right.threadId;
        });
    detailWindow->setCpuCoreViewSample(std::move(viewSample));
}

void ProcessDock::pruneProcessNetworkTrafficCounters()
{
    // 只保留当前仍存活的 PID，阻止抓包累计表随进程创建/退出次数永久增长。
    std::unordered_set<std::uint32_t> livePidSet;
    livePidSet.reserve(m_cacheByIdentity.size());
    for (const auto& cachePair : m_cacheByIdentity)
    {
        if (!cachePair.second.isExitedInLatestRound)
        {
            livePidSet.insert(cachePair.second.record.pid);
        }
    }

    if (m_processNetworkTrafficService != nullptr)
    {
        m_processNetworkTrafficService->PruneCounters(livePidSet);
    }
}

std::unordered_map<std::uint32_t, ProcessDock::NetworkTrafficCounters>
ProcessDock::snapshotProcessNetworkTrafficCounters() const
{
    // snapshotProcessNetworkTrafficCounters：
    // - 输入：无；
    // - 处理：向 ETW 累计器请求当前 PID 网络累计字节快照；
    // - 返回：刷新线程可安全读取的独立快照。
    std::unordered_map<std::uint32_t, NetworkTrafficCounters> snapshot;
    if (m_processNetworkTrafficService == nullptr)
    {
        return snapshot;
    }

    const auto etwSnapshot = m_processNetworkTrafficService->SnapshotCounters();
    snapshot.reserve(etwSnapshot.size());
    for (const auto& [processId, counters] : etwSnapshot)
    {
        snapshot.emplace(processId, NetworkTrafficCounters{ counters.rxBytes, counters.txBytes });
    }
    return snapshot;
}

bool ProcessDock::eventFilter(QObject* watched, QEvent* event)
{
    if (event == nullptr)
    {
        return QWidget::eventFilter(watched, event);
    }

    // 只处理左键按下：
    // - 鼠标释放/移动不改变选择；
    // - 右键仍保留上下文菜单的冻结选择语义。
    if (event->type() != QEvent::MouseButtonPress)
    {
        return QWidget::eventFilter(watched, event);
    }

    const QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
    if (mouseEvent == nullptr || mouseEvent->button() != Qt::LeftButton)
    {
        return QWidget::eventFilter(watched, event);
    }

    if (m_processTable == nullptr ||
        m_sideTabWidget == nullptr ||
        m_sideTabWidget->currentWidget() != m_processListPage ||
        m_contextMenuVisible ||
        !isVisible())
    {
        return QWidget::eventFilter(watched, event);
    }

    QWidget* watchedWidget = qobject_cast<QWidget*>(watched);
    if (watchedWidget == nullptr)
    {
        return QWidget::eventFilter(watched, event);
    }

    // 只响应当前 ProcessDock 内部点击，避免影响其它 Dock 或独立详情窗口。
    const bool clickedInsideThisDock = (watchedWidget == this) || isAncestorOf(watchedWidget);
    if (!clickedInsideThisDock)
    {
        return QWidget::eventFilter(watched, event);
    }

    // 表格空白区没有 item，点击这里也应视为“取消当前进程选择”。
    if (watchedWidget == m_processTable->viewport())
    {
        const QPoint viewportPosition = activityMousePosition(mouseEvent);
        if (!m_processTable->indexAt(viewportPosition).isValid())
        {
            clearProcessTableSelection();
        }
        return QWidget::eventFilter(watched, event);
    }

    // 表头、滚动条和真实单元格仍属于表格，不清空选择；其它控件/空白区域清空。
    const bool clickedInsideProcessTable =
        (watchedWidget == m_processTable) ||
        m_processTable->isAncestorOf(watchedWidget);
    if (!clickedInsideProcessTable)
    {
        clearProcessTableSelection();
    }

    return QWidget::eventFilter(watched, event);
}

void ProcessDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    // 首次显示或重新回到可见状态时，把搜索焦点交给进程搜索框：
    // - 用户切到该页面后可以直接键入搜索词；
    // - 不要求先手动点击搜索框。
    if (m_sideTabWidget != nullptr && m_sideTabWidget->currentWidget() == m_processListPage)
    {
        focusProcessSearchBox(true);
    }

    if (m_initialRefreshScheduled)
    {
        return;
    }

    // 首次进入进程页时立即开始异步刷新：
    // - 不在主窗口启动阶段枚举，只有用户真正切到页面后才启动；
    // - 与“开始刷新”按钮采用同一套周期监视与活动记录状态；
    // - 强制首轮刷新不等待定时器间隔，避免用户看到空表。
    m_initialRefreshScheduled = true;
    m_monitoringEnabled = true;
    m_activityRecordingEnabled = true;
    if (m_activitySamples.empty())
    {
        m_activityRecordingStartTick100ns = steadyNow100ns();
        m_activityNextSequence = 0;
    }
    m_activityTimelinePinnedToLatest = true;
    m_activityTableSnapshotIndex = -1;
    m_activityTableSnapshotRecords.clear();
    updateProcessActivityStatusLabel();
    requestAsyncRefresh(true);

    // showEvent 内部阶段列表页的 isVisible() 可能尚未稳定，延迟到事件循环首轮再启动周期计时器。
    QTimer::singleShot(0, this, [this]() {
        if (m_refreshTimer != nullptr && isProcessActivityRefreshAllowedNow())
        {
            m_refreshTimer->start(refreshIntervalMillisecondsFromInput());
        }
        updateProcessActivityStatusLabel();
    });
}

bool ProcessDock::invokeMainWindowPidListSlot(const char* methodName, const QString& pidListText) const
{
    QObject* receiver = mainWindowActionReceiver();
    if (receiver == nullptr || pidListText.trimmed().isEmpty())
    {
        return false;
    }
    return QMetaObject::invokeMethod(
        receiver,
        methodName,
        Qt::QueuedConnection,
        Q_ARG(QString, pidListText));
}

void ProcessDock::connectDetailWindowNavigation(ProcessDetailWindow* detailWindow)
{
    if (detailWindow == nullptr)
    {
        return;
    }
    if (m_monitoringEnabled)
    {
        // 详情窗口出现即开始首个采样区间，避免用户进入 CPU 核心页后再多等一轮。
        ensureCpuCoreUsageCaptureStarted();
    }
    synchronizeDetailWindowPerformanceHistory(detailWindow, detailWindow->identityKey());
    const auto coreRecordIt = m_cacheByIdentity.find(detailWindow->identityKey());
    if (coreRecordIt != m_cacheByIdentity.end())
    {
        syncCpuCoreUsageToDetailWindow(detailWindow, coreRecordIt->second.record);
    }
    else
    {
        ks::process::ProcessRecord fallbackRecord{};
        fallbackRecord.pid = detailWindow->pid();
        syncCpuCoreUsageToDetailWindow(detailWindow, fallbackRecord);
    }
    connect(detailWindow, &ProcessDetailWindow::requestOpenMemoryDockByPid, this,
        [this](const std::uint32_t targetPid) {
            (void)invokeMainWindowPidSlot("focusMemoryDockByPid", targetPid);
        });
    connect(detailWindow, &ProcessDetailWindow::requestOpenNetworkDockByPid, this,
        [this](const std::uint32_t targetPid) {
            (void)invokeMainWindowPidListSlot("focusNetworkDockByPids", QString::number(targetPid));
        });
    connect(detailWindow, &ProcessDetailWindow::requestOpenWindowDockByPid, this,
        [this](const std::uint32_t targetPid) {
            (void)invokeMainWindowPidListSlot("focusWindowDockByPids", QString::number(targetPid));
        });
    connect(detailWindow, &ProcessDetailWindow::requestOpenFileDetailByPath, this,
        [this](const QString& filePath) {
            QObject* const receiver = mainWindowActionReceiver();
            const bool invokeOk = receiver != nullptr &&
                QMetaObject::invokeMethod(
                    receiver,
                    "openFileDetailDockByPath",
                    Qt::QueuedConnection,
                    Q_ARG(QString, filePath));
            if (!invokeOk)
            {
                kLogEvent logEvent;
                warn << logEvent
                    << "[ProcessDock] requestOpenFileDetailByPath 转发失败, path="
                    << filePath.toStdString()
                    << eol;
            }
        });
}

void ProcessDock::refreshThemeVisuals()
{
    // 仅重建当前表格可视层，不触发新的后台枚举任务。
    // 用途：深浅色切换后，立即刷新“新增/退出”行的主题高亮色。
    applyBlueComboBoxRuntimeStyle(m_viewModeCombo);
    updateThreadColumnPresetButtons();
    rebuildTable();
    rebuildThreadTable();
}

void ProcessDock::initializeUi()
{
    // 根布局只容纳一个顶部 tab 控件。
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(0, 0, 0, 0);
    m_rootLayout->setSpacing(0);

    m_sideTabWidget = new QTabWidget(this);
    m_sideTabWidget->setTabPosition(QTabWidget::North);
    m_sideTabWidget->setDocumentMode(true);
    m_sideTabWidget->setIconSize(SideTabIconSize);

    // 顶部页签使用内容自适应宽度，避免固定宽度导致不同字号/语言下被截断。
    // 页签字号不在局部 QSS 中设置，统一继承 Qt 默认应用字号。
    if (m_sideTabWidget->tabBar() != nullptr)
    {
        m_sideTabWidget->tabBar()->setExpanding(false);
        m_sideTabWidget->tabBar()->setUsesScrollButtons(true);
        m_sideTabWidget->tabBar()->setStyleSheet(QStringLiteral(
            "QTabBar{background:transparent;border:none;}"
            "QTabBar::tab{min-height:%1px;padding:3px 12px;margin:0px;border:none;border-radius:0px;}"
            "QTabBar::tab:selected{background-color:%2;color:%5;font-weight:700;}"
            "QTabBar::tab:hover:!selected{background-color:%3;color:%4;}" )
            .arg(ProcessTabMinHeightPx)
            .arg(KswordTheme::PrimaryBlueHex)
            // 悬停底色没有蓝色系的动态角色可用，退回中性 alternate-base，
            // 保证深浅色切换时不会残留旧主题的浅蓝方块。
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(QStringLiteral("palette(highlighted-text)")));
    }

    // “进程列表”页是本模块核心页面。
    m_processListPage = new QWidget(this);
    m_processPageLayout = new QVBoxLayout(m_processListPage);
    m_processPageLayout->setContentsMargins(6, 6, 6, 6);
    m_processPageLayout->setSpacing(6);

    // 初始化上方控制栏和下方表格。
    initializeTopControls();
    initializeProcessActivityPanel();
    initializeProcessTable();
    initializeThreadPage();
    initializeCrossViewPage();
    initializeCreateProcessPage();

    m_rootLayout->addWidget(m_sideTabWidget);
}

void ProcessDock::initializeTopControls()
{
    // 控制区改为“两行布局”：第一行放操作按钮，第二行单独放监控状态。
    QVBoxLayout* controlContainerLayout = new QVBoxLayout();
    controlContainerLayout->setContentsMargins(0, 0, 0, 0);
    controlContainerLayout->setSpacing(4);

    m_controlLayout = new QHBoxLayout();
    m_controlLayout->setContentsMargins(0, 0, 0, 0);
    m_controlLayout->setSpacing(8);
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();

    // 树状视图：勾选时按父子关系构建树；默认关闭以展示应用/后台/系统分类。
    m_treeViewCheck = new QCheckBox(QStringLiteral("树状视图"), this);
    m_treeViewCheck->setChecked(false);
    m_treeViewCheck->setToolTip(QStringLiteral("勾选后按父子关系显示进程。未勾选时按应用、后台进程和 Windows 进程分类；搜索或查看历史活动快照时自动使用扁平结果。"));
    languageManager.bindText(
        m_treeViewCheck,
        QStringLiteral("process.toolbar.friendly"),
        QStringLiteral("树状视图"));
    languageManager.bindToolTip(
        m_treeViewCheck,
        QStringLiteral("process.tooltip.friendly"),
        QStringLiteral("勾选后按父子关系显示进程。未勾选时按应用、后台进程和 Windows 进程分类；搜索或查看历史活动快照时自动使用扁平结果。"));

    // 视图模式下拉框：默认监视视图。
    // 项由 rebuildViewModeComboItems 统一生成：内置预设在前，用户自定义视图追加在后。
    m_viewModeCombo = new QComboBox(this);
    m_viewModeCombo->setObjectName(QStringLiteral("ProcessDockViewModeCombo"));
    loadCustomViewsFromSettings();
    rebuildViewModeComboItems();
    m_viewModeCombo->setToolTip("切换列视图预设；可在“选择列”里把当前列保存为自定义视图。");
    languageManager.bindToolTip(
        m_viewModeCombo,
        QStringLiteral("process.tooltip.view_mode"),
        QStringLiteral("切换列视图预设；可在“选择列”里把当前列保存为自定义视图。"));
    m_viewModeCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_viewModeCombo->setMinimumContentsLength(8);
    m_viewModeCombo->setMaximumWidth(180);

    applyBlueComboBoxRuntimeStyle(m_viewModeCombo);

    // 开始/暂停按钮：按需求仅显示图标。
    m_startButton = new QPushButton(QIcon(IconStart), "", this);
    m_pauseButton = new QPushButton(QIcon(IconPause), "", this);
    KswordTheme::ApplyCompactIconButtonMetrics(m_startButton);
    KswordTheme::ApplyCompactIconButtonMetrics(m_pauseButton);
    m_startButton->setToolTip("开始周期性刷新进程列表，并同步记录进程活动");
    m_pauseButton->setToolTip("暂停周期性刷新进程列表，并同步停止记录");
    languageManager.bindToolTip(
        m_startButton,
        QStringLiteral("process.tooltip.start"),
        QStringLiteral("开始周期性刷新进程列表，并同步记录进程活动"));
    languageManager.bindToolTip(
        m_pauseButton,
        QStringLiteral("process.tooltip.pause"),
        QStringLiteral("暂停周期性刷新进程列表，并同步停止记录"));

    // 统一刷新间隔同时驱动后台枚举、活动采样和表格重绘。
    m_refreshLabel = new QLabel("刷新间隔:", this);
    languageManager.bindText(m_refreshLabel, QStringLiteral("process.label.refresh_interval"), QStringLiteral("刷新间隔:"));
    m_refreshIntervalSpin = new QDoubleSpinBox(this);
    m_refreshIntervalSpin->setDecimals(1);
    m_refreshIntervalSpin->setRange(
        static_cast<double>(ActivityMinimumIntervalMilliseconds) / 1000.0,
        static_cast<double>(ActivityMaximumIntervalMilliseconds) / 1000.0);
    m_refreshIntervalSpin->setSingleStep(0.5);
    m_refreshIntervalSpin->setSuffix(QStringLiteral(" s"));
    m_refreshIntervalSpin->setValue(1.0);
    m_refreshIntervalSpin->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    m_refreshIntervalSpin->setKeyboardTracking(false);
    m_refreshIntervalSpin->setToolTip("同时控制进程刷新、活动采样和列表更新，可调 0.5~60 秒，默认 1 秒；间隔越小系统枚举开销越大。");
    languageManager.bindToolTip(
        m_refreshIntervalSpin,
        QStringLiteral("process.tooltip.sample_interval"),
        QStringLiteral("同时控制进程刷新、活动采样和列表更新，可调 0.5~60 秒，默认 1 秒；间隔越小系统枚举开销越大。"));

    // 进程搜索框：
    // - 直接基于当前缓存做本地过滤，不额外触发系统查询；
    // - 切到“进程列表”页后会自动聚焦，支持直接键入搜索词。
    m_processSearchLineEdit = new QLineEdit(this);
    m_processSearchLineEdit->setClearButtonEnabled(true);
    m_processSearchLineEdit->setPlaceholderText("搜索 PID / 名称 / 路径 / 命令行 / 用户");
    m_processSearchLineEdit->setToolTip("切到进程列表页后可直接输入搜索词");
    languageManager.bindPlaceholder(
        m_processSearchLineEdit,
        QStringLiteral("process.placeholder.search"),
        QStringLiteral("搜索 PID / 名称 / 路径 / 命令行 / 用户"));
    languageManager.bindToolTip(
        m_processSearchLineEdit,
        QStringLiteral("process.tooltip.search"),
        QStringLiteral("切到进程列表页后可直接输入搜索词"));
    m_processSearchLineEdit->setStyleSheet(buildBlueLineEditStyle());
    m_processSearchLineEdit->setMaximumWidth(320);

    // “选择列”入口：
    // - 列集合已经对齐任务管理器“详细信息”页，仅靠表头右键逐列勾选不便于批量增减；
    // - 这里提供与任务管理器一致的显式入口，表头右键菜单里也保留同名项。
    m_columnChooserButton = new QPushButton(QStringLiteral("选择列"), this);
    m_columnChooserButton->setToolTip(QStringLiteral("添加或移除进程列表中显示的列。"));
    languageManager.bindText(
        m_columnChooserButton,
        QStringLiteral("process.toolbar.column_chooser"),
        QStringLiteral("选择列"));
    languageManager.bindToolTip(
        m_columnChooserButton,
        QStringLiteral("process.tooltip.column_chooser"),
        QStringLiteral("添加或移除进程列表中显示的列。"));
    m_columnChooserButton->setStyleSheet(buildBlueButtonStyle(false));

    // 按钮统一蓝色风格（图标按钮版本）。
    const QString buttonStyle = buildBlueButtonStyle(true);
    m_startButton->setStyleSheet(buttonStyle);
    m_pauseButton->setStyleSheet(buttonStyle);

    // 第一行放“操作按钮 + 刷新间隔”。
    m_controlLayout->addWidget(m_treeViewCheck);
    m_controlLayout->addWidget(m_viewModeCombo);
    m_controlLayout->addWidget(m_startButton);
    m_controlLayout->addWidget(m_pauseButton);
    m_controlLayout->addWidget(m_columnChooserButton);
    m_controlLayout->addWidget(m_processSearchLineEdit);
    m_controlLayout->addStretch(1);
    m_controlLayout->addWidget(m_refreshLabel);
    m_controlLayout->addWidget(m_refreshIntervalSpin);
    controlContainerLayout->addLayout(m_controlLayout);
    m_processPageLayout->addLayout(controlContainerLayout);
}

void ProcessDock::initializeProcessActivityPanel()
{
    // 活动面板放在进程表上方：
    // - 不额外枚举进程，只消费每轮刷新后的 m_cacheByIdentity；
    // - 图表、时间轴和快照共享同一份有界样本缓存。
    m_activityPanelWidget = new QWidget(m_processListPage);
    m_activityPanelWidget->setObjectName(QStringLiteral("processActivityPanelWidget"));
    m_activityPanelWidget->setAutoFillBackground(false);
    m_activityPanelWidget->setAttribute(Qt::WA_StyledBackground, true);
    m_activityPanelWidget->setStyleSheet(QStringLiteral(
        "QWidget#processActivityPanelWidget {"
        "  background:transparent;"
        "  background-color:transparent;"
        "  border:1px solid %1;"
        "  border-radius:4px;"
        "}")
        .arg(KswordTheme::BorderHex()));
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();

    QVBoxLayout* panelLayout = new QVBoxLayout(m_activityPanelWidget);
    panelLayout->setContentsMargins(6, 6, 6, 6);
    panelLayout->setSpacing(5);

    m_activityClearButton = new QPushButton(QStringLiteral("清空"), m_activityPanelWidget);
    m_activityClearButton->setToolTip(QStringLiteral("清空当前刷新同步记录的进程活动样本。"));
    languageManager.bindText(m_activityClearButton, QStringLiteral("process.activity.clear"), QStringLiteral("清空"));
    languageManager.bindToolTip(
        m_activityClearButton,
        QStringLiteral("process.activity.tooltip.clear"),
        QStringLiteral("清空当前刷新同步记录的进程活动样本。"));
    m_activityClearButton->setStyleSheet(buildBlueButtonStyle(false));

    m_activityListOnlyRefreshCheck = new QCheckBox(QStringLiteral("不记录历史"), m_activityPanelWidget);
    m_activityListOnlyRefreshCheck->setToolTip(QStringLiteral("勾选后周期刷新仍会更新进程列表，但不会向上方时间轴写入新的活动记录。"));
    languageManager.bindText(
        m_activityListOnlyRefreshCheck,
        QStringLiteral("process.activity.list_only"),
        QStringLiteral("不记录历史"));
    languageManager.bindToolTip(
        m_activityListOnlyRefreshCheck,
        QStringLiteral("process.activity.tooltip.list_only"),
        QStringLiteral("勾选后周期刷新仍会更新进程列表，但不会向上方时间轴写入新的活动记录。"));

    const QString metricButtonStyle = QStringLiteral(
        "QPushButton {"
        "  color:%1;"
        "  background:%2;"
        "  border:1px solid %3;"
        "  border-radius:3px;"
        "  padding:3px 8px;"
        "}"
        "QPushButton:checked {"
        "  color:%5;"
        "  background:%4;"
        "  border:1px solid %4;"
        "}"
        "QPushButton:hover {"
        "  border:1px solid %4;"
        "}")
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::BorderHex())
        .arg(KswordTheme::PrimaryBlueHex)
        .arg(QStringLiteral("palette(highlighted-text)"));

    // 指标按钮必须可独立开关：
    // - 默认全部点亮，用户打开页面即可看到 CPU/内存/磁盘/网络/GPU 全部曲线；
    // - 后续可以按需关闭单项指标，避免曲线过密。
    auto createMetricButton =
        [this, &metricButtonStyle](const QString& text, const bool checkedByDefault)
        {
            QPushButton* button = new QPushButton(text, m_activityPanelWidget);
            button->setCheckable(true);
            button->setChecked(checkedByDefault);
            button->setStyleSheet(metricButtonStyle);
            button->setToolTip(QStringLiteral("切换该指标是否绘制在上方百分比折线图中。"));
            return button;
        };
    m_activityCpuButton = createMetricButton(QStringLiteral("CPU"), true);
    m_activityMemoryButton = createMetricButton(QStringLiteral("内存"), true);
    m_activityDiskButton = createMetricButton(QStringLiteral("磁盘"), true);
    m_activityNetworkButton = createMetricButton(QStringLiteral("网络"), true);
    m_activityGpuButton = createMetricButton(QStringLiteral("GPU"), true);
    languageManager.bindText(m_activityCpuButton, QStringLiteral("process.activity.metric.cpu"), QStringLiteral("CPU"));
    languageManager.bindText(m_activityMemoryButton, QStringLiteral("process.activity.metric.memory"), QStringLiteral("内存"));
    languageManager.bindText(m_activityDiskButton, QStringLiteral("process.activity.metric.disk"), QStringLiteral("磁盘"));
    languageManager.bindText(m_activityNetworkButton, QStringLiteral("process.activity.metric.network"), QStringLiteral("网络"));
    languageManager.bindText(m_activityGpuButton, QStringLiteral("process.activity.metric.gpu"), QStringLiteral("GPU"));
    for (QPushButton* metricButton : {
             m_activityCpuButton,
             m_activityMemoryButton,
             m_activityDiskButton,
             m_activityNetworkButton,
             m_activityGpuButton })
    {
        languageManager.bindToolTip(
            metricButton,
            QStringLiteral("process.activity.tooltip.metric"),
            QStringLiteral("切换该指标是否绘制在上方百分比折线图中。"));
    }

    // 准星按钮放在“网络/GPU”等时间轴指标按钮右侧：
    // - 交互与窗口页拾取按钮一致，必须按住拖到目标窗口后松开；
    // - 释放后不打开窗口详情，而是按目标窗口所属 PID 过滤进程列表并打开进程详情。
    ProcessWindowPickerDragButton* processPickerButton = new ProcessWindowPickerDragButton(m_activityPanelWidget);
    processPickerButton->setIcon(QIcon(IconWindowPickerTarget));
    KswordTheme::ApplyCompactIconButtonMetrics(processPickerButton);
    processPickerButton->setStyleSheet(buildBlueButtonStyle(true));
    processPickerButton->setToolTip(QStringLiteral("按住并拖拽准星到目标窗口，松开后按该窗口 PID 筛选进程并打开进程详细信息"));
    languageManager.bindToolTip(
        processPickerButton,
        QStringLiteral("process.activity.tooltip.picker"),
        QStringLiteral("按住并拖拽准星到目标窗口，松开后按该窗口 PID 筛选进程并打开进程详细信息"));
    processPickerButton->setReleaseCallback([this](const QPoint& globalPos) {
        handleProcessWindowPickerRelease(globalPos);
    });
    m_activityProcessPickerButton = processPickerButton;

    QLabel* activityDisplayLabel = new QLabel(QStringLiteral("显示:"), m_activityPanelWidget);
    languageManager.bindText(
        activityDisplayLabel,
        QStringLiteral("process.activity.display"),
        QStringLiteral("显示:"));
    // 将活动控制项放到顶部搜索框之后，图表面板只保留图表本身。
    int topControlInsertIndex = m_controlLayout->indexOf(m_processSearchLineEdit) + 1;
    for (QWidget* const controlWidget : {
             static_cast<QWidget*>(m_activityClearButton),
             static_cast<QWidget*>(m_activityListOnlyRefreshCheck),
             static_cast<QWidget*>(activityDisplayLabel),
             static_cast<QWidget*>(m_activityCpuButton),
             static_cast<QWidget*>(m_activityMemoryButton),
             static_cast<QWidget*>(m_activityDiskButton),
             static_cast<QWidget*>(m_activityNetworkButton),
             static_cast<QWidget*>(m_activityGpuButton),
             static_cast<QWidget*>(m_activityProcessPickerButton) })
    {
        m_controlLayout->insertWidget(topControlInsertIndex++, controlWidget);
    }

    m_activityChartWidget = new ProcessActivityChartWidget(this, m_activityPanelWidget);
    m_activityChartWidget->setToolTip(QString());

    m_activityTimelineSlider = new ProcessActivityTimelineSlider(this, m_activityPanelWidget);
    m_activityTimelineSlider->setRange(0, 0);
    m_activityTimelineSlider->setValue(0);
    m_activityTimelineSlider->setVisible(false);

    // 快照说明曾经用于展示折线图当前采样点的长文本，但会挤占进程列表空间。
    // 现在保留对象指针给旧逻辑判空使用，同时不加入布局、不显示文本。
    m_activitySnapshotLabel = new QLabel(m_activityPanelWidget);
    m_activitySnapshotLabel->setVisible(false);
    m_activitySnapshotLabel->setWordWrap(false);
    m_activitySnapshotLabel->setMinimumHeight(0);
    m_activitySnapshotLabel->setMaximumHeight(0);
    m_activitySnapshotLabel->setTextInteractionFlags(Qt::NoTextInteraction);
    m_activitySnapshotLabel->setStyleSheet(QStringLiteral(
        "QLabel {"
        "  color:%1;"
        "  background:transparent;"
        "  background-color:transparent;"
        "  border:1px solid %2;"
        "  border-radius:3px;"
        "  padding:4px;"
        "}")
        .arg(KswordTheme::TextSecondaryHex())
        .arg(KswordTheme::BorderHex()));

    panelLayout->addWidget(m_activityChartWidget);
    m_processPageLayout->addWidget(m_activityPanelWidget, 0);
}

void ProcessDock::handleProcessWindowPickerRelease(const QPoint& globalPos)
{
    // 该函数是进程页准星拾取的业务入口：
    // - 命中逻辑与窗口页保持一致，先拿鼠标下窗口，再回退到根窗口；
    // - 结果不进入窗口详情，而是转成 PID 过滤和进程详情。
    kLogEvent pickEvent;
    info << pickEvent
        << "[ProcessDock] 进程准星拾取释放, x="
        << globalPos.x()
        << ", y="
        << globalPos.y()
        << eol;

    POINT nativePoint{};
    nativePoint.x = globalPos.x();
    nativePoint.y = globalPos.y();

    // rawWindowHandle 是鼠标下最细粒度窗口；rootWindowHandle 用于顶级窗口回退。
    HWND rawWindowHandle = ::WindowFromPoint(nativePoint);
    HWND rootWindowHandle = rawWindowHandle != nullptr ? ::GetAncestor(rawWindowHandle, GA_ROOT) : nullptr;
    HWND targetWindowHandle = rawWindowHandle != nullptr ? rawWindowHandle : rootWindowHandle;
    if (targetWindowHandle == nullptr || ::IsWindow(targetWindowHandle) == FALSE)
    {
        warn << pickEvent
            << "[ProcessDock] 进程准星拾取失败：WindowFromPoint 未命中有效窗口。"
            << eol;
        QMessageBox::information(
            this,
            QStringLiteral("进程拾取"),
            QStringLiteral("未命中可用窗口，请重试。"));
        return;
    }

    // 优先解析原始窗口 PID；异常时再用根窗口 PID 兜底，贴近窗口页拾取体验。
    DWORD targetPid = 0;
    DWORD targetTid = ::GetWindowThreadProcessId(targetWindowHandle, &targetPid);
    if ((targetPid == 0 || targetTid == 0) && rootWindowHandle != nullptr && rootWindowHandle != targetWindowHandle)
    {
        targetWindowHandle = rootWindowHandle;
        targetPid = 0;
        targetTid = ::GetWindowThreadProcessId(targetWindowHandle, &targetPid);
    }

    const quint64 targetHwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(targetWindowHandle));
    if (targetPid == 0)
    {
        warn << pickEvent
            << "[ProcessDock] 进程准星拾取失败：无法解析目标窗口 PID, hwnd=0x"
            << std::hex
            << targetHwndValue
            << std::dec
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("进程拾取"),
            QStringLiteral("无法读取目标窗口所属进程 PID。"));
        return;
    }

    // 切回实时表格：用户拖窗口定位的是当前系统进程，历史快照表格不应继续覆盖实时列表。
    m_activityTimelinePinnedToLatest = true;
    m_activityTableSnapshotIndex = -1;
    m_activityTableSnapshotRecords.clear();
    if (m_activityTimelineSlider != nullptr && !m_activitySamples.empty())
    {
        const bool oldUpdating = m_activityTimelineSliderUpdating;
        m_activityTimelineSliderUpdating = true;
        m_activityTimelineSlider->setValue(static_cast<int>(m_activitySamples.size()) - 1);
        m_activityTimelineSliderUpdating = oldUpdating;
    }

    // 设置进程列表筛选器为 PID：
    // - 直接写入顶部搜索框，复用现有过滤逻辑和 UI 可见状态；
    // - blockSignals 后手动 rebuild，避免历史状态切换时重复重建。
    if (m_processSearchLineEdit != nullptr)
    {
        QSignalBlocker blocker(m_processSearchLineEdit);
        m_processSearchLineEdit->setText(QStringLiteral("pid:%1").arg(static_cast<qulonglong>(targetPid)));
    }
    // 优先把目标 PID 对应行设为重建后的当前行，筛选后用户能直接看到定位结果。
    m_trackedSelectedIdentityKey.clear();
    m_trackedSelectedIdentityKeys.clear();
    for (const auto& cachePair : m_cacheByIdentity)
    {
        if (cachePair.second.record.pid == targetPid)
        {
            m_trackedSelectedIdentityKey = cachePair.first;
            m_trackedSelectedIdentityKeys.push_back(cachePair.first);
            break;
        }
    }
    rebuildTable();
    updateProcessActivityStatusLabel();

    info << pickEvent
        << "[ProcessDock] 进程准星拾取成功, hwnd=0x"
        << std::hex
        << targetHwndValue
        << std::dec
        << ", pid="
        << targetPid
        << ", tid="
        << targetTid
        << "，已设置进程列表筛选器并打开进程详情。"
        << eol;
    openProcessDetailWindowByPid(static_cast<std::uint32_t>(targetPid));
}

void ProcessDock::initializeProcessTable()
{
    // 进程列表迁移到 QTableView + FlatTableModel：
    // - 行数据只保存在模型的轻量 ProcessTableRow 中；
    // - 每轮刷新通过稳定行键增量发布删除/插入/重排/数据变化，避免 reset 整张表；
    // - 树状视图仍通过 Name 列缩进文本模拟，保持旧外观和交互语义。
    // 列表头文本、i18n 键与 TableColumn 枚举必须严格一一对应，否则整张表的列会错位。
    // TableColumn 是私有嵌套枚举，无法在表定义处做编译期断言，这里在启动路径上兜底自检。
    if (ProcessTableHeaders.size() != static_cast<int>(TableColumn::Count) ||
        ProcessTableHeaderKeyCount != static_cast<std::size_t>(TableColumn::Count))
    {
        kLogEvent logEvent;
        err << logEvent
            << "[ProcessDock] 列定义不一致：headerTextCount=" << ProcessTableHeaders.size()
            << ", headerKeyCount=" << ProcessTableHeaderKeyCount
            << ", columnCount=" << static_cast<int>(TableColumn::Count)
            << eol;
    }

    m_processTable = new ks::ui::TableActionTableView(this);
    // 进程表刷新频率和行数都较高：
    // - 禁用 MainWindow 全局 smooth-scroll 接管，避免滚轮事件被 QPropertyAnimation 重写；
    // - 保持 QTableView/滚动条默认滚动手感，不额外添加惯性或延迟；
    // - 返回行为：仅设置 Qt 动态属性，无其它副作用。
    m_processTable->setProperty("ksword_disable_smooth_scroll", true);
    if (m_processTable->viewport() != nullptr)
    {
        m_processTable->viewport()->setProperty("ksword_disable_smooth_scroll", true);
    }

    std::vector<ProcessTableModel::ColumnSpec> columnSpecs;
    columnSpecs.reserve(static_cast<std::size_t>(TableColumn::Count));
    for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::Count); ++columnIndex)
    {
        ProcessTableModel::ColumnSpec columnSpec{};
        columnSpec.headerText = ProcessTableHeaders.at(columnIndex);
        columnSpec.alignment = (columnIndex == toColumnIndex(TableColumn::IsAdmin))
            ? (Qt::AlignCenter | Qt::AlignVCenter)
            : (Qt::AlignLeft | Qt::AlignVCenter);
        columnSpecs.push_back(std::move(columnSpec));
    }
    m_processTableModel = new ProcessTableModel(
        std::move(columnSpecs),
        [this](const ProcessTableRow& tableRow, const int column, const int role) -> QVariant
        {
            return processTableData(tableRow, column, role);
        },
        this,
        [](const ProcessTableRow& tableRow, const int) -> Qt::ItemFlags
        {
            // Inputs: one ProcessTableRow and the requested column.
            // Processing: group headers are display-only; application aggregates are selectable batch targets.
            // Return: item flags used by Qt selection and context menu targeting.
            return tableRow.rowKind == ProcessDock::ProcessTableRowKind::GroupHeader
                ? Qt::ItemIsEnabled
                : (Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        },
        [](const ProcessTableRow& tableRow) -> std::string
        {
            if (tableRow.rowKind == ProcessDock::ProcessTableRowKind::Process)
            {
                return std::string("process:") + tableRow.identityKey;
            }
            return std::string("synthetic:")
                + std::to_string(static_cast<int>(tableRow.rowKind))
                + ":"
                + tableRow.expansionKey.toUtf8().toStdString();
        });
    m_processSortProxy = new ProcessTableSortProxy(this);
    m_processSortProxy->setSourceModel(m_processTableModel);
    static_cast<ProcessTableSortProxy*>(m_processSortProxy)->setHeaderTexts(ProcessTableHeaders);
    m_processTable->setModel(m_processSortProxy);

    m_processTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    // 选择模式：
    // - 普通左键仍保持单行焦点；
    // - 按住 Ctrl 左键点击时由 Qt 进入复选式多选/取消选择；
    // - 右键菜单会读取所有已选行并批量执行动作。
    m_processTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_processTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // “CPU 核心”列会按真实逻辑处理器数量保留完整内容宽度：
    // - 表格水平方向忽略内容 sizeHint，避免列宽经页面布局反向撑大 ProcessDock；
    // - 超出 viewport 的列统一交给表格底部横向滚动条，不压缩逐核心扇形。
    m_processTable->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
    m_processTable->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    m_processTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_processTable->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    // 按像素滚动可让滚轮和触控板事件在到达时立刻推进 viewport，
    // 避免固定行高表格把输入聚合为较大的逐项跳动。
    m_processTable->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_processTable->setSortingEnabled(true);
    m_processTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_processTable->setAlternatingRowColors(true);
    m_processTable->setItemDelegate(new ProcessRowHighlightDelegate(
        m_processTable,
        toColumnIndex(TableColumn::CpuCore)));
    m_processTable->setProperty("ksword_preserve_custom_table_delegate", true);
    m_processTable->setShowGrid(false);
    m_processTable->setWordWrap(false);
    m_processTable->setCornerButtonEnabled(false);
    // 全局 TableColumnAutoFit 会在首次显示/尺寸变化时尽量把普通列压入 viewport；
    // 逐核心列或用户手动拖宽后的溢出宽度由上面的按需横向滚动承接。
    if (QScrollBar* verticalScrollBar = m_processTable->verticalScrollBar())
    {
        verticalScrollBar->setProperty("ksword_disable_smooth_scroll", true);
        verticalScrollBar->setSingleStep(12);
    }
    if (QScrollBar* horizontalScrollBar = m_processTable->horizontalScrollBar())
    {
        horizontalScrollBar->setProperty("ksword_disable_smooth_scroll", true);
    }

    // 表头支持拖动、右键显示/隐藏列。
    if (QHeaderView* verticalHeader = m_processTable->verticalHeader())
    {
        verticalHeader->setVisible(false);
        verticalHeader->setSectionResizeMode(QHeaderView::Fixed);
        verticalHeader->setDefaultSectionSize(24);
    }
    QHeaderView* headerView = m_processTable->horizontalHeader();
    headerView->setSectionsMovable(true);
    headerView->setStretchLastSection(false);
    headerView->setContextMenuPolicy(Qt::CustomContextMenu);
    headerView->setStyleSheet(QStringLiteral(
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

    // 列布局配置必须在首次套用视图预设之前读入：
    // applyViewMode 会在铺完预设后叠加用户覆盖，顺序反了会让自定义列在启动时被冲掉。
    loadProcessColumnLayoutFromSettings();

    applyDefaultColumnWidths();
    applyViewMode(ViewMode::Monitor);
    m_lastProcessDetailDemandFlags = currentProcessDetailDemandFlags();
    applyAdaptiveColumnWidths();
    m_processPageLayout->addWidget(m_processTable, 1);

    // 满足需求 3.1：侧边栏 Tab 中包含“进程列表”页签。
    m_sideTabWidget->addTab(m_processListPage, blueTintedIcon(IconProcessMain), "进程列表");
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget,
        m_processListPage,
        QStringLiteral("process.tab.list"),
        QStringLiteral("进程列表"));
    m_sideTabWidget->setCurrentIndex(0);
    refreshSideTabIconContrast();
}

void ProcessDock::initializeCreateProcessPage()
{
    m_createProcessPage = new QWidget(this);
    applyTransparentContainerStyle(m_createProcessPage);
    m_createProcessPageLayout = new QVBoxLayout(m_createProcessPage);
    m_createProcessPageLayout->setContentsMargins(6, 6, 6, 6);
    m_createProcessPageLayout->setSpacing(6);

    QScrollArea* scrollArea = new QScrollArea(m_createProcessPage);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    applyTransparentContainerStyle(scrollArea);
    m_createProcessPageLayout->addWidget(scrollArea, 1);

    QWidget* contentWidget = new QWidget(scrollArea);
    applyTransparentContainerStyle(contentWidget);
    QVBoxLayout* contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setContentsMargins(2, 2, 2, 2);
    contentLayout->setSpacing(8);
    scrollArea->setWidget(contentWidget);

    const QString inputStyle = buildBlueLineEditStyle();
    const QString comboStyle = buildBlueComboBoxStyle();
    const QString buttonStyle = buildBlueButtonStyle(false);

    // 每次重建页面前先清空位标志复选框缓存，避免重复初始化导致悬空指针。
    m_creationFlagChecks.clear();
    m_startupFlagChecks.clear();
    m_startupFillAttributeChecks.clear();
    m_tokenDesiredAccessChecks.clear();

    // buildBitmaskCheckGroup 作用：
    // - 根据“标志定义列表”自动生成复选框分组；
    // - 每个复选框通过 Qt Property 保存 flagValue/flagName，后续可统一做组合计算。
    const auto buildBitmaskCheckGroup =
        [](
            QWidget* parentWidget,
            const QString& groupTitle,
            const std::vector<BitmaskFlagDefinition>& definitionList,
            std::vector<QCheckBox*>* outputCheckBoxList) -> QGroupBox*
    {
        QGroupBox* groupBox = new QGroupBox(groupTitle, parentWidget);
        applyTransparentContainerStyle(groupBox);
        QGridLayout* groupLayout = new QGridLayout(groupBox);
        groupLayout->setContentsMargins(6, 6, 6, 6);
        groupLayout->setHorizontalSpacing(10);
        groupLayout->setVerticalSpacing(4);

        const int columnCount = 3;
        for (std::size_t index = 0; index < definitionList.size(); ++index)
        {
            const BitmaskFlagDefinition& definition = definitionList[index];
            QCheckBox* flagCheck = new QCheckBox(QString::fromUtf8(definition.nameText), groupBox);
            flagCheck->setProperty("flagValue", static_cast<qulonglong>(definition.value));
            flagCheck->setProperty("flagName", QString::fromUtf8(definition.nameText));
            flagCheck->setToolTip(
                QStringLiteral("%1\n值: 0x%2\n说明: %3")
                .arg(QString::fromUtf8(definition.nameText))
                .arg(QString::number(static_cast<qulonglong>(definition.value), 16).toUpper())
                .arg(QString::fromUtf8(definition.descriptionText)));

            const int row = static_cast<int>(index / static_cast<std::size_t>(columnCount));
            const int col = static_cast<int>(index % static_cast<std::size_t>(columnCount));
            groupLayout->addWidget(flagCheck, row, col);

            if (outputCheckBoxList != nullptr)
            {
                outputCheckBoxList->push_back(flagCheck);
            }
        }
        return groupBox;
    };

    // 1) 创建方式 + 令牌来源配置。
    QGroupBox* methodGroup = new QGroupBox("创建方式 / 令牌来源", contentWidget);
    applyTransparentContainerStyle(methodGroup);
    QGridLayout* methodLayout = new QGridLayout(methodGroup);
    methodLayout->setHorizontalSpacing(8);
    methodLayout->setVerticalSpacing(6);
    m_createMethodCombo = new QComboBox(methodGroup);
    m_createMethodCombo->addItem("CreateProcessW");
    m_createMethodCombo->addItem("CreateProcessAsTokenW (内部使用 CreateProcessAsUserW + fallback)");
    m_createMethodCombo->setStyleSheet(comboStyle);
    m_createMethodCombo->setCurrentIndex(0);
    m_createMethodCombo->setToolTip("默认直接调用 CreateProcessW；切换到 Token 模式时会按 PID 打开并调整令牌。");

    m_tokenSourcePidEdit = new QLineEdit("0", methodGroup);
    m_tokenDesiredAccessEdit = new QLineEdit("0x00000FAB", methodGroup);
    m_tokenDuplicatePrimaryCheck = new QCheckBox("DuplicateTokenEx 成 PrimaryToken", methodGroup);
    m_tokenDuplicatePrimaryCheck->setChecked(true);
    m_tokenSourcePidEdit->setStyleSheet(inputStyle);
    m_tokenDesiredAccessEdit->setStyleSheet(inputStyle);

    // 方法选择区域补充中文语义，避免只看英文 API 名不易理解。
    methodLayout->addWidget(new QLabel("API（创建方式）:", methodGroup), 0, 0);
    methodLayout->addWidget(m_createMethodCombo, 0, 1, 1, 3);
    methodLayout->addWidget(new QLabel("源 PID（令牌来源进程）:", methodGroup), 1, 0);
    methodLayout->addWidget(m_tokenSourcePidEdit, 1, 1);
    methodLayout->addWidget(new QLabel("令牌访问掩码（DesiredAccess）:", methodGroup), 1, 2);
    methodLayout->addWidget(m_tokenDesiredAccessEdit, 1, 3);
    methodLayout->addWidget(m_tokenDuplicatePrimaryCheck, 2, 0, 1, 4);

    // Token DesiredAccess 位标志勾选区：
    // - 覆盖最常见 TOKEN_* / 标准权限 / GENERIC_*；
    // - 用户可通过勾选组合，自动拼出访问掩码。
    QGroupBox* tokenAccessGroup = buildBitmaskCheckGroup(
        methodGroup,
        "Token DesiredAccess 位标志组合",
        TokenDesiredAccessDefinitions,
        &m_tokenDesiredAccessChecks);
    methodLayout->addWidget(tokenAccessGroup, 3, 0, 1, 4);
    contentLayout->addWidget(methodGroup);

    // 2) CreateProcessW 基础参数。
    QGroupBox* basicGroup = new QGroupBox("CreateProcessW 参数（全部可选 Null）", contentWidget);
    applyTransparentContainerStyle(basicGroup);
    QGridLayout* basicLayout = new QGridLayout(basicGroup);
    basicLayout->setHorizontalSpacing(8);
    basicLayout->setVerticalSpacing(6);

    m_useApplicationNameCheck = new QCheckBox("启用 lpApplicationName（应用程序路径）", basicGroup);
    m_useCommandLineCheck = new QCheckBox("启用 lpCommandLine（命令行参数）", basicGroup);
    m_useCurrentDirectoryCheck = new QCheckBox("启用 lpCurrentDirectory（当前工作目录）", basicGroup);
    m_useEnvironmentCheck = new QCheckBox("启用 lpEnvironment（环境变量块）", basicGroup);
    m_environmentUnicodeCheck = new QCheckBox("环境块按 Unicode 传递（CREATE_UNICODE_ENVIRONMENT）", basicGroup);
    m_inheritHandleCheck = new QCheckBox("bInheritHandles（是否继承句柄）=TRUE", basicGroup);

    m_applicationNameEdit = new QLineEdit(basicGroup);
    m_applicationBrowseButton = new QPushButton("浏览…", basicGroup);
    m_commandLineEdit = new QLineEdit(basicGroup);
    m_currentDirectoryEdit = new QLineEdit(basicGroup);
    m_currentDirectoryBrowseButton = new QPushButton("浏览…", basicGroup);
    m_environmentEditor = new QPlainTextEdit(basicGroup);
    m_creationFlagsEdit = new QLineEdit("0x00000000", basicGroup);
    m_environmentEditor->setPlaceholderText("每行一个 KEY=VALUE，留空则为 null。");
    m_environmentEditor->setFixedHeight(72);

    m_applicationNameEdit->setStyleSheet(inputStyle);
    m_commandLineEdit->setStyleSheet(inputStyle);
    m_currentDirectoryEdit->setStyleSheet(inputStyle);
    m_environmentEditor->setStyleSheet(inputStyle);
    m_creationFlagsEdit->setStyleSheet(inputStyle);
    m_applicationBrowseButton->setStyleSheet(buttonStyle);
    m_currentDirectoryBrowseButton->setStyleSheet(buttonStyle);

    m_useApplicationNameCheck->setChecked(false);
    m_useCommandLineCheck->setChecked(false);
    m_useCurrentDirectoryCheck->setChecked(false);
    m_useEnvironmentCheck->setChecked(false);
    m_environmentUnicodeCheck->setChecked(true);

    basicLayout->addWidget(m_useApplicationNameCheck, 0, 0);
    basicLayout->addWidget(m_applicationNameEdit, 0, 1, 1, 2);
    basicLayout->addWidget(m_applicationBrowseButton, 0, 3);
    basicLayout->addWidget(m_useCommandLineCheck, 1, 0);
    basicLayout->addWidget(m_commandLineEdit, 1, 1, 1, 3);
    basicLayout->addWidget(m_useCurrentDirectoryCheck, 2, 0);
    basicLayout->addWidget(m_currentDirectoryEdit, 2, 1, 1, 2);
    basicLayout->addWidget(m_currentDirectoryBrowseButton, 2, 3);
    basicLayout->addWidget(m_useEnvironmentCheck, 3, 0);
    basicLayout->addWidget(m_environmentEditor, 3, 1, 2, 3);
    basicLayout->addWidget(m_environmentUnicodeCheck, 5, 1, 1, 3);
    basicLayout->addWidget(new QLabel("dwCreationFlags（创建标志）:", basicGroup), 6, 0);
    basicLayout->addWidget(m_creationFlagsEdit, 6, 1);
    basicLayout->addWidget(m_inheritHandleCheck, 6, 2, 1, 2);

    // dwCreationFlags 位标志勾选区：
    // - 列出 CreateProcess 常见全部标志；
    // - 用户勾选后自动组合成掩码写回 dwCreationFlags 输入框。
    QGroupBox* creationFlagsGroup = buildBitmaskCheckGroup(
        basicGroup,
        "dwCreationFlags 位标志组合",
        CreateProcessFlagDefinitions,
        &m_creationFlagChecks);
    basicLayout->addWidget(creationFlagsGroup, 7, 0, 1, 4);
    contentLayout->addWidget(basicGroup);

    // 3) PROCESS / THREAD SECURITY_ATTRIBUTES。
    QGroupBox* securityGroup = new QGroupBox("SECURITY_ATTRIBUTES（Process / Thread）", contentWidget);
    applyTransparentContainerStyle(securityGroup);
    QGridLayout* securityLayout = new QGridLayout(securityGroup);
    securityLayout->setHorizontalSpacing(8);
    securityLayout->setVerticalSpacing(6);

    m_useProcessSecurityCheck = new QCheckBox("启用 lpProcessAttributes（进程安全属性）", securityGroup);
    m_processSecurityLengthEdit = new QLineEdit("0", securityGroup);
    m_processSecurityDescriptorEdit = new QLineEdit("0", securityGroup);
    m_processSecurityInheritCheck = new QCheckBox("bInheritHandle（进程 SA）", securityGroup);

    m_useThreadSecurityCheck = new QCheckBox("启用 lpThreadAttributes（线程安全属性）", securityGroup);
    m_threadSecurityLengthEdit = new QLineEdit("0", securityGroup);
    m_threadSecurityDescriptorEdit = new QLineEdit("0", securityGroup);
    m_threadSecurityInheritCheck = new QCheckBox("bInheritHandle（线程 SA）", securityGroup);

    m_processSecurityLengthEdit->setStyleSheet(inputStyle);
    m_processSecurityDescriptorEdit->setStyleSheet(inputStyle);
    m_threadSecurityLengthEdit->setStyleSheet(inputStyle);
    m_threadSecurityDescriptorEdit->setStyleSheet(inputStyle);

    securityLayout->addWidget(m_useProcessSecurityCheck, 0, 0);
    securityLayout->addWidget(new QLabel("nLength（结构体长度）", securityGroup), 0, 1);
    securityLayout->addWidget(m_processSecurityLengthEdit, 0, 2);
    securityLayout->addWidget(new QLabel("lpSecurityDescriptor（安全描述符指针）", securityGroup), 0, 3);
    securityLayout->addWidget(m_processSecurityDescriptorEdit, 0, 4);
    securityLayout->addWidget(m_processSecurityInheritCheck, 0, 5);
    securityLayout->addWidget(m_useThreadSecurityCheck, 1, 0);
    securityLayout->addWidget(new QLabel("nLength（结构体长度）", securityGroup), 1, 1);
    securityLayout->addWidget(m_threadSecurityLengthEdit, 1, 2);
    securityLayout->addWidget(new QLabel("lpSecurityDescriptor（安全描述符指针）", securityGroup), 1, 3);
    securityLayout->addWidget(m_threadSecurityDescriptorEdit, 1, 4);
    securityLayout->addWidget(m_threadSecurityInheritCheck, 1, 5);
    contentLayout->addWidget(securityGroup);

    // 4) STARTUPINFOW 全字段。
    QGroupBox* startupGroup = new QGroupBox("STARTUPINFOW（全部字段）", contentWidget);
    applyTransparentContainerStyle(startupGroup);
    QGridLayout* startupLayout = new QGridLayout(startupGroup);
    startupLayout->setHorizontalSpacing(8);
    startupLayout->setVerticalSpacing(6);
    m_useStartupInfoCheck = new QCheckBox("启用 lpStartupInfo（启动信息结构体，取消则传 NULL）", startupGroup);
    m_useStartupInfoCheck->setChecked(true);
    m_useStartupInfoCheck->setToolTip("默认启用并传入有效 STARTUPINFOW；取消勾选只用于测试 NULL 参数失败路径。");

    m_siCbEdit = new QLineEdit("0", startupGroup);
    m_siReservedEdit = new QLineEdit(startupGroup);
    m_siDesktopEdit = new QLineEdit(startupGroup);
    m_siTitleEdit = new QLineEdit(startupGroup);
    m_siXEdit = new QLineEdit("0", startupGroup);
    m_siYEdit = new QLineEdit("0", startupGroup);
    m_siXSizeEdit = new QLineEdit("0", startupGroup);
    m_siYSizeEdit = new QLineEdit("0", startupGroup);
    m_siXCountCharsEdit = new QLineEdit("0", startupGroup);
    m_siYCountCharsEdit = new QLineEdit("0", startupGroup);
    m_siFillAttributeEdit = new QLineEdit("0x00000000", startupGroup);
    m_siFlagsEdit = new QLineEdit("0x00000000", startupGroup);
    m_siShowWindowEdit = new QLineEdit("0", startupGroup);
    m_siCbReserved2Edit = new QLineEdit("0", startupGroup);
    m_siReserved2PtrEdit = new QLineEdit("0", startupGroup);
    m_siStdInputEdit = new QLineEdit("0", startupGroup);
    m_siStdOutputEdit = new QLineEdit("0", startupGroup);
    m_siStdErrorEdit = new QLineEdit("0", startupGroup);

    const QList<QLineEdit*> startupEdits{
        m_siCbEdit, m_siReservedEdit, m_siDesktopEdit, m_siTitleEdit,
        m_siXEdit, m_siYEdit, m_siXSizeEdit, m_siYSizeEdit,
        m_siXCountCharsEdit, m_siYCountCharsEdit, m_siFillAttributeEdit,
        m_siFlagsEdit, m_siShowWindowEdit, m_siCbReserved2Edit,
        m_siReserved2PtrEdit, m_siStdInputEdit, m_siStdOutputEdit, m_siStdErrorEdit
    };
    for (QLineEdit* startupEdit : startupEdits)
    {
        startupEdit->setStyleSheet(inputStyle);
    }

    int startupRow = 0;
    startupLayout->addWidget(m_useStartupInfoCheck, startupRow++, 0, 1, 6);
    const auto addStartupField = [&startupLayout, &startupRow](const QString& labelText, QWidget* editorWidget, const int colOffset)
        {
            startupLayout->addWidget(new QLabel(labelText), startupRow, colOffset);
            startupLayout->addWidget(editorWidget, startupRow, colOffset + 1);
        };

    addStartupField("cb（结构体大小）", m_siCbEdit, 0);
    addStartupField("lpReserved（保留字符串）", m_siReservedEdit, 2);
    addStartupField("lpDesktop（目标桌面）", m_siDesktopEdit, 4);
    ++startupRow;
    addStartupField("lpTitle（窗口标题）", m_siTitleEdit, 0);
    addStartupField("dwX（窗口X坐标）", m_siXEdit, 2);
    addStartupField("dwY（窗口Y坐标）", m_siYEdit, 4);
    ++startupRow;
    addStartupField("dwXSize（窗口宽）", m_siXSizeEdit, 0);
    addStartupField("dwYSize（窗口高）", m_siYSizeEdit, 2);
    addStartupField("dwXCountChars（控制台宽）", m_siXCountCharsEdit, 4);
    ++startupRow;
    addStartupField("dwYCountChars（控制台高）", m_siYCountCharsEdit, 0);
    addStartupField("dwFillAttribute（控制台属性）", m_siFillAttributeEdit, 2);
    addStartupField("dwFlags（启动标志）", m_siFlagsEdit, 4);
    ++startupRow;
    addStartupField("wShowWindow（显示方式）", m_siShowWindowEdit, 0);
    addStartupField("cbReserved2（保留2长度）", m_siCbReserved2Edit, 2);
    addStartupField("lpReserved2（保留2指针）", m_siReserved2PtrEdit, 4);
    ++startupRow;
    addStartupField("hStdInput（标准输入句柄）", m_siStdInputEdit, 0);
    addStartupField("hStdOutput（标准输出句柄）", m_siStdOutputEdit, 2);
    addStartupField("hStdError（标准错误句柄）", m_siStdErrorEdit, 4);
    ++startupRow;

    // STARTUPINFO.dwFillAttribute 位标志勾选区：
    // - 提供前景/背景颜色与样式位的可视化组合。
    QGroupBox* startupFillAttrGroup = buildBitmaskCheckGroup(
        startupGroup,
        "STARTUPINFO.dwFillAttribute 位标志组合",
        ConsoleFillAttributeDefinitions,
        &m_startupFillAttributeChecks);
    startupLayout->addWidget(startupFillAttrGroup, startupRow++, 0, 1, 6);

    // STARTUPINFO.dwFlags 位标志勾选区：
    // - 列出 STARTF_* 标志；
    // - 通过复选框直接组合，并自动回填到 dwFlags 输入框。
    QGroupBox* startupFlagsGroup = buildBitmaskCheckGroup(
        startupGroup,
        "STARTUPINFO.dwFlags 位标志组合",
        StartupInfoFlagDefinitions,
        &m_startupFlagChecks);
    startupLayout->addWidget(startupFlagsGroup, startupRow++, 0, 1, 6);

    contentLayout->addWidget(startupGroup);

    // 5) PROCESS_INFORMATION 全字段。
    QGroupBox* processInfoGroup = new QGroupBox("PROCESS_INFORMATION（输出结构体，支持自定义初值）", contentWidget);
    applyTransparentContainerStyle(processInfoGroup);
    QGridLayout* processInfoLayout = new QGridLayout(processInfoGroup);
    processInfoLayout->setHorizontalSpacing(8);
    processInfoLayout->setVerticalSpacing(6);

    m_useProcessInfoCheck = new QCheckBox("启用 lpProcessInformation（进程信息输出结构，取消则传 NULL）", processInfoGroup);
    m_useProcessInfoCheck->setChecked(true);
    m_useProcessInfoCheck->setToolTip("默认启用并传入有效 PROCESS_INFORMATION；取消勾选只用于测试 NULL 参数失败路径。");
    m_piProcessHandleEdit = new QLineEdit("0", processInfoGroup);
    m_piThreadHandleEdit = new QLineEdit("0", processInfoGroup);
    m_piPidEdit = new QLineEdit("0", processInfoGroup);
    m_piTidEdit = new QLineEdit("0", processInfoGroup);
    m_piProcessHandleEdit->setStyleSheet(inputStyle);
    m_piThreadHandleEdit->setStyleSheet(inputStyle);
    m_piPidEdit->setStyleSheet(inputStyle);
    m_piTidEdit->setStyleSheet(inputStyle);

    processInfoLayout->addWidget(m_useProcessInfoCheck, 0, 0, 1, 4);
    processInfoLayout->addWidget(new QLabel("hProcess（输出进程句柄）", processInfoGroup), 1, 0);
    processInfoLayout->addWidget(m_piProcessHandleEdit, 1, 1);
    processInfoLayout->addWidget(new QLabel("hThread（输出线程句柄）", processInfoGroup), 1, 2);
    processInfoLayout->addWidget(m_piThreadHandleEdit, 1, 3);
    processInfoLayout->addWidget(new QLabel("dwProcessId（输出PID）", processInfoGroup), 2, 0);
    processInfoLayout->addWidget(m_piPidEdit, 2, 1);
    processInfoLayout->addWidget(new QLabel("dwThreadId（输出TID）", processInfoGroup), 2, 2);
    processInfoLayout->addWidget(m_piTidEdit, 2, 3);
    contentLayout->addWidget(processInfoGroup);

    // 6) Token 特权编辑器。
    QGroupBox* tokenPrivilegeGroup = new QGroupBox("Token 特权调整（AdjustTokenPrivileges）", contentWidget);
    applyTransparentContainerStyle(tokenPrivilegeGroup);
    QVBoxLayout* tokenPrivilegeLayout = new QVBoxLayout(tokenPrivilegeGroup);
    const QStringList privilegeNames = tokenPrivilegeNames();
    m_tokenPrivilegeTable = new ks::ui::VisibleTableWidget(privilegeNames.size(), 2, tokenPrivilegeGroup);
    m_tokenPrivilegeTable->setHorizontalHeaderLabels(QStringList{ "Privilege", "Action" });
    m_tokenPrivilegeTable->horizontalHeader()->setStretchLastSection(true);
    m_tokenPrivilegeTable->verticalHeader()->setVisible(false);
    m_tokenPrivilegeTable->setSelectionMode(QAbstractItemView::NoSelection);
    m_tokenPrivilegeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tokenPrivilegeTable->setAlternatingRowColors(true);
    m_tokenPrivilegeTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_tokenPrivilegeTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            // Token 特权表复制菜单：
            // - 输入：用户右键点击的特权行；
            // - 处理：读取 Privilege 单元格和 Action 下拉框当前文本，拼成 TSV；
            // - 返回：仅写入剪贴板，不修改 Token、不调用 AdjustTokenPrivileges。
            if (m_tokenPrivilegeTable == nullptr)
            {
                return;
            }

            const int rowIndex = m_tokenPrivilegeTable->rowAt(localPosition.y());
            if (rowIndex < 0 || rowIndex >= m_tokenPrivilegeTable->rowCount())
            {
                return;
            }

            m_tokenPrivilegeTable->setCurrentCell(rowIndex, 0);

            QMenu contextMenu(m_tokenPrivilegeTable);
            contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            if (contextMenu.exec(m_tokenPrivilegeTable->viewport()->mapToGlobal(localPosition)) != copyRowAction)
            {
                return;
            }

            const QTableWidgetItem* privilegeItem = m_tokenPrivilegeTable->item(rowIndex, 0);
            const QComboBox* actionCombo = qobject_cast<QComboBox*>(m_tokenPrivilegeTable->cellWidget(rowIndex, 1));
            QStringList rowFields;
            rowFields.reserve(2);
            rowFields << (privilegeItem != nullptr ? privilegeItem->text() : QString());
            rowFields << (actionCombo != nullptr ? actionCombo->currentText() : QString());
            QApplication::clipboard()->setText(rowFields.join(QChar('\t')));
        });

    for (int row = 0; row < privilegeNames.size(); ++row)
    {
        QTableWidgetItem* nameItem = new QTableWidgetItem(privilegeNames.at(row));
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        m_tokenPrivilegeTable->setItem(row, 0, nameItem);

        QComboBox* actionCombo = new QComboBox(m_tokenPrivilegeTable);
        actionCombo->addItem("保持", static_cast<int>(ks::process::TokenPrivilegeAction::Keep));
        actionCombo->addItem("启用", static_cast<int>(ks::process::TokenPrivilegeAction::Enable));
        actionCombo->addItem("禁用", static_cast<int>(ks::process::TokenPrivilegeAction::Disable));
        actionCombo->addItem("移除", static_cast<int>(ks::process::TokenPrivilegeAction::Remove));
        actionCombo->setCurrentIndex(0);
        actionCombo->setStyleSheet(comboStyle);
        m_tokenPrivilegeTable->setCellWidget(row, 1, actionCombo);
    }

    QHBoxLayout* tokenActionLayout = new QHBoxLayout();
    m_applyTokenPrivilegeButton = new QPushButton("仅应用令牌调整（不创建）", tokenPrivilegeGroup);
    m_resetTokenPrivilegeButton = new QPushButton("重置全部特权动作为保持", tokenPrivilegeGroup);
    m_applyTokenPrivilegeButton->setStyleSheet(buttonStyle);
    m_resetTokenPrivilegeButton->setStyleSheet(buttonStyle);
    tokenActionLayout->addWidget(m_applyTokenPrivilegeButton);
    tokenActionLayout->addWidget(m_resetTokenPrivilegeButton);
    tokenActionLayout->addStretch(1);

    tokenPrivilegeLayout->addWidget(m_tokenPrivilegeTable, 1);
    tokenPrivilegeLayout->addLayout(tokenActionLayout);
    contentLayout->addWidget(tokenPrivilegeGroup);

    // 7) 操作按钮 + 输出日志。
    QGroupBox* actionGroup = new QGroupBox("执行与结果", contentWidget);
    applyTransparentContainerStyle(actionGroup);
    QVBoxLayout* actionLayout = new QVBoxLayout(actionGroup);
    QHBoxLayout* actionButtonLayout = new QHBoxLayout();
    m_launchProcessButton = new QPushButton("执行创建进程", actionGroup);
    m_resetCreateFormButton = new QPushButton("恢复默认配置", actionGroup);
    m_launchProcessButton->setStyleSheet(buttonStyle);
    m_resetCreateFormButton->setStyleSheet(buttonStyle);
    actionButtonLayout->addWidget(m_launchProcessButton);
    actionButtonLayout->addWidget(m_resetCreateFormButton);
    actionButtonLayout->addStretch(1);

    m_createResultOutput = new QTextEdit(actionGroup);
    m_createResultOutput->setReadOnly(true);
    m_createResultOutput->setMinimumHeight(140);
    m_createResultOutput->setStyleSheet(inputStyle);
    m_createResultOutput->setPlaceholderText("这里显示请求参数摘要、API 返回结果和失败错误码。");

    actionLayout->addLayout(actionButtonLayout);
    actionLayout->addWidget(m_createResultOutput, 1);
    contentLayout->addWidget(actionGroup, 1);

    // 默认值补充：命令行默认跟随 applicationName。
    m_commandLineEdit->setPlaceholderText("例如: \"C:\\Windows\\System32\\notepad.exe\" C:\\test.txt");
    m_applicationNameEdit->setPlaceholderText("可执行文件路径（可为空并传 null）");
    m_currentDirectoryEdit->setPlaceholderText("工作目录（可为空并传 null）");

    // 为关键 CreateProcess 参数补充中文解释 Tooltip，便于用户理解每个字段的语义。
    m_applicationNameEdit->setToolTip("lpApplicationName：应用程序路径。可为 null，由命令行首段决定可执行文件。");
    m_commandLineEdit->setToolTip("lpCommandLine：完整命令行。可执行路径 + 参数，传入后可能被 API 就地修改。");
    m_currentDirectoryEdit->setToolTip("lpCurrentDirectory：子进程初始工作目录。");
    m_environmentEditor->setToolTip("lpEnvironment：环境变量块。每行 KEY=VALUE；禁用或启用但内容为空时传 null。取消 Unicode 时按系统 ANSI 代码页传递。");
    m_inheritHandleCheck->setToolTip("bInheritHandles：是否继承父进程可继承句柄。");
    m_creationFlagsEdit->setToolTip("dwCreationFlags：创建标志位掩码；可在下方复选框中逐位勾选组合。");
    m_useStartupInfoCheck->setToolTip("lpStartupInfo：启动信息结构体，默认传入有效 STARTUPINFOW；取消勾选才传 null。");
    m_useProcessInfoCheck->setToolTip("lpProcessInformation：默认传入有效输出结构接收 PID/TID；返回的句柄会在后端记录后立即关闭。");
    m_useProcessSecurityCheck->setToolTip("lpProcessAttributes：进程对象安全属性。");
    m_useThreadSecurityCheck->setToolTip("lpThreadAttributes：主线程对象安全属性。");
    m_siFlagsEdit->setToolTip("STARTUPINFO.dwFlags：启动标志位掩码；可在下方 STARTF 复选框中组合。");
    m_siFillAttributeEdit->setToolTip("STARTUPINFO.dwFillAttribute：控制台颜色/样式位；可在下方复选框组合。");
    m_tokenDesiredAccessEdit->setToolTip("Token DesiredAccess：令牌访问掩码；可在下方复选框组合。");

    m_sideTabWidget->addTab(m_createProcessPage, blueTintedIcon(IconStart), "创建进程");
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget,
        m_createProcessPage,
        QStringLiteral("process.tab.create"),
        QStringLiteral("创建进程"));
    refreshSideTabIconContrast();
    initializeCreateProcessConnections();
}

void ProcessDock::initializeConnections()
{
    // 树状视图：勾选时按父子关系显示；取消勾选时按应用/后台/系统分类。
    connect(m_treeViewCheck, &QCheckBox::toggled, this, [this](const bool checked) {
        m_activityTableSnapshotIndex = -1;
        m_activityTableSnapshotRecords.clear();
        // 用户手动切换复选框后退出表头触发的普通扁平模式，并重置友好视图排序会话。
        m_flatListForcedByHeaderSort = false;
        m_friendlySortActive = false;
        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 树状视图开关变更, treeView="
            << (checked ? "true" : "false")
            << eol;
        rebuildTable();
    });

    // 视图模式切换：重置默认可见列。
    connect(m_viewModeCombo, &QComboBox::currentIndexChanged, this, [this](const int modeIndex) {
        // 程序重建下拉项期间不响应，避免 rebuildViewModeComboItems 触发多余的刷新。
        if (m_viewModeComboUpdating)
        {
            return;
        }

        m_activityTableSnapshotIndex = -1;
        m_activityTableSnapshotRecords.clear();

        const int customIndex = currentCustomViewIndex();
        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 视图模式切换, itemIndex=" << modeIndex
            << ", customViewIndex=" << customIndex
            << eol;

        if (customIndex >= 0)
        {
            applyCustomView(customIndex);
        }
        else
        {
            // 切换内置预设时清空逐列覆盖：否则上一个视图里手动加的列会跟着带到新视图。
            m_userColumnVisibilityOverride.clear();
            saveProcessColumnLayoutToSettings();
            applyViewMode(currentViewMode());
        }

        m_lastProcessDetailDemandFlags = currentProcessDetailDemandFlags();
        rebuildTable();
        requestAsyncRefresh(true);
    });

    // 开始/暂停监视：仅切换标记和定时器，不阻塞 UI。
    connect(m_startButton, &QPushButton::clicked, this, [this]() {
        kLogEvent logEvent;
        info << logEvent << "[ProcessDock] 用户点击开始刷新，恢复周期刷新并同步记录进程活动。" << eol;
        m_monitoringEnabled = true;
        m_activityRecordingEnabled = true;
        if (m_activitySamples.empty())
        {
            m_activityRecordingStartTick100ns = steadyNow100ns();
            m_activityNextSequence = 0;
        }
        m_activityTimelinePinnedToLatest = true;
        m_activityTableSnapshotIndex = -1;
        m_activityTableSnapshotRecords.clear();
        if (m_refreshTimer != nullptr)
        {
            if (isProcessActivityRefreshAllowedNow())
            {
                m_refreshTimer->start(refreshIntervalMillisecondsFromInput());
            }
            else
            {
                m_refreshTimer->stop();
            }
        }
        requestAsyncRefresh(true);
    });
    connect(m_pauseButton, &QPushButton::clicked, this, [this]() {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 用户点击暂停刷新，周期刷新与进程活动记录一起暂停。" << eol;
        m_monitoringEnabled = false;
        m_activityRecordingEnabled = false;
        if (m_refreshTimer != nullptr)
        {
            m_refreshTimer->stop();
        }
        // 未缓存图标只属于显示增强。暂停后取消未开始任务，并丢弃在途任务的回传结果。
        ++m_processIconExtractionGeneration;
        m_processIconExtractionPool.clear();
        m_processIconPathsInFlight.clear();
        stopProcessNetworkTrafficCapture();
        stopCpuCoreUsageCapture();
        m_threadCounterSampleByIdentity.clear();
        updateProcessActivityStatusLabel();
    });

    // 选择列：打开添加/减少列对话框，与表头右键菜单里的同名项走同一实现。
    if (m_columnChooserButton != nullptr)
    {
        connect(m_columnChooserButton, &QPushButton::clicked, this, [this]() {
            showColumnChooserDialog();
        });
    }

    // 统一间隔步进控件：已关闭键盘跟踪，值变更后同时更新枚举和表格节流。
    connect(m_refreshIntervalSpin, &QDoubleSpinBox::valueChanged, this, [this](double) {
        applyRefreshIntervalInput();
    });

    // 清空记录缓存：重置序号、时间轴和吸附状态。
    connect(m_activityClearButton, &QPushButton::clicked, this, [this]() {
        m_activitySamples.clear();
        m_activityTableSnapshotIndex = -1;
        m_activityTableSnapshotRecords.clear();
        m_activityNextSequence = 0;
        m_activityRecordingStartTick100ns = steadyNow100ns();
        m_activityTimelinePinnedToLatest = true;
        refreshProcessActivityTimeline();
        refreshProcessActivityChart();
        rebuildTable();
        updateProcessActivityStatusLabel();
        if (m_activitySnapshotLabel != nullptr)
        {
            m_activitySnapshotLabel->setText(processContextText(
                "process.activity.snapshot.empty",
                QStringLiteral("时间轴快照：暂无样本")));
        }
    });

    // 指标按钮：切换后只重绘图表，不改变样本缓存。
    const auto connectMetricButton = [this](QPushButton* button) {
        if (button == nullptr)
        {
            return;
        }
        connect(button, &QPushButton::toggled, this, [this]() {
            refreshProcessActivityChart();
            const int sampleIndex = (m_activityTimelineSlider != nullptr) ? m_activityTimelineSlider->value() : -1;
            if (sampleIndex >= 0)
            {
                previewProcessActivitySnapshotForIndex(sampleIndex);
            }
        });
    };
    connectMetricButton(m_activityCpuButton);
    connectMetricButton(m_activityMemoryButton);
    connectMetricButton(m_activityDiskButton);
    connectMetricButton(m_activityNetworkButton);
    connectMetricButton(m_activityGpuButton);

    // 时间轴滑块：用户拖到最右侧后进入“吸附最新”模式，否则停留历史样本。
    connect(m_activityTimelineSlider, &QSlider::valueChanged, this, [this](const int sampleIndex) {
        if (m_activityTimelineSlider == nullptr)
        {
            return;
        }
        if (!m_activityTimelineSliderUpdating)
        {
            // 用户要求：只有点击时间轴才切换表格时刻。
            // 普通 valueChanged 可能来自程序同步或键盘操作，这里只更新快照提示。
            previewProcessActivitySnapshotForIndex(sampleIndex);
            return;
        }
        previewProcessActivitySnapshotForIndex(sampleIndex);
    });

    // 不记录历史：
    // - 勾选时不清空历史样本，只暂停后续 append；
    // - 取消后继续沿用同一条记录时间轴，方便对比前后变化。
    connect(m_activityListOnlyRefreshCheck, &QCheckBox::toggled, this, [this](const bool checked) {
        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 不记录历史开关变更, listOnly="
            << (checked ? "true" : "false")
            << eol;
        updateProcessActivityStatusLabel();
        refreshProcessActivityChart();
    });

    // 表格右键菜单。
    connect(m_processTable, &QWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showTableContextMenu(localPosition);
    });

    // 表头右键菜单（列显示/隐藏）。
    connect(m_processTable->horizontalHeader(), &QHeaderView::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showHeaderContextMenu(localPosition);
    });

    // 友好视图需要保留“应用/后台/系统”分组结构，不能让 QSortFilterProxyModel 直接打散源顺序。
    // 树状视图点表头后保持友好视图未勾选，解绑父子关系并切到普通扁平枚举排序。
    connect(m_processTable->horizontalHeader(), &QHeaderView::sectionClicked, this, [this](const int logicalIndex) {
        if (isProcessActivityTableSnapshotActive() ||
            !currentProcessSearchText().isEmpty())
        {
            return;
        }
        if (logicalIndex < 0 || logicalIndex >= static_cast<int>(TableColumn::Count))
        {
            return;
        }

        // 树状行的父子顺序不能直接交给普通列排序。首次点击固定升序，
        // 保持复选框未勾选，仅切换内部投影为没有父子关系的普通进程枚举。
        const bool treeModeWasEnabled = isTreeModeEnabled();
        if (treeModeWasEnabled)
        {
            m_flatListForcedByHeaderSort = true;
            if (QHeaderView* const headerView = m_processTable->horizontalHeader())
            {
                headerView->setSortIndicator(logicalIndex, Qt::AscendingOrder);
                headerView->setSortIndicatorShown(true);
            }
            rebuildTable();
            return;
        }

        // 已由表头切换为普通扁平枚举时，排序代理会按 Qt 默认行为在升序/降序间切换。
        // 此处不再写入友好视图专用排序状态。
        if (m_flatListForcedByHeaderSort)
        {
            return;
        }

        if (m_friendlySortActive && m_friendlySortColumn == logicalIndex)
        {
            m_friendlySortOrder = (m_friendlySortOrder == Qt::AscendingOrder)
                ? Qt::DescendingOrder
                : Qt::AscendingOrder;
        }
        else
        {
            m_friendlySortColumn = logicalIndex;
            m_friendlySortOrder = Qt::AscendingOrder;
        }
        m_friendlySortActive = true;

        if (!isFriendlyViewEnabled())
        {
            return;
        }

        if (m_processSortProxy != nullptr)
        {
            m_processSortProxy->sort(toColumnIndex(TableColumn::Name), Qt::AscendingOrder);
        }
        rebuildTable();
    });

    // 搜索框输入变更后直接重建表格：
    // - 仅过滤当前缓存，不等待下一轮刷新；
    // - 这样键入 notepad 等关键词时结果会立即收敛。
    connect(m_processSearchLineEdit, &QLineEdit::textChanged, this, [this](const QString&) {
        rebuildTable();
    });

    // 切回“进程列表”页时自动聚焦搜索框：
    // - 用户无需先点一下输入框；
    // - 可以直接开始输入 notepad 等搜索词。
    connect(m_sideTabWidget, &QTabWidget::currentChanged, this, [this](const int currentIndex) {
        if (m_sideTabWidget == nullptr || currentIndex < 0)
        {
            return;
        }
        refreshSideTabIconContrast();

        QWidget* currentPage = m_sideTabWidget->widget(currentIndex);
        if (currentPage == m_processListPage)
        {
            if (m_monitoringEnabled && m_refreshTimer != nullptr && !m_refreshTimer->isActive())
            {
                m_refreshTimer->start(refreshIntervalMillisecondsFromInput());
            }
            focusProcessSearchBox(true);
            updateProcessActivityStatusLabel();
            if (m_monitoringEnabled)
            {
                requestAsyncRefresh(true);
            }
            return;
        }
        if (currentPage == m_threadPage)
        {
            updateProcessActivityStatusLabel();
            requestAsyncThreadRefresh(true);
            return;
        }
        updateProcessActivityStatusLabel();
    });

    // currentChanged 作用：
    // - 记录当前被用户选中的进程 identityKey；
    // - 周期刷新后 rebuildTable 会按这个 key 恢复高亮。
    if (QItemSelectionModel* selectionModel = m_processTable->selectionModel())
    {
        connect(selectionModel, &QItemSelectionModel::currentChanged, this, [this](const QModelIndex& currentIndex, const QModelIndex&) {
            if (!currentIndex.isValid())
            {
                if (!m_contextMenuVisible)
                {
                    m_trackedSelectedIdentityKey.clear();
                    m_trackedSelectedIdentityKeys.clear();
                    m_trackedSelectedColumn = 0;
                }
                return;
            }

            const int currentColumn = currentIndex.column();
            if (currentColumn >= 0 && currentColumn < static_cast<int>(TableColumn::Count))
            {
                m_trackedSelectedColumn = currentColumn;
            }
            syncTrackedSelectionFromTable();
        });

        // selectionChanged 作用：
        // - 记录 Ctrl 复选后的完整行集合；
        // - 周期刷新 rebuildTable 后按 identityKey 恢复多选状态。
        connect(selectionModel, &QItemSelectionModel::selectionChanged, this, [this](const QItemSelection&, const QItemSelection&) {
            syncTrackedSelectionFromTable();
            refreshProcessActivityChart();
            if (m_activityTimelineSlider != nullptr && !m_activitySamples.empty())
            {
                previewProcessActivitySnapshotForIndex(m_activityTimelineSlider->value());
            }
        });
    }

    // pressed 作用：
    // - 左键点选某一行时同步记录点击列；
    // - 刷新恢复时尽量回到用户原来的焦点列。
    connect(m_processTable, &QAbstractItemView::pressed, this, [this](const QModelIndex& index) {
        if (!index.isValid())
        {
            return;
        }

        const ProcessTableRow* tableRow = processTableRowForViewIndex(index);
        if (tableRow != nullptr && tableRow->rowKind == ProcessTableRowKind::Process)
        {
            m_trackedSelectedIdentityKey = tableRow->identityKey;
        }
        else if (tableRow != nullptr)
        {
            m_trackedSelectedIdentityKey.clear();
        }
        if (index.column() >= 0 && index.column() < static_cast<int>(TableColumn::Count))
        {
            m_trackedSelectedColumn = index.column();
        }
        QTimer::singleShot(0, this, [this]()
        {
            syncTrackedSelectionFromTable();
        });
    });

    // 双击友好视图合成行时折叠/展开；真实进程行保持“打开详情”的任务管理器式行为。
    connect(m_processTable, &QAbstractItemView::doubleClicked, this, [this](const QModelIndex& index) {
        const ProcessTableRow* tableRow = processTableRowForViewIndex(index);
        if (tableRow == nullptr)
        {
            return;
        }

        if (tableRow->rowKind == ProcessTableRowKind::GroupHeader ||
            tableRow->rowKind == ProcessTableRowKind::ApplicationAggregate)
        {
            if (!tableRow->expansionKey.isEmpty())
            {
                const bool defaultExpanded = tableRow->rowKind == ProcessTableRowKind::GroupHeader;
                const bool currentExpanded = m_friendlyExpandedStateByKey.value(
                    tableRow->expansionKey,
                    defaultExpanded);
                m_friendlyExpandedStateByKey.insert(tableRow->expansionKey, !currentExpanded);
                rebuildTable();
            }
            return;
        }

        if (tableRow->rowKind == ProcessTableRowKind::Process)
        {
            openProcessDetailWindowByPid(tableRow->record.pid);
        }
    });

    // Alt+E 作用：
    // - 提供与任务管理器类似的快速结束进程快捷键；
    // - 仅在“进程列表”页且存在选中行时执行“结束进程组合动作”。
    QShortcut* terminateShortcut = new QShortcut(QKeySequence(Qt::ALT | Qt::Key_E), this);
    terminateShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    connect(terminateShortcut, &QShortcut::activated, this, [this]() {
        if (m_sideTabWidget == nullptr || m_sideTabWidget->currentWidget() != m_processListPage)
        {
            return;
        }

        if (selectedActionTargets().empty())
        {
            kLogEvent logEvent;
            warn << logEvent
                << "[ProcessDock] Alt+E 被忽略：当前没有选中可结束的进程。"
                << eol;
            return;
        }

        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 触发快捷键 Alt+E，执行结束进程组合动作。"
            << eol;
        executeTerminateProcessAction();
    });

    // 线程页专属连接：集中在独立函数中，避免主连接函数继续膨胀。
    initializeThreadPageConnections();
    initializeCrossViewConnections();
}

void ProcessDock::initializeCreateProcessConnections()
{
    if (m_applicationBrowseButton != nullptr)
    {
        connect(m_applicationBrowseButton, &QPushButton::clicked, this, [this]() {
            browseCreateProcessApplicationPath();
            });
    }
    if (m_currentDirectoryBrowseButton != nullptr)
    {
        connect(m_currentDirectoryBrowseButton, &QPushButton::clicked, this, [this]() {
            browseCreateProcessCurrentDirectory();
            });
    }
    if (m_launchProcessButton != nullptr)
    {
        connect(m_launchProcessButton, &QPushButton::clicked, this, [this]() {
            executeCreateProcessRequest();
            });
    }
    if (m_resetCreateFormButton != nullptr)
    {
        connect(m_resetCreateFormButton, &QPushButton::clicked, this, [this]() {
            resetCreateProcessForm();
            });
    }
    if (m_applyTokenPrivilegeButton != nullptr)
    {
        connect(m_applyTokenPrivilegeButton, &QPushButton::clicked, this, [this]() {
            executeApplyTokenPrivilegeEditsOnly();
            });
    }
    if (m_resetTokenPrivilegeButton != nullptr && m_tokenPrivilegeTable != nullptr)
    {
        connect(m_resetTokenPrivilegeButton, &QPushButton::clicked, this, [this]() {
            for (int row = 0; row < m_tokenPrivilegeTable->rowCount(); ++row)
            {
                QComboBox* actionCombo = qobject_cast<QComboBox*>(m_tokenPrivilegeTable->cellWidget(row, 1));
                if (actionCombo != nullptr)
                {
                    actionCombo->setCurrentIndex(0);
                }
            }
            appendCreateResultLine("已重置全部特权动作到“保持”。");
            });
    }

    // 选择应用程序路径后，若 lpCommandLine 为空则自动填充便于快速执行。
    if (m_applicationNameEdit != nullptr && m_commandLineEdit != nullptr)
    {
        connect(m_applicationNameEdit, &QLineEdit::textChanged, this, [this](const QString& textValue) {
            if (textValue.trimmed().isEmpty())
            {
                return;
            }
            if (m_commandLineEdit->text().trimmed().isEmpty())
            {
                m_commandLineEdit->setText(QStringLiteral("\"%1\"").arg(textValue.trimmed()));
            }
            });
    }

    if (m_createMethodCombo != nullptr && m_tokenSourcePidEdit != nullptr)
    {
        connect(m_createMethodCombo, &QComboBox::currentIndexChanged, this, [this](const int indexValue) {
            const bool tokenMode = (indexValue == 1);
            m_tokenSourcePidEdit->setEnabled(tokenMode);
            m_tokenDesiredAccessEdit->setEnabled(tokenMode);
            m_tokenDuplicatePrimaryCheck->setEnabled(tokenMode);
            m_tokenPrivilegeTable->setEnabled(tokenMode);
            m_applyTokenPrivilegeButton->setEnabled(tokenMode);
            m_resetTokenPrivilegeButton->setEnabled(tokenMode);
            appendCreateResultLine(tokenMode
                ? "已切换到 Token 创建模式。"
                : "已切换到普通 CreateProcessW 模式。");
            });
        m_createMethodCombo->setCurrentIndex(0);
    }

    // 位标志编辑联动：
    // - 勾选复选框自动组合掩码写回输入框；
    // - 手工修改输入框会反向刷新复选框状态。
    bindBitmaskEditor(m_creationFlagsEdit, &m_creationFlagChecks, "dwCreationFlags");
    bindBitmaskEditor(m_siFlagsEdit, &m_startupFlagChecks, "STARTUPINFO.dwFlags");
    bindBitmaskEditor(m_siFillAttributeEdit, &m_startupFillAttributeChecks, "STARTUPINFO.dwFillAttribute");
    bindBitmaskEditor(m_tokenDesiredAccessEdit, &m_tokenDesiredAccessChecks, "Token DesiredAccess");

    const bool tokenMode = (m_createMethodCombo != nullptr && m_createMethodCombo->currentIndex() == 1);
    if (m_tokenSourcePidEdit != nullptr) m_tokenSourcePidEdit->setEnabled(tokenMode);
    if (m_tokenDesiredAccessEdit != nullptr) m_tokenDesiredAccessEdit->setEnabled(tokenMode);
    if (m_tokenDuplicatePrimaryCheck != nullptr) m_tokenDuplicatePrimaryCheck->setEnabled(tokenMode);
    if (m_tokenPrivilegeTable != nullptr) m_tokenPrivilegeTable->setEnabled(tokenMode);
    if (m_applyTokenPrivilegeButton != nullptr) m_applyTokenPrivilegeButton->setEnabled(tokenMode);
    if (m_resetTokenPrivilegeButton != nullptr) m_resetTokenPrivilegeButton->setEnabled(tokenMode);
}

void ProcessDock::initializeTimer()
{
    // 周期监视定时器：默认每秒执行后台刷新、活动采样和表格重绘。
    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(refreshIntervalMillisecondsFromInput());
    connect(m_refreshTimer, &QTimer::timeout, this, [this]() {
        requestAsyncRefresh(false);
    });
    // 首次显示前不启动，避免主窗口启动阶段后台偷跑刷新。
}

int ProcessDock::refreshIntervalMillisecondsFromInput() const
{
    // 步进控件自身已把取值限制在 0.5~60 秒，控件缺失时回退默认 1 秒；
    // clamp 保留为兜底，确保控件范围与定时器上下限常量始终一致。
    const double safeSeconds = (m_refreshIntervalSpin != nullptr)
        ? m_refreshIntervalSpin->value()
        : 1.0;
    const double clampedSeconds = std::clamp(
        safeSeconds,
        static_cast<double>(ActivityMinimumIntervalMilliseconds) / 1000.0,
        static_cast<double>(ActivityMaximumIntervalMilliseconds) / 1000.0);
    const int milliseconds = static_cast<int>(std::llround(clampedSeconds * 1000.0));
    return std::clamp(
        milliseconds,
        ActivityMinimumIntervalMilliseconds,
        ActivityMaximumIntervalMilliseconds);
}

void ProcessDock::applyRefreshIntervalInput()
{
    const int intervalMs = refreshIntervalMillisecondsFromInput();
    const double normalizedSeconds = static_cast<double>(intervalMs) / 1000.0;

    // 回写规范化后的值：控件范围与常量一致时是无变化写入，
    // 若将来两者出现偏差，界面显示的仍是定时器真正采用的间隔。
    if (m_refreshIntervalSpin != nullptr)
    {
        QSignalBlocker blocker(m_refreshIntervalSpin);
        m_refreshIntervalSpin->setValue(normalizedSeconds);
    }

    if (m_refreshTimer != nullptr)
    {
        m_refreshTimer->setInterval(intervalMs);
        if (m_monitoringEnabled && isProcessActivityRefreshAllowedNow())
        {
            m_refreshTimer->start(intervalMs);
        }
    }
    updateProcessActivityStatusLabel();

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 活动采样/后台监视间隔变更为 "
        << intervalMs
        << " ms。"
        << eol;
}

void ProcessDock::focusProcessSearchBox(const bool selectAllText)
{
    if (m_processSearchLineEdit == nullptr)
    {
        return;
    }

    // 使用 singleShot(0) 把聚焦动作延后到当前事件循环尾部：
    // - 避免与页签切换、显示事件内部的焦点竞争；
    // - 保证用户切页后第一时间就能直接输入搜索词。
    QPointer<QLineEdit> guardSearchLineEdit(m_processSearchLineEdit);
    QTimer::singleShot(0, this, [guardSearchLineEdit, selectAllText]() {
        if (guardSearchLineEdit == nullptr)
        {
            return;
        }

        guardSearchLineEdit->setFocus(Qt::ShortcutFocusReason);
        if (selectAllText)
        {
            guardSearchLineEdit->selectAll();
        }
    });
}

QString ProcessDock::currentProcessSearchText() const
{
    if (m_processSearchLineEdit == nullptr)
    {
        return QString();
    }

    return m_processSearchLineEdit->text().trimmed();
}

bool ProcessDock::processRecordMatchesSearch(const ks::process::ProcessRecord& processRecord) const
{
    const QString searchText = currentProcessSearchText();
    if (searchText.isEmpty())
    {
        return true;
    }

    // 显式 PID 过滤语法：
    // - 准星拾取会写入 pid:<数字>，保证只收敛到目标窗口所属进程；
    // - 普通纯数字输入仍保留原来的模糊搜索行为，不破坏用户既有习惯。
    const QString lowerSearchText = searchText.toLower();
    if (lowerSearchText.startsWith(QStringLiteral("pid:")) ||
        lowerSearchText.startsWith(QStringLiteral("pid=")))
    {
        bool pidParseOk = false;
        const std::uint32_t filterPid = searchText.mid(4).trimmed().toUInt(&pidParseOk);
        if (pidParseOk)
        {
            return processRecord.pid == filterPid;
        }
    }

    // 搜索字段覆盖：
    // - 进程名 / PID / 路径 / 命令行 / 用户 / 签名 / 启动时间 / 父 PID；
    // - 统一使用 contains(忽略大小写) 做模糊匹配，方便快速定位。
    const QStringList searchableFields{
        QString::fromStdString(processRecord.processName),
        QString::number(processRecord.pid),
        QString::fromStdString(processRecord.imagePath),
        QString::fromStdString(processRecord.r0ImagePath),
        QString::fromStdString(processRecord.commandLine),
        QString::fromStdString(processRecord.userName),
        QString::fromStdString(processRecord.signatureState),
        processR0StatusText(processRecord.r0Status),
        processFieldSourceText(processRecord.r0ProtectionSource),
        QString::fromStdString(processRecord.startTimeText),
        QString::number(processRecord.parentPid)
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

void ProcessDock::applyDefaultColumnWidths()
{
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Name), 280);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Pid), 80);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Cpu), 80);
    m_processTable->setColumnWidth(
        toColumnIndex(TableColumn::CpuCore),
        ks::ui::ProcessCpuCapacityCellSizeHint(
            m_processTable->fontMetrics(),
            m_logicalCpuCount).width());
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Ram), 90);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Disk), 95);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Gpu), 80);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Net), 95);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Signature), 260);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Path), 280);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::ParentPid), 90);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::CommandLine), 320);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::User), 180);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::StartTime), 160);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::IsAdmin), 90);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::PplLevel), 220);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Protection), 130);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Ppl), 120);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::HandleCount), 90);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::HandleTable), 180);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::SectionObject), 180);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::R0Status), 130);

    // ======== 任务管理器对齐列 ========
    // 宽度按“表头文案 + 典型取值”估算，用户拖动后由全局列宽自适应器保留手动值。
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::PackageName), 280);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Status), 90);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::SessionId), 80);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::JobObject), 100);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::CpuTime), 100);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::CycleTime), 140);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::WorkingSet), 120);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::PeakWorkingSet), 150);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::WorkingSetDelta), 150);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::ActivePrivateWorkingSet), 190);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::PrivateWorkingSet), 160);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::SharedWorkingSet), 160);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::CommitSize), 110);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::PagedPool), 120);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::NonPagedPool), 130);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::PageFaults), 110);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::PageFaultDelta), 130);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::BasePriority), 100);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::ThreadCount), 70);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::UserObjects), 90);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::GdiObjects), 90);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::IoReads), 100);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::IoWrites), 100);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::IoOther), 100);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::IoReadBytes), 130);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::IoWriteBytes), 130);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::IoOtherBytes), 130);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::OsContext), 140);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Platform), 90);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::UacVirtualization), 110);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::Description), 260);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::DataExecutionPrevention), 130);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::ControlFlowGuard), 120);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::HardwareStackProtection), 190);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::EnterpriseContext), 110);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::DpiAwareness), 130);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::PowerThrottling), 100);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::GpuEngine), 130);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::GpuDedicatedMemory), 140);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::GpuSharedMemory), 140);
    m_processTable->setColumnWidth(toColumnIndex(TableColumn::ProcessType), 110);
}

std::vector<int> ProcessDock::defaultVisibleColumnsForViewMode(const ViewMode viewMode)
{
    // 输入：内置视图预设。
    // 处理：给出该预设默认展示的列集合；每个预设都强制包含进程名与 PID。
    // 返回：列逻辑索引集合，是 applyViewMode 与“恢复默认”共用的唯一事实来源。
    std::vector<int> visibleColumns{
        toColumnIndex(TableColumn::Name),
        toColumnIndex(TableColumn::Pid)
    };

    const auto appendColumns = [&visibleColumns](const std::initializer_list<TableColumn> columns) -> void
        {
            for (const TableColumn column : columns)
            {
                visibleColumns.push_back(toColumnIndex(column));
            }
        };

    switch (viewMode)
    {
    case ViewMode::Detail:
        // 详细信息：静态与管理信息，不带性能计数器列。
        appendColumns({
            TableColumn::Status,
            TableColumn::Signature,
            TableColumn::Path,
            TableColumn::ParentPid,
            TableColumn::CommandLine,
            TableColumn::User,
            TableColumn::StartTime,
            TableColumn::IsAdmin,
            TableColumn::PplLevel,
            TableColumn::Description,
            TableColumn::Platform,
            TableColumn::Protection,
            TableColumn::Ppl,
            TableColumn::HandleTable,
            TableColumn::SectionObject,
            TableColumn::R0Status });
        break;

    case ViewMode::Memory:
        appendColumns({
            TableColumn::WorkingSet,
            TableColumn::PeakWorkingSet,
            TableColumn::WorkingSetDelta,
            TableColumn::ActivePrivateWorkingSet,
            TableColumn::PrivateWorkingSet,
            TableColumn::SharedWorkingSet,
            TableColumn::CommitSize,
            TableColumn::PagedPool,
            TableColumn::NonPagedPool,
            TableColumn::PageFaults,
            TableColumn::PageFaultDelta });
        break;

    case ViewMode::DiskIo:
        appendColumns({
            TableColumn::Disk,
            TableColumn::IoReads,
            TableColumn::IoWrites,
            TableColumn::IoOther,
            TableColumn::IoReadBytes,
            TableColumn::IoWriteBytes,
            TableColumn::IoOtherBytes });
        break;

    case ViewMode::Gpu:
        appendColumns({
            TableColumn::Gpu,
            TableColumn::GpuEngine,
            TableColumn::GpuDedicatedMemory,
            TableColumn::GpuSharedMemory,
            TableColumn::CpuTime,
            TableColumn::CycleTime });
        break;

    case ViewMode::Security:
        appendColumns({
            TableColumn::Signature,
            TableColumn::User,
            TableColumn::IsAdmin,
            TableColumn::PplLevel,
            TableColumn::UacVirtualization,
            TableColumn::DataExecutionPrevention,
            TableColumn::ControlFlowGuard,
            TableColumn::HardwareStackProtection,
            TableColumn::EnterpriseContext,
            TableColumn::JobObject,
            TableColumn::PackageName });
        break;

    case ViewMode::Kernel:
        appendColumns({
            TableColumn::Protection,
            TableColumn::Ppl,
            TableColumn::HandleTable,
            TableColumn::SectionObject,
            TableColumn::R0Status,
            TableColumn::SessionId,
            TableColumn::BasePriority,
            TableColumn::ThreadCount,
            TableColumn::HandleCount });
        break;

    case ViewMode::Monitor:
    default:
        appendColumns({
            TableColumn::Cpu,
            TableColumn::Ram,
            TableColumn::Disk,
            TableColumn::Gpu,
            TableColumn::Net,
            TableColumn::HandleCount,
            TableColumn::Protection,
            TableColumn::Ppl,
            TableColumn::HandleTable,
            TableColumn::SectionObject,
            TableColumn::R0Status,
            TableColumn::CpuCore });
        break;
    }

    return visibleColumns;
}

QString ProcessDock::viewModeDisplayName(const ViewMode viewMode)
{
    switch (viewMode)
    {
    case ViewMode::Detail:
        return processContextText("process.view.detail", QStringLiteral("详细信息视图"));
    case ViewMode::Memory:
        return processContextText("process.view.memory", QStringLiteral("内存视图"));
    case ViewMode::DiskIo:
        return processContextText("process.view.disk_io", QStringLiteral("磁盘 I/O 视图"));
    case ViewMode::Gpu:
        return processContextText("process.view.gpu", QStringLiteral("GPU 视图"));
    case ViewMode::Security:
        return processContextText("process.view.security", QStringLiteral("安全策略视图"));
    case ViewMode::Kernel:
        return processContextText("process.view.kernel", QStringLiteral("内核证据视图"));
    case ViewMode::Monitor:
    default:
        return processContextText("process.view.monitor", QStringLiteral("监视视图"));
    }
}

void ProcessDock::applyViewMode(const ViewMode viewMode)
{
    if (m_processTable == nullptr)
    {
        return;
    }

    const bool hideR0OnlyColumns = m_autoHideUnavailableR0Columns;

    // 先全部隐藏，再按预设打开目标列，保证状态可预测。
    for (int column = 0; column < static_cast<int>(TableColumn::Count); ++column)
    {
        m_processTable->setColumnHidden(column, true);
    }

    for (const int columnIndex : defaultVisibleColumnsForViewMode(viewMode))
    {
        if (columnIndex < 0 || columnIndex >= static_cast<int>(TableColumn::Count))
        {
            continue;
        }

        // R0 扩展整轮不可用时不展示内核专属列：整列都会是 Unavailable，没有信息量。
        if (hideR0OnlyColumns &&
            processColumnGroupOf(static_cast<TableColumn>(columnIndex)) == ProcessColumnGroup::Kernel)
        {
            continue;
        }
        m_processTable->setColumnHidden(columnIndex, false);
    }

    // 用户在“选择列”里添加/移除的列必须压在视图预设之上，
    // 否则每次切换视图都会把用户自己配的列冲掉。
    applyUserColumnVisibilityOverrides();
    applyAdaptiveColumnWidths();
}

void ProcessDock::applyCustomView(const int customIndex)
{
    if (m_processTable == nullptr ||
        customIndex < 0 ||
        customIndex >= static_cast<int>(m_customViews.size()))
    {
        return;
    }

    // 自定义视图直接定义完整列集合，因此不再叠加逐列覆盖：
    // 用户此后在“选择列”里的调整会重新写入覆盖表，并可另存为新的视图。
    m_userColumnVisibilityOverride.clear();

    const ProcessCustomView& customView = m_customViews[static_cast<std::size_t>(customIndex)];
    std::unordered_set<int> visibleColumnSet(
        customView.visibleColumns.begin(),
        customView.visibleColumns.end());
    // 进程名与 PID 是行标识，任何视图都必须保留。
    visibleColumnSet.insert(toColumnIndex(TableColumn::Name));
    visibleColumnSet.insert(toColumnIndex(TableColumn::Pid));

    for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::Count); ++columnIndex)
    {
        bool shouldShow = (visibleColumnSet.find(columnIndex) != visibleColumnSet.end());
        if (shouldShow &&
            m_autoHideUnavailableR0Columns &&
            processColumnGroupOf(static_cast<TableColumn>(columnIndex)) == ProcessColumnGroup::Kernel)
        {
            shouldShow = false;
        }
        m_processTable->setColumnHidden(columnIndex, !shouldShow);
    }

    saveProcessColumnLayoutToSettings();
    applyAdaptiveColumnWidths();

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 已应用自定义视图, name=" << customView.name.toStdString()
        << ", columnCount=" << visibleColumnSet.size()
        << eol;
}

void ProcessDock::applyAdaptiveColumnWidths()
{
    // 该函数作用：
    // - 只把进程表列切到可交互模式，并请求全局列宽自适应器按 viewport 压缩默认宽度；
    // - 不再强制 Stretch，也不修改滚动条策略，用户拖宽列后允许横向滚动条自然出现；
    // - 若用户已经手动调整过列宽，全局自适应器会跳过本次请求以保留用户宽度。
    if (m_processTable == nullptr)
    {
        return;
    }

    QHeaderView* headerView = m_processTable->horizontalHeader();
    if (headerView == nullptr)
    {
        return;
    }

    headerView->setStretchLastSection(false);
    for (int column = 0; column < static_cast<int>(TableColumn::Count); ++column)
    {
        headerView->setSectionResizeMode(column, QHeaderView::Interactive);
    }

    ks::ui::RequestTableColumnAutoFit(m_processTable);
}

void ProcessDock::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);

    // Dock 尺寸变化后只请求一次默认自适应：
    // - 未手动调列宽时压入 viewport；
    // - 已手动调列宽时保留用户宽度，横向滚动条按需出现。
    applyAdaptiveColumnWidths();
}

void ProcessDock::requestAsyncRefresh(const bool forceRefresh)
{
    // 需求：每次刷新前都检测 Ctrl，按下则跳过本轮（无论是否强制刷新）。
    if ((::GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0)
    {
        kLogEvent logEvent;
        dbg << logEvent << "[ProcessDock] 检测到 Ctrl 按下，本轮刷新跳过。" << eol;
        return;
    }

    // 非强制刷新时，暂停监视或正在刷新则直接跳过。
    if (!forceRefresh)
    {
        // 右键菜单弹出期间冻结周期刷新，防止菜单绑定项被重建后失效。
        if (m_contextMenuVisible)
        {
            kLogEvent logEvent;
            dbg << logEvent << "[ProcessDock] 右键菜单处于打开状态，本轮刷新跳过。" << eol;
            return;
        }

        if (!m_monitoringEnabled || m_refreshInProgress)
        {
            kLogEvent logEvent;
            dbg << logEvent
                << "[ProcessDock] 跳过非强制刷新, monitoringEnabled=" << (m_monitoringEnabled ? "true" : "false")
                << ", refreshInProgress=" << (m_refreshInProgress ? "true" : "false")
                << eol;
            return;
        }

        // “不记录历史”只影响是否写入活动样本，不应阻断后台列表刷新。
        if (!isProcessActivityRefreshAllowedNow())
        {
            kLogEvent logEvent;
            dbg << logEvent << "[ProcessDock] 跳过非强制刷新：监视未启用。" << eol;
            updateProcessActivityStatusLabel();
            return;
        }
    }

    // 强制刷新也要避免并发任务叠加。
    if (m_refreshInProgress)
    {
        kLogEvent logEvent;
        dbg << logEvent << "[ProcessDock] 跳过刷新：当前已有后台刷新任务在执行。" << eol;
        return;
    }
    m_refreshInProgress = true;

    // 进程页不再暴露策略选择，但继续固定使用现有 NtQuery 枚举实现。
    constexpr int strategyIndex = static_cast<int>(ks::process::ProcessEnumStrategy::NtQuerySystemInfo);
    // 静态详情预算按“当前是否真的显示了需要打开进程才能补齐的列”判定，
    // 而不是绑定在某个具体视图上：用户在任意视图手动加上命令行/描述列时同样需要补齐。
    const bool detailModeEnabled = isStaticDetailIntensiveViewActive();
    // 每轮在驱动控制设备就绪时进行 R0/R3 对比；R3 状态仅保留用户态列表并静默跳过。
    constexpr bool queryKernelProcessList = true;
    const bool isFirstRefresh = m_cacheByIdentity.empty();
    const int staticDetailFillBudget =
        detailModeEnabled
        ? (isFirstRefresh ? 96 : 48)   // 详细视图也做预算控制，避免首轮全量静态查询导致 UI 抖动。
        : (isFirstRefresh ? 8 : 4);    // 监视视图优先速度，预算更小。
    // 按需采集位图：
    // - 只有用户真正显示了 GDI 对象、作业、缓解策略、显存等列时，才让后台为它们付出额外句柄/PDH 成本；
    // - 默认列布局下该值为 0，刷新开销与补齐这些列之前完全一致。
    const std::uint32_t detailDemandFlags = currentProcessDetailDemandFlags();
    const std::uint32_t cpuCount = m_logicalCpuCount;
    auto previousCache = m_cacheByIdentity;
    auto previousCounters = m_counterSampleByIdentity;
    ensureProcessNetworkTrafficCaptureStarted();
    auto networkTrafficSnapshot = snapshotProcessNetworkTrafficCounters();
    // CPU核心列可见或详情窗口需要数据时，才常驻同一个系统级 CSwitch 会话。
    // 强制刷新若来自隐藏页面或不需要逐核心数据，也不能偷偷保留高频会话。
    const bool cpuCoreUsageDemanded =
        isProcessColumnVisible(TableColumn::CpuCore) ||
        std::any_of(
            m_detailWindowByIdentity.cbegin(),
            m_detailWindowByIdentity.cend(),
            [](const auto& detailWindowPair)
            {
                return detailWindowPair.second != nullptr;
            });
    const bool cpuCoreCaptureAllowed =
        isProcessActivityRefreshAllowedNow() && cpuCoreUsageDemanded;
    if (cpuCoreCaptureAllowed)
    {
        ensureCpuCoreUsageCaptureStarted();
    }
    else if (m_cpuCoreUsageCaptureStarted)
    {
        stopCpuCoreUsageCapture();
    }
    const std::shared_ptr<ks::process::ProcessCpuCoreEtwMonitor> cpuCoreUsageService =
        cpuCoreCaptureAllowed ? m_cpuCoreUsageService : nullptr;
    const std::chrono::steady_clock::time_point cpuCoreSnapshotNow =
        std::chrono::steady_clock::now();
    const bool cpuCoreSnapshotDue =
        cpuCoreUsageService != nullptr &&
        (m_lastCpuCoreUsageSnapshotTime.time_since_epoch().count() == 0 ||
            std::chrono::duration_cast<std::chrono::milliseconds>(
                cpuCoreSnapshotNow - m_lastCpuCoreUsageSnapshotTime).count() >=
                CpuCoreSnapshotMinimumIntervalMilliseconds);
    if (cpuCoreSnapshotDue)
    {
        // 投递时就更新时间，刷新任务本身互斥，因此不会并发生成两份逐核心矩阵。
        m_lastCpuCoreUsageSnapshotTime = cpuCoreSnapshotNow;
    }
    const std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> previousCpuCoreUsageSnapshot =
        m_latestCpuCoreUsageSnapshot;

    // ticket 用于丢弃过期结果（防止乱序覆盖）。
    const std::uint64_t localTicket = ++m_refreshTicket;
    m_lastRefreshStartTime = std::chrono::steady_clock::now();
    QPointer<ProcessDock> guard(this);

    {
        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 进程监视刷新开始, ticket=" << localTicket
            << ", force=" << (forceRefresh ? "true" : "false")
            << ", strategy=" << strategyToText(toStrategy(strategyIndex))
            << ", detailMode=" << (detailModeEnabled ? "true" : "false")
            << ", kernelCompare=" << (queryKernelProcessList ? "true" : "false")
            << ", staticBudget=" << staticDetailFillBudget
            << ", cacheSize=" << previousCache.size()
            << ", refreshIntervalMs=" << refreshIntervalMillisecondsFromInput()
            << eol;
    }

    // QRunnable + 线程池：满足“异步刷新，不阻塞 GUI”。
    // 注意：forceUiRefresh 必须在进入后台 lambda 前保存成局部值；
    // 否则内层 QueuedConnection lambda 在工作线程里无法再引用 requestAsyncRefresh 的参数。
    const bool forceUiRefresh = forceRefresh;
    QRunnable* backgroundTask = QRunnable::create([
        guard,
        localTicket,
        strategyIndex,
        detailModeEnabled,
        queryKernelProcessList,
        staticDetailFillBudget,
        detailDemandFlags,
        cpuCount,
        forceUiRefresh,
        previousCache = std::move(previousCache),
        previousCounters = std::move(previousCounters),
        networkTrafficSnapshot = std::move(networkTrafficSnapshot),
        cpuCoreUsageService,
        cpuCoreSnapshotDue,
        previousCpuCoreUsageSnapshot]() mutable {
        // 先在工作线程构造完整 PID/TID×核心快照，ETW 回调锁竞争不会占用 GUI 事件循环。
        std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> cpuCoreUsageSnapshot =
            previousCpuCoreUsageSnapshot;
        if (cpuCoreUsageService != nullptr && cpuCoreSnapshotDue)
        {
            // 即使异步 Start 尚未完成也取得带处理器拓扑的失效态快照，让 UI 画灰槽而非假 0%。
            cpuCoreUsageSnapshot = std::make_shared<ks::process::CpuCoreUsageSnapshot>(
                cpuCoreUsageService->SnapshotAndReset());
        }

        ProcessDock::RefreshResult refreshResult = ProcessDock::buildRefreshResult(
            strategyIndex,
            detailModeEnabled,
            queryKernelProcessList,
            staticDetailFillBudget,
            detailDemandFlags,
            localTicket,
            previousCache,
            previousCounters,
            networkTrafficSnapshot,
            cpuCount);
        refreshResult.cpuCoreUsageSnapshot = std::move(cpuCoreUsageSnapshot);

        if (guard == nullptr)
        {
            return;
        }

        // 结果通过队列连接回主线程更新 UI。
        QMetaObject::invokeMethod(guard, [
            guard,
            localTicket,
            refreshResult = std::move(refreshResult),
            forceUiRefresh]() mutable {
            if (guard == nullptr)
            {
                return;
            }

            // 只接受最新 ticket 的结果，旧结果直接丢弃。
            if (localTicket < guard->m_refreshTicket)
            {
                guard->m_refreshInProgress = false;
                return;
            }

            guard->applyRefreshResult(std::move(refreshResult), forceUiRefresh);
            guard->m_refreshInProgress = false;
        }, Qt::QueuedConnection);
    });

    backgroundTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(backgroundTask);
}

void ProcessDock::applyRefreshResult(RefreshResult refreshResult, const bool forceUiRefresh)
{
    // 后台快照不仅会重建模型，也会先替换菜单动作查询使用的进程缓存。
    // 菜单打开时把整次提交延后，避免旧行与新缓存短暂错配。
    if (ks::ui::IsTableUiCommitBlockedByContextMenu({m_processTable}))
    {
        auto deferredResult = std::make_shared<RefreshResult>(std::move(refreshResult));
        const QPointer<ProcessDock> safeThis(this);
        if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("process-main-refresh-result"),
                {m_processTable},
                [safeThis, deferredResult, forceUiRefresh]() mutable
                {
                    if (!safeThis.isNull())
                    {
                        safeThis->applyRefreshResult(std::move(*deferredResult), forceUiRefresh);
                    }
                }))
        {
            return;
        }
        refreshResult = std::move(*deferredResult);
    }

    // 计算主线程观测耗时，用于“刷新状态标签”和日志输出。
    const auto nowTime = std::chrono::steady_clock::now();
    const auto elapsedMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(nowTime - m_lastRefreshStartTime).count());

    restorePersistedAffinityForNewProcesses(refreshResult);

    // 逐核心快照与本轮进程缓存来自同一次 ticket；暂停后到达的旧结果不得复活最后一帧。
    const std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> previousCpuCoreSnapshot =
        m_latestCpuCoreUsageSnapshot;
    if (m_monitoringEnabled &&
        m_cpuCoreUsageCaptureDesired->load(std::memory_order_acquire))
    {
        m_latestCpuCoreUsageSnapshot = std::move(refreshResult.cpuCoreUsageSnapshot);
    }
    else
    {
        m_latestCpuCoreUsageSnapshot.reset();
    }
    const bool cpuCoreSnapshotChanged =
        previousCpuCoreSnapshot != m_latestCpuCoreUsageSnapshot;

    // 把最新进程数据同步到已打开的详情窗口（若对应进程仍存在）。
    // 性能策略：
    // 1) 仅同步“可见且未最小化”的详情窗口；
    // 2) 轻微变化由节流器吸收，避免每轮刷新都触发重型解析链路。
    const std::chrono::milliseconds detailWindowSyncInterval(1500);
    for (auto windowIt = m_detailWindowByIdentity.begin(); windowIt != m_detailWindowByIdentity.end();)
    {
        if (windowIt->second == nullptr)
        {
            m_detailWindowLastSyncTimeByIdentity.erase(windowIt->first);
            windowIt = m_detailWindowByIdentity.erase(windowIt);
            continue;
        }

        const QPointer<ProcessDetailWindow>& detailWindow = windowIt->second;
        if (!detailWindow->isVisible() || detailWindow->isMinimized())
        {
            ++windowIt;
            continue;
        }

        const auto nextCacheIt = refreshResult.nextCache.find(windowIt->first);
        if (nextCacheIt == refreshResult.nextCache.end())
        {
            ++windowIt;
            continue;
        }

        const auto previousCacheIt = m_cacheByIdentity.find(windowIt->first);
        const bool hasSignificantChange =
            (previousCacheIt == m_cacheByIdentity.end()) ||
            hasDetailWindowSignificantChange(previousCacheIt->second.record, nextCacheIt->second.record);

        const auto lastSyncIt = m_detailWindowLastSyncTimeByIdentity.find(windowIt->first);
        const bool reachPeriodicSyncTime =
            (lastSyncIt == m_detailWindowLastSyncTimeByIdentity.end()) ||
            (std::chrono::duration_cast<std::chrono::milliseconds>(nowTime - lastSyncIt->second) >= detailWindowSyncInterval);

        if (hasSignificantChange || reachPeriodicSyncTime)
        {
            detailWindow->updateBaseRecord(nextCacheIt->second.record);
            syncCpuCoreUsageToDetailWindow(detailWindow, nextCacheIt->second.record);
            m_detailWindowLastSyncTimeByIdentity[windowIt->first] = nowTime;
        }
        ++windowIt;
    }

    // 用新结果替换缓存；表格重绘由独立“列表刷新(s)”节流，避免高频打点拖垮 UI。
    m_cacheByIdentity = std::move(refreshResult.nextCache);
    m_counterSampleByIdentity = std::move(refreshResult.nextCounters);
    pruneProcessNetworkTrafficCounters();

    // 每轮刷新立即为全部进程映像投递后台图标查询，表格不再等待滚动空闲期。
    queueProcessIconExtractionsForCurrentProcesses();

    appendProcessActivitySample();
    if (isProcessActivityTableSnapshotActive())
    {
        rebuildProcessActivityTableSnapshotRecords();
    }
    const bool processTableRebuilt = shouldRebuildProcessTableForRefresh(forceUiRefresh);
    if (processTableRebuilt)
    {
        rebuildTable();
        m_lastProcessTableRebuildTime = nowTime;
    }
    else if (cpuCoreSnapshotChanged &&
        m_processTable != nullptr &&
        m_processTable->viewport() != nullptr)
    {
        // 逐核心快照独立于整表 2 秒节流：只重绘 CPU 列可见矩形，不触碰其它列或模型行。
        const int cpuColumn = toColumnIndex(TableColumn::CpuCore);
        const int cpuColumnLeft = m_processTable->columnViewportPosition(cpuColumn);
        const int cpuColumnWidth = m_processTable->columnWidth(cpuColumn);
        const QRect cpuViewportRect(
            cpuColumnLeft,
            0,
            cpuColumnWidth,
            m_processTable->viewport()->height());
        m_processTable->viewport()->update(
            cpuViewportRect.intersected(m_processTable->viewport()->rect()));
    }
    if (m_sideTabWidget != nullptr && m_sideTabWidget->currentWidget() == m_threadPage)
    {
        requestAsyncThreadRefresh(false);
    }

    // 输出详细刷新日志，便于后续性能与正确性排查。
    {
        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 刷新完成, elapsedMs(main)=" << elapsedMs
            << ", elapsedMs(worker)=" << refreshResult.workerElapsedMs
            << ", strategySelected=" << strategyToText(refreshResult.selectedStrategy)
            << ", strategyActual=" << strategyToText(refreshResult.actualStrategy)
            << ", enumerated=" << refreshResult.enumeratedCount
            << ", reused=" << refreshResult.reusedProcessCount
            << ", new=" << refreshResult.newProcessCount
            << ", exitedHold=" << refreshResult.exitedProcessCount
            << ", staticFilled=" << refreshResult.staticFilledCount
            << ", staticDeferred=" << refreshResult.staticDeferredCount
            << ", imagePathFilled=" << refreshResult.imagePathFilledCount
            << ", kernelCompareEnabled=" << (refreshResult.kernelCompareEnabled ? "true" : "false")
            << ", kernelQuerySucceeded=" << (refreshResult.kernelQuerySucceeded ? "true" : "false")
            << ", kernelEnumerated=" << refreshResult.kernelEnumeratedCount
            << ", kernelOnly=" << refreshResult.kernelOnlyCount
            << ", kernelDetail=" << refreshResult.kernelQueryDetailText
            << ", cacheNow=" << m_cacheByIdentity.size()
            << ", uiRebuildForced=" << (forceUiRefresh ? "true" : "false")
            << eol;
    }
}

void ProcessDock::restorePersistedAffinityForNewProcesses(RefreshResult& refreshResult)
{
    // currentIdentityKeys：用于清理已经退出进程的完成与退避记录。
    std::unordered_set<std::string> currentIdentityKeys;
    currentIdentityKeys.reserve(refreshResult.nextCache.size());

    // nowTime：整轮恢复共用单调时间，保证同一刷新中的退避判断一致。
    const std::chrono::steady_clock::time_point nowTime = std::chrono::steady_clock::now();

    // restoredRuleCount：统计本轮成功应用的持久化规则数量。
    std::size_t restoredRuleCount = 0U;

    // failedRuleCount：统计本轮实际尝试后失败的规则数量。
    std::size_t failedRuleCount = 0U;

    for (const auto& cachePair : refreshResult.nextCache)
    {
        // identityKey：PID 与创建时间组成的进程实例稳定标识。
        const std::string& identityKey = cachePair.first;

        // cacheEntry：本轮刷新得到的进程缓存条目。
        const CacheEntry& cacheEntry = cachePair.second;
        currentIdentityKeys.insert(identityKey);
        if (cacheEntry.isExitedInLatestRound || cacheEntry.isKernelOnlyInLatestRound ||
            cacheEntry.record.pid == 0U || cacheEntry.record.imagePath.empty() ||
            m_affinityRestoreCompletedIdentityKeys.find(identityKey) !=
                m_affinityRestoreCompletedIdentityKeys.end())
        {
            continue;
        }

        // retryIt：若上次恢复失败，用于判断本轮是否已到重试时间。
        const auto retryIt = m_affinityRestoreRetryByIdentity.find(identityKey);
        if (retryIt != m_affinityRestoreRetryByIdentity.end() &&
            nowTime < retryIt->second.nextAttemptTime)
        {
            continue;
        }

        // ruleFound：区分“明确无规则”和读取/应用失败，避免把失败误记为完成。
        bool ruleFound = false;

        // detailText：接收注册表读取、句柄打开或亲和性设置的诊断信息。
        std::string detailText;

        // restoreOk：仅当规则读取与实际应用均成功时为 true。
        const bool restoreOk = ks::process::restorePersistedProcessAffinityRule(
            static_cast<DWORD>(cacheEntry.record.pid),
            cacheEntry.record.imagePath,
            &ruleFound,
            &detailText);

        // 成功且明确没有规则时完成记账，不再重复查询同一进程实例。
        if (restoreOk && !ruleFound)
        {
            m_affinityRestoreCompletedIdentityKeys.insert(identityKey);
            m_affinityRestoreRetryByIdentity.erase(identityKey);
            continue;
        }

        // restoreEvent：让每次实际恢复及其诊断信息共享一个可追踪日志事件。
        kLogEvent restoreEvent;
        (restoreOk ? info : warn) << restoreEvent
            << "[ProcessDock] persisted CPU affinity restore, pid=" << cacheEntry.record.pid
            << ", imagePath=" << cacheEntry.record.imagePath
            << ", ok=" << (restoreOk ? "true" : "false")
            << ", detail=" << (detailText.empty() ? "none" : detailText) << eol;
        if (restoreOk)
        {
            m_affinityRestoreCompletedIdentityKeys.insert(identityKey);
            m_affinityRestoreRetryByIdentity.erase(identityKey);
            ++restoredRuleCount;
        }
        else
        {
            // retryState：保存本进程实例的连续失败次数与下一次重试时间。
            AffinityRestoreRetryState& retryState =
                m_affinityRestoreRetryByIdentity[identityKey];
            if (retryState.consecutiveFailureCount < std::numeric_limits<std::uint32_t>::max())
            {
                ++retryState.consecutiveFailureCount;
            }

            // retryDelay：失败次数对应的有上限指数退避时长。
            const std::chrono::milliseconds retryDelay =
                affinityRestoreRetryDelay(retryState.consecutiveFailureCount);
            retryState.nextAttemptTime = nowTime + retryDelay;

            // retryEvent：记录自动恢复仍会继续，以及下一次允许尝试的等待时间。
            kLogEvent retryEvent;
            warn << retryEvent
                << "[ProcessDock] persisted CPU affinity restore will retry, pid="
                << cacheEntry.record.pid
                << ", failureCount=" << retryState.consecutiveFailureCount
                << ", retryAfterMs=" << retryDelay.count()
                << eol;
            ++failedRuleCount;
        }
    }

    // 进程退出后清除完成记录，使未来复用 PID 但创建时间不同的实例独立判断。
    for (auto it = m_affinityRestoreCompletedIdentityKeys.begin();
         it != m_affinityRestoreCompletedIdentityKeys.end();)
    {
        if (currentIdentityKeys.find(*it) == currentIdentityKeys.end())
        {
            it = m_affinityRestoreCompletedIdentityKeys.erase(it);
        }
        else
        {
            ++it;
        }
    }

    // 同步清理退出进程的失败退避状态，避免长时间运行后积累无效 identity。
    for (auto it = m_affinityRestoreRetryByIdentity.begin();
         it != m_affinityRestoreRetryByIdentity.end();)
    {
        if (currentIdentityKeys.find(it->first) == currentIdentityKeys.end())
        {
            it = m_affinityRestoreRetryByIdentity.erase(it);
        }
        else
        {
            ++it;
        }
    }

    if (restoredRuleCount != 0U || failedRuleCount != 0U)
    {
        kLogEvent restoreSummaryEvent;
        (failedRuleCount == 0U ? info : warn) << restoreSummaryEvent
            << "[ProcessDock] persisted CPU affinity restore summary, restored=" << restoredRuleCount
            << ", failed=" << failedRuleCount << eol;
    }
}

bool ProcessDock::shouldRebuildProcessTableForRefresh(const bool forceUiRefresh) const
{
    // 强制刷新、历史快照表格、首轮显示必须立刻重绘。
    if (forceUiRefresh || isProcessActivityTableSnapshotActive() || m_lastProcessTableRebuildTime.time_since_epoch().count() == 0)
    {
        return true;
    }

    // 后台监视按统一刷新间隔节流表格重绘。
    const int intervalMs = refreshIntervalMillisecondsFromInput();
    const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - m_lastProcessTableRebuildTime).count();
    return elapsedMs >= intervalMs;
}

ProcessDock::RefreshResult ProcessDock::buildRefreshResult(
    const int strategyIndex,
    const bool detailModeEnabled,
    const bool queryKernelProcessList,
    const int staticDetailFillBudget,
    const std::uint32_t detailDemandFlags,
    const std::uint64_t refreshTicket,
    const std::unordered_map<std::string, CacheEntry>& previousCache,
    const std::unordered_map<std::string, ks::process::CounterSample>& previousCounters,
    const std::unordered_map<std::uint32_t, ProcessDock::NetworkTrafficCounters>& networkTrafficSnapshot,
    const std::uint32_t logicalCpuCount)
{
    const auto workerStartTime = std::chrono::steady_clock::now();

    RefreshResult refreshResult;
    refreshResult.nextCache.clear();
    refreshResult.nextCounters.clear();
    refreshResult.selectedStrategyIndex = strategyIndex;
    refreshResult.selectedStrategy = toStrategy(strategyIndex);
    refreshResult.actualStrategy = refreshResult.selectedStrategy;
    refreshResult.detailModeEnabled = detailModeEnabled;
    refreshResult.kernelCompareEnabled = queryKernelProcessList;

    const ks::process::ProcessEnumStrategy strategy = toStrategy(strategyIndex);
    std::vector<ks::process::ProcessRecord> latestProcessList = ks::process::EnumerateProcesses(
        strategy,
        &refreshResult.actualStrategy,
        detailDemandFlags & ks::process::ProcessDetailDemand::GpuMask);
    const std::uint64_t sampleTick = steadyNow100ns();
    std::unordered_set<std::uint32_t> kernelOnlyPidSet;
    std::unordered_map<std::uint32_t, KernelProcessSnapshotEntry> kernelProcessByPid;

    // 可选阶段：向 R0 请求内核进程列表，并追加“仅内核可见”的记录。
    if (queryKernelProcessList)
    {
        std::vector<KernelProcessSnapshotEntry> kernelProcessList;
        std::string kernelQueryDetailText;
        const bool queryKernelOk = enumerateProcessesByR0Driver(&kernelProcessList, &kernelQueryDetailText);
        refreshResult.kernelQuerySucceeded = queryKernelOk;
        refreshResult.kernelQueryDetailText = kernelQueryDetailText;
        refreshResult.kernelEnumeratedCount = kernelProcessList.size();

        if (queryKernelOk)
        {
            std::unordered_set<std::uint32_t> userPidSet;
            userPidSet.reserve(latestProcessList.size() * 2 + 1);
            kernelProcessByPid.reserve(kernelProcessList.size() * 2 + 1);
            for (const KernelProcessSnapshotEntry& kernelProcess : kernelProcessList)
            {
                kernelProcessByPid[kernelProcess.processId] = kernelProcess;
            }
            for (const ks::process::ProcessRecord& processRecord : latestProcessList)
            {
                userPidSet.insert(processRecord.pid);
            }

            for (const KernelProcessSnapshotEntry& kernelProcess : kernelProcessList)
            {
                if (userPidSet.find(kernelProcess.processId) != userPidSet.end())
                {
                    continue;
                }
                userPidSet.insert(kernelProcess.processId);

                ks::process::ProcessRecord kernelOnlyRecord{};
                kernelOnlyRecord.pid = kernelProcess.processId;
                kernelOnlyRecord.parentPid = kernelProcess.parentProcessId;
                mergeKernelProcessExtension(kernelOnlyRecord, kernelProcess);
                const bool cidTableWeakEvidence =
                    (kernelProcess.flags &
                        (KSWORD_ARK_PROCESS_FLAG_CID_TABLE_REFERENCE_FAILED |
                            KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED)) != 0U;
                kernelOnlyRecord.creationTime100ns = kernelProcess.creationTime100ns != 0ULL
                    ? kernelProcess.creationTime100ns
                    : KernelOnlyCreationTimeSeed + static_cast<std::uint64_t>(kernelProcess.processId);
                kernelOnlyRecord.processName = kernelProcess.imageName.empty()
                    ? std::string("[R0] Unknown")
                    : std::string("[R0] ") + kernelProcess.imageName;
                kernelOnlyRecord.imagePath = cidTableWeakEvidence
                    ? "[CID Table命中：对象引用失败或已退出]"
                    : "[仅内核枚举可见]";
                kernelOnlyRecord.commandLine = cidTableWeakEvidence
                    ? "[CID Table命中：保留显示，可尝试R0结束]"
                    : "[仅内核枚举可见]";
                kernelOnlyRecord.userName = "-";
                kernelOnlyRecord.signatureState = cidTableWeakEvidence
                    ? "CIDTable(Weak)"
                    : "KernelOnly(Hidden?)";
                kernelOnlyRecord.signaturePublisher.clear();
                kernelOnlyRecord.signatureTrusted = false;
                kernelOnlyRecord.startTimeText = "-";
                kernelOnlyRecord.architectureText = "Unknown";
                kernelOnlyRecord.priorityText = "-";
                kernelOnlyRecord.isAdmin = false;
                kernelOnlyRecord.dynamicCountersReady = true;
                kernelOnlyRecord.staticDetailsReady = true;

                latestProcessList.push_back(std::move(kernelOnlyRecord));
                kernelOnlyPidSet.insert(kernelProcess.processId);
                ++refreshResult.kernelOnlyCount;
            }
        }
        else if (refreshResult.kernelQueryDetailText.empty())
        {
            refreshResult.kernelQueryDetailText = "query kernel process list failed";
        }
    }

    refreshResult.enumeratedCount = latestProcessList.size();

    // 静态详情预算控制：
    // - 预算用于限制“路径/命令行/用户/签名”等慢操作，避免首轮刷新过慢；
    // - 监视模式预算较低，详细模式预算较高。
    const std::size_t staticFillBudget = static_cast<std::size_t>(std::max(0, staticDetailFillBudget));

    // 第一阶段：预处理 identity、复用旧字段，并筛选“需要补静态详情”的 PID 列表。
    std::vector<std::string> identityKeys(latestProcessList.size());
    std::vector<bool> isNewProcess(latestProcessList.size(), false);
    std::vector<bool> shouldFillStatic(latestProcessList.size(), false);
    std::vector<bool> includeSignatureList(latestProcessList.size(), false);
    std::vector<bool> isStaticFillCandidate(latestProcessList.size(), false);
    std::vector<char> staticFillSucceeded(latestProcessList.size(), 0);

    for (std::size_t recordIndex = 0; recordIndex < latestProcessList.size(); ++recordIndex)
    {
        ks::process::ProcessRecord& processRecord = latestProcessList[recordIndex];

        // 若 creationTime 未取到，仍可用 0 参与 key（稳定但区分度降低）。
        const std::string identityKey = ks::process::BuildProcessIdentityKey(
            processRecord.pid,
            processRecord.creationTime100ns);
        identityKeys[recordIndex] = identityKey;

        const auto oldCacheIt = previousCache.find(identityKey);
        const bool isKernelOnlyRecord =
            (kernelOnlyPidSet.find(processRecord.pid) != kernelOnlyPidSet.end());
        bool needsStaticFill = false;
        bool includeSignatureCheck = false;
        if (oldCacheIt != previousCache.end())
        {
            // 复用规则：PID + 创建时间相同则复用旧静态字段（性能计数器除外）。
            const ks::process::ProcessRecord& oldRecord = oldCacheIt->second.record;
            if (processRecord.imagePath.empty()) processRecord.imagePath = oldRecord.imagePath;
            if (processRecord.commandLine.empty()) processRecord.commandLine = oldRecord.commandLine;
            if (processRecord.userName.empty()) processRecord.userName = oldRecord.userName;
            if (processRecord.signatureState.empty()) processRecord.signatureState = oldRecord.signatureState;
            if (processRecord.signaturePublisher.empty()) processRecord.signaturePublisher = oldRecord.signaturePublisher;
            if (processRecord.r0FieldFlags == 0U) processRecord.r0FieldFlags = oldRecord.r0FieldFlags;
            if (processRecord.r0ImagePath.empty()) processRecord.r0ImagePath = oldRecord.r0ImagePath;
            if (processRecord.r0Status == KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE) processRecord.r0Status = oldRecord.r0Status;
            // PPL 保护级别枚举是手动刷新字段，不能从上一轮缓存继承。
            processRecord.protectionLevelKnown = false;
            processRecord.protectionLevel = 0;
            processRecord.protectionLevelText.clear();
            processRecord.r0Flags = oldRecord.r0Flags;
            processRecord.r0DynDataCapabilityMask = oldRecord.r0DynDataCapabilityMask;
            processRecord.r0Protection = oldRecord.r0Protection;
            processRecord.r0SignatureLevel = oldRecord.r0SignatureLevel;
            processRecord.r0SectionSignatureLevel = oldRecord.r0SectionSignatureLevel;
            processRecord.r0SessionSource = oldRecord.r0SessionSource;
            processRecord.r0ImagePathSource = oldRecord.r0ImagePathSource;
            processRecord.r0ProtectionSource = oldRecord.r0ProtectionSource;
            processRecord.r0SignatureLevelSource = oldRecord.r0SignatureLevelSource;
            processRecord.r0SectionSignatureLevelSource = oldRecord.r0SectionSignatureLevelSource;
            processRecord.r0ObjectTableSource = oldRecord.r0ObjectTableSource;
            processRecord.r0SectionObjectSource = oldRecord.r0SectionObjectSource;
            processRecord.r0ProtectionOffset = oldRecord.r0ProtectionOffset;
            processRecord.r0SignatureLevelOffset = oldRecord.r0SignatureLevelOffset;
            processRecord.r0SectionSignatureLevelOffset = oldRecord.r0SectionSignatureLevelOffset;
            processRecord.r0ObjectTableOffset = oldRecord.r0ObjectTableOffset;
            processRecord.r0SectionObjectOffset = oldRecord.r0SectionObjectOffset;
            processRecord.r0ObjectTableAddress = oldRecord.r0ObjectTableAddress;
            processRecord.r0SectionObjectAddress = oldRecord.r0SectionObjectAddress;
            processRecord.signatureTrusted = oldRecord.signatureTrusted;
            if (processRecord.startTimeText.empty()) processRecord.startTimeText = oldRecord.startTimeText;
            processRecord.isAdmin = oldRecord.isAdmin;
            processRecord.staticDetailsReady = oldRecord.staticDetailsReady;

            // 任务管理器对齐列中的“进程生命周期内不变”字段同样走复用路径，
            // 这样它们只在进程首次出现时采集一次，后续刷新零成本。
            processRecord.inJobObject = oldRecord.inJobObject;
            processRecord.jobObjectKnown = oldRecord.jobObjectKnown;
            processRecord.uacVirtualizationState = oldRecord.uacVirtualizationState;
            processRecord.dataExecutionPreventionState = oldRecord.dataExecutionPreventionState;
            processRecord.controlFlowGuardState = oldRecord.controlFlowGuardState;
            processRecord.hardwareStackProtectionState = oldRecord.hardwareStackProtectionState;
            processRecord.dpiAwarenessLevel = oldRecord.dpiAwarenessLevel;
            processRecord.packageNameKnown = oldRecord.packageNameKnown;
            if (processRecord.packageFullName.empty()) processRecord.packageFullName = oldRecord.packageFullName;
            if (processRecord.fileDescription.empty()) processRecord.fileDescription = oldRecord.fileDescription;
            if (processRecord.osContextText.empty()) processRecord.osContextText = oldRecord.osContextText;
            if (processRecord.enterpriseContextText.empty()) processRecord.enterpriseContextText = oldRecord.enterpriseContextText;
            if (processRecord.architectureText.empty()) processRecord.architectureText = oldRecord.architectureText;

            // GUI 资源计数是动态值：这里先继承旧值避免列在两轮之间闪烁，
            // 本轮若仍被请求会立即覆盖为最新数字。
            processRecord.gdiObjectCount = oldRecord.gdiObjectCount;
            processRecord.userObjectCount = oldRecord.userObjectCount;
            processRecord.guiResourceKnown = oldRecord.guiResourceKnown;
            ++refreshResult.reusedProcessCount;

            // 旧进程若静态字段还不完整，或签名仍 Pending，则进入“待补齐候选”。
            // 对持续失败的进程做退避，避免反复占满预算导致其它进程长期 Pending。
            const bool signaturePending = (processRecord.signatureState.empty() || processRecord.signatureState == "Pending");
            const bool baseNeedsStaticFill = !processRecord.staticDetailsReady || (detailModeEnabled && signaturePending);
            const std::uint32_t oldFailureCount = oldCacheIt->second.staticFillFailureCount;
            if (baseNeedsStaticFill && oldFailureCount >= 3)
            {
                // 失败次数高时采用“稀疏重试”：降低对主预算的持续占用。
                // 公式引入 PID 偏移，避免同一轮集中重试同一批进程。
                constexpr std::uint64_t retryBackoffPeriod = 8;
                const bool shouldRetryThisRound =
                    ((refreshTicket + static_cast<std::uint64_t>(processRecord.pid)) % retryBackoffPeriod) == 0;
                needsStaticFill = shouldRetryThisRound;
            }
            else
            {
                needsStaticFill = baseNeedsStaticFill;
            }
            includeSignatureCheck = detailModeEnabled;
        }
        else
        {
            if (isKernelOnlyRecord)
            {
                // 仅内核可见记录默认不走“新增绿色”路径，避免与红色隐藏高亮冲突。
                isNewProcess[recordIndex] = false;
                needsStaticFill = false;
                includeSignatureCheck = false;
            }
            else
            {
                // 新出现进程：计数 + 依据预算决定是否补齐静态详情。
                ++refreshResult.newProcessCount;
                isNewProcess[recordIndex] = true;
                needsStaticFill = true;
                includeSignatureCheck = detailModeEnabled;
            }
        }
        const auto kernelProcessIt = kernelProcessByPid.find(processRecord.pid);
        if (kernelProcessIt != kernelProcessByPid.end())
        {
            mergeKernelProcessExtension(processRecord, kernelProcessIt->second);
        }

        if (isKernelOnlyRecord)
        {
            processRecord.staticDetailsReady = true;
            processRecord.dynamicCountersReady = true;
            if (processRecord.signatureState.empty())
            {
                processRecord.signatureState = "KernelOnly(Hidden?)";
            }
        }

        if (needsStaticFill)
        {
            isStaticFillCandidate[recordIndex] = true;
            includeSignatureList[recordIndex] = includeSignatureCheck;
        }
    }

    // 预算选择策略：
    // - 先收集全部候选，再做“轮转挑选”；
    // - 避免固定从头挑选导致尾部进程长期 Pending。
    std::vector<std::size_t> staticFillCandidateIndices;
    staticFillCandidateIndices.reserve(latestProcessList.size());
    for (std::size_t recordIndex = 0; recordIndex < isStaticFillCandidate.size(); ++recordIndex)
    {
        if (isStaticFillCandidate[recordIndex])
        {
            staticFillCandidateIndices.push_back(recordIndex);
        }
    }

    if (!staticFillCandidateIndices.empty() && staticFillBudget > 0)
    {
        const std::size_t candidateCount = staticFillCandidateIndices.size();
        const std::size_t allowCount = std::min(staticFillBudget, candidateCount);
        const std::size_t rotationOffset =
            static_cast<std::size_t>(
                (refreshTicket * static_cast<std::uint64_t>(std::max(1, staticDetailFillBudget)))
                % static_cast<std::uint64_t>(candidateCount));
        for (std::size_t offset = 0; offset < allowCount; ++offset)
        {
            const std::size_t candidateOrder = (rotationOffset + offset) % candidateCount;
            const std::size_t selectedIndex = staticFillCandidateIndices[candidateOrder];
            shouldFillStatic[selectedIndex] = true;
        }
    }

    // 未命中预算的候选统一保持 Pending，等待后续轮次补齐。
    for (const std::size_t recordIndex : staticFillCandidateIndices)
    {
        if (shouldFillStatic[recordIndex])
        {
            continue;
        }
        ks::process::ProcessRecord& processRecord = latestProcessList[recordIndex];
        if (processRecord.signatureState.empty())
        {
            processRecord.signatureState = "Pending";
        }
        processRecord.signaturePublisher.clear();
        processRecord.signatureTrusted = false;
        ++refreshResult.staticDeferredCount;
    }

    // 第二阶段：把“路径/签名/参数”等慢静态操作并行化，减少详细视图卡顿。
    std::vector<std::size_t> staticFillIndices;
    staticFillIndices.reserve(latestProcessList.size());
    for (std::size_t recordIndex = 0; recordIndex < shouldFillStatic.size(); ++recordIndex)
    {
        if (shouldFillStatic[recordIndex])
        {
            staticFillIndices.push_back(recordIndex);
        }
    }

    if (!staticFillIndices.empty())
    {
        // 线程数量策略：
        // - 详细视图：使用更多并行度，加速签名校验；
        // - 监视视图：仅小并发，避免过度占用 CPU。
        const unsigned int hardwareThreads = std::max(1u, std::thread::hardware_concurrency());
        const unsigned int wantedThreads = detailModeEnabled
            ? std::max(4u, std::min(12u, hardwareThreads))
            : 2u;
        const unsigned int workerCount = std::max(
            1u,
            std::min<unsigned int>(wantedThreads, static_cast<unsigned int>(staticFillIndices.size())));

        std::atomic<std::size_t> nextTaskIndex{ 0 };
        std::vector<std::thread> workerThreads;
        workerThreads.reserve(workerCount);

        // 每个线程循环领取 PID 任务并调用 FillProcessStaticDetails。
        for (unsigned int workerId = 0; workerId < workerCount; ++workerId)
        {
            workerThreads.emplace_back([&]() {
                for (;;)
                {
                    const std::size_t taskOrder = nextTaskIndex.fetch_add(1);
                    if (taskOrder >= staticFillIndices.size())
                    {
                        break;
                    }

                    const std::size_t recordIndex = staticFillIndices[taskOrder];
                    const bool fillOk = ks::process::FillProcessStaticDetails(
                        latestProcessList[recordIndex],
                        includeSignatureList[recordIndex]);
                    staticFillSucceeded[recordIndex] = fillOk ? 1 : 0;

                    // 失败降级策略：
                    // - 避免签名列长期保持 Pending；
                    // - 对权限受限场景直接标注 No Access。
                    if (!fillOk && includeSignatureList[recordIndex])
                    {
                        ks::process::ProcessRecord& processRecord = latestProcessList[recordIndex];
                        if (processRecord.signatureState.empty() || processRecord.signatureState == "Pending")
                        {
                            processRecord.signatureState = "No Access";
                            processRecord.signaturePublisher.clear();
                            processRecord.signatureTrusted = false;
                        }
                    }
                }
                });
        }

        for (std::thread& workerThread : workerThreads)
        {
            if (workerThread.joinable())
            {
                workerThread.join();
            }
        }
        refreshResult.staticFilledCount += staticFillIndices.size();
    }

    // 第二阶段补充：单独全量补齐 imagePath。
    // 说明：
    // 1) 图标展示只依赖 imagePath，且路径查询比“命令行/签名”更轻；
    // 2) 不受静态详情预算限制，确保每轮已枚举进程都能进入后台图标采集。
    std::vector<std::size_t> imagePathFillIndices;
    imagePathFillIndices.reserve(latestProcessList.size());
    for (std::size_t recordIndex = 0; recordIndex < latestProcessList.size(); ++recordIndex)
    {
        const ks::process::ProcessRecord& processRecord = latestProcessList[recordIndex];
        if (processRecord.pid == 0 || !processRecord.imagePath.empty())
        {
            continue;
        }
        imagePathFillIndices.push_back(recordIndex);
    }

    if (!imagePathFillIndices.empty())
    {
        // 独立路径补齐线程池：仅执行 QueryProcessPathByPid，避免 UI 线程兜底查询造成卡顿。
        const unsigned int hardwareThreads = std::max(1u, std::thread::hardware_concurrency());
        const unsigned int wantedThreads = detailModeEnabled ? std::min(8u, hardwareThreads) : std::min(4u, hardwareThreads);
        const unsigned int workerCount = std::max(
            1u,
            std::min<unsigned int>(wantedThreads, static_cast<unsigned int>(imagePathFillIndices.size())));
        std::atomic<std::size_t> nextTaskIndex{ 0 };
        std::atomic<std::size_t> filledCount{ 0 };
        std::vector<std::thread> workerThreads;
        workerThreads.reserve(workerCount);
        for (unsigned int workerId = 0; workerId < workerCount; ++workerId)
        {
            workerThreads.emplace_back([&]() {
                for (;;)
                {
                    const std::size_t taskOrder = nextTaskIndex.fetch_add(1);
                    if (taskOrder >= imagePathFillIndices.size())
                    {
                        break;
                    }

                    const std::size_t recordIndex = imagePathFillIndices[taskOrder];
                    ks::process::ProcessRecord& processRecord = latestProcessList[recordIndex];
                    const std::string pathText = ks::process::QueryProcessPathByPid(processRecord.pid);
                    if (!pathText.empty())
                    {
                        processRecord.imagePath = pathText;
                        filledCount.fetch_add(1);
                    }
                }
                });
        }
        for (std::thread& workerThread : workerThreads)
        {
            if (workerThread.joinable())
            {
                workerThread.join();
            }
        }
        refreshResult.imagePathFilledCount = filledCount.load();
    }

    // 第二阶段补充二：任务管理器对齐列的按需字段采集。
    // 分层策略：
    // - 静态位（作业归属 / 缓解策略 / UAC 虚拟化 / 映像说明 / 操作系统上下文 / 企业上下文）
    //   在进程生命周期内不变，只在首次成功前反复尝试，成功后记账并永久跳过；
    // - 动态位（GDI 与用户对象计数）每轮都要重新读取，否则数字会停在首次采样值；
    // - GPU 位由 EnumerateProcesses 内部一次性 PDH 采样覆盖全表，不在这里逐进程处理。
    // 该阶段必须放在 imagePath 补齐之后：说明与操作系统上下文都依赖映像路径。
    std::vector<std::uint32_t> onDemandResolvedFlagsByRecord(latestProcessList.size(), 0U);
    if (detailDemandFlags != ks::process::ProcessDetailDemand::None)
    {
        constexpr std::uint32_t DynamicDemandMask = ks::process::ProcessDetailDemand::GuiResources;
        const std::uint32_t requestedDynamicFlags = detailDemandFlags & DynamicDemandMask;
        const std::uint32_t requestedStaticFlags =
            detailDemandFlags & ~(DynamicDemandMask | ks::process::ProcessDetailDemand::GpuMask);

        std::vector<std::uint32_t> onDemandRoundFlagsByRecord(latestProcessList.size(), 0U);
        std::vector<std::size_t> onDemandIndices;
        onDemandIndices.reserve(latestProcessList.size());

        for (std::size_t recordIndex = 0; recordIndex < latestProcessList.size(); ++recordIndex)
        {
            const ks::process::ProcessRecord& processRecord = latestProcessList[recordIndex];

            const auto oldCacheIt = previousCache.find(identityKeys[recordIndex]);
            const std::uint32_t alreadyResolvedFlags =
                (oldCacheIt == previousCache.end()) ? 0U : oldCacheIt->second.onDemandResolvedFlags;
            onDemandResolvedFlagsByRecord[recordIndex] = alreadyResolvedFlags;

            // PID 0 与“仅内核可见”记录没有可打开的用户态句柄，
            // 跳过可以避免每轮为它们白白执行 OpenProcess。
            if (processRecord.pid == 0 ||
                kernelOnlyPidSet.find(processRecord.pid) != kernelOnlyPidSet.end())
            {
                continue;
            }

            std::uint32_t pendingStaticFlags = requestedStaticFlags & ~alreadyResolvedFlags;
            if (processRecord.imagePath.empty())
            {
                // 映像路径还没补上时无法解析说明/清单，本轮先跳过并等待下一轮。
                pendingStaticFlags &= ~ks::process::ProcessDetailDemand::ImageFileMask;
            }

            const std::uint32_t roundFlags = requestedDynamicFlags | pendingStaticFlags;
            if (roundFlags == 0U)
            {
                continue;
            }

            onDemandRoundFlagsByRecord[recordIndex] = roundFlags;
            onDemandIndices.push_back(recordIndex);
        }

        if (!onDemandIndices.empty())
        {
            // 这些查询以 OpenProcess + 若干轻量信息类为主，并发度与图标路径补齐保持一致；
            // 由于默认列布局不会触发本阶段，这里的成本只在用户主动开启相关列后才产生。
            const unsigned int hardwareThreads = std::max(1u, std::thread::hardware_concurrency());
            const unsigned int wantedThreads = std::min(8u, hardwareThreads);
            const unsigned int workerCount = std::max(
                1u,
                std::min<unsigned int>(wantedThreads, static_cast<unsigned int>(onDemandIndices.size())));

            std::atomic<std::size_t> nextTaskIndex{ 0 };
            std::vector<std::thread> workerThreads;
            workerThreads.reserve(workerCount);
            for (unsigned int workerId = 0; workerId < workerCount; ++workerId)
            {
                workerThreads.emplace_back([&]() {
                    for (;;)
                    {
                        const std::size_t taskOrder = nextTaskIndex.fetch_add(1);
                        if (taskOrder >= onDemandIndices.size())
                        {
                            break;
                        }

                        const std::size_t recordIndex = onDemandIndices[taskOrder];
                        std::uint32_t resolvedFlags = 0U;
                        (void)ks::process::FillProcessOnDemandDetails(
                            latestProcessList[recordIndex],
                            onDemandRoundFlagsByRecord[recordIndex],
                            &resolvedFlags);

                        // 只把“确实成功”的静态位记为已完成：
                        // 被拒绝访问的进程会在后续轮次继续重试，而不是永远显示占位符。
                        onDemandResolvedFlagsByRecord[recordIndex] |=
                            (resolvedFlags & ~DynamicDemandMask);
                    }
                    });
            }
            for (std::thread& workerThread : workerThreads)
            {
                if (workerThread.joinable())
                {
                    workerThread.join();
                }
            }
        }
    }

    // 第三阶段：计算性能差值并写回缓存（该阶段仍串行，保证逻辑简单稳定）。
    for (std::size_t recordIndex = 0; recordIndex < latestProcessList.size(); ++recordIndex)
    {
        ks::process::ProcessRecord& processRecord = latestProcessList[recordIndex];
        const std::string& identityKey = identityKeys[recordIndex];

        // 若当前策略未填动态计数器，则显式刷新一次。
        if (!processRecord.dynamicCountersReady)
        {
            ks::process::RefreshProcessDynamicCounters(processRecord);
        }

        // 计算 CPU/DISK 衍生计数，并写入下一轮样本。
        ks::process::CounterSample nextSample{};
        const auto oldCounterIt = previousCounters.find(identityKey);
        const ks::process::CounterSample* oldSample =
            (oldCounterIt == previousCounters.end()) ? nullptr : &oldCounterIt->second;
        ks::process::UpdateDerivedCounters(
            processRecord,
            oldSample,
            nextSample,
            logicalCpuCount,
            sampleTick);

        // 网络吞吐计算：
        // - 输入：抓包线程按 PID 累计的 TCP/UDP 下行、上行字节；
        // - 处理：与上一轮 CounterSample 做差，再除以同一个刷新间隔；
        // - 返回：写入 ProcessRecord 的 down/up/total KB/s，同时把累计值保存到下一轮样本。
        const auto networkCounterIt = networkTrafficSnapshot.find(processRecord.pid);
        if (networkCounterIt != networkTrafficSnapshot.end())
        {
            nextSample.networkRxBytes = networkCounterIt->second.rxBytes;
            nextSample.networkTxBytes = networkCounterIt->second.txBytes;
        }
        if (oldSample != nullptr && sampleTick > oldSample->sampleTick100ns)
        {
            const double deltaSeconds = static_cast<double>(sampleTick - oldSample->sampleTick100ns) / 10000000.0;
            if (deltaSeconds > 0.0)
            {
                const std::uint64_t deltaRxBytes =
                    (nextSample.networkRxBytes >= oldSample->networkRxBytes)
                    ? (nextSample.networkRxBytes - oldSample->networkRxBytes)
                    : 0ULL;
                const std::uint64_t deltaTxBytes =
                    (nextSample.networkTxBytes >= oldSample->networkTxBytes)
                    ? (nextSample.networkTxBytes - oldSample->networkTxBytes)
                    : 0ULL;
                processRecord.netRxKBps = (static_cast<double>(deltaRxBytes) / deltaSeconds) / 1024.0;
                processRecord.netTxKBps = (static_cast<double>(deltaTxBytes) / deltaSeconds) / 1024.0;
                processRecord.netKBps = processRecord.netRxKBps + processRecord.netTxKBps;
            }
        }
        refreshResult.nextCounters[identityKey] = nextSample;

        CacheEntry cacheEntry{};
        cacheEntry.record = std::move(processRecord);
        cacheEntry.onDemandResolvedFlags = onDemandResolvedFlagsByRecord[recordIndex];
        cacheEntry.missingRounds = 0;
        cacheEntry.isNewInLatestRound = isNewProcess[recordIndex];
        cacheEntry.isExitedInLatestRound = false;
        cacheEntry.isKernelOnlyInLatestRound =
            (kernelOnlyPidSet.find(cacheEntry.record.pid) != kernelOnlyPidSet.end());
        {
            // staticFillAttemptCount/staticFillFailureCount 用途：
            // - 记录当前 identity 的补齐尝试历史；
            // - 下一轮用于“连续失败退避”，降低失败进程对预算的长期占用。
            const auto oldCacheIt = previousCache.find(identityKey);
            const std::uint32_t oldAttemptCount =
                (oldCacheIt == previousCache.end()) ? 0U : oldCacheIt->second.staticFillAttemptCount;
            const std::uint32_t oldFailureCount =
                (oldCacheIt == previousCache.end()) ? 0U : oldCacheIt->second.staticFillFailureCount;
            const bool attemptedThisRound = shouldFillStatic[recordIndex];
            const bool fillOkThisRound = (staticFillSucceeded[recordIndex] != 0);

            cacheEntry.staticFillAttemptCount = attemptedThisRound
                ? (oldAttemptCount + 1U)
                : oldAttemptCount;
            cacheEntry.staticFillFailureCount = attemptedThisRound
                ? (fillOkThisRound ? 0U : (oldFailureCount + 1U))
                : oldFailureCount;

            // 若当前记录已经具备可用静态详情，则主动清零失败计数。
            if (cacheEntry.record.staticDetailsReady && cacheEntry.record.signatureState != "Pending")
            {
                cacheEntry.staticFillFailureCount = 0;
            }
        }
        refreshResult.nextCache.emplace(identityKey, std::move(cacheEntry));

    }

    // 再处理退出进程：上一轮存在、本轮不存在，则保留显示 1 轮灰底。
    for (const auto& oldPair : previousCache)
    {
        if (refreshResult.nextCache.find(oldPair.first) != refreshResult.nextCache.end())
        {
            continue;
        }

        const CacheEntry& oldEntry = oldPair.second;
        if (oldEntry.isKernelOnlyInLatestRound)
        {
            // 仅内核可见记录不做“退出保留”，避免在关闭内核对比后残留一轮灰底。
            continue;
        }
        if (oldEntry.missingRounds >= 1)
        {
            // 已经保留过一轮，本次彻底移除。
            continue;
        }

        CacheEntry exitedEntry = oldEntry;
        exitedEntry.missingRounds = oldEntry.missingRounds + 1;
        exitedEntry.isNewInLatestRound = false;
        exitedEntry.isExitedInLatestRound = true;
        // 退出保留行也不能携带上一轮手动 PPL 枚举，避免灰色残留行显示过期保护级别。
        exitedEntry.record.protectionLevelKnown = false;
        exitedEntry.record.protectionLevel = 0;
        exitedEntry.record.protectionLevelText.clear();
        refreshResult.nextCache.emplace(oldPair.first, std::move(exitedEntry));
        ++refreshResult.exitedProcessCount;

        const auto oldCounterIt = previousCounters.find(oldPair.first);
        if (oldCounterIt != previousCounters.end())
        {
            refreshResult.nextCounters.emplace(oldPair.first, oldCounterIt->second);
        }
    }

    refreshResult.workerElapsedMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - workerStartTime).count());

    return refreshResult;
}

void ProcessDock::rebuildTable()
{
    if (m_processTable == nullptr || m_processTableModel == nullptr || m_processSortProxy == nullptr)
    {
        return;
    }

    // 右键菜单保存的是当前模型行。菜单关闭前禁止替换模型，
    // 否则周期刷新会让菜单动作落到另一进程。
    const QPointer<ProcessDock> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("process-main-table-rebuild"),
        {m_processTable},
        [safeThis]()
        {
            if (!safeThis.isNull())
            {
                safeThis->rebuildTable();
            }
        }))
    {
        return;
    }

    const auto tableRebuildStartTime = std::chrono::steady_clock::now();

    if (isProcessActivityTableSnapshotActive())
    {
        rebuildProcessActivityTableSnapshotRecords();
    }

    // 记录用户当前排序列与顺序，解决“刷新后被重置为 PID 排序”的问题。
    QHeaderView* headerView = m_processTable->horizontalHeader();
    const int previousSortColumn = headerView != nullptr
        ? headerView->sortIndicatorSection()
        : toColumnIndex(TableColumn::Pid);
    const Qt::SortOrder previousSortOrder = headerView != nullptr
        ? headerView->sortIndicatorOrder()
        : Qt::AscendingOrder;
    // 表头尚未生成排序指示器时使用 PID，保证排序键快照和实际排序列一致。
    const int safePreviousSortColumn =
        (previousSortColumn >= 0 && previousSortColumn < static_cast<int>(TableColumn::Count))
        ? previousSortColumn
        : toColumnIndex(TableColumn::Pid);
    const std::string trackedIdentityKeyBeforeRebuild =
        !m_trackedSelectedIdentityKey.empty()
        ? m_trackedSelectedIdentityKey
        : selectedIdentityKey();
    std::unordered_set<std::string> trackedIdentityKeysBeforeRebuild;
    for (const std::string& identityKey : m_trackedSelectedIdentityKeys)
    {
        if (!identityKey.empty())
        {
            trackedIdentityKeysBeforeRebuild.insert(identityKey);
        }
    }
    if (!trackedIdentityKeyBeforeRebuild.empty())
    {
        trackedIdentityKeysBeforeRebuild.insert(trackedIdentityKeyBeforeRebuild);
    }
    const int trackedColumnBeforeRebuild = std::clamp(
        m_trackedSelectedColumn,
        0,
        static_cast<int>(TableColumn::Count) - 1);

    // 滚动位置快照：
    // - 保存刷新前用户视口位置；
    // - 刷新后恢复，避免每轮数据替换跳回顶部。
    QScrollBar* verticalScrollBar = m_processTable->verticalScrollBar();
    QScrollBar* horizontalScrollBar = m_processTable->horizontalScrollBar();
    const int verticalScrollValueBeforeRebuild = (verticalScrollBar != nullptr) ? verticalScrollBar->value() : 0;
    const int horizontalScrollValueBeforeRebuild = (horizontalScrollBar != nullptr) ? horizontalScrollBar->value() : 0;

    const bool activitySnapshotActive = isProcessActivityTableSnapshotActive();
    const bool searchResultActive = !currentProcessSearchText().isEmpty();
    // 历史快照和搜索结果都是扁平行，可直接使用代理排序；树状/友好分组保留各自的行序语义。
    const bool enableSorting = activitySnapshotActive || searchResultActive ||
        (!isTreeModeEnabled() && !isFriendlyViewEnabled());
    if (m_processSortProxy != nullptr)
    {
        auto* processSortProxy = static_cast<ProcessTableSortProxy*>(m_processSortProxy);
        processSortProxy->setPreserveSourceOrder(!enableSorting);
    }

    const std::vector<DisplayRow> displayRows = buildDisplayOrder();

    // 先预计算 RAM/DISK/NET/句柄数的本轮最大值，用于把绝对值映射成“占用比例高亮”。
    double maxRamMB = 0.0;
    double maxDiskMBps = 0.0;
    double maxNetKBps = 0.0;
    std::uint32_t maxHandleCount = 0;
    for (const DisplayRow& displayRow : displayRows)
    {
        if (displayRow.record == nullptr || displayRow.rowKind == ProcessTableRowKind::GroupHeader)
        {
            continue;
        }
        maxRamMB = std::max(maxRamMB, displayRow.record->workingSetMB);
        maxDiskMBps = std::max(maxDiskMBps, displayRow.record->diskMBps);
        maxNetKBps = std::max(maxNetKBps, displayRow.record->netKBps);
        maxHandleCount = std::max(maxHandleCount, displayRow.record->handleCount);
    }

    // tableRows 作用：
    // - 把 DisplayRow 转成 FlatTableModel 可直接持有的轻量行快照；
    // - 所有颜色、排序键、图标都由 processTableData 按 role 懒解析；
    // - 这样每轮刷新只替换 vector，不再创建/销毁旧 item。
    // “类型”列需要每行的应用/后台/系统归类。友好视图的 DisplayRow 已经带上该信息，
    // 树状与列表视图则要单独算一次；仅在该列可见时才做，避免为隐藏列枚举窗口。
    const bool processTypeColumnVisible = isProcessColumnVisible(TableColumn::ProcessType);
    std::unordered_map<std::uint32_t, FriendlyProcessGroupType> friendlyGroupTypeByPid;
    if (processTypeColumnVisible && !isFriendlyViewEnabled())
    {
        friendlyGroupTypeByPid = buildFriendlyGroupTypeByPid();
    }

    std::vector<ProcessTableRow> tableRows;
    tableRows.reserve(displayRows.size());
    for (const DisplayRow& displayRow : displayRows)
    {
        if (displayRow.record == nullptr)
        {
            continue;
        }

        const ks::process::ProcessRecord& processRecord = *displayRow.record;
        ProcessTableRow tableRow{};
        tableRow.record = processRecord;
        tableRow.rowKind = displayRow.rowKind;
        tableRow.friendlyGroupType = displayRow.friendlyGroupType;
        if (!friendlyGroupTypeByPid.empty())
        {
            const auto groupTypeIt = friendlyGroupTypeByPid.find(processRecord.pid);
            if (groupTypeIt != friendlyGroupTypeByPid.end())
            {
                tableRow.friendlyGroupType = groupTypeIt->second;
            }
        }
        tableRow.syntheticTitle = displayRow.syntheticTitle;
        tableRow.expansionKey = displayRow.expansionKey;
        tableRow.actionIdentityKeys = displayRow.actionIdentityKeys;
        tableRow.identityKey = displayRow.rowKind == ProcessTableRowKind::Process
            ? ks::process::BuildProcessIdentityKey(processRecord.pid, processRecord.creationTime100ns)
            : std::string();
        if (displayRow.rowKind == ProcessTableRowKind::Process && !displayRow.isExited)
        {
            tableRow.cpuCoreProcessIds.push_back(processRecord.pid);
        }
        else if (displayRow.rowKind == ProcessTableRowKind::ApplicationAggregate)
        {
            // 应用父行复用现有成员 identity 列表，解析为本轮真实 PID 后交给逐核心绘制器求和。
            tableRow.cpuCoreProcessIds.reserve(
                static_cast<qsizetype>(displayRow.actionIdentityKeys.size()));
            for (const std::string& memberIdentityKey : displayRow.actionIdentityKeys)
            {
                const auto memberIt = m_cacheByIdentity.find(memberIdentityKey);
                if (memberIt == m_cacheByIdentity.end() ||
                    memberIt->second.isExitedInLatestRound)
                {
                    continue;
                }
                tableRow.cpuCoreProcessIds.push_back(memberIt->second.record.pid);
            }
        }
        tableRow.depth = displayRow.depth;
        tableRow.hasChildren = displayRow.hasChildren;
        tableRow.isNew = displayRow.isNew;
        tableRow.isExited = displayRow.isExited;
        tableRow.isKernelOnly = displayRow.isKernelOnly;
        tableRow.activitySnapshotActive = activitySnapshotActive;
        // 逐核心 ETW 快照由 ProcessDock 全部实时行共享，不进入每行对象，避免行数级 shared_ptr 增减。
        tableRow.cpuUsageRatio = std::clamp(processRecord.cpuPercent / 100.0, 0.0, 1.0);
        tableRow.ramUsageRatio = (maxRamMB > 0.0)
            ? std::clamp(processRecord.workingSetMB / maxRamMB, 0.0, 1.0)
            : 0.0;
        tableRow.diskUsageRatio = (maxDiskMBps > 0.0)
            ? std::clamp(processRecord.diskMBps / maxDiskMBps, 0.0, 1.0)
            : 0.0;
        tableRow.gpuUsageRatio = std::clamp(processRecord.gpuPercent / 100.0, 0.0, 1.0);
        tableRow.netUsageRatio = (maxNetKBps > 0.0)
            ? std::clamp(processRecord.netKBps / maxNetKBps, 0.0, 1.0)
            : 0.0;
        tableRow.handleUsageRatio = (maxHandleCount > 0U)
            ? std::clamp(
                static_cast<double>(processRecord.handleCount) / static_cast<double>(maxHandleCount),
                0.0,
                1.0)
            : 0.0;
        tableRows.push_back(std::move(tableRow));
    }

    // 排序键快照作用：
    // - 仅比较当前用户排序列的数值键和展示键；
    // - 键未变化时保留 QSortFilterProxyModel 已有顺序，跳过一次完整排序；
    // - 新增、退出或当前排序值变化时仍按原有规则立即重新排序。
    struct ProcessSortCellSnapshot
    {
        bool hasNumericValue = false; // hasNumericValue：当前列是否提供数值排序键。
        double numericValue = 0.0;    // numericValue：ProcessNumericSortRole 的原始数值。
        QString displayText;          // displayText：数值相等或文本列时的稳定次级排序键。
    };
    const auto tableRowStableKey = [](const ProcessTableRow& tableRow) -> std::string
    {
        if (tableRow.rowKind == ProcessTableRowKind::Process)
        {
            return std::string("process:") + tableRow.identityKey;
        }
        return std::string("synthetic:")
            + std::to_string(static_cast<int>(tableRow.rowKind))
            + ":"
            + tableRow.expansionKey.toUtf8().toStdString();
    };
    const auto captureSortCell = [this, safePreviousSortColumn](const ProcessTableRow& tableRow) -> ProcessSortCellSnapshot
    {
        ProcessSortCellSnapshot snapshot{};
        bool numericParseOk = false;
        const QVariant numericSortValue = processTableData(
            tableRow,
            safePreviousSortColumn,
            ProcessNumericSortRole);
        const double numericValue = numericSortValue.toDouble(&numericParseOk);
        snapshot.hasNumericValue = numericParseOk;
        snapshot.numericValue = numericValue;
        snapshot.displayText = processTableData(
            tableRow,
            safePreviousSortColumn,
            Qt::DisplayRole).toString();
        return snapshot;
    };
    const auto requiresProcessTableResort = [&]() -> bool
    {
        // 树状和友好视图由源顺序定义结构，仍沿用原有代理排序触发路径。
        if (!enableSorting)
        {
            return true;
        }

        const std::vector<ProcessTableRow>& previousRows = m_processTableModel->rows();
        if (previousRows.size() != tableRows.size())
        {
            return true;
        }

        std::unordered_map<std::string, ProcessSortCellSnapshot> previousSortCells;
        previousSortCells.reserve(previousRows.size());
        for (const ProcessTableRow& previousRow : previousRows)
        {
            const std::string stableKey = tableRowStableKey(previousRow);
            if (stableKey.empty() ||
                !previousSortCells.emplace(stableKey, captureSortCell(previousRow)).second)
            {
                return true;
            }
        }

        for (const ProcessTableRow& nextRow : tableRows)
        {
            const std::string stableKey = tableRowStableKey(nextRow);
            const auto previousSortCellIt = previousSortCells.find(stableKey);
            if (stableKey.empty() || previousSortCellIt == previousSortCells.end())
            {
                return true;
            }

            const ProcessSortCellSnapshot nextSortCell = captureSortCell(nextRow);
            const ProcessSortCellSnapshot& previousSortCell = previousSortCellIt->second;
            if (previousSortCell.hasNumericValue != nextSortCell.hasNumericValue ||
                previousSortCell.numericValue != nextSortCell.numericValue ||
                previousSortCell.displayText != nextSortCell.displayText)
            {
                return true;
            }
        }
        return false;
    };
    const bool processTableResortRequired = requiresProcessTableResort();

    // 刷新期间临时冻结视图和选择信号，合并增量模型变更的中间态重绘。
    QSignalBlocker tableSignalBlocker(m_processTable);
    std::unique_ptr<QSignalBlocker> selectionSignalBlocker;
    if (QItemSelectionModel* selectionModel = m_processTable->selectionModel())
    {
        selectionSignalBlocker = std::make_unique<QSignalBlocker>(selectionModel);
    }
    m_processTable->setUpdatesEnabled(false);

    const auto modelApplyStartTime = std::chrono::steady_clock::now();
    const ProcessTableModel::UpdateStats modelUpdateStats =
        m_processTableModel->setRows(std::move(tableRows));
    const auto modelApplyElapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - modelApplyStartTime).count();

    const auto sortStartTime = std::chrono::steady_clock::now();
    // QTableView::setSortingEnabled(true) 会立即触发排序；仅在开关状态变化时调用，防止无数据变化的周期刷新重复排序。
    const bool sortingStateChanged = (m_processTable->isSortingEnabled() != enableSorting);
    if (sortingStateChanged)
    {
        m_processTable->setSortingEnabled(enableSorting);
    }
    if (enableSorting)
    {
        if (sortingStateChanged || processTableResortRequired)
        {
            // 恢复用户上一次排序选择，而不是强制回到 PID 升序。
            m_processTable->sortByColumn(safePreviousSortColumn, previousSortOrder);
        }
    }
    else
    {
        // 树状/友好模式由 build*DisplayOrder 决定顺序；代理用第 0 列触发一次源顺序排序。
        m_processSortProxy->sort(toColumnIndex(TableColumn::Name), Qt::AscendingOrder);
        if (headerView != nullptr && isFriendlyViewEnabled())
        {
            headerView->setSortIndicatorShown(true);
            headerView->setSortIndicator(m_friendlySortColumn, m_friendlySortOrder);
        }
    }
    const auto sortElapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - sortStartTime).count();

    // 按 identityKey 恢复用户之前选中的进程：
    // - Ctrl 多选集合逐行用 Select|Rows 写回，避免刷新后丢失批量选择；
    // - 当前焦点只通过 NoUpdate 更新，不允许 currentIndex 把多选压成单选；
    // - 若该进程已不存在，则清空追踪状态，避免错误高亮。
    bool restoredAnySelection = false;
    QItemSelectionModel* selectionModel = m_processTable->selectionModel();
    bool selectionRestoreRequired = modelUpdateStats.modelReset;
    if (selectionModel != nullptr && !selectionRestoreRequired)
    {
        // 增量模型更新会维护 persistent index；当前实际选择仍与追踪集合一致时，不清空再重选，避免高频刷新闪烁。
        std::unordered_set<std::string> currentSelectedIdentityKeys;
        bool containsSyntheticSelection = false;
        const std::vector<QModelIndex> selectedRows = selectedProcessTableRowIndexes(false);
        currentSelectedIdentityKeys.reserve(selectedRows.size());
        for (const QModelIndex& rowIndex : selectedRows)
        {
            const ProcessTableRow* selectedTableRow = processTableRowForViewIndex(rowIndex);
            if (selectedTableRow == nullptr ||
                selectedTableRow->rowKind != ProcessTableRowKind::Process ||
                selectedTableRow->identityKey.empty())
            {
                containsSyntheticSelection = true;
                continue;
            }
            currentSelectedIdentityKeys.insert(selectedTableRow->identityKey);
        }

        selectionRestoreRequired =
            containsSyntheticSelection ||
            currentSelectedIdentityKeys != trackedIdentityKeysBeforeRebuild;
        if (!selectionRestoreRequired && !trackedIdentityKeyBeforeRebuild.empty())
        {
            const QModelIndex currentIndex = selectionModel->currentIndex();
            const ProcessTableRow* currentTableRow = processTableRowForViewIndex(currentIndex);
            selectionRestoreRequired =
                currentTableRow == nullptr ||
                currentTableRow->identityKey != trackedIdentityKeyBeforeRebuild ||
                currentIndex.column() != trackedColumnBeforeRebuild;
        }
    }
    if (selectionModel != nullptr && selectionRestoreRequired)
    {
        selectionModel->clearSelection();
        for (const std::string& identityKey : trackedIdentityKeysBeforeRebuild)
        {
            const QModelIndex rowIndex = processTableViewIndexForIdentityKey(identityKey, 0);
            if (rowIndex.isValid())
            {
                selectionModel->select(
                    rowIndex,
                    QItemSelectionModel::Select | QItemSelectionModel::Rows);
                restoredAnySelection = true;
            }
        }

        QModelIndex currentIndexToRestore = processTableViewIndexForIdentityKey(
            trackedIdentityKeyBeforeRebuild,
            trackedColumnBeforeRebuild);
        if (!currentIndexToRestore.isValid() && !trackedIdentityKeysBeforeRebuild.empty())
        {
            currentIndexToRestore = processTableViewIndexForIdentityKey(
                *trackedIdentityKeysBeforeRebuild.begin(),
                trackedColumnBeforeRebuild);
        }
        if (currentIndexToRestore.isValid())
        {
            selectionModel->setCurrentIndex(currentIndexToRestore, QItemSelectionModel::NoUpdate);
            restoredAnySelection = true;
        }
    }

    if (restoredAnySelection)
    {
        syncTrackedSelectionFromTable();
        m_trackedSelectedColumn = trackedColumnBeforeRebuild;
    }
    else if (selectionRestoreRequired &&
        !trackedIdentityKeysBeforeRebuild.empty() &&
        currentProcessSearchText().isEmpty())
    {
        m_trackedSelectedIdentityKey.clear();
        m_trackedSelectedIdentityKeys.clear();
        m_trackedSelectedColumn = 0;
    }

    // 根据本轮数据刷新标题栏“占用总和”。
    updateUsageSummaryInHeader(displayRows);
    applyR0ColumnAvailability(displayRows);

    // 恢复滚动位置：保持用户当前视图位置不被刷新打断。
    if (verticalScrollBar != nullptr)
    {
        verticalScrollBar->setValue(std::clamp(
            verticalScrollValueBeforeRebuild,
            verticalScrollBar->minimum(),
            verticalScrollBar->maximum()));
    }
    if (horizontalScrollBar != nullptr)
    {
        horizontalScrollBar->setValue(std::clamp(
            horizontalScrollValueBeforeRebuild,
            horizontalScrollBar->minimum(),
            horizontalScrollBar->maximum()));
    }

    // 表格重建完成后恢复刷新绘制。
    m_processTable->setUpdatesEnabled(true);
    m_processTable->viewport()->update();
    const auto tableRebuildElapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - tableRebuildStartTime).count();

    // 重建完成后输出一条细粒度日志，便于分析 UI 刷新开销与排序状态。
    kLogEvent logEvent;
    dbg << logEvent
        << "[ProcessDock] rebuildTable 完成, rows=" << displayRows.size()
        << ", treeMode=" << (isTreeModeEnabled() ? "true" : "false")
        << ", friendlyView=" << (isFriendlyViewEnabled() ? "true" : "false")
        << ", sortingEnabled=" << (enableSorting ? "true" : "false")
        << ", sortColumn=" << (enableSorting && headerView != nullptr ? headerView->sortIndicatorSection() : -1)
        << ", modelInserted=" << modelUpdateStats.insertedRowCount
        << ", modelRemoved=" << modelUpdateStats.removedRowCount
        << ", modelReordered=" << (modelUpdateStats.orderChanged ? "true" : "false")
        << ", modelReset=" << (modelUpdateStats.modelReset ? "true" : "false")
        << ", modelApplyUs=" << modelApplyElapsedUs
        << ", sortUs=" << sortElapsedUs
        << ", totalUiRebuildUs=" << tableRebuildElapsedUs
        << eol;
}

void ProcessDock::updateUsageSummaryInHeader(const std::vector<DisplayRow>& displayRows)
{
    // 标题栏展示占用总和：
    // - QTableView 没有 headerItem，动态标题由 ProcessTableSortProxy::headerData 提供；
    // - 本函数只计算当前可见行聚合值并更新代理表头，不触碰模型行数据。
    if (m_processSortProxy == nullptr)
    {
        return;
    }

    double totalCpuPercent = 0.0;
    double totalRamMB = 0.0;
    double totalDiskMBps = 0.0;
    double totalGpuPercent = 0.0;
    double totalNetKBps = 0.0;
    std::uint64_t totalHandleCount = 0;
    for (const DisplayRow& displayRow : displayRows)
    {
        if (displayRow.record == nullptr ||
            displayRow.rowKind != ProcessTableRowKind::Process ||
            displayRow.isExited)
        {
            continue;
        }

        // CPU 汇总按用户要求排除“System Idle Process”(PID=0) 的空闲占比。
        const bool isSystemIdleProcess =
            (displayRow.record->pid == 0) ||
            (QString::fromStdString(displayRow.record->processName).compare("System Idle Process", Qt::CaseInsensitive) == 0);
        if (!isSystemIdleProcess)
        {
            totalCpuPercent += displayRow.record->cpuPercent;
        }

        totalRamMB += displayRow.record->ramMB;
        totalDiskMBps += displayRow.record->diskMBps;
        totalGpuPercent += displayRow.record->gpuPercent;
        totalNetKBps += displayRow.record->netKBps;
        totalHandleCount += displayRow.record->handleCount;
    }

    QStringList headerTexts = ProcessTableHeaders;
    headerTexts[toColumnIndex(TableColumn::Cpu)] = QString("CPU %1%").arg(totalCpuPercent, 0, 'f', 2);
    headerTexts[toColumnIndex(TableColumn::Ram)] = QString("RAM %1 MB").arg(totalRamMB, 0, 'f', 1);
    headerTexts[toColumnIndex(TableColumn::Disk)] = QString("DISK %1 MB/s").arg(totalDiskMBps, 0, 'f', 2);
    headerTexts[toColumnIndex(TableColumn::Gpu)] = QString("GPU %1%").arg(totalGpuPercent, 0, 'f', 1);
    headerTexts[toColumnIndex(TableColumn::Net)] = QString("Net %1 KB/s").arg(totalNetKBps, 0, 'f', 2);
    headerTexts[toColumnIndex(TableColumn::HandleCount)] = QString("句柄数 %1").arg(static_cast<qulonglong>(totalHandleCount));

    auto* processSortProxy = static_cast<ProcessTableSortProxy*>(m_processSortProxy);
    processSortProxy->setHeaderTexts(std::move(headerTexts));
}

void ProcessDock::applyR0ColumnAvailability(const std::vector<DisplayRow>& displayRows)
{
    if (m_processTable == nullptr)
    {
        return;
    }

    bool hasVisibleR0Extension = false;
    for (const DisplayRow& displayRow : displayRows)
    {
        if (displayRow.record == nullptr ||
            displayRow.rowKind != ProcessTableRowKind::Process ||
            displayRow.isExited)
        {
            continue;
        }

        if (isProcessR0ExtensionVisible(*displayRow.record))
        {
            hasVisibleR0Extension = true;
            break;
        }
    }

    const bool shouldAutoHide = !hasVisibleR0Extension;
    const bool stateChanged = (m_autoHideUnavailableR0Columns != shouldAutoHide);
    m_autoHideUnavailableR0Columns = shouldAutoHide;
    if (!stateChanged)
    {
        return;
    }

    const int r0OnlyColumns[] = {
        toColumnIndex(TableColumn::Protection),
        toColumnIndex(TableColumn::Ppl),
        toColumnIndex(TableColumn::HandleTable),
        toColumnIndex(TableColumn::SectionObject),
        toColumnIndex(TableColumn::R0Status)
    };

    if (shouldAutoHide)
    {
        for (const int columnIndex : r0OnlyColumns)
        {
            m_processTable->setColumnHidden(columnIndex, true);
        }
        applyAdaptiveColumnWidths();
    }
    else
    {
        // R0 扩展重新可用时按“视图预设 + 用户列选择”整体重铺一次：
        // 直接强制显示这几列会覆盖用户在“选择列”里主动隐藏它们的决定。
        applyViewMode(currentViewMode());
    }

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] R0-only 列自动"
        << (shouldAutoHide ? "隐藏" : "显示")
        << ", reason="
        << (shouldAutoHide ? "所有可见行 R0 扩展均为 Unavailable" : "检测到可用 R0 扩展字段")
        << eol;
}

bool ProcessDock::isProcessActivityMetricEnabled(const ProcessActivityMetric metric) const
{
    // 按钮为空时采用默认全显示：
    // - 与初始化后的按钮状态保持一致；
    // - 这样首帧绘制不会因为控件尚未绑定而漏掉磁盘/网络/GPU。
    // 这保证面板初始化前调用也不会产生空指针。
    switch (metric)
    {
    case ProcessActivityMetric::Cpu:
        return m_activityCpuButton == nullptr || m_activityCpuButton->isChecked();
    case ProcessActivityMetric::Memory:
        return m_activityMemoryButton == nullptr || m_activityMemoryButton->isChecked();
    case ProcessActivityMetric::Disk:
        return m_activityDiskButton == nullptr || m_activityDiskButton->isChecked();
    case ProcessActivityMetric::Network:
        return m_activityNetworkButton == nullptr || m_activityNetworkButton->isChecked();
    case ProcessActivityMetric::Gpu:
        return m_activityGpuButton == nullptr || m_activityGpuButton->isChecked();
    default:
        return false;
    }
}

namespace
{
    // processActivitySampleMetricValue 作用：
    // - 根据当前选择范围提取一个样本的单项数值；
    // - selectionKeys 为空时取总体，非空时汇总对应进程。
    double processActivitySampleMetricValue(
        const ProcessDock::ProcessActivitySample& sample,
        const ProcessDock::ProcessActivityMetric metric,
        const std::vector<std::string>& selectionKeys)
    {
        if (selectionKeys.empty())
        {
            switch (metric)
            {
            case ProcessDock::ProcessActivityMetric::Cpu:
                return sample.totalCpuPercent;
            case ProcessDock::ProcessActivityMetric::Memory:
                return sample.totalMemoryMB;
            case ProcessDock::ProcessActivityMetric::Disk:
                return sample.totalDiskMBps;
            case ProcessDock::ProcessActivityMetric::Network:
                return sample.totalNetKBps;
            case ProcessDock::ProcessActivityMetric::Gpu:
                return sample.totalGpuPercent;
            default:
                return 0.0;
            }
        }

        double value = 0.0;
        for (const ProcessDock::ProcessActivityProcessPoint& processPoint : sample.processes)
        {
            if (std::find(selectionKeys.begin(), selectionKeys.end(), processPoint.identityKey) == selectionKeys.end())
            {
                continue;
            }
            switch (metric)
            {
            case ProcessDock::ProcessActivityMetric::Cpu:
                value += processPoint.cpuPercent;
                break;
            case ProcessDock::ProcessActivityMetric::Memory:
                value += processPoint.workingSetMB;
                break;
            case ProcessDock::ProcessActivityMetric::Disk:
                value += processPoint.diskMBps;
                break;
            case ProcessDock::ProcessActivityMetric::Network:
                value += processPoint.netKBps;
                break;
            case ProcessDock::ProcessActivityMetric::Gpu:
                value += processPoint.gpuPercent;
                break;
            default:
                break;
            }
        }
        return value;
    }
}

bool ProcessDock::isProcessActivityRefreshAllowedNow() const
{
    // 监视启动后，无论当前进程子页为何都保持刷新和记录。
    if (!m_monitoringEnabled)
    {
        return false;
    }

    return true;
}

bool ProcessDock::isProcessActivityRecordingAllowedNow() const
{
    // 记录允许逻辑在刷新允许之上额外叠加“不记录历史”：
    // - 这样可以继续更新下方列表；
    // - 同时不污染上方时间轴样本。
    if (!isProcessActivityRefreshAllowedNow())
    {
        return false;
    }

    if (m_activityListOnlyRefreshCheck != nullptr && m_activityListOnlyRefreshCheck->isChecked())
    {
        return false;
    }

    return true;
}

template <typename Destination, typename Source>
void ProcessDock::copyProcessActivityDynamicFields(Destination& destination, const Source& source)
{
    // 两种快照类型共享同名动态字段；集中在一处复制可避免采样与回放字段列表漂移。
    destination.cpuPercent = source.cpuPercent;
    destination.cpuCorePercent = source.cpuCorePercent;
    destination.ramMB = source.ramMB;
    destination.workingSetMB = source.workingSetMB;
    destination.diskMBps = source.diskMBps;
    destination.netKBps = source.netKBps;
    destination.netRxKBps = source.netRxKBps;
    destination.netTxKBps = source.netTxKBps;
    destination.gpuPercent = source.gpuPercent;
    destination.threadCount = source.threadCount;
    destination.handleCount = source.handleCount;
    destination.suspendedThreadCount = source.suspendedThreadCount;
    destination.basePriority = source.basePriority;
    destination.processStateKnown = source.processStateKnown;
    destination.processSuspended = source.processSuspended;
    destination.efficiencyModeSupported = source.efficiencyModeSupported;
    destination.efficiencyModeEnabled = source.efficiencyModeEnabled;
    destination.rawCpuTime100ns = source.rawCpuTime100ns;
    destination.cycleTime = source.cycleTime;
    destination.rawWorkingSetBytes = source.rawWorkingSetBytes;
    destination.peakWorkingSetBytes = source.peakWorkingSetBytes;
    destination.privateWorkingSetBytes = source.privateWorkingSetBytes;
    destination.sharedWorkingSetBytes = source.sharedWorkingSetBytes;
    destination.commitSizeBytes = source.commitSizeBytes;
    destination.pagedPoolBytes = source.pagedPoolBytes;
    destination.nonPagedPoolBytes = source.nonPagedPoolBytes;
    destination.pageFaultCount = source.pageFaultCount;
    destination.workingSetDeltaBytes = source.workingSetDeltaBytes;
    destination.pageFaultDeltaCount = source.pageFaultDeltaCount;
    destination.cycleTimeKnown = source.cycleTimeKnown;
    destination.memoryDetailKnown = source.memoryDetailKnown;
    destination.privateWorkingSetKnown = source.privateWorkingSetKnown;
    destination.ioReadOperationCount = source.ioReadOperationCount;
    destination.ioWriteOperationCount = source.ioWriteOperationCount;
    destination.ioOtherOperationCount = source.ioOtherOperationCount;
    destination.ioReadTransferBytes = source.ioReadTransferBytes;
    destination.ioWriteTransferBytes = source.ioWriteTransferBytes;
    destination.ioOtherTransferBytes = source.ioOtherTransferBytes;
    destination.gdiObjectCount = source.gdiObjectCount;
    destination.userObjectCount = source.userObjectCount;
    destination.ioDetailKnown = source.ioDetailKnown;
    destination.guiResourceKnown = source.guiResourceKnown;
    destination.gpuDedicatedMemoryBytes = source.gpuDedicatedMemoryBytes;
    destination.gpuSharedMemoryBytes = source.gpuSharedMemoryBytes;
    destination.gpuEngineText = source.gpuEngineText;
    destination.gpuMemoryKnown = source.gpuMemoryKnown;
}

void ProcessDock::appendProcessActivitySample()
{
    if (!isProcessActivityRecordingAllowedNow())
    {
        updateProcessActivityStatusLabel();
        refreshProcessActivityChart();
        return;
    }

    if (m_activityRecordingStartTick100ns == 0 || m_activitySamples.empty())
    {
        m_activityRecordingStartTick100ns = steadyNow100ns();
    }

    ProcessActivitySample sample{};
    const std::uint64_t nowTick100ns = steadyNow100ns();
    sample.sequence = m_activityNextSequence++;
    sample.elapsedMs = (nowTick100ns >= m_activityRecordingStartTick100ns)
        ? ((nowTick100ns - m_activityRecordingStartTick100ns) / 10000ULL)
        : 0ULL;
    sample.unixMilliseconds = QDateTime::currentMSecsSinceEpoch();
    sample.processes.reserve(m_cacheByIdentity.size());

    for (const auto& cachePair : m_cacheByIdentity)
    {
        const CacheEntry& cacheEntry = cachePair.second;
        if (cacheEntry.isExitedInLatestRound)
        {
            continue;
        }

        const ks::process::ProcessRecord& processRecord = cacheEntry.record;
        ProcessActivityProcessPoint processPoint{};
        processPoint.identityKey = cachePair.first;
        processPoint.processName = processRecord.processName;
        processPoint.imagePath = processRecord.imagePath;
        processPoint.iconCacheKey = processRecord.processName + "|" + processRecord.imagePath;
        processPoint.creationTime100ns = processRecord.creationTime100ns;
        processPoint.pid = processRecord.pid;
        copyProcessActivityDynamicFields(processPoint, processRecord);

        const bool isSystemIdleProcess =
            (processRecord.pid == 0) ||
            (QString::fromStdString(processRecord.processName).compare("System Idle Process", Qt::CaseInsensitive) == 0);
        if (!isSystemIdleProcess)
        {
            sample.totalCpuPercent += processRecord.cpuPercent;
        }
        sample.totalMemoryMB += processRecord.workingSetMB;
        sample.totalDiskMBps += processRecord.diskMBps;
        sample.totalNetKBps += processRecord.netKBps;
        sample.totalGpuPercent += processRecord.gpuPercent;

        // 历史快照只保存轻量数据，不在采样循环重复投递图标查询：
        // - 当前进程列表会在每轮刷新时全量提交后台 Shell 图标任务；
        // - 这里复用已经就绪的路径缓存，历史行未命中时由其显示路径补投后台任务；
        // - 图标仍完全基于快照中的进程名和路径，不会额外按 PID 查询。
        if (!processPoint.iconCacheKey.empty())
        {
            const QString iconKey = QString::fromStdString(processPoint.iconCacheKey);
            const QString imagePath = QString::fromStdString(processPoint.imagePath).trimmed();
            const auto liveIconIt = m_iconCacheByPath.find(imagePath);
            if (!m_activityIconCacheByProcessKey.contains(iconKey) &&
                liveIconIt != m_iconCacheByPath.end())
            {
                if (m_activityIconCacheByProcessKey.size() >= ActivityIconCacheMaximumCount)
                {
                    m_activityIconCacheByProcessKey.erase(m_activityIconCacheByProcessKey.begin());
                }
                m_activityIconCacheByProcessKey.insert(iconKey, liveIconIt.value());
            }
        }
        sample.processes.push_back(std::move(processPoint));
    }

    m_activitySamples.push_back(std::move(sample));
    const bool sampleIndexShiftedLeft = trimProcessActivitySamples();
    if (m_activityChartWidget != nullptr)
    {
        m_activityChartWidget->animateLatestSample(sampleIndexShiftedLeft);
    }
    if (!m_activitySamples.empty())
    {
        appendProcessActivitySampleToDetailWindows(m_activitySamples.back());
    }
    if (m_activityTableSnapshotIndex >= static_cast<int>(m_activitySamples.size()))
    {
        m_activityTableSnapshotIndex = -1;
        m_activityTableSnapshotRecords.clear();
    }
    refreshProcessActivityTimeline(sampleIndexShiftedLeft);
    refreshProcessActivityChart();
    updateProcessActivityStatusLabel();
}

void ProcessDock::synchronizeDetailWindowPerformanceHistory(
    ProcessDetailWindow* const detailWindow,
    const std::string& identityKey) const
{
    if (detailWindow == nullptr || identityKey.empty())
    {
        return;
    }

    std::vector<ProcessDetailWindow::PerformanceHistorySample> history;
    history.reserve(m_activitySamples.size());
    for (const ProcessActivitySample& activitySample : m_activitySamples)
    {
        const auto processPointIt = std::find_if(
            activitySample.processes.cbegin(),
            activitySample.processes.cend(),
            [&identityKey](const ProcessActivityProcessPoint& processPoint) {
                return processPoint.identityKey == identityKey;
            });
        if (processPointIt == activitySample.processes.cend())
        {
            continue;
        }

        ProcessDetailWindow::PerformanceHistorySample detailSample;
        detailSample.unixMilliseconds = activitySample.unixMilliseconds;
        detailSample.cpuPercent = processPointIt->cpuPercent;
        detailSample.cpuCorePercent = processPointIt->cpuCorePercent;
        detailSample.memoryMB = processPointIt->workingSetMB;
        detailSample.diskMBps = processPointIt->diskMBps;
        detailSample.networkRxKBps = processPointIt->netRxKBps;
        detailSample.networkTxKBps = processPointIt->netTxKBps;
        detailSample.gpuPercent = processPointIt->gpuPercent;
        history.push_back(detailSample);
    }
    detailWindow->setPerformanceHistory(std::move(history));
}

void ProcessDock::appendProcessActivitySampleToDetailWindows(const ProcessActivitySample& sample)
{
    for (const auto& detailWindowPair : m_detailWindowByIdentity)
    {
        ProcessDetailWindow* const detailWindow = detailWindowPair.second.data();
        if (detailWindow == nullptr)
        {
            continue;
        }

        const auto processPointIt = std::find_if(
            sample.processes.cbegin(),
            sample.processes.cend(),
            [&detailWindowPair](const ProcessActivityProcessPoint& processPoint) {
                return processPoint.identityKey == detailWindowPair.first;
            });
        if (processPointIt == sample.processes.cend())
        {
            continue;
        }

        ProcessDetailWindow::PerformanceHistorySample detailSample;
        detailSample.unixMilliseconds = sample.unixMilliseconds;
        detailSample.cpuPercent = processPointIt->cpuPercent;
        detailSample.cpuCorePercent = processPointIt->cpuCorePercent;
        detailSample.memoryMB = processPointIt->workingSetMB;
        detailSample.diskMBps = processPointIt->diskMBps;
        detailSample.networkRxKBps = processPointIt->netRxKBps;
        detailSample.networkTxKBps = processPointIt->netTxKBps;
        detailSample.gpuPercent = processPointIt->gpuPercent;
        detailWindow->appendPerformanceHistorySample(detailSample);
    }
}

bool ProcessDock::trimProcessActivitySamples()
{
    // 样本缓存固定上限，避免长时间记录造成内存无限增长。
    if (m_activitySamples.size() <= ActivityMaximumSampleCount)
    {
        return false;
    }

    const std::size_t removeCount = m_activitySamples.size() - ActivityMaximumSampleCount;
    for (std::size_t removeIndex = 0; removeIndex < removeCount; ++removeIndex)
    {
        m_activitySamples.pop_front();
    }
    if (m_activityTableSnapshotIndex >= 0)
    {
        m_activityTableSnapshotIndex -= static_cast<int>(removeCount);
        if (m_activityTableSnapshotIndex < 0)
        {
            m_activityTableSnapshotIndex = -1;
            m_activityTableSnapshotRecords.clear();
        }
    }
    return removeCount > 0;
}

void ProcessDock::refreshProcessActivityTimeline(const bool indexShiftedLeft)
{
    if (m_activityTimelineSlider == nullptr)
    {
        return;
    }

    const bool oldUpdating = m_activityTimelineSliderUpdating;
    const int sampleCount = static_cast<int>(m_activitySamples.size());
    const int previousValue = (indexShiftedLeft && !m_activityTimelinePinnedToLatest)
        ? std::max(0, m_activityTimelineSlider->value())
        : m_activityTimelineSlider->value();
    const int previousMaximum = m_activityTimelineSlider->maximum();
    const bool shouldPinToLatest = m_activityTimelinePinnedToLatest || previousValue >= previousMaximum;

    m_activityTimelineSliderUpdating = true;
    m_activityTimelineSlider->setRange(0, std::max(0, sampleCount - 1));
    if (sampleCount == 0)
    {
        m_activityTimelineSlider->setValue(0);
    }
    else if (shouldPinToLatest)
    {
        m_activityTimelineSlider->setValue(sampleCount - 1);
        m_activityTimelinePinnedToLatest = true;
    }
    else
    {
        const int restoredValue = std::clamp(previousValue, 0, sampleCount - 1);
        m_activityTimelineSlider->setValue(restoredValue);
        m_activityTimelinePinnedToLatest = (restoredValue >= sampleCount - 1);
    }
    m_activityTimelineSliderUpdating = oldUpdating;

    if (sampleCount > 0)
    {
        if (m_activityTimelinePinnedToLatest)
        {
            m_activityTableSnapshotIndex = -1;
            m_activityTableSnapshotRecords.clear();
        }
        else if (isProcessActivityTableSnapshotActive())
        {
            rebuildProcessActivityTableSnapshotRecords();
        }
        previewProcessActivitySnapshotForIndex(m_activityTimelineSlider->value());
    }
    else if (m_activityChartWidget != nullptr)
    {
        m_activityChartWidget->setFocusedSampleIndex(-1);
    }
}

void ProcessDock::refreshProcessActivityChart()
{
    if (m_activityChartWidget != nullptr)
    {
        const int sampleIndex = (m_activityTimelineSlider != nullptr) ? m_activityTimelineSlider->value() : -1;
        m_activityChartWidget->setFocusedSampleIndex(sampleIndex);
        m_activityChartWidget->update();
    }
}

void ProcessDock::updateProcessActivityStatusLabel()
{
    const bool recordingAllowed = isProcessActivityRecordingAllowedNow();
    m_activityRecordingEnabled = recordingAllowed;
}

void ProcessDock::previewProcessActivitySnapshotForIndex(const int sampleIndex)
{
    if (m_activitySamples.empty())
    {
        m_activityTableSnapshotIndex = -1;
        m_activityTableSnapshotRecords.clear();
        if (m_activitySnapshotLabel != nullptr && m_activitySnapshotLabel->isVisible())
        {
            m_activitySnapshotLabel->setText(processContextText(
                "process.activity.snapshot.empty",
                QStringLiteral("时间轴快照：暂无样本")));
        }
        if (m_activityChartWidget != nullptr)
        {
            m_activityChartWidget->setFocusedSampleIndex(-1);
        }
        return;
    }

    const int safeIndex = std::clamp(sampleIndex, 0, static_cast<int>(m_activitySamples.size()) - 1);
    if (m_activityChartWidget != nullptr)
    {
        m_activityChartWidget->setFocusedSampleIndex(safeIndex);
    }
    if (m_activitySnapshotLabel != nullptr && m_activitySnapshotLabel->isVisible())
    {
        m_activitySnapshotLabel->setText(buildProcessActivitySnapshotText(safeIndex));
    }
}

void ProcessDock::showProcessActivitySnapshotForIndex(const int sampleIndex)
{
    previewProcessActivitySnapshotForIndex(sampleIndex);
}

void ProcessDock::commitProcessActivityTimelineIndex(const int sampleIndex)
{
    if (m_activitySamples.empty())
    {
        m_activityTableSnapshotIndex = -1;
        m_activityTableSnapshotRecords.clear();
        previewProcessActivitySnapshotForIndex(-1);
        rebuildTable();
        updateProcessActivityStatusLabel();
        return;
    }

    const int safeIndex = std::clamp(sampleIndex, 0, static_cast<int>(m_activitySamples.size()) - 1);
    const bool latestSelected =
        (m_activityTimelineSlider != nullptr && safeIndex >= m_activityTimelineSlider->maximum()) ||
        (safeIndex >= static_cast<int>(m_activitySamples.size()) - 1);

    m_activityTimelinePinnedToLatest = latestSelected;
    m_activityTableSnapshotIndex = latestSelected ? -1 : safeIndex;
    if (m_activityTimelineSlider != nullptr && m_activityTimelineSlider->value() != safeIndex)
    {
        const bool oldUpdating = m_activityTimelineSliderUpdating;
        m_activityTimelineSliderUpdating = true;
        m_activityTimelineSlider->setValue(safeIndex);
        m_activityTimelineSliderUpdating = oldUpdating;
    }

    previewProcessActivitySnapshotForIndex(safeIndex);
    rebuildProcessActivityTableSnapshotRecords();
    rebuildTable();
    updateProcessActivityStatusLabel();
}

bool ProcessDock::isProcessActivityTableSnapshotActive() const
{
    return m_activityTableSnapshotIndex >= 0 &&
        m_activityTableSnapshotIndex < static_cast<int>(m_activitySamples.size());
}

void ProcessDock::rebuildProcessActivityTableSnapshotRecords()
{
    m_activityTableSnapshotRecords.clear();
    if (!isProcessActivityTableSnapshotActive())
    {
        return;
    }

    const ProcessActivitySample& sample =
        m_activitySamples[static_cast<std::size_t>(m_activityTableSnapshotIndex)];
    m_activityTableSnapshotRecords.reserve(sample.processes.size());
    for (const ProcessActivityProcessPoint& processPoint : sample.processes)
    {
        ks::process::ProcessRecord record{};
        record.pid = processPoint.pid;
        record.parentPid = 0;
        record.creationTime100ns = processPoint.creationTime100ns;
        if (record.creationTime100ns == 0)
        {
            record.creationTime100ns = (sample.sequence + 1U) * 100000ULL + processPoint.pid;
        }
        record.processName = processPoint.processName.empty() ? std::string("PID ") + std::to_string(processPoint.pid) : processPoint.processName;
        record.imagePath = processPoint.imagePath.empty() ? std::string("历史快照") : processPoint.imagePath;
        record.commandLine = "时间轴历史样本";
        record.userName = "-";
        record.signatureState = "历史快照";
        record.startTimeText = QDateTime::fromMSecsSinceEpoch(sample.unixMilliseconds)
            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"))
            .toStdString();
        copyProcessActivityDynamicFields(record, processPoint);
        record.activePrivateWorkingSetBytes = processPoint.processSuspended
            ? 0U
            : processPoint.privateWorkingSetBytes;
        record.staticDetailsReady = true;
        record.dynamicCountersReady = true;
        m_activityTableSnapshotRecords.push_back(std::move(record));
    }
}

QString ProcessDock::buildProcessActivitySnapshotText(const int sampleIndex) const
{
    if (m_activitySamples.empty())
    {
        return QStringLiteral("时间轴快照：暂无样本");
    }

    const int safeIndex = std::clamp(sampleIndex, 0, static_cast<int>(m_activitySamples.size()) - 1);
    const ProcessActivitySample& sample = m_activitySamples[static_cast<std::size_t>(safeIndex)];
    const std::vector<std::string> selectionKeys = currentProcessActivitySelectionKeys();

    const double cpuValue = processActivitySampleMetricValue(sample, ProcessActivityMetric::Cpu, selectionKeys);
    const double memoryValue = processActivitySampleMetricValue(sample, ProcessActivityMetric::Memory, selectionKeys);
    const double diskValue = processActivitySampleMetricValue(sample, ProcessActivityMetric::Disk, selectionKeys);
    const double netValue = processActivitySampleMetricValue(sample, ProcessActivityMetric::Network, selectionKeys);
    const double gpuValue = processActivitySampleMetricValue(sample, ProcessActivityMetric::Gpu, selectionKeys);
    double maxDiskValue = 0.0;
    double maxNetValue = 0.0;
    for (const ProcessActivitySample& historySample : m_activitySamples)
    {
        maxDiskValue = std::max(maxDiskValue, processActivitySampleMetricValue(historySample, ProcessActivityMetric::Disk, selectionKeys));
        maxNetValue = std::max(maxNetValue, processActivitySampleMetricValue(historySample, ProcessActivityMetric::Network, selectionKeys));
    }
    const double memoryPercent = clampPercentValue(
        (memoryValue / std::max(1.0, m_activityTotalPhysicalMemoryMB)) * 100.0);
    const double diskPercent = clampPercentValue((diskValue / std::max(1.0, maxDiskValue)) * 100.0);
    const double netPercent = clampPercentValue((netValue / std::max(1.0, maxNetValue)) * 100.0);
    std::vector<ProcessActivityProcessPoint> matchedProcesses;
    if (!selectionKeys.empty())
    {
        for (const ProcessActivityProcessPoint& processPoint : sample.processes)
        {
            if (std::find(selectionKeys.begin(), selectionKeys.end(), processPoint.identityKey) == selectionKeys.end())
            {
                continue;
            }
            matchedProcesses.push_back(processPoint);
        }
    }

    const QDateTime sampleDateTime = QDateTime::fromMSecsSinceEpoch(sample.unixMilliseconds);
    QString text = processContextText(
        "process.activity.snapshot.template",
        QStringLiteral("时间轴快照：%1 / +%2 | 范围:%3 | CPU %4% | 内存 %5% (%6 MB) | 磁盘 %7% (%8 MB/s) | 网络 %9% (%10 KB/s) | GPU %11%"))
        .arg(sampleDateTime.toString(QStringLiteral("HH:mm:ss.zzz")))
        .arg(formatActivityElapsedText(sample.elapsedMs))
        .arg(selectionKeys.empty()
            ? processContextText("process.activity.snapshot.scope.total", QStringLiteral("总体"))
            : processContextText("process.activity.snapshot.scope.selected", QStringLiteral("选中%1个进程"))
                .arg(static_cast<qulonglong>(selectionKeys.size())))
        .arg(clampPercentValue(cpuValue), 0, 'f', 2)
        .arg(memoryPercent, 0, 'f', 2)
        .arg(memoryValue, 0, 'f', 1)
        .arg(diskPercent, 0, 'f', 2)
        .arg(diskValue, 0, 'f', 2)
        .arg(netPercent, 0, 'f', 2)
        .arg(netValue, 0, 'f', 2)
        .arg(gpuValue, 0, 'f', 1);

    QStringList enabledMetricTextList;
    const ProcessActivityMetric allMetrics[] = {
        ProcessActivityMetric::Cpu,
        ProcessActivityMetric::Memory,
        ProcessActivityMetric::Disk,
        ProcessActivityMetric::Network,
        ProcessActivityMetric::Gpu
    };
    for (const ProcessActivityMetric metric : allMetrics)
    {
        if (isProcessActivityMetricEnabled(metric))
        {
            const double metricValue = processActivitySampleMetricValue(sample, metric, selectionKeys);
            double percentValue = 0.0;
            switch (metric)
            {
            case ProcessActivityMetric::Cpu:
            case ProcessActivityMetric::Gpu:
                percentValue = clampPercentValue(metricValue);
                break;
            case ProcessActivityMetric::Memory:
                percentValue = memoryPercent;
                break;
            case ProcessActivityMetric::Disk:
                percentValue = diskPercent;
                break;
            case ProcessActivityMetric::Network:
                percentValue = netPercent;
                break;
            default:
                percentValue = 0.0;
                break;
            }
            enabledMetricTextList << QStringLiteral("%1 %2%3")
                .arg(processActivityMetricText(metric))
                .arg(percentValue, 0, 'f', percentValue >= 100.0 ? 1 : 2)
                .arg(processActivityMetricUnit(metric));
        }
    }
    if (!enabledMetricTextList.isEmpty())
    {
        text += QStringLiteral(" | 当前显示: %1").arg(enabledMetricTextList.join(QStringLiteral(", ")));
    }

    if (!selectionKeys.empty())
    {
        QStringList processTextList;
        const int maxProcessPreviewCount = 4;
        for (int i = 0; i < static_cast<int>(matchedProcesses.size()) && i < maxProcessPreviewCount; ++i)
        {
            const ProcessActivityProcessPoint& processPoint = matchedProcesses[static_cast<std::size_t>(i)];
            processTextList << QStringLiteral("%1(%2)")
                .arg(QString::fromStdString(processPoint.processName.empty() ? std::string("PID") : processPoint.processName))
                .arg(processPoint.pid);
        }
        if (matchedProcesses.size() > static_cast<std::size_t>(maxProcessPreviewCount))
        {
            processTextList << QStringLiteral("...");
        }
        text += QStringLiteral(" | 进程: %1").arg(processTextList.isEmpty() ? QStringLiteral("该时刻未出现") : processTextList.join(QStringLiteral(", ")));
    }
    else
    {
        text += QStringLiteral(" | 进程数: %1").arg(static_cast<qulonglong>(sample.processes.size()));
    }

    return text;
}

std::vector<std::string> ProcessDock::currentProcessActivitySelectionKeys() const
{
    // 使用已追踪的多选集合，避免读右键菜单冻结副本；
    // 图表只关心用户当前表格选择，不应被上下文菜单动作影响。
    std::vector<std::string> selectionKeys;
    std::unordered_set<std::string> visitedSet;
    if (m_processTable != nullptr)
    {
        const std::vector<QModelIndex> selectedRows = selectedProcessTableRowIndexes(false);
        selectionKeys.reserve(selectedRows.size());
        for (const QModelIndex& rowIndex : selectedRows)
        {
            const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
            if (tableRow == nullptr)
            {
                continue;
            }
            if (!tableRow->identityKey.empty() && visitedSet.insert(tableRow->identityKey).second)
            {
                selectionKeys.push_back(tableRow->identityKey);
            }
            for (const std::string& aggregateIdentityKey : tableRow->actionIdentityKeys)
            {
                if (!aggregateIdentityKey.empty() && visitedSet.insert(aggregateIdentityKey).second)
                {
                    selectionKeys.push_back(aggregateIdentityKey);
                }
            }
        }
    }
    if (isProcessActivityTableSnapshotActive() && selectionKeys.empty())
    {
        return selectionKeys;
    }
    if (selectionKeys.empty())
    {
        for (const std::string& identityKey : m_trackedSelectedIdentityKeys)
        {
            if (!identityKey.empty() &&
                m_cacheByIdentity.find(identityKey) != m_cacheByIdentity.end() &&
                visitedSet.insert(identityKey).second)
            {
                selectionKeys.push_back(identityKey);
            }
        }
    }
    return selectionKeys;
}


QVariant ProcessDock::processTableData(const ProcessTableRow& tableRow, const int column, const int role)
{
    // 参数和记录检查：模型可能在 reset 期间请求旧索引数据，空记录直接返回空值。
    if (column < 0 || column >= static_cast<int>(TableColumn::Count))
    {
        return {};
    }

    const ks::process::ProcessRecord& processRecord = tableRow.record;
    const TableColumn tableColumn = static_cast<TableColumn>(column);
    if (role == Qt::UserRole)
    {
        // UserRole 作用：
        // - 保留旧表格第 0 列保存 identityKey 的数据契约；
        // - 便于后续复制、右键动作或外部调试直接从模型索引读取稳定行标识；
        // - 返回该行 PID+创建时间组成的 identityKey 文本。
        return QString::fromStdString(tableRow.identityKey);
    }
    if (tableColumn == TableColumn::Name)
    {
        if (role == ProcessTreeDepthRole)
        {
            return tableRow.depth;
        }
        if (role == ProcessRowKindRole)
        {
            return static_cast<int>(tableRow.rowKind);
        }
        if (role == ProcessExpandableRole)
        {
            return tableRow.rowKind == ProcessTableRowKind::GroupHeader ||
                tableRow.rowKind == ProcessTableRowKind::ApplicationAggregate ||
                tableRow.hasChildren;
        }
        if (role == ProcessExpandedRole)
        {
            if (tableRow.rowKind == ProcessTableRowKind::ApplicationAggregate)
            {
                return m_friendlyExpandedStateByKey.value(tableRow.expansionKey, false);
            }
            if (tableRow.rowKind == ProcessTableRowKind::GroupHeader)
            {
                return m_friendlyExpandedStateByKey.value(tableRow.expansionKey, true);
            }
            return tableRow.hasChildren;
        }
    }
    if (tableColumn == TableColumn::CpuCore && role == Qt::SizeHintRole)
    {
        // CPU 列的首选宽度同时容纳现有百分比和全部逻辑处理器容量槽。
        // 返回 SizeHintRole 后，全局列宽自适应器不会把方框压成不可辨认的一排省略号。
        const QFontMetrics tableFontMetrics = m_processTable != nullptr
            ? m_processTable->fontMetrics()
            : QFontMetrics(QApplication::font());
        return ks::ui::ProcessCpuCapacityCellSizeHint(
            tableFontMetrics,
            m_logicalCpuCount);
    }
    if (tableColumn == TableColumn::CpuCore &&
        (tableRow.rowKind == ProcessTableRowKind::Process ||
            tableRow.rowKind == ProcessTableRowKind::ApplicationAggregate) &&
        !tableRow.activitySnapshotActive)
    {
        if (role == ks::ui::ProcessCpuUsageSnapshotRole &&
            m_latestCpuCoreUsageSnapshot != nullptr &&
            !tableRow.isExited &&
            !tableRow.cpuCoreProcessIds.isEmpty())
        {
            // QVariant 只复制 shared_ptr 控制块；应用父行和真实进程行共享同一轮 ETW 快照。
            return QVariant::fromValue(m_latestCpuCoreUsageSnapshot);
        }
        if (role == ks::ui::ProcessCpuProcessIdsRole)
        {
            return QVariant::fromValue(tableRow.cpuCoreProcessIds);
        }
        if (role == Qt::ToolTipRole)
        {
            return processContextText(
                "process.table.cell.cpu_core_summary_tooltip",
                QStringLiteral(
                    "CPU：%1%\n单核等效：%2%\n"
                    "每个扇形对应一个真实逻辑 CPU；悬停扇形查看处理器组、编号和本轮占用。"))
                .arg(processRecord.cpuPercent, 0, 'f', 2)
                .arg(processRecord.cpuCorePercent, 0, 'f', 2);
        }
    }
    if (tableRow.rowKind == ProcessTableRowKind::GroupHeader)
    {
        // GroupHeader is a synthetic non-process row:
        // - inputs are the stored title and expansion key;
        // - processing keeps only the Name column populated;
        // - return values are display/tooltip/paint roles, never process action data.
        if (role == Qt::DisplayRole)
        {
            if (tableColumn != TableColumn::Name)
            {
                return QString();
            }
            return tableRow.syntheticTitle;
        }
        if (role == Qt::ToolTipRole && tableColumn == TableColumn::Name)
        {
            return QStringLiteral("分类标题：双击可折叠/展开；不会作为进程操作目标。");
        }
        if (role == Qt::FontRole)
        {
            QFont font;
            font.setBold(true);
            return font;
        }
        if (role == Qt::ForegroundRole)
        {
            return QBrush(KswordTheme::PrimaryBlueColor);
        }
        if (role == Qt::BackgroundRole)
        {
            const QColor backgroundColor = KswordTheme::WithAlpha(
                KswordTheme::PrimaryBlueSubtleColor(),
                KswordTheme::IsDarkModeEnabled() ? 180 : 255);
            return QBrush(backgroundColor);
        }
        if (role == ProcessNumericSortRole)
        {
            return -1.0;
        }
        return {};
    }
    if (tableColumn == TableColumn::ProcessType)
    {
        // “类型”列的取值来自行的友好分组结果，而不是 ProcessRecord 字段；
        // rebuildTable 会在任意视图模式下为真实进程行填好 friendlyGroupType。
        if (role == Qt::DisplayRole)
        {
            return friendlyGroupTypeName(tableRow.friendlyGroupType);
        }
        if (role == ProcessNumericSortRole)
        {
            return static_cast<double>(static_cast<int>(tableRow.friendlyGroupType));
        }
    }
    if (tableRow.rowKind == ProcessTableRowKind::ApplicationAggregate)
    {
        // ApplicationAggregate is a synthetic application parent row:
        // - name comes from syntheticTitle and metrics come from the aggregate record;
        // - the row is selectable and expands actions to every real process in this application;
        // - double-click still controls expand/collapse and children remain normal process rows.
        if (role == Qt::DisplayRole)
        {
            if (tableColumn == TableColumn::Name)
            {
                return tableRow.syntheticTitle;
            }
            return formatColumnText(processRecord, tableColumn, tableRow.depth);
        }
        if (role == Qt::DecorationRole && tableColumn == TableColumn::Name)
        {
            return resolveProcessIcon(processRecord);
        }
        if (role == Qt::ToolTipRole && tableColumn == TableColumn::Name)
        {
            return processContextText(
                "process.friendly.aggregate.tooltip",
                QStringLiteral("应用聚合行：汇总该应用进程树；选中或右键后，进程动作会应用到全部成员；双击可折叠/展开。"));
        }
        if (role == Qt::FontRole)
        {
            QFont font;
            font.setBold(true);
            return font;
        }
    }
    if (role == Qt::DisplayRole)
    {
        // DisplayRole 只负责文本；Name 列层级线/图标由 delegate 统一绘制，避免图标落在缩进前。
        return formatColumnText(
            processRecord,
            tableColumn,
            tableColumn == TableColumn::Name ? 0 : tableRow.depth);
    }
    if (role == Qt::DecorationRole && tableColumn == TableColumn::Name)
    {
        // Name 列固定显示目标 EXE 图标（命中缓存后开销可控）。
        return resolveProcessIcon(processRecord);
    }
    if (role == Qt::ToolTipRole && tableColumn == TableColumn::Name)
    {
        if (tableRow.activitySnapshotActive)
        {
            return QStringLiteral("历史快照行：该行来自时间轴样本，不代表当前实时进程状态。");
        }
        if (processRecord.efficiencyModeEnabled)
        {
            return QStringLiteral("%1\n效率模式已启用")
                .arg(QString::fromStdString(processRecord.processName));
        }
        return QString::fromStdString(processRecord.processName);
    }
    if (role == ProcessEfficiencyModeKnownRole && tableColumn == TableColumn::Name)
    {
        return processRecord.efficiencyModeSupported;
    }
    if (role == ProcessEfficiencyModeRole && tableColumn == TableColumn::Name)
    {
        return processRecord.efficiencyModeEnabled;
    }
    if (role == ProcessNumericSortRole)
    {
        // 排序键使用原始数值：展示文本可以带单位，但排序必须按真实大小比较。
        switch (tableColumn)
        {
        case TableColumn::Pid:
            return static_cast<double>(processRecord.pid);
        case TableColumn::Cpu:
            return processRecord.cpuPercent;
        case TableColumn::CpuCore:
            return processRecord.cpuCorePercent;
        case TableColumn::Ram:
            return processRecord.workingSetMB;
        case TableColumn::Disk:
            return processRecord.diskMBps;
        case TableColumn::Gpu:
            return processRecord.gpuPercent;
        case TableColumn::Net:
            return processRecord.netKBps;
        case TableColumn::ParentPid:
            return static_cast<double>(processRecord.parentPid);
        case TableColumn::StartTime:
            return static_cast<double>(processRecord.creationTime100ns);
        case TableColumn::IsAdmin:
            return processRecord.isAdmin ? 1.0 : 0.0;
        case TableColumn::PplLevel:
            return processRecord.protectionLevelKnown ? static_cast<double>(processRecord.protectionLevel) : -1.0;
        case TableColumn::Protection:
        case TableColumn::Ppl:
            return static_cast<double>(processRecord.r0Protection);
        case TableColumn::HandleCount:
            return static_cast<double>(processRecord.handleCount);
        case TableColumn::HandleTable:
            return ((processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE) != 0U) ? 1.0 : 0.0;
        case TableColumn::SectionObject:
            return ((processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE) != 0U) ? 1.0 : 0.0;
        case TableColumn::R0Status:
            return static_cast<double>(processRecord.r0Status);

        // ======== 任务管理器对齐列的数值排序键 ========
        // 展示文本带单位或千位分隔符，排序必须回到原始数值，否则 "9 K" 会排在 "10,240 K" 之后。
        case TableColumn::Status:
            return processRecord.processStateKnown
                ? (processRecord.processSuspended ? 1.0 : 0.0)
                : -1.0;
        case TableColumn::SessionId:
            return static_cast<double>(processRecord.sessionId);
        case TableColumn::JobObject:
            return processRecord.jobObjectKnown
                ? (processRecord.inJobObject ? 1.0 : 0.0)
                : -1.0;
        case TableColumn::CpuTime:
            return static_cast<double>(processRecord.rawCpuTime100ns);
        case TableColumn::CycleTime:
            return processRecord.cycleTimeKnown ? static_cast<double>(processRecord.cycleTime) : -1.0;
        case TableColumn::WorkingSet:
            return static_cast<double>(processRecord.rawWorkingSetBytes);
        case TableColumn::PeakWorkingSet:
            return static_cast<double>(processRecord.peakWorkingSetBytes);
        case TableColumn::WorkingSetDelta:
            return static_cast<double>(processRecord.workingSetDeltaBytes);
        case TableColumn::ActivePrivateWorkingSet:
            return static_cast<double>(processRecord.activePrivateWorkingSetBytes);
        case TableColumn::PrivateWorkingSet:
            return static_cast<double>(processRecord.privateWorkingSetBytes);
        case TableColumn::SharedWorkingSet:
            return static_cast<double>(processRecord.sharedWorkingSetBytes);
        case TableColumn::CommitSize:
            return static_cast<double>(processRecord.commitSizeBytes);
        case TableColumn::PagedPool:
            return static_cast<double>(processRecord.pagedPoolBytes);
        case TableColumn::NonPagedPool:
            return static_cast<double>(processRecord.nonPagedPoolBytes);
        case TableColumn::PageFaults:
            return static_cast<double>(processRecord.pageFaultCount);
        case TableColumn::PageFaultDelta:
            return static_cast<double>(processRecord.pageFaultDeltaCount);
        case TableColumn::BasePriority:
            return static_cast<double>(processRecord.basePriority);
        case TableColumn::ThreadCount:
            return static_cast<double>(processRecord.threadCount);
        case TableColumn::UserObjects:
            return processRecord.guiResourceKnown ? static_cast<double>(processRecord.userObjectCount) : -1.0;
        case TableColumn::GdiObjects:
            return processRecord.guiResourceKnown ? static_cast<double>(processRecord.gdiObjectCount) : -1.0;
        case TableColumn::IoReads:
            return static_cast<double>(processRecord.ioReadOperationCount);
        case TableColumn::IoWrites:
            return static_cast<double>(processRecord.ioWriteOperationCount);
        case TableColumn::IoOther:
            return static_cast<double>(processRecord.ioOtherOperationCount);
        case TableColumn::IoReadBytes:
            return static_cast<double>(processRecord.ioReadTransferBytes);
        case TableColumn::IoWriteBytes:
            return static_cast<double>(processRecord.ioWriteTransferBytes);
        case TableColumn::IoOtherBytes:
            return static_cast<double>(processRecord.ioOtherTransferBytes);
        case TableColumn::UacVirtualization:
            return processFeatureStateSortValue(processRecord.uacVirtualizationState);
        case TableColumn::DataExecutionPrevention:
            return processFeatureStateSortValue(processRecord.dataExecutionPreventionState);
        case TableColumn::ControlFlowGuard:
            return processFeatureStateSortValue(processRecord.controlFlowGuardState);
        case TableColumn::HardwareStackProtection:
            return processFeatureStateSortValue(processRecord.hardwareStackProtectionState);
        case TableColumn::DpiAwareness:
            return (processRecord.dpiAwarenessLevel == ks::process::ProcessDpiAwarenessLevel::Unknown)
                ? -1.0
                : static_cast<double>(static_cast<std::uint32_t>(processRecord.dpiAwarenessLevel));
        case TableColumn::PowerThrottling:
            return processRecord.efficiencyModeSupported
                ? (processRecord.efficiencyModeEnabled ? 1.0 : 0.0)
                : -1.0;
        case TableColumn::GpuDedicatedMemory:
            return processRecord.gpuMemoryKnown
                ? static_cast<double>(processRecord.gpuDedicatedMemoryBytes)
                : -1.0;
        case TableColumn::GpuSharedMemory:
            return processRecord.gpuMemoryKnown
                ? static_cast<double>(processRecord.gpuSharedMemoryBytes)
                : -1.0;
        default:
            return {};
        }
    }
    if (role != Qt::BackgroundRole && role != Qt::ForegroundRole)
    {
        return {};
    }

    const QColor adminYesColor = KswordTheme::SuccessColor();
    const QColor adminNoColor = KswordTheme::ErrorColor();

    // 退出保留进程灰色高亮；CID 表弱引用/terminating 行灰色高亮；
    // 仅内核可见进程红色高亮；普通新增进程绿色高亮。
    if (tableRow.isExited)
    {
        return role == Qt::BackgroundRole
            ? QVariant(QBrush(KswordTheme::ExitedRowBackgroundColor()))
            : QVariant(QBrush(KswordTheme::ExitedRowForegroundColor()));
    }
    if ((processRecord.r0Flags &
        (KSWORD_ARK_PROCESS_FLAG_CID_TABLE_REFERENCE_FAILED |
            KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED)) != 0U)
    {
        return role == Qt::BackgroundRole
            ? QVariant(QBrush(KswordTheme::ExitedRowBackgroundColor()))
            : QVariant(QBrush(KswordTheme::ExitedRowForegroundColor()));
    }
    if (tableRow.isKernelOnly)
    {
        const QColor kernelOnlyForeground = KswordTheme::ErrorColor();
        const QColor kernelOnlyBackground = KswordTheme::WithAlpha(
            KswordTheme::ErrorBackgroundColor(),
            KswordTheme::IsDarkModeEnabled() ? 140 : 255);
        return role == Qt::BackgroundRole
            ? QVariant(QBrush(kernelOnlyBackground))
            : QVariant(QBrush(kernelOnlyForeground));
    }
    if (tableRow.isNew && role == Qt::BackgroundRole)
    {
        return QBrush(KswordTheme::NewRowBackgroundColor());
    }

    if (role == Qt::ForegroundRole)
    {
        // 管理员列：按要求使用“绿色/红色方块”直观显示状态。
        if (tableColumn == TableColumn::IsAdmin)
        {
            return QBrush(processRecord.isAdmin ? adminYesColor : adminNoColor);
        }
        // 数字签名列：非受信任时标红，方便快速识别风险进程。
        if (tableColumn == TableColumn::Signature)
        {
            if (!processRecord.signatureTrusted && processRecord.signatureState != "Pending")
            {
                return QBrush(adminNoColor);
            }
            if (processRecord.signatureTrusted)
            {
                return QBrush(adminYesColor);
            }
        }

        const auto highUsageForeground = [](const double usageRatio) -> QVariant
        {
            return usageRatio >= 0.70
                ? QVariant(QBrush(KswordTheme::OnAccentColor()))
                : QVariant();
        };
        switch (tableColumn)
        {
        case TableColumn::Cpu:
            return highUsageForeground(tableRow.cpuUsageRatio);
        case TableColumn::Ram:
            return highUsageForeground(tableRow.ramUsageRatio);
        case TableColumn::Disk:
            return highUsageForeground(tableRow.diskUsageRatio);
        case TableColumn::Gpu:
            return highUsageForeground(tableRow.gpuUsageRatio);
        case TableColumn::Net:
            return highUsageForeground(tableRow.netUsageRatio);
        case TableColumn::HandleCount:
            return highUsageForeground(tableRow.handleUsageRatio);
        default:
            return {};
        }
    }

    const auto usageBackground = [](const double usageRatio) -> QVariant
    {
        return QBrush(usageRatioToHighlightColor(usageRatio));
    };
    switch (tableColumn)
    {
    case TableColumn::Cpu:
        return usageBackground(tableRow.cpuUsageRatio);
    case TableColumn::Ram:
        return usageBackground(tableRow.ramUsageRatio);
    case TableColumn::Disk:
        return usageBackground(tableRow.diskUsageRatio);
    case TableColumn::Gpu:
        return usageBackground(tableRow.gpuUsageRatio);
    case TableColumn::Net:
        return usageBackground(tableRow.netUsageRatio);
    case TableColumn::HandleCount:
        return usageBackground(tableRow.handleUsageRatio);
    default:
        return {};
    }
}

const ProcessDock::ProcessTableRow* ProcessDock::processTableRowForViewIndex(const QModelIndex& viewIndex) const
{
    // 输入：QTableView/代理模型索引；处理：映射回 FlatTableModel 源行；返回：行指针或 nullptr。
    if (!viewIndex.isValid() || m_processSortProxy == nullptr || m_processTableModel == nullptr)
    {
        return nullptr;
    }

    const QModelIndex sourceIndex = m_processSortProxy->mapToSource(viewIndex);
    if (!sourceIndex.isValid())
    {
        return nullptr;
    }
    return m_processTableModel->rowAt(sourceIndex.row());
}

QModelIndex ProcessDock::processTableViewIndexForIdentityKey(const std::string& identityKey, const int column) const
{
    // 输入：稳定 identityKey 和目标列；处理：扫描模型行并映射到当前代理视图；返回：有效视图索引或空索引。
    if (identityKey.empty() || m_processSortProxy == nullptr || m_processTableModel == nullptr)
    {
        return QModelIndex();
    }

    const int safeColumn = std::clamp(column, 0, static_cast<int>(TableColumn::Count) - 1);
    const std::vector<ProcessTableRow>& rows = m_processTableModel->rows();
    for (int rowIndex = 0; rowIndex < static_cast<int>(rows.size()); ++rowIndex)
    {
        if (rows[static_cast<std::size_t>(rowIndex)].identityKey != identityKey)
        {
            continue;
        }

        const QModelIndex sourceIndex = m_processTableModel->index(rowIndex, safeColumn);
        return m_processSortProxy->mapFromSource(sourceIndex);
    }
    return QModelIndex();
}

std::vector<QModelIndex> ProcessDock::selectedProcessTableRowIndexes(const bool includeCurrentFallback) const
{
    // 输入：是否允许 currentIndex 兜底；处理：按行去重选中项；返回：每行第 0 列视图索引集合。
    std::vector<QModelIndex> rowIndexes;
    if (m_processTable == nullptr)
    {
        return rowIndexes;
    }

    std::set<int> visitedRows;
    if (QItemSelectionModel* selectionModel = m_processTable->selectionModel())
    {
        const QModelIndexList selectedRows = selectionModel->selectedRows(0);
        rowIndexes.reserve(static_cast<std::size_t>(selectedRows.size()));
        for (const QModelIndex& selectedIndex : selectedRows)
        {
            if (!selectedIndex.isValid() || !visitedRows.insert(selectedIndex.row()).second)
            {
                continue;
            }
            rowIndexes.push_back(selectedIndex);
        }

        const QModelIndex currentIndex = selectionModel->currentIndex();
        if (includeCurrentFallback && rowIndexes.empty() && currentIndex.isValid())
        {
            const QModelIndex rowIndex = currentIndex.sibling(currentIndex.row(), 0);
            if (rowIndex.isValid() && visitedRows.insert(rowIndex.row()).second)
            {
                rowIndexes.push_back(rowIndex);
            }
        }
    }
    return rowIndexes;
}

ProcessDock::ProcessActionTarget ProcessDock::processActionTargetFromTableRow(const ProcessTableRow& tableRow) const
{
    // 输入：模型行；处理：优先从实时缓存取完整记录，缓存缺失时用模型行 record 兜底；返回：动作目标副本。
    ProcessActionTarget actionTarget{};
    if (tableRow.rowKind != ProcessTableRowKind::Process)
    {
        return actionTarget;
    }
    actionTarget.identityKey = tableRow.identityKey;
    actionTarget.isKernelOnly = tableRow.isKernelOnly;
    if (actionTarget.identityKey.empty())
    {
        return actionTarget;
    }

    const auto cacheIt = m_cacheByIdentity.find(actionTarget.identityKey);
    if (cacheIt != m_cacheByIdentity.end())
    {
        actionTarget.record = cacheIt->second.record;
        actionTarget.isKernelOnly = cacheIt->second.isKernelOnlyInLatestRound;
        return actionTarget;
    }
    actionTarget.record = tableRow.record;
    return actionTarget;
}

void ProcessDock::appendProcessActionTargetsFromTableRow(
    const ProcessTableRow& tableRow,
    std::vector<ProcessActionTarget>& actionTargets,
    std::unordered_set<std::string>& visitedIdentitySet) const
{
    // 真实进程行追加一个目标；应用聚合行展开全部成员，保持和 Ctrl 多选完全相同的动作语义。
    const auto appendIdentityTarget = [this, &tableRow, &actionTargets, &visitedIdentitySet](const std::string& identityKey)
    {
        if (identityKey.empty() || !visitedIdentitySet.insert(identityKey).second)
        {
            return;
        }

        ProcessActionTarget actionTarget{};
        actionTarget.identityKey = identityKey;
        const auto cacheIt = m_cacheByIdentity.find(identityKey);
        if (cacheIt != m_cacheByIdentity.end())
        {
            actionTarget.record = cacheIt->second.record;
            actionTarget.isKernelOnly = cacheIt->second.isKernelOnlyInLatestRound;
        }
        else if (tableRow.rowKind == ProcessTableRowKind::Process && identityKey == tableRow.identityKey)
        {
            actionTarget.record = tableRow.record;
            actionTarget.isKernelOnly = tableRow.isKernelOnly;
        }
        else
        {
            visitedIdentitySet.erase(identityKey);
            return;
        }
        actionTargets.push_back(std::move(actionTarget));
    };

    if (tableRow.rowKind == ProcessTableRowKind::Process)
    {
        appendIdentityTarget(tableRow.identityKey);
        return;
    }
    if (tableRow.rowKind == ProcessTableRowKind::ApplicationAggregate)
    {
        for (const std::string& identityKey : tableRow.actionIdentityKeys)
        {
            appendIdentityTarget(identityKey);
        }
    }
}

std::vector<ProcessDock::DisplayRow> ProcessDock::buildDisplayOrder() const
{
    if (isProcessActivityTableSnapshotActive())
    {
        return buildActivitySnapshotDisplayOrder();
    }

    // 搜索激活时统一返回扁平结果：
    // - 用户搜索的目标是“快速定位进程”，不需要树结构干扰；
    // - 扁平结果还能避免父节点未命中时留下孤立缩进。
    if (!currentProcessSearchText().isEmpty())
    {
        return buildListDisplayOrder();
    }

    if (isFriendlyViewEnabled())
    {
        return buildFriendlyDisplayOrder();
    }

    return isTreeModeEnabled() ? buildTreeDisplayOrder() : buildListDisplayOrder();
}

std::vector<ProcessDock::DisplayRow> ProcessDock::buildActivitySnapshotDisplayOrder() const
{
    // 历史时间轴模式：
    // - 下方进程表直接展示当时样本中的进程快照；
    // - 不走实时缓存和树形父子排序，避免把历史时刻与当前系统状态混合。
    std::vector<DisplayRow> displayRows;
    displayRows.reserve(m_activityTableSnapshotRecords.size());
    for (const ks::process::ProcessRecord& processRecord : m_activityTableSnapshotRecords)
    {
        if (!processRecordMatchesSearch(processRecord))
        {
            continue;
        }

        DisplayRow displayRow{};
        displayRow.record = const_cast<ks::process::ProcessRecord*>(&processRecord);
        displayRow.depth = 0;
        displayRow.isNew = false;
        displayRow.isExited = false;
        displayRow.isKernelOnly = false;
        displayRows.push_back(displayRow);
    }

    std::sort(displayRows.begin(), displayRows.end(), [](const DisplayRow& leftRow, const DisplayRow& rightRow) {
        if (leftRow.record == nullptr || rightRow.record == nullptr)
        {
            return false;
        }
        return leftRow.record->pid < rightRow.record->pid;
    });
    return displayRows;
}

std::vector<ProcessDock::DisplayRow> ProcessDock::buildListDisplayOrder() const
{
    std::vector<DisplayRow> displayRows;
    displayRows.reserve(m_cacheByIdentity.size());

    for (const auto& cachePair : m_cacheByIdentity)
    {
        if (!processRecordMatchesSearch(cachePair.second.record))
        {
            continue;
        }

        DisplayRow displayRow{};
        displayRow.record = const_cast<ks::process::ProcessRecord*>(&cachePair.second.record);
        displayRow.depth = 0;
        displayRow.isNew = cachePair.second.isNewInLatestRound;
        displayRow.isExited = cachePair.second.isExitedInLatestRound;
        displayRow.isKernelOnly = cachePair.second.isKernelOnlyInLatestRound;
        displayRows.push_back(displayRow);
    }

    std::sort(displayRows.begin(), displayRows.end(), [](const DisplayRow& leftRow, const DisplayRow& rightRow) {
        if (leftRow.record == nullptr || rightRow.record == nullptr)
        {
            return false;
        }
        return leftRow.record->pid < rightRow.record->pid;
    });
    return displayRows;
}

std::vector<ProcessDock::DisplayRow> ProcessDock::buildTreeDisplayOrder() const
{
    // Step1：把缓存转换成便于处理的指针数组。
    struct Node
    {
        const std::string* identityKey = nullptr;
        const CacheEntry* cacheEntry = nullptr;
    };
    std::vector<Node> nodes;
    nodes.reserve(m_cacheByIdentity.size());
    for (const auto& cachePair : m_cacheByIdentity)
    {
        nodes.push_back(Node{ &cachePair.first, &cachePair.second });
    }

    // Step2：参照 KswordARKLight 的 ProcessModel，先建立 PID 来源索引，再关联有效父节点。
    std::unordered_map<std::uint32_t, std::vector<Node>> childrenByParentPid;
    std::unordered_map<std::uint32_t, const Node*> sourceNodeByPid;
    sourceNodeByPid.reserve(nodes.size());
    for (const Node& node : nodes)
    {
        if (node.cacheEntry == nullptr)
        {
            continue;
        }
        const std::uint32_t processId = node.cacheEntry->record.pid;
        const auto existingSourceIt = sourceNodeByPid.find(processId);
        if (existingSourceIt == sourceNodeByPid.end() ||
            (existingSourceIt->second->cacheEntry->isExitedInLatestRound && !node.cacheEntry->isExitedInLatestRound) ||
            node.cacheEntry->record.creationTime100ns > existingSourceIt->second->cacheEntry->record.creationTime100ns)
        {
            sourceNodeByPid[processId] = &node;
        }
    }

    const auto nodeLess = [](const Node& leftNode, const Node& rightNode)
    {
        if (leftNode.cacheEntry == nullptr || rightNode.cacheEntry == nullptr)
        {
            return leftNode.cacheEntry != nullptr;
        }
        const QString leftName = QString::fromStdString(leftNode.cacheEntry->record.processName);
        const QString rightName = QString::fromStdString(rightNode.cacheEntry->record.processName);
        const int nameResult = leftName.compare(rightName, Qt::CaseInsensitive);
        if (nameResult != 0)
        {
            return nameResult < 0;
        }
        if (leftNode.cacheEntry->record.pid != rightNode.cacheEntry->record.pid)
        {
            return leftNode.cacheEntry->record.pid < rightNode.cacheEntry->record.pid;
        }
        return leftNode.cacheEntry->record.creationTime100ns < rightNode.cacheEntry->record.creationTime100ns;
    };

    for (const Node& node : nodes)
    {
        if (node.cacheEntry == nullptr)
        {
            continue;
        }
        const std::uint32_t processId = node.cacheEntry->record.pid;
        const std::uint32_t parentPid = node.cacheEntry->record.parentPid;
        if (parentPid != 0U && parentPid != processId && sourceNodeByPid.find(parentPid) != sourceNodeByPid.end())
        {
            childrenByParentPid[parentPid].push_back(node);
        }
    }

    // 子列表按“名称（不区分大小写）+ PID”排序，与 KswordARKLight 的稳定顺序一致。
    for (auto& pair : childrenByParentPid)
    {
        auto& childNodes = pair.second;
        std::sort(childNodes.begin(), childNodes.end(), nodeLess);
    }

    // Step3：父 PID 不存在、为 0 或自引用时视为根节点。
    std::vector<Node> rootNodes;
    for (const Node& node : nodes)
    {
        if (node.cacheEntry == nullptr)
        {
            continue;
        }
        const std::uint32_t processId = node.cacheEntry->record.pid;
        const std::uint32_t parentPid = node.cacheEntry->record.parentPid;
        if (parentPid == 0U || parentPid == processId || sourceNodeByPid.find(parentPid) == sourceNodeByPid.end())
        {
            rootNodes.push_back(node);
        }
    }
    std::sort(rootNodes.begin(), rootNodes.end(), nodeLess);

    // Step4：DFS 生成“树状列表顺序 + 缩进深度”。
    std::vector<DisplayRow> displayRows;
    std::unordered_set<std::string> visitedIdentitySet;

    std::function<void(const Node&, int)> appendNode;
    appendNode = [&](const Node& node, const int depth)
        {
            if (node.identityKey == nullptr || node.cacheEntry == nullptr)
            {
                return;
            }
            if (visitedIdentitySet.find(*node.identityKey) != visitedIdentitySet.end())
            {
                return;
            }
            visitedIdentitySet.insert(*node.identityKey);

            DisplayRow displayRow{};
            displayRow.record = const_cast<ks::process::ProcessRecord*>(&node.cacheEntry->record);
            displayRow.depth = depth;
            displayRow.hasChildren =
                childrenByParentPid.find(node.cacheEntry->record.pid) != childrenByParentPid.end();
            displayRow.isNew = node.cacheEntry->isNewInLatestRound;
            displayRow.isExited = node.cacheEntry->isExitedInLatestRound;
            displayRow.isKernelOnly = node.cacheEntry->isKernelOnlyInLatestRound;
            displayRows.push_back(displayRow);

            const auto childIt = childrenByParentPid.find(node.cacheEntry->record.pid);
            if (childIt == childrenByParentPid.end())
            {
                return;
            }
            for (const Node& childNode : childIt->second)
            {
                appendNode(childNode, depth + 1);
            }
        };

    for (const Node& rootNode : rootNodes)
    {
        appendNode(rootNode, 0);
    }

    // 兜底：若仍有未访问节点（极端 parent 环），直接平铺补入。
    for (const Node& node : nodes)
    {
        if (node.identityKey == nullptr || node.cacheEntry == nullptr)
        {
            continue;
        }
        if (visitedIdentitySet.find(*node.identityKey) != visitedIdentitySet.end())
        {
            continue;
        }
        DisplayRow fallbackRow{};
        fallbackRow.record = const_cast<ks::process::ProcessRecord*>(&node.cacheEntry->record);
        fallbackRow.depth = 0;
        fallbackRow.hasChildren = childrenByParentPid.find(node.cacheEntry->record.pid) != childrenByParentPid.end();
        fallbackRow.isNew = node.cacheEntry->isNewInLatestRound;
        fallbackRow.isExited = node.cacheEntry->isExitedInLatestRound;
        fallbackRow.isKernelOnly = node.cacheEntry->isKernelOnlyInLatestRound;
        displayRows.push_back(fallbackRow);
    }

    return displayRows;
}

std::unordered_map<std::uint32_t, ProcessDock::FriendlyProcessGroupType>
ProcessDock::buildFriendlyGroupTypeByPid() const
{
    // 输入：当前进程缓存。
    // 处理：复用友好视图的三分类规则（可见窗口归属 -> 应用；Windows 目录下 -> 系统；其余 -> 后台）。
    // 返回：PID 到分组类型的映射，供“类型”列在任意视图模式下取值。
    std::unordered_map<std::uint32_t, FriendlyProcessGroupType> groupTypeByPid;
    groupTypeByPid.reserve(m_cacheByIdentity.size() * 2U + 1U);

    std::unordered_map<std::uint32_t, std::uint32_t> parentPidByPid;
    parentPidByPid.reserve(m_cacheByIdentity.size() * 2U + 1U);
    for (const auto& cachePair : m_cacheByIdentity)
    {
        parentPidByPid[cachePair.second.record.pid] = cachePair.second.record.parentPid;
    }

    const QSet<std::uint32_t> visibleWindowPidSet = collectVisibleWindowPidSet();
    wchar_t windowsDirectoryBuffer[MAX_PATH]{};
    QString windowsDirectoryPath;
    const UINT windowsDirectoryLength = ::GetWindowsDirectoryW(windowsDirectoryBuffer, MAX_PATH);
    if (windowsDirectoryLength > 0U)
    {
        windowsDirectoryPath = QDir::fromNativeSeparators(
            QString::fromWCharArray(windowsDirectoryBuffer, static_cast<int>(windowsDirectoryLength))).toLower();
    }

    for (const auto& cachePair : m_cacheByIdentity)
    {
        const ks::process::ProcessRecord& processRecord = cachePair.second.record;
        if (findFriendlyApplicationRootPid(processRecord.pid, parentPidByPid, visibleWindowPidSet) != 0U)
        {
            groupTypeByPid[processRecord.pid] = FriendlyProcessGroupType::Application;
            continue;
        }
        groupTypeByPid[processRecord.pid] =
            isFriendlyWindowsSystemProcess(processRecord, windowsDirectoryPath)
            ? FriendlyProcessGroupType::WindowsSystem
            : FriendlyProcessGroupType::Background;
    }

    return groupTypeByPid;
}

std::vector<ProcessDock::DisplayRow> ProcessDock::buildFriendlyDisplayOrder() const
{
    // Inputs: live process cache, hidden-item switch, and current visible-window owners.
    // Processing: classify rows into Application/Background/System, then emit a source-order
    // table that visually behaves like a tree while staying on QTableView + FlatTableModel.
    // Return: display rows containing group headers, application aggregates, and real processes.
    struct FriendlyNode
    {
        const std::string* identityKey = nullptr;
        const CacheEntry* cacheEntry = nullptr;
        std::uint32_t applicationRootPid = 0;
    };

    std::vector<FriendlyNode> nodes;
    nodes.reserve(m_cacheByIdentity.size());
    std::unordered_map<std::uint32_t, std::uint32_t> parentPidByPid;
    parentPidByPid.reserve(m_cacheByIdentity.size());

    for (const auto& cachePair : m_cacheByIdentity)
    {
        const ks::process::ProcessRecord& processRecord = cachePair.second.record;
        parentPidByPid[processRecord.pid] = processRecord.parentPid;
        nodes.push_back(FriendlyNode{ &cachePair.first, &cachePair.second, 0U });
    }

    const QSet<std::uint32_t> visibleWindowPidSet = collectVisibleWindowPidSet();
    wchar_t windowsDirectoryBuffer[MAX_PATH]{};
    QString windowsDirectoryPath;
    const UINT windowsDirectoryLength = ::GetWindowsDirectoryW(windowsDirectoryBuffer, MAX_PATH);
    if (windowsDirectoryLength > 0U)
    {
        windowsDirectoryPath = QDir::fromNativeSeparators(
            QString::fromWCharArray(windowsDirectoryBuffer, static_cast<int>(windowsDirectoryLength))).toLower();
    }

    std::vector<const FriendlyNode*> applicationNodes;
    std::vector<const FriendlyNode*> backgroundNodes;
    std::vector<const FriendlyNode*> systemNodes;
    applicationNodes.reserve(nodes.size());
    backgroundNodes.reserve(nodes.size());
    systemNodes.reserve(nodes.size());

    for (FriendlyNode& node : nodes)
    {
        if (node.cacheEntry == nullptr)
        {
            continue;
        }

        node.applicationRootPid = findFriendlyApplicationRootPid(
            node.cacheEntry->record.pid,
            parentPidByPid,
            visibleWindowPidSet);
        if (node.applicationRootPid != 0U)
        {
            applicationNodes.push_back(&node);
            continue;
        }

        if (isFriendlyWindowsSystemProcess(node.cacheEntry->record, windowsDirectoryPath))
        {
            systemNodes.push_back(&node);
        }
        else
        {
            backgroundNodes.push_back(&node);
        }
    }

    const int friendlySortColumn = std::clamp(
        m_friendlySortColumn,
        0,
        static_cast<int>(TableColumn::Count) - 1);
    const Qt::SortOrder friendlySortOrder = m_friendlySortOrder;
    const auto compareRecordByFriendlySort =
        [friendlySortColumn, friendlySortOrder](
            const ks::process::ProcessRecord& leftRecord,
            const ks::process::ProcessRecord& rightRecord) -> bool
        {
            // Inputs: two process records and the active friendly-view sort column/order.
            // Processing: compare only the primary selected column with the selected direction,
            // then use name/PID/creation time as ascending tie breakers so rows do not jitter.
            // Return: true when left should be displayed before right.
            const auto compareText = [](const QString& leftText, const QString& rightText) -> int
            {
                const int caseInsensitiveResult = leftText.compare(rightText, Qt::CaseInsensitive);
                if (caseInsensitiveResult != 0)
                {
                    return caseInsensitiveResult;
                }
                return leftText.compare(rightText, Qt::CaseSensitive);
            };
            const auto compareDouble = [](const double leftValue, const double rightValue) -> int
            {
                if (std::fabs(leftValue - rightValue) <= 0.001)
                {
                    return 0;
                }
                return leftValue < rightValue ? -1 : 1;
            };
            const auto compareUInt64 = [](const std::uint64_t leftValue, const std::uint64_t rightValue) -> int
            {
                if (leftValue == rightValue)
                {
                    return 0;
                }
                return leftValue < rightValue ? -1 : 1;
            };

            int primaryResult = 0;
            switch (static_cast<TableColumn>(friendlySortColumn))
            {
            case TableColumn::Name:
                primaryResult = compareText(
                    QString::fromStdString(leftRecord.processName),
                    QString::fromStdString(rightRecord.processName));
                break;
            case TableColumn::Pid:
                primaryResult = compareUInt64(leftRecord.pid, rightRecord.pid);
                break;
            case TableColumn::Cpu:
                primaryResult = compareDouble(leftRecord.cpuPercent, rightRecord.cpuPercent);
                break;
            case TableColumn::CpuCore:
                primaryResult = compareDouble(
                    leftRecord.cpuCorePercent,
                    rightRecord.cpuCorePercent);
                break;
            case TableColumn::Ram:
                primaryResult = compareDouble(leftRecord.workingSetMB, rightRecord.workingSetMB);
                break;
            case TableColumn::Disk:
                primaryResult = compareDouble(leftRecord.diskMBps, rightRecord.diskMBps);
                break;
            case TableColumn::Gpu:
                primaryResult = compareDouble(leftRecord.gpuPercent, rightRecord.gpuPercent);
                break;
            case TableColumn::Net:
                primaryResult = compareDouble(leftRecord.netKBps, rightRecord.netKBps);
                break;
            case TableColumn::Signature:
                primaryResult = compareText(
                    QString::fromStdString(leftRecord.signatureState),
                    QString::fromStdString(rightRecord.signatureState));
                break;
            case TableColumn::Path:
                primaryResult = compareText(
                    QString::fromStdString(leftRecord.imagePath),
                    QString::fromStdString(rightRecord.imagePath));
                break;
            case TableColumn::ParentPid:
                primaryResult = compareUInt64(leftRecord.parentPid, rightRecord.parentPid);
                break;
            case TableColumn::CommandLine:
                primaryResult = compareText(
                    QString::fromStdString(leftRecord.commandLine),
                    QString::fromStdString(rightRecord.commandLine));
                break;
            case TableColumn::User:
                primaryResult = compareText(
                    QString::fromStdString(leftRecord.userName),
                    QString::fromStdString(rightRecord.userName));
                break;
            case TableColumn::StartTime:
                primaryResult = compareUInt64(leftRecord.creationTime100ns, rightRecord.creationTime100ns);
                break;
            case TableColumn::IsAdmin:
                primaryResult = compareUInt64(leftRecord.isAdmin ? 1U : 0U, rightRecord.isAdmin ? 1U : 0U);
                break;
            case TableColumn::PplLevel:
                primaryResult = compareUInt64(leftRecord.protectionLevel, rightRecord.protectionLevel);
                break;
            case TableColumn::Protection:
            case TableColumn::Ppl:
                primaryResult = compareUInt64(leftRecord.r0Protection, rightRecord.r0Protection);
                break;
            case TableColumn::HandleCount:
                primaryResult = compareUInt64(leftRecord.handleCount, rightRecord.handleCount);
                break;
            case TableColumn::HandleTable:
                primaryResult = compareUInt64(
                    (leftRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE) != 0U ? 1U : 0U,
                    (rightRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE) != 0U ? 1U : 0U);
                break;
            case TableColumn::SectionObject:
                primaryResult = compareUInt64(
                    (leftRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE) != 0U ? 1U : 0U,
                    (rightRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE) != 0U ? 1U : 0U);
                break;
            case TableColumn::R0Status:
                primaryResult = compareUInt64(leftRecord.r0Status, rightRecord.r0Status);
                break;
            default:
                primaryResult = 0;
                break;
            }

            if (primaryResult != 0)
            {
                return friendlySortOrder == Qt::AscendingOrder
                    ? primaryResult < 0
                    : primaryResult > 0;
            }

            const int nameTieResult = compareText(
                QString::fromStdString(leftRecord.processName),
                QString::fromStdString(rightRecord.processName));
            if (nameTieResult != 0)
            {
                return nameTieResult < 0;
            }
            if (leftRecord.pid != rightRecord.pid)
            {
                return leftRecord.pid < rightRecord.pid;
            }
            return leftRecord.creationTime100ns < rightRecord.creationTime100ns;
        };

    const auto processSorter = [&compareRecordByFriendlySort](const FriendlyNode* leftNode, const FriendlyNode* rightNode) -> bool
    {
        if (leftNode == nullptr || rightNode == nullptr ||
            leftNode->cacheEntry == nullptr || rightNode->cacheEntry == nullptr)
        {
            return leftNode < rightNode;
        }

        return compareRecordByFriendlySort(leftNode->cacheEntry->record, rightNode->cacheEntry->record);
    };

    std::sort(applicationNodes.begin(), applicationNodes.end(), processSorter);
    std::sort(backgroundNodes.begin(), backgroundNodes.end(), processSorter);
    std::sort(systemNodes.begin(), systemNodes.end(), processSorter);

    m_friendlySyntheticRecords.clear();
    m_friendlySyntheticRecords.reserve(applicationNodes.size() + 3U);

    std::vector<DisplayRow> displayRows;
    displayRows.reserve(nodes.size() + applicationNodes.size() + 3U);

    const auto appendSyntheticRecordRow =
        [this, &displayRows](
            const ks::process::ProcessRecord& syntheticRecord,
            const ProcessTableRowKind rowKind,
            const FriendlyProcessGroupType groupType,
            const QString& title,
            const QString& expansionKey,
            const std::vector<std::string>& actionIdentityKeys,
            const int depth)
        {
            // Inputs: prepared synthetic ProcessRecord and row metadata.
            // Processing: store the record in a stable member vector, then add a DisplayRow pointer.
            // Return: no value; displayRows receives one synthetic row.
            m_friendlySyntheticRecords.push_back(syntheticRecord);

            DisplayRow displayRow{};
            displayRow.record = &m_friendlySyntheticRecords.back();
            displayRow.rowKind = rowKind;
            displayRow.friendlyGroupType = groupType;
            displayRow.syntheticTitle = title;
            displayRow.expansionKey = expansionKey;
            displayRow.actionIdentityKeys = actionIdentityKeys;
            displayRow.depth = depth;
            displayRow.hasChildren = rowKind == ProcessTableRowKind::GroupHeader ||
                rowKind == ProcessTableRowKind::ApplicationAggregate;
            displayRows.push_back(std::move(displayRow));
        };

    const auto appendGroupHeader =
        [&appendSyntheticRecordRow](const FriendlyProcessGroupType groupType, const int entryCount)
        {
            ks::process::ProcessRecord syntheticRecord{};
            syntheticRecord.processName = friendlyGroupTitle(groupType, entryCount).toStdString();
            syntheticRecord.imagePath = "[FriendlyGroup]";
            appendSyntheticRecordRow(
                syntheticRecord,
                ProcessTableRowKind::GroupHeader,
                groupType,
                friendlyGroupTitle(groupType, entryCount),
                friendlyExpansionKeyForGroup(groupType),
                {},
                0);
        };

    const auto appendRealNode =
        [&displayRows](const FriendlyNode* node, const int depth, const bool hasChildren = false)
        {
            if (node == nullptr || node->cacheEntry == nullptr)
            {
                return;
            }

            DisplayRow displayRow{};
            displayRow.record = const_cast<ks::process::ProcessRecord*>(&node->cacheEntry->record);
            displayRow.rowKind = ProcessTableRowKind::Process;
            displayRow.depth = depth;
            displayRow.hasChildren = hasChildren;
            displayRow.isNew = node->cacheEntry->isNewInLatestRound;
            displayRow.isExited = node->cacheEntry->isExitedInLatestRound;
            displayRow.isKernelOnly = node->cacheEntry->isKernelOnlyInLatestRound;
            displayRows.push_back(std::move(displayRow));
        };

    appendGroupHeader(FriendlyProcessGroupType::Application, static_cast<int>(applicationNodes.size()));
    if (m_friendlyExpandedStateByKey.value(
        friendlyExpansionKeyForGroup(FriendlyProcessGroupType::Application),
        true))
    {
        std::unordered_map<std::uint32_t, std::vector<const FriendlyNode*>> applicationNodesByRootPid;
        for (const FriendlyNode* node : applicationNodes)
        {
            if (node == nullptr || node->cacheEntry == nullptr)
            {
                continue;
            }
            const std::uint32_t rootPid = node->applicationRootPid != 0U
                ? node->applicationRootPid
                : node->cacheEntry->record.pid;
            applicationNodesByRootPid[rootPid].push_back(node);
        }

        std::vector<std::pair<std::uint32_t, std::vector<const FriendlyNode*>>> applicationBuckets;
        applicationBuckets.reserve(applicationNodesByRootPid.size());
        for (auto& bucketPair : applicationNodesByRootPid)
        {
            std::sort(bucketPair.second.begin(), bucketPair.second.end(), processSorter);
            applicationBuckets.push_back(std::make_pair(bucketPair.first, std::move(bucketPair.second)));
        }

        const auto aggregateApplicationBucket =
            [](const std::vector<const FriendlyNode*>& bucketNodes, const std::uint32_t rootPid)
            {
                std::vector<const CacheEntry*> cacheEntries;
                cacheEntries.reserve(bucketNodes.size());
                for (const FriendlyNode* node : bucketNodes)
                {
                    if (node != nullptr && node->cacheEntry != nullptr)
                    {
                        cacheEntries.push_back(node->cacheEntry);
                    }
                }
                return aggregateFriendlyApplicationRecord(cacheEntries, rootPid);
            };

        std::sort(
            applicationBuckets.begin(),
            applicationBuckets.end(),
            [&aggregateApplicationBucket, &compareRecordByFriendlySort](const auto& leftBucket, const auto& rightBucket)
            {
                const ks::process::ProcessRecord leftAggregate =
                    aggregateApplicationBucket(leftBucket.second, leftBucket.first);
                const ks::process::ProcessRecord rightAggregate =
                    aggregateApplicationBucket(rightBucket.second, rightBucket.first);
                return compareRecordByFriendlySort(leftAggregate, rightAggregate);
            });

        for (const auto& bucket : applicationBuckets)
        {
            const std::uint32_t rootPid = bucket.first;
            const std::vector<const FriendlyNode*>& bucketNodes = bucket.second;
            if (bucketNodes.empty())
            {
                continue;
            }

            const ks::process::ProcessRecord aggregateRecord =
                aggregateApplicationBucket(bucketNodes, rootPid);
            std::vector<std::string> aggregateActionIdentityKeys;
            aggregateActionIdentityKeys.reserve(bucketNodes.size());
            for (const FriendlyNode* bucketNode : bucketNodes)
            {
                if (bucketNode != nullptr &&
                    bucketNode->identityKey != nullptr &&
                    !bucketNode->identityKey->empty())
                {
                    aggregateActionIdentityKeys.push_back(*bucketNode->identityKey);
                }
            }
            appendSyntheticRecordRow(
                aggregateRecord,
                ProcessTableRowKind::ApplicationAggregate,
                FriendlyProcessGroupType::Application,
                QStringLiteral("%1 (%2)").arg(QString::fromStdString(aggregateRecord.processName)).arg(bucketNodes.size()),
                friendlyExpansionKeyForApplication(rootPid),
                aggregateActionIdentityKeys,
                1);

            if (!m_friendlyExpandedStateByKey.value(friendlyExpansionKeyForApplication(rootPid), false))
            {
                continue;
            }

            std::unordered_map<std::uint32_t, std::vector<const FriendlyNode*>> childrenByParentPid;
            childrenByParentPid.reserve(bucketNodes.size());
            for (const FriendlyNode* node : bucketNodes)
            {
                if (node == nullptr || node->cacheEntry == nullptr)
                {
                    continue;
                }
                childrenByParentPid[node->cacheEntry->record.parentPid].push_back(node);
            }
            for (auto& childPair : childrenByParentPid)
            {
                std::sort(childPair.second.begin(), childPair.second.end(), processSorter);
            }

            std::unordered_set<std::uint32_t> emittedPidSet;
            const std::function<void(const FriendlyNode*, int)> appendTreeNode =
                [&](const FriendlyNode* node, const int depth)
                {
                    if (node == nullptr || node->cacheEntry == nullptr)
                    {
                        return;
                    }
                    const std::uint32_t pid = node->cacheEntry->record.pid;
                    if (!emittedPidSet.insert(pid).second)
                    {
                        return;
                    }

                    appendRealNode(
                        node,
                        depth,
                        childrenByParentPid.find(pid) != childrenByParentPid.end());
                    const auto childIt = childrenByParentPid.find(pid);
                    if (childIt == childrenByParentPid.end())
                    {
                        return;
                    }
                    for (const FriendlyNode* childNode : childIt->second)
                    {
                        appendTreeNode(childNode, depth + 1);
                    }
                };

            const auto rootIt = std::find_if(
                bucketNodes.cbegin(),
                bucketNodes.cend(),
                [rootPid](const FriendlyNode* node)
                {
                    return node != nullptr &&
                        node->cacheEntry != nullptr &&
                        node->cacheEntry->record.pid == rootPid;
                });
            if (rootIt != bucketNodes.cend())
            {
                appendTreeNode(*rootIt, 2);
            }

            for (const FriendlyNode* node : bucketNodes)
            {
                if (node == nullptr || node->cacheEntry == nullptr)
                {
                    continue;
                }
                if (emittedPidSet.find(node->cacheEntry->record.pid) == emittedPidSet.end())
                {
                    appendTreeNode(node, 2);
                }
            }
        }
    }

    const auto appendFlatGroup =
        [&](const FriendlyProcessGroupType groupType, const std::vector<const FriendlyNode*>& groupNodes)
        {
            appendGroupHeader(groupType, static_cast<int>(groupNodes.size()));
            if (!m_friendlyExpandedStateByKey.value(friendlyExpansionKeyForGroup(groupType), true))
            {
                return;
            }
            for (const FriendlyNode* node : groupNodes)
            {
                appendRealNode(node, 1);
            }
        };
    appendFlatGroup(FriendlyProcessGroupType::Background, backgroundNodes);
    appendFlatGroup(FriendlyProcessGroupType::WindowsSystem, systemNodes);

    return displayRows;
}

void ProcessDock::showTableContextMenu(const QPoint& localPosition)
{
    const QModelIndex clickedIndex = m_processTable->indexAt(localPosition);
    if (!clickedIndex.isValid())
    {
        clearContextActionBinding();
        return;
    }

    const ProcessTableRow* clickedTableRow = processTableRowForViewIndex(clickedIndex);
    if (clickedTableRow == nullptr || clickedTableRow->rowKind == ProcessTableRowKind::GroupHeader)
    {
        clearContextActionBinding();
        return;
    }

    // 右键行为：
    // - 若右键点在已有多选集合内，则保持集合不变，菜单动作对所有选中行生效；
    // - 若右键点在未选中行上，则切换为该单行，保持传统右键体验。
    if (QItemSelectionModel* selectionModel = m_processTable->selectionModel())
    {
        const bool clickedRowAlreadySelected = selectionModel->isRowSelected(clickedIndex.row(), clickedIndex.parent());
        if (!clickedRowAlreadySelected)
        {
            selectionModel->clearSelection();
            selectionModel->select(clickedIndex, QItemSelectionModel::Select | QItemSelectionModel::Rows);
        }
        selectionModel->setCurrentIndex(clickedIndex, QItemSelectionModel::NoUpdate);
    }

    bindContextActionToIndex(clickedIndex);
    const std::vector<ProcessActionTarget> contextActionTargets = selectedActionTargets();
    const bool hasBatchSelection = contextActionTargets.size() > 1;
    const ks::process::ProcessRecord* contextProcessRecord =
        contextActionTargets.empty() ? nullptr : &contextActionTargets.front().record;
    DWORD contextIntegrityRid = 0;
    std::string contextIntegrityDetailText;
    const bool contextIntegrityKnown = contextProcessRecord != nullptr &&
        queryProcessIntegrityRid(
            contextProcessRecord->pid,
            &contextIntegrityRid,
            &contextIntegrityDetailText);

    QMenu contextMenu(this);
    // 右键菜单显式样式：避免浅色模式在透明父控件下出现黑底黑字。
    contextMenu.setStyleSheet(buildThreadContextMenuStyle());

    // R0 动作继续使用对应业务图标；动作文字和分组已经明确标注 R0 来源。
    const auto buildR0ActionIcon = [this](const char* iconPath) -> QIcon
    {
        return blueTintedIcon(iconPath);
    };

    QAction* copyCellAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_copy_cell.svg"),
        processContextText("process.menu.copy_cell", QStringLiteral("复制单元格")));
    QAction* copyRowAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_copy_row.svg"),
        processContextText("process.menu.copy_row", QStringLiteral("复制行")));
    contextMenu.addSeparator();
    if (hasBatchSelection)
    {
        QAction* batchHintAction = contextMenu.addAction(
            blueTintedIcon(":/Icon/process_list.svg"),
            processContextText(
                "process.menu.batch_hint",
                QStringLiteral("已选择 %1 个进程，支持批量动作")).arg(contextActionTargets.size()));
        batchHintAction->setEnabled(false);
        contextMenu.addSeparator();
    }

    // 结束动作区：
    // - 取消“结束进程”二级菜单，改为一级动作；
    // - 进程树目标只从当前 R3 快照的父 PID 关系推导，R0 不参与识别；
    // - R0 进程树逐 PID 复用现有结束进程 IOCTL，不新增树专用协议。
    QAction* terminateProcessAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.terminate", QStringLiteral("结束进程")));
    QAction* terminateAndDeleteImageAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        processContextText(
            "process.menu.terminate_delete_image",
            QStringLiteral("结束进程并删除映像文件")));
    const bool canDeleteSingleImage = contextActionTargets.size() == 1U &&
        contextActionTargets.front().record.pid != 0U &&
        contextActionTargets.front().record.creationTime100ns != 0U &&
        !contextActionTargets.front().record.imagePath.empty();
    terminateAndDeleteImageAction->setEnabled(canDeleteSingleImage);
    terminateAndDeleteImageAction->setToolTip(
        canDeleteSingleImage
            ? processContextText(
                "process.menu.terminate_delete_image.tooltip",
                QStringLiteral("绑定当前 PID 创建时间和文件 ID；确认退出后删除同一映像文件对象"))
            : processContextText(
                "process.menu.terminate_delete_image.unavailable",
                QStringLiteral("仅支持单选且必须具有可验证的 PID 创建时间与映像路径")));
    QAction* terminateProcessTreeAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.terminate_tree", QStringLiteral("结束进程树")));
    QAction* r0TerminateAction = contextMenu.addAction(
        buildR0ActionIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.r0_terminate", QStringLiteral("R0结束进程")));
    QAction* r0TerminateTreeAction = contextMenu.addAction(
        buildR0ActionIcon(":/Icon/process_terminate.svg"),
        processContextText("process.menu.r0_terminate_tree", QStringLiteral("R0结束进程树")));
    QAction* r0SuspendAction = contextMenu.addAction(
        buildR0ActionIcon(":/Icon/process_suspend.svg"),
        processContextText("process.menu.r0_suspend", QStringLiteral("R0挂起进程")));
    QAction* refreshPplLevelAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_refresh.svg"),
        processContextText("process.menu.refresh_ppl", QStringLiteral("手动刷新PPL保护级别")));
    refreshPplLevelAction->setToolTip(QStringLiteral("查询 ProcessProtectionLevelInfo；结果只更新当前列表快照，不写入跨轮缓存。"));
    QMenu* r0PplLevelSubMenu = contextMenu.addMenu(
        buildR0ActionIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.set_ppl", QStringLiteral("R0设置进程保护(PPL/PP)")));
    QAction* r0PplNoneAction = r0PplLevelSubMenu->addAction(
        buildR0ActionIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.close_ppl", QStringLiteral("关闭进程保护 (0x00)")));
    r0PplNoneAction->setData(0x00U);
    // 保护预设：
    // - signer 命名/数值与 PPLcontrol 的 PsProtectedSigner* 对齐；
    // - protectionLevel = (Signer << 4) | Type；Type=1 是 PPL，Type=2 是完整 PP；
    // - 同一 signer 下 PP 强于 PPL：PPL 进程也拿不到 PP 进程的高权限句柄。
    struct ProcessProtectionSignerPreset
    {
        int signerValue;         // signerValue：Signer 数值（1~7）。
        const char* signerName;  // signerName：菜单展示名称。
        const char* meaningText; // meaningText：菜单展示释义。
    };
    const ProcessProtectionSignerPreset presetList[] =
    {
        { 1, "Authenticode", "签名代码（Authenticode）" },
        { 2, "CodeGen", "动态代码生成" },
        { 3, "Antimalware", "反恶意软件" },
        { 4, "Lsa", "本地安全机构" },
        { 5, "Windows", "Windows 组件" },
        { 6, "WinTcb", "可信计算基础（最高）" },
        { 7, "WinSystem", "系统 signer（System 进程同级）" }
    };
    struct ProcessProtectionTypePreset
    {
        unsigned int typeValue;     // typeValue：PS_PROTECTION 类型位。
        const char* sectionTextUtf8; // sectionTextUtf8：分组标题。
    };
    const ProcessProtectionTypePreset typeList[] =
    {
        { 1U, "PPL 轻量保护（Type=1）" },
        { 2U, "PP 完整保护（Type=2，更强）" }
    };
    for (const ProcessProtectionTypePreset& typeEntry : typeList)
    {
        r0PplLevelSubMenu->addSection(QString::fromUtf8(typeEntry.sectionTextUtf8));
        for (const ProcessProtectionSignerPreset& presetEntry : presetList)
        {
            const unsigned int protectionLevel =
                (static_cast<unsigned int>(presetEntry.signerValue) << 4U) | typeEntry.typeValue;
            const QString protectionLevelHexText = QStringLiteral("0x%1")
                .arg(protectionLevel, 2, 16, QChar('0'))
                .toUpper();
            QAction* presetAction = r0PplLevelSubMenu->addAction(
                buildR0ActionIcon(":/Icon/process_critical.svg"),
                QStringLiteral("%1 (%2) → %3 [%4]")
                .arg(QString::fromLatin1(presetEntry.signerName))
                .arg(presetEntry.signerValue)
                .arg(QString::fromUtf8(presetEntry.meaningText))
                .arg(protectionLevelHexText));
            presetAction->setData(protectionLevel);
        }
    }
    QMenu* r0VisibilitySubMenu = contextMenu.addMenu(
        buildR0ActionIcon(":/Icon/process_details.svg"),
        processContextText("process.menu.hide", QStringLiteral("R0进程隐藏(可恢复)")));
    QAction* r0HideUnlinkOnlyAction = r0VisibilitySubMenu->addAction(
        buildR0ActionIcon(":/Icon/process_suspend.svg"),
        processContextText("process.menu.hide_unlink", QStringLiteral("隐藏选中进程：只断链")));
    QAction* r0HidePatchPidOnlyAction = r0VisibilitySubMenu->addAction(
        buildR0ActionIcon(":/Icon/process_uncritical.svg"),
        processContextText("process.menu.hide_pid", QStringLiteral("隐藏选中进程：只改PID")));
    QAction* r0HideLegacyBothAction = r0VisibilitySubMenu->addAction(
        buildR0ActionIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.hide_legacy", QStringLiteral("隐藏选中进程：改PID+断链(旧版高风险)")));
    r0VisibilitySubMenu->addSeparator();
    QAction* r0UnhideProcessAction = r0VisibilitySubMenu->addAction(
        buildR0ActionIcon(":/Icon/process_resume.svg"),
        processContextText("process.menu.unhide", QStringLiteral("取消隐藏选中进程")));
    QAction* r0ClearHiddenProcessAction = r0VisibilitySubMenu->addAction(
        buildR0ActionIcon(":/Icon/log_clear.svg"),
        processContextText("process.menu.clear_hidden", QStringLiteral("清空全部隐藏标记")));
    r0HideUnlinkOnlyAction->setToolTip(QStringLiteral("只摘除 ActiveProcessLinks，不修改 PID；Ksword 更容易按原 PID 找回和恢复。"));
    r0HidePatchPidOnlyAction->setToolTip(QStringLiteral("只修改 UniqueProcessId，不摘链；高风险，可能影响按原 PID 查找目标。"));
    r0HideLegacyBothAction->setToolTip(QStringLiteral("兼容旧版：同时修改 UniqueProcessId 并摘除 ActiveProcessLinks；风险最高，仅用于复现实验。"));
    r0UnhideProcessAction->setToolTip(QStringLiteral("恢复由 Ksword 记录的 UniqueProcessId 和进程链表位置；若原位置不再相邻，则挂回 System 链头后。"));
    r0ClearHiddenProcessAction->setToolTip(QStringLiteral("恢复所有由 Ksword 摘链的进程，并清空驱动内记录。"));
    QMenu* criticalProcessSubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.critical", QStringLiteral("关键进程 / BreakOnTermination")));
    QAction* setCriticalAction = criticalProcessSubMenu->addAction(
        blueTintedIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.r3_critical", QStringLiteral("R3设为关键进程")));
    QAction* clearCriticalAction = criticalProcessSubMenu->addAction(
        blueTintedIcon(":/Icon/process_uncritical.svg"),
        processContextText("process.menu.r3_uncritical", QStringLiteral("R3取消关键进程")));
    criticalProcessSubMenu->addSeparator();
    QAction* r0EnableBreakAction = criticalProcessSubMenu->addAction(
        buildR0ActionIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.r0_break", QStringLiteral("R0启用 BreakOnTermination")));
    QAction* r0DisableBreakAction = criticalProcessSubMenu->addAction(
        buildR0ActionIcon(":/Icon/process_uncritical.svg"),
        processContextText("process.menu.r0_unbreak", QStringLiteral("R0关闭 BreakOnTermination")));
    setCriticalAction->setToolTip(QStringLiteral("将进程标记为关键进程；意外终止可能导致系统崩溃。"));
    clearCriticalAction->setToolTip(QStringLiteral("取消进程的关键标记。"));
    r0EnableBreakAction->setToolTip(QStringLiteral("将进程标记为关键进程；意外终止可能导致系统崩溃。"));
    r0DisableBreakAction->setToolTip(QStringLiteral("取消进程的关键标记。"));
    QMenu* r0DangerSubMenu = contextMenu.addMenu(
        buildR0ActionIcon(":/Icon/process_uncritical.svg"),
        processContextText("process.menu.danger", QStringLiteral("R0危险进程标志/DKOM")));
    QAction* r0DisableApcAction = r0DangerSubMenu->addAction(
        buildR0ActionIcon(":/Icon/process_suspend.svg"),
        processContextText("process.menu.disable_apc", QStringLiteral("禁止APC插入(现有线程)")));
    QAction* r0DkomCidRemoveAction = r0DangerSubMenu->addAction(
        buildR0ActionIcon(":/Icon/process_uncritical.svg"),
        processContextText("process.menu.remove_cid", QStringLiteral("DKOM从PspCidTable删除")));
    r0DisableApcAction->setToolTip(QStringLiteral("清除目标进程现有线程 ETHREAD ApcQueueable 位；新建线程不自动继承。"));
    r0DkomCidRemoveAction->setToolTip(QStringLiteral("从 PspCidTable 清零目标 EPROCESS 的 CID 表项；高风险且不可通过本菜单恢复。"));
    contextMenu.addSeparator();

    QAction* suspendAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_suspend.svg"),
        processContextText("process.menu.suspend", QStringLiteral("挂起进程")));
    QAction* resumeAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_resume.svg"),
        processContextText("process.menu.resume", QStringLiteral("恢复进程")));
    QAction* enableEfficiencyAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_resume.svg"),
        processContextText("process.menu.efficiency_on", QStringLiteral("开启效率模式（绿叶）")));
    QAction* disableEfficiencyAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_suspend.svg"),
        processContextText("process.menu.efficiency_off", QStringLiteral("关闭效率模式")));
    if (contextProcessRecord != nullptr && contextProcessRecord->efficiencyModeSupported)
    {
        enableEfficiencyAction->setEnabled(!contextProcessRecord->efficiencyModeEnabled);
        disableEfficiencyAction->setEnabled(contextProcessRecord->efficiencyModeEnabled);
    }
    QAction* openFolderAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_open_folder.svg"),
        processContextText("process.menu.open_folder", QStringLiteral("打开所在目录")));
    QMenu* gotoSubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_details.svg"),
        QStringLiteral("转到"));
    QAction* openHandleAction = gotoSubMenu->addAction(
        blueTintedIcon(":/Icon/process_list.svg"), QStringLiteral("句柄"));
    QAction* openMemoryAction = gotoSubMenu->addAction(
        blueTintedIcon(":/Icon/process_details.svg"), QStringLiteral("内存"));
    QAction* openNetworkAction = gotoSubMenu->addAction(
        blueTintedIcon(":/Icon/process_main.svg"), QStringLiteral("网络"));
    QAction* openWindowAction = gotoSubMenu->addAction(
        blueTintedIcon(":/Icon/process_tree.svg"), QStringLiteral("窗口"));
    QAction* openMessageHooksAction = gotoSubMenu->addAction(
        blueTintedIcon(":/Icon/process_list.svg"),
        processContextText("process.menu.message_hooks", QStringLiteral("消息 Hook")));
    openMessageHooksAction->setToolTip(processContextText(
        "process.menu.message_hooks.tooltip",
        QStringLiteral("默认显示作用于该进程线程的非全局 Hook；窗口内可切换为安装者或双侧相关范围。")));
    openMemoryAction->setEnabled(!hasBatchSelection);
    openMessageHooksAction->setEnabled(
        !hasBatchSelection &&
        contextProcessRecord != nullptr &&
        contextProcessRecord->pid != 0U);
    if (hasBatchSelection)
    {
        openMemoryAction->setToolTip(QStringLiteral("内存页一次只能附加一个进程。"));
        openMessageHooksAction->setToolTip(processContextText(
            "process.menu.message_hooks.single.tooltip",
            QStringLiteral("消息 Hook 窗口一次只能绑定一个进程。")));
    }
    QAction* injectionPageAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_priority.svg"),
        processContextText("process.menu.injection", QStringLiteral("DLL/Shellcode 注入")));
    injectionPageAction->setToolTip(QStringLiteral("打开进程详细信息并直达“操作”页的 DLL/Shellcode 注入区域。"));
    injectionPageAction->setEnabled(!hasBatchSelection);
    QAction* scanHotkeyAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_refresh.svg"),
        processContextText("process.menu.hotkeys", QStringLiteral("扫描进程热键")));
    scanHotkeyAction->setToolTip(QStringLiteral("打开进程详细信息并直达“进程热键”页，扫描窗口热键、菜单快捷键、Accelerator、快捷方式和R0热键表。"));
    scanHotkeyAction->setEnabled(!hasBatchSelection);

    // 令牌特权二级菜单：
    // - 查询和调整均在线程池执行，避免 OpenProcessToken/AdjustTokenPrivileges 阻塞 GUI；
    // - 每一项用 QWidgetAction 承载无边框 QPushButton，前缀显示勾选状态，点击后菜单保持展开；
    // - 多选时只有全部目标都包含该特权才允许切换，一次点击立即提交到全部目标。
    QMenu* privilegeSubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.privileges", QStringLiteral("令牌特权")));
    privilegeSubMenu->setStyleSheet(buildThreadContextMenuStyle());
    privilegeSubMenu->setToolTipsVisible(true);
    privilegeSubMenu->setToolTip(processContextText(
        "process.menu.privileges.tooltip",
        QStringLiteral("点击切换全部选中进程的令牌特权；菜单会保持展开，便于连续调整。")));
    QAction* privilegeLoadingAction = privilegeSubMenu->addAction(
        processContextText(
            "process.menu.privileges.querying",
            QStringLiteral("正在查询令牌特权...")));
    privilegeLoadingAction->setEnabled(false);

    struct ContextPrivilegeTargetState
    {
        std::uint32_t processId = 0;
        std::uint64_t creationTime100ns = 0;
        std::string processName;
        bool querySucceeded = false;
        bool usedR0 = false;
        std::vector<ks::process::TokenPrivilegeInfo> privileges;
        std::string detailText;
    };
    struct ContextPrivilegeAdjustResult
    {
        std::size_t targetIndex = 0U;
        bool succeeded = false;
        bool r0Attempted = false;
        std::string detailText;
        std::string r3DetailText;
    };

    const QPointer<ProcessDock> privilegeDockGuard(this);
    const QPointer<QMenu> privilegeMenuGuard(privilegeSubMenu);
    const std::vector<ProcessActionTarget> privilegeTargets = contextActionTargets;
    QRunnable* privilegeQueryTask = QRunnable::create([
        privilegeDockGuard,
        privilegeMenuGuard,
        privilegeTargets]() mutable
    {
        const auto targetStates = std::make_shared<std::vector<ContextPrivilegeTargetState>>();
        targetStates->reserve(privilegeTargets.size());
        for (const ProcessActionTarget& actionTarget : privilegeTargets)
        {
            ContextPrivilegeTargetState targetState;
            targetState.processId = actionTarget.record.pid;
            targetState.creationTime100ns = actionTarget.record.creationTime100ns;
            targetState.processName = actionTarget.record.processName;
            std::string r3DetailText;
            HANDLE rawIdentityHandle = nullptr;
            if (!acquireProcessActionIdentityHold(
                    targetState.processId,
                    targetState.creationTime100ns,
                    &rawIdentityHandle,
                    &targetState.detailText))
            {
                targetStates->push_back(std::move(targetState));
                continue;
            }
            const ScopedProcessActionHandle identityHandle(rawIdentityHandle);

            targetState.querySucceeded =
                ks::process::QueryTokenPrivilegesByProcessHandle(
                    rawIdentityHandle,
                    &targetState.privileges,
                    &r3DetailText);
            if (!targetState.querySucceeded)
            {
                ksword::ark::DriverClient r0Client;
                const ksword::ark::ProcessTokenPrivilegeResult r0Result =
                    r0Client.queryProcessTokenPrivileges(
                        targetState.processId,
                        targetState.creationTime100ns);
                if (r0Result.io.ok
                    && (r0Result.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
                        || r0Result.status ==
                            KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL))
                {
                    std::vector<ks::process::TokenPrivilegeLuidEntry> r0Entries;
                    r0Entries.reserve(r0Result.entries.size());
                    for (const ksword::ark::ProcessTokenPrivilegeEntry& r0Entry : r0Result.entries)
                    {
                        ks::process::TokenPrivilegeLuidEntry entry{};
                        entry.luidLowPart = r0Entry.luidLowPart;
                        entry.luidHighPart = r0Entry.luidHighPart;
                        entry.attributes = r0Entry.attributes;
                        r0Entries.push_back(entry);
                    }
                    targetState.querySucceeded = ks::process::BuildKnownTokenPrivilegeSnapshot(
                        r0Entries,
                        &targetState.privileges,
                        &targetState.detailText);
                    targetState.usedR0 = targetState.querySucceeded;
                }

                if (!targetState.querySucceeded)
                {
                    targetState.detailText = r3DetailText;
                    if (!r0Result.io.message.empty())
                    {
                        targetState.detailText += " | ";
                        targetState.detailText += r0Result.io.message;
                    }
                }
            }
            targetStates->push_back(std::move(targetState));
        }

        if (privilegeDockGuard == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(privilegeDockGuard, [
            privilegeDockGuard,
            privilegeMenuGuard,
            targetStates]()
        {
            if (privilegeDockGuard == nullptr || privilegeMenuGuard == nullptr)
            {
                return;
            }

            privilegeMenuGuard->clear();
            if (targetStates->empty())
            {
                QAction* unavailableAction = privilegeMenuGuard->addAction(
                    processContextText(
                        "process.menu.privileges.unavailable",
                        QStringLiteral("无法读取全部选中进程的令牌特权。")));
                unavailableAction->setEnabled(false);
                return;
            }

            const QString privilegeButtonStyle = QStringLiteral(
                "QPushButton {"
                "  min-width:300px; min-height:30px; max-height:30px;"
                "  padding:0 12px; text-align:left;"
                "  color:%1; background:transparent;"
                "  border:none; border-bottom:1px solid %4;"
                "}"
                "QPushButton:hover { background:%2; }"
                "QPushButton:pressed { background:%2; }"
                "QPushButton:disabled { color:%3; }")
                .arg(KswordTheme::TextPrimaryHex())
                .arg(KswordTheme::SurfaceAltHex())
                .arg(KswordTheme::TextSecondaryHex())
                .arg(KswordTheme::BorderHex());

            const std::size_t privilegeCount = ks::process::KnownTokenPrivilegeNames().size();
            std::vector<std::size_t> controllablePrivilegeIndices;
            controllablePrivilegeIndices.reserve(privilegeCount);
            for (std::size_t privilegeIndex = 0U;
                 privilegeIndex < privilegeCount;
                 ++privilegeIndex)
            {
                bool controllableForAll = true;
                for (const ContextPrivilegeTargetState& targetState : *targetStates)
                {
                    if (!targetState.querySucceeded
                        || privilegeIndex >= targetState.privileges.size())
                    {
                        controllableForAll = false;
                        break;
                    }
                    const ks::process::TokenPrivilegeState privilegeState =
                        targetState.privileges[privilegeIndex].state;
                    if (privilegeState != ks::process::TokenPrivilegeState::Enabled
                        && privilegeState != ks::process::TokenPrivilegeState::Disabled)
                    {
                        controllableForAll = false;
                        break;
                    }
                }
                if (controllableForAll)
                {
                    controllablePrivilegeIndices.push_back(privilegeIndex);
                }
            }

            if (controllablePrivilegeIndices.empty())
            {
                QAction* unavailableAction = privilegeMenuGuard->addAction(
                    processContextText(
                        "process.menu.privileges.none",
                        QStringLiteral("没有可调整的令牌特权。")));
                unavailableAction->setEnabled(false);
                return;
            }

            for (const std::size_t privilegeIndex : controllablePrivilegeIndices)
            {
                QWidgetAction* rowAction = new QWidgetAction(privilegeMenuGuard);
                QPushButton* privilegeButton = new QPushButton(privilegeMenuGuard);
                privilegeButton->setCheckable(true);
                privilegeButton->setFlat(true);
                privilegeButton->setFocusPolicy(Qt::NoFocus);
                privilegeButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
                privilegeButton->setStyleSheet(privilegeButtonStyle);
                rowAction->setDefaultWidget(privilegeButton);
                privilegeMenuGuard->addAction(rowAction);

                const QPointer<QPushButton> privilegeButtonGuard(privilegeButton);
                const auto updatePrivilegeButton = [
                    targetStates,
                    privilegeButtonGuard,
                    privilegeIndex]()
                {
                    if (privilegeButtonGuard == nullptr)
                    {
                        return;
                    }

                    std::size_t enabledCount = 0U;
                    for (const ContextPrivilegeTargetState& targetState : *targetStates)
                    {
                        const ks::process::TokenPrivilegeState privilegeState =
                            targetState.privileges[privilegeIndex].state;
                        if (privilegeState == ks::process::TokenPrivilegeState::Enabled)
                        {
                            ++enabledCount;
                        }
                    }

                    const bool enabledForAll = enabledCount == targetStates->size();
                    const bool mixedState = enabledCount > 0U
                        && enabledCount < targetStates->size();

                    const QString checkMark = enabledForAll
                        ? QStringLiteral("✓")
                        : (mixedState ? QStringLiteral("—") : QStringLiteral(" "));
                    const QSignalBlocker signalBlocker(privilegeButtonGuard);
                    privilegeButtonGuard->setText(
                        QStringLiteral("%1  %2")
                            .arg(
                                checkMark,
                                QString::fromLatin1(
                                    ks::process::KnownTokenPrivilegeNames().at(privilegeIndex).c_str())));
                    privilegeButtonGuard->setChecked(enabledForAll);
                    privilegeButtonGuard->setEnabled(true);
                    privilegeButtonGuard->setToolTip(
                        processContextText(
                            "process.menu.privileges.toggle",
                            QStringLiteral("点击切换全部选中进程的此项令牌特权。")));
                    privilegeButtonGuard->style()->unpolish(privilegeButtonGuard);
                    privilegeButtonGuard->style()->polish(privilegeButtonGuard);
                    privilegeButtonGuard->update();
                };
                updatePrivilegeButton();

                connect(privilegeButton, &QPushButton::clicked, privilegeMenuGuard, [
                    privilegeDockGuard,
                    privilegeMenuGuard,
                    targetStates,
                    privilegeButtonGuard,
                    privilegeIndex,
                    updatePrivilegeButton](const bool enablePrivilege)
                {
                    if (privilegeDockGuard == nullptr
                        || privilegeMenuGuard == nullptr
                        || privilegeButtonGuard == nullptr)
                    {
                        return;
                    }

                    privilegeButtonGuard->setEnabled(false);

                    const std::string privilegeName =
                        ks::process::KnownTokenPrivilegeNames().at(privilegeIndex);
                    QRunnable* adjustTask = QRunnable::create([
                        privilegeDockGuard,
                        privilegeMenuGuard,
                        targetStates,
                        privilegeButtonGuard,
                        privilegeIndex,
                        privilegeName,
                        enablePrivilege,
                        updatePrivilegeButton]()
                    {
                        std::vector<ContextPrivilegeAdjustResult> adjustResults;
                        adjustResults.reserve(targetStates->size());
                        for (std::size_t targetIndex = 0U;
                             targetIndex < targetStates->size();
                             ++targetIndex)
                        {
                            ContextPrivilegeAdjustResult adjustResult;
                            adjustResult.targetIndex = targetIndex;
                            ks::process::TokenPrivilegeEdit privilegeEdit;
                            privilegeEdit.privilegeName = privilegeName;
                            privilegeEdit.action = enablePrivilege
                                ? ks::process::TokenPrivilegeAction::Enable
                                : ks::process::TokenPrivilegeAction::Disable;
                            const ContextPrivilegeTargetState& targetState =
                                (*targetStates)[targetIndex];
                            HANDLE rawIdentityHandle = nullptr;
                            if (acquireProcessActionIdentityHold(
                                    targetState.processId,
                                    targetState.creationTime100ns,
                                    &rawIdentityHandle,
                                    &adjustResult.detailText))
                            {
                                const ScopedProcessActionHandle identityHandle(
                                    rawIdentityHandle);
                                adjustResult.succeeded =
                                    ks::process::ApplyTokenPrivilegeEditsByProcessHandle(
                                        rawIdentityHandle,
                                        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                        false,
                                        std::vector<ks::process::TokenPrivilegeEdit>{
                                            privilegeEdit },
                                        &adjustResult.detailText);
                            }
                            if (!adjustResult.succeeded)
                            {
                                adjustResult.r3DetailText = adjustResult.detailText;
                                const ks::process::TokenPrivilegeInfo& privilegeInfo =
                                    (*targetStates)[targetIndex].privileges[privilegeIndex];
                                if (privilegeInfo.luidKnown)
                                {
                                    adjustResult.r0Attempted = true;
                                    ksword::ark::ProcessTokenPrivilegeEntry r0Edit{};
                                    r0Edit.luidLowPart = privilegeInfo.luidLowPart;
                                    r0Edit.luidHighPart = privilegeInfo.luidHighPart;
                                    r0Edit.action = enablePrivilege
                                        ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE
                                        : KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE;
                                    ksword::ark::DriverClient r0Client;
                                    const ksword::ark::ProcessTokenPrivilegeResult r0Result =
                                        r0Client.adjustProcessTokenPrivileges(
                                            targetState.processId,
                                            targetState.creationTime100ns,
                                            std::vector<ksword::ark::ProcessTokenPrivilegeEntry>{
                                                r0Edit },
                                            false);
                                    adjustResult.succeeded = r0Result.io.ok
                                        && r0Result.status ==
                                            KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
                                        && r0Result.appliedCount == 1U;
                                    adjustResult.detailText = r0Result.io.message;
                                }
                            }
                            adjustResults.push_back(std::move(adjustResult));
                        }

                        if (privilegeDockGuard == nullptr)
                        {
                            return;
                        }
                        QMetaObject::invokeMethod(privilegeDockGuard, [
                            privilegeDockGuard,
                            privilegeMenuGuard,
                            targetStates,
                            privilegeButtonGuard,
                            privilegeIndex,
                            privilegeName,
                            enablePrivilege,
                            updatePrivilegeButton,
                            adjustResults = std::move(adjustResults)]() mutable
                        {
                            if (privilegeDockGuard == nullptr
                                || privilegeMenuGuard == nullptr
                                || privilegeButtonGuard == nullptr)
                            {
                                return;
                            }

                            bool allSucceeded = true;
                            std::size_t r0FallbackCount = 0U;
                            QStringList failureDetails;
                            for (const ContextPrivilegeAdjustResult& adjustResult : adjustResults)
                            {
                                ContextPrivilegeTargetState& targetState =
                                    (*targetStates)[adjustResult.targetIndex];
                                if (!adjustResult.r3DetailText.empty())
                                {
                                    if (adjustResult.r0Attempted)
                                    {
                                        ++r0FallbackCount;
                                    }
                                    kLogEvent r3FailureEvent;
                                    warn << r3FailureEvent
                                        << "[ProcessDock]::R3 token privilege adjustment failed, pid="
                                        << targetState.processId
                                        << "::privilege=" << privilegeName
                                        << ", enable=" << (enablePrivilege ? "true" : "false")
                                        << ", detail=" << adjustResult.r3DetailText
                                        << "::r0Attempted=" << (adjustResult.r0Attempted ? "true" : "false")
                                        << "::finalSucceeded=" << (adjustResult.succeeded ? "true" : "false")
                                        << eol;
                                }
                                if (adjustResult.succeeded)
                                {
                                    continue;
                                }

                                allSucceeded = false;
                                failureDetails.push_back(QStringLiteral("PID %1: %2")
                                    .arg(targetState.processId)
                                    .arg(QString::fromStdString(adjustResult.detailText)));
                            }

                            if (allSucceeded)
                            {
                                for (ContextPrivilegeTargetState& targetState : *targetStates)
                                {
                                    targetState.privileges[privilegeIndex].state = enablePrivilege
                                        ? ks::process::TokenPrivilegeState::Enabled
                                        : ks::process::TokenPrivilegeState::Disabled;
                                }
                            }
                            updatePrivilegeButton();
                            if (!allSucceeded)
                            {
                                privilegeButtonGuard->setToolTip(
                                    failureDetails.join(QStringLiteral("\n")));
                                privilegeMenuGuard->setToolTip(
                                    processContextText(
                                        "process.menu.privileges.adjust_failed",
                                        QStringLiteral("部分进程的令牌特权调整失败。"))
                                    + QStringLiteral("\n")
                                    + failureDetails.join(QStringLiteral("\n")));
                            }

                            kLogEvent actionEvent;
                            (allSucceeded ? info : warn) << actionEvent
                                << "[ProcessDock]::token privilege menu adjustment::privilege="
                                << privilegeName
                                << ", enable=" << (enablePrivilege ? "true" : "false")
                                << ", targetCount=" << targetStates->size()
                                << ", r0FallbackCount=" << r0FallbackCount
                                << "::allSucceeded=" << (allSucceeded ? "true" : "false")
                                << eol;
                        }, Qt::QueuedConnection);
                    });
                    adjustTask->setAutoDelete(true);
                    QThreadPool::globalInstance()->start(adjustTask);
                });
            }
        }, Qt::QueuedConnection);
    });
    privilegeQueryTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(privilegeQueryTask);

    // 跨组 CPU 亲和性矩阵：
    // - 用 QWidgetAction 承载每一行核心按钮，按钮交互不会触发 QAction::triggered，
    //   因此子菜单在连续勾选时保持展开，仅由用户点击菜单外区域关闭；
    // - 多选进程时仅在所有目标均可读取亲和性时开放，避免对部分目标产生不透明的写入；
    // - 每个目标保留自己的其余稳定坐标，只对用户点击的 Gx:Ly 做增减。
    QMenu* affinitySubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_priority.svg"),
        processContextText("process.menu.affinity", QStringLiteral("CPU 亲和性")));
    affinitySubMenu->setStyleSheet(buildThreadContextMenuStyle());
    affinitySubMenu->setToolTipsVisible(true);

    struct ContextAffinityTargetState
    {
        DWORD processId = 0;
        ks::process::ProcessAffinitySnapshot snapshot;
    };
    const auto affinityTargetStates = std::make_shared<std::vector<ContextAffinityTargetState>>();
    affinityTargetStates->reserve(contextActionTargets.size());
    bool affinityReadable = !contextActionTargets.empty();
    std::vector<ks::process::LogicalProcessorCoordinate>
        commonProcessorCoordinates;
    bool hasHardConstrainedProcessor = false;
    std::string affinityReadDetailText;
    for (const ProcessActionTarget& actionTarget : contextActionTargets)
    {
        ks::process::ProcessAffinitySnapshot affinitySnapshot;
        std::string detailText;
        if (!ks::process::QueryProcessAffinityState(
                static_cast<DWORD>(actionTarget.record.pid),
                &affinitySnapshot,
                &detailText))
        {
            affinityReadable = false;
            affinityReadDetailText = detailText;
            break;
        }
        ContextAffinityTargetState targetState;
        targetState.processId = static_cast<DWORD>(actionTarget.record.pid);
        targetState.snapshot = std::move(affinitySnapshot);
        hasHardConstrainedProcessor =
            hasHardConstrainedProcessor ||
            std::any_of(
                targetState.snapshot.processors.begin(),
                targetState.snapshot.processors.end(),
                [](const ks::process::LogicalProcessorState& processor)
                {
                    return processor.constrainedByHardAffinity;
                });
        if (affinityTargetStates->empty())
        {
            for (const ks::process::LogicalProcessorState& processor :
                 targetState.snapshot.processors)
            {
                commonProcessorCoordinates.push_back(
                    processor.coordinate);
            }
        }
        else
        {
            commonProcessorCoordinates.erase(
                std::remove_if(
                    commonProcessorCoordinates.begin(),
                    commonProcessorCoordinates.end(),
                    [&targetState](
                        const ks::process::LogicalProcessorCoordinate&
                            coordinate)
                    {
                        return std::none_of(
                            targetState.snapshot.processors.begin(),
                            targetState.snapshot.processors.end(),
                            [&coordinate](
                                const ks::process::LogicalProcessorState&
                                    processor)
                            {
                                return processor.coordinate == coordinate;
                            });
                    }),
                commonProcessorCoordinates.end());
        }
        affinityTargetStates->push_back(targetState);
    }
    ks::process::normalizeLogicalProcessorCoordinates(
        &commonProcessorCoordinates);
    const bool includeProcessorGroup =
        ks::process::logicalProcessorGroupCount(
            commonProcessorCoordinates) > 1U;
    affinitySubMenu->setToolTip(processContextText(
        includeProcessorGroup
            ? "process.menu.affinity.tooltip.multigroup"
            : "process.menu.affinity.tooltip",
        includeProcessorGroup
            ? QStringLiteral(
                "检测到多个 Windows Processor Group；按 Gx:Ly 切换 CPU Set，蓝色按钮表示已启用。")
            : QStringLiteral(
                "按 Lx 切换 CPU Set，蓝色按钮表示已启用。")));
    if (hasHardConstrainedProcessor)
    {
        affinitySubMenu->setToolTip(
            affinitySubMenu->toolTip() +
            QStringLiteral("\n") +
            processContextText(
                "process.menu.affinity.constraint_notice",
                QStringLiteral(
                    "部分处理器受现有 processor group/thread/Job/legacy affinity 约束，当前不可调度；对应按钮已禁用。")));
    }
    if (commonProcessorCoordinates.empty())
    {
        affinityReadable = false;
        if (affinityReadDetailText.empty())
        {
            affinityReadDetailText =
                "selected processes do not share an available logical processor coordinate";
        }
    }

    const auto affinityChanged = std::make_shared<bool>(false);
    if (!affinityReadable)
    {
        affinitySubMenu->setEnabled(false);
        affinitySubMenu->setToolTip(
            processContextText(
                "process.menu.affinity.unavailable",
                QStringLiteral("无法读取全部选中进程的 CPU 亲和性。")));
        kLogEvent affinityReadEvent;
        warn << affinityReadEvent
            << "[ProcessDock] context CPU affinity query failed, targetCount="
            << contextActionTargets.size()
            << ", detail="
            << (affinityReadDetailText.empty()
                ? "none"
                : affinityReadDetailText)
            << eol;
    }
    else
    {
        constexpr int affinityMatrixColumnCount = 6;
        const QString affinityCoreButtonStyle = QStringLiteral(
            "QToolButton {"
            "  min-width:42px; min-height:28px; padding:2px 6px;"
            "  color:%1; background:transparent; border:1px solid %2; border-radius:4px;"
            "}"
            "QToolButton:hover { border-color:%3; background:%4; }"
            "QToolButton:checked { color:%5; background:%3; border-color:%3; }"
            "QToolButton[affinityMixed=\"true\"] { border-color:%3; border-style:dashed; }")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::OnAccentDynamicHex());

        const auto affinityCoordinates = std::make_shared<
            std::vector<ks::process::LogicalProcessorCoordinate>>(
                commonProcessorCoordinates);
        const auto affinityCoreButtons =
            std::make_shared<std::vector<QToolButton*>>(
                affinityCoordinates->size(),
                nullptr);
        const auto updateAffinityCoreButtons =
            [affinityTargetStates,
                affinityCoordinates,
                affinityCoreButtons]()
        {
            for (std::size_t processorIndex = 0U;
                 processorIndex < affinityCoreButtons->size();
                 ++processorIndex)
            {
                QToolButton* const coreButton =
                    (*affinityCoreButtons)[processorIndex];
                if (coreButton == nullptr)
                {
                    continue;
                }
                const ks::process::LogicalProcessorCoordinate coordinate =
                    (*affinityCoordinates)[processorIndex];
                bool availableForAll = !affinityTargetStates->empty();
                bool enabledForAll = !affinityTargetStates->empty();
                bool enabledForAny = false;
                for (const ContextAffinityTargetState& targetState : *affinityTargetStates)
                {
                    const auto processorIt = std::find_if(
                        targetState.snapshot.processors.begin(),
                        targetState.snapshot.processors.end(),
                        [&coordinate](
                            const ks::process::LogicalProcessorState&
                                processor)
                        {
                            return processor.coordinate == coordinate;
                        });
                    const bool availableForTarget =
                        processorIt != targetState.snapshot.processors.end() &&
                        processorIt->available;
                    const bool enabledForTarget =
                        availableForTarget && processorIt->selected;
                    availableForAll =
                        availableForAll && availableForTarget;
                    enabledForAll = enabledForAll && enabledForTarget;
                    enabledForAny = enabledForAny || enabledForTarget;
                }

                const QSignalBlocker signalBlocker(coreButton);
                coreButton->setEnabled(availableForAll);
                coreButton->setChecked(availableForAll && enabledForAll);
                coreButton->setProperty(
                    "affinityMixed",
                    availableForAll && enabledForAny && !enabledForAll);
                coreButton->style()->unpolish(coreButton);
                coreButton->style()->polish(coreButton);
                coreButton->update();
            }
        };

        for (std::size_t rowStart = 0U;
             rowStart < affinityCoordinates->size();
             rowStart += affinityMatrixColumnCount)
        {
            QWidgetAction* rowAction = new QWidgetAction(affinitySubMenu);
            QWidget* rowWidget = new QWidget(affinitySubMenu);
            QHBoxLayout* rowLayout = new QHBoxLayout(rowWidget);
            rowLayout->setContentsMargins(8, 3, 8, 3);
            rowLayout->setSpacing(6);
            const std::size_t rowEnd = std::min(
                rowStart + static_cast<std::size_t>(affinityMatrixColumnCount),
                affinityCoordinates->size());
            for (std::size_t processorIndex = rowStart;
                 processorIndex < rowEnd;
                 ++processorIndex)
            {
                const ks::process::LogicalProcessorCoordinate coordinate =
                    (*affinityCoordinates)[processorIndex];
                QToolButton* coreButton = new QToolButton(rowWidget);
                const auto topologyIt = std::find_if(
                    affinityTargetStates->front().snapshot.processors.begin(),
                    affinityTargetStates->front().snapshot.processors.end(),
                    [&coordinate](
                        const ks::process::LogicalProcessorState& processor)
                    {
                        return processor.coordinate == coordinate;
                    });
                const QString identityText = QString::fromStdString(
                    ks::process::processorDisplayIdentityText(
                        coordinate,
                        includeProcessorGroup));
                const QString topologyText =
                    topologyIt !=
                        affinityTargetStates->front().snapshot.processors.end()
                        ? QString::fromStdString(
                            topologyIt->topologyLabel)
                        : QString();
                coreButton->setText(
                    topologyText.isEmpty()
                        ? identityText
                        : identityText + QStringLiteral("\n") +
                            topologyText);
                coreButton->setCheckable(true);
                coreButton->setAutoRaise(false);
                coreButton->setFocusPolicy(Qt::NoFocus);
                QString processorToolTip = processContextText(
                        "process.menu.affinity.core_tooltip",
                        QStringLiteral("%1（%2）；点击切换全部选中进程的 CPU Set。"))
                        .arg(identityText, topologyText);
                bool constrainedForAnyTarget = false;
                bool unavailableForAnyTarget = false;
                for (const ContextAffinityTargetState& targetState :
                     *affinityTargetStates)
                {
                    const auto targetProcessorIt = std::find_if(
                        targetState.snapshot.processors.begin(),
                        targetState.snapshot.processors.end(),
                        [&coordinate](
                            const ks::process::LogicalProcessorState&
                                processor)
                        {
                            return processor.coordinate == coordinate;
                        });
                    if (targetProcessorIt ==
                        targetState.snapshot.processors.end())
                    {
                        unavailableForAnyTarget = true;
                        continue;
                    }
                    constrainedForAnyTarget =
                        constrainedForAnyTarget ||
                        targetProcessorIt->constrainedByHardAffinity;
                    unavailableForAnyTarget =
                        unavailableForAnyTarget ||
                        !targetProcessorIt->available;
                }
                if (constrainedForAnyTarget)
                {
                    processorToolTip += QStringLiteral("\n") +
                        processContextText(
                            "process.menu.affinity.constraint_tooltip",
                            QStringLiteral(
                                "受现有 processor group/thread/Job/legacy affinity 约束，CPU Sets 无法在当前状态下调度到此处理器。"));
                }
                else if (unavailableForAnyTarget)
                {
                    processorToolTip += QStringLiteral("\n") +
                        processContextText(
                            "process.menu.affinity.allocated_tooltip",
                            QStringLiteral(
                                "此 CPU Set 对至少一个选中进程不可用。"));
                }
                coreButton->setToolTip(processorToolTip);
                coreButton->setStyleSheet(affinityCoreButtonStyle);
                rowLayout->addWidget(coreButton);
                (*affinityCoreButtons)[processorIndex] = coreButton;
                connect(coreButton, &QToolButton::clicked, affinitySubMenu,
                    [affinitySubMenu,
                        affinityTargetStates,
                        affinityChanged,
                        updateAffinityCoreButtons,
                        coordinate,
                        coreButton](const bool enabled)
                    {
                        std::vector<ks::process::ProcessAffinityRule>
                            nextRules;
                        nextRules.reserve(affinityTargetStates->size());
                        for (const ContextAffinityTargetState& targetState :
                             *affinityTargetStates)
                        {
                            ks::process::ProcessAffinityRule nextRule;
                            if (targetState.snapshot.unrestricted)
                            {
                                for (const ks::process::LogicalProcessorState&
                                     processor :
                                     targetState.snapshot.processors)
                                {
                                    if (processor.available)
                                    {
                                        nextRule.processors.push_back(
                                            processor.coordinate);
                                    }
                                }
                            }
                            else
                            {
                                nextRule =
                                    ks::process::affinityRuleFromSnapshot(
                                        targetState.snapshot);
                            }

                            if (enabled)
                            {
                                nextRule.processors.push_back(coordinate);
                            }
                            else
                            {
                                nextRule.processors.erase(
                                    std::remove(
                                        nextRule.processors.begin(),
                                        nextRule.processors.end(),
                                        coordinate),
                                    nextRule.processors.end());
                            }
                            nextRule.selectAllAvailable = false;
                            ks::process::
                                normalizeLogicalProcessorCoordinates(
                                    &nextRule.processors);
                            if (nextRule.processors.empty())
                            {
                                const QSignalBlocker signalBlocker(
                                    coreButton);
                                coreButton->setChecked(true);
                                affinitySubMenu->setToolTip(
                                    processContextText(
                                        "process.menu.affinity.last_core",
                                        QStringLiteral(
                                            "至少保留一个可用逻辑处理器。")));
                                return;
                            }
                            nextRules.push_back(std::move(nextRule));
                        }

                        const QMessageBox::StandardButton confirmation =
                            QMessageBox::warning(
                                affinitySubMenu,
                                processContextText(
                                    "process.affinity.risk.title",
                                    QStringLiteral("CPU 亲和性风险")),
                                processContextText(
                                    "process.affinity.risk.apply",
                                    QStringLiteral(
                                        "跨组/CPU Set 亲和性可能显著降低性能，并与线程或 Job 约束冲突；极端配置可能使进程无法调度、冻结并造成数据丢失。是否继续？")),
                                QMessageBox::Yes | QMessageBox::No,
                                QMessageBox::No);
                        if (confirmation != QMessageBox::Yes)
                        {
                            updateAffinityCoreButtons();
                            return;
                        }

                        bool allUpdated = true;
                        QStringList failedProcessDetails;
                        for (std::size_t targetIndex = 0U;
                             targetIndex < affinityTargetStates->size();
                             ++targetIndex)
                        {
                            ContextAffinityTargetState& targetState =
                                (*affinityTargetStates)[targetIndex];
                            std::string detailText;
                            if (ks::process::SetProcessAffinityRuleByPid(
                                    targetState.processId,
                                    nextRules[targetIndex],
                                    &detailText))
                            {
                                ks::process::ProcessAffinitySnapshot
                                    refreshedSnapshot;
                                if (ks::process::QueryProcessAffinityState(
                                        targetState.processId,
                                        &refreshedSnapshot,
                                        &detailText))
                                {
                                    targetState.snapshot =
                                        std::move(refreshedSnapshot);
                                    *affinityChanged = true;
                                    continue;
                                }
                            }
                            allUpdated = false;
                            failedProcessDetails << QStringLiteral("PID %1: %2")
                                .arg(targetState.processId)
                                .arg(QString::fromStdString(detailText));
                        }
                        if (!allUpdated)
                        {
                            const QString failureText = processContextText(
                                "process.menu.affinity.update_failed",
                                QStringLiteral(
                                    "CPU 亲和性更新未完全生效；详细信息已写入日志。"));
                            affinitySubMenu->setToolTip(failureText);
                            QMessageBox::warning(
                                affinitySubMenu,
                                processContextText(
                                    "process.menu.affinity",
                                    QStringLiteral("CPU 亲和性")),
                                failureText);
                        }
                        updateAffinityCoreButtons();

                        kLogEvent actionEvent;
                        (allUpdated ? info : warn) << actionEvent
                            << "[ProcessDock] 右键 CPU 亲和性更新, processor="
                            << ks::process::processorIdentityText(
                                coordinate)
                            << ", enabled="
                            << (enabled ? "true" : "false")
                            << ", targetCount="
                            << affinityTargetStates->size()
                            << ", allUpdated="
                            << (allUpdated ? "true" : "false")
                            << ", failed="
                            << (failedProcessDetails.isEmpty()
                                ? "none"
                                : failedProcessDetails
                                    .join(QStringLiteral(" | "))
                                    .toStdString())
                            << eol;
                    });
            }
            rowLayout->addStretch(1);
            rowAction->setDefaultWidget(rowWidget);
            affinitySubMenu->addAction(rowAction);
        }
        updateAffinityCoreButtons();
    }

    // 优先级二级菜单。
    QMenu* prioritySubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_priority.svg"),
        processContextText("process.menu.priority", QStringLiteral("设置进程优先级")));
    QAction* idlePriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "Idle");
    QAction* belowNormalPriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "Below Normal");
    QAction* normalPriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "Normal");
    QAction* aboveNormalPriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "Above Normal");
    QAction* highPriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "High");
    QAction* realtimePriority = prioritySubMenu->addAction(blueTintedIcon(":/Icon/process_priority.svg"), "Realtime");
    idlePriority->setData(0);
    belowNormalPriority->setData(1);
    normalPriority->setData(2);
    aboveNormalPriority->setData(3);
    highPriority->setData(4);
    realtimePriority->setData(5);

    // 完整性二级菜单：
    // - 读取右键目标（批量时取第一个目标）的 TokenIntegrityLevel；
    // - 用前缀圆点标出当前 RID，避免 Qt 平台 checkmark 在不同主题下不可见；
    // - 执行动作仍支持批量，所有选中进程都会尝试写入同一 Mandatory Label。
    QMenu* integritySubMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_critical.svg"),
        processContextText("process.menu.integrity", QStringLiteral("完整性")));
    integritySubMenu->setToolTipsVisible(true);
    if (!contextIntegrityKnown && contextProcessRecord != nullptr)
    {
        integritySubMenu->setToolTip(QStringLiteral("当前完整性读取失败：%1")
            .arg(QString::fromStdString(contextIntegrityDetailText)));
    }
    for (const ProcessIntegrityLevelPreset& preset : ProcessIntegrityLevelPresets)
    {
        const bool isCurrentLevel = contextIntegrityKnown && contextIntegrityRid == preset.rid;
        QAction* integrityAction = integritySubMenu->addAction(
            blueTintedIcon(":/Icon/process_critical.svg"),
            QStringLiteral("%1 %2 - %3")
                .arg(isCurrentLevel ? QStringLiteral("●") : QStringLiteral(" "))
                .arg(QString::fromLatin1(preset.nameText))
                .arg(processContextText(
                    QStringLiteral("process.integrity.") + QString::fromLatin1(preset.nameText),
                    QString::fromUtf8(preset.detailText))));
        integrityAction->setData(static_cast<unsigned int>(preset.rid));
    }

    QAction* detailsAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_details.svg"),
        processContextText("process.menu.details", QStringLiteral("进程详细信息")));
    detailsAction->setEnabled(!hasBatchSelection);
    contextMenu.addSeparator();
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [contextActionTargets]() -> ks::online_scan::SandboxUploadTarget
        {
            // 输入：右键菜单冻结的进程动作目标。
            // 处理：优先使用缓存 imagePath，若为空则交给 PID 解析兜底。
            // 返回：待上传文件路径和结果窗口来源说明。
            ks::online_scan::SandboxUploadTarget uploadTarget;
            if (contextActionTargets.empty())
            {
                return uploadTarget;
            }

            const ks::process::ProcessRecord& record = contextActionTargets.front().record;
            uploadTarget.filePath = QString::fromStdString(record.imagePath);
            uploadTarget.sourceText = QStringLiteral("进程列表 PID=%1 %2")
                .arg(record.pid)
                .arg(QString::fromStdString(record.processName));
            if (uploadTarget.filePath.trimmed().isEmpty() && record.pid != 0)
            {
                uploadTarget.filePath = QString::fromStdString(ks::process::QueryProcessPathByPid(record.pid));
            }
            return uploadTarget;
        });
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(!contextActionTargets.empty());
    }

    m_contextMenuVisible = true;
    QAction* selectedAction = contextMenu.exec(m_processTable->viewport()->mapToGlobal(localPosition));
    m_contextMenuVisible = false;
    if (*affinityChanged)
    {
        // 亲和性矩阵按钮在子菜单存续期间直接写入，菜单关闭后再刷新列表，
        // 避免刷新过程重建右键绑定或导致展开中的矩阵提前收起。
        requestAsyncRefresh(true);
    }
    {
        if (selectedAction == nullptr)
        {
            clearContextActionBinding();
            return;
        }

        {
            kLogEvent logEvent;
            info << logEvent
                << "[ProcessDock] 右键菜单执行动作: " << selectedAction->text().toStdString()
                << eol;
        }

        if (selectedAction == copyCellAction) { copyCurrentCell(); }
        else if (selectedAction == copyRowAction) { copyCurrentRow(); }
        else if (selectedAction == terminateProcessAction) { executeTerminateProcessAction(); }
        else if (selectedAction == terminateAndDeleteImageAction) { executeTerminateAndDeleteImageAction(); }
        else if (selectedAction == terminateProcessTreeAction) { executeTerminateProcessTreeAction(); }
        else if (selectedAction == r0TerminateAction) { executeR0TerminateProcessAction(); }
        else if (selectedAction == r0TerminateTreeAction) { executeR0TerminateProcessTreeAction(); }
        else if (selectedAction == r0SuspendAction) { executeR0SuspendProcessAction(); }
        else if (selectedAction == r0HideUnlinkOnlyAction) {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST);
        }
        else if (selectedAction == r0HidePatchPidOnlyAction) {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID);
        }
        else if (selectedAction == r0HideLegacyBothAction) {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_LEGACY_BOTH);
        }
        else if (selectedAction == r0UnhideProcessAction) { executeR0SetProcessHiddenAction(false); }
        else if (selectedAction == r0ClearHiddenProcessAction) { executeR0ClearProcessHiddenAction(); }
        else if (selectedAction == r0EnableBreakAction) { executeR0SetBreakOnTerminationAction(true); }
        else if (selectedAction == r0DisableBreakAction) { executeR0SetBreakOnTerminationAction(false); }
        else if (selectedAction == r0DisableApcAction) { executeR0DisableApcInsertionAction(); }
        else if (selectedAction == r0DkomCidRemoveAction) { executeR0DkomRemoveFromCidTableAction(); }
        else if (selectedAction == refreshPplLevelAction) { executeRefreshPplProtectionLevelAction(); }
        else if (selectedAction == suspendAction) { executeSuspendAction(); }
        else if (selectedAction == resumeAction) { executeResumeAction(); }
        else if (selectedAction == enableEfficiencyAction) { executeSetEfficiencyModeAction(true); }
        else if (selectedAction == disableEfficiencyAction) { executeSetEfficiencyModeAction(false); }
        else if (selectedAction == setCriticalAction) { executeSetCriticalAction(true); }
        else if (selectedAction == clearCriticalAction) { executeSetCriticalAction(false); }
        else if (selectedAction == openFolderAction) { executeOpenFolderAction(); }
        else if (selectedAction == openHandleAction) { executeFocusHandleAction(); }
        else if (selectedAction == openMemoryAction) { executeOpenMemoryOperationAction(); }
        else if (selectedAction == openNetworkAction) { executeFocusNetworkAction(); }
        else if (selectedAction == openWindowAction) { executeFocusWindowAction(); }
        else if (selectedAction == openMessageHooksAction && !contextActionTargets.empty())
        {
            executeOpenMessageHooksAction(contextActionTargets.front().record);
        }
        else if (selectedAction == injectionPageAction) { openSelectedProcessInjectionPage(); }
        else if (selectedAction == scanHotkeyAction) { openSelectedProcessHotkeyScanner(); }
        else if (selectedAction == detailsAction) { openProcessDetailsPlaceholder(); }
        else if (selectedAction->parent() == prioritySubMenu)
        {
            executeSetPriorityAction(selectedAction->data().toInt());
        }
        else if (selectedAction->parent() == integritySubMenu)
        {
            const DWORD integrityRid = selectedAction->data().toUInt();
            executeSetProcessIntegrityAction(
                integrityRid,
                processIntegrityNameFromRid(integrityRid));
        }
        else if (selectedAction->parent() == r0PplLevelSubMenu)
        {
            const unsigned int levelValue = selectedAction->data().toUInt();
            if (levelValue > 0xFFU)
            {
                kLogEvent actionEvent;
                warn << actionEvent
                    << "[ProcessDock] R0 进程保护层级无效: levelValue="
                    << levelValue
                    << eol;
                showActionResultMessage(
                    QStringLiteral("R0设置进程保护层级"),
                    false,
                    std::string("invalid PPL level value"),
                    actionEvent);
                clearContextActionBinding();
                return;
            }

            executeR0SetPplProtectionAction(
                static_cast<std::uint8_t>(levelValue),
                selectedAction->text());
        }
    }
    clearContextActionBinding();
}

void ProcessDock::showHeaderContextMenu(const QPoint& localPosition)
{
    Q_UNUSED(localPosition);

    if (m_processTable == nullptr)
    {
        return;
    }

    QMenu columnMenu(this);
    columnMenu.setStyleSheet(KswordTheme::ContextMenuStyle());

    // 顶部入口指向完整的“选择列”对话框：列数已经接近任务管理器的全量集合，
    // 只靠一次一项的右键菜单难以做批量增减。
    QAction* const chooserAction = columnMenu.addAction(
        processContextText("process.columns.menu.open_chooser", QStringLiteral("选择列...")));
    QAction* const resetAction = columnMenu.addAction(
        processContextText("process.columns.menu.reset_default", QStringLiteral("恢复默认列")));
    columnMenu.addSeparator();

    // 其余为逐列快捷勾选，保留原有的“点一下切一列”交互。
    std::vector<QAction*> columnActions;
    columnActions.reserve(static_cast<std::size_t>(TableColumn::Count));
    for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::Count); ++columnIndex)
    {
        QAction* toggleAction = columnMenu.addAction(
            translatedProcessHeader(columnIndex, ProcessTableHeaders.at(columnIndex)));
        toggleAction->setCheckable(true);
        toggleAction->setChecked(!m_processTable->isColumnHidden(columnIndex));
        toggleAction->setData(columnIndex);
        // 进程名列是行标识，不允许整列隐藏。
        toggleAction->setEnabled(columnIndex != toColumnIndex(TableColumn::Name));
        columnActions.push_back(toggleAction);
    }

    QAction* selectedAction = columnMenu.exec(QCursor::pos());
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == chooserAction)
    {
        showColumnChooserDialog();
        return;
    }
    if (selectedAction == resetAction)
    {
        resetProcessColumnsToViewDefault();
        return;
    }

    const int columnIndex = selectedAction->data().toInt();
    const bool shouldShow = selectedAction->isChecked();
    setProcessColumnVisible(columnIndex, shouldShow);

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 列显示状态变更, column=" << columnIndex
        << ", header=" << ProcessTableHeaders.value(columnIndex).toStdString()
        << ", visible=" << (shouldShow ? "true" : "false")
        << eol;
}

void ProcessDock::copyCurrentCell()
{
    if (m_processTable == nullptr)
    {
        return;
    }

    int currentColumn = 0;
    if (QItemSelectionModel* selectionModel = m_processTable->selectionModel())
    {
        currentColumn = selectionModel->currentIndex().column();
    }
    currentColumn = std::clamp(currentColumn, 0, static_cast<int>(TableColumn::Count) - 1);

    const std::vector<QModelIndex> selectedRows = selectedProcessTableRowIndexes(true);
    QStringList cellTexts;
    cellTexts.reserve(static_cast<int>(selectedRows.size()));
    std::unordered_set<std::string> visitedIdentitySet;
    for (const QModelIndex& rowIndex : selectedRows)
    {
        const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
        if (tableRow == nullptr)
        {
            continue;
        }
        if (!tableRow->identityKey.empty() && visitedIdentitySet.find(tableRow->identityKey) != visitedIdentitySet.end())
        {
            continue;
        }
        if (!tableRow->identityKey.empty())
        {
            visitedIdentitySet.insert(tableRow->identityKey);
        }

        const QModelIndex cellIndex = rowIndex.sibling(rowIndex.row(), currentColumn);
        cellTexts.push_back(cellIndex.data(Qt::DisplayRole).toString());
    }

    QApplication::clipboard()->setText(cellTexts.join("\n"));

    kLogEvent logEvent;
    dbg << logEvent
        << "[ProcessDock] 复制单元格, column=" << currentColumn
        << ", rowCount=" << cellTexts.size()
        << ", text=" << cellTexts.join("\\n").toStdString()
        << eol;
}

void ProcessDock::copyCurrentRow()
{
    if (m_processTable == nullptr)
    {
        return;
    }

    const std::vector<QModelIndex> selectedRows = selectedProcessTableRowIndexes(true);
    QStringList rowTexts;
    rowTexts.reserve(static_cast<int>(selectedRows.size()));
    std::unordered_set<std::string> visitedIdentitySet;
    for (const QModelIndex& rowIndex : selectedRows)
    {
        const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
        if (tableRow == nullptr)
        {
            continue;
        }
        if (!tableRow->identityKey.empty() && visitedIdentitySet.find(tableRow->identityKey) != visitedIdentitySet.end())
        {
            continue;
        }
        if (!tableRow->identityKey.empty())
        {
            visitedIdentitySet.insert(tableRow->identityKey);
        }

        QStringList rowFields;
        rowFields.reserve(static_cast<int>(TableColumn::Count));
        for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::Count); ++columnIndex)
        {
            const QModelIndex cellIndex = rowIndex.sibling(rowIndex.row(), columnIndex);
            rowFields.push_back(cellIndex.data(Qt::DisplayRole).toString());
        }
        rowTexts.push_back(rowFields.join("\t"));
    }
    QApplication::clipboard()->setText(rowTexts.join("\n"));

    kLogEvent logEvent;
    dbg << logEvent
        << "[ProcessDock] 复制整行, rowCount=" << rowTexts.size()
        << ", text=" << rowTexts.join("\\n").toStdString()
        << eol;
}


void ProcessDock::bindContextActionToIndex(const QModelIndex& clickedIndex)
{
    clearContextActionBinding();
    if (m_processTable == nullptr)
    {
        return;
    }

    // 右键动作绑定：
    // - 优先绑定当前所有选中行，让菜单动作天然支持 Ctrl 复选批量操作；
    // - 如果当前没有选中行，则退化为右键点中的单行。
    const std::vector<QModelIndex> selectedRows = selectedProcessTableRowIndexes(true);
    std::vector<QModelIndex> effectiveRows = selectedRows;
    if (effectiveRows.empty() && clickedIndex.isValid())
    {
        effectiveRows.push_back(clickedIndex.sibling(clickedIndex.row(), 0));
    }

    std::unordered_set<std::string> visitedIdentitySet;
    for (const QModelIndex& rowIndex : effectiveRows)
    {
        const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
        if (tableRow == nullptr)
        {
            continue;
        }
        appendProcessActionTargetsFromTableRow(*tableRow, m_contextActionRecords, visitedIdentitySet);
    }

    if (m_contextActionRecords.empty())
    {
        return;
    }

    m_contextActionIdentityKey = m_contextActionRecords.front().identityKey;
    m_contextActionRecord = m_contextActionRecords.front().record;
    m_hasContextActionRecord = true;
}

void ProcessDock::clearContextActionBinding()
{
    m_contextActionIdentityKey.clear();
    m_contextActionRecords.clear();
    m_hasContextActionRecord = false;
    m_contextMenuVisible = false;
}

std::string ProcessDock::selectedIdentityKey() const
{
    if (!m_contextActionIdentityKey.empty())
    {
        return m_contextActionIdentityKey;
    }

    if (m_processTable == nullptr)
    {
        return std::string();
    }

    if (QItemSelectionModel* selectionModel = m_processTable->selectionModel())
    {
        const QModelIndex currentIndex = selectionModel->currentIndex();
        const ProcessTableRow* tableRow = processTableRowForViewIndex(currentIndex);
        if (tableRow != nullptr && tableRow->rowKind == ProcessTableRowKind::Process)
        {
            return tableRow->identityKey;
        }
        if (tableRow != nullptr &&
            tableRow->rowKind == ProcessTableRowKind::ApplicationAggregate &&
            tableRow->actionIdentityKeys.size() == 1U)
        {
            return tableRow->actionIdentityKeys.front();
        }
    }
    return std::string();
}

ks::process::ProcessRecord* ProcessDock::selectedRecord()
{
    const std::string identityKey = selectedIdentityKey();
    if (identityKey.empty())
    {
        return nullptr;
    }

    auto cacheIt = m_cacheByIdentity.find(identityKey);
    if (cacheIt == m_cacheByIdentity.end())
    {
        if (m_hasContextActionRecord)
        {
            return &m_contextActionRecord;
        }
        return nullptr;
    }
    return &cacheIt->second.record;
}

std::vector<ProcessDock::ProcessActionTarget> ProcessDock::selectedActionTargets() const
{
    // 右键菜单弹出期间优先使用冻结的动作绑定，避免刷新或选择变化影响执行对象。
    if (!m_contextActionRecords.empty())
    {
        return m_contextActionRecords;
    }

    std::vector<ProcessActionTarget> actionTargets;
    std::unordered_set<std::string> visitedIdentitySet;

    if (m_processTable != nullptr)
    {
        const std::vector<QModelIndex> selectedRows = selectedProcessTableRowIndexes(true);
        for (const QModelIndex& rowIndex : selectedRows)
        {
            const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
            if (tableRow == nullptr)
            {
                continue;
            }
            appendProcessActionTargetsFromTableRow(*tableRow, actionTargets, visitedIdentitySet);
        }
    }

    return actionTargets;
}

std::vector<ProcessDock::ProcessActionTarget> ProcessDock::processTreeActionTargets() const
{
    // 进程树识别只读取 R3 刷新写入的主进程缓存：
    // - 不读取 R0 cross-view 或 R0-only 行，避免内核枚举结果改变父子关系；
    // - 仅保留最新轮仍存活的记录，避免退出进程或 PID 复用污染树目标。
    std::unordered_map<std::uint32_t, std::vector<ProcessActionTarget>> childrenByParentPid;
    childrenByParentPid.reserve(m_cacheByIdentity.size());
    for (const auto& cachePair : m_cacheByIdentity)
    {
        const CacheEntry& cacheEntry = cachePair.second;
        if (cacheEntry.isExitedInLatestRound || cacheEntry.record.pid == 0U)
        {
            continue;
        }

        ProcessActionTarget snapshotTarget{};
        snapshotTarget.identityKey = cachePair.first;
        snapshotTarget.record = cacheEntry.record;
        childrenByParentPid[snapshotTarget.record.parentPid].push_back(std::move(snapshotTarget));
    }

    // 固定同一父节点的遍历顺序，保证同一份 R3 快照每次生成的动作列表一致。
    for (auto& childPair : childrenByParentPid)
    {
        std::vector<ProcessActionTarget>& childTargets = childPair.second;
        std::sort(childTargets.begin(), childTargets.end(), [](const ProcessActionTarget& left, const ProcessActionTarget& right)
        {
            if (left.record.pid != right.record.pid)
            {
                return left.record.pid < right.record.pid;
            }
            return left.identityKey < right.identityKey;
        });
    }

    const std::vector<ProcessActionTarget> selectedTargets = selectedActionTargets();
    std::vector<ProcessActionTarget> pendingTargets;
    pendingTargets.reserve(m_cacheByIdentity.size());
    std::unordered_set<std::uint32_t> scheduledPidSet;
    scheduledPidSet.reserve(m_cacheByIdentity.size());

    // 选中根也必须存在于 R3 主缓存，R0-only 行不会被当作进程树根。
    for (const ProcessActionTarget& selectedTarget : selectedTargets)
    {
        const auto cacheIt = m_cacheByIdentity.find(selectedTarget.identityKey);
        if (cacheIt == m_cacheByIdentity.end() ||
            cacheIt->second.isExitedInLatestRound ||
            cacheIt->second.record.pid == 0U)
        {
            continue;
        }

        const std::uint32_t processId = cacheIt->second.record.pid;
        if (!scheduledPidSet.insert(processId).second)
        {
            continue;
        }

        ProcessActionTarget rootTarget{};
        rootTarget.identityKey = cacheIt->first;
        rootTarget.record = cacheIt->second.record;
        pendingTargets.push_back(std::move(rootTarget));
    }

    std::vector<ProcessActionTarget> treeTargets;
    treeTargets.reserve(pendingTargets.size());
    for (std::size_t pendingIndex = 0U; pendingIndex < pendingTargets.size(); ++pendingIndex)
    {
        ProcessActionTarget currentTarget = pendingTargets[pendingIndex];
        treeTargets.push_back(currentTarget);

        const auto childIt = childrenByParentPid.find(currentTarget.record.pid);
        if (childIt == childrenByParentPid.end())
        {
            continue;
        }

        for (const ProcessActionTarget& childTarget : childIt->second)
        {
            if (scheduledPidSet.insert(childTarget.record.pid).second)
            {
                pendingTargets.push_back(childTarget);
            }
        }
    }

    return treeTargets;
}

void ProcessDock::clearProcessTableSelection()
{
    if (m_processTable == nullptr || m_contextMenuVisible)
    {
        return;
    }

    // hadSelectionState：
    // - 既检查 Qt 当前选择，也检查跨刷新追踪 key；
    // - 避免没有选择时反复刷新图表和 viewport。
    const bool hadSelectionState =
        !selectedProcessTableRowIndexes(true).empty() ||
        !m_trackedSelectedIdentityKey.empty() ||
        !m_trackedSelectedIdentityKeys.empty();
    if (!hadSelectionState)
    {
        return;
    }

    // 清空 Qt 选择模型：
    // - 阻断中间信号，防止 selectionChanged 在 currentIndex 尚未清空时重新写回追踪 key；
    // - 后续手动刷新活动图，保证 UI 状态只更新一次。
    {
        QSignalBlocker tableSignalBlocker(m_processTable);
        if (QItemSelectionModel* selectionModel = m_processTable->selectionModel())
        {
            QSignalBlocker selectionSignalBlocker(selectionModel);
            selectionModel->clear();
        }
        m_processTable->setCurrentIndex(QModelIndex());
    }

    // 清空 ProcessDock 自己的跨刷新选择缓存，让活动图 selectionKeys 为空并回到整体曲线。
    m_trackedSelectedIdentityKey.clear();
    m_trackedSelectedIdentityKeys.clear();
    m_trackedSelectedColumn = 0;
    clearContextActionBinding();

    refreshProcessActivityChart();
    if (m_activityTimelineSlider != nullptr && !m_activitySamples.empty())
    {
        previewProcessActivitySnapshotForIndex(m_activityTimelineSlider->value());
    }
    m_processTable->viewport()->update();

    kLogEvent logEvent;
    dbg << logEvent
        << "[ProcessDock] 已清空进程表选择，活动图切换为整体视图。"
        << eol;
}

void ProcessDock::syncTrackedSelectionFromTable()
{
    if (m_processTable == nullptr || m_contextMenuVisible)
    {
        return;
    }

    std::vector<std::string> selectedIdentityKeys;
    std::unordered_set<std::string> visitedIdentitySet;
    const std::vector<QModelIndex> selectedRows = selectedProcessTableRowIndexes(false);
    selectedIdentityKeys.reserve(selectedRows.size());

    for (const QModelIndex& rowIndex : selectedRows)
    {
        const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
        if (tableRow == nullptr ||
            tableRow->rowKind != ProcessTableRowKind::Process ||
            tableRow->identityKey.empty())
        {
            continue;
        }
        if (!visitedIdentitySet.insert(tableRow->identityKey).second)
        {
            continue;
        }
        selectedIdentityKeys.push_back(tableRow->identityKey);
    }

    const QModelIndex currentIndex = m_processTable->selectionModel() != nullptr
        ? m_processTable->selectionModel()->currentIndex()
        : QModelIndex();
    const ProcessTableRow* currentRow = processTableRowForViewIndex(currentIndex);
    if (currentRow != nullptr &&
        currentRow->rowKind == ProcessTableRowKind::Process &&
        !currentRow->identityKey.empty())
    {
        m_trackedSelectedIdentityKey = currentRow->identityKey;
        if (visitedIdentitySet.find(currentRow->identityKey) == visitedIdentitySet.end())
        {
            selectedIdentityKeys.push_back(currentRow->identityKey);
        }
    }
    else
    {
        m_trackedSelectedIdentityKey.clear();
    }

    m_trackedSelectedIdentityKeys = std::move(selectedIdentityKeys);
}

void ProcessDock::dispatchProcessActionTargetsInParallel(
    const QString& actionTitle,
    const std::vector<ProcessActionTarget>& actionTargets,
    const std::function<bool(const ProcessActionTarget&, std::string*)>& actionInvoker,
    const bool refreshWhenAnySucceeded,
    const bool forceAsyncWithTimeout,
    const bool requireVerifiedProcessIdentity)
{
    // 参数检查：没有目标或没有执行体时直接记录并返回。
    if (actionTargets.empty() || !actionInvoker)
    {
        kLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] 批量动作被忽略：目标为空或执行体为空, title="
            << actionTitle.toStdString()
            << eol;
        return;
    }

    // 对任何按 PID 定位目标的变更动作，先在同一进程对象上验证 PID + 创建时间，并将
    // 查询句柄保持至 actionInvoker 返回。这样 R3 或 R0 动作实现即使仍以 PID 为入口，
    // 也不会在目标退出后误落到被 Windows 复用的 PID。
    const auto invokeAction = [actionInvoker, requireVerifiedProcessIdentity](
        const ProcessActionTarget& actionTarget,
        std::string* const detailTextOut) -> bool
    {
        if (!requireVerifiedProcessIdentity || actionTarget.isKernelOnly)
        {
            return actionInvoker(actionTarget, detailTextOut);
        }

        HANDLE rawIdentityHandle = nullptr;
        std::string identityDetailText;
        if (!acquireProcessActionIdentityHold(
                actionTarget.record.pid,
                actionTarget.record.creationTime100ns,
                &rawIdentityHandle,
                &identityDetailText))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = identityDetailText;
            }
            return false;
        }

        ScopedProcessActionHandle identityHandle(rawIdentityHandle);
        return actionInvoker(actionTarget, detailTextOut);
    };

    // R3 结束进程包含外部调试器和会话管理回退，单目标也必须异步执行。
    // 其它动作沿用原单目标同步语义，避免扩大本次改动范围。
    if (actionTargets.size() == 1U && !forceAsyncWithTimeout)
    {
        std::string detailText;
        const bool actionOk = invokeAction(actionTargets.front(), &detailText);
        kLogEvent actionEvent;
        (actionOk ? info : err) << actionEvent
            << "[ProcessDock] 单进程动作完成, title=" << actionTitle.toStdString()
            << ", pid=" << actionTargets.front().record.pid
            << ", ok=" << (actionOk ? "true" : "false")
            << ", detail=" << (detailText.empty() ? "无附加信息" : detailText)
            << eol;
        showActionResultMessage(actionTitle, actionOk, detailText, actionEvent);
        if (actionOk && refreshWhenAnySucceeded)
        {
            requestAsyncRefresh(true);
        }
        clearContextActionBinding();
        return;
    }

    // 批量动作：每个 PID 独立线程执行，避免一个目标卡住后阻塞后续目标。
    static constexpr int kProcessActionTimeoutMs = 15000;
    QPointer<ProcessDock> guard(this);
    const QString localActionTitle = actionTitle;
    const std::size_t targetCount = actionTargets.size();
    const auto finishedCounter = std::make_shared<std::atomic_size_t>(0U);
    const auto anySucceeded = std::make_shared<std::atomic_bool>(false);
    kLogEvent startEvent;
    info << startEvent
        << "[ProcessDock] 启动批量动作, title=" << localActionTitle.toStdString()
        << ", targetCount=" << targetCount
        << eol;

    for (const ProcessActionTarget& actionTarget : actionTargets)
    {
        // resultReported 用途：在“正常完成”和“超时看门狗”之间只允许一方回填 UI。
        // 超时后的迟到结果仍写日志和参与刷新统计，但不能覆盖已报告的失败结论。
        std::shared_ptr<std::atomic_bool> resultReported;
        if (forceAsyncWithTimeout)
        {
            resultReported = std::make_shared<std::atomic_bool>(false);
            QTimer::singleShot(
                kProcessActionTimeoutMs,
                this,
                [guard, localActionTitle, actionTarget, resultReported]()
                {
                    bool expected = false;
                    if (!resultReported->compare_exchange_strong(
                        expected,
                        true,
                        std::memory_order_acq_rel))
                    {
                        return;
                    }

                    const std::string timeoutDetail =
                        "process action timed out after 15000 ms; target may be PPL-protected or a system API is blocked";
                    kLogEvent timeoutEvent;
                    err << timeoutEvent
                        << "[ProcessDock] 进程动作超时, title="
                        << localActionTitle.toStdString()
                        << ", pid="
                        << actionTarget.record.pid
                        << ", detail="
                        << timeoutDetail
                        << eol;

                    if (guard != nullptr)
                    {
                        guard->showActionResultMessage(
                            localActionTitle,
                            false,
                            timeoutDetail,
                            timeoutEvent);
                    }
                });
        }

        std::thread([
            guard,
            localActionTitle,
            actionTarget,
            invokeAction,
            refreshWhenAnySucceeded,
            targetCount,
            finishedCounter,
            anySucceeded,
            resultReported]()
        {
            std::string detailText;
            const bool actionOk = invokeAction(actionTarget, &detailText);
            const std::string normalizedDetailText = detailText.empty() ? "无附加信息" : detailText;
            if (actionOk)
            {
                anySucceeded->store(true, std::memory_order_relaxed);
            }
            const std::size_t finishedCount =
                finishedCounter->fetch_add(1U, std::memory_order_acq_rel) + 1U;
            const bool allTargetsFinished = (finishedCount >= targetCount);

            kLogEvent threadEvent;
            (actionOk ? info : err) << threadEvent
                << "[ProcessDock] 批量动作单目标完成, title=" << localActionTitle.toStdString()
                << ", pid=" << actionTarget.record.pid
                << ", identity=" << actionTarget.identityKey
                << ", ok=" << (actionOk ? "true" : "false")
                << ", detail=" << normalizedDetailText
                << eol;

            bool reportCompletion = true;
            if (resultReported != nullptr)
            {
                bool expected = false;
                reportCompletion = resultReported->compare_exchange_strong(
                    expected,
                    true,
                    std::memory_order_acq_rel);
            }
            if (!reportCompletion)
            {
                kLogEvent lateResultEvent;
                warn << lateResultEvent
                    << "[ProcessDock] 进程动作在超时提示后返回, title="
                    << localActionTitle.toStdString()
                    << ", pid="
                    << actionTarget.record.pid
                    << ", ok="
                    << (actionOk ? "true" : "false")
                    << ", detail="
                    << normalizedDetailText
                    << eol;
            }

            if (guard == nullptr)
            {
                return;
            }

            if (reportCompletion)
            {
                QMetaObject::invokeMethod(guard, [guard, localActionTitle, actionOk, detailText]()
                {
                    if (guard == nullptr)
                    {
                        return;
                    }

                    kLogEvent uiEvent;
                    guard->showActionResultMessage(localActionTitle, actionOk, detailText, uiEvent);
                }, Qt::QueuedConnection);
            }

            if (!allTargetsFinished || guard == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(guard, [guard, localActionTitle, refreshWhenAnySucceeded, anySucceeded]()
            {
                if (guard == nullptr)
                {
                    return;
                }

                if (refreshWhenAnySucceeded && anySucceeded->load(std::memory_order_relaxed))
                {
                    kLogEvent refreshEvent;
                    info << refreshEvent
                        << "[ProcessDock] 批量动作全部完成，触发一次刷新, title="
                        << localActionTitle.toStdString()
                        << eol;
                    guard->requestAsyncRefresh(true);
                }
            }, Qt::QueuedConnection);
        }).detach();
    }

    // 保持 R3 单目标动作的上下文清理时机，防止后台执行期间右键绑定指向旧行。
    if (forceAsyncWithTimeout && actionTargets.size() == 1U)
    {
        clearContextActionBinding();
    }
}

QString ProcessDock::formatColumnText(const ks::process::ProcessRecord& processRecord, const TableColumn column, const int depth) const
{
    switch (column)
    {
    case TableColumn::Name:
        Q_UNUSED(depth);
        return QString::fromStdString(processRecord.processName);
    case TableColumn::Pid:
        return QString::number(processRecord.pid);
    case TableColumn::Cpu:
        // CPU 改为两位小数，避免低占用进程全部显示 0.0 的视觉误差。
        return QString::number(processRecord.cpuPercent, 'f', 2) + "%";
    case TableColumn::Ram:
        return processContextText("process.table.cell.ram", QStringLiteral("使用 %1 MB / 申请 %2 MB"))
            .arg(processRecord.workingSetMB, 0, 'f', 1)
            .arg(processRecord.ramMB, 0, 'f', 1);
    case TableColumn::Disk:
        return QString::number(processRecord.diskMBps, 'f', 2) + " MB/s";
    case TableColumn::Gpu:
        return QString::number(processRecord.gpuPercent, 'f', 1) + "%";
    case TableColumn::Net:
        return QStringLiteral("↓%1 / ↑%2 KB/s")
            .arg(processRecord.netRxKBps, 0, 'f', 2)
            .arg(processRecord.netTxKBps, 0, 'f', 2);
    case TableColumn::Signature:
        // 显示“厂家 + 可信状态”文本，未填充时显示 Unknown。
        return QString::fromStdString(processRecord.signatureState.empty() ? "Unknown" : processRecord.signatureState);
    case TableColumn::Path:
        return QString::fromStdString(processRecord.imagePath.empty() ? "-" : processRecord.imagePath);
    case TableColumn::ParentPid:
        return QString::number(processRecord.parentPid);
    case TableColumn::CommandLine:
        return QString::fromStdString(processRecord.commandLine.empty() ? "-" : processRecord.commandLine);
    case TableColumn::User:
        return QString::fromStdString(processRecord.userName.empty() ? "-" : processRecord.userName);
    case TableColumn::StartTime:
        return QString::fromStdString(processRecord.startTimeText);
    case TableColumn::IsAdmin:
        // 用方块 + 文本表示管理员状态（颜色在重建表格时设置）。
        return processRecord.isAdmin
            ? processContextText("process.table.cell.admin_yes", QStringLiteral("■ 是"))
            : processContextText("process.table.cell.admin_no", QStringLiteral("■ 否"));
    case TableColumn::PplLevel:
        // PPL 保护级别枚举只由用户手动刷新，不从缓存继承。
        if (!processRecord.protectionLevelKnown)
        {
            return QStringLiteral("未手动刷新");
        }
        return QString::fromStdString(processRecord.protectionLevelText.empty()
            ? "Unknown"
            : processRecord.protectionLevelText);
    case TableColumn::Protection:
        if ((processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable (%1)").arg(processFieldSourceText(processRecord.r0ProtectionSource));
        }
        return QStringLiteral("%1 (%2)")
            .arg(byteHexText(processRecord.r0Protection))
            .arg(processFieldSourceText(processRecord.r0ProtectionSource));
    case TableColumn::Ppl:
        if ((processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return (processRecord.r0Protection == 0U)
            ? QStringLiteral("None (0x00)")
            : QStringLiteral("PPL %1").arg(byteHexText(processRecord.r0Protection));
    case TableColumn::HandleCount:
        return QString::number(processRecord.handleCount);
    case TableColumn::HandleTable:
        return pointerAvailabilityText(
            (processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE) != 0U,
            processRecord.r0ObjectTableAddress,
            processRecord.r0ObjectTableSource);
    case TableColumn::SectionObject:
        return pointerAvailabilityText(
            (processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE) != 0U,
            processRecord.r0SectionObjectAddress,
            processRecord.r0SectionObjectSource);
    case TableColumn::R0Status:
        return processR0StatusText(processRecord.r0Status);

    // ======== 任务管理器“详细信息”页对齐列 ========
    // 统一原则：字段未采集或系统不提供时显示占位符，不用 0 冒充真实值。
    case TableColumn::PackageName:
        if (!processRecord.packageNameKnown)
        {
            return ProcessColumnUnavailableText;
        }
        // 非打包进程在任务管理器里同样是空白，这里用占位符明确表达“不属于任何程序包”。
        return processRecord.packageFullName.empty()
            ? ProcessColumnUnavailableText
            : QString::fromStdString(processRecord.packageFullName);
    case TableColumn::Status:
        if (!processRecord.processStateKnown)
        {
            return ProcessColumnUnavailableText;
        }
        return processRecord.processSuspended
            ? processContextText("process.table.cell.status_suspended", QStringLiteral("已挂起"))
            : processContextText("process.table.cell.status_running", QStringLiteral("正在运行"));
    case TableColumn::SessionId:
        return QString::number(processRecord.sessionId);
    case TableColumn::JobObject:
        // 作业对象 ID 没有公开查询接口；这里如实区分“不在作业中(0)”与“归属某个作业”。
        if (!processRecord.jobObjectKnown)
        {
            return ProcessColumnUnavailableText;
        }
        return processRecord.inJobObject
            ? processContextText("process.table.cell.job_object_member", QStringLiteral("归属作业"))
            : QStringLiteral("0");
    case TableColumn::CpuTime:
        return processCpuTimeText(processRecord.rawCpuTime100ns);
    case TableColumn::CycleTime:
        return processRecord.cycleTimeKnown
            ? processGroupedNumberText(processRecord.cycleTime)
            : ProcessColumnUnavailableText;
    case TableColumn::WorkingSet:
        return processKilobyteText(processRecord.rawWorkingSetBytes);
    case TableColumn::PeakWorkingSet:
        return processRecord.memoryDetailKnown
            ? processKilobyteText(processRecord.peakWorkingSetBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::WorkingSetDelta:
        return processSignedKilobyteText(processRecord.workingSetDeltaBytes);
    case TableColumn::ActivePrivateWorkingSet:
        return processRecord.privateWorkingSetKnown
            ? processKilobyteText(processRecord.activePrivateWorkingSetBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::PrivateWorkingSet:
        return processRecord.privateWorkingSetKnown
            ? processKilobyteText(processRecord.privateWorkingSetBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::SharedWorkingSet:
        return processRecord.privateWorkingSetKnown
            ? processKilobyteText(processRecord.sharedWorkingSetBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::CommitSize:
        return processRecord.memoryDetailKnown
            ? processKilobyteText(processRecord.commitSizeBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::PagedPool:
        return processRecord.memoryDetailKnown
            ? processKilobyteText(processRecord.pagedPoolBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::NonPagedPool:
        return processRecord.memoryDetailKnown
            ? processKilobyteText(processRecord.nonPagedPoolBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::PageFaults:
        return processRecord.memoryDetailKnown
            ? processGroupedNumberText(processRecord.pageFaultCount)
            : ProcessColumnUnavailableText;
    case TableColumn::PageFaultDelta:
        return processRecord.memoryDetailKnown
            ? processGroupedSignedNumberText(processRecord.pageFaultDeltaCount)
            : ProcessColumnUnavailableText;
    case TableColumn::BasePriority:
        return QString::number(processRecord.basePriority);
    case TableColumn::ThreadCount:
        return QString::number(processRecord.threadCount);
    case TableColumn::UserObjects:
        return processRecord.guiResourceKnown
            ? processGroupedNumberText(processRecord.userObjectCount)
            : ProcessColumnUnavailableText;
    case TableColumn::GdiObjects:
        return processRecord.guiResourceKnown
            ? processGroupedNumberText(processRecord.gdiObjectCount)
            : ProcessColumnUnavailableText;
    case TableColumn::IoReads:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioReadOperationCount)
            : ProcessColumnUnavailableText;
    case TableColumn::IoWrites:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioWriteOperationCount)
            : ProcessColumnUnavailableText;
    case TableColumn::IoOther:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioOtherOperationCount)
            : ProcessColumnUnavailableText;
    case TableColumn::IoReadBytes:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioReadTransferBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::IoWriteBytes:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioWriteTransferBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::IoOtherBytes:
        return processRecord.ioDetailKnown
            ? processGroupedNumberText(processRecord.ioOtherTransferBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::OsContext:
        // 没有兼容性清单的映像在任务管理器里同样是空白，这里统一用占位符表示“无声明”。
        return processRecord.osContextText.empty()
            ? ProcessColumnUnavailableText
            : QString::fromStdString(processRecord.osContextText);
    case TableColumn::Platform:
        return processRecord.architectureText.empty()
            ? ProcessColumnUnavailableText
            : QString::fromStdString(processRecord.architectureText);
    case TableColumn::UacVirtualization:
        return processFeatureStateText(processRecord.uacVirtualizationState);
    case TableColumn::Description:
        return processRecord.fileDescription.empty()
            ? ProcessColumnUnavailableText
            : QString::fromStdString(processRecord.fileDescription);
    case TableColumn::DataExecutionPrevention:
        return processFeatureStateText(processRecord.dataExecutionPreventionState);
    case TableColumn::ControlFlowGuard:
        return processFeatureStateText(processRecord.controlFlowGuardState);
    case TableColumn::HardwareStackProtection:
        return processFeatureStateText(processRecord.hardwareStackProtectionState);
    case TableColumn::DpiAwareness:
        return processDpiAwarenessText(processRecord.dpiAwarenessLevel);
    case TableColumn::EnterpriseContext:
        if (processRecord.enterpriseContextText.empty())
        {
            return ProcessColumnUnavailableText;
        }
        if (processRecord.enterpriseContextText == "Personal")
        {
            return processContextText("process.table.cell.enterprise_personal", QStringLiteral("个人"));
        }
        return QString::fromStdString(processRecord.enterpriseContextText);
    case TableColumn::PowerThrottling:
        if (!processRecord.efficiencyModeSupported)
        {
            return ProcessColumnUnavailableText;
        }
        return processRecord.efficiencyModeEnabled
            ? processFeatureStateText(ks::process::ProcessFeatureState::Enabled)
            : processFeatureStateText(ks::process::ProcessFeatureState::Disabled);
    case TableColumn::GpuEngine:
        return processRecord.gpuEngineText.empty()
            ? ProcessColumnUnavailableText
            : QString::fromStdString(processRecord.gpuEngineText);
    case TableColumn::GpuDedicatedMemory:
        return processRecord.gpuMemoryKnown
            ? processMegabyteText(processRecord.gpuDedicatedMemoryBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::GpuSharedMemory:
        return processRecord.gpuMemoryKnown
            ? processMegabyteText(processRecord.gpuSharedMemoryBytes)
            : ProcessColumnUnavailableText;
    case TableColumn::ProcessType:
        // 类型依赖“应用 / 后台进程 / Windows 进程”的行分组结果，
        // 该信息保存在 ProcessTableRow 而不是 ProcessRecord，由 processTableData 直接产出。
        return QString();
    case TableColumn::CpuCore:
        // CPU核心列只由 delegate 自绘真实逐核心扇形，不额外显示文本。
        return QString();
    default:
        return QString();
    }
}

QIcon ProcessDock::blueTintedIcon(const char* iconPath, const QSize& iconSize) const
{
    return tintedProcessTabIcon(iconPath, KswordTheme::PrimaryBlueColor, iconSize);
}

QIcon ProcessDock::tintedProcessTabIcon(
    const char* iconPath,
    const QColor& tintColor,
    const QSize& iconSize) const
{
    // SVG 着色流程：先按原路径渲染透明图，再用 SourceIn 覆盖指定颜色。
    QSvgRenderer renderer(QString::fromUtf8(iconPath));
    if (!renderer.isValid())
    {
        return QIcon(QString::fromUtf8(iconPath));
    }

    QPixmap iconPixmap(iconSize);
    iconPixmap.fill(Qt::transparent);

    QPainter painter(&iconPixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    renderer.render(&painter, QRectF(0, 0, iconSize.width(), iconSize.height()));
    painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    painter.fillRect(iconPixmap.rect(), tintColor);
    painter.end();
    return QIcon(iconPixmap);
}

void ProcessDock::refreshSideTabIconContrast()
{
    if (m_sideTabWidget == nullptr)
    {
        return;
    }

    // 顶部 Tab 选中态是深蓝背景，当前页图标改为白色以避免融入背景。
    const int currentIndex = m_sideTabWidget->currentIndex();
    const QColor selectedIconColor(255, 255, 255);
    const QIcon processIcon = currentIndex == m_sideTabWidget->indexOf(m_processListPage)
        ? tintedProcessTabIcon(IconProcessMain, selectedIconColor)
        : blueTintedIcon(IconProcessMain);
    const QIcon threadIcon = currentIndex == m_sideTabWidget->indexOf(m_threadPage)
        ? tintedProcessTabIcon(IconThreadTab, selectedIconColor)
        : blueTintedIcon(IconThreadTab);
    const QIcon createIcon = currentIndex == m_sideTabWidget->indexOf(m_createProcessPage)
        ? tintedProcessTabIcon(IconStart, selectedIconColor)
        : blueTintedIcon(IconStart);

    if (m_processListPage != nullptr)
    {
        m_sideTabWidget->setTabIcon(m_sideTabWidget->indexOf(m_processListPage), processIcon);
    }
    if (m_threadPage != nullptr)
    {
        m_sideTabWidget->setTabIcon(m_sideTabWidget->indexOf(m_threadPage), threadIcon);
    }
    if (m_createProcessPage != nullptr)
    {
        m_sideTabWidget->setTabIcon(m_sideTabWidget->indexOf(m_createProcessPage), createIcon);
    }
}

void ProcessDock::showActionResultMessage(
    const QString& title,
    const bool actionOk,
    const std::string& detailText,
    const kLogEvent& actionEvent)
{
    if (!actionOk)
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            title,
            QString::fromStdString(detailText));
    }
    // 统一动作结果日志：按照规范不再弹窗，避免频繁打断用户流程。
    const std::string normalizedDetailText = detailText.empty() ? "无附加信息" : detailText;
    (actionOk ? info : err) << actionEvent
        << "[ProcessDock] 动作结果, title=" << title.toStdString()
        << ", actionOk=" << (actionOk ? "true" : "false")
        << ", detail=" << normalizedDetailText
        << eol;
}

std::string ProcessDock::buildRulerPrefix(const int depth)
{
    if (depth <= 0)
    {
        return std::string();
    }

    std::string prefixText;
    for (int index = 0; index < depth; ++index)
    {
        prefixText += (index + 1 == depth) ? "└─ " : "│  ";
    }
    return prefixText;
}

int ProcessDock::toColumnIndex(const TableColumn column)
{
    return static_cast<int>(column);
}

QString ProcessDock::processColumnDisplayName(const int columnIndex)
{
    // 输入：列逻辑索引。
    // 处理：查列表头文本表并按当前语言翻译；表定义在本文件的匿名命名空间中。
    // 返回：列名；索引越界时返回空串，调用方据此跳过该项。
    if (columnIndex < 0 || columnIndex >= ProcessTableHeaders.size())
    {
        return QString();
    }
    return translatedProcessHeader(columnIndex, ProcessTableHeaders.at(columnIndex));
}

void ProcessDock::syncEditValueFromBitmaskChecks(
    QLineEdit* const valueEdit,
    const std::vector<QCheckBox*>* const checkBoxList)
{
    // 参数合法性检查：任一为空直接返回，避免空指针访问。
    if (valueEdit == nullptr || checkBoxList == nullptr)
    {
        return;
    }

    // 先计算“所有已知位掩码 + 已勾选位掩码”，
    // 以便在回写时保留用户手工输入但列表中未覆盖的未知位。
    std::uint32_t knownMask = 0;
    std::uint32_t checkedMask = 0;
    for (QCheckBox* checkBox : *checkBoxList)
    {
        if (checkBox == nullptr)
        {
            continue;
        }
        bool convertOk = false;
        const std::uint32_t flagValue = static_cast<std::uint32_t>(
            checkBox->property("flagValue").toULongLong(&convertOk));
        if (!convertOk)
        {
            continue;
        }

        knownMask |= flagValue;
        if (checkBox->isChecked())
        {
            checkedMask |= flagValue;
        }
    }

    // 保留未知位：避免勾选一个已知位时误清空手工填入的其他位。
    bool parseOk = false;
    const std::uint32_t originalValue = parseUInt32WithDefault(valueEdit->text(), 0, &parseOk);
    const std::uint32_t unknownMask = parseOk ? (originalValue & ~knownMask) : 0;
    const std::uint32_t mergedValue = (checkedMask | unknownMask);

    const QString mergedText = QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(mergedValue), 8, 16, QChar('0'))
        .toUpper();
    if (valueEdit->text().compare(mergedText, Qt::CaseInsensitive) == 0)
    {
        return;
    }

    // 阻断 textChanged 信号，防止“回写文本 -> 再次反向同步”递归触发。
    const QSignalBlocker blocker(valueEdit);
    valueEdit->setText(mergedText);
}

void ProcessDock::syncBitmaskChecksFromEditValue(
    QLineEdit* const valueEdit,
    const std::vector<QCheckBox*>* const checkBoxList,
    const QString& fieldDisplayName)
{
    // 参数合法性检查：任一为空直接返回。
    if (valueEdit == nullptr || checkBoxList == nullptr)
    {
        return;
    }

    // 解析失败时仅跳过勾选同步，不主动覆写用户输入内容。
    bool parseOk = false;
    const std::uint32_t editValue = parseUInt32WithDefault(valueEdit->text(), 0, &parseOk);
    if (!parseOk)
    {
        Q_UNUSED(fieldDisplayName);
        return;
    }

    // 按输入值逐项更新勾选状态；使用 QSignalBlocker 防止触发 toggled 回调。
    for (QCheckBox* checkBox : *checkBoxList)
    {
        if (checkBox == nullptr)
        {
            continue;
        }

        bool convertOk = false;
        const std::uint32_t flagValue = static_cast<std::uint32_t>(
            checkBox->property("flagValue").toULongLong(&convertOk));
        if (!convertOk || flagValue == 0)
        {
            continue;
        }

        const bool shouldChecked = ((editValue & flagValue) == flagValue);
        if (checkBox->isChecked() == shouldChecked)
        {
            continue;
        }

        const QSignalBlocker blocker(checkBox);
        checkBox->setChecked(shouldChecked);
    }
}

void ProcessDock::bindBitmaskEditor(
    QLineEdit* const valueEdit,
    std::vector<QCheckBox*>* const checkBoxList,
    const QString& fieldDisplayName)
{
    // 参数校验：没有输入框或没有复选框列表则不绑定。
    if (valueEdit == nullptr || checkBoxList == nullptr)
    {
        return;
    }

    // 复选框 -> 文本框：每次勾选变化都回算位掩码。
    for (QCheckBox* checkBox : *checkBoxList)
    {
        if (checkBox == nullptr)
        {
            continue;
        }

        connect(checkBox, &QCheckBox::toggled, this, [this, valueEdit, checkBoxList, fieldDisplayName](bool) {
            syncEditValueFromBitmaskChecks(valueEdit, checkBoxList);

            kLogEvent logEvent;
            dbg << logEvent
                << "[ProcessDock] 位标志勾选变更, field="
                << fieldDisplayName.toStdString()
                << ", value="
                << valueEdit->text().toStdString()
                << eol;
            });
    }

    // 文本框 -> 复选框：支持用户手工输入十进制或 0x 十六进制。
    connect(valueEdit, &QLineEdit::textChanged, this, [this, valueEdit, checkBoxList, fieldDisplayName](const QString&) {
        syncBitmaskChecksFromEditValue(valueEdit, checkBoxList, fieldDisplayName);
        });

    // 初始同步：页面打开时让默认值和复选框状态一致。
    syncBitmaskChecksFromEditValue(valueEdit, checkBoxList, fieldDisplayName);
}

bool ProcessDock::parseUnsignedText(const QString& text, std::uint64_t& valueOut)
{
    QString normalizedText = text.trimmed();
    if (normalizedText.isEmpty())
    {
        valueOut = 0;
        return true;
    }

    int numberBase = 10;
    if (normalizedText.startsWith("0x", Qt::CaseInsensitive))
    {
        normalizedText = normalizedText.mid(2);
        numberBase = 16;
    }
    else if (normalizedText.endsWith(QStringLiteral("h"), Qt::CaseInsensitive))
    {
        normalizedText.chop(1);
        numberBase = 16;
    }

    bool parseOk = false;
    const std::uint64_t parsedValue = normalizedText.toULongLong(&parseOk, numberBase);
    if (!parseOk)
    {
        valueOut = 0;
        return false;
    }
    valueOut = parsedValue;
    return true;
}

std::uint32_t ProcessDock::parseUInt32WithDefault(
    const QString& text,
    const std::uint32_t defaultValue,
    bool* const parseOkOut)
{
    std::uint64_t parsedValue = 0;
    if (!parseUnsignedText(text, parsedValue))
    {
        if (parseOkOut != nullptr)
        {
            *parseOkOut = false;
        }
        return defaultValue;
    }
    if (parsedValue > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
    {
        if (parseOkOut != nullptr)
        {
            *parseOkOut = false;
        }
        return defaultValue;
    }
    if (parseOkOut != nullptr)
    {
        *parseOkOut = true;
    }
    return static_cast<std::uint32_t>(parsedValue);
}

std::uint64_t ProcessDock::parseUInt64WithDefault(
    const QString& text,
    const std::uint64_t defaultValue,
    bool* const parseOkOut)
{
    std::uint64_t parsedValue = 0;
    if (!parseUnsignedText(text, parsedValue))
    {
        if (parseOkOut != nullptr)
        {
            *parseOkOut = false;
        }
        return defaultValue;
    }
    if (parseOkOut != nullptr)
    {
        *parseOkOut = true;
    }
    return parsedValue;
}

QSet<std::uint32_t> ProcessDock::collectVisibleWindowPidSet()
{
    // Inputs: current desktop top-level window list.
    // Processing: EnumWindows collects visible, non-tool, non-owned windows and maps them to owner PIDs.
    // Return: PID set used as application roots for friendly process grouping.
    QSet<std::uint32_t> visibleWindowPidSet;
    ::EnumWindows(
        [](HWND windowHandle, LPARAM parameter) -> BOOL
        {
            auto* pidSet = reinterpret_cast<QSet<std::uint32_t>*>(parameter);
            if (pidSet == nullptr ||
                windowHandle == nullptr ||
                ::IsWindowVisible(windowHandle) == FALSE)
            {
                return TRUE;
            }

            if (::GetWindow(windowHandle, GW_OWNER) != nullptr)
            {
                return TRUE;
            }

            const LONG_PTR extendedStyle = ::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE);
            if ((extendedStyle & WS_EX_TOOLWINDOW) != 0)
            {
                return TRUE;
            }

            wchar_t titleBuffer[2]{};
            if (::GetWindowTextW(windowHandle, titleBuffer, 2) <= 0)
            {
                return TRUE;
            }

            DWORD pidValue = 0;
            ::GetWindowThreadProcessId(windowHandle, &pidValue);
            if (pidValue != 0U)
            {
                pidSet->insert(static_cast<std::uint32_t>(pidValue));
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&visibleWindowPidSet));
    return visibleWindowPidSet;
}

std::uint32_t ProcessDock::findFriendlyApplicationRootPid(
    const std::uint32_t pid,
    const std::unordered_map<std::uint32_t, std::uint32_t>& parentPidByPid,
    const QSet<std::uint32_t>& visibleWindowPidSet)
{
    // Inputs: one PID, the PID->parent index, and visible-window root candidates.
    // Processing: walk ancestors defensively and stop on missing parents, cycles, or PID zero.
    // Return: the first visible-window PID in the ancestor chain, or 0 when the process is not an app tree.
    std::unordered_set<std::uint32_t> visitedPidSet;
    std::uint32_t currentPid = pid;
    while (currentPid != 0U && visitedPidSet.insert(currentPid).second)
    {
        if (visibleWindowPidSet.contains(currentPid))
        {
            return currentPid;
        }

        const auto parentIt = parentPidByPid.find(currentPid);
        if (parentIt == parentPidByPid.end() || parentIt->second == currentPid)
        {
            break;
        }
        currentPid = parentIt->second;
    }
    return 0U;
}

bool ProcessDock::isFriendlyWindowsSystemProcess(
    const ks::process::ProcessRecord& processRecord,
    const QString& normalizedWindowsDirectoryPath)
{
    // Inputs: a process snapshot and normalized Windows directory path.
    // Processing: classify kernel/session-manager/core Windows names or Windows-directory images as system.
    // Return: true when the row belongs under the friendly “系统” group.
    if (processRecord.pid == 0U || processRecord.pid == 4U)
    {
        return true;
    }

    const QString processName = QString::fromStdString(processRecord.processName).trimmed().toLower();
    static const QSet<QString> kSystemProcessNames = {
        QStringLiteral("system"),
        QStringLiteral("system idle process"),
        QStringLiteral("registry"),
        QStringLiteral("smss.exe"),
        QStringLiteral("csrss.exe"),
        QStringLiteral("wininit.exe"),
        QStringLiteral("winlogon.exe"),
        QStringLiteral("services.exe"),
        QStringLiteral("lsass.exe"),
        QStringLiteral("lsaiso.exe"),
        QStringLiteral("fontdrvhost.exe"),
        QStringLiteral("dwm.exe"),
        QStringLiteral("wudfhost.exe"),
        QStringLiteral("audiodg.exe"),
        QStringLiteral("memory compression")
    };
    if (kSystemProcessNames.contains(processName))
    {
        return true;
    }

    const QString imagePath = QString::fromStdString(
        !processRecord.imagePath.empty() ? processRecord.imagePath : processRecord.r0ImagePath).trimmed();
    if (imagePath.isEmpty() || normalizedWindowsDirectoryPath.isEmpty())
    {
        return false;
    }

    const QString normalizedImagePath = QDir::fromNativeSeparators(imagePath).toLower();
    return normalizedImagePath.startsWith(normalizedWindowsDirectoryPath + QStringLiteral("/"));
}

QString ProcessDock::friendlyGroupTitle(const FriendlyProcessGroupType groupType, const int entryCount)
{
    // Inputs: friendly group type and current member count.
    // Processing: format localized group names shared by headers and synthetic records.
    // Return: user-visible title text.
    switch (groupType)
    {
    case FriendlyProcessGroupType::Application:
        return processContextText("process.group.application", QStringLiteral("应用 (%1)")).arg(entryCount);
    case FriendlyProcessGroupType::WindowsSystem:
        return processContextText("process.group.system", QStringLiteral("系统 (%1)")).arg(entryCount);
    case FriendlyProcessGroupType::Background:
    default:
        return processContextText("process.group.background", QStringLiteral("后台进程 (%1)")).arg(entryCount);
    }
}

QString ProcessDock::friendlyGroupTypeName(const FriendlyProcessGroupType groupType)
{
    // 输入：友好视图分组类型。
    // 处理：返回不带成员计数的短名称，供“类型”列逐行展示。
    // 返回：与任务管理器“类型”列一致的应用 / 后台进程 / Windows 进程文本。
    switch (groupType)
    {
    case FriendlyProcessGroupType::Application:
        return processContextText("process.type.application", QStringLiteral("应用"));
    case FriendlyProcessGroupType::WindowsSystem:
        return processContextText("process.type.windows", QStringLiteral("Windows 进程"));
    case FriendlyProcessGroupType::Background:
    default:
        return processContextText("process.type.background", QStringLiteral("后台进程"));
    }
}

QString ProcessDock::friendlyExpansionKeyForGroup(const FriendlyProcessGroupType groupType)
{
    // Inputs: friendly group type.
    // Processing: convert enum to stable state key.
    // Return: key used by m_friendlyExpandedStateByKey.
    switch (groupType)
    {
    case FriendlyProcessGroupType::Application:
        return QStringLiteral("friendly:group:application");
    case FriendlyProcessGroupType::WindowsSystem:
        return QStringLiteral("friendly:group:system");
    case FriendlyProcessGroupType::Background:
    default:
        return QStringLiteral("friendly:group:background");
    }
}

QString ProcessDock::friendlyExpansionKeyForApplication(const std::uint32_t rootPid)
{
    // Inputs: an application root PID.
    // Processing: format a stable key that survives refreshes while PID remains alive.
    // Return: key used to persist aggregate expansion state.
    return QStringLiteral("friendly:app:%1").arg(static_cast<qulonglong>(rootPid));
}

ks::process::ProcessRecord ProcessDock::aggregateFriendlyApplicationRecord(
    const std::vector<const CacheEntry*>& applicationEntries,
    const std::uint32_t rootPid)
{
    // Inputs: all cache entries assigned to one application root and that root PID.
    // Processing: choose the root process as display identity and sum per-process metrics.
    // Return: synthetic ProcessRecord for the non-actionable application aggregate row.
    ks::process::ProcessRecord aggregateRecord{};
    if (applicationEntries.empty())
    {
        aggregateRecord.pid = rootPid;
        aggregateRecord.processName = "Application";
        return aggregateRecord;
    }

    const CacheEntry* identityEntry = applicationEntries.front();
    for (const CacheEntry* entry : applicationEntries)
    {
        if (entry != nullptr && entry->record.pid == rootPid)
        {
            identityEntry = entry;
            break;
        }
    }
    if (identityEntry != nullptr)
    {
        aggregateRecord = identityEntry->record;
    }

    aggregateRecord.pid = rootPid;
    aggregateRecord.parentPid = 0U;
    aggregateRecord.threadCount = 0U;
    aggregateRecord.handleCount = 0U;
    aggregateRecord.cpuPercent = 0.0;
    aggregateRecord.cpuCorePercent = 0.0;
    aggregateRecord.ramMB = 0.0;
    aggregateRecord.workingSetMB = 0.0;
    aggregateRecord.diskMBps = 0.0;
    aggregateRecord.gpuPercent = 0.0;
    aggregateRecord.netKBps = 0.0;
    aggregateRecord.netRxKBps = 0.0;
    aggregateRecord.netTxKBps = 0.0;

    // 任务管理器对齐列同样需要在聚合行上给出整棵应用的合计值，
    // 否则折叠状态下这些列会只显示根进程的数字，与 CPU/内存列的语义不一致。
    aggregateRecord.rawWorkingSetBytes = 0;
    aggregateRecord.rawCpuTime100ns = 0;
    aggregateRecord.cycleTime = 0;
    aggregateRecord.peakWorkingSetBytes = 0;
    aggregateRecord.privateWorkingSetBytes = 0;
    aggregateRecord.activePrivateWorkingSetBytes = 0;
    aggregateRecord.sharedWorkingSetBytes = 0;
    aggregateRecord.commitSizeBytes = 0;
    aggregateRecord.pagedPoolBytes = 0;
    aggregateRecord.nonPagedPoolBytes = 0;
    aggregateRecord.pageFaultCount = 0;
    aggregateRecord.workingSetDeltaBytes = 0;
    aggregateRecord.pageFaultDeltaCount = 0;
    aggregateRecord.ioReadOperationCount = 0;
    aggregateRecord.ioWriteOperationCount = 0;
    aggregateRecord.ioOtherOperationCount = 0;
    aggregateRecord.ioReadTransferBytes = 0;
    aggregateRecord.ioWriteTransferBytes = 0;
    aggregateRecord.ioOtherTransferBytes = 0;
    aggregateRecord.gdiObjectCount = 0;
    aggregateRecord.userObjectCount = 0;
    aggregateRecord.gpuDedicatedMemoryBytes = 0;
    aggregateRecord.gpuSharedMemoryBytes = 0;
    aggregateRecord.suspendedThreadCount = 0;

    // 可用性标记先清空，再对成员做“或”合并：
    // 只要有一个成员进程拿到了该组字段，聚合行就展示合计值而不是占位符。
    aggregateRecord.memoryDetailKnown = false;
    aggregateRecord.privateWorkingSetKnown = false;
    aggregateRecord.ioDetailKnown = false;
    aggregateRecord.guiResourceKnown = false;
    aggregateRecord.gpuMemoryKnown = false;
    aggregateRecord.cycleTimeKnown = false;

    // 只有全部成员线程都处于挂起状态时，应用整体才算“已挂起”。
    std::uint32_t aggregateStateKnownCount = 0;
    std::uint32_t aggregateSuspendedCount = 0;
    std::uint32_t aggregateMemberCount = 0;

    for (const CacheEntry* entry : applicationEntries)
    {
        if (entry == nullptr)
        {
            continue;
        }
        const ks::process::ProcessRecord& memberRecord = entry->record;
        ++aggregateMemberCount;

        aggregateRecord.threadCount += memberRecord.threadCount;
        aggregateRecord.handleCount += memberRecord.handleCount;
        aggregateRecord.cpuPercent += memberRecord.cpuPercent;
        aggregateRecord.cpuCorePercent += memberRecord.cpuCorePercent;
        aggregateRecord.ramMB += memberRecord.ramMB;
        aggregateRecord.workingSetMB += memberRecord.workingSetMB;
        aggregateRecord.diskMBps += memberRecord.diskMBps;
        aggregateRecord.gpuPercent += memberRecord.gpuPercent;
        aggregateRecord.netKBps += memberRecord.netKBps;
        aggregateRecord.netRxKBps += memberRecord.netRxKBps;
        aggregateRecord.netTxKBps += memberRecord.netTxKBps;

        aggregateRecord.rawWorkingSetBytes += memberRecord.rawWorkingSetBytes;
        aggregateRecord.rawCpuTime100ns += memberRecord.rawCpuTime100ns;
        aggregateRecord.cycleTime += memberRecord.cycleTime;
        aggregateRecord.peakWorkingSetBytes += memberRecord.peakWorkingSetBytes;
        aggregateRecord.privateWorkingSetBytes += memberRecord.privateWorkingSetBytes;
        aggregateRecord.activePrivateWorkingSetBytes += memberRecord.activePrivateWorkingSetBytes;
        aggregateRecord.sharedWorkingSetBytes += memberRecord.sharedWorkingSetBytes;
        aggregateRecord.commitSizeBytes += memberRecord.commitSizeBytes;
        aggregateRecord.pagedPoolBytes += memberRecord.pagedPoolBytes;
        aggregateRecord.nonPagedPoolBytes += memberRecord.nonPagedPoolBytes;
        aggregateRecord.pageFaultCount += memberRecord.pageFaultCount;
        aggregateRecord.workingSetDeltaBytes += memberRecord.workingSetDeltaBytes;
        aggregateRecord.pageFaultDeltaCount += memberRecord.pageFaultDeltaCount;
        aggregateRecord.ioReadOperationCount += memberRecord.ioReadOperationCount;
        aggregateRecord.ioWriteOperationCount += memberRecord.ioWriteOperationCount;
        aggregateRecord.ioOtherOperationCount += memberRecord.ioOtherOperationCount;
        aggregateRecord.ioReadTransferBytes += memberRecord.ioReadTransferBytes;
        aggregateRecord.ioWriteTransferBytes += memberRecord.ioWriteTransferBytes;
        aggregateRecord.ioOtherTransferBytes += memberRecord.ioOtherTransferBytes;
        aggregateRecord.gdiObjectCount += memberRecord.gdiObjectCount;
        aggregateRecord.userObjectCount += memberRecord.userObjectCount;
        aggregateRecord.gpuDedicatedMemoryBytes += memberRecord.gpuDedicatedMemoryBytes;
        aggregateRecord.gpuSharedMemoryBytes += memberRecord.gpuSharedMemoryBytes;
        aggregateRecord.suspendedThreadCount += memberRecord.suspendedThreadCount;

        aggregateRecord.memoryDetailKnown |= memberRecord.memoryDetailKnown;
        aggregateRecord.privateWorkingSetKnown |= memberRecord.privateWorkingSetKnown;
        aggregateRecord.ioDetailKnown |= memberRecord.ioDetailKnown;
        aggregateRecord.guiResourceKnown |= memberRecord.guiResourceKnown;
        aggregateRecord.gpuMemoryKnown |= memberRecord.gpuMemoryKnown;
        aggregateRecord.cycleTimeKnown |= memberRecord.cycleTimeKnown;

        if (memberRecord.processStateKnown)
        {
            ++aggregateStateKnownCount;
            if (memberRecord.processSuspended)
            {
                ++aggregateSuspendedCount;
            }
        }
    }

    aggregateRecord.processStateKnown =
        (aggregateMemberCount > 0U && aggregateStateKnownCount == aggregateMemberCount);
    aggregateRecord.processSuspended =
        (aggregateRecord.processStateKnown && aggregateSuspendedCount == aggregateMemberCount);
    return aggregateRecord;
}

void ProcessDock::appendCreateResultLine(const QString& lineText)
{
    if (m_createResultOutput == nullptr)
    {
        return;
    }

    // 结果框混合固定提示和后端原始详情；仅转换可命中的固定提示，原始错误内容保持逐字不变。
    const QString timeText = QDateTime::currentDateTime().toString("HH:mm:ss");
    m_createResultOutput->append(QString("[%1] %2").arg(
        timeText,
        ks::i18n::sourceText(lineText)));
}

void ProcessDock::browseCreateProcessApplicationPath()
{
    const QString filePath = QFileDialog::getOpenFileName(
        this,
        "选择可执行文件",
        m_applicationNameEdit != nullptr ? m_applicationNameEdit->text().trimmed() : QString(),
        "Executable (*.exe);;All Files (*.*)");
    if (filePath.isEmpty())
    {
        return;
    }

    if (m_applicationNameEdit != nullptr)
    {
        m_applicationNameEdit->setText(filePath);
    }
    if (m_useApplicationNameCheck != nullptr)
    {
        m_useApplicationNameCheck->setChecked(true);
    }
}

void ProcessDock::browseCreateProcessCurrentDirectory()
{
    const QString startPath = m_currentDirectoryEdit != nullptr
        ? m_currentDirectoryEdit->text().trimmed()
        : QString();
    const QString directoryPath = QFileDialog::getExistingDirectory(
        this,
        "选择工作目录",
        startPath);
    if (directoryPath.isEmpty())
    {
        return;
    }

    if (m_currentDirectoryEdit != nullptr)
    {
        m_currentDirectoryEdit->setText(directoryPath);
    }
    if (m_useCurrentDirectoryCheck != nullptr)
    {
        m_useCurrentDirectoryCheck->setChecked(true);
    }
}

void ProcessDock::resetCreateProcessForm()
{
    if (m_createMethodCombo != nullptr) m_createMethodCombo->setCurrentIndex(0);
    if (m_useApplicationNameCheck != nullptr) m_useApplicationNameCheck->setChecked(false);
    if (m_applicationNameEdit != nullptr) m_applicationNameEdit->clear();
    if (m_useCommandLineCheck != nullptr) m_useCommandLineCheck->setChecked(false);
    if (m_commandLineEdit != nullptr) m_commandLineEdit->clear();
    if (m_useCurrentDirectoryCheck != nullptr) m_useCurrentDirectoryCheck->setChecked(false);
    if (m_currentDirectoryEdit != nullptr) m_currentDirectoryEdit->clear();
    if (m_useEnvironmentCheck != nullptr) m_useEnvironmentCheck->setChecked(false);
    if (m_environmentUnicodeCheck != nullptr) m_environmentUnicodeCheck->setChecked(true);
    if (m_environmentEditor != nullptr) m_environmentEditor->clear();
    if (m_inheritHandleCheck != nullptr) m_inheritHandleCheck->setChecked(false);
    if (m_creationFlagsEdit != nullptr) m_creationFlagsEdit->setText("0x00000000");

    if (m_useProcessSecurityCheck != nullptr) m_useProcessSecurityCheck->setChecked(false);
    if (m_processSecurityLengthEdit != nullptr) m_processSecurityLengthEdit->setText("0");
    if (m_processSecurityDescriptorEdit != nullptr) m_processSecurityDescriptorEdit->setText("0");
    if (m_processSecurityInheritCheck != nullptr) m_processSecurityInheritCheck->setChecked(false);
    if (m_useThreadSecurityCheck != nullptr) m_useThreadSecurityCheck->setChecked(false);
    if (m_threadSecurityLengthEdit != nullptr) m_threadSecurityLengthEdit->setText("0");
    if (m_threadSecurityDescriptorEdit != nullptr) m_threadSecurityDescriptorEdit->setText("0");
    if (m_threadSecurityInheritCheck != nullptr) m_threadSecurityInheritCheck->setChecked(false);

    if (m_useStartupInfoCheck != nullptr) m_useStartupInfoCheck->setChecked(true);
    if (m_siCbEdit != nullptr) m_siCbEdit->setText("0");
    if (m_siReservedEdit != nullptr) m_siReservedEdit->clear();
    if (m_siDesktopEdit != nullptr) m_siDesktopEdit->clear();
    if (m_siTitleEdit != nullptr) m_siTitleEdit->clear();
    if (m_siXEdit != nullptr) m_siXEdit->setText("0");
    if (m_siYEdit != nullptr) m_siYEdit->setText("0");
    if (m_siXSizeEdit != nullptr) m_siXSizeEdit->setText("0");
    if (m_siYSizeEdit != nullptr) m_siYSizeEdit->setText("0");
    if (m_siXCountCharsEdit != nullptr) m_siXCountCharsEdit->setText("0");
    if (m_siYCountCharsEdit != nullptr) m_siYCountCharsEdit->setText("0");
    if (m_siFillAttributeEdit != nullptr) m_siFillAttributeEdit->setText("0x00000000");
    if (m_siFlagsEdit != nullptr) m_siFlagsEdit->setText("0x00000000");
    if (m_siShowWindowEdit != nullptr) m_siShowWindowEdit->setText("0");
    if (m_siCbReserved2Edit != nullptr) m_siCbReserved2Edit->setText("0");
    if (m_siReserved2PtrEdit != nullptr) m_siReserved2PtrEdit->setText("0");
    if (m_siStdInputEdit != nullptr) m_siStdInputEdit->setText("0");
    if (m_siStdOutputEdit != nullptr) m_siStdOutputEdit->setText("0");
    if (m_siStdErrorEdit != nullptr) m_siStdErrorEdit->setText("0");

    if (m_useProcessInfoCheck != nullptr) m_useProcessInfoCheck->setChecked(true);
    if (m_piProcessHandleEdit != nullptr) m_piProcessHandleEdit->setText("0");
    if (m_piThreadHandleEdit != nullptr) m_piThreadHandleEdit->setText("0");
    if (m_piPidEdit != nullptr) m_piPidEdit->setText("0");
    if (m_piTidEdit != nullptr) m_piTidEdit->setText("0");

    if (m_tokenSourcePidEdit != nullptr) m_tokenSourcePidEdit->setText("0");
    if (m_tokenDesiredAccessEdit != nullptr) m_tokenDesiredAccessEdit->setText("0x00000FAB");
    if (m_tokenDuplicatePrimaryCheck != nullptr) m_tokenDuplicatePrimaryCheck->setChecked(true);

    if (m_tokenPrivilegeTable != nullptr)
    {
        for (int row = 0; row < m_tokenPrivilegeTable->rowCount(); ++row)
        {
            QComboBox* actionCombo = qobject_cast<QComboBox*>(m_tokenPrivilegeTable->cellWidget(row, 1));
            if (actionCombo != nullptr)
            {
                actionCombo->setCurrentIndex(0);
            }
        }
    }

    if (m_createResultOutput != nullptr)
    {
        m_createResultOutput->clear();
    }
    appendCreateResultLine("已恢复创建进程表单默认值。");
}

ks::process::CreateProcessRequest ProcessDock::buildCreateProcessRequestFromUi(
    bool* const buildOk,
    QString* const errorTextOut) const
{
    ks::process::CreateProcessRequest request;
    if (buildOk != nullptr)
    {
        *buildOk = false;
    }

    const auto failBuild = [errorTextOut](const QString& textValue) {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = textValue;
        }
        };

    request.useApplicationName = (m_useApplicationNameCheck != nullptr && m_useApplicationNameCheck->isChecked());
    request.applicationName = (m_applicationNameEdit != nullptr) ? m_applicationNameEdit->text().trimmed().toStdString() : std::string();

    request.useCommandLine = (m_useCommandLineCheck != nullptr && m_useCommandLineCheck->isChecked());
    request.commandLine = (m_commandLineEdit != nullptr) ? m_commandLineEdit->text().trimmed().toStdString() : std::string();

    request.useCurrentDirectory = (m_useCurrentDirectoryCheck != nullptr && m_useCurrentDirectoryCheck->isChecked());
    request.currentDirectory = (m_currentDirectoryEdit != nullptr) ? m_currentDirectoryEdit->text().trimmed().toStdString() : std::string();

    request.useEnvironment = (m_useEnvironmentCheck != nullptr && m_useEnvironmentCheck->isChecked());
    request.environmentUnicode = (m_environmentUnicodeCheck != nullptr && m_environmentUnicodeCheck->isChecked());
    if (request.useEnvironment && m_environmentEditor != nullptr)
    {
        // lpEnvironment 语义：
        // - 勾选并填写至少一行 KEY=VALUE 时，后端按 Unicode/ANSI 选项构造环境块；
        // - 勾选但内容为空时，仍按 UI 提示传 nullptr，表示继承父进程环境；
        // - 这样避免把空编辑器误转成“空环境块”，导致子进程缺失 PATH 等基础变量。
        const QStringList envLines = m_environmentEditor->toPlainText().split('\n');
        for (const QString& lineText : envLines)
        {
            const QString trimmedText = lineText.trimmed();
            if (!trimmedText.isEmpty())
            {
                request.environmentEntries.push_back(trimmedText.toStdString());
            }
        }
        if (request.environmentEntries.empty())
        {
            request.useEnvironment = false;
        }
    }

    request.inheritHandles = (m_inheritHandleCheck != nullptr && m_inheritHandleCheck->isChecked());

    bool parseOk = false;
    request.creationFlags = parseUInt32WithDefault(
        m_creationFlagsEdit != nullptr ? m_creationFlagsEdit->text() : QString(),
        0,
        &parseOk);
    if (!parseOk)
    {
        failBuild("dwCreationFlags 解析失败，请输入十进制或 0x 十六进制。");
        return request;
    }
    // CREATE_UNICODE_ENVIRONMENT 既能由专用复选框表达，也能由 dwCreationFlags 位标志区手工组合。
    // 这里以最终 flags 为准反向合并，防止 UI flags 中已有 Unicode 位但环境块按 ANSI 构造。
    if ((request.creationFlags & 0x00000400U) != 0U)
    {
        request.environmentUnicode = true;
    }

    request.processAttributes.useValue = (m_useProcessSecurityCheck != nullptr && m_useProcessSecurityCheck->isChecked());
    if (request.processAttributes.useValue)
    {
        request.processAttributes.nLength = parseUInt32WithDefault(
            m_processSecurityLengthEdit != nullptr ? m_processSecurityLengthEdit->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            failBuild("Process SECURITY_ATTRIBUTES.nLength 解析失败。");
            return request;
        }
        request.processAttributes.securityDescriptor = parseUInt64WithDefault(
            m_processSecurityDescriptorEdit != nullptr ? m_processSecurityDescriptorEdit->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            failBuild("Process SECURITY_ATTRIBUTES.lpSecurityDescriptor 解析失败。");
            return request;
        }
        request.processAttributes.inheritHandle = (m_processSecurityInheritCheck != nullptr && m_processSecurityInheritCheck->isChecked());
    }

    request.threadAttributes.useValue = (m_useThreadSecurityCheck != nullptr && m_useThreadSecurityCheck->isChecked());
    if (request.threadAttributes.useValue)
    {
        request.threadAttributes.nLength = parseUInt32WithDefault(
            m_threadSecurityLengthEdit != nullptr ? m_threadSecurityLengthEdit->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            failBuild("Thread SECURITY_ATTRIBUTES.nLength 解析失败。");
            return request;
        }
        request.threadAttributes.securityDescriptor = parseUInt64WithDefault(
            m_threadSecurityDescriptorEdit != nullptr ? m_threadSecurityDescriptorEdit->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            failBuild("Thread SECURITY_ATTRIBUTES.lpSecurityDescriptor 解析失败。");
            return request;
        }
        request.threadAttributes.inheritHandle = (m_threadSecurityInheritCheck != nullptr && m_threadSecurityInheritCheck->isChecked());
    }

    request.startupInfo.useValue = (m_useStartupInfoCheck != nullptr && m_useStartupInfoCheck->isChecked());
    if (request.startupInfo.useValue)
    {
        request.startupInfo.cb = parseUInt32WithDefault(m_siCbEdit != nullptr ? m_siCbEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.cb 解析失败。"); return request; }
        request.startupInfo.lpReserved = (m_siReservedEdit != nullptr ? m_siReservedEdit->text() : QString()).toStdString();
        request.startupInfo.lpDesktop = (m_siDesktopEdit != nullptr ? m_siDesktopEdit->text() : QString()).toStdString();
        request.startupInfo.lpTitle = (m_siTitleEdit != nullptr ? m_siTitleEdit->text() : QString()).toStdString();
        request.startupInfo.dwX = parseUInt32WithDefault(m_siXEdit != nullptr ? m_siXEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.dwX 解析失败。"); return request; }
        request.startupInfo.dwY = parseUInt32WithDefault(m_siYEdit != nullptr ? m_siYEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.dwY 解析失败。"); return request; }
        request.startupInfo.dwXSize = parseUInt32WithDefault(m_siXSizeEdit != nullptr ? m_siXSizeEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.dwXSize 解析失败。"); return request; }
        request.startupInfo.dwYSize = parseUInt32WithDefault(m_siYSizeEdit != nullptr ? m_siYSizeEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.dwYSize 解析失败。"); return request; }
        request.startupInfo.dwXCountChars = parseUInt32WithDefault(m_siXCountCharsEdit != nullptr ? m_siXCountCharsEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.dwXCountChars 解析失败。"); return request; }
        request.startupInfo.dwYCountChars = parseUInt32WithDefault(m_siYCountCharsEdit != nullptr ? m_siYCountCharsEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.dwYCountChars 解析失败。"); return request; }
        request.startupInfo.dwFillAttribute = parseUInt32WithDefault(m_siFillAttributeEdit != nullptr ? m_siFillAttributeEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.dwFillAttribute 解析失败。"); return request; }
        request.startupInfo.dwFlags = parseUInt32WithDefault(m_siFlagsEdit != nullptr ? m_siFlagsEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.dwFlags 解析失败。"); return request; }
        request.startupInfo.wShowWindow = static_cast<std::uint16_t>(
            parseUInt32WithDefault(m_siShowWindowEdit != nullptr ? m_siShowWindowEdit->text() : QString(), 0, &parseOk));
        if (!parseOk) { failBuild("STARTUPINFO.wShowWindow 解析失败。"); return request; }
        request.startupInfo.cbReserved2 = static_cast<std::uint16_t>(
            parseUInt32WithDefault(m_siCbReserved2Edit != nullptr ? m_siCbReserved2Edit->text() : QString(), 0, &parseOk));
        if (!parseOk) { failBuild("STARTUPINFO.cbReserved2 解析失败。"); return request; }
        request.startupInfo.lpReserved2 = parseUInt64WithDefault(m_siReserved2PtrEdit != nullptr ? m_siReserved2PtrEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.lpReserved2 解析失败。"); return request; }
        request.startupInfo.hStdInput = parseUInt64WithDefault(m_siStdInputEdit != nullptr ? m_siStdInputEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.hStdInput 解析失败。"); return request; }
        request.startupInfo.hStdOutput = parseUInt64WithDefault(m_siStdOutputEdit != nullptr ? m_siStdOutputEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.hStdOutput 解析失败。"); return request; }
        request.startupInfo.hStdError = parseUInt64WithDefault(m_siStdErrorEdit != nullptr ? m_siStdErrorEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("STARTUPINFO.hStdError 解析失败。"); return request; }
    }

    request.processInfo.useValue = (m_useProcessInfoCheck != nullptr && m_useProcessInfoCheck->isChecked());
    if (request.processInfo.useValue)
    {
        request.processInfo.hProcess = parseUInt64WithDefault(m_piProcessHandleEdit != nullptr ? m_piProcessHandleEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("PROCESS_INFORMATION.hProcess 解析失败。"); return request; }
        request.processInfo.hThread = parseUInt64WithDefault(m_piThreadHandleEdit != nullptr ? m_piThreadHandleEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("PROCESS_INFORMATION.hThread 解析失败。"); return request; }
        request.processInfo.dwProcessId = parseUInt32WithDefault(m_piPidEdit != nullptr ? m_piPidEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("PROCESS_INFORMATION.dwProcessId 解析失败。"); return request; }
        request.processInfo.dwThreadId = parseUInt32WithDefault(m_piTidEdit != nullptr ? m_piTidEdit->text() : QString(), 0, &parseOk);
        if (!parseOk) { failBuild("PROCESS_INFORMATION.dwThreadId 解析失败。"); return request; }
    }

    request.tokenModeEnabled = (m_createMethodCombo != nullptr && m_createMethodCombo->currentIndex() == 1);
    if (request.tokenModeEnabled)
    {
        request.tokenSourcePid = parseUInt32WithDefault(
            m_tokenSourcePidEdit != nullptr ? m_tokenSourcePidEdit->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            failBuild("Token 模式 source PID 解析失败。");
            return request;
        }
        request.tokenDesiredAccess = parseUInt32WithDefault(
            m_tokenDesiredAccessEdit != nullptr ? m_tokenDesiredAccessEdit->text() : QString(),
            0,
            &parseOk);
        if (!parseOk)
        {
            failBuild("Token 模式 desired access 解析失败。");
            return request;
        }
        request.duplicatePrimaryToken = (m_tokenDuplicatePrimaryCheck != nullptr && m_tokenDuplicatePrimaryCheck->isChecked());

        if (m_tokenPrivilegeTable != nullptr)
        {
            for (int row = 0; row < m_tokenPrivilegeTable->rowCount(); ++row)
            {
                QTableWidgetItem* privilegeItem = m_tokenPrivilegeTable->item(row, 0);
                QComboBox* actionCombo = qobject_cast<QComboBox*>(m_tokenPrivilegeTable->cellWidget(row, 1));
                if (privilegeItem == nullptr || actionCombo == nullptr)
                {
                    continue;
                }

                const auto actionValue = static_cast<ks::process::TokenPrivilegeAction>(
                    actionCombo->currentData().toInt());
                if (actionValue == ks::process::TokenPrivilegeAction::Keep)
                {
                    continue;
                }

                ks::process::TokenPrivilegeEdit editItem{};
                editItem.privilegeName = privilegeItem->text().trimmed().toStdString();
                editItem.action = actionValue;
                request.tokenPrivilegeEdits.push_back(std::move(editItem));
            }
        }
    }

    if (buildOk != nullptr)
    {
        *buildOk = true;
    }
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    return request;
}

bool ProcessDock::buildTokenPrivilegeEditRequestFromUi(
    ks::process::CreateProcessRequest* const requestOut,
    QString* const errorTextOut) const
{
    // 仅应用令牌调整时不需要 CreateProcessW 的路径、环境、STARTUPINFO 等参数。
    // 输入：requestOut 接收 Token 字段；errorTextOut 接收解析失败原因。
    // 处理：只校验 Token 模式、source PID、DesiredAccess 和特权表动作。
    // 返回：true 表示可调用 ApplyTokenPrivilegeEditsByPid；false 表示 UI 参数不满足调权要求。
    if (requestOut == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = "内部错误：requestOut 为空。";
        }
        return false;
    }

    ks::process::CreateProcessRequest request;
    request.tokenModeEnabled = (m_createMethodCombo != nullptr && m_createMethodCombo->currentIndex() == 1);
    if (!request.tokenModeEnabled)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = "当前不是 Token 模式，无法仅应用令牌调整。";
        }
        return false;
    }

    bool parseOk = false;
    request.tokenSourcePid = parseUInt32WithDefault(
        m_tokenSourcePidEdit != nullptr ? m_tokenSourcePidEdit->text() : QString(),
        0,
        &parseOk);
    if (!parseOk)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = "Token 模式 source PID 解析失败。";
        }
        return false;
    }

    request.tokenDesiredAccess = parseUInt32WithDefault(
        m_tokenDesiredAccessEdit != nullptr ? m_tokenDesiredAccessEdit->text() : QString(),
        0,
        &parseOk);
    if (!parseOk)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = "Token 模式 desired access 解析失败。";
        }
        return false;
    }

    request.duplicatePrimaryToken = (m_tokenDuplicatePrimaryCheck != nullptr && m_tokenDuplicatePrimaryCheck->isChecked());
    if (m_tokenPrivilegeTable != nullptr)
    {
        for (int row = 0; row < m_tokenPrivilegeTable->rowCount(); ++row)
        {
            QTableWidgetItem* privilegeItem = m_tokenPrivilegeTable->item(row, 0);
            QComboBox* actionCombo = qobject_cast<QComboBox*>(m_tokenPrivilegeTable->cellWidget(row, 1));
            if (privilegeItem == nullptr || actionCombo == nullptr)
            {
                continue;
            }

            const auto actionValue = static_cast<ks::process::TokenPrivilegeAction>(
                actionCombo->currentData().toInt());
            if (actionValue == ks::process::TokenPrivilegeAction::Keep)
            {
                continue;
            }

            ks::process::TokenPrivilegeEdit editItem{};
            editItem.privilegeName = privilegeItem->text().trimmed().toStdString();
            editItem.action = actionValue;
            request.tokenPrivilegeEdits.push_back(std::move(editItem));
        }
    }

    *requestOut = std::move(request);
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    return true;
}

void ProcessDock::executeApplyTokenPrivilegeEditsOnly()
{
    // 令牌调整动作日志：整段流程复用同一个 kLogEvent，避免离散调用链。
    kLogEvent actionEvent;
    QString errorText;
    ks::process::CreateProcessRequest request;
    if (!buildTokenPrivilegeEditRequestFromUi(&request, &errorText))
    {
        appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("参数解析失败: ")) + errorText);
        err << actionEvent
            << "[ProcessDock] 令牌调整参数解析失败, error="
            << errorText.toStdString()
            << eol;
        return;
    }

    std::string detailText;
    const bool adjustOk = ks::process::ApplyTokenPrivilegeEditsByPid(
        request.tokenSourcePid,
        request.tokenDesiredAccess,
        request.duplicatePrimaryToken,
        request.tokenPrivilegeEdits,
        &detailText);
    std::ostringstream desiredAccessStream;
    desiredAccessStream << "0x" << std::uppercase << std::hex << request.tokenDesiredAccess;

    appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("令牌调整结果: %1")).arg(
        ks::i18n::sourceText(adjustOk ? QStringLiteral("成功") : QStringLiteral("失败"))));
    appendCreateResultLine(detailText.empty()
        ? ks::i18n::sourceText(QStringLiteral("无附加信息"))
        : QString::fromStdString(detailText));
    (adjustOk ? info : err) << actionEvent
        << "[ProcessDock] 令牌调整完成, ok=" << (adjustOk ? "true" : "false")
        << ", sourcePid=" << request.tokenSourcePid
        << ", desiredAccess=" << desiredAccessStream.str()
        << ", duplicatePrimary=" << (request.duplicatePrimaryToken ? "true" : "false")
        << ", editCount=" << request.tokenPrivilegeEdits.size()
        << ", detail=" << (detailText.empty() ? "无附加信息" : detailText)
        << eol;
}

void ProcessDock::executeCreateProcessRequest()
{
    // 创建进程动作日志：整段流程复用同一个 kLogEvent，避免离散调用链。
    kLogEvent createProcessEvent;
    bool buildOk = false;
    QString errorText;
    const ks::process::CreateProcessRequest request = buildCreateProcessRequestFromUi(&buildOk, &errorText);
    if (!buildOk)
    {
        appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("参数解析失败: ")) + errorText);
        err << createProcessEvent
            << "[ProcessDock] CreateProcess 参数解析失败, error="
            << errorText.toStdString()
            << eol;
        return;
    }

    ks::process::CreateProcessResult createResult{};
    const bool launchOk = ks::process::LaunchProcess(request, &createResult);
    appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("调用结果: %1")).arg(
        ks::i18n::sourceText(launchOk ? QStringLiteral("成功") : QStringLiteral("失败"))));
    appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("路径模式: %1")).arg(
        createResult.usedTokenPath ? QStringLiteral("Token") : QStringLiteral("CreateProcessW")));
    appendCreateResultLine(ks::i18n::sourceText(QStringLiteral("错误码: %1")).arg(createResult.win32Error));
    appendCreateResultLine(QString::fromStdString(createResult.detailText));
    if (createResult.processInfoAvailable)
    {
        appendCreateResultLine(
            ks::i18n::sourceText(QStringLiteral(
                "输出 PI: pid=%1 tid=%2（后端已关闭返回的 hProcess/hThread 句柄快照: 0x%3 / 0x%4）"))
            .arg(createResult.dwProcessId)
            .arg(createResult.dwThreadId)
            .arg(QString::number(createResult.hProcess, 16))
            .arg(QString::number(createResult.hThread, 16)));
    }

    (launchOk ? info : err) << createProcessEvent
        << "[ProcessDock] CreateProcess 请求完成, ok=" << (launchOk ? "true" : "false")
        << ", tokenMode=" << (request.tokenModeEnabled ? "true" : "false")
        << ", error=" << createResult.win32Error
        << ", detail=" << createResult.detailText
        << eol;

    if (launchOk)
    {
        requestAsyncRefresh(true);
    }
}

bool ProcessDock::isTreeModeEnabled() const
{
    // 勾选树状视图时按父子关系显示；点表头后内部可临时切为普通扁平枚举。
    return m_treeViewCheck != nullptr &&
        m_treeViewCheck->isChecked() &&
        !m_flatListForcedByHeaderSort;
}

bool ProcessDock::isFriendlyViewEnabled() const
{
    // 树状视图未勾选时，按应用/后台/系统分类显示。
    return m_treeViewCheck != nullptr && !m_treeViewCheck->isChecked();
}

ProcessDock::ViewMode ProcessDock::currentViewMode() const
{
    // 下拉项的 data 约定：>=0 表示内置预设的 ViewMode 值，<0 表示自定义视图。
    if (m_viewModeCombo == nullptr)
    {
        return ViewMode::Monitor;
    }

    bool parseOk = false;
    const int dataValue = m_viewModeCombo->currentData().toInt(&parseOk);
    if (!parseOk || dataValue < 0 || dataValue >= static_cast<int>(ViewMode::Count))
    {
        // 自定义视图没有对应的内置预设：按监视视图处理，
        // 它只用于“恢复默认列”和刷新预算判定，不影响自定义视图当前的列集合。
        return ViewMode::Monitor;
    }
    return static_cast<ViewMode>(dataValue);
}

int ProcessDock::currentCustomViewIndex() const
{
    if (m_viewModeCombo == nullptr)
    {
        return -1;
    }

    bool parseOk = false;
    const int dataValue = m_viewModeCombo->currentData().toInt(&parseOk);
    if (!parseOk || dataValue >= 0)
    {
        return -1;
    }

    const int customIndex = -dataValue - 1;
    return (customIndex < static_cast<int>(m_customViews.size())) ? customIndex : -1;
}

bool ProcessDock::isStaticDetailIntensiveViewActive() const
{
    // 输入：进程表当前的列显隐状态。
    // 处理：判断是否显示了需要逐进程打开句柄才能补齐的静态字段。
    // 返回：true 表示后台刷新应使用更高的静态详情预算并执行签名校验。
    // 这样做比把预算写死在“详细信息视图”上更准确：用户在监视视图里手动加上
    // 命令行或描述列时，同样需要这些字段被真正补齐。
    return isProcessColumnVisible(TableColumn::Signature) ||
        isProcessColumnVisible(TableColumn::Path) ||
        isProcessColumnVisible(TableColumn::CommandLine) ||
        isProcessColumnVisible(TableColumn::User) ||
        isProcessColumnVisible(TableColumn::Description) ||
        isProcessColumnVisible(TableColumn::Platform);
}

void ProcessDock::executeR0TerminateProcessAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0TerminateProcessAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    executeR0TerminateProcessActions(QStringLiteral("R0结束进程"), actionTargets);
}

void ProcessDock::executeR0TerminateProcessTreeAction()
{
    const std::vector<ProcessActionTarget> actionTargets = processTreeActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] executeR0TerminateProcessTreeAction 被忽略：选中进程未包含在当前 R3 快照中。"
            << eol;
        QMessageBox::information(
            this,
            processContextText("process.menu.r0_terminate_tree", QStringLiteral("R0结束进程树")),
            processContextText(
                "process.action.r0_terminate_tree.r3_snapshot_unavailable",
                QStringLiteral("当前选中进程未包含在 R3 进程快照中，无法识别进程树。")));
        return;
    }

    executeR0TerminateProcessActions(
        processContextText("process.menu.r0_terminate_tree", QStringLiteral("R0结束进程树")),
        actionTargets);
}

void ProcessDock::executeR0TerminateProcessActions(
    const QString& actionTitle,
    const std::vector<ProcessActionTarget>& actionTargets)
{
    QStringList targetPidList;
    for (const ProcessActionTarget& actionTarget : actionTargets)
    {
        targetPidList.push_back(QString::number(actionTarget.record.pid));
    }
    const QString targetDescription = ks::i18n::sourceText(
        QStringLiteral("%1 个进程；PID：%2"))
        .arg(actionTargets.size())
        .arg(targetPidList.join(QStringLiteral(", ")));
    if (!ks::ui::confirmDestructiveAction(
            this,
            QStringLiteral("process-termination-r0"),
            actionTitle,
            targetDescription,
            ks::i18n::sourceText(QStringLiteral(
                "R0 结束操作不可逆，可能造成数据丢失、系统不稳定或蓝屏。请确认目标无误后再继续。"))))
    {
        clearContextActionBinding();
        return;
    }

    dispatchProcessActionTargetsInParallel(
        actionTitle,
        actionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            // 每个动作目标都会单独调用 ArkDriverClient，形成独立的结束进程 IOCTL。
            return terminateProcessByR0Driver(
                actionTarget.record.pid,
                r0ActionExpectedCreationTime(actionTarget.record),
                detailTextOut);
        },
        true,
        false,
        true);
}

void ProcessDock::executeR0SuspendProcessAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0SuspendProcessAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("R0挂起进程"),
        actionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return suspendProcessByR0Driver(actionTarget.record.pid, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeR0SetProcessHiddenAction(
    const bool hidden,
    const unsigned long visibilityFlags)
{
    // 输入：hidden 指示隐藏/恢复方向，visibilityFlags 仅用于隐藏动作选择 R0 模式。
    // 处理：批量调用驱动 IOCTL，并在隐藏成功后打开内核对比与 Ksword 隐藏项显示。
    // 返回：无返回值；结果通过消息框、日志和异步刷新反馈给用户。
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0SetProcessHiddenAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    if (hidden)
    {
        const bool patchPid =
            ((visibilityFlags & KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID) != 0UL);
        const bool unlinkList =
            ((visibilityFlags & KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST) != 0UL);
        QString modeText;
        QString riskText;
        if (patchPid && unlinkList)
        {
            modeText = QStringLiteral("改 PID + 断链（旧版双操作）");
            riskText = QStringLiteral("风险：最高；可能导致按原 PID 查找困难，退出路径也更敏感。");
        }
        else if (patchPid)
        {
            modeText = QStringLiteral("只改 PID");
            riskText = QStringLiteral("风险：高；目标仍在活动链表中，但按原 PID 查找可能失效。");
        }
        else
        {
            modeText = QStringLiteral("只断链");
            riskText = QStringLiteral("风险：相对低于改 PID；不改 UniqueProcessId，Ksword 更容易按原 PID 找回。");
        }

        const QMessageBox::StandardButton choice = QMessageBox::warning(
            this,
            QStringLiteral("R0进程隐藏(可恢复)"),
            QStringLiteral(
                "将把选中的 %1 个进程写入 Ksword 驱动隐藏表。\n\n"
                "模式：%2\n"
                "%3\n\n"
                "说明：驱动只保存 Ksword 本次修改过的字段；取消隐藏/清空时按记录恢复。")
                .arg(actionTargets.size())
                .arg(modeText)
                .arg(riskText),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (choice != QMessageBox::Yes)
        {
            return;
        }
    }

    std::size_t successCount = 0U;
    std::size_t failureCount = 0U;
    QStringList detailLines;
    const unsigned long action = hidden
        ? KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE
        : KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE;

    for (const ProcessActionTarget& actionTarget : actionTargets)
    {
        std::string detailText;
        const bool actionOk = setProcessVisibilityByR0Driver(
            actionTarget.record.pid,
            action,
            hidden ? visibilityFlags : 0UL,
            &detailText);
        if (actionOk)
        {
            ++successCount;
            if (hidden)
            {
                m_hiddenProcessPidSet.insert(actionTarget.record.pid);
            }
            else
            {
                m_hiddenProcessPidSet.erase(actionTarget.record.pid);
            }
        }
        else
        {
            ++failureCount;
        }
        detailLines.push_back(QStringLiteral("PID=%1 %2 | %3")
            .arg(actionTarget.record.pid)
            .arg(actionOk ? QStringLiteral("OK") : QStringLiteral("FAIL"))
            .arg(QString::fromStdString(detailText.empty() ? std::string("无附加信息") : detailText)));
    }

    const QString titleText = hidden
        ? QStringLiteral("R0隐藏进程")
        : QStringLiteral("R0取消隐藏进程");
    const QString summaryText = QStringLiteral("%1 完成：成功 %2，失败 %3\n\n%4")
        .arg(titleText)
        .arg(successCount)
        .arg(failureCount)
        .arg(detailLines.join(QLatin1Char('\n')));

    kLogEvent logEvent;
    (failureCount == 0U ? info : warn) << logEvent
        << "[ProcessDock] " << titleText.toStdString()
        << " completed, success=" << successCount
        << ", failure=" << failureCount
        << eol;
    showActionResultMessage(titleText, failureCount == 0U, summaryText.toStdString(), logEvent);
    requestAsyncRefresh(true);
}

void ProcessDock::executeR0ClearProcessHiddenAction()
{
    const QMessageBox::StandardButton choice = QMessageBox::question(
        this,
        QStringLiteral("清空R0隐藏标记"),
        QStringLiteral("确定清空 Ksword 驱动内全部可恢复进程隐藏标记吗？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (choice != QMessageBox::Yes)
    {
        return;
    }

    std::string detailText;
    const bool actionOk = setProcessVisibilityByR0Driver(
        0U,
        KSWORD_ARK_PROCESS_VISIBILITY_ACTION_CLEAR_ALL,
        0UL,
        &detailText);
    if (actionOk)
    {
        m_hiddenProcessPidSet.clear();
    }

    kLogEvent logEvent;
    (actionOk ? info : warn) << logEvent
        << "[ProcessDock] 清空R0隐藏标记完成, ok="
        << (actionOk ? "true" : "false")
        << ", detail=" << (detailText.empty() ? "无附加信息" : detailText)
        << eol;
    showActionResultMessage(
        QStringLiteral("清空R0隐藏标记"),
        actionOk,
        detailText.empty() ? std::string("无附加信息") : detailText,
        logEvent);
    requestAsyncRefresh(true);
}

void ProcessDock::executeR0SetBreakOnTerminationAction(const bool enabled)
{
    // BreakOnTermination：
    // - R0 侧使用 ZwSetInformationProcess，不直接硬编码 EPROCESS.Flags；
    // - 批量目标逐个分发，失败详情写入统一动作日志。
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0SetBreakOnTerminationAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const QMessageBox::StandardButton choice = QMessageBox::warning(
        this,
        enabled ? QStringLiteral("启用 BreakOnTermination") : QStringLiteral("关闭 BreakOnTermination"),
        enabled
        ? QStringLiteral("将把选中的 %1 个进程设为关键进程。目标退出可能触发系统崩溃保护。是否继续？").arg(actionTargets.size())
        : QStringLiteral("将清除选中 %1 个进程的 BreakOnTermination。是否继续？").arg(actionTargets.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (choice != QMessageBox::Yes)
    {
        return;
    }

    const unsigned long action = enabled
        ? KSWORD_ARK_PROCESS_SPECIAL_ACTION_ENABLE_BREAK_ON_TERMINATION
        : KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_BREAK_ON_TERMINATION;
    dispatchProcessActionTargetsInParallel(
        enabled ? QStringLiteral("R0启用BreakOnTermination") : QStringLiteral("R0关闭BreakOnTermination"),
        actionTargets,
        [action](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return setProcessSpecialFlagsByR0Driver(
                actionTarget.record.pid,
                action,
                r0ActionExpectedCreationTime(actionTarget.record),
                detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeR0DisableApcInsertionAction()
{
    // 禁 APC 插入：
    // - R0 侧只处理当前已有线程的 ApcQueueable 位；
    // - 新创建线程不在本次结果范围内，因此提示中明确边界。
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0DisableApcInsertionAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const QMessageBox::StandardButton choice = QMessageBox::warning(
        this,
        QStringLiteral("禁止APC插入"),
        QStringLiteral(
            "将清除选中 %1 个进程当前线程的 ApcQueueable 位。\n\n"
            "说明：该动作影响现有线程；目标后续新建线程不自动覆盖。错误线程偏移可能导致系统不稳定。是否继续？")
            .arg(actionTargets.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (choice != QMessageBox::Yes)
    {
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("R0禁止APC插入"),
        actionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return setProcessSpecialFlagsByR0Driver(
                actionTarget.record.pid,
                KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_APC_INSERTION,
                r0ActionExpectedCreationTime(actionTarget.record),
                detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeR0DkomRemoveFromCidTableAction()
{
    // PspCidTable DKOM：
    // - 目标对象由 R0 根据 PID 引用；
    // - UI 不传 EPROCESS 地址；
    // - 删除后 PsLookupProcessByProcessId 可能无法再找到目标，需刷新列表。
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0DkomRemoveFromCidTableAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const QMessageBox::StandardButton choice = QMessageBox::critical(
        this,
        QStringLiteral("DKOM从PspCidTable删除"),
        QStringLiteral(
            "将从 PspCidTable 删除选中 %1 个进程的 CID 表项。\n\n"
            "风险：该动作不可通过当前菜单恢复，可能破坏句柄/PID 查询语义，错误系统版本或竞态会导致蓝屏。是否继续？")
            .arg(actionTargets.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (choice != QMessageBox::Yes)
    {
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("R0 DKOM PspCidTable删除"),
        actionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return dkomProcessByR0Driver(
                actionTarget.record.pid,
                KSWORD_ARK_PROCESS_DKOM_ACTION_REMOVE_FROM_PSP_CID_TABLE,
                detailTextOut);
        },
        false,
        false,
        true);
    requestAsyncRefresh(true);
}

void ProcessDock::executeR0SetPplProtectionAction(
    const std::uint8_t protectionLevel,
    const QString& levelDisplayText)
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeR0SetPplProtectionAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const ks::process::ProcessRecord& primaryRecord = actionTargets.front().record;
    const std::uint32_t targetPid = primaryRecord.pid;
    std::uint8_t targetSignatureLevel = 0U;
    std::uint8_t targetSectionSignatureLevel = 0U;
    const bool signaturePredictionOk = resolvePplSignatureLevelsForUi(
        protectionLevel,
        &targetSignatureLevel,
        &targetSectionSignatureLevel);
    const QString currentProtectionText =
        ((primaryRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) != 0U)
        ? byteHexText(primaryRecord.r0Protection)
        : QStringLiteral("Unavailable");
    const QString currentSignatureText =
        ((primaryRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SIGNATURE_LEVEL_PRESENT) != 0U)
        ? byteHexText(primaryRecord.r0SignatureLevel)
        : QStringLiteral("Unavailable");
    const QString currentSectionSignatureText =
        ((primaryRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_SIGNATURE_LEVEL_PRESENT) != 0U)
        ? byteHexText(primaryRecord.r0SectionSignatureLevel)
        : QStringLiteral("Unavailable");
    const QString targetSignatureText = signaturePredictionOk
        ? byteHexText(targetSignatureLevel)
        : QStringLiteral("Unknown");
    const QString targetSectionSignatureText = signaturePredictionOk
        ? byteHexText(targetSectionSignatureLevel)
        : QStringLiteral("Unknown");
    const QString confirmationText = QStringLiteral(
        "将通过 R0 驱动修改目标进程 PPL/PP（EPROCESS.Protection）字段。\n\n"
        "进程: %1 (PID %2)%12\n"
        "当前 Protection: %3  来源: %4\n"
        "目标 Protection: %5  菜单: %6\n\n"
        "SignatureLevel 影响:\n"
        "  当前 SignatureLevel: %7 -> 目标: %8\n"
        "  当前 SectionSignatureLevel: %9 -> 目标: %10\n\n"
        "%11\n\n"
        "风险: 该动作会直接写 EPROCESS.Protection/SignatureLevel/SectionSignatureLevel。"
        "错误的 DynData 偏移、系统版本差异或目标进程状态变化可能导致回滚失败、访问异常或系统不稳定。"
        "继续前请确认已保存当前字段值用于手工回滚。")
        .arg(QString::fromStdString(primaryRecord.processName.empty() ? std::string("Unknown") : primaryRecord.processName))
        .arg(targetPid)
        .arg(currentProtectionText)
        .arg(processFieldSourceText(primaryRecord.r0ProtectionSource))
        .arg(byteHexText(protectionLevel))
        .arg(levelDisplayText)
        .arg(currentSignatureText)
        .arg(targetSignatureText)
        .arg(currentSectionSignatureText)
        .arg(targetSectionSignatureText)
        .arg(pplMutationCapabilityText(primaryRecord))
        .arg(actionTargets.size() > 1U ? QStringLiteral("\n批量目标数: %1，确认后每个进程会独立线程执行。").arg(actionTargets.size()) : QString());

    const QMessageBox::StandardButton confirmationButton = QMessageBox::warning(
        this,
        QStringLiteral("确认 R0 设置 PPL 层级"),
        confirmationText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmationButton != QMessageBox::Yes)
    {
        kLogEvent cancelEvent;
        warn << cancelEvent
            << "[ProcessDock] R0 set PPL action cancelled by user, pid="
            << targetPid
            << ", protectionLevel=0x"
            << std::hex
            << std::uppercase
            << static_cast<unsigned int>(protectionLevel)
            << std::dec
            << eol;
        return;
    }

    const QString actionTitle = QStringLiteral("R0设置进程保护层级(%1)").arg(levelDisplayText);
    dispatchProcessActionTargetsInParallel(
        actionTitle,
        actionTargets,
        [protectionLevel](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return setPplProtectionLevelByR0Driver(actionTarget.record.pid, protectionLevel, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeRefreshPplProtectionLevelAction()
{
    // 该动作只刷新用户选中的当前快照字段，不触发完整进程枚举。
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] PPL 保护级别刷新被忽略：当前没有选中进程。" << eol;
        return;
    }

    std::size_t successCount = 0;
    std::size_t failureCount = 0;
    QStringList resultLineList;
    resultLineList.reserve(static_cast<qsizetype>(actionTargets.size()));

    // 每个目标独立调用 GetProcessInformation，避免 PPL 列依赖旧缓存。
    for (const ProcessActionTarget& actionTarget : actionTargets)
    {
        auto cacheIt = m_cacheByIdentity.find(actionTarget.identityKey);
        if (cacheIt == m_cacheByIdentity.end())
        {
            ++failureCount;
            resultLineList.push_back(QStringLiteral("PID %1: cache missing")
                .arg(actionTarget.record.pid));
            continue;
        }

        HANDLE processHandle = nullptr;
        std::string identityDetail;
        if (!acquireProcessActionIdentityHold(
                actionTarget.record.pid,
                actionTarget.record.creationTime100ns,
                &processHandle,
                &identityDetail))
        {
            ++failureCount;
            resultLineList.push_back(QStringLiteral("PID %1: %2")
                .arg(actionTarget.record.pid)
                .arg(QString::fromStdString(identityDetail)));
            continue;
        }
        const ScopedProcessActionHandle identityHold(processHandle);

        std::uint32_t protectionLevelValue = 0;
        std::string protectionLevelText;
        std::string errorText;
        const bool queryOk = ks::process::QueryProcessProtectionLevelByPid(
            actionTarget.record.pid,
            &protectionLevelValue,
            &protectionLevelText,
            &errorText);
        if (queryOk)
        {
            cacheIt->second.record.protectionLevelKnown = true;
            cacheIt->second.record.protectionLevel = protectionLevelValue;
            cacheIt->second.record.protectionLevelText = protectionLevelText;
            ++successCount;
            resultLineList.push_back(QStringLiteral("PID %1: %2")
                .arg(actionTarget.record.pid)
                .arg(QString::fromStdString(protectionLevelText)));
        }
        else
        {
            cacheIt->second.record.protectionLevelKnown = true;
            cacheIt->second.record.protectionLevel = 0;
            cacheIt->second.record.protectionLevelText = errorText.empty()
                ? std::string("Query failed")
                : std::string("Query failed: ") + errorText;
            ++failureCount;
            resultLineList.push_back(QStringLiteral("PID %1: %2")
                .arg(actionTarget.record.pid)
                .arg(QString::fromStdString(cacheIt->second.record.protectionLevelText)));
        }
    }

    rebuildTable();
    kLogEvent actionEvent;
    (failureCount == 0 ? info : warn) << actionEvent
        << "[ProcessDock] PPL 保护级别手动刷新完成, targets=" << actionTargets.size()
        << ", success=" << successCount
        << ", failure=" << failureCount
        << ", detail=" << resultLineList.join(" | ").toStdString()
        << eol;
}

void ProcessDock::executeTerminateProcessAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeTerminateProcessAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    executeTerminateProcessActions(QStringLiteral("结束进程"), actionTargets);
}

void ProcessDock::executeTerminateAndDeleteImageAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.size() != 1U ||
        actionTargets.front().record.pid == 0U ||
        actionTargets.front().record.creationTime100ns == 0U ||
        actionTargets.front().record.imagePath.empty())
    {
        kLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] executeTerminateAndDeleteImageAction 被拒绝："
            << "目标必须为一个具有创建时间和映像路径的进程。"
            << eol;
        clearContextActionBinding();
        return;
    }

    executeTerminateProcessActions(
        processContextText(
            "process.menu.terminate_delete_image",
            QStringLiteral("结束进程并删除映像文件")),
        actionTargets,
        true);
}

void ProcessDock::executeTerminateProcessTreeAction()
{
    const std::vector<ProcessActionTarget> actionTargets = processTreeActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] executeTerminateProcessTreeAction 被忽略：选中进程未包含在当前 R3 快照中。"
            << eol;
        QMessageBox::information(
            this,
            processContextText("process.menu.terminate_tree", QStringLiteral("结束进程树")),
            processContextText(
                "process.action.terminate_tree.r3_snapshot_unavailable",
                QStringLiteral("当前选中进程未包含在 R3 进程快照中，无法识别进程树。")));
        return;
    }

    executeTerminateProcessActions(
        processContextText("process.menu.terminate_tree", QStringLiteral("结束进程树")),
        actionTargets);
}

void ProcessDock::executeTerminateProcessActions(
    const QString& actionTitle,
    const std::vector<ProcessActionTarget>& actionTargets,
    const bool deleteImageAfterExit)
{
    QStringList targetPidList;
    for (const ProcessActionTarget& actionTarget : actionTargets)
    {
        targetPidList.push_back(QString::number(actionTarget.record.pid));
    }
    QString targetDescription = ks::i18n::sourceText(
        QStringLiteral("%1 个进程；PID：%2"))
        .arg(actionTargets.size())
        .arg(targetPidList.join(QStringLiteral(", ")));
    QString suppressionKey = QStringLiteral("process-termination-r3");
    QString riskDescription;
    if (deleteImageAfterExit)
    {
        if (actionTargets.size() != 1U)
        {
            clearContextActionBinding();
            return;
        }
        const ProcessActionTarget& deleteTarget = actionTargets.front();
        const QString imagePath = QString::fromStdString(deleteTarget.record.imagePath);
        targetDescription = processContextText(
            "process.action.terminate_delete_image.target",
            QStringLiteral("PID：%1\n映像：%2"))
            .arg(deleteTarget.record.pid)
            .arg(imagePath);
        riskDescription = processContextText(
            "process.action.terminate_delete_image.risk",
            QStringLiteral(
                "该操作不可撤销。KSword 将先校验 PID 创建时间和文件 ID，"
                "锁定当前映像文件对象，结束并确认原进程退出后永久删除该文件。"
                "若目标是系统或关键进程，可能立即崩溃、丢失数据或导致系统无法启动。"
                "KSword 只告知风险，不按进程类别限制该操作；"
                "若身份、路径或退出状态无法确认，则不会删除。"));
        // 永久文件删除不允许持久关闭确认提示，因此 suppressionKey 固定为空。
        suppressionKey.clear();
    }
    if (!ks::ui::confirmDestructiveAction(
            this,
            suppressionKey,
            actionTitle,
            targetDescription,
            riskDescription))
    {
        clearContextActionBinding();
        return;
    }

    if (deleteImageAfterExit)
    {
        // 最终确认改为直接点击：不再要求输入确认短语，改用默认聚焦“否”的高风险提示。
        const auto finalAnswer = QMessageBox::warning(
            this,
            processContextText(
                "process.action.terminate_delete_image.type_title",
                QStringLiteral("最终确认永久删除")),
            processContextText(
                "process.action.terminate_delete_image.final_prompt",
                QStringLiteral("确认结束进程 %1 并永久删除其映像文件？此操作不可撤销。"))
                .arg(actionTargets.front().record.pid),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (finalAnswer != QMessageBox::Yes)
        {
            kLogEvent cancellationEvent;
            warn << cancellationEvent
                << "[ProcessDock] 结束并删除映像动作已取消：用户在最终确认中选择了否。"
                << eol;
            clearContextActionBinding();
            return;
        }
    }

    dispatchProcessActionTargetsInParallel(
        actionTitle,
        actionTargets,
        [deleteImageAfterExit](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            // targetPid 用途：固定本次动作的目标 PID，避免中途选中行变化影响执行对象。
            const std::uint32_t targetPid = actionTarget.record.pid;
            // 单目标动作统一复用 actionEvent，保证同一调用链日志 GUID 一致。
            kLogEvent actionEvent;
            info << actionEvent
                << "[ProcessDock] 开始执行结束进程组合动作, pid=" << targetPid
                << eol;

            // 删除模式必须在任何结束方法执行前锁定精确文件对象；失败时不执行结束，
            // 防止出现“进程已结束但删除目标身份无法验证”的半完成动作。
            ks::process::CapturedProcessImageDeleteTarget capturedImageTarget;
            std::string imageCaptureDetail;
            if (deleteImageAfterExit)
            {
                const std::wstring expectedImagePath =
                    QString::fromStdString(actionTarget.record.imagePath).toStdWString();
                const bool captureOk = ks::process::CaptureProcessImageDeleteTarget(
                    targetPid,
                    actionTarget.record.creationTime100ns,
                    expectedImagePath,
                    &capturedImageTarget,
                    &imageCaptureDetail);
                if (!captureOk)
                {
                    err << actionEvent
                        << "[ProcessDock] 结束并删除映像前置身份锁定失败, pid="
                        << targetPid
                        << ", detail="
                        << imageCaptureDetail
                        << eol;
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = "文件身份锁定失败：" + imageCaptureDetail;
                    }
                    return false;
                }
            }

            // 先做一次进程存在性检查，避免对已退出 PID 执行无意义操作。
            bool initialQueryOk = false;
            bool processStillPresent = isProcessPresentBySnapshot(targetPid, &initialQueryOk);
            if (!initialQueryOk)
            {
                warn << actionEvent
                    << "[ProcessDock] 结束进程前置存在性检查失败，将按“进程仍存在”继续处理, pid="
                    << targetPid
                    << eol;
            }
            if (!processStillPresent)
            {
                info << actionEvent
                    << "[ProcessDock] 目标进程已不存在，结束动作直接判定成功, pid="
                    << targetPid
                    << eol;
                if (deleteImageAfterExit)
                {
                    std::string deletionDetail;
                    const bool deletionOk = ks::process::DeleteCapturedProcessImage(
                        &capturedImageTarget,
                        &deletionDetail);
                    (deletionOk ? info : err) << actionEvent
                        << "[ProcessDock] 原进程在文件身份锁定后退出，执行精确映像删除, pid="
                        << targetPid
                        << ", ok="
                        << (deletionOk ? "true" : "false")
                        << ", detail="
                        << deletionDetail
                        << eol;
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = "capture=" + imageCaptureDetail +
                            " | process=already exited | delete=" + deletionDetail;
                    }
                    return deletionOk;
                }
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = "目标进程已不存在，无需执行结束动作。";
                }
                return true;
            }

            // kTerminateRoundLimit 用途：限制“全方法链”轮次，避免异常目标导致无限阻塞 UI。
            constexpr int kTerminateRoundLimit = 2;
            // processExited 用途：记录组合动作最终是否确认目标进程已退出。
            bool processExited = false;
            // actionDetailStream 用途：汇总每一轮、每一方法的细节，供最终统一输出。
            std::ostringstream actionDetailStream;
            actionDetailStream << "pid=" << targetPid;
            if (deleteImageAfterExit)
            {
                actionDetailStream << " | capture=" << imageCaptureDetail;
            }

            // TerminateMethodEntry 作用：描述一个可执行的“结束进程原理方法”。
            struct TerminateMethodEntry
            {
                const char* methodName = nullptr; // methodName：日志中显示的方法名。
                std::function<bool(std::string*)> invokeMethod; // invokeMethod：方法调用体。
            };

            // terminateMethodList 作用：
            // - 维护“结束进程原理”的顺序清单；
            // - 每个进程的内部方法链保持顺序，但多个进程之间并行执行。
            const std::vector<TerminateMethodEntry> terminateMethodList =
            {
                { "TerminateProcess(Kernel32)", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByWin32(targetPid, detailOut); } },
                { "NtTerminateProcess/ZwTerminateProcess", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByNtNative(targetPid, detailOut); } },
                { "WTSTerminateProcess(WTS API)", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByWtsApi(targetPid, detailOut); } },
                { "WinStationTerminateProcess(winsta)", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByWinStationApi(targetPid, detailOut); } },
                { "TerminateJobObject(Job)", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByJobObject(targetPid, detailOut); } },
                { "NtTerminateJobObject/ZwTerminateJobObject", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByNtJobObject(targetPid, detailOut); } },
                { "RmShutdown(Restart Manager)", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByRestartManager(targetPid, false, detailOut); } },
                { "RmShutdown(Restart Manager, force)", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByRestartManager(targetPid, true, detailOut); } },
                { "DuplicateHandle(-1)+TerminateProcess", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByDuplicateHandlePseudo(targetPid, detailOut); } },
                { "TerminateThread(全部线程)", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateAllThreadsByPid(targetPid, detailOut); } },
                { "NtTerminateThread/ZwTerminateThread(全部线程)", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateAllThreadsByPidNtNative(targetPid, detailOut); } },
                { "DebugActiveProcess 调试附加", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByDebugAttach(targetPid, detailOut); } },
                { "ntsd -c q -p <pid>", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByNtsdCommand(targetPid, detailOut); } },
                { "NtUnmapViewOfSection 卸载 ntdll.dll", [targetPid](std::string* detailOut)
                    { return ks::process::TerminateProcessByNtUnmapNtdll(targetPid, detailOut); } }
            };

            for (int roundIndex = 0; roundIndex < kTerminateRoundLimit && !processExited; ++roundIndex)
            {
                // roundNumber 用途：日志中的轮次编号（从 1 开始，便于人工排查）。
                const int roundNumber = roundIndex + 1;

                for (std::size_t methodIndex = 0;
                    methodIndex < terminateMethodList.size() && !processExited;
                    ++methodIndex)
                {
                    const TerminateMethodEntry& methodEntry = terminateMethodList[methodIndex];
                    if (methodEntry.methodName == nullptr || !methodEntry.invokeMethod)
                    {
                        continue;
                    }

                    std::string methodDetailText;
                    const bool methodOk = methodEntry.invokeMethod(&methodDetailText);
                    const std::string normalizedMethodDetailText =
                        methodDetailText.empty() ? "无附加信息" : methodDetailText;
                    (methodOk ? info : err) << actionEvent
                        << "[ProcessDock] 结束进程组合动作-方法执行, pid="
                        << targetPid
                        << ", round="
                        << roundNumber
                        << ", method="
                        << methodEntry.methodName
                        << ", ok="
                        << (methodOk ? "true" : "false")
                        << ", detail="
                        << normalizedMethodDetailText
                        << eol;
                    if (!methodOk)
                    {
                        warn << actionEvent
                            << "[ProcessDock] 当前方法执行失败，继续尝试下一方法, pid="
                            << targetPid
                            << ", round="
                            << roundNumber
                            << ", method="
                            << methodEntry.methodName
                            << eol;
                    }

                    actionDetailStream
                        << " | round"
                        << roundNumber
                        << ":"
                        << methodEntry.methodName
                        << "="
                        << (methodOk ? "ok" : "fail")
                        << "("
                        << normalizedMethodDetailText
                        << ")";

                    bool queryProcessPresentOk = false;
                    bool pidWasReused = false;
                    if (deleteImageAfterExit)
                    {
                        std::uint64_t currentCreationTime100ns = 0U;
                        std::string identityDetail;
                        if (ks::process::QueryProcessCreationTimeByPid(
                                targetPid,
                                &currentCreationTime100ns,
                                &identityDetail))
                        {
                            queryProcessPresentOk = true;
                            processStillPresent =
                                currentCreationTime100ns == actionTarget.record.creationTime100ns;
                            pidWasReused = !processStillPresent;
                        }
                        else
                        {
                            // OpenProcess/GetProcessTimes 失败时退回系统快照；快照仍显示 PID
                            // 就按原进程存活处理，不以“无法验证”作为删除许可。
                            processStillPresent = isProcessPresentBySnapshot(
                                targetPid,
                                &queryProcessPresentOk);
                        }
                    }
                    else
                    {
                        processStillPresent = isProcessPresentBySnapshot(
                            targetPid,
                            &queryProcessPresentOk);
                    }
                    if (!queryProcessPresentOk)
                    {
                        warn << actionEvent
                            << "[ProcessDock] 方法执行后存在性检查失败，按“仍存活”继续尝试, pid="
                            << targetPid
                            << ", round="
                            << roundNumber
                            << ", method="
                            << methodEntry.methodName
                            << eol;
                    }
                    if (!processStillPresent)
                    {
                        processExited = true;
                        info << actionEvent
                            << "[ProcessDock] 目标进程已退出, pid="
                            << targetPid
                            << ", round="
                            << roundNumber
                            << ", method="
                            << methodEntry.methodName
                            << ", pidReused="
                            << (pidWasReused ? "true" : "false")
                            << eol;
                        break;
                    }
                }

                if (!processExited)
                {
                    warn << actionEvent
                        << "[ProcessDock] 本轮全方法链执行后目标仍存活，将进入下一轮, pid="
                        << targetPid
                        << ", round="
                        << roundNumber
                        << eol;
                }
            }

            if (!processExited)
            {
                err << actionEvent
                    << "[ProcessDock] 结束进程组合动作达到上限后目标仍存活, pid="
                    << targetPid
                    << ", roundLimit="
                    << kTerminateRoundLimit
                    << eol;
            }

            if (detailTextOut != nullptr)
            {
                *detailTextOut = actionDetailStream.str();
            }
            if (!processExited || !deleteImageAfterExit)
            {
                return processExited;
            }

            std::string deletionDetail;
            const bool deletionOk = ks::process::DeleteCapturedProcessImage(
                &capturedImageTarget,
                &deletionDetail);
            (deletionOk ? info : err) << actionEvent
                << "[ProcessDock] 目标进程退出后执行精确映像删除, pid="
                << targetPid
                << ", ok="
                << (deletionOk ? "true" : "false")
                << ", detail="
                << deletionDetail
                << eol;
            actionDetailStream << " | delete="
                << (deletionOk ? "ok" : "fail")
                << "("
                << deletionDetail
                << ")";
            if (detailTextOut != nullptr)
            {
                *detailTextOut = actionDetailStream.str();
            }
            return deletionOk;
        },
        true,
        true,
        true);
}

void ProcessDock::executeTerminateThreadsAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeTerminateThreadsAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("TerminateThread(全部线程)"),
        actionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::TerminateAllThreadsByPid(actionTarget.record.pid, detailTextOut);
        },
        true,
        false,
        true);
}

void ProcessDock::executeSuspendAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeSuspendAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("挂起进程"),
        actionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::SuspendProcessIfCreationTimeMatches(actionTarget.record.pid, actionTarget.record.creationTime100ns, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeResumeAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeResumeAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("恢复进程"),
        actionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::ResumeProcessIfCreationTimeMatches(actionTarget.record.pid, actionTarget.record.creationTime100ns, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeSetCriticalAction(const bool enableCritical)
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeSetCriticalAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        enableCritical ? QStringLiteral("设为关键进程") : QStringLiteral("取消关键进程"),
        actionTargets,
        [enableCritical](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::SetProcessCriticalFlag(actionTarget.record.pid, enableCritical, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeSetPriorityAction(const int priorityActionId)
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeSetPriorityAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    ks::process::ProcessPriorityLevel priorityLevel = ks::process::ProcessPriorityLevel::Normal;
    switch (priorityActionId)
    {
    case 0: priorityLevel = ks::process::ProcessPriorityLevel::Idle; break;
    case 1: priorityLevel = ks::process::ProcessPriorityLevel::BelowNormal; break;
    case 2: priorityLevel = ks::process::ProcessPriorityLevel::Normal; break;
    case 3: priorityLevel = ks::process::ProcessPriorityLevel::AboveNormal; break;
    case 4: priorityLevel = ks::process::ProcessPriorityLevel::High; break;
    case 5: priorityLevel = ks::process::ProcessPriorityLevel::Realtime; break;
    default: break;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("设置进程优先级"),
        actionTargets,
        [priorityLevel](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::SetProcessPriority(actionTarget.record.pid, priorityLevel, detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeSetProcessIntegrityAction(
    const unsigned long integrityRid,
    const QString& levelDisplayText)
{
    // 输入：完整性 RID 与菜单显示文本。
    // 处理：把选中进程快照交给统一批量执行器；每个目标先走 R0 内核 API，驱动不可用/旧驱动时回退 R3。
    // 返回：无返回值；成功/失败由 dispatchProcessActionTargetsInParallel 写入日志。
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeSetProcessIntegrityAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const DWORD targetIntegrityRid = static_cast<DWORD>(integrityRid);
    const QString actionTitle = QStringLiteral("设置进程完整性(%1)").arg(levelDisplayText);
    dispatchProcessActionTargetsInParallel(
        actionTitle,
        actionTargets,
        [targetIntegrityRid](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return setProcessIntegrityLevelByR0ThenR3(
                actionTarget.record.pid,
                targetIntegrityRid,
                detailTextOut);
        },
        false,
        false,
        true);
}

void ProcessDock::executeSetEfficiencyModeAction(const bool enableEfficiencyMode)
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeSetEfficiencyModeAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    const QString actionTitle =
        enableEfficiencyMode ? QStringLiteral("开启效率模式") : QStringLiteral("关闭效率模式");
    dispatchProcessActionTargetsInParallel(
        actionTitle,
        actionTargets,
        [enableEfficiencyMode](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::SetProcessEfficiencyMode(
                actionTarget.record.pid,
                enableEfficiencyMode,
                detailTextOut);
        },
        false,
        false,
        true);

    // UI 缓存即时更新：线程执行结果仍会独立记录；这里仅让已选行视觉状态快速响应。
    for (const ProcessActionTarget& actionTarget : actionTargets)
    {
        const auto cacheIt = m_cacheByIdentity.find(actionTarget.identityKey);
        if (cacheIt != m_cacheByIdentity.end())
        {
            cacheIt->second.record.efficiencyModeSupported = true;
            cacheIt->second.record.efficiencyModeEnabled = enableEfficiencyMode;
        }
    }
    if (m_processTable != nullptr)
    {
        m_processTable->viewport()->update();
    }
}

void ProcessDock::executeOpenFolderAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeOpenFolderAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("打开所在目录"),
        actionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::OpenProcessFolder(actionTarget.record.pid, detailTextOut);
        },
        false);
}

void ProcessDock::executeOpenMemoryOperationAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeOpenMemoryOperationAction 被忽略：当前没有选中进程。" << eol;
        return;
    }
    if (actionTargets.size() != 1U)
    {
        QMessageBox::information(this, QStringLiteral("跳转到内存"), QStringLiteral("内存操作一次只能附加一个进程，请仅选择一个进程。"));
        return;
    }

    const bool invokeOk = invokeMainWindowPidSlot("focusMemoryDockByPid", actionTargets.front().record.pid);
    if (!invokeOk)
    {
        kLogEvent actionEvent;
        showActionResultMessage(
            QStringLiteral("跳转到内存操作"),
            false,
            std::string("focusMemoryDockByPid invoke failed"),
            actionEvent);
    }
}

void ProcessDock::executeFocusHandleAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    QSet<quint32> seenPidSet;
    QStringList pidTextList;
    for (const ProcessActionTarget& target : actionTargets)
    {
        const quint32 processId = static_cast<quint32>(target.record.pid);
        if (processId != 0U && !seenPidSet.contains(processId))
        {
            seenPidSet.insert(processId);
            pidTextList.push_back(QString::number(processId));
        }
    }
    (void)invokeMainWindowPidListSlot("focusHandleDockByPids", pidTextList.join(','));
}

void ProcessDock::executeFocusNetworkAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    QSet<quint32> seenPidSet;
    QStringList pidTextList;
    for (const ProcessActionTarget& target : actionTargets)
    {
        const quint32 processId = static_cast<quint32>(target.record.pid);
        if (processId != 0U && !seenPidSet.contains(processId))
        {
            seenPidSet.insert(processId);
            pidTextList.push_back(QString::number(processId));
        }
    }
    (void)invokeMainWindowPidListSlot("focusNetworkDockByPids", pidTextList.join(','));
}

void ProcessDock::executeFocusWindowAction()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    QSet<quint32> seenPidSet;
    QStringList pidTextList;
    for (const ProcessActionTarget& target : actionTargets)
    {
        const quint32 processId = static_cast<quint32>(target.record.pid);
        if (processId != 0U && !seenPidSet.contains(processId))
        {
            seenPidSet.insert(processId);
            pidTextList.push_back(QString::number(processId));
        }
    }
    (void)invokeMainWindowPidListSlot("focusWindowDockByPids", pidTextList.join(','));
}

void ProcessDock::executeOpenMessageHooksAction(
    const ks::process::ProcessRecord& targetRecord)
{
    if (targetRecord.pid == 0U)
    {
        return;
    }

    // 使用右键菜单打开时冻结的进程快照，避免菜单关闭后选择变化导致查询错进程。
    ProcessMessageHookTarget target;
    target.processId = targetRecord.pid;
    target.sessionId = targetRecord.sessionId;
    target.creationTime100ns = targetRecord.creationTime100ns;
    target.processName = QString::fromStdString(targetRecord.processName);

    auto* hookWindow = new ProcessMessageHookWindow(target, nullptr);
    hookWindow->show();
    hookWindow->raise();
    hookWindow->activateWindow();

    kLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDock] open process message hooks window, pid="
        << target.processId
        << ", sessionId="
        << target.sessionId
        << eol;
}

void ProcessDock::requestOpenProcessDetailByPid(const std::uint32_t pid)
{
    // 对外统一入口：便于 FileDock/主窗口按 PID 打开进程详情。
    kLogEvent requestDetailEvent;
    info << requestDetailEvent
        << "[ProcessDock] requestOpenProcessDetailByPid: pid="
        << pid
        << eol;
    openProcessDetailWindowByPid(pid);
}

void ProcessDock::requestOpenProcessDetailByIdentity(
    const std::uint32_t pid,
    const std::uint64_t creationTime100ns)
{
    // requestDetailEvent：记录跨模块传入的完整历史 identity。
    kLogEvent requestDetailEvent;
    info << requestDetailEvent
        << "[ProcessDock] requestOpenProcessDetailByIdentity: pid="
        << pid
        << ", creationTime100ns="
        << creationTime100ns
        << eol;

    // rejectHistoricalTarget：统一记录并提示拒绝原因，不允许静默退化为纯 PID 跳转。
    const auto rejectHistoricalTarget = [this, pid](
        const QString& messageText,
        const std::string& diagnosticText)
    {
        // rejectEvent：串联本次历史跳转被拒绝的 PID 与底层诊断。
        kLogEvent rejectEvent;
        warn << rejectEvent
            << "[ProcessDock] historical process identity rejected, pid="
            << pid
            << ", detail="
            << diagnosticText
            << eol;
        QMessageBox::information(
            this,
            QStringLiteral("历史进程已退出"),
            messageText);
    };

    // identity 缺失本身即不可验证，必须拒绝而不是打开当前占用该 PID 的进程。
    if (pid == 0U || creationTime100ns == 0U)
    {
        rejectHistoricalTarget(
            QStringLiteral(
                "该历史记录缺少可验证的进程身份。为避免 PID 复用后打开无关进程，本次跳转已取消。"),
            "historical process identity is incomplete");
        return;
    }

    // currentCreationTime100ns：跳转瞬间重新读取当前 PID 的创建时间。
    std::uint64_t currentCreationTime100ns = 0U;

    // identityDetailText：接收 OpenProcess/GetProcessTimes 失败原因。
    std::string identityDetailText;

    // identityQueryOk：只有实时身份查询成功才能继续打开历史目标。
    const bool identityQueryOk = ks::process::QueryProcessCreationTimeByPid(
        pid,
        &currentCreationTime100ns,
        &identityDetailText);
    if (!identityQueryOk)
    {
        rejectHistoricalTarget(
            QStringLiteral(
                "该历史记录对应的原进程已退出，或当前无法验证其进程身份。"
                "为避免 PID 复用后打开无关进程，本次跳转已取消。"),
            identityDetailText.empty()
                ? std::string("current process identity is unavailable")
                : identityDetailText);
        return;
    }
    if (currentCreationTime100ns != creationTime100ns)
    {
        rejectHistoricalTarget(
            QStringLiteral(
                "该历史记录对应的原进程已退出，PID %1 已被其他进程复用。"
                "为避免打开无关进程，本次跳转已取消。").arg(pid),
            "process creation time mismatch");
        return;
    }

    // identityKey：严格定位缓存中的同一进程实例，不按 PID 取任意首项。
    const std::string identityKey = ks::process::BuildProcessIdentityKey(
        pid,
        creationTime100ns);

    // cachedEntryIt：若本轮缓存仍标记目标退出，则遵循历史状态拒绝打开。
    const auto cachedEntryIt = m_cacheByIdentity.find(identityKey);
    if (cachedEntryIt != m_cacheByIdentity.end())
    {
        if (cachedEntryIt->second.isExitedInLatestRound)
        {
            rejectHistoricalTarget(
                QStringLiteral(
                    "该历史记录对应的原进程已退出。为避免 PID 复用后打开无关进程，本次跳转已取消。"),
                "cached process record is marked exited");
            return;
        }
        if (!cachedEntryIt->second.isKernelOnlyInLatestRound)
        {
            showProcessDetailWindowForRecord(
                identityKey,
                cachedEntryIt->second.record);
            return;
        }
    }

    // queriedRecord：缓存未覆盖但实时 identity 匹配时构造轻量记录，详情页后台补齐字段。
    ks::process::ProcessRecord queriedRecord{};
    queriedRecord.pid = pid;
    queriedRecord.creationTime100ns = creationTime100ns;
    queriedRecord.processName = ks::process::GetProcessNameByPID(pid);
    if (queriedRecord.processName.empty())
    {
        queriedRecord.processName = "PID_" + std::to_string(pid);
    }
    showProcessDetailWindowForRecord(identityKey, queriedRecord);
}

void ProcessDock::openProcessDetailsPlaceholder()
{
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 打开进程详细信息失败：当前没有选中进程。" << eol;
        QMessageBox::warning(this, "进程详细信息", "请先在表格中选中一个进程。");
        return;
    }
    if (actionTargets.size() > 1U)
    {
        kLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] 打开进程详细信息失败：详情窗口仅支持单进程, selectedCount="
            << actionTargets.size()
            << eol;
        QMessageBox::information(this, "进程详细信息", "请只选中一个进程再打开详情窗口。");
        return;
    }

    // 详情窗口展示前不再同步补齐静态字段：
    // - 旧逻辑会在 UI 线程读取命令行、令牌和数字签名；
    // - 签名校验与权限受限进程会让“打开进程详细信息”明显卡顿；
    // - 现在先用列表缓存开窗，ProcessDetailWindow 内部后台补齐缺失字段。
    ks::process::ProcessRecord detailRecord = actionTargets.front().record;

    // identityKey 用于“一进程一窗口”复用逻辑。
    const std::string identityKey = ks::process::BuildProcessIdentityKey(
        detailRecord.pid,
        detailRecord.creationTime100ns);

    auto existingWindowIt = m_detailWindowByIdentity.find(identityKey);
    if (existingWindowIt != m_detailWindowByIdentity.end() && existingWindowIt->second != nullptr)
    {
        existingWindowIt->second->updateBaseRecord(detailRecord);
        m_detailWindowLastSyncTimeByIdentity[identityKey] = std::chrono::steady_clock::now();
        existingWindowIt->second->show();
        existingWindowIt->second->raise();
        existingWindowIt->second->activateWindow();

        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 复用已存在进程详情窗口, pid=" << detailRecord.pid
            << ", identity=" << identityKey
            << eol;
        return;
    }

    // 创建新的独立窗口（不属于 Docking System，可并行打开多个）。
    ProcessDetailWindow* detailWindow = new ProcessDetailWindow(detailRecord, nullptr);
    detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
    m_detailWindowByIdentity[identityKey] = detailWindow;
    m_detailWindowLastSyncTimeByIdentity[identityKey] = std::chrono::steady_clock::now();

    // 详情窗口销毁后，从缓存移除，防止悬空指针。
    connect(detailWindow, &QObject::destroyed, this, [this, identityKey]() {
        m_detailWindowByIdentity.erase(identityKey);
        m_detailWindowLastSyncTimeByIdentity.erase(identityKey);
    });

    // “转到父进程”由详情窗口发信号到这里统一处理。
    connect(detailWindow, &ProcessDetailWindow::requestOpenProcessByPid, this, [this](const std::uint32_t parentPid) {
        openProcessDetailWindowByPid(parentPid);
    });
    connect(detailWindow, &ProcessDetailWindow::requestOpenHandleDockByPid, this, [this](const std::uint32_t targetPid) {
        const bool invokeOk = invokeMainWindowPidSlot("focusHandleDockByPid", targetPid);
        if (!invokeOk)
        {
            kLogEvent logEvent;
            warn << logEvent
                << "[ProcessDock] requestOpenHandleDockByPid 转发失败, pid="
                << targetPid
                << eol;
        }
    });

    connectDetailWindowNavigation(detailWindow);
    detailWindow->show();
    detailWindow->raise();
    detailWindow->activateWindow();

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 创建新的进程详情窗口, pid=" << detailRecord.pid
        << ", identity=" << identityKey
        << eol;
}

void ProcessDock::openSelectedProcessHotkeyScanner()
{
    // 进程列表右键“扫描进程热键”入口：
    // - 输入：当前右键菜单冻结的单个进程动作目标；
    // - 处理：复用已有详情窗口缓存，必要时创建详情窗口，然后切到热键页并触发扫描；
    // - 返回：无。批量选择时直接提示，避免一次打开多个详情窗口造成 UI 噪声。
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 扫描进程热键失败：当前没有选中进程。" << eol;
        QMessageBox::warning(this, QStringLiteral("扫描进程热键"), QStringLiteral("请先在表格中选中一个进程。"));
        return;
    }
    if (actionTargets.size() > 1U)
    {
        kLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] 扫描进程热键失败：仅支持单进程, selectedCount="
            << actionTargets.size()
            << eol;
        QMessageBox::information(this, QStringLiteral("扫描进程热键"), QStringLiteral("请只选中一个进程再扫描热键。"));
        return;
    }

    ks::process::ProcessRecord detailRecord = actionTargets.front().record;
    const std::string identityKey = ks::process::BuildProcessIdentityKey(
        detailRecord.pid,
        detailRecord.creationTime100ns);

    ProcessDetailWindow* detailWindow = nullptr;
    auto existingWindowIt = m_detailWindowByIdentity.find(identityKey);
    if (existingWindowIt != m_detailWindowByIdentity.end() && existingWindowIt->second != nullptr)
    {
        detailWindow = existingWindowIt->second.data();
        detailWindow->updateBaseRecord(detailRecord);
        m_detailWindowLastSyncTimeByIdentity[identityKey] = std::chrono::steady_clock::now();
    }
    else
    {
        detailWindow = new ProcessDetailWindow(detailRecord, nullptr);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
        m_detailWindowByIdentity[identityKey] = detailWindow;
        m_detailWindowLastSyncTimeByIdentity[identityKey] = std::chrono::steady_clock::now();

        connect(detailWindow, &QObject::destroyed, this, [this, identityKey]() {
            m_detailWindowByIdentity.erase(identityKey);
            m_detailWindowLastSyncTimeByIdentity.erase(identityKey);
        });
        connect(detailWindow, &ProcessDetailWindow::requestOpenProcessByPid, this, [this](const std::uint32_t parentPid) {
            openProcessDetailWindowByPid(parentPid);
        });
        connect(detailWindow, &ProcessDetailWindow::requestOpenHandleDockByPid, this, [this](const std::uint32_t targetPid) {
            const bool invokeOk = invokeMainWindowPidSlot("focusHandleDockByPid", targetPid);
            if (!invokeOk)
            {
                kLogEvent logEvent;
                warn << logEvent
                    << "[ProcessDock] requestOpenHandleDockByPid 转发失败, pid="
                    << targetPid
                    << eol;
            }
        });
    }

    if (detailWindow == nullptr)
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 扫描进程热键失败：详情窗口创建失败。" << eol;
        QMessageBox::warning(this, QStringLiteral("扫描进程热键"), QStringLiteral("无法创建进程详细信息窗口。"));
        return;
    }

    connectDetailWindowNavigation(detailWindow);
    detailWindow->show();
    detailWindow->raise();
    detailWindow->activateWindow();
    detailWindow->showHotkeyTabAndRefresh();

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 打开进程热键扫描入口, pid="
        << detailRecord.pid
        << ", identity="
        << identityKey
        << eol;
}

void ProcessDock::openSelectedProcessInjectionPage()
{
    // 进程列表右键“DLL/Shellcode 注入”入口：
    // - 输入：当前右键菜单冻结的单个进程动作目标；
    // - 处理：复用已有详情窗口缓存，必要时创建详情窗口，然后切到“操作”页；
    // - 返回：无。批量选择时直接提示，避免一次打开多个详情窗口造成 UI 噪声。
    const std::vector<ProcessActionTarget> actionTargets = selectedActionTargets();
    if (actionTargets.empty())
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 打开 DLL/Shellcode 注入页失败：当前没有选中进程。" << eol;
        QMessageBox::warning(this, QStringLiteral("DLL/Shellcode 注入"), QStringLiteral("请先在表格中选中一个进程。"));
        return;
    }
    if (actionTargets.size() > 1U)
    {
        kLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] 打开 DLL/Shellcode 注入页失败：仅支持单进程, selectedCount="
            << actionTargets.size()
            << eol;
        QMessageBox::information(this, QStringLiteral("DLL/Shellcode 注入"), QStringLiteral("请只选中一个进程再打开注入页。"));
        return;
    }

    ks::process::ProcessRecord detailRecord = actionTargets.front().record;
    const std::string identityKey = ks::process::BuildProcessIdentityKey(
        detailRecord.pid,
        detailRecord.creationTime100ns);

    ProcessDetailWindow* detailWindow = nullptr;
    auto existingWindowIt = m_detailWindowByIdentity.find(identityKey);
    if (existingWindowIt != m_detailWindowByIdentity.end() && existingWindowIt->second != nullptr)
    {
        detailWindow = existingWindowIt->second.data();
        detailWindow->updateBaseRecord(detailRecord);
        m_detailWindowLastSyncTimeByIdentity[identityKey] = std::chrono::steady_clock::now();
    }
    else
    {
        detailWindow = new ProcessDetailWindow(detailRecord, nullptr);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
        m_detailWindowByIdentity[identityKey] = detailWindow;
        m_detailWindowLastSyncTimeByIdentity[identityKey] = std::chrono::steady_clock::now();

        connect(detailWindow, &QObject::destroyed, this, [this, identityKey]() {
            m_detailWindowByIdentity.erase(identityKey);
            m_detailWindowLastSyncTimeByIdentity.erase(identityKey);
        });
        connect(detailWindow, &ProcessDetailWindow::requestOpenProcessByPid, this, [this](const std::uint32_t parentPid) {
            openProcessDetailWindowByPid(parentPid);
        });
        connect(detailWindow, &ProcessDetailWindow::requestOpenHandleDockByPid, this, [this](const std::uint32_t targetPid) {
            const bool invokeOk = invokeMainWindowPidSlot("focusHandleDockByPid", targetPid);
            if (!invokeOk)
            {
                kLogEvent logEvent;
                warn << logEvent
                    << "[ProcessDock] requestOpenHandleDockByPid 转发失败, pid="
                    << targetPid
                    << eol;
            }
        });
    }

    if (detailWindow == nullptr)
    {
        kLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 打开 DLL/Shellcode 注入页失败：详情窗口创建失败。" << eol;
        QMessageBox::warning(this, QStringLiteral("DLL/Shellcode 注入"), QStringLiteral("无法创建进程详细信息窗口。"));
        return;
    }

    connectDetailWindowNavigation(detailWindow);
    detailWindow->show();
    detailWindow->raise();
    detailWindow->activateWindow();
    detailWindow->showActionTab();

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 打开 DLL/Shellcode 注入页入口, pid="
        << detailRecord.pid
        << ", identity="
        << identityKey
        << eol;
}

void ProcessDock::showProcessDetailWindowForRecord(
    const std::string& identityKey,
    const ks::process::ProcessRecord& detailRecord)
{
    // existingWindowIt：同一 PID+创建时间只复用一扇详情窗口。
    const auto existingWindowIt = m_detailWindowByIdentity.find(identityKey);
    if (existingWindowIt != m_detailWindowByIdentity.end() &&
        existingWindowIt->second != nullptr)
    {
        existingWindowIt->second->updateBaseRecord(detailRecord);
        m_detailWindowLastSyncTimeByIdentity[identityKey] =
            std::chrono::steady_clock::now();
        existingWindowIt->second->show();
        existingWindowIt->second->raise();
        existingWindowIt->second->activateWindow();
        return;
    }

    // detailWindow：缺失的静态字段由窗口后台补齐，避免阻塞 UI 跳转路径。
    ProcessDetailWindow* const detailWindow =
        new ProcessDetailWindow(detailRecord, nullptr);
    detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
    m_detailWindowByIdentity[identityKey] = detailWindow;
    m_detailWindowLastSyncTimeByIdentity[identityKey] =
        std::chrono::steady_clock::now();
    connect(
        detailWindow,
        &QObject::destroyed,
        this,
        [this, identityKey]()
        {
            m_detailWindowByIdentity.erase(identityKey);
            m_detailWindowLastSyncTimeByIdentity.erase(identityKey);
        });
    connect(
        detailWindow,
        &ProcessDetailWindow::requestOpenProcessByPid,
        this,
        [this](const std::uint32_t parentPid)
        {
            openProcessDetailWindowByPid(parentPid);
        });
    connect(
        detailWindow,
        &ProcessDetailWindow::requestOpenHandleDockByPid,
        this,
        [this](const std::uint32_t targetPid)
        {
            // invokeOk：将详情窗口的句柄页跳转请求交给主窗口。
            const bool invokeOk =
                invokeMainWindowPidSlot("focusHandleDockByPid", targetPid);
            if (!invokeOk)
            {
                kLogEvent logEvent;
                warn << logEvent
                    << "[ProcessDock] requestOpenHandleDockByPid 转发失败, pid="
                    << targetPid
                    << eol;
            }
        });
    connectDetailWindowNavigation(detailWindow);
    detailWindow->show();
    detailWindow->raise();
    detailWindow->activateWindow();
}

void ProcessDock::openProcessDetailWindowByPid(const std::uint32_t pid)
{
    // currentCreationTime100ns：实时身份查询成功时精确选择当前 PID 的缓存项。
    std::uint64_t currentCreationTime100ns = 0U;

    // identityDetailText：普通实时表跳转不弹身份错误，仅用于决定是否回退缓存。
    std::string identityDetailText;

    // identityQueryOk：成功时避免在新旧 identity 重叠期间选择退出项。
    const bool identityQueryOk = ks::process::QueryProcessCreationTimeByPid(
        pid,
        &currentCreationTime100ns,
        &identityDetailText);
    if (identityQueryOk)
    {
        // currentIdentityKey：实时 PID 对应的唯一缓存键。
        const std::string currentIdentityKey = ks::process::BuildProcessIdentityKey(
            pid,
            currentCreationTime100ns);

        // currentCacheIt：只接受未退出、非内核占位的当前进程记录。
        const auto currentCacheIt = m_cacheByIdentity.find(currentIdentityKey);
        if (currentCacheIt != m_cacheByIdentity.end() &&
            !currentCacheIt->second.isExitedInLatestRound &&
            !currentCacheIt->second.isKernelOnlyInLatestRound)
        {
            showProcessDetailWindowForRecord(
                currentIdentityKey,
                currentCacheIt->second.record);
            return;
        }

        // queriedRecord：缓存尚未刷新时用实时 identity 构造轻量记录。
        ks::process::ProcessRecord queriedRecord{};
        queriedRecord.pid = pid;
        queriedRecord.creationTime100ns = currentCreationTime100ns;
        queriedRecord.processName = ks::process::GetProcessNameByPID(pid);
        if (queriedRecord.processName.empty())
        {
            queriedRecord.processName = "PID_" + std::to_string(pid);
        }
        showProcessDetailWindowForRecord(currentIdentityKey, queriedRecord);
        return;
    }

    // fallbackCacheEntry：受保护进程无法实时查询时，仅从未退出缓存中选择最新 identity。
    const CacheEntry* fallbackCacheEntry = nullptr;

    // fallbackIdentityKey：与 fallbackCacheEntry 同步保存其稳定键。
    std::string fallbackIdentityKey;
    for (const auto& cachePair : m_cacheByIdentity)
    {
        const CacheEntry& cacheEntry = cachePair.second;
        if (cacheEntry.record.pid != pid ||
            cacheEntry.isExitedInLatestRound ||
            cacheEntry.isKernelOnlyInLatestRound)
        {
            continue;
        }
        if (fallbackCacheEntry == nullptr ||
            cacheEntry.record.creationTime100ns >
                fallbackCacheEntry->record.creationTime100ns)
        {
            fallbackCacheEntry = &cacheEntry;
            fallbackIdentityKey = cachePair.first;
        }
    }
    if (fallbackCacheEntry != nullptr)
    {
        showProcessDetailWindowForRecord(
            fallbackIdentityKey,
            fallbackCacheEntry->record);
        return;
    }

    // queriedRecord：保留纯 PID 实时入口兼容性；历史入口不会走到此降级路径。
    ks::process::ProcessRecord queriedRecord{};
    queriedRecord.pid = pid;
    queriedRecord.processName = ks::process::GetProcessNameByPID(pid);
    if (queriedRecord.processName.empty())
    {
        queriedRecord.processName = "PID_" + std::to_string(pid);
    }
    const std::string identityKey = ks::process::BuildProcessIdentityKey(
        queriedRecord.pid,
        queriedRecord.creationTime100ns);
    showProcessDetailWindowForRecord(identityKey, queriedRecord);
}
