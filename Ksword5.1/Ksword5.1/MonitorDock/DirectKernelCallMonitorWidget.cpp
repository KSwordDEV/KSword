#include "DirectKernelCallMonitorWidget.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ThemeBinding.h"

// ============================================================
// DirectKernelCallMonitorWidget.cpp
// 作用：
// 1) 用 ETW System Syscall Provider 采集系统调用事件；
// 2) 严格解码经典进入/退出事件，关联原始 QPC、CPU 和 StackWalk 载荷身份；
// 3) 解析 ntdll/win32u 导出桩，辅助把系统调用号转换为服务名。
// ============================================================

#include "MonitorTextViewer.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/ThemeStatusRole.h"
#include "../theme.h"
#include "../../../shared/evidence/SyscallEvidence.h"

#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QAction>
#include <QApplication>
#include <QByteArray>
#include <QCheckBox>
#include <QClipboard>
#include <QFile>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QElapsedTimer>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPoint>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <cstring>
#include <optional>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Objbase.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <evntrace.h>
#include <evntcons.h>

// 兼容旧版 SDK：EVENT_TRACE_FLAG_SYSTEMCALL 是 PERF_SYSCALL 的 legacy kernel flag。
// 若头文件未暴露该宏，使用 evntrace.h 中长期稳定的系统调用事件标志位。
#ifndef EVENT_TRACE_FLAG_SYSTEMCALL
#define EVENT_TRACE_FLAG_SYSTEMCALL 0x00000080
#endif

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")

namespace
{
    constexpr int kRoleGlobalSearchText = Qt::UserRole;
    constexpr int kRoleProcessSearchText = Qt::UserRole + 1;
    constexpr int kRoleServiceSearchText = Qt::UserRole + 2;
    constexpr int kRoleDetailDocument = Qt::UserRole + 3;
    constexpr int kRoleProcessCreationTime100ns = Qt::UserRole + 4;

    constexpr GUID kPerfInfoGuid =
        { 0xce1dbfb4, 0x137e, 0x4da6, { 0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc } };
    constexpr GUID kStackWalkGuid =
        { 0xdef2fe46, 0x7bd6, 0x4b80, { 0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3 } };

    std::uint64_t correlationNowMs()
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    void retainLossCount(std::atomic<std::uint64_t>& counter, ULONG observed)
    {
        auto previous = counter.load();
        while (previous < observed && !counter.compare_exchange_weak(previous, observed)) {}
    }

    QString blueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QSpinBox{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus,QSpinBox:focus{border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            + KswordTheme::ThemedComboBoxStyle();
    }

    QString blueHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;padding:4px;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex());
    }

    QPushButton* createIconButton(QWidget* parentWidget, const QString& iconPath, const QString& tooltipText)
    {
        QPushButton* buttonPointer = new QPushButton(QIcon(iconPath), QString(), parentWidget);
        buttonPointer->setToolTip(tooltipText);
        buttonPointer->setFixedSize(QSize(30, 28));
        buttonPointer->setStyleSheet(blueButtonStyle());
        return buttonPointer;
    }

    QTableWidgetItem* createReadOnlyItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString guidToText(const GUID& guidValue)
    {
        wchar_t buffer[64] = {};
        if (::StringFromGUID2(guidValue, buffer, static_cast<int>(std::size(buffer))) <= 0)
        {
            return QStringLiteral("{00000000-0000-0000-0000-000000000000}");
        }
        return QString::fromWCharArray(buffer);
    }

    QString formatAddress(const std::uint64_t addressValue)
    {
        if (addressValue == 0)
        {
            return QStringLiteral("<未知>");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(addressValue), 16, 16, QChar(u'0'))
            .toUpper();
    }

    bool isKernelModeAddress(const std::uint64_t addressValue)
    {
        // 说明：
        // - SysCallEnter 的 SysCallAddress 是内核服务例程地址，不是用户态 syscall 指令位置；
        // - x64 内核地址通常位于 canonical high-half，x86 兼容地址通常从 0x80000000 起；
        // - 该判断只用于避免把内核地址误判成“用户态直接 syscall”。
        return addressValue >= 0xFFFF000000000000ULL
            || (addressValue <= 0xFFFFFFFFULL && addressValue >= 0x80000000ULL);
    }

    QString normalizeName(const QString& text)
    {
        QString normalized = text.toLower();
        normalized.remove(QRegularExpression(QStringLiteral("[^a-z0-9]")));
        return normalized;
    }

    bool textMatch(
        const QString& sourceText,
        const QString& patternText,
        const bool useRegex,
        const Qt::CaseSensitivity caseSensitivity)
    {
        if (patternText.trimmed().isEmpty())
        {
            return true;
        }

        if (!useRegex)
        {
            return sourceText.contains(patternText, caseSensitivity);
        }

        QRegularExpression::PatternOptions options = QRegularExpression::NoPatternOption;
        if (caseSensitivity == Qt::CaseInsensitive)
        {
            options |= QRegularExpression::CaseInsensitiveOption;
        }
        const QRegularExpression regex(patternText, options);
        return regex.isValid() && regex.match(sourceText).hasMatch();
    }

    std::optional<std::uint32_t> tryReadSyscallNumberFromStub(
        const unsigned char* functionPointer, const std::size_t length)
    {
        if (functionPointer == nullptr)
        {
            return std::nullopt;
        }

        // Only a complete x64 service stub yields a number. An arbitrary B8
        // immediate (or a detoured export) must not populate the service map.
        const auto code = ks::evidence::syscall::InspectCode(functionPointer, length, 0);
        if (code.nativeStub && code.hasSystemCallNumber)
        {
            return code.systemCallNumber;
        }
        return std::nullopt;
    }

    bool serviceNameAllowed(const QString& exportName, const QStringList& prefixList)
    {
        for (const QString& prefixText : prefixList)
        {
            if (exportName.startsWith(prefixText, Qt::CaseSensitive))
            {
                return true;
            }
        }
        return false;
    }

    void appendSyscallExportsFromModule(
        const wchar_t* moduleName,
        const QStringList& prefixList,
        std::unordered_map<std::uint32_t, DirectKernelCallMonitorWidget::SyscallMapEntry>* mapPointer)
    {
        if (moduleName == nullptr || mapPointer == nullptr)
        {
            return;
        }

        HMODULE moduleHandle = ::GetModuleHandleW(moduleName);
        if (moduleHandle == nullptr)
        {
            moduleHandle = ::LoadLibraryW(moduleName);
        }
        if (moduleHandle == nullptr)
        {
            return;
        }

        const auto* basePointer = reinterpret_cast<const unsigned char*>(moduleHandle);
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(basePointer);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return;
        }

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(basePointer + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            return;
        }

        const IMAGE_DATA_DIRECTORY& exportDirectoryInfo =
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDirectoryInfo.VirtualAddress == 0 || exportDirectoryInfo.Size == 0)
        {
            return;
        }

        const auto* exportDirectory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            basePointer + exportDirectoryInfo.VirtualAddress);
        const auto* nameRvaArray = reinterpret_cast<const DWORD*>(basePointer + exportDirectory->AddressOfNames);
        const auto* ordinalArray = reinterpret_cast<const WORD*>(basePointer + exportDirectory->AddressOfNameOrdinals);
        const auto* functionRvaArray = reinterpret_cast<const DWORD*>(basePointer + exportDirectory->AddressOfFunctions);
        const QString moduleText = QString::fromWCharArray(moduleName);

        for (DWORD indexValue = 0; indexValue < exportDirectory->NumberOfNames; ++indexValue)
        {
            const char* exportNamePointer = reinterpret_cast<const char*>(basePointer + nameRvaArray[indexValue]);
            const QString exportName = QString::fromLatin1(exportNamePointer);
            if (!serviceNameAllowed(exportName, prefixList))
            {
                continue;
            }

            const WORD ordinalValue = ordinalArray[indexValue];
            if (ordinalValue >= exportDirectory->NumberOfFunctions)
            {
                continue;
            }

            const DWORD functionRva = functionRvaArray[ordinalValue];
            if (functionRva >= ntHeaders->OptionalHeader.SizeOfImage)
            {
                continue;
            }
            if (functionRva >= exportDirectoryInfo.VirtualAddress
                && functionRva < exportDirectoryInfo.VirtualAddress + exportDirectoryInfo.Size)
            {
                continue;
            }

            const unsigned char* functionPointer = basePointer + functionRva;
            const std::size_t readableLength = (std::min)(std::size_t(32),
                static_cast<std::size_t>(ntHeaders->OptionalHeader.SizeOfImage - functionRva));
            const std::optional<std::uint32_t> syscallNumber = tryReadSyscallNumberFromStub(functionPointer, readableLength);
            if (!syscallNumber.has_value())
            {
                continue;
            }

            DirectKernelCallMonitorWidget::SyscallMapEntry& entry = (*mapPointer)[*syscallNumber];
            entry.syscallNumber = *syscallNumber;
            if (entry.serviceName.isEmpty())
            {
                entry.serviceName = exportName;
                entry.sourceModule = moduleText;
            }
            else if (!entry.serviceName.split(QStringLiteral(" / ")).contains(exportName))
            {
                entry.serviceName += QStringLiteral(" / %1").arg(exportName);
                entry.sourceModule += QStringLiteral(" / %1").arg(moduleText);
            }
        }
    }


}

DirectKernelCallMonitorWidget::DirectKernelCallMonitorWidget(QWidget* parent)
    : QWidget(parent)
{
    kLogEvent event;
    info << event << "[DirectKernelCallMonitorWidget] 初始化直接内核调用监控页。" << eol;

    initializeUi();
    initializeConnections();
    reloadSyscallMap();
    updateActionState();
    updateStatusLabel();
}

DirectKernelCallMonitorWidget::~DirectKernelCallMonitorWidget()
{
    stopCaptureInternal(true);
    if (m_uiUpdateTimer != nullptr)
    {
        m_uiUpdateTimer->stop();
    }
    if (m_filterDebounceTimer != nullptr)
    {
        m_filterDebounceTimer->stop();
    }

    kLogEvent event;
    info << event << "[DirectKernelCallMonitorWidget] 直接内核调用监控页已析构。" << eol;
}

void DirectKernelCallMonitorWidget::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(6);

    m_controlPanel = new QWidget(this);
    QGridLayout* controlLayout = new QGridLayout(m_controlPanel);
    controlLayout->setContentsMargins(6, 6, 6, 6);
    controlLayout->setHorizontalSpacing(6);
    controlLayout->setVerticalSpacing(6);

    controlLayout->addWidget(new QLabel(QStringLiteral("目标 PID"), m_controlPanel), 0, 0);
    m_targetPidEdit = new QLineEdit(m_controlPanel);
    m_targetPidEdit->setPlaceholderText(QStringLiteral("多个 PID 用逗号/空格分隔；留空需勾选全局采集"));
    m_targetPidEdit->setStyleSheet(blueInputStyle());
    controlLayout->addWidget(m_targetPidEdit, 0, 1, 1, 3);

    m_globalCaptureCheck = new QCheckBox(QStringLiteral("全局采集"), m_controlPanel);
    m_globalCaptureCheck->setToolTip(QStringLiteral("采集全系统 syscall 事件，事件量可能很大"));
    controlLayout->addWidget(m_globalCaptureCheck, 0, 4);

    m_resolveAddressCheck = new QCheckBox(QStringLiteral("解析调用地址"), m_controlPanel);
    m_resolveAddressCheck->setChecked(true);
    m_resolveAddressCheck->setToolTip(QStringLiteral("关联用户调用栈并只读检查 syscall 桩，识别直接调用、疑似间接调用和 SysWhispers 兼容形态"));
    controlLayout->addWidget(m_resolveAddressCheck, 0, 5);

    controlLayout->addWidget(new QLabel(QStringLiteral("最大行数"), m_controlPanel), 1, 0);
    m_maxRowsSpin = new QSpinBox(m_controlPanel);
    m_maxRowsSpin->setRange(1000, 20000);
    m_maxRowsSpin->setSingleStep(1000);
    m_maxRowsSpin->setValue(12000);
    m_maxRowsSpin->setStyleSheet(blueInputStyle());
    controlLayout->addWidget(m_maxRowsSpin, 1, 1);

    controlLayout->addWidget(new QLabel(QStringLiteral("缓冲区(KB)"), m_controlPanel), 1, 2);
    m_bufferSizeSpin = new QSpinBox(m_controlPanel);
    m_bufferSizeSpin->setRange(64, 4096);
    m_bufferSizeSpin->setSingleStep(64);
    m_bufferSizeSpin->setValue(512);
    m_bufferSizeSpin->setStyleSheet(blueInputStyle());
    controlLayout->addWidget(m_bufferSizeSpin, 1, 3);

    m_reloadMapButton = createIconButton(
        m_controlPanel,
        QStringLiteral(":/Icon/process_refresh.svg"),
        QStringLiteral("重新解析 ntdll/win32u syscall 号映射"));
    m_startButton = createIconButton(
        m_controlPanel,
        QStringLiteral(":/Icon/process_start.svg"),
        QStringLiteral("开始直接内核调用监控"));
    m_stopButton = createIconButton(
        m_controlPanel,
        QStringLiteral(":/Icon/process_terminate.svg"),
        QStringLiteral("停止监控"));
    m_pauseButton = createIconButton(
        m_controlPanel,
        QStringLiteral(":/Icon/process_pause.svg"),
        QStringLiteral("暂停事件入表"));
    m_clearButton = createIconButton(
        m_controlPanel,
        QStringLiteral(":/Icon/log_clear.svg"),
        QStringLiteral("清空当前事件表"));
    m_exportButton = createIconButton(
        m_controlPanel,
        QStringLiteral(":/Icon/log_export.svg"),
        QStringLiteral("导出当前可见事件为 TSV"));

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(6);
    buttonLayout->addWidget(m_reloadMapButton);
    buttonLayout->addWidget(m_startButton);
    buttonLayout->addWidget(m_stopButton);
    buttonLayout->addWidget(m_pauseButton);
    buttonLayout->addWidget(m_clearButton);
    buttonLayout->addWidget(m_exportButton);
    buttonLayout->addStretch(1);
    ks::ui::NormalizeToolbarRow(buttonLayout);
    controlLayout->addLayout(buttonLayout, 1, 4, 1, 2);

    m_mapStatusLabel = new QLabel(QStringLiteral("syscall 映射：待解析"), m_controlPanel);
    ks::ui::ApplyStatusRole(m_mapStatusLabel, ks::ui::StatusRole::Idle);
    controlLayout->addWidget(m_mapStatusLabel, 2, 0, 1, 3);

    m_statusLabel = new QLabel(QStringLiteral("● 空闲"), m_controlPanel);
    m_statusLabel->setWordWrap(true);
    ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Idle);
    controlLayout->addWidget(m_statusLabel, 2, 3, 1, 3);
    m_rootLayout->addWidget(m_controlPanel, 0);

    m_filterPanel = new QWidget(this);
    QGridLayout* filterLayout = new QGridLayout(m_filterPanel);
    filterLayout->setContentsMargins(6, 6, 6, 6);
    filterLayout->setHorizontalSpacing(6);
    filterLayout->setVerticalSpacing(6);

    filterLayout->addWidget(new QLabel(QStringLiteral("进程"), m_filterPanel), 0, 0);
    m_processFilterEdit = new QLineEdit(m_filterPanel);
    m_processFilterEdit->setPlaceholderText(QStringLiteral("PID / TID / 进程名"));
    m_processFilterEdit->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(m_processFilterEdit, 0, 1);

    filterLayout->addWidget(new QLabel(QStringLiteral("服务"), m_filterPanel), 0, 2);
    m_serviceFilterEdit = new QLineEdit(m_filterPanel);
    m_serviceFilterEdit->setPlaceholderText(QStringLiteral("Nt/Zw/NtUser/NtGdi 或调用号"));
    m_serviceFilterEdit->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(m_serviceFilterEdit, 0, 3);

    filterLayout->addWidget(new QLabel(QStringLiteral("详情"), m_filterPanel), 0, 4);
    m_detailFilterEdit = new QLineEdit(m_filterPanel);
    m_detailFilterEdit->setPlaceholderText(QStringLiteral("调用地址 / 判定 / 字段详情"));
    m_detailFilterEdit->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(m_detailFilterEdit, 0, 5);

    filterLayout->addWidget(new QLabel(QStringLiteral("全字段"), m_filterPanel), 1, 0);
    m_globalFilterEdit = new QLineEdit(m_filterPanel);
    m_globalFilterEdit->setPlaceholderText(QStringLiteral("对整行文本做统一过滤"));
    m_globalFilterEdit->setStyleSheet(blueInputStyle());
    // 各列过滤提示没有统一的 search 元数据，明确登记四个结果过滤框；采集 PID 不在此列。
    for (QLineEdit* field : {m_processFilterEdit, m_serviceFilterEdit, m_detailFilterEdit, m_globalFilterEdit})
    {
        ks::ui::StyleSearchField(field);
    }
    filterLayout->addWidget(m_globalFilterEdit, 1, 1, 1, 3);

    m_regexCheck = new QCheckBox(QStringLiteral("正则"), m_filterPanel);
    m_caseCheck = new QCheckBox(QStringLiteral("区分大小写"), m_filterPanel);
    m_invertCheck = new QCheckBox(QStringLiteral("反向"), m_filterPanel);
    m_keepBottomCheck = new QCheckBox(QStringLiteral("保持贴底"), m_filterPanel);
    m_keepBottomCheck->setChecked(true);
    filterLayout->addWidget(m_regexCheck, 1, 4);
    filterLayout->addWidget(m_caseCheck, 1, 5);
    filterLayout->addWidget(m_invertCheck, 2, 0);
    filterLayout->addWidget(m_keepBottomCheck, 2, 1);

    m_clearFilterButton = createIconButton(
        m_filterPanel,
        QStringLiteral(":/Icon/log_clear.svg"),
        QStringLiteral("清空筛选条件"));
    filterLayout->addWidget(m_clearFilterButton, 2, 2);

    m_filterStatusLabel = new QLabel(QStringLiteral("筛选结果：0 / 0"), m_filterPanel);
    ks::ui::ApplyStatusRole(m_filterStatusLabel, ks::ui::StatusRole::Idle);
    filterLayout->addWidget(m_filterStatusLabel, 2, 3, 1, 3);
    m_rootLayout->addWidget(m_filterPanel, 0);

    m_eventTable = new ks::ui::VisibleTableWidget(this);
    // 系统调用主事件流需要快照取证，保留完整栏。
    ks::ui::SetTableActionBarMode(m_eventTable, ks::ui::TableActionBarMode::Full);
    m_eventTable->setColumnCount(EventColumnCount);
    m_eventTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("时间(100ns)"),
        QStringLiteral("PID / TID"),
        QStringLiteral("进程"),
        QStringLiteral("桩内调用号（静态）"),
        QStringLiteral("服务名"),
        QStringLiteral("判定"),
        QStringLiteral("调用地址"),
        QStringLiteral("事件名"),
        QStringLiteral("详情")
    });
    m_eventTable->setAlternatingRowColors(true);
    m_eventTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_eventTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_eventTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_eventTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_eventTable->verticalHeader()->setVisible(false);
    m_eventTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    m_eventTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_eventTable->setColumnWidth(EventColumnTime100ns, 160);
    m_eventTable->setColumnWidth(EventColumnPidTid, 100);
    m_eventTable->setColumnWidth(EventColumnProcess, 180);
    m_eventTable->setColumnWidth(EventColumnSyscallNumber, 84);
    m_eventTable->setColumnWidth(EventColumnServiceName, 220);
    m_eventTable->setColumnWidth(EventColumnVerdict, 96);
    m_eventTable->setColumnWidth(EventColumnCallAddress, 164);
    m_eventTable->setColumnWidth(EventColumnEventName, 150);
    m_eventTable->setColumnWidth(EventColumnDetail, 440);
    m_rootLayout->addWidget(m_eventTable, 1);

    m_uiUpdateTimer = new QTimer(this);
    m_uiUpdateTimer->setInterval(100);

    m_filterDebounceTimer = new QTimer(this);
    m_filterDebounceTimer->setInterval(180);
    m_filterDebounceTimer->setSingleShot(true);
}

void DirectKernelCallMonitorWidget::initializeConnections()
{
    connect(m_reloadMapButton, &QPushButton::clicked, this, [this]() {
        reloadSyscallMap();
    });
    connect(m_startButton, &QPushButton::clicked, this, [this]() {
        startCapture();
    });
    connect(m_stopButton, &QPushButton::clicked, this, [this]() {
        stopCapture();
    });
    connect(m_pauseButton, &QPushButton::clicked, this, [this]() {
        setCapturePaused(!m_capturePaused.load());
    });
    connect(m_clearButton, &QPushButton::clicked, this, [this]() {
        if (m_eventTable != nullptr)
        {
            m_eventTable->clearContents();
            m_eventTable->setRowCount(0);
        }
        updateActionState();
        updateStatusLabel();
        applyFilter();
    });
    connect(m_exportButton, &QPushButton::clicked, this, [this]() {
        exportVisibleRowsToTsv();
    });

    const auto bindFilterEdit = [this](QLineEdit* editPointer) {
        if (editPointer != nullptr)
        {
            connect(editPointer, &QLineEdit::textChanged, this, [this]() {
                scheduleFilterApply();
            });
        }
    };
    bindFilterEdit(m_processFilterEdit);
    bindFilterEdit(m_serviceFilterEdit);
    bindFilterEdit(m_detailFilterEdit);
    bindFilterEdit(m_globalFilterEdit);

    connect(m_regexCheck, &QCheckBox::toggled, this, [this]() {
        scheduleFilterApply();
    });
    connect(m_caseCheck, &QCheckBox::toggled, this, [this]() {
        scheduleFilterApply();
    });
    connect(m_invertCheck, &QCheckBox::toggled, this, [this]() {
        scheduleFilterApply();
    });
    connect(m_clearFilterButton, &QPushButton::clicked, this, [this]() {
        clearFilter();
    });

    connect(m_eventTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showEventContextMenu(position);
    });
    connect(m_eventTable, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* itemPointer) {
        if (itemPointer != nullptr)
        {
            openEventDetailViewerForRow(itemPointer->row());
        }
    });
    connect(m_uiUpdateTimer, &QTimer::timeout, this, [this]() {
        flushPendingRows();
    });
    connect(m_filterDebounceTimer, &QTimer::timeout, this, [this]() {
        applyFilter();
    });
}

void DirectKernelCallMonitorWidget::reloadSyscallMap()
{
    std::unordered_map<std::uint32_t, SyscallMapEntry> newMap;
    appendSyscallExportsFromModule(
        L"ntdll.dll",
        QStringList{ QStringLiteral("Nt"), QStringLiteral("Zw") },
        &newMap);
    appendSyscallExportsFromModule(
        L"win32u.dll",
        QStringList{ QStringLiteral("NtUser"), QStringLiteral("NtGdi") },
        &newMap);

    {
        std::lock_guard<std::mutex> lock(m_syscallMapMutex);
        m_syscallMap = std::move(newMap);
    }

    if (m_mapStatusLabel != nullptr)
    {
        m_mapStatusLabel->setText(QStringLiteral("syscall 映射：%1 项（ntdll/win32u）")
            .arg(static_cast<qulonglong>(m_syscallMap.size())));
        ks::ui::ApplyStatusRole(m_mapStatusLabel,
            m_syscallMap.empty() ? ks::ui::StatusRole::Warning : ks::ui::StatusRole::Success);
    }

    kLogEvent event;
    info << event << "[DirectKernelCallMonitorWidget] 已解析 syscall 映射, count="
        << m_syscallMap.size() << eol;
}

void DirectKernelCallMonitorWidget::startCapture()
{
    if (m_captureRunning.load())
    {
        if (m_capturePaused.load())
        {
            setCapturePaused(false);
        }
        return;
    }

    if (m_captureThread != nullptr && m_captureThread->joinable())
    {
        m_captureThread->join();
        m_captureThread.reset();
    }

    if (!stopOwnedSession())
    {
        updateStatusLabel();
        return;
    }

    const std::set<std::uint32_t> pidSet = parsePidSet(m_targetPidEdit != nullptr ? m_targetPidEdit->text() : QString());
    const bool captureAll = m_globalCaptureCheck != nullptr && m_globalCaptureCheck->isChecked();
    if (pidSet.empty() && !captureAll)
    {
        QMessageBox::information(
            this,
            QStringLiteral("直接内核调用监控"),
            QStringLiteral("请先输入目标 PID，或勾选“全局采集”。"));
        return;
    }

    if (captureAll)
    {
        const QMessageBox::StandardButton answer = QMessageBox::question(
            this,
            QStringLiteral("直接内核调用监控"),
            QStringLiteral("全局 syscall 事件量可能极大，建议只在短时间窗口内采集。是否继续？"),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (answer != QMessageBox::Yes)
        {
            return;
        }
    }

    if (m_eventTable != nullptr)
    {
        m_eventTable->clearContents();
        m_eventTable->setRowCount(0);
    }
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        m_pendingRows.clear();
        m_pendingDroppedRows = 0;
    }
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        m_processNameCache.clear();
        m_moduleRangeCache.clear();
        m_moduleRefreshTimes.clear();
    }
    m_stackCorrelator.Reset();
    ++m_captureIntervalGeneration;
    m_consumerIntervalGeneration = m_captureIntervalGeneration.load();
    m_frameInspectionCache.clear();
    m_stackEnableStatus.store(ERROR_SUCCESS);
    m_startTraceStatus.store(ERROR_SUCCESS);
    m_openTraceStatus.store(ERROR_SUCCESS);
    m_processTraceStatus.store(ERROR_SUCCESS);
    m_etwEventsLost.store(0);
    m_etwBuffersLost.store(0);
    m_stackMatched.store(0);
    m_stackMissing.store(0);
    m_stackConflicts.store(0);
    m_stackCapacityEvicted.store(0);
    m_lastTraceStatsQuery = {};
    LARGE_INTEGER qpcBefore{}, qpcAfter{}, frequency{};
    FILETIME captureTime{};
    ::QueryPerformanceFrequency(&frequency);
    ::QueryPerformanceCounter(&qpcBefore);
    ::GetSystemTimePreciseAsFileTime(&captureTime);
    ::QueryPerformanceCounter(&qpcAfter);
    m_qpcOrigin = static_cast<std::uint64_t>(qpcBefore.QuadPart + (qpcAfter.QuadPart - qpcBefore.QuadPart) / 2);
    m_qpcFrequency = static_cast<std::uint64_t>((std::max)(1LL, frequency.QuadPart));
    m_filetimeOrigin = (static_cast<std::uint64_t>(captureTime.dwHighDateTime) << 32) | captureTime.dwLowDateTime;
    {
        std::lock_guard<std::mutex> lock(m_captureConfigMutex);
        m_capturePidSet = pidSet;
    }

    const int bufferSizeKb = m_bufferSizeSpin != nullptr ? m_bufferSizeSpin->value() : 512;
    m_captureAllProcesses.store(captureAll);
    m_resolveCallAddress.store(m_resolveAddressCheck == nullptr || m_resolveAddressCheck->isChecked());
    m_captureRunning.store(true);
    m_capturePaused.store(false);
    m_captureStopFlag.store(false);
    m_sessionHandle.store(0);
    m_traceHandle.store(0);
    GUID sessionGuid{};
    const HRESULT guidStatus = ::CoCreateGuid(&sessionGuid);
    if (FAILED(guidStatus))
    {
        m_captureRunning.store(false);
        updateActionState();
        return;
    }
    m_sessionName = QStringLiteral("KswordDirectKernelCall-%1-%2")
        .arg(::GetCurrentProcessId()).arg(guidToText(sessionGuid));

    if (m_captureProgressPid == 0)
    {
        m_captureProgressPid = kPro.addReusable(this, "监控", "直接内核调用监控");
    }
    kPro.set(m_captureProgressPid, "准备 System Syscall ETW 会话", 0, 10.0f);

    if (m_uiUpdateTimer != nullptr && !m_uiUpdateTimer->isActive())
    {
        m_uiUpdateTimer->start();
    }
    updateActionState();
    updateStatusLabel();

    QPointer<DirectKernelCallMonitorWidget> guardThis(this);
    m_captureThread = std::make_unique<std::thread>([guardThis, bufferSizeKb, sessionGuid]() {
        if (guardThis == nullptr)
        {
            return;
        }

        const auto reportStopped = [guardThis]()
        {
            QMetaObject::invokeMethod(qApp, [guardThis]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->m_captureRunning.store(false);
                guardThis->m_capturePaused.store(false);
                if (guardThis->m_uiUpdateTimer != nullptr)
                {
                    guardThis->flushPendingRows();
                }
                if (guardThis->m_statusLabel != nullptr)
                {
                    guardThis->m_statusLabel->setText(QStringLiteral("● 已停止"));
                    ks::ui::ApplyStatusRole(guardThis->m_statusLabel, ks::ui::StatusRole::Idle);
                }
                guardThis->updateActionState();
                guardThis->updateStatusLabel();
                kPro.set(guardThis->m_captureProgressPid, "直接内核调用监控结束", 0, 100.0f);
            }, Qt::QueuedConnection);
        };

        const std::wstring sessionNameWide = guardThis->m_sessionName.toStdWString();
        const ULONG traceNameBytes = static_cast<ULONG>((sessionNameWide.size() + 1) * sizeof(wchar_t));
        const ULONG propertyBufferSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + traceNameBytes);
        std::vector<unsigned char> propertyBuffer(propertyBufferSize, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
        properties->Wnode.BufferSize = propertyBufferSize;
        properties->Wnode.ClientContext = 1; // QPC; header and StackWalk payload must share one clock.
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // 私有 SystemTraceProvider 会话不能使用 SystemTraceControlGuid。
        // 如果 private logger name 搭配 SystemTraceControlGuid，StartTraceW 会返回 87。
        properties->Wnode.Guid = sessionGuid;
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        // 使用 legacy EnableFlags 启用 syscall 事件，避免较新 System Provider
        // EnableTraceEx2 路径在部分系统/SDK 组合上返回 ERROR_INVALID_PARAMETER。
        properties->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
        properties->FlushTimer = 1;
        properties->BufferSize = static_cast<ULONG>(bufferSizeKb);
        properties->MinimumBuffers = 32;
        properties->MaximumBuffers = 128;

        wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(propertyBuffer.data() + properties->LoggerNameOffset);
        ::wcscpy_s(loggerNamePointer, sessionNameWide.size() + 1, sessionNameWide.c_str());

        TRACEHANDLE sessionHandle = 0;
        ULONG startStatus = ::StartTraceW(&sessionHandle, loggerNamePointer, properties);
        guardThis->m_startTraceStatus.store(startStatus);

        if (startStatus != ERROR_SUCCESS)
        {
            QMetaObject::invokeMethod(qApp, [guardThis, startStatus]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->m_captureRunning.store(false);
                guardThis->m_capturePaused.store(false);
                guardThis->m_statusLabel->setText(QStringLiteral("● StartTrace失败:%1").arg(startStatus));
                ks::ui::ApplyStatusRole(guardThis->m_statusLabel, ks::ui::StatusRole::Error);
                guardThis->updateActionState();
                guardThis->updateStatusLabel();
                kPro.set(guardThis->m_captureProgressPid, "System Syscall 会话启动失败", 0, 100.0f);
            }, Qt::QueuedConnection);
            return;
        }

        guardThis->m_sessionHandle.store(static_cast<std::uint64_t>(sessionHandle));
        CLASSIC_EVENT_ID stackEvent{};
        stackEvent.EventGuid = kPerfInfoGuid;
        stackEvent.Type = 51; // SysCallEnter
        guardThis->m_stackEnableStatus.store(::TraceSetInformation(
            sessionHandle, TraceStackTracingInfo, &stackEvent, sizeof(stackEvent)));
        if (guardThis->m_captureStopFlag.load())
        {
            guardThis->stopOwnedSession();
            reportStopped();
            return;
        }
        kPro.set(guardThis->m_captureProgressPid, "已启用 syscall kernel flag", 0, 30.0f);

        EVENT_TRACE_LOGFILEW traceLogFile{};
        traceLogFile.LoggerName = loggerNamePointer;
        traceLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
            | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        traceLogFile.EventRecordCallback = &DirectKernelCallMonitorWidget::eventRecordCallback;
        traceLogFile.BufferCallback = &DirectKernelCallMonitorWidget::bufferCallback;
        traceLogFile.Context = guardThis.data();

        TRACEHANDLE traceHandle = ::OpenTraceW(&traceLogFile);
        if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            const ULONG lastError = ::GetLastError();
            guardThis->m_openTraceStatus.store(lastError);
            guardThis->stopOwnedSession();
            QMetaObject::invokeMethod(qApp, [guardThis, lastError]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->m_captureRunning.store(false);
                guardThis->m_capturePaused.store(false);
                guardThis->m_statusLabel->setText(QStringLiteral("● OpenTrace失败:%1").arg(lastError));
                ks::ui::ApplyStatusRole(guardThis->m_statusLabel, ks::ui::StatusRole::Error);
                guardThis->updateActionState();
                guardThis->updateStatusLabel();
                kPro.set(guardThis->m_captureProgressPid, "OpenTrace 失败", 0, 100.0f);
            }, Qt::QueuedConnection);
            return;
        }

        guardThis->m_traceHandle.store(static_cast<std::uint64_t>(traceHandle));
        if (guardThis->m_captureStopFlag.load())
        {
            const std::uint64_t ownedTraceHandle = guardThis->m_traceHandle.exchange(0);
            if (ownedTraceHandle != 0)
            {
                ::CloseTrace(static_cast<TRACEHANDLE>(ownedTraceHandle));
            }
            guardThis->stopOwnedSession();
            reportStopped();
            return;
        }
        kPro.set(guardThis->m_captureProgressPid, "接收 syscall 事件", 0, 55.0f);

        const ULONG processStatus = ::ProcessTrace(&traceHandle, 1, nullptr, nullptr);
        guardThis->m_processTraceStatus.store(processStatus == ERROR_CANCELLED ? ERROR_SUCCESS : processStatus);
        guardThis->publishCorrelatedRows(guardThis->m_stackCorrelator.Expire(correlationNowMs(), true));
        guardThis->m_frameInspectionCache.clear();
        const std::uint64_t ownedTraceHandle = guardThis->m_traceHandle.exchange(0);
        if (ownedTraceHandle != 0)
        {
            ::CloseTrace(static_cast<TRACEHANDLE>(ownedTraceHandle));
        }

        guardThis->stopOwnedSession();

        QMetaObject::invokeMethod(qApp, [guardThis, processStatus]() {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->m_captureRunning.store(false);
            guardThis->m_capturePaused.store(false);
            if (guardThis->m_uiUpdateTimer != nullptr)
            {
                guardThis->flushPendingRows();
            }
            if (processStatus == ERROR_SUCCESS)
            {
                guardThis->m_statusLabel->setText(QStringLiteral("● 已停止"));
                ks::ui::ApplyStatusRole(guardThis->m_statusLabel, ks::ui::StatusRole::Idle);
            }
            else
            {
                guardThis->m_statusLabel->setText(QStringLiteral("● ProcessTrace结束:%1").arg(processStatus));
                ks::ui::ApplyStatusRole(guardThis->m_statusLabel, ks::ui::StatusRole::Warning);
            }
            guardThis->updateActionState();
            guardThis->updateStatusLabel();
            kPro.set(guardThis->m_captureProgressPid, "直接内核调用监控结束", 0, 100.0f);
        }, Qt::QueuedConnection);
    });
}

void DirectKernelCallMonitorWidget::stopCapture()
{
    stopCaptureInternal(false);
}

bool DirectKernelCallMonitorWidget::stopOwnedSession()
{
    const auto ownedSession = m_sessionHandle.exchange(0);
    if (ownedSession == 0) { return true; }
    const auto name = m_sessionName.toStdWString();
    std::vector<unsigned char> bytes(sizeof(EVENT_TRACE_PROPERTIES) + (name.size() + 1) * sizeof(wchar_t), 0);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(bytes.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(bytes.size());
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    auto* loggerName = reinterpret_cast<wchar_t*>(bytes.data() + properties->LoggerNameOffset);
    ::wcscpy_s(loggerName, name.size() + 1, name.c_str());
    const ULONG status = ::ControlTraceW(static_cast<TRACEHANDLE>(ownedSession),
        loggerName, properties, EVENT_TRACE_CONTROL_STOP);
    if (status == ERROR_SUCCESS || status == ERROR_WMI_INSTANCE_NOT_FOUND)
    {
        m_sessionStopStatus.store(ERROR_SUCCESS);
        if (status == ERROR_SUCCESS)
        {
            retainLossCount(m_etwEventsLost, properties->EventsLost);
            retainLossCount(m_etwBuffersLost, properties->RealTimeBuffersLost);
        }
        return true;
    }
    // Keep ownership after a failed stop. The consumer's final cleanup,
    // destructor, or next start can retry without touching another session.
    std::uint64_t empty = 0;
    m_sessionHandle.compare_exchange_strong(empty, ownedSession);
    m_sessionStopStatus.store(status);
    return false;
}

void DirectKernelCallMonitorWidget::stopCaptureInternal(bool waitForThread)
{
    m_captureStopFlag.store(true);

    const std::uint64_t ownedTraceHandle = m_traceHandle.exchange(0);
    if (ownedTraceHandle != 0)
    {
        ::CloseTrace(static_cast<TRACEHANDLE>(ownedTraceHandle));
    }

    stopOwnedSession();

    if (m_captureThread == nullptr || !m_captureThread->joinable())
    {
        m_captureThread.reset();
        m_captureRunning.store(false);
        m_capturePaused.store(false);
        if (m_uiUpdateTimer != nullptr)
        {
            m_uiUpdateTimer->stop();
        }
        updateActionState();
        updateStatusLabel();
        return;
    }

    if (waitForThread)
    {
        m_captureThread->join();
        m_captureThread.reset();
        stopOwnedSession();
        m_captureRunning.store(false);
        m_capturePaused.store(false);
        if (m_uiUpdateTimer != nullptr)
        {
            m_uiUpdateTimer->stop();
        }
        updateActionState();
        updateStatusLabel();
        return;
    }

    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(QStringLiteral("● 停止中..."));
        ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Warning);
    }
    // 停止按钮不能转移 m_captureThread 的所有权。该线程持有 ETW 的
    // 原始 Context，析构路径需要保留 join 句柄，才能在释放 QWidget 前
    // 等待 ProcessTrace 及其回调完全结束。
    updateActionState();
    updateStatusLabel();
}

void DirectKernelCallMonitorWidget::setCapturePaused(bool paused)
{
    if (!m_captureRunning.load())
    {
        return;
    }
    m_capturePaused.store(paused);
    ++m_captureIntervalGeneration;
    updateActionState();
    updateStatusLabel();
}

void DirectKernelCallMonitorWidget::updateActionState()
{
    const bool running = m_captureRunning.load();
    const bool paused = m_capturePaused.load();
    const bool hasRows = m_eventTable != nullptr && m_eventTable->rowCount() > 0;

    if (m_targetPidEdit != nullptr)
    {
        m_targetPidEdit->setEnabled(!running);
    }
    if (m_globalCaptureCheck != nullptr)
    {
        m_globalCaptureCheck->setEnabled(!running);
    }
    if (m_resolveAddressCheck != nullptr)
    {
        m_resolveAddressCheck->setEnabled(!running);
    }
    if (m_bufferSizeSpin != nullptr)
    {
        m_bufferSizeSpin->setEnabled(!running);
    }
    if (m_reloadMapButton != nullptr)
    {
        m_reloadMapButton->setEnabled(!running);
    }
    if (m_startButton != nullptr)
    {
        m_startButton->setEnabled(!running || paused);
        m_startButton->setIcon(QIcon(paused
            ? QStringLiteral(":/Icon/process_resume.svg")
            : QStringLiteral(":/Icon/process_start.svg")));
        m_startButton->setToolTip(paused
            ? QStringLiteral("继续直接内核调用监控")
            : QStringLiteral("开始直接内核调用监控"));
    }
    if (m_stopButton != nullptr)
    {
        m_stopButton->setEnabled(running);
    }
    if (m_pauseButton != nullptr)
    {
        m_pauseButton->setEnabled(running);
        m_pauseButton->setIcon(QIcon(paused
            ? QStringLiteral(":/Icon/process_resume.svg")
            : QStringLiteral(":/Icon/process_pause.svg")));
        m_pauseButton->setToolTip(paused
            ? QStringLiteral("继续事件入表")
            : QStringLiteral("暂停事件入表"));
    }
    if (m_clearButton != nullptr)
    {
        m_clearButton->setEnabled(!running && hasRows);
    }
    if (m_exportButton != nullptr)
    {
        m_exportButton->setEnabled(hasRows);
    }
}

void DirectKernelCallMonitorWidget::updateStatusLabel()
{
    if (m_statusLabel == nullptr)
    {
        return;
    }
    const int eventCount = m_eventTable != nullptr ? m_eventTable->rowCount() : 0;
    QString targetText;
    if (m_captureAllProcesses.load())
    {
        targetText = QStringLiteral("全局");
    }
    else
    {
        std::lock_guard<std::mutex> lock(m_captureConfigMutex);
        targetText = QStringLiteral("PID=%1").arg(static_cast<qulonglong>(m_capturePidSet.size()));
    }

    if (m_captureRunning.load())
    {
        if (m_capturePaused.load())
        {
            m_statusLabel->setText(QStringLiteral("● 已暂停  %1 | 事件=%2").arg(targetText).arg(eventCount));
            ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Warning);
        }
        else
        {
            m_statusLabel->setText(QStringLiteral("● 监听中  %1 | 事件=%2").arg(targetText).arg(eventCount));
            ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Info);
        }
    }
    else if (m_startTraceStatus.load() != ERROR_SUCCESS)
    {
        m_statusLabel->setText(QStringLiteral("● StartTrace失败:%1").arg(m_startTraceStatus.load()));
        ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Error);
    }
    else if (m_openTraceStatus.load() != ERROR_SUCCESS)
    {
        m_statusLabel->setText(QStringLiteral("● OpenTrace失败:%1").arg(m_openTraceStatus.load()));
        ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Error);
    }
    else if (m_processTraceStatus.load() != ERROR_SUCCESS)
    {
        m_statusLabel->setText(QStringLiteral("● ProcessTrace结束:%1").arg(m_processTraceStatus.load()));
        ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Warning);
    }
    else
    {
        m_statusLabel->setText(QStringLiteral("● 空闲  事件=%1").arg(eventCount));
        ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Idle);
    }
    std::size_t queueDropped = 0;
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        queueDropped = m_pendingDroppedRows;
    }
    m_statusLabel->setText(m_statusLabel->text() + QStringLiteral(
        " | 栈匹配=%1 / 缺失=%2 / 冲突=%3 / 容量淘汰=%4 | ETW 丢失=%5 / 缓冲丢失=%6 / 队列丢弃=%7")
        .arg(m_stackMatched.load()).arg(m_stackMissing.load()).arg(m_stackConflicts.load())
        .arg(m_stackCapacityEvicted.load()).arg(m_etwEventsLost.load()).arg(m_etwBuffersLost.load())
        .arg(static_cast<qulonglong>(queueDropped)));
    if (m_stackEnableStatus.load() != ERROR_SUCCESS)
    {
        m_statusLabel->setText(m_statusLabel->text() + QStringLiteral(" | 调用栈启用失败：%1").arg(m_stackEnableStatus.load()));
        ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Error);
    }
    if (m_sessionStopStatus.load() != ERROR_SUCCESS)
    {
        m_statusLabel->setText(m_statusLabel->text() + QStringLiteral(" | ETW 会话停止失败：%1").arg(m_sessionStopStatus.load()));
        ks::ui::ApplyStatusRole(m_statusLabel, ks::ui::StatusRole::Error);
    }
}

void WINAPI DirectKernelCallMonitorWidget::eventRecordCallback(struct _EVENT_RECORD* eventRecordPtr)
{
    if (eventRecordPtr == nullptr)
    {
        return;
    }
    EVENT_RECORD* eventRecord = reinterpret_cast<EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord->UserContext == nullptr)
    {
        return;
    }
    auto* widget = reinterpret_cast<DirectKernelCallMonitorWidget*>(eventRecord->UserContext);
    widget->enqueueEventFromRecord(eventRecordPtr);
}

ULONG WINAPI DirectKernelCallMonitorWidget::bufferCallback(struct _EVENT_TRACE_LOGFILEW* traceLogFile)
{
    if (traceLogFile == nullptr || traceLogFile->Context == nullptr)
    {
        return TRUE;
    }
    auto* widget = static_cast<DirectKernelCallMonitorWidget*>(traceLogFile->Context);
    widget->synchronizeCaptureInterval();
    widget->publishCorrelatedRows(widget->m_stackCorrelator.Expire(correlationNowMs()));
    const auto now = std::chrono::steady_clock::now();
    const auto session = widget->m_sessionHandle.load();
    if (session != 0 && now - widget->m_lastTraceStatsQuery >= std::chrono::seconds(1))
    {
        widget->m_lastTraceStatsQuery = now;
        std::vector<unsigned char> bytes(sizeof(EVENT_TRACE_PROPERTIES) + 2048 * sizeof(wchar_t), 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(bytes.data());
        properties->Wnode.BufferSize = static_cast<ULONG>(bytes.size());
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        if (::ControlTraceW(static_cast<TRACEHANDLE>(session), nullptr, properties, EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS)
        {
            retainLossCount(widget->m_etwEventsLost, properties->EventsLost);
            retainLossCount(widget->m_etwBuffersLost, properties->RealTimeBuffersLost);
        }
    }
    return TRUE;
}

void DirectKernelCallMonitorWidget::enqueueRow(CapturedEventRow row)
{
    std::lock_guard<std::mutex> lock(m_pendingMutex);
    if (m_pendingRows.size() >= kPendingRowCapacity)
    {
        m_pendingRows.pop_front();
        ++m_pendingDroppedRows;
    }
    m_pendingRows.push_back(std::move(row));
}

void DirectKernelCallMonitorWidget::synchronizeCaptureInterval()
{
    const auto generation = m_captureIntervalGeneration.load();
    if (generation != m_consumerIntervalGeneration)
    {
        m_stackCorrelator.Reset();
        m_consumerIntervalGeneration = generation;
    }
}

void DirectKernelCallMonitorWidget::enqueueEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr)
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr)
    {
        return;
    }
    synchronizeCaptureInterval();
    if (m_captureStopFlag.load() || m_capturePaused.load())
    {
        // A discarded event or stack must never survive into another capture interval.
        m_stackCorrelator.Reset();
        return;
    }
    const auto nowMs = correlationNowMs();
    publishCorrelatedRows(m_stackCorrelator.Expire(nowMs));
    const auto opcode = eventRecord->EventHeader.EventDescriptor.Opcode;
    const std::size_t pointerSize = (eventRecord->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
    const ks::evidence::syscall::Key key{
        static_cast<std::uint64_t>(eventRecord->EventHeader.TimeStamp.QuadPart),
        static_cast<std::uint16_t>(::GetEventProcessorIndex(eventRecord)) };
    if (::IsEqualGUID(eventRecord->EventHeader.ProviderId, kStackWalkGuid) && opcode == 32)
    {
        std::uint64_t timestamp = 0;
        std::uint32_t pid = 0, tid = 0;
        std::vector<std::uint64_t> frames;
        if (ks::evidence::syscall::ParseStackPayload(
                static_cast<const std::uint8_t*>(eventRecord->UserData), eventRecord->UserDataLength,
                pointerSize, timestamp, pid, tid, frames))
        {
            if (!shouldCapturePid(pid)) { return; }
            // Payload identity belongs to the triggering event. The stack record's
            // header may instead name the worker collecting the deferred user stack.
            publishCorrelatedRows(m_stackCorrelator.AddStack(
                {timestamp, key.cpu}, pid, tid, std::move(frames), nowMs));
        }
        return;
    }
    ks::evidence::syscall::SyscallPayload payload;
    if (!::IsEqualGUID(eventRecord->EventHeader.ProviderId, kPerfInfoGuid)
        || !ks::evidence::syscall::ParseSyscallPayload(opcode, pointerSize,
            eventRecord->UserData, eventRecord->UserDataLength, payload))
    {
        return;
    }
    auto row = buildRowFromRecord(eventRecordPtr);
    if (row.pid != UINT32_MAX && !shouldCapturePid(row.pid)) { return; }
    if (opcode == 52)
    {
        // Exit carries an NTSTATUS, never a service number or a user return PC.
        if (row.pid != UINT32_MAX && shouldCapturePid(row.pid))
        {
            row.processText = processNameForPid(row.pid, &row.processCreationTime100ns);
            row.globalSearchText += QStringLiteral(" | %1 | %2").arg(row.processText, row.time100nsText);
            enqueueRow(std::move(row));
        }
        return;
    }
    const auto pid = row.pid;
    const auto tid = row.tid;
    publishCorrelatedRows(m_stackCorrelator.AddEvent(key, pid, tid, std::move(row), nowMs));
    // Modern providers may attach the stack directly instead of emitting StackWalk.
    // Only a complete, bounded extension with usable header identity is admitted.
    if (pid == UINT32_MAX || tid == UINT32_MAX || eventRecord->ExtendedData == nullptr)
    {
        return;
    }
    for (USHORT i = 0; i < eventRecord->ExtendedDataCount; ++i)
    {
        const auto& extended = eventRecord->ExtendedData[i];
        const std::size_t width = extended.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 ? 8
            : extended.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 ? 4 : 0;
        if (width == 0 || extended.DataPtr == 0 || extended.DataSize <= 8
            || (extended.DataSize - 8) % width != 0 || (extended.DataSize - 8) / width > 192)
        {
            continue;
        }
        std::vector<std::uint64_t> frames;
        const auto* data = reinterpret_cast<const unsigned char*>(extended.DataPtr);
        for (std::size_t offset = 8; offset < extended.DataSize; offset += width)
        {
            std::uint64_t address = 0;
            std::memcpy(&address, data + offset, width);
            frames.push_back(address);
        }
        publishCorrelatedRows(m_stackCorrelator.AddStack(key, pid, tid, std::move(frames), nowMs));
    }
}

DirectKernelCallMonitorWidget::CapturedEventRow DirectKernelCallMonitorWidget::buildRowFromRecord(
    const struct _EVENT_RECORD* eventRecordPtr)
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    CapturedEventRow row;
    const auto rawQpc = static_cast<std::uint64_t>(eventRecord->EventHeader.TimeStamp.QuadPart);
    const long double delta = (static_cast<long double>(rawQpc) - m_qpcOrigin) * 10000000.0L / m_qpcFrequency;
    row.eventTime100ns = static_cast<std::uint64_t>((std::max)(0.0L, static_cast<long double>(m_filetimeOrigin) + delta));
    row.time100nsText = QString::number(static_cast<qulonglong>(row.eventTime100ns));
    row.pid = eventRecord->EventHeader.ProcessId;
    row.tid = eventRecord->EventHeader.ThreadId;
    row.pidTidText = QStringLiteral("%1 / %2").arg(row.pid).arg(row.tid);
    row.pointerSize = (eventRecord->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
    row.syscallNumberText = QStringLiteral("<未知>");
    row.serviceName = QStringLiteral("<未解析>");
    row.callAddressText = QStringLiteral("<未知>");
    row.verdictText = QStringLiteral("证据不足：未取得用户调用栈");
    if (eventRecord->EventHeader.EventDescriptor.Opcode == 51)
    {
        row.eventName = QStringLiteral("SysCallEnter");
        std::memcpy(&row.kernelServiceAddress, eventRecord->UserData, row.pointerSize);
        row.detailDocument = {};
        row.detailDocument.field(QStringLiteral("内核服务地址"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(formatAddress(row.kernelServiceAddress))));
        row.detailDocument.field(QStringLiteral("原始 QPC"), QStringLiteral("%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(rawQpc))));
    }
    else
    {
        row.eventName = QStringLiteral("SysCallExit");
        std::uint32_t status = 0;
        std::memcpy(&status, eventRecord->UserData, sizeof(status));
        row.verdictText = QStringLiteral("系统调用退出（不含调用号）");
        row.detailText = QStringLiteral("NTSTATUS=0x%1").arg(status, 8, 16, QChar(u'0'));
        row.detailDocument.field(QStringLiteral("NTSTATUS"), QStringLiteral("0x%1").arg(status, 8, 16, QChar(u'0')));
        row.globalSearchText = QStringLiteral("%1 | %2 | %3").arg(row.pidTidText, row.eventName, row.detailText);
    }
    return row;
}

void DirectKernelCallMonitorWidget::publishCorrelatedRows(
    std::vector<ks::evidence::syscall::Correlator<CapturedEventRow>::Output> outputs)
{
    for (auto& output : outputs)
    {
        switch (output.state)
        {
        case ks::evidence::syscall::CorrelationState::Matched: ++m_stackMatched; break;
        case ks::evidence::syscall::CorrelationState::MissingStack: ++m_stackMissing; break;
        case ks::evidence::syscall::CorrelationState::Ambiguous: ++m_stackConflicts; break;
        case ks::evidence::syscall::CorrelationState::CapacityEvicted: ++m_stackCapacityEvicted; break;
        }
        auto& row = output.row;
        row.pid = output.pid;
        row.tid = output.tid;
        // Rejected arrivals count as drops; do not flood the UI queue with them.
        // Global capture can show raw rows with unknown identity. PID-scoped
        // capture still requires a known header or exact stack payload identity.
        if (output.state == ks::evidence::syscall::CorrelationState::CapacityEvicted
            || !shouldCapturePid(row.pid) || m_capturePaused.load())
        {
            continue;
        }
        row.pidTidText = QStringLiteral("%1 / %2").arg(
            row.pid == UINT32_MAX ? QStringLiteral("<未知>") : QString::number(row.pid),
            row.tid == UINT32_MAX ? QStringLiteral("<未知>") : QString::number(row.tid));
        row.processText = row.pid == UINT32_MAX ? QStringLiteral("<未知>")
            : processNameForPid(row.pid, &row.processCreationTime100ns);
        if (row.pid == UINT32_MAX)
        {
            row.verdictText = QStringLiteral("证据不足：进程身份不可验证");
        }
        else if (row.processCreationTime100ns > row.eventTime100ns)
        {
            row.processText = QStringLiteral("PID %1").arg(row.pid);
            row.processCreationTime100ns = 0;
            row.verdictText = QStringLiteral("证据不足：进程身份不匹配");
        }
        else if (output.state == ks::evidence::syscall::CorrelationState::Matched)
        {
            analyzeUserStack(row, output.frames);
        }
        else if (output.state == ks::evidence::syscall::CorrelationState::Ambiguous)
        {
            row.verdictText = QStringLiteral("证据不足：调用栈关联冲突");
        }
        row.detailText = QStringLiteral("%1 | %2 | %3").arg(row.verdictText, row.callAddressText, row.serviceName);
        row.detailDocument.section(QStringLiteral("事件"));
        row.detailDocument.field(QStringLiteral("时间（100 ns）"), row.time100nsText);
        row.detailDocument.field(QStringLiteral("进程"), row.processText);
        row.detailDocument.field(QStringLiteral("PID / TID"), row.pidTidText);
        row.detailDocument.field(QStringLiteral("事件"), row.eventName);
        row.detailDocument.field(QStringLiteral("判定"), row.verdictText);
        row.detailDocument.field(QStringLiteral("调用地址"), row.callAddressText);
        row.detailDocument.field(QStringLiteral("服务名称"), row.serviceName);
        row.detailDocument.field(QStringLiteral("调用号"), row.syscallNumberText);
        row.detailDocument.field(QStringLiteral("调用栈启用状态"), QString::number(m_stackEnableStatus.load()));
        row.globalSearchText = QStringLiteral("%1 | %2 | %3 | %4 | %5")
            .arg(row.time100nsText, row.processText, row.pidTidText, row.eventName, row.detailDocument.toPlainText(false));
        enqueueRow(std::move(row));
    }
}

void DirectKernelCallMonitorWidget::analyzeUserStack(CapturedEventRow& row, const std::vector<std::uint64_t>& frames)
{
    using namespace ks::evidence::syscall;
    std::vector<std::uint64_t> userFrames;
    row.detailDocument.section(QStringLiteral("ETW 调用栈"));
    std::size_t frameIndex = 0;
    for (const auto address : frames)
    {
        row.detailDocument.field(QStringLiteral("Frame"), QStringLiteral("%1: %2")
            .arg(frameIndex++).arg(formatAddress(address)));
        if (IsUserAddress(address, row.pointerSize))
        {
            userFrames.push_back(address);
        }
    }
    if (userFrames.empty())
    {
        return;
    }
    row.callAddress = userFrames.front();
    row.callAddressText = formatAddress(row.callAddress);
    if (!m_resolveCallAddress.load())
    {
        row.verdictText = QStringLiteral("证据不足：调用地址解析已关闭");
        return;
    }
    if (row.pointerSize != 8)
    {
        row.verdictText = QStringLiteral("证据不足：当前桩检测仅支持原生 x64");
        return;
    }
    if (row.processCreationTime100ns == 0)
    {
        row.verdictText = QStringLiteral("证据不足：进程身份不可验证");
        return;
    }
    // Inspection is a bounded post-event sample, not proof that these bytes ran.
    // Cache for 250ms with process-instance identity to keep hot syscall streams
    // from repeatedly opening handles and reading the same callsite.
    const auto sampledAt = std::chrono::steady_clock::now();
    HANDLE process = nullptr;
    std::shared_ptr<void> processOwner;
    bool triedOpen = false;
    bool unsupportedArchitecture = false;
    auto openVerified = [&]() {
        if (triedOpen) { return process != nullptr; }
        triedOpen = true;
        process = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, row.pid);
        FILETIME created{}, exited{}, kernel{}, user{};
        if (process != nullptr && ::GetProcessTimes(process, &created, &exited, &kernel, &user))
        {
            const auto creation = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
            if (creation == row.processCreationTime100ns && creation <= row.eventTime100ns)
            {
                BOOL wow64 = FALSE;
                if (::IsWow64Process(process, &wow64) && !wow64)
                {
                    processOwner = std::shared_ptr<void>(process, [](void* handle) { ::CloseHandle(handle); });
                    return true;
                }
                unsupportedArchitecture = true;
            }
        }
        if (process != nullptr) { ::CloseHandle(process); process = nullptr; }
        return false;
    };
    auto readWindow = [&](std::uint64_t pc, std::vector<unsigned char>& bytes, std::size_t& pcOffset) {
        MEMORY_BASIC_INFORMATION info{};
        if (!IsUserAddress(pc) || !::VirtualQueryEx(process, reinterpret_cast<LPCVOID>(pc), &info, sizeof(info))
            || info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
        {
            return false;
        }
        const auto regionStart = reinterpret_cast<std::uint64_t>(info.BaseAddress);
        const auto regionEnd = regionStart + info.RegionSize;
        const auto start = (std::max)(regionStart, pc > 192 ? pc - 192 : 0);
        const auto end = (std::min)(regionEnd, pc + 192);
        if (end <= start) { return false; }
        bytes.resize(static_cast<std::size_t>(end - start));
        SIZE_T read = 0;
        if (!::ReadProcessMemory(process, reinterpret_cast<LPCVOID>(start), bytes.data(), bytes.size(), &read)
            || read != bytes.size())
        {
            bytes.clear();
            return false;
        }
        pcOffset = static_cast<std::size_t>(pc - start);
        return true;
    };
    std::vector<FrameEvidence> evidence;
    bool unreadable = false;
    for (std::size_t i = 0; i < (std::min)(std::size_t(2), userFrames.size()); ++i)
    {
        const auto pc = userFrames[i];
        const auto key = std::make_pair(row.pid, pc);
        auto cached = m_frameInspectionCache.find(key);
        FrameInspection inspection;
        if (cached != m_frameInspectionCache.end() && cached->second.creationTime100ns == row.processCreationTime100ns
            && ((!cached->second.readable && !cached->second.processOwner)
                || (cached->second.processOwner && ::WaitForSingleObject(cached->second.processOwner.get(), 0) == WAIT_TIMEOUT))
            && sampledAt - cached->second.sampledAt < std::chrono::milliseconds(250))
        {
            inspection = cached->second;
        }
        else
        {
            inspection.creationTime100ns = row.processCreationTime100ns;
            inspection.sampledAt = sampledAt;
            inspection.evidence.address = pc;
            if (openVerified())
            {
                inspection.processOwner = processOwner;
                MEMORY_BASIC_INFORMATION info{};
                if (::VirtualQueryEx(process, reinterpret_cast<LPCVOID>(pc), &info, sizeof(info)) && info.State == MEM_COMMIT)
                {
                    const DWORD protection = info.Protect & 0xff;
                    inspection.evidence.executable = !(info.Protect & PAGE_GUARD) &&
                        (protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ
                         || protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY);
                    inspection.evidence.nonImage = info.Type == MEM_PRIVATE || info.Type == MEM_MAPPED;
                    inspection.moduleText = moduleNameForAddress(row.pid, pc);
                    // Toolhelp is only a presentation hint. Native-module trust
                    // comes from a MEM_IMAGE mapping with the same actual file path
                    // as our system DLL, not target-controlled loader metadata.
                    if (info.Type == MEM_IMAGE)
                    {
                        std::vector<wchar_t> mappedPath(32768, L'\0');
                        if (::GetMappedFileNameW(process, reinterpret_cast<LPVOID>(pc), mappedPath.data(), 32768))
                        {
                            bool systemIdentitiesComplete = true;
                            const QString targetPath = QString::fromWCharArray(mappedPath.data());
                            const wchar_t* nativeNames[] = {L"ntdll.dll", L"win32u.dll"};
                            for (const auto* name : nativeNames)
                            {
                                const auto localModule = ::GetModuleHandleW(name);
                                std::vector<wchar_t> localMappedPath(32768, L'\0'), localDosPath(32768, L'\0');
                                wchar_t systemDirectory[MAX_PATH]{};
                                const bool localIdentityKnown = localModule != nullptr
                                    && ::GetMappedFileNameW(::GetCurrentProcess(), localModule, localMappedPath.data(), 32768)
                                    && ::GetModuleFileNameW(localModule, localDosPath.data(), 32768)
                                    && ::GetSystemDirectoryW(systemDirectory, MAX_PATH)
                                    && QDir::cleanPath(QString::fromWCharArray(localDosPath.data())).compare(
                                        QDir::cleanPath(QString::fromWCharArray(systemDirectory) + QChar(u'/')
                                            + QString::fromWCharArray(name)), Qt::CaseInsensitive) == 0;
                                systemIdentitiesComplete &= localIdentityKnown;
                                if (localIdentityKnown
                                    && targetPath.compare(QString::fromWCharArray(localMappedPath.data()), Qt::CaseInsensitive) == 0)
                                {
                                    inspection.evidence.nativeModule = true;
                                    inspection.moduleText = QString::fromWCharArray(name);
                                    break;
                                }
                            }
                            // Unknown system identities cannot establish that an
                            // image is non-native, even if Toolhelp supplied a name.
                            inspection.evidence.moduleIdentityKnown = inspection.evidence.nativeModule || systemIdentitiesComplete;
                        }
                    }

                    std::vector<unsigned char> bytes;
                    std::size_t offset = 0;
                    if (inspection.evidence.executable && readWindow(pc, bytes, offset))
                    {
                        inspection.readable = true;
                        inspection.evidence.code = InspectCode(bytes.data(), bytes.size(), offset);
                        // A tail-jumping wrapper does not remain on the stack.
                        // For a return immediately following call rel32, inspect
                        // that call's target for the full resolver-wrapper shape.
                        if (i == 1 && offset >= 5 && bytes[offset - 5] == 0xe8)
                        {
                            std::int32_t displacement = 0;
                            std::memcpy(&displacement, bytes.data() + offset - 4, sizeof(displacement));
                            const auto target = static_cast<std::uint64_t>(static_cast<std::int64_t>(pc) + displacement);
                            std::vector<unsigned char> targetBytes;
                            std::size_t targetOffset = 0;
                            MEMORY_BASIC_INFORMATION targetInfo{};
                            if (IsUserAddress(target) && ::VirtualQueryEx(process, reinterpret_cast<LPCVOID>(target), &targetInfo, sizeof(targetInfo))
                                && targetInfo.State == MEM_COMMIT && (targetInfo.Protect & PAGE_GUARD) == 0
                                && ((targetInfo.Protect & 0xff) == PAGE_EXECUTE_READ
                                    || (targetInfo.Protect & 0xff) == PAGE_EXECUTE_READWRITE
                                    || (targetInfo.Protect & 0xff) == PAGE_EXECUTE_WRITECOPY)
                                && readWindow(target, targetBytes, targetOffset))
                            {
                                if (CompatibleWrapperAtEntry(targetBytes.data() + targetOffset,
                                        targetBytes.size() - targetOffset))
                                {
                                    inspection.evidence.code.whispererCompatible = true;
                                }
                            }
                        }
                    }
                }
            }
            if (m_frameInspectionCache.size() >= 4096) { m_frameInspectionCache.clear(); }
            m_frameInspectionCache[key] = inspection;
        }
        unreadable |= !inspection.readable;
        evidence.push_back(inspection.evidence);
        row.detailDocument.section(QStringLiteral("用户帧"));
        row.detailDocument.field(QStringLiteral("Index"), QString::number(i));
        row.detailDocument.field(QStringLiteral("Address"), formatAddress(pc));
        row.detailDocument.field(QStringLiteral("Module"), inspection.moduleText.isEmpty()
            ? QStringLiteral("<未解析>") : inspection.moduleText);
    }
    if (unsupportedArchitecture)
    {
        row.verdictText = QStringLiteral("证据不足：当前桩检测仅支持原生 x64");
        return;
    }
    const auto assessment = Assess(evidence);
    switch (assessment.path)
    {
    case PathKind::Direct: row.verdictText = QStringLiteral("疑似直接 syscall（指令已核对）"); break;
    case PathKind::Indirect:
        row.verdictText = assessment.whispererCompatible
            ? QStringLiteral("疑似间接 syscall（兼容解析桩）")
            : QStringLiteral("系统 syscall 桩（动态代码来源）");
        break;
    case PathKind::NativeStub: row.verdictText = QStringLiteral("系统 syscall 桩（来源未证明安全）"); break;
    default: row.verdictText = unreadable ? QStringLiteral("证据不足：调用代码不可读") : QStringLiteral("证据不足：未匹配 syscall 桩"); break;
    }
    if (assessment.whispererCompatible)
    {
        row.verdictText += QStringLiteral(" / SysWhispers 兼容形态");
    }
    if (assessment.path != PathKind::Indirect && !evidence.empty() && evidence.front().code.hasSystemCallNumber)
    {
        row.hasSyscallNumber = true;
        row.syscallNumber = evidence.front().code.systemCallNumber;
        row.syscallNumberText = QStringLiteral("%1 / 0x%2").arg(row.syscallNumber).arg(row.syscallNumber, 4, 16, QChar(u'0'));
        row.serviceName = serviceNameForNumber(row.syscallNumber);
        row.detailDocument.note(QStringLiteral("显示的调用号来自桩内静态立即数；未采集执行时的 EAX。"));
    }
    row.detailDocument.note(QStringLiteral("判定基于事件关联和采集后的内存样本；动态代码也可能来自 JIT、运行时或安全软件。兼容形态不能确定工具、版本或恶意性。"));
}

QString DirectKernelCallMonitorWidget::serviceNameForNumber(std::uint32_t syscallNumber) const
{
    std::lock_guard<std::mutex> lock(m_syscallMapMutex);
    const auto found = m_syscallMap.find(syscallNumber);
    if (found == m_syscallMap.end())
    {
        return QStringLiteral("<未命中映射>");
    }
    return found->second.serviceName;
}

QString DirectKernelCallMonitorWidget::processNameForPid(
    const std::uint32_t pid,
    std::uint64_t* const creationTime100nsOut)
{
    // creationTime100nsOut：默认写 0，只有缓存或实时查询成功时才返回可验证 identity。
    if (creationTime100nsOut != nullptr)
    {
        *creationTime100nsOut = 0U;
    }
    if (pid == 0U)
    {
        return QStringLiteral("System");
    }

    // nowTime：使用单调时钟决定本 PID 是否需要重新验证。
    const std::chrono::steady_clock::time_point nowTime =
        std::chrono::steady_clock::now();

    // cachedEntry：锁外查询系统时保留上一份缓存，避免持有互斥量执行 Win32 调用。
    ProcessIdentityCacheEntry cachedEntry;

    // hasCachedEntry：标记 cachedEntry 是否来自有效缓存。
    bool hasCachedEntry = false;
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        const auto found = m_processNameCache.find(pid);
        if (found != m_processNameCache.end())
        {
            cachedEntry = found->second;
            hasCachedEntry = true;

            // cacheAge：一秒内复用已验证 identity，避免高频 ETW 事件重复打开句柄。
            const auto cacheAge = std::chrono::duration_cast<std::chrono::milliseconds>(
                nowTime - found->second.lastValidationTime);
            if (cacheAge.count() < kProcessIdentityValidationIntervalMs)
            {
                if (creationTime100nsOut != nullptr)
                {
                    *creationTime100nsOut = found->second.creationTime100ns;
                }
                return found->second.processText;
            }
        }
    }

    // observedCreationTime100ns：本轮重新验证得到的当前进程创建时间。
    std::uint64_t observedCreationTime100ns = 0U;

    // identityDetailText：接收底层查询诊断；高频捕获路径不直接向 UI 弹窗。
    std::string identityDetailText;

    // identityQueryOk：决定是否能安全更新 PID 对应的 identity。
    const bool identityQueryOk = ks::process::QueryProcessCreationTimeByPid(
        pid,
        &observedCreationTime100ns,
        &identityDetailText);

    // identityChanged：创建时间变化表示 PID 已复用，必须重新解析名称并清理模块缓存。
    const bool identityChanged = identityQueryOk &&
        (!hasCachedEntry || cachedEntry.creationTime100ns != observedCreationTime100ns);

    // processText：查询失败时沿用旧名称；首次失败则显示纯 PID。
    QString processText = hasCachedEntry
        ? cachedEntry.processText
        : QStringLiteral("PID %1").arg(pid);
    if (identityChanged)
    {
        // processHandle：仅在首次发现或 PID 复用时查询一次映像名称。
        const HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(pid));
        if (processHandle != nullptr)
        {
            // pathBuffer/pathLength：接收目标进程完整映像路径。
            std::vector<wchar_t> pathBuffer(32768, L'\0');
            DWORD pathLength = static_cast<DWORD>(pathBuffer.size());
            if (::QueryFullProcessImageNameW(
                    processHandle,
                    0,
                    pathBuffer.data(),
                    &pathLength) != FALSE &&
                pathLength > 0U)
            {
                // imagePath/fileName：将完整路径转换为事件表中的短名称。
                const QString imagePath = QString::fromWCharArray(
                    pathBuffer.data(),
                    static_cast<int>(pathLength));
                const QString fileName = QFileInfo(imagePath).fileName();
                processText = fileName.isEmpty()
                    ? QStringLiteral("PID %1").arg(pid)
                    : QStringLiteral("%1 (%2)").arg(fileName).arg(pid);
            }
            ::CloseHandle(processHandle);
        }
    }

    // nextCacheEntry：查询失败时保留旧 identity，最多拒绝跳转而不会误开新进程。
    ProcessIdentityCacheEntry nextCacheEntry;
    nextCacheEntry.processText = processText;
    nextCacheEntry.creationTime100ns = identityQueryOk
        ? observedCreationTime100ns
        : (hasCachedEntry ? cachedEntry.creationTime100ns : 0U);
    nextCacheEntry.lastValidationTime = nowTime;
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        if (identityChanged)
        {
            m_moduleRangeCache.erase(pid);
            m_moduleRefreshTimes.erase(pid);
        }
        m_processNameCache[pid] = nextCacheEntry;
    }
    if (creationTime100nsOut != nullptr)
    {
        *creationTime100nsOut = nextCacheEntry.creationTime100ns;
    }
    return processText;
}

QString DirectKernelCallMonitorWidget::moduleNameForAddress(std::uint32_t pid, std::uint64_t addressValue)
{
    if (pid == 0 || addressValue == 0) { return QString(); }
    const auto now = std::chrono::steady_clock::now();
    bool refresh = true;
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        const auto stamp = m_moduleRefreshTimes.find(pid);
        const auto ranges = m_moduleRangeCache.find(pid);
        bool hit = false;
        if (ranges != m_moduleRangeCache.end())
        {
            for (const auto& range : ranges->second)
            {
                hit |= addressValue >= range.startAddress && addressValue < range.endAddress;
            }
        }
        if (stamp != m_moduleRefreshTimes.end())
        {
            refresh = now - stamp->second >= std::chrono::milliseconds(hit ? 1000 : 250);
        }
    }
    // Do not hold the cache lock while taking a potentially slow module snapshot.
    if (refresh) { refreshModuleRangesForPid(pid); }
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    const auto found = m_moduleRangeCache.find(pid);
    if (found != m_moduleRangeCache.end())
    {
        for (const auto& range : found->second)
        {
            if (addressValue >= range.startAddress && addressValue < range.endAddress) { return range.moduleName; }
        }
    }
    return QString();
}

void DirectKernelCallMonitorWidget::refreshModuleRangesForPid(std::uint32_t pid)
{
    std::vector<ModuleRange> ranges;
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (::Module32FirstW(snapshot, &entry))
        {
            do
            {
                ModuleRange range;
                range.startAddress = reinterpret_cast<std::uint64_t>(entry.modBaseAddr);
                range.endAddress = range.startAddress + entry.modBaseSize;
                range.moduleName = QString::fromWCharArray(entry.szModule);
                range.imagePath = QString::fromWCharArray(entry.szExePath);
                ranges.push_back(std::move(range));
            } while (::Module32NextW(snapshot, &entry));
        }
        ::CloseHandle(snapshot);
    }
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    m_moduleRangeCache[pid] = std::move(ranges);
    m_moduleRefreshTimes[pid] = std::chrono::steady_clock::now();
}

std::set<std::uint32_t> DirectKernelCallMonitorWidget::parsePidSet(const QString& text) const
{
    std::set<std::uint32_t> pidSet;
    const QStringList tokenList = text.split(QRegularExpression(QStringLiteral("[,;\\s]+")), Qt::SkipEmptyParts);
    for (const QString& token : tokenList)
    {
        QString normalized = token.trimmed();
        bool ok = false;
        std::uint32_t pid = 0;
        if (normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            pid = normalized.mid(2).toUInt(&ok, 16);
        }
        else
        {
            pid = normalized.toUInt(&ok, 10);
        }
        if (ok && pid != 0)
        {
            pidSet.insert(pid);
        }
    }
    return pidSet;
}

bool DirectKernelCallMonitorWidget::shouldCapturePid(std::uint32_t pid) const
{
    if (m_captureAllProcesses.load())
    {
        return true;
    }
    std::lock_guard<std::mutex> lock(m_captureConfigMutex);
    return pid != UINT32_MAX && m_capturePidSet.find(pid) != m_capturePidSet.end();
}

void DirectKernelCallMonitorWidget::flushPendingRows()
{
    if (m_eventTable == nullptr)
    {
        return;
    }

    // QMenu::exec() 会运行嵌套事件循环；定时刷新必须在读取待处理队列前进入
    // 表格提交门，否则前端裁剪会让菜单捕获的行号指向另一条事件。
    const QPointer<DirectKernelCallMonitorWidget> guardThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("direct-kernel-call-event-flush"),
        { m_eventTable },
        [guardThis]()
        {
            if (!guardThis.isNull())
            {
                guardThis->flushPendingRows();
            }
        }))
    {
        return;
    }

    std::vector<CapturedEventRow> rowList;
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        const std::size_t takeCount = std::min(kUiFlushRowLimit, m_pendingRows.size());
        rowList.reserve(takeCount);
        for (std::size_t index = 0; index < takeCount; ++index)
        {
            rowList.push_back(std::move(m_pendingRows.front()));
            m_pendingRows.pop_front();
        }
    }
    if (rowList.empty())
    {
        // Counters and setup failures must remain visible even with zero rows.
        updateStatusLabel();
        if (!m_captureRunning.load() && m_uiUpdateTimer != nullptr)
        {
            m_uiUpdateTimer->stop();
        }
        return;
    }

    const bool updatesEnabled = m_eventTable->updatesEnabled();
    m_eventTable->setUpdatesEnabled(false);
    QElapsedTimer budgetTimer;
    budgetTimer.start();
    std::size_t renderedCount = 0;
    for (const CapturedEventRow& rowValue : rowList)
    {
        appendEventRow(rowValue);
        ++renderedCount;
        if (budgetTimer.elapsed() >= kUiFlushBudgetMs)
        {
            break;
        }
    }
    const int maxRows = m_maxRowsSpin != nullptr ? m_maxRowsSpin->value() : 12000;
    const int removeCount = std::max(0, m_eventTable->rowCount() - maxRows);
    if (removeCount > 0 && m_eventTable->model() != nullptr)
    {
        m_eventTable->model()->removeRows(0, removeCount);
    }
    m_eventTable->setUpdatesEnabled(updatesEnabled);
    if (updatesEnabled && m_eventTable->viewport() != nullptr)
    {
        m_eventTable->viewport()->update();
    }

    if (renderedCount < rowList.size())
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        for (std::size_t index = rowList.size(); index > renderedCount; --index)
        {
            m_pendingRows.push_front(std::move(rowList[index - 1]));
        }
        while (m_pendingRows.size() > kPendingRowCapacity)
        {
            m_pendingRows.pop_back();
            ++m_pendingDroppedRows;
        }
    }

    applyFilter();
    updateActionState();
    updateStatusLabel();

    if (m_keepBottomCheck != nullptr && m_keepBottomCheck->isChecked())
    {
        m_eventTable->scrollToBottom();
    }
}

void DirectKernelCallMonitorWidget::appendEventRow(const CapturedEventRow& rowValue)
{
    const int row = m_eventTable->rowCount();
    m_eventTable->insertRow(row);

    QTableWidgetItem* timeItem = createReadOnlyItem(rowValue.time100nsText);
    timeItem->setData(kRoleProcessSearchText, QStringLiteral("%1 | %2").arg(rowValue.pidTidText, rowValue.processText));
    timeItem->setData(kRoleServiceSearchText, QStringLiteral("%1 | %2").arg(rowValue.syscallNumberText, rowValue.serviceName));
    timeItem->setData(kRoleGlobalSearchText, rowValue.globalSearchText);
    timeItem->setData(kRoleDetailDocument, QVariant::fromValue(rowValue.detailDocument));
    timeItem->setData(
        kRoleProcessCreationTime100ns,
        QVariant::fromValue<qulonglong>(rowValue.processCreationTime100ns));

    m_eventTable->setItem(row, EventColumnTime100ns, timeItem);
    m_eventTable->setItem(row, EventColumnPidTid, createReadOnlyItem(rowValue.pidTidText));
    m_eventTable->setItem(row, EventColumnProcess, createReadOnlyItem(rowValue.processText));
    m_eventTable->setItem(row, EventColumnSyscallNumber, createReadOnlyItem(rowValue.syscallNumberText));
    m_eventTable->setItem(row, EventColumnServiceName, createReadOnlyItem(rowValue.serviceName));
    m_eventTable->setItem(row, EventColumnVerdict, createReadOnlyItem(rowValue.verdictText));
    m_eventTable->setItem(row, EventColumnCallAddress, createReadOnlyItem(rowValue.callAddressText));
    m_eventTable->setItem(row, EventColumnEventName, createReadOnlyItem(rowValue.eventName));
    m_eventTable->setItem(row, EventColumnDetail, createReadOnlyItem(rowValue.detailText));
}

void DirectKernelCallMonitorWidget::scheduleFilterApply()
{
    if (m_filterDebounceTimer != nullptr)
    {
        m_filterDebounceTimer->start();
    }
}

void DirectKernelCallMonitorWidget::applyFilter()
{
    if (m_eventTable == nullptr)
    {
        return;
    }

    const QString processFilter = m_processFilterEdit != nullptr ? m_processFilterEdit->text() : QString();
    const QString serviceFilter = m_serviceFilterEdit != nullptr ? m_serviceFilterEdit->text() : QString();
    const QString detailFilter = m_detailFilterEdit != nullptr ? m_detailFilterEdit->text() : QString();
    const QString globalFilter = m_globalFilterEdit != nullptr ? m_globalFilterEdit->text() : QString();
    const bool useRegex = m_regexCheck != nullptr && m_regexCheck->isChecked();
    const bool invertMatch = m_invertCheck != nullptr && m_invertCheck->isChecked();
    const Qt::CaseSensitivity caseSensitivity =
        (m_caseCheck != nullptr && m_caseCheck->isChecked())
        ? Qt::CaseSensitive
        : Qt::CaseInsensitive;

    const bool hasTextFilter = !processFilter.trimmed().isEmpty()
        || !serviceFilter.trimmed().isEmpty()
        || !detailFilter.trimmed().isEmpty()
        || !globalFilter.trimmed().isEmpty();
    const bool requiresFiltering = hasTextFilter || invertMatch;
    if (!requiresFiltering)
    {
        if (m_filterActive)
        {
            for (int row = 0; row < m_eventTable->rowCount(); ++row)
            {
                m_eventTable->setRowHidden(row, false);
            }
        }
        m_filterActive = false;
        if (m_filterStatusLabel != nullptr)
        {
            m_filterStatusLabel->setText(QStringLiteral("筛选结果：%1 / %2")
                .arg(m_eventTable->rowCount())
                .arg(m_eventTable->rowCount()));
            ks::ui::ApplyStatusRole(m_filterStatusLabel,
                m_eventTable->rowCount() > 0 ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Idle);
        }
        return;
    }

    m_filterActive = true;

    int visibleCount = 0;
    for (int row = 0; row < m_eventTable->rowCount(); ++row)
    {
        QTableWidgetItem* timeItem = m_eventTable->item(row, EventColumnTime100ns);
        const QString processText = timeItem != nullptr ? timeItem->data(kRoleProcessSearchText).toString() : QString();
        const QString serviceText = timeItem != nullptr ? timeItem->data(kRoleServiceSearchText).toString() : QString();
        const QString globalText = timeItem != nullptr ? timeItem->data(kRoleGlobalSearchText).toString() : QString();
        const QString detailText = m_eventTable->item(row, EventColumnDetail) != nullptr
            ? m_eventTable->item(row, EventColumnDetail)->text()
            : QString();

        bool matched = textMatch(processText, processFilter, useRegex, caseSensitivity)
            && textMatch(serviceText, serviceFilter, useRegex, caseSensitivity)
            && textMatch(detailText, detailFilter, useRegex, caseSensitivity)
            && textMatch(globalText, globalFilter, useRegex, caseSensitivity);
        if (invertMatch)
        {
            matched = !matched;
        }

        m_eventTable->setRowHidden(row, !matched);
        if (matched)
        {
            ++visibleCount;
        }
    }

    if (m_filterStatusLabel != nullptr)
    {
        m_filterStatusLabel->setText(QStringLiteral("筛选结果：%1 / %2").arg(visibleCount).arg(m_eventTable->rowCount()));
        ks::ui::ApplyStatusRole(m_filterStatusLabel,
            visibleCount > 0 ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Idle);
    }
}

void DirectKernelCallMonitorWidget::clearFilter()
{
    const QSignalBlocker processBlocker(m_processFilterEdit);
    const QSignalBlocker serviceBlocker(m_serviceFilterEdit);
    const QSignalBlocker detailBlocker(m_detailFilterEdit);
    const QSignalBlocker globalBlocker(m_globalFilterEdit);
    const QSignalBlocker regexBlocker(m_regexCheck);
    const QSignalBlocker caseBlocker(m_caseCheck);
    const QSignalBlocker invertBlocker(m_invertCheck);

    if (m_processFilterEdit != nullptr)
    {
        m_processFilterEdit->clear();
    }
    if (m_serviceFilterEdit != nullptr)
    {
        m_serviceFilterEdit->clear();
    }
    if (m_detailFilterEdit != nullptr)
    {
        m_detailFilterEdit->clear();
    }
    if (m_globalFilterEdit != nullptr)
    {
        m_globalFilterEdit->clear();
    }
    if (m_regexCheck != nullptr)
    {
        m_regexCheck->setChecked(false);
    }
    if (m_caseCheck != nullptr)
    {
        m_caseCheck->setChecked(false);
    }
    if (m_invertCheck != nullptr)
    {
        m_invertCheck->setChecked(false);
    }
    applyFilter();
}

void DirectKernelCallMonitorWidget::exportVisibleRowsToTsv()
{
    if (m_eventTable == nullptr || m_eventTable->rowCount() == 0)
    {
        QMessageBox::information(this, QStringLiteral("导出"), QStringLiteral("当前没有可导出的事件。"));
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出直接内核调用事件"),
        QStringLiteral("direct-kernel-call-events.tsv"),
        QStringLiteral("TSV 文件 (*.tsv);;所有文件 (*.*)"));
    if (filePath.isEmpty())
    {
        return;
    }

    QFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        QMessageBox::warning(this, QStringLiteral("导出"), QStringLiteral("无法写入文件：%1").arg(filePath));
        return;
    }

    QTextStream stream(&outputFile);
    QStringList headerList;
    for (int column = 0; column < m_eventTable->columnCount(); ++column)
    {
        headerList << m_eventTable->horizontalHeaderItem(column)->text();
    }
    stream << headerList.join(QChar(u'\t')) << QChar(u'\n');

    for (int row = 0; row < m_eventTable->rowCount(); ++row)
    {
        if (m_eventTable->isRowHidden(row))
        {
            continue;
        }
        QStringList cellList;
        for (int column = 0; column < m_eventTable->columnCount(); ++column)
        {
            QString text = m_eventTable->item(row, column) != nullptr
                ? m_eventTable->item(row, column)->text()
                : QString();
            text.replace(QChar(u'\t'), QChar(u' '));
            text.replace(QChar(u'\n'), QChar(u' '));
            cellList << text;
        }
        stream << cellList.join(QChar(u'\t')) << QChar(u'\n');
    }
    outputFile.close();
}

void DirectKernelCallMonitorWidget::showEventContextMenu(const QPoint& position)
{
    if (m_eventTable == nullptr)
    {
        return;
    }
    QTableWidgetItem* itemPointer = m_eventTable->itemAt(position);
    if (itemPointer == nullptr)
    {
        return;
    }

    const int row = itemPointer->row();
    QMenu menu(this);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* detailAction = menu.addAction(QStringLiteral("查看详情"));
    QAction* copyRowAction = menu.addAction(QStringLiteral("复制当前行"));
    QAction* copyDetailAction = menu.addAction(QStringLiteral("复制详情"));
    const QTableWidgetItem* processIdItem = m_eventTable->item(row, EventColumnPidTid);
    std::uint32_t processId = 0;
    const bool hasProcessId = processIdItem != nullptr &&
        ks::online_scan::tryParsePidFromText(processIdItem->text().section(QChar(u'/'), 0, 0), &processId) &&
        processId != 0U;

    // processCreationTime100ns：从事件行角色读取捕获时的进程 identity。
    const QTableWidgetItem* const identityItem =
        m_eventTable->item(row, EventColumnTime100ns);
    const quint64 processCreationTime100ns = identityItem != nullptr
        ? identityItem->data(kRoleProcessCreationTime100ns).toULongLong()
        : 0U;

    // hasProcessIdentity：只有 PID 与创建时间都存在时才允许历史记录跳转。
    const bool hasProcessIdentity = hasProcessId && processCreationTime100ns != 0U;
    QAction* openProcessDetailAction = menu.addAction(QStringLiteral("转到进程详细信息"));
    openProcessDetailAction->setEnabled(hasProcessIdentity);
    if (hasProcessId && !hasProcessIdentity)
    {
        openProcessDetailAction->setToolTip(QStringLiteral(
            "无法验证该历史事件的进程创建时间；为避免 PID 复用后打开无关进程，已禁用跳转。"));
    }
    menu.addSeparator();
    ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [this, row]() -> ks::online_scan::SandboxUploadTarget {
            // 输入：直接内核调用事件表当前右键行。
            // 处理：从 PID/TID 列解析 PID，并查询该 PID 的进程镜像路径。
            // 返回：可上传文件路径；无法解析或进程路径不可读时返回 errorText。
            QTableWidgetItem* pidItem = m_eventTable != nullptr
                ? m_eventTable->item(row, EventColumnPidTid)
                : nullptr;
            std::uint32_t pidValue = 0;
            if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(
                    pidItem->text().section(QChar(u'/'), 0, 0), &pidValue))
            {
                return {
                    QString(),
                    QStringLiteral("直接内核调用事件"),
                    QStringLiteral("当前事件行未解析出有效 PID，无法上传发起进程文件。")
                };
            }

            const QString processPath = QString::fromStdString(ks::process::QueryProcessPathByPid(pidValue)).trimmed();
            if (processPath.isEmpty())
            {
                return {
                    QString(),
                    QStringLiteral("直接内核调用事件 PID=%1").arg(pidValue),
                    QStringLiteral("无法解析 PID=%1 的进程镜像路径。进程可能已退出，或当前权限不足。").arg(pidValue)
                };
            }

            return {
                processPath,
                QStringLiteral("直接内核调用事件 PID=%1").arg(pidValue),
                QString()
            };
        });
    QAction* selectedAction = menu.exec(m_eventTable->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == detailAction)
    {
        openEventDetailViewerForRow(row);
        return;
    }

    if (selectedAction == openProcessDetailAction)
    {
        ks::ui::OpenProcessDetailByIdentity(
            processId,
            processCreationTime100ns);
        return;
    }

    ks::ui::FieldDocument detailText;
    QTableWidgetItem* timeItem = m_eventTable->item(row, EventColumnTime100ns);
    if (timeItem != nullptr)
    {
        detailText = timeItem->data(kRoleDetailDocument).value<ks::ui::FieldDocument>();
    }
    if (selectedAction == copyDetailAction)
    {
        QApplication::clipboard()->setText(detailText.toPlainText(true));
        return;
    }

    if (selectedAction == copyRowAction)
    {
        QStringList cellList;
        for (int column = 0; column < m_eventTable->columnCount(); ++column)
        {
            cellList << (m_eventTable->item(row, column) != nullptr ? m_eventTable->item(row, column)->text() : QString());
        }
        QApplication::clipboard()->setText(cellList.join(QChar(u'\t')));
    }
}

void DirectKernelCallMonitorWidget::openEventDetailViewerForRow(int rowIndex)
{
    if (m_eventTable == nullptr || rowIndex < 0 || rowIndex >= m_eventTable->rowCount())
    {
        return;
    }
    QTableWidgetItem* timeItem = m_eventTable->item(rowIndex, EventColumnTime100ns);
    if (timeItem == nullptr)
    {
        return;
    }
    const ks::ui::FieldDocument detailText = timeItem->data(kRoleDetailDocument).value<ks::ui::FieldDocument>();
    monitor_text_viewer::showReadOnlyDocumentWindow(
        this,
        QStringLiteral("直接内核调用详情"),
        detailText,
        QStringLiteral("monitor/direct-kernel-call/%1.txt").arg(rowIndex + 1));
}
