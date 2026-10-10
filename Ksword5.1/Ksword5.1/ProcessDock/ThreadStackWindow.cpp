#include "ThreadStackWindow.h"
#include "../UI/FlatButtonTheme.h"

// ============================================================
// ThreadStackWindow.cpp
// 作用：
// - 使用 R3 线程挂起 + GetThreadContext + StackWalk64 捕获用户态调用栈；
// - 使用 DbgHelp 解析模块/符号，失败时降级为 module+offset 或裸地址；
// - 使用现有 R0 KTHREAD 字段展示内核栈边界辅助信息。
// ============================================================

#include "../theme.h"
#include "../UI/UI_All.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/DetailDialogChrome.h"
#include "../ksword/log/log.h"
#include "../ksword/dbghelp_serialization.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QThreadPool>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QResizeEvent>
#include <QSizePolicy>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Psapi.lib")

namespace
{
    using NtQueryInformationThreadFn = NTSTATUS(NTAPI*)(
        HANDLE,
        THREADINFOCLASS,
        PVOID,
        ULONG,
        PULONG);

    struct ThreadBasicInformationNative
    {
        NTSTATUS exitStatus = 0;
        PVOID tebBaseAddress = nullptr;
        CLIENT_ID clientId{};
        ULONG_PTR affinityMask = 0;
        LONG priority = 0;
        LONG basePriority = 0;
    };

    // formatHex 作用：统一格式化 64 位地址。
    // 参数 value：数值。
    // 参数 zeroAsUnavailable：是否把 0 显示为 Unavailable。
    // 返回：格式化文本。
    QString formatHex(const std::uint64_t value, const bool zeroAsUnavailable = false)
    {
        if (zeroAsUnavailable && value == 0)
        {
            return QStringLiteral("Unavailable");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 0, 16)
            .toUpper();
    }

    // buildOpaqueDialogStyle 作用：覆盖父级透明样式，保证栈窗口可读。
    // 参数 objectName：窗口 objectName。
    // 返回：QSS。
    QString buildOpaqueDialogStyle(const QString& objectName)
    {
        return QStringLiteral(
            "QDialog#%1{"
            "  background-color:palette(window) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QTreeWidget,"
            "QDialog#%1 QAbstractScrollArea,"
            "QDialog#%1 QAbstractScrollArea::viewport{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QHeaderView::section{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:palette(text) !important;"
            "}")
            .arg(objectName);
    }

    // queryThreadBasicInfo 作用：通过 NtQueryInformationThread 查询 TEB 和 ClientId。
    // 参数 threadHandle：线程句柄。
    // 参数 target：需要补齐的目标。
    // 参数 diagnosticOut：追加诊断。
    // 返回：true 表示查询成功。
    bool queryThreadBasicInfo(HANDLE threadHandle, ThreadStackTarget& target, QStringList& diagnosticOut)
    {
        HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdllModule == nullptr)
        {
            diagnosticOut << QStringLiteral("ntdll unavailable");
            return false;
        }

        auto ntQueryInformationThread = reinterpret_cast<NtQueryInformationThreadFn>(
            ::GetProcAddress(ntdllModule, "NtQueryInformationThread"));
        if (ntQueryInformationThread == nullptr)
        {
            diagnosticOut << QStringLiteral("NtQueryInformationThread unavailable");
            return false;
        }

        ThreadBasicInformationNative basicInfo{};
        const NTSTATUS status = ntQueryInformationThread(
            threadHandle,
            static_cast<THREADINFOCLASS>(0),
            &basicInfo,
            static_cast<ULONG>(sizeof(basicInfo)),
            nullptr);
        if (status < 0)
        {
            diagnosticOut << QStringLiteral("ThreadBasicInformation failed 0x%1")
                .arg(static_cast<quint32>(status), 8, 16, QChar('0')).toUpper();
            return false;
        }

        if (target.tebBaseAddress == 0)
        {
            target.tebBaseAddress = reinterpret_cast<std::uint64_t>(basicInfo.tebBaseAddress);
        }
        return true;
    }

    // readUserStackLimitsFromTeb 作用：从远程 TEB.NT_TIB 读取用户栈边界。
    // 参数 processHandle：进程句柄。
    // 参数 target：需要补齐的目标。
    // 参数 diagnosticOut：追加诊断。
    // 返回：true 表示读取成功。
    bool readUserStackLimitsFromTeb(HANDLE processHandle, ThreadStackTarget& target, QStringList& diagnosticOut)
    {
        if (processHandle == nullptr || target.tebBaseAddress == 0)
        {
            return false;
        }

        NT_TIB tib{};
        SIZE_T bytesRead = 0;
        const BOOL readOk = ::ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(target.tebBaseAddress),
            &tib,
            sizeof(tib),
            &bytesRead);
        if (readOk == FALSE || bytesRead < sizeof(PVOID) * 2)
        {
            diagnosticOut << QStringLiteral("Read TEB stack limits failed %1").arg(::GetLastError());
            return false;
        }

        if (target.userStackBase == 0)
        {
            target.userStackBase = reinterpret_cast<std::uint64_t>(tib.StackBase);
        }
        if (target.userStackLimit == 0)
        {
            target.userStackLimit = reinterpret_cast<std::uint64_t>(tib.StackLimit);
        }
        return true;
    }

    // queryModuleNameForAddress 作用：用 Psapi 查询地址所属模块名。
    // 参数 processHandle：进程句柄。
    // 参数 address：指令地址。
    // 参数 moduleBaseOut：接收模块基址。
    // 返回：模块名，失败返回空。
    QString queryModuleNameForAddress(HANDLE processHandle, const std::uint64_t address, std::uint64_t* moduleBaseOut)
    {
        if (moduleBaseOut != nullptr)
        {
            *moduleBaseOut = 0;
        }
        if (processHandle == nullptr || address == 0)
        {
            return QString();
        }

        HMODULE moduleHandle = nullptr;
        DWORD neededBytes = 0;
        if (::EnumProcessModules(processHandle, &moduleHandle, sizeof(moduleHandle), &neededBytes) == FALSE)
        {
            return QString();
        }

        const int moduleCount = static_cast<int>(neededBytes / sizeof(HMODULE));
        if (moduleCount <= 0)
        {
            return QString();
        }

        std::vector<HMODULE> modules(static_cast<std::size_t>(moduleCount));
        if (::EnumProcessModules(processHandle, modules.data(), neededBytes, &neededBytes) == FALSE)
        {
            return QString();
        }

        for (HMODULE currentModule : modules)
        {
            MODULEINFO moduleInfo{};
            if (::GetModuleInformation(processHandle, currentModule, &moduleInfo, sizeof(moduleInfo)) == FALSE)
            {
                continue;
            }

            const auto base = reinterpret_cast<std::uint64_t>(moduleInfo.lpBaseOfDll);
            const auto end = base + static_cast<std::uint64_t>(moduleInfo.SizeOfImage);
            if (address < base || address >= end)
            {
                continue;
            }

            wchar_t moduleName[MAX_PATH] = {};
            const DWORD chars = ::GetModuleBaseNameW(
                processHandle,
                currentModule,
                moduleName,
                static_cast<DWORD>(std::size(moduleName)));
            if (moduleBaseOut != nullptr)
            {
                *moduleBaseOut = base;
            }
            return chars > 0
                ? QString::fromWCharArray(moduleName, static_cast<int>(chars))
                : QStringLiteral("module+0x%1").arg(static_cast<qulonglong>(address - base), 0, 16).toUpper();
        }

        return QString();
    }

    // symbolPathText 作用：构造本进程 DbgHelp 符号路径。
    // 参数：无。
    // 返回：符号路径，默认包含本地缓存和 Microsoft symbol server。
    QString symbolPathText()
    {
        return QStringLiteral("srv*%TEMP%\\KswordSymbols*https://msdl.microsoft.com/download/symbols");
    }

    // initializeSymbols 作用：初始化 DbgHelp 符号会话。
    // 参数 processHandle：目标进程句柄。
    // 参数 diagnosticOut：追加诊断。
    // 返回：true 表示初始化成功。
    bool initializeSymbols(HANDLE processHandle, QStringList& diagnosticOut)
    {
        if (processHandle == nullptr)
        {
            return false;
        }

        ::SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
        const std::wstring path = symbolPathText().toStdWString();
        if (::SymInitializeW(processHandle, path.c_str(), TRUE) == FALSE)
        {
            diagnosticOut << QStringLiteral("SymInitialize failed %1").arg(::GetLastError());
            return false;
        }
        return true;
    }

    // resolveSymbol 作用：解析单个地址的符号名和偏移。
    // 参数 processHandle：目标进程句柄。
    // 参数 address：地址。
    // 参数 displacementOut：接收偏移。
    // 返回：符号名，失败返回空。
    QString resolveSymbol(HANDLE processHandle, const std::uint64_t address, std::uint64_t* displacementOut)
    {
        if (displacementOut != nullptr)
        {
            *displacementOut = 0;
        }
        if (processHandle == nullptr || address == 0)
        {
            return QString();
        }

        constexpr std::size_t symbolBufferSize = sizeof(SYMBOL_INFOW) + (MAX_SYM_NAME * sizeof(wchar_t));
        alignas(SYMBOL_INFOW) std::array<unsigned char, symbolBufferSize> symbolBuffer{};
        auto* symbolInfo = reinterpret_cast<SYMBOL_INFOW*>(symbolBuffer.data());
        symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
        symbolInfo->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (::SymFromAddrW(processHandle, static_cast<DWORD64>(address), &displacement, symbolInfo) == FALSE)
        {
            return QString();
        }

        if (displacementOut != nullptr)
        {
            *displacementOut = static_cast<std::uint64_t>(displacement);
        }
        return QString::fromWCharArray(symbolInfo->Name, static_cast<int>(symbolInfo->NameLen));
    }

    // captureThreadStack 作用：执行实际栈捕获和解析。
    // 参数 inputTarget：目标线程。
    // 返回：捕获结果。
    ThreadStackWindow::CaptureResult captureThreadStack(const ThreadStackTarget& inputTarget)
    {
        ThreadStackWindow::CaptureResult result{};
        result.enrichedTarget = inputTarget;
        QStringList diagnosticLines;
        const auto beginTime = std::chrono::steady_clock::now();

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            inputTarget.processId);
        if (processHandle == nullptr)
        {
            result.diagnosticText = QStringLiteral("OpenProcess failed %1").arg(::GetLastError());
            return result;
        }

        HANDLE threadHandle = ::OpenThread(
            THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
            FALSE,
            inputTarget.threadId);
        if (threadHandle == nullptr)
        {
            result.diagnosticText = QStringLiteral("OpenThread failed %1").arg(::GetLastError());
            ::CloseHandle(processHandle);
            return result;
        }

        (void)queryThreadBasicInfo(threadHandle, result.enrichedTarget, diagnosticLines);
        (void)readUserStackLimitsFromTeb(processHandle, result.enrichedTarget, diagnosticLines);

        // Serialize the entire DbgHelp session before suspending the thread.
        // Pool ETL and dump symbolization use the same process-wide lock.
        const std::lock_guard<std::mutex> symbolsLock(ks::dbghelp::SerializationMutex());
        const bool symbolsReady = initializeSymbols(processHandle, diagnosticLines);
        DWORD suspendResult = ::SuspendThread(threadHandle);
        if (suspendResult == static_cast<DWORD>(-1))
        {
            result.diagnosticText = QStringLiteral("SuspendThread failed %1").arg(::GetLastError());
            if (symbolsReady)
            {
                ::SymCleanup(processHandle);
            }
            ::CloseHandle(threadHandle);
            ::CloseHandle(processHandle);
            return result;
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (::GetThreadContext(threadHandle, &context) == FALSE)
        {
            diagnosticLines << QStringLiteral("GetThreadContext failed %1").arg(::GetLastError());
            (void)::ResumeThread(threadHandle);
            if (symbolsReady)
            {
                ::SymCleanup(processHandle);
            }
            ::CloseHandle(threadHandle);
            ::CloseHandle(processHandle);
            result.diagnosticText = diagnosticLines.join(QStringLiteral(" | "));
            return result;
        }

        STACKFRAME64 stackFrame{};
        DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
#if defined(_M_X64)
        machineType = IMAGE_FILE_MACHINE_AMD64;
        stackFrame.AddrPC.Offset = context.Rip;
        stackFrame.AddrPC.Mode = AddrModeFlat;
        stackFrame.AddrFrame.Offset = context.Rbp;
        stackFrame.AddrFrame.Mode = AddrModeFlat;
        stackFrame.AddrStack.Offset = context.Rsp;
        stackFrame.AddrStack.Mode = AddrModeFlat;
#elif defined(_M_IX86)
        machineType = IMAGE_FILE_MACHINE_I386;
        stackFrame.AddrPC.Offset = context.Eip;
        stackFrame.AddrPC.Mode = AddrModeFlat;
        stackFrame.AddrFrame.Offset = context.Ebp;
        stackFrame.AddrFrame.Mode = AddrModeFlat;
        stackFrame.AddrStack.Offset = context.Esp;
        stackFrame.AddrStack.Mode = AddrModeFlat;
#else
        diagnosticLines << QStringLiteral("unsupported architecture");
#endif

        constexpr int kMaxFrames = 128;
        for (int frameIndex = 0; frameIndex < kMaxFrames; ++frameIndex)
        {
            const BOOL walkOk = ::StackWalk64(
                machineType,
                processHandle,
                threadHandle,
                &stackFrame,
                &context,
                nullptr,
                SymFunctionTableAccess64,
                SymGetModuleBase64,
                nullptr);
            if (walkOk == FALSE || stackFrame.AddrPC.Offset == 0)
            {
                if (frameIndex == 0)
                {
                    diagnosticLines << QStringLiteral("StackWalk64 stopped %1").arg(::GetLastError());
                }
                break;
            }

            ThreadStackWindow::StackFrameRow row{};
            row.index = static_cast<std::uint32_t>(result.frames.size());
            row.address = static_cast<std::uint64_t>(stackFrame.AddrPC.Offset);
            std::uint64_t moduleBase = 0;
            row.moduleName = queryModuleNameForAddress(processHandle, row.address, &moduleBase);
            row.symbolName = symbolsReady ? resolveSymbol(processHandle, row.address, &row.displacement) : QString();
            if (row.symbolName.isEmpty())
            {
                row.symbolName = moduleBase != 0
                    ? QStringLiteral("%1+%2").arg(row.moduleName, formatHex(row.address - moduleBase))
                    : QStringLiteral("<no symbol>");
            }
            row.modeText = QStringLiteral("User");
            result.frames.push_back(std::move(row));
        }

        (void)::ResumeThread(threadHandle);
        if (symbolsReady)
        {
            ::SymCleanup(processHandle);
        }
        ::CloseHandle(threadHandle);
        ::CloseHandle(processHandle);

        result.ok = !result.frames.empty();
        result.elapsedMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - beginTime).count());
        result.diagnosticText = diagnosticLines.join(QStringLiteral(" | "));
        return result;
    }

    // columnIndex 作用：把列枚举转为整数。
    int columnIndex(const ThreadStackWindow::StackColumn column)
    {
        return static_cast<int>(column);
    }
}

ThreadStackWindow::ThreadStackWindow(const ThreadStackTarget& target, QWidget* parent)
    : QDialog(parent)
    , m_target(target)
{
    initializeUi();
    initializeConnections();
    requestAsyncCapture(true);
}

void ThreadStackWindow::initializeUi()
{
    setObjectName(QStringLiteral("ThreadStackWindowRoot"));
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(true);
    setStyleSheet(buildOpaqueDialogStyle(objectName()));
    setWindowTitle(QStringLiteral("线程调用栈 - TID %1").arg(m_target.threadId));
    ks::ui::applyResponsiveWindowGeometry(
        this,
        parentWidget(),
        QSize(980, 620),
        QSize(720, 480));

    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(8, 8, 8, 8);
    m_rootLayout->setSpacing(6);

    m_toolbarLayout = new QHBoxLayout();
    m_toolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolbarLayout->setSpacing(6);

    m_refreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), this);
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshButton);
    m_refreshButton->setToolTip(QStringLiteral("重新捕获调用栈"));
    m_refreshButton->setStyleSheet(ks::ui::BuildFlatButtonStyle() + QStringLiteral("QPushButton,QToolButton{border-radius:3px;padding:4px 10px;font-weight:600;}"));

    m_copyButton = new QPushButton(QIcon(":/Icon/process_copy_row.svg"), QString(), this);
    KswordTheme::ApplyCompactIconButtonMetrics(m_copyButton);
    m_copyButton->setToolTip(QStringLiteral("复制全部调用栈"));
    m_copyButton->setStyleSheet(ks::ui::BuildFlatButtonStyle() + QStringLiteral("QPushButton,QToolButton{border-radius:3px;padding:4px 10px;font-weight:600;}"));

    m_targetLabel = new QLabel(this);
    m_targetLabel->setMinimumWidth(0);
    m_targetLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_targetLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_targetLabel->setText(QStringLiteral("PID=%1 TID=%2 进程=%3 Start=%4 Win32Start=%5")
        .arg(m_target.processId)
        .arg(m_target.threadId)
        .arg(m_target.processName.trimmed().isEmpty() ? QStringLiteral("Unknown") : m_target.processName)
        .arg(formatHex(m_target.startAddress, true))
        .arg(formatHex(m_target.win32StartAddress, true)));
    m_targetLabel->setToolTip(m_targetLabel->text());
    m_targetLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextPrimaryHex()));

    m_toolbarLayout->addWidget(m_refreshButton);
    m_toolbarLayout->addWidget(m_copyButton);
    m_toolbarLayout->addWidget(m_targetLabel, 1);

    m_boundaryLabel = new QLabel(this);
    m_boundaryLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_boundaryLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    m_statusLabel = new QLabel(QStringLiteral("● 等待捕获"), this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setMinimumWidth(0);
    m_statusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    m_frameTable = new QTreeWidget(this);
    m_frameTable->setColumnCount(columnIndex(StackColumn::Count));
    m_frameTable->setHeaderLabels(QStringList{
        QStringLiteral("#"),
        QStringLiteral("地址"),
        QStringLiteral("模块"),
        QStringLiteral("符号"),
        QStringLiteral("偏移"),
        QStringLiteral("模式")
        });
    m_frameTable->setRootIsDecorated(false);
    m_frameTable->setItemsExpandable(false);
    m_frameTable->setAlternatingRowColors(true);
    m_frameTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_frameTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_frameTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_frameTable->setSortingEnabled(false);
    m_frameTable->setContextMenuPolicy(Qt::CustomContextMenu);
    if (m_frameTable->header() != nullptr)
    {
        m_frameTable->header()->setSectionResizeMode(QHeaderView::Interactive);
        m_frameTable->header()->setStretchLastSection(true);
    }

    m_rootLayout->addLayout(m_toolbarLayout);
    m_rootLayout->addWidget(m_boundaryLabel);
    m_rootLayout->addWidget(m_statusLabel);
    m_rootLayout->addWidget(m_frameTable, 1);
    updateBoundaryText();
    applyAdaptiveColumnWidths();
    ks::ui::ApplyDetailDialogChrome(this);
}

void ThreadStackWindow::initializeConnections()
{
    connect(m_refreshButton, &QPushButton::clicked, this, [this]()
        {
            requestAsyncCapture(true);
        });
    connect(m_copyButton, &QPushButton::clicked, this, [this]()
        {
            copyAllFrames();
        });
    connect(m_frameTable, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& position)
        {
            showFrameContextMenu(position);
        });
}

void ThreadStackWindow::requestAsyncCapture(const bool forceRefresh)
{
    if (m_captureInProgress)
    {
        if (forceRefresh)
        {
            m_capturePending = true;
        }
        return;
    }

    m_captureInProgress = true;
    const std::uint64_t ticket = ++m_captureTicket;
    m_statusLabel->setText(QStringLiteral("● 正在捕获线程调用栈..."));
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:700;").arg(KswordTheme::PrimaryBlueHex));
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(false);
    }

    if (m_captureProgressPid == 0)
    {
        m_captureProgressPid = kPro.addReusable(this, "线程调用栈", "捕获调用栈");
    }
    kPro.set(m_captureProgressPid, "挂起线程并执行 StackWalk64", 0, 25.0f);

    const ThreadStackTarget targetSnapshot = m_target;
    QPointer<ThreadStackWindow> guardThis(this);
    auto* task = QRunnable::create([guardThis, ticket, targetSnapshot]()
        {
            CaptureResult result = captureThreadStack(targetSnapshot);
            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, ticket, result]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->applyCaptureResult(ticket, result);
                },
                Qt::QueuedConnection);
        });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void ThreadStackWindow::applyCaptureResult(const std::uint64_t ticket, const CaptureResult& result)
{
    if (ticket < m_captureTicket)
    {
        return;
    }

    QPointer<ThreadStackWindow> guardThis(this);
    if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("thread-stack-capture-apply"),
            {m_frameTable},
            [guardThis, ticket, result]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->applyCaptureResult(ticket, result);
                }
            }))
    {
        return;
    }

    m_captureInProgress = false;
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(true);
    }

    m_target = result.enrichedTarget;
    m_frames = result.frames;
    updateBoundaryText();
    rebuildFrameTable();

    QString statusText = QStringLiteral("● 捕获完成 %1 ms | 帧数 %2")
        .arg(result.elapsedMs)
        .arg(m_frames.size());
    if (!result.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(" | 存在诊断；详情已写入日志。");
        kLogEvent diagnosticEvent;
        warn << diagnosticEvent
            << "[ThreadStackWindow] capture completed with diagnostics, pid="
            << m_target.processId
            << ", tid=" << m_target.threadId
            << ", frameCount=" << m_frames.size()
            << ", detail=" << result.diagnosticText.toStdString()
            << eol;
    }
    m_statusLabel->setText(statusText);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
        .arg((result.ok ? KswordTheme::SuccessColor() : KswordTheme::WarningColor()).name(QColor::HexRgb)));
    kPro.set(m_captureProgressPid, "线程调用栈捕获完成", 0, 100.0f);

    if (m_capturePending)
    {
        m_capturePending = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestAsyncCapture(true);
            }, Qt::QueuedConnection);
    }
}

void ThreadStackWindow::rebuildFrameTable()
{
    if (m_frameTable == nullptr)
    {
        return;
    }

    m_frameTable->clear();
    for (const StackFrameRow& frame : m_frames)
    {
        auto* item = new QTreeWidgetItem();
        item->setText(columnIndex(StackColumn::Index), QString::number(frame.index));
        item->setText(columnIndex(StackColumn::Address), formatHex(frame.address));
        item->setText(columnIndex(StackColumn::Module), frame.moduleName.trimmed().isEmpty() ? QStringLiteral("-") : frame.moduleName);
        item->setText(columnIndex(StackColumn::Symbol), frame.symbolName);
        item->setText(columnIndex(StackColumn::Offset), formatHex(frame.displacement));
        item->setText(columnIndex(StackColumn::Mode), frame.modeText);
        m_frameTable->addTopLevelItem(item);
    }
    if (m_frameTable->topLevelItemCount() > 0)
    {
        m_frameTable->setCurrentItem(m_frameTable->topLevelItem(0));
    }
    applyAdaptiveColumnWidths();
}

void ThreadStackWindow::updateBoundaryText()
{
    if (m_boundaryLabel == nullptr)
    {
        return;
    }

    m_boundaryLabel->setText(QStringLiteral("UserStack=%1 - %2 | TEB=%3 | R0 KernelStack=%4 StackBase=%5 StackLimit=%6 Initial=%7 | R0Status=%8 Cap=0x%9")
        .arg(formatHex(m_target.userStackLimit, true))
        .arg(formatHex(m_target.userStackBase, true))
        .arg(formatHex(m_target.tebBaseAddress, true))
        .arg(formatHex(m_target.r0KernelStack, true))
        .arg(formatHex(m_target.r0StackBase, true))
        .arg(formatHex(m_target.r0StackLimit, true))
        .arg(formatHex(m_target.r0InitialStack, true))
        .arg(m_target.r0ThreadStatus)
        .arg(static_cast<qulonglong>(m_target.r0CapabilityMask), 0, 16));
}

void ThreadStackWindow::copyAllFrames()
{
    QStringList lines;
    lines << QStringLiteral("#\tAddress\tModule\tSymbol\tOffset\tMode");
    for (const StackFrameRow& frame : m_frames)
    {
        lines << QStringLiteral("%1\t%2\t%3\t%4\t%5\t%6")
            .arg(frame.index)
            .arg(formatHex(frame.address))
            .arg(frame.moduleName)
            .arg(frame.symbolName)
            .arg(formatHex(frame.displacement))
            .arg(frame.modeText);
    }
    QApplication::clipboard()->setText(lines.join('\n'));
}

void ThreadStackWindow::copyCurrentFrame()
{
    if (m_frameTable == nullptr || m_frameTable->currentItem() == nullptr)
    {
        return;
    }

    QStringList fields;
    for (int column = 0; column < columnIndex(StackColumn::Count); ++column)
    {
        fields.push_back(m_frameTable->currentItem()->text(column));
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

void ThreadStackWindow::showFrameContextMenu(const QPoint& localPosition)
{
    if (m_frameTable == nullptr || m_frameTable->itemAt(localPosition) == nullptr)
    {
        return;
    }
    m_frameTable->setCurrentItem(m_frameTable->itemAt(localPosition));

    QMenu menu(this);
    // 调用栈菜单样式：
    // - 输入：当前帧表右键菜单；
    // - 处理：显式设置主题不透明样式，避免透明父容器下菜单文字不可读；
    // - 返回：无，只影响复制菜单展示。
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* copyFrameAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制当前帧"));
    QAction* copyAllAction = menu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制全部调用栈"));

    QAction* selectedAction = menu.exec(m_frameTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyFrameAction)
    {
        copyCurrentFrame();
    }
    else if (selectedAction == copyAllAction)
    {
        copyAllFrames();
    }
}

void ThreadStackWindow::resizeEvent(QResizeEvent* event)
{
    QDialog::resizeEvent(event);
    applyAdaptiveColumnWidths();
}

void ThreadStackWindow::applyAdaptiveColumnWidths()
{
    if (m_frameTable == nullptr)
    {
        return;
    }

    const int viewportWidth = m_frameTable->viewport()->width();
    const int indexWidth = 60;
    const int addressWidth = 150;
    const int moduleWidth = 170;
    const int offsetWidth = 110;
    const int modeWidth = 100;
    const int symbolWidth = std::max(320, viewportWidth - indexWidth - addressWidth - moduleWidth - offsetWidth - modeWidth - 24);

    m_frameTable->setColumnWidth(columnIndex(StackColumn::Index), indexWidth);
    m_frameTable->setColumnWidth(columnIndex(StackColumn::Address), addressWidth);
    m_frameTable->setColumnWidth(columnIndex(StackColumn::Module), moduleWidth);
    m_frameTable->setColumnWidth(columnIndex(StackColumn::Symbol), symbolWidth);
    m_frameTable->setColumnWidth(columnIndex(StackColumn::Offset), offsetWidth);
    m_frameTable->setColumnWidth(columnIndex(StackColumn::Mode), modeWidth);
}
