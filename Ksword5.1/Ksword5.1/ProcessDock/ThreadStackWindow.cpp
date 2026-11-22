#include "ThreadStackWindow.h"
#include "ThreadDetailWindow.h"
#include "KernelDumpStackWindow.h"
#include "../UI/ToolbarMetrics.h"
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
#include "../UI/TablePresentation.h"
#include "../UI/ThemeStatusRole.h"
#include "../ArkDriverClient/ArkDriverClient.h"
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
#include <exception>
#include <cstdint>
#include <cstring>
#include <limits>
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

        if (basicInfo.tebBaseAddress != nullptr)
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

        if (tib.StackBase != nullptr)
        {
            target.userStackBase = reinterpret_cast<std::uint64_t>(tib.StackBase);
        }
        if (tib.StackLimit != nullptr)
        {
            target.userStackLimit = reinterpret_cast<std::uint64_t>(tib.StackLimit);
        }
        return true;
    }

    struct ModuleRange { std::uint64_t base = 0, end = 0; QString name; };
    std::vector<ModuleRange> snapshotModules(HANDLE process)
    {
        DWORD bytes = 0;
        (void)::EnumProcessModules(process, nullptr, 0, &bytes);
        std::vector<HMODULE> modules(bytes / sizeof(HMODULE));
        if (modules.empty() || !::EnumProcessModules(process, modules.data(), bytes, &bytes)) return {};
        modules.resize(std::min(modules.size(), static_cast<std::size_t>(bytes / sizeof(HMODULE))));
        std::vector<ModuleRange> ranges;
        for (const auto module : modules)
        {
            MODULEINFO info{};
            if (!::GetModuleInformation(process, module, &info, sizeof(info))) continue;
            wchar_t name[MAX_PATH]{};
            const DWORD count = ::GetModuleBaseNameW(process, module, name, MAX_PATH);
            const auto base = reinterpret_cast<std::uint64_t>(info.lpBaseOfDll);
            ranges.push_back({base, base + info.SizeOfImage, QString::fromWCharArray(name, static_cast<int>(count))});
        }
        return ranges;
    }

    struct CapturedStackMemory
    {
        std::uint64_t low = 0, high = 0, capturedLow = 0;
        std::vector<unsigned char> bytes;
    };
    thread_local const CapturedStackMemory* capturedStack = nullptr;
    BOOL CALLBACK readCapturedStack(HANDLE process, DWORD64 address, PVOID buffer, DWORD size, LPDWORD read)
    {
        if (read) *read = 0;
        const auto* snapshot = capturedStack;
        if (snapshot && address >= snapshot->low && address < snapshot->high)
        {
            if (address < snapshot->capturedLow || size > snapshot->high - address) return FALSE;
            const auto offset = static_cast<std::size_t>(address - snapshot->low);
            std::memcpy(buffer, snapshot->bytes.data() + offset, size);
            if (read) *read = size;
            return TRUE;
        }
        SIZE_T count = 0;
        const BOOL ok = ::ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), buffer, size, &count);
        if (read) *read = static_cast<DWORD>(count);
        return ok;
    }

    struct NativeHandle
    {
        HANDLE value;
        ~NativeHandle() { if (value && value != INVALID_HANDLE_VALUE) ::CloseHandle(value); }
    };

    // 输入冻结的窗口目标；调用与 CLI 相同的持句柄采集，不挂起线程、不回退到线索。
    // result 接收真实帧和原始回执；符号缺失只影响注释，不影响裸地址显示。
    void captureKernelThreadStack(ThreadStackWindow::CaptureResult& result)
    {
        const auto& target = result.enrichedTarget; // 当前操作绑定的身份，不读取列表缓存地址。
        result.queriedKernel = true;
        KSWORD_ARK_THREAD_STACK_REQUEST request{}; // 唯一协议只接受身份及预算，无任何内核地址。
        request.size = sizeof(request);
        request.version = KSWORD_ARK_THREAD_STACK_VERSION;
        request.processId = target.processId;
        request.threadId = target.threadId;
        request.expectedProcessCreationTime100ns = target.processCreationTime100ns;
        request.expectedThreadCreationTime100ns = target.threadCreationTime100ns;
        request.frameLimit = KSWORD_ARK_THREAD_STACK_MAX_FRAMES;
        request.timeoutMs = 1000;
        result.kernel = ksword::ark::DriverClient().captureVerifiedThreadStack(request);
        result.diagnosticText = QString::fromStdString(result.kernel.capture.io.message);
        for (const auto& frame : result.kernel.frames)
        {
            ThreadStackWindow::StackFrameRow row; // 每项必须来自一个真正的驱动返回地址。
            row.index = static_cast<std::uint32_t>(result.frames.size());
            row.address = frame.address;
            row.moduleName = QString::fromStdWString(frame.moduleName);
            row.symbolName = frame.symbolName.empty() ?
                (frame.moduleName.empty() ? QStringLiteral("<no symbol>") :
                    row.moduleName + QLatin1Char('+') + formatHex(frame.displacement)) :
                QString::fromStdWString(frame.symbolName);
            row.displacement = frame.displacement;
            row.modeText = result.kernel.usedSavedContext ? QStringLiteral("Kernel / Saved context") : QStringLiteral("Kernel / APC");
            result.frames.push_back(std::move(row));
        }
        result.ok = !result.frames.empty();
    }
    struct ThreadResume
    {
        HANDLE thread;
        bool suspended = false;
        ~ThreadResume() { resume(); }
        void resume() { if (suspended) { (void)::ResumeThread(thread); suspended = false; } }
    };
    struct SymbolCleanup
    {
        HANDLE process;
        bool initialized;
        ~SymbolCleanup() { if (initialized) ::SymCleanup(process); }
    };

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

        const NativeHandle processOwner{processHandle};
        HANDLE threadHandle = ::OpenThread(
            THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
            FALSE,
            inputTarget.threadId);
        if (threadHandle == nullptr)
        {
            result.diagnosticText = QStringLiteral("OpenThread failed %1").arg(::GetLastError());
            return result;
        }

        const NativeHandle threadOwner{threadHandle};
        if (::GetProcessIdOfThread(threadHandle) != inputTarget.processId)
        {
            result.diagnosticText = QStringLiteral("OpenThread failed %1").arg(ERROR_INVALID_OWNER);
            return result;
        }
        FILETIME processCreated{}, threadCreated{}, exited{}, kernel{}, user{};
        const bool processTimesOk = ::GetProcessTimes(processHandle, &processCreated, &exited, &kernel, &user);
        const bool threadTimesOk = ::GetThreadTimes(threadHandle, &threadCreated, &exited, &kernel, &user);
        const auto timeValue = [](const FILETIME& time) { return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32U) | time.dwLowDateTime; };
        const auto processTime = timeValue(processCreated), threadTime = timeValue(threadCreated);
        if (!processTimesOk || !threadTimesOk ||
            (inputTarget.processCreationTime100ns != 0 && inputTarget.processCreationTime100ns != processTime) ||
            (inputTarget.threadCreationTime100ns != 0 && inputTarget.threadCreationTime100ns != threadTime))
        {
            result.diagnosticText = QStringLiteral("OpenThread failed %1").arg(ERROR_INVALID_OWNER);
            return result;
        }
        result.enrichedTarget.processCreationTime100ns = processTime;
        result.enrichedTarget.threadCreationTime100ns = threadTime;
        (void)queryThreadBasicInfo(threadHandle, result.enrichedTarget, diagnosticLines);
        (void)readUserStackLimitsFromTeb(processHandle, result.enrichedTarget, diagnosticLines);
        CapturedStackMemory snapshot;
        snapshot.low = result.enrichedTarget.userStackLimit;
        snapshot.high = result.enrichedTarget.userStackBase;
        if (snapshot.low == 0 || snapshot.high <= snapshot.low ||
            snapshot.high - snapshot.low > std::numeric_limits<std::size_t>::max())
        {
            result.diagnosticText = QStringLiteral("Read TEB stack limits failed %1").arg(ERROR_INVALID_ADDRESS);
            return result;
        }
        // Allocate before pausing, including for a thread in this process.
        snapshot.bytes.resize(static_cast<std::size_t>(snapshot.high - snapshot.low));
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        ThreadResume resume{threadHandle};
        if (::SuspendThread(threadHandle) == static_cast<DWORD>(-1))
        {
            result.diagnosticText = QStringLiteral("SuspendThread failed %1").arg(::GetLastError());
            return result;
        }
        resume.suspended = true;
        const BOOL contextOk = ::GetThreadContext(threadHandle, &context);
        DWORD captureError = contextOk ? ERROR_SUCCESS : ::GetLastError();
#if defined(_M_X64)
        snapshot.capturedLow = context.Rsp;
#elif defined(_M_IX86)
        snapshot.capturedLow = context.Esp;
#else
        snapshot.capturedLow = 0;
#endif
        SIZE_T capturedBytes = 0;
        bool stackOk = contextOk && snapshot.capturedLow >= snapshot.low && snapshot.capturedLow < snapshot.high;
        if (stackOk)
        {
            const auto offset = static_cast<std::size_t>(snapshot.capturedLow - snapshot.low);
            const auto count = static_cast<std::size_t>(snapshot.high - snapshot.capturedLow);
            stackOk = ::ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(snapshot.capturedLow),
                snapshot.bytes.data() + offset, count, &capturedBytes) && capturedBytes == count;
            if (!stackOk) captureError = ::GetLastError();
        }
        else if (contextOk) captureError = ERROR_INVALID_ADDRESS;
        // No symbol lock, module enumeration, network symbol access or formatting
        // occurs while the target is stopped. The walk reads immutable stack bytes.
        resume.resume();
        if (!stackOk)
        {
            result.diagnosticText = QStringLiteral("GetThreadContext failed %1").arg(captureError);
            return result;
        }
        const auto modules = snapshotModules(processHandle);
        const std::lock_guard<std::mutex> symbolsLock(ks::dbghelp::SerializationMutex());
        const bool symbolsReady = initializeSymbols(processHandle, diagnosticLines);
        const SymbolCleanup symbols{processHandle, symbolsReady};
        struct StackReadScope
        {
            explicit StackReadScope(const CapturedStackMemory& memory) { capturedStack = &memory; }
            ~StackReadScope() { capturedStack = nullptr; }
        } stackReadScope(snapshot);

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
                readCapturedStack,
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
            for (const auto& module : modules)
            {
                if (row.address >= module.base && row.address < module.end)
                { moduleBase = module.base; row.moduleName = module.name; break; }
            }
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
    requestAsyncCapture(CaptureMode::Kernel);
}

void ThreadStackWindow::initializeUi()
{
    setObjectName(QStringLiteral("ThreadStackWindowRoot"));
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(true);
    // 根表面与表头仅由下方共享详情主题拥有，避免旧透明规则覆盖统一分层。
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

    m_refreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("R3 刷新"), this);
    m_refreshButton->setToolTip(QStringLiteral("仅重新捕获用户态调用栈"));
    ks::ui::ApplyFlatButtonTheme(m_refreshButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);

    m_kernelRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("R0 在线内核栈"), this);
    m_kernelRefreshButton->setToolTip(QStringLiteral("采集目标线程的原始保存内核栈；仅明确不支持时回退为 APC 诊断，不挂起线程"));
    ks::ui::ApplyFlatButtonTheme(m_kernelRefreshButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);

    // 真正的内核帧从显式选择的转储展开，不混入 R0 指针查询。
    auto* dumpStack = new QPushButton(QStringLiteral("打开内核转储"), this);
    dumpStack->setToolTip(QStringLiteral("从转储快照展开内核调用栈，不读取实时内核"));
    ks::ui::ApplyFlatButtonTheme(dumpStack, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
    connect(dumpStack, &QPushButton::clicked, this, [this]() { ShowKernelDumpStackWindow(this, m_target); });

    m_copyButton = new QPushButton(QIcon(":/Icon/process_copy_row.svg"), QString(), this);
    KswordTheme::ApplyCompactIconButtonMetrics(m_copyButton);
    m_copyButton->setToolTip(QStringLiteral("复制全部调用栈"));
    ks::ui::ApplyFlatButtonTheme(m_copyButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);

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
    m_toolbarLayout->addWidget(m_kernelRefreshButton);
    m_toolbarLayout->addWidget(dumpStack);
    m_toolbarLayout->addWidget(m_copyButton);
    m_toolbarLayout->addWidget(m_targetLabel, 1);
    ks::ui::NormalizeToolbarRow(m_toolbarLayout);

    m_boundaryLabel = new QLabel(this);
    m_boundaryLabel->setWordWrap(true);
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
    // 专业帧树不安装 QTableView 操作条（None）；复制由已有工具行和右键菜单承载。
    ks::ui::ApplyTablePresentation(m_frameTable);
    if (m_frameTable->header() != nullptr)
    {
        m_frameTable->header()->setSectionResizeMode(QHeaderView::Interactive);
        m_frameTable->header()->setStretchLastSection(true);
    }

    initializeColumnViews();
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
            requestAsyncCapture(CaptureMode::User);
        });
    connect(m_kernelRefreshButton, &QPushButton::clicked, this, [this]()
        {
            requestAsyncCapture(CaptureMode::Kernel);
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

void ThreadStackWindow::requestAsyncCapture(const CaptureMode mode)
{
    if (m_captureInProgress)
    {
        return;
    }

    m_captureInProgress = true;
    const std::uint64_t ticket = ++m_captureTicket;
    m_statusLabel->setText(QStringLiteral("● 正在捕获线程调用栈..."));
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:700;").arg(KswordTheme::PrimaryBlueHex));
    m_refreshButton->setEnabled(false);
    m_kernelRefreshButton->setEnabled(false);

    if (m_captureProgressPid == 0)
    {
        m_captureProgressPid = kPro.addReusable(this, "线程调用栈", "捕获调用栈");
    }
    kPro.set(m_captureProgressPid, "捕获调用栈", 0, 25.0f);

    const ThreadStackTarget targetSnapshot = m_target;
    QPointer<ThreadStackWindow> guardThis(this);
    auto* task = QRunnable::create([guardThis, ticket, targetSnapshot, mode]()
        {
            const auto started = std::chrono::steady_clock::now(); // 覆盖失败的 R3 路径与随后执行的 R0 路径。
            CaptureResult result{}; // 异常同样必须回到原提交入口，解除在途状态及两个刷新按钮。
            result.enrichedTarget = targetSnapshot;
            try
            {
                if (mode == CaptureMode::User)
                {
                    result = captureThreadStack(targetSnapshot);
                }
                if (mode == CaptureMode::Kernel)
                {
                    captureKernelThreadStack(result);
                }
            }
            catch (const std::exception& failure)
            {
                result = CaptureResult{}; // 异常中的半成品不能伪装为成功，也不能回退捕获另一个模式。
                result.enrichedTarget = targetSnapshot;
                result.queriedKernel = mode == CaptureMode::Kernel;
                result.kernel.capture.io.win32Error = ERROR_UNHANDLED_EXCEPTION;
                result.diagnosticText = QString::fromUtf8(failure.what());
            }
            catch (...)
            {
                result = CaptureResult{}; // 未分类的 C++ 失败仍通过同一 UI 完成路径结束，不吞成空成功。
                result.enrichedTarget = targetSnapshot;
                result.queriedKernel = mode == CaptureMode::Kernel;
                result.kernel.capture.io.win32Error = ERROR_UNHANDLED_EXCEPTION;
                result.diagnosticText = QStringLiteral("线程调用栈捕获失败");
            }
            result.elapsedMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started).count());
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
    m_refreshButton->setEnabled(true);
    m_kernelRefreshButton->setEnabled(true);

    m_target = result.enrichedTarget;
    m_frames = result.frames;
    m_queriedKernel = result.queriedKernel;
    m_kernelCapture = result.kernel;
    updateBoundaryText();
    rebuildFrameTable();

    // 只有保存上下文的真实用户机器帧边界才算完整；APC 诊断继续保留部分语义。
    QString statusText = result.queriedKernel
        ? describeKernelCapture(result)
        : result.ok ? QStringLiteral("● 捕获完成 %1 ms | 帧数 %2").arg(result.elapsedMs).arg(m_frames.size())
        : QStringLiteral("线程调用栈捕获失败");
    if (!result.diagnosticText.trimmed().isEmpty() && (!result.queriedKernel || !result.ok))
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
    m_statusLabel->setStyleSheet(QString());
    const bool completeKernel = result.kernel.usedSavedContext && result.kernel.capture.io.ok &&
        result.kernel.targetAliveAtReadback && result.kernel.capture.response.result == KSWORD_ARK_STACK_SNAPSHOT_COMPLETE; // 状态色必须依据同次验证回执。
    ks::ui::ApplyStatusRole(m_statusLabel, result.queriedKernel ? completeKernel ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning :
        result.ok ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
    kPro.set(m_captureProgressPid, "线程调用栈捕获完成", 0, 100.0f);

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

void ThreadStackWindow::copyAllFrames()
{
    QStringList lines;
    if (m_queriedKernel)
    {
        lines << m_statusLabel->text() << m_boundaryLabel->text(); // 导出保留不完整语义和同次采样来源。
    }
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
