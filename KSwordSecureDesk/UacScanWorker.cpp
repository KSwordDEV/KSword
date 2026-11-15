#include "UacScanWorker.h"

#include <QCoreApplication>
#include <QDataStream>
#include <QDir>
#include <QImage>
#include <QIODevice>
#include <QPixmap>
#include <QWinEventNotifier>

#include <array>
#include <cmath>
#include <cstring>
#include <vector>
#include <mutex>
#include <process.h>

namespace
{
    constexpr quint32 kMagic = 0x55414353;
    constexpr quint32 kVersion = 1;
    constexpr size_t kPayloadCapacity = 1024 * 1024;

    struct AttributeListLease
    {
        LPPROC_THREAD_ATTRIBUTE_LIST value;
        ~AttributeListLease() { DeleteProcThreadAttributeList(value); }
    };

    struct SharedScan
    {
        quint32 magic = kMagic;
        quint32 version = kVersion;
        DWORD parentPid = 0;
        DWORD sessionId = 0;
        quint64 parentCreation = 0;
        UacScanOriginHint originHint;
        quint64 request = 0;
        quint64 response = 0;
        quint32 payloadSize = 0;
        char payload[kPayloadCapacity];
    };

    struct CollectorOwner
    {
        std::array<HANDLE, 5> handles{};
        SharedScan* shared = nullptr;
        std::atomic_int exitCode{0};

        ~CollectorOwner()
        {
            if (shared) UnmapViewOfFile(shared);
            for (HANDLE handle : handles) if (handle) CloseHandle(handle);
        }
    };

    void writeProcess(QDataStream& stream, const ProcessIdentity& value)
    {
        stream << quint32(value.pid) << quint32(value.parentPid) << quint32(value.sessionId)
               << value.creationTime << value.imagePath << value.commandLine << value.fileDescription;
    }

    void readProcess(QDataStream& stream, ProcessIdentity& value)
    {
        quint32 pid = 0, parent = 0, session = 0;
        stream >> pid >> parent >> session >> value.creationTime >> value.imagePath
               >> value.commandLine >> value.fileDescription;
        value.pid = pid;
        value.parentPid = parent;
        value.sessionId = session;
    }

    QByteArray encode(const UacScanResult& result)
    {
        QByteArray bytes;
        QDataStream stream(&bytes, QIODevice::WriteOnly);
        stream.setVersion(QDataStream::Qt_6_0);
        const auto& identity = result.identity;
        const auto& state = result.actionState;
        stream << quint64(reinterpret_cast<quintptr>(identity.consentWindow)) << identity.windowRect
               << identity.displayName << identity.publisher << identity.imagePath << identity.matchText
               << identity.evidence << identity.observedAtMs << identity.exact << identity.isUac;
        writeProcess(stream, state.origin);
        stream << state.originResolved << state.launchChain << state.integrityLevel << state.elevationType
               << state.startTime << state.runDuration << state.originSignature << state.targetSignature;
        writeProcess(stream, state.target);
        stream << state.unique << state.protectedProcess << state.reason;

        // Resolve shell/icon engines inside the killable collector. Only a
        // small raw bitmap crosses back, so GUI decoding cannot invoke them.
        QByteArray pixels;
        quint32 iconWidth = 0, iconHeight = 0;
        double iconDpr = 1.0;
        if (!state.originIcon.isNull())
        {
            const QImage image = state.originIcon.pixmap(20, 20).toImage()
                .convertToFormat(QImage::Format_ARGB32);
            if (!image.isNull() && image.width() <= 256 && image.height() <= 256)
            {
                iconWidth = image.width();
                iconHeight = image.height();
                iconDpr = image.devicePixelRatio();
                pixels = QByteArray(reinterpret_cast<const char*>(image.constBits()), image.sizeInBytes());
            }
        }
        stream << iconWidth << iconHeight << iconDpr << pixels;
        return stream.status() == QDataStream::Ok && bytes.size() <= kPayloadCapacity ? bytes : QByteArray();
    }

    bool decode(const QByteArray& bytes, DWORD sessionId, UacScanResult& result)
    {
        QDataStream stream(bytes);
        stream.setVersion(QDataStream::Qt_6_0);
        auto& identity = result.identity;
        auto& state = result.actionState;
        quint64 hwnd = 0;
        stream >> hwnd >> identity.windowRect >> identity.displayName >> identity.publisher
               >> identity.imagePath >> identity.matchText >> identity.evidence >> identity.observedAtMs
               >> identity.exact >> identity.isUac;
        identity.consentWindow = reinterpret_cast<HWND>(static_cast<quintptr>(hwnd));
        readProcess(stream, state.origin);
        stream >> state.originResolved >> state.launchChain >> state.integrityLevel >> state.elevationType
               >> state.startTime >> state.runDuration >> state.originSignature >> state.targetSignature;
        readProcess(stream, state.target);
        stream >> state.unique >> state.protectedProcess >> state.reason;
        QByteArray pixels;
        quint32 iconWidth = 0, iconHeight = 0;
        double iconDpr = 1.0;
        stream >> iconWidth >> iconHeight >> iconDpr >> pixels;
        if (stream.status() != QDataStream::Ok || !stream.atEnd() ||
            iconWidth > 256 || iconHeight > 256 || !std::isfinite(iconDpr) || iconDpr <= 0 || iconDpr > 16 ||
            pixels.size() != static_cast<qsizetype>(iconWidth * iconHeight * 4) ||
            (pixels.isEmpty() && (iconWidth || iconHeight))) return false;
        if (state.originResolved && (!state.origin.isValid() || state.origin.sessionId != sessionId)) return false;
        if (state.unique && !state.originResolved) return false;
        state.protectedProcess = state.protectedProcess ||
            ProcessInspector::isProtectedName(state.origin.imagePath) || state.origin.pid == GetCurrentProcessId();
        if (!pixels.isEmpty())
        {
            const QImage image(reinterpret_cast<const uchar*>(pixels.constData()), iconWidth, iconHeight, QImage::Format_ARGB32);
            QImage owned = image.copy();
            owned.setDevicePixelRatio(iconDpr);
            state.originIcon = QIcon(QPixmap::fromImage(std::move(owned)));
        }
        return true;
    }

    quintptr argumentHandle(const QStringList& args, const QString& key)
    {
        for (const QString& arg : args)
            if (arg.startsWith(key)) return static_cast<quintptr>(arg.mid(key.size()).toULongLong());
        return 0;
    }

    bool isDirectParent(DWORD expected)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W entry{sizeof(entry)};
        bool matches = false;
        for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry))
            if (entry.th32ProcessID == GetCurrentProcessId())
            {
                matches = entry.th32ParentProcessID == expected;
                break;
            }
        CloseHandle(snapshot);
        return matches;
    }

    bool parentMatches(HANDLE parent, const SharedScan& shared)
    {
        if (!parent || shared.parentPid == 0 || shared.parentCreation == 0 ||
            GetProcessId(parent) != shared.parentPid || !isDirectParent(shared.parentPid) ||
            processCreationTime(parent) != shared.parentCreation || WaitForSingleObject(parent, 0) != WAIT_TIMEOUT)
            return false;
        DWORD sessionId = 0;
        if (!ProcessIdToSessionId(shared.parentPid, &sessionId) || sessionId != shared.sessionId ||
            sessionId != PrivilegeStage::currentSessionId()) return false;
        wchar_t path[32768] = {};
        DWORD length = static_cast<DWORD>(std::size(path));
        return QueryFullProcessImageNameW(parent, 0, path, &length) &&
            QDir::cleanPath(QString::fromWCharArray(path, length)).compare(
                QDir::cleanPath(QCoreApplication::applicationFilePath()), Qt::CaseInsensitive) == 0;
    }
}

struct UacScanWorker::NativeOwner
{
    HANDLE job = nullptr;
    HANDLE process = nullptr;
    HANDLE request = nullptr;
    HANDLE ready = nullptr;
    HANDLE stop = nullptr;
    HANDLE mapping = nullptr;
    HANDLE parent = nullptr;
    SharedScan* shared = nullptr;

    ~NativeOwner()
    {
        if (stop) SetEvent(stop);
        // KILL_ON_JOB_CLOSE covers only our suspended-then-assigned child and
        // its descendants, even if a COM provider or signature call is hung.
        // No in-process C++ thread or ETW owner is terminated or detached.
        if (job) CloseHandle(job);
        if (shared) UnmapViewOfFile(shared);
        for (HANDLE handle : {process, request, ready, stop, mapping, parent})
            if (handle) CloseHandle(handle);
    }
};

struct UacScanWorker::Startup
{
    QString executable;
    std::atomic_bool closed{false};
    std::mutex gate;
    bool done = false;
    std::unique_ptr<NativeOwner> result;
};

UacScanWorker::UacScanWorker(QObject* parent) : QObject(parent)
{
    connect(&m_startPoll, &QTimer::timeout, this, [this] { collectStartup(); });
}

UacScanWorker::~UacScanWorker() { close(); }

std::unique_ptr<UacScanWorker::NativeOwner> UacScanWorker::createNative(
    const QString& executable, const std::atomic_bool& closed)
{
    if (closed.load()) return {};
    auto native = std::make_unique<NativeOwner>();
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    native->request = CreateEventW(&security, FALSE, FALSE, nullptr);
    native->ready = CreateEventW(&security, FALSE, FALSE, nullptr);
    native->stop = CreateEventW(&security, TRUE, FALSE, nullptr);
    native->mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0, sizeof(SharedScan), nullptr);
    if (!native->request || !native->ready || !native->stop || !native->mapping) return {};
    native->shared = static_cast<SharedScan*>(MapViewOfFile(native->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedScan)));
    if (!native->shared || !DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(),
        &native->parent, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, 0)) return {};
    // The mapped region is private to this pair, never a named IPC endpoint.
    native->shared->magic = kMagic;
    native->shared->version = kVersion;
    native->shared->parentPid = GetCurrentProcessId();
    native->shared->sessionId = PrivilegeStage::currentSessionId();
    native->shared->parentCreation = processCreationTime(GetCurrentProcess());
    if (!native->shared->parentCreation) return {};
    native->job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!native->job || !SetInformationJobObject(native->job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        return {};

    const std::array<HANDLE, 5> inherited{native->request, native->ready, native->stop, native->mapping, native->parent};
    SIZE_T attributeSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
    std::vector<BYTE> attributeBuffer(attributeSize);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeBuffer.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize)) return {};
    const AttributeListLease attributeLease{attributes};
    const bool attributesOk = UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        const_cast<HANDLE*>(inherited.data()), sizeof(inherited), nullptr, nullptr) != FALSE;
    if (!attributesOk)
        return {};
    QString command = quoteArgument(executable) + QStringLiteral(" --ksword-uac-stage=collector");
    for (size_t index = 0; index < inherited.size(); ++index)
        command += QStringLiteral(" --ksword-scan-h%1=%2").arg(index).arg(reinterpret_cast<quintptr>(inherited[index]));
    std::wstring nativeCommand = command.toStdWString();
    const std::wstring nativeExecutable = executable.toStdWString();
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    wchar_t desktop[] = L"winsta0\\Winlogon";
    startup.StartupInfo.lpDesktop = desktop;
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION process{};
    // Duplicate this already verified SYSTEM/UIAccess primary token, rather
    // than asking a second privilege-stage launcher to discover another one.
    HANDLE sourceToken = nullptr;
    HANDLE primaryToken = nullptr;
    const bool tokenOk = !closed.load() && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &sourceToken) &&
        DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &primaryToken);
    if (sourceToken) CloseHandle(sourceToken);
    const bool created = tokenOk && !closed.load() && CreateProcessAsUserW(primaryToken, nativeExecutable.c_str(), nativeCommand.data(), nullptr, nullptr, TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
        &startup.StartupInfo, &process) != FALSE;
    if (primaryToken) CloseHandle(primaryToken);
    if (!created) return {};
    native->process = process.hProcess;
    const bool assigned = AssignProcessToJobObject(native->job, process.hProcess) != FALSE;
    const bool resumed = assigned && !closed.load() && ResumeThread(process.hThread) != static_cast<DWORD>(-1);
    CloseHandle(process.hThread);
    if (!resumed)
    {
        // This is the exact suspended process returned by our create call,
        // before any collector code runs. Never terminate a discovered PID.
        TerminateProcess(process.hProcess, ERROR_CANCELLED);
        return {};
    }
    // Retain only the parent endpoint handles; child inheritance is complete.
    for (HANDLE handle : inherited) SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
    return native;
}

bool UacScanWorker::start()
{
    auto startup = std::make_shared<Startup>();
    startup->executable = QCoreApplication::applicationFilePath();
    m_startup = startup;
    auto context = std::make_unique<std::shared_ptr<Startup>>(startup);
    // The native starter owns only values. Closing/destroying this controller
    // can abandon it even while the OS process-creation call has not returned.
    const uintptr_t thread = _beginthreadex(nullptr, 0, [](void* value) -> unsigned
    {
        const std::unique_ptr<std::shared_ptr<Startup>> context(
            static_cast<std::shared_ptr<Startup>*>(value));
        const auto& state = *context;
        std::unique_ptr<NativeOwner> native;
        try { native = createNative(state->executable, state->closed); }
        catch (...) { }
        {
            std::lock_guard lock(state->gate);
            if (!state->closed.load()) state->result = std::move(native);
            state->done = true;
        }
        return 0;
    }, context.get(), 0, nullptr);
    if (!thread) return false;
    context.release();
    CloseHandle(reinterpret_cast<HANDLE>(thread));
    m_startPoll.start(20); // Active only during initial/recovery startup.
    return true;
}

void UacScanWorker::collectStartup()
{
    if (m_closed || !m_startup) return;
    std::unique_ptr<NativeOwner> native;
    {
        std::lock_guard lock(m_startup->gate);
        if (!m_startup->done) return;
        native = std::move(m_startup->result);
    }
    m_startPoll.stop();
    m_startup.reset();
    if (!native) { finish(false); return; }
    try
    {
        m_native = std::move(native);
        m_ready = std::make_unique<QWinEventNotifier>(m_native->ready);
        m_exited = std::make_unique<QWinEventNotifier>(m_native->process);
        connect(m_ready.get(), &QWinEventNotifier::activated, this, [this](HANDLE) { finish(true); });
        connect(m_exited.get(), &QWinEventNotifier::activated, this, [this](HANDLE) { finish(false); });
    }
    catch (...) { finish(false); return; }
    sendRequest();
}

bool UacScanWorker::request(const UacScanOriginHint& originHint, std::function<void(UacScanResult)> completed)
{
    if (m_closed || m_busy) return false;
    if (GetTickCount64() < m_retryAfterMs) return false;
    m_busy = true;
    m_completed = std::move(completed);
    m_originHint = originHint;
    bool started = false;
    try
    {
        if (!m_native) started = start();
    }
    catch (...)
    {
        finish(false);
        return true;
    }
    if (!m_native)
    {
        if (!started) finish(false);
        return true;
    }
    sendRequest();
    return true;
}

void UacScanWorker::sendRequest()
{
    auto& shared = *m_native->shared;
    shared.payloadSize = 0;
    shared.response = 0;
    shared.request = ++m_sequence;
    shared.originHint = m_originHint;
    MemoryBarrier();
    if (!SetEvent(m_native->request)) finish(false);
}

void UacScanWorker::finish(bool success)
{
    if (m_closed) return;
    if (!m_busy)
    {
        if (!success)
        {
            discardProcess();
            m_retryAfterMs = GetTickCount64() + 1000;
        }
        return;
    }
    UacScanResult result;
    if (success && m_native)
    {
        MemoryBarrier();
        const auto& shared = *m_native->shared;
        success = shared.magic == kMagic && shared.version == kVersion &&
            shared.response == m_sequence && shared.payloadSize > 0 && shared.payloadSize <= kPayloadCapacity;
        if (success)
        {
            try { success = decode(QByteArray(shared.payload, shared.payloadSize), shared.sessionId, result); }
            catch (...) { success = false; }
        }
    }
    else success = false;
    if (!success)
    {
        result = {};
        discardProcess();
        // Repeated launch/authentication failures must not create a process
        // storm during the normal 75 ms UAC wake-up polling window.
        m_retryAfterMs = GetTickCount64() + 1000;
    }
    m_busy = false;
    auto completed = std::move(m_completed);
    // Invalid or crashed collection is a negative observation: use
    // the existing hide/disabled-actions path, never keep a stale prompt.
    if (completed) completed(std::move(result));
}

void UacScanWorker::discardProcess()
{
    m_startPoll.stop();
    if (m_startup) m_startup->closed = true;
    m_startup.reset();
    if (m_ready) m_ready->setEnabled(false);
    if (m_exited) m_exited->setEnabled(false);
    m_ready.reset();
    m_exited.reset();
    m_native.reset();
}

void UacScanWorker::close()
{
    if (m_closed) return;
    m_closed = true;
    m_completed = {};
    discardProcess();
    m_busy = false;
}

namespace
{
int collectorLoop(const std::shared_ptr<CollectorOwner>& owner)
{
    const auto& handles = owner->handles;
    auto* shared = owner->shared;
    const DWORD companionPid = shared->parentPid;
    const HANDLE waits[]{handles[2], handles[4], handles[0]};
    quint64 previous = 0;
    for (;;)
    {
        if (WaitForMultipleObjects(3, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 2) return 0;
        MemoryBarrier();
        const quint64 sequence = shared->request;
        if (!sequence || sequence <= previous) return 15;
        previous = sequence;
        UacScanCancellation budget{handles[2], handles[4]};
        UacScanResult result;
        try
        {
            if (!budget.canceled()) result = collectUacScan(companionPid, shared->originHint, budget);
            if (budget.canceled()) result = {};
            QByteArray bytes = encode(result);
            if (budget.canceled()) bytes = encode(UacScanResult{});
            if (bytes.isEmpty())
                shared->payloadSize = 0;
            else
            {
                std::memcpy(shared->payload, bytes.constData(), bytes.size());
                shared->payloadSize = static_cast<quint32>(bytes.size());
            }
        }
        catch (...)
        {
            shared->payloadSize = 0;
        }
        shared->response = sequence;
        MemoryBarrier();
        if (!SetEvent(handles[1])) return 16;
    }
}
}

int runUacScanCollector(const QStringList& args)
{
    // This branch never starts a monitor, acquires the companion owner mutex,
    // launches another privilege stage, creates business UI, or acts on a PID.
    if (!PrivilegeStage::isSystem() || !PrivilegeStage::hasUiAccess() ||
        PrivilegeStage::currentDesktopName().compare(QStringLiteral("Winlogon"), Qt::CaseInsensitive) != 0)
        return 12;
    auto owner = std::make_shared<CollectorOwner>();
    for (size_t index = 0; index < owner->handles.size(); ++index)
    {
        HANDLE handle = reinterpret_cast<HANDLE>(argumentHandle(args, QStringLiteral("--ksword-scan-h%1=").arg(index)));
        DWORD flags = 0;
        if (!handle || !GetHandleInformation(handle, &flags) || !(flags & HANDLE_FLAG_INHERIT)) return 13;
        for (size_t previous = 0; previous < index; ++previous)
            if (owner->handles[previous] == handle) return 13;
        owner->handles[index] = handle;
    }
    owner->shared = static_cast<SharedScan*>(MapViewOfFile(owner->handles[3], FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedScan)));
    if (!owner->shared) return 13;
    if (owner->shared->magic != kMagic || owner->shared->version != kVersion ||
        !parentMatches(owner->handles[4], *owner->shared)) return 14;
    for (HANDLE handle : owner->handles) SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);

    // Qt's GUI thread may initialize an STA. Preserve the old scanner's MTA
    // worker while the collector's own Qt loop services icon/platform requests.
    // This join exists only in the killable child, never in UacDeskWindow.
    std::thread worker([owner]
    {
        owner->exitCode.store(collectorLoop(owner));
        QMetaObject::invokeMethod(QCoreApplication::instance(), [] { QCoreApplication::quit(); }, Qt::QueuedConnection);
    });
    QCoreApplication::exec();
    SetEvent(owner->handles[2]);
    worker.join();
    return owner->exitCode.load();
}
