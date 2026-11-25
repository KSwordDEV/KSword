#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "ActionTransportValidation.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace ActionTransportValidation;

// 父端观察或子端读取共享计数；输入有效映射字段，输出原子快照，不改变数值。
LONG64 Load(volatile LONG64* value) {
    return InterlockedCompareExchange64(value, 0, 0);
}

// 单一 HANDLE 所有者；移动转移关闭责任，析构不接管线程的挂起责任。
class Handle {
    HANDLE value_ = nullptr; // 当前独占的句柄，空值不需要关闭。
public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() {
        reset();
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            reset();
            value_ = std::exchange(other.value_, nullptr);
        }
        return *this;
    }
    // 调用者仅借用句柄，不转移资源责任。
    HANDLE get() const {
        return value_;
    }
    // 接收新独占句柄前关闭旧资源；不得用于尚有在途 I/O 的缓冲区生命周期。
    void reset(HANDLE value = nullptr) {
        if (value_ && value_ != INVALID_HANDLE_VALUE) {
            CloseHandle(value_);
        }
        value_ = value;
    }
};
// Win32 调用失败时记错误并抛出，由外层 Session 统一清理；输入为刚返回的状态。
void Require(bool ok, const char* operation) {
    if (!ok) {
        const DWORD error = GetLastError();
        std::printf("API_FAILURE operation=%s win32=%lu\n", operation, error);
        throw std::runtime_error(operation);
    }
}
int assertions = 0; // 只在父进程主线程记录已执行断言数。
// 父端记录具名断言；失败立即展开栈，避免后续阶段掩盖当前失败。
void Check(bool ok, const char* name) {
    ++assertions;
    std::printf("ASSERT %s %s\n", ok ? "PASS" : "FAIL", name);
    std::fflush(stdout);
    if (!ok) {
        throw std::runtime_error(name);
    }
}
// 各阶段共享一个观察预算；left 把每项等待裁到剩余预算内。
struct Deadline {
    ULONGLONG until = GetTickCount64() + kStageBudget;
    DWORD left(DWORD maximum) const {
        const auto now = GetTickCount64();
        return now >= until ? 0 : static_cast<DWORD>(std::min<ULONGLONG>(maximum, until - now));
    }
};
// 调用者提供非阻塞观察条件和上限；返回条件是否满足，不把超时解释为普遍死锁。
template<class Predicate> bool Poll(Predicate predicate, DWORD milliseconds) {
    const ULONGLONG end = GetTickCount64() + milliseconds;
    do {
        if (predicate()) {
            return true;
        }
        Sleep(1);
    } while (GetTickCount64() < end);
    return predicate();
}
// 以零等待观察事件或进程是否结束，供所有有界循环调用。
bool Signaled(HANDLE event) {
    return WaitForSingleObject(event, 0) == WAIT_OBJECT_0;
}

// 字节流拆帧器保留部分帧；每次最多读七字节，显式覆盖短读而不假设消息边界。
class Reader {
    std::array<unsigned char, sizeof(Frame)> buffer_{}; // 尚未拼好的单帧内容。
    DWORD used_ = 0; // 已接收的有效字节，不随一次空读丢弃。
public:
    // 单个消费者调用；只读 Peek 确认可用的字节，完整帧才赋值输出并返回真。
    bool step(HANDLE pipe, Frame& frame) {
        DWORD available = 0;
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) || !available) {
            return false;
        }
        const DWORD request = std::min({ available, static_cast<DWORD>(sizeof(Frame)) - used_, DWORD{7} });
        DWORD received = 0;
        if (!ReadFile(pipe, buffer_.data() + used_, request, &received, nullptr) || !received) {
            return false;
        }
        used_ += received;
        if (used_ != sizeof(Frame)) {
            return false;
        }
        CopyMemory(&frame, buffer_.data(), sizeof(frame));
        used_ = 0;
        return true;
    }
    // 父端有界等待一帧，超时仍保留已读部分供下一次调用继续拼接。
    bool wait(HANDLE pipe, Frame& frame, DWORD timeout) {
        return Poll([&] { return step(pipe, frame); }, timeout);
    }
};
// 每阶段只向空的 4 KiB 管道写一条 64 字节命令/回执；五字节分片覆盖写入边界。
// 本函数只用于这些有容量保证的小帧，不承担遥测大包和通用生产背压策略。
bool WriteFrame(HANDLE pipe, const Frame& frame) {
    const auto* data = reinterpret_cast<const unsigned char*>(&frame);
    DWORD offset = 0;
    while (offset < sizeof(frame)) {
        const DWORD request = std::min(DWORD{5}, static_cast<DWORD>(sizeof(frame)) - offset);
        DWORD written = 0;
        if (!WriteFile(pipe, data + offset, request, &written, nullptr) || written == 0) {
            return false;
        }
        offset += written;
    }
    return true;
}
// 父子接收端核对固定头和会话身份；命令序号及线程身份由具体调用者追加校验。
bool Valid(const Frame& frame, std::uint64_t session, Kind kind, DWORD pid) {
    return frame.magic == kMagic && frame.version == 1 && frame.bytes == sizeof(Frame)
        && frame.session == session && frame.kind == kind && frame.pid == pid && frame.reserved == 0;
}

// 启动命令中的固定句柄顺序，也就是进程创建允许继承列表的全部条目。
enum Slot : size_t {
    CommandRead, AckWrite, TelemetryWrite, Stop, Go, Attempted,
    WriterDone, Mapping, ParentAlive, SlotCount
};
struct ChildState {
    std::array<HANDLE, SlotCount> handles{}; // 仅由父端显式继承，不扫描其它进程。
    Shared* shared = nullptr; // 工作线程全部结束前保持映射有效。
    Frame hello; // Go 事件发布前填完，工作线程之后只读。
    bool split = false; // false 为同一写入/消费线程的负控。
};
// 子端命令消费者：输入会话及管道，实际更新共享计数后才发送 Applied ACK。
void ControlLoop(ChildState& state) {
    Reader reader;
    while (!Signaled(state.handles[Stop]) && !Signaled(state.handles[ParentAlive])) {
        Frame command;
        if (reader.step(state.handles[CommandRead], command)) {
            if (!Valid(command, state.hello.session, Kind::Apply, GetCurrentProcessId()) || command.command == 0) {
                InterlockedExchange(&state.shared->childError, 1);
                SetEvent(state.handles[Stop]);
                break;
            }
            // 应用副作用和 ACK 严格分开，父端同时核对两者。
            Frame ack = state.hello;
            ack.kind = Kind::Applied;
            ack.command = command.command;
            ack.value = static_cast<std::uint64_t>(InterlockedIncrement64(&state.shared->applied));
            if (!WriteFrame(state.handles[AckWrite], ack)) {
                InterlockedExchange(&state.shared->childError, 2);
                break;
            }
        } else {
            Sleep(1);
        }
    }
}
// 子端遥测线程：一次同步写远大于管道配额；负控写返回后才允许消费命令。
// bulk 的寿命覆盖 WriteFile 全程；主线程取消后必须 join，不能提前销毁缓冲区。
DWORD WINAPI Writer(void* context) {
    auto& state = *static_cast<ChildState*>(context);
    std::vector<unsigned char> bulk(kBulkBytes);
    if (WaitForSingleObject(state.handles[Go], kStageBudget) != WAIT_OBJECT_0) {
        return 3;
    }
    if (Signaled(state.handles[Stop])) {
        return 0;
    }
    for (DWORD offset = 0; offset < kBulkBytes; offset += sizeof(Frame)) {
        Frame telemetry = state.hello;
        telemetry.kind = Kind::Telemetry;
        telemetry.value = offset / sizeof(Frame);
        CopyMemory(bulk.data() + offset, &telemetry, sizeof(telemetry));
    }
    // 事件只表示即将尝试；父端还必须看到管道中有字节且 WriterDone 未置位。
    SetEvent(state.handles[Attempted]);
    DWORD written = 0;
    const BOOL ok = WriteFile(state.handles[TelemetryWrite], bulk.data(), kBulkBytes, &written, nullptr);
    InterlockedExchange(&state.shared->writerError, static_cast<LONG>(ok ? ERROR_SUCCESS : GetLastError()));
    SetEvent(state.handles[WriterDone]);
    if (!state.split && !Signaled(state.handles[Stop])) {
        ControlLoop(state);
    }
    return 0;
}
// 正控专用子线程入口；Go 发布身份后进入有界轮询，不依赖遥测线程或业务锁。
DWORD WINAPI Control(void* context) {
    auto& state = *static_cast<ChildState*>(context);
    if (WaitForSingleObject(state.handles[Go], kStageBudget) != WAIT_OBJECT_0) {
        return 3;
    }
    ControlLoop(state);
    return 0;
}
// self-child 入口解析继承句柄；返回码向父端报告失败，业务主线程只做良性计数。
int Child(int argc, wchar_t** argv) {
    if (argc != static_cast<int>(SlotCount) + 4) {
        return 10;
    }
    ChildState state;
    state.split = wcscmp(argv[2], L"split") == 0;
    state.hello.session = _wcstoui64(argv[3], nullptr, 10);
    for (size_t index = 0; index < SlotCount; ++index) {
        state.handles[index] = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(_wcstoui64(argv[index + 4], nullptr, 10)));
        DWORD flags = 0;
        if (!GetHandleInformation(state.handles[index], &flags)) {
            return 11;
        }
    }
    state.shared = static_cast<Shared*>(MapViewOfFile(state.handles[Mapping], FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
    if (!state.shared) {
        return 12;
    }
    // 创建已声明工作线程；Go 未置位，身份在 Hello 发出前保持确定。
    state.hello.pid = GetCurrentProcessId();
    state.hello.mainTid = GetCurrentThreadId();
    Handle writer(CreateThread(nullptr, 0, Writer, &state, 0, &state.hello.writerTid));
    Handle control;
    if (state.split) {
        control.reset(CreateThread(nullptr, 0, Control, &state, 0, &state.hello.controlTid));
    } else {
        state.hello.controlTid = state.hello.writerTid;
    }
    int result = 0; // 启动失败也走同一停止、取消、等待路径。
    if (!writer.get() || (state.split && !control.get())) {
        result = 13;
    } else if (!WriteFrame(state.handles[AckWrite], state.hello)) {
        result = 14;
    }
    const auto end = GetTickCount64() + 4500;
    while (result == 0 && !Signaled(state.handles[Stop])
        && !Signaled(state.handles[ParentAlive]) && GetTickCount64() < end) {
        InterlockedIncrement64(&state.shared->businessTicks);
        Sleep(1);
    }
    // 无论正常停止或启动失败，先让门控线程退出，再取消同步 I/O 并确认完成。
    // CancelSynchronousIo 本身不是完成证明，线程成功结束才允许释放 Shared。
    SetEvent(state.handles[Stop]);
    SetEvent(state.handles[Go]);
    if (writer.get()) {
        CancelSynchronousIo(writer.get());
    }
    const DWORD writerWait = writer.get() ? WaitForSingleObject(writer.get(), 500) : WAIT_OBJECT_0;
    const DWORD controlWait = control.get() ? WaitForSingleObject(control.get(), 500) : WAIT_OBJECT_0;
    const bool clean = writerWait == WAIT_OBJECT_0 && controlWait == WAIT_OBJECT_0;
    if (!clean) {
        // 只终止当前夹具子进程，不展开仍被工作线程引用的栈和缓冲区。
        ExitProcess(15);
    }
    UnmapViewOfFile(state.shared);
    return result;
}

// CreateProcess 属性内存所有者；输入继承白名单，仅在进程创建调用期间使用。
class AttributeList {
    std::vector<unsigned char> storage_; // Windows 要求调用者提供的可变长属性缓冲区。
    LPPROC_THREAD_ATTRIBUTE_LIST list_ = nullptr;
public:
    explicit AttributeList(std::array<HANDLE, SlotCount>& handles) {
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        storage_.resize(bytes);
        auto* candidate = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
        Require(InitializeProcThreadAttributeList(candidate, 1, 0, &bytes) != FALSE, "attribute initialize");
        list_ = candidate;
        if (!UpdateProcThreadAttribute(list_, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handles.data(), handles.size() * sizeof(HANDLE), nullptr, nullptr)) {
            // 构造失败不会调用析构，必须在抛出前归还已初始化的属性资源。
            const DWORD error = GetLastError();
            DeleteProcThreadAttributeList(list_);
            list_ = nullptr;
            SetLastError(error);
            Require(false, "handle allowlist");
        }
    }
    ~AttributeList() {
        if (list_) {
            DeleteProcThreadAttributeList(list_);
        }
    }
    // 借用属性列表，仅用于当前进程创建调用。
    LPPROC_THREAD_ATTRIBUTE_LIST get() const {
        return list_;
    }
};
// 单次挂起责任：只归还自己增加的一次计数，不循环清空外部挂起状态。
struct Hold {
    HANDLE thread = nullptr; // 借用 Session 中已验证归属的线程句柄。
    bool owned = false; // 即使上下文读取失败，已取得的计数也必须恢复。
    DWORD tid = 0;
    CONTEXT context{};
    // 外部父控制器调用；SuspendThread 后再取上下文，二者都成功才可宣告停稳。
    bool acquire(HANDLE handle) {
        thread = handle;
        tid = GetThreadId(handle);
        const DWORD previous = SuspendThread(handle);
        if (previous == static_cast<DWORD>(-1)) {
            return false;
        }
        owned = true;
        context.ContextFlags = CONTEXT_CONTROL;
        return GetThreadContext(handle, &context) != FALSE;
    }
    // 正常放行和异常清理共用；失败时保留 owned，允许析构再尝试并报告失败。
    bool release() {
        if (!owned) {
            return true;
        }
        const DWORD previous = ResumeThread(thread);
        if (previous == static_cast<DWORD>(-1)) {
            return false;
        }
        owned = false;
        return previous >= 1;
    }
    ~Hold() {
        release();
    }
};

// 父端拥有一个精确自建子进程及其 IPC；异常展开时也先恢复、取消、确认退出。
class Session {
    Handle job_; // 父端独占且不继承；父进程退出关闭最后句柄时内核清理本组自有子进程。
    std::array<Handle, SlotCount> childHandles_; // 父端持有的继承源，独占子端管道端及时关闭。
    Handle process_, primary_, writer_, control_, telemetryRead_, commandWrite_, ackRead_;
    Shared* shared_ = nullptr; // 父端视图，必须晚于子进程退出释放。
    bool cleaned_ = false; // 防止正常清理后析构重复取消/等待。
    bool jobAssigned_ = false; // 未分配成功的子进程不得归还创建挂起计数开始执行。
    FILETIME creation_{}; // 随精确进程句柄记录创建身份，供证据关联。
    Reader ackReader_; // ACK 管道唯一消费者，保留部分帧。
public:
    std::array<Hold, 3> holds;
    Frame hello;
    DWORD pid = 0;
    std::uint64_t session = 0;
    DWORD capacity = 0;
    Session() = default;
    ~Session() {
        if (!cleaned_) {
            cleanup();
        }
        if (shared_) {
            UnmapViewOfFile(shared_);
        }
    }
    // 创建并验证当前 EXE 的子进程；输入线程拆分模式及剩余预算，失败统一抛出。
    void start(bool split, Deadline& deadline) {
        // Job 不使用可继承安全属性，也不进入 childHandles_ 或 HANDLE_LIST。
        // 若当前宿主的 Job 约束不允许嵌套分配，明确失败，不修改宿主或请求 breakaway。
        job_.reset(CreateJobObjectW(nullptr, nullptr));
        Require(job_.get() != nullptr, "create private noninherited job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimits{};
        jobLimits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        Require(SetInformationJobObject(job_.get(), JobObjectExtendedLimitInformation,
            &jobLimits, sizeof(jobLimits)) != FALSE, "set private job kill on close");

        SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
        // 每根管道只有一个读取者；只有明确列入白名单的子端允许继承。
        const auto pipe = [&](Handle& read, Handle& write) {
            HANDLE r = nullptr;
            HANDLE w = nullptr;
            Require(CreatePipe(&r, &w, &sa, kPipeCapacity) != FALSE, "CreatePipe");
            read.reset(r);
            write.reset(w);
        };
        pipe(childHandles_[CommandRead], commandWrite_);
        pipe(ackRead_, childHandles_[AckWrite]);
        pipe(telemetryRead_, childHandles_[TelemetryWrite]);
        for (HANDLE parent : { commandWrite_.get(), ackRead_.get(), telemetryRead_.get() }) {
            Require(SetHandleInformation(parent, HANDLE_FLAG_INHERIT, 0) != FALSE, "noninherited parent pipe");
        }
        // 手动复位事件只承担协调；匿名共享映射额外观察真实应用计数和业务停顿。
        for (size_t index : { size_t{Stop}, size_t{Go}, size_t{Attempted}, size_t{WriterDone} }) {
            childHandles_[index].reset(CreateEventW(&sa, TRUE, FALSE, nullptr));
            Require(childHandles_[index].get() != nullptr, "CreateEvent");
        }
        childHandles_[Mapping].reset(CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(Shared), nullptr));
        Require(childHandles_[Mapping].get() != nullptr, "CreateFileMapping");
        shared_ = static_cast<Shared*>(MapViewOfFile(childHandles_[Mapping].get(), FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
        Require(shared_ != nullptr, "parent MapViewOfFile");
        childHandles_[ParentAlive].reset(OpenProcess(SYNCHRONIZE, TRUE, GetCurrentProcessId()));
        Require(childHandles_[ParentAlive].get() != nullptr, "parent liveness handle");
        std::array<HANDLE, SlotCount> inherited{}; // 进程创建的完整白名单，不使用全局继承。
        for (size_t index = 0; index < SlotCount; ++index) {
            inherited[index] = childHandles_[index].get();
        }
        AttributeList attributes(inherited);
        // 仅从当前模块绝对路径启动，挂起创建后先校验进程和主线程身份。
        std::array<wchar_t, 32768> executable{};
        Require(GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size())) != 0, "self image");
        LARGE_INTEGER clock{};
        QueryPerformanceCounter(&clock);
        session = static_cast<std::uint64_t>(clock.QuadPart) ^ (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32);
        std::wstring command = L"\"" + std::wstring(executable.data()) + L"\" --child "
            + (split ? L"split " : L"shared ") + std::to_wstring(session);
        for (HANDLE handle : inherited) {
            command += L" " + std::to_wstring(reinterpret_cast<ULONG_PTR>(handle));
        }
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = attributes.get();
        PROCESS_INFORMATION info{};
        Require(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS,
            nullptr, nullptr, &startup.StartupInfo, &info) != FALSE, "self CreateProcess");
        process_.reset(info.hProcess);
        primary_.reset(info.hThread);
        pid = info.dwProcessId;
        // 创建挂起的计数也是本父进程所有，后续验证失败同样需要归还。
        holds[0].thread = primary_.get();
        holds[0].owned = true;
        FILETIME exit{}, kernel{}, user{};
        Require(GetProcessTimes(process_.get(), &creation_, &exit, &kernel, &user) != FALSE, "creation identity");
        std::array<wchar_t, 32768> image{};
        DWORD length = static_cast<DWORD>(image.size());
        Require(QueryFullProcessImageNameW(process_.get(), 0, image.data(), &length) != FALSE, "child image identity");
        Check(GetProcessId(process_.get()) == pid && GetProcessIdOfThread(primary_.get()) == pid
            && GetThreadId(primary_.get()) == info.dwThreadId
            && CompareStringOrdinal(image.data(), -1, executable.data(), -1, TRUE) == CSTR_EQUAL,
            "created_process_and_primary_thread_are_exact_self_child");
        // 在首次 ResumeThread 前加入专用 Job，冻结子线程也不影响内核退出兜底。
        Require(AssignProcessToJobObject(job_.get(), process_.get()) != FALSE, "assign suspended self child to private job");
        jobAssigned_ = true;
        DWORD jobHandleFlags = 0;
        BOOL inJob = FALSE;
        Require(GetHandleInformation(job_.get(), &jobHandleFlags) != FALSE, "read private job inheritance");
        Require(IsProcessInJob(process_.get(), job_.get(), &inJob) != FALSE, "read exact child job membership");
        Require(QueryInformationJobObject(job_.get(), JobObjectExtendedLimitInformation,
            &jobLimits, sizeof(jobLimits), nullptr) != FALSE, "read private job kill on close");
        Check((jobHandleFlags & HANDLE_FLAG_INHERIT) == 0 && inJob
            && (jobLimits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0,
            "private_noninherited_kill_on_close_job_assigned_before_first_resume");
        std::printf("JOB_GUARD pid=%lu assigned=1 inherited=0 kill_on_close=1 before_first_resume=1\n", pid);
        // 校验后运行子进程；Hello 只能提供候选 TID，还要按句柄核对所属进程。
        Require(holds[0].release(), "release initial creation hold");
        Check(ackReader_.wait(ackRead_.get(), hello, deadline.left(1200))
            && Valid(hello, session, Kind::Hello, pid) && hello.command == 0
            && hello.mainTid == info.dwThreadId && hello.writerTid != 0 && hello.controlTid != 0
            && hello.mainTid != hello.writerTid
            && (split ? hello.controlTid != hello.writerTid && hello.controlTid != hello.mainTid
                      : hello.controlTid == hello.writerTid),
            "hello_frame_session_and_created_process_correlate");
        constexpr DWORD rights = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_TERMINATE | SYNCHRONIZE;
        writer_.reset(OpenThread(rights, FALSE, hello.writerTid));
        control_.reset(OpenThread(rights, FALSE, hello.controlTid));
        Check(writer_.get() && control_.get() && GetProcessIdOfThread(writer_.get()) == pid
            && GetProcessIdOfThread(control_.get()) == pid
            && GetThreadId(writer_.get()) == hello.writerTid && GetThreadId(control_.get()) == hello.controlTid,
            "all_declared_worker_handles_belong_to_created_child");
        // 关闭父端多余副本，否则读取端关闭不能可靠中断子端写入。
        childHandles_[CommandRead].reset();
        childHandles_[AckWrite].reset();
        childHandles_[TelemetryWrite].reset();
        DWORD inputCapacity = 0;
        Require(GetNamedPipeInfo(telemetryRead_.get(), nullptr, &capacity, &inputCapacity, nullptr) != FALSE, "pipe capacity");
        capacity = std::max(capacity, inputCapacity);
        Check(capacity > 0 && kBulkBytes > capacity, "telemetry_write_exceeds_reported_pipe_capacity");
        Require(SetEvent(childHandles_[Go].get()) != FALSE, "start workers");
        // 不凭时间未返回判断背压：尝试事件、可见字节、未完成和业务已启动缺一不可。
        Check(Poll([&] {
            DWORD available = 0;
            return Signaled(childHandles_[Attempted].get())
                && PeekNamedPipe(telemetryRead_.get(), nullptr, 0, nullptr, &available, nullptr)
                && available > 0 && !Signaled(childHandles_[WriterDone].get()) && Load(&shared_->businessTicks) > 0;
        }, deadline.left(1200)), "attempt_event_and_buffered_bytes_with_writer_not_done");
        DWORD buffered = 0;
        Require(PeekNamedPipe(telemetryRead_.get(), nullptr, 0, nullptr, &buffered, nullptr) != FALSE, "saturation evidence");
        std::printf("SESSION pid=%lu session=%llu creation=%lu:%lu declared_tids=%lu,%lu,%lu capacity=%lu bulk=%lu buffered=%lu writer_done=0 split=%u\n",
            pid, session, creation_.dwHighDateTime, creation_.dwLowDateTime, hello.mainTid, hello.writerTid,
            hello.controlTid, capacity, kBulkBytes, buffered, split ? 1U : 0U);
    }
    // 父端每阶段投递一条命令；真仅表示管道写入成功，绝不表示子端已执行。
    bool enqueue(std::uint64_t commandId) {
        Frame command = hello;
        command.kind = Kind::Apply;
        command.command = commandId;
        return WriteFrame(commandWrite_.get(), command);
    }
    // 在剩余预算内接收并核对已应用回执，要求命令、会话、进程和线程身份一致。
    bool ack(std::uint64_t commandId, DWORD timeout) {
        Frame frame;
        return ackReader_.wait(ackRead_.get(), frame, timeout)
            && Valid(frame, session, Kind::Applied, pid) && frame.command == commandId && frame.value == 1
            && frame.mainTid == hello.mainTid && frame.writerTid == hello.writerTid && frame.controlTid == hello.controlTid;
    }
    // 负控窗口同时检查没有完整回执及独立共享副作用仍为零。
    bool noAck(DWORD timeout) {
        Frame frame;
        return !ackReader_.wait(ackRead_.get(), frame, timeout) && Load(&shared_->applied) == 0;
    }
    // 冻结前后调用，返回业务主线程的原子计数快照。
    LONG64 ticks() const {
        return Load(&shared_->businessTicks);
    }
    // 故障注入监督者按创建时间核验 PID，避免借名称或重用 PID 操作其它进程。
    ULONGLONG creationTime() const {
        ULARGE_INTEGER value{};
        value.LowPart = creation_.dwLowDateTime;
        value.HighPart = creation_.dwHighDateTime;
        return value.QuadPart;
    }
    // 仅表示自有写调用尚未返回，结合先前字节和尝试事件形成背压证据。
    bool writerBlocked() const {
        return !Signaled(childHandles_[WriterDone].get());
    }
    // 负控解除条件：完整读取大包并逐个校验固定帧，随后同一命令应能继续应用。
    bool drainTelemetry(DWORD timeout) {
        std::vector<unsigned char> bytes(kBulkBytes);
        DWORD consumed = 0;
        bool readFailed = false;
        const bool drained = Poll([&] {
            DWORD available = 0;
            if (!PeekNamedPipe(telemetryRead_.get(), nullptr, 0, nullptr, &available, nullptr)) {
                readFailed = true;
                return true;
            }
            if (available && consumed < kBulkBytes) {
                DWORD received = 0;
                if (!ReadFile(telemetryRead_.get(), bytes.data() + consumed,
                    std::min(available, kBulkBytes - consumed), &received, nullptr)) {
                    readFailed = true;
                    return true;
                }
                consumed += received;
            }
            return consumed == kBulkBytes && Signaled(childHandles_[WriterDone].get());
        }, timeout);
        if (!drained || readFailed || consumed != kBulkBytes) {
            return false;
        }
        // 原始读取可能跨多个帧，先凑足声明总长度，再按固定帧边界检查序号。
        for (DWORD offset = 0; offset < consumed; offset += sizeof(Frame)) {
            Frame frame;
            CopyMemory(&frame, bytes.data() + offset, sizeof(frame));
            if (!Valid(frame, session, Kind::Telemetry, pid) || frame.value != offset / sizeof(Frame)) {
                return false;
            }
        }
        std::printf("TELEMETRY_DRAIN bytes=%lu fixed_frames=%lu session=%llu\n", consumed,
            consumed / static_cast<DWORD>(sizeof(Frame)), session);
        return true;
    }
    // 只挂起事先登记的三个应用线程；全部上下文确认后才输出冻结完成断言。
    void freeze() {
        const std::array<HANDLE, 3> threads{ primary_.get(), writer_.get(), control_.get() };
        bool confirmed = true;
        for (size_t index = 0; index < threads.size(); ++index) {
            const bool held = holds[index].acquire(threads[index]);
            confirmed = confirmed && held;
            std::printf("HOLD tid=%lu owner_pid=%lu context_confirmed=%u rip=0x%llx own_count=%u\n",
                holds[index].tid, GetProcessIdOfThread(threads[index]), held ? 1U : 0U,
                holds[index].context.Rip, holds[index].owned ? 1U : 0U);
        }
        Check(confirmed, "external_parent_holds_all_three_declared_app_threads_with_context");
    }
    // 仅控制线程放行后复核业务线程现场与计数，输入冻结瞬间的业务快照。
    bool businessStillHeld(LONG64 frozenTicks) const {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        return holds[0].owned && holds[1].owned && !holds[2].owned
            && GetThreadContext(primary_.get(), &context) && context.Rip == holds[0].context.Rip
            && ticks() == frozenTicks && writerBlocked();
    }
    // 正常路径及异常析构共用：先恢复自有计数，再取消写入，最后确认进程退出。
    // 返回假会使验收失败；不能以 CancelSynchronousIo 返回成功代替 I/O 和进程完成。
    bool cleanup() {
        if (cleaned_) {
            return true;
        }
        cleaned_ = true;
        if (process_.get() && !jobAssigned_) {
            // 分配失败时子进程仍处于初始挂起，不能按正常恢复路径让未受保护的子端运行。
            // 只终止 CreateProcess 返回的精确句柄，确认终止后该已死线程无需恢复计数。
            const BOOL terminated = TerminateProcess(process_.get(), 98);
            const DWORD terminateError = terminated ? ERROR_SUCCESS : GetLastError();
            const bool exited = WaitForSingleObject(process_.get(), 200) == WAIT_OBJECT_0;
            if (exited) {
                holds[0].owned = false;
            }
            std::printf("CLEANUP_JOB_ASSIGN_FAILURE pid=%lu terminated=%u exited=%u win32=%lu\n",
                pid, terminated ? 1U : 0U, exited ? 1U : 0U, terminateError);
            return false;
        }
        bool released = true;
        for (auto& hold : holds) {
            released = hold.release() && released;
        }
        if (childHandles_[Stop].get()) {
            SetEvent(childHandles_[Stop].get());
        }
        DWORD cancelError = 0;
        if (writer_.get() && !CancelSynchronousIo(writer_.get())) {
            cancelError = GetLastError();
        }
        telemetryRead_.reset();
        commandWrite_.reset();
        // 正常退出必须从原始进程句柄确认；强制清理只针对该句柄且不计通过。
        bool exited = !process_.get() || WaitForSingleObject(process_.get(), 800) == WAIT_OBJECT_0;
        bool forced = false;
        if (!exited && GetProcessId(process_.get()) == pid) {
            // 绝不使用名称扫描或其它目标；即使成功强制结束，也保留失败结论。
            forced = true;
            if (!TerminateProcess(process_.get(), 99)) {
                std::printf("CLEANUP_TERMINATION_FAILURE pid=%lu win32=%lu\n", pid, GetLastError());
            }
            exited = WaitForSingleObject(process_.get(), 200) == WAIT_OBJECT_0;
        }
        DWORD exitCode = 0;
        if (process_.get() && !GetExitCodeProcess(process_.get(), &exitCode)) {
            exited = false;
        }
        const LONG childError = shared_ ? InterlockedCompareExchange(&shared_->childError, 0, 0) : 0;
        const LONG writerError = shared_ ? InterlockedCompareExchange(&shared_->writerError, 0, 0) : 0;
        std::printf("CLEANUP pid=%lu holds_released=%u exited=%u forced_termination=%u child_exit=%lu cancel_error=%lu writer_error=%ld child_error=%ld\n",
            pid, released ? 1U : 0U, exited ? 1U : 0U, forced ? 1U : 0U, exitCode, cancelError, writerError, childError);
        return released && exited && !forced && exitCode == 0 && childError == 0;
    }
};

// 父端顺序运行一个依赖实验；输入 1/2/3，任何断言失败都先展开 Session 清理。
void RunStage(unsigned int number) {
    std::printf("STAGE_BEGIN %u\n", number);
    const auto began = GetTickCount64();
    Deadline deadline;
    Session child;
    child.start(number != 1, deadline);
    if (number == 3) {
        // 冻结已含主业务线程和控制读取者，父进程自身始终保有恢复责任。
        child.freeze();
        const LONG64 frozenTicks = child.ticks();
        Check(child.enqueue(303), "frozen_child_command_303_queued_to_os_pipe");
        Check(child.noAck(deadline.left(250)) && child.ticks() == frozenTicks,
            "all_declared_app_threads_held_no_applied_state_or_ack");
        Check(child.holds[2].release(), "external_parent_releases_only_control_reader_own_hold");
        Check(child.ack(303, deadline.left(1200)), "command_303_applied_ack_after_control_only_release");
        Check(child.businessStillHeld(frozenTicks), "business_context_ticks_and_telemetry_hold_preserved_after_ack");
    } else {
        // 负控进一步排空遥测验证因果恢复；正控保持遥测堵塞直到清理。
        const auto command = number == 1 ? 101ULL : 202ULL;
        Check(child.enqueue(command), "command_fragmented_fixed_frame_queued_to_os_pipe");
        if (number == 1) {
            Check(child.noAck(deadline.left(250)) && child.writerBlocked(),
                "shared_sync_execution_consumer_blocked_before_command_apply");
            Check(child.drainTelemetry(deadline.left(1200)), "draining_backpressure_completes_correlated_telemetry_frames");
            Check(child.ack(command, deadline.left(1200)), "same_queued_command_101_applies_only_after_telemetry_drain");
        } else {
            Check(child.ack(command, deadline.left(1200)), "separate_control_reader_applied_correlated_ack_under_backpressure");
            Check(child.writerBlocked(), "telemetry_writer_still_not_done_when_control_ack_arrives");
        }
    }
    Check(child.cleanup(), "owned_child_clean_exit_all_parent_suspend_counts_released");
    const auto elapsed = GetTickCount64() - began;
    Check(elapsed < 5000, "stage_finished_within_five_second_limit");
    std::printf("STAGE_END %u elapsed_ms=%llu\n", number, elapsed);
}

// 仅供外部脚本杀死本精确夹具父进程；Job 是唯一子进程退出触发器。
// 若监督者未执行，十秒后走正常清理并失败，不永久留下持有停止责任的父进程。
void RunParentDeathTarget() {
    Deadline deadline;
    Session child;
    child.start(true, deadline);
    child.freeze();
    const LONG64 frozenTicks = child.ticks();
    Check(child.enqueue(404), "fault_target_command_queued_while_declared_threads_held");
    Check(child.noAck(deadline.left(250)) && child.ticks() == frozenTicks,
        "fault_target_no_apply_or_ack_with_all_declared_threads_held");
    std::printf("FAULT_READY parent_pid=%lu child_pid=%lu child_creation=%llu declared_held=3\n",
        GetCurrentProcessId(), child.pid, child.creationTime());
    std::fflush(stdout);
    Handle timeout(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Require(timeout.get() != nullptr, "fault target timeout event");
    WaitForSingleObject(timeout.get(), 10000);
    Check(false, "supervisor_must_kill_exact_fault_parent_before_deadline");
}
} // namespace

// 同一 EXE 的父/子入口；默认输出断言日志和最终退出码，子模式不操作任何第三方。
int wmain(int argc, wchar_t** argv) {
    if (argc > 1 && wcscmp(argv[1], L"--child") == 0) {
        return Child(argc, argv);
    }
    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    std::printf("SCOPE self_child_only declared_app_threads_only runtime_threads_excluded dependency_test_not_throughput\n");
    try {
        if (argc == 2 && wcscmp(argv[1], L"--parent-kill-target") == 0) {
            RunParentDeathTarget();
        }
        for (unsigned int stage = 1; stage <= 3; ++stage) {
            RunStage(stage);
        }
        std::printf("RESULT=PASS assertions=%d failures=0\n", assertions);
        return 0;
    } catch (const std::exception& error) {
        std::printf("RESULT=FAIL assertions=%d failure=%s\n", assertions, error.what());
        return 1;
    }
}
