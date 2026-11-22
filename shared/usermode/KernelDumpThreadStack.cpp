#include "KernelDumpThreadStack.h"

#if defined(_WIN32) && defined(_M_X64)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <ShlObj.h>
#include <initguid.h>
#include <DbgEng.h>
#include <DbgHelp.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <cwchar>
#include <limits>
#include <mutex>
#include <string_view>
#include <utility>

#pragma comment(lib, "shell32.lib")

namespace
{
    using Microsoft::WRL::ComPtr;
    using ks::kernel_dump::ThreadStackStatus;

    // DbgEng 的会话、回调和符号操作全部由请求线程串行完成。
    std::mutex g_dumpSessionMutex;
    constexpr ULONG kOpenWaitMs = 30000;   // 首次等待的预算，不是整个符号操作的超时。
    constexpr std::size_t kOutputLimit = 32768; // 固定扩展回执的最大字符数。

    // 检查 DOS 绝对本地路径；不接受 URL、UNC、映射网络盘或设备路径。
    bool IsLocalAbsolute(const std::wstring& path)
    {
        if (path.size() < 4 || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/') ||
            path.find_first_of(L"\r\n", 3) != std::wstring::npos ||
            path.find(L'\0') != std::wstring::npos || path.find(L':', 2) != std::wstring::npos)
        {
            return false;
        }
        const wchar_t root[]{path[0], L':', L'\\', L'\0'}; // 只查询路径的根卷类型。
        const UINT driveType = GetDriveTypeW(root); // 禁止网络盘与未知卷。
        return driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE || driveType == DRIVE_RAMDISK;
    }

    // 返回受信加载目录；不从当前目录、PATH 或转储目录查找 DLL。
    std::wstring DebuggerDirectory(const std::wstring& configured)
    {
        if (!configured.empty())
        {
            return configured;
        }
        wchar_t programFiles[MAX_PATH]{}; // 系统登记的 32 位 Program Files 路径。
        if (FAILED(SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILESX86, nullptr, SHGFP_TYPE_CURRENT, programFiles)))
        {
            return {};
        }
        return std::wstring(programFiles) + L"\\Windows Kits\\10\\Debuggers\\x64";
    }

    // 只保留本次操作的常规文本；警告/错误另外作为部分展开的证据。
    class OutputSink final : public IDebugOutputCallbacksWide
    {
    public:
        // 实现 COM 查询；实例由会话作用域持有，不由回调删除。
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override
        {
            if (!object)
            {
                return E_POINTER;
            }
            *object = nullptr;
            if (iid != __uuidof(IUnknown) && iid != IID_IDebugOutputCallbacksWide)
            {
                return E_NOINTERFACE;
            }
            *object = static_cast<IDebugOutputCallbacksWide*>(this);
            AddRef();
            return S_OK;
        }

        // 记录引擎持有的回调引用；实际存储期由调用栈保证。
        ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(++references_); }
        ULONG STDMETHODCALLTYPE Release() override { return static_cast<ULONG>(--references_); }

        // 收集引擎分段写入的文本；不允许扩展回执无限增长。
        HRESULT STDMETHODCALLTYPE Output(ULONG mask, PCWSTR text) override
        {
            warning |= (mask & (DEBUG_OUTPUT_WARNING | DEBUG_OUTPUT_ERROR)) != 0;
            if (!text || !(mask & DEBUG_OUTPUT_NORMAL))
            {
                return S_OK;
            }
            while (*text && length_ != text_.size())
            {
                text_[length_++] = *text++;
            }
            truncated |= *text != L'\0';
            return S_OK;
        }

        // 开始新的命令阶段，旧输出不得参与线程身份判断。
        void Reset() noexcept
        {
            length_ = 0;
            warning = truncated = false;
        }

        // 返回当前阶段的非拥有文本，下一次 Reset 后失效。
        std::wstring_view Text() const noexcept { return {text_.data(), length_}; }

        bool warning = false;   // 当前阶段出现了引擎警告或错误。
        bool truncated = false; // 当前阶段的普通输出超过缓冲区。

    private:
        std::array<wchar_t, kOutputLimit> text_{}; // 有界回执缓冲区。
        std::size_t length_ = 0;                 // 已写入的字符数。
        ULONG references_ = 1;                  // 同一会话线程上的 COM 引用数。
    };

    // 保存引擎及会话引用；按回调仍存活、DLL 尚未卸载的顺序销毁。
    struct DumpSession
    {
        HMODULE engine = nullptr;       // 按绝对路径加载的 DbgEng。
        OutputSink output;              // 各阶段共用的有界回执。
        ComPtr<IDebugClient5> client;   // 转储入口及宽字符回调。
        bool opened = false;            // 已创建转储会话，退出时须结束。

        // 仅结束本对象打开的离线调试会话，不做任何运行控制。
        ~DumpSession()
        {
            if (client)
            {
                if (opened)
                {
                    client->EndSession(DEBUG_END_PASSIVE);
                }
                client->SetOutputCallbacksWide(nullptr);
                client.Reset();
            }
            if (engine)
            {
                FreeLibrary(engine);
            }
        }
    };

    struct ThreadRecord
    {
        ULONG64 address = 0; // 扩展返回的 ETHREAD，调用者不可指定。
        ULONG process = 0;   // Cid 的进程部分。
        ULONG thread = 0;    // Cid 的线程部分。
        unsigned count = 0;  // 结构化 THREAD 行数，必须恰好为 1。
    };

    // 去掉固定扩展格式中的空白，不按系统 locale 解释数字。
    void SkipSpace(std::wstring_view& text)
    {
        while (!text.empty() && (text.front() == L' ' || text.front() == L'\t'))
        {
            text.remove_prefix(1);
        }
    }

    // 解析调试器十六进制地址/标识，允许 x64 地址中的反引号分隔符。
    bool ReadHex(std::wstring_view& text, ULONG64& value)
    {
        if (text.starts_with(L"0x"))
        {
            text.remove_prefix(2);
        }
        value = 0;
        unsigned digits = 0; // x64 数值最多 16 个有效十六进制字符。
        while (!text.empty())
        {
            const wchar_t ch = text.front(); // 当前待读字符。
            if (ch == L'`' && digits == 8)
            {
                text.remove_prefix(1);
                continue;
            }
            const int digit = ch >= L'0' && ch <= L'9' ? ch - L'0' :
                ch >= L'a' && ch <= L'f' ? ch - L'a' + 10 :
                ch >= L'A' && ch <= L'F' ? ch - L'A' + 10 : -1;
            if (digit < 0)
            {
                break;
            }
            if (++digits > 16)
            {
                return false;
            }
            value = (value << 4) | static_cast<unsigned>(digit);
            text.remove_prefix(1);
        }
        return digits != 0;
    }

    // 校验唯一 THREAD/Cid 行；重复、畸形或失败回执不能授权切换上下文。
    ThreadRecord ParseThread(std::wstring_view text)
    {
        ThreadRecord record{}; // 未发现 THREAD 行时保持零值。
        while (!text.empty())
        {
            const auto end = text.find(L'\n'); // 调试器回执允许 CRLF。
            auto line = text.substr(0, end);   // 单行视图，不复制输出。
            text = end == text.npos ? std::wstring_view{} : text.substr(end + 1);
            SkipSpace(line);
            if (!line.starts_with(L"THREAD "))
            {
                continue;
            }
            ++record.count;
            line.remove_prefix(7);
            SkipSpace(line);
            ULONG64 address = 0, pid = 0, tid = 0; // 本行的 ETHREAD 与 Cid。
            if (!ReadHex(line, address))
            {
                continue;
            }
            SkipSpace(line);
            if (!line.starts_with(L"Cid ") && !line.starts_with(L"Cid:"))
            {
                continue;
            }
            line.remove_prefix(4);
            SkipSpace(line);
            if (!ReadHex(line, pid) || line.empty() || line.front() != L'.')
            {
                continue;
            }
            line.remove_prefix(1);
            constexpr auto kMaxId = std::numeric_limits<ULONG>::max(); // Cid 的公开 Windows ID 宽度。
            if (!ReadHex(line, tid) || pid > kMaxId || tid > kMaxId ||
                (!line.empty() && line.front() != L' ' && line.front() != L'\t' && line.front() != L'\r'))
            {
                continue;
            }
            record.address = address;
            record.process = static_cast<ULONG>(pid);
            record.thread = static_cast<ULONG>(tid);
        }
        return record;
    }

    // 复核 .thread 明确设置的线程；没有确认文本时禁止继续到默认 CPU。
    bool ConfirmExplicitThread(std::wstring_view text, ULONG64 expected)
    {
        constexpr std::wstring_view marker = L"Implicit thread is now "; // 微软调试器固定回执前缀。
        const auto offset = text.find(marker);
        if (offset == text.npos)
        {
            return false;
        }
        text.remove_prefix(offset + marker.size());
        ULONG64 selected = 0; // 回执中的对象地址，不来自用户参数。
        return ReadHex(text, selected) && selected == expected &&
            (text.empty() || text.front() == L'\r' || text.front() == L'\n');
    }

    // 读取固定 r rip,rsp 回执；必须标为上次显式设置的上下文。
    bool ParseExplicitRegisters(std::wstring_view text, ULONG64& ip, ULONG64& sp)
    {
        constexpr std::wstring_view marker = L"Last set context:";
        const auto context = text.find(marker);
        if (context == text.npos)
        {
            return false;
        }
        text.remove_prefix(context + marker.size());
        const auto position = text.find(L"rip=");
        if (position == text.npos)
        {
            return false;
        }
        text.remove_prefix(position + 4);
        if (!ReadHex(text, ip))
        {
            return false;
        }
        SkipSpace(text);
        if (!text.starts_with(L"rsp="))
        {
            return false;
        }
        text.remove_prefix(4);
        return ReadHex(text, sp) && (text.empty() || text.front() == L'\r' || text.front() == L'\n');
    }

    // 只求值内部组装的固定 C++ 类型字段，不接受来自用户的表达式。
    HRESULT EvaluateScalar(IDebugControl4& control, const std::wstring& expression, ULONG64& result)
    {
        DEBUG_VALUE value{};  // 调试引擎转换后的 64 位标量。
        ULONG consumed = 0;  // 要求引擎消费完整表达式。
        const HRESULT hr = control.EvaluateWide(expression.c_str(), DEBUG_VALUE_INT64, &value, &consumed);
        if (hr != S_OK || value.Type != DEBUG_VALUE_INT64 || consumed != expression.size())
        {
            return FAILED(hr) ? hr : E_FAIL;
        }
        result = value.I64;
        return S_OK;
    }

    // AMD64 原生内核地址位于线性地址空间上半区；不发布用户栈帧。
    bool IsKernelAddress(ULONG64 value) noexcept { return (value >> 63) != 0; }
}
#endif

namespace ks::kernel_dump
{
    ThreadStackResult UnwindThreadStack(const ThreadStackRequest& request)
    {
        ThreadStackResult result{}; // 失败回执也保留请求身份和来源。
        result.dumpPath = request.dumpPath;
        result.processId = request.processId;
        result.threadId = request.threadId;
#if defined(_WIN32) && defined(_M_X64)
        // 统一设置失败状态；线程核验或上下文失败不留下任何帧。
        const auto fail = [&result](ThreadStackStatus status, HRESULT error, const wchar_t* text)
        {
            result.status = status;
            result.hresult = static_cast<std::uint32_t>(error);
            result.diagnostic = text;
            return std::move(result);
        };

        if (!request.processId || !request.threadId || !request.frameLimit ||
            request.frameLimit > MaxThreadStackFrames || !IsLocalAbsolute(request.dumpPath) ||
            (!request.debuggerDirectory.empty() && !IsLocalAbsolute(request.debuggerDirectory)) ||
            request.symbolPath.find(L'\0') != std::wstring::npos)
        {
            return fail(ThreadStackStatus::InvalidRequest, E_INVALIDARG, L"Invalid local dump path, target identity, or frame limit.");
        }

        const auto directory = DebuggerDirectory(request.debuggerDirectory); // 可信工具安装目录。
        if (!IsLocalAbsolute(directory) || directory.find(L';') != std::wstring::npos)
        {
            return fail(ThreadStackStatus::EngineUnavailable, E_INVALIDARG, L"The x64 Debugging Tools directory is unavailable.");
        }
        const std::lock_guard lock(g_dumpSessionMutex); // 同一进程中的转储请求不并行。
        DumpSession session; // 会话只存在于本次后台调用中。
        const auto enginePath = directory + L"\\dbgeng.dll"; // 禁止隐式降级到系统旧版本。
        session.engine = LoadLibraryExW(enginePath.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!session.engine)
        {
            return fail(ThreadStackStatus::EngineUnavailable, HRESULT_FROM_WIN32(GetLastError()), L"Cannot load x64 Debugging Tools (dbgeng.dll).");
        }
        const FARPROC exportAddress = GetProcAddress(session.engine, "DebugCreate"); // 唯一动态解析的入口。
        if (!exportAddress)
        {
            return fail(ThreadStackStatus::EngineUnavailable, HRESULT_FROM_WIN32(GetLastError()), L"DebugCreate is unavailable.");
        }
        decltype(&DebugCreate) create = nullptr; // 用 SDK 声明保留 Windows 调用约定。
        static_assert(sizeof(create) == sizeof(exportAddress));
        std::memcpy(&create, &exportAddress, sizeof(create));
        HRESULT hr = create(IID_IDebugClient5, reinterpret_cast<void**>(session.client.GetAddressOf()));
        if (FAILED(hr) || !session.client)
        {
            return fail(ThreadStackStatus::EngineUnavailable, hr, L"Cannot create a DbgEng client.");
        }

        // 在 session 之前释放这些接口引用，再卸载 DLL。
        ComPtr<IDebugControl4> control;    // 离线目标、固定扩展和展开操作。
        ComPtr<IDebugSymbols3> symbols;    // 符号路径、模块及帧名称。
        if (FAILED(hr = session.client->QueryInterface(IID_PPV_ARGS(control.GetAddressOf()))) ||
            FAILED(hr = session.client->QueryInterface(IID_PPV_ARGS(symbols.GetAddressOf()))) ||
            FAILED(hr = session.client->SetOutputCallbacksWide(&session.output)) ||
            FAILED(hr = session.client->SetOutputMask(DEBUG_OUTPUT_NORMAL | DEBUG_OUTPUT_WARNING | DEBUG_OUTPUT_ERROR)))
        {
            return fail(ThreadStackStatus::EngineUnavailable, hr, L"Required DbgEng interfaces are unavailable.");
        }

        // 显式设置本地默认路径；不继承 _NT_SYMBOL_PATH 或 _NT_EXECUTABLE_IMAGE_PATH。
        const auto& symbolPath = request.symbolPath.empty() ? directory : request.symbolPath;
        ULONG options = 0; // 保留引擎无关的符号选项，关闭强制匹配及图像搜索。
        if (FAILED(hr = symbols->GetSymbolOptions(&options)) ||
            FAILED(hr = symbols->SetSymbolOptions((options & ~(SYMOPT_LOAD_ANYTHING | SYMOPT_IGNORE_CVREC)) |
                SYMOPT_EXACT_SYMBOLS | SYMOPT_NO_PROMPTS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_IMAGE_SEARCH)) ||
            FAILED(hr = symbols->SetImagePathWide(directory.c_str())) ||
            FAILED(hr = symbols->SetSymbolPathWide(symbolPath.c_str())))
        {
            return fail(ThreadStackStatus::EngineUnavailable, hr, L"Cannot configure DbgEng symbol settings.");
        }

        hr = session.client->OpenDumpFileWide(request.dumpPath.c_str(), 0); // 唯一的目标打开操作。
        if (hr != S_OK)
        {
            return fail(ThreadStackStatus::DumpOpenFailed, hr, L"DbgEng could not open the supplied dump.");
        }
        session.opened = true;
        if ((hr = control->WaitForEvent(0, kOpenWaitMs)) != S_OK)
        {
            return fail(ThreadStackStatus::DumpOpenFailed, hr, L"The dump target did not become ready.");
        }
        ULONG targetClass = 0, qualifier = 0, processor = 0; // 调试目标和处理器，不能由文件扩展名推断。
        if (FAILED(hr = control->GetDebuggeeType(&targetClass, &qualifier)) ||
            FAILED(hr = control->GetActualProcessorType(&processor)) ||
            targetClass != DEBUG_CLASS_KERNEL || processor != IMAGE_FILE_MACHINE_AMD64 ||
            (qualifier != DEBUG_KERNEL_SMALL_DUMP && qualifier != DEBUG_KERNEL_DUMP &&
             qualifier != DEBUG_KERNEL_FULL_DUMP && qualifier != DEBUG_KERNEL_ACTIVE_DUMP))
        {
            return fail(ThreadStackStatus::UnsupportedDump, hr, L"The target is not a supported x64 kernel dump.");
        }
        result.dumpQualifier = qualifier;
        ULONG dumpTime = 0; // 非必需：旧或损坏的转储可能没有可读时间。
        if (control->GetCurrentTimeDate(&dumpTime) == S_OK)
        {
            result.dumpTimeUnixSeconds = dumpTime;
        }

        ULONG64 extension = 0; // 只调用安装目录中的 Microsoft kdexts，不走扩展搜索链。
        const auto extensionPath = directory + L"\\winxp\\kdexts.dll";
        if (FAILED(hr = control->AddExtensionWide(extensionPath.c_str(), 0, &extension)) || !extension)
        {
            return fail(ThreadStackStatus::EngineUnavailable, hr, L"The installed kernel debugger extension kdexts.dll is unavailable.");
        }
        wchar_t lookup[64]{}; // 固定扩展命令，只插入已经校验的数值 TID。
        swprintf_s(lookup, L"!kdexts.thread -t 0x%X 0", request.threadId);
        session.output.Reset();
        // 命令输出显式发给本客户的回调，与调试器交互命令采用同一路径。
        hr = control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, lookup, DEBUG_EXECUTE_NOT_LOGGED | DEBUG_EXECUTE_NO_REPEAT);
        const auto record = ParseThread(session.output.Text()); // 从转储验证，不复查宿主实时进程。
        if (hr != S_OK || session.output.truncated || record.count != 1 || !IsKernelAddress(record.address))
        {
            return fail(ThreadStackStatus::ThreadNotFound, hr, L"No unique target thread could be read from the dump. Check dump coverage and exact kernel symbols.");
        }
        if (record.process != request.processId || record.thread != request.threadId)
        {
            return fail(ThreadStackStatus::IdentityMismatch, S_OK, L"The dump THREAD Cid does not match the requested PID/TID.");
        }

        wchar_t address[24]{}; // 仅序列化刚查到并匹配的 ETHREAD，不接受外部内核地址。
        swprintf_s(address, L"0x%llX", record.address);
        const auto prefix = std::wstring(L"@@c++(((nt!_ETHREAD*)") + address + L")->";
        ULONG64 processTime = 0, threadTime = 0; // 可选的 dump 侧 FILETIME。
        if (request.threadCreationTime100ns &&
            (hr = EvaluateScalar(*control.Get(), prefix + L"CreateTime.QuadPart)", threadTime)) != S_OK)
        {
            return fail(ThreadStackStatus::IdentityUnavailable, hr, L"The thread creation FILETIME is not readable from the dump.");
        }
        result.threadCreationTime100ns = threadTime;
        if (request.processCreationTime100ns &&
            (hr = EvaluateScalar(*control.Get(), std::wstring(L"@@c++(((nt!_EPROCESS*)(((nt!_ETHREAD*)") +
                address + L")->Tcb.Process))->CreateTime.QuadPart)", processTime)) != S_OK)
        {
            return fail(ThreadStackStatus::IdentityUnavailable, hr, L"The owner process creation FILETIME is not readable from the dump.");
        }
        result.processCreationTime100ns = processTime;
        if ((request.threadCreationTime100ns && request.threadCreationTime100ns != threadTime) ||
            (request.processCreationTime100ns && request.processCreationTime100ns != processTime))
        {
            return fail(ThreadStackStatus::IdentityMismatch, S_OK, L"The requested creation FILETIME does not match the dump.");
        }
        result.identityMatched = true;

        // .thread 接受已经核验的 ETHREAD，并从转储保存的数据建立显式寄存器上下文。
        const auto select = std::wstring(L".thread ") + address;
        session.output.Reset();
        hr = control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, select.c_str(), DEBUG_EXECUTE_NOT_LOGGED | DEBUG_EXECUTE_NO_REPEAT);
        if (hr != S_OK || session.output.truncated || !ConfirmExplicitThread(session.output.Text(), record.address))
        {
            return fail(ThreadStackStatus::ContextUnavailable, hr, L"DbgEng did not confirm selecting the requested dump thread.");
        }
        session.output.Reset();
        hr = control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, L"r rip,rsp", DEBUG_EXECUTE_NOT_LOGGED | DEBUG_EXECUTE_NO_REPEAT);
        ULONG64 ip = 0, sp = 0; // 只读取显式上下文的 RIP/RSP，杜绝误用当前 CPU 的寄存器。
        if (hr != S_OK || session.output.truncated || !ParseExplicitRegisters(session.output.Text(), ip, sp) ||
            !IsKernelAddress(ip) || !IsKernelAddress(sp))
        {
            return fail(ThreadStackStatus::ContextUnavailable, hr, L"The selected thread has no verified saved kernel context in this dump.");
        }

        // 多取一帧以区分刚好到达边界和确实被帧数限制截断。
        std::array<DEBUG_STACK_FRAME, MaxThreadStackFrames + 1> stack{};
        ULONG filled = 0; // DbgEng 实际返回的帧数（含探测帧）。
        session.output.Reset();
        hr = control->GetStackTrace(0, 0, 0, stack.data(), request.frameLimit + 1, &filled);
        if (FAILED(hr) || !filled || filled > request.frameLimit + 1 ||
            stack[0].InstructionOffset != ip || stack[0].StackOffset != sp)
        {
            return fail(ThreadStackStatus::UnwindUnavailable, hr, L"DbgEng did not return a stack starting at the selected kernel context.");
        }
        bool incomplete = session.output.warning || session.output.truncated; // 记录符号化前的展开告警。
        result.frames.reserve(std::min(filled, static_cast<ULONG>(request.frameLimit)));
        for (ULONG index = 0; index < filled; ++index)
        {
            const auto& item = stack[index]; // DbgEng 返回的真实行，不扫描或补造帧。
            if (!IsKernelAddress(item.InstructionOffset))
            {
                break;
            }
            if (!IsKernelAddress(item.StackOffset) || (index && item.StackOffset == stack[index - 1].StackOffset &&
                item.InstructionOffset == stack[index - 1].InstructionOffset))
            {
                incomplete = true;
                break;
            }
            if (index == request.frameLimit)
            {
                result.limited = true;
                break;
            }

            ThreadStackFrame frame{}; // 模块/符号查不到时仍保留寄存器展开证据。
            frame.index = index;
            frame.instruction = item.InstructionOffset;
            frame.stack = item.StackOffset;
            frame.returnAddress = item.ReturnOffset;
            wchar_t name[1024]{}; // 单个模块名/符号名的有界输出缓冲区。
            ULONG moduleIndex = 0; // 包含当前指令的模块索引。
            ULONG64 base = 0, displacement = 0; // 模块基址与相对符号位移。
            if (symbols->GetModuleByOffset(frame.instruction, 0, &moduleIndex, &base) == S_OK &&
                symbols->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, moduleIndex, base, name, ARRAYSIZE(name), nullptr) == S_OK)
            {
                frame.module = name;
            }
            if (symbols->GetNameByOffsetWide(frame.instruction, name, ARRAYSIZE(name), nullptr, &displacement) == S_OK &&
                std::wcschr(name, L'!'))
            {
                frame.symbol = name;
                frame.displacement = displacement;
            }
            result.frames.push_back(std::move(frame));
        }
        // 最后一个可见内核返回地址仍有内核调用方时，不宣称已走完全链。
        if (result.frames.empty())
        {
            return fail(ThreadStackStatus::UnwindUnavailable, hr, L"DbgEng returned no verified kernel frames.");
        }
        incomplete |= result.limited || hr != S_OK || IsKernelAddress(result.frames.back().returnAddress);
        result.status = incomplete ? ThreadStackStatus::Partial : ThreadStackStatus::Ok;
        if (incomplete)
        {
            result.diagnostic = result.limited ? L"Kernel dump unwind reached the requested frame limit." :
                L"DbgEng returned a verified kernel stack prefix; the full chain is not confirmed.";
        }
#else
        result.status = ThreadStackStatus::EngineUnavailable;
        result.diagnostic = L"Kernel dump unwinding requires an x64 Windows build.";
#endif
        return result;
    }
}
