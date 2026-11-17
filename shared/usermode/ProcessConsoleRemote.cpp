#include "ProcessConsoleRemote.h"
#include "../ApiMonitorRemoteExports.h"

#include <algorithm>
#include <cstddef>
#include <cstring>

namespace ks::process::console_detail
{
    namespace
    {
        // 两种位数共用固定宽度调用包，避免宿主指针宽度改变远程字段偏移。
        struct CallPacket
        {
            std::uint64_t function = 0;            // 被调用函数的目标地址。
            std::uint64_t getLastError = 0;        // 目标 GetLastError 地址。
            std::uint64_t thisPointer = 0;         // x86 thiscall 的 ECX。
            std::array<std::uint64_t, 8> args{};   // 顺序排列的整数/指针参数。
            std::uint64_t result = 0;              // 完整返回值，不能用线程退出码代替。
            DWORD error = 0;                       // 在同一线程捕获的 LastError。
            DWORD completed = 0;                   // 完成标记，防止线程异常被误报成功。
            DWORD argumentCount = 0;               // x86 需要压栈的参数数量。
        };
        static_assert(offsetof(CallPacket, args) == 24);
        static_assert(offsetof(CallPacket, result) == 88);
        static_assert(offsetof(CallPacket, argumentCount) == 104);

        // x86：保存非易失寄存器，逆序压参，设置 thiscall ECX，并统一恢复栈。
        // 调用包和函数不在同一页；cdecl/stdcall/thiscall 均由恢复 EBP 消除清栈差异。
        constexpr unsigned char kCall32[] =
        {
            0x55, 0x8B, 0xEC, 0x53, 0x56, 0x57, // push ebp; mov ebp,esp; push ebx/esi/edi
            0x8B, 0x75, 0x08,                   // mov esi,[ebp+8]
            0x8B, 0x4E, 0x68,                   // mov ecx,[esi+104]
            0x8D, 0x7E, 0x18,                   // lea edi,[esi+24]
            0x85, 0xC9, 0x74, 0x08,             // test ecx,ecx; jz invoke
            0x49, 0xFF, 0x34, 0xCF,             // dec ecx; push [edi+ecx*8]
            0x85, 0xC9, 0x75, 0xF8,             // test ecx,ecx; jnz push-argument
            0x8B, 0x4E, 0x10, 0xFF, 0x16,       // mov ecx,[esi+16]; call [esi]
            0x89, 0x46, 0x58,                   // mov [esi+88],eax
            0xC7, 0x46, 0x5C, 0, 0, 0, 0,       // mov [esi+92],0
            0xFF, 0x56, 0x08,                   // call [esi+8] (GetLastError)
            0x89, 0x46, 0x60,                   // mov [esi+96],eax
            0xC7, 0x46, 0x64, 1, 0, 0, 0,       // mov [esi+100],1
            0x8D, 0x65, 0xF4,                   // lea esp,[ebp-12]
            0x5F, 0x5E, 0x5B, 0x5D,             // pop edi/esi/ebx/ebp
            0x31, 0xC0, 0xC2, 4, 0              // xor eax,eax; ret 4
        };

        // x64：保持 16 字节栈对齐，预留 shadow space 和最多四个额外栈参数。
        // 先保存 RAX，再获取 LastError；完成标记必须在所有结果已写回之后设置。
        constexpr unsigned char kCall64[] =
        {
            0x53, 0x48, 0x83, 0xEC, 0x40,       // push rbx; sub rsp,64
            0x48, 0x89, 0xCB,                   // mov rbx,rcx
            0x48, 0x8B, 0x43, 0x38,             // mov rax,[rbx+56] (arg5)
            0x48, 0x89, 0x44, 0x24, 0x20,       // mov [rsp+32],rax
            0x48, 0x8B, 0x43, 0x40,             // mov rax,[rbx+64] (arg6)
            0x48, 0x89, 0x44, 0x24, 0x28,       // mov [rsp+40],rax
            0x48, 0x8B, 0x43, 0x48,             // mov rax,[rbx+72] (arg7)
            0x48, 0x89, 0x44, 0x24, 0x30,       // mov [rsp+48],rax
            0x48, 0x8B, 0x43, 0x50,             // mov rax,[rbx+80] (arg8)
            0x48, 0x89, 0x44, 0x24, 0x38,       // mov [rsp+56],rax
            0x48, 0x8B, 0x4B, 0x18,             // mov rcx,[rbx+24]
            0x48, 0x8B, 0x53, 0x20,             // mov rdx,[rbx+32]
            0x4C, 0x8B, 0x43, 0x28,             // mov r8,[rbx+40]
            0x4C, 0x8B, 0x4B, 0x30,             // mov r9,[rbx+48]
            0xFF, 0x13,                         // call [rbx]
            0x48, 0x89, 0x43, 0x58,             // mov [rbx+88],rax
            0xFF, 0x53, 0x08,                   // call [rbx+8] (GetLastError)
            0x89, 0x43, 0x60,                   // mov [rbx+96],eax
            0xC7, 0x43, 0x64, 1, 0, 0, 0,       // mov [rbx+100],1
            0x48, 0x83, 0xC4, 0x40,             // add rsp,64
            0x5B, 0x31, 0xC0, 0xC3              // pop rbx; xor eax,eax; ret
        };
    }

    // 构造仅保存请求身份；initialize 才打开目标并分配远程资源。
    RemoteSession::RemoteSession(DWORD processId, std::uint64_t creationTime)
        : m_processId(processId), m_creationTime(creationTime)
    {
    }

    // 析构释放本地句柄；只有确认远程线程结束，才能回收远程代码及参数。
    RemoteSession::~RemoteSession()
    {
        // 等待超时不能撤销正在执行的代码；保留其页到目标退出，避免释放后取指。
        if (m_process && !m_inFlight)
        {
            if (m_code)
            {
                ::VirtualFreeEx(m_process, m_code, 0, MEM_RELEASE);
            }
            if (m_data)
            {
                ::VirtualFreeEx(m_process, m_data, 0, MEM_RELEASE);
            }
        }
        if (m_process)
        {
            ::CloseHandle(m_process);
        }
    }

    // fail 输入失败阶段与错误码，保存可读诊断并返回 false，供原调用链直接传播。
    bool RemoteSession::fail(const std::string& operation, DWORD code)
    {
        m_error = operation + "; error=" + std::to_string(code);
        ::SetLastError(code);
        return false;
    }

    // 三个只读访问器分别返回失败明细、远程 LastError 和目标是否为 x86。
    const std::string& RemoteSession::error() const
    {
        return m_error;
    }

    DWORD RemoteSession::lastError() const
    {
        return m_lastError;
    }

    bool RemoteSession::target32() const
    {
        return m_machine == IMAGE_FILE_MACHINE_I386;
    }

    bool RemoteSession::initialize()
    {
        if (m_processId <= 4 || !m_creationTime)
        {
            return fail("invalid process identity", ERROR_INVALID_PARAMETER);
        }
        // 在同一个具备操作权限的句柄上验证时间，避免查询后重新打开造成 PID 复用。
        m_process = ::OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE,
            FALSE, m_processId);
        if (!m_process)
        {
            return fail("OpenProcess console", ::GetLastError());
        }
        FILETIME created{}, exited{}, kernel{}, user{}; // 核验身份所需的四个时间字段。
        if (!::GetProcessTimes(m_process, &created, &exited, &kernel, &user))
        {
            return fail("GetProcessTimes console", ::GetLastError());
        }
        // observed 是从操作句柄读取的真实创建时间，必须与菜单快照完全一致。
        const auto observed = (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        if (observed != m_creationTime || ::WaitForSingleObject(m_process, 0) != WAIT_TIMEOUT)
        {
            return fail("process identity changed or exited", ERROR_INVALID_PARAMETER);
        }

        // 复用已有跨位数探测/目标 PE 导出解析，不依赖本机 DLL 地址或额外 broker。
        std::wstring architectureError; // 位数探测器的附加说明。
        if (!ks::winapi_monitor::queryProcessMachine(m_process, &m_machine, &architectureError)
            || (sizeof(void*) == 4 && !target32()))
        {
            return fail("unsupported console target architecture", ERROR_NOT_SUPPORTED);
        }
        m_getLastError = ks::winapi_monitor::findRemoteExport(
            m_process, m_processId, m_machine, L"kernel32.dll", "GetLastError");
        m_getProcAddress = ks::winapi_monitor::findRemoteExport(
            m_process, m_processId, m_machine, L"kernel32.dll", "GetProcAddress");
        if (!m_getLastError || !m_getProcAddress)
        {
            return fail("resolve target console bootstrap exports", ERROR_PROC_NOT_FOUND);
        }
        const auto* code = target32() ? kCall32 : kCall64; // 与目标一致的调用例程。
        const auto codeBytes = target32() ? sizeof(kCall32) : sizeof(kCall64); // 目标例程长度。
        m_data = ::VirtualAllocEx(m_process, nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        m_code = ::VirtualAllocEx(m_process, nullptr, codeBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!m_data || !m_code)
        {
            return fail("allocate console call pages", ::GetLastError());
        }
        if (target32() && (address(4095) > UINT32_MAX || reinterpret_cast<std::uintptr_t>(m_code) > UINT32_MAX))
        {
            return fail("console x86 address exceeds range", ERROR_NOT_ENOUGH_MEMORY);
        }

        // 写代码后只保留 RX 权限并刷新指令缓存，数据页始终不可执行。
        SIZE_T written = 0; // 实际写入的调用代码长度。
        DWORD previousProtection = 0; // VirtualProtectEx 返回的原页面权限。
        if (!::WriteProcessMemory(m_process, m_code, code, codeBytes, &written) || written != codeBytes
            || !::VirtualProtectEx(m_process, m_code, codeBytes, PAGE_EXECUTE_READ, &previousProtection)
            || !::FlushInstructionCache(m_process, m_code, codeBytes))
        {
            return fail("prepare console call code", ::GetLastError());
        }
        m_deadline = ::GetTickCount64() + 10000;
        return true;
    }

    // address 输入数据页内偏移，返回目标地址；write 会核对偏移和长度是否越界。
    std::uint64_t RemoteSession::address(std::size_t offset) const
    {
        return reinterpret_cast<std::uintptr_t>(m_data) + offset;
    }

    // read 从目标地址完整读取 bytes 字节到 output；部分读取视为失败。
    bool RemoteSession::read(std::uint64_t remoteAddress, void* output, std::size_t bytes)
    {
        if (!ks::winapi_monitor::readRemoteBytes(m_process,
                static_cast<std::uintptr_t>(remoteAddress), output, bytes))
        {
            return fail("read console target memory", ::GetLastError());
        }
        return true;
    }

    // write 将调用参数或字符串写到 RW 数据页，返回是否完整写入。
    bool RemoteSession::write(std::size_t offset, const void* input, std::size_t bytes)
    {
        SIZE_T written = 0; // 实际写入的暂存数据长度。
        if (offset > 4096 || bytes > 4096 - offset || !::WriteProcessMemory(m_process,
                reinterpret_cast<void*>(static_cast<std::uintptr_t>(address(offset))), input, bytes, &written)
            || written != bytes)
        {
            return fail("write console call data", ERROR_WRITE_FAULT);
        }
        return true;
    }

    bool RemoteSession::invoke(std::uint64_t function, const std::uint64_t* arguments,
        std::size_t count, std::uint64_t& result, std::uint64_t thisPointer)
    {
        // 不重用仍在执行的包；最多八个参数，所有调用共用十秒总预算。
        if (m_inFlight || !function || count > 8 || ::GetTickCount64() >= m_deadline)
        {
            return fail("console call deadline or invalid packet", ERROR_TIMEOUT);
        }
        CallPacket packet{}; // 当前一次调用的参数及远程回执。
        packet.function = function;
        packet.getLastError = m_getLastError;
        packet.thisPointer = thisPointer;
        packet.argumentCount = static_cast<DWORD>(count);
        if (count != 0)
        {
            std::copy_n(arguments, count, packet.args.begin());
        }
        if (!write(0, &packet, sizeof(packet)))
        {
            return false;
        }
        HANDLE thread = ::CreateRemoteThread(m_process, nullptr, 0, // 本次调用唯一远程线程。
            reinterpret_cast<LPTHREAD_START_ROUTINE>(m_code), m_data, 0, nullptr);
        if (!thread)
        {
            return fail("CreateRemoteThread console", ::GetLastError());
        }

        // 线程未结束时不能释放代码/参数；超时不终止目标线程，也不伪报成功。
        m_inFlight = true;
        const auto now = ::GetTickCount64(); // 单次采样避免两次时钟跨过截止点发生减法下溢。
        const auto remaining = m_deadline > now ? m_deadline - now : 0; // 操作剩余预算。
        const DWORD wait = ::WaitForSingleObject(thread, static_cast<DWORD>((std::min)(remaining, 5000ULL))); // 实际等待结果。
        const DWORD waitError = ::GetLastError(); // CloseHandle 前保留等待失败原因。
        ::CloseHandle(thread);
        if (wait != WAIT_OBJECT_0)
        {
            return fail("console call unfinished; remote pages retained until target exit",
                wait == WAIT_FAILED ? waitError : ERROR_TIMEOUT);
        }
        m_inFlight = false;
        if (!read(address(0), &packet, sizeof(packet)) || packet.completed != 1)
        {
            return fail("console remote call did not complete", ERROR_PROCESS_ABORTED);
        }
        result = packet.result;
        m_lastError = packet.error;
        return true;
    }

    bool RemoteSession::call(const wchar_t* module, const char* name,
        std::initializer_list<std::uint64_t> arguments, std::uint64_t& result, std::uint64_t thisPointer)
    {
        // 通过目标 GetProcAddress 解析其已加载导出，避免重复逐字节扫描大导出表。
        std::uint64_t function = 0; // 本次函数的目标地址。
        if (!dataExport(module, name, function))
        {
            return false;
        }
        if (!function)
        {
            return fail(std::string("resolve console export ") + name, ERROR_PROC_NOT_FOUND);
        }
        return invoke(function, arguments.begin(), arguments.size(), result, thisPointer);
    }

    std::uint64_t RemoteSession::moduleHandle(const wchar_t* name) const
    {
        HANDLE snapshot = ks::winapi_monitor::remoteModuleSnapshot(m_processId); // 一次只读模块快照。
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return 0;
        }
        MODULEENTRY32W entry{}; // 当前模块的名称及目标基址。
        entry.dwSize = sizeof(entry);
        std::uint64_t base = 0; // 匹配模块的目标地址，未加载时为零。
        for (BOOL found = ::Module32FirstW(snapshot, &entry); found; found = ::Module32NextW(snapshot, &entry))
        {
            if (_wcsicmp(entry.szModule, name) == 0)
            {
                base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
                break;
            }
        }
        ::CloseHandle(snapshot);
        return base;
    }

    bool RemoteSession::dataExport(const wchar_t* module, const char* name, std::uint64_t& result)
    {
        // 数据导出不满足代码页验证；在目标调用 GetProcAddress 获取原始数据地址。
        const auto base = moduleHandle(module); // 已加载模块句柄，不执行 LoadLibrary。
        if (!base || !write(256, name, std::strlen(name) + 1))
        {
            return fail("console runtime module unavailable", ERROR_MOD_NOT_FOUND);
        }
        const std::uint64_t arguments[] = {base, address(256)}; // 目标模块句柄和导出名指针。
        return invoke(m_getProcAddress, arguments, 2, result, 0);
    }
}
