#include "ProcessConsole.h"
#include "ProcessConsoleRemote.h"

#include <cstdio>

namespace ks::process
{
    namespace
    {
        using console_detail::RemoteSession;

        // callRequired：调用返回 BOOL 的控制台 API，输入模块、导出及参数。
        // 输出成功与否；失败阶段留在 session 中，不把零返回误认为调用成功。
        bool callRequired(RemoteSession& session, const char* name,
            std::initializer_list<std::uint64_t> arguments)
        {
            std::uint64_t value = 0; // 目标 API 的完整返回值。
            if (!session.call(L"kernel32.dll", name, arguments, value))
            {
                return false;
            }
            return value != 0 || session.fail(name, session.lastError());
        }

        // configureConsole：复现原 DLL 的控制台、CONIN$/CONOUT$、标准句柄与编码步骤。
        // 输入为已核验的会话，输出为 Win32 层是否完成；不改变调用方的控制台。
        bool configureConsole(RemoteSession& session)
        {
            std::uint64_t window = 0; // 目标已有的控制台窗口句柄。
            if (!session.call(L"kernel32.dll", "GetConsoleWindow", {}, window))
            {
                return false;
            }
            if (!window && !callRequired(session, "AllocConsole", {}))
            {
                return false;
            }

            // 字符串与输出槽位位于调用包之后，调用之间保持不变。
            const wchar_t inputName[] = L"CONIN$";   // 控制台输入设备名。
            const wchar_t outputName[] = L"CONOUT$"; // 控制台输出设备名。
            if (!session.write(512, inputName, sizeof(inputName))
                || !session.write(544, outputName, sizeof(outputName)))
            {
                return false;
            }
            std::uint64_t inputHandle = 0;  // 留在目标进程中的输入句柄。
            std::uint64_t outputHandle = 0; // 留在目标进程中的输出/错误句柄。
            const auto invalidHandle = session.target32() ? UINT32_MAX : UINT64_MAX;
            if (!session.call(L"kernel32.dll", "CreateFileW",
                    {session.address(512), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                        0, OPEN_EXISTING, 0, 0}, inputHandle))
            {
                return false;
            }
            if (inputHandle == invalidHandle)
            {
                return session.fail("CreateFileW CONIN$", session.lastError());
            }
            if (!session.call(L"kernel32.dll", "CreateFileW",
                    {session.address(544), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE,
                        0, OPEN_EXISTING, 0, 0}, outputHandle))
            {
                return false;
            }
            if (outputHandle == invalidHandle)
            {
                const DWORD openError = session.lastError(); // 清理前保存设备打开错误。
                std::uint64_t ignored = 0; // CloseHandle 的返回值无需改变原失败原因。
                session.call(L"kernel32.dll", "CloseHandle", {inputHandle}, ignored);
                return session.fail("CreateFileW CONOUT$", openError);
            }

            // 安装后的设备句柄由目标继续使用，不能随宿主临时调用页一起关闭。
            return callRequired(session, "SetStdHandle", {STD_INPUT_HANDLE, inputHandle})
                && callRequired(session, "SetStdHandle", {STD_OUTPUT_HANDLE, outputHandle})
                && callRequired(session, "SetStdHandle", {STD_ERROR_HANDLE, outputHandle})
                && callRequired(session, "SetConsoleOutputCP", {CP_UTF8})
                && callRequired(session, "SetConsoleCP", {CP_UTF8});
        }

        // redirectCStreams：只对目标已加载的同代 UCRT 操作，不引入另一份 DLL 运行库。
        // 输入为会话和运行库名；输出三路标准流重定向及无缓冲设置是否完成。
        bool redirectCStreams(RemoteSession& session, const wchar_t* runtime)
        {
            const char inputName[] = "CONIN$";   // freopen_s 的窄字符输入路径。
            const char outputName[] = "CONOUT$"; // freopen_s 的窄字符输出路径。
            const char readMode[] = "r";         // 标准输入打开模式。
            const char writeMode[] = "w";        // 标准输出和错误打开模式。
            if (!session.write(576, inputName, sizeof(inputName))
                || !session.write(608, outputName, sizeof(outputName))
                || !session.write(640, readMode, sizeof(readMode))
                || !session.write(656, writeMode, sizeof(writeMode)))
            {
                return false;
            }

            // __acrt_iob_func 在目标运行库返回目标 FILE*，不把本机 FILE 布局写进去。
            for (std::uint64_t index = 0; index < 3; ++index)
            {
                std::uint64_t stream = 0; // 当前目标标准流 FILE*。
                std::uint64_t status = 0; // errno_t / setvbuf 的整型返回码。
                if (!session.call(runtime, "__acrt_iob_func", {index}, stream) || !stream)
                {
                    return session.fail("resolve target C standard stream", ERROR_INVALID_DATA);
                }
                if (!session.call(runtime, "freopen_s",
                    {session.address(704), session.address(index == 0 ? 576 : 608),
                        session.address(index == 0 ? 640 : 656), stream}, status))
                {
                    return false;
                }
                if (status != 0)
                {
                    return session.fail("target freopen_s errno", static_cast<DWORD>(status));
                }
                if (index != 0)
                {
                    if (!session.call(runtime, "setvbuf", {stream, 0, _IONBF, 0}, status))
                    {
                        return false;
                    }
                    if (status != 0)
                    {
                        return session.fail("target setvbuf", ERROR_INVALID_DATA);
                    }
                }
            }
            return true;
        }

        // clearCppStreams：复现 MSVC 14.x 的 sync_with_stdio 和六路输出流 clear。
        // 从目标 ostream 的 vbtable 读取 basic_ios 虚基偏移，不硬编码对象大小。
        bool clearCppStreams(RemoteSession& session, const wchar_t* runtime)
        {
            std::uint64_t ignored = 0; // sync_with_stdio 返回的原同步状态。
            if (!session.call(runtime, "?sync_with_stdio@ios_base@std@@SA_N_N@Z", {1}, ignored))
            {
                return false;
            }
            const char* names[] = {"cout", "clog", "cerr", "wcout", "wclog", "wcerr"};
            for (std::size_t index = 0; index < 6; ++index)
            {
                const bool wide = index >= 3; // 后三项为 wchar_t 标准流。
                const std::string character = wide ? "_W" : "D"; // MSVC 模板实参编码。
                const std::string objectName = std::string("?") + names[index]
                    + "@std@@3V?$basic_ostream@" + character + "U?$char_traits@"
                    + character + "@std@@@1@A";
                std::uint64_t object = 0;  // ostream 数据导出的目标地址。
                std::uint64_t vbtable = 0; // ostream 的虚基表地址。
                std::int32_t baseOffset = 0; // 表中 basic_ios 的相对偏移。
                if (!session.dataExport(runtime, objectName.c_str(), object) || !object)
                {
                    return session.fail("target C++ stream export unavailable", ERROR_PROC_NOT_FOUND);
                }
                if (!session.read(object, &vbtable, session.target32() ? 4 : 8)
                    || !session.read(vbtable + sizeof(std::int32_t), &baseOffset, sizeof(baseOffset)))
                {
                    return false;
                }
                if (baseOffset <= 0 || baseOffset > 1024)
                {
                    return session.fail("target C++ virtual base unavailable", ERROR_INVALID_DATA);
                }

                // x86 成员函数由 ECX 传 this；x64 则把 this 放入第一个寄存器参数。
                const std::uint64_t base = object + baseOffset; // 目标 basic_ios 对象地址。
                const std::string clearName = "?clear@?$basic_ios@" + character
                    + "U?$char_traits@" + character + "@std@@@std@@"
                    + (session.target32() ? "QAEXH_N@Z" : "QEAAXH_N@Z");
                const bool cleared = session.target32()
                    ? session.call(runtime, clearName.c_str(), {0, 0}, ignored, base)
                    : session.call(runtime, clearName.c_str(), {base, 0, 0}, ignored);
                if (!cleared)
                {
                    return false;
                }
            }
            return true;
        }
    }

    bool ForceProcessConsole(std::uint32_t processId,
        std::uint64_t expectedCreationTime100ns, std::string* detailTextOut)
    {
        // 会话拥有远程资源；任何失败都会保留具体阶段，不走 AttachConsole 宿主回退。
        RemoteSession session(processId, expectedCreationTime100ns); // 同一真实进程实例。
        bool ok = session.initialize() && configureConsole(session); // Win32 必需步骤状态。
        std::string detail = "Win32 console/standard handles/UTF-8: "; // 分层执行回执。
        detail += ok ? "ok" : "failed";
        if (ok)
        {
            // 原实现使用 VS14 UCRT/STL；静态链接的目标不猜内部全局状态。
            const wchar_t* cRuntime = session.moduleHandle(L"ucrtbase.dll") ? L"ucrtbase.dll"
                : session.moduleHandle(L"ucrtbased.dll") ? L"ucrtbased.dll" : nullptr;
            if (cRuntime)
            {
                ok = redirectCStreams(session, cRuntime);
                detail += ok ? "; C streams: ok" : "; C streams: failed";
            }
            else
            {
                detail += "; C streams: shared UCRT not loaded (static/private CRT unchanged)";
            }
            const wchar_t* cppRuntime = session.moduleHandle(L"msvcp140.dll") ? L"msvcp140.dll"
                : session.moduleHandle(L"msvcp140d.dll") ? L"msvcp140d.dll" : nullptr;
            if (ok && cppRuntime)
            {
                ok = clearCppStreams(session, cppRuntime);
                detail += ok ? "; C++ streams: ok" : "; C++ streams: failed";
            }
            else if (ok)
            {
                detail += "; C++ streams: shared MSVC14 STL not loaded (static/private STL unchanged)";
            }
        }
        if (!ok)
        {
            detail += "; " + session.error();
        }
        if (detailTextOut)
        {
            *detailTextOut = detail;
        }
        return ok;
    }
}
