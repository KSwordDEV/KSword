#include "../../shared/usermode/KernelDumpThreadStack.h"

#include <cwchar>
#include <iostream>

using namespace ks::kernel_dump;

namespace
{
    // 为本次测试累计断言；失败时输出标签，供构建日志定位。
    int failures = 0;
    void Check(bool pass, const wchar_t* label)
    {
        std::wcout << (pass ? L"PASS " : L"FAIL ") << label << L'\n';
        failures += !pass;
    }
}

// 无参数时仅测不访问目标的拒绝路径；四个参数时才打开调用者供应的 dump。
int wmain(int argc, wchar_t** argv)
{
    ThreadStackRequest request{}; // 每个用例复用真实生产入口。
    Check(UnwindThreadStack(request).status == ThreadStackStatus::InvalidRequest, L"missing request");
    request.processId = 4;
    request.threadId = 8;
    request.dumpPath = L"relative.dmp";
    Check(UnwindThreadStack(request).status == ThreadStackStatus::InvalidRequest, L"relative path");
    request.dumpPath = L"\\\\example.invalid\\dump.dmp";
    Check(UnwindThreadStack(request).status == ThreadStackStatus::InvalidRequest, L"UNC path rejected before opening");
    request.dumpPath = L"C:\\Windows\\not-a-ksword-test-dump.dmp";
    request.frameLimit = MaxThreadStackFrames + 1;
    Check(UnwindThreadStack(request).status == ThreadStackStatus::InvalidRequest, L"reject over-limit request");
    request.frameLimit = MaxThreadStackFrames;
    request.debuggerDirectory = request.dumpPath;
    const auto noEngine = UnwindThreadStack(request); // 测试指定不存在的加载目录，不打开转储。
    Check(noEngine.status == ThreadStackStatus::EngineUnavailable && noEngine.frames.empty(), L"engine unavailable");

    if (argc == 2)
    {
        // 此模式让调用者明确提供无效的本地转储（如纯文本测试文件）。
        request.dumpPath = argv[1];
        request.debuggerDirectory.clear();
        const auto invalid = UnwindThreadStack(request); // 实际加载 DbgEng，再让其拒绝无效转储。
        std::wcout << invalid.diagnostic << L" HRESULT=0x" << std::hex << invalid.hresult << std::dec << L'\n';
        Check(invalid.status == ThreadStackStatus::DumpOpenFailed && invalid.frames.empty(), L"DbgEng rejects invalid dump");
    }
    else if (argc == 5 || argc == 7)
    {
        // 传入真实 x64 dump、十进制 PID/TID、受信本地符号路径，可选两个十进制 FILETIME。
        request.dumpPath = argv[1];
        request.processId = std::wcstoul(argv[2], nullptr, 10);
        request.threadId = std::wcstoul(argv[3], nullptr, 10);
        request.symbolPath = argv[4];
        request.debuggerDirectory.clear();
        if (argc == 7)
        {
            request.processCreationTime100ns = std::wcstoull(argv[5], nullptr, 10);
            request.threadCreationTime100ns = std::wcstoull(argv[6], nullptr, 10);
        }
        const auto unwind = UnwindThreadStack(request); // 原身份必须通过并产生至少两帧。
        std::wcout << unwind.diagnostic << L" HRESULT=0x" << std::hex << unwind.hresult << std::dec << L'\n';
        Check((unwind.status == ThreadStackStatus::Ok || unwind.status == ThreadStackStatus::Partial) &&
            unwind.identityMatched && unwind.frames.size() >= 2, L"verified real unwind");
        for (const auto& frame : unwind.frames)
        {
            std::wcout << frame.index << L" IP=" << std::hex << frame.instruction << L" SP=" << frame.stack
                << std::dec << L' ' << frame.symbol << L'\n';
        }
        request.frameLimit = 1;
        const auto limited = UnwindThreadStack(request); // 只能发布限制内的同一线程第一帧。
        Check(limited.status == ThreadStackStatus::Partial && limited.limited && limited.frames.size() == 1 &&
            !unwind.frames.empty() && limited.frames[0].instruction == unwind.frames[0].instruction,
            L"cap reports only the verified top frame");
        ++request.processId;
        const auto wrongCid = UnwindThreadStack(request); // 同 TID、错误 PID 绝不能退回崩溃 CPU 栈。
        Check(wrongCid.status == ThreadStackStatus::IdentityMismatch && wrongCid.frames.empty(), L"wrong PID rejected");
        if (argc == 7)
        {
            --request.processId;
            ++request.threadCreationTime100ns;
            const auto wrongTime = UnwindThreadStack(request); // 同 PID/TID 但异代线程。
            Check(wrongTime.status == ThreadStackStatus::IdentityMismatch && wrongTime.frames.empty(), L"wrong creation FILETIME rejected");
        }
    }
    else if (argc != 1)
    {
        std::wcerr << L"Usage: kernel_dump_thread_stack_tests [bad-dump | dump PID TID symbol-path [process-filetime thread-filetime]]\n";
        return 2;
    }
    return failures ? 1 : 0;
}
