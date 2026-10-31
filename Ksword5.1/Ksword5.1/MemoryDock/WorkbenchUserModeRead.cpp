#include "WorkbenchUserModeRead.h"
#include "../../../shared/evidence/memory_workbench/MemoryTargetSession.h"

#include <Windows.h>
#include <memory>
#include <utility>

namespace ksword::memwb_ports_detail
{
    ksword::memwb::IoReadResult ReadUserModeVirtual(
        std::uint32_t pid, std::uint64_t address, std::uint64_t length)
    {
        using namespace ksword::memwb;
        IoReadResult result;
        if (IsKernelVirtualAddress(address))
        {
            result.status = IoReadStatus::Failed;
            result.failure =
                "用户态通道（R3 ReadProcessMemory）无法访问内核虚拟地址，请切换到标准驱动（R0）通道。";
            return result;
        }

        // Each read owns its handle; it does not borrow the Dock attachment.
        const HANDLE process = ::OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (process == nullptr)
        {
            result.status = IoReadStatus::Failed;
            result.failure = "R3 通道打开进程失败，win32=" + std::to_string(::GetLastError()) + "。";
            return result;
        }
        const std::unique_ptr<void, decltype(&::CloseHandle)> lease(process, &::CloseHandle);

        std::vector<std::uint8_t> buffer(static_cast<std::size_t>(length), 0U);
        SIZE_T bytesRead = 0;
        const BOOL readOk = ::ReadProcessMemory(process,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
            buffer.data(), static_cast<SIZE_T>(length), &bytesRead);
        const DWORD readError = readOk ? ERROR_SUCCESS : ::GetLastError();

        // Failed address validation can leave a nonsensical count on some
        // Windows builds. Accept only success / partial-copy, bounded by the
        // buffer actually supplied. Never grow it or accept its zero-filled tail.
        if (bytesRead > length || (!readOk && readError != ERROR_PARTIAL_COPY)) bytesRead = 0;
        if (bytesRead == 0)
        {
            result.status = IoReadStatus::Unreadable;
            result.failure = "R3 通道读取 0 字节，win32=" + std::to_string(readError) +
                "，目标地址可能未提交或无读权限。";
            return result;
        }
        buffer.resize(static_cast<std::size_t>(bytesRead));
        result.data = std::move(buffer);
        result.status = bytesRead == length ? IoReadStatus::Ok : IoReadStatus::Partial;
        return result;
    }
}
