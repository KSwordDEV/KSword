#pragma once

#include <Windows.h>
#include <array>
#include <cstdint>
#include <initializer_list>
#include <string>

namespace ks::process::console_detail
{
    // RemoteSession 仅供强开控制台后端使用：持有同一目标句柄及可复用调用页。
    // 所有地址由目标映像解析；参数仅限整数/指针，不支持浮点或可变参数。
    class RemoteSession final
    {
    public:
        // 构造/析构：接收目标身份；析构释放已停止执行的远程页和本地句柄。
        RemoteSession(DWORD processId, std::uint64_t creationTime);
        ~RemoteSession();
        RemoteSession(const RemoteSession&) = delete;
        RemoteSession& operator=(const RemoteSession&) = delete;

        // initialize：验证进程身份和位数，建立 RW 数据页及独立 RX 调用页。
        bool initialize();
        // call：执行目标已有导出；thisPointer 仅用于 x86 thiscall，返回完整指针宽度。
        bool call(const wchar_t* module, const char* name,
            std::initializer_list<std::uint64_t> arguments,
            std::uint64_t& result, std::uint64_t thisPointer = 0);
        // address：返回暂存区的目标地址；read/write 输入地址、缓冲区及长度。
        std::uint64_t address(std::size_t offset) const;
        bool read(std::uint64_t remoteAddress, void* output, std::size_t bytes);
        bool write(std::size_t offset, const void* input, std::size_t bytes);
        // moduleHandle/dataExport：只查询已加载模块及其数据导出，不加载额外模块。
        std::uint64_t moduleHandle(const wchar_t* name) const;
        bool dataExport(const wchar_t* module, const char* name, std::uint64_t& result);
        // fail：记录失败阶段和错误码；error 返回诊断，lastError 返回远程线程错误码。
        bool fail(const std::string& operation, DWORD code);
        const std::string& error() const;
        DWORD lastError() const;
        bool target32() const;

    private:
        // invoke：写入一个固定调用包，等待远程线程真正结束后才允许复用内存。
        bool invoke(std::uint64_t function, const std::uint64_t* arguments,
            std::size_t count, std::uint64_t& result, std::uint64_t thisPointer);

        DWORD m_processId = 0;                // 请求中的目标 PID。
        std::uint64_t m_creationTime = 0;     // 请求中的目标创建时间。
        HANDLE m_process = nullptr;           // 已核验身份的目标句柄。
        USHORT m_machine = 0;                 // 目标 PE 架构。
        void* m_data = nullptr;               // 4096 字节 RW 参数与暂存页。
        void* m_code = nullptr;               // 只读可执行的调用例程。
        std::uint64_t m_getLastError = 0;     // 目标的 GetLastError 入口。
        std::uint64_t m_getProcAddress = 0;   // 目标的 GetProcAddress 入口。
        ULONGLONG m_deadline = 0;             // 本次完整操作的最晚结束时间。
        bool m_inFlight = false;              // 超时/等待失败时禁止释放仍在使用的页。
        DWORD m_lastError = 0;                // 最近一次远程调用捕获的 LastError。
        std::string m_error;                  // 最近失败的阶段说明。
    };
}
