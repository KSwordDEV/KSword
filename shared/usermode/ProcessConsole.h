#pragma once

#include <cstdint>
#include <string>

namespace ks::process
{
    // ForceProcessConsole：按 PID+创建时间为运行中的进程执行原强开控制台步骤。
    // 调用方在工作线程调用；不加载自定义 DLL，不附加调用方自己的控制台。
    // 输入为目标身份；输出为是否完成必需步骤及逐层执行明细，CRT 缺失单独说明。
    bool ForceProcessConsole(
        std::uint32_t processId,                 // 目标 PID。
        std::uint64_t expectedCreationTime100ns, // 列表快照中的真实创建时间。
        std::string* detailTextOut = nullptr);   // 可选的执行明细输出。
}
