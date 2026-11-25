#pragma once

#include <windows.h>
#include <cstdint>

namespace ActionTransportValidation {
// 仅用于本夹具的固定线路布局；每阶段只有一个命令，不代表产品协议。
constexpr DWORD kPipeCapacity = 4096;
constexpr DWORD kBulkBytes = 1024 * 1024;
constexpr DWORD kStageBudget = 3500;
constexpr std::uint32_t kMagic = 0x41545631;

enum class Kind : std::uint32_t {
    Hello = 1,
    Apply = 2,
    Applied = 3,
    Telemetry = 4
};

// 父子双方按字节累计到完整帧后才能解释；身份字段防止把入队当作应用回执。
struct Frame {
    std::uint32_t magic = kMagic;
    std::uint32_t version = 1;
    Kind kind = Kind::Hello;
    std::uint32_t bytes = 64;
    std::uint64_t session = 0;    // 本次父子进程会话关联标识。
    std::uint64_t command = 0;    // 命令编号，Hello 和遥测保持零。
    DWORD pid = 0;               // 本次自有子进程 PID。
    DWORD mainTid = 0;           // 主线程也是业务计数线程。
    DWORD writerTid = 0;         // 遥测写入者；负控中同时消费命令。
    DWORD controlTid = 0;        // 正控专用控制读取者。
    std::uint64_t value = 0;      // 应用计数或遥测帧序号。
    std::uint64_t reserved = 0;
};
static_assert(sizeof(Frame) == 64);

// 匿名共享映射提供独立于 ACK 管道的副作用观察，全部通过 Interlocked 访问。
struct Shared {
    volatile LONG64 businessTicks; // 主线程持续增加，用于核对冻结时不再前进。
    volatile LONG64 applied;       // 控制消费者实际应用命令后才增加。
    volatile LONG writerError;     // 同步写返回状态，取消预期为 ERROR_OPERATION_ABORTED。
    volatile LONG childError;      // 协议或子端控制错误，不允许静默通过。
};
} // namespace ActionTransportValidation
