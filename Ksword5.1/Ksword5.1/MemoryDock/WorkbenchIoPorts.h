#pragma once

// ============================================================
// WorkbenchIoPorts.h
// 作用：
// - 内存工作台 Phase 3 WP-C 的"真实端口"薄壳：把既有的内存访问门面
//   （MemoryAccessBackend.h/.cpp）与驱动客户端（ArkDriverClient）适配到
//   Qt-free 逻辑层定义的 ksword::memwb::IMemoryIoPort 与
//   ksword::memwb::IKernelMutationPort 两个抽象接口上。
// - 本文件只做协议翻译与通道分发，不包含分块 / 重试 / 回滚 / 确认之类的策略——
//   那些策略已经在 shared/evidence/memory_workbench/ 的 Qt-free 逻辑层
//   （MemoryPageReader、MemoryIoByteStore、MemoryKernelMutation）里实现并测试
//   过；本文件的职责边界是"问门面一次、翻译一次结果"。
// - 依据：docs/内存工作台Phase3集成设计.md 第 0 节第 16/17 条、第 2 节 WP-C 文件
//   清单、第 3 节不变式 2/3/5/7；以及本次任务下发的【已核实的后端事实】1-8 条
//   （下称 FACTS，编号与任务说明一致，便于交叉核对）。
//
// ============================================================
// 冻结接口摘要（本文件新增的两个公开类型；改名或改语义须先同步通知）
// ============================================================
//   class WorkbenchIoPort : public ksword::memwb::IMemoryIoPort
//     Limits(session) -> IoLimits                         按通道/范围给出单次上限（FACTS 1）
//     Read(session,address,length) -> IoReadResult         按 FACTS 2/3/4 分发并映射
//     Write(session,address,bytes,approved) -> IoWriteResult 按 FACTS 5 分发并映射
//     —— 无成员状态，可被读线程与 UI 线程并发调用；每次调用各自开句柄。
//   class WorkbenchKernelMutationPort : public ksword::memwb::IKernelMutationPort
//     Prepare(address,after,expectedBefore) -> MutationPrepareResult   封装 PREPARE
//     DryRunCommit(transactionId) -> MutationStepResult                封装 DRY_RUN 提交
//     ForceCommit(transactionId) -> MutationStepResult                 封装 FORCE 提交
//     Rollback(transactionId) -> MutationStepResult                    封装回滚
//     ReadBack(address,length) -> IoReadResult                         内核虚拟地址直读复核
//     —— 无成员状态；每次调用各自构造 DriverClient，不持有驱动句柄。
//
// ============================================================
// 协议与验证边界
// ============================================================
// DriverClient 与共享协议头是函数签名和状态值的唯一来源。
// 本端口只翻译单次调用回执；事务切片、原值核对和实际恢复由逻辑层负责。
// 当前组件验证入口见 docs/内存编辑器组件清单.md；编译不等同于真实目标写入验收。
// ============================================================

#include "MemoryAccessBackend.h"
#include "WorkbenchIoMapping.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../../../shared/evidence/memory_workbench/MemoryIoPort.h"
#include "../../../shared/evidence/memory_workbench/MemoryTargetSession.h"

#include <cstdint>
#include <string>
#include <vector>

// M-1（主会话审核拆分）：MapFacadeReadOutcome、MapFacadeWriteOutcome、
// MapStandardDriverVirtualRead 三个纯映射函数已经搬进 WorkbenchIoMapping.h/
// .cpp（见上面的 #include），本文件与 WorkbenchIoPorts.cpp/.Kernel.cpp 只负责
// "真的去问门面/驱动一次"，问完调用那三个函数翻译结果，不在这里重复声明。

namespace ksword::memwb_ports
{
    // WorkbenchIoPort：
    // - 作用：ksword::memwb::IMemoryIoPort 的真实实现，是内存工作台读写一段
    //   目标内存时真正触碰硬件/驱动的那一跳。
    // - 通道分发（细节见 WorkbenchIoPorts.cpp 顶部注释）：
    //     物理范围（任意通道） -> 经 ksword::memory_backend::readPhysical/
    //       writePhysical（物理读写本身没有"伪造零字节"的问题，统一经门面）；
    //     虚拟范围 + UserMode  -> 本类自行 OpenProcess/ReadProcessMemory/
    //       WriteProcessMemory（门面的用户态分支无法区分"打开失败"与
    //       "读到 0 字节"，不满足 IoReadStatus 的四态语义，FACTS 第 3 条）；
    //     虚拟范围 + StandardDriver 读 -> 直接调用
    //       ksword::ark::DriverClient::readVirtualMemory，不带
    //       ZERO_FILL_UNREADABLE（门面固定带这个标志，会把未读到的字节说成
    //       "读到了全 0"，FACTS 第 2 条）；
    //     虚拟范围 + StandardDriver 写 + 内核虚拟地址 -> 明确失败（该组合必须
    //       经 IKernelMutationPort 分步字节事务，不在本类处理，FACTS 第 5/6
    //       条）；
    //     虚拟范围 + StandardDriver 写（非内核地址）、Hvm、Ddma -> 经
    //       ksword::memory_backend::readVirtual/writeVirtual。
    // - Ddma 通道读写共用同一把进程级互斥闸（静态存储，函数内持锁范围最小且
    //   不嵌套），因为门面本身对磁盘控制器传输通道没有互斥（设计文档第 3 节
    //   不变式 2）。
    // - 线程安全：无成员状态，会话由每次调用的参数传入；可被读线程与 UI 线程
    //   并发调用。R3/R0 调用每次各自开句柄，不缓存、不共享 Dock 持有的句柄。
    class WorkbenchIoPort final : public ksword::memwb::IMemoryIoPort
    {
    public:
        WorkbenchIoPort() = default;

        // Limits：见文件头"冻结接口摘要"；按 FACTS 第 1 条给出协议上限。
        // StandardDriver 通道按范围区分虚拟/物理上限；UserMode（R3 没有协议
        // 上限）、Hvm（门面内部按 1024 字节切片）、Ddma（门面内部按 4KiB 页
        // 切片）三个通道统一返回 0（不限），避免在这里重复做出一个可能与
        // 门面内部切片不一致的第二份切片决定。
        ksword::memwb::IoLimits Limits(
            const ksword::memwb::MemoryTargetSession& session) const override;

        // Read：见文件头与本类顶部注释的通道分发说明。
        ksword::memwb::IoReadResult Read(
            const ksword::memwb::MemoryTargetSession& session,
            std::uint64_t address,
            std::uint64_t length) override;

        // Write：见文件头与本类顶部注释的通道分发说明。
        ksword::memwb::IoWriteResult Write(
            const ksword::memwb::MemoryTargetSession& session,
            std::uint64_t address,
            const std::vector<std::uint8_t>& bytes,
            bool approved) override;

    private:
        // ReadUserModeVirtual：R3 通道虚拟读，自行实现而不经门面（原因见上）。
        // 传入：pid 目标进程号；address 虚拟地址；length 请求长度。
        // 传出：Failed（内核地址或打开进程失败）/ Unreadable（读到 0 字节）/
        //       Partial（0<字节<请求）/ Ok（全部读到）。
        static ksword::memwb::IoReadResult ReadUserModeVirtual(
            std::uint32_t pid,
            std::uint64_t address,
            std::uint64_t length);

        // ReadStandardDriverVirtual：标准驱动通道虚拟读，直接调用
        // DriverClient::readVirtualMemory，不带 ZERO_FILL_UNREADABLE。
        // 内核虚拟地址由 IsKernelVirtualAddress 判定（唯一判据来源，见
        // MemoryTargetSession.h），而不是看 session.scope，因为 R0 驱动本身
        // 就是按地址数值而不是按调用方声称的范围来决定是否需要
        // KERNEL_ADDRESS 标志。
        static ksword::memwb::IoReadResult ReadStandardDriverVirtual(
            std::uint32_t pid,
            std::uint64_t address,
            std::uint64_t length);

        // ReadViaFacade：经 ksword::memory_backend 门面的读取分支（物理范围
        // 的任意通道、虚拟范围的 Hvm/Ddma 通道）。Ddma 通道在调用门面之前先
        // 做 isDdmaUsable 预检（FACTS 第 4 条："磁盘传输会话不可用"->Failed，
        // 这一条无法从门面返回值事后区分，必须作为前置闸门），并在预检通过
        // 后持进程级互斥闸再调用门面。
        static ksword::memwb::IoReadResult ReadViaFacade(
            const ksword::memwb::MemoryTargetSession& session,
            std::uint64_t address,
            std::uint64_t length);

        // WriteViaFacade：经门面的写入分支（除"标准驱动+内核虚拟地址"之外的
        // 全部组合）。Ddma 通道同样先做 isDdmaUsable 预检再持闸调用。
        static ksword::memwb::IoWriteResult WriteViaFacade(
            const ksword::memwb::MemoryTargetSession& session,
            std::uint64_t address,
            const std::vector<std::uint8_t>& bytes,
            bool approved);
    };

    // WorkbenchKernelMutationPort：
    // - 作用：ksword::memwb::IKernelMutationPort 的真实实现，封装"标准驱动
    //   通道 + 内核虚拟地址"写入必须经过的分步字节事务 IOCTL
    //   （PREPARE/COMMIT/ROLLBACK，shared/driver/KswordArkMutationIoctl.h）。
    // - 本类只负责"问一次、答一次"：Prepare 的四项交叉校验（transactionId、
    //   beforeBytes 长度、expectedBefore 前缀比对）由上层
    //   ksword::memwb::WriteKernelBytes 负责，本类的 Prepare 只判断 R0 是否
    //   把这一步本身的状态回报为 PREPARED。
    // - 回滚成功判据（DryRunCommit/ForceCommit 同理，只是比对各自的状态值）
    //   按共享协议回执判定：
    //   io.ok 且 status 为 ROLLED_BACK 或 ALREADY_AT_BEFORE 才算 Rollback
    //   成功；是否真的恢复仍由调用方（MemoryKernelMutation）用 ReadBack 复核，
    //   本类不代为判断"恢复没恢复"。
    // - 线程安全：无成员状态；每次调用各自构造 ksword::ark::DriverClient。
    class WorkbenchKernelMutationPort final : public ksword::memwb::IKernelMutationPort
    {
    public:
        WorkbenchKernelMutationPort() = default;

        ksword::memwb::MutationPrepareResult Prepare(
            std::uint64_t address,
            const std::vector<std::uint8_t>& after,
            const std::vector<std::uint8_t>& expectedBefore) override;

        ksword::memwb::MutationStepResult DryRunCommit(std::uint64_t transactionId) override;

        ksword::memwb::MutationStepResult ForceCommit(std::uint64_t transactionId) override;

        ksword::memwb::MutationStepResult Rollback(std::uint64_t transactionId) override;

        ksword::memwb::IoReadResult ReadBack(
            std::uint64_t address,
            std::uint64_t length) override;

    private:
        // BuildPrepareFailureText：Prepare 失败时的细节串，带地址（这一步的
        // 调用方唯一一次把地址传给本类，之后三步都只有事务号）。
        static std::string BuildPrepareFailureText(
            std::uint64_t address,
            std::uint64_t transactionId,
            std::uint32_t status,
            long lastStatus,
            const std::string& ioMessage);

        // BuildStepFailureText：DryRunCommit/ForceCommit/Rollback 失败时的
        // 细节串，不带地址（接口没有把地址传给这三步，不得编造）。
        static std::string BuildStepFailureText(
            const char* stageName,
            std::uint64_t transactionId,
            std::uint32_t status,
            long lastStatus,
            const std::string& ioMessage);
    };
}
