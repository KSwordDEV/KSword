#include "WorkbenchIoPorts.h"

#include <sstream>

// ============================================================
// WorkbenchIoPorts.Kernel.cpp
// 作用：
// - 实现 WorkbenchKernelMutationPort（ksword::memwb::IKernelMutationPort 的
//   真实端口），封装"标准驱动通道 + 内核虚拟地址"写入必须经过的分步字节
//   事务 IOCTL：PREPARE -> COMMIT(DRY_RUN) -> COMMIT(FORCE) -> 回读复核，
//   失败则 ROLLBACK。
// - 本文件只翻译协议状态，不做"该不该回滚""回滚够不够"之类的判断——那些
//   策略在 shared/evidence/memory_workbench/MemoryKernelMutation.h 里实现
//   并测试过；本文件负责发一次 IOCTL、翻译一次结果，不包含切片循环与回滚列表。
// ============================================================

namespace ksword::memwb_ports
{
    // BuildPrepareFailureText：保留地址、事务、协议状态、NT 状态和原始驱动信息。
    std::string WorkbenchKernelMutationPort::BuildPrepareFailureText(
        const std::uint64_t address,
        const std::uint64_t transactionId,
        const std::uint32_t status,
        const long lastStatus,
        const std::string& ioMessage)
    {
        std::ostringstream stream;
        stream << "内核字节事务 PREPARE 失败：地址=0x"
            << std::hex << std::uppercase << address << std::dec
            << " tx=" << transactionId
            << " 状态=" << status
            << " NT=0x" << std::hex << std::uppercase
            << static_cast<unsigned long>(lastStatus) << std::dec
            << " 信息=" << (ioMessage.empty() ? "无额外驱动消息" : ioMessage);
        return stream.str();
    }

    // BuildStepFailureText：DryRunCommit/ForceCommit/Rollback 失败时的细节
    // 串。接口没有把地址传给这三步（见 IKernelMutationPort::DryRunCommit/
    // ForceCommit/Rollback 签名），因此不写地址——写一个编造出来的地址比
    // 不写更容易误导排查。
    std::string WorkbenchKernelMutationPort::BuildStepFailureText(
        const char* const stageName,
        const std::uint64_t transactionId,
        const std::uint32_t status,
        const long lastStatus,
        const std::string& ioMessage)
    {
        std::ostringstream stream;
        stream << stageName << " 失败：tx=" << transactionId
            << " 状态=" << status
            << " NT=0x" << std::hex << std::uppercase
            << static_cast<unsigned long>(lastStatus) << std::dec
            << " 信息=" << (ioMessage.empty() ? "无额外驱动消息" : ioMessage);
        return stream.str();
    }

    // Prepare：对一片（调用方已按 kKernelMutationSliceBytes 切好，≤64 字节）
    // 内核虚拟地址字节发起"演练 + 校验写入前内容"请求。
    // - flags 固定 DRY_RUN|EXPECTED_BEFORE_PRESENT，targetKind 固定
    //   KERNEL_VIRTUAL_BYTES_SMALL，遵循共享字节事务协议。
    // - 本类的 ok 只判断"这一步本身"：io.ok 且 status==PREPARED；
    //   transactionId!=0、beforeBytes 长度是否足够、以及 beforeBytes 前缀
    //   是否与 expectedBefore 相等，这三项交叉校验留给调用方
    //   （ksword::memwb::WriteKernelBytes）做——本类只负责把 R0 的原始回报
    //   如实转译，不重复别处已经做过的判断。
    ksword::memwb::MutationPrepareResult WorkbenchKernelMutationPort::Prepare(
        const std::uint64_t address,
        const std::vector<std::uint8_t>& after,
        const std::vector<std::uint8_t>& expectedBefore)
    {
        ksword::memwb::MutationPrepareResult result;

        ksword::ark::MutationPrepareInput input;
        input.flags =
            KSWORD_ARK_MUTATION_FLAG_DRY_RUN | KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT;
        input.targetKind = KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL;
        input.processId = 0U;
        input.bytes = static_cast<std::uint32_t>(after.size());
        input.targetAddress = address;
        input.targetContext = 0ULL;
        input.afterBytes = after;
        input.expectedBeforeBytes = expectedBefore;

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::MutationResponseResult response = driverClient.prepareMutation(input);

        result.transactionId = response.transactionId;
        result.beforeBytes = response.beforeBytes;
        result.ok = response.io.ok && response.status == KSWORD_ARK_MUTATION_STATUS_PREPARED;
        if (!result.ok)
        {
            result.failure = BuildPrepareFailureText(
                address, response.transactionId, response.status, response.lastStatus,
                response.io.message);
        }
        return result;
    }

    // DryRunCommit：对 Prepare 得到的事务执行一次演练提交（不真正落地），
    // 与旧编排第 1500-1519 行一致。
    ksword::memwb::MutationStepResult WorkbenchKernelMutationPort::DryRunCommit(
        const std::uint64_t transactionId)
    {
        ksword::memwb::MutationStepResult result;

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::MutationResponseResult response =
            driverClient.commitMutation(transactionId, KSWORD_ARK_MUTATION_FLAG_DRY_RUN);

        result.ok = response.io.ok && response.status == KSWORD_ARK_MUTATION_STATUS_DRY_RUN;
        if (!result.ok)
        {
            result.failure = BuildStepFailureText(
                "内核字节事务 DRY_RUN 提交", transactionId, response.status,
                response.lastStatus, response.io.message);
        }
        return result;
    }

    // ForceCommit：对事务执行强制真实提交，与旧编排第 1521-1541 行一致；
    // FORCE|UI_CONFIRMED 是固定组合（设计文档第 0 节第 16 条："固定带
    // FORCE|UI_CONFIRMED（旧行为）"），界面确认已经在写事务的确认步完成，
    // 这里不再向用户询问。
    ksword::memwb::MutationStepResult WorkbenchKernelMutationPort::ForceCommit(
        const std::uint64_t transactionId)
    {
        ksword::memwb::MutationStepResult result;

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::MutationResponseResult response = driverClient.commitMutation(
            transactionId,
            KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);

        result.ok = response.io.ok && response.status == KSWORD_ARK_MUTATION_STATUS_COMMITTED;
        if (!result.ok)
        {
            result.failure = BuildStepFailureText(
                "内核字节事务 FORCE 提交", transactionId, response.status,
                response.lastStatus, response.io.message);
        }
        return result;
    }

    // Rollback：把已经（部分）提交的事务回滚。成功判据复刻自旧编排第
    // 1686-1699 行：io.ok 且 status 为 ROLLED_BACK 或 ALREADY_AT_BEFORE 才算
    // 这一步成功；是否真的恢复到 expectedBefore 由调用方
    // （ksword::memwb::WriteKernelBytes）另外调用 ReadBack 独立复核，本类不
    // 代为判断"恢复没恢复"，只翻译 R0 对"回滚这一步"自身的回报。
    ksword::memwb::MutationStepResult WorkbenchKernelMutationPort::Rollback(
        const std::uint64_t transactionId)
    {
        ksword::memwb::MutationStepResult result;

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::MutationResponseResult response = driverClient.rollbackMutation(
            transactionId,
            KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);

        result.ok = response.io.ok &&
            (response.status == KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK ||
             response.status == KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE);
        if (!result.ok)
        {
            result.failure = BuildStepFailureText(
                "内核字节事务 ROLLBACK", transactionId, response.status,
                response.lastStatus, response.io.message);
        }
        return result;
    }

    // ReadBack：提交或回滚之后，走普通内核虚拟地址读取通道独立核对
    // [address, address+length) 的当前内容，不依赖事务号（事务可能已经
    // 结束）。与 WorkbenchIoPort::ReadStandardDriverVirtual 发起的是同一种
    // 调用（标准驱动、内核虚拟地址、不带 ZERO_FILL_UNREADABLE），因此复用
    // 同一个映射函数 MapStandardDriverVirtualRead，不在两处各写一遍判据。
    ksword::memwb::IoReadResult WorkbenchKernelMutationPort::ReadBack(
        const std::uint64_t address,
        const std::uint64_t length)
    {
        // 分步字节事务的目标按协议恒为内核虚拟地址，这里仍显式判断而不是
        // 假设，与 WorkbenchIoPort 保持同一判据来源（MemoryTargetSession.h
        // 的 IsKernelVirtualAddress），不新引入第二份阈值。
        const bool kernelAddress = ksword::memwb::IsKernelVirtualAddress(address);
        const unsigned long flags =
            kernelAddress ? KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS : 0UL;

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::VirtualMemoryReadResult driverResult = driverClient.readVirtualMemory(
            0U, address, static_cast<std::uint32_t>(length), flags);
        return ksword::memwb_ports_detail::MapStandardDriverVirtualRead(driverResult);
    }
}
