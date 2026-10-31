#pragma once
#include <optional>

// ============================================================
// MemoryIoPort.h
// 作用：
// - 定义"内存工作台读写一段真实目标内存"的最小抽象接口 IMemoryIoPort，以及
//   "内核分步字节事务"（Prepare/DryRun/Force/Rollback/ReadBack）的抽象接口
//   IKernelMutationPort。真实实现（薰壳适配 MemoryAccessBackend / ArkDriverClient）
//   属于后续工作包，本文件只固定接口形状，供 MemoryPageReader 等 Qt-free 逻辑层
//   与假端口测试依赖。
// - 本文件只声明类型，不含任何实现、不含任何真实 I/O，因此不依赖任何协议头
//   （shared/driver/*）或 Windows 头；只依赖标准库与同目录的 MemoryTargetSession.h。
//
// ============================================================
// 冻结接口摘要（由主会话定死，改名或改语义必须先同步通知）
// ============================================================
//   struct IoLimits{maxReadBytes,maxWriteBytes}       单次访问的字节上限，0=不限
//   enum class IoReadStatus{Ok,Partial,Unreadable,Failed}
//   struct IoReadResult{status,data,scratchAreaDirty,readModifyWriteWindow,failure}
//                                                      .BytesDone() == data.size()
//   struct IoWriteResult{ok,partial,bytesDone,needsApproval,rolledBack,
//                         scratchAreaDirty,readModifyWriteWindow,failure}
//   class IMemoryIoPort{ Limits(session); Read(session,address,length);
//                         Write(session,address,bytes,approved) }
//   struct MutationStepResult{ok,failure}
//   struct MutationPrepareResult{ok,transactionId,beforeBytes,failure}
//   class IKernelMutationPort{ Prepare; DryRunCommit; ForceCommit; Rollback; ReadBack }
//
// ============================================================
// 四种读取状态的含义（不是四种"失败等级"，是四种不同的事实）
// ============================================================
// - Ok：请求的 [address, address+length) 全部读到，data.size()==length。
// - Partial：data 是**真实读到**的前缀，长度非空且小于 length；前缀之后的字节
//   本次没有读到（既不是"读到了 0"，也不是"通道坏了"）。调用方（如
//   MemoryPageReader）据此判定"失败点"所在，不得把 data 之后的内容当作任何值。
// - Unreadable：一个字节都没读到，且原因**在目标本身**（页面保护、地址不存在、
//   驱动明确回报"读不到"），通道本身是健康的，换一个地址可能就能读到。
// - Failed：通道自身出了问题（句柄失效、驱动未加载、DDMA 会话失效……），
//   没有得到关于目标任何字节是否可读的结论；调用方不应把这当成"目标不可读"，
//   也不应据此判断旁边的地址可读还是不可读。
// 不变式：仅仅"没读到"绝不能等同于"读到了全 0"——界面与逻辑层都必须能分清
// "没有数据"与"数据是 0"，这正是本文件存在的理由之一。
//
// ============================================================
// IByteStore 的区分：本接口与 MemoryWriteTransaction.h 的 IByteStore 不是一回事
// ============================================================
// - IByteStore 是"写事务已经决定要写这几个字节"之后的最后一跳，语义更贴近
//   "读/写一段已知地址"的协议细节（needsExplicitApproval、rolledBack 等）。
// - IMemoryIoPort 面向更上层的页读取 / 通道选择，Read 的语义是"尽量读、如实
//   报告读到了多少"，不是"必须整体成功才算数"。两者刻意不合并，真实适配层
//   （后续工作包的 WorkbenchIoPorts）各自按语义转译，不在这里做语义折叠。
//
// 线程模型：本文件只有类型声明，没有状态，天然线程安全；具体实现的线程安全性
// 由各自的实现自行声明（真实端口按设计文档要求"每次按 PID 自己开句柄"）。
// C++20、Qt-free、Win32-free。
// ============================================================

#include "MemoryTargetSession.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ksword::memwb
{
    // IoLimits：一次 Read / Write 允许携带的最大字节数，由端口按自己的通道给出。
    // 0 表示"没有额外限制"（调用方可以一次请求任意长度，端口自己决定怎么切）。
    // 调用方法：先调用 IMemoryIoPort::Limits(session) 取得，再用它规划分块。
    struct IoLimits
    {
        // maxReadBytes：单次 Read 允许的最大字节数，0=不限。
        std::uint64_t maxReadBytes = 0;
        // maxWriteBytes：单次 Write 允许的最大字节数，0=不限。
        std::uint64_t maxWriteBytes = 0;
    };

    // IoReadStatus：一次 Read 的结果种类，含义见文件头"四种读取状态"一节。
    // 没有"自动重试""自动降级"的隐含状态——四种之外没有第五种可能。
    enum class IoReadStatus
    {
        // Ok：全部读到，data 长度等于请求长度。
        Ok,
        // Partial：data 是真实读到的非空前缀，短于请求长度。
        Partial,
        // Unreadable：一个字节也没读到，原因在目标本身。
        Unreadable,
        // Failed：通道自身失败，没有得到关于目标的任何结论。
        Failed
    };

    // IoReadResult：Read 的返回值。默认值是最安全的"失败、什么都没读到"。
    struct IoReadResult
    {
        // status：见 IoReadStatus。
        IoReadStatus status = IoReadStatus::Failed;
        // data：Ok 时等于请求长度；Partial 时是真实前缀；Unreadable/Failed 时为空。
        std::vector<std::uint8_t> data;
        // scratchAreaDirty：本次访问弄脏了暂存区域（例如 DDMA 暂存扇区未能还原）。
        // Ok/Partial 成功时也可能为真，不能只在失败分支里看这个字段。
        bool scratchAreaDirty = false;
        // readModifyWriteWindow：本次访问走了"读-改-写"窗口，期间目标可能被别的
        // 写入者改动，调用方据此知道这次读到的数据存在一个竞态窗口。
        bool readModifyWriteWindow = false;
        // failure：失败原因细节串（英文，细节串而非面向用户的句子，界面层负责本地化）。
        // Ok/Partial 时也可以非空，用来搬运"回退/降级"一类的注记文本。
        std::string failure;

        // BytesDone：实际读到的字节数，即 data 的长度。
        // 调用方法：result.BytesDone()；对 Ok 恒等于请求长度，对其余状态是真实前缀长度。
        std::uint64_t BytesDone() const noexcept
        {
            return data.size();
        }
    };

    // IoWriteResult：Write 的返回值。默认值是最安全的"没有写、不同意"。
    struct IoWriteResult
    {
        // ok：这次写入是否成功（忽略 partial 这一维度，partial 单独报）。
        bool ok = false;
        // partial：只写入了一部分。ok 为真时 partial 也可能为真，调用方按失败处理。
        bool partial = false;
        // bytesDone：实际写入的字节数。
        std::uint64_t bytesDone = 0;
        // needsApproval：后端要求用户显式同意后带着同意标志重试同一次写入；
        // 此时端口必须尚未写入任何字节（与 MemoryWriteTransaction::AccessResult
        // 的 needsExplicitApproval 同一语义，字段名按本文件冻结摘要命名）。
        bool needsApproval = false;
        // rolledBack：失败后端口已把这次写入回滚（目标恢复到写之前）。
        bool rolledBack = false;
        // scratchAreaDirty：同 IoReadResult，成功也可能为真。
        bool scratchAreaDirty = false;
        // readModifyWriteWindow：同 IoReadResult。
        bool readModifyWriteWindow = false;
        // failure：失败原因细节串，规则同 IoReadResult::failure。
        std::string failure;
    };

    // IMemoryIoPort：读写一段真实目标内存的最小抽象，真实实现是薰壳，只转译协议，
    // 不做分块 / 重试 / 回退之类的策略——那些策略全部在 Qt-free 的调用方
    // （MemoryPageReader、未来的 MemoryIoByteStore）里实现，端口只负责"问一次、
    // 答一次"，这样策略才能离线用假端口完整测试。
    class IMemoryIoPort
    {
    public:
        struct UnreadableExtent { std::uint64_t first = 0, last = 0; };
        // Optional, worker-only mapping evidence. Never infer a region from a failed byte read.
        virtual std::optional<UnreadableExtent> QueryUnreadableExtent(const MemoryTargetSession&, std::uint64_t)
        { return std::nullopt; }
        virtual ~IMemoryIoPort() = default;

        // Limits：本端口在当前会话下的单次访问上限。调用方据此规划分块，每次
        // 访问前都应该重新取一遍（不同会话、不同通道可能给出不同上限）。
        virtual IoLimits Limits(const MemoryTargetSession& session) const = 0;

        // Read：尽量读取 [address, address+length)，如实报告读到了多少。
        // 传入：session 当前目标会话；address 起始绝对地址；length 请求长度。
        // 传出：IoReadResult，语义见文件头"四种读取状态"一节。
        virtual IoReadResult Read(
            const MemoryTargetSession& session,
            std::uint64_t address,
            std::uint64_t length) = 0;

        // Write：把 bytes 写到 address。
        // 传入：approved 为真表示调用方已经取得用户对这次写入的显式同意
        //       （语义与 MemoryWriteTransaction::IByteStore::Write 的
        //       explicitApproval 一致）。
        // 传出：IoWriteResult。端口要求同意而 approved 为假时，needsApproval
        //       必须为真且不得写入任何字节。
        virtual IoWriteResult Write(
            const MemoryTargetSession& session,
            std::uint64_t address,
            const std::vector<std::uint8_t>& bytes,
            bool approved) = 0;
    };

    // ------------------------------------------------------------
    // 内核分步字节事务：旧编排的"Prepare -> DryRun -> Force -> ReadBack ->
    // （失败则 Rollback）"五步协议，每步独立成一个调用，方便调用方
    // （MemoryKernelMutation，后续工作包）在任一步失败时精确知道停在哪一步、
    // 该对哪些已记录的片执行回滚。
    // ------------------------------------------------------------

    // MutationStepResult：DryRunCommit / ForceCommit / Rollback 共用的结果形状，
    // 这三步都只需要"成功与否 + 失败原因"，不需要额外搬运数据。
    struct MutationStepResult
    {
        // ok：这一步是否成功。
        bool ok = false;
        // failure：失败原因细节串；成功时通常为空。
        std::string failure;
    };

    // MutationPrepareResult：Prepare 的结果，比 MutationStepResult 多出事务号与
    // 回读到的"写入前字节"，供调用方核对 expectedBefore 并在失败时用于回滚记账。
    struct MutationPrepareResult
    {
        // ok：Prepare 是否成功（通常要求 transactionId!=0 且 beforeBytes 足够长）。
        bool ok = false;
        // transactionId：后端分配的事务号，后续三步都要带着它；0 表示无效。
        std::uint64_t transactionId = 0;
        // beforeBytes：Prepare 时回读到的"写入前"字节，供调用方核对与 expectedBefore
        // 的前缀是否一致。
        std::vector<std::uint8_t> beforeBytes;
        // failure：失败原因细节串。
        std::string failure;
    };

    // IKernelMutationPort：内核虚拟地址分步字节事务的抽象，每个调用对应设计文档
    // 第 0 节第 16 条描述的其中一步；真实实现每片最多 64 字节（协议常量），本接口
    // 不感知这个数字，切片规则由调用方（MemoryKernelMutation）负责。
    class IKernelMutationPort
    {
    public:
        virtual ~IKernelMutationPort() = default;

        // Prepare：对 address 处的一片字节发起"演练 + 校验写入前内容"请求。
        // 传入：after 想写入的新字节；expectedBefore 调用方记忆中的原字节
        //       （用于核对目标是否已被别处改过）。
        // 传出：MutationPrepareResult，见上。
        virtual MutationPrepareResult Prepare(
            std::uint64_t address,
            const std::vector<std::uint8_t>& after,
            const std::vector<std::uint8_t>& expectedBefore) = 0;

        // DryRunCommit：对 Prepare 得到的事务执行一次演练提交（不真正落地）。
        virtual MutationStepResult DryRunCommit(std::uint64_t transactionId) = 0;

        // ForceCommit：对事务执行强制真实提交（真正落地到目标内存）。
        virtual MutationStepResult ForceCommit(std::uint64_t transactionId) = 0;

        // Rollback：把已经（部分）提交的事务回滚，恢复到 Prepare 之前的字节。
        virtual MutationStepResult Rollback(std::uint64_t transactionId) = 0;

        // ReadBack：提交之后回读 [address, address+length)，核对是否等于 after。
        // 独立于事务号，因为回读走的是普通内核虚拟地址读取通道，不是事务通道。
        virtual IoReadResult ReadBack(std::uint64_t address, std::uint64_t length) = 0;
    };
}
