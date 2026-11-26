#pragma once

#include "ArchivedEvidenceGraph.h"
#include "../Project/ProjectNativeExecution.h"

namespace Ksword::ActionAnalyze::Detection {

// 保留三份独立来源坐标。关联说明同一已报告线程在写入范围中被观察，不反推因果。
struct NativeTransferAssociation {
    ApiTransferLink transfer;
    std::uint64_t nativeSegmentOrdinal = 0;
    std::uint64_t nativeRecordSequence = 0;
    std::string nativeSha256;
    std::string observation; // execution-enter-attempt 或 instruction-completed，按原生档实值。
    std::uint64_t instructionAddress = 0;
    std::uint32_t tid = 0;
    std::uint64_t threadCreationFileTime = 0;
    std::optional<std::uint64_t> observedQpc;
    std::uint64_t createEnterQpc = 0;
    // 当前两类档案没有共同启动期时钟证明，保留原值但不比较先后。
    bool commonClockVerified = false;
    // API 与历史文件的声明身份尚未认证；本次匹配不提供区域/内容版本或直接归因。
    bool sourceAuthenticated = false;
    bool regionVersionVerified = false;
    bool causalityConfirmed = false;
};

// 输入来自已通过项目读端核验的 API 图页与原生段，不访问目标进程。
// 创建记录必须就是 transfer.threadCreate，且返回线程的 TID+FILETIME 与原生实际执行线程一致。
// 要求实际 RIP 位于实际写入半开范围；没有共同启动期时钟证明时不推断跨来源先后。
std::optional<NativeTransferAssociation> AssociateNativeTransfer(const SampleScope& scope,
    const ApiTransferLink& transfer, const ArchivedGraphRecord& creation,
    const ArchivedNativeExecution& execution, std::uint64_t nativeSegmentOrdinal);

// APC请求目标线程与实际原生执行线程的一致性候选，不声明队列请求导致执行。
struct NativeApcTransferAssociation {
    ApiApcTransferLink transfer; // 先前写入与后续接受队列请求的两个原坐标。
    std::uint64_t nativeSegmentOrdinal = 0; // 原生执行证据所在独立lane段号。
    std::uint64_t nativeRecordSequence = 0; // 原生执行记录序号。
    std::string nativeSha256; // 核验后的原生段摘要。
    std::string observation; // 进入尝试或单指令完成，保持原阶段。
    std::uint64_t instructionAddress = 0; // 必须等于本候选的请求APC例程入口。
    std::optional<std::uint64_t> observedQpc; // 原生时钟原值，禁止与API时钟比较先后。
    bool commonClockVerified = false; // 无共同启动期时钟证明。
    bool sourceAuthenticated = false; // 无历史生产者认证。
    bool regionVersionVerified = false; // 无区域或内容版本证明。
    bool causalityConfirmed = false; // 同线程同入口仍不证明APC投递路径。
};

// queue必须是transfer.queue指向的原始返回记录；不访问进程，不以入队接受代替执行。
std::optional<NativeApcTransferAssociation> AssociateNativeApcTransfer(const SampleScope& scope,
    const ApiApcTransferLink& transfer, const ArchivedGraphRecord& queue,
    const ArchivedNativeExecution& execution, std::uint64_t nativeSegmentOrdinal);

// 设置上下文请求与独立执行观察的一致性结果，不表示由设置请求导致实际执行。
struct NativeContextTransferAssociation {
    ApiContextTransferLink transfer; // 写入和设置请求的两个已提交原坐标。
    std::uint64_t nativeSegmentOrdinal = 0; // 独立raw-native段号。
    std::uint64_t nativeRecordSequence = 0; // 已核验执行记录的原序号。
    std::string nativeSha256; // 执行段的实际摘要。
    std::string observation; // 原执行阶段，进入尝试和指令完成不混用。
    std::uint64_t instructionAddress = 0; // 与请求IP相等的真实原生指令起点。
    std::optional<std::uint64_t> observedQpc; // 原生时钟原值，不跨来源排序。
    bool commonClockVerified = false; // 未确认共同启动期时钟。
    bool sourceAuthenticated = false; // 文件完整性不认证历史生产者。
    bool regionVersionVerified = false; // 未确认写入与执行之间的内存版本。
    bool causalityConfirmed = false; // 同线程同IP仍不证明请求导致执行。
};

// 输入已核验的写入→请求候选、该请求原包和执行段；返回精确线程/请求IP一致的候选。
// 不访问目标，也不把请求SP或CONTEXT地址用作历史现场读取。
std::optional<NativeContextTransferAssociation> AssociateNativeContextTransfer(const SampleScope& scope,
    const ApiContextTransferLink& transfer, const ArchivedGraphRecord& context,
    const ArchivedNativeExecution& execution, std::uint64_t nativeSegmentOrdinal);

} // namespace Ksword::ActionAnalyze::Detection
