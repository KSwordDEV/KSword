#pragma once

#include "InjectionDiscovery.h"
#include "../../../shared/evidence/ApiInjectionFields.h"
#include "../../../shared/evidence/ApiApcFields.h"
#include "../../../shared/evidence/ApiContextFields.h"

#include <deque>

namespace Ksword::ActionAnalyze::Detection {

// 连接的是源包报告的写入与后续线程创建，不授予实际执行或区域版本结论。
struct ApiTransferLink {
    EvidenceRef write; // 已核验原始写入包的位置。
    EvidenceRef threadCreate; // 后续创建请求返回包的位置，可位于另一段。
    std::uint32_t actorPid = 0; // 两包共同声明的发起者 PID。
    std::uint64_t actorCreationFileTime = 0; // 区分发起者 PID 的不同代次。
    std::uint32_t targetPid = 0; // 两包共同解析的目标 PID。
    std::uint64_t targetCreationFileTime = 0; // 区分目标 PID 的不同代次。
    std::uint64_t writtenAddress = 0; // 实际写入区间起点。
    std::uint64_t writtenBytes = 0; // 实际完成长度，不以请求长度代替。
    std::uint64_t requestedStartAddress = 0; // 落在该区间中的请求线程入口。
    bool operator==(const ApiTransferLink&) const = default;
};

// APC队列接受与先前写入的一致性候选；入队成功不提供投递或执行事实。
struct ApiApcTransferLink {
    EvidenceRef write; // 实际完成写入的原包坐标。
    EvidenceRef queue; // 后续APC队列请求返回包的原始坐标。
    std::uint32_t actorPid = 0; // 两包共同报告的发起者PID。
    std::uint64_t actorCreationFileTime = 0; // 发起者创建代次。
    std::uint32_t targetPid = 0; // APC线程所属目标进程。
    std::uint64_t targetCreationFileTime = 0; // 目标进程创建代次。
    std::uint32_t targetTid = 0; // API调用窗口中核验的目标线程编号。
    std::uint64_t targetThreadCreationFileTime = 0; // 目标线程创建代次。
    std::uint64_t writtenAddress = 0; // 实际写入区间首地址。
    std::uint64_t writtenBytes = 0; // 实际完成写入的字节数。
    std::uint64_t requestedRoutineAddress = 0; // 落在实际写入范围内的请求APC例程。
    bool operator==(const ApiApcTransferLink&) const = default;
};

// 先前实际写入与后续设置上下文请求的一致性候选，不宣称目标采用请求IP。
struct ApiContextTransferLink {
    EvidenceRef write; // 已提交的实际写入原包。
    EvidenceRef context; // 已提交的上下文设置返回原包。
    std::uint32_t actorPid = 0; // 两次调用共同报告的源进程。
    std::uint64_t actorCreationFileTime = 0; // 源进程创建代次。
    std::uint32_t targetPid = 0; // 请求线程所属进程。
    std::uint64_t targetCreationFileTime = 0; // 目标进程创建代次。
    std::uint32_t targetTid = 0; // 设置上下文的目标线程。
    std::uint64_t targetThreadCreationFileTime = 0; // 目标线程创建代次。
    std::uint64_t writtenAddress = 0; // 先前实际写入区间起点。
    std::uint64_t writtenBytes = 0; // 实际完成长度，不以请求长度代替。
    std::uint64_t requestedIp = 0; // 原请求指令地址，必须落在写入范围。
    std::uint64_t requestedSp = 0; // 同次CONTROL请求中的栈指针。
    std::uint64_t contextArchitecture = 0; // 请求CONTEXT的32/64位ABI。
    bool operator==(const ApiContextTransferLink&) const = default;
};

// 每个分析实例只接收同一采样。保留有界的实际写入记录，逐包消费且不访问目标现场。
class ApiTransferChain final {
public:
    explicit ApiTransferChain(SampleScope scope);
    // 输入必须由归档调用者在封装核验成功后提交；返回本条创建操作形成的全部区间候选。
    std::vector<ApiTransferLink> Accept(const EvidenceRef& evidence,
        const ks::winapi_monitor::ApiMonitorEventPacket& packet);
    // 每包先调用Accept登记写入，再调用本函数分析AAAP1；共享同一有界写入窗口，不重复缓存。
    std::vector<ApiApcTransferLink> AcceptApc(const EvidenceRef& evidence,
        const ks::winapi_monitor::ApiMonitorEventPacket& packet) const;
    // 在Accept后消费AACT1，输出真实写入范围内的请求IP候选，仍不授执行结论。
    std::vector<ApiContextTransferLink> AcceptContext(const EvidenceRef& evidence,
        const ks::winapi_monitor::ApiMonitorEventPacket& packet) const;
    // 容量淘汰意味着旧链路可能遗漏，必须随查询回执公开。
    std::uint64_t EvictedWrites() const noexcept { return evictedWrites_; }

private:
    struct Write {
        EvidenceRef evidence; // 保存实际段与序号，跨段关联不使用当前页行号。
        Evidence::ApiInjectionFieldsV1 fields; // 源端冻结的身份、范围和时间。
        std::uint32_t actorPid = 0; // 包头中的调用者 PID。
        std::uint64_t session = 0; // 同一来源管道会话，不与另一轮采样混合。
    };
    SampleScope scope_; // 项目及采样作用域，由上层从当前目录冻结。
    std::deque<Write> writes_; // 最近成功且有实际范围的写入。
    std::uint64_t evictedWrites_ = 0; // 只累计本分析实例中的容量淘汰。
};

} // namespace Ksword::ActionAnalyze::Detection
