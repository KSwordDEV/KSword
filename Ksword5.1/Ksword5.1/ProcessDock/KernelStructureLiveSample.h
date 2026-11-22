#pragma once

#include "KernelStructureTree.h"
#include "../ArkDriverClient/ArkStructureSampling.h"

#include <memory>

namespace ks::ui::kernelstructure
{
    // 页面创建时冻结目标；句柄贯穿所有刷新，缺少的创建时间不能在后续请求中重新绑定。
    struct LiveTarget
    {
        ksword::ark::DriverHandle process; // 可访问时持有原进程，防止仅凭旧 PID 切换对象。
        ksword::ark::DriverHandle thread; // 线程页持有原线程，进程页保持无效句柄。
        KSWORD_ARK_STRUCTURE_SAMPLE_REQUEST request{}; // 只含 PID、TID 和已冻结的创建时间。
        QString diagnostic; // 冻结身份失败的原因；非空时不发送任何采样请求。
    };

    // 一次正文查询的结果；即使退回固定字段，也保留新接口不可用的独立原因。
    struct LiveSample
    {
        ksword::ark::StructureSampleResult body; // 原始正文回执及其全行投影属于同一次采样。
        QString diagnostic; // GUI 线程翻译的失败原因，不在工作线程访问语言管理器。
    };

    // 在入口调用；输入列表身份，输出共享只读目标。零创建时间只从当前持有的句柄补齐。
    std::shared_ptr<const LiveTarget> CaptureLiveTarget(std::uint32_t pid, std::uint64_t processCreationTime,
        std::uint32_t tid = 0, std::uint64_t threadCreationTime = 0);

    // 输入冻结目标；输出当前仍可使用的身份状态。完整已知身份可由新协议独立复核。
    bool LiveTargetRunning(const LiveTarget& target);

    // 工作线程调用；输入冻结目标和磁盘布局，输出单次正文采样，仅完整身份通过才设置 runningMatch。
    LiveSample ReadLiveSample(const LiveTarget& target, Layout& layout);

    // GUI 线程调用；输入本次采样，输出 UTC 起止时间、非原子说明、全部行计数或明确失败原因。
    QString DescribeLiveSample(const LiveSample& sample);
}
