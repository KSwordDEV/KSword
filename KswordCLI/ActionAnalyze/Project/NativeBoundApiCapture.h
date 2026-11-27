#pragma once

#include "AttachedApiCapture.h"
#include <atomic>

namespace Ksword::ActionAnalyze {

// 三端在点击时冻结的参数；本服务只接收明确来源，不从native目标推导来源。
struct NativeBoundApiRequest {
    DWORD sourcePid = 0; // 显式选择的API来源PID。
    std::uint64_t sourceCreationFileTime = 0; // 与来源PID一起复核真实进程实例。
    DWORD durationMs = 3000; // Ready后的有限采集区间，范围1000..10000毫秒。
    bool confirmed = false; // 用户本次确认装载匹配架构的产品Agent。
};

// 由原串行worker从活owner读取；只有值，不包含句柄、停止令牌或恢复责任。
struct NativeBoundApiTarget {
    DWORD pid = 0; // 原native owner实际控制的目标PID。
    std::uint64_t creationFileTime = 0; // 原owner查询到的目标创建时间。
    bool attached = false; // 原owner当前是否仍附加。
};

// 与CLI错误标识对应的准入拒绝；归档/采集失败由receipt分别保存。
enum class NativeBoundApiRejection {
    None,
    InvalidSource,
    ProjectUnavailable,
    NativeUnavailable,
    SourceIsNativeTarget
};

// 可由三端快照直接传回UI；不需要UI打开项目文件或解析JSON。
struct NativeBoundApiResult {
    bool accepted = false; // 参数、原writer和native目标准入通过，不代表采集成功。
    NativeBoundApiRejection rejection = NativeBoundApiRejection::None; // 稳定的准入原因。
    ProjectResult admission; // 仅准入结果，不覆盖采集与存储回执。
    std::string projectId; // 借用原writer对应的冻结项目身份。
    std::string sampleId; // 本次原采样ID；拒绝时也保留请求身份。
    NativeBoundApiRequest request; // 产生本回执的来源草稿快照。
    NativeBoundApiTarget nativeTarget; // 请求时原owner查询的目标快照。
    CooperativeApiReceipt receipt; // 原采集器的附加、清退、归档、规则和转移候选值。

    // 无输入；返回采集本身状态码，部分区间、清退或派生缺口不能变成完整成功。
    int CaptureExitCode() const noexcept;
    // 无输入；返回原CLI综合状态码；采集与archive原值仍可独立读取。
    int ExitCode() const noexcept;
};

// 原采集线程发布的启动值；身份取自本次请求与原writer，不借用native停止票据。
struct NativeBoundApiProgress {
    std::string projectId; // 本次借用的项目身份。
    std::string sampleId; // 本次写入的原采样身份。
    NativeBoundApiRequest request; // 本次冻结的API来源和有限区间。
    NativeBoundApiTarget nativeTarget; // 启动前从原owner读取的不同目标实例。
    ks::winapi_monitor::CaptureStartupProgress startup; // 原采集器实际完成的最后里程碑。
};

// 回调在原采集线程同步执行；调用端只复制值，不查询或释放native owner。
using NativeBoundApiStartup = std::function<void(const NativeBoundApiProgress&)>;

// 纯值准入：供Prepare提前显示错误；writer/sample准入仍在执行时核对。
// 输入明确来源与原owner目标，返回稳定拒绝原因；不查询进程或变更控制状态。
NativeBoundApiRejection ValidateNativeBoundApiRequest(const NativeBoundApiRequest& request,
    const NativeBoundApiTarget& nativeTarget) noexcept;

// 在原native串行worker同步执行，借用document及sampleId，不开lease/sample/writer。
// nativeTarget必须来自当前原owner查询；cancel只停止API，服务不持有或调用native owner。
// onStartup在同线程借用本次冻结身份和原阶段，调用者只复制值；不参与Ready或归档判定。
// 返回纯值完整回执；已有raw/checkpoints由原采集归档链拒绝，禁止覆盖或跳段。
NativeBoundApiResult CaptureNativeBoundApi(ProjectDocument& document, std::string_view sampleId,
    const NativeBoundApiRequest& request, const NativeBoundApiTarget& nativeTarget,
    const std::atomic_bool& cancel, const NativeBoundApiStartup& onStartup = {},
    const CooperativeApiCommitted& onCommitted = {}, const CooperativeApiTransferCommitted& onTransfers = {});

} // namespace Ksword::ActionAnalyze
