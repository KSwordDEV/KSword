#pragma once

#include "../../../KswordCLI/ActionAnalyze/Detection/PrivateExecutionCandidates.h"
#include "../../../KswordCLI/ActionAnalyze/Project/NativeBoundApiCapture.h"
#include <memory>

namespace ks::action_analyze
{
    // 原页面从本轮worker快照提供的绑定；不从目录文本或裸PID推导现场资格。
    struct NativeExecutionCandidatesContext
    {
        std::wstring projectDirectory; // 原archive创建项目时冻结的目录，沿用同一字符串。
        std::string projectId; // 已知时提供原项目UUID；首次仅有目录/sample时可空，回执始终填实际值。
        std::string sampleId; // 原archive的唯一采样，不允许候选请求改选采样。
        Ksword::ActionAnalyze::NativeBoundApiTarget target; // 原native目标PID、创建时间和附加状态。
        bool nxBinding = false; // 原binding当前为NX；仅影响准备草稿，不阻止只读查询。
        bool fullHeld = false; // 原页面核对的完整Held资格；不包含停止令牌。
    };

    // 拥有全部字符串的跨线程请求；不能把底层string_view请求直接放入队列。
    struct NativeExecutionCandidatesRequest
    {
        NativeExecutionCandidatesContext context; // 点击时本轮项目、采样及目标强实例。
        std::uint64_t serial = 0; // Pane单调请求号，拒绝旧异步结果覆盖新请求。
        std::uint64_t throughOrdinal = 1; // 用户明确指定1..128的已提交API截止段。
        std::optional<Ksword::ActionAnalyze::Detection::RawLocator> after; // 上页末行原Stored坐标。
        std::string snapshot; // 续页绑定原完整前缀；首读可以为空。
    };

    // worker发布的纯值回执；只在成功时携带完整候选页，失败不冒充成功空页。
    struct NativeExecutionCandidatesResult
    {
        NativeExecutionCandidatesRequest request; // 完整保存实际请求，便于核对游标及来源。
        NativeExecutionCandidatesContext context; // archive确认的实际目录、项目与原sample。
        Ksword::ActionAnalyze::ProjectResult result; // 本次只读失败独立于内存/API归档状态。
        std::uint64_t readFileTime = 0; // 本次读取完成的UTC FILETIME，非原事件发生时间。
        std::shared_ptr<const Ksword::ActionAnalyze::Detection::PrivateExecutionCandidatesPage> page; // 成功纯值页。
    };

    // 比较真实归属及目标代次；NX/Held/attached变化由动作资格单独核对。
    // 两个参数均为原worker/Panes冻结值，不进行文件或进程查询。
    bool SameExecutionCandidatesBinding(const NativeExecutionCandidatesContext& left,
        const NativeExecutionCandidatesContext& right);
}
