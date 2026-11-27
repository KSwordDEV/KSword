#include "NativeSessionApiFields.h"

#include <algorithm>
#include <limits>

namespace Ksword::Features::ActionAnalyze {
namespace project = Ksword::ActionAnalyze;
namespace {
// text为ASCII正十进制UTF-16文本，value输出无损数值；拒绝空、零、前导零及溢出。
bool Decimal(const std::wstring& text, std::uint64_t& value)
{
    if (text.empty() || text.front() == L'0')
    {
        return false;
    }
    value = 0;
    for (const auto ch : text) // 逐位检查避免wcstoull接受符号或部分合法前缀。
    {
        if (ch < L'0' || ch > L'9')
        {
            return false;
        }
        const auto digit = static_cast<unsigned>(ch - L'0'); // 当前十进制位。
        if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10)
        {
            return false;
        }
        value = value * 10 + digit;
    }
    return value != 0;
}

// 输入原EDIT句柄，输出有界全文；无效句柄返回空，由Prepare明确拒绝。
std::wstring Input(HWND control)
{
    if (!::IsWindow(control))
    {
        return {};
    }
    wchar_t text[32]{}; // 身份最多20位，超长文本由后端拒绝，不能截断成合法PID。
    if (::GetWindowTextLengthW(control) >= 31)
    {
        return {};
    }
    const auto length = ::GetWindowTextW(control, text, 32); // 当次冻结的输入长度。
    return std::wstring(text, static_cast<std::size_t>(length));
}

// 输入UTF-8项目身份、规则诊断或版本，输出UTF-16；保留非ASCII错误文本。
std::wstring Wide(std::string_view text)
{
    if (text.empty())
    {
        return {};
    }
    const auto length = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), nullptr, 0); // 所需UTF-16长度，错误不截断成成功摘要。
    if (!length)
    {
        return L"UTF-8 解码失败";
    }
    std::wstring result(static_cast<std::size_t>(length), L'\0'); // 本次完整转换输出。
    if (!::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
        result.data(), length))
    {
        return L"UTF-8 解码失败";
    }
    return result;
}
} // namespace

// 将在途身份与最后阶段写入原详情文本，保留完整来源，避免把旧最终回执归到新请求。
std::wstring FormatLightNativeSessionApiProgress(const project::NativeBoundApiProgress& progress)
{
    const auto& startup = progress.startup; // 控制器发布的真实值，不依据按钮或包数猜Ready。
    std::wstring text = L"\r\nAPI 附加与采集"; // 追加到原CodeEditor详情正文，不创建第二份日志。
    text += L"\r\n项目 ID：" + Wide(progress.projectId);
    text += L"\r\n采样 ID：" + Wide(progress.sampleId);
    text += L"\r\nAPI 来源 PID：" + std::to_wstring(progress.request.sourcePid);
    text += L"\r\n创建 FILETIME：" + std::to_wstring(progress.request.sourceCreationFileTime);
    text += L"\r\n原调试目标 PID：" + std::to_wstring(progress.nativeTarget.pid);
    // 阶段ID与CLI一致；Ready之后仍须等完整采集和排空的最终回执。
    text += L"\r\n最后确认的启动阶段：" + Wide(ks::winapi_monitor::CaptureStartupStageName(startup.stage));
    text += L"\r\n启动阶段耗时（毫秒）：" + std::to_wstring(startup.elapsedMs);
    text += L"\r\n就绪覆盖修订：" + (startup.coverageRevision ? std::to_wstring(startup.coverageRevision) : L"—");
    return text;
}

// 输入同次回调借用的checkpoint与规则快照，输出单目标和执行集合共用的原值文本。
std::wstring FormatLightNativeSessionApiCheckpoint(const project::ProjectApiCheckpoint& checkpoint,
    const project::CooperativeApiRuleReceipt& rules)
{
    std::wstring text = L"\r\n\r\n[API 已提交运行进度]\r\n采样=" + Wide(checkpoint.sampleId); // 规范详情追加文本。
    text += L"\r\n归档坐标=raw/" + std::to_wstring(checkpoint.ordinal) + L" #" +
        std::to_wstring(checkpoint.rawEnd.lastSequence);
    text += L"\r\n原包序号=" + std::to_wstring(checkpoint.lastSourceSequence) +
        L"\r\n段SHA256=" + Wide(checkpoint.rawSha256);
    text += L"\r\n终段=" + std::wstring(checkpoint.finalSegment ? L"是" : L"否") +
        L"\r\n规则命中=" + std::to_wstring(rules.matchedRows) +
        L"\r\n规则内容SHA256=" + Wide(rules.sourceSha256);
    if (rules.failed)
    {
        text += L"\r\n规则派生失败=" + Wide(rules.configError);
    }
    if (!rules.latest)
    {
        return text;
    }

    const auto& match = *rules.latest; // 最近命中保留自己的原段坐标，不贴到当前checkpoint。
    text += L"\r\n最近命中=raw/" + std::to_wstring(rules.latestSegment) + L" #" +
        std::to_wstring(match.rawSequence) + L" · " + Wide(match.api) + L" · " + Wide(match.ruleId);
    if (match.behavior)
    {
        text += L"\r\n行为释义=" + Wide(match.behavior->summaryZh.empty()
            ? match.behavior->summary : match.behavior->summaryZh);
        text += L"\r\n规则证据=" + Wide(match.behavior->evidence);
    }
    return text;
}

bool PrepareLightNativeSessionApi(const std::wstring& pid, const std::wstring& creation,
    const std::wstring& duration, const project::NativeBoundApiTarget& nativeTarget,
    project::NativeBoundApiRequest& out, std::wstring& reason)
{
    std::uint64_t sourcePid = 0; // 完整解析后检查DWORD边界。
    std::uint64_t sourceCreation = 0; // 真实创建FILETIME。
    std::uint64_t durationMs = 0; // 本次有限区间，不能截断或默认回填。
    if (!Decimal(pid, sourcePid) || sourcePid > MAXDWORD || !Decimal(creation, sourceCreation) ||
        !Decimal(duration, durationMs) || durationMs < 1000 || durationMs > 10000)
    {
        reason = L"请输入明确来源 PID、创建 FILETIME 和 1000–10000 毫秒采集时长。";
        return false;
    }
    project::NativeBoundApiRequest draft; // 仅成功时赋给out，草稿不携带上次授权。
    draft.sourcePid = static_cast<DWORD>(sourcePid);
    draft.sourceCreationFileTime = sourceCreation;
    draft.durationMs = static_cast<DWORD>(durationMs);
    draft.confirmed = true; // 临时执行同一纯值校验，实际输出撤销确认。
    if (project::ValidateNativeBoundApiRequest(draft, nativeTarget) != project::NativeBoundApiRejection::None)
    {
        reason = L"需有已附加的原调试会话，API 来源必须是另一个明确进程实例。";
        return false;
    }
    draft.confirmed = false;
    out = draft;
    reason.clear();
    return true;
}

bool CollectLightNativeSessionApi(HWND parent, HWND pid, HWND creation, HWND duration,
    const project::NativeBoundApiTarget& nativeTarget, project::NativeBoundApiRequest& out, std::wstring& reason)
{
    project::NativeBoundApiRequest draft; // 确认期间冻结来源与区间，后续编辑不改变本次请求。
    if (!PrepareLightNativeSessionApi(Input(pid), Input(creation), Input(duration), nativeTarget, draft, reason))
    {
        return false;
    }
    const auto text = L"向 PID " + std::to_wstring(draft.sourcePid) + L"、创建 FILETIME " +
        std::to_wstring(draft.sourceCreationFileTime) + L" 装载产品 Agent，采集 " +
        std::to_wstring(draft.durationMs) + L" 毫秒并写入原采样？\r\n停止只清退 API，不继续或关闭原调试会话。"; // 本次准确确认正文。
    if (::MessageBoxW(parent, text.c_str(), L"确认同采样 API 附加", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES ||
        !::IsWindow(parent))
    {
        reason = L"已取消同采样 API 采集。";
        return false;
    }
    draft.confirmed = true;
    out = draft;
    return true;
}

std::wstring FormatLightNativeSessionApi(const project::NativeBoundApiResult& result)
{
    const auto& run = result.receipt; // 只使用本请求的纯值回执，不读取文件或当前草稿。
    const auto& capture = run.capture; // 附加及清退结果与归档独立。
    std::wstring text = L"\r\n同采样 API 回执\r\n项目：" + Wide(result.projectId) + L"\r\n采样：" + Wide(result.sampleId);
    // 参数名称和值由同一函数追加，保留零值与各阶段错误，不从摘要猜状态。
    const auto number = [&](const wchar_t* name, std::uint64_t value)
    {
        text += L"\r\n" + std::wstring(name) + L"：" + std::to_wstring(value);
    };
    const auto boolean = [&](const wchar_t* name, bool value)
    {
        text += L"\r\n" + std::wstring(name) + (value ? L"：是" : L"：否");
    };
    const auto status = [&](const wchar_t* name, const project::ProjectResult& value)
    {
        text += L"\r\n" + std::wstring(name) + L"：" + Wide(project::ProjectErrorName(value.error)) +
            L" / " + Wide(value.detail) + L" / Win32 " + std::to_wstring(value.nativeError);
    };
    number(L"API 来源 PID", result.request.sourcePid);
    number(L"来源创建 FILETIME", result.request.sourceCreationFileTime);
    number(L"采集时长（毫秒）", result.request.durationMs);
    number(L"原调试目标 PID", result.nativeTarget.pid);
    number(L"原调试目标创建 FILETIME", result.nativeTarget.creationFileTime);
    boolean(L"请求已接纳", result.accepted);
    status(L"API 准入", result.admission);
    if (!result.accepted)
    {
        number(L"准入拒绝码", static_cast<unsigned>(result.rejection));
        return text; // 未调用采集器不输出默认成功的空归档结果。
    }

    status(L"采样绑定", run.sampleStatus);
    number(L"综合退出码", static_cast<unsigned>(result.ExitCode()));
    number(L"采集退出码", static_cast<unsigned>(result.CaptureExitCode()));
    boolean(L"Agent 路径可用", run.agentPathAvailable);
    boolean(L"已尝试装载 Agent", capture.agentLoadAttempted);
    boolean(L"Agent 模块已核验", capture.agentModuleVerified);
    boolean(L"附加实例已核验", capture.attachmentIdentityVerified);
    if (capture.startup)
    {
        // 仅沿原采集器快照展示最后阶段，失败清退不因晚到安装包补成Ready。
        const auto stage = ks::winapi_monitor::CaptureStartupStageName(capture.startup->stage); // 后端稳定ASCII阶段ID。
        text += L"\r\n最后确认的启动阶段：" + Wide(stage);
        number(L"启动阶段耗时（毫秒）", capture.startup->elapsedMs);
    }
    if (capture.readyCoverageRevision)
    {
        number(L"就绪覆盖修订", *capture.readyCoverageRevision);
    }
    boolean(L"采集已就绪", capture.started);
    boolean(L"完整有限区间", capture.completedInterval);
    boolean(L"已取消", capture.cancelled);
    number(L"收到包数", capture.received);
    number(L"无效包数", capture.invalidPackets);
    number(L"缓冲丢包数", capture.bufferDropped);
    for (const auto& error : capture.errors) // 原始宽字符错误完整保留。
    {
        text += L"\r\n采集错误：" + error;
    }
    boolean(L"API 清退完成", capture.cleanupComplete);
    boolean(L"已写停止标记", capture.stopWritten);
    const auto process = std::find_if(capture.processes.begin(), capture.processes.end(), [&](const auto& value)
    {
        return value.pid == result.request.sourcePid && value.creation == result.request.sourceCreationFileTime;
    }); // 只匹配真实来源强实例，不从native目标或首行回填。
    if (process != capture.processes.end())
    {
        boolean(L"管道已连接", process->connected);
        boolean(L"Hook 已安装", process->installed);
        boolean(L"Hook 已移除", process->removed);
        boolean(L"管道正常结束", process->cleanPipeEof);
        boolean(L"来源进程已退出", process->exited);
        number(L"管道错误", process->pipeError);
        if (process->connected)
        {
            number(L"来源会话 ID", process->session);
            number(L"Agent 报告丢包数", process->agentDropped);
        }
    }

    status(L"原包归档", run.archiveStatus);
    number(L"已接收普通包数", run.ordinaryPackets);
    number(L"已归档普通包数", run.archivedPackets);
    number(L"已提交段数", run.committedSegments);
    number(L"保留线索数", run.retainedClues);
    number(L"遗漏线索数", run.omittedClues);
    if (run.archive.written)
    {
        number(L"原包写入字节坐标", run.archive.written->byteOffset);
    }
    if (run.archive.flushed)
    {
        number(L"原包刷盘字节坐标", run.archive.flushed->byteOffset);
        number(L"原包末记录序号", run.archive.flushed->lastSequence);
    }
    text += L"\r\n规则集：" + Wide(run.rules.presetSet) + L"\r\n规则来源 SHA-256：" + Wide(run.rules.sourceSha256);
    boolean(L"规则失败", run.rules.failed);
    text += L"\r\n规则配置错误：" + Wide(run.rules.configError);
    number(L"规则命中行数", run.rules.matchedRows);
    number(L"线程创建候选数", run.transfers.candidateCount);
    number(L"APC 候选数", run.transfers.apcCandidateCount);
    number(L"上下文候选数", run.transfers.contextCandidateCount);
    number(L"已淘汰写入数", run.transfers.evictedWrites);
    text += L"\r\n同采样仅表示保存归属；API 来源与原调试目标分别保留。采集、清退、归档和规则结果独立，不证明执行、区域代次或因果。";
    return text;
}
} // namespace Ksword::Features::ActionAnalyze
