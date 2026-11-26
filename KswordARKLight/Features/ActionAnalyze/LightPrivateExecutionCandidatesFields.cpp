#include "LightPrivateExecutionCandidatesFields.h"
#include <cwchar>

namespace Ksword::Features::ActionAnalyze {
namespace {
// 将服务返回的ASCII操作标识转换为显示文字，不解析调用摘要。
std::wstring Wide(std::string_view text) {
    return {text.begin(), text.end()};
}
// 输入已核验原调用，返回生命周期类型名称，Free始终带仅请求语义。
const wchar_t* Operation(const private_execution::PrivateMemoryCall& call) {
    if (!call.record.apiMemoryLifecycle) return L"AAIM1不可用";
    switch (call.record.apiMemoryLifecycle->operation) {
    case Ksword::Evidence::ApiMemoryOperation::Allocate: return L"Allocate";
    case Ksword::Evidence::ApiMemoryOperation::Protect: return L"Protect";
    case Ksword::Evidence::ApiMemoryOperation::Free: return L"Free（仅请求）";
    }
    return L"未知";
}
// 向同一规范正文追加原调用坐标、有效位及实际输出，不查询当前目标。
void AppendCall(std::wstring& text, const private_execution::PrivateMemoryCall& call) {
    text += L"\r\n原API：" + Wide(call.record.operation) + L" · " + Operation(call);
    text += L"\r\n原API坐标：" + PrivateCandidateCoordinate(call);
    text += L"\r\n项目/采样：" + Wide(call.evidence.projectId) + L" / " + Wide(call.evidence.sampleId);
    text += L"\r\n来源/代次：" + Wide(call.evidence.sourceId) + L" / " + Wide(call.evidence.sourceEpoch);
    text += L"\r\n来源序号：" + (call.evidence.sourceSequence ? std::to_wstring(*call.evidence.sourceSequence) : L"未知");
    text += L"\r\n来源API会话：" + (call.record.apiSourceSession ? std::to_wstring(*call.record.apiSourceSession) : L"未知");
    text += L"\r\n原字节位置：record " + std::to_wstring(call.record.recordOffset) + L" · block " +
        std::to_wstring(call.record.blockOrdinal) + L" · inline " + std::to_wstring(call.record.inlineOffset) +
        L" / " + std::to_wstring(call.record.inlineBytes) + L" B";
    text += L"\r\n原段摘要：" + Wide(call.sha256);
    if (!call.record.apiMemoryLifecycle) return;
    const auto& f = *call.record.apiMemoryLifecycle; // 严格AAIM1解码值，未知字段按有效位显示。
    using namespace Ksword::Evidence;
    text += L"\r\n目标PID/创建FILETIME：" + ((f.flags & ApiMemoryTargetIdentity)
        ? std::to_wstring(f.targetPid) + L" / " + std::to_wstring(f.targetCreationFileTime) : L"未知");
    text += (f.flags & ApiMemoryTargetStable) ? L" · 原调用前后身份稳定" : L" · 原调用身份稳定性未知";
    text += L"\r\n来源PID/创建FILETIME：" + (call.record.headerPid ? std::to_wstring(*call.record.headerPid) : L"未知") + L" / " +
        ((f.flags & ApiMemoryActorIdentity) ? std::to_wstring(f.actorCreationFileTime) : L"未知");
    text += L"\r\n请求起点/字节：" + ((f.flags & ApiMemoryRequestedBase) ? PrivateCandidateHex(f.requestedBase) : L"未知") + L" / " +
        ((f.flags & ApiMemoryRequestedBytes) ? std::to_wstring(f.requestedBytes) : L"未知");
    text += L"\r\n实际输出起点/字节：" + ((f.flags & ApiMemoryOutputBase) ? PrivateCandidateHex(f.outputBase) : L"未知") + L" / " +
        ((f.flags & ApiMemoryOutputBytes) ? std::to_wstring(f.outputBytes) : L"未知");
    text += L"\r\nNTSTATUS：" + (f.returnValid ? PrivateCandidateHex(static_cast<std::uint32_t>(f.status)) : L"未知");
    text += L"\r\n字段有效位：" + PrivateCandidateHex(f.flags) + L" · 源ABI " + std::to_wstring(f.pointerBits);
    text += L"\r\n原调用进入/返回QPC：" + std::to_wstring(f.enterQpc) + L" / " + std::to_wstring(f.returnQpc);
    if (f.operation == ApiMemoryOperation::Free) {
        text += L"\r\nFreeType：" + PrivateCandidateHex(f.freeType) + L" · 实际释放范围、释放完成及当前存活均未知";
    } else {
        text += L"\r\n新保护：" + PrivateCandidateHex(f.newProtection) + L" · AllocationType " + PrivateCandidateHex(f.allocationType);
        text += L"\r\n旧保护：" + ((f.flags & ApiMemoryOldProtection) ? PrivateCandidateHex(f.oldProtection) : L"未知");
    }
}
}

// 输入完整64位地址/标志，输出无截断十六进制文字。
std::wstring PrivateCandidateHex(std::uint64_t value) {
    wchar_t text[24]{}; // 足够容纳0x前缀、16位数字和终止字符。
    swprintf_s(text, L"0x%llX", static_cast<unsigned long long>(value));
    return text;
}

// 返回原sample中的raw段及记录序号，绝不以来源序号替代文件坐标。
std::wstring PrivateCandidateCoordinate(const private_execution::PrivateMemoryCall& call) {
    return call.evidence.raw ? L"raw/" + std::to_wstring(call.evidence.raw->segmentOrdinal) + L" #" +
        std::to_wstring(call.evidence.raw->sequence) : L"原坐标未知";
}

// 将已准备子范围及原API来源显示到AddRange草稿/回执，保留历史语义边界。
std::wstring FormatLightPrivateExecutionOrigin(const private_execution::PrivateExecutionRangeDraft& draft) {
    return L"AAIM1候选来源：" + PrivateCandidateCoordinate(draft.origin) + L" · " + Wide(draft.origin.record.operation) +
        L"\r\n来源项目/采样：" + Wide(draft.projectId) + L" / " + Wide(draft.sampleId) +
        L"\r\n来源目标PID/创建FILETIME：" + std::to_wstring(draft.targetPid) + L" / " + std::to_wstring(draft.targetCreationFileTime) +
        L"\r\n显式子范围：" + PrivateCandidateHex(draft.address) + L" / " + std::to_wstring(draft.bytes) +
        L" B；allocation代次、当前存活及实际释放未知，纳入仍须原NX完整Held回读。";
}

// 生成列表选中行唯一详情文档；复制、搜索及导出均使用本结果。
std::wstring FormatLightPrivateExecutionCandidate(const private_execution::PrivateExecutionCandidate& candidate) {
    std::wstring text = L"范围候选的原始依据（历史只读，不授予控制权）"; // 完整详情正文。
    text += candidate.rangeCandidate ? L"\r\n实际范围候选：是" : L"\r\n实际范围候选：否";
    text += L" · " + Wide(candidate.reason);
    text += candidate.executableProtection ? L"\r\n原新保护含执行位：是" : L"\r\n原新保护含执行位：否";
    text += candidate.strongTarget ? L" · 强目标身份：是" : L" · 强目标身份：未知";
    AppendCall(text, candidate.origin);
    text += L"\r\n后续相关Free请求总数：" + std::to_wstring(candidate.freeRequestCount) + L" · 保留原请求 " + std::to_wstring(candidate.freeRequests.size());
    for (const auto& link : candidate.freeRequests) {
        text += L"\r\n\r\n后续Free仅请求：";
        text += link.requestedRangeOverlaps ? L"请求范围相交" : L"请求范围相交未知/否";
        text += link.requestedBaseInside ? L" · 请求base位于候选内" : L" · 请求base不在候选内";
        AppendCall(text, link.call);
    }
    text += L"\r\n\r\n实际释放范围、allocation代次和当前存活未知；分配成功或可执行保护不是执行证据，也不证明MEM_PRIVATE。";
    return text;
}

// 输入同一候选及A/B视角，输出互补精简单元格；详情仍保留全部字段。
std::vector<std::wstring> LightPrivateExecutionCandidateCells(const private_execution::PrivateExecutionCandidate& candidate, bool provenance) {
    const auto& call = candidate.origin; // 每行唯一原调用，不跨行合并allocation。
    if (provenance) return {PrivateCandidateCoordinate(call), Wide(call.evidence.sourceId) + L" / " + Wide(call.evidence.sourceEpoch),
        call.evidence.sourceSequence ? std::to_wstring(*call.evidence.sourceSequence) : L"未知", std::to_wstring(candidate.freeRequestCount)};
    const auto& f = call.record.apiMemoryLifecycle;
    const bool free = f && f->operation == Ksword::Evidence::ApiMemoryOperation::Free;
    return {Operation(call), f && (f->flags & Ksword::Evidence::ApiMemoryTargetIdentity)
        ? std::to_wstring(f->targetPid) + L" / " + std::to_wstring(f->targetCreationFileTime) : L"强目标未知",
        f && !free && (f->flags & Ksword::Evidence::ApiMemoryOutputBase) ? PrivateCandidateHex(f->outputBase) : L"实际范围未知",
        f && !free && (f->flags & Ksword::Evidence::ApiMemoryOutputBytes) ? std::to_wstring(f->outputBytes) : L"未知",
        free ? L"Free仅请求" : f ? PrivateCandidateHex(f->newProtection) + (candidate.executableProtection ? L" · X" : L" · 无X") : L"未知"};
}
} // namespace Ksword::Features::ActionAnalyze
