#pragma once

#include "Protocol.h"
#include "../Control/NativeDebugOwner.h"
#include "../Project/ProjectDocument.h"
#include "../Project/NativeBoundApiCapture.h"

namespace ks::cli::action_analyze {

struct NativeSessionApiReply {
    bool accepted = false; // 参数或会话拒绝用error；实际采集结果独立写入响应exitCode。
    JsonValue result;
};

// 共用参数解析只处理来源与区间；包络/session/expected由各原控制入口核对。
struct NativeSessionApiInput {
    std::optional<Ksword::ActionAnalyze::NativeBoundApiRequest> capture; // 成功时含明确确认的来源，不访问目标。
    bool startupProgress = false; // 调用端显式订阅在途进度。
    bool captureProgress = false; // 独立订阅已提交检查点与候选，不把启动通知当成运行水位。
    JsonValue error; // 解析失败的同源协议诊断。
};
NativeSessionApiInput PrepareNativeSessionApi(const Request& request, bool jsonl); // 输入原请求，返回值参数或错误。
JsonValue DescribeNativeSessionApi(const Ksword::ActionAnalyze::NativeBoundApiResult& result,
    const control::NativeControlResult& before, const control::NativeControlResult& after); // 复用完整原始采集/归档/清退投影。

// 在原CLI控制线程串行执行，借用原项目写租约；不创建项目、采样或调试owner。
NativeSessionApiReply CaptureNativeSessionApi(Ksword::ActionAnalyze::ProjectDocument& document,
    std::string_view sampleId, const Request& request, bool jsonl,
    const control::OwnerIdentity& identity, control::NativeDebugOwner& owner);

} // namespace ks::cli::action_analyze
