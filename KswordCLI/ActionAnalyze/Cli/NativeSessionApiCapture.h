#pragma once

#include "Protocol.h"
#include "../Control/NativeDebugOwner.h"
#include "../Project/ProjectDocument.h"

namespace ks::cli::action_analyze {

struct NativeSessionApiReply {
    bool accepted = false; // 参数或会话拒绝用error；实际采集结果独立写入响应exitCode。
    JsonValue result;
};

// 在原CLI控制线程串行执行，借用原项目写租约；不创建项目、采样或调试owner。
NativeSessionApiReply CaptureNativeSessionApi(Ksword::ActionAnalyze::ProjectDocument& document,
    std::string_view sampleId, const Request& request, bool jsonl,
    const control::OwnerIdentity& identity, control::NativeDebugOwner& owner);

} // namespace ks::cli::action_analyze
