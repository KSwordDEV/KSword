#include "NativeExecutionPresentation.h"
#include "../../../shared/usermode/backend/process/ProcessControls.h"

namespace Ksword::Features::ActionAnalyze {

// 所有真实身份、地址、阶段和 raw 坐标均保留在原规范源中，文本只加阅读边界。
std::wstring NativeExecutionDetails(const Evidence::JsonValue& source)
{
    const auto canonical = Evidence::WriteJson(source, 2); // 无损 JSON，Qt 字段视图消费同一文档。
    std::string kind; // 原生历史和API候选共享原文，不共享推断语义。
    const auto* type = source.find("kind"); // 后台规范来源类型。
    const bool history = type && type->tryGetString(kind) && kind == "native-execution-history";
    return std::wstring(history ? L"原生执行历史\r\n历史观察保留原始停点、绑定和寄存器；不授予实时控制权。\r\n\r\n"
        : L"API 与原生执行一致性候选\r\n候选不证明注入、因果、区域版本或跨来源时序；进入尝试与指令完成按原记录分别呈现。\r\n\r\n") +
        ks::r3::process::Utf8ToWide(canonical);
}

}
