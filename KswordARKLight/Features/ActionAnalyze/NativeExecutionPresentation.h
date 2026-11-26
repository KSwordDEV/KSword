#pragma once

#include "../../../shared/evidence/EvidenceJson.h"
#include <string>

namespace Ksword::Features::ActionAnalyze {
// 输入两端共用的规范来源文档，输出 Light 既有详情文本；不读取文件或解释为活控制状态。
std::wstring NativeExecutionDetails(const Evidence::JsonValue& source);
}
