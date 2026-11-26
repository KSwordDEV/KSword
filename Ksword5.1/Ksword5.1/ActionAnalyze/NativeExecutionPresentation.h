#pragma once

#include "../UI/StructuredFieldView.h"
#include "../../../shared/evidence/ApiNativeExecutionProjection.h"

namespace ks::action_analyze {
struct SegmentRow; // 既有后台行类型，展示声明不拥有或构造原行。
// 输入共享只读文档，输出同一规范字段树；不执行文件读取或重新匹配。
ks::ui::FieldDocument NativeExecutionDocument(const Ksword::Evidence::JsonValue& source);
// 输入后台原生读回执，输出独立状态摘要，完整空结果与失败严格区分。
QString NativeExecutionStatus(const Ksword::Evidence::ApiNativeExecutionProjection<SegmentRow>& projection);
}
