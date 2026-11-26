#pragma once

#include "NativeStopMemoryCandidates.h"
#include "../UI/StructuredFieldView.h"

namespace ks::action_analyze
{
    // 输入已核验原调用，输出三列中的本地化状态/实际范围短文；无任何进程/文件访问。
    QString PrivateCandidateState(const Ksword::ActionAnalyze::Detection::PrivateExecutionCandidate& row);
    QString PrivateCandidateRange(const Ksword::ActionAnalyze::Detection::PrivateExecutionCandidate& row);
    // 输入原只读回执和可选选中行，生成唯一规范字段文档，搜索/复制/导出使用同一文档。
    ks::ui::FieldDocument PrivateExecutionCandidatesFields(const NativeExecutionCandidatesResult& view, int row);
}
