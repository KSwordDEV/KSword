#pragma once

#include <string>

namespace Ksword::ActionAnalyze
{
    struct CooperativeApiTransferReceipt;
}

namespace Ksword::Features::ActionAnalyze
{
    struct EvidenceRecord;

    // 将当前归档行的版本化 API 字段写为详情文本；没有结构字段时返回空文本。
    std::wstring ApiTransferDetails(const EvidenceRecord& record);
    // 将 AAAP1 原行格式化为同一原生详情文本；未知身份不以零代替。
    std::wstring ApiApcDetails(const EvidenceRecord& record);
    // 输入已核验原行，返回 AACT1 请求和原调用结果文本；缺协议时为空，不查询现场。
    std::wstring ApiContextDetails(const EvidenceRecord& record);
    // 输入已核验原行，返回 AASM1 请求和实际返回范围文本；缺协议时为空，不建立别名身份。
    std::wstring ApiSectionMapDetails(const EvidenceRecord& record);
    // 从活采已发布回执生成候选摘要，保留累计数、淘汰数及最近双方的 raw 坐标。
    std::wstring ApiTransferProgress(const Ksword::ActionAnalyze::CooperativeApiTransferReceipt& receipt);
}
