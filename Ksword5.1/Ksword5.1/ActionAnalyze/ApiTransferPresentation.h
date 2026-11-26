#pragma once

#include <cstdint>

namespace Ksword::ActionAnalyze::Detection
{
    struct ApiTransferLink;
    struct ApiApcTransferLink;
    struct ApiContextTransferLink;
}

namespace ks::ui
{
    struct FieldDocument;
}

namespace ks::action_analyze
{
    struct SegmentApiClue;

    // 将已解码 API 参数加入当前详情文档；输入不含现场句柄，输出供显示、复制及导出共用。
    void AppendApiTransferFields(ks::ui::FieldDocument& document, const SegmentApiClue& clue);
    // 把 AAAP1 的十四字段及入队结果加入同一规范详情源；缺协议时不追加内容。
    void AppendApiApcFields(ks::ui::FieldDocument& document, const SegmentApiClue& clue);
    // 调用时传入规范文档和已核验行；追加 AACT1 十五字段及原返回，缺协议时不写入，无返回值。
    void AppendApiContextFields(ks::ui::FieldDocument& document, const SegmentApiClue& clue);
    // 调用时传入规范文档和已核验行；分列 AASM1 请求及返回范围，缺协议时不写入，无返回值。
    void AppendApiSectionMapFields(ks::ui::FieldDocument& document, const SegmentApiClue& clue);
    // 输入同一原包行和唯一规范文档；追加AAIM1请求、输出、状态和身份，缺协议时不写入。
    void AppendApiMemoryLifecycleFields(ks::ui::FieldDocument& document, const SegmentApiClue& clue);
    // 将活采的累计候选和最近原始坐标写入同一个规范文档；latest 可空。
    void AppendApiTransferProgress(ks::ui::FieldDocument& document, std::uint64_t candidates,
        std::uint64_t evictedWrites, const Ksword::ActionAnalyze::Detection::ApiTransferLink* latest);
    // 输入同一文档、累计数及可空最近 APC 回执；追加现有字段正文，无查询、计时器或返回值。
    void AppendApiApcProgress(ks::ui::FieldDocument& document, std::uint64_t candidates,
        const Ksword::ActionAnalyze::Detection::ApiApcTransferLink* latest);
    // 输入原文档、独立累计数和可空最近上下文候选；原位追加请求摘要，无查询和返回值。
    void AppendApiContextProgress(ks::ui::FieldDocument& document, std::uint64_t candidates,
        const Ksword::ActionAnalyze::Detection::ApiContextTransferLink* latest);
}
