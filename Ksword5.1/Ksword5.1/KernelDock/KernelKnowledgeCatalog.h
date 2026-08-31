#pragma once

#include <QString>

#include <vector>

namespace ks::kernel_knowledge
{
    // Coverage 作用：描述专题的实现链状态；历史枚举值继续保留，便于旧语言包
    // 和未来增量专题兼容。当前 71 项由校验器统一要求为 Available。
    enum class Coverage : int
    {
        Available = 0,
        AvailableNeedsExplanation,
        Partial,
        Planned
    };

    // CategoryDefinition 作用：描述知识树一级分类与其微软官方参考入口。
    // id 只用于构造语言包键；referenceUrl 是只读外部文档链接。
    struct CategoryDefinition
    {
        const char* id = nullptr;
        const char* referenceUrl = nullptr;
    };

    // TopicDefinition 作用：定义一个专题的稳定身份、能力覆盖度与可选站内观察入口。
    // routeId 为空表示当前只能按文章中的路径手工进入其它 Dock，不伪造跨页跳转。
    struct TopicDefinition
    {
        const char* id = nullptr;
        const char* categoryId = nullptr;
        Coverage coverage = Coverage::Planned;
        const char* routeId = nullptr;
    };

    // categories：返回按《第二规划》章节顺序排列的一级分类。
    // 返回引用在进程生命周期内稳定，调用者不得修改。
    const std::vector<CategoryDefinition>& categories();

    // topics：返回完整 71 专题清单。
    // 返回引用在进程生命周期内稳定，顺序同时作为上一篇/下一篇导航顺序。
    const std::vector<TopicDefinition>& topics();

    // categoryForTopic：按专题 categoryId 查找一级分类。
    // 输入 topic 为目录中的专题；返回匹配分类，目录损坏时返回 nullptr。
    const CategoryDefinition* categoryForTopic(const TopicDefinition& topic);

    // categoryText：读取分类的本地化标题。
    // 输入 category 与字段名；返回语言包文本，缺键时返回稳定键便于诊断。
    QString categoryText(const CategoryDefinition& category, const char* field = "title");

    // topicText：读取专题的本地化标题、摘要、关键词或正文。
    // 输入 topic 与字段名；返回语言包文本，缺键时返回稳定键便于诊断。
    QString topicText(const TopicDefinition& topic, const char* field);

    // coverageText：把底层能力覆盖枚举转换成本地化标签。
    // 输入 coverage；返回适合树列与状态徽标展示的短文本。
    QString coverageText(Coverage coverage);
}
