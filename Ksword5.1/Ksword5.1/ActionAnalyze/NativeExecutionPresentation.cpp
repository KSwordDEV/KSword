#include "NativeExecutionPresentation.h"
#include "OfflineSegmentReader.h"
#include "../Internationalization/LanguageManager.h"

namespace ks::action_analyze {
namespace {
// 输入共享 JSON 字段，递归生成同值字段；协议字段名称保留原名以便跨端核对。
ks::ui::FieldNode Node(const QString& name, const Ksword::Evidence::JsonValue& value)
{
    ks::ui::FieldNode node; // 与规范源一一对应，复制和导出不维护第二份数据。
    node.name = name;
    node.translateName = false;
    if (const auto* object = value.asObject())
    {
        node.kind = ks::ui::FieldNode::Kind::Section;
        for (const auto& field : *object) // 当前对象的原字段顺序。
        {
            node.children.append(Node(QString::fromStdString(field.first), field.second));
        }
    }
    else
    {
        std::string text; // 字符串不额外套 JSON 引号，数值/空值保持无损协议表示。
        node.value = QString::fromStdString(value.tryGetString(text) ? text : Ksword::Evidence::WriteJson(value));
    }
    return node;
}
}

// 同一文档负责字段展示、搜索、复制与导出；完整 native 原文包含实际 PID 和线程代次。
ks::ui::FieldDocument NativeExecutionDocument(const Ksword::Evidence::JsonValue& source)
{
    ks::ui::FieldDocument document; // 共享详情框架使用的唯一规范文档。
    document.title = QStringLiteral("API 与原生执行一致性候选");
    document.note(QStringLiteral("候选不证明注入、因果、区域版本或跨来源时序；进入尝试与指令完成按原记录分别呈现。"));
    document.nodes.append(Node(QStringLiteral("api-native"), source));
    return document;
}

// 本摘要只描述实际读取范围，不把候选窗口为空解释为没有执行。
QString NativeExecutionStatus(const Ksword::Evidence::ApiNativeExecutionProjection<SegmentRow>& projection)
{
    using Ksword::Evidence::NativeHistoryState;
    using ks::i18n::sourceText;
    if (projection.state == NativeHistoryState::NotRequested)
    {
        return {};
    }
    if (projection.state == NativeHistoryState::Failed)
    {
        return sourceText(QStringLiteral("原生历史读取失败：段 %1；%2；Win32 %3。API 来源树仍可使用。"))
            .arg(projection.failedOrdinal).arg(QString::fromLatin1(projection.problem.detail)).arg(projection.problem.nativeError);
    }
    if (projection.state == NativeHistoryState::Canceled)
    {
        return sourceText(QStringLiteral("原生历史读取已取消。"));
    }
    auto text = sourceText(QStringLiteral("原生历史：已核验 %1 条，执行候选保留 %2 / 匹配 %3；映射输入淘汰 %4。"))
        .arg(projection.verifiedNativeCount).arg(projection.candidates.size()).arg(projection.candidateCount).arg(projection.evictedMaps);
    if (projection.state == NativeHistoryState::Limited)
    {
        text += sourceText(QStringLiteral("已达到原生历史 4096 段读取上限。"));
    }
    return text;
}
}
