#include "../Framework.h"
#include "ApiHandoffPresentation.h"
#include "../UI/StructuredFieldView.h"
#include "../Internationalization/LanguageManager.h"
#include "../../../shared/evidence/ApiHandoffReceiptView.h"
#include <string_view>
#include <vector>

namespace ks::action_analyze
{
    // 将后端冻结回执映射成主题字段树；无回执与格式错误分开呈现，返回值拥有完整来源正文。
    ks::ui::FieldDocument ApiHandoffDocument(const QString& receipt)
    {
        ks::ui::FieldDocument document; // 接管页唯一规范数据，复制、搜索和导出不另建摘要副本。
        document.title = QStringLiteral("自动接管");
        if (receipt.isEmpty())
        {
            document.section(QStringLiteral("自动接管概览"))
                .field(QStringLiteral("接管回执状态"), QStringLiteral("尚无自动接管回执"), true);
            return document;
        }

        const auto utf8 = receipt.toUtf8(); // 保留原始整数字符串，禁止经QJson浮点数转换身份。
        const auto parsed = Ksword::Evidence::ParseJson(std::string_view(utf8.constData(), utf8.size()));
        const auto groups = parsed.ok() ? Ksword::Evidence::BuildHandoffReceiptView(parsed.value)
            : std::vector<Ksword::Evidence::HandoffReceiptSection>{}; // 解析失败不伪造空结果或成功。
        if (groups.empty())
        {
            document.section(QStringLiteral("自动接管概览"))
                .field(QStringLiteral("接管回执状态"), QStringLiteral("接管回执格式不可用"), true);
        }

        // 每个来源或准入形成可折叠节点；PID只作摘要，完整创建代次仍保留在节点字段中。
        for (const auto& group : groups)
        {
            ks::ui::FieldNode section; // 文档拥有的分组，不借用原JSON或旧树项指针。
            section.kind = ks::ui::FieldNode::Kind::Section;
            section.name = QString::fromWCharArray(group.name);
            section.status = group.failed ? ks::ui::FieldNode::Status::Error : ks::ui::FieldNode::Status::Neutral;
            section.initiallyExpanded = document.nodes.isEmpty() || group.failed;
            // 分组值只作导航摘要，字段仍保留完整的PID与创建代次，不把列表位置当身份。
            for (const auto& field : group.fields)
            {
                const auto label = QString::fromWCharArray(field.name); // 判别共享投影明确指定的身份字段。
                if (label == QStringLiteral("API 目标 PID") || label == QStringLiteral("来源 PID"))
                {
                    section.value = QStringLiteral("PID %1").arg(QString::fromUtf8(field.value.data(), field.value.size()));
                    break;
                }
            }
            for (const auto& field : group.fields)
            {
                ks::ui::FieldNode node; // 保留原值与本地化标记，缺失值不会变成否或零。
                node.name = QString::fromWCharArray(field.name);
                node.value = QString::fromUtf8(field.value.data(), field.value.size());
                node.translateValue = field.translate;
                section.children.push_back(std::move(node));
            }
            document.nodes.push_back(std::move(section));
        }

        // 完整JSON折叠保留，独有字段和未来扩展仍能被同一文档搜索、复制与导出。
        document.section(QStringLiteral("自动接管回执"))
            .field(QStringLiteral("原始回执 JSON"), receipt);
        document.nodes.last().initiallyExpanded = false;
        return document;
    }
}
