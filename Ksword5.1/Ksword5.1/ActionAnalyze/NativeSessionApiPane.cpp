#include "../Framework.h"
#include "NativeSessionApiPane.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ThemedMessageBox.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QSpinBox>
#include <QVBoxLayout>
#include <charconv>
#include <limits>

namespace ks::action_analyze {
namespace project = Ksword::ActionAnalyze;
using ks::i18n::sourceText;
namespace {
// input为原输入框，value输出完整正十进制；错误不补默认PID或创建时间。
bool Decimal(const QLineEdit* input, std::uint64_t& value)
{
    const auto text = input->text().trimmed().toLatin1(); // 本次冻结的ASCII身份文本。
    if (text.isEmpty() || text.front() == '0')
    {
        return false;
    }
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value); // 全字符解析结果。
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && value != 0;
}
} // namespace

NativeSessionApiPane::NativeSessionApiPane(QWidget* parent) : QWidget(parent)
{
    auto* root = new QVBoxLayout(this); // 参数区内不增加第二层页根留白。
    root->setContentsMargins(0, 0, 0, 0);
    auto* section = new QGroupBox(this); // 同一ParameterWorkspace中的共享自然高度分区。
    auto* form = new QFormLayout(section); // 窄栏折行由共享表单拥有。
    ks::ui::StyleSecondaryForm(form, 100);
    ks::i18n::LanguageManager::instance().bindText(section, {}, QStringLiteral("同采样 API 来源"));
    m_pid = new QLineEdit(section);
    m_creation = new QLineEdit(section);
    m_duration = new QSpinBox(section);
    m_pid->setObjectName(QStringLiteral("action_analyze_native_api_source_pid"));
    m_creation->setObjectName(QStringLiteral("action_analyze_native_api_source_creation"));
    m_duration->setObjectName(QStringLiteral("action_analyze_native_api_duration"));
    m_pid->setMaxLength(10);
    m_creation->setMaxLength(20);
    // 有限区间只是草稿，不提供持续模式或第二个采集停止入口。
    m_duration->setRange(1000, 10000);
    m_duration->setValue(3000);

    // 标签与输入保持同一buddy，主题和翻译不替换草稿控件。
    const auto field = [&](QWidget* input, const QString& title)
    {
        auto* label = new QLabel(section); // 自然高度字段标题。
        label->setBuddy(input);
        ks::i18n::LanguageManager::instance().bindText(label, {}, title);
        form->addRow(label, input);
    };
    field(m_pid, QStringLiteral("API 来源 PID"));
    field(m_creation, QStringLiteral("创建 FILETIME"));
    field(m_duration, QStringLiteral("同采样 API 时长（毫秒）"));
    m_error = new QLabel(section);
    m_error->setWordWrap(true);
    ks::ui::ApplyStatusRole(m_error, ks::ui::StatusRole::Error);
    form->addRow(m_error);

    auto* hint = new QLabel(section); // 说明仅承载业务约束，不另建日志或结果区。
    hint->setWordWrap(true);
    ks::i18n::LanguageManager::instance().bindText(hint, {}, QStringLiteral("选择原调试目标以外的明确来源实例。确认后采集 1–10 秒，写入本会话原项目与采样；API 停止不会继续或关闭原调试会话。已有 API 归档时拒绝再次写入。"));
    form->addRow(hint);
    ks::ui::StyleParameterSection(section);
    root->addWidget(section);
}

bool NativeSessionApiPane::Prepare(const project::NativeBoundApiTarget& nativeTarget,
    project::NativeBoundApiRequest& out)
{
    std::uint64_t pid = 0; // 无损解析后再检查DWORD上限。
    std::uint64_t creation = 0; // 真实FILETIME，不接受日期或候选摘要。
    project::NativeBoundApiRequest draft; // 本次纯值草稿，只有成功时赋给out。
    if (!Decimal(m_pid, pid) || pid > (std::numeric_limits<DWORD>::max)() || !Decimal(m_creation, creation))
    {
        m_error->setText(sourceText(QStringLiteral("请输入授权目标的十进制 PID 和创建 FILETIME。")));
        return false;
    }
    draft.sourcePid = static_cast<DWORD>(pid);
    draft.sourceCreationFileTime = creation;
    draft.durationMs = static_cast<DWORD>(m_duration->value());
    draft.confirmed = true; // 仅用于纯值校验；成功输出前撤销，实际确认由Confirm完成。
    if (project::ValidateNativeBoundApiRequest(draft, nativeTarget) != project::NativeBoundApiRejection::None)
    {
        m_error->setText(sourceText(QStringLiteral("需有原项目、采样和已附加的调试会话；API 来源必须是另一个明确实例。")));
        return false;
    }
    draft.confirmed = false;
    out = draft;
    m_error->clear();
    return true;
}

bool NativeSessionApiPane::Confirm(project::NativeBoundApiRequest& request)
{
    request.confirmed = false; // 拒绝或窗口销毁不能沿用旧授权。
    const QPointer<NativeSessionApiPane> alive(this); // 模态消息期间防止父页面销毁。
    const auto answer = QMessageBox::question(this, sourceText(QStringLiteral("确认显式 API 附加")),
        sourceText(QStringLiteral("向 PID %1、创建 FILETIME %2 装载产品 Agent，采集 %3 毫秒并写入原采样？\n停止仅清退 API Hook 和管道，保留原调试停点与会话。"))
            .arg(request.sourcePid).arg(request.sourceCreationFileTime).arg(request.durationMs),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No); // 全局ThemedMessageBox主题拥有消息框外观。
    if (!alive || answer != QMessageBox::Yes)
    {
        return false;
    }
    request.confirmed = true;
    return true;
}

} // namespace ks::action_analyze
