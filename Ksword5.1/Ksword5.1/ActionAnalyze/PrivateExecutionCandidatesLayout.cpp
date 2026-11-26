#include "../Framework.h"
#include "PrivateExecutionCandidatesPane.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/FlowLayout.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/ResultTableHost.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/TablePresentation.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QStandardItemModel>
#include <QTableView>
#include <QVBoxLayout>

namespace ks::action_analyze
{
    // 输入父控件、稳定ID及说明，返回共享主题文字动作；复杂范围动作保留明确文字。
    static QPushButton* CandidateAction(QWidget* parent, const char* id, const QString& title, const QString& hint)
    {
        auto* button = new QPushButton(parent); // 生命周期由参数分区拥有，不创建独立窗口。
        button->setObjectName(QString::fromLatin1(id));
        auto& language = ks::i18n::LanguageManager::instance(); // 标题和tooltip共同热更新。
        language.bindText(button, {}, title);
        language.bindToolTip(button, {}, hint);
        return button;
    }

    // 输入父分区，返回自然高度、纯文本、可换行的状态标签；长ID不撑宽参数栏。
    static QLabel* CandidateLabel(QWidget* parent)
    {
        auto* label = new QLabel(parent); // 仅展示纯值，不把归档字符串解释成HTML。
        label->setTextFormat(Qt::PlainText);
        label->setWordWrap(true);
        label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        return label;
    }

    // 与原NativeSessionApiPane/PrivateExecutionRangePane相同：参数正文内只建共享分区。
    void PrivateExecutionCandidatesPane::BuildLayout()
    {
        auto& language = ks::i18n::LanguageManager::instance(); // 固定文案使用统一双语绑定。
        auto* root = new QVBoxLayout(this); // 页根四边留白由原ParameterWorkspace唯一负责。
        root->setContentsMargins(0, 0, 0, 0);
        root->setSpacing(8);
        setObjectName(QStringLiteral("action_analyze_private_candidates"));
        auto* section = new QGroupBox(this); // 参数→查询结果→选中范围按流程自然排列。
        language.bindText(section, {}, QStringLiteral("私有执行范围候选"));
        auto* body = new QVBoxLayout(section); // 分区外观/内边距由StyleParameterSection管理。
        auto* form = new QFormLayout;
        ks::ui::StyleSecondaryForm(form, 100);
        m_through = new QSpinBox(section);
        m_through->setObjectName(QStringLiteral("private_candidates_through"));
        m_through->setRange(1, 128);
        m_through->setValue(1);
        m_through->setMaximumWidth(180);
        auto* label = new QLabel(section); // 截止段是显式扫描范围，不表示当前最新完整尾部。
        label->setBuddy(m_through);
        language.bindText(label, {}, QStringLiteral("候选截止段（1–128）"));
        form->addRow(label, m_through);
        body->addLayout(form);

        auto* queries = new QWidget(section); // 查询动作可换行，窄栏不裁切文字。
        auto* queryFlow = new ks::ui::FlowLayout(queries, 0, 8, 8);
        m_read = CandidateAction(queries, "private_candidates_read", {},
            QStringLiteral("按当前截止段重新读取首个候选页；读取失败时保留旧结果。"));
        m_read->setAccessibleName(ks::i18n::sourceText(QStringLiteral("读取候选")));
        KswordTheme::ApplyStandardIconButtonMetrics(m_read);
        ks::ui::SetThemeButtonIcon(m_read, QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
        m_next = CandidateAction(queries, "private_candidates_next", QStringLiteral("下一页候选"),
            QStringLiteral("使用已显示结果的原截止段、游标及完整快照读取下一页，每页最多 8 行。"));
        queryFlow->addWidget(m_read);
        queryFlow->addWidget(m_next);
        ks::ui::NormalizeToolbarLayout(queryFlow);
        body->addWidget(queries);
        m_status = CandidateLabel(section);
        m_source = CandidateLabel(section);
        body->addWidget(m_status);
        body->addWidget(m_source);

        // 三列只呈现原调用/坐标、实际范围和候选状态；强实例及原包字段放入折叠详情。
        m_table = new ks::ui::TableActionTableView(section);
        m_table->setObjectName(QStringLiteral("private_candidates_rows"));
        m_model = new QStandardItemModel(0, 3, m_table);
        m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_table->setSelectionMode(QAbstractItemView::SingleSelection);
        m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_table->setWordWrap(false);
        m_table->verticalHeader()->hide();
        ks::ui::ResultTableCapabilities capabilities; // 历史只读候选无需快照/暂停等重复操作条。
        capabilities.actionBar = ks::ui::TableActionBarMode::None;
        capabilities.headerClickSorting = false;
        ks::ui::ResultTableHost::ensure(m_table)->bindModel(m_model,
            {{0, QStringLiteral("call")}, {1, QStringLiteral("actual")}, {2, QStringLiteral("state")}}, capabilities);
        ks::ui::ApplyTablePresentation(m_table);
        m_table->setColumnWidth(0, 180);
        m_table->setColumnWidth(1, 205);
        m_table->setColumnWidth(2, 205);
        body->addWidget(m_table);

        auto* rangeForm = new QFormLayout; // 需要同时看到候选与明确子范围，不因选行覆盖旧草稿。
        ks::ui::StyleSecondaryForm(rangeForm, 100);
        m_address = new QLineEdit(section);
        m_address->setObjectName(QStringLiteral("private_candidates_address"));
        m_address->setMaxLength(20);
        language.bindPlaceholder(m_address, {}, QStringLiteral("显式填写地址（十进制或 0x）"));
        auto* addressLabel = new QLabel(section);
        language.bindText(addressLabel, {}, QStringLiteral("候选子范围起点"));
        addressLabel->setBuddy(m_address);
        rangeForm->addRow(addressLabel, m_address);
        m_pages = new QSpinBox(section);
        m_pages->setObjectName(QStringLiteral("private_candidates_pages"));
        m_pages->setRange(1, 64);
        m_pages->setMaximumWidth(180);
        auto* pagesLabel = new QLabel(section); // 长度明确以4KiB整页表达。
        language.bindText(pagesLabel, {}, QStringLiteral("页数（4KiB，1–64）"));
        pagesLabel->setBuddy(m_pages);
        rangeForm->addRow(pagesLabel, m_pages);
        body->addLayout(rangeForm);
        auto* drafts = new QWidget(section);
        auto* draftFlow = new ks::ui::FlowLayout(drafts, 0, 8, 8);
        m_load = CandidateAction(drafts, "private_candidates_load", QStringLiteral("填入候选整段"),
            QStringLiteral("仅将符合整页和 64 页上限的实际整段填入草稿；不裁剪、不扩大范围。"));
        m_prepare = CandidateAction(drafts, "private_candidates_prepare", QStringLiteral("准备选中范围草稿"),
            QStringLiteral("核对本轮项目、采样和目标强实例后交回原范围草稿区；仍需原追加按钮显式提交。"));
        draftFlow->addWidget(m_load);
        draftFlow->addWidget(m_prepare);
        ks::ui::NormalizeToolbarLayout(draftFlow);
        body->addWidget(drafts);
        m_draftSource = CandidateLabel(section);
        m_eligibility = CandidateLabel(section);
        body->addWidget(m_draftSource);
        body->addWidget(m_eligibility);
        ks::ui::StyleParameterSection(section);
        root->addWidget(section);

        auto* details = new QGroupBox(this); // 完整原包字段默认折叠，不在参数区展开大型详情。
        language.bindText(details, {}, QStringLiteral("私有执行候选字段"));
        auto* detailBody = new QVBoxLayout(details);
        m_fields = new ks::ui::StructuredFieldView(details);
        m_fields->setSearchTargetPrefix(QStringLiteral("private_execution_candidates"));
        m_fields->setValueModelProjection();
        m_fields->setHiddenProjectionDeferred();
        detailBody->addWidget(m_fields);
        ks::ui::StyleParameterSection(details);
        root->addWidget(ks::ui::FoldParameterSection(details, false));
        ks::ui::StyleParameterFields(section);
    }
}
