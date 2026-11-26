#include "../Framework.h"
#include "ExecutionGroupSiteEditor.h"
#include "PrivateAddressWatchFields.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QComboBox>
#include <QDir>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <limits>

namespace ks::action_analyze
{
    // 输入父参数区，创建身份、模式、模块位置与条件；无目标控制副作用。
    ExecutionGroupSiteEditor::ExecutionGroupSiteEditor(QWidget* parent) : QWidget(parent)
    {
        auto& language = ks::i18n::LanguageManager::instance(); // 动态双语由共享绑定管理。
        auto* root = new QVBoxLayout(this); // 外层参数分区独占四边留白。
        root->setContentsMargins(0, 0, 0, 0);
        m_identity = new PrivateAddressWatchFields(this);
        root->addWidget(m_identity);
        auto* body = new QWidget(this); // 表单保持自然高度，滚动由ParameterWorkspace负责。
        m_form = new QFormLayout(body);
        ks::ui::StyleSecondaryForm(m_form, 100);
        m_form->setContentsMargins(0, 0, 0, 0);
        const auto addRow = [&](const QString& title, QWidget* field)
        {
            auto* label = new QLabel(body); // 标签与真实输入建立键盘buddy关系。
            label->setBuddy(field);
            language.bindText(label, {}, title);
            m_form->addRow(label, field);
        };

        m_kind = new QComboBox(body); // 模式索引稳定，翻译不会改变解析方式。
        for (const auto& title : {QStringLiteral("模块导出执行"), QStringLiteral("模块 RVA 执行"),
            QStringLiteral("私有地址执行"), QStringLiteral("私有页范围执行")})
        {
            m_kind->addItem({});
            language.bindComboBoxItem(m_kind, m_kind->count() - 1, {}, title);
        }
        addRow(QStringLiteral("执行站点类型"), m_kind);
        m_moduleRow = new QWidget(body);
        auto* moduleLayout = new QHBoxLayout(m_moduleRow); // 原生文件选择器选单个模块，输入也可直接填写。
        moduleLayout->setContentsMargins(0, 0, 0, 0);
        moduleLayout->setSpacing(8);
        m_module = new QLineEdit(m_moduleRow);
        m_module->setMaxLength(32767);
        auto* browse = new QPushButton(QStringLiteral("…"), m_moduleRow); // 标准紧凑选择器，不创建另一套路径模型。
        language.bindToolTip(browse, {}, QStringLiteral("选择目标进程已加载的模块绝对路径。"));
        KswordTheme::ApplyStandardIconButtonMetrics(browse);
        moduleLayout->addWidget(m_module, 1);
        moduleLayout->addWidget(browse);
        ks::ui::NormalizeToolbarLayout(moduleLayout);
        addRow(QStringLiteral("模块绝对路径"), m_moduleRow);
        m_location = new QLineEdit(body); // 导出字节名与RVA由模式明确区分，不接受模糊符号。
        m_location->setMaxLength(4096);
        addRow(QStringLiteral("导出名或 RVA"), m_location);
        language.bindToolTip(m_location, {}, QStringLiteral("导出名区分大小写；RVA 支持十进制或 0x 十六进制，须由用户确认指令边界。"));
        m_condition = new QLineEdit(body);
        m_condition->setMaxLength(8192);
        addRow(QStringLiteral("命中条件"), m_condition);
        language.bindToolTip(m_condition, {}, QStringLiteral("条件仅作用于本成员，加入草稿时编译；留空沿用原生执行停点。"));
        root->addWidget(body);
        connect(browse, &QPushButton::clicked, this, [this]
        {
            const auto path = QFileDialog::getOpenFileName(this, ks::i18n::sourceText(QStringLiteral("选择模块")), m_module->text());
            if (!path.isEmpty())
            {
                m_module->setText(QDir::toNativeSeparators(path)); // 取消选择保留原草稿。
            }
        });
        connect(m_kind, &QComboBox::currentIndexChanged, this, [this] { UpdateMode(); });
        UpdateMode();
    }

    // 输入当前机制索引，只调整对应表单行；隐藏行原值留作下次编辑。
    void ExecutionGroupSiteEditor::UpdateMode()
    {
        const bool image = m_kind->currentIndex() < 2; // 模块两种定位均不读取私有地址。
        m_identity->SetPageExecutionMode(m_kind->currentIndex() == 3, image);
        m_form->setRowVisible(m_moduleRow, image);
        m_form->setRowVisible(m_location, image);
    }

    // 输入表单，输出冻结站点或明确错误；条件在任何附加前编译成功。
    bool ExecutionGroupSiteEditor::Prepare(execution_group_native::ExecutionGroupSite& site, QString& error) const
    {
        using ks::i18n::sourceText;
        execution_group_native::ExecutionGroupSite parsed; // 所有校验完成后才替换调用方值。
        PrivateAddressWatchTarget target; // 原身份输入解析保留完整64位FILETIME。
        const bool image = m_kind->currentIndex() < 2;
        if (!m_identity->Prepare(target, m_kind->currentIndex() == 3, !image))
        {
            error = sourceText(QStringLiteral("请填写非零 PID、创建 FILETIME 和有效执行地址；页范围起点须为 4KiB 对齐。"));
            return false;
        }
        parsed.pid = target.pid;
        parsed.creationFileTime = target.creation;
        parsed.address = target.address;
        parsed.rangeBytes = target.rangeBytes;
        if (image)
        {
            const auto module = QDir::toNativeSeparators(m_module->text().trimmed()); // 与backend一致，只接绝对盘符路径。
            const bool drive = module.size() > 3 && ((module[0] >= QLatin1Char('A') && module[0] <= QLatin1Char('Z')) ||
                (module[0] >= QLatin1Char('a') && module[0] <= QLatin1Char('z')));
            if (!drive || module[1] != QLatin1Char(':') || module[2] != QLatin1Char('\\') ||
                module.contains(QLatin1Char('"')) || module.contains(QLatin1Char('\r')) || module.contains(QLatin1Char('\n')) ||
                module.contains(QChar(0)))
            {
                error = sourceText(QStringLiteral("模块必须是完整的盘符绝对路径。"));
                return false;
            }
            parsed.modulePath = module.toStdWString();
            if (m_kind->currentIndex() == 1)
            {
                parsed.rva = ParseImageExecutionRva(m_location->text()); // 拒绝零、负数及32位溢出。
                if (!parsed.rva)
                {
                    error = sourceText(QStringLiteral("请输入非零的 32 位模块 RVA。"));
                    return false;
                }
            }
            else
            {
                parsed.exactExport = m_location->text().trimmed().toUtf8().toStdString(); // 保留导出大小写。
                if (parsed.exactExport.empty() || parsed.exactExport.size() > 4096 || parsed.exactExport.find('\0') != std::string::npos)
                {
                    error = sourceText(QStringLiteral("请输入完整且区分大小写的导出名。"));
                    return false;
                }
            }
        }
        if (parsed.rangeBytes && parsed.address > (std::numeric_limits<std::uint64_t>::max)() - parsed.rangeBytes)
        {
            error = sourceText(QStringLiteral("执行范围超出地址边界。"));
            return false;
        }
        parsed.conditionSource = m_condition->text().toStdWString(); // 条件原文与不可变谓词共同冻结。
        auto condition = execution_group_native::PrepareDataWatchCondition(parsed.conditionSource);
        if (condition.diagnostic)
        {
            error = sourceText(QStringLiteral("成员条件无效：%1")).arg(QString::fromLatin1(condition.diagnostic));
            return false;
        }
        parsed.condition = std::move(condition.predicate);
        site = std::move(parsed);
        error.clear();
        return true;
    }
}
