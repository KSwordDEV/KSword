#include "../Framework.h"
#include "ExecutionGroupSiteEditor.h"
#include "PrivateAddressWatchFields.h"
#include "../../../KswordCLI/ActionAnalyze/Control/NativeBreakpointImageIdentity.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"
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
        m_imageSha256 = new QLineEdit(body); // 不采集文件散列，只编辑用户给出的可选约束。
        m_imageSha256->setObjectName(QStringLiteral("execution_group_expected_image_sha256"));
        m_imageSha256->setMaxLength(128); // 超过64位仍保留为非法输入，不能截成有效散列后发送。
        addRow(QStringLiteral("期望映像 SHA256（可选）"), m_imageSha256);
        language.bindToolTip(m_imageSha256, {}, QStringLiteral("仅模块导出或 RVA 可填写64位小写十六进制 SHA256；留空不设约束。原生所有者核验实际调试装载文件后才武装断点，不自动采集。"));
        m_definitionId = new QLineEdit(body); // 高级关联草稿不替代明确模块和RVA，启动前统一核对。
        m_definitionId->setObjectName(QStringLiteral("execution_group_definition_id"));
        m_definitionId->setMaxLength(128); // 超长ID保留为非法输入，不截成有效UUID。
        addRow(QStringLiteral("冻结断点定义 ID（可选）"), m_definitionId);
        language.bindToolTip(m_definitionId, {}, QStringLiteral("仅模块 RVA 可关联项目断点定义。启动前核对本轮采样冻结的启用定义、模块名、RVA 与映像散列；任一不符时不附加任何成员。"));
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
        m_form->setRowVisible(m_imageSha256, image); // 不清除隐藏草稿；Prepare只在模块分支发送。
        m_form->setRowVisible(m_definitionId, m_kind->currentIndex() == 1); // 不把定义ID发送给导出或私有地址站点。
    }

    // 输入保存的单成员草稿，回填全部参数；实际绑定的测量散列不能覆盖期望值。
    void ExecutionGroupSiteEditor::LoadDraft(const execution_group_native::ExecutionGroupSite& site)
    {
        const int kind = site.address ? (site.rangeBytes ? 3 : 2) : (site.rva ? 1 : 0); // 保存的机制决定可见参数。
        m_identity->LoadDraft({site.pid, site.creationFileTime, site.address, site.rangeBytes});
        m_module->setText(QString::fromStdWString(site.modulePath));
        m_location->setText(site.rva ? QStringLiteral("0x%1").arg(*site.rva, 0, 16) : QString::fromStdString(site.exactExport));
        if (!site.address)
        {
            m_imageSha256->setText(site.imageSha256 ? QString::fromStdString(*site.imageSha256) : QString());
        }
        if (site.rva)
        {
            m_definitionId->setText(QString::fromStdString(site.definitionId)); // 显式载入完整保存项，隐藏模式保留之前草稿。
        }
        m_condition->setText(QString::fromStdWString(site.conditionSource));
        m_kind->setCurrentIndex(kind);
        UpdateMode(); // 同模式重载也同步行可见性，私有站点保留现有隐藏散列草稿。
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
            const auto imageSha256 = m_imageSha256->text().toUtf8().toStdString(); // 原文严格校验，不自动转小写或修剪。
            if (!imageSha256.empty())
            {
                if (!execution_group_native::ValidNativeImageSha256(imageSha256))
                {
                    error = sourceText(QStringLiteral("映像 SHA256 须为空或64位小写十六进制。"));
                    return false;
                }
                parsed.imageSha256 = imageSha256; // 后端从实际装载事件文件核验；此处不访问模块文件。
            }
            if (m_kind->currentIndex() == 1)
            {
                parsed.rva = ParseImageExecutionRva(m_location->text()); // 拒绝零、负数及32位溢出。
                if (!parsed.rva)
                {
                    error = sourceText(QStringLiteral("请输入非零的 32 位模块 RVA。"));
                    return false;
                }
                parsed.definitionId = m_definitionId->text().toUtf8().toStdString(); // 不修剪或重写定义身份。
                if (!parsed.definitionId.empty() && !Ksword::ActionAnalyze::ProjectStorage::IsUuid(parsed.definitionId))
                {
                    error = sourceText(QStringLiteral("冻结断点定义 ID 须为空或规范 UUID。"));
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
