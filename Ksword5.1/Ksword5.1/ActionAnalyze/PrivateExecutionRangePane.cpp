#include "../Framework.h"
#include "PrivateExecutionRangePane.h"
#include "PrivateAddressWatchFields.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/ThemedMessageBox.h"
#include "../theme.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QPointer>
#include <QSignalBlocker>
#include <QVBoxLayout>
#include <charconv>
#include <limits>

namespace ks::action_analyze
{
    // 输入参数正文宿主，创建单个共享分区；所有新增范围均须用户明确提交。
    PrivateExecutionRangePane::PrivateExecutionRangePane(QWidget* parent) : QWidget(parent)
    {
        auto& language = ks::i18n::LanguageManager::instance(); // 文案与应用语言同步。
        auto* root = new QVBoxLayout(this); // 不重复叠加页根留白。
        root->setContentsMargins(0, 0, 0, 0);
        auto* section = new QGroupBox(this); // 分区由共享参数皮肤管理。
        auto* form = new QFormLayout(section); // 自然高度，窄栏使用标签折行。
        ks::ui::StyleSecondaryForm(form, 100);
        ks::ui::StyleParameterSection(section);
        language.bindText(section, {}, QStringLiteral("纳入新的私有执行范围"));
        m_address = new QLineEdit(section);
        m_address->setObjectName(QStringLiteral("action_analyze_execution_add_range_base"));
        m_address->setMaxLength(20);
        m_pages = new QLineEdit(section); // 独立输入继续由标准主题和共享参数分区接入。
        m_pages->setObjectName(QStringLiteral("action_analyze_execution_add_range_pages"));
        m_pages->setText(QStringLiteral("1"));

        // 起点与页数是待执行草稿，编辑时不读取目标或改动已设防范围。
        auto* addressLabel = new QLabel(section); // 起点标签与输入建立键盘定位关系。
        addressLabel->setBuddy(m_address);
        language.bindText(addressLabel, {}, QStringLiteral("新范围起点"));
        form->addRow(addressLabel, m_address);
        auto* pagesLabel = new QLabel(section); // 每页4096字节，避免把页数当字节数。
        pagesLabel->setBuddy(m_pages);
        language.bindText(pagesLabel, {}, QStringLiteral("执行关注页数"));
        form->addRow(pagesLabel, m_pages);
        m_origin = new QLabel(section); // 草稿来源与实际纳入回执分开，选择候选不代表已经设防。
        m_origin->setTextFormat(Qt::PlainText);
        m_origin->setWordWrap(true);
        m_origin->hide();
        form->addRow(m_origin);
        auto* hint = new QLabel(section); // 说明操作边界，不把请求已接受解释为实际执行。
        hint->setWordWrap(true);
        language.bindText(hint, {}, QStringLiteral("在当前完整执行停点下显式纳入另一段私有执行页，不继续目标。单段必须来自同一分配，范围须为整页且地址不能溢出。"));
        form->addRow(hint);

        m_add = new QPushButton(section); // 简单追加动作使用统一图标和释义。
        m_add->setObjectName(QStringLiteral("action_analyze_execution_add_range"));
        KswordTheme::ApplyStandardIconButtonMetrics(m_add);
        ks::ui::SetThemeButtonIcon(m_add, QIcon(QStringLiteral(":/Icon/action_analyze_add_range.svg")));
        language.bindToolTip(m_add, {}, QStringLiteral("将所填范围纳入本会话执行监控，保留当前停点和原恢复责任。"));
        m_add->setAccessibleName(ks::i18n::sourceText(QStringLiteral("纳入新的私有执行范围")));
        form->addRow(m_add);
        m_status = new QLabel(section); // 局部错误不覆盖当前会话的原生回执。
        m_status->setWordWrap(true);
        m_status->setTextFormat(Qt::PlainText);
        form->addRow(m_status);
        root->addWidget(section);
        connect(m_add, &QPushButton::clicked, this, &PrivateExecutionRangePane::SubmitRange);
        const auto edited = [this] {
            m_origin->clear(); // 手工改地址或页数后，不沿用原候选身份说明。
            m_origin->hide();
        };
        connect(m_address, &QLineEdit::textChanged, this, edited);
        connect(m_pages, &QLineEdit::textChanged, this, edited);
        m_add->setEnabled(false);
    }

    // 输入原页面的同回合资格；禁用仍保留草稿，允许在下一完整停点重新提交。
    void PrivateExecutionRangePane::SetAvailable(bool available, const QString& reason)
    {
        m_available = available;
        m_add->setEnabled(available);
        m_status->setText(reason);
        m_status->setVisible(!reason.isEmpty());
        ks::ui::ApplyStatusRole(m_status, ks::ui::StatusRole::Idle);
        m_add->setAccessibleName(ks::i18n::sourceText(QStringLiteral("纳入新的私有执行范围")));
    }

    // 只加载明确整页子范围；调用方已核对sample与目标，实际MEM_PRIVATE准入仍留给原owner。
    bool PrivateExecutionRangePane::SetDraft(std::uint64_t address, std::uint64_t bytes, const QString& origin,
        const std::function<bool()>& stillCurrent)
    {
        if (!address || address % 4096 || !bytes || bytes % 4096 ||
            bytes > (std::numeric_limits<std::uint64_t>::max)() - address)
        {
            return false;
        }
        const auto selectedAddress = QStringLiteral("0x%1").arg(address, 0, 16); // 保持用户可辨的真实地址。
        const auto selectedPages = QString::number(bytes / 4096); // 完整64位页数，不经过int截断。
        if (!m_address->text().trimmed().isEmpty() &&
            (m_address->text().compare(selectedAddress, Qt::CaseInsensitive) != 0 || m_pages->text() != selectedPages))
        {
            const QPointer<PrivateExecutionRangePane> alive(this); // 模态期间父页可被关闭。
            const auto answer = QMessageBox::question(this, ks::i18n::sourceText(QStringLiteral("载入执行范围草稿")),
                ks::i18n::sourceText(QStringLiteral("替换当前新增范围草稿？已纳入的范围和当前停点将保留。")),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            if (!alive || answer != QMessageBox::Yes)
            {
                return false;
            }
        }
        if (stillCurrent && !stillCurrent())
        {
            return false; // 确认期间目标或采样已变化，不把旧候选写到新会话草稿。
        }
        const QSignalBlocker addressBlock(m_address); // 两个参数一次更新，不触发手动编辑的来源清除。
        const QSignalBlocker pagesBlock(m_pages);
        m_address->setText(selectedAddress);
        m_pages->setText(selectedPages);
        m_origin->setText(origin);
        m_origin->setVisible(!origin.isEmpty());
        return true; // 只有草稿已加载；显式纳入按钮另行冻结当时的完整停止票据。
    }

    // 输入十进制或0x地址和页数，输出完整值；不接受负数、尾随字符、溢出或非对齐地址。
    void PrivateExecutionRangePane::SubmitRange()
    {
        if (!m_available || !addRange)
        {
            return;
        }
        auto text = m_address->text().trimmed().toLatin1(); // 非ASCII字符无法解析为合法地址。
        int radix = 10; // 无0x前缀时始终按十进制解释。
        if (text.startsWith("0x") || text.startsWith("0X"))
        {
            text.remove(0, 2);
            radix = 16;
        }
        std::uint64_t address = 0; // 完整64位地址，不经过浮点或32位转换。
        const auto parsed = std::from_chars(text.constData(), text.constData() + text.size(), address, radix);
        std::uint64_t bytes = 0; // 先严格解析页数并检查乘法，再检查地址加法。
        if (text.isEmpty() || parsed.ec != std::errc{} || parsed.ptr != text.constData() + text.size() ||
            !address || address % 4096 || !ParsePrivateExecutionPageBytes(m_pages->text(), bytes) ||
            bytes > (std::numeric_limits<std::uint64_t>::max)() - address)
        {
            m_status->setText(ks::i18n::sourceText(QStringLiteral("请输入非零、4KiB对齐的起点及正十进制页数，页数字节换算和地址范围均不能溢出。")));
            m_status->show();
            ks::ui::ApplyStatusRole(m_status, ks::ui::StatusRole::Error);
            m_address->setFocus(Qt::OtherFocusReason);
            return;
        }
        m_status->clear();
        m_status->hide();
        addRange(address, bytes); // 页保护、重复范围及当前事件由原native再检查。
    }
}
