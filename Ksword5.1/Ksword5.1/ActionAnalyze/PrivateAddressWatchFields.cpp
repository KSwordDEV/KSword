#include "../Framework.h"
#include "PrivateAddressWatchFields.h"
#include "../Internationalization/LanguageManager.h"

#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QSpinBox>
#include <limits>

namespace ks::action_analyze
{
    namespace
    {
        // 解析完整无符号数字，拒绝符号、尾随字符和溢出；仅地址允许0x前缀。
        bool ReadUnsigned(const QLineEdit* field, bool hexadecimal, std::uint64_t& result)
        {
            auto text = field->text().trimmed(); // 外围空白不改变实际数字。
            int base = 10; // PID和创建时间始终使用十进制。
            if (hexadecimal && text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
            {
                text.remove(0, 2);
                base = 16;
            }
            if (text.isEmpty())
            {
                return false;
            }
            for (const auto character : text)
            {
                const auto code = character.unicode(); // 只接受ASCII数字，避免宽字符隐式转换。
                const bool digit = code >= '0' && code <= '9';
                const bool hex = base == 16 && ((code >= 'a' && code <= 'f') || (code >= 'A' && code <= 'F'));
                if (!digit && !hex)
                {
                    return false;
                }
            }
            bool parsed = false; // Qt同时校验整个uint64范围。
            result = text.toULongLong(&parsed, base);
            return parsed && result != 0;
        }
    }

    // 输入父参数区，返回自然高度表单；窗口生命周期由父对象管理。
    PrivateAddressWatchFields::PrivateAddressWatchFields(QWidget* parent) : QWidget(parent)
    {
        auto& language = ks::i18n::LanguageManager::instance(); // 文案随应用语言绑定更新。
        auto* form = new QFormLayout(this); // 标签可下折，参数正文沿用宿主独立滚动。
        form->setContentsMargins(0, 0, 0, 0); // 留白只由外层参数分区负责。
        form->setRowWrapPolicy(QFormLayout::WrapLongRows);
        form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        form->setLabelAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        const auto addField = [&](QLineEdit*& field, const char* name, const QString& title)
        {
            field = new QLineEdit(this); // 标准输入主题负责底色、焦点与尺寸。
            field->setObjectName(QString::fromLatin1(name));
            field->setMaxLength(20);
            auto* label = new QLabel(this); // buddy保留键盘定位与无障碍关系。
            label->setBuddy(field);
            language.bindText(label, {}, title);
            form->addRow(label, field);
            connect(field, &QLineEdit::textChanged, this, [this]
            {
                if (changed)
                {
                    changed();
                }
            });
        };
        addField(m_pid, "action_analyze_watch_pid", QStringLiteral("目标 PID"));
        addField(m_creation, "action_analyze_watch_creation", QStringLiteral("进程创建 FILETIME"));
        addField(m_address, "action_analyze_watch_private_address", QStringLiteral("私有地址"));
        m_pageCount = new QSpinBox(this); // 标准输入主题与宿主参数布局负责尺寸和底色。
        m_pageCount->setObjectName(QStringLiteral("action_analyze_watch_execution_pages"));
        m_pageCount->setRange(1, 64);
        m_pageCount->setValue(1);
        auto* pageLabel = new QLabel(this); // 页数是显式草稿，不查询或枚举目标的实际区域。
        pageLabel->setBuddy(m_pageCount);
        language.bindText(pageLabel, {}, QStringLiteral("执行关注页数"));
        language.bindToolTip(m_pageCount, {}, QStringLiteral("每页4096字节，最多64页。范围必须属于同一私有分配；保留各页原保护，拒绝空洞。"));
        form->addRow(pageLabel, m_pageCount);
        form->setRowVisible(m_pageCount, false);
        connect(m_pageCount, &QSpinBox::valueChanged, this, [this]
        {
            if (changed)
            {
                changed(); // 修改范围只更新下一次启动资格，不重绑当前结果。
            }
        });
        language.bindToolTip(m_creation, {}, QStringLiteral("填写该进程实例的创建 FILETIME（十进制），开始时核对实例身份。"));
        language.bindToolTip(m_address, {}, QStringLiteral("地址支持十进制或0x十六进制。执行关注要求私有 EXECUTE/RX/RWX，写关注要求自然对齐的私有 RW/RWX；不会修改页保护。"));
    }

    // 输入当前草稿，输出完整目标；失败时不留下部分解析身份。
    bool PrivateAddressWatchFields::Prepare(PrivateAddressWatchTarget& target, bool pageExecution, bool requireAddress) const
    {
        target = {};
        std::uint64_t pid = 0; // 先以64位解析，再显式检查PID宽度。
        PrivateAddressWatchTarget selected; // 仅全部成功后向调用方提交。
        if (!ReadUnsigned(m_pid, false, pid) || pid > (std::numeric_limits<std::uint32_t>::max)() ||
            !ReadUnsigned(m_creation, false, selected.creation) ||
            (requireAddress && !ReadUnsigned(m_address, true, selected.address)))
        {
            return false;
        }
        if (pageExecution)
        {
            // 单页参数由模式显式选择；后端负责真实MEM_PRIVATE、提交状态及原保护核验。
            constexpr std::uint64_t pageBytes = 4096; // 当前AMD64执行页关注的页大小。
            if (selected.address % pageBytes != 0)
            {
                return false;
            }
            selected.rangeBytes = pageBytes * static_cast<std::uint64_t>(m_pageCount->value());
        }
        selected.pid = static_cast<std::uint32_t>(pid);
        target = selected;
        return true;
    }

    // 输入当前选择的执行机制；提示跟随模式变化，避免整页模式沿用“不改保护”的说明。
    void PrivateAddressWatchFields::SetPageExecutionMode(bool pageExecution, bool imageExecution)
    {
        using ks::i18n::sourceText;
        auto* form = static_cast<QFormLayout*>(layout()); // 模块模式仍显示精确实例，地址由模块内位置选择。
        form->setRowVisible(m_address, !imageExecution);
        form->setRowVisible(m_pageCount, pageExecution);
        m_address->setToolTip(sourceText(pageExecution
            ? QStringLiteral("填写4KiB对齐的私有执行页起点。整页关注临时撤去执行权限，保留原读写权限；关闭时由原会话恢复保护。")
            : QStringLiteral("地址支持十进制或0x十六进制。执行关注要求私有 EXECUTE/RX/RWX，写关注要求自然对齐的私有 RW/RWX；不会修改页保护。")));
    }

    // 输入完整RVA文本，输出非零32位值；不接受符号、八进制、尾随字符或溢出。
    std::optional<std::uint32_t> ParseImageExecutionRva(const QString& text)
    {
        auto value = text.trimmed(); // 仅移除表单两侧空白，数值语义与CLI十进制/0x保持一致。
        const bool hexadecimal = value.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive);
        if (hexadecimal)
        {
            value.remove(0, 2);
        }
        if (value.isEmpty())
        {
            return {};
        }
        for (const auto character : value)
        {
            const auto code = character.unicode(); // 所有有效数字均为ASCII，拒绝隐式Unicode数字转换。
            if (!((code >= '0' && code <= '9') || (hexadecimal &&
                ((code >= 'a' && code <= 'f') || (code >= 'A' && code <= 'F')))))
            {
                return {};
            }
        }
        bool parsed = false; // Qt完整检查32位范围，不截断超宽地址。
        const auto rva = value.toUInt(&parsed, hexadecimal ? 16 : 10);
        return parsed && rva ? std::optional<std::uint32_t>{rva} : std::nullopt;
    }

    // 输入完整已保存目标，回填身份、地址与页数；仅由显式载入动作调用，无控制副作用。
    void PrivateAddressWatchFields::LoadDraft(const PrivateAddressWatchTarget& target)
    {
        m_pid->setText(QString::number(target.pid));
        m_creation->setText(QString::number(target.creation));
        m_address->setText(target.address ? QStringLiteral("0x%1").arg(target.address, 0, 16) : QString());
        m_pageCount->setValue(target.rangeBytes ? static_cast<int>(target.rangeBytes / 4096) : 1);
    }

    // 不清空输入或修改结果，仅阻止活会话期间改写本轮目标草稿。
    void PrivateAddressWatchFields::SetActive(bool active)
    {
        for (auto* field : {m_pid, m_creation, m_address})
        {
            field->setReadOnly(active);
        }
        m_pageCount->setEnabled(!active); // 活会话中的范围来自冻结请求，不能由草稿改变。
    }
}
