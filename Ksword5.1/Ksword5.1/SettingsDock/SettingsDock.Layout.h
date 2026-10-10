#pragma once

#include "../Internationalization/LanguageManager.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/ToolbarMetrics.h"

#include <QAbstractButton>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QScrollArea>
#include <QVBoxLayout>

namespace ks::settings::ui
{
    // ScrollPage 只包装当前页内容，让顶部标签和窗口底部操作始终留在可见范围。
    // content 所有权交给返回的滚动区；原有控件实例和信号连接保持有效。
    inline QWidget* ScrollPage(QWidget* content)
    {
        auto* scroll = new QScrollArea(content->parentWidget()); // 当前页唯一纵向滚动入口。
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        content->setMinimumWidth(0);
        scroll->setWidget(content);
        return scroll;
    }

    // Section 为明确的设置分区保留标题和细分隔线，布局不再绘制逐项卡片。
    inline void Section(QGroupBox* section)
    {
        ks::ui::StyleSecondarySection(section);
        if (section->layout() != nullptr)
        {
            section->layout()->setContentsMargins(0, 0, 0, 0);
            section->layout()->setSpacing(8);
            // 表单在控件齐备后再统一左列宽度，不能只在空表单上调用几何策略。
            for (int index = 0; index < section->layout()->count(); ++index)
            {
                auto* form = qobject_cast<QFormLayout*>(section->layout()->itemAt(index)->layout());
                if (form != nullptr)
                {
                    const int storedWidth = form->property("ksword_settings_label_width").toInt();
                    ks::ui::StyleSecondaryForm(form, storedWidth > 0 ? storedWidth : 160);
                }
            }
        }
    }

    // Label 创建绑定语言包的左列标签；labelKey 只负责显示，不参与保存配置。
    inline QLabel* Label(QWidget* parent, const QString& labelKey, const QString& fallback)
    {
        auto* label = new QLabel(parent); // 对齐到控件行的标签。
        label->setWordWrap(true);
        ks::i18n::LanguageManager::instance().bindText(label, labelKey, fallback);
        return label;
    }

    // Form 把一组相关选项排在同一标签列；窄页允许长行换行，不裁剪输入内容。
    inline QFormLayout* Form(QVBoxLayout* parent, int labelWidth = 160)
    {
        auto* form = new QFormLayout(); // 每个分区独立维护行，标签宽度共用。
        form->setProperty("ksword_settings_label_width", labelWidth);
        ks::ui::StyleSecondaryForm(form, labelWidth);
        parent->addLayout(form);
        return form;
    }

    // ControlRow 包装一排输入或动作，外部表单只看到一个 field，内部仍按原先伸缩。
    inline QWidget* ControlRow(QHBoxLayout* row, QWidget* parent)
    {
        auto* field = new QWidget(parent); // 容纳同一设置的控件、数值和次要动作。
        row->setContentsMargins(0, 0, 0, 0);
        row->setSpacing(8);
        field->setLayout(row);
        ks::ui::NormalizeToolbarRow(row);
        return field;
    }

    // ToggleRow 把已有复选框的文字放入左列，使勾选位置与其他输入控件对齐。
    // 左列接管原语言绑定，复选框保留状态与原信号；不创建新的配置开关。
    inline void ToggleRow(QFormLayout* form, QAbstractButton* toggle,
        const QString& labelKey, const QString& fallback)
    {
        auto* label = Label(toggle->parentWidget(), labelKey, fallback);
        label->setBuddy(toggle);
        toggle->setText(QString());
        ks::i18n::LanguageManager::instance().bindText(toggle, QString(), QString());

        form->addRow(label, toggle);
    }
}
