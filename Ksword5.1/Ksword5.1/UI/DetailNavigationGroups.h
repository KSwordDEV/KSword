#pragma once

#include "./FlatButtonTheme.h"
#include "./ThemeBinding.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include <QAbstractButton>
#include <QButtonGroup>
#include <QLabel>
#include <QPointer>
#include <QSet>
#include <QTabWidget>
#include <QVariant>
#include <QVBoxLayout>

namespace ks::ui
{
    enum class DetailNavigationKind
    {
        General, Performance, Resources, Security, Internals, Interaction,
        Extensions, Content, Analysis, Ownership, Display, Explanation, Behaviour
    };

    struct DetailTabGroup
    {
        DetailNavigationKind kind = DetailNavigationKind::General; // 明确的业务类型，不从翻译文字猜测。
        QList<int> indexes; // 原始 Tab 索引；导航显示顺序改变不会重排业务页。
    };

    inline QString DetailNavigationGroupSource(DetailNavigationKind kind)
    {
        switch (kind)
        {
        case DetailNavigationKind::Performance:
            return QStringLiteral("性能");
        case DetailNavigationKind::Resources:
            return QStringLiteral("资源");
        case DetailNavigationKind::Security:
            return QStringLiteral("安全");
        case DetailNavigationKind::Internals:
            return QStringLiteral("内部结构");
        case DetailNavigationKind::Interaction:
            return QStringLiteral("交互与操作");
        case DetailNavigationKind::Extensions:
            return QStringLiteral("扩展");
        case DetailNavigationKind::Content:
            return QStringLiteral("内容");
        case DetailNavigationKind::Analysis:
            return QStringLiteral("分析");
        case DetailNavigationKind::Ownership:
            return QStringLiteral("归属");
        case DetailNavigationKind::Display:
            return QStringLiteral("显示与合成");
        case DetailNavigationKind::Explanation:
            return QStringLiteral("说明");
        case DetailNavigationKind::Behaviour:
            return QStringLiteral("行为");
        default:
            return QStringLiteral("概览");
        }
    }

    inline QString DetailNavigationGroupKey(DetailNavigationKind kind)
    {
        return QStringLiteral("detail.navigation.group.%1").arg(static_cast<int>(kind));
    }

    // 在页面构造处登记类型与显示顺序，后续新增/隐藏页签仍由原 TabWidget 管理。
    inline void SetDetailTabGroups(QTabWidget* tabs, const QList<DetailTabGroup>& groups)
    {
        if (tabs == nullptr)
        {
            return;
        }
        QVariantList saved;
        for (const auto& group : groups)
        {
            QVariantList indexes;
            for (int index : group.indexes)
            {
                indexes.append(index);
            }
            saved.append(QVariant(QVariantList{static_cast<int>(group.kind), indexes}));
        }
        tabs->setProperty("ksword_detail_navigation_groups", saved);
    }

    // 统一高亮几何与真实颜色配方；忽略长标题的最小宽度，让侧栏严格服从 viewport。
    inline void ApplyDetailNavigationButtonTheme(QAbstractButton* button)
    {
        if (button == nullptr)
        {
            return;
        }
        button->setProperty("ksword_detail_navigation_button", true);
        button->setMinimumWidth(0);
        button->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
        button->setStyleSheet(BuildFlatButtonStyle(FlatButtonTone::Neutral, FlatButtonAppearance::Navigation)
            + QStringLiteral("QToolButton{border-radius:5px;padding:8px 10px;text-align:left;}"));
        ApplyFlatButtonTheme(button, FlatButtonTone::Neutral, FlatButtonAppearance::Navigation);
    }

    // 只在结构变化时重排原按钮，避免 LayoutRequest -> 重排 -> LayoutRequest 的循环。
    inline void ArrangeDetailNavigationGroups(QWidget* navigation, QTabWidget* tabs, QButtonGroup* buttons)
    {
        if (navigation == nullptr || tabs == nullptr || buttons == nullptr)
        {
            return;
        }
        auto* layout = qobject_cast<QVBoxLayout*>(navigation->layout());
        if (layout == nullptr)
        {
            return;
        }
        QList<DetailTabGroup> plan;
        QSet<int> used;
        QString signature;
        const QVariantList saved = tabs->property("ksword_detail_navigation_groups").toList();
        for (const QVariant& entry : saved)
        {
            const QVariantList values = entry.toList();
            if (values.size() != 2)
            {
                continue;
            }
            DetailTabGroup group;
            group.kind = static_cast<DetailNavigationKind>(values[0].toInt());
            for (const QVariant& value : values[1].toList())
            {
                const int index = value.toInt();
                if (index >= 0 && index < tabs->count() && tabs->isTabVisible(index)
                    && buttons->button(index) != nullptr && !used.contains(index))
                {
                    group.indexes.append(index);
                    used.insert(index);
                }
            }
            if (!group.indexes.isEmpty())
            {
                plan.append(group);
            }
        }
        // 新增且未登记的页面仍可访问，置于概览组末尾，不能因元数据漏项而消失。
        DetailTabGroup remaining;
        for (int index = 0; index < tabs->count(); ++index)
        {
            if (!used.contains(index) && tabs->isTabVisible(index) && buttons->button(index) != nullptr)
            {
                remaining.indexes.append(index);
            }
        }
        if (!remaining.indexes.isEmpty())
        {
            plan.append(remaining);
        }
        for (const auto& group : plan)
        {
            signature += QString::number(static_cast<int>(group.kind)) + QLatin1Char(':');
            for (int index : group.indexes)
            {
                signature += QString::number(index) + QLatin1Char(',');
            }
            signature += QLatin1Char(';');
        }
        const QVariant previousLayout = navigation->property("ksword_detail_navigation_layout");
        if (previousLayout.isValid() && previousLayout.toString() == signature)
        {
            return;
        }
        navigation->setProperty("ksword_detail_navigation_layout", signature);
        QList<QWidget*> extraWidgets; // 批量文件说明等业务附加控件继续保留。
        while (QLayoutItem* item = layout->takeAt(0))
        {
            QWidget* widget = item->widget();
            if (widget != nullptr && widget->property("ksword_detail_navigation_group").toBool())
            {
                delete widget;
            }
            else if (widget != nullptr && !buttons->buttons().contains(qobject_cast<QAbstractButton*>(widget)))
            {
                extraWidgets.append(widget);
            }
            delete item;
        }
        for (const auto& group : plan)
        {
            auto* label = new QLabel(navigation);
            label->setProperty("ksword_detail_navigation_group", true);
            label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
            ks::i18n::LanguageManager::instance().bindText(label, DetailNavigationGroupKey(group.kind),
                DetailNavigationGroupSource(group.kind));
            const QPointer<QLabel> guarded(label);
            BindWidgetTheme(label, [guarded]()
            {
                if (guarded.isNull())
                {
                    return;
                }
                const QString style = QStringLiteral("QLabel{color:%1;font-weight:600;padding:6px 10px 2px;}")
                    .arg(KswordTheme::EnsureTextContrast(KswordTheme::TextSecondaryColor(),
                        KswordTheme::SurfaceAltColor(), 4.5).name());
                if (guarded->styleSheet() != style)
                {
                    guarded->setStyleSheet(style);
                }
            });
            layout->addWidget(label);
            for (int index : group.indexes)
            {
                layout->addWidget(buttons->button(index));
            }
        }
        for (QWidget* widget : extraWidgets)
        {
            layout->addWidget(widget);
        }
        layout->addStretch(1);
    }
}
