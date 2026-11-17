#include "../Framework.h"
#include "./SettingsPresentation.h"
#include "./ThemeBinding.h"
#include "../theme.h"
#include <QAbstractButton>
#include <QApplication>
#include <QFontDatabase>
#include <QFormLayout>
#include <QLabel>
#include <QPointer>
#include <QTabBar>
#include <QTimer>
#include <algorithm>

namespace
{
    // 完整最终规则逐值比较：语言/重复palette事件不使同一设置子树再次repolish。
    // 不依赖主题代次，避免遗漏显式局部规则被替换后的重新接管。
    void applySettingsRules(QWidget* widget, const QString& rules)
    {
        widget->setProperty("ksword_settings_style_block", rules);
        if (widget->styleSheet() != rules) widget->setStyleSheet(rules);
    }

    // 只追踪已登记的设置表单。字体或复合控件尺寸变化后，同步左右两列的视觉中心。
    class SettingsFormMetrics final : public QObject
    {
    public:
        explicit SettingsFormMetrics(QFormLayout* form) : QObject(form), m_form(form)
        {
            refreshHost();
            schedule();
        }

        void refresh(bool changed = true)
        {
            m_dirty = m_dirty || changed;
            prepare();
        }

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            const QPointer<QObject> alive(watched);
            if (event->type() == QEvent::Show || event->type() == QEvent::Polish)
            {
                if (watched == m_host) prepare();
            }
            else if (event->type() == QEvent::LayoutRequest)
            {
                if (watched == m_host) prepare();
            }
            else if (event->type() == QEvent::FontChange
                || event->type() == QEvent::ApplicationFontChange
                || event->type() == QEvent::ScreenChangeInternal)
            {
                if (!m_applying) schedule();
            }
            else if (event->type() == QEvent::ChildAdded || event->type() == QEvent::ChildRemoved)
            {
                if (!m_applying) schedule();
            }
            return alive.isNull();
        }

    private:
        void refreshHost()
        {
            if (!m_form) return;
            QWidget* host = m_form->parentWidget();
            if (host == m_host) return;
            if (m_host) m_host->removeEventFilter(this);
            m_host = host;
            if (m_host) m_host->installEventFilter(this);
        }

        void schedule(bool changed = true)
        {
            m_dirty = m_dirty || changed;
            if (m_pending) return;
            m_pending = true;
            QTimer::singleShot(0, this, [this]()
            {
                m_pending = false;
                prepare(true);
            });
        }

        // Registered row metrics run at Show/posted-layout boundaries, never
        // in Paint. A stale constructor timer does not move a painted form.
        void prepare(bool deferred = false)
        {
            if (!m_form || m_applying) return;
            refreshHost();
            const int rows = m_form->rowCount();
            if (rows != m_lastRowCount) m_dirty = true;
            if (!m_dirty) return;
            if (!deferred && m_host && (m_host->window()->windowType() == Qt::Popup
                || m_host->window()->windowType() == Qt::ToolTip))
            {
                schedule();
                return;
            }
            m_dirty = false;
            m_lastRowCount = rows;
            m_applying = true;
            const QPointer<SettingsFormMetrics> alive(this);
            apply();
            if (alive) m_applying = false;
        }

        void apply()
        {
            const QPointer<QFormLayout> form(m_form);
            const int labelWidth = form->property("ksword_settings_label_width").toInt();
            for (int row = 0; form && row < form->rowCount(); ++row)
            {
                QLayoutItem* labelItem = m_form->itemAt(row, QFormLayout::LabelRole);
                QLayoutItem* fieldItem = m_form->itemAt(row, QFormLayout::FieldRole);
                const QPointer<QLabel> label(labelItem ? qobject_cast<QLabel*>(labelItem->widget()) : nullptr);
                const QPointer<QWidget> field(fieldItem ? fieldItem->widget() : nullptr);
                // 跨行说明不强加控件行高；长标签仍可按实际宽度换行。
                if (!label || label->text().isEmpty() || !field)
                {
                    continue;
                }
                label->installEventFilter(this);
                field->installEventFilter(this);
                if (label->alignment() != (Qt::AlignLeft | Qt::AlignVCenter))
                    label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
                if (!form || !label || !field) return;
                if (!label->wordWrap()) label->setWordWrap(true);
                if (!form || !label || !field) return;
                if (label->minimumWidth() != labelWidth)
                {
                    label->setMinimumWidth(labelWidth);
                }
                if (!form || !label || !field) return;
                // 行内文字按同一字号测量，右侧的原生复选框也占据完整的单行高度。
                const int rowHeight = std::max({28, label->fontMetrics().height() + 12,
                    field->fontMetrics().height() + 12});
                if (field->minimumHeight() != rowHeight)
                {
                    field->setMinimumHeight(rowHeight);
                }
                if (!form || !label || !field) return;
                // 不能将复合行的无宽度 sizeHint 固化为最小高度：可换行说明的建议
                // 高度可能很大。实际换行与整行高度交给 QFormLayout 的 heightForWidth。
                if (label->minimumHeight() != rowHeight)
                {
                    label->setMinimumHeight(rowHeight);
                }
            }
        }

        QPointer<QFormLayout> m_form; // 布局拥有此对象，不跨设置页保存状态。
        QPointer<QWidget> m_host;
        int m_lastRowCount = -1;
        bool m_dirty = true; // 首显消费与后续字体更新共用同一工作。
        bool m_pending = false; // 每轮只执行一次尺寸同步。
        bool m_applying = false; // 自身几何更新不安排重复工作。
    };
}

namespace ks::ui
{
    void StyleSettingsForm(QFormLayout* form, int labelWidth)
    {
        if (!form)
        {
            return;
        }
        const bool labelWidthChanged = form->property("ksword_settings_label_width").toInt() != labelWidth;
        if (labelWidthChanged) form->setProperty("ksword_settings_label_width", labelWidth);
        if (form->horizontalSpacing() != 16) form->setHorizontalSpacing(16);
        if (form->verticalSpacing() != 4) form->setVerticalSpacing(4);
        if (form->labelAlignment() != (Qt::AlignLeft | Qt::AlignVCenter)) form->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        if (form->formAlignment() != (Qt::AlignLeft | Qt::AlignTop)) form->setFormAlignment(Qt::AlignLeft | Qt::AlignTop);
        if (form->fieldGrowthPolicy() != QFormLayout::AllNonFixedFieldsGrow) form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        if (form->rowWrapPolicy() != QFormLayout::WrapLongRows) form->setRowWrapPolicy(QFormLayout::WrapLongRows);
        auto* metrics = static_cast<SettingsFormMetrics*>(
            form->property("ksword_settings_form_metrics_owner").value<QObject*>());
        if (!metrics)
        {
            metrics = new SettingsFormMetrics(form);
            form->setProperty("ksword_settings_form_metrics", true);
            form->setProperty("ksword_settings_form_metrics_owner", QVariant::fromValue<QObject*>(metrics));
        }
        metrics->refresh(labelWidthChanged);
    }

    void ApplySettingsPresentation(QWidget* settings)
    {
        if (settings == nullptr)
        {
            return;
        }
        QFont body = QApplication::font(); // 保留用户配置家族，设置正文只提高阅读字号下限。
        if (body.pixelSize() > 0)
        {
            body.setPixelSize(std::max(14, body.pixelSize()));
        }
        else
        {
            body.setPointSizeF(std::max(10.5, body.pointSizeF()));
        }
        body.setWeight(QFont::Normal);
        settings->setFont(body);
        if (settings->property("ksword_settings_content").toBool())
        {
            return;
        }
        settings->setProperty("ksword_settings_content", true);
        const QPointer<QWidget> owner(settings);
        BindWidgetTheme(settings, [owner]()
        {
            if (!owner)
            {
                return;
            }
            // 输入面比窗口稍亮，边界使用低饱和中性色；不再用大片亮灰块分隔每一行。
            QString rules = QStringLiteral(
                "QWidget[ksword_settings_content=\"true\"]{background:transparent;color:__TEXT__; }"
                // 表单正文与控件文案同级，避免全局按钮半粗体让右列显得更重。
                "QWidget[ksword_settings_content=\"true\"] QLabel,"
                "QWidget[ksword_settings_content=\"true\"] QAbstractButton,"
                "QWidget[ksword_settings_content=\"true\"] QLineEdit,"
                "QWidget[ksword_settings_content=\"true\"] QComboBox,"
                "QWidget[ksword_settings_content=\"true\"] QAbstractSpinBox{font-weight:400;}"
                "QWidget[ksword_settings_content=\"true\"] QLabel[ksword_settings_hint=\"true\"]{color:__SECONDARY__; }"
                "QWidget[ksword_settings_content=\"true\"] QLabel:disabled{color:__DISABLED__; }");
            rules.replace(QStringLiteral("__TEXT__"), KswordTheme::TextPrimaryColor().name());
            rules.replace(QStringLiteral("__DISABLED__"), KswordTheme::TextDisabledColor().name());
            rules.replace(QStringLiteral("__SECONDARY__"), KswordTheme::EnsureTextContrast(
                KswordTheme::TextSecondaryColor(), KswordTheme::WindowColor(), 4.5).name());
            applySettingsRules(owner, rules);
        }, ThemePalettePolicy::PreserveLocal);
    }

    void StyleSettingsColorButton(QAbstractButton* button)
    {
        if (button == nullptr)
        {
            return;
        }
        button->setProperty("ksword_theme_icon_managed", true); // 色块是未应用配置的数据原色。
        QFont code = button->font(); // 色值保留等宽家族，但不另行放大字号或加重。
        code.setFamily(QFontDatabase::systemFont(QFontDatabase::FixedFont).family());
        code.setWeight(QFont::Normal);
        button->setFont(code);
        const QPointer<QAbstractButton> target(button);
        BindWidgetTheme(button, [target]()
        {
            if (target)
            {
                const QColor input = KswordTheme::BlendColors(KswordTheme::WindowColor(), KswordTheme::SurfaceAltColor(), 70);
                applySettingsRules(target, QStringLiteral(
                    "QPushButton{background:%1;color:%2;border:1px solid %3;border-radius:5px;padding:3px 8px;font-weight:400;}"
                    "QPushButton:hover{border-color:%4;}"
                    "QPushButton:disabled{color:%5;}")
                    .arg(input.name(), KswordTheme::TextPrimaryColor().name(), KswordTheme::BorderColor().name(),
                        KswordTheme::ControlAccentColor().name(), KswordTheme::TextDisabledColor().name()));
            }
        }, ThemePalettePolicy::PreserveLocal);
    }

    void StyleSettingsNavigation(QTabBar* bar, const QFont& bodyFont)
    {
        if (bar == nullptr)
        {
            return;
        }
        QFont navigation = bodyFont; // 导航比正文略大，保留字号单位和用户字体家族。
        if (navigation.pixelSize() > 0)
        {
            navigation.setPixelSize(std::max(16, navigation.pixelSize() + 2));
        }
        else
        {
            navigation.setPointSizeF(std::max(11.5, navigation.pointSizeF() + 1.0));
        }
        bar->setProperty("ksword_settings_tabs", true);
        bar->setFont(navigation);
    }

    void StyleSettingsLinkButton(QAbstractButton* button)
    {
        if (button == nullptr)
        {
            return;
        }
        const QPointer<QAbstractButton> target(button);
        BindWidgetTheme(button, [target]()
        {
            if (target)
            {
                const QColor base = KswordTheme::WindowColor();
                applySettingsRules(target, QStringLiteral(
                    "QAbstractButton{background:transparent;color:%1;border:0;padding:3px 6px;font-weight:400;}"
                    "QAbstractButton:hover{background:%2;border-radius:4px;}"
                    "QAbstractButton:disabled{color:%3;}")
                    .arg(KswordTheme::EnsureTextContrast(KswordTheme::PrimaryAccentColor(), base, 4.5).name(),
                        KswordTheme::BlendColors(base, KswordTheme::ControlAccentColor(), 20).name(),
                        KswordTheme::TextDisabledColor().name()));
            }
        }, ThemePalettePolicy::PreserveLocal);
    }
}
