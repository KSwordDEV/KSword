#include "ThemeBinding.h"
#include "../theme.h"
#include <QAbstractSpinBox>
#include <QLineEdit>

#include <QApplication>
#include <QEvent>
#include <QList>
#include <QObject>
#include <QPalette>
#include <QPointer>
#include <QThread>
#include <QTimer>
#include <QVariant>
#include <QWidget>

#include <algorithm>
#include <utility>

namespace
{
    // kBindingProperty 保存控件自身的绑定对象；该对象由控件的 QObject 子树持有。
    constexpr char kBindingProperty[] = "KSWORD_EXPLICIT_THEME_BINDING";
    constexpr char kSearchFieldProperty[] = "KSWORD_SEARCH_FIELD_THEME"; // 已明确登记的搜索框。
    constexpr char kSearchStyleBegin[] = "/* KSWORD_SEARCH_FIELD_BEGIN */"; // 本组件样式起点。
    constexpr char kSearchStyleEnd[] = "/* KSWORD_SEARCH_FIELD_END */"; // 本组件样式终点。
    constexpr char kSpinStyleBegin[] = "/* KSWORD_SPIN_FIELD_BEGIN */"; // 数值框独有颜色片段起点。
    constexpr char kSpinStyleEnd[] = "/* KSWORD_SPIN_FIELD_END */"; // 页面其它样式不属于此片段。
    class WidgetThemeBinding;

    // 只替换本组件拥有的颜色片段，页面的尺寸、padding 和其它规则继续保留。
    QString replaceFieldStyle(QString style, const QString& replacement,
        const char* beginMarker, const char* endMarker)
    {
        const qsizetype begin = style.indexOf(QLatin1String(beginMarker));
        const qsizetype end = style.indexOf(QLatin1String(endMarker), begin);
        if (begin >= 0 && end >= begin)
        {
            style.replace(begin, end + qstrlen(endMarker) - begin, replacement);
        }
        else
        {
            style += replacement;
        }
        return style;
    }

    // ThemeBindingRegistry 只维护已登记对象和合并队列，不猜测颜色含义或扫描业务控件树。
    class ThemeBindingRegistry final : public QObject
    {
    public:
        // application 是 GUI 应用对象，负责发布器寿命；没有额外所有权转移。
        explicit ThemeBindingRegistry(QApplication* application)
            : QObject(application)
        {
            application->installEventFilter(this);
        }

        // add 登记唯一绑定；schedule 只向下一轮事件循环提交一次刷新。
        void add(WidgetThemeBinding* binding);
        void schedule(WidgetThemeBinding* binding);
        void scheduleAll();

    protected:
        // 应用调色板更新只排队刷新；各控件的局部 palette 事件由自己的绑定观察。
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (watched == parent() && event != nullptr &&
                event->type() == QEvent::ApplicationPaletteChange)
            {
                scheduleAll();
            }
            return QObject::eventFilter(watched, event);
        }

    private:
        // drain 对弱引用快照逐一刷新；回调可创建或删除其他绑定，不破坏正在遍历的队列。
        void drain();
        QList<QPointer<WidgetThemeBinding>> m_bindings; // 存活登记项，不拥有控件。
        QList<QPointer<WidgetThemeBinding>> m_pending;  // 本轮待刷新项，保持登记顺序。
        bool m_scheduled = false; // 合并同一轮重复主题事件的调度门禁。
    };

    // registry 仅供 GUI 线程使用；QPointer 在 QApplication 销毁后自动失效。
    ThemeBindingRegistry* registry()
    {
        auto* application = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (application == nullptr || QThread::currentThread() != application->thread())
        {
            return nullptr;
        }
        static QPointer<ThemeBindingRegistry> installedRegistry;
        if (installedRegistry == nullptr)
        {
            installedRegistry = new ThemeBindingRegistry(application);
        }
        return installedRegistry.data();
    }

    class WidgetThemeBinding final : public QObject
    {
    public:
        // widget 持有绑定；ownerRegistry 仅管理刷新调度，不改变 QWidget 父级或布局。
        WidgetThemeBinding(QWidget* widget, ThemeBindingRegistry* ownerRegistry,
            std::function<void()> refresh, ks::ui::ThemePalettePolicy palettePolicy)
            : QObject(widget), m_widget(widget), m_registry(ownerRegistry),
              m_refresh(std::move(refresh)), m_palettePolicy(palettePolicy)
        {
            widget->installEventFilter(this);
            widget->setProperty(kBindingProperty, QVariant::fromValue<QObject*>(this));
        }

        // replace 在同一控件上替换角色策略，不重复安装过滤器或增加登记项。
        void replace(std::function<void()> refresh, ks::ui::ThemePalettePolicy palettePolicy)
        {
            m_refresh = std::move(refresh);
            m_palettePolicy = palettePolicy;
        }

        // apply 只在 GUI 线程调用；先复制函数，再执行可能销毁自身的样式更新。
        void apply()
        {
            if (m_widget == nullptr || !m_refresh)
            {
                return;
            }
            if (m_applying)
            {
                // 嵌套事件循环可能提前消费新策略的队列；外层退出后仍须保留这次刷新。
                m_refreshRequested = true;
                return;
            }
            m_applying = true;
            const QPointer<WidgetThemeBinding> lifetime(this); // 刷新后探活，避免访问已删对象。
            const QPointer<QWidget> widget(m_widget); // palette 更新本身也可能使控件关闭。
            const bool preserveLocal = m_palettePolicy == ks::ui::ThemePalettePolicy::PreserveLocal;
            const QPalette localPalette = widget->palette(); // 保留独立窗口声明的当前局部角色。
            const auto refresh = m_refresh; // 回调中重新登记也不会销毁正在执行的函数。
            refresh();
            if (lifetime != nullptr && widget != nullptr && preserveLocal)
            {
                // Qt setStyleSheet 会把后设的局部 palette 还原为旧 QSS 基线，因此需要显式恢复。
                widget->setPalette(localPalette);
            }
            if (lifetime != nullptr)
            {
                lifetime->m_applying = false;
                if (lifetime->m_refreshRequested && lifetime->m_registry != nullptr)
                {
                    lifetime->m_refreshRequested = false;
                    lifetime->m_registry->schedule(lifetime.data());
                }
            }
        }

    protected:
        // 局部 palette 或语言变化可能改变角色文本；自身 setStyleSheet 的重入事件不再排队。
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (!m_applying && m_registry != nullptr && event != nullptr &&
                (event->type() == QEvent::PaletteChange ||
                    event->type() == QEvent::ApplicationPaletteChange ||
                    event->type() == QEvent::LanguageChange))
            {
                m_registry->schedule(this);
            }
            return QObject::eventFilter(watched, event);
        }

    private:
        QPointer<QWidget> m_widget; // 明确拥有样式的单个控件，不隐式接管子控件。
        QPointer<ThemeBindingRegistry> m_registry; // 应用销毁后停止调度。
        std::function<void()> m_refresh; // 根据稳定语义角色重新求值的完整刷新函数。
        ks::ui::ThemePalettePolicy m_palettePolicy; // 是否保留独立窗口的局部调色板。
        bool m_applying = false; // 禁止刷新过程中因自身样式事件递归调度。
        bool m_refreshRequested = false; // 嵌套循环消费的刷新在外层结束后重新排队。
    };

    // add 将对象放入唯一登记表，并安排首次刷新；不在控件构造期间同步执行样式函数。
    void ThemeBindingRegistry::add(WidgetThemeBinding* binding)
    {
        // 动态页面反复开关时及时清理死亡登记项，不等用户下次切换主题。
        m_bindings.erase(std::remove_if(m_bindings.begin(), m_bindings.end(),
            [](const QPointer<WidgetThemeBinding>& current) { return current.isNull(); }),
            m_bindings.end());
        m_bindings.append(binding);
        schedule(binding);
    }

    void ThemeBindingRegistry::schedule(WidgetThemeBinding* binding)
    {
        if (binding == nullptr)
        {
            return;
        }
        // weakBinding 为当前对象的弱引用；重复事件只保留一次待刷新记录。
        const QPointer<WidgetThemeBinding> weakBinding(binding);
        if (!m_pending.contains(weakBinding))
        {
            m_pending.append(weakBinding);
        }
        if (m_scheduled)
        {
            return;
        }
        m_scheduled = true;
        QTimer::singleShot(0, this, [this]() { drain(); });
    }

    void ThemeBindingRegistry::scheduleAll()
    {
        // 清理死亡登记项；只遍历明确接入的对象，避免主题切换扫描整个 UI。
        m_bindings.erase(std::remove_if(m_bindings.begin(), m_bindings.end(),
            [](const QPointer<WidgetThemeBinding>& binding) { return binding.isNull(); }),
            m_bindings.end());
        for (const auto& binding : m_bindings)
        {
            schedule(binding.data());
        }
    }

    void ThemeBindingRegistry::drain()
    {
        // 先分离本轮队列；回调新增的登记项进入下一轮，避免遍历容器因重入失效。
        auto pending = std::move(m_pending); // 只包含本轮待刷新的弱引用。
        m_pending.clear();
        m_scheduled = false;
        for (const auto& binding : pending)
        {
            if (binding != nullptr)
            {
                binding->apply();
            }
        }
    }

    // bindingForWidget 仅从仍存活的直接子对象中确认缓存地址，避免手动删子对象后的悬空属性。
    WidgetThemeBinding* bindingForWidget(const QWidget* widget)
    {
        if (widget == nullptr)
        {
            return nullptr;
        }
        QObject* cached = widget->property(kBindingProperty).value<QObject*>(); // 只比较缓存地址。
        if (cached == nullptr)
        {
            return nullptr;
        }
        for (QObject* child : widget->children()) // child 由 GUI 线程中的现有 QObject 子树持有。
        {
            if (child == cached)
            {
                return dynamic_cast<WidgetThemeBinding*>(child);
            }
        }
        return nullptr;
    }
}

bool ks::ui::BindWidgetTheme(QWidget* widget, std::function<void()> refresh,
    ThemePalettePolicy palettePolicy)
{
    ThemeBindingRegistry* ownerRegistry = registry(); // 同时校验 QApplication 和 GUI 线程。
    if (ownerRegistry == nullptr || widget == nullptr || !refresh ||
        widget->thread() != QThread::currentThread())
    {
        return false;
    }
    // 只复用本组件写入、且仍由该控件持有的绑定；不会借用其他属性中的 QObject。
    auto* binding = bindingForWidget(widget); // 只使用现有直接子树中的存活绑定。
    if (binding != nullptr && binding->parent() == widget)
    {
        binding->replace(std::move(refresh), palettePolicy);
        ownerRegistry->schedule(binding);
    }
    else
    {
        binding = new WidgetThemeBinding(widget, ownerRegistry, std::move(refresh), palettePolicy);
        ownerRegistry->add(binding);
    }
    return true;
}

// 数值与单位由原生编辑器维护；主题绑定只修复可见文字与实际底色的对比度。
bool ks::ui::BindSpinBoxTheme(QAbstractSpinBox* spinBox)
{
    if (spinBox == nullptr)
    {
        return false;
    }
    const QPointer<QAbstractSpinBox> guardedSpin(spinBox);
    const bool outerBound = BindWidgetTheme(spinBox, [guardedSpin]()
    {
        if (guardedSpin.isNull())
        {
            return;
        }
        const QColor background = KswordTheme::ControlInputSurfaceColor(); // 与同排搜索/组合框共用输入面。
        const QColor hoverBackground = KswordTheme::ControlInputHoverColor(background);
        const QColor focusBackground = KswordTheme::ControlInputFocusColor(background);
        const QColor backgrounds[] = {background, hoverBackground, focusBackground};
        const QColor foreground = KswordTheme::EnsureTextContrastForBackgrounds(
            KswordTheme::TextPrimaryColor(), backgrounds, 3);
        const QColor disabledBackground = KswordTheme::SurfaceMutedColor();
        const QColor disabledForeground = KswordTheme::EnsureTextContrast(
            KswordTheme::TextDisabledColor(), disabledBackground, 3.0);
        const QString block = QString::fromLatin1(kSpinStyleBegin) + QStringLiteral(
            "QAbstractSpinBox{background-color:%1;color:%2;border:none;}"
            "QAbstractSpinBox:hover{background-color:%3;border:none;}"
            "QAbstractSpinBox:focus{background-color:%4;border:none;}"
            "QAbstractSpinBox:disabled{background-color:%5;color:%6;border:none;}")
            .arg(background.name(), foreground.name(), hoverBackground.name(), focusBackground.name(),
                disabledBackground.name(), disabledForeground.name())
            + QString::fromLatin1(kSpinStyleEnd);
        const QString style = replaceFieldStyle(guardedSpin->styleSheet(), block,
            kSpinStyleBegin, kSpinStyleEnd); // 保留页面自己设置的宽度、padding 与步进几何。
        if (guardedSpin->styleSheet() != style)
        {
            guardedSpin->setStyleSheet(style);
        }
    });

    // 内部 QLineEdit 单独登记，旧色值补偿不会再次覆盖已经明确拥有的前景规则。
    QLineEdit* editor = spinBox->findChild<QLineEdit*>(QStringLiteral("qt_spinbox_lineedit"));
    if (editor == nullptr)
    {
        return outerBound;
    }
    const QPointer<QLineEdit> guardedEditor(editor);
    const bool editorBound = BindWidgetTheme(editor, [guardedEditor]()
    {
        if (guardedEditor.isNull())
        {
            return;
        }
        const QColor background = KswordTheme::ControlInputSurfaceColor();
        const QColor backgrounds[] = {background, KswordTheme::ControlInputHoverColor(background),
            KswordTheme::ControlInputFocusColor(background)}; // 内部文字随外层三态底面校准。
        const QColor foreground = KswordTheme::EnsureTextContrastForBackgrounds(
            KswordTheme::TextPrimaryColor(), backgrounds, 3);
        const QColor disabledForeground = KswordTheme::EnsureTextContrast(
            KswordTheme::TextDisabledColor(), KswordTheme::SurfaceMutedColor(), 3.0);
        const QString block = QString::fromLatin1(kSpinStyleBegin) + QStringLiteral(
            "QLineEdit,QLineEdit:hover,QLineEdit:focus,QLineEdit:read-only{background:transparent;color:%1;border:none;"
            "selection-background-color:%2;selection-color:%3;}"
            "QLineEdit:disabled{background:transparent;color:%4;border:none;}")
            .arg(foreground.name(), KswordTheme::ControlAccentColor().name(),
                KswordTheme::OnAccentColor(KswordTheme::ControlAccentColor()).name(), disabledForeground.name())
            + QString::fromLatin1(kSpinStyleEnd);
        const QString style = replaceFieldStyle(guardedEditor->styleSheet(), block,
            kSpinStyleBegin, kSpinStyleEnd);
        if (guardedEditor->styleSheet() != style)
        {
            guardedEditor->setStyleSheet(style);
        }
    });
    return outerBound && editorBound;
}

bool ks::ui::BindSearchFieldTheme(QLineEdit* searchField)
{
    if (searchField == nullptr)
    {
        return false;
    }
    // 表格布局反复核验专用搜索框时不重复登记，已安装的绑定仍负责热主题刷新。
    if (searchField->property(kSearchFieldProperty).toBool() && HasWidgetThemeBinding(searchField))
    {
        return true;
    }
    const QPointer<QLineEdit> guardedField(searchField); // 排队刷新不会延长字段的寿命。
    const bool bound = BindWidgetTheme(searchField, [guardedField]()
    {
        if (guardedField.isNull())
        {
            return;
        }
        const QPalette parentColors = guardedField->parentWidget() != nullptr
            ? guardedField->parentWidget()->palette() : QApplication::palette();
        QColor pageSurface = parentColors.color(QPalette::Active, QPalette::Base);
        if (!pageSurface.isValid() || pageSurface.alpha() != 255)
        {
            // 透明背景中的零 alpha 黑并不代表实际黑底，不能直接把它改成不透明。
            pageSurface = KswordTheme::SurfaceColor();
        }
        QColor background = parentColors.color(QPalette::Active, QPalette::AlternateBase);
        if (!background.isValid() || background.alpha() != 255)
        {
            background = KswordTheme::SurfaceAltColor();
        }
        background = KswordTheme::ControlInputSurfaceColor(pageSurface, background);
        const QColor hoverBackground = KswordTheme::ControlInputHoverColor(background);
        const QColor focusBackground = KswordTheme::ControlInputFocusColor(background);
        const QColor backgrounds[] = {background, hoverBackground, focusBackground};
        // 占位提示常有半透明 alpha；先还原明确前景再校准，不能把透明黑当有效首选色。
        const auto opaqueForeground = [](QColor preferred, const QColor& fallback)
        {
            if (!preferred.isValid() || preferred.alpha() == 0)
            {
                preferred = fallback;
            }
            preferred.setAlpha(255);
            return preferred;
        };
        const QColor foreground = KswordTheme::EnsureTextContrastForBackgrounds(opaqueForeground(
            parentColors.color(QPalette::Active, QPalette::Text), KswordTheme::TextPrimaryColor()), backgrounds, 3);
        const QColor placeholder = KswordTheme::EnsureTextContrastForBackgrounds(opaqueForeground(
            parentColors.color(QPalette::Active, QPalette::PlaceholderText), KswordTheme::TextSecondaryColor()), backgrounds, 3);
        const QColor disabledForeground = KswordTheme::EnsureTextContrast(opaqueForeground(
            parentColors.color(QPalette::Disabled, QPalette::Text), KswordTheme::TextDisabledColor()), background, 3.0);
        const QColor disabledPlaceholder = KswordTheme::EnsureTextContrast(opaqueForeground(
            parentColors.color(QPalette::Disabled, QPalette::PlaceholderText), KswordTheme::TextSecondaryColor()), background, 3.0);

        // 搜索与普通输入共享柔和交互填充；保留页面几何与具体的 placeholder 文本。
        // 页面明确选择统一搜索几何后，局部主题重建也必须保留同一留白和圆角。
        const QString geometry = guardedField->property("ksword_page_search_style").toBool()
            ? QStringLiteral("QLineEdit[ksword_page_search_style=\"true\"]{padding:0px 10px;border-radius:5px;}") : QString();
        const QString block = QString::fromLatin1(kSearchStyleBegin) + geometry + QStringLiteral(
            "QLineEdit,QLineEdit:read-only{background-color:%1;color:%2;placeholder-text-color:%6;border:none;}"
            "QLineEdit:hover{background-color:%4;border:none;}"
            "QLineEdit:focus{background-color:%5;border:none;}"
            "QLineEdit:disabled{background-color:%1;color:%3;placeholder-text-color:%7;border:none;}")
            .arg(background.name(), foreground.name(), disabledForeground.name(),
                hoverBackground.name(), focusBackground.name(), placeholder.name(), disabledPlaceholder.name())
            + QString::fromLatin1(kSearchStyleEnd);
        const QString style = replaceFieldStyle(guardedField->styleSheet(), block,
            kSearchStyleBegin, kSearchStyleEnd);
        if (guardedField->styleSheet() != style)
        {
            guardedField->setStyleSheet(style);
        }
        if (guardedField.isNull())
        {
            return;
        }
        // PlaceholderText 由 QLineEdit 实际绘制读取，不依赖父级 color 或半透明默认色。
        QPalette fieldColors = guardedField->palette(); // 只改本字段自己的可读颜色角色。
        for (const QPalette::ColorGroup group : {QPalette::Active, QPalette::Inactive, QPalette::Disabled})
        {
            const bool disabled = group == QPalette::Disabled;
            fieldColors.setColor(group, QPalette::Base, background);
            fieldColors.setColor(group, QPalette::Text, disabled ? disabledForeground : foreground);
            fieldColors.setColor(group, QPalette::PlaceholderText,
                disabled ? disabledPlaceholder : placeholder);
        }
        if (guardedField->palette() != fieldColors)
        {
            guardedField->setPalette(fieldColors);
        }
    });
    if (bound && !guardedField.isNull())
    {
        guardedField->setProperty(kSearchFieldProperty, true);
    }
    return bound;
}

bool ks::ui::HasWidgetThemeBinding(const QWidget* widget)
{
    // 判定只在 GUI 线程的旧样式兼容路径调用；未登记子控件仍允许原补偿机制处理。
    return bindingForWidget(widget) != nullptr;
}

void ks::ui::RefreshWidgetThemeBindings()
{
    if (ThemeBindingRegistry* ownerRegistry = registry())
    {
        ownerRegistry->scheduleAll();
    }
}
