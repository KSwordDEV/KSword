#include "./DetailPresentation.h"
#include "./DetailDialogChrome.h"
#include "./DetailLayoutRegistry.h"
#include "./StructuredFieldView.h"
#include "./PrimaryPageStyle.h"
#include "./PageControlStyle.h"
#include "./ToolbarMetrics.h"
#include "./ThemeBinding.h"
#include "../theme.h"
#include <QAbstractScrollArea>
#include <QAbstractButton>
#include <QAbstractSpinBox>
#include <QBoxLayout>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHash>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QSet>
#include <QSplitter>
#include <QStackedWidget>
#include <QTabBar>
#include <QTimer>
#include <algorithm>
#include <utility>

namespace
{
    // 使用占位保留原布局位置；构造共享宿主会重新挂父对象，不能依赖旧layout项继续存在。
    template<class Factory>
    bool replaceDetailWidget(QWidget* original, Factory create)
    {
        QWidget* parent = original ? original->parentWidget() : nullptr;
        // 惰性构造的子控件也可能暂时隐藏；只继承业务显式 hide，不能让新宿主永久不可见。
        const bool explicitlyHidden = original && original->isHidden()
            && original->testAttribute(Qt::WA_WState_ExplicitShowHide);
        if (auto* splitter = qobject_cast<QSplitter*>(parent))
        {
            const int index = splitter->indexOf(original);
            if (index < 0)
            {
                return false;
            }
            const QList<int> sizes = splitter->sizes();
            auto* placeholder = new QWidget();
            splitter->replaceWidget(index, placeholder);
            original->setParent(nullptr);
            // 暂不挂到Splitter，避免构造过程被其ChildAdded自动插到末尾。
            QWidget* replacement = create(nullptr);
            splitter->replaceWidget(index, replacement);
            replacement->setVisible(!explicitlyHidden);
            delete placeholder;
            if (std::any_of(sizes.cbegin(), sizes.cend(), [](int size) { return size > 0; }))
            {
                splitter->setSizes(sizes); // 隐藏页首次布局前的全零尺寸不能当成用户的折叠比例。
            }
            return true;
        }
        QLayout* layout = parent ? parent->layout() : nullptr;
        if (!layout)
        {
            return false;
        }
        auto* placeholder = new QWidget(parent);
        QLayoutItem* replaced = layout->replaceWidget(original, placeholder);
        if (!replaced)
        {
            delete placeholder;
            return false;
        }
        delete replaced;
        QWidget* replacement = create(parent);
        delete layout->replaceWidget(placeholder, replacement);
        replacement->setVisible(!explicitlyHidden);
        delete placeholder;
        return true;
    }

    bool insideDetailScroll(QWidget* widget, QWidget* root)
    {
        for (QWidget* parent = widget->parentWidget(); parent && parent != root; parent = parent->parentWidget())
        {
            if (qobject_cast<QScrollArea*>(parent))
            {
                return true;
            }
        }
        return false;
    }

    class DetailWindowFramework final : public QObject
    {
    public:
        explicit DetailWindowFramework(QWidget* window) : QObject(window), m_window(window)
        {
            window->installEventFilter(this);
        }
        // 构造结束后的Show是唯一全窗安装点，首帧前完成重挂，避免先显示旧布局再闪到新布局。
        void prepareForShow()
        {
            if (!m_window || !m_window->layout() || m_applying)
            {
                return;
            }
            if (!m_prepared)
            {
                m_dirtyScopes = {m_window};
                m_styleDirty = true;
            }
            apply();
        }
        void schedule()
        {
            // Polish或构造尾部登记时尚未出现安全的Show，不能在半构造布局上安装框架。
            if (!m_prepared || m_pending || m_applying || !m_window || !m_window->isVisible())
            {
                return;
            }
            m_pending = true;
            QTimer::singleShot(0, this, [this]()
            {
                m_pending = false;
                if (m_window && m_window->isVisible())
                {
                    apply(); // 排队期间已隐藏时保留dirty，Show再整理，不重抛隐藏根QSS。
                }
            });
        }
    protected:
        bool eventFilter(QObject* object, QEvent* event) override
        {
            if (m_applying)
            {
                return QObject::eventFilter(object, event);
            }
            if (object == m_window && event->type() == QEvent::Show)
            {
                prepareForShow();
            }
            else if (event->type() == QEvent::ChildAdded || event->type() == QEvent::ChildRemoved
                || event->type() == QEvent::ParentChange)
            {
                // 只监听页面/布局宿主。惰性页构造结束后整理这个子树，不因字段刷新遍历整窗。
                auto* scope = qobject_cast<QWidget*>(object);
                if (scope && qobject_cast<QScrollArea*>(scope->parentWidget()))
                {
                    scope = scope->parentWidget(); // QScrollArea通过viewport接入新的正文。
                }
                markStructureDirty(scope);
            }
            else if (object == m_window && (event->type() == QEvent::StyleChange
                || event->type() == QEvent::PaletteChange || event->type() == QEvent::FontChange
                || event->type() == QEvent::ApplicationFontChange))
            {
                m_styleDirty = true;
                schedule();
            }
            return QObject::eventFilter(object, event);
        }
    private:
        using WidgetList = QVector<QPointer<QWidget>>;

        bool keepsOwnLayout(QWidget* widget) const
        {
            for (auto* parent = widget; parent; parent = parent->parentWidget())
            {
                // 参数骨架只保留布局，普通控件仍接标准主题；专业保护标记继续保留原含义。
                if (parent->property("ksword_detail_keep_layout").toBool()
                    || parent->property("ksword_secondary_keep_layout").toBool()
                    || parent->property("ksword_parameter_workspace").toBool())
                {
                    return true;
                }
                if (parent == m_window)
                {
                    break;
                }
            }
            return false;
        }
        // 判断结构宿主是否属于当前可见页；未打开的Tab不在弹窗首帧提前迁移/建投影。
        bool isCurrentPageScope(QWidget* scope) const
        {
            QWidget* page = scope;
            for (QWidget* parent = scope ? scope->parentWidget() : nullptr;
                parent && page != m_window; page = parent, parent = parent->parentWidget())
            {
                auto* stack = qobject_cast<QStackedWidget*>(parent);
                if (stack && stack->currentWidget() != page)
                {
                    return false;
                }
            }
            return true;
        }
        // 专业编辑器、文档投影和叶控件内部不属于详情布局框架的结构观察范围。
        void collectWidgets(QWidget* scope, WidgetList& widgets) const
        {
            if (!scope || (scope != m_window && scope->window() != m_window) || keepsOwnLayout(scope)
                || scope->property("ksword_detail_projection_source").toBool()
                || scope->property("ksword_detail_projection").toBool())
            {
                return;
            }
            widgets.append(scope);
            if (qobject_cast<ks::ui::StructuredFieldView*>(scope)
                || qobject_cast<QAbstractButton*>(scope) || qobject_cast<QAbstractSpinBox*>(scope)
                || qobject_cast<QComboBox*>(scope) || qobject_cast<QLineEdit*>(scope)
                || qobject_cast<QLabel*>(scope) || qobject_cast<QTabBar*>(scope))
            {
                return;
            }
            if (auto* scroll = qobject_cast<QAbstractScrollArea*>(scope))
            {
                if (auto* area = qobject_cast<QScrollArea*>(scroll))
                {
                    collectWidgets(area->widget(), widgets);
                }
                return; // 不扫描表/树/代码编辑器的viewport及内部滚动条。
            }
            if (auto* stack = qobject_cast<QStackedWidget*>(scope))
            {
                collectWidgets(stack->currentWidget(), widgets);
                return; // 其余页面在currentChanged安全点准备，不把全部Tab的代价压到首Show。
            }
            const auto children = scope->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly);
            for (auto* child : children)
            {
                collectWidgets(child, widgets);
            }
        }
        void observe(QWidget* widget)
        {
            if (!widget || m_observed.contains(widget))
            {
                return;
            }
            m_observed.insert(widget);
            widget->installEventFilter(this);
            connect(widget, &QObject::destroyed, this, [this, widget]() { m_observed.remove(widget); });
            if (auto* stack = qobject_cast<QStackedWidget*>(widget))
            {
                // currentChanged发生在页身份与Qt父子关系稳定后；同步处理保证新页首帧已是新布局。
                const QPointer<QStackedWidget> safeStack(stack);
                connect(stack, &QStackedWidget::currentChanged, this, [this, safeStack](int)
                {
                    if (!safeStack || !m_prepared || m_applying)
                    {
                        return;
                    }
                    QWidget* page = safeStack->currentWidget();
                    if (page && !m_preparedPages.value(page, false))
                    {
                        markStructureDirty(page); // 首次激活仍在首绘前处理；热切只消费真实结构dirty。
                    }
                    if (m_window && m_window->isVisible())
                    {
                        apply(); // 窗口隐藏时只留dirty，重开Show再处理，避免后台程序化切页消耗UI时间。
                    }
                });
            }
        }
        void rememberPreparedPage(QWidget* page)
        {
            if (!page)
            {
                return;
            }
            if (!m_preparedPages.contains(page))
            {
                connect(page, &QObject::destroyed, this, [this, page]() { m_preparedPages.remove(page); });
            }
            m_preparedPages.insert(page, true);
        }
        void observeContainers(const WidgetList& widgets)
        {
            for (const auto& pointer : widgets)
            {
                QWidget* widget = pointer.data();
                if (!widget || qobject_cast<ks::ui::StructuredFieldView*>(widget)
                    || qobject_cast<QAbstractButton*>(widget) || qobject_cast<QAbstractSpinBox*>(widget)
                    || qobject_cast<QComboBox*>(widget) || qobject_cast<QLineEdit*>(widget)
                    || qobject_cast<QLabel*>(widget) || qobject_cast<QTabBar*>(widget))
                {
                    continue;
                }
                if (auto* scroll = qobject_cast<QAbstractScrollArea*>(widget))
                {
                    if (auto* area = qobject_cast<QScrollArea*>(scroll))
                    {
                        observe(area);
                        observe(area->viewport());
                    }
                    continue;
                }
                // 包含尚无layout的惰性QWidget页面，不监听普通叶控件的Show/FontChange。
                if (widget->layout() || qobject_cast<QSplitter*>(widget)
                    || qobject_cast<QStackedWidget*>(widget)
                    || qstrcmp(widget->metaObject()->className(), "QWidget") == 0)
                {
                    observe(widget);
                }
            }
        }
        void markStructureDirty(QWidget* scope)
        {
            if (!scope || (scope != m_window && scope->window() != m_window) || keepsOwnLayout(scope))
            {
                return;
            }
            for (auto page = m_preparedPages.begin(); page != m_preparedPages.end(); ++page)
            {
                if (page.key() == scope || scope->isAncestorOf(page.key()) || page.key()->isAncestorOf(scope))
                {
                    page.value() = false; // 宽scope只收集当前分支；隐藏页不能因dirty合并而丢掉失效。
                }
            }
            for (const auto& pointer : m_dirtyScopes)
            {
                if (pointer && (pointer == scope || pointer->isAncestorOf(scope)))
                {
                    return;
                }
            }
            m_dirtyScopes.erase(std::remove_if(m_dirtyScopes.begin(), m_dirtyScopes.end(),
                [scope](const QPointer<QWidget>& item) { return !item || scope->isAncestorOf(item); }),
                m_dirtyScopes.end());
            m_dirtyScopes.append(scope);
            schedule();
        }
        void adoptRoot()
        {
            QLayout* original = m_window->layout();
            if (!original || m_window->property("ksword_detail_framework_root").toBool())
            {
                return;
            }
            m_window->setProperty("ksword_detail_framework_root", true);
            const auto headers = m_window->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly);
            for (auto* widget : headers)
            {
                if (widget->property("ksword_detail_header").toBool())
                {
                    return; // 原窗口已提供真实对象身份，保留其原业务摘要和动作。
                }
            }
            // 现有布局整体转交正文宿主；复用原布局和控件，不重写业务页面。
            auto* body = new QWidget(m_window);
            body->setProperty("ksword_detail_framework_body", true);
            body->setMinimumSize(0, 0);
            body->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
            body->setLayout(original);
            original->setContentsMargins(20, 16, 20, 16);
            if (auto* box = qobject_cast<QBoxLayout*>(original))
            {
                box->setSpacing(12);
            }
            auto* root = new QVBoxLayout(m_window);
            root->setContentsMargins(0, 0, 0, 0);
            root->setSpacing(0);
            auto* summary = ks::ui::CreateDetailSummaryHeader(m_window, m_window->windowTitle(),
                QString(), m_window->windowIcon());
            root->addWidget(summary);
            if (auto* title = summary->findChild<QLabel*>(QLatin1String("ksword_detail_summary_title")))
            {
                connect(m_window, &QWidget::windowTitleChanged, title, &QLabel::setText);
            }
            root->addWidget(body, 1);
            // 对话框按钮盒保留原角色和信号，放到固定底部，正文滚动时始终可达。
            const auto footers = body->findChildren<QDialogButtonBox*>(QString(), Qt::FindDirectChildrenOnly);
            for (auto* footer : footers)
            {
                original->removeWidget(footer);
                footer->setContentsMargins(20, 10, 20, 10);
                root->addWidget(footer);
            }
        }
        bool prepareTabs(const WidgetList& widgets)
        {
            bool replaced = false; // 只有真实换宿主才重新收集一次已改变的页面结构。
            for (const auto& pointer : widgets)
            {
                auto* tabs = qobject_cast<QTabWidget*>(pointer.data());
                if (!tabs || tabs->property("ksword_detail_tabs").toBool()
                    || tabs->property("ksword_detail_nested_tabs").toBool())
                {
                    continue;
                }
                bool nested = false;
                for (QWidget* parent = tabs->parentWidget(); parent && parent != m_window; parent = parent->parentWidget())
                {
                    if (qobject_cast<QTabWidget*>(parent))
                    {
                        nested = true;
                        break;
                    }
                }
                if (!nested)
                {
                    replaced |= replaceDetailWidget(tabs, [tabs](QWidget* parent)
                    {
                        return ks::ui::CreateDetailTabShell(tabs, parent);
                    });
                }
                else
                {
                    tabs->setProperty("ksword_detail_nested_tabs", true);
                    tabs->setMinimumSize(0, 0);
                    tabs->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
                    ks::ui::StylePageTabs(tabs); // 保留内部Tab身份并复用同一导航动画和主题。
                }
            }
            return replaced;
        }
        bool prepareFields(const WidgetList& widgets)
        {
            bool replaced = false; // 文档源尚未投影时才重新收集新宿主与布局。
            for (const auto& pointer : widgets)
            {
                auto* source = qobject_cast<ks::ui::StructuredFieldView*>(pointer.data());
                if (!source || source->property("ksword_detail_projection_source").toBool())
                {
                    continue;
                }
                const bool scrollBody = !insideDetailScroll(source, m_window);
                // 已登记详情布局的字段源也是稳定面板身份，不能重挂后让宿主继续操纵旧面板。
                const bool managedDetailPane = ks::ui::DetailLayoutRegistry::hostFor(source) != nullptr;
                if (qobject_cast<QStackedWidget*>(source->parentWidget()) || managedDetailPane)
                {
                    // Tab/Stack页和受管详情面板只替换内部布局，保留索引、父子契约和业务显隐引用。
                    source->setDocumentOnly();
                    delete source->layout(); // Qt只删除布局项；原搜索和报告动作仍由source拥有。
                    source->setMinimumSize(0, 0);
                    source->setSizePolicy(QSizePolicy::Ignored,
                        scrollBody ? QSizePolicy::Ignored : QSizePolicy::Preferred);
                    auto* body = new QVBoxLayout(source);
                    body->setContentsMargins(0, 0, 0, 0);
                    body->setSpacing(0);
                    body->addWidget(ks::ui::CreateDetailFieldProjection(source, source, scrollBody));
                    replaced = true;
                    continue;
                }
                replaced |= replaceDetailWidget(source, [source, scrollBody](QWidget* parent)
                {
                    return ks::ui::CreateDetailFieldProjection(source, parent, scrollBody);
                });
            }
            return replaced;
        }
        void prepareForm(QFormLayout* form)
        {
            if (form->property("ksword_detail_framework_form").toBool())
            {
                return;
            }
            form->setProperty("ksword_detail_framework_form", true);
            ks::ui::ConfigureDetailForm(form);
            for (int index = 0; index < form->rowCount(); ++index)
            {
                auto* labelItem = form->itemAt(index, QFormLayout::LabelRole);
                if (auto* label = labelItem ? qobject_cast<QLabel*>(labelItem->widget()) : nullptr)
                {
                    label->setMinimumWidth(0);
                    label->setWordWrap(true);
                }
                auto* fieldItem = form->itemAt(index, QFormLayout::FieldRole);
                if (auto* widget = fieldItem ? fieldItem->widget() : nullptr)
                {
                    ks::ui::StyleStandaloneInput(widget);
                }
            }
        }
        void prepareForms(const WidgetList& widgets)
        {
            for (const auto& pointer : widgets)
            {
                QLayout* layout = pointer ? pointer->layout() : nullptr;
                if (!layout)
                {
                    continue;
                }
                if (auto* form = qobject_cast<QFormLayout*>(layout))
                {
                    prepareForm(form);
                }
                // 布局对象只包含子布局，专业Widget子树已在collectWidgets中排除。
                for (auto* form : layout->findChildren<QFormLayout*>())
                {
                    prepareForm(form);
                }
            }
        }
        void prepareScrollAreas(const WidgetList& widgets)
        {
            for (const auto& pointer : widgets)
            {
                auto* scroll = qobject_cast<QScrollArea*>(pointer.data());
                if (!scroll || scroll->property("ksword_detail_sidebar").toBool() || !scroll->widget())
                {
                    continue;
                }
                if (!scroll->property("ksword_detail_scroll_prepared").toBool())
                {
                    scroll->setProperty("ksword_detail_scroll_prepared", true);
                    scroll->setFrameShape(QFrame::NoFrame);
                    scroll->setWidgetResizable(true);
                    scroll->setMinimumSize(0, 0);
                    scroll->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
                }
                auto* body = scroll->widget();
                body->setMinimumWidth(0);
                QSizePolicy policy(QSizePolicy::Ignored, QSizePolicy::Preferred);
                Qt::ScrollBarPolicy vertical = Qt::ScrollBarAsNeeded;
                // 只处理单正文视图的重复滚动壳，参数+多个独立数据视图保留业务滚动边界。
                QLayout* layout = scroll->widget()->layout();
                if (layout && layout->count() == 1)
                {
                    QWidget* content = layout->itemAt(0)->widget();
                    const bool projection = content && content->property("ksword_detail_projection").toBool();
                    if (qobject_cast<QAbstractScrollArea*>(content)
                        || (projection && content->property("ksword_detail_projection_scroll").toBool()))
                    {
                        scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
                        vertical = Qt::ScrollBarAlwaysOff;
                        policy = QSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
                        content->setMinimumSize(0, 0);
                        content->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
                    }
                    else if (projection)
                    {
                        content->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
                    }
                }
                if (body->sizePolicy() != policy)
                {
                    body->setSizePolicy(policy);
                }
                if (scroll->verticalScrollBarPolicy() != vertical)
                {
                    scroll->setVerticalScrollBarPolicy(vertical);
                }
            }
        }
        void applyStyle()
        {
            // 根窗口仍可刷新业务主题；共享外框只维护自己的末尾块，避免旧QSS覆盖卡片间底色。
            // 自有主题根（进程详情）已生成同一套Chrome，不能追加后再被业务StyleChange删除。
            if (m_window->property("ksword_global_dialog_theme").toBool()
                || m_window->property("ksword_detail_theme_owner").toBool()
                || m_window->property("ksword_secondary_window").toBool())
            {
                return; // Explicit secondary roots already have one theme/QSS owner.
            }
            const QString begin = QStringLiteral("/* KSWORD_DETAIL_FRAMEWORK_BEGIN */");
            const QString end = QStringLiteral("/* KSWORD_DETAIL_FRAMEWORK_END */");
            QString style = m_window->styleSheet();
            const qsizetype first = style.indexOf(begin);
            const qsizetype last = first < 0 ? -1 : style.indexOf(end, first);
            if (first >= 0 && last >= first)
            {
                style.remove(first, last + end.size() - first);
            }
            style = style.trimmed() + QLatin1Char('\n') + begin
                + ks::ui::BuildDetailDialogChromeStyle(m_window->objectName()) + end;
            // 普通QDialog根QSS由GlobalDialogTheme唯一持有，不能与它轮流移除/追加样式块。
            if (m_window->styleSheet() != style)
            {
                m_window->setStyleSheet(style);
            }
        }
        void apply()
        {
            if (!m_window || !m_window->layout() || m_applying || keepsOwnLayout(m_window)
                || (m_prepared && m_dirtyScopes.isEmpty() && !m_styleDirty))
            {
                return;
            }
            m_applying = true;
            if (!m_prepared)
            {
                // 全部接入窗口沿用用户字体和更大的字号，统一补齐未登记弹窗的字号下限。
                QFont font = m_window->font();
                if (font.pixelSize() > 0 && font.pixelSize() < 14)
                {
                    font.setPixelSize(14);
                }
                else if (font.pixelSize() <= 0 && font.pointSizeF() < 10.0)
                {
                    font.setPointSizeF(10.0);
                }
                if (font != m_window->font())
                {
                    m_window->setFont(font);
                }
                adoptRoot();
                m_window->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
                m_window->setMinimumSize(qMin(m_window->minimumWidth(), 640), qMin(m_window->minimumHeight(), 440));
                m_prepared = true;
            }
            const WidgetList scopes = std::exchange(m_dirtyScopes, {});
            for (const auto& scope : scopes)
            {
                if (!scope || (scope != m_window && !m_window->isAncestorOf(scope)))
                {
                    continue;
                }
                if (!m_window->isVisible() || !isCurrentPageScope(scope))
                {
                    m_dirtyScopes.append(scope); // 隐藏页保留最新结构请求，切到该页后再一次性处理。
                    continue;
                }
                WidgetList widgets;
                collectWidgets(scope, widgets);
                if (prepareTabs(widgets))
                {
                    widgets.clear(); // 首次导航接入可能同步创建当前惰性页，字段取其构造后的快照。
                    collectWidgets(scope, widgets);
                }
                if (prepareFields(widgets))
                {
                    widgets.clear(); // 源视图的旧控件已销毁，观察新宿主而不是保存失效控件。
                    collectWidgets(scope, widgets);
                }
                prepareForms(widgets);
                prepareScrollAreas(widgets);
                observeContainers(widgets);
                if (scope && qobject_cast<QStackedWidget*>(scope->parentWidget()))
                {
                    rememberPreparedPage(scope);
                }
                for (const auto& widget : widgets)
                {
                    if (auto* stack = qobject_cast<QStackedWidget*>(widget.data()))
                    {
                        rememberPreparedPage(stack->currentWidget());
                    }
                }
            }
            if (m_styleDirty)
            {
                m_styleDirty = false;
                applyStyle(); // 字号和主题变化不再重新遍历、重挂页面结构。
            }
            m_applying = false;
        }
        QPointer<QWidget> m_window; // 原窗口保留身份、模态关系和业务关闭语义。
        QSet<QWidget*> m_observed; // 只观察布局宿主，字段/表格的普通事件不触发结构遍历。
        WidgetList m_dirtyScopes; // 惰性构造按最小宿主子树合并，销毁后自动失效。
        QHash<QWidget*, bool> m_preparedPages; // 每个Stack页的结构完成状态；失效后仍保留唯一销毁连接。
        bool m_prepared = false; // 首帧前安装一次，重开不重挂原业务布局。
        bool m_styleDirty = false; // 主题刷新与结构更新分开。
        bool m_pending = false;
        bool m_applying = false; // 防止重挂父对象期间重复整理同一布局。
    };
}

void ks::ui::InstallDetailWindowFramework(QWidget* window)
{
    if (!window || !window->isWindow() || window->property("ksword_detail_keep_layout").toBool()
        || window->property("ksword_secondary_keep_layout").toBool())
    {
        return;
    }
    const auto controller = window->property("ksword_detail_framework_controller").value<QObject*>();
    if (controller)
    {
        static_cast<DetailWindowFramework*>(controller)->schedule();
        return;
    }
    window->setProperty("ksword_detail_shell", true);
    auto* framework = new DetailWindowFramework(window);
    window->setProperty("ksword_detail_framework_controller", QVariant::fromValue<QObject*>(framework));
}

void ks::ui::PrepareDetailWindowForShow(QWidget* window)
{
    if (!window || window->property("ksword_detail_keep_layout").toBool()
        || window->property("ksword_secondary_keep_layout").toBool())
    {
        return;
    }
    InstallDetailWindowFramework(window);
    if (const auto controller = window->property("ksword_detail_framework_controller").value<QObject*>())
    {
        static_cast<DetailWindowFramework*>(controller)->prepareForShow();
    }
}
