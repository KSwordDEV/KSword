#include "GlobalRefreshShortcut.h"
#include "ShortcutRegistry.h"
#include <QKeySequenceEdit>

#include <QAbstractButton>
#include <QApplication>
#include <QEvent>
#include <QKeyEvent>
#include <QPointer>
#include <QSet>
#include <QVector>
#include <QString>
#include <QWidget>

namespace
{
    // looksLikeRefreshButton 作用：
    // - 判断一个按钮是否是“刷新”按钮；
    // - 项目里刷新按钮多为纯图标按钮，可靠线索依次是
    //   objectName、按钮文字、tooltip；三者任一命中即可。
    bool looksLikeRefreshButton(const QAbstractButton* button)
    {
        if (button == nullptr)
        {
            return false;
        }
        if (button->objectName().contains(QStringLiteral("refresh"), Qt::CaseInsensitive))
        {
            return true;
        }
        // 只认前缀，避免把“刷新时校验签名”这类勾选项或说明性文案误当成刷新按钮。
        if (button->text().trimmed().startsWith(QStringLiteral("刷新")))
        {
            return true;
        }
        return button->toolTip().trimmed().startsWith(QStringLiteral("刷新"));
    }

    // findRefreshButtonNear 作用：
    // - 从焦点控件开始逐级向上查找，命中最近一层祖先里的刷新按钮；
    // - 就近查找保证多页共存时触发的是当前页而不是别的页。
    // 返回：可点击的刷新按钮；找不到返回 nullptr。
    QAbstractButton* findRefreshButtonNear(QWidget* startWidget)
    {
        // 每个 QObject 在一次 F5 中最多检查一次；隐藏页和其它窗口是明确边界。
        QSet<QObject*> visited;
        for (QWidget* scope = startWidget; scope != nullptr; scope = scope->parentWidget())
        {
            QVector<QObject*> pending;
            const auto appendChildren = [&pending](QObject* object)
            {
                const auto& children = object->children();
                for (auto child = children.crbegin(); child != children.crend(); ++child)
                {
                    pending.append(*child); // 与 findChildren 相同的前序、对象顺序。
                }
            };
            appendChildren(scope);
            while (!pending.isEmpty())
            {
                QObject* object = pending.takeLast();
                if (visited.contains(object))
                {
                    continue;
                }
                visited.insert(object);
                if (auto* widget = qobject_cast<QWidget*>(object);
                    widget != nullptr && (widget->isWindow() || !widget->isVisible() || !widget->isEnabled()))
                {
                    continue;
                }
                if (auto* button = qobject_cast<QAbstractButton*>(object);
                    button != nullptr && looksLikeRefreshButton(button))
                {
                    return button; // 无需先构建该作用域全部按钮列表。
                }
                appendChildren(object);
            }
            if (scope->isWindow())
            {
                break;
            }
        }
        return nullptr;
    }

    // GlobalRefreshShortcutFilter 作用：
    // - QApplication 级事件过滤器；
    // - 捕获不带修饰键的 F5，并转发给当前页面的刷新按钮。
    class GlobalRefreshShortcutFilter final : public QObject
    {
    public:
        explicit GlobalRefreshShortcutFilter(QObject* parentObject)
            : QObject(parentObject)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject == nullptr || eventObject->type() != QEvent::KeyPress)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
            // 只处理裸 F5；带 Ctrl/Shift/Alt 的组合留给各页面自行使用。
            if (!ks::ui::ShortcutRegistry::instance().matches(QStringLiteral("app.refresh"), keyEvent))
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QWidget* startWidget = QApplication::focusWidget();
            for (QWidget* widget = startWidget; widget; widget = widget->parentWidget())
                if (qobject_cast<QKeySequenceEdit*>(widget)) return false;
            if (startWidget == nullptr)
            {
                startWidget = QApplication::activeWindow();
            }
            QAbstractButton* refreshButton = findRefreshButtonNear(startWidget);
            if (refreshButton == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            refreshButton->click();
            return true;
        }
    };

    // globalRefreshShortcutFilterInstance 作用：
    // - 返回过滤器单例，父对象绑定 QApplication，无需手动释放。
    GlobalRefreshShortcutFilter* globalRefreshShortcutFilterInstance()
    {
        static QPointer<GlobalRefreshShortcutFilter> filterInstance;
        if (filterInstance == nullptr && qApp != nullptr)
        {
            filterInstance = new GlobalRefreshShortcutFilter(qApp);
        }
        return filterInstance.data();
    }
}

namespace ks::ui
{
    void InstallGlobalRefreshShortcut(QApplication* appInstance)
    {
        if (appInstance == nullptr)
        {
            return;
        }
        InstallCommonShortcutCatalog();
        auto& registry = ShortcutRegistry::instance();
        registry.define({QStringLiteral("app.refresh"), QStringLiteral("刷新当前页面"), QStringLiteral("application"), {}, QKeySequence(Qt::Key_F5), {}});
        registry.attach(QStringLiteral("app.refresh"), appInstance, [](const QKeySequence&, QString*) { return true; });
        GlobalRefreshShortcutFilter* filterInstance = globalRefreshShortcutFilterInstance();
        if (filterInstance == nullptr)
        {
            return;
        }
        appInstance->installEventFilter(filterInstance);
    }
}
