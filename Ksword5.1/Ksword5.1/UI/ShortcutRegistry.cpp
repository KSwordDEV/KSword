#include "ShortcutRegistry.h"
#include "MemoryWorkbench/WorkbenchActions.h"
#include "../Framework/BackgroundTaskRegistry.h"
#include "../Internationalization/LanguageManager.h"

#include <QAction>
#include <QCoreApplication>
#include <QKeyEvent>
#include <QSettings>
#include <QScopedValueRollback>
#include <QShortcut>
#include <QEvent>
#include <algorithm>

namespace ks::ui
{
    namespace
    {
        ShortcutRegistry::Setter shortcutSetter(QShortcut* shortcut)
        {
            const auto originalKeys = shortcut->keys();
            const QKeySequence originalPrimary = shortcut->key();
            return [shortcut, originalKeys, originalPrimary](const QKeySequence& keys, QString*) {
                // Platform standard keys may have alternatives (for example Ctrl+Insert).
                // A default binding preserves them; a custom/empty binding is explicit.
                if (keys == originalPrimary) shortcut->setKeys(originalKeys);
                else shortcut->setKey(keys);
                return true;
            };
        }
    }
    void InstallCommonShortcutCatalog()
    {
        auto& registry = ShortcutRegistry::instance();
        static QPointer<ShortcutRegistry> installed;
        if (installed == &registry) return;
        installed = &registry;
        struct Spec { const char* id; const char* title; const char* context; const char* keys; };
        static const Spec specs[] = {
            {"editor.find", "查找文本", "editor", "Ctrl+F"},
            {"editor.replace", "替换文本", "editor", "Ctrl+H"},
            {"editor.goto", "跳转到行", "editor", "Ctrl+G"},
            {"editor.next", "下一个匹配", "editor", "F3"},
            {"editor.previous", "上一个匹配", "editor", "Shift+F3"},
            {"editor.save", "保存文本", "editor", "Ctrl+S"},
            {"editor.open", "打开文本", "editor", "Ctrl+O"},
            {"editor.new", "新建文本", "editor", "Ctrl+N"},
            {"editor.save_as", "文本另存为", "editor", "Ctrl+Shift+S"},
            {"editor.copy", "复制文本", "editor", "Ctrl+C"},
            {"file.path", "编辑文件路径", "file", "Alt+D"},
            {"file.open", "打开文件", "file", "Return"},
            {"file.rename", "重命名文件", "file", "F2"},
            {"file.delete", "删除文件", "file", "Del"},
            {"file.copy", "复制文件", "file", "Ctrl+C"},
            {"registry.path", "编辑注册表路径", "registry", "Ctrl+L"},
            {"registry.rename", "重命名注册表对象", "registry", "F2"},
            {"registry.refresh", "刷新注册表", "registry", "F5"},
            {"registry.new_tab", "新建注册表位置页", "registry", "Ctrl+T"},
            {"registry.apply", "应用注册表修改", "registry", "Ctrl+S"},
            {"process.terminate", "结束选中进程", "process", "Alt+E"},
            {"debug.step", "内存调试单步", "debug", "F7"},
            {"debug.continue", "内存调试继续", "debug", "F9"},
            {"debug.pause", "内存调试暂停", "debug", "F12"}
        };
        for (const Spec& spec : specs)
            registry.define({QString::fromLatin1(spec.id), QString::fromUtf8(spec.title), QString::fromLatin1(spec.context),
                {}, QKeySequence::fromString(QString::fromLatin1(spec.keys), QKeySequence::PortableText), {}});
        registry.define({QStringLiteral("file.open_keypad"), QStringLiteral("打开文件（小键盘 Enter）"), QStringLiteral("file"),
            {}, QKeySequence(Qt::Key_Enter), {}});
        RegisterWorkbenchShortcutCatalog();
    }

    ShortcutRegistry& ShortcutRegistry::instance()
    {
        static QPointer<ShortcutRegistry> registry;
        if (!registry) registry = new ShortcutRegistry(QCoreApplication::instance());
        return *registry;
    }

    ShortcutRegistry::ShortcutRegistry(QObject* parent, QString settingsPath)
        : QObject(parent), m_settingsPath(settingsPath.isEmpty()
            ? BackgroundTaskRegistry::defaultSettingsPath() : std::move(settingsPath))
    {
    }

    bool ShortcutRegistry::define(Command command)
    {
        if (command.id.isEmpty() || command.title.isEmpty() || command.context.isEmpty()) return false;
        auto existing = m_entries.constFind(command.id);
        if (existing != m_entries.cend())
            return existing->command.context == command.context && existing->command.defaults == command.defaults;
        command.binding = command.defaults;
        QSettings settings(m_settingsPath, QSettings::IniFormat);
        const QString key = QStringLiteral("shortcuts/") + command.id;
        if (command.editable && settings.contains(key))
        {
            const QString saved = settings.value(key).toString();
            const QKeySequence keys = QKeySequence::fromString(saved, QKeySequence::PortableText);
            if ((saved.isEmpty() || !keys.isEmpty()) && (command.sequence || keys.count() <= 1))
                command.binding = keys;
        }
        const QString id = command.id;
        m_entries.insert(id, {std::move(command), {}});
        auto& installed = m_entries[id].command;
        if (installed.binding != installed.defaults && !conflicts(id, installed.binding).isEmpty())
        {
            installed.binding = {};
            installed.restriction = i18n::sourceText(QStringLiteral("已保存的绑定存在冲突，当前未启用；请重新设置。"));
        }
        ++m_revision;
        return true;
    }

    bool ShortcutRegistry::attach(const QString& id, QObject* owner, Setter setter)
    {
        auto it = m_entries.find(id);
        if (it == m_entries.end() || !owner || owner->thread() != thread() || !setter) return false;
        for (const Target& target : it->targets) if (target.owner == owner) return true;
        QString error;
        if (!setter(it->command.binding, &error)) return false;
        m_entries[id].targets.push_back({owner, std::move(setter)});
        connect(owner, &QObject::destroyed, this, [this, id]() {
            auto entry = m_entries.find(id);
            if (entry == m_entries.end()) return;
            auto& targets = entry->targets;
            targets.erase(std::remove_if(targets.begin(), targets.end(),
                [](const Target& target) { return target.owner.isNull(); }), targets.end());
            ++m_revision;
        });
        ++m_revision;
        return true;
    }

    bool ShortcutRegistry::bindAction(const QString& id, const QString& title, const QString& context, QAction* action)
    {
        if (!action || !define({id, title, context, {}, action->shortcut(), {}})) return false;
        const QString description = action->toolTip() == action->text() ? title : action->toolTip();
        const bool attached = attach(id, action, [action](const QKeySequence& keys, QString*) { action->setShortcut(keys); return true; });
        if (attached) setShortcutHint(id, action, description);
        return attached;
    }

    void ShortcutRegistry::setShortcutHint(const QString& id, QObject* owner, const QString& description)
    {
        if (!owner || !m_entries.contains(id)) return;
        const bool observed = m_hints.contains(owner);
        m_hints.insert(owner, {id, description, owner});
        if (observed) { refreshToolTips(id, owner); return; }
        owner->installEventFilter(this);
        if (owner->parent() && owner->parent()->inherits("QMenu")) owner->parent()->installEventFilter(this);
        connect(owner, &QObject::destroyed, this, [this, owner]() { m_hints.remove(owner); });
        refreshToolTips(id, owner);
    }

    void ShortcutRegistry::refreshToolTips(const QString& id, QObject* owner)
    {
        if (m_updatingHints) return;
        QScopedValueRollback<bool> updating(m_updatingHints, true);
        const auto hints = owner ? (m_hints.contains(owner) ? QList<Hint>{m_hints.value(owner)} : QList<Hint>{}) : m_hints.values();
        for (const Hint& hint : hints)
        {
            if (!hint.owner || (!id.isEmpty() && hint.id != id)) continue;
            QString text = i18n::displayText(hint.description);
            const QString keys = binding(hint.id).toString(QKeySequence::NativeText);
            if (!keys.isEmpty()) text += QLatin1Char('\n') + keys;
            if (hint.owner->property("toolTip").toString() != text) hint.owner->setProperty("toolTip", text);
        }
    }

    bool ShortcutRegistry::eventFilter(QObject* owner, QEvent* event)
    {
        if (event->type() == QEvent::LanguageChange || event->type() == QEvent::ToolTip || event->type() == QEvent::Show)
        {
            refreshToolTips({}, owner);
            if (owner->inherits("QMenu"))
                for (QObject* action : owner->children()) refreshToolTips({}, action);
        }
        return QObject::eventFilter(owner, event);
    }

    bool ShortcutRegistry::bindShortcut(const QString& id, const QString& title, const QString& context, QShortcut* shortcut)
    {
        if (!shortcut || !define({id, title, context, {}, shortcut->key(), {}})) return false;
        return attach(id, shortcut, shortcutSetter(shortcut));
    }

    bool ShortcutRegistry::bindDefaultShortcut(const QString& context, QShortcut* shortcut)
    {
        InstallCommonShortcutCatalog();
        if (!shortcut) return false;
        for (const auto& command : snapshot())
            if (command.context == context && command.defaults == shortcut->key())
                return attach(command.id, shortcut, shortcutSetter(shortcut));
        return false;
    }

    QVector<ShortcutRegistry::Command> ShortcutRegistry::snapshot() const
    {
        QVector<Command> result;
        for (const Entry& entry : m_entries)
        {
            Command command = entry.command;
            for (const Target& target : entry.targets)
                if (target.owner)
                {
                    ++command.targets;
                    if (const auto* shortcut = qobject_cast<QShortcut*>(target.owner.data()))
                        for (const QKeySequence& keys : shortcut->keys())
                            if (!keys.isEmpty() && keys != command.binding)
                                command.alternateBindings.append(keys.toString(QKeySequence::NativeText));
                }
            command.alternateBindings.removeDuplicates();
            result.push_back(std::move(command));
        }
        std::sort(result.begin(), result.end(), [](const Command& a, const Command& b) { return a.id < b.id; });
        return result;
    }

    QKeySequence ShortcutRegistry::binding(const QString& id) const
    {
        auto it = m_entries.constFind(id);
        return it == m_entries.cend() ? QKeySequence{} : it->command.binding;
    }

    bool ShortcutRegistry::matches(const QString& id, const QKeyEvent* event) const
    {
        const QKeySequence keys = binding(id);
        if (!event || keys.count() != 1) return false;
        const auto modifiers = event->modifiers() & ~Qt::KeypadModifier;
        return keys[0] == QKeyCombination(modifiers, static_cast<Qt::Key>(event->key()));
    }

    QStringList ShortcutRegistry::conflicts(const QString& id, const QKeySequence& keys) const
    {
        QStringList result;
        const auto entry = m_entries.constFind(id);
        if (entry == m_entries.cend() || keys.isEmpty()) return result;
        for (const Entry& other : m_entries)
        {
            const Command& command = other.command;
            if (command.id == id || command.binding.isEmpty()) continue;
            if (keys == entry->command.defaults && command.binding == command.defaults && keys == command.defaults) continue;
            // A page's own refresh retains precedence over the default F5 fallback.
            if ((command.id == QStringLiteral("app.refresh") && command.binding == command.defaults
                    && entry->command.context != QStringLiteral("application") && entry->command.context != QStringLiteral("system"))
                || (id == QStringLiteral("app.refresh") && keys == entry->command.defaults
                    && command.context != QStringLiteral("application") && command.context != QStringLiteral("system")))
                continue;
            const QString& context = entry->command.context;
            const bool overlap = context == command.context || context == QStringLiteral("system")
                || command.context == QStringLiteral("system") || context == QStringLiteral("application")
                || command.context == QStringLiteral("application") || context == QStringLiteral("navigation")
                || command.context == QStringLiteral("navigation");
            bool matches = keys.matches(command.binding) != QKeySequence::NoMatch
                || command.binding.matches(keys) != QKeySequence::NoMatch;
            if (overlap && !matches)
                for (const Target& target : other.targets)
                    if (const auto* shortcut = qobject_cast<QShortcut*>(target.owner.data()))
                        for (const QKeySequence& alternate : shortcut->keys())
                            if (!alternate.isEmpty() && (keys.matches(alternate) != QKeySequence::NoMatch
                                || alternate.matches(keys) != QKeySequence::NoMatch)) matches = true;
            if (overlap && matches) result.append(i18n::displayText(command.title));
        }
        return result;
    }

    bool ShortcutRegistry::fail(QString* error, const QString& message) const
    {
        if (error) *error = message;
        return false;
    }

    bool ShortcutRegistry::rebind(const QString& id, const QKeySequence& keys, QString* error)
    {
        if (m_applyingBinding) return fail(error, i18n::sourceText(QStringLiteral("正在更新绑定，请稍后重试。")));
        QScopedValueRollback<bool> applying(m_applyingBinding, true);
        auto it = m_entries.find(id);
        if (it == m_entries.end()) return fail(error, i18n::sourceText(QStringLiteral("快捷键不再可用。")));
        if (!it->command.editable) return fail(error, i18n::displayText(it->command.restriction));
        if (!it->command.sequence && keys.count() > 1)
            return fail(error, i18n::sourceText(QStringLiteral("此动作只支持单个组合键。")));
        if (keys == it->command.binding) return true;
        const QStringList occupied = conflicts(id, keys);
        if (!occupied.isEmpty())
            return fail(error, i18n::sourceText(QStringLiteral("快捷键已被以下动作占用：%1"))
                .arg(occupied.join(QStringLiteral("、"))));
        const QKeySequence previous = it->command.binding;
        const auto targets = it->targets;
        for (const Target& target : targets)
        {
            if (target.owner && !target.setter(keys, error))
            {
                for (const Target& rollback : targets) if (rollback.owner) rollback.setter(previous, nullptr);
                return false;
            }
        }
        QSettings settings(m_settingsPath, QSettings::IniFormat);
        const QString settingKey = QStringLiteral("shortcuts/") + id;
        const bool hadSetting = settings.contains(settingKey);
        const QVariant previousSetting = settings.value(settingKey);
        if (keys == m_entries[id].command.defaults) settings.remove(settingKey);
        else settings.setValue(settingKey, keys.toString(QKeySequence::PortableText));
        settings.sync();
        if (settings.status() != QSettings::NoError)
        {
            if (hadSetting) settings.setValue(settingKey, previousSetting); else settings.remove(settingKey);
            for (const Target& target : targets) if (target.owner) target.setter(previous, nullptr);
            return fail(error, i18n::sourceText(QStringLiteral("无法保存设置，请检查配置目录的写入权限。")));
        }
        m_entries[id].command.binding = keys;
        refreshToolTips(id);
        ++m_revision;
        return true;
    }

    bool ShortcutRegistry::restoreDefault(const QString& id, QString* error)
    {
        auto it = m_entries.constFind(id);
        if (it == m_entries.cend()) return fail(error, i18n::sourceText(QStringLiteral("快捷键不再可用。")));
        return rebind(id, it->command.defaults, error);
    }
}
