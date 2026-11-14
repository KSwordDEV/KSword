#pragma once

#include <QObject>
#include <QKeySequence>
#include <QPointer>
#include <QHash>
#include <QVector>
#include <QStringList>
#include <functional>

class QAction;
class QShortcut;
class QKeyEvent;

namespace ks::ui
{
    void InstallCommonShortcutCatalog();
    class ShortcutRegistry final : public QObject
    {
    public:
        struct Command
        {
            QString id, title, context, restriction;
            QKeySequence defaults, binding;
            bool editable = true;
            bool sequence = false;
            int targets = 0;
            QStringList alternateBindings;
        };
        using Setter = std::function<bool(const QKeySequence&, QString*)>;
        static ShortcutRegistry& instance();
        explicit ShortcutRegistry(QObject* parent = nullptr, QString settingsPath = {});
        bool define(Command command);
        bool attach(const QString& id, QObject* owner, Setter setter);
        bool bindAction(const QString& id, const QString& title, const QString& context, QAction* action);
        bool bindShortcut(const QString& id, const QString& title, const QString& context, QShortcut* shortcut);
        bool bindDefaultShortcut(const QString& context, QShortcut* shortcut);
        void setShortcutHint(const QString& id, QObject* owner, const QString& description);
        QVector<Command> snapshot() const;
        QKeySequence binding(const QString& id) const;
        bool matches(const QString& id, const QKeyEvent* event) const;
        QStringList conflicts(const QString& id, const QKeySequence& keys) const;
        bool rebind(const QString& id, const QKeySequence& keys, QString* error = nullptr);
        bool restoreDefault(const QString& id, QString* error = nullptr);
        quint64 revision() const { return m_revision; }

    protected:
        bool eventFilter(QObject* owner, QEvent* event) override;

    private:
        struct Target { QPointer<QObject> owner; Setter setter; };
        struct Entry { Command command; QVector<Target> targets; };
        bool fail(QString* error, const QString& message) const;
        void refreshToolTips(const QString& id = {}, QObject* owner = nullptr);
        struct Hint { QString id, description; QPointer<QObject> owner; };
        QHash<QObject*, Hint> m_hints;
        bool m_updatingHints = false;
        QHash<QString, Entry> m_entries;
        QString m_settingsPath;
        quint64 m_revision = 0;
        bool m_applyingBinding = false;
    };
}
