#pragma once

#include <QDialog>
#include <QWidget>
#include <functional>
#include <memory>

class ProgressDockWidget;

namespace ks::ui
{
    class TaskManagerDialog final : public QDialog
    {
    public:
        explicit TaskManagerDialog(QWidget* parent = nullptr);
        void showBackgroundTasks();
    private:
        ProgressDockWidget* m_tasks = nullptr;
    };
    class BackgroundTaskPage final : public QWidget
    {
    public:
        explicit BackgroundTaskPage(QWidget* parent = nullptr);
        ~BackgroundTaskPage() override;
    protected:
        void showEvent(QShowEvent*) override;
        void hideEvent(QHideEvent*) override;
    private:
        struct State;
        std::unique_ptr<State> m;
        void refresh();
        void selectTask();
        void apply(int operation);
    };

    // One nonmodal window; the system tab lazily adopts the existing hotkey views.
    class ShortcutManagerDialog final : public QDialog
    {
    public:
        using SystemFactory = std::function<QWidget*(QWidget*)>;
        using SystemSearch = std::function<void(const QString&)>;
        ShortcutManagerDialog(QWidget* parent, SystemFactory factory, SystemSearch search);
        ~ShortcutManagerDialog() override;
        void showSystemPage();
    protected:
        void showEvent(QShowEvent*) override;
        void hideEvent(QHideEvent*) override;
    private:
        struct State;
        std::unique_ptr<State> m;
        void refresh();
        void selectCommand();
        void apply(int operation);
    };
}
