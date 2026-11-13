#pragma once

#include <QAbstractItemView>
#include <QApplication>
#include <QKeyEvent>
#include <QPointer>

namespace ks::ui
{
    // Opt in only for a view whose doubleClicked signal is its default business action.
    // Keep native mouse/edit handling and existing application-level guards (e.g. snapshot
    // comparison). Enter invokes that action once without synthesizing a click or changing selection.
    inline void InstallKeyboardItemActivation(QAbstractItemView* view)
    {
        if (!view || view->property("ksword_keyboard_item_activation").toBool()) return;
        class ActivationFilter final : public QObject
        {
        public:
            explicit ActivationFilter(QAbstractItemView* target) : QObject(target), m_view(target)
            {
                target->installEventFilter(this);
            }
        protected:
            bool eventFilter(QObject* watched, QEvent* event) override
            {
                if (!m_view || watched != m_view || !qApp->property("ksword_mouseless_mode").toBool()
                    || (event->type() != QEvent::ShortcutOverride && event->type() != QEvent::KeyPress)) return false;
                auto* key = static_cast<QKeyEvent*>(event);
                if ((key->key() != Qt::Key_Return && key->key() != Qt::Key_Enter)
                    || (key->modifiers() & (Qt::ShiftModifier | Qt::ControlModifier | Qt::AltModifier
                        | Qt::MetaModifier | Qt::GroupSwitchModifier))) return false;
                QWidget* focus = QApplication::focusWidget();
                if (!focus || !m_view->isVisible() || !m_view->isEnabled()) return false;
                if (focus != m_view && focus != m_view->viewport() && focus != m_view->focusProxy()) return false;
                key->accept();
                if (event->type() == QEvent::KeyPress && !key->isAutoRepeat())
                {
                    const QModelIndex current = m_view->currentIndex();
                    if (current.isValid() && current.flags().testFlag(Qt::ItemIsEnabled))
                        emit m_view->doubleClicked(current);
                    // The callback may reset the model or destroy this view/filter.
                }
                return true;
            }
        private:
            QPointer<QAbstractItemView> m_view;
        };
        view->setProperty("ksword_keyboard_item_activation", true);
        new ActivationFilter(view);
    }
}
