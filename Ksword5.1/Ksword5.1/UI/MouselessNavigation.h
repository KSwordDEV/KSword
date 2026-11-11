#pragma once

#include "./MouselessNavigationState.h"
#include <QAbstractNativeEventFilter>
#include <QElapsedTimer>
#include <QObject>
#include <QPointer>
#include <QVector>
#include <functional>

class QDialog;
class QFocusFrame;
class QKeyEvent;
class QWidget;

namespace ks::ui
{
    // One controller for the main process. Enumerates only the active, visible branch
    // on an explicit navigation request; modal windows always remain the navigation boundary.
    class MouselessNavigation final : public QObject, public QAbstractNativeEventFilter
    {
    public:
        MouselessNavigation(QWidget* mainWindow, std::function<void(bool)> modeChanged,
            std::function<void()> dismissTransientPanels);
        ~MouselessNavigation() override;
        void setEnabled(bool enabled);
        void showTutorial();

    protected:
        bool eventFilter(QObject* object, QEvent* event) override;
        bool nativeEventFilter(const QByteArray& type, void* message, qintptr* result) override;

    private:
        struct Region
        {
            QPointer<QWidget> anchor;
            QVector<QPointer<QWidget>> controls;
            QString title;
        };
        QWidget* navigationWindow() const;
        QVector<Region> regions(QWidget* window) const;
        int currentRegion(const QVector<Region>& items, QWidget* focus) const;
        void moveFocus(bool backwards, bool withinRegion);
        void focusControl(QWidget* control);
        void showKeyTips();
        void hideKeyTips();
        void updateFocusFrame();
        void recoverFocus();
        bool activateControl(QWidget* focus, QKeyEvent* key);
        bool contextMenu(QWidget* focus);
        void offerFirstTutorial();

        QPointer<QWidget> m_mainWindow;
        QPointer<QFocusFrame> m_focusFrame;
        QPointer<QWidget> m_tipOverlay;
        QPointer<QDialog> m_tutorial;
        QVector<Region> m_tipRegions;
        QString m_tipPrefix;
        int m_tipDigits = 1;
        std::function<void(bool)> m_modeChanged;
        std::function<void()> m_dismissTransientPanels;
        MouselessGesture m_gesture;
        QElapsedTimer m_clock;
        bool m_enabled = false;
        bool m_altHeld = false;
        bool m_tipUsed = false;
        bool m_firstTutorialQueued = false;
        bool m_tutorialOffered = false;
    };
}
