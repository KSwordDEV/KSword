#pragma once

#include "./MouselessNavigationState.h"
#include <QAbstractNativeEventFilter>
#include <QElapsedTimer>
#include <QObject>
#include <QPointer>
#include <QVector>
#include <functional>

class QFocusFrame;
class QKeyEvent;
class QLabel;
class QVBoxLayout;
class QWidget;

namespace ks::ui
{
    // One controller for the main process. Enumerates only the active, visible branch
    // on an explicit navigation request; modal windows always remain the navigation boundary.
    class MouselessNavigation final : public QObject, public QAbstractNativeEventFilter
    {
    public:
        MouselessNavigation(QWidget* mainWindow, QWidget* tutorialHost, QVBoxLayout* tutorialLayout,
            QWidget* workspace, std::function<void(bool)> modeChanged,
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
        struct FocusPolicyChange
        {
            QPointer<QWidget> widget;
            Qt::FocusPolicy original;
        };
        struct RegionFocus
        {
            QPointer<QWidget> anchor;
            QPointer<QWidget> control;
        };
        QWidget* navigationWindow() const;
        QVector<Region> regions(QWidget* window) const;
        int currentRegion(const QVector<Region>& items, QWidget* focus) const;
        void moveFocus(bool backwards, bool byRegion);
        bool focusControl(QWidget* control);
        bool focusRegion(const Region& region, bool backwards = false);
        void restoreFocusPolicies();
        void highlightRegion(QWidget* anchor);
        void rememberNavigationFocus(QWidget* anchor, int tabIndex);
        void queueNavigationFocusRestore();
        void showKeyTips();
        void hideKeyTips();
        void updateFocusFrame();
        void recoverFocus();
        bool activateControl(QWidget* focus, QKeyEvent* key);
        bool contextMenu(QWidget* focus);
        void offerFirstTutorial();
        void advanceTutorial(int direction);
        void closeTutorial();
        void locateTutorialTarget();

        QPointer<QWidget> m_mainWindow;
        QPointer<QWidget> m_tutorialHost;
        QPointer<QVBoxLayout> m_tutorialLayout;
        QPointer<QWidget> m_workspace;
        QPointer<QFocusFrame> m_focusFrame;
        QPointer<QWidget> m_tipOverlay;
        QPointer<QWidget> m_regionHighlight;
        QPointer<QWidget> m_navigationFocusAnchor;
        QPointer<QWidget> m_tutorial;
        QPointer<QWidget> m_tutorialReturnFocus;
        QPointer<QLabel> m_tutorialStatus;
        QVector<Region> m_tipRegions;
        QVector<FocusPolicyChange> m_focusPolicyChanges;
        QVector<RegionFocus> m_regionFocus;
        QString m_tipPrefix;
        int m_tipDigits = 1;
        int m_tutorialStep = 0;
        int m_navigationTabIndex = -1;
        quint64 m_inputRevision = 0;
        quint64 m_navigationInputRevision = 0;
        bool m_navigationRestoreQueued = false;
        std::function<void()> m_renderTutorial;
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
