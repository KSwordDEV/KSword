#pragma once

#include "DesktopDrawingRenderer.h"

#include <QAbstractNativeEventFilter>
#include <QColor>
#include <QWidget>

class QComboBox;
class QLabel;
class QPushButton;
class QSpinBox;
class QTimer;

namespace ks::misc
{
    class DesktopDrawingPage final : public QWidget, public QAbstractNativeEventFilter
    {
    public:
        explicit DesktopDrawingPage(QWidget* parent = nullptr);
        ~DesktopDrawingPage() override;

        bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

    private:
        void initializeUi();
        void refreshDisplays();
        void updateCoordinates();
        void chooseColor();
        void updateColorButton();
        void startDrawing();
        void stopDrawing();
        void drawFrame();
        void showFailure(desktop_drawing::DrawResult result);
        void setRunning(bool running);

        desktop_drawing::Renderer m_renderer;
        std::vector<desktop_drawing::Display> m_displays;
        QColor m_color{ 255, 80, 80 };
        QTimer* m_timer = nullptr;
        QWidget* m_settings = nullptr;
        QComboBox* m_displayCombo = nullptr;
        QComboBox* m_patternCombo = nullptr;
        QSpinBox* m_xSpin = nullptr;
        QSpinBox* m_ySpin = nullptr;
        QSpinBox* m_sizeSpin = nullptr;
        QSpinBox* m_lineWidthSpin = nullptr;
        QSpinBox* m_rateSpin = nullptr;
        QPushButton* m_colorButton = nullptr;
        QPushButton* m_startButton = nullptr;
        QPushButton* m_stopButton = nullptr;
        QLabel* m_statusLabel = nullptr;
        QLabel* m_hotkeyLabel = nullptr;
        bool m_hotkeyRegistered = false;
    };
}
