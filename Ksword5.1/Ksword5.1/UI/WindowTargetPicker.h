#pragma once

#include <QPoint>
#include <QPushButton>
#include <functional>

namespace ks::ui
{
    // Both list pages share the native-coordinate drag/release path. The callback
    // receives an HWND value, never a Qt global position or a new hit test.
    class WindowTargetPickerButton final : public QPushButton
    {
    public:
        using PickCallback = std::function<void(quintptr)>;
        explicit WindowTargetPickerButton(QWidget* parent = nullptr);
        void setPickCallback(PickCallback callback);

    protected:
        void mousePressEvent(QMouseEvent* event) override;
        void mouseMoveEvent(QMouseEvent* event) override;
        void mouseReleaseEvent(QMouseEvent* event) override;

    private:
        PickCallback m_callback;
        QPoint m_pressPhysical;
        int m_dragDistance = 0;
        bool m_tracking = false;
        bool m_dragged = false;
    };
}
