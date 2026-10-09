#pragma once

#include "../ksword/scanner/binary_scanner.h"
#include <QWidget>
#include <functional>
#include <memory>

class QMouseEvent;
class QKeyEvent;
class QPaintEvent;

namespace ks::ui
{
    // A proportional map of captured disk bytes, independent of the viewer.
    // Clicking resolves to a file offset, never to a guessed virtual address.
    class BinaryOverviewBar final : public QWidget
    {
    public:
        explicit BinaryOverviewBar(QWidget* parent = nullptr);
        void setLayout(std::shared_ptr<const ks::scanner::BinaryScanResult> layout);
        void setCurrentOffset(std::uint64_t offset);
        std::uint64_t currentOffset() const { return m_currentOffset; }
        std::function<void(std::uint64_t)> offsetActivated;
        QSize sizeHint() const override;
        QSize minimumSizeHint() const override;
    protected:
        void paintEvent(QPaintEvent* event) override;
        void mousePressEvent(QMouseEvent* event) override;
        void keyPressEvent(QKeyEvent* event) override;
        bool event(QEvent* event) override;
    private:
        std::uint64_t offsetAt(int x) const;
        QString tooltipAt(std::uint64_t offset) const;
        void activate(std::uint64_t offset);
        std::shared_ptr<const ks::scanner::BinaryScanResult> m_layout;
        std::uint64_t m_currentOffset = 0;
    };
}
