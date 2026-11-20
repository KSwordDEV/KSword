#pragma once

#include <QWidget>

#include <functional>
#include <memory>

namespace ksword::detection
{
    class ProcessDetectionPane final : public QWidget
    {
    public:
        explicit ProcessDetectionPane(bool deep, QWidget* parent);
        ~ProcessDetectionPane() override;

        void runSelected();
        void chooseMethods();
        QString evidenceForProcess(quint32 pid, quint64 creationTime100ns) const;
        void setReportChanged(std::function<void()> callback);

    private:
        struct State;
        std::unique_ptr<State> m_state;
    };
}
