#pragma once
#include <QWidget>
#include <functional>
#include <cstdint>
#include <memory>
namespace ks::process { struct ProcessRecord; }

class ProcessNetworkPage final : public QWidget {
public:
    explicit ProcessNetworkPage(const ks::process::ProcessRecord& target, QWidget* parent = nullptr);
    ~ProcessNetworkPage() override;
    void updateRateSnapshot(const ks::process::ProcessRecord& record);
    void setRates(double receivedKiBps, double sentKiBps, bool known);
    void shutdown();
    std::function<void(std::uint32_t)> openFullMonitorRequested;
protected:
    void changeEvent(QEvent* event) override;
private:
    struct State;
    std::unique_ptr<State> m_state;
    void startCapture();
    void stopCapture();
    void pollPackets();
    void refreshConnections();
    void disconnectSelected();
    void exportPackets(bool pcap);
    void applyHostBlock(bool wholeProcess);
    void applyRateLimit();
    void refreshPolicies();
    void removeSelectedPolicy();
    void updateButtons();
    void showPacket();
    void retranslate();
    void log(const QString& text);
};
