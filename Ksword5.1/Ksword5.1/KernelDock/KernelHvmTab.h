#include "../UI/StructuredFieldView.h"
#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

#include <cstdint>
#include <functional>

class QLabel;
class QPushButton;
class QShowEvent;
class QTableWidget;
class CodeEditorWidget;

// KernelHvmTab presents VT-x/EPT capability, reversible resource preparation,
// per-CPU VMX validation, a one-shot VMCALL guest, VM-exit evidence, and teardown.
class KernelHvmTab final : public QWidget
{
public:
    enum class FeatureArea
    {
        Ept,
        NestedVmx,
        Evmcs
    };

    explicit KernelHvmTab(QWidget* parent = nullptr);
    KernelHvmTab(FeatureArea featureArea, QWidget* parent);
    ~KernelHvmTab() override = default;
    void testPreparedBackend() { selfTestBackend(); }
    std::function<void(bool)> onBusyChanged;

protected:
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void refreshAsync();
    void applyMetrics(ksword::ark::HvmMetricsResult result);
    void applyStatus(ksword::ark::HvmStatusResult result);
    void runControlAsync(
        unsigned long command,
        bool force,
        bool enableEptEvents = false,
        bool enableNestedVmx = false,
        bool enableEvmcs = false);
    void applyControl(
        unsigned long command,
        ksword::ark::HvmControlResult control,
        ksword::ark::HvmStatusResult status);
    void prepareBackend();
    void selfTestBackend();
    void launchControlledGuest();
    void teardownBackend();
    void startResident();
    void stopResident();
    void validateNested();
    void validateEvmcs();
    void addEptRule();
    void queryEptRule();
    void removeEptRule();
    void clearEptRules();
    void queryEvents();
    void clearEvents();
    void runEptRuleAsync(
        unsigned long operation,
        unsigned long ruleId,
        unsigned long deniedAccess,
        std::uint64_t physicalAddress,
        std::uint64_t pageCount,
        bool log,
        bool allowOnce);
    void applyEptRule(
        unsigned long operation,
        ksword::ark::HvmEptRuleResult result,
        ksword::ark::HvmStatusResult status);
    void runEventQueryAsync(bool clear);
    void applyEvents(
        bool clear,
        ksword::ark::HvmEventResult result);
    bool confirmTyped(const QString& warning, const QString& phrase);
    void updateButtons();
    ks::ui::FieldDocument buildDetail(
        const KSWORD_ARK_QUERY_HVM_RESPONSE& response) const;
    static QString featureText(std::uint64_t flags);
    static QString stateText(std::uint32_t flags);
    static QString implementationText(std::uint32_t implementation);
    static QString nestedStateText(std::uint32_t state);
    // executionStageText：逐 CPU 的执行阶段。AMD 侧「执行状态」那一列用它——
    // 驱动回报的是 0..7 的序号，摆一个裸数字等于什么都没说。
    static QString executionStageText(std::uint32_t stage);
    static QString ntStatusText(long status);
    static QString fixedAscii(const char* text, int capacity);

    QLabel* m_statusLabel = nullptr;
    QLabel* m_summaryLabel = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QPushButton* m_prepareButton = nullptr;
    QPushButton* m_selfTestButton = nullptr;
    QPushButton* m_launchButton = nullptr;
    QPushButton* m_teardownButton = nullptr;
    QPushButton* m_startResidentButton = nullptr;
    QPushButton* m_stopResidentButton = nullptr;
    QPushButton* m_featureActionButton = nullptr;
    QTableWidget* m_cpuTable = nullptr;
    ks::ui::StructuredFieldView* m_detailEdit = nullptr;
    FeatureArea m_featureArea = FeatureArea::Ept;
    KSWORD_ARK_QUERY_HVM_RESPONSE m_snapshot{};
    bool m_firstRefreshStarted = false;
    bool m_operationRunning = false;
    bool m_supported = false;
};
