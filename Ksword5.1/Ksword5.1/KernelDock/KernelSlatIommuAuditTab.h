#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

#include <cstdint>

class QCheckBox;
class QLabel;
class QPushButton;
class QShowEvent;
class QTableWidget;
#include "../UI/StructuredFieldView.h"

// Guest-visible, read-only cross-view evidence for EPT/NPT hooks and IOMMU
// configuration. It deliberately does not claim that an opaque outer SLAT is
// clean when the guest-visible virtual and physical views agree.
class KernelSlatIommuAuditTab final : public QWidget
{
public:
    explicit KernelSlatIommuAuditTab(QWidget* parent = nullptr);
    ~KernelSlatIommuAuditTab() override = default;

protected:
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void refreshAsync();
    void applyResult(ksword::ark::SlatIommuAuditResult result);
    void populateProbeTable(
        const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE& response);
    void populateIommuTable(
        const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE& response);
    ks::ui::FieldDocument buildDetail(
        const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE& response) const;
    static QString featureText(std::uint64_t flags);
    static QString riskText(std::uint32_t flags);
    static QString iommuTypeText(std::uint32_t type);
    static QString iommuFlagsText(std::uint32_t flags);
    static QString probeVerdictText(
        const KSWORD_ARK_SLAT_PROBE_ROW& row);
    static QString ntStatusText(long status);
    static QString hex64(std::uint64_t value);
    static QString fixedAscii(const char* text, int capacity);

    QLabel* m_statusLabel = nullptr;
    QLabel* m_summaryLabel = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QCheckBox* m_includeMmioCheck = nullptr;
    QTableWidget* m_probeTable = nullptr;
    QTableWidget* m_iommuTable = nullptr;
    ks::ui::StructuredFieldView* m_detailEdit = nullptr;
    bool m_firstRefreshStarted = false;
    bool m_queryRunning = false;
};
