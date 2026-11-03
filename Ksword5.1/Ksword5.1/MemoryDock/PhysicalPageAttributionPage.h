#pragma once
#include "PhysicalPageScan.h"
#include "PhysicalPageMappings.h"
#include <QWidget>
#include <QPointer>
#include <QStringList>
#include <functional>
class QLabel;
class QPushButton;
class QLineEdit;
class QProgressBar;
class QSpinBox;
class QTableWidget;
#include "../UI/StructuredFieldView.h"
class QTabWidget;
class MemoryAttributionChart;
class QCheckBox;
class QTimer;
class MemoryConsumerEvidencePage;
namespace ks::ui { class MetricAreaWindow; }

class PhysicalPageAttributionPage final : public QWidget {
public:
    explicit PhysicalPageAttributionPage(QWidget* parent = nullptr);
    ~PhysicalPageAttributionPage() override;
    void startScan();
    static QString classificationName(ksword::pfn::Use use);
    void focusCategory(int use);
    void openMetricAreaView(int mode = -1);
    bool hasMetricAreaData() const;
    // Invoked on the UI thread after an immutable scan result has been published.
    std::function<void(const std::shared_ptr<ksword::pfn::Scan>&)> snapshotReady;
    std::function<void(const QString&)> openModuleDetails;
protected:
    void changeEvent(QEvent*) override;
private:
    void poll();
    void rebuild();
    void rebuildGroups();
    void startGroupFilter();
    void applyGroupProjection();
    void selectCategory(int use);
    void inspectPfn();
    void showMappings(std::uint64_t pfn);
    void startMappings();
    void exportEvidence();
    void retranslate();
    void refreshMetricAreaView();
    struct MetricAreaJob;
    void publishMetricAreaView(const std::shared_ptr<MetricAreaJob>& job);
    QPushButton* m_scanButton = nullptr;
    QPushButton* m_cancelButton = nullptr;
    QPushButton* m_mappingButton = nullptr;
    QPushButton* m_exportButton = nullptr;
    QPushButton* m_inspectButton = nullptr;
    QPushButton* m_areaButton = nullptr;
    QSpinBox* m_budget = nullptr;
    QCheckBox* m_retainRaw = nullptr;
    QCheckBox* m_exportMappings = nullptr;
    MemoryConsumerEvidencePage* m_consumerPage = nullptr;
    QLabel* m_summary = nullptr;
    QProgressBar* m_progress = nullptr;
    QLineEdit* m_filter = nullptr;
    QLineEdit* m_pfn = nullptr;
    ks::ui::StructuredFieldView* m_evidence = nullptr;
    ks::ui::StructuredFieldView* m_pageEvidence = nullptr;
    QTableWidget* m_categories = nullptr;
    QTableWidget* m_ownerCoverage = nullptr;
    QTableWidget* m_objects = nullptr;
    QTableWidget* m_pageConsumers = nullptr;
    QTableWidget* m_groups = nullptr;
    QTableWidget* m_examples = nullptr;
    QTableWidget* m_mappings = nullptr;
    QTabWidget* m_tabs = nullptr;
    MemoryAttributionChart* m_chart = nullptr;
    QPointer<ks::ui::MetricAreaWindow> m_metricAreaWindow;
    std::shared_ptr<MetricAreaJob> m_metricAreaJob;
    std::weak_ptr<const ksword::pfn::Scan> m_metricAreaPresented;
    int m_metricAreaPresentedMode = -1;
    QStringList m_metricAreaPresentedLabels;
    int m_selectedCategory = -1;
    std::size_t m_areaFocusGroup = static_cast<std::size_t>(-1);
    std::shared_ptr<ksword::pfn::ScanJob> m_job;
    std::shared_ptr<ksword::pfn::Scan> m_scan;
    struct GroupIndex;
    struct GroupFilterJob;
    std::shared_ptr<const GroupIndex> m_groupIndex;
    std::shared_ptr<GroupFilterJob> m_groupFilterJob;
    std::vector<std::size_t> m_groupRows;
    QTimer* m_groupFilterTimer = nullptr;
    std::uint64_t m_groupFilterRevision = 0;
    bool m_groupFilterPending = false;
    bool m_groupProjectionDirty = false;
    std::shared_ptr<ksword::pfn::Scan> m_lastAttempt;
    bool m_latestAttemptFailed = false;
    std::vector<ksword::pfn::AuditCriterionSample> m_auditHistory;
    std::shared_ptr<ksword::pfn::MappingJob> m_mappingJob;
    std::shared_ptr<ksword::pfn::Mappings> m_mappingScan;
    struct Inspection;
    std::shared_ptr<Inspection> m_inspection;
    struct ExportJob;
    std::shared_ptr<ExportJob> m_exportJob;
};
