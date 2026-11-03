#pragma once
#include "HyperVMemoryEvidence.h"
#include <QWidget>
#include <QPointer>
#include <array>
#include <functional>
class QLabel;
class QPushButton;
class QLineEdit;
class QProgressBar;
class QTableView;
class QTimer;
class QShowEvent;
struct HyperPreparedData;
struct HyperViewData;
#include "../UI/StructuredFieldView.h"
class QTabWidget;
class MemoryAttributionChart;
namespace ksword::pfn { struct Scan; }
namespace ks::ui { class MetricAreaWindow; }

class HyperVMemoryPage final : public QWidget {
public:
    explicit HyperVMemoryPage(QWidget* parent = nullptr);
    ~HyperVMemoryPage() override;
    void startCollection();
    void setSnapshotContext(const QString& time, std::uint64_t remainder);
    void setPfnContext(const std::shared_ptr<ksword::pfn::Scan>& scan);
    void openMetricAreaView();
    bool hasMetricAreaData() const;
    std::function<void()> metricAreaStateChanged;
protected:
    void changeEvent(QEvent*) override;
    void showEvent(QShowEvent*) override;
private:
    void poll();
    void retranslate();
    void rebuild();
    void rebuildPartitions();
    void showPartition(int index);
    void exportEvidence();
    void requestProjection(bool rebuild = false);
    void pollProjection();
    void bindCurrentProjection();
    void refreshMetricAreaView(int kind);
    void updateMetricAreaAction();
    QPushButton* m_collect = nullptr;
    QPushButton* m_cancel = nullptr;
    QPushButton* m_export = nullptr;
    QPushButton* m_metricAreaButton = nullptr;
    std::array<QPointer<ks::ui::MetricAreaWindow>, 4> m_metricAreaWindows;
    QLineEdit* m_filter = nullptr;
    QLabel* m_summary = nullptr;
    QProgressBar* m_progress = nullptr;
    MemoryAttributionChart* m_chart = nullptr;
    QTabWidget* m_tabs = nullptr;
    QTableView* m_partitions = nullptr;
    QTableView* m_host = nullptr;
    QTableView* m_processes = nullptr;
    QTableView* m_sources = nullptr;
    ks::ui::StructuredFieldView* m_detail = nullptr;
    ks::ui::StructuredFieldView* m_evidence = nullptr;
    ksword::hyperv::Context m_latestContext, m_jobContext, m_resultContext;
    std::shared_ptr<ksword::hyperv::Job> m_job;
    struct ProjectionJob;
    struct DetailJob;
    std::shared_ptr<ProjectionJob> m_projectionJob;
    std::shared_ptr<DetailJob> m_detailJob;
    std::shared_ptr<const HyperPreparedData> m_prepared;
    std::shared_ptr<const HyperViewData> m_readyView;
    std::uint64_t m_projectionVersion = 0, m_publishedVersion = 0, m_localeVersion = 0;
    std::array<std::uint64_t, 5> m_boundVersions{};
    QTimer* m_projectionDebounce = nullptr;
    bool m_rebuildProjection = true;
    int m_requestedPartition = -1, m_shownPartition = -1;
    std::uint64_t m_detailLocale = 0;
    std::shared_ptr<const ksword::hyperv::Snapshot> m_detailSnapshot;
    struct ExportJob;
    std::shared_ptr<ExportJob> m_exportJob;
    std::shared_ptr<ksword::hyperv::Snapshot> m_snapshot, m_previous;
};
