#pragma once

#include "PoolTraceReader.h"
#include <QWidget>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <functional>
#include <memory>
#include <vector>
#include <unordered_map>
#include <unordered_set>

class QComboBox;
class QLabel;
class QLineEdit;
#include "../UI/StructuredFieldView.h"
class QPushButton;
struct PoolPreparedProjection;
class QTableView;
class QTimer;
class QShowEvent;
class PoolAllocationTableModel;
class PoolStackListModel;
namespace ks::ui { class MetricAreaWindow; }

// Bounded, read-only ETL analysis. Historical stacks are evidence of a call
// path, and observed outstanding allocations are not proof of a pool leak.
class PoolAllocationAnalysisWidget final : public QWidget {
public:
    using ReadProvider = std::function<ks::evidence::pool::TraceReadResult(
        const std::wstring&, const std::atomic_bool&)>;
    using ResolveProvider = std::function<std::vector<std::wstring>(
        const ks::evidence::pool::TraceReadResult&, const ks::evidence::pool::Group&,
        const std::atomic_bool&)>;

    explicit PoolAllocationAnalysisWidget(QWidget* parent = nullptr);
    ~PoolAllocationAnalysisWidget() override;
    void analyzeFile(const QString& path);
    void setOpenModuleDetails(std::function<void(const QString&)> callback);

    // Controlled offline Qt fixtures; production defaults use PoolTraceReader.
    void setResultForTesting(ks::evidence::pool::TraceReadResult result);
    void setProvidersForTesting(ReadProvider reader, ResolveProvider resolver);

protected:
    void changeEvent(QEvent* event) override;
    void showEvent(QShowEvent* event) override;

private:
    struct ReadJob;
    struct ResolveJob;
    struct ProjectionJob;
    void pollJobs();
    void startRead(const QString& path);
    void cancelJobs();
    void rebuildRows();
    void requestProjection(bool rebuild = false);
    void clearProjection();
    void clearStackModel();
    void selectRow();
    void selectStack();
    void resolveStack();
    void showStack();
    void updateSummary();
    void updateControls();
    void retranslate();
    void openMetricAreaView();
    void refreshMetricAreaView();
    struct MetricAreaJob;
    const ks::evidence::pool::Group* selectedGroup() const;

    QPushButton* m_open = nullptr;
    QPushButton* m_cancel = nullptr;
    QPushButton* m_resolve = nullptr;
    QPushButton* m_module = nullptr;
    QPushButton* m_areaButton = nullptr;
    QPointer<ks::ui::MetricAreaWindow> m_areaWindow;
    std::shared_ptr<MetricAreaJob> m_areaJob;
    std::weak_ptr<const void> m_areaPresentedView;
    int m_areaPresentedMode = -1;
    QStringList m_areaPresentedLabels;
    QComboBox* m_grouping = nullptr;
    QComboBox* m_stacks = nullptr;
    QLineEdit* m_filter = nullptr;
    QLabel* m_note = nullptr;
    QLabel* m_status = nullptr;
    QLabel* m_summary = nullptr;
    ks::ui::StructuredFieldView* m_frames = nullptr;
    QTableView* m_table = nullptr;
    PoolAllocationTableModel* m_model = nullptr;
    PoolStackListModel* m_stackModel = nullptr;
    QTimer* m_projectionDebounce = nullptr;
    std::shared_ptr<ProjectionJob> m_projectionJob;
    std::shared_ptr<const PoolPreparedProjection> m_prepared;
    std::uint64_t m_projectionVersion = 0, m_publishedVersion = 0;
    bool m_rebuildProjection = false, m_projectionFailed = false;
    int m_sortColumn = 5;
    Qt::SortOrder m_sortOrder = Qt::DescendingOrder;
    QTimer* m_poll = nullptr;
    std::shared_ptr<ReadJob> m_readJob;
    std::shared_ptr<ResolveJob> m_resolveJob;
    std::shared_ptr<const ks::evidence::pool::TraceReadResult> m_result;

    ReadProvider m_reader;
    ResolveProvider m_resolver;
    std::function<void(const QString&)> m_openModuleDetails;
    QString m_path;
    QString m_pendingPath;
    QString m_modulePath;
    std::vector<std::wstring> m_symbols;
    std::uint64_t m_symbolGroupId = 0;
};
