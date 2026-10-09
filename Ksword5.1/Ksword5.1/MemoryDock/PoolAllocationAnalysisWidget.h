#pragma once

#include "PoolTraceReader.h"
#include <QWidget>
#include <QString>
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
class QSortFilterProxyModel;
class QTableView;
class QTimer;
class PoolAllocationTableModel;
class PoolStackListModel;

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

private:
    struct ReadJob;
    struct ResolveJob;
    void pollJobs();
    void startRead(const QString& path);
    void cancelJobs();
    void rebuildRows();
    void indexResult();
    void clearStackModel();
    void selectRow();
    void selectStack();
    void resolveStack();
    void showStack();
    void updateSummary();
    void updateControls();
    void retranslate();
    const ks::evidence::pool::Group* selectedGroup() const;

    QPushButton* m_open = nullptr;
    QPushButton* m_cancel = nullptr;
    QPushButton* m_resolve = nullptr;
    QPushButton* m_module = nullptr;
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
    QSortFilterProxyModel* m_proxy = nullptr;
    QTimer* m_poll = nullptr;
    std::shared_ptr<ReadJob> m_readJob;
    std::shared_ptr<ResolveJob> m_resolveJob;
    std::shared_ptr<const ks::evidence::pool::TraceReadResult> m_result;
    std::unordered_map<std::uint64_t, const ks::evidence::pool::TraceImage*> m_images;
    std::unordered_set<std::uint64_t> m_kernelImages;
    std::unordered_map<std::uint64_t, const ks::evidence::pool::Group*> m_groups;
    ReadProvider m_reader;
    ResolveProvider m_resolver;
    std::function<void(const QString&)> m_openModuleDetails;
    QString m_path;
    QString m_pendingPath;
    QString m_modulePath;
    std::vector<std::wstring> m_symbols;
    std::uint64_t m_symbolGroupId = 0;
};
