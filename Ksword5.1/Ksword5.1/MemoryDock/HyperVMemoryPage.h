#pragma once
#include "HyperVMemoryEvidence.h"
#include <QWidget>
class QLabel;
class QPushButton;
class QLineEdit;
class QProgressBar;
class QTableWidget;
class CodeEditorWidget;
class QTabWidget;
class MemoryAttributionChart;
namespace ksword::pfn { struct Scan; }

class HyperVMemoryPage final : public QWidget {
public:
    explicit HyperVMemoryPage(QWidget* parent = nullptr);
    ~HyperVMemoryPage() override;
    void startCollection();
    void setSnapshotContext(const QString& time, std::uint64_t remainder);
    void setPfnContext(const std::shared_ptr<ksword::pfn::Scan>& scan);
protected:
    void changeEvent(QEvent*) override;
private:
    void poll();
    void retranslate();
    void rebuild();
    void rebuildPartitions();
    void showPartition(int index);
    void exportEvidence();
    QPushButton* m_collect = nullptr;
    QPushButton* m_cancel = nullptr;
    QPushButton* m_export = nullptr;
    QLineEdit* m_filter = nullptr;
    QLabel* m_summary = nullptr;
    QProgressBar* m_progress = nullptr;
    MemoryAttributionChart* m_chart = nullptr;
    QTabWidget* m_tabs = nullptr;
    QTableWidget* m_partitions = nullptr;
    QTableWidget* m_host = nullptr;
    QTableWidget* m_processes = nullptr;
    QTableWidget* m_sources = nullptr;
    CodeEditorWidget* m_detail = nullptr;
    CodeEditorWidget* m_evidence = nullptr;
    ksword::hyperv::Context m_latestContext, m_jobContext, m_resultContext;
    std::shared_ptr<ksword::hyperv::Job> m_job;
    std::shared_ptr<ksword::hyperv::Snapshot> m_snapshot, m_previous;
};
