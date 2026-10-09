#pragma once
#include <QWidget>
#include <QJsonObject>
#include <memory>
#include <functional>
#include "../../../shared/evidence/PoolTraceCapturePolicy.h"
class QLabel;
class QPushButton;
class QSpinBox;
class CodeEditorWidget;
class QTableWidget;
class QTimer;
class QProcess;
class QTemporaryDir;
class QTabWidget;
class PoolAllocationAnalysisWidget;

// Separate consumer observations and prospective allocation history. Neither
// data source is added to the PFN ledger or used to rename its residual.
class MemoryConsumerEvidencePage final : public QWidget {
public:
    explicit MemoryConsumerEvidencePage(QWidget* parent = nullptr);
    ~MemoryConsumerEvidencePage() override;
    QJsonObject evidence() const;
    std::function<void(const QString&)> openModuleDetails;
protected:
    void changeEvent(QEvent*) override;
private:
    struct GpuJob;
    void startGpu();
    void pollGpu();
    void rebuildGpu();
    void startTrace();
    void stopTrace();
    void runTrace(const QStringList& arguments, ksword::pool_trace::Command action);
    void traceFinished(int exitCode, bool normal);
    void appendCommandOutput(const QString& output);
    void updateTraceControls();
    void persistTrace();
    void retranslate();
    QPushButton* m_gpuButton = nullptr;
    QPushButton* m_traceStart = nullptr;
    QPushButton* m_traceStop = nullptr;
    QSpinBox* m_duration = nullptr;
    QLabel* m_note = nullptr;
    QLabel* m_gpuStatus = nullptr;
    QTableWidget* m_gpuTable = nullptr;
    CodeEditorWidget* m_traceLog = nullptr;
    QTabWidget* m_detailTabs = nullptr;
    PoolAllocationAnalysisWidget* m_poolAnalysis = nullptr;
    QTimer* m_captureTimer = nullptr;
    QTimer* m_commandTimer = nullptr;
    QProcess* m_process = nullptr;
    std::shared_ptr<GpuJob> m_gpuJob;
    std::shared_ptr<GpuJob> m_gpuResult;
    QString m_instance, m_output, m_metadataOutput, m_wpr, m_commandOutput, m_profileSpec, m_commandStarted;
    std::unique_ptr<QTemporaryDir> m_profileDirectory;
    QJsonObject m_traceEvidence;
    ksword::pool_trace::CaptureState m_capture;
    int m_captureDuration = 30;
    qint64 m_previousOutputModified = 0, m_previousOutputSize = -1;
    bool m_outputExisted = false, m_shuttingDown = false;
    bool m_commandTimedOut = false, m_commandOutputTruncated = false, m_commandFailedToStart = false;
};
