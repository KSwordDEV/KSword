#pragma once

#include <QString>
#include <QStringList>
#include <QWidget>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class QCheckBox;
class QComboBox;
class QEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QTabWidget;
class QTableWidget;
struct ScannerAsyncState;

namespace ks::ui
{
    class BinaryOverviewBar;
    class MemoryEditorWidget;
}

namespace ks::scanner
{
    struct AtomicPatchResult;
    struct BinaryScanResult;
}

// ScannerDock 作用：
// - 提供 PE/ELF/Mach-O/ISO9660 结构化扫描和攻击路径检测页；
// - 提供“原字节比较 + 等长替换 + 原子提交”的普通文件安全编辑页；
// - 扫描与大文件复制均在线程池执行，避免阻塞主界面。
class ScannerDock final : public QWidget
{
public:
    // 构造函数作用：建立扫描器界面并进入“等待选择文件”状态。
    // 参数 parent：Qt 父控件；返回值：无。
    explicit ScannerDock(QWidget* parent = nullptr);

    // 析构函数作用：使尚未回到 UI 线程的异步结果失效。
    ~ScannerDock() override;

protected:
    // changeEvent 作用：语言切换时重译固定控件和已显示的扫描结果。
    // 参数 event：Qt 事件；返回值：无。
    void changeEvent(QEvent* event) override;

private:
    // 以下函数分别负责构建/重译界面、选择目标，以及启动异步扫描或写入。
    void buildUi();
    void buildAnalysisUi();
    void retranslateAnalysisUi();
    void renderAnalysisResult();
    void navigateAnalysisOffset(std::uint64_t offset, bool showDisassembly = false);
    void loadAnalysisWindow(std::uint64_t offset);
    void updateAnalysisAddress(std::uint64_t offset);
    void jumpAnalysisAddress();
    void retranslateUi();
    void chooseFile();
    void beginScan();
    void beginPatch();

    // finishScan/finishPatch 作用：仅接收当前 generation 的后台结果并更新 UI。
    // generation：任务代次；scannedPath/patchedPath：任务实际使用的目标路径。
    void finishScan(
        std::uint64_t generation,
        const QString& scannedPath,
        std::shared_ptr<ks::scanner::BinaryScanResult> result);
    void finishPatch(
        std::uint64_t generation,
        const QString& patchedPath,
        std::shared_ptr<ks::scanner::AtomicPatchResult> result);

    // renderResult 作用：把格式中立模型渲染为摘要、头、结构表和诊断页。
    void renderResult(const ks::scanner::BinaryScanResult& result);
    void clearResultTabs();

    // createReadOnlyTable 作用：创建统一只读表格；调用方负责填充行列。
    QTableWidget* createReadOnlyTable(QWidget* parent = nullptr) const;

    // createStructuredTablePage 作用：为宽表建立互补 A/B/C 列组和表头列菜单。
    QWidget* createStructuredTablePage(QTableWidget* table, int columnCount) const;

    // createAttackPathPage 作用：展示规则结论、评分和逐条可复核证据。
    QWidget* createAttackPathPage(const ks::scanner::BinaryScanResult& result) const;

    // 以下辅助函数统一处理本地化、诊断级别和状态栏状态。
    QString translated(const char* key, const char* fallback) const;
    QString localizedTableTitle(const std::string& tableId, const std::string& fallback) const;
    QString localizedColumnTitle(const std::string& fallback) const;
    QString localizedTableValue(
        const std::string& tableId,
        int column,
        const std::string& fallback) const;
    QString localizedDiagnosticMessage(
        const std::string& code,
        const std::string& fallback) const;
    QString diagnosticSeverityText(int severity) const;
    QString attackPathSeverityText(int severity) const;
    QString attackPathStageText(const std::string& stage) const;
    QString attackPathEvidenceText(const std::string& code) const;
    void setStatus(const char* key, const char* fallback, const QStringList& arguments = {});
    void refreshStatus();
    void setScanBusy(bool busy);
    void setPatchBusy(bool busy);

    QLabel* m_pathLabel = nullptr; // m_pathLabel：目标路径字段标题。
    QLineEdit* m_pathEdit = nullptr; // m_pathEdit：当前扫描/编辑目标路径。
    QPushButton* m_browseButton = nullptr; // m_browseButton：打开普通文件选择器。
    QPushButton* m_scanButton = nullptr; // m_scanButton：启动结构化扫描。
    QLabel* m_statusLabel = nullptr; // m_statusLabel：展示当前任务及最终结果。

    QTabWidget* m_mainTabs = nullptr; // m_mainTabs：扫描与安全编辑两大功能页。
    QTabWidget* m_resultTabs = nullptr; // m_resultTabs：本次扫描产生的结构化子页。
    QWidget* m_inspectionPage = nullptr; // m_inspectionPage：只读解析页容器。
    QWidget* m_editorPage = nullptr; // m_editorPage：等长字节编辑页容器。

    QWidget* m_analysisPage = nullptr;
    ks::ui::BinaryOverviewBar* m_overviewBar = nullptr;
    ks::ui::MemoryEditorWidget* m_analysisEditor = nullptr;
    QLabel* m_analysisLegend = nullptr;
    QLabel* m_analysisSectionLabel = nullptr;
    QComboBox* m_analysisSectionCombo = nullptr;
    QComboBox* m_analysisAddressKind = nullptr;
    QLineEdit* m_analysisAddressEdit = nullptr;
    QPushButton* m_analysisJumpButton = nullptr;
    QPushButton* m_analysisEntryButton = nullptr;
    QPushButton* m_analysisPreviousButton = nullptr;
    QPushButton* m_analysisNextButton = nullptr;
    QPushButton* m_analysisFindButton = nullptr;
    QLabel* m_analysisPosition = nullptr;
    std::shared_ptr<const std::vector<std::uint8_t>> m_analysisSnapshot;
    std::uint64_t m_currentFileOffset = 0;
    std::uint64_t m_analysisNavigationGeneration = 0;
    bool m_analysisArchitectureInitialized = false;
    bool m_analysisLoading = false;

    QLabel* m_offsetLabel = nullptr; // m_offsetLabel：文件偏移字段标题。
    QLineEdit* m_offsetEdit = nullptr; // m_offsetEdit：十进制/十六进制文件偏移。
    QLabel* m_replacementLabel = nullptr; // m_replacementLabel：替换字节字段标题。
    QLineEdit* m_replacementEdit = nullptr; // m_replacementEdit：十六进制替换内容。
    QCheckBox* m_backupCheckBox = nullptr; // m_backupCheckBox：是否保留时间戳备份。
    QCheckBox* m_riskCheckBox = nullptr; // m_riskCheckBox：最终确认前的风险核对。
    QPushButton* m_applyPatchButton = nullptr; // m_applyPatchButton：执行安全写入。

    std::shared_ptr<ks::scanner::BinaryScanResult> m_lastResult; // m_lastResult：语言切换时重绘的最近结果。
    QString m_statusKey; // m_statusKey：当前状态对应的语言包键。
    QString m_statusFallback; // m_statusFallback：语言包缺失时使用的中文文本。
    QStringList m_statusArguments; // m_statusArguments：依次替换状态文本中的占位符。
    std::atomic<std::uint64_t> m_scanGeneration{ 0 }; // m_scanGeneration：淘汰过期扫描回调。
    std::atomic<std::uint64_t> m_patchGeneration{ 0 }; // m_patchGeneration：淘汰过期写入回调。
    std::shared_ptr<ScannerAsyncState> m_asyncState; // m_asyncState：跨线程投递时保护 owner 生命周期。
    bool m_scanBusy = false; // m_scanBusy：扫描任务是否正在运行。
    bool m_patchBusy = false; // m_patchBusy：原子写入任务是否正在运行。
};
