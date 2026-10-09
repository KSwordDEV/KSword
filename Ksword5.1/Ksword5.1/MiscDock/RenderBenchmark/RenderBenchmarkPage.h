#pragma once

// ============================================================
// RenderBenchmarkPage.h
// 作用：
// 1) 在“杂项”中提供窗口渲染与 DWM 合成的基准测试入口；
// 2) 量化主窗口一次整树重绘的真实成本，拆出背景层与子控件树各自占比；
// 3) 用同构离屏窗口模拟拖动，对比“刷新时重绘整树”与“不重绘”的掉帧率；
// 4) 抓屏采样验证本机 acrylic 是否真的生效、是否跟随窗口位置重采样；
// 5) 用 WM_NULL 往返探测任意目标窗口在移动期间的 UI 线程卡顿。
// 设计说明：
// - 全部测量都在 UI 线程执行：被测对象就是 UI 线程本身，放后台线程测不到；
//   因此每项测试都会短暂占用界面，运行期间禁用按钮并显示状态。
// - 主窗口那项用 QWidget::render 渲染到离屏位图，不触碰屏幕上的真实像素，
//   既拿到与真实重绘同量级的耗时，又不会让用户看到界面闪烁。
// - 结论会随 Windows 版本变化（未公开的 ACCENT_POLICY 行为尤其如此），
//   所以这里只报告本机实测值，不写死任何“应该是多少”的判断。
// ============================================================

#include "../../Framework.h"

#include <QString>
#include <QVector>
#include <QWidget>

class QComboBox;
class QLabel;
class CodeEditorWidget;
class QProgressBar;
class QPushButton;
class QSpinBox;

namespace ks::misc
{
    // BenchmarkSampleSummary 作用：
    // - 汇总一组耗时样本，四项测试共用同一套统计口径；
    // - overBudgetCount 按 60fps 帧预算（16.7ms）计数，直接对应“掉帧”。
    struct BenchmarkSampleSummary
    {
        double averageMs = 0.0;   // averageMs：样本平均耗时。
        double p95Ms = 0.0;       // p95Ms：95 分位耗时，比平均值更能反映卡顿感。
        double worstMs = 0.0;     // worstMs：最差单次耗时。
        int overBudgetCount = 0;  // overBudgetCount：超出帧预算的样本数。
        int sampleCount = 0;      // sampleCount：有效样本总数。
    };

    // TargetWindowEntry 作用：
    // - 响应探针的候选目标窗口；
    // - 保存 HWND 数值而不是指针，避免窗口销毁后悬垂。
    struct TargetWindowEntry
    {
        quint64 windowHandleValue = 0; // windowHandleValue：目标窗口句柄的整数形式。
        QString displayText;           // displayText：下拉框展示用的“标题 - 进程名 (PID)”。
        bool belongsToSelf = false;    // belongsToSelf：是否是本进程窗口，默认优先选中。
    };

    class RenderBenchmarkPage final : public QWidget
    {
    public:
        // 构造函数：只建界面，不自动跑任何测试。
        // - 基准测试会占用 UI 线程若干秒，必须由用户显式发起；
        // - 参数 parent：Qt 父控件。
        explicit RenderBenchmarkPage(QWidget* parent = nullptr);
        ~RenderBenchmarkPage() override = default;

    private:
        // initializeUi：创建说明、四个测试分组与报告区。
        void initializeUi();
        // initializeConnections：连接各测试按钮与报告区操作。
        void initializeConnections();

        // runMainWindowRepaintBenchmark：
        // - 量主窗口根容器一次整树重绘的耗时，并拆出仅背景层的部分；
        // - 用离屏 render，不影响屏幕上的真实界面。
        void runMainWindowRepaintBenchmark();

        // runDragSimulationBenchmark：
        // - 建一个与主窗口同构的测试窗口（透明 + 磨砂 + 满屏透明表格），
        //   模拟 60fps 拖动，对比“每次刷新重绘整树”与“不重绘”两种策略。
        void runDragSimulationBenchmark();

        // runCompositionProbe：
        // - 铺两块纯色面板当背景，把磨砂窗口在其间移动，抓屏采样平均色；
        // - 判定 acrylic 是否真的生效，以及是否自动跟随窗口位置重采样。
        void runCompositionProbe();

        // runWindowResponseProbe：
        // - 对选定目标窗口连续 SetWindowPos 模拟拖动，
        //   每帧用 WM_NULL 往返测该窗口 UI 线程被阻塞的时长；
        // - 测完把窗口放回原位置。
        void runWindowResponseProbe();

        // runAllBenchmarks：按顺序跑完四项，中间保持界面可响应。
        void runAllBenchmarks();

        // refreshTargetWindowList：枚举当前可见顶层窗口，填充响应探针的目标下拉框。
        void refreshTargetWindowList();

        // appendReportLine / appendReportSection：把结果写进报告区。
        void appendReportLine(const QString& lineText);
        void appendReportSection(const QString& titleText);

        // appendSummaryLine：按统一格式输出一组样本的统计值。
        void appendSummaryLine(const QString& labelText, const BenchmarkSampleSummary& summary);

        // setBusy：测试期间禁用所有发起按钮，避免重入。
        void setBusy(bool busy, const QString& statusText = QString());

        // copyReportToClipboard / saveReportToFile：报告导出。
        void copyReportToClipboard();
        void saveReportToFile();

    private:
        QLabel* m_statusLabel = nullptr;              // m_statusLabel：当前运行状态与提示。
        QPushButton* m_runAllButton = nullptr;        // m_runAllButton：顺序执行全部测试。
        QPushButton* m_runRepaintButton = nullptr;    // m_runRepaintButton：主窗口重绘基准。
        QPushButton* m_runDragButton = nullptr;       // m_runDragButton：拖动 A/B 对比。
        QPushButton* m_runCompositionButton = nullptr;// m_runCompositionButton：DWM 合成能力探测。
        QPushButton* m_runResponseButton = nullptr;   // m_runResponseButton：目标窗口响应探针。
        QPushButton* m_refreshTargetsButton = nullptr;// m_refreshTargetsButton：重新枚举候选窗口。
        QPushButton* m_copyReportButton = nullptr;    // m_copyReportButton：复制报告。
        QPushButton* m_saveReportButton = nullptr;    // m_saveReportButton：导出报告。
        QPushButton* m_clearReportButton = nullptr;   // m_clearReportButton：清空报告。

        QSpinBox* m_repaintIterationSpin = nullptr;   // m_repaintIterationSpin：重绘基准的采样次数。
        QSpinBox* m_dragFrameSpin = nullptr;          // m_dragFrameSpin：拖动模拟的帧数。
        QSpinBox* m_dragRowSpin = nullptr;            // m_dragRowSpin：测试窗口内表格行数。
        QSpinBox* m_responseFrameSpin = nullptr;      // m_responseFrameSpin：响应探针的帧数。
        QComboBox* m_targetWindowCombo = nullptr;     // m_targetWindowCombo：响应探针的目标窗口。

        QProgressBar* m_progressBar = nullptr;        // m_progressBar：长测试的进度提示。
        CodeEditorWidget* m_reportEdit = nullptr;       // m_reportEdit：结果报告区。

        QVector<TargetWindowEntry> m_targetWindows;   // m_targetWindows：候选目标窗口快照。
        bool m_busy = false;                          // m_busy：是否有测试正在执行。
        // m_batchRunning：是否处于“运行全部测试”批次中。
        // 单项测试结束时会解除忙碌态，若不额外记住批次状态，
        // 两项之间放行事件的那一小段时间按钮会重新可点，用户能插进来触发第二个测试。
        bool m_batchRunning = false;
    };
}
