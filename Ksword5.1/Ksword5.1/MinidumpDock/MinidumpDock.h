#include "../UI/StructuredFieldView.h"
#pragma once

// ============================================================
// MinidumpDock.h
// 作用：
// - 提供“转储分析”页：打开并解析 Windows 转储文件；
// - 支持用户态 MDMP minidump（应用崩溃转储）与内核 PAGEDUMP/PAGEDU64
//   转储（蓝屏 DMP，含 C:\Windows\Minidump 小型转储）；
// - 展示诊断结论、肇事模块候选、概览、异常/停止码、调用栈、寄存器、
//   流目录、模块/驱动、线程、内存、原始内存预览、句柄、已卸载模块与全文报告；
//   解析在线程池执行，不阻塞 UI。
// 调用方式：
// - MainWindow 按 dockKey "minidump" 懒加载创建本控件；
// - 用户通过工具栏选择文件后自动解析，也可回车/点解析按钮重析。
// ============================================================

#include <QString>
#include <QStringList>
#include <QWidget>

#include <atomic>
#include <cstdint>
#include <memory>

class CodeEditorWidget;
class QEvent;
class QLabel;
class QLineEdit;
class QPushButton;
class QTabWidget;
class QTableWidget;
class QTextBrowser;
class DumpMemoryView;
struct MinidumpAsyncState;

namespace ks::minidump
{
    struct DumpParseResult;
}

// MinidumpDock 作用：转储分析页的根控件；负责工具栏、状态栏与结果页签。
class MinidumpDock final : public QWidget
{
public:
    // 构造函数作用：建立界面并进入“等待选择转储文件”状态。
    // 参数 parent：Qt 父控件；返回值：无。
    explicit MinidumpDock(QWidget* parent = nullptr);

    // 析构函数作用：使尚未回到 UI 线程的异步解析结果失效。
    ~MinidumpDock() override;

    // openDumpFile 作用：由外部指定转储文件并立即开始解析。
    // 参数 filePath：转储文件完整路径；返回值：无。
    // 供 MainWindow 的"发现新转储"询问弹窗在用户确认后调用。
    void openDumpFile(const QString& filePath);

protected:
    // changeEvent 作用：语言切换时重译固定控件并重绘已有解析结果。
    // 参数 event：Qt 事件；返回值：无。
    void changeEvent(QEvent* event) override;

private:
    // 以下函数负责构建/重译界面、选择文件、启动异步解析与导出报告。
    void buildUi();
    void retranslateUi();
    void chooseFile();
    void beginParse();
    void exportReport();

    // finishParse 作用：仅接收当前 generation 的后台解析结果并更新 UI。
    // generation：任务代次；result：自包含的解析结果。
    void finishParse(
        std::uint64_t generation,
        std::shared_ptr<ks::minidump::DumpParseResult> result);

    // renderResult 作用：把解析结果渲染为概览、异常、流、模块等页签。
    // 参数 result：解析结果；返回值：无。实现位于 MinidumpDock.Tables.cpp。
    void renderResult(const ks::minidump::DumpParseResult& result);

    // promptKswordRelatedCrash 作用：解析结果指向 KSword 自身组件时引导上报。
    // 参数 result：解析结果；返回值：无。
    // 只在命中肇事候选/调用栈/已卸载表时弹出——仅出现在已加载模块表里
    // 不构成证据，KSword 运行期间它必然在表里。
    void promptKswordRelatedCrash(const ks::minidump::DumpParseResult& result);

    // clearResultTabs 作用：移除全部结果页签（控件复用，不销毁）。
    void clearResultTabs();

    // createReadOnlyTable 作用：创建统一风格的只读表格；调用方负责填充。
    // 参数 parent：父控件；返回值：新表格。实现位于 MinidumpDock.Tables.cpp。
    QTableWidget* createReadOnlyTable(QWidget* parent = nullptr) const;

    // createStructuredTablePage 作用：为宽表建立互补 A/B/C 列组预设与
    // 表头右键逐列显隐菜单；5 列以内直接返回原表。
    // 参数 table：目标表格；columnCount：列数；返回值：包装后的页面控件。
    QWidget* createStructuredTablePage(QTableWidget* table, int columnCount) const;

    // buildReportText 作用：把解析结果拼成全文报告（中文规范文本）。
    // 参数 result：解析结果；返回值：报告文本。实现位于 MinidumpDock.Tables.cpp。
    ks::ui::FieldDocument buildReportText(const ks::minidump::DumpParseResult& result) const;

    // 以下辅助函数统一处理本地化与状态栏。
    QString translated(const char* key, const char* fallback) const;
    void setStatus(const char* key, const char* fallback, const QStringList& arguments = {});
    void refreshStatus();
    void setBusy(bool busy);

    QLabel* m_pathLabel = nullptr;      // m_pathLabel：目标路径字段标题。
    QLineEdit* m_pathEdit = nullptr;    // m_pathEdit：当前转储文件路径。
    QLabel* m_symbolPathLabel = nullptr;   // m_symbolPathLabel：符号路径字段标题。
    QLineEdit* m_symbolPathEdit = nullptr; // m_symbolPathEdit：符号搜索路径，留空则用本地默认路径。
    QPushButton* m_browseButton = nullptr;   // m_browseButton：打开文件选择器。
    QPushButton* m_systemDirButton = nullptr; // m_systemDirButton：定位系统蓝屏转储目录。
    QPushButton* m_parseButton = nullptr;    // m_parseButton：启动解析。
    QPushButton* m_exportButton = nullptr;   // m_exportButton：导出全文报告。
    QLabel* m_statusLabel = nullptr;    // m_statusLabel：展示当前任务及最终结果。

    QTabWidget* m_resultTabs = nullptr; // m_resultTabs：解析结果页签容器。
    // m_analysisView：诊断结论页。
    // 这里刻意不用表格：结论是"一句话判断 + 证据链 + 建议"这种叙述性内容，
    // 塞进"项目-内容"两列会让每条证据都重复一遍"发现"二字，关键结论也淹没在行里。
    QTextBrowser* m_analysisView = nullptr;
    QTableWidget* m_blameTable = nullptr;     // m_blameTable：肇事模块候选表。
    QTableWidget* m_stackTable = nullptr;     // m_stackTable：疑似调用栈表。
    QTableWidget* m_registerTable = nullptr;  // m_registerTable：崩溃点寄存器表。
    QTableWidget* m_overviewTable = nullptr;  // m_overviewTable：概览“属性-值”表。
    QTableWidget* m_exceptionTable = nullptr; // m_exceptionTable：异常/停止码详情表。
    QTableWidget* m_executionContextTable = nullptr; // m_executionContextTable：崩溃现场 CPU/线程/进程快照表。
    QTableWidget* m_streamTable = nullptr;    // m_streamTable：流目录/TRIAGE 布局表。
    QTableWidget* m_moduleTable = nullptr;    // m_moduleTable：模块/驱动表。
    QTableWidget* m_threadTable = nullptr;    // m_threadTable：线程表。
    QTableWidget* m_memoryTable = nullptr;    // m_memoryTable：内存区域表。
    QTableWidget* m_handleTable = nullptr;    // m_handleTable：句柄表。
    QTableWidget* m_unloadedTable = nullptr;  // m_unloadedTable：已卸载模块表。
    QTableWidget* m_symbolTable = nullptr;    // m_symbolTable：逐模块符号匹配状态表。
    QTableWidget* m_poolTagTable = nullptr;   // m_poolTagTable：池标记候选与归属表。
    QTableWidget* m_crashHistoryTable = nullptr; // m_crashHistoryTable：系统崩溃时间线表。
    QWidget* m_stackPage = nullptr;     // m_stackPage：调用栈表的 A/B/C 包装页。
    QWidget* m_modulePage = nullptr;    // m_modulePage：模块表的 A/B/C 包装页。
    QWidget* m_threadPage = nullptr;    // m_threadPage：线程表的 A/B/C 包装页。
    QWidget* m_memoryPage = nullptr;    // m_memoryPage：内存表的 A/B/C 包装页。
    QWidget* m_handlePage = nullptr;    // m_handlePage：句柄表的 A/B/C 包装页。
    QTabWidget* m_rawMemoryTabs = nullptr; // 已验证 TRIAGE 字节块的只读分页预览。
    DumpMemoryView* m_memoryView = nullptr; // m_memoryView：按虚拟地址重开 DMP 的只读内存查看器。
    ks::ui::StructuredFieldView* m_reportEditor = nullptr; // m_reportEditor：全文报告只读编辑器。

    std::shared_ptr<ks::minidump::DumpParseResult> m_lastResult; // m_lastResult：语言切换时重绘的最近结果。
    QString m_statusKey;        // m_statusKey：当前状态对应的语言包键。
    QString m_statusFallback;   // m_statusFallback：语言包缺失时使用的中文文本。
    QStringList m_statusArguments; // m_statusArguments：依次替换状态文本中的占位符。
    std::atomic<std::uint64_t> m_parseGeneration{ 0 }; // m_parseGeneration：淘汰过期解析回调。
    std::shared_ptr<MinidumpAsyncState> m_asyncState; // m_asyncState：跨线程投递时保护 owner 生命周期。
    bool m_parseBusy = false;   // m_parseBusy：解析任务是否正在运行。
};
