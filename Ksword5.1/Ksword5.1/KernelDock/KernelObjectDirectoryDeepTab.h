#pragma once

// ============================================================
// KernelObjectDirectoryDeepTab.h
// 作用说明：
// 1) 提供“对象命名空间 / 目录递归”独立页面；
// 2) 页面自行启动后台线程调用 KernelObjectDirectoryDeepWorker；
// 3) 不依赖 KernelDock 私有成员，便于后续集成到二级 Tab。
// ============================================================

#include "KernelObjectDirectoryDeepWorker.h"

#include <QWidget>

#include <atomic>
#include <vector>

#include "../UI/StructuredFieldView.h"
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTreeWidget;
class QTreeWidgetItem;

// KernelObjectDirectoryDeepTab
// - 输入：用户在 UI 中提供根路径和最大递归深度。
// - 处理：后台线程执行 NtOpenDirectoryObject + NtQueryDirectoryObject 递归枚举。
// - 返回：无直接返回值；结果通过 QTreeWidget 和详情框展示。
class KernelObjectDirectoryDeepTab final : public QWidget
{
public:
    explicit KernelObjectDirectoryDeepTab(QWidget* parent = nullptr);
    ~KernelObjectDirectoryDeepTab() override = default;

private:
    // initializeUi：
    // - 作用：创建根路径输入、刷新按钮、深度输入、结果树与详情框。
    // - 返回：无。
    void initializeUi();

    // startRefresh：
    // - 作用：读取 UI 参数并启动后台递归枚举。
    // - 返回：无；刷新完成后通过 QueuedConnection 回填 UI。
    void startRefresh();

    // setRefreshRunning：
    // - 作用：统一切换刷新按钮、状态标签与输入控件状态。
    // - 参数 running：true=刷新中；false=空闲。
    // - 返回：无。
    void setRefreshRunning(bool running);

    // rebuildTree：
    // - 作用：把 m_rows 重建为树形显示。
    // - 返回：无。
    void rebuildTree();

    // showCurrentItemDetail：
    // - 作用：根据当前树节点的数据索引显示详细字段。
    // - 返回：无。
    void showCurrentItemDetail();

    // formatEntryDetail：
    // - 作用：把单条枚举记录格式化为详情文本。
    // - 参数 entry：Worker 返回的一条对象记录。
    // - 返回：可直接显示在 ks::ui::StructuredFieldView 的多行文本。
    static ks::ui::FieldDocument formatEntryDetail(const KernelObjectDirectoryDeepEntry& entry);

private:
    QLineEdit* m_rootPathEdit = nullptr;       // m_rootPathEdit：Object Manager 根路径输入框。
    QPushButton* m_refreshButton = nullptr;    // m_refreshButton：启动后台递归刷新。
    QSpinBox* m_maxDepthSpinBox = nullptr;     // m_maxDepthSpinBox：最大递归深度输入。
    QLabel* m_statusLabel = nullptr;           // m_statusLabel：刷新状态摘要。
    QTreeWidget* m_resultTree = nullptr;       // m_resultTree：递归结果树。
    ks::ui::StructuredFieldView* m_detailEditor = nullptr; // m_detailEditor：当前节点详情。

    std::atomic_bool m_refreshRunning{ false }; // m_refreshRunning：防止重复刷新。
    std::vector<KernelObjectDirectoryDeepEntry> m_rows; // m_rows：最近一次 Worker 结果。
};
