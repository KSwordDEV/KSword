#pragma once

// ============================================================
// KernelObjectTypeMatrixTab.h
// 作用说明：
// 1) 提供对象类型统计与可枚举策略矩阵；
// 2) 复用 KernelDockQueryWorker 的 ObjectTypesInformation 解析；
// 3) 通过 ArkDriverClient 合并 R0 ObTypeIndexTable 槽位与名称/索引验证。
// ============================================================

#include "KernelDock.h"

#include <QWidget>

#include <atomic>
#include <vector>

class QLabel;
class QLineEdit;
class QPushButton;
class QPoint;
class QTableWidget;
class QTableWidgetItem;
#include "../UI/StructuredFieldView.h"

class KernelObjectTypeMatrixTab final : public QWidget
{
public:
    explicit KernelObjectTypeMatrixTab(QWidget* parent = nullptr);
    ~KernelObjectTypeMatrixTab() override = default;

    void requestInitialRefresh();
    static QString strategyForType(const QString& typeNameText);
    static QString formatAccessMask(std::uint32_t accessMask);

private:
    struct R0SnapshotState
    {
        bool attempted = false;
        bool transportOk = false;
        bool unsupported = false;
        std::uint32_t status = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t tableAddress = 0;
        std::uint64_t snapshotHash = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t otNameOffset = 0xFFFFFFFFUL;
        std::uint32_t otIndexOffset = 0xFFFFFFFFUL;
        std::uint32_t returnedCount = 0;
        QString diagnosticText;
    };

    void initializeUi();
    void initializeConnections();
    void refreshAsync();
    void applyRefreshResult(std::vector<KernelObjectTypeEntry> rows, R0SnapshotState r0State, const QString& errorText, bool success);
    void rebuildTable();
    void showContextMenu(const QPoint& localPosition);
    void copyCurrentRow() const;
    void updateDetailForRow(int tableRow);
    ks::ui::FieldDocument buildDetailText(const KernelObjectTypeEntry& entry) const;

    // buildDiagnosticDetailText：
    // - 输入：刷新失败、无数据或筛选无结果的原因；
    // - 处理：展开当前筛选、数据来源和下一步排查方向；
    // - 返回：可直接写入详情编辑器的只读文本。
    ks::ui::FieldDocument buildDiagnosticDetailText(const QString& reasonText) const;

    // insertDiagnosticRow：
    // - 输入：诊断行标题和详情文本；
    // - 处理：向表格写入一行可复制的占位记录；
    // - 返回：无返回值，详情文本保存在 UserRole + 2。
    void insertDiagnosticRow(const QString& titleText, const ks::ui::FieldDocument& detailText);

    bool rowMatchesFilter(const KernelObjectTypeEntry& entry) const;
    std::size_t sourceIndexForTableRow(int tableRow) const;
    static QTableWidgetItem* readOnlyItem(const QString& text);

private:
    QPushButton* m_refreshButton = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTableWidget* m_table = nullptr;
    ks::ui::StructuredFieldView* m_detailEditor = nullptr;

    std::atomic_bool m_refreshing{ false };
    bool m_initialRefreshRequested = false;
    std::vector<KernelObjectTypeEntry> m_rows;
    R0SnapshotState m_r0State;
    ks::ui::FieldDocument m_diagnosticDocument;
};
