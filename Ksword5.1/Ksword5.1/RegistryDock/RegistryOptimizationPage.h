#include "../UI/StructuredFieldView.h"
#pragma once

// ============================================================
// RegistryOptimizationPage.h
// Purpose:
// 1) Dynamically load Dism++ style registry optimization JSON from profiles/;
// 2) Build the System Optimization UI at runtime instead of hardcoding rows;
// 3) Apply selected registry/service/explorer actions with explicit confirmation.
// ============================================================

#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QWidget>

#include <cstdint>

class QLabel;
class QLineEdit;
class QPushButton;
class QProcess;
class QSplitter;
class QTableWidget;
class QTemporaryDir;
class QTreeWidget;
class QTimer;
class CodeEditorWidget;

// RegistryOptimizationPage:
// - Input: parent widget plus profiles/registry_optimization_items.json at runtime;
// - Processing: parses item/group/scope/state/action objects and creates controls per visible row;
// - Return behavior: QWidget subclass has no direct return value; status is surfaced in the UI.
class RegistryOptimizationPage final : public QWidget
{
public:
    // Constructor:
    // - Input parent: Qt parent widget owning this page;
    // - Processing: builds controls, wires signals, then loads the JSON profile;
    // - Return: no explicit return value.
    explicit RegistryOptimizationPage(QWidget* parent = nullptr);
    ~RegistryOptimizationPage() override;

private:
    // OptimizationState:
    // - Input: parsed from one JSON states[] object;
    // - Processing: stores label, detection condition, warning, and action list;
    // - Return: value object used by table controls.
    struct OptimizationState
    {
        QString tagText;
        QString labelText;
        QString conditionText;
        QString warningText;
        QVector<QJsonObject> actionList;
    };

    // OptimizationScope:
    // - Input: parsed from one JSON scopes[] object;
    // - Processing: groups state choices by Current/Default/System scope;
    // - Return: value object used by one table row.
    struct OptimizationScope
    {
        QString scopeText;
        QString conditionText;
        QVector<OptimizationState> stateList;
    };

    // OptimizationItem:
    // - Input: parsed from one top-level JSON item object;
    // - Processing: keeps item metadata and all scope definitions;
    // - Return: value object stored in m_itemList.
    struct OptimizationItem
    {
        int groupIndex = 0;
        int itemIndex = 0;
        QString groupNameText;
        QString itemNameText;
        QString itemTypeText;
        QString groupConditionText;
        QString itemConditionText;
        QString warningText;
        QVector<OptimizationScope> scopeList;
    };

    // VisibleRow:
    // - Input: item/scope indexes selected by current group/filter;
    // - Processing: maps QTableWidget rows back to parsed model objects;
    // - Return: lightweight row reference.
    struct VisibleRow
    {
        int itemIndex = -1;
        int scopeIndex = -1;
    };

private:
    // ColumnPreset：
    // - 用途：记录系统优化表格当前使用的 A/B/自定义列组；
    // - A：操作视图，B：诊断视图，Custom：用户通过表头菜单手动改列。
    enum class ColumnPreset
    {
        A,
        B,
        Custom
    };

private:
    void initializeUi();
    void initializeConnections();
    void loadOptimizationProfile();
    QStringList profileCandidatePaths() const;
    void rebuildGroupTree();
    void rebuildItemTable();
    void refreshVisibleStates();
    void refreshVisibleRowState(int tableRow);
    void cancelStateRefresh();
    void updateDetailPanel(int tableRow);
    void updateStatusText(const QString& text);
    void applyColumnPreset(ColumnPreset preset);
    void refreshColumnPresetButtonStyles();
    void showHeaderColumnMenu(const QPoint& localPos);
    bool isColumnVisibleInPreset(int columnIndex, ColumnPreset preset) const;

    const OptimizationState* selectedTargetStateForRow(int tableRow) const;
    const OptimizationState* detectedStateForScope(const OptimizationScope& scope) const;
    bool applyVisibleRow(int tableRow);
    void beginStateApply(int tableRow, const OptimizationItem& item, const OptimizationScope& scope, const OptimizationState& state);
    void continueStateApply();
    void finishStateApply();
    void cancelStateApply(const QString& reasonText = QString());
    void completePendingAction(bool actionOk, const QString& errorText);
    void setApplyControlsEnabled(bool enabled);
    bool startExternalAction(const QJsonObject& actionObject, QString* errorTextOut);
    static bool actionRequiresExternalProcess(const QJsonObject& actionObject);
    bool executeAction(
        const QJsonObject& actionObject,
        ks::ui::FieldDocument* detailLinesOut,
        bool* restartExplorerOut);

    bool executeRegistryWriteAction(const QJsonObject& actionObject, QString* errorTextOut);
    bool executeRegistryDeleteAction(const QJsonObject& actionObject, QString* errorTextOut);
    bool executeRegistryMoveAction(const QJsonObject& actionObject, QString* errorTextOut);
    bool executeServiceStartAction(const QJsonObject& actionObject, QString* errorTextOut);
    bool executeExplorerNotifyAction(const QJsonObject& actionObject, QString* errorTextOut);

    static bool evaluateConditionText(const QString& conditionText);

private:
    QPushButton* m_columnPresetAButton = nullptr; // A 列组按钮：默认操作视图。
    QPushButton* m_columnPresetBButton = nullptr; // B 列组按钮：条件/警告诊断视图。
    QLineEdit* m_filterEdit = nullptr;           // Free-text filter for group/item/scope names.
    QPushButton* m_reloadButton = nullptr;       // Reloads JSON from profiles at runtime.
    QPushButton* m_refreshStateButton = nullptr; // Re-evaluates visible row state conditions.
    QPushButton* m_cancelApplyButton = nullptr;  // Cancels the current external optimization action sequence.
    QTimer* m_filterDebounceTimer = nullptr;     // 延迟合并连续筛选输入。
    QSplitter* m_splitter = nullptr;             // Left groups, right item list/details.
    QTreeWidget* m_groupTree = nullptr;          // Dynamic group tree from JSON group_name.
    QTableWidget* m_itemTable = nullptr;         // Dynamic option rows and per-row controls.
    ks::ui::StructuredFieldView* m_detailText = nullptr;    // 选中项目/动作的只读详情，支持语言切换重绘。
    QLabel* m_statusLabel = nullptr;             // Profile load/apply status.

    QString m_loadedProfilePath;                 // Actual JSON path selected from candidates.
    QVector<OptimizationItem> m_itemList;        // Parsed top-level optimization items.
    QVector<VisibleRow> m_visibleRows;           // Current table row to model mapping.
    ColumnPreset m_columnPreset = ColumnPreset::A; // 当前列组预设。
    bool m_rebuildingTable = false;              // Guards refresh signals during table rebuild.
    bool m_stateRefreshInProgress = false;       // 可见状态后台刷新是否仍在执行。
    std::uint64_t m_stateRefreshGeneration = 0;  // 忽略过期后台状态结果。
    bool m_stateApplyInProgress = false;         // 当前是否正在串行应用优化动作。
    int m_stateApplyTableRow = -1;               // 应用开始时对应的表格行。
    QString m_stateApplyItemName;                // 应用中的项目名称。
    QString m_stateApplyTargetLabel;             // 应用中的目标状态名称。
    QVector<QJsonObject> m_stateApplyActions;    // 保持原 JSON 顺序的待执行动作。
    int m_stateApplyNextActionIndex = 0;         // 下一项待执行动作索引。
    QJsonObject m_stateApplyActiveAction;        // 当前异步外部动作。
    ks::ui::FieldDocument m_stateApplyDetailLines;         // 当前动作序列的诊断信息。
    bool m_stateApplyAllOk = true;               // 所有已完成动作是否成功。
    bool m_stateApplyRestartExplorer = false;    // 是否需要提示 Explorer 重启。
    QProcess* m_stateApplyProcess = nullptr;     // 仅承载当前非阻塞 cmd/tar 子进程。
    QTemporaryDir* m_stateApplyTemporaryDir = nullptr; // FileCreateByZIP 解压期间保留临时目录。
    QString m_stateApplyZipDestinationPath;      // FileCreateByZIP 的最终目标路径。
};
