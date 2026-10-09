#include "../UI/StructuredFieldView.h"
#pragma once

// ============================================================
// KernelDockIpcTab.h
// 作用说明：
// 1) 提供只读 IPC 视图；
// 2) 聚合 NamedPipe、ALPC 与通信对象枚举页；
// 3) 不暴露任何写路径或破坏性动作。
// ============================================================

#include "../Framework.h"
#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

#include <cstdint>

class CodeEditorWidget;
class QLabel;
class QLineEdit;
class QPushButton;
class QHBoxLayout;
class QTableWidget;
class QTabWidget;

class KernelDockIpcTab final : public QWidget
{
public:
    explicit KernelDockIpcTab(QWidget* parent = nullptr);
    ~KernelDockIpcTab() override = default;

private:
    void initializeUi();
    void initializeConnections();
    void initializeAlpcPage();
    void refreshAlpcQuery();
    void applyIpcSummaryResult();
    void applyAlpcQueryResult();
    ks::ui::FieldDocument buildAlpcDetail(int rowIndex) const;
    void updateAlpcDetailForRow(int rowIndex);
    ks::ui::FieldDocument buildIpcSummaryDetail(int rowIndex) const;
    void updateIpcSummaryDetailForRow(int rowIndex);
    void copyIpcSummaryCurrentRow() const;
    void copyAlpcCurrentRow() const;
    static QString formatHex32(std::uint32_t value);
    static QString formatHex64(std::uint64_t value);
    static QString statusText(long statusValue);

private:
    QTabWidget* m_innerTabWidget = nullptr;

    QWidget* m_alpcPage = nullptr;
    QHBoxLayout* m_alpcToolbarLayout = nullptr;
    QLineEdit* m_alpcProcessIdEdit = nullptr;
    QLineEdit* m_alpcHandleEdit = nullptr;
    QPushButton* m_alpcRefreshButton = nullptr;
    QLabel* m_alpcStatusLabel = nullptr;
    QTableWidget* m_ipcSummaryTable = nullptr;
    QTableWidget* m_alpcTable = nullptr;
    ks::ui::StructuredFieldView* m_alpcDetailEditor = nullptr;

    std::uint32_t m_alpcProcessId = 0;
    std::uint64_t m_alpcHandleValue = 0;
    ksword::ark::IpcSummaryAuditResult m_lastIpcSummaryResult;
    ksword::ark::AlpcPortQueryResult m_lastAlpcResult;
};
