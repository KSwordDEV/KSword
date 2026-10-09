#include "../UI/StructuredFieldView.h"
#pragma once

// ============================================================
// HardwareR0EvidencePage.h
// 作用：
// 1) 在硬件 Dock 中新增只读 R0 硬件证据页；
// 2) 通过 ArkDriverClient 复用现有 Kernel CPU Integrity 协议；
// 3) 展示每 CPU 控制寄存器、MSR、IDT/GDT/IDTR/GDTR 等 R0 入口证据。
// ============================================================

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QWidget>

#include <atomic>   // std::atomic_bool/std::atomic_uint64_t：异步查询互斥与票据。
#include <cstdint>  // std::uint32_t/std::uint64_t：协议字段与地址展示。
#include <vector>   // std::vector：保存 R0 evidence 缓存。

class CodeEditorWidget;
class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QVBoxLayout;

// HardwareR0EvidencePage 说明：
// - 输入：Qt 父控件；
// - 处理：只通过 ArkDriverClient 异步查询 R0 CPU/IDT 证据，不直接调用 DeviceIoControl；
// - 返回：该控件无业务返回值，查询结果直接展示在表格和详情编辑器中。
class HardwareR0EvidencePage final : public QWidget
{
public:
    // 构造函数：
    // - parent：Qt 父控件；
    // - 处理：初始化 UI、绑定控件，并延迟启动一次 R0 证据刷新。
    explicit HardwareR0EvidencePage(QWidget* parent = nullptr);

    // 析构函数：
    // - 不持有裸线程句柄；
    // - QRunnable 回投通过 QPointer 防止对象销毁后访问。
    ~HardwareR0EvidencePage() override = default;

private:
    // initializeUi 作用：
    // - 输入：无；
    // - 处理：创建工具栏、证据表和详情区；
    // - 返回：无。
    void initializeUi();

    // initializeConnections 作用：
    // - 输入：无；
    // - 处理：连接刷新、过滤、风险筛选和表格选择事件；
    // - 返回：无。
    void initializeConnections();

    // refreshEvidenceAsync 作用：
    // - 输入：forceRefresh 表示用户主动刷新；
    // - 处理：后台查询 R0 capability、DynData capability 和 CPU integrity evidence；
    // - 返回：无，结果通过 queued connection 回填 UI。
    void refreshEvidenceAsync(bool forceRefresh);

    // applyEvidenceQueryResults 作用：
    // - 按 ticket 原子替换 R0 能力、DynData 与 CPU evidence 缓存；
    // - 表格菜单打开时延迟整组结果，确保 UserRole 缓存索引仍有效。
    void applyEvidenceQueryResults(
        std::uint64_t ticket,
        ksword::ark::DriverCapabilitiesQueryResult capabilityResult,
        ksword::ark::DynDataCapabilitiesResult dynDataResult,
        ksword::ark::DriverIntegrityResult integrityResult);

    // rebuildEvidenceTable 作用：
    // - 输入：无，读取 m_evidenceCache 与过滤控件；
    // - 处理：重建表格显示，不访问驱动；
    // - 返回：无。
    void rebuildEvidenceTable();

    // showSelectedEvidenceDetail 作用：
    // - 输入：无，读取当前表格选中行；
    // - 处理：从 UserRole 映射回 evidence 缓存并填充详情编辑器；
    // - 返回：无。
    void showSelectedEvidenceDetail();

    // setStatusText 作用：
    // - 输入：状态文本和颜色；
    // - 处理：统一刷新状态标签样式；
    // - 返回：无。
    void setStatusText(const QString& text, const QString& colorText);

private:
    QVBoxLayout* m_rootLayout = nullptr;       // m_rootLayout：页面根布局。
    QPushButton* m_refreshButton = nullptr;    // m_refreshButton：刷新 R0 证据按钮。
    QCheckBox* m_riskOnlyCheck = nullptr;      // m_riskOnlyCheck：仅显示 riskFlags 非零项。
    QLineEdit* m_filterEdit = nullptr;         // m_filterEdit：本地过滤 owner/detail/risk/class 文本。
    QSpinBox* m_maxRowsSpin = nullptr;         // m_maxRowsSpin：单次最大 evidence 行数。
    QSpinBox* m_idtVectorsSpin = nullptr;      // m_idtVectorsSpin：每 CPU 展开的 IDT 向量数量。
    QLabel* m_statusLabel = nullptr;           // m_statusLabel：展示 R0 查询状态摘要。
    QTableWidget* m_evidenceTable = nullptr;   // m_evidenceTable：CPU/MSR/IDT/GDT 证据表。
    ks::ui::StructuredFieldView* m_detailEditor = nullptr;// m_detailEditor：证据详情文本编辑器。

    ksword::ark::DriverCapabilitiesQueryResult m_lastCapabilityResult; // m_lastCapabilityResult：最近一次驱动能力快照。
    ksword::ark::DynDataCapabilitiesResult m_lastDynDataResult; // m_lastDynDataResult：最近一次 DynData 能力快照。
    ksword::ark::DriverIntegrityResult m_lastIntegrityResult; // m_lastIntegrityResult：最近一次完整响应摘要。
    std::vector<ksword::ark::DriverIntegrityEvidenceEntry> m_evidenceCache; // m_evidenceCache：最近一次 R0 evidence 行缓存。
    std::atomic_bool m_refreshing{ false };    // m_refreshing：避免并发刷新。
    std::atomic<std::uint64_t> m_refreshTicket{ 0 }; // m_refreshTicket：丢弃过期后台结果。
};
