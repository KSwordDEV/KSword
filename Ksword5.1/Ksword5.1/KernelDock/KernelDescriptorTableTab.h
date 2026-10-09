#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"
#include "KernelCleanImageBaseline.h"

#include <QString>
#include <QWidget>

#include <cstddef>
#include <cstdint>
#include <vector>

class QLabel;
class QEvent;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QTableWidget;
class CodeEditorWidget;

// KernelDescriptorTableKind：
// - 作用：指定描述符子页仅展示 IDT 或仅展示 GDT；
// - 使用：I/O 管理页分别创建两个实例，避免在子页内再次出现表类型下拉框。
enum class KernelDescriptorTableKind
{
    Idt,
    Gdt
};

// KernelDescriptorTableTab：以只读 R0 CPU 快照展示每 CPU IDT 或 GDT。
// IDT 页展示 handler 模块归属，GDT 页展开 segment/TSS 位域。
class KernelDescriptorTableTab final : public QWidget
{
public:
    // 构造函数：
    // - 输入 tableKind：固定显示的描述符类型，parent：Qt 父控件；
    // - 处理：创建对应 IDT/GDT 专属表格，并在首次显示时异步刷新；
    // - 返回：无显式返回值。
    explicit KernelDescriptorTableTab(
        KernelDescriptorTableKind tableKind,
        QWidget* parent = nullptr);
    ~KernelDescriptorTableTab() override = default;

protected:
    void showEvent(QShowEvent* event) override;
    // changeEvent：应用调色板变更（换主题）时用已缓存的行重建表，刷新烘焙进单元格的高亮画刷。
    void changeEvent(QEvent* event) override;

private:
    void initializeUi();
    void refreshAsync();
    void applyResult(
        ksword::ark::DriverIntegrityResult result,
        std::vector<ks::kernel::TrustedIdtBaselineResult>
            trustedIdtBaselines);
    void rebuildTable();
    void showCurrentDetail();
    void restoreSelectedIdtBaseline();
    void showCopyMenu(const QPoint& position);

    // WatchPlan：一行能建的三条 HVM 监视，在弹出菜单**之前**算好的快照。
    //
    // 之所以是快照而不是"选完再去查行"：菜单的 exec 是嵌套事件循环，而本页
    // 刷新走后台线程加 QueuedConnection 回投，菜单开着的那几秒里 m_rows 可以
    // 被整体换掉。那之后按同一个下标取到的是另一行——而这种错不报错，只是
    // 把监视装到了一页毫不相干的内存上。
    struct WatchPlan
    {
        // 表项本身（描述符行）或中断对象基址（KINTERRUPT 行）：写监视。
        bool entryValid = false;
        quint64 entryAddress = 0;
        quint64 entryLength = 0;   // 0 表示整页（KINTERRUPT 大小不在 R3 写死）
        QString entryLabel;
        QString entryTip;          // 不可用时说明为什么，不留空按钮
        // 这一项指向的代码：执行监视。
        bool targetValid = false;
        quint64 targetAddress = 0;
        QString targetLabel;
        QString targetTip;
        // 这张表所在页的页表项：回答"谁把表重映射走了"。
        bool pteValid = false;
        quint64 pteSourceAddress = 0;  // 传给 openHvmWatchOnPte 的是表基址
        QString pteLabel;
    };

    // buildWatchPlan：按 m_rows 下标算出上面那份快照。越界时返回全不可用。
    WatchPlan buildWatchPlan(std::size_t sourceIndex) const;
    bool rowMatchesFilter(
        const ksword::ark::DriverIntegrityEvidenceEntry& row,
        std::size_t sourceIndex) const;
    QString columnText(
        const ksword::ark::DriverIntegrityEvidenceEntry& row,
        int column,
        std::size_t sourceIndex) const;
    QString detailText(
        const ksword::ark::DriverIntegrityEvidenceEntry& row,
        std::size_t sourceIndex) const;
    static QString tableName(const ksword::ark::DriverIntegrityEvidenceEntry& row);
    static QString descriptorTypeText(const ksword::ark::DriverIntegrityEvidenceEntry& row);
    static QString hex64(std::uint64_t value);
    static QString hex32(std::uint32_t value);
    static QString rowClipboardText(QTableWidget* table, int row, bool includeHeader);

    KernelDescriptorTableKind m_tableKind; // m_tableKind：当前实例固定展示 IDT 或 GDT。
    QLineEdit* m_filterEdit = nullptr;      // m_filterEdit：当前类型表项的关键词筛选框。
    QPushButton* m_refreshButton = nullptr; // m_refreshButton：重新读取当前描述符表。
    QPushButton* m_restoreIdtButton = nullptr; // m_restoreIdtButton：仅 IDT 页创建的启动期基线恢复按钮。
    QLabel* m_statusLabel = nullptr;        // m_statusLabel：异步查询状态和表项数量。
    QTableWidget* m_table = nullptr;        // m_table：描述符结构化结果表。
    CodeEditorWidget* m_detailEdit = nullptr; // m_detailEdit：当前表项的只读诊断详情。
    std::vector<ksword::ark::DriverIntegrityEvidenceEntry> m_rows; // m_rows：当前类型的 R0 快照。
    std::vector<ks::kernel::TrustedIdtBaselineResult> m_trustedIdtBaselines; // m_trustedIdtBaselines：与 IDT 行对齐的可信映像/PDB 预期 Handler 证据。
    bool m_refreshRunning = false;          // m_refreshRunning：防止重复并发查询。
    bool m_firstRefreshStarted = false;     // m_firstRefreshStarted：首次显示自动刷新标志。
};
