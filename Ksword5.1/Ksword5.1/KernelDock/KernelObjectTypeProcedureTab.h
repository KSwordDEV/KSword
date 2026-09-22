#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QString>
#include <QWidget>

#include <cstdint>
#include <vector>

class QEvent;
class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QTableWidget;

// KernelObjectTypeProcedureTab：
// - 逐个对象类型读取 OBJECT_TYPE 里嵌着的八个方法指针（Dump/Open/Close/Delete/Parse/Security/QueryName/OkayToClose），
//   并核对每个指针的归属模块与所在节（本版本不做入口跳板/内联绕行检查——协议里的 DETOUR 字段是预留的，恒为 0）；
// - 这些指针被改掉时，对象类型表和类型对象地址都毫无变化，只核对一级地址的检测看不到，所以带 HIDDEN_HOOK 位的行
//   整行高亮并明确标出“存在隐藏行为”；
// - 方法指针块的偏移不在任何偏移表里，R0 靠运行时自验证发现它；验证没通过（layoutState 不是 VALIDATED）时，
//   本页如实显示“检查未启用（这不代表没有 Hook）”，行只作参考，绝不给出“被劫持”或“干净”的结论；
// - 全部为只读证据，支持文本筛选与行/全表复制，不提供任何修改入口。
class KernelObjectTypeProcedureTab final : public QWidget
{
public:
    explicit KernelObjectTypeProcedureTab(QWidget* parent = nullptr);
    ~KernelObjectTypeProcedureTab() override = default;

    // requestInitialRefresh：
    // - 仅在用户首次切入本子页时发起 R0 查询；
    // - 重复调用保持幂等，不影响工具栏的手动刷新。
    void requestInitialRefresh();

protected:
    // changeEvent：
    // - 主题切换后重新给整行上色（单元格画刷是绘制路径，烘焙后不会自己跟随主题）；
    // - 只重涂已有行，不访问驱动。
    void changeEvent(QEvent* event) override;

private:
    struct ProcedureRow
    {
        std::uint32_t typeIndex = 0;
        QString typeName;
        std::uint32_t procedureKind = 0;       // KSWORD_ARK_OBJTYPE_PROC_*。
        std::uint32_t riskFlags = 0;           // 驱动原始上报值；显示时经 effectiveRisk 收口。
        std::uint32_t entryFlags = 0;          // KSWORD_ARK_OBJTYPE_ENTRY_FLAG_*。
        std::int32_t lastStatus = 0;
        std::uint64_t slotAddress = 0;
        std::uint64_t targetAddress = 0;
        std::uint64_t detourTargetAddress = 0;
        QString ownerModule;
        QString sectionName;
    };

    struct Snapshot
    {
        std::vector<ProcedureRow> rows;
        bool queryFailed = false;              // true 表示 IOCTL 本身失败（含驱动缺入口）。
        bool unsupported = false;
        QString ioMessage;                     // 诊断串，放进状态标签的 tooltip。
        std::uint32_t layoutState = KSWORD_ARK_OBJTYPE_LAYOUT_UNAVAILABLE;
        std::uint32_t procedureBlockOffset = 0;
        std::uint32_t layoutAnchorTypes = 0;
        std::uint32_t layoutAnchorAgree = 0;
        std::uint32_t layoutReason = 0;        // KSWORD_ARK_OBJTYPE_LAYOUT_REASON_*：没验证过时为什么。
        std::uint32_t typeCount = 0;           // 按 typeIndex 去重后的类型数。
        bool truncated = false;
        bool skippedTypes = false;             // 有对象类型的表槽读失败被跳过：结果不完整。
    };

    void initializeUi();
    void refreshAsync();
    void applySnapshot(Snapshot snapshot);
    void populateTable();
    void applyRowHighlights();
    void updateStatusLabel();
    void applyFilter();
    void showCopyMenu(const QPoint& position);
    bool layoutVerified() const;
    std::uint32_t effectiveRisk(const ProcedureRow& row) const;
    QString stateText(const ProcedureRow& row) const;
    QString rowDetailText(const ProcedureRow& row) const;
    static QString methodText(std::uint32_t procedureKind);
    static QString hex64(std::uint64_t value);
    static QString hex32(std::uint32_t value);
    static QString tableRowText(QTableWidget* table, int row, bool includeHeader);

    QTableWidget* m_table = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QPushButton* m_clearFilterButton = nullptr;
    QLabel* m_statusLabel = nullptr;
    std::vector<ProcedureRow> m_rows;
    bool m_hasResult = false;                  // false 表示还没有收到过任何查询结果。
    bool m_queryFailed = false;
    bool m_unsupported = false;
    QString m_ioMessage;
    std::uint32_t m_layoutState = KSWORD_ARK_OBJTYPE_LAYOUT_UNAVAILABLE;
    std::uint32_t m_procedureBlockOffset = 0;
    std::uint32_t m_layoutAnchorTypes = 0;
    std::uint32_t m_layoutAnchorAgree = 0;
    std::uint32_t m_layoutReason = 0;
    std::uint32_t m_typeCount = 0;
    bool m_truncated = false;
    bool m_skippedTypes = false;
    bool m_refreshRunning = false;
    bool m_initialRefreshRequested = false;
};
