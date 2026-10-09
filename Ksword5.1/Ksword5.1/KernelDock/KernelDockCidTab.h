#include "../UI/StructuredFieldView.h"
#pragma once

// ============================================================
// KernelDockCidTab.h
// 作用说明：
// 1) 提供只读 CID / cross-view 聚合页；
// 2) 合并进程与线程 cross-view 结果，展示 public walk / CID / Active / ThreadList 证据；
// 3) 仅做 R3 只读展示，不包含任何修复、隐藏、摘链或写操作。
// ============================================================

#include "../Framework.h"

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QPoint>
#include <QWidget>

#include <atomic>
#include <cstdint>
#include <vector>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class CodeEditorWidget;
class QHBoxLayout;

class KernelDockCidTab final : public QWidget
{
public:
    explicit KernelDockCidTab(QWidget* parent = nullptr);
    ~KernelDockCidTab() override = default;

private:
    // CidTableSummary：
    // - 用途：缓存 enumCidTable 的响应头摘要；
    // - 输入：由刷新线程从 ArkDriverClient::enumCidTable 填充；
    // - 输出：状态栏和详情区展示 PspCidTable/计数/截断/访问预算。
    struct CidTableSummary
    {
        bool queried = false;                       // queried：本轮是否已经调用 enumCidTable。
        bool ok = false;                            // ok：传输和协议解析是否成功。
        bool unsupported = false;                   // unsupported：旧驱动或缺少 handler 时为 true。
        std::uint32_t status = 0;                   // status：R0 CID 枚举语义状态。
        std::uint32_t totalCount = 0;               // totalCount：R0 观测到的 CID 总数。
        std::uint32_t returnedCount = 0;            // returnedCount：R0 返回给 R3 的 CID 行数。
        std::uint32_t visitedCount = 0;             // visitedCount：R0 实际访问的表项数。
        std::uint32_t maxVisitCount = 0;            // maxVisitCount：R0 本次访问预算。
        std::uint32_t flags = 0;                    // flags：R0 响应 flags，保留截断/策略信息。
        long lastStatus = 0;                        // lastStatus：R0 最近 NTSTATUS。
        std::uint64_t pspCidTableAddress = 0;       // pspCidTableAddress：PspCidTable 地址。
        std::uint64_t dynDataCapabilityMask = 0;    // dynDataCapabilityMask：DynData 能力位。
        std::uint32_t htTableCodeOffset = 0;        // htTableCodeOffset：HANDLE_TABLE.TableCode 偏移。
        std::uint32_t hteLowValueOffset = 0;        // hteLowValueOffset：HANDLE_TABLE_ENTRY.LowValue 偏移。
        QString messageText;                        // messageText：ArkDriverClient 诊断信息。
    };

    struct CidEvidenceRow
    {
        bool isRawCid = false;
        bool isThread = false;
        std::uint32_t cidValue = 0;
        std::uint32_t cidHandleIndex = 0;
        std::uint32_t cidExpectedKind = 0;
        std::uint32_t cidEntryFlags = 0;
        long cidReferenceStatus = 0;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        std::uint32_t parentProcessId = 0;
        std::uint64_t objectAddress = 0;
        std::uint64_t processObjectAddress = 0;
        std::uint64_t startAddress = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t anomalyFlags = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        long lastStatus = 0;
        std::uint32_t confidence = 0;
        std::uint32_t detailStatus = 0;
        std::uint32_t denoiseFlags = 0;
        std::uint32_t publicProcessId = 0;
        std::uint32_t activeListProcessId = 0;
        std::uint32_t cidTableProcessId = 0;
        std::uint32_t publicThreadId = 0;
        std::uint32_t threadListThreadId = 0;
        std::uint32_t cidTableThreadId = 0;
        std::uint32_t threadListProcessId = 0;
        long publicWalkStatus = 0;
        long activeListStatus = 0;
        long cidTableStatus = 0;
        long threadListStatus = 0;
        long startAddressStatus = 0;
        QString imageNameText;
        QString detailText;
    };

    // initializeUi：
    // - 创建工具栏、表格和详情面板；
    // - 首次构造时保持只读，刷新由后台线程驱动。
    void initializeUi();

    // initializeConnections：
    // - 绑定刷新、过滤和详情联动；
    // - 所有操作只更新本地展示，不触发写路径。
    void initializeConnections();

    // refreshAsync：
    // - 后台查询 process/thread cross-view；
    // - 成功后回填表格与详情面板。
    void refreshAsync();

    // applyRefreshResult：
    // - 输入 rows/errorText/success：刷新结果；
    // - 处理：恢复按钮状态并重建表格。
    void applyRefreshResult(std::vector<CidEvidenceRow> rows, const QString& errorText, bool success);

    // rebuildTable：
    // - 按过滤关键字重建结果表；
    // - 只读显示，不允许编辑或操作。
    void rebuildTable();

    // showContextMenu：
    // - 显示复制菜单；
    // - 不提供任何删除/修复/摘链按钮。
    void showContextMenu(const QPoint& localPosition);

    // copyCurrentRow：
    // - 复制当前行到剪贴板；
    // - 字段使用 Tab 分隔，便于粘贴到日志或表格。
    void copyCurrentRow() const;

    // selectedRow：
    // - 返回当前选中行；
    // - 无选中或越界时返回 nullptr。
    const CidEvidenceRow* selectedRow() const;

    // buildDetailText：
    // - 生成当前行详情文本；
    // - 只做纯格式化，不含任何驱动 IOCTL；[KernelObjectSummary] 段由后台任务补齐。
    ks::ui::FieldDocument buildDetailText(const CidEvidenceRow* row) const;

    // scheduleDetailRefresh：
    // - 输入：无，直接读取当前选中行；
    // - 处理：立即渲染本地详情，并把 R0 对象摘要请求推入 150ms 去抖窗口；
    // - 返回：无返回值，同时递增 generation 作废所有在途回投。
    void scheduleDetailRefresh();

    // requestKernelObjectSummaryAsync：
    // - 输入：无，按当前选中行生成 targetKind/cidValue/objectAddress；
    // - 处理：在 QThreadPool 里执行 queryKernelObjectSummary，回投时校验 generation；
    // - 返回：无返回值，UI 只在回投槽内被触碰。
    void requestKernelObjectSummaryAsync();

    // appendKernelObjectSummaryText：
    // - 输入 summaryText：后台线程格式化好的 [KernelObjectSummary] 段；
    // - 处理：拼接在本地详情文本之后写入详情面板；
    // - 返回：无返回值。
    void appendKernelObjectSummaryText(const ks::ui::FieldDocument& summaryText);

    // buildDiagnosticDetailText：
    // - 输入：当前空表/筛选空命中的诊断原因；
    // - 处理：把 CID 表摘要、筛选关键字和驱动消息展开为详情文本；
    // - 返回：可直接显示在 CodeEditorWidget 的只读说明。
    ks::ui::FieldDocument buildDiagnosticDetailText(const QString& reasonText) const;

    // insertDiagnosticRow：
    // - 输入：表格短标题、状态列文本和详情文本；
    // - 处理：向当前表格写入一行可复制的诊断占位；
    // - 返回：无返回值，诊断详情保存在 UserRole，供详情区读取。
    void insertDiagnosticRow(const QString& titleText, const QString& statusText, const ks::ui::FieldDocument& detailText);

    // rowMatchesFilter：
    // - 按文本关键字筛选；
    // - 过滤字段覆盖类型、PID/TID、地址、状态和详情摘要。
    bool rowMatchesFilter(const CidEvidenceRow& row) const;

    static QTableWidgetItem* readOnlyItem(const QString& text);
    static QString formatHex32(std::uint32_t value);
    static QString formatHex64(std::uint64_t value);
    static QString statusLabelText(long statusValue);
    static QString sourceMaskText(std::uint32_t mask);
    static QString anomalyFlagsText(std::uint32_t flags);
    static QString denoiseFlagsText(std::uint32_t flags);
    static QString detailStatusText(std::uint32_t status);
    static QString roleText(bool isThread);
    static QString cidKindText(std::uint32_t kind);
    static QString cidEntryFlagsText(std::uint32_t flags);
    static QString cidEnumStatusText(std::uint32_t status);
    static QString objectSummaryStatusText(std::uint32_t status);
    static QString objectHeaderStatusText(std::uint32_t status);
    static QString fixedWideText(const wchar_t* text, std::size_t maxChars);
    static bool cidSummaryTruncated(const CidTableSummary& summary);

    // formatKernelObjectSummaryText：
    // - 输入 summary：queryKernelObjectSummary 返回的纯值类型结果；
    // - 处理：只做字符串格式化，可安全地在后台线程执行；
    // - 返回：详情面板追加段文本。
    static ks::ui::FieldDocument formatKernelObjectSummaryText(const ksword::ark::KernelObjectSummaryAuditResult& summary);

private:
    QHBoxLayout* m_toolbarLayout = nullptr;
    QPushButton* m_refreshButton = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QLabel* m_statusLabel = nullptr;
    QTableWidget* m_table = nullptr;
    ks::ui::StructuredFieldView* m_detailEditor = nullptr;
    QTimer* m_detailRequestTimer = nullptr;     // detailRequestTimer：R0 对象摘要请求的去抖定时器。

    std::atomic_bool m_refreshing{ false };
    CidTableSummary m_cidSummary;
    std::vector<CidEvidenceRow> m_rows;
    ks::ui::FieldDocument m_detailBaseText;
    ks::ui::FieldDocument m_diagnosticDocument;                   // detailBaseText：当前行的本地详情文本，回投时在其后追加摘要。
    std::uint64_t m_detailGeneration = 0;       // detailGeneration：淘汰被新选中行取代的旧摘要回投。
};
