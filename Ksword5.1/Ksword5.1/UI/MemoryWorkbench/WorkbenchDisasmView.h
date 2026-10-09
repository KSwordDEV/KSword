#pragma once

// Shared address-backed disassembly canvas. Target I/O and writes belong to the host.

#include "../../../../shared/evidence/memory_workbench/MemoryDiffOverlay.h"

#include <QAbstractTableModel>
#include <QByteArray>
#include <QString>
#include <QVector>
#include <QWidget>

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

class QEvent;
class QKeyEvent;
class QLabel;
class QPoint;
class QRect;
class QMenu;
class QLineEdit;

namespace ks::ui
{
    class HexViewSegmented;

    // WorkbenchByteWindow：一次 FetchWindow 的结果，见文件头"一"。
    struct WorkbenchByteWindow
    {
        bool ok = false;                                            // false 表示该区间此刻完全不可用（已跳出已读取窗口等）
        std::uint64_t address = 0;                                  // 窗口起始地址
        std::vector<std::uint8_t> bytes;                            // 现值（含暂存补丁）
        std::vector<std::uint8_t> validMask;                        // 1=有效，0=不可读，2=加载中；后两种不得解码或写入
        std::vector<std::uint8_t> baselineBytes;                    // 基线值（未叠加补丁）
        std::vector<std::uint8_t> baselineValidMask;                // 基线值是否有效
        std::vector<std::uint8_t> previousBytes;                    // 上次读取值
        std::vector<std::uint8_t> previousValidMask;                // 上次读取值是否有效
        std::vector<ksword::memwb::ByteChangeKind> changeKinds;     // 逐字节变化种类，与 bytes 等长
    };

    // IWorkbenchBytesProvider：反汇编/文本/对比三页共用的只读数据源，见文件头"一"。
    //
    // 生命周期契约（可疑点 4）：三个子页只保存裸指针（非拥有），不做任何引用计数或
    // QPointer 包裹——本接口不是 QObject，无法用 QPointer 自动探活。调用方（宿主）必须
    // 保证：provider 的生存期覆盖它被设置（setBytesProvider）之后、到下一次
    // setBytesProvider(另一个指针或 nullptr) 之前的全部时间；销毁 provider 前必须先对
    // 每个仍持有它的子页调用 setBytesProvider(nullptr)，否则下一次 refreshView/jumpTo
    // 等触发的 FetchWindow 调用会是悬空指针解引用。
    class IWorkbenchBytesProvider
    {
    public:
        virtual ~IWorkbenchBytesProvider() = default;

        // FetchWindow：取 [address, address+length) 的叠加字节快照（同步调用，不做真正 I/O，
        // 只是从宿主已经持有的 MemoryDiffOverlay 读出来）。length 为 0 时返回 ok=true 的空窗口。
        virtual WorkbenchByteWindow FetchWindow(std::uint64_t address, std::uint64_t length) const = 0;

        // AddressBits：当前会话位数（32 或 64），作为反汇编页默认架构分段的依据。
        virtual int AddressBits() const = 0;

        // HasPreviousRead：对比页的"两次读取之间"分组是否有数据可比（没有上次读取时整段隐藏）。
        virtual bool HasPreviousRead() const = 0;
    };

    // DecodedRow：反汇编单行，既可能是真解码的指令，也可能是重同步插入的单字节 db 占位。
    struct DecodedRow
    {
        std::uint64_t address = 0;      // 本行起始地址
        QByteArray bytes;               // 本行覆盖的原始字节
        QString mnemonic;               // 指令助记符；db 占位行固定为 "db"
        QString operands;               // 操作数文本；db 占位行是该字节的十六进制
        bool decoded = false;           // 是否被解码器识别（db 占位行恒为 false）
    };

    // WorkbenchAssembleResult：一次单指令汇编的结果，与 ks::ui::AssemblyResult 字段对应。
    struct WorkbenchAssembleResult
    {
        bool success = false;   // 是否编译成功
        QByteArray bytes;       // 成功时的机器码；失败时为空
        QString error;          // 失败时的原因（不带"第 N 行"前缀，调用方是单行编辑器）
        // errorLine：D6——失败时的源码行号（1 基）；来源跟 ks::ui::AssemblyResult::errorLine
        // 一样由汇编后端给出，宿主注入的后端负责透传，不在这里猜测。行内编辑路径永远是
        // 单行源码，不展示行号前缀；只有预览对话框（多行源码）会用它。0 表示后端没有给出
        // （旧后端/夹具假后端），调用方应当把它当成"第 1 行"而不是显示 "第 0 行"。
        int errorLine = 0;
    };

    // DecodeOneFn：尝试解码 [address, address+available) 的第一条指令。
    // 传入：起始字节指针、可用字节数、绝对地址、是否 x64；传出：解码结果（nullopt 表示该后端
    // 在此处失败，调用方据此退化为单字节 db 并前进一个字节重试）。绝不抛异常。
    using DecodeOneFn = std::function<std::optional<DecodedRow>(
        const std::uint8_t* bytes, std::size_t available, std::uint64_t address, bool x64)>;

    // AssembleOneFn：把一行 Intel 汇编源码编译成机器码。
    using AssembleOneFn = std::function<WorkbenchAssembleResult(const QString& source, std::uint64_t address, bool x64)>;

    // Convert an operand's semantic address (e.g. a PE VA) into the provider's
    // coordinate (e.g. a file offset). nullopt rejects unmapped/ambiguous targets.
    using OperandTargetResolver = std::function<std::optional<std::uint64_t>(std::uint64_t)>;

    // DecodeWindowResynced：核心重同步算法，见文件头"三"；纯函数，供生产代码与离屏夹具共用。
    // 传入：已确认全部有效的字节、这段字节的起始地址、单条解码回调、最多解码的行数上限、是否 x64。
    // 传出：解码行列表，真实指令与 db 占位行混排，覆盖范围之和恰好等于 bytes.size()
    //       （除非达到 maxInstructions 提前停止）。
    QVector<DecodedRow> DecodeWindowResynced(
        const std::vector<std::uint8_t>& bytes,
        std::uint64_t baseAddress,
        const DecodeOneFn& decodeOne,
        std::uint32_t maxInstructions,
        bool x64);

    // WorkbenchDisasmModel：反汇编表格的模型，四列：地址/字节/助记符/操作数。
    // 行数据来自宿主调用 setRows 时一次性整体替换（窗口有界，通常几百行以内）。
    class WorkbenchDisasmModel final : public QAbstractTableModel
    {
        Q_OBJECT

    public:
        explicit WorkbenchDisasmModel(QObject* parent = nullptr);

        // setRows：整体替换显示的行；rowKinds 与 rows 等长，给出每行的底色变化种类
        // （Unchanged 表示不着色）；endOfWindowNote 非空时追加一条"超出已读取窗口"提示行
        // （decoded=false，mnemonic 即该提示文案，bytes 为空，提示行不计入 rowKinds）。
        void setRows(
            const QVector<DecodedRow>& rows,
            const QVector<ksword::memwb::ByteChangeKind>& rowKinds,
            const QString& endOfWindowNote);

        // rowAt：取某一行的数据；越界返回 nullopt。
        std::optional<DecodedRow> rowAt(int row) const;

        // isEndOfWindowRow：该行是不是"超出已读取窗口"提示行（不可编辑、不可跟随）。
        bool isEndOfWindowRow(int row) const;

        int rowCount(const QModelIndex& parent = QModelIndex()) const override;
        int columnCount(const QModelIndex& parent = QModelIndex()) const override;
        QVariant data(const QModelIndex& index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        Qt::ItemFlags flags(const QModelIndex& index) const override;

    private:
        QVector<DecodedRow> m_rows;                                  // 当前显示的行
        QVector<ksword::memwb::ByteChangeKind> m_rowKinds;           // 与 m_rows 等长的底色变化种类
        QString m_endOfWindowNote;                                   // 非空表示末尾追加了一条提示行
    };

    class MemoryRowCanvas;
    class WorkbenchDisasmView final : public QWidget
    {
        Q_OBJECT
    public:
        explicit WorkbenchDisasmView(QWidget* parent = nullptr);
        ~WorkbenchDisasmView() override;
        void setBytesProvider(IWorkbenchBytesProvider* provider);
        void setDecodeBackend(DecodeOneFn backend);
        void setAssembleBackend(AssembleOneFn backend);
        void setOperandTargetResolver(OperandTargetResolver resolver);
        void setAddressBits(int bits);
        void setArchitectureOverride(bool x64);
        void clearArchitectureOverride();
        void setAddressRange(std::uint64_t base, std::uint64_t length);
        void setAddressBounds(std::uint64_t first, std::uint64_t last);
        bool isX64() const;
        bool isEditable() const;
        void setEditable(bool editable);
        bool jumpTo(std::uint64_t address);
        void refreshView();
        void invalidateEditContext();
        void reset();
        bool hasAnchor() const { return m_hasAnchor; }
        std::uint64_t anchorAddress() const;
        MemoryRowCanvas* canvas() const;
        WorkbenchDisasmModel* model() const;
        std::optional<DecodedRow> selectedInstruction() const;
        bool isEditing() const;
        void beginSelectedInstructionEdit();
        void openFind();
        void findPrevious();
        QSize minimumSizeHint() const override;
    public slots:
        void navigateBack();
    signals:
        void stageRequested(quint64 address, QByteArray bytes);
        void requestHexLocate(quint64 address);
        void selectionChanged(quint64 first, quint64 last);
        void contextMenuAboutToShow(QMenu* menu, quint64 address, bool hasBytes);
        void windowRequested(quint64 address, quint64 length);
        void architectureChanged(bool x64);
        void statusMessage(const QString& text);
    protected:
        bool eventFilter(QObject* watched, QEvent* event) override;
    private:
        static constexpr std::uint64_t kDecodeWindowBytes = 4096;
        static constexpr std::uint64_t kLookaheadBytes = 15;
        static constexpr std::uint32_t kMaxInstructionRows = 4096;
        static constexpr int kMaxBackStack = 64;
        void rebuildRows();
        void rebuildRowsNow();
        void updateCanvas(bool preserveViewport);
        void browseMore(int direction, int lines);
        void findNext();
        void findMatch(bool backwards);
        void pushBackStack(std::uint64_t address);
        bool tryFollowOperand(const DecodedRow& row, std::uint64_t* addressOut) const;
        void showContextMenu(const QPoint& viewportPos);
        void beginRowEdit(int row);
        void cancelInlineEdit();
        void commitInlineEdit();
        void showInlineEditError(const QRect& editorRect, const QString& message);
        void hideInlineEditError();
        void showAssemblyPreviewDialog(const DecodedRow& expectedRow);
        IWorkbenchBytesProvider* m_provider = nullptr;
        DecodeOneFn m_decodeOne;
        AssembleOneFn m_assembleOne;
        OperandTargetResolver m_operandTargetResolver;
        HexViewSegmented* m_archSegmented = nullptr;
        MemoryRowCanvas* m_canvas = nullptr;
        QLineEdit* m_inlineEditor = nullptr;
        QWidget* m_findBar = nullptr;
        QLineEdit* m_findEdit = nullptr;
        WorkbenchDisasmModel* m_model = nullptr;
        QLabel* m_status = nullptr;
        QLabel* m_inlineError = nullptr;
        std::uint64_t m_anchor = 0;
        std::uint64_t m_editContextRevision = 0;
        std::uint64_t m_lastRebuiltAnchor = 0;
        bool m_hasAnchor = false;
        bool m_hasLastRebuiltAnchor = false;
        bool m_editingActive = false;
        bool m_refreshPending = false;
        bool m_editable = true;
        bool m_x64Override = false;
        bool m_x64OverrideValue = true;
        bool m_programmaticArchChange = false;
        std::optional<std::pair<std::uint64_t, std::uint64_t>> m_addressRange;
        std::vector<std::uint64_t> m_backStack;
        std::vector<std::uint64_t> m_browseHistory;
    };
}
