#pragma once

#include "../KernelDisassemblyDialog.h"
#include "../MemoryEditHistory.Core.h"
#include "../MemorySnapshotBytesProvider.h"
#include "WorkbenchPseudocodeView.h"
#include <QWidget>
#include <memory>
#include <vector>

class CodeTextEdit;
class QComboBox;
class QCheckBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QMenu;
class QPushButton;
class QTabWidget;
class QTableWidget;

namespace ks::ui
{
    class WorkbenchDisasmView;
    class WorkbenchTextView;
    class HexView;
    class WorkbenchCompareView;
    // 相对读取基线的一段连续修改；宿主据此提交自己的写前比对和实际回读事务。
    struct MemoryEditBlock
    {
        std::uint64_t address = 0; // 修改起点，坐标域与捕获快照一致。
        QByteArray originalBytes; // 本段读取基线，不能用待提交字节代替。
        QByteArray bytes; // 等长暂存替换字节；存在差异不表示真实写入已成功。
    };

    // 捕获证据的工作台宿主：复用正式 HexView、反汇编、文本/结构、对比与 C 子页。
    // 宿主传入字节与冻结身份；这里仅暂存编辑和历史，不读取或写入真实目标。
    // 文件偏移恒为 64 位；显式 VA 映射只用于指令/伪代码解释，不改变显示坐标。
    class SnapshotWorkbenchWidget final : public QWidget
    {
        Q_OBJECT
    public:
        // parent 只管理 Qt 生命周期；构造共享子页，不附加目标或读取真实字节。
        explicit SnapshotWorkbenchWidget(QWidget* parent = nullptr);
        // 解除子视图的 provider 后销毁宿主，取消尚未完成的解释请求。
        ~SnapshotWorkbenchWidget() override;
        // 返回宿主拥有的正式 HexView；直接改缓冲后须调用 refreshFromHexEditor。
        HexView* hexEditor() const;
        // kind 区分内存地址与文件偏移；切换使旧解释失效，不能借此授予目标权限。
        void setAddressKind(SnapshotAddressKind kind);
        // 返回当前显示坐标域，文件偏移始终保留 64 位。
        SnapshotAddressKind addressKind() const { return m_addressKind; }
        // bytes 是宿主实际取得的完整窗口，base 是该窗口坐标；architecture 仅决定解码。
        // anchor 在窗口内时作为初始定位，否则定位 base；溢出的范围拒绝并清空。
        // 非空 sourceIdentity 必须涵盖真实来源/后端/代次；只有同身份、起点和长度才保留上次读取。
        // 空身份只允许当前读取基线比较；新快照重置暂存历史，不触发真实目标写入。
        void setSnapshot(const QByteArray& bytes, std::uint64_t base,
            DisassemblyArchitecture architecture = DisassemblyArchitecture::X64,
            std::uint64_t anchor = 0, const QString& sourceIdentity = QString());
        // 返回当前共享缓存的值副本，包含尚未提交的编辑。
        QByteArray data() const;
        // 返回最近建立/接受的基线副本，供宿主判断修改和执行写前比对。
        QByteArray originalBytes() const;
        // 返回当前捕获窗口起点，含义由 addressKind 决定。
        std::uint64_t baseAddress() const;
        // 返回当前 x86/x64 解码选择，不推断目标实际体系结构。
        DisassemblyArchitecture currentArchitecture() const;
        // editable 只开放本地暂存；宿主仍独立负责真实写入权限、确认和后端事务。
        void setEditable(bool editable);
        // 返回当前缓存与读取基线是否存在差异，不表示真实目标发生变化。
        bool hasChanges() const;
        // 返回各段连续差异的原字节/替换字节值副本；基线长度失配时返回空集合。
        QVector<MemoryEditBlock> diffBlocks() const;
        // 把当前缓存设为新基线并清空历史，不写真实目标。
        // 写回宿主须先核验实际回读；新实际读取优先用 setSnapshot 建立基线。
        void acceptChanges();
        // 用读取基线恢复本地缓存并清空历史，不撤销真实目标已经提交的修改。
        void discardChanges();
        // 清空捕获字节、身份、映射、选区和历史，取消旧子页的来源上下文。
        void clear();
        // 同步 HexView 直接修改到 provider、差异/历史和各子页；新范围须用 setSnapshot。
        void refreshFromHexEditor();
        // 定位 address 并同步可见子页/C 上下文；未载入时只向宿主请求范围内窗口。
        void jumpToAddress(std::uint64_t address);
        // 打开当前字节、指令、文本或 C 子页的查找；对比页转到 HEX 查找。
        void openFindPanel();
        // 切到反汇编并定位 address；未载入时发 windowRequested，不伪造指令字节。
        void showDisassemblyAt(std::uint64_t address);
        // 返回宿主拥有的正式反汇编/文本子页；调用方不得越过宿主生命周期使用。
        WorkbenchDisasmView* disassemblyView() const;
        WorkbenchTextView* textView() const;
        // snapshot 必须与文件结构分析使用同一不可变捕获；imageBase/regions 给出明确 VA 映射。
        // 仅文件偏移域接受该证据，间隙、overlay 和仅虚拟存在字节没有可用 PE 地址。
        // x86Compatible 决定是否允许 x86/x64 解释，不改变原始文件显示坐标。
        void setFileAnalysisContext(std::shared_ptr<const std::vector<std::uint8_t>> snapshot,
            std::uint64_t imageBase, const QVector<FileAnalysisRegion>& regions,
            bool x86Compatible = true);
        // 把捕获文件 offset 映射为可证实 VA；无映射或范围不合法时返回 nullopt。
        std::optional<std::uint64_t> fileOffsetToVirtualAddress(std::uint64_t offset) const;
        // base/length 限定宿主允许请求的捕获总范围；零长/溢出清除范围，不补零或主动读取。
        void setCapturedAddressRange(std::uint64_t base, std::uint64_t length);
        // 定位 address 后切到 C 页分析；未载入时只请求窗口，字节就绪前不启动反编译。
        void showPseudocodeAt(std::uint64_t address);
        // 返回共享 C 页拥有的原文编辑器和反编译器；只读结果不授权真实目标写入。
        CodeTextEdit* pseudocodeView() const;
        GhidraDecompiler* decompiler() const;
        // 返回与当前缓存逐字节一致的已选指令副本；缺选区、越界或陈旧行返回 nullopt。
        std::optional<DisassemblySelection> selectedInstruction() const;
        // 只接受宿主读取时冻结的进程 VA 身份；缺创建时间时禁用导航，不按当前 PID 补授。
        // 文件偏移、物理和内核证据不能继承进程导航目标，字节缓存和编辑通路不受影响。
        void setProcessContext(std::uint32_t pid, std::uint64_t createTime100ns = 0);
        // 回放上一/下一步本地暂存历史；不向真实目标写入或撤销已提交事务。
        void undo();
        void redo();

    signals:
        // 共享缓存刷新通知；宿主应重新获取值副本，信号本身不是写入回执。
        void bytesChanged();
        // 当前定位 address 通知，使用本宿主的内存地址或文件偏移域。
        void currentAddressChanged(std::uint64_t address);
        // 宿主可向当前 menu 追加业务动作；address/valid 是当前指令坐标及有效性。
        // 菜单嵌套事件循环前宿主须冻结字节/来源，退出后复核代次与生命周期。
        void instructionContextMenuAboutToShow(QMenu* menu, std::uint64_t address, bool valid);
        // 请求宿主载入捕获范围内 address/length；由宿主保留准确来源和完整性检查。
        void windowRequested(quint64 address, quint64 length);

    protected:
        // 响应字体/主题变更更新展示，不改捕获证据、暂存字节或来源权限。
        void changeEvent(QEvent* event) override;

    private:
        // 从当前缓存和锚点更新正式反汇编页，保留宿主的坐标解释。
        void rebuildDisassembly();
        // 更新正式文本/结构子页，只呈现完整有效的已捕获窗口。
        void rebuildText();
        // 更新完整捕获比较；不足或超限由共享比较模型明确报告。
        void rebuildComparison();
        // 将读取基线与上次读取参照安装到 HEX，展示暂存与真实读取变化。
        void updateHighlights();
        // forward=true 重做、false 撤销；仅回放当前基线之上的本地历史。
        void applyHistory(bool forward);
        // 根据缓存、权限和历史刷新按钮/状态，不自行提升写权限。
        void updateState();
        // 打开共享汇编预览；确认后仍只将完整指令补丁暂存到当前缓存。
        void showAssemblyEditor();
        // 配置行内汇编编辑；单击/工具按钮只暂存单条完整指令，不写入真实内存。
        void initializeInlineAssemblyEditing();
        // 在可编辑状态下请求正式反汇编页编辑已选指令。
        void beginInlineAssemblyEdit();
        // 将当前字节、读取参照、位数与范围同步到只读 provider，不访问真实目标。
        void synchronizeSnapshotProvider();
        // 在当前可编辑捕获内以 bytes 等长替换 address 起的缓存，并更新历史和选区。
        void stageSnapshotBytes(std::uint64_t address, const QByteArray& bytes);
        // 在正式反汇编视图中选择 address 对应的已解码行。
        void selectInstruction(std::uint64_t address);
        // 返回可见指令/文本选区起点，否则返回 HEX 光标或空缓存基址。
        std::uint64_t selectedAddress() const;
        // 判断 address 是否属于当前已经载入的字节，不将可请求范围当作已读取。
        bool contains(std::uint64_t address) const;
        // 将架构选择框转换为明确的 x86/x64 解码枚举。
        DisassemblyArchitecture architecture() const;
        // 建立共享 C 子页并连接捕获字节/窗口请求端口。
        void initializePseudocodeView();
        // 取消陈旧 C 请求；clearContext=true 同时撤销捕获范围及文件解释上下文。
        void invalidatePseudocode(bool clearContext = false);
        // 同步 C 上下文并刷新其当前可用状态，不自行开始真实读取。
        void updatePseudocodeState();
        // 用当前来源、修订代次、位置和架构构造 C 页不可变解释上下文。
        void synchronizePseudocodeContext();
        // 选择捕获内的闭区间 first..last；倒序或任一端点未载入时返回 false。
        bool selectByteRange(std::uint64_t first, std::uint64_t last);
        // 仅在授权捕获范围内尚缺请求字节时发窗口信号并返回 true，不代表读取完成。
        bool requestCapturedWindow(std::uint64_t address, std::uint64_t length);
        // 把可证实的捕获 VA 反向映射为文件偏移；无对应原始字节时返回 nullopt。
        std::optional<std::uint64_t> virtualAddressToFileOffset(std::uint64_t address) const;

        WorkbenchCompareView* m_comparison = nullptr; // 与实时工作台共用虚拟比较模型。
        WorkbenchPseudocodeView* m_pseudocodePage = nullptr; // 与实时工作台共用反编译页。
        HexView* m_hex = nullptr; // 当前共享字节缓存及正式 HEX 画布。
        QTabWidget* m_tabs = nullptr; // HEX、反汇编、文本、对比和 C 子页切换器。
        WorkbenchDisasmView* m_disassembly = nullptr; // 正式反汇编及行内汇编视图。
        QCheckBox* m_highlightChanges = nullptr; // 控制参照差异的展示，不改字节。
        WorkbenchTextView* m_text = nullptr; // 共用文本和结构解释视图。
        QComboBox* m_architecture = nullptr; // 用户明确选择的 x86/x64 解码位数。
        QLineEdit* m_decodeAddress = nullptr; // 反汇编起点输入，与捕获坐标域一致。
        QLabel* m_decodeLabel = nullptr; // 起点输入说明标签。
        QPushButton* m_assemble = nullptr; // 打开完整指令汇编预览的按钮。
        QPushButton* m_undo = nullptr; // 撤销本地暂存历史按钮。
        QPushButton* m_redo = nullptr; // 重做本地暂存历史按钮。
        QLabel* m_status = nullptr; // 捕获范围和暂存修改状态。
        QLabel* m_decodeStatus = nullptr; // 指令解码状态及范围说明。
        QByteArray m_original; // 当前读取基线，显式接受或新捕获时重建。
        QByteArray m_observed; // 已记录到编辑历史的最新缓存，用于聚合后续变化。
        QByteArray m_previousRead; // 同身份/起点/长度的上次实际读取基线。
        QByteArray m_lastReferenceOriginal; // 已安装参照的共享字节，重复编辑不重建整个基线。
        QByteArray m_lastReferencePrevious; // 相同来源的上次读取参照。
        QByteArray m_recentChanges; // 当前与上次实际读取不同的逐字节展示标记。
        MemorySnapshotBytesProvider m_bytesProvider; // 仅服务当前捕获缓存的共享只读 provider。
        QString m_sourceIdentity; // 宿主提供的稳定真实来源/后端/会话身份。
        detail::MemoryEditHistory m_history; // 当前基线之上的有界本地差异历史。
        std::uint64_t m_base = 0; // 已载入窗口起点，不等同于全部可请求范围。
        std::uint64_t m_anchor = 0; // 当前正式反汇编起点。
        std::uint64_t m_snapshotRevision = 0; // 取消陈旧编辑、解释和模态动作的修订代次。
        SnapshotAddressKind m_addressKind = SnapshotAddressKind::MemoryAddress; // 当前地址或文件偏移域。
        bool m_editable = false; // 本地暂存是否开放；不代表真实目标写权限。
        bool m_syncing = false; // 共享子页同步期间防止重复导航处理。
        std::uint32_t m_processPid = 0; // 读取时捕获的进程 PID，仅用于显式进程导航。
        std::uint64_t m_processCreateTime100ns = 0; // 与 PID 配对的创建时间，阻断 PID 复用。
        std::shared_ptr<const std::vector<std::uint8_t>> m_fileAnalysisSnapshot; // 文件分析所用不可变原始捕获。
        QVector<FileAnalysisRegion> m_fileAnalysisRegions; // 文件原始区间到 PE VA 的可证实映射。
        std::optional<std::pair<std::uint64_t, std::uint64_t>> m_capturedAddressRange; // 可请求捕获总范围的闭区间。
        std::uint64_t m_fileImageBase = 0; // 文件映像解释基址，不改变文件偏移显示坐标。
        bool m_fileX86Compatible = true; // 文件格式是否允许当前 x86/x64 解释。
    };
}
