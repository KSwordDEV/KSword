#pragma once

// 统一 C 伪代码子页：只消费宿主的已捕获字节，目标读取和编辑始终由宿主负责。
#include "WorkbenchDisasmView.h"
#include "../Decompiler/GhidraDecompiler.h"
#include <QWidget>
#include <QVector>
#include <QElapsedTimer>
#include <memory>
#include <optional>

class CodeEditorWidget;
class CodeTextEdit;
class QLineEdit;
class QLabel;
class QPushButton;
class QProgressBar;
class QTimer;

namespace ks::ui
{
    // 文件节映射同时供快照结构分析与伪代码定位使用，偏移与 VA 不混用。
    struct FileAnalysisRegion
    {
        std::uint64_t fileOffset = 0;       // 文件中的节起点。
        std::uint64_t fileSize = 0;         // 真正捕获的文件字节长度。
        std::uint64_t rva = 0;              // 节的映像相对地址。
        std::uint64_t virtualSize = 0;      // 节映射长度，不把零填充区当文件字节。
        QString name;                       // 原始节名。
        bool executable = false;            // 结构分析提供的可执行标记。
    };
    enum class SnapshotAddressKind { MemoryAddress, FileOffset };

    // 宿主每次改身份、来源代次或分析窗口时更新此上下文；长度不包含任何未捕获范围。
    struct WorkbenchPseudocodeContext
    {
        QString sourceIdentity;               // 产生这些字节的冻结来源身份。
        std::uint64_t revision = 0;            // 来源代次，重读/身份变化后不可沿用旧结果。
        std::uint64_t baseAddress = 0;         // 可分析窗口的起点（VA 或文件偏移）。
        std::uint64_t length = 0;              // 可分析窗口长度，地址加法必须不回绕。
        std::uint64_t selectedAddress = 0;     // 请求分析的函数位置。
        int addressBits = 64;                 // x86/x64 指令架构，不决定文件偏移宽度。
        bool x86Compatible = true;            // 非 x86/x64 映像不能交给当前后端。
        SnapshotAddressKind addressKind = SnapshotAddressKind::MemoryAddress;
        std::uint64_t maximumWindowBytes = 0; // 0 使用后端上限，否则服从宿主缓存读取上限。
    };

    class WorkbenchPseudocodeView final : public QWidget
    {
        Q_OBJECT
    public:
        explicit WorkbenchPseudocodeView(QWidget* parent = nullptr);
        ~WorkbenchPseudocodeView() override;
        // 与其它工作台子页一致，不把工具栏文字的最小宽度传播到宿主页面栈。
        QSize minimumSizeHint() const override
        {
            return QSize(0, 0);
        }
        // provider 非拥有，销毁前宿主必须先传 nullptr；本页不直接执行目标 I/O。
        void setBytesProvider(IWorkbenchBytesProvider* provider);
        void setContext(const WorkbenchPseudocodeContext& context);
        // PE 路径使用结构分析的同一冻结映像，并叠加当前已捕获窗口的编辑字节。
        void setFileAnalysisContext(std::shared_ptr<const std::vector<std::uint8_t>> snapshot,
            std::uint64_t imageBase, const QVector<FileAnalysisRegion>& regions,
            bool x86Compatible = true);
        std::optional<std::uint64_t> fileOffsetToVirtualAddress(std::uint64_t offset) const;
        std::optional<std::uint64_t> virtualAddressToFileOffset(std::uint64_t address) const;
        // invalidate 清理旧结果并取消外部进程；refreshView 只重验字节和继续待加载请求。
        void invalidate();
        void refreshView();
        void startDecompilation();
        void openFindPanel();
        // 使用完整项目编辑器外壳，底层 CodeTextEdit 仅供光标行定位和离屏验收。
        CodeTextEdit* editor() const noexcept;
        GhidraDecompiler* decompiler() const noexcept;

    signals:
        void windowRequested(quint64 address, quint64 length);
        void requestHexLocate(quint64 address);
        void requestDisasmLocate(quint64 address);

    protected:
        void changeEvent(QEvent* event) override;

    private:
        void buildUi();
        void refreshDecompilerRuntime();
        void updateState();
        void locateLine(bool disassembly);
        void finishDecompilation(const DecompilerResult& result);
        // buildRequest 校验每个字节掩码，返回 false 时 reason 是稳定错误码。
        bool buildRequest(DecompilerRequest& request, QString& reason) const;
        bool requestStillCurrent() const;
        void setStatus(const QString& source);
        bool setCode(const QString& code);
        // 一次显式分析含读页等待；续读可保留原耗时，不把未知工作量画成百分比。
        void beginProgress(const QElapsedTimer* continued = nullptr);
        void stopProgress();
        // 只接受当前票据的真实后端阶段，刷新不读取目标或改动正文。
        void handleProgress(const DecompilerProgress& progress);
        void refreshProgress();
        bool setProgressVisible(QWidget* widget, bool visible);

        IWorkbenchBytesProvider* provider_ = nullptr; // 宿主拥有的共同数据源。
        WorkbenchPseudocodeContext context_;          // 当前冻结分析上下文。
        WorkbenchPseudocodeContext requestContext_;   // 启动时身份、代次和范围。
        DecompilerRequest request_;                  // 启动时字节，用于完成后逐字复核。
        std::shared_ptr<const std::vector<std::uint8_t>> fileSnapshot_; // 同一份完整 PE 证据。
        QVector<FileAnalysisRegion> fileRegions_;    // 单义文件偏移与 RVA 映射。
        std::uint64_t imageBase_ = 0;                 // PE 首选映像基址。
        std::uint64_t epoch_ = 0;                     // 重入回调与过期结果失效票据。
        bool fileX86Compatible_ = true;               // PE 指令架构是否受支持。
        bool waitingForBytes_ = false;               // 一次显式请求等待宿主读页。
        bool hasRequest_ = false;                    // 结果/进程对应的字节票据是否仍有效。
        QVector<quint64> lineAddresses_;              // 每行的后端 VA 或原始地址。
        QVector<bool> lineValid_;                    // 地址有效标记，地址 0 也允许定位。
        QString statusSource_;                       // 可随语言切换重译的原始提示。
        GhidraDecompiler* decompiler_ = nullptr;      // 隔离的官方 Ghidra 后端。
        CodeEditorWidget* code_ = nullptr;            // 带查找工具栏的统一编辑器外壳。
        CodeTextEdit* text_ = nullptr;                // 外壳拥有的底层只读 C 编辑器。
        QLineEdit* directory_ = nullptr;              // 可选的自定义 Ghidra 目录。
        QLabel* runtimeStatus_ = nullptr;             // 安装与配置状态。
        QLabel* status_ = nullptr;                    // 请求、边界及错误诊断。
        QPushButton* install_ = nullptr;              // 官方插件管理入口。
        QPushButton* refresh_ = nullptr;              // 刷新后端配置。
        QPushButton* decompile_ = nullptr;            // 显式反编译当前函数。
        QPushButton* cancel_ = nullptr;               // 取消当前运行/等待读取。
        QPushButton* locateHex_ = nullptr;            // 对当前 C 行定位十六进制。
        QPushButton* locateDisasm_ = nullptr;         // 对当前 C 行定位反汇编。
        QProgressBar* progress_ = nullptr;            // 有界真实工作量或不定活动条。
        QLabel* progressLabel_ = nullptr;             // 本次阶段及实际耗时。
        QTimer* progressTimer_ = nullptr;             // 只在有限分析期间更新耗时。
        QElapsedTimer progressElapsed_;               // 单调时钟，不受系统时间调整影响。
        DecompilerProgress progressState_;             // 当前阶段与实际完成量。
        std::uint64_t progressEpoch_ = 0;              // 进度所属的来源票据。
        bool progressActive_ = false;                 // 完成/取消/换源后忽略迟到进度。
    };
}
