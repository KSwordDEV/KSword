#pragma once

// ============================================================
// DdmaPage.h
// 作用：
// 1) 配置并管理 DDMA（磁盘直接内存访问）通道，这份配置被"内存"页下的
//    内存搜索、内存查看器、驱动内存读写、系统内存审计四个子页共用；
// 2) 提供 DDMA 自身的物理读写入口；
// 3) 提供"标准通道 vs DDMA"同址复核，用来发现被 SLAT 重定向的物理页。
//
// DDMA 是什么：
// - 让磁盘控制器用总线主控 DMA 直接读写任意物理地址。数据通路走 HBA 而不
//   经过 CPU 页表，因此不受 SLAT/EPT 约束，能读到被上层虚拟化重定向或隐藏
//   的物理页内容。技术来源：https://github.com/btbd/ddma。
//
// 代价（界面上必须始终讲清楚，不能藏起来）：
// - 结构性地需要借用一块磁盘扇区当中转站，所以本页强制要求用户显式指定
//   暂存扇区 LBA 并确认其可被覆盖，不提供任何默认值；
// - 开着内核调试的机器上会命中 MiShowBadMapper 蓝屏，此时整条通道禁用。
// ============================================================

#include "MemoryAccessBackend.h"
// DdmaDiskEntry 按值存进 std::vector，必须拿到完整类型，不能前置声明。
#include "../ArkDriverClient/ArkDriverClient.h"
// 暂存扇区候选的纯算术在 shared/evidence 里，Qt-free / Win32-free，单测覆盖同一份。
#include "../../../shared/evidence/DdmaScratchPlan.h"
// 地址/扇区号的进制规则同样在 shared/evidence 里，两边共用同一份并被穷举测试覆盖。
#include "../../../shared/evidence/NumericTextParse.h"

#include <QByteArray>
#include <QString>
#include "../UI/StructuredFieldView.h"
#include <QWidget>

#include <atomic>
#include <cstdint>
#include <functional>
#include <vector>

class QCheckBox;
class QEvent;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
namespace ks::ui
{
    class HexView;
}
class CodeTextEdit;

namespace ks::ui
{
    class VisibleTableWidget;
    class SnapshotWorkbenchWidget;
}

class DdmaPage final : public QWidget
{
public:
    // 构造函数：
    // - 作用：构建 DDMA 页的全部界面并置为"未配置"状态；
    // - 参数 parent：Qt 父控件指针，可为空。
    explicit DdmaPage(QWidget* parent = nullptr);

    // session：
    // - 作用：返回当前 DDMA 会话配置；
    // - 返回：常量引用。本页是进程级会话的唯一写入者，这里返回的就是写进
    //   ksword::memory_backend 那一份的本地副本，两者恒等。
    const ksword::memory_backend::DdmaSession& session() const { return m_session; }

    // setSessionChangedCallback：
    // - 作用：注册会话变化回调，让 MemoryDock 在配置变动后刷新其它页的后端状态；
    // - 参数 callback：无参回调，在主线程调用。
    void setSessionChangedCallback(std::function<void()> callback);

protected:
    // changeEvent：
    // - 作用：深浅色切换后重新下发语义色样式；
    // - 参数 event：Qt 事件对象。
    void changeEvent(QEvent* event) override;

private:
    // ========================================================
    // 界面构建
    // ========================================================

    // initializeUi：构建根布局与四个分组。
    void initializeUi();
    // buildIntroGroup：构建顶部说明块，讲清 DDMA 是什么、代价是什么。
    QGroupBox* buildIntroGroup();
    // buildChannelGroup：构建暂存扇区输入、确认勾选、探测按钮与磁盘表。
    QGroupBox* buildChannelGroup();
    // buildAccessGroup：构建 DDMA 自身的物理读写入口。
    QGroupBox* buildAccessGroup();
    // buildCompareGroup：构建"标准通道 vs DDMA"同址复核入口。
    QGroupBox* buildCompareGroup();

    // applySemanticStyles：
    // - 作用：给会话状态标签与高危按钮下发语义色；
    // - 说明：语义色是调用瞬间的快照，构造期与主题切换必须走同一条路径。
    void applySemanticStyles();

    // ========================================================
    // 交互逻辑
    // ========================================================

    // parseScratchLbaFromUi：
    // - 作用：解析暂存 LBA 输入框；
    // - 参数 lbaOut：输出解析结果；
    // - 参数 errorTextOut：失败原因；
    // - 返回：true 表示用户确实填了一个合法 LBA。空输入一律判为未填写，
    //   不会退化成 0——LBA 0 是 MBR 所在扇区，绝不能靠默认值选中它。
    bool parseScratchLbaFromUi(std::uint64_t& lbaOut, QString& errorTextOut) const;

    // probeChannels：
    // - 作用：枚举 \Driver\Disk 设备并（在已填 LBA 时）逐块做一次 ATA DMA 读探测；
    // - 处理：结果写入磁盘表，同时刷新能力标志与会话可用性。
    void probeChannels();

    // ScratchDetection：一次候选侦测的完整结果，含可直接展示的证据文本。
    struct ScratchDetection
    {
        bool ok = false;                // 是否算出了可用候选。
        std::uint64_t suggestedLba = 0; // 建议填入的 LBA。
        QString sourceText;             // 候选来源：专属暂存文件 / 未分配间隙。
        QString summaryText;            // 面向用户的结论与证据。
        QString scratchFilePath;        // 走文件路线时的暂存文件路径，否则为空。
        bool contentAllZero = false;    // 建议区间当前是否全零。
    };

    // detectScratchByOwnedFile：
    // - 作用：在选中磁盘上的某个卷里建一个专属暂存文件，用它自己的簇当暂存区；
    // - 为什么不是"挑一个空闲簇"：从读到卷位图到 DMA 真正发生之间，系统随时可能
    //   把那个簇分配给新文件并写入，我们的"还原"就会把刚写进去的文件数据覆盖回
    //   旧内容。先把簇占为己有，这个竞态就不存在了——那块扇区归我们，写坏也只
    //   坏我们自己的文件。
    // - 处理：枚举卷 → 找出落在本磁盘上的 → 建文件并落盘 → 取 retrieval pointers
    //   拿 LCN → 用卷起始偏移与簇大小换算成磁盘 LBA。
    // - 返回：成功时 ok 为真且 scratchFilePath 非空；失败时 summaryText 说明原因。
    ScratchDetection detectScratchByOwnedFile(
        std::uint32_t driveIndex,
        std::uint32_t sectorSize);

    // detectScratchCandidatesForSelectedDisk：
    // - 作用：读当前选中磁盘的分区表，算出可作暂存区的未分配间隙，并读回建议
    //   区间的实际内容作为第二重证据；
    // - 处理：分区表只说"未分配"，不保证那里真的空着——磁盘头部间隙正是引导器
    //   寄居处。所以分级交给 shared/evidence 的纯算术，本函数只负责 Win32 读取
    //   与"读回来是不是全零"这一条实测证据；
    // - 返回：侦测结果；失败时 summaryText 说明卡在哪一步。
    ScratchDetection detectScratchCandidatesForSelectedDisk();

    // detectScratchCandidatesByGap：
    // - 作用：退路——当专属暂存文件那条路走不通时，改从分区表的未分配间隙里挑；
    // - 说明：分区表说"未分配"只代表没人登记，不代表那里是空的，所以分级与
    //   内容复核两道证据缺一不可。
    ScratchDetection detectScratchCandidatesByGap(
        std::uint32_t driveIndex,
        const ksword::ark::DdmaDiskEntry& entry);

    // buildScratchContext：
    // - 作用：为一个候选起始 LBA 生成"这块扇区现在是什么"的结构上下文；
    // - 内容：目标磁盘、覆盖范围、磁盘字节偏移、**落在哪个分区里还是分区之外**、
    //   当前内容是否全零、以及前 128 字节的十六进制预览；
    // - 说明：一律现读现算，不复用侦测过程里的中间值——这段是给用户"再确认一次"
    //   用的，必须反映点下按钮那一刻磁盘上的真实状态。
    struct ScratchContext
    {
        ks::ui::FieldDocument fields;
        QString bytePreview; // Literal hex/ASCII view of disk bytes, not a property report.
    };
    ScratchContext buildScratchContext(
        std::uint32_t driveIndex,
        std::uint64_t startLba,
        std::uint32_t sectorSize,
        bool& allZeroOut);

    // detectScratchFromUi：把侦测结果落到 LBA 输入框并展示证据。
    // 刻意**不**替用户勾上确认框：自动算出候选是为了省掉手算，不是替他承担责任。
    void detectScratchFromUi();

    // physicalDriveIndexFromDeviceName：
    // - 输入：\Device\Harddisk0\DR0 这类设备对象名；
    // - 输出：磁盘序号，用于拼出 \\.\PhysicalDriveN；
    // - 返回：解析成功与否。名字拿不到时不能猜，只能让侦测失败。
    static bool physicalDriveIndexFromDeviceName(
        const std::wstring& deviceName,
        std::uint32_t& indexOut);

    // activateSelectedDisk：
    // - 作用：把磁盘表当前选中行设为 DDMA 通道，落地成会话配置。
    void activateSelectedDisk();

    // clearSession：
    // - 作用：清空会话配置，让所有页面立刻退回标准通道。
    void clearSession();

    // refreshSessionState：
    // - 作用：按当前控件与探测结果重算会话可用性并刷新状态标签；
    // - 说明：唯一的可用性判据在 MemoryAccessBackend::isDdmaUsable，本函数
    //   只负责把结论展示出来，不重复实现判据。
    void refreshSessionState();

    // readPhysicalFromUi：按界面参数用 DDMA 读取物理内存并填充十六进制视图。
    void readPhysicalFromUi();
    void resetAccessSnapshot();
    void refreshAccessEditorState();

    // writePhysicalFromUi：把十六进制视图里改动过的字节用 DDMA 写回物理内存。
    void writePhysicalFromUi();

    // compareBackendsFromUi：
    // - 作用：对同一物理地址分别用标准通道与 DDMA 各读一页并逐字节比对；
    // - 说明：两者不一致正是"这一页被 SLAT 重定向或隐藏"的直接证据，
    //   这也是 DDMA 相对标准通道的全部价值所在。
    void compareBackendsFromUi();

    // parseAddressText：解析物理地址。无前缀按十六进制，0x 前缀恒为十六进制。
    static bool parseAddressText(const QString& text, std::uint64_t& valueOut);
    // parseSectorNumberText：解析扇区 LBA。LBA 是数量不是地址，无前缀按十进制。
    static bool parseSectorNumberText(const QString& text, std::uint64_t& valueOut);
    // formatAddress：格式化成 16 位十六进制文本。
    static QString formatAddress(std::uint64_t address);

private:
    // ========================================================
    // 会话与探测缓存
    // ========================================================

    ksword::memory_backend::DdmaSession m_session;      // 当前会话配置。
    std::vector<ksword::ark::DdmaDiskEntry> m_diskCache; // 最近一次探测到的磁盘。
    bool m_probeCompleted = false;                      // 是否至少成功探测过一次。
    bool m_kernelDebuggerEnabled = false;               // 探测到的内核调试状态。
    std::uint32_t m_transferBytes = 0;                  // R0 自报的一次传输长度。
    std::uint32_t m_scratchSectorCount = 0;             // R0 自报的暂存扇区数。
    std::function<void()> m_sessionChangedCallback;     // 会话变化回调。

    // ========================================================
    // 读写快照
    // ========================================================

    QByteArray m_originalBytes;     // 读回的原始字节，用于比对差异。
    QByteArray m_editedBytes;       // 编辑缓存，写回时只提交差异部分。
    std::uint64_t m_snapshotAddress = 0; // 快照起始物理地址。
    bool m_hasSnapshot = false;     // 是否已有有效快照。
    ksword::memory_backend::DdmaSession m_snapshotSession; // 快照绑定的磁盘与暂存区。
    std::uint64_t m_snapshotSessionGeneration = 0;

    // ========================================================
    // 控件
    // ========================================================

    QLineEdit* m_scratchLbaEdit = nullptr;          // 暂存扇区 LBA 输入。
    QCheckBox* m_scratchAckCheck = nullptr;         // 覆盖确认勾选。
    QLabel* m_scratchImpactLabel = nullptr;         // 实时显示会覆盖哪几个扇区。
    QPushButton* m_probeButton = nullptr;           // 探测按钮。
    QPushButton* m_detectScratchButton = nullptr;   // 侦测候选暂存扇区按钮。
    QLabel* m_scratchDetectLabel = nullptr;         // 侦测结论与证据。
    // 扇区上下文：候选定下来之后，把"这块扇区现在是什么"摊开给用户再确认一次。
    ks::ui::StructuredFieldView* m_scratchContextView = nullptr;
    CodeTextEdit* m_scratchBytesView = nullptr;
    QString m_scratchFilePath;                      // 当前专属暂存文件路径，可为空。
    QPushButton* m_activateButton = nullptr;        // 启用为通道按钮。
    QPushButton* m_clearButton = nullptr;           // 清除会话按钮。
    ks::ui::VisibleTableWidget* m_diskTable = nullptr; // 磁盘表。
    QLabel* m_capabilityLabel = nullptr;            // 能力标志摘要。
    QLabel* m_sessionStateLabel = nullptr;          // 会话可用性状态。

    QLineEdit* m_accessAddressEdit = nullptr;       // 物理地址输入。
    QSpinBox* m_accessLengthSpin = nullptr;         // 读取长度。
    QPushButton* m_accessReadButton = nullptr;      // DDMA 读取按钮。
    QPushButton* m_accessWriteButton = nullptr;     // DDMA 写回按钮。
    ks::ui::SnapshotWorkbenchWidget* m_accessMemoryEditor = nullptr; // 多视图暂存编辑器。
    ks::ui::HexView* m_accessHexEditor = nullptr;   // 十六进制视图别名。
    QLabel* m_accessStatusLabel = nullptr;          // 读写状态文本。

    QLineEdit* m_compareAddressEdit = nullptr;      // 复核物理地址输入。
    QPushButton* m_compareButton = nullptr;         // 复核按钮。
    QLabel* m_compareResultLabel = nullptr;         // 复核结论。
    QTableWidget* m_compareTable = nullptr;         // 逐字节差异明细。
};
