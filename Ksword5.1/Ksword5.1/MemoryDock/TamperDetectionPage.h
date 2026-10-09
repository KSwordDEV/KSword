#pragma once

// ============================================================
// TamperDetectionPage.h
// 作用：
// - 对同一段内存同时走多条相互独立的读取路径，逐页互比，找出"CPU 读到的内容"
//   与"内存里真实的内容"不一致的页。
//
// 为什么需要这一页（它和既有的内存对比不是一回事）：
// - 内存 vs 磁盘映像的比对（ImageDiff / 注入扫描）能抓到普通的 inline hook，
//   但**抓不到 SLAT / EPT 级别的隐藏**：那种隐藏让处理器取指时走真页、读数据时
//   走影子页，而影子页里放的正是磁盘上那份原始字节。于是"内存 vs 磁盘"会得到
//   完美一致的结果，隐藏者要的就是这个效果。
// - 拆穿它的唯一办法是一条**不经过 CPU 页表**的读取路径。本项目里那条路径是
//   DDMA（磁盘控制器总线主控 DMA）：数据由 HBA 直接搬进指定物理页，不受
//   SLAT / EPT 约束。CPU 侧与 DMA 侧对同一物理页给出不同答案，就是重定向的判据。
//
// 关键设计（都是判据的一部分，不是实现细节）：
// - **物理地址只翻译一次**。R0 物理读与 DDMA 读必须落在同一个物理页上，否则
//   两次翻译之间的任何变化都会被算成内容差异，而那是个假读数。
// - **多轮采样**。内存随时可能正在被合法写入（自修改代码、热补丁、数据页），
//   一次不一致与一次篡改在单轮里无法区分。只有每一轮都不一致才升为结论。
// - **读失败不是"干净"**。任何一条路径失败、不可用或未覆盖，该页的结论只能是
//   "无法判定"，绝不允许良性化成"未发现问题"。
// - 判定矩阵与四态语义在 shared/evidence/MemoryTamperCrossView.h，Qt-free，
//   由离线套件穷举覆盖。本页只负责采集与展示，不自己下结论。
// ============================================================

#include "MemoryAccessBackend.h"

#include "../../../shared/evidence/MemoryTamperCrossView.h"

#include <QString>
#include <QWidget>

#include <cstdint>
#include <functional>
#include <vector>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class CodeEditorWidget;
class QPushButton;
class QSpinBox;
class QTableWidget;

namespace ks::ui
{
    class VisibleTableWidget;
}

namespace ksword::memory_dock
{
    // TamperPageResult：一页的采集与结论。
    struct TamperPageResult
    {
        std::uint64_t virtualAddress = 0;
        std::uint64_t physicalAddress = 0;
        bool physicalAddressValid = false;
        QString translateFailureText;
        Ksword::Evidence::TamperFinding finding;
    };

    // TamperScanRequest：一次扫描的全部输入，拷贝到工作线程，不含任何 Qt 控件。
    struct TamperScanRequest
    {
        std::uint32_t processId = 0;
        std::uint64_t startAddress = 0;
        std::uint64_t pageCount = 0;
        int roundCount = 3;
        bool useUserMode = true;
        bool useKernelVirtual = true;
        bool useKernelPhysical = true;
        bool useHvm = true;
        bool useDma = true;
        // 两条静态参考。它们不反映内存现状，只回答"这一页本来该是什么样"，
        // 因此与活体路径分属不同的组，跨组分歧的含义也不同。
        bool useImageSection = false;
        bool useOnDiskImage = false;
        // 磁盘映像归一化需要加载基址与文件路径：同一份文件在不同基址上的字节
        // 并不相同（重定位），拿文件原样去比每一次正常加载都会被报成差异。
        std::uint64_t moduleBaseAddress = 0;
        QString moduleFilePath;
        ksword::memory_backend::DdmaSession ddmaSession;
    };

    // 不带 Q_OBJECT：本页不声明自有信号槽，全部用 lambda + connect(this, ...)，
    // 与同目录的 DdmaPage / SystemMemoryAuditPage 一致，省掉一次 moc。
    class TamperDetectionPage final : public QWidget
    {
    public:
        explicit TamperDetectionPage(QWidget* parent = nullptr);
        ~TamperDetectionPage() override;

        // setAttachedProcess：由 MemoryDock 在附加/分离时同步过来。
        void setAttachedProcess(std::uint32_t processId, const QString& processName);

        // setModuleCandidates：把当前进程的模块列表同步过来，供目标下拉框使用。
        // 每一项是 (显示文本, 基址, 大小)。
        struct ModuleCandidate
        {
            QString displayText;
            QString filePath;
            std::uint64_t baseAddress = 0;
            std::uint64_t sizeBytes = 0;
        };
        void setModuleCandidates(const std::vector<ModuleCandidate>& candidates);

        // refreshChannelAvailability：DDMA 会话变化时由 MemoryDock 调用。
        void refreshChannelAvailability();

    private:
        void buildUi();
        void wireSignals();
        void startScan();
        void applyScanResults(const std::vector<TamperPageResult>& results);
        void renderSelectedDetail();
        void updateRunButtonState();
        bool parseScanRange(std::uint64_t& startOut, std::uint64_t& pageCountOut, QString& errorOut) const;

        std::uint32_t m_attachedPid = 0;
        QString m_attachedProcessName;
        std::vector<ModuleCandidate> m_moduleCandidates;
        std::vector<TamperPageResult> m_results;
        bool m_scanInFlight = false;
        std::uint64_t m_scanGeneration = 0;

        QComboBox* m_targetCombo = nullptr;
        QLineEdit* m_rangeStartEdit = nullptr;  // 目标选"自定义范围"时的起始地址。
        QCheckBox* m_useUserModeCheck = nullptr;
        QCheckBox* m_useKernelVirtualCheck = nullptr;
        QCheckBox* m_useKernelPhysicalCheck = nullptr;
        QCheckBox* m_useHvmCheck = nullptr;
        QCheckBox* m_useDmaCheck = nullptr;
        QCheckBox* m_useImageSectionCheck = nullptr;
        QCheckBox* m_useOnDiskImageCheck = nullptr;
        QSpinBox* m_roundSpin = nullptr;
        QSpinBox* m_maxPageSpin = nullptr;
        QPushButton* m_runButton = nullptr;
        QLabel* m_statusLabel = nullptr;
        QLabel* m_channelHintLabel = nullptr;
        ks::ui::VisibleTableWidget* m_resultTable = nullptr;
        CodeEditorWidget* m_detailText = nullptr;
    };
}
