#pragma once

// ============================================================
// DiskEditorTab.h
// 作用：
// 1) 提供类似 DiskGenius 的物理磁盘查看与扇区编辑页面；
// 2) 展示友好的横向柱形分区图、分区表、扇区 HEX 编辑器和操作日志；
// 3) 写盘默认加“只读/解锁/二次确认/扇区对齐”保护，避免误操作。
// ============================================================

#include "DiskAdvancedModels.h"
#include "DiskEditorModels.h"
#include "DiskCaptureTransaction.h"

#include "../../Framework.h"

#include <QByteArray>
#include <QWidget>

#include <cstdint>
#include <vector>

class QCheckBox;
class QComboBox;
class QGroupBox;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class CodeEditorWidget;
class QPushButton;
class QSpinBox;
class QSplitter;
class QTabWidget;
class QTableWidget;
class QVBoxLayout;
namespace ks::ui
{
    class HexView;
}

namespace ks::misc
{
    class DiskMapWidget;

    // DiskEditorTab 说明：
    // - 输入：用户选择的物理磁盘、偏移和读取长度；
    // - 处理逻辑：后台枚举磁盘，主线程展示布局并按需读写；
    // - 返回行为：无业务返回值，所有结果显示到 UI 和日志。
    class DiskEditorTab final : public QWidget
    {
    public:
        // 构造函数：
        // - parent 为 Qt 父控件；
        // - 初始化 UI 后异步枚举磁盘。
        explicit DiskEditorTab(QWidget* parent = nullptr);

        // 析构函数：
        // - 后台回投使用 QPointer；
        // - 无需手动等待线程。
        ~DiskEditorTab() override = default;

    private:
        // initializeUi：
        // - 创建顶部工具栏、分区视图、扇区编辑区和日志区；
        // - 无输入参数，无返回值。
        void initializeUi();

        // initializeToolbar：
        // - 创建磁盘选择、刷新、跳转、读写保护按钮；
        // - 无输入参数，无返回值。
        void initializeToolbar();

        // initializeLayoutPanels：
        // - 创建柱形图、分区表、HEX 编辑器、侧边详情和日志；
        // - 无输入参数，无返回值。
        void initializeLayoutPanels();

        // initializeAdvancedPanels：
        // - 创建结构解析、卷映射、健康信息、搜索和镜像工具页；
        // - parent 为承载高级页的父控件；
        // - 无返回值。
        void initializeAdvancedPanels(QWidget* parent);

        // initializeConnections：
        // - 连接 UI 信号到页面动作；
        // - 无输入参数，无返回值。
        void initializeConnections();

        // refreshDiskListAsync：
        // - 后台枚举物理磁盘；
        // - forceRefresh 表示用户主动刷新；
        // - 无返回值，完成后回主线程更新。
        void refreshDiskListAsync(bool forceRefresh);

        // applyDiskList：
        // - 应用后台枚举结果；
        // - disks 为磁盘列表；
        // - errorText 为失败诊断；
        // - 无返回值。
        void applyDiskList(std::vector<DiskDeviceInfo> disks, const QString& errorText);

        // currentDisk：
        // - 获取当前选中的磁盘；
        // - 返回磁盘指针，未选中返回 nullptr。
        const DiskDeviceInfo* currentDisk() const;

        // currentPartition：
        // - 获取当前选中的分区或未分配块；
        // - 返回分区指针，未选中返回 nullptr。
        const DiskPartitionInfo* currentPartition() const;

        // updateDiskSummary：
        // - 刷新磁盘摘要卡片；
        // - 无输入参数，无返回值。
        void updateDiskSummary();

        // rebuildPartitionTable：
        // - 按当前磁盘重建分区表；
        // - 无输入参数，无返回值。
        void rebuildPartitionTable();

        // rebuildVolumeHints：
        // - 用最新卷映射结果回填分区表和分区详情提示；
        // - 无输入参数，无返回值。
        void rebuildVolumeHints();

        // syncPartitionSelection：
        // - 同步表格、柱形图、偏移输入框和详情；
        // - partitionIndex 为 DiskPartitionInfo::tableIndex；
        // - focusHex 表示是否立即读取该分区起始扇区；
        // - 无返回值。
        void syncPartitionSelection(int partitionIndex, bool focusHex);

        // readCurrentRangeAsync：
        // - 按当前磁盘、偏移和长度读取字节；
        // - reasonText 为日志说明；
        // - 无返回值。
        void readCurrentRangeAsync(const QString& reasonText);

        // applyReadResult：
        // - 把后台读取结果应用到 HEX 编辑器；
        // - baseOffset 为读取偏移；
        // - bytes 为读取到的数据；
        // - errorText 为空表示成功；
        // - 无返回值。
        void applyReadResult(DiskCapturedRange captured, const QString& errorText);

        // invalidateCapturedRange：切源/读取失败/写入未验证时清除所有旧证据与写回资格。
        void invalidateCapturedRange();
        // hasWritableCapture：按钮和写回入口共用来源门禁，不把非空旧缓冲当作可写资格。
        bool hasWritableCapture() const;

        // writeCurrentBuffer：
        // - 将当前 HEX 缓冲写回磁盘；
        // - 内部执行保护校验和用户确认；
        // - 无返回值。
        void writeCurrentBuffer();

        // refreshStructureReportAsync：
        // - 后台读取前部扇区并解析 MBR/GPT/启动扇区/卷映射/健康信息；
        // - reasonText 为日志说明；
        // - 无返回值。
        void refreshStructureReportAsync(const QString& reasonText);

        // applyStructureReport：
        // - 应用结构解析报告到高级页表格；
        // - report 为解析结果；
        // - errorText 为空表示成功；
        // - 无返回值。
        void applyStructureReport(DiskStructureReport report, const QString& errorText);

        // rebuildStructureTable：
        // - 用 m_structureReport.fields 重建结构字段表；
        // - 无输入参数，无返回值。
        void rebuildStructureTable();

        // rebuildVolumeTable：
        // - 用 m_structureReport.volumes 重建卷映射表；
        // - 无输入参数，无返回值。
        void rebuildVolumeTable();

        // rebuildHealthTable：
        // - 用 m_structureReport.healthItems 重建设备能力/健康表；
        // - 无输入参数，无返回值。
        void rebuildHealthTable();

        // rebuildRawBackendSelector：
        // - 根据当前磁盘 R0 预检结果重建三层访问下拉框；
        // - 不可用层不会加入列表，避免界面宣称与实际后端不一致。
        void rebuildRawBackendSelector();

        // currentRawBackend：
        // - 返回当前显式选中的 R0 磁盘后端；
        // - 未选择时回到 Windows 存储栈后端。
        unsigned long currentRawBackend() const;

        // runSearchAsync：
        // - 按工具区输入执行磁盘范围搜索；
        // - 无输入参数，无返回值。
        void runSearchAsync();

        // runHashAsync：
        // - 按工具区输入计算范围哈希；
        // - 无输入参数，无返回值。
        void runHashAsync();

        // runExportAsync：
        // - 按工具区输入导出磁盘镜像片段；
        // - 无输入参数，无返回值。
        void runExportAsync();

        // runImportAsync：
        // - 按工具区输入导入文件到磁盘；
        // - 写入前执行只读保护和 WRITE 确认；
        // - 无返回值。
        void runImportAsync();

        // runCompareAsync：
        // - 按工具区输入对比磁盘范围和文件；
        // - 无输入参数，无返回值。
        void runCompareAsync();

        // runScanAsync：
        // - 按工具区输入做快速读扫；
        // - 无输入参数，无返回值。
        void runScanAsync();

        // applyRangeTaskResult：
        // - 应用搜索/哈希/导出/导入/对比/读扫任务结果；
        // - taskName 为任务名称；
        // - result 为后台结果；
        // - 无返回值。
        void applyRangeTaskResult(const QString& taskName, DiskRangeTaskResult result);

        // updateToolRangeFromSelection：
        // - 将当前分区或当前读取范围同步到工具区 offset/length；
        // - usePartitionRange=true 时优先使用当前分区完整范围；
        // - 无返回值。
        void updateToolRangeFromSelection(bool usePartitionRange);

        // browseToolFile：
        // - 打开文件选择对话框并填入工具文件路径；
        // - saveMode=true 时选择保存路径，否则选择现有文件；
        // - 无返回值。
        void browseToolFile(bool saveMode);

        // parseToolRange：
        // - 解析工具区 offset/length；
        // - offsetOut/lengthOut 接收结果；
        // - 返回 true 表示解析成功。
        bool parseToolRange(std::uint64_t& offsetOut, std::uint64_t& lengthOut) const;

        // updateDirtyState：
        // - 设置当前缓冲是否有未保存修改；
        // - dirty 为目标状态；
        // - 无返回值。
        void updateDirtyState(bool dirty);

        // appendLog：
        // - 写入右侧操作日志；
        // - message 为日志正文；
        // - 无返回值。
        void appendLog(const QString& message);

        // severityText：
        // - 将结构/健康严重度转为中文文本；
        // - severity 为输入严重度；
        // - 返回展示文本。
        static QString severityText(DiskStructureSeverity severity);

        // parseAddressText：
        // - 解析十进制或 0x 十六进制地址；
        // - text 为输入文本；
        // - valueOut 为输出数值；
        // - 返回 true 表示解析成功。
        static bool parseAddressText(const QString& text, std::uint64_t& valueOut);

        // setControlsEnabledForBusy：
        // - 根据后台任务状态启禁用按钮；
        // - busy 为 true 时表示正在读/写/刷新；
        // - 无返回值。
        void setControlsEnabledForBusy(bool busy);

    private:
        QVBoxLayout* m_rootLayout = nullptr;        // m_rootLayout：页面根布局。
        QWidget* m_toolbarWidget = nullptr;         // m_toolbarWidget：顶部工具栏容器。
        QHBoxLayout* m_toolbarLayout = nullptr;     // m_toolbarLayout：顶部工具栏布局。
        QComboBox* m_diskCombo = nullptr;           // m_diskCombo：物理磁盘选择框。
        QComboBox* m_backendCombo = nullptr;        // m_backendCombo：三层 R0 磁盘访问后端选择框。
        QPushButton* m_refreshButton = nullptr;     // m_refreshButton：刷新磁盘列表按钮。
        QPushButton* m_readButton = nullptr;        // m_readButton：读取当前范围按钮。
        QPushButton* m_writeButton = nullptr;       // m_writeButton：写回当前缓冲按钮。
        QPushButton* m_partitionStartButton = nullptr; // m_partitionStartButton：跳到当前分区起始。
        QLineEdit* m_offsetEdit = nullptr;          // m_offsetEdit：读取起始偏移。
        QSpinBox* m_lengthSpin = nullptr;           // m_lengthSpin：读取长度。
        QCheckBox* m_readOnlyCheck = nullptr;       // m_readOnlyCheck：只读保护开关。
        QCheckBox* m_requireAlignedCheck = nullptr; // m_requireAlignedCheck：写入扇区对齐保护。
        QLabel* m_statusLabel = nullptr;            // m_statusLabel：页面状态摘要。

        DiskMapWidget* m_diskMapWidget = nullptr;   // m_diskMapWidget：横向柱形分区图。
        QSplitter* m_mainSplitter = nullptr;        // m_mainSplitter：左侧布局和右侧日志详情分割器。
        QTableWidget* m_partitionTable = nullptr;   // m_partitionTable：分区列表。
        ks::ui::HexView* m_hexEditor = nullptr;     // m_hexEditor：扇区 HEX 查看/编辑器。
        QTabWidget* m_advancedTabs = nullptr;        // m_advancedTabs：高级分析与工具页集合。
        QTableWidget* m_structureTable = nullptr;    // m_structureTable：MBR/GPT/启动扇区解析表。
        QTableWidget* m_volumeTable = nullptr;       // m_volumeTable：卷与盘符映射表。
        QTableWidget* m_healthTable = nullptr;       // m_healthTable：设备能力/健康表。
        QTableWidget* m_searchResultTable = nullptr; // m_searchResultTable：扇区搜索结果表。
        QPushButton* m_analyzeButton = nullptr;      // m_analyzeButton：刷新结构解析按钮。
        QPushButton* m_toolUseSelectionButton = nullptr; // m_toolUseSelectionButton：使用当前读取范围按钮。
        QPushButton* m_toolUsePartitionButton = nullptr; // m_toolUsePartitionButton：使用当前分区范围按钮。
        QPushButton* m_toolBrowseOpenButton = nullptr; // m_toolBrowseOpenButton：选择输入文件按钮。
        QPushButton* m_toolBrowseSaveButton = nullptr; // m_toolBrowseSaveButton：选择输出文件按钮。
        QPushButton* m_searchButton = nullptr;       // m_searchButton：范围搜索按钮。
        QPushButton* m_hashButton = nullptr;         // m_hashButton：范围哈希按钮。
        QPushButton* m_exportButton = nullptr;       // m_exportButton：镜像导出按钮。
        QPushButton* m_importButton = nullptr;       // m_importButton：镜像导入按钮。
        QPushButton* m_compareButton = nullptr;      // m_compareButton：文件对比按钮。
        QPushButton* m_scanButton = nullptr;         // m_scanButton：读扫按钮。
        QLineEdit* m_toolOffsetEdit = nullptr;       // m_toolOffsetEdit：高级工具起始偏移。
        QLineEdit* m_toolLengthEdit = nullptr;       // m_toolLengthEdit：高级工具长度。
        QLineEdit* m_searchPatternEdit = nullptr;    // m_searchPatternEdit：搜索模式输入。
        QLineEdit* m_toolFileEdit = nullptr;         // m_toolFileEdit：镜像/对比文件路径。
        QComboBox* m_searchModeCombo = nullptr;      // m_searchModeCombo：搜索模式。
        QComboBox* m_hashAlgorithmCombo = nullptr;   // m_hashAlgorithmCombo：哈希算法。
        QSpinBox* m_maxResultSpin = nullptr;         // m_maxResultSpin：最大搜索/差异结果数。
        QSpinBox* m_scanBlockSpin = nullptr;         // m_scanBlockSpin：读扫块大小。
        QLabel* m_diskSummaryLabel = nullptr;       // m_diskSummaryLabel：磁盘摘要文本。
        QLabel* m_partitionDetailLabel = nullptr;   // m_partitionDetailLabel：当前分区详情。
        CodeEditorWidget* m_logEdit = nullptr;        // m_logEdit：操作日志。

        std::vector<DiskDeviceInfo> m_disks;        // m_disks：当前磁盘枚举缓存。
        DiskStructureReport m_structureReport;      // m_structureReport：高级结构/卷/健康报告。
        QByteArray m_loadedBytes;                   // m_loadedBytes：最近读取的原始缓冲。
        std::optional<DiskCapturedRange> m_capturedRange; // m_capturedRange：唯一可用于写回的冻结来源。
        std::uint64_t m_captureGeneration = 0;      // m_captureGeneration：来源或读取变化即递增。
        std::uint64_t m_readGeneration = 0;         // m_readGeneration：只有所属异步读可以结束 busy 状态。
        std::uint64_t m_loadedBaseOffset = 0;       // m_loadedBaseOffset：HEX 缓冲对应磁盘偏移。
        int m_selectedPartitionIndex = -1;          // m_selectedPartitionIndex：当前分区索引。
        bool m_busy = false;                        // m_busy：后台任务互斥标志。
        bool m_dirty = false;                       // m_dirty：当前 HEX 缓冲是否已修改。
    };
}
