#pragma once

// ============================================================
// DiskMonitorStoragePanel.h
// 作用：
// 1) 为硬盘监控页提供资源监视器风格的“存储”区域；
// 2) 在后台采集固定卷容量与 IOCTL_DISK_PERFORMANCE 原始计数器；
// 3) 在 UI 线程计算活动时间、吞吐、响应时间和队列长度。
// ============================================================

#include <QHash>
#include <QString>
#include <QStringList>
#include <QWidget>
#include <QPointer>

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>

class QTableWidget;
class QTableView;
class QBoxLayout;
struct DiskMonitorStoragePerformanceState;
namespace ks::ui { class MetricAreaWindow; }

// DiskMonitorStorageSample：
// - 输入：collectSamples() 从 Windows 固定卷和磁盘性能接口读取；
// - 处理：保留累计计数器，避免后台线程访问任何 Qt 控件；
// - 输出：由 DiskMonitorStoragePanel::applySamples() 转换为每秒速率。
struct DiskMonitorStorageSample
{
    QString driveRoot;                       // driveRoot：卷根目录，例如 C:\。
    QString volumeGuidName;                  // volumeGuidName：规范化卷 GUID 路径。
    QString volumeLabel;                     // volumeLabel：卷标，系统未提供时为空。
    QString fileSystemName;                  // fileSystemName：文件系统名称，例如 NTFS。
    QString storageManagerName;              // storageManagerName：性能提供者标识。
    std::array<std::uint16_t, 8> storageManagerIdentity{}; // storageManagerIdentity：原始 8 WCHAR 身份。
    std::uint64_t availableBytes = 0U;       // availableBytes：当前用户可用空间。
    std::uint64_t totalBytes = 0U;           // totalBytes：卷总容量。
    std::uint64_t sampleTickMs = 0U;         // sampleTickMs：IOCTL 完成附近的单调时间。
    std::uint64_t bytesRead = 0U;            // bytesRead：磁盘累计读取字节。
    std::uint64_t bytesWritten = 0U;         // bytesWritten：磁盘累计写入字节。
    std::uint32_t readCount = 0U;            // readCount：磁盘累计读取次数。
    std::uint32_t writeCount = 0U;           // writeCount：磁盘累计写入次数。
    std::uint64_t readTime100ns = 0U;        // readTime100ns：累计读取耗时，单位 100ns。
    std::uint64_t writeTime100ns = 0U;       // writeTime100ns：累计写入耗时，单位 100ns。
    std::uint64_t idleTime100ns = 0U;        // idleTime100ns：累计空闲时间，单位 100ns。
    std::uint64_t queryTime100ns = 0U;       // queryTime100ns：IOCTL 返回的系统查询时间戳。
    std::uint32_t volumeSerialNumber = 0U;   // volumeSerialNumber：卷序列号，辅助识别换盘。
    std::uint32_t storageDeviceNumber = 0U;  // storageDeviceNumber：性能提供者设备编号。
    std::uint32_t queueDepth = 0U;           // queueDepth：采样瞬间磁盘队列深度。
    std::uint32_t performanceError = 0U;     // performanceError：本轮性能查询错误码。
    bool capacityAvailable = false;          // capacityAvailable：容量查询是否成功。
    bool volumeSerialAvailable = false;      // volumeSerialAvailable：卷序列号查询是否成功。
    bool performanceAvailable = false;       // performanceAvailable：磁盘性能计数器是否可用。
    bool baselinePending = false;            // baselinePending：本轮仅建立了新身份基线。
};

// DiskMonitorStorageBatch：
// - 采样结果与枚举完整性必须一起提交到 UI；
// - 只有 enumerationSucceeded=true 且 fixedVolumeCount=0 才表示确实无固定卷。
struct DiskMonitorStorageBatch
{
    std::vector<DiskMonitorStorageSample> sampleList;
    QStringList invalidatedBaselineKeys;
    std::uint32_t enumerationError = 0U;
    int fixedVolumeCount = 0;
    int performanceAvailableCount = 0;
    int baselinePendingCount = 0;
    int failedPerformanceCount = 0;
    bool enumerationSucceeded = false;
};

// Independent value/resource owner. The caller serializes collect and retire;
// DiskMonitorPage joins its sampling thread before retiring leases.
class DiskMonitorStorageSamplingBackend final
{
public:
    DiskMonitorStorageSamplingBackend();
    ~DiskMonitorStorageSamplingBackend();
    DiskMonitorStorageBatch collectSamples(const std::atomic_bool* stopRequested = nullptr);
    void retirePerformanceCountersAsync(const QString& reason);

private:
    std::unique_ptr<DiskMonitorStoragePerformanceState> m_performanceState;
};

// DiskMonitorStoragePanel：
// - 构造后显示固定卷存储表；
// - samplingBackend() 仅在 GUI 线程取共享采集资源，后台不借用 QWidget；
// - applySamples() 只能在 UI 线程调用，并维护跨轮计数器基线。
class DiskMonitorStoragePanel final : public QWidget
{
public:
    // 构造函数：
    // - parent：Qt 父控件；
    // - 返回：创建只读存储表，不启动独立线程或定时器。
    explicit DiskMonitorStoragePanel(QWidget* parent = nullptr);
    ~DiskMonitorStoragePanel() override;

    // 仅在 GUI 线程取拥有型采集资源；worker 使用 backend，不借用面板。
    std::shared_ptr<DiskMonitorStorageSamplingBackend> samplingBackend() const;

    // retirePerformanceCountersAsync：
    // - 处理：把 active lease 移交给进程期唯一的后台退役协调器；
    // - 不在 GUI 线程执行 IOCTL/OFF，可重复执行。
    void retirePerformanceCountersAsync(const QString& reason);

    // applySamples：
    // - 输入：后台线程得到的原始样本；
    // - 处理：用上一轮基线计算速率、活动时间和响应时间，再刷新表格；
    // - 返回：无，样本为空时显示明确占位行。
    void applySamples(DiskMonitorStorageBatch sampleBatch);

    // summaryText：
    // - 输入：无；
    // - 返回：最近一轮最高活动时间、总吞吐和卷数量摘要。
    QString summaryText() const;

protected:
    void changeEvent(QEvent* event) override;

private:
    // StorageBaseline：
    // - 作用：保存单卷上一轮累计值；
    // - key：卷 GUID + 卷序列号 + StorageManagerName + StorageDeviceNumber。
    struct StorageBaseline
    {
        std::uint64_t sampleTickMs = 0U;     // sampleTickMs：IOCTL 完成附近的单调采样时间。
        std::uint64_t bytesRead = 0U;        // bytesRead：上一轮累计读取字节。
        std::uint64_t bytesWritten = 0U;     // bytesWritten：上一轮累计写入字节。
        std::uint32_t readCount = 0U;        // readCount：上一轮累计读取次数。
        std::uint32_t writeCount = 0U;       // writeCount：上一轮累计写入次数。
        std::uint64_t readTime100ns = 0U;    // readTime100ns：上一轮累计读取耗时。
        std::uint64_t writeTime100ns = 0U;   // writeTime100ns：上一轮累计写入耗时。
        std::uint64_t idleTime100ns = 0U;    // idleTime100ns：上一轮累计空闲时间。
        std::uint64_t queryTime100ns = 0U;   // queryTime100ns：上一轮系统查询时间戳。
        bool performanceAvailable = false;   // performanceAvailable：上一轮性能值是否有效。
    };

    // formatBytes：
    // - 输入：字节数；
    // - 返回：自动选择 B/KB/MB/GB/TB 的可读容量。
    static QString formatBytes(double byteCount);

    // formatRate：
    // - 输入：每秒字节数；
    // - 返回：带 /s 后缀的可读吞吐。
    static QString formatRate(double bytesPerSecond);
    void openAreaWindow();
    void refreshAreaWindow();

    struct AreaRow
    {
        QString key, drive, label;
        double readRate = 0, writeRate = 0;
        bool known = false;
    };
    std::vector<AreaRow> m_areaRows;
    QPointer<ks::ui::MetricAreaWindow> m_areaWindow;
    int m_areaMode = 2;

    QTableWidget* m_table = nullptr;         // m_table：固定卷存储状态表。
    std::shared_ptr<DiskMonitorStorageSamplingBackend> m_samplingBackend;
    QHash<QString, StorageBaseline> m_baselineByIdentity; // m_baselineByIdentity：稳定卷身份到历史基线。
    QString m_summaryText;                   // m_summaryText：最近一轮资源监视器式摘要。
};

// Disk-monitor business column groups, composed with the shared segmented control.
// Header customization clears A/B; showing all columns enables full-field export.
namespace disk_monitor_ui
{
    void InstallColumnPresets(QBoxLayout* toolbar, QTableView* table,
        std::vector<int> overview, std::vector<int> diagnostics,
        const QString& overviewTip, const QString& diagnosticsTip, int initialPreset = 0);
}
