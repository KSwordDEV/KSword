#pragma once

#include "OfflineSegmentReader.h"
#include "OfflineObjectEvidence.h"

#include <QSet>
#include <functional>
#include <QWidget>
#include <memory>

class QCheckBox;
class QDialog;
class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class QTableView;
class QTimer;

namespace ks::ui
{
    class AsyncOperation;
    class FlowLayout;
    class ResultTableHost;
    class StructuredFieldView;
    struct FieldDocument;
}

namespace ks::action_analyze
{
    class SegmentTableModel;
    class SegmentWaterfall;
    class LiveEtwCapture;
    struct LiveEtwReceipt;
    struct ToolbarOverviewCapabilities;
    struct SampleSensitiveClue;

    // 行为追踪总览独立持有归档证据，项目页提供可选的身份对照。
    class OfflineSegmentOverview final : public QWidget
    {
    public:
        // 在 parent 下创建离线总览，不自动打开文件。
        explicit OfflineSegmentOverview(QWidget* parent);
        ~OfflineSegmentOverview() override;

        // 更新下一次采样的项目清单和目录对照；不改变正在运行的采样归属。
        void setProjectContext(const ProjectSnapshot& project, const QString& sampleId, const QString& sampleStatus);
        // 显式从目录打开选中采样的首个原始段。返回是否已开始读取。
        bool openSampleArchive(const SampleRequest& sample, const SampleSensitiveClue* clue = nullptr);
        // 由工作台的新扫描入口激活参数控件，不创建采样或改动目标草稿。
        void focusScanTarget();
        // 工作台各页共用此状态回执；调用方只订阅读取，不控制原生会话。
        std::function<void(const QString&)> sessionStatusChanged;
        // 项目真实登记后通知目录按当前选择刷新；不激活项目页。
        std::function<void(const QString&, const QString&)> liveSampleRegistered;
        std::function<void()> openBreakpointPage; // 工作台负责切换到已经登记的全局断点页。
        std::function<void()> activateOverview; // 浮窗的归档动作受理后定位共用总览。

    protected:
        // 接收语言变化，更新固定文案及当前数据显示。
        void changeEvent(QEvent* event) override;
        void showEvent(QShowEvent* event) override;

    private:
        // 打开文件对话框或将指定文件作为下一次后台读取请求。
        void chooseSegment();
        bool openSegment(const QString& path, std::optional<SampleRequest> sample = std::nullopt,
            const SampleSensitiveClue* clue = nullptr);
        // 取消有效读取代次，继续展示上次成功提交的结果。
        void cancelRead();
        // 接收后台值，保留失败前的已发布结果。
        void publish(const SegmentSnapshot& result);
        // 在现有工具带加采集入口，并在同一视图应用实时快照。
        void createLiveControls(ks::ui::FlowLayout* parameters, ks::ui::FlowLayout* actions);
        // 建立可停靠的动作带。浮出时移动同一组按钮，关闭浮窗时归位。
        QWidget* createActionToolbar();
        void toggleActionToolbar();
        void restoreActionToolbar();
        void updateActionToolbarText();
        // 按动作自然宽度、当前屏幕工作区计算浮窗尺寸下限。不改内嵌栏布局。
        void fitFloatingActionToolbar();
        void startLive();
        void stopLive();
        void refreshLive(bool final = false);
        void finishLive(const LiveEtwReceipt& result);
        void updateLiveControls();
        void followLive();
        // 打开最近一次监控已核验的归档前缀，并同步这个图标的可用性。
        void openCapturedArchive();
        void updateCapturedArchiveAction();
        // 将当前会话和已显示结果投影成工具条资格，供按钮与执行入口共用。
        ToolbarOverviewCapabilities toolbarCapabilities() const;
        // 时间线或表格操作冻结当前窗口；后台采集继续。
        void pauseLiveView();
        bool liveViewInteracting() const;
        void setActiveSnapshot(const SegmentSnapshot& result);
        // 同一输入路径和段身份允许沿用类别、时间和选择。
        void fillCategories(bool preserve);
        // 从草稿读取并提交半开范围，失败保留上次范围。
        void applyTimeRange();
        // 清除当前整组显示筛选，不移动记录选择。
        void clearFilters();
        // 同步有效过滤条件、表格、瀑布和稳定选中项。
        void applyFilters();
        // 以段内序号选中记录，共享表格和瀑布的选择锚。
        void selectSequence(quint64 sequence, bool scrollTable);
        // 刷新状态和共享详情文档，不执行文件 I/O。
        void updateText();
        void updateDetails();
        // 建立底部键盘可访问的引用区及共享菜单入口。
        QWidget* createObjectEvidence(QWidget* parent);
        // 同步证据清单和选中的对象身份；nullptr 清空当前记录引用。
        void updateObjectEvidence(const SegmentRow* row);
        // 校验对象归属并报告当前应用的对象筛选。
        bool matchesSample(const ArchivedObjectObservation& object) const;
        QString objectFilterSummary() const;
        // 将已验证的网络投影加到当前记录的共享详情文档。
        static void appendNetworkEvidence(ks::ui::FieldDocument& document, const SegmentNetworkEvidence& evidence);
        // 用实际网络端点和协议扩展关键字匹配。
        static bool matchesNetworkKeyword(const SegmentNetworkEvidence& evidence, const QString& keyword);

        ks::ui::AsyncOperation* m_read = nullptr; // 归档独立工作槽。
        ks::ui::ResultTableHost* m_host = nullptr; // 紧凑表格和提交门禁。
        ks::ui::StructuredFieldView* m_details = nullptr; // 单一记录详情文档。
        SegmentTableModel* m_model = nullptr; // 事件表的有界值模型。
        SegmentWaterfall* m_waterfall = nullptr; // 来源为已显示记录的被动时间视图。
        QTableView* m_table = nullptr; // 事件列表的真实焦点控件。
        QListWidget* m_categories = nullptr; // 仅显示归档中出现的类别。
        QLabel* m_categoryLabel = nullptr; // 类别列表的可访问标签。
        QLabel* m_timeLabel = nullptr; // 接收 QPC 的时钟域说明。
        QLabel* m_startLabel = nullptr; // 含起始端点的输入标签。
        QLabel* m_endLabel = nullptr; // 不含结束端点的输入标签。
        QWidget* m_timeBand = nullptr; // 可展开的附加时间筛选区。
        QLineEdit* m_keyword = nullptr; // 表中编号、时间和事件的关键字。
        QCheckBox* m_apiSource = nullptr; // 独立的 API 显示条件，仅可在来源核验后开放。
        QCheckBox* m_etwSource = nullptr; // 独立的 ETW 显示条件，仅可在来源核验后开放。
        QPushButton* m_more = nullptr; // 展开或收起附加时间筛选。
        QPushButton* m_clear = nullptr; // 清除所有已应用的显示筛选。
        QLineEdit* m_start = nullptr; // 时间起点草稿。
        QLineEdit* m_end = nullptr; // 时间终点草稿。
        QPushButton* m_apply = nullptr; // 提交时间草稿。
        QPushButton* m_reset = nullptr; // 清空时间过滤。
        QPushButton* m_open = nullptr; // 打开独立 Stored 文件。
        QPushButton* m_retry = nullptr; // 重读上一次请求的文件。
        QPushButton* m_cancel = nullptr; // 取消归档读取并保留当前显示。
        QLabel* m_identity = nullptr; // 已发布文件和段身份。
        QLabel* m_context = nullptr; // 归档与项目选中身份的实际关系。
        QLabel* m_status = nullptr; // 最新读取回执及可读范围。
        QLabel* m_filterStatus = nullptr; // 结果数量或时间草稿错误。
        QLabel* m_graphStatus = nullptr; // 关系和来源解析能力。
        QLabel* m_objectStatus = nullptr; // 通过菜单显式查看的对象证据。
        OfflineObjectEvidence* m_objects = nullptr; // 当前证据的可导航对象引用。
        QString m_projectManifest; // 下次开始时冻结的项目清单路径。
        QString m_projectRevision; // 已打开项目的配置修订，启动时重新核对。
        QString m_projectId; // 已打开项目的 UUID。
        QString m_sampleId; // 当前目录所选采样的 UUID。
        QString m_sampleStatus; // 无段时显示的项目采样状态。
        QString m_lastPath; // 最新读取请求路径。
        std::optional<SampleRequest> m_lastSampleRequest; // 重试沿用已冻结的目录身份。
        std::shared_ptr<const SegmentSnapshot> m_snapshot; // 最后发布的段。
        SegmentEnd m_latestEnd = SegmentEnd::Unavailable; // 最新读取结尾；可与保留结果不同。
        quint64 m_latestOffset = 0; // 最新问题发生的位置。
        quint64 m_latestVerifiedOrdinal = 0; // 最新请求核验通过的最后一段，独立于仍显示的旧结果。
        quint64 m_latestFailedOrdinal = 0; // 最新请求遇到的第一个坏段。
        bool m_latestPublished = false; // 最新读取是否替换了视图。
        bool m_reading = false; // 有有效的读取请求在途。
        bool m_updatingSelection = false; // 表格和瀑布相互更新时防止回环。
        bool m_invalidRange = false; // 当前提交草稿是否有错误。
        std::optional<quint64> m_lower; // 已应用包含下界。
        std::optional<quint64> m_upper; // 已应用不含上界。
        std::optional<quint64> m_sequence; // 用户选择，过滤时可以暂不可见。
        std::optional<SegmentRow> m_selectedLiveRow; // 同一采样内独立保留的选中证据。
        std::optional<ArchivedObjectObservation> m_objectFilter; // 生效的采样内对象范围。
        std::optional<ArchivedObjectObservation> m_viewedObject; // 用户显式查看的归档引用。
        QSet<quint16> m_filterCategories; // 当前选中的实际归档类别。
        ks::ui::AsyncOperation* m_liveOperation = nullptr; // 原生会话只在后台启动和收尾。
        QTimer* m_liveTimer = nullptr; // 有新事件时发布同一总览快照。
        QLineEdit* m_pidInput = nullptr; // 本次启动的目标 PID 草稿。
        QLineEdit* m_providerInput = nullptr; // 本次启动的 ETW provider GUID 草稿。
        QPushButton* m_startLive = nullptr; // 真实采样入口。
        QPushButton* m_stopLive = nullptr; // 请求收尾或重试同一所有者的清退。
        QPushButton* m_followLive = nullptr; // 只恢复视图跟随。
        QPushButton* m_captureArchive = nullptr; // 打开原监控所写归档，与当前项目浏览选择无关。
        QPushButton* m_breakpointPage = nullptr; // 打开全局断点定义，不改变活动会话。
        QWidget* m_actionDock = nullptr; // 内嵌工具带原位，浮出时不占用页面高度。
        QWidget* m_actionStrip = nullptr; // 两种布局共用的真实按钮宿主。
        QDialog* m_actionWindow = nullptr; // 只在首次浮出时创建的原生置顶窗口。
        QPushButton* m_floatActions = nullptr; // 浮出或停靠入口，由窗口归属决定提示。
        std::shared_ptr<LiveEtwCapture> m_live; // 后台操作和实时快照共用的会话所有者。
        QString m_liveFeedback; // 最近一次实时请求的回执。
        QString m_liveManifest; // 当前采样冻结的项目清单，不随项目浏览改变。
        QString m_liveProjectId; // 当前采样的实际项目归属。
        QString m_announcedSample; // 已通知目录刷新的真实采样，避免重复触发。
        bool m_liveRegistered = false; // 同一个工作台拥有唯一原生任务和预览刷新。
        bool m_liveBusy = false; // 已提交启动或清退事务。
        bool m_liveRecovery = false; // 清退仍有未解决责任。
        bool m_liveStopping = false; // 已请求收尾，等待真实回执。
        bool m_followingLive = true; // 拖选或查看历史时暂停显示跟随。
        bool m_livePreviewEnabled = false; // 用户打开正式归档后禁止实时结果回投覆盖。
        bool m_liveHasRows = false; // 停止后仍可回到同一采样的最后窗口。
    };
}
