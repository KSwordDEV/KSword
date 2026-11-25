#pragma once

#include "OfflineSegmentReader.h"

#include <QSet>
#include <QWidget>
#include <memory>

class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class QTableView;

namespace ks::ui
{
    class AsyncOperation;
    class ResultTableHost;
    class StructuredFieldView;
}

namespace ks::action_analyze
{
    class SegmentTableModel;
    class SegmentWaterfall;

    // 行为追踪总览独立持有归档证据，项目页提供可选的身份对照。
    class OfflineSegmentOverview final : public QWidget
    {
    public:
        // 在 parent 下创建离线总览，不自动打开文件。
        explicit OfflineSegmentOverview(QWidget* parent);
        ~OfflineSegmentOverview() override;

        // 更新用于对照的目录身份和选中采样；不切换归档或选择。
        void setProjectContext(const QString& projectId, const QString& sampleId, const QString& sampleStatus);

    protected:
        // 接收语言变化，更新固定文案及当前数据显示。
        void changeEvent(QEvent* event) override;

    private:
        // 打开文件对话框或将指定文件作为下一次后台读取请求。
        void chooseSegment();
        void openSegment(const QString& path);
        // 取消有效读取代次，继续展示上次成功提交的结果。
        void cancelRead();
        // 接收后台值，保留失败前的已发布结果。
        void publish(const SegmentSnapshot& result);
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
        QString m_projectId; // 已打开项目的 UUID。
        QString m_sampleId; // 当前目录所选采样的 UUID。
        QString m_sampleStatus; // 无段时显示的项目采样状态。
        QString m_lastPath; // 最新读取请求路径。
        std::shared_ptr<const SegmentSnapshot> m_snapshot; // 最后发布的段。
        SegmentEnd m_latestEnd = SegmentEnd::Unavailable; // 最新读取结尾；可与保留结果不同。
        quint64 m_latestOffset = 0; // 最新问题发生的位置。
        bool m_latestPublished = false; // 最新读取是否替换了视图。
        bool m_reading = false; // 有有效的读取请求在途。
        bool m_updatingSelection = false; // 表格和瀑布相互更新时防止回环。
        bool m_invalidRange = false; // 当前提交草稿是否有错误。
        std::optional<quint64> m_lower; // 已应用包含下界。
        std::optional<quint64> m_upper; // 已应用不含上界。
        std::optional<quint64> m_sequence; // 用户选择，过滤时可以暂不可见。
        QSet<quint16> m_filterCategories; // 当前选中的实际归档类别。
    };
}
