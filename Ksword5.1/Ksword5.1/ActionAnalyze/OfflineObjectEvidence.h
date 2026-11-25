#pragma once

#include <QList>
#include <QUuid>
#include <QWidget>
#include <optional>

class QBoxLayout;
class QLabel;
class QPaintEvent;
class QPushButton;
class QResizeEvent;

namespace ks::action_analyze
{
    enum class ArchivedObjectKind { Process, Thread };

    // 只表示采样内已验证的对象引用。没有 PID/TID、创建时间或实时身份。
    struct ArchivedObjectObservation
    {
        QUuid projectId; // 归档段头项目身份。
        QUuid sampleId; // 对象引用所属采样。
        ArchivedObjectKind kind = ArchivedObjectKind::Process; // CanonicalEvent 引用的实际对象种类。
        quint64 id = 0; // 采样内的对象编号。

        bool operator==(const ArchivedObjectObservation&) const = default;
    };

    struct SegmentRow;
    class ObjectContextMenu;

    // 按正文实例引用匹配。调用方先核对范围，返回该行是否引用同种类和编号的对象。
    bool RowReferencesObject(const SegmentRow& row, const ArchivedObjectObservation& object);

    enum class EvidenceGraphSource { Archive, Live }; // 决定事件节点和空态的来源说明。

    // 事件节点携带冻结的范围及已知编号，缺失的编号由调用方保留为空。
    struct EvidenceGraphEvent
    {
        QUuid projectId; // 事件归属的实际项目。
        QUuid sampleId; // 事件归属的实际采样。
        std::optional<quint64> eventOrdinal; // 事件规范序号，零有效。
        std::optional<quint64> recordSequence; // 归档段内记录序号，零有效。

        bool operator==(const EvidenceGraphEvent&) const = default;
    };

    // 显示当前事件的直接证据引用。采集或读盘由调用方拥有。
    struct EvidenceGraphSnapshot
    {
        EvidenceGraphSource source = EvidenceGraphSource::Archive; // 当前事件的实际来源。
        std::optional<EvidenceGraphEvent> event; // 空值清除节点，显示对应来源的空态。
        std::optional<quint64> actorProcessId; // 规范事件的执行方引用。
        std::optional<quint64> targetProcessId; // 规范事件的目标方引用。
        std::optional<quint64> observedThreadId; // 规范事件的观测线程引用。
        std::optional<quint64> associatedProcessId; // 类型化网络证据给出的关联进程引用。

        bool operator==(const EvidenceGraphSnapshot&) const = default;
    };

    // 总览底部证据图。对象节点是可独立聚焦及读取的原生按钮。
    class OfflineObjectEvidence final : public QWidget
    {
    public:
        // owner 同时持有图和 menu。菜单提供当前来源的对象能力回调。
        OfflineObjectEvidence(QWidget* owner, ObjectContextMenu* menu);

        // 在 GUI 线程提交已核验且仍属当前请求代次的事件。按完整对象身份保留焦点。
        void setEvidence(const EvidenceGraphSnapshot& snapshot);

    protected:
        // 子按钮的鼠标和菜单键事件共用同一个冻结对象；方向键只切焦点。
        bool eventFilter(QObject* watched, QEvent* event) override;
        void paintEvent(QPaintEvent* event) override;
        void resizeEvent(QResizeEvent* event) override;
        void changeEvent(QEvent* event) override;

    private:
        struct Node
        {
            ArchivedObjectObservation object; // 节点的实际采样、种类和编号。
            unsigned roles = 0; // 同一对象可在当前事件承担多个有证据的角色。
            QPushButton* button = nullptr; // 由证据图持有并保留对象身份。
        };

        // 根据当前宽度调整节点方向，并更新可见文字和无障碍名称。
        void layoutNodes();
        void updateText();
        // 从当前节点打开正式对象菜单，使用给定的全局锚点。
        bool showObjectMenu(const QPoint& globalPosition, const ArchivedObjectObservation& object);

        EvidenceGraphSnapshot m_snapshot; // 最后提交的事件和值范围。
        QList<Node> m_nodes; // 按角色顺序排列的唯一对象节点。
        ObjectContextMenu* m_menu; // 归工作台持有的共享菜单。
        QLabel* m_eventLabel = nullptr; // 图的实际事件节点。
        QLabel* m_stateLabel = nullptr; // 未选择或无可画关系时的说明。
        QBoxLayout* m_nodeLayout = nullptr; // 同一组按钮随宽度横排或纵排。
        bool m_vertical = false; // 当前窄宽布局和连线路由。
    };
}
