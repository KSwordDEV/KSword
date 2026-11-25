#pragma once

#include "ObjectDiagnosticExport.h"

#include <QObject>
#include <QPoint>
#include <QPointer>

class QContextMenuEvent;
class QMenu;
class QWidget;

namespace ks::ui
{
    class AsyncOperation;
}

namespace ks::action_analyze
{
    enum class ObjectMenuKind { Process, Thread };

    // 已显示的采样内对象，关系未解析时也可供查看、筛选和复制。
    struct ObjectMenuRef
    {
        ObjectSampleRef sample; // 段头或已核验项目提供的实际采样身份。
        ObjectMenuKind kind = ObjectMenuKind::Process; // 归档字段声明的对象类别。
        quint64 objectId = 0; // 非零采样内编号。

        // 校验可见引用具备稳定范围。
        bool isValid() const;
        // 判断强身份是否确指此引用，供导出能力复核。
        bool matches(const ObjectSelection& subject) const;
    };

    // 按当前已发布证据与界面状态给出资格，关闭时可携带用户可读原因。
    struct ObjectActionCapability
    {
        bool available = false; // 工作台已经具有对应的真实处理路径。
        QString reason; // 不可用时展示的详情。
    };

    enum class DiagnosticAvailability
    {
        Unresolved, // 归档未核验或无解析能力，不能判断有无证据。
        Absent,     // 已查询完成，本对象没有对应证据。
        Failed,     // 查询失败，可返回真实原因。
        Ready       // 获得已核验证据描述，仍须复核身份和文件完整性。
    };

    struct ObjectMenuCapabilities
    {
        ObjectActionCapability viewEvidence; // 可否通过共享详情打开此对象。
        ObjectActionCapability filterByObject; // 当前显示投影可否应用此实例筛选。
        DiagnosticAvailability diagnostic = DiagnosticAvailability::Unresolved; // 具体的归档查询结果。
        QString diagnosticReason; // 已知的查询失败或不可用原因。
        std::optional<ObjectSelection> verifiedSubject; // 归档身份消费者已核验的独立强对象。
        std::optional<ArchivedDiagnostic> archive; // 该对象选定的归档证据。
    };

    struct ObjectMenuCallbacks
    {
        // 查询必须仅查内存状态，不在 GUI 线程读盘。接收本次捕获的不可变选择。
        std::function<ObjectMenuCapabilities(const ObjectMenuRef&)> capabilities;
        // 分别调用工作台已有证据与显示筛选入口，函数接收本次身份而非行号。
        std::function<void(const ObjectMenuRef&)> viewEvidence;
        std::function<void(const ObjectMenuRef&)> filterByObject;
    };

    // 节点和对象清单共用的控制器。传入工作台 owner 与实际能力回调，使用 Qt 原生鼠标与菜单键。
    class ObjectContextMenu final : public QObject
    {
    public:
        using ObjectPicker = std::function<std::optional<ObjectMenuRef>(const QPoint& localPosition)>;

        // 同一工作台持有一个实例，并提供已有详情与显示筛选能力。
        explicit ObjectContextMenu(QWidget* owner, ObjectMenuCallbacks callbacks);
        ~ObjectContextMenu() override;

        // 从焦点控件或视口转发 Qt 上下文事件。鼠标按命中值，键盘按当前对象值和本地锚点。
        // 返回是否弹出；空白区域、空焦点或未核验身份不改变当前选择。
        bool handleContextMenu(QContextMenuEvent& event, QWidget* source, const ObjectPicker& pickAt,
            std::optional<ObjectMenuRef> keyboardObject, const QPoint& keyboardAnchor);

        // 已由调用方分辨鼠标与键盘时，使用全局位置和冻结对象直接弹出。
        bool popup(const QPoint& globalPosition, ObjectMenuRef object);

    private:
        enum class Action { View, Filter, Copy, Export, Explain };

        // 用当前工作台状态查询冻结对象的操作能力，并验证实际处理回调存在。
        ObjectMenuCapabilities capabilities(const ObjectMenuRef& object) const;
        // 菜单关闭后执行该动作，使用打开菜单时的对象及可选证据描述。
        void dispatch(Action action, const ObjectMenuRef& object,
            const std::optional<ArchivedDiagnostic>& offeredArchive);
        // 确认目标路径和冻结的证据后提交异步文件事务。
        void chooseExport(const ObjectMenuRef& object, const ArchivedDiagnostic& offeredArchive);

        QWidget* m_owner; // 控制器的父窗口，拥有菜单及反馈对话框。
        ObjectMenuCallbacks m_callbacks; // 仅由 GUI 线程查询与调用。
        ks::ui::AsyncOperation* m_export; // 单个已接纳的独立导出事务。
        QPointer<QMenu> m_menu; // 当前活动菜单，可随 owner 提前销毁。
    };
}
