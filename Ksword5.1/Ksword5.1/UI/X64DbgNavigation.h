#pragma once
#include <QtGlobal>

class QMenu;
class QWidget;

namespace ks::ui::x64dbg_navigation
{
    enum class View { Disassembly, Dump };
    struct Target
    {
        quint32 pid = 0; // 原始进程记录或捕获字节所属的 PID。
        quint64 processCreateTime100ns = 0; // 原目标的创建时间；零表示缺少身份见证。
        quint64 address = 0; // 零表示显示调试器当前指令，否则为原目标中的地址。
        View view = View::Disassembly; // 请求定位的调试器视图。
    };

    enum class IdentityStatus { Missing, Unavailable, Changed, Matching };

    // HasCapturedIdentity：只检查调用方保留的原身份，不按当前 PID 补授身份。
    // 输入 pid/createTime100ns：原记录的身份；返回是否拥有完整的导航授权上下文。
    inline bool HasCapturedIdentity(quint32 pid, quint64 createTime100ns) noexcept
    {
        return pid != 0 && createTime100ns != 0;
    }

    // CheckCapturedIdentity：将已保留的身份与当前观察值比较；缺原身份时不调用观察器。
    // 输入 target：不可修改的原目标；observe(pid) 返回当前创建时间或零（不可访问）。
    // 返回 Missing/Unavailable/Changed/Matching；观察结果永远不能替代原创建时间。
    template<class ObserveCreationTime>
    IdentityStatus CheckCapturedIdentity(const Target& target, ObserveCreationTime&& observe) noexcept
    {
        if (!HasCapturedIdentity(target.pid, target.processCreateTime100ns))
        {
            return IdentityStatus::Missing;
        }
        const quint64 currentCreation = observe(target.pid); // 当前观测仅用于复核原身份。
        if (currentCreation == 0)
        {
            return IdentityStatus::Unavailable;
        }
        return currentCreation == target.processCreateTime100ns
            ? IdentityStatus::Matching : IdentityStatus::Changed;
    }

    // ProcessCreateTime100ns：即时查询当前活进程，可在捕获阶段明确建立身份或用于复核。
    // 输入 pid：要查询的 PID；返回创建时间，进程退出或权限不足时返回零。
    quint64 ProcessCreateTime100ns(quint32 pid) noexcept;
    // Open/AddAction：只接受调用方冻结的原目标身份。零身份不能在菜单阶段重新取得。
    // 输入 owner：提示框/动作宿主；target：原进程身份和地址；不改变调试执行状态。
    void Open(QWidget* owner, const Target& target);
    void AddAction(QMenu* menu, QWidget* owner, const Target& target);
    void Configure(QWidget* owner);
}
