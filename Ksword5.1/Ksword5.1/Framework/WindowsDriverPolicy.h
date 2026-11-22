#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

namespace ks::driver_policy
{
    // UpdateState：已核实服务分支的累计更新基线；未知分支绝不按版本大小猜测。
    enum class UpdateState { Unknown, BeforeJuly2026, July2026OrLater };
    // PolicyState：固定强制策略的实际读回；审核策略不算强制策略。
    enum class PolicyState { Unknown, Absent, Inactive, Active };

    // Snapshot：只读预检值；所有不确定字段默认拒绝自动处理。
    struct Snapshot
    {
        unsigned long build = 0;              // build：RtlGetVersion 当前运行的 build。
        unsigned long revision = 0;           // revision：同一 build 的注册表 UBR。
        bool server = false;                  // server：区分客户端和 Server 的不同更新序列。
        bool elevated = false;                // elevated：当前进程是否已提升。
        bool rebootClear = false;             // rebootClear：已确认 CBS/WU 均无待重启标记。
        bool toolAvailable = false;           // toolAvailable：系统目录存在 CiTool。
        UpdateState update = UpdateState::Unknown; // update：累计更新基线判定。
        PolicyState policy = PolicyState::Unknown; // policy：固定 GUID 的生效及授权读回。
        QString detail;                       // detail：CiTool 原始回执或诊断，不当作结论。
    };

    // RemovalResult：仅证明命令是否被接受，不能将其描述为当前会话已经解除阻止。
    struct RemovalResult
    {
        bool accepted = false; // accepted：重新预检通过且 CiTool 正常返回 0。
        QString detail;        // detail：最终预检及命令回执。
    };

    // EnforcePolicyId/RemovalArguments：固定目标，调用者不能传任意策略或命令。
    QString EnforcePolicyId();
    QStringList RemovalArguments();
    // ClassifyUpdate：输入精确 build/UBR 和产品类型，返回可审计的更新基线状态。
    UpdateState ClassifyUpdate(unsigned long build, unsigned long revision, bool server);
    // ParsePolicyState：输入 CiTool JSON，只认固定 GUID 的 IsEnforced && IsAuthorized。
    PolicyState ParsePolicyState(const QByteArray& json);
    // CanRemove：纯函数，只有所有先决条件均已确认时允许提供自动处理。
    bool CanRemove(const Snapshot& snapshot);
    // QuerySnapshot：在线程池调用；只读系统版本、提升状态、重启标记和 CiTool 列表。
    Snapshot QuerySnapshot();
    // RemovePolicy：用户明确确认后在线程池调用；执行前重新检查，不删除文件或修改 BCD。
    RemovalResult RemovePolicy();
}
