#include "../Framework.h"
#include "ProcessDock.h"
#include "../../../shared/usermode/ProcessConsole.h"
#include "../Internationalization/LanguageManager.h"

// executeForceConsoleAction：进程列表右键的无自定义 DLL 控制台动作。
// 输入为菜单冻结的目标快照；后台执行并通过现有逐目标日志/通知回填，无返回值。
void ProcessDock::executeForceConsoleAction(const std::vector<ProcessActionTarget>& actionTargets)
{
    // 复用现有异步动作执行器，单目标也在线程内运行，不阻塞菜单/刷新线程。
    const QString title = ks::i18n::text(
        QStringLiteral("process.menu.force_console"), QStringLiteral("强开控制台"));
    dispatchProcessActionTargetsInParallel(
        title,
        actionTargets,
        [](const ProcessActionTarget& target, std::string* detailTextOut)
        {
            // 后端在真正具有执行权限的句柄上再次核验相同创建时间。
            return ks::process::ForceProcessConsole(
                target.record.pid, target.record.creationTime100ns, detailTextOut);
        },
        false,
        true,
        true);
}
