// 独立进程内存调试页的模式配置：复用工作台服务，不建立 Windows 调试会话。
#include "MemoryWorkbenchView.h"
#include "WorkbenchTarget.h"
#include "WorkbenchSessionBar.h"
#include "Int3PatchPanel.h"

#include <QPointer>
#include <QStackedWidget>

namespace ks::ui
{
    bool MemoryWorkbenchView::setMemoryDebugMode(const bool enabled)
    {
        if (memoryDebugMode_ == enabled)
        {
            return true;
        }
        if (!target_ || (enabled && embedded_))
        {
            return false;
        }
        const QPointer<MemoryWorkbenchView> self(this);
        if (enabled)
        {
            // 先用正常身份守卫切换，再生效显示模式；拒绝时原工作台完全不变。
            IdentityRequest request;
            request.scope = ksword::memwb::Scope::ProcessVirtual;
            request.channel = ksword::memwb::Channel::UserMode;
            const auto current = target_->session();
            if (current.pid != 0U)
            {
                request.pinPid = current.pid;
                request.expectCreateTime = current.processCreateTime100ns;
            }
            if (!target_->requestIdentity(request, LeaveReason::ScopeChange) || !self)
            {
                return false;
            }
        }
        memoryDebugMode_ = enabled;
        target_->setPolicy(WorkbenchTarget::Policy{
            /*lockToDock=*/embedded_,
            /*allowKernelPhysical=*/!embedded_ && !enabled,
            /*allowFollowDock=*/!enabled});
        sessionBar_->setMemoryDebugMode(enabled);
        // int3 在本页不是调试断点；隐藏入口且禁用，退出也不处理其它视图的补丁。
        int3Panel_->setEnabled(!enabled);
        int3Panel_->setVisible(!enabled);
        if (enabled)
        {
            subTabStack_->setCurrentIndex(1);
        }
        refreshTargetDisplays();
        refreshChannelGateDisplay();
        return true;
    }

    bool MemoryWorkbenchView::isMemoryDebugMode() const noexcept
    {
        return memoryDebugMode_;
    }

    bool MemoryWorkbenchView::clearMemoryDebugTarget()
    {
        return memoryDebugMode_ && target_ && target_->clearMemoryDebugTarget();
    }

}
