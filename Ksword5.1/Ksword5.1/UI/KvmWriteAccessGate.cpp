#include "KvmWriteAccessGate.h"

#include "KvmControl.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Internationalization/LanguageManager.h"

bool ks::ui::requestKvmWriteAccess(QWidget* const parent)
{
    // 已经开着就什么都不问：确认框问的是「要不要解锁这一整类能力」，能力已经
    // 解锁时再弹一次只会让用户学会闭眼点确认。
    if (ksword::kvm::isWriteAccessEnabled())
    {
        return true;
    }

    // 打开写权限等于解锁一整类可改写系统状态的能力，必须显式确认一次。
    //
    // 下面这四段与标题栏 KVM 菜单里的写权限开关逐字相同，这不是巧合而是要求：
    // suppressionKey 决定了「不再提示」的持久化条目，两处必须落在同一个 key 上，
    // 否则从对话框里勾过的用户换个入口还会再被拦一次。
    const bool confirmed = ks::ui::confirmDestructiveAction(
        parent,
        QStringLiteral("KvmWriteAccess"),
        ks::i18n::sourceText(QStringLiteral("开启 KSwordVM 写权限")),
        ks::i18n::sourceText(QStringLiteral("本机物理内存与 EPT 映射")),
        ks::i18n::sourceText(QStringLiteral("开启后 KVM 的 R-1 改写能力（EPT 强制权限、隐蔽 Hook、内存隐藏、物理内存写入）将可用。这些操作绕过内核层保护，误用会直接损坏运行中的系统。")));
    ksword::kvm::setWriteAccessEnabled(confirmed);
    return confirmed;
}
