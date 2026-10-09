#pragma once

// ============================================================
// MemoryWorkbenchView.Internal.h
// 作用：
// - MemoryWorkbenchView 的私有卫星头，只供 MemoryWorkbenchView.cpp /.Ui.cpp /
//   .Session.cpp /.Nav.cpp 四个实现文件内部共享几个纯函数帮助器，不是公开接口
//   的一部分，外部文件不应 #include 它——唯一例外是 WorkbenchBookIntake.cpp：它必须
//   生成与本视图逐字相同的地址簿目标键，所以直接复用 BuildAddressBookTargetKey，
//   而不是再抄一份格式串（仿 WorkbenchWriteController.Internal.h
//   "detail:: 自由函数"的写法，只是这里的函数都不需要访问类的私有成员，纯粹按
//   值/引用计算，因此放在命名空间作用域而不是类的私有静态方法）。
// - 三个函数都不做任何 I/O、不碰任何 Qt 控件状态，可以被夹具直接单独调用测试。
// ============================================================

#include "../../../../shared/evidence/memory_workbench/MemoryTargetSession.h"

#include <QString>

#include <cstdint>
#include <string>

namespace ks::ui::detail
{
    // IsFollowSubPage：统一判断需要跟随 HEX 地址的正式子页；导航、恢复和数据刷新共用。
    // 传入正式堆栈页号，返回是否为反汇编、文本、比较或 C 伪代码页。
    inline bool IsFollowSubPage(const int page)
    {
        return page >= 1 && page <= 4;
    }

    // BuildSessionIdentityKey：overlay/基线喂入器/撤销协调器共用的"会话身份串"。
    // 固定按 base=0、len=0 求值（设计文档 §1："overlay identity=
    // IdentityKey(session,0,0)"——基线窗口本身会随视口跟随移动，身份串不应该
    // 随窗口的 base/len 变化，否则每次窗口移动都会被误判成"换了身份"而清补丁）。
    std::string BuildSessionIdentityKey(const ksword::memwb::MemoryTargetSession& session);

    // BuildAddressBookTargetKey：地址簿"按目标分组"用的键（targetKey）。只随
    // "目标身份"变化：进程范围用 pid+创建时间，内核/物理范围各自固定一个常量
    // 字符串。不随通道变化——同一个目标切换 R3/R0/HVM/DDMA 不应该让地址簿把它
    // 当成两个不同的目标来分组（装配接口文档 §8.2 G4 的去重规则同样要求"同
    // targetKey"的判断稳定，不能随通道抖动）。
    std::string BuildAddressBookTargetKey(const ksword::memwb::MemoryTargetSession& session);

    // BuildTargetDescriptionText：会话条目标 chip 与确认框正文共用的"目标"人话
    // 描述（装配接口文档 §6 第一行 B2：两处共用同一份数据源，但不共用控件状态，
    // 因此各自独立调用本函数拼一次，而不是互相读对方控件的 text()）。
    // 传入参数与 WorkbenchSessionBar::setTargetInfo 完全一致，额外多一个 scope
    // 用于判断内核/物理范围要不要显示"未附加"红字（B3：那两个范围不存在"选目标"
    // 这一步）。
    QString BuildTargetDescriptionText(
        bool attached,
        const QString& processName,
        quint32 pid,
        quint32 addressBits,
        bool canReadWrite,
        ksword::memwb::Scope scope);
}
