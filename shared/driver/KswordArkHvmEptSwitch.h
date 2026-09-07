/*
 * KswordArkHvmEptSwitch.h
 *
 * 「切 EPTP」这套分离视图后端里，算错了**不会报错**、只会安静地做错事的位运算
 * 与状态机，集中放在这里。收录标准与 KswordArkHvmControls.h 完全一致：纯输入
 * 到输出、无副作用、错了很难当场发现。
 *
 * ------------------------------------------------------------------
 * 这套机制是什么，为什么它的算术特别容易错得没有症状
 * ------------------------------------------------------------------
 *
 * 今天的分离视图是「写叶 + monitor-trap」：主值拒绝要重定向的那种访问，EPT
 * violation 里把叶改成次值，武装 MTF 让 guest 退休一条指令，再在 MTF 退出里
 * 把叶改回主值。每一次被重定向的访问要两次 VM 退出，而且叶每次都被立刻改回，
 * 所以连续 N 次同类访问是 2N 次退出。
 *
 * 这套后端改成：把「主值」与「次值」放进两套**内容不同的完整层次**，运行期只
 * 对自己 VMCS 的 EPT_POINTER 字段做一次 VMWRITE 换掉当前处理器走的那棵树，
 * 不写任何叶、不武装 MTF、不发 INVEPT。于是 2N 次退出变成 1 次，并且「运行期
 * 没有任何软件对 EPT 表的写」——一个处理器的翻转对别的处理器不可见这件事由
 * 构造保证，而不是靠把窗口压到一条指令。
 *
 * 代价是这套后端的正确性几乎全部落在**位域布局与索引编码**上，而这一类错误的
 * 共同特征是没有诊断面：
 *
 *   - 叶项里保留位没清干净、或 2MiB 叶的页帧没按 2MiB 对齐 —— 表现是 VM entry
 *     之后某一次访问触发 EPT misconfiguration（exit reason 49）。那个退出不告诉
 *     你是哪一位不对，只告诉你有一位不对。
 *   - EPTP 的页遍历级数字段存的是「级数减一」。写成 4 而不是 3，VM entry 直接
 *     失败，错误码同样只有一个数。
 *   - 层次索引与叶号差一格 —— 恢复判据作用在一个无关的页上，被保护的那一页从此
 *     毫无保护，而所有自检都是绿的。
 *   - 决策状态机错一个分支 —— 要么某一页永久停在影子层次上（没有任何报错），
 *     要么本该 fail-closed 的组合被放行成一个不前进的环，表现是**整机静默死锁**：
 *     没有蓝屏、没有事件、没有日志，每一次退出单独看都完全正常。
 *
 * 这些都不是「跑一次就知道」的错误，所以它们必须在编译机上被证明。本头文件
 * 被内核态 C 与宿主机 C++ 单测**共用同一份实现**（不是抄一遍，因此不会漂移）。
 *
 * ------------------------------------------------------------------
 * 层次编号：为什么是 1 + L 套而不是 2 套
 * ------------------------------------------------------------------
 *
 * 参考实现只有「全主值 / 全次值」两套层次，那在只有一组统一 hook 状态时是对的。
 * 本驱动允许同时安装多个视图，而 EPTP 是每处理器**一个**值——处理器同一时刻
 * 只能在一套层次里。用「全次值」那套去服务某一页的读，会顺带把其它视图页也换成
 * 次值，于是一个从没被碰过的 CLOAK 页在这段时间里对读者暴露影子。那是语义改变，
 * 不是性能改变。
 *
 * 所以编号是：索引 0 = 基座（每一叶都取主值，也就是今天的稳态），索引 k =
 * 「只有第 k-1 号叶取次值，其余全部主值」。由此白拿三条性质：
 *   - 任何时刻至多一个叶被放宽，影响面与今天的 MTF 机制逐字节相同；
 *   - 从层次 c 切到层次 f 自动把 c 那一叶收回主值，不需要额外动作；
 *   - 「有没有叶被放宽」就是「索引是不是 0」，不需要第二个布尔量去同步。
 *
 * ------------------------------------------------------------------
 * 不可表示的组合：为什么拒绝判据和状态机同等重要
 * ------------------------------------------------------------------
 *
 * 只要层次数少于 2^L，就一定存在「一条指令同时需要两个叶的次值」的组合（取指
 * 落在 HOOK 页而操作数读落在 CLOAK 页；或一个 CLOAK 代码页里的 RIP 相对数据
 * 引用指向自己）。那种组合在任何单套层次里都不成立。MTF 机制下它的结局是
 * fail-closed 退虚拟化；EPTP 切换下如果不被识别出来，它就是那个静默死锁。
 *
 * **这里必须精确说明哪一半由谁负责，因为上一版的文案在这里说错了，而说错的
 * 后果是集成者以为拒绝已经做完了。** 两半是：
 *
 *   - 单叶不可表示（一次违规同时要求同一叶的主值与次值，例如 CLOAK 页上的
 *     「读 + 取指」）：由 KswordArkHvmEptSwDecide 判定，返回
 *     REASON_UNREPRESENTABLE。这一半是纯函数可判的，因为一次违规的全部信息
 *     都在参数里。
 *   - **跨叶**不可表示（取指落在 HOOK 页、操作数读落在 CLOAK 页）：
 *     KswordArkHvmEptSwDecide **看不到**，也不可能看到——它一次只收到一次
 *     违规，而那一次违规的每一半单独看都可以被服务。表现是
 *     SWITCH k -> SWITCH j -> SWITCH k -> ... 在同一个 RIP 上无限循环，
 *     每一次退出单独看都完全正常。这一半只能由跨退出的**前进性台账**
 *     KswordArkHvmEptSwProgressAdmit（本文件下半部分）识别，而且它是
 *     KswordArkHvmEptSwPlanSwitch 的**调用前置条件**，不是可选的加固：
 *     调用方必须在每次真正写 VMCS 之前先让台账承认这次切换在前进，
 *     台账说不前进就走 fail-closed，与「翻转失败」同一条路径。
 *
 * 因此本文件里的每一条 REFUSE，以及 ProgressAdmit 的每一次拒绝，都是**必须被
 * 上层接到 fail-closed 汇流**的信号，而不是可以忽略的提示。
 *
 * ------------------------------------------------------------------
 * 依赖
 * ------------------------------------------------------------------
 *
 * 只包含同族的 KswordArkHvmControls.h（同样 header-only、同样不引用 WDK、CRT
 * 或 Windows 头）。**不再包含 <stdint.h>**：本族另外两个头（Controls 与
 * EptpSwitch）都只用 unsigned long long / unsigned long 与 static __inline，
 * 三个头必须是同一份可移植性契约，否则哪天有人把本文件加进
 * tools/hvm_unit_tests/ 那个 C TU，编译器换一档就编不过。
 *
 * 包含 Controls.h 还有第二个理由：EPT/EPTP 的位布局在本仓库里原本有三份副本
 * （hvm_internal.h 的 KSW_EPT_*、Controls.h、以及本文件）。凡是 Controls.h
 * 已经给出的常量，本文件一律**别名**过去而不是重新写一遍数值——重新写一遍就
 * 是第二个真值来源，而这正是本文件存在的理由所要消灭的东西。
 *
 * ------------------------------------------------------------------
 * 与已删除的 KswordArkHvmEptpSwitch.h 的关系（合并记录）
 * ------------------------------------------------------------------
 *
 * shared/driver/KswordArkHvmEptpSwitch.h 曾是同一个设计的另一次实现（前缀
 * KswordArkHvmEptp*），两份同一天写成、都没接进任何地方。本文件是超集，
 * 合并完成后那个头与它的 tools/hvm_unit_tests/hvm_eptp_switch_tests.c 已被
 * 删除（两者都没有任何生产代码或 CI 引用；副本留在本轮的 scratchpad 里）。
 * 下面这张对照表留着，是为了让将来翻到旧提交的人知道那些 EptpXxx 去哪了：
 * 那个头里唯一本文件原来没有的东西是前进性台账（ProgressReset /
 * ProgressAdmit / MAX_SAME_RIP_SWITCHES / PROGRESS 结构），已经按本文件的
 * 命名与上限合并到文件末尾。其余每一项在本文件里都有对应且更严的版本：
 *
 *   EptpAccessToLeafBits   -> EptSwAccessToLeafBits（另加数值断言）
 *   EptpLeafGrants         -> EptSwGrants（另加 PERM_MASK 掩取）
 *   EptpLeafIsLegal        -> EptSwPermissionsAreLegal（是 LeafIsWellFormed 的一项）
 *   EptpBuildPair          -> EptSwKindPermissions + EptSwComposeLeaf
 *   EptpPairIsTotal        -> EptSwPairIsTotal（逐位相同）
 *   EptpIndexFromLeaf/LeafFromIndex/IndexIsBase -> 同名 EptSw* 版本（另加边界拒绝）
 *   EptpDecide             -> EptSwDecide（另加原因码与空指针拒绝）
 *   EptpViewPageCost/TotalPageCost -> EptSwBaseCount + EptSwSecondaryPageCost
 *                                     （另加 MAX_LEAVES 上界）
 *   ACTION_PASS            -> 无对应，因为那个常量在它自己的文件里也从未被返回
 *
 * 也就是说合并之后那个头是纯重复，已删除。
 * 唯一**故意保留差异**的是叶数上限，理由见 MAX_LEAVES 的注释。
 */

#pragma once

#include "KswordArkHvmControls.h"

/* ------------------------------------------------------------------ */
/* 编译期断言                                                           */
/* ------------------------------------------------------------------ */

/*
 * 常量之间的关系用编译期断言钉死，而不是靠注释。
 * 用负长度数组的老写法，是因为它在 C89 的 MSVC 与 C++ 里表现一致，
 * 不需要 /std:c11 也不需要 <assert.h>。
 */
#define KSWORD_ARK_HVM_EPTSW_CAT_(a, b) a##b
#define KSWORD_ARK_HVM_EPTSW_CAT(a, b) KSWORD_ARK_HVM_EPTSW_CAT_(a, b)
#define KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(expr) \
    typedef char KSWORD_ARK_HVM_EPTSW_CAT(KswordArkHvmEptSwAssert_, __LINE__)[(expr) ? 1 : -1]

/* ------------------------------------------------------------------ */
/* EPT 叶项的位布局                                                     */
/* ------------------------------------------------------------------ */

/*
 * 三个权限位。数值来自架构（SDM Vol.3C, Table 29-6「Format of an EPT
 * Page-Table Entry」bit 0 = read、bit 1 = write、bit 2 = execute），不是本
 * 驱动的约定，永远不要重新编号。
 *
 * 别名到 Controls.h 而不是重写数值：重写就是第二个真值来源。位置一旦被重新
 * 编号，硬件不会报错，只会按另一种权限做判定——CLOAK 的「不可读」变成
 * 「不可写」，影子页对所有读者永久暴露，而所有自检都是绿的。
 */
#define KSWORD_ARK_HVM_EPTSW_READ    KSWORD_ARK_HVM_EPT_READ
#define KSWORD_ARK_HVM_EPTSW_WRITE   KSWORD_ARK_HVM_EPT_WRITE
#define KSWORD_ARK_HVM_EPTSW_EXECUTE KSWORD_ARK_HVM_EPT_EXECUTE
/* 三个权限位的并集，反复用于「除权限以外的一切」这种取反掩码。 */
#define KSWORD_ARK_HVM_EPTSW_PERM_MASK          \
    (KSWORD_ARK_HVM_EPTSW_READ |                \
     KSWORD_ARK_HVM_EPTSW_WRITE |               \
     KSWORD_ARK_HVM_EPTSW_EXECUTE)

/* 别名过来的位必须仍然是架构上的那三位。数值断言，不是符号自等。 */
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_READ == 0x1ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_WRITE == 0x2ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_EXECUTE == 0x4ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_PERM_MASK == 0x7ULL);

/* 叶项内存类型字段：bits 5:3（SDM Table 29-6，EPT memory type）。 */
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_SHIFT 3
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_MASK 0x7ULL

/*
 * bit 6 = ignore PAT；bit 7 = 大页标记（只在 PDPTE/PDE 上有意义）。
 *
 * 这两位的位置只有数值断言能钉住：把 IGNORE_PAT 挪到 bit 5 会落进内存类型域，
 * 一个 WB 页会被当成 WP 页；把 LARGE_PAGE 挪一位则会让处理器把一个 2MiB 叶
 * 当成指向下一级表的指针，直接去走页内容。两者都不报错。
 */
#define KSWORD_ARK_HVM_EPTSW_IGNORE_PAT 0x0000000000000040ULL
#define KSWORD_ARK_HVM_EPTSW_LARGE_PAGE 0x0000000000000080ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_IGNORE_PAT == (1ULL << 6));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_LARGE_PAGE == (1ULL << 7));
/* ignore-PAT 与大页位都不能落进内存类型域，否则一次赋值会改掉缓存类型。 */
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    ((KSWORD_ARK_HVM_EPTSW_IGNORE_PAT | KSWORD_ARK_HVM_EPTSW_LARGE_PAGE) &
     (KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_MASK <<
      KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_SHIFT)) == 0ULL);

/*
 * bits 9:8 = accessed / dirty（只有 EPTP 开了 A/D 才由硬件写）。
 * bit 8 是 accessed、bit 9 是 dirty，顺序不可颠倒：颠倒之后「这一页被写过」
 * 会被读成「这一页被访问过」，任何基于 A/D 的取证判据都会给出反的结论。
 */
#define KSWORD_ARK_HVM_EPTSW_ACCESSED 0x0000000000000100ULL
#define KSWORD_ARK_HVM_EPTSW_DIRTY    0x0000000000000200ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_ACCESSED == (1ULL << 8));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_DIRTY == (1ULL << 9));

/* bit 10 = 用户态可执行（只在 mode-based execute control 下有意义）。 */
#define KSWORD_ARK_HVM_EPTSW_USER_EXECUTE 0x0000000000000400ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_USER_EXECUTE == (1ULL << 10));

/*
 * bit 63 = suppress-#VE。架构默认是**反的**：该位为 0 的叶是「可转换」的，
 * 于是一旦启用 EPT-violation #VE，这种叶的每次违规都会被反射进 guest。这里的
 * guest 是正在跑的 Windows，它的 IDT[20] 没有为我们发明的 #VE 做准备，结局是
 * #GP -> #DF -> triple fault。
 *
 * 所以「属性继承」必须把这一位带过去。掉这一位不会在安装时报错，也不会在任何
 * 驱动自检里报错——只在 #VE 被打开、且那一页真的被访问时，一次性把机器打死。
 */
#define KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE 0x8000000000000000ULL

/* 叶项与 EPTP 共用的物理地址域：bits 51:12。别名，理由同权限位。 */
#define KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK KSWORD_ARK_HVM_EPT_PHYSICAL_MASK
/* 2MiB 叶的页帧域：bits 51:21。bits 20:12 在大页叶上是**保留必须为零**。 */
#define KSWORD_ARK_HVM_EPTSW_LARGE_FRAME_MASK 0x000FFFFFFFE00000ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK == 0x000FFFFFFFFFF000ULL);

/*
 * bits 62:52。架构上这一段部分「被忽略」、部分归 verify-guest-paging /
 * paging-write-access / supervisor shadow stack 等本驱动从不启用的功能。
 * 本驱动的策略是这一段必须全零：这里出现非零位，只可能是内存损坏或者一次
 * 写错了移位的按位或，两者都值得当场拒绝而不是带着上机器。
 *
 * 注意这里**只有 62:52**，不含 bit 63：叶项的 bit 63 是 suppress-#VE，
 * 那一位在叶里合法而且必须置。EPTP 那边的 bit 63 是保留必须为零，因此另有
 * 一个更宽的掩码 KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH，两者不可互换。
 */
#define KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH 0x7FF0000000000000ULL

/* 页与大页的字节数、每张表的条目数与条目宽度。前两个别名到 Controls.h。 */
#define KSWORD_ARK_HVM_EPTSW_PAGE_BYTES KSWORD_ARK_HVM_PAGE_BYTES
#define KSWORD_ARK_HVM_EPTSW_LARGE_BYTES KSWORD_ARK_HVM_LARGE_PAGE_BYTES
#define KSWORD_ARK_HVM_EPTSW_TABLE_ENTRIES 512UL
#define KSWORD_ARK_HVM_EPTSW_ENTRY_BYTES 8ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_PAGE_BYTES == 0x1000ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_LARGE_BYTES == 0x200000ULL);

/* suppress-#VE 是 bit 63，而 bits 62:52 是本驱动要求全零的那一段。 */
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE == (1ULL << 63));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH == 0x7FF0000000000000ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    (KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH &
     KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE) == 0ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_LARGE_FRAME_MASK ==
    (KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK &
     ~(KSWORD_ARK_HVM_EPTSW_LARGE_BYTES - 1ULL)));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    (KSWORD_ARK_HVM_EPTSW_TABLE_ENTRIES * KSWORD_ARK_HVM_EPTSW_ENTRY_BYTES) ==
    KSWORD_ARK_HVM_EPTSW_PAGE_BYTES);

/*
 * 架构定义的 EPT 内存类型编码（SDM Vol.3C, 29.3.7「EPT and Memory Typing」）。
 * 0 = UC、1 = WC、4 = WT、5 = WP、6 = WB；2、3、7 保留，写进叶里就是一次
 * EPT misconfiguration。UC 与 WB 别名到 Controls.h，那是 EPTP 侧的同一套编码。
 */
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_UC KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_UC
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WC 1ULL
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WT 4ULL
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WP 5ULL
#define KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WB KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_WB
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_UC == 0ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WC == 1ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WT == 4ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WP == 5ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WB == 6ULL);

/*
 * IA32_VMX_EPT_VPID_CAP 里本文件用到的能力位
 * （SDM Vol.3D, Appendix A.10「VPID and EPT Capabilities」）。
 *
 * 这些数是要与一个真实 MSR 值按位与的，所以位号错一格的表现是「硬件明明支持
 * 却被判成不支持」（多一次不必要的降级，还看得见）或者更糟的反面「硬件不支持
 * 却被判成支持」——execute-only 那一位如果读错，CLOAK 的主值会被当成可用，
 * 而实际写进去的 --x 叶在缺这项能力的机器上是 misconfiguration。
 * 已有的四位别名到 Controls.h；四位数值全部另有断言。
 */
#define KSWORD_ARK_HVM_EPTSW_CAP_EXECUTE_ONLY  0x0000000000000001ULL /* bit 0  */
#define KSWORD_ARK_HVM_EPTSW_CAP_PAGE_WALK_4   KSWORD_ARK_HVM_EPT_CAP_PAGE_WALK_4
#define KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_UC KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_UC
#define KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_WB KSWORD_ARK_HVM_EPT_CAP_MEMORY_TYPE_WB
#define KSWORD_ARK_HVM_EPTSW_CAP_INVEPT        0x0000000000100000ULL /* bit 20 */
#define KSWORD_ARK_HVM_EPTSW_CAP_ACCESSED_DIRTY KSWORD_ARK_HVM_EPT_CAP_ACCESSED_DIRTY
#define KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_SINGLE 0x0000000002000000ULL /* bit 25 */
#define KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_ALL    0x0000000004000000ULL /* bit 26 */

KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_EXECUTE_ONLY == (1ULL << 0));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_PAGE_WALK_4 == (1ULL << 6));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_UC == (1ULL << 8));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_WB == (1ULL << 14));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_INVEPT == (1ULL << 20));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_ACCESSED_DIRTY == (1ULL << 21));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_SINGLE == (1ULL << 25));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_ALL == (1ULL << 26));

/*
 * 由能力 MSR 读出 execute-only 是否可用。
 *
 * 上一版把 CAP_EXECUTE_ONLY 定义出来却没有任何函数读它，于是那个宏可以被挪到
 * 任何一位而单测毫无反应（评审的变异 M16 就是这么活下来的）；同时每个调用方
 * 各自去解 bit 0，等于给同一个判断留了 N 个真值来源。这个函数把它收成一个。
 * 判错的后果不对称：判成「支持」而硬件不支持，写下去的 --x 叶是一次
 * EPT misconfiguration；判成「不支持」只是多一次降级。
 */
static __inline int
KswordArkHvmEptSwExecuteOnlySupported(
    unsigned long long EptVpidCapability
    )
{
    return (EptVpidCapability & KSWORD_ARK_HVM_EPTSW_CAP_EXECUTE_ONLY) != 0ULL
        ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* 协议规模上限                                                         */
/* ------------------------------------------------------------------ */

/*
 * 可翻转叶的上限，与协议里视图表的容量一致
 * （KswordArkHvmIoctl.h 的 KSWORD_ARK_HVM_MAX_VIEWS = 32）。
 *
 * 定义在文件这么靠前的位置，是因为**每一个**吃 LeafCount 的函数都必须用它做
 * 上界，包括本文件最靠前的那个（PreEntryInvalidationCount）。上一版把它定义
 * 在页开销那一节，于是靠前的那个函数没有上界可用，成了唯一一个能被
 * LeafCount = 0xFFFFFFFF 溢出成 0 的消费者。
 *
 * 与 hvm_ept_local.h 的 KSW_HVM_MAX_LOCAL_LEAVES（= 8）**故意不同**，两个数
 * 不是同一个量：那个 8 是每处理器私有层次能承受的叶数，
 * 这里的 32 对齐的是协议同时可安装的视图数。集成时如果两套机制复合，
 * 生效的是**较小**的那个；这一条必须由集成 owner 在接线处显式取 min，
 * 不能指望两个头自己对齐——它们描述的本来就是两个约束。
 */
#define KSWORD_ARK_HVM_EPTSW_MAX_LEAVES 32UL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_MAX_LEAVES == 32UL);

/* ------------------------------------------------------------------ */
/* 叶项的解析                                                           */
/* ------------------------------------------------------------------ */

/* 取出叶项里的三个权限位。 */
static __inline unsigned long long
KswordArkHvmEptSwLeafPermissions(
    unsigned long long LeafEntry
    )
{
    return LeafEntry & KSWORD_ARK_HVM_EPTSW_PERM_MASK;
}

/* 取出叶项编码的页帧（bits 51:12）。 */
static __inline unsigned long long
KswordArkHvmEptSwLeafFrame(
    unsigned long long LeafEntry
    )
{
    return LeafEntry & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK;
}

/* 取出叶项的内存类型编码。 */
static __inline unsigned long long
KswordArkHvmEptSwLeafMemoryType(
    unsigned long long LeafEntry
    )
{
    return (LeafEntry >> KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_MASK;
}

/*
 * 取出「除权限与页帧以外的一切」。
 *
 * 这就是视图构造里的属性继承源：内存类型、ignore-PAT、大页标记、A/D、
 * suppress-#VE 全部在这一坨里。用「保留一份白名单」而不是「减去两个域」写这个
 * 函数是危险的——白名单漏掉哪一位，那一位就会在主/次值里悄悄变成零，而两者
 * 里最要命的正是 suppress-#VE（见其宏注释）与内存类型（把 MMIO 页从 UC 改成
 * WB，表现是设备行为随机出错，没人会怀疑到 EPT 上）。
 */
static __inline unsigned long long
KswordArkHvmEptSwLeafAttributes(
    unsigned long long LeafEntry
    )
{
    return LeafEntry &
        ~(KSWORD_ARK_HVM_EPTSW_PERM_MASK | KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK);
}

/*
 * 由属性、页帧、权限合成一个叶项。
 *
 * 三个输入**都要掩**，这一条不是防御性编程而是必须：
 *   - 页帧没掩，一个未对齐的影子物理地址会把低 12 位泼进权限位与内存类型域，
 *     结果是一个权限比预期宽、缓存类型被改掉的叶，而它看上去完全正常；
 *   - 权限没掩，调用方传进来的协议访问掩码里任何额外的位都会落到内存类型上；
 *   - 属性没掩，调用方如果传了一个完整的原始叶项（而不是 Attributes 的结果），
 *     旧页帧会与新页帧按位或在一起——指向一个既不是真页也不是影子页的地方。
 *     CLOAK 主值一旦指向错的帧，执行的就是错的字节，而安装期看不出任何异常。
 */
static __inline unsigned long long
KswordArkHvmEptSwComposeLeaf(
    unsigned long long Attributes,
    unsigned long long Frame,
    unsigned long long Permissions
    )
{
    return (Attributes &
                ~(KSWORD_ARK_HVM_EPTSW_PERM_MASK |
                  KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK)) |
        (Frame & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) |
        (Permissions & KSWORD_ARK_HVM_EPTSW_PERM_MASK);
}

/* ------------------------------------------------------------------ */
/* 叶项的良构判据                                                       */
/* ------------------------------------------------------------------ */

/* 叶项良构判据的结果码。0 = 合法，其余各自指出**哪一项**不对。 */
#define KSWORD_ARK_HVM_EPTSW_LEAF_OK              0UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PARAMETER   1UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PERMISSIONS 2UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_MEMORY_TYPE 3UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_LARGE_BIT   4UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_ALIGNMENT   5UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PHYS_WIDTH  6UL
#define KSWORD_ARK_HVM_EPTSW_LEAF_BAD_RESERVED    7UL

/* 物理地址宽度的合法取值区间，来自 CPUID.80000008H:EAX[7:0] 的架构上下界。 */
#define KSWORD_ARK_HVM_EPTSW_MIN_PHYS_BITS 32UL
#define KSWORD_ARK_HVM_EPTSW_MAX_PHYS_BITS 52UL

/* 判断一个内存类型编码是否是架构定义的五种之一。 */
static __inline int
KswordArkHvmEptSwMemoryTypeIsLegal(
    unsigned long long MemoryType
    )
{
    switch (MemoryType) {
    case KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_UC:
    case KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WC:
    case KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WT:
    case KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WP:
    case KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WB:
        /* 报告架构承认的编码。 */
        return 1;
    default:
        /* 2、3、7 保留：写进叶里就是一次 EPT misconfiguration。 */
        return 0;
    }
}

/*
 * 判断一组权限位在本机制下是否可用。
 *
 * 三条判据，都是「不满足就变成 exit reason 49，而那个退出不告诉你是哪一位」：
 *   - 写必带读。EPT 没有「只写」这种编码。
 *   - 执行不带读只在硬件报告 execute-only 时合法。缺这条能力时把 X 单独写进叶，
 *     整页都会 misconfiguration。
 *   - 权限全零架构上是「不存在」而不是错误，但本机制不接受：一个三种访问都不
 *     授予的叶，无论切到哪套层次都会再次违规，那是一个不前进的环，而环的表现
 *     是整机静默死锁。所以在这里就把它判成非法。
 */
static __inline int
KswordArkHvmEptSwPermissionsAreLegal(
    unsigned long long Permissions,
    int ExecuteOnlySupported
    )
{
    const unsigned long long bits = Permissions & KSWORD_ARK_HVM_EPTSW_PERM_MASK;

    /* 拒绝「不存在」的叶：本机制永远找不到能服务它的层次。 */
    if (bits == 0ULL) {
        return 0;
    }
    /* 写必须伴随读。 */
    if ((bits & KSWORD_ARK_HVM_EPTSW_WRITE) != 0ULL &&
        (bits & KSWORD_ARK_HVM_EPTSW_READ) == 0ULL) {
        return 0;
    }
    /* 只有硬件支持时，执行才可以不带读。 */
    if ((bits & KSWORD_ARK_HVM_EPTSW_EXECUTE) != 0ULL &&
        (bits & KSWORD_ARK_HVM_EPTSW_READ) == 0ULL &&
        !ExecuteOnlySupported) {
        return 0;
    }
    /* 报告这组权限可以被硬件接受。 */
    return 1;
}

/*
 * 判断页帧是否按它所在层级对齐。
 *
 * 4KiB 叶不可能不对齐（物理域从 bit 12 起，低 12 位是别的字段），所以这个函数
 * 对非大页恒为真——保留这条分支是为了让调用点读起来是「按层级判对齐」而不是
 * 「大页才判」，将来若引入 1GiB 叶只需在这里加一格。
 * 大页叶则实打实：bits 20:12 是保留必须为零，一个只按 4KiB 对齐的影子帧写进
 * 2MiB 叶，安装期一切正常，第一次访问就是 misconfiguration。
 */
static __inline int
KswordArkHvmEptSwFrameIsAligned(
    unsigned long long Frame,
    int IsLargePage
    )
{
    if (IsLargePage) {
        /* 大页叶要求 2MiB 对齐。 */
        return (Frame & (KSWORD_ARK_HVM_EPTSW_LARGE_BYTES - 1ULL)) == 0ULL
            ? 1 : 0;
    }
    /* 4KiB 叶要求页对齐。 */
    return (Frame & (KSWORD_ARK_HVM_EPTSW_PAGE_BYTES - 1ULL)) == 0ULL ? 1 : 0;
}

/*
 * 全面校验一个叶项，返回**具体**的失败项而不是一个布尔。
 *
 * 判据顺序固定：参数、权限、内存类型、大页标记、页帧对齐、物理宽度、保留高位。
 * 顺序固定是为了让单测能逐项构造「只错这一项」的样本；如果顺序会变，测试就只能
 * 断言「非零」，而那正好把「错了另一项」的回归放过去。
 *
 * MaxPhysicalAddressBits 来自 CPUID.80000008H:EAX[7:0]。超出这个宽度的物理位
 * 必须为零：多一位不会被忽略，它会让整项变成 misconfiguration。
 */
static __inline unsigned long
KswordArkHvmEptSwLeafIsWellFormed(
    unsigned long long LeafEntry,
    int IsLargePage,
    unsigned long MaxPhysicalAddressBits,
    int ExecuteOnlySupported
    )
{
    unsigned long long widthMask = 0ULL;

    /* 拒绝一个不可能来自 CPUID 的物理宽度，免得下面的移位是未定义行为。 */
    if (MaxPhysicalAddressBits < KSWORD_ARK_HVM_EPTSW_MIN_PHYS_BITS ||
        MaxPhysicalAddressBits > KSWORD_ARK_HVM_EPTSW_MAX_PHYS_BITS) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PARAMETER;
    }
    /* 权限组合必须能被硬件接受。 */
    if (!KswordArkHvmEptSwPermissionsAreLegal(
            KswordArkHvmEptSwLeafPermissions(LeafEntry),
            ExecuteOnlySupported)) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PERMISSIONS;
    }
    /* 内存类型必须是五种架构编码之一。 */
    if (!KswordArkHvmEptSwMemoryTypeIsLegal(
            KswordArkHvmEptSwLeafMemoryType(LeafEntry))) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_MEMORY_TYPE;
    }
    /*
     * 大页标记必须与调用方声明的层级一致。不一致的两种后果都很难查：
     * 该置不置，处理器会把这一项当成指向下一级表的指针，于是把页内容当页表走；
     * 不该置却置了，一个 4KiB 页表项会被当成 2MiB 叶。
     */
    if (IsLargePage) {
        if ((LeafEntry & KSWORD_ARK_HVM_EPTSW_LARGE_PAGE) == 0ULL) {
            return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_LARGE_BIT;
        }
    } else {
        if ((LeafEntry & KSWORD_ARK_HVM_EPTSW_LARGE_PAGE) != 0ULL) {
            return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_LARGE_BIT;
        }
    }
    /* 页帧必须按层级对齐。 */
    if (!KswordArkHvmEptSwFrameIsAligned(
            KswordArkHvmEptSwLeafFrame(LeafEntry),
            IsLargePage)) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_ALIGNMENT;
    }
    /* 物理域里超出实现宽度的高位必须为零。 */
    widthMask = KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK &
        ~((1ULL << MaxPhysicalAddressBits) - 1ULL);
    if ((LeafEntry & widthMask) != 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_PHYS_WIDTH;
    }
    /* 本驱动从不使用的高位段必须为零。 */
    if ((LeafEntry & KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH) != 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_LEAF_BAD_RESERVED;
    }
    /* 报告这一项可以被硬件接受。 */
    return KSWORD_ARK_HVM_EPTSW_LEAF_OK;
}

/* ------------------------------------------------------------------ */
/* EPTP 字段                                                            */
/* ------------------------------------------------------------------ */

/*
 * EPTP 字段布局：bits 2:0 内存类型，bits 5:3 页遍历级数减一，bit 6 A/D
 * （SDM Vol.3C, Table 25-9「Format of Extended-Page-Table Pointer」）。
 * 四个字段全部别名到 Controls.h，理由同权限位：两处各写一份数值，哪天有人
 * 改了其中一处，VM entry 只会返回一个错误码，不会说是哪一位不一致。
 */
#define KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK \
    KSWORD_ARK_HVM_EPTP_MEMORY_TYPE_MASK
#define KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT \
    KSWORD_ARK_HVM_EPTP_WALK_LENGTH_SHIFT
#define KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK KSWORD_ARK_HVM_EPTP_WALK_LENGTH_MASK
#define KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY KSWORD_ARK_HVM_EPTP_ACCESSED_DIRTY
/*
 * bits 11:7 保留必须为零（bit 7 在新版 SDM 里给 supervisor shadow stack 用，
 * 本驱动不启用那项控制，所以对我们仍然是必须为零）。这一段不是「被忽略」，
 * 非零会让 VM entry 直接失败。
 */
#define KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_LOW KSWORD_ARK_HVM_EPTP_RESERVED_LOW

/*
 * bits 63:52 保留必须为零。
 *
 * 上一版没有为这一段单列判据，只靠 widthMask = ~((1 << MAXPHYADDR) - 1) 的
 * 副作用兜住：在 MAXPHYADDR < 52 的机器上那个掩码确实覆盖了 63:52，所以行为
 * 是对的。但叶那条路径用的是更窄的 PHYSICAL_MASK & ~(...) 加一条独立的
 * RESERVED_HIGH 检查——两条路径形状不一样，迟早被人「顺手统一」成叶那种写法，
 * 而统一之后 bits 63:52 就完全无人检查了：一个带 bit 55 的 EPTP 会被判成合法，
 * 写进 VMCS 之后 VM entry 直接失败，错误码只有一个数，不说是哪一位。
 * 评审的变异 M15 做的正是这件事，而当时的 344 条断言一条都没响。
 *
 * 所以这一段现在有自己的掩码、自己的结果码、以及自己的数值断言。
 * 它比叶那条宽一位：叶的 bit 63 是 suppress-#VE（合法且必须置），
 * EPTP 的 bit 63 是保留必须为零。
 */
#define KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH 0xFFF0000000000000ULL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH ==
    (KSWORD_ARK_HVM_EPTSW_RESERVED_HIGH | KSWORD_ARK_HVM_EPTSW_SUPPRESS_VE));
/* 保留高位与物理地址域必须互不重叠，否则一个合法根地址会被判成保留位非零。 */
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    (KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH &
     KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) == 0ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK == 0x7ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT == 3);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK == 0x7ULL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY == (1ULL << 6));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_LOW == 0x0000000000000F80ULL);

/* 本驱动使用的四级页遍历。 */
#define KSWORD_ARK_HVM_EPTSW_EPTP_WALK_LEVELS 4UL

/* EPTP 良构判据的结果码。 */
#define KSWORD_ARK_HVM_EPTSW_EPTP_OK              0UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PARAMETER   1UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_ROOT        2UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE 3UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_WALK        4UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_AD          5UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED    6UL
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PHYS_WIDTH  7UL
/* bits 63:52 非零：架构保留，与本机实现宽度无关。 */
#define KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH 8UL

/*
 * 由根表物理地址与三项控制合成一个 EPTP。
 *
 * 唯一真正容易错的是**页遍历级数字段存的是级数减一**：四级 walk 写 3。写成 4
 * 的结果是 VM entry 失败，而失败只给一个错误码，不说是哪个字段——在一台没有
 * 内核调试器的目标机上，这就是「装上去就重启，看不出为什么」。
 *
 * 根地址同样必须掩：一个未对齐的根会把低位泼进内存类型与级数字段，于是你得到
 * 一个字段全乱但看上去只是「地址有点怪」的指针。
 *
 * 级数非法时返回 0。0 永远不是合法 EPTP（级数字段为 0），所以它是一个不会与
 * 任何成功结果混淆的失败值。
 */
static __inline unsigned long long
KswordArkHvmEptSwComposeEptp(
    unsigned long long RootPhysical,
    unsigned long long MemoryType,
    unsigned long WalkLevels,
    int EnableAccessedDirty
    )
{
    unsigned long long eptp = 0ULL;

    /* 级数字段只有三位，能表示 1..8 级；其余取值无法编码。 */
    if (WalkLevels == 0UL || WalkLevels > 8UL) {
        return 0ULL;
    }
    /* 页帧对齐到表边界。 */
    eptp = RootPhysical & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK;
    /* 内存类型落在 bits 2:0。 */
    eptp |= MemoryType & KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK;
    /* 级数字段存的是级数减一。 */
    eptp |= ((unsigned long long)(WalkLevels - 1UL) &
        KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK) <<
        KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT;
    /* A/D 只在硬件支持且调用方要求时置位。 */
    if (EnableAccessedDirty) {
        eptp |= KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY;
    }
    /* 返回完整的 EPT pointer 值。 */
    return eptp;
}

/* 取出 EPTP 指向的根表物理地址。 */
static __inline unsigned long long
KswordArkHvmEptSwEptpRoot(
    unsigned long long Eptp
    )
{
    return Eptp & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK;
}

/* 取出 EPTP 的内存类型编码。 */
static __inline unsigned long long
KswordArkHvmEptSwEptpMemoryType(
    unsigned long long Eptp
    )
{
    return Eptp & KSWORD_ARK_HVM_EPTSW_EPTP_MEMORY_TYPE_MASK;
}

/*
 * 取出 EPTP 的页遍历**级数**（不是字段原值）。
 * 解析时忘记加一与合成时忘记减一是同一个错误的两面，两处都必须显式写出来。
 */
static __inline unsigned long
KswordArkHvmEptSwEptpWalkLevels(
    unsigned long long Eptp
    )
{
    return (unsigned long)(((Eptp >> KSWORD_ARK_HVM_EPTSW_EPTP_WALK_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_EPTP_WALK_MASK) + 1ULL);
}

/* 报告 EPTP 是否开启了 accessed/dirty 跟踪。 */
static __inline int
KswordArkHvmEptSwEptpHasAccessedDirty(
    unsigned long long Eptp
    )
{
    return (Eptp & KSWORD_ARK_HVM_EPTSW_EPTP_ACCESSED_DIRTY) != 0ULL ? 1 : 0;
}

/*
 * 取出 EPT 缓存标签 EP4TA（EPTP 的 bits 51:12）。
 *
 * 这个数是整套「切 EPTP 之后不需要 INVEPT」论证的支点：guest-physical 与
 * combined 映射都按 EP4TA 打标签，两套层次的根地址不同则标签不同，缓存条目
 * 互不别名。反过来说，如果两套「不同」的层次因为构造 bug 拿到了同一个根，
 * 切换就完全不改变标签——处理器继续用旧翻译，同一条指令再次违规，于是得到
 * 一个不前进的环。所以这个数必须能被单独检查，见下面的 SwitchNeedsInvalidation。
 */
static __inline unsigned long long
KswordArkHvmEptSwEp4ta(
    unsigned long long Eptp
    )
{
    return Eptp & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK;
}

/*
 * 全面校验一个 EPTP，返回具体失败项。
 *
 * 判据顺序固定：参数、根地址、内存类型、级数、A/D、保留低位、保留高位、
 * 物理宽度。
 *
 * 与 KswordArkHvmControls.h 的 KswordArkHvmEptpIsValid 的关系（必须写清楚，
 * 否则同一个 EPTP 在一个驱动里会因为调到哪个 helper 而得到两个答案）：
 * 本函数是**严格更强**的那一个，多拒绝三类值——根地址为零、
 * MaxPhysicalAddressBits 落在 [32,52] 之外、bits 63:52 非零。也就是说
 * 「本函数返回 EPTP_OK」蕴含「KswordArkHvmEptpIsValid 返回非零」，反之不成立。
 * 切换后端的每一个 EPTP 都必须过本函数：那三类多出来的拒绝，正是「槽位忘了
 * 填」「宽度参数是垃圾」「保留位被别的代码泼进来」这三种只会静默走错树的
 * 构造错误。单测里有一条断言钉住这个蕴含方向。
 *
 * 根地址为零单列一项：字段判据管不到它（0 在字段层面「合法」），但一个根为零
 * 的 EPTP 只可能来自「槽位忘了填」，而它的后果是处理器从物理页 0 开始走页表。
 * 把它判成非法，是把一个默默走错树的 bug 变成一次拒绝。
 */
static __inline unsigned long
KswordArkHvmEptSwEptpIsWellFormed(
    unsigned long long Eptp,
    unsigned long long EptVpidCapability,
    unsigned long MaxPhysicalAddressBits
    )
{
    const unsigned long long memoryType = KswordArkHvmEptSwEptpMemoryType(Eptp);
    unsigned long long widthMask = 0ULL;

    /* 拒绝一个不可能来自 CPUID 的物理宽度。 */
    if (MaxPhysicalAddressBits < KSWORD_ARK_HVM_EPTSW_MIN_PHYS_BITS ||
        MaxPhysicalAddressBits > KSWORD_ARK_HVM_EPTSW_MAX_PHYS_BITS) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PARAMETER;
    }
    /* 根地址为零意味着这个槽从来没被填过。 */
    if (KswordArkHvmEptSwEptpRoot(Eptp) == 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_ROOT;
    }
    /* 内存类型必须是硬件报告支持的那一种。 */
    if (memoryType == KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_UC) {
        if ((EptVpidCapability &
                KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_UC) == 0ULL) {
            return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE;
        }
    } else if (memoryType == KSWORD_ARK_HVM_EPTSW_MEMORY_TYPE_WB) {
        if ((EptVpidCapability &
                KSWORD_ARK_HVM_EPTSW_CAP_MEMORY_TYPE_WB) == 0ULL) {
            return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE;
        }
    } else {
        /* EPTP 只承认 UC 与 WB，与叶项的五种编码不是同一套。 */
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_MEMORY_TYPE;
    }
    /* 级数必须正好是四，并且硬件必须报告支持四级 walk。 */
    if (KswordArkHvmEptSwEptpWalkLevels(Eptp) !=
            KSWORD_ARK_HVM_EPTSW_EPTP_WALK_LEVELS ||
        (EptVpidCapability &
            KSWORD_ARK_HVM_EPTSW_CAP_PAGE_WALK_4) == 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_WALK;
    }
    /* 只有硬件支持时才允许开启 accessed/dirty。 */
    if (KswordArkHvmEptSwEptpHasAccessedDirty(Eptp) &&
        (EptVpidCapability &
            KSWORD_ARK_HVM_EPTSW_CAP_ACCESSED_DIRTY) == 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_AD;
    }
    /* 低位保留域必须为零。 */
    if ((Eptp & KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_LOW) != 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED;
    }
    /*
     * 高位保留域 bits 63:52 必须为零。这一条**先于**宽度判据，而且不依赖
     * MaxPhysicalAddressBits：它是架构常量，在任何机器上都成立。分开写不是
     * 冗余——把它并进宽度掩码，看上去等价（MAXPHYADDR <= 52 时确实等价），
     * 但那样这一段就没有独立判据了，谁把宽度掩码收窄成叶那种
     * PHYSICAL_MASK & ~(...) 的形状，bits 63:52 立刻无人检查，
     * 而后果是 VM entry 失败，只给一个错误码。
     */
    if ((Eptp & KSWORD_ARK_HVM_EPTSW_EPTP_RESERVED_HIGH) != 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_RESERVED_HIGH;
    }
    /* 超出实现物理宽度的高位必须为零。 */
    widthMask = ~((1ULL << MaxPhysicalAddressBits) - 1ULL);
    if ((Eptp & widthMask) != 0ULL) {
        return KSWORD_ARK_HVM_EPTSW_EPTP_BAD_PHYS_WIDTH;
    }
    /* 报告这个指针可以被 VM entry 接受。 */
    return KSWORD_ARK_HVM_EPTSW_EPTP_OK;
}

/*
 * 由已经在用的 EPTP 派生出指向另一套层次根表的 EPTP。
 *
 * **必须派生而不是重新合成。** 合成会让内存类型、页遍历级数、A/D 位有第二个
 * 真值来源：基座那边将来改了任何一项（比如按 CPUID 决定开不开 A/D），次层次
 * 这边不会跟着改，而 VM entry 只会返回一个错误码，不会说是哪一套指针、哪一位
 * 不一致。派生出来的指针有一条可以直接陈述的性质：VM entry 接受它当且仅当
 * 接受基座指针。
 */
static __inline unsigned long long
KswordArkHvmEptSwRebaseEptp(
    unsigned long long SourceEptp,
    unsigned long long NewRootPhysical
    )
{
    /*
     * 直接复用 Controls.h 的实现而不是再写一遍同一个表达式：这个公式在
     * 本仓库里被三处需要（私有层次的表项、私有 EPTP、这里的次层次 EPTP），
     * 写三遍就有三处可以各自算错，而算错的表现是走到一张不相干的表上。
     */
    return KswordArkHvmEptRebaseEntry(SourceEptp, NewRootPhysical);
}

/*
 * 报告一次 EPTP 切换是否需要显式失效。
 *
 * 正常情况恒为否，理由见 Ep4ta 的注释：换根就是换标签，处理器不会用另一套的
 * 缓存翻译。这个函数存在的意义是把那条论证变成一个**可以被违反**的判据——
 * 当两套层次因为构造错误共享了根（例如「次层次」是靠只翻转 A/D 位造出来的），
 * 标签不变，切换在硬件上是空操作，同一条指令会永远重新违规。那种情况下这里
 * 返回真，调用方据此拒绝，而不是带着一个静默死锁上机器。
 */
static __inline int
KswordArkHvmEptSwSwitchNeedsInvalidation(
    unsigned long long FromEptp,
    unsigned long long ToEptp
    )
{
    return KswordArkHvmEptSwEp4ta(FromEptp) == KswordArkHvmEptSwEp4ta(ToEptp)
        ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* INVEPT descriptor                                                    */
/* ------------------------------------------------------------------ */

/*
 * 架构定义的两种 INVEPT 类型（SDM Vol.3C, 30.3「INVEPT」：type 1 =
 * single-context、type 2 = all-context；0 与 3 保留）。
 *
 * **这两个数会被原样装进寄存器交给 INVEPT 指令**，所以它们不是本文件的内部
 * 编号，改一个数就是改一条指令的语义。上一版所有断言都只用符号引用它们，
 * 于是把 1 与 2 对调之后 344 条断言全过（评审的变异 M06），而真机上的后果是：
 * 请求 single-context 时发出的是 all-context（多刷了整台机器，还看得见），
 * 或者反过来，请求 all-context 时发出一次 descriptor 全零的 single-context
 * ——那一次失效什么都没刷掉，guest 继续用过期翻译，没有任何症状。
 * 因此这里与单测里都必须有**数值**断言。
 */
#define KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE 1UL
#define KSWORD_ARK_HVM_EPTSW_INVEPT_ALL    2UL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE == 1UL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_INVEPT_ALL == 2UL);

/* INVEPT 的 16 字节内存操作数。 */
typedef struct _KSWORD_ARK_HVM_EPTSW_INVEPT_DESCRIPTOR
{
    /* qword 0：single-context 时是完整的 EPT pointer 值。 */
    unsigned long long Eptp;
    /* qword 1：架构规定必须为零。 */
    unsigned long long Reserved;
} KSWORD_ARK_HVM_EPTSW_INVEPT_DESCRIPTOR;

/* 报告硬件是否支持某一种 INVEPT 类型。 */
static __inline int
KswordArkHvmEptSwInveptTypeSupported(
    unsigned long Type,
    unsigned long long EptVpidCapability
    )
{
    /* 没有 INVEPT 指令本身，谈类型没有意义。 */
    if ((EptVpidCapability & KSWORD_ARK_HVM_EPTSW_CAP_INVEPT) == 0ULL) {
        return 0;
    }
    if (Type == KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE) {
        return (EptVpidCapability &
            KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_SINGLE) != 0ULL ? 1 : 0;
    }
    if (Type == KSWORD_ARK_HVM_EPTSW_INVEPT_ALL) {
        return (EptVpidCapability &
            KSWORD_ARK_HVM_EPTSW_CAP_INVEPT_ALL) != 0ULL ? 1 : 0;
    }
    /* 0 与 3 是保留类型：执行它们只会得到 VMfail。 */
    return 0;
}

/*
 * 构造一个 INVEPT descriptor。
 *
 * 三处「错了不报错」：
 *
 *  1. qword 0 存的是**完整的 EPT pointer**，不是根地址。现有处理器只看 bits
 *     51:12，所以把低位掩掉「也能用」——直到某一天不能用，而那时的表现是
 *     失效没生效、guest 读到过期翻译。「在这块芯片上能跑」不是驱动该替架构
 *     做的判断，所以这里原样传 EPTP。
 *  2. all-context 时 descriptor 被架构忽略，但这里显式清零。传一个非零值不会
 *     报错，却会让「调用方其实想要 single 却传错了类型」这个 bug 一直藏着——
 *     清零之后，误用 all 去失效某一套层次时，至少不会有一个看着对的 EPTP 摆在
 *     descriptor 里误导读代码的人。
 *  3. 失败时把 descriptor 清零。忽略返回值的调用方如果就地执行 INVEPT，
 *     栈上的残留值会被当成一个真的 EPTP 去失效——那可能是任意一套层次。
 *
 * 返回非零表示 descriptor 可用。
 */
static __inline int
KswordArkHvmEptSwBuildInveptDescriptor(
    unsigned long Type,
    unsigned long long Eptp,
    unsigned long long EptVpidCapability,
    KSWORD_ARK_HVM_EPTSW_INVEPT_DESCRIPTOR* Descriptor
    )
{
    /* 没有输出位置就没有可以构造的东西。 */
    if (Descriptor == 0) {
        return 0;
    }
    /* 先清零，任何后续失败路径都不会留下可执行的残留。 */
    Descriptor->Eptp = 0ULL;
    Descriptor->Reserved = 0ULL;
    /* 硬件必须支持这一种类型。 */
    if (!KswordArkHvmEptSwInveptTypeSupported(Type, EptVpidCapability)) {
        return 0;
    }
    if (Type == KSWORD_ARK_HVM_EPTSW_INVEPT_SINGLE) {
        /* single-context 必须点名一套真实存在的层次。 */
        if (KswordArkHvmEptSwEptpRoot(Eptp) == 0ULL) {
            return 0;
        }
        /* 原样传递完整的 EPT pointer 值。 */
        Descriptor->Eptp = Eptp;
    }
    /* all-context 保持全零。 */
    return 1;
}

/*
 * 计算进入 guest 之前必须发出的 single-context INVEPT 次数。
 *
 * 每一套次层次都由回收来的非分页内存构成，可能带着上一次驻留留下的过期标签；
 * 而这一次驻留期间**永远不会再发 INVEPT**（运行期不写表，靠标签隔离），所以
 * 进入前这一次是它唯一的机会。漏掉一套的表现是那一页在启动初期读到别人的旧
 * 翻译，之后自愈——一个只在冷启动窗口出现、无法复现的错误。
 *
 * 基座是已经在跑的共享层次，不重复失效；这一条同时保证「不请求这套特性时
 * 路径与今天逐字节相同」。
 *
 * **返回 0 是一个有含义的值：「没有次层次需要失效」。** 所以这个函数绝对不能
 * 靠溢出回绕产出 0。上一版是全文件唯一没有 MAX_LEAVES 上界、也不加宽的
 * LeafCount 消费者：LeafCount + 1 在 uint32 里对 0xFFFFFFFF 回绕成 0，
 * 调用方于是以为一次 INVEPT 都不用发，带着每一套回收内存里的过期 EP4TA 标签
 * 进 guest——表现是冷启动窗口里某些页读到上一次驻留的旧翻译，之后自愈，
 * 无法复现。现在两道防护同时上：先按协议上限拒绝，再用 64 位承载和。
 */
static __inline unsigned long long
KswordArkHvmEptSwPreEntryInvalidationCount(
    unsigned long LeafCount,
    int SharedBaseAlreadyLive
    )
{
    /* 一叶都没有就没有次层次，也就没有要失效的东西。 */
    if (LeafCount == 0UL) {
        return 0ULL;
    }
    /*
     * 越界的叶数与文件里其它每一个 LeafCount 消费者同样拒绝：
     * SecondaryPageCost / HierarchyCount / IndexFromLeaf / Decide 都拒绝
     * 大于 MAX_LEAVES 的值，这里放行就等于给同一个上限留了一个缺口。
     */
    if (LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES) {
        return 0ULL;
    }
    /* 每叶一套次层次，各失效一次；和用 64 位承载，不可能回绕。 */
    return (unsigned long long)LeafCount +
        (SharedBaseAlreadyLive ? 0ULL : 1ULL);
}

/* ------------------------------------------------------------------ */
/* 索引算术                                                             */
/* ------------------------------------------------------------------ */

/* 每一级索引都是九位。 */
#define KSWORD_ARK_HVM_EPTSW_INDEX_MASK 0x1FFULL
#define KSWORD_ARK_HVM_EPTSW_PML4_SHIFT 39
#define KSWORD_ARK_HVM_EPTSW_PDPT_SHIFT 30
#define KSWORD_ARK_HVM_EPTSW_PD_SHIFT 21
#define KSWORD_ARK_HVM_EPTSW_PT_SHIFT 12

/*
 * 由 guest 物理地址取出四级索引。
 *
 * 移位量写错一档不会 fault：走的是一张**存在且可写**的表，只是描述的是另一段
 * 物理内存。于是次层次改的是隔壁 GiB 窗口的权限，被保护的页毫无保护，而两边
 * 都没有任何症状。九位掩码同样不能省：不掩的话 PML4 索引会随高位地址长成一个
 * 巨大的数，越过表尾写进相邻页。
 */
static __inline unsigned long
KswordArkHvmEptSwPml4Index(
    unsigned long long GuestPhysical
    )
{
    return (unsigned long)((GuestPhysical >> KSWORD_ARK_HVM_EPTSW_PML4_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_INDEX_MASK);
}

/* 取出 1GiB 窗口的索引。 */
static __inline unsigned long
KswordArkHvmEptSwPdptIndex(
    unsigned long long GuestPhysical
    )
{
    return (unsigned long)((GuestPhysical >> KSWORD_ARK_HVM_EPTSW_PDPT_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_INDEX_MASK);
}

/* 取出 2MiB 叶的索引。 */
static __inline unsigned long
KswordArkHvmEptSwPdIndex(
    unsigned long long GuestPhysical
    )
{
    return (unsigned long)((GuestPhysical >> KSWORD_ARK_HVM_EPTSW_PD_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_INDEX_MASK);
}

/* 取出被拆分的 2MiB 区里 4KiB 页的索引。 */
static __inline unsigned long
KswordArkHvmEptSwPtIndex(
    unsigned long long GuestPhysical
    )
{
    return (unsigned long)((GuestPhysical >> KSWORD_ARK_HVM_EPTSW_PT_SHIFT) &
        KSWORD_ARK_HVM_EPTSW_INDEX_MASK);
}

/*
 * 由四级索引还原页基址。
 *
 * 这不是给驱动用的，是给自检与单测用的：分解与还原互为逆运算这件事，是「改哪
 * 一格」与「复制哪一张表」两个决定自洽的唯一证据。这两个数一旦错开一格，次值
 * 就写到相邻的页上——那一页从此被重定向，而被保护的那一页毫无保护。
 */
static __inline unsigned long long
KswordArkHvmEptSwComposeGuestPhysical(
    unsigned long Pml4Index,
    unsigned long PdptIndex,
    unsigned long PdIndex,
    unsigned long PtIndex
    )
{
    return (((unsigned long long)Pml4Index & KSWORD_ARK_HVM_EPTSW_INDEX_MASK) <<
                KSWORD_ARK_HVM_EPTSW_PML4_SHIFT) |
        (((unsigned long long)PdptIndex & KSWORD_ARK_HVM_EPTSW_INDEX_MASK) <<
                KSWORD_ARK_HVM_EPTSW_PDPT_SHIFT) |
        (((unsigned long long)PdIndex & KSWORD_ARK_HVM_EPTSW_INDEX_MASK) <<
                KSWORD_ARK_HVM_EPTSW_PD_SHIFT) |
        (((unsigned long long)PtIndex & KSWORD_ARK_HVM_EPTSW_INDEX_MASK) <<
                KSWORD_ARK_HVM_EPTSW_PT_SHIFT);
}

/* 把地址向下取整到包含它的 2MiB 叶。 */
static __inline unsigned long long
KswordArkHvmEptSwLeafBase(
    unsigned long long GuestPhysical
    )
{
    return GuestPhysical & ~(KSWORD_ARK_HVM_EPTSW_LARGE_BYTES - 1ULL);
}

/* 把地址向下取整到包含它的 4KiB 页。 */
static __inline unsigned long long
KswordArkHvmEptSwPageBase(
    unsigned long long GuestPhysical
    )
{
    return GuestPhysical & ~(KSWORD_ARK_HVM_EPTSW_PAGE_BYTES - 1ULL);
}

/*
 * 计算一张表里某一格的物理地址。
 *
 * 表基址要掩：调用方拿到的往往是一个带字段位的**条目值**而不是干净的地址，
 * 不掩就把字段位加进了地址。索引越界要拒绝而不是回绕：512 号格子落在下一页
 * 的第 0 格上，那一页可能是另一张表，写下去不会报错。返回 0 表示拒绝——
 * 一张 EPT 表永远不会坐落在物理地址 0。
 *
 * **掩码必须是 PHYSICAL_MASK（bits 51:12），不是 ~(PAGE_BYTES - 1)。**
 * 上一版用的是后者，它只清 bits 11:0，把 bit 63 与 62:52 原样留在返回值里。
 * 而本文件用一整段解释「驱动构造的每一个叶项都带 bit 63 的 suppress-#VE」
 * ——也就是说，按文档说的那样把一个原始条目值传进来，返回的「物理地址」
 * 会带着 bit 63：实测 (0x8000000023456007, 3) 返回 0x8000000023456018 而不是
 * 0x0000000023456018。驱动拿这个数去写 EPT 表，写的是一个天文数字的物理地址，
 * 而在 x64 上那要么是一次不可预测的写、要么是一次 MMU 拒绝，两者都离现场很远。
 * 同族的 KswordArkHvmEptTablePointer / KswordArkHvmEptRebaseEntry 用的一直是
 * PHYSICAL_MASK，这里现在与它们一致。
 */
static __inline unsigned long long
KswordArkHvmEptSwEntryAddress(
    unsigned long long TablePhysical,
    unsigned long EntryIndex
    )
{
    /* 拒绝越界索引，不做回绕。 */
    if (EntryIndex >= KSWORD_ARK_HVM_EPTSW_TABLE_ENTRIES) {
        return 0ULL;
    }
    /* 只取页帧域，字段位（含 bit 63）一律不带进地址。 */
    return (TablePhysical & KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) +
        ((unsigned long long)EntryIndex * KSWORD_ARK_HVM_EPTSW_ENTRY_BYTES);
}

/* ------------------------------------------------------------------ */
/* 层次集合的规模与页开销                                               */
/* ------------------------------------------------------------------ */

/*
 * 一套次层次的固定页数：私有根 + 私有 PDPT + 私有 PD + 私有叶表。
 *
 * 深度与叶的位置无关：一个叶只落在一个 PML4 槽、一个 GiB 窗口里，路径之外的
 * 每一张表继续与基座共享。所以是常数四，不是「按叶分布计算」。
 */
#define KSWORD_ARK_HVM_EPTSW_PATH_PAGES 4ULL

/* 可翻转叶的上限定义在文件上方的「协议镜像常量」一节，因为它在这一节之前
 * 就已经被 KswordArkHvmEptSwPreEntryInvalidationCount 用到了。 */

/*
 * 基座套数。
 *
 * 这是整套方案经济性的开关，也是最容易被无声改错的一处：运行期不写任何 EPT 表
 * 之后，次层次可以被所有处理器共享，于是基座套数是 1，总页数与处理器数**完全
 * 无关**。谁要是顺手把它改成按核计费，功能一切正常，只是 256 核机器上要 32 页
 * 变成 8192 页——没有任何症状，只有预算判据在大机器上开始拒绝启动。
 *
 * 只有与「每处理器私有基座」复合时才按核计费：那时每个处理器的次层次必须从它
 * 自己的私有基座派生，否则切过去就丢掉了私有路径。
 */
static __inline unsigned long
KswordArkHvmEptSwBaseCount(
    int UsePrivateBase,
    unsigned long ProcessorCount
    )
{
    /* 复合模式下每个处理器一套基座。 */
    if (UsePrivateBase) {
        return ProcessorCount;
    }
    /* 共享基座模式下只有一套，与处理器数无关。 */
    return 1UL;
}

/*
 * 计算全部次层次占用的页数。
 *
 * 算少了就会写出块尾——在一个随机的、离现场很远的时刻崩；算多了只是浪费。
 * 叶数越界与基座数为零都返回 0，让调用方在**一页都还没分配**的时候拒绝。
 */
static __inline unsigned long long
KswordArkHvmEptSwSecondaryPageCost(
    unsigned long BaseCount,
    unsigned long LeafCount
    )
{
    /* 没有基座就没有可以派生的次层次。 */
    if (BaseCount == 0UL) {
        return 0ULL;
    }
    /* 叶数超过协议上限时拒绝，顺便挡住乘法溢出。 */
    if (LeafCount == 0UL || LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES) {
        return 0ULL;
    }
    /* 每套基座下每叶一套次层次，每套四页。 */
    return (unsigned long long)BaseCount * (unsigned long long)LeafCount *
        KSWORD_ARK_HVM_EPTSW_PATH_PAGES;
}

/*
 * 一套基座下的层次总数：基座自己加上每叶一套。
 * 这个数就是 EPTP 台账的长度；台账短一格，运行期就会按索引读出界。
 */
static __inline unsigned long
KswordArkHvmEptSwHierarchyCount(
    unsigned long LeafCount
    )
{
    /* 一叶都没有时这套机制无事可做，不构造任何层次。 */
    if (LeafCount == 0UL || LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES) {
        return 0UL;
    }
    /* 索引 0 是基座，索引 1..L 各对应一叶。 */
    return LeafCount + 1UL;
}

/* 报告一个已算出的页开销是否放得进为它保留的预算。 */
static __inline int
KswordArkHvmEptSwFitsBudget(
    unsigned long long PageCost,
    unsigned long long Cap
    )
{
    return (PageCost != 0ULL && PageCost <= Cap) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* 层次索引与叶号的编码                                                 */
/* ------------------------------------------------------------------ */

/* 基座的索引。 */
#define KSWORD_ARK_HVM_EPTSW_INDEX_BASE 0UL

/* 报告一个层次索引是不是基座。 */
static __inline int
KswordArkHvmEptSwIndexIsBase(
    unsigned long Index
    )
{
    return Index == KSWORD_ARK_HVM_EPTSW_INDEX_BASE ? 1 : 0;
}

/*
 * 叶号到层次索引。**必须整体加一。**
 *
 * 令索引等于叶号会让「第 0 叶正取次值」与「什么都没放宽」变成同一个值，于是第
 * 0 叶切进去就再也切不回来——那一页从此永久停在影子上，而没有任何报错：视图
 * 还在、驱动还在跑、自检全绿，只是被保护的那一页对所有读者永远是影子内容。
 *
 * 返回非零表示成功。
 */
static __inline int
KswordArkHvmEptSwIndexFromLeaf(
    unsigned long LeafIndex,
    unsigned long LeafCount,
    unsigned long* Index
    )
{
    /* 没有输出位置就没有可以编码的东西。 */
    if (Index == 0) {
        return 0;
    }
    /* 拒绝越界的叶号与越界的叶数。 */
    if (LeafCount == 0UL || LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES ||
        LeafIndex >= LeafCount) {
        return 0;
    }
    /* 索引 0 留给基座，所以叶号整体后移一格。 */
    *Index = LeafIndex + 1UL;
    return 1;
}

/*
 * 层次索引到叶号。反解差一格，恢复判据就会作用在一个无关的页上：
 * 那一页被收回主值（它本来就是主值，无事发生），而真正被放宽的那一页留在次值上。
 *
 * 基座没有对应的叶，所以对索引 0 返回失败而不是某个哨兵值——哨兵值会被当成
 * 一个真的叶号用下去。
 */
static __inline int
KswordArkHvmEptSwLeafFromIndex(
    unsigned long Index,
    unsigned long LeafCount,
    unsigned long* LeafIndex
    )
{
    /* 没有输出位置就没有可以解码的东西。 */
    if (LeafIndex == 0) {
        return 0;
    }
    /* 拒绝越界的叶数。 */
    if (LeafCount == 0UL || LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES) {
        return 0;
    }
    /* 基座不对应任何叶。 */
    if (KswordArkHvmEptSwIndexIsBase(Index)) {
        return 0;
    }
    /* 拒绝超过层次集合规模的索引。 */
    if (Index > LeafCount) {
        return 0;
    }
    /* 与编码严格互逆。 */
    *LeafIndex = Index - 1UL;
    return 1;
}

/* ------------------------------------------------------------------ */
/* 访问类型与视图种类                                                   */
/* ------------------------------------------------------------------ */

/*
 * 协议访问位的本地镜像，必须与 KswordArkHvmIoctl.h:336-338 的
 * KSWORD_ARK_HVM_EPT_ACCESS_* 逐位相同。不直接包含那个头，是因为它需要
 * CTL_CODE 与 Windows 类型，宿主机测试就进不来了。
 *
 * 「镜像」这件事有两道钉子，缺一不可：
 *   1. 本文件与单测里的**数值**断言（就在下面），保证本地这一份不被重新编号；
 *   2. 同时包含两个头的驱动侧 .c 里的 C_ASSERT，保证对面那一份不被重新编号。
 *
 * 第 2 条是集成 owner 必须落地的，本头文件做不到。要写的正好这五行：
 *   C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_READ    == KSWORD_ARK_HVM_EPT_ACCESS_READ);
 *   C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE   == KSWORD_ARK_HVM_EPT_ACCESS_WRITE);
 *   C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE == KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE);
 *   C_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_CLOAK     == KSWORD_ARK_HVM_VIEW_KIND_CLOAK);
 *   C_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_HOOK      == KSWORD_ARK_HVM_VIEW_KIND_HOOK);
 *
 * 上一版这里写着「三条显式 if 分支的存在就是为了让任一侧重新编号被单测发现」。
 * 那句话是错的，而且被实测推翻：把 READ 与 WRITE 对调、把 CLOAK 与 HOOK 对调，
 * 原来的 344 条断言全过（评审的变异 M27 与 M26），因为所有断言都只用符号，
 * 而 R 与 W 在两种视图里恰好对称。显式分支只保证「不是直接赋值」，
 * 钉死数值的是断言，不是分支。
 */
#define KSWORD_ARK_HVM_EPTSW_ACCESS_READ    0x00000001UL
#define KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE   0x00000002UL
#define KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE 0x00000004UL
/* 三种已定义访问位的并集，用来识别「协议里还没有的访问类别」。 */
#define KSWORD_ARK_HVM_EPTSW_ACCESS_MASK    0x00000007UL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_READ == 1UL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE == 2UL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE == 4UL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(
    KSWORD_ARK_HVM_EPTSW_ACCESS_MASK ==
    (KSWORD_ARK_HVM_EPTSW_ACCESS_READ | KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE |
     KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE));
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_MASK == 7UL);

/*
 * 协议视图种类的本地镜像，取值与 KswordArkHvmIoctl.h:754/756 的
 * KSWORD_ARK_HVM_VIEW_KIND_* 相同。对调这两个数没有任何症状：
 * IOCTL 送进来的 kind = 1（CLOAK）会被服务成 HOOK 的权限对，于是主值变成
 * rw- 的真帧——那一页对所有读者永远可读，「隐藏」变成了「暴露」，
 * 而 hook 与视图列表看起来一切正常。
 */
#define KSWORD_ARK_HVM_EPTSW_KIND_CLOAK 1UL
#define KSWORD_ARK_HVM_EPTSW_KIND_HOOK  2UL
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_CLOAK == 1UL);
KSWORD_ARK_HVM_EPTSW_STATIC_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_HOOK == 2UL);

/*
 * 把协议访问掩码翻译成叶项里的权限位。
 *
 * 两组常量目前数值相同（1/2/4），而这正是危险所在：写成直接赋值不会有任何报错，
 * 直到某一天有一侧被重新编号，翻转就按错误的权限做决定——表现是某种访问永远
 * 拿不到它需要的那套层次（环），或者拿到了不该拿的那套（信息泄露）。
 *
 * 三次显式判断只做了一半的事：它保证这里不是「把协议掩码原样当叶权限用」，
 * 但它**抓不到重新编号**——两侧同时被重新编号时，三条分支照样一一对应。
 * 真正钉死的是上面那五条数值断言，以及单测里用**字面量**两侧对照的那几条
 * （s.expect(AccessToLeafBits(0x1) == 0x1) 之类）。不要把这条注释再写成
 * 「分支的存在就是为了让单测发现重新编号」——上一版就是那么写的，实测不成立。
 */
static __inline unsigned long long
KswordArkHvmEptSwAccessToLeafBits(
    unsigned long Access
    )
{
    unsigned long long bits = 0ULL;

    /* 取回数据读对应的叶权限位。 */
    if ((Access & KSWORD_ARK_HVM_EPTSW_ACCESS_READ) != 0UL) {
        bits |= KSWORD_ARK_HVM_EPTSW_READ;
    }
    /* 取回数据写对应的叶权限位。 */
    if ((Access & KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE) != 0UL) {
        bits |= KSWORD_ARK_HVM_EPTSW_WRITE;
    }
    /* 取回取指对应的叶权限位。 */
    if ((Access & KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE) != 0UL) {
        bits |= KSWORD_ARK_HVM_EPTSW_EXECUTE;
    }
    /* 返回这次访问需要的完整权限。 */
    return bits;
}

/*
 * 判断一组叶权限是否授予这次访问需要的**全部**权限位。
 *
 * 空访问掩码必须返回「未授予」。裸的 (Entry & needed) == needed 在 needed 为零
 * 时会把任何叶判成「已授予」，于是那次违规被当成「当前层次够用」而放行，一次
 * VMRESUME 之后再次违规——一个不报错的死循环。
 */
static __inline int
KswordArkHvmEptSwGrants(
    unsigned long long LeafPermissions,
    unsigned long Access
    )
{
    const unsigned long long needed = KswordArkHvmEptSwAccessToLeafBits(Access);

    /* 空需求永远不算被满足。 */
    if (needed == 0ULL) {
        return 0;
    }
    /* 必须**全部**位都被授予，任何一位缺失都会再次违规。 */
    return ((LeafPermissions & KSWORD_ARK_HVM_EPTSW_PERM_MASK) & needed) ==
        needed ? 1 : 0;
}

/*
 * 由视图种类给出主/次值各自的权限。
 *
 * CLOAK：执行走真页，读写走影子。主值 --x（真帧），次值 rw-（影子帧）。
 * HOOK： 读写走真页，执行走影子。主值 rw-（真帧），次值 --x（影子帧）。
 *
 * **两种种类在这套机制下都必须有 execute-only。** 今天的 MTF 路径在缺这项能力
 * 时把 HOOK 的次值退化成 r-x，论证是「窗口只有一条指令，读者必须正好落进去」。
 * EPTP 切换没有 MTF：次层次一直生效到反向访问为止，期间这个处理器上跑的任何
 * 代码（包括中断处理程序）读那一页都读到影子。r-x 的次值等于把补丁字节公开，
 * 而这件事没有任何症状——hook 照常工作，只是它不再隐蔽。所以这里对两种种类
 * 一律要求 execute-only，由调用方决定是拒绝还是降级回 MTF 路径。
 *
 * 返回非零表示这一对可用。
 */
static __inline int
KswordArkHvmEptSwKindPermissions(
    unsigned long Kind,
    int ExecuteOnlySupported,
    unsigned long long* PrimaryPermissions,
    unsigned long long* SecondaryPermissions
    )
{
    /* 没有输出位置就没有可以给出的一对。 */
    if (PrimaryPermissions == 0 || SecondaryPermissions == 0) {
        return 0;
    }
    /* 两种种类各有一个 X 不带 R 的值，缺 execute-only 就无法表示。 */
    if (!ExecuteOnlySupported) {
        return 0;
    }
    if (Kind == KSWORD_ARK_HVM_EPTSW_KIND_CLOAK) {
        /* 主值：执行真页。 */
        *PrimaryPermissions = KSWORD_ARK_HVM_EPTSW_EXECUTE;
        /* 次值：读写影子。 */
        *SecondaryPermissions =
            KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE;
        return 1;
    }
    if (Kind == KSWORD_ARK_HVM_EPTSW_KIND_HOOK) {
        /* 主值：读写真页。 */
        *PrimaryPermissions =
            KSWORD_ARK_HVM_EPTSW_READ | KSWORD_ARK_HVM_EPTSW_WRITE;
        /* 次值：执行影子。 */
        *SecondaryPermissions = KSWORD_ARK_HVM_EPTSW_EXECUTE;
        return 1;
    }
    /* 未知种类不给出任何一对。 */
    return 0;
}

/*
 * 判断主/次值的并集是否覆盖读、写、执行三种访问。
 *
 * 某种访问如果两侧都不授予，运行期永远找不到可切的目标，只能 fail-closed
 * 退虚拟化——而这件事只有到了目标机器上、只有当 guest 真的做了那种访问时
 * 才暴露：安装时一切正常，跑几小时后突然退虚拟化。这条判据把它提前到安装时。
 */
static __inline int
KswordArkHvmEptSwPairIsTotal(
    unsigned long long PrimaryPermissions,
    unsigned long long SecondaryPermissions
    )
{
    return ((PrimaryPermissions | SecondaryPermissions) &
        KSWORD_ARK_HVM_EPTSW_PERM_MASK) == KSWORD_ARK_HVM_EPTSW_PERM_MASK
        ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* 切换决策状态机                                                       */
/* ------------------------------------------------------------------ */

/*
 * 结局只有两种。
 *
 * 没有第三种「无需切换、直接恢复」：一次 EPT violation 如果不需要换层次，
 * 就意味着当前层次已经授予了这次访问，而那与「发生了违规」矛盾。把它当成
 * 「resume 就好」不会报错，会得到一个不前进的环。所以那种输入在这里是 REFUSE。
 */
#define KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE 0UL
#define KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH 1UL

/* 拒绝原因。每一条都必须被上层接到 fail-closed 汇流，不能被忽略。 */
#define KSWORD_ARK_HVM_EPTSW_REASON_NONE            0UL
/* 叶号 / 叶数 / 当前索引越界。 */
#define KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS          1UL
/* 访问掩码为空：没有任何层次能「满足」一个空需求。 */
#define KSWORD_ARK_HVM_EPTSW_REASON_EMPTY_ACCESS    2UL
/* 访问掩码里有协议尚未定义的位，按读处理会挑错层次。 */
#define KSWORD_ARK_HVM_EPTSW_REASON_UNKNOWN_ACCESS  3UL
/* 视图种类未知。 */
#define KSWORD_ARK_HVM_EPTSW_REASON_KIND            4UL
/* 缺 execute-only：这套机制无法在不泄露影子的前提下表示这一对。 */
#define KSWORD_ARK_HVM_EPTSW_REASON_NO_EXECUTE_ONLY 5UL
/* 当前层次已经授予这次访问却仍然违规：认知与硬件不一致。 */
#define KSWORD_ARK_HVM_EPTSW_REASON_SPURIOUS        6UL
/* 两侧都不授予：这次访问在任何单套层次里都不成立。 */
#define KSWORD_ARK_HVM_EPTSW_REASON_UNREPRESENTABLE 7UL
/* EPTP 台账长度不对，或槽位没填。 */
#define KSWORD_ARK_HVM_EPTSW_REASON_LEDGER          8UL
/* 源与目标共享 EP4TA：切过去等于没切。 */
#define KSWORD_ARK_HVM_EPTSW_REASON_ALIASED         9UL

/* 一次切换决策的完整结果。 */
typedef struct _KSWORD_ARK_HVM_EPTSW_TRANSITION
{
    /* 要写进 VMCS EPT_POINTER 字段的值；REFUSE 时为零。 */
    unsigned long long TargetEptp;
    /* OUTCOME_REFUSE 或 OUTCOME_SWITCH。 */
    unsigned long Outcome;
    /* 切换之后这个处理器所在的层次索引；REFUSE 时为零。 */
    unsigned long NextIndex;
    /* REFUSE 时的具体原因。 */
    unsigned long Reason;
    /*
     * 这里曾经有一个 Invalidate 字段，文档说「非零表示这次切换还需要显式
     * INVEPT」。它被删掉了，因为它**永远不可能非零**：唯一会置位的条件
     * （源与目标共享 EP4TA）被 KswordArkHvmEptSwPlanSwitch 转成了
     * REASON_ALIASED 的 REFUSE。留着它的坏处是实打实的——单测里那条
     * 「每组断言检查 Invalidate 标志」按构造恒真，读起来像一条覆盖，
     * 实际上一个字节的信息都没有，任何仍然拒绝的别名逻辑变异都能从它下面走过去。
     * 需要显式 INVEPT 的场景只有一处，那就是进入 guest 之前的批量失效，
     * 由 KswordArkHvmEptSwPreEntryInvalidationCount 计数，不走这个结构。
     */
} KSWORD_ARK_HVM_EPTSW_TRANSITION;

/*
 * 把结果置成一次带原因的拒绝。
 *
 * 空指针必须在这里挡住而不是解引用：这是一个公开的 static __inline，
 * 驱动侧的 .c 会直接调它来构造一次拒绝，而它跑在 DISPATCH_LEVEL 的
 * VM-exit 处理路径上——那里的一次空解引用就是一次蓝屏，而且现场离
 * 真正的错误（谁没填 Transition）很远。文件里其它每一个取指针的函数
 * 都检查了，这一个漏了。
 */
static __inline unsigned long
KswordArkHvmEptSwRefuse(
    KSWORD_ARK_HVM_EPTSW_TRANSITION* Transition,
    unsigned long Reason
    )
{
    /* 没有输出位置时仍然报告拒绝，绝不解引用。 */
    if (Transition == 0) {
        return KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
    }
    Transition->TargetEptp = 0ULL;
    Transition->Outcome = KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
    Transition->NextIndex = 0UL;
    Transition->Reason = Reason;
    return KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
}

/*
 * 由（当前层次索引 × 违规叶 × 访问类型 × 视图种类）决定切到哪套层次。
 *
 * 状态就是一个索引：0 = 基座（每一叶都取主值），k = 只有第 k-1 号叶取次值。
 * 于是「这一叶此刻是主值还是次值」只有一个判据：当前索引等不等于这一叶的索引。
 * 注意「在别的叶的层次里」与「在基座里」对本叶而言是同一种状态——本叶都取主值
 * ——但目标不同：前者切到本叶的层次会顺带把那一叶收回主值，这正是「任何时刻
 * 至多一叶被放宽」这条不变式的来源。
 *
 * 每一条 REFUSE 都对应一种「不拒绝就会静默死锁或静默泄露」的输入，理由见各自
 * 的原因码注释。返回值同时也写进 Transition->Outcome。
 */
static __inline unsigned long
KswordArkHvmEptSwDecide(
    unsigned long ActiveIndex,
    unsigned long FaultLeafIndex,
    unsigned long LeafCount,
    unsigned long Access,
    unsigned long Kind,
    int ExecuteOnlySupported,
    KSWORD_ARK_HVM_EPTSW_TRANSITION* Transition
    )
{
    unsigned long long primary = 0ULL;
    unsigned long long secondary = 0ULL;
    unsigned long faultIndex = 0UL;

    /* 没有输出位置就没有可以做的决定。 */
    if (Transition == 0) {
        return KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
    }
    /* 先置成拒绝，任何提前返回都不会留下一个看着像成功的结果。 */
    (void)KswordArkHvmEptSwRefuse(
        Transition, KSWORD_ARK_HVM_EPTSW_REASON_NONE);
    /* 叶数必须落在协议上限内。 */
    if (LeafCount == 0UL || LeafCount > KSWORD_ARK_HVM_EPTSW_MAX_LEAVES) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS);
    }
    /* 违规叶必须是集合里的一叶。 */
    if (FaultLeafIndex >= LeafCount) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS);
    }
    /* 当前索引必须落在 [0, LeafCount] 内，否则台账与 VMCS 已经不一致。 */
    if (ActiveIndex > LeafCount) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_BOUNDS);
    }
    /*
     * 协议之外的访问位必须显式拒绝。把未知位当零处理不会报错，但会用「读」的
     * 判据去服务一种我们还不理解的访问，于是挑中错误的层次。
     */
    if ((Access & ~KSWORD_ARK_HVM_EPTSW_ACCESS_MASK) != 0UL) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_UNKNOWN_ACCESS);
    }
    /* 空访问掩码没有可满足的目标。 */
    if (KswordArkHvmEptSwAccessToLeafBits(Access) == 0ULL) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_EMPTY_ACCESS);
    }
    /* 缺 execute-only 时这套机制无法表示任何一种视图。 */
    if (!ExecuteOnlySupported) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_NO_EXECUTE_ONLY);
    }
    /* 取出这种视图的主/次权限。 */
    if (!KswordArkHvmEptSwKindPermissions(
            Kind, ExecuteOnlySupported, &primary, &secondary)) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_KIND);
    }
    /* 这一叶的次层次索引。 */
    faultIndex = FaultLeafIndex + 1UL;
    if (ActiveIndex == faultIndex) {
        /* 这一叶此刻取次值。 */
        if (KswordArkHvmEptSwGrants(secondary, Access)) {
            /* 次值已授予却仍然违规：我们对硬件状态的认知是错的。 */
            return KswordArkHvmEptSwRefuse(
                Transition, KSWORD_ARK_HVM_EPTSW_REASON_SPURIOUS);
        }
        if (!KswordArkHvmEptSwGrants(primary, Access)) {
            /* 回基座还是会违规，那是一个环。 */
            return KswordArkHvmEptSwRefuse(
                Transition, KSWORD_ARK_HVM_EPTSW_REASON_UNREPRESENTABLE);
        }
        /* 反向访问：回基座，这一叶收回主值。 */
        Transition->Outcome = KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
        Transition->NextIndex = KSWORD_ARK_HVM_EPTSW_INDEX_BASE;
        Transition->Reason = KSWORD_ARK_HVM_EPTSW_REASON_NONE;
        return KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
    }
    /* 这一叶此刻取主值，无论我们在基座还是在别的叶的层次里。 */
    if (KswordArkHvmEptSwGrants(primary, Access)) {
        /* 主值已授予却仍然违规：我们对硬件状态的认知是错的。 */
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_SPURIOUS);
    }
    if (!KswordArkHvmEptSwGrants(secondary, Access)) {
        /* 两侧都不授予：这次访问在任何单套层次里都不可表示。 */
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_UNREPRESENTABLE);
    }
    /* 切到这一叶的层次；原来被放宽的那一叶由此自动收回主值。 */
    Transition->Outcome = KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
    Transition->NextIndex = faultIndex;
    Transition->Reason = KSWORD_ARK_HVM_EPTSW_REASON_NONE;
    return KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
}

/*
 * 在决策之上补齐要真正写进 VMCS 的那个值。
 *
 * 分成两步而不是一步，是因为决策只依赖索引与权限，可以被穷举；而台账查表依赖
 * 一块运行期内存，只能被抽样。两者混在一起，穷举测试就得连带构造 EPTP 表，
 * 而那正是最容易在测试里「照着实现写」的地方。
 *
 * 这里额外挡两类构造错误，它们的共同点是「运行期完全没有症状，只是不前进」：
 *   - 台账长度不等于 1 + 叶数：按索引取值会读出界，取到的可能是一个看着合法的
 *     旧指针；
 *   - 源与目标共享 EP4TA：切换不改变缓存标签，硬件上是空操作。
 *
 * **调用前置条件（不是建议）：** 本函数返回 OUTCOME_SWITCH 之后、真正
 * VMWRITE EPT_POINTER 之前，调用方必须先让本处理器的前进性台账承认这次切换，
 * 即 KswordArkHvmEptSwProgressAdmit(&progress, rip, gpa, transition.NextIndex)
 * 返回非零；返回零就走 fail-closed，与「翻转失败」同一条路径。
 *
 * 为什么这一条不能并进本函数：本函数是纯函数，看到的只有这一次违规；
 * 而「一条指令同时需要两个叶的次值」（取指落在 HOOK 页、操作数读落在 CLOAK 页）
 * 这种组合的每一半单独看都完全可以被服务，本函数会老老实实地返回 SWITCH，
 * 一次又一次，RIP 一步都不动。那不是本函数判错了，是那个信息根本不在参数里。
 * 少了台账这一步，机器的表现是静默死锁：没有蓝屏、没有事件、没有日志。
 */
static __inline unsigned long
KswordArkHvmEptSwPlanSwitch(
    const unsigned long long* EptpTable,
    unsigned long EptpCount,
    unsigned long ActiveIndex,
    unsigned long FaultLeafIndex,
    unsigned long LeafCount,
    unsigned long Access,
    unsigned long Kind,
    int ExecuteOnlySupported,
    KSWORD_ARK_HVM_EPTSW_TRANSITION* Transition
    )
{
    unsigned long long target = 0ULL;
    unsigned long long source = 0ULL;

    /* 没有输出位置就没有可以做的计划。 */
    if (Transition == 0) {
        return KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
    }
    /* 先做纯索引决策，它自己会置好拒绝态。 */
    if (KswordArkHvmEptSwDecide(
            ActiveIndex,
            FaultLeafIndex,
            LeafCount,
            Access,
            Kind,
            ExecuteOnlySupported,
            Transition) != KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH) {
        /* 原样把拒绝原因交给调用方。 */
        return KSWORD_ARK_HVM_EPTSW_OUTCOME_REFUSE;
    }
    /* 台账必须正好是「基座 + 每叶一套」。 */
    if (EptpTable == 0 ||
        EptpCount != KswordArkHvmEptSwHierarchyCount(LeafCount)) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_LEDGER);
    }
    /* 索引已由决策校验过落在 [0, LeafCount] 内。 */
    source = EptpTable[ActiveIndex];
    target = EptpTable[Transition->NextIndex];
    /* 两个槽都必须被真正填过。 */
    if (KswordArkHvmEptSwEptpRoot(source) == 0ULL ||
        KswordArkHvmEptSwEptpRoot(target) == 0ULL) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_LEDGER);
    }
    /* 共享标签的两套层次之间切换是空操作。 */
    if (KswordArkHvmEptSwSwitchNeedsInvalidation(source, target)) {
        return KswordArkHvmEptSwRefuse(
            Transition, KSWORD_ARK_HVM_EPTSW_REASON_ALIASED);
    }
    /* 交出要写进 VMCS EPT_POINTER 的确切值。 */
    Transition->TargetEptp = target;
    return KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH;
}

/* ------------------------------------------------------------------ */
/* 前进性台账：Decide 看不见的那一半不可表示                            */
/* ------------------------------------------------------------------ */

/*
 * 这一节是从已删除的 shared/driver/KswordArkHvmEptpSwitch.h 合并过来的，那是同
 * 一设计的另一次实现（前缀 KswordArkHvmEptp*）。两份里只有这一节是本文件原来**没有**的
 * 判据，其余部分本文件都是超集，所以只把这一节搬过来，并按本文件的命名与上限
 * 重写。合并的理由不是「代码复用」，是「同一个判断只能有一个真值来源」：
 * 两个头各留一份环检测，将来必然一边改一边不改。
 *
 * 这一节解决的是文件开头「不可表示的组合」里的**跨叶**那一半：
 *
 *   一条指令同时需要两个叶的次值——取指落在 HOOK 页（要切到 HOOK 那一叶的
 *   层次），同一条指令的操作数读落在 CLOAK 页（要切到 CLOAK 那一叶的层次）。
 *   每套层次只放宽一叶，所以没有任何单套层次能同时服务这两半。
 *
 * KswordArkHvmEptSwDecide 对此**无能为力，而且不是它写错了**：它一次只收到一次
 * 违规，那一次违规的每一半单独看都可服务，于是它诚实地返回
 * SWITCH k -> SWITCH j -> SWITCH k -> ...，RIP 一步不动，每一次退出单独看
 * 都完全正常。这就是本文件反复提到的整机静默死锁：没有蓝屏、没有事件、
 * 没有日志，因为从来没有发生过任何一次「错误」。
 *
 * 判据只能是跨退出的，因此需要每 VCPU 一份的历史。这不违背「不给同一个判断
 * 制造第二个真值来源」——它判的是另一件事：Decide 判「这一次违规能不能被一次
 * 切换解决」，台账判「这一串切换有没有在前进」。
 */

/*
 * 同一个 RIP 上允许连续发生多少次切换。
 *
 * 一条指令合法地连续违规不止一次：取指一次、每个内存操作数各一次。四是这条
 * 路径上能想到的最大值（取指 + 三个访问），八留出一倍余量。超过它一定是环。
 * 这个上限只是长环的兜底；周期 1 与周期 2 的环由下面的精确判据抓。
 *
 * 调大它不会更安全：它只决定「多久之后放弃」，而放弃的代价是一次 fail-closed
 * 退虚拟化，远小于一台静默死锁的机器。
 */
#define KSWORD_ARK_HVM_EPTSW_MAX_SAME_RIP_SWITCHES 8UL

/*
 * 每处理器一份的前进性台账。
 *
 * 只记两代历史，因为要抓的两类环都在两代之内：
 *   周期 1：切过去之后同一条指令、同一页、同一目标又来一次——切换没有效果。
 *   周期 2：A 需要 X 的次值、B 需要 Y 的次值，而一条指令同时需要两者，于是
 *           在两套层次之间来回跳。这正是上面那个跨叶组合。
 *
 * 这个结构必须是**每处理器私有**的：两个处理器共用一份，A 的 RIP 会把 B 的
 * 计数清掉，于是 B 的环永远数不满——判据在多核上静默失效，而单核测试全绿。
 */
typedef struct _KSWORD_ARK_HVM_EPTSW_PROGRESS
{
    /* 上一次切换时的 guest RIP。 */
    unsigned long long LastRip;
    /* 上一次切换时的违规客户物理地址。 */
    unsigned long long LastGuestPhysical;
    /* 上上次切换时的 guest RIP。 */
    unsigned long long PreviousRip;
    /* 上上次切换时的违规客户物理地址。 */
    unsigned long long PreviousGuestPhysical;
    /* 上一次切换的目标层次索引。 */
    unsigned long LastTarget;
    /* 上上次切换的目标层次索引。 */
    unsigned long PreviousTarget;
    /* 同一个 RIP 上已经连续切换了多少次。 */
    unsigned long SameRipSwitches;
    /* 保持 64 位成员自然对齐。 */
    unsigned long Reserved0;
} KSWORD_ARK_HVM_EPTSW_PROGRESS;

/*
 * 把台账清成「还没有切换过」。
 *
 * 进入驻留、每次 VMCS 重配、以及每次视图集合变化之后都要调用：不清的话，
 * 上一批视图留下的 (RIP, 页, 目标) 会把新一批的第一次合法切换判成环，
 * 表现是刚装上视图就 fail-closed 退虚拟化。
 */
static __inline void
KswordArkHvmEptSwProgressReset(
    KSWORD_ARK_HVM_EPTSW_PROGRESS* Progress
    )
{
    /* 忽略空台账而不是解引用它。 */
    if (Progress == 0) {
        return;
    }
    Progress->LastRip = 0ULL;
    Progress->LastGuestPhysical = 0ULL;
    Progress->PreviousRip = 0ULL;
    Progress->PreviousGuestPhysical = 0ULL;
    Progress->LastTarget = KSWORD_ARK_HVM_EPTSW_INDEX_BASE;
    Progress->PreviousTarget = KSWORD_ARK_HVM_EPTSW_INDEX_BASE;
    Progress->SameRipSwitches = 0UL;
    Progress->Reserved0 = 0UL;
}

/*
 * 判断这次切换是否在前进，顺带把它记进台账。
 *
 * 返回非零表示可以切；返回零表示这次切换不会带来前进，调用方必须 fail-closed
 * （与今天「翻转失败」走的是同一条路径），而不是切过去等着再回来。
 *
 * 被拒绝时台账**不更新**：这一次退出的结局是退虚拟化，台账没有下一次可服务，
 * 而保留现场对事后判读更有用。
 *
 * 注意 RIP 不同就重新计数，这一点是有意的：RIP 变了说明上一条指令退休了，
 * 也就是上一次切换确实起了作用。反过来，RIP 相同并不必然是环——同一条指令的
 * 取指与操作数可以各要一次切换——所以只有「同一 RIP 且 (页, 目标) 与前两代
 * 之一完全相同」才判定为环。把这一条写成「同一 RIP 就拒绝」会让每一条跨两个
 * 视图页的正常指令都退虚拟化；写成「只看目标不看页」会放过周期 2 的环。
 */
static __inline int
KswordArkHvmEptSwProgressAdmit(
    KSWORD_ARK_HVM_EPTSW_PROGRESS* Progress,
    unsigned long long Rip,
    unsigned long long GuestPhysical,
    unsigned long TargetIndex
    )
{
    /* 没有台账就无法证明前进性，按不前进处理。 */
    if (Progress == 0) {
        return 0;
    }
    if (Rip != Progress->LastRip) {
        /* 另一条指令：历史与它无关，从头计数并接受。 */
        Progress->PreviousRip = Progress->LastRip;
        Progress->PreviousGuestPhysical = Progress->LastGuestPhysical;
        Progress->PreviousTarget = Progress->LastTarget;
        Progress->LastRip = Rip;
        Progress->LastGuestPhysical = GuestPhysical;
        Progress->LastTarget = TargetIndex;
        Progress->SameRipSwitches = 1UL;
        return 1;
    }
    /* 周期 1：同一条指令、同一页、同一目标又来一次。 */
    if (GuestPhysical == Progress->LastGuestPhysical &&
        TargetIndex == Progress->LastTarget) {
        return 0;
    }
    /* 周期 2：与上上次完全重合，说明在两套层次之间来回跳。 */
    if (Rip == Progress->PreviousRip &&
        GuestPhysical == Progress->PreviousGuestPhysical &&
        TargetIndex == Progress->PreviousTarget) {
        return 0;
    }
    /* 长环兜底：同一个 RIP 上切得太多次，一定不是正常指令。 */
    if (Progress->SameRipSwitches >=
        KSWORD_ARK_HVM_EPTSW_MAX_SAME_RIP_SWITCHES) {
        return 0;
    }
    /* 记录这一代并接受。 */
    Progress->PreviousRip = Progress->LastRip;
    Progress->PreviousGuestPhysical = Progress->LastGuestPhysical;
    Progress->PreviousTarget = Progress->LastTarget;
    Progress->LastGuestPhysical = GuestPhysical;
    Progress->LastTarget = TargetIndex;
    Progress->SameRipSwitches += 1UL;
    return 1;
}
