#include "HvmCommandCatalog.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "../../shared/driver/KswordArkHvmIoctl.h"

static const HVM_COMMAND_SPEC g_commands[] = {
    { "prepare-svm-general", "准备 AMD 通用嵌套实验", "生命周期", "预分配通用 SVM/NPT 资源；与有界探针配置互斥，尚未完成操作系统验收。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_PREPARE,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED | KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED | KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_SVM, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "resident-svm-general", "启动 AMD 通用嵌套实验", "生命周期", "需要 prepare-svm-general 和逐核自检；暴露 SVM，启用实验性通用退出分派。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED | KSWORD_ARK_HVM_CONTROL_FLAG_FORCE | KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED | KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_SVM, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "prepare-svm-probe", "准备 AMD 嵌套探针", "生命周期", "预分配 AMD 有界嵌套自检资源；不开放内层虚拟机运行。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_PREPARE,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED | KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED | KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "self-test-svm-nested", "AMD 嵌套 VMRUN 自检", "生命周期", "逐核执行虚拟 SVM 寄存器、VMRUN、内层退出反射与原生恢复；需要 prepare-svm-probe。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_SELF_TEST,
      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED | KSWORD_ARK_HVM_CONTROL_FLAG_FORCE | KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED | KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "metrics", "虚拟化测量", "查询与观测", "读取逐核转换时间与资源计数；AMD 另含 SVM 原始退出、NPT 诊断及首故障锁存。", HvmMetrics, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "status", "运行状态", "查询与观测", "读取完整能力、处理器状态与退出计数。", HvmStatus, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "cpuid-view", "CPUID 可见性", "查询与观测", "读取当前进程看到的 Hypervisor 身份；无需加载驱动。", HvmCpuid, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "probe-platform", "平台探针", "查询与观测", "读取 CET、KVA shadow 和平台状态，不进入 VMX。", HvmPlatform, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "selfcheck", "使用前自检", "查询与观测", "只读检查能力、后端和当前状态，报告未满足的条件。", HvmSelfcheck, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "gdt-dump", "GDT 快照", "查询与观测", "读取指定处理器的 GDT。处理器编号为十进制。", HvmGdt, 1, 0UL, 0UL, 1,
      { { "处理器编号（十进制）", HvmDecimal32, "0" } } },
    { "events", "事件记录", "查询与观测", "读取序号大于指定值的事件；默认读取环内现有记录。", HvmEvents, 1, 0UL, 0UL, 2,
      { { "起始事件序号（十进制）", HvmDecimal64, "0" }, { "最多事件数（十进制）", HvmDecimal32, "64" } } },
    { "ept-leaf", "EPT 叶项", "查询与观测", "读取指定物理地址的基础 EPT 翻译链与权限。", HvmEptLeaf, 1, 0UL, 0UL, 1,
      { { "物理地址（十六进制）", HvmHex64, "0" } } },
    { "prepare", "准备资源", "生命周期", "按 VMX/EPT 或 SVM/NPT 后端分配资源，不进入常驻；允许受支持的外层虚拟化环境。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_PREPARE, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "prepare-eptpsw", "准备 EPTP 切换后端", "生命周期", "准备资源并请求 EPTP 切换；之后检查 EPTP_SWITCH_ARMED。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_PREPARE, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPTP_SWITCH, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "prepare-localept", "准备每核私有 EPT", "生命周期", "准备资源并请求每处理器私有 EPT。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_PREPARE, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "self-test", "处理器虚拟化自检", "生命周期", "逐处理器执行后端自检；AMD 必须完成带已知退出标记的 VMRUN 往返。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_SELF_TEST, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "resident", "启动常驻", "生命周期", "准备并通过自检后启动全处理器常驻。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_START_RESIDENT, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "resident-nested", "启动嵌套常驻", "生命周期", "启动常驻并开启嵌套 VMX 指令派发。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_START_RESIDENT, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "resident-nested-hidehv", "启动嵌套常驻并隐藏身份", "生命周期", "启动嵌套常驻，并对来宾用户态 CPUID 隐藏 Hypervisor 身份。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_START_RESIDENT, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX |
      KSWORD_ARK_HVM_CONTROL_FLAG_HIDE_HYPERVISOR, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "resident-nested-fullsnapshot", "嵌套常驻完整快照对照", "生命周期", "保留 CPUID 退出的完整诊断字段读取，作为同一驱动的性能对照。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_START_RESIDENT, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX |
      KSWORD_ARK_HVM_CONTROL_FLAG_HIDE_HYPERVISOR |
      KSWORD_ARK_HVM_CONTROL_FLAG_FULL_EXIT_SNAPSHOT, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "resident-vmreadbench", "VMREAD 开销测量", "生命周期", "每次退出额外执行指定次数的 VMREAD；仅用于测量。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_START_RESIDENT, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_VMREAD_BENCH, 1,
      { { "VMREAD 次数（十进制）", HvmDecimal32, "512" } } },
    { "resident-trace", "启动常驻并记录退出", "生命周期", "普通退出也写入事件环；高频记录会覆盖旧事件。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_START_RESIDENT, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_TRACE_ROUTINE_EXITS, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "soak", "有界常驻自检", "生命周期", "启动常驻，保持指定时间，再停止；时长单位为毫秒。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_SOAK, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED, 1,
      { { "保持时长（毫秒）", HvmDecimal32, "1000" } } },
    { "stop", "停止常驻", "生命周期", "停止全部处理器的常驻；查看返回的活动处理器数。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "teardown", "释放资源", "生命周期", "停止常驻后释放资源与保留的页。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_TEARDOWN, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "reset-fault", "重置故障", "生命周期", "停止常驻后清除可恢复的故障状态。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_RESET_FAULT, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "launch-test-guest", "一次性测试来宾", "嵌套与诊断", "执行一次受控 VMLAUNCH/VMCALL，然后返回。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "validate-nested", "嵌套能力校验", "嵌套与诊断", "校验嵌套 VMX 与 eVMCS 能力；按返回结果判断完成范围。", HvmControl, 0, KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED, KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
      KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX |
      KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "nested-probe", "单核嵌套探针", "嵌套与诊断", "要求嵌套常驻已开启，实测 VMX 指令与 L2 进入和退出。", HvmNestedProbe, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "nested-probe-all", "全核嵌套探针", "嵌套与诊断", "每个处理器并发执行嵌套探针，任一处理器失败即失败。", HvmNestedProbeAll, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "nested-ad", "EPT A/D 拒绝探针", "嵌套与诊断", "实测不支持的 EPT A/D 配置是否正确被拒绝。", HvmNestedAd, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "nested-selfvirt", "单核自虚拟化探针", "嵌套与诊断", "验证 L1 上下文进入 L2、退出反射以及回到 L1。", HvmSelfvirt, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "nested-selfvirt-all", "全核自虚拟化探针", "嵌套与诊断", "每个处理器并发验证自虚拟化与返回。", HvmSelfvirtAll, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "acl-probe", "设备访问位探针", "嵌套与诊断", "使用不同访问权限的设备句柄验证 IOCTL 访问门。", HvmAcl, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "probe-flags", "控制标志拒绝探针", "嵌套与诊断", "发送负向测试请求验证标志检查；会改变测试状态。", HvmFlags, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "probe-xonly", "仅执行权限探针", "嵌套与诊断", "要求常驻停止；安装测试规则、启动、读回、停止并清理。", HvmXonly, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "rule-allowonce", "单次放行规则探针", "嵌套与诊断", "常驻停止时验证规则安装门，并立即移除测试规则。", HvmAllowOnce, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "tlb-probe", "跨核 TLB 探针", "嵌套与诊断", "在指定毫秒数内检查跨处理器翻译失效。", HvmTlb, 0, 0UL, 0UL, 1,
      { { "保持时长（毫秒）", HvmDecimal32, "1000" } } },
    { "tlb-probe-exit", "强制退出 TLB 探针", "嵌套与诊断", "每次读之前执行 CPUID 强制退出，再验证翻译失效。", HvmTlbExit, 0, 0UL, 0UL, 1,
      { { "保持时长（毫秒）", HvmDecimal32, "1000" } } },
    { "view-query", "查询分离视图", "EPT 视图", "读取已安装的 EPT 分离视图。", HvmViewQuery, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "view-probe", "视图安装探针", "EPT 视图", "资源已准备且常驻停止时安装测试视图并立即移除。", HvmViewProbe, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "view-effect", "视图效果验证", "EPT 视图", "要求 EPTP 切换后端和自检；此测试会起停常驻。", HvmViewEffect, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "view-verify", "验证现有视图", "EPT 视图", "分别报告现有视图的结构与实际读回效果。", HvmViewVerify, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "nested-page-query", "查询嵌套页映射", "TinyCore 换页", "读取最近的 EPT12 根、替换页、合成次数和保留状态。", HvmPageQuery, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "nested-page-map", "替换 TinyCore 物理页", "TinyCore 换页", "在线替换一页 4 KiB WB RAM。先查询当前 EPT12 根，并使用专用测试页。", HvmPageMap, 0, 0UL, 0UL, 4,
      { { "EPT12 指针（十六进制）", HvmHex64, NULL }, { "来宾物理页（十六进制，4 KiB 对齐）", HvmPageAddress, NULL }, { "影子页填充值（00–FF）", HvmByte, NULL }, { "VMM 进程 PID（0 自动选择 VMware）", HvmDecimal32, "0" } } },
    { "nested-page-map-region", "替换整段物理区间", "TinyCore 换页", "按 2 MiB 或 1 GiB 粒度替换一整段 WB RAM。整段都从原内容复制，所以刚映射完来宾看到的东西完全不变；随后用 nested-page-stage 改需要改的那几页。粒度只在 EPT12 自己也用同等或更粗的叶子映射该区间时才被接受，否则整条拒绝，不会降级成一页。", HvmPageMapRegion, 0, 0UL, 0UL, 4,
      { { "EPT12 指针（十六进制）", HvmHex64, NULL }, { "来宾物理基址（十六进制，需按粒度对齐）", HvmPageAddress, NULL }, { "叶粒度（12=4 KiB，21=2 MiB，30=1 GiB）", HvmDecimal32, "21" }, { "VMM 进程 PID（0 自动选择 VMware）", HvmDecimal32, "0" } } },
    { "nested-page-map-region-scan", "扫描源表后替换区间", "TinyCore 换页", "按大页粒度替换一整段，但允许源侧是 4 KiB 映射：先把区间内每一个源表项读一遍，权限与内存类型全部一致才放行。代价是租约变弱：后续只对首页路径做即时漂移检测，其余表项被改不会立即发现。不确定就用 nested-page-map-region。", HvmPageMapRegionScan, 0, 0UL, 0UL, 4,
      { { "EPT12 指针（十六进制）", HvmHex64, NULL }, { "来宾物理基址（十六进制，需按粒度对齐）", HvmPageAddress, NULL }, { "叶粒度（12=4 KiB，21=2 MiB，30=1 GiB）", HvmDecimal32, "21" }, { "VMM 进程 PID（0 自动选择 VMware）", HvmDecimal32, "0" } } },
    { "nested-page-stage", "改写区间内一页", "TinyCore 换页", "覆写已发布区间里第 N 个 4 KiB 页的替换内容。索引超出区间会被拒绝而不是截断。这不是原子更新：并发读的来宾可能看到新旧混合的字节。", HvmPageStage, 0, 0UL, 0UL, 2,
      { { "页索引（十进制，0 起）", HvmDecimal32, NULL }, { "填充值（00–FF）", HvmByte, NULL } } },
    { "nested-page-digest", "区间内容摘要", "TinyCore 换页", "读回已发布区间与它克隆自的源区间，各算一个摘要。两者相等说明克隆仍与源一致；stage 一页之后应该只有背衬摘要变。不返回字节本身。", HvmPageDigest, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "nested-page-remove", "撤销 TinyCore 换页", "TinyCore 换页", "取消替换并等待全部处理器失效；retired 非零表示仍有保留页。", HvmPageRemove, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "nested-page-map-test", "换页故障注入", "TinyCore 换页", "仅用于专用测试页：1 分配失败，2 提交前取消，3 提交后回滚，4 提交失效失败。", HvmPageMapTest, 0, 0UL, 0UL, 4,
      { { "EPT12 指针（十六进制）", HvmHex64, NULL }, { "来宾物理页（十六进制，4 KiB 对齐）", HvmPageAddress, NULL }, { "影子页填充值（00–FF）", HvmByte, NULL }, { "故障阶段（1–4）", HvmDecimal32, NULL } } },
    { "nested-page-remove-test", "撤销失效故障注入", "TinyCore 换页", "模拟撤销时失效失败，保留 retired 页；随后用正常撤销命令重试回收。", HvmPageRemoveTest, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "watch-add-va", "监视内核虚拟地址", "内存监视", "对一个内核虚拟地址建立首次访问监视。地址在这一刻翻译成物理页并就此绑定，之后来宾把同一个虚拟地址重映射到别处也不会跟过去。实际监视单位恒为它所在的整个 4 KiB 物理页，不是给出的长度。", HvmWatchAddVa, 0, 0UL, 0UL, 3,
      { { "内核虚拟地址（十六进制）", HvmHex64, NULL }, { "关心的长度（十进制字节，0 表示整页）", HvmDecimal32, "8" }, { "访问掩码（1=读 2=写 4=执行，可相加）", HvmHex32, "2" } } },
    { "watch-add-pa", "监视物理页", "内存监视", "对一个物理地址所在的 4 KiB 页建立首次访问监视。不做翻译，地址按页对齐后使用。", HvmWatchAddPa, 0, 0UL, 0UL, 3,
      { { "物理地址（十六进制）", HvmHex64, NULL }, { "关心的长度（十进制字节，0 表示整页）", HvmDecimal32, "0" }, { "访问掩码（1=读 2=写 4=执行，可相加）", HvmHex32, "2" } } },
    { "watch-list", "列出内存监视", "内存监视", "读回整张监视表：状态、请求与实际访问类型、累计命中次数、最近一次命中的现场与事件序号。", HvmWatchList, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "watch-rearm", "重新武装内存监视", "内存监视", "让一条已命中或已失效的监视再等下一次访问，保留编号与累计命中次数。", HvmWatchRearm, 0, 0UL, 0UL, 1,
      { { "监视编号（十进制）", HvmDecimal32, NULL } } },
    { "watch-remove", "移除内存监视", "内存监视", "撤销一条监视并恢复该页权限。", HvmWatchRemove, 0, 0UL, 0UL, 1,
      { { "监视编号（十进制）", HvmDecimal32, NULL } } },
    { "watch-selftest", "内存监视端到端自检（写）", "内存监视", "在本进程里分配并锁住一页，装一条写监视，写它，再逐项核对命中现场：命中一次、自动解除、原写最终生效、第二次写不再命中、常驻处理器数不变。常驻没在跑或装不上时记 BLOCKED 而不是 FAIL。", HvmWatchSelfTest, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "watch-selftest-read", "内存监视端到端自检（读）", "内存监视", "同写自检的流程，只把被监视的访问换成读。额外核对一条只有读才成立的判据：EPT 不允许可写而不可读，所以「只监视读」在硬件上必然连写也一起监视，实际访问掩码应当比请求的宽。", HvmWatchSelfTestRead, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "watch-selftest-exec", "内存监视端到端自检（执行）", "内存监视", "同写自检的流程，只把被监视的访问换成执行：页按可执行分配并写入一条 ret，然后调用它。拒绝执行不需要 execute-only 能力（读写照留），所以掩码不该被放宽——放宽了就是缺陷而不是环境限制。", HvmWatchSelfTestExec, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "watch-selftest-smp", "内存监视多核同时命中自检", "内存监视", "把每个可用处理器各绑一个线程，同时写同一个被监视页。要问的不是能不能命中，而是多核竞争下会不会各算一次第一次：命中数必须恰好是 1，每个线程的写都要落盘，处理器一个都不能掉出虚拟化。只有一个处理器或有多个处理器组时记 BLOCKED。", HvmWatchSelfTestSmp, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "watch-selftest-remap", "内存监视 VA 重映射自检", "内存监视", "装完监视后把同一个虚拟地址解提交再提交，换到另一个物理页，然后证明监视**没有**跟过去：它仍报告原来那个物理页，写新映射也不产生命中。第一版不跟踪重映射是承诺而不是遗漏。内存管理器还回同一个页框时记 BLOCKED。", HvmWatchSelfTestRemap, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "watch-selftest-evidence", "内存监视事件丢失自检", "内存监视", "开着例行退出追踪起常驻，让事件环快速回绕，把命中那一行挤出去，然后核对：事件查询取不回它了，但监视自己仍报得出命中过与现场。表里同时留一条从没被碰过的监视作对照——只有两者读数不同，「命中但证据丢了」与「从未命中」才算真的区分得开。", HvmWatchSelfTestEvidence, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "watch-selftest-conflict", "内存监视视图冲突自检", "内存监视", "先把一页交给一条 CLOAK 分离视图，再让监视去要同一页。一页只能有一个主人：要证的是装不上、说得清是谁占着、以及原视图一根毫毛没动。第三条最要紧——顺手改了别人叶项的实现，从返回值上看与正确实现完全一样。这台机器装不上分离视图时记 BLOCKED。安装视图要 EPTP 切换后端，而后端是在 prepare 那一刻定的，所以这条自检**会先 teardown**：运行时里现有的监视与视图都会被清掉。", HvmWatchSelfTestConflict, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "watch-selftest-process", "内存监视进程归因自检", "内存监视", "在自己身上装一条写监视、命中它，然后把现场记下的 CR3 送回驱动反查 PID。判据是归出来的必须是本进程——归不出来是一条限制（用户态命中在 KVA Shadow 下本就对不上内核 CR3），归到别的进程上才是假证据。另外拿一个不可能存在的地址空间去问，必须干净地答没有。", HvmWatchSelfTestProcess, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "watch-selftest-restart", "内存监视常驻重启自检", "内存监视", "装一条监视，起常驻再停，核对它被标成已失效；重新起常驻后不会自己变回武装状态，写它也不再命中；显式重新武装之后才回到武装状态，并且换了一个新的武装代次。要防的是旧监视在下一次常驻里悄悄继续改 EPT 叶项，而那时它盯的页可能已经被回收给别人了。", HvmWatchSelfTestRestart, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "msr-log", "记录指定 MSR", "寄存器策略", "添加指定 MSR 的日志策略；编号为十六进制。", HvmMsrLog, 0, 0UL, 0UL, 1,
      { { "MSR 编号（十六进制）", HvmHex32, "10" } } },
    { "msr-clear", "清空 MSR 策略", "寄存器策略", "清空已安装的 MSR 策略。", HvmMsrClear, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "cr-track-cr3-on", "开启 CR3 追踪", "寄存器策略", "常驻启动前开启 CR3 追踪，供 R-1 进程操作使用。", HvmCrOn, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "cr-track-cr3-off", "关闭 CR3 追踪", "寄存器策略", "常驻停止时关闭 CR3 追踪。", HvmCrOff, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "inject-query", "查询注入", "R-1 进程", "读取 R-1 注入表。", HvmInjectQuery, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "inject-test", "标记写入测试", "R-1 进程", "向目标进程的标记地址写常数；需提供执行靶页地址。", HvmInjectTest, 0, 0UL, 0UL, 4,
      { { "进程 PID（十进制）", HvmDecimal32, NULL }, { "执行靶页地址（十六进制）", HvmHex64, NULL }, { "标记地址（十六进制）", HvmHex64, NULL }, { "写入值（十六进制）", HvmHex32, "4B535744" } } },
    { "inject-dll", "注入 DLL", "R-1 进程", "使用指定执行靶页与 LoadLibraryW 地址注入 DLL；路径支持 Unicode。", HvmInjectDll, 0, 0UL, 0UL, 4,
      { { "进程 PID（十进制）", HvmDecimal32, NULL }, { "执行靶页地址（十六进制）", HvmHex64, NULL }, { "LoadLibraryW 地址（十六进制，0 自动解析）", HvmHex64, NULL }, { "DLL 完整路径", HvmPath, NULL } } },
    { "inject-release", "撤销进程注入", "R-1 进程", "撤销指定 PID 的 R-1 注入。", HvmInjectRelease, 0, 0UL, 0UL, 1,
      { { "进程 PID（十进制）", HvmDecimal32, NULL } } },
    { "inject-release-all", "撤销全部注入", "R-1 进程", "撤销全部 R-1 注入。", HvmInjectClear, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "proc-query", "查询进程处置", "R-1 进程", "读取已安装的 R-1 进程处置。", HvmProcQuery, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "proc-freeze", "冻结进程", "R-1 进程", "拒绝靶页执行并注入缺页异常；要求 CR3 追踪和 EPTP 切换。", HvmProcFreeze, 0, 0UL, 0UL, 2,
      { { "进程 PID（十进制）", HvmDecimal32, NULL }, { "执行靶页地址（十六进制）", HvmHex64, NULL } } },
    { "proc-terminate", "结束进程", "R-1 进程", "拒绝靶页执行并注入无效指令异常，由来宾处理进程退出。", HvmProcTerminate, 0, 0UL, 0UL, 2,
      { { "进程 PID（十进制）", HvmDecimal32, NULL }, { "执行靶页地址（十六进制）", HvmHex64, NULL } } },
    { "proc-release", "撤销进程处置", "R-1 进程", "撤销指定 PID 的处置。", HvmProcRelease, 0, 0UL, 0UL, 1,
      { { "进程 PID（十进制）", HvmDecimal32, NULL } } },
    { "proc-release-all", "清空进程处置", "R-1 进程", "撤销全部 R-1 进程处置。", HvmProcClear, 0, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "help", "命令帮助", "查询与观测", "显示全部命令及参数；不访问驱动。", HvmHelp, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
    { "commands", "命令目录", "查询与观测", "输出 GUI 与 CLI 共用的命令和参数定义。", HvmCommands, 1, 0UL, 0UL, 0,
      { { NULL, HvmDecimal32, NULL } } },
};

const HVM_COMMAND_SPEC* KswordHvmCommands(size_t* count)
{
    if (count != NULL) { *count = sizeof(g_commands) / sizeof(g_commands[0]); }
    return g_commands;
}

const HVM_COMMAND_SPEC* KswordHvmFindCommand(const char* name)
{
    size_t i;
    if (name == NULL) { return NULL; }
    if (strcmp(name, "--help") == 0) { name = "help"; }
    for (i = 0; i < sizeof(g_commands) / sizeof(g_commands[0]); ++i) {
        if (strcmp(g_commands[i].name, name) == 0) { return &g_commands[i]; }
    }
    return NULL;
}

static int HvmArgumentError(char* error, size_t size, const char* name)
{
    if (error != NULL && size > 0) {
        (void)snprintf(error, size, "%s", name);
    }
    return 2;
}

int KswordHvmValidateArguments(const HVM_COMMAND_SPEC* command, int count,
    const char* const* arguments, unsigned long long values[KSW_HVM_COMMAND_MAX_ARGS],
    char* error, size_t errorSize)
{
    unsigned int i;
    if (error != NULL && errorSize != 0) { error[0] = 0; }
    if (command == NULL || values == NULL || count < 0 ||
        count > (int)command->argumentCount || (count != 0 && arguments == NULL)) {
        return HvmArgumentError(error, errorSize, "argument-count");
    }
    memset(values, 0, sizeof(*values) * KSW_HVM_COMMAND_MAX_ARGS);
    for (i = 0; i < command->argumentCount; ++i) {
        const HVM_COMMAND_ARGUMENT* spec = &command->arguments[i];
        const char* input = (int)i < count ? arguments[i] : spec->defaultValue;
        const char* digits;
        const char* cursor;
        char* end = NULL;
        unsigned long long maximum = ULLONG_MAX;
        int base = (spec->kind == HvmDecimal32 || spec->kind == HvmDecimal64) ? 10 : 16;
        if (input == NULL || input[0] == 0) {
            return HvmArgumentError(error, errorSize, spec->name);
        }
        if (spec->kind == HvmPath) {
            int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, NULL, 0);
            if (length <= 1 || length > KSWORD_ARK_HVM_INJECT_MAX_PAYLOAD_BYTES / (int)sizeof(wchar_t)) {
                return HvmArgumentError(error, errorSize, spec->name);
            }
            continue;
        }
        digits = input;
        if (base == 16 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) { digits += 2; }
        if (*digits == 0) { return HvmArgumentError(error, errorSize, spec->name); }
        for (cursor = digits; *cursor; ++cursor) {
            if (!((*cursor >= '0' && *cursor <= '9') ||
                  (base == 16 && ((*cursor >= 'a' && *cursor <= 'f') || (*cursor >= 'A' && *cursor <= 'F'))))) {
                return HvmArgumentError(error, errorSize, spec->name);
            }
        }
        errno = 0;
        values[i] = _strtoui64(digits, &end, base);
        if (spec->kind == HvmDecimal32 || spec->kind == HvmHex32) { maximum = 0xFFFFFFFFULL; }
        if (spec->kind == HvmByte) { maximum = 0xFFULL; }
        if (errno == ERANGE || end == digits || *end != 0 || values[i] > maximum ||
            (spec->kind == HvmPageAddress && (values[i] & 0xFFFULL) != 0)) {
            return HvmArgumentError(error, errorSize, spec->name);
        }
    }
    if (command->handler == HvmGdt && values[0] > INT_MAX) {
        return HvmArgumentError(error, errorSize, command->arguments[0].name);
    }
    if (command->handler == HvmPageMapTest && (values[3] < 1 || values[3] > 4)) {
        return HvmArgumentError(error, errorSize, command->arguments[3].name);
    }
    return 0;
}

void KswordHvmPrintJsonString(const char* text)
{
    const unsigned char* c = (const unsigned char*)text;
    size_t remaining = strlen(text);
    putchar('"');
    while (remaining) {
        /* ASCII-only JSON survives Windows PowerShell's legacy pipe decoding.
         * Decode UTF-8 before escaping: escaping individual bytes changes text.
         * UTF-16 surrogate pairs are the JSON representation of non-BMP text. */
        if (*c >= 0x80) {
            wchar_t units[2];
            int length = *c >= 0xF0 ? 4 : (*c >= 0xE0 ? 3 : 2);
            int count = remaining >= (size_t)length
                ? MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                      (const char*)c, length, units, 2) : 0;
            int i;
            if (!count) {
                printf("\\ufffd");
                length = 1;
            } else {
                for (i = 0; i < count; ++i) {
                    printf("\\u%04x", (unsigned int)units[i]);
                }
            }
            c += length;
            remaining -= (size_t)length;
            continue;
        }
        if (*c == '"' || *c == '\\') { putchar('\\'); putchar(*c); }
        else if (*c < 0x20) { printf("\\u%04x", *c); }
        else { putchar(*c); }
        ++c;
        --remaining;
    }
    putchar('"');
}

void KswordHvmPrintCommands(int asJson)
{
    size_t i, count;
    const HVM_COMMAND_SPEC* commands = KswordHvmCommands(&count);
    if (asJson) { printf("{\"kind\":\"commands\",\"version\":1,\"commands\":["); }
    else { printf("hvm_ctl [--json] [--validate] <command> [arguments]\n"); }
    for (i = 0; i < count; ++i) {
        unsigned int j;
        const HVM_COMMAND_SPEC* c = &commands[i];
        if (asJson) {
            if (i) { putchar(','); }
            printf("{\"name\":"); KswordHvmPrintJsonString(c->name);
            printf(",\"title\":"); KswordHvmPrintJsonString(c->title);
            printf(",\"group\":"); KswordHvmPrintJsonString(c->group);
            printf(",\"description\":"); KswordHvmPrintJsonString(c->description);
            printf(",\"readOnly\":%s,\"command\":%lu,\"flags\":%lu,\"arguments\":[",
                c->readOnly ? "true" : "false", c->command, c->flags);
            for (j = 0; j < c->argumentCount; ++j) {
                const HVM_COMMAND_ARGUMENT* a = &c->arguments[j];
                if (j) { putchar(','); }
                printf("{\"name\":"); KswordHvmPrintJsonString(a->name);
                printf(",\"kind\":%d,\"default\":", a->kind);
                if (a->defaultValue) { KswordHvmPrintJsonString(a->defaultValue); } else { printf("null"); }
                putchar('}');
            }
            printf("]}");
        } else {
            printf("  %s", c->name);
            for (j = 0; j < c->argumentCount; ++j) {
                printf(" %c%s%c", c->arguments[j].defaultValue ? '[' : '<', c->arguments[j].name,
                       c->arguments[j].defaultValue ? ']' : '>');
            }
            printf("\n    %s\n", c->description);
        }
    }
    if (asJson) { printf("]}\n"); }
    else { printf("\n--validate: validate arguments without opening the driver.\n"
                  "Exit: 0=success, 1=transport failure, 2=refused/invalid, 3=not exercised.\n"); }
}
