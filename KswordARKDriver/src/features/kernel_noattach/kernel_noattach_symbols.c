#include "kernel_noattach_symbols.h"
#include "../../platform/runtime_signature_scan.h"

/* Phase A0：骨架版本，所有 7 个 ntoskrnl 符号均通过结构性锚点交叉验证发现，
 * 不再依赖硬编码 KnaProfiles 数组。当前阶段仅占位，供后续阶段逐步接入 IDT
 * 读取、反向 call 图追踪、.pdata 函数边界确认与 patch 空间自适应等能力。
 *
 * 正式路径可用之前，KswordARKKernelNoAttach 保留现有 KnaProfiles 匹配通道，
 * 因此此函数仅在 A1+ 启用后的调用点被注入；本阶段暂返回 STATUS_NOT_SUPPORTED。 */
NTSTATUS KnaResolveSymbols(KNA_RESOLVED_SYMBOLS *Out)
{
    /* Out 可以为 NULL；骨架阶段不写入任何字段。 */
    UNREFERENCED_PARAMETER(Out);
    /* 骨架不触碰内核映像，避免在实现未完成时产生任何副作用。 */
    return STATUS_NOT_SUPPORTED;
}
