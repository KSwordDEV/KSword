#include "timer_dpc_decode.h"
#include "../../platform/runtime_signature_scan.h"

// 输入为完整 64 位值和旋转数；显式处理零位旋转，避免移位 64 位的未定义行为。
static ULONG64
KswordARKTimerDpcRotateLeft(
    _In_ ULONG64 Value,
    _In_ ULONG Rotation
    )
{
    return Rotation == 0UL ? Value : // 零位旋转保持原值。
        (Value << Rotation) | (Value >> (64UL - Rotation)); // 校准只传入 1..63。
}

// 反转字节序；使用无符号运算，保持 C 回归与内核构建的数值语义一致。
static ULONG64
KswordARKTimerDpcSwapBytes(
    _In_ ULONG64 Value
    )
{
    Value = ((Value & 0x00FF00FF00FF00FFULL) << 8U) | // 先交换相邻字节。
        ((Value >> 8U) & 0x00FF00FF00FF00FFULL); // 保留另一半字节。
    Value = ((Value & 0x0000FFFF0000FFFFULL) << 16U) | // 再交换相邻双字节。
        ((Value >> 16U) & 0x0000FFFF0000FFFFULL); // 保留另一半双字节。
    return (Value << 32U) | (Value >> 32U); // 最后交换高低双字。
}

// 已知编码 E=ror(bswap(A xor D) xor T,n) xor B，故
// D=bswap(rol(E,n) xor T) xor C，其中 C=bswap(rol(B,n)) xor A。
// 两个私有密钥只需合并为 C；从已知 T/E/D 样本枚举 n 并验证唯一性。
BOOLEAN
KswordARKTimerDpcCalibrateDecoder(
    _In_reads_(SampleCount) const KSW_TIMER_DPC_SAMPLE* Samples,
    _In_ ULONG SampleCount,
    _Out_ KSW_TIMER_DPC_DECODER* Decoder
    )
{
    ULONG index = 0UL; // 当前样本下标。
    ULONG rotation = 0UL; // 当前候选旋转位数。
    ULONG matches = 0UL; // 满足全部样本的候选数，必须恰好为一。
    BOOLEAN plain = TRUE; // 明文模式也必须由全部样本证明。
    BOOLEAN differentTimers = FALSE; // 防止单个探针掩盖地址绑定差异。
    BOOLEAN differentDpcs = FALSE; // 防止重复样本制造虚假的校准证据。
    KSW_TIMER_DPC_DECODER candidate; // 成功前不发布候选参数。

    if (Decoder == NULL) { // 输出指针必须有效。
        return FALSE; // 不访问空输出。
    }
    RtlZeroMemory(Decoder, sizeof(*Decoder)); // 失败始终清空旧参数。
    RtlZeroMemory(&candidate, sizeof(candidate)); // 初始化局部候选。
    if (Samples == NULL || SampleCount < 4UL) { // 至少两只定时器和两个 DPC 输入。
        return FALSE; // 不用不足的证据猜测编码。
    }
    for (index = 0UL; index < SampleCount; ++index) { // 校验样本多样性与明文模式。
        plain = plain && Samples[index].EncodedDpc == Samples[index].DpcAddress; // 每项均须一致。
        differentTimers |= Samples[index].TimerAddress != Samples[0].TimerAddress; // 要求不同对象。
        differentDpcs |= Samples[index].DpcAddress != Samples[0].DpcAddress; // 要求不同输入。
    }
    if (!differentTimers || !differentDpcs) { // 重复样本不能提供有效验证。
        return FALSE; // 保留无效状态。
    }
    if (plain) { // 旧系统直接存储 KDPC 地址。
        Decoder->Valid = TRUE; // 默认 Encoded=FALSE，无需密钥。
        return TRUE; // 明文模式也经过受控实测。
    }
    for (rotation = 0UL; rotation < 64UL; ++rotation) { // 有界枚举所有旋转数。
        const ULONG64 key = KswordARKTimerDpcSwapBytes( // 首个样本推导等价密钥。
            KswordARKTimerDpcRotateLeft(Samples[0].EncodedDpc, rotation) ^
            Samples[0].TimerAddress) ^ Samples[0].DpcAddress;

        for (index = 1UL; index < SampleCount; ++index) { // 其余样本独立验证该候选。
            if ((KswordARKTimerDpcSwapBytes( // 不解引用任何编码值。
                    KswordARKTimerDpcRotateLeft(Samples[index].EncodedDpc, rotation) ^
                    Samples[index].TimerAddress) ^ key) != Samples[index].DpcAddress) {
                break; // 任一样本不符即拒绝该候选。
            }
        }
        if (index == SampleCount) { // 候选必须满足全部已知输入。
            candidate.Rotation = rotation; // 保存唯一性判定所需参数。
            candidate.XorKey = key; // 此值只用于本次枚举。
            matches += 1UL; // 多解时仍拒绝，而不选第一个。
        }
    }
    if (matches != 1UL) { // 未知编码或歧义都不能继续猜测。
        return FALSE; // 输出保持清零。
    }
    candidate.Valid = TRUE; // 证明变换与全部探针一致。
    candidate.Encoded = TRUE; // 开启带定时器地址的解码。
    *Decoder = candidate; // 一次性发布完整状态。
    return TRUE; // 调用者仍负责验证解码结果的地址。
}

// KDPC 探针不会在正常校准期间到期；空回调不访问探针栈上的上下文。
static VOID
KswordARKTimerDpcProbeRoutine(
    _In_ KDPC* Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    UNREFERENCED_PARAMETER(Dpc); // 只提供合法的已知 DPC 对象。
    UNREFERENCED_PARAMETER(Context); // 不持有调用者上下文。
    UNREFERENCED_PARAMETER(Argument1); // 不处理定时器参数。
    UNREFERENCED_PARAMETER(Argument2); // 不处理定时器参数。
}

BOOLEAN
KswordARKTimerDpcInitializeDecoder(
    _In_ ULONG TimerDpcOffset,
    _Out_ KSW_TIMER_DPC_DECODER* Decoder
    )
{
    KTIMER timers[2]; // 两个不同地址的自建定时器。
    KDPC dpcs[2]; // 两个不同地址的已知 DPC 输入。
    KSW_TIMER_DPC_SAMPLE samples[6]; // 每个定时器依次采集 NULL 和两个 DPC。
    LARGE_INTEGER dueTime; // 极远的相对到期时间，避免探针排队执行。
    ULONG timerIndex = 0UL; // 当前定时器下标。
    ULONG inputIndex = 0UL; // 当前 DPC 输入下标。
    ULONG sampleIndex = 0UL; // 下一个样本的下标。
    BOOLEAN readable = TRUE; // 完整采集后才允许校准。

    if (Decoder == NULL) { // 必须有可写输出。
        return FALSE; // 拒绝空输出。
    }
    RtlZeroMemory(Decoder, sizeof(*Decoder)); // 不复用旧快照的参数。
    if (KeGetCurrentIrql() > APC_LEVEL || // 安全读取不能运行在 DISPATCH_LEVEL。
        TimerDpcOffset != (ULONG)FIELD_OFFSET(KTIMER, Dpc)) { // 探针必须验证实际布局。
        return FALSE; // 不兼容的公共布局不能证明现场编码。
    }
    RtlZeroMemory(samples, sizeof(samples)); // 所有样本先清零。
    dueTime.QuadPart = -0x0010000000000000LL; // 约十四年后的相对到期时间。
    for (timerIndex = 0UL; timerIndex < RTL_NUMBER_OF(timers); ++timerIndex) { // 初始化全部自建对象。
        KeInitializeTimerEx(&timers[timerIndex], NotificationTimer); // 不影响其它内核定时器。
        KeInitializeDpc(&dpcs[timerIndex], KswordARKTimerDpcProbeRoutine, NULL); // 已知合法对象。
    }
    for (timerIndex = 0UL; timerIndex < RTL_NUMBER_OF(timers); ++timerIndex) { // 交叉验证地址绑定。
        for (inputIndex = 0UL; inputIndex < 3UL; ++inputIndex) { // 同地址使用三个已知 DPC 输入。
            KDPC* dpc = inputIndex == 0UL ? NULL : &dpcs[inputIndex - 1UL]; // NULL 也要走真实编码。
            KSW_TIMER_DPC_SAMPLE* sample = &samples[sampleIndex++]; // 每次只写一个独立样本。

            (VOID)KeSetTimerEx(&timers[timerIndex], dueTime, 0L, dpc); // 只让内核写入它自己的编码。
            sample->TimerAddress = (ULONG64)(ULONG_PTR)&timers[timerIndex]; // 保存绑定对象地址。
            sample->DpcAddress = (ULONG64)(ULONG_PTR)dpc; // 保存调用时的已知明文。
            readable &= KswordARKRuntimeReadMemory( // 不直接解引用候选字段。
                (const UCHAR*)&timers[timerIndex] + TimerDpcOffset,
                &sample->EncodedDpc, sizeof(sample->EncodedDpc));
            (VOID)KeCancelTimer(&timers[timerIndex]); // 每个样本后立即取消，失败时同样收尾。
        }
    }
    return readable && KswordARKTimerDpcCalibrateDecoder( // 全部样本可读才发布唯一结果。
        samples, RTL_NUMBER_OF(samples), Decoder);
}

BOOLEAN
KswordARKTimerDpcDecodePointer(
    _In_ const KSW_TIMER_DPC_DECODER* Decoder,
    _In_ ULONG64 TimerAddress,
    _In_ ULONG64 EncodedDpc,
    _Out_ ULONG64* DpcAddress
    )
{
    if (DpcAddress == NULL) { // 调用方必须提供输出。
        return FALSE; // 不访问空输出。
    }
    *DpcAddress = 0ULL; // 失败不泄漏未经验证的编码值作为地址。
    if (Decoder == NULL || !Decoder->Valid || Decoder->Rotation >= 64UL) { // 必须先完成校准。
        return FALSE; // 保留读取不完整语义。
    }
    *DpcAddress = Decoder->Encoded ? // 明文模式保留旧系统行为。
        KswordARKTimerDpcSwapBytes(KswordARKTimerDpcRotateLeft(EncodedDpc,
            Decoder->Rotation) ^ TimerAddress) ^ Decoder->XorKey : EncodedDpc; // 只做数值转换。
    return TRUE; // 地址范围、字段完整读取仍由枚举器检查。
}
