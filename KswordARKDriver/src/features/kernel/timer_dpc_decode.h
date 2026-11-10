#pragma once

#include <ntddk.h>

// 本次快照独有的解码状态；不缓存可能随启动改变的内核编码参数。
typedef struct _KSW_TIMER_DPC_DECODER
{
    BOOLEAN Valid; // 所有受控样本均已验证。
    BOOLEAN Encoded; // FALSE 表示已验证的旧系统明文指针。
    ULONG Rotation; // 解码时向左旋转的位数，范围为 0..63。
    ULONG64 XorKey; // 合并两个内核密钥后的等价异或值。
} KSW_TIMER_DPC_DECODER;

// 受控输入样本只用于推导数学变换，绝不解引用 EncodedDpc。
typedef struct _KSW_TIMER_DPC_SAMPLE
{
    ULONG64 TimerAddress; // 参与编码的 KTIMER 地址。
    ULONG64 EncodedDpc; // KeSetTimerEx 写入的原始字段。
    ULONG64 DpcAddress; // 调用 KeSetTimerEx 时传入的已知 KDPC，可为零。
} KSW_TIMER_DPC_SAMPLE;

// 从至少四个样本验证唯一解码模式；失败时清空 Decoder，不猜测系统版本。
BOOLEAN
KswordARKTimerDpcCalibrateDecoder(
    _In_reads_(SampleCount) const KSW_TIMER_DPC_SAMPLE* Samples,
    _In_ ULONG SampleCount,
    _Out_ KSW_TIMER_DPC_DECODER* Decoder
    );

// 用自建长到期定时器校准本次快照；返回前取消所有探针，不保留内核对象。
BOOLEAN
KswordARKTimerDpcInitializeDecoder(
    _In_ ULONG TimerDpcOffset,
    _Out_ KSW_TIMER_DPC_DECODER* Decoder
    );

// 仅转换数值，不读取候选对象；失败时输出零，成功后调用者仍须验证地址并安全读取。
BOOLEAN
KswordARKTimerDpcDecodePointer(
    _In_ const KSW_TIMER_DPC_DECODER* Decoder,
    _In_ ULONG64 TimerAddress,
    _In_ ULONG64 EncodedDpc,
    _Out_ ULONG64* DpcAddress
    );
