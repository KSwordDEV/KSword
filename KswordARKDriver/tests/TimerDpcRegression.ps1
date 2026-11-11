[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..\..'),
    [string]$KernelImage
)

$ErrorActionPreference = 'Stop'
$taskRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$taskOutput = Join-Path $taskRoot '.codex-build-logs\timer-dpc-regression'
$taskVcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (!(Test-Path -LiteralPath $taskVcvars)) { $taskVcvars = 'D:\Software\VS\VC\Auxiliary\Build\vcvars64.bat' }
$taskKit = 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0'
foreach ($taskRequired in @($taskVcvars, $taskKit)) {
    if (!(Test-Path -LiteralPath $taskRequired)) { throw "Required input missing: $taskRequired" }
}
New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null
$taskSource = Join-Path $taskOutput 'timer_dpc_regression.c'
$taskExecutable = Join-Path $taskOutput 'timer_dpc_regression.exe'
$taskQuery = Join-Path $taskOutput 'timer_dpc_query_prefix.c'
$taskProduction = [IO.File]::ReadAllText((Join-Path $taskRoot 'KswordARKDriver\src\features\kernel\timer_dpc_query.c'))
$taskCut = [regex]::Match($taskProduction, 'NTSTATUS\s+KswordARKDriverEnumerateTimerDpc\(')
if (!$taskCut.Success) { throw 'Cannot locate public timer enumeration boundary.' }
# 保留真实桶遍历和条目生成；全处理器切换、池分配及 PRCB 访问不在离线夹具中执行。
$taskPrefix = $taskProduction.Substring(0, $taskCut.Index)
$taskKernel = Join-Path $taskRoot 'KswordARKDriver\src\features\kernel'
$taskPrefix = [regex]::Replace($taskPrefix, '#include "([^"\r\n]+)"', {
    param($match)
    $taskHeader = $match.Groups[1].Value
    if ($taskHeader.StartsWith('ark/')) { return $match.Value }
    $taskAbsolute = [IO.Path]::GetFullPath((Join-Path $taskKernel $taskHeader)).Replace('\', '/')
    return '#include "' + $taskAbsolute + '"'
})
[IO.File]::WriteAllText($taskQuery, $taskPrefix, [Text.UTF8Encoding]::new($false))

# 编译真实校准器和枚举器；有界合成内存及定时器 API 替代真实内核操作，不装载驱动。
$taskCode = @'
#include <ntifs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <intrin.h>
#pragma warning(push)
#pragma warning(disable: 4324) // WDK/WDF 头中框架结构体有显式对齐。
#include "ark/ark_driver.h"
#include "@ROOT@/KswordARKDriver/src/features/dyndata/dyndata_v4_internal.h"
#include "@ROOT@/KswordARKDriver/src/features/kernel/timer_dpc_decode.h"
#include "@ROOT@/KswordARKDriver/src/platform/runtime_signature_scan.h"
#pragma warning(pop)

#define TIMER_BASE 0xFFFF800010000000ULL
#define DPC_BASE 0xFFFF800020000000ULL
#define HEAD_BASE 0xFFFF800030000000ULL
static ULONG failures; // 断言失败数。
static ULONG checks; // 已执行断言数。
static ULONG testRotation; // 独立编码器的旋转数。
static ULONG64 keyA = 0x123456789ABCDEF0ULL; // 独立编码器第一个随机密钥。
static ULONG64 keyB = 0xFEDCBA9876543210ULL; // 独立编码器第二个随机密钥。
static BOOLEAN testPlain; // 模拟旧系统明文存储。
static BOOLEAN badEncoding; // 模拟未知编码方式。
static BOOLEAN readFailure; // 模拟探针读取失败。
static BOOLEAN contextFailure; // 模拟 DPC 上下文字段不可读。
static KIRQL testIrql; // 模拟读取 IRQL。
static ULONG cancelCount; // 确认每个受控样本都取消定时器。
static KTIMER* probeTimers[2]; // 只允许安全读取当前探针字段。
static ULONG probeCount; // 已初始化探针数。
static KTIMER fixtureTimer; // 合成现场定时器。
static KDPC fixtureDpc; // 合成现场 DPC。
static LIST_ENTRY fixtureHead; // 合成现场桶头。
static PVOID testSystemRange = (PVOID)(ULONG_PTR)0xFFFF800000000000ULL;

static VOID Check(BOOLEAN Condition, const char* Name) // 汇总断言，成功时不刷屏。
{
    ++checks;
    if (!Condition) { ++failures; printf("FAIL %s\n", Name); }
}

static ULONG64 Encode(ULONG64 Timer, ULONG64 Dpc) // 独立使用 MSVC intrinsic 重放实机指令。
{
    if (testPlain) { return Dpc; }
    if (badEncoding) { return Dpc ^ 0x1234ULL; }
    return _rotr64(_byteswap_uint64(keyA ^ Dpc) ^ Timer, (int)testRotation) ^ keyB;
}

static VOID TestInitTimer(KTIMER* Timer, TIMER_TYPE Type) // 只初始化并登记自建对象。
{
    UNREFERENCED_PARAMETER(Type);
    memset(Timer, 0, sizeof(*Timer));
    if (probeCount < RTL_NUMBER_OF(probeTimers)) { probeTimers[probeCount++] = Timer; }
}

static VOID TestInitDpc(KDPC* Dpc, PKDEFERRED_ROUTINE Routine, PVOID Context) // 替代系统初始化。
{
    memset(Dpc, 0, sizeof(*Dpc));
    Dpc->DeferredRoutine = Routine;
    Dpc->DeferredContext = Context;
}

static BOOLEAN TestSetTimer(KTIMER* Timer, LARGE_INTEGER Due, LONG Period, KDPC* Dpc) // 写入独立编码。
{
    UNREFERENCED_PARAMETER(Due);
    UNREFERENCED_PARAMETER(Period);
    Timer->Dpc = (KDPC*)(ULONG_PTR)Encode((ULONG64)(ULONG_PTR)Timer, (ULONG64)(ULONG_PTR)Dpc);
    return FALSE;
}

static BOOLEAN TestCancelTimer(KTIMER* Timer) // 检查清理调用，绝不操作系统定时器。
{
    UNREFERENCED_PARAMETER(Timer);
    ++cancelCount;
    return TRUE;
}

static KIRQL TestIrql(VOID) { return testIrql; } // 用于验证高 IRQL 拒绝。

static BOOLEAN TestRead(const VOID* Address, VOID* Buffer, SIZE_T Bytes) // 有界合成安全读取。
{
    ULONG index;
    ULONG64 address = (ULONG64)(ULONG_PTR)Address;
    const ULONG64 bases[] = { TIMER_BASE, DPC_BASE, HEAD_BASE };
    const VOID* sources[] = { &fixtureTimer, &fixtureDpc, &fixtureHead };
    const SIZE_T sizes[] = { sizeof(fixtureTimer), sizeof(fixtureDpc), sizeof(fixtureHead) };
    if (readFailure || testIrql > APC_LEVEL) { return FALSE; }
    for (index = 0UL; index < probeCount; ++index) {
        if (Address == (const UCHAR*)probeTimers[index] + FIELD_OFFSET(KTIMER, Dpc) && Bytes == 8U) {
            memcpy(Buffer, Address, Bytes);
            return TRUE;
        }
    }
    if (contextFailure && address == DPC_BASE + FIELD_OFFSET(KDPC, DeferredContext)) { return FALSE; }
    for (index = 0UL; index < RTL_NUMBER_OF(bases); ++index) {
        if (address >= bases[index] && address - bases[index] < sizes[index] &&
            Bytes <= sizes[index] - (SIZE_T)(address - bases[index])) {
            memcpy(Buffer, (const UCHAR*)sources[index] + (SIZE_T)(address - bases[index]), Bytes);
            return TRUE;
        }
    }
    return FALSE;
}

#undef KeGetCurrentIrql
#undef KeInitializeDpc
#define KeGetCurrentIrql TestIrql
#define KeInitializeTimerEx TestInitTimer
#define KeInitializeDpc TestInitDpc
#define KeSetTimerEx TestSetTimer
#define KeCancelTimer TestCancelTimer
#define KswordARKRuntimeReadMemory TestRead
#define MmSystemRangeStart testSystemRange
#include "@ROOT@/KswordARKDriver/src/features/kernel/timer_dpc_decode.c"
#include "@QUERY@"

static VOID MakeSamples(KSW_TIMER_DPC_SAMPLE* Samples) // 独立地址与空/非空输入交叉组成六个样本。
{
    ULONG t;
    ULONG d;
    for (t = 0UL; t < 2UL; ++t) {
        for (d = 0UL; d < 3UL; ++d) {
            KSW_TIMER_DPC_SAMPLE* sample = &Samples[t * 3UL + d];
            sample->TimerAddress = TIMER_BASE + (ULONG64)t * 0xC0ULL;
            sample->DpcAddress = d == 0UL ? 0ULL : DPC_BASE + (ULONG64)d * 0x40ULL;
            sample->EncodedDpc = Encode(sample->TimerAddress, sample->DpcAddress);
        }
    }
}

static VOID TestEnumeration(const KSW_TIMER_DPC_DECODER* Decoder, ULONG64 Dpc, BOOLEAN Partial) // 执行真实桶枚举。
{
    UCHAR output[KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE + sizeof(KSWORD_ARK_TIMER_DPC_ENTRY)];
    ULONG64 seen[2] = { 0ULL, 0ULL };
    KSW_TIMER_DPC_BUILDER builder;
    KSWORD_ARK_TIMER_DPC_ENTRY* row;
    const ULONG64 link = TIMER_BASE + FIELD_OFFSET(KTIMER, TimerListEntry);
    memset(&builder, 0, sizeof(builder));
    memset(output, 0, sizeof(output));
    memset(&fixtureTimer, 0, sizeof(fixtureTimer));
    memset(&fixtureDpc, 0, sizeof(fixtureDpc));
    fixtureTimer.Dpc = (KDPC*)(ULONG_PTR)Encode(TIMER_BASE, Dpc);
    fixtureTimer.DueTime.QuadPart = 123456789LL;
    fixtureTimer.Period = 100;
    fixtureTimer.TimerListEntry.Flink = (LIST_ENTRY*)(ULONG_PTR)HEAD_BASE;
    fixtureTimer.TimerListEntry.Blink = (LIST_ENTRY*)(ULONG_PTR)HEAD_BASE;
    fixtureHead.Flink = (LIST_ENTRY*)(ULONG_PTR)link;
    fixtureHead.Blink = (LIST_ENTRY*)(ULONG_PTR)link;
    fixtureDpc.DeferredRoutine = (PKDEFERRED_ROUTINE)(ULONG_PTR)0xFFFF800040000100ULL;
    fixtureDpc.DeferredContext = (PVOID)(ULONG_PTR)0x12345678ULL;
    builder.Response = (KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE*)output;
    builder.Capacity = 1UL;
    builder.MaxEntries = 2UL;
    builder.MaxEntriesPerBucket = 2UL;
    builder.SeenTimers = seen;
    builder.Decoder = *Decoder;
    builder.Layout.TimerTimerListEntry = FIELD_OFFSET(KTIMER, TimerListEntry);
    builder.Layout.TimerDueTime = FIELD_OFFSET(KTIMER, DueTime);
    builder.Layout.TimerPeriod = FIELD_OFFSET(KTIMER, Period);
    builder.Layout.TimerType = FIELD_OFFSET(KTIMER, Header.Type);
    builder.Layout.TimerDpc = FIELD_OFFSET(KTIMER, Dpc);
    builder.Layout.DpcDeferredRoutine = FIELD_OFFSET(KDPC, DeferredRoutine);
    builder.Layout.DpcDeferredContext = FIELD_OFFSET(KDPC, DeferredContext);
    Check(KswordARKTimerDpcEnumerateBucket(&builder, 0U, 0U, 1UL, HEAD_BASE), "bucket traversal completes");
    Check(builder.Response->returnedCount == 1UL && builder.Response->totalCount == 1UL, "one row retained");
    Check(builder.Response->corruptBucketCount == 0UL, "valid chain not marked corrupt");
    row = &builder.Response->entries[0];
    Check(row->dueTime == 123456789LL && row->period == 100, "timer fields preserved");
    Check(builder.Response->readFailureCount == (Partial ? 1UL : 0UL), "read failure count accurate");
    Check(((row->flags & KSWORD_ARK_TIMER_DPC_ENTRY_READ_PARTIAL) != 0UL) == Partial, "row partial state accurate");
    Check(builder.Response->statusFlags == (Partial ?
        KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL | KSWORD_ARK_TIMER_DPC_STATUS_READ_FAILED : 0UL), "response flags accurate");
    if (!Partial) {
        Check(row->dpcAddress == Dpc, "decoded address returned");
        Check(((row->flags & KSWORD_ARK_TIMER_DPC_ENTRY_DPC_PRESENT) != 0UL) == (Dpc != 0ULL), "null DPC semantics");
        if (Dpc != 0ULL) {
            Check((row->flags & KSWORD_ARK_TIMER_DPC_ENTRY_DPC_FIELDS_PRESENT) != 0UL &&
                row->deferredRoutine == 0xFFFF800040000100ULL && row->deferredContext == 0x12345678ULL,
                "DPC routine and context parsed");
        }
    }
}

int main(int Argc, char** Argv) // 覆盖数学变换、探针生命周期与真实枚举结果。
{
    KSW_TIMER_DPC_SAMPLE samples[6];
    KSW_TIMER_DPC_DECODER decoder;
    ULONG seed;
    ULONG index;
    ULONG64 decoded;
    if (Argc == 2) { // 可选：读取真实内核 PE 指令仿真生成的独立样本。
        FILE* file = NULL;
        Check(fopen_s(&file, Argv[1], "rb") == 0 && file != NULL, "kernel replay samples opened");
        if (file == NULL) { return 1; }
        Check(fread(samples, sizeof(samples[0]), 6U, file) == 6U, "kernel replay samples read");
        fclose(file);
        Check(KswordARKTimerDpcCalibrateDecoder(samples, 6UL, &decoder), "actual kernel instructions calibrated");
        for (index = 0UL; index < 6UL; ++index) {
            Check(KswordARKTimerDpcDecodePointer(&decoder, samples[index].TimerAddress,
                samples[index].EncodedDpc, &decoded) && decoded == samples[index].DpcAddress,
                "actual kernel instruction sample decoded");
        }
    }
    for (seed = 0UL; seed < 8UL; ++seed) {
        keyA = 0x123456789ABCDEF0ULL ^ ((ULONG64)seed * 0x789ABCDE1234567ULL);
        keyB = 0xFEDCBA9876543210ULL ^ ((ULONG64)seed * 0x123456789ABCDEFULL);
        for (testRotation = 0UL; testRotation < 64UL; ++testRotation) {
            MakeSamples(samples);
            Check(KswordARKTimerDpcCalibrateDecoder(samples, 6UL, &decoder), "unique rotation calibrated");
            Check(decoder.Encoded && decoder.Rotation == testRotation, "correct rotation selected");
            for (index = 0UL; index < 6UL; ++index) {
                Check(KswordARKTimerDpcDecodePointer(&decoder, samples[index].TimerAddress,
                    samples[index].EncodedDpc, &decoded) && decoded == samples[index].DpcAddress, "sample decoded");
            }
            TestEnumeration(&decoder, DPC_BASE, FALSE);
            TestEnumeration(&decoder, 0ULL, FALSE);
        }
    }
    testPlain = TRUE;
    MakeSamples(samples);
    Check(KswordARKTimerDpcCalibrateDecoder(samples, 6UL, &decoder) && !decoder.Encoded, "legacy plaintext calibrated");
    TestEnumeration(&decoder, DPC_BASE, FALSE);
    TestEnumeration(&decoder, 0ULL, FALSE);
    testPlain = FALSE;
    testRotation = 23UL;
    probeCount = 0UL;
    cancelCount = 0UL;
    Check(KswordARKTimerDpcInitializeDecoder(FIELD_OFFSET(KTIMER, Dpc), &decoder), "production probe calibration");
    Check(cancelCount == 6UL && probeCount == 2UL, "all probe samples cancelled");
    TestEnumeration(&decoder, DPC_BASE, FALSE);
    contextFailure = TRUE;
    TestEnumeration(&decoder, DPC_BASE, TRUE);
    contextFailure = FALSE;
    TestEnumeration(&decoder, DPC_BASE + 0x1000ULL, TRUE);
    Check(!KswordARKTimerDpcInitializeDecoder(0UL, &decoder) && !decoder.Valid, "wrong field offset rejected");
    TestEnumeration(&decoder, DPC_BASE, TRUE);
    probeCount = 0UL;
    cancelCount = 0UL;
    readFailure = TRUE;
    Check(!KswordARKTimerDpcInitializeDecoder(FIELD_OFFSET(KTIMER, Dpc), &decoder) && !decoder.Valid, "unreadable probe rejected");
    Check(cancelCount == 6UL, "failed probes still cancelled");
    readFailure = FALSE;
    testIrql = DISPATCH_LEVEL;
    Check(!KswordARKTimerDpcInitializeDecoder(FIELD_OFFSET(KTIMER, Dpc), &decoder), "high IRQL rejected");
    testIrql = PASSIVE_LEVEL;
    MakeSamples(samples);
    samples[5].EncodedDpc ^= 1ULL;
    Check(!KswordARKTimerDpcCalibrateDecoder(samples, 6UL, &decoder) && !decoder.Valid, "inconsistent samples rejected");
    for (index = 0UL; index < 6UL; ++index) { samples[index] = samples[0]; }
    Check(!KswordARKTimerDpcCalibrateDecoder(samples, 6UL, &decoder), "repeated evidence rejected");
    MakeSamples(samples);
    Check(!KswordARKTimerDpcCalibrateDecoder(samples, 3UL, &decoder), "insufficient samples rejected");
    badEncoding = TRUE;
    MakeSamples(samples);
    Check(!KswordARKTimerDpcCalibrateDecoder(samples, 6UL, &decoder), "unknown transform rejected");
    decoder.Valid = TRUE;
    decoder.Rotation = 64UL;
    decoded = ~0ULL;
    Check(!KswordARKTimerDpcDecodePointer(&decoder, TIMER_BASE, 1ULL, &decoded) && decoded == 0ULL, "invalid rotation rejected and output cleared");
    printf("checks=%lu failures=%lu\n", checks, failures);
    return failures != 0UL;
}
'@
$taskCode = $taskCode.Replace('@ROOT@', $taskRoot.Replace('\', '/'))
$taskCode = $taskCode.Replace('@QUERY@', $taskQuery.Replace('\', '/'))
[IO.File]::WriteAllText($taskSource, $taskCode, [Text.UTF8Encoding]::new($false))
$taskIncludes = @(
    (Join-Path $taskKit 'km'), (Join-Path $taskKit 'shared'), (Join-Path $taskKit 'ucrt'),
    'C:\Program Files (x86)\Windows Kits\10\Include\wdf\kmdf\1.15',
    (Join-Path $taskRoot 'KswordARKDriver\include'), (Join-Path $taskRoot 'KswordARKDriver'),
    (Join-Path $taskRoot 'shared')
)
$taskCompile = @('call', ('"{0}"' -f $taskVcvars), '>', 'nul', '&&',
    'cl.exe', '/nologo', '/W4', '/WX', '/Od', '/Gy', '/utf-8', '/TC', '/D_AMD64_', '/DAMD64')
$taskCompile += $taskIncludes | ForEach-Object { '/I"{0}"' -f $_ }
$taskCompile += @(
    ('/Fo"{0}"' -f (Join-Path $taskOutput 'timer_dpc_regression.obj')),
    ('/Fe"{0}"' -f $taskExecutable), ('"{0}"' -f $taskSource), '/link', '/OPT:REF'
)
& cmd.exe /d /s /c ($taskCompile -join ' ')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($KernelImage) {
    $taskSamples = Join-Path $taskOutput 'kernel_samples.bin'
    & python (Join-Path $PSScriptRoot 'timer_dpc_kernel_replay.py') --kernel-image $KernelImage --output $taskSamples
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $taskExecutable $taskSamples
} else {
    & $taskExecutable
}
exit $LASTEXITCODE
