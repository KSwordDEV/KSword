/*
 * hvm_probe —— 用户态 CPUID 探针：回答"这台机器（可能是嵌套的 L1）能不能跑 KSword HVM"。
 *
 * 存在的理由：Win32_ComputerSystem.HypervisorPresent 读的是 CPUID.1:ECX[31]，它只说明
 * "我上面有 hypervisor"。任何虚拟机里这一位都是 1，用它判断"guest 内部有没有东西抢 VT-x"
 * 是错的。真正决定 KSword HVM 能否 VMXON 的是下面这些位。
 *
 * 检查项与驱动里 hvm_evmcs.c 的判定链逐条对应，所以在不加载驱动的前提下就能预告
 * KswordARKHvmEvmcsDiscover 会走到哪一步、为什么停下。
 *
 * 只读 CPUID，不写任何状态，不需要管理员权限。
 *
 * 编译： cl /nologo /W4 /WX /O2 hvm_probe.c
 */

#include <stdio.h>
#include <string.h>
#include <intrin.h>
/* 只为 SetConsoleOutputCP：本文件是 UTF-8 源码，而中文 Windows 的控制台默认是
 * CP936。不切代码页的话每个中文字都会变成乱码 —— 实测在 guest 里就是这样。 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* TLFS 定义的合成 CPUID 叶，与 hvm_evmcs.c 中的同名常量保持一致。 */
#define HV_CPUID_VENDOR_AND_MAX  0x40000000u
#define HV_CPUID_INTERFACE       0x40000001u
#define HV_CPUID_FEATURES        0x40000003u
#define HV_CPUID_RECOMMENDATIONS 0x40000004u
#define HV_CPUID_NESTED_FEATURES 0x4000000Au
/* "Hv#1" 的小端编码。 */
#define HV_INTERFACE_SIGNATURE   0x31237648u
/* TLFS 建议使用 eVMCS 接口。Hyper-V 只在该虚拟机开了嵌套虚拟化时才置这一位。 */
#define HV_RECOMMEND_EVMCS       (1u << 14)

static void put_line(void)
{
    printf("--------------------------------------------------------------\n");
}

static void verdict(const char* name, int ok, const char* why)
{
    printf("  [%s] %-42s %s\n", ok ? "OK " : "NO ", name, why);
}

int main(void)
{
    UINT previousCp;
    int regs[4];
    unsigned int maxBasic, maxExt, maxHvLeaf;
    unsigned int ecx1, edx81;
    int hypervisorPresent, vmxSupported, page1gb;
    char vendor[13];
    char hvVendor[13];
    int gateOk = 1;

    /* 切到 UTF-8，退出前还原，免得把调用者的控制台留在改过的状态。 */
    previousCp = GetConsoleOutputCP();
    (void)SetConsoleOutputCP(CP_UTF8);

    __cpuid(regs, 0);
    maxBasic = (unsigned int)regs[0];
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[3], 4);
    memcpy(vendor + 8, &regs[2], 4);
    vendor[12] = '\0';

    __cpuid(regs, 1);
    ecx1 = (unsigned int)regs[2];
    /* CPUID.1:ECX[5] = VMX。这一位才是"我自己能不能 VMXON"的前提。 */
    vmxSupported = (ecx1 >> 5) & 1u;
    /* CPUID.1:ECX[31] = hypervisor present。任何虚拟机里都是 1，不代表 VT-x 被占。 */
    hypervisorPresent = (int)((ecx1 >> 31) & 1u);

    __cpuid(regs, (int)0x80000000u);
    maxExt = (unsigned int)regs[0];
    page1gb = 0;
    if (maxExt >= 0x80000001u) {
        __cpuid(regs, (int)0x80000001u);
        edx81 = (unsigned int)regs[3];
        /* CPUID.80000001H:EDX[26] = 1 GiB 页。M-04 的能力门用的就是它。 */
        page1gb = (int)((edx81 >> 26) & 1u);
    }

    put_line();
    printf(" KSword HVM 环境探针\n");
    put_line();
    printf("  CPU 厂商            : %s\n", vendor);
    printf("  CPUID 最大基本叶    : 0x%08X\n", maxBasic);
    printf("  CPUID 最大扩展叶    : 0x%08X\n", maxExt);
    printf("\n");

    put_line();
    printf(" 1. 能不能 VMXON（KSword HVM 的硬前提）\n");
    put_line();
    gateOk &= vmxSupported;
    verdict("CPUID.1:ECX[5] VMX 可用", vmxSupported,
            vmxSupported ? "VT-x 已透传进来"
                         : "看不到 VT-x —— 嵌套虚拟化没开，或宿主没暴露");
    printf("  [--] %-42s %s\n", "CPUID.1:ECX[31] hypervisor present",
           hypervisorPresent ? "1（上面有 hypervisor，虚拟机里属正常，不是问题）"
                             : "0（裸机）");
    verdict("CPUID.80000001H:EDX[26] 1 GiB 页", page1gb,
            page1gb ? "支持" : "不支持（页表遍历的 1 GiB 路径不可用）");
    printf("\n");

    if (!hypervisorPresent) {
        put_line();
        printf(" 2. 上层 hypervisor：无（裸机运行）\n");
        put_line();
        printf("  非嵌套环境，下面的 TLFS 检查不适用。\n");
        goto done;
    }

    __cpuid(regs, (int)HV_CPUID_VENDOR_AND_MAX);
    maxHvLeaf = (unsigned int)regs[0];
    memcpy(hvVendor + 0, &regs[1], 4);
    memcpy(hvVendor + 4, &regs[2], 4);
    memcpy(hvVendor + 8, &regs[3], 4);
    hvVendor[12] = '\0';

    put_line();
    printf(" 2. 上层 hypervisor 的 TLFS 信息（对应 hvm_evmcs.c 的判定链）\n");
    put_line();
    printf("  合成叶厂商串        : %s\n", hvVendor);
    printf("  合成叶最大值        : 0x%08X\n", maxHvLeaf);

    if (strcmp(hvVendor, "Microsoft Hv") != 0) {
        printf("\n  上层不是 Hyper-V，eVMCS 那条链不适用。\n");
        goto done;
    }

    /* 与 hvm_evmcs.c 完全相同的四道闸门，逐条报告卡在哪。 */
    {
        int leafOk = (maxHvLeaf >= HV_CPUID_NESTED_FEATURES);
        unsigned int iface = 0u, privileges = 0u, recommend = 0u;
        int ifaceOk = 0, evmcsRecommended = 0, versionOk = 0;
        unsigned int verLow = 0u, verHigh = 0u;

        verdict("合成叶覆盖到 0x4000000A", leafOk,
                leafOk ? "嵌套特性叶可读" : "叶不够 —— 宿主没开嵌套虚拟化");

        if (leafOk) {
            __cpuid(regs, (int)HV_CPUID_INTERFACE);
            iface = (unsigned int)regs[0];
            ifaceOk = (iface == HV_INTERFACE_SIGNATURE);
            verdict("接口签名 = Hv#1", ifaceOk, ifaceOk ? "标准 Hv#1 接口" : "签名不符");

            __cpuid(regs, (int)HV_CPUID_FEATURES);
            privileges = (unsigned int)regs[1];
            printf("  [--] %-42s 0x%08X%s\n", "分区权限掩码 (0x40000003:EBX)",
                   privileges,
                   (privileges & 1u) ? "（含 CreatePartitions，是根分区）" : "（guest 分区）");

            __cpuid(regs, (int)HV_CPUID_RECOMMENDATIONS);
            recommend = (unsigned int)regs[0];
            evmcsRecommended = ((recommend & HV_RECOMMEND_EVMCS) != 0u);
            verdict("建议使用 eVMCS (0x40000004:EAX bit14)", evmcsRecommended,
                    evmcsRecommended
                        ? "**宿主已为本机开启嵌套虚拟化**"
                        : "未置位 —— 宿主没给这台虚拟机开 ExposeVirtualizationExtensions");

            __cpuid(regs, (int)HV_CPUID_NESTED_FEATURES);
            verLow = ((unsigned int)regs[0]) & 0xFFu;
            verHigh = (((unsigned int)regs[0]) >> 8) & 0xFFu;
            versionOk = (verLow <= 1u && verHigh >= 1u);
            printf("  [%s] %-42s 区间 [%u, %u]\n", versionOk ? "OK " : "NO ",
                   "eVMCS 版本 1 在支持区间内", verLow, verHigh);
        }

        printf("\n");
        put_line();
        printf(" 3. 结论\n");
        put_line();
        if (!vmxSupported) {
            printf("  KSword HVM **无法启动**：CPUID 里看不到 VMX。\n");
            printf("  处理：宿主上关机后执行\n");
            printf("      Set-VMProcessor -VMName <名> -ExposeVirtualizationExtensions $true\n");
        } else {
            printf("  VMX 可见，KSword HVM 具备 VMXON 的 CPUID 前提。\n");
            printf("  仍需在 guest 内确认（本探针读不到 MSR，需驱动侧或提权工具）：\n");
            printf("    * IA32_FEATURE_CONTROL 的锁定位与 VMXON-outside-SMX 允许位\n");
            printf("    * bcdedit 的 hypervisorlaunchtype 必须是 Off\n");
            printf("    * VBS / HVCI 必须关闭\n");
            printf("  以上三项若有一项不满足，VT-x 会被 guest 自己的 hypervisor 先占住。\n\n");
            if (leafOk && ifaceOk && evmcsRecommended && versionOk) {
                printf("  eVMCS：四道闸门全通过 —— 驱动会把能力位 HYPERV_EVMCS_CAPABLE 置上。\n");
                printf("  但注意 KswordARKHvmEvmcsValidate 目前**刻意只报 PARTIAL 并返回\n");
                printf("  STATUS_NOT_IMPLEMENTED**，所以实际走的是普通 VMX，由 L0 模拟，\n");
                printf("  每条 VMREAD/VMWRITE 都会陷出，性能数字不能代表真机。\n");
            } else {
                printf("  eVMCS：闸门未全通过，驱动会报 UNAVAILABLE。不影响普通 VMX 路径。\n");
            }
        }
    }

done:
    printf("\n");
    put_line();
    if (previousCp != 0u) {
        (void)SetConsoleOutputCP(previousCp);
    }
    return 0;
}
