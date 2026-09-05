/*
 * hvmprobe - 用户态硬件虚拟化环境探测器
 *
 * 存在的理由：KswordARK 的 HVM 后端在启动常驻前会检查一串 CPUID/MSR 条件，
 * 其中 CPUID.1:ECX[31]（hypervisor present）在虚拟机里必然为 1，导致常驻被拒。
 * 要判断某台虚拟机能不能用来测常驻，得先知道 guest 实际看到的 CPUID 长什么样。
 *
 * 这个程序不加载驱动、不需要签名、不需要管理员，把驱动会读到的那几项 CPUID
 * 原样打印出来，因此可以直接拷进虚拟机运行，用来验证 .vmx 的改动是否生效。
 *
 * 编译（host 上，静态链接以免虚拟机里缺运行库）：
 *   cl /nologo /O2 /MT /W4 hvmprobe.c /Fe:hvmprobe.exe
 */

#include <windows.h>
#include <intrin.h>
#include <stdio.h>

/* 把 CPUID 的三个寄存器拼回 12 字节厂商串。 */
static void
CopyVendor(char* out, int b, int d, int c)
{
    memcpy(out + 0, &b, 4);
    memcpy(out + 4, &d, 4);
    memcpy(out + 8, &c, 4);
    out[12] = '\0';
}

/* Hyper-V 的厂商串在 leaf 0x40000000 里是 EBX/ECX/EDX 顺序，与 leaf 0 不同。 */
static void
CopyHvVendor(char* out, int b, int c, int d)
{
    memcpy(out + 0, &b, 4);
    memcpy(out + 4, &c, 4);
    memcpy(out + 8, &d, 4);
    out[12] = '\0';
}

static void
PrintBit(const char* name, int value, const char* meaning)
{
    printf("  %-34s %s   %s\n", name, value ? "yes" : "no ", meaning);
}

/* 读一个 DWORD 注册表值；找不到时返回 fallback。 */
static DWORD
ReadDword(const char* subKey, const char* valueName, DWORD fallback)
{
    HKEY key = NULL;
    DWORD value = fallback;
    DWORD size = sizeof(value);
    DWORD type = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &key) !=
        ERROR_SUCCESS) {
        return fallback;
    }
    if (RegQueryValueExA(key, valueName, NULL, &type,
                         (LPBYTE)&value, &size) != ERROR_SUCCESS ||
        type != REG_DWORD) {
        value = fallback;
    }
    RegCloseKey(key);
    return value;
}

int
main(void)
{
    int regs[4] = { 0 };
    char vendor[13] = { 0 };
    char hvVendor[13] = { 0 };
    int hypervisorPresent = 0;
    int vmxSupported = 0;
    int svmSupported = 0;
    DWORD vbsEnabled = 0;
    DWORD hvciRunning = 0;

    printf("hvmprobe - KswordARK HVM 环境探测\n");
    printf("================================================================\n\n");

    /* leaf 0：厂商标识，决定走 VMX 还是 SVM 分支。 */
    __cpuid(regs, 0);
    CopyVendor(vendor, regs[1], regs[3], regs[2]);
    printf("CPU 厂商: %s\n", vendor);

    /* leaf 1：VMX 与 hypervisor-present 两个决定性位。 */
    __cpuid(regs, 1);
    vmxSupported = (regs[2] >> 5) & 1;
    hypervisorPresent = (regs[2] >> 31) & 1;
    printf("\nCPUID.1:ECX 关键位\n");
    PrintBit("[5]  VMX", vmxSupported, "Intel 硬件虚拟化");
    PrintBit("[31] hypervisor present", hypervisorPresent,
             "驱动据此判定已有 hypervisor 占用");

    /* AMD 侧的对应位，便于同一份输出覆盖两种平台。 */
    __cpuid(regs, (int)0x80000000);
    if ((unsigned)regs[0] >= 0x80000001u) {
        __cpuid(regs, (int)0x80000001);
        svmSupported = (regs[2] >> 2) & 1;
        printf("\nCPUID.80000001:ECX 关键位\n");
        PrintBit("[2]  SVM", svmSupported, "AMD 硬件虚拟化");
    }

    /* hypervisor 厂商串只在 present 位为 1 时有定义。 */
    if (hypervisorPresent) {
        __cpuid(regs, (int)0x40000000);
        CopyHvVendor(hvVendor, regs[1], regs[2], regs[3]);
        printf("\nhypervisor 厂商串: \"%s\"  (CPUID.40000000)\n", hvVendor);
        printf("  最大 hypervisor leaf: 0x%08X\n", (unsigned)regs[0]);
    }

    /*
     * VBS 与 HVCI 会让 Windows 自己的 hypervisor 常驻，效果与身处虚拟机相同，
     * 所以在真机上也要一起看。这两项用户态可读，不需要管理员。
     */
    vbsEnabled = ReadDword(
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        "EnableVirtualizationBasedSecurity", 0);
    hvciRunning = ReadDword(
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios"
        "\\HypervisorEnforcedCodeIntegrity",
        "Enabled", 0);
    printf("\nWindows 虚拟化安全\n");
    printf("  %-34s %lu\n", "EnableVirtualizationBasedSecurity",
           (unsigned long)vbsEnabled);
    printf("  %-34s %lu\n", "HVCI Enabled", (unsigned long)hvciRunning);

    /* 把上面的事实翻译成"驱动会怎么做"，这是跑这个程序的真正目的。 */
    printf("\n----------------------------------------------------------------\n");
    printf("对 KswordARK 常驻的判定\n\n");
    if (!vmxSupported && !svmSupported && hypervisorPresent) {
        /*
         * 这是最容易误判的一种：CPU 本身支持虚拟化，但底下的 hypervisor
         * 没有把它暴露上来，于是能力探测阶段就看不到 VMX/SVM。
         * 真机上通常是 HVCI/内存完整性拉起了 Hyper-V；虚拟机里则是宿主
         * 没开嵌套，或者宿主自己也运行在别的 hypervisor 之下。
         */
        printf("  拒绝：底层 hypervisor \"%s\" 没有把硬件虚拟化暴露上来，\n",
               hvVendor);
        printf("  连 VMX/SVM 能力位都看不到，PREPARE 阶段即失败。\n\n");
        if (vbsEnabled != 0 || hvciRunning != 0) {
            printf("  本机原因很可能是 VBS/HVCI：它会拉起 Hyper-V 并接管 VT-x。\n");
            printf("  需要关闭内存完整性并设置 hypervisorlaunchtype off 后重启。\n");
        } else {
            printf("  若这是虚拟机，宿主需要开启嵌套虚拟化\n");
            printf("  （VMware 为 vhv.enable = \"TRUE\"），\n");
            printf("  且宿主自身不能运行在别的 hypervisor 之下。\n");
        }
    } else if (!vmxSupported && !svmSupported) {
        printf("  拒绝：没有硬件虚拟化能力，也没有检测到 hypervisor。\n");
        printf("  通常是固件里关闭了虚拟化，需要在 BIOS/UEFI 中开启。\n");
    } else if (hypervisorPresent) {
        printf("  拒绝：hvm_resident.c 对 HYPERVISOR_PRESENT 是无条件拒绝，\n");
        printf("  常驻与 SOAK 都会返回 HYPERVISOR_CONFLICT。\n\n");
        printf("  可测的部分：驱动加载卸载、能力探测、R-1 内存通道、\n");
        printf("  控制寄存器策略配置、事件流面板、全部错误路径。\n");
    } else if (vmxSupported) {
        printf("  可以尝试：VMX 可用且 CPUID 未报告 hypervisor，\n");
        printf("  常驻的硬件门可以通过。\n");
    } else {
        printf("  硬件支持 SVM，但当前版本没有 SVM 后端，\n");
        printf("  驱动会返回 BACKEND_NOT_IMPLEMENTED。\n");
    }
    printf("\n");
    return 0;
}
