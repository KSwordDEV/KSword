#pragma once
#include "KswordArkHvmNoAttachIoctl.h"

/* 两种传输共享停止/命令布局，版本和 IOCTL 明确区分实际机制。 */
#define KSWORD_ARK_KERNEL_NOATTACH_VERSION 1UL
/* 独立普通驱动通道，不创建 Windows 调试对象或目标内组件。 */
#define KSWORD_ARK_IOCTL_FUNCTION_KERNEL_NOATTACH 0x938UL
/* 内核异常接管和寄存器控制只允许特权写通道。 */
#define IOCTL_KSWORD_ARK_KERNEL_NOATTACH \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_KERNEL_NOATTACH, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* OPEN 另要求理解内核补丁和驱动本次启动留驻的代价。 */
#define KSWORD_ARK_KERNEL_NOATTACH_HOOK_ACK 4UL
/* 普通驱动的四个硬件地址槽，不冒充 EPT 容量。 */
#define KSWORD_ARK_KERNEL_NOATTACH_MAX_BREAKPOINTS 4UL
/* 能力明确说明使用 DR 执行断点。 */
#define KSWORD_ARK_KERNEL_NOATTACH_CAP_DR 0x20UL
/* 单步使用目标 TF，由内核异常消费者处理。 */
#define KSWORD_ARK_KERNEL_NOATTACH_CAP_TF 0x40UL
/* 传输由内核异常分发接管，不使用 VMX/SVM。 */
#define KSWORD_ARK_KERNEL_NOATTACH_CAP_EXCEPTION 0x80UL
/* 首次成功安装后保留转接代码和模块引用到重启。 */
#define KSWORD_ARK_KERNEL_NOATTACH_CAP_BOOT_RESIDENT 0x100UL
/* 行配置已接受，仍在等待目标线程实际提交。 */
#define KSWORD_ARK_KERNEL_NOATTACH_BP_PENDING 0x400UL
/* 同一份字段定义，没有另造 R0/R3 结构副本。 */
typedef KSWORD_ARK_HVM_NOATTACH_REQUEST KSWORD_ARK_KERNEL_NOATTACH_REQUEST;
/* 原因 1 为主动 TF 暂停，2 为 TF 单步，3 为 DR 命中，4 为上下文提交。 */
typedef KSWORD_ARK_HVM_NOATTACH_RESPONSE KSWORD_ARK_KERNEL_NOATTACH_RESPONSE;
