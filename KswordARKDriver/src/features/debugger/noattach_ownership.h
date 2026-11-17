#pragma once
#include <ntddk.h>

/* 一次只允许一个无附加执行后端取得停止权。 */
#define KNA_OWNER_HVM 1L
/* 普通异常通道不要求 VMX/SVM 支持。 */
#define KNA_OWNER_KERNEL 2L
/* CAS 在各自控制锁外形成跨后端预约。 */
BOOLEAN KswordARKNoAttachTryReserve(LONG Backend);
/* 旧持有者不能释放另一后端的新预约。 */
VOID KswordARKNoAttachRelease(LONG Backend);
/* 普通 HVM 修改也必须尊重无附加会话所有权。 */
BOOLEAN KswordARKNoAttachReserved(VOID);
/* 已核对的同模块永久留驻门可以被 HVM 生命周期借用。 */
BOOLEAN KswordARKKernelNoAttachDriverPinned(PDRIVER_OBJECT Driver, PDRIVER_UNLOAD *Original);
