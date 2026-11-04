/*++

Module Name:

    section_support.c

Abstract:

    Shared Section/ControlArea helper routines for Phase-7 queries.

    ControlArea mapping walks run under EX_SPIN_LOCK at DISPATCH_LEVEL.  Two
    containment tools stop working there: MmCopyMemory requires APC_LEVEL or
    below, and __try/__except cannot catch an invalid kernel dereference — the
    fault bugchecks instead of raising.  Everything that can be validated is
    therefore validated before the lock is taken, and the walk itself only
    touches memory that MmIsAddressValid confirms is resident.

Environment:

    Kernel-mode Driver Framework

--*/

#include "section_support.h"
#include "../../platform/kernel_object_probe.h"

#define KSW_SECTION_MAPPING_HARD_WALK_LIMIT 4096UL

/*
 * EPROCESS 是不透明结构，UniqueProcessId 的偏移随版本变化。中文说明：
 * PsGetProcessId 会读到对象内部，因此常驻探测覆盖一段保守长度，而不是只
 * 探测首个指针。
 */
#define KSW_SECTION_EPROCESS_PROBE_BYTES 0x800U

typedef struct _MMVAD_SHORT
{
    union _KSW_MMVAD_SHORT_NODE_UNION
    {
        struct _KSW_MMVAD_SHORT_NODE_FIELDS
        {
            struct _MMVAD_SHORT* NextVad;
            PVOID ExtraCreateInfo;
        } NodeFields;
        RTL_BALANCED_NODE VadNode;
    } NodeUnion;
    ULONG StartingVpn;
    ULONG EndingVpn;
#ifdef _WIN64
    UCHAR StartingVpnHigh;
    UCHAR EndingVpnHigh;
    UCHAR CommitChargeHigh;
    union _KSW_MMVAD_SHORT_HIGHER_UNION
    {
        UCHAR SpareNT64VadUChar;
        struct _KSW_MMVAD_SHORT_HIGHER_FIELDS
        {
            UCHAR EndingVpnHigher : 4;
            UCHAR CommitChargeHigher : 4;
        } HigherFields;
    } HigherUnion;
#endif
    LONG ReferenceCount;
    EX_PUSH_LOCK PushLock;
    ULONG LongFlags;
    ULONG LongFlags1;
#ifdef _WIN64
    union _KSW_MMVAD_SHORT_U5
    {
        ULONG_PTR EventListULongPtr;
        UCHAR StartingVpnHigher : 4;
    } u5;
#else
    PVOID EventList;
#endif
} MMVAD_SHORT, *PMMVAD_SHORT;

typedef struct _MMVAD
{
    MMVAD_SHORT Core;
    ULONG LongFlags2;
    PVOID Subsection;
    PVOID FirstPrototypePte;
    PVOID LastContiguousPte;
    LIST_ENTRY ViewLinks;
    union _KSW_MMVAD_PROCESS_UNION
    {
        PEPROCESS VadsProcess;
        UCHAR ViewMapType : 3;
    } ProcessUnion;
} MMVAD, *PMMVAD;

typedef NTSTATUS
(NTAPI* KSW_PS_REFERENCE_PROCESS_FILE_POINTER_FN)(
    _In_ PEPROCESS Process,
    _Outptr_ PFILE_OBJECT* FileObject
    );

static BOOLEAN
KswordARKSectionMappingWalkIsSafe(
    _In_ PVOID ControlArea,
    _In_ const KSW_DYN_STATE* DynState,
    _Outptr_ PEX_SPIN_LOCK* LockOut,
    _Outptr_ PLIST_ENTRY* ListHeadOut
    )
/*++

Routine Description:

    在升 IRQL 之前完成所有可做的校验。中文说明：偏移必须来自可用的
    DynData；锁与链表头必须整体落在常驻内存内；链表头与两个邻接节点必须
    通过 fault-tolerant 读互相自洽。任何一项不成立都拒绝进入自旋锁。

Return Value:

    TRUE 表示可以安全获取自旋锁并遍历。

--*/
{
    PEX_SPIN_LOCK lock = NULL;
    PLIST_ENTRY listHead = NULL;

    if (LockOut == NULL || ListHeadOut == NULL) {
        return FALSE;
    }
    *LockOut = NULL;
    *ListHeadOut = NULL;
    if (ControlArea == NULL || DynState == NULL ||
        !KswordARKSectionIsOffsetPresent(DynState->Kernel.MmControlAreaListHead) ||
        !KswordARKSectionIsOffsetPresent(DynState->Kernel.MmControlAreaLock)) {
        return FALSE;
    }
    lock = (PEX_SPIN_LOCK)((PUCHAR)ControlArea + DynState->Kernel.MmControlAreaLock);
    listHead = (PLIST_ENTRY)((PUCHAR)ControlArea + DynState->Kernel.MmControlAreaListHead);
    if (!KswordARKKernelProbeRangeIsResident(lock, sizeof(*lock)) ||
        !KswordARKKernelProbeRangeIsResident(listHead, sizeof(*listHead)) ||
        !KswordARKKernelProbeListHeadIsSane((ULONG_PTR)listHead)) {
        return FALSE;
    }
    *LockOut = lock;
    *ListHeadOut = listHead;
    return TRUE;
}

static BOOLEAN
KswordARKSectionMappingNodeIsUsable(
    _In_ PLIST_ENTRY Link,
    _Outptr_ PMMVAD* VadOut
    )
/*++

Routine Description:

    锁内逐节点校验。中文说明：链表节点与其宿主 MMVAD 都必须常驻，否则
    立即停止遍历——此刻已在 DISPATCH_LEVEL，错误解引用会直接蓝屏。

Return Value:

    TRUE 表示该节点可以安全读取。

--*/
{
    PMMVAD vad = NULL;

    if (VadOut == NULL) {
        return FALSE;
    }
    *VadOut = NULL;
    if (!KswordARKKernelProbeRangeIsResident(Link, sizeof(*Link))) {
        return FALSE;
    }
    vad = CONTAINING_RECORD(Link, MMVAD, ViewLinks);
    if (!KswordARKKernelProbeRangeIsResident(vad, sizeof(*vad))) {
        return FALSE;
    }
    *VadOut = vad;
    return TRUE;
}

BOOLEAN
KswordARKSectionIsOffsetPresent(
    _In_ ULONG Offset
    )
/*++

Routine Description:

    判断 DynData offset 是否可用。中文说明：Section/ControlArea 是私有结构，
    任何字段缺失都必须 fail closed，不能按 Windows build 猜测。

Arguments:

    Offset - DynData 中的字段偏移。

Return Value:

    TRUE 表示 offset 可用；FALSE 表示字段不可用。

--*/
{
    return (Offset != KSW_DYN_OFFSET_UNAVAILABLE && Offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

ULONG
KswordARKSectionNormalizeOffset(
    _In_ ULONG Offset
    )
/*++

Routine Description:

    转换 offset 诊断值。中文说明：R3 只展示 offset，不把 offset 作为后续
    内核对象操作凭据。

Arguments:

    Offset - 原始 DynData offset。

Return Value:

    可展示 offset，或 KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE。

--*/
{
    if (!KswordARKSectionIsOffsetPresent(Offset)) {
        return KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
    }

    return Offset;
}

VOID
KswordARKSectionPrepareOffsets(
    _Inout_ KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE* Response,
    _In_ const KSW_DYN_STATE* DynState
    )
/*++

Routine Description:

    把 Section 相关 DynData 诊断字段复制到响应包。中文说明：这些字段帮助 UI
    显示当前 profile 是否满足 Phase-7，不参与对象引用。

Arguments:

    Response - 可写响应包。
    DynState - DynData 快照。

Return Value:

    None. 本函数没有返回值。

--*/
{
    if (Response == NULL || DynState == NULL) {
        return;
    }

    Response->dynDataCapabilityMask = DynState->CapabilityMask;
    Response->epSectionObjectOffset = KswordARKSectionNormalizeOffset(DynState->Kernel.EpSectionObject);
    Response->mmSectionControlAreaOffset = KswordARKSectionNormalizeOffset(DynState->Kernel.MmSectionControlArea);
    Response->mmControlAreaListHeadOffset = KswordARKSectionNormalizeOffset(DynState->Kernel.MmControlAreaListHead);
    Response->mmControlAreaLockOffset = KswordARKSectionNormalizeOffset(DynState->Kernel.MmControlAreaLock);
}

BOOLEAN
KswordARKSectionHasRequiredDynData(
    _In_ const KSW_DYN_STATE* DynState
    )
/*++

Routine Description:

    检查 Section/ControlArea 查询能力。中文说明：这里要求完整
    KSW_CAP_SECTION_CONTROL_AREA，避免只读到 SectionObject 却误入映射枚举。

Arguments:

    DynState - DynData 快照。

Return Value:

    TRUE 表示 capability 满足；FALSE 表示不可查询。

--*/
{
    if (DynState == NULL) {
        return FALSE;
    }

    return ((DynState->CapabilityMask & KSW_CAP_SECTION_CONTROL_AREA) == KSW_CAP_SECTION_CONTROL_AREA) ? TRUE : FALSE;
}

NTSTATUS
KswordARKSectionReferenceProcessImageControlArea(
    _In_ PEPROCESS ProcessObject,
    _Outptr_result_maybenull_ PFILE_OBJECT* FileObjectOut,
    _Outptr_result_maybenull_ PVOID* ControlAreaOut
    )
/*++

Routine Description:

    Resolve the process image ControlArea without EPROCESS.SectionObject or
    SECTION.ControlArea offsets.  PsReferenceProcessFilePointer supplies a
    referenced FILE_OBJECT, whose public SectionObjectPointer projection owns
    the image ControlArea pointer.  The caller releases FileObjectOut.

--*/
{
    UNICODE_STRING routineName;
    KSW_PS_REFERENCE_PROCESS_FILE_POINTER_FN referenceFile = NULL;
    PFILE_OBJECT fileObject = NULL;
    PSECTION_OBJECT_POINTERS sectionPointers = NULL;
    PVOID controlArea = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (ProcessObject == NULL || FileObjectOut == NULL || ControlAreaOut == NULL ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    *FileObjectOut = NULL;
    *ControlAreaOut = NULL;
    RtlInitUnicodeString(&routineName, L"PsReferenceProcessFilePointer");
    referenceFile = (KSW_PS_REFERENCE_PROCESS_FILE_POINTER_FN)
        MmGetSystemRoutineAddress(&routineName);
    if (referenceFile == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    status = referenceFile(ProcessObject, &fileObject);
    if (!NT_SUCCESS(status) || fileObject == NULL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }
    __try {
        sectionPointers = fileObject->SectionObjectPointer;
        if (sectionPointers != NULL) {
            controlArea = sectionPointers->ImageSectionObject;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status) || controlArea == NULL) {
        ObDereferenceObject(fileObject);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }
    *FileObjectOut = fileObject;
    *ControlAreaOut = controlArea;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKSectionReadPointerField(
    _In_ PVOID Object,
    _In_ ULONG Offset,
    _Outptr_result_maybenull_ PVOID* PointerOut
    )
/*++

Routine Description:

    安全读取指针字段。中文说明：所有私有字段读取都用 SEH 包裹，目标进程
    退出或字段异常时返回错误码。

Arguments:

    Object - 结构基址。
    Offset - 字段偏移。
    PointerOut - 接收指针。

Return Value:

    STATUS_SUCCESS 或异常 NTSTATUS。

--*/
{
    PVOID pointerValue = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Object == NULL || PointerOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKSectionIsOffsetPresent(Offset)) {
        return STATUS_NOT_SUPPORTED;
    }

    __try {
        RtlCopyMemory(&pointerValue, (PUCHAR)Object + Offset, sizeof(pointerValue));
        *PointerOut = pointerValue;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static PVOID
KswordARKSectionVadStartAddress(
    _In_ PMMVAD Vad
    )
/*++

Routine Description:

    按 System Informer 的 MiGetVadStartAddress 公式计算 VAD 起始地址。中文说明：
    LA57 高位由 MMVAD_SHORT.u5.StartingVpnHigher 吸收，不按系统版本猜测。

Arguments:

    Vad - ControlArea 链表中的 MMVAD。

Return Value:

    VAD 起始虚拟地址。

--*/
{
#ifdef _WIN64
    ULONG_PTR higher = Vad->Core.u5.StartingVpnHigher;
    ULONG_PTR high = Vad->Core.StartingVpnHigh;
    ULONG_PTR low = Vad->Core.StartingVpn;
    return (PVOID)((low | ((high | (higher << 8)) << 32)) << PAGE_SHIFT);
#else
    return (PVOID)((ULONG_PTR)Vad->Core.StartingVpn << PAGE_SHIFT);
#endif
}

static PVOID
KswordARKSectionVadEndAddress(
    _In_ PMMVAD Vad
    )
/*++

Routine Description:

    按 System Informer 的 MiGetVadEndAddress 公式计算 VAD 结束地址。中文说明：
    返回的是区间末尾后一页边界，便于 UI 显示映射范围。

Arguments:

    Vad - ControlArea 链表中的 MMVAD。

Return Value:

    VAD 结束虚拟地址。

--*/
{
#ifdef _WIN64
    ULONG_PTR higher = Vad->Core.HigherUnion.HigherFields.EndingVpnHigher;
    ULONG_PTR high = Vad->Core.EndingVpnHigh;
    ULONG_PTR low = Vad->Core.EndingVpn;
    return (PVOID)(((low + 1) | ((high | (higher << 8)) << 32)) << PAGE_SHIFT);
#else
    return (PVOID)(((ULONG_PTR)Vad->Core.EndingVpn + 1) << PAGE_SHIFT);
#endif
}

NTSTATUS
KswordARKSectionReadProcessSectionObject(
    _In_ PEPROCESS ProcessObject,
    _In_ const KSW_DYN_STATE* DynState,
    _Outptr_result_maybenull_ PVOID* SectionObjectOut
    )
/*++

Routine Description:

    从 EPROCESS.SectionObject 读取目标进程主映像 SectionObject。中文说明：此处
    只接受 PID 查到的 EPROCESS，不接受 R3 传入的任意 EPROCESS/Section 地址。

Arguments:

    ProcessObject - 已引用目标 EPROCESS。
    DynState - DynData 快照。
    SectionObjectOut - 接收 SectionObject 指针。

Return Value:

    STATUS_SUCCESS 或读取错误。

--*/
{
    if (ProcessObject == NULL || DynState == NULL || SectionObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SectionObjectOut = NULL;
    return KswordARKSectionReadPointerField(ProcessObject, DynState->Kernel.EpSectionObject, SectionObjectOut);
}

NTSTATUS
KswordARKSectionReadControlArea(
    _In_ PVOID SectionObject,
    _In_ const KSW_DYN_STATE* DynState,
    _Outptr_result_maybenull_ PVOID* ControlAreaOut,
    _Out_ BOOLEAN* RemoteUnsupportedOut
    )
/*++

Routine Description:

    从 SectionObject 读取 ControlArea。中文说明：低两位带标记的远程映射按
    System Informer 逻辑视为暂不支持，并明确回传状态给 UI。

Arguments:

    SectionObject - EPROCESS.SectionObject 当前指针。
    DynState - DynData 快照。
    ControlAreaOut - 接收 ControlArea。
    RemoteUnsupportedOut - 接收低位标记是否表示 remote mapping unsupported。

Return Value:

    STATUS_SUCCESS、STATUS_NOT_SUPPORTED 或读取错误。

--*/
{
    PVOID rawControlArea = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (ControlAreaOut != NULL) {
        *ControlAreaOut = NULL;
    }
    if (RemoteUnsupportedOut != NULL) {
        *RemoteUnsupportedOut = FALSE;
    }
    if (SectionObject == NULL || DynState == NULL || ControlAreaOut == NULL || RemoteUnsupportedOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKSectionReadPointerField(SectionObject, DynState->Kernel.MmSectionControlArea, &rawControlArea);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (((ULONG_PTR)rawControlArea & 3ULL) != 0ULL) {
        *RemoteUnsupportedOut = TRUE;
        rawControlArea = (PVOID)((ULONG_PTR)rawControlArea & ~3ULL);
        *ControlAreaOut = rawControlArea;
        return STATUS_NOT_SUPPORTED;
    }

    *ControlAreaOut = rawControlArea;
    return (rawControlArea != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS
KswordARKSectionEnumerateMappings(
    _In_ PVOID ControlArea,
    _In_ const KSW_DYN_STATE* DynState,
    _Inout_ KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE* Response,
    _In_ size_t EntryCapacity
    )
/*++

Routine Description:

    枚举 ControlArea 映射链表。中文说明：逻辑照搬 System Informer 的核心模型：
    持有 MmControlAreaLock 共享自旋锁，遍历 MmControlAreaListHead，并从
    MMVAD.ViewLinks 反推进程 PID 与起止地址。

Arguments:

    ControlArea - 已读取的 ControlArea 指针。
    DynState - DynData 快照。
    Response - 可写响应包。
    EntryCapacity - 输出映射条目容量。

Return Value:

    STATUS_SUCCESS 或链表/锁/读取错误。

--*/
{
    PEX_SPIN_LOCK lock = NULL;
    PLIST_ENTRY listHead = NULL;
    PLIST_ENTRY link = NULL;
    KIRQL oldIrql = 0;
    BOOLEAN lockHeld = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    ULONG walked = 0UL;

    if (ControlArea == NULL || DynState == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：所有可在低 IRQL 完成的校验都必须发生在取锁之前。 */
    if (!KswordARKSectionMappingWalkIsSafe(
            ControlArea,
            DynState,
            &lock,
            &listHead)) {
        return STATUS_NOT_SUPPORTED;
    }

    oldIrql = ExAcquireSpinLockShared(lock);
    lockHeld = TRUE;

    for (link = listHead->Flink; link != listHead; link = link->Flink) {
        PMMVAD vad = NULL;

        /* 中文说明：成环但自洽的链表会让 DISPATCH_LEVEL 遍历永不返回。 */
        if (walked >= KSW_SECTION_MAPPING_HARD_WALK_LIMIT) {
            Response->fieldFlags |= KSWORD_ARK_SECTION_FIELD_MAPPING_TRUNCATED;
            break;
        }
        walked += 1UL;
        if (!KswordARKSectionMappingNodeIsUsable(link, &vad)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (Response->totalCount != MAXULONG) {
            Response->totalCount += 1UL;
        }

        if ((size_t)Response->returnedCount < EntryCapacity) {
            KSWORD_ARK_SECTION_MAPPING_ENTRY* entry = &Response->mappings[Response->returnedCount];
            RtlZeroMemory(entry, sizeof(*entry));
            entry->viewMapType = (ULONG)vad->ProcessUnion.ViewMapType;
            /* 私有 VAD 布局不匹配时不可把无效范围发布为有效映射。 */
            entry->startVa = (ULONG64)(ULONG_PTR)KswordARKSectionVadStartAddress(vad);
            entry->endVa = (ULONG64)(ULONG_PTR)KswordARKSectionVadEndAddress(vad);
            if (entry->startVa == 0ULL || entry->startVa >= entry->endVa) {
                status = STATUS_DATA_ERROR;
                break;
            }
            if (vad->ProcessUnion.ViewMapType == KSWORD_ARK_SECTION_MAP_TYPE_PROCESS) {
                PEPROCESS mappedProcess = (PEPROCESS)((ULONG_PTR)vad->ProcessUnion.VadsProcess & ~(ULONG_PTR)KSWORD_ARK_SECTION_MAP_TYPE_PROCESS);
                if (KswordARKKernelProbeRangeIsResident(
                        mappedProcess,
                        KSW_SECTION_EPROCESS_PROBE_BYTES)) {
                    entry->processId = HandleToULong(PsGetProcessId(mappedProcess));
                }
            }
            Response->returnedCount += 1UL;
        }

        if (!KswordARKKernelProbeRangeIsResident(link->Flink, sizeof(*link)) ||
            link->Flink->Blink != link) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }

    if (lockHeld) {
        ExReleaseSpinLockShared(lock, oldIrql);
        lockHeld = FALSE;
    }

    if (NT_SUCCESS(status)) {
        Response->fieldFlags |= KSWORD_ARK_SECTION_FIELD_MAPPING_LIST_PRESENT;
        if (Response->returnedCount < Response->totalCount) {
            Response->fieldFlags |= KSWORD_ARK_SECTION_FIELD_MAPPING_TRUNCATED;
        }
    }

    return status;
}

NTSTATUS
KswordARKSectionEnumerateFileControlAreaMappings(
    _In_ PVOID ControlArea,
    _In_ ULONG SectionKind,
    _In_ const KSW_DYN_STATE* DynState,
    _Inout_ KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE* Response,
    _In_ size_t EntryCapacity
    )
/*++

Routine Description:

    枚举文件 Data/Image ControlArea 的映射链表。中文说明：FileObject 的
    SECTION_OBJECT_POINTERS 已直接给出 ControlArea，因此这里不再使用
    MmSectionControlArea 偏移，只复用 MmControlAreaListHead 和 Lock。

Arguments:

    ControlArea - FileObject->SectionObjectPointer 中的 Data/Image ControlArea。
    SectionKind - 当前 ControlArea 类型，Data 或 Image。
    DynState - DynData 快照，提供 ControlArea 链表和锁偏移。
    Response - 可写文件映射响应包。
    EntryCapacity - 输出条目容量上限。

Return Value:

    STATUS_SUCCESS 或链表/锁访问错误。

--*/
{
    PEX_SPIN_LOCK lock = NULL;
    PLIST_ENTRY listHead = NULL;
    PLIST_ENTRY link = NULL;
    KIRQL oldIrql = 0;
    BOOLEAN lockHeld = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    ULONG walked = 0UL;

    if (ControlArea == NULL || DynState == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：所有可在低 IRQL 完成的校验都必须发生在取锁之前。 */
    if (!KswordARKSectionMappingWalkIsSafe(
            ControlArea,
            DynState,
            &lock,
            &listHead)) {
        return STATUS_NOT_SUPPORTED;
    }

    oldIrql = ExAcquireSpinLockShared(lock);
    lockHeld = TRUE;

    for (link = listHead->Flink; link != listHead; link = link->Flink) {
        PMMVAD vad = NULL;

        /* 中文说明：成环但自洽的链表会让 DISPATCH_LEVEL 遍历永不返回。 */
        if (walked >= KSW_SECTION_MAPPING_HARD_WALK_LIMIT) {
            Response->fieldFlags |=
                KSWORD_ARK_FILE_SECTION_FIELD_MAPPING_TRUNCATED;
            break;
        }
        walked += 1UL;
        if (!KswordARKSectionMappingNodeIsUsable(link, &vad)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (Response->totalCount != MAXULONG) {
            Response->totalCount += 1UL;
        }

        if ((size_t)Response->returnedCount < EntryCapacity) {
            KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY* entry = &Response->mappings[Response->returnedCount];
            RtlZeroMemory(entry, sizeof(*entry));
            entry->sectionKind = SectionKind;
            entry->viewMapType = (ULONG)vad->ProcessUnion.ViewMapType;
            entry->controlAreaAddress = (ULONG64)(ULONG_PTR)ControlArea;
            /* 可能是版本不匹配的私有 VAD 布局，拒绝不可能的地址范围。 */
            entry->startVa = (ULONG64)(ULONG_PTR)KswordARKSectionVadStartAddress(vad);
            entry->endVa = (ULONG64)(ULONG_PTR)KswordARKSectionVadEndAddress(vad);
            if (entry->startVa == 0ULL || entry->startVa >= entry->endVa) {
                status = STATUS_DATA_ERROR;
                break;
            }
            if (vad->ProcessUnion.ViewMapType == KSWORD_ARK_SECTION_MAP_TYPE_PROCESS) {
                PEPROCESS mappedProcess = (PEPROCESS)((ULONG_PTR)vad->ProcessUnion.VadsProcess & ~(ULONG_PTR)KSWORD_ARK_SECTION_MAP_TYPE_PROCESS);
                if (KswordARKKernelProbeRangeIsResident(
                        mappedProcess,
                        KSW_SECTION_EPROCESS_PROBE_BYTES)) {
                    entry->processId = HandleToULong(PsGetProcessId(mappedProcess));
                    if (Response->mappedProcessCount != MAXULONG) {
                        Response->mappedProcessCount += 1UL;
                    }
                    if (SectionKind == KSWORD_ARK_FILE_SECTION_KIND_DATA &&
                        Response->dataMappedProcessCount != MAXULONG) {
                        Response->dataMappedProcessCount += 1UL;
                    }
                    if (SectionKind == KSWORD_ARK_FILE_SECTION_KIND_IMAGE &&
                        Response->imageMappedProcessCount != MAXULONG) {
                        Response->imageMappedProcessCount += 1UL;
                    }
                }
            }
            Response->returnedCount += 1UL;
        }

        if (!KswordARKKernelProbeRangeIsResident(link->Flink, sizeof(*link)) ||
            link->Flink->Blink != link) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }

    if (lockHeld) {
        ExReleaseSpinLockShared(lock, oldIrql);
        lockHeld = FALSE;
    }

    if (NT_SUCCESS(status)) {
        Response->fieldFlags |= KSWORD_ARK_FILE_SECTION_FIELD_MAPPING_LIST_PRESENT;
        if (Response->returnedCount < Response->totalCount) {
            Response->fieldFlags |= KSWORD_ARK_FILE_SECTION_FIELD_MAPPING_TRUNCATED;
        }
    }

    return status;
}




