/*++

Module Name:

    network_inventory_nsi.c

Abstract:

    Read-only TCP and UDP endpoint collection through the netio NSI provider.

Environment:

    Kernel mode, PASSIVE_LEVEL only

--*/

#include "network_inventory_internal.h"

#define KSWORD_ARK_NSI_STORE_ACTIVE 1UL
#define KSWORD_ARK_NSI_TCP_ALL_TABLE 3UL
#define KSWORD_ARK_NSI_UDP_ENDPOINT_TABLE 1UL
#define KSWORD_ARK_NSI_TCP_DYNAMIC_BYTES_CURRENT 24UL
#define KSWORD_ARK_NSI_TCP_DYNAMIC_BYTES_LEGACY 16UL
#define KSWORD_ARK_NSI_TCP_STATIC_BYTES 32UL
#define KSWORD_ARK_NSI_UDP_STATIC_BYTES 32UL
#define KSWORD_ARK_NSI_MODULE_ID_GUID 1UL

#define KSWORD_ARK_NSI_AF_INET 2U
#define KSWORD_ARK_NSI_AF_INET6 23U
#define KSWORD_ARK_NSI_IPPROTO_TCP 6UL
#define KSWORD_ARK_NSI_IPPROTO_UDP 17UL

typedef struct _KSWORD_ARK_NSI_MODULE_ID
{
    USHORT Length;
    ULONG Type;
    GUID Guid;
} KSWORD_ARK_NSI_MODULE_ID;

typedef struct _KSWORD_ARK_NSI_SOCKADDR_V4
{
    USHORT Family;
    USHORT Port;
    ULONG Address;
    UCHAR Zero[8];
} KSWORD_ARK_NSI_SOCKADDR_V4;

typedef struct _KSWORD_ARK_NSI_SOCKADDR_V6
{
    USHORT Family;
    USHORT Port;
    ULONG FlowInfo;
    UCHAR Address[16];
    ULONG ScopeId;
} KSWORD_ARK_NSI_SOCKADDR_V6;

typedef union _KSWORD_ARK_NSI_SOCKADDR
{
    KSWORD_ARK_NSI_SOCKADDR_V4 Ipv4;
    KSWORD_ARK_NSI_SOCKADDR_V6 Ipv6;
    UCHAR Bytes[28];
} KSWORD_ARK_NSI_SOCKADDR;

typedef struct _KSWORD_ARK_NSI_TCP_KEY
{
    KSWORD_ARK_NSI_SOCKADDR Local;
    KSWORD_ARK_NSI_SOCKADDR Remote;
} KSWORD_ARK_NSI_TCP_KEY;

typedef struct _KSWORD_ARK_NSI_TCP_STATIC
{
    ULONG Reserved0[3];
    ULONG ProcessId;
    ULONG64 CreateTime;
    ULONG64 ModuleInfo;
} KSWORD_ARK_NSI_TCP_STATIC;

typedef struct _KSWORD_ARK_NSI_UDP_STATIC
{
    ULONG ProcessId;
    ULONG Reserved0;
    ULONG64 CreateTime;
    ULONG Flags;
    ULONG Reserved1;
    ULONG64 ModuleInfo;
} KSWORD_ARK_NSI_UDP_STATIC;

// 中文说明：NSI 未公开 ABI 必须由严格布局断言保护，尺寸漂移时直接编译失败。
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_NSI_MODULE_ID, Type) == 4);
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_NSI_MODULE_ID, Guid) == 8);
C_ASSERT(sizeof(KSWORD_ARK_NSI_MODULE_ID) == 24);
C_ASSERT(sizeof(KSWORD_ARK_NSI_SOCKADDR_V4) == 16);
C_ASSERT(sizeof(KSWORD_ARK_NSI_SOCKADDR_V6) == 28);
C_ASSERT(sizeof(KSWORD_ARK_NSI_SOCKADDR) == 28);
C_ASSERT(sizeof(KSWORD_ARK_NSI_TCP_KEY) == 56);
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_NSI_TCP_STATIC, ProcessId) == 12);
C_ASSERT(sizeof(KSWORD_ARK_NSI_TCP_STATIC) == 32);
C_ASSERT(sizeof(KSWORD_ARK_NSI_UDP_STATIC) == 32);

// {EB004A03-9B1A-11D4-9123-0050047759BC}
static const KSWORD_ARK_NSI_MODULE_ID KSWORD_ARK_NSI_TCP_MODULE_ID =
{
    sizeof(KSWORD_ARK_NSI_MODULE_ID),
    KSWORD_ARK_NSI_MODULE_ID_GUID,
    { 0xeb004a03, 0x9b1a, 0x11d4, { 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc } }
};

// {EB004A02-9B1A-11D4-9123-0050047759BC}
static const KSWORD_ARK_NSI_MODULE_ID KSWORD_ARK_NSI_UDP_MODULE_ID =
{
    sizeof(KSWORD_ARK_NSI_MODULE_ID),
    KSWORD_ARK_NSI_MODULE_ID_GUID,
    { 0xeb004a02, 0x9b1a, 0x11d4, { 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc } }
};

// 中文说明：netio.lib 导出该未文档化只读入口；所有尺寸均由上方 C_ASSERT 和运行时
// ERROR_INSUFFICIENT_BUFFER 式失败保护，绝不按未知布局解析返回缓冲。
NTSYSAPI
NTSTATUS
NTAPI
NsiAllocateAndGetTable(
    _In_ ULONG Store,
    _In_ const KSWORD_ARK_NSI_MODULE_ID* ModuleId,
    _In_ ULONG TableId,
    _Outptr_result_bytebuffer_maybenull_(*CountOut * KeyEntrySize) PVOID* KeyTableOut,
    _In_ ULONG KeyEntrySize,
    _Outptr_result_bytebuffer_maybenull_(*CountOut * ReadWriteEntrySize) PVOID* ReadWriteTableOut,
    _In_ ULONG ReadWriteEntrySize,
    _Outptr_result_bytebuffer_maybenull_(*CountOut * DynamicEntrySize) PVOID* DynamicTableOut,
    _In_ ULONG DynamicEntrySize,
    _Outptr_result_bytebuffer_maybenull_(*CountOut * StaticEntrySize) PVOID* StaticTableOut,
    _In_ ULONG StaticEntrySize,
    _Out_ ULONG* CountOut,
    _In_ ULONG Reserved
    );

NTSYSAPI
VOID
NTAPI
NsiFreeTable(
    _In_opt_ PVOID KeyTable,
    _In_opt_ PVOID ReadWriteTable,
    _In_opt_ PVOID DynamicTable,
    _In_opt_ PVOID StaticTable
    );

static ULONG
KswordARKNetworkNsiAddressFamily(
    _In_ const KSWORD_ARK_NSI_SOCKADDR* Address
    )
{
    if (Address == NULL) {
        return KSWORD_ARK_NETWORK_ADDRESS_FAMILY_UNKNOWN;
    }
    if (Address->Ipv4.Family == KSWORD_ARK_NSI_AF_INET) {
        return KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4;
    }
    if (Address->Ipv6.Family == KSWORD_ARK_NSI_AF_INET6) {
        return KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6;
    }
    return KSWORD_ARK_NETWORK_ADDRESS_FAMILY_UNKNOWN;
}

static BOOLEAN
KswordARKNetworkNsiFamilyRequested(
    _In_ ULONG AddressFamily,
    _In_ ULONG QueryFlags
    )
{
    if (AddressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4) {
        return (QueryFlags & KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_IPV4) != 0UL;
    }
    if (AddressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6) {
        return (QueryFlags & KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_IPV6) != 0UL;
    }
    return FALSE;
}

static VOID
KswordARKNetworkNsiCopyAddress(
    _Out_writes_(16) UCHAR Destination[16],
    _In_ const KSWORD_ARK_NSI_SOCKADDR* Source,
    _In_ ULONG AddressFamily
    )
{
    RtlZeroMemory(Destination, 16U);
    if (AddressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4) {
        RtlCopyMemory(Destination, &Source->Ipv4.Address, sizeof(Source->Ipv4.Address));
    }
    else if (AddressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6) {
        RtlCopyMemory(Destination, Source->Ipv6.Address, sizeof(Source->Ipv6.Address));
    }
}

static USHORT
KswordARKNetworkNsiHostPort(
    _In_ const KSWORD_ARK_NSI_SOCKADDR* Address
    )
{
    return (Address != NULL) ? RtlUshortByteSwap(Address->Ipv4.Port) : 0U;
}

static VOID
KswordARKNetworkNsiFreeSnapshot(
    _In_opt_ PVOID KeyTable,
    _In_opt_ PVOID ReadWriteTable,
    _In_opt_ PVOID DynamicTable,
    _In_opt_ PVOID StaticTable
    )
{
    if (KeyTable != NULL || ReadWriteTable != NULL || DynamicTable != NULL || StaticTable != NULL) {
        NsiFreeTable(KeyTable, ReadWriteTable, DynamicTable, StaticTable);
    }
}

NTSTATUS
KswordARKNetworkCollectNsiEndpoints(
    _In_ BOOLEAN TcpTable,
    _In_ ULONG QueryFlags,
    _Out_writes_opt_(RowCapacity) KSWORD_ARK_NETWORK_ENDPOINT_ROW* Rows,
    _In_ ULONG RowCapacity,
    _Out_ ULONG* TotalRowsOut,
    _Out_ ULONG* ReturnedRowsOut
    )
/*++

Routine Description:

    使用 netio.sys 的只读 NSI provider 快照取得 TCP/UDP 表。该路径与 IP Helper
    使用同一数据源，不遍历 tcpip 私有链表；无法证明的对象/LUID 字段保持为零并
    由 PDB_UNAVAILABLE/FIELD_MISSING 标记。

Return Value:

    STATUS_SUCCESS 仅表示完整 NSI 快照成功。尺寸不匹配或 provider 失败时不返回
    半解析行，由调用方写入显式降级状态。

--*/
{
    const KSWORD_ARK_NSI_MODULE_ID* moduleId =
        TcpTable ? &KSWORD_ARK_NSI_TCP_MODULE_ID : &KSWORD_ARK_NSI_UDP_MODULE_ID;
    const ULONG tableId = TcpTable ? KSWORD_ARK_NSI_TCP_ALL_TABLE : KSWORD_ARK_NSI_UDP_ENDPOINT_TABLE;
    const ULONG keySize = TcpTable ? sizeof(KSWORD_ARK_NSI_TCP_KEY) : sizeof(KSWORD_ARK_NSI_SOCKADDR);
    const ULONG staticSize = TcpTable ? KSWORD_ARK_NSI_TCP_STATIC_BYTES : KSWORD_ARK_NSI_UDP_STATIC_BYTES;
    const ULONG dynamicCandidates[] =
    {
        KSWORD_ARK_NSI_TCP_DYNAMIC_BYTES_CURRENT,
        KSWORD_ARK_NSI_TCP_DYNAMIC_BYTES_LEGACY
    };
    PVOID keyTable = NULL;
    PVOID readWriteTable = NULL;
    PVOID dynamicTable = NULL;
    PVOID staticTable = NULL;
    ULONG dynamicSize = TcpTable ? dynamicCandidates[0] : 0UL;
    ULONG count = 0UL;
    ULONG recognizedFamilyRows = 0UL;
    ULONG candidateIndex = 0UL;
    ULONG index = 0UL;
    ULONG totalRows = 0UL;
    ULONG returnedRows = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (TotalRowsOut == NULL || ReturnedRowsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TotalRowsOut = 0UL;
    *ReturnedRowsOut = 0UL;
    if (Rows == NULL && RowCapacity != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    for (candidateIndex = 0UL;
         candidateIndex < (TcpTable ? RTL_NUMBER_OF(dynamicCandidates) : 1UL);
         ++candidateIndex) {
        dynamicSize = TcpTable ? dynamicCandidates[candidateIndex] : 0UL;
        keyTable = NULL;
        readWriteTable = NULL;
        dynamicTable = NULL;
        staticTable = NULL;
        count = 0UL;

        status = NsiAllocateAndGetTable(
            KSWORD_ARK_NSI_STORE_ACTIVE,
            moduleId,
            tableId,
            &keyTable,
            keySize,
            &readWriteTable,
            0UL,
            &dynamicTable,
            dynamicSize,
            &staticTable,
            staticSize,
            &count,
            0UL);
        if (status == STATUS_SUCCESS) {
            break;
        }

        KswordARKNetworkNsiFreeSnapshot(keyTable, readWriteTable, dynamicTable, staticTable);
    }

    if (status != STATUS_SUCCESS) {
        return status;
    }
    if (count != 0UL &&
        (keyTable == NULL || staticTable == NULL || (TcpTable && dynamicTable == NULL))) {
        KswordARKNetworkNsiFreeSnapshot(keyTable, readWriteTable, dynamicTable, staticTable);
        return STATUS_DATA_ERROR;
    }

    // 先验证 key ABI，再做查询族筛选；合法但未被请求的地址族不是 ABI 错误。
    for (index = 0UL; index < count; ++index) {
        const UCHAR* keyBytes = (const UCHAR*)keyTable + ((SIZE_T)index * keySize);
        const KSWORD_ARK_NSI_SOCKADDR* localAddress =
            (const KSWORD_ARK_NSI_SOCKADDR*)keyBytes;
        const ULONG addressFamily = KswordARKNetworkNsiAddressFamily(localAddress);

        if (addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4 ||
            addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6) {
            recognizedFamilyRows += 1UL;
        }
    }
    if (count != 0UL && recognizedFamilyRows == 0UL) {
        KswordARKNetworkNsiFreeSnapshot(keyTable, readWriteTable, dynamicTable, staticTable);
        return STATUS_DATA_ERROR;
    }

    for (index = 0UL; index < count; ++index) {
        const UCHAR* keyBytes = (const UCHAR*)keyTable + ((SIZE_T)index * keySize);
        const KSWORD_ARK_NSI_SOCKADDR* localAddress = (const KSWORD_ARK_NSI_SOCKADDR*)keyBytes;
        const KSWORD_ARK_NSI_SOCKADDR* remoteAddress = TcpTable ?
            (const KSWORD_ARK_NSI_SOCKADDR*)(keyBytes + sizeof(KSWORD_ARK_NSI_SOCKADDR)) : NULL;
        const ULONG addressFamily = KswordARKNetworkNsiAddressFamily(localAddress);
        KSWORD_ARK_NETWORK_ENDPOINT_ROW* row = NULL;

        if (!KswordARKNetworkNsiFamilyRequested(addressFamily, QueryFlags)) {
            continue;
        }

        totalRows += 1UL;
        if (Rows == NULL || returnedRows >= RowCapacity) {
            continue;
        }

        row = &Rows[returnedRows];
        RtlZeroMemory(row, sizeof(*row));
        row->rowId = returnedRows;
        row->addressFamily = addressFamily;
        row->protocol = TcpTable ? KSWORD_ARK_NSI_IPPROTO_TCP : KSWORD_ARK_NSI_IPPROTO_UDP;
        row->flags =
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING;
        row->sourceFlags = KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
        row->localPort = KswordARKNetworkNsiHostPort(localAddress);
        KswordARKNetworkNsiCopyAddress(row->localAddress, localAddress, addressFamily);

        if (TcpTable) {
            const KSWORD_ARK_NSI_TCP_STATIC* staticRow =
                (const KSWORD_ARK_NSI_TCP_STATIC*)((const UCHAR*)staticTable +
                    ((SIZE_T)index * staticSize));
            /* NSI may accept a size that does not describe its actual stride.
             * Until calibrated, do not publish an unverified TCP state. */
            row->state = KSWORD_ARK_NETWORK_TCP_STATE_UNKNOWN;
            row->owningPid = staticRow->ProcessId;
            row->remotePort = KswordARKNetworkNsiHostPort(remoteAddress);
            KswordARKNetworkNsiCopyAddress(row->remoteAddress, remoteAddress, addressFamily);
        }
        else {
            const KSWORD_ARK_NSI_UDP_STATIC* staticRow =
                (const KSWORD_ARK_NSI_UDP_STATIC*)((const UCHAR*)staticTable +
                    ((SIZE_T)index * staticSize));
            row->state = KSWORD_ARK_NETWORK_TCP_STATE_UNKNOWN;
            row->owningPid = staticRow->ProcessId;
        }

        if (row->owningPid == 0UL) {
            row->flags |= KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN;
        }
        returnedRows += 1UL;
    }

    if (totalRows > returnedRows && Rows != NULL) {
        for (index = 0UL; index < returnedRows; ++index) {
            Rows[index].flags |= KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED;
        }
    }

    KswordARKNetworkNsiFreeSnapshot(keyTable, readWriteTable, dynamicTable, staticTable);
    *TotalRowsOut = totalRows;
    *ReturnedRowsOut = returnedRows;
    return STATUS_SUCCESS;
}
