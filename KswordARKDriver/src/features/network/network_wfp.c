/*++

Module Name:

    network_wfp.c

Abstract:

    WFP callout registration and classify implementation for KswordARK.

Environment:

    Kernel-mode WFP

--*/

#include "network_internal.h"



// 本文件只声明当前实现实际用到的 WFP 最小 ABI，避免直接包含 fwpsk.h/ndis.h
// 在当前 WDK/项目 Werror 组合下触发第三方头文件告警。
#define KSWORD_ARK_FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 44U
#define KSWORD_ARK_FWPS_LAYER_ALE_AUTH_CONNECT_V4 48U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS 2U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT 4U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL 5U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS 6U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT 7U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS 2U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT 4U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL 5U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS 6U
#define KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT 7U
#define KSWORD_ARK_FWPS_METADATA_FIELD_PROCESS_ID 0x00000020U
#define KSWORD_ARK_FWPS_RIGHT_ACTION_WRITE 0x00000001U
#define KSWORD_ARK_FWPS_CLASSIFY_OUT_FLAG_ABSORB 0x00000001U
#define KSWORD_ARK_FWPM_SESSION_FLAG_DYNAMIC 0x00000001U
#define KSWORD_ARK_FWP_EMPTY 0U
#define KSWORD_ARK_FWP_UINT8 1U
#define KSWORD_ARK_FWP_UINT16 2U
#define KSWORD_ARK_FWP_UINT32 3U

// 中文说明：下面三个 action type 是 WDK fwptypes.h 暴露给 BFE 的固定 ABI 值。
// 中文说明：FWP_ACTION_* 由低位动作编号叠加 TERMINATING/CALLOUT 标志组成，不能手工
// 写成其它组合；错误值会让 FwpmFilterAdd0 返回 STATUS_FWP_INVALID_ACTION_TYPE。
#define KSWORD_ARK_FWP_ACTION_BLOCK 0x00001001U
#define KSWORD_ARK_FWP_ACTION_PERMIT 0x00001002U
#define KSWORD_ARK_FWP_ACTION_CALLOUT_TERMINATING 0x00005003U
#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10U
#endif

typedef VOID* SEC_WINNT_AUTH_IDENTITY_W_PTR;
typedef UINT32 KSWORD_ARK_FWP_ACTION_TYPE;
typedef UINT32 KSWORD_ARK_FWP_DATA_TYPE;
typedef enum _KSWORD_ARK_FWPS_CALLOUT_NOTIFY_TYPE
{
    KswordArkFwpsCalloutNotifyAddFilter = 0,
    KswordArkFwpsCalloutNotifyDeleteFilter = 1,
    KswordArkFwpsCalloutNotifyTypeMax = 2
} KSWORD_ARK_FWPS_CALLOUT_NOTIFY_TYPE;

typedef struct _KSWORD_ARK_FWP_BYTE_BLOB
{
    UINT32 size;
    UINT8* data;
} KSWORD_ARK_FWP_BYTE_BLOB;

typedef struct _KSWORD_ARK_FWP_BYTE_ARRAY16
{
    UINT8 byteArray16[16];
} KSWORD_ARK_FWP_BYTE_ARRAY16;

typedef struct _KSWORD_ARK_FWP_VALUE0
{
    KSWORD_ARK_FWP_DATA_TYPE type;
    union
    {
        UINT8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64* uint64;
        INT8 int8;
        INT16 int16;
        INT32 int32;
        INT64* int64;
        float float32;
        double* double64;
        KSWORD_ARK_FWP_BYTE_ARRAY16* byteArray16;
        KSWORD_ARK_FWP_BYTE_BLOB* byteBlob;
        VOID* sid;
        UINT8* sd;
        VOID* tokenInformation;
        UINT64* tokenAccessInformation;
        LPWSTR unicodeString;
        KSWORD_ARK_FWP_BYTE_BLOB* byteBlobArray6;
        VOID* bitmapArray64;
    } value;
} KSWORD_ARK_FWP_VALUE0;

typedef struct _KSWORD_ARK_FWPS_INCOMING_VALUE0
{
    // 中文说明：WDK fwpstypes.h 中每项仅包含 value，字段编号由数组索引确定。
    KSWORD_ARK_FWP_VALUE0 value;
} KSWORD_ARK_FWPS_INCOMING_VALUE0;

// 中文说明：禁止引入额外前缀或改变数组步长，否则协议、地址和端口全部错位。
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_FWPS_INCOMING_VALUE0, value) == 0);
C_ASSERT(sizeof(KSWORD_ARK_FWPS_INCOMING_VALUE0) == sizeof(KSWORD_ARK_FWP_VALUE0));

typedef struct _KSWORD_ARK_FWPS_INCOMING_VALUES0
{
    UINT16 layerId;
    UINT32 valueCount;
    KSWORD_ARK_FWPS_INCOMING_VALUE0* incomingValue;
} KSWORD_ARK_FWPS_INCOMING_VALUES0;

// 中文说明：FWPS_INCOMING_METADATA_VALUES0 在 processId 前包含固定的
// FWPS_DISCARD_METADATA0；即使本功能不读取丢弃原因，也不能省略它，否则后续
// processId 会从错误偏移读取。这里只复制官方前缀布局，不依赖后续版本化字段。
typedef struct _KSWORD_ARK_FWPS_DISCARD_METADATA0
{
    UINT32 discardModule;
    UINT32 discardReason;
    UINT64 filterId;
} KSWORD_ARK_FWPS_DISCARD_METADATA0;

typedef struct _KSWORD_ARK_FWPS_INCOMING_METADATA_VALUES0
{
    UINT32 currentMetadataValues;
    UINT32 flags;
    UINT64 reserved;
    KSWORD_ARK_FWPS_DISCARD_METADATA0 discardMetadata;
    UINT64 flowHandle;
    UINT32 ipHeaderSize;
    UINT32 transportHeaderSize;
    VOID* processPath;
    UINT64 token;
    UINT64 processId;
} KSWORD_ARK_FWPS_INCOMING_METADATA_VALUES0;

// 官方 FWPS_INCOMING_METADATA_VALUES0 的稳定前缀中 processId 位于 64 字节处。
// 编译期保护可阻止以后“精简”未使用字段时再次破坏 classify ABI。
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_FWPS_INCOMING_METADATA_VALUES0, processId) == 64);

typedef struct _KSWORD_ARK_FWPS_FILTER0
{
    UINT64 filterId;
    UINT64 weight;
    UINT16 subLayerWeight;
    UINT16 flags;
    UINT32 numFilterConditions;
    VOID* filterCondition;
    KSWORD_ARK_FWP_ACTION_TYPE actionType;
    UINT64 context;
    GUID* providerContextKey;
} KSWORD_ARK_FWPS_FILTER0;

typedef struct _KSWORD_ARK_FWPS_CLASSIFY_OUT0
{
    KSWORD_ARK_FWP_ACTION_TYPE actionType;
    UINT64 outContext;
    UINT64 filterId;
    UINT32 rights;
    UINT32 flags;
    UINT32 reserved;
} KSWORD_ARK_FWPS_CLASSIFY_OUT0;

typedef VOID (NTAPI* KSWORD_ARK_FWPS_CALLOUT_CLASSIFY_FN0)(
    _In_ const KSWORD_ARK_FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const KSWORD_ARK_FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const KSWORD_ARK_FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ KSWORD_ARK_FWPS_CLASSIFY_OUT0* ClassifyOut);

typedef NTSTATUS (NTAPI* KSWORD_ARK_FWPS_CALLOUT_NOTIFY_FN0)(
    _In_ KSWORD_ARK_FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ const KSWORD_ARK_FWPS_FILTER0* Filter);

typedef VOID (NTAPI* KSWORD_ARK_FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0)(
    _In_ UINT16 LayerId,
    _In_ UINT32 CalloutId,
    _In_ UINT64 FlowContext);

typedef struct _KSWORD_ARK_FWPS_CALLOUT0
{
    GUID calloutKey;
    UINT32 flags;
    KSWORD_ARK_FWPS_CALLOUT_CLASSIFY_FN0 classifyFn;
    KSWORD_ARK_FWPS_CALLOUT_NOTIFY_FN0 notifyFn;
    KSWORD_ARK_FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 flowDeleteFn;
} KSWORD_ARK_FWPS_CALLOUT0;

typedef struct _KSWORD_ARK_FWPM_DISPLAY_DATA0
{
    WCHAR* name;
    WCHAR* description;
} KSWORD_ARK_FWPM_DISPLAY_DATA0;

typedef struct _KSWORD_ARK_FWPM_SESSION0
{
    GUID sessionKey;
    KSWORD_ARK_FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    UINT32 txnWaitTimeoutInMSec;
    UINT32 processId;
    VOID* sid;
    WCHAR* username;
    BOOLEAN kernelMode;
} KSWORD_ARK_FWPM_SESSION0;

typedef struct _KSWORD_ARK_FWPM_CALLOUT0
{
    GUID calloutKey;
    KSWORD_ARK_FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    KSWORD_ARK_FWP_BYTE_BLOB providerData;
    GUID applicableLayer;
    UINT32 calloutId;
} KSWORD_ARK_FWPM_CALLOUT0;

// 中文说明：FWPM_ACTION0 的 type 是独立字段，后面才是按 type 解释的 GUID 联合体。
// 中文说明：不能把整个对象声明成 union，否则写 calloutKey 会覆盖 type 并触发
// STATUS_FWP_INVALID_ACTION_TYPE。
typedef struct _KSWORD_ARK_FWPM_ACTION0
{
    // 中文说明：type 保存 BFE 校验的 FWP_ACTION_TYPE，不与 GUID 共享存储。
    KSWORD_ARK_FWP_ACTION_TYPE type;
    union
    {
        // 中文说明：filterType 仅供普通 filter action 使用。
        GUID filterType;
        // 中文说明：calloutKey 标识 CALLOUT action 对应的内核 callout。
        GUID calloutKey;
    } actionKey;
} KSWORD_ARK_FWPM_ACTION0;

// 中文说明：固定检查 WDK FWPM_ACTION0 ABI，避免后续重构再次让 GUID 覆盖 type。
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_FWPM_ACTION0, actionKey) == sizeof(KSWORD_ARK_FWP_ACTION_TYPE));
C_ASSERT(sizeof(KSWORD_ARK_FWPM_ACTION0) == (sizeof(KSWORD_ARK_FWP_ACTION_TYPE) + sizeof(GUID)));

typedef struct _KSWORD_ARK_FWPM_FILTER0
{
    GUID filterKey;
    KSWORD_ARK_FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    KSWORD_ARK_FWP_BYTE_BLOB providerData;
    GUID layerKey;
    GUID subLayerKey;
    KSWORD_ARK_FWP_VALUE0 weight;
    UINT32 numFilterConditions;
    VOID* filterCondition;
    KSWORD_ARK_FWPM_ACTION0 action;
    union
    {
        UINT64 rawContext;
        GUID providerContextKey;
    } rawContextUnion;
    GUID* reserved;
    UINT64 filterId;
    KSWORD_ARK_FWP_VALUE0 effectiveWeight;
} KSWORD_ARK_FWPM_FILTER0;

typedef struct _KSWORD_ARK_FWPM_SUBLAYER0
{
    GUID subLayerKey;
    KSWORD_ARK_FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    KSWORD_ARK_FWP_BYTE_BLOB providerData;
    UINT16 weight;
} KSWORD_ARK_FWPM_SUBLAYER0;

NTSYSAPI
NTSTATUS
NTAPI
FwpsCalloutRegister0(
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _In_ const KSWORD_ARK_FWPS_CALLOUT0* Callout,
    _Out_opt_ UINT32* CalloutId);

NTSYSAPI
NTSTATUS
NTAPI
FwpsCalloutUnregisterById0(
    _In_ UINT32 CalloutId);

NTSYSAPI
NTSTATUS
NTAPI
FwpmEngineOpen0(
    _In_opt_ const WCHAR* ServerName,
    _In_ UINT32 AuthnService,
    _In_opt_ SEC_WINNT_AUTH_IDENTITY_W_PTR AuthIdentity,
    _In_opt_ const KSWORD_ARK_FWPM_SESSION0* Session,
    _Out_ HANDLE* EngineHandle);

NTSYSAPI
NTSTATUS
NTAPI
FwpmEngineClose0(
    _In_ HANDLE EngineHandle);

NTSYSAPI
NTSTATUS
NTAPI
FwpmTransactionBegin0(
    _In_ HANDLE EngineHandle,
    _In_ UINT32 Flags);

NTSYSAPI
NTSTATUS
NTAPI
FwpmTransactionCommit0(
    _In_ HANDLE EngineHandle);

NTSYSAPI
NTSTATUS
NTAPI
FwpmTransactionAbort0(
    _In_ HANDLE EngineHandle);

NTSYSAPI
NTSTATUS
NTAPI
FwpmSubLayerAdd0(
    _In_ HANDLE EngineHandle,
    _In_ const KSWORD_ARK_FWPM_SUBLAYER0* SubLayer,
    _In_opt_ PSECURITY_DESCRIPTOR Sd);

NTSYSAPI
NTSTATUS
NTAPI
FwpmSubLayerDeleteByKey0(
    _In_ HANDLE EngineHandle,
    _In_ const GUID* Key);

NTSYSAPI
NTSTATUS
NTAPI
FwpmCalloutAdd0(
    _In_ HANDLE EngineHandle,
    _In_ const KSWORD_ARK_FWPM_CALLOUT0* Callout,
    _In_opt_ PSECURITY_DESCRIPTOR Sd,
    _Out_opt_ UINT32* Id);

NTSYSAPI
NTSTATUS
NTAPI
FwpmCalloutDeleteByKey0(
    _In_ HANDLE EngineHandle,
    _In_ const GUID* Key);

NTSYSAPI
NTSTATUS
NTAPI
FwpmFilterAdd0(
    _In_ HANDLE EngineHandle,
    _In_ const KSWORD_ARK_FWPM_FILTER0* Filter,
    _In_opt_ PSECURITY_DESCRIPTOR Sd,
    _Out_opt_ UINT64* Id);

NTSYSAPI
NTSTATUS
NTAPI
FwpmFilterDeleteById0(
    _In_ HANDLE EngineHandle,
    _In_ UINT64 Id);

// {D2B28BC6-9E08-4D07-9F7B-2BA821D8AA51}
static const GUID KSWORD_ARK_WFP_SUBLAYER =
{ 0xd2b28bc6, 0x9e08, 0x4d07, { 0x9f, 0x7b, 0x2b, 0xa8, 0x21, 0xd8, 0xaa, 0x51 } };

// {9CEBA6FD-DC43-4E48-A013-FDB83823674B}
static const GUID KSWORD_ARK_WFP_CONNECT_CALLOUT =
{ 0x9ceba6fd, 0xdc43, 0x4e48, { 0xa0, 0x13, 0xfd, 0xb8, 0x38, 0x23, 0x67, 0x4b } };

// {75FCE1D8-0E28-4C58-9957-90181B75B6AA}
static const GUID KSWORD_ARK_WFP_RECV_ACCEPT_CALLOUT =
{ 0x75fce1d8, 0x0e28, 0x4c58, { 0x99, 0x57, 0x90, 0x18, 0x1b, 0x75, 0xb6, 0xaa } };

// {C38D57D1-05A7-4C33-904F-7FBCEEE60E82}
static const GUID KSWORD_ARK_FWPM_LAYER_ALE_AUTH_CONNECT_V4 =
{ 0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };

// {E1CD9FE7-F4B5-4273-96C0-592E487B8650}
static const GUID KSWORD_ARK_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 =
{ 0xe1cd9fe7, 0xf4b5, 0x4273, { 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50 } };

static UINT16
KswordARKNetworkReadHostOrderPort(
    _In_ UINT16 HostOrderValue
    )
/*++

Routine Description:

    读取 WFP FWP_UINT16 端口。中文说明：WFP 规范明确 FWP_UINT16 IP port 使用
    主机字节序，不能再次做字节交换。

Arguments:

    HostOrderValue - WFP 提供的主机字节序 16 位端口。

Return Value:

    主机字节序端口。

--*/
{
    // 中文说明：WFP 已提供主机序，直接返回避免端口反向。
    return HostOrderValue;
}

static ULONG
KswordARKNetworkReadUint32Field(
    _In_ const KSWORD_ARK_FWPS_INCOMING_VALUES0* Values,
    _In_ UINT32 FieldIndex
    )
/*++

Routine Description:

    从 WFP incoming values 读取 UINT32 字段。中文说明：调用方传入层对应字段索引，
    函数只做越界与类型宽度保护。

Arguments:

    Values - WFP classify 输入字段集合。
    FieldIndex - 字段索引。

Return Value:

    字段值；字段不存在时返回 0。

--*/
{
    // 中文说明：WFP 数组指针、索引和稳定 FWP_UINT32 类型必须同时有效。
    if (Values == NULL ||
        Values->incomingValue == NULL ||
        FieldIndex >= Values->valueCount ||
        Values->incomingValue[FieldIndex].value.type != KSWORD_ARK_FWP_UINT32) {
        // 中文说明：字段缺失或 union 类型不符时返回 0，禁止错误解释 union。
        return 0UL;
    }
    // 中文说明：类型已验证，可安全读取 uint32 union 成员。
    return Values->incomingValue[FieldIndex].value.value.uint32;
}

static ULONG
KswordARKNetworkReadUint16Field(
    _In_ const KSWORD_ARK_FWPS_INCOMING_VALUES0* Values,
    _In_ UINT32 FieldIndex
    )
/*++

Routine Description:

    从 WFP incoming values 读取 UINT16 字段。中文说明：端口字段按 WFP 定义读取，
    再由调用方决定是否做字节序转换。

Arguments:

    Values - WFP classify 输入字段集合。
    FieldIndex - 字段索引。

Return Value:

    字段值；字段不存在时返回 0。

--*/
{
    // 中文说明：WFP 数组指针、索引和稳定 FWP_UINT16 类型必须同时有效。
    if (Values == NULL ||
        Values->incomingValue == NULL ||
        FieldIndex >= Values->valueCount ||
        Values->incomingValue[FieldIndex].value.type != KSWORD_ARK_FWP_UINT16) {
        // 中文说明：字段缺失或 union 类型不符时返回 0。
        return 0UL;
    }
    // 中文说明：类型已验证，可安全读取 uint16 union 成员。
    return (ULONG)Values->incomingValue[FieldIndex].value.value.uint16;
}

static ULONG
KswordARKNetworkReadUint8Field(
    _In_ const KSWORD_ARK_FWPS_INCOMING_VALUES0* Values,
    _In_ UINT32 FieldIndex
    )
/*++

Routine Description:

    从 WFP incoming values 读取 UINT8 字段。中文说明：ALE IP_PROTOCOL 是
    FWP_UINT8，不能用 UINT32 联合体成员解释。

Arguments:

    Values - WFP classify 输入字段集合。
    FieldIndex - 字段索引。

Return Value:

    字段值；字段不存在时返回 0。

--*/
{
    // 中文说明：先校验 WFP 字段数组边界。
    if (Values == NULL ||
        Values->incomingValue == NULL ||
        FieldIndex >= Values->valueCount ||
        Values->incomingValue[FieldIndex].value.type != KSWORD_ARK_FWP_UINT8) {
        // 中文说明：字段不可用或 union 类型不符时返回 0。
        return 0UL;
    }
    // 中文说明：协议字段按 FWP_UINT8 读取并扩展为 ULONG。
    return (ULONG)Values->incomingValue[FieldIndex].value.value.uint8;
}

static ULONG
KswordARKNetworkReadProcessId(
    _In_ const KSWORD_ARK_FWPS_INCOMING_METADATA_VALUES0* Metadata
    )
/*++

Routine Description:

    从 WFP metadata 提取进程 ID。中文说明：不是所有层都有 processId，缺失时返回
    0，让仅按端口/协议匹配的规则仍可工作。

Arguments:

    Metadata - WFP metadata。

Return Value:

    进程 ID；未知时返回 0。

--*/
{
    if (Metadata == NULL) {
        return 0UL;
    }
    if ((Metadata->currentMetadataValues & KSWORD_ARK_FWPS_METADATA_FIELD_PROCESS_ID) == 0ULL) {
        return 0UL;
    }
    return (ULONG)(ULONG_PTR)Metadata->processId;
}

static BOOLEAN
KswordARKNetworkClassifyExtractTuple(
    _In_ const KSWORD_ARK_FWPS_INCOMING_VALUES0* Values,
    _In_ const KSWORD_ARK_FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _Out_ ULONG* DirectionOut,
    _Out_ ULONG* ProtocolOut,
    _Out_ ULONG* LocalAddressV4Out,
    _Out_ ULONG* RemoteAddressV4Out,
    _Out_ USHORT* LocalPortOut,
    _Out_ USHORT* RemotePortOut,
    _Out_ ULONG* ProcessIdOut
    )
/*++

Routine Description:

    从 ALE connect/recv-accept 层提取规则匹配与事件所需摘要。中文说明：当前仅
    覆盖 IPv4；驱动保留原始协议号，R3 监控页当前只展示 TCP/UDP。

Arguments:

    Values - WFP classify 输入字段集合。
    Metadata - WFP metadata。
    DirectionOut - 返回入站/出站方向。
    ProtocolOut - 返回协议号。
    LocalAddressV4Out - 返回主机序本地 IPv4。
    RemoteAddressV4Out - 返回主机序远端 IPv4。
    LocalPortOut - 返回本地端口。
    RemotePortOut - 返回远端端口。
    ProcessIdOut - 返回进程 ID。

Return Value:

    TRUE 表示字段提取成功；FALSE 表示层不受支持。

--*/
{
    // 中文说明：保存 WFP 已提供为主机序的本地端口。
    UINT16 localPortHost = 0U;
    // 中文说明：保存 WFP 已提供为主机序的远端端口。
    UINT16 remotePortHost = 0U;

    // 中文说明：所有输出字段都必须可写，避免 classify 热路径部分初始化。
    if (Values == NULL || DirectionOut == NULL || ProtocolOut == NULL ||
        LocalAddressV4Out == NULL || RemoteAddressV4Out == NULL ||
        LocalPortOut == NULL || RemotePortOut == NULL || ProcessIdOut == NULL) {
        // 中文说明：参数无效时拒绝形成事件。
        return FALSE;
    }

    // 中文说明：ALE_AUTH_CONNECT_V4 表示出站流授权。
    if (Values->layerId == KSWORD_ARK_FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        // 中文说明：connect 层固定映射为出站。
        *DirectionOut = KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND;
        // 中文说明：协议字段按 FWP_UINT8 读取。
        *ProtocolOut = KswordARKNetworkReadUint8Field(Values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL);
        // 中文说明：IPv4 地址字段按 FWP_UINT32 主机序读取。
        *LocalAddressV4Out = KswordARKNetworkReadUint32Field(Values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS);
        // 中文说明：读取主机序远端 IPv4。
        *RemoteAddressV4Out = KswordARKNetworkReadUint32Field(Values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS);
        // 中文说明：读取主机序本地端口。
        localPortHost = (UINT16)KswordARKNetworkReadUint16Field(Values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT);
        // 中文说明：读取主机序远端端口。
        remotePortHost = (UINT16)KswordARKNetworkReadUint16Field(Values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT);
    }
    // 中文说明：ALE_AUTH_RECV_ACCEPT_V4 表示入站流授权。
    else if (Values->layerId == KSWORD_ARK_FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4) {
        // 中文说明：recv-accept 层固定映射为入站。
        *DirectionOut = KSWORD_ARK_NETWORK_DIRECTION_INBOUND;
        // 中文说明：协议字段按 FWP_UINT8 读取。
        *ProtocolOut = KswordARKNetworkReadUint8Field(Values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL);
        // 中文说明：读取主机序本地 IPv4。
        *LocalAddressV4Out = KswordARKNetworkReadUint32Field(Values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS);
        // 中文说明：读取主机序远端 IPv4。
        *RemoteAddressV4Out = KswordARKNetworkReadUint32Field(Values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS);
        // 中文说明：读取主机序本地端口。
        localPortHost = (UINT16)KswordARKNetworkReadUint16Field(Values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT);
        // 中文说明：读取主机序远端端口。
        remotePortHost = (UINT16)KswordARKNetworkReadUint16Field(Values, KSWORD_ARK_FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT);
    }
    else {
        // 中文说明：IPv6 和其它 layer 本版不写入 IPv4 事件 ring。
        return FALSE;
    }

    // 中文说明：WFP port 已是主机序，helper 明确避免二次交换。
    *LocalPortOut = KswordARKNetworkReadHostOrderPort(localPortHost);
    // 中文说明：保持远端端口的主机序数值。
    *RemotePortOut = KswordARKNetworkReadHostOrderPort(remotePortHost);
    // 中文说明：PID 缺失时 helper 返回 0。
    *ProcessIdOut = KswordARKNetworkReadProcessId(Metadata);
    // 中文说明：完整 IPv4 ALE 摘要已形成。
    return TRUE;
}

static BOOLEAN
KswordARKNetworkShouldBlockClassify(
    _In_ ULONG Direction,
    _In_ ULONG Protocol,
    _In_ USHORT LocalPort,
    _In_ USHORT RemotePort,
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    在规则快照中查找阻断规则。中文说明：allow 规则优先返回 FALSE，block 规则命中
    返回 TRUE，hide-port 规则不影响网络放行。

Arguments:

    Direction - 当前方向。
    Protocol - 协议号。
    LocalPort - 本地端口。
    RemotePort - 远端端口。
    ProcessId - 进程 ID。

Return Value:

    TRUE 表示阻断；FALSE 表示放行。

--*/
{
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    KIRQL oldIrql = PASSIVE_LEVEL;
    ULONG ruleIndex = 0UL;
    BOOLEAN shouldBlock = FALSE;

    if (InterlockedCompareExchange(
            &runtime->ClassifyRulesActive,
            0L,
            0L) == 0L) {
        return FALSE;
    }

    KeAcquireSpinLock(&runtime->ClassifyRuleLock, &oldIrql);
    for (ruleIndex = 0UL; ruleIndex < KSWORD_ARK_NETWORK_MAX_RULES; ++ruleIndex) {
        const KSWORD_ARK_NETWORK_RULE* rule = &runtime->ClassifyRules[ruleIndex];
        if (rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_ALLOW &&
            rule->action != KSWORD_ARK_NETWORK_RULE_ACTION_BLOCK) {
            continue;
        }
        if (!KswordARKNetworkRuleMatchesLocked(
            rule,
            Direction,
            Protocol,
            LocalPort,
            RemotePort,
            ProcessId)) {
            continue;
        }
        shouldBlock = (rule->action == KSWORD_ARK_NETWORK_RULE_ACTION_BLOCK) ? TRUE : FALSE;
        break;
    }
    KeReleaseSpinLock(&runtime->ClassifyRuleLock, oldIrql);

    return shouldBlock;
}

VOID NTAPI
KswordARKNetworkClassifyFn(
    _In_ const KSWORD_ARK_FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const KSWORD_ARK_FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const KSWORD_ARK_FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ KSWORD_ARK_FWPS_CLASSIFY_OUT0* classifyOut
    )
/*++

Routine Description:

    WFP ALE classify 回调。中文说明：每次受支持的 IPv4 connect/recv-accept 授权均
    记录真实无 payload 流事件；只在拥有 ACTION_WRITE 且规则命中时设置 BLOCK。

Arguments:

    inFixedValues - WFP 输入字段。
    inMetaValues - WFP metadata。
    layerData - 未使用。
    filter - 未使用。
    flowContext - 未使用。
    classifyOut - WFP 动作输出。

Return Value:

    None. 本函数没有返回值。

--*/
{
    // 中文说明：获取静态非分页网络运行时。
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    // 中文说明：保存 ALE 层推导的入站/出站方向。
    ULONG direction = 0UL;
    // 中文说明：保存 FWP_UINT8 IP 协议号。
    ULONG protocol = 0UL;
    // 中文说明：保存 FWP_UINT32 主机序本地 IPv4。
    ULONG localAddressV4 = 0UL;
    // 中文说明：保存 FWP_UINT32 主机序远端 IPv4。
    ULONG remoteAddressV4 = 0UL;
    // 中文说明：保存 FWP_UINT16 主机序本地端口。
    USHORT localPort = 0U;
    // 中文说明：保存 FWP_UINT16 主机序远端端口。
    USHORT remotePort = 0U;
    // 中文说明：保存 WFP metadata PID。
    ULONG processId = 0UL;
    // 中文说明：保存最终是否由本 callout 实际阻断。
    BOOLEAN shouldBlock = FALSE;
    // 中文说明：保存本次 classify 是否允许写 action。
    BOOLEAN actionWritable = FALSE;
    // 中文说明：保存写入共享事件行的语义标志。
    ULONG eventFlags = 0UL;

    // 中文说明：当前 ALE 事件通道不读取 layerData。
    UNREFERENCED_PARAMETER(layerData);
    // 中文说明：当前 ALE 事件通道不读取 filter 上下文。
    UNREFERENCED_PARAMETER(filter);
    // 中文说明：当前 ALE 事件通道不分配 flow context。
    UNREFERENCED_PARAMETER(flowContext);

    // 中文说明：静态运行时理论上始终存在，空值时不得继续访问计数器。
    if (runtime == NULL) {
        // 中文说明：不干预其它 WFP policy。
        return;
    }

    // 中文说明：计数所有到达本 callout 的 classify 调用，包括只读仲裁调用。
    InterlockedIncrement64(&runtime->ClassifyCount);
    // 中文说明：只对受支持的 IPv4 connect/recv-accept 层提取完整元数据。
    if (!KswordARKNetworkClassifyExtractTuple(
        inFixedValues,
        inMetaValues,
        &direction,
        &protocol,
        &localAddressV4,
        &remoteAddressV4,
        &localPort,
        &remotePort,
        &processId)) {
        // 中文说明：字段不受支持但 action 可写时保持既有默认放行行为。
        if (classifyOut != NULL &&
            (classifyOut->rights & KSWORD_ARK_FWPS_RIGHT_ACTION_WRITE) != 0U) {
            // 中文说明：未知层不由本 callout 阻断。
            classifyOut->actionType = KSWORD_ARK_FWP_ACTION_PERMIT;
        }
        // 中文说明：不为无法形成完整 IPv4 五元组的 classify 伪造事件。
        return;
    }

    // 中文说明：只有非空 classifyOut 且持有 ACTION_WRITE 才能改变仲裁结果。
    actionWritable =
        classifyOut != NULL &&
        (classifyOut->rights & KSWORD_ARK_FWPS_RIGHT_ACTION_WRITE) != 0U;
    // 中文说明：只有可写 action 时才执行现有规则判定，避免标记未实际执行的 block。
    if (actionWritable) {
        // 中文说明：读取规则快照并计算最终阻断。
        shouldBlock = KswordARKNetworkShouldBlockClassify(
            direction,
            protocol,
            localPort,
            remotePort,
            processId);
    }

    // 中文说明：根据实际 ALE layer 标记事件来源。
    eventFlags =
        (inFixedValues->layerId == KSWORD_ARK_FWPS_LAYER_ALE_AUTH_CONNECT_V4) ?
        KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_CONNECT :
        KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_RECV_ACCEPT;
    // 中文说明：无 action write 权限时明确标记只观察、未改写。
    if (!actionWritable) {
        // 中文说明：R3 可据此避免把规则预判误认为实际动作。
        eventFlags |= KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ACTION_WRITE_UNAVAILABLE;
    }
    // 中文说明：只有实际准备设置 BLOCK 时写入 blocked 标志。
    if (shouldBlock) {
        // 中文说明：事件语义与下面实际 action 保持一致。
        eventFlags |= KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_BLOCKED;
    }

    // 中文说明：在修改 classifyOut 前写入固定非分页 ring；该函数仅使用自旋锁。
    KswordARKNetworkRecordWfpAleEvent(
        direction,
        protocol,
        localAddressV4,
        remoteAddressV4,
        localPort,
        remotePort,
        processId,
        eventFlags);

    // 中文说明：无 action write 权限时只记录事件，不干预已有仲裁结果。
    if (!actionWritable) {
        // 中文说明：事件已完成，直接返回。
        return;
    }

    // 中文说明：规则命中时执行既有阻断动作。
    if (shouldBlock) {
        // 中文说明：设置 terminating block。
        classifyOut->actionType = KSWORD_ARK_FWP_ACTION_BLOCK;
        // 中文说明：清除 action write 权限，防止后续低权重 filter 改写。
        classifyOut->rights &= ~KSWORD_ARK_FWPS_RIGHT_ACTION_WRITE;
        // 中文说明：吸收命中流量以维持既有阻断行为。
        classifyOut->flags |= KSWORD_ARK_FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        // 中文说明：累计实际阻断次数。
        InterlockedIncrement64(&runtime->BlockedCount);
    }
    else {
        // 中文说明：没有 block 规则命中时显式放行。
        classifyOut->actionType = KSWORD_ARK_FWP_ACTION_PERMIT;
    }
}

NTSTATUS NTAPI
KswordARKNetworkNotifyFn(
    _In_ KSWORD_ARK_FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ const KSWORD_ARK_FWPS_FILTER0* filter
    )
/*++

Routine Description:

    WFP notify 回调。中文说明：当前不维护 flow 上下文，因此只接受通知并返回成功。

Arguments:

    notifyType - 通知类型。
    filterKey - 过滤器 key。
    filter - 过滤器对象。

Return Value:

    STATUS_SUCCESS。

--*/
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

VOID NTAPI
KswordARKNetworkFlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
    )
/*++

Routine Description:

    WFP flow-delete 回调。中文说明：当前不分配 flow context，因此无需释放资源。

Arguments:

    layerId - WFP 层 ID。
    calloutId - callout ID。
    flowContext - flow 上下文。

Return Value:

    None. 本函数没有返回值。

--*/
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

static NTSTATUS
KswordARKNetworkRegisterCallout(
    _In_ KSWORD_ARK_NETWORK_RUNTIME* Runtime,
    _In_ const GUID* CalloutKey,
    _Out_ UINT32* CalloutIdOut
    )
/*++

Routine Description:

    调用 FwpsCalloutRegister 注册内核 classify 入口。中文说明：两个 ALE 层复用同一
    classify 函数，通过 layerId 区分方向。

Arguments:

    Runtime - 网络运行时。
    CalloutKey - callout GUID。
    CalloutIdOut - 返回 callout id。

Return Value:

    FwpsCalloutRegister0 返回状态。

--*/
{
    KSWORD_ARK_FWPS_CALLOUT0 callout;

    if (Runtime == NULL || Runtime->DeviceObject == NULL || CalloutKey == NULL || CalloutIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *CalloutKey;
    callout.classifyFn = KswordARKNetworkClassifyFn;
    callout.notifyFn = KswordARKNetworkNotifyFn;
    callout.flowDeleteFn = KswordARKNetworkFlowDeleteFn;
    return FwpsCalloutRegister0(
        Runtime->DeviceObject,
        &callout,
        CalloutIdOut);
}

static NTSTATUS
KswordARKNetworkAddCalloutToEngine(
    _In_ KSWORD_ARK_NETWORK_RUNTIME* Runtime,
    _In_ const GUID* CalloutKey,
    _In_ const GUID* LayerKey,
    _In_z_ PCWSTR DisplayName
    )
/*++

Routine Description:

    向 BFE 添加 callout 对象。中文说明：FWPM callout 绑定到具体 layer，随后 filter
    才能引用该 callout。

Arguments:

    Runtime - 网络运行时。
    CalloutKey - callout GUID。
    LayerKey - WFP layer GUID。
    DisplayName - 显示名称。

Return Value:

    FwpmCalloutAdd0 返回状态。

--*/
{
    KSWORD_ARK_FWPM_CALLOUT0 callout;

    if (Runtime == NULL || Runtime->EngineHandle == NULL || CalloutKey == NULL || LayerKey == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *CalloutKey;
    callout.displayData.name = (PWSTR)DisplayName;
    callout.applicableLayer = *LayerKey;
    return FwpmCalloutAdd0(Runtime->EngineHandle, &callout, NULL, NULL);
}

static NTSTATUS
KswordARKNetworkAddFilter(
    _In_ KSWORD_ARK_NETWORK_RUNTIME* Runtime,
    _In_ const GUID* CalloutKey,
    _In_ const GUID* LayerKey,
    _In_z_ PCWSTR DisplayName,
    _Out_ UINT64* FilterIdOut
    )
/*++

Routine Description:

    添加匹配所有流量的 callout filter。中文说明：具体放行/阻断由 classify 内部的
    KswordARK 规则表决定，filter 本身不保存用户规则。

Arguments:

    Runtime - 网络运行时。
    CalloutKey - callout GUID。
    LayerKey - WFP layer GUID。
    DisplayName - 显示名称。
    FilterIdOut - 返回 filter id。

Return Value:

    FwpmFilterAdd0 返回状态。

--*/
{
    KSWORD_ARK_FWPM_FILTER0 filter;

    if (Runtime == NULL || Runtime->EngineHandle == NULL || CalloutKey == NULL ||
        LayerKey == NULL || FilterIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&filter, sizeof(filter));
    filter.layerKey = *LayerKey;
    filter.displayData.name = (PWSTR)DisplayName;
    filter.action.type = KSWORD_ARK_FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.actionKey.calloutKey = *CalloutKey;
    filter.subLayerKey = KSWORD_ARK_WFP_SUBLAYER;
    filter.weight.type = KSWORD_ARK_FWP_EMPTY;
    filter.numFilterConditions = 0U;
    filter.filterCondition = NULL;
    return FwpmFilterAdd0(Runtime->EngineHandle, &filter, NULL, FilterIdOut);
}

static NTSTATUS
KswordARKNetworkAddSublayer(
    _In_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    )
/*++

Routine Description:

    向 BFE 添加 KswordARK 子层。中文说明：子层权重设置为中等值，避免压过系统关键
    安全策略，同时保证本驱动 filter 可分组清理。

Arguments:

    Runtime - 网络运行时。

Return Value:

    FwpmSubLayerAdd0 返回状态。

--*/
{
    KSWORD_ARK_FWPM_SUBLAYER0 subLayer;

    if (Runtime == NULL || Runtime->EngineHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&subLayer, sizeof(subLayer));
    subLayer.subLayerKey = KSWORD_ARK_WFP_SUBLAYER;
    subLayer.displayData.name = L"KswordARK Network Filter";
    subLayer.weight = 0x4000U;
    return FwpmSubLayerAdd0(Runtime->EngineHandle, &subLayer, NULL);
}

NTSTATUS
KswordARKNetworkWfpRegister(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    )
/*++

Routine Description:

    注册 KswordARK WFP callout、sublayer 和 filter。中文说明：任何一步失败都会
    调用注销路径清理已创建对象，避免残留 BFE 项。

Arguments:

    Runtime - 网络运行时。

Return Value:

    STATUS_SUCCESS 或 WFP API 返回状态。

--*/
{
    KSWORD_ARK_FWPM_SESSION0 session;
    NTSTATUS status = STATUS_SUCCESS;

    if (Runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKNetworkRegisterCallout(
        Runtime,
        &KSWORD_ARK_WFP_CONNECT_CALLOUT,
        &Runtime->ConnectCalloutId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = KswordARKNetworkRegisterCallout(
        Runtime,
        &KSWORD_ARK_WFP_RECV_ACCEPT_CALLOUT,
        &Runtime->RecvAcceptCalloutId);
    if (!NT_SUCCESS(status)) {
        KswordARKNetworkWfpUnregister(Runtime);
        return status;
    }

    // 中文说明：ALE 规则 callout 注册后，再注册 IPv4/IPv6 四个逐包观察 callout。
    status = KswordARKNetworkTrafficRegisterRuntimeCallouts(Runtime);
    // 中文说明：任一逐包 runtime callout 失败都走统一清理，避免只覆盖部分方向。
    if (!NT_SUCCESS(status)) {
        // 中文说明：注销已创建的 ALE 与逐包 runtime callout。
        KswordARKNetworkWfpUnregister(Runtime);
        // 中文说明：返回精确 WFP 注册错误。
        return status;
    }

    RtlZeroMemory(&session, sizeof(session));
    session.flags = KSWORD_ARK_FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &Runtime->EngineHandle);
    Runtime->EngineStatus = status;
    if (!NT_SUCCESS(status)) {
        KswordARKNetworkWfpUnregister(Runtime);
        return status;
    }

    status = FwpmTransactionBegin0(Runtime->EngineHandle, 0U);
    if (!NT_SUCCESS(status)) {
        KswordARKNetworkWfpUnregister(Runtime);
        return status;
    }

    status = KswordARKNetworkAddSublayer(Runtime);
    if (NT_SUCCESS(status)) {
        status = KswordARKNetworkAddCalloutToEngine(
            Runtime,
            &KSWORD_ARK_WFP_CONNECT_CALLOUT,
            &KSWORD_ARK_FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            L"KswordARK ALE connect callout");
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKNetworkAddCalloutToEngine(
            Runtime,
            &KSWORD_ARK_WFP_RECV_ACCEPT_CALLOUT,
            &KSWORD_ARK_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            L"KswordARK ALE recv-accept callout");
    }
    // 中文说明：在同一事务中加入四个 IPPACKET callout 与 inspection filter。
    if (NT_SUCCESS(status)) {
        // 中文说明：逐包模块使用同一个动态 engine 和 KswordARK 子层。
        status = KswordARKNetworkTrafficAddEngineObjects(Runtime);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKNetworkAddFilter(
            Runtime,
            &KSWORD_ARK_WFP_CONNECT_CALLOUT,
            &KSWORD_ARK_FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            L"KswordARK ALE connect filter",
            &Runtime->ConnectFilterId);
    }
    if (NT_SUCCESS(status)) {
        status = KswordARKNetworkAddFilter(
            Runtime,
            &KSWORD_ARK_WFP_RECV_ACCEPT_CALLOUT,
            &KSWORD_ARK_FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            L"KswordARK ALE recv-accept filter",
            &Runtime->RecvAcceptFilterId);
    }

    if (NT_SUCCESS(status)) {
        status = FwpmTransactionCommit0(Runtime->EngineHandle);
        if (NT_SUCCESS(status)) {
            // 中文说明：ALE 规则与逐包四层对象同一事务提交，能力位同步可见。
            Runtime->RuntimeFlags |=
                KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED |
                KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED;
            // 中文说明：记录逐包数据面已提交成功。
            Runtime->TrafficCaptureStatus = STATUS_SUCCESS;
            return STATUS_SUCCESS;
        }
    }
    else {
        (VOID)FwpmTransactionAbort0(Runtime->EngineHandle);
    }

    // 中文说明：提交或任一对象添加失败时，逐包查询应回报精确失败状态。
    Runtime->TrafficCaptureStatus = status;
    // 中文说明：清理事务外 runtime callout 与可能残留的动态 engine 对象。
    KswordARKNetworkWfpUnregister(Runtime);
    return status;
}

VOID
KswordARKNetworkWfpUnregister(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    )
/*++

Routine Description:

    注销 WFP filter、callout 和引擎句柄。中文说明：所有删除操作都按非空/非零判断
    执行，保证初始化失败路径和正常卸载路径都可重复调用。

Arguments:

    Runtime - 网络运行时。

Return Value:

    None. 本函数没有返回值。

--*/
{
    if (Runtime == NULL) {
        return;
    }

    if (Runtime->EngineHandle != NULL) {
        // 中文说明：先删除逐包 filter/callout，避免关闭 engine 后丢失显式清理机会。
        KswordARKNetworkTrafficDeleteEngineObjects(Runtime);
        if (Runtime->ConnectFilterId != 0ULL) {
            (VOID)FwpmFilterDeleteById0(Runtime->EngineHandle, Runtime->ConnectFilterId);
            Runtime->ConnectFilterId = 0ULL;
        }
        if (Runtime->RecvAcceptFilterId != 0ULL) {
            (VOID)FwpmFilterDeleteById0(Runtime->EngineHandle, Runtime->RecvAcceptFilterId);
            Runtime->RecvAcceptFilterId = 0ULL;
        }
        (VOID)FwpmCalloutDeleteByKey0(Runtime->EngineHandle, &KSWORD_ARK_WFP_CONNECT_CALLOUT);
        (VOID)FwpmCalloutDeleteByKey0(Runtime->EngineHandle, &KSWORD_ARK_WFP_RECV_ACCEPT_CALLOUT);
        (VOID)FwpmSubLayerDeleteByKey0(Runtime->EngineHandle, &KSWORD_ARK_WFP_SUBLAYER);
        FwpmEngineClose0(Runtime->EngineHandle);
        Runtime->EngineHandle = NULL;
    }

    if (Runtime->ConnectCalloutId != 0U) {
        (VOID)FwpsCalloutUnregisterById0(Runtime->ConnectCalloutId);
        Runtime->ConnectCalloutId = 0U;
    }
    if (Runtime->RecvAcceptCalloutId != 0U) {
        (VOID)FwpsCalloutUnregisterById0(Runtime->RecvAcceptCalloutId);
        Runtime->RecvAcceptCalloutId = 0U;
    }

    // 中文说明：最后注销四个逐包 runtime callout；函数支持部分初始化。
    KswordARKNetworkTrafficUnregisterRuntimeCallouts(Runtime);

    Runtime->RuntimeFlags &= ~(
        KSWORD_ARK_NETWORK_RUNTIME_WFP_REGISTERED |
        KSWORD_ARK_NETWORK_RUNTIME_WFP_STARTED |
        KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED);
}
