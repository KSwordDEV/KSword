/* 中文说明：Windows 回环不经过 IPPACKET；transport 观察仍复用原 ring 与捕获代次。 */
#include "network_traffic.h"

// 中文说明：只注册可恢复真实 IP 头的 v4/v6 入站回环层。
#define KSWORD_ARK_LOOPBACK_CALLOUT_COUNT 2UL

// 中文说明：复用原动态会话子层，不安装独立来源或第三方驱动。
static const GUID g_LoopbackSublayer =
{ 0xd2b28bc6, 0x9e08, 0x4d07, { 0x9f, 0x7b, 0x2b, 0xa8, 0x21, 0xd8, 0xaa, 0x51 } };
// 中文说明：WDK 内置 FLAGS 条件 GUID，避免依赖 GUID 数据导入库。
const GUID KswordARKNetworkTrafficFlagsCondition =
{ 0x632ce23b, 0x5167, 0x435c, { 0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c } };

// 中文说明：每层的稳定 callout/layer GUID、真实字段索引与清理 ID。
typedef struct _KSWORD_ARK_LOOPBACK_CALLOUT
{
    GUID CalloutKey; // 中文说明：本驱动专用回环 callout。
    GUID LayerKey; // 中文说明：WDK 内置 transport 层 GUID。
    UINT16 LayerId; // 中文说明：运行时层身份，不通过数组布局猜测。
    ULONG FlagsIndex; // 中文说明：该层的 IS_LOOPBACK 标志索引。
    ULONG ProtocolIndex; // 中文说明：真实 IP protocol 字段索引。
    ULONG LocalIndex; // 中文说明：本地地址字段索引。
    ULONG RemoteIndex; // 中文说明：远端地址字段索引。
    BOOLEAN Ipv6; // 中文说明：决定地址宽度和 FWP 值类型。
    UINT32 CalloutId; // 中文说明：部分注册时也可逆序清退。
    UINT64 FilterId; // 中文说明：父事务 abort 后同样清零。
} KSWORD_ARK_LOOPBACK_CALLOUT;

// 中文说明：只保留两个入站层及各自真实 WDK 字段索引，不注册出站 transport。
static KSWORD_ARK_LOOPBACK_CALLOUT g_LoopbackCallouts[KSWORD_ARK_LOOPBACK_CALLOUT_COUNT] =
{
    {
        { 0x572f077b, 0xda40, 0x463c, { 0xb7, 0x16, 0x16, 0x6f, 0x93, 0x46, 0x3b, 0x1d } },
        { 0x5926dfc8, 0xe3cf, 0x4426, { 0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d } },
        FWPS_LAYER_INBOUND_TRANSPORT_V4, FWPS_FIELD_INBOUND_TRANSPORT_V4_FLAGS,
        FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL, FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS,
        FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS, FALSE, 0U, 0ULL
    },
    {
        { 0x5d20e817, 0xc5f2, 0x4a82, { 0x9a, 0x6a, 0xdf, 0x3d, 0x9d, 0x41, 0x0e, 0x72 } },
        { 0x634a869f, 0xfc23, 0x4b90, { 0xb0, 0xc1, 0xbf, 0x62, 0x0a, 0x36, 0xae, 0x6f } },
        FWPS_LAYER_INBOUND_TRANSPORT_V6, FWPS_FIELD_INBOUND_TRANSPORT_V6_FLAGS,
        FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL, FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS,
        FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS, TRUE, 0U, 0ULL
    }
};

// 中文说明：只复制已存在的 MDL 字节；不让 NDIS 为缺失报头分配回退空间。
static BOOLEAN KswordARKLoopbackCopy(
    _Inout_ NET_BUFFER* NetBuffer,
    _In_ ULONG Retreat,
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* Row)
{
    // 中文说明：保存连续或由 NDIS 复制后的数据指针。
    UCHAR* bytes = NULL;
    // 中文说明：没有真实 headroom 或长度相加溢出时不修改 NBL。
    if (NET_BUFFER_DATA_OFFSET(NetBuffer) < Retreat ||
        NET_BUFFER_DATA_LENGTH(NetBuffer) > MAXULONG - Retreat) {
        // 中文说明：禁止合成头部或触发分配。
        return FALSE;
    }
    // 中文说明：回退量来自真实 IP 与 transport 头 metadata，不访问未指明的 headroom。
    if (NdisRetreatNetBufferDataStart(NetBuffer, Retreat, 0UL, NULL) != NDIS_STATUS_SUCCESS) {
        // 中文说明：NDIS 未回退时不需要恢复。
        return FALSE;
    }
    // 中文说明：总长始终是实际可见 NBL 长度，而非推算 IP 长度。
    Row->totalPacketLength = NET_BUFFER_DATA_LENGTH(NetBuffer);
    // 中文说明：有限前缀保持原有固定 512 字节预算。
    Row->capturedLength = min(Row->totalPacketLength, KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES);
    // 中文说明：空 NBL 不调用要求非零长度的 NDIS 读取。
    if (Row->capturedLength != 0UL) {
        // 中文说明：跨 MDL 数据由 NDIS 复制到同一固定行，不保留原 MDL 指针。
        bytes = (UCHAR*)NdisGetDataBuffer(NetBuffer, Row->capturedLength, Row->capturedBytes, 1UL, 0UL);
        // 中文说明：直接指向原 MDL 的连续数据必须复制为稳定快照。
        if (bytes != NULL && bytes != Row->capturedBytes) {
            // 中文说明：长度已受协议数组上限约束。
            RtlCopyMemory(Row->capturedBytes, bytes, Row->capturedLength);
        }
    }
    // 中文说明：读取后先按成功回退量严格恢复，再进行解析或任意返回。
    NdisAdvanceNetBufferDataStart(NetBuffer, Retreat, FALSE, NULL);
    // 中文说明：只有真实复制成功才允许解析。
    return bytes != NULL;
}

// 中文说明：按 WFP 地址字段类型读取端点，IPv4 UINT32 是主机序。
static BOOLEAN KswordARKLoopbackAddress(
    _In_ const FWP_VALUE0* Value,
    _In_ BOOLEAN Ipv6,
    _Out_writes_(16) UCHAR* Address)
{
    // 中文说明：IPv6 必须提供完整的 16 字节数组。
    if (Ipv6) {
        // 中文说明：类型和指针均需可用。
        if (Value->type != FWP_BYTE_ARRAY16_TYPE || Value->byteArray16 == NULL) {
            // 中文说明：无可靠地址则不形成记录。
            return FALSE;
        }
        // 中文说明：保存原网络序地址。
        RtlCopyMemory(Address, Value->byteArray16->byteArray16, 16UL);
    }
    else {
        // 中文说明：IPv4 字段必须为 WFP UINT32。
        if (Value->type != FWP_UINT32) {
            // 中文说明：不猜测非预期 ABI 类型。
            return FALSE;
        }
        // 中文说明：显式逐字节转换，避免未对齐写入和隐式收窄告警。
        Address[0] = (UCHAR)(Value->uint32 >> 24U);
        // 中文说明：保存第二个网络序字节。
        Address[1] = (UCHAR)(Value->uint32 >> 16U);
        // 中文说明：保存第三个网络序字节。
        Address[2] = (UCHAR)(Value->uint32 >> 8U);
        // 中文说明：保存最低网络序字节。
        Address[3] = (UCHAR)Value->uint32;
    }
    // 中文说明：端点地址已真实取得。
    return TRUE;
}

// 中文说明：只发布可回退并验证成功的真实 IP 字节，不提供无 IP 头的替代捕获层。
static VOID KswordARKLoopbackCapture(
    _Inout_ NET_BUFFER* NetBuffer,
    _In_ const KSWORD_ARK_LOOPBACK_CALLOUT* Config,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _In_reads_(16) const UCHAR* Local,
    _In_reads_(16) const UCHAR* Remote,
    _In_ UCHAR Protocol,
    _In_ ULONG Generation)
{
    // 中文说明：固定 IP 记录沿用现有 R0/R3 行格式和 512 字节前缀。
    KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW row = { 0 };
    // 中文说明：入站偏移位于 payload，必须按 metadata 回退真实传输头和 IP 头。
    ULONG retreat = 0UL;
    // 中文说明：根据层选择实际地址宽度。
    const ULONG addressLength = Config->Ipv6 ? 16UL : 4UL;
    // 中文说明：保存系统时间，而非将单调时钟冒充 UTC。
    LARGE_INTEGER systemTime = { 0 };

    // 中文说明：两种头长都必须明确存在、非零且相加不溢出；缺失时不猜测或伪造。
    if ((Metadata->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE) == 0U ||
        (Metadata->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE) == 0U ||
        Metadata->ipHeaderSize == 0UL || Metadata->transportHeaderSize == 0UL ||
        Metadata->ipHeaderSize > MAXULONG - Metadata->transportHeaderSize) {
        // 中文说明：保持真实 IP-only 协议，不退为 L4-only 行。
        return;
    }
    // 中文说明：入站 transport 的 data offset 位于 payload，回退两种实际头长。
    retreat = Metadata->ipHeaderSize + Metadata->transportHeaderSize;
    // 中文说明：只读取已存在的完整 IP 前缀，内部确保所有退出前恢复 NB 偏移。
    if (!KswordARKLoopbackCopy(NetBuffer, retreat, &row)) {
        // 中文说明：真实头不可读取时不发布当前 NB。
        return;
    }
    // 中文说明：只记录入站观察，不生成对应的出站行或声称双向覆盖。
    row.direction = KSWORD_ARK_NETWORK_DIRECTION_INBOUND;
    // 中文说明：复用原 IP/传输头解析，并核对真实层端点及 payload 边界。
    if (!KswordARKNetworkTrafficParsePacket(&row) ||
        row.addressFamily != (Config->Ipv6 ? KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6 : KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4) ||
        row.protocol != (ULONG)Protocol || row.payloadOffset != retreat ||
        RtlCompareMemory(row.localAddress, Local, addressLength) != addressLength ||
        RtlCompareMemory(row.remoteAddress, Remote, addressLength) != addressLength) {
        // 中文说明：解析失败或元数据不一致时不把任意 headroom 声明成 IP 包。
        return;
    }
    // 中文说明：保持原固定 ABI、版本和 flags，现有消费者无需新增捕获层。
    row.version = KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION;
    // 中文说明：固定 row 不扩展长度。
    row.size = sizeof(row);
    // 中文说明：与 IPPACKET 共用 metadata PID 的边界和未知值语义。
    row.processId = KswordARKNetworkTrafficReadProcessId(Metadata);
    // 中文说明：读取正式捕获 UTC。
    KeQuerySystemTime(&systemTime);
    // 中文说明：保存 100ns FILETIME 时间域。
    row.timestamp100ns = (ULONG64)systemTime.QuadPart;
    // 中文说明：复用原代次校验、自旋锁和单调 ring 序号。
    KswordARKNetworkTrafficRecordPacket(&row, Generation);
}

// 中文说明：只观察 WFP 明确标记为 loopback 的两个入站 transport 层。
static VOID NTAPI KswordARKLoopbackClassify(
    _In_ const FWPS_INCOMING_VALUES0* Values,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    // 中文说明：共享启停状态和捕获代次，不另开来源开关。
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    // 中文说明：按真实层 ID 选配置。
    const KSWORD_ARK_LOOPBACK_CALLOUT* config = NULL;
    // 中文说明：保存本次捕获代次。
    ULONG generation = 0UL;
    // 中文说明：配置表只有 v4/v6 两个入站槽位。
    ULONG index = 0UL;
    // 中文说明：端点来自 WFP 真实分类字段。
    UCHAR local[16] = { 0 };
    // 中文说明：保持 IPv4 未使用尾部为零。
    UCHAR remote[16] = { 0 };
    // 中文说明：保存 TCP/UDP 协议号。
    UCHAR protocol = 0U;
    // 中文说明：按 NBL/NB 链观察全部缓冲。
    NET_BUFFER_LIST* list = NULL;
    // 中文说明：不持有 BFE filter 指针。
    UNREFERENCED_PARAMETER(Filter);
    // 中文说明：不维护 flow context。
    UNREFERENCED_PARAMETER(FlowContext);
    // 中文说明：永远非终止观察，不改变防火墙判定。
    if (ClassifyOut != NULL && (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0U) {
        // 中文说明：不 permit、不 block、不 absorb。
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
    }
    // 中文说明：无数据或停止态不复制任何字节。
    if (runtime == NULL || Values == NULL || Values->incomingValue == NULL || Metadata == NULL || LayerData == NULL) {
        // 中文说明：空 layerData 在 WFP 某些通知中合法。
        return;
    }
    // 中文说明：先取代次再读启用状态，ring 写入时再次确认代次。
    generation = (ULONG)InterlockedCompareExchange(&runtime->TrafficCaptureGeneration, 0L, 0L);
    // 中文说明：停止态或跨越启停的回调不进入读取路径。
    if (InterlockedCompareExchange(&runtime->TrafficCaptureEnabled, 0L, 0L) == 0L ||
        generation != (ULONG)InterlockedCompareExchange(&runtime->TrafficCaptureGeneration, 0L, 0L)) {
        // 中文说明：复用原迟到写入防护。
        return;
    }
    // 中文说明：不假定 WDK 的字段枚举顺序在 v4/v6 之间相同。
    for (index = 0UL; index < KSWORD_ARK_LOOPBACK_CALLOUT_COUNT; ++index) {
        // 中文说明：只接纳两个入站配置中的真实层。
        if (g_LoopbackCallouts[index].LayerId == Values->layerId) {
            // 中文说明：配置静态生命周期覆盖全部回调。
            config = &g_LoopbackCallouts[index];
            // 中文说明：已找到唯一层配置。
            break;
        }
    }
    // 中文说明：每个访问字段先验证边界；filter 条件之外仍显式核对 loopback。
    if (config == NULL || Values->valueCount <= config->FlagsIndex ||
        Values->valueCount <= config->ProtocolIndex || Values->valueCount <= config->LocalIndex ||
        Values->valueCount <= config->RemoteIndex ||
        Values->incomingValue[config->FlagsIndex].value.type != FWP_UINT32 ||
        (Values->incomingValue[config->FlagsIndex].value.uint32 & FWP_CONDITION_FLAG_IS_LOOPBACK) == 0U ||
        Values->incomingValue[config->ProtocolIndex].value.type != FWP_UINT8) {
        // 中文说明：非 loopback 在这里退出，避免与 IPPACKET 重复。
        return;
    }
    // 中文说明：只保留原协议支持的 TCP/UDP。
    protocol = Values->incomingValue[config->ProtocolIndex].value.uint8;
    // 中文说明：不将 ICMP 等报文解释为 TCP/UDP。
    if ((protocol != 6U && protocol != 17U) ||
        !KswordARKLoopbackAddress(&Values->incomingValue[config->LocalIndex].value, config->Ipv6, local) ||
        !KswordARKLoopbackAddress(&Values->incomingValue[config->RemoteIndex].value, config->Ipv6, remote)) {
        // 中文说明：端点或协议不受支持则不发布。
        return;
    }
    // 中文说明：transport packet 层的 LayerData 是 NBL。
    list = (NET_BUFFER_LIST*)LayerData;
    // 中文说明：链中每个 NBL 保持原次序。
    while (list != NULL) {
        // 中文说明：取得当前 NBL 的首个 NET_BUFFER。
        NET_BUFFER* buffer = NET_BUFFER_LIST_FIRST_NB(list);
        // 中文说明：遍历真实 NB，不凭空切分 offload 数据。
        while (buffer != NULL) {
            // 中文说明：复制后立即恢复所有 data offset，再写原 ring。
            KswordARKLoopbackCapture(buffer, config, Metadata, local, remote, protocol, generation);
            // 中文说明：推进当前 NB 链。
            buffer = NET_BUFFER_NEXT_NB(buffer);
        }
        // 中文说明：推进 NBL 链。
        list = NET_BUFFER_LIST_NEXT_NBL(list);
    }
}

// 中文说明：观察过滤器无额外 flow/filter 生命周期状态。
static NTSTATUS NTAPI KswordARKLoopbackNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER0* Filter)
{
    // 中文说明：接受新增和删除通知。
    UNREFERENCED_PARAMETER(NotifyType);
    // 中文说明：不保存过滤器键。
    UNREFERENCED_PARAMETER(FilterKey);
    // 中文说明：不保存内核过滤器指针。
    UNREFERENCED_PARAMETER(Filter);
    // 中文说明：无状态通知成功。
    return STATUS_SUCCESS;
}

// 中文说明：父注册只调用一次，任何部分失败都由父层统一回滚。
NTSTATUS KswordARKNetworkTrafficLoopbackRegister(_Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime)
{
    // 中文说明：遍历稳定的两个入站层。
    ULONG index = 0UL;
    // 中文说明：设备对象由父初始化保证，这里仍验证必要参数。
    if (Runtime == NULL || Runtime->DeviceObject == NULL) {
        // 中文说明：不调用带空设备的 WFP API。
        return STATUS_INVALID_PARAMETER;
    }
    // 中文说明：与 IPPACKET 同属驱动原运行时生命周期。
    for (index = 0UL; index < KSWORD_ARK_LOOPBACK_CALLOUT_COUNT; ++index) {
        // 中文说明：每层独立 runtime callout。
        FWPS_CALLOUT0 callout = { 0 };
        // 中文说明：保存精确 WFP 状态。
        NTSTATUS status = STATUS_SUCCESS;
        // 中文说明：使用稳定驱动 GUID。
        callout.calloutKey = g_LoopbackCallouts[index].CalloutKey;
        // 中文说明：两层共用 loopback-only 入站回调。
        callout.classifyFn = KswordARKLoopbackClassify;
        // 中文说明：过滤器通知无需额外上下文。
        callout.notifyFn = KswordARKLoopbackNotify;
        // 中文说明：注册 ID 保留给逆序清退。
        status = FwpsCalloutRegister0(Runtime->DeviceObject, &callout, &g_LoopbackCallouts[index].CalloutId);
        // 中文说明：失败立即返回，父层负责普通层和回环层整体回滚。
        if (!NT_SUCCESS(status)) {
            // 中文说明：不把部分注册作为成功。
            return status;
        }
    }
    // 中文说明：两个入站层 runtime 成功。
    return STATUS_SUCCESS;
}

// 中文说明：全部对象都加入父动态 engine 的现有事务。
NTSTATUS KswordARKNetworkTrafficLoopbackAdd(_Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime)
{
    // 中文说明：保存层索引。
    ULONG index = 0UL;
    // 中文说明：没有父 engine 时不创建独立会话。
    if (Runtime == NULL || Runtime->EngineHandle == NULL) {
        // 中文说明：明确报告父初始化不完整。
        return STATUS_INVALID_PARAMETER;
    }
    // 中文说明：每层先添加 callout，再添加仅回环匹配的 filter。
    for (index = 0UL; index < KSWORD_ARK_LOOPBACK_CALLOUT_COUNT; ++index) {
        // 中文说明：构造 engine callout。
        FWPM_CALLOUT0 callout = { 0 };
        // 中文说明：构造非终止 inspection filter。
        FWPM_FILTER0 filter = { 0 };
        // 中文说明：唯一匹配条件是 WFP 的 IS_LOOPBACK 标志。
        FWPM_FILTER_CONDITION0 condition = { 0 };
        // 中文说明：保存精确事务错误。
        NTSTATUS status = STATUS_SUCCESS;
        // 中文说明：管理对象与 runtime 使用同一稳定 GUID。
        callout.calloutKey = g_LoopbackCallouts[index].CalloutKey;
        // 中文说明：诊断名称不参与匹配。
        callout.displayData.name = L"KswordARK inbound loopback IP packet callout";
        // 中文说明：仅绑定真实 v4/v6 入站 transport 层。
        callout.applicableLayer = g_LoopbackCallouts[index].LayerKey;
        // 中文说明：使用父 engine 与父事务。
        status = FwpmCalloutAdd0(Runtime->EngineHandle, &callout, NULL, NULL);
        // 中文说明：错误交给父事务整体撤销。
        if (!NT_SUCCESS(status)) {
            // 中文说明：不继续添加不完整来源。
            return status;
        }
        // 中文说明：内置 FLAGS 条件，不通过 127/8 地址猜测回环。
        condition.fieldKey = KswordARKNetworkTrafficFlagsCondition;
        // 中文说明：其它标志可同时存在，但必须包含 IS_LOOPBACK。
        condition.matchType = FWP_MATCH_FLAGS_ALL_SET;
        // 中文说明：WFP FLAGS 类型为 UINT32。
        condition.conditionValue.type = FWP_UINT32;
        // 中文说明：只观察 Windows 标识的回环包。
        condition.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        // 中文说明：绑定同一 transport 层。
        filter.layerKey = g_LoopbackCallouts[index].LayerKey;
        // 中文说明：保留可识别的 BFE 诊断名称。
        filter.displayData.name = L"KswordARK inbound loopback-only IP packet filter";
        // 中文说明：复用原动态子层。
        filter.subLayerKey = g_LoopbackSublayer;
        // 中文说明：沿用普通逐包观察的空权重。
        filter.weight.type = FWP_EMPTY;
        // 中文说明：不改变最终防火墙 permit/block 结果。
        filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
        // 中文说明：动作绑定本层 runtime callout。
        filter.action.calloutKey = g_LoopbackCallouts[index].CalloutKey;
        // 中文说明：过滤器只有一个 loopback 条件。
        filter.numFilterConditions = 1UL;
        // 中文说明：条件栈内生命周期覆盖同步 FwpmFilterAdd0。
        filter.filterCondition = &condition;
        // 中文说明：保存 filter ID 用于父会话显式卸载。
        status = FwpmFilterAdd0(Runtime->EngineHandle, &filter, NULL, &g_LoopbackCallouts[index].FilterId);
        // 中文说明：任一层失败都由父事务回滚。
        if (!NT_SUCCESS(status)) {
            // 中文说明：不报告局部来源就绪。
            return status;
        }
    }
    // 中文说明：两个入站层全部加入父事务。
    return STATUS_SUCCESS;
}

// 中文说明：部分添加、事务 abort 或重复清理均安全。
VOID KswordARKNetworkTrafficLoopbackDelete(_Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime)
{
    // 中文说明：逆序释放，先解除 filter 引用。
    LONG index = 0L;
    // 中文说明：无父运行时无需操作。
    if (Runtime == NULL) {
        // 中文说明：保持空清理幂等。
        return;
    }
    // 中文说明：所有过滤器先于 callout 删除。
    for (index = (LONG)KSWORD_ARK_LOOPBACK_CALLOUT_COUNT - 1L; index >= 0L; --index) {
        // 中文说明：动态会话可能已随 abort 移除对象。
        if (Runtime->EngineHandle != NULL && g_LoopbackCallouts[index].FilterId != 0ULL) {
            // 中文说明：忽略单项清理错误，继续释放其余过滤器。
            (VOID)FwpmFilterDeleteById0(Runtime->EngineHandle, g_LoopbackCallouts[index].FilterId);
        }
        // 中文说明：事务已回滚的 ID 也必须清零。
        g_LoopbackCallouts[index].FilterId = 0ULL;
    }
    // 中文说明：父 engine 仍存在时删除 engine callout。
    if (Runtime->EngineHandle != NULL) {
        // 中文说明：逆序删除稳定对象键。
        for (index = (LONG)KSWORD_ARK_LOOPBACK_CALLOUT_COUNT - 1L; index >= 0L; --index) {
            // 中文说明：对象不存在表示父事务已撤销，同样继续清理。
            (VOID)FwpmCalloutDeleteByKey0(Runtime->EngineHandle, &g_LoopbackCallouts[index].CalloutKey);
        }
    }
}

// 中文说明：Fwps 注销等待活动 classify 回调结束，不能先销毁原 ring。
VOID KswordARKNetworkTrafficLoopbackUnregister(VOID)
{
    // 中文说明：按注册逆序清退。
    LONG index = 0L;
    // 中文说明：部分注册失败同样经过这里。
    for (index = (LONG)KSWORD_ARK_LOOPBACK_CALLOUT_COUNT - 1L; index >= 0L; --index) {
        // 中文说明：只注销已成功注册的 runtime ID。
        if (g_LoopbackCallouts[index].CalloutId != 0U) {
            // 中文说明：不触碰其它模块或其它驱动的 callout。
            (VOID)FwpsCalloutUnregisterById0(g_LoopbackCallouts[index].CalloutId);
            // 中文说明：清零已清退 ID，使重复清理无副作用。
            g_LoopbackCallouts[index].CalloutId = 0U;
        }
    }
}
