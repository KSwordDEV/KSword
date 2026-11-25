#pragma once

#include "PacketEvidenceProjection.h"

namespace ks::network {
struct PacketRecord;
}

namespace ks::r3::monitor {

// 仅由既有、已获授权的 R3 Raw Socket 所有者对已捕获 PacketRecord 调用。
// collector 取自真实源并提供其自己的采集序号。scope/proof 绑定同一来源代次和强实例。
// 这个适配器无需启动或订阅抓包。
PacketEvidenceProjection ProjectExistingRawSocketPacket(
    const NetworkSampleScopeView& scope, const PacketCollectorRecordView& collector,
    const ks::network::PacketRecord& record,
    const std::optional<PacketProcessEvidenceView>& proof);

} // namespace ks::r3::monitor
