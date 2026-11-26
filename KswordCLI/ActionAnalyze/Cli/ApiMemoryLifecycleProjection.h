#pragma once
#include "../../../shared/evidence/ApiMemoryLifecycleFields.h"
#include "../../../shared/evidence/EvidenceJson.h"
#include "../../CommandRegistry.h"

namespace ks::cli::action_analyze {
// fields为已核验AAIM1，session为同包会话；返回无损JSON，不授予图角色或region代次。
Ksword::Evidence::JsonValue ApiMemoryLifecycleJson(const Ksword::Evidence::ApiMemoryLifecycleFieldsV1& fields,
    std::uint64_t session);
// packet为完整原API包；无合法AAIM1时返回null，供api detail与monitor原输出共用。
Json ApiMemoryLifecycleCliJson(const ks::winapi_monitor::ApiMonitorEventPacket& packet);
} // namespace ks::cli::action_analyze
