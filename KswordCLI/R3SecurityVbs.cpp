#include "R3SecurityShared.h"
#include "../shared/usermode/backend/security/Vbs.h"
namespace ks::cli {
void registerSecurityVbs(){security::add(L"security vbs query",L"Query VBS/HVCI/SKCI CIM, configured registry values and disk availability.",[](const Args& a){return security::query(a,ks::r3::security::VbsProbes());});
    security::add(L"security vbs device-guard query",L"Read VBS status/configured/running service properties from CIM.",[](const Args& a){return security::query(a,ks::r3::security::VbsProbes(),{L"device-guard"});});
    security::add(L"security vbs hvci query",L"Read configured HVCI Enabled/WasEnabledBy/Locked registry values.",[](const Args& a){return security::query(a,ks::r3::security::VbsProbes(),{L"hvci-enabled",L"hvci-was-enabled-by",L"hvci-locked"});});
    security::add(L"security vbs registry query",L"Read configured VBS/platform/LSA registry values.",[](const Args& a){return security::query(a,ks::r3::security::VbsProbes(),{L"enable-vbs",L"require-platform",L"lsa-flags"});});
    security::add(L"security vbs files enum",L"Query securekernel/skci/ci disk-file presence; no active module claim.",[](const Args& a){return security::query(a,ks::r3::security::VbsProbes(),{L"system-files"});});
}
}
