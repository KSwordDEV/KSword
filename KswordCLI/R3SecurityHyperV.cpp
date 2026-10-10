#include "R3SecurityShared.h"
#include "../shared/usermode/backend/security/HyperV.h"
namespace ks::cli {
void registerSecurityHyperV(){security::add(L"security hyperv query",L"Query R3 hypervisor/feature/PnP/service/configuration evidence.",[](const Args& a){return security::query(a,ks::r3::security::HyperVProbes());});
    security::add(L"security hyperv computer-system query",L"Read generic hypervisor flag and computer manufacturer/model from CIM.",[](const Args& a){return security::query(a,ks::r3::security::HyperVProbes(),{L"computer-system"});});
    security::add(L"security hyperv features enum",L"Read four existing Windows optional-feature registrations/states.",[](const Args& a){return security::query(a,ks::r3::security::HyperVProbes(),{L"optional-features"});});
    security::add(L"security hyperv devices enum",L"Read existing Hyper-V/VMBus-related PnP name candidates (40 rows).",[](const Args& a){return security::query(a,ks::r3::security::HyperVProbes(),{L"pnp-candidates"});});
    security::add(L"security hyperv services query",L"Read VMBus/VMSMP/HvHost/vpci SCM registration/status.",[](const Args& a){return security::query(a,ks::r3::security::HyperVProbes(),{L"vmbus",L"vmsmp",L"hvhost",L"vpci"});});
    security::add(L"security hyperv registry query",L"Read DeviceGuard HVCI configuration; not a BCD hypervisor launch type.",[](const Args& a){return security::query(a,ks::r3::security::HyperVProbes(),{L"device-guard-hvci"});});
}
}
