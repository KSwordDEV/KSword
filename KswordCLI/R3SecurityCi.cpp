#include "R3SecurityShared.h"
namespace ks::cli {
void registerSecurityCi(){addFamily(L"security",L"Query public R3 security configuration and availability evidence.");const auto query=[](const Args& a){return security::query(a,ks::r3::security::CodeIntegrityProbes());};security::add(L"security ci query",L"Query R3 CI/WDAC configuration, cached state and availability evidence.",query);
    security::add(L"security ci device-guard query",L"Read CIM DeviceGuard CI policy/service properties.",[](const Args& a){return security::query(a,ks::r3::security::CodeIntegrityProbes(),{L"device-guard"});});
    security::add(L"security ci policy-files enum",L"Count files in CI policy directories; no activation/enforcement claim.",[](const Args& a){return security::query(a,ks::r3::security::CodeIntegrityProbes(),{L"policy-files"});});
    security::add(L"security ci registry query",L"Read CI policy/configuration and SecureBoot cache values in HKLM64.",[](const Args& a){return security::query(a,ks::r3::security::CodeIntegrityProbes(),{L"upgraded-system",L"enabled",L"secure-boot-cache"});});
    security::add(L"security ci service query",L"Query CI driver service registration/status; no loaded-module proof.",[](const Args& a){return security::query(a,ks::r3::security::CodeIntegrityProbes(),{L"ci-service"});});
}
}
