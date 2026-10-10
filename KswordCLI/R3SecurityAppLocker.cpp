#include "R3SecurityShared.h"
#include "../shared/usermode/backend/security/AppLocker.h"
namespace ks::cli {
void registerSecurityAppLocker(){security::add(L"security applocker query",L"Query effective rule counts, AppID/service/log/configuration evidence.",[](const Args& a){return security::query(a,ks::r3::security::AppLockerProbes());});
    security::add(L"security applocker policy query",L"Read effective policy collection/rule counts; no execution permission prediction.",[](const Args& a){return security::query(a,ks::r3::security::AppLockerProbes(),{L"effective-policy"});});
    security::add(L"security applocker service query",L"Read AppIDSvc current status and configured start type.",[](const Args& a){return security::query(a,ks::r3::security::AppLockerProbes(),{L"appid-service"});});
    security::add(L"security applocker event-log query",L"Read existing AppLocker/CI channel enabled/record-count metadata.",[](const Args& a){return security::query(a,ks::r3::security::AppLockerProbes(),{L"event-logs"});});
    security::add(L"security applocker drivers query",L"Read AppID/applockerfltr/mssecflt SCM registration/status.",[](const Args& a){return security::query(a,ks::r3::security::AppLockerProbes(),{L"appid",L"applocker-filter",L"security-filter"});});
    security::add(L"security applocker registry query",L"Read configured SRP DefaultLevel in HKLM64.",[](const Args& a){return security::query(a,ks::r3::security::AppLockerProbes(),{L"srp-default-level"});});
}
}
