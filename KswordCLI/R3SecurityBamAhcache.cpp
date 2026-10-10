#include "R3SecurityShared.h"
#include "../shared/usermode/backend/security/BamAhcache.h"
namespace ks::cli {
void registerSecurityBamAhcache(){security::add(L"security bam query",L"Read BAM UserSettings count and driver service summary, no execution history.",[](const Args& a){return security::query(a,ks::r3::security::BamAhcacheProbes(),{L"bam-summary",L"bam-service"});});
    security::add(L"security bam registry query",L"Count existing BAM UserSettings child keys; no SID/value/path history.",[](const Args& a){return security::query(a,ks::r3::security::BamAhcacheProbes(),{L"bam-summary"});});
    security::add(L"security bam service query",L"Read BAM SCM registration/status.",[](const Args& a){return security::query(a,ks::r3::security::BamAhcacheProbes(),{L"bam-service"});});
    security::add(L"security ahcache query",L"Read Amcache disk/key/service summaries, no hive or execution history.",[](const Args& a){return security::query(a,ks::r3::security::BamAhcacheProbes(),{L"amcache-file",L"appcompat-keys",L"ahcache-service"});});
    security::add(L"security ahcache amcache query",L"Read Amcache.hve presence/size/write-time metadata only.",[](const Args& a){return security::query(a,ks::r3::security::BamAhcacheProbes(),{L"amcache-file"});});
    security::add(L"security ahcache registry query",L"Read AppCompatCache/AppCompatFlags key existence only.",[](const Args& a){return security::query(a,ks::r3::security::BamAhcacheProbes(),{L"appcompat-keys"});});
    security::add(L"security ahcache service query",L"Read ahcache SCM registration/status.",[](const Args& a){return security::query(a,ks::r3::security::BamAhcacheProbes(),{L"ahcache-service"});});
}
}
