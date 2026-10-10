#include "R3SecurityShared.h"
#include "../shared/usermode/backend/security/BugcheckEvidence.h"
namespace ks::cli {
void registerSecurityBugcheck(){const auto query=[](const Args& a){auto result=security::query(a,ks::r3::security::BugcheckEnvironmentProbes());result.diagnostics.push_back(L"This migrated R3 backend exposes computer manufacturer/model only. It does not query bugcheck history/dumps, validate a crash, modify branding or trigger a bugcheck. Environment strings are reported labels, not trusted VMware/vendor attestation.");return result;};
    const std::wstring notes=L"Payload: available, manufacturer, model and environmentOnly. The migrated backend has only this one computer-system source; no crash history/dumps, crash validation, branding writes or bugcheck trigger. Strings are reported environment labels, not trusted VMware/vendor attestation.";
    security::add(L"security bugcheck query",L"Read the existing R3 computer environment evidence; no crash history or trigger.",query,notes);
    security::add(L"security bugcheck environment query",L"Read reported manufacturer/model only; no VMware attestation or crash proof.",query,notes);
}
}
