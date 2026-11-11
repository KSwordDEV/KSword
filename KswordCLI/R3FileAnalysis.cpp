#include "R3FileShared.h"
#include "../shared/usermode/backend/file/FileAnalysis.h"
#include <wintrust.h>
#include <softpub.h>
namespace ks::cli {
namespace {
namespace backend = ks::r3::file;
Result hash(const Args& args) {
    const auto path = file::path(args, L"--path"); const auto result = backend::ReadSha256(path);
    return {result.success ? 0 : 3, Json::object({{L"path", Json::string(path)}, {L"algorithm", Json::string(L"SHA256")},
        {L"digest", result.success ? Json::string(result.digest) : Json{}}, {L"bytesRead", Json::count(result.bytesRead)},
        {L"complete", Json::boolean(result.success)}, {L"win32Error", Json::number(result.errorCode)}}),
        result.errorText.empty() ? std::vector<std::wstring>{} : std::vector<std::wstring>{result.errorText}};
}
Result entropy(const Args& args) {
    const auto path = file::path(args, L"--path"); const auto budget = args.integer(L"--max-bytes", 16ull * 1024 * 1024);
    if (!budget) throw std::invalid_argument("--max-bytes must be positive");
    const auto result = backend::ReadFileEntropy(path, budget);
    const int code = result.complete ? 0 : result.sampled || result.success ? 6 : 3;
    return {code, Json::object({{L"path", Json::string(path)}, {L"maxBytes", Json::count(budget)}, {L"sampledBytes", Json::count(result.sampled)},
        {L"sizeBytes", result.sizeKnown ? Json::count(result.size) : Json{}}, {L"bitsPerByte", result.success || result.sampled ? Json::real(result.bitsPerByte) : Json{}},
        {L"complete", Json::boolean(result.complete)}, {L"limited", Json::boolean(result.limited)}, {L"win32Error", Json::number(result.errorCode)}}),
        result.limited ? std::vector<std::wstring>{L"Entropy covers only the byte budget, not the whole file."} : result.errorCode ?
            std::vector<std::wstring>{L"File read failed; any available entropy describes only the returned prefix."} : std::vector<std::wstring>{}};
}
Result signature(const Args& args) {
    const auto path = file::path(args, L"--path"); const auto target = file::evidence(path);
    if (!target.present || target.directory()) return {3, Json::object({{L"path", Json::string(path)}, {L"target", target.json()}}), {L"Target file metadata is unavailable or the target is a directory."}};
    const auto result = backend::ReadEmbeddedSignature(path);
    const auto catalog = backend::ReadCatalogSignature(path);
    const auto status = result.trustStatus;
    const auto embeddedState = status == ERROR_SUCCESS ? L"trusted" : status == TRUST_E_NOSIGNATURE ? L"no-embedded-signature" : status == CERT_E_EXPIRED ? L"expired" :
        status == TRUST_E_BAD_DIGEST ? L"bad-digest" : L"not-trusted";
    const bool verdict = status == ERROR_SUCCESS || status == TRUST_E_NOSIGNATURE || status == CERT_E_EXPIRED || status == TRUST_E_BAD_DIGEST ||
        status == CERT_E_UNTRUSTEDROOT || status == CERT_E_CHAINING || status == TRUST_E_EXPLICIT_DISTRUST || status == TRUST_E_SUBJECT_NOT_TRUSTED;
    const bool trusted = status == ERROR_SUCCESS || catalog.trusted;
    const auto known = [](LONG value) { return value == ERROR_SUCCESS || value == TRUST_E_NOSIGNATURE || value == CERT_E_EXPIRED ||
        value == TRUST_E_BAD_DIGEST || value == CERT_E_UNTRUSTEDROOT || value == CERT_E_CHAINING ||
        value == TRUST_E_EXPLICIT_DISTRUST || value == TRUST_E_SUBJECT_NOT_TRUSTED; };
    bool catalogKnownVerdict = catalog.evaluated;
    std::vector<Json> candidates;
    for (const auto& candidate : catalog.candidates) {
        const bool knownStatus = known(candidate.trustStatus);
        catalogKnownVerdict = catalogKnownVerdict && knownStatus;
        candidates.push_back(Json::object({{L"path",Json::string(candidate.catalogPath)}, {L"hashAlgorithm",Json::string(candidate.hashAlgorithm)},
            {L"trustStatus",Json::hex(static_cast<DWORD>(candidate.trustStatus))},
            {L"trusted",knownStatus ? Json::boolean(candidate.trustStatus == ERROR_SUCCESS) : Json{}}}));
    }
    const bool evidenceComplete = (catalog.complete || catalog.trusted) && result.evaluated && verdict && (!catalog.evaluated || catalogKnownVerdict || catalog.trusted);
    const bool effectiveKnown = trusted || (evidenceComplete && (status != TRUST_E_NOSIGNATURE || catalog.evaluated));
    const auto state = trusted ? L"trusted" : status == TRUST_E_NOSIGNATURE ?
        (catalog.evaluated && catalogKnownVerdict ? L"catalog-not-trusted" : L"no-embedded-signature") : embeddedState;
    const int code = evidenceComplete && effectiveKnown ? 0 :
        !trusted && catalog.complete && !catalog.evaluated && !verdict ?
            (status == TRUST_E_PROVIDER_UNKNOWN || status == TRUST_E_SUBJECT_FORM_UNKNOWN ? 5 : 3) : 6;
    return {code, Json::object({{L"path", Json::string(path)}, {L"source", Json::string(L"WinVerifyTrust/Authenticode")},
        {L"evaluated", Json::boolean(result.evaluated)}, {L"trusted", effectiveKnown ? Json::boolean(trusted) : Json{}},
        {L"signatureState", Json::string(state)}, {L"trustStatus", Json::hex(static_cast<DWORD>(status))}, {L"description", Json::string(result.message)},
        {L"embedded", Json::object({{L"evaluated",Json::boolean(result.evaluated)}, {L"state",Json::string(embeddedState)},
            {L"trustStatus",Json::hex(static_cast<DWORD>(status))}, {L"trusted",result.evaluated && verdict && status != TRUST_E_NOSIGNATURE ? Json::boolean(status == ERROR_SUCCESS) : Json{}}})},
        {L"catalog", Json::object({{L"evaluated",Json::boolean(catalog.evaluated)}, {L"trusted",catalog.trusted || catalogKnownVerdict ? Json::boolean(catalog.trusted) : Json{}},
            {L"trustStatus",catalog.evaluated ? Json::hex(static_cast<DWORD>(catalog.trustStatus)) : Json{}},
            {L"path",catalog.catalogPath.empty() ? Json{} : Json::string(catalog.catalogPath)},
            {L"hashAlgorithm",catalog.hashAlgorithm.empty() ? Json{} : Json::string(catalog.hashAlgorithm)},
            {L"catalogsExamined",Json::number(catalog.catalogsExamined)}, {L"searchComplete",Json::boolean(catalog.complete)},
            {L"candidates",Json::array(candidates)}, {L"win32Error",Json::number(catalog.errorCode)}})},
        {L"catalogChecked", Json::boolean(catalog.complete || catalog.trusted)}, {L"revocationChecked", Json::boolean(false)}, {L"networkRetrieval", Json::boolean(false)}}),
        {L"Catalog lookup covers installed driver-subsystem SHA256/SHA1 catalogs only. Cached-only trust does not check revocation; file contents can change during the separate checks."}};
}
}
void registerFileAnalysis() {
    addCommand({L"file hash query", L"KswordCLI.exe file hash query --path PATH [--backend r3] [--json]",
        L"Compute the whole-file SHA256 digest.", L"Required: --path. Optional: --backend r3, --json.",
        L"Fields: algorithm, digest, bytesRead, complete, win32Error. Any read/hash failure returns no digest. Shared writable files are not atomic snapshots.", hash});
    addCommand({L"file entropy query", L"KswordCLI.exe file entropy query --path PATH [--max-bytes N] [--backend r3] [--json]",
        L"Compute byte Shannon entropy over a bounded file prefix.", L"Required: --path. Optional: --max-bytes positive (default 16777216), --backend r3, --json.",
        L"Fields: bitsPerByte, sampledBytes, sizeBytes, limited, complete, win32Error. Budget-limited or partially read prefixes return 6; unreadable files return 3; empty files have entropy 0.", entropy});
    addCommand({L"file signature query", L"KswordCLI.exe file signature query --path PATH [--backend r3] [--json]",
        L"Query Authenticode trust with cached-only retrieval and no revocation check.", L"Required: --path. Optional: --backend r3, --json.",
        L"Reports embedded and installed driver-subsystem SHA256/SHA1 catalog evidence independently. trusted is true if either verifies; absent or incomplete evidence is unknown and returns 6. trustStatus retains the embedded status; catalog includes its own status, path, searchComplete and errors. Cached-only; no revocation or atomic file snapshot.", signature});
}
}
