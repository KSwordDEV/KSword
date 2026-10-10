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
    const auto status = result.trustStatus;
    const auto state = status == ERROR_SUCCESS ? L"trusted" : status == TRUST_E_NOSIGNATURE ? L"unsigned" : status == CERT_E_EXPIRED ? L"expired" :
        status == TRUST_E_BAD_DIGEST ? L"bad-digest" : L"not-trusted";
    const bool verdict = status == ERROR_SUCCESS || status == TRUST_E_NOSIGNATURE || status == CERT_E_EXPIRED || status == TRUST_E_BAD_DIGEST ||
        status == CERT_E_UNTRUSTEDROOT || status == CERT_E_CHAINING || status == TRUST_E_EXPLICIT_DISTRUST || status == TRUST_E_SUBJECT_NOT_TRUSTED;
    const int code = !result.evaluated ? 3 : verdict ? 0 : status == TRUST_E_PROVIDER_UNKNOWN || status == TRUST_E_SUBJECT_FORM_UNKNOWN ? 5 : 3;
    return {code, Json::object({{L"path", Json::string(path)}, {L"source", Json::string(L"WinVerifyTrust/Authenticode")},
        {L"evaluated", Json::boolean(result.evaluated)}, {L"trusted", Json::boolean(result.evaluated && status == ERROR_SUCCESS)},
        {L"signatureState", Json::string(state)}, {L"trustStatus", Json::hex(static_cast<DWORD>(status))}, {L"description", Json::string(result.message)},
        {L"revocationChecked", Json::boolean(false)}, {L"networkRetrieval", Json::boolean(false)}})};
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
        L"Fields: evaluated, trusted, signatureState, trustStatus, revocationChecked, networkRetrieval. Query success is independent of trust; unsigned and untrusted files remain explicitly marked.", signature});
}
}
