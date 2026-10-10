#include "R3FileShared.h"
#include "../shared/usermode/backend/kernel/HookDiskBaseline.h"
#include <algorithm>
namespace ks::cli {
namespace {
namespace b=ks::r3::kernel::disk;
Result query(const Args& a,bool compare){Args normalized=a;normalized.values[L"--path"]=b::NormalizeKernelModulePath(a.require(L"--path"));const auto path=file::path(normalized,L"--path");const auto rva=a.u32(L"--rva");a.require(L"--rva");
    const auto supplied=compare?parseHexPayload(a.require(L"--bytes")):std::vector<std::uint8_t>{};const auto count=compare?static_cast<DWORD>(supplied.size()):a.u32(L"--count",KSWORD_ARK_KERNEL_HOOK_BYTES);
    if(!count||count>KSWORD_ARK_KERNEL_HOOK_BYTES)throw std::invalid_argument("baseline byte count must be 1..16");
    std::vector<std::uint8_t> fileBytes,bytes;b::DiskReadEvidence read;b::RvaEvidence mapping;const bool fileRead=b::ReadWholeBinaryFile(path,fileBytes,&read);std::uint64_t offset=0;
    const bool mapped=fileRead&&b::RvaToFileOffset(fileBytes,rva,count,offset,&mapping);if(mapped)bytes.assign(fileBytes.begin()+static_cast<std::ptrdiff_t>(offset),fileBytes.begin()+static_cast<std::ptrdiff_t>(offset+count));
    const auto fileId=(std::uint64_t(read.identity.nFileIndexHigh)<<32)|read.identity.nFileIndexLow;const auto writeTime=(std::uint64_t(read.identity.ftLastWriteTime.dwHighDateTime)<<32)|read.identity.ftLastWriteTime.dwLowDateTime;
    const int code=mapping.malformed||read.error==ERROR_BAD_EXE_FORMAT?4:read.limited?5:!fileRead?3:!mapped?5:!read.closed||!read.identityKnown||read.identityChanged?6:0;
    return {code,Json::object({{L"source",Json::string(L"shared disk PE RVA-to-file baseline; no live memory read")},{L"path",Json::string(path)},{L"rva",Json::hex(rva)},
        {L"requestedByteCount",Json::count(count)},{L"available",Json::boolean(mapped)},{L"fileOffset",mapped?Json::hex(offset):Json{}},{L"byteCount",Json::count(bytes.size())},{L"bytesHex",mapped?Json::bytes(bytes,bytes.size()):Json{}},
        {L"comparisonSource",compare?Json::string(L"caller-supplied bytes; origin unverified"):Json{}},{L"suppliedBytesHex",compare?Json::bytes(supplied,supplied.size()):Json{}},
        {L"differs",compare&&mapped?Json::boolean(bytes!=supplied):Json{}},
        {L"mapping",Json::object({{L"validPe",Json::boolean(mapping.validPe)},{L"mapped",Json::boolean(mapping.mapped)},{L"malformed",Json::boolean(mapping.malformed)},
            {L"optionalMagic",mapping.validPe?Json::hex(mapping.optionalMagic):Json{}}})},
        {L"file",Json::object({{L"opened",Json::boolean(read.opened)},{L"sizeKnown",Json::boolean(read.sizeKnown)},{L"sizeBytes",read.sizeKnown?Json::count(read.size):Json{}},
            {L"bytesRead",Json::count(read.bytesRead)},{L"complete",Json::boolean(read.complete)},{L"limited",Json::boolean(read.limited)},{L"win32Error",Json::number(read.error)},
            {L"identityKnown",Json::boolean(read.identityKnown)},{L"identityWin32Error",Json::number(read.identityError)},{L"identityChanged",read.identityKnown?Json::boolean(read.identityChanged):Json{}},
            {L"volumeSerialNumber",read.identityKnown?Json::hex(read.identity.dwVolumeSerialNumber):Json{}},{L"fileId",read.identityKnown?Json::hex(fileId):Json{}},{L"lastWriteTime",read.identityKnown?Json::count(writeTime):Json{}},
            {L"closeAttempted",Json::boolean(read.closeAttempted)},{L"closed",read.closeAttempted?Json::boolean(read.closed):Json{}},{L"closeWin32Error",read.closeAttempted?Json::number(read.closeError):Json{}}})}}),
        {L"Disk bytes only. Compare uses caller-supplied bytes whose process/kernel/module identity and origin are not verified; a difference is not a detected live hook. The original Light adapter can pair R0-provided bytes with this mapping; this R3 CLI does not request them. Header/section/raw range arithmetic uses 64-bit bounds; zero-filled virtual tails and unmapped RVAs have no disk bytes. Read cap 128 MiB; requested baseline 1..16 bytes. File identity and write metadata before/after reading are observations, not an atomic content snapshot; concurrent writes may escape timestamp checks. No driver, memory/patch operation or R0 fallback."}};
}
}
void registerKernelHookBaseline(){const std::wstring notes=L"Output: source/path/RVA, requested/returned byte counts, available/fileOffset/bytesHex, PE mapping magic/valid/malformed, file open/read/size/identity/change/close evidence; compare additionally reports supplied bytes, unverified comparisonSource and nullable differs. Disk PE headers/sections/raw ranges bounded with 64-bit arithmetic. File read cap 128 MiB; no disk bytes for unmapped/zero-fill tail. Complete evidence 0 (including a verified byte difference), file I/O failure 3, malformed PE 4, size cap/unmapped bytes 5, identity/change/close limitation 6. No live hook conclusion, driver open, memory query/patch or R0 fallback. Help performs no file read.";
    addCommand({L"kernel hook-baseline query",L"KswordCLI.exe kernel hook-baseline query --path PATH --rva N [--count N] [--backend r3] [--json]",L"Read 1..16 disk PE bytes at an RVA using the shared hook baseline mapper.",
        L"Required: --path disk PE file (Win32 path; SystemRoot/NT DOS prefixes normalized); --rva uint32. Optional: --count 1..16 (16); --backend r3; --json.",notes,[](const Args& a){return query(a,false);}});
    addCommand({L"kernel hook-baseline compare",L"KswordCLI.exe kernel hook-baseline compare --path PATH --rva N --bytes HEX [--backend r3] [--json]",L"Compare caller-supplied bytes with disk PE baseline; no live hook claim.",
        L"Required: --path disk PE file; --rva uint32; --bytes hex payload of 1..16 bytes. Optional: --backend r3; --json.",notes,[](const Args& a){return query(a,true);}});
}
}
