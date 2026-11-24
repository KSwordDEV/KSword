#include "CommandRegistry.h"
#include "../shared/usermode/ThreadLayoutProfile.h"

#include <Windows.h>
#include <stdexcept>

namespace ks::cli {
namespace {
namespace layout = ks::threadlayout;
namespace fs = std::filesystem;

fs::path systemKernelPath()
{
    std::wstring system(32768, L'\0');
    const auto length = ::GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size()));
    if (!length || length >= system.size()) return {};
    system.resize(length);
    return fs::path(system) / L"ntoskrnl.exe";
}

fs::path executableProfileRoot()
{
    std::wstring image(32768, L'\0');
    const auto length = ::GetModuleFileNameW(nullptr, image.data(), static_cast<DWORD>(image.size()));
    if (!length || length >= image.size()) return {};
    image.resize(length);
    return fs::path(image).parent_path() / L"profiles";
}

// TSV field text must be UTF-8. Do not substitute invented characters on decode failure.
std::wstring profileText(const std::string& text)
{
    const auto bytes = static_cast<int>(text.size()); // The shared loader bounds each column.
    const auto length = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), bytes, nullptr, 0);
    if (!length) return {};
    std::wstring result(length, L'\0');
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), bytes, result.data(), length) != length)
        return {};
    return result;
}

Json pathJson(const fs::path& path) { return path.empty() ? Json{} : Json::string(path.wstring()); }

Result queryLayout(const Args& args, const layout::Kind kind)
{
    const auto imageOption = args.get(L"--image");
    const auto profilesOption = args.get(L"--profiles");
    if (args.has(L"--image") && imageOption.empty()) throw std::invalid_argument("--image must not be empty");
    if (args.has(L"--profiles") && profilesOption.empty()) throw std::invalid_argument("--profiles must not be empty");

    const auto image = args.has(L"--image") ? fs::path(imageOption) : systemKernelPath();
    const auto profiles = args.has(L"--profiles") ? fs::path(profilesOption) : executableProfileRoot();
    const auto identity = image.empty() ? layout::Identity{} : layout::ReadImageIdentity(image);
    const bool hasIdentity = identity.machine != 0 && identity.imageSize != 0 && !identity.pdbKey.empty();
    const auto shard = hasIdentity && !profiles.empty()
        ? profiles / layout::PackFileName : fs::path{}; // 包路径是真实来源，不再报告不存在的外置 TSV。
    const auto output = [&](const wchar_t* availability, Json rootSize, const std::vector<Json>& fields)
    {
        return Json::object({
            {L"availability", Json::string(availability)},
            {L"source", Json::string(L"pdb_layout_profile")},
            {L"metadataOnly", Json::boolean(true)},
            {L"rootType", Json::string(kind == layout::Kind::Thread ? L"_ETHREAD" : L"_EPROCESS")},
            {L"imagePath", pathJson(image)},
            {L"imageIdentity", hasIdentity ? Json::object({
                {L"machine", Json::number(identity.machine)}, {L"timestamp", Json::number(identity.timestamp)},
                {L"imageSize", Json::number(identity.imageSize)}, {L"pdbKey", Json::string(profileText(identity.pdbKey))}
            }) : Json{}},
            {L"profilePath", pathJson(shard)},
            {L"rootSize", rootSize},
            {L"fields", Json::array(fields)}
        });
    };
    if (!hasIdentity)
        return {5, output(L"image_identity_unavailable", {}, {}), {L"Could not read an AMD64 disk PE with an RSDS identity."}};
    if (shard.empty())
        return {5, output(L"profile_directory_unavailable", {}, {}), {L"Could not locate the profiles directory beside the CLI executable."}};

    // v4 索引只定位候选；共享消费者仍精确核对 PE/RSDS 和根类型，不使用邻版读取。
    const auto profile = layout::LoadPack(shard, identity, kind);
    if (profile.fields.empty())
        return {5, output(L"profile_unavailable", {}, {}), {L"The exact layout profile is missing, unreadable, invalid, or does not match the disk PE/RSDS identity."}};

    std::vector<Json> fields;
    fields.reserve(profile.fields.size());
    for (const auto& field : profile.fields)
    {
        const auto name = profileText(field.name);
        const auto type = profileText(field.type);
        if (name.empty() || type.empty())
            return {5, output(L"profile_unavailable", {}, {}), {L"The layout profile contains invalid UTF-8 field text."}};

        fields.push_back(Json::object({
            {L"id", Json::number(static_cast<std::uint32_t>(fields.size() + 1))},
            {L"parent", Json::number(field.parent)},
            {L"offset", Json::number(field.offset)},
            {L"name", Json::string(name)},
            {L"type", Json::string(type)},
            {L"bitOffset", field.bitOffset < 0 ? Json{} : Json::signedNumber(field.bitOffset)},
            {L"bitWidth", field.bitWidth < 0 ? Json{} : Json::signedNumber(field.bitWidth)},
            {L"unionAlias", Json::boolean(field.unionAlias)}
        }));
    }
    return {0, output(L"available", Json::number(profile.rootSize), fields), {}};
}
}

void registerProcessLayouts()
{
    const auto add = [](const wchar_t* path, const wchar_t* summary, const layout::Kind kind)
    {
        addCommand({path, std::wstring(L"KswordCLI.exe ") + path + L" [--image PATH] [--profiles DIR] [--json]",
            summary,
            L"Optional: --image disk PE (default: system ntoskrnl.exe), --profiles directory containing ark_dyndata_pack_v4.json.qz (default: profiles beside the CLI executable), --json.",
            L"Read-only disk metadata; matches the PE identity and RSDS GUID/Age. Offsets are relative to each parent. Union markers do not select an active branch. No live object values or driver access; unavailable evidence returns exit 5.",
            [kind](const Args& args) { return queryLayout(args, kind); }});
    };
    add(L"process thread layout query", L"Query the exact PDB-derived _ETHREAD layout for a disk kernel.", layout::Kind::Thread);
    add(L"process layout query", L"Query the exact PDB-derived _EPROCESS layout for a disk kernel.", layout::Kind::Process);
}
}
