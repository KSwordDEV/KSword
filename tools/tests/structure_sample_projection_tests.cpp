#include "../../shared/usermode/StructureSampleProjection.h"

#include <iostream>
#include <limits>
#include <set>

namespace
{
    namespace sample = ks::structure_sample;
    namespace layout = ks::threadlayout;
    int failures = 0;

    void Check(const bool value, const char* message)
    {
        std::cout << (value ? "PASS " : "FAIL ") << message << '\n';
        failures += !value;
    }

    layout::Field Field(const std::uint32_t parent, const std::uint32_t offset, const char* name,
        const char* type, const int bit = -1, const int width = -1, const bool alias = false)
    {
        return {parent, offset, name, type, bit, width, alias};
    }
}

int wmain(const int argc, wchar_t** argv)
{
    layout::Profile profile;
    profile.identity = {0x8664, 123, 456, "0123456789ABCDEF0123456789ABCDEF1"};
    profile.rootSize = 64;
    profile.fields = {
        Field(0, 0, "Nested", "_NESTED"),
        Field(1, 0, "Negative", "0x0012 (long)"),
        Field(1, 4, "Bits", "bitfield(0x0022 (unsigned long), offset=3, bits=2)", 3, 2),
        Field(0, 8, "Pointer", "_ETHREAD*"),
        Field(0, 16, "VoidPointer", "0x0603 (void*)"),
        Field(0, 24, "Minimum", "0x0013 (__int64)"),
        Field(0, 32, "Union", "<unnamed-tag>", -1, -1, true),
        Field(7, 0, "Raw", "0x0023 (unsigned __int64)"),
        Field(0, 40, "Array", "0x0022 (unsigned long)[8]"),
        Field(0, 48, "Flag", "0x0030 (bool)"),
        Field(0, 56, "InvalidBits", "bitfield(0x0020 (unsigned char), offset=7, bits=2)", 7, 2),
        Field(0, 60, "End", "0x0022 (unsigned long)"),
    };
    std::vector<std::uint8_t> bytes(64, 0);
    bytes[0] = bytes[1] = bytes[2] = bytes[3] = 0xff;
    bytes[4] = 24;
    bytes[8] = 0x78;
    bytes[15] = 0xff;
    bytes[16] = 0x42;
    bytes[31] = 0x80;
    bytes[32] = 0x81;
    bytes[48] = 1;
    const auto result = sample::Project(profile, profile.identity, profile.rootSize, bytes.data(), bytes.size());
    Check(result.identityMatched && result.totalRows == 12 && result.fields.size() == 12, "all rows retained");
    Check(result.sampledRows == 8 && result.unionRows == 1 && result.coverageRows == 7 && result.aggregateRows == 2 &&
        result.unsupportedRows == 1 && result.unreadRows == 1, "coverage includes all rows without counting parents");
    Check(result.fields[1].text == "0xFFFFFFFF (-1)", "signed 32-bit value");
    Check(result.fields[1].path == "Nested.Negative", "nested member path");
    Check(result.fields[2].value == 3 && result.fields[2].raw == 24, "bitfield extraction retains storage");
    Check(result.fields[3].text == "0xFF00000000000078", "pointer is value, never dereferenced");
    Check(result.fields[4].value == 0x42 && result.fields[4].width == 8, "CodeView simple pointer width");
    Check(result.fields[5].text == "0x8000000000000000 (-9223372036854775808)", "signed minimum without overflow");
    Check(result.fields[7].unionInterpretation && result.fields[7].value == 0x81, "union inheritance is raw interpretation");
    Check(result.fields[8].status == sample::FieldStatus::UnsupportedType, "array is not a first-element scalar");
    Check(result.fields[9].text == "0x1 (true)", "boolean decode");
    Check(result.fields[10].status == sample::FieldStatus::InvalidLayout, "reject out-of-storage bitfield");
    Check(result.fields[11].status == sample::FieldStatus::Sampled, "last full field within snapshot");
    Check(result.fields[11].value == 0 && result.fields[11].text == "0x0 (0)",
        "valid zero bytes decode as a genuine zero rather than unavailability");
    const auto partial = sample::Project(profile, profile.identity, profile.rootSize, bytes.data(), 63);
    Check(partial.fields[11].status == sample::FieldStatus::OutsideSnapshot && partial.sampledRows == 7,
        "partial final field never reads beyond copied prefix");
    const auto empty = sample::Project(profile, profile.identity, profile.rootSize, nullptr, 0);
    Check(empty.identityMatched && empty.sampledRows == 0 && empty.fields.size() == 12, "failed copy publishes no fake zeroes");
    auto wrong = profile.identity;
    wrong.pdbKey.back() = '2';
    Check(!sample::Project(profile, wrong, profile.rootSize, bytes.data(), bytes.size()).identityMatched, "PDB mismatch");
    Check(!sample::Project(profile, profile.identity, 63, bytes.data(), 63).identityMatched, "root-size mismatch");
    Check(!sample::Project(profile, profile.identity, 64, bytes.data(), 65).identityMatched, "oversized copy rejected");
    Check(!sample::Project(profile, profile.identity, 64, nullptr, 1).identityMatched, "null copy buffer rejected");
    std::vector<std::uint8_t> valid(8, 0xff); // 稀疏读取时只删除一个字段内部的一个字节证据。
    valid[0] &= static_cast<std::uint8_t>(~4U);
    const auto sparse = sample::Project(profile, profile.identity, 64, bytes.data(), 64, valid.data(), valid.size());
    Check(sparse.identityMatched && sparse.fields[1].status == sample::FieldStatus::OutsideSnapshot &&
        sparse.fields[2].status == sample::FieldStatus::Sampled && sparse.sampledRows == 7,
        "sparse bitmap invalidates only fields covering unread bytes");
    Check(!sample::Project(profile, profile.identity, 64, bytes.data(), 64, valid.data(), 7).identityMatched,
        "truncated validity bitmap rejected");
    valid[7] &= static_cast<std::uint8_t>(~0x10U); // 恰好使全零末字段的一个字节失效。
    const auto zeroMissing = sample::Project(profile, profile.identity, 64, bytes.data(), 64, valid.data(), valid.size());
    Check(zeroMissing.fields[11].status == sample::FieldStatus::OutsideSnapshot && zeroMissing.fields[11].text.empty(),
        "invalid zero-filled storage never produces displayed zero text");
    auto duplicate = profile; // 别名可以显示，但不能重复计入覆盖率分子。
    duplicate.fields.push_back(Field(0, 60, "EndAlias", "0x0022 (unsigned long)"));
    const auto deduplicated = sample::Project(duplicate, duplicate.identity, 64, bytes.data(), 64);
    Check(deduplicated.sampledRows == 9 && deduplicated.coverageRows == 7 && deduplicated.totalRows == 13,
        "duplicate storage increases denominator but not coverage numerator");
    auto invalid = profile;
    invalid.fields[0].parent = 1;
    Check(!sample::Project(invalid, invalid.identity, 64, bytes.data(), 64).identityMatched, "cyclic parent rejected");

    // 版本边界必须使用数字四元组；缺少严格前后两侧时一律按黄色，而不是推断布局可靠。
    layout::Version parsedVersion{}; // 仅完整合法的固定文件版本才允许参与排序。
    Check(layout::ParseVersion("10.0.19041.10", parsedVersion) && parsedVersion[3] == 10, "numeric version parsed");
    Check(!layout::ParseVersion("10.0.19041.10.extra", parsedVersion) &&
        !layout::ParseVersion("10.0.19041", parsedVersion) && !layout::ParseVersion("10.0.19041.65536", parsedVersion),
        "malformed and oversized versions rejected");
    const layout::Identity target{0x8664, 999, 4096, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1"}; // 冻结的当前 PE 身份。
    std::vector<layout::CatalogEntry> catalog{ // 同分支两侧分别具有独立精确 RSDS。
        {{0x8664, 1, 4096, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB1"}, {10, 0, 19041, 9}},
        {{0x8664, 2, 4096, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC1"}, {10, 0, 19041, 11}},
    };
    Check(layout::SelectNeighbors(catalog, target, {10, 0, 19041, 10}).bracketed,
        "strictly between two distinct packaged versions is bracketed");
    for (const auto revision : {0U, 8U, 9U, 11U, 12U, 65535U}) // 包外两端和恰好端点均不能算双侧夹住。
    {
        Check(!layout::SelectNeighbors(catalog, target, {10, 0, 19041, revision}).bracketed,
            "outside range and exact endpoints require yellow");
    }
    Check(!layout::SelectNeighbors(catalog, target, {10, 0, 26100, 10}).bracketed,
        "different branch never supplies invented neighbors");
    Check(!layout::SelectNeighbors(catalog, target, {}).bracketed, "unknown current version requires yellow");
    catalog.push_back({{0x8664, 3, 4096, "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD1"}, {10, 0, 19041, 11}});
    Check(!layout::SelectNeighbors(catalog, target, {10, 0, 19041, 10}).bracketed,
        "ambiguous same-version next candidate requires yellow");

    // 可选参数是真实精确分片；零缓冲只测生产投影覆盖能力，不冒充现场采样验收。
    for (int i = 1; i < argc; ++i)
    {
        const auto kind = std::wstring(argv[i]).find(L"process_layouts") != std::wstring::npos ?
            layout::Kind::Process : layout::Kind::Thread;
        const auto exact = layout::Load(argv[i], nullptr, kind);
        const auto directory = std::filesystem::path(argv[i]).parent_path(); // 以当前实际分片目录作为覆盖分母。
        const auto versions = layout::LoadCatalog(directory); // 不把历史固定文件数当作发布完整性证据。
        std::set<std::filesystem::path> shards; // 每份已发布 TSV 必须在版本目录中恰好出现一次。
        for (const auto& file : std::filesystem::directory_iterator(directory))
        {
            if (file.is_regular_file() && file.path().extension() == L".tsv")
            {
                shards.insert(file.path().filename());
            }
        }
        const auto publishedCount = shards.size(); // 擦除已核对项目后，空集合才表示没有遗漏。
        bool unique = true; // 重复或伪造的目录项即使总数相同也必须失败。
        for (const auto& entry : versions)
        {
            unique = shards.erase(layout::FileName(entry.identity)) == 1 && unique;
        }
        Check(unique && shards.empty() && versions.size() == publishedCount && publishedCount != 0,
            "packaged catalog references every actual exact shard exactly once");
        const std::vector<std::uint8_t> synthetic(exact.rootSize, 0);
        const auto coverage = sample::Project(exact, exact.identity, exact.rootSize, synthetic.data(), synthetic.size());
        std::cout << "SYNTHETIC_PROJECTION_ONLY rows=" << coverage.totalRows << " decoded=" << coverage.sampledRows
            << " union=" << coverage.unionRows << " strictCoverage=" << coverage.coverageRows << '\n';
        Check(coverage.identityMatched && coverage.coverageRows * 2 > coverage.totalRows,
            "exact layout scalar projection exceeds half excluding aliases");
    }
    return failures ? 1 : 0;
}
