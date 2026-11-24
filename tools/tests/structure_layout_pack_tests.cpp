#include "../../shared/usermode/ThreadLayoutProfile.h"
#include "../../Launcher/Json.h"

#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace
{
    namespace layout = ks::threadlayout; // 直接链接生产读取器，不复制字段解析算法。

    // 调用：输入断言条件和说明；失败抛出异常，由 main 统一返回非零退出码。
    void Require(const bool condition, const char* message)
    {
        if (!condition)
        {
            throw std::runtime_error(message);
        }
    }

    // 调用：无输入，检查选择性 JSON 仍验证被跳过的值，重复键不会变成合法结构。
    void CheckJson()
    {
        launcher::JsonValue value; // 只接收白名单根成员的 DOM。
        std::string error; // 解析器实际错误，不参与断言结果伪造。
        Require(launcher::ParseJsonRootMembers(
            R"({"profiles":[{"nested":[true,null,-12.5,"escaped\ntext"]}],"packVersion":4})",
            {"packVersion"}, &value, &error), "selective JSON parse");
        Require(!value.get("profiles") && value.numberOr("packVersion", 0) == 4, "skip profiles DOM");
        Require(!launcher::ParseJsonRootMembers(R"({"profiles":[{"x":}] ,"packVersion":4})",
            {"packVersion"}, &value, &error), "validate discarded JSON");
        Require(!launcher::ParseJsonRootMembers(R"({"packVersion":4,"packVersion":3})",
            {"packVersion"}, &value, &error), "reject duplicate retained root");
        Require(!launcher::ParseJsonRootMembers("{} trailing", {"packVersion"}, &value, &error),
            "reject JSON suffix");
    }

    // 调用：输入源布局与 v4 布局，逐字段比较全部语义；任何行丢失或属性变化均失败。
    void Compare(const layout::Profile& source, const layout::Profile& packed)
    {
        Require(!source.fields.empty() && source.rootSize == packed.rootSize &&
            source.fields.size() == packed.fields.size(), "root size and complete field count");
        Require(source.identity.machine == packed.identity.machine &&
            source.identity.timestamp == packed.identity.timestamp &&
            source.identity.imageSize == packed.identity.imageSize &&
            source.identity.pdbKey == packed.identity.pdbKey, "complete PE/RSDS identity");
        for (std::size_t index = 0; index < source.fields.size(); ++index)
        {
            const auto& a = source.fields[index]; // 源 TSV 的一行原始语义。
            const auto& b = packed.fields[index]; // 包内重建并经生产解析器核验的一行。
            Require(a.parent == b.parent && a.offset == b.offset && a.name == b.name && a.type == b.type &&
                a.bitOffset == b.bitOffset && a.bitWidth == b.bitWidth && a.unionAlias == b.unionAlias,
                "lossless field metadata");
        }
    }

    // 调用：输入正式包及源码 profiles 根，验证两类所有字段、版本和身份；不访问驱动。
    void CheckPack(const std::filesystem::path& pack, const std::filesystem::path& source)
    {
        for (const auto kind : {layout::Kind::Thread, layout::Kind::Process})
        {
            const auto directory = source / layout::Directory(kind); // 只作为独立对照，不用于运行时回退。
            const auto expected = layout::LoadCatalog(directory);
            const auto actual = layout::LoadPackCatalog(pack, kind);
            Require(!expected.empty() && expected.size() == actual.size(), "all catalog entries embedded");
            std::size_t fields = 0; // 本类根结构真实逐行比较数。
            for (std::size_t index = 0; index < actual.size(); ++index)
            {
                const auto& entry = actual[index]; // 保持索引原序，邻版选择行为不变。
                Require(entry.version == expected[index].version &&
                    entry.identity.pdbKey == expected[index].identity.pdbKey &&
                    layout::FileName(entry.identity) == layout::FileName(expected[index].identity), "version catalog unchanged");
                const auto raw = layout::Load(directory / layout::FileName(entry.identity), &entry.identity, kind);
                const auto restored = layout::LoadPack(pack, entry.identity, kind);
                Compare(raw, restored);
                fields += restored.fields.size();
            }
            auto wrong = actual.front().identity; // 同 PE、错误 RSDS 必须拒绝，不能误用参考授权。
            wrong.pdbKey[0] = wrong.pdbKey[0] == 'A' ? 'B' : 'A';
            Require(layout::LoadPack(pack, wrong, kind).fields.empty(), "wrong RSDS rejected");
            wrong = actual.front().identity;
            wrong.pdbKey.clear();
            Require(layout::LoadPack(pack, wrong, kind).fields.empty(), "missing RSDS rejected");
            std::cout << (kind == layout::Kind::Thread ? "ETHREAD" : "EPROCESS") << " profiles=" << actual.size()
                << " fields=" << fields << '\n';
        }
    }
}

// 调用：pack/source 两参数执行全量回归；--reject 路径列表验证损坏包不可用，不进行设备调用。
int wmain(const int argc, const wchar_t* const* argv)
{
    try
    {
        CheckJson(); // 所有模式都先确认原生选择性解析行为。
        Require(argc >= 3, "usage: pack sourceRoot | --reject badPack...");
        if (std::wstring_view(argv[1]) == L"--reject")
        {
            for (int index = 2; index < argc; ++index)
            {
                for (const auto kind : {layout::Kind::Thread, layout::Kind::Process})
                {
                    Require(layout::LoadPackCatalog(argv[index], kind).empty(), "invalid pack catalog must fail closed");
                }
            }
        }
        else
        {
            CheckPack(argv[1], argv[2]);
        }
        std::cout << "STRUCTURE_LAYOUT_PACK_TESTS=PASS\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
