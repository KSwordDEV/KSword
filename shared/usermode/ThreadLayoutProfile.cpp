#include "ThreadLayoutProfile.h"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <set>
#include <string_view>

namespace ks::threadlayout
{
    namespace
    {
        constexpr std::size_t kMaxBytes = 512 * 1024; // 只读取单个小分片。
        constexpr std::size_t kMaxRows = 4096; // 同时限制 GUI 树与 CLI 序列化开销。

        // 将一行切成 TSV 单元格，保留空列（非位域的两个位置）。
        std::vector<std::string_view> Columns(std::string_view line)
        {
            std::vector<std::string_view> result; // 借用当前行文本，不保存到 Profile。
            for (;;)
            {
                const auto delimiter = line.find('\t'); // 该单元格结尾。
                result.push_back(line.substr(0, delimiter));
                if (delimiter == line.npos || result.size() > 7)
                {
                    return result;
                }
                line.remove_prefix(delimiter + 1);
            }
        }

        // 解析十进制非负整数，溢出或部分匹配时返回 false。
        bool Number(const std::string_view value, std::uint32_t& output)
        {
            if (value.empty())
            {
                return false;
            }
            const auto* end = value.data() + value.size(); // 转换必须消耗完整单元格。
            const auto parsed = std::from_chars(value.data(), end, output);
            return parsed.ec == std::errc{} && parsed.ptr == end;
        }

        // 拒绝空名和包括 DEL 在内的控制字符，避免污染 CLI 和表格。
        bool Text(const std::string_view value)
        {
            return !value.empty() && value.size() <= 1024 &&
                std::all_of(value.begin(), value.end(), [](const unsigned char ch)
                {
                    return ch >= 32 && ch != 127;
                });
        }
    }

    std::filesystem::path FileName(const Identity& identity)
    {
        return std::to_string(identity.machine) + '-' + std::to_string(identity.timestamp) + '-' +
            std::to_string(identity.imageSize) + ".tsv";
    }

    const wchar_t* Directory(const Kind kind)
    {
        return kind == Kind::Thread ? L"thread_layouts" : L"process_layouts";
    }

    bool ParseVersion(const std::string& text, Version& output)
    {
        Version parsed{}; // 只有完整成功才覆盖输出，避免半个版本参与排序。
        std::string_view remaining(text); // 四段必须完整消费，不能忽略额外后缀。
        for (std::size_t index = 0; index < parsed.size(); ++index)
        {
            const auto dot = remaining.find('.'); // 当前数字段的结束位置。
            if ((index == parsed.size() - 1) != (dot == remaining.npos) ||
                !Number(remaining.substr(0, dot), parsed[index]) || parsed[index] > 65535)
            {
                return false;
            }
            if (dot != remaining.npos)
            {
                remaining.remove_prefix(dot + 1);
            }
        }
        if (!parsed[0] || !parsed[2])
        {
            return false;
        }
        output = parsed;
        return true;
    }

    std::vector<CatalogEntry> LoadCatalog(const std::filesystem::path& directory)
    {
        std::ifstream input(directory / L"_versions.index", std::ios::binary | std::ios::ate); // 不扫描语料盘或网络。
        const auto size = input.tellg(); // 版本目录同样有固定读取上限。
        if (size <= 0 || size > static_cast<std::streamoff>(kMaxBytes))
        {
            return {};
        }
        input.seekg(0);
        std::string line; // 每行只保存身份和文件版本，不保存字段或可读取偏移。
        if (!std::getline(input, line) || line != "KSWLAYOUTVERSIONS1")
        {
            return {};
        }
        std::set<std::string> seen; // 同一分片只能声明一个版本，冲突时整表失效。
        std::vector<CatalogEntry> entries; // 返回的记录只包含实际发布的分片。
        while (std::getline(input, line))
        {
            const auto columns = Columns(line); // Machine、TimeDateStamp、SizeOfImage、RSDS 和四段版本。
            CatalogEntry entry; // 当前已检查的元数据记录。
            if (entries.size() >= 8192 || columns.size() != 5 ||
                !Number(columns[0], entry.identity.machine) || entry.identity.machine != 0x8664 ||
                !Number(columns[1], entry.identity.timestamp) || !Number(columns[2], entry.identity.imageSize) ||
                !entry.identity.imageSize || columns[3].size() < 33 || columns[3].size() > 40 ||
                columns[3].find_first_not_of("0123456789ABCDEF") != std::string_view::npos ||
                !ParseVersion(std::string(columns[4]), entry.version))
            {
                return {};
            }
            entry.identity.pdbKey = columns[3];
            const auto name = FileName(entry.identity); // 目录表不能提供路径、地址或偏移。
            if (!seen.insert(name.string()).second)
            {
                return {};
            }
            std::error_code error; // 文件移除、不可用与权限失败均不算包内可用版本。
            if (std::filesystem::is_regular_file(directory / name, error))
            {
                entries.push_back(std::move(entry));
            }
        }
        return input.eof() ? entries : std::vector<CatalogEntry>{};
    }

    Neighbors SelectNeighbors(const std::vector<CatalogEntry>& entries, const Identity& current, const Version& version)
    {
        Neighbors result; // 不知道当前数字版本时，默认没有双侧证据，必须黄色。
        if (!version[0] || !version[2])
        {
            return result;
        }
        bool previousAmbiguous = false; // 相同候选版本存在不同 PE 身份时不能任意挑选。
        bool nextAmbiguous = false; // 下一侧使用同样的歧义拒绝规则。
        for (const auto& entry : entries)
        {
            if (entry.identity.machine != current.machine || entry.identity.pdbKey == current.pdbKey ||
                !std::equal(version.begin(), version.begin() + 3, entry.version.begin()) || entry.version == version)
            {
                continue;
            }
            auto& selected = entry.version < version ? result.previous : result.next; // 数字四元组决定前后关系。
            auto& ambiguous = entry.version < version ? previousAmbiguous : nextAmbiguous;
            const bool better = selected.identity.pdbKey.empty() ||
                (entry.version < version ? entry.version > selected.version : entry.version < selected.version);
            if (better)
            {
                selected = entry;
                ambiguous = false;
            }
            else if (entry.version == selected.version && (entry.identity.pdbKey != selected.identity.pdbKey ||
                entry.identity.timestamp != selected.identity.timestamp || entry.identity.imageSize != selected.identity.imageSize))
            {
                ambiguous = true;
            }
        }
        if (previousAmbiguous)
        {
            result.previous = {};
        }
        if (nextAmbiguous)
        {
            result.next = {};
        }
        result.bracketed = !result.previous.identity.pdbKey.empty() && !result.next.identity.pdbKey.empty() &&
            result.previous.identity.pdbKey != result.next.identity.pdbKey;
        return result;
    }

    std::vector<CatalogEntry> SelectReferenceCandidates(const std::vector<CatalogEntry>& entries,
        const Identity& current, const Version& version)
    {
        std::vector<CatalogEntry> previous; // 最近较早版本的所有不同 PE/PDB 来源，仅供元数据展示。
        std::vector<CatalogEntry> sameVersion; // 同一文件版本但不同 RSDS 的布局也只是参考，不冒充精确命中。
        std::vector<CatalogEntry> next; // 最近较晚版本采用相同规则，不因同版多来源丢弃整个方向。
        if (!version[0] || !version[2])
        {
            return {};
        }
        for (const auto& entry : entries) // 只接受同架构和同分支，邻版永远不能授权现场读取。
        {
            if (entry.identity.machine != current.machine || entry.identity.pdbKey == current.pdbKey ||
                !std::equal(version.begin(), version.begin() + 3, entry.version.begin()))
            {
                continue;
            }
            if (entry.version == version)
            {
                sameVersion.push_back(entry);
                continue;
            }
            auto& side = entry.version < version ? previous : next; // 两个方向分别选择最近的数字版本。
            if (side.empty() || (entry.version < version ? entry.version > side.front().version :
                entry.version < side.front().version))
            {
                side.clear(); // 只淘汰更远的版本，不淘汰同一最近版本的其他精确来源。
            }
            if (side.empty() || entry.version == side.front().version)
            {
                side.push_back(entry);
            }
        }
        previous.insert(previous.end(), sameVersion.begin(), sameVersion.end()); // 同版异身份位于前后来源之间，仍仅是参考。
        previous.insert(previous.end(), next.begin(), next.end()); // 输出前侧在先，保留来源身份供调用者明确标注。
        return previous;
    }

    Profile Load(const std::filesystem::path& file, const Identity* expected, const Kind kind)
    {
        std::ifstream input(file, std::ios::binary | std::ios::ate); // 固定大小读取，不随文件膨胀。
        const auto size = input.tellg(); // 先确认文件存在并满足单分片预算。
        if (size <= 0 || size > static_cast<std::streamoff>(kMaxBytes))
        {
            return {};
        }
        std::string bytes(static_cast<std::size_t>(size), '\0'); // UTF-8 TSV 原始数据，只在本函数使用。
        input.seekg(0);
        if (!input.read(bytes.data(), static_cast<std::streamsize>(size)) || bytes.back() != '\n')
        {
            return {};
        }

        Profile result; // 任一行坏掉就丢弃整份，避免部分布局冒充完整布局。
        std::string_view remaining(bytes); // 逐行推进，无额外的整文件副本。
        const auto next = [&remaining]()
        {
            const auto end = remaining.find('\n'); // 文件尾必须已经是换行。
            const auto line = remaining.substr(0, end);
            remaining.remove_prefix(end + 1);
            return Columns(line);
        };
        const auto header = next(); // 文件格式、PE/PDB 身份与根类型大小。
        auto& id = result.identity;
        const auto marker = kind == Kind::Thread ? "KSWTHREAD1" : "KSWPROCESS1"; // 各根类型单独校验。
        if (header.size() != 6 || header[0] != marker || !Number(header[1], id.machine) || id.machine != 0x8664 ||
            !Number(header[2], id.timestamp) || !Number(header[3], id.imageSize) || !id.imageSize ||
            header[4].size() < 33 || header[4].size() > 40 ||
            header[4].find_first_not_of("0123456789ABCDEF") != std::string_view::npos ||
            !Number(header[5], result.rootSize) || !result.rootSize || result.rootSize > 65536)
        {
            return {};
        }
        id.pdbKey = header[4];
        if (expected && (id.machine != expected->machine || id.timestamp != expected->timestamp ||
            id.imageSize != expected->imageSize || (!expected->pdbKey.empty() && id.pdbKey != expected->pdbKey)))
        {
            return {};
        }

        std::vector<std::uint32_t> absolute{0}; // 仅核对相对于根的边界，不涉及内核地址。
        while (!remaining.empty())
        {
            const auto row = next(); // 父行编号、偏移、类型、位域和 union 分支标识。
            Field field;
            if (result.fields.size() >= kMaxRows || row.size() != 7 ||
                !Number(row[0], field.parent) || field.parent >= absolute.size() || !Number(row[1], field.offset) ||
                field.offset >= result.rootSize - absolute[field.parent] || !Text(row[2]) || !Text(row[3]) ||
                (row[6] != "member" && row[6] != "union"))
            {
                return {};
            }
            if (!row[4].empty() || !row[5].empty())
            {
                std::uint32_t bit = 0, count = 0; // Windows 内核位域的存储位置和宽度。
                if (!Number(row[4], bit) || !Number(row[5], count) || bit >= 64 || !count || count > 64 - bit)
                {
                    return {};
                }
                field.bitOffset = static_cast<int>(bit);
                field.bitWidth = static_cast<int>(count);
            }
            field.name = row[2];
            field.type = row[3];
            field.unionAlias = row[6] == "union";
            absolute.push_back(absolute[field.parent] + field.offset);
            result.fields.push_back(std::move(field));
        }
        return result.fields.empty() ? Profile{} : std::move(result);
    }
}
