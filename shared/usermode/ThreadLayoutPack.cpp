#include "ThreadLayoutProfile.h"
#include "../../Launcher/Json.h"
#include "../../third_party/zlib/zlib.h"

#include <cmath>
#include <fstream>
#include <memory>
#include <mutex>
#include <set>

namespace ks::threadlayout
{
    namespace
    {
        constexpr std::size_t kMaxPackBytes = 160 * 1024 * 1024; // 整包解压上限，独立于单分片预算。
        using Json = launcher::JsonValue; // 复用现有 Qt-free JSON 读取器，CLI 不新增 Qt 依赖。

        struct Pack
        {
            Json layouts; // 仅保留完整布局扩展，不常驻几十万个驱动 item 的 DOM。
            std::array<std::vector<CatalogEntry>, 2> catalogs; // 两种根类型分别拥有版本与精确身份。
        };

        // 调用：输入根类型，返回固定数组下标；不是 R0 类型号。
        std::size_t Slot(const Kind kind)
        {
            return kind == Kind::Thread ? 0 : 1;
        }

        // 调用：输入根类型，返回 v4 扩展中的规范键，不把键解释为路径。
        const char* GroupName(const Kind kind)
        {
            return kind == Kind::Thread ? "thread_layouts" : "process_layouts";
        }

        // 调用：输入 JSON 数字和上限，返回严格正整数；类型错、非整数或越界返回零。
        std::uint32_t Positive(const Json& value, const std::uint32_t maximum)
        {
            if (!value.isNumber())
            {
                return 0;
            }
            const auto number = value.number(); // 转换前检查，避免 NaN/无穷或越界整数转换。
            if (!std::isfinite(number) || number < 1 || number > maximum || std::floor(number) != number)
            {
                return 0;
            }
            return static_cast<std::uint32_t>(number);
        }

        // 调用：输入已验证的索引身份、根类型和大小，重建原始 TSV 头；不合成现场数据。
        std::string Header(const Identity& identity, const Kind kind, const std::uint32_t size)
        {
            return std::string(kind == Kind::Thread ? "KSWTHREAD1\t" : "KSWPROCESS1\t") +
                std::to_string(identity.machine) + '\t' + std::to_string(identity.timestamp) + '\t' +
                std::to_string(identity.imageSize) + '\t' + identity.pdbKey + '\t' + std::to_string(size) + '\n';
        }

        // 调用：输入正式 qz 文件，返回完整解压文本；长度、CRC、尾随数据或读取失败均返回空。
        std::string ReadPack(const std::filesystem::path& path)
        {
            std::ifstream file(path, std::ios::binary | std::ios::ate); // 只读固定的本地发布文件。
            const auto length = file.tellg(); // 压缩文件同样限制体积，先校验再分配。
            if (length <= 4 || length > static_cast<std::streamoff>(kMaxPackBytes))
            {
                return {};
            }
            std::string bytes(static_cast<std::size_t>(length), '\0'); // 原 qCompress 容器字节。
            file.seekg(0);
            if (!file.read(bytes.data(), static_cast<std::streamsize>(length)))
            {
                return {};
            }
            std::uint32_t size = 0; // qCompress 的前四字节是大端未压缩长度。
            for (std::size_t index = 0; index < 4; ++index)
            {
                size = (size << 8) | static_cast<unsigned char>(bytes[index]);
            }
            if (!size || size > kMaxPackBytes)
            {
                return {};
            }
            std::string text(size, '\0'); // 有界单次解压，不允许流自行扩大内存。
            auto destination = static_cast<uLongf>(text.size()); // zlib 输出的实际长度。
            auto source = static_cast<uLong>(bytes.size() - 4); // zlib 已消费的输入长度。
            const auto status = uncompress2(reinterpret_cast<Bytef*>(text.data()), &destination,
                reinterpret_cast<const Bytef*>(bytes.data() + 4), &source);
            if (status != Z_OK || destination != text.size() || source != bytes.size() - 4)
            {
                return {};
            }
            return text;
        }

        // 调用：输入包元数据，检查索引与每个去重字段集；成功返回 true，否则整份布局扩展拒绝。
        bool Validate(Pack& pack)
        {
            const auto* format = pack.layouts.get("formatVersion"); // 扩展自身版本，不改变 v4 协议。
            const auto* sets = pack.layouts.get("fieldSets"); // 所有结构共用的完整正文映射。
            if (!format || Positive(*format, 1) != 1 || !sets || !sets->isObject() ||
                sets->object().empty() || sets->object().size() > 16384)
            {
                return false;
            }
            std::set<std::string> used; // 拒绝没有任何结构引用的隐藏正文。
            for (const auto kind : {Kind::Thread, Kind::Process})
            {
                const auto* group = pack.layouts.get(GroupName(kind)); // 根类型必须同时存在。
                const auto* catalog = group ? group->get("catalog") : nullptr;
                const auto* profiles = group ? group->get("profiles") : nullptr;
                if (!catalog || !catalog->isString() || !profiles || !profiles->isObject())
                {
                    return false;
                }
                auto& entries = pack.catalogs[Slot(kind)]; // 只公布通过正文校验的版本来源。
                entries = ParseCatalog(catalog->string());
                if (entries.empty() || entries.size() != profiles->object().size())
                {
                    return false;
                }
                std::set<std::pair<std::uint32_t, std::string>> checked; // 同类型、大小与正文只解析一次。
                for (const auto& entry : entries)
                {
                    const auto* record = profiles->get(FileName(entry.identity).string().c_str());
                    if (!record || !record->isArray() || record->array().size() != 2)
                    {
                        return false;
                    }
                    const auto& values = record->array(); // 两项分别是根大小与字段集去重键。
                    const auto size = Positive(values[0], 65536);
                    if (!size || !values[1].isString())
                    {
                        return false;
                    }
                    const auto& key = values[1].string(); // 哈希形状只作为内嵌键，不是授权证明。
                    const auto* body = sets->get(key.c_str());
                    if (key.size() != 64 || key.find_first_not_of("0123456789abcdef") != std::string::npos ||
                        !body || !body->isString() || body->string().size() > 512 * 1024)
                    {
                        return false;
                    }
                    used.insert(key);
                    if (checked.emplace(size, key).second &&
                        Parse(Header(entry.identity, kind, size) + body->string(), &entry.identity, kind).fields.empty())
                    {
                        return false;
                    }
                }
            }
            return used.size() == sets->object().size();
        }

        // 调用：输入包路径，返回共享只读缓存；文件被替换后重新验证，失败不使用上次成功的数据。
        std::shared_ptr<const Pack> Open(const std::filesystem::path& path)
        {
            static std::mutex mutex; // 合并 GUI 多个后台消费者的同包加载。
            static std::filesystem::path cachedPath; // 当前唯一正式包的位置。
            static std::filesystem::file_time_type cachedTime{}; // 观察发布文件替换。
            static std::uintmax_t cachedSize = 0; // 大小变化也使缓存失效。
            static std::shared_ptr<const Pack> cached; // 只缓存验证成功的扩展。
            const std::lock_guard guard(mutex); // 初始化期间不重复解压约百 MB 的 JSON。
            std::error_code error; // 文件缺失或权限错误与合法空结果分开处理为不可用。
            const auto time = std::filesystem::last_write_time(path, error);
            if (error)
            {
                return {};
            }
            const auto size = std::filesystem::file_size(path, error);
            if (error)
            {
                return {};
            }
            if (cached && path == cachedPath && time == cachedTime && size == cachedSize)
            {
                return cached;
            }
            cached.reset(); // 新文件无效时不能继续使用旧布局。
            Json root; // 选择性 DOM 只保留版本及结构扩展。
            std::string diagnostic; // 解析失败不向外伪造任何精确字段。
            const auto text = ReadPack(path);
            if (text.empty() || !launcher::ParseJsonRootMembers(text,
                {"schemaVersion", "packVersion", "structureLayouts"}, &root, &diagnostic))
            {
                return {};
            }
            const auto* schema = root.get("schemaVersion");
            const auto* version = root.get("packVersion");
            auto* layouts = root.get("structureLayouts");
            if (!schema || Positive(*schema, 1) != 1 || !version || Positive(*version, 4) != 4 || !layouts)
            {
                return {};
            }
            auto loaded = std::make_shared<Pack>(); // 校验完成前不向其他线程发布。
            loaded->layouts = *layouts;
            if (!Validate(*loaded))
            {
                return {};
            }
            cachedPath = path;
            cachedTime = time;
            cachedSize = size;
            cached = std::move(loaded);
            return cached;
        }
    }

    std::vector<CatalogEntry> LoadPackCatalog(const std::filesystem::path& path, const Kind kind)
    {
        const auto pack = Open(path); // 返回副本，调用者不能修改共享缓存中的身份与版本。
        return pack ? pack->catalogs[Slot(kind)] : std::vector<CatalogEntry>{};
    }

    Profile LoadPack(const std::filesystem::path& path, const Identity& expected, const Kind kind)
    {
        if (expected.pdbKey.empty()) // 不能退化为只有 PE 三元组的采样授权。
        {
            return {};
        }
        const auto pack = Open(path); // 原生和 Qt 消费者都经过同一完整身份查找。
        if (!pack)
        {
            return {};
        }
        for (const auto& entry : pack->catalogs[Slot(kind)])
        {
            const auto& id = entry.identity; // 版本仅用于参考选择，不替代四项精确匹配。
            if (id.machine != expected.machine || id.timestamp != expected.timestamp ||
                id.imageSize != expected.imageSize || id.pdbKey != expected.pdbKey)
            {
                continue;
            }
            const auto* record = pack->layouts.get(GroupName(kind))->get("profiles")->get(FileName(id).string().c_str());
            const auto& values = record->array(); // Open 已核验这条记录及正文，仍复用生产字段解析器。
            const auto size = Positive(values[0], 65536);
            const auto* body = pack->layouts.get("fieldSets")->get(values[1].string().c_str());
            return Parse(Header(id, kind, size) + body->string(), &expected, kind);
        }
        return {};
    }
}
