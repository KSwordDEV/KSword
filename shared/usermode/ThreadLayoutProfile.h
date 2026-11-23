#pragma once

#include <cstdint>
#include <array>
#include <filesystem>
#include <string>
#include <vector>

namespace ks::threadlayout
{
    enum class Kind { Thread, Process }; // 用户态目录的根类型。
    // PE 三元组用于定位分片；有 PDB 键时同时匹配 GUID 与 Age。
    struct Identity
    {
        std::uint32_t machine = 0; // PE 目标架构。
        std::uint32_t timestamp = 0; // PE COFF 时间戳。
        std::uint32_t imageSize = 0; // PE 映像大小。
        std::string pdbKey; // 大写无连字符 GUID 和十六进制 Age。
    };

    // 纯符号元数据：没有对象地址、采样值或写入能力。
    struct Field
    {
        std::uint32_t parent = 0; // 0 为 ETHREAD；其他值为父行的一基编号。
        std::uint32_t offset = 0; // 相对于直接父项，不是运行时地址。
        std::string name; // PDB 成员名。
        std::string type; // PDB 可显示类型。
        int bitOffset = -1; // -1 表示非位域。
        int bitWidth = -1; // -1 表示非位域。
        bool unionAlias = false; // 位于 union 内，不代表当前活动分支。
    };

    struct Profile
    {
        Identity identity; // 分片声明的源 PE/PDB 身份。
        std::uint32_t rootSize = 0; // _ETHREAD 的符号类型大小。
        std::vector<Field> fields; // 父项在先的顺序。
    };

    using Version = std::array<std::uint32_t, 4>; // 四段数字文件版本；不能按字符串或 PE 时间戳排序。
    struct CatalogEntry
    {
        Identity identity; // 包内实际分片的完整 PE/RSDS 身份。
        Version version{}; // 已发布元数据记录的数字文件版本。
    };
    struct Neighbors
    {
        CatalogEntry previous; // 同架构、同分支的最近较早版本；缺失时 identity 为空。
        CatalogEntry next; // 同架构、同分支的最近较晚版本；缺失时 identity 为空。
        bool bracketed = false; // 必须两侧都存在；等于最早/最晚版本同样不算夹在中间。
    };

    // 输入四段版本文本；全部解析成功时填写 output 并返回 true。
    bool ParseVersion(const std::string& text, Version& output);
    // 输入发布分片目录，返回仅引用目录内真实存在分片的版本表；缺失或损坏时为空。
    std::vector<CatalogEntry> LoadCatalog(const std::filesystem::path& directory);
    // 输入包内版本表和当前精确身份/文件版本，输出最近双侧；缺任意一侧必须按黄色处理。
    Neighbors SelectNeighbors(const std::vector<CatalogEntry>& entries, const Identity& current, const Version& version);
    // 输入同一版本表与当前身份，返回最近双侧的全部来源；歧义只限制采样/风险判定，不抹掉参考字段。
    std::vector<CatalogEntry> SelectReferenceCandidates(const std::vector<CatalogEntry>& entries,
        const Identity& current, const Version& version);

    // 使用 PE 三元组返回发布目录内的分片文件名，不访问设备或网络。
    std::filesystem::path FileName(const Identity& identity);

    // 输入单个分片与可选预期身份；无效、不匹配或缺文件时返回空 Profile。
    Profile Load(const std::filesystem::path& file, const Identity* expected = nullptr, Kind kind = Kind::Thread);

    // 返回 profile 根目录下的线程/进程布局相对路径。
    const wchar_t* Directory(Kind kind);

    // 读取指定磁盘 PE（为空时为系统 ntoskrnl.exe）的三元组与 RSDS 键。
    Identity ReadImageIdentity(const std::filesystem::path& image = {});
    // 从指定 PE 的固定版本资源读取四段数字版本；为空时读取系统 ntoskrnl.exe。
    Version ReadImageVersion(const std::filesystem::path& image = {});
}
