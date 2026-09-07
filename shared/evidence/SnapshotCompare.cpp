#include "SnapshotCompare.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <utility>

namespace Ksword::Evidence {
namespace {

// 键分隔符与 ObjectIdentity 保持一致：不会出现在路径、GUID 或数字里。
constexpr char kSep = '\x1F';

char FoldAscii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// 路径归一化：只折叠大小写并统一分隔符，不解析符号链接（那要现场访问）。
std::string FoldPath(const std::string& path) {
    std::string out;
    out.reserve(path.size());
    for (const char raw : path) {
        out.push_back(raw == '/' ? '\\' : FoldAscii(raw));
    }
    return out;
}

std::string FoldText(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char raw : text) {
        out.push_back(FoldAscii(raw));
    }
    return out;
}

bool EqualPathFold(const std::string& a, const std::string& b) {
    return FoldPath(a) == FoldPath(b);
}

// 不分配版本：Match* 是 noexcept 的，不能在里面构造临时 std::string。
bool EqualTextFoldNoAlloc(const std::string& a, const std::string& b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (FoldAscii(a[i]) != FoldAscii(b[i])) {
            return false;
        }
    }
    return true;
}

void AppendKey(std::string& key, const std::string& value) {
    key.push_back(kSep);
    key.append(value);
}

void AppendKey(std::string& key, const OptionalU64& value) {
    key.push_back(kSep);
    if (value.present) {
        key.append(FormatU64(value.value, U64Format::Decimal));
    }
}

void PushUnique(std::vector<std::string>& list, std::string value) {
    if (value.empty()) {
        return;
    }
    if (std::find(list.begin(), list.end(), value) == list.end()) {
        list.push_back(std::move(value));
    }
}

// D-05：把 EntityField 渲染成展示串。Absent 与"数字缺失"都不产出文本，
// 由 known 标志区分 —— 否则未知会被读成空串这一个具体值。
void RenderField(const EntityField* field, bool& known, std::string& text) {
    known = false;
    text.clear();
    if (field == nullptr) {
        return;
    }
    switch (field->kind) {
    case FieldValueKind::Absent:
        return;
    case FieldValueKind::Text:
        known = true;
        text = field->text;
        return;
    case FieldValueKind::Number:
        if (field->number.present) {
            known = true;
            text = FormatU64(field->number.value, field->numberFormat);
        }
        return;
    }
}

const EntityField* FindField(const std::vector<EntityField>& fields, const std::string& name) {
    for (const EntityField& field : fields) {
        if (field.name == name) {
            return &field;
        }
    }
    return nullptr;
}

struct ResolvedAddress final {
    bool resolved = false;
    const SnapshotModule* module = nullptr;
    std::uint32_t rva = 0;
};

// D-03：把绝对地址解析到"映像 + RVA"。模块基址或尺寸缺失时 rvaExtent() 是空区间，
// 空区间不 contains 任何 RVA，因此这类模块永远不会被当成命中 —— 缺信息不等于命中。
ResolvedAddress ResolveAddress(const Snapshot& snapshot, const OptionalU64& address) {
    ResolvedAddress result;
    if (!address.present) {
        return result;
    }
    for (const SnapshotModule& module : snapshot.modules) {
        if (!module.imageBase.present) {
            continue;
        }
        if (address.value < module.imageBase.value) {
            continue;
        }
        const std::uint64_t offset = address.value - module.imageBase.value;
        if (offset > 0xFFFFFFFFULL) {
            continue;
        }
        const RvaRange extent = module.rvaExtent();
        const std::uint32_t rva = static_cast<std::uint32_t>(offset);
        if (!extent.contains(rva)) {
            continue;
        }
        result.resolved = true;
        result.module = &module;
        result.rva = rva;
        return result;
    }
    return result;
}

// 两个映像身份不可比时，区分"同一路径的不同版本"与"根本不是同一个模块"。
// D-03 点名要求前者不得被当成相同代码，因此它必须是可单独看到的一档。
AddressNormalizationState ClassifyIncomparableImages(const DriverInstanceId& a,
                                                     const DriverInstanceId& b) {
    if (!a.imagePath.empty() && !b.imagePath.empty() && EqualPathFold(a.imagePath, b.imagePath)) {
        return AddressNormalizationState::ImageVersionDiffers;
    }
    return AddressNormalizationState::DifferentModule;
}

MatchResult MatchEntityIdentity(const SnapshotEntity& a, const SnapshotEntity& b) noexcept {
    if (a.kind != b.kind) {
        return MatchResult::NoMatch;
    }
    switch (a.kind) {
    case ObjectKind::Process:
        return MatchProcessInstance(a.process, b.process);
    case ObjectKind::Thread:
        return MatchThreadInstance(a.thread, b.thread);
    case ObjectKind::Driver:
    case ObjectKind::Module:
        return MatchDriverInstance(a.driver, b.driver);
    case ObjectKind::File:
        return MatchFileIdentity(a.file, b.file);
    case ObjectKind::Service:
    case ObjectKind::Device:
    case ObjectKind::Handle:
    case ObjectKind::Connection:
    case ObjectKind::Unknown:
        return MatchLogicalObject(a.logical, b.logical);
    }
    return MatchResult::Candidate;
}

} // namespace

// ---------------------------------------------------------------------------
// 逻辑身份
// ---------------------------------------------------------------------------
IdentityStrength LogicalObjectId::strength() const noexcept {
    if (domain.empty() || name.empty()) {
        return IdentityStrength::Unusable;
    }
    return IdentityStrength::Strong;
}

std::string LogicalObjectId::crossSessionKey() const {
    if (strength() != IdentityStrength::Strong) {
        return std::string();
    }
    // D-02：name/scopeKey 折叠大小写后入键。服务名与注册表键名在 Windows 上大小写
    // 不敏感，两个 collector 给出的大小写不同是**表示**变化；不折叠会把同一个对象
    // 分进两个桶，直接产出一对假增删。domain 是调用方自己的分类标签，不折叠 ——
    // 折叠它只会把两个不同域并到一起，属于放宽判据。
    std::string key("logical");
    AppendKey(key, domain);
    AppendKey(key, FoldText(name));
    AppendKey(key, FoldText(scopeKey));
    return key;
}

MatchResult MatchLogicalObject(const LogicalObjectId& a, const LogicalObjectId& b) noexcept {
    if (!a.domain.empty() && !b.domain.empty() && a.domain != b.domain) {
        return MatchResult::NoMatch;
    }
    // 折叠后仍不同才是"不同对象"；仅大小写不同只降级不否定（见下）。
    bool representationDiffers = false;
    if (!a.name.empty() && !b.name.empty()) {
        if (!EqualTextFoldNoAlloc(a.name, b.name)) {
            return MatchResult::NoMatch;
        }
        representationDiffers = representationDiffers || a.name != b.name;
    }
    if (!a.scopeKey.empty() && !b.scopeKey.empty()) {
        if (!EqualTextFoldNoAlloc(a.scopeKey, b.scopeKey)) {
            return MatchResult::NoMatch;  // 同名不同作用域是两个对象
        }
        representationDiffers = representationDiffers || a.scopeKey != b.scopeKey;
    }
    // F-03 统一门槛：任一侧身份不足时最强只给 Candidate。
    if (a.strength() == IdentityStrength::Unusable || b.strength() == IdentityStrength::Unusable) {
        return MatchResult::Candidate;
    }
    if (a.scopeKey.empty() != b.scopeKey.empty()) {
        return MatchResult::Candidate;  // 一侧没说作用域，不能确认
    }
    if (representationDiffers) {
        // D-02：折叠让两条记录能配上（不再造假增删），但两侧原文不一致本身就说明
        // 至少一个来源没有归一化。这种情况只给"可能是同一个"，不给"确认"。
        return MatchResult::Candidate;
    }
    return MatchResult::Confirmed;
}

std::string SnapshotDriverKey(const DriverInstanceId& id) {
    const std::string raw = id.crossSessionKey();
    if (raw.empty()) {
        return raw;  // 身份不足：不发主键，也不靠折叠把它救回来
    }
    // crossSessionKey 的第一段是 imagePath（见 ObjectIdentity.cpp）。这里不重解析它的
    // 内部结构，而是用同一份身份重建一个路径已折叠的键：路径大小写与分隔符写法在
    // PsLoadedModuleList / SCM / 磁盘枚举之间本来就不同，属于表示差异。
    DriverInstanceId folded = id;
    folded.imagePath = FoldPath(id.imagePath);
    std::string key("snapdriver");
    AppendKey(key, folded.crossSessionKey());
    return key;
}

bool KindComparableAcrossBoot(ObjectKind kind) noexcept {
    switch (kind) {
    case ObjectKind::Driver:
    case ObjectKind::Module:
    case ObjectKind::File:
    case ObjectKind::Service:
        // 磁盘/注册表上的持久对象，重启后仍是同一个逻辑对象，可比逻辑属性。
        return true;
    case ObjectKind::Process:
    case ObjectKind::Thread:
    case ObjectKind::Handle:
    case ObjectKind::Connection:
    case ObjectKind::Device:
        // 实例对象绑定启动周期。D-02 明令进程实例不得跨启动硬配；设备对象同理是
        // 运行期对象树的一部分，保守起见一并排除 —— 保守只会少给结论，不会给错。
        return false;
    case ObjectKind::Unknown:
        return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 枚举名
// ---------------------------------------------------------------------------
const char* ScopeComparabilityName(ScopeComparability value) noexcept {
    switch (value) {
    case ScopeComparability::Unknown:              return "Unknown";
    case ScopeComparability::Identical:            return "Identical";
    case ScopeComparability::EarlierSubsetOfLater: return "EarlierSubsetOfLater";
    case ScopeComparability::LaterSubsetOfEarlier: return "LaterSubsetOfEarlier";
    case ScopeComparability::PartialOverlap:       return "PartialOverlap";
    case ScopeComparability::Disjoint:             return "Disjoint";
    }
    return "Unknown";
}

const char* CrossBootComparabilityName(CrossBootComparability value) noexcept {
    switch (value) {
    case CrossBootComparability::UnknownBoot:   return "UnknownBoot";
    case CrossBootComparability::SameBoot:      return "SameBoot";
    case CrossBootComparability::DifferentBoot: return "DifferentBoot";
    }
    return "UnknownBoot";
}

const char* RedactionClassName(RedactionClass value) noexcept {
    switch (value) {
    case RedactionClass::None:       return "None";
    case RedactionClass::UserName:   return "UserName";
    case RedactionClass::Hostname:   return "Hostname";
    case RedactionClass::FilePath:   return "FilePath";
    case RedactionClass::AccountSid: return "AccountSid";
    }
    return "None";
}

bool ParseRedactionClassName(std::string_view text, RedactionClass& out) noexcept {
    if (text == "None")       { out = RedactionClass::None; return true; }
    if (text == "UserName")   { out = RedactionClass::UserName; return true; }
    if (text == "Hostname")   { out = RedactionClass::Hostname; return true; }
    if (text == "FilePath")   { out = RedactionClass::FilePath; return true; }
    if (text == "AccountSid") { out = RedactionClass::AccountSid; return true; }
    return false;
}

const char* FieldSemanticsName(FieldSemantics value) noexcept {
    switch (value) {
    case FieldSemantics::Opaque:          return "Opaque";
    case FieldSemantics::LoadBaseAddress: return "LoadBaseAddress";
    case FieldSemantics::KernelAddress:   return "KernelAddress";
    }
    return "Opaque";
}

bool ParseFieldSemanticsName(std::string_view text, FieldSemantics& out) noexcept {
    if (text == "Opaque")          { out = FieldSemantics::Opaque; return true; }
    if (text == "LoadBaseAddress") { out = FieldSemantics::LoadBaseAddress; return true; }
    if (text == "KernelAddress")   { out = FieldSemantics::KernelAddress; return true; }
    return false;
}

const char* FieldValueKindName(FieldValueKind value) noexcept {
    switch (value) {
    case FieldValueKind::Absent: return "Absent";
    case FieldValueKind::Text:   return "Text";
    case FieldValueKind::Number: return "Number";
    }
    return "Absent";
}

bool ParseFieldValueKindName(std::string_view text, FieldValueKind& out) noexcept {
    if (text == "Absent") { out = FieldValueKind::Absent; return true; }
    if (text == "Text")   { out = FieldValueKind::Text; return true; }
    if (text == "Number") { out = FieldValueKind::Number; return true; }
    return false;
}

const char* AddressNormalizationStateName(AddressNormalizationState value) noexcept {
    switch (value) {
    case AddressNormalizationState::NotApplicable:       return "NotApplicable";
    case AddressNormalizationState::ValueMissing:        return "ValueMissing";
    case AddressNormalizationState::ModuleNotFound:      return "ModuleNotFound";
    case AddressNormalizationState::ImageIdentityWeak:   return "ImageIdentityWeak";
    case AddressNormalizationState::ImageVersionDiffers: return "ImageVersionDiffers";
    case AddressNormalizationState::DifferentModule:     return "DifferentModule";
    case AddressNormalizationState::Normalized:          return "Normalized";
    }
    return "NotApplicable";
}

const char* EntitySideStateName(EntitySideState value) noexcept {
    switch (value) {
    case EntitySideState::Present:             return "Present";
    case EntitySideState::AbsentCovered:       return "AbsentCovered";
    case EntitySideState::AbsentOutOfScope:    return "AbsentOutOfScope";
    case EntitySideState::UnknownSourceFailed: return "UnknownSourceFailed";
    case EntitySideState::UnknownCoverage:     return "UnknownCoverage";
    case EntitySideState::UnknownCrossBoot:    return "UnknownCrossBoot";
    case EntitySideState::UnknownAmbiguousIdentity: return "UnknownAmbiguousIdentity";
    }
    return "UnknownSourceFailed";
}

const char* MatchConfidenceName(MatchConfidence value) noexcept {
    switch (value) {
    case MatchConfidence::NoMatch:   return "NoMatch";
    case MatchConfidence::Uncertain: return "Uncertain";
    case MatchConfidence::Confirmed: return "Confirmed";
    }
    return "NoMatch";
}

const char* EntityChangeName(EntityChange value) noexcept {
    switch (value) {
    case EntityChange::Unchanged:            return "Unchanged";
    case EntityChange::PartiallyComparable:  return "PartiallyComparable";
    case EntityChange::Modified:             return "Modified";
    case EntityChange::Added:                return "Added";
    case EntityChange::Removed:              return "Removed";
    case EntityChange::NotComparable:        return "NotComparable";
    case EntityChange::InsufficientCoverage: return "InsufficientCoverage";
    }
    return "NotComparable";
}

const char* FieldChangeName(FieldChange value) noexcept {
    switch (value) {
    case FieldChange::Unchanged:           return "Unchanged";
    case FieldChange::NormalizedUnchanged: return "NormalizedUnchanged";
    case FieldChange::Changed:             return "Changed";
    case FieldChange::Unknown:             return "Unknown";
    case FieldChange::NotComparable:       return "NotComparable";
    }
    return "Unknown";
}

const char* ReviewPriorityName(ReviewPriority value) noexcept {
    switch (value) {
    case ReviewPriority::NotAssessed:   return "NotAssessed";
    case ReviewPriority::Informational: return "Informational";
    case ReviewPriority::NeedsReview:   return "NeedsReview";
    }
    return "NotAssessed";
}

const char* SnapshotLoadStatusName(SnapshotLoadStatus value) noexcept {
    switch (value) {
    case SnapshotLoadStatus::Ok:                      return "Ok";
    case SnapshotLoadStatus::OkWithUnknownFields:     return "OkWithUnknownFields";
    case SnapshotLoadStatus::EmptyInput:              return "EmptyInput";
    case SnapshotLoadStatus::MalformedJson:           return "MalformedJson";
    case SnapshotLoadStatus::MissingSchema:           return "MissingSchema";
    case SnapshotLoadStatus::WrongSchemaId:           return "WrongSchemaId";
    case SnapshotLoadStatus::UnsupportedMajorVersion: return "UnsupportedMajorVersion";
    case SnapshotLoadStatus::MissingRequiredField:    return "MissingRequiredField";
    case SnapshotLoadStatus::InvalidFieldValue:       return "InvalidFieldValue";
    case SnapshotLoadStatus::LimitExceeded:           return "LimitExceeded";
    }
    return "MalformedJson";
}

JsonLimits SnapshotJsonLimits() noexcept {
    // 7.2 的 L1 负载：100,000 条实体记录，含 5 类实体、地址与长路径。本模块自己
    // 写出的这种文档约 100 MiB、约 600 万个 JSON 节点，通用默认档（32 MiB /
    // 524,288 节点 / 64 MiB 节点预算）连自己刚写出来的合法文件都读不回来。
    //
    // 这里的上限是按 L1 反推的：
    //   字节：100 MiB 实测 -> 留 3 倍余量 = 320 MiB
    //   节点：每条实体约 42 + 8×字段数 个节点，100,000 条取 16,000,000
    //   节点字节：16,000,000 × sizeof(JsonValue)(≈88B) ≈ 1.4 GiB -> 取 2 GiB
    //   容器成员：实体数组本身就是 100,000 -> 取 2,000,000
    // 上限依旧存在（不是"取消检查"），只是换成了快照持久化这一档；读外来文件的
    // 调用方仍然可以传自己的 JsonLimits。
    JsonLimits limits;
    limits.maxDepth = 64U;
    limits.maxStringBytes = 4u * 1024u * 1024u;
    limits.maxContainerItems = 2u * 1000u * 1000u;
    limits.maxTotalNodes = 16u * 1000u * 1000u;
    limits.maxTotalBytes = 320u * 1024u * 1024u;
    limits.maxEstimatedNodeBytes = 2048u * 1024u * 1024u;
    return limits;
}

// ---------------------------------------------------------------------------
// D-01：选择范围
// ---------------------------------------------------------------------------
ScopeComparability CompareScopes(const SnapshotScope& earlier, const SnapshotScope& later) {
    // 未声明范围就无从校验边界。D-01 的默认值必须是"未知"而不是"一样"，
    // 否则忘记填范围的调用方会白得一个"可以判删除"的许可。
    if (!earlier.declared || !later.declared) {
        return ScopeComparability::Unknown;
    }
    if (earlier.scopeId.empty() || later.scopeId.empty()) {
        return ScopeComparability::Unknown;
    }
    if (earlier.scopeId != later.scopeId) {
        return ScopeComparability::Disjoint;
    }
    if (earlier.wholeDomain && later.wholeDomain) {
        return ScopeComparability::Identical;
    }
    if (earlier.wholeDomain) {
        return ScopeComparability::LaterSubsetOfEarlier;
    }
    if (later.wholeDomain) {
        return ScopeComparability::EarlierSubsetOfLater;
    }

    std::vector<std::string> a = earlier.selectors;
    std::vector<std::string> b = later.selectors;
    std::sort(a.begin(), a.end());
    a.erase(std::unique(a.begin(), a.end()), a.end());
    std::sort(b.begin(), b.end());
    b.erase(std::unique(b.begin(), b.end()), b.end());
    if (a.empty() || b.empty()) {
        // 声称非全域却一个筛选项都没给：说不清覆盖了什么。
        return ScopeComparability::Unknown;
    }
    if (a == b) {
        return ScopeComparability::Identical;
    }
    const bool aInB = std::includes(b.begin(), b.end(), a.begin(), a.end());
    const bool bInA = std::includes(a.begin(), a.end(), b.begin(), b.end());
    if (aInB) {
        return ScopeComparability::EarlierSubsetOfLater;
    }
    if (bInA) {
        return ScopeComparability::LaterSubsetOfEarlier;
    }
    std::vector<std::string> common;
    std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(common));
    return common.empty() ? ScopeComparability::Disjoint : ScopeComparability::PartialOverlap;
}

bool RemovalInferable(ScopeComparability value) noexcept {
    // 只有新快照的范围盖住旧快照的范围时，"旧有新无"才可能是移除。
    return value == ScopeComparability::Identical ||
           value == ScopeComparability::EarlierSubsetOfLater;
}

bool AdditionInferable(ScopeComparability value) noexcept {
    return value == ScopeComparability::Identical ||
           value == ScopeComparability::LaterSubsetOfEarlier;
}

// ---------------------------------------------------------------------------
// 快照结构
// ---------------------------------------------------------------------------
RvaRange SnapshotModule::rvaExtent() const noexcept {
    if (!imageSize.present || imageSize.value == 0U || imageSize.value > 0xFFFFFFFFULL) {
        return RvaRange{};  // 空区间：不 contains 任何 RVA
    }
    RvaRange range;
    range.rva = 0U;
    range.length = static_cast<std::uint32_t>(imageSize.value);
    return range;
}

std::string SnapshotEntity::identityKey() const {
    switch (kind) {
    case ObjectKind::Process: return process.crossSessionKey();
    case ObjectKind::Thread:  return thread.crossSessionKey();
    case ObjectKind::Driver:
    case ObjectKind::Module:  return SnapshotDriverKey(driver);
    case ObjectKind::File:    return file.crossSessionKey();
    case ObjectKind::Service:
    case ObjectKind::Device:
    case ObjectKind::Handle:
    case ObjectKind::Connection:
    case ObjectKind::Unknown: return logical.crossSessionKey();
    }
    return std::string();
}

std::string SnapshotEntity::candidateKey() const {
    // D-02：弱身份去重键**只在本次比较内有效**。它由可复用标识拼成，绝不是跨会话
    // 主键，也绝不允许据此宣称"确实是同一个对象"。
    std::string key("cand");
    AppendKey(key, std::string(ObjectKindName(kind)));
    switch (kind) {
    case ObjectKind::Process:
        AppendKey(key, process.pid);
        AppendKey(key, FoldText(process.imageName));
        break;
    case ObjectKind::Thread:
        AppendKey(key, thread.process.pid);
        AppendKey(key, thread.tid);
        break;
    case ObjectKind::Driver:
    case ObjectKind::Module:
        AppendKey(key, FoldPath(driver.imagePath));
        AppendKey(key, driver.pdbSignature);
        break;
    case ObjectKind::File:
        AppendKey(key, FoldPath(file.path));
        AppendKey(key, file.contentHash);
        break;
    case ObjectKind::Service:
    case ObjectKind::Device:
    case ObjectKind::Handle:
    case ObjectKind::Connection:
    case ObjectKind::Unknown:
        AppendKey(key, logical.domain);
        AppendKey(key, FoldText(logical.name));
        break;
    }
    return key;
}

IdentityStrength SnapshotEntity::strength() const noexcept {
    switch (kind) {
    case ObjectKind::Process: return process.strength();
    case ObjectKind::Thread:  return thread.strength();
    case ObjectKind::Driver:
    case ObjectKind::Module:  return driver.strength();
    case ObjectKind::File:    return file.strength();
    case ObjectKind::Service:
    case ObjectKind::Device:
    case ObjectKind::Handle:
    case ObjectKind::Connection:
    case ObjectKind::Unknown: return logical.strength();
    }
    return IdentityStrength::Unusable;
}

std::string SnapshotEntity::displayText() const {
    switch (kind) {
    case ObjectKind::Process:
        return process.imageName.empty() ? std::string("process") : process.imageName;
    case ObjectKind::Thread:
        return std::string("thread");
    case ObjectKind::Driver:
    case ObjectKind::Module:
        return driver.imagePath.empty() ? std::string("module") : driver.imagePath;
    case ObjectKind::File:
        return file.path.empty() ? std::string("file") : file.path;
    case ObjectKind::Service:
    case ObjectKind::Device:
    case ObjectKind::Handle:
    case ObjectKind::Connection:
    case ObjectKind::Unknown:
        return logical.name.empty() ? std::string("object") : logical.name;
    }
    return std::string("object");
}

const SnapshotPartition* Snapshot::findPartition(std::string_view partitionId) const noexcept {
    for (const SnapshotPartition& partition : partitions) {
        if (partition.partitionId == partitionId) {
            return &partition;
        }
    }
    return nullptr;
}

const SnapshotModule* Snapshot::findModule(std::string_view moduleId) const noexcept {
    for (const SnapshotModule& module : modules) {
        if (module.moduleId == moduleId) {
            return &module;
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// 比较
// ---------------------------------------------------------------------------
namespace {

struct SideContext final {
    const Snapshot* snapshot = nullptr;
    const SnapshotPartition* partition = nullptr;
    bool partitionPresent = false;
};

bool SideCarriesObservation(const SideContext& side) noexcept {
    return side.partitionPresent && side.partition != nullptr &&
           StatusCarriesObservation(side.partition->envelope.outcome.status);
}

// D-04 + F-06：有资格支撑"确实没有"需要正面证据 —— 采集成功、声称覆盖了本快照的
// 选择范围、且覆盖账目自身给出了完整性证据。默认构造的空账目不算。
bool SideUsableForAbsence(const SideContext& side) noexcept {
    if (!SideCarriesObservation(side)) {
        return false;
    }
    if (!side.partition->coversScope) {
        return false;
    }
    if (side.partition->envelope.outcome.status == CollectionStatus::Partial) {
        return false;
    }
    return side.partition->envelope.coverage.fullyCovered();
}

EntitySideState MissingSideState(const SideContext& side,
                                 ObjectKind kind,
                                 CrossBootComparability boot,
                                 bool directionInferable) {
    if (!SideCarriesObservation(side)) {
        // 未采集 / 失败 / 不支持 / 拒绝访问 —— D-04 的红线：这不是"没有"。
        return EntitySideState::UnknownSourceFailed;
    }
    if (!KindComparableAcrossBoot(kind) && boot != CrossBootComparability::SameBoot) {
        // D-02：实例类对象跨启动（或无法证明同启动）时缺席没有意义。
        return EntitySideState::UnknownCrossBoot;
    }
    if (!SideUsableForAbsence(side)) {
        return EntitySideState::UnknownCoverage;
    }
    if (!directionInferable) {
        // D-01：这一侧确实完整，但两次选择范围的关系不支持这个方向的推断。
        return EntitySideState::AbsentOutOfScope;
    }
    return EntitySideState::AbsentCovered;
}

const char* LimitationForState(EntitySideState state) noexcept {
    switch (state) {
    case EntitySideState::UnknownSourceFailed: return "snapshot.limitation.sourceFailed";
    case EntitySideState::UnknownCoverage:     return "snapshot.limitation.coverageIncomplete";
    case EntitySideState::UnknownCrossBoot:    return "snapshot.limitation.crossBootInstance";
    case EntitySideState::AbsentOutOfScope:    return "snapshot.limitation.scopeNotComparable";
    case EntitySideState::UnknownAmbiguousIdentity:
        return "snapshot.limitation.duplicateIdentityKey";
    case EntitySideState::Present:
    case EntitySideState::AbsentCovered:       return "";
    }
    return "";
}

EntityChange DeriveChange(EntitySideState earlier,
                          EntitySideState later,
                          bool anyChangedField,
                          bool anyIncomparableField) {
    if (earlier == EntitySideState::Present && later == EntitySideState::Present) {
        if (anyChangedField) {
            return EntityChange::Modified;
        }
        return anyIncomparableField ? EntityChange::PartiallyComparable : EntityChange::Unchanged;
    }
    if (earlier == EntitySideState::Present) {
        switch (later) {
        case EntitySideState::AbsentCovered:       return EntityChange::Removed;
        case EntitySideState::UnknownCoverage:     return EntityChange::InsufficientCoverage;
        case EntitySideState::AbsentOutOfScope:
        case EntitySideState::UnknownSourceFailed:
        case EntitySideState::UnknownCrossBoot:
        case EntitySideState::UnknownAmbiguousIdentity:
        case EntitySideState::Present:             return EntityChange::NotComparable;
        }
        return EntityChange::NotComparable;
    }
    if (later == EntitySideState::Present) {
        switch (earlier) {
        case EntitySideState::AbsentCovered:       return EntityChange::Added;
        case EntitySideState::UnknownCoverage:     return EntityChange::InsufficientCoverage;
        case EntitySideState::AbsentOutOfScope:
        case EntitySideState::UnknownSourceFailed:
        case EntitySideState::UnknownCrossBoot:
        case EntitySideState::UnknownAmbiguousIdentity:
        case EntitySideState::Present:             return EntityChange::NotComparable;
        }
        return EntityChange::NotComparable;
    }
    return EntityChange::NotComparable;
}

FieldDelta CompareOneField(const std::string& name,
                           const EntityField* earlierField,
                           const EntityField* laterField,
                           const SnapshotEntity& earlierEntity,
                           const SnapshotEntity& laterEntity,
                           const Snapshot& earlierSnapshot,
                           const Snapshot& laterSnapshot) {
    FieldDelta delta;
    delta.name = name;
    if (earlierField != nullptr) {
        delta.semantics = earlierField->semantics;
    } else if (laterField != nullptr) {
        delta.semantics = laterField->semantics;
    }
    RenderField(earlierField, delta.earlierKnown, delta.earlierText);
    RenderField(laterField, delta.laterKnown, delta.laterText);

    // 一侧没有这个字段，或者两侧语义声明不一致 —— 都不给"变化"结论。
    if (earlierField == nullptr || laterField == nullptr) {
        delta.change = FieldChange::Unknown;
        return delta;
    }
    if (earlierField->semantics != laterField->semantics) {
        delta.change = FieldChange::NotComparable;
        return delta;
    }
    if (earlierField->kind == FieldValueKind::Absent || laterField->kind == FieldValueKind::Absent) {
        // Absent 是"未采集"，不是空串也不是 0。
        delta.change = FieldChange::Unknown;
        if (delta.semantics != FieldSemantics::Opaque) {
            delta.normalization.state = AddressNormalizationState::ValueMissing;
        }
        return delta;
    }
    if (earlierField->kind != laterField->kind) {
        delta.change = FieldChange::NotComparable;
        return delta;
    }

    switch (delta.semantics) {
    case FieldSemantics::Opaque:
        if (earlierField->kind == FieldValueKind::Text) {
            delta.change = (earlierField->text == laterField->text) ? FieldChange::Unchanged
                                                                    : FieldChange::Changed;
            return delta;
        }
        if (!earlierField->number.present || !laterField->number.present) {
            delta.change = FieldChange::Unknown;
            return delta;
        }
        delta.change = (earlierField->number.value == laterField->number.value)
                           ? FieldChange::Unchanged
                           : FieldChange::Changed;
        return delta;

    case FieldSemantics::LoadBaseAddress: {
        // D-03：装载基址本身不是差异证据 —— 前提是两侧确实是同一个映像。
        if (earlierField->kind != FieldValueKind::Number) {
            delta.change = FieldChange::NotComparable;  // 地址字段被写成文本：表示形式不对
            return delta;
        }
        if (!earlierField->number.present || !laterField->number.present) {
            delta.change = FieldChange::Unknown;
            delta.normalization.state = AddressNormalizationState::ValueMissing;
            return delta;
        }
        const bool driverKind = earlierEntity.kind == ObjectKind::Driver ||
                                earlierEntity.kind == ObjectKind::Module;
        if (!driverKind || laterEntity.kind != earlierEntity.kind) {
            // 没有映像身份可依据，就不许把"基址一样"当成"同一份代码"。
            delta.normalization.state = AddressNormalizationState::ImageIdentityWeak;
            delta.change = FieldChange::NotComparable;
            return delta;
        }
        const MatchResult match = MatchDriverInstance(earlierEntity.driver, laterEntity.driver);
        if (match == MatchResult::Confirmed) {
            delta.normalization.state = AddressNormalizationState::Normalized;
            delta.normalization.earlierRva = OptionalU64::of(0U);
            delta.normalization.laterRva = OptionalU64::of(0U);
            delta.change = (earlierField->number.value == laterField->number.value)
                               ? FieldChange::Unchanged
                               : FieldChange::NormalizedUnchanged;
            return delta;
        }
        delta.normalization.state =
            (match == MatchResult::Candidate)
                ? AddressNormalizationState::ImageIdentityWeak
                : ClassifyIncomparableImages(earlierEntity.driver, laterEntity.driver);
        delta.change = FieldChange::NotComparable;
        return delta;
    }

    case FieldSemantics::KernelAddress: {
        if (earlierField->kind != FieldValueKind::Number) {
            delta.change = FieldChange::NotComparable;
            return delta;
        }
        if (!earlierField->number.present || !laterField->number.present) {
            delta.change = FieldChange::Unknown;
            delta.normalization.state = AddressNormalizationState::ValueMissing;
            return delta;
        }
        const ResolvedAddress earlierHit = ResolveAddress(earlierSnapshot, earlierField->number);
        const ResolvedAddress laterHit = ResolveAddress(laterSnapshot, laterField->number);
        if (!earlierHit.resolved || !laterHit.resolved) {
            // D-03：模块缺失时不归一化，也不拿原始地址硬比 —— 两次装载基址不同
            // 会立刻造出假差异。
            delta.normalization.state = AddressNormalizationState::ModuleNotFound;
            if (earlierHit.resolved) {
                delta.normalization.earlierModuleId = earlierHit.module->moduleId;
                delta.normalization.earlierRva = OptionalU64::of(earlierHit.rva);
            }
            if (laterHit.resolved) {
                delta.normalization.laterModuleId = laterHit.module->moduleId;
                delta.normalization.laterRva = OptionalU64::of(laterHit.rva);
            }
            delta.change = FieldChange::NotComparable;
            return delta;
        }
        delta.normalization.earlierModuleId = earlierHit.module->moduleId;
        delta.normalization.laterModuleId = laterHit.module->moduleId;
        delta.normalization.earlierRva = OptionalU64::of(earlierHit.rva);
        delta.normalization.laterRva = OptionalU64::of(laterHit.rva);

        const MatchResult match =
            MatchDriverInstance(earlierHit.module->identity, laterHit.module->identity);
        if (match == MatchResult::Confirmed) {
            delta.normalization.state = AddressNormalizationState::Normalized;
            if (earlierHit.rva != laterHit.rva) {
                delta.change = FieldChange::Changed;
            } else if (earlierField->number.value == laterField->number.value) {
                delta.change = FieldChange::Unchanged;
            } else {
                delta.change = FieldChange::NormalizedUnchanged;
            }
            return delta;
        }
        // D-03：只有确认可比才归一化。不同版本的相同 RVA 绝不是相同代码。
        delta.normalization.state =
            (match == MatchResult::Candidate)
                ? AddressNormalizationState::ImageIdentityWeak
                : ClassifyIncomparableImages(earlierHit.module->identity, laterHit.module->identity);
        delta.change = FieldChange::NotComparable;
        return delta;
    }
    }
    delta.change = FieldChange::Unknown;
    return delta;
}

void FillSideMetadata(EntityDelta& delta,
                      const SnapshotEntity* earlierEntity,
                      const SnapshotEntity* laterEntity,
                      const SideContext& earlierSide,
                      const SideContext& laterSide) {
    if (earlierEntity != nullptr) {
        delta.earlierRawRecordId = earlierEntity->rawRecordId;
        delta.earlierDisplayOrder = earlierEntity->displayOrder;
    }
    if (laterEntity != nullptr) {
        delta.laterRawRecordId = laterEntity->rawRecordId;
        delta.laterDisplayOrder = laterEntity->displayOrder;
    }
    if (earlierSide.partition != nullptr) {
        delta.earlierEvidenceId = earlierSide.partition->envelope.evidenceId;
        delta.earlierObservedUtc100ns = earlierSide.partition->envelope.window.endUtc100ns;
    }
    if (laterSide.partition != nullptr) {
        delta.laterEvidenceId = laterSide.partition->envelope.evidenceId;
        delta.laterObservedUtc100ns = laterSide.partition->envelope.window.endUtc100ns;
    }
    delta.displayOrderChanged = earlierEntity != nullptr && laterEntity != nullptr &&
                                earlierEntity->displayOrder != laterEntity->displayOrder;
}

void ApplyReviewRules(EntityDelta& delta, const std::vector<ReviewRule>& rules) {
    // D-05：引擎自己不发明优先级，只执行调用方声明的规则；没有规则就保持 NotAssessed。
    for (const ReviewRule& rule : rules) {
        if (!rule.partitionId.empty() && rule.partitionId != delta.partitionId) {
            continue;
        }
        bool applies = false;
        if (rule.fieldName.empty()) {
            applies = delta.change == EntityChange::Modified ||
                      delta.change == EntityChange::Added ||
                      delta.change == EntityChange::Removed;
        } else {
            for (const FieldDelta& field : delta.fields) {
                if (field.name == rule.fieldName && field.change == FieldChange::Changed) {
                    applies = true;
                    break;
                }
            }
        }
        if (!applies) {
            continue;
        }
        if (static_cast<int>(rule.priority) > static_cast<int>(delta.review.priority)) {
            delta.review.priority = rule.priority;
        }
        PushUnique(delta.review.reasonKeys, rule.reasonKey);
    }
}

struct EntityBucket final {
    std::vector<const SnapshotEntity*> earlier;
    std::vector<const SnapshotEntity*> later;
};

std::string DeltaSortKey(const EntityDelta& delta) {
    std::string key = delta.partitionId;
    key.push_back(kSep);
    key.append(delta.identityKey.empty() ? delta.candidateKey : delta.identityKey);
    key.push_back(kSep);
    key.append(delta.displayText);
    key.push_back(kSep);
    key.append(delta.earlierRawRecordId);
    key.push_back(kSep);
    key.append(delta.laterRawRecordId);
    return key;
}

} // namespace

SnapshotComparison CompareSnapshots(const Snapshot& earlier,
                                    const Snapshot& later,
                                    const SnapshotCompareOptions& options) {
    SnapshotComparison result;
    result.scope = CompareScopes(earlier.scope, later.scope);

    const std::string& earlierBoot = earlier.envelope.window.bootId;
    const std::string& laterBoot = later.envelope.window.bootId;
    if (earlierBoot.empty() || laterBoot.empty()) {
        result.boot = CrossBootComparability::UnknownBoot;
    } else {
        result.boot = (earlierBoot == laterBoot) ? CrossBootComparability::SameBoot
                                                 : CrossBootComparability::DifferentBoot;
    }

    // D-01：两份快照来自不同机器时，任何"增/删"都失去意义。这不会让比较停摆 ——
    // 逻辑属性照常比，只是增删被降级成不可比较。
    const std::string& earlierMachine = earlier.envelope.window.machineId;
    const std::string& laterMachine = later.envelope.window.machineId;
    const bool machineMismatch =
        !earlierMachine.empty() && !laterMachine.empty() && earlierMachine != laterMachine;

    if (result.scope == ScopeComparability::Unknown) {
        result.limitationKeys.push_back("snapshot.limitation.scopeUndeclared");
    } else if (result.scope != ScopeComparability::Identical) {
        result.limitationKeys.push_back("snapshot.limitation.scopeDiffers");
    }
    if (result.boot == CrossBootComparability::DifferentBoot) {
        result.limitationKeys.push_back("snapshot.limitation.differentBoot");
    } else if (result.boot == CrossBootComparability::UnknownBoot) {
        result.limitationKeys.push_back("snapshot.limitation.bootUndeclared");
    }
    if (machineMismatch) {
        result.limitationKeys.push_back("snapshot.limitation.machineMismatch");
    }

    const bool removalAllowed = RemovalInferable(result.scope) && !machineMismatch;
    const bool additionAllowed = AdditionInferable(result.scope) && !machineMismatch;

    // ---- 分区账目：两侧分区 id 的并集，缺席一侧显式落成 NotCollected ----
    std::vector<std::string> partitionIds;
    for (const SnapshotPartition& partition : earlier.partitions) {
        PushUnique(partitionIds, partition.partitionId);
    }
    for (const SnapshotPartition& partition : later.partitions) {
        PushUnique(partitionIds, partition.partitionId);
    }
    // 实体引用了却没有声明账目的分区同样必须进账 —— 悄悄跳过就等于"没采到 = 正常"。
    for (const SnapshotEntity& entity : earlier.entities) {
        PushUnique(partitionIds, entity.partitionId);
    }
    for (const SnapshotEntity& entity : later.entities) {
        PushUnique(partitionIds, entity.partitionId);
    }
    std::sort(partitionIds.begin(), partitionIds.end());

    std::vector<EvidenceEnvelope> envelopes;
    envelopes.push_back(earlier.envelope);
    envelopes.push_back(later.envelope);

    std::vector<EntityDelta> deltas;

    for (const std::string& partitionId : partitionIds) {
        SideContext earlierSide;
        earlierSide.snapshot = &earlier;
        earlierSide.partition = earlier.findPartition(partitionId);
        earlierSide.partitionPresent = earlierSide.partition != nullptr;

        SideContext laterSide;
        laterSide.snapshot = &later;
        laterSide.partition = later.findPartition(partitionId);
        laterSide.partitionPresent = laterSide.partition != nullptr;

        PartitionAccount account;
        account.partitionId = partitionId;
        account.earlierPresent = earlierSide.partitionPresent;
        account.laterPresent = laterSide.partitionPresent;
        account.earlierStatus = earlierSide.partitionPresent
                                    ? earlierSide.partition->envelope.outcome.status
                                    : CollectionStatus::NotCollected;
        account.laterStatus = laterSide.partitionPresent
                                  ? laterSide.partition->envelope.outcome.status
                                  : CollectionStatus::NotCollected;
        account.earlierUsableForAbsence = SideUsableForAbsence(earlierSide);
        account.laterUsableForAbsence = SideUsableForAbsence(laterSide);

        ObjectKind kind = ObjectKind::Unknown;
        bool kindMismatch = false;
        if (earlierSide.partition != nullptr && laterSide.partition != nullptr) {
            kind = earlierSide.partition->kind;
            kindMismatch = earlierSide.partition->kind != laterSide.partition->kind;
        } else if (earlierSide.partition != nullptr) {
            kind = earlierSide.partition->kind;
        } else if (laterSide.partition != nullptr) {
            kind = laterSide.partition->kind;
        }
        account.kind = kind;

        if (!account.earlierPresent) {
            account.limitationKeys.push_back("snapshot.partition.earlierNotCollected");
        }
        if (!account.laterPresent) {
            account.limitationKeys.push_back("snapshot.partition.laterNotCollected");
        }
        if (account.earlierPresent && !SideCarriesObservation(earlierSide)) {
            account.limitationKeys.push_back("snapshot.partition.earlierNoObservation");
        }
        if (account.laterPresent && !SideCarriesObservation(laterSide)) {
            account.limitationKeys.push_back("snapshot.partition.laterNoObservation");
        }
        if (SideCarriesObservation(earlierSide) && !account.earlierUsableForAbsence) {
            account.limitationKeys.push_back("snapshot.partition.earlierCoverageIncomplete");
        }
        if (SideCarriesObservation(laterSide) && !account.laterUsableForAbsence) {
            account.limitationKeys.push_back("snapshot.partition.laterCoverageIncomplete");
        }
        if (kindMismatch) {
            account.limitationKeys.push_back("snapshot.partition.kindMismatch");
        }
        account.comparable =
            SideCarriesObservation(earlierSide) && SideCarriesObservation(laterSide) && !kindMismatch;

        // D-04：两侧同名分区声明了不同的实体类型，就不是同一份采集视图。此时"旧有
        // 新无"完全可能只是两个 collector 装了不同的东西，不能当成增删。分区账目
        // 已经因此判 not comparable，逐条结论必须跟着一起收紧，否则同一份结果里
        // 账目说"没比"、行却说"被删除了"。
        const bool partitionRemovalAllowed = removalAllowed && !kindMismatch;
        const bool partitionAdditionAllowed = additionAllowed && !kindMismatch;

        if (earlierSide.partition != nullptr) {
            envelopes.push_back(earlierSide.partition->envelope);
        }
        if (laterSide.partition != nullptr) {
            envelopes.push_back(laterSide.partition->envelope);
        }

        // ---- 收集本分区的实体并按身份分桶 ----
        std::map<std::string, EntityBucket> strongBuckets;
        std::map<std::string, EntityBucket> weakBuckets;
        for (const SnapshotEntity& entity : earlier.entities) {
            if (entity.partitionId != partitionId) {
                continue;
            }
            const std::string key = entity.identityKey();
            if (key.empty()) {
                weakBuckets[entity.candidateKey()].earlier.push_back(&entity);
            } else {
                strongBuckets[key].earlier.push_back(&entity);
            }
        }
        for (const SnapshotEntity& entity : later.entities) {
            if (entity.partitionId != partitionId) {
                continue;
            }
            const std::string key = entity.identityKey();
            if (key.empty()) {
                weakBuckets[entity.candidateKey()].later.push_back(&entity);
            } else {
                strongBuckets[key].later.push_back(&entity);
            }
        }

        auto makeDelta = [&](const SnapshotEntity* earlierEntity,
                             const SnapshotEntity* laterEntity,
                             const std::string& strongKey,
                             const std::string& weakKey,
                             MatchConfidence confidence) {
            EntityDelta delta;
            delta.partitionId = partitionId;
            delta.identityKey = strongKey;
            delta.candidateKey = weakKey;
            const SnapshotEntity* any = earlierEntity != nullptr ? earlierEntity : laterEntity;
            if (any != nullptr) {
                delta.kind = any->kind;
                delta.strength = any->strength();
                delta.displayText = any->displayText();
            } else {
                delta.kind = kind;
            }
            delta.matchConfidence = confidence;
            FillSideMetadata(delta, earlierEntity, laterEntity, earlierSide, laterSide);

            bool anyChanged = false;
            bool anyIncomparable = false;
            if (earlierEntity != nullptr && laterEntity != nullptr) {
                delta.earlierState = EntitySideState::Present;
                delta.laterState = EntitySideState::Present;
                std::vector<std::string> names;
                for (const EntityField& field : earlierEntity->fields) {
                    PushUnique(names, field.name);
                }
                for (const EntityField& field : laterEntity->fields) {
                    PushUnique(names, field.name);
                }
                for (const std::string& name : names) {
                    const EntityField* ef = FindField(earlierEntity->fields, name);
                    const EntityField* lf = FindField(laterEntity->fields, name);
                    FieldDelta field = CompareOneField(name, ef, lf, *earlierEntity, *laterEntity,
                                                       earlier, later);
                    field.earlierCollectorId = earlierSide.partition != nullptr
                                                   ? earlierSide.partition->envelope.source.collectorId
                                                   : std::string();
                    field.laterCollectorId = laterSide.partition != nullptr
                                                 ? laterSide.partition->envelope.source.collectorId
                                                 : std::string();
                    field.earlierObservedUtc100ns = delta.earlierObservedUtc100ns;
                    field.laterObservedUtc100ns = delta.laterObservedUtc100ns;
                    field.earlierEvidenceId = delta.earlierEvidenceId;
                    field.laterEvidenceId = delta.laterEvidenceId;
                    if (field.change == FieldChange::Changed) {
                        anyChanged = true;
                    }
                    if (field.change == FieldChange::Unknown ||
                        field.change == FieldChange::NotComparable) {
                        anyIncomparable = true;
                    }
                    if (field.change != FieldChange::Unchanged) {
                        delta.fields.push_back(std::move(field));
                    }
                }
            } else if (earlierEntity != nullptr) {
                delta.earlierState = EntitySideState::Present;
                delta.laterState =
                    MissingSideState(laterSide, delta.kind, result.boot, partitionRemovalAllowed);
            } else {
                delta.laterState = EntitySideState::Present;
                delta.earlierState =
                    MissingSideState(earlierSide, delta.kind, result.boot, partitionAdditionAllowed);
            }

            delta.change =
                DeriveChange(delta.earlierState, delta.laterState, anyChanged, anyIncomparable);

            // D-02：身份不足时绝不产出增删 —— 无法稳定匹配只能是不确定。
            if (delta.matchConfidence == MatchConfidence::Uncertain &&
                (delta.change == EntityChange::Added || delta.change == EntityChange::Removed)) {
                delta.change = EntityChange::NotComparable;
                PushUnique(delta.limitationKeys, "snapshot.limitation.identityInsufficient");
            }

            PushUnique(delta.limitationKeys, LimitationForState(delta.earlierState));
            PushUnique(delta.limitationKeys, LimitationForState(delta.laterState));
            if (kindMismatch) {
                // 不然读者只会看到一句"范围不支持这个方向的推断"，看不出真正的原因。
                PushUnique(delta.limitationKeys, "snapshot.partition.kindMismatch");
            }
            ApplyReviewRules(delta, options.reviewRules);
            deltas.push_back(std::move(delta));
        };

        for (const auto& entry : strongBuckets) {
            const EntityBucket& bucket = entry.second;
            const bool ambiguous = bucket.earlier.size() > 1U || bucket.later.size() > 1U;
            if (ambiguous) {
                // 同一稳定键出现多条：无法确定配对关系，只能落成不确定，不猜。
                //
                // D-04：对面那一侧的状态**必须**照实推导，不能一律写成 UnknownCoverage。
                // 否则同一个 AccessDenied 的 collector，在有重复键的行上显示成"采到了
                // 但覆盖不全"、在别的行上显示成"来源失败"，同一分区的行与账目自相矛盾。
                // 重复键是**额外**的限制，叠加在真实侧状态之上，不是替换它。
                //
                // 另一半同样重要：对面桶里确实有同键记录时，那一侧既不是"没有"也不能
                // 说"在"（说"在"等于宣称这一条配上了），只能是 UnknownAmbiguousIdentity。
                auto pushAmbiguous = [&](const SnapshotEntity* earlierEntity,
                                         const SnapshotEntity* laterEntity) {
                    const SnapshotEntity* self =
                        earlierEntity != nullptr ? earlierEntity : laterEntity;
                    EntityDelta delta;
                    delta.partitionId = partitionId;
                    delta.identityKey = entry.first;
                    delta.kind = self->kind;
                    delta.strength = self->strength();
                    delta.displayText = self->displayText();
                    delta.matchConfidence = MatchConfidence::Uncertain;
                    if (earlierEntity != nullptr) {
                        delta.earlierState = EntitySideState::Present;
                        delta.laterState =
                            bucket.later.empty()
                                ? MissingSideState(laterSide, delta.kind, result.boot,
                                                   partitionRemovalAllowed)
                                : EntitySideState::UnknownAmbiguousIdentity;
                    } else {
                        delta.laterState = EntitySideState::Present;
                        delta.earlierState =
                            bucket.earlier.empty()
                                ? MissingSideState(earlierSide, delta.kind, result.boot,
                                                   partitionAdditionAllowed)
                                : EntitySideState::UnknownAmbiguousIdentity;
                    }
                    // 配对关系不确定，因此无论两侧状态如何都不给增删/未变结论。
                    delta.change = EntityChange::NotComparable;
                    PushUnique(delta.limitationKeys, "snapshot.limitation.duplicateIdentityKey");
                    PushUnique(delta.limitationKeys, LimitationForState(delta.earlierState));
                    PushUnique(delta.limitationKeys, LimitationForState(delta.laterState));
                    if (kindMismatch) {
                        PushUnique(delta.limitationKeys, "snapshot.partition.kindMismatch");
                    }
                    FillSideMetadata(delta, earlierEntity, laterEntity, earlierSide, laterSide);
                    ApplyReviewRules(delta, options.reviewRules);
                    deltas.push_back(std::move(delta));
                };
                for (const SnapshotEntity* entity : bucket.earlier) {
                    pushAmbiguous(entity, nullptr);
                }
                for (const SnapshotEntity* entity : bucket.later) {
                    pushAmbiguous(nullptr, entity);
                }
                continue;
            }
            const SnapshotEntity* e = bucket.earlier.empty() ? nullptr : bucket.earlier.front();
            const SnapshotEntity* l = bucket.later.empty() ? nullptr : bucket.later.front();
            MatchConfidence confidence = MatchConfidence::NoMatch;
            if (e != nullptr && l != nullptr) {
                const MatchResult match = MatchEntityIdentity(*e, *l);
                if (match == MatchResult::NoMatch) {
                    // 键相同却被身份判据否掉：拆成两条不确定记录，绝不硬配。
                    makeDelta(e, nullptr, entry.first, std::string(), MatchConfidence::Uncertain);
                    makeDelta(nullptr, l, entry.first, std::string(), MatchConfidence::Uncertain);
                    continue;
                }
                confidence = (match == MatchResult::Confirmed) ? MatchConfidence::Confirmed
                                                               : MatchConfidence::Uncertain;
            }
            makeDelta(e, l, entry.first, std::string(), confidence);
        }

        for (const auto& entry : weakBuckets) {
            const EntityBucket& bucket = entry.second;
            if (bucket.earlier.size() == 1U && bucket.later.size() == 1U &&
                MatchEntityIdentity(*bucket.earlier.front(), *bucket.later.front()) !=
                    MatchResult::NoMatch) {
                // D-02：只能候选匹配 —— 配上但标不确定，比造一对假增删诚实。
                makeDelta(bucket.earlier.front(), bucket.later.front(), std::string(), entry.first,
                          MatchConfidence::Uncertain);
                continue;
            }
            for (const SnapshotEntity* entity : bucket.earlier) {
                makeDelta(entity, nullptr, std::string(), entry.first, MatchConfidence::Uncertain);
            }
            for (const SnapshotEntity* entity : bucket.later) {
                makeDelta(nullptr, entity, std::string(), entry.first, MatchConfidence::Uncertain);
            }
        }

        result.partitions.push_back(std::move(account));
    }

    std::sort(deltas.begin(), deltas.end(), [](const EntityDelta& a, const EntityDelta& b) {
        return DeltaSortKey(a) < DeltaSortKey(b);
    });

    // ---- 计数（在过滤 Unchanged 之前完成，口径才不会被展示选项影响）----
    for (const EntityDelta& delta : deltas) {
        switch (delta.change) {
        case EntityChange::Unchanged:            ++result.unchangedCount; break;
        case EntityChange::PartiallyComparable:  ++result.partiallyComparableCount; break;
        case EntityChange::Modified:             ++result.modifiedCount; break;
        case EntityChange::Added:                ++result.addedCount; break;
        case EntityChange::Removed:              ++result.removedCount; break;
        case EntityChange::NotComparable:        ++result.notComparableCount; break;
        case EntityChange::InsufficientCoverage: ++result.insufficientCoverageCount; break;
        }
    }

    for (PartitionAccount& account : result.partitions) {
        for (const EntityDelta& delta : deltas) {
            if (delta.partitionId != account.partitionId) {
                continue;
            }
            if (delta.change == EntityChange::NotComparable ||
                delta.change == EntityChange::InsufficientCoverage) {
                ++account.entitiesNotComparable;
            } else {
                ++account.entitiesCompared;
            }
        }
        bool partitionDifference = false;
        for (const EntityDelta& delta : deltas) {
            if (delta.partitionId != account.partitionId) {
                continue;
            }
            if (delta.change == EntityChange::Modified || delta.change == EntityChange::Added ||
                delta.change == EntityChange::Removed) {
                partitionDifference = true;
                break;
            }
        }
        if (!account.comparable) {
            account.conclusion = AnalysisConclusion::NoEvidence;
        } else if (partitionDifference) {
            account.conclusion = AnalysisConclusion::DifferenceObserved;
        } else if (account.entitiesNotComparable != 0U || !account.earlierUsableForAbsence ||
                   !account.laterUsableForAbsence || result.scope != ScopeComparability::Identical) {
            account.conclusion = AnalysisConclusion::Indeterminate;
        } else {
            account.conclusion = AnalysisConclusion::NoDifferenceObserved;
        }
    }

    bool anyComparablePartition = false;
    bool allPartitionsClean = true;
    for (const PartitionAccount& account : result.partitions) {
        if (account.comparable) {
            anyComparablePartition = true;
        }
        if (!account.comparable || !account.earlierUsableForAbsence ||
            !account.laterUsableForAbsence) {
            allPartitionsClean = false;
        }
    }

    const bool differenceFound =
        result.addedCount != 0U || result.removedCount != 0U || result.modifiedCount != 0U;
    if (!anyComparablePartition) {
        // F-05：没有可用观测就不是"未发现差异"。
        result.conclusion = AnalysisConclusion::NoEvidence;
    } else if (differenceFound) {
        result.conclusion = AnalysisConclusion::DifferenceObserved;
    } else if (!allPartitionsClean || result.scope != ScopeComparability::Identical ||
               machineMismatch || result.notComparableCount != 0U ||
               result.insufficientCoverageCount != 0U || result.partiallyComparableCount != 0U) {
        result.conclusion = AnalysisConclusion::Indeterminate;
    } else {
        result.conclusion = AnalysisConclusion::NoDifferenceObserved;
    }

    result.trust = BuildTrustStatement(envelopes);

    if (options.emitUnchanged) {
        result.deltas = std::move(deltas);
    } else {
        for (EntityDelta& delta : deltas) {
            if (delta.change != EntityChange::Unchanged) {
                result.deltas.push_back(std::move(delta));
            }
        }
    }

    // ---- 自检：只看已发布的结果，不复用上面任何一个中间变量 ----
    // 旧实现在这里读 removalAllowed / additionAllowed 等**产生**这些行的局部变量，
    // 于是每个子句都恒真：784 种生成组合、20 种注入损坏，没有一次能让它变成 false。
    // 现在改成对 result 的独立复核（见 CheckComparisonSelfConsistency）。
    result.selfCheckPassed = CheckComparisonSelfConsistency(result);
    return result;
}

namespace {

bool HasKey(const std::vector<std::string>& list, const char* value) {
    return std::find(list.begin(), list.end(), std::string(value)) != list.end();
}

bool AnyFieldChange(const EntityDelta& delta, FieldChange change) {
    for (const FieldDelta& field : delta.fields) {
        if (field.change == change) {
            return true;
        }
    }
    return false;
}

const PartitionAccount* FindAccountFor(const SnapshotComparison& comparison,
                                       const std::string& partitionId) {
    for (const PartitionAccount& account : comparison.partitions) {
        if (account.partitionId == partitionId) {
            return &account;
        }
    }
    return nullptr;
}

// 单条结论与它自己的两侧状态、字段清单是否相容。
bool RowConsistent(const EntityDelta& delta,
                   const PartitionAccount& account,
                   bool removalInferable,
                   bool additionInferable) {
    const bool bothPresent = delta.earlierState == EntitySideState::Present &&
                             delta.laterState == EntitySideState::Present;
    switch (delta.change) {
    case EntityChange::Removed:
        // "移除"的全部依据：旧侧在场、新侧确实完整地采到了并且没有它、范围与机器
        // 允许这个方向的推断、配对不是"不确定"。分区账目按 envelope 结算，因此这里
        // 读的是账目而不是当初那个 bool。
        return removalInferable && delta.earlierState == EntitySideState::Present &&
               delta.laterState == EntitySideState::AbsentCovered &&
               delta.matchConfidence != MatchConfidence::Uncertain && account.comparable &&
               account.laterPresent && account.laterUsableForAbsence &&
               account.laterStatus == CollectionStatus::Success;
    case EntityChange::Added:
        return additionInferable && delta.laterState == EntitySideState::Present &&
               delta.earlierState == EntitySideState::AbsentCovered &&
               delta.matchConfidence != MatchConfidence::Uncertain && account.comparable &&
               account.earlierPresent && account.earlierUsableForAbsence &&
               account.earlierStatus == CollectionStatus::Success;
    case EntityChange::Unchanged:
        // 归一化掉的字段（同映像不同基址）可以留在清单里；真变化/未知/不可比较不行。
        return bothPresent && !AnyFieldChange(delta, FieldChange::Changed) &&
               !AnyFieldChange(delta, FieldChange::Unknown) &&
               !AnyFieldChange(delta, FieldChange::NotComparable);
    case EntityChange::Modified:
        return bothPresent && AnyFieldChange(delta, FieldChange::Changed);
    case EntityChange::PartiallyComparable:
        return bothPresent && !AnyFieldChange(delta, FieldChange::Changed) &&
               (AnyFieldChange(delta, FieldChange::Unknown) ||
                AnyFieldChange(delta, FieldChange::NotComparable));
    case EntityChange::InsufficientCoverage:
        return (delta.earlierState == EntitySideState::Present &&
                delta.laterState == EntitySideState::UnknownCoverage) ||
               (delta.laterState == EntitySideState::Present &&
                delta.earlierState == EntitySideState::UnknownCoverage);
    case EntityChange::NotComparable:
        // 两侧都在场却"不可比较"说明配对逻辑与结论打架；而且必须说得出为什么。
        return !bothPresent && !delta.limitationKeys.empty();
    }
    return false;
}

} // namespace

bool CheckComparisonSelfConsistency(const SnapshotComparison& comparison) {
    std::size_t unchanged = 0;
    std::size_t partially = 0;
    std::size_t modified = 0;
    std::size_t added = 0;
    std::size_t removed = 0;
    std::size_t notComparable = 0;
    std::size_t insufficient = 0;
    for (const EntityDelta& delta : comparison.deltas) {
        switch (delta.change) {
        case EntityChange::Unchanged:            ++unchanged; break;
        case EntityChange::PartiallyComparable:  ++partially; break;
        case EntityChange::Modified:             ++modified; break;
        case EntityChange::Added:                ++added; break;
        case EntityChange::Removed:              ++removed; break;
        case EntityChange::NotComparable:        ++notComparable; break;
        case EntityChange::InsufficientCoverage: ++insufficient; break;
        }
    }
    if (partially != comparison.partiallyComparableCount || modified != comparison.modifiedCount ||
        added != comparison.addedCount || removed != comparison.removedCount ||
        notComparable != comparison.notComparableCount ||
        insufficient != comparison.insufficientCoverageCount) {
        return false;
    }
    const std::size_t published = comparison.unchangedCount + comparison.partiallyComparableCount +
                                  comparison.modifiedCount + comparison.addedCount +
                                  comparison.removedCount + comparison.notComparableCount +
                                  comparison.insufficientCoverageCount;
    // emitUnchanged=false 时未变化的行不进 deltas，这是唯一允许的缺口；除此之外
    // 行数必须与计数总和严格相等。
    const bool unchangedRowsPresent = unchanged == comparison.unchangedCount;
    if (unchangedRowsPresent) {
        if (comparison.deltas.size() != published) {
            return false;
        }
    } else if (unchanged == 0U) {
        if (comparison.deltas.size() + comparison.unchangedCount != published) {
            return false;
        }
    } else {
        return false;
    }

    const bool machineMismatch = HasKey(comparison.limitationKeys, "snapshot.limitation.machineMismatch");
    const bool removalInferable = RemovalInferable(comparison.scope) && !machineMismatch;
    const bool additionInferable = AdditionInferable(comparison.scope) && !machineMismatch;

    for (const EntityDelta& delta : comparison.deltas) {
        const PartitionAccount* account = FindAccountFor(comparison, delta.partitionId);
        if (account == nullptr) {
            return false;  // 每一条结论都必须挂在一份采集账目上
        }
        if (!RowConsistent(delta, *account, removalInferable, additionInferable)) {
            return false;
        }
    }

    bool anyComparablePartition = false;
    bool allPartitionsClean = true;
    for (const PartitionAccount& account : comparison.partitions) {
        // 账目自身：可比较 <=> 两侧都携带观测且实体类型一致。
        const bool bothObserved = StatusCarriesObservation(account.earlierStatus) &&
                                  StatusCarriesObservation(account.laterStatus);
        const bool kindMismatch = HasKey(account.limitationKeys, "snapshot.partition.kindMismatch");
        if (account.comparable != (bothObserved && !kindMismatch)) {
            return false;
        }
        // "有资格支撑确实没有"只能来自完整成功的采集 —— Partial/失败都不行。
        if (account.earlierUsableForAbsence && account.earlierStatus != CollectionStatus::Success) {
            return false;
        }
        if (account.laterUsableForAbsence && account.laterStatus != CollectionStatus::Success) {
            return false;
        }
        if (!account.earlierPresent && account.earlierStatus != CollectionStatus::NotCollected) {
            return false;
        }
        if (!account.laterPresent && account.laterStatus != CollectionStatus::NotCollected) {
            return false;
        }

        std::size_t rowsCompared = 0;
        std::size_t rowsNotComparable = 0;
        bool partitionDifference = false;
        for (const EntityDelta& delta : comparison.deltas) {
            if (delta.partitionId != account.partitionId) {
                continue;
            }
            if (delta.change == EntityChange::NotComparable ||
                delta.change == EntityChange::InsufficientCoverage) {
                ++rowsNotComparable;
            } else {
                ++rowsCompared;
            }
            if (delta.change == EntityChange::Modified || delta.change == EntityChange::Added ||
                delta.change == EntityChange::Removed) {
                partitionDifference = true;
            }
        }
        if (rowsNotComparable != account.entitiesNotComparable) {
            return false;
        }
        if (unchangedRowsPresent && rowsCompared != account.entitiesCompared) {
            return false;
        }
        AnalysisConclusion expected = AnalysisConclusion::NoDifferenceObserved;
        if (!account.comparable) {
            expected = AnalysisConclusion::NoEvidence;
        } else if (partitionDifference) {
            expected = AnalysisConclusion::DifferenceObserved;
        } else if (account.entitiesNotComparable != 0U || !account.earlierUsableForAbsence ||
                   !account.laterUsableForAbsence ||
                   comparison.scope != ScopeComparability::Identical) {
            expected = AnalysisConclusion::Indeterminate;
        }
        if (account.conclusion != expected) {
            return false;
        }
        if (account.comparable) {
            anyComparablePartition = true;
        }
        if (!account.comparable || !account.earlierUsableForAbsence ||
            !account.laterUsableForAbsence) {
            allPartitionsClean = false;
        }
    }

    const bool differenceFound = comparison.addedCount != 0U || comparison.removedCount != 0U ||
                                 comparison.modifiedCount != 0U;
    const bool qualifiesNoDifference =
        anyComparablePartition && !differenceFound && allPartitionsClean &&
        comparison.scope == ScopeComparability::Identical && !machineMismatch &&
        comparison.notComparableCount == 0U && comparison.insufficientCoverageCount == 0U &&
        comparison.partiallyComparableCount == 0U;
    switch (comparison.conclusion) {
    case AnalysisConclusion::NoEvidence:
        return !anyComparablePartition;
    case AnalysisConclusion::DifferenceObserved:
        return anyComparablePartition && differenceFound;
    case AnalysisConclusion::NoDifferenceObserved:
        return qualifiesNoDifference;
    case AnalysisConclusion::Indeterminate:
        return anyComparablePartition && !differenceFound && !qualifiesNoDifference;
    }
    return false;
}

// ---------------------------------------------------------------------------
// D-08：预期变化清单核对
// ---------------------------------------------------------------------------
const char* ExpectationOutcomeName(ExpectationOutcome value) noexcept {
    switch (value) {
    case ExpectationOutcome::NotAssessed: return "NotAssessed";
    case ExpectationOutcome::Satisfied:   return "Satisfied";
    case ExpectationOutcome::Violated:    return "Violated";
    }
    return "NotAssessed";
}

namespace {

// D-08：声明与结果行必须用**同一把键**去配。EntityDelta 强身份时给 identityKey，
// 弱身份时 identityKey 为空、只有 candidateKey；旧实现只比 identityKey，于是任何
// identityKey 为空的声明都会撞上"第一个弱身份对象"，等于核对了一个没指名的对象。
std::string DeltaMatchKey(const EntityDelta& delta) {
    return delta.identityKey.empty() ? delta.candidateKey : delta.identityKey;
}

std::string WantMatchKey(const ExpectedChange& want) {
    return want.identityKey.empty() ? want.candidateKey : want.identityKey;
}

std::string InvalidLabel(const ExpectedChange& want) {
    const std::string key = WantMatchKey(want);
    return want.partitionId + "/" + (key.empty() ? std::string("<no-identity>") : key);
}

} // namespace

ExpectationCheck CheckExpectedChanges(const SnapshotComparison& comparison,
                                      const std::vector<ExpectedChange>& expected) {
    ExpectationCheck check;
    for (const ExpectedChange& want : expected) {
        const std::string wantKey = WantMatchKey(want);
        if (wantKey.empty()) {
            // 没指向任何对象的声明不可核对。D-08 要求"预先列出本次改变的字段及对象
            // 身份"，空身份满足不了这个要求，更不能算成已核对通过。
            check.invalid.push_back(InvalidLabel(want));
            continue;
        }
        const PartitionAccount* account = FindAccountFor(comparison, want.partitionId);
        if (account == nullptr || !account->comparable) {
            // 目标分区根本没比出来：既不能说"观察到了"，也不能说"该变的没变"。
            check.invalid.push_back(InvalidLabel(want));
            continue;
        }
        const EntityDelta* found = nullptr;
        for (const EntityDelta& delta : comparison.deltas) {
            if (delta.partitionId != want.partitionId || DeltaMatchKey(delta) != wantKey) {
                continue;
            }
            found = &delta;
            break;
        }
        if (found == nullptr || found->change != want.change) {
            check.missing.push_back(wantKey);
            continue;
        }
        bool fieldsOk = true;
        for (const std::string& fieldName : want.fieldNames) {
            bool hit = false;
            for (const FieldDelta& field : found->fields) {
                if (field.name == fieldName && field.change == FieldChange::Changed) {
                    hit = true;
                    break;
                }
            }
            if (!hit) {
                fieldsOk = false;
                break;
            }
        }
        if (fieldsOk) {
            check.satisfied.push_back(wantKey);
        } else {
            check.missing.push_back(wantKey);
        }
    }

    for (const EntityDelta& delta : comparison.deltas) {
        if (delta.change != EntityChange::Modified && delta.change != EntityChange::Added &&
            delta.change != EntityChange::Removed) {
            continue;
        }
        const std::string deltaKey = DeltaMatchKey(delta);
        bool declared = false;
        for (const ExpectedChange& want : expected) {
            if (want.partitionId == delta.partitionId && WantMatchKey(want) == deltaKey &&
                !deltaKey.empty()) {
                declared = true;
                break;
            }
        }
        if (!declared) {
            // "其它变化只记录不擅自归因"：这里只列出键，不附加任何解释。
            check.unexpectedKeys.push_back(deltaKey);
        }
    }

    // D-08：三态。"什么都没声明"和"这份比较根本没有证据"都不是通过 —— 旧实现里
    // allSatisfied 对空清单恒真，且从不看比较本身是否有证据，于是零证据也能给绿灯。
    if (expected.empty() || comparison.conclusion == AnalysisConclusion::NoEvidence ||
        !comparison.selfCheckPassed) {
        check.outcome = ExpectationOutcome::NotAssessed;
    } else if (check.missing.empty() && check.invalid.empty() &&
               check.satisfied.size() == expected.size()) {
        check.outcome = ExpectationOutcome::Satisfied;
    } else {
        check.outcome = ExpectationOutcome::Violated;
    }
    check.allSatisfied = check.outcome == ExpectationOutcome::Satisfied;
    return check;
}

// ---------------------------------------------------------------------------
// D-06：持久化
// ---------------------------------------------------------------------------
namespace {

bool ParseCollectionStatusName(std::string_view text, CollectionStatus& out) noexcept {
    if (text == "NotCollected") { out = CollectionStatus::NotCollected; return true; }
    if (text == "Success")      { out = CollectionStatus::Success; return true; }
    if (text == "Partial")      { out = CollectionStatus::Partial; return true; }
    if (text == "Unsupported")  { out = CollectionStatus::Unsupported; return true; }
    if (text == "AccessDenied") { out = CollectionStatus::AccessDenied; return true; }
    if (text == "Timeout")      { out = CollectionStatus::Timeout; return true; }
    if (text == "Error")        { out = CollectionStatus::Error; return true; }
    return false;
}

bool ParseSourceOriginName(std::string_view text, SourceOrigin& out) noexcept {
    if (text == "Unknown")       { out = SourceOrigin::Unknown; return true; }
    if (text == "LiveKernel")    { out = SourceOrigin::LiveKernel; return true; }
    if (text == "LiveUserMode")  { out = SourceOrigin::LiveUserMode; return true; }
    if (text == "ExternalFile")  { out = SourceOrigin::ExternalFile; return true; }
    if (text == "OfflineSample") { out = SourceOrigin::OfflineSample; return true; }
    return false;
}

bool ParseCaptureModeName(std::string_view text, CaptureMode& out) noexcept {
    if (text == "Unknown")   { out = CaptureMode::Unknown; return true; }
    if (text == "Snapshot")  { out = CaptureMode::Snapshot; return true; }
    if (text == "Streaming") { out = CaptureMode::Streaming; return true; }
    if (text == "Replay")    { out = CaptureMode::Replay; return true; }
    return false;
}

bool ParseObjectKindName(std::string_view text, ObjectKind& out) noexcept {
    if (text == "Unknown")    { out = ObjectKind::Unknown; return true; }
    if (text == "Process")    { out = ObjectKind::Process; return true; }
    if (text == "Thread")     { out = ObjectKind::Thread; return true; }
    if (text == "Driver")     { out = ObjectKind::Driver; return true; }
    if (text == "Module")     { out = ObjectKind::Module; return true; }
    if (text == "File")       { out = ObjectKind::File; return true; }
    if (text == "Handle")     { out = ObjectKind::Handle; return true; }
    if (text == "Connection") { out = ObjectKind::Connection; return true; }
    if (text == "Device")     { out = ObjectKind::Device; return true; }
    if (text == "Service")    { out = ObjectKind::Service; return true; }
    return false;
}

bool ParseU64FormatName(std::string_view text, U64Format& out) noexcept {
    if (text == "Decimal")    { out = U64Format::Decimal; return true; }
    if (text == "HexAddress") { out = U64Format::HexAddress; return true; }
    return false;
}

const char* U64FormatName(U64Format value) noexcept {
    return value == U64Format::HexAddress ? "HexAddress" : "Decimal";
}

JsonValue WriteOptional(const OptionalU64& value, U64Format format) {
    return JsonValue::makeOptionalU64Text(value, format);
}

JsonValue WriteEnvelopeJson(const EvidenceEnvelope& envelope) {
    JsonObject source;
    source.emplace_back("collectorId", JsonValue::makeString(envelope.source.collectorId));
    source.emplace_back("collectorVersion",
                        JsonValue::makeU64Text(envelope.source.collectorVersion, U64Format::Decimal));
    source.emplace_back("sourceGroup", JsonValue::makeString(envelope.source.sourceGroup));
    source.emplace_back("origin", JsonValue::makeString(SourceOriginName(envelope.source.origin)));
    source.emplace_back("dependsOn", JsonValue::makeString(envelope.source.dependsOn));

    JsonObject window;
    window.emplace_back("startUtc100ns", WriteOptional(envelope.window.startUtc100ns, U64Format::Decimal));
    window.emplace_back("endUtc100ns", WriteOptional(envelope.window.endUtc100ns, U64Format::Decimal));
    window.emplace_back("startMonotonic", WriteOptional(envelope.window.startMonotonic, U64Format::Decimal));
    window.emplace_back("endMonotonic", WriteOptional(envelope.window.endMonotonic, U64Format::Decimal));
    window.emplace_back("monotonicFrequency",
                        WriteOptional(envelope.window.monotonicFrequency, U64Format::Decimal));
    window.emplace_back("machineId", JsonValue::makeString(envelope.window.machineId));
    window.emplace_back("bootId", JsonValue::makeString(envelope.window.bootId));
    window.emplace_back("sessionId", JsonValue::makeString(envelope.window.sessionId));
    window.emplace_back("mode", JsonValue::makeString(CaptureModeName(envelope.window.mode)));

    JsonObject outcome;
    outcome.emplace_back("status", JsonValue::makeString(CollectionStatusName(envelope.outcome.status)));
    outcome.emplace_back("nativeCode", WriteOptional(envelope.outcome.nativeCode, U64Format::Decimal));
    outcome.emplace_back("nativeCodeDomain", JsonValue::makeString(envelope.outcome.nativeCodeDomain));
    outcome.emplace_back("message", JsonValue::makeString(envelope.outcome.message));

    const CoverageAccount& coverage = envelope.coverage;
    JsonObject cov;
    cov.emplace_back("requestedBegin", WriteOptional(coverage.requestedBegin, U64Format::Decimal));
    cov.emplace_back("requestedEnd", WriteOptional(coverage.requestedEnd, U64Format::Decimal));
    cov.emplace_back("processedBegin", WriteOptional(coverage.processedBegin, U64Format::Decimal));
    cov.emplace_back("processedEnd", WriteOptional(coverage.processedEnd, U64Format::Decimal));
    cov.emplace_back("succeeded", JsonValue::makeU64Text(coverage.succeeded, U64Format::Decimal));
    cov.emplace_back("failed", JsonValue::makeU64Text(coverage.failed, U64Format::Decimal));
    cov.emplace_back("skipped", JsonValue::makeU64Text(coverage.skipped, U64Format::Decimal));
    cov.emplace_back("truncated", JsonValue::makeU64Text(coverage.truncated, U64Format::Decimal));
    cov.emplace_back("limitHit", JsonValue::makeBool(coverage.limitHit));
    cov.emplace_back("limit", WriteOptional(coverage.limit, U64Format::Decimal));
    cov.emplace_back("cancelled", JsonValue::makeBool(coverage.cancelled));
    cov.emplace_back("totalKnown", WriteOptional(coverage.totalKnown, U64Format::Decimal));

    JsonObject root;
    root.emplace_back("source", JsonValue::makeObject(std::move(source)));
    root.emplace_back("window", JsonValue::makeObject(std::move(window)));
    root.emplace_back("outcome", JsonValue::makeObject(std::move(outcome)));
    root.emplace_back("coverage", JsonValue::makeObject(std::move(cov)));
    root.emplace_back("evidenceId", JsonValue::makeString(envelope.evidenceId));
    return JsonValue::makeObject(std::move(root));
}

JsonValue WriteDriverIdentity(const DriverInstanceId& id) {
    JsonObject obj;
    obj.emplace_back("bootId", JsonValue::makeString(id.bootId));
    obj.emplace_back("imagePath", JsonValue::makeString(id.imagePath));
    obj.emplace_back("imageBase", WriteOptional(id.imageBase, U64Format::HexAddress));
    obj.emplace_back("imageSize", WriteOptional(id.imageSize, U64Format::Decimal));
    obj.emplace_back("timeDateStamp", WriteOptional(id.timeDateStamp, U64Format::Decimal));
    obj.emplace_back("checksum", WriteOptional(id.checksum, U64Format::Decimal));
    obj.emplace_back("pdbSignature", JsonValue::makeString(id.pdbSignature));
    obj.emplace_back("loadOrderIndex", WriteOptional(id.loadOrderIndex, U64Format::Decimal));
    return JsonValue::makeObject(std::move(obj));
}

JsonValue WriteProcessIdentity(const ProcessInstanceId& id) {
    JsonObject obj;
    obj.emplace_back("bootId", JsonValue::makeString(id.bootId));
    obj.emplace_back("pid", WriteOptional(id.pid, U64Format::Decimal));
    obj.emplace_back("createTime100ns", WriteOptional(id.createTime100ns, U64Format::Decimal));
    obj.emplace_back("eprocessAddress", WriteOptional(id.eprocessAddress, U64Format::HexAddress));
    obj.emplace_back("imageName", JsonValue::makeString(id.imageName));
    return JsonValue::makeObject(std::move(obj));
}

JsonValue WriteThreadIdentity(const ThreadInstanceId& id) {
    JsonObject obj;
    obj.emplace_back("process", WriteProcessIdentity(id.process));
    obj.emplace_back("tid", WriteOptional(id.tid, U64Format::Decimal));
    obj.emplace_back("createTime100ns", WriteOptional(id.createTime100ns, U64Format::Decimal));
    obj.emplace_back("ethreadAddress", WriteOptional(id.ethreadAddress, U64Format::HexAddress));
    return JsonValue::makeObject(std::move(obj));
}

JsonValue WriteFileIdentityJson(const FileIdentity& id) {
    JsonObject obj;
    obj.emplace_back("path", JsonValue::makeString(id.path));
    obj.emplace_back("volumeSerial", WriteOptional(id.volumeSerial, U64Format::Decimal));
    obj.emplace_back("fileId", JsonValue::makeString(id.fileId));
    obj.emplace_back("sizeBytes", WriteOptional(id.sizeBytes, U64Format::Decimal));
    obj.emplace_back("lastWriteUtc100ns", WriteOptional(id.lastWriteUtc100ns, U64Format::Decimal));
    obj.emplace_back("contentHash", JsonValue::makeString(id.contentHash));
    return JsonValue::makeObject(std::move(obj));
}

JsonValue WriteLogicalIdentity(const LogicalObjectId& id) {
    JsonObject obj;
    obj.emplace_back("domain", JsonValue::makeString(id.domain));
    obj.emplace_back("name", JsonValue::makeString(id.name));
    obj.emplace_back("scopeKey", JsonValue::makeString(id.scopeKey));
    return JsonValue::makeObject(std::move(obj));
}

// ---- 读取上下文 ----
struct ReadCtx final {
    SnapshotLoadStatus status = SnapshotLoadStatus::Ok;
    std::string detail;
    std::vector<std::string> unknownPaths;

    bool fail(SnapshotLoadStatus s, std::string d) {
        if (status == SnapshotLoadStatus::Ok) {
            status = s;
            detail = std::move(d);
        }
        return false;
    }
    bool ok() const noexcept { return status == SnapshotLoadStatus::Ok; }
};

void CollectUnknown(const JsonObject& obj,
                    const std::vector<std::string>& known,
                    const std::string& path,
                    JsonObject* sink,
                    ReadCtx& ctx) {
    for (const auto& member : obj) {
        if (std::find(known.begin(), known.end(), member.first) != known.end()) {
            continue;
        }
        ctx.unknownPaths.push_back(path + "." + member.first);
        if (sink != nullptr) {
            sink->emplace_back(member.first, member.second);
        }
    }
}

bool ReadString(const JsonValue& obj, const char* name, std::string& out, ReadCtx& ctx,
                bool required, const std::string& path) {
    const JsonValue* value = obj.find(name);
    if (value == nullptr || value->isNull()) {
        if (required) {
            return ctx.fail(SnapshotLoadStatus::MissingRequiredField, path + "." + name);
        }
        return true;
    }
    if (!value->tryGetString(out)) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path + "." + name);
    }
    return true;
}

bool ReadOptU64(const JsonValue& obj, const char* name, OptionalU64& out, ReadCtx& ctx,
                const std::string& path) {
    const JsonValue* value = obj.find(name);
    if (value == nullptr) {
        return true;  // 旧版 fixture 可以整条缺席 —— 缺席就是"未知"
    }
    if (!value->tryGetOptionalU64(out)) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path + "." + name);
    }
    return true;
}

bool ReadU64(const JsonValue& obj, const char* name, std::uint64_t& out, ReadCtx& ctx,
             const std::string& path) {
    const JsonValue* value = obj.find(name);
    if (value == nullptr || value->isNull()) {
        return true;
    }
    if (!value->tryGetU64(out)) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path + "." + name);
    }
    return true;
}

bool ReadBool(const JsonValue& obj, const char* name, bool& out, ReadCtx& ctx,
              const std::string& path) {
    const JsonValue* value = obj.find(name);
    if (value == nullptr || value->isNull()) {
        return true;
    }
    if (!value->tryGetBool(out)) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path + "." + name);
    }
    return true;
}

// 枚举一律"未知名字 = 明确失败"，绝不静默回落到默认枚举值。
template <typename Enum, typename Parser>
bool ReadEnum(const JsonValue& obj, const char* name, Enum& out, Parser parser, ReadCtx& ctx,
              const std::string& path) {
    const JsonValue* value = obj.find(name);
    if (value == nullptr || value->isNull()) {
        return true;
    }
    std::string text;
    if (!value->tryGetString(text)) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path + "." + name);
    }
    if (!parser(text, out)) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path + "." + name + "=" + text);
    }
    return true;
}

bool ReadEnvelopeJson(const JsonValue& node, EvidenceEnvelope& envelope, ReadCtx& ctx,
                      const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path);
    }
    if (const JsonValue* source = node.find("source"); source != nullptr) {
        if (source->asObject() == nullptr) {
            return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path + ".source");
        }
        std::uint64_t version = 0;
        if (!ReadString(*source, "collectorId", envelope.source.collectorId, ctx, false, path) ||
            !ReadU64(*source, "collectorVersion", version, ctx, path) ||
            !ReadString(*source, "sourceGroup", envelope.source.sourceGroup, ctx, false, path) ||
            !ReadEnum(*source, "origin", envelope.source.origin, ParseSourceOriginName, ctx, path) ||
            !ReadString(*source, "dependsOn", envelope.source.dependsOn, ctx, false, path)) {
            return false;
        }
        if (version > 0xFFFFFFFFULL) {
            return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path + ".source.collectorVersion");
        }
        envelope.source.collectorVersion = static_cast<std::uint32_t>(version);
    }
    if (const JsonValue* window = node.find("window"); window != nullptr) {
        if (window->asObject() == nullptr) {
            return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path + ".window");
        }
        CaptureWindow& w = envelope.window;
        if (!ReadOptU64(*window, "startUtc100ns", w.startUtc100ns, ctx, path) ||
            !ReadOptU64(*window, "endUtc100ns", w.endUtc100ns, ctx, path) ||
            !ReadOptU64(*window, "startMonotonic", w.startMonotonic, ctx, path) ||
            !ReadOptU64(*window, "endMonotonic", w.endMonotonic, ctx, path) ||
            !ReadOptU64(*window, "monotonicFrequency", w.monotonicFrequency, ctx, path) ||
            !ReadString(*window, "machineId", w.machineId, ctx, false, path) ||
            !ReadString(*window, "bootId", w.bootId, ctx, false, path) ||
            !ReadString(*window, "sessionId", w.sessionId, ctx, false, path) ||
            !ReadEnum(*window, "mode", w.mode, ParseCaptureModeName, ctx, path)) {
            return false;
        }
    }
    if (const JsonValue* outcome = node.find("outcome"); outcome != nullptr) {
        if (outcome->asObject() == nullptr) {
            return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path + ".outcome");
        }
        CollectionOutcome& o = envelope.outcome;
        if (!ReadEnum(*outcome, "status", o.status, ParseCollectionStatusName, ctx, path) ||
            !ReadOptU64(*outcome, "nativeCode", o.nativeCode, ctx, path) ||
            !ReadString(*outcome, "nativeCodeDomain", o.nativeCodeDomain, ctx, false, path) ||
            !ReadString(*outcome, "message", o.message, ctx, false, path)) {
            return false;
        }
    }
    if (const JsonValue* cov = node.find("coverage"); cov != nullptr) {
        if (cov->asObject() == nullptr) {
            return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path + ".coverage");
        }
        CoverageAccount& c = envelope.coverage;
        if (!ReadOptU64(*cov, "requestedBegin", c.requestedBegin, ctx, path) ||
            !ReadOptU64(*cov, "requestedEnd", c.requestedEnd, ctx, path) ||
            !ReadOptU64(*cov, "processedBegin", c.processedBegin, ctx, path) ||
            !ReadOptU64(*cov, "processedEnd", c.processedEnd, ctx, path) ||
            !ReadU64(*cov, "succeeded", c.succeeded, ctx, path) ||
            !ReadU64(*cov, "failed", c.failed, ctx, path) ||
            !ReadU64(*cov, "skipped", c.skipped, ctx, path) ||
            !ReadU64(*cov, "truncated", c.truncated, ctx, path) ||
            !ReadBool(*cov, "limitHit", c.limitHit, ctx, path) ||
            !ReadOptU64(*cov, "limit", c.limit, ctx, path) ||
            !ReadBool(*cov, "cancelled", c.cancelled, ctx, path) ||
            !ReadOptU64(*cov, "totalKnown", c.totalKnown, ctx, path)) {
            return false;
        }
    }
    return ReadString(node, "evidenceId", envelope.evidenceId, ctx, false, path);
}

bool ReadDriverIdentity(const JsonValue& node, DriverInstanceId& id, ReadCtx& ctx,
                        const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path);
    }
    return ReadString(node, "bootId", id.bootId, ctx, false, path) &&
           ReadString(node, "imagePath", id.imagePath, ctx, false, path) &&
           ReadOptU64(node, "imageBase", id.imageBase, ctx, path) &&
           ReadOptU64(node, "imageSize", id.imageSize, ctx, path) &&
           ReadOptU64(node, "timeDateStamp", id.timeDateStamp, ctx, path) &&
           ReadOptU64(node, "checksum", id.checksum, ctx, path) &&
           ReadString(node, "pdbSignature", id.pdbSignature, ctx, false, path) &&
           ReadOptU64(node, "loadOrderIndex", id.loadOrderIndex, ctx, path);
}

bool ReadProcessIdentity(const JsonValue& node, ProcessInstanceId& id, ReadCtx& ctx,
                         const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path);
    }
    return ReadString(node, "bootId", id.bootId, ctx, false, path) &&
           ReadOptU64(node, "pid", id.pid, ctx, path) &&
           ReadOptU64(node, "createTime100ns", id.createTime100ns, ctx, path) &&
           ReadOptU64(node, "eprocessAddress", id.eprocessAddress, ctx, path) &&
           ReadString(node, "imageName", id.imageName, ctx, false, path);
}

bool ReadThreadIdentity(const JsonValue& node, ThreadInstanceId& id, ReadCtx& ctx,
                        const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path);
    }
    if (const JsonValue* process = node.find("process"); process != nullptr) {
        if (!ReadProcessIdentity(*process, id.process, ctx, path + ".process")) {
            return false;
        }
    }
    return ReadOptU64(node, "tid", id.tid, ctx, path) &&
           ReadOptU64(node, "createTime100ns", id.createTime100ns, ctx, path) &&
           ReadOptU64(node, "ethreadAddress", id.ethreadAddress, ctx, path);
}

bool ReadFileIdentityJson(const JsonValue& node, FileIdentity& id, ReadCtx& ctx,
                          const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path);
    }
    return ReadString(node, "path", id.path, ctx, false, path) &&
           ReadOptU64(node, "volumeSerial", id.volumeSerial, ctx, path) &&
           ReadString(node, "fileId", id.fileId, ctx, false, path) &&
           ReadOptU64(node, "sizeBytes", id.sizeBytes, ctx, path) &&
           ReadOptU64(node, "lastWriteUtc100ns", id.lastWriteUtc100ns, ctx, path) &&
           ReadString(node, "contentHash", id.contentHash, ctx, false, path);
}

bool ReadLogicalIdentity(const JsonValue& node, LogicalObjectId& id, ReadCtx& ctx,
                         const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::InvalidFieldValue, path);
    }
    return ReadString(node, "domain", id.domain, ctx, false, path) &&
           ReadString(node, "name", id.name, ctx, false, path) &&
           ReadString(node, "scopeKey", id.scopeKey, ctx, false, path);
}

const std::vector<std::string>& RootKnownKeys() {
    static const std::vector<std::string> keys = {
        "schema", "versionMajor", "versionMinor", "snapshotId",
        "envelope", "scope", "partitions", "modules", "entities"};
    return keys;
}

const std::vector<std::string>& EntityKnownKeys() {
    static const std::vector<std::string> keys = {
        "partitionId", "kind", "rawRecordId", "displayOrder",
        "process", "thread", "driver", "file", "logical", "fields"};
    return keys;
}

} // namespace

std::string WriteSnapshotJson(const Snapshot& snapshot, unsigned indent) {
    JsonObject root;
    root.emplace_back("schema", JsonValue::makeString(kSnapshotSchemaId));
    root.emplace_back("versionMajor", JsonValue::makeU64Text(kSnapshotSchemaMajor, U64Format::Decimal));
    root.emplace_back("versionMinor", JsonValue::makeU64Text(kSnapshotSchemaMinor, U64Format::Decimal));
    root.emplace_back("snapshotId", JsonValue::makeString(snapshot.snapshotId));
    root.emplace_back("envelope", WriteEnvelopeJson(snapshot.envelope));

    JsonObject scope;
    scope.emplace_back("scopeId", JsonValue::makeString(snapshot.scope.scopeId));
    scope.emplace_back("declared", JsonValue::makeBool(snapshot.scope.declared));
    scope.emplace_back("wholeDomain", JsonValue::makeBool(snapshot.scope.wholeDomain));
    JsonArray selectors;
    for (const std::string& selector : snapshot.scope.selectors) {
        selectors.push_back(JsonValue::makeString(selector));
    }
    scope.emplace_back("selectors", JsonValue::makeArray(std::move(selectors)));
    root.emplace_back("scope", JsonValue::makeObject(std::move(scope)));

    JsonArray partitions;
    for (const SnapshotPartition& partition : snapshot.partitions) {
        JsonObject obj;
        obj.emplace_back("partitionId", JsonValue::makeString(partition.partitionId));
        obj.emplace_back("kind", JsonValue::makeString(ObjectKindName(partition.kind)));
        obj.emplace_back("coversScope", JsonValue::makeBool(partition.coversScope));
        obj.emplace_back("envelope", WriteEnvelopeJson(partition.envelope));
        partitions.push_back(JsonValue::makeObject(std::move(obj)));
    }
    root.emplace_back("partitions", JsonValue::makeArray(std::move(partitions)));

    JsonArray modules;
    for (const SnapshotModule& module : snapshot.modules) {
        JsonObject obj;
        obj.emplace_back("moduleId", JsonValue::makeString(module.moduleId));
        obj.emplace_back("imageBase", WriteOptional(module.imageBase, U64Format::HexAddress));
        obj.emplace_back("imageSize", WriteOptional(module.imageSize, U64Format::Decimal));
        obj.emplace_back("identity", WriteDriverIdentity(module.identity));
        modules.push_back(JsonValue::makeObject(std::move(obj)));
    }
    root.emplace_back("modules", JsonValue::makeArray(std::move(modules)));

    JsonArray entities;
    for (const SnapshotEntity& entity : snapshot.entities) {
        JsonObject obj;
        obj.emplace_back("partitionId", JsonValue::makeString(entity.partitionId));
        obj.emplace_back("kind", JsonValue::makeString(ObjectKindName(entity.kind)));
        obj.emplace_back("rawRecordId", JsonValue::makeString(entity.rawRecordId));
        obj.emplace_back("displayOrder",
                         JsonValue::makeU64Text(static_cast<std::uint64_t>(entity.displayOrder),
                                                U64Format::Decimal));
        obj.emplace_back("process", WriteProcessIdentity(entity.process));
        obj.emplace_back("thread", WriteThreadIdentity(entity.thread));
        obj.emplace_back("driver", WriteDriverIdentity(entity.driver));
        obj.emplace_back("file", WriteFileIdentityJson(entity.file));
        obj.emplace_back("logical", WriteLogicalIdentity(entity.logical));

        JsonArray fields;
        for (const EntityField& field : entity.fields) {
            JsonObject item;
            item.emplace_back("name", JsonValue::makeString(field.name));
            item.emplace_back("semantics", JsonValue::makeString(FieldSemanticsName(field.semantics)));
            item.emplace_back("kind", JsonValue::makeString(FieldValueKindName(field.kind)));
            item.emplace_back("text", JsonValue::makeString(field.text));
            item.emplace_back("number", WriteOptional(field.number, field.numberFormat));
            item.emplace_back("numberFormat", JsonValue::makeString(U64FormatName(field.numberFormat)));
            item.emplace_back("redaction", JsonValue::makeString(RedactionClassName(field.redaction)));
            fields.push_back(JsonValue::makeObject(std::move(item)));
        }
        obj.emplace_back("fields", JsonValue::makeArray(std::move(fields)));

        // D-06：读进来时保留的未知可选字段原样写回，保存不会静默丢掉别人的扩展。
        for (const auto& unknown : entity.unknownFields) {
            obj.emplace_back(unknown.first, unknown.second);
        }
        entities.push_back(JsonValue::makeObject(std::move(obj)));
    }
    root.emplace_back("entities", JsonValue::makeArray(std::move(entities)));

    for (const auto& unknown : snapshot.unknownFields) {
        root.emplace_back(unknown.first, unknown.second);
    }
    return WriteJson(JsonValue::makeObject(std::move(root)), indent);
}

SnapshotLoadResult ReadSnapshotJson(std::string_view text) {
    return ReadSnapshotJson(text, SnapshotJsonLimits());
}

SnapshotLoadResult ReadSnapshotJson(std::string_view text, const JsonLimits& limits) {
    SnapshotLoadResult result;
    if (text.empty()) {
        result.status = SnapshotLoadStatus::EmptyInput;
        result.errorDetail = "empty";
        return result;
    }
    const JsonParseResult parsed = ParseJson(text, limits);
    if (!parsed.ok()) {
        // D-06：超出解析上限的**合法**文档与损坏文档必须是两种状态。塌成
        // MalformedJson 会让"这份快照太大，抬高上限"和"这份文件坏了"在 UI 上
        // 长得一模一样。
        switch (parsed.status) {
        case JsonParseStatus::SizeLimit:
        case JsonParseStatus::NodeLimit:
        case JsonParseStatus::DepthLimit:
            result.status = SnapshotLoadStatus::LimitExceeded;
            break;
        default:
            result.status = SnapshotLoadStatus::MalformedJson;
            break;
        }
        result.errorDetail = JsonParseStatusName(parsed.status);  // 原始错误码，不美化
        result.errorOffset = parsed.errorOffset;
        return result;
    }
    const JsonValue& root = parsed.value;
    if (root.asObject() == nullptr) {
        result.status = SnapshotLoadStatus::MalformedJson;
        result.errorDetail = "root is not an object";
        return result;
    }

    const JsonValue* schema = root.find("schema");
    std::string schemaText;
    if (schema == nullptr || !schema->tryGetString(schemaText)) {
        result.status = SnapshotLoadStatus::MissingSchema;
        result.errorDetail = "schema";
        return result;
    }
    if (schemaText != kSnapshotSchemaId) {
        result.status = SnapshotLoadStatus::WrongSchemaId;
        result.errorDetail = schemaText;
        return result;
    }
    const JsonValue* majorNode = root.find("versionMajor");
    std::uint64_t major = 0;
    if (majorNode == nullptr || !majorNode->tryGetU64(major)) {
        result.status = SnapshotLoadStatus::MissingSchema;
        result.errorDetail = "versionMajor";
        return result;
    }
    std::uint64_t minor = 0;
    if (const JsonValue* minorNode = root.find("versionMinor"); minorNode != nullptr) {
        if (!minorNode->tryGetU64(minor)) {
            result.status = SnapshotLoadStatus::InvalidFieldValue;
            result.errorDetail = "versionMinor";
            return result;
        }
    }
    result.versionMajor = static_cast<std::uint32_t>(major & 0xFFFFFFFFULL);
    result.versionMinor = static_cast<std::uint32_t>(minor & 0xFFFFFFFFULL);
    if (major != kSnapshotSchemaMajor) {
        // D-06：未知主版本明确拒绝 —— 不做"尽力而为"的部分解析。
        result.status = SnapshotLoadStatus::UnsupportedMajorVersion;
        result.errorDetail = FormatU64(major, U64Format::Decimal);
        return result;
    }

    ReadCtx ctx;
    Snapshot snapshot;
    CollectUnknown(*root.asObject(), RootKnownKeys(), "root", &snapshot.unknownFields, ctx);

    if (!ReadString(root, "snapshotId", snapshot.snapshotId, ctx, false, "root")) {
        result.status = ctx.status;
        result.errorDetail = ctx.detail;
        return result;
    }
    if (const JsonValue* envelope = root.find("envelope"); envelope != nullptr) {
        if (!ReadEnvelopeJson(*envelope, snapshot.envelope, ctx, "root.envelope")) {
            result.status = ctx.status;
            result.errorDetail = ctx.detail;
            return result;
        }
    }
    if (const JsonValue* scope = root.find("scope"); scope != nullptr) {
        if (scope->asObject() == nullptr) {
            result.status = SnapshotLoadStatus::InvalidFieldValue;
            result.errorDetail = "root.scope";
            return result;
        }
        if (!ReadString(*scope, "scopeId", snapshot.scope.scopeId, ctx, false, "root.scope") ||
            !ReadBool(*scope, "declared", snapshot.scope.declared, ctx, "root.scope") ||
            !ReadBool(*scope, "wholeDomain", snapshot.scope.wholeDomain, ctx, "root.scope")) {
            result.status = ctx.status;
            result.errorDetail = ctx.detail;
            return result;
        }
        if (const JsonValue* selectors = scope->find("selectors"); selectors != nullptr) {
            const JsonArray* array = selectors->asArray();
            if (array == nullptr) {
                result.status = SnapshotLoadStatus::InvalidFieldValue;
                result.errorDetail = "root.scope.selectors";
                return result;
            }
            for (const JsonValue& item : *array) {
                std::string selector;
                if (!item.tryGetString(selector)) {
                    result.status = SnapshotLoadStatus::InvalidFieldValue;
                    result.errorDetail = "root.scope.selectors[]";
                    return result;
                }
                snapshot.scope.selectors.push_back(std::move(selector));
            }
        }
    }
    if (const JsonValue* partitions = root.find("partitions"); partitions != nullptr) {
        const JsonArray* array = partitions->asArray();
        if (array == nullptr) {
            result.status = SnapshotLoadStatus::InvalidFieldValue;
            result.errorDetail = "root.partitions";
            return result;
        }
        for (const JsonValue& item : *array) {
            SnapshotPartition partition;
            if (item.asObject() == nullptr) {
                result.status = SnapshotLoadStatus::InvalidFieldValue;
                result.errorDetail = "root.partitions[]";
                return result;
            }
            if (!ReadString(item, "partitionId", partition.partitionId, ctx, true, "root.partitions[]") ||
                !ReadEnum(item, "kind", partition.kind, ParseObjectKindName, ctx, "root.partitions[]") ||
                !ReadBool(item, "coversScope", partition.coversScope, ctx, "root.partitions[]")) {
                result.status = ctx.status;
                result.errorDetail = ctx.detail;
                return result;
            }
            if (const JsonValue* envelope = item.find("envelope"); envelope != nullptr) {
                if (!ReadEnvelopeJson(*envelope, partition.envelope, ctx, "root.partitions[].envelope")) {
                    result.status = ctx.status;
                    result.errorDetail = ctx.detail;
                    return result;
                }
            }
            snapshot.partitions.push_back(std::move(partition));
        }
    }
    if (const JsonValue* modules = root.find("modules"); modules != nullptr) {
        const JsonArray* array = modules->asArray();
        if (array == nullptr) {
            result.status = SnapshotLoadStatus::InvalidFieldValue;
            result.errorDetail = "root.modules";
            return result;
        }
        for (const JsonValue& item : *array) {
            SnapshotModule module;
            if (item.asObject() == nullptr) {
                result.status = SnapshotLoadStatus::InvalidFieldValue;
                result.errorDetail = "root.modules[]";
                return result;
            }
            if (!ReadString(item, "moduleId", module.moduleId, ctx, true, "root.modules[]") ||
                !ReadOptU64(item, "imageBase", module.imageBase, ctx, "root.modules[]") ||
                !ReadOptU64(item, "imageSize", module.imageSize, ctx, "root.modules[]")) {
                result.status = ctx.status;
                result.errorDetail = ctx.detail;
                return result;
            }
            if (const JsonValue* identity = item.find("identity"); identity != nullptr) {
                if (!ReadDriverIdentity(*identity, module.identity, ctx, "root.modules[].identity")) {
                    result.status = ctx.status;
                    result.errorDetail = ctx.detail;
                    return result;
                }
            }
            snapshot.modules.push_back(std::move(module));
        }
    }
    if (const JsonValue* entities = root.find("entities"); entities != nullptr) {
        const JsonArray* array = entities->asArray();
        if (array == nullptr) {
            result.status = SnapshotLoadStatus::InvalidFieldValue;
            result.errorDetail = "root.entities";
            return result;
        }
        for (const JsonValue& item : *array) {
            const JsonObject* obj = item.asObject();
            if (obj == nullptr) {
                result.status = SnapshotLoadStatus::InvalidFieldValue;
                result.errorDetail = "root.entities[]";
                return result;
            }
            SnapshotEntity entity;
            CollectUnknown(*obj, EntityKnownKeys(), "root.entities[]", &entity.unknownFields, ctx);
            std::uint64_t order = 0;
            if (!ReadString(item, "partitionId", entity.partitionId, ctx, true, "root.entities[]") ||
                !ReadEnum(item, "kind", entity.kind, ParseObjectKindName, ctx, "root.entities[]") ||
                !ReadString(item, "rawRecordId", entity.rawRecordId, ctx, false, "root.entities[]") ||
                !ReadU64(item, "displayOrder", order, ctx, "root.entities[]")) {
                result.status = ctx.status;
                result.errorDetail = ctx.detail;
                return result;
            }
            entity.displayOrder = static_cast<std::size_t>(order);
            bool identityOk = true;
            if (const JsonValue* node = item.find("process"); node != nullptr) {
                identityOk = ReadProcessIdentity(*node, entity.process, ctx, "root.entities[].process");
            }
            if (identityOk) {
                if (const JsonValue* node = item.find("thread"); node != nullptr) {
                    identityOk = ReadThreadIdentity(*node, entity.thread, ctx, "root.entities[].thread");
                }
            }
            if (identityOk) {
                if (const JsonValue* node = item.find("driver"); node != nullptr) {
                    identityOk = ReadDriverIdentity(*node, entity.driver, ctx, "root.entities[].driver");
                }
            }
            if (identityOk) {
                if (const JsonValue* node = item.find("file"); node != nullptr) {
                    identityOk = ReadFileIdentityJson(*node, entity.file, ctx, "root.entities[].file");
                }
            }
            if (identityOk) {
                if (const JsonValue* node = item.find("logical"); node != nullptr) {
                    identityOk = ReadLogicalIdentity(*node, entity.logical, ctx, "root.entities[].logical");
                }
            }
            if (!identityOk) {
                result.status = ctx.status;
                result.errorDetail = ctx.detail;
                return result;
            }
            if (const JsonValue* fields = item.find("fields"); fields != nullptr) {
                const JsonArray* fieldArray = fields->asArray();
                if (fieldArray == nullptr) {
                    result.status = SnapshotLoadStatus::InvalidFieldValue;
                    result.errorDetail = "root.entities[].fields";
                    return result;
                }
                for (const JsonValue& fieldItem : *fieldArray) {
                    if (fieldItem.asObject() == nullptr) {
                        result.status = SnapshotLoadStatus::InvalidFieldValue;
                        result.errorDetail = "root.entities[].fields[]";
                        return result;
                    }
                    EntityField field;
                    if (!ReadString(fieldItem, "name", field.name, ctx, true, "root.entities[].fields[]") ||
                        !ReadEnum(fieldItem, "semantics", field.semantics, ParseFieldSemanticsName, ctx,
                                  "root.entities[].fields[]") ||
                        !ReadEnum(fieldItem, "kind", field.kind, ParseFieldValueKindName, ctx,
                                  "root.entities[].fields[]") ||
                        !ReadString(fieldItem, "text", field.text, ctx, false, "root.entities[].fields[]") ||
                        !ReadOptU64(fieldItem, "number", field.number, ctx, "root.entities[].fields[]") ||
                        !ReadEnum(fieldItem, "numberFormat", field.numberFormat, ParseU64FormatName, ctx,
                                  "root.entities[].fields[]") ||
                        !ReadEnum(fieldItem, "redaction", field.redaction, ParseRedactionClassName, ctx,
                                  "root.entities[].fields[]")) {
                        result.status = ctx.status;
                        result.errorDetail = ctx.detail;
                        return result;
                    }
                    entity.fields.push_back(std::move(field));
                }
            }
            snapshot.entities.push_back(std::move(entity));
        }
    }

    if (!ctx.ok()) {
        result.status = ctx.status;
        result.errorDetail = ctx.detail;
        return result;
    }
    result.unknownFieldPaths = ctx.unknownPaths;
    result.status = ctx.unknownPaths.empty() ? SnapshotLoadStatus::Ok
                                             : SnapshotLoadStatus::OkWithUnknownFields;
    result.snapshot = std::move(snapshot);
    return result;
}

// ---------------------------------------------------------------------------
// D-07：脱敏
// ---------------------------------------------------------------------------
namespace {

bool IsWordChar(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

std::string MapKey(RedactionClass cls, std::string_view original) {
    std::string key(1, static_cast<char>('0' + static_cast<int>(cls)));
    key.push_back(kSep);
    key.append(FoldText(original));
    return key;
}

// 从路径里取出紧跟 marker 的那一段。marker 已折叠成小写反斜杠形式。
void CollectSegmentAfter(const std::string& folded, const std::string& raw, const char* marker,
                         std::vector<std::string>& out) {
    const std::string needle(marker);
    std::size_t pos = 0;
    while ((pos = folded.find(needle, pos)) != std::string::npos) {
        const std::size_t begin = pos + needle.size();
        std::size_t end = folded.find('\\', begin);
        if (end == std::string::npos) {
            end = folded.size();
        }
        if (end > begin) {
            out.push_back(raw.substr(begin, end - begin));
        }
        pos = begin;
    }
}

void CollectUncHost(const std::string& folded, const std::string& raw,
                    std::vector<std::string>& out) {
    if (folded.size() < 3U || folded[0] != '\\' || folded[1] != '\\') {
        return;
    }
    std::size_t end = folded.find('\\', 2U);
    if (end == std::string::npos) {
        end = folded.size();
    }
    if (end > 2U) {
        out.push_back(raw.substr(2U, end - 2U));
    }
}

// D-06 保留下来的未知可选字段是任意厂商 JSON。脱敏必须能走进去（D-07：敏感原值
// 不得藏在原始字段里），因此这里提供一个受深度限制的遍历/重写对。
inline constexpr std::size_t kUnknownFieldMaxDepth = 64;

template <typename Fn>
void ForEachJsonString(const JsonValue& value, std::size_t depth, Fn&& fn) {
    if (depth > kUnknownFieldMaxDepth) {
        return;
    }
    if (const JsonObject* object = value.asObject(); object != nullptr) {
        for (const auto& member : *object) {
            fn(member.first);  // 键名本身也可能带用户名
            ForEachJsonString(member.second, depth + 1U, fn);
        }
        return;
    }
    if (const JsonArray* array = value.asArray(); array != nullptr) {
        for (const JsonValue& item : *array) {
            ForEachJsonString(item, depth + 1U, fn);
        }
        return;
    }
    if (value.type() == JsonType::String) {
        std::string text;
        if (value.tryGetString(text)) {
            fn(text);
        }
    }
}

void CollectSids(const std::string& raw, std::vector<std::string>& out) {
    const std::string folded = FoldText(raw);
    std::size_t pos = 0;
    while ((pos = folded.find("s-1-", pos)) != std::string::npos) {
        if (pos != 0U && IsWordChar(raw[pos - 1U])) {
            ++pos;
            continue;
        }
        std::size_t end = pos;
        while (end < raw.size() && ((raw[end] >= '0' && raw[end] <= '9') || raw[end] == '-' ||
                                    raw[end] == 'S' || raw[end] == 's')) {
            ++end;
        }
        while (end > pos && raw[end - 1U] == '-') {
            --end;  // 不把尾随的分隔符吞进 SID
        }
        if (end - pos > 4U) {
            out.push_back(raw.substr(pos, end - pos));
        }
        pos = end;
    }
}

} // namespace

std::string RedactionSession::assign(RedactionClass cls, const std::string& original) {
    if (original.empty()) {
        return std::string();
    }
    const std::string key = MapKey(cls, original);
    const auto it = map_.find(key);
    if (it != map_.end()) {
        return it->second;
    }
    std::string replacement;
    switch (cls) {
    case RedactionClass::UserName:
        ++userCount_;
        replacement = "<user-" + FormatU64(static_cast<std::uint64_t>(userCount_), U64Format::Decimal) + ">";
        break;
    case RedactionClass::Hostname:
        ++hostCount_;
        replacement = "<host-" + FormatU64(static_cast<std::uint64_t>(hostCount_), U64Format::Decimal) + ">";
        break;
    case RedactionClass::AccountSid:
        ++sidCount_;
        replacement = "<sid-" + FormatU64(static_cast<std::uint64_t>(sidCount_), U64Format::Decimal) + ">";
        break;
    case RedactionClass::None:
    case RedactionClass::FilePath:
        return std::string();  // 路径本身不整体替换 —— 替换掉它里面的用户/主机段即可
    }
    map_.emplace(key, replacement);
    RedactionMapping mapping;
    mapping.cls = cls;
    mapping.original = original;
    mapping.replacement = replacement;
    report_.mappings.push_back(std::move(mapping));
    return replacement;
}

std::string RedactionSession::replacementFor(RedactionClass cls, std::string_view original) const {
    const auto it = map_.find(MapKey(cls, original));
    return it == map_.end() ? std::string() : it->second;
}

void RedactionSession::learn(const Snapshot& source) {
    std::vector<std::string> users;
    std::vector<std::string> hosts;
    std::vector<std::string> sids;

    auto scanPath = [&](const std::string& value) {
        if (value.empty()) {
            return;
        }
        const std::string folded = FoldPath(value);
        const std::string raw = value;
        CollectSegmentAfter(folded, raw, "\\users\\", users);
        CollectSegmentAfter(folded, raw, "\\home\\", users);
        CollectSegmentAfter(folded, raw, "\\documents and settings\\", users);
        CollectUncHost(folded, raw, hosts);
        CollectSids(raw, sids);
    };

    // D-07：未知可选字段里的路径/SID 同样要参与学习。只在导出时替换而不学习，
    // 会出现"只在厂商扩展里露过面的用户名"整段漏网。
    auto scanUnknown = [&](const JsonObject& unknown) {
        for (const auto& member : unknown) {
            scanPath(member.first);
            ForEachJsonString(member.second, 0U, [&](const std::string& text) { scanPath(text); });
        }
    };

    scanPath(source.envelope.outcome.message);
    scanPath(source.envelope.source.dependsOn);
    if (!source.envelope.window.machineId.empty()) {
        hosts.push_back(source.envelope.window.machineId);
    }
    scanUnknown(source.unknownFields);
    for (const std::string& selector : source.scope.selectors) {
        scanPath(selector);
    }
    for (const SnapshotPartition& partition : source.partitions) {
        scanPath(partition.envelope.outcome.message);
        scanPath(partition.envelope.source.dependsOn);
        if (!partition.envelope.window.machineId.empty()) {
            hosts.push_back(partition.envelope.window.machineId);
        }
    }
    for (const SnapshotModule& module : source.modules) {
        scanPath(module.identity.imagePath);
    }
    for (const SnapshotEntity& entity : source.entities) {
        scanPath(entity.process.imageName);
        scanPath(entity.driver.imagePath);
        scanPath(entity.file.path);
        scanPath(entity.logical.name);
        scanPath(entity.logical.scopeKey);
        scanPath(entity.rawRecordId);
        scanUnknown(entity.unknownFields);
        for (const EntityField& field : entity.fields) {
            scanPath(field.text);
            switch (field.redaction) {
            case RedactionClass::UserName:
                if (!field.text.empty()) {
                    users.push_back(field.text);
                }
                break;
            case RedactionClass::Hostname:
                if (!field.text.empty()) {
                    hosts.push_back(field.text);
                }
                break;
            case RedactionClass::AccountSid:
                if (!field.text.empty()) {
                    sids.push_back(field.text);
                }
                break;
            case RedactionClass::FilePath:
            case RedactionClass::None:
                break;
            }
        }
    }

    if (options_.redactUserNames) {
        for (const std::string& user : users) {
            assign(RedactionClass::UserName, user);
        }
    }
    if (options_.redactHostnames) {
        for (const std::string& host : hosts) {
            assign(RedactionClass::Hostname, host);
        }
    }
    if (options_.redactSids) {
        for (const std::string& sid : sids) {
            assign(RedactionClass::AccountSid, sid);
        }
    }
}

void RedactionSession::redact(const Snapshot& source, Snapshot& out) {
    // 先学习：free-text 字段里可能出现只在别处路径里露过面的用户名。
    learn(source);
    out = source;  // 源快照是 const 输入，改的永远是副本

    // 长的原值优先匹配，避免短名字先把长名字啃掉一半。
    struct Needle final {
        std::string folded;
        const RedactionMapping* mapping = nullptr;
    };
    std::vector<Needle> needles;
    needles.reserve(report_.mappings.size());
    for (const RedactionMapping& mapping : report_.mappings) {
        if (!mapping.original.empty()) {
            needles.push_back(Needle{FoldText(mapping.original), &mapping});
        }
    }
    std::sort(needles.begin(), needles.end(), [](const Needle& a, const Needle& b) {
        if (a.folded.size() != b.folded.size()) {
            return a.folded.size() > b.folded.size();
        }
        return a.folded < b.folded;
    });

    // 7.3 / D-07 性能：朴素实现在每个词边界上把**全部**占位名试一遍，代价是
    // 文本长度 × 占位名数量；而占位名是从数据里自动收割的（每个 Users\ 段、每个
    // UNC 主机、每段 S-1-…），会随快照一起增长，于是 L1 规模下一次导出要十几秒。
    // 这里按折叠后的首字符分桶：每个位置只试首字符对得上的候选，桶内仍保持
    // 长度降序，"最长匹配优先"的语义不变。
    std::array<std::vector<const Needle*>, 256> byFirstChar{};
    std::array<bool, 256> firstCharPresent{};
    firstCharPresent.fill(false);
    for (const Needle& needle : needles) {
        const auto first = static_cast<unsigned char>(needle.folded[0]);
        byFirstChar[first].push_back(&needle);
        firstCharPresent[first] = true;
    }

    std::size_t replacements = 0;
    std::size_t comparisons = 0;
    // 从左到右扫一遍，命中就直接输出占位符并跳过原值 —— 已经写出的占位符不再被
    // 重新扫描。否则一个名叫 "user" 的账户会把 "<user-1>" 再吃一次，套成嵌套。
    // 返回替换次数；调用方决定要不要把它计入报告（探测键名时不计）。
    auto scrubValue = [&](std::string& value) -> std::size_t {
        if (value.empty() || needles.empty()) {
            return 0U;
        }
        bool anyCandidate = false;
        for (const char raw : value) {
            if (firstCharPresent[static_cast<unsigned char>(FoldAscii(raw))]) {
                anyCandidate = true;
                break;
            }
        }
        if (!anyCandidate) {
            return 0U;  // 一个候选的首字符都没出现：整串直接放过，不折叠也不逐位试
        }
        const std::string folded = FoldText(value);
        std::string rewritten;
        rewritten.reserve(value.size());
        std::size_t index = 0;
        std::size_t hits = 0;
        while (index < value.size()) {
            bool matched = false;
            const bool leftOk = index == 0U || !IsWordChar(value[index - 1U]);
            if (leftOk) {
                const std::vector<const Needle*>& bucket =
                    byFirstChar[static_cast<unsigned char>(folded[index])];
                for (const Needle* needle : bucket) {
                    ++comparisons;
                    if (index + needle->folded.size() > value.size()) {
                        continue;
                    }
                    if (folded.compare(index, needle->folded.size(), needle->folded) != 0) {
                        continue;
                    }
                    const std::size_t after = index + needle->folded.size();
                    if (after < value.size() && IsWordChar(value[after])) {
                        continue;  // 词边界不成立：alice 不该在 aliceworks 里被替换
                    }
                    rewritten.append(needle->mapping->replacement);
                    index = after;
                    matched = true;
                    ++hits;
                    break;
                }
            }
            if (!matched) {
                rewritten.push_back(value[index]);
                ++index;
            }
        }
        if (hits != 0U) {
            value = rewritten;
        }
        return hits;
    };

    auto scrub = [&](std::string& value, const std::string& path) {
        const std::size_t hits = scrubValue(value);
        if (hits != 0U) {
            replacements += hits;
            report_.replacedFieldPaths.push_back(path);
        }
    };

    // 7.3：本地可中断工作必须有取消点。取消时不交付半脱敏的快照 —— 那比不脱敏
    // 更危险（看着像已处理，实际还带着原值）。
    bool cancelled = false;
    auto checkCancel = [&]() -> bool {
        if (cancelled) {
            return true;
        }
        if (cancel_ && cancel_()) {
            cancelled = true;
        }
        return cancelled;
    };

    // D-07：未知可选字段（D-06 承诺原样回写的那些）同样要脱敏。厂商扩展里塞着
    // 完整用户路径是常态，原样导出等于把敏感原值藏进"原始字段"。
    // 键名命中时不改名（改名会撞键、也会破坏调用方的扩展语义），整条成员删除并
    // 登记进 removedFieldPaths —— 声明删除，而不是悄悄漏出去。
    std::function<bool(const JsonValue&, const std::string&, std::size_t, JsonValue&)> scrubJson =
        [&](const JsonValue& in, const std::string& path, std::size_t depth,
            JsonValue& outValue) -> bool {
        if (depth > kUnknownFieldMaxDepth) {
            return false;  // 深到扫不动的子树一律删除并声明，不放行
        }
        if (const JsonObject* object = in.asObject(); object != nullptr) {
            JsonObject rebuilt;
            for (const auto& member : *object) {
                std::string probe = member.first;
                const std::string childPath = path + "." + member.first;
                if (scrubValue(probe) != 0U) {
                    // 键名本身带敏感原值：删除声明里写**替换后**的键名，否则这份
                    // "被删除清单"自己就把原值抄了出去。
                    report_.removedFieldPaths.push_back(path + "." + probe);
                    continue;
                }
                JsonValue child;
                if (!scrubJson(member.second, childPath, depth + 1U, child)) {
                    report_.removedFieldPaths.push_back(childPath);
                    continue;
                }
                rebuilt.emplace_back(member.first, std::move(child));
            }
            outValue = JsonValue::makeObject(std::move(rebuilt));
            return true;
        }
        if (const JsonArray* array = in.asArray(); array != nullptr) {
            JsonArray rebuilt;
            for (std::size_t i = 0; i < array->size(); ++i) {
                const std::string childPath =
                    path + "[" + FormatU64(static_cast<std::uint64_t>(i), U64Format::Decimal) + "]";
                JsonValue child;
                if (!scrubJson((*array)[i], childPath, depth + 1U, child)) {
                    report_.removedFieldPaths.push_back(childPath);
                    continue;
                }
                rebuilt.push_back(std::move(child));
            }
            outValue = JsonValue::makeArray(std::move(rebuilt));
            return true;
        }
        if (in.type() == JsonType::String) {
            std::string text;
            if (!in.tryGetString(text)) {
                return false;
            }
            scrub(text, path);
            outValue = JsonValue::makeString(std::move(text));
            return true;
        }
        outValue = in;  // 数字/布尔/null 不承载文本
        return true;
    };

    auto scrubUnknown = [&](JsonObject& unknown, const std::string& base) {
        JsonObject rebuilt;
        for (const auto& member : unknown) {
            std::string probe = member.first;
            const std::string path = base + "." + member.first;
            if (scrubValue(probe) != 0U) {
                report_.removedFieldPaths.push_back(base + "." + probe);
                continue;
            }
            JsonValue child;
            if (!scrubJson(member.second, path, 1U, child)) {
                report_.removedFieldPaths.push_back(path);
                continue;
            }
            rebuilt.emplace_back(member.first, std::move(child));
        }
        unknown = std::move(rebuilt);
    };

    scrub(out.snapshotId, "snapshotId");
    scrub(out.envelope.window.machineId, "envelope.window.machineId");
    scrub(out.envelope.source.dependsOn, "envelope.source.dependsOn");
    scrub(out.envelope.evidenceId, "envelope.evidenceId");
    if (options_.dropCollectorMessages) {
        if (!out.envelope.outcome.message.empty()) {
            out.envelope.outcome.message.clear();
            report_.removedFieldPaths.push_back("envelope.outcome.message");
        }
    } else {
        scrub(out.envelope.outcome.message, "envelope.outcome.message");
    }
    for (std::size_t i = 0; i < out.scope.selectors.size(); ++i) {
        scrub(out.scope.selectors[i],
              "scope.selectors[" + FormatU64(static_cast<std::uint64_t>(i), U64Format::Decimal) + "]");
    }
    scrubUnknown(out.unknownFields, "unknownFields");
    for (std::size_t i = 0; i < out.partitions.size(); ++i) {
        if (checkCancel()) {
            break;
        }
        const std::string base =
            "partitions[" + FormatU64(static_cast<std::uint64_t>(i), U64Format::Decimal) + "]";
        SnapshotPartition& partition = out.partitions[i];
        scrub(partition.envelope.window.machineId, base + ".envelope.window.machineId");
        scrub(partition.envelope.source.dependsOn, base + ".envelope.source.dependsOn");
        scrub(partition.envelope.evidenceId, base + ".envelope.evidenceId");
        if (options_.dropCollectorMessages) {
            if (!partition.envelope.outcome.message.empty()) {
                partition.envelope.outcome.message.clear();
                report_.removedFieldPaths.push_back(base + ".envelope.outcome.message");
            }
        } else {
            scrub(partition.envelope.outcome.message, base + ".envelope.outcome.message");
        }
    }
    for (std::size_t i = 0; i < out.modules.size(); ++i) {
        const std::string base =
            "modules[" + FormatU64(static_cast<std::uint64_t>(i), U64Format::Decimal) + "]";
        scrub(out.modules[i].identity.imagePath, base + ".identity.imagePath");
    }
    for (std::size_t i = 0; i < out.entities.size(); ++i) {
        if (checkCancel()) {
            break;
        }
        const std::string base =
            "entities[" + FormatU64(static_cast<std::uint64_t>(i), U64Format::Decimal) + "]";
        SnapshotEntity& entity = out.entities[i];
        scrub(entity.process.imageName, base + ".process.imageName");
        scrub(entity.thread.process.imageName, base + ".thread.process.imageName");
        scrub(entity.driver.imagePath, base + ".driver.imagePath");
        scrub(entity.file.path, base + ".file.path");
        scrub(entity.logical.name, base + ".logical.name");
        scrub(entity.logical.scopeKey, base + ".logical.scopeKey");
        scrub(entity.rawRecordId, base + ".rawRecordId");
        for (std::size_t f = 0; f < entity.fields.size(); ++f) {
            scrub(entity.fields[f].text,
                  base + ".fields[" + FormatU64(static_cast<std::uint64_t>(f), U64Format::Decimal) +
                      "].text");
        }
        scrubUnknown(entity.unknownFields, base + ".unknownFields");
    }
    report_.replacementCount += replacements;
    report_.needleComparisons += comparisons;
    if (cancelled) {
        // 取消：不交付部分结果。报告保留已经做过的记录，并明写 cancelled。
        out = Snapshot{};
        report_.cancelled = true;
    }
}

void RedactSnapshot(const Snapshot& source,
                    const RedactionOptions& options,
                    Snapshot& out,
                    RedactionReport& report) {
    RedactionSession session(options);
    session.redact(source, out);
    report = session.report();
}

} // namespace Ksword::Evidence
