#include "ObjectIdentity.h"

namespace Ksword::Evidence {
namespace {

// 主键分隔符不会出现在路径、GUID 或数字里，避免 "a|b" 与 "a" + "|b" 撞键。
constexpr char kSep = '\x1F';

void AppendField(std::string& key, const std::string& value) {
    key.push_back(kSep);
    key.append(value);
}

void AppendField(std::string& key, const OptionalU64& value, U64Format format) {
    key.push_back(kSep);
    if (value.present) {
        key.append(FormatU64(value.value, format));
    }
}

// 两个可选值的三态比较：都在且相等 -> Equal；都在且不等 -> Differ；任一缺失 -> Missing。
enum class FieldCompare { Equal, Differ, Missing };

FieldCompare Compare(const OptionalU64& a, const OptionalU64& b) noexcept {
    if (!a.present || !b.present) {
        return FieldCompare::Missing;
    }
    return a.value == b.value ? FieldCompare::Equal : FieldCompare::Differ;
}

FieldCompare Compare(const std::string& a, const std::string& b) noexcept {
    if (a.empty() || b.empty()) {
        return FieldCompare::Missing;
    }
    return a == b ? FieldCompare::Equal : FieldCompare::Differ;
}

// 启动周期：两边都有且不同 -> 不是同一个实例。有一边缺失只能降级为不确定。
FieldCompare CompareBoot(const std::string& a, const std::string& b) noexcept {
    return Compare(a, b);
}

// F-03 统一身份门槛：任一侧连弱主键都构不成时，最强只能是 Candidate。
//
// 为什么必须统一加：strength() 与 crossSessionKey() 已经在说"身份不足、不给主键"，
// 匹配器却可能因为几个次要字段恰好相等而回 Confirmed（例如两个 imagePath/pdb 全空、
// 只剩 timeDateStamp+imageSize 的模块记录）。那不仅自相矛盾，还会出现单调性倒置：
// 补上不同的路径（信息变多）反而从 Confirmed 掉到 NoMatch。矛盾证据仍可判 NoMatch，
// 这里只封"确认"这一档。
MatchResult CapByStrength(MatchResult result, IdentityStrength a, IdentityStrength b) noexcept {
    if (result != MatchResult::Confirmed) {
        return result;
    }
    if (a == IdentityStrength::Unusable || b == IdentityStrength::Unusable) {
        return MatchResult::Candidate;
    }
    return result;
}

// 路径归一化：只做大小写折叠与分隔符统一，不解析符号链接（那需要现场访问）。
// 用于文件"内容+路径"主键，保证 "C:\\A\\B.sys" 与 "c:/a/b.sys" 不被当成两个对象。
std::string NormalizePath(const std::string& path) {
    std::string out;
    out.reserve(path.size());
    for (const char raw : path) {
        char c = raw;
        if (c == '/') {
            c = '\\';
        } else if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
        out.push_back(c);
    }
    return out;
}

MatchResult MatchProcessInstanceCore(const ProcessInstanceId& a, const ProcessInstanceId& b) noexcept;
MatchResult MatchThreadInstanceCore(const ThreadInstanceId& a, const ThreadInstanceId& b) noexcept;
MatchResult MatchDriverInstanceCore(const DriverInstanceId& a, const DriverInstanceId& b) noexcept;
MatchResult MatchFileIdentityCore(const FileIdentity& a, const FileIdentity& b) noexcept;
MatchResult MatchHandleIdentityCore(const HandleIdentity& a, const HandleIdentity& b) noexcept;
MatchResult MatchConnectionIdentityCore(const ConnectionIdentity& a, const ConnectionIdentity& b) noexcept;

} // namespace

const char* ObjectKindName(ObjectKind kind) noexcept {
    switch (kind) {
    case ObjectKind::Unknown:    return "Unknown";
    case ObjectKind::Process:    return "Process";
    case ObjectKind::Thread:     return "Thread";
    case ObjectKind::Driver:     return "Driver";
    case ObjectKind::Module:     return "Module";
    case ObjectKind::File:       return "File";
    case ObjectKind::Handle:     return "Handle";
    case ObjectKind::Connection: return "Connection";
    case ObjectKind::Device:     return "Device";
    case ObjectKind::Service:    return "Service";
    }
    return "Unknown";
}

const char* MatchResultName(MatchResult result) noexcept {
    switch (result) {
    case MatchResult::NoMatch:   return "NoMatch";
    case MatchResult::Candidate: return "Candidate";
    case MatchResult::Confirmed: return "Confirmed";
    }
    return "Candidate";
}

const char* IdentityStrengthName(IdentityStrength strength) noexcept {
    switch (strength) {
    case IdentityStrength::Unusable: return "Unusable";
    case IdentityStrength::Weak:     return "Weak";
    case IdentityStrength::Strong:   return "Strong";
    }
    return "Unusable";
}

// ---------------------------------------------------------------------------
// 进程
// ---------------------------------------------------------------------------
IdentityStrength ProcessInstanceId::strength() const noexcept {
    if (!pid.present) {
        return IdentityStrength::Unusable;
    }
    if (createTime100ns.present && !bootId.empty()) {
        return IdentityStrength::Strong;
    }
    return IdentityStrength::Weak;
}

std::string ProcessInstanceId::crossSessionKey() const {
    if (strength() != IdentityStrength::Strong) {
        return std::string();  // F-03：身份不足不给跨会话主键
    }
    std::string key("proc");
    AppendField(key, bootId);
    AppendField(key, pid, U64Format::Decimal);
    AppendField(key, createTime100ns, U64Format::Decimal);
    return key;
}

MatchResult MatchProcessInstance(const ProcessInstanceId& a, const ProcessInstanceId& b) noexcept {
    return CapByStrength(MatchProcessInstanceCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult MatchProcessInstanceCore(const ProcessInstanceId& a, const ProcessInstanceId& b) noexcept {
    if (Compare(a.pid, b.pid) == FieldCompare::Differ) {
        return MatchResult::NoMatch;
    }
    if (CompareBoot(a.bootId, b.bootId) == FieldCompare::Differ) {
        return MatchResult::NoMatch;  // 不同启动周期的同 PID 一定不是同一实例
    }
    switch (Compare(a.createTime100ns, b.createTime100ns)) {
    case FieldCompare::Differ:
        return MatchResult::NoMatch;  // PID 复用：创建时间不同即不同实例
    case FieldCompare::Equal:
        // 创建时间一致，还需要 PID 在场才谈得上确认。
        if (Compare(a.pid, b.pid) == FieldCompare::Equal && !a.bootId.empty() && !b.bootId.empty()) {
            return MatchResult::Confirmed;
        }
        return MatchResult::Candidate;
    case FieldCompare::Missing:
        break;
    }
    // 创建时间缺失：地址只能当本次辅助证据，不足以确认。
    return MatchResult::Candidate;
}

} // namespace

// ---------------------------------------------------------------------------
// 线程
// ---------------------------------------------------------------------------
IdentityStrength ThreadInstanceId::strength() const noexcept {
    if (!tid.present) {
        return IdentityStrength::Unusable;
    }
    if (process.strength() == IdentityStrength::Strong && createTime100ns.present) {
        return IdentityStrength::Strong;
    }
    return IdentityStrength::Weak;
}

std::string ThreadInstanceId::crossSessionKey() const {
    if (strength() != IdentityStrength::Strong) {
        return std::string();
    }
    std::string key("thread");
    AppendField(key, process.crossSessionKey());
    AppendField(key, tid, U64Format::Decimal);
    AppendField(key, createTime100ns, U64Format::Decimal);
    return key;
}

MatchResult MatchThreadInstance(const ThreadInstanceId& a, const ThreadInstanceId& b) noexcept {
    return CapByStrength(MatchThreadInstanceCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult MatchThreadInstanceCore(const ThreadInstanceId& a, const ThreadInstanceId& b) noexcept {
    if (Compare(a.tid, b.tid) == FieldCompare::Differ) {
        return MatchResult::NoMatch;
    }
    const MatchResult owner = MatchProcessInstance(a.process, b.process);
    if (owner == MatchResult::NoMatch) {
        // X-03：残缺所属信息不会挂到同 PID 的新进程。
        return MatchResult::NoMatch;
    }
    switch (Compare(a.createTime100ns, b.createTime100ns)) {
    case FieldCompare::Differ:
        return MatchResult::NoMatch;  // TID 复用
    case FieldCompare::Equal:
        return owner == MatchResult::Confirmed ? MatchResult::Confirmed : MatchResult::Candidate;
    case FieldCompare::Missing:
        break;
    }
    return MatchResult::Candidate;
}

} // namespace

// ---------------------------------------------------------------------------
// 驱动
// ---------------------------------------------------------------------------
IdentityStrength DriverInstanceId::strength() const noexcept {
    if (imagePath.empty() && pdbSignature.empty()) {
        return IdentityStrength::Unusable;
    }
    if (!pdbSignature.empty()) {
        return IdentityStrength::Strong;
    }
    if (timeDateStamp.present && imageSize.present) {
        return IdentityStrength::Strong;
    }
    return IdentityStrength::Weak;
}

std::string DriverInstanceId::crossSessionKey() const {
    if (strength() != IdentityStrength::Strong) {
        return std::string();
    }
    std::string key("driver");
    AppendField(key, imagePath);
    AppendField(key, pdbSignature);
    AppendField(key, timeDateStamp, U64Format::Decimal);
    AppendField(key, imageSize, U64Format::Decimal);
    return key;
}

MatchResult MatchDriverInstance(const DriverInstanceId& a, const DriverInstanceId& b) noexcept {
    return CapByStrength(MatchDriverInstanceCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult MatchDriverInstanceCore(const DriverInstanceId& a, const DriverInstanceId& b) noexcept {
    // I-01：磁盘同名文件不自动视为加载时的对应版本。
    const FieldCompare pdb = Compare(a.pdbSignature, b.pdbSignature);
    if (pdb == FieldCompare::Differ) {
        return MatchResult::NoMatch;
    }
    const FieldCompare stamp = Compare(a.timeDateStamp, b.timeDateStamp);
    const FieldCompare size = Compare(a.imageSize, b.imageSize);
    if (stamp == FieldCompare::Differ || size == FieldCompare::Differ) {
        return MatchResult::NoMatch;
    }
    const FieldCompare path = Compare(a.imagePath, b.imagePath);
    if (path == FieldCompare::Differ) {
        // 路径不同但映像身份一致仍可能是同一份文件的两处副本 —— 保留候选。
        // 注意这里也覆盖 stamp+size 一致的情形：否则"弱证据(stamp+size)得 NoMatch、
        // 强证据(pdb)得 Candidate"又是一次结论强度倒置。
        if (pdb == FieldCompare::Equal || (stamp == FieldCompare::Equal && size == FieldCompare::Equal)) {
            return MatchResult::Candidate;
        }
        return MatchResult::NoMatch;
    }
    if (pdb == FieldCompare::Equal) {
        return MatchResult::Confirmed;  // RSDS GUID+Age 是最强的映像身份
    }
    // F-03：timeDateStamp+imageSize 是弱得多的组合（同一次编译的任何副本都相同，
    // 且 R0 枚举拿不到路径时它们是唯一剩下的字段）。只有两侧 imagePath 都在场并
    // 相等，才谈得上"同一个加载实例"；路径缺失一律停在 Candidate。
    if (stamp == FieldCompare::Equal && size == FieldCompare::Equal && path == FieldCompare::Equal) {
        return MatchResult::Confirmed;
    }
    return MatchResult::Candidate;
}

} // namespace

// ---------------------------------------------------------------------------
// 文件
// ---------------------------------------------------------------------------
IdentityStrength FileIdentity::strength() const noexcept {
    if (path.empty() && fileId.empty() && contentHash.empty()) {
        return IdentityStrength::Unusable;
    }
    if (!fileId.empty() && volumeSerial.present) {
        return IdentityStrength::Strong;  // (卷序列号, FileId) 才是文件对象身份
    }
    // F-03：内容哈希单独不构成文件对象身份 —— 同一串字节可以同时躺在
    // System32 和用户目录下。只有"内容 + 路径"一起才够做跨会话主键。
    if (!contentHash.empty() && !path.empty()) {
        return IdentityStrength::Strong;
    }
    return IdentityStrength::Weak;
}

std::string FileIdentity::crossSessionKey() const {
    // 对象身份键：硬链接的多条路径共享同一个 (volumeSerial, fileId)，因此有它时
    // 不掺路径，键才在同一个文件对象的不同路径之间保持一致。
    if (!fileId.empty() && volumeSerial.present) {
        std::string key("file");
        AppendField(key, volumeSerial, U64Format::Decimal);
        AppendField(key, fileId);
        return key;
    }
    // 内容键：前缀与对象身份键区分开，并且必须带上归一化路径 —— 否则正版驱动与
    // 被投放到别处的同字节副本会共用一个主键（F-03）。
    if (!contentHash.empty() && !path.empty()) {
        std::string key("file-content");
        AppendField(key, contentHash);
        AppendField(key, NormalizePath(path));
        return key;
    }
    return std::string();  // 身份不足不给跨会话主键
}

MatchResult MatchFileIdentity(const FileIdentity& a, const FileIdentity& b) noexcept {
    return CapByStrength(MatchFileIdentityCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult MatchFileIdentityCore(const FileIdentity& a, const FileIdentity& b) noexcept {
    const FieldCompare hash = Compare(a.contentHash, b.contentHash);
    if (hash == FieldCompare::Differ) {
        return MatchResult::NoMatch;
    }
    const FieldCompare volume = Compare(a.volumeSerial, b.volumeSerial);
    const FieldCompare id = Compare(a.fileId, b.fileId);
    if (volume == FieldCompare::Differ || id == FieldCompare::Differ) {
        return MatchResult::NoMatch;  // 同路径不同文件
    }
    // 只有 (卷序列号, FileId) 才是文件对象身份。它相等就是同一个文件对象，
    // 哪怕两条路径不同（硬链接）。
    if (volume == FieldCompare::Equal && id == FieldCompare::Equal) {
        return MatchResult::Confirmed;
    }
    // F-03：路径判据必须排在内容哈希前面。内容一致 ≠ 同一个文件对象：
    // System32 下的正版驱动和被投放到用户目录的同字节副本内容哈希完全相同，
    // 早先的实现在这里直接凭 hash 给 Confirmed，下面那条"路径不同即 NoMatch"
    // 永远够不着，两个文件于是共用一个身份。
    if (Compare(a.path, b.path) == FieldCompare::Differ) {
        return (hash == FieldCompare::Equal) ? MatchResult::Candidate : MatchResult::NoMatch;
    }
    // 内容一致但 (volume,fileId) 拿不到：说明不了这是同一个文件对象，停在候选。
    return MatchResult::Candidate;
}

} // namespace

// ---------------------------------------------------------------------------
// 句柄
// ---------------------------------------------------------------------------
IdentityStrength HandleIdentity::strength() const noexcept {
    if (!handleValue.present) {
        return IdentityStrength::Unusable;
    }
    if (owner.strength() == IdentityStrength::Strong) {
        return IdentityStrength::Strong;
    }
    return IdentityStrength::Weak;
}

std::string HandleIdentity::crossSessionKey() const {
    if (strength() != IdentityStrength::Strong) {
        return std::string();
    }
    std::string key("handle");
    AppendField(key, owner.crossSessionKey());
    AppendField(key, handleValue, U64Format::HexAddress);
    return key;
}

MatchResult MatchHandleIdentity(const HandleIdentity& a, const HandleIdentity& b) noexcept {
    return CapByStrength(MatchHandleIdentityCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult MatchHandleIdentityCore(const HandleIdentity& a, const HandleIdentity& b) noexcept {
    if (Compare(a.handleValue, b.handleValue) == FieldCompare::Differ) {
        return MatchResult::NoMatch;
    }
    const MatchResult owner = MatchProcessInstance(a.owner, b.owner);
    if (owner == MatchResult::NoMatch) {
        return MatchResult::NoMatch;
    }
    if (Compare(a.typeName, b.typeName) == FieldCompare::Differ) {
        return MatchResult::NoMatch;
    }
    // 句柄值会被回收：即使 owner 已确认，也只有对象地址一致才谈得上同一对象。
    if (owner == MatchResult::Confirmed && Compare(a.objectAddress, b.objectAddress) == FieldCompare::Equal) {
        return MatchResult::Confirmed;
    }
    return MatchResult::Candidate;
}

} // namespace

// ---------------------------------------------------------------------------
// 连接
// ---------------------------------------------------------------------------
IdentityStrength ConnectionIdentity::strength() const noexcept {
    if (localAddress.empty() || protocol == 0U) {
        return IdentityStrength::Unusable;
    }
    if (observedFirstUtc100ns.present && !bootId.empty()) {
        return IdentityStrength::Strong;
    }
    return IdentityStrength::Weak;
}

std::string ConnectionIdentity::fiveTupleKey() const {
    std::string key("conn5");
    AppendField(key, FormatU64(protocol, U64Format::Decimal));
    AppendField(key, localAddress);
    AppendField(key, FormatU64(localPort, U64Format::Decimal));
    AppendField(key, remoteAddress);
    AppendField(key, FormatU64(remotePort, U64Format::Decimal));
    return key;
}

std::string ConnectionIdentity::crossSessionKey() const {
    if (strength() != IdentityStrength::Strong) {
        return std::string();
    }
    std::string key = fiveTupleKey();
    AppendField(key, bootId);
    AppendField(key, observedFirstUtc100ns, U64Format::Decimal);
    return key;
}

MatchResult MatchConnectionIdentity(const ConnectionIdentity& a, const ConnectionIdentity& b) noexcept {
    return CapByStrength(MatchConnectionIdentityCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult MatchConnectionIdentityCore(const ConnectionIdentity& a, const ConnectionIdentity& b) noexcept {
    if (a.fiveTupleKey() != b.fiveTupleKey()) {
        return MatchResult::NoMatch;
    }
    const FieldCompare boot = CompareBoot(a.bootId, b.bootId);
    if (boot == FieldCompare::Differ) {
        return MatchResult::NoMatch;
    }
    // 相同五元组不同时段是不同连接：观察区间不相交即判 NoMatch。
    if (a.observedFirstUtc100ns.present && a.observedLastUtc100ns.present &&
        b.observedFirstUtc100ns.present && b.observedLastUtc100ns.present) {
        const bool disjoint = a.observedLastUtc100ns.value < b.observedFirstUtc100ns.value ||
                              b.observedLastUtc100ns.value < a.observedFirstUtc100ns.value;
        if (disjoint) {
            return MatchResult::NoMatch;
        }
        const MatchResult owner = MatchProcessInstance(a.owner, b.owner);
        if (owner == MatchResult::NoMatch) {
            return MatchResult::NoMatch;
        }
        // F-03：跨启动保护需要正面证据。两侧 bootId 都为空时 Compare() 返回的是
        // Missing 而不是 Differ，早先的实现就这样跳过了整条保护 —— 两台机器/两次
        // 启动的同一个五元组会被判成同一条连接。
        if (boot != FieldCompare::Equal) {
            return MatchResult::Candidate;
        }
        // 五元组会被复用（同一个端口在同一次启动里也会被下一个进程重新绑上），
        // 所属进程完全未知时最多只能是候选。
        if (owner != MatchResult::Confirmed) {
            return MatchResult::Candidate;
        }
        return MatchResult::Confirmed;
    }
    return MatchResult::Candidate;
}

} // namespace

// ---------------------------------------------------------------------------
// 通用引用
// ---------------------------------------------------------------------------
namespace {

ObjectRef MakeRef(ObjectKind kind,
                  std::string key,
                  IdentityStrength strength,
                  std::string display,
                  std::string evidenceId) {
    ObjectRef ref;
    ref.kind = kind;
    ref.key = std::move(key);
    ref.strength = strength;
    ref.displayText = std::move(display);
    ref.evidenceId = std::move(evidenceId);
    return ref;
}

} // namespace

ObjectRef MakeProcessRef(const ProcessInstanceId& id, std::string evidenceId) {
    std::string display = id.imageName;
    if (id.pid.present) {
        display += " (" + FormatU64(id.pid.value, U64Format::Decimal) + ")";
    }
    return MakeRef(ObjectKind::Process, id.crossSessionKey(), id.strength(), std::move(display),
                   std::move(evidenceId));
}

ObjectRef MakeThreadRef(const ThreadInstanceId& id, std::string evidenceId) {
    std::string display = "TID " + FormatOptionalU64(id.tid, U64Format::Decimal);
    return MakeRef(ObjectKind::Thread, id.crossSessionKey(), id.strength(), std::move(display),
                   std::move(evidenceId));
}

ObjectRef MakeDriverRef(const DriverInstanceId& id, std::string evidenceId) {
    return MakeRef(ObjectKind::Driver, id.crossSessionKey(), id.strength(), id.imagePath,
                   std::move(evidenceId));
}

ObjectRef MakeFileRef(const FileIdentity& id, std::string evidenceId) {
    return MakeRef(ObjectKind::File, id.crossSessionKey(), id.strength(), id.path,
                   std::move(evidenceId));
}

ObjectRef MakeHandleRef(const HandleIdentity& id, std::string evidenceId) {
    std::string display = id.typeName + " " + FormatOptionalU64(id.handleValue, U64Format::HexAddress);
    return MakeRef(ObjectKind::Handle, id.crossSessionKey(), id.strength(), std::move(display),
                   std::move(evidenceId));
}

ObjectRef MakeConnectionRef(const ConnectionIdentity& id, std::string evidenceId) {
    std::string display = id.localAddress + ":" + FormatU64(id.localPort, U64Format::Decimal) + " -> " +
                          id.remoteAddress + ":" + FormatU64(id.remotePort, U64Format::Decimal);
    return MakeRef(ObjectKind::Connection, id.crossSessionKey(), id.strength(), std::move(display),
                   std::move(evidenceId));
}

} // namespace Ksword::Evidence
