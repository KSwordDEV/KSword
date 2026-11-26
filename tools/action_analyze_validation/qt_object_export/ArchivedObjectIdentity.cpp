#include "ArchivedObjectIdentity.h"

#include "../../../shared/evidence/EvidenceJson.h"

#include <algorithm>
#include <charconv>
#include <initializer_list>
#include <limits>
#include <string_view>

namespace ks::action_analyze
{
namespace
{
    namespace json = Ksword::Evidence;
    constexpr qsizetype kMaxBytes = 4 * 1024 * 1024; // A0 小文档上限。

    struct ObservationRef
    {
        QUuid sampleId; // 同一采样中的对象引用。
        quint64 objectId = 0; // 非零采样本地编号。
    };

    struct Observation
    {
        ArchivedObjectKind kind = ArchivedObjectKind::Process; // 已解析的对象类别。
        ObservationRef ref; // 自身引用。
        ObservationRef owner; // 线程的所属进程引用，缺失时 ID 为零。
        bool strong = false; // 正文字段的强身份声明。
        QString machine; // 进程所属机器。
        QString boot; // 进程所属启动代次。
        quint32 nativeId = 0; // 分别为 PID 或 TID。
        quint64 creation = 0; // 创建 FILETIME，可包含 A0 已知零值。
    };

    // 验证值为闭合集合中的对象，各必填字段随后按类型读取。
    bool ClosedObject(const json::JsonValue& value, std::initializer_list<std::string_view> allowed)
    {
        const auto* fields = value.asObject(); // 共享解析器已拒绝重名键。
        return fields && std::all_of(fields->begin(), fields->end(), [allowed](const auto& field) {
            return std::find(allowed.begin(), allowed.end(), field.first) != allowed.end();
        });
    }

    // 读取非空字符串，字段可选时仅接受真实缺失。
    bool Text(const json::JsonValue* value, std::string& out, bool required = true)
    {
        return value ? value->tryGetString(out) && !out.empty() : !required;
    }

    // 读取严格小写 UUID。sourceEpoch 可以保留格式合法的全零 UUID。
    bool Uuid(const json::JsonValue* value, QUuid& out)
    {
        std::string raw; // 观察记录中的 JSON 字符串。
        if (!Text(value, raw) || raw.size() != 36)
        {
            return false;
        }
        const auto text = QString::fromUtf8(raw.data(), static_cast<qsizetype>(raw.size())); // 只与规范输出比对。
        out = QUuid(text);
        return out.toString(QUuid::WithoutBraces) == text;
    }

    // u64 必须是规范十进制文本。无前导零，拒绝溢出和尾随字符。
    bool U64Text(const json::JsonValue* value, quint64& out, bool required = true)
    {
        if (!value)
        {
            return !required;
        }
        std::string raw; // 十进制字符串，禁止数字类型或隐式转换。
        if (!Text(value, raw) || raw.size() > 20 || (raw.size() > 1 && raw.front() == '0'))
        {
            return false;
        }
        const auto result = std::from_chars(raw.data(), raw.data() + raw.size(), out); // 严格检查完整消费。
        return result.ec == std::errc{} && result.ptr == raw.data() + raw.size();
    }

    // u32 仅接受 JSON 整数字面量，A0 允许 -0 规范化为零。
    bool U32(const json::JsonValue* value, quint32& out, bool required)
    {
        if (!value)
        {
            return !required;
        }
        std::uint64_t number = 0; // 在窄化前核对无符号范围。
        if ((value->type() != json::JsonType::UInt && value->type() != json::JsonType::Int)
            || !value->tryGetU64(number) || number > (std::numeric_limits<quint32>::max)())
        {
            return false;
        }
        out = static_cast<quint32>(number);
        return true;
    }

    // 身份引用必须同时具备采样 UUID 和非零对象编号。
    bool ReadRef(const json::JsonValue* value, ObservationRef& ref, bool required = true)
    {
        if (!value)
        {
            return !required;
        }
        return ClosedObject(*value, {"sampleId", "objectId"}) && Uuid(value->find("sampleId"), ref.sampleId)
            && U64Text(value->find("objectId"), ref.objectId) && ref.objectId;
    }

    // 核对强身份所需的已验证来源字段及接收区间，区间不用于推测事件顺序。
    bool ReadBasis(const json::JsonValue* value, bool strong)
    {
        if (!value || !ClosedObject(*value,
            {"sourceId", "sourceEpoch", "verification", "receiveClockId", "firstReceiveQpc", "lastReceiveQpc"}))
        {
            return false;
        }
        std::string source; // 观察来源 ID。
        QUuid epoch; // 观察来源代次。
        std::string clock; // 接收区间共享的时钟 ID。
        std::string verification; // 记录的核验状态。
        quint64 first = 0; // 首个接收 QPC 观察值。
        quint64 last = 0; // 最后接收 QPC 观察值。
        return Text(value->find("sourceId"), source) && Uuid(value->find("sourceEpoch"), epoch)
            && Text(value->find("receiveClockId"), clock) && Text(value->find("verification"), verification)
            && (verification == "verified" || (!strong && verification == "unverified"))
            && U64Text(value->find("firstReceiveQpc"), first) && U64Text(value->find("lastReceiveQpc"), last) && first <= last;
    }

    // 只解码 A0 公开的身份值。JSON 重名、非法 UTF-8、未知字段及错误类型均拒绝。
    bool ParseObservation(QByteArrayView bytes, Observation& out)
    {
        if (bytes.isEmpty() || bytes.size() > kMaxBytes || bytes.startsWith("\xef\xbb\xbf") || !bytes.isValidUtf8())
        {
            return false;
        }
        json::JsonLimits limits; // 两层对象，最多 6 个字段的来源和少量身份字段。
        limits.maxTotalBytes = kMaxBytes;
        limits.maxDepth = 4;
        limits.maxStringBytes = 64 * 1024;
        limits.maxContainerItems = 12;
        limits.maxTotalNodes = 32;
        const auto parsed = json::ParseJson({bytes.data(), static_cast<std::size_t>(bytes.size())}, limits); // 有界无损公共解析器。
        const auto& value = parsed.value; // 类型检查后再投影到 Qt 值。
        std::string kind; // 输入类别字符串。
        std::string strength; // 输入身份强度字符串。
        if (!parsed.ok() || !Text(value.find("kind"), kind) || !Text(value.find("strength"), strength)
            || (strength != "strong" && strength != "weak" && strength != "unknown"))
        {
            return false;
        }
        out.strong = strength == "strong";
        if (!ReadRef(value.find("ref"), out.ref) || !ReadBasis(value.find("basis"), out.strong)
            || !U64Text(value.find("createTime100ns"), out.creation, out.strong))
        {
            return false;
        }
        if (kind == "thread")
        {
            out.kind = ArchivedObjectKind::Thread;
            return ClosedObject(value, {"kind", "ref", "strength", "basis", "owner", "tid", "createTime100ns"})
                && ReadRef(value.find("owner"), out.owner, out.strong) && U32(value.find("tid"), out.nativeId, out.strong);
        }
        // 进程字段按规范严格校验，弱身份的可选字段也不能使用错误类型。
        std::string machine; // 机器 ID 的原始 UTF-8。
        std::string boot; // 启动代次 ID 的原始 UTF-8。
        if (kind != "process" || !ClosedObject(value, {"kind", "ref", "strength", "basis", "machineId", "bootId", "pid", "createTime100ns"})
            || !Text(value.find("machineId"), machine, out.strong) || !Text(value.find("bootId"), boot, out.strong)
            || !U32(value.find("pid"), out.nativeId, out.strong))
        {
            return false;
        }
        out.machine = QString::fromUtf8(machine.data(), static_cast<qsizetype>(machine.size()));
        out.boot = QString::fromUtf8(boot.data(), static_cast<qsizetype>(boot.size()));
        return true;
    }
}

ArchivedIdentityResult ResolveArchivedObjectIdentity(const ObjectSampleRef& sample, ArchivedObjectKind kind,
    quint64 objectId, std::optional<QByteArrayView> observation, std::optional<QByteArrayView> ownerObservation)
{
    if (sample.projectId.isNull() || sample.sampleId.isNull() || !objectId)
    {
        return {ArchivedIdentityState::Invalid, {}};
    }
    if (!observation)
    {
        return {ArchivedIdentityState::Missing, {}};
    }
    Observation selected; // 所选对象的独立身份。
    if (!ParseObservation(*observation, selected))
    {
        return {ArchivedIdentityState::Invalid, {}};
    }
    if (selected.kind != kind || selected.ref.objectId != objectId || selected.ref.sampleId != sample.sampleId)
    {
        return {ArchivedIdentityState::IdentityMismatch, {}};
    }
    if (kind == ArchivedObjectKind::Thread && selected.owner.objectId
        && (selected.owner.sampleId != sample.sampleId || selected.owner.objectId == objectId))
    {
        return {ArchivedIdentityState::IdentityMismatch, {}};
    }
    if (!selected.strong)
    {
        return {ArchivedIdentityState::Unresolved, {}};
    }

    ObjectSelection subject; // 只有 owner 校验通过才提交线程对象。
    subject.sample = sample;
    Observation owner; // 请求线程时从同一采样匹配的强进程身份。
    const Observation* process = &selected; // 进程操作直接使用所选对象。
    if (kind == ArchivedObjectKind::Thread)
    {
        if (!ownerObservation)
        {
            return {ArchivedIdentityState::Unresolved, {}};
        }
        if (!ParseObservation(*ownerObservation, owner))
        {
            return {ArchivedIdentityState::Invalid, {}};
        }
        if (owner.kind != ArchivedObjectKind::Process || owner.ref.sampleId != sample.sampleId || owner.ref.objectId != selected.owner.objectId)
        {
            return {ArchivedIdentityState::IdentityMismatch, {}};
        }
        if (!owner.strong)
        {
            return {ArchivedIdentityState::Unresolved, {}};
        }
        process = &owner;
        subject.thread = ThreadObjectRef{objectId, owner.ref.objectId, selected.nativeId, selected.creation};
    }
    subject.process = {process->ref.objectId, process->machine, process->boot, process->nativeId, process->creation};
    // A0 允许属性为零。本菜单的转储目标目前不支持该实例值，保持可解析但不可执行。
    return subject.isValid() ? ArchivedIdentityResult{ArchivedIdentityState::Ready, subject}
        : ArchivedIdentityResult{ArchivedIdentityState::Unresolved, {}};
}
}
