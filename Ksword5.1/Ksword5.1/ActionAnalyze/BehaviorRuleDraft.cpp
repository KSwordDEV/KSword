#include "BehaviorRuleDraft.h"
#include "../../../shared/evidence/EvidenceJson.h"

#include <algorithm>
#include <charconv>
#include <initializer_list>
#include <limits>
#include <utility>

namespace ks::action_analyze
{
namespace
{
    namespace rule = Ksword::ActionAnalyze::Rules;
    namespace json = Ksword::Evidence;
    using namespace std::literals;

    constexpr std::size_t kMaxEvents = 256; // 编辑器只提供小规模合成回放。
    constexpr auto kSample = "e7e9fdcc-2081-4ca2-813d-4898a89890fc"sv; // 合成样本命名空间。
    constexpr auto kProject = "3cb09760-900b-4de6-88e1-6dddcc9d5a20"sv; // 合成项目命名空间。
    constexpr auto kSource = "draft-source"sv; // 合成来源。
    constexpr auto kEpoch = "draft-epoch"sv; // 合成来源代次。
    constexpr auto kThread = "draft-thread"sv; // 合成线程实例。
    constexpr auto kClock = "draft-clock"sv; // 草稿中的 100 ns 计时域。

    // 只开放 A0 字段目录中可无损投影为 U64 的字段，以及两个样本/项目标识字段。
    constexpr std::pair<std::string_view, rule::FieldType> kFields[] = {
        {"event.projectId", rule::FieldType::Text},
        {"event.sampleId", rule::FieldType::Text},
        {"event.eventOrdinal", rule::FieldType::U64},
        {"source.sequence", rule::FieldType::U64},
        {"source.headerPid", rule::FieldType::U64},
        {"source.headerTid", rule::FieldType::U64},
        {"time.receivedQpc", rule::FieldType::U64}
    };

    constexpr std::pair<std::string_view, rule::Phase> kPhases[] = { // A0 稳定阶段名。
        {"entry", rule::Phase::Entry}, {"return", rule::Phase::Return},
        {"submit", rule::Phase::Submit}, {"complete", rule::Phase::Complete},
        {"observation", rule::Phase::Observation}
    };

    constexpr std::pair<std::string_view, rule::FieldOp> kOperators[] = { // 已实现的字段运算。
        {"eq", rule::FieldOp::Equal}, {"ne", rule::FieldOp::NotEqual},
        {"lt", rule::FieldOp::Less}, {"le", rule::FieldOp::LessEqual},
        {"gt", rule::FieldOp::Greater}, {"ge", rule::FieldOp::GreaterEqual},
        {"contains", rule::FieldOp::Contains}, {"startsWith", rule::FieldOp::StartsWith},
        {"endsWith", rule::FieldOp::EndsWith}, {"isNull", rule::FieldOp::IsNull},
        {"isComplete", rule::FieldOp::IsComplete}
    };

    // 在有限的键值目录中返回对应枚举，未登记的键返回空值。
    template<class T, std::size_t N>
    std::optional<T> Lookup(const std::pair<std::string_view, T>(&catalog)[N], std::string_view key)
    {
        for (const auto& [name, value] : catalog) // 候选名称及所映射枚举。
        {
            if (name == key)
            {
                return value;
            }
        }
        return std::nullopt;
    }

    // 尝试读取对象成员的字符串，为未找到或类型不符的情况返回空串。
    std::string Text(const json::JsonValue& object, std::string_view key)
    {
        std::string text; // 从 JSON 成员复制的原始 UTF-8 值。
        const auto* member = object.find(key); // 当前要读取的成员。
        if (member)
        {
            member->tryGetString(text);
        }
        return text;
    }

    // 仅接受规范十进制字符串，用于 64 位字段以及发布序号等有明确单位的值。
    std::optional<std::uint64_t> Decimal(const json::JsonValue* value)
    {
        std::string digits; // 保存待解码的十进制数字。
        if (!value || !value->tryGetString(digits) || digits.empty()
            || (digits.size() > 1 && digits.front() == '0'))
        {
            return std::nullopt;
        }
        std::uint64_t number = 0; // 完整解析后的无符号数。
        const auto* end = digits.data() + digits.size(); // 必须消耗的输入边界。
        const auto parsed = std::from_chars(digits.data(), end, number); // 保留转换错误。
        if (parsed.ec != std::errc{} || parsed.ptr != end)
        {
            return std::nullopt;
        }
        return number;
    }

    // ID 约束仅用于草稿标签和精确事件类型选择器，返回是否为受支持的键。
    bool IsKey(std::string_view key)
    {
        return !key.empty() && key.size() <= rule::MaxKeyBytes
            && std::ranges::all_of(key, [](char ch) // 限定为工具可读、不含换行的 ID 字符。
        {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
        });
    }

    // 规范 JSON Pointer 的单个路径片段，便于定位任意未知键。
    std::string EscapePointer(std::string_view key)
    {
        std::string escaped; // 转义后的路径片段。
        for (const char ch : key) // 处理一个原始字符。
        {
            switch (ch)
            {
            case '~': escaped += "~0"; break;
            case '/': escaped += "~1"; break;
            default: escaped += ch; break;
            }
        }
        return escaped;
    }

    // 把当前诊断追加到回执并返回 false，调用方在首个问题处停止。
    bool Fail(BehaviorRuleCheck& result, std::string_view error, std::string path)
    {
        result.error = error;
        result.pointer = std::move(path);
        return false;
    }

    // 拒绝非对象和未知字段。必需字段的类型与缺失由各自解释器处理。
    bool Keys(const json::JsonValue& value, std::initializer_list<std::string_view> accepted,
        const std::string& path, BehaviorRuleCheck& result)
    {
        const auto* object = value.asObject(); // 当前待检查对象。
        if (!object)
        {
            return Fail(result, "expected-object", path);
        }
        for (const auto& member : *object) // 在当前对象检查闭集键。
        {
            if (std::ranges::find(accepted, member.first) == accepted.end())
            {
                return Fail(result, "unknown-member", path + '/' + EscapePointer(member.first));
            }
        }
        return true;
    }

    // 保留选择器事件名和已准备的谓词，使传入回放引擎的引用有效。
    struct DraftSelection
    {
        std::string eventType; // 草稿声明的精确事件名称。
        rule::PreparedPredicate predicate; // 已经由规则引擎完成类型检查。
    };

    // 将规则引擎的准备错误映射到稳定的文本诊断码。
    std::string_view PreparationError(rule::PrepareError error)
    {
        switch (error)
        {
        case rule::PrepareError::InvalidPhase: return "invalid-phase";
        case rule::PrepareError::InvalidCatalog: return "invalid-field-catalog";
        case rule::PrepareError::NodeLimit: return "predicate-node-limit";
        case rule::PrepareError::InvalidTree: return "invalid-predicate-tree";
        case rule::PrepareError::DepthLimit: return "predicate-depth-limit";
        case rule::PrepareError::UnknownField: return "unknown-field";
        case rule::PrepareError::FieldNotInPhase: return "field-unavailable-in-phase";
        case rule::PrepareError::UnsupportedOperator: return "unsupported-operator";
        case rule::PrepareError::TypeMismatch: return "operand-type-mismatch";
        case rule::PrepareError::LiteralLimit: return "literal-limit";
        case rule::PrepareError::InvalidUtf8: return "invalid-utf8";
        default: return "invalid-predicate";
        }
    }

    // 把单个布尔常量或字段测试转为后序树节点，交给现有引擎处理字段类型和操作符。
    bool DecodePredicate(const json::JsonValue& value, const std::string& path,
        rule::AstNode& node, BehaviorRuleCheck& result)
    {
        bool constant = false; // 可用于只匹配事件类型和阶段的布尔谓词。
        if (value.tryGetBool(constant))
        {
            node = constant;
            return true;
        }
        if (!Keys(value, {"field", "operator", "value"}, path, result))
        {
            return false;
        }
        auto field = Text(value, "field"); // 规则准备将验证字段键及阶段。
        const auto type = Lookup(kFields, field); // 获取供字面量解码使用的类型。
        if (!type)
        {
            return Fail(result, "unknown-field", path + "/field");
        }
        const auto op = Lookup(kOperators, Text(value, "operator")); // 白名单中的运算。
        if (!op)
        {
            return Fail(result, "unsupported-operator", path + "/operator");
        }

        // 质量测试没有右侧值。字段缺失时的三值逻辑由规则引擎判定。
        const bool takesValue = *op != rule::FieldOp::IsNull && *op != rule::FieldOp::IsComplete;
        const auto* right = value.find("value"); // 用户提供的右操作数。
        rule::Literal literal; // 类型化右操作数或 null。
        if (takesValue != (right != nullptr))
        {
            return Fail(result, takesValue ? "missing-value" : "unexpected-value", path + "/value");
        }
        if (right && !right->isNull())
        {
            if (*type == rule::FieldType::U64)
            {
                const auto number = Decimal(right); // 严格的十进制无符号操作数。
                if (!number)
                {
                    return Fail(result, "expected-u64-string", path + "/value");
                }
                literal = *number;
            }
            else
            {
                std::string text; // 文本比较按原始 UTF-8 数据处理。
                if (!right->tryGetString(text))
                {
                    return Fail(result, "expected-text", path + "/value");
                }
                literal = std::move(text);
            }
        }
        node = rule::FieldTest{*op, std::move(field), std::move(literal)};
        return true;
    }

    // 读取选择器并按当前明确阶段准备谓词，失败时保留 JSON Pointer。
    bool DecodeSelection(const json::JsonValue& root, std::string_view name,
        DraftSelection& output, BehaviorRuleCheck& result)
    {
        const auto path = '/' + std::string(name); // 当前选择器在草稿中的位置。
        const auto* selector = root.find(name); // 当前选择器 JSON 对象。
        if (!selector)
        {
            return Fail(result, "missing-selector", path);
        }
        if (!Keys(*selector, {"eventType", "phase", "predicate"}, path, result))
        {
            return false;
        }
        output.eventType = Text(*selector, "eventType");
        if (!IsKey(output.eventType))
        {
            return Fail(result, "invalid-event-type", path + "/eventType");
        }
        const auto phase = Lookup(kPhases, Text(*selector, "phase")); // 选择器指定的事件阶段。
        if (!phase)
        {
            return Fail(result, "invalid-phase", path + "/phase");
        }

        // 当前切片开放的基础字段都属于 A0 的 all 阶段集合。
        const auto predicatePath = path + "/predicate"; // 语法诊断映射目标。
        const auto* predicate = selector->find("predicate"); // 规则原文中的谓词值。
        if (!predicate)
        {
            return Fail(result, "missing-predicate", predicatePath);
        }
        std::vector<rule::FieldBinding> bindings; // 仅绑定受本端支持的字段。
        for (const auto& [id, type] : kFields) // 构造此阶段适用的字段目录。
        {
            bindings.push_back({id, type, *phase});
        }

        // 字符串由声明式解析器生成完整 AST。布尔和对象格式保留旧草稿的行为。
        std::string expression; // JSON 解码后的纯 UTF-8 表达式，不包含外层引号。
        if (predicate->tryGetString(expression))
        {
            auto prepared = rule::PreparePredicateExpression(expression, *phase, bindings); // 包含类型与阶段校验。
            if (prepared.error != rule::ExpressionError::None)
            {
                result.expressionLocation = prepared.location;
                const auto error = prepared.preparationError == rule::PrepareError::None
                    ? rule::ExpressionErrorId(prepared.error) : PreparationError(prepared.preparationError);
                return Fail(result, error, predicatePath);
            }
            output.predicate = std::move(prepared.predicate);
            return true;
        }

        rule::AstNode node = false; // 旧草稿只有一个布尔常量或字段测试节点。
        if (!DecodePredicate(*predicate, predicatePath, node, result))
        {
            return false;
        }
        auto prepared = rule::PreparePredicate(*phase, bindings, std::span(&node, 1)); // 实际引擎准备回执。
        if (prepared.error != rule::PrepareError::None)
        {
            return Fail(result, PreparationError(prepared.error), predicatePath);
        }
        output.predicate = std::move(prepared.predicate);
        return true;
    }

    // 解析后的合成事件拥有文本和字段数组。调用 Replay 时才生成只读借用视图。
    struct DraftEvent
    {
        std::string eventType; // 精确事件类型标签。
        rule::Phase phase = rule::Phase::Observation; // 已验证的阶段枚举。
        std::uint64_t ordinal = 0; // 样本内事件身份。
        std::optional<std::uint64_t> sequence; // 显式来源发布序号。
        std::optional<rule::EventTime> time; // 同一合成时钟内的比较时间。
        std::vector<rule::FieldSample> fields; // 已排序的 A0 字段投影。
    };

    // 把用户可填的观测字段解码为基础类型，身份和源序号由事件头统一投影。
    bool DecodeObservedFields(const json::JsonValue& fields, const std::string& path,
        DraftEvent& output, BehaviorRuleCheck& result)
    {
        if (!Keys(fields, {"source.headerPid", "source.headerTid", "time.receivedQpc"}, path, result))
        {
            return false;
        }
        for (const auto& [id, type] : kFields) // 遍历稳定目录。动态 JSON 键不进入引擎。
        {
            const auto* input = fields.find(id); // 当前字段的原始值。
            if (!input)
            {
                continue; // 缺失字段由引擎解释为 NotCollected。
            }
            const auto number = Decimal(input); // 规范十进制输入。
            if (!number)
            {
                return Fail(result, "expected-u64-string", path + '/' + std::string(id));
            }
            if (id != "time.receivedQpc" && *number > (std::numeric_limits<std::uint32_t>::max)())
            {
                return Fail(result, "u32-out-of-range", path + '/' + std::string(id));
            }
            output.fields.push_back({id, rule::Quality::Known, *number});
        }
        return true;
    }

    // 读取一个合成事件。允许省略时间或源序号，便于制作 Unknown 用例。
    bool DecodeEvent(const json::JsonValue& value, const std::string& path,
        DraftEvent& output, BehaviorRuleCheck& result)
    {
        if (!Keys(value, {"ordinal", "sourceSequence", "time100ns", "eventType", "phase", "fields"}, path, result))
        {
            return false;
        }
        const auto ordinal = Decimal(value.find("ordinal")); // 样本内唯一标识。
        if (!ordinal)
        {
            return Fail(result, "expected-u64-string", path + "/ordinal");
        }
        const auto phase = Lookup(kPhases, Text(value, "phase")); // 事件发生阶段。
        if (!phase)
        {
            return Fail(result, "invalid-phase", path + "/phase");
        }
        output.eventType = Text(value, "eventType");
        if (!IsKey(output.eventType))
        {
            return Fail(result, "invalid-event-type", path + "/eventType");
        }

        // 从合成事件本身导出信封键，始终保留样本身份和归档序号的一致性。
        output.ordinal = *ordinal;
        output.phase = *phase;
        output.fields.push_back({"event.projectId", rule::Quality::Known, kProject});
        output.fields.push_back({"event.sampleId", rule::Quality::Known, kSample});
        output.fields.push_back({"event.eventOrdinal", rule::Quality::Known, *ordinal});
        if (const auto* input = value.find("sourceSequence")) // 可缺失的发布顺序标识。
        {
            output.sequence = Decimal(input);
            if (!output.sequence)
            {
                return Fail(result, "expected-u64-string", path + "/sourceSequence");
            }
            output.fields.push_back({"source.sequence", rule::Quality::Known, *output.sequence});
        }
        if (const auto* input = value.find("time100ns")) // 可缺失的 100 ns 时刻。
        {
            const auto ticks = Decimal(input); // 同一个合成时钟中的时间值。
            if (!ticks)
            {
                return Fail(result, "expected-u64-string", path + "/time100ns");
            }
            output.time = rule::EventTime{kClock, *ticks};
        }
        if (const auto* fields = value.find("fields")) // 可选观测字段对象。
        {
            if (!DecodeObservedFields(*fields, path + "/fields", output, result))
            {
                return false;
            }
        }
        std::ranges::sort(output.fields, {}, &rule::FieldSample::id); // 引擎要求按字段 ID 排序。
        return true;
    }

    // 跟随规则引擎汇总输入错误，避免覆盖无效事件或冲突标识。
    std::string_view ReplayError(rule::ReplayError error)
    {
        switch (error)
        {
        case rule::ReplayError::InvalidRequest: return "invalid-replay-request";
        case rule::ReplayError::InvalidEvent: return "invalid-replay-event";
        case rule::ReplayError::ConflictingEventId: return "conflicting-event-id";
        case rule::ReplayError::InputLimit: return "replay-input-limit";
        default: return "invalid-replay";
        }
    }
}

// 提供有真实命中和 Unknown 结果的初始合成例子。事件名仅用于这个示例。
std::string_view BehaviorRuleExample()
{
    return R"({
  "kind": "semantic-rule",
  "version": 1,
  "ruleId": "demo.repeated-read",
  "mode": "countAtLeast",
  "window100ns": "300000000",
  "threshold": "2",
  "step": {
    "eventType": "demo.file.read",
    "phase": "observation",
    "predicate": "(source.headerPid == 42u64 && !isNull(source.headerPid)) || source.headerPid == 0x2au64"
  },
  "anchor": {
    "eventType": "demo.file.read",
    "phase": "observation",
    "predicate": true
  },
  "replay": [
    {"ordinal": "0", "time100ns": "300000000", "eventType": "demo.file.read",
     "phase": "observation", "fields": {"source.headerPid": "42"}},
    {"ordinal": "1", "time100ns": "310000000", "eventType": "demo.file.read",
     "phase": "observation", "fields": {"source.headerPid": "42"}},
    {"ordinal": "2", "time100ns": "320000000", "eventType": "demo.file.read",
     "phase": "observation"}
  ]
}
)"sv;
}

// 后台处理完整的草稿快照，结果只包含可以独立展示的值。
BehaviorRuleCheck CheckBehaviorRuleDraft(std::string_view utf8, bool runReplay)
{
    BehaviorRuleCheck result; // 本次草稿检查和可选回放的独立回执。
    json::JsonLimits limits; // 将严格 JSON 解析器限制在编辑和合成回放的规模。
    limits.maxTotalBytes = BehaviorRuleMaxBytes;
    limits.maxDepth = 16;
    limits.maxContainerItems = kMaxEvents;
    limits.maxTotalNodes = 4096;
    limits.maxStringBytes = rule::MaxValueBytes;
    const auto parsed = json::ParseJson(utf8, limits); // 保留重复键、溢出和语法位置的诊断。
    if (!parsed.ok())
    {
        result.error = json::JsonParseStatusName(parsed.status);
        result.offset = parsed.errorOffset;
        return result;
    }
    const auto& root = parsed.value; // 整份版本化草稿文档。
    if (!Keys(root, {"kind", "version", "ruleId", "mode", "window100ns", "threshold", "step", "anchor", "replay"},
        {}, result))
    {
        return result;
    }
    if (Text(root, "kind") != "semantic-rule")
    {
        Fail(result, "unsupported-kind", "/kind");
        return result;
    }
    const auto* formatVersion = root.find("version"); // 当前编辑器草稿格式版本。
    std::uint64_t version = 0; // 严格读取 JSON 整数，避免把字符串当作版本号。
    if (!formatVersion || formatVersion->type() != json::JsonType::UInt
        || !formatVersion->tryGetU64(version) || version != 1)
    {
        Fail(result, "unsupported-version", "/version");
        return result;
    }
    result.ruleId = Text(root, "ruleId");
    if (!IsKey(result.ruleId))
    {
        result.ruleId.clear();
        Fail(result, "invalid-rule-id", "/ruleId");
        return result;
    }

    // 匹配类型直接对应现有规则引擎的计数和双步序列操作。
    constexpr std::pair<std::string_view, rule::ReplayKind> modes[] = {
        {"countAtLeast", rule::ReplayKind::CountAtLeast}, {"countEqual", rule::ReplayKind::CountEqual},
        {"sequence", rule::ReplayKind::Sequence}
    };
    const auto mode = Lookup(modes, Text(root, "mode")); // 选中的规则模式。
    if (!mode)
    {
        Fail(result, "unsupported-mode", "/mode");
        return result;
    }
    const auto window = Decimal(root.find("window100ns")); // 闭区间窗口的宽度。
    if (!window || *window > rule::MaxWindow100ns)
    {
        Fail(result, "invalid-window", "/window100ns");
        return result;
    }
    const auto* thresholdInput = root.find("threshold"); // 计数阈值。序列不得携带此字段。
    const auto threshold = Decimal(thresholdInput); // 规范十进制计数。
    if (*mode == rule::ReplayKind::Sequence ? thresholdInput != nullptr : !threshold)
    {
        Fail(result, "invalid-threshold", "/threshold");
        return result;
    }
    DraftSelection step; // 候选事件的精确选择器。
    DraftSelection anchor; // 建立计数窗口或序列结束的锚点选择器。
    if (!DecodeSelection(root, "step", step, result) || !DecodeSelection(root, "anchor", anchor, result))
    {
        return result;
    }

    // 验证命令也读取合成输入，使打开的草稿能完整校验。
    std::vector<DraftEvent> events; // 拥有本次分析中所有引擎视图引用的数据。
    if (const auto* input = root.find("replay")) // 无回放字段的草稿仍可单独校验。
    {
        const auto* array = input->asArray(); // 合成事件列表。
        if (!array)
        {
            Fail(result, "expected-event-array", "/replay");
            return result;
        }
        result.eventCount = array->size();
        events.resize(result.eventCount);
        for (std::size_t index = 0; index < events.size(); ++index) // 逐条验证并报告位置。
        {
            if (!DecodeEvent(array->at(index), "/replay/" + std::to_string(index), events[index], result))
            {
                return result;
            }
        }
    }
    if (!runReplay)
    {
        return result;
    }

    // 固定合成作用域。序列顺序仅来自用户填写的 sourceSequence。
    // 草稿无法提供归档覆盖凭证，缺证据的结果由引擎保持 Unknown。
    const rule::ReplayScope scope{kSample, kSource, kEpoch, kThread, kClock}; // 一条合成源和线程。
    rule::ReplaySnapshot snapshot{result.ruleId, scope, 0, std::nullopt, true}; // 与当前回执同寿命。
    const rule::ReplayRule request{*mode, {step.eventType, &step.predicate},
        {anchor.eventType, &anchor.predicate}, *window, threshold.value_or(0)}; // 仅使用已准备谓词。
    std::vector<rule::ReplayEvent> views; // 指向 events 中的已验证只读事件。
    views.reserve(events.size());
    for (const auto& event : events) // 建立只读证据视图及本次最高事件身份。
    {
        snapshot.archiveThroughOrdinal = (std::max)(snapshot.archiveThroughOrdinal, event.ordinal);
        views.push_back({kSample, event.ordinal, kSource, kEpoch, event.sequence, kThread,
            event.time, event.eventType, event.phase, event.fields});
    }
    auto replay = rule::Replay(snapshot, request, views); // 正式离线引擎回执。
    if (replay.error != rule::ReplayError::None)
    {
        Fail(result, ReplayError(replay.error), "/replay");
    }
    else
    {
        result.replay = std::move(replay);
    }
    return result;
}
}
