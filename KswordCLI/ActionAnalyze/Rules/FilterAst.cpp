#include "FilterAst.h"

#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <utility>

namespace Ksword::ActionAnalyze::Rules {
namespace {

constexpr std::size_t MaxNodes = 512;
constexpr std::size_t MaxDepth = 32;
constexpr std::size_t MaxCatalogBindings = 512;
constexpr std::size_t MaxLiteralBytes = 8 * 1024;

// 以下闭集检查用于准备阶段，避免未经识别的枚举值进入执行器。
bool ValidPhase(Phase phase)
{
    switch (phase) {
    case Phase::Entry: case Phase::Return: case Phase::Submit:
    case Phase::Complete: case Phase::Observation:
        return true;
    }
    return false;
}

bool ValidType(FieldType type)
{
    return type == FieldType::Bool || type == FieldType::U64 || type == FieldType::Text;
}

bool ValidKey(std::string_view key)
{
    return !key.empty() && key.size() <= MaxKeyBytes;
}

// 已知文本必须是完整 UTF-8。截断文本由投影保留完整字符组成的已获前缀。
bool ValidUtf8(std::string_view text)
{
    for (std::size_t i = 0; i < text.size();) {
        const auto first = static_cast<unsigned char>(text[i++]);
        if (first <= 0x7f) {
            continue;
        }
        unsigned tails = 0;
        unsigned low = 0x80;
        unsigned high = 0xbf;
        // 首字节决定剩余字节数和首个续字节范围，排除过长编码和代理项。
        if (first >= 0xc2 && first <= 0xdf) {
            tails = 1;
        } else if (first >= 0xe0 && first <= 0xef) {
            tails = 2;
            low = first == 0xe0 ? 0xa0 : low;
            high = first == 0xed ? 0x9f : high;
        } else if (first >= 0xf0 && first <= 0xf4) {
            tails = 3;
            low = first == 0xf0 ? 0x90 : low;
            high = first == 0xf4 ? 0x8f : high;
        } else {
            return false;
        }
        if (tails > text.size() - i) {
            return false;
        }
        // 后续续字节回到普通的 0x80 到 0xbf 范围。
        for (unsigned tail = 0; tail < tails; ++tail) {
            const auto byte = static_cast<unsigned char>(text[i++]);
            if (byte < low || byte > high) {
                return false;
            }
            low = 0x80;
            high = 0xbf;
        }
    }
    return true;
}

bool IsNullLiteral(const Literal& literal)
{
    return std::holds_alternative<std::monostate>(literal);
}

PrepareError CheckTest(const FieldTest& test, FieldType type)
{
    // 只接受与目录类型一致的字面量，质量比较使用独立枚举。
    const bool numeric = std::holds_alternative<std::uint64_t>(test.literal);
    const bool boolean = std::holds_alternative<bool>(test.literal);
    const bool text = std::holds_alternative<std::string>(test.literal);
    bool compatible = false;
    switch (test.op) {
    case FieldOp::IsNull: case FieldOp::IsComplete: case FieldOp::IsKnown:
        compatible = IsNullLiteral(test.literal);
        break;
    case FieldOp::QualityEqual: case FieldOp::QualityNotEqual: {
        const auto* quality = std::get_if<Quality>(&test.literal); // 结构化谓词也须通过闭集检查。
        compatible = quality && *quality >= Quality::Known && *quality <= Quality::Redacted;
        break;
    }
    case FieldOp::Equal: case FieldOp::NotEqual:
        compatible = IsNullLiteral(test.literal) || (numeric && type == FieldType::U64) ||
                     (boolean && type == FieldType::Bool) || (text && type == FieldType::Text);
        break;
    case FieldOp::Less: case FieldOp::LessEqual: case FieldOp::Greater: case FieldOp::GreaterEqual:
        compatible = numeric && type == FieldType::U64;
        break;
    case FieldOp::Contains: case FieldOp::StartsWith: case FieldOp::EndsWith:
        compatible = text && type == FieldType::Text;
        break;
    default:
        return PrepareError::UnsupportedOperator;
    }
    return compatible ? PrepareError::None : PrepareError::TypeMismatch;
}

Truth AsTruth(bool value)
{
    return value ? Truth::True : Truth::False;
}

Truth Negate(Truth value)
{
    return value == Truth::Unknown ? value : AsTruth(value == Truth::False);
}

bool ShapeMatches(const FieldSample& field, FieldType type)
{
    // 未采等状态没有值。截断文本可以携带一个已获前缀。
    const bool empty = std::holds_alternative<std::monostate>(field.value);
    switch (field.quality) {
    case Quality::Known:
        return (type == FieldType::Bool && std::holds_alternative<bool>(field.value)) ||
               (type == FieldType::U64 && std::holds_alternative<std::uint64_t>(field.value)) ||
               (type == FieldType::Text && std::holds_alternative<std::string_view>(field.value));
    case Quality::Truncated:
        return empty || (type == FieldType::Text && std::holds_alternative<std::string_view>(field.value));
    case Quality::Null: case Quality::NotCollected: case Quality::Unsupported:
    case Quality::AccessDenied: case Quality::ReadFailed: case Quality::DecodeFailed: case Quality::Redacted:
        return empty;
    }
    return false;
}

// 单事件解释器只借用可信的准备结果和只读字段视图。
class Evaluator {
public:
    Evaluator(std::span<const AstNode> nodes, std::span<const FieldType> types,
              std::span<const FieldSample> fields, std::size_t limit)
        : nodes_(nodes), types_(types), fields_(fields), limit_(limit)
    {
    }

    Evaluation Run()
    {
        // 先验证排序和唯一性，随后每次字段读取都可二分查找。
        if (fields_.size() > MaxEventFields) {
            return {Truth::Unknown, EvaluationFault::InvalidInput, 0};
        }
        std::string_view previous;
        for (const auto& field : fields_) {
            if (!ValidKey(field.id)) {
                return {Truth::Unknown, EvaluationFault::InvalidInput, used_};
            }
            if (!Spend(1 + field.id.size() + previous.size())) {
                return {Truth::Unknown, fault_, used_};
            }
            if (previous >= field.id) {
                return {Truth::Unknown, EvaluationFault::InvalidInput, used_};
            }
            previous = field.id;
        }
        const auto truth = Node(nodes_.size() - 1);
        return {fault_ == EvaluationFault::None ? truth : Truth::Unknown, fault_, used_};
    }

private:
    // used_ 始终不超过 limit_。首次故障留下明确诊断。
    bool Spend(std::size_t amount)
    {
        if (fault_ != EvaluationFault::None) {
            return false;
        }
        if (amount > limit_ - used_) {
            fault_ = EvaluationFault::Budget;
            return false;
        }
        used_ += amount;
        return true;
    }

    Truth Node(std::size_t index)
    {
        // 节点消费预算，树深度由 PreparePredicate 验证。
        if (!Spend(1)) {
            return Truth::Unknown;
        }
        const auto& node = nodes_[index];
        if (const auto* constant = std::get_if<bool>(&node)) {
            return AsTruth(*constant);
        }
        if (const auto* negation = std::get_if<Not>(&node)) {
            return Negate(Node(negation->child));
        }
        if (const auto* logical = std::get_if<Logical>(&node)) {
            // 只有左侧已决定整个运算才短路。U 还需要检查右侧决定值。
            const auto left = Node(logical->left);
            const auto decisive = logical->op == Logic::And ? Truth::False : Truth::True;
            const auto neutral = Negate(decisive);
            if (left == decisive) {
                return left;
            }
            const auto right = Node(logical->right);
            if (right == decisive || left == neutral) {
                return right;
            }
            return Truth::Unknown;
        }
        if (const auto* binary = std::get_if<BooleanBinary>(&node)) {
            const auto left = Node(binary->left); // 先读取左侧；首次故障仍由原解释器保留。
            const auto right = Node(binary->right); // 非短路操作必须读取右侧，不能隐藏除零或预算故障。
            switch (binary->op)
            {
            case BooleanBinaryOp::And:
                if (left == Truth::False || right == Truth::False) return Truth::False;
                return left == Truth::True && right == Truth::True ? Truth::True : Truth::Unknown;
            case BooleanBinaryOp::Or:
                if (left == Truth::True || right == Truth::True) return Truth::True;
                return left == Truth::False && right == Truth::False ? Truth::False : Truth::Unknown;
            case BooleanBinaryOp::Xor:
                if (left == Truth::Unknown || right == Truth::Unknown) return Truth::Unknown;
                return AsTruth(left != right);
            case BooleanBinaryOp::Equal:
            case BooleanBinaryOp::NotEqual:
                // 比较必须取得两侧真实布尔值；两个未知也不能推断为相等。
                if (left == Truth::Unknown || right == Truth::Unknown)
                {
                    return Truth::Unknown;
                }
                return AsTruth(binary->op == BooleanBinaryOp::Equal ? left == right : left != right);
            }
            fault_ = EvaluationFault::InvalidInput;
            return Truth::Unknown;
        }
        if (const auto* conditional = std::get_if<Conditional>(&node)) {
            const auto selected = SelectBranch(*conditional);
            return selected ? Node(*selected) : Truth::Unknown;
        }
        if (const auto* comparison = std::get_if<NumericComparison>(&node)) {
            const auto left = Number(comparison->left);
            const auto right = Number(comparison->right);
            if (!left || !right) {
                return Truth::Unknown;
            }
            switch (comparison->op) {
            case FieldOp::Equal: return AsTruth(*left == *right);
            case FieldOp::NotEqual: return AsTruth(*left != *right);
            case FieldOp::Less: return AsTruth(*left < *right);
            case FieldOp::LessEqual: return AsTruth(*left <= *right);
            case FieldOp::Greater: return AsTruth(*left > *right);
            case FieldOp::GreaterEqual: return AsTruth(*left >= *right);
            default: return Truth::Unknown;
            }
        }
        if (const auto* test = std::get_if<FieldTest>(&node)) {
            return Test(*test, types_[index]);
        }
        if (const auto* comparison = std::get_if<TextFieldComparison>(&node))
        {
            return CompareTextFields(*comparison); // 同事件字段直接比较，不生成字符串副本或新事件投影。
        }
        fault_ = EvaluationFault::InvalidInput;
        return Truth::Unknown;
    }

    // 条件只求值一次。Unknown 不访问任何分支，包含两个分支恰好相同的情况。
    std::optional<std::size_t> SelectBranch(const Conditional& conditional)
    {
        const auto condition = Node(conditional.condition);
        if (condition == Truth::Unknown) {
            return std::nullopt;
        }
        return condition == Truth::True ? conditional.whenTrue : conditional.whenFalse;
    }

    // 递归读取已验证的数值子树；空 optional 表示未知，不表示数值零。
    std::optional<std::uint64_t> Number(std::size_t index)
    {
        if (!Spend(1)) {
            return std::nullopt;
        }
        const auto& node = nodes_[index]; // 当前实际消费预算的数值节点。
        if (const auto* conditional = std::get_if<Conditional>(&node)) {
            const auto selected = SelectBranch(*conditional);
            return selected ? Number(*selected) : std::nullopt;
        }
        if (const auto* literal = std::get_if<NumericLiteral>(&node)) {
            return literal->value;
        }
        if (const auto* reference = std::get_if<NumericField>(&node)) {
            constexpr std::size_t MaxLookups = 9; // 与旧字段谓词使用相同的查找计费上界。
            if (!fields_.empty() && !Spend(MaxLookups * (1 + MaxKeyBytes))) {
                return std::nullopt;
            }
            const auto it = std::lower_bound(fields_.begin(), fields_.end(), reference->field,
                [](const FieldSample& field, std::string_view id) { return field.id < id; });
            if (it == fields_.end() || it->id != reference->field) {
                return std::nullopt;
            }
            if (!ShapeMatches(*it, FieldType::U64)) {
                fault_ = EvaluationFault::InvalidInput;
                return std::nullopt;
            }
            // 未知值不参与数值运算，即使另一个操作数为零也不折叠。
            return it->quality == Quality::Known
                ? std::optional{std::get<std::uint64_t>(it->value)} : std::nullopt;
        }
        if (const auto* unary = std::get_if<NumericUnary>(&node)) {
            const auto value = Number(unary->child); // 先保留操作数的未知状态。
            return value ? std::optional{ApplyNumericOperator(unary->op, *value)} : std::nullopt;
        }
        if (const auto* binary = std::get_if<NumericBinary>(&node)) {
            const auto left = Number(binary->left); // 左值先求，稳定保留首次故障。
            const auto right = Number(binary->right); // 数值操作不使用布尔短路。
            // 按左到右求值；已知零除数独立于左值是否可用。
            if (fault_ == EvaluationFault::None && right && *right == 0 &&
                (binary->op == NumericBinaryOp::Divide || binary->op == NumericBinaryOp::Remainder)) {
                fault_ = EvaluationFault::DivisionByZero;
            }
            if (!left || !right || fault_ != EvaluationFault::None) {
                return std::nullopt;
            }
            std::uint64_t value = 0; // 仅在运算成功后向父节点发布。
            if (ApplyNumericOperator(binary->op, *left, *right, value)) {
                return value;
            }
        }
        if (fault_ == EvaluationFault::None) {
            fault_ = EvaluationFault::InvalidInput;
        }
        return std::nullopt;
    }

    // 输入目录ID，返回当前事件中的原文本字段或空；质量未知保持原值，坏形状/UTF-8设置原故障。
    const FieldSample* TextField(std::string_view id)
    {
        constexpr std::size_t MaxLookups = 9; // 与已有字段查找相同的预算上界。
        if (!fields_.empty() && !Spend(MaxLookups * (1 + MaxKeyBytes)))
        {
            return nullptr;
        }
        const auto found = std::lower_bound(fields_.begin(), fields_.end(), id,
            [](const FieldSample& field, std::string_view key) { return field.id < key; }); // 当前事件原字段。
        if (found == fields_.end() || found->id != id)
        {
            return nullptr; // 未投影不等于null或空字符串。
        }
        if (!ShapeMatches(*found, FieldType::Text))
        {
            fault_ = EvaluationFault::InvalidInput;
            return nullptr;
        }
        const auto* text = std::get_if<std::string_view>(&found->value); // 借用字段正文，比较期间不复制。
        if (text)
        {
            if (text->size() > MaxValueBytes)
            {
                fault_ = EvaluationFault::Budget;
                return nullptr;
            }
            if (!Spend(text->size()))
            {
                return nullptr;
            }
            if (!ValidUtf8(*text))
            {
                fault_ = EvaluationFault::InvalidInput;
                return nullptr;
            }
        }
        return &*found;
    }

    // 输入已准备的文本比较，按左到右读取双方；输出真/假/未知，显式null与未采集分别处理。
    Truth CompareTextFields(const TextFieldComparison& comparison)
    {
        const auto* left = TextField(comparison.left); // 左字段的原值及采集质量。
        const auto* right = TextField(comparison.right); // 非短路读取右字段，复用首次故障及预算。
        if (!left || !right || fault_ != EvaluationFault::None)
        {
            return Truth::Unknown;
        }
        const bool leftComplete = left->quality == Quality::Known || left->quality == Quality::Null; // 左值是否完整。
        const bool rightComplete = right->quality == Quality::Known || right->quality == Quality::Null; // 右值是否完整。
        if (!leftComplete || !rightComplete)
        {
            return Truth::Unknown; // 两个截断前缀相同也不能认定完整文本相同。
        }
        bool equal = left->quality == right->quality; // 两个显式null相等，null与已知文本不相等。
        if (left->quality == Quality::Known && right->quality == Quality::Known)
        {
            const auto leftText = std::get<std::string_view>(left->value); // 已校验的完整UTF-8左值。
            const auto rightText = std::get<std::string_view>(right->value); // 已校验的完整UTF-8右值。
            if (!Spend(std::min(leftText.size(), rightText.size())))
            {
                return Truth::Unknown;
            }
            equal = leftText == rightText;
        }
        return AsTruth(comparison.op == FieldOp::Equal ? equal : !equal);
    }

    Truth Test(const FieldTest& test, FieldType type)
    {
        // 用固定上界计费，避免把字段查找视为零成本。
        constexpr std::size_t MaxLookups = 9; // 128 个字段的二分查找加最终比较
        if (!fields_.empty() && !Spend(MaxLookups * (1 + MaxKeyBytes))) {
            return Truth::Unknown;
        }
        const auto it = std::lower_bound(fields_.begin(), fields_.end(), test.field,
            [](const FieldSample& field, std::string_view id) { return field.id < id; });
        const FieldSample missing{test.field, Quality::NotCollected, std::monostate{}};
        const auto& field = it != fields_.end() && it->id == test.field ? *it : missing;
        if (!ShapeMatches(field, type)) {
            fault_ = EvaluationFault::InvalidInput;
            return Truth::Unknown;
        }
        // 质量和 null 测试只读取投影元数据，不扫描原值。
        const bool known = field.quality == Quality::Known;
        const bool isNull = field.quality == Quality::Null;
        if (test.op == FieldOp::IsKnown) {
            return AsTruth(known);
        }
        if (test.op == FieldOp::QualityEqual || test.op == FieldOp::QualityNotEqual) {
            const bool sameQuality = field.quality == std::get<Quality>(test.literal); // 仅比较采集标记。
            return AsTruth(test.op == FieldOp::QualityEqual ? sameQuality : !sameQuality);
        }
        if (test.op == FieldOp::IsNull) {
            return AsTruth(isNull);
        }
        if (test.op == FieldOp::IsComplete) {
            return AsTruth(known || isNull);
        }
        if (IsNullLiteral(test.literal)) {
            if (!known && !isNull) {
                return Truth::Unknown;
            }
            return AsTruth(test.op == FieldOp::Equal ? isNull : !isNull);
        }
        if (isNull && (test.op == FieldOp::Equal || test.op == FieldOp::NotEqual)) {
            return AsTruth(test.op == FieldOp::NotEqual);
        }
        if (const auto* text = std::get_if<std::string_view>(&field.value)) {
            // 文本扫描先计费，再按严格 UTF-8 和长度语义解释字节。
            if (text->size() > MaxValueBytes) {
                fault_ = EvaluationFault::Budget;
                return Truth::Unknown;
            }
            if (!Spend(text->size())) {
                return Truth::Unknown;
            }
            if (!ValidUtf8(*text)) {
                fault_ = EvaluationFault::InvalidInput;
                return Truth::Unknown;
            }
            return Text(test.op, *text, std::get<std::string>(test.literal), known);
        }
        if (!known) {
            return Truth::Unknown;
        }
        if (type == FieldType::Bool) {
            const auto equal = std::get<bool>(field.value) == std::get<bool>(test.literal);
            return AsTruth(test.op == FieldOp::Equal ? equal : !equal);
        }
        // 标量操作只比较已经检查过的同类型数据。
        const auto value = std::get<std::uint64_t>(field.value);
        const auto limit = std::get<std::uint64_t>(test.literal);
        switch (test.op) {
        case FieldOp::Equal: return AsTruth(value == limit);
        case FieldOp::NotEqual: return AsTruth(value != limit);
        case FieldOp::Less: return AsTruth(value < limit);
        case FieldOp::LessEqual: return AsTruth(value <= limit);
        case FieldOp::Greater: return AsTruth(value > limit);
        case FieldOp::GreaterEqual: return AsTruth(value >= limit);
        default: return Truth::Unknown;
        }
    }

    Truth Text(FieldOp op, std::string_view value, std::string_view pattern, bool complete)
    {
        // 截断状态下只采信已获前缀能直接证明的结果。
        const auto common = std::min(value.size(), pattern.size());
        switch (op) {
        case FieldOp::Equal: case FieldOp::NotEqual: {
            if (!Spend(common)) {
                return Truth::Unknown;
            }
            const auto equal = value.size() > pattern.size() || value.substr(0, common) != pattern.substr(0, common)
                ? Truth::False
                : (complete ? AsTruth(value.size() == pattern.size()) : Truth::Unknown);
            return op == FieldOp::Equal ? equal : Negate(equal);
        }
        case FieldOp::StartsWith:
            if (!Spend(common)) {
                return Truth::Unknown;
            }
            if (value.substr(0, common) != pattern.substr(0, common)) {
                return Truth::False;
            }
            return pattern.size() <= value.size() ? Truth::True : (complete ? Truth::False : Truth::Unknown);
        case FieldOp::EndsWith:
            if (!complete || !Spend(common)) {
                return Truth::Unknown;
            }
            return AsTruth(value.ends_with(pattern));
        case FieldOp::Contains:
            // 逐次匹配计费，最坏扫描量受本轮预算限制。
            if (pattern.empty()) {
                return Truth::True;
            }
            if (pattern.size() <= value.size()) {
                for (std::size_t offset = 0; offset <= value.size() - pattern.size(); ++offset) {
                    if (!Spend(1 + pattern.size())) {
                        return Truth::Unknown;
                    }
                    if (value.substr(offset, pattern.size()) == pattern) {
                        return Truth::True;
                    }
                }
            }
            return complete ? Truth::False : Truth::Unknown;
        default:
            return Truth::Unknown;
        }
    }

    std::span<const AstNode> nodes_;
    std::span<const FieldType> types_;
    std::span<const FieldSample> fields_;
    std::size_t limit_;
    std::size_t used_ = 0;
    EvaluationFault fault_ = EvaluationFault::None;
};

} // namespace

Preparation PreparePredicate(Phase phase, std::span<const FieldBinding> catalog,
                             std::span<const AstNode> nodes)
{
    if (!ValidPhase(phase)) {
        return {{}, PrepareError::InvalidPhase};
    }
    if (catalog.size() > MaxCatalogBindings) {
        return {{}, PrepareError::InvalidCatalog};
    }
    if (nodes.empty() || nodes.size() > MaxNodes) {
        return {{}, PrepareError::NodeLimit};
    }
    // 目录同字段可登记多个阶段，每个阶段的定义唯一。
    std::map<std::pair<std::string_view, Phase>, FieldType> bindings;
    for (const auto& field : catalog) {
        if (!ValidKey(field.id) || !ValidType(field.type) || !ValidPhase(field.phase) ||
            !bindings.emplace(std::pair{field.id, field.phase}, field.type).second) {
            return {{}, PrepareError::InvalidCatalog};
        }
    }

    // 后序树一次线性检查即可验证子节点方向、唯一父节点和深度。
    std::array<bool, MaxNodes> hasParent{};
    std::array<std::size_t, MaxNodes> depth{};
    std::vector<FieldType> types(nodes.size(), FieldType::Bool);
    std::vector<FieldType> outputs(nodes.size(), FieldType::Bool); // 节点输出类型，不混同旧字段原值类型。
    std::size_t literalBytes = 0;
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        const auto attach = [&](std::size_t child) {
            if (child >= i || hasParent[child]) {
                return false;
            }
            hasParent[child] = true;
            depth[i] = std::max(depth[i], depth[child]);
            return true;
        };
        const auto& node = nodes[i];
        if (const auto* negation = std::get_if<Not>(&node)) {
            if (!attach(negation->child)) {
                return {{}, PrepareError::InvalidTree, i};
            }
            if (outputs[negation->child] != FieldType::Bool) {
                return {{}, PrepareError::TypeMismatch, i};
            }
        } else if (const auto* logical = std::get_if<Logical>(&node)) {
            if (logical->op != Logic::And && logical->op != Logic::Or) {
                return {{}, PrepareError::UnsupportedOperator, i};
            }
            if (!attach(logical->left) || !attach(logical->right)) {
                return {{}, PrepareError::InvalidTree, i};
            }
            if (outputs[logical->left] != FieldType::Bool || outputs[logical->right] != FieldType::Bool) {
                return {{}, PrepareError::TypeMismatch, i};
            }
        } else if (const auto* binary = std::get_if<BooleanBinary>(&node)) {
            if (binary->op != BooleanBinaryOp::And && binary->op != BooleanBinaryOp::Xor &&
                binary->op != BooleanBinaryOp::Or && binary->op != BooleanBinaryOp::Equal &&
                binary->op != BooleanBinaryOp::NotEqual)
            {
                return {{}, PrepareError::UnsupportedOperator, i};
            }
            if (!attach(binary->left) || !attach(binary->right))
            {
                return {{}, PrepareError::InvalidTree, i};
            }
            if (outputs[binary->left] != FieldType::Bool || outputs[binary->right] != FieldType::Bool)
            {
                return {{}, PrepareError::TypeMismatch, i};
            }
        } else if (const auto* conditional = std::get_if<Conditional>(&node)) {
            // 所有分支均在准备时绑定和检查；运行时才按条件选择其中一个。
            if (!attach(conditional->condition) || !attach(conditional->whenTrue) ||
                !attach(conditional->whenFalse)) {
                return {{}, PrepareError::InvalidTree, i};
            }
            const auto branchType = outputs[conditional->whenTrue];
            if (outputs[conditional->condition] != FieldType::Bool ||
                branchType != outputs[conditional->whenFalse] ||
                (branchType != FieldType::Bool && branchType != FieldType::U64)) {
                return {{}, PrepareError::TypeMismatch, i};
            }
            outputs[i] = branchType;
        } else if (std::holds_alternative<NumericLiteral>(node)) {
            outputs[i] = FieldType::U64;
        } else if (const auto* reference = std::get_if<NumericField>(&node)) {
            if (!ValidKey(reference->field)) {
                return {{}, PrepareError::UnknownField, i};
            }
            const auto binding = bindings.find({reference->field, phase});
            if (binding == bindings.end()) {
                const auto first = bindings.lower_bound({reference->field, Phase::Entry});
                return {{}, first == bindings.end() || first->first.first != reference->field
                    ? PrepareError::UnknownField : PrepareError::FieldNotInPhase, i};
            }
            if (binding->second != FieldType::U64) {
                return {{}, PrepareError::TypeMismatch, i};
            }
            outputs[i] = FieldType::U64;
            types[i] = FieldType::U64;
        } else if (const auto* unary = std::get_if<NumericUnary>(&node)) {
            if (!IsValidNumericOperator(unary->op)) {
                return {{}, PrepareError::UnsupportedOperator, i};
            }
            if (!attach(unary->child)) {
                return {{}, PrepareError::InvalidTree, i};
            }
            if (outputs[unary->child] != FieldType::U64) {
                return {{}, PrepareError::TypeMismatch, i};
            }
            outputs[i] = FieldType::U64;
        } else if (const auto* binary = std::get_if<NumericBinary>(&node)) {
            if (!IsValidNumericOperator(binary->op)) {
                return {{}, PrepareError::UnsupportedOperator, i};
            }
            if (!attach(binary->left) || !attach(binary->right)) {
                return {{}, PrepareError::InvalidTree, i};
            }
            if (outputs[binary->left] != FieldType::U64 || outputs[binary->right] != FieldType::U64) {
                return {{}, PrepareError::TypeMismatch, i};
            }
            outputs[i] = FieldType::U64;
        } else if (const auto* comparison = std::get_if<NumericComparison>(&node)) {
            if (comparison->op < FieldOp::Equal || comparison->op > FieldOp::GreaterEqual) {
                return {{}, PrepareError::UnsupportedOperator, i};
            }
            if (!attach(comparison->left) || !attach(comparison->right)) {
                return {{}, PrepareError::InvalidTree, i};
            }
            if (outputs[comparison->left] != FieldType::U64 || outputs[comparison->right] != FieldType::U64) {
                return {{}, PrepareError::TypeMismatch, i};
            }
        } else if (const auto* comparison = std::get_if<TextFieldComparison>(&node)) {
            // 文本比较是布尔叶节点；同时核对两字段及当前阶段，不能按运行值临时决定类型。
            if (comparison->op != FieldOp::Equal && comparison->op != FieldOp::NotEqual)
            {
                return {{}, PrepareError::UnsupportedOperator, i};
            }
            for (const auto field : {std::string_view(comparison->left), std::string_view(comparison->right)}) // 借用当前需要绑定的字段ID。
            {
                if (!ValidKey(field))
                {
                    return {{}, PrepareError::UnknownField, i};
                }
                const auto binding = bindings.find({field, phase}); // 字段在本次事件阶段的静态类型。
                if (binding == bindings.end())
                {
                    const auto first = bindings.lower_bound({field, Phase::Entry}); // 区分未登记与阶段不可用。
                    return {{}, first == bindings.end() || first->first.first != field
                        ? PrepareError::UnknownField : PrepareError::FieldNotInPhase, i};
                }
                if (binding->second != FieldType::Text)
                {
                    return {{}, PrepareError::TypeMismatch, i};
                }
            }
        } else if (const auto* test = std::get_if<FieldTest>(&node)) {
            if (!ValidKey(test->field)) {
                return {{}, PrepareError::UnknownField, i};
            }
            const auto binding = bindings.find({test->field, phase});
            // 区分未知字段与已登记但当前阶段无法访问的字段。
            if (binding == bindings.end()) {
                const auto first = bindings.lower_bound({test->field, Phase::Entry});
                const auto error = first == bindings.end() || first->first.first != test->field
                    ? PrepareError::UnknownField : PrepareError::FieldNotInPhase;
                return {{}, error, i};
            }
            const auto error = CheckTest(*test, binding->second);
            if (error != PrepareError::None) {
                return {{}, error, i};
            }
            if (const auto* text = std::get_if<std::string>(&test->literal)) {
                if (text->size() > MaxLiteralBytes - literalBytes) {
                    return {{}, PrepareError::LiteralLimit, i};
                }
                literalBytes += text->size();
                if (!ValidUtf8(*text)) {
                    return {{}, PrepareError::InvalidUtf8, i};
                }
            }
            types[i] = binding->second;
        } else if (!std::holds_alternative<bool>(node)) {
            return {{}, PrepareError::InvalidTree, i};
        }
        if (++depth[i] > MaxDepth) {
            return {{}, PrepareError::DepthLimit, i};
        }
    }
    if (outputs.back() != FieldType::Bool) {
        return {{}, PrepareError::TypeMismatch, nodes.size() - 1};
    }
    for (std::size_t i = 0; i + 1 < nodes.size(); ++i) {
        if (!hasParent[i]) {
            return {{}, PrepareError::InvalidTree, i};
        }
    }
    Preparation prepared;
    // 在所有检查通过后才复制和发布准备结果。
    prepared.predicate.phase_ = phase;
    prepared.predicate.nodes_.assign(nodes.begin(), nodes.end());
    prepared.predicate.types_ = std::move(types);
    return prepared;
}

Evaluation EvaluatePredicate(const PreparedPredicate& predicate, Phase phase,
                             std::span<const FieldSample> fields, std::size_t workLimit)
{
    if (!predicate.valid() || predicate.phase_ != phase) {
        return {Truth::Unknown, EvaluationFault::InvalidInput, 0};
    }
    return Evaluator(predicate.nodes_, predicate.types_, fields,
                     std::min(workLimit, MaxPredicateWork)).Run();
}

// CLI、归档和桌面可共用稳定故障 ID，避免把算术故障误报为坏输入。
std::string_view EvaluationFaultId(EvaluationFault fault) noexcept
{
    switch (fault) {
    case EvaluationFault::None: return {};
    case EvaluationFault::InvalidInput: return "invalid-input";
    case EvaluationFault::Budget: return "budget";
    case EvaluationFault::DivisionByZero: return "division-by-zero";
    }
    return "invalid-input";
}

} // namespace Ksword::ActionAnalyze::Rules
