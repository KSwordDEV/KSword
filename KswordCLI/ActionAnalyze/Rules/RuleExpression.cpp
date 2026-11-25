#include "RuleExpression.h"

#include <charconv>
#include <optional>
#include <utility>

namespace Ksword::ActionAnalyze::Rules {
namespace {

constexpr std::size_t MaxNodes = 512; // 与现有 AST 的准备上限一致。
constexpr std::size_t MaxNesting = 32; // 独立限制括号和前缀操作符的解析栈。

struct TokenRange {
    std::size_t begin;
    std::size_t end;
};

struct FunctionSpec {
    std::string_view name; // 大小写敏感的完整函数名。
    FieldOp op; // 直接绑定现有解释器的操作。
    bool takesText; // 文本函数要求一个字符串常量，质量函数只接收字段。
};

constexpr FunctionSpec Functions[] = {
    {"Text.Contains", FieldOp::Contains, true},
    {"Text.StartsWith", FieldOp::StartsWith, true},
    {"Text.EndsWith", FieldOp::EndsWith, true},
    {"Text.Equals", FieldOp::Equal, true},
    {"isKnown", FieldOp::IsKnown, false},
    {"isNull", FieldOp::IsNull, false},
    {"isComplete", FieldOp::IsComplete, false},
};

// 状态名与归档质量目录一致。只解释有限关键字，保留大小写。
std::optional<Quality> QualityByName(std::string_view name)
{
    constexpr std::pair<std::string_view, Quality> names[] = {
        {"known", Quality::Known}, {"null", Quality::Null}, {"notCollected", Quality::NotCollected},
        {"unsupported", Quality::Unsupported}, {"accessDenied", Quality::AccessDenied},
        {"readFailed", Quality::ReadFailed}, {"truncated", Quality::Truncated},
        {"decodeFailed", Quality::DecodeFailed}, {"redacted", Quality::Redacted},
    }; // 仅接受协议中明确登记的状态。
    for (const auto& [word, quality] : names) {
        if (name == word) {
            return quality;
        }
    }
    return std::nullopt;
}

// 所有标识符按固定 ASCII 规则解释，不受系统区域设置影响。
bool IdentifierStart(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_';
}

bool Digit(char ch)
{
    return ch >= '0' && ch <= '9';
}

bool HexDigit(char ch)
{
    return Digit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

// 已验证的 Unicode 标量转为 UTF-8。NUL 保留在值内，后续按长度比较。
void AppendScalar(std::string& text, unsigned scalar)
{
    if (scalar <= 0x7F) {
        text.push_back(static_cast<char>(scalar));
    } else if (scalar <= 0x7FF) {
        text.push_back(static_cast<char>(0xC0u | (scalar >> 6)));
    } else if (scalar <= 0xFFFF) {
        text.push_back(static_cast<char>(0xE0u | (scalar >> 12)));
    } else {
        text.push_back(static_cast<char>(0xF0u | (scalar >> 18)));
        text.push_back(static_cast<char>(0x80u | ((scalar >> 12) & 0x3Fu)));
    }
    if (scalar > 0x7FF) {
        text.push_back(static_cast<char>(0x80u | ((scalar >> 6) & 0x3Fu)));
    }
    if (scalar > 0x7F) {
        text.push_back(static_cast<char>(0x80u | (scalar & 0x3Fu)));
    }
}

// 将表达式内字节范围转换为位置，CRLF 只占一个换行。
ExpressionLocation Locate(std::string_view source, TokenRange range)
{
    ExpressionLocation location{range.begin, range.end - range.begin}; // 诊断的累计行、列。
    for (std::size_t i = 0; i < range.begin; ++i) {
        if (source[i] == '\r' || source[i] == '\n') {
            if (source[i] == '\n' && i != 0 && source[i - 1] == '\r') {
                continue;
            }
            ++location.line;
            location.byteColumn = 1;
        } else {
            ++location.byteColumn;
        }
    }
    return location;
}

class Parser {
public:
    // 调用期间借用输入表达式。解析中生成节点，准备完成后由结果持有 AST。
    explicit Parser(std::string_view source) : source_(source) {}

    ExpressionPreparation Run(Phase phase, std::span<const FieldBinding> catalog)
    {
        if (!Disjunction(0)) {
            return result_;
        }
        SkipSpace();
        if (position_ != source_.size()) {
            Fail(ExpressionError::UnexpectedToken, Here());
            return result_;
        }
        // 静态验证整个树，包括运行时可能短路的分支。
        auto checked = PreparePredicate(phase, catalog, nodes_); // 现有类型检查及已准备的 AST。
        if (checked.error != PrepareError::None) {
            const bool global = checked.error == PrepareError::InvalidPhase ||
                checked.error == PrepareError::InvalidCatalog; // 两类错误属于调用上下文。
            Fail(ExpressionError::PreparationFailed, global ? TokenRange{0, 0} : ranges_.at(checked.node));
            result_.preparationError = checked.error;
        } else {
            result_.predicate = std::move(checked.predicate);
        }
        return std::move(result_);
    }

private:
    // 保留第一个错误。EOF 使用零长度定位。
    bool Fail(ExpressionError error, TokenRange range)
    {
        if (result_.error == ExpressionError::None) {
            result_.error = error;
            result_.location = Locate(source_, range);
        }
        return false;
    }

    TokenRange Here() const
    {
        return {position_, position_ < source_.size() ? position_ + 1 : position_};
    }

    // 语法空白只接受空格、制表符和标准行结束符。
    void SkipSpace()
    {
        while (position_ < source_.size()) {
            const char ch = source_[position_]; // 正在检查的空白字节。
            if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
                break;
            }
            ++position_;
        }
    }

    bool Take(std::string_view token)
    {
        SkipSpace();
        if (!source_.substr(position_).starts_with(token)) {
            return false;
        }
        position_ += token.size();
        return true;
    }

    // 每个节点记录诊断来源。使用后序索引把相同表达式直接交给已有解释器。
    bool Emit(AstNode node, TokenRange range)
    {
        if (nodes_.size() == MaxNodes) {
            return Fail(ExpressionError::NodeLimit, range);
        }
        nodes_.push_back(std::move(node));
        ranges_.push_back(range);
        return true;
    }

    bool Disjunction(std::size_t nesting)
    {
        return Binary(nesting, "||", Logic::Or, &Parser::Conjunction);
    }

    bool Conjunction(std::size_t nesting)
    {
        return Binary(nesting, "&&", Logic::And, &Parser::PredicateOperand);
    }

    // 同优先级二元连接左结合。循环防止长链消耗解析栈。
    using ParseOperand = bool (Parser::*)(std::size_t);
    bool Binary(std::size_t nesting, std::string_view token, Logic op, ParseOperand operand)
    {
        if (!(this->*operand)(nesting)) {
            return false;
        }
        while (Take(token)) {
            const TokenRange range{position_ - token.size(), position_}; // 当前连接符。
            const auto left = nodes_.size() - 1; // 左子树根。
            if (!(this->*operand)(nesting) || !Emit(Logical{op, left, nodes_.size() - 1}, range)) {
                return false;
            }
        }
        return true;
    }

    // 比较绑定于这个级别。非号在 C# 中优先于比较；否定比较必须显式加括号。
    bool PredicateOperand(std::size_t nesting)
    {
        return Unary(nesting, true);
    }

    bool Unary(std::size_t nesting, bool allowComparison)
    {
        SkipSpace();
        const auto site = Here(); // 前缀操作符或括号的诊断位置。
        if (nesting > MaxNesting) {
            return Fail(ExpressionError::NestingLimit, site);
        }
        if (!source_.substr(position_).starts_with("!=") && Take("!")) {
            return Unary(nesting + 1, false) && Emit(Not{nodes_.size() - 1}, site);
        }
        if (Take("(")) {
            return Disjunction(nesting + 1) &&
                (Take(")") || Fail(ExpressionError::ExpectedCloseParen, Here()));
        }
        return Atom(allowComparison);
    }

    // 读取不含空白的点分字段路径或函数标识符，并拒绝空片段。
    bool Path(TokenRange& range, ExpressionError missing)
    {
        SkipSpace();
        range.begin = position_;
        if (position_ == source_.size() || !IdentifierStart(source_[position_])) {
            return Fail(missing, Here());
        }
        for (;;) {
            ++position_;
            while (position_ < source_.size() &&
                (IdentifierStart(source_[position_]) || Digit(source_[position_]))) {
                ++position_;
            }
            if (position_ == source_.size() || source_[position_] != '.') {
                range.end = position_;
                return true;
            }
            ++position_;
            if (position_ == source_.size() || !IdentifierStart(source_[position_])) {
                return Fail(ExpressionError::InvalidFieldPath, Here());
            }
        }
    }

    // 比较的左侧为字段，右侧为字面量。裸布尔字段用已类型化的等于 true 表示。
    bool Atom(bool allowComparison)
    {
        TokenRange range{}; // 字段或函数名的字节范围。
        if (!Path(range, ExpressionError::ExpectedPredicate)) {
            return false;
        }
        const auto name = TextAt(range); // 原文中的字段或白名单函数名称。
        if (name == "true" || name == "false") {
            return Emit(name == "true", range);
        }
        if (name == "null") {
            return Fail(ExpressionError::ExpectedPredicate, range);
        }
        if (Take("(")) {
            if (name == "quality") {
                return allowComparison
                    ? QualityComparison()
                    : Fail(ExpressionError::ExpectedQualityComparison, range);
            }
            return Call(name, range);
        }
        const auto op = allowComparison ? Comparison() : std::nullopt; // 裸字段必须是 Bool。
        Literal literal = true; // 布尔简写的右侧值。
        if (op && !ReadLiteral(literal)) {
            return false;
        }
        return Emit(FieldTest{op.value_or(FieldOp::Equal), std::string(name), std::move(literal)}, range);
    }

    std::optional<FieldOp> Comparison()
    {
        constexpr std::pair<std::string_view, FieldOp> operators[] = {
            {"==", FieldOp::Equal}, {"!=", FieldOp::NotEqual}, {"<=", FieldOp::LessEqual},
            {">=", FieldOp::GreaterEqual}, {"<", FieldOp::Less}, {">", FieldOp::Greater}
        }; // 先尝试长操作符，避免将 <= 切成两个符号。
        for (const auto& [token, op] : operators) {
            if (Take(token)) {
                return op;
            }
        }
        return std::nullopt;
    }

    // 白名单调用的唯一字段参数，关键字不能当作证据字段。
    bool FieldArgument(TokenRange& field)
    {
        if (!Path(field, ExpressionError::InvalidFieldPath)) {
            return false;
        }
        const auto id = TextAt(field); // 目录绑定按原文大小写。
        if (id == "true" || id == "false" || id == "null") {
            return Fail(ExpressionError::InvalidFieldPath, field);
        }
        return true;
    }

    // quality(field) 只能作为有限枚举的相等比较，不生成可执行函数。
    bool QualityComparison()
    {
        TokenRange field{}; // 目录或阶段失败时定位字段参数。
        if (!FieldArgument(field)) {
            return false;
        }
        if (!Take(")")) {
            return Fail(ExpressionError::ExpectedCloseParen, Here());
        }
        SkipSpace();
        const auto operatorSite = Here(); // 缺失或不受支持的比较符位置。
        const auto op = Comparison(); // 只接受 == 或 !=，不赋予状态排序语义。
        if (op != FieldOp::Equal && op != FieldOp::NotEqual) {
            return Fail(ExpressionError::ExpectedQualityComparison,
                op ? TokenRange{operatorSite.begin, position_} : operatorSite);
        }
        SkipSpace();
        const auto stateStart = position_; // 未登记的状态定位到完整字面量。
        std::string state; // 复用普通和逐字字符串的解码规则。
        if (!ReadString(state)) {
            return false;
        }
        const auto quality = QualityByName(state); // 准备时绑定规范的状态枚举。
        if (!quality) {
            return Fail(ExpressionError::InvalidQuality, {stateStart, position_});
        }
        const auto qualityOp = *op == FieldOp::Equal ? FieldOp::QualityEqual : FieldOp::QualityNotEqual; // AST 中的质量比较。
        return Emit(FieldTest{qualityOp, std::string(TextAt(field)), *quality}, field);
    }

    // 调用句法只生成字段测试节点，不存在动态成员分派或用户方法。
    bool Call(std::string_view name, TokenRange site)
    {
        for (const auto& function : Functions) {
            if (name != function.name) {
                continue;
            }
            TokenRange field{}; // 第一个参数为字段路径。
            if (!FieldArgument(field)) {
                return false;
            }
            Literal literal; // 质量检查无第二参数，文本检查需要字符串。
            if (function.takesText) {
                std::string text; // 已解码的 UTF-8 字面量。
                if (!Take(",")) {
                    return Fail(ExpressionError::ExpectedComma, Here());
                }
                if (!ReadString(text)) {
                    return false;
                }
                literal = std::move(text);
            }
            if (!Take(")")) {
                return Fail(ExpressionError::ExpectedCloseParen, Here());
            }
            return Emit(FieldTest{function.op, std::string(TextAt(field)), std::move(literal)}, field);
        }
        return Fail(ExpressionError::UnsupportedCall, site);
    }

    std::string_view TextAt(TokenRange range) const
    {
        return source_.substr(range.begin, range.end - range.begin);
    }

    // 其余字面量函数处理整数、布尔、null 和 UTF-8 文本。
    bool ReadLiteral(Literal& value);
    bool ReadNumber(Literal& value);
    bool ReadString(std::string& text);
    bool Escape(std::string& text, std::size_t start);
    bool UnicodeEscape(std::string& text, std::size_t start, std::size_t digits);
    bool HexEscape(unsigned& value, std::size_t digits);

    std::string_view source_; // 调用方持有的原始 UTF-8 字节。
    std::size_t position_ = 0; // 下一个未消费字节。
    ExpressionPreparation result_; // 只在解析完成后发布已准备的谓词。
    std::vector<AstNode> nodes_; // 紧凑后序树，根为最后一个节点。
    std::vector<TokenRange> ranges_; // 与节点一一对应的表达式来源。
};

// 排除用户定义的常量。同名的函数、字段、数字后缀都不能用作右侧字面量。
bool Parser::ReadLiteral(Literal& value)
{
    SkipSpace();
    const auto input = source_.substr(position_); // 尚未消费的右操作数与其后的表达式。
    if (input.empty()) {
        return Fail(ExpressionError::ExpectedLiteral, Here());
    }
    if (input.front() == '"' || input.front() == '@') {
        std::string text; // 字面量解码结果，成功才转交节点。
        if (!ReadString(text)) {
            return false;
        }
        value = std::move(text);
        return true;
    }
    if (Digit(input.front())) {
        return ReadNumber(value);
    }
    TokenRange range{}; // 布尔或 null 关键字的完整位置。
    if (!Path(range, ExpressionError::ExpectedLiteral)) {
        return false;
    }
    const auto keyword = TextAt(range); // 按完整标识符比较，禁止关键字前缀。
    if (keyword == "true" || keyword == "false") {
        value = keyword == "true";
    } else if (keyword == "null") {
        value = std::monostate{};
    } else {
        return Fail(ExpressionError::ExpectedLiteral, range);
    }
    return true;
}

// 十进制和 0x 十六进制均要求显式 u64 后缀。使用 from_chars 无损验证全宽度。
bool Parser::ReadNumber(Literal& value)
{
    const auto start = position_; // 包括前缀与后缀在内的诊断起始位置。
    const bool hex = source_.substr(position_).starts_with("0x"); // 字面量的基数。
    if (hex) {
        position_ += 2;
    }
    const auto first = position_; // 去掉基数前缀的第一位。
    while (position_ < source_.size() && (hex ? HexDigit(source_[position_]) : Digit(source_[position_]))) {
        ++position_;
    }
    const auto last = position_; // 数字部分结束，不允许数字与后缀之间有空白。
    if (first == last || !source_.substr(position_).starts_with("u64")) {
        return Fail(ExpressionError::InvalidNumber, {start, position_});
    }
    position_ += 3;
    if (position_ < source_.size() &&
        (IdentifierStart(source_[position_]) || Digit(source_[position_]))) {
        return Fail(ExpressionError::InvalidNumber, {start, position_ + 1});
    }
    std::uint64_t number = 0; // 通过检查后进入类型化节点的数值。
    const auto end = source_.data() + last; // 检查数值部分是否全部消耗。
    const auto parsed = std::from_chars(source_.data() + first, end, number, hex ? 16 : 10);
    if (parsed.ec == std::errc::result_out_of_range) {
        return Fail(ExpressionError::NumericOverflow, {start, position_});
    }
    if (parsed.ec != std::errc{} || parsed.ptr != end) {
        return Fail(ExpressionError::InvalidNumber, {start, position_});
    }
    value = number;
    return true;
}

// 普通字符串采用明确转义表。逐字字符串只处理成对双引号。
bool Parser::ReadString(std::string& text)
{
    SkipSpace();
    const auto start = position_; // 开始引号的位置，包括逐字字符串前缀。
    const bool verbatim = Take("@\""); // 不接受 @ 与引号之间的空白。
    if (!verbatim && !Take("\"")) {
        return Fail(ExpressionError::ExpectedLiteral, Here());
    }
    while (position_ < source_.size()) {
        const auto here = position_; // 处理前记录转义或错误字符起点。
        const char ch = source_[position_++]; // 当前原始字节。
        if (ch == '"') {
            if (!verbatim || position_ == source_.size() || source_[position_] != '"') {
                return true;
            }
            ++position_;
            text.push_back('"');
        } else if (!verbatim && ch == '\\') {
            if (!Escape(text, here)) {
                return false;
            }
        } else {
            // 普通字符串只允许转义后的控制字符。逐字形式允许原始制表和换行。
            if (static_cast<unsigned char>(ch) < 0x20 &&
                !(verbatim && (ch == '\t' || ch == '\r' || ch == '\n'))) {
                return Fail(ExpressionError::InvalidString, {here, position_});
            }
            text.push_back(ch);
        }
    }
    return Fail(ExpressionError::InvalidString, {start, position_});
}

// 转义表从 ASCII 标记生成固定字符。Unicode 解码使用专用标量处理。
bool Parser::Escape(std::string& text, std::size_t start)
{
    if (position_ == source_.size()) {
        return Fail(ExpressionError::InvalidString, {start, position_});
    }
    const char escaped = source_[position_++]; // 反斜杠之后的语法字符。
    switch (escaped) {
    case '\\': text.push_back('\\'); break;
    case '"': text.push_back('"'); break;
    case '\'': text.push_back('\''); break;
    case '0': text.push_back('\0'); break;
    case 'a': text.push_back('\a'); break;
    case 'b': text.push_back('\b'); break;
    case 'f': text.push_back('\f'); break;
    case 'n': text.push_back('\n'); break;
    case 'r': text.push_back('\r'); break;
    case 't': text.push_back('\t'); break;
    case 'v': text.push_back('\v'); break;
    case 'u': return UnicodeEscape(text, start, 4);
    case 'U': return UnicodeEscape(text, start, 8);
    default: return Fail(ExpressionError::UnsupportedEscape, {start, position_});
    }
    return true;
}

// \u 的高低代理项必须相邻配对。\U 直接要求合法标量。
bool Parser::UnicodeEscape(std::string& text, std::size_t start, std::size_t digits)
{
    unsigned scalar = 0; // 最初可能是 UTF-16 高代理项，写入前必须成为合法标量。
    if (!HexEscape(scalar, digits)) {
        return Fail(ExpressionError::InvalidString, {start, position_});
    }
    if (digits == 4 && scalar >= 0xD800 && scalar <= 0xDBFF &&
        source_.substr(position_).starts_with("\\u")) {
        position_ += 2;
        unsigned tail = 0; // 高代理项后必须紧跟有效的低代理项。
        if (!HexEscape(tail, 4) || tail < 0xDC00 || tail > 0xDFFF) {
            return Fail(ExpressionError::InvalidString, {start, position_});
        }
        scalar = 0x10000u + ((scalar - 0xD800u) << 10) + (tail - 0xDC00u);
    }
    if (scalar > 0x10FFFFu || (scalar >= 0xD800 && scalar <= 0xDFFF)) {
        return Fail(ExpressionError::InvalidString, {start, position_});
    }
    AppendScalar(text, scalar);
    return true;
}

// 读取固定长度十六进制转义。格式不符时消费到遇到的首个坏字节之前。
bool Parser::HexEscape(unsigned& value, std::size_t digits)
{
    const auto first = position_; // 方便将验证后的连续十六进制数字直接转换。
    for (std::size_t index = 0; index < digits; ++index) {
        if (position_ == source_.size() || !HexDigit(source_[position_])) {
            return false;
        }
        ++position_;
    }
    const auto end = source_.data() + position_; // 只转换已证明属于本转义的字节。
    const auto parsed = std::from_chars(source_.data() + first, end, value, 16);
    return parsed.ec == std::errc{} && parsed.ptr == end;
}

} // namespace

ExpressionPreparation PreparePredicateExpression(std::string_view source, Phase phase,
    std::span<const FieldBinding> catalog)
{
    if (source.size() > MaxPredicateExpressionBytes) {
        ExpressionPreparation result; // 超长输入不进入词法分析。
        result.error = ExpressionError::TextLimit;
        result.location = Locate(source, {MaxPredicateExpressionBytes, source.size()});
        return result;
    }
    return Parser(source).Run(phase, catalog);
}

std::string_view ExpressionErrorId(ExpressionError error) noexcept
{
    switch (error) {
    case ExpressionError::None: return {};
    case ExpressionError::TextLimit: return "expression-byte-limit";
    case ExpressionError::ExpectedPredicate: return "expression-expected-predicate";
    case ExpressionError::ExpectedLiteral: return "expression-expected-literal";
    case ExpressionError::ExpectedCloseParen: return "expression-expected-close-paren";
    case ExpressionError::ExpectedComma: return "expression-expected-comma";
    case ExpressionError::UnexpectedToken: return "expression-unexpected-token";
    case ExpressionError::InvalidFieldPath: return "expression-invalid-field-path";
    case ExpressionError::UnsupportedCall: return "expression-unsupported-function";
    case ExpressionError::InvalidNumber: return "expression-invalid-u64";
    case ExpressionError::NumericOverflow: return "expression-u64-overflow";
    case ExpressionError::InvalidString: return "expression-invalid-string";
    case ExpressionError::UnsupportedEscape: return "expression-unsupported-escape";
    case ExpressionError::NestingLimit: return "expression-nesting-limit";
    case ExpressionError::NodeLimit: return "expression-node-limit";
    case ExpressionError::PreparationFailed: return "expression-preparation-failed";
    case ExpressionError::ExpectedQualityComparison: return "expression-expected-quality-comparison";
    case ExpressionError::InvalidQuality: return "expression-invalid-quality";
    }
    return "expression-invalid";
}

} // namespace Ksword::ActionAnalyze::Rules
