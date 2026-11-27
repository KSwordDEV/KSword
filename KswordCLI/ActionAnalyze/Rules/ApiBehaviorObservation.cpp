#include "ApiBehaviorObservation.h"

#include <initializer_list>
#include <iterator>
#include <utility>

namespace Ksword::ActionAnalyze::Rules {
namespace {

// 固定布局中的一个字段：空 id 只校验而不发布；末尾文本没有结束证据，不允许发布。
enum class Encoding { Text, Decimal, Hex };
struct Part {
    std::wstring_view prefix; // 原生产 formatter 的固定字段前缀。
    Encoding encoding; // 原参数的实际编码。
    std::string_view id{}; // 对外字段 ID；选定文本由比较投影器另发 ASCII 小写字段。
};

// 有界转换 UTF-16，不使用本机代码页解释归档。ANSI 只接受无损的 ASCII 子集。
std::optional<std::string> Utf8(std::wstring_view text, bool ansi)
{
    std::string result; // 本次字符串的拥有型 UTF-8 数据。
    for (std::size_t index = 0; index < text.size(); ++index) {
        std::uint32_t code = static_cast<std::uint16_t>(text[index]); // 当前 Unicode 码点。
        if (code < 0x20 || code == 0x7f || code == L'=' || code == L'<' || code == L'>') {
            return std::nullopt; // 不接受不可读标记、控制字符或可伪造布局的字段分隔。
        }
        if (ansi && code >= 0x80) {
            return std::nullopt; // 旧 ANSI formatter 逐字节扩展，未归档 ACP，不能恢复中文。
        }
        if (code >= 0xd800 && code <= 0xdbff) {
            if (++index == text.size()) {
                return std::nullopt;
            }
            const auto low = static_cast<std::uint16_t>(text[index]); // 代理对的低半部分。
            if (low < 0xdc00 || low > 0xdfff) {
                return std::nullopt;
            }
            code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
        } else if (code >= 0xdc00 && code <= 0xdfff) {
            return std::nullopt;
        }
        // 显式编码，避免平台字符串转换引入替换字符后被当作精确匹配。
        if (code < 0x80) {
            result.push_back(static_cast<char>(code));
        } else if (code < 0x800) {
            result.push_back(static_cast<char>(0xc0 | (code >> 6)));
            result.push_back(static_cast<char>(0x80 | (code & 63)));
        } else if (code < 0x10000) {
            result.push_back(static_cast<char>(0xe0 | (code >> 12)));
            result.push_back(static_cast<char>(0x80 | ((code >> 6) & 63)));
            result.push_back(static_cast<char>(0x80 | (code & 63)));
        } else {
            result.push_back(static_cast<char>(0xf0 | (code >> 18)));
            result.push_back(static_cast<char>(0x80 | ((code >> 12) & 63)));
            result.push_back(static_cast<char>(0x80 | ((code >> 6) & 63)));
            result.push_back(static_cast<char>(0x80 | (code & 63)));
        }
    }
    return result;
}

// 只折叠 ASCII 大写，不依赖系统区域或静默改写非 ASCII 码点。
std::string Lower(std::string value)
{
    for (auto& character : value) {
        if (character >= 'A' && character <= 'Z') {
            character += 'a' - 'A';
        }
    }
    return value;
}

// 消费整个数字片段。溢出、负号、空白及非法尾字符均拒绝，不使用宽松的 strtoull。
std::optional<std::uint64_t> Number(std::wstring_view value, Encoding encoding)
{
    const auto base = encoding == Encoding::Hex ? 16u : 10u; // 此 formatter 的基数。
    if (base == 16) {
        if (!value.starts_with(L"0x")) {
            return std::nullopt;
        }
        value.remove_prefix(2);
    }
    if (value.empty()) {
        return std::nullopt;
    }
    std::uint64_t result = 0; // 已验证数字前缀的值。
    for (const auto character : value) {
        const unsigned digit = character >= L'0' && character <= L'9' ? character - L'0' :
            character >= L'A' && character <= L'F' ? character - L'A' + 10 :
            character >= L'a' && character <= L'f' ? character - L'a' + 10 : 16u;
        if (digit >= base || result > (UINT64_MAX - digit) / base) {
            return std::nullopt;
        }
        result = result * base + digit;
    }
    return result;
}

// 生成包装器在 formatter 后追加最多八个入口槽值；逐项验证而不把地址解释成字符串。
std::optional<std::wstring_view> WithoutArguments(std::wstring_view detail, unsigned count)
{
    constexpr std::wstring_view prefixes[] = {L" arg1=", L" arg2=", L" arg3=", L" arg4=",
        L" arg5=", L" arg6=", L" arg7=", L" arg8="}; // 生成器的固定尾字段顺序。
    if (!count || count > std::size(prefixes)) {
        return std::nullopt;
    }
    const auto first = detail.find(prefixes[0]); // 原 formatter 与生成尾部的边界。
    if (first == detail.npos) {
        return std::nullopt;
    }
    auto tail = detail.substr(first); // 必须全部消费且不接受重排、缺项或额外字段。
    for (unsigned index = 0; index < count; ++index) {
        if (!tail.starts_with(prefixes[index])) {
            return std::nullopt;
        }
        tail.remove_prefix(prefixes[index].size());
        const auto end = index + 1 == count ? tail.size() : tail.find(prefixes[index + 1]); // 此槽的完整值。
        if (end == tail.npos || !Number(tail.substr(0, end), Encoding::Hex)) {
            return std::nullopt;
        }
        tail.remove_prefix(end);
    }
    return tail.empty() ? std::optional{detail.substr(0, first)} : std::nullopt;
}

// 严格消费该 API 的完整格式。失败不发布任何参数，返回观察仍可独立保留。
bool Layout(ApiBehaviorObservation& result, std::wstring_view detail, bool ansi,
    std::initializer_list<Part> parts)
{
    std::vector<ApiBehaviorParameter> fields; // 仅在完整格式通过后提交。
    const auto* part = parts.begin(); // 当前 formatter 字段。
    for (; part != parts.end(); ++part) {
        if (!detail.starts_with(part->prefix)) {
            return false;
        }
        detail.remove_prefix(part->prefix.size());
        const bool last = part + 1 == parts.end(); // 最后一个字段必须是数值，文本需要后继分隔。
        const auto end = last ? detail.size() : detail.find((part + 1)->prefix); // 该字段的唯一合法后继边界。
        if (end == detail.npos || (last && part->encoding == Encoding::Text)) {
            return false;
        }
        const auto value = detail.substr(0, end); // 本字段的完整有界片段。
        if (part->encoding == Encoding::Text) {
            const auto text = Utf8(value, ansi); // 拒绝歧义分隔、非法代理和不可读标记。
            if (!text) {
                return false;
            }
            if (!part->id.empty() && !text->empty()) {
                fields.push_back({part->id, *text});
            }
        } else {
            const auto number = Number(value, part->encoding); // 必须消费全字段。
            if (!number) {
                return false;
            }
            if (!part->id.empty()) {
                fields.push_back({part->id, *number});
            }
        }
        detail.remove_prefix(end);
    }
    if (!detail.empty()) {
        return false;
    }
    result.parameters = std::move(fields);
    return true;
}

// 从显式根键与子键组成规范比较值；不查询当前注册表，也不解析历史普通句柄。
void RegistryPath(ApiBehaviorObservation& result)
{
    std::string root; // 只有预定义根键才可恢复绝对键路径。
    std::string subkey; // 原包采集的精确子键文本。
    for (const auto& field : result.parameters) {
        if (field.id == "registry.key") {
            const auto& key = std::get<std::string>(field.value); // RegOpenKey 的 HKxx\path。
            const auto slash = key.find('\\'); // 显式根键与原子键的分界。
            if (slash != key.npos) {
                root = Lower(key.substr(0, slash));
                subkey = key.substr(slash + 1);
            }
        } else if (field.id == "registry.rootHandle") {
            const auto handle = std::get<std::uint64_t>(field.value); // x86 或符号扩展的 x64 预定义 HKEY。
            if (handle == 0x80000002ull || handle == 0xffffffff80000002ull) {
                root = "hklm";
            } else if (handle == 0x80000001ull || handle == 0xffffffff80000001ull) {
                root = "hkcu";
            }
        } else if (field.id == "registry.subkey") {
            subkey = std::get<std::string>(field.value);
        }
    }
    if ((root != "hklm" && root != "hkcu") || subkey.empty()) {
        return;
    }
    // 不折叠 ..、斜杠、重复分隔或尾空白；只对实际明确的 Windows 键名做 ASCII 大小写折叠。
    const auto path = root + "\\" + subkey; // 保留原子键大小写的显示值。
    result.parameters.push_back({"registry.path", path});
    result.parameters.push_back({"registry.pathLower", Lower(path)});
}

// 文本投影额外发布有明确定义的比较字段，规则作者无需使用正则。
void ComparisonFields(ApiBehaviorObservation& result)
{
    std::vector<ApiBehaviorParameter> extra; // 迭代期间不使原参数容器失效。
    for (const auto& field : result.parameters) {
        const auto* text = std::get_if<std::string>(&field.value); // 只处理目录中登记的文本字段。
        if (!text) {
            continue;
        }
        if (field.id == "module.name") {
            extra.push_back({"module.nameLower", Lower(*text)});
        } else if (field.id == "registry.valueName") {
            extra.push_back({"registry.valueNameLower", Lower(*text)});
        } else if (field.id == "service.name") {
            extra.push_back({"service.nameLower", Lower(*text)});
        } else if (field.id == "process.application") {
            const auto slash = text->find_last_of("\\/"); // 应用参数的文件名，不从命令行猜执行目标。
            extra.push_back({"process.applicationBaseLower", Lower(text->substr(slash == text->npos ? 0 : slash + 1))});
        } else if (field.id == "network.host") {
            extra.push_back({"network.hostLower", Lower(*text)});
            // 域名投影只接受 ASCII DNS 标签，IP、URL、空标签和未知 IDN 不伪装成域名。
            auto domain = Lower(*text); // 单个 DNS 绝对名尾点可规范化移除。
            if (domain.ends_with('.')) {
                domain.pop_back();
            }
            bool valid = !domain.empty() && domain.size() <= 253; // DNS 展示名的总长度限制。
            bool alphabetic = false; // 排除纯数字 IPv4 字面量。
            bool numericHost = true; // Windows 也接受 0x7f000001 等十六进制 IPv4 表示。
            std::size_t begin = 0; // 当前标签起点。
            while (valid && begin < domain.size()) {
                const auto dot = domain.find('.', begin); // 当前标签的结束位置。
                const auto label = std::string_view(domain).substr(begin,
                    dot == domain.npos ? domain.size() - begin : dot - begin);
                valid = !label.empty() && label.size() <= 63 && label.front() != '-' && label.back() != '-';
                for (const auto ch : label) {
                    alphabetic = alphabetic || (ch >= 'a' && ch <= 'z');
                    valid = valid && ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-');
                }
                // 各段均为十进制/八进制数字或带 0x 的十六进制时，保守作为 IP 候选排除。
                const bool hexadecimal = label.starts_with("0x"); // 此段是否使用显式十六进制前缀。
                const auto digits = label.substr(hexadecimal ? 2 : 0); // 去掉前缀后的数字片段。
                bool numericLabel = !digits.empty(); // 不接受只有 0x 的空数值。
                for (const auto digit : digits) {
                    numericLabel = numericLabel && ((digit >= '0' && digit <= '9') ||
                        (hexadecimal && digit >= 'a' && digit <= 'f'));
                }
                numericHost = numericHost && numericLabel;
                begin = dot == domain.npos ? domain.size() : dot + 1;
            }
            if (valid && alphabetic && !numericHost && !domain.ends_with('.')) {
                extra.push_back({"network.domainLower", std::move(domain)});
            }
        }
    }
    result.parameters.insert(result.parameters.end(), extra.begin(), extra.end());
    RegistryPath(result);
}

} // namespace

// 返回约定来自已登记的精确导出，状态与参数各自缺失，不互相补造。
std::optional<ApiBehaviorObservation> ReadApiBehaviorObservation(
    const ks::winapi_monitor::ApiMonitorEventPacket& packet)
{
    using namespace ks::winapi_monitor;
    const auto* clue = Evidence::ClassifyApiMonitorClue(packet); // 复用归档/采集的模块和类别核对。
    if (!clue || !packet.sessionIdentity || !packet.pid ||
        packet.hookKind != static_cast<std::uint32_t>(HookKind::Strong) ||
        packet.snapshotIndex != kApiCallReturnValueMarker ||
        (packet.resultKind != static_cast<std::uint32_t>(EventResultKind::StatusCode) &&
         packet.resultKind != static_cast<std::uint32_t>(EventResultKind::StatusUnknown))) {
        return std::nullopt;
    }
    const auto api = clue->api; // 生命周期专用协议继续由其独立读侧解释。
    const auto family = clue->family; // 当前正式目录中的单事件类别。
    ApiBehaviorObservation result; // 当前调用的独立返回事实。
    result.returnBits = packet.hookAddress;
    result.statusDomain = "win32";
    if (family == "registry-query" || family == "registry-write" || family == "network-name-query") {
        if (packet.hookAddress > UINT32_MAX) {
            return std::nullopt;
        }
        result.succeeded = packet.hookAddress == 0;
        result.statusDomain = family == "network-name-query" ? "addrinfo-return" : "lstatus";
    } else if (family == "system-query" || api == L"NtResumeThread") {
        if (packet.hookAddress > UINT32_MAX) {
            return std::nullopt; // 此生产包装器将 32 位 NTSTATUS 零扩展存入返回槽。
        }
        const auto low = static_cast<std::uint32_t>(packet.hookAddress); // NTSTATUS 只解释低 32 位。
        result.succeeded = (low & 0x80000000u) == 0;
        result.statusDomain = "ntstatus";
    } else if (api == L"ResumeThread") {
        // DWORD为旧挂起计数，0表示调用成功；只有0xffffffff是失败返回，不按BOOL解释。
        if (packet.hookAddress > UINT32_MAX) {
            return std::nullopt;
        }
        result.succeeded = packet.hookAddress != UINT32_MAX;
    } else if (family == "file-open") {
        result.succeeded = packet.hookAddress != 0 && packet.hookAddress != UINT64_MAX &&
            packet.hookAddress != UINT32_MAX; // x64 与 x86 INVALID_HANDLE_VALUE 均拒绝。
    } else if (family == "process-enumeration" || family == "module-query" || family == "process-start" ||
        family == "file-copy" || family == "file-write" || family == "service-control" ||
        family == "network-session" || family == "network-request") {
        // 句柄返回保留完整指针宽度；BOOL 返回只允许生产包装器保存的低 32 位。
        const bool handleReturn = api == L"GetModuleHandleW" || api == L"GetModuleHandleA" ||
            api == L"CreateServiceW" || api == L"CreateServiceA" || api == L"OpenServiceW" ||
            api == L"OpenServiceA" || family == "network-session" || api == L"WinHttpOpenRequest" ||
            api == L"HttpOpenRequestW" || api == L"HttpOpenRequestA";
        if (!handleReturn && packet.hookAddress > UINT32_MAX) {
            return std::nullopt;
        }
        result.succeeded = packet.hookAddress != 0;
    } else {
        return std::nullopt;
    }
    // 已登记的无错误源包装器只在失败时声明 StatusUnknown；状态型 API 始终有返回状态。
    if (packet.resultKind == static_cast<std::uint32_t>(EventResultKind::StatusUnknown) &&
        (result.succeeded || result.statusDomain != "win32")) {
        return std::nullopt;
    }
    // 仅原包声明有效时发布状态。零成功的 API 还要求状态与返回低位相符。
    if (packet.resultKind == static_cast<std::uint32_t>(EventResultKind::StatusCode)) {
        result.status = family == "network-name-query" ? static_cast<std::uint32_t>(result.returnBits) :
            static_cast<std::uint32_t>(packet.resultCode); // GetAddrInfo 错误由返回值给出，包装器的 WSA 状态不保证对应。
        if ((result.statusDomain != "win32" && *result.status != static_cast<std::uint32_t>(result.returnBits)) ||
            (result.statusDomain == "win32" && result.succeeded && *result.status != 0)) {
            return std::nullopt;
        }
    }
    if (api == L"ResumeThread" && result.succeeded) {
        // 该值来自显式返回槽而非detail；直接NT入口的可选输出没有独立有效位，不猜计数。
        result.parameters.push_back({"thread.previousSuspendCount", result.returnBits});
    }
    // 文本布局独立校验：无尾界、满缓冲及可识别的截断/不可读标记不作为参数来源。
    auto detail = Evidence::ApiMonitorPacketText(packet.detailText); // 完整包内的 NUL 终止视图。
    if (detail.empty() || detail.size() + 1 >= std::size(packet.detailText)) {
        return result;
    }
    const bool ansi = api.ends_with(L"A") || api == L"getaddrinfo" ||
        api == L"Module32First" || api == L"Module32Next"; // 未归档 ACP 的接口只解 ASCII。
    // 专用处理器没有 arg 尾；生成包装器按实际签名核验完整尾部后才解码具名参数。
    unsigned arguments = 0; // 当前精确 API 的生成入口槽数量。
    if (api.starts_with(L"Module32")) {
        arguments = 2;
    } else if (api == L"GetModuleHandleW" || api == L"GetModuleHandleA" || api == L"DeleteService") {
        arguments = 1;
    } else if (family == "system-query" || family == "network-name-query" || api == L"WinHttpConnect") {
        arguments = 4;
    } else if (api == L"CreateServiceW" || api == L"CreateServiceA" ||
        api == L"InternetConnectW" || api == L"InternetConnectA" ||
        api == L"HttpOpenRequestW" || api == L"HttpOpenRequestA") {
        arguments = 8;
    } else if (api == L"OpenServiceW" || api == L"OpenServiceA" || api == L"StartServiceW" || api == L"StartServiceA") {
        arguments = 3;
    } else if (api == L"WinHttpOpenRequest" || api == L"WinHttpSendRequest") {
        arguments = 7;
    } else if (api == L"HttpSendRequestW" || api == L"HttpSendRequestA") {
        arguments = 5;
    }
    if (arguments) {
        constexpr std::wstring_view failed = L" call_failed=1 error=unavailable"; // 无错误源接口的生成尾注。
        if (!result.succeeded && packet.resultKind == static_cast<std::uint32_t>(EventResultKind::StatusUnknown) &&
            detail.ends_with(failed)) {
            detail.remove_suffix(failed.size());
        }
        const auto formatter = WithoutArguments(detail, arguments); // 只有具名部分与签名尾均合法才发布字段。
        if (!formatter) {
            return result;
        }
        detail = *formatter;
    }
    using E = Encoding;
    bool decoded = false; // 仅完整布局成功后发布参数。
    if (api == L"RegOpenKeyW" || api == L"RegOpenKeyA" || api == L"RegOpenKeyExW" || api == L"RegOpenKeyExA") {
        decoded = Layout(result, detail, ansi, {{L"key=", E::Text, "registry.key"}, {L" sam=", E::Hex}});
    } else if (api == L"RegGetValueW" || api == L"RegGetValueA" || api == L"RegSetKeyValueW" || api == L"RegSetKeyValueA") {
        // GetValue/SetKeyValue 共享的真实格式包含子键；普通句柄仍不足以生成绝对路径。
        decoded = Layout(result, detail, ansi, {{L"hkey=", E::Hex, "registry.rootHandle"},
            {L" subkey=", E::Text, "registry.subkey"}, {L" value=", E::Text, "registry.valueName"},
            {L" flags=", E::Hex}, {L" type=", E::Decimal}, {L" size=", E::Decimal}});
    } else if (api == L"RegQueryValueExW" || api == L"RegQueryValueExA" || api == L"RegSetValueExW" || api == L"RegSetValueExA") {
        decoded = Layout(result, detail, ansi, {{L"hkey=", E::Hex, "registry.rootHandle"},
            {L" value=", E::Text, "registry.valueName"}, {L" type=", E::Decimal}, {L" size=", E::Decimal}});
    } else if (api == L"GetModuleHandleW" || api == L"GetModuleHandleA") {
        // 查询参数与枚举输出分开，枚举失败时不读取残留结构内的名字。
        decoded = Layout(result, detail, ansi, {{L"name=", E::Text, "module.name"}, {L" module=", E::Hex}});
    } else if (api.starts_with(L"Module32")) {
        decoded = result.succeeded && Layout(result, detail, ansi, {{L"snapshot=", E::Hex},
            {L" module=", E::Text, "module.name"}, {L" base=", E::Hex}});
    } else if (api == L"NtQuerySystemInformation") {
        decoded = Layout(result, detail, ansi, {{L"class=", E::Decimal, "system.informationClass"},
            {L" length=", E::Decimal}, {L" return=", E::Decimal}});
    } else if (api == L"CreateProcessW" || api == L"CreateProcessA") {
        // 应用参数和命令行是两份独立数据；不根据命令行头词猜实际映像。
        decoded = Layout(result, detail, ansi, {{L"app=", E::Text, "process.application"},
            {L" cmd=", E::Text, "process.commandLine"}, {L" cwd=", E::Text}, {L" flags=", E::Hex},
            {L" inherit=", E::Decimal}, {L" childPid=", E::Decimal}});
    } else if (family == "file-open") {
        decoded = Layout(result, detail, ansi, {{L"path=", E::Text, "file.path"},
            {L" access=", E::Hex, "file.desiredAccess"}, {L" share=", E::Hex},
            {L" disposition=", E::Decimal, "file.creationDisposition"}, {L" flags=", E::Hex}, {L" handle=", E::Hex}});
    } else if (family == "file-copy") {
        decoded = Layout(result, detail, ansi, {{L"src=", E::Text, "file.sourcePath"},
            {L" dst=", E::Text, "file.path"}, {L" flags=", E::Hex}});
    } else if (family == "file-write") {
        // HookedWriteFile 仅成功、非 OVERLAPPED 且安全读回时输出完成数字；两项计数只随完整布局一起发布。
        // 失败、异步成功或输出不可读时的 transferred=unknown 不转换成零，也不据句柄补造路径。
        // MonitorConfig 将摘要限制下限设为 64；只接受更短布局，避免最终数字在截断边界仍被误认为完整。
        decoded = result.succeeded && detail.size() < 64 && Layout(result, detail, ansi, {{L"handle=", E::Hex},
            {L" request=", E::Decimal, "file.requestedBytes"},
            {L" transferred=", E::Decimal, "file.transferredBytes"}});
    } else if (api == L"CreateServiceW" || api == L"CreateServiceA") {
        // 只采服务创建请求中的名称、启动类型与路径；不查询运行状态或密码。
        decoded = Layout(result, detail, ansi, {{L"service=", E::Text, "service.name"},
            {L" type=", E::Hex, "service.type"}, {L" start=", E::Hex, "service.startType"},
            {L" path=", E::Text, "service.binaryPath"}, {L" handle=", E::Hex}});
    } else if (api == L"OpenServiceW" || api == L"OpenServiceA") {
        decoded = Layout(result, detail, ansi, {{L"scm=", E::Hex}, {L" service=", E::Text, "service.name"},
            {L" access=", E::Hex}, {L" handle=", E::Hex}});
    } else if (api == L"StartServiceW" || api == L"StartServiceA") {
        decoded = Layout(result, detail, ansi, {{L"service=", E::Hex}, {L" argc=", E::Decimal}});
    } else if (api == L"DeleteService") {
        decoded = Layout(result, detail, ansi, {{L"service=", E::Hex}});
    } else if (api == L"WinHttpConnect") {
        // 会话请求的主机与端口仅属于当前调用，不能串接成另一个请求的目标。
        decoded = Layout(result, detail, ansi, {{L"session=", E::Hex}, {L" host=", E::Text, "network.host"},
            {L" port=", E::Decimal, "network.port"}, {L" handle=", E::Hex}});
    } else if (api == L"InternetConnectW" || api == L"InternetConnectA") {
        decoded = Layout(result, detail, ansi, {{L"root=", E::Hex}, {L" host=", E::Text, "network.host"},
            {L" port=", E::Decimal, "network.port"}, {L" service=", E::Decimal}, {L" handle=", E::Hex}});
    } else if (family == "network-name-query") {
        decoded = Layout(result, detail, ansi, {{L"node=", E::Text, "network.host"},
            {L" service=", E::Text}, {L" result=", E::Hex}});
    } else if (api == L"WinHttpOpenRequest" || api == L"HttpOpenRequestW" || api == L"HttpOpenRequestA") {
        // 只发布完整方法及对象；响应状态、正文和上下游连接均没有当前包证据。
        decoded = Layout(result, detail, ansi, {{L"connect=", E::Hex}, {L" verb=", E::Text, "network.method"},
            {L" object=", E::Text, "network.object"}, {L" flags=", E::Hex}, {L" handle=", E::Hex}});
    } else if (api == L"WinHttpSendRequest") {
        decoded = Layout(result, detail, ansi, {{L"request=", E::Hex}, {L" headersLen=", E::Decimal},
            {L" optionalLen=", E::Decimal}, {L" total=", E::Decimal}});
    } else if (api == L"HttpSendRequestW" || api == L"HttpSendRequestA") {
        decoded = Layout(result, detail, ansi, {{L"request=", E::Hex},
            {L" headersLen=", E::Decimal}, {L" optionalLen=", E::Decimal}});
    }
    // 只有完整布局通过才建立比较投影，参数失败不影响已独立核对的返回位。
    if (decoded) {
        ComparisonFields(result);
    }
    return result;
}

} // namespace Ksword::ActionAnalyze::Rules
