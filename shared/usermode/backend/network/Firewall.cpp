#include "Firewall.h"
#include <objbase.h>
#include <oleauto.h>
#include <netfw.h>
#include <utility>
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
namespace ks::r3::network {
namespace {
template <typename Interface>
class ComHandle final {
public:
    ComHandle() = default;

    ~ComHandle() {
        reset();
    }

    ComHandle(const ComHandle&) = delete;
    ComHandle& operator=(const ComHandle&) = delete;

    Interface** put() noexcept {
        reset();
        return &pointer_;
    }

    void** putVoid() noexcept {
        reset();
        return reinterpret_cast<void**>(&pointer_);
    }

    Interface* get() const noexcept {
        return pointer_;
    }

    Interface* operator->() const noexcept {
        return pointer_;
    }

    explicit operator bool() const noexcept {
        return pointer_ != nullptr;
    }

    void reset() noexcept {
        if (pointer_ != nullptr) {
            pointer_->Release();
            pointer_ = nullptr;
        }
    }

private:
    Interface* pointer_ = nullptr;
};

// TakeBstr copies an out-parameter BSTR into a std::wstring and frees it. The
// firewall interface hands out a fresh allocation for every string property, so
// every successful getter has to be paired with a SysFreeString.
std::wstring TakeBstr(BSTR value) {
    if (value == nullptr) {
        return {};
    }
    std::wstring text(value, ::SysStringLen(value));
    ::SysFreeString(value);
    return text;
}

std::wstring ReadStringProperty(HRESULT (STDMETHODCALLTYPE INetFwRule::*getter)(BSTR*), INetFwRule& rule, std::uint32_t& flags, unsigned bit) {
    BSTR value = nullptr;
    if (FAILED((rule.*getter)(&value))) {
        if (value) ::SysFreeString(value);
        return {};
    }
    flags |= 1u << bit;
    return TakeBstr(value);
}

std::wstring ProfileStateText(INetFwPolicy2& policy, const NET_FW_PROFILE_TYPE2 profile, const wchar_t* label, FirewallEnumerationResult& result) {
    VARIANT_BOOL enabled = VARIANT_FALSE;
    if (FAILED(policy.get_FirewallEnabled(profile, &enabled))) {
        return std::wstring(label) + L"=未知";
    }
    result.profileKnownFlags |= static_cast<std::uint32_t>(profile);
    if (enabled != VARIANT_FALSE) result.profileEnabledFlags |= static_cast<std::uint32_t>(profile);
    return std::wstring(label) + (enabled != VARIANT_FALSE ? L"=开启" : L"=关闭");
}

} // namespace
FirewallEnumerationResult EnumerateFirewallRules() {
    FirewallEnumerationResult result{};

    const HRESULT initialized = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    // RPC_E_CHANGED_MODE means someone already initialized this thread with the
    // other apartment model. The firewall proxy works either way, but the
    // uninitialize must not run in that case or it would unbalance their count.
    const bool ownsComInitialization = SUCCEEDED(initialized);
    if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) {
        result.hresult = static_cast<std::uint32_t>(initialized);
        result.diagnosticText = L"COM 初始化失败：" + FormatWin32Error(static_cast<std::uint32_t>(initialized)) + L"。";
        return result;
    }

    {
        ComHandle<INetFwPolicy2> policy;
        HRESULT status = ::CoCreateInstance(
            __uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), policy.putVoid());
        if (FAILED(status) || !policy) {
            result.diagnosticText =
                L"无法创建防火墙策略对象（INetFwPolicy2）：" + FormatWin32Error(static_cast<std::uint32_t>(status)) +
                L"。该接口需要 Windows Defender Firewall 服务（MpsSvc）处于运行状态。";
        } else {
            result.profileSummary =
                ProfileStateText(*policy.get(), NET_FW_PROFILE2_DOMAIN, L"域", result) + L"，" +
                ProfileStateText(*policy.get(), NET_FW_PROFILE2_PRIVATE, L"专用", result) + L"，" +
                ProfileStateText(*policy.get(), NET_FW_PROFILE2_PUBLIC, L"公用", result);

            ComHandle<INetFwRules> rules;
            status = policy->get_Rules(rules.put());
            if (FAILED(status) || !rules) {
                result.diagnosticText =
                    L"无法读取防火墙规则集合：" + FormatWin32Error(static_cast<std::uint32_t>(status)) + L"。";
            } else {
                ComHandle<IUnknown> unknown;
                status = rules->get__NewEnum(unknown.put());
                ComHandle<IEnumVARIANT> enumerator;
                if (SUCCEEDED(status) && unknown) {
                    status = unknown->QueryInterface(__uuidof(IEnumVARIANT), enumerator.putVoid());
                }
                if (FAILED(status) || !enumerator) {
                    result.diagnosticText =
                        L"无法枚举防火墙规则：" + FormatWin32Error(static_cast<std::uint32_t>(status)) + L"。";
                } else {
                    VARIANT item{};
                    ::VariantInit(&item);
                    ULONG fetched = 0;
                    while ((status = enumerator->Next(1, &item, &fetched)) == S_OK && fetched == 1) {
                        if (item.vt == VT_DISPATCH && item.pdispVal != nullptr) {
                            ComHandle<INetFwRule> rule;
                            const auto ruleStatus = item.pdispVal->QueryInterface(__uuidof(INetFwRule), rule.putVoid());
                            if (SUCCEEDED(ruleStatus) && rule) {
                                FirewallRuleEntry entry{};
                                entry.name = ReadStringProperty(&INetFwRule::get_Name, *rule.get(), entry.fieldFlags, 0);
                                entry.description = ReadStringProperty(&INetFwRule::get_Description, *rule.get(), entry.fieldFlags, 1);
                                entry.grouping = ReadStringProperty(&INetFwRule::get_Grouping, *rule.get(), entry.fieldFlags, 2);
                                entry.applicationName = ReadStringProperty(&INetFwRule::get_ApplicationName, *rule.get(), entry.fieldFlags, 3);
                                entry.serviceName = ReadStringProperty(&INetFwRule::get_ServiceName, *rule.get(), entry.fieldFlags, 4);
                                entry.localPorts = ReadStringProperty(&INetFwRule::get_LocalPorts, *rule.get(), entry.fieldFlags, 5);
                                entry.remotePorts = ReadStringProperty(&INetFwRule::get_RemotePorts, *rule.get(), entry.fieldFlags, 6);
                                entry.localAddresses = ReadStringProperty(&INetFwRule::get_LocalAddresses, *rule.get(), entry.fieldFlags, 7);
                                entry.remoteAddresses = ReadStringProperty(&INetFwRule::get_RemoteAddresses, *rule.get(), entry.fieldFlags, 8);
                                entry.interfaceTypes = ReadStringProperty(&INetFwRule::get_InterfaceTypes, *rule.get(), entry.fieldFlags, 9);

                                NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_IN;
                                if (SUCCEEDED(rule->get_Direction(&direction))) {
                                    entry.fieldFlags |= 1u << 10;
                                    entry.direction = static_cast<std::int32_t>(direction);
                                }
                                NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
                                if (SUCCEEDED(rule->get_Action(&action))) {
                                    entry.fieldFlags |= 1u << 11;
                                    entry.action = static_cast<std::int32_t>(action);
                                }
                                LONG protocol = 0;
                                if (SUCCEEDED(rule->get_Protocol(&protocol))) {
                                    entry.fieldFlags |= 1u << 12;
                                    entry.protocol = static_cast<std::int32_t>(protocol);
                                }
                                long profiles = 0;
                                if (SUCCEEDED(rule->get_Profiles(&profiles))) {
                                    entry.fieldFlags |= 1u << 13;
                                    entry.profiles = static_cast<std::int32_t>(profiles);
                                }
                                VARIANT_BOOL enabled = VARIANT_FALSE;
                                if (SUCCEEDED(rule->get_Enabled(&enabled))) {
                                    entry.fieldFlags |= 1u << 14;
                                    entry.enabled = enabled != VARIANT_FALSE;
                                }
                                VARIANT_BOOL edgeTraversal = VARIANT_FALSE;
                                if (SUCCEEDED(rule->get_EdgeTraversal(&edgeTraversal))) {
                                    entry.fieldFlags |= 1u << 15;
                                    entry.edgeTraversal = edgeTraversal != VARIANT_FALSE;
                                }
                                result.entries.push_back(std::move(entry));
                            } else {
                                result.hresult = static_cast<std::uint32_t>(FAILED(ruleStatus) ? ruleStatus : E_NOINTERFACE);
                            }
                        } else {
                            result.hresult = static_cast<std::uint32_t>(DISP_E_TYPEMISMATCH);
                        }
                        ::VariantClear(&item);
                        ::VariantInit(&item);
                        fetched = 0;
                    }
                    ::VariantClear(&item);
                    result.complete = status == S_FALSE && result.hresult == 0;
                    if (status == S_OK) status = E_UNEXPECTED;
                    result.success = true;
                }
            }
        }
        if (FAILED(status)) result.hresult = static_cast<std::uint32_t>(status);
    }

    if (ownsComInitialization) {
        ::CoUninitialize();
    }
    return result;
}
}
