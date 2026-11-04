#include "FirewallOperations.h"
#include <Windows.h>
#include <Wincrypt.h>
#include <netfw.h>
#include <oleauto.h>
#include <algorithm>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")

namespace ks::r3::network {
namespace {
template<class T> struct ComPtr {
    T* value = nullptr;
    ~ComPtr() { if (value) value->Release(); }
    T** put() { return &value; }
    T* operator->() const { return value; }
};
struct ComScope {
    HRESULT status = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    ~ComScope() { if (SUCCEEDED(status)) CoUninitialize(); }
    bool ok() const { return SUCCEEDED(status) || status == RPC_E_CHANGED_MODE; }
};
struct Bstr {
    BSTR value;
    explicit Bstr(const std::wstring& text) : value(SysAllocStringLen(text.data(), static_cast<UINT>(text.size()))) {}
    ~Bstr() { SysFreeString(value); }
};
bool sameName(const std::wstring& left, const std::wstring& right) {
    return CompareStringOrdinal(left.c_str(), static_cast<int>(left.size()), right.c_str(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}
bool hashBytes(HCRYPTHASH hash, const void* bytes, DWORD count) {
    return CryptHashData(hash, static_cast<const BYTE*>(bytes), count, 0) != FALSE;
}
bool hashText(HCRYPTHASH hash, const std::wstring& text) {
    if (text.size() > MAXDWORD / sizeof(wchar_t)) return false;
    const auto size = static_cast<DWORD>(text.size() * sizeof(wchar_t));
    return hashBytes(hash, &size, sizeof(size)) && (size == 0 || hashBytes(hash, text.data(), size));
}
bool fieldsMatch(const FirewallRuleEntry& current, const FirewallRuleEntry& requested) {
    const auto has = [&](unsigned bit) { return (requested.fieldFlags & (1u << bit)) != 0; };
    if ((current.fieldFlags & requested.fieldFlags) != requested.fieldFlags) return false;
    return (!has(1) || current.description == requested.description) &&
        (!has(2) || current.grouping == requested.grouping) &&
        (!has(3) || current.applicationName == requested.applicationName) &&
        (!has(4) || current.serviceName == requested.serviceName) &&
        (!has(5) || current.localPorts == requested.localPorts) &&
        (!has(6) || current.remotePorts == requested.remotePorts) &&
        (!has(7) || current.localAddresses == requested.localAddresses) &&
        (!has(8) || current.remoteAddresses == requested.remoteAddresses) &&
        (!has(9) || current.interfaceTypes == requested.interfaceTypes) &&
        (!has(10) || current.direction == requested.direction) &&
        (!has(11) || current.action == requested.action) &&
        (!has(12) || current.protocol == requested.protocol) &&
        (!has(13) || current.profiles == requested.profiles) &&
        (!has(14) || current.enabled == requested.enabled) &&
        (!has(15) || current.edgeTraversal == requested.edgeTraversal) &&
        (!has(16) || current.icmpTypesAndCodes == requested.icmpTypesAndCodes);
}
FirewallRuleEntry mergedFields(FirewallRuleEntry current, const FirewallRuleEntry& patch) {
    const auto has = [&](unsigned bit) { return (patch.fieldFlags & (1u << bit)) != 0; };
    if (has(1)) current.description=patch.description;
    if (has(2)) current.grouping=patch.grouping;
    if (has(3)) current.applicationName=patch.applicationName;
    if (has(4)) current.serviceName=patch.serviceName;
    if (has(5)) current.localPorts=patch.localPorts;
    if (has(6)) current.remotePorts=patch.remotePorts;
    if (has(7)) current.localAddresses=patch.localAddresses;
    if (has(8)) current.remoteAddresses=patch.remoteAddresses;
    if (has(9)) current.interfaceTypes=patch.interfaceTypes;
    if (has(10)) current.direction=patch.direction;
    if (has(11)) current.action=patch.action;
    if (has(12)) current.protocol=patch.protocol;
    if (has(13)) current.profiles=patch.profiles;
    if (has(14)) current.enabled=patch.enabled;
    if (has(15)) current.edgeTraversal=patch.edgeTraversal;
    if (has(16)) current.icmpTypesAndCodes=patch.icmpTypesAndCodes;
    current.fieldFlags |= patch.fieldFlags;
    return current;
}
HRESULT openRules(ComPtr<INetFwPolicy2>& policy, ComPtr<INetFwRules>& rules) {
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2), reinterpret_cast<void**>(policy.put()));
    if (FAILED(hr)) return hr;
    if (!policy.value) return E_UNEXPECTED;
    return policy->get_Rules(rules.put());
}
HRESULT findRuleByFingerprint(INetFwRules& rules, const std::wstring& name,
                              const std::wstring& fingerprint, ComPtr<INetFwRule>& selected) {
    ComPtr<IUnknown> unknown; HRESULT hr=rules.get__NewEnum(unknown.put());
    if (FAILED(hr) || !unknown.value) return FAILED(hr) ? hr : E_UNEXPECTED;
    ComPtr<IEnumVARIANT> enumerator;
    hr=unknown->QueryInterface(__uuidof(IEnumVARIANT),reinterpret_cast<void**>(enumerator.put()));
    if (FAILED(hr) || !enumerator.value) return FAILED(hr) ? hr : E_UNEXPECTED;
    unsigned matched=0;
    for (;;) {
        VARIANT item{}; VariantInit(&item); ULONG fetched=0;
        hr=enumerator->Next(1,&item,&fetched);
        if (hr==S_FALSE) { VariantClear(&item); break; }
        if (hr!=S_OK || fetched!=1 || item.vt!=VT_DISPATCH || !item.pdispVal) {
            VariantClear(&item); return FAILED(hr) ? hr : E_UNEXPECTED;
        }
        ComPtr<INetFwRule> candidate;
        hr=item.pdispVal->QueryInterface(__uuidof(INetFwRule),reinterpret_cast<void**>(candidate.put()));
        VariantClear(&item);
        if (FAILED(hr) || !candidate.value) return FAILED(hr) ? hr : E_NOINTERFACE;
        FirewallRuleEntry value;
        if (!ReadFirewallRule(candidate.value,value)) return E_UNEXPECTED;
        if (sameName(value.name,name)) {
            const auto actual=FirewallRuleFingerprint(value);
            if (actual.empty()) return E_UNEXPECTED;
            if (actual==fingerprint) {
                if (++matched>1) return HRESULT_FROM_WIN32(ERROR_DUP_NAME);
                selected.value=candidate.value; candidate.value=nullptr;
            }
        }
    }
    return matched==1 ? S_OK : HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}
HRESULT setString(INetFwRule& rule, HRESULT (STDMETHODCALLTYPE INetFwRule::*setter)(BSTR), const std::wstring& text) {
    Bstr value(text);
    return value.value ? (rule.*setter)(value.value) : E_OUTOFMEMORY;
}
HRESULT applyFields(INetFwRule& rule, const FirewallRuleEntry& fields, bool& touched) {
    HRESULT hr = S_OK;
    const auto has = [&](unsigned bit) { return (fields.fieldFlags & (1u << bit)) != 0; };
    const auto apply = [&](bool selected, const auto& action) {
        if (selected && SUCCEEDED(hr)) { hr = action(); if (SUCCEEDED(hr)) touched = true; }
    };
    apply(has(1), [&] { return setString(rule, &INetFwRule::put_Description, fields.description); });
    apply(has(2), [&] { return setString(rule, &INetFwRule::put_Grouping, fields.grouping); });
    apply(has(3), [&] { return setString(rule, &INetFwRule::put_ApplicationName, fields.applicationName); });
    apply(has(4), [&] { return setString(rule, &INetFwRule::put_ServiceName, fields.serviceName); });
    // Windows validates ports against protocol at each setter.
    apply(has(12), [&] { return rule.put_Protocol(fields.protocol); });
    apply(has(16), [&] { return setString(rule, &INetFwRule::put_IcmpTypesAndCodes, fields.icmpTypesAndCodes); });
    apply(has(5), [&] { return setString(rule, &INetFwRule::put_LocalPorts, fields.localPorts); });
    apply(has(6), [&] { return setString(rule, &INetFwRule::put_RemotePorts, fields.remotePorts); });
    apply(has(7), [&] { return setString(rule, &INetFwRule::put_LocalAddresses, fields.localAddresses); });
    apply(has(8), [&] { return setString(rule, &INetFwRule::put_RemoteAddresses, fields.remoteAddresses); });
    apply(has(9), [&] { return setString(rule, &INetFwRule::put_InterfaceTypes, fields.interfaceTypes); });
    apply(has(10), [&] { return rule.put_Direction(static_cast<NET_FW_RULE_DIRECTION>(fields.direction)); });
    apply(has(11), [&] { return rule.put_Action(static_cast<NET_FW_ACTION>(fields.action)); });
    apply(has(13), [&] { return rule.put_Profiles(fields.profiles); });
    apply(has(14), [&] { return rule.put_Enabled(fields.enabled ? VARIANT_TRUE : VARIANT_FALSE); });
    apply(has(15), [&] { return rule.put_EdgeTraversal(fields.edgeTraversal ? VARIANT_TRUE : VARIANT_FALSE); });
    return hr;
}
enum class Operation { Create, Update, Remove };
FirewallMutationResult mutate(const FirewallRuleMutation& mutation, Operation op) {
    FirewallMutationResult result;
    result.stage = L"preflight";
    if (mutation.name.empty() || (op != Operation::Create && mutation.expectedFingerprint.empty())) {
        result.hresult = static_cast<std::uint32_t>(E_INVALIDARG); result.diagnostic = L"A name and, for changes, the previously observed fingerprint are required."; return result;
    }
    result.before = QueryFirewallRule(mutation.name,op == Operation::Create ? L"" : mutation.expectedFingerprint);
    result.preflightComplete = result.before.complete;
    if (!result.before.success || !result.before.complete) {
        result.hresult = result.before.hresult; result.diagnostic = L"Rule enumeration was incomplete; no change was attempted."; return result;
    }
    if (op == Operation::Create ? result.before.nameMatchingCount != 0 : result.before.matchingCount != 1) {
        result.hresult = HRESULT_FROM_WIN32(result.before.matchingCount ? ERROR_DUP_NAME : ERROR_NOT_FOUND);
        result.diagnostic = L"The name must be absent for creation and the fingerprint must identify exactly one rule for mutation."; return result;
    }
    if (op == Operation::Remove && result.before.nameMatchingCount != 1) {
        result.hresult = HRESULT_FROM_WIN32(ERROR_DUP_NAME);
        result.diagnostic = L"Delete is unavailable for duplicate names because the Windows API removes by name."; return result;
    }
    if (op == Operation::Update && mutation.rename && mutation.newName.empty()) {
        result.hresult=static_cast<std::uint32_t>(E_INVALIDARG); result.diagnostic=L"The new name must not be empty."; return result;
    }
    if (op == Operation::Update && mutation.rename && !sameName(mutation.name,mutation.newName)) {
        const auto target=QueryFirewallRule(mutation.newName);
        if (!target.success || !target.complete || target.nameMatchingCount != 0) {
            result.hresult=HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS); result.diagnostic=L"The new name is not confirmed absent."; return result;
        }
    }
    ComScope com;
    if (!com.ok()) { result.hresult = static_cast<std::uint32_t>(com.status); result.stage = L"com"; return result; }
    ComPtr<INetFwPolicy2> policy; ComPtr<INetFwRules> rules;
    HRESULT hr = openRules(policy, rules);
    if (FAILED(hr) || !rules.value) { result.hresult = static_cast<std::uint32_t>(FAILED(hr) ? hr : E_UNEXPECTED); result.stage = L"open-rules"; return result; }
    // Re-enumerate immediately before the operation; no Windows Firewall API
    // provides an atomic compare-and-remove for a rule name.
    const auto current = QueryFirewallRule(mutation.name,op == Operation::Create ? L"" : mutation.expectedFingerprint);
    if (!current.success || !current.complete || (op == Operation::Create ? current.nameMatchingCount != 0 :
        current.matchingCount != 1 || (op == Operation::Remove && current.nameMatchingCount != 1))) {
        result.hresult = HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH); result.stage = L"revalidate";
        result.diagnostic = L"The rule set changed or could not be revalidated; no change was attempted."; return result;
    }
    if (op == Operation::Update && mutation.rename && !sameName(mutation.name,mutation.newName)) {
        const auto target=QueryFirewallRule(mutation.newName);
        if (!target.success || !target.complete || target.nameMatchingCount != 0) {
            result.hresult=HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH); result.stage=L"revalidate";
            result.diagnostic=L"The new name changed or could not be revalidated; no change was attempted."; return result;
        }
    }
    Bstr name(mutation.name);
    if (!name.value) { result.hresult = static_cast<std::uint32_t>(E_OUTOFMEMORY); result.stage = L"name"; return result; }
    result.stage = L"write";
    bool touched = false;
    if (op == Operation::Remove) {
        result.requestAttempted = true;
        hr = rules->Remove(name.value);
    } else {
        ComPtr<INetFwRule> rule;
        if (op == Operation::Create) {
            hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                __uuidof(INetFwRule), reinterpret_cast<void**>(rule.put()));
            if (SUCCEEDED(hr) && rule.value) hr = rule->put_Name(name.value);
        } else {
            hr = findRuleByFingerprint(*rules.value,mutation.name,mutation.expectedFingerprint,rule);
        }
        if (SUCCEEDED(hr) && !rule.value) hr = E_UNEXPECTED;
        if (SUCCEEDED(hr) && op == Operation::Update) result.requestAttempted=true;
        if (SUCCEEDED(hr)) hr = applyFields(*rule.value, mutation.fields, touched);
        if (SUCCEEDED(hr) && op == Operation::Update && mutation.rename) {
            hr=setString(*rule.value,&INetFwRule::put_Name,mutation.newName);
            if (SUCCEEDED(hr)) touched=true;
        }
        if (SUCCEEDED(hr) && op == Operation::Create) { result.requestAttempted=true; hr = rules->Add(rule.value); }
        result.partialEffectPossible = op == Operation::Update && touched && FAILED(hr);
    }
    result.hresult = static_cast<std::uint32_t>(hr);
    result.requestSucceeded = SUCCEEDED(hr);
    auto expectedEntry=mergedFields(result.before.entry,mutation.fields);
    if (mutation.rename && op == Operation::Update) expectedEntry.name=mutation.newName;
    const auto expected = op == Operation::Update ? FirewallRuleFingerprint(expectedEntry) : std::wstring{};
    result.after = QueryFirewallRule(mutation.rename && op == Operation::Update ? mutation.newName : mutation.name,expected);
    result.postcheckComplete = result.after.success && result.after.complete;
    if (result.postcheckComplete) {
        result.verified = op == Operation::Remove ? result.after.nameMatchingCount == 0 :
            result.after.matchingCount == 1 && fieldsMatch(result.after.entry, mutation.fields);
    }
    if (FAILED(hr)) result.diagnostic = L"The firewall API failed; a prior setter may already have changed the rule.";
    else if (!result.verified) result.diagnostic = L"The API returned success but the observed rule did not confirm the requested effect.";
    result.stage = L"complete";
    return result;
}
}

std::wstring FirewallRuleFingerprint(const FirewallRuleEntry& entry) {
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return {};
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) { CryptReleaseContext(provider, 0); return {}; }
    bool ok = hashBytes(hash, &entry.fieldFlags, sizeof(entry.fieldFlags));
    for (const auto* text : {&entry.name, &entry.description, &entry.grouping, &entry.applicationName,
        &entry.serviceName, &entry.localPorts, &entry.remotePorts, &entry.localAddresses, &entry.remoteAddresses, &entry.interfaceTypes, &entry.icmpTypesAndCodes})
        ok = ok && hashText(hash, *text);
    for (const auto number : {entry.direction, entry.action, entry.protocol, entry.profiles,
        static_cast<std::int32_t>(entry.enabled), static_cast<std::int32_t>(entry.edgeTraversal)})
        ok = ok && hashBytes(hash, &number, sizeof(number));
    BYTE digest[32]{}; DWORD length = sizeof(digest);
    ok = ok && CryptGetHashParam(hash, HP_HASHVAL, digest, &length, 0) && length == sizeof(digest);
    CryptDestroyHash(hash); CryptReleaseContext(provider, 0);
    if (!ok) return {};
    static const wchar_t digits[] = L"0123456789abcdef";
    std::wstring result; result.reserve(64);
    for (const auto byte : digest) { result.push_back(digits[byte >> 4]); result.push_back(digits[byte & 15]); }
    return result;
}

FirewallRuleLookup QueryFirewallRule(const std::wstring& name, const std::wstring& fingerprint) {
    FirewallRuleLookup result;
    if (name.empty()) { result.hresult = static_cast<std::uint32_t>(E_INVALIDARG); return result; }
    const auto snapshot = EnumerateFirewallRules();
    result.success = snapshot.success;
    result.complete = snapshot.success && snapshot.complete;
    result.hresult = snapshot.hresult;
    result.diagnostic = snapshot.diagnosticText;
    for (const auto& entry : snapshot.entries) {
        if ((entry.fieldFlags & 1u) == 0) { result.complete = false; continue; }
        if (sameName(entry.name, name)) {
            ++result.nameMatchingCount;
            const auto actual=FirewallRuleFingerprint(entry);
            if (actual.empty()) { result.complete=false; result.hresult=static_cast<std::uint32_t>(E_UNEXPECTED); continue; }
            if (fingerprint.empty() || fingerprint==actual) {
                result.candidates.push_back({entry,actual});
                ++result.matchingCount; result.entry=entry; result.fingerprint=actual;
            }
        }
    }
    if (result.matchingCount != 1) result.fingerprint.clear();
    return result;
}
FirewallMutationResult CreateFirewallRule(const FirewallRuleMutation& mutation) { return mutate(mutation, Operation::Create); }
FirewallMutationResult UpdateFirewallRule(const FirewallRuleMutation& mutation) { return mutate(mutation, Operation::Update); }
FirewallMutationResult RemoveFirewallRule(const FirewallRuleMutation& mutation) { return mutate(mutation, Operation::Remove); }
}
