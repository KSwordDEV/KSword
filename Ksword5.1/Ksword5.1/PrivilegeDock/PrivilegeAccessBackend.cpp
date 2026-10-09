#include "PrivilegeAccessBackend.h"

// 访问诊断 Win32 后端：仅查询或申请对象句柄，所有拥有资源通过 RAII 释放。
// 请求与结果按值共享，独立探针线程结束后不会污染线程池身份。
#include <Sddl.h>
#include <QStringList>
#include <cstring>
#include <iterator>
#include <string>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Authz.lib")

namespace ks::privilege::access::detail
{
    // 将有效 SID 转成稳定字符串；无效或失败时返回空值。
    QString sidText(PSID sid)
    {
        if (sid == nullptr || !IsValidSid(sid)) return {};
        LPWSTR string = nullptr;
        if (!ConvertSidToStringSidW(sid, &string)) return {};
        const QString result = QString::fromWCharArray(string);
        LocalFree(string);
        return result;
    }

    // 解析 SID 的显示名称，不用显示名称替代身份。
    QString sidAccount(PSID sid)
    {
        if (sid == nullptr || !IsValidSid(sid)) return {};
        DWORD accountSize = 0;
        DWORD domainSize = 0;
        SID_NAME_USE use{};
        LookupAccountSidW(nullptr, sid, nullptr, &accountSize, nullptr, &domainSize, &use);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || accountSize > 32768 || domainSize > 32768)
            return {};
        std::vector<wchar_t> account(accountSize + 1);
        std::vector<wchar_t> domain(domainSize + 1);
        if (!LookupAccountSidW(nullptr, sid, account.data(), &accountSize,
            domain.data(), &domainSize, &use)) return {};
        const QString name = QString::fromWCharArray(account.data());
        const QString prefix = QString::fromWCharArray(domain.data());
        return prefix.isEmpty() ? name : prefix + QLatin1Char('\\') + name;
    }

    // 检查工作任务取消标记，并记录明确的取消阶段。
    bool isCancelled(const std::shared_ptr<std::atomic_bool>& flag, Result& result)
    {
        if (!flag->load(std::memory_order_relaxed)) return false;
        result.stage = Stage::Cancelled;
        result.error = ERROR_CANCELLED;
        return true;
    }

    // 有界读取可变长度令牌字段，拒绝不完整缓冲。
    bool queryTokenBytes(HANDLE token, TOKEN_INFORMATION_CLASS type, std::vector<BYTE>& bytes)
    {
        DWORD size = 0;
        GetTokenInformation(token, type, nullptr, 0, &size);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0 || size > 1024 * 1024)
            return false;
        bytes.resize(size);
        return GetTokenInformation(token, type, bytes.data(), size, &size) != FALSE;
    }

    // 读取固定令牌身份及修改序列，供后续复核。
    bool queryStatistics(HANDLE token, TOKEN_STATISTICS& stats)
    {
        DWORD size = sizeof(stats);
        return GetTokenInformation(token, TokenStatistics, &stats, size, &size) != FALSE;
    }

    // 比较完整 LUID 的高低两部分。
    bool sameLuid(const LUID left, const LUID right)
    {
        return left.LowPart == right.LowPart && left.HighPart == right.HighPart;
    }

    // 验证令牌身份和 ModifiedId 均未改变。
    bool sameStatistics(const TOKEN_STATISTICS& left, const TOKEN_STATISTICS& right)
    {
        return sameLuid(left.TokenId, right.TokenId) && sameLuid(left.ModifiedId, right.ModifiedId)
            && sameLuid(left.AuthenticationId, right.AuthenticationId);
    }

    // 读取已固定进程的创建时间，输出用于防 PID 复用的身份。
    bool creationTime(HANDLE process, ULONGLONG& value)
    {
        FILETIME creation{}, exit{}, kernel{}, user{};
        if (!GetProcessTimes(process, &creation, &exit, &kernel, &user)) return false;
        value = (ULONGLONG(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
        return true;
    }

    // 通过已打开文件句柄读取规范 DOS 路径。
    QString filePath(HANDLE file)
    {
        DWORD size = GetFinalPathNameByHandleW(file, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (size == 0 || size > 32768) return {};
        std::vector<wchar_t> storage(size + 1);
        const DWORD written = GetFinalPathNameByHandleW(file, storage.data(), DWORD(storage.size()),
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        return written > 0 && written < storage.size() ? QString::fromWCharArray(storage.data()) : QString();
    }

    // 只接受本地盘路径，拒绝设备、网络、命名流和保留设备名。
    bool localDiskPath(const QString& value)
    {
        QString path = value;
        if (path.startsWith(QStringLiteral("\\\\?\\"))) path = path.mid(4);
        if (path.size() < 3 || !path[0].isLetter() || path[1] != QLatin1Char(':')
            || (path[2] != QLatin1Char('\\') && path[2] != QLatin1Char('/')))
            return false;
        // 命名数据流和保留设备名可能在打开时产生对象专属副作用，必须拒绝。
        if (path.mid(2).contains(QLatin1Char(':'))) return false;
        const QStringList components = QString(path.mid(3)).replace(QLatin1Char('/'), QLatin1Char('\\'))
            .split(QLatin1Char('\\'));
        for (const QString& component : components)
        {
            const QString name = component.section(QLatin1Char('.'), 0, 0).trimmed().toUpper();
            if (name == QStringLiteral("CON") || name == QStringLiteral("PRN")
                || name == QStringLiteral("AUX") || name == QStringLiteral("NUL")) return false;
            if (name.size() == 4 && (name.startsWith(QStringLiteral("COM")) || name.startsWith(QStringLiteral("LPT")))
                && (name[3].isDigit() || name[3] == QChar(0x00b9)
                    || name[3] == QChar(0x00b2) || name[3] == QChar(0x00b3))) return false;
        }
        const std::wstring root = (path.left(2) + QLatin1Char('\\')).toStdWString();
        const UINT type = GetDriveTypeW(root.c_str());
        return type == DRIVE_FIXED || type == DRIVE_REMOVABLE || type == DRIVE_RAMDISK || type == DRIVE_CDROM;
    }

    // 已解析的根键和子键，明确区分目标用户的 HKCU。
    struct RegistryTarget
    {
        HKEY root = nullptr; // 已识别的本地根键。
        QString subkey; // 规范化后的相对子键名称。
    };

    // 把输入根键和目标用户 SID 解析成明确的本地注册表路径。
    RegistryTarget registryTarget(const QString& input, const QString& userSid)
    {
        const QString normalized = QString(input).replace(QLatin1Char('/'), QLatin1Char('\\'));
        const int separator = normalized.indexOf(QLatin1Char('\\'));
        const QString prefix = (separator < 0 ? normalized : normalized.left(separator)).toUpper();
        QString subkey = separator < 0 ? QString() : normalized.mid(separator + 1);
        if (prefix == QStringLiteral("HKLM") || prefix == QStringLiteral("HKEY_LOCAL_MACHINE"))
            return {HKEY_LOCAL_MACHINE, subkey};
        if (prefix == QStringLiteral("HKU") || prefix == QStringLiteral("HKEY_USERS"))
            return {HKEY_USERS, subkey};
        if ((prefix == QStringLiteral("HKCU") || prefix == QStringLiteral("HKEY_CURRENT_USER"))
            && !userSid.isEmpty())
            return {HKEY_USERS, subkey.isEmpty() ? userSid : userSid + QLatin1Char('\\') + subkey};
        return {};
    }

    // 从已打开注册表句柄读取内核规范名称。
    QString registryPath(HKEY key)
    {
        // NtQueryKey 的 KeyNameInformation 返回已解析符号链接的内核规范路径。
        using QueryKey = LONG (NTAPI*)(HANDLE, int, void*, ULONG, ULONG*);
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        QueryKey function = nullptr;
        const FARPROC address = ntdll != nullptr ? GetProcAddress(ntdll, "NtQueryKey") : nullptr;
        static_assert(sizeof(function) == sizeof(address));
        std::memcpy(&function, &address, sizeof(function));
        if (function == nullptr) return {};
        ULONG size = 0;
        function(key, 3, nullptr, 0, &size);
        if (size < sizeof(ULONG) || size > 1024 * 1024) return {};
        std::vector<BYTE> bytes(size);
        if (function(key, 3, bytes.data(), size, &size) < 0) return {};
        ULONG nameBytes = 0;
        std::memcpy(&nameBytes, bytes.data(), sizeof(nameBytes));
        if (nameBytes > bytes.size() - sizeof(ULONG) || nameBytes % sizeof(wchar_t) != 0) return {};
        return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(bytes.data() + sizeof(ULONG)),
            int(nameBytes / sizeof(wchar_t)));
    }

    // 按 information 指定范围提取原始 SDDL，释放 Windows 返回的内存。
    QString sddl(PSECURITY_DESCRIPTOR descriptor, const SECURITY_INFORMATION information)
    {
        LPWSTR storage = nullptr;
        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
            information, &storage, nullptr)) return {};
        const QString result = QString::fromWCharArray(storage);
        LocalFree(storage);
        return result;
    }

    // 按锚点句柄读取所有者、组和 DACL。
    DWORD readDescriptor(const Anchor& anchor, Descriptor& descriptor)
    {
        return GetSecurityInfo(anchor.objectHandle(), anchor.objectType(),
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            nullptr, nullptr, nullptr, nullptr, &descriptor.value);
    }

    // 按锚点句柄读取完整性标签，保留读取失败状态。
    DWORD readLabel(const Anchor& anchor, Descriptor& descriptor)
    {
        return GetSecurityInfo(anchor.objectHandle(), anchor.objectType(), LABEL_SECURITY_INFORMATION,
            nullptr, nullptr, nullptr, nullptr, &descriptor.value);
    }

    // 逐项收集用户、普通和限制 SID、完整性及强制策略；缺项保留未知。
    void collectTokenEvidence(const Anchor& anchor, Result& result, std::vector<SidEvidence>& sids)
    {
        std::vector<BYTE> bytes;
        if (queryTokenBytes(anchor.token.value, TokenUser, bytes))
        {
            const auto sid = reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid;
            result.userSid = sidText(sid);
            result.user = sidAccount(sid);
            sids.push_back({result.userSid, SE_GROUP_ENABLED, true, false});
        }
        else result.sidEvidenceComplete = false;
        for (const auto type : {TokenGroups, TokenRestrictedSids})
        {
            if (!queryTokenBytes(anchor.token.value, type, bytes))
            {
                result.sidEvidenceComplete = false;
                continue;
            }
            const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(bytes.data());
            const size_t capacity = (bytes.size() - offsetof(TOKEN_GROUPS, Groups)) / sizeof(SID_AND_ATTRIBUTES);
            if (groups->GroupCount > capacity)
            {
                result.sidEvidenceComplete = false;
                continue;
            }
            for (DWORD index = 0; index < groups->GroupCount; ++index)
            {
                const auto& group = groups->Groups[index];
                const bool restricted = type == TokenRestrictedSids;
                sids.push_back({sidText(group.Sid), group.Attributes, false, restricted});
                if (restricted) ++result.restrictedGroups;
                else
                {
                    ++result.groups;
                    if (group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) ++result.denyOnlyGroups;
                }
            }
        }
        if (queryTokenBytes(anchor.token.value, TokenIntegrityLevel, bytes))
        {
            const auto sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(bytes.data())->Label.Sid;
            if (IsValidSid(sid) && *GetSidSubAuthorityCount(sid) > 0)
            {
                result.tokenRid = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
                result.tokenIntegrityKnown = true;
            }
        }
        TOKEN_MANDATORY_POLICY policy{};
        DWORD size = sizeof(policy);
        result.tokenPolicyKnown = GetTokenInformation(anchor.token.value, TokenMandatoryPolicy,
            &policy, size, &size) != FALSE;
        result.tokenPolicy = policy.Policy;
        size = sizeof(result.appContainer);
        result.appContainerKnown = GetTokenInformation(anchor.token.value, TokenIsAppContainer,
            &result.appContainer, size, &size) != FALSE;
    }

    // 以 KSword 当前身份固定对象句柄；不执行对象内容或配置变更。
    bool openTarget(Anchor& anchor, Result& result)
    {
        const auto& request = anchor.request;
        if (request.kind == ObjectKind::File)
        {
            if (!localDiskPath(request.path))
            {
                result.stage = Stage::InvalidTarget;
                result.error = ERROR_INVALID_NAME;
                return false;
            }
            const auto path = request.path.toStdWString();
            anchor.file = CreateFileW(path.c_str(), READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (anchor.file != INVALID_HANDLE_VALUE)
            {
                if (GetFileType(anchor.file) != FILE_TYPE_DISK)
                {
                    result.stage = Stage::InvalidTarget;
                    result.error = ERROR_INVALID_NAME;
                    return false;
                }
                anchor.canonicalPath = filePath(anchor.file);
                anchor.fileIdentityKnown = GetFileInformationByHandleEx(anchor.file, FileIdentityClass,
                    &anchor.fileIdentity, sizeof(anchor.fileIdentity)) != FALSE;
                if (anchor.canonicalPath.isEmpty() || !localDiskPath(anchor.canonicalPath))
                {
                    result.stage = Stage::TargetIdentity;
                    result.error = ERROR_NOT_SUPPORTED;
                    return false;
                }
            }
            else result.error = GetLastError();
        }
        else if (request.kind == ObjectKind::Registry)
        {
            const auto parsed = registryTarget(request.path, result.userSid);
            if (parsed.root == nullptr)
            {
                result.stage = Stage::InvalidTarget;
                result.error = ERROR_INVALID_NAME;
                return false;
            }
            const auto subkey = parsed.subkey.toStdWString();
            result.error = RegOpenKeyExW(parsed.root, subkey.c_str(), 0,
                READ_CONTROL | request.registryView, &anchor.key);
            if (result.error == ERROR_SUCCESS)
            {
                anchor.canonicalPath = registryPath(anchor.key);
                if (anchor.canonicalPath.isEmpty())
                {
                    result.stage = Stage::TargetIdentity;
                    result.error = ERROR_NOT_SUPPORTED;
                    return false;
                }
            }
        }
        else
        {
            if (request.path.isEmpty() || request.path.contains(QLatin1Char('\\'))
                || request.path.contains(QLatin1Char('/')))
            {
                result.stage = Stage::InvalidTarget;
                result.error = ERROR_INVALID_NAME;
                return false;
            }
            anchor.manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (anchor.manager != nullptr)
            {
                const auto name = request.path.toStdWString();
                anchor.service = OpenServiceW(anchor.manager, name.c_str(), READ_CONTROL);
            }
            if (anchor.service == nullptr) result.error = GetLastError();
            else anchor.canonicalPath = request.path;
        }
        if (result.error != ERROR_SUCCESS)
        {
            result.stage = Stage::Target;
            return false;
        }
        result.canonicalPath = anchor.canonicalPath;
        return true;
    }

    // 采集实际主令牌和描述符证据；取消或身份变化时返回失败阶段。
    Result diagnose(const Request& request, const std::shared_ptr<std::atomic_bool>& cancellation)
    {
        Result result;
        result.request = request;
        auto anchor = std::make_shared<Anchor>();
        anchor->request = request;
        if (isCancelled(cancellation, result)) return result;
        anchor->process.value = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, request.pid);
        if (anchor->process.value == nullptr)
        {
            result.stage = Stage::Process;
            result.error = GetLastError();
            return result;
        }
        if (!creationTime(anchor->process.value, anchor->creation)
            || WaitForSingleObject(anchor->process.value, 0) != WAIT_TIMEOUT)
        {
            result.stage = Stage::ProcessIdentity;
            result.error = ERROR_RETRY;
            return result;
        }
        wchar_t image[32768]{};
        DWORD imageSize = DWORD(std::size(image));
        if (QueryFullProcessImageNameW(anchor->process.value, 0, image, &imageSize))
            result.processPath = QString::fromWCharArray(image, int(imageSize));
        if (!OpenProcessToken(anchor->process.value, TOKEN_QUERY | TOKEN_DUPLICATE, &anchor->token.value))
        {
            result.stage = Stage::Token;
            result.error = GetLastError();
            return result;
        }
        if (!queryStatistics(anchor->token.value, anchor->statistics))
        {
            result.stage = Stage::TokenIdentity;
            result.error = GetLastError();
            return result;
        }
        if (!DuplicateTokenEx(anchor->token.value, TOKEN_QUERY | TOKEN_IMPERSONATE,
            nullptr, SecurityImpersonation, TokenImpersonation, &anchor->impersonation.value))
        {
            result.stage = Stage::Duplicate;
            result.error = GetLastError();
            return result;
        }
        std::vector<SidEvidence> sids;
        collectTokenEvidence(*anchor, result, sids);
        if (isCancelled(cancellation, result)) return result;
        if (!openTarget(*anchor, result)) return result;
        Descriptor descriptor;
        result.error = readDescriptor(*anchor, descriptor);
        if (result.error != ERROR_SUCCESS || descriptor.value == nullptr)
        {
            result.stage = Stage::Descriptor;
            return result;
        }
        PSID owner = nullptr;
        PSID group = nullptr;
        BOOL defaulted = FALSE;
        GetSecurityDescriptorOwner(descriptor.value, &owner, &defaulted);
        GetSecurityDescriptorGroup(descriptor.value, &group, &defaulted);
        result.ownerSid = sidText(owner);
        result.owner = sidAccount(owner);
        result.groupSid = sidText(group);
        result.descriptorSddl = sddl(descriptor.value,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION);
        if (result.descriptorSddl.isEmpty())
        {
            result.stage = Stage::Descriptor;
            result.error = ERROR_INVALID_SECURITY_DESCR;
            return result;
        }
        anchor->descriptorSddl = result.descriptorSddl;
        SECURITY_DESCRIPTOR_CONTROL control = 0;
        DWORD revision = 0;
        GetSecurityDescriptorControl(descriptor.value, &control, &revision);
        result.daclProtected = (control & SE_DACL_PROTECTED) != 0;
        PACL dacl = nullptr;
        BOOL present = FALSE;
        GetSecurityDescriptorDacl(descriptor.value, &present, &dacl, &defaulted);
        result.daclPresent = present != FALSE;
        result.nullDacl = !result.daclPresent || dacl == nullptr;
        if (dacl != nullptr)
        {
            const DWORD descriptorSize = GetSecurityDescriptorLength(descriptor.value);
            const size_t offset = reinterpret_cast<const BYTE*>(dacl)
                - static_cast<const BYTE*>(descriptor.value);
            const auto view = decodeAcl(dacl, offset <= descriptorSize ? descriptorSize - offset : 0);
            result.aclValid = view.valid;
            result.complex = view.complex;
            for (const auto& ace : view.aces)
            {
                if (isCancelled(cancellation, result)) return result;
                AceEvidence row;
                row.ace = ace;
                if (!ace.sid.empty())
                {
                    const auto sid = const_cast<BYTE*>(ace.sid.data());
                    row.sid = sidText(sid);
                    row.account = sidAccount(sid);
                    for (const auto& evidence : sids)
                        if (evidence.sid == row.sid) row.matches.push_back(evidence);
                }
                result.aces.push_back(std::move(row));
            }
        }
        if (isCancelled(cancellation, result)) return result;
        result.native = checkDescriptor(descriptor.value, anchor->impersonation.value,
            request.kind, request.desired);
        result.authz = checkDescriptorAuthz(descriptor.value, anchor->token.value,
            request.kind, request.desired);
        for (const auto& privilege : result.native.usedPrivileges)
        {
            DWORD size = 0;
            LUID luid = privilege.Luid;
            LookupPrivilegeNameW(nullptr, &luid, nullptr, &size);
            if (size == 0 || size > 32768) continue;
            std::vector<wchar_t> name(size + 1);
            if (LookupPrivilegeNameW(nullptr, &luid, name.data(), &size))
                result.usedPrivilegeNames.push_back(QString::fromWCharArray(name.data(), int(size)));
        }
        Descriptor label;
        result.labelError = readLabel(*anchor, label);
        anchor->labelError = result.labelError;
        if (result.labelError == ERROR_SUCCESS && label.value != nullptr)
        {
            result.labelKnown = true;
            result.labelRid = SECURITY_MANDATORY_MEDIUM_RID;
            result.labelPolicy = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
            result.labelSddl = sddl(label.value, LABEL_SECURITY_INFORMATION);
            anchor->labelSddl = result.labelSddl;
            PACL sacl = nullptr;
            BOOL saclPresent = FALSE;
            if (!GetSecurityDescriptorSacl(label.value, &saclPresent, &sacl, &defaulted))
                result.labelKnown = false;
            if (saclPresent && sacl != nullptr)
            {
                const DWORD descriptorSize = GetSecurityDescriptorLength(label.value);
                const size_t offset = reinterpret_cast<const BYTE*>(sacl) - static_cast<const BYTE*>(label.value);
                const auto view = decodeAcl(sacl, offset <= descriptorSize ? descriptorSize - offset : 0);
                if (!view.valid) result.labelKnown = false;
                for (const auto& ace : view.aces)
                {
                    if (ace.type != SYSTEM_MANDATORY_LABEL_ACE_TYPE || ace.sid.empty()) continue;
                    const auto sid = const_cast<BYTE*>(ace.sid.data());
                    const SID_IDENTIFIER_AUTHORITY mandatory = SECURITY_MANDATORY_LABEL_AUTHORITY;
                    if (*GetSidSubAuthorityCount(sid) == 0
                        || std::memcmp(GetSidIdentifierAuthority(sid), &mandatory, sizeof(mandatory)) != 0)
                    {
                        result.labelKnown = false;
                        continue;
                    }
                    if (result.labelExplicit) result.labelKnown = false;
                    result.labelExplicit = true;
                    result.labelRid = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
                    result.labelPolicy = ace.mask;
                    if (ace.flags & INHERIT_ONLY_ACE) result.labelKnown = false;
                }
            }
        }
        if (!result.labelKnown && result.labelError == ERROR_SUCCESS)
        {
            result.labelError = ERROR_INVALID_SECURITY_DESCR;
            // 单独保留描述符读取状态，供随后快照一致性复核。
        }
        if (isCancelled(cancellation, result)) return result;
        TOKEN_STATISTICS finalStatistics{};
        if (!queryStatistics(anchor->token.value, finalStatistics)
            || !sameStatistics(finalStatistics, anchor->statistics))
        {
            result.stage = Stage::TokenIdentity;
            result.error = ERROR_RETRY;
            return result;
        }
        if (WaitForSingleObject(anchor->process.value, 0) != WAIT_TIMEOUT)
        {
            result.stage = Stage::ProcessIdentity;
            result.error = ERROR_RETRY;
            return result;
        }
        result.anchor = std::move(anchor);
        return result;
    }

    // 复核进程创建时间、令牌修改序列、对象身份及前后描述符一致性。
    bool validateAnchor(const Anchor& anchor, Result& result)
    {
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, anchor.request.pid));
        ULONGLONG creation = 0;
        if (process.value == nullptr || !creationTime(process.value, creation)
            || creation != anchor.creation || WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT)
        {
            result.stage = Stage::ProcessIdentity;
            result.error = ERROR_RETRY;
            return false;
        }
        Handle token;
        TOKEN_STATISTICS stats{};
        TOKEN_STATISTICS retainedStats{};
        if (!OpenProcessToken(process.value, TOKEN_QUERY, &token.value)
            || !queryStatistics(token.value, stats) || !sameStatistics(stats, anchor.statistics)
            || !queryStatistics(anchor.token.value, retainedStats)
            || !sameStatistics(retainedStats, anchor.statistics))
        {
            result.stage = Stage::TokenIdentity;
            result.error = ERROR_RETRY;
            return false;
        }
        if (anchor.request.kind == ObjectKind::File)
        {
            FileIdentity identity{};
            if (!anchor.fileIdentityKnown || !GetFileInformationByHandleEx(anchor.file, FileIdentityClass,
                &identity, sizeof(identity))
                || std::memcmp(&identity, &anchor.fileIdentity, sizeof(identity)) != 0
                || filePath(anchor.file) != anchor.canonicalPath)
            {
                result.stage = Stage::TargetIdentity;
                result.error = ERROR_RETRY;
                return false;
            }
        }
        if (anchor.request.kind == ObjectKind::Registry && registryPath(anchor.key) != anchor.canonicalPath)
        {
            result.stage = Stage::TargetIdentity;
            result.error = ERROR_RETRY;
            return false;
        }
        Descriptor descriptor;
        const DWORD error = readDescriptor(anchor, descriptor);
        if (error != ERROR_SUCCESS || descriptor.value == nullptr
            || sddl(descriptor.value, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION) != anchor.descriptorSddl)
        {
            result.stage = Stage::Descriptor;
            result.error = error != ERROR_SUCCESS ? error : ERROR_RETRY;
            return false;
        }
        Descriptor label;
        const DWORD labelError = readLabel(anchor, label);
        if (labelError != anchor.labelError || (labelError == ERROR_SUCCESS
            && (label.value == nullptr || sddl(label.value, LABEL_SECURITY_INFORMATION) != anchor.labelSddl)))
        {
            result.stage = Stage::Label;
            result.error = ERROR_RETRY;
            return false;
        }
        return true;
    }

    // 专用线程身份作用域；退出前显式恢复，失败也不会污染共享线程池。
    class ScopedImpersonation
    {
    public:
        explicit ScopedImpersonation(HANDLE token)
        {
            m_active = ImpersonateLoggedOnUser(token) != FALSE;
            m_error = m_active ? ERROR_SUCCESS : GetLastError();
        }
        ~ScopedImpersonation()
        {
            if (m_active)
            {
                RevertToSelf();
            }
        }
        bool active() const
        {
            return m_active;
        }
        DWORD error() const
        {
            return m_error;
        }
        bool revert()
        {
            if (!m_active) return true;
            if (RevertToSelf())
            {
                m_active = false;
                return true;
            }
            m_error = GetLastError();
            // 第二次身份清理尝试也仅发生在一次性专用线程内。
            if (SetThreadToken(nullptr, nullptr))
            {
                m_active = false;
                return true;
            }
            return false;
        }
    private:
        bool m_active = false;
        DWORD m_error = ERROR_SUCCESS;
    };

    // 在独立线程模拟固定主令牌，申请所选权限并关闭句柄，随后复核锚点。
    Result probeOnDedicatedThread(const Result& baseline,
        const std::shared_ptr<std::atomic_bool>& cancellation)
    {
        Result result = baseline;
        result.probe = true;
        result.probeOpened = false;
        result.probeIdentityVerified = false;
        result.probeError = ERROR_SUCCESS;
        result.stage = Stage::None;
        if (isCancelled(cancellation, result) || result.anchor == nullptr) return result;
        const auto& anchor = *result.anchor;
        if (!validateAnchor(anchor, result)) return result;
        if (isCancelled(cancellation, result)) return result;
        ScopedImpersonation impersonation(anchor.impersonation.value);
        if (!impersonation.active())
        {
            result.stage = Stage::Impersonate;
            result.error = impersonation.error();
            return result;
        }
        // 模拟身份期间只申请现存文件、键或服务的句柄。
        // 不执行内容读写、安全设置、删除或服务启停。
        if (anchor.request.kind == ObjectKind::File)
        {
            const auto path = anchor.request.path.toStdWString();
            Handle handle(CreateFileW(path.c_str(), anchor.request.desired,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            result.probeOpened = handle.value != INVALID_HANDLE_VALUE;
            result.probeError = result.probeOpened ? ERROR_SUCCESS : GetLastError();
            if (result.probeOpened)
            {
                FileIdentity identity{};
                result.probeIdentityVerified = GetFileInformationByHandleEx(handle.value, FileIdentityClass,
                    &identity, sizeof(identity)) != FALSE
                    && std::memcmp(&identity, &anchor.fileIdentity, sizeof(identity)) == 0
                    && filePath(handle.value) == anchor.canonicalPath;
            }
        }
        else if (anchor.request.kind == ObjectKind::Registry)
        {
            const auto parsed = registryTarget(anchor.request.path, result.userSid);
            const auto subkey = parsed.subkey.toStdWString();
            KeyHandle key;
            result.probeError = RegOpenKeyExW(parsed.root, subkey.c_str(), 0,
                anchor.request.desired | anchor.request.registryView, &key.value);
            result.probeOpened = result.probeError == ERROR_SUCCESS;
            if (key.value != nullptr)
            {
                result.probeIdentityVerified = registryPath(key.value) == anchor.canonicalPath;
            }
        }
        else
        {
            // SCM 连接权限也在目标主体上下文中检查。
            ServiceHandle manager;
            manager.value = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (manager.value != nullptr)
            {
                const auto name = anchor.request.path.toStdWString();
                ServiceHandle service;
                service.value = OpenServiceW(manager.value, name.c_str(), anchor.request.desired);
                result.probeOpened = service.value != nullptr;
                result.probeError = result.probeOpened ? ERROR_SUCCESS : GetLastError();
                // 保留的服务句柄阻止同名服务被删除后重新创建。
                result.probeIdentityVerified = result.probeOpened && anchor.service != nullptr;
            }
            else result.probeError = GetLastError();
        }
        result.reverted = impersonation.revert();
        if (!result.reverted)
        {
            result.stage = Stage::Revert;
            result.error = impersonation.error();
            return result;
        }
        if (isCancelled(cancellation, result)) return result;
        // 关闭探针句柄后再次复核，以识别并发身份或 ACL 变化。
        if (!validateAnchor(anchor, result)) result.probeIdentityVerified = false;
        return result;
    }

}
