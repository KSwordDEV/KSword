#include "ServiceDeleteAccess.h"

#include <Aclapi.h>
#include <memory>
#include <vector>

namespace ksword::service
{
    namespace
    {
        // Win32 令牌与 SCM 句柄类型不同，分别封装关闭，避免异常路径泄漏。
        struct TokenCloser
        {
            void operator()(void* value) const
            {
                CloseHandle(value);
            }
        };
        struct ServiceCloser
        {
            void operator()(SC_HANDLE__* value) const
            {
                CloseServiceHandle(value);
            }
        };
        struct LocalCloser
        {
            void operator()(ACL* value) const
            {
                LocalFree(value);
            }
        };
        using Token = std::unique_ptr<void, TokenCloser>;
        using Service = std::unique_ptr<SC_HANDLE__, ServiceCloser>;

        // 输入令牌/特权名，输出 Win32 错误；必须检查 NOT_ALL_ASSIGNED，不能误报申请成功。
        DWORD EnablePrivilege(HANDLE token, const wchar_t* name)
        {
            TOKEN_PRIVILEGES privileges{}; // 本次仅启用一个特权。
            privileges.PrivilegeCount = 1;
            if (!LookupPrivilegeValueW(nullptr, name, &privileges.Privileges[0].Luid))
            {
                return GetLastError();
            }
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            SetLastError(ERROR_SUCCESS);
            if (!AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr))
            {
                return GetLastError();
            }
            return GetLastError();
        }

        // 只调整当前操作的复制令牌，不永久启用进程特权，也不污染线程池下一个任务。
        class TakeoverContext
        {
        public:
            // 输入当前线程有效身份；复制令牌、启用接管/恢复特权并临时模拟，返回错误码。
            DWORD enter()
            {
                HANDLE raw = nullptr; // 原有效线程令牌；无线程令牌时使用进程身份。
                if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, TRUE, &raw))
                {
                    previous_.reset(raw);
                }
                else if (GetLastError() != ERROR_NO_TOKEN)
                {
                    return GetLastError();
                }

                Token process; // 没有模拟身份时读取进程令牌，不能绕过已有受限线程身份。
                if (!previous_)
                {
                    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &raw))
                    {
                        return GetLastError();
                    }
                    process.reset(raw);
                }
                if (!DuplicateTokenEx(previous_ ? previous_.get() : process.get(),
                        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
                        nullptr, SecurityImpersonation, TokenImpersonation, &raw))
                {
                    return GetLastError();
                }
                elevated_.reset(raw);

                // 修改前同时准备恢复特权，否则任意原 Owner 可能无法设置回去。
                for (const wchar_t* privilege : {L"SeTakeOwnershipPrivilege", L"SeRestorePrivilege"})
                {
                    const DWORD error = EnablePrivilege(elevated_.get(), privilege); // 申请结果。
                    if (error != ERROR_SUCCESS)
                    {
                        return error;
                    }
                }
                DWORD bytes = 0; // TokenUser 缓冲区长度；SID 生命周期覆盖整个回退。
                GetTokenInformation(elevated_.get(), TokenUser, nullptr, 0, &bytes);
                user_.resize(bytes);
                if (!GetTokenInformation(elevated_.get(), TokenUser, user_.data(), bytes, &bytes))
                {
                    return GetLastError();
                }
                if (!SetThreadToken(nullptr, elevated_.get()))
                {
                    return GetLastError();
                }
                active_ = true;
                return ERROR_SUCCESS;
            }

            // 返回复制令牌用户 SID；只在 enter 成功后调用，不转交所有权。
            PSID sid() const
            {
                return reinterpret_cast<const TOKEN_USER*>(user_.data())->User.Sid;
            }

            // 恢复原线程身份；错误单独报告，避免把恢复失败伪装成完整成功。
            DWORD leave()
            {
                if (!active_)
                {
                    return ERROR_SUCCESS;
                }
                if (!SetThreadToken(nullptr, previous_.get()))
                {
                    return GetLastError();
                }
                active_ = false;
                return ERROR_SUCCESS;
            }
            ~TakeoverContext()
            {
                leave();
            }

        private:
            Token previous_; // 调用前的线程模拟令牌，没有则为空。
            Token elevated_; // 仅本操作启用特权的副本。
            std::vector<BYTE> user_; // 副本用户 SID 的存储。
            bool active_ = false; // 是否需要恢复线程身份。
        };

        // 权限快照与恢复宿主绑定同一个 SCM 句柄；异常退出也尝试恢复。
        class SecuritySnapshot
        {
        public:
            // 输入可读安全描述符的服务句柄，输出完整 Owner/DACL 快照或错误。
            DWORD capture(SC_HANDLE source)
            {
                DWORD bytes = 0; // 服务安全描述符所需大小。
                QueryServiceObjectSecurity(source, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    nullptr, 0, &bytes);
                if (bytes == 0)
                {
                    return GetLastError();
                }
                data.resize(bytes);
                if (!QueryServiceObjectSecurity(source, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        data.data(), bytes, &bytes))
                {
                    return GetLastError();
                }
                return ERROR_SUCCESS;
            }

            // 恢复快照；调用者保持 SeRestorePrivilege，且保留失败回执。
            DWORD restore()
            {
                restoreAttempted = true;
                if (!changed)
                {
                    return ERROR_SUCCESS;
                }
                const SECURITY_INFORMATION parts = OWNER_SECURITY_INFORMATION
                    | (daclChanged ? DACL_SECURITY_INFORMATION : 0); // 未改 DACL 时只恢复 Owner。
                if (!SetServiceObjectSecurity(handle.get(), parts,
                        data.data()))
                {
                    return GetLastError();
                }
                changed = false;
                return ERROR_SUCCESS;
            }
            ~SecuritySnapshot()
            {
                if (!restoreAttempted)
                {
                    restore();
                }
            }

            Service handle; // 接管前已获得 WRITE_OWNER，接管后换成同时带 WRITE_DAC 的句柄。
            std::vector<BYTE> data; // 原安全描述符，修改前分配完毕。
            bool changed = false; // 是否需要恢复；仅确认写入成功后置位。
            bool daclChanged = false; // DACL 写入成功后才要求 WRITE_DAC 恢复。
            bool restoreAttempted = false; // 正常路径已记录恢复结果时不再做无回执重试。
        };
    }

    DeleteAccessResult OpenDeleteAccessWithTakeover(SC_HANDLE manager,
        const std::wstring& name, const std::function<void()>& warning)
    {
        DeleteAccessResult result; // 对外返回原始错误和独立恢复信息。
        if (warning)
        {
            warning();
        }
        TakeoverContext context; // 声明早于权限快照，保证先恢复权限再退出特权上下文。
        result.stage = L"EnablePrivilege/SetThreadToken";
        result.error = context.enter();
        if (result.error != ERROR_SUCCESS)
        {
            return result;
        }

        SecuritySnapshot original; // 在任何持久权限修改前读取原 Owner/DACL。
        result.stage = L"OpenService(READ_CONTROL)";
        Service readable(OpenServiceW(manager, name.c_str(), READ_CONTROL));
        result.error = readable ? original.capture(readable.get()) : GetLastError();
        if (result.error == ERROR_SUCCESS)
        {
            result.stage = L"OpenService(WRITE_DAC)";
            original.handle.reset(OpenServiceW(manager, name.c_str(), WRITE_DAC | WRITE_OWNER));
            if (!original.handle && GetLastError() == ERROR_ACCESS_DENIED)
            {
                // 接管阶段只请求 WRITE_OWNER，不能夹带尚未获准的 DELETE/WRITE_DAC。
                result.stage = L"OpenService(WRITE_OWNER)";
                original.handle.reset(OpenServiceW(manager, name.c_str(), WRITE_OWNER));
                if (original.handle)
                {
                    SECURITY_DESCRIPTOR descriptor{}; // 仅设置 Owner，不触碰 DACL/SACL。
                    InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
                    SetSecurityDescriptorOwner(&descriptor, context.sid(), FALSE);
                    result.stage = L"SetServiceObjectSecurity(OWNER)";
                    if (SetServiceObjectSecurity(original.handle.get(), OWNER_SECURITY_INFORMATION, &descriptor))
                    {
                        original.changed = true;
                        Service writable(OpenServiceW(manager, name.c_str(), WRITE_DAC | WRITE_OWNER));
                        result.stage = L"OpenService(WRITE_DAC|WRITE_OWNER)";
                        if (writable)
                        {
                            original.handle = std::move(writable);
                        }
                        else
                        {
                            result.error = GetLastError();
                        }
                    }
                    else
                    {
                        result.error = GetLastError();
                    }
                }
            }
            if (!original.handle)
            {
                result.error = GetLastError();
            }
        }

        // 保留原 ACL，追加当前 SID 的最小查询/删除权；显式拒绝仍由系统判定。
        if (result.error == ERROR_SUCCESS)
        {
            PACL oldAcl = nullptr; // 指向原安全描述符内的 ACL，不单独释放。
            BOOL present = FALSE; // 区分原 NULL DACL 与普通 ACL。
            BOOL defaulted = FALSE; // GetSecurityDescriptorDacl 的附加输出。
            GetSecurityDescriptorDacl(original.data.data(), &present, &oldAcl, &defaulted);
            EXPLICIT_ACCESSW access{}; // 不授予配置、停止服务等与删除无关的权限。
            access.grfAccessPermissions = DELETE | SERVICE_QUERY_CONFIG;
            access.grfAccessMode = GRANT_ACCESS;
            access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            access.Trustee.ptstrName = static_cast<LPWSTR>(context.sid());
            PACL rawAcl = nullptr; // SetEntriesInAcl 返回的 LocalAlloc 存储。
            result.stage = L"SetEntriesInAcl";
            result.error = SetEntriesInAclW(1, &access, oldAcl, &rawAcl);
            std::unique_ptr<ACL, LocalCloser> acl(rawAcl);
            if (result.error == ERROR_SUCCESS)
            {
                SECURITY_DESCRIPTOR descriptor{}; // 仅临时更新 DACL。
                InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
                SetSecurityDescriptorDacl(&descriptor, TRUE, acl.get(), FALSE);
                result.stage = L"SetServiceObjectSecurity(DACL)";
                if (SetServiceObjectSecurity(original.handle.get(), DACL_SECURITY_INFORMATION, &descriptor))
                {
                    original.changed = true;
                    original.daclChanged = true;
                    result.stage = L"OpenService(DELETE|SERVICE_QUERY_CONFIG)";
                    result.handle = OpenServiceW(manager, name.c_str(), DELETE | SERVICE_QUERY_CONFIG);
                    result.error = result.handle ? ERROR_SUCCESS : GetLastError();
                }
                else
                {
                    result.error = GetLastError();
                }
            }
        }

        // 先恢复安全描述符，再交付已授权句柄；恢复失败不继续删除。
        result.securityChanged = original.changed;
        result.restoreError = original.restore();
        result.securityRestored = result.securityChanged && result.restoreError == ERROR_SUCCESS;
        if (result.restoreError != ERROR_SUCCESS)
        {
            result.stage = L"RestoreServiceObjectSecurity";
            result.error = result.restoreError;
        }
        const DWORD identityError = context.leave(); // 恢复线程身份也属于本次操作结果。
        if (identityError != ERROR_SUCCESS)
        {
            result.stage = L"RestoreThreadToken";
            result.error = identityError;
        }
        if (result.error != ERROR_SUCCESS && result.handle)
        {
            CloseServiceHandle(result.handle);
            result.handle = nullptr;
        }
        return result;
    }
}
