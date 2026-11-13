// 只替换 SCM/特权写入 API，真实解析安全描述符；不创建、修改或删除机器上的服务。
#include "../shared/usermode/ServiceDeleteAccess.h"
#include <Aclapi.h>
#include <sddl.h>
#include <cstdlib>
#include <iostream>

namespace
{
    // 每种故障覆盖一个实际恢复分支；状态仅属于当前受控测试。
    enum class Fault { None, Privilege, Owner, ReopenDac, Dacl, DeleteHandle, Restore };
    Fault fault = Fault::None; // 本轮注入的故障阶段。
    bool taken = false; // 已临时接管 Owner。
    bool granted = false; // 已临时授予删除权。
    bool directDac = false; // 调用者本来就有 WRITE_DAC/WRITE_OWNER。
    int warnings = 0; // 权限告警次数。
    int closes = 0; // SCM 句柄关闭计数。
    int restores = 0; // 权限恢复调用次数。
    PSECURITY_DESCRIPTOR snapshot = nullptr; // 原 Owner/DACL 的真实 SDK 解析结果。

    // 断言失败立即终止，输出可定位的语义；输入条件及说明，无返回值。
    void Check(bool condition, const char* description)
    {
        if (!condition)
        {
            std::cerr << "FAIL: " << description << '\n';
            std::exit(1);
        }
    }

    // 模拟真实的分阶段访问检查，只有接管后才能打开 WRITE_DAC。
    SC_HANDLE WINAPI TestOpenService(SC_HANDLE, LPCWSTR, DWORD access)
    {
        SetLastError(ERROR_ACCESS_DENIED);
        if (access == READ_CONTROL)
        {
            return reinterpret_cast<SC_HANDLE>(1);
        }
        if (access == WRITE_OWNER)
        {
            return reinterpret_cast<SC_HANDLE>(2);
        }
        if (access == (WRITE_DAC | WRITE_OWNER)
            && (directDac || (taken && fault != Fault::ReopenDac)))
        {
            return reinterpret_cast<SC_HANDLE>(3);
        }
        if (access == (DELETE | SERVICE_QUERY_CONFIG) && granted && fault != Fault::DeleteHandle)
        {
            return reinterpret_cast<SC_HANDLE>(4);
        }
        return nullptr;
    }

    // 输出真实自相对 SD，模拟标准两次缓冲查询调用。
    BOOL WINAPI TestQuerySecurity(SC_HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR output,
        DWORD size, LPDWORD needed)
    {
        *needed = GetSecurityDescriptorLength(snapshot);
        if (size < *needed)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        CopyMemory(output, snapshot, *needed);
        return TRUE;
    }

    // 校验 Owner/DACL 写入及恢复；拒绝将不完整恢复误报为成功。
    BOOL WINAPI TestSetSecurity(SC_HANDLE, SECURITY_INFORMATION parts, PSECURITY_DESCRIPTOR descriptor)
    {
        if (parts & OWNER_SECURITY_INFORMATION)
        {
            PSID owner = nullptr; // 当前请求写入的所有者。
            PSID originalOwner = nullptr; // 原快照所有者，用于判断恢复。
            BOOL defaulted = FALSE; // SDK 输出标志。
            GetSecurityDescriptorOwner(descriptor, &owner, &defaulted);
            GetSecurityDescriptorOwner(snapshot, &originalOwner, &defaulted);
            if (EqualSid(owner, originalOwner))
            {
                ++restores;
                if (fault == Fault::Restore)
                {
                    SetLastError(ERROR_ACCESS_DENIED);
                    return FALSE;
                }
                if (granted)
                {
                    Check((parts & DACL_SECURITY_INFORMATION) != 0, "restore original DACL too");
                }
                taken = false;
                granted = false;
                return TRUE;
            }
            if (fault == Fault::Owner)
            {
                SetLastError(ERROR_ACCESS_DENIED);
                return FALSE;
            }
            taken = true;
            return TRUE;
        }
        Check(parts == DACL_SECURITY_INFORMATION, "only DACL is changed during permission grant");
        if (fault == Fault::Dacl)
        {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        PACL acl = nullptr; // 本次写入的真实 ACL，检查最小权限及保留旧 ACE。
        BOOL present = FALSE; // ACL 是否存在。
        BOOL defaulted = FALSE; // SDK 输出标志。
        GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted);
        Check(present && acl && acl->AceCount == 2, "preserve existing ACE and add one grant");
        bool found = false; // 是否找到最小删除权限 ACE。
        for (DWORD index = 0; index < acl->AceCount; ++index)
        {
            void* raw = nullptr; // ACL 内部 ACE，不单独释放。
            Check(GetAce(acl, index, &raw) != FALSE, "read ACE");
            const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw); // 实际允许项。
            found = found || ace->Mask == (DELETE | SERVICE_QUERY_CONFIG);
        }
        Check(found, "grant only DELETE and SERVICE_QUERY_CONFIG");
        granted = true;
        return TRUE;
    }

    // 不改变任何真实令牌，只模拟特权申请成功或 NOT_ALL_ASSIGNED。
    BOOL WINAPI TestAdjust(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD)
    {
        SetLastError(fault == Fault::Privilege ? ERROR_NOT_ALL_ASSIGNED : ERROR_SUCCESS);
        return TRUE;
    }
    // 模拟线程令牌写入；测试始终保留进程原有效身份。
    BOOL WINAPI TestSetThreadToken(PHANDLE, HANDLE)
    {
        return TRUE;
    }
    // 只统计模拟服务句柄关闭，绝不把假句柄交给操作系统。
    BOOL WINAPI TestCloseService(SC_HANDLE)
    {
        ++closes;
        return TRUE;
    }
}

#define OpenServiceW TestOpenService
#define QueryServiceObjectSecurity TestQuerySecurity
#define SetServiceObjectSecurity TestSetSecurity
#define AdjustTokenPrivileges TestAdjust
#define SetThreadToken TestSetThreadToken
#define CloseServiceHandle TestCloseService
#include "../shared/usermode/ServiceDeleteAccess.cpp"
#undef OpenServiceW
#undef QueryServiceObjectSecurity
#undef SetServiceObjectSecurity
#undef AdjustTokenPrivileges
#undef SetThreadToken
#undef CloseServiceHandle

// 运行接管成功、已有权限和每个持久修改失败分支；返回 0 表示全部通过。
int main()
{
    Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:S-1-5-80-123D:(A;;RC;;;AU)", SDDL_REVISION_1, &snapshot, nullptr) != FALSE,
        "create original service security descriptor");
    for (const bool existingDac : {false, true})
    {
        for (const Fault injected : {Fault::None, Fault::Privilege, Fault::Owner,
                Fault::ReopenDac, Fault::Dacl, Fault::DeleteHandle, Fault::Restore})
        {
            fault = injected;
            directDac = existingDac;
            taken = granted = false;
            warnings = closes = restores = 0;
            const auto result = ksword::service::OpenDeleteAccessWithTakeover(
                reinterpret_cast<SC_HANDLE>(9), L"KswordTestFixture", [] { ++warnings; });
            Check(warnings == 1, "emit one warning before privilege request");
            const bool success = fault == Fault::None
                || (existingDac && (fault == Fault::Owner || fault == Fault::ReopenDac));
            Check((result.handle != nullptr) == success, "return handle only on complete success");
            Check((result.error == ERROR_SUCCESS) == success, "retain failure status");
            Check(!(taken || granted) || fault == Fault::Restore, "restore all temporary permission changes");
            if (fault == Fault::Restore)
            {
                Check(result.securityChanged && !result.securityRestored
                    && result.restoreError == ERROR_ACCESS_DENIED, "report rollback failure separately");
                Check(restores == 1, "do not hide failed restoration with an unreported retry");
            }
            if (success)
            {
                Check(result.securityRestored && restores == 1, "restore before handing out deletion handle");
                TestCloseService(result.handle);
            }
        }
    }
    LocalFree(snapshot);
    std::cout << "PASS: 14 service permission takeover scenarios (no real service changes)\n";
    return 0;
}
