#include "PrivilegeTypes.h"
namespace ks::r3::privilege {
namespace {

struct PrivilegeDescription {
    const wchar_t* name;
    const wchar_t* description;
    const wchar_t* risk;
};

// kPrivilegeDescriptions explains what each privilege actually permits. The
// Windows-supplied display name is often a fragment ("从远程系统强制关机") that
// does not say what the holder gains, and for the access-check-bypassing ones
// that gap is exactly where mistakes happen.
//
// The risk column marks privileges that let a holder go around an ACL rather
// than be granted by one. It describes the capability, not an accusation: these
// are legitimately held by backup software, debuggers and service hosts.
constexpr PrivilegeDescription kPrivilegeDescriptions[] = {
    { L"SeDebugPrivilege",
      L"可打开任意进程（含高完整性与系统进程）读写内存与线程。",
      L"可绕过进程访问检查" },
    { L"SeBackupPrivilege",
      L"读取任意文件与注册表项时绕过 ACL，用于备份。",
      L"可绕过文件读取 ACL" },
    { L"SeRestorePrivilege",
      L"写入任意文件与注册表项时绕过 ACL，并可更改所有者。",
      L"可绕过文件写入 ACL" },
    { L"SeTakeOwnershipPrivilege",
      L"无需 WRITE_OWNER 权限即可取得任意对象的所有权。",
      L"可夺取对象所有权" },
    { L"SeLoadDriverPrivilege",
      L"加载与卸载内核驱动。",
      L"可加载内核代码" },
    { L"SeTcbPrivilege",
      L"以操作系统的一部分身份运行，可构造任意令牌。",
      L"等同系统可信计算基" },
    { L"SeImpersonatePrivilege",
      L"在获得令牌后模拟其他用户执行操作。",
      L"可模拟其他账户" },
    { L"SeAssignPrimaryTokenPrivilege",
      L"以指定的主令牌创建进程。",
      L"可用他人身份建进程" },
    { L"SeCreateTokenPrivilege",
      L"直接构造访问令牌，绕过正常的登录流程。",
      L"可凭空构造令牌" },
    { L"SeSecurityPrivilege",
      L"读写对象的 SACL 并管理安全日志。",
      L"可改审计记录" },
    { L"SeSystemEnvironmentPrivilege",
      L"读写固件环境变量（含 UEFI 变量）。",
      L"可改固件变量" },
    { L"SeShutdownPrivilege", L"关闭本机。", L"" },
    { L"SeRemoteShutdownPrivilege", L"关闭远程计算机。", L"" },
    { L"SeSystemtimePrivilege", L"修改系统时间。", L"" },
    { L"SeTimeZonePrivilege", L"修改系统时区。", L"" },
    { L"SeProfileSingleProcessPrivilege", L"对单个进程做性能分析采样。", L"" },
    { L"SeSystemProfilePrivilege", L"对整个系统做性能分析采样。", L"" },
    { L"SeIncreaseBasePriorityPrivilege", L"提升进程的调度优先级。", L"" },
    { L"SeIncreaseQuotaPrivilege", L"调整进程的内存配额。", L"" },
    { L"SeIncreaseWorkingSetPrivilege", L"增加进程工作集大小。", L"" },
    { L"SeCreatePagefilePrivilege", L"创建页面文件。", L"" },
    { L"SeCreateGlobalPrivilege", L"在全局命名空间创建命名对象。", L"" },
    { L"SeCreatePermanentPrivilege", L"创建永久性内核对象。", L"" },
    { L"SeCreateSymbolicLinkPrivilege", L"创建符号链接。", L"" },
    { L"SeManageVolumePrivilege", L"执行卷维护任务，可直接打开卷设备。", L"可直接访问卷" },
    { L"SeLockMemoryPrivilege", L"将页面锁定在物理内存中。", L"" },
    { L"SeAuditPrivilege", L"生成安全审计记录。", L"" },
    { L"SeChangeNotifyPrivilege", L"遍历目录时跳过逐级权限检查（默认授予）。", L"" },
    { L"SeUndockPrivilege", L"将计算机从扩展坞中移除。", L"" },
    { L"SeEnableDelegationPrivilege", L"允许账户被信任以进行委派。", L"可配置委派" },
    { L"SeTrustedCredManAccessPrivilege", L"以受信任调用方访问凭据管理器。", L"可读凭据管理器" },
    { L"SeRelabelPrivilege", L"修改对象的完整性标签。", L"可改完整性级别" },
    { L"SeDelegateSessionUserImpersonatePrivilege", L"模拟同一会话中的其他已登录用户。", L"可模拟会话用户" },
};

} // namespace
std::wstring PrivilegeStateText(const PrivilegeEntry& entry) {
    if (entry.removed) {
        return L"已移除";
    }
    if (entry.enabled) {
        return entry.enabledByDefault ? L"已启用（默认）" : L"已启用";
    }
    return L"已禁用";
}
std::wstring DescribePrivilege(const std::wstring& privilegeName) {
    for (const PrivilegeDescription& item : kPrivilegeDescriptions) {
        if (privilegeName == item.name) {
            return item.description;
        }
    }
    return {};
}
std::wstring PrivilegeRiskText(const std::wstring& privilegeName) {
    for (const PrivilegeDescription& item : kPrivilegeDescriptions) {
        if (privilegeName == item.name) {
            return item.risk;
        }
    }
    return {};
}
}
