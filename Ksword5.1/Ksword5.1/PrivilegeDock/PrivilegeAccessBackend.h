#pragma once

// 访问诊断内部协议：UI、采集后端和报告格式共享同一值类型。
// 调用方只提交 Request 和取消标记；后台不访问 Qt 窗口对象。
#include "PrivilegeAccessSecurity.h"
#include <QString>
#include <atomic>
#include <memory>
#include <vector>

namespace ks::privilege::access::detail
{
    // 普通进程、令牌和文件句柄的 RAII 所有者。
    struct Handle
    {
        HANDLE value = nullptr; // 当前对象的唯一拥有资源或查询值。
        // 接管 handle；不复制所有权，析构时关闭有效句柄。
        explicit Handle(HANDLE handle = nullptr) : value(handle) {}
        ~Handle()
        {
            if (value != nullptr && value != INVALID_HANDLE_VALUE)
            {
                CloseHandle(value);
            }
        }
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
    };

    // Windows 分配的安全描述符，析构时使用 LocalFree 释放。
    struct Descriptor
    {
        PSECURITY_DESCRIPTOR value = nullptr; // 当前对象的唯一拥有资源或查询值。
        ~Descriptor()
        {
            if (value != nullptr)
            {
                LocalFree(value);
            }
        }
        Descriptor() = default;
        Descriptor(const Descriptor&) = delete;
        Descriptor& operator=(const Descriptor&) = delete;
    };

    // 注册表探针句柄，离开作用域即关闭。
    struct KeyHandle
    {
        HKEY value = nullptr; // 当前对象的唯一拥有资源或查询值。
        ~KeyHandle()
        {
            if (value != nullptr)
            {
                RegCloseKey(value);
            }
        }
    };

    // SCM 或服务探针句柄，离开作用域即关闭。
    struct ServiceHandle
    {
        SC_HANDLE value = nullptr; // 当前对象的唯一拥有资源或查询值。
        ~ServiceHandle()
        {
            if (value != nullptr)
            {
                CloseServiceHandle(value);
            }
        }
    };

    // 令牌中的一个 SID 及属性，用于说明 ACE 匹配来源。
    struct SidEvidence
    {
        QString sid; // 稳定 SID 字符串。
        DWORD attributes = 0; // Windows 原始 SID 属性位。
        bool user = false; // 是否为主体用户 SID。
        bool restricted = false; // 是否属于限制 SID 集合。
    };

    // 诊断输入快照，由 UI 校验后按值提交后台。
    struct Request
    {
        DWORD pid = 0; // 目标进程 PID。
        ObjectKind kind = ObjectKind::File; // 文件、注册表或服务对象类别。
        QString path; // 输入的对象名称。
        DWORD desired = GENERIC_READ; // 请求的原始访问掩码。
        DWORD registryView = KEY_WOW64_64KEY; // 明确的注册表 32/64 位视图。
    };

    // FILE_ID_INFO 的公开 ABI；保持兼容较旧 SDK 的声明宏。
    // 文件卷号和 128 位标识，避免同名文件被替换后误认。
    struct FileIdentity
    {
        ULONGLONG volume = 0; // 所属卷的序列号。
        BYTE id[16]{}; // 该卷内文件的 128 位标识。
    };
    constexpr auto FileIdentityClass = static_cast<FILE_INFO_BY_HANDLE_CLASS>(18);
    static_assert(sizeof(FileIdentity) == 24);

    enum class Stage
    {
        None, Cancelled, Process, ProcessIdentity, Token, TokenIdentity, Duplicate,
        InvalidTarget, Target, TargetIdentity, Descriptor, Label, Impersonate, Revert, Internal
    };

    // 保留进程、令牌和对象句柄，以便探针前后复核同一证据。
    struct Anchor
    {
        Request request; // 用户请求的不可变副本。
        Handle process; // 保留的进程对象句柄。
        Handle token; // 保留的目标主令牌。
        Handle impersonation; // 复制的模拟令牌，只用于访问计算和专用探针线程。
        HANDLE file = INVALID_HANDLE_VALUE; // 固定文件对象的句柄。
        HKEY key = nullptr; // 固定注册表键对象的句柄。
        SC_HANDLE service = nullptr; // 固定服务对象的句柄。
        SC_HANDLE manager = nullptr; // 本地 SCM 连接句柄。
        ULONGLONG creation = 0; // 进程创建时间，防止 PID 复用。
        TOKEN_STATISTICS statistics{}; // 主令牌身份和修改序列。
        FileIdentity fileIdentity{}; // 保留文件的卷号与文件标识。
        bool fileIdentityKnown = false; // 文件身份是否成功读取。
        QString canonicalPath; // 固定句柄解析出的规范路径。
        QString descriptorSddl; // 用于前后比较的原始描述符 SDDL。
        QString labelSddl; // 用于前后比较的原始完整性标签 SDDL。
        DWORD labelError = ERROR_SUCCESS; // 标签读取的 Win32 状态。
        ~Anchor()
        {
            if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
            if (key != nullptr) RegCloseKey(key);
            if (service != nullptr) CloseServiceHandle(service);
            if (manager != nullptr) CloseServiceHandle(manager);
        }
        HANDLE objectHandle() const
        {
            if (request.kind == ObjectKind::Registry) return reinterpret_cast<HANDLE>(key);
            if (request.kind == ObjectKind::Service) return reinterpret_cast<HANDLE>(service);
            return file;
        }
        SE_OBJECT_TYPE objectType() const
        {
            if (request.kind == ObjectKind::Registry) return SE_REGISTRY_KEY;
            if (request.kind == ObjectKind::Service) return SE_SERVICE;
            return SE_FILE_OBJECT;
        }
    };

    // 保持原始 ACL 顺序的 ACE 和 SID 匹配信息。
    struct AceEvidence
    {
        AceView ace; // 经过长度验证的原始 ACE 视图。
        QString sid; // 稳定 SID 字符串。
        QString account; // 用于展示的账户名称，不用于关联身份。
        std::vector<SidEvidence> matches; // 匹配此 ACE 的令牌 SID 及属性。
    };

    // 诊断值快照，同时保存完整、不完整和不可读的证据。
    struct Result
    {
        Request request; // 用户请求的不可变副本。
        Stage stage = Stage::None; // 诊断停止或失败的阶段。
        DWORD error = ERROR_SUCCESS; // 主流程 Win32 错误。
        std::shared_ptr<Anchor> anchor; // 后台工作共同持有的身份锚点。
        QString processPath; // 目标进程的映像路径。
        QString user; // 是否为主体用户 SID。
        QString userSid; // 主体用户 SID。
        QString owner; // 对象所有者显示名称。
        QString ownerSid; // 对象所有者 SID。
        QString groupSid; // 对象主要组 SID。
        QString canonicalPath; // 固定句柄解析出的规范路径。
        QString descriptorSddl; // 用于前后比较的原始描述符 SDDL。
        QString labelSddl; // 用于前后比较的原始完整性标签 SDDL。
        bool daclPresent = false; // 描述符是否包含 DACL。
        bool nullDacl = false; // DACL 是否未设置或为 NULL。
        bool aclValid = true; // ACE 长度和 SID 格式是否通过校验。
        bool complex = false; // 是否存在需额外条件或对象层级的 ACE。
        bool daclProtected = false; // DACL 是否禁止继承。
        bool labelKnown = false; // 对象完整性标签是否可解释。
        bool labelExplicit = false; // 是否存在显式完整性标签。
        DWORD labelError = ERROR_SUCCESS; // 标签读取的 Win32 状态。
        DWORD labelRid = 0; // 对象完整性级别 RID。
        DWORD labelPolicy = 0; // 对象强制标签策略。
        bool tokenIntegrityKnown = false; // 主体完整性级别是否已读取。
        DWORD tokenRid = 0; // 主体完整性级别 RID。
        bool tokenPolicyKnown = false; // 主体强制策略是否已读取。
        DWORD tokenPolicy = 0; // 主体令牌强制策略位。
        bool appContainerKnown = false; // AppContainer 状态是否已读取。
        DWORD appContainer = 0; // 主体 AppContainer 状态。
        DWORD groups = 0; // 成功读取的普通组数量。
        DWORD denyOnlyGroups = 0; // 普通组中仅拒绝 SID 的数量。
        DWORD restrictedGroups = 0; // 成功读取的限制 SID 数量。
        bool sidEvidenceComplete = true; // SID 证据是否完整。
        std::vector<AceEvidence> aces; // 保持原始顺序的 ACE 证据。
        NativeCheck native; // AccessCheck 计算回执。
        NativeCheck authz; // AuthzAccessCheck 计算回执。
        bool probe = false; // 是否执行过真实打开探针。
        bool probeOpened = false; // 请求权限的打开是否成功。
        bool probeIdentityVerified = false; // 打开对象是否与固定锚点一致。
        bool reverted = true; // 探针线程是否恢复身份。
        DWORD probeError = ERROR_SUCCESS; // 真实打开的 Win32 状态。
        std::vector<QString> usedPrivilegeNames; // AccessCheck 使用的特权名称。
    };


    // diagnose：读取 request 的进程主令牌和对象描述符；返回证据与失败阶段。
    Result diagnose(const Request& request, const std::shared_ptr<std::atomic_bool>& cancellation);

    // probeOnDedicatedThread：仅供独立线程使用；复核 baseline 后申请并立即关闭对象句柄。
    Result probeOnDedicatedThread(const Result& baseline,
        const std::shared_ptr<std::atomic_bool>& cancellation);

    // 以下格式化入口只在 UI 线程调用，保留当前语言和原始报告行顺序。
    QString text(const char* key, const char* source);
    QString hex(DWORD value);
    QString stageText(Stage stage);
    QString errorText(DWORD error);
    QString aceType(const AceView& ace);
    QString maskText(ObjectKind kind, DWORD mask);
    QString aceFlags(const AceView& ace);
    QString matchesText(const AceEvidence& row, const Result& result);
    QString reportText(const Result& result);
}
