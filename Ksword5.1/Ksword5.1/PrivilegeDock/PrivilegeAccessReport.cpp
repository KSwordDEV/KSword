#include "../UI/StructuredFieldView.h"
#include "PrivilegeAccessBackend.h"
#include "../Internationalization/LanguageManager.h"
#include <QStringList>

// 访问诊断报告只负责当前语言的展示，采集和对象操作由 Backend 执行。
namespace ks::privilege::access::detail
{
    // 按固定 key 和规范源文本取得当前语言，不改写动态证据。
    QString text(const char* key, const char* source)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), QString::fromUtf8(source));
    }

    // 以固定宽度十六进制显示 Windows 掩码。
    QString hex(const DWORD value)
    {
        return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0')).toUpper();
    }

    // 把失败阶段映射为用户可读的当前语言说明。
    QString stageText(const Stage stage)
    {
        switch (stage)
        {
        case Stage::Cancelled: return text("privilege.workbench.access.stage.cancelled", "已取消");
        case Stage::Process: return text("privilege.workbench.access.stage.process", "打开目标进程");
        case Stage::ProcessIdentity: return text("privilege.workbench.access.stage.process_identity", "核验进程创建时间与存活状态");
        case Stage::Token: return text("privilege.workbench.access.stage.token", "读取进程主令牌");
        case Stage::TokenIdentity: return text("privilege.workbench.access.stage.token_identity", "核验令牌身份与修改序列");
        case Stage::Duplicate: return text("privilege.workbench.access.stage.duplicate", "复制模拟令牌");
        case Stage::InvalidTarget: return text("privilege.workbench.access.stage.invalid_target", "校验本地对象名称");
        case Stage::Target: return text("privilege.workbench.access.stage.target", "以 KSword 身份读取对象");
        case Stage::TargetIdentity: return text("privilege.workbench.access.stage.target_identity", "核验对象身份与规范路径");
        case Stage::Descriptor: return text("privilege.workbench.access.stage.descriptor", "读取或核验安全描述符");
        case Stage::Label: return text("privilege.workbench.access.stage.label", "核验完整性标签");
        case Stage::Impersonate: return text("privilege.workbench.access.stage.impersonate", "模拟目标进程主令牌");
        case Stage::Revert: return text("privilege.workbench.access.stage.revert", "恢复诊断线程身份");
        case Stage::Internal: return text("privilege.workbench.access.stage.internal", "后台诊断");
        default: return {};
        }
    }

    // 格式化 Win32 状态码并释放系统消息缓冲。
    QString errorText(const DWORD error)
    {
        LPWSTR storage = nullptr;
        const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0, reinterpret_cast<LPWSTR>(&storage), 0, nullptr);
        const QString message = length != 0 ? QString::fromWCharArray(storage, int(length)).trimmed() : QString();
        if (storage != nullptr) LocalFree(storage);
        return message.isEmpty() ? QString::number(error) : QString::number(error) + QStringLiteral(" — ") + message;
    }

    // 区分描述符允许、拒绝和无法计算，不能当作真实操作结论。
    QString verdict(const NativeCheck& result)
    {
        if (!result.succeeded) return text("privilege.workbench.access.unavailable", "无法评估");
        return result.allowed ? text("privilege.workbench.access.allowed", "描述符允许")
            : text("privilege.workbench.access.denied", "描述符拒绝");
    }

    // 显示 ACE 类型，未知类型保留原始编号。
    QString aceType(const AceView& ace)
    {
        if (isAllowType(ace.type)) return ace.complex
            ? text("privilege.workbench.access.ace.allow_complex", "允许（对象或条件 ACE）")
            : text("privilege.workbench.access.ace.allow", "允许");
        if (isDenyType(ace.type)) return ace.complex
            ? text("privilege.workbench.access.ace.deny_complex", "拒绝（对象或条件 ACE）")
            : text("privilege.workbench.access.ace.deny", "拒绝");
        return text("privilege.workbench.access.ace.other", "其他 ACE，类型 %1").arg(ace.type);
    }

    // 按对象类型解释访问掩码，未知位保留十六进制值。
    QString maskText(const ObjectKind kind, DWORD mask)
    {
        QStringList parts;
        const auto append = [&](const DWORD bit, const char* name)
        {
            if ((mask & bit) != 0) { parts.push_back(QString::fromLatin1(name)); mask &= ~bit; }
        };
        append(GENERIC_READ, "GENERIC_READ");
        append(GENERIC_WRITE, "GENERIC_WRITE");
        append(GENERIC_EXECUTE, "GENERIC_EXECUTE");
        append(GENERIC_ALL, "GENERIC_ALL");
        append(MAXIMUM_ALLOWED, "MAXIMUM_ALLOWED");
        append(DELETE, "DELETE");
        append(READ_CONTROL, "READ_CONTROL");
        append(WRITE_DAC, "WRITE_DAC");
        append(WRITE_OWNER, "WRITE_OWNER");
        append(SYNCHRONIZE, "SYNCHRONIZE");
        append(ACCESS_SYSTEM_SECURITY, "ACCESS_SYSTEM_SECURITY");
        if (kind == ObjectKind::File)
        {
            append(FILE_READ_DATA, "FILE_READ_DATA / LIST_DIRECTORY");
            append(FILE_WRITE_DATA, "FILE_WRITE_DATA / ADD_FILE");
            append(FILE_APPEND_DATA, "FILE_APPEND_DATA / ADD_SUBDIRECTORY");
            append(FILE_READ_EA, "FILE_READ_EA");
            append(FILE_WRITE_EA, "FILE_WRITE_EA");
            append(FILE_EXECUTE, "FILE_EXECUTE / TRAVERSE");
            append(FILE_DELETE_CHILD, "FILE_DELETE_CHILD");
            append(FILE_READ_ATTRIBUTES, "FILE_READ_ATTRIBUTES");
            append(FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES");
        }
        else if (kind == ObjectKind::Registry)
        {
            append(KEY_QUERY_VALUE, "KEY_QUERY_VALUE");
            append(KEY_SET_VALUE, "KEY_SET_VALUE");
            append(KEY_CREATE_SUB_KEY, "KEY_CREATE_SUB_KEY");
            append(KEY_ENUMERATE_SUB_KEYS, "KEY_ENUMERATE_SUB_KEYS");
            append(KEY_NOTIFY, "KEY_NOTIFY");
            append(KEY_CREATE_LINK, "KEY_CREATE_LINK");
        }
        else
        {
            append(SERVICE_QUERY_CONFIG, "SERVICE_QUERY_CONFIG");
            append(SERVICE_CHANGE_CONFIG, "SERVICE_CHANGE_CONFIG");
            append(SERVICE_QUERY_STATUS, "SERVICE_QUERY_STATUS");
            append(SERVICE_ENUMERATE_DEPENDENTS, "SERVICE_ENUMERATE_DEPENDENTS");
            append(SERVICE_START, "SERVICE_START");
            append(SERVICE_STOP, "SERVICE_STOP");
            append(SERVICE_PAUSE_CONTINUE, "SERVICE_PAUSE_CONTINUE");
            append(SERVICE_INTERROGATE, "SERVICE_INTERROGATE");
            append(SERVICE_USER_DEFINED_CONTROL, "SERVICE_USER_DEFINED_CONTROL");
        }
        if (mask != 0) parts.push_back(hex(mask));
        return parts.isEmpty() ? QStringLiteral("0") : parts.join(QStringLiteral(" | "));
    }

    // 显示继承和作用域属性，不重排原始 ACE。
    QString aceFlags(const AceView& ace)
    {
        QStringList flags;
        if (ace.flags & INHERITED_ACE) flags << text("privilege.workbench.access.flag.inherited", "继承");
        else flags << text("privilege.workbench.access.flag.explicit", "显式");
        if (ace.flags & INHERIT_ONLY_ACE) flags << text("privilege.workbench.access.flag.inherit_only", "仅对子对象生效");
        if (ace.flags & OBJECT_INHERIT_ACE) flags << QStringLiteral("OI");
        if (ace.flags & CONTAINER_INHERIT_ACE) flags << QStringLiteral("CI");
        if (ace.flags & NO_PROPAGATE_INHERIT_ACE) flags << QStringLiteral("NP");
        if (ace.malformed) flags << text("privilege.workbench.access.flag.malformed", "格式无效");
        return flags.join(QStringLiteral(" | "));
    }

    // 说明令牌 SID 与 ACE 的候选匹配来源和请求交集。
    QString matchesText(const AceEvidence& row, const Result& result)
    {
        QStringList matches;
        for (const auto& match : row.matches)
        {
            if (match.user) matches << text("privilege.workbench.access.match.user", "用户 SID");
            else if (match.restricted) matches << text("privilege.workbench.access.match.restricted", "限制 SID");
            else if (match.attributes & SE_GROUP_USE_FOR_DENY_ONLY)
                matches << text("privilege.workbench.access.match.deny_only", "仅拒绝组");
            else if (match.attributes & SE_GROUP_ENABLED)
                matches << text("privilege.workbench.access.match.enabled", "已启用组");
            else matches << text("privilege.workbench.access.match.disabled", "未启用组");
        }
        if (matches.isEmpty()) matches << text("privilege.workbench.access.match.none", "未匹配用户或常规组");
        const DWORD overlap = mappedAccess(result.request.kind, row.ace.mask)
            & mappedAccess(result.request.kind, result.request.desired);
        if (overlap != 0) matches << text("privilege.workbench.access.match.overlap", "请求交集 %1").arg(hex(overlap));
        if (row.ace.complex) matches << text("privilege.workbench.access.match.limited", "需要对象层级或条件上下文");
        return matches.join(QStringLiteral(" | "));
    }

    // 按既有顺序输出主体、描述符、限制提示与探针结论，保留 SDDL 原文。
    ks::ui::FieldDocument buildAccessDocument(const Result& result)
    {
        ks::ui::FieldDocument lines;
        if (result.stage != Stage::None)
        {
            lines.field(QStringLiteral("阶段"), QStringLiteral("%1").arg(stageText(result.stage)));
            lines.field(QStringLiteral("错误"), QStringLiteral("%1").arg(errorText(result.error)));
            if (result.error == ERROR_RETRY)
                lines.note(QStringLiteral("进程、令牌、对象或描述符已变化，请重新评估。"));
            if (!result.probe) return lines;
        }
        lines.field(QStringLiteral("主体"), QStringLiteral("PID %1").arg(QStringLiteral("%1").arg(result.request.pid)));
        lines.field(QStringLiteral("进程路径"), result.processPath);
        lines.field(QStringLiteral("用户"), QStringLiteral("%1").arg(result.user));
        lines.field(QStringLiteral("用户 SID"), result.userSid);
        if (result.anchor != nullptr)
        {
            lines.field(QStringLiteral("进程创建时间"), QStringLiteral("%1").arg(result.anchor->creation));
            lines.field(QStringLiteral("令牌 ID"), QStringLiteral("%1:%2").arg(QStringLiteral("%1").arg(result.anchor->statistics.TokenId.HighPart)).arg(QStringLiteral("%1").arg(result.anchor->statistics.TokenId.LowPart)));
            lines.field(QStringLiteral("修改序列"), QStringLiteral("%1:%2").arg(QStringLiteral("%1").arg(result.anchor->statistics.ModifiedId.HighPart)).arg(QStringLiteral("%1").arg(result.anchor->statistics.ModifiedId.LowPart)));
        }
        lines.field(QStringLiteral("常规组"), QStringLiteral("%1").arg(result.groups));
        lines.field(QStringLiteral("仅拒绝组"), QStringLiteral("%1").arg(result.denyOnlyGroups));
        lines.field(QStringLiteral("限制 SID"), QStringLiteral("%1").arg(result.restrictedGroups));
        if (!result.sidEvidenceComplete)
            lines.note(QStringLiteral("部分 SID 证据读取失败；组计数及 ACE 匹配仅反映成功读取的部分，不能把未匹配解释为不属于令牌。"));
        lines.field(QStringLiteral("对象"), QStringLiteral("%1").arg(result.request.path));
        lines.field(QStringLiteral("规范路径"), QStringLiteral("%1").arg(result.canonicalPath));
        lines.field(QStringLiteral("所有者"), QStringLiteral("%1").arg(result.owner));
        lines.field(QStringLiteral("所有者 SID"), result.ownerSid);
        lines.field(QStringLiteral("主要组 SID"), QStringLiteral("%1").arg(result.groupSid));
        lines.field(QStringLiteral("请求"), QStringLiteral("%1 → %2").arg(QStringLiteral("%1").arg(hex(result.request.desired))).arg(QStringLiteral("%1").arg(hex(mappedAccess(result.request.kind, result.request.desired)))));
        lines.field(QStringLiteral("具体权限"), QStringLiteral("%1").arg(maskText(result.request.kind, mappedAccess(result.request.kind, result.request.desired))));
        if (result.nullDacl)
            lines.field(QStringLiteral("DACL 未设置或为 NULL"), QStringLiteral("不以 DACL 限制访问；仍受令牌限制、完整性及对象机制影响。"), true);
        else if (result.aces.empty())
            lines.field(QStringLiteral("空 DACL"), QStringLiteral("没有允许 ACE；所有者隐含权利或已启用特权仍可能影响特定请求。"), true);
        else
{
            lines.field(QStringLiteral("DACL"), QStringLiteral("%1 条 ACE").arg(QStringLiteral("%1").arg(result.aces.size())));
            lines.field(QStringLiteral("保护继承"), QStringLiteral("%1").arg(result.daclProtected ? QStringLiteral("1") : QStringLiteral("0")));
            lines.field(QStringLiteral("格式"), QStringLiteral("%1").arg(result.aclValid ? text("privilege.workbench.access.valid", "有效") : text("privilege.workbench.access.invalid", "无效")));
            }
        lines.field(QStringLiteral("AccessCheck"), QStringLiteral("%1").arg(verdict(result.native)));
        lines.field(QStringLiteral("授予掩码"), QStringLiteral("授予掩码 %1").arg(QStringLiteral("%1").arg(hex(result.native.granted))));
        lines.field(QStringLiteral("状态"), QStringLiteral("状态 %1").arg(QStringLiteral("%1").arg(errorText(result.native.error))));
        lines.field(QStringLiteral("AuthzAccessCheck"), QStringLiteral("%1").arg(verdict(result.authz)));
        lines.field(QStringLiteral("授予掩码"), QStringLiteral("授予掩码 %1").arg(QStringLiteral("%1").arg(hex(result.authz.granted))));
        lines.field(QStringLiteral("状态"), QStringLiteral("状态 %1").arg(QStringLiteral("%1").arg(errorText(result.authz.error))));
        if (result.native.succeeded && result.authz.succeeded && result.native.allowed != result.authz.allowed)
            lines.field(QStringLiteral("两种描述符评估结果不同"), QStringLiteral("特权、受限令牌或条件上下文覆盖可能不同，不能合并为实际操作结论。"), true);
        if (!result.usedPrivilegeNames.empty())
        {
            QStringList names;
            for (const auto& name : result.usedPrivilegeNames) names << name;
            lines.field(QStringLiteral("AccessCheck 使用的令牌特权"), QStringLiteral("%1").arg(names.join(QStringLiteral(", "))));
        }
        if (result.tokenIntegrityKnown)
{
            lines.field(QStringLiteral("主体完整性 RID"), QStringLiteral("%1").arg(hex(result.tokenRid)));
            lines.field(QStringLiteral("令牌强制策略"), QStringLiteral("%1").arg(result.tokenPolicyKnown ? hex(result.tokenPolicy)
                    : text("privilege.workbench.access.unknown", "未知")));
            }
        else lines.field(QStringLiteral("主体完整性"), QStringLiteral("未成功读取。"), true);
        if (result.labelKnown)
        {
            lines.field(QStringLiteral("对象完整性 RID"), QStringLiteral("%1").arg(hex(result.labelRid)));
            lines.field(QStringLiteral("标签策略"), QStringLiteral("%1").arg(hex(result.labelPolicy)));
            lines.field(QStringLiteral("来源"), QStringLiteral("%1").arg(result.labelExplicit
                    ? text("privilege.workbench.access.label.explicit", "显式强制标签")
                    : text("privilege.workbench.access.label.default", "未设置标签，按 Windows 默认中完整性解释")));
            if (result.tokenIntegrityKnown && result.tokenPolicyKnown)
            {
                const DWORD hint = integrityHintMask(result.request.kind, result.request.desired,
                    result.tokenRid, result.labelRid, result.labelPolicy, result.tokenPolicy);
                lines.note((hint != 0
                    ? text("privilege.workbench.access.report.mic_hint", "完整性约束提示：请求与可能受向上访问限制的权限交集为 %1；这是按通用映射形成的证据提示，需实际打开验证。").arg(hex(hint))
                    : text("privilege.workbench.access.report.mic_no_hint", "完整性约束提示：已知标签和通用映射未发现向上访问交集；这不能证明实际操作成功。")));
            }
        }
        else{
 lines.field(QStringLiteral("对象完整性标签未知"), QStringLiteral("%1").arg(errorText(result.labelError)));
 lines.note(QStringLiteral("不能把读取失败解释为没有限制。"));
 }
        if (result.complex)
            lines.note(QStringLiteral("包含对象、回调或其他复杂 ACE；未提供对象层级、资源属性或自定义回调，相关评估覆盖有限。"));
        if (!result.appContainerKnown || result.appContainer != 0)
            lines.note(QStringLiteral("AppContainer、能力 SID 和资源声明可能引入额外约束；常规 SID 匹配列仅用于解释证据。"));
        lines.note(QStringLiteral("ACE 表按原始顺序显示。SID 匹配和请求交集仅标注候选相关 ACE，不等同于完整决策轨迹；所有者、特权、仅拒绝组及限制 SID 由 Windows 评估接口处理。"));
        lines.note(QStringLiteral("描述符由 KSword 当前身份按固定对象句柄读取；主体是选定进程的主令牌，不包含该进程线程临时模拟身份。描述符评估不覆盖路径遍历、共享锁、文件系统过滤器、中央访问策略或后续操作条件。"));
        if (!result.probe)
            lines.field(QStringLiteral("实际打开"), QStringLiteral("尚未测试。可点击“测试实际打开”模拟主令牌，申请所选访问权并立即关闭句柄。"), true);
        else if (result.stage != Stage::None)
            lines.note(QStringLiteral("实际打开测试未形成可确认的同一对象结论；请根据阶段错误重新评估。"));
        else if (!result.probeOpened)
            lines.field(QStringLiteral("实际打开"), QStringLiteral("失败，%1。失败可来自对象权限、路径、共享模式、SCM 连接或其他系统约束。").arg(QStringLiteral("%1").arg(errorText(result.probeError))));
        else if (!result.probeIdentityVerified)
            lines.note(QStringLiteral("句柄打开成功，但对象身份无法核验或已变化；不能视为所评估对象的访问证明。"));
        else lines.field(QStringLiteral("实际打开"), QStringLiteral("所选主令牌已获准打开同一对象并关闭句柄；这仅证明该时刻的句柄申请成功。"), true);
        lines.note(QStringLiteral("测试不执行写入、删除、修改 ACL 或服务控制；即使请求这些权限，也只申请并关闭句柄。未验证具体操作成功，并发变更仍可能发生。"));
        lines.field(QStringLiteral("SDDL"), result.descriptorSddl);
        if (!result.labelSddl.isEmpty()) lines.field(QStringLiteral("LABEL SDDL"), result.labelSddl);
        return lines;
    }

}
