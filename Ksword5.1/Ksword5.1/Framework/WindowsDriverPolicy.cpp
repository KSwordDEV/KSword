#include "../Framework.h"
#include "WindowsDriverPolicy.h"

#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QUuid>

namespace ks::driver_policy
{
    namespace
    {
        // SystemToolPath：返回系统目录中的唯一工具路径；不搜索 PATH 或当前工作目录。
        QString SystemToolPath()
        {
            wchar_t buffer[MAX_PATH]{}; // buffer：系统目录的有界缓冲。
            const UINT length = ::GetSystemDirectoryW(buffer, MAX_PATH); // length：系统路径长度。
            if (length == 0 || length >= MAX_PATH)
            {
                return {};
            }
            return QDir(QString::fromWCharArray(buffer)).filePath(QString::fromLatin1("CiTool.exe"));
        }

        // ReadDword：从 64 位系统视图读取 DWORD；失败不将零值当作成功。
        bool ReadDword(const wchar_t* name, DWORD& value)
        {
            DWORD bytes = sizeof(value); // bytes：限定目标值大小，类型由 RRF 校验。
            return ::RegGetValueW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", name,
                RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, nullptr, &value, &bytes) == ERROR_SUCCESS;
        }

        // RebootMarkerAbsent：只有明确不存在才返回 true；拒绝访问同样阻止自动处理。
        bool RebootMarkerAbsent(const wchar_t* path)
        {
            HKEY key = nullptr; // key：只读标记键，不创建任何键。
            const LSTATUS status = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key); // status：区别不存在与读取失败。
            if (key != nullptr)
            {
                ::RegCloseKey(key);
            }
            return status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
        }

        // JsonTrue：兼容 CiTool 的 JSON bool/字符串 bool，但不把缺项或任意字符串当 true。
        bool JsonTrue(const QJsonValue& value)
        {
            return value.isBool() ? value.toBool()
                : value.isString() && value.toString().compare(
                    QStringLiteral("true"), Qt::CaseInsensitive) == 0;
        }

        // RunTool：仅由后台调用；超时回收子进程，返回值必须同时满足正常退出及 exit=0。
        bool RunTool(const QStringList& arguments, QByteArray& output, QString& detail)
        {
            QProcess process; // process：本次独占的系统 CiTool 子进程。
            process.setProgram(SystemToolPath());
            process.setArguments(arguments);
            process.setProcessChannelMode(QProcess::MergedChannels);
            process.start();
            if (!process.waitForStarted(3000))
            {
                detail = process.errorString();
                return false;
            }
            // 等待发生在线程池，GUI 不执行同步进程等待；任何失败都不能触发后备修改。
            if (!process.waitForFinished(15000))
            {
                process.kill();
                process.waitForFinished(3000);
                detail = QStringLiteral("CiTool timeout; ") + process.errorString();
                return false;
            }
            output = process.readAll();
            detail = QString::fromLatin1("CiTool exit=%1\n%2").arg(process.exitCode())
                .arg(QString::fromUtf8(output).trimmed().left(2048));
            return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
        }
    }

    QString EnforcePolicyId()
    {
        return QStringLiteral("{8F9CB695-5D48-48D6-A329-7202B44607E3}");
    }

    QStringList RemovalArguments()
    {
        return {QStringLiteral("--remove-policy"), EnforcePolicyId()};
    }

    UpdateState ClassifyUpdate(const unsigned long build, const unsigned long revision,
        const bool server)
    {
        // 26H2 的 26300 分支以已核实的 KB5124010 累计更新为下界，不借用 26100 的 UBR。
        // 输入仍为真实 build/UBR；更早的 26300 只返回未知，不能误称为七月以前的系统。
        // 来源：https://support.microsoft.com/en-us/servicing/os/windows-11/2026/09/
        // kb5124010-windows-11-24h2-25h2-update
        if (!server && build == 26300)
        {
            return revision >= 9550 ? UpdateState::July2026OrLater : UpdateState::Unknown;
        }

        // 2026-07-14 微软累计更新基线；不看系统日期、安装日期或 DisplayVersion。
        // Client：KB5101650 / KB5101649 / KB5099414；Server 2025：KB5099536。
        // 来源：https://support.microsoft.com/en-us/servicing/os/windows-11/2026/07/
        // july-14-2026-kb5101650-os-builds-26200-8875-and-26100-8875
        // Server：https://support.microsoft.com/en-us/servicing/os/windows-server/2026/07/
        // july-14-2026-kb5099536-os-build-26100-33158
        unsigned long minimum = 0; // minimum：该产品服务分支已经核实的七月安全更新 UBR。
        if (server)
        {
            if (build == 26100)
            {
                minimum = 33158;
            }
        }
        else
        {
            switch (build)
            {
            case 22631: minimum = 7376; break;
            case 26100:
            case 26200: minimum = 8875; break;
            case 28000: minimum = 2525; break;
            default: break;
            }
        }
        // 未登记分支（含未知 Insider/未来版本）只给帮助，不能以“build 更大”放行。
        if (minimum == 0)
        {
            return UpdateState::Unknown;
        }
        return revision >= minimum ? UpdateState::July2026OrLater : UpdateState::BeforeJuly2026;
    }

    PolicyState ParsePolicyState(const QByteArray& json)
    {
        QJsonParseError error{}; // error：避免将进程文本/损坏 JSON 误判为没有策略。
        const QJsonDocument document = QJsonDocument::fromJson(json, &error); // document：一次查询回执。
        if (error.error != QJsonParseError::NoError || !document.isObject()
            || !document.object().value(QStringLiteral("Policies")).isArray())
        {
            return PolicyState::Unknown;
        }
        const QJsonArray policies = document.object().value(QStringLiteral("Policies")).toArray(); // policies：实际列表。
        PolicyState state = PolicyState::Absent; // state：重复目标行属于异常回执，拒绝自动处理。
        for (const QJsonValue& value : policies)
        {
            const QJsonObject policy = value.toObject(); // policy：仅匹配固定强制策略，不依赖本地化名称。
            if (QUuid(policy.value(QStringLiteral("PolicyID")).toString()) != QUuid(EnforcePolicyId()))
            {
                continue;
            }
            if (state != PolicyState::Absent
                || !policy.contains(QStringLiteral("IsEnforced"))
                || !policy.contains(QString::fromLatin1("IsAuthorized")))
            {
                return PolicyState::Unknown;
            }
            state = JsonTrue(policy.value(QStringLiteral("IsEnforced")))
                && JsonTrue(policy.value(QString::fromLatin1("IsAuthorized")))
                ? PolicyState::Active : PolicyState::Inactive;
        }
        return state;
    }

    bool CanRemove(const Snapshot& snapshot)
    {
        return snapshot.update == UpdateState::July2026OrLater && snapshot.elevated
            && snapshot.rebootClear && snapshot.toolAvailable && snapshot.policy == PolicyState::Active;
    }

    Snapshot QuerySnapshot()
    {
        Snapshot snapshot; // snapshot：此次后台只读检查的完整值回执。
        OSVERSIONINFOEXW version{}; // version：真实运行版本，避开应用兼容性清单虚拟化。
        version.dwOSVersionInfoSize = sizeof(version);
        using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOEXW*);
        const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll"); // ntdll：进程已有系统模块，不加载外部 DLL。
        const auto rtlGetVersion = ntdll == nullptr ? nullptr
            : reinterpret_cast<RtlGetVersionFn>(::GetProcAddress(ntdll, "RtlGetVersion")); // rtlGetVersion：只读版本入口。
        if (rtlGetVersion != nullptr && rtlGetVersion(&version) == 0 && version.dwMajorVersion == 10)
        {
            snapshot.build = version.dwBuildNumber;
            snapshot.server = version.wProductType != VER_NT_WORKSTATION;
        }
        // CurrentBuild 在 Windows 中为 REG_SZ；用单独的类型校验读取，不能使用 DWORD 解释。
        wchar_t registryBuildText[32]{}; // registryBuildText：注册表分支字符串的有界缓冲。
        DWORD buildBytes = sizeof(registryBuildText); // buildBytes：限定字符串长度。
        DWORD revision = 0; // revision：与上述真实运行 build 配对的安装修订号。
        if (snapshot.build != 0 && ::RegGetValueW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber",
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, registryBuildText, &buildBytes) == ERROR_SUCCESS
            && QString::fromWCharArray(registryBuildText).toULong() == snapshot.build
            && ReadDword(L"UBR", revision))
        {
            snapshot.revision = revision;
            snapshot.update = ClassifyUpdate(snapshot.build, revision, snapshot.server);
        }
        HANDLE token = nullptr; // token：只读提升状态句柄，离开本段立即释放。
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            TOKEN_ELEVATION elevation{}; // elevation：当前实际提升状态，不是管理员组名推断。
            DWORD bytes = 0; // bytes：令牌信息实际长度。
            snapshot.elevated = ::GetTokenInformation(token, TokenElevation,
                &elevation, sizeof(elevation), &bytes) && elevation.TokenIsElevated != 0;
            ::CloseHandle(token);
        }
        snapshot.rebootClear = RebootMarkerAbsent(
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending")
            && RebootMarkerAbsent(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired");
        snapshot.toolAvailable = QFileInfo::exists(SystemToolPath());
        if (snapshot.toolAvailable)
        {
            QByteArray output; // output：保留 JSON 原始字节，不依赖控制台代码页。
            if (RunTool({QStringLiteral("--list-policies"), QStringLiteral("-json")}, output, snapshot.detail))
            {
                snapshot.policy = ParsePolicyState(output);
            }
        }
        return snapshot;
    }

    RemovalResult RemovePolicy()
    {
        // 点击与执行之间状态可能变化；再次核查后只调用微软支持的单一固定目标操作。
        const Snapshot current = QuerySnapshot(); // current：执行时重新冻结的真实资格。
        RemovalResult result; // result：默认不宣称成功，也没有旧系统的文件删除后备路径。
        result.detail = current.detail;
        if (!CanRemove(current))
        {
            return result;
        }
        QByteArray output; // output：命令原始回执，供用户排查失败。
        result.accepted = RunTool(RemovalArguments(), output, result.detail);
        return result;
    }
}
