#include "../Framework.h"
#include "PrivilegeAccountSupport.h"
#include <QSet>
#include <Windows.h>

namespace ks::privilege::account_detail
{
    // 输入根账户、已确认的间接组和本地成员索引；输出每个 SID 一次，循环关系自动终止。
    QVector<Row> reachablePolicySources(const Row& root, const QVector<Row>& seeds,
        const QHash<QString, QVector<Row>>& parents)
    {
        QVector<Row> sources; // 广度队列同时就是后续查询的来源集合。
        QSet<QString> visited; // SID 身份去重，不能用可重名的显示名称。
        const auto append = [&sources, &visited](Row row, const QString& path)
        {
            if (row.sid.isEmpty() || visited.contains(row.sid)) return;
            visited.insert(row.sid);
            row.path = path;
            sources.push_back(std::move(row));
        };
        append(root, root.name);
        // 已采集的直接关系优先建立路径，避免被含省略号的间接结果抢先占用身份。
        const auto expandParents = [&sources, &parents, &append]()
        {
            for (qsizetype index = 0; index < sources.size(); ++index)
            {
                const Row source = sources[index]; // 追加 QVector 时不持有元素引用。
                for (const Row& parent : parents.value(source.sid))
                    append(parent, source.path + QStringLiteral(" → ") + parent.name);
            }
        };
        expandParents();
        for (const Row& seed : seeds)
        {
            // NetAPI 包含间接成员时不提供中间域组路径，用“…”明确表示未展开。
            const QString separator = seed.extra == QStringLiteral("direct")
                ? QStringLiteral(" → ") : QStringLiteral(" → … → "); // 已知或间接关系。
            append(seed, root.name + separator + seed.name);
        }
        // 补上仅由 NetAPI 确认的间接成员关系，再展开这些来源的本地父组。
        expandParents();
        return sources;
    }

    // 输入账户或 SID，在后台汇总账户与可解析本地组的 LSA 分配，不修改任何系统状态。
    RowsResult queryAccountAndGroupRights(const QString& account)
    {
        RowsResult result; // 即使部分组查询失败，也保留所有成功的权限来源。
        const RowsResult identity = resolveAccountIdentity(account); // 确认账户类型和规范 SID。
        if (!identity.error.isEmpty() || identity.rows.isEmpty())
        {
            result = queryRights(account);
            appendError(result.error, identity.error);
            return result;
        }
        const Row root = identity.rows.first(); // 查询根身份，组输入同样支持向上查找本地父组。
        QVector<Row> seeds; // NetAPI 已确认的直接/间接本地组。
        if (root.extra.toInt() == SidTypeUser)
        {
            const RowsResult memberships = accountGroups(root.name); // 复用现有用户→本地组路径。
            seeds = memberships.rows;
            if (!memberships.error.isEmpty()) appendError(result.error, memberships.error);
        }

        // 构建一次反向成员索引，每个本地组仅枚举一次；可继续解析组输入及组间关系。
        const RowsResult groups = enumerateGroups(); // 本机真实组目录及分页错误。
        QHash<QString, QVector<Row>> parents; // 成员 SID → 直接包含该成员的本地组。
        if (!groups.error.isEmpty()) appendError(result.error, groups.error);
        for (const Row& group : groups.rows)
        {
            const RowsResult members = enumerateMembers(group.name); // 不在 UI 线程枚举。
            if (!members.error.isEmpty())
                appendError(result.error, group.name + QStringLiteral(": ") + members.error);
            for (const Row& member : members.rows)
            {
                if (!member.sid.isEmpty()) parents[member.sid].push_back(group);
            }
        }

        // 本次范围是本地组图；域账户不能把未知域嵌套误报为完整查询成功。
        wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1] = {}; // 比较身份域与当前计算机名。
        DWORD computerLength = MAX_COMPUTERNAME_LENGTH + 1; // GetComputerNameW 输入/输出长度。
        const bool localNameKnown = ::GetComputerNameW(computer, &computerLength) != FALSE;
        const QString domain = root.name.section(QLatin1Char('\\'), 0, 0); // 规范名称的域部分。
        const bool localIdentity = root.sid.startsWith(QStringLiteral("S-1-5-32-"))
            || (localNameKnown && domain.compare(QString::fromWCharArray(computer), Qt::CaseInsensitive) == 0);
        if (!localIdentity)
            appendError(result.error, privilegeWorkerText("privilege.workbench.rights.group_scope_partial",
                QStringLiteral("已查询自身及可解析的本地组；域组与特殊身份的完整成员关系未展开。")));

        const QVector<Row> sources = reachablePolicySources(root, seeds, parents); // 去重后的来源及证据路径。
        for (const Row& source : sources)
        {
            const RowsResult rights = queryRights(source.sid); // 直接分配逐来源查询，保留拒绝登录项。
            if (!rights.error.isEmpty())
                appendError(result.error, source.name + QStringLiteral(": ") + rights.error);
            for (Row row : rights.rows)
            {
                row.extra = source.name;
                row.path = source.path;
                result.rows.push_back(std::move(row));
            }
        }
        return result;
    }
}
