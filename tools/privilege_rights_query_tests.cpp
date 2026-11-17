// 编译真实组权限查询实现，替换只读采集边界；不创建账户、不修改组或 LSA 策略。
#include "../Ksword5.1/Ksword5.1/Framework.h"
#include "../Ksword5.1/Ksword5.1/PrivilegeDock/PrivilegeAccountSupport.h"
#include <QCoreApplication>
#include <QSet>
#include <cstdio>
#include <cstdlib>

namespace
{
    using namespace ks::privilege::account_detail;
    Row root; // 本轮查询的规范根身份。
    RowsResult identity; // 身份解析的受控回执。
    RowsResult groups; // 本地组目录及可能的分页错误。
    RowsResult memberships; // NetAPI 补充的用户所属组关系。
    QHash<QString, RowsResult> members; // 组显示名对应的直接成员。
    QHash<QString, RowsResult> rights; // 来源 SID 对应的直接权限。
    QStringList queried; // 实际查询的来源顺序，用于检查重复访问。
    int checks = 0; // 已执行的独立断言数。

    // 输入断言和标签；失败立即退出，成功累计，无系统状态写入。
    void check(bool valid, const char* message)
    {
        ++checks;
        if (!valid)
        {
            std::fprintf(stderr, "FAIL: %s\n", message);
            std::exit(1);
        }
    }

    // 输入身份名/SID，返回组图和查询夹具共用的行；extra 默认标识本地用户。
    Row account(const QString& name, const QString& sid)
    {
        Row value; // 本次构造的值身份，不依赖系统名称解析。
        value.name = name;
        value.sid = sid;
        value.extra = QString::number(SidTypeUser);
        return value;
    }

    // 输入来源 SID，返回同名权限；多来源场景不能只按权限名称去重。
    Row right(const QString& sid)
    {
        Row value; // 含真实来源 SID 的直接分配记录。
        value.name = QStringLiteral("SeDebugPrivilege");
        value.sid = sid;
        return value;
    }
}

namespace ks::privilege::account_detail
{
    // 以下函数替换外部采集边界；输入用于选择夹具，输出仍由生产查询聚合。
    RowsResult resolveAccountIdentity(const QString&) { return identity; }
    RowsResult accountGroups(const QString&) { return memberships; }
    RowsResult enumerateGroups(unsigned long) { return groups; }
    RowsResult enumerateMembers(const QString& name, unsigned long) { return members.value(name); }
    RowsResult queryRights(const QString& sid)
    {
        queried.push_back(sid);
        return rights.value(sid);
    }

    // 夹具不加载语言包；生产代码中的诊断原文保留，便于检查错误传播。
    QString privilegeWorkerText(const char*, const QString& source) { return source; }
    void appendError(QString& target, const QString& error)
    {
        if (error.isEmpty()) return;
        if (!target.isEmpty()) target += QLatin1Char('\n');
        target += error;
    }
}

// 入口读取真实计算机名以覆盖本地身份分类；其它数据全部来自内存夹具。
int main(int argc, char** argv)
{
    using namespace ks::privilege::account_detail;
    QCoreApplication application(argc, argv); // Qt 值对象所需的测试宿主。
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1] = {}; // 当前计算机名缓冲区。
    DWORD length = MAX_COMPUTERNAME_LENGTH + 1; // 系统调用输入/输出字符数。
    check(::GetComputerNameW(computer, &length) != FALSE, "computer identity available");
    root = account(QString::fromWCharArray(computer) + QStringLiteral("\\Fixture"), QStringLiteral("S-1-5-21-1"));
    const Row a = account(QStringLiteral("GroupA"), QStringLiteral("S-1-5-32-101")); // 第一父组。
    const Row b = account(QStringLiteral("GroupB"), QStringLiteral("S-1-5-32-102")); // 循环中的第二父组。
    const Row c = account(QStringLiteral("GroupC"), QStringLiteral("S-1-5-32-103")); // NetAPI 间接来源。
    Row seed = c; // 未展开完整关系路径的间接成员。
    seed.extra = QStringLiteral("indirect");
    QHash<QString, QVector<Row>> parents; // 成员 SID 到父组的受控反向图。
    parents[root.sid] = {a, a};
    parents[a.sid] = {b};
    parents[b.sid] = {a, root};
    const auto sources = reachablePolicySources(root, {a, seed, seed}, parents); // 运行真实遍历。
    check(sources.size() == 4, "cycles and duplicate seeds terminate by SID");
    check(sources[0].sid == root.sid && sources[0].path == root.name, "root included once");
    check(sources[1].path == root.name + QStringLiteral(" → GroupA"), "direct path retained");
    check(sources[2].path == root.name + QStringLiteral(" → GroupA → GroupB"), "nested local path retained");
    check(sources[3].path.contains(QStringLiteral(" → … → ")), "unexpanded indirect path marked");

    // 三个来源具有同名权限：聚合必须保留三行，各来源仅查询一次。
    identity = {{root}, {}};
    groups = {{a, b}, {}};
    members[a.name] = {{root, b}, {}};
    members[b.name] = {{a}, {}};
    rights[root.sid] = {{right(root.sid)}, {}};
    rights[a.sid] = {{right(a.sid)}, {}};
    rights[b.sid] = {{right(b.sid)}, {}};
    auto result = queryAccountAndGroupRights(root.sid); // 实际生产聚合入口。
    check(result.error.isEmpty(), "local complete graph has no failure");
    check(result.rows.size() == 3, "same right from distinct sources retained");
    check(queried.size() == 3 && QSet<QString>(queried.begin(), queried.end()).size() == 3,
        "each source queried exactly once");
    check(result.rows[1].extra == a.name && result.rows[2].path.endsWith(QStringLiteral("GroupB")),
        "source names and paths projected into result");

    // 单个来源和成员关系读取失败时，成功的自身与父组数据仍必须保留。
    queried.clear();
    rights[b.sid] = {{}, QStringLiteral("source denied")};
    members[b.name].error = QStringLiteral("membership incomplete");
    groups.error = QStringLiteral("group enumeration incomplete");
    memberships.error = QStringLiteral("NetAPI incomplete");
    result = queryAccountAndGroupRights(root.sid);
    check(result.rows.size() == 2, "partial failures preserve successful assignments");
    check(result.error.contains(QStringLiteral("source denied"))
        && result.error.contains(QStringLiteral("membership incomplete"))
        && result.error.contains(QStringLiteral("group enumeration incomplete"))
        && result.error.contains(QStringLiteral("NetAPI incomplete")), "all partial diagnostics retained");
    check(queried.size() == 3, "partial failures do not abort remaining source queries");

    // 组身份不应调用用户所属组入口；特殊身份保留自身并明确范围限制。
    root.extra = QString::number(SidTypeAlias);
    identity = {{root}, {}};
    groups.error.clear();
    members[b.name].error.clear();
    result = queryAccountAndGroupRights(root.sid);
    check(!result.error.contains(QStringLiteral("NetAPI incomplete")), "group input skips user memberships");
    root = account(QStringLiteral("NT AUTHORITY\\SYSTEM"), QStringLiteral("S-1-5-18"));
    identity = {{root}, {}};
    rights[root.sid] = {{right(root.sid)}, {}};
    groups = {};
    memberships = {};
    result = queryAccountAndGroupRights(root.sid);
    check(result.rows.size() == 1 && !result.error.isEmpty(), "special identity keeps own rights with scope notice");

    // 无法解析显示身份时仍允许 SID 的直接分配回退，错误不得丢失或伪装完整。
    identity = {{}, QStringLiteral("identity unresolved")};
    result = queryAccountAndGroupRights(root.sid);
    check(result.rows.size() == 1 && result.error.contains(QStringLiteral("identity unresolved")),
        "identity failure preserves direct SID fallback and diagnostic");
    std::printf("Privilege rights query: %d checks passed\n", checks);
    return 0;
}
