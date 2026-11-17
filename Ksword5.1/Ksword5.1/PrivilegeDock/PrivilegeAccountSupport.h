#pragma once

#include "../UI/ImmutableValueTable.h"
#include <QString>
#include <QVector>
#include <functional>

class QLabel;
class QPushButton;

// 账户工具内部共享接口；页面只提交参数，Win32/LSA 查询仍在后台执行。
namespace ks::privilege::account_detail
{
    struct Row
    {
        QString name; // 账户名或权限常量。
        QString sid; // 此行真实策略来源的 SID。
        QString detail; // 账户说明或权限说明。
        QString extra; // 成员关系或权限来源显示名。
        bool disabled = false; // 账户是否已禁用。
        QString detailRight; // 用于重新翻译权限说明的常量。
        QString path; // 汇总查询中账户到来源组的一条已确认路径。
    };

    struct RowsResult
    {
        QVector<Row> rows; // 已成功查询的结果，部分失败时仍保留。
        QString error; // 失败或不完整原因；空字符串表示范围内查询完成。
    };

    using ValueTable = ks::ui::ImmutableValueTable;
    using TableHeader = ks::ui::ImmutableTableHeader;
    using RowsWork = std::function<RowsResult()>;
    using RowsDone = std::function<void(const RowsResult&)>;

    // 输入翻译键和中文原文，返回 UI 线程或冻结后台上下文中的翻译。
    QString privilegeText(const char* key, const QString& source);
    QString privilegeWorkerText(const char* key, const QString& source);
    // 把非空诊断附加到输出，保留其它已成功采集的数据。
    void appendError(QString& target, const QString& error);
    // 同步后台查询：输入账户/SID 或权限常量，输出直接策略分配。
    RowsResult queryRights(const QString& account);
    RowsResult assignedAccounts(const QString& right);
    QStringList rightsCatalog();
    QString rightDescription(const QString& right);
    // 只读解析目标并检查权限是否已直接分配；写入函数单独执行并回读。
    RowsResult previewDirectRight(const QString& account, const QString& right);
    RowsResult writeDirectRight(const QString& sidString, const QString& right, bool add);
    // 枚举本地组和成员；preferredLength 供已有分页测试使用。
    RowsResult enumerateGroups(unsigned long preferredLength = 65536);
    RowsResult enumerateMembers(const QString& group, unsigned long preferredLength = 65536);
    RowsResult accountGroups(const QString& input);
    // 查询账户身份；extra 为 SID_NAME_USE 数值，失败不会伪装成空组关系。
    RowsResult resolveAccountIdentity(const QString& input);
    // 按 SID 广度遍历已采集的本地组关系；每个来源只展开一次，避免循环。
    RowsResult queryAccountAndGroupRights(const QString& account);
    // 输入根身份、已发现组和成员→父组索引，返回按 SID 去重且保留一条来源路径的身份集合。
    QVector<Row> reachablePolicySources(const Row& root, const QVector<Row>& seeds,
        const QHash<QString, QVector<Row>>& parents);

    // 接入已有 latest-only 后台通道，销毁页面后不再向 UI 投递结果。
    void runAccountRows(QObject* page, RowsWork work, RowsDone done);
    void runLatestAccountRows(QObject* page, const char* key, RowsWork work, RowsDone done);
    void invalidateLatestRows(QObject* page, const char* key);
    // 复用现有结果容器和复制/导出语义；写操作返回宿主是否仍存活。
    ValueTable* makeTable(QWidget* parent, QVector<TableHeader> headers);
    bool fillTable(ValueTable* table, const QVector<Row>& rows, bool account = false, bool membership = false);
    bool filterTable(ValueTable* table, const QString& query);
    bool clearRows(ValueTable* table);
    QPushButton* button(QWidget* page, const char* key, const QString& text);
    void showResult(QLabel* status, const RowsResult& result);
}
