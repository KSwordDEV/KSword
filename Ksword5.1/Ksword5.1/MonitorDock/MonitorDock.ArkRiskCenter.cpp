#include "MonitorDock.h"
#include "../UI/VisibleTableWidget.h"
#include "../Internationalization/LanguageManager.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../ksword/process/process.h"
#include "../theme.h"

// F-09 / F-12：本文件是把这两条判据接进生产调用点的第一处。
// 判据本身留在 shared/evidence 里（Qt-free / Win32-free），这边只做值转换和提示文案，
// 不在 Qt 侧另造一套“像不像同一个进程”的土办法。
#include "../../../shared/evidence/LiveNavigation.h"
#include "../../../shared/evidence/ObjectIdentity.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QByteArray>
#include <QCheckBox>
#include <QClipboard>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QIODevice>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaMethod>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QVariant>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

// evidence：分析层判据的短别名。生产侧只往里传值、只读它的枚举结论。
namespace evidence = Ksword::Evidence;

namespace
{
    enum class RiskColumn : int { Score = 0, Source, Category, Title, Detail, Count };

    constexpr int kRiskEntryIndexRole = Qt::UserRole + 1;
    constexpr int kRiskProcessIdRole = Qt::UserRole + 2;
    // kRiskEvidenceIdRole：F-12 的证据 id 随表格行走。
    // 为什么不复用 kRiskEntryIndexRole 去查缓存：下标在快照被换掉之后仍然“有效”，
    // 会静默指向另一条记录；证据 id 查不到就是查不到，能把这种情况显式暴露出来。
    constexpr int kRiskEvidenceIdRole = Qt::UserRole + 3;

    // ERROR_ACCESS_DENIED / ERROR_INVALID_PARAMETER。
    // 这里不引 Windows.h：本文件只需要区分“读不到”和“不存在”两种失败，
    // 用两个常量比拖进整个 Win32 头更清楚。
    constexpr std::uint64_t kWin32ErrorAccessDenied = 5U;
    constexpr std::uint64_t kWin32ErrorInvalidParameter = 87U;

    int riskColumnIndex(const RiskColumn column)
    {
        // Input: risk-center logical column. Processing: cast to Qt table column. Return: integer index.
        return static_cast<int>(column);
    }

    QString hex64(const std::uint64_t value)
    {
        // Input: 64-bit address/hash/mask. Processing: render fixed-width uppercase hex. Return: display text.
        return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 16, 16, QChar('0')).toUpper();
    }

    QString hex32(const std::uint32_t value)
    {
        // Input: 32-bit flags/status. Processing: render fixed-width uppercase hex. Return: display text.
        return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')).toUpper();
    }

    QString wideText(const std::wstring& value)
    {
        // Input: ArkDriverClient wide string. Processing: convert to QString. Return: empty or display text.
        return value.empty() ? QString() : QString::fromStdWString(value);
    }

    QString narrowText(const std::string& value)
    {
        // Input: ArkDriverClient narrow string. Processing: convert to QString. Return: empty or display text.
        return value.empty() ? QString() : QString::fromStdString(value);
    }

    QString friendlyIoMessage(const std::string& value)
    {
        // 输入：ArkDriverClient io.message 原始文本。
        // 处理：把 DeviceIoControl/unsupported/空消息转换为适合状态栏和风险明细的中文说明。
        // 返回：可直接拼入 ARK 风险中心摘要行的短文本。
        const QString rawText = narrowText(value).trimmed();
        if (rawText.isEmpty())
        {
            return QStringLiteral("无额外驱动消息");
        }
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该审计入口");
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供该审计入口");
        }
        return rawText;
    }

    double clampScore(const double score)
    {
        // Input: arbitrary risk score. Processing: clamp to the risk-center range. Return: 0..100 score.
        return std::max(0.0, std::min(100.0, score));
    }

    QString scoreText(const double score)
    {
        // Input: normalized risk score. Processing: keep one decimal place. Return: sortable display text.
        return QString::number(clampScore(score), 'f', 1);
    }

    QString ioSummary(const ksword::ark::IoResult& io)
    {
        // Input: ArkDriverClient I/O result. Processing: compact transport/protocol diagnostics. Return: one line.
        return QStringLiteral("ok=%1 win32=%2 nt=%3 bytes=%4 说明=%5")
            .arg(io.ok ? QStringLiteral("true") : QStringLiteral("false"))
            .arg(io.win32Error)
            .arg(hex32(static_cast<std::uint32_t>(io.ntStatus)))
            .arg(io.bytesReturned)
            .arg(friendlyIoMessage(io.message));
    }

    QString arkRiskTableMenuStyle()
    {
        // 输入：无。
        // 处理：生成不透明 QMenu 样式，避免深色主题下右键菜单透明或文字不可读。
        // 返回：可直接 setStyleSheet 到表格右键菜单的样式文本。
        return QStringLiteral(
            "QMenu{background:%1;color:%2;border:1px solid %3;}"
            "QMenu::item{padding:5px 24px 5px 24px;background:transparent;}"
            "QMenu::item:selected{background:%4;color:%6;}"
            "QMenu::item:disabled{color:%5;}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::TextSecondaryHex())
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    void copyArkRiskTableCurrentRow(QTableWidget* table)
    {
        // 输入：风险中心表格。
        // 处理：读取当前显示行的所有列，按 TSV 写入剪贴板。
        // 返回：无返回值；无当前行或剪贴板不可用时静默返回。
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int rowIndex = table->currentRow();
        if (rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(fields.join(QChar('\t')));
    }

    void installArkRiskTableCopyMenu(MonitorDock* dock, QTableWidget* table)
    {
        // 输入：风险中心所属 Dock 与结果表格。
        // 处理：安装“复制当前行”和“转到进程详细信息”的右键菜单；右键点击行时同步当前单元格。
        //       跳转本身交给 MonitorDock::navigateToProcessDetailFromArkRiskRow，因为
        //       F-09/F-12 的判据需要读 Dock 的快照缓存（证据 id 反查），菜单这层拿不到。
        // 返回：无返回值；不触发任何审计动作或系统修改。
        if (dock == nullptr || table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QPointer<MonitorDock> guardDock(dock);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [guardDock, table](const QPoint& localPosition) {
            const QModelIndex clickedIndex = table->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                table->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            }

            QMenu menu(table);
            menu.setStyleSheet(arkRiskTableMenuStyle());
            QAction* copyRowAction = menu.addAction(QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);

            quint32 processId = 0U;
            const QTableWidgetItem* scoreItem = table->currentRow() >= 0
                ? table->item(table->currentRow(), riskColumnIndex(RiskColumn::Score))
                : nullptr;
            bool processIdOk = false;
            const qulonglong storedProcessId = scoreItem != nullptr
                ? scoreItem->data(kRiskProcessIdRole).toULongLong(&processIdOk)
                : 0ULL;
            if (processIdOk && storedProcessId > 0ULL &&
                storedProcessId <= static_cast<qulonglong>(std::numeric_limits<quint32>::max()))
            {
                processId = static_cast<quint32>(storedProcessId);
            }

            QAction* openProcessAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_details.svg")),
                QStringLiteral("转到进程详细信息"));
            // 只要这行指向某个 PID 就允许点击：身份够不够由判据说了算，
            // 说明也由判据给。菜单这层提前灰掉只会让用户不知道为什么不能跳。
            openProcessAction->setEnabled(processId != 0U);

            const int currentRow = table->currentRow();
            const QAction* selectedAction = menu.exec(table->viewport()->mapToGlobal(localPosition));
            if (selectedAction == copyRowAction)
            {
                copyArkRiskTableCurrentRow(table);
            }
            else if (selectedAction == openProcessAction && guardDock != nullptr)
            {
                guardDock->navigateToProcessDetailFromArkRiskRow(currentRow);
            }
        });
    }

    quint32 payloadProcessId(const QJsonObject& payload)
    {
        const QJsonValue processIdValue = payload.value(QStringLiteral("processId"));
        bool processIdOk = false;
        const qulonglong processId = processIdValue.toVariant().toULongLong(&processIdOk);
        return processIdOk && processId > 0ULL &&
            processId <= static_cast<qulonglong>(std::numeric_limits<quint32>::max())
            ? static_cast<quint32>(processId)
            : 0U;
    }

    QString arkRiskSessionBootId()
    {
        // 输入：无。
        // 处理：返回本次 KSword 运行的会话标识，用作 ProcessInstanceId::bootId 的保守替身。
        //       为什么可以这么用（F-03/F-09）：
        //         1) ObjectIdentity.h 要求两侧 bootId 非空且相等才可能判 Confirmed，这一位
        //            是用来挡“跨启动的同 PID”的；
        //         2) 风险中心快照只存在于内存，采集与点击必然发生在同一次进程运行内，而一
        //            次进程运行不可能跨越重启，所以“同一运行 ⇒ 同一启动周期”不是过度声称；
        //         3) 反向的偏差是安全的：两次运行即使同属一次系统启动也会拿到不同 token，
        //            结果只会退化成 Candidate 并拒绝跳转，不会放行错误目标。
        // 返回：进程内恒定的会话标识文本。
        static const QString sessionBootId = QStringLiteral("ksword-run-%1-%2")
            .arg(static_cast<qulonglong>(QCoreApplication::applicationPid()))
            .arg(static_cast<qulonglong>(QDateTime::currentMSecsSinceEpoch()));
        return sessionBootId;
    }

    bool parseWin32CodeFromDetail(const std::string& detailText, std::uint64_t& codeOut)
    {
        // 输入：ks::process::QueryProcessCreationTimeByPid 的诊断原文，形如 "OpenProcess failed(5)"。
        // 处理：取最后一对括号里的十进制数。解析失败绝不编一个 0 出来——那会把“错误码未知”
        //       伪装成“错误码是 0（成功）”。
        // 返回：解析成功为 true 且写 codeOut，否则 false 且不改 codeOut。
        const std::size_t openIndex = detailText.rfind('(');
        if (openIndex == std::string::npos)
        {
            return false;
        }
        const std::size_t closeIndex = detailText.find(')', openIndex + 1U);
        if (closeIndex == std::string::npos || closeIndex <= openIndex + 1U)
        {
            return false;
        }
        const std::string_view codeText =
            std::string_view(detailText).substr(openIndex + 1U, closeIndex - openIndex - 1U);
        return evidence::ParseU64(codeText, codeOut);
    }

    struct LiveProcessProbe final
    {
        // present：是否有正面证据表明该 PID 当前确实绑着一个进程对象。
        // 注意它不等于 createTimeKnown：权限不足读不到创建时间，恰恰说明对象存在。
        bool present = false;
        bool createTimeKnown = false;
        std::uint64_t createTime100ns = 0U;
        evidence::CollectionOutcome outcome;
    };

    LiveProcessProbe probeProcessCreateTime(const std::uint32_t processId)
    {
        // 输入：目标 PID。
        // 处理：读一次当前进程实例的创建时间，并把失败语义拆开（F-05）：
        //         * 成功                       -> present + createTimeKnown
        //         * ERROR_INVALID_PARAMETER(87) -> 这个 PID 上没有进程，present=false
        //         * ERROR_ACCESS_DENIED(5) 及其它 -> 对象在，但创建时间读不到，present=true
        //       为什么默认落在“读不到”而不是“已退出”：ResolveProcessNavigation 把
        //       !found 直接判成 RejectObjectExited；如果把权限失败也算作 !found，就会
        //       对一个还活着的进程宣称“已退出”，那是凭空捏造的结论。
        //       两条路径都会拒绝跳转，差别只在给用户的说明是否属实。
        // 返回：探测结果；原始错误码与原文一并保留在 outcome 里。
        LiveProcessProbe probe;
        if (processId == 0U)
        {
            probe.outcome = evidence::CollectionOutcome::notCollected();
            return probe;
        }

        std::uint64_t createTime100ns = 0U;
        std::string detailText;
        if (ks::process::QueryProcessCreationTimeByPid(processId, &createTime100ns, &detailText))
        {
            probe.present = true;
            probe.createTimeKnown = true;
            probe.createTime100ns = createTime100ns;
            probe.outcome = evidence::CollectionOutcome::success();
            return probe;
        }

        std::uint64_t win32Code = 0U;
        const bool codeKnown = parseWin32CodeFromDetail(detailText, win32Code);
        if (!codeKnown)
        {
            // 错误码解析不出来：状态记 Error，nativeCode 保持 unset（“未知”不是 0）。
            probe.present = true;
            probe.outcome.status = evidence::CollectionStatus::Error;
            probe.outcome.message = detailText;
            return probe;
        }

        probe.present = win32Code != kWin32ErrorInvalidParameter;
        probe.outcome = evidence::CollectionOutcome::failure(
            win32Code == kWin32ErrorAccessDenied
                ? evidence::CollectionStatus::AccessDenied
                : evidence::CollectionStatus::Error,
            std::string("WIN32"),
            win32Code,
            detailText);
        return probe;
    }

    evidence::ProcessInstanceId makeSavedProcessIdentity(const MonitorDock::ArkRiskCenterEntry& entry)
    {
        // 输入：一行风险记录。
        // 处理：把采集期固定下来的字段翻译成分析层的 ProcessInstanceId。只做值转换，
        //       不把 Qt 类型塞进 shared/evidence。
        //       pid / createTime 缺失时保持 OptionalU64 的 unset 状态：那会让 strength()
        //       落到 Weak/Unusable，crossSessionKey() 返回空串，导航随即被判 IdentityUnusable。
        //       这正是我们想要的——身份不足就不许跳。
        // 返回：采集期身份。
        evidence::ProcessInstanceId identity;
        identity.bootId = entry.identityBootId.toStdString();
        if (entry.processId != 0U)
        {
            identity.pid = evidence::OptionalU64::of(static_cast<std::uint64_t>(entry.processId));
        }
        if (entry.processCreateTimeKnown)
        {
            identity.createTime100ns = evidence::OptionalU64::of(entry.processCreateTime100ns);
        }
        identity.imageName = entry.payload.value(QStringLiteral("imageName")).toString().toStdString();
        return identity;
    }

    QJsonValue optionalU64Json(const evidence::OptionalU64& value, const evidence::U64Format format)
    {
        // 输入：可能未知的 64 位值与持久化格式。
        // 处理：未知写 JSON null，已知写十进制/十六进制字符串。
        //       F-08：全程走字符串，不经过 double；“未知”也绝不退化成 "0"。
        // 返回：可直接插入 payload 的 JSON 值。
        const std::string text = evidence::FormatOptionalU64(value, format);
        return text.empty() ? QJsonValue(QJsonValue::Null) : QJsonValue(QString::fromStdString(text));
    }

    QJsonObject collectionOutcomeJson(const evidence::CollectionOutcome& outcome)
    {
        // 输入：一次采集的结果。
        // 处理：把状态、原始错误码域、原始错误码和原文一起写进导出，
        //       让“权限不足 / 不存在 / 其它失败”在 JSON/CSV 里也保持可区分（F-05）。
        // 返回：payload 子对象。
        QJsonObject json;
        json.insert(QStringLiteral("status"),
            QString::fromLatin1(evidence::CollectionStatusName(outcome.status)));
        json.insert(QStringLiteral("nativeCodeDomain"),
            outcome.nativeCodeDomain.empty() ? QJsonValue(QJsonValue::Null)
                                             : QJsonValue(QString::fromStdString(outcome.nativeCodeDomain)));
        json.insert(QStringLiteral("nativeCode"),
            optionalU64Json(outcome.nativeCode, evidence::U64Format::Decimal));
        json.insert(QStringLiteral("message"),
            outcome.message.empty() ? QJsonValue(QJsonValue::Null)
                                    : QJsonValue(QString::fromStdString(outcome.message)));
        return json;
    }

    void attachArkRiskNavigationIdentity(
        std::vector<MonitorDock::ArkRiskCenterEntry>& entries,
        const QString& sessionBootId,
        const std::uint64_t refreshTicket)
    {
        // 输入：已排好序的风险行、本次运行的会话标识、本轮刷新票据。
        // 处理：F-12 给每行发一个证据 id；F-09 在**采集瞬间**就把该行指向的进程实例
        //       身份（PID + 创建时间）固定下来。
        //       为什么创建时间必须在这里读：等用户点击时再读，读到的是“此刻占着这个
        //       PID 的进程”，那就没有任何东西能证明它和风险行说的是同一个实例——PID
        //       复用会被完全漏掉。
        //       读不到时保持 processCreateTimeKnown=false，绝不写 0 顶替。
        // 返回：无返回值。本函数在工作线程运行，只写源文本与数值，不调用 LanguageManager。
        std::unordered_map<std::uint32_t, LiveProcessProbe> probeCache;
        for (std::size_t index = 0; index < entries.size(); ++index)
        {
            MonitorDock::ArkRiskCenterEntry& entry = entries[index];
            // 证据 id 带上票据：旧快照的行不会和新快照的行撞号，
            // 于是“菜单还开着但快照已换”能被查出来而不是静默指向别人。
            entry.evidenceId = QStringLiteral("ark-risk/%1/%2")
                .arg(static_cast<qulonglong>(refreshTicket))
                .arg(static_cast<qulonglong>(index));
            entry.payload.insert(QStringLiteral("evidenceId"), entry.evidenceId);

            entry.identityBootId = sessionBootId;
            entry.processId = static_cast<std::uint32_t>(payloadProcessId(entry.payload));
            if (entry.processId == 0U)
            {
                // 这行本来就不指向进程（驱动 / CPU / Hook 类）。
                // 保持 NotCollected：不是“采集失败”，也不是“没有身份问题”。
                entry.processIdentityOutcome = evidence::CollectionOutcome::notCollected();
                continue;
            }

            auto cached = probeCache.find(entry.processId);
            if (cached == probeCache.end())
            {
                cached = probeCache.emplace(entry.processId, probeProcessCreateTime(entry.processId)).first;
            }
            const LiveProcessProbe& probe = cached->second;
            entry.processCreateTimeKnown = probe.createTimeKnown;
            entry.processCreateTime100ns = probe.createTime100ns;
            entry.processIdentityOutcome = probe.outcome;

            evidence::OptionalU64 createTime;
            if (probe.createTimeKnown)
            {
                createTime = evidence::OptionalU64::of(probe.createTime100ns);
            }
            QJsonObject identityJson;
            identityJson.insert(QStringLiteral("bootId"), sessionBootId);
            identityJson.insert(QStringLiteral("pid"),
                QString::fromStdString(evidence::FormatU64(entry.processId, evidence::U64Format::Decimal)));
            identityJson.insert(QStringLiteral("createTime100ns"),
                optionalU64Json(createTime, evidence::U64Format::Decimal));
            identityJson.insert(QStringLiteral("createTimeCollection"), collectionOutcomeJson(probe.outcome));
            entry.payload.insert(QStringLiteral("processIdentity"), identityJson);
        }
    }

    bool processDetailRouteAvailable()
    {
        // 输入：无。
        // 处理：只读探测是否存在能接收带身份进程详情导航的顶层窗口。
        //       为什么不用 invokeMethod 试探：那会真的把导航发出去，无法先判断再决定；
        //       F-12 要求“目标缺失时准确解释”，就必须把“目标页不在”和“对象不在页面里”
        //       分成两个可区分的结论。
        // 返回：存在可接收该导航的窗口为 true。
        const QWidgetList topLevelWidgetList = QApplication::topLevelWidgets();
        for (const QWidget* topLevelWidget : topLevelWidgetList)
        {
            if (topLevelWidget == nullptr)
            {
                continue;
            }
            const QMetaObject* metaObject = topLevelWidget->metaObject();
            for (int methodIndex = 0; methodIndex < metaObject->methodCount(); ++methodIndex)
            {
                const QMetaMethod method = metaObject->method(methodIndex);
                // 按方法名 + 形参个数匹配，不拼签名字符串：moc 记录的是头文件里写的
                // 类型名（quint32/quint64），拼签名一旦和它对不上就会误判成“目标页不在”。
                if (method.parameterCount() == 2 &&
                    method.name() == QByteArrayLiteral("openProcessDetailByIdentity"))
                {
                    return true;
                }
            }
        }
        return false;
    }

    QString arkRiskNavigationRejectionText(
        const evidence::NavigationOutcome outcome,
        const evidence::LiveNavigationDecision liveDecision,
        const bool liveDecisionEvaluated,
        const bool noProcessBinding)
    {
        // 输入：F-12 的请求判定、F-09 的现场复核判定、后者是否真的跑过，
        //       以及这行是否压根不指向任何进程。
        // 处理：把两条判据的结论翻译成用户能读懂的一句话。只在 GUI 线程调用，
        //       所以这里可以走 LanguageManager。
        // 返回：拒绝原因文本。
        if (noProcessBinding)
        {
            // 判据同样是 IdentityUnusable，但原因是"没有对象"而不是"创建时间没取到"。
            // 复用后者的文案会让用户去查一个根本不存在的权限问题。
            return ks::i18n::contextText(
                QStringLiteral("monitor.ark_risk.nav.no_process"),
                QStringLiteral("该风险记录没有关联到任何进程实例，无法转到进程详情。"));
        }
        if (!liveDecisionEvaluated)
        {
            switch (outcome)
            {
            case evidence::NavigationOutcome::IdentityUnusable:
                return ks::i18n::contextText(
                    QStringLiteral("monitor.ark_risk.nav.identity_unusable"),
                    QStringLiteral(
                        "该风险记录在采集时没能取到进程创建时间，身份不足以确认是同一个进程实例。"
                        "为避免 PID 被复用后打开无关进程，本次跳转已取消。"));
            case evidence::NavigationOutcome::EvidenceIdMissing:
                return ks::i18n::contextText(
                    QStringLiteral("monitor.ark_risk.nav.evidence_id_missing"),
                    QStringLiteral("该行没有携带证据 id，跳转后无法回到原始证据，本次跳转已取消。"));
            case evidence::NavigationOutcome::EvidenceNotSaved:
                return ks::i18n::contextText(
                    QStringLiteral("monitor.ark_risk.nav.evidence_not_saved"),
                    QStringLiteral(
                        "这条证据已不在当前风险快照中（快照可能已被重新刷新）。请重新刷新风险后再试。"));
            case evidence::NavigationOutcome::TargetPageMissing:
                return ks::i18n::contextText(
                    QStringLiteral("monitor.ark_risk.nav.target_page_missing"),
                    QStringLiteral("找不到可接收进程详情导航的主窗口，目标页可能已关闭。"));
            case evidence::NavigationOutcome::ObjectNotPresent:
                return ks::i18n::contextText(
                    QStringLiteral("monitor.ark_risk.nav.object_not_present"),
                    QStringLiteral("该 PID 对应的进程当前已不存在，无法转到进程详情。"));
            case evidence::NavigationOutcome::Delivered:
                // Delivered 一定会进入现场复核，走不到这里；留着是为了穷尽枚举。
                break;
            }
            // 兜底只说"无法确认"，不替判据编一个更确定的结论。
            return ks::i18n::contextText(
                QStringLiteral("monitor.ark_risk.nav.identity_unverifiable"),
                QStringLiteral(
                    "现场无法确认该 PID 仍是采集时的那个进程实例（例如权限不足读不到创建时间）。"
                    "本次跳转已取消。"));
        }

        switch (liveDecision)
        {
        case evidence::LiveNavigationDecision::RejectObjectExited:
            return ks::i18n::contextText(
                QStringLiteral("monitor.ark_risk.nav.object_exited"),
                QStringLiteral("该风险记录对应的进程实例已退出，本次跳转已取消。"));
        case evidence::LiveNavigationDecision::RejectIdentityMismatch:
            return ks::i18n::contextText(
                QStringLiteral("monitor.ark_risk.nav.identity_mismatch"),
                QStringLiteral(
                    "该 PID 现在属于另一个进程实例（创建时间不一致，PID 已被复用）。"
                    "本次跳转已取消，不会把操作交给新进程。"));
        case evidence::LiveNavigationDecision::RejectIdentityUnverifiable:
            return ks::i18n::contextText(
                QStringLiteral("monitor.ark_risk.nav.identity_unverifiable"),
                QStringLiteral(
                    "现场无法确认该 PID 仍是采集时的那个进程实例（例如权限不足读不到创建时间）。"
                    "本次跳转已取消。"));
        case evidence::LiveNavigationDecision::Allow:
            // Allow 时调用方已经跳走，不会来要拒绝文案；同样只为穷尽枚举。
            break;
        }
        return ks::i18n::contextText(
            QStringLiteral("monitor.ark_risk.nav.identity_unverifiable"),
            QStringLiteral(
                "现场无法确认该 PID 仍是采集时的那个进程实例（例如权限不足读不到创建时间）。"
                "本次跳转已取消。"));
    }

    QJsonObject payloadBase(const QString& source, const QString& category, const QString& title, const QString& detail, const double score)
    {
        // 输入：风险来源、分类、标题、详情和分数。
        // 处理：构造导出和详情区复用的 JSON 根对象。
        // 返回：包含风险基础字段的 payload 对象。
        QJsonObject payload;
        payload.insert(QStringLiteral("source"), source);
        payload.insert(QStringLiteral("category"), category);
        payload.insert(QStringLiteral("title"), title);
        payload.insert(QStringLiteral("detail"), detail);
        payload.insert(QStringLiteral("riskScore"), clampScore(score));
        return payload;
    }

    MonitorDock::ArkRiskCenterEntry makeEntry(
        const QString& source,
        const QString& category,
        const QString& title,
        const QString& detail,
        const double score,
        QJsonObject payload)
    {
        // Input: display fields and structured payload. Processing: fill cache row. Return: risk-center entry.
        MonitorDock::ArkRiskCenterEntry entry;
        entry.sourceName = source;
        entry.category = category;
        entry.title = title;
        entry.detail = detail;
        entry.riskScore = clampScore(score);
        entry.riskScoreText = scoreText(entry.riskScore);
        payload.insert(QStringLiteral("source"), source);
        payload.insert(QStringLiteral("category"), category);
        payload.insert(QStringLiteral("title"), title);
        payload.insert(QStringLiteral("detail"), detail);
        payload.insert(QStringLiteral("riskScore"), entry.riskScore);
        entry.payload = std::move(payload);
        return entry;
    }

    class ScoreItem final : public QTableWidgetItem
    {
    public:
        explicit ScoreItem(const double score)
            : QTableWidgetItem(scoreText(score))
        {
            // Input: risk score. Processing: store numeric UserRole for sorting. Return: constructor has no return.
            setData(Qt::UserRole, clampScore(score));
            setTextAlignment(Qt::AlignVCenter | Qt::AlignRight);
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            // Input: another table item. Processing: prefer numeric UserRole comparison. Return: sort decision.
            bool leftOk = false;
            bool rightOk = false;
            const double left = data(Qt::UserRole).toDouble(&leftOk);
            const double right = other.data(Qt::UserRole).toDouble(&rightOk);
            return (leftOk && rightOk) ? left < right : QTableWidgetItem::operator<(other);
        }
    };

    QTableWidgetItem* textItem(const QString& value)
    {
        // Input: display text. Processing: create read-only table item. Return: item owned by QTableWidget.
        QTableWidgetItem* item = new QTableWidgetItem(value);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QString csvEscape(const QString& value)
    {
        // Input: CSV field. Processing: quote when needed and double embedded quotes. Return: CSV-safe text.
        QString escaped = value;
        escaped.replace(QChar('"'), QStringLiteral("\"\""));
        if (escaped.contains(QChar(',')) || escaped.contains(QChar('"')) || escaped.contains(QChar('\n')) || escaped.contains(QChar('\r')))
        {
            escaped = QStringLiteral("\"%1\"").arg(escaped);
        }
        return escaped;
    }

    bool matchesFilter(const MonitorDock::ArkRiskCenterEntry& entry, const QString& filter)
    {
        // Input: cache row and filter text. Processing: case-insensitive scan across display fields and JSON. Return: match flag.
        if (filter.isEmpty())
        {
            return true;
        }
        const QString payloadText = QString::fromUtf8(QJsonDocument(entry.payload).toJson(QJsonDocument::Compact));
        const QStringList fields{ entry.sourceName, entry.category, entry.title, entry.detail, entry.riskScoreText, payloadText };
        for (const QString& field : fields)
        {
            if (field.contains(filter, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    void addStatusEntry(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, QStringList& statusLines, const QString& source, const QString& category, const bool ok, const bool unsupported, const ksword::ark::IoResult& io)
    {
        // Input: one read-only query status. Processing: append status text and optional low-risk failure row. Return: no value.
        const QString summary = unsupported ? QStringLiteral("%1: 未集成/驱动过旧/能力缺失").arg(source) : QStringLiteral("%1: %2").arg(source, ioSummary(io));
        statusLines << summary;
        if (ok)
        {
            return;
        }
        const double risk = unsupported ? 0.0 : 5.0;
        QJsonObject payload = payloadBase(source, category, unsupported ? QStringLiteral("等待 R0 支持") : QStringLiteral("查询失败"), summary, risk);
        payload.insert(QStringLiteral("unsupported"), unsupported);
        payload.insert(QStringLiteral("win32Error"), static_cast<int>(io.win32Error));
        payload.insert(QStringLiteral("ntStatus"), hex32(static_cast<std::uint32_t>(io.ntStatus)));
        entries.push_back(makeEntry(source, category, unsupported ? QStringLiteral("未集成/驱动过旧") : QStringLiteral("查询失败"), summary, risk, payload));
    }

    double memoryScore(const ksword::ark::KernelMemoryEvidenceEntry& row)
    {
        // Input: memory evidence row. Processing: score RWX/non-module/pool/text risks and confidence. Return: risk score.
        double score = 0.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX) score += 35.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE) score += 35.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE) score += 25.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL) score += 25.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE) score += 12.0;
        if (row.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING) score += 12.0;
        score += std::min<double>(15.0, static_cast<double>(row.confidence) / 10.0);
        return clampScore(score);
    }

    QString memoryRiskText(const std::uint32_t flags)
    {
        // Input: memory evidence risk bits. Processing: map known bits. Return: compact text.
        QStringList parts;
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX) parts << QStringLiteral("RWX");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE) parts << QStringLiteral("非模块执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE) parts << QStringLiteral("模块非text执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL) parts << QStringLiteral("执行池");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE) parts << QStringLiteral("大页执行");
        if (flags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING) parts << QStringLiteral("Owner缺失");
        return parts.isEmpty() ? QStringLiteral("正常") : parts.join(QStringLiteral(" | "));
    }

    double crossViewScore(const std::uint32_t flags, const std::uint32_t confidence)
    {
        // Input: cross-view anomaly bits and confidence. Processing: score DKOM-style mismatches. Return: risk score.
        double score = 0.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST) score += 40.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE) score += 35.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN) score += 35.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY) score += 30.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) score += 30.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) score += 30.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST) score += 28.0;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY) score += 20.0;
        score += std::min<double>(15.0, static_cast<double>(confidence) / 10.0);
        return clampScore(score);
    }

    QString crossViewText(const std::uint32_t flags)
    {
        // Input: cross-view anomaly bits. Processing: map known DKOM indicators. Return: compact text.
        QStringList parts;
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY) parts << QStringLiteral("CID-only");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY) parts << QStringLiteral("Active-only");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST) parts << QStringLiteral("缺ActiveList");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE) parts << QStringLiteral("缺CID");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN) parts << QStringLiteral("孤儿线程");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST) parts << QStringLiteral("线程进程缺失");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) parts << QStringLiteral("入口出模块");
        if (flags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) parts << QStringLiteral("悬空对象");
        return parts.isEmpty() ? QStringLiteral("正常") : parts.join(QStringLiteral(" | "));
    }

    double driverScore(const std::uint32_t flags, const std::uint32_t confidence)
    {
        // Input: driver integrity risk bits and confidence. Processing: score CPU/IDT/owner/dispatch risks. Return: risk score.
        double score = 0.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER) score += 40.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH) score += 35.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE) score += 35.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED) score += 35.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID) score += 25.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED) score += 25.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED) score += 22.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH) score += 18.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH) score += 18.0;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED) score += 18.0;
        score += std::min<double>(15.0, static_cast<double>(confidence) / 10.0);
        return clampScore(score);
    }

    QString driverRiskText(const std::uint32_t flags)
    {
        // Input: driver integrity risk bits. Processing: map high-value known bits. Return: compact text.
        QStringList parts;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH) parts << QStringLiteral("Owner不匹配");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE) parts << QStringLiteral("外跳");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER) parts << QStringLiteral("IDT外部Owner");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED) parts << QStringLiteral("WP关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED) parts << QStringLiteral("NXE关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED) parts << QStringLiteral("SMEP关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED) parts << QStringLiteral("SMAP关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID) parts << QStringLiteral("描述符异常");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH) parts << QStringLiteral("Section不匹配");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH) parts << QStringLiteral("跨驱动挂接");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED) parts << QStringLiteral("模块未解析");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE) parts << QStringLiteral("DynData缺失");
        return parts.isEmpty() ? hex32(flags) : parts.join(QStringLiteral(" | "));
    }

    QString hookStatusText(const std::uint32_t status)
    {
        // Input: kernel hook status. Processing: map known status codes. Return: display text.
        switch (status)
        {
        case KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN: return QStringLiteral("Clean");
        case KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS: return QStringLiteral("Suspicious");
        case KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH: return QStringLiteral("InternalBranch");
        case KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED: return QStringLiteral("ReadFailed");
        case KSWORD_ARK_KERNEL_HOOK_STATUS_PARSE_FAILED: return QStringLiteral("ParseFailed");
        case KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED: return QStringLiteral("ForceRequired");
        default: return QStringLiteral("Status(%1)").arg(status);
        }
    }

    double hookScore(const std::uint32_t status, const bool hasPatchOrDiff)
    {
        // Input: hook status and patch/diff presence. Processing: score suspicious hook evidence. Return: risk score.
        double score = hasPatchOrDiff ? 25.0 : 0.0;
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS) score += 60.0;
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED) score += 55.0;
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED) score += 15.0;
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_PARSE_FAILED) score += 15.0;
        if (status == KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH) score += 8.0;
        return clampScore(score);
    }

    QString callbackClassText(const std::uint32_t callbackClass)
    {
        // Input: callback class id. Processing: map shared protocol constants. Return: display text.
        switch (callbackClass)
        {
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY: return QStringLiteral("Registry");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS: return QStringLiteral("Process");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD: return QStringLiteral("Thread");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE: return QStringLiteral("Image");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT: return QStringLiteral("Object");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER: return QStringLiteral("Minifilter");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT: return QStringLiteral("WFP");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER: return QStringLiteral("ETW");
        default: return QStringLiteral("Callback(%1)").arg(callbackClass);
        }
    }

    double callbackScore(const ksword::ark::CallbackEnumEntry& row)
    {
        // Input: callback enumeration row. Processing: score private/unresolved/untrusted rows. Return: risk score.
        double score = 0.0;
        if (row.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED) score += 20.0;
        if (row.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED ||
            row.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN ||
            row.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY ||
            row.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST ||
            row.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST)
        {
            score += 25.0;
        }
        if (row.moduleBase == 0U && row.callbackAddress != 0U) score += 30.0;
        if ((row.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE) == 0U) score += 15.0;
        if ((row.trustFlags & (KSWORD_ARK_CALLBACK_TRUST_REVALIDATED | KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API | KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE)) == 0U) score += 12.0;
        return clampScore(score);
    }

    QString mutationOperationText(const std::uint32_t operation)
    {
        // Input: mutation operation id. Processing: map known audit operation. Return: display text.
        switch (operation)
        {
        case KSWORD_ARK_MUTATION_OPERATION_PREPARE: return QStringLiteral("Prepare");
        case KSWORD_ARK_MUTATION_OPERATION_COMMIT: return QStringLiteral("Commit");
        case KSWORD_ARK_MUTATION_OPERATION_ROLLBACK: return QStringLiteral("Rollback");
        case KSWORD_ARK_MUTATION_OPERATION_QUERY_AUDIT: return QStringLiteral("QueryAudit");
        default: return QStringLiteral("Operation(%1)").arg(operation);
        }
    }

    QString mutationStatusText(const std::uint32_t status)
    {
        // Input: mutation status id. Processing: map common audit status. Return: display text.
        switch (status)
        {
        case KSWORD_ARK_MUTATION_STATUS_PREPARED: return QStringLiteral("Prepared");
        case KSWORD_ARK_MUTATION_STATUS_DRY_RUN: return QStringLiteral("DryRun");
        case KSWORD_ARK_MUTATION_STATUS_COMMITTED: return QStringLiteral("Committed");
        case KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK: return QStringLiteral("RolledBack");
        case KSWORD_ARK_MUTATION_STATUS_REJECTED_SAFETY_POLICY: return QStringLiteral("RejectedSafetyPolicy");
        case KSWORD_ARK_MUTATION_STATUS_REJECTED_BEFORE_MISMATCH: return QStringLiteral("RejectedBeforeMismatch");
        case KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED: return QStringLiteral("RejectedTargetChanged");
        case KSWORD_ARK_MUTATION_STATUS_WRITE_FAILED: return QStringLiteral("WriteFailed");
        case KSWORD_ARK_MUTATION_STATUS_READ_FAILED: return QStringLiteral("ReadFailed");
        default: return QStringLiteral("Status(%1)").arg(status);
        }
    }

    double mutationScore(const ksword::ark::MutationAuditEntry& row)
    {
        // Input: mutation audit row. Processing: score commit/write-fail/rejected changes; dry-run lowers score. Return: risk score.
        double score = 0.0;
        if (row.operation == KSWORD_ARK_MUTATION_OPERATION_COMMIT) score += 45.0;
        if (row.status == KSWORD_ARK_MUTATION_STATUS_COMMITTED) score += 30.0;
        if (row.status == KSWORD_ARK_MUTATION_STATUS_WRITE_FAILED) score += 25.0;
        if (row.status == KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED) score += 18.0;
        if (row.status == KSWORD_ARK_MUTATION_STATUS_REJECTED_BEFORE_MISMATCH) score += 16.0;
        if (row.operation == KSWORD_ARK_MUTATION_OPERATION_ROLLBACK) score += 12.0;
        if (row.riskFlags != 0U) score += 20.0;
        if ((row.flags & KSWORD_ARK_MUTATION_FLAG_DRY_RUN) != 0U) score -= 20.0;
        return clampScore(score);
    }

    void appendMemory(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::KernelMemoryEvidenceResult& result)
    {
        // Input: memory evidence result. Processing: append only non-zero risk rows. Return: no value.
        for (const auto& row : result.entries)
        {
            if (row.riskFlags == 0U) continue;
            const double risk = memoryScore(row);
            const QString title = QStringLiteral("%1 %2").arg(memoryRiskText(row.riskFlags), hex64(row.virtualAddress));
            const QString detail = QStringLiteral("owner=%1 size=%2 confidence=%3 %4")
                .arg(wideText(row.ownerName), hex64(row.regionSize)).arg(row.confidence).arg(wideText(row.detail));
            QJsonObject payload = payloadBase(QStringLiteral("Memory Evidence"), QStringLiteral("Memory"), title, detail, risk);
            payload.insert(QStringLiteral("virtualAddress"), hex64(row.virtualAddress));
            payload.insert(QStringLiteral("regionSize"), hex64(row.regionSize));
            payload.insert(QStringLiteral("riskFlags"), hex32(row.riskFlags));
            payload.insert(QStringLiteral("permissionFlags"), hex32(row.permissionFlags));
            payload.insert(QStringLiteral("ownerName"), wideText(row.ownerName));
            payload.insert(QStringLiteral("contentHash"), hex64(row.contentHash));
            entries.push_back(makeEntry(QStringLiteral("Memory Evidence"), QStringLiteral("Memory"), title, detail, risk, payload));
        }
    }

    void appendProcessCrossView(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::ProcessCrossViewResult& result)
    {
        // Input: process cross-view result. Processing: append anomalous process rows. Return: no value.
        for (const auto& row : result.entries)
        {
            if (row.anomalyFlags == 0U) continue;
            const double risk = crossViewScore(row.anomalyFlags, row.confidence);
            const QString title = QStringLiteral("PID %1 %2").arg(row.processId).arg(crossViewText(row.anomalyFlags));
            const QString detail = QStringLiteral("image=%1 object=%2 source=%3 %4")
                .arg(narrowText(row.imageName), hex64(row.objectAddress), hex32(row.sourceMask), narrowText(row.detail));
            QJsonObject payload = payloadBase(QStringLiteral("Process Cross-View"), QStringLiteral("Process"), title, detail, risk);
            payload.insert(QStringLiteral("processId"), static_cast<int>(row.processId));
            payload.insert(QStringLiteral("imageName"), narrowText(row.imageName));
            payload.insert(QStringLiteral("objectAddress"), hex64(row.objectAddress));
            payload.insert(QStringLiteral("anomalyFlags"), hex32(row.anomalyFlags));
            payload.insert(QStringLiteral("sourceMask"), hex32(row.sourceMask));
            entries.push_back(makeEntry(QStringLiteral("Process Cross-View"), QStringLiteral("Process"), title, detail, risk, payload));
        }
    }

    void appendThreadCrossView(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::ThreadCrossViewResult& result)
    {
        // Input: thread cross-view result. Processing: append anomalous thread rows. Return: no value.
        for (const auto& row : result.entries)
        {
            if (row.anomalyFlags == 0U) continue;
            const double risk = crossViewScore(row.anomalyFlags, row.confidence);
            const QString title = QStringLiteral("TID %1/PID %2 %3").arg(row.threadId).arg(row.processId).arg(crossViewText(row.anomalyFlags));
            const QString detail = QStringLiteral("thread=%1 process=%2 start=%3 %4")
                .arg(hex64(row.objectAddress), hex64(row.processObjectAddress), hex64(row.startAddress), narrowText(row.detail));
            QJsonObject payload = payloadBase(QStringLiteral("Thread Cross-View"), QStringLiteral("Thread"), title, detail, risk);
            payload.insert(QStringLiteral("threadId"), static_cast<int>(row.threadId));
            payload.insert(QStringLiteral("processId"), static_cast<int>(row.processId));
            payload.insert(QStringLiteral("objectAddress"), hex64(row.objectAddress));
            payload.insert(QStringLiteral("anomalyFlags"), hex32(row.anomalyFlags));
            payload.insert(QStringLiteral("sourceMask"), hex32(row.sourceMask));
            entries.push_back(makeEntry(QStringLiteral("Thread Cross-View"), QStringLiteral("Thread"), title, detail, risk, payload));
        }
    }

    void appendDriverIntegrity(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const QString& source, const ksword::ark::DriverIntegrityResult& result)
    {
        // Input: driver or CPU integrity result. Processing: append rows with risk flags. Return: no value.
        for (const auto& row : result.entries)
        {
            if (row.riskFlags == 0U) continue;
            const double risk = driverScore(row.riskFlags, row.confidence);
            const QString title = QStringLiteral("%1 %2").arg(source, driverRiskText(row.riskFlags));
            const QString detail = QStringLiteral("owner=%1 object=%2 target=%3 cpu=G%4/%5/V%6 %7")
                .arg(wideText(row.ownerModule), hex64(row.objectAddress), hex64(row.targetAddress))
                .arg(row.processorGroup).arg(row.processorNumber).arg(row.vector).arg(wideText(row.detail));
            QJsonObject payload = payloadBase(source, QStringLiteral("Driver"), title, detail, risk);
            payload.insert(QStringLiteral("riskFlags"), hex32(row.riskFlags));
            payload.insert(QStringLiteral("objectAddress"), hex64(row.objectAddress));
            payload.insert(QStringLiteral("targetAddress"), hex64(row.targetAddress));
            payload.insert(QStringLiteral("ownerModule"), wideText(row.ownerModule));
            payload.insert(QStringLiteral("processorGroup"), static_cast<int>(row.processorGroup));
            payload.insert(QStringLiteral("processorNumber"), static_cast<int>(row.processorNumber));
            payload.insert(QStringLiteral("vector"), static_cast<int>(row.vector));
            entries.push_back(makeEntry(source, QStringLiteral("Driver"), title, detail, risk, payload));
        }
    }

    void appendInlineHooks(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::KernelInlineHookScanResult& result)
    {
        // Input: inline hook scan result. Processing: append suspicious or patched rows. Return: no value.
        for (const auto& row : result.entries)
        {
            const bool hasPatch = row.hookType != KSWORD_ARK_INLINE_HOOK_TYPE_NONE;
            const double risk = hookScore(row.status, hasPatch);
            if (risk <= 0.0) continue;
            const QString functionName = narrowText(row.functionName).trimmed();
            const QString title = QStringLiteral("%1 %2").arg(hookStatusText(row.status), functionName.isEmpty() ? hex64(row.functionAddress) : functionName);
            const QString detail = QStringLiteral("module=%1 targetModule=%2 function=%3 target=%4")
                .arg(wideText(row.moduleName), wideText(row.targetModuleName), hex64(row.functionAddress), hex64(row.targetAddress));
            QJsonObject payload = payloadBase(QStringLiteral("Inline Hook"), QStringLiteral("Hook"), title, detail, risk);
            payload.insert(QStringLiteral("status"), hookStatusText(row.status));
            payload.insert(QStringLiteral("hookType"), static_cast<int>(row.hookType));
            payload.insert(QStringLiteral("functionAddress"), hex64(row.functionAddress));
            payload.insert(QStringLiteral("targetAddress"), hex64(row.targetAddress));
            payload.insert(QStringLiteral("moduleName"), wideText(row.moduleName));
            entries.push_back(makeEntry(QStringLiteral("Inline Hook"), QStringLiteral("Hook"), title, detail, risk, payload));
        }
    }

    void appendIatEatHooks(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::KernelIatEatHookScanResult& result)
    {
        // Input: IAT/EAT hook scan result. Processing: append suspicious or pointer-diff rows. Return: no value.
        for (const auto& row : result.entries)
        {
            const bool differs = row.currentTarget != 0U && row.expectedTarget != 0U && row.currentTarget != row.expectedTarget;
            const double risk = hookScore(row.status, differs);
            if (risk <= 0.0) continue;
            const QString hookClass = row.hookClass == KSWORD_ARK_IAT_EAT_HOOK_CLASS_EAT ? QStringLiteral("EAT") : QStringLiteral("IAT");
            const QString title = QStringLiteral("%1 %2 %3").arg(hookClass, hookStatusText(row.status), narrowText(row.functionName));
            const QString detail = QStringLiteral("module=%1 import=%2 current=%3 expected=%4")
                .arg(wideText(row.moduleName), wideText(row.importModuleName), hex64(row.currentTarget), hex64(row.expectedTarget));
            QJsonObject payload = payloadBase(QStringLiteral("IAT/EAT Hook"), QStringLiteral("Hook"), title, detail, risk);
            payload.insert(QStringLiteral("hookClass"), hookClass);
            payload.insert(QStringLiteral("status"), hookStatusText(row.status));
            payload.insert(QStringLiteral("thunkAddress"), hex64(row.thunkAddress));
            payload.insert(QStringLiteral("currentTarget"), hex64(row.currentTarget));
            payload.insert(QStringLiteral("expectedTarget"), hex64(row.expectedTarget));
            payload.insert(QStringLiteral("moduleName"), wideText(row.moduleName));
            entries.push_back(makeEntry(QStringLiteral("IAT/EAT Hook"), QStringLiteral("Hook"), title, detail, risk, payload));
        }
    }

    void appendCallbacks(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::CallbackEnumResult& result)
    {
        // Input: callback enumeration result. Processing: append private/unresolved/untrusted callback rows. Return: no value.
        for (const auto& row : result.entries)
        {
            const double risk = callbackScore(row);
            if (risk < 20.0) continue;
            const QString callbackClass = callbackClassText(row.callbackClass);
            const QString title = QStringLiteral("%1 %2").arg(callbackClass, hex64(row.callbackAddress));
            const QString detail = QStringLiteral("module=%1 name=%2 altitude=%3 source=%4 trust=%5")
                .arg(wideText(row.modulePath), wideText(row.name), wideText(row.altitude)).arg(row.source).arg(hex32(row.trustFlags));
            QJsonObject payload = payloadBase(QStringLiteral("Callback"), QStringLiteral("Callback"), title, detail, risk);
            payload.insert(QStringLiteral("callbackClass"), callbackClass);
            payload.insert(QStringLiteral("source"), static_cast<int>(row.source));
            payload.insert(QStringLiteral("fieldFlags"), hex32(row.fieldFlags));
            payload.insert(QStringLiteral("trustFlags"), hex32(row.trustFlags));
            payload.insert(QStringLiteral("callbackAddress"), hex64(row.callbackAddress));
            payload.insert(QStringLiteral("modulePath"), wideText(row.modulePath));
            payload.insert(QStringLiteral("name"), wideText(row.name));
            payload.insert(QStringLiteral("altitude"), wideText(row.altitude));
            entries.push_back(makeEntry(QStringLiteral("Callback"), QStringLiteral("Callback"), title, detail, risk, payload));
        }
    }

    void appendMutationAudit(std::vector<MonitorDock::ArkRiskCenterEntry>& entries, const ksword::ark::MutationAuditResult& result)
    {
        // Input: read-only mutation audit result. Processing: append audit rows without exposing write controls. Return: no value.
        for (const auto& row : result.entries)
        {
            const double risk = mutationScore(row);
            if (risk <= 0.0) continue;
            const QString operation = mutationOperationText(row.operation);
            const QString status = mutationStatusText(row.status);
            const QString title = QStringLiteral("TX %1 %2 %3").arg(static_cast<qulonglong>(row.transactionId)).arg(operation, status);
            const QString detail = QStringLiteral("target=%1 bytes=%2 pid=%3 flags=%4 risk=%5")
                .arg(hex64(row.targetAddress)).arg(row.bytes).arg(row.processId).arg(hex32(row.flags), hex32(row.riskFlags));
            QJsonObject payload = payloadBase(QStringLiteral("Mutation Audit"), QStringLiteral("Mutation"), title, detail, risk);
            payload.insert(QStringLiteral("operation"), operation);
            payload.insert(QStringLiteral("status"), status);
            payload.insert(QStringLiteral("transactionId"), QString::number(static_cast<qulonglong>(row.transactionId)));
            payload.insert(QStringLiteral("sequence"), QString::number(static_cast<qulonglong>(row.sequence)));
            payload.insert(QStringLiteral("targetAddress"), hex64(row.targetAddress));
            payload.insert(QStringLiteral("bytes"), static_cast<int>(row.bytes));
            payload.insert(QStringLiteral("processId"), static_cast<int>(row.processId));
            payload.insert(QStringLiteral("flags"), hex32(row.flags));
            payload.insert(QStringLiteral("riskFlags"), hex32(row.riskFlags));
            entries.push_back(makeEntry(QStringLiteral("Mutation Audit"), QStringLiteral("Mutation"), title, detail, risk, payload));
        }
    }
}

void MonitorDock::initializeArkRiskCenterTab()
{
    // 输入：无，由 initializeUi 调用。
    // 处理：创建只读 ARK 风险中心页；所有驱动访问都在 ArkDriverClient 中完成。
    // 返回：无返回值，控件由 Qt 父子树释放。
    m_arkRiskCenterPage = new QWidget(m_sideTabWidget);
    QVBoxLayout* pageLayout = new QVBoxLayout(m_arkRiskCenterPage);
    pageLayout->setContentsMargins(6, 6, 6, 6);
    pageLayout->setSpacing(6);

    QHBoxLayout* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(8);

    m_arkRiskRefreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新风险"), m_arkRiskCenterPage);
    m_arkRiskRefreshButton->setToolTip(QStringLiteral("只读聚合 Memory / Process / Driver / Callback / Hook / Mutation 发现"));
    m_arkRiskHighOnlyCheck = new QCheckBox(QStringLiteral("仅高风险"), m_arkRiskCenterPage);
    m_arkRiskHighOnlyCheck->setChecked(true);
    m_arkRiskHighOnlyCheck->setToolTip(QStringLiteral("仅显示 riskScore >= 50 的记录"));
    m_arkRiskFilterEdit = new QLineEdit(m_arkRiskCenterPage);
    m_arkRiskFilterEdit->setClearButtonEnabled(true);
    m_arkRiskFilterEdit->setPlaceholderText(QStringLiteral("过滤来源/分类/标题/详情/JSON"));
    m_arkRiskExportJsonButton = new QPushButton(QStringLiteral("导出 JSON"), m_arkRiskCenterPage);
    m_arkRiskExportCsvButton = new QPushButton(QStringLiteral("导出 CSV"), m_arkRiskCenterPage);
    m_arkRiskStatusLabel = new QLabel(QStringLiteral("状态：等待刷新"), m_arkRiskCenterPage);
    m_arkRiskStatusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_arkRiskStatusLabel->setStyleSheet(QStringLiteral("color:%1; font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    toolbarLayout->addWidget(m_arkRiskRefreshButton);
    toolbarLayout->addWidget(m_arkRiskHighOnlyCheck);
    toolbarLayout->addWidget(m_arkRiskFilterEdit, 1);
    toolbarLayout->addWidget(m_arkRiskExportJsonButton);
    toolbarLayout->addWidget(m_arkRiskExportCsvButton);
    toolbarLayout->addWidget(m_arkRiskStatusLabel);
    pageLayout->addLayout(toolbarLayout);

    QSplitter* splitter = new QSplitter(Qt::Vertical, m_arkRiskCenterPage);
    pageLayout->addWidget(splitter, 1);

    m_arkRiskTable = new ks::ui::VisibleTableWidget(splitter);
    m_arkRiskTable->setColumnCount(riskColumnIndex(RiskColumn::Count));
    m_arkRiskTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("riskScore"),
        QStringLiteral("来源"),
        QStringLiteral("分类"),
        QStringLiteral("标题"),
        QStringLiteral("详情")
        });
    m_arkRiskTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_arkRiskTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_arkRiskTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_arkRiskTable->setAlternatingRowColors(true);
    m_arkRiskTable->setSortingEnabled(true);
    m_arkRiskTable->verticalHeader()->setVisible(false);
    m_arkRiskTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_arkRiskTable->horizontalHeader()->setSectionResizeMode(riskColumnIndex(RiskColumn::Detail), QHeaderView::Stretch);
    installArkRiskTableCopyMenu(this, m_arkRiskTable);
    splitter->addWidget(m_arkRiskTable);

    m_arkRiskDetailEdit = new CodeEditorWidget(splitter);
    m_arkRiskDetailEdit->setReadOnly(true);
    m_arkRiskDetailEdit->setText(QStringLiteral("ARK 风险中心为只读聚合页。\n不提供任意写、修复、提交 mutation 或驱动卸载按钮；Mutation 仅展示 dry-run/audit/rollback 状态。"));
    splitter->addWidget(m_arkRiskDetailEdit);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(
        m_arkRiskTable, m_arkRiskDetailEdit, m_arkRiskCenterPage);

    connect(m_arkRiskRefreshButton, &QPushButton::clicked, this, [this]() { refreshArkRiskCenterAsync(); });
    connect(m_arkRiskFilterEdit, &QLineEdit::textChanged, this, [this]() { rebuildArkRiskCenterTable(); });
    connect(m_arkRiskHighOnlyCheck, &QCheckBox::toggled, this, [this]() { rebuildArkRiskCenterTable(); });
    connect(m_arkRiskTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) { showArkRiskCenterDetailForCurrentRow(); });
    connect(m_arkRiskExportJsonButton, &QPushButton::clicked, this, [this]() { exportArkRiskCenterAsJson(); });
    connect(m_arkRiskExportCsvButton, &QPushButton::clicked, this, [this]() { exportArkRiskCenterAsCsv(); });

    m_sideTabWidget->addTab(m_arkRiskCenterPage, QIcon(QStringLiteral(":/Icon/process_critical.svg")), QStringLiteral("ARK 风险中心"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget,
        m_arkRiskCenterPage,
        QStringLiteral("monitor.tab.ark_risk_center"),
        QStringLiteral("ARK 风险中心"));
}

void MonitorDock::refreshArkRiskCenterAsync()
{
    // 输入：刷新按钮或首次进入页面触发。
    // 处理：后台通过 ArkDriverClient 只读查询多路证据，主线程更新缓存和表格。
    // 返回：无返回值。
    if (m_arkRiskRefreshInProgress)
    {
        return;
    }

    m_arkRiskRefreshInProgress = true;
    const std::uint64_t ticket = ++m_arkRiskRefreshTicket;
    if (m_arkRiskRefreshButton != nullptr)
    {
        m_arkRiskRefreshButton->setEnabled(false);
    }
    if (m_arkRiskStatusLabel != nullptr)
    {
        m_arkRiskStatusLabel->setText(QStringLiteral("状态：聚合查询中..."));
        m_arkRiskStatusLabel->setStyleSheet(QStringLiteral("color:%1; font-weight:700;").arg(KswordTheme::PrimaryBlueHex));
    }

    QPointer<MonitorDock> guardThis(this);
    // sessionBootId 在 GUI 线程先取一次：进程内恒定，工作线程直接用值，
    // 免得静态初始化和采集在不同线程上竞争。
    const QString sessionBootId = arkRiskSessionBootId();
    QRunnable* task = QRunnable::create([guardThis, ticket, sessionBootId]() {
        std::vector<MonitorDock::ArkRiskCenterEntry> entries;
        QStringList statusLines;
        const ksword::ark::DriverClient client;

        const unsigned long memoryFlags =
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
        const auto memory = client.queryKernelMemoryEvidence(memoryFlags);
        addStatusEntry(entries, statusLines, QStringLiteral("Memory Evidence"), QStringLiteral("Memory"), memory.io.ok, memory.unsupported, memory.io);
        if (memory.io.ok) appendMemory(entries, memory);

        const auto process = client.queryProcessCrossView();
        addStatusEntry(entries, statusLines, QStringLiteral("Process Cross-View"), QStringLiteral("Process"), process.io.ok, process.unsupported, process.io);
        if (process.io.ok) appendProcessCrossView(entries, process);

        const auto thread = client.queryThreadCrossView();
        addStatusEntry(entries, statusLines, QStringLiteral("Thread Cross-View"), QStringLiteral("Thread"), thread.io.ok, thread.unsupported, thread.io);
        if (thread.io.ok) appendThreadCrossView(entries, thread);

        const auto driver = client.queryDriverIntegrity();
        addStatusEntry(entries, statusLines, QStringLiteral("Driver Integrity"), QStringLiteral("Driver"), driver.io.ok, driver.unsupported, driver.io);
        if (driver.io.ok) appendDriverIntegrity(entries, QStringLiteral("Driver Integrity"), driver);

        const auto cpu = client.queryKernelCpuIntegrity();
        addStatusEntry(entries, statusLines, QStringLiteral("CPU Integrity"), QStringLiteral("Driver"), cpu.io.ok, cpu.unsupported, cpu.io);
        if (cpu.io.ok) appendDriverIntegrity(entries, QStringLiteral("CPU Integrity"), cpu);

        const auto inlineHooks = client.scanInlineHooks();
        addStatusEntry(entries, statusLines, QStringLiteral("Inline Hook"), QStringLiteral("Hook"), inlineHooks.io.ok, false, inlineHooks.io);
        if (inlineHooks.io.ok) appendInlineHooks(entries, inlineHooks);

        const auto iatEatHooks = client.enumerateIatEatHooks();
        addStatusEntry(entries, statusLines, QStringLiteral("IAT/EAT Hook"), QStringLiteral("Hook"), iatEatHooks.io.ok, false, iatEatHooks.io);
        if (iatEatHooks.io.ok) appendIatEatHooks(entries, iatEatHooks);

        const auto callbacks = client.enumerateCallbacks();
        addStatusEntry(entries, statusLines, QStringLiteral("Callback"), QStringLiteral("Callback"), callbacks.io.ok, false, callbacks.io);
        if (callbacks.io.ok) appendCallbacks(entries, callbacks);

        const auto mutation = client.queryMutationAudit();
        addStatusEntry(entries, statusLines, QStringLiteral("Mutation Audit"), QStringLiteral("Mutation"), mutation.io.ok, mutation.unsupported, mutation.io);
        if (mutation.io.ok) appendMutationAudit(entries, mutation);

        std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
            return left.riskScore > right.riskScore;
        });

        // F-09/F-12：排序定稿后再发证据 id 并固定进程身份，让 id 与最终顺序一一对应。
        attachArkRiskNavigationIdentity(entries, sessionBootId, ticket);

        if (guardThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            guardThis.data(),
            [guardThis, ticket, entries = std::move(entries), statusLines = std::move(statusLines)]() mutable {
                if (guardThis == nullptr || guardThis->m_arkRiskRefreshTicket != ticket)
                {
                    return;
                }

                auto deferredEntries =
                    std::make_shared<std::vector<MonitorDock::ArkRiskCenterEntry>>(std::move(entries));
                auto deferredStatusLines = std::make_shared<QStringList>(std::move(statusLines));
                auto commit = [guardThis, ticket, deferredEntries, deferredStatusLines]() mutable
                {
                    if (guardThis == nullptr || guardThis->m_arkRiskRefreshTicket != ticket)
                    {
                        return;
                    }

                    guardThis->m_arkRiskRefreshInProgress = false;
                    if (guardThis->m_arkRiskRefreshButton != nullptr)
                    {
                        guardThis->m_arkRiskRefreshButton->setEnabled(true);
                    }
                    guardThis->m_arkRiskCenterEntries = std::move(*deferredEntries);
                    guardThis->rebuildArkRiskCenterTable();
                    guardThis->showArkRiskCenterDetailForCurrentRow();
                    if (guardThis->m_arkRiskStatusLabel != nullptr)
                    {
                        guardThis->m_arkRiskStatusLabel->setText(
                            QStringLiteral("状态：%1 项；%2")
                            .arg(static_cast<qulonglong>(guardThis->m_arkRiskCenterEntries.size()))
                            .arg(deferredStatusLines->join(QStringLiteral("；"))));
                        guardThis->m_arkRiskStatusLabel->setStyleSheet(
                            QStringLiteral("color:%1; font-weight:700;")
                                .arg(KswordTheme::TextPrimaryHex()));
                    }
                };
                if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                        guardThis.data(),
                        QStringLiteral("monitor-ark-risk-center-snapshot-apply"),
                        {guardThis->m_arkRiskTable},
                        commit))
                {
                    return;
                }
                commit();
            },
            Qt::QueuedConnection);
    });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void MonitorDock::rebuildArkRiskCenterTable()
{
    // 输入：无，读取风险中心缓存和过滤控件。
    // 处理：按 high-only 与关键字投影表格；不访问驱动。
    // 返回：无返回值。
    if (m_arkRiskTable == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_arkRiskDetailEdit);
    const QString filter = m_arkRiskFilterEdit != nullptr ? m_arkRiskFilterEdit->text().trimmed() : QString();
    const bool highOnly = m_arkRiskHighOnlyCheck != nullptr && m_arkRiskHighOnlyCheck->isChecked();

    std::vector<std::size_t> visibleIndexes;
    visibleIndexes.reserve(m_arkRiskCenterEntries.size());
    for (std::size_t index = 0; index < m_arkRiskCenterEntries.size(); ++index)
    {
        const auto& entry = m_arkRiskCenterEntries[index];
        if (highOnly && entry.riskScore < 50.0)
        {
            continue;
        }
        if (!matchesFilter(entry, filter))
        {
            continue;
        }
        visibleIndexes.push_back(index);
    }

    const QSignalBlocker blocker(m_arkRiskTable);
    m_arkRiskTable->setSortingEnabled(false);
    m_arkRiskTable->setRowCount(static_cast<int>(visibleIndexes.size()));
    for (int row = 0; row < static_cast<int>(visibleIndexes.size()); ++row)
    {
        const std::size_t cacheIndex = visibleIndexes[static_cast<std::size_t>(row)];
        const auto& entry = m_arkRiskCenterEntries[cacheIndex];
        QTableWidgetItem* scoreItem = new ScoreItem(entry.riskScore);
        scoreItem->setData(kRiskEntryIndexRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(cacheIndex)));
        // PID 与证据 id 都取自缓存行本身，而不是再解析一遍 payload：
        // 采集期已经把身份定死了，这里只搬运（F-09）。
        scoreItem->setData(kRiskProcessIdRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(entry.processId)));
        scoreItem->setData(kRiskEvidenceIdRole, entry.evidenceId);
        m_arkRiskTable->setItem(row, riskColumnIndex(RiskColumn::Score), scoreItem);
        m_arkRiskTable->setItem(row, riskColumnIndex(RiskColumn::Source), textItem(entry.sourceName));
        m_arkRiskTable->setItem(row, riskColumnIndex(RiskColumn::Category), textItem(entry.category));
        m_arkRiskTable->setItem(row, riskColumnIndex(RiskColumn::Title), textItem(entry.title));
        m_arkRiskTable->setItem(row, riskColumnIndex(RiskColumn::Detail), textItem(entry.detail));
    }
    if (m_arkRiskTable->rowCount() > 0 && m_arkRiskTable->currentRow() < 0)
    {
        m_arkRiskTable->setCurrentCell(0, riskColumnIndex(RiskColumn::Score));
    }
    m_arkRiskTable->setSortingEnabled(true);
    ks::ui::RequestTableColumnAutoFit(m_arkRiskTable);
}

void MonitorDock::showArkRiskCenterDetailForCurrentRow() const
{
    // 输入：无，读取当前表格选择。
    // 处理：通过缓存索引展开摘要和 JSON payload。
    // 返回：无返回值。
    if (m_arkRiskDetailEdit == nullptr || m_arkRiskTable == nullptr)
    {
        return;
    }
    const int row = m_arkRiskTable->currentRow();
    if (row < 0)
    {
        m_arkRiskDetailEdit->setText(QStringLiteral("请选择一条风险记录。"));
        return;
    }
    const QTableWidgetItem* scoreItem = m_arkRiskTable->item(row, riskColumnIndex(RiskColumn::Score));
    bool ok = false;
    const qulonglong cacheIndex = scoreItem != nullptr ? scoreItem->data(kRiskEntryIndexRole).toULongLong(&ok) : 0ULL;
    if (!ok || cacheIndex >= static_cast<qulonglong>(m_arkRiskCenterEntries.size()))
    {
        m_arkRiskDetailEdit->setText(QStringLiteral("当前行缓存索引无效。"));
        return;
    }
    const auto& entry = m_arkRiskCenterEntries[static_cast<std::size_t>(cacheIndex)];
    QString detail;
    detail += QStringLiteral("ARK 风险详情\n");
    detail += QStringLiteral("riskScore: %1\nsource: %2\ncategory: %3\ntitle: %4\ndetail: %5\n\n")
        .arg(entry.riskScoreText, entry.sourceName, entry.category, entry.title, entry.detail);
    detail += QString::fromUtf8(QJsonDocument(entry.payload).toJson(QJsonDocument::Indented));
    m_arkRiskDetailEdit->setText(detail);
}

void MonitorDock::navigateToProcessDetailFromArkRiskRow(const int tableRow)
{
    // 输入：风险中心表格的显示行号。
    // 处理：F-12 + F-09 的双重判据，本轮第一个把这两条判据接进生产的调用点。
    //       原实现是 ks::ui::OpenProcessDetailByPid(processId) —— 裸 PID 跳转，
    //       风险行是异步采集的，从采集到点击之间目标随时可能退出并让出 PID，
    //       裸 PID 会把操作交给恰好占用该号码的新进程。
    // 返回：无返回值。判据不过时只弹说明，绝不退回裸 PID 跳转。
    if (m_arkRiskTable == nullptr || tableRow < 0 || tableRow >= m_arkRiskTable->rowCount())
    {
        return;
    }

    // 证据 id 从表格行上取：F-12 要求导航带得上它。
    const QTableWidgetItem* scoreItem = m_arkRiskTable->item(tableRow, riskColumnIndex(RiskColumn::Score));
    const QString evidenceId = scoreItem != nullptr
        ? scoreItem->data(kRiskEvidenceIdRole).toString()
        : QString();

    // 按证据 id 反查当前快照，而不是按行号或缓存下标：
    // 下标在快照被换掉之后仍然“有效”，会静默指向另一条记录；id 查不到就是查不到。
    const MonitorDock::ArkRiskCenterEntry* entry = nullptr;
    if (!evidenceId.isEmpty())
    {
        for (const MonitorDock::ArkRiskCenterEntry& candidate : m_arkRiskCenterEntries)
        {
            if (candidate.evidenceId == evidenceId)
            {
                entry = &candidate;
                break;
            }
        }
    }

    // outcome / liveDecision：两条判据各自的原始结论，一路带进提示文本，便于对照日志排障。
    evidence::NavigationOutcome outcome = evidence::NavigationOutcome::EvidenceIdMissing;
    evidence::LiveNavigationDecision liveDecision = evidence::LiveNavigationDecision::Allow;
    bool liveDecisionEvaluated = false;
    // identityDiagnosticParts：采集期与现场复核各自的原始诊断都留着。
    // 两者说的是不同时刻的不同失败，塌成一条就分不清是“当初没取到”还是“现在读不到”。
    QStringList identityDiagnosticParts;
    quint32 rejectedProcessId = 0U;
    bool noProcessBinding = false;

    if (evidenceId.isEmpty())
    {
        // 请求根本没带证据 id：DecideNavigation 对这种请求也是判 EvidenceIdMissing，
        // 这里没有可构造的请求对象，所以直接用同一个枚举值表达，不另造语义。
        outcome = evidence::NavigationOutcome::EvidenceIdMissing;
    }
    else if (entry == nullptr)
    {
        // 带了 id 但当前快照里查不到：这条证据不在会话中，不能现场“猜”一条补上。
        outcome = evidence::NavigationOutcome::EvidenceNotSaved;
    }
    else if (entry->processId == 0U)
    {
        // 这行本来就不指向进程（驱动 / CPU / Hook 类）。身份判定同样是 IdentityUnusable
        // ——ProcessInstanceId 没有 pid 就是 Unusable——但拒绝理由要说清是"没有对象"。
        outcome = evidence::NavigationOutcome::IdentityUnusable;
        noProcessBinding = true;
    }
    else
    {
        rejectedProcessId = entry->processId;
        if (!entry->processIdentityOutcome.message.empty())
        {
            identityDiagnosticParts << QStringLiteral("capture=%1(%2)")
                .arg(QString::fromStdString(entry->processIdentityOutcome.message),
                    QString::fromLatin1(
                        evidence::CollectionStatusName(entry->processIdentityOutcome.status)));
        }

        // 采集期身份（离线侧）。
        const evidence::ProcessInstanceId savedIdentity = makeSavedProcessIdentity(*entry);

        // 现场复核（F-09）：跳转瞬间重新读一次，绝不复用采集期结果——
        // 复用等于没有复核。
        const LiveProcessProbe liveProbe = probeProcessCreateTime(entry->processId);
        evidence::LiveResolution liveResolution;
        liveResolution.found = liveProbe.present;
        if (liveProbe.present)
        {
            // 现场这一侧填**当前**运行会话，而不是抄采集行里的那个。
            // 抄过来等于无条件宣称“两边同属一个启动周期”；一旦以后支持从文件载入
            // 旧快照，那个假设就会悄悄放行跨启动的同 PID。分开填之后，两个 bootId
            // 不同就会被 MatchProcessInstance 判 NoMatch，正是我们要的拒绝（F-03）。
            liveResolution.liveProcess.bootId = arkRiskSessionBootId().toStdString();
            liveResolution.liveProcess.pid =
                evidence::OptionalU64::of(static_cast<std::uint64_t>(entry->processId));
            if (liveProbe.createTimeKnown)
            {
                liveResolution.liveProcess.createTime100ns =
                    evidence::OptionalU64::of(liveProbe.createTime100ns);
            }
            liveResolution.liveProcess.imageName = savedIdentity.imageName;
        }
        if (!liveProbe.outcome.message.empty())
        {
            identityDiagnosticParts << QStringLiteral("live=%1(%2)")
                .arg(QString::fromStdString(liveProbe.outcome.message),
                    QString::fromLatin1(evidence::CollectionStatusName(liveProbe.outcome.status)));
        }

        evidence::NavigationRequest request;
        request.page = evidence::NavigationPage::Process;
        // MakeProcessRef 的 key 来自 crossSessionKey()：身份不到 Strong 就是空串，
        // ObjectRef::navigable() 随即为假，DecideNavigation 判 IdentityUnusable。
        // 这正是“创建时间取不到就不许跳”的落点。
        request.object = evidence::MakeProcessRef(savedIdentity, evidenceId.toStdString());
        request.evidenceId = evidenceId.toStdString();
        request.anchor = evidence::FormatU64(entry->processId, evidence::U64Format::Decimal);
        request.requireExactMatch = true;

        outcome = evidence::DecideNavigation(
            request,
            processDetailRouteAvailable(),
            // 对象是否还在：以现场探测为准。权限不足读不到创建时间时对象仍然在，
            // 那种情况要落到下面的身份复核去解释，而不是谎称“对象不在”。
            liveProbe.present,
            // 证据 id 已在当前快照里命中，这段证据确实还在会话中。
            true);

        if (outcome == evidence::NavigationOutcome::Delivered)
        {
            liveDecision = evidence::ResolveProcessNavigation(savedIdentity, liveResolution);
            liveDecisionEvaluated = true;
            if (liveDecision == evidence::LiveNavigationDecision::Allow)
            {
                // Allow 蕴含 MatchProcessInstance == Confirmed，而 Confirmed 要求两侧
                // 创建时间都在场且相等，所以这里的 processCreateTime100ns 必然是真值。
                // 即便未来有人破坏了这个前提，OpenProcessDetailByIdentity 对
                // creationTime==0 也会直接拒绝，不会退化成裸 PID 跳转。
                ks::ui::OpenProcessDetailByIdentity(entry->processId, entry->processCreateTime100ns);
                return;
            }
        }
    }

    QString messageText =
        arkRiskNavigationRejectionText(outcome, liveDecision, liveDecisionEvaluated, noProcessBinding);
    messageText += QStringLiteral("\n\n");
    messageText += ks::i18n::contextText(
        QStringLiteral("monitor.ark_risk.nav.context"),
        QStringLiteral("证据 id：%1\nPID：%2\n判据：%3 / %4"))
        .arg(evidenceId.isEmpty() ? QStringLiteral("-") : evidenceId)
        .arg(rejectedProcessId)
        .arg(QString::fromLatin1(evidence::NavigationOutcomeName(outcome)),
            liveDecisionEvaluated
                ? QString::fromLatin1(evidence::LiveNavigationDecisionName(liveDecision))
                : QStringLiteral("-"));
    if (!identityDiagnosticParts.isEmpty())
    {
        messageText += QStringLiteral("\n");
        messageText += ks::i18n::contextText(
            QStringLiteral("monitor.ark_risk.nav.diagnostic"),
            QStringLiteral("身份查询诊断：%1"))
            .arg(identityDiagnosticParts.join(QStringLiteral(" | ")));
    }

    QMessageBox::information(
        this,
        ks::i18n::contextText(
            QStringLiteral("monitor.ark_risk.nav.title"),
            QStringLiteral("无法转到进程详情")),
        messageText);
}

void MonitorDock::exportArkRiskCenterAsJson() const
{
    // 输入：无，读取风险中心缓存。
    // 处理：用户选择路径后写 JSON 数组；缓存为空时提示。
    // 返回：无返回值。
    if (m_arkRiskCenterEntries.empty())
    {
        QMessageBox::information(const_cast<MonitorDock*>(this), QStringLiteral("ARK 风险中心"), QStringLiteral("当前没有可导出的风险记录。"));
        return;
    }
    const QString defaultPath = QDir::home().filePath(QStringLiteral("ark-risk-center-%1.json").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-hhmmss"))));
    const QString filePath = QFileDialog::getSaveFileName(const_cast<MonitorDock*>(this), QStringLiteral("导出 ARK 风险 JSON"), defaultPath, QStringLiteral("JSON (*.json)"));
    if (filePath.isEmpty())
    {
        return;
    }
    QJsonArray rows;
    for (const auto& entry : m_arkRiskCenterEntries)
    {
        rows.append(entry.payload);
    }
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(const_cast<MonitorDock*>(this), QStringLiteral("导出失败"), file.errorString());
        return;
    }
    file.write(QJsonDocument(rows).toJson(QJsonDocument::Indented));
}

void MonitorDock::exportArkRiskCenterAsCsv() const
{
    // 输入：无，读取风险中心缓存。
    // 处理：用户选择路径后写 CSV；缓存为空时提示。
    // 返回：无返回值。
    if (m_arkRiskCenterEntries.empty())
    {
        QMessageBox::information(const_cast<MonitorDock*>(this), QStringLiteral("ARK 风险中心"), QStringLiteral("当前没有可导出的风险记录。"));
        return;
    }
    const QString defaultPath = QDir::home().filePath(QStringLiteral("ark-risk-center-%1.csv").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-hhmmss"))));
    const QString filePath = QFileDialog::getSaveFileName(const_cast<MonitorDock*>(this), QStringLiteral("导出 ARK 风险 CSV"), defaultPath, QStringLiteral("CSV (*.csv)"));
    if (filePath.isEmpty())
    {
        return;
    }
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
    {
        QMessageBox::warning(const_cast<MonitorDock*>(this), QStringLiteral("导出失败"), file.errorString());
        return;
    }
    file.write("riskScore,source,category,title,detail,json\n");
    for (const auto& entry : m_arkRiskCenterEntries)
    {
        const QString jsonText = QString::fromUtf8(QJsonDocument(entry.payload).toJson(QJsonDocument::Compact));
        const QString line = QStringLiteral("%1,%2,%3,%4,%5,%6\n")
            .arg(csvEscape(entry.riskScoreText),
                csvEscape(entry.sourceName),
                csvEscape(entry.category),
                csvEscape(entry.title),
                csvEscape(entry.detail),
                csvEscape(jsonText));
        file.write(line.toUtf8());
    }
}
