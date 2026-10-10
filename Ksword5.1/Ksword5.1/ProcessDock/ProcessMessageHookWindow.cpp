#include "ProcessMessageHookWindow.h"
#include "../UI/FlatButtonTheme.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/UI_All.h"
#include "../UI/DetailDialogChrome.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMenu>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace
{
    class ScopedHookIdentityHandle final
    {
    public:
        explicit ScopedHookIdentityHandle(const HANDLE handleValue)
            : m_handle(handleValue)
        {
        }

        ~ScopedHookIdentityHandle()
        {
            if (m_handle != nullptr)
            {
                ::CloseHandle(m_handle);
            }
        }

        ScopedHookIdentityHandle(const ScopedHookIdentityHandle&) = delete;
        ScopedHookIdentityHandle& operator=(const ScopedHookIdentityHandle&) = delete;

    private:
        HANDLE m_handle = nullptr;
    };

    // hookWindowText：通过 source_translations 翻译此独立窗口的短文本。
    QString hookWindowText(const QString& sourceText)
    {
        return ks::i18n::sourceText(sourceText);
    }

    // formatHex：统一格式化 Hook 地址、句柄和对象字段。
    QString formatHex(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 0, 16)
            .toUpper();
    }

    // formatNtStatus：保留 NTSTATUS 原始十六进制值。
    QString formatNtStatus(const long status)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(status), 8, 16, QChar('0'))
            .toUpper();
    }

    // fixedWideText：安全读取共享协议中的固定 wchar_t 缓冲区。
    QString fixedWideText(const wchar_t* buffer, const std::size_t capacity)
    {
        if (buffer == nullptr || capacity == 0U)
        {
            return {};
        }

        std::size_t length = 0U;
        while (length < capacity && buffer[length] != L'\0')
        {
            ++length;
        }
        return length == 0U
            ? QString()
            : QString::fromWCharArray(buffer, static_cast<qsizetype>(length));
    }

    // hookTypeText：把 Win32 Hook 类型号转换成 WH_* 名称。
    QString hookTypeText(const std::uint32_t hookType)
    {
        switch (hookType)
        {
        case 0xFFFFFFFFUL: return QStringLiteral("WH_MSGFILTER(-1)");
        case 0UL: return QStringLiteral("WH_JOURNALRECORD");
        case 1UL: return QStringLiteral("WH_JOURNALPLAYBACK");
        case 2UL: return QStringLiteral("WH_KEYBOARD");
        case 3UL: return QStringLiteral("WH_GETMESSAGE");
        case 4UL: return QStringLiteral("WH_CALLWNDPROC");
        case 5UL: return QStringLiteral("WH_CBT");
        case 6UL: return QStringLiteral("WH_SYSMSGFILTER");
        case 7UL: return QStringLiteral("WH_MOUSE");
        case 8UL: return QStringLiteral("WH_HARDWARE");
        case 9UL: return QStringLiteral("WH_DEBUG");
        case 10UL: return QStringLiteral("WH_SHELL");
        case 11UL: return QStringLiteral("WH_FOREGROUNDIDLE");
        case 12UL: return QStringLiteral("WH_CALLWNDPROCRET");
        case 13UL: return QStringLiteral("WH_KEYBOARD_LL");
        case 14UL: return QStringLiteral("WH_MOUSE_LL");
        default: return QStringLiteral("WH_TYPE(%1)").arg(hookType);
        }
    }

    // hookFlagsText：展开消息 Hook 标志，同时保留原始位掩码。
    QString hookFlagsText(const std::uint32_t flags)
    {
        QStringList names;
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_GLOBAL) != 0U) names << QStringLiteral("GLOBAL");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_ANSI) != 0U) names << QStringLiteral("ANSI");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NEED_SKIP) != 0U) names << QStringLiteral("NEED_SKIP");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_HUNG) != 0U) names << QStringLiteral("HUNG");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_FAULTED) != 0U) names << QStringLiteral("FAULTED");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NO_DELAY) != 0U) names << QStringLiteral("NO_DELAY");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_WOW64_DLL) != 0U) names << QStringLiteral("WOW64_DLL");
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_DESTROYED) != 0U) names << QStringLiteral("DESTROYED");
        if (names.isEmpty())
        {
            names << QStringLiteral("0");
        }
        return QStringLiteral("%1 (%2)").arg(names.join(QStringLiteral(" | ")), formatHex(flags));
    }

    // hookStatusText：把 Win32k 审计状态转换成稳定短文本。
    QString hookStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_WIN32K_STATUS_OK: return QStringLiteral("OK");
        case KSWORD_ARK_WIN32K_STATUS_PARTIAL: return QStringLiteral("Partial");
        case KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED: return QStringLiteral("Unsupported");
        case KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING: return QStringLiteral("ProfileMissing");
        case KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND: return QStringLiteral("Win32kNotFound");
        case KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED: return QStringLiteral("BufferTruncated");
        case KSWORD_ARK_WIN32K_STATUS_READ_FAILED: return QStringLiteral("ReadFailed");
        case KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED: return QStringLiteral("EnumFailed");
        default: return QStringLiteral("Status(%1)").arg(status);
        }
    }

    // hookSourceText：说明证据来自线程 Hook 链还是全局 Hook 链。
    QString hookSourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SOURCE_THREAD: return QStringLiteral("ThreadHookChain");
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SOURCE_GLOBAL: return QStringLiteral("GlobalHookChain");
        default: return QStringLiteral("Source(%1)").arg(source);
        }
    }

    // queryScopeFlags：把窗口范围映射为共享协议的 owner/target 选择位。
    std::uint32_t queryScopeFlags(const ProcessMessageHookWindow::QueryScope scope)
    {
        switch (scope)
        {
        case ProcessMessageHookWindow::QueryScope::InstalledByProcess:
            return KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_OWNER;
        case ProcessMessageHookWindow::QueryScope::RelatedToProcess:
            return KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_OWNER |
                KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_TARGET;
        case ProcessMessageHookWindow::QueryScope::TargetThreads:
        default:
            return KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_TARGET;
        }
    }

    // queryScopeText：为状态栏和查询范围下拉框提供一致的用户可见文本。
    QString queryScopeText(const ProcessMessageHookWindow::QueryScope scope)
    {
        switch (scope)
        {
        case ProcessMessageHookWindow::QueryScope::InstalledByProcess:
            return hookWindowText(QStringLiteral("由该进程安装"));
        case ProcessMessageHookWindow::QueryScope::RelatedToProcess:
            return hookWindowText(QStringLiteral("与该进程相关（目标或所有者）"));
        case ProcessMessageHookWindow::QueryScope::TargetThreads:
        default:
            return hookWindowText(QStringLiteral("作用于该进程线程"));
        }
    }

    // entryMatchesProcessScope：防御性复核 R0 返回，并兼容忽略新 Flag 的旧驱动。
    bool entryMatchesProcessScope(
        const KSWORD_ARK_WIN32K_HOOK_ENTRY& entry,
        const ProcessMessageHookTarget& target,
        const ProcessMessageHookWindow::QueryScope scope)
    {
        const bool targetSessionMatches = target.sessionId == 0U ||
            entry.targetSessionId == 0U ||
            entry.targetSessionId == target.sessionId;
        const bool ownerSessionMatches = target.sessionId == 0U ||
            entry.sessionId == 0U ||
            entry.sessionId == target.sessionId;
        const bool targetMatches =
            entry.hookScope == KSWORD_ARK_WIN32K_MESSAGE_HOOK_SCOPE_THREAD &&
            entry.targetProcessId == target.processId &&
            targetSessionMatches;
        const bool ownerMatches = entry.processId == target.processId &&
            ownerSessionMatches;

        switch (scope)
        {
        case ProcessMessageHookWindow::QueryScope::InstalledByProcess:
            return ownerMatches;
        case ProcessMessageHookWindow::QueryScope::RelatedToProcess:
            return targetMatches || ownerMatches;
        case ProcessMessageHookWindow::QueryScope::TargetThreads:
        default:
            return targetMatches;
        }
    }

    // moduleText：优先解析模块 atom 名称，失败时仍保留 moduleId/atom 证据。
    QString moduleText(const KSWORD_ARK_WIN32K_HOOK_ENTRY& entry)
    {
        QString atomName;
        if (entry.moduleAtom != 0U && entry.moduleAtom <= 0xFFFFU)
        {
            std::array<wchar_t, 512> buffer{};
            const UINT length = ::GlobalGetAtomNameW(
                static_cast<ATOM>(entry.moduleAtom),
                buffer.data(),
                static_cast<int>(buffer.size()));
            if (length != 0U)
            {
                atomName = QString::fromWCharArray(buffer.data(), static_cast<qsizetype>(length));
            }
        }

        QStringList evidence;
        if (!atomName.trimmed().isEmpty()) evidence << atomName;
        if (entry.moduleId != 0U) evidence << QStringLiteral("moduleId=%1").arg(entry.moduleId);
        if (entry.moduleAtom != 0U) evidence << QStringLiteral("atom=%1").arg(formatHex(entry.moduleAtom));
        return evidence.isEmpty() ? QStringLiteral("-") : evidence.join(QStringLiteral(" | "));
    }

    // columnIndex：把列枚举转换成 QTableWidget 使用的整数。
    int columnIndex(const ProcessMessageHookWindow::Column column)
    {
        return static_cast<int>(column);
    }

    // presetButtonStyle：按选中状态绘制 A/B 列组按钮。
    QString presetButtonStyle(const bool selected)
    {
        // 业务列预设仍按当前属性选择强调态，固定宽度和字重保持原值。
        return ks::ui::BuildFlatButtonStyle(selected ? ks::ui::FlatButtonTone::Accent : ks::ui::FlatButtonTone::Neutral)
            + QStringLiteral("QPushButton{min-width:26px;max-width:26px;padding:3px 0;border-radius:0;font-weight:700;}");
    }
}

ProcessMessageHookWindow::ProcessMessageHookWindow(
    const ProcessMessageHookTarget& target,
    QWidget* parent)
    : QDialog(parent)
    , m_target(target)
{
    // 独立顶层、非模态并关闭即释放，允许同时查看多个进程。
    setWindowFlag(Qt::Window, true);
    setWindowModality(Qt::NonModal);
    setAttribute(Qt::WA_DeleteOnClose, true);
    initializeUi();
    initializeConnections();
    requestRefresh();
}

void ProcessMessageHookWindow::initializeUi()
{
    setObjectName(QStringLiteral("ProcessMessageHookWindowRoot"));
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(true);
    setStyleSheet(KswordTheme::OpaqueDialogStyle(objectName()));
    ks::i18n::LanguageManager::instance().bindWindowTitle(
        this,
        QStringLiteral("process.message_hook.title"),
        QStringLiteral("进程消息 Hook"));
    ks::ui::applyResponsiveWindowGeometry(
        this,
        parentWidget(),
        QSize(1180, 680),
        QSize(720, 480));

    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(10, 10, 10, 10);
    rootLayout->setSpacing(7);

    auto* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);

    m_refreshButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
        hookWindowText(QStringLiteral("刷新")),
        this);
    m_refreshButton->setStyleSheet(ks::ui::BuildFlatButtonStyle() + QStringLiteral("QPushButton,QToolButton{border-radius:3px;padding:4px 10px;font-weight:600;}"));

    auto* scopeLabel = new QLabel(hookWindowText(QStringLiteral("范围：")), this);
    m_scopeCombo = new QComboBox(this);
    m_scopeCombo->addItem(
        queryScopeText(QueryScope::TargetThreads),
        static_cast<int>(QueryScope::TargetThreads));
    m_scopeCombo->addItem(
        queryScopeText(QueryScope::InstalledByProcess),
        static_cast<int>(QueryScope::InstalledByProcess));
    m_scopeCombo->addItem(
        queryScopeText(QueryScope::RelatedToProcess),
        static_cast<int>(QueryScope::RelatedToProcess));
    m_scopeCombo->setToolTip(hookWindowText(QStringLiteral(
        "选择按目标线程、Hook 安装者或两者查询；筛选同时在 R0 和 R3 生效。")));
    m_scopeCombo->setStyleSheet(KswordTheme::ThemedComboBoxStyle());
    m_scopeCombo->setMinimumContentsLength(18);
    scopeLabel->setBuddy(m_scopeCombo);

    m_columnAButton = new QPushButton(QStringLiteral("A"), this);
    m_columnAButton->setToolTip(hookWindowText(
        QStringLiteral("显示 A 组精简列：目标线程、Hook 类型、所有者、回调、模块和状态。")));
    m_columnAButton->setCursor(Qt::PointingHandCursor);

    m_columnBButton = new QPushButton(QStringLiteral("B"), this);
    m_columnBButton->setToolTip(hookWindowText(
        QStringLiteral("显示 B 组精简列：对象地址、来源、NTSTATUS 和诊断证据。")));
    m_columnBButton->setCursor(Qt::PointingHandCursor);

    const QString processName = m_target.processName.trimmed().isEmpty()
        ? QStringLiteral("-")
        : m_target.processName.trimmed();
    m_targetLabel = new QLabel(
        hookWindowText(QStringLiteral("目标：%1  PID=%2  Session=%3"))
            .arg(processName)
            .arg(m_target.processId)
            .arg(m_target.sessionId),
        this);
    m_targetLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_targetLabel->setStyleSheet(
        QStringLiteral("font-weight:600;color:%1;").arg(KswordTheme::TextPrimaryHex()));

    toolbarLayout->addWidget(m_refreshButton, 0);
    toolbarLayout->addWidget(scopeLabel, 0);
    toolbarLayout->addWidget(m_scopeCombo, 0);
    toolbarLayout->addSpacing(4);
    toolbarLayout->addWidget(m_columnAButton, 0);
    toolbarLayout->addWidget(m_columnBButton, 0);
    toolbarLayout->addWidget(m_targetLabel, 1);
    rootLayout->addLayout(toolbarLayout);

    m_statusLabel = new QLabel(hookWindowText(QStringLiteral("等待查询消息 Hook。")), this);
    m_statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    rootLayout->addWidget(m_statusLabel, 0);

    m_table = new QTableWidget(this);
    m_table->setColumnCount(columnIndex(Column::Count));
    m_table->setHorizontalHeaderLabels(QStringList{
        hookWindowText(QStringLiteral("目标 PID")),
        hookWindowText(QStringLiteral("目标 TID")),
        hookWindowText(QStringLiteral("Hook 类型")),
        hookWindowText(QStringLiteral("所有者 PID")),
        hookWindowText(QStringLiteral("所有者 TID")),
        hookWindowText(QStringLiteral("回调地址")),
        hookWindowText(QStringLiteral("模块")),
        hookWindowText(QStringLiteral("Flags")),
        hookWindowText(QStringLiteral("状态")),
        hookWindowText(QStringLiteral("Session")),
        hookWindowText(QStringLiteral("Hook 句柄")),
        hookWindowText(QStringLiteral("Hook 对象")),
        hookWindowText(QStringLiteral("模块基址")),
        hookWindowText(QStringLiteral("过程偏移")),
        hookWindowText(QStringLiteral("来源")),
        hookWindowText(QStringLiteral("NTSTATUS")),
        hookWindowText(QStringLiteral("诊断")) });
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->setWordWrap(false);
    m_table->setTextElideMode(Qt::ElideRight);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);
    rootLayout->addWidget(m_table, 1);

    applyColumnPreset(QStringLiteral("A"));
    ks::ui::ApplyDetailDialogChrome(this);
}

void ProcessMessageHookWindow::initializeConnections()
{
    connect(m_refreshButton, &QPushButton::clicked, this, [this]()
        {
            requestRefresh();
        });
    connect(m_scopeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
        [this](const int)
        {
            requestRefresh();
        });
    connect(m_columnAButton, &QPushButton::clicked, this, [this]()
        {
            applyColumnPreset(QStringLiteral("A"));
        });
    connect(m_columnBButton, &QPushButton::clicked, this, [this]()
        {
            applyColumnPreset(QStringLiteral("B"));
        });
    connect(m_table, &QTableWidget::customContextMenuRequested, this,
        [this](const QPoint& position)
        {
            showTableContextMenu(position);
        });
    connect(m_table->horizontalHeader(), &QHeaderView::customContextMenuRequested, this,
        [this](const QPoint& position)
        {
            showHeaderContextMenu(position);
        });
}

ProcessMessageHookWindow::QueryScope ProcessMessageHookWindow::currentQueryScope() const
{
    if (m_scopeCombo == nullptr)
    {
        return QueryScope::TargetThreads;
    }

    bool conversionOk = false;
    const int scopeValue = m_scopeCombo->currentData().toInt(&conversionOk);
    if (!conversionOk ||
        scopeValue < static_cast<int>(QueryScope::TargetThreads) ||
        scopeValue > static_cast<int>(QueryScope::RelatedToProcess))
    {
        return QueryScope::TargetThreads;
    }
    return static_cast<QueryScope>(scopeValue);
}

void ProcessMessageHookWindow::requestRefresh()
{
    if (m_refreshInProgress)
    {
        m_refreshPending = true;
        return;
    }

    m_refreshInProgress = true;
    const std::uint64_t ticket = ++m_refreshTicket;
    const QueryScope queryScope = currentQueryScope();
    m_refreshButton->setEnabled(false);
    // 查询进行中保留上次表格作为视觉参考，但禁用交互，避免将旧范围误当当前结果。
    m_table->setEnabled(false);
    m_statusLabel->setText(
        hookWindowText(QStringLiteral("正在查询：%1…"))
            .arg(queryScopeText(queryScope)));
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::PrimaryBlueHex));

    const ProcessMessageHookTarget target = m_target;
    QPointer<ProcessMessageHookWindow> guardThis(this);
    auto* task = QRunnable::create([guardThis, ticket, target, queryScope]()
        {
            QueryResult queryResult;
            queryResult.queryScope = queryScope;
            HANDLE rawIdentityHandle = nullptr;
            DWORD identityError = ERROR_INVALID_PARAMETER;
            if (target.processId != 0U && target.creationTime100ns != 0U)
            {
                rawIdentityHandle = ::OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    target.processId);
                identityError = rawIdentityHandle != nullptr
                    ? ERROR_SUCCESS
                    : ::GetLastError();
            }
            const ScopedHookIdentityHandle identityHandle(rawIdentityHandle);

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            const bool identityReadable = rawIdentityHandle != nullptr
                && ::GetProcessTimes(
                    rawIdentityHandle,
                    &creationTime,
                    &exitTime,
                    &kernelTime,
                    &userTime) != FALSE;
            if (!identityReadable && rawIdentityHandle != nullptr)
            {
                identityError = ::GetLastError();
            }
            const std::uint64_t actualCreationTime100ns = identityReadable
                ? (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U)
                    | static_cast<std::uint64_t>(creationTime.dwLowDateTime)
                : 0U;
            if (!identityReadable
                || actualCreationTime100ns != target.creationTime100ns)
            {
                queryResult.ioMessage = hookWindowText(QStringLiteral(
                    "进程身份已变化（PID 可能已被复用），已拒绝操作。"));
                queryResult.detail = QStringLiteral(
                    "expectedCreateTime100ns=%1; actualCreateTime100ns=%2; error=%3")
                    .arg(static_cast<qulonglong>(target.creationTime100ns))
                    .arg(static_cast<qulonglong>(actualCreationTime100ns))
                    .arg(identityError);
            }
            else
            {
                const ksword::ark::Win32kHooksPdbResult driverResult =
                    ksword::ark::DriverClient().queryWin32kHooksPdb(
                        KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL |
                            queryScopeFlags(queryScope),
                        target.sessionId,
                        target.processId,
                        0UL,
                        KSWORD_ARK_WIN32K_MESSAGE_HOOK_DEFAULT_MAX_ENTRIES);

                queryResult.ioOk = driverResult.io.ok;
                queryResult.unsupported = driverResult.unsupported;
                queryResult.status = driverResult.status;
                queryResult.totalCount = driverResult.totalCount;
                queryResult.returnedCount = driverResult.returnedCount;
                queryResult.discoveredChainCount = driverResult.discoveredChainCount;
                queryResult.visitedNodeCount = driverResult.visitedNodeCount;
                queryResult.readFailureCount = driverResult.readFailureCount;
                queryResult.corruptLinkCount = driverResult.corruptLinkCount;
                queryResult.duplicateCount = driverResult.duplicateCount;
                queryResult.lastStatus = driverResult.lastStatus;
                queryResult.ioMessage = QString::fromStdString(driverResult.io.message);
                queryResult.detail = driverResult.detail.empty()
                    ? QString()
                    : QString::fromWCharArray(
                        driverResult.detail.c_str(),
                        static_cast<qsizetype>(driverResult.detail.size()));

                queryResult.rows.reserve(driverResult.entries.size());
                for (const KSWORD_ARK_WIN32K_HOOK_ENTRY& entry : driverResult.entries)
                {
                    if (!entryMatchesProcessScope(entry, target, queryScope))
                    {
                        continue;
                    }

                    QStringList diagnosticParts;
                    diagnosticParts << QStringLiteral("fieldFlags=%1").arg(formatHex(entry.fieldFlags));
                    diagnosticParts << QStringLiteral("ownerSession=%1").arg(entry.sessionId);
                    diagnosticParts << QStringLiteral("targetSession=%1").arg(entry.targetSessionId);
                    diagnosticParts << QStringLiteral("threadInfo=%1").arg(formatHex(entry.threadInfo));
                    diagnosticParts << QStringLiteral("targetThreadInfo=%1").arg(formatHex(entry.targetThreadInfo));
                    diagnosticParts << QStringLiteral("desktop=%1").arg(formatHex(entry.desktopObject));
                    const QString entryDetail = fixedWideText(
                        entry.detail,
                        KSWORD_ARK_WIN32K_DETAIL_CHARS).trimmed();
                    if (!entryDetail.isEmpty()) diagnosticParts << entryDetail;

                    queryResult.rows.push_back(QStringList{
                        QString::number(entry.targetProcessId),
                        QString::number(entry.targetThreadId),
                        hookTypeText(entry.hookType),
                        QString::number(entry.processId),
                        QString::number(entry.threadId),
                        formatHex(entry.procedureAddress),
                        moduleText(entry),
                        hookFlagsText(entry.flags),
                        hookStatusText(entry.status),
                        QString::number(entry.targetSessionId != 0U ? entry.targetSessionId : entry.sessionId),
                        formatHex(entry.hookHandle),
                        formatHex(entry.hookObject),
                        formatHex(entry.moduleBase),
                        formatHex(entry.procedureOffset),
                        hookSourceText(entry.source),
                        formatNtStatus(entry.lastStatus),
                        diagnosticParts.join(QStringLiteral("; ")) });
                }
                queryResult.matchedCount = static_cast<std::uint32_t>(queryResult.rows.size());
            }

            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, ticket, queryResult]()
                {
                    if (guardThis != nullptr)
                    {
                        guardThis->applyQueryResult(ticket, queryResult);
                    }
                },
                Qt::QueuedConnection);
        });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void ProcessMessageHookWindow::applyQueryResult(
    const std::uint64_t ticket,
    const QueryResult& result)
{
    if (ticket < m_refreshTicket)
    {
        return;
    }

    m_refreshInProgress = false;

    // 范围切换发生在异步查询期间时，不让旧范围结果短暂覆盖新选择。
    if (result.queryScope != currentQueryScope())
    {
        m_refreshPending = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestRefresh();
            }, Qt::QueuedConnection);
        return;
    }

    m_refreshButton->setEnabled(true);
    rebuildTable(result);
    m_table->setEnabled(true);

    const QString overallStatus = hookStatusText(result.status);
    QString statusText;
    const QString scopeText = queryScopeText(result.queryScope);
    const bool statusOk = result.ioOk &&
        result.status == KSWORD_ARK_WIN32K_STATUS_OK &&
        result.readFailureCount == 0U &&
        result.corruptLinkCount == 0U &&
        result.returnedCount >= result.totalCount;
    if (!result.ioOk)
    {
        statusText = hookWindowText(QStringLiteral("查询失败：%1"))
            .arg(result.ioMessage.trimmed().isEmpty()
                ? hookWindowText(QStringLiteral("驱动接口不可用或版本不匹配。"))
                : result.ioMessage.trimmed());
    }
    else if (result.rows.empty())
    {
        statusText = hookWindowText(
            QStringLiteral("查询完成：驱动返回 %1 行，按“%2”复核后没有可显示的 Hook。总体状态：%3。"))
            .arg(result.returnedCount)
            .arg(scopeText)
            .arg(overallStatus);
    }
    else
    {
        statusText = hookWindowText(
            QStringLiteral("查询完成：按“%1”显示 %2 条 Hook，驱动返回 %3/%4 行。总体状态：%5。"))
            .arg(scopeText)
            .arg(result.matchedCount)
            .arg(result.returnedCount)
            .arg(result.totalCount)
            .arg(overallStatus);
    }
    if (result.ioOk)
    {
        statusText += QLatin1Char(' ') + hookWindowText(QStringLiteral(
            "遍历：链 %1，节点 %2，读取失败 %3，损坏链接 %4，重复 %5。"))
            .arg(result.discoveredChainCount)
            .arg(result.visitedNodeCount)
            .arg(result.readFailureCount)
            .arg(result.corruptLinkCount)
            .arg(result.duplicateCount);
    }
    m_statusLabel->setText(statusText);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg((statusOk ? KswordTheme::SuccessColor() : KswordTheme::WarningColor())
                .name(QColor::HexRgb)));

    if (m_refreshPending)
    {
        m_refreshPending = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestRefresh();
            }, Qt::QueuedConnection);
    }
}

void ProcessMessageHookWindow::rebuildTable(const QueryResult& result)
{
    m_table->setSortingEnabled(false);
    m_table->clearContents();

    if (!result.rows.empty())
    {
        m_table->setRowCount(static_cast<int>(result.rows.size()));
        for (int row = 0; row < static_cast<int>(result.rows.size()); ++row)
        {
            const QStringList& cells = result.rows[static_cast<std::size_t>(row)];
            for (int column = 0; column < columnIndex(Column::Count); ++column)
            {
                auto* item = new QTableWidgetItem(column < cells.size() ? cells[column] : QString());
                item->setToolTip(item->text());
                m_table->setItem(row, column, item);
            }
        }
    }
    else
    {
        m_table->setRowCount(1);
        QStringList detailParts;
        detailParts << QStringLiteral("io=%1").arg(result.ioOk ? QStringLiteral("ok") : QStringLiteral("failed"));
        detailParts << QStringLiteral("status=%1").arg(hookStatusText(result.status));
        detailParts << QStringLiteral("returned=%1/%2").arg(result.returnedCount).arg(result.totalCount);
        detailParts << QStringLiteral("scope=%1").arg(queryScopeText(result.queryScope));
        detailParts << QStringLiteral("chains=%1").arg(result.discoveredChainCount);
        detailParts << QStringLiteral("visited=%1").arg(result.visitedNodeCount);
        detailParts << QStringLiteral("readFailures=%1").arg(result.readFailureCount);
        detailParts << QStringLiteral("corruptLinks=%1").arg(result.corruptLinkCount);
        detailParts << QStringLiteral("duplicates=%1").arg(result.duplicateCount);
        detailParts << QStringLiteral("lastStatus=%1").arg(formatNtStatus(result.lastStatus));
        if (!result.ioMessage.trimmed().isEmpty()) detailParts << result.ioMessage.trimmed();
        if (!result.detail.trimmed().isEmpty()) detailParts << result.detail.trimmed();

        for (int column = 0; column < columnIndex(Column::Count); ++column)
        {
            m_table->setItem(0, column, new QTableWidgetItem(QStringLiteral("-")));
        }
        m_table->item(0, columnIndex(Column::HookType))->setText(
            hookWindowText(QStringLiteral("<无可显示的消息 Hook>")));
        m_table->item(0, columnIndex(Column::Status))->setText(hookStatusText(result.status));
        m_table->item(0, columnIndex(Column::LastStatus))->setText(formatNtStatus(result.lastStatus));
        m_table->item(0, columnIndex(Column::Diagnostic))->setText(detailParts.join(QStringLiteral("; ")));
        for (int column = 0; column < columnIndex(Column::Count); ++column)
        {
            m_table->item(0, column)->setToolTip(m_table->item(0, column)->text());
        }
    }

    m_table->setSortingEnabled(true);
    if (m_table->rowCount() > 0)
    {
        m_table->selectRow(0);
    }
    m_table->resizeRowsToContents();
}

void ProcessMessageHookWindow::applyColumnPreset(const QString& presetName)
{
    static const std::array<Column, 9> groupA{
        Column::TargetProcessId,
        Column::TargetThreadId,
        Column::HookType,
        Column::OwnerProcessId,
        Column::OwnerThreadId,
        Column::CallbackAddress,
        Column::Module,
        Column::Flags,
        Column::Status };
    static const std::array<Column, 11> groupB{
        Column::TargetProcessId,
        Column::TargetThreadId,
        Column::HookType,
        Column::SessionId,
        Column::HookHandle,
        Column::HookObject,
        Column::ModuleBase,
        Column::ProcedureOffset,
        Column::Source,
        Column::LastStatus,
        Column::Diagnostic };

    for (int column = 0; column < columnIndex(Column::Count); ++column)
    {
        const auto matchesColumn = [column](const Column candidate)
        {
            return columnIndex(candidate) == column;
        };
        const bool visible = presetName == QStringLiteral("B")
            ? std::any_of(groupB.begin(), groupB.end(), matchesColumn)
            : std::any_of(groupA.begin(), groupA.end(), matchesColumn);
        m_table->setColumnHidden(column, !visible);
    }
    m_table->setProperty("kswordColumnPreset", presetName == QStringLiteral("B")
        ? QStringLiteral("B")
        : QStringLiteral("A"));
    updateColumnPresetButtons();
}

void ProcessMessageHookWindow::updateColumnPresetButtons()
{
    const QString preset = m_table->property("kswordColumnPreset").toString();
    m_columnAButton->setStyleSheet(presetButtonStyle(preset == QStringLiteral("A")));
    m_columnBButton->setStyleSheet(presetButtonStyle(preset == QStringLiteral("B")));
}

void ProcessMessageHookWindow::showHeaderContextMenu(const QPoint& localPosition)
{
    QMenu menu(this);
    QAction* titleAction = menu.addAction(hookWindowText(QStringLiteral("显示的列")));
    titleAction->setEnabled(false);
    menu.addSeparator();

    for (int column = 0; column < columnIndex(Column::Count); ++column)
    {
        const QTableWidgetItem* headerItem = m_table->horizontalHeaderItem(column);
        QAction* action = menu.addAction(headerItem != nullptr ? headerItem->text() : QString::number(column));
        action->setCheckable(true);
        action->setChecked(!m_table->isColumnHidden(column));
        action->setData(column);
    }
    menu.addSeparator();
    QAction* showAllAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/filter_funnel.svg")),
        hookWindowText(QStringLiteral("显示全部列")));

    QAction* selectedAction = menu.exec(
        m_table->horizontalHeader()->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == showAllAction)
    {
        for (int column = 0; column < columnIndex(Column::Count); ++column)
        {
            m_table->setColumnHidden(column, false);
        }
        m_table->setProperty("kswordColumnPreset", QStringLiteral("Custom"));
        updateColumnPresetButtons();
        return;
    }

    const int column = selectedAction->data().toInt();
    if (!selectedAction->isChecked() && visibleColumnCount() <= 1)
    {
        m_table->setColumnHidden(column, false);
        return;
    }
    m_table->setColumnHidden(column, !selectedAction->isChecked());
    m_table->setProperty("kswordColumnPreset", QStringLiteral("Custom"));
    updateColumnPresetButtons();
}

void ProcessMessageHookWindow::showTableContextMenu(const QPoint& localPosition)
{
    const QModelIndex index = m_table->indexAt(localPosition);
    if (index.isValid())
    {
        m_table->setCurrentCell(index.row(), index.column());
        m_table->selectRow(index.row());
    }

    QMenu menu(this);
    QAction* copyCellAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_cell.svg")),
        hookWindowText(QStringLiteral("复制单元格")));
    QAction* copyRowAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        hookWindowText(QStringLiteral("复制当前行")));
    QAction* copyAllAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        hookWindowText(QStringLiteral("复制全部行")));
    copyCellAction->setEnabled(m_table->currentItem() != nullptr);
    copyRowAction->setEnabled(m_table->currentRow() >= 0);
    copyAllAction->setEnabled(m_table->rowCount() > 0);

    QAction* selectedAction = menu.exec(m_table->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyCellAction) copyCurrentCell();
    else if (selectedAction == copyRowAction) copyCurrentRow();
    else if (selectedAction == copyAllAction) copyAllRows();
}

void ProcessMessageHookWindow::copyCurrentCell() const
{
    if (m_table->currentItem() != nullptr)
    {
        QApplication::clipboard()->setText(m_table->currentItem()->text());
    }
}

void ProcessMessageHookWindow::copyCurrentRow() const
{
    if (m_table->currentRow() >= 0)
    {
        QApplication::clipboard()->setText(
            tableHeaderText() + QLatin1Char('\n') + tableRowText(m_table->currentRow()));
    }
}

void ProcessMessageHookWindow::copyAllRows() const
{
    QStringList lines;
    lines << tableHeaderText();
    for (int row = 0; row < m_table->rowCount(); ++row)
    {
        lines << tableRowText(row);
    }
    QApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
}

QString ProcessMessageHookWindow::tableRowText(const int row) const
{
    QStringList fields;
    for (int column = 0; column < columnIndex(Column::Count); ++column)
    {
        const QTableWidgetItem* item = m_table->item(row, column);
        fields << (item != nullptr ? item->text() : QString());
    }
    return fields.join(QLatin1Char('\t'));
}

QString ProcessMessageHookWindow::tableHeaderText() const
{
    QStringList headers;
    for (int column = 0; column < columnIndex(Column::Count); ++column)
    {
        const QTableWidgetItem* item = m_table->horizontalHeaderItem(column);
        headers << (item != nullptr ? item->text() : QString());
    }
    return headers.join(QLatin1Char('\t'));
}

int ProcessMessageHookWindow::visibleColumnCount() const
{
    int count = 0;
    for (int column = 0; column < columnIndex(Column::Count); ++column)
    {
        if (!m_table->isColumnHidden(column))
        {
            ++count;
        }
    }
    return count;
}
