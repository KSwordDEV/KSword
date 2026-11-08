#include "ClipboardGuardPage.h"
#include "../../../../shared/ApiMonitorInjection.h"
#include "../../theme.h"
#include "../../MonitorDock/WinApiMonitorProtocol.h"
#include "../../Framework/PrivilegeElevationPrompt.h"
#include "../../Internationalization/LanguageManager.h"
#include "../../UI/TableInteractionSupport.h"

#include <QApplication>
#include <QBrush>
#include <QCheckBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QSaveFile>
#include <QScrollBar>
#include <QTimer>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QStringConverter>
#include <QThreadPool>
#include <QUuid>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <iterator>
#include <functional>

// ============================================================
// ClipboardGuardPage.Session.cpp
// 作用：
// 1) 规则表与驱动的双向同步（KSWORD_ARK_CLIPBOARD_POLICY_RULE 整表下发/回读）；
// 2) 按规则匹配当前运行进程，按目标位数注入 Agent 并写会话 INI；
// 3) 每个受管进程一条命名管道读取线程，事件解析后送进共享队列，
//    由 QTimer 批量刷进事件表（照抄 WinAPIDock 的 child-pipe 范式）。
// ============================================================

namespace ks::misc
{
    namespace
    {
        constexpr DWORD kPacketSize = static_cast<DWORD>(sizeof(ks::winapi_monitor::ApiMonitorEventPacket));

        template <std::size_t kCount>
        QString wideBufferToText(const wchar_t(&bufferValue)[kCount])
        {
            QString textValue = QString::fromWCharArray(bufferValue, static_cast<int>(kCount));
            const int nullIndex = textValue.indexOf(QChar(u'\0'));
            if (nullIndex >= 0)
            {
                textValue.truncate(nullIndex);
            }
            return textValue.trimmed();
        }

        // parseDetailField 作用：从 "key1=value1 key2=value2 ..." 形式的 detail 文本里
        // 取出某个 key 的值。ReportClipboardEvent（APIMonitor_x64 侧）用同样的分隔约定拼串，
        // 双方约定好格式即可，不需要一套共享的序列化库。
        QString parseDetailField(const QString& detailText, const QString& keyName)
        {
            const QString markerText = keyName + QStringLiteral("=");
            const int markerIndex = detailText.indexOf(markerText);
            if (markerIndex < 0)
            {
                return QString();
            }
            const int valueStart = markerIndex + markerText.size();
            int valueEnd = detailText.indexOf(QChar(u' '), valueStart);
            if (valueEnd < 0)
            {
                valueEnd = detailText.size();
            }
            return detailText.mid(valueStart, valueEnd - valueStart);
        }

        // packetToEventRow 作用：把 Agent 固定事件包解析成表格展示用的结构。
        ClipboardGuardEventRow packetToEventRow(const ks::winapi_monitor::ApiMonitorEventPacket& packetValue, const QString& processText)
        {
            ClipboardGuardEventRow rowValue;
            rowValue.timeText = QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz"));
            rowValue.pid = packetValue.pid;
            rowValue.tid = packetValue.tid;
            rowValue.processText = processText;

            const QString detailText = wideBufferToText(packetValue.detailText);
            rowValue.operationText = parseDetailField(detailText, QStringLiteral("op"));
            rowValue.formatText = parseDetailField(detailText, QStringLiteral("fmt"));
            rowValue.resultText = parseDetailField(detailText, QStringLiteral("action"));
            rowValue.sessionText = parseDetailField(detailText, QStringLiteral("session"));
            rowValue.integrityText = parseDetailField(detailText, QStringLiteral("integrity"));
            rowValue.ownerText = parseDetailField(detailText, QStringLiteral("owner"));
            rowValue.seq = parseDetailField(detailText, QStringLiteral("seq")).toULongLong();
            return rowValue;
        }
    }

    void ClipboardGuardInbox::push(ClipboardGuardEventRow row)
    {
        std::lock_guard<std::mutex> lock(mutex);
        ++received;
        if (pendingRows.size() >= PendingCapacity) { pendingRows.pop_front(); ++dropped; }
        pendingRows.push_back(std::move(row));
    }

    std::vector<ClipboardGuardEventRow> ClipboardGuardInbox::take(const std::size_t limit)
    {
        std::vector<ClipboardGuardEventRow> rows;
        std::lock_guard<std::mutex> lock(mutex);
        const auto count = std::min(limit, pendingRows.size()); rows.reserve(count);
        for (std::size_t i = 0; i < count; ++i) { rows.push_back(std::move(pendingRows.front())); pendingRows.pop_front(); }
        return rows;
    }

    QString ClipboardGuardInbox::processName(const quint32 pid)
    {
        std::lock_guard<std::mutex> lock(mutex);
        const auto found = processNames.find(pid);
        return found == processNames.end() ? QStringLiteral("PID %1").arg(pid) : found->second;
    }

    void ClipboardGuardInbox::replaceNames(std::unordered_map<quint32, QString> names)
    {
        { std::lock_guard<std::mutex> lock(mutex); processNames.swap(names); }
    }

    void ClipboardGuardInbox::noteAgentDropped(const quint64 session, const quint64 count)
    {
        std::lock_guard<std::mutex> lock(mutex);
        agentDropped[session] = std::max(agentDropped[session], count);
    }

    void ClipboardGuardInbox::finishSessionDrops(const quint64 session)
    {
        std::lock_guard<std::mutex> lock(mutex);
        const auto found = agentDropped.find(session);
        if (found == agentDropped.end()) return;
        completedAgentDropped += found->second;
        agentDropped.erase(found);
    }

    ClipboardGuardInbox::Counts ClipboardGuardInbox::counts() const
    {
        std::lock_guard<std::mutex> lock(mutex);
        Counts value{ received, dropped, completedAgentDropped, pendingRows.size() };
        for (const auto& item : agentDropped) value.agentDropped += item.second;
        return value;
    }

    ClipboardGuardRuntime::ClipboardGuardRuntime(std::shared_ptr<ClipboardGuardInbox> inbox)
        : m_inbox(std::move(inbox)) {}

    void ClipboardGuardRuntime::requestStop()
    {
        { std::lock_guard<std::mutex> lock(m_queueMutex); m_stopRequested.store(true); }
        m_wake.notify_all();
    }

    bool ClipboardGuardRuntime::requestScan(std::vector<ClipboardGuardRule> rules, QString agentBasePath)
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        if (m_stopRequested.load()) return false;
        if (!m_started.load())
        {
            const std::weak_ptr<ClipboardGuardRuntime> weak = shared_from_this();
            m_cleanupLease = ks::ui::AsyncCleanupRegistry::global().acquire([weak]()
            { if (const auto runtime = weak.lock()) runtime->requestStop(); });
            if (!m_cleanupLease) return false;
            m_started.store(true);
            try { std::thread([runtime = shared_from_this()]() { runtime->run(); }).detach(); }
            catch (...) { m_stopRequested.store(true); m_started.store(false); m_finished.store(true); m_cleanupLease.reset(); return false; }
        }
        // Only unstarted policy snapshots coalesce; an entered scan/transaction is
        // never superseded. Runtime stop is observed at safe per-target boundaries.
        m_summary.ruleCount = rules.size();
        m_pending = ScanRequest{ std::move(rules), std::move(agentBasePath) };
        m_wake.notify_all();
        return true;
    }

    void ClipboardGuardRuntime::run()
    {
        try
        {
            for (;;)
            {
                std::optional<ScanRequest> request;
                {
                    std::unique_lock<std::mutex> lock(m_queueMutex);
                    m_wake.wait(lock, [this]() { return m_stopRequested.load() || m_pending.has_value(); });
                    if (m_stopRequested.load()) { m_pending.reset(); break; }
                    request = std::move(m_pending); m_pending.reset();
                }
                scan(*request);
            }
        }
        catch (...)
        {
            requestStop();
            kLogEvent event; err << event << "[ClipboardGuard] runtime scan failed; stopping owned sessions" << eol;
        }
        // All accepted native sessions remain owned here after QWidget destruction.
        // STOP/config ACL, CancelSynchronousIo and joins are still real cleanup.
        for (;;)
        {
            std::uint32_t pid = 0;
            { std::lock_guard<std::mutex> lock(m_sessionsMutex); if (m_sessions.empty()) break; pid = m_sessions.front()->pid; }
            teardownSession(pid);
        }
        m_cleanupLease.reset(); // owned local pipe/session handles and PID leases ended
        m_finished.store(true);
    }

    ClipboardGuardRuntime::Summary ClipboardGuardRuntime::summary() const
    {
        Summary result;
        { std::lock_guard<std::mutex> lock(m_queueMutex); result = m_summary; }
        { std::lock_guard<std::mutex> lock(m_sessionsMutex);
            for (const auto& session : m_sessions)
                if (session && session->hooksInstalled.load() && !session->pipeThreadExited.load()) ++result.protectedCount;
        }
        result.stopping = m_stopRequested.load();
        return result;
    }

    void ClipboardGuardRuntime::scan(const ScanRequest& request)
    {
        if (m_stopRequested.load()) return;
        m_agentBasePath = request.agentBasePath;
        const auto processList = ks::process::EnumerateProcesses(ks::process::ProcessEnumStrategy::Auto);
        if (m_stopRequested.load()) return;
        std::unordered_map<quint32, QString> names;
        std::unordered_map<quint32, std::uint64_t> identities;
        for (const auto& process : processList)
        {
            if (m_stopRequested.load()) return;
            names.emplace(process.pid, QString::fromStdString(process.processName));
            identities.emplace(process.pid, process.creationTime100ns);
        }
        m_inbox->replaceNames(std::move(names));
        const auto selfPid = static_cast<std::uint32_t>(::GetCurrentProcessId());
        std::vector<std::uint32_t> matched;
        Summary result; result.ruleCount = request.rules.size();
        for (const auto& process : processList)
        {
            if (m_stopRequested.load()) return;
            if (process.pid == 0 || process.pid == 4 || process.pid == selfPid) continue;
            const auto* rule = findMatchingRuleIn(request.rules, process);
            if (!rule) continue;
            matched.push_back(process.pid);
            QString error;
            if (!ensureProcessProtected(process, *rule, &error))
            { ++result.failureCount; result.lastError = error; }
        }
        if (m_stopRequested.load()) return;
        std::vector<std::uint32_t> sessionPids;
        { std::lock_guard<std::mutex> lock(m_sessionsMutex); for (const auto& session : m_sessions) if (session) sessionPids.push_back(session->pid); }
        for (const auto pid : sessionPids)
        {
            if (m_stopRequested.load()) return;
            if (std::find(matched.begin(), matched.end(), pid) == matched.end()) teardownSession(pid);
        }
        {
            std::lock_guard<std::mutex> lock(m_inbox->mutex);
            for (auto it = m_inbox->residentAgentCreationTimes.begin(); it != m_inbox->residentAgentCreationTimes.end();)
            {
                const auto found = identities.find(it->first);
                it = found != identities.end() && found->second == it->second ? std::next(it) : m_inbox->residentAgentCreationTimes.erase(it);
            }
        }
        { std::lock_guard<std::mutex> lock(m_queueMutex); m_summary = std::move(result); }
    }

    void ClipboardGuardPage::refreshRuleTable()
    {
        if (m_ruleTable == nullptr)
        {
            return;
        }
        m_ruleTable->setRowCount(static_cast<int>(m_rules.size()));
        for (std::size_t rowIndex = 0; rowIndex < m_rules.size(); ++rowIndex)
        {
            const ClipboardGuardRule& ruleValue = m_rules[rowIndex];
            const int row = static_cast<int>(rowIndex);
            QString targetText;
            QString kindText;
            switch (ruleValue.targetKind)
            {
            case 1: targetText = QString::number(ruleValue.targetProcessId); kindText = QStringLiteral("PID"); break;
            case 2: targetText = ruleValue.targetImage; kindText = QStringLiteral("映像名"); break;
            case 3: targetText = ruleValue.targetImage; kindText = QStringLiteral("完整路径"); break;
            case 4: targetText = QStringLiteral("（全部进程）"); kindText = QStringLiteral("全局"); break;
            default: kindText = QStringLiteral("未设置"); break;
            }
            const auto actionText = [](const quint32 actionValue) {
                switch (actionValue)
                {
                case 1: return QStringLiteral("拦截");
                case 2: return QStringLiteral("仅记录");
                default: return QStringLiteral("允许");
                }
            };
            m_ruleTable->setItem(row, 0, createReadOnlyItem(targetText));
            m_ruleTable->setItem(row, 1, createReadOnlyItem(kindText));
            m_ruleTable->setItem(row, 2, createReadOnlyItem(ruleValue.ruleName));
            m_ruleTable->setItem(row, 3, createReadOnlyItem(actionText(ruleValue.readAction)));
            m_ruleTable->setItem(row, 4, createReadOnlyItem(actionText(ruleValue.writeAction)));
            m_ruleTable->setItem(row, 5, createReadOnlyItem(actionText(ruleValue.enumAction)));
            m_ruleTable->setItem(row, 6, createReadOnlyItem(ruleValue.enabled ? QStringLiteral("是") : QStringLiteral("否")));
        }

        // 复选框状态跟着规则表一起刷新，避免"手动删掉全局规则行"之后复选框
        // 还留在勾选状态这种两处状态各说各话的情况；阻塞信号防止这次同步
        // 反过来触发一次 toggleGlobalMonitor。
        if (m_globalMonitorCheck != nullptr)
        {
            const QSignalBlocker blocker(m_globalMonitorCheck);
            m_globalMonitorCheck->setChecked(hasEnabledGlobalRule());
        }
    }

    bool ClipboardGuardPage::hasEnabledGlobalRule() const
    {
        return std::any_of(m_rules.cbegin(), m_rules.cend(), [](const ClipboardGuardRule& ruleValue) {
            return ruleValue.enabled && ruleValue.targetKind == 4U;
        });
    }

    void ClipboardGuardPage::syncRulesToDriver()
    {
        std::vector<KSWORD_ARK_CLIPBOARD_POLICY_RULE> driverRules;
        driverRules.reserve(m_rules.size());
        for (const ClipboardGuardRule& ruleValue : m_rules)
        {
            KSWORD_ARK_CLIPBOARD_POLICY_RULE driverRule{};
            driverRule.ruleId = ruleValue.ruleId;
            driverRule.flags = ruleValue.enabled ? KSWORD_ARK_CLIPBOARD_POLICY_RULE_FLAG_ENABLED : 0UL;
            driverRule.targetKind = ruleValue.targetKind;
            driverRule.targetProcessId = ruleValue.targetProcessId;
            driverRule.readAction = ruleValue.readAction;
            driverRule.writeAction = ruleValue.writeAction;
            driverRule.enumAction = ruleValue.enumAction;
            const std::wstring targetImageText = ruleValue.targetImage.toStdWString();
            wcsncpy_s(driverRule.targetImage, targetImageText.c_str(), KSWORD_ARK_CLIPBOARD_POLICY_IMAGE_CHARS - 1U);
            const std::wstring ruleNameText = ruleValue.ruleName.toStdWString();
            wcsncpy_s(driverRule.ruleName, ruleNameText.c_str(), KSWORD_ARK_CLIPBOARD_POLICY_NAME_CHARS - 1U);
            driverRules.push_back(driverRule);
        }

        const ksword::ark::IoResult result = m_driverClient.setClipboardPolicy(
            KSWORD_ARK_CLIPBOARD_POLICY_FLAG_ENABLED, driverRules);
        if (!result.ok && m_statusLabel != nullptr)
        {
            m_statusLabel->setText(QStringLiteral("规则下发驱动失败：%1").arg(QString::fromStdString(result.message)));
        }
    }

    void ClipboardGuardPage::loadRulesFromDriver()
    {
        const ksword::ark::ClipboardPolicyStateResult result = m_driverClient.queryClipboardPolicyState();
        if (!result.io.ok)
        {
            if (m_statusLabel != nullptr)
            {
                m_statusLabel->setText(QStringLiteral("驱动策略回读失败：%1（可能驱动未加载，规则仍可在本页新增，下发时会再次报错）")
                    .arg(QString::fromStdString(result.io.message)));
            }
            return;
        }

        m_rules.clear();
        quint32 maxRuleId = 0;
        for (unsigned long ruleIndex = 0; ruleIndex < result.response.ruleCount; ++ruleIndex)
        {
            const KSWORD_ARK_CLIPBOARD_POLICY_RULE& driverRule = result.response.rules[ruleIndex];
            ClipboardGuardRule ruleValue;
            ruleValue.ruleId = driverRule.ruleId;
            ruleValue.enabled = (driverRule.flags & KSWORD_ARK_CLIPBOARD_POLICY_RULE_FLAG_ENABLED) != 0UL;
            ruleValue.targetKind = driverRule.targetKind;
            ruleValue.targetProcessId = driverRule.targetProcessId;
            ruleValue.targetImage = QString::fromWCharArray(driverRule.targetImage);
            ruleValue.ruleName = QString::fromWCharArray(driverRule.ruleName);
            ruleValue.readAction = driverRule.readAction;
            ruleValue.writeAction = driverRule.writeAction;
            ruleValue.enumAction = driverRule.enumAction;
            maxRuleId = std::max(maxRuleId, ruleValue.ruleId);
            m_rules.push_back(ruleValue);
        }
        m_nextLocalRuleId = maxRuleId + 1U;
        refreshRuleTable();
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(QStringLiteral("已从驱动加载 %1 条规则。").arg(m_rules.size()));
        }
    }

    const ClipboardGuardRule* ClipboardGuardRuntime::findMatchingRuleIn(
        const std::vector<ClipboardGuardRule>& rules, const ks::process::ProcessRecord& processRecord)
    {
        const QString imagePath = QString::fromStdString(processRecord.imagePath);
        const QString imageName = imagePath.isEmpty()
            ? QString::fromStdString(processRecord.processName)
            : QFileInfo(imagePath).fileName();
        // globalRulePointer：命中的全局规则先记下来，不立即返回——具体规则
        // （PID/映像名/路径）必须优先于全局规则，哪怕它在规则表里排在全局规则
        // 后面；这样"全局仅记录 + 对某个进程单独设拦截"才能按预期生效。
        const ClipboardGuardRule* globalRulePointer = nullptr;
        for (const ClipboardGuardRule& ruleValue : rules)
        {
            if (!ruleValue.enabled)
            {
                continue;
            }
            switch (ruleValue.targetKind)
            {
            case 1: // PID
                if (ruleValue.targetProcessId == processRecord.pid)
                {
                    return &ruleValue;
                }
                break;
            case 2: // IMAGE_NAME
                if (!imageName.isEmpty() && imageName.compare(ruleValue.targetImage, Qt::CaseInsensitive) == 0)
                {
                    return &ruleValue;
                }
                break;
            case 3: // IMAGE_PATH：允许规则写完整路径或去盘符的路径尾部，大小写不敏感后缀匹配。
                if (!imagePath.isEmpty() && !ruleValue.targetImage.isEmpty()
                    && imagePath.endsWith(ruleValue.targetImage, Qt::CaseInsensitive))
                {
                    return &ruleValue;
                }
                break;
            case 4: // ALL：全局监控，先记下来，等具体规则都查完了再决定用不用它。
                globalRulePointer = &ruleValue;
                break;
            default:
                break;
            }
        }
        return globalRulePointer;
    }

    bool ClipboardGuardRuntime::writeSessionConfigForPid(
        const std::uint32_t pid, const ClipboardGuardRule& matchedRule,
        const QString& sessionId, QString* const errorTextOut) const
    {
        std::wstring agentDllPath, platformError;
        if (!ks::winapi_monitor::resolveAgentPath(pid,
                m_agentBasePath.toStdWString(),
                &agentDllPath, &platformError))
        {
            if (errorTextOut) *errorTextOut = QStringLiteral("无法选择匹配目标进程位数的 Agent DLL：%1")
                .arg(QString::fromStdWString(platformError));
            return false;
        }

        const QString configPath = QString::fromStdWString(ks::winapi_monitor::buildConfigPathForPid(pid));
        std::wstring sessionError;
        if (!ks::winapi_monitor::addSessionDirectoryReader(pid, &sessionError))
        {
            if (errorTextOut) *errorTextOut = QStringLiteral("无法准备跨账户会话目录：%1")
                .arg(QString::fromStdWString(sessionError));
            return false;
        }
        if (!QDir().mkpath(QFileInfo(configPath).absolutePath()))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法创建会话目录：%1").arg(QFileInfo(configPath).absolutePath());
            }
            return false;
        }

        QSaveFile configFile(configPath);
        if (!configFile.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法写入会话配置：%1").arg(configPath);
            }
            return false;
        }

        const auto actionKeyword = [](const quint32 actionValue) {
            switch (actionValue)
            {
            case 1: return QStringLiteral("block");
            case 2: return QStringLiteral("log_only");
            default: return QStringLiteral("allow");
            }
        };

        QTextStream outputStream(&configFile);
        outputStream.setEncoding(QStringConverter::Utf16LE);
        outputStream.setGenerateByteOrderMark(true);
        outputStream << "[monitor]\n";
        outputStream << "pipe_name=" << QString::fromStdWString(ks::winapi_monitor::buildPipeNameForPid(pid)) << '\n';
        outputStream << "stop_flag_path=" << QString::fromStdWString(ks::winapi_monitor::buildStopFlagPathForPid(pid)) << '\n';
        outputStream << "session_id=" << sessionId << '\n';
        std::wstring controllerSid;
        if (!ks::winapi_monitor::currentProcessUserSidString(&controllerSid))
        {
            if (errorTextOut) *errorTextOut = QStringLiteral("无法读取当前控制端 SID。");
            return false;
        }
        outputStream << "controller_sid=" << QString::fromStdWString(controllerSid) << '\n';
        outputStream << "agent_dll_path=" << QDir::toNativeSeparators(QString::fromStdWString(agentDllPath)) << '\n';
        // 只开剪贴板分类，不随手把通用文件/注册表/网络/进程/加载器监控一起打开——
        // "剪贴板保护"和通用 API 监控是两个不同的使用场景，这里只要剪贴板这一份。
        outputStream << "enable_file=0\n";
        outputStream << "enable_registry=0\n";
        outputStream << "enable_network=0\n";
        outputStream << "enable_process=0\n";
        outputStream << "enable_memory=0\n";
        outputStream << "enable_thread=0\n";
        outputStream << "enable_service=0\n";
        outputStream << "enable_security=0\n";
        outputStream << "enable_crypto=0\n";
        outputStream << "enable_com=0\n";
        outputStream << "enable_window=0\n";
        outputStream << "enable_gui=0\n";
        outputStream << "enable_loader=0\n";
        outputStream << "enable_raw_fallback=0\n";
        outputStream << "fake_success_enabled=0\n";
        outputStream << "enable_clipboard=1\n";
        outputStream << "clipboard_read_action=" << actionKeyword(matchedRule.readAction) << '\n';
        outputStream << "clipboard_write_action=" << actionKeyword(matchedRule.writeAction) << '\n';
        outputStream << "clipboard_enum_action=" << actionKeyword(matchedRule.enumAction) << '\n';

        outputStream.flush();
        if (outputStream.status() != QTextStream::Ok || !configFile.commit())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("会话配置提交失败：%1").arg(configPath);
            }
            return false;
        }
        std::wstring aclError;
        if (!ks::winapi_monitor::grantSessionFileRead(configPath.toStdWString(), pid, &aclError))
        {
            if (errorTextOut) *errorTextOut = QStringLiteral("无法授予目标进程读取会话配置的权限：%1")
                .arg(QString::fromStdWString(aclError));
            return false;
        }
        // 新配置完整提交后再撤销上一次会话的停止标记；否则常驻 Agent
        // 在 WaitForNextSessionConfig 中会一直等待，无法重启同一 PID 的监控。
        const QString stopFlagPath = QString::fromStdWString(ks::winapi_monitor::buildStopFlagPathForPid(pid));
        if (QFile::exists(stopFlagPath) && !QFile::remove(stopFlagPath))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("会话配置已写入，但无法撤销停止标记：%1").arg(stopFlagPath);
            }
            return false;
        }
        return true;
    }

    bool ClipboardGuardRuntime::ensureProcessProtected(
        const ks::process::ProcessRecord& processRecord, const ClipboardGuardRule& matchedRule, QString* const errorTextOut)
    {
        if (m_stopRequested.load()) return false;
        std::uint64_t creationTime = 0;
        const std::unique_ptr<void, decltype(&::CloseHandle)> process(
            ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processRecord.pid), &::CloseHandle);
        if (process) creationTime = ks::winapi_monitor::processCreationIdentity(process.get());
        if (creationTime == 0 || (processRecord.creationTime100ns != 0
            && processRecord.creationTime100ns != creationTime))
        {
            if (errorTextOut) *errorTextOut = QString::number(ERROR_INVALID_PARAMETER);
            return false;
        }
        QString existingSessionId;
        bool actionsUnchanged = false;
        bool pipeThreadExited = false;
        bool identityChanged = false;
        {
            std::lock_guard<std::mutex> lock(m_sessionsMutex);
            for (const std::unique_ptr<Session>& sessionPointer : m_sessions)
            {
                if (sessionPointer != nullptr && sessionPointer->pid == processRecord.pid)
                {
                    identityChanged = sessionPointer->creationTime100ns != creationTime;
                    existingSessionId = sessionPointer->sessionId;
                    pipeThreadExited = sessionPointer->pipeThreadExited.load();
                    actionsUnchanged = sessionPointer->readAction == matchedRule.readAction
                        && sessionPointer->writeAction == matchedRule.writeAction
                        && sessionPointer->enumAction == matchedRule.enumAction;
                    break;
                }
            }
        }
        if (pipeThreadExited || identityChanged)
        {
            teardownSession(processRecord.pid);
            existingSessionId.clear();
        }
        if (!existingSessionId.isEmpty() && actionsUnchanged)
        {
            return true;
        }

        const bool newSession = existingSessionId.isEmpty();
        const QString sessionId = newSession
            ? QUuid::createUuid().toString(QUuid::WithoutBraces)
            : existingSessionId;

        ks::winapi_monitor::SessionLease lease;
        DWORD leaseError = 0;
        if (newSession && !lease.acquire(processRecord.pid, &leaseError))
        {
            if (errorTextOut) *errorTextOut = QStringLiteral("无法占用 PID=%1 的 Agent 会话（错误码 %2）；该进程可能已由 API 监控或剪贴板保护占用。")
                .arg(processRecord.pid).arg(leaseError);
            return false;
        }
        if (m_stopRequested.load()) return false;
        QString writeError;
        if (!writeSessionConfigForPid(processRecord.pid, matchedRule, sessionId, &writeError))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = writeError;
            }
            return false;
        }

        if (m_stopRequested.load())
        {
            writeStopFlag(processRecord.pid);
            return false;
        }
        if (newSession)
        {
            // 先启动管道客户端，再注入 Agent；它建立服务端后即可连接。
            try { startPipeReadThreadForPid(processRecord.pid, creationTime, sessionId, matchedRule, std::move(lease)); }
            catch (...) { writeStopFlag(processRecord.pid); teardownSession(processRecord.pid); throw; }
            if (m_stopRequested.load()) { teardownSession(processRecord.pid); return false; }
            bool reuseResidentAgent = false;
            {
                std::lock_guard<std::mutex> lock(m_inbox->mutex);
                const auto residentIt = m_inbox->residentAgentCreationTimes.find(processRecord.pid);
                reuseResidentAgent = residentIt != m_inbox->residentAgentCreationTimes.cend()
                    && residentIt->second == creationTime;
            }
            if (!reuseResidentAgent)
            {
                std::wstring agentDllPath, injectError;
                if (!ks::winapi_monitor::resolveAgentPath(processRecord.pid,
                        m_agentBasePath.toStdWString(),
                        &agentDllPath, &injectError)
                    || !ks::winapi_monitor::injectAgentNative(processRecord.pid, agentDllPath, &injectError, creationTime, nullptr))
                {
                    teardownSession(processRecord.pid);
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("注入 PID=%1 失败：%2")
                            .arg(processRecord.pid).arg(QString::fromStdWString(injectError));
                    }
                    return false;
                }
                {
                    std::lock_guard<std::mutex> lock(m_inbox->mutex);
                    m_inbox->residentAgentCreationTimes[processRecord.pid] = creationTime;
                }
            }
        }
        else
        {
            std::lock_guard<std::mutex> lock(m_sessionsMutex);
            for (const std::unique_ptr<Session>& sessionPointer : m_sessions)
            {
                if (sessionPointer != nullptr && sessionPointer->pid == processRecord.pid
                    && sessionPointer->sessionId == sessionId)
                {
                    sessionPointer->readAction = matchedRule.readAction;
                    sessionPointer->writeAction = matchedRule.writeAction;
                    sessionPointer->enumAction = matchedRule.enumAction;
                    break;
                }
            }
        }
        return true;
    }

    void ClipboardGuardRuntime::writeStopFlag(const std::uint32_t pid)
    {
        // 写停止标记，让 Agent 自己的 250ms 轮询发现后主动卸载 hook、退出会话。
        const QString stopFlagPath = QString::fromStdWString(ks::winapi_monitor::buildStopFlagPathForPid(pid));
        QFile stopFile(stopFlagPath);
        if (stopFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
        {
            stopFile.write("stop");
            stopFile.close();
            std::wstring aclError;
            (void)ks::winapi_monitor::grantSessionFileRead(stopFlagPath.toStdWString(), pid, &aclError);
        }

    }

    void ClipboardGuardRuntime::teardownSession(const std::uint32_t pid)
    {
        std::unique_ptr<Session> sessionPointer;
        {
            std::lock_guard<std::mutex> lock(m_sessionsMutex);
            const auto sessionIt = std::find_if(m_sessions.begin(), m_sessions.end(),
                [pid](const std::unique_ptr<Session>& candidate) { return candidate != nullptr && candidate->pid == pid; });
            if (sessionIt == m_sessions.end())
            {
                return;
            }
            sessionPointer = std::move(*sessionIt);
            m_sessions.erase(sessionIt);
        }

        writeStopFlag(pid);

        sessionPointer->stopFlag.store(true);
        if (sessionPointer->pipeThread != nullptr && sessionPointer->pipeThread->joinable())
        {
            // ReadFile 是由管道线程发起的同步 I/O；跨线程 CloseHandle 不能可靠
            // 取消它，还可能和读取线程的 CloseHandle 双重关闭同一个句柄。
            // 请求取消后由读取线程自己关闭管道句柄。
            ::CancelSynchronousIo(sessionPointer->pipeThread->native_handle());
            sessionPointer->pipeThread->join();
        }
        m_inbox->finishSessionDrops(ks::winapi_monitor::sessionIdentity(sessionPointer->sessionId.toStdWString()));
    }

    void ClipboardGuardRuntime::startPipeReadThreadForPid(
        const std::uint32_t pid, const std::uint64_t creationTime, const QString& sessionId, const ClipboardGuardRule& rule, ks::winapi_monitor::SessionLease lease)
    {
        auto sessionPointer = std::make_unique<Session>();
        sessionPointer->lease = std::move(lease);
        sessionPointer->pid = pid;
        sessionPointer->sessionId = sessionId;
        sessionPointer->creationTime100ns = creationTime;
        sessionPointer->readAction = rule.readAction;
        sessionPointer->writeAction = rule.writeAction;
        sessionPointer->enumAction = rule.enumAction;
        Session* const sessionRawPointer = sessionPointer.get();

        const QString pipeNameText = QString::fromStdWString(ks::winapi_monitor::buildPipeNameForPid(pid));
        const auto inbox = m_inbox;
        {
            std::lock_guard<std::mutex> lock(m_sessionsMutex);
            m_sessions.push_back(std::move(sessionPointer));
        }

        sessionRawPointer->pipeThread = std::make_unique<std::thread>([inbox, sessionRawPointer, pipeNameText, pid]() {
            HANDLE pipeHandle = INVALID_HANDLE_VALUE;
            for (int attempt = 0; attempt < 120; ++attempt)
            {
                if (sessionRawPointer->stopFlag.load())
                {
                    sessionRawPointer->pipeThreadExited.store(true);
                    return;
                }
                pipeHandle = ::CreateFileW(
                    reinterpret_cast<LPCWSTR>(pipeNameText.utf16()), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (pipeHandle != INVALID_HANDLE_VALUE)
                {
                    break;
                }
                const DWORD lastError = ::GetLastError();
                if (lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PIPE_BUSY)
                {
                    sessionRawPointer->pipeThreadExited.store(true);
                    return;
                }
                ::WaitNamedPipeW(reinterpret_cast<LPCWSTR>(pipeNameText.utf16()), 250);
                ::Sleep(120);
            }
            if (pipeHandle == INVALID_HANDLE_VALUE)
            {
                sessionRawPointer->pipeThreadExited.store(true);
                return;
            }

            sessionRawPointer->pipeHandleValue.store(reinterpret_cast<std::uintptr_t>(pipeHandle));

            while (!sessionRawPointer->stopFlag.load())
            {
                ks::winapi_monitor::ApiMonitorEventPacket packetValue{};
                if (!ks::winapi_monitor::readEventPacket(pipeHandle, &packetValue, sessionRawPointer->stopFlag))
                {
                    break;
                }
                if (packetValue.size != sizeof(packetValue) || packetValue.pid != pid
                    || packetValue.version != ks::winapi_monitor::kProtocolVersion)
                {
                    continue;
                }
                if (packetValue.eventKind != static_cast<std::uint32_t>(ks::winapi_monitor::EventKind::ApiCall)
                    || packetValue.sessionIdentity != ks::winapi_monitor::sessionIdentity(sessionRawPointer->sessionId.toStdWString())) continue;
                if (packetValue.category == static_cast<std::uint32_t>(ks::winapi_monitor::EventCategory::Internal))
                {
                    // 管道连上后 Agent 还要安装 Hook；只有收到确认事件，
                    // 页面才能把该进程计入“当前受保护进程”。
                    if (wideBufferToText(packetValue.apiName) == QStringLiteral("HooksInstalled"))
                    {
                        sessionRawPointer->hooksInstalled.store(true);
                    }
                    else if (wideBufferToText(packetValue.apiName) == QStringLiteral("EventsDropped"))
                    {
                        bool ok = false;
                        const auto count = wideBufferToText(packetValue.detailText).toULongLong(&ok);
                        if (ok) inbox->noteAgentDropped(packetValue.sessionIdentity, count);
                    }
                    continue;
                }
                // 只关心剪贴板分类；本会话的 INI 已经只开了这一类，这里再过滤一层双保险。
                if (packetValue.category != static_cast<std::uint32_t>(ks::winapi_monitor::EventCategory::Clipboard))
                {
                    continue;
                }

                inbox->push(packetToEventRow(packetValue, inbox->processName(pid)));
            }

            const std::uintptr_t storedHandleValue = sessionRawPointer->pipeHandleValue.exchange(0);
            if (storedHandleValue != 0)
            {
                ::CloseHandle(reinterpret_cast<HANDLE>(storedHandleValue));
            }
            sessionRawPointer->hooksInstalled.store(false);
            sessionRawPointer->pipeThreadExited.store(true);
        });

    }

    void ClipboardGuardPage::scheduleEventProjection()
    {
        if (m_projectionScheduled || !isVisible()) return;
        m_projectionScheduled = true;
        QTimer::singleShot(0, this, [this]()
        {
            m_projectionScheduled = false;
            flushPendingRows();
        });
    }

    void ClipboardGuardPage::flushPendingRows()
    {
        // Sampling, matching and native protection continue while hidden. Only
        // item construction/painting is demand-driven; the existing inbox owns
        // every accepted row until projected or explicitly counted as evicted.
        if (!m_eventTable || !isVisible() || !m_eventTable->isVisible()) return;
        const QPointer<ClipboardGuardPage> self(this);
        if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(this,
                QStringLiteral("clipboard_guard_events"), { m_eventTable },
                [self]() { if (self) self->flushPendingRows(); })) return;

        QElapsedTimer budget;
        budget.start();
        if (m_projectionRows.empty())
        {
            auto rows = m_inbox->take(kUiFlushRowLimit);
            for (auto& row : rows) m_projectionRows.push_back(std::move(row));
        }
        if (m_projectionRows.empty()) { updateRuntimeStatus(); return; }

        auto* const scrollbar = m_eventTable->verticalScrollBar();
        const bool followTail = scrollbar && scrollbar->value() >= scrollbar->maximum() - 1;
        const bool updatesEnabled = m_eventTable->updatesEnabled();
        const bool sortingEnabled = m_eventTable->isSortingEnabled();
        m_eventTable->setUpdatesEnabled(false);
        // A whole row is installed before sorting can relocate it; item roles,
        // selection and the identity used by quick rules/call-stack stay aligned.
        if (sortingEnabled) m_eventTable->setSortingEnabled(false);
        std::size_t projected = 0;
        while (!m_projectionRows.empty() && projected < kUiFlushRowLimit
            && (projected == 0 || budget.elapsed() < kProjectionBudgetMs))
        {
            appendEventRow(m_projectionRows.front());
            m_projectionRows.pop_front();
            ++projected;
        }
        trimRetainedEventRows();
        if (sortingEnabled) m_eventTable->setSortingEnabled(true);
        m_eventTable->setUpdatesEnabled(updatesEnabled);
        if (followTail) m_eventTable->scrollToBottom();
        updateRuntimeStatus();
        if (!m_projectionRows.empty() || m_inbox->counts().pending != 0)
            scheduleEventProjection();
    }

    void ClipboardGuardPage::trimRetainedEventRows()
    {
        const int excess = m_eventTable->rowCount() - kRetainedEventRows;
        if (excess <= 0) return;
        std::vector<int> removeRows;
        removeRows.reserve(static_cast<std::size_t>(excess));
        for (int i = 0; i < excess; ++i)
        {
            removeRows.push_back(m_retainedEventAnchors.front()->row());
            m_retainedEventAnchors.pop_front();
        }
        // Retain the latest arrivals even under a user sort. Delete descending
        // contiguous spans to keep the other anchor pointers and selection valid.
        std::sort(removeRows.begin(), removeRows.end(), std::greater<int>());
        for (std::size_t i = 0; i < removeRows.size();)
        {
            const int last = removeRows[i];
            int first = last;
            while (++i < removeRows.size() && removeRows[i] == first - 1) --first;
            m_eventTable->model()->removeRows(first, last - first + 1);
            m_evictedRows += static_cast<std::uint64_t>(last - first + 1);
        }
    }

    void ClipboardGuardPage::appendEventRow(const ClipboardGuardEventRow& rowValue)
    {
        const int row = m_eventTable->rowCount();
        m_eventTable->insertRow(row);
        auto* const timeItem = createReadOnlyItem(rowValue.timeText);
        m_eventTable->setItem(row, ColumnTime, timeItem);
        m_retainedEventAnchors.push_back(timeItem);
        m_eventTable->setItem(row, ColumnProcess, createReadOnlyItem(rowValue.processText));
        m_eventTable->setItem(row, ColumnPid, createReadOnlyItem(QString::number(rowValue.pid)));
        m_eventTable->setItem(row, ColumnOperation, createReadOnlyItem(rowValue.operationText));
        m_eventTable->setItem(row, ColumnFormat, createReadOnlyItem(rowValue.formatText));
        QTableWidgetItem* const resultItem = createReadOnlyItem(rowValue.resultText);
        if (rowValue.resultText == QStringLiteral("Blocked"))
        {
            resultItem->setForeground(QBrush(KswordTheme::ErrorColor()));
        }
        m_eventTable->setItem(row, ColumnResult, resultItem);
        m_eventTable->setItem(row, ColumnTid, createReadOnlyItem(QString::number(rowValue.tid)));
        m_eventTable->setItem(row, ColumnSession, createReadOnlyItem(rowValue.sessionText));
        m_eventTable->setItem(row, ColumnIntegrity, createReadOnlyItem(rowValue.integrityText));
        m_eventTable->setItem(row, ColumnOwner, createReadOnlyItem(rowValue.ownerText));
        QTableWidgetItem* const seqItem = createReadOnlyItem(QString::number(rowValue.seq));
        seqItem->setData(Qt::UserRole, static_cast<qulonglong>(rowValue.seq));
        m_eventTable->setItem(row, ColumnSeq, seqItem);
        m_eventTable->item(row, ColumnPid)->setData(Qt::UserRole, rowValue.pid);
    }

    void ClipboardGuardPage::updateRuntimeStatus()
    {
        if (!isVisible() || !m_runtime || !m_runtime->hasStarted() || !m_statusLabel) return;
        if (m_statusUpdateClock.isValid() && m_statusUpdateClock.elapsed() < 200) return;
        m_statusUpdateClock.start();
        const auto value = m_runtime->summary();
        const auto counts = m_inbox->counts();
        QString text = ks::i18n::sourceText(QStringLiteral("规则 %1 条，当前受保护进程 %2 个。"))
            .arg(value.ruleCount).arg(value.protectedCount);
        if (value.failureCount > 0)
            text += ks::i18n::sourceText(QStringLiteral(" 有 %1 个进程处理失败，最后一次错误：%2"))
                .arg(value.failureCount).arg(value.lastError);
        text += ks::i18n::sourceText(QStringLiteral(" | Agent 丢失=%1，UI 丢失=%2，已移出表格=%3，待显示=%4"))
            .arg(counts.agentDropped).arg(counts.dropped).arg(m_evictedRows)
            .arg(counts.pending + m_projectionRows.size());
        if (m_statusLabel->text() != text) m_statusLabel->setText(text);
    }

    void ClipboardGuardPage::refreshProcessListAndSessionsAsync()
    {
        if (m_runtime->hasFinished()) m_runtime = std::make_shared<ClipboardGuardRuntime>(m_inbox);
        (void)m_runtime->requestScan(m_rules,
            QCoreApplication::applicationDirPath() + QStringLiteral("/APIMonitor_x64.dll"));
        updateRuntimeStatus();
    }
}
