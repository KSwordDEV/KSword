#include "ProcessDetailWindow.InternalCommon.h"
#include "../UI/TableContextMenu.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/DetailDialogChrome.h"
#include "../UI/X64DbgNavigation.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/MetricAreaWindow.h"
#include "../MemoryDock/MemoryDock.h"
#include <Shellapi.h>
#include <QSet>

using namespace process_detail_window_internal;

// ============================================================
// ProcessDetailWindow.Module.cpp
// 作用：
// - 负责模块页异步刷新、模块表构建、模块右键动作执行。
// - 聚焦“模块信息与模块相关动作”逻辑。
// ============================================================

// 显式析构第一步关闭请求门禁，随后才销毁派生页面缓存与控件成员。
ProcessDetailWindow::~ProcessDetailWindow()
{
    if (m_detailActionOperation) m_detailActionOperation->close();
    if (m_kernelFieldWatchOperation) m_kernelFieldWatchOperation->close();
    if (m_moduleOperation)
    {
        m_moduleOperation->close();
    }
}

void ProcessDetailWindow::requestAsyncModuleRefresh(const bool forceRefresh)
{
    // 自动首刷不重复排队；用户强制刷新保留最新参数，取代旧请求结果。
    if (!m_moduleOperation)
    {
        m_moduleOperation = std::make_unique<ks::ui::AsyncOperation>(this);
        m_moduleOperation->setStateChangedCallback([this]()
        {
            m_moduleRefreshing = m_moduleOperation->isBusy();
            if (m_moduleRefreshing && !m_firstModuleRefreshDone && m_moduleRefreshProgressPid > 0)
            {
                kPro.set(m_moduleRefreshProgressPid, "开始读取模块快照...", 10, 0.10f);
            }
        });
    }
    if (!forceRefresh && m_moduleOperation->isBusy())
    {
        return;
    }
    m_moduleInitialRefreshStarted = true;

    // 请求值只包含后端身份和选项，线程池不得读取页面成员或 QObject 守卫。
    struct ModuleRequest
    {
        std::uint32_t processId = 0; // 本轮进程 PID。
        std::uint64_t creationTime = 0; // 防 PID 复用的进程创建时间。
        bool includeSignature = false; // 本轮签名检查选项快照。
    };
    const ModuleRequest request{ m_baseRecord.pid, m_baseRecord.creationTime100ns,
        m_signatureCheckBox != nullptr && m_signatureCheckBox->isChecked() };
    const bool firstRefresh = !m_firstModuleRefreshDone; // 首轮才展示全局有限进度。
    if (firstRefresh && m_moduleRefreshProgressPid <= 0)
    {
        m_moduleRefreshProgressPid = kPro.addReusable(this,
            "模块列表首次刷新", "准备读取模块与线程信息...");
    }
    const int progressPid = firstRefresh ? m_moduleRefreshProgressPid : 0; // 值化收尾资源。
    updateModuleStatusLabel("● 正在刷新模块列表...", true);

    // 刷新开始日志：记录本轮身份、选项和触发来源，区分自动首刷与用户强制刷新。
    kLogEvent moduleRefreshStartEvent;
    info << moduleRefreshStartEvent
        << "[ProcessDetailWindow] 模块刷新开始, pid=" << request.processId
        << ", creationTime100ns=" << request.creationTime
        << ", includeSignature=" << (request.includeSignature ? "true" : "false")
        << ", forceRefresh=" << (forceRefresh ? "true" : "false")
        << ", firstRefresh=" << (firstRefresh ? "true" : "false")
        << eol;

    m_moduleRefreshTicket = m_moduleOperation->submit<ModuleRequest, std::shared_ptr<const ModuleRefreshResult>>(request,
        [](const ModuleRequest& snapshot, const ks::ui::AsyncOperationToken& token)
        {
            const auto startTime = std::chrono::steady_clock::now(); // 查询耗时基准。
            auto result = std::make_shared<ModuleRefreshResult>(); // 后台按值结果，不含任何页面地址。
            result->includeSignatureCheck = snapshot.includeSignature;
            if (!token.isCanceled())
            {
                result->moduleSnapshot = ks::process::EnumerateProcessModulesAndThreadsIfIdentityMatches(
                    snapshot.processId, snapshot.creationTime, snapshot.includeSignature);
            }
            auto rows = std::shared_ptr<std::vector<ModuleRowValue>>(new std::vector<ModuleRowValue>,
                [](std::vector<ModuleRowValue>* obsolete) noexcept
                {
                    // A stale/closed AsyncOperation result may die on the GUI thread.
                    // Own the allocation in its queued disposer as well as on execution.
                    try
                    {
                        auto retired = std::unique_ptr<std::vector<ModuleRowValue>>(obsolete);
                        auto task = std::unique_ptr<QRunnable>(QRunnable::create([retired = std::move(retired)] {}));
                        QThreadPool::globalInstance()->start(task.get());
                        task.release();
                    }
                    catch (...) {} // Allocation failure retains ordinary RAII cleanup.
                });
            struct ShellComScope
            {
                HRESULT status = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
                ~ShellComScope() { if (SUCCEEDED(status)) ::CoUninitialize(); }
                bool usable() const { return SUCCEEDED(status) || status == RPC_E_CHANGED_MODE; }
            } shellCom;
            struct ShellIconOwner
            {
                HICON value = nullptr;
                ~ShellIconOwner() { if (value) ::DestroyIcon(value); }
            };
            rows->reserve(result->moduleSnapshot.modules.size());
            for (auto& record : result->moduleSnapshot.modules)
            {
                QImage image;
                if (!token.isCanceled() && shellCom.usable() && !record.modulePath.empty())
                {
                    const QString path = QString::fromStdString(record.modulePath);
                    SHFILEINFOW shellInfo{};
                    const auto queried = ::SHGetFileInfoW(reinterpret_cast<LPCWSTR>(path.utf16()), 0,
                        &shellInfo, sizeof(shellInfo), SHGFI_ICON | SHGFI_SMALLICON);
                    const ShellIconOwner icon{shellInfo.hIcon};
                    if (queried != 0 && icon.value != nullptr) image = QImage::fromHICON(icon.value);
                }
                rows->push_back(ModuleRowValue{std::move(record), std::move(image)});
            }
            result->moduleCount = rows->size();
            result->threadCount = result->moduleSnapshot.threads.size();
            decltype(result->moduleSnapshot.modules){}.swap(result->moduleSnapshot.modules);
            decltype(result->moduleSnapshot.threads){}.swap(result->moduleSnapshot.threads);
            result->moduleRows = std::move(rows);
            result->elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - startTime).count());
            return std::shared_ptr<const ModuleRefreshResult>(std::move(result));
        },
        [this, request](const std::shared_ptr<const ModuleRefreshResult>& result, const std::uint64_t ticket)
        {
            return tryApplyModuleRefreshResult(ticket, request.processId, request.creationTime, result);
        },
        [this](const std::exception_ptr exception)
        {
            // 异常回调补写完整原因，避免异步 worker 失败只剩固定 UI 文案。
            std::string detail = "unknown exception";
            if (exception != nullptr)
            {
                try
                {
                    std::rethrow_exception(exception);
                }
                catch (const std::exception& error)
                {
                    detail = error.what();
                }
                catch (...)
                {
                    detail = "non-standard exception";
                }
            }
            kLogEvent errorEvent;
            err << errorEvent
                << "[ProcessDetailWindow] module refresh worker failed, pid="
                << m_baseRecord.pid << ", creationTime100ns=" << m_baseRecord.creationTime100ns
                << ", detail=" << detail << eol;
            updateModuleStatusLabel(QStringLiteral("● 模块刷新失败。"), false);
            if (m_moduleStatusLabel != nullptr)
            {
                m_moduleStatusLabel->setStyleSheet(buildStateLabelStyle(statusErrorColor(), 700));
            }
        },
        [progressPid](const ks::ui::AsyncOperationOutcome outcome)
        {
            // 成功/取消/页面关闭/丢队列共享一次收尾，不从 worker 读取页面 PID。
            if (progressPid > 0)
            {
                kPro.set(progressPid, outcome == ks::ui::AsyncOperationOutcome::Applied
                    ? "模块首次刷新完成" : "模块刷新已结束", 100, 1.0f);
            }
        });
}

bool ProcessDetailWindow::tryApplyModuleRefreshResult(const std::uint64_t ticket,
    const std::uint32_t processId, const std::uint64_t creationTime,
    const std::shared_ptr<const ModuleRefreshResult>& refreshResult)
{
    // 菜单延期回调可能在新请求后重放，不能仅依赖第一次收到结果时的验证。
    if (!m_moduleOperation || !m_moduleOperation->isCurrent(ticket)
        || m_baseRecord.pid != processId || m_baseRecord.creationTime100ns != creationTime)
    {
        return true;
    }
    if (ks::ui::IsItemViewUiCommitBlockedByContextMenu({ m_moduleTable }))
    {
        const auto snapshot = refreshResult; // 值结果。
        const QPointer<ProcessDetailWindow> safeThis(this); // 只在 UI 延期回调读取。
        if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(this,
            QStringLiteral("process-detail-module-snapshot"), { m_moduleTable },
            [safeThis, ticket, processId, creationTime, snapshot]()
            {
                if (!safeThis.isNull()
                    && safeThis->tryApplyModuleRefreshResult(ticket, processId, creationTime, snapshot))
                {
                    safeThis->m_moduleOperation->completeDeferred(ticket);
                }
            }))
        {
            return false;
        }
    }
    applyModuleRefreshResult(refreshResult);
    return false; // Completion belongs to the final visible immutable projection.
}

void ProcessDetailWindow::applyModuleRefreshResult(const std::shared_ptr<const ModuleRefreshResult>& refreshResult)
{
    // 模块刷新结果应用日志：输出模块数、线程数和耗时。
    kLogEvent applyModuleResultEvent;
    info << applyModuleResultEvent
        << "[ProcessDetailWindow] applyModuleRefreshResult: modules="
        << (refreshResult->moduleRows ? refreshResult->moduleRows->size() : 0U)
        << ", threads="
        << refreshResult->moduleSnapshot.threads.size()
        << ", elapsedMs="
        << refreshResult->elapsedMs
        << eol;

    m_moduleRecords = refreshResult->moduleRows;
    const QPointer<ProcessDetailWindow> alive(this);
    const auto ticket = m_moduleRefreshTicket;
    ModuleRefreshResult summary = *refreshResult;
    summary.moduleRows.reset();
    m_moduleTable->sourceReady = [alive, summary = std::move(summary), ticket]
    {
        if (!alive || !alive->m_moduleRefreshing || !alive->m_moduleOperation || !alive->m_moduleOperation->isCurrent(ticket)) return;
        alive->finishModuleRefreshPresentation(summary);
        if (alive && alive->m_moduleOperation) alive->m_moduleOperation->completeDeferred(ticket);
    };
    m_moduleTable->preparationFailed = [alive, ticket](const QString& error)
    {
        if (!alive || !alive->m_moduleOperation || !alive->m_moduleOperation->isCurrent(ticket)) return;

        // 表格投影失败日志：保留后台准备阶段返回的原始错误，区分枚举失败和前端投影失败。
        kLogEvent preparationFailedEvent;
        err << preparationFailedEvent
            << "[ProcessDetailWindow] module table preparation failed, pid="
            << alive->m_baseRecord.pid
            << ", creationTime100ns=" << alive->m_baseRecord.creationTime100ns
            << ", ticket=" << ticket
            << ", moduleRows=" << (alive->m_moduleRecords ? alive->m_moduleRecords->size() : 0U)
            << ", detail=" << error.toStdString()
            << eol;
        alive->updateModuleStatusLabel(QStringLiteral("● 模块刷新失败。"), false);
        if (alive->m_moduleStatusLabel != nullptr)
        {
            alive->m_moduleStatusLabel->setStyleSheet(buildStateLabelStyle(statusErrorColor(), 700));
        }
        if (alive && alive->m_moduleOperation) alive->m_moduleOperation->completeDeferred(ticket);
    };
    rebuildModuleTable();
}

void ProcessDetailWindow::finishModuleRefreshPresentation(
    const ModuleRefreshResult& refreshResult)
{
    const QString diagnosticText = QString::fromStdString(refreshResult.moduleSnapshot.diagnosticText);

    // 更新状态标签：显示耗时、模块数量与线程数量。
    QString statusText = QString("● 刷新完成 %1 ms | 模块:%2 线程:%3")
        .arg(refreshResult.elapsedMs)
        .arg(refreshResult.moduleCount)
        .arg(refreshResult.threadCount);
    if (!diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(
            " | 存在诊断；详情已写入日志。");
    }
    updateModuleStatusLabel(statusText, false);
    if (refreshResult.moduleCount == 0U)
    {
        m_moduleStatusLabel->setStyleSheet(buildStateLabelStyle(statusErrorColor(), 700));
    }

    // 首次刷新结束后隐藏对应进度任务卡片。
    if (!m_firstModuleRefreshDone)
    {
        m_firstModuleRefreshDone = true;
    }

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDetailWindow] 模块刷新完成, pid=" << m_baseRecord.pid
        << ", elapsedMs=" << refreshResult.elapsedMs
        << ", moduleCount=" << refreshResult.moduleCount
        << ", threadCount=" << refreshResult.threadCount
        << ", includeSignature=" << (refreshResult.includeSignatureCheck ? "true" : "false")
        << ", diagnostic=" << refreshResult.moduleSnapshot.diagnosticText
        << eol;

    // 两种枚举后端均未取得模块时输出错误级别和完整诊断，避免 warn 过滤掩盖失败。
    if (refreshResult.moduleCount == 0U)
    {
        kLogEvent errorEvent;
        err << errorEvent
            << "[ProcessDetailWindow] R3/R0 module enumeration produced no modules, pid=" << m_baseRecord.pid
            << ", moduleCount=" << refreshResult.moduleCount
            << ", diagnostic=" << refreshResult.moduleSnapshot.diagnosticText
            << eol;
    }
}

void ProcessDetailWindow::rebuildModuleTable()
{
    if (m_moduleTable == nullptr) return;
    const auto rows = m_moduleRecords;
    const QColor trusted = signatureTrustedColor();
    const QColor secondary = statusSecondaryColor();
    const QColor untrusted = signatureUntrustedColor();
    const QIcon placeholder(QStringLiteral(":/Icon/process_main.svg"));
    m_moduleTable->setSourceFactory([rows, trusted, secondary, untrusted, placeholder](const ks::i18n::SourceTextSnapshot& translator)
    {
        QVector<ks::ui::ImmutableTableRow> values;
        QSet<QString> usedKeys; // 已发布的行键集合，用于保证不可变数据源的身份唯一。
        int keyCollisionCount = 0; // 本轮因重复身份而补齐的行数。
        if (rows) values.reserve(static_cast<qsizetype>(rows->size()));
        if (rows) for (const auto& value : *rows)
        {
            const auto& record = value.record;
            const QString path = QString::fromStdString(record.modulePath);
            const double kb = static_cast<double>(record.moduleSizeBytes) / 1024.0;
            const QString size = kb < 1024.0 ? QStringLiteral("%1 KB").arg(QString::number(kb, 'f', 1))
                : QStringLiteral("%1 MB").arg(QString::number(kb / 1024.0, 'f', 2));
            ks::ui::ImmutableTableRow row;
            const QString baseKey = QString::number(record.moduleBaseAddress) + QChar('|') + path;
            row.key = baseKey;
            if (usedKeys.contains(row.key))
            {
                // R0 映像映射或异常枚举可能出现重复基址/路径，不能丢弃整张表。
                ++keyCollisionCount;
                int duplicateIndex = 1;
                do
                {
                    row.key = baseKey + QStringLiteral("|duplicate=") + QString::number(duplicateIndex++);
                } while (usedKeys.contains(row.key));
            }
            usedKeys.insert(row.key);
            row.cells = {path, size, translator.sourceText(QString::fromStdString(record.signatureState)),
                (QStringLiteral("0x") + QString::number(record.entryPointRva, 16).toUpper()),
                translator.sourceText(QString::fromStdString(record.runningState)), QString::fromStdString(record.threadIdText)};
            row.roles.insert(Qt::UserRole, path);
            row.roles.insert(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(record.moduleBaseAddress));
            row.roles.insert(Qt::UserRole + 2, QVariant::fromValue(record.representativeThreadId));
            row.roles.insert(Qt::UserRole + 3, QVariant::fromValue<qulonglong>(record.moduleSizeBytes));
            row.columnRoles[toModuleColumnIndex(ModuleColumn::ThreadId)].insert(Qt::ToolTipRole,
                translator.sourceText(QStringLiteral("%1\n仅列出启动地址位于该模块内的线程，不代表当前执行位置。? 表示部分线程的启动地址无法查询。"))
                    .arg(QString::fromStdString(record.threadIdText)));
            row.roles.insert(Qt::DecorationRole, value.icon.isNull() ? QVariant(placeholder) : QVariant(value.icon));
            row.columnRoles[toModuleColumnIndex(ModuleColumn::Signature)].insert(Qt::ForegroundRole,
                record.signatureTrusted ? trusted : (record.signatureState == "Pending" || record.signatureState == "Unknown") ? secondary : untrusted);
            values.push_back(std::move(row));
        }
        if (keyCollisionCount > 0)
        {
            // 记录数据身份修复次数，便于确认枚举结果是否包含重复映射。
            kLogEvent keyCollisionEvent;
            warn << keyCollisionEvent
                << "[ProcessDetailWindow] module table row keys normalized, count="
                << keyCollisionCount
                << eol;
        }
        return ks::ui::MakeImmutableTableSource(std::move(values));
    });
    filterModuleTable(m_moduleFilterEdit != nullptr ? m_moduleFilterEdit->text() : QString());
}

void ProcessDetailWindow::filterModuleTable(const QString& filterText)
{
    if (m_moduleTable != nullptr) m_moduleTable->setQuery(filterText.trimmed());
}

void ProcessDetailWindow::openModuleAreaWindow()
{
    if (!m_moduleAreaWindow)
    {
        auto* window = new ks::ui::MetricAreaWindow(this);
        m_moduleAreaWindow = window;
        window->itemActivated = [this](const QString& key) {
            if (!m_moduleTable) return;
            for (int row = 0; row < m_moduleTable->rowCount(); ++row)
                if (m_moduleTable->rowKey(row) == key) { m_moduleTable->selectKey(key); break; }
        };
        window->appearanceChanged = [this] { refreshModuleAreaWindow(); };
    }
    refreshModuleAreaWindow();
    m_moduleAreaWindow->show(); m_moduleAreaWindow->raise(); m_moduleAreaWindow->activateWindow();
}

void ProcessDetailWindow::refreshModuleAreaWindow()
{
    if (!m_moduleAreaWindow || !m_moduleTable) return;
    m_moduleAreaWindow->setSubject(ks::i18n::sourceText(QStringLiteral("全部模块")),
        ks::i18n::sourceText(QStringLiteral("模块")),
        ks::i18n::sourceText(QStringLiteral("模块基址")),
        ks::i18n::sourceText(QStringLiteral("面积表示模块虚拟映像大小；点击矩形可选中原列表中的模块。")));
    std::vector<ks::ui::MetricAreaNode> nodes;
    nodes.reserve(static_cast<std::size_t>(m_moduleTable->rowCount()));
    for (int row = 0; row < m_moduleTable->rowCount(); ++row)
    {
        const QString path = m_moduleTable->cell(row, 0, Qt::UserRole).toString();
        const auto rawSize = m_moduleTable->cell(row, 0, Qt::UserRole + 3);
        ks::ui::MetricAreaNode node;
        node.key = m_moduleTable->rowKey(row);
        node.name = QFileInfo(path).fileName();
        node.identity = QStringLiteral("0x%1").arg(m_moduleTable->cell(row, 0, Qt::UserRole + 1).toULongLong(), 0, 16).toUpper();
        node.known = rawSize.isValid(); node.weight = rawSize.toDouble();
        node.value = m_moduleTable->cell(row, toModuleColumnIndex(ModuleColumn::Size)).toString();
        node.icon = qvariant_cast<QIcon>(m_moduleTable->cell(row, 0, Qt::DecorationRole));
        node.tooltip = path + QLatin1Char('\n') + node.identity + QLatin1Char('\n') + node.value;
        nodes.push_back(std::move(node));
    }
    m_moduleAreaWindow->setPresentation(ks::i18n::sourceText(QStringLiteral("模块映像大小")),
        ks::i18n::sourceText(QStringLiteral("来自当前筛选后的已提交模块列表；虚拟映像大小不代表实际驻留内存。")), std::move(nodes));
}

void ProcessDetailWindow::updateModuleStatusLabel(const QString& statusText, const bool refreshing)
{
    if (m_moduleStatusLabel == nullptr)
    {
        return;
    }

    // Theme/language refresh passes the already rendered label back here.
    // Keep its base status separate so the action receipt is appended once.
    if (m_moduleRefreshStatusText.isEmpty() || statusText != m_moduleStatusLabel->text())
        m_moduleRefreshStatusText = statusText;
    QString rendered = m_moduleRefreshStatusText;
    if (m_moduleActionFeedback)
    {
        const auto& feedback = *m_moduleActionFeedback;
        QString target = ks::i18n::sourceText(QStringLiteral("PID=%1；模块 %2；基址 %3"))
            .arg(feedback.processId).arg(QString::fromStdString(feedback.module.modulePath),
                formatHexText(feedback.module.moduleBaseAddress));
        if (feedback.threadAction)
            target += ks::i18n::sourceText(QStringLiteral("；代表线程 TID=%1"))
                .arg(feedback.module.representativeThreadId);
        const QString detail = feedback.detailText.isEmpty()
            ? ks::i18n::sourceText(QStringLiteral("无附加信息"))
            : ks::i18n::LanguageManager::instance().displayText(feedback.detailText);
        rendered += QLatin1Char('\n') + ks::i18n::sourceText(QStringLiteral("最近操作 %1：%2；%3\n%4"))
            .arg(ks::i18n::sourceText(feedback.titleSource),
                ks::i18n::sourceText(feedback.ok ? QStringLiteral("成功") : QStringLiteral("失败")), target, detail);
        if (!feedback.ok)
            rendered += QLatin1Char('\n') + ks::i18n::sourceText(QStringLiteral("可刷新模块列表，核对目标后重试。"));
    }
    m_moduleStatusLabel->setTextFormat(Qt::PlainText);
    m_moduleStatusLabel->setText(rendered);
    m_moduleStatusLabel->setToolTip(rendered);

    // 状态标签更新日志：输出文本与刷新状态。
    kLogEvent moduleStatusEvent;
    dbg << moduleStatusEvent
        << "[ProcessDetailWindow] updateModuleStatusLabel: refreshing="
        << (refreshing ? "true" : "false")
        << ", statusText="
        << statusText.toStdString()
        << eol;

    if (m_moduleActionFeedback && !m_moduleActionFeedback->ok)
    {
        m_moduleStatusLabel->setStyleSheet(buildStateLabelStyle(statusErrorColor(), 700));
    }
    else if (refreshing)
    {
        m_moduleStatusLabel->setStyleSheet(buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700));
    }
    else if (statusText.contains(QStringLiteral("失败"))
        || statusText.contains(QStringLiteral("failed"), Qt::CaseInsensitive))
    {
        m_moduleStatusLabel->setStyleSheet(buildStateLabelStyle(statusErrorColor(), 700));
    }
    else
    {
        m_moduleStatusLabel->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
    }
}

void ProcessDetailWindow::reportModuleActionResult(const QString& titleSource,
    const ks::process::ProcessModuleRecord& module, const std::uint32_t processId,
    const bool actionOk, const std::string& detailText, const kLogEvent& actionEvent,
    const bool threadAction)
{
    if (m_moduleStatusLabel && m_moduleRefreshStatusText.isEmpty())
        m_moduleRefreshStatusText = m_moduleStatusLabel->text();
    m_moduleActionFeedback = std::make_unique<ModuleActionFeedback>(ModuleActionFeedback{
        titleSource, QString::fromStdString(detailText), module, processId, actionOk, threadAction});
    updateModuleStatusLabel(m_moduleRefreshStatusText, m_moduleRefreshing);
    // Keep the existing privilege-recovery and logging behavior local to this
    // module action; other detail pages keep their existing feedback contract.
    showActionResultMessage(ks::i18n::sourceText(titleSource), actionOk, detailText, actionEvent);
}

void ProcessDetailWindow::showModuleContextMenu(const QPoint& localPosition)
{
    // 右键菜单入口日志：记录点击位置。
    kLogEvent moduleContextMenuEvent;
    dbg << moduleContextMenuEvent
        << "[ProcessDetailWindow] showModuleContextMenu: x="
        << localPosition.x()
        << ", y="
        << localPosition.y()
        << eol;

    const QModelIndex clickedItem = m_moduleTable->indexAt(localPosition);
    if (!clickedItem.isValid())
    {
        return;
    }
    m_moduleTable->setCurrentIndex(clickedItem);

    // 嵌套菜单期间异步刷新可能回填；新动作只使用菜单打开时的模块与进程实例。
    const auto* selectedModule = selectedModuleRecord(); // 当前源行映射后的模块。
    if (selectedModule == nullptr)
    {
        return;
    }
    const auto module = *selectedModule; // 不跨菜单保存缓存指针。
    const auto processId = m_baseRecord.pid; // 菜单所属进程身份。
    const auto creationTime = m_baseRecord.creationTime100ns;
    const QPointer<ProcessDetailWindow> owner(this); // 防止菜单期间关闭详情窗。
    const bool validRange = creationTime != 0 && module.moduleBaseAddress != 0
        && module.moduleSizeBytes != 0
        && module.moduleSizeBytes <= std::numeric_limits<std::uint64_t>::max() - module.moduleBaseAddress;
    const bool validEntry = validRange && module.entryPointRva != 0
        && module.entryPointRva < module.moduleSizeBytes;
    const QString modulePath = QString::fromStdString(module.modulePath); // 文件页路由使用原路径。

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    contextMenu.setToolTipsVisible(true);
    // 菜单统一使用共享不透明背景及禁用态；每个新动作有明确用途说明。
    const auto addAction = [](QMenu* menu, const char* icon, const char* key,
        const QString& title, const QString& tooltip)
    {
        QAction* action = menu->addAction(ks::ui::MakeThemeAccentIcon(QIcon(QString::fromLatin1(icon))),
            ks::i18n::contextText(QString::fromLatin1(key), title)); // 返回供分发比较的动作。
        action->setIconVisibleInMenu(true);
        action->setToolTip(ks::i18n::sourceText(tooltip));
        return action;
    };

    QAction* copyCellAction = contextMenu.addAction(QIcon(":/Icon/process_copy_cell.svg"), "复制单元格");
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copyCellAction, ks::ui::TableContextActionRole::CopyCell);
    QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), "复制行");
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);
    QAction* copyBaseAction = addAction(&contextMenu, ":/Icon/process_copy_cell.svg",
        "process.detail.module.copy_base", QStringLiteral("复制基址"), QStringLiteral("复制所选模块的加载基址"));
    QAction* copyPathAction = addAction(&contextMenu, ":/Icon/process_copy_row.svg",
        "process.detail.module.copy_path", QStringLiteral("复制路径"), QStringLiteral("复制所选模块的完整文件路径"));
    copyBaseAction->setEnabled(module.moduleBaseAddress != 0);
    copyPathAction->setEnabled(!modulePath.isEmpty());
    if (module.moduleBaseAddress == 0)
        copyBaseAction->setToolTip(ks::i18n::sourceText(QStringLiteral("模块基址不可用。")));
    contextMenu.addSeparator();
    QAction* gotoModuleAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), "查看模块详情");
    QAction* openMemoryAction = addAction(&contextMenu, ":/Icon/memwb_tab_hex.svg",
        "process.detail.module.open_memory", QStringLiteral("查看内存"),
        QStringLiteral("切到当前进程的内存工作台并定位模块加载基址"));
    openMemoryAction->setEnabled(validRange);

    // 直接按用户任务列出目标，不用“相关页面”之类的分类把常用动作藏进二级菜单。
    QAction* entryAction = addAction(&contextMenu, ":/Icon/memwb_tab_disasm.svg",
        "process.detail.module.open_entry", QStringLiteral("转到入口点"),
        QStringLiteral("按模块基址加入口点 RVA 定位内存工作台"));
    entryAction->setEnabled(validEntry);
    QAction* regionsAction = addAction(&contextMenu, ":/Icon/codeeditor_structured.svg",
        "process.detail.module.open_regions", QStringLiteral("定位内存区域"),
        QStringLiteral("切到内存区域列表并选中模块基址所在区域"));
    QAction* searchAction = addAction(&contextMenu, ":/Icon/codeeditor_find.svg",
        "process.detail.module.search_range", QStringLiteral("搜索内存…"),
        QStringLiteral("预填模块起止地址并打开内存搜索，不自动开始扫描"));
    regionsAction->setEnabled(validRange);
    searchAction->setEnabled(validRange);
    QAction* fileDetailAction = addAction(&contextMenu, ":/Icon/process_details.svg",
        "process.detail.module.file_detail", QStringLiteral("文件属性…"),
        QStringLiteral("通过文件页面查看所选模块的落盘文件详情"));
    fileDetailAction->setEnabled(QFileInfo(modulePath).isFile());

    // R3/R0 Dump 直接列出，保留惯用名称与对应图标。
    contextMenu.addSeparator();
    QAction* dumpR3Action = addAction(&contextMenu, ":/Icon/disk_save.svg",
        "process.detail.module.dump_r3", QStringLiteral("R3 Dump…"),
        QStringLiteral("使用 R3 读取完整模块内存并保存为 bin，不重建 PE 文件"));
    QAction* dumpR0Action = addAction(&contextMenu, ":/Icon/disk_save.svg",
        "process.detail.module.dump_r0", QStringLiteral("R0 Dump…"),
        QStringLiteral("使用 R0 驱动读取完整模块内存并保存为 bin，不重建 PE 文件"));
    dumpR3Action->setEnabled(validRange);
    dumpR0Action->setEnabled(validRange);
    // 禁用项保留可读的依赖原因，资源 DLL 没有入口点时也不会被误认为菜单故障。
    if (!validEntry)
    {
        entryAction->setToolTip(ks::i18n::sourceText(QStringLiteral("入口点不可用或不在模块范围内。")));
    }
    if (!fileDetailAction->isEnabled())
    {
        fileDetailAction->setToolTip(ks::i18n::sourceText(QStringLiteral("模块文件不存在或路径不可用。")));
    }
    if (!validRange)
    {
        const QString reason = ks::i18n::sourceText(QStringLiteral("模块地址范围或进程身份无效。")); // 共享依赖说明。
        for (QAction* action : {openMemoryAction, regionsAction, searchAction, dumpR3Action, dumpR0Action})
        {
            action->setToolTip(reason);
        }
    }
    contextMenu.addSeparator();
    if (validRange)
        ks::ui::x64dbg_navigation::AddAction(&contextMenu, this,
            {processId, creationTime, module.moduleBaseAddress,
                ks::ui::x64dbg_navigation::View::Disassembly});
    QAction* openFolderAction = contextMenu.addAction(QIcon(":/Icon/process_open_folder.svg"), "打开文件夹");
    contextMenu.addSeparator();
    QAction* unloadAction = contextMenu.addAction(QIcon(":/Icon/process_terminate.svg"), "卸载");
    const bool validThreadIdentity = processId != 0 && creationTime != 0
        && module.representativeThreadId != 0 && module.representativeThreadCreationTime100ns != 0;
    const auto addThreadAction = [&](const char* icon, const char* key, const QString& pattern)
    {
        auto* action = contextMenu.addAction(QIcon(QString::fromLatin1(icon)),
            ks::i18n::contextText(QString::fromLatin1(key), pattern).arg(module.representativeThreadId));
        action->setEnabled(validThreadIdentity);
        action->setToolTip(ks::i18n::sourceText(validThreadIdentity
            ? QStringLiteral("仅操作此模块行的代表线程；如需选择其它线程，请进入进程详情的“线程”页。")
            : QStringLiteral("代表线程或进程实例身份不可用；请刷新模块列表后重试。")));
        return action;
    };
    QAction* suspendThreadAction = addThreadAction(":/Icon/process_suspend.svg",
        "process.detail.module.suspend_representative_thread", QStringLiteral("挂起代表线程 TID=%1"));
    QAction* resumeThreadAction = addThreadAction(":/Icon/process_resume.svg",
        "process.detail.module.resume_representative_thread", QStringLiteral("恢复代表线程 TID=%1"));
    QAction* terminateThreadAction = addThreadAction(":/Icon/process_terminate.svg",
        "process.detail.module.terminate_representative_thread", QStringLiteral("结束代表线程 TID=%1"));

    QAction* selectedAction = contextMenu.exec(m_moduleTable->viewport()->mapToGlobal(localPosition));
    if (!owner || selectedAction == nullptr || m_baseRecord.pid != processId
        || m_baseRecord.creationTime100ns != creationTime)
    {
        return;
    }

    if (selectedAction == copyCellAction) { copyCurrentModuleCell(); return; }
    if (selectedAction == copyRowAction) { copyCurrentModuleRow(); return; }
    // 所有新增动作按值分发，不再查询可能已变化的选区。
    if (selectedAction == copyBaseAction)
    {
        QApplication::clipboard()->setText(formatHexText(module.moduleBaseAddress));
        return;
    }
    if (selectedAction == copyPathAction)
    {
        QApplication::clipboard()->setText(modulePath);
        return;
    }
    if (selectedAction == fileDetailAction)
    {
        emit requestOpenFileDetailByPath(modulePath);
        return;
    }
    // 内存动作均走同一惰性请求，不让各菜单项复制附加和首显时序。
    const std::pair<QAction*, ModuleMemoryAction> memoryActions[] = {
        {openMemoryAction, ModuleMemoryAction::Base}, {entryAction, ModuleMemoryAction::EntryPoint},
        {regionsAction, ModuleMemoryAction::Regions}, {searchAction, ModuleMemoryAction::Search},
        {dumpR3Action, ModuleMemoryAction::DumpR3}, {dumpR0Action, ModuleMemoryAction::DumpR0}
    };
    for (const auto& [action, destination] : memoryActions)
    {
        if (selectedAction == action)
        {
            requestModuleMemoryAction(module, destination);
            return;
        }
    }
    if (selectedAction == gotoModuleAction) { showCurrentModuleDetailDialog(); return; }
    if (selectedAction == openFolderAction) { openModuleFolder(module, processId, creationTime); return; }
    if (selectedAction == unloadAction) { unloadModule(module, processId, creationTime); return; }
    if (selectedAction == suspendThreadAction) { suspendModuleThread(module, processId, creationTime); return; }
    if (selectedAction == resumeThreadAction) { resumeModuleThread(module, processId, creationTime); return; }
    if (selectedAction == terminateThreadAction) { terminateModuleThread(module, processId, creationTime); return; }
}

// requestModuleMemoryAction：保存菜单值快照并打开内嵌内存页，不等待固定时间猜测加载完成。
void ProcessDetailWindow::requestModuleMemoryAction(
    const ks::process::ProcessModuleRecord& module, const ModuleMemoryAction action)
{
    if (m_tabWidget == nullptr || m_embeddedMemoryTab == nullptr)
    {
        return;
    }
    // 只保留最新导航意图；同一详情窗内的快速连续操作不会排队打开过时地址。
    m_pendingModuleMemoryRequest = std::make_unique<ModuleMemoryRequest>(
        ModuleMemoryRequest{m_baseRecord.pid, m_baseRecord.creationTime100ns, module, action});
    ensureTabContentInitialized(m_embeddedMemoryTab);
    m_tabWidget->setCurrentWidget(m_embeddedMemoryTab);
    ensureEmbeddedMemoryView();
}

// applyPendingModuleMemoryAction：内存页真实就绪后消费一次；身份校验和异步附加由共享入口执行。
void ProcessDetailWindow::applyPendingModuleMemoryAction()
{
    if (m_embeddedMemoryDock == nullptr || !m_pendingModuleMemoryRequest)
    {
        return;
    }
    const auto request = std::move(m_pendingModuleMemoryRequest); // 移走后再进可能产生事件循环的操作。
    if (request->pid != m_baseRecord.pid || request->creationTime != m_baseRecord.creationTime100ns)
    {
        return;
    }
    const auto& module = request->module; // 此次请求独占的模块快照。
    if (request->action == ModuleMemoryAction::DumpR3 || request->action == ModuleMemoryAction::DumpR0)
    {
        const auto backend = request->action == ModuleMemoryAction::DumpR0
            ? ksword::memory_backend::MemoryAccessBackend::StandardDriver
            : ksword::memory_backend::MemoryAccessBackend::UserMode; // Dump 后端不会隐式回退。
        // 冷建内存页也先按强身份附加，取消保存后仍可继续查看本进程的区域与工作台。
        const QPointer<MemoryDock> dock(m_embeddedMemoryDock); // 附加守卫可能异步完成或销毁页面。
        dock->openProcessMemoryRange(request->pid, request->creationTime,
            module.moduleBaseAddress, module.moduleSizeBytes, MemoryDock::ProcessMemoryDestination::Regions,
            [dock, pid = request->pid, creationTime = request->creationTime,
                base = module.moduleBaseAddress, size = module.moduleSizeBytes,
                name = QString::fromStdString(module.moduleName), backend](const bool allowed)
            {
                if (dock && allowed)
                {
                    dock->requestDumpProcessModule(pid, creationTime, base, size, name, backend);
                }
            });
        return;
    }

    // 搜索范围使用整个模块；入口点仅改变定位地址，避免把 RVA 当作进程 VA。
    auto destination = MemoryDock::ProcessMemoryDestination::Workbench; // 默认进入内存工作台。
    if (request->action == ModuleMemoryAction::Regions)
    {
        destination = MemoryDock::ProcessMemoryDestination::Regions;
    }
    else if (request->action == ModuleMemoryAction::Search)
    {
        destination = MemoryDock::ProcessMemoryDestination::Search;
    }
    const auto address = module.moduleBaseAddress
        + (request->action == ModuleMemoryAction::EntryPoint ? module.entryPointRva : 0U); // 绝对地址。
    const auto length = request->action == ModuleMemoryAction::EntryPoint ? 1U : module.moduleSizeBytes;
    m_embeddedMemoryDock->openProcessMemoryRange(request->pid, request->creationTime,
        address, length, destination);
}

void ProcessDetailWindow::copyCurrentModuleCell()
{
    const QModelIndex currentItem = m_moduleTable->currentIndex();
    if (!currentItem.isValid()) return;
    const int currentColumn = currentItem.column();
    QApplication::clipboard()->setText(currentItem.data().toString());
    kLogEvent copyModuleCellEvent;
    dbg << copyModuleCellEvent
        << "[ProcessDetailWindow] copyCurrentModuleCell: column="
        << currentColumn
        << eol;
}

void ProcessDetailWindow::copyCurrentModuleRow()
{
    if (m_moduleTable->currentRow() < 0) return;
    QStringList fields;
    fields.reserve(static_cast<int>(ModuleColumn::Count));
    for (int columnIndex = 0; columnIndex < static_cast<int>(ModuleColumn::Count); ++columnIndex)
    {
        fields.push_back(m_moduleTable->currentCell(columnIndex).toString());
    }
    QApplication::clipboard()->setText(fields.join("\t"));
    kLogEvent copyModuleRowEvent;
    dbg << copyModuleRowEvent
        << "[ProcessDetailWindow] copyCurrentModuleRow: 完成复制整行。"
        << eol;
}

void ProcessDetailWindow::showCurrentModuleDetailDialog()
{
    // showCurrentModuleDetailDialog 作用：
    // - 将模块表当前行映射回 ProcessModuleRecord；
    // - 构造只读详情文本并放入项目内置 StructuredFieldView；
    // - 返回：无，用户可复制全部或打开模块所在目录。
    const ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }

    const QString modulePathText = QString::fromStdString(moduleRecord->modulePath);
    ks::ui::FieldDocument document;
    document.section(QStringLiteral("模块详情"));
    document.field(QStringLiteral("进程 ID"), QString::number(m_baseRecord.pid));
    document.field(QStringLiteral("进程名"), QString::fromStdString(m_baseRecord.processName));
    document.field(QStringLiteral("模块路径"), modulePathText);
    document.field(QStringLiteral("模块基址"), formatHexText(moduleRecord->moduleBaseAddress));
    document.field(QStringLiteral("模块大小"), formatModuleSizeText(moduleRecord->moduleSizeBytes));
    document.field(QStringLiteral("入口点 RVA"), formatHexText(moduleRecord->entryPointRva));
    document.field(QStringLiteral("签名状态"), QString::fromStdString(moduleRecord->signatureState), true);
    document.field(QStringLiteral("签名可信"), moduleRecord->signatureTrusted ? QStringLiteral("true") : QStringLiteral("false"), true);
    document.field(QStringLiteral("运行状态"), QString::fromStdString(moduleRecord->runningState), true);
    document.field(QStringLiteral("代表线程 ID"), QString::number(moduleRecord->representativeThreadId));
    document.field(QStringLiteral("线程 ID 文本"), QString::fromStdString(moduleRecord->threadIdText));

    QDialog detailDialog(this);
    detailDialog.setWindowTitle(QStringLiteral("模块详情 - %1").arg(QFileInfo(modulePathText).fileName()));
    detailDialog.resize(760, 520);
    detailDialog.setStyleSheet(QStringLiteral("QDialog{background:%1;color:%2;}")
        .arg(KswordTheme::SurfaceHex(), KswordTheme::TextPrimaryHex())
        + ks::ui::BuildFlatButtonStyle()
        + QStringLiteral("QPushButton{border-radius:4px;padding:5px 10px;}"));

    QVBoxLayout* dialogLayout = new QVBoxLayout(&detailDialog);
    dialogLayout->setContentsMargins(10, 10, 10, 10);
    dialogLayout->setSpacing(8);

    QLabel* summaryLabel = new QLabel(
        QStringLiteral("模块基址 %1 | 大小 %2 | 签名 %3")
            .arg(formatHexText(moduleRecord->moduleBaseAddress))
            .arg(formatModuleSizeText(moduleRecord->moduleSizeBytes))
            .arg(QString::fromStdString(moduleRecord->signatureState)),
        &detailDialog);
    summaryLabel->setWordWrap(true);
    dialogLayout->addWidget(summaryLabel);

    auto* detailEditor = new ks::ui::StructuredFieldView(&detailDialog);
    detailEditor->setDocument(document);
    dialogLayout->addWidget(detailEditor, 1);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch(1);

    QPushButton* copyButton = new QPushButton(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制全部"), &detailDialog);
    copyButton->setToolTip(QStringLiteral("复制当前模块详情文本"));
    buttonLayout->addWidget(copyButton);

    QPushButton* openFolderButton = new QPushButton(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("打开目录"), &detailDialog);
    openFolderButton->setToolTip(QStringLiteral("打开当前模块所在文件夹"));
    buttonLayout->addWidget(openFolderButton);

    QPushButton* closeButton = new QPushButton(QStringLiteral("关闭"), &detailDialog);
    closeButton->setToolTip(QStringLiteral("关闭模块详情窗口"));
    buttonLayout->addWidget(closeButton);
    ks::ui::NormalizeToolbarRow(buttonLayout);
    dialogLayout->addLayout(buttonLayout);

    connect(copyButton, &QPushButton::clicked, &detailDialog, [detailEditor]()
    {
        QApplication::clipboard()->setText(detailEditor->plainText());
    });
    connect(openFolderButton, &QPushButton::clicked, &detailDialog, [modulePathText]()
    {
        std::string detailTextLocal;
        ks::process::OpenFolderByPath(modulePathText.toStdString(), &detailTextLocal);
    });
    connect(closeButton, &QPushButton::clicked, &detailDialog, &QDialog::accept);

    kLogEvent moduleDetailEvent;
    info << moduleDetailEvent
        << "[ProcessDetailWindow] showCurrentModuleDetailDialog: path="
        << moduleRecord->modulePath
        << ", base="
        << formatHexText(moduleRecord->moduleBaseAddress).toStdString()
        << eol;

    ks::ui::ApplyDetailDialogChrome(&detailDialog);
    detailDialog.exec();
}

void ProcessDetailWindow::openModuleFolder(const ks::process::ProcessModuleRecord& module,
    const std::uint32_t processId, const std::uint64_t creationTime)
{
    const auto* moduleRecord = &module;

    Q_UNUSED(creationTime);
    std::string detailText;
    const bool actionOk = ks::process::OpenFolderByPath(moduleRecord->modulePath, &detailText);
    kLogEvent openModuleFolderEvent;
    info << openModuleFolderEvent
        << "[ProcessDetailWindow] openCurrentModuleFolder: path="
        << moduleRecord->modulePath
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << eol;
    reportModuleActionResult(QStringLiteral("打开模块所在目录"), module, processId, actionOk, detailText, openModuleFolderEvent);
}

void ProcessDetailWindow::unloadModule(const ks::process::ProcessModuleRecord& module,
    const std::uint32_t processId, const std::uint64_t creationTime)
{
    const auto* moduleRecord = &module;

    std::string detailText;
    const bool actionOk = ks::process::UnloadModuleByBaseAddressIfIdentityMatches(
        processId,
        creationTime,
        moduleRecord->moduleBaseAddress,
        &detailText);
    kLogEvent unloadModuleEvent;
    info << unloadModuleEvent
        << "[ProcessDetailWindow] unloadCurrentModule: base="
        << formatHexText(moduleRecord->moduleBaseAddress).toStdString()
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << eol;
    reportModuleActionResult(QStringLiteral("卸载模块"), module, processId, actionOk, detailText, unloadModuleEvent);
    if (actionOk)
    {
        requestAsyncModuleRefresh(true);
    }
}

void ProcessDetailWindow::suspendModuleThread(const ks::process::ProcessModuleRecord& module,
    const std::uint32_t processId, const std::uint64_t creationTime)
{
    const auto* moduleRecord = &module;
    // 挂起线程动作：同一动作链统一复用 actionEvent，避免离散 GUID。
    kLogEvent actionEvent;
    if (processId == 0 || creationTime == 0 || moduleRecord->representativeThreadId == 0
        || moduleRecord->representativeThreadCreationTime100ns == 0)
    {
        const std::string errorDetailText = "代表线程或进程实例身份不可用；请刷新模块列表后重试。";
        warn << actionEvent
            << "[ProcessDetailWindow] suspendCurrentModuleThread: 缺少 ThreadID。"
            << eol;
        reportModuleActionResult(QStringLiteral("挂起线程"), module, processId, false, errorDetailText, actionEvent, true);
        return;
    }

    std::string detailText;
    const bool actionOk = ks::process::SuspendThreadIfProcessAndThreadIdentityMatches(
        moduleRecord->representativeThreadId,
        processId,
        creationTime,
        moduleRecord->representativeThreadCreationTime100ns,
        &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] suspendCurrentModuleThread: tid="
        << moduleRecord->representativeThreadId
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << eol;
    reportModuleActionResult(QStringLiteral("挂起线程"), module, processId, actionOk, detailText, actionEvent, true);
    if (actionOk) requestAsyncModuleRefresh(true);
}

void ProcessDetailWindow::resumeModuleThread(const ks::process::ProcessModuleRecord& module,
    const std::uint32_t processId, const std::uint64_t creationTime)
{
    const auto* moduleRecord = &module;
    // 恢复线程动作：同一动作链统一复用 actionEvent，避免离散 GUID。
    kLogEvent actionEvent;
    if (processId == 0 || creationTime == 0 || moduleRecord->representativeThreadId == 0
        || moduleRecord->representativeThreadCreationTime100ns == 0)
    {
        const std::string errorDetailText = "代表线程或进程实例身份不可用；请刷新模块列表后重试。";
        warn << actionEvent
            << "[ProcessDetailWindow] resumeCurrentModuleThread: 缺少 ThreadID。"
            << eol;
        reportModuleActionResult(QStringLiteral("恢复线程"), module, processId, false, errorDetailText, actionEvent, true);
        return;
    }

    std::string detailText;
    const bool actionOk = ks::process::ResumeThreadIfProcessAndThreadIdentityMatches(
        moduleRecord->representativeThreadId,
        processId,
        creationTime,
        moduleRecord->representativeThreadCreationTime100ns,
        &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] resumeCurrentModuleThread: tid="
        << moduleRecord->representativeThreadId
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << eol;
    reportModuleActionResult(QStringLiteral("恢复线程"), module, processId, actionOk, detailText, actionEvent, true);
    if (actionOk) requestAsyncModuleRefresh(true);
}

void ProcessDetailWindow::terminateModuleThread(const ks::process::ProcessModuleRecord& module,
    const std::uint32_t processId, const std::uint64_t creationTime)
{
    const auto* moduleRecord = &module;
    // 结束线程动作：同一动作链统一复用 actionEvent，避免离散 GUID。
    kLogEvent actionEvent;
    if (processId == 0 || creationTime == 0 || moduleRecord->representativeThreadId == 0
        || moduleRecord->representativeThreadCreationTime100ns == 0)
    {
        const std::string errorDetailText = "代表线程或进程实例身份不可用；请刷新模块列表后重试。";
        warn << actionEvent
            << "[ProcessDetailWindow] terminateCurrentModuleThread: 缺少 ThreadID。"
            << eol;
        reportModuleActionResult(QStringLiteral("结束线程"), module, processId, false, errorDetailText, actionEvent, true);
        return;
    }

    std::string detailText;
    const bool actionOk = ks::process::TerminateThreadIfProcessAndThreadIdentityMatches(
        moduleRecord->representativeThreadId,
        processId,
        creationTime,
        moduleRecord->representativeThreadCreationTime100ns,
        &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] terminateCurrentModuleThread: tid="
        << moduleRecord->representativeThreadId
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << eol;
    reportModuleActionResult(QStringLiteral("结束线程"), module, processId, actionOk, detailText, actionEvent, true);
    if (actionOk)
    {
        requestAsyncModuleRefresh(true);
    }
}

