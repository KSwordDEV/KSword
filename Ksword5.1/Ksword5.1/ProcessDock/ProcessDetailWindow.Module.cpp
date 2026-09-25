#include "ProcessDetailWindow.InternalCommon.h"

using namespace process_detail_window_internal;

// ============================================================
// ProcessDetailWindow.Module.cpp
// 作用：
// - 负责模块页异步刷新、模块表构建、模块右键动作执行。
// - 聚焦“模块信息与模块相关动作”逻辑。
// ============================================================

void ProcessDetailWindow::requestAsyncModuleRefresh(const bool forceRefresh)
{
    // 模块刷新入口日志：记录强制刷新标记与当前刷新状态。
    kLogEvent requestModuleRefreshEvent;
    info << requestModuleRefreshEvent
        << "[ProcessDetailWindow] requestAsyncModuleRefresh: forceRefresh="
        << (forceRefresh ? "true" : "false")
        << ", refreshing="
        << (m_moduleRefreshing ? "true" : "false")
        << ", pid="
        << m_baseRecord.pid
        << eol;

    // 避免并发刷新导致结果乱序。
    if (m_moduleRefreshing)
    {
        if (!forceRefresh)
        {
            return;
        }
        // force=true 时仍不叠加任务，只记录日志并直接返回。
        kLogEvent logEvent;
        warn << logEvent
            << "[ProcessDetailWindow] 忽略模块刷新请求：已有刷新任务在运行, pid="
            << m_baseRecord.pid
            << eol;
        return;
    }

    // 任何进入模块刷新函数的真实请求都视为模块页已按需加载。
    // 这样用户手动点击刷新后，后续切回模块页不会再触发一次自动首刷。
    m_moduleInitialRefreshStarted = true;

    const std::uint32_t pidValue = m_baseRecord.pid;
    const std::uint64_t expectedCreationTime100ns = m_baseRecord.creationTime100ns;
    const bool includeSignatureCheck = (m_signatureCheckBox != nullptr) && m_signatureCheckBox->isChecked();
    const bool firstRefresh = !m_firstModuleRefreshDone;

    kLogEvent requestModuleRefreshConfigEvent;
    dbg << requestModuleRefreshConfigEvent
        << "[ProcessDetailWindow] requestAsyncModuleRefresh: includeSignatureCheck="
        << (includeSignatureCheck ? "true" : "false")
        << ", firstRefresh="
        << (firstRefresh ? "true" : "false")
        << eol;

    // 首次模块刷新用进度条，满足“首次慢操作可见化”需求。
    if (firstRefresh)
    {
        if (m_moduleRefreshProgressPid <= 0)
        {
            m_moduleRefreshProgressPid = kPro.addReusable(
                this,
                "模块列表首次刷新",
                "准备读取模块与线程信息...");
        }
        kPro.set(m_moduleRefreshProgressPid, "开始读取模块快照...", 10, 0.10f);
    }

    m_moduleRefreshing = true;
    const std::uint64_t localTicket = ++m_moduleRefreshTicket;
    updateModuleStatusLabel("● 正在刷新模块列表...", true);

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDetailWindow] 模块刷新开始, pid=" << pidValue
        << ", includeSignature=" << (includeSignatureCheck ? "true" : "false")
        << ", ticket=" << localTicket
        << eol;

    QPointer<ProcessDetailWindow> guard(this);
    QRunnable* backgroundTask = QRunnable::create([guard, localTicket, pidValue, expectedCreationTime100ns, includeSignatureCheck, firstRefresh]() {
        const auto startTime = std::chrono::steady_clock::now();
        ModuleRefreshResult refreshResult{};
        refreshResult.includeSignatureCheck = includeSignatureCheck;
        refreshResult.moduleSnapshot = ks::process::EnumerateProcessModulesAndThreadsIfIdentityMatches(
            pidValue,
            expectedCreationTime100ns,
            includeSignatureCheck);
        refreshResult.elapsedMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count());

        if (guard == nullptr)
        {
            kLogEvent requestModuleRefreshGuardEvent;
            warn << requestModuleRefreshGuardEvent
                << "[ProcessDetailWindow] requestAsyncModuleRefresh: guard失效，后台结果丢弃, pid="
                << pidValue
                << eol;
            return;
        }

        if (firstRefresh && guard->m_moduleRefreshProgressPid > 0)
        {
            kPro.set(guard->m_moduleRefreshProgressPid, "后台读取完成，准备更新界面...", 85, 0.85f);
        }

        QMetaObject::invokeMethod(guard, [guard, localTicket, refreshResult]() {
            if (guard == nullptr)
            {
                return;
            }
            if (localTicket < guard->m_moduleRefreshTicket)
            {
                kLogEvent requestModuleRefreshOutdatedEvent;
                dbg << requestModuleRefreshOutdatedEvent
                    << "[ProcessDetailWindow] requestAsyncModuleRefresh: 过期ticket结果丢弃, localTicket="
                    << localTicket
                    << ", latestTicket="
                    << guard->m_moduleRefreshTicket
                    << eol;
                guard->m_moduleRefreshing = false;
                return;
            }
            guard->applyModuleRefreshResult(refreshResult);
            guard->m_moduleRefreshing = false;
        }, Qt::QueuedConnection);
    });

    backgroundTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(backgroundTask);
}

void ProcessDetailWindow::applyModuleRefreshResult(const ModuleRefreshResult& refreshResult)
{
    // 模块刷新结果应用日志：输出模块数、线程数和耗时。
    kLogEvent applyModuleResultEvent;
    info << applyModuleResultEvent
        << "[ProcessDetailWindow] applyModuleRefreshResult: modules="
        << refreshResult.moduleSnapshot.modules.size()
        << ", threads="
        << refreshResult.moduleSnapshot.threads.size()
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << eol;

    // 覆盖模块缓存并重建表格。
    m_moduleRecords = refreshResult.moduleSnapshot.modules;
    rebuildModuleTable();

    const QString diagnosticText = QString::fromStdString(refreshResult.moduleSnapshot.diagnosticText);

    // 更新状态标签：显示耗时、模块数量与线程数量。
    QString statusText = QString("● 刷新完成 %1 ms | 模块:%2 线程:%3")
        .arg(refreshResult.elapsedMs)
        .arg(refreshResult.moduleSnapshot.modules.size())
        .arg(refreshResult.moduleSnapshot.threads.size());
    if (!diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(
            " | 存在诊断；详情已写入日志。");
    }
    updateModuleStatusLabel(statusText, false);
    if (refreshResult.moduleSnapshot.modules.empty())
    {
        m_moduleStatusLabel->setStyleSheet(buildStateLabelStyle(statusErrorColor(), 700));
    }

    // 首次刷新结束后隐藏对应进度任务卡片。
    if (!m_firstModuleRefreshDone)
    {
        m_firstModuleRefreshDone = true;
        if (m_moduleRefreshProgressPid > 0)
        {
            kPro.set(m_moduleRefreshProgressPid, "模块首次刷新完成", 100, 1.0f);
        }
    }

    kLogEvent logEvent;
    info << logEvent
        << "[ProcessDetailWindow] 模块刷新完成, pid=" << m_baseRecord.pid
        << ", elapsedMs=" << refreshResult.elapsedMs
        << ", moduleCount=" << refreshResult.moduleSnapshot.modules.size()
        << ", threadCount=" << refreshResult.moduleSnapshot.threads.size()
        << ", includeSignature=" << (refreshResult.includeSignatureCheck ? "true" : "false")
        << ", diagnostic=" << refreshResult.moduleSnapshot.diagnosticText
        << eol;

    // 模块数为 0 时额外输出告警日志，便于快速定位权限/跨位数问题。
    if (refreshResult.moduleSnapshot.modules.empty())
    {
        kLogEvent warnEvent;
        warn << warnEvent
            << "[ProcessDetailWindow] 模块列表为空, pid=" << m_baseRecord.pid
            << ", diagnostic=" << refreshResult.moduleSnapshot.diagnosticText
            << eol;
    }
}

void ProcessDetailWindow::rebuildModuleTable()
{
    // 重建模块表日志：用于衡量 UI 列表规模。
    kLogEvent rebuildModuleTableEvent;
    dbg << rebuildModuleTableEvent
        << "[ProcessDetailWindow] rebuildModuleTable: recordCount="
        << m_moduleRecords.size()
        << eol;

    m_moduleTable->clear();

    for (const ks::process::ProcessModuleRecord& moduleRecord : m_moduleRecords)
    {
        QTreeWidgetItem* rowItem = new QTreeWidgetItem();
        rowItem->setText(toModuleColumnIndex(ModuleColumn::Path), QString::fromStdString(moduleRecord.modulePath));
        rowItem->setText(toModuleColumnIndex(ModuleColumn::Size), formatModuleSizeText(moduleRecord.moduleSizeBytes));
        rowItem->setText(toModuleColumnIndex(ModuleColumn::Signature), QString::fromStdString(moduleRecord.signatureState));
        rowItem->setText(toModuleColumnIndex(ModuleColumn::EntryOffset), formatHexText(moduleRecord.entryPointRva));
        rowItem->setText(toModuleColumnIndex(ModuleColumn::State), QString::fromStdString(moduleRecord.runningState));
        rowItem->setText(toModuleColumnIndex(ModuleColumn::ThreadId), QString::fromStdString(moduleRecord.threadIdText));

        rowItem->setIcon(toModuleColumnIndex(ModuleColumn::Path), resolveProcessIcon(moduleRecord.modulePath, 16));

        // 保存右键动作需要的核心数据。
        rowItem->setData(toModuleColumnIndex(ModuleColumn::Path), Qt::UserRole, QString::fromStdString(moduleRecord.modulePath));
        rowItem->setData(
            toModuleColumnIndex(ModuleColumn::Path),
            Qt::UserRole + 1,
            QVariant::fromValue<qulonglong>(moduleRecord.moduleBaseAddress));
        rowItem->setData(toModuleColumnIndex(ModuleColumn::Path), Qt::UserRole + 2, QVariant::fromValue(moduleRecord.representativeThreadId));

        // 按签名可信状态上色：可信绿色，不可信红色，Pending/未知灰色。
        if (moduleRecord.signatureTrusted)
        {
            rowItem->setForeground(toModuleColumnIndex(ModuleColumn::Signature), signatureTrustedColor());
        }
        else if (moduleRecord.signatureState == "Pending" || moduleRecord.signatureState == "Unknown")
        {
            rowItem->setForeground(toModuleColumnIndex(ModuleColumn::Signature), statusSecondaryColor());
        }
        else
        {
            rowItem->setForeground(toModuleColumnIndex(ModuleColumn::Signature), signatureUntrustedColor());
        }

        m_moduleTable->addTopLevelItem(rowItem);
    }

    m_moduleTable->sortItems(toModuleColumnIndex(ModuleColumn::Path), Qt::AscendingOrder);
    filterModuleTable(m_moduleFilterEdit != nullptr ? m_moduleFilterEdit->text() : QString());
}

void ProcessDetailWindow::filterModuleTable(const QString& filterText)
{
    if (m_moduleTable == nullptr)
    {
        return;
    }

    const QString normalizedFilter = filterText.trimmed();
    for (int rowIndex = 0; rowIndex < m_moduleTable->topLevelItemCount(); ++rowIndex)
    {
        QTreeWidgetItem* const rowItem = m_moduleTable->topLevelItem(rowIndex);
        if (rowItem == nullptr)
        {
            continue;
        }

        bool matched = normalizedFilter.isEmpty();
        if (!matched)
        {
            for (int columnIndex = 0; columnIndex < m_moduleTable->columnCount(); ++columnIndex)
            {
                if (rowItem->text(columnIndex).contains(normalizedFilter, Qt::CaseInsensitive))
                {
                    matched = true;
                    break;
                }
            }
        }
        rowItem->setHidden(!matched);
    }
}

void ProcessDetailWindow::updateModuleStatusLabel(const QString& statusText, const bool refreshing)
{
    if (m_moduleStatusLabel == nullptr)
    {
        return;
    }

    m_moduleStatusLabel->setText(statusText);

    // 状态标签更新日志：输出文本与刷新状态。
    kLogEvent moduleStatusEvent;
    dbg << moduleStatusEvent
        << "[ProcessDetailWindow] updateModuleStatusLabel: refreshing="
        << (refreshing ? "true" : "false")
        << ", statusText="
        << statusText.toStdString()
        << eol;

    if (refreshing)
    {
        m_moduleStatusLabel->setStyleSheet(buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700));
    }
    else
    {
        m_moduleStatusLabel->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
    }
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

    QTreeWidgetItem* clickedItem = m_moduleTable->itemAt(localPosition);
    if (clickedItem == nullptr)
    {
        return;
    }
    m_moduleTable->setCurrentItem(clickedItem);

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(QStringLiteral(
        "QMenu{"
        "  background:%1;"
        "  color:%2;"
        "  border:1px solid %3;"
        "}"
        "QMenu::item:selected{"
        "  background:%4;"
        "  color:%5;"
        "}"
        "QMenu::separator{"
        "  height:1px;"
        "  background:%3;"
        "  margin:4px 8px;"
        "}")
        .arg(KswordTheme::SurfaceColorHex())
        .arg(KswordTheme::TextPrimaryColorHex())
        .arg(KswordTheme::BorderColorHex())
        .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
        .arg(KswordTheme::OnAccentHex()));

    QAction* copyCellAction = contextMenu.addAction(QIcon(":/Icon/process_copy_cell.svg"), "复制单元格");
    QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), "复制行");
    contextMenu.addSeparator();
    QAction* gotoModuleAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), "查看模块详情");
    QAction* openFolderAction = contextMenu.addAction(QIcon(":/Icon/process_open_folder.svg"), "打开文件夹");
    QAction* unloadAction = contextMenu.addAction(QIcon(":/Icon/process_terminate.svg"), "卸载");
    QAction* suspendThreadAction = contextMenu.addAction(QIcon(":/Icon/process_suspend.svg"), "挂起线程");
    QAction* resumeThreadAction = contextMenu.addAction(QIcon(":/Icon/process_resume.svg"), "恢复线程");
    QAction* terminateThreadAction = contextMenu.addAction(QIcon(":/Icon/process_terminate.svg"), "结束线程");

    QAction* selectedAction = contextMenu.exec(m_moduleTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == copyCellAction) { copyCurrentModuleCell(); return; }
    if (selectedAction == copyRowAction) { copyCurrentModuleRow(); return; }
    if (selectedAction == gotoModuleAction) { showCurrentModuleDetailDialog(); return; }
    if (selectedAction == openFolderAction) { openCurrentModuleFolder(); return; }
    if (selectedAction == unloadAction) { unloadCurrentModule(); return; }
    if (selectedAction == suspendThreadAction) { suspendCurrentModuleThread(); return; }
    if (selectedAction == resumeThreadAction) { resumeCurrentModuleThread(); return; }
    if (selectedAction == terminateThreadAction) { terminateCurrentModuleThread(); return; }
}

void ProcessDetailWindow::copyCurrentModuleCell()
{
    QTreeWidgetItem* currentItem = m_moduleTable->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }

    const int currentColumn = m_moduleTable->currentColumn();
    if (currentColumn < 0)
    {
        return;
    }
    QApplication::clipboard()->setText(currentItem->text(currentColumn));
    kLogEvent copyModuleCellEvent;
    dbg << copyModuleCellEvent
        << "[ProcessDetailWindow] copyCurrentModuleCell: column="
        << currentColumn
        << eol;
}

void ProcessDetailWindow::copyCurrentModuleRow()
{
    QTreeWidgetItem* currentItem = m_moduleTable->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }

    QStringList fields;
    fields.reserve(static_cast<int>(ModuleColumn::Count));
    for (int columnIndex = 0; columnIndex < static_cast<int>(ModuleColumn::Count); ++columnIndex)
    {
        fields.push_back(currentItem->text(columnIndex));
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
    // - 构造只读详情文本并放入项目内置 CodeEditorWidget；
    // - 返回：无，用户可复制全部或打开模块所在目录。
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }

    const QString modulePathText = QString::fromStdString(moduleRecord->modulePath);
    const QString detailText = QStringList({
        QStringLiteral("进程 ID: %1").arg(m_baseRecord.pid),
        QStringLiteral("进程名: %1").arg(QString::fromStdString(m_baseRecord.processName)),
        QStringLiteral("模块路径: %1").arg(modulePathText),
        QStringLiteral("模块基址: %1").arg(formatHexText(moduleRecord->moduleBaseAddress)),
        QStringLiteral("模块大小: %1").arg(formatModuleSizeText(moduleRecord->moduleSizeBytes)),
        QStringLiteral("入口点 RVA: %1").arg(formatHexText(moduleRecord->entryPointRva)),
        QStringLiteral("签名状态: %1").arg(QString::fromStdString(moduleRecord->signatureState)),
        QStringLiteral("签名可信: %1").arg(moduleRecord->signatureTrusted ? QStringLiteral("true") : QStringLiteral("false")),
        QStringLiteral("运行状态: %1").arg(QString::fromStdString(moduleRecord->runningState)),
        QStringLiteral("代表线程 ID: %1").arg(moduleRecord->representativeThreadId),
        QStringLiteral("线程 ID 文本: %1").arg(QString::fromStdString(moduleRecord->threadIdText))
    }).join(QChar('\n'));

    QDialog detailDialog(this);
    detailDialog.setWindowTitle(QStringLiteral("模块详情 - %1").arg(QFileInfo(modulePathText).fileName()));
    detailDialog.resize(760, 520);
    detailDialog.setStyleSheet(QStringLiteral(
        "QDialog{background:%1;color:%2;}"
        "QPushButton{background:%3;color:%2;border:1px solid %4;border-radius:4px;padding:5px 10px;}"
        "QPushButton:hover{background:%5;}")
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::SurfaceAltColorHex())
        .arg(KswordTheme::BorderHex())
        .arg(KswordTheme::PrimaryBlueHex));

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

    CodeEditorWidget* detailEditor = new CodeEditorWidget(&detailDialog);
    detailEditor->setReadOnly(true);
    detailEditor->setLocalizedText(detailText);
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
    dialogLayout->addLayout(buttonLayout);

    connect(copyButton, &QPushButton::clicked, &detailDialog, [detailEditor]()
    {
        QApplication::clipboard()->setText(detailEditor->text());
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

    detailDialog.exec();
}

void ProcessDetailWindow::openCurrentModuleFolder()
{
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }

    std::string detailText;
    const bool actionOk = ks::process::OpenFolderByPath(moduleRecord->modulePath, &detailText);
    kLogEvent openModuleFolderEvent;
    info << openModuleFolderEvent
        << "[ProcessDetailWindow] openCurrentModuleFolder: path="
        << moduleRecord->modulePath
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << eol;
    showActionResultMessage("打开模块所在目录", actionOk, detailText, openModuleFolderEvent);
}

void ProcessDetailWindow::unloadCurrentModule()
{
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }

    std::string detailText;
    const bool actionOk = ks::process::UnloadModuleByBaseAddressIfIdentityMatches(
        m_baseRecord.pid,
        m_baseRecord.creationTime100ns,
        moduleRecord->moduleBaseAddress,
        &detailText);
    kLogEvent unloadModuleEvent;
    info << unloadModuleEvent
        << "[ProcessDetailWindow] unloadCurrentModule: base="
        << formatHexText(moduleRecord->moduleBaseAddress).toStdString()
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << eol;
    showActionResultMessage("卸载模块", actionOk, detailText, unloadModuleEvent);
    if (actionOk)
    {
        requestAsyncModuleRefresh(true);
    }
}

void ProcessDetailWindow::suspendCurrentModuleThread()
{
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }
    // 挂起线程动作：同一动作链统一复用 actionEvent，避免离散 GUID。
    kLogEvent actionEvent;
    if (moduleRecord->representativeThreadId == 0)
    {
        const std::string errorDetailText = "当前模块行没有可用 ThreadID。";
        warn << actionEvent
            << "[ProcessDetailWindow] suspendCurrentModuleThread: 缺少 ThreadID。"
            << eol;
        showActionResultMessage("挂起线程", false, errorDetailText, actionEvent);
        return;
    }

    std::string detailText;
    const bool actionOk = ks::process::SuspendThreadIfProcessAndThreadIdentityMatches(
        moduleRecord->representativeThreadId,
        m_baseRecord.pid,
        m_baseRecord.creationTime100ns,
        moduleRecord->representativeThreadCreationTime100ns,
        &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] suspendCurrentModuleThread: tid="
        << moduleRecord->representativeThreadId
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << eol;
    showActionResultMessage("挂起线程", actionOk, detailText, actionEvent);
}

void ProcessDetailWindow::resumeCurrentModuleThread()
{
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }
    // 恢复线程动作：同一动作链统一复用 actionEvent，避免离散 GUID。
    kLogEvent actionEvent;
    if (moduleRecord->representativeThreadId == 0)
    {
        const std::string errorDetailText = "当前模块行没有可用 ThreadID。";
        warn << actionEvent
            << "[ProcessDetailWindow] resumeCurrentModuleThread: 缺少 ThreadID。"
            << eol;
        showActionResultMessage("恢复线程", false, errorDetailText, actionEvent);
        return;
    }

    std::string detailText;
    const bool actionOk = ks::process::ResumeThreadIfProcessAndThreadIdentityMatches(
        moduleRecord->representativeThreadId,
        m_baseRecord.pid,
        m_baseRecord.creationTime100ns,
        moduleRecord->representativeThreadCreationTime100ns,
        &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] resumeCurrentModuleThread: tid="
        << moduleRecord->representativeThreadId
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << eol;
    showActionResultMessage("恢复线程", actionOk, detailText, actionEvent);
}

void ProcessDetailWindow::terminateCurrentModuleThread()
{
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }
    // 结束线程动作：同一动作链统一复用 actionEvent，避免离散 GUID。
    kLogEvent actionEvent;
    if (moduleRecord->representativeThreadId == 0)
    {
        const std::string errorDetailText = "当前模块行没有可用 ThreadID。";
        warn << actionEvent
            << "[ProcessDetailWindow] terminateCurrentModuleThread: 缺少 ThreadID。"
            << eol;
        showActionResultMessage("结束线程", false, errorDetailText, actionEvent);
        return;
    }

    std::string detailText;
    const bool actionOk = ks::process::TerminateThreadIfProcessAndThreadIdentityMatches(
        moduleRecord->representativeThreadId,
        m_baseRecord.pid,
        m_baseRecord.creationTime100ns,
        moduleRecord->representativeThreadCreationTime100ns,
        &detailText);
    (actionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] terminateCurrentModuleThread: tid="
        << moduleRecord->representativeThreadId
        << ", actionOk="
        << (actionOk ? "true" : "false")
        << eol;
    showActionResultMessage("结束线程", actionOk, detailText, actionEvent);
    if (actionOk)
    {
        requestAsyncModuleRefresh(true);
    }
}

