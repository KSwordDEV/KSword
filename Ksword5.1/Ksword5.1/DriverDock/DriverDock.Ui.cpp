#include "DriverDock.Internal.h"
#include "../KernelDock/KernelThreadAuditTab.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/DetailLayoutRegistry.h"

// 说明：由原聚合式实现迁移为独立 .cpp，成员函数实现保持原样。
using namespace ksword::driver_dock_internal;

namespace ksword::driver_dock_internal
{
    namespace
    {
        // 证据采集工作线程只生成稳定源文本；该标记按线程隔离，不改变 GUI 线程语言状态。
        thread_local bool driverEvidenceSourceTextOnly = false;
    }

    QString driverText(const char* const contextKey, const QString& sourceText)
    {
        if (driverEvidenceSourceTextOnly)
        {
            return sourceText;
        }
        return ks::i18n::contextText(QString::fromLatin1(contextKey), sourceText);
    }

    bool swapDriverEvidenceSourceTextMode(const bool sourceTextOnly)
    {
        const bool previousMode = driverEvidenceSourceTextOnly;
        driverEvidenceSourceTextOnly = sourceTextOnly;
        return previousMode;
    }

    QStringList driverServiceTableHeaders()
    {
        return {
            driverText("driver.header.service_name", QStringLiteral("服务名")),
            driverText("driver.header.display_name", QStringLiteral("显示名")),
            driverText("driver.header.status", QStringLiteral("状态")),
            driverText("driver.header.start_type", QStringLiteral("启动类型")),
            driverText("driver.header.error_control", QStringLiteral("错误控制")),
            driverText("driver.header.image_path", QStringLiteral("映像路径")),
            driverText("driver.header.description", QStringLiteral("描述"))
        };
    }

    QStringList driverModuleTableHeaders()
    {
        return {
            driverText("driver.header.module_name", QStringLiteral("模块名")),
            driverText("driver.header.base_address", QStringLiteral("基址")),
            driverText("driver.header.digital_signature", QStringLiteral("数字签名")),
            driverText("driver.header.driver_object", QStringLiteral("DriverObject")),
            driverText("driver.header.driver_start", QStringLiteral("DriverStart")),
            driverText("driver.header.major_function", QStringLiteral("MajorFunction")),
            driverText("driver.header.iat_eat", QStringLiteral("IAT/EAT")),
            driverText("driver.header.inline_hook", QStringLiteral("Inline Hook")),
            driverText("driver.header.callback", QStringLiteral("Callback")),
            driverText("driver.header.module_image_path", QStringLiteral("映像路径"))
        };
    }

    QStringList driverObjectEvidenceTableHeaders()
    {
        return {
            driverText("driver.header.field", QStringLiteral("字段")),
            driverText("driver.header.value", QStringLiteral("值"))
        };
    }

    QStringList driverDeviceObjectTableHeaders()
    {
        return {
            driverText("driver.header.relationship", QStringLiteral("关系")),
            driverText("driver.header.device_object", QStringLiteral("DeviceObject")),
            driverText("driver.header.device_name", QStringLiteral("设备名")),
            driverText("driver.header.type", QStringLiteral("Type")),
            driverText("driver.header.flags", QStringLiteral("Flags")),
            driverText("driver.header.characteristics", QStringLiteral("Characteristics")),
            driverText("driver.header.stack", QStringLiteral("Stack")),
            driverText("driver.header.next_device", QStringLiteral("NextDevice")),
            driverText("driver.header.attached_device", QStringLiteral("AttachedDevice")),
            driverText("driver.header.driver_object", QStringLiteral("DriverObject"))
        };
    }

    QStringList driverEvidenceTableHeaders()
    {
        return {
            driverText("driver.header.evidence", QStringLiteral("证据")),
            driverText("driver.header.object", QStringLiteral("对象")),
            driverText("driver.header.target", QStringLiteral("目标")),
            driverText("driver.header.risk", QStringLiteral("风险")),
            driverText("driver.header.confidence", QStringLiteral("置信度")),
            driverText("driver.header.detail", QStringLiteral("Detail"))
        };
    }

    QStringList driverIntegrityTableHeaders()
    {
        return {
            driverText("driver.header.class", QStringLiteral("类别")),
            driverText("driver.header.object", QStringLiteral("对象")),
            driverText("driver.header.target", QStringLiteral("目标")),
            driverText("driver.header.owner", QStringLiteral("Owner")),
            driverText("driver.header.cpu_vector", QStringLiteral("CPU/Vector")),
            driverText("driver.header.risk", QStringLiteral("风险")),
            driverText("driver.header.confidence", QStringLiteral("置信度")),
            driverText("driver.header.explanation", QStringLiteral("说明"))
        };
    }

    QStringList driverMajorFunctionTableHeaders()
    {
        return {
            driverText("driver.header.irp_mj", QStringLiteral("IRP_MJ")),
            driverText("driver.header.dispatch", QStringLiteral("Dispatch")),
            driverText("driver.header.module", QStringLiteral("模块")),
            driverText("driver.header.module_base", QStringLiteral("模块基址")),
            driverText("driver.header.location", QStringLiteral("位置"))
        };
    }

    QStringList driverModuleCrossViewTableHeaders()
    {
        return {
            driverText("driver.header.evidence", QStringLiteral("证据")),
            driverText("driver.header.object", QStringLiteral("对象")),
            driverText("driver.header.target", QStringLiteral("目标")),
            driverText("driver.header.risk", QStringLiteral("风险")),
            driverText("driver.header.source", QStringLiteral("来源")),
            driverText("driver.header.confidence", QStringLiteral("置信度")),
            driverText("driver.header.detail", QStringLiteral("Detail"))
        };
    }

    QStringList driverUnloadedDriverTableHeaders()
    {
        // 表头顺序与 issue 截图保持一致，三个来源缺失的字段由行 HAS_* 标志显示“-”。
        return {
            driverText("driver.unloaded.header.name", QStringLiteral("名称")),
            driverText("driver.unloaded.header.base", QStringLiteral("基址")),
            driverText("driver.unloaded.header.size", QStringLiteral("大小")),
            driverText("driver.unloaded.header.timestamp", QStringLiteral("时间戳")),
            driverText("driver.unloaded.header.load_status", QStringLiteral("加载状态")),
            driverText("driver.unloaded.header.unload_time", QStringLiteral("卸载时间"))
        };
    }
}

namespace
{
    QString driverTableCellText(QTableWidget* table, const int rowIndex, const int columnIndex)
    {
        // driverTableCellText：
        // - 输入：表格、行号和列号；
        // - 处理：安全读取单元格文本；
        // - 返回：空单元格返回空字符串。
        if (table == nullptr)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
        return item != nullptr ? item->text() : QString();
    }

    void copyDriverTableCurrentRow(QTableWidget* table)
    {
        // copyDriverTableCurrentRow：
        // - 输入：DriverDock 只读表格；
        // - 处理：复制当前行 TSV；
        // - 返回：无，剪贴板不可用或未选中时直接返回。
        if (table == nullptr || QGuiApplication::clipboard() == nullptr)
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
            fields.push_back(driverTableCellText(table, rowIndex, columnIndex));
        }
        QGuiApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    void installDriverTableCopyMenu(QTableWidget* table)
    {
        // installDriverTableCopyMenu：
        // - 输入：无破坏动作的 DriverDock 只读证据表；
        // - 处理：安装复制当前行菜单；
        // - 返回：无，不触发 R0/R3 修改操作。
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex clickedIndex = table->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                table->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            }

            QMenu contextMenu(table);
            contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                driverText("driver.menu.copy_row", QStringLiteral("复制当前行")));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            if (contextMenu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyDriverTableCurrentRow(table);
            }
        });
    }
}

void DriverDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        applyTranslatedHeaders();
        updateDebugCaptureButtonState();
        refreshDebugOutputLines();
        // 签名缓存只保存语义；切换语言时同步重建行文本、筛选结果、详情和摘要。
        rebuildLoadedModuleTable();
        updateLoadedModuleEvidenceStatusText();
    }
}

void DriverDock::applyTranslatedHeaders()
{
    if (m_servicePage != nullptr && m_tabWidget != nullptr)
    {
        const int serviceTabIndex = m_tabWidget->indexOf(m_servicePage);
        if (serviceTabIndex >= 0)
        {
            m_tabWidget->setTabText(
                serviceTabIndex,
                driverText("driver.tab.services", QStringLiteral("驱动服务")));
        }
    }
    if (m_kernelModulePage != nullptr && m_tabWidget != nullptr)
    {
        const int kernelModuleTabIndex = m_tabWidget->indexOf(m_kernelModulePage);
        if (kernelModuleTabIndex >= 0)
        {
            m_tabWidget->setTabText(
                kernelModuleTabIndex,
                driverText("driver.tab.kernel_modules", QStringLiteral("内核模块")));
        }
    }
    if (m_serviceFilterEdit != nullptr)
    {
        m_serviceFilterEdit->setPlaceholderText(driverText(
            "driver.service.filter.placeholder", QStringLiteral("搜索驱动服务")));
        m_serviceFilterEdit->setToolTip(driverText(
            "driver.service.filter.tooltip", QStringLiteral("按服务名、显示名、描述和映像路径过滤")));
    }
    if (m_moduleFilterEdit != nullptr)
    {
        m_moduleFilterEdit->setPlaceholderText(driverText(
            "driver.kernel_module.filter.placeholder", QStringLiteral("搜索内核模块")));
        m_moduleFilterEdit->setToolTip(driverText(
            "driver.kernel_module.filter.tooltip", QStringLiteral("按模块名、签名状态和映像路径过滤")));
    }
    if (m_serviceTable != nullptr)
    {
        m_serviceTable->setHorizontalHeaderLabels(driverServiceTableHeaders());
    }
    if (m_moduleTable != nullptr)
    {
        m_moduleTable->setHorizontalHeaderLabels(driverModuleTableHeaders());
    }
    if (m_driverObjectEvidenceTable != nullptr)
    {
        m_driverObjectEvidenceTable->setHorizontalHeaderLabels(driverObjectEvidenceTableHeaders());
    }
    if (m_deviceObjectTable != nullptr)
    {
        m_deviceObjectTable->setHorizontalHeaderLabels(driverDeviceObjectTableHeaders());
    }
    if (m_driverExtensionEvidenceTable != nullptr)
    {
        m_driverExtensionEvidenceTable->setHorizontalHeaderLabels(driverEvidenceTableHeaders());
    }
    if (m_majorFunctionTable != nullptr)
    {
        m_majorFunctionTable->setHorizontalHeaderLabels(driverMajorFunctionTableHeaders());
    }
    if (m_fastIoEvidenceTable != nullptr)
    {
        m_fastIoEvidenceTable->setHorizontalHeaderLabels(driverEvidenceTableHeaders());
    }
    if (m_integrityTable != nullptr)
    {
        m_integrityTable->setHorizontalHeaderLabels(driverIntegrityTableHeaders());
    }
    if (m_moduleCrossViewTable != nullptr)
    {
        m_moduleCrossViewTable->setHorizontalHeaderLabels(driverModuleCrossViewTableHeaders());
    }
    if (m_unloadedPiddbTable != nullptr)
    {
        m_unloadedPiddbTable->setHorizontalHeaderLabels(driverUnloadedDriverTableHeaders());
    }
    if (m_unloadedPiddbDeleteButton != nullptr)
    {
        m_unloadedPiddbDeleteButton->setText(
            driverText(
                "driver.unloaded.delete_exact",
                QStringLiteral("删除选中 PiDDB 表项")));
    }
    if (m_systemThreadAuditTab != nullptr)
    {
        const int systemThreadTabIndex = m_tabWidget->indexOf(m_systemThreadAuditTab);
        if (systemThreadTabIndex >= 0)
        {
            m_tabWidget->setTabText(
                systemThreadTabIndex,
                driverText("driver.tab.system_threads", QStringLiteral("系统线程")));
            m_tabWidget->setTabToolTip(
                systemThreadTabIndex,
                driverText(
                    "driver.tab.system_threads.tooltip",
                    QStringLiteral("枚举 System(PID 4) 线程并提供受保护的第三方驱动线程管理")));
        }
    }
    if (m_kswordSelfDriverPage != nullptr && m_kswordSelfDriverTabIndex >= 0)
    {
        m_tabWidget->setTabText(
            m_kswordSelfDriverTabIndex,
            driverText("driver.tab.self_driver", QStringLiteral("Ksword自身驱动")));
        m_tabWidget->setTabToolTip(
            m_kswordSelfDriverTabIndex,
            driverText(
                "driver.tab.self_driver.tooltip",
                QStringLiteral("KswordARK 动态偏移与驱动状态")));
    }
}

void DriverDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(6);

    m_tabWidget = new QTabWidget(this);
    m_rootLayout->addWidget(m_tabWidget, 1);

    initializeServiceTab();
    initializeKernelModuleTab();
    initializeOperateTab();
    initializeDebugOutputTab();
    initializeObjectInfoTab();
    initializeModuleCrossViewTab();
    initializeIntegrityTab();
    initializeUnloadedPiddbTab();
    initializeSystemThreadTab();
}

void DriverDock::initializeSystemThreadTab()
{
    if (m_tabWidget == nullptr || m_systemThreadAuditTab != nullptr)
    {
        return;
    }

    // 系统线程页只负责展示与确认；所有 KswordARK 操作由组件内 ArkDriverClient 完成。
    m_systemThreadAuditTab = new KernelThreadAuditTab(
        KernelThreadAuditTab::Mode::SystemThreads,
        m_tabWidget);
    const int tabIndex = m_tabWidget->addTab(
        m_systemThreadAuditTab,
        QIcon(QStringLiteral(":/Icon/process_threads.svg")),
        driverText("driver.tab.system_threads", QStringLiteral("系统线程")));
    m_tabWidget->setTabToolTip(
        tabIndex,
        driverText(
            "driver.tab.system_threads.tooltip",
            QStringLiteral("枚举 System(PID 4) 线程并提供受保护的第三方驱动线程管理")));
}

void DriverDock::initializeServiceTab()
{
    // 输入：无；处理：建立独立的驱动服务页；返回：无。
    m_servicePage = new QWidget(m_tabWidget);
    m_overviewPage = m_servicePage;
    m_serviceLayout = new QVBoxLayout(m_servicePage);
    m_overviewLayout = m_serviceLayout;
    m_serviceLayout->setContentsMargins(4, 4, 4, 4);
    m_serviceLayout->setSpacing(6);

    m_overviewToolLayout = new QHBoxLayout();
    m_overviewToolLayout->setContentsMargins(0, 0, 0, 0);
    m_overviewToolLayout->setSpacing(6);

    m_refreshServiceButton = new QPushButton(m_servicePage);
    m_refreshServiceButton->setIcon(QIcon(":/Icon/process_refresh.svg"));
    m_refreshServiceButton->setToolTip(driverText(
        "driver.toolbar.refresh_services.tooltip", QStringLiteral("刷新驱动服务列表")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshServiceButton);

    m_serviceFilterEdit = new QLineEdit(m_servicePage);
    m_serviceFilterEdit->setPlaceholderText(driverText(
        "driver.service.filter.placeholder", QStringLiteral("搜索驱动服务")));
    m_serviceFilterEdit->setToolTip(driverText(
        "driver.service.filter.tooltip", QStringLiteral("按服务名、显示名、描述和映像路径过滤")));

    m_overviewStatusLabel = new QLabel(driverText(
        "driver.status.waiting_refresh", QStringLiteral("状态：等待刷新")), m_servicePage);
    m_overviewStatusLabel->setWordWrap(true);
    m_overviewToolLayout->addWidget(m_refreshServiceButton);
    m_overviewToolLayout->addWidget(m_serviceFilterEdit, 1);
    m_overviewToolLayout->addWidget(m_overviewStatusLabel);
    m_serviceLayout->addLayout(m_overviewToolLayout);

    m_serviceTable = new ks::ui::VisibleTableWidget(m_servicePage);
    m_serviceTable->setColumnCount(7);
    m_serviceTable->setHorizontalHeaderLabels(driverServiceTableHeaders());
    m_serviceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_serviceTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_serviceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_serviceTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_serviceTable->setAlternatingRowColors(true);
    m_serviceTable->verticalHeader()->setVisible(false);
    m_serviceTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_serviceTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    m_serviceTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    m_serviceLayout->addWidget(m_serviceTable, 1);

    m_tabWidget->addTab(m_servicePage, QIcon(":/Icon/process_list.svg"), driverText(
        "driver.tab.services", QStringLiteral("驱动服务")));
}

void DriverDock::initializeKernelModuleTab()
{
    // 输入：无；处理：建立模块列表和统一详情编辑器；返回：无。
    m_kernelModulePage = new QWidget(m_tabWidget);
    m_kernelModuleLayout = new QVBoxLayout(m_kernelModulePage);
    m_kernelModuleLayout->setContentsMargins(4, 4, 4, 4);
    m_kernelModuleLayout->setSpacing(6);
    m_kernelModuleToolLayout = new QHBoxLayout();
    m_kernelModuleToolLayout->setContentsMargins(0, 0, 0, 0);
    m_kernelModuleToolLayout->setSpacing(6);

    m_refreshModuleButton = new QPushButton(m_kernelModulePage);
    m_refreshModuleButton->setIcon(QIcon(":/Icon/process_refresh.svg"));
    m_refreshModuleButton->setToolTip(driverText(
        "driver.toolbar.refresh_modules.tooltip", QStringLiteral("刷新已加载内核模块")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshModuleButton);
    m_refreshModuleEvidenceButton = new QPushButton(m_kernelModulePage);
    m_refreshModuleEvidenceButton->setIcon(QIcon(":/Icon/process_refresh.svg"));
    m_refreshModuleEvidenceButton->setToolTip(driverText(
        "driver.toolbar.refresh_module_evidence.tooltip", QStringLiteral("刷新内核模块证据")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshModuleEvidenceButton);
    m_moduleEvidenceStatusLabel = new QLabel(driverText(
        "driver.overview.evidence.status.waiting", QStringLiteral("证据：等待刷新")), m_kernelModulePage);
    m_moduleEvidenceStatusLabel->setWordWrap(true);
    m_moduleFilterEdit = new QLineEdit(m_kernelModulePage);
    m_moduleFilterEdit->setPlaceholderText(driverText(
        "driver.kernel_module.filter.placeholder", QStringLiteral("搜索内核模块")));
    m_moduleFilterEdit->setToolTip(driverText(
        "driver.kernel_module.filter.tooltip", QStringLiteral("按模块名、签名状态和映像路径过滤")));
    m_kernelModuleToolLayout->addWidget(m_refreshModuleButton);
    m_kernelModuleToolLayout->addWidget(m_refreshModuleEvidenceButton);
    m_kernelModuleToolLayout->addWidget(m_moduleFilterEdit, 1);
    m_kernelModuleToolLayout->addWidget(m_moduleEvidenceStatusLabel);
    m_kernelModuleLayout->addLayout(m_kernelModuleToolLayout);

    m_moduleTable = new ks::ui::VisibleTableWidget(m_kernelModulePage);
    m_moduleTable->setColumnCount(ModuleTableColumnCount);
    m_moduleTable->setHorizontalHeaderLabels(driverModuleTableHeaders());
    m_moduleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_moduleTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_moduleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_moduleTable->setAlternatingRowColors(true);
    m_moduleTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_moduleTable->verticalHeader()->setVisible(false);
    m_moduleTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_moduleTable->horizontalHeader()->setSectionResizeMode(ModuleImagePathColumn, QHeaderView::Stretch);
    m_kernelModuleLayout->addWidget(m_moduleTable, 3);

    m_moduleEvidenceDetailEditor = new CodeEditorWidget(m_kernelModulePage);
    m_moduleEvidenceDetailEditor->setReadOnly(true);
    m_moduleEvidenceDetailEditor->setText(driverText(
        "driver.overview.evidence.detail.initial", QStringLiteral("请选择一条已加载模块，或点击证据刷新按钮。")));
    m_kernelModuleLayout->addWidget(m_moduleEvidenceDetailEditor, 2);
    ks::ui::DetailLayoutRegistry::registerHost(
        m_moduleTable, m_moduleEvidenceDetailEditor, m_kernelModulePage);
    m_tabWidget->addTab(m_kernelModulePage, QIcon(":/Icon/process_list.svg"), driverText(
        "driver.tab.kernel_modules", QStringLiteral("内核模块")));
}

void DriverDock::initializeOperateTab()
{
    m_operatePage = new QWidget(m_tabWidget);
    m_operateLayout = new QVBoxLayout(m_operatePage);
    m_operateLayout->setContentsMargins(4, 4, 4, 4);
    m_operateLayout->setSpacing(6);

    QGridLayout* formLayout = new QGridLayout();
    formLayout->setHorizontalSpacing(8);
    formLayout->setVerticalSpacing(6);
    formLayout->setColumnStretch(1, 1);
    formLayout->setColumnStretch(3, 1);

    m_serviceNameEdit = new QLineEdit(m_operatePage);
    m_serviceNameEdit->setPlaceholderText(
        driverText("driver.form.service_name.placeholder", QStringLiteral("例如 MyDriver")));
    m_displayNameEdit = new QLineEdit(m_operatePage);
    m_displayNameEdit->setPlaceholderText(
        driverText("driver.form.display_name.placeholder", QStringLiteral("例如 My Driver Service")));
    m_binaryPathEdit = new QLineEdit(m_operatePage);
    m_binaryPathEdit->setPlaceholderText(
        driverText(
            "driver.form.binary_path.placeholder",
            QStringLiteral("例如 C:\\Windows\\System32\\drivers\\mydrv.sys")));
    m_descriptionEdit = new QLineEdit(m_operatePage);
    m_descriptionEdit->setPlaceholderText(
        driverText("driver.form.description.placeholder", QStringLiteral("描述（可选）")));

    m_browsePathButton = new QPushButton(m_operatePage);
    m_browsePathButton->setIcon(QIcon(":/Icon/process_open_folder.svg"));
    m_browsePathButton->setToolTip(
        driverText("driver.form.browse_path.tooltip", QStringLiteral("浏览并选择 .sys 文件")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_browsePathButton);

    m_startTypeCombo = new QComboBox(m_operatePage);
    m_startTypeCombo->addItem(
        driverText("driver.form.start_type.boot", QStringLiteral("引导启动（BOOT）")),
        static_cast<int>(SERVICE_BOOT_START));
    m_startTypeCombo->addItem(
        driverText("driver.form.start_type.system", QStringLiteral("系统启动（SYSTEM）")),
        static_cast<int>(SERVICE_SYSTEM_START));
    m_startTypeCombo->addItem(
        driverText("driver.form.start_type.auto", QStringLiteral("自动启动（AUTO）")),
        static_cast<int>(SERVICE_AUTO_START));
    m_startTypeCombo->addItem(
        driverText("driver.form.start_type.demand", QStringLiteral("手动启动（DEMAND）")),
        static_cast<int>(SERVICE_DEMAND_START));
    m_startTypeCombo->addItem(
        driverText("driver.form.start_type.disabled", QStringLiteral("禁用（DISABLED）")),
        static_cast<int>(SERVICE_DISABLED));

    m_errorControlCombo = new QComboBox(m_operatePage);
    m_errorControlCombo->addItem(
        driverText("driver.form.error_control.ignore", QStringLiteral("忽略（IGNORE）")),
        static_cast<int>(SERVICE_ERROR_IGNORE));
    m_errorControlCombo->addItem(
        driverText("driver.form.error_control.normal", QStringLiteral("正常（NORMAL）")),
        static_cast<int>(SERVICE_ERROR_NORMAL));
    m_errorControlCombo->addItem(
        driverText("driver.form.error_control.severe", QStringLiteral("严重（SEVERE）")),
        static_cast<int>(SERVICE_ERROR_SEVERE));
    m_errorControlCombo->addItem(
        driverText("driver.form.error_control.critical", QStringLiteral("致命（CRITICAL）")),
        static_cast<int>(SERVICE_ERROR_CRITICAL));

    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.service_name", QStringLiteral("服务名:")),
        m_operatePage), 0, 0);
    formLayout->addWidget(m_serviceNameEdit, 0, 1);
    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.display_name", QStringLiteral("显示名:")),
        m_operatePage), 0, 2);
    formLayout->addWidget(m_displayNameEdit, 0, 3);
    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.binary_path", QStringLiteral("驱动路径:")),
        m_operatePage), 1, 0);
    formLayout->addWidget(m_binaryPathEdit, 1, 1, 1, 2);
    formLayout->addWidget(m_browsePathButton, 1, 3);
    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.start_type", QStringLiteral("启动类型:")),
        m_operatePage), 2, 0);
    formLayout->addWidget(m_startTypeCombo, 2, 1);
    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.error_control", QStringLiteral("错误控制:")),
        m_operatePage), 2, 2);
    formLayout->addWidget(m_errorControlCombo, 2, 3);
    formLayout->addWidget(new QLabel(
        driverText("driver.form.label.description", QStringLiteral("描述:")),
        m_operatePage), 3, 0);
    formLayout->addWidget(m_descriptionEdit, 3, 1, 1, 3);
    m_operateLayout->addLayout(formLayout);

    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(6);

    m_registerOrUpdateButton = new QPushButton(m_operatePage);
    m_registerOrUpdateButton->setIcon(QIcon(":/Icon/codeeditor_save.svg"));
    m_registerOrUpdateButton->setToolTip(
        driverText("driver.form.register_update.tooltip", QStringLiteral("注册新服务或更新现有服务")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_registerOrUpdateButton);

    m_loadDriverButton = new QPushButton(m_operatePage);
    m_loadDriverButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_loadDriverButton->setToolTip(
        driverText("driver.form.load.tooltip", QStringLiteral("挂载（启动）驱动服务")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_loadDriverButton);

    m_unloadDriverButton = new QPushButton(m_operatePage);
    m_unloadDriverButton->setIcon(QIcon(":/Icon/process_pause.svg"));
    m_unloadDriverButton->setToolTip(
        driverText("driver.form.unload.tooltip", QStringLiteral("卸载（停止）驱动服务")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_unloadDriverButton);

    m_deleteServiceButton = new QPushButton(m_operatePage);
    m_deleteServiceButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_deleteServiceButton->setToolTip(
        driverText("driver.form.delete.tooltip", QStringLiteral("删除驱动服务注册")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_deleteServiceButton);

    m_refreshStateButton = new QPushButton(m_operatePage);
    m_refreshStateButton->setIcon(QIcon(":/Icon/process_refresh.svg"));
    m_refreshStateButton->setToolTip(
        driverText("driver.form.refresh_state.tooltip", QStringLiteral("刷新当前服务状态")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshStateButton);

    actionLayout->addWidget(m_registerOrUpdateButton);
    actionLayout->addWidget(m_loadDriverButton);
    actionLayout->addWidget(m_unloadDriverButton);
    actionLayout->addWidget(m_deleteServiceButton);
    actionLayout->addWidget(m_refreshStateButton);
    actionLayout->addStretch(1);
    m_operateLayout->addLayout(actionLayout);

    m_operateLogOutput = new QPlainTextEdit(m_operatePage);
    m_operateLogOutput->setReadOnly(true);
    m_operateLogOutput->setMaximumBlockCount(1200);
    m_operateLogOutput->setPlaceholderText(
        driverText("driver.form.operation_log.placeholder", QStringLiteral("驱动操作日志显示在这里。")));
    m_operateLayout->addWidget(m_operateLogOutput, 1);

    m_tabWidget->addTab(
        m_operatePage,
        QIcon(":/Icon/process_main.svg"),
        driverText("driver.tab.operations", QStringLiteral("驱动操作")));
}

void DriverDock::initializeDebugOutputTab()
{
    m_debugOutputPage = new QWidget(m_tabWidget);
    m_debugOutputLayout = new QVBoxLayout(m_debugOutputPage);
    m_debugOutputLayout->setContentsMargins(4, 4, 4, 4);
    m_debugOutputLayout->setSpacing(6);

    m_debugToolLayout = new QHBoxLayout();
    m_debugToolLayout->setContentsMargins(0, 0, 0, 0);
    m_debugToolLayout->setSpacing(6);

    m_startCaptureButton = new QPushButton(m_debugOutputPage);
    m_startCaptureButton->setIcon(QIcon(":/Icon/process_start.svg"));
    // 捕获来源与筛选口径并入启动按钮，页首不再常驻一行说明。
    m_startCaptureButton->setToolTip(
        driverText(
            "driver.debug.start.tooltip",
            QStringLiteral("启动调试输出捕获。经 KswordARK R0 回调捕获 DbgPrint/DbgPrintEx/KdPrintEx，只显示通过当前内核调试筛选器的消息。")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_startCaptureButton);

    m_stopCaptureButton = new QPushButton(m_debugOutputPage);
    m_stopCaptureButton->setIcon(QIcon(":/Icon/process_pause.svg"));
    m_stopCaptureButton->setToolTip(
        driverText("driver.debug.stop.tooltip", QStringLiteral("停止调试输出捕获")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_stopCaptureButton);

    m_clearDebugOutputButton = new QPushButton(m_debugOutputPage);
    m_clearDebugOutputButton->setIcon(QIcon(":/Icon/log_clear.svg"));
    m_clearDebugOutputButton->setToolTip(
        driverText("driver.debug.clear.tooltip", QStringLiteral("清空调试输出")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_clearDebugOutputButton);

    m_copyDebugOutputButton = new QPushButton(m_debugOutputPage);
    m_copyDebugOutputButton->setIcon(QIcon(":/Icon/log_copy.svg"));
    m_copyDebugOutputButton->setToolTip(
        driverText("driver.debug.copy.tooltip", QStringLiteral("复制全部调试输出")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_copyDebugOutputButton);

    m_debugCaptureStatusLabel = new QLabel(
        driverText("driver.debug.status.not_started", QStringLiteral("状态：未启动")),
        m_debugOutputPage);
    m_debugCaptureStatusLabel->setWordWrap(true);

    m_debugToolLayout->addWidget(m_startCaptureButton);
    m_debugToolLayout->addWidget(m_stopCaptureButton);
    m_debugToolLayout->addWidget(m_clearDebugOutputButton);
    m_debugToolLayout->addWidget(m_copyDebugOutputButton);
    m_debugToolLayout->addWidget(m_debugCaptureStatusLabel, 1);
    m_debugOutputLayout->addLayout(m_debugToolLayout);

    m_debugOutputEdit = new QPlainTextEdit(m_debugOutputPage);
    m_debugOutputEdit->setReadOnly(true);
    m_debugOutputEdit->setMaximumBlockCount(2000);
    m_debugOutputEdit->setPlaceholderText(
        driverText("driver.debug.output.placeholder", QStringLiteral("调试输出会实时显示在这里。")));
    m_debugOutputLayout->addWidget(m_debugOutputEdit, 1);

    m_tabWidget->addTab(
        m_debugOutputPage,
        QIcon(":/Icon/log_track.svg"),
        driverText("driver.tab.debug_output", QStringLiteral("调试输出")));
}

void DriverDock::initializeObjectInfoTab()
{
    // Phase-9 对象信息页：
    // - 输入 DriverObject 名称，R0 侧自行引用对象；
    // - 页面拆成 DriverObject / DeviceObject / DriverExtension / MajorFunction / FastIo 五个子页；
    // - 所有展示均为只读诊断，不提供写入、补丁或卸载操作。
    m_objectInfoPage = new QWidget(m_tabWidget);
    m_objectInfoLayout = new QVBoxLayout(m_objectInfoPage);
    m_objectInfoLayout->setContentsMargins(4, 4, 4, 4);
    m_objectInfoLayout->setSpacing(6);

    QHBoxLayout* queryLayout = new QHBoxLayout();
    queryLayout->setContentsMargins(0, 0, 0, 0);
    queryLayout->setSpacing(6);

    m_objectDriverNameEdit = new QLineEdit(m_objectInfoPage);
    m_objectDriverNameEdit->setPlaceholderText(
        driverText("driver.object.driver_name.placeholder", QStringLiteral("\\Driver\\Null 或 Null")));
    m_objectDriverNameEdit->setToolTip(
        driverText(
            "driver.object.driver_name.tooltip",
            QStringLiteral("只接受 DriverObject 名称；不要输入内核地址。")));

    m_fillObjectDriverNameButton = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), m_objectInfoPage);
    KswordTheme::ApplyCompactIconButtonMetrics(m_fillObjectDriverNameButton);
    m_fillObjectDriverNameButton->setToolTip(
        driverText(
            "driver.object.fill_driver_name.tooltip",
            QStringLiteral("从驱动服务列表当前选中行填充 \\Driver\\服务名")));

    m_queryObjectInfoButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_objectInfoPage);
    KswordTheme::ApplyCompactIconButtonMetrics(m_queryObjectInfoButton);
    m_queryObjectInfoButton->setToolTip(
        driverText(
            "driver.object.query.tooltip",
            QStringLiteral("通过 KswordARK 查询 DriverObject / DeviceObject")));

    m_objectEvidenceRefreshButton = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), m_objectInfoPage);
    KswordTheme::ApplyCompactIconButtonMetrics(m_objectEvidenceRefreshButton);
    m_objectEvidenceRefreshButton->setToolTip(
        driverText(
            "driver.object.refresh_evidence.tooltip",
            QStringLiteral("仅重建当前 DriverObject / Integrity 证据投影")));

    m_objectInfoStatusLabel = new QLabel(
        driverText("driver.object.status.waiting", QStringLiteral("状态：等待查询")),
        m_objectInfoPage);
    m_objectInfoStatusLabel->setWordWrap(true);

    queryLayout->addWidget(new QLabel(QStringLiteral("DriverObject:"), m_objectInfoPage));
    queryLayout->addWidget(m_objectDriverNameEdit, 1);
    queryLayout->addWidget(m_fillObjectDriverNameButton);
    queryLayout->addWidget(m_queryObjectInfoButton);
    queryLayout->addWidget(m_objectEvidenceRefreshButton);
    queryLayout->addWidget(m_objectInfoStatusLabel, 1);
    m_objectInfoLayout->addLayout(queryLayout);

    // DriverObject 顶部摘要属于 R0 只读诊断文本：
    // - 使用项目统一 CodeEditorWidget，保证深浅色与复制/查找体验一致；
    // - 摘要下方仍有结构化表格承载具体字段，不做 summary-only 展示。
    m_objectInfoSummaryEdit = new CodeEditorWidget(m_objectInfoPage);
    m_objectInfoSummaryEdit->setReadOnly(true);
    m_objectInfoSummaryEdit->setMaximumHeight(145);
    m_objectInfoSummaryEdit->setText(
        driverText("driver.object.summary.initial", QStringLiteral("DriverObject 摘要显示在这里。")));
    m_objectInfoLayout->addWidget(m_objectInfoSummaryEdit);

    m_objectDetailTabWidget = new QTabWidget(m_objectInfoPage);
    m_objectDetailTabWidget->setDocumentMode(true);
    m_objectInfoLayout->addWidget(m_objectDetailTabWidget, 1);

    auto configureReadOnlyTable = [](QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        installDriverTableCopyMenu(table);
    };

    // DriverObject 诊断页：只展示当前对象查询的基础字段和简要证据。
    m_driverObjectPage = new QWidget(m_objectDetailTabWidget);
    QVBoxLayout* driverObjectLayout = new QVBoxLayout(m_driverObjectPage);
    driverObjectLayout->setContentsMargins(0, 0, 0, 0);
    driverObjectLayout->setSpacing(4);
    // DriverObject 子页摘要：
    // - 只显示当前 DriverObject 的核心字段；
    // - 详细证据继续由下方表格展示，文本控件统一为 CodeEditorWidget。
    m_driverObjectPageSummaryEdit = new CodeEditorWidget(m_driverObjectPage);
    m_driverObjectPageSummaryEdit->setReadOnly(true);
    m_driverObjectPageSummaryEdit->setMaximumHeight(130);
    m_driverObjectPageSummaryEdit->setText(
        driverText(
            "driver.object.page_summary.initial",
            QStringLiteral("DriverObject 页摘要显示在这里。")));
    driverObjectLayout->addWidget(m_driverObjectPageSummaryEdit);

    m_driverObjectEvidenceTable = new ks::ui::VisibleTableWidget(m_driverObjectPage);
    m_driverObjectEvidenceTable->setColumnCount(2);
    m_driverObjectEvidenceTable->setHorizontalHeaderLabels(driverObjectEvidenceTableHeaders());
    configureReadOnlyTable(m_driverObjectEvidenceTable);
    m_driverObjectEvidenceTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    driverObjectLayout->addWidget(m_driverObjectEvidenceTable, 1);
    m_objectDetailTabWidget->addTab(m_driverObjectPage, QIcon(":/Icon/process_details.svg"), QStringLiteral("DriverObject"));

    // DeviceObject 诊断页：展示 DriverObject 下挂载的设备链。
    m_deviceObjectPage = new QWidget(m_objectDetailTabWidget);
    QVBoxLayout* deviceLayout = new QVBoxLayout(m_deviceObjectPage);
    deviceLayout->setContentsMargins(0, 0, 0, 0);
    deviceLayout->setSpacing(4);
    deviceLayout->addWidget(new QLabel(
        driverText(
            "driver.object.device_chain.title",
            QStringLiteral("DeviceObject / AttachedDevice 链")),
        m_deviceObjectPage));

    m_deviceObjectTable = new ks::ui::VisibleTableWidget(m_deviceObjectPage);
    m_deviceObjectTable->setColumnCount(10);
    m_deviceObjectTable->setHorizontalHeaderLabels(driverDeviceObjectTableHeaders());
    configureReadOnlyTable(m_deviceObjectTable);
    m_deviceObjectTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    deviceLayout->addWidget(m_deviceObjectTable, 1);
    m_objectDetailTabWidget->addTab(m_deviceObjectPage, QIcon(":/Icon/process_list.svg"), QStringLiteral("DeviceObject"));

    // DriverExtension 诊断页：当前协议不直接暴露 DriverExtension 指针，因此展示关联证据。
    m_driverExtensionPage = new QWidget(m_objectDetailTabWidget);
    QVBoxLayout* driverExtensionLayout = new QVBoxLayout(m_driverExtensionPage);
    driverExtensionLayout->setContentsMargins(0, 0, 0, 0);
    driverExtensionLayout->setSpacing(4);
    m_driverExtensionStatusLabel = new QLabel(
        driverText(
            "driver.object.driver_extension.status.waiting",
            QStringLiteral("状态：等待 DriverObject 查询。")),
        m_driverExtensionPage);
    m_driverExtensionStatusLabel->setWordWrap(true);
    driverExtensionLayout->addWidget(m_driverExtensionStatusLabel);
    m_driverExtensionEvidenceTable = new ks::ui::VisibleTableWidget(m_driverExtensionPage);
    m_driverExtensionEvidenceTable->setColumnCount(6);
    m_driverExtensionEvidenceTable->setHorizontalHeaderLabels(driverEvidenceTableHeaders());
    configureReadOnlyTable(m_driverExtensionEvidenceTable);
    m_driverExtensionEvidenceTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_driverExtensionEvidenceTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    driverExtensionLayout->addWidget(m_driverExtensionEvidenceTable, 1);
    m_objectDetailTabWidget->addTab(m_driverExtensionPage, QIcon(":/Icon/process_critical.svg"), QStringLiteral("DriverExtension"));

    // MajorFunction 诊断页：展示 IRP 分发入口及其模块归属。
    m_majorFunctionPage = new QWidget(m_objectDetailTabWidget);
    QVBoxLayout* majorLayout = new QVBoxLayout(m_majorFunctionPage);
    majorLayout->setContentsMargins(0, 0, 0, 0);
    majorLayout->setSpacing(4);
    majorLayout->addWidget(new QLabel(
        driverText("driver.object.major_function.title", QStringLiteral("MajorFunction 表")),
        m_majorFunctionPage));

    m_majorFunctionTable = new ks::ui::VisibleTableWidget(m_majorFunctionPage);
    m_majorFunctionTable->setColumnCount(5);
    m_majorFunctionTable->setHorizontalHeaderLabels(driverMajorFunctionTableHeaders());
    configureReadOnlyTable(m_majorFunctionTable);
    m_majorFunctionTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    majorLayout->addWidget(m_majorFunctionTable, 1);
    m_objectDetailTabWidget->addTab(m_majorFunctionPage, QIcon(":/Icon/process_threads.svg"), QStringLiteral("MajorFunction"));

    // FastIo 诊断页：当前协议只回填完整性侧证据，因此以证据表方式展示。
    m_fastIoPage = new QWidget(m_objectDetailTabWidget);
    QVBoxLayout* fastIoLayout = new QVBoxLayout(m_fastIoPage);
    fastIoLayout->setContentsMargins(0, 0, 0, 0);
    fastIoLayout->setSpacing(4);
    m_fastIoStatusLabel = new QLabel(
        driverText(
            "driver.object.fast_io.status.waiting",
            QStringLiteral("状态：等待 Driver Integrity 证据。")),
        m_fastIoPage);
    m_fastIoStatusLabel->setWordWrap(true);
    fastIoLayout->addWidget(m_fastIoStatusLabel);
    m_fastIoEvidenceTable = new ks::ui::VisibleTableWidget(m_fastIoPage);
    m_fastIoEvidenceTable->setColumnCount(6);
    m_fastIoEvidenceTable->setHorizontalHeaderLabels(driverEvidenceTableHeaders());
    configureReadOnlyTable(m_fastIoEvidenceTable);
    m_fastIoEvidenceTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_fastIoEvidenceTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    fastIoLayout->addWidget(m_fastIoEvidenceTable, 1);
    m_objectDetailTabWidget->addTab(m_fastIoPage, QIcon(":/Icon/process_pause.svg"), QStringLiteral("FastIo"));

    if (m_objectDetailTabWidget != nullptr)
    {
        m_objectDetailTabWidget->setCurrentIndex(0);
    }

    rebuildDriverObjectEvidenceViews();

    m_tabWidget->addTab(
        m_objectInfoPage,
        QIcon(":/Icon/process_details.svg"),
        driverText("driver.tab.object_info", QStringLiteral("对象信息")));
}

void DriverDock::initializeModuleCrossViewTab()
{
    // 模块 Cross-View 页：
    // - 仅从已缓存的 Driver Integrity 结果投影出 ModuleView / PsLoadedModules / DriverObject / DriverSection 等证据；
    // - 不额外发起危险操作，也不引入新 R0 协议。
    m_moduleCrossViewPage = new QWidget(m_tabWidget);
    m_moduleCrossViewLayout = new QVBoxLayout(m_moduleCrossViewPage);
    m_moduleCrossViewLayout->setContentsMargins(4, 4, 4, 4);
    m_moduleCrossViewLayout->setSpacing(6);

    m_moduleCrossViewToolLayout = new QHBoxLayout();
    m_moduleCrossViewToolLayout->setContentsMargins(0, 0, 0, 0);
    m_moduleCrossViewToolLayout->setSpacing(6);

    m_moduleCrossViewRefreshButton = new QPushButton(m_moduleCrossViewPage);
    m_moduleCrossViewRefreshButton->setIcon(QIcon(":/Icon/process_refresh.svg"));
    m_moduleCrossViewRefreshButton->setToolTip(
        driverText("driver.cross_view.refresh.tooltip", QStringLiteral("刷新 Driver Integrity 并重建模块 Cross-View")));
    KswordTheme::ApplyCompactIconButtonMetrics(m_moduleCrossViewRefreshButton);

    m_moduleCrossViewStatusLabel = new QLabel(
        driverText("driver.cross_view.status.waiting", QStringLiteral("状态：等待刷新")),
        m_moduleCrossViewPage);
    m_moduleCrossViewStatusLabel->setWordWrap(true);

    m_moduleCrossViewToolLayout->addWidget(m_moduleCrossViewRefreshButton);
    m_moduleCrossViewToolLayout->addWidget(m_moduleCrossViewStatusLabel, 1);
    m_moduleCrossViewLayout->addLayout(m_moduleCrossViewToolLayout);

    m_moduleCrossViewTable = new ks::ui::VisibleTableWidget(m_moduleCrossViewPage);
    m_moduleCrossViewTable->setColumnCount(7);
    m_moduleCrossViewTable->setHorizontalHeaderLabels(driverModuleCrossViewTableHeaders());
    m_moduleCrossViewTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_moduleCrossViewTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_moduleCrossViewTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_moduleCrossViewTable->setAlternatingRowColors(true);
    m_moduleCrossViewTable->verticalHeader()->setVisible(false);
    m_moduleCrossViewTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_moduleCrossViewTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_moduleCrossViewTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    installDriverTableCopyMenu(m_moduleCrossViewTable);
    m_moduleCrossViewLayout->addWidget(m_moduleCrossViewTable, 1);

    m_tabWidget->addTab(
        m_moduleCrossViewPage,
        QIcon(":/Icon/process_list.svg"),
        driverText("driver.tab.module_cross_view", QStringLiteral("Module Cross-View")));
    rebuildModuleCrossViewTable();
}

void DriverDock::initializeConnections()
{
    // 概览页：刷新与过滤连接。
    connect(m_refreshServiceButton, &QPushButton::clicked, this, [this]()
        {
            refreshDriverServiceRecords();
        });
    connect(m_refreshModuleButton, &QPushButton::clicked, this, [this]()
        {
            refreshLoadedKernelModuleRecords();
        });
    connect(m_refreshModuleEvidenceButton, &QPushButton::clicked, this, [this]()
        {
            refreshLoadedModuleEvidenceAsync();
        });
    connect(m_serviceFilterEdit, &QLineEdit::textChanged, this, [this](const QString&)
        {
            rebuildDriverServiceTableByFilter();
        });
    connect(m_moduleFilterEdit, &QLineEdit::textChanged, this, [this](const QString&)
        {
            rebuildLoadedModuleTable();
        });

    // 内核模块页：刷新、过滤和统一详情布局连接。
    connect(m_serviceTable, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            syncOperateFormBySelectedService();
        });
    connect(m_serviceTable, &QTableWidget::cellDoubleClicked, this, [this](const int, const int)
        {
            syncOperateFormBySelectedService();
            if (m_tabWidget != nullptr && m_operatePage != nullptr)
            {
                m_tabWidget->setCurrentWidget(m_operatePage);
            }
        });
    connect(m_serviceTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            showServiceTableContextMenu(localPosition);
        });
    connect(m_moduleTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            showModuleTableContextMenu(localPosition);
        });
    connect(m_moduleTable, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            showSelectedModuleEvidenceDetail();
        });

    // 操作页：浏览路径、注册更新、挂载卸载、删除、状态查询。
    connect(m_browsePathButton, &QPushButton::clicked, this, [this]()
        {
            const QString filePath = QFileDialog::getOpenFileName(
                this,
                driverText("driver.dialog.select_file.title", QStringLiteral("选择驱动文件")),
                QString(),
                QStringLiteral("Driver Files (*.sys);;All Files (*.*)"));
            if (!filePath.isEmpty() && m_binaryPathEdit != nullptr)
            {
                m_binaryPathEdit->setText(filePath);
            }
        });
    connect(m_registerOrUpdateButton, &QPushButton::clicked, this, [this]()
        {
            registerOrUpdateDriverService();
        });
    connect(m_loadDriverButton, &QPushButton::clicked, this, [this]()
        {
            loadSelectedDriverService();
        });
    connect(m_unloadDriverButton, &QPushButton::clicked, this, [this]()
        {
            unloadSelectedDriverService();
        });
    connect(m_deleteServiceButton, &QPushButton::clicked, this, [this]()
        {
            deleteSelectedDriverService();
        });
    connect(m_refreshStateButton, &QPushButton::clicked, this, [this]()
        {
            refreshSelectedServiceStateToForm();
        });

    // 调试输出：启动、停止、清空、复制。
    connect(m_startCaptureButton, &QPushButton::clicked, this, [this]()
        {
            startDebugOutputCapture();
        });
    connect(m_stopCaptureButton, &QPushButton::clicked, this, [this]()
        {
            stopDebugOutputCapture();
        });
    connect(m_clearDebugOutputButton, &QPushButton::clicked, this, [this]()
        {
            clearDebugOutputLines();
        });
    connect(m_copyDebugOutputButton, &QPushButton::clicked, this, [this]()
        {
            if (m_debugOutputEdit == nullptr || QGuiApplication::clipboard() == nullptr)
            {
                return;
            }
            QGuiApplication::clipboard()->setText(m_debugOutputEdit->toPlainText());
        });

    // 对象信息页：从服务名填充 DriverObject 名称并执行 R0 查询。
    connect(m_fillObjectDriverNameButton, &QPushButton::clicked, this, [this]()
        {
            fillObjectDriverNameFromSelection();
        });
    connect(m_queryObjectInfoButton, &QPushButton::clicked, this, [this]()
        {
            querySelectedDriverObjectInfo();
        });
    connect(m_objectDriverNameEdit, &QLineEdit::returnPressed, this, [this]()
        {
            querySelectedDriverObjectInfo();
        });
    connect(m_objectEvidenceRefreshButton, &QPushButton::clicked, this, [this]()
        {
            rebuildDriverObjectEvidenceViews();
        });
    connect(m_objectDetailTabWidget, &QTabWidget::currentChanged, this, [this](int)
        {
            rebuildDriverObjectEvidenceViews();
        });

    // 驱动完整性页：所有动作均为只读查询或本地过滤，不提供修复/写入按钮。
    connect(m_integrityRefreshButton, &QPushButton::clicked, this, [this]()
        {
            refreshDriverIntegrityAsync(false);
        });
    connect(m_integrityCpuOnlyButton, &QPushButton::clicked, this, [this]()
        {
            refreshDriverIntegrityAsync(true);
        });
    connect(m_integrityRiskOnlyCheck, &QCheckBox::toggled, this, [this]()
        {
            rebuildDriverIntegrityTable();
            showSelectedDriverIntegrityDetail();
        });
    connect(m_integrityFillFromSelectionButton, &QPushButton::clicked, this, [this]()
        {
            fillObjectDriverNameFromSelection();
            if (m_integrityDriverNameEdit != nullptr && m_objectDriverNameEdit != nullptr)
            {
                m_integrityDriverNameEdit->setText(m_objectDriverNameEdit->text());
            }
        });
    connect(m_integrityTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int)
        {
            showSelectedDriverIntegrityDetail();
        });

    // 证据投影页：只读刷新和表内选择，不触发任何修复动作。
    connect(m_moduleCrossViewRefreshButton, &QPushButton::clicked, this, [this]()
        {
            refreshDriverIntegrityAsync(false);
        });
    connect(m_moduleCrossViewTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int)
        {
            if (m_moduleCrossViewStatusLabel != nullptr && m_moduleCrossViewTable != nullptr)
            {
                m_moduleCrossViewStatusLabel->setText(
                    driverText("driver.cross_view.status.projected", QStringLiteral("状态：当前显示 %1 条投影证据。"))
                    .arg(m_moduleCrossViewTable->rowCount()));
            }
        });

    // 已卸载驱动页本身仍由 DriverDock.Unloaded.cpp 唯一构建和连接。
    // 这里仅附加远端已有的 PiDDB 精确管理动作，不重复查询、过滤、详情或复制连接。
    if (m_unloadedPiddbPage != nullptr &&
        m_unloadedPiddbSourceLayout != nullptr &&
        m_unloadedPiddbTable != nullptr &&
        m_unloadedPiddbRefreshButton != nullptr &&
        m_unloadedPiddbMmSourceRadio != nullptr &&
        m_unloadedPiddbPiDdbSourceRadio != nullptr &&
        m_unloadedPiddbCiSourceRadio != nullptr)
    {
        m_unloadedPiddbDeleteButton = new QPushButton(
            driverText(
                "driver.unloaded.delete_exact",
                QStringLiteral("删除选中 PiDDB 表项")),
            m_unloadedPiddbPage);
        m_unloadedPiddbDeleteButton->setStyleSheet(
            KswordTheme::ThemedButtonStyle());
        m_unloadedPiddbDeleteButton->setEnabled(false);
        m_unloadedPiddbSourceLayout->insertWidget(
            m_unloadedPiddbSourceLayout->indexOf(
                m_unloadedPiddbRefreshButton),
            m_unloadedPiddbDeleteButton);

        connect(
            m_unloadedPiddbDeleteButton,
            &QPushButton::clicked,
            this,
            &DriverDock::deleteSelectedPiDdbEntry);
        connect(
            m_unloadedPiddbTable,
            &QTableWidget::currentCellChanged,
            this,
            [this](int, int, int, int) {
                if (m_unloadedPiddbDeleteButton != nullptr)
                {
                    m_unloadedPiddbDeleteButton->setEnabled(
                        selectedPiDdbEntryIdentity(nullptr));
                }
            });
        connect(
            m_unloadedPiddbRefreshButton,
            &QPushButton::clicked,
            this,
            [this]() {
                if (m_unloadedPiddbDeleteButton != nullptr)
                {
                    m_unloadedPiddbDeleteButton->setEnabled(false);
                }
            });
        const auto disableDeleteOnSourceChange =
            [this](const bool) {
                if (m_unloadedPiddbDeleteButton != nullptr)
                {
                    m_unloadedPiddbDeleteButton->setEnabled(false);
                }
            };
        connect(
            m_unloadedPiddbMmSourceRadio,
            &QRadioButton::toggled,
            this,
            disableDeleteOnSourceChange);
        connect(
            m_unloadedPiddbPiDdbSourceRadio,
            &QRadioButton::toggled,
            this,
            disableDeleteOnSourceChange);
        connect(
            m_unloadedPiddbCiSourceRadio,
            &QRadioButton::toggled,
            this,
            disableDeleteOnSourceChange);
    }
}
