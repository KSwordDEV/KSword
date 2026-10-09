#include "ScannerDock.h"
#include "../UI/FlatButtonTheme.h"

#include "Internationalization/LanguageManager.h"
#include "ksword/scanner/binary_scanner.h"
#include "theme.h"

#include <QAction>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <memory>
#include <vector>

namespace
{
    // fromBackendUtf8 作用：把扫描后端的 UTF-8 标识与回退文本转换为 Qt 字符串。
    QString fromBackendUtf8(const std::string& value)
    {
        return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
    }
}

QString ScannerDock::localizedTableTitle(
    const std::string& tableId,
    const std::string& fallback) const
{
    const QString id = fromBackendUtf8(tableId).toLower();
    if (id == QStringLiteral("sections"))
    {
        return translated("scanner.table.sections", "节区");
    }
    if (id == QStringLiteral("segments"))
    {
        return translated("scanner.table.segments", "段");
    }
    if (id == QStringLiteral("imports"))
    {
        return translated("scanner.table.imports", "导入");
    }
    if (id == QStringLiteral("exports"))
    {
        return translated("scanner.table.exports", "导出");
    }
    if (id == QStringLiteral("symbols"))
    {
        return translated("scanner.table.symbols", "符号");
    }
    if (id == QStringLiteral("load_commands"))
    {
        return translated("scanner.table.load_commands", "加载命令");
    }
    if (id == QStringLiteral("fat_architectures") ||
        id == QStringLiteral("architectures") ||
        id == QStringLiteral("slices"))
    {
        return translated("scanner.table.architectures", "架构切片");
    }
    if (id == QStringLiteral("dynamic_entries") ||
        id == QStringLiteral("dynamic_dependencies"))
    {
        return translated("scanner.table.dynamic_entries", "动态链接条目");
    }
    if (id == QStringLiteral("dynamic_libraries"))
    {
        return translated("scanner.table.dynamic_libraries", "动态库");
    }
    if (id == QStringLiteral("program_headers"))
    {
        return translated("scanner.table.program_headers", "程序头");
    }
    if (id == QStringLiteral("container_entries"))
    {
        return translated("scanner.table.container_entries", "容器成员");
    }
    return ks::i18n::sourceText(fromBackendUtf8(fallback));
}

QString ScannerDock::localizedColumnTitle(const std::string& fallback) const
{
    const QString value = fromBackendUtf8(fallback);
    const QString normalized = value.trimmed().toLower();
    if (normalized == QStringLiteral("name"))
    {
        return translated("scanner.column.name", "名称");
    }
    if (normalized == QStringLiteral("value"))
    {
        return translated("scanner.column.value", "值");
    }
    if (normalized == QStringLiteral("index"))
    {
        return translated("scanner.column.index", "索引");
    }
    if (normalized == QStringLiteral("type"))
    {
        return translated("scanner.column.type", "类型");
    }
    if (normalized == QStringLiteral("flags"))
    {
        return translated("scanner.column.flags", "标志");
    }
    if (normalized == QStringLiteral("offset") || normalized == QStringLiteral("file offset"))
    {
        return translated("scanner.column.offset", "偏移");
    }
    if (normalized == QStringLiteral("size") || normalized == QStringLiteral("file size"))
    {
        return translated("scanner.column.size", "大小");
    }
    if (normalized == QStringLiteral("address") ||
        normalized == QStringLiteral("virtual address"))
    {
        return translated("scanner.column.address", "地址");
    }
    if (normalized == QStringLiteral("format"))
    {
        return translated("scanner.column.format", "格式");
    }
    if (normalized == QStringLiteral("byte order"))
    {
        return translated("scanner.column.byte_order", "字节序");
    }
    if (normalized == QStringLiteral("module") || normalized == QStringLiteral("library"))
    {
        return translated("scanner.column.module", "模块");
    }
    if (normalized == QStringLiteral("ordinal"))
    {
        return translated("scanner.column.ordinal", "序号");
    }
    if (normalized == QStringLiteral("path"))
    {
        return translated("scanner.column.path", "路径");
    }
    if (normalized == QStringLiteral("extent"))
    {
        return translated("scanner.column.extent", "区段号");
    }
    if (normalized == QStringLiteral("volume id"))
    {
        return translated("scanner.column.volume_id", "卷标识");
    }
    if (normalized == QStringLiteral("filename encoding"))
    {
        return translated("scanner.column.filename_encoding", "文件名编码");
    }
    if (normalized == QStringLiteral("logical block size"))
    {
        return translated("scanner.column.logical_block_size", "逻辑块大小");
    }
    if (normalized == QStringLiteral("container entries"))
    {
        return translated("scanner.column.container_entries", "容器成员数");
    }
    if (normalized == QStringLiteral("volume descriptor offset"))
    {
        return translated("scanner.column.volume_descriptor_offset", "卷描述符偏移");
    }
    if (normalized == QStringLiteral("root directory extent"))
    {
        return translated("scanner.column.root_directory_extent", "根目录区段号");
    }
    if (normalized == QStringLiteral("root directory size"))
    {
        return translated("scanner.column.root_directory_size", "根目录大小");
    }
    return ks::i18n::sourceText(value);
}

QString ScannerDock::localizedTableValue(
    const std::string& tableId,
    const int column,
    const std::string& fallback) const
{
    const QString id = fromBackendUtf8(tableId).toLower();
    const QString value = fromBackendUtf8(fallback);
    if (id == QStringLiteral("container_entries") && column == 1)
    {
        if (value == QStringLiteral("Directory"))
        {
            return translated("scanner.container.type.directory", "目录");
        }
        if (value == QStringLiteral("File"))
        {
            return translated("scanner.container.type.file", "文件");
        }
        if (value == QStringLiteral("File (multi-extent)"))
        {
            return translated("scanner.container.type.multi_extent", "文件（多区段）");
        }
    }
    return ks::i18n::sourceText(value);
}

QString ScannerDock::localizedDiagnosticMessage(
    const std::string& code,
    const std::string& fallback) const
{
    const QString id = fromBackendUtf8(code).toLower();
    if (id == QStringLiteral("iso.volume_descriptor_invalid"))
    {
        return translated("scanner.diagnostic.iso.volume_invalid", "ISO9660 卷描述符或根目录无效。");
    }
    if (id == QStringLiteral("iso.directory_record_invalid"))
    {
        return translated("scanner.diagnostic.iso.directory_invalid", "ISO9660 目录记录被截断或格式错误。");
    }
    if (id == QStringLiteral("iso.identifier_invalid"))
    {
        return translated("scanner.diagnostic.iso.identifier_invalid", "ISO9660 文件标识超出目录记录范围。");
    }
    if (id == QStringLiteral("iso.extent_mismatch"))
    {
        return translated("scanner.diagnostic.iso.extent_mismatch", "ISO9660 区段的小端与大端副本不一致。");
    }
    if (id == QStringLiteral("iso.extent_out_of_bounds"))
    {
        return translated("scanner.diagnostic.iso.extent_out_of_bounds", "ISO9660 成员区段超出镜像快照。");
    }
    if (id == QStringLiteral("iso.entry_limit_reached"))
    {
        return translated("scanner.diagnostic.iso.entry_limit", "ISO9660 遍历已在成员数量上限处停止。");
    }
    if (id == QStringLiteral("iso.read_only_analysis"))
    {
        return translated("scanner.diagnostic.iso.read_only", "镜像仅从稳定字节快照解析；未挂载镜像，也未执行成员。");
    }
    return ks::i18n::sourceText(fromBackendUtf8(fallback));
}

QString ScannerDock::diagnosticSeverityText(const int severity) const
{
    switch (static_cast<ks::scanner::DiagnosticSeverity>(severity))
    {
    case ks::scanner::DiagnosticSeverity::Information:
        return translated("scanner.severity.information", "信息");
    case ks::scanner::DiagnosticSeverity::Warning:
        return translated("scanner.severity.warning", "警告");
    case ks::scanner::DiagnosticSeverity::Error:
        return translated("scanner.severity.error", "错误");
    default:
        return translated("scanner.severity.unknown", "未知");
    }
}

QString ScannerDock::attackPathSeverityText(const int severity) const
{
    switch (static_cast<ks::scanner::AttackPathSeverity>(severity))
    {
    case ks::scanner::AttackPathSeverity::Information:
        return translated("scanner.attack.severity.information", "信息");
    case ks::scanner::AttackPathSeverity::Suspicious:
        return translated("scanner.attack.severity.suspicious", "可疑");
    case ks::scanner::AttackPathSeverity::High:
        return translated("scanner.attack.severity.high", "高危");
    case ks::scanner::AttackPathSeverity::Critical:
        return translated("scanner.attack.severity.critical", "严重");
    default:
        return translated("scanner.severity.unknown", "未知");
    }
}

QString ScannerDock::attackPathStageText(const std::string& stage) const
{
    const QString id = fromBackendUtf8(stage).toLower();
    if (id == QStringLiteral("sideload"))
    {
        return translated("scanner.attack.stage.sideload", "DLL 侧载");
    }
    if (id == QStringLiteral("elevation"))
    {
        return translated("scanner.attack.stage.elevation", "权限提升");
    }
    if (id == QStringLiteral("masquerade"))
    {
        return translated("scanner.attack.stage.masquerade", "进程伪装");
    }
    if (id == QStringLiteral("payload_decode"))
    {
        return translated("scanner.attack.stage.payload_decode", "载荷解码");
    }
    if (id == QStringLiteral("persistence"))
    {
        return translated("scanner.attack.stage.persistence", "驱动服务");
    }
    if (id == QStringLiteral("defense_evasion"))
    {
        return translated("scanner.attack.stage.defense_evasion", "防护破坏");
    }
    return ks::i18n::sourceText(fromBackendUtf8(stage));
}

QString ScannerDock::attackPathEvidenceText(const std::string& code) const
{
    const QString id = fromBackendUtf8(code).toLower();
    if (id == QStringLiteral("container.libcef_sideload_pair"))
    {
        return translated("scanner.attack.evidence.sideload_pair", "容器内 PE 的导入表指向同目录 libcef.dll。");
    }
    if (id == QStringLiteral("proxy.cef_surface"))
    {
        return translated("scanner.attack.evidence.cef_surface", "DLL 提供 cef_execute_process、cef_initialize 等 CEF 代理导出。");
    }
    if (id == QStringLiteral("proxy.cmstplua_uac"))
    {
        return translated("scanner.attack.evidence.cmstplua", "发现 CMSTPLUA 提权 moniker、CoGetObject 与管理员令牌检查组合。");
    }
    if (id == QStringLiteral("proxy.peb_masquerade"))
    {
        return translated("scanner.attack.evidence.peb_masquerade", "发现把 PEB 进程参数改写为 C:\\Windows\\explorer.exe 的组合证据。");
    }
    if (id == QStringLiteral("proxy.driver_service"))
    {
        return translated("scanner.attack.evidence.driver_service", "发现创建并启动 GhostSystemDriver 内核驱动服务的组合证据。");
    }
    if (id == QStringLiteral("proxy.avp_evasion"))
    {
        return translated("scanner.attack.evidence.avp_evasion", "提权/驱动投递路径同时检查 avp.exe，符合安全软件规避。");
    }
    if (id == QStringLiteral("embedded.double_base64_driver"))
    {
        return translated("scanner.attack.evidence.embedded_driver", "UTF-16 Base64 经两层 Base64 和十六进制解码后得到 PE 驱动。");
    }
    if (id == QStringLiteral("driver.defender_registry"))
    {
        return translated("scanner.attack.evidence.defender_registry", "驱动同时修改 TamperProtection、实时防护和多个 Defender 服务键。");
    }
    if (id == QStringLiteral("driver.security_process_kill"))
    {
        return translated("scanner.attack.evidence.process_kill", "驱动导入 ZwTerminateProcess 并包含多家安全产品进程目标。");
    }
    if (id == QStringLiteral("driver.unload_360"))
    {
        return translated("scanner.attack.evidence.unload_360", "驱动调用 ZwUnloadDriver 并清理 360 注册表树。");
    }
    return fromBackendUtf8(code);
}

QWidget* ScannerDock::createAttackPathPage(
    const ks::scanner::BinaryScanResult& result) const
{
    auto* page = new QWidget(m_resultTabs); // page：攻击路径结论与证据表的容器。
    auto* layout = new QVBoxLayout(page); // layout：先显示结论，再显示逐条证据。
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);

    auto* verdictLabel = new QLabel(page); // verdictLabel：展示最终阈值判定和规则版本。
    verdictLabel->setWordWrap(true);
    verdictLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    verdictLabel->setText(
        result.attackPath.matched
            ? translated(
                "scanner.attack.verdict.detected",
                "检测到 EXIT / GhostSystemDriver 攻击路径：评分 %1/100，规则 %2。")
                .arg(result.attackPath.score)
                .arg(fromBackendUtf8(result.attackPath.ruleId))
            : translated(
                "scanner.attack.verdict.below_threshold",
                "发现相关静态证据，但未达到攻击路径阈值：评分 %1/100，规则 %2。")
                .arg(result.attackPath.score)
                .arg(fromBackendUtf8(result.attackPath.ruleId)));
    layout->addWidget(verdictLabel);

    auto* table = createReadOnlyTable(page); // table：每行对应一个可复核证据与原始偏移。
    table->setColumnCount(7);
    table->setHorizontalHeaderLabels({
        translated("scanner.column.severity", "级别"),
        translated("scanner.attack.column.stage", "阶段"),
        translated("scanner.attack.column.evidence", "静态证据"),
        translated("scanner.attack.column.artifact", "对象"),
        QStringLiteral("MITRE ATT&CK"),
        translated("scanner.attack.column.score", "评分"),
        translated("scanner.column.offset", "偏移")
    });
    table->setRowCount(static_cast<int>(result.attackPath.evidence.size()));
    for (int row = 0; row < table->rowCount(); ++row)
    {
        const auto& evidence = result.attackPath.evidence[static_cast<std::size_t>(row)];
        table->setItem(row, 0, new QTableWidgetItem(
            attackPathSeverityText(static_cast<int>(evidence.severity))));
        table->setItem(row, 1, new QTableWidgetItem(attackPathStageText(evidence.stage)));
        table->setItem(row, 2, new QTableWidgetItem(attackPathEvidenceText(evidence.code)));
        table->setItem(row, 3, new QTableWidgetItem(fromBackendUtf8(evidence.artifact)));
        table->setItem(row, 4, new QTableWidgetItem(fromBackendUtf8(evidence.mitreTechnique)));
        table->setItem(row, 5, new QTableWidgetItem(QStringLiteral("+%1").arg(evidence.score)));
        table->setItem(
            row,
            6,
            new QTableWidgetItem(
                evidence.hasOffset
                    ? QStringLiteral("0x%1").arg(evidence.offset, 0, 16).toUpper()
                    : translated("scanner.attack.offset.decoded", "解码后对象")));
    }
    table->resizeColumnsToContents();
    layout->addWidget(table, 1);
    return page;
}

QWidget* ScannerDock::createStructuredTablePage(
    QTableWidget* table,
    const int columnCount) const
{
    // 五列以内无需拆组；返回原表可避免增加无意义的控制条。
    if (table == nullptr || columnCount <= 5)
    {
        return table;
    }

    // page/pageLayout：宽表页由紧贴的 A/B/C 控件和原只读表组成。
    auto* page = new QWidget(m_resultTabs); // page：本结构表的外层页面。
    auto* pageLayout = new QVBoxLayout(page); // pageLayout：纵向排列列组按钮与数据表。
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(4);
    auto* buttonLayout = new QHBoxLayout(); // buttonLayout：无间距排列 A/B/C 按钮。
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(0);

    // groupCount：最多三组；第一列作为识别键在各组保留，其余列平均分配。
    const int remainingColumns = columnCount - 1; // remainingColumns：除识别列外的字段数。
    const int groupCount = std::clamp((remainingColumns + 3) / 4, 2, 3); // groupCount：实际列组数。
    const int columnsPerGroup = (remainingColumns + groupCount - 1) / groupCount; // columnsPerGroup：每组字段上限。
    auto groups = std::make_shared<std::vector<std::vector<int>>>(); // groups：每个预设显示的列索引。
    auto buttons = std::make_shared<std::vector<QPointer<QPushButton>>>(); // buttons：可安全失效的列组按钮。

    // activeStyle/inactiveStyle：当前预设使用主题强调色；自定义显隐时全部取消着色。
    // A/B/C 的强调状态仍由列预设决定；自定义布局保持中性实心底色。
    const QString activeStyle = ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Accent)
        + QStringLiteral("QPushButton{padding:3px 10px;}");
    const QString inactiveStyle = ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Neutral)
        + QStringLiteral("QPushButton{padding:3px 10px;}");

    for (int groupIndex = 0; groupIndex < groupCount; ++groupIndex)
    {
        // columns：每组保留第 0 列，并加入属于本组的互补字段。
        std::vector<int> columns{ 0 }; // columns：当前 A/B/C 预设的可见列。
        const int firstColumn = 1 + groupIndex * columnsPerGroup; // firstColumn：当前分组首列。
        const int endColumn = std::min(columnCount, firstColumn + columnsPerGroup); // endColumn：当前分组尾后列。
        for (int column = firstColumn; column < endColumn; ++column)
        {
            columns.push_back(column);
        }
        groups->push_back(std::move(columns));

        // groupButton：A/B/C 采用紧贴布局，并通过悬停说明当前行为。
        const char16_t groupLetter = static_cast<char16_t>(u'A' + groupIndex); // groupLetter：当前组的字母标识。
        auto* groupButton = new QPushButton(
            QString(QChar(groupLetter)),
            page); // groupButton：切换到当前互补字段组。
        groupButton->setMinimumWidth(36);
        groupButton->setToolTip(
            translated(
                "scanner.column_view.tooltip",
                "列组 %1：显示一组互补字段；可在表头右键自定义列。")
                .arg(groupButton->text()));
        groupButton->setStyleSheet(groupIndex == 0 ? activeStyle : inactiveStyle);
        buttons->push_back(groupButton);
        buttonLayout->addWidget(groupButton);
    }
    buttonLayout->addStretch(1);
    pageLayout->addLayout(buttonLayout);
    pageLayout->addWidget(table, 1);

    // applyGroup：切换预设时先隐藏所有列，再仅显示目标组并更新按钮主题。
    const auto applyGroup =
        [table, groups, buttons, activeStyle, inactiveStyle](const int groupIndex)
        {
            for (int column = 0; column < table->columnCount(); ++column)
            {
                table->setColumnHidden(column, true);
            }
            for (const int column : groups->at(static_cast<std::size_t>(groupIndex)))
            {
                table->setColumnHidden(column, false);
            }
            for (int buttonIndex = 0; buttonIndex < static_cast<int>(buttons->size()); ++buttonIndex)
            {
                if (buttons->at(static_cast<std::size_t>(buttonIndex)))
                {
                    buttons->at(static_cast<std::size_t>(buttonIndex))->setStyleSheet(
                        buttonIndex == groupIndex ? activeStyle : inactiveStyle);
                }
            }
        };

    for (int groupIndex = 0; groupIndex < static_cast<int>(buttons->size()); ++groupIndex)
    {
        // groupButton：当前按钮连接到自己的预设索引，点击不会改变表内数据。
        QPushButton* groupButton = buttons->at(static_cast<std::size_t>(groupIndex)); // groupButton：待连接按钮。
        connect(
            groupButton,
            &QPushButton::clicked,
            page,
            [applyGroup, groupIndex]() { applyGroup(groupIndex); });
    }
    applyGroup(0);

    // 表头右键菜单允许逐列显隐；每次手动调整后取消 A/B/C 激活色，表示自定义布局。
    QHeaderView* tableHeader = table->horizontalHeader(); // tableHeader：承载列菜单的表头。
    tableHeader->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(
        tableHeader,
        &QHeaderView::customContextMenuRequested,
        page,
        [this, table, tableHeader, buttons, inactiveStyle](const QPoint& position)
        {
            QMenu menu(tableHeader); // menu：仅在当前右键操作期间存在的列显隐菜单。
            menu.setStyleSheet(QStringLiteral(
                "QMenu { background:%1; color:%2; border:1px solid %3; }"
                "QMenu::item { padding:5px 22px; }"
                "QMenu::item:selected { background:%4; color:%5; }"
                "QMenu::item:disabled { color:%6; }")
                .arg(
                    KswordTheme::SurfaceHex(),
                    KswordTheme::TextPrimaryHex(),
                    KswordTheme::BorderHex(),
                    KswordTheme::AccentHex(KswordTheme::AccentRole::Blue),
                    KswordTheme::OnAccentDynamicHex(),
                    KswordTheme::TextDisabledColorHex()));

            // columnAction：勾选状态直接反映当前列可见性。
            for (int column = 0; column < table->columnCount(); ++column)
            {
                QAction* columnAction = menu.addAction( // columnAction：控制单列显隐的菜单项。
                    table->horizontalHeaderItem(column) != nullptr
                        ? table->horizontalHeaderItem(column)->text()
                        : translated("scanner.column.unnamed", "未命名列"));
                columnAction->setCheckable(true);
                columnAction->setChecked(!table->isColumnHidden(column));
                connect(
                    columnAction,
                    &QAction::toggled,
                    &menu,
                    [table, column, buttons, inactiveStyle](const bool visible)
                    {
                        table->setColumnHidden(column, !visible);
                        for (const QPointer<QPushButton>& button : *buttons)
                        {
                            if (button)
                            {
                                button->setStyleSheet(inactiveStyle);
                            }
                        }
                    });
            }
            menu.exec(tableHeader->mapToGlobal(position));
        });
    return page;
}
