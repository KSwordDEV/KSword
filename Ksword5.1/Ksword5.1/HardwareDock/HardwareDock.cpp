#include "HardwareDock.h"
#include "../../../shared/ui/KsPainterChart.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "DiskMonitorPage.h"
#include "MemoryCompositionHistoryWidget.h"
#include "HardwarePowerPage.h"
#include "HardwareR0EvidencePage.h"
#include "HardwareOtherDevicesPage.h"
#include "HardwareDeviceManagerPage.h"
#include "HardwareHwidDispatchPage.h"
#include "HardwareI8042AuditPage.h"
#include "../Internationalization/LanguageManager.h"

// ============================================================
// HardwareDock.cpp
// 作用：
// 1) 提供利用率优先的硬件监控视图与硬件总览；
// 2) 利用 PDH + Power API 周期采样 CPU/内存/每核频率；
// 3) 显卡与内存模块信息通过 PowerShell/WMI 文本化展示。
// ============================================================

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../theme.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/PerformanceNavCard.h"

#include <QAbstractScrollArea>
#include <QAbstractItemView>
#include <QAction>
#include <QBrush>
#include <QClipboard>
#include <QCoreApplication>
#include <QDateTime>
#include <QEasingCurve>
#include <QEvent>
#include <QFrame>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QList>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPainter>
#include <QPen>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QRunnable>
#include <QScrollArea>
#include <QShowEvent>
#include <QSizePolicy>
#include <QSplitter>
#include <QStackedWidget>
#include <QTabBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariant>
#include <QVariantAnimation>

#include <algorithm>
#include <atomic>
#include <bit>
#include <cmath>
#include <cstring>
#include <limits>
#include <mutex>
#include <thread>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <intrin.h>
#include <Objbase.h>
#include <Pdh.h>
#include <pdhmsg.h>
#include <PowrProf.h>
#include <Psapi.h>
#include <d3dkmthk.h>
#include <dxgi1_6.h>
#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "PowrProf.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "Dxgi.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace
{
    // hardwareR0QueryMutex 用途：
    // - 串行化 HardwareDock 内的健康快照与设备审计 IOCTL；
    // - 避免自动刷新和快速切页同时向同一驱动设备提交大体积查询。
    std::mutex hardwareR0QueryMutex;

    // queryPowerShellTextSync 前置声明：
    // - 供下方硬件摘要函数调用；
    // - 实际定义位于同命名空间后半段。
    QString queryPowerShellTextSync(const QString& scriptText, int timeoutMs);

    // createReadOnlyTextPage 作用：
    // - 输入父控件、标题与提示文本；
    // - 处理：创建“标题 + 说明 + CodeEditorWidget”标准只读页面；
    // - 返回：已初始化的页面控件。
    QWidget* createReadOnlyTextPage(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& hintText,
        CodeEditorWidget** editorOut)
    {
        QWidget* pageWidget = new QWidget(parentWidget);
        QVBoxLayout* pageLayout = new QVBoxLayout(pageWidget);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(6);

        QLabel* titleLabel = new QLabel(titleText, pageWidget);
        // 页面口径挂在标题上，不再单独占一行：四个只读审计页共用这个工厂，省下的是四行版面。
        titleLabel->setToolTip(hintText);
        titleLabel->setStyleSheet(
            QStringLiteral("font-size:18px;font-weight:700;color:%1;")
            .arg(KswordTheme::TextPrimaryHex()));
        pageLayout->addWidget(titleLabel, 0);

        CodeEditorWidget* editor = new CodeEditorWidget(pageWidget);
        editor->setReadOnly(true);
        pageLayout->addWidget(editor, 1);

        if (editorOut != nullptr)
        {
            *editorOut = editor;
        }
        return pageWidget;
    }

    // hardwareDeviceAuditTableHeaders 作用：
    // - 输入：无；
    // - 处理：集中定义硬件设备审计明细表列，三类设备页保持一致；
    // - 返回：表头列表，调用方直接传给 QTableWidget。
    QStringList hardwareDeviceAuditTableHeaders()
    {
        return QStringList{
            QStringLiteral("Profile"),
            QStringLiteral("行类型"),
            QStringLiteral("角色"),
            QStringLiteral("状态"),
            QStringLiteral("风险"),
            QStringLiteral("置信度"),
            QStringLiteral("链路深度"),
            QStringLiteral("附加深度"),
            QStringLiteral("驱动"),
            QStringLiteral("服务"),
            QStringLiteral("ImagePath"),
            QStringLiteral("设备"),
            QStringLiteral("DriverObject"),
            QStringLiteral("DeviceObject/AttachedDevice"),
            QStringLiteral("Attached/NextAttached"),
            QStringLiteral("NextDevice/Next"),
            QStringLiteral("OwnerDriver"),
            QStringLiteral("DeviceType"),
            QStringLiteral("DeviceFlags"),
            QStringLiteral("StackSize"),
            QStringLiteral("Alignment"),
            QStringLiteral("FieldFlags"),
            QStringLiteral("LastStatus"),
            QStringLiteral("IntegrityStatus"),
            QStringLiteral("IntegrityRows"),
            QStringLiteral("Modules"),
            QStringLiteral("IntegrityFlags"),
            QStringLiteral("备注")
        };
    }

    // hardwareAuditTableCellText 作用：
    // - 输入：表格、行号、列号；
    // - 处理：安全读取单元格文本；
    // - 返回：不存在时返回空字符串。
    QString hardwareAuditTableCellText(QTableWidget* table, const int rowIndex, const int columnIndex)
    {
        if (table == nullptr)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
        return item != nullptr ? item->text() : QString();
    }

    // copyHardwareAuditCurrentRow 作用：
    // - 输入：目标设备审计表格；
    // - 处理：把当前行按 TSV 写入剪贴板；
    // - 返回：无，不触发任何 R0/R3 查询。
    void copyHardwareAuditCurrentRow(QTableWidget* table)
    {
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
            fields.push_back(hardwareAuditTableCellText(table, rowIndex, columnIndex));
        }
        QGuiApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    // installHardwareAuditCopyMenu 作用：
    // - 输入：需要右键复制的设备审计表格；
    // - 处理：安装带显式样式的“复制当前行”菜单，避免透明菜单黑底黑字；
    // - 返回：无，菜单动作仅复制文本。
    void installHardwareAuditCopyMenu(QTableWidget* table)
    {
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

            QMenu menu(table);
            menu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyHardwareAuditCurrentRow(table);
            }
        });
    }

    // rowMatchesDeviceAuditFilter 作用：
    // - 输入：设备审计表、行号和过滤文本；
    // - 处理：在该行全部可见字段中做大小写不敏感搜索；
    // - 返回：true 表示该行保留显示，false 表示本地隐藏。
    bool rowMatchesDeviceAuditFilter(
        QTableWidget* table,
        const int rowIndex,
        const QString& filterText)
    {
        if (table == nullptr || filterText.trimmed().isEmpty())
        {
            return true;
        }

        const QString normalizedFilterText = filterText.trimmed();
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            const QString cellText = item != nullptr ? item->text() : QString();
            if (cellText.contains(normalizedFilterText, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    // applyDeviceAuditTableFilter 作用：
    // - 输入：设备审计表和搜索框文本；
    // - 处理：仅通过 setRowHidden 本地过滤，避免重复 R0 查询；
    // - 返回：无，空表格指针直接忽略。
    void applyDeviceAuditTableFilter(QTableWidget* table, const QString& filterText)
    {
        if (table == nullptr)
        {
            return;
        }

        const QString normalizedFilterText = filterText.trimmed();
        for (int rowIndex = 0; rowIndex < table->rowCount(); ++rowIndex)
        {
            table->setRowHidden(
                rowIndex,
                !rowMatchesDeviceAuditFilter(table, rowIndex, normalizedFilterText));
        }
    }

    // buildDeviceAuditSearchStyle 作用：
    // - 输入：无；
    // - 处理：复用全局主题色创建搜索框样式；
    // - 返回：QLineEdit stylesheet 文本。
    QString buildDeviceAuditSearchStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %1;border-radius:4px;padding:4px 6px;color:%2;background:transparent;/* %3 */}"
            "QLineEdit:focus{border:1px solid %4;}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::PrimaryBlueHex);
    }

    // deviceAuditColumnGroupA 作用：
    // - 输入：无；
    // - 处理：定义设备审计默认 A 组列，优先展示定位风险和链路关系所需字段；
    // - 返回：应显示的列索引集合，调用方按索引隐藏其它列。
    QVector<int> deviceAuditColumnGroupA()
    {
        return QVector<int>{
            0,  // Profile：区分 DeviceStack/InputStack/UsbTopology。
            1,  // 行类型：区分 DriverSummary 与 DeviceRow。
            2,  // 角色：展示 PDO/FDO/filter/controller 等角色。
            3,  // 状态：展示 R0 单行状态。
            4,  // 风险：展示 Clean/IntegrityPartial/CrossDriverAttach 等风险。
            8,  // 驱动：展示 DriverObject 名称。
            11, // 设备：展示 DeviceObject 友好占位名。
            22  // LastStatus：展示底层 NTSTATUS。
        };
    }

    // deviceAuditColumnGroupB 作用：
    // - 输入：无；
    // - 处理：定义设备审计 B 组精简诊断列，和 A 组形成不同视角而不是扩展全集；
    // - 返回：应显示的列索引集合，只保留少量身份列和服务/flags/integrity 诊断字段。
    QVector<int> deviceAuditColumnGroupB()
    {
        return QVector<int>{
            0,  // Profile：保留页面来源上下文。
            8,  // 驱动：展示 DriverObject 名称。
            6,  // 链路深度：展示 NextDevice/DeviceObject 链深度。
            7,  // 附加深度：展示 AttachedDevice 链深度。
            12, // DriverObject：保留对象地址上下文。
            13, // DeviceObject/AttachedDevice：保留设备对象地址上下文。
            14, // Attached/NextAttached：保留附加链地址上下文。
            15, // NextDevice/Next：保留设备链地址上下文。
            16  // OwnerDriver：展示附加对象 owner。
        };
    }

    // deviceAuditColumnGroupC 作用：
    // - 输入：无；
    // - 处理：定义设备审计 C 组精简诊断列，专门承载服务路径、字段 flags 和完整性摘要；
    // - 返回：应显示的列索引集合，和其它列组互补以降低单视图拥挤度。
    QVector<int> deviceAuditColumnGroupC()
    {
        return QVector<int>{
            0,  // Profile：保留页面来源上下文。
            9,  // 服务：展示 service leaf。
            10, // ImagePath：展示映像路径字段。
            21, // FieldFlags：展示字段有效性。
            23, // IntegrityStatus：展示 DriverIntegrity status。
            24, // IntegrityRows：展示 returned/total。
            25, // Modules：展示模块数量。
            26, // IntegrityFlags：展示 DriverIntegrity statusFlags。
            27  // 备注：展示无法结构化归列的差异信息。
        };
    }

    // containsColumnIndex 作用：
    // - 输入：列组和目标列号；
    // - 处理：线性判断列号是否属于当前组；
    // - 返回：true 表示该列应展示。
    bool containsColumnIndex(const QVector<int>& columnGroup, const int columnIndex)
    {
        return std::find(columnGroup.begin(), columnGroup.end(), columnIndex) != columnGroup.end();
    }

    // buildColumnPresetButtonStyle 作用：
    // - 输入：按钮是否处于选中预设状态；
    // - 处理：选中时使用主题主色背景，未选中时透明背景并保留主题文字色；
    // - 返回：QPushButton stylesheet 文本。
    QString buildColumnPresetButtonStyle(const bool selected)
    {
        const QString backgroundText = selected
            ? KswordTheme::AccentHex(KswordTheme::AccentRole::Blue)
            : QStringLiteral("transparent");
        const QString borderText = selected
            ? KswordTheme::AccentHex(KswordTheme::AccentRole::Blue)
            : KswordTheme::BorderHex();
        const QString textColor = selected
            ? KswordTheme::OnAccentDynamicHex()
            : KswordTheme::TextPrimaryHex();
        return QStringLiteral(
            "QPushButton{min-width:24px;max-width:24px;padding:3px 0;border:1px solid %1;"
            "border-radius:0;color:%2;background:%3;font-weight:700;}"
            "QPushButton:hover{border-color:%4;}"
            "QPushButton:pressed{background:%4;color:%5;}")
            .arg(borderText)
            .arg(textColor)
            .arg(backgroundText)
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    // updateColumnPresetButtons 作用：
    // - 输入：表格和 A/B/C 按钮；
    // - 处理：根据表格当前 columnPreset 属性刷新按钮着色；
    // - 返回：无，空指针安全忽略。
    void updateColumnPresetButtons(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC)
    {
        if (table == nullptr || buttonA == nullptr || buttonB == nullptr || buttonC == nullptr)
        {
            return;
        }

        const QString presetText = table->property("kswordColumnPreset").toString();
        buttonA->setStyleSheet(buildColumnPresetButtonStyle(presetText == QStringLiteral("A")));
        buttonB->setStyleSheet(buildColumnPresetButtonStyle(presetText == QStringLiteral("B")));
        buttonC->setStyleSheet(buildColumnPresetButtonStyle(presetText == QStringLiteral("C")));
    }

    // applyColumnPresetToTable 作用：
    // - 输入：表格、要显示的列组、预设名和 A/B/C 按钮；
    // - 处理：隐藏列组外字段，并把 A/B/C 按钮更新到对应高亮；
    // - 返回：无，列组无效时只显示有效列。
    void applyColumnPresetToTable(
        QTableWidget* table,
        const QVector<int>& columnGroup,
        const QString& presetText,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC)
    {
        if (table == nullptr)
        {
            return;
        }

        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            table->setColumnHidden(columnIndex, !containsColumnIndex(columnGroup, columnIndex));
        }
        table->setProperty("kswordColumnPreset", presetText);
        updateColumnPresetButtons(table, buttonA, buttonB, buttonC);
    }

    // visibleColumnCount 作用：
    // - 输入：目标表格；
    // - 处理：统计当前未隐藏列，避免表头菜单把表格全部隐藏；
    // - 返回：可见列数量。
    int visibleColumnCount(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return 0;
        }

        int count = 0;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            if (!table->isColumnHidden(columnIndex))
            {
                ++count;
            }
        }
        return count;
    }

    // createColumnPresetButton 作用：
    // - 输入：父控件、按钮文本和 tooltip；
    // - 处理：创建 A/B/C 短按钮，按钮文本按需求只显示单个字母；
    // - 返回：由 Qt 父对象释放的 QPushButton。
    QPushButton* createColumnPresetButton(
        QWidget* parentWidget,
        const QString& buttonText,
        const QString& tooltipText)
    {
        QPushButton* button = new QPushButton(buttonText, parentWidget);
        button->setToolTip(tooltipText);
        button->setStyleSheet(buildColumnPresetButtonStyle(false));
        button->setCursor(Qt::PointingHandCursor);
        return button;
    }

    // installHeaderColumnMenu 作用：
    // - 输入：表格、A/B/C 按钮；
    // - 处理：在表头安装右键列显隐菜单，菜单显式设置主题样式；
    // - 返回：无，用户手动改列后 A/B/C 均取消高亮。
    void installHeaderColumnMenu(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC)
    {
        if (table == nullptr || table->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* headerView = table->horizontalHeader();
        headerView->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(headerView, &QHeaderView::customContextMenuRequested, table, [table, headerView, buttonA, buttonB, buttonC](const QPoint& localPosition)
        {
            QMenu menu(table);
            menu.setStyleSheet(KswordTheme::ContextMenuStyle());
            for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* headerItem = table->horizontalHeaderItem(columnIndex);
                const QString titleText = headerItem != nullptr
                    ? headerItem->text()
                    : QStringLiteral("Column %1").arg(columnIndex);
                QAction* columnAction = menu.addAction(titleText);
                columnAction->setCheckable(true);
                columnAction->setChecked(!table->isColumnHidden(columnIndex));
                columnAction->setData(columnIndex);
            }

            QAction* selectedAction = menu.exec(headerView->viewport()->mapToGlobal(localPosition));
            if (selectedAction == nullptr)
            {
                return;
            }

            const int columnIndex = selectedAction->data().toInt();
            const bool shouldShow = selectedAction->isChecked();
            if (!shouldShow && visibleColumnCount(table) <= 1)
            {
                table->setColumnHidden(columnIndex, false);
                return;
            }

            table->setColumnHidden(columnIndex, !shouldShow);
            table->setProperty("kswordColumnPreset", QStringLiteral("Custom"));
            updateColumnPresetButtons(table, buttonA, buttonB, buttonC);
        });
    }

    // installColumnPresetControls 作用：
    // - 输入：表格、A/B/C 按钮和三个逻辑列组；
    // - 处理：连接 A/B/C 切换、安装表头菜单，并默认套用 A 组；
    // - 返回：无，调用后表格进入 A 组默认列布局。
    void installColumnPresetControls(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC,
        const QVector<int>& groupA,
        const QVector<int>& groupB,
        const QVector<int>& groupC)
    {
        if (table == nullptr || buttonA == nullptr || buttonB == nullptr || buttonC == nullptr)
        {
            return;
        }

        QObject::connect(buttonA, &QPushButton::clicked, table, [table, buttonA, buttonB, buttonC, groupA]()
        {
            applyColumnPresetToTable(table, groupA, QStringLiteral("A"), buttonA, buttonB, buttonC);
        });
        QObject::connect(buttonB, &QPushButton::clicked, table, [table, buttonA, buttonB, buttonC, groupB]()
        {
            applyColumnPresetToTable(table, groupB, QStringLiteral("B"), buttonA, buttonB, buttonC);
        });
        QObject::connect(buttonC, &QPushButton::clicked, table, [table, buttonA, buttonB, buttonC, groupC]()
        {
            applyColumnPresetToTable(table, groupC, QStringLiteral("C"), buttonA, buttonB, buttonC);
        });
        installHeaderColumnMenu(table, buttonA, buttonB, buttonC);
        applyColumnPresetToTable(table, groupA, QStringLiteral("A"), buttonA, buttonB, buttonC);
    }

    // createDeviceAuditTable 作用：
    // - 输入：父控件；
    // - 处理：创建只读、可排序、支持复制行的设备审计表格；
    // - 返回：QTableWidget 指针，由 Qt 父子树释放。
    QTableWidget* createDeviceAuditTable(QWidget* parentWidget)
    {
        QTableWidget* table = new ks::ui::VisibleTableWidget(parentWidget);
        const QStringList headers = hardwareDeviceAuditTableHeaders();
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        table->horizontalHeader()->setStretchLastSection(true);
        installHardwareAuditCopyMenu(table);
        return table;
    }

    // createDeviceAuditPage 作用：
    // - 输入：父控件、标题、提示、输出编辑器和输出表格指针；
    // - 处理：创建“摘要文本 + 完整 R0 行表格”的标准页；
    // - 返回：已初始化页面控件。
    QWidget* createDeviceAuditPage(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& hintText,
        CodeEditorWidget** editorOut,
        QTableWidget** tableOut)
    {
        QWidget* pageWidget = createReadOnlyTextPage(parentWidget, titleText, hintText, editorOut);
        QVBoxLayout* pageLayout = qobject_cast<QVBoxLayout*>(pageWidget->layout());
        if (pageLayout != nullptr)
        {
            QLineEdit* searchEdit = new QLineEdit(pageWidget);
            searchEdit->setClearButtonEnabled(true);
            searchEdit->setPlaceholderText(
                QStringLiteral("搜索 Profile / 行类型 / 风险 / 地址 / FieldFlags / LastStatus / 备注"));
            searchEdit->setStyleSheet(buildDeviceAuditSearchStyle());
            QTableWidget* table = createDeviceAuditTable(pageWidget);

            QHBoxLayout* tableToolLayout = new QHBoxLayout();
            tableToolLayout->setContentsMargins(0, 0, 0, 0);
            tableToolLayout->setSpacing(6);

            QHBoxLayout* presetLayout = new QHBoxLayout();
            presetLayout->setContentsMargins(0, 0, 0, 0);
            presetLayout->setSpacing(0);

            QPushButton* groupAButton = createColumnPresetButton(
                pageWidget,
                QStringLiteral("A"),
                QStringLiteral("显示默认精简列：状态、风险、链路深度和关键对象地址。"));
            QPushButton* groupBButton = createColumnPresetButton(
                pageWidget,
                QStringLiteral("B"),
                QStringLiteral("显示 B 组精简列：链路深度和对象地址关系。"));
            QPushButton* groupCButton = createColumnPresetButton(
                pageWidget,
                QStringLiteral("C"),
                QStringLiteral("显示 C 组精简列：服务、路径、FieldFlags、integrity 和备注。"));
            presetLayout->addWidget(groupAButton, 0);
            presetLayout->addWidget(groupBButton, 0);
            presetLayout->addWidget(groupCButton, 0);

            tableToolLayout->addLayout(presetLayout, 0);
            tableToolLayout->addWidget(searchEdit, 1);
            pageLayout->addLayout(tableToolLayout, 0);
            pageLayout->addWidget(table, 2);
            table->setProperty("kswordDeviceAuditFilter", searchEdit->text());
            installColumnPresetControls(
                table,
                groupAButton,
                groupBButton,
                groupCButton,
                deviceAuditColumnGroupA(),
                deviceAuditColumnGroupB(),
                deviceAuditColumnGroupC());
            QObject::connect(searchEdit, &QLineEdit::textChanged, table, [table](const QString& filterText)
            {
                table->setProperty("kswordDeviceAuditFilter", filterText);
                applyDeviceAuditTableFilter(table, filterText);
            });
            if (tableOut != nullptr)
            {
                *tableOut = table;
            }
        }
        return pageWidget;
    }

    // CPU core chart compact layout constants:
    // - Input: used by the CPU utilization page grid and each per-core chart cell.
    // - Processing: reduce the grid gap and per-cell chrome so dense multi-core CPUs waste less blank space.
    // - Return behavior: constants only; no runtime return value.
    constexpr int kCpuCoreChartGridSpacingPx = 2;
    constexpr int kCpuCoreChartCellMarginPx = 2;
    constexpr int kCpuCoreChartInnerSpacingPx = 1;
    constexpr int kCpuCoreChartChromeReservePx = 5;

    struct CpuCoreGridShape
    {
        int columnCount = 1;
        int rowCount = 1;
    };

    // chooseCpuCoreGridShape 作用：
    // - 输入：当前逻辑处理器数量；
    // - 处理：恢复接近平方形的原始排列，列数向上取平方根、行数按剩余核心向上取整；
    // - 返回：4 线程稳定得到 2x2，其它核心数也不会退化成单行长条。
    CpuCoreGridShape chooseCpuCoreGridShape(const int logicalProcessorCount)
    {
        const int coreCount = std::max(1, logicalProcessorCount);
        const int columnCount = std::max(
            1,
            static_cast<int>(std::ceil(std::sqrt(static_cast<double>(coreCount)))));
        const int rowCount = std::max(
            1,
            static_cast<int>(std::ceil(
                static_cast<double>(coreCount) /
                static_cast<double>(columnCount))));
        return CpuCoreGridShape{columnCount, rowCount};
    }

    // formatHardwareAuditHex32 作用：
    // - 输入：R0 审计返回的 32 位状态、标志或计数字段；
    // - 处理：统一格式化为 0xXXXXXXXX，便于和协议文档/日志比对；
    // - 返回：Qt 字符串，不修改任何 R0/R3 状态。
    QString formatHardwareAuditHex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 8, 16, QChar('0'))
            .toUpper();
    }

    // formatHardwareAuditHex64 作用：
    // - 输入：R0 设备审计行中的 DriverObject/DeviceObject 等 64 位地址；
    // - 处理：统一格式化为 0xXXXXXXXXXXXXXXXX；
    // - 返回：仅用于 UI 文本展示的 QString。
    QString formatHardwareAuditHex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    // arkClientMessageToQString 作用：
    // - 输入：ArkDriverClient IoResult::message 的窄字节诊断；
    // - 处理：按 UTF-8 转成 Qt 字符串，空消息用占位符表示；
    // - 返回：可直接追加到 CodeEditorWidget 的文本。
    QString arkClientMessageToQString(const std::string& messageText)
    {
        if (messageText.empty())
        {
            return QStringLiteral("<empty>");
        }
        return QString::fromUtf8(messageText.data(), static_cast<int>(messageText.size()));
    }

    // friendlyHardwareIoMessage 作用：
    // - 输入：ArkDriverClient 返回的底层 message 和 unsupported 标记；
    // - 处理：把 DeviceIoControl/status/bytesReturned 这类工程日志折叠成人读说明；
    // - 返回：适合摘要页、表格末列和详情文本展示的中文说明。
    QString friendlyHardwareIoMessage(
        const std::string& messageText,
        const bool unsupported)
    {
        const QString rawText = arkClientMessageToQString(messageText).trimmed();
        if (unsupported)
        {
            return QStringLiteral("当前加载的 R0 驱动不支持该硬件审计入口，请同步驱动版本。");
        }
        if (rawText.isEmpty() || rawText == QStringLiteral("<empty>"))
        {
            return QStringLiteral("驱动未返回额外说明。");
        }
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或 R3/R0 协议版本不匹配。");
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动不支持该只读硬件审计查询。");
        }
        if (rawText.contains(QStringLiteral("status="), Qt::CaseInsensitive) &&
            rawText.contains(QStringLiteral("bytesReturned="), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动已返回结构化硬件审计结果；底层 IO 状态已在本页字段中展开。");
        }
        return rawText;
    }

    // friendlyDeviceAuditEntryDetail 作用：
    // - 输入：R0 单条设备审计 entry.detail 文本；
    // - 处理：把底层 IOCTL/DynData/unsupported 等工程提示转换为表格末列可读说明；
    // - 返回：中文短说明，避免 DevNode/USB/HID 明细列直接塞驱动日志。
    QString friendlyDeviceAuditEntryDetail(const QString& detailText)
    {
        const QString rawText = detailText.trimmed();
        if (rawText.isEmpty())
        {
            return QStringLiteral("R0 返回结构化设备对象行");
        }
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("设备审计行来自失败/兼容性诊断，底层驱动接口调用未成功。");
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动不支持该设备链路的深度字段，已保留基础行。");
        }
        if (rawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("profile"), Qt::CaseInsensitive))
        {
            return QStringLiteral("PDB/DynData 能力未完全满足，设备对象基础信息可用，深度字段暂不可用。");
        }
        if (rawText.contains(QStringLiteral("trunc"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("buffer"), Qt::CaseInsensitive))
        {
            return QStringLiteral("设备审计结果可能被缓冲区截断，当前仅展示已返回的结构化行。");
        }
        if (rawText.contains(QStringLiteral("access denied"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("privilege"), Qt::CaseInsensitive))
        {
            return QStringLiteral("权限不足，设备链路只能展示可访问的只读证据。");
        }
        return rawText;
    }

    // hardwareIoOkText 作用：
    // - 输入：IoResult::ok 布尔值；
    // - 处理：转换成中文短状态，避免详情页展示 true/false；
    // - 返回：成功/失败文本。
    QString hardwareIoOkText(const bool ok)
    {
        return ok ? QStringLiteral("成功") : QStringLiteral("失败");
    }

    // deviceAuditStatusText 作用：
    // - 输入：shared/driver 设备审计 queryStatus；
    // - 处理：映射为用户可读状态，同时保留未知值；
    // - 返回：状态标签，不触发任何查询。
    QString deviceAuditStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_PARTIAL:
            return QStringLiteral("PARTIAL");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_NOT_FOUND:
            return QStringLiteral("NOT_FOUND");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("BUFFER_TRUNCATED");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED:
            return QStringLiteral("QUERY_FAILED");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_UNSUPPORTED:
            return QStringLiteral("UNSUPPORTED");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_UNAVAILABLE:
        default:
            return QStringLiteral("UNAVAILABLE(%1)").arg(statusValue);
        }
    }

    // deviceAuditRoleText 作用：
    // - 输入：R0 设备审计行 roleHint；
    // - 处理：映射 PDO/FDO/filter/controller 等角色；
    // - 返回：用于风险行摘要的短文本。
    QString deviceAuditRoleText(const std::uint32_t roleValue)
    {
        switch (roleValue)
        {
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_PDO:
            return QStringLiteral("PDO");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_FDO:
            return QStringLiteral("FDO");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_UPPER_FILTER:
            return QStringLiteral("UpperFilter");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_LOWER_FILTER:
            return QStringLiteral("LowerFilter");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_CLASS_DRIVER:
            return QStringLiteral("ClassDriver");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER:
            return QStringLiteral("BusDriver");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_COMPOSITE:
            return QStringLiteral("Composite");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE:
            return QStringLiteral("Interface");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_CONTROLLER:
            return QStringLiteral("Controller");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY:
            return QStringLiteral("Display");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_WATCHDOG:
            return QStringLiteral("Watchdog");
        default:
            return QStringLiteral("Unknown(%1)").arg(roleValue);
        }
    }

    // deviceAuditRiskText 作用：
    // - 输入：R0 设备审计 riskFlags；
    // - 处理：展开关键风险位，未命中时显示 Clean；
    // - 返回：风险摘要文本，UI 只展示证据，不做修复动作。
    QString deviceAuditRiskText(const std::uint32_t riskFlags)
    {
        QStringList riskPartList;
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_UNAVAILABLE) != 0U)
        {
            riskPartList << QStringLiteral("Unavailable");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_QUERY_FAILED) != 0U)
        {
            riskPartList << QStringLiteral("QueryFailed");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_NAME_MISSING) != 0U)
        {
            riskPartList << QStringLiteral("NameMissing");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_IMAGE_PATH_MISSING) != 0U)
        {
            riskPartList << QStringLiteral("ImagePathMissing");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_DEVICE_LOOP) != 0U)
        {
            riskPartList << QStringLiteral("DeviceLoop");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_ATTACHED_LOOP) != 0U)
        {
            riskPartList << QStringLiteral("AttachedLoop");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_CROSS_DRIVER_ATTACH) != 0U)
        {
            riskPartList << QStringLiteral("CrossDriverAttach");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_ROLE_AMBIGUOUS) != 0U)
        {
            riskPartList << QStringLiteral("RoleAmbiguous");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_STACK_TRUNCATED) != 0U)
        {
            riskPartList << QStringLiteral("StackTruncated");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_INTEGRITY_PARTIAL) != 0U)
        {
            riskPartList << QStringLiteral("IntegrityPartial");
        }
        if (riskPartList.isEmpty())
        {
            return QStringLiteral("Clean");
        }
        return riskPartList.join(QStringLiteral("|"));
    }

    // deviceAuditResponseFlagText 作用：
    // - 输入：R0 设备审计 responseFlags；
    // - 处理：展开 truncated/partial/empty 等响应级状态；
    // - 返回：用于 summary 首屏的状态文本。
    QString deviceAuditResponseFlagText(const std::uint32_t responseFlags)
    {
        QStringList flagPartList;
        if ((responseFlags & KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_TRUNCATED) != 0U)
        {
            flagPartList << QStringLiteral("Truncated");
        }
        if ((responseFlags & KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_PARTIAL) != 0U)
        {
            flagPartList << QStringLiteral("Partial");
        }
        if ((responseFlags & KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_EMPTY) != 0U)
        {
            flagPartList << QStringLiteral("Empty");
        }
        if (flagPartList.isEmpty())
        {
            return QStringLiteral("None");
        }
        return flagPartList.join(QStringLiteral("|"));
    }

    // deviceAuditRowKindText 作用：
    // - 输入：R0 device audit rowKind 原始枚举；
    // - 处理：把 summary/device 两类行明确标出来，并保留枚举值，方便和驱动协议核对；
    // - 返回：表格“行类型”列文本。
    QString deviceAuditRowKindText(const std::uint32_t rowKind)
    {
        switch (rowKind)
        {
        case KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DRIVER_SUMMARY:
            return QStringLiteral("DriverSummary(%1)").arg(rowKind);
        case KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DEVICE_ROW:
            return QStringLiteral("DeviceRow(%1)").arg(rowKind);
        default:
            return QStringLiteral("RowKind(%1)").arg(rowKind);
        }
    }

    // DeviceAuditParsedDetail 作用：
    // - 输入：由 parseDeviceAuditDetailFromR0 生成；
    // - 处理：把驱动当前 detail 文本中的稳定键值拆分为 UI 列；
    // - 返回：纯数据结构，无成员函数返回值。
    struct DeviceAuditParsedDetail
    {
        QString ownerDriver;      // ownerDriver：AttachedDevice 行 detail 中的 OwnerDriver=0x...。
        QString integrityStatus;  // integrityStatus：DriverSummary detail 中的 Driver integrity status。
        QString integrityRows;    // integrityRows：DriverSummary detail 中的 rows=returned/total。
        QString modules;          // modules：DriverSummary detail 中的 modules=...。
        QString integrityFlags;   // integrityFlags：DriverSummary detail 中的 statusFlags=0x...。
    };

    // deviceAuditDetailValue 作用：
    // - 输入：R0 detail 原文和稳定键名，例如 OwnerDriver/statusFlags；
    // - 处理：按 “key=value” 形式提取到分号、句号或空白前为止；
    // - 返回：匹配到的值；不存在时返回空字符串。
    QString deviceAuditDetailValue(const QString& detailText, const QString& keyText)
    {
        const QRegularExpression expression(
            QStringLiteral("(?:^|[;\\s])%1\\s*=\\s*([^;\\s.]+)")
                .arg(QRegularExpression::escape(keyText)),
            QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch match = expression.match(detailText);
        if (!match.hasMatch())
        {
            return QString();
        }
        return match.captured(1).trimmed().toUpper();
    }

    // parseDeviceAuditDetailFromR0 作用：
    // - 输入：KSWORD_ARK_DEVICE_AUDIT_ENTRY.detail 原文；
    // - 处理：只解析驱动源码中稳定生成的键值，避免把整句英文诊断塞到表格主列；
    // - 返回：可直接映射到结构化列的字段集合。
    DeviceAuditParsedDetail parseDeviceAuditDetailFromR0(const QString& detailText)
    {
        DeviceAuditParsedDetail parsed;
        parsed.ownerDriver = deviceAuditDetailValue(detailText, QStringLiteral("OwnerDriver"));
        parsed.integrityStatus = deviceAuditDetailValue(detailText, QStringLiteral("status"));
        parsed.integrityRows = deviceAuditDetailValue(detailText, QStringLiteral("rows"));
        parsed.modules = deviceAuditDetailValue(detailText, QStringLiteral("modules"));
        parsed.integrityFlags = deviceAuditDetailValue(detailText, QStringLiteral("statusFlags"));
        return parsed;
    }

    // isStructuredDeviceAuditDetail 作用：
    // - 输入：R0 detail 原文；
    // - 处理：识别已经被表格列拆分的稳定格式；
    // - 返回：true 表示不再把原文重复放到“备注”列。
    bool isStructuredDeviceAuditDetail(const QString& detailText)
    {
        const QString rawText = detailText.trimmed();
        return rawText.contains(QStringLiteral("Driver integrity status="), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("DeviceObject="), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("AttachedDevice="), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("OwnerDriver="), Qt::CaseInsensitive);
    }

    // appendDeviceAuditSummaryText 作用：
    // - 输入：页面标题、wrapper 返回值和请求深度；
    // - 处理：汇总 returnedCount/totalCount、maxDepth/truncated、IO 状态和风险行；
    // - 返回：可追加到设备栈/输入链/USB 拓扑 CodeEditorWidget 的只读文本。
    QString appendDeviceAuditSummaryText(
        const QString& titleText,
        const ksword::ark::DeviceAuditResult& auditResult,
        const std::uint32_t requestedMaxDepth)
    {
        std::uint32_t maxObservedDepth = 0U;
        std::uint32_t riskRowCount = 0U;
        for (const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry : auditResult.entries)
        {
            maxObservedDepth = std::max(maxObservedDepth, static_cast<std::uint32_t>(entry.relationDepth));
            maxObservedDepth = std::max(maxObservedDepth, static_cast<std::uint32_t>(entry.attachedDepth));
            if (entry.riskFlags != KSWORD_ARK_DEVICE_AUDIT_RISK_NONE)
            {
                ++riskRowCount;
            }
        }

        const bool truncatedFlag =
            (auditResult.responseFlags & KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_TRUNCATED) != 0U
            || auditResult.returnedCount < auditResult.totalCount;

        QString text;
        text += QStringLiteral("\n\n[%1]\n").arg(titleText);
        text += QStringLiteral("以下内容为只读设备证据，不会修改设备状态。\n");
        text += QStringLiteral("调用状态: %1；兼容性: %2；Win32=%3；NTSTATUS=%4；返回字节=%5\n")
            .arg(hardwareIoOkText(auditResult.io.ok))
            .arg(auditResult.unsupported ? QStringLiteral("驱动不支持") : QStringLiteral("接口可用"))
            .arg(auditResult.io.win32Error)
            .arg(formatHardwareAuditHex32(static_cast<std::uint32_t>(auditResult.io.ntStatus)))
            .arg(auditResult.io.bytesReturned);
        text += QStringLiteral("驱动说明: %1\n")
            .arg(friendlyHardwareIoMessage(auditResult.io.message, auditResult.unsupported));
        text += QStringLiteral("协议状态: version=%1；queryStatus=%2；lastStatus=%3；entrySize=%4\n")
            .arg(auditResult.version)
            .arg(deviceAuditStatusText(auditResult.status))
            .arg(formatHardwareAuditHex32(static_cast<std::uint32_t>(auditResult.lastStatus)))
            .arg(auditResult.entrySize);
        text += QStringLiteral("对象计数: returned=%1；total=%2；已解析=%3；目标=%4；驱动=%5；设备=%6\n")
            .arg(auditResult.returnedCount)
            .arg(auditResult.totalCount)
            .arg(auditResult.entries.size())
            .arg(auditResult.targetCount)
            .arg(auditResult.driverCount)
            .arg(auditResult.deviceCount);
        text += QStringLiteral("链路深度: 观察最大=%1；请求上限=%2；是否截断=%3；响应标志=%4（%5）\n")
            .arg(maxObservedDepth)
            .arg(requestedMaxDepth)
            .arg(truncatedFlag ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(formatHardwareAuditHex32(auditResult.responseFlags))
            .arg(deviceAuditResponseFlagText(auditResult.responseFlags));
        text += QStringLiteral("风险摘要: 风险行=%1；profileFlags=%2；处理建议=%3\n")
            .arg(riskRowCount)
            .arg(formatHardwareAuditHex32(auditResult.profileFlags))
            .arg(riskRowCount == 0U ? QStringLiteral("未发现 R0 风险行") : QStringLiteral("请查看表格中非 Clean 的风险行"));

        int shownRows = 0;
        for (const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry : auditResult.entries)
        {
            if (entry.riskFlags == KSWORD_ARK_DEVICE_AUDIT_RISK_NONE && shownRows >= 8)
            {
                continue;
            }

            const QString driverNameText = QString::fromWCharArray(entry.driverName).trimmed();
            const QString deviceNameText = QString::fromWCharArray(entry.deviceName).trimmed();
            const QString detailText = QString::fromWCharArray(entry.detail).trimmed();
            const QString readableEntryDetailText = friendlyDeviceAuditEntryDetail(detailText);
            text += QStringLiteral("行[%1]: 角色=%2；状态=%3；风险=%4（%5）；置信度=%6；深度=%7/%8；驱动=%9；设备=%10；DriverObject=%11；DeviceObject=%12；说明=%13\n")
                .arg(shownRows)
                .arg(deviceAuditRoleText(entry.roleHint))
                .arg(deviceAuditStatusText(entry.status))
                .arg(deviceAuditRiskText(entry.riskFlags))
                .arg(formatHardwareAuditHex32(entry.riskFlags))
                .arg(entry.confidence)
                .arg(entry.relationDepth)
                .arg(entry.attachedDepth)
                .arg(driverNameText.isEmpty() ? QStringLiteral("<unnamed>") : driverNameText)
                .arg(deviceNameText.isEmpty() ? QStringLiteral("<unnamed>") : deviceNameText)
                .arg(formatHardwareAuditHex64(entry.driverObjectAddress))
                .arg(formatHardwareAuditHex64(entry.deviceObjectAddress))
                .arg(readableEntryDetailText);
            ++shownRows;
            if (shownRows >= 12)
            {
                break;
            }
        }

        if (auditResult.entries.empty())
        {
            text += QStringLiteral("明细行: <无返回行>\n");
        }
        return text;
    }

    // buildDeviceAuditRows 作用：
    // - 输入：wrapper 名称和 ArkDriverClient 设备审计结果；
    // - 处理：把全部 R0 entry 转成结构化表格行，空结果也保留一行可读诊断；
    // - 返回：QVector<QStringList>，每行列数与 hardwareDeviceAuditTableHeaders 一致。
    QVector<QStringList> buildDeviceAuditRows(
        const QString& profileName,
        const ksword::ark::DeviceAuditResult& auditResult)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(auditResult.entries.size()) + 1);

        if (auditResult.entries.empty())
        {
            const QString stateText = auditResult.io.ok
                ? QStringLiteral("驱动接口可用，但没有返回设备行")
                : (auditResult.unsupported
                    ? QStringLiteral("当前驱动不支持该设备审计入口")
                    : QStringLiteral("设备审计接口暂不可用"));
            rows.push_back(QStringList{
                profileName,
                QStringLiteral("NoRows"),
                QStringLiteral("<none>"),
                deviceAuditStatusText(auditResult.status),
                auditResult.unsupported ? QStringLiteral("Unsupported") : QStringLiteral("NoRows"),
                QStringLiteral("0"),
                QStringLiteral("0"),
                QStringLiteral("0"),
                QStringLiteral("<none>"),
                QStringLiteral("<none>"),
                QStringLiteral("<none>"),
                QStringLiteral("<none>"),
                QStringLiteral("0x0"),
                QStringLiteral("0x0"),
                QStringLiteral("0x0"),
                QStringLiteral("0x0"),
                QStringLiteral("0x0"),
                formatHardwareAuditHex32(0U),
                formatHardwareAuditHex32(0U),
                QStringLiteral("0"),
                QStringLiteral("0"),
                formatHardwareAuditHex32(0U),
                formatHardwareAuditHex32(static_cast<std::uint32_t>(auditResult.lastStatus)),
                deviceAuditStatusText(auditResult.status),
                QStringLiteral("%1/%2").arg(auditResult.returnedCount).arg(auditResult.totalCount),
                QString::number(auditResult.driverCount),
                formatHardwareAuditHex32(auditResult.responseFlags),
                QStringLiteral("%1；returned=%2 total=%3；%4")
                    .arg(stateText)
                    .arg(auditResult.returnedCount)
                    .arg(auditResult.totalCount)
                    .arg(friendlyHardwareIoMessage(auditResult.io.message, auditResult.unsupported))
            });
            return rows;
        }

        for (const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry : auditResult.entries)
        {
            const QString driverNameText = QString::fromWCharArray(entry.driverName).trimmed();
            const QString serviceNameText = QString::fromWCharArray(entry.serviceName).trimmed();
            const QString deviceNameText = QString::fromWCharArray(entry.deviceName).trimmed();
            const QString imagePathText = QString::fromWCharArray(entry.imagePath).trimmed();
            const QString detailText = QString::fromWCharArray(entry.detail).trimmed();
            const QString readableEntryDetailText = friendlyDeviceAuditEntryDetail(detailText);
            const DeviceAuditParsedDetail parsedDetail = parseDeviceAuditDetailFromR0(detailText);
            QStringList noteParts;
            if (!detailText.isEmpty() && !isStructuredDeviceAuditDetail(detailText))
            {
                noteParts << readableEntryDetailText;
            }
            if (detailText.isEmpty())
            {
                noteParts << QStringLiteral("R0 未返回额外备注");
            }
            if (auditResult.responseFlags != 0U)
            {
                noteParts << QStringLiteral("responseFlags=%1(%2)")
                    .arg(formatHardwareAuditHex32(auditResult.responseFlags))
                    .arg(deviceAuditResponseFlagText(auditResult.responseFlags));
            }
            if (entry.profileFlags != auditResult.profileFlags)
            {
                noteParts << QStringLiteral("entryProfile=%1")
                    .arg(formatHardwareAuditHex32(entry.profileFlags));
            }

            rows.push_back(QStringList{
                profileName,
                deviceAuditRowKindText(entry.rowKind),
                deviceAuditRoleText(entry.roleHint),
                deviceAuditStatusText(entry.status),
                deviceAuditRiskText(entry.riskFlags),
                QString::number(entry.confidence),
                QString::number(entry.relationDepth),
                QString::number(entry.attachedDepth),
                driverNameText.isEmpty() ? QStringLiteral("<unnamed>") : driverNameText,
                serviceNameText.isEmpty() ? QStringLiteral("<none>") : serviceNameText,
                imagePathText.isEmpty() ? QStringLiteral("<none>") : imagePathText,
                deviceNameText.isEmpty() ? QStringLiteral("<unnamed>") : deviceNameText,
                formatHardwareAuditHex64(entry.driverObjectAddress),
                formatHardwareAuditHex64(entry.deviceObjectAddress),
                formatHardwareAuditHex64(entry.attachedDeviceAddress),
                formatHardwareAuditHex64(entry.nextDeviceObjectAddress),
                parsedDetail.ownerDriver.isEmpty()
                    ? QStringLiteral("<none>")
                    : parsedDetail.ownerDriver,
                formatHardwareAuditHex32(entry.deviceType),
                formatHardwareAuditHex32(entry.characteristics),
                QString::number(entry.stackSize),
                QString::number(entry.alignmentRequirement),
                formatHardwareAuditHex32(entry.fieldFlags),
                formatHardwareAuditHex32(static_cast<std::uint32_t>(entry.lastStatus)),
                parsedDetail.integrityStatus.isEmpty()
                    ? QString()
                    : parsedDetail.integrityStatus,
                parsedDetail.integrityRows,
                parsedDetail.modules,
                parsedDetail.integrityFlags,
                noteParts.join(QStringLiteral("；"))
            });
        }

        return rows;
    }

    // makeDeviceAuditItem 作用：
    // - 输入：单元格文本；
    // - 处理：创建只读 QTableWidgetItem；
    // - 返回：由表格接管生命周期的 item 指针。
    QTableWidgetItem* makeDeviceAuditItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    // populateDeviceAuditTable 作用：
    // - 输入：目标表格与行模型；
    // - 处理：保持排序状态，填入全部只读行；
    // - 返回：无，空表格指针直接忽略。
    void populateDeviceAuditTable(QTableWidget* table, const QVector<QStringList>& rows)
    {
        if (table == nullptr)
        {
            return;
        }

        const bool wasSortingEnabled = table->isSortingEnabled();
        table->setSortingEnabled(false);
        table->setRowCount(rows.size());
        for (int rowIndex = 0; rowIndex < rows.size(); ++rowIndex)
        {
            const QStringList& row = rows.at(rowIndex);
            for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
            {
                const QString cellText = columnIndex < row.size() ? row.at(columnIndex) : QString();
                table->setItem(rowIndex, columnIndex, makeDeviceAuditItem(cellText));
            }
        }
        table->setSortingEnabled(wasSortingEnabled);
        applyDeviceAuditTableFilter(
            table,
            table->property("kswordDeviceAuditFilter").toString());
    }

    // createHardwareDeferredPlaceholder 作用：
    // - 输入：父控件、标题文本和说明文本；
    // - 处理：创建轻量占位页，让重页面在用户真正进入子 Tab 后再加载；
    // - 返回：占位 QWidget 指针，调用方负责把它加入目标布局。
    QWidget* createHardwareDeferredPlaceholder(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& hintText)
    {
        QWidget* placeholderWidget = new QWidget(parentWidget);
        placeholderWidget->setAutoFillBackground(false);
        placeholderWidget->setAttribute(Qt::WA_StyledBackground, false);

        QVBoxLayout* placeholderLayout = new QVBoxLayout(placeholderWidget);
        placeholderLayout->setContentsMargins(24, 24, 24, 24);
        placeholderLayout->setSpacing(8);
        placeholderLayout->addStretch(1);

        QLabel* titleLabel = new QLabel(titleText, placeholderWidget);
        titleLabel->setAlignment(Qt::AlignCenter);
        titleLabel->setStyleSheet(
            QStringLiteral("font-size:16px;font-weight:700;color:%1;")
            .arg(KswordTheme::TextPrimaryHex()));
        placeholderLayout->addWidget(titleLabel, 0);

        QLabel* hintLabel = new QLabel(hintText, placeholderWidget);
        hintLabel->setAlignment(Qt::AlignCenter);
        hintLabel->setWordWrap(true);
        hintLabel->setStyleSheet(
            QStringLiteral("font-size:12px;color:%1;")
            .arg(KswordTheme::TextSecondaryHex()));
        placeholderLayout->addWidget(hintLabel, 0);
        placeholderLayout->addStretch(1);
        return placeholderWidget;
    }

    // appendTransparentBackgroundStyle 作用：
    // - 给“硬件 -> 计数器/利用率”页控件补充透明背景样式；
    // - 若控件属于滚动区域，还会同步把 viewport 设为透明，避免残留底色。
    void appendTransparentBackgroundStyle(QWidget* widgetPointer)
    {
        if (widgetPointer == nullptr)
        {
            return;
        }

        widgetPointer->setAttribute(Qt::WA_StyledBackground, true);
        widgetPointer->setAutoFillBackground(false);

        // transparentDeclarationText 用途：透明背景声明片段；transparentRuleText 用途：当前控件专用规则块。
        const QString transparentDeclarationText =
            QStringLiteral("background:transparent;background-color:transparent;border:none;");
        const QString transparentRuleText = QStringLiteral("%1{%2}")
            .arg(QString::fromLatin1(widgetPointer->metaObject()->className()))
            .arg(transparentDeclarationText);
        if (!widgetPointer->styleSheet().contains(QStringLiteral("background:transparent")))
        {
            widgetPointer->setStyleSheet(widgetPointer->styleSheet() + transparentRuleText);
        }

        QAbstractScrollArea* abstractScrollAreaPointer =
            qobject_cast<QAbstractScrollArea*>(widgetPointer);
        if (abstractScrollAreaPointer == nullptr || abstractScrollAreaPointer->viewport() == nullptr)
        {
            return;
        }

        abstractScrollAreaPointer->viewport()->setAttribute(Qt::WA_StyledBackground, true);
        abstractScrollAreaPointer->viewport()->setAutoFillBackground(false);
        if (!abstractScrollAreaPointer->viewport()->styleSheet().contains(QStringLiteral("background:transparent")))
        {
            const QString viewportTransparentRuleText = QStringLiteral("%1{%2}")
                .arg(QString::fromLatin1(abstractScrollAreaPointer->viewport()->metaObject()->className()))
                .arg(transparentDeclarationText);
            abstractScrollAreaPointer->viewport()->setStyleSheet(
                abstractScrollAreaPointer->viewport()->styleSheet() + viewportTransparentRuleText);
        }
    }

    // configureTransparentChart 作用：
    // - 统一关闭图表背景与绘图区背景；
    // - 避免 QChart 在透明容器上仍然绘制白底/深底块。
    void configureTransparentChart(QChart* chartPointer)
    {
        if (chartPointer == nullptr)
        {
            return;
        }

        chartPointer->setBackgroundVisible(false);
        chartPointer->setPlotAreaBackgroundVisible(false);
        chartPointer->setBackgroundRoundness(0);
        chartPointer->setMargins(QMargins(0, 0, 0, 0));
    }

    // configureTransparentChartViewOnly 作用：
    // - 只清理 QChart 外层背景，不覆盖调用者已设置的 plotArea 背景和网格边框；
    // - CPU 单核利用率图需要保留绘图区方框/填充，因此不能调用 configureTransparentChart；
    // - 返回行为：无返回值，空指针直接忽略。
    void configureTransparentChartViewOnly(QChart* chartPointer)
    {
        if (chartPointer == nullptr)
        {
            return;
        }

        chartPointer->setBackgroundVisible(false);
        chartPointer->setBackgroundRoundness(0);
        chartPointer->setMargins(QMargins(0, 0, 0, 0));
    }

    // configureCompressibleWidget 作用：
    // - 清掉控件默认最小尺寸，允许 Dock 窄宽/低高时继续压缩而不是请求外层滚动条；
    // - horizontalPolicy/verticalPolicy 用于按页面角色指定横纵向分配策略；
    // - 返回行为：无返回值，只修改 QWidget 的布局属性。
    void configureCompressibleWidget(
        QWidget* widgetPointer,
        const QSizePolicy::Policy horizontalPolicy = QSizePolicy::Preferred,
        const QSizePolicy::Policy verticalPolicy = QSizePolicy::Preferred)
    {
        if (widgetPointer == nullptr)
        {
            return;
        }

        widgetPointer->setMinimumSize(0, 0);
        widgetPointer->setSizePolicy(horizontalPolicy, verticalPolicy);
    }

    // configureCompressibleLabel 作用：
    // - 让长设备名、CPU/GPU 型号和详情文本在空间不足时被布局压缩/裁剪；
    // - 这样页面宽高变小时优先缩小内容，而不是把外层 QScrollArea 撑出滚动条；
    // - 返回行为：无返回值，只修改 QLabel 的布局属性。
    void configureCompressibleLabel(
        QLabel* labelPointer,
        const QSizePolicy::Policy horizontalPolicy = QSizePolicy::Ignored,
        const QSizePolicy::Policy verticalPolicy = QSizePolicy::Preferred)
    {
        configureCompressibleWidget(labelPointer, horizontalPolicy, verticalPolicy);
    }

    // configurePersistentHeaderLabel 作用：
    // - 用于“利用率”详情页顶部标题和右侧设备型号备注；
    // - 这些标签必须始终保留一行可见高度，不能被图表区域压缩到 0；
    // - 返回行为：无返回值，只调整 QLabel 的单行布局策略。
    void configurePersistentHeaderLabel(
        QLabel* labelPointer,
        const QSizePolicy::Policy horizontalPolicy = QSizePolicy::Preferred)
    {
        if (labelPointer == nullptr)
        {
            return;
        }

        labelPointer->setMinimumSize(0, 0);
        labelPointer->setWordWrap(false);
        labelPointer->setSizePolicy(horizontalPolicy, QSizePolicy::Fixed);
        labelPointer->setMinimumHeight(std::max(1, labelPointer->sizeHint().height()));
    }

    // lockLabelHeightToFont 作用：
    // - 在设置大字号样式后重新按字体度量锁定 QLabel 行高；
    // - 解决 QLabel 先计算普通字号 sizeHint、后套 46px 样式时顶部/底部被布局裁剪的问题；
    // - 参数 extraVerticalPadding：给字体 ascent/descent 外额外预留的上下像素总量；
    // - 返回行为：无返回值，仅更新标签最小/最大高度。
    void lockLabelHeightToFont(QLabel* labelPointer, const int extraVerticalPadding)
    {
        if (labelPointer == nullptr)
        {
            return;
        }

        // ensurePolished 用途：让 stylesheet 的 font-size/font-weight 先生效，再读取字体度量。
        labelPointer->ensurePolished();
        // fontHeight 用途：读取应用样式后真实字体高度，避免依赖过期 sizeHint。
        const int fontHeight = labelPointer->fontMetrics().height();
        // targetHeight 用途：大标题保留上下余量，避免高 DPI 与字体 fallback 时被裁剪。
        const int targetHeight = std::max(
            labelPointer->sizeHint().height(),
            fontHeight + std::max(0, extraVerticalPadding));
        labelPointer->setMinimumHeight(targetHeight);
        labelPointer->setMaximumHeight(targetHeight);
    }

    // bytesToGiBText 作用：
    // - 把字节数转换为 GiB 文本，保留 2 位小数。
    QString bytesToGiBText(const std::uint64_t bytesValue)
    {
        const double gibValue = static_cast<double>(bytesValue) / (1024.0 * 1024.0 * 1024.0);
        return QStringLiteral("%1 GiB").arg(gibValue, 0, 'f', 2);
    }

    // bytesPerSecondToText 作用：
    // - 把字节每秒速率转换为可读文本（B/s、KB/s、MB/s、GB/s）；
    // - 用于利用率子页摘要中展示磁盘/网络速率。
    QString bytesPerSecondToText(const double bytesPerSecondValue)
    {
        const double safeValue = std::max(0.0, bytesPerSecondValue);
        if (safeValue < 1024.0)
        {
            return QStringLiteral("%1 B/s").arg(safeValue, 0, 'f', 1);
        }
        if (safeValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB/s").arg(safeValue / 1024.0, 0, 'f', 1);
        }
        if (safeValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB/s").arg(safeValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB/s").arg(safeValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // bytesToReadableText 作用：
    // - 把字节数转换为 B/KB/MB/GB 的可读文本；
    // - 用于任务管理器参数区展示容量信息。
    QString bytesToReadableText(const double bytesValue)
    {
        const double safeValue = std::max(0.0, bytesValue);
        if (safeValue < 1024.0)
        {
            return QStringLiteral("%1 B").arg(safeValue, 0, 'f', 0);
        }
        if (safeValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB").arg(safeValue / 1024.0, 0, 'f', 1);
        }
        if (safeValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB").arg(safeValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB").arg(safeValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // resolveGpuEngineKeyFromCounter 作用：
    // - 把 PDH GPU 引擎计数器名称映射为固定键名；
    // - 仅关心任务管理器常见四类：3D/Copy/Video Encode/Video Decode。
    QString resolveGpuEngineKeyFromCounter(const QString& counterNameText)
    {
        const QString lowerText = counterNameText.toLower();
        if (lowerText.contains(QStringLiteral("engtype_3d")))
        {
            return QStringLiteral("3d");
        }
        if (lowerText.contains(QStringLiteral("engtype_copy")))
        {
            return QStringLiteral("copy");
        }
        if (lowerText.contains(QStringLiteral("engtype_videoencode"))
            || lowerText.contains(QStringLiteral("engtype_videncode")))
        {
            return QStringLiteral("video_encode");
        }
        if (lowerText.contains(QStringLiteral("engtype_videodecode"))
            || lowerText.contains(QStringLiteral("engtype_viddecode")))
        {
            return QStringLiteral("video_decode");
        }
        return QString();
    }

    // packLuidKey 作用：
    // - 把 Windows LUID 的 HighPart/LowPart 合并为稳定 64 位键；
    // - 用于 DXGI 显卡适配器与 PDH GPU Engine 实例之间做关联。
    std::uint64_t packLuidKey(const LUID& luidValue)
    {
        const std::uint64_t highPartValue =
            static_cast<std::uint64_t>(static_cast<std::uint32_t>(luidValue.HighPart));
        const std::uint64_t lowPartValue =
            static_cast<std::uint64_t>(luidValue.LowPart);
        return (highPartValue << 32U) | lowPartValue;
    }

    // interfaceLuidToKey 作用：
    // - 把 MIB_IF_ROW2 的 InterfaceLuid.Value 转为无符号键；
    // - 调用方用该键跨采样周期匹配同一块网卡。
    std::uint64_t interfaceLuidToKey(const std::uint64_t luidValue)
    {
        return luidValue;
    }

    // simplifyDiskInstanceName 作用：
    // - 把 PDH PhysicalDisk 实例名转换为任务管理器风格标题；
    // - 示例："0 C:" 显示为“磁盘 0 (C:)”。
    QString simplifyDiskInstanceName(const QString& instanceNameText)
    {
        const QString trimmedText = instanceNameText.trimmed();
        if (trimmedText.isEmpty())
        {
            return QStringLiteral("磁盘");
        }
        if (trimmedText == QStringLiteral("_Total"))
        {
            return QStringLiteral("磁盘总计");
        }

        const int spaceIndex = trimmedText.indexOf(QLatin1Char(' '));
        if (spaceIndex > 0)
        {
            const QString diskIndexText = trimmedText.left(spaceIndex).trimmed();
            const QString volumeText = trimmedText.mid(spaceIndex + 1).trimmed();
            if (!volumeText.isEmpty())
            {
                return QStringLiteral("磁盘 %1 (%2)").arg(diskIndexText, volumeText);
            }
            return QStringLiteral("磁盘 %1").arg(diskIndexText);
        }

        return QStringLiteral("磁盘 %1").arg(trimmedText);
    }

    // parseGpuAdapterKeyFromCounterName 作用：
    // - 从 PDH GPU Engine 或 GPU Adapter Memory 实例名中解析 LUID；
    // - Windows 常见格式包含“luid_0xHIGH_0xLOW”，失败时返回 false。
    bool parseGpuAdapterKeyFromCounterName(
        const QString& counterNameText,
        std::uint64_t* adapterKeyOut)
    {
        if (adapterKeyOut == nullptr)
        {
            return false;
        }

        static const QRegularExpression luidRegex(
            QStringLiteral("luid_0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)"));
        const QRegularExpressionMatch matchValue = luidRegex.match(counterNameText);
        if (!matchValue.hasMatch())
        {
            return false;
        }

        bool highOk = false;
        bool lowOk = false;
        const std::uint64_t highValue = matchValue.captured(1).toULongLong(&highOk, 16);
        const std::uint64_t lowValue = matchValue.captured(2).toULongLong(&lowOk, 16);
        if (!highOk || !lowOk)
        {
            return false;
        }

        *adapterKeyOut = ((highValue & 0xFFFFFFFFULL) << 32U) | (lowValue & 0xFFFFFFFFULL);
        return true;
    }

    // GpuAdapterTelemetrySnapshot：
    // - 通过 DXGI 适配器 LUID 绑定 WDDM/D3DKMT 数据，避免 WMI AdapterRAM 的 32 位截断；
    // - Frequency 是驱动当前时钟，MaxFrequency/MaxFrequencyOC 只用于最大值参考。
    struct GpuAdapterTelemetrySnapshot
    {
        std::uint64_t dedicatedVideoMemoryBytes = 0;
        std::uint64_t sharedSystemMemoryBytes = 0;
        double currentCoreClockMhz = 0.0;
        double maxCoreClockMhz = 0.0;
        double currentMemoryClockMhz = 0.0;
        double maxMemoryClockMhz = 0.0;
    };

    // queryD3dKmtAdapterInfo 作用：
    // - 统一组装 D3DKMTQueryAdapterInfo 请求；
    // - 返回 true 表示驱动接受该查询类型，旧 WDDM 驱动不支持时由调用方继续使用 DXGI 回退。
    bool queryD3dKmtAdapterInfo(
        const D3DKMT_HANDLE adapterHandle,
        const KMTQUERYADAPTERINFOTYPE queryType,
        void* queryBuffer,
        const UINT queryBufferSize)
    {
        if (adapterHandle == 0 || queryBuffer == nullptr || queryBufferSize == 0)
        {
            return false;
        }

        D3DKMT_QUERYADAPTERINFO queryInfo{};
        queryInfo.hAdapter = adapterHandle;
        queryInfo.Type = queryType;
        queryInfo.pPrivateDriverData = queryBuffer;
        queryInfo.PrivateDriverDataSize = queryBufferSize;
        return ::D3DKMTQueryAdapterInfo(&queryInfo) >= 0;
    }

    // queryGpuAdapterTelemetrySnapshot 作用：
    // - 输入 DXGI 返回的同一适配器 LUID，读取真实显存段大小和实时 3D/显存频率；
    // - 3D 节点通过 NODEMETADATA 识别，避免把 Copy/Video 节点时钟误当作 GPU 核心速度；
    // - 任一 D3DKMT 查询成功即返回 true，缺失字段保持 0 供上层按字段回退。
    bool queryGpuAdapterTelemetrySnapshot(
        const LUID& adapterLuid,
        GpuAdapterTelemetrySnapshot* snapshotOut)
    {
        if (snapshotOut == nullptr)
        {
            return false;
        }
        *snapshotOut = GpuAdapterTelemetrySnapshot{};

        D3DKMT_OPENADAPTERFROMLUID openInfo{};
        openInfo.AdapterLuid = adapterLuid;
        if (::D3DKMTOpenAdapterFromLuid(&openInfo) < 0 || openInfo.hAdapter == 0)
        {
            return false;
        }

        bool anyQuerySucceeded = false;

        D3DKMT_SEGMENTSIZEINFO segmentSizeInfo{};
        if (queryD3dKmtAdapterInfo(
                openInfo.hAdapter,
                KMTQAITYPE_GETSEGMENTSIZE,
                &segmentSizeInfo,
                sizeof(segmentSizeInfo)))
        {
            snapshotOut->dedicatedVideoMemoryBytes =
                static_cast<std::uint64_t>(segmentSizeInfo.DedicatedVideoMemorySize);
            snapshotOut->sharedSystemMemoryBytes =
                static_cast<std::uint64_t>(segmentSizeInfo.SharedSystemMemorySize);
            anyQuerySucceeded = true;
        }

        D3DKMT_ADAPTER_PERFDATA adapterPerfData{};
        adapterPerfData.PhysicalAdapterIndex = 0;
        if (queryD3dKmtAdapterInfo(
                openInfo.hAdapter,
                KMTQAITYPE_ADAPTERPERFDATA,
                &adapterPerfData,
                sizeof(adapterPerfData)))
        {
            constexpr double hertzPerMegahertz = 1000000.0;
            snapshotOut->currentMemoryClockMhz =
                static_cast<double>(adapterPerfData.MemoryFrequency) / hertzPerMegahertz;
            const double reportedMaxMemoryClockMhz = static_cast<double>(std::max(
                adapterPerfData.MaxMemoryFrequency,
                adapterPerfData.MaxMemoryFrequencyOC)) / hertzPerMegahertz;
            snapshotOut->maxMemoryClockMhz = std::max(
                snapshotOut->currentMemoryClockMhz,
                reportedMaxMemoryClockMhz);
            anyQuerySucceeded = true;
        }

        ULONG nodeCount = 1;
        D3DKMT_QUERYSTATISTICS adapterStatistics{};
        adapterStatistics.Type = D3DKMT_QUERYSTATISTICS_ADAPTER;
        adapterStatistics.AdapterLuid = adapterLuid;
        if (::D3DKMTQueryStatistics(&adapterStatistics) >= 0)
        {
            nodeCount = std::clamp(
                adapterStatistics.QueryResult.AdapterInformation.NodeCount,
                1UL,
                64UL);
        }

        double fallbackCurrentClockMhz = 0.0;
        double fallbackMaxClockMhz = 0.0;
        bool found3dNode = false;
        for (ULONG nodeOrdinal = 0; nodeOrdinal < nodeCount; ++nodeOrdinal)
        {
            D3DKMT_NODE_PERFDATA nodePerfData{};
            nodePerfData.NodeOrdinal = nodeOrdinal;
            nodePerfData.PhysicalAdapterIndex = 0;
            if (!queryD3dKmtAdapterInfo(
                    openInfo.hAdapter,
                    KMTQAITYPE_NODEPERFDATA,
                    &nodePerfData,
                    sizeof(nodePerfData)))
            {
                continue;
            }

            constexpr double hertzPerMegahertz = 1000000.0;
            const double currentClockMhz =
                static_cast<double>(nodePerfData.Frequency) / hertzPerMegahertz;
            const double reportedMaxClockMhz = static_cast<double>(std::max(
                nodePerfData.MaxFrequency,
                nodePerfData.MaxFrequencyOC)) / hertzPerMegahertz;
            const double maxClockMhz = std::max(currentClockMhz, reportedMaxClockMhz);
            fallbackCurrentClockMhz = std::max(fallbackCurrentClockMhz, currentClockMhz);
            fallbackMaxClockMhz = std::max(fallbackMaxClockMhz, maxClockMhz);
            anyQuerySucceeded = true;

            D3DKMT_NODEMETADATA nodeMetadata{};
            nodeMetadata.NodeOrdinalAndAdapterIndex = nodeOrdinal;
            if (queryD3dKmtAdapterInfo(
                    openInfo.hAdapter,
                    KMTQAITYPE_NODEMETADATA,
                    &nodeMetadata,
                    sizeof(nodeMetadata))
                && nodeMetadata.NodeData.EngineType == DXGK_ENGINE_TYPE_3D)
            {
                found3dNode = true;
                snapshotOut->currentCoreClockMhz = std::max(
                    snapshotOut->currentCoreClockMhz,
                    currentClockMhz);
                snapshotOut->maxCoreClockMhz = std::max(
                    snapshotOut->maxCoreClockMhz,
                    maxClockMhz);
            }
        }

        if (!found3dNode || snapshotOut->currentCoreClockMhz <= 0.0)
        {
            snapshotOut->currentCoreClockMhz = fallbackCurrentClockMhz;
        }
        if (!found3dNode || snapshotOut->maxCoreClockMhz <= 0.0)
        {
            snapshotOut->maxCoreClockMhz = fallbackMaxClockMhz;
        }

        D3DKMT_CLOSEADAPTER closeInfo{};
        closeInfo.hAdapter = openInfo.hAdapter;
        ::D3DKMTCloseAdapter(&closeInfo);
        return anyQuerySucceeded;
    }

    // formatGpuClockMhzText 作用：
    // - 把驱动返回的 MHz 值格式化为整数；
    // - 不支持实时性能数据时明确显示 N/A，避免把 0 MHz 误报为真实速度。
    QString formatGpuClockMhzText(const double clockMhz)
    {
        return clockMhz > 0.0
            ? QString::number(clockMhz, 'f', 0)
            : QStringLiteral("N/A");
    }

    // formatGpuMemoryUsageGiBText 作用：
    // - 区分系统级显存占用的真实 0 与计数器不可用；
    // - 计数器不可用时显示 N/A，避免再次把采样失败误报为 0.00 GiB。
    QString formatGpuMemoryUsageGiBText(
        const double usageGiB,
        const bool usageAvailable,
        const int decimalPlaces = 2)
    {
        return usageAvailable
            ? QString::number(std::max(0.0, usageGiB), 'f', decimalPlaces)
            : QStringLiteral("N/A");
    }

    // formatDurationText 作用：
    // - 把秒数格式化为“天:时:分:秒”；
    // - 用于 CPU 页“正常运行时间”展示。
    QString formatDurationText(const std::uint64_t totalSeconds)
    {
        const std::uint64_t dayCount = totalSeconds / 86400ULL;
        const std::uint64_t hourCount = (totalSeconds % 86400ULL) / 3600ULL;
        const std::uint64_t minuteCount = (totalSeconds % 3600ULL) / 60ULL;
        const std::uint64_t secondCount = totalSeconds % 60ULL;
        return QStringLiteral("%1:%2:%3:%4")
            .arg(dayCount)
            .arg(hourCount, 2, 10, QLatin1Char('0'))
            .arg(minuteCount, 2, 10, QLatin1Char('0'))
            .arg(secondCount, 2, 10, QLatin1Char('0'));
    }

    // queryCpuBrandTextByCpuid 作用：
    // - 通过 CPUID 指令读取 CPU 品牌字符串；
    // - 避免 CPU 型号依赖 PowerShell 查询。
    QString queryCpuBrandTextByCpuid()
    {
        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 0x80000000);
        const unsigned int maxExtendedLeaf = static_cast<unsigned int>(cpuInfo[0]);
        if (maxExtendedLeaf < 0x80000004)
        {
            return QStringLiteral("N/A");
        }

        char brandBuffer[49] = {};
        int* brandIntBuffer = reinterpret_cast<int*>(brandBuffer);
        __cpuid(brandIntBuffer, 0x80000002);
        __cpuid(brandIntBuffer + 4, 0x80000003);
        __cpuid(brandIntBuffer + 8, 0x80000004);

        const QString brandText = QString::fromLatin1(brandBuffer).trimmed();
        return brandText.isEmpty() ? QStringLiteral("N/A") : brandText;
    }

    // countBits 作用：
    // - 计算处理器亲和掩码中的置位数量；
    // - 用于统计逻辑处理器个数。
    int countBits(const KAFFINITY affinityMask)
    {
        return std::popcount(static_cast<unsigned long long>(affinityMask));
    }

    // MemoryHardwareSummarySnapshot 作用：
    // - 保存内存硬件摘要（频率、插槽、外形规格）；
    // - 由后台 PowerShell 查询填充，用于利用率详情页展示。
    struct MemoryHardwareSummarySnapshot
    {
        int speedMhz = 0;               // speedMhz：内存主频（MHz）。
        int usedSlots = 0;              // usedSlots：已使用插槽数量。
        int totalSlots = 0;             // totalSlots：主板总插槽数量。
        QString formFactorText = QStringLiteral("N/A"); // formFactorText：内存外形规格文本。
    };

    // GpuHardwareSummarySnapshot 作用：
    // - 保存显卡摘要（名称、驱动、显存）；
    // - 由后台 PowerShell 查询填充，用于 GPU 利用率详情页展示。
    struct GpuHardwareSummarySnapshot
    {
        QString adapterNameText = QStringLiteral("N/A");    // adapterNameText：显卡名称。
        QString driverVersionText = QStringLiteral("N/A");  // driverVersionText：驱动版本。
        QString driverDateText = QStringLiteral("N/A");     // driverDateText：驱动日期。
        QString pnpDeviceIdText = QStringLiteral("N/A");    // pnpDeviceIdText：PNP 设备ID。
        double dedicatedMemoryGiB = 0.0;                    // dedicatedMemoryGiB：专用显存 GiB。
        struct AdapterSnapshot
        {
            int adapterIndex = -1;
            QString adapterNameText = QStringLiteral("N/A");
            double dedicatedMemoryGiB = 0.0;
            double sharedMemoryGiB = 0.0;
            double currentCoreClockMhz = 0.0;
            double maxCoreClockMhz = 0.0;
            double currentMemoryClockMhz = 0.0;
            double maxMemoryClockMhz = 0.0;
        };
        QVector<AdapterSnapshot> adapterList;
    };

    // queryMemoryHardwareSummarySnapshot 作用：
    // - 查询内存硬件参数（速度、插槽、外形规格）；
    // - 仅在后台线程调用，避免阻塞 UI。
    MemoryHardwareSummarySnapshot queryMemoryHardwareSummarySnapshot()
    {
        const QString scriptText = QStringLiteral(
            "$mods=Get-CimInstance Win32_PhysicalMemory; "
            "$arr=Get-CimInstance Win32_PhysicalMemoryArray | Select-Object -First 1 -ExpandProperty MemoryDevices; "
            "$speed=($mods | Select-Object -First 1 -ExpandProperty ConfiguredClockSpeed); "
            "$formCode=($mods | Select-Object -First 1 -ExpandProperty FormFactor); "
            "$formText=if([int]$formCode -eq 8){'DIMM'}elseif([int]$formCode -eq 12){'SODIMM'}elseif([int]$formCode -gt 0){'代码'+[string]$formCode}else{'N/A'}; "
            "\"$speed|$($mods.Count)|$arr|$formText\"");
        const QString outputText = queryPowerShellTextSync(scriptText, 3200);
        const QStringList fieldList = outputText.split('|');

        MemoryHardwareSummarySnapshot snapshot;
        if (fieldList.size() >= 4)
        {
            snapshot.speedMhz = fieldList.at(0).trimmed().toInt();
            snapshot.usedSlots = fieldList.at(1).trimmed().toInt();
            snapshot.totalSlots = fieldList.at(2).trimmed().toInt();
            snapshot.formFactorText = fieldList.at(3).trimmed();
            if (snapshot.formFactorText.isEmpty())
            {
                snapshot.formFactorText = QStringLiteral("N/A");
            }
        }
        return snapshot;
    }

    // queryGpuHardwareSummarySnapshot 作用：
    // - 查询显卡摘要（名称、驱动版本、专用显存）；
    // - 仅在后台线程调用，避免阻塞 UI。
    GpuHardwareSummarySnapshot queryGpuHardwareSummarySnapshot()
    {
        const QString scriptText = QStringLiteral(
            "$gpu=Get-CimInstance Win32_VideoController | Select-Object -First 1 Name,DriverVersion,DriverDate,PNPDeviceID; "
            "if($null -eq $gpu){'N/A|N/A|N/A|N/A'}else{\"$($gpu.Name)|$($gpu.DriverVersion)|$($gpu.DriverDate)|$($gpu.PNPDeviceID)\"}");
        const QString outputText = queryPowerShellTextSync(scriptText, 2800);
        const QStringList fieldList = outputText.split('|');

        GpuHardwareSummarySnapshot snapshot;
        if (fieldList.size() >= 4)
        {
            snapshot.adapterNameText = fieldList.at(0).trimmed();
            snapshot.driverVersionText = fieldList.at(1).trimmed();
            snapshot.driverDateText = fieldList.at(2).trimmed();
            snapshot.pnpDeviceIdText = fieldList.at(3).trimmed();
        }

        // Win32_VideoController.AdapterRAM 是 32 位字段，大显存会截断到约 4 GiB；
        // 容量必须从与性能采样相同的 DXGI LUID/WDDM 适配器读取。
        IDXGIFactory6* factoryPointer = nullptr;
        if (SUCCEEDED(::CreateDXGIFactory1(IID_PPV_ARGS(&factoryPointer)))
            && factoryPointer != nullptr)
        {
            double selectedDedicatedMemoryGiB = -1.0;
            for (UINT adapterIndex = 0;; ++adapterIndex)
            {
                IDXGIAdapter1* adapterPointer = nullptr;
                const HRESULT enumStatus = factoryPointer->EnumAdapters1(adapterIndex, &adapterPointer);
                if (enumStatus == DXGI_ERROR_NOT_FOUND)
                {
                    break;
                }
                if (FAILED(enumStatus) || adapterPointer == nullptr)
                {
                    continue;
                }

                DXGI_ADAPTER_DESC1 adapterDesc{};
                adapterPointer->GetDesc1(&adapterDesc);
                if ((adapterDesc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) == 0)
                {
                    GpuHardwareSummarySnapshot::AdapterSnapshot adapterSnapshot;
                    adapterSnapshot.adapterIndex = static_cast<int>(adapterIndex);
                    const QString dxgiAdapterName =
                        QString::fromWCharArray(adapterDesc.Description).trimmed();
                    if (!dxgiAdapterName.isEmpty())
                    {
                        adapterSnapshot.adapterNameText = dxgiAdapterName;
                    }

                    GpuAdapterTelemetrySnapshot telemetrySnapshot;
                    queryGpuAdapterTelemetrySnapshot(adapterDesc.AdapterLuid, &telemetrySnapshot);
                    const std::uint64_t dedicatedMemoryBytes =
                        telemetrySnapshot.dedicatedVideoMemoryBytes > 0
                        ? telemetrySnapshot.dedicatedVideoMemoryBytes
                        : static_cast<std::uint64_t>(adapterDesc.DedicatedVideoMemory);
                    const std::uint64_t sharedMemoryBytes =
                        telemetrySnapshot.sharedSystemMemoryBytes > 0
                        ? telemetrySnapshot.sharedSystemMemoryBytes
                        : static_cast<std::uint64_t>(adapterDesc.SharedSystemMemory);
                    constexpr double oneGiBInBytes = 1024.0 * 1024.0 * 1024.0;
                    adapterSnapshot.dedicatedMemoryGiB =
                        static_cast<double>(dedicatedMemoryBytes) / oneGiBInBytes;
                    adapterSnapshot.sharedMemoryGiB =
                        static_cast<double>(sharedMemoryBytes) / oneGiBInBytes;
                    adapterSnapshot.currentCoreClockMhz = telemetrySnapshot.currentCoreClockMhz;
                    adapterSnapshot.maxCoreClockMhz = telemetrySnapshot.maxCoreClockMhz;
                    adapterSnapshot.currentMemoryClockMhz = telemetrySnapshot.currentMemoryClockMhz;
                    adapterSnapshot.maxMemoryClockMhz = telemetrySnapshot.maxMemoryClockMhz;
                    snapshot.adapterList.push_back(adapterSnapshot);

                    // 主 GPU 摘要优先选择专用显存最大的适配器，避免多 GPU 机器被核显占据。
                    if (adapterSnapshot.dedicatedMemoryGiB > selectedDedicatedMemoryGiB)
                    {
                        selectedDedicatedMemoryGiB = adapterSnapshot.dedicatedMemoryGiB;
                        snapshot.adapterNameText = adapterSnapshot.adapterNameText;
                        snapshot.dedicatedMemoryGiB = adapterSnapshot.dedicatedMemoryGiB;
                    }
                }
                adapterPointer->Release();
            }
            factoryPointer->Release();
        }
        return snapshot;
    }

    // formatGpuHardwareSummaryText 作用：
    // - 在 UI 线程把 DXGI/WDDM 快照格式化到“显卡”信息页；
    // - WMI 仅补充驱动与显示模式，不再承担显存容量识别。
    QString formatGpuHardwareSummaryText(
        const GpuHardwareSummarySnapshot& snapshot,
        const QString& wmiText)
    {
        QStringList adapterBlockList;
        for (const GpuHardwareSummarySnapshot::AdapterSnapshot& adapter : snapshot.adapterList)
        {
            const QString dedicatedMemoryText = adapter.dedicatedMemoryGiB > 0.0
                ? QString::number(adapter.dedicatedMemoryGiB, 'f', 2)
                : QStringLiteral("N/A");
            const QString sharedMemoryText = adapter.sharedMemoryGiB > 0.0
                ? QString::number(adapter.sharedMemoryGiB, 'f', 2)
                : QStringLiteral("N/A");
            adapterBlockList.push_back(
                ks::i18n::contextText(
                    QStringLiteral("hardware.gpu.static.telemetry.adapter"),
                    QStringLiteral("[GPU %1 - DXGI/WDDM]\n名称: %2\n专用显存: %3 GiB\n共享 GPU 内存: %4 GiB\n核心频率: %5 MHz（最大 %6 MHz）\n显存频率: %7 MHz（最大 %8 MHz）"))
                .arg(adapter.adapterIndex)
                .arg(adapter.adapterNameText)
                .arg(dedicatedMemoryText)
                .arg(sharedMemoryText)
                .arg(formatGpuClockMhzText(adapter.currentCoreClockMhz))
                .arg(formatGpuClockMhzText(adapter.maxCoreClockMhz))
                .arg(formatGpuClockMhzText(adapter.currentMemoryClockMhz))
                .arg(formatGpuClockMhzText(adapter.maxMemoryClockMhz)));
        }

        if (adapterBlockList.isEmpty())
        {
            adapterBlockList.push_back(
                ks::i18n::contextText(
                    QStringLiteral("hardware.gpu.static.telemetry.unavailable"),
                    QStringLiteral("未从 DXGI/WDDM 读取到 GPU 显存与频率信息。")));
        }

        const QString telemetryHeading = ks::i18n::contextText(
            QStringLiteral("hardware.gpu.static.telemetry.heading"),
            QStringLiteral("[实时 GPU 硬件信息]"));
        const QString wmiHeading = ks::i18n::contextText(
            QStringLiteral("hardware.gpu.static.wmi.heading"),
            QStringLiteral("[WMI 驱动与显示信息]"));
        return telemetryHeading
            + QStringLiteral("\n")
            + adapterBlockList.join(QStringLiteral("\n\n"))
            + QStringLiteral("\n\n")
            + wmiHeading
            + QStringLiteral("\n")
            + wmiText.trimmed();
    }

    // createNoFrameChartView 作用：
    // - 创建无边框 ChartView，统一 Dock 内视觉风格。
    QChartView* createNoFrameChartView(QChart* chart, QWidget* parentWidget)
    {
        configureTransparentChart(chart);
        QChartView* chartView = new QChartView(chart, parentWidget);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setFrameShape(QFrame::NoFrame);
        // ChartView 本身也可能产生 QGraphicsView 滚动条，这里统一关闭并允许高度压到 0。
        chartView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        chartView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        chartView->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
        configureCompressibleWidget(chartView, QSizePolicy::Expanding, QSizePolicy::Expanding);
        appendTransparentBackgroundStyle(chartView);
        return chartView;
    }

    // createPlotBackgroundChartView 作用：
    // - 创建保留 plotArea 样式的 ChartView；
    // - 用于所有利用率折线图，使绘图区方框、网格和面积填充不会被通用透明逻辑关闭；
    // - 返回值：已设置无边框和透明 viewport 的 QChartView。
    QChartView* createPlotBackgroundChartView(QChart* chart, QWidget* parentWidget)
    {
        configureTransparentChartViewOnly(chart);
        // QChart 的 SeriesAnimations 会按点下标把整条旧曲线形变成新曲线；
        // 滑动窗口同时删除首点、追加尾点时，这会表现为每秒整图重绘。曲线数据保持即时更新，
        // 仅由 animateLiveValueAxisRange 平滑移动可视 X 窗口。
        chart->setAnimationOptions(QChart::NoAnimation);
        QChartView* chartView = new QChartView(chart, parentWidget);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setFrameShape(QFrame::NoFrame);
        // ChartView 本身仍然不显示滚动条，尺寸由外层利用率布局统一控制。
        chartView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        chartView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        chartView->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
        configureCompressibleWidget(chartView, QSizePolicy::Expanding, QSizePolicy::Expanding);
        appendTransparentBackgroundStyle(chartView);
        return chartView;
    }

    // animateLiveValueAxisRange 作用：
    // - 折线追加新点后只平滑移动 X 轴窗口，不对整条 QLineSeries 做点位形变；
    // - 同一坐标轴在一次刷新中被双线共用时，后一次目标会替换前一次动画；
    // - 260 ms 明显短于 1 s 采样周期，避免动画积压。
    void animateLiveValueAxisRange(
        QValueAxis* axisPointer,
        const double targetMinValue,
        const double targetMaxValue)
    {
        if (axisPointer == nullptr || targetMaxValue <= targetMinValue)
        {
            return;
        }

        const double startMinValue = axisPointer->min();
        const double startMaxValue = axisPointer->max();
        if (qFuzzyCompare(startMinValue + 1.0, targetMinValue + 1.0)
            && qFuzzyCompare(startMaxValue + 1.0, targetMaxValue + 1.0))
        {
            axisPointer->setRange(targetMinValue, targetMaxValue);
            return;
        }

        const QList<QVariantAnimation*> previousAnimations =
            axisPointer->findChildren<QVariantAnimation*>(
                QStringLiteral("kswordLiveAxisRangeAnimation"),
                Qt::FindDirectChildrenOnly);
        for (QVariantAnimation* previousAnimation : previousAnimations)
        {
            previousAnimation->stop();
            delete previousAnimation;
        }

        QVariantAnimation* axisAnimation = new QVariantAnimation(axisPointer);
        axisAnimation->setObjectName(QStringLiteral("kswordLiveAxisRangeAnimation"));
        axisAnimation->setDuration(260);
        axisAnimation->setEasingCurve(QEasingCurve::OutCubic);
        axisAnimation->setStartValue(0.0);
        axisAnimation->setEndValue(1.0);

        const QPointer<QValueAxis> safeAxisPointer(axisPointer);
        QObject::connect(
            axisAnimation,
            &QVariantAnimation::valueChanged,
            axisPointer,
            [safeAxisPointer,
             startMinValue,
             startMaxValue,
             targetMinValue,
             targetMaxValue](const QVariant& progressValue)
            {
                if (safeAxisPointer == nullptr)
                {
                    return;
                }
                const double progress = progressValue.toDouble();
                safeAxisPointer->setRange(
                    startMinValue + (targetMinValue - startMinValue) * progress,
                    startMaxValue + (targetMaxValue - startMaxValue) * progress);
            });
        QObject::connect(
            axisAnimation,
            &QVariantAnimation::finished,
            axisPointer,
            [safeAxisPointer, targetMinValue, targetMaxValue]()
            {
                if (safeAxisPointer != nullptr)
                {
                    safeAxisPointer->setRange(targetMinValue, targetMaxValue);
                }
            });
        QObject::connect(
            axisAnimation,
            &QVariantAnimation::finished,
            axisAnimation,
            &QObject::deleteLater);
        axisAnimation->start();
    }

    // colorWithAlpha 作用：
    // - 基于折线主色生成不同透明度的辅助色；
    // - 用于绘图区背景、网格、边框和面积填充保持同一色相。
    QColor colorWithAlpha(const QColor& sourceColor, const int alphaValue)
    {
        return QColor(
            sourceColor.red(),
            sourceColor.green(),
            sourceColor.blue(),
            std::clamp(alphaValue, 0, 255));
    }

    // initializeLineSeriesHistory 作用：
    // - 按固定历史长度预填充折线点；
    // - 让界面首次显示时图表有完整 X 轴窗口，后续采样只做滑动窗口追加。
    void initializeLineSeriesHistory(
        QLineSeries* lineSeries,
        const int historyLength,
        const double sampleValue = 0.0)
    {
        if (lineSeries == nullptr)
        {
            return;
        }

        for (int indexValue = 0; indexValue < historyLength; ++indexValue)
        {
            lineSeries->append(indexValue, sampleValue);
        }
    }

    // createBaselineSeries 作用：
    // - 创建与折线点数量一致的 0 轴基准线；
    // - QAreaSeries 依赖上下两条线闭合区域，因此每条利用率线都单独持有基准线。
    QLineSeries* createBaselineSeries(
        QWidget* parentWidget,
        const int historyLength,
        const double baselineValue = 0.0)
    {
        QLineSeries* baselineSeries = new QLineSeries(parentWidget);
        initializeLineSeriesHistory(baselineSeries, historyLength, baselineValue);
        return baselineSeries;
    }

    // addFilledAreaSeries 作用：
    // - 把一条折线和一条基准线组合为面积图并加入 QChart；
    // - 返回值：新建的 QAreaSeries，失败时返回 nullptr。
    QAreaSeries* addFilledAreaSeries(
        QChart* chartPointer,
        QLineSeries* lineSeries,
        QLineSeries* baselineSeries,
        const QColor& lineColor,
        const int fillAlpha = 46)
    {
        if (chartPointer == nullptr || lineSeries == nullptr || baselineSeries == nullptr)
        {
            return nullptr;
        }

        QAreaSeries* areaSeries = new QAreaSeries(lineSeries, baselineSeries);
        areaSeries->setName(lineSeries->name());
        areaSeries->setColor(colorWithAlpha(lineColor, fillAlpha));
        areaSeries->setBorderColor(lineColor);
        areaSeries->setPen(QPen(lineColor, 1.6));
        chartPointer->addSeries(areaSeries);
        return areaSeries;
    }

    // configureUtilizationPlotChart 作用：
    // - 统一设置利用率图表的外观；
    // - 保留透明外背景，同时给 plotArea 添加浅色背景和明确方框。
    void configureUtilizationPlotChart(
        QChart* chartPointer,
        const QColor& accentColor,
        const QString& titleText = QString(),
        const bool legendVisible = false)
    {
        if (chartPointer == nullptr)
        {
            return;
        }

        chartPointer->legend()->setVisible(legendVisible);
        if (legendVisible)
        {
            chartPointer->legend()->setAlignment(Qt::AlignBottom);
        }
        chartPointer->setBackgroundVisible(false);
        chartPointer->setBackgroundRoundness(0);
        chartPointer->setMargins(QMargins(0, 0, 0, 0));
        chartPointer->setTitle(titleText);
        chartPointer->setTitleBrush(QBrush(KswordTheme::TextPrimaryColor()));
        if (legendVisible)
        {
            chartPointer->legend()->setLabelColor(KswordTheme::TextSecondaryColor());
        }
        chartPointer->setPlotAreaBackgroundVisible(true);
        chartPointer->setPlotAreaBackgroundBrush(QBrush(colorWithAlpha(accentColor, 18)));
        chartPointer->setPlotAreaBackgroundPen(QPen(colorWithAlpha(accentColor, 150), 1.0));
    }

    // configureUtilizationValueAxis 作用：
    // - 统一隐藏轴标签但保留轴线与网格；
    // - 方框和横向网格共同强化利用率趋势图边界。
    void configureUtilizationValueAxis(
        QValueAxis* axisPointer,
        const QColor& accentColor,
        const double lowerValue,
        const double upperValue)
    {
        if (axisPointer == nullptr)
        {
            return;
        }

        axisPointer->setRange(lowerValue, upperValue);
        axisPointer->setLabelsVisible(false);
        axisPointer->setGridLineVisible(true);
        axisPointer->setMinorGridLineVisible(false);
        axisPointer->setLineVisible(true);
        axisPointer->setLinePen(QPen(colorWithAlpha(accentColor, 140), 1.0));
        axisPointer->setGridLinePen(QPen(colorWithAlpha(accentColor, 46), 1.0));
    }

    // queryPowerShellTextSync 作用：
    // - 在当前线程同步执行一条 PowerShell 脚本并返回文本结果；
    // - 仅在后台工作线程调用，避免阻塞 UI 线程。
    // 参数 scriptText：要执行的 PowerShell 命令文本。
    // 参数 timeoutMs：超时时间（毫秒）。
    // 返回值：标准输出文本；失败时返回错误描述。
    QString queryPowerShellTextSync(const QString& scriptText, const int timeoutMs)
    {
        QProcess process;
        process.setProgram(QStringLiteral("powershell.exe"));
        process.setArguments({
            QStringLiteral("-NoProfile"),
            QStringLiteral("-ExecutionPolicy"),
            QStringLiteral("Bypass"),
            QStringLiteral("-Command"),
            scriptText
            });
        process.start();

        // waitStartedOk 用途：判断 PowerShell 进程是否成功拉起。
        const bool waitStartedOk = process.waitForStarted(1200);
        if (!waitStartedOk)
        {
            return QStringLiteral("PowerShell启动失败。");
        }

        // waitFinishedOk 用途：判断命令是否在超时前结束。
        const bool waitFinishedOk = process.waitForFinished(timeoutMs);
        if (!waitFinishedOk)
        {
            process.kill();
            process.waitForFinished(800);
            return QStringLiteral("PowerShell执行超时（%1 ms）。").arg(timeoutMs);
        }

        // standardOutputText 用途：保存命令标准输出。
        // standardErrorText  用途：保存命令标准错误输出。
        const QString standardOutputText = QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
        const QString standardErrorText = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
        {
            return QStringLiteral("PowerShell执行失败。\nExitCode=%1\nError=%2")
                .arg(process.exitCode())
                .arg(standardErrorText.isEmpty() ? QStringLiteral("<空>") : standardErrorText);
        }

        if (standardOutputText.isEmpty())
        {
            return QStringLiteral("<无输出>");
        }
        return standardOutputText;
    }

    // buildOverviewStaticTextSnapshot 作用：
    // - 构建“概览”页静态文本快照；
    // - 仅做轻量 Win32/Qt 系统信息读取，不依赖 UI 对象。
    QString buildOverviewStaticTextSnapshot()
    {
        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);

        MEMORYSTATUSEX memoryStatus{};
        memoryStatus.dwLength = sizeof(memoryStatus);
        ::GlobalMemoryStatusEx(&memoryStatus);

        QString text;
        text += QStringLiteral("系统名称: %1\n").arg(QSysInfo::prettyProductName());
        text += QStringLiteral("CPU架构: %1\n").arg(QSysInfo::currentCpuArchitecture());
        text += QStringLiteral("内核类型: %1\n").arg(QSysInfo::kernelType());
        text += QStringLiteral("内核版本: %1\n").arg(QSysInfo::kernelVersion());
        text += QStringLiteral("逻辑处理器数量: %1\n").arg(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        text += QStringLiteral("处理器组掩码(十六进制): 0x%1\n")
            .arg(QString::number(static_cast<qulonglong>(systemInfo.dwActiveProcessorMask), 16).toUpper());
        text += QStringLiteral("页面大小: %1 字节\n").arg(systemInfo.dwPageSize);
        text += QStringLiteral("物理内存总量: %1\n").arg(bytesToGiBText(memoryStatus.ullTotalPhys));
        text += QStringLiteral("当前可用内存: %1\n").arg(bytesToGiBText(memoryStatus.ullAvailPhys));
        text += QStringLiteral("虚拟内存总量: %1\n").arg(bytesToGiBText(memoryStatus.ullTotalVirtual));
        text += QStringLiteral("当前可用虚拟内存: %1\n").arg(bytesToGiBText(memoryStatus.ullAvailVirtual));
        text += QStringLiteral("系统启动时间: %1\n")
            .arg(QDateTime::fromMSecsSinceEpoch(
                QDateTime::currentMSecsSinceEpoch() - static_cast<qint64>(::GetTickCount64()))
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
        return text;
    }

    // buildOverviewPeripheralTextSnapshot 作用：
    // - 采集“概览”页的外设与硬件设备总览文本；
    // - 覆盖用户要求的声卡/网卡/摄像头，并补充主板/BIOS/磁盘等信息。
    // 说明：
    // - 该函数会执行 PowerShell + CIM 查询；
    // - 必须在后台线程调用，避免阻塞 UI 线程。
    QString buildOverviewPeripheralTextSnapshot()
    {
        const QString scriptText = QStringLiteral(
            "$ErrorActionPreference='SilentlyContinue'; "
            "function Write-Section([string]$title,[object]$rows){ "
            "  if($null -eq $rows){return \"[$title]`n<未检测到>`n`n\"}; "
            "  $count = ($rows | Measure-Object).Count; "
            "  if($count -eq 0){return \"[$title]`n<未检测到>`n`n\"}; "
            "  $table = ($rows | Format-Table -AutoSize | Out-String); "
            "  return \"[$title]`n$table`n\"; "
            "}; "
            "$text = ''; "
            "$baseBoardRows = Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version,SerialNumber; "
            "$biosRows = Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber; "
            "$cpuRows = Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed; "
            "$diskRows = Get-CimInstance Win32_DiskDrive | Select-Object Model,InterfaceType,MediaType,Size,SerialNumber; "
            "$gpuRows = Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM,DriverVersion,VideoProcessor; "
            "$soundRows = Get-CimInstance Win32_SoundDevice | Select-Object Name,Manufacturer,Status; "
            "$networkRows = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true } | "
            "  Select-Object Name,AdapterType,Speed,MACAddress,NetConnectionStatus,Manufacturer; "
            "$cameraRows = Get-CimInstance Win32_PnPEntity | "
            "  Where-Object { $_.PNPClass -eq 'Image' -or $_.Service -like '*usbvideo*' } | "
            "  Select-Object Name,Manufacturer,Status,Service,PNPDeviceID; "
            "$monitorRows = Get-CimInstance Win32_DesktopMonitor | Select-Object Name,MonitorType,ScreenWidth,ScreenHeight,Status; "
            "$printerRows = Get-CimInstance Win32_Printer | Select-Object Name,DriverName,PortName,WorkOffline,Default; "
            "$usbRows = Get-CimInstance Win32_USBControllerDevice | Select-Object Dependent -First 30; "
            "$text += Write-Section '主板' $baseBoardRows; "
            "$text += Write-Section 'BIOS' $biosRows; "
            "$text += Write-Section '处理器' $cpuRows; "
            "$text += Write-Section '磁盘设备' $diskRows; "
            "$text += Write-Section '显卡设备' $gpuRows; "
            "$text += Write-Section '声卡设备' $soundRows; "
            "$text += Write-Section '网卡设备(物理)' $networkRows; "
            "$text += Write-Section '摄像头设备' $cameraRows; "
            "$text += Write-Section '显示器设备' $monitorRows; "
            "$text += Write-Section '打印机设备' $printerRows; "
            "$text += Write-Section 'USB控制器映射(前30条)' $usbRows; "
            "$text");
        return queryPowerShellTextSync(scriptText, 9000);
    }

    // buildGpuStaticTextSnapshot 作用：
    // - 通过 WMI 采集显卡信息文本；
    // - 该函数会调用 PowerShell，必须放在后台线程执行。
    QString buildGpuStaticTextSnapshot()
    {
        const QString scriptText = QStringLiteral(
            "$list=Get-CimInstance Win32_VideoController | "
            "Select-Object Name,DriverVersion,VideoProcessor,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate,PNPDeviceID; "
            "if($null -eq $list){'未读取到显卡信息'} else {$list | Format-Table -AutoSize | Out-String}");
        return queryPowerShellTextSync(scriptText, 5000);
    }

    // buildMemoryStaticTextSnapshot 作用：
    // - 通过 WMI 采集内存条与系统内存信息文本；
    // - 该函数会调用 PowerShell，必须放在后台线程执行。
    QString buildMemoryStaticTextSnapshot()
    {
        const QString scriptText = QStringLiteral(
            "$phy=Get-CimInstance Win32_PhysicalMemory | "
            "Select-Object BankLabel,Manufacturer,PartNumber,ConfiguredClockSpeed,Capacity,SMBIOSMemoryType; "
            "$os=Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory; "
            "'[物理内存条]';"
            "$phy | Format-Table -AutoSize | Out-String; "
            "'[操作系统内存]';"
            "$os | Format-List | Out-String");
        return queryPowerShellTextSync(scriptText, 6000);
    }

    // SensorProbeResult 作用：
    // - 保存一次传感器探测的值、来源和失败原因；
    // - 供异步刷新逻辑决定界面展示与日志输出。
    struct SensorProbeResult
    {
        QString valueText = QStringLiteral("N/A"); // valueText：探测到的传感器值文本。
        QString sourceText; // sourceText：成功读取时的来源标识。
        QString reasonText; // reasonText：失败时的原因汇总。
        QString rawOutputText; // rawOutputText：脚本原始返回文本，便于诊断。
        bool success = false; // success：本次探测是否读到有效值。
        bool expectedUnavailable = false; // expectedUnavailable：传感器源按系统能力缺失，属于可预期不可用。
    };

#pragma pack(push, 4)
    // CoreTempSharedDataPrefix 作用：
    // - 映射 Core Temp 共享内存结构中长期兼容的原始前缀；
    // - 新版 CoreTempMappingObjectEx 会在该前缀后追加字段，温度读取只需要前缀；
    // - 结构体成员顺序来自 Core Temp 开发者文档，4 字节对齐必须保持一致。
    struct CoreTempSharedDataPrefix
    {
        unsigned int uiLoad[256];      // uiLoad：每线程/核心负载，当前温度读取不使用。
        unsigned int uiTjMax[128];     // uiTjMax：每核心 TjMax，用于 DeltaToTjMax 转换。
        unsigned int uiCoreCnt;        // uiCoreCnt：单 CPU 核心数量。
        unsigned int uiCPUCnt;         // uiCPUCnt：CPU 封装数量。
        float fTemp[256];              // fTemp：每核心温度或到 TjMax 距离。
        float fVID;                    // fVID：Core Temp 上报的 VID 电压。
        float fCPUSpeed;               // fCPUSpeed：CPU 当前频率。
        float fFSBSpeed;               // fFSBSpeed：总线频率。
        float fMultiplier;             // fMultiplier：倍频。
        char sCPUName[100];            // sCPUName：Core Temp 识别到的 CPU 名称。
        unsigned char ucFahrenheit;    // ucFahrenheit：温度是否为华氏度。
        unsigned char ucDeltaToTjMax;  // ucDeltaToTjMax：温度字段是否为到 TjMax 的距离。
    };
#pragma pack(pop)

    // isReadableSensorValue 作用：
    // - 判断传感器文本是否是可展示的有效值；
    // - 统一处理空串和 N/A。
    bool isReadableSensorValue(const QString& sensorValueText)
    {
        const QString trimmedValueText = sensorValueText.trimmed();
        return !trimmedValueText.isEmpty() && trimmedValueText != QStringLiteral("N/A");
    }

    // formatCelsiusSensorValue 作用：
    // - 统一校验并格式化摄氏温度；
    // - 输入 valueCelsius 为摄氏度浮点值；
    // - 返回空串表示越界或 NaN，否则返回带 °C 后缀的展示文本。
    QString formatCelsiusSensorValue(const double valueCelsius)
    {
        if (!std::isfinite(valueCelsius) || valueCelsius < -30.0 || valueCelsius > 130.0)
        {
            return QString();
        }
        return QStringLiteral("%1°C").arg(valueCelsius, 0, 'f', 1);
    }

    // parseSensorProbeOutput 作用：
    // - 解析 PowerShell 返回的 OK|... / ERR|... 协议文本；
    // - 回退兼容旧版“只返回一个值”的简单文本。
    SensorProbeResult parseSensorProbeOutput(const QString& rawOutputText)
    {
        SensorProbeResult probeResult;
        probeResult.rawOutputText = rawOutputText.trimmed();

        const QString firstLineText = probeResult.rawOutputText
            .split('\n', Qt::SkipEmptyParts)
            .value(0)
            .trimmed();
        if (firstLineText.startsWith(QStringLiteral("OK|")))
        {
            const QStringList resultPartList = firstLineText.split('|');
            probeResult.valueText =
                resultPartList.size() >= 2 ? resultPartList.at(1).trimmed() : QStringLiteral("N/A");
            probeResult.sourceText =
                resultPartList.size() >= 3 ? resultPartList.mid(2).join(QStringLiteral("|")).trimmed() : QString();
            probeResult.success = isReadableSensorValue(probeResult.valueText);
            if (!probeResult.success)
            {
                probeResult.reasonText = QStringLiteral("脚本返回成功标记，但值为空。");
            }
            return probeResult;
        }

        if (firstLineText.startsWith(QStringLiteral("ERR|")))
        {
            probeResult.reasonText = firstLineText.mid(4).trimmed();
            if (probeResult.reasonText.isEmpty())
            {
                probeResult.reasonText = QStringLiteral("脚本返回失败标记，但未提供原因。");
            }
            return probeResult;
        }

        if (firstLineText.isEmpty())
        {
            probeResult.reasonText = QStringLiteral("脚本无输出。");
            return probeResult;
        }

        if (firstLineText == QStringLiteral("<无输出>")
            || firstLineText.contains(QStringLiteral("PowerShell"))
            || firstLineText.contains(QStringLiteral("失败"))
            || firstLineText.contains(QStringLiteral("超时")))
        {
            probeResult.reasonText = firstLineText;
            return probeResult;
        }

        probeResult.valueText = firstLineText;
        probeResult.success = isReadableSensorValue(probeResult.valueText);
        if (!probeResult.success)
        {
            probeResult.reasonText = QStringLiteral("脚本仅返回了空值或 N/A。");
        }
        return probeResult;
    }

    // buildSensorProbeSignatureText 作用：
    // - 生成用于日志去重的稳定签名；
    // - 成功时包含来源和值，失败时包含原因。
    QString buildSensorProbeSignatureText(
        const QString& probeNameText,
        const SensorProbeResult& probeResult)
    {
        if (probeResult.success)
        {
            return QStringLiteral("%1:OK:%2:%3")
                .arg(probeNameText)
                .arg(probeResult.sourceText)
                .arg(probeResult.valueText);
        }

        return QStringLiteral("%1:ERR:%2")
            .arg(probeNameText)
            .arg(probeResult.reasonText);
    }

    // buildSensorProbeLogFragment 作用：
    // - 生成单个传感器项的日志片段；
    // - 失败时优先带出原因，成功时带出来源和值。
    QString buildSensorProbeLogFragment(
        const QString& probeNameText,
        const SensorProbeResult& probeResult)
    {
        if (probeResult.success)
        {
            return QStringLiteral("%1=%2，来源=%3")
                .arg(probeNameText)
                .arg(probeResult.valueText)
                .arg(probeResult.sourceText.isEmpty() ? QStringLiteral("未标注") : probeResult.sourceText);
        }

        return QStringLiteral("%1失败，原因=%2")
            .arg(probeNameText)
            .arg(probeResult.reasonText.isEmpty() ? QStringLiteral("未提供原因。") : probeResult.reasonText);
    }

    // sensorReasonContainsAny 作用：
    // - 在探测诊断文本中查找任一特征片段；
    // - 参数 reasonText 为 PowerShell/CIM/Counter 汇总原因；
    // - 参数 markerTextList 为需要匹配的可预期或硬失败关键字；
    // - 返回 true 表示至少命中一个关键字，否则返回 false。
    bool sensorReasonContainsAny(
        const QString& reasonText,
        const QStringList& markerTextList)
    {
        for (const QString& markerText : markerTextList)
        {
            if (!markerText.isEmpty() && reasonText.contains(markerText, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    // sensorProbeHasExecutionFailure 作用：
    // - 区分“脚本/权限/进程执行失败”和“硬件传感器源本来不存在”；
    // - 真正执行异常仍需要 WARN，避免把 PowerShell 超时或拒绝访问静默吞掉；
    // - 返回 true 表示应按异常失败处理，false 表示还需继续做可预期不可用判定。
    bool sensorProbeHasExecutionFailure(const SensorProbeResult& probeResult)
    {
        const QString diagnosticText = probeResult.reasonText
            + QStringLiteral("\n")
            + probeResult.rawOutputText;
        static const QStringList hardFailureMarkerList = {
            QStringLiteral("PowerShell启动失败"),
            QStringLiteral("PowerShell执行失败"),
            QStringLiteral("PowerShell执行超时"),
            QStringLiteral("脚本无输出"),
            QStringLiteral("脚本返回成功标记"),
            QStringLiteral("脚本仅返回"),
            QStringLiteral("拒绝访问"),
            QStringLiteral("Access denied"),
            QStringLiteral("RPC")
        };
        return sensorReasonContainsAny(diagnosticText, hardFailureMarkerList);
    }

    // isExpectedCpuTemperatureUnavailable 作用：
    // - 识别 Windows 常见的 CPU 温度不可暴露场景；
    // - Libre/OpenHardwareMonitor 命名空间缺失、ACPI 热区不支持、热区计数器无实例都很常见；
    // - 返回 true 时 UI 继续展示 N/A，但日志不应升级为 WARN。
    bool isExpectedCpuTemperatureUnavailable(const SensorProbeResult& probeResult)
    {
        if (probeResult.success || probeResult.reasonText.isEmpty())
        {
            return false;
        }
        if (sensorProbeHasExecutionFailure(probeResult))
        {
            return false;
        }

        static const QStringList expectedTemperatureMarkerList = {
            QStringLiteral("Core Temp共享内存未打开"),
            QStringLiteral("无效命名空间"),
            QStringLiteral("Invalid namespace"),
            QStringLiteral("不支持"),
            QStringLiteral("Not supported"),
            QStringLiteral("指定的实例不存在"),
            QStringLiteral("does not exist"),
            QStringLiteral("未找到CPU温度传感器"),
            QStringLiteral("无热区数据"),
            QStringLiteral("读取值无效"),
            QStringLiteral("样本值无效"),
            QStringLiteral("无数据"),
            QStringLiteral("传感器存在但值无效"),
            QStringLiteral("热区值超出有效范围"),
            QStringLiteral("未找到可用温度来源")
        };
        return sensorReasonContainsAny(probeResult.reasonText, expectedTemperatureMarkerList);
    }

    // isExpectedCpuVoltageUnavailable 作用：
    // - 识别 Win32_Processor CurrentVoltage 不提供或不可解析的常见情况；
    // - 这些值来自 SMBIOS，很多主板/虚拟化环境不会提供真实核心电压；
    // - 返回 true 时只保留 N/A 展示，不输出误导性的 WARN。
    bool isExpectedCpuVoltageUnavailable(const SensorProbeResult& probeResult)
    {
        if (probeResult.success || probeResult.reasonText.isEmpty())
        {
            return false;
        }
        if (sensorProbeHasExecutionFailure(probeResult))
        {
            return false;
        }

        static const QStringList expectedVoltageMarkerList = {
            QStringLiteral("CurrentVoltage"),
            QStringLiteral("无法解析"),
            QStringLiteral("未返回处理器对象"),
            QStringLiteral("WMIC path Win32_Processor: 无输出"),
            QStringLiteral("SMBIOS Type4"),
            QStringLiteral("SMBIOS RSMB")
        };
        return sensorReasonContainsAny(probeResult.reasonText, expectedVoltageMarkerList);
    }

    // queryCoreTempSharedMemoryProbeResult 作用：
    // - 读取 Core Temp 暴露的全局共享内存 CoreTempMappingObject；
    // - CPU-Z/硬件监控类工具通常依赖驱动/MSR，Windows WMI 读不到时可借助此类后端；
    // - 成功时返回当前核心温度最大值，失败时返回结构化原因。
    SensorProbeResult queryCoreTempSharedMemoryProbeResult()
    {
        SensorProbeResult probeResult;
        HANDLE mappingHandle = ::OpenFileMappingW(
            FILE_MAP_READ,
            FALSE,
            L"Global\\CoreTempMappingObjectEx");
        if (mappingHandle == nullptr)
        {
            mappingHandle = ::OpenFileMappingW(
                FILE_MAP_READ,
                FALSE,
                L"CoreTempMappingObjectEx");
        }
        if (mappingHandle == nullptr)
        {
            mappingHandle = ::OpenFileMappingW(
                FILE_MAP_READ,
                FALSE,
                L"Global\\CoreTempMappingObject");
        }
        if (mappingHandle == nullptr)
        {
            mappingHandle = ::OpenFileMappingW(
                FILE_MAP_READ,
                FALSE,
                L"CoreTempMappingObject");
        }
        if (mappingHandle == nullptr)
        {
            probeResult.reasonText = QStringLiteral("Core Temp共享内存未打开。");
            return probeResult;
        }

        const void* mappedViewPointer = ::MapViewOfFile(
            mappingHandle,
            FILE_MAP_READ,
            0,
            0,
            sizeof(CoreTempSharedDataPrefix));
        if (mappedViewPointer == nullptr)
        {
            const DWORD errorCode = ::GetLastError();
            ::CloseHandle(mappingHandle);
            probeResult.reasonText = QStringLiteral("Core Temp共享内存映射失败，Win32错误=%1。")
                .arg(errorCode);
            return probeResult;
        }

        const CoreTempSharedDataPrefix* sharedDataPointer =
            static_cast<const CoreTempSharedDataPrefix*>(mappedViewPointer);
        const unsigned int packageCount = std::clamp(sharedDataPointer->uiCPUCnt, 1U, 128U);
        const unsigned int coreCount = std::clamp(sharedDataPointer->uiCoreCnt, 1U, 256U);
        const unsigned int sampleCount = std::min(256U, std::max(coreCount, packageCount * coreCount));
        double maxTemperatureCelsius = -1000.0;
        for (unsigned int sampleIndex = 0; sampleIndex < sampleCount; ++sampleIndex)
        {
            double valueCelsius = static_cast<double>(sharedDataPointer->fTemp[sampleIndex]);
            if (sharedDataPointer->ucFahrenheit != 0U)
            {
                valueCelsius = (valueCelsius - 32.0) * 5.0 / 9.0;
            }
            if (sharedDataPointer->ucDeltaToTjMax != 0U)
            {
                const unsigned int tjMaxIndex = std::min(sampleIndex, 127U);
                const double tjMaxValue = static_cast<double>(sharedDataPointer->uiTjMax[tjMaxIndex]);
                if (tjMaxValue > 0.0)
                {
                    valueCelsius = tjMaxValue - valueCelsius;
                }
            }
            if (!std::isfinite(valueCelsius) || valueCelsius < -30.0 || valueCelsius > 130.0)
            {
                continue;
            }
            maxTemperatureCelsius = std::max(maxTemperatureCelsius, valueCelsius);
        }

        const QString valueText = formatCelsiusSensorValue(maxTemperatureCelsius);
        if (isReadableSensorValue(valueText))
        {
            probeResult.valueText = valueText;
            probeResult.sourceText = QStringLiteral("Core Temp共享内存 / 核心最高温");
            probeResult.success = true;
        }
        else
        {
            probeResult.reasonText = QStringLiteral("Core Temp共享内存存在，但未得到有效核心温度样本。");
        }

        ::UnmapViewOfFile(mappedViewPointer);
        ::CloseHandle(mappingHandle);
        return probeResult;
    }

    // queryCpuTemperatureProbeResult 作用：
    // - 查询 CPU 温度第一可用值（单位 °C）；
    // - 按“Libre/OpenHardwareMonitor -> CIM/WMI 热区 -> Thermal Counter -> TemperatureProbe”顺序回退；
    // - 失败时返回结构化原因文本。
    SensorProbeResult queryCpuTemperatureProbeResult()
    {
        SensorProbeResult coreTempProbeResult = queryCoreTempSharedMemoryProbeResult();
        if (coreTempProbeResult.success)
        {
            return coreTempProbeResult;
        }

        const QString temperatureScript = QStringLiteral(
            "$ErrorActionPreference='Stop'; "
            "function Add-Reason($list,[string]$reason){ if(-not [string]::IsNullOrWhiteSpace($reason)){ [void]$list.Add($reason) } }; "
            "function Format-Temp([double]$value){ "
            "  if([double]::IsNaN($value) -or [double]::IsInfinity($value)){ return $null }; "
            "  if($value -lt -30 -or $value -gt 130){ return $null }; "
            "  return ([math]::Round($value,1)).ToString() + '°C'; "
            "}; "
            "function Emit-Success([string]$value,[string]$source){ Write-Output ('OK|' + $value + '|' + $source); exit 0 }; "
            "function Test-CpuSensor($sensor){ "
            "  $name=[string]$sensor.Name; $identifier=[string]$sensor.Identifier; $hardwareName=[string]$sensor.HardwareName; "
            "  $text=($name + ' ' + $identifier + ' ' + $hardwareName); "
            "  if($text -match '(?i)cpu|processor|package|core|xeon|intel'){ return $true }; "
            "  if($identifier -match '(?i)/intelcpu|/cpu|/amdcpu'){ return $true }; "
            "  return $false; "
            "}; "
            "$reasons = New-Object 'System.Collections.Generic.List[string]'; "
            "foreach($serviceName in @('LibreHardwareMonitor','OpenHardwareMonitor','CoreTemp','HWiNFO64','HWiNFO32')){ "
            "  try { "
            "    $svc=Get-Service -Name $serviceName -ErrorAction SilentlyContinue; "
            "    if($null -ne $svc){ Add-Reason $reasons ('服务 ' + $serviceName + ': ' + [string]$svc.Status) } "
            "  } catch { } "
            "}; "
            "foreach($ns in @('root/LibreHardwareMonitor','root/OpenHardwareMonitor')){ "
            "  try { "
            "    $sensorRows=@(Get-CimInstance -Namespace $ns -ClassName Sensor -ErrorAction Stop); "
            "    $cpuTemps=@($sensorRows | Where-Object { "
            "      $_.SensorType -eq 'Temperature' -and "
            "      (Test-CpuSensor $_) "
            "    } | Sort-Object @{Expression={if($_.Name -match 'Package|CPU Package'){0}elseif($_.Name -match 'Core'){1}else{2}}}, Name); "
            "    if($cpuTemps.Count -le 0){ Add-Reason $reasons ('CIM ' + $ns + ': 未找到CPU温度传感器'); continue }; "
            "    foreach($sensor in $cpuTemps){ "
            "      $temp=Format-Temp ([double]$sensor.Value); "
            "      if($null -ne $temp){ Emit-Success $temp ('CIM ' + $ns + ' / ' + $sensor.Name) } "
            "    } "
            "    Add-Reason $reasons ('CIM ' + $ns + ': 传感器存在但值无效'); "
            "  } catch { Add-Reason $reasons ('CIM ' + $ns + ': ' + $_.Exception.Message) } "
            "}; "
            "foreach($ns in @('root/CIMV2','root/WMI')){ "
            "  foreach($className in @('Sensor','HardwareMonitor')){ "
            "    try { "
            "      $genericRows=@(Get-CimInstance -Namespace $ns -ClassName $className -ErrorAction Stop); "
            "      $genericTemps=@($genericRows | Where-Object { "
            "        (($_.SensorType -eq 'Temperature') -or ($_.Type -eq 'Temperature') -or ($_.Name -match '(?i)temperature|temp')) -and "
            "        (Test-CpuSensor $_) "
            "      }); "
            "      foreach($sensor in $genericTemps){ "
            "        $rawValue=$null; "
            "        if($null -ne $sensor.Value){ $rawValue=$sensor.Value } elseif($null -ne $sensor.CurrentValue){ $rawValue=$sensor.CurrentValue } elseif($null -ne $sensor.CurrentReading){ $rawValue=$sensor.CurrentReading }; "
            "        if($null -ne $rawValue){ "
            "          $temp=Format-Temp ([double]$rawValue); "
            "          if($null -ne $temp){ Emit-Success $temp ('CIM ' + $ns + ' / ' + $className + ' / ' + [string]$sensor.Name) } "
            "        } "
            "      } "
            "      if($genericRows.Count -gt 0){ Add-Reason $reasons ('CIM ' + $ns + '/' + $className + ': 未找到可用CPU温度值') } "
            "    } catch { } "
            "  } "
            "}; "
            "try { "
            "  $zoneRows=@(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop); "
            "  if($zoneRows.Count -le 0){ Add-Reason $reasons 'CIM root/wmi: 无热区数据' }; "
            "  foreach($row in $zoneRows){ "
            "    $temp=Format-Temp ((([double]$row.CurrentTemperature)/10.0)-273.15); "
            "    if($null -ne $temp){ Emit-Success $temp 'CIM root/wmi / MSAcpi_ThermalZoneTemperature' } "
            "  } "
            "  Add-Reason $reasons 'CIM root/wmi: 热区值超出有效范围'; "
            "} catch { Add-Reason $reasons ('CIM root/wmi: ' + $_.Exception.Message) } "
            "try { "
            "  $zoneRows=@(Get-WmiObject -Namespace root\\wmi -Class MSAcpi_ThermalZoneTemperature -ErrorAction Stop); "
            "  if($zoneRows.Count -le 0){ Add-Reason $reasons 'WMI root\\\\wmi: 无热区数据' }; "
            "  foreach($row in $zoneRows){ "
            "    $temp=Format-Temp ((([double]$row.CurrentTemperature)/10.0)-273.15); "
            "    if($null -ne $temp){ Emit-Success $temp 'WMI root\\\\wmi / MSAcpi_ThermalZoneTemperature' } "
            "  } "
            "  Add-Reason $reasons 'WMI root\\\\wmi: 热区值超出有效范围'; "
            "} catch { Add-Reason $reasons ('WMI root\\\\wmi: ' + $_.Exception.Message) } "
            "foreach($counterPath in @('\\Thermal Zone Information(*)\\High Precision Temperature','\\Thermal Zone Information(*)\\Temperature')){ "
            "  try { "
            "    $samples=@((Get-Counter $counterPath -ErrorAction Stop).CounterSamples); "
            "    if($samples.Count -le 0){ Add-Reason $reasons ('Counter ' + $counterPath + ': 无实例'); continue }; "
            "    foreach($sample in $samples){ "
            "      $raw=[double]$sample.CookedValue; "
            "      if($raw -gt 200){ $raw=($raw/10.0)-273.15 }; "
            "      $temp=Format-Temp $raw; "
            "      if($null -ne $temp){ Emit-Success $temp ('Counter ' + $sample.Path) } "
            "    } "
            "    Add-Reason $reasons ('Counter ' + $counterPath + ': 样本值无效'); "
            "  } catch { Add-Reason $reasons ('Counter ' + $counterPath + ': ' + $_.Exception.Message) } "
            "}; "
            "try { "
            "  $probeRows=@(Get-CimInstance Win32_TemperatureProbe -ErrorAction Stop); "
            "  if($probeRows.Count -le 0){ Add-Reason $reasons 'CIM Win32_TemperatureProbe: 无数据' }; "
            "  foreach($probe in $probeRows){ "
            "    if($null -eq $probe.CurrentReading){ continue }; "
            "    $temp=Format-Temp ([double]$probe.CurrentReading); "
            "    if($null -ne $temp){ Emit-Success $temp 'CIM Win32_TemperatureProbe / CurrentReading' } "
            "  } "
            "  Add-Reason $reasons 'CIM Win32_TemperatureProbe: 读取值无效'; "
            "} catch { Add-Reason $reasons ('CIM Win32_TemperatureProbe: ' + $_.Exception.Message) } "
            "if($reasons.Count -le 0){ Add-Reason $reasons '未找到可用温度来源' }; "
            "Write-Output ('ERR|' + ($reasons -join ' || '));");
        SensorProbeResult probeResult = parseSensorProbeOutput(queryPowerShellTextSync(temperatureScript, 5200));
        if (!coreTempProbeResult.reasonText.isEmpty())
        {
            probeResult.reasonText = coreTempProbeResult.reasonText
                + QStringLiteral(" || ")
                + probeResult.reasonText;
        }
        if (isExpectedCpuTemperatureUnavailable(probeResult))
        {
            probeResult.expectedUnavailable = true;
            probeResult.reasonText = QStringLiteral(
                "当前系统未暴露CPU温度传感器；已保持N/A。"
                "CPU本身可能有DTS，但Windows WMI通常不直接暴露；"
                "请开启Core Temp共享内存、LibreHardwareMonitor或OpenHardwareMonitor的WMI后端。");
        }
        return probeResult;
    }

    // decodeSmbiosProcessorVoltageText 作用：
    // - 按 SMBIOS 规范解码 Type 4 Processor Information 的 Voltage 字节；
    // - bit7 置位时低 7 位是“当前电压 × 10”，否则低 3 位是平台标称电压能力位；
    // - 返回空字符串表示该字节不携带可用电压信息。
    QString decodeSmbiosProcessorVoltageText(const unsigned char rawVoltage)
    {
        if (rawVoltage == 0U)
        {
            return QString();
        }
        if ((rawVoltage & 0x80U) != 0U)
        {
            // decodedVolts 用途：SMBIOS 规定该编码下低 7 位为电压值的十倍整数。
            const double decodedVolts = static_cast<double>(rawVoltage & 0x7FU) / 10.0;
            if (decodedVolts > 0.0)
            {
                return QString::number(decodedVolts, 'f', 2) + QStringLiteral("V");
            }
            return QString();
        }
        if ((rawVoltage & 0x01U) != 0U)
        {
            return QStringLiteral("5.0V");
        }
        if ((rawVoltage & 0x02U) != 0U)
        {
            return QStringLiteral("3.3V");
        }
        if ((rawVoltage & 0x04U) != 0U)
        {
            return QStringLiteral("2.9V");
        }
        return QString();
    }

    // SmbiosVoltageReadResult 作用：
    // - 承载一次 SMBIOS 直读的结论；
    // - tableReadable 区分“固件表本身读不到”和“表读到了但不含可用电压”，前者才需要回退查询。
    struct SmbiosVoltageReadResult
    {
        SensorProbeResult probeResult;  // probeResult：与其他探测统一的结构化结果。
        bool tableReadable = false;     // tableReadable：SMBIOS 原始表是否成功取到。
    };

    // querySmbiosProcessorVoltageProbeResult 作用：
    // - 直接在本进程读取 SMBIOS 原始表并解析首个中央处理器的 Voltage 字段；
    // - Win32_Processor.CurrentVoltage 本身就转自这张表，直读可省掉 powershell.exe 启动与 WMI/WMIC 往返；
    // - 该路径耗时在微秒级，从根上消除周期刷新触发 PowerShell 超时的可能。
    SmbiosVoltageReadResult querySmbiosProcessorVoltageProbeResult()
    {
        SmbiosVoltageReadResult readResult;

        // kRawSmbiosProvider 用途：firmware table provider 签名 'RSMB' 的大端整数形式。
        constexpr DWORD kRawSmbiosProvider = 0x52534D42U;
        const UINT requiredSize = ::GetSystemFirmwareTable(kRawSmbiosProvider, 0, nullptr, 0);
        if (requiredSize == 0U)
        {
            readResult.probeResult.reasonText =
                QStringLiteral("SMBIOS RSMB: 固件表不可用，GetLastError=%1").arg(::GetLastError());
            return readResult;
        }

        std::vector<unsigned char> tableBuffer(static_cast<std::size_t>(requiredSize), 0U);
        const UINT copiedSize = ::GetSystemFirmwareTable(
            kRawSmbiosProvider,
            0,
            tableBuffer.data(),
            requiredSize);
        if (copiedSize == 0U || copiedSize > requiredSize)
        {
            readResult.probeResult.reasonText =
                QStringLiteral("SMBIOS RSMB: 表读取失败，GetLastError=%1").arg(::GetLastError());
            return readResult;
        }

        // kRawSmbiosHeaderSize 用途：RawSMBIOSData 头部固定 8 字节（调用方法/主次版本/DMI 修订 + 4 字节长度）。
        constexpr std::size_t kRawSmbiosHeaderSize = 8U;
        if (static_cast<std::size_t>(copiedSize) <= kRawSmbiosHeaderSize)
        {
            readResult.probeResult.reasonText = QStringLiteral("SMBIOS RSMB: 表长度异常（%1 字节）。").arg(copiedSize);
            return readResult;
        }

        readResult.tableReadable = true;

        const unsigned char* tableBegin = tableBuffer.data() + kRawSmbiosHeaderSize;
        const std::size_t tableSize = static_cast<std::size_t>(copiedSize) - kRawSmbiosHeaderSize;

        // rawVoltageFoundText 用途：找到了中央处理器结构但字节不可解码时保留原始值，便于诊断。
        QString rawVoltageFoundText;
        std::size_t structureOffset = 0U;
        while (structureOffset + 4U <= tableSize)
        {
            const unsigned char structureType = tableBegin[structureOffset];
            const unsigned char formattedLength = tableBegin[structureOffset + 1U];
            if (formattedLength < 4U || structureOffset + formattedLength > tableSize)
            {
                break;
            }
            if (structureType == 127U)
            {
                // Type 127 = End-of-Table，后续内容不再有效。
                break;
            }

            // Type 4 = Processor Information；偏移 0x05 为处理器类型，0x11 为 Voltage。
            if (structureType == 4U && formattedLength > 0x11U && tableBegin[structureOffset + 0x05U] == 3U)
            {
                const unsigned char rawVoltage = tableBegin[structureOffset + 0x11U];
                const QString voltageText = decodeSmbiosProcessorVoltageText(rawVoltage);
                if (!voltageText.isEmpty())
                {
                    readResult.probeResult.valueText = voltageText;
                    readResult.probeResult.sourceText = QStringLiteral("SMBIOS Type4 / Processor Voltage");
                    readResult.probeResult.success = true;
                    return readResult;
                }
                if (rawVoltageFoundText.isEmpty())
                {
                    rawVoltageFoundText = QStringLiteral("0x%1")
                        .arg(QString::number(static_cast<unsigned int>(rawVoltage), 16).toUpper());
                }
            }

            // 格式化区之后是字符串区，以连续两个 0 字节结束；空字符串区本身就是两个 0。
            std::size_t stringAreaCursor = structureOffset + formattedLength;
            while (stringAreaCursor + 1U < tableSize
                && !(tableBegin[stringAreaCursor] == 0U && tableBegin[stringAreaCursor + 1U] == 0U))
            {
                ++stringAreaCursor;
            }
            structureOffset = stringAreaCursor + 2U;
        }

        if (!rawVoltageFoundText.isEmpty())
        {
            readResult.probeResult.reasonText =
                QStringLiteral("SMBIOS Type4: Voltage=%1 无法解析（固件未填写实际核心电压）。")
                .arg(rawVoltageFoundText);
            return readResult;
        }

        readResult.probeResult.reasonText = QStringLiteral("SMBIOS Type4: 未找到中央处理器结构。");
        return readResult;
    }

    // queryCpuVoltageProbeResultUncached 作用：
    // - 查询 CPU 电压第一可用值（单位 V）；
    // - 主路径直读 SMBIOS，只有固件表整体不可读时才回退 CIM 查询；
    // - 同时兼容 SMBIOS 位标志与十倍电压值编码，失败时返回结构化原因文本。
    SensorProbeResult queryCpuVoltageProbeResultUncached()
    {
        const SmbiosVoltageReadResult smbiosReadResult = querySmbiosProcessorVoltageProbeResult();
        if (smbiosReadResult.probeResult.success)
        {
            return smbiosReadResult.probeResult;
        }
        if (smbiosReadResult.tableReadable)
        {
            // 固件表已读到却没有可用电压时，WMI/WMIC 只是同一字节的二次转译，
            // 再起 powershell.exe 既拿不到新信息，又是本地日志里超时告警的唯一来源。
            SensorProbeResult probeResult = smbiosReadResult.probeResult;
            probeResult.expectedUnavailable = true;
            probeResult.reasonText = QStringLiteral(
                "当前系统未暴露CPU电压传感器；已保持N/A。"
                "SMBIOS Type4 Voltage 由固件填写，多数平台不提供实时核心电压。原始诊断：")
                + smbiosReadResult.probeResult.reasonText;
            return probeResult;
        }

        const QString voltageScript = QStringLiteral(
            "$ErrorActionPreference='Stop'; "
            "function Add-Reason($list,[string]$reason){ if(-not [string]::IsNullOrWhiteSpace($reason)){ [void]$list.Add($reason) } }; "
            // Win32_Processor.CurrentVoltage 已经把 SMBIOS 的 bit7 标志剥掉，
            // 直接给出“电压 × 10”的整数（例如 0.8V 对应 8），因此先按十倍值解释，
            // 只有落在标称能力位取值上时才退回 5.0/3.3/2.9V 的位判定。
            "function Format-Voltage([int]$raw){ "
            "  if($raw -le 0){ return $null }; "
            "  if(($raw -band 0x80) -ne 0){ "
            "    $decoded=(($raw -band 0x7F) / 10.0); "
            "    if($decoded -gt 0){ return ([math]::Round($decoded,2)).ToString('0.00') + 'V' } "
            "  }; "
            "  if($raw -ge 5 -and $raw -le 100){ "
            "    return ([math]::Round(($raw / 10.0),2)).ToString('0.00') + 'V'; "
            "  }; "
            "  if(($raw -band 0x1) -ne 0){ return '5.0V' }; "
            "  if(($raw -band 0x2) -ne 0){ return '3.3V' }; "
            "  if(($raw -band 0x4) -ne 0){ return '2.9V' }; "
            "  return $null; "
            "}; "
            "function Emit-Success([string]$value,[string]$source){ Write-Output ('OK|' + $value + '|' + $source); exit 0 }; "
            "$reasons = New-Object 'System.Collections.Generic.List[string]'; "
            "try { "
            "  $cpu=Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1; "
            "  if($null -eq $cpu){ Add-Reason $reasons 'CIM Win32_Processor: 未返回处理器对象' } "
            "  else { "
            "    $voltage=Format-Voltage ([uint16]$cpu.CurrentVoltage); "
            "    if($null -ne $voltage){ Emit-Success $voltage 'CIM Win32_Processor / CurrentVoltage' } "
            "    Add-Reason $reasons ('CIM Win32_Processor: CurrentVoltage=' + [string]$cpu.CurrentVoltage + ' 无法解析'); "
            "  } "
            "} catch { Add-Reason $reasons ('CIM Win32_Processor: ' + $_.Exception.Message) } "
            "if($reasons.Count -le 0){ Add-Reason $reasons '未找到可用电压来源' }; "
            "Write-Output ('ERR|' + ($reasons -join ' || '));");

        // 回退路径只保留 CIM 一条分支：
        // - Get-WmiObject 与 wmic.exe 读的是同一份 WMI 数据，拿不到额外信息；
        // - wmic.exe 在新版 Windows 上已是按需功能，缺失时会显著拉长整体耗时；
        // - 分支收敛后单进程预算放宽到 9000 ms，冷启动 WMI 也能跑完。
        SensorProbeResult probeResult = parseSensorProbeOutput(queryPowerShellTextSync(voltageScript, 9000));
        if (!smbiosReadResult.probeResult.reasonText.isEmpty())
        {
            probeResult.reasonText = smbiosReadResult.probeResult.reasonText
                + QStringLiteral(" || ")
                + probeResult.reasonText;
        }
        if (isExpectedCpuVoltageUnavailable(probeResult))
        {
            probeResult.expectedUnavailable = true;
            probeResult.reasonText = QStringLiteral(
                "当前系统未暴露CPU电压传感器；已保持N/A。"
                "Win32_Processor CurrentVoltage 常由SMBIOS决定，可能不是可读传感器。");
        }
        return probeResult;
    }

    // cpuVoltageProbeCacheMutex 用途：保护电压探测结论缓存，探测发生在后台线程。
    // cpuVoltageProbeCacheValid 用途：标记缓存中是否已有确定结论。
    // cpuVoltageProbeCacheResult 用途：保存已确定的电压探测结论。
    std::mutex cpuVoltageProbeCacheMutex;
    bool cpuVoltageProbeCacheValid = false;
    SensorProbeResult cpuVoltageProbeCacheResult;

    // queryCpuVoltageProbeResult 作用：
    // - 对外提供带缓存的 CPU 电压探测；
    // - Voltage 取自固件启动时填好的 SMBIOS 静态表，运行期不会变化，5 秒一轮的刷新没有必要重复探测；
    // - 只缓存“读到有效值”和“确认平台不暴露”这两类确定结论，执行类失败留给下一轮重试。
    SensorProbeResult queryCpuVoltageProbeResult()
    {
        {
            const std::lock_guard<std::mutex> cacheGuard(cpuVoltageProbeCacheMutex);
            if (cpuVoltageProbeCacheValid)
            {
                return cpuVoltageProbeCacheResult;
            }
        }

        const SensorProbeResult probeResult = queryCpuVoltageProbeResultUncached();
        if (probeResult.success || probeResult.expectedUnavailable)
        {
            const std::lock_guard<std::mutex> cacheGuard(cpuVoltageProbeCacheMutex);
            cpuVoltageProbeCacheResult = probeResult;
            cpuVoltageProbeCacheValid = true;
        }
        return probeResult;
    }

    // HardwareDockCpuCounterBundle 作用：
    // - 承载后台线程创建好的 CPU 相关 PDH 句柄与失败状态码；
    // - 只保存值类型，便于整体回投 UI 线程接管，不牵扯任何 QWidget。
    struct HardwareDockCpuCounterBundle
    {
        void* cpuQueryHandle = nullptr;              // cpuQueryHandle：CPU 查询句柄。
        std::vector<void*> coreCounterHandles;       // coreCounterHandles：每个逻辑核心的计数器句柄。
        void* cpuPerformanceCounterHandle = nullptr; // cpuPerformanceCounterHandle：处理器性能百分比计数器句柄。
        void* cpuFrequencyCounterHandle = nullptr;   // cpuFrequencyCounterHandle：处理器基准频率计数器句柄。
        PDH_STATUS openQueryStatus = ERROR_SUCCESS;  // openQueryStatus：PdhOpenQueryW 返回值，供失败日志使用。
    };

    // hardwareDockCpuCounterInitializing 作用：
    // - 标记当前是否已有一轮后台 PDH 初始化在执行；
    // - 防止初始化未完成期间每秒刷新重复投递任务。
    std::atomic_bool hardwareDockCpuCounterInitializing{ false };

    // createHardwareDockCpuCounters 作用：
    // - 入参 coreCount：逻辑核心数量，决定注册多少个 \Processor(n) 计数器；
    // - 处理：在调用线程完成 PdhOpenQueryW/PdhAddEnglishCounterW 与首次基线采集；
    // - 返回：句柄集合，失败字段保持 nullptr 由调用方按空句柄回退。
    HardwareDockCpuCounterBundle createHardwareDockCpuCounters(const int coreCount)
    {
        HardwareDockCpuCounterBundle counterBundle;

        PDH_HQUERY queryHandle = nullptr;
        counterBundle.openQueryStatus = ::PdhOpenQueryW(nullptr, 0, &queryHandle);
        if (counterBundle.openQueryStatus != ERROR_SUCCESS || queryHandle == nullptr)
        {
            return counterBundle;
        }

        const int safeCoreCount = std::max(0, coreCount);
        counterBundle.coreCounterHandles.reserve(static_cast<std::size_t>(safeCoreCount));
        for (int coreIndex = 0; coreIndex < safeCoreCount; ++coreIndex)
        {
            const QString counterPath = QStringLiteral("\\Processor(%1)\\% Processor Time").arg(coreIndex);
            PDH_HCOUNTER counterHandle = nullptr;
            const PDH_STATUS addStatus = ::PdhAddEnglishCounterW(
                queryHandle,
                reinterpret_cast<LPCWSTR>(counterPath.utf16()),
                0,
                &counterHandle);
            if (addStatus != ERROR_SUCCESS || counterHandle == nullptr)
            {
                // 某个核心计数器失败时占位 nullptr，后续采样按 0 处理。
                counterBundle.coreCounterHandles.push_back(nullptr);
                continue;
            }
            counterBundle.coreCounterHandles.push_back(counterHandle);
        }

        // Windows 任务管理器式“速度”不能直接使用 ProcessorInformation.CurrentMhz：
        // 现代 HWP/CPPC 平台常把它固定在基础频率。有效速度 = 基准频率 × 处理器性能百分比。
        const auto addCpuTotalCounter =
            [queryHandle](const QString& counterPath, void** counterHandleOut)
            {
                if (counterHandleOut == nullptr)
                {
                    return;
                }
                PDH_HCOUNTER counterHandle = nullptr;
                const PDH_STATUS addStatus = ::PdhAddEnglishCounterW(
                    queryHandle,
                    reinterpret_cast<LPCWSTR>(counterPath.utf16()),
                    0,
                    &counterHandle);
                *counterHandleOut = addStatus == ERROR_SUCCESS ? counterHandle : nullptr;
            };
        addCpuTotalCounter(
            QStringLiteral("\\Processor Information(_Total)\\% Processor Performance"),
            &counterBundle.cpuPerformanceCounterHandle);
        addCpuTotalCounter(
            QStringLiteral("\\Processor Information(_Total)\\Processor Frequency"),
            &counterBundle.cpuFrequencyCounterHandle);

        ::PdhCollectQueryData(queryHandle);
        counterBundle.cpuQueryHandle = queryHandle;
        return counterBundle;
    }

    // closeHardwareDockCpuCounters 作用：
    // - 入参 counterBundle：待释放的句柄集合；
    // - 处理：关闭 PDH 查询，供控件已销毁或句柄已由更早一轮接管时丢弃结果；
    // - 返回：无返回值。
    void closeHardwareDockCpuCounters(const HardwareDockCpuCounterBundle& counterBundle)
    {
        if (counterBundle.cpuQueryHandle != nullptr)
        {
            ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(counterBundle.cpuQueryHandle));
        }
    }
}

HardwareDock::HardwareDock(QWidget* parent)
    : QWidget(parent)
{
    // 构造流程日志：便于定位硬件页初始化失败点。
    kLogEvent event;
    info << event << "[HardwareDock] 构造开始。" << eol;
    // 硬件页整体不向 ADS 外层申请最小尺寸，窄面板下由内部图表主动压缩。
    configureCompressibleWidget(this, QSizePolicy::Expanding, QSizePolicy::Expanding);

    initializeUi();
    initializeConnections();

    // 启动阶段先填充占位文本，避免首帧等待 PowerShell 导致窗口卡住。
    m_cachedOverviewStaticText = QStringLiteral("硬件概览加载中，请稍候...");
    m_cachedGpuStaticText = QStringLiteral("显卡信息加载中，请稍候...");
    m_cachedMemoryStaticText = QStringLiteral("内存信息加载中，请稍候...");
    m_cachedSensorText = QStringLiteral("N/A|N/A");
    if (m_cpuModelLabel != nullptr && !m_cpuModelText.isEmpty())
    {
        m_cpuModelLabel->setText(m_cpuModelText);
    }

    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(1000);
    connect(m_refreshTimer, &QTimer::timeout, this, [this]() {
        refreshAllViews();
    });

    info << event << "[HardwareDock] 构造完成。" << eol;
}

HardwareDock::~HardwareDock()
{
    if (m_refreshTimer != nullptr)
    {
        m_refreshTimer->stop();
    }

    if (m_cpuPerfQueryHandle != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_cpuPerfQueryHandle));
        m_cpuPerfQueryHandle = nullptr;
        m_coreCounterHandles.clear();
        m_cpuPerformanceCounterHandle = nullptr;
        m_cpuFrequencyCounterHandle = nullptr;
    }

    if (m_diskPerfQueryHandle != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_diskPerfQueryHandle));
        m_diskPerfQueryHandle = nullptr;
        m_diskReadCounterHandle = nullptr;
        m_diskWriteCounterHandle = nullptr;
    }

    if (m_gpuPerfQueryHandle != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_gpuPerfQueryHandle));
        m_gpuPerfQueryHandle = nullptr;
        m_gpuCounterHandle = nullptr;
        m_gpuDedicatedMemoryCounterHandle = nullptr;
        m_gpuSharedMemoryCounterHandle = nullptr;
    }
}

void HardwareDock::resizeEvent(QResizeEvent* resizeEventPointer)
{
    QWidget::resizeEvent(resizeEventPointer);
    adjustUtilizationChartHeights();
}

bool HardwareDock::eventFilter(QObject* watchedObject, QEvent* eventObject)
{
    if (eventObject != nullptr
        && eventObject->type() == QEvent::MouseButtonRelease
        && m_utilizationBodySplitter != nullptr
        && watchedObject == m_utilizationBodySplitter->handle(1))
    {
        // 非 opaque resize 模式下，释放事件先于最终子控件布局到达；排到下一轮
        // 事件循环后再读取 viewport 宽度，并保留用户刚提交的 splitter 尺寸。
        QTimer::singleShot(0, this, [this]()
        {
            adjustUtilizationChartHeights();
        });
    }

    return QWidget::eventFilter(watchedObject, eventObject);
}

void HardwareDock::showEvent(QShowEvent* showEventPointer)
{
    QWidget::showEvent(showEventPointer);

    // R0 证据页构造后会立即发起驱动查询；欢迎页只复用本 Dock 的用户态
    // 性能采样，因此必须把该页延迟到用户真正打开硬件 Dock 后再创建。
    if (m_r0EvidencePage == nullptr && m_sideTabWidget != nullptr)
    {
        initializeR0EvidenceTab();
    }

    startPerformanceSampling(true);

    // splitter 在 Dock 首次显示前可能还没有最终宽度，因此分两轮尝试应用
    // 300px 默认左栏；成功后不再覆盖用户后续拖动结果。
    QTimer::singleShot(0, this, [this]()
    {
        applyInitialUtilizationSplitterSize();
    });
    QTimer::singleShot(80, this, [this]()
    {
        applyInitialUtilizationSplitterSize();
    });

    // 首次显示阶段分阶段重排，确保滚动区 viewport 高度已经稳定。
    scheduleUtilizationLayoutRefresh();
}

void HardwareDock::startPerformanceSampling(const bool includeDriverHealth)
{
    m_driverHealthSamplingEnabled = includeDriverHealth;
    if (m_initialSamplingStarted)
    {
        return;
    }

    m_initialSamplingStarted = true;
    startInitialSamplingAfterFirstPaint();
}

void HardwareDock::startInitialSamplingAfterFirstPaint()
{
    // safeThis 用途：延迟任务触发前 Dock 可能已被销毁，QPointer 可避免悬空访问。
    QPointer<HardwareDock> safeThis(this);

    // 首轮采样延迟 80ms：
    // - 让 ADS Dock 切换和占位 UI 先完成绘制；
    // - 避免 PDH/DXGI/Power API 首次初始化耗时直接压在点击响应链路上。
    QTimer::singleShot(80, this, [safeThis]()
    {
        if (safeThis.isNull())
        {
            return;
        }

        HardwareDock* dockPointer = safeThis.data();
        if (dockPointer->m_coreChartEntries.empty())
        {
            dockPointer->initializeCoreCharts();
        }
        dockPointer->initializePerformanceCounters();
        dockPointer->refreshCpuTopologyStaticInfo();
        dockPointer->refreshSystemVolumeInfo();
        dockPointer->refreshStaticHardwareTexts(false);
        dockPointer->refreshAllViews();
        dockPointer->requestAsyncStaticInfoRefresh();
        dockPointer->requestAsyncSensorRefresh();
        if (dockPointer->m_driverHealthSamplingEnabled)
        {
            dockPointer->requestAsyncR0HardwareHealthRefresh();
        }

        if (dockPointer->m_refreshTimer != nullptr)
        {
            dockPointer->m_refreshTimer->start();
        }
    });
}

void HardwareDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(4, 4, 4, 4);
    m_rootLayout->setSpacing(6);

    // 顶部横向页签：
    // - 外层只负责硬件功能分类，不再占用左侧内容宽度；
    // - 页签按内容宽度排列，空间不足时使用滚动按钮，避免强行压缩文字；
    // - 用户可见名称统一使用清晰中文，内部协议缩写放到页面说明中。
    m_sideTabWidget = new QTabWidget(this);
    configureCompressibleWidget(m_sideTabWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_sideTabWidget->setTabPosition(QTabWidget::North);
    m_sideTabWidget->setDocumentMode(true);
    m_sideTabWidget->setUsesScrollButtons(true);
    m_sideTabWidget->setElideMode(Qt::ElideNone);
    if (m_sideTabWidget->tabBar() != nullptr)
    {
        m_sideTabWidget->tabBar()->setExpanding(false);
        m_sideTabWidget->tabBar()->setMovable(false);
    }
    m_rootLayout->addWidget(m_sideTabWidget, 1);

    // 页签顺序：性能与硬件信息 -> 设备管理 -> 底层诊断。
    // 先注册“性能监控”，让硬件 Dock 初次打开时直接显示实时数据。
    initializeUtilizationTab();
    initializeOverviewTab();
    initializeCpuTab();
    initializePowerTab();
    initializeGpuTab();
    initializeMemoryTab();
    initializeDiskMonitorTab();
    initializeDeviceManagerTab();
    initializeOtherDevicesTab();
    initializeHwidDispatchTab();
    initializeDeviceStackTab();
    initializeKeyboardMouseHidTab();
    initializeI8042AuditTab();
    initializeUsbTopologyTab();
    initializePnpAcpiPciTab();

    if (m_sideTabWidget != nullptr)
    {
        connect(
            m_sideTabWidget,
            &QTabWidget::currentChanged,
            this,
            [this](const int tabIndexValue)
            {
                Q_UNUSED(tabIndexValue);
                if (m_sideTabWidget == nullptr || m_utilizationPage == nullptr)
                {
                    return;
                }

                QWidget* currentTabWidget = m_sideTabWidget->currentWidget();
                if (currentTabWidget == m_diskMonitorHostPage)
                {
                    // 硬盘监控会启动 ETW 与进程 IO 扫描，必须等用户真正进入该子页再创建。
                    QTimer::singleShot(0, this, [this]()
                    {
                        ensureDiskMonitorTabInitialized();
                    });
                    return;
                }
                if (currentTabWidget == m_otherDevicesHostPage)
                {
                    // 其他设备页会枚举 PNP/驱动/硬件清单，延迟到子页首次激活时执行。
                    QTimer::singleShot(0, this, [this]()
                    {
                        ensureOtherDevicesTabInitialized();
                    });
                    return;
                }

                if (currentTabWidget == m_deviceStackPage
                    || currentTabWidget == m_keyboardMouseHidPage
                    || currentTabWidget == m_usbTopologyPage
                    || currentTabWidget == m_pnpAcpiPciPage)
                {
                    refreshStaticHardwareTexts(true);
                    return;
                }

                if (m_sideTabWidget->currentWidget() != m_utilizationPage)
                {
                    return;
                }
                // 进入“利用率”总页时刷新高度，修复首次进入 CPU 子页时尚未正确撑开的问题。
                scheduleUtilizationLayoutRefresh();
            });
    }
}

void HardwareDock::initializeOverviewTab()
{
    m_overviewPage = new QWidget(m_sideTabWidget);
    m_overviewLayout = new QVBoxLayout(m_overviewPage);
    m_overviewLayout->setContentsMargins(4, 4, 4, 4);
    m_overviewLayout->setSpacing(6);

    m_overviewSummaryLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.overview.sampling"), QStringLiteral("采样中...")),
        m_overviewPage);
    m_overviewSummaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    m_overviewLayout->addWidget(m_overviewSummaryLabel, 0);

    m_overviewEditor = new CodeEditorWidget(m_overviewPage);
    m_overviewEditor->setReadOnly(true);
    m_overviewLayout->addWidget(m_overviewEditor, 1);

    const int tabIndex = m_sideTabWidget->addTab(m_overviewPage, QStringLiteral("硬件概览"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_overviewPage, QStringLiteral("hardware.tab.overview"), QStringLiteral("硬件概览"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("查看处理器、内存、显卡和系统硬件摘要"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_overviewPage, QStringLiteral("hardware.tooltip.overview"), QStringLiteral("查看处理器、内存、显卡和系统硬件摘要"));
}

void HardwareDock::initializeUtilizationTab()
{
    m_utilizationPage = new QWidget(m_sideTabWidget);
    configureCompressibleWidget(m_utilizationPage, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(m_utilizationPage);
    m_utilizationLayout = new QVBoxLayout(m_utilizationPage);
    m_utilizationLayout->setContentsMargins(4, 4, 4, 4);
    m_utilizationLayout->setSpacing(6);

    // 任务管理器风格布局：
    // - 左侧为性能导航卡片列表；
    // - 右侧为详情页堆栈，随左侧选中项切换。
    m_utilizationBodySplitter = new QSplitter(Qt::Horizontal, m_utilizationPage);
    m_utilizationBodySplitter->setChildrenCollapsible(false);
    // 拖动期间只显示橡皮筋，不实时重排左侧卡片；松开后再一次性提交新宽度。
    m_utilizationBodySplitter->setOpaqueResize(false);
    m_utilizationBodySplitter->setHandleWidth(8);
    configureCompressibleWidget(
        m_utilizationBodySplitter,
        QSizePolicy::Expanding,
        QSizePolicy::Expanding);
    m_utilizationLayout->addWidget(m_utilizationBodySplitter, 1);

    m_utilizationSidebarList = new QListWidget(m_utilizationPage);
    m_utilizationSidebarList->setFrameShape(QFrame::NoFrame);
    m_utilizationSidebarList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    // 设备数量较多时不能继续把缩略卡片压到不可读高度，改为保留卡片高度并允许左侧独立滚动。
    m_utilizationSidebarList->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_utilizationSidebarList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_utilizationSidebarList->setSelectionMode(QAbstractItemView::SingleSelection);
    m_utilizationSidebarList->setSpacing(2);
    configureCompressibleWidget(m_utilizationSidebarList, QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_utilizationSidebarList->setMinimumWidth(140);
    m_utilizationSidebarList->setStyleSheet(
        QStringLiteral(
            "QListWidget{border:none;background:transparent;}"
            "QListWidget::item{border:none;padding:0px;margin:0px;}"
            "QListWidget::item:selected{background:transparent;}"));
    appendTransparentBackgroundStyle(m_utilizationSidebarList);
    m_utilizationBodySplitter->addWidget(m_utilizationSidebarList);

    m_utilizationDetailStack = new QStackedWidget(m_utilizationBodySplitter);
    // 详情页内容由多个子页共享，不能让隐藏子页的 sizeHint 反向限制 splitter。
    configureCompressibleWidget(m_utilizationDetailStack, QSizePolicy::Ignored, QSizePolicy::Expanding);
    // 保证左侧即使被拖到较宽，右侧详情仍保留可读区域；这也是 splitter 的
    // 最大左栏边界，而不是由卡片 sizeHint 间接决定。
    m_utilizationDetailStack->setMinimumWidth(360);
    appendTransparentBackgroundStyle(m_utilizationDetailStack);
    m_utilizationBodySplitter->addWidget(m_utilizationDetailStack);
    if (QWidget* const splitterHandle = m_utilizationBodySplitter->handle(1))
    {
        splitterHandle->installEventFilter(this);
    }
    // opaque resize 关闭时左侧列表不会跟随橡皮筋实时重排；监听 splitterMoved，
    // 在最终宽度提交后重新定位卡片，确保设备名称不会留在旧的绘制区域之外。
    connect(
        m_utilizationBodySplitter,
        &QSplitter::splitterMoved,
        this,
        [this](const int, const int)
        {
            QTimer::singleShot(0, this, [this]()
            {
                if (m_utilizationBodySplitter == nullptr
                    || m_utilizationSidebarList == nullptr)
                {
                    return;
                }
                syncUtilizationSidebarCardWidths();
                adjustUtilizationChartHeights();
            });
        });
    m_utilizationBodySplitter->setStretchFactor(0, 0);
    m_utilizationBodySplitter->setStretchFactor(1, 1);
    // 先给出可用的预置值；首次显示后 applyInitialUtilizationSplitterSize 会按实际
    // splitter 可用宽度把左侧校准到 300px，之后完全保留用户拖动结果。
    m_utilizationBodySplitter->setSizes({ 300, 360 });

    initializeUtilizationCpuSubTab();
    initializeUtilizationMemorySubTab();
    initializeUtilizationDiskSubTab();
    initializeUtilizationNetworkSubTab();
    initializeUtilizationGpuSubTab();
    initializeUtilizationSidebarCards();

    connect(
        m_utilizationSidebarList,
        &QListWidget::currentRowChanged,
        this,
        [this](const int rowIndex)
        {
            syncUtilizationSidebarSelection(rowIndex);
        });

    m_utilizationSidebarList->setCurrentRow(0);
    syncUtilizationSidebarSelection(0);

    const int tabIndex = m_sideTabWidget->addTab(m_utilizationPage, QStringLiteral("性能监控"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_utilizationPage, QStringLiteral("hardware.tab.utilization"), QStringLiteral("性能监控"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("实时查看处理器、内存、磁盘、网络和显卡使用情况"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_utilizationPage, QStringLiteral("hardware.tooltip.utilization"), QStringLiteral("实时查看处理器、内存、磁盘、网络和显卡使用情况"));
}

void HardwareDock::initializeUtilizationSidebarCards()
{
    if (m_utilizationSidebarList == nullptr)
    {
        return;
    }

    m_cpuNavCard = addUtilizationSidebarCard(
        m_utilizationCpuSubPage,
        ks::i18n::contextText(QStringLiteral("hardware.utilization.card.cpu"), QStringLiteral("CPU")),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Cpu),
        UtilizationDeviceKind::Cpu,
        -1);
    m_memoryNavCard = addUtilizationSidebarCard(
        m_utilizationMemorySubPage,
        ks::i18n::contextText(QStringLiteral("hardware.utilization.card.memory"), QStringLiteral("内存")),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Memory),
        UtilizationDeviceKind::Memory,
        -1);
    // 磁盘、网卡、GPU 不再注册固定聚合卡片：
    // - 设备发现后由 ensure*UtilizationDevice 动态追加；
    // - 这样多硬盘/多显卡/多网卡会像任务管理器一样各占一个入口。
    m_diskNavCard = nullptr;
    m_networkNavCard = nullptr;
    m_gpuNavCard = nullptr;

    if (m_memoryNavCard != nullptr)
    {
        m_memoryNavCard->setSeriesColors(
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Memory),
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::SharedMemory));
    }
}

PerformanceNavCard* HardwareDock::addUtilizationSidebarCard(
    QWidget* detailPage,
    const QString& titleText,
    const QColor& accentColor,
    const UtilizationDeviceKind kind,
    const int deviceIndex)
{
    if (m_utilizationSidebarList == nullptr)
    {
        return nullptr;
    }

    // itemPointer 用途：承载 PerformanceNavCard 的 QListWidget 行。
    QListWidgetItem* itemPointer = new QListWidgetItem();
    // cardPointer 用途：实际绘制任务管理器风格缩略卡片。
    PerformanceNavCard* cardPointer = new PerformanceNavCard(m_utilizationSidebarList);
    cardPointer->setTitleText(titleText);
    cardPointer->setSubtitleText(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.card.sampling"),
            QStringLiteral("采样中...")));
    cardPointer->setAccentColor(accentColor);
    // 只把高度交给 QListWidget 管理；宽度始终由 viewport/分割器决定，不能把
    // 卡片推荐宽度写进 item，否则拖动 splitter 时 QListView 会反向拉回 splitter。
    itemPointer->setSizeHint(QSize(0, cardPointer->sizeHint().height()));
    m_utilizationSidebarList->addItem(itemPointer);
    m_utilizationSidebarList->setItemWidget(itemPointer, cardPointer);

    // navEntry 用途：记录 QListWidget 行号与 QStackedWidget 页面之间的稳定映射。
    UtilizationNavEntry navEntry;
    navEntry.navCard = cardPointer;
    navEntry.detailPage = detailPage;
    navEntry.kind = kind;
    navEntry.deviceIndex = deviceIndex;
    m_utilizationNavEntries.push_back(navEntry);
    return cardPointer;
}

void HardwareDock::syncUtilizationSidebarSelection(const int selectedRowIndex)
{
    if (m_utilizationDetailStack == nullptr)
    {
        return;
    }

    const int pageCount = m_utilizationDetailStack->count();
    if (pageCount <= 0)
    {
        return;
    }

    const int entryCount = static_cast<int>(m_utilizationNavEntries.size());
    const int boundedRowIndex = entryCount > 0
        ? std::clamp(selectedRowIndex, 0, entryCount - 1)
        : std::clamp(selectedRowIndex, 0, pageCount - 1);

    // targetPageIndex 用途：把左侧行号映射到右侧堆栈真实页面索引。
    int targetPageIndex = std::clamp(boundedRowIndex, 0, pageCount - 1);
    if (boundedRowIndex >= 0 && boundedRowIndex < entryCount)
    {
        QWidget* targetPageWidget = m_utilizationNavEntries[static_cast<std::size_t>(boundedRowIndex)].detailPage;
        if (targetPageWidget != nullptr)
        {
            const int resolvedIndex = m_utilizationDetailStack->indexOf(targetPageWidget);
            if (resolvedIndex >= 0)
            {
                targetPageIndex = resolvedIndex;
            }
        }
    }
    m_utilizationDetailStack->setCurrentIndex(targetPageIndex);

    for (int entryIndex = 0; entryIndex < entryCount; ++entryIndex)
    {
        UtilizationNavEntry& entry = m_utilizationNavEntries[static_cast<std::size_t>(entryIndex)];
        if (entry.navCard != nullptr)
        {
            entry.navCard->setSelectedState(entryIndex == boundedRowIndex);
        }
    }

    // 选项切换后立即重算大图高度，避免首帧出现滚动条。
    scheduleUtilizationLayoutRefresh();
}

void HardwareDock::applyInitialUtilizationSplitterSize()
{
    if (m_utilizationSplitterInitialSizeApplied
        || m_utilizationBodySplitter == nullptr)
    {
        return;
    }

    const QList<int> currentSizes = m_utilizationBodySplitter->sizes();
    const int availableWidth = currentSizes.value(0) + currentSizes.value(1);
    if (availableWidth <= 0)
    {
        return;
    }

    const int maxLeftWidth = std::max(140, availableWidth - 360);
    const int leftWidth = std::clamp(300, 140, maxLeftWidth);
    m_utilizationBodySplitter->setSizes({ leftWidth, std::max(0, availableWidth - leftWidth) });
    m_utilizationSplitterInitialSizeApplied = true;
    syncUtilizationSidebarCardWidths();
}

void HardwareDock::syncUtilizationSidebarCardWidths()
{
    if (m_utilizationSidebarList == nullptr)
    {
        return;
    }

    const int cardWidth = m_utilizationSidebarList->viewport()->width();
    if (cardWidth <= 0)
    {
        return;
    }

    const QList<int> savedSplitterSizes = m_utilizationBodySplitter != nullptr
        ? m_utilizationBodySplitter->sizes()
        : QList<int>();
    QList<int> boundedSplitterSizes = savedSplitterSizes;
    if (boundedSplitterSizes.size() == 2)
    {
        const int availableWidth = boundedSplitterSizes.value(0) + boundedSplitterSizes.value(1);
        const int maxLeftWidth = std::max(140, availableWidth - 360);
        const int boundedLeftWidth = std::clamp(
            boundedSplitterSizes.value(0),
            140,
            maxLeftWidth);
        boundedSplitterSizes = {
            boundedLeftWidth,
            std::max(0, availableWidth - boundedLeftWidth) };
    }
    // QListWidget 的行宽始终由 viewport 决定；这里只固定行高，避免把某一轮
    // 初始布局得到的宽度写成后续 splitter 的隐性最小宽度。
    const QSize nextSizeHint(0, 52);
    bool itemSizeChanged = false;

    for (int rowIndex = 0; rowIndex < m_utilizationSidebarList->count(); ++rowIndex)
    {
        QListWidgetItem* const itemPointer = m_utilizationSidebarList->item(rowIndex);
        if (itemPointer == nullptr)
        {
            continue;
        }

        if (itemPointer->sizeHint() != nextSizeHint)
        {
            itemPointer->setSizeHint(nextSizeHint);
            itemSizeChanged = true;
        }

        if (QWidget* const cardWidget = m_utilizationSidebarList->itemWidget(itemPointer))
        {
            cardWidget->setMinimumWidth(0);
            cardWidget->setMaximumWidth(QWIDGETSIZE_MAX);
            // QListWidget 的 index widget 在 splitter 松动后可能仍保留上一轮宽度。
            // 用当前 item 矩形的纵坐标和 viewport 宽度同步一次，随后由视图布局接管。
            QRect cardGeometry = m_utilizationSidebarList->visualItemRect(itemPointer);
            if (cardGeometry.height() <= 0)
            {
                cardGeometry.setHeight(nextSizeHint.height());
            }
            cardGeometry.setWidth(cardWidth);
            cardWidget->setGeometry(cardGeometry);
            cardWidget->updateGeometry();
            cardWidget->update();
        }
    }

    if (!itemSizeChanged
        || m_utilizationBodySplitter == nullptr
        || savedSplitterSizes.size() != 2)
    {
        return;
    }

    // QListWidget 行的宽度 hint 可能触发父 splitter 重新分配；立即恢复一次，
    // 再在布局事件完成后恢复一次，确保释放时保留用户实际拖到的位置。
    m_utilizationBodySplitter->setSizes(boundedSplitterSizes);
    QTimer::singleShot(0, this, [this, boundedSplitterSizes]()
    {
        if (m_utilizationBodySplitter != nullptr)
        {
            m_utilizationBodySplitter->setSizes(boundedSplitterSizes);
        }
    });
}

void HardwareDock::adjustUtilizationChartHeights()
{
    // applyFixedHeightIfChanged 作用：
    // - 仅在目标高度变化时写入最小/最大高度，避免无意义重排触发递归 resize；
    // - widgetPointer：待设置控件；heightValue：目标固定高度（像素）；
    // - 返回行为：无返回值，非法高度直接忽略。
    auto applyFixedHeightIfChanged =
        [](QWidget* widgetPointer, const int heightValue)
        {
            if (widgetPointer == nullptr || heightValue <= 0)
            {
                return;
            }
            if (widgetPointer->minimumHeight() == heightValue
                && widgetPointer->maximumHeight() == heightValue)
            {
                return;
            }
            widgetPointer->setMinimumHeight(heightValue);
            widgetPointer->setMaximumHeight(heightValue);
        };

    // applyMaxHeightIfChanged 作用：
    // - 仅调整最大高度，最小高度保持 0，防止文字区反向撑大父布局；
    // - widgetPointer：目标控件；maxHeightValue：目标最大高度（像素）；
    // - 返回行为：无返回值，非法高度直接忽略。
    auto applyMaxHeightIfChanged =
        [](QWidget* widgetPointer, const int maxHeightValue)
        {
            if (widgetPointer == nullptr || maxHeightValue <= 0)
            {
                return;
            }
            if (widgetPointer->minimumHeight() == 0
                && widgetPointer->maximumHeight() == maxHeightValue)
            {
                return;
            }
            widgetPointer->setMinimumHeight(0);
            widgetPointer->setMaximumHeight(maxHeightValue);
        };

    // applyFixedWidthIfChanged 作用：
    // - 仅在目标宽度变化时写入最小/最大宽度，避免 CPU 核心网格因子控件 sizeHint 重新抢占列宽；
    // - widgetPointer：待设置控件；widthValue：目标固定宽度（像素）；
    // - 返回行为：无返回值，非法宽度直接忽略。
    auto applyFixedWidthIfChanged =
        [](QWidget* widgetPointer, const int widthValue)
        {
            if (widgetPointer == nullptr || widthValue <= 0)
            {
                return;
            }
            if (widgetPointer->minimumWidth() == widthValue
                && widgetPointer->maximumWidth() == widthValue)
            {
                return;
            }
            widgetPointer->setMinimumWidth(widthValue);
            widgetPointer->setMaximumWidth(widthValue);
        };

    // ===================== 左侧设备列表：按宽度收缩，按高度滚动 =====================
    if (m_utilizationPage != nullptr && m_utilizationSidebarList != nullptr)
    {
        // cardHeight 用途：保持缩略图最小可读高度；多磁盘/多网卡/GPU 时由列表滚动承接溢出。
        if (m_utilizationSidebarList->spacing() != 2)
        {
            m_utilizationSidebarList->setSpacing(2);
        }
        syncUtilizationSidebarCardWidths();
    }

    // ===================== CPU 页：按核心网格动态压缩宽高 =====================
    if (m_utilizationCpuSubPage != nullptr
        && m_coreChartHostWidget != nullptr
        && m_coreChartGridLayout != nullptr
        && !m_coreChartEntries.empty())
    {
        // cpuReferenceHeight 用途：稳定页面高度，避免用子控件 sizeHint 反向撑高外层 Dock。
        int cpuReferenceHeight = 0;
        if (m_utilizationDetailStack != nullptr)
        {
            cpuReferenceHeight = m_utilizationDetailStack->contentsRect().height();
        }
        if (cpuReferenceHeight <= 0)
        {
            cpuReferenceHeight = m_utilizationCpuSubPage->contentsRect().height();
        }
        if (cpuReferenceHeight <= 0)
        {
            cpuReferenceHeight = 240;
        }

        const int titleHeight = 72;
        const int headerHeight = std::max(
            m_cpuModelLabel != nullptr ? m_cpuModelLabel->height() : 0,
            titleHeight);
        const int summaryHeight = m_utilizationSummaryLabel != nullptr
            ? m_utilizationSummaryLabel->sizeHint().height()
            : 16;
        const int detailHeight = std::max({
            m_cpuUtilPrimaryDetailLabel != nullptr ? m_cpuUtilPrimaryDetailLabel->sizeHint().height() : 0,
            m_cpuUtilSecondaryDetailLabel != nullptr ? m_cpuUtilSecondaryDetailLabel->sizeHint().height() : 0,
            m_cpuUtilTertiaryDetailLabel != nullptr ? m_cpuUtilTertiaryDetailLabel->sizeHint().height() : 0
        });
        // availableChartAreaHeight 用途：核心图可用高度；允许极小高度，保证页面整体不冒滚动条。
        const int availableChartAreaHeight = std::max(
            1,
            cpuReferenceHeight - headerHeight - summaryHeight - detailHeight - 42);
        const int gridRows = std::max(1, m_cpuCoreGridRowCount);
        const int gridSpacing = std::max(0, m_coreChartGridLayout->verticalSpacing());
        // cellHeight 用途：每个逻辑处理器小卡片高度；低高度下继续压缩而不是让滚动条接管。
        const int cellHeight = std::max(
            1,
            (availableChartAreaHeight - gridSpacing * (gridRows - 1)) / gridRows);

        // cpuReferenceWidth 用途：
        // - 以滚动区 viewport 当前宽度为准，避免 QGridLayout 按 QChartView/标题 sizeHint 把第一列撑大；
        // - 当前页面的 CPU 核心图不希望横向滚动，所有列在首帧和 resize 后都按同一宽度重排。
        int cpuReferenceWidth = 0;
        if (m_coreChartScrollArea != nullptr && m_coreChartScrollArea->viewport() != nullptr)
        {
            cpuReferenceWidth = m_coreChartScrollArea->viewport()->contentsRect().width();
        }
        if (cpuReferenceWidth <= 0 && m_coreChartScrollArea != nullptr)
        {
            cpuReferenceWidth = m_coreChartScrollArea->contentsRect().width();
        }
        if (cpuReferenceWidth <= 0)
        {
            cpuReferenceWidth = m_utilizationCpuSubPage->contentsRect().width();
        }

        const int gridColumns = std::max(1, m_cpuCoreGridColumnCount);
        const int horizontalGridSpacing = std::max(0, m_coreChartGridLayout->horizontalSpacing());
        const int availableChartAreaWidth = std::max(1, cpuReferenceWidth);
        const int cellWidth = std::max(
            1,
            (availableChartAreaWidth - horizontalGridSpacing * (gridColumns - 1)) / gridColumns);
        const int hostWidth = gridColumns * cellWidth + horizontalGridSpacing * (gridColumns - 1);

        // 列宽策略说明：
        // - QGridLayout 默认会参考每个子控件的 sizeHint，QChartView 在首帧/数据刷新后可能让第 0 列迅速变宽；
        // - 这里同时设置列 stretch、列最小宽和单元格固定宽，确保 6 列等场景始终均分 viewport；
        // - 多余的历史列（若核心数变化后残留）重置为 0，避免旧 stretch 继续参与分配。
        const int layoutColumnCount = std::max(gridColumns, m_coreChartGridLayout->columnCount());
        for (int columnIndex = 0; columnIndex < layoutColumnCount; ++columnIndex)
        {
            const bool activeColumn = columnIndex < gridColumns;
            m_coreChartGridLayout->setColumnStretch(columnIndex, activeColumn ? 1 : 0);
            m_coreChartGridLayout->setColumnMinimumWidth(columnIndex, activeColumn ? cellWidth : 0);
        }

        for (CoreChartEntry& chartEntry : m_coreChartEntries)
        {
            if (chartEntry.containerWidget != nullptr)
            {
                applyFixedWidthIfChanged(chartEntry.containerWidget, cellWidth);
                applyFixedHeightIfChanged(chartEntry.containerWidget, cellHeight);
            }
            if (chartEntry.chartView != nullptr)
            {
                const int titleReserveHeight = chartEntry.titleLabel != nullptr
                    ? std::min(18, std::max(0, chartEntry.titleLabel->sizeHint().height()))
                    : 0;
                const int chartHeight = std::max(1, cellHeight - titleReserveHeight - kCpuCoreChartChromeReservePx);
                applyFixedHeightIfChanged(chartEntry.chartView, chartHeight);
            }
        }

        const int hostHeight = gridRows * cellHeight + gridSpacing * (gridRows - 1);
        applyFixedWidthIfChanged(m_coreChartHostWidget, hostWidth);
        applyFixedHeightIfChanged(m_coreChartHostWidget, hostHeight);
        if (m_coreChartScrollArea != nullptr)
        {
            // CPU 核心图区域固定到可用高度，核心多时压缩单元格，不显示滚动条。
            applyFixedHeightIfChanged(m_coreChartScrollArea, availableChartAreaHeight);
        }

        applyMaxHeightIfChanged(m_cpuUtilPrimaryDetailLabel, std::max(1, m_cpuUtilPrimaryDetailLabel != nullptr ? m_cpuUtilPrimaryDetailLabel->sizeHint().height() : 1));
        applyMaxHeightIfChanged(m_cpuUtilSecondaryDetailLabel, std::max(1, m_cpuUtilSecondaryDetailLabel != nullptr ? m_cpuUtilSecondaryDetailLabel->sizeHint().height() : 1));
        applyMaxHeightIfChanged(m_cpuUtilTertiaryDetailLabel, std::max(1, m_cpuUtilTertiaryDetailLabel != nullptr ? m_cpuUtilTertiaryDetailLabel->sizeHint().height() : 1));
    }

    // ===================== 其他页：按页面高度比例压缩主图 =====================
    auto adjustMainChartHeight =
        [](
            QWidget* pageWidget,
            QWidget* chartView,
            const double ratioValue,
            const int minHeightValue,
            const int reserveHeightValue)
        {
            if (pageWidget == nullptr || chartView == nullptr)
            {
                return;
            }
            const int pageHeight = pageWidget->contentsRect().height();
            if (pageHeight <= 0)
            {
                return;
            }
            const int safeMinHeight = std::max(1, minHeightValue);
            const int maxAllowedHeight = std::max(1, pageHeight - reserveHeightValue);
            const int expectedHeight = static_cast<int>(std::round(static_cast<double>(pageHeight) * ratioValue));
            const int finalHeight = std::clamp(expectedHeight, 1, maxAllowedHeight);
            const int boundedHeight = std::min(finalHeight, std::max(safeMinHeight, maxAllowedHeight));
            if (chartView->minimumHeight() != boundedHeight
                || chartView->maximumHeight() != boundedHeight)
            {
                chartView->setMinimumHeight(boundedHeight);
                chartView->setMaximumHeight(boundedHeight);
            }
        };

    adjustMainChartHeight(m_utilizationMemorySubPage, m_memoryCompositionHistoryWidget, 0.36, 24, 116);
    adjustMainChartHeight(m_utilizationDiskSubPage, m_diskUtilChartView, 0.40, 24, 120);
    adjustMainChartHeight(m_utilizationNetworkSubPage, m_networkUtilChartView, 0.40, 24, 120);

    applyMaxHeightIfChanged(m_memoryUtilPrimaryDetailLabel, std::max(1, m_memoryUtilPrimaryDetailLabel != nullptr ? m_memoryUtilPrimaryDetailLabel->sizeHint().height() : 1));
    applyMaxHeightIfChanged(m_memoryUtilSecondaryDetailLabel, std::max(1, m_memoryUtilSecondaryDetailLabel != nullptr ? m_memoryUtilSecondaryDetailLabel->sizeHint().height() : 1));
    applyMaxHeightIfChanged(m_diskUtilDetailLabel, std::max(1, m_diskUtilDetailLabel != nullptr ? m_diskUtilDetailLabel->sizeHint().height() : 1));
    applyMaxHeightIfChanged(m_networkUtilDetailLabel, std::max(1, m_networkUtilDetailLabel != nullptr ? m_networkUtilDetailLabel->sizeHint().height() : 1));
    for (DiskUtilizationDevice& device : m_diskUtilDevices)
    {
        adjustMainChartHeight(device.pageWidget, device.chartView, 0.40, 24, 120);
        if (device.detailLabel != nullptr)
        {
            applyMaxHeightIfChanged(device.detailLabel, std::max(1, device.detailLabel->sizeHint().height()));
        }
    }
    for (NetworkUtilizationDevice& device : m_networkUtilDevices)
    {
        adjustMainChartHeight(device.pageWidget, device.chartView, 0.40, 24, 120);
        if (device.detailLabel != nullptr)
        {
            applyMaxHeightIfChanged(device.detailLabel, std::max(1, device.detailLabel->sizeHint().height()));
        }
    }

    // GPU 页：四个引擎图 + 两条显存曲线全部动态压缩。
    if (m_utilizationGpuSubPage != nullptr)
    {
        // gpuReferenceHeight 用途：GPU 子页布局参考高度，优先使用堆栈可见区域，避免自反馈增高。
        int gpuReferenceHeight = 0;
        if (m_utilizationDetailStack != nullptr)
        {
            gpuReferenceHeight = m_utilizationDetailStack->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            gpuReferenceHeight = m_utilizationGpuSubPage->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            gpuReferenceHeight = 320;
        }

        const int titleHeight = std::max(
            m_gpuAdapterTitleLabel != nullptr ? m_gpuAdapterTitleLabel->sizeHint().height() : 0,
            58);
        const int summaryHeight = m_gpuUtilSummaryLabel != nullptr
            ? m_gpuUtilSummaryLabel->sizeHint().height()
            : 20;
        const int detailHeight = m_gpuUtilDetailLabel != nullptr
            ? m_gpuUtilDetailLabel->sizeHint().height()
            : 22;
        // reservedHeight 用途：GPU 页非图表区预留高度（含布局间距与上下边距）。
        const int reservedHeight = titleHeight + summaryHeight + detailHeight + 38;
        const int availableHeight = std::max(1, gpuReferenceHeight - reservedHeight);

        // engineAreaHeight 用途：分配给 2x2 引擎图区域的高度。
        const int engineAreaHeight = std::max(
            1,
            static_cast<int>(std::round(static_cast<double>(availableHeight) * 0.52)));
        const int memoryAreaEachHeight = std::max(1, (availableHeight - engineAreaHeight - 8) / 2);
        if (m_gpuEngineHostWidget != nullptr && m_gpuEngineGridLayout != nullptr)
        {
            const int rowSpacing = std::max(0, m_gpuEngineGridLayout->verticalSpacing());
            const int cellHeight = std::max(1, (engineAreaHeight - rowSpacing) / 2);
            for (GpuEngineChartEntry& chartEntry : m_gpuEngineCharts)
            {
                if (chartEntry.chartView != nullptr)
                {
                    applyMaxHeightIfChanged(chartEntry.chartView, std::max(1, cellHeight - 10));
                }
                if (chartEntry.titleLabel != nullptr)
                {
                    chartEntry.titleLabel->setMinimumHeight(0);
                    chartEntry.titleLabel->setMaximumHeight(18);
                }
            }
            applyMaxHeightIfChanged(m_gpuEngineHostWidget, engineAreaHeight);
        }

        if (m_gpuDedicatedMemoryChartView != nullptr)
        {
            applyMaxHeightIfChanged(m_gpuDedicatedMemoryChartView, memoryAreaEachHeight);
        }
        if (m_gpuSharedMemoryChartView != nullptr)
        {
            applyMaxHeightIfChanged(m_gpuSharedMemoryChartView, memoryAreaEachHeight);
        }
        if (m_gpuUtilDetailLabel != nullptr)
        {
            applyMaxHeightIfChanged(m_gpuUtilDetailLabel, std::max(1, m_gpuUtilDetailLabel->sizeHint().height()));
        }
    }
    for (GpuUtilizationDevice& device : m_gpuUtilDevices)
    {
        if (device.pageWidget == nullptr)
        {
            continue;
        }

        // gpuReferenceHeight 用途：多 GPU 子页的当前稳定高度。
        int gpuReferenceHeight = 0;
        if (m_utilizationDetailStack != nullptr)
        {
            gpuReferenceHeight = m_utilizationDetailStack->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            gpuReferenceHeight = device.pageWidget->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            continue;
        }

        const int layoutSpacing = 6;
        const int headerHeight = 58;
        const int summaryHeight = device.summaryLabel != nullptr
            ? device.summaryLabel->sizeHint().height()
            : 0;
        const int detailHeight = device.detailLabel != nullptr
            ? device.detailLabel->sizeHint().height()
            : 0;
        const int reservedHeight = headerHeight + summaryHeight + detailHeight + layoutSpacing * 7 + 12;
        const int graphAreaHeight = std::max(1, gpuReferenceHeight - reservedHeight);
        const int engineAreaHeight = std::max(1, graphAreaHeight / 2);
        const int memoryAreaEachHeight = std::max(1, graphAreaHeight / 4);

        if (device.engineHostWidget != nullptr && device.engineGridLayout != nullptr)
        {
            const int rowSpacing = std::max(0, device.engineGridLayout->verticalSpacing());
            const int cellHeight = std::max(1, (engineAreaHeight - rowSpacing) / 2);
            for (GpuEngineChartEntry& chartEntry : device.engineCharts)
            {
                if (chartEntry.chartView != nullptr)
                {
                    applyMaxHeightIfChanged(chartEntry.chartView, std::max(1, cellHeight - 14));
                }
                if (chartEntry.titleLabel != nullptr)
                {
                    chartEntry.titleLabel->setMinimumHeight(0);
                    chartEntry.titleLabel->setMaximumHeight(18);
                }
            }
            applyMaxHeightIfChanged(device.engineHostWidget, engineAreaHeight);
        }
        applyMaxHeightIfChanged(device.dedicatedMemoryChartView, memoryAreaEachHeight);
        applyMaxHeightIfChanged(device.sharedMemoryChartView, memoryAreaEachHeight);
        if (device.detailLabel != nullptr)
        {
            applyMaxHeightIfChanged(device.detailLabel, std::max(1, device.detailLabel->sizeHint().height()));
        }
    }
}

void HardwareDock::initializeUtilizationCpuSubTab()
{
    m_utilizationCpuSubPage = new QWidget(m_utilizationDetailStack);
    configureCompressibleWidget(m_utilizationCpuSubPage, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(m_utilizationCpuSubPage);
    QVBoxLayout* cpuSubLayout = new QVBoxLayout(m_utilizationCpuSubPage);
    cpuSubLayout->setContentsMargins(4, 4, 4, 4);
    cpuSubLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.cpu.title"), QStringLiteral("CPU")),
        m_utilizationCpuSubPage);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    m_cpuModelLabel = new QLabel(QStringLiteral("检测中..."), m_utilizationCpuSubPage);
    configurePersistentHeaderLabel(m_cpuModelLabel);
    m_cpuModelLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    m_cpuModelLabel->setStyleSheet(
        QStringLiteral("font-size:15px;font-weight:500;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(m_cpuModelLabel, 6);
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(m_cpuModelLabel, 0);
    cpuSubLayout->addLayout(headerLayout, 0);

    m_utilizationSummaryLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.cpu.summary.initial"),
            QStringLiteral("30 秒内的利用率 %")),
        m_utilizationCpuSubPage);
    configureCompressibleLabel(m_utilizationSummaryLabel);
    m_utilizationSummaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    cpuSubLayout->addWidget(m_utilizationSummaryLabel, 0);

    m_coreChartScrollArea = new QScrollArea(m_utilizationCpuSubPage);
    m_coreChartScrollArea->setWidgetResizable(true);
    m_coreChartScrollArea->setFrameShape(QFrame::NoFrame);
    // 核心数量很多时压缩网格，不显示内部滚动条。
    m_coreChartScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_coreChartScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_coreChartScrollArea->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
    configureCompressibleWidget(m_coreChartScrollArea, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(m_coreChartScrollArea);
    m_coreChartHostWidget = new QWidget(m_coreChartScrollArea);
    configureCompressibleWidget(m_coreChartHostWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(m_coreChartHostWidget);
    m_coreChartGridLayout = new QGridLayout(m_coreChartHostWidget);
    m_coreChartGridLayout->setContentsMargins(0, 0, 0, 0);
    m_coreChartGridLayout->setHorizontalSpacing(kCpuCoreChartGridSpacingPx);
    m_coreChartGridLayout->setVerticalSpacing(kCpuCoreChartGridSpacingPx);
    // coreChartPlaceholderLabel 用途：首帧前暂时代替大量 QChartView，避免构造硬件页时一次性创建每核心图表。
    QLabel* coreChartPlaceholderLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.cpu.chart_placeholder"),
            QStringLiteral("CPU 核心图将在首帧后加载...")),
        m_coreChartHostWidget);
    coreChartPlaceholderLabel->setAlignment(Qt::AlignCenter);
    coreChartPlaceholderLabel->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;")
        .arg(KswordTheme::TextSecondaryHex()));
    m_coreChartGridLayout->addWidget(coreChartPlaceholderLabel, 0, 0, 1, 1);
    m_coreChartScrollArea->setWidget(m_coreChartHostWidget);
    cpuSubLayout->addWidget(m_coreChartScrollArea, 1);

    QHBoxLayout* detailLayout = new QHBoxLayout();
    detailLayout->setSpacing(16);
    m_cpuUtilPrimaryDetailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.cpu.detail.primary_sampling"),
            QStringLiteral("CPU 详情采样中...")),
        m_utilizationCpuSubPage);
    m_cpuUtilSecondaryDetailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.cpu.detail.secondary_sampling"),
            QStringLiteral("硬件参数读取中...")),
        m_utilizationCpuSubPage);
    m_cpuUtilTertiaryDetailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.cpu.detail.tertiary_sampling"),
            QStringLiteral("缓存与 R0 状态读取中...")),
        m_utilizationCpuSubPage);
    configureCompressibleLabel(m_cpuUtilPrimaryDetailLabel);
    configureCompressibleLabel(m_cpuUtilSecondaryDetailLabel);
    configureCompressibleLabel(m_cpuUtilTertiaryDetailLabel);
    m_cpuUtilPrimaryDetailLabel->setWordWrap(false);
    m_cpuUtilSecondaryDetailLabel->setWordWrap(false);
    m_cpuUtilTertiaryDetailLabel->setWordWrap(false);
    m_cpuUtilPrimaryDetailLabel->setTextFormat(Qt::RichText);
    m_cpuUtilPrimaryDetailLabel->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    m_cpuUtilSecondaryDetailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    m_cpuUtilTertiaryDetailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    m_cpuUtilPrimaryDetailLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    m_cpuUtilSecondaryDetailLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    m_cpuUtilTertiaryDetailLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    detailLayout->addWidget(m_cpuUtilPrimaryDetailLabel, 5);
    detailLayout->addWidget(m_cpuUtilSecondaryDetailLabel, 3);
    detailLayout->addWidget(m_cpuUtilTertiaryDetailLabel, 3);
    cpuSubLayout->addLayout(detailLayout, 0);

    m_utilizationDetailStack->addWidget(m_utilizationCpuSubPage);
}

void HardwareDock::initializeUtilizationMemorySubTab()
{
    m_utilizationMemorySubPage = new QWidget(m_utilizationDetailStack);
    configureCompressibleWidget(m_utilizationMemorySubPage, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(m_utilizationMemorySubPage);
    QVBoxLayout* memorySubLayout = new QVBoxLayout(m_utilizationMemorySubPage);
    memorySubLayout->setContentsMargins(4, 4, 4, 4);
    memorySubLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.memory.title"), QStringLiteral("内存")),
        m_utilizationMemorySubPage);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    m_memoryCapacityLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.memory.capacity_sampling"), QStringLiteral("读取中...")),
        m_utilizationMemorySubPage);
    configurePersistentHeaderLabel(m_memoryCapacityLabel, QSizePolicy::Ignored);
    m_memoryCapacityLabel->setStyleSheet(
        QStringLiteral("font-size:31px;font-weight:500;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(m_memoryCapacityLabel, 8);
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(m_memoryCapacityLabel, 0);
    memorySubLayout->addLayout(headerLayout, 0);

    m_memoryUtilSummaryLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.memory.summary.initial"), QStringLiteral("内存使用量")),
        m_utilizationMemorySubPage);
    configureCompressibleLabel(m_memoryUtilSummaryLabel);
    m_memoryUtilSummaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    memorySubLayout->addWidget(m_memoryUtilSummaryLabel, 0);

    m_memoryCompositionHistoryWidget = new MemoryCompositionHistoryWidget(m_utilizationMemorySubPage);
    configureCompressibleWidget(m_memoryCompositionHistoryWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    memorySubLayout->addWidget(m_memoryCompositionHistoryWidget, 1);

    QHBoxLayout* detailLayout = new QHBoxLayout();
    detailLayout->setSpacing(16);
    m_memoryUtilPrimaryDetailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.memory.detail.primary_sampling"),
            QStringLiteral("内存参数采样中...")),
        m_utilizationMemorySubPage);
    m_memoryUtilSecondaryDetailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.memory.detail.secondary_sampling"),
            QStringLiteral("硬件参数读取中...")),
        m_utilizationMemorySubPage);
    configureCompressibleLabel(m_memoryUtilPrimaryDetailLabel);
    configureCompressibleLabel(m_memoryUtilSecondaryDetailLabel);
    m_memoryUtilPrimaryDetailLabel->setWordWrap(false);
    m_memoryUtilSecondaryDetailLabel->setWordWrap(false);
    m_memoryUtilPrimaryDetailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    m_memoryUtilSecondaryDetailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    detailLayout->addWidget(m_memoryUtilPrimaryDetailLabel, 1);
    detailLayout->addWidget(m_memoryUtilSecondaryDetailLabel, 1);
    memorySubLayout->addLayout(detailLayout, 0);

    m_utilizationDetailStack->addWidget(m_utilizationMemorySubPage);
}

void HardwareDock::initializeUtilizationDiskSubTab()
{
    m_utilizationDiskSubPage = new QWidget(m_utilizationDetailStack);
    configureCompressibleWidget(m_utilizationDiskSubPage, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(m_utilizationDiskSubPage);
    QVBoxLayout* diskSubLayout = new QVBoxLayout(m_utilizationDiskSubPage);
    diskSubLayout->setContentsMargins(4, 4, 4, 4);
    diskSubLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.disk.title"), QStringLiteral("磁盘")),
        m_utilizationDiskSubPage);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    diskSubLayout->addWidget(titleLabel, 0);

    m_diskUtilSummaryLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.disk.sampling"),
            QStringLiteral("磁盘采样初始化中...")),
        m_utilizationDiskSubPage);
    configureCompressibleLabel(m_diskUtilSummaryLabel);
    m_diskUtilSummaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    diskSubLayout->addWidget(m_diskUtilSummaryLabel, 0);

    m_diskReadLineSeries = new QLineSeries(m_utilizationDiskSubPage);
    m_diskReadLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.disk.read"), QStringLiteral("读取")));
    const QColor diskReadColor(80, 170, 255);
    const QColor diskWriteColor(255, 190, 105);
    m_diskReadLineSeries->setColor(diskReadColor);
    m_diskReadBaselineSeries = createBaselineSeries(m_utilizationDiskSubPage, m_historyLength);
    m_diskWriteLineSeries = new QLineSeries(m_utilizationDiskSubPage);
    m_diskWriteLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.disk.write"), QStringLiteral("写入")));
    m_diskWriteLineSeries->setColor(diskWriteColor);
    m_diskWriteBaselineSeries = createBaselineSeries(m_utilizationDiskSubPage, m_historyLength);
    initializeLineSeriesHistory(m_diskReadLineSeries, m_historyLength);
    initializeLineSeriesHistory(m_diskWriteLineSeries, m_historyLength);

    QChart* diskChart = new QChart();
    m_diskReadAreaSeries = addFilledAreaSeries(
        diskChart,
        m_diskReadLineSeries,
        m_diskReadBaselineSeries,
        diskReadColor,
        42);
    m_diskWriteAreaSeries = addFilledAreaSeries(
        diskChart,
        m_diskWriteLineSeries,
        m_diskWriteBaselineSeries,
        diskWriteColor,
        34);
    configureUtilizationPlotChart(
        diskChart,
        diskReadColor,
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.disk.chart_title"),
            QStringLiteral("磁盘读写速率趋势")),
        true);

    m_diskUtilAxisX = new QValueAxis(diskChart);
    configureUtilizationValueAxis(m_diskUtilAxisX, diskReadColor, 0.0, static_cast<double>(m_historyLength));

    m_diskUtilAxisY = new QValueAxis(diskChart);
    configureUtilizationValueAxis(m_diskUtilAxisY, diskReadColor, 0.0, 1.0);

    diskChart->addAxis(m_diskUtilAxisX, Qt::AlignBottom);
    diskChart->addAxis(m_diskUtilAxisY, Qt::AlignLeft);
    if (m_diskReadAreaSeries != nullptr)
    {
        m_diskReadAreaSeries->attachAxis(m_diskUtilAxisX);
        m_diskReadAreaSeries->attachAxis(m_diskUtilAxisY);
    }
    if (m_diskWriteAreaSeries != nullptr)
    {
        m_diskWriteAreaSeries->attachAxis(m_diskUtilAxisX);
        m_diskWriteAreaSeries->attachAxis(m_diskUtilAxisY);
    }

    m_diskUtilChartView = createPlotBackgroundChartView(diskChart, m_utilizationDiskSubPage);
    diskSubLayout->addWidget(m_diskUtilChartView, 1);

    m_diskUtilDetailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.disk.detail_sampling"),
            QStringLiteral("磁盘参数采样中...")),
        m_utilizationDiskSubPage);
    configureCompressibleLabel(m_diskUtilDetailLabel);
    m_diskUtilDetailLabel->setWordWrap(false);
    m_diskUtilDetailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    diskSubLayout->addWidget(m_diskUtilDetailLabel, 0);

    m_utilizationDetailStack->addWidget(m_utilizationDiskSubPage);
}

void HardwareDock::initializeUtilizationNetworkSubTab()
{
    m_utilizationNetworkSubPage = new QWidget(m_utilizationDetailStack);
    configureCompressibleWidget(m_utilizationNetworkSubPage, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(m_utilizationNetworkSubPage);
    QVBoxLayout* networkSubLayout = new QVBoxLayout(m_utilizationNetworkSubPage);
    networkSubLayout->setContentsMargins(4, 4, 4, 4);
    networkSubLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.network.title"), QStringLiteral("以太网")),
        m_utilizationNetworkSubPage);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    networkSubLayout->addWidget(titleLabel, 0);

    m_networkUtilSummaryLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.network.sampling"),
            QStringLiteral("网络采样初始化中...")),
        m_utilizationNetworkSubPage);
    configureCompressibleLabel(m_networkUtilSummaryLabel);
    m_networkUtilSummaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    networkSubLayout->addWidget(m_networkUtilSummaryLabel, 0);

    m_networkRxLineSeries = new QLineSeries(m_utilizationNetworkSubPage);
    m_networkRxLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.network.down"), QStringLiteral("下行")));
    const QColor networkRxColor(92, 190, 255);
    const QColor networkTxColor(153, 129, 255);
    m_networkRxLineSeries->setColor(networkRxColor);
    m_networkRxBaselineSeries = createBaselineSeries(m_utilizationNetworkSubPage, m_historyLength);
    m_networkTxLineSeries = new QLineSeries(m_utilizationNetworkSubPage);
    m_networkTxLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.network.up"), QStringLiteral("上行")));
    m_networkTxLineSeries->setColor(networkTxColor);
    m_networkTxBaselineSeries = createBaselineSeries(m_utilizationNetworkSubPage, m_historyLength);
    initializeLineSeriesHistory(m_networkRxLineSeries, m_historyLength);
    initializeLineSeriesHistory(m_networkTxLineSeries, m_historyLength);

    QChart* networkChart = new QChart();
    m_networkRxAreaSeries = addFilledAreaSeries(
        networkChart,
        m_networkRxLineSeries,
        m_networkRxBaselineSeries,
        networkRxColor,
        42);
    m_networkTxAreaSeries = addFilledAreaSeries(
        networkChart,
        m_networkTxLineSeries,
        m_networkTxBaselineSeries,
        networkTxColor,
        34);
    configureUtilizationPlotChart(
        networkChart,
        networkRxColor,
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.network.chart_title"),
            QStringLiteral("网络收发速率趋势")),
        true);

    m_networkUtilAxisX = new QValueAxis(networkChart);
    configureUtilizationValueAxis(m_networkUtilAxisX, networkRxColor, 0.0, static_cast<double>(m_historyLength));

    m_networkUtilAxisY = new QValueAxis(networkChart);
    configureUtilizationValueAxis(m_networkUtilAxisY, networkRxColor, 0.0, 1.0);

    networkChart->addAxis(m_networkUtilAxisX, Qt::AlignBottom);
    networkChart->addAxis(m_networkUtilAxisY, Qt::AlignLeft);
    if (m_networkRxAreaSeries != nullptr)
    {
        m_networkRxAreaSeries->attachAxis(m_networkUtilAxisX);
        m_networkRxAreaSeries->attachAxis(m_networkUtilAxisY);
    }
    if (m_networkTxAreaSeries != nullptr)
    {
        m_networkTxAreaSeries->attachAxis(m_networkUtilAxisX);
        m_networkTxAreaSeries->attachAxis(m_networkUtilAxisY);
    }

    m_networkUtilChartView = createPlotBackgroundChartView(networkChart, m_utilizationNetworkSubPage);
    networkSubLayout->addWidget(m_networkUtilChartView, 1);

    m_networkUtilDetailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.network.detail_sampling"),
            QStringLiteral("网络参数采样中...")),
        m_utilizationNetworkSubPage);
    configureCompressibleLabel(m_networkUtilDetailLabel);
    m_networkUtilDetailLabel->setWordWrap(false);
    m_networkUtilDetailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    networkSubLayout->addWidget(m_networkUtilDetailLabel, 0);

    m_utilizationDetailStack->addWidget(m_utilizationNetworkSubPage);
}

void HardwareDock::initializeUtilizationGpuSubTab()
{
    m_utilizationGpuSubPage = new QWidget(m_utilizationDetailStack);
    configureCompressibleWidget(m_utilizationGpuSubPage, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(m_utilizationGpuSubPage);
    QVBoxLayout* gpuSubLayout = new QVBoxLayout(m_utilizationGpuSubPage);
    gpuSubLayout->setContentsMargins(4, 4, 4, 4);
    gpuSubLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.gpu.title"), QStringLiteral("GPU")),
        m_utilizationGpuSubPage);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    m_gpuAdapterTitleLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.gpu.adapter_sampling"),
            QStringLiteral("适配器读取中...")),
        m_utilizationGpuSubPage);
    configurePersistentHeaderLabel(m_gpuAdapterTitleLabel, QSizePolicy::Ignored);
    m_gpuAdapterTitleLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    m_gpuAdapterTitleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:500;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(m_gpuAdapterTitleLabel, 6);
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(m_gpuAdapterTitleLabel, 0);
    gpuSubLayout->addLayout(headerLayout, 0);

    m_gpuUtilSummaryLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.gpu.sampling"),
            QStringLiteral("GPU采样初始化中...")),
        m_utilizationGpuSubPage);
    configureCompressibleLabel(m_gpuUtilSummaryLabel);
    m_gpuUtilSummaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    gpuSubLayout->addWidget(m_gpuUtilSummaryLabel, 0);

    // GPU 引擎四宫格：
    // - 对齐任务管理器的 3D / Copy / Video Encode / Video Decode；
    // - 每个引擎独立曲线和标题，便于定位瓶颈引擎。
    m_gpuEngineHostWidget = new QWidget(m_utilizationGpuSubPage);
    configureCompressibleWidget(m_gpuEngineHostWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(m_gpuEngineHostWidget);
    m_gpuEngineGridLayout = new QGridLayout(m_gpuEngineHostWidget);
    m_gpuEngineGridLayout->setContentsMargins(0, 0, 0, 0);
    m_gpuEngineGridLayout->setHorizontalSpacing(6);
    m_gpuEngineGridLayout->setVerticalSpacing(6);
    m_gpuEngineCharts.clear();

    auto addGpuEngineChart =
        [this](const QString& engineKeyText, const QString& displayNameText, const QColor& lineColor, const int rowIndex, const int columnIndex)
        {
            QWidget* cellWidget = new QWidget(m_gpuEngineHostWidget);
            configureCompressibleWidget(cellWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
            appendTransparentBackgroundStyle(cellWidget);
            QVBoxLayout* cellLayout = new QVBoxLayout(cellWidget);
            cellLayout->setContentsMargins(0, 0, 0, 0);
            cellLayout->setSpacing(2);

            QLabel* cellTitle = new QLabel(displayNameText, cellWidget);
            configureCompressibleLabel(cellTitle);
            cellTitle->setStyleSheet(
                QStringLiteral("font-size:14px;font-weight:600;color:%1;")
                .arg(KswordTheme::TextPrimaryHex()));
            cellLayout->addWidget(cellTitle, 0);

            QLineSeries* lineSeries = new QLineSeries(cellWidget);
            lineSeries->setColor(lineColor);
            QLineSeries* baselineSeries = createBaselineSeries(cellWidget, m_historyLength);
            initializeLineSeriesHistory(lineSeries, m_historyLength);

            QChart* chartPointer = new QChart();
            QAreaSeries* areaSeries = addFilledAreaSeries(
                chartPointer,
                lineSeries,
                baselineSeries,
                lineColor,
                44);
            configureUtilizationPlotChart(chartPointer, lineColor);

            QValueAxis* axisX = new QValueAxis(chartPointer);
            configureUtilizationValueAxis(axisX, lineColor, 0.0, static_cast<double>(m_historyLength));

            QValueAxis* axisY = new QValueAxis(chartPointer);
            configureUtilizationValueAxis(axisY, lineColor, 0.0, 100.0);

            chartPointer->addAxis(axisX, Qt::AlignBottom);
            chartPointer->addAxis(axisY, Qt::AlignLeft);
            if (areaSeries != nullptr)
            {
                areaSeries->attachAxis(axisX);
                areaSeries->attachAxis(axisY);
            }

            QChartView* chartView = createPlotBackgroundChartView(chartPointer, cellWidget);
            cellLayout->addWidget(chartView, 1);
            m_gpuEngineGridLayout->addWidget(cellWidget, rowIndex, columnIndex);

            GpuEngineChartEntry chartEntry;
            chartEntry.engineKeyText = engineKeyText;
            chartEntry.displayNameText = displayNameText;
            chartEntry.titleLabel = cellTitle;
            chartEntry.chartView = chartView;
            chartEntry.lineSeries = lineSeries;
            chartEntry.baselineSeries = baselineSeries;
            chartEntry.areaSeries = areaSeries;
            chartEntry.axisX = axisX;
            chartEntry.axisY = axisY;
            m_gpuEngineCharts.push_back(chartEntry);
        };

    addGpuEngineChart(
        QStringLiteral("3d"), QStringLiteral("3D"),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Gpu), 0, 0);
    addGpuEngineChart(
        QStringLiteral("copy"), QStringLiteral("Copy"),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Copy), 0, 1);
    addGpuEngineChart(
        QStringLiteral("video_encode"), QStringLiteral("Video Encode"),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::VideoEncode), 1, 0);
    addGpuEngineChart(
        QStringLiteral("video_decode"), QStringLiteral("Video Decode"),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::VideoDecode), 1, 1);
    gpuSubLayout->addWidget(m_gpuEngineHostWidget, 1);

    // 显存曲线：专用显存 + 共享显存。
    m_gpuDedicatedMemoryLineSeries = new QLineSeries(m_utilizationGpuSubPage);
    const QColor gpuDedicatedMemoryColor =
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::DedicatedMemory);
    const QColor gpuSharedMemoryColor =
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::SharedMemory);
    m_gpuDedicatedMemoryLineSeries->setColor(gpuDedicatedMemoryColor);
    m_gpuDedicatedMemoryBaselineSeries = createBaselineSeries(m_utilizationGpuSubPage, m_historyLength);
    m_gpuSharedMemoryLineSeries = new QLineSeries(m_utilizationGpuSubPage);
    m_gpuSharedMemoryLineSeries->setColor(gpuSharedMemoryColor);
    m_gpuSharedMemoryBaselineSeries = createBaselineSeries(m_utilizationGpuSubPage, m_historyLength);
    initializeLineSeriesHistory(m_gpuDedicatedMemoryLineSeries, m_historyLength);
    initializeLineSeriesHistory(m_gpuSharedMemoryLineSeries, m_historyLength);

    auto createGpuMemoryChart =
        [this](
            const QString& titleText,
            QLineSeries* lineSeries,
            QLineSeries* baselineSeries,
            QAreaSeries** areaSeriesOut,
            const QColor& lineColor,
            QValueAxis** axisXOut,
            QValueAxis** axisYOut,
            QChartView** chartViewOut)
        {
            QChart* chartPointer = new QChart();
            QAreaSeries* areaSeries = addFilledAreaSeries(
                chartPointer,
                lineSeries,
                baselineSeries,
                lineColor,
                42);
            configureUtilizationPlotChart(chartPointer, lineColor, titleText);

            QValueAxis* axisX = new QValueAxis(chartPointer);
            configureUtilizationValueAxis(axisX, lineColor, 0.0, static_cast<double>(m_historyLength));

            QValueAxis* axisY = new QValueAxis(chartPointer);
            configureUtilizationValueAxis(axisY, lineColor, 0.0, 1.0);

            chartPointer->addAxis(axisX, Qt::AlignBottom);
            chartPointer->addAxis(axisY, Qt::AlignLeft);
            if (areaSeries != nullptr)
            {
                areaSeries->attachAxis(axisX);
                areaSeries->attachAxis(axisY);
            }

            if (areaSeriesOut != nullptr)
            {
                *areaSeriesOut = areaSeries;
            }
            if (axisXOut != nullptr)
            {
                *axisXOut = axisX;
            }
            if (axisYOut != nullptr)
            {
                *axisYOut = axisY;
            }
            if (chartViewOut != nullptr)
            {
                *chartViewOut = createPlotBackgroundChartView(chartPointer, m_utilizationGpuSubPage);
            }
        };

    createGpuMemoryChart(
        QStringLiteral("专用 GPU 内存利用率"),
        m_gpuDedicatedMemoryLineSeries,
        m_gpuDedicatedMemoryBaselineSeries,
        &m_gpuDedicatedMemoryAreaSeries,
        gpuDedicatedMemoryColor,
        &m_gpuDedicatedMemoryAxisX,
        &m_gpuDedicatedMemoryAxisY,
        &m_gpuDedicatedMemoryChartView);
    createGpuMemoryChart(
        QStringLiteral("共享 GPU 内存利用率"),
        m_gpuSharedMemoryLineSeries,
        m_gpuSharedMemoryBaselineSeries,
        &m_gpuSharedMemoryAreaSeries,
        gpuSharedMemoryColor,
        &m_gpuSharedMemoryAxisX,
        &m_gpuSharedMemoryAxisY,
        &m_gpuSharedMemoryChartView);

    gpuSubLayout->addWidget(m_gpuDedicatedMemoryChartView, 0);
    gpuSubLayout->addWidget(m_gpuSharedMemoryChartView, 0);

    m_gpuUtilDetailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.gpu.detail_sampling"),
            QStringLiteral("GPU参数采样中...")),
        m_utilizationGpuSubPage);
    configureCompressibleLabel(m_gpuUtilDetailLabel);
    m_gpuUtilDetailLabel->setWordWrap(false);
    m_gpuUtilDetailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    gpuSubLayout->addWidget(m_gpuUtilDetailLabel, 0);

    m_utilizationDetailStack->addWidget(m_utilizationGpuSubPage);
}

void HardwareDock::initializeCpuTab()
{
    m_cpuPage = new QWidget(m_sideTabWidget);
    m_cpuLayout = new QVBoxLayout(m_cpuPage);
    m_cpuLayout->setContentsMargins(4, 4, 4, 4);
    m_cpuLayout->setSpacing(6);

    m_cpuDetailLabel = new QLabel(QStringLiteral("温度/电压读取中..."), m_cpuPage);
    m_cpuDetailLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    m_cpuLayout->addWidget(m_cpuDetailLabel, 0);

    m_cpuDetailTable = new ks::ui::VisibleTableWidget(m_cpuPage);
    m_cpuDetailTable->setColumnCount(7);
    m_cpuDetailTable->setHorizontalHeaderLabels({
        QStringLiteral("逻辑处理器"),
        QStringLiteral("利用率(%)"),
        QStringLiteral("当前频率(MHz)"),
        QStringLiteral("最大频率(MHz)"),
        QStringLiteral("限频(MHz)"),
        QStringLiteral("温度"),
        QStringLiteral("电压")
        });
    m_cpuDetailTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_cpuDetailTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_cpuDetailTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_cpuDetailTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_cpuDetailTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_cpuDetailTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_cpuDetailTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_cpuDetailTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_cpuDetailTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_cpuDetailTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    m_cpuDetailTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    installHardwareAuditCopyMenu(m_cpuDetailTable);
    m_cpuLayout->addWidget(m_cpuDetailTable, 1);

    const int tabIndex = m_sideTabWidget->addTab(m_cpuPage, QStringLiteral("处理器"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_cpuPage, QStringLiteral("hardware.tab.cpu"), QStringLiteral("处理器"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("查看处理器型号、核心利用率、频率、温度和电压"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_cpuPage, QStringLiteral("hardware.tooltip.cpu"), QStringLiteral("查看处理器型号、核心利用率、频率、温度和电压"));
}

void HardwareDock::initializePowerTab()
{
    // 电源页拥有独立的 Windows 电源方案与受控 R0 CPU 调节逻辑。
    m_powerPage = new HardwarePowerPage(m_sideTabWidget);
    const int tabIndex = m_sideTabWidget->addTab(
        m_powerPage,
        QStringLiteral("电源"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget,
        m_powerPage,
        QStringLiteral("hardware.tab.power"),
        QStringLiteral("电源"));
    m_sideTabWidget->setTabToolTip(
        tabIndex,
        QStringLiteral("管理 Windows 电源方案与受控 CPU 功耗、Turbo 和 HWP 设置"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget,
        m_powerPage,
        QStringLiteral("hardware.tooltip.power"),
        QStringLiteral("管理 Windows 电源方案与受控 CPU 功耗、Turbo 和 HWP 设置"));
}

void HardwareDock::initializeR0EvidenceTab()
{
    // 底层硬件检查页：
    // - 输入：无，依赖 HardwareR0EvidencePage 内部通过 ArkDriverClient 访问驱动；
    // - 处理：把 CPU/MSR/IDT/GDT 只读证据作为硬件 Dock 的独立顶部页签；
    // - 返回：无，页面由 Qt 父子树托管。
    m_r0EvidencePage = new HardwareR0EvidencePage(m_sideTabWidget);
    const int tabIndex = m_sideTabWidget->addTab(
        m_r0EvidencePage,
        QStringLiteral("底层硬件检查"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_r0EvidencePage, QStringLiteral("hardware.tab.r0_evidence"), QStringLiteral("底层硬件检查"));
    m_sideTabWidget->setTabToolTip(
        tabIndex,
        QStringLiteral("查看处理器寄存器与系统表的底层只读检查结果"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_r0EvidencePage, QStringLiteral("hardware.tooltip.r0_evidence"), QStringLiteral("查看处理器寄存器与系统表的底层只读检查结果"));
}

void HardwareDock::initializeGpuTab()
{
    m_gpuPage = new QWidget(m_sideTabWidget);
    m_gpuLayout = new QVBoxLayout(m_gpuPage);
    m_gpuLayout->setContentsMargins(4, 4, 4, 4);
    m_gpuLayout->setSpacing(6);

    m_gpuEditor = new CodeEditorWidget(m_gpuPage);
    m_gpuEditor->setReadOnly(true);
    m_gpuLayout->addWidget(m_gpuEditor, 1);

    const int tabIndex = m_sideTabWidget->addTab(m_gpuPage, QStringLiteral("显卡"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_gpuPage, QStringLiteral("hardware.tab.gpu"), QStringLiteral("显卡"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("查看显卡型号、显存与驱动信息"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_gpuPage, QStringLiteral("hardware.tooltip.gpu"), QStringLiteral("查看显卡型号、显存与驱动信息"));
}

void HardwareDock::initializeMemoryTab()
{
    m_memoryPage = new QWidget(m_sideTabWidget);
    m_memoryLayout = new QVBoxLayout(m_memoryPage);
    m_memoryLayout->setContentsMargins(4, 4, 4, 4);
    m_memoryLayout->setSpacing(6);

    m_memoryEditor = new CodeEditorWidget(m_memoryPage);
    m_memoryEditor->setReadOnly(true);
    m_memoryLayout->addWidget(m_memoryEditor, 1);

    const int tabIndex = m_sideTabWidget->addTab(m_memoryPage, QStringLiteral("内存"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_memoryPage, QStringLiteral("hardware.tab.memory"), QStringLiteral("内存"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("查看内存容量、模组与使用情况"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_memoryPage, QStringLiteral("hardware.tooltip.memory"), QStringLiteral("查看内存容量、模组与使用情况"));
}

void HardwareDock::initializeDiskMonitorTab()
{
    // 硬盘监控页包含 ETW 会话与全进程 IO 枚举，首次打开硬件 Dock 时只创建轻量宿主。
    m_diskMonitorHostPage = new QWidget(m_sideTabWidget);
    QVBoxLayout* hostLayout = new QVBoxLayout(m_diskMonitorHostPage);
    hostLayout->setContentsMargins(0, 0, 0, 0);
    hostLayout->setSpacing(0);
    hostLayout->addWidget(
        createHardwareDeferredPlaceholder(
            m_diskMonitorHostPage,
            QStringLiteral("硬盘监控待加载"),
            QStringLiteral("切换到本页后再启动文件 ETW 与进程 IO 采样，避免拖慢硬件页首次打开。")),
        1);
    const int tabIndex = m_sideTabWidget->addTab(m_diskMonitorHostPage, QStringLiteral("磁盘活动"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_diskMonitorHostPage, QStringLiteral("hardware.tab.disk_activity"), QStringLiteral("磁盘活动"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("查看文件访问与进程磁盘读写活动"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_diskMonitorHostPage, QStringLiteral("hardware.tooltip.disk_activity"), QStringLiteral("查看文件访问与进程磁盘读写活动"));
}

void HardwareDock::initializeDeviceManagerTab()
{
    // 设备管理页：
    // - 输入：无，内部使用 SetupAPI/CfgMgr 异步枚举 PnP 设备；
    // - 处理：直接创建页面，页面自身控制后台刷新和搜索；
    // - 返回：无，作为硬件 Dock 的独立 Tab 呈现。
    m_deviceManagerPage = new HardwareDeviceManagerPage(m_sideTabWidget);
    const int tabIndex = m_sideTabWidget->addTab(m_deviceManagerPage, QStringLiteral("设备管理"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_deviceManagerPage, QStringLiteral("hardware.tab.device_manager"), QStringLiteral("设备管理"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("搜索、查看和管理 Windows 设备"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_deviceManagerPage, QStringLiteral("hardware.tooltip.device_manager"), QStringLiteral("搜索、查看和管理 Windows 设备"));
}

void HardwareDock::initializeHwidDispatchTab()
{
    // initializeHwidDispatchTab：
    // - 输入：无，依赖 m_sideTabWidget；
    // - 处理：新增 EASY-HWID-SPOOFER Dispatch-only 集成页；
    // - 返回：无返回值，页面由 Qt 父子树释放。
    m_hwidDispatchPage = new HardwareHwidDispatchPage(m_sideTabWidget);
    const int tabIndex = m_sideTabWidget->addTab(m_hwidDispatchPage, QStringLiteral("硬件标识设置"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_hwidDispatchPage, QStringLiteral("hardware.tab.hwid"), QStringLiteral("硬件标识设置"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("查看和调整支持的磁盘与网络硬件标识"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_hwidDispatchPage, QStringLiteral("hardware.tooltip.hwid"), QStringLiteral("查看和调整支持的磁盘与网络硬件标识"));
}

void HardwareDock::initializeOtherDevicesTab()
{
    // 其他设备页会拉取硬件/PNP/驱动清单，首次打开硬件 Dock 时先用占位页占住 Tab。
    m_otherDevicesHostPage = new QWidget(m_sideTabWidget);
    QVBoxLayout* hostLayout = new QVBoxLayout(m_otherDevicesHostPage);
    hostLayout->setContentsMargins(0, 0, 0, 0);
    hostLayout->setSpacing(0);
    hostLayout->addWidget(
        createHardwareDeferredPlaceholder(
            m_otherDevicesHostPage,
            QStringLiteral("其他设备待加载"),
            QStringLiteral("切换到本页后再异步枚举设备清单，减少硬件 Dock 初次点击耗时。")),
        1);
    const int tabIndex = m_sideTabWidget->addTab(m_otherDevicesHostPage, QStringLiteral("其他设备"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_otherDevicesHostPage, QStringLiteral("hardware.tab.other_devices"), QStringLiteral("其他设备"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("查看处理器、内存和显卡之外的硬件清单"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_otherDevicesHostPage, QStringLiteral("hardware.tooltip.other_devices"), QStringLiteral("查看处理器、内存和显卡之外的硬件清单"));
}

void HardwareDock::initializeDeviceStackTab()
{
    m_deviceStackPage = createDeviceAuditPage(
        m_sideTabWidget,
        QStringLiteral("设备节点与驱动链"),
        QStringLiteral("对比系统设备记录与内核设备栈，帮助发现异常关联；本页为只读。"),
        &m_deviceStackEditor,
        &m_deviceStackTable);
    const int tabIndex = m_sideTabWidget->addTab(m_deviceStackPage, QStringLiteral("设备驱动链"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_deviceStackPage, QStringLiteral("hardware.tab.device_stack"), QStringLiteral("设备驱动链"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("检查设备节点、驱动对象与附加驱动关系"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_deviceStackPage, QStringLiteral("hardware.tooltip.device_stack"), QStringLiteral("检查设备节点、驱动对象与附加驱动关系"));
}

void HardwareDock::initializeKeyboardMouseHidTab()
{
    m_keyboardMouseHidPage = createDeviceAuditPage(
        m_sideTabWidget,
        QStringLiteral("键盘、鼠标与其他输入设备"),
        QStringLiteral("只读审计：键盘、鼠标、HID 与输入设备状态，默认不做消息截获与输入抓取。"),
        &m_keyboardMouseHidEditor,
        &m_keyboardMouseHidTable);
    const int tabIndex = m_sideTabWidget->addTab(m_keyboardMouseHidPage, QStringLiteral("键盘与鼠标"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_keyboardMouseHidPage, QStringLiteral("hardware.tab.keyboard_mouse"), QStringLiteral("键盘与鼠标"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("检查键盘、鼠标与其他输入设备状态"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_keyboardMouseHidPage, QStringLiteral("hardware.tooltip.keyboard_mouse"), QStringLiteral("检查键盘、鼠标与其他输入设备状态"));
}

void HardwareDock::initializeI8042AuditTab()
{
    m_i8042AuditPage = new HardwareI8042AuditPage(m_sideTabWidget);
    const int tabIndex = m_sideTabWidget->addTab(
        m_i8042AuditPage,
        QStringLiteral("i8042prt 审计"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget,
        m_i8042AuditPage,
        QStringLiteral("hardware.tab.i8042_audit"),
        QStringLiteral("i8042prt 审计"));
    m_sideTabWidget->setTabToolTip(
        tabIndex,
        QStringLiteral("精确验证 i8042prt 映像描述符、键鼠端点归属与设备栈关系"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget,
        m_i8042AuditPage,
        QStringLiteral("hardware.tooltip.i8042_audit"),
        QStringLiteral("精确验证 i8042prt 映像描述符、键鼠端点归属与设备栈关系"));
}

void HardwareDock::initializeUsbTopologyTab()
{
    m_usbTopologyPage = createDeviceAuditPage(
        m_sideTabWidget,
        QStringLiteral("USB 设备关系"),
        QStringLiteral("只读审计：USB 拓扑、控制器、Hub、端口与设备树关系。"),
        &m_usbTopologyEditor,
        &m_usbTopologyTable);
    const int tabIndex = m_sideTabWidget->addTab(m_usbTopologyPage, QStringLiteral("USB 设备"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_usbTopologyPage, QStringLiteral("hardware.tab.usb"), QStringLiteral("USB 设备"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("检查 USB 控制器、集线器、端口与设备关系"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_usbTopologyPage, QStringLiteral("hardware.tooltip.usb"), QStringLiteral("检查 USB 控制器、集线器、端口与设备关系"));
}

void HardwareDock::initializePnpAcpiPciTab()
{
    m_pnpAcpiPciPage = createReadOnlyTextPage(
        m_sideTabWidget,
        QStringLiteral("即插即用与系统总线"),
        QStringLiteral("只读审计：PnP、ACPI、PCI、DevNode 状态与 cross-view 风险标记。"),
        &m_pnpAcpiPciEditor);
    const int tabIndex = m_sideTabWidget->addTab(m_pnpAcpiPciPage, QStringLiteral("系统总线"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_sideTabWidget, m_pnpAcpiPciPage, QStringLiteral("hardware.tab.system_bus"), QStringLiteral("系统总线"));
    m_sideTabWidget->setTabToolTip(tabIndex, QStringLiteral("查看即插即用、电源管理与 PCI 总线设备状态"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        m_sideTabWidget, m_pnpAcpiPciPage, QStringLiteral("hardware.tooltip.system_bus"), QStringLiteral("查看即插即用、电源管理与 PCI 总线设备状态"));
}

void HardwareDock::ensureDiskMonitorTabInitialized()
{
    if (m_diskMonitorPage != nullptr || m_diskMonitorHostPage == nullptr)
    {
        return;
    }

    QVBoxLayout* hostLayout = qobject_cast<QVBoxLayout*>(m_diskMonitorHostPage->layout());
    if (hostLayout == nullptr)
    {
        hostLayout = new QVBoxLayout(m_diskMonitorHostPage);
        hostLayout->setContentsMargins(0, 0, 0, 0);
        hostLayout->setSpacing(0);
    }

    // 清理占位控件：真实页面会接管整个宿主区域，旧 QWidget 交给事件循环释放。
    while (QLayoutItem* itemPointer = hostLayout->takeAt(0))
    {
        QWidget* itemWidget = itemPointer->widget();
        if (itemWidget != nullptr)
        {
            itemWidget->deleteLater();
        }
        delete itemPointer;
    }

    m_diskMonitorPage = new DiskMonitorPage(m_diskMonitorHostPage);
    hostLayout->addWidget(m_diskMonitorPage, 1);
}

void HardwareDock::ensureOtherDevicesTabInitialized()
{
    if (m_otherDevicesPage != nullptr || m_otherDevicesHostPage == nullptr)
    {
        return;
    }

    QVBoxLayout* hostLayout = qobject_cast<QVBoxLayout*>(m_otherDevicesHostPage->layout());
    if (hostLayout == nullptr)
    {
        hostLayout = new QVBoxLayout(m_otherDevicesHostPage);
        hostLayout->setContentsMargins(0, 0, 0, 0);
        hostLayout->setSpacing(0);
    }

    // 清理占位控件：设备清单页内部会自行异步刷新，宿主只负责承载真实页面。
    while (QLayoutItem* itemPointer = hostLayout->takeAt(0))
    {
        QWidget* itemWidget = itemPointer->widget();
        if (itemWidget != nullptr)
        {
            itemWidget->deleteLater();
        }
        delete itemPointer;
    }

    m_otherDevicesPage = new HardwareOtherDevicesPage(m_otherDevicesHostPage);
    hostLayout->addWidget(m_otherDevicesPage, 1);
}

void HardwareDock::initializeCoreCharts()
{
    if (m_coreChartGridLayout == nullptr || m_coreChartHostWidget == nullptr)
    {
        return;
    }

    // 清空首帧占位或旧核心图：本函数负责把 CPU 核心图区域替换为真实 QChartView 网格。
    while (QLayoutItem* itemPointer = m_coreChartGridLayout->takeAt(0))
    {
        QWidget* itemWidget = itemPointer->widget();
        if (itemWidget != nullptr)
        {
            itemWidget->deleteLater();
        }
        delete itemPointer;
    }

    const DWORD logicalProcessorCount = std::max<DWORD>(1, ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    const int coreCount = static_cast<int>(logicalProcessorCount);
    const CpuCoreGridShape gridShape = chooseCpuCoreGridShape(coreCount);
    m_cpuCoreGridColumnCount = gridShape.columnCount;
    m_cpuCoreGridRowCount = gridShape.rowCount;

    m_coreChartEntries.clear();
    m_coreChartEntries.reserve(coreCount);

    for (int coreIndex = 0; coreIndex < coreCount; ++coreIndex)
    {
        CoreChartEntry chartEntry;
        chartEntry.containerWidget = new QWidget(m_coreChartHostWidget);
        configureCompressibleWidget(chartEntry.containerWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
        appendTransparentBackgroundStyle(chartEntry.containerWidget);
        QVBoxLayout* containerLayout = new QVBoxLayout(chartEntry.containerWidget);
        containerLayout->setContentsMargins(
            kCpuCoreChartCellMarginPx,
            kCpuCoreChartCellMarginPx,
            kCpuCoreChartCellMarginPx,
            kCpuCoreChartCellMarginPx);
        containerLayout->setSpacing(kCpuCoreChartInnerSpacingPx);

        chartEntry.titleLabel = new QLabel(
            QStringLiteral("CPU %1").arg(coreIndex),
            chartEntry.containerWidget);
        configureCompressibleLabel(chartEntry.titleLabel);
        chartEntry.titleLabel->setStyleSheet(
            QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
        chartEntry.titleLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        containerLayout->addWidget(chartEntry.titleLabel, 0);

        chartEntry.lineSeries = new QLineSeries(chartEntry.containerWidget);
        chartEntry.lineSeries->setColor(
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Cpu));
        chartEntry.baselineSeries = new QLineSeries(chartEntry.containerWidget);
        for (int indexValue = 0; indexValue < m_historyLength; ++indexValue)
        {
            chartEntry.lineSeries->append(indexValue, 0.0);
            chartEntry.baselineSeries->append(indexValue, 0.0);
        }

        QChart* chart = new QChart();
        chartEntry.areaSeries = new QAreaSeries(chartEntry.lineSeries, chartEntry.baselineSeries);
        const QColor cpuChartColor =
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Cpu);
        chartEntry.areaSeries->setColor(KswordTheme::WithAlpha(cpuChartColor, 46));
        chartEntry.areaSeries->setBorderColor(cpuChartColor);
        chartEntry.areaSeries->setPen(QPen(cpuChartColor, 1.6));
        chart->addSeries(chartEntry.areaSeries);
        chart->legend()->hide();
        chart->setBackgroundVisible(false);
        chart->setBackgroundRoundness(0);
        chart->setMargins(QMargins(0, 0, 0, 0));
        chart->setPlotAreaBackgroundVisible(true);
        chart->setPlotAreaBackgroundBrush(QBrush(KswordTheme::WithAlpha(cpuChartColor, 18)));
        chart->setPlotAreaBackgroundPen(QPen(KswordTheme::WithAlpha(cpuChartColor, 150), 1.0));

        chartEntry.axisX = new QValueAxis(chart);
        chartEntry.axisX->setRange(0, m_historyLength - 1);
        chartEntry.axisX->setLabelsVisible(false);
        chartEntry.axisX->setGridLineVisible(true);
        chartEntry.axisX->setMinorGridLineVisible(false);
        chartEntry.axisX->setLineVisible(true);
        chartEntry.axisX->setLinePen(QPen(KswordTheme::WithAlpha(cpuChartColor, 140), 1.0));
        chartEntry.axisX->setGridLinePen(QPen(KswordTheme::WithAlpha(cpuChartColor, 46), 1.0));

        chartEntry.axisY = new QValueAxis(chart);
        chartEntry.axisY->setRange(0.0, 100.0);
        chartEntry.axisY->setLabelsVisible(false);
        chartEntry.axisY->setGridLineVisible(true);
        chartEntry.axisY->setMinorGridLineVisible(false);
        chartEntry.axisY->setLineVisible(true);
        chartEntry.axisY->setLinePen(QPen(KswordTheme::WithAlpha(cpuChartColor, 140), 1.0));
        chartEntry.axisY->setGridLinePen(QPen(KswordTheme::WithAlpha(cpuChartColor, 46), 1.0));

        chart->addAxis(chartEntry.axisX, Qt::AlignBottom);
        chart->addAxis(chartEntry.axisY, Qt::AlignLeft);
        chartEntry.areaSeries->attachAxis(chartEntry.axisX);
        chartEntry.areaSeries->attachAxis(chartEntry.axisY);

        chartEntry.chartView = createPlotBackgroundChartView(chart, chartEntry.containerWidget);
        containerLayout->addWidget(chartEntry.chartView, 1);

        const int rowIndex = coreIndex / gridShape.columnCount;
        const int columnIndex = coreIndex % gridShape.columnCount;
        m_coreChartGridLayout->addWidget(chartEntry.containerWidget, rowIndex, columnIndex);
        m_coreChartEntries.push_back(chartEntry);
    }

    adjustUtilizationChartHeights();
}

void HardwareDock::initializeConnections()
{
    // 暂无额外交互按钮，预留函数用于后续扩展。
}

void HardwareDock::scheduleUtilizationLayoutRefresh()
{
    // 当前事件循环先重排一次，确保新追加设备卡片能立即拿到稳定尺寸。
    adjustUtilizationChartHeights();
    // 0ms 延迟用于等待 QListWidget 插入行后完成 viewport 尺寸更新。
    QTimer::singleShot(0, this, [this]()
    {
        adjustUtilizationChartHeights();
    });
    // 80ms 延迟用于 ADS Dock 动画或首次显示链路完成后再校准一次。
    QTimer::singleShot(80, this, [this]()
    {
        adjustUtilizationChartHeights();
    });
}

int HardwareDock::findDiskUtilizationDeviceIndexByInstance(const QString& instanceNameText) const
{
    for (int indexValue = 0; indexValue < static_cast<int>(m_diskUtilDevices.size()); ++indexValue)
    {
        const DiskUtilizationDevice& device = m_diskUtilDevices[static_cast<std::size_t>(indexValue)];
        if (QString::compare(device.instanceNameText, instanceNameText, Qt::CaseInsensitive) == 0)
        {
            return indexValue;
        }
    }
    return -1;
}

int HardwareDock::ensureDiskUtilizationDevice(
    const DiskRateSample& sample,
    const int ordinalIndex)
{
    const int existingIndex = findDiskUtilizationDeviceIndexByInstance(sample.instanceNameText);
    if (existingIndex >= 0)
    {
        return existingIndex;
    }

    // device 用途：为新发现的物理磁盘实例保留 UI 控件和历史采样。
    DiskUtilizationDevice device;
    device.instanceNameText = sample.instanceNameText;
    const bool useDefaultDisplayName = sample.displayNameText.isEmpty();
    device.displayNameText = useDefaultDisplayName
        ? QStringLiteral("磁盘 %1").arg(ordinalIndex)
        : sample.displayNameText;
    if (useDefaultDisplayName)
    {
        device.displayNameText = ks::i18n::contextText(
            QStringLiteral("hardware.utilization.card.disk.prefix"),
            QStringLiteral("磁盘")) + device.displayNameText.mid(QStringLiteral("磁盘").size());
    }
    createDiskUtilizationDevicePage(&device);
    m_diskUtilDevices.push_back(device);

    const int deviceIndex = static_cast<int>(m_diskUtilDevices.size()) - 1;
    m_diskUtilDevices[static_cast<std::size_t>(deviceIndex)].navCard = addUtilizationSidebarCard(
        m_diskUtilDevices[static_cast<std::size_t>(deviceIndex)].pageWidget,
        m_diskUtilDevices[static_cast<std::size_t>(deviceIndex)].displayNameText,
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Disk),
        UtilizationDeviceKind::Disk,
        deviceIndex);
    if (m_diskUtilDevices[static_cast<std::size_t>(deviceIndex)].navCard != nullptr)
    {
        m_diskUtilDevices[static_cast<std::size_t>(deviceIndex)].navCard->setSeriesColors(
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Read),
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Write));
    }
    scheduleUtilizationLayoutRefresh();
    return deviceIndex;
}

int HardwareDock::findNetworkUtilizationDeviceIndexByKey(const std::uint64_t interfaceKey) const
{
    for (int indexValue = 0; indexValue < static_cast<int>(m_networkUtilDevices.size()); ++indexValue)
    {
        const NetworkUtilizationDevice& device = m_networkUtilDevices[static_cast<std::size_t>(indexValue)];
        if (device.interfaceKey == interfaceKey)
        {
            return indexValue;
        }
    }
    return -1;
}

int HardwareDock::ensureNetworkUtilizationDevice(
    const NetworkRateSample& sample,
    const int ordinalIndex)
{
    const int existingIndex = findNetworkUtilizationDeviceIndexByKey(sample.interfaceKey);
    if (existingIndex >= 0)
    {
        return existingIndex;
    }

    // device 用途：为新发现的网卡接口保留 UI 控件和增量采样基线。
    NetworkUtilizationDevice device;
    device.interfaceKey = sample.interfaceKey;
    const bool useDefaultDisplayName = sample.displayNameText.isEmpty();
    device.displayNameText = useDefaultDisplayName
        ? QStringLiteral("以太网 %1").arg(ordinalIndex)
        : sample.displayNameText;
    if (useDefaultDisplayName)
    {
        device.displayNameText = ks::i18n::contextText(
            QStringLiteral("hardware.utilization.card.network.prefix"),
            QStringLiteral("以太网")) + device.displayNameText.mid(QStringLiteral("以太网").size());
    }
    device.linkBitsPerSecond = sample.linkBitsPerSecond;
    device.lastRxBytes = sample.totalRxBytes;
    device.lastTxBytes = sample.totalTxBytes;
    device.lastSampleMs = QDateTime::currentMSecsSinceEpoch();
    device.hasPreviousSample = true;
    createNetworkUtilizationDevicePage(&device);
    m_networkUtilDevices.push_back(device);

    const int deviceIndex = static_cast<int>(m_networkUtilDevices.size()) - 1;
    m_networkUtilDevices[static_cast<std::size_t>(deviceIndex)].navCard = addUtilizationSidebarCard(
        m_networkUtilDevices[static_cast<std::size_t>(deviceIndex)].pageWidget,
        m_networkUtilDevices[static_cast<std::size_t>(deviceIndex)].displayNameText,
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Network),
        UtilizationDeviceKind::Network,
        deviceIndex);
    if (m_networkUtilDevices[static_cast<std::size_t>(deviceIndex)].navCard != nullptr)
    {
        m_networkUtilDevices[static_cast<std::size_t>(deviceIndex)].navCard->setSeriesColors(
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Read),
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Write));
    }
    scheduleUtilizationLayoutRefresh();
    return deviceIndex;
}

int HardwareDock::findGpuUtilizationDeviceIndexByKey(const std::uint64_t adapterKey) const
{
    for (int indexValue = 0; indexValue < static_cast<int>(m_gpuUtilDevices.size()); ++indexValue)
    {
        const GpuUtilizationDevice& device = m_gpuUtilDevices[static_cast<std::size_t>(indexValue)];
        if (device.adapterKeyAssigned && device.adapterKey == adapterKey)
        {
            return indexValue;
        }
    }
    return -1;
}

int HardwareDock::ensureGpuUtilizationDevice(
    const GpuUsageSample& sample,
    const int ordinalIndex)
{
    const int existingIndex = findGpuUtilizationDeviceIndexByKey(sample.adapterKey);
    if (existingIndex >= 0)
    {
        return existingIndex;
    }

    // device 用途：为新发现的 DXGI 适配器保留任务管理器风格 GPU 详情页。
    GpuUtilizationDevice device;
    device.adapterKey = sample.adapterKey;
    device.adapterKeyAssigned = true;
    device.adapterIndex = sample.adapterIndex;
    device.displayNameText = ks::i18n::contextText(
        QStringLiteral("hardware.utilization.card.gpu.prefix"),
        QStringLiteral("GPU"))
        + QStringLiteral(" %1").arg(ordinalIndex);
    createGpuUtilizationDevicePage(&device);
    m_gpuUtilDevices.push_back(device);

    const int deviceIndex = static_cast<int>(m_gpuUtilDevices.size()) - 1;
    m_gpuUtilDevices[static_cast<std::size_t>(deviceIndex)].navCard = addUtilizationSidebarCard(
        m_gpuUtilDevices[static_cast<std::size_t>(deviceIndex)].pageWidget,
        m_gpuUtilDevices[static_cast<std::size_t>(deviceIndex)].displayNameText,
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Gpu),
        UtilizationDeviceKind::Gpu,
        deviceIndex);
    scheduleUtilizationLayoutRefresh();
    return deviceIndex;
}

void HardwareDock::createDiskUtilizationDevicePage(DiskUtilizationDevice* devicePointer)
{
    if (devicePointer == nullptr || m_utilizationDetailStack == nullptr)
    {
        return;
    }

    devicePointer->pageWidget = new QWidget(m_utilizationDetailStack);
    configureCompressibleWidget(devicePointer->pageWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(devicePointer->pageWidget);
    QVBoxLayout* pageLayout = new QVBoxLayout(devicePointer->pageWidget);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(devicePointer->displayNameText, devicePointer->pageWidget);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    pageLayout->addWidget(titleLabel, 0);

    devicePointer->summaryLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.device.disk.sampling"),
            QStringLiteral("磁盘采样初始化中...")),
        devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->summaryLabel);
    devicePointer->summaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    pageLayout->addWidget(devicePointer->summaryLabel, 0);

    devicePointer->readLineSeries = new QLineSeries(devicePointer->pageWidget);
    devicePointer->readLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.disk.read"), QStringLiteral("读取")));
    const QColor readColor(80, 170, 255);
    const QColor writeColor(255, 190, 105);
    devicePointer->readLineSeries->setColor(readColor);
    devicePointer->readBaselineSeries = createBaselineSeries(devicePointer->pageWidget, m_historyLength);
    devicePointer->writeLineSeries = new QLineSeries(devicePointer->pageWidget);
    devicePointer->writeLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.disk.write"), QStringLiteral("写入")));
    devicePointer->writeLineSeries->setColor(writeColor);
    devicePointer->writeBaselineSeries = createBaselineSeries(devicePointer->pageWidget, m_historyLength);
    initializeLineSeriesHistory(devicePointer->readLineSeries, m_historyLength);
    initializeLineSeriesHistory(devicePointer->writeLineSeries, m_historyLength);

    QChart* chart = new QChart();
    devicePointer->readAreaSeries = addFilledAreaSeries(
        chart,
        devicePointer->readLineSeries,
        devicePointer->readBaselineSeries,
        readColor,
        42);
    devicePointer->writeAreaSeries = addFilledAreaSeries(
        chart,
        devicePointer->writeLineSeries,
        devicePointer->writeBaselineSeries,
        writeColor,
        34);
    configureUtilizationPlotChart(
        chart,
        readColor,
        QStringLiteral("%1 %2")
            .arg(devicePointer->displayNameText)
            .arg(ks::i18n::contextText(
                QStringLiteral("hardware.utilization.disk.rate_suffix"),
                QStringLiteral("读写速率趋势"))),
        true);
    devicePointer->axisX = new QValueAxis(chart);
    configureUtilizationValueAxis(devicePointer->axisX, readColor, 0.0, static_cast<double>(m_historyLength));
    devicePointer->axisY = new QValueAxis(chart);
    configureUtilizationValueAxis(devicePointer->axisY, readColor, 0.0, 1.0);
    chart->addAxis(devicePointer->axisX, Qt::AlignBottom);
    chart->addAxis(devicePointer->axisY, Qt::AlignLeft);
    if (devicePointer->readAreaSeries != nullptr)
    {
        devicePointer->readAreaSeries->attachAxis(devicePointer->axisX);
        devicePointer->readAreaSeries->attachAxis(devicePointer->axisY);
    }
    if (devicePointer->writeAreaSeries != nullptr)
    {
        devicePointer->writeAreaSeries->attachAxis(devicePointer->axisX);
        devicePointer->writeAreaSeries->attachAxis(devicePointer->axisY);
    }
    devicePointer->chartView = createPlotBackgroundChartView(chart, devicePointer->pageWidget);
    pageLayout->addWidget(devicePointer->chartView, 1);

    devicePointer->detailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.device.disk.detail_sampling"),
            QStringLiteral("磁盘参数采样中...")),
        devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->detailLabel);
    devicePointer->detailLabel->setWordWrap(false);
    devicePointer->detailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    pageLayout->addWidget(devicePointer->detailLabel, 0);

    m_utilizationDetailStack->addWidget(devicePointer->pageWidget);
}

void HardwareDock::createNetworkUtilizationDevicePage(NetworkUtilizationDevice* devicePointer)
{
    if (devicePointer == nullptr || m_utilizationDetailStack == nullptr)
    {
        return;
    }

    devicePointer->pageWidget = new QWidget(m_utilizationDetailStack);
    configureCompressibleWidget(devicePointer->pageWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(devicePointer->pageWidget);
    QVBoxLayout* pageLayout = new QVBoxLayout(devicePointer->pageWidget);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(devicePointer->displayNameText, devicePointer->pageWidget);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    pageLayout->addWidget(titleLabel, 0);

    devicePointer->summaryLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.device.network.sampling"),
            QStringLiteral("网络采样初始化中...")),
        devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->summaryLabel);
    devicePointer->summaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    pageLayout->addWidget(devicePointer->summaryLabel, 0);

    devicePointer->rxLineSeries = new QLineSeries(devicePointer->pageWidget);
    devicePointer->rxLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.network.down"), QStringLiteral("下行")));
    const QColor rxColor(92, 190, 255);
    const QColor txColor(255, 190, 105);
    devicePointer->rxLineSeries->setColor(rxColor);
    devicePointer->rxBaselineSeries = createBaselineSeries(devicePointer->pageWidget, m_historyLength);
    devicePointer->txLineSeries = new QLineSeries(devicePointer->pageWidget);
    devicePointer->txLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.network.up"), QStringLiteral("上行")));
    devicePointer->txLineSeries->setColor(txColor);
    devicePointer->txBaselineSeries = createBaselineSeries(devicePointer->pageWidget, m_historyLength);
    initializeLineSeriesHistory(devicePointer->rxLineSeries, m_historyLength);
    initializeLineSeriesHistory(devicePointer->txLineSeries, m_historyLength);

    QChart* chart = new QChart();
    devicePointer->rxAreaSeries = addFilledAreaSeries(
        chart,
        devicePointer->rxLineSeries,
        devicePointer->rxBaselineSeries,
        rxColor,
        42);
    devicePointer->txAreaSeries = addFilledAreaSeries(
        chart,
        devicePointer->txLineSeries,
        devicePointer->txBaselineSeries,
        txColor,
        34);
    configureUtilizationPlotChart(
        chart,
        rxColor,
        QStringLiteral("%1 %2")
            .arg(devicePointer->displayNameText)
            .arg(ks::i18n::contextText(
                QStringLiteral("hardware.utilization.network.rate_suffix"),
                QStringLiteral("收发速率趋势"))),
        true);
    devicePointer->axisX = new QValueAxis(chart);
    configureUtilizationValueAxis(devicePointer->axisX, rxColor, 0.0, static_cast<double>(m_historyLength));
    devicePointer->axisY = new QValueAxis(chart);
    configureUtilizationValueAxis(devicePointer->axisY, rxColor, 0.0, 1.0);
    chart->addAxis(devicePointer->axisX, Qt::AlignBottom);
    chart->addAxis(devicePointer->axisY, Qt::AlignLeft);
    if (devicePointer->rxAreaSeries != nullptr)
    {
        devicePointer->rxAreaSeries->attachAxis(devicePointer->axisX);
        devicePointer->rxAreaSeries->attachAxis(devicePointer->axisY);
    }
    if (devicePointer->txAreaSeries != nullptr)
    {
        devicePointer->txAreaSeries->attachAxis(devicePointer->axisX);
        devicePointer->txAreaSeries->attachAxis(devicePointer->axisY);
    }
    devicePointer->chartView = createPlotBackgroundChartView(chart, devicePointer->pageWidget);
    pageLayout->addWidget(devicePointer->chartView, 1);

    devicePointer->detailLabel = new QLabel(QStringLiteral("网络参数采样中..."), devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->detailLabel);
    devicePointer->detailLabel->setWordWrap(false);
    devicePointer->detailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    pageLayout->addWidget(devicePointer->detailLabel, 0);

    m_utilizationDetailStack->addWidget(devicePointer->pageWidget);
}

void HardwareDock::createGpuUtilizationDevicePage(GpuUtilizationDevice* devicePointer)
{
    if (devicePointer == nullptr || m_utilizationDetailStack == nullptr)
    {
        return;
    }

    devicePointer->pageWidget = new QWidget(m_utilizationDetailStack);
    configureCompressibleWidget(devicePointer->pageWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(devicePointer->pageWidget);
    QVBoxLayout* pageLayout = new QVBoxLayout(devicePointer->pageWidget);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(devicePointer->displayNameText, devicePointer->pageWidget);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    devicePointer->adapterTitleLabel = new QLabel(QStringLiteral("适配器读取中..."), devicePointer->pageWidget);
    configurePersistentHeaderLabel(devicePointer->adapterTitleLabel, QSizePolicy::Ignored);
    devicePointer->adapterTitleLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    devicePointer->adapterTitleLabel->setStyleSheet(
        QStringLiteral("font-size:15px;font-weight:500;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(devicePointer->adapterTitleLabel, 6);
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(devicePointer->adapterTitleLabel, 0);
    pageLayout->addLayout(headerLayout, 0);

    devicePointer->summaryLabel = new QLabel(QStringLiteral("GPU采样初始化中..."), devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->summaryLabel);
    devicePointer->summaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    pageLayout->addWidget(devicePointer->summaryLabel, 0);

    devicePointer->engineHostWidget = new QWidget(devicePointer->pageWidget);
    configureCompressibleWidget(devicePointer->engineHostWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(devicePointer->engineHostWidget);
    devicePointer->engineGridLayout = new QGridLayout(devicePointer->engineHostWidget);
    devicePointer->engineGridLayout->setContentsMargins(0, 0, 0, 0);
    devicePointer->engineGridLayout->setHorizontalSpacing(6);
    devicePointer->engineGridLayout->setVerticalSpacing(6);
    devicePointer->engineCharts.clear();

    auto addEngineChart =
        [this, devicePointer](
            const QString& keyText,
            const QString& displayText,
            const QColor& lineColor,
            const int rowIndex,
            const int columnIndex)
        {
            QWidget* cellWidget = new QWidget(devicePointer->engineHostWidget);
            configureCompressibleWidget(cellWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
            appendTransparentBackgroundStyle(cellWidget);
            QVBoxLayout* cellLayout = new QVBoxLayout(cellWidget);
            cellLayout->setContentsMargins(3, 3, 3, 3);
            cellLayout->setSpacing(2);

            GpuEngineChartEntry chartEntry;
            chartEntry.engineKeyText = keyText;
            chartEntry.displayNameText = displayText;
            chartEntry.titleLabel = new QLabel(displayText, cellWidget);
            configureCompressibleLabel(chartEntry.titleLabel);
            chartEntry.titleLabel->setStyleSheet(
                QStringLiteral("font-size:12px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
            cellLayout->addWidget(chartEntry.titleLabel, 0);

            chartEntry.lineSeries = new QLineSeries(cellWidget);
            chartEntry.lineSeries->setColor(lineColor);
            chartEntry.baselineSeries = createBaselineSeries(cellWidget, m_historyLength);
            initializeLineSeriesHistory(chartEntry.lineSeries, m_historyLength);

            QChart* chart = new QChart();
            chartEntry.areaSeries = addFilledAreaSeries(
                chart,
                chartEntry.lineSeries,
                chartEntry.baselineSeries,
                lineColor,
                44);
            configureUtilizationPlotChart(chart, lineColor);
            chartEntry.axisX = new QValueAxis(chart);
            configureUtilizationValueAxis(chartEntry.axisX, lineColor, 0.0, static_cast<double>(m_historyLength));
            chartEntry.axisY = new QValueAxis(chart);
            configureUtilizationValueAxis(chartEntry.axisY, lineColor, 0.0, 100.0);
            chart->addAxis(chartEntry.axisX, Qt::AlignBottom);
            chart->addAxis(chartEntry.axisY, Qt::AlignLeft);
            if (chartEntry.areaSeries != nullptr)
            {
                chartEntry.areaSeries->attachAxis(chartEntry.axisX);
                chartEntry.areaSeries->attachAxis(chartEntry.axisY);
            }
            chartEntry.chartView = createPlotBackgroundChartView(chart, cellWidget);
            cellLayout->addWidget(chartEntry.chartView, 1);

            devicePointer->engineGridLayout->addWidget(cellWidget, rowIndex, columnIndex);
            devicePointer->engineCharts.push_back(chartEntry);
        };

    addEngineChart(
        QStringLiteral("3d"), QStringLiteral("3D"),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Gpu), 0, 0);
    addEngineChart(
        QStringLiteral("copy"), QStringLiteral("Copy"),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Copy), 0, 1);
    addEngineChart(
        QStringLiteral("video_encode"), QStringLiteral("Video Encode"),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::VideoEncode), 1, 0);
    addEngineChart(
        QStringLiteral("video_decode"), QStringLiteral("Video Decode"),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::VideoDecode), 1, 1);
    pageLayout->addWidget(devicePointer->engineHostWidget, 1);

    auto createMemoryChart =
        [this, devicePointer](
            const QString& titleText,
            QLineSeries** seriesOut,
            QLineSeries** baselineSeriesOut,
            QAreaSeries** areaSeriesOut,
            const QColor& lineColor,
            QValueAxis** axisXOut,
            QValueAxis** axisYOut,
            QChartView** chartViewOut)
        {
            *seriesOut = new QLineSeries(devicePointer->pageWidget);
            (*seriesOut)->setColor(lineColor);
            *baselineSeriesOut = createBaselineSeries(devicePointer->pageWidget, m_historyLength);
            initializeLineSeriesHistory(*seriesOut, m_historyLength);

            QChart* chart = new QChart();
            *areaSeriesOut = addFilledAreaSeries(
                chart,
                *seriesOut,
                *baselineSeriesOut,
                lineColor,
                42);
            configureUtilizationPlotChart(chart, lineColor, titleText);
            *axisXOut = new QValueAxis(chart);
            configureUtilizationValueAxis(*axisXOut, lineColor, 0.0, static_cast<double>(m_historyLength));
            *axisYOut = new QValueAxis(chart);
            configureUtilizationValueAxis(*axisYOut, lineColor, 0.0, 1.0);
            chart->addAxis(*axisXOut, Qt::AlignBottom);
            chart->addAxis(*axisYOut, Qt::AlignLeft);
            if (*areaSeriesOut != nullptr)
            {
                (*areaSeriesOut)->attachAxis(*axisXOut);
                (*areaSeriesOut)->attachAxis(*axisYOut);
            }
            *chartViewOut = createPlotBackgroundChartView(chart, devicePointer->pageWidget);
        };

    createMemoryChart(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.gpu.dedicated_memory_label"),
            QStringLiteral("专用 GPU 内存利用率")),
        &devicePointer->dedicatedMemoryLineSeries,
        &devicePointer->dedicatedMemoryBaselineSeries,
        &devicePointer->dedicatedMemoryAreaSeries,
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::DedicatedMemory),
        &devicePointer->dedicatedMemoryAxisX,
        &devicePointer->dedicatedMemoryAxisY,
        &devicePointer->dedicatedMemoryChartView);
    createMemoryChart(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.gpu.shared_memory_label"),
            QStringLiteral("共享 GPU 内存利用率")),
        &devicePointer->sharedMemoryLineSeries,
        &devicePointer->sharedMemoryBaselineSeries,
        &devicePointer->sharedMemoryAreaSeries,
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::SharedMemory),
        &devicePointer->sharedMemoryAxisX,
        &devicePointer->sharedMemoryAxisY,
        &devicePointer->sharedMemoryChartView);
    pageLayout->addWidget(devicePointer->dedicatedMemoryChartView, 0);
    pageLayout->addWidget(devicePointer->sharedMemoryChartView, 0);

    devicePointer->detailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.device.gpu.detail_sampling"),
            QStringLiteral("GPU参数采样中...")),
        devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->detailLabel);
    devicePointer->detailLabel->setWordWrap(false);
    devicePointer->detailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    pageLayout->addWidget(devicePointer->detailLabel, 0);

    m_utilizationDetailStack->addWidget(devicePointer->pageWidget);
}

void HardwareDock::refreshCpuTopologyStaticInfo()
{
    if (m_cpuModelText.isEmpty() || m_cpuModelText == QStringLiteral("N/A"))
    {
        m_cpuModelText = queryCpuBrandTextByCpuid();
    }
    if (m_cpuModelLabel != nullptr && !m_cpuModelText.isEmpty())
    {
        m_cpuModelLabel->setText(m_cpuModelText);
    }

    DWORD requiredBytes = 0;
    ::GetLogicalProcessorInformationEx(RelationAll, nullptr, &requiredBytes);
    if (requiredBytes == 0)
    {
        m_cpuLogicalCoreCount = static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        return;
    }

    std::vector<unsigned char> buffer(requiredBytes);
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* infoPointer =
        reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data());
    if (::GetLogicalProcessorInformationEx(RelationAll, infoPointer, &requiredBytes) == FALSE)
    {
        m_cpuLogicalCoreCount = static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        return;
    }

    int packageCount = 0;
    int physicalCoreCount = 0;
    int logicalCoreCount = 0;
    std::uint64_t l1Bytes = 0;
    std::uint64_t l2Bytes = 0;
    std::uint64_t l3Bytes = 0;

    DWORD offsetBytes = 0;
    while (offsetBytes < requiredBytes)
    {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* entryPointer =
            reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data() + offsetBytes);
        if (entryPointer->Relationship == RelationProcessorPackage)
        {
            ++packageCount;
        }
        else if (entryPointer->Relationship == RelationProcessorCore)
        {
            ++physicalCoreCount;
            for (WORD groupIndex = 0; groupIndex < entryPointer->Processor.GroupCount; ++groupIndex)
            {
                logicalCoreCount += countBits(entryPointer->Processor.GroupMask[groupIndex].Mask);
            }
        }
        else if (entryPointer->Relationship == RelationCache)
        {
            if (entryPointer->Cache.Level == 1)
            {
                l1Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
            else if (entryPointer->Cache.Level == 2)
            {
                l2Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
            else if (entryPointer->Cache.Level == 3)
            {
                l3Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
        }

        if (entryPointer->Size == 0)
        {
            break;
        }
        offsetBytes += entryPointer->Size;
    }

    m_cpuPackageCount = std::max(1, packageCount);
    m_cpuPhysicalCoreCount = std::max(1, physicalCoreCount);
    m_cpuLogicalCoreCount = logicalCoreCount > 0
        ? logicalCoreCount
        : static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    m_cpuL1CacheBytes = l1Bytes;
    m_cpuL2CacheBytes = l2Bytes;
    m_cpuL3CacheBytes = l3Bytes;
}

void HardwareDock::refreshSystemVolumeInfo()
{
    QString systemDrive = qEnvironmentVariable("SystemDrive");
    if (systemDrive.isEmpty())
    {
        systemDrive = QStringLiteral("C:");
    }

    QString rootPath = systemDrive;
    if (!rootPath.endsWith('\\'))
    {
        rootPath += QLatin1Char('\\');
    }

    ULARGE_INTEGER freeAvailableBytes{};
    ULARGE_INTEGER totalBytes{};
    ULARGE_INTEGER totalFreeBytes{};
    if (::GetDiskFreeSpaceExW(
        reinterpret_cast<LPCWSTR>(rootPath.utf16()),
        &freeAvailableBytes,
        &totalBytes,
        &totalFreeBytes) == TRUE)
    {
        m_systemVolumeTotalBytes = static_cast<std::uint64_t>(totalBytes.QuadPart);
        m_systemVolumeFreeBytes = static_cast<std::uint64_t>(totalFreeBytes.QuadPart);
    }

    wchar_t volumeNameBuffer[MAX_PATH] = {};
    if (::GetVolumeInformationW(
        reinterpret_cast<LPCWSTR>(rootPath.utf16()),
        volumeNameBuffer,
        MAX_PATH,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        0) == TRUE)
    {
        const QString volumeNameText = QString::fromWCharArray(volumeNameBuffer).trimmed();
        if (!volumeNameText.isEmpty())
        {
            m_systemVolumeText = QStringLiteral("%1 (%2)").arg(volumeNameText, systemDrive);
            return;
        }
    }

    m_systemVolumeText = rootPath;
}

void HardwareDock::initializePerformanceCounters()
{
    // 计数器初始化整体异步化：
    // - PdhOpenQueryW + 逐核 PdhAddEnglishCounterW + \Processor Information 首次触达合计上百毫秒；
    // - 原来只是延后到首帧之后，仍然压在 UI 线程；现在交给线程池，完成后回投接管句柄；
    // - 句柄就绪前 samplePerCoreUsage 直接返回 false，界面按 0 占位显示。
    if (m_cpuPerfQueryHandle != nullptr)
    {
        return;
    }

    // expectedInitializingValue 用途：CAS 期望值（false=当前没有初始化任务在跑）。
    bool expectedInitializingValue = false;
    if (!hardwareDockCpuCounterInitializing.compare_exchange_strong(expectedInitializingValue, true))
    {
        return;
    }

    // coreCount 必须在 UI 线程读取：m_coreChartEntries 保存的是图表控件。
    const int coreCount = static_cast<int>(m_coreChartEntries.size());

    // applicationContext 与事件循环同寿命；工作线程不解引用 Dock 指针。
    QObject* const applicationContext = QCoreApplication::instance();
    if (applicationContext == nullptr)
    {
        hardwareDockCpuCounterInitializing.store(false);
        return;
    }

    // safeThis 用途：后台任务可能晚于 Dock 销毁，回投后必须验证生命周期。
    const QPointer<HardwareDock> safeThis(this);
    QThreadPool::globalInstance()->start(
        [applicationContext, safeThis, coreCount]()
        {
            // 后台线程只做纯数据采集，产出可跨线程搬运的句柄值类型。
            const HardwareDockCpuCounterBundle counterBundle = createHardwareDockCpuCounters(coreCount);

            const bool invokeOk = QMetaObject::invokeMethod(
                applicationContext,
                [safeThis, counterBundle]()
                {
                    if (safeThis.isNull())
                    {
                        closeHardwareDockCpuCounters(counterBundle);
                        hardwareDockCpuCounterInitializing.store(false);
                        return;
                    }

                    if (counterBundle.cpuQueryHandle == nullptr)
                    {
                        kLogEvent event;
                        warn << event
                            << "[HardwareDock] 初始化PDH失败：PdhOpenQueryW, status="
                            << counterBundle.openQueryStatus
                            << eol;
                        hardwareDockCpuCounterInitializing.store(false);
                        return;
                    }

                    if (safeThis->m_cpuPerfQueryHandle != nullptr)
                    {
                        // 更早一轮初始化已经接管句柄，本轮结果直接释放避免泄漏。
                        closeHardwareDockCpuCounters(counterBundle);
                        hardwareDockCpuCounterInitializing.store(false);
                        return;
                    }

                    safeThis->m_cpuPerfQueryHandle = counterBundle.cpuQueryHandle;
                    safeThis->m_coreCounterHandles = counterBundle.coreCounterHandles;
                    safeThis->m_cpuPerformanceCounterHandle = counterBundle.cpuPerformanceCounterHandle;
                    safeThis->m_cpuFrequencyCounterHandle = counterBundle.cpuFrequencyCounterHandle;
                    hardwareDockCpuCounterInitializing.store(false);
                },
                Qt::QueuedConnection);

            if (!invokeOk)
            {
                closeHardwareDockCpuCounters(counterBundle);
                hardwareDockCpuCounterInitializing.store(false);
            }
        });
}

void HardwareDock::refreshAllViews()
{
    std::vector<double> coreUsageList;
    coreUsageList.reserve(m_coreChartEntries.size());
    double totalCpuUsage = 0.0;
    if (!samplePerCoreUsage(&coreUsageList, &totalCpuUsage))
    {
        coreUsageList.assign(m_coreChartEntries.size(), 0.0);
        totalCpuUsage = 0.0;
    }

    double memoryUsagePercent = 0.0;
    sampleMemoryUsage(&memoryUsagePercent);

    double diskReadBytesPerSec = 0.0;
    double diskWriteBytesPerSec = 0.0;
    double diskReadAverageBytesPerSec = 0.0;
    double diskWriteAverageBytesPerSec = 0.0;
    std::vector<DiskRateSample> diskSampleList;
    if (sampleDiskRates(&diskSampleList))
    {
        for (const DiskRateSample& sample : diskSampleList)
        {
            diskReadBytesPerSec += std::max(0.0, sample.readBytesPerSec);
            diskWriteBytesPerSec += std::max(0.0, sample.writeBytesPerSec);
        }
        if (!diskSampleList.empty())
        {
            const double diskCount = static_cast<double>(diskSampleList.size());
            diskReadAverageBytesPerSec = diskReadBytesPerSec / diskCount;
            diskWriteAverageBytesPerSec = diskWriteBytesPerSec / diskCount;
        }
    }
    else
    {
        diskReadBytesPerSec = 0.0;
        diskWriteBytesPerSec = 0.0;
    }

    double networkRxBytesPerSec = 0.0;
    double networkTxBytesPerSec = 0.0;
    double networkRxAverageBytesPerSec = 0.0;
    double networkTxAverageBytesPerSec = 0.0;
    std::vector<NetworkRateSample> networkSampleList;
    if (sampleNetworkRates(&networkSampleList))
    {
        for (const NetworkRateSample& sample : networkSampleList)
        {
            networkRxBytesPerSec += std::max(0.0, sample.rxBytesPerSec);
            networkTxBytesPerSec += std::max(0.0, sample.txBytesPerSec);
        }
        if (!networkSampleList.empty())
        {
            const double networkCount = static_cast<double>(networkSampleList.size());
            networkRxAverageBytesPerSec = networkRxBytesPerSec / networkCount;
            networkTxAverageBytesPerSec = networkTxBytesPerSec / networkCount;
        }
    }
    else
    {
        networkRxBytesPerSec = 0.0;
        networkTxBytesPerSec = 0.0;
    }

    double gpuUsagePercent = 0.0;
    double gpuUsageAveragePercent = 0.0;
    std::vector<GpuUsageSample> gpuSampleList;
    if (sampleGpuUsages(&gpuSampleList))
    {
        double gpuUsageSum = 0.0;
        for (const GpuUsageSample& sample : gpuSampleList)
        {
            gpuUsagePercent = std::max(gpuUsagePercent, sample.overallUsagePercent);
            gpuUsageSum += std::clamp(sample.overallUsagePercent, 0.0, 100.0);
        }
        if (!gpuSampleList.empty())
        {
            gpuUsageAveragePercent = gpuUsageSum / static_cast<double>(gpuSampleList.size());
        }
    }
    else
    {
        gpuUsagePercent = 0.0;
    }

    std::vector<CpuPowerSnapshot> powerInfoList;
    sampleCpuPowerInfo(&powerInfoList);
    double sampledCpuSpeedGhz = 0.0;
    m_lastCpuSpeedGhz = sampleCpuEffectiveSpeed(&sampledCpuSpeedGhz)
        ? sampledCpuSpeedGhz
        : 0.0;

    ++m_sampleCounter;
    pushBoundedHistorySample(&m_cpuUsageHistoryPercent, totalCpuUsage);
    pushBoundedHistorySample(&m_memoryUsageHistoryPercent, memoryUsagePercent);
    pushBoundedHistorySample(&m_gpuUsageHistoryPercent, gpuUsagePercent);
    pushBoundedHistorySample(
        &m_diskAggregateHistoryBytesPerSec,
        std::max(0.0, diskReadBytesPerSec) + std::max(0.0, diskWriteBytesPerSec));
    pushBoundedHistorySample(
        &m_networkAggregateHistoryBytesPerSec,
        std::max(0.0, networkRxBytesPerSec) + std::max(0.0, networkTxBytesPerSec));
    if (m_driverHealthSamplingEnabled)
    {
        requestAsyncR0HardwareHealthRefresh();
    }
    updateOverviewText(totalCpuUsage, memoryUsagePercent);
    updateUtilizationView(
        coreUsageList,
        memoryUsagePercent,
        diskReadBytesPerSec,
        diskWriteBytesPerSec,
        networkRxBytesPerSec,
        networkTxBytesPerSec,
        gpuUsagePercent);
    updateAdditionalDiskUtilizationDevices(diskSampleList);
    updateAdditionalNetworkUtilizationDevices(networkSampleList);
    updateAdditionalGpuUtilizationDevices(gpuSampleList);
    updateCpuDetailTable(coreUsageList, powerInfoList);
    updateTaskManagerDetailLabels(
        coreUsageList,
        powerInfoList,
        memoryUsagePercent,
        diskReadBytesPerSec,
        diskWriteBytesPerSec,
        networkRxBytesPerSec,
        networkTxBytesPerSec,
        gpuUsagePercent);
    emit performanceSnapshotChanged(
        totalCpuUsage,
        memoryUsagePercent,
        diskReadAverageBytesPerSec,
        diskWriteAverageBytesPerSec,
        networkRxAverageBytesPerSec,
        networkTxAverageBytesPerSec,
        gpuUsageAveragePercent);
    // 高度重排只在 resize/tab 切换时执行，避免每秒重算导致核心图容器抖动。

    // 周期刷新策略：
    // - 传感器每 5 秒异步更新一次；
    // - 静态文本每 60 秒异步更新一次（兼顾信息时效与系统开销）。
    if ((m_sampleCounter % 5) == 1)
    {
        requestAsyncSensorRefresh();
    }
    if ((m_sampleCounter % 60) == 1)
    {
        requestAsyncStaticInfoRefresh();
    }
}

bool HardwareDock::samplePerCoreUsage(
    std::vector<double>* coreUsageOut,
    double* totalUsageOut)
{
    if (coreUsageOut == nullptr || totalUsageOut == nullptr)
    {
        return false;
    }
    if (m_cpuPerfQueryHandle == nullptr)
    {
        initializePerformanceCounters();
    }
    if (m_cpuPerfQueryHandle == nullptr)
    {
        return false;
    }

    const PDH_HQUERY queryHandle = reinterpret_cast<PDH_HQUERY>(m_cpuPerfQueryHandle);
    const PDH_STATUS collectStatus = ::PdhCollectQueryData(queryHandle);
    if (collectStatus != ERROR_SUCCESS)
    {
        return false;
    }

    coreUsageOut->clear();
    coreUsageOut->reserve(m_coreCounterHandles.size());
    double usageSum = 0.0;
    int validCount = 0;

    for (void* counterHandleVoid : m_coreCounterHandles)
    {
        if (counterHandleVoid == nullptr)
        {
            coreUsageOut->push_back(0.0);
            continue;
        }

        PDH_FMT_COUNTERVALUE formattedValue{};
        const PDH_STATUS readStatus = ::PdhGetFormattedCounterValue(
            reinterpret_cast<PDH_HCOUNTER>(counterHandleVoid),
            PDH_FMT_DOUBLE,
            nullptr,
            &formattedValue);
        if (readStatus != ERROR_SUCCESS)
        {
            coreUsageOut->push_back(0.0);
            continue;
        }

        const double usageValue = std::clamp(formattedValue.doubleValue, 0.0, 100.0);
        coreUsageOut->push_back(usageValue);
        usageSum += usageValue;
        ++validCount;
    }

    *totalUsageOut = validCount > 0 ? (usageSum / static_cast<double>(validCount)) : 0.0;
    return true;
}

bool HardwareDock::sampleCpuEffectiveSpeed(double* speedGhzOut) const
{
    if (speedGhzOut == nullptr
        || m_cpuPerformanceCounterHandle == nullptr
        || m_cpuFrequencyCounterHandle == nullptr)
    {
        return false;
    }

    const auto readCounterValue =
        [](void* counterHandle, double* valueOut)
        {
            if (counterHandle == nullptr || valueOut == nullptr)
            {
                return false;
            }
            PDH_FMT_COUNTERVALUE formattedValue{};
            const PDH_STATUS status = ::PdhGetFormattedCounterValue(
                reinterpret_cast<PDH_HCOUNTER>(counterHandle),
                PDH_FMT_DOUBLE,
                nullptr,
                &formattedValue);
            if (status != ERROR_SUCCESS
                || (formattedValue.CStatus != PDH_CSTATUS_VALID_DATA
                    && formattedValue.CStatus != PDH_CSTATUS_NEW_DATA)
                || !std::isfinite(formattedValue.doubleValue))
            {
                return false;
            }
            *valueOut = formattedValue.doubleValue;
            return true;
        };

    double performancePercent = 0.0;
    double baseFrequencyMhz = 0.0;
    if (!readCounterValue(m_cpuPerformanceCounterHandle, &performancePercent)
        || !readCounterValue(m_cpuFrequencyCounterHandle, &baseFrequencyMhz))
    {
        return false;
    }

    const double effectiveFrequencyMhz = baseFrequencyMhz * performancePercent / 100.0;
    if (!std::isfinite(effectiveFrequencyMhz)
        || effectiveFrequencyMhz <= 0.0
        || effectiveFrequencyMhz > 20000.0)
    {
        return false;
    }

    *speedGhzOut = effectiveFrequencyMhz / 1000.0;
    return true;
}

bool HardwareDock::sampleCpuPowerInfo(std::vector<CpuPowerSnapshot>* powerInfoOut)
{
    if (powerInfoOut == nullptr)
    {
        return false;
    }

    const ULONG logicalProcessorCount = std::max<ULONG>(
        1,
        static_cast<ULONG>(m_coreChartEntries.size()));
    // KsProcessorPowerInformation 用途：
    // - 与 CallNtPowerInformation(ProcessorInformation) 输出结构保持二进制兼容；
    // - 避免不同 SDK 版本缺少 PROCESSOR_POWER_INFORMATION 定义导致编译失败。
    struct KsProcessorPowerInformation
    {
        ULONG Number;            // Number：逻辑处理器编号。
        ULONG MaxMhz;            // MaxMhz：最大频率。
        ULONG CurrentMhz;        // CurrentMhz：当前频率。
        ULONG MhzLimit;          // MhzLimit：限频上限。
        ULONG MaxIdleState;      // MaxIdleState：最大空闲状态。
        ULONG CurrentIdleState;  // CurrentIdleState：当前空闲状态。
    };
    std::vector<KsProcessorPowerInformation> nativeInfoList(logicalProcessorCount);

    const NTSTATUS ntStatus = ::CallNtPowerInformation(
        ProcessorInformation,
        nullptr,
        0,
        nativeInfoList.data(),
        static_cast<ULONG>(nativeInfoList.size() * sizeof(KsProcessorPowerInformation)));
    if (ntStatus != 0)
    {
        return false;
    }

    powerInfoOut->clear();
    powerInfoOut->reserve(nativeInfoList.size());
    for (const KsProcessorPowerInformation& nativeInfo : nativeInfoList)
    {
        CpuPowerSnapshot snapshot;
        snapshot.coreIndex = nativeInfo.Number;
        snapshot.currentMhz = nativeInfo.CurrentMhz;
        snapshot.maxMhz = nativeInfo.MaxMhz;
        snapshot.limitMhz = nativeInfo.MhzLimit;
        powerInfoOut->push_back(snapshot);
    }
    return true;
}

bool HardwareDock::sampleMemoryUsage(double* memoryUsagePercentOut)
{
    if (memoryUsagePercentOut == nullptr)
    {
        return false;
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus) == FALSE)
    {
        *memoryUsagePercentOut = 0.0;
        return false;
    }

    *memoryUsagePercentOut = static_cast<double>(memoryStatus.dwMemoryLoad);
    return true;
}

bool HardwareDock::sampleDiskRates(std::vector<DiskRateSample>* sampleListOut)
{
    if (sampleListOut == nullptr)
    {
        return false;
    }

    if (m_diskPerfQueryHandle == nullptr)
    {
        PDH_HQUERY queryHandle = nullptr;
        if (::PdhOpenQueryW(nullptr, 0, &queryHandle) != ERROR_SUCCESS || queryHandle == nullptr)
        {
            return false;
        }

        PDH_HCOUNTER readCounterHandle = nullptr;
        PDH_HCOUNTER writeCounterHandle = nullptr;
        const PDH_STATUS addReadStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(*)\\Disk Read Bytes/sec",
            0,
            &readCounterHandle);
        const PDH_STATUS addWriteStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(*)\\Disk Write Bytes/sec",
            0,
            &writeCounterHandle);
        if (addReadStatus != ERROR_SUCCESS || addWriteStatus != ERROR_SUCCESS)
        {
            ::PdhCloseQuery(queryHandle);
            return false;
        }

        m_diskPerfQueryHandle = queryHandle;
        m_diskReadCounterHandle = readCounterHandle;
        m_diskWriteCounterHandle = writeCounterHandle;
        ::PdhCollectQueryData(queryHandle);
    }

    const PDH_HQUERY queryHandle = reinterpret_cast<PDH_HQUERY>(m_diskPerfQueryHandle);
    if (::PdhCollectQueryData(queryHandle) != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD readBufferSize = 0;
    DWORD readItemCount = 0;
    PDH_STATUS readQueryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(m_diskReadCounterHandle),
        PDH_FMT_DOUBLE,
        &readBufferSize,
        &readItemCount,
        nullptr);
    if (readQueryStatus != PDH_MORE_DATA || readBufferSize == 0 || readItemCount == 0)
    {
        sampleListOut->clear();
        return true;
    }

    std::vector<unsigned char> readBuffer(readBufferSize);
    PDH_FMT_COUNTERVALUE_ITEM_W* readItemPointer =
        reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(readBuffer.data());
    readQueryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(m_diskReadCounterHandle),
        PDH_FMT_DOUBLE,
        &readBufferSize,
        &readItemCount,
        readItemPointer);
    if (readQueryStatus != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD writeBufferSize = 0;
    DWORD writeItemCount = 0;
    PDH_STATUS writeQueryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(m_diskWriteCounterHandle),
        PDH_FMT_DOUBLE,
        &writeBufferSize,
        &writeItemCount,
        nullptr);
    if (writeQueryStatus != PDH_MORE_DATA || writeBufferSize == 0 || writeItemCount == 0)
    {
        return false;
    }

    std::vector<unsigned char> writeBuffer(writeBufferSize);
    PDH_FMT_COUNTERVALUE_ITEM_W* writeItemPointer =
        reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(writeBuffer.data());
    writeQueryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(m_diskWriteCounterHandle),
        PDH_FMT_DOUBLE,
        &writeBufferSize,
        &writeItemCount,
        writeItemPointer);
    if (writeQueryStatus != ERROR_SUCCESS)
    {
        return false;
    }

    sampleListOut->clear();
    sampleListOut->reserve(readItemCount);
    for (DWORD readIndex = 0; readIndex < readItemCount; ++readIndex)
    {
        const PDH_FMT_COUNTERVALUE_ITEM_W& readItem = readItemPointer[readIndex];
        const QString instanceNameText = QString::fromWCharArray(
            readItem.szName != nullptr ? readItem.szName : L"").trimmed();
        if (instanceNameText.isEmpty() || instanceNameText == QStringLiteral("_Total"))
        {
            continue;
        }
        if (readItem.FmtValue.CStatus != ERROR_SUCCESS)
        {
            continue;
        }

        DiskRateSample sample;
        sample.instanceNameText = instanceNameText;
        sample.displayNameText = simplifyDiskInstanceName(instanceNameText);
        sample.readBytesPerSec = std::max(0.0, readItem.FmtValue.doubleValue);
        for (DWORD writeIndex = 0; writeIndex < writeItemCount; ++writeIndex)
        {
            const PDH_FMT_COUNTERVALUE_ITEM_W& writeItem = writeItemPointer[writeIndex];
            const QString writeInstanceNameText = QString::fromWCharArray(
                writeItem.szName != nullptr ? writeItem.szName : L"").trimmed();
            if (QString::compare(writeInstanceNameText, instanceNameText, Qt::CaseInsensitive) == 0
                && writeItem.FmtValue.CStatus == ERROR_SUCCESS)
            {
                sample.writeBytesPerSec = std::max(0.0, writeItem.FmtValue.doubleValue);
                break;
            }
        }
        sampleListOut->push_back(sample);
    }
    return true;
}

bool HardwareDock::sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut)
{
    if (readBytesPerSecOut == nullptr || writeBytesPerSecOut == nullptr)
    {
        return false;
    }

    std::vector<DiskRateSample> sampleList;
    const bool sampleOk = sampleDiskRates(&sampleList);
    if (!sampleOk)
    {
        return false;
    }

    double totalReadBytesPerSec = 0.0;
    double totalWriteBytesPerSec = 0.0;
    for (const DiskRateSample& sample : sampleList)
    {
        totalReadBytesPerSec += std::max(0.0, sample.readBytesPerSec);
        totalWriteBytesPerSec += std::max(0.0, sample.writeBytesPerSec);
    }
    *readBytesPerSecOut = totalReadBytesPerSec;
    *writeBytesPerSecOut = totalWriteBytesPerSec;
    return true;
}

bool HardwareDock::sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut)
{
    if (rxBytesPerSecOut == nullptr || txBytesPerSecOut == nullptr)
    {
        return false;
    }

    MIB_IF_TABLE2* tablePointer = nullptr;
    if (::GetIfTable2(&tablePointer) != NO_ERROR || tablePointer == nullptr)
    {
        return false;
    }

    std::uint64_t totalRxBytes = 0;
    std::uint64_t totalTxBytes = 0;
    std::uint64_t primaryTrafficBytes = 0;
    QString primaryAdapterName;
    std::uint64_t primaryLinkBitsPerSecond = 0;
    for (ULONG rowIndex = 0; rowIndex < tablePointer->NumEntries; ++rowIndex)
    {
        const MIB_IF_ROW2& rowValue = tablePointer->Table[rowIndex];
        if (rowValue.OperStatus != IfOperStatusUp)
        {
            continue;
        }
        if (rowValue.Type == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            continue;
        }

        totalRxBytes += static_cast<std::uint64_t>(rowValue.InOctets);
        totalTxBytes += static_cast<std::uint64_t>(rowValue.OutOctets);

        // 对齐任务管理器展示口径：
        // - 选择当前“累计流量最高”的活动网卡作为主展示网卡；
        // - 记录其链路速率，供详情页显示。
        const std::uint64_t rowTrafficBytes = static_cast<std::uint64_t>(rowValue.InOctets)
            + static_cast<std::uint64_t>(rowValue.OutOctets);
        if (rowTrafficBytes >= primaryTrafficBytes)
        {
            primaryTrafficBytes = rowTrafficBytes;
            primaryAdapterName = QString::fromWCharArray(rowValue.Alias);
            primaryLinkBitsPerSecond = std::max<std::uint64_t>(
                static_cast<std::uint64_t>(rowValue.ReceiveLinkSpeed),
                static_cast<std::uint64_t>(rowValue.TransmitLinkSpeed));
        }
    }
    ::FreeMibTable(tablePointer);

    m_primaryNetworkAdapterName = primaryAdapterName;
    m_primaryNetworkLinkBitsPerSecond = primaryLinkBitsPerSecond;

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    if (m_lastNetworkSampleMs <= 0)
    {
        m_lastNetworkSampleMs = nowMs;
        m_lastNetworkRxBytes = totalRxBytes;
        m_lastNetworkTxBytes = totalTxBytes;
        *rxBytesPerSecOut = 0.0;
        *txBytesPerSecOut = 0.0;
        return true;
    }

    const qint64 elapsedMs = nowMs - m_lastNetworkSampleMs;
    if (elapsedMs <= 0)
    {
        return false;
    }

    const std::uint64_t deltaRx = totalRxBytes >= m_lastNetworkRxBytes
        ? (totalRxBytes - m_lastNetworkRxBytes)
        : 0;
    const std::uint64_t deltaTx = totalTxBytes >= m_lastNetworkTxBytes
        ? (totalTxBytes - m_lastNetworkTxBytes)
        : 0;
    m_lastNetworkSampleMs = nowMs;
    m_lastNetworkRxBytes = totalRxBytes;
    m_lastNetworkTxBytes = totalTxBytes;

    *rxBytesPerSecOut = static_cast<double>(deltaRx) * 1000.0 / static_cast<double>(elapsedMs);
    *txBytesPerSecOut = static_cast<double>(deltaTx) * 1000.0 / static_cast<double>(elapsedMs);
    return true;
}

bool HardwareDock::sampleNetworkRates(std::vector<NetworkRateSample>* sampleListOut)
{
    if (sampleListOut == nullptr)
    {
        return false;
    }

    MIB_IF_TABLE2* tablePointer = nullptr;
    if (::GetIfTable2(&tablePointer) != NO_ERROR || tablePointer == nullptr)
    {
        return false;
    }

    sampleListOut->clear();
    sampleListOut->reserve(tablePointer->NumEntries);
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    std::uint64_t primaryTrafficBytes = 0;
    QString primaryAdapterName;
    std::uint64_t primaryLinkBitsPerSecond = 0;
    for (ULONG rowIndex = 0; rowIndex < tablePointer->NumEntries; ++rowIndex)
    {
        const MIB_IF_ROW2& rowValue = tablePointer->Table[rowIndex];
        if (rowValue.OperStatus != IfOperStatusUp)
        {
            continue;
        }
        if (rowValue.Type == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            continue;
        }

        NetworkRateSample sample;
        sample.interfaceKey = interfaceLuidToKey(static_cast<std::uint64_t>(rowValue.InterfaceLuid.Value));
        sample.displayNameText = QString::fromWCharArray(rowValue.Alias).trimmed();
        if (sample.displayNameText.isEmpty())
        {
            sample.displayNameText = QString::fromWCharArray(rowValue.Description).trimmed();
        }
        sample.linkBitsPerSecond = std::max<std::uint64_t>(
            static_cast<std::uint64_t>(rowValue.ReceiveLinkSpeed),
            static_cast<std::uint64_t>(rowValue.TransmitLinkSpeed));
        sample.totalRxBytes = static_cast<std::uint64_t>(rowValue.InOctets);
        sample.totalTxBytes = static_cast<std::uint64_t>(rowValue.OutOctets);

        const int deviceIndex = ensureNetworkUtilizationDevice(
            sample,
            static_cast<int>(sampleListOut->size()));
        if (deviceIndex >= 0 && deviceIndex < static_cast<int>(m_networkUtilDevices.size()))
        {
            NetworkUtilizationDevice& device = m_networkUtilDevices[static_cast<std::size_t>(deviceIndex)];
            const qint64 elapsedMs = nowMs - device.lastSampleMs;
            if (device.hasPreviousSample && elapsedMs > 0)
            {
                const std::uint64_t deltaRx = sample.totalRxBytes >= device.lastRxBytes
                    ? (sample.totalRxBytes - device.lastRxBytes)
                    : 0;
                const std::uint64_t deltaTx = sample.totalTxBytes >= device.lastTxBytes
                    ? (sample.totalTxBytes - device.lastTxBytes)
                    : 0;
                sample.rxBytesPerSec = static_cast<double>(deltaRx) * 1000.0 / static_cast<double>(elapsedMs);
                sample.txBytesPerSec = static_cast<double>(deltaTx) * 1000.0 / static_cast<double>(elapsedMs);
            }
            device.lastRxBytes = sample.totalRxBytes;
            device.lastTxBytes = sample.totalTxBytes;
            device.lastSampleMs = nowMs;
            device.linkBitsPerSecond = sample.linkBitsPerSecond;
            device.hasPreviousSample = true;
        }
        const std::uint64_t trafficBytes = sample.totalRxBytes + sample.totalTxBytes;
        if (trafficBytes >= primaryTrafficBytes)
        {
            primaryTrafficBytes = trafficBytes;
            primaryAdapterName = sample.displayNameText;
            primaryLinkBitsPerSecond = sample.linkBitsPerSecond;
        }
        sampleListOut->push_back(sample);
    }
    ::FreeMibTable(tablePointer);
    m_primaryNetworkAdapterName = primaryAdapterName;
    m_primaryNetworkLinkBitsPerSecond = primaryLinkBitsPerSecond;
    return true;
}

bool HardwareDock::sampleGpuUsages(std::vector<GpuUsageSample>* sampleListOut)
{
    if (sampleListOut == nullptr)
    {
        return false;
    }

    // GpuSamplingSharedState 作用：
    // - GPU 采样需要 DXGI 全适配器枚举加 \GPU Engine(*) 通配符全实例数组格式化，
    //   实例数等于“进程数 × 引擎类型”，放在每秒定时器里会持续占用 UI 线程；
    // - 这里把整段采集搬到后台任务，UI 线程只读取最近一次快照；
    // - 后台任务只读写这份共享状态，不触碰任何 QWidget。
    struct GpuSamplingSharedState
    {
        std::mutex stateMutex;                        // stateMutex：保护快照与 PDH 句柄。
        std::vector<GpuUsageSample> cachedSampleList; // cachedSampleList：最近一次采样快照。
        bool samplingInFlight = false;                // samplingInFlight：是否已有后台采样在执行。
        void* pdhQueryHandle = nullptr;               // pdhQueryHandle：GPU PDH 查询句柄。
        void* engineCounterHandle = nullptr;          // engineCounterHandle：GPU 引擎利用率计数器句柄。
        void* dedicatedMemoryCounterHandle = nullptr; // dedicatedMemoryCounterHandle：专用显存占用计数器句柄。
        void* sharedMemoryCounterHandle = nullptr;    // sharedMemoryCounterHandle：共享显存占用计数器句柄。
    };

    // 共享状态刻意堆分配且不回收：
    // - 后台采样可能在进程退出阶段仍在运行，静态对象析构会与之竞争；
    // - PDH 查询句柄同样交给进程退出统一回收，避免关闭正在被使用的查询。
    static GpuSamplingSharedState* const gpuSamplingSharedState = new GpuSamplingSharedState();
    GpuSamplingSharedState* const samplingStatePointer = gpuSamplingSharedState;

    // shouldStartBackgroundSampling 用途：本次刷新是否需要投递新一轮后台采集。
    bool shouldStartBackgroundSampling = false;
    {
        const std::lock_guard<std::mutex> stateLock(samplingStatePointer->stateMutex);
        *sampleListOut = samplingStatePointer->cachedSampleList;
        if (!samplingStatePointer->samplingInFlight)
        {
            samplingStatePointer->samplingInFlight = true;
            shouldStartBackgroundSampling = true;
        }
    }

    if (shouldStartBackgroundSampling)
    {
        QThreadPool::globalInstance()->start(
            [samplingStatePointer]()
            {
                // DXGI 与 PDH 全部在本线程内完成，COM 接口指针不跨线程传递。
                const HRESULT comInitializeStatus = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

                // 句柄先在锁内取出、结束时再写回：
                // - 同一时刻只有一个采样任务，但任务可能落在不同线程上；
                // - 借助互斥量建立内存可见性，避免上一轮写入对本轮不可见。
                void* gpuQueryHandle = nullptr;
                void* engineCounterHandle = nullptr;
                void* dedicatedMemoryCounterHandle = nullptr;
                void* sharedMemoryCounterHandle = nullptr;
                {
                    const std::lock_guard<std::mutex> stateLock(samplingStatePointer->stateMutex);
                    gpuQueryHandle = samplingStatePointer->pdhQueryHandle;
                    engineCounterHandle = samplingStatePointer->engineCounterHandle;
                    dedicatedMemoryCounterHandle = samplingStatePointer->dedicatedMemoryCounterHandle;
                    sharedMemoryCounterHandle = samplingStatePointer->sharedMemoryCounterHandle;
                }

                // oneGiBInBytes 用途：把 DXGI 字节字段转换为任务管理器常见 GiB 文本。
                constexpr double oneGiBInBytes = 1024.0 * 1024.0 * 1024.0;
                // collectedSampleList 用途：本轮采集结果，成功后整体替换共享快照。
                std::vector<GpuUsageSample> collectedSampleList;
                // collectSucceeded 用途：DXGI 枚举失败时保留上一轮快照，不清空界面数据。
                bool collectSucceeded = false;

                IDXGIFactory6* factoryPointer = nullptr;
                const HRESULT createFactoryStatus = ::CreateDXGIFactory1(IID_PPV_ARGS(&factoryPointer));
                if (SUCCEEDED(createFactoryStatus) && factoryPointer != nullptr)
                {
                    collectSucceeded = true;
                    for (UINT adapterIndex = 0;; ++adapterIndex)
                    {
                        IDXGIAdapter1* adapterPointer = nullptr;
                        const HRESULT enumStatus = factoryPointer->EnumAdapters1(adapterIndex, &adapterPointer);
                        if (enumStatus == DXGI_ERROR_NOT_FOUND)
                        {
                            break;
                        }
                        if (FAILED(enumStatus) || adapterPointer == nullptr)
                        {
                            continue;
                        }

                        DXGI_ADAPTER_DESC1 adapterDesc{};
                        adapterPointer->GetDesc1(&adapterDesc);
                        if ((adapterDesc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0)
                        {
                            adapterPointer->Release();
                            continue;
                        }

                        GpuUsageSample sample;
                        sample.adapterKey = packLuidKey(adapterDesc.AdapterLuid);
                        sample.adapterIndex = static_cast<int>(adapterIndex);
                        sample.displayNameText = QString::fromWCharArray(adapterDesc.Description).trimmed();
                        sample.dedicatedMemoryGiB = static_cast<double>(adapterDesc.DedicatedVideoMemory) / oneGiBInBytes;
                        sample.sharedMemoryGiB = static_cast<double>(adapterDesc.SharedSystemMemory) / oneGiBInBytes;

                        GpuAdapterTelemetrySnapshot telemetrySnapshot;
                        if (queryGpuAdapterTelemetrySnapshot(adapterDesc.AdapterLuid, &telemetrySnapshot))
                        {
                            sample.currentCoreClockMhz = telemetrySnapshot.currentCoreClockMhz;
                            sample.maxCoreClockMhz = telemetrySnapshot.maxCoreClockMhz;
                            sample.currentMemoryClockMhz = telemetrySnapshot.currentMemoryClockMhz;
                            sample.maxMemoryClockMhz = telemetrySnapshot.maxMemoryClockMhz;
                            if (telemetrySnapshot.dedicatedVideoMemoryBytes > 0)
                            {
                                sample.dedicatedMemoryGiB =
                                    static_cast<double>(telemetrySnapshot.dedicatedVideoMemoryBytes) / oneGiBInBytes;
                            }
                            if (telemetrySnapshot.sharedSystemMemoryBytes > 0)
                            {
                                sample.sharedMemoryGiB =
                                    static_cast<double>(telemetrySnapshot.sharedSystemMemoryBytes) / oneGiBInBytes;
                            }
                        }

                        IDXGIAdapter3* adapter3Pointer = nullptr;
                        const HRESULT queryInterfaceStatus = adapterPointer->QueryInterface(
                            IID_PPV_ARGS(&adapter3Pointer));
                        if (SUCCEEDED(queryInterfaceStatus) && adapter3Pointer != nullptr)
                        {
                            DXGI_QUERY_VIDEO_MEMORY_INFO localMemoryInfo{};
                            DXGI_QUERY_VIDEO_MEMORY_INFO nonLocalMemoryInfo{};
                            const HRESULT localStatus = adapter3Pointer->QueryVideoMemoryInfo(
                                0,
                                DXGI_MEMORY_SEGMENT_GROUP_LOCAL,
                                &localMemoryInfo);
                            const HRESULT nonLocalStatus = adapter3Pointer->QueryVideoMemoryInfo(
                                0,
                                DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL,
                                &nonLocalMemoryInfo);
                            if (SUCCEEDED(localStatus))
                            {
                                // CurrentUsage 只表示当前进程的显存提交量，不能作为整张 GPU 的系统占用。
                                sample.dedicatedBudgetGiB =
                                    static_cast<double>(localMemoryInfo.Budget) / oneGiBInBytes;
                            }
                            if (SUCCEEDED(nonLocalStatus))
                            {
                                sample.sharedBudgetGiB =
                                    static_cast<double>(nonLocalMemoryInfo.Budget) / oneGiBInBytes;
                            }
                            adapter3Pointer->Release();
                        }

                        if (sample.dedicatedMemoryGiB <= 0.0 && sample.dedicatedBudgetGiB > 0.0)
                        {
                            sample.dedicatedMemoryGiB = sample.dedicatedBudgetGiB;
                        }
                        if (sample.dedicatedBudgetGiB <= 0.0)
                        {
                            sample.dedicatedBudgetGiB = sample.dedicatedMemoryGiB;
                        }
                        if (sample.sharedMemoryGiB <= 0.0 && sample.sharedBudgetGiB > 0.0)
                        {
                            sample.sharedMemoryGiB = sample.sharedBudgetGiB;
                        }
                        if (sample.sharedMemoryGiB <= 0.0)
                        {
                            MEMORYSTATUSEX memoryStatus{};
                            memoryStatus.dwLength = sizeof(memoryStatus);
                            if (::GlobalMemoryStatusEx(&memoryStatus) == TRUE)
                            {
                                const double totalMemoryGiB =
                                    static_cast<double>(memoryStatus.ullTotalPhys) / oneGiBInBytes;
                                sample.sharedMemoryGiB = std::max(0.5, totalMemoryGiB * 0.5);
                            }
                        }
                        if (sample.sharedBudgetGiB <= 0.0)
                        {
                            sample.sharedBudgetGiB = sample.sharedMemoryGiB;
                        }

                        collectedSampleList.push_back(sample);
                        adapterPointer->Release();
                    }
                    factoryPointer->Release();
                }

                if (collectSucceeded && !collectedSampleList.empty())
                {
                    // memoryCounterReadable 用途：只有本轮确实完成过一次 collect 才去读显存数组。
                    bool memoryCounterReadable = false;
                    if (gpuQueryHandle == nullptr)
                    {
                        // 首次注册 \GPU Engine(*) 通配符实例开销最大，现在完全落在后台线程。
                        PDH_HQUERY queryHandle = nullptr;
                        if (::PdhOpenQueryW(nullptr, 0, &queryHandle) == ERROR_SUCCESS && queryHandle != nullptr)
                        {
                            PDH_HCOUNTER counterHandle = nullptr;
                            const PDH_STATUS addStatus = ::PdhAddEnglishCounterW(
                                queryHandle,
                                L"\\GPU Engine(*)\\Utilization Percentage",
                                0,
                                &counterHandle);
                            if (addStatus != ERROR_SUCCESS || counterHandle == nullptr)
                            {
                                ::PdhCloseQuery(queryHandle);
                            }
                            else
                            {
                                PDH_HCOUNTER newDedicatedMemoryCounterHandle = nullptr;
                                if (::PdhAddEnglishCounterW(
                                        queryHandle,
                                        L"\\GPU Adapter Memory(*)\\Dedicated Usage",
                                        0,
                                        &newDedicatedMemoryCounterHandle) != ERROR_SUCCESS)
                                {
                                    newDedicatedMemoryCounterHandle = nullptr;
                                }

                                PDH_HCOUNTER newSharedMemoryCounterHandle = nullptr;
                                if (::PdhAddEnglishCounterW(
                                        queryHandle,
                                        L"\\GPU Adapter Memory(*)\\Shared Usage",
                                        0,
                                        &newSharedMemoryCounterHandle) != ERROR_SUCCESS)
                                {
                                    newSharedMemoryCounterHandle = nullptr;
                                }

                                gpuQueryHandle = queryHandle;
                                engineCounterHandle = counterHandle;
                                dedicatedMemoryCounterHandle = newDedicatedMemoryCounterHandle;
                                sharedMemoryCounterHandle = newSharedMemoryCounterHandle;
                                ::PdhCollectQueryData(queryHandle);
                                ::Sleep(1);
                                ::PdhCollectQueryData(queryHandle);
                                memoryCounterReadable = true;
                            }
                        }
                    }
                    else if (::PdhCollectQueryData(reinterpret_cast<PDH_HQUERY>(gpuQueryHandle)) == ERROR_SUCCESS)
                    {
                        memoryCounterReadable = true;

                        DWORD bufferSize = 0;
                        DWORD itemCount = 0;
                        PDH_STATUS queryStatus = ::PdhGetFormattedCounterArrayW(
                            reinterpret_cast<PDH_HCOUNTER>(engineCounterHandle),
                            PDH_FMT_DOUBLE,
                            &bufferSize,
                            &itemCount,
                            nullptr);
                        if (queryStatus == PDH_MORE_DATA && bufferSize > 0 && itemCount > 0)
                        {
                            std::vector<unsigned char> rawBuffer(bufferSize);
                            PDH_FMT_COUNTERVALUE_ITEM_W* itemPointer =
                                reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(rawBuffer.data());
                            queryStatus = ::PdhGetFormattedCounterArrayW(
                                reinterpret_cast<PDH_HCOUNTER>(engineCounterHandle),
                                PDH_FMT_DOUBLE,
                                &bufferSize,
                                &itemCount,
                                itemPointer);
                            if (queryStatus == ERROR_SUCCESS)
                            {
                                for (DWORD itemIndex = 0; itemIndex < itemCount; ++itemIndex)
                                {
                                    const PDH_FMT_COUNTERVALUE_ITEM_W& itemValue = itemPointer[itemIndex];
                                    if (itemValue.FmtValue.CStatus != ERROR_SUCCESS)
                                    {
                                        continue;
                                    }

                                    const QString engineNameText = QString::fromWCharArray(
                                        itemValue.szName != nullptr ? itemValue.szName : L"");
                                    std::uint64_t adapterKey = 0;
                                    if (!parseGpuAdapterKeyFromCounterName(engineNameText, &adapterKey))
                                    {
                                        continue;
                                    }

                                    const QString engineKeyText = resolveGpuEngineKeyFromCounter(engineNameText);
                                    if (engineKeyText.isEmpty())
                                    {
                                        continue;
                                    }

                                    GpuUsageSample* samplePointer = nullptr;
                                    for (GpuUsageSample& sample : collectedSampleList)
                                    {
                                        if (sample.adapterKey == adapterKey)
                                        {
                                            samplePointer = &sample;
                                            break;
                                        }
                                    }
                                    if (samplePointer == nullptr)
                                    {
                                        continue;
                                    }

                                    const double engineUsagePercent =
                                        std::clamp(itemValue.FmtValue.doubleValue, 0.0, 100.0);
                                    if (engineKeyText == QStringLiteral("3d"))
                                    {
                                        samplePointer->usage3DPercent =
                                            std::max(samplePointer->usage3DPercent, engineUsagePercent);
                                    }
                                    else if (engineKeyText == QStringLiteral("copy"))
                                    {
                                        samplePointer->usageCopyPercent =
                                            std::max(samplePointer->usageCopyPercent, engineUsagePercent);
                                    }
                                    else if (engineKeyText == QStringLiteral("video_encode"))
                                    {
                                        samplePointer->usageVideoEncodePercent =
                                            std::max(samplePointer->usageVideoEncodePercent, engineUsagePercent);
                                    }
                                    else if (engineKeyText == QStringLiteral("video_decode"))
                                    {
                                        samplePointer->usageVideoDecodePercent =
                                            std::max(samplePointer->usageVideoDecodePercent, engineUsagePercent);
                                    }
                                    samplePointer->overallUsagePercent =
                                        std::max(samplePointer->overallUsagePercent, engineUsagePercent);
                                }
                            }
                        }
                    }

                    // GPU Adapter Memory 是 WDDM 的系统级显存占用；按实例名中的 LUID 汇总后，
                    // 与 DXGI 枚举出的适配器一一对应，避免把 KSword 进程自身的 CurrentUsage 当成全局值。
                    const auto applyGpuMemoryCounter = [&collectedSampleList, oneGiBInBytes](
                        void* counterHandleValue,
                        const bool dedicatedMemory)
                    {
                        if (counterHandleValue == nullptr)
                        {
                            return;
                        }

                        DWORD bufferSize = 0;
                        DWORD itemCount = 0;
                        PDH_STATUS queryStatus = ::PdhGetFormattedCounterArrayW(
                            reinterpret_cast<PDH_HCOUNTER>(counterHandleValue),
                            PDH_FMT_DOUBLE,
                            &bufferSize,
                            &itemCount,
                            nullptr);
                        if (queryStatus != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
                        {
                            return;
                        }

                        std::vector<unsigned char> rawBuffer(bufferSize);
                        PDH_FMT_COUNTERVALUE_ITEM_W* itemPointer =
                            reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(rawBuffer.data());
                        queryStatus = ::PdhGetFormattedCounterArrayW(
                            reinterpret_cast<PDH_HCOUNTER>(counterHandleValue),
                            PDH_FMT_DOUBLE,
                            &bufferSize,
                            &itemCount,
                            itemPointer);
                        if (queryStatus != ERROR_SUCCESS)
                        {
                            return;
                        }

                        for (DWORD itemIndex = 0; itemIndex < itemCount; ++itemIndex)
                        {
                            const PDH_FMT_COUNTERVALUE_ITEM_W& itemValue = itemPointer[itemIndex];
                            const DWORD valueStatus = itemValue.FmtValue.CStatus;
                            if (valueStatus != PDH_CSTATUS_VALID_DATA
                                && valueStatus != PDH_CSTATUS_NEW_DATA)
                            {
                                continue;
                            }

                            const QString counterNameText = QString::fromWCharArray(
                                itemValue.szName != nullptr ? itemValue.szName : L"");
                            std::uint64_t adapterKey = 0;
                            if (!parseGpuAdapterKeyFromCounterName(counterNameText, &adapterKey))
                            {
                                continue;
                            }

                            const auto sampleIterator = std::find_if(
                                collectedSampleList.begin(),
                                collectedSampleList.end(),
                                [adapterKey](const GpuUsageSample& sample)
                                {
                                    return sample.adapterKey == adapterKey;
                                });
                            if (sampleIterator == collectedSampleList.end())
                            {
                                continue;
                            }

                            const double usageGiB =
                                std::max(0.0, itemValue.FmtValue.doubleValue) / oneGiBInBytes;
                            if (dedicatedMemory)
                            {
                                sampleIterator->dedicatedUsedGiB += usageGiB;
                                sampleIterator->dedicatedUsageAvailable = true;
                            }
                            else
                            {
                                sampleIterator->sharedUsedGiB += usageGiB;
                                sampleIterator->sharedUsageAvailable = true;
                            }
                        }
                    };

                    if (memoryCounterReadable)
                    {
                        applyGpuMemoryCounter(dedicatedMemoryCounterHandle, true);
                        applyGpuMemoryCounter(sharedMemoryCounterHandle, false);
                    }
                }

                {
                    const std::lock_guard<std::mutex> stateLock(samplingStatePointer->stateMutex);
                    samplingStatePointer->pdhQueryHandle = gpuQueryHandle;
                    samplingStatePointer->engineCounterHandle = engineCounterHandle;
                    samplingStatePointer->dedicatedMemoryCounterHandle = dedicatedMemoryCounterHandle;
                    samplingStatePointer->sharedMemoryCounterHandle = sharedMemoryCounterHandle;
                    if (collectSucceeded)
                    {
                        samplingStatePointer->cachedSampleList = collectedSampleList;
                    }
                    samplingStatePointer->samplingInFlight = false;
                }

                if (SUCCEEDED(comInitializeStatus))
                {
                    ::CoUninitialize();
                }
            });
    }

    if (sampleListOut->empty())
    {
        return true;
    }

    // 详情页创建与卡片注册只能在 UI 线程做，因此放在快照回到本线程之后。
    for (int sampleIndex = 0; sampleIndex < static_cast<int>(sampleListOut->size()); ++sampleIndex)
    {
        ensureGpuUtilizationDevice(
            (*sampleListOut)[static_cast<std::size_t>(sampleIndex)],
            sampleIndex);
    }

    // 旧聚合 GPU 页固定展示专用显存最大的主适配器；不能合并利用率后仍沿用“第一张卡”的频率/显存。
    const auto primarySampleIterator = std::max_element(
        sampleListOut->cbegin(),
        sampleListOut->cend(),
        [](const GpuUsageSample& leftSample, const GpuUsageSample& rightSample)
        {
            if (!qFuzzyCompare(
                    leftSample.dedicatedMemoryGiB + 1.0,
                    rightSample.dedicatedMemoryGiB + 1.0))
            {
                return leftSample.dedicatedMemoryGiB < rightSample.dedicatedMemoryGiB;
            }
            return leftSample.overallUsagePercent < rightSample.overallUsagePercent;
        });
    const GpuUsageSample& primarySample = *primarySampleIterator;
    m_gpuAdapterNameText = primarySample.displayNameText;
    m_gpuCurrentCoreClockMhz = primarySample.currentCoreClockMhz;
    m_gpuMaxCoreClockMhz = primarySample.maxCoreClockMhz;
    m_gpuCurrentMemoryClockMhz = primarySample.currentMemoryClockMhz;
    m_gpuMaxMemoryClockMhz = primarySample.maxMemoryClockMhz;
    m_gpuDedicatedMemoryGiB = primarySample.dedicatedMemoryGiB;
    m_gpuSharedMemoryGiB = primarySample.sharedMemoryGiB;
    m_gpuDedicatedUsedGiB = primarySample.dedicatedUsedGiB;
    m_gpuDedicatedUsageAvailable = primarySample.dedicatedUsageAvailable;
    m_gpuDedicatedBudgetGiB = primarySample.dedicatedBudgetGiB;
    m_gpuSharedUsedGiB = primarySample.sharedUsedGiB;
    m_gpuSharedUsageAvailable = primarySample.sharedUsageAvailable;
    m_gpuSharedBudgetGiB = primarySample.sharedBudgetGiB;
    m_gpuUsage3DPercent = primarySample.usage3DPercent;
    m_gpuUsageCopyPercent = primarySample.usageCopyPercent;
    m_gpuUsageVideoEncodePercent = primarySample.usageVideoEncodePercent;
    m_gpuUsageVideoDecodePercent = primarySample.usageVideoDecodePercent;
    return true;
}

bool HardwareDock::sampleGpuUsage(double* gpuUsagePercentOut)
{
    if (gpuUsagePercentOut == nullptr)
    {
        return false;
    }

    if (m_gpuPerfQueryHandle == nullptr)
    {
        PDH_HQUERY queryHandle = nullptr;
        if (::PdhOpenQueryW(nullptr, 0, &queryHandle) != ERROR_SUCCESS || queryHandle == nullptr)
        {
            return false;
        }

        PDH_HCOUNTER counterHandle = nullptr;
        const PDH_STATUS addStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\GPU Engine(*)\\Utilization Percentage",
            0,
            &counterHandle);
        if (addStatus != ERROR_SUCCESS || counterHandle == nullptr)
        {
            ::PdhCloseQuery(queryHandle);
            return false;
        }

        m_gpuPerfQueryHandle = queryHandle;
        m_gpuCounterHandle = counterHandle;
        ::PdhCollectQueryData(queryHandle);
        *gpuUsagePercentOut = 0.0;
        return true;
    }

    const PDH_HQUERY queryHandle = reinterpret_cast<PDH_HQUERY>(m_gpuPerfQueryHandle);
    if (::PdhCollectQueryData(queryHandle) != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD bufferSize = 0;
    DWORD itemCount = 0;
    PDH_STATUS queryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(m_gpuCounterHandle),
        PDH_FMT_DOUBLE,
        &bufferSize,
        &itemCount,
        nullptr);
    if (queryStatus != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
    {
        m_gpuUsage3DPercent = 0.0;
        m_gpuUsageCopyPercent = 0.0;
        m_gpuUsageVideoEncodePercent = 0.0;
        m_gpuUsageVideoDecodePercent = 0.0;
        *gpuUsagePercentOut = 0.0;
        sampleGpuMemoryInfoByDxgi();
        return true;
    }

    std::vector<unsigned char> rawBuffer(bufferSize);
    PDH_FMT_COUNTERVALUE_ITEM_W* itemPtr = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(rawBuffer.data());
    queryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(m_gpuCounterHandle),
        PDH_FMT_DOUBLE,
        &bufferSize,
        &itemCount,
        itemPtr);
    if (queryStatus != ERROR_SUCCESS)
    {
        m_gpuUsage3DPercent = 0.0;
        m_gpuUsageCopyPercent = 0.0;
        m_gpuUsageVideoEncodePercent = 0.0;
        m_gpuUsageVideoDecodePercent = 0.0;
        *gpuUsagePercentOut = 0.0;
        sampleGpuMemoryInfoByDxgi();
        return true;
    }

    // 任务管理器“总体 GPU”近似值：
    // - 先按引擎分类记录峰值；
    // - 再取四类引擎中的最大值作为总体利用率。
    double usage3DPercent = 0.0;
    double usageCopyPercent = 0.0;
    double usageVideoEncodePercent = 0.0;
    double usageVideoDecodePercent = 0.0;
    double peakUsage = 0.0;
    for (DWORD indexValue = 0; indexValue < itemCount; ++indexValue)
    {
        const PDH_FMT_COUNTERVALUE_ITEM_W& itemValue = itemPtr[indexValue];
        if (itemValue.FmtValue.CStatus != ERROR_SUCCESS)
        {
            continue;
        }

        // engineUsagePercent 用途：当前计数器样本值，限制在 0~100。
        const double engineUsagePercent = std::clamp(itemValue.FmtValue.doubleValue, 0.0, 100.0);
        const QString engineNameText = QString::fromWCharArray(
            itemValue.szName != nullptr ? itemValue.szName : L"");
        const QString engineKeyText = resolveGpuEngineKeyFromCounter(engineNameText);
        if (engineKeyText == QStringLiteral("3d"))
        {
            usage3DPercent = std::max(usage3DPercent, engineUsagePercent);
        }
        else if (engineKeyText == QStringLiteral("copy"))
        {
            usageCopyPercent = std::max(usageCopyPercent, engineUsagePercent);
        }
        else if (engineKeyText == QStringLiteral("video_encode"))
        {
            usageVideoEncodePercent = std::max(usageVideoEncodePercent, engineUsagePercent);
        }
        else if (engineKeyText == QStringLiteral("video_decode"))
        {
            usageVideoDecodePercent = std::max(usageVideoDecodePercent, engineUsagePercent);
        }

        peakUsage = std::max(peakUsage, engineUsagePercent);
    }

    m_gpuUsage3DPercent = usage3DPercent;
    m_gpuUsageCopyPercent = usageCopyPercent;
    m_gpuUsageVideoEncodePercent = usageVideoEncodePercent;
    m_gpuUsageVideoDecodePercent = usageVideoDecodePercent;
    *gpuUsagePercentOut = std::clamp(peakUsage, 0.0, 100.0);
    sampleGpuMemoryInfoByDxgi();
    return true;
}

bool HardwareDock::sampleGpuMemoryInfoByDxgi()
{
    // oneGiBInBytes 用途：字节到 GiB 的统一换算系数。
    constexpr double oneGiBInBytes = 1024.0 * 1024.0 * 1024.0;

    IDXGIFactory6* factoryPointer = nullptr;
    const HRESULT createFactoryStatus = ::CreateDXGIFactory1(IID_PPV_ARGS(&factoryPointer));
    if (FAILED(createFactoryStatus) || factoryPointer == nullptr)
    {
        return false;
    }

    bool querySuccess = false;
    for (UINT adapterIndex = 0;; ++adapterIndex)
    {
        IDXGIAdapter1* adapterPointer = nullptr;
        const HRESULT enumStatus = factoryPointer->EnumAdapters1(adapterIndex, &adapterPointer);
        if (enumStatus == DXGI_ERROR_NOT_FOUND)
        {
            break;
        }
        if (FAILED(enumStatus) || adapterPointer == nullptr)
        {
            continue;
        }

        DXGI_ADAPTER_DESC1 adapterDesc{};
        adapterPointer->GetDesc1(&adapterDesc);
        if ((adapterDesc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0)
        {
            adapterPointer->Release();
            continue;
        }

        IDXGIAdapter3* adapter3Pointer = nullptr;
        const HRESULT queryInterfaceStatus = adapterPointer->QueryInterface(
            IID_PPV_ARGS(&adapter3Pointer));
        if (SUCCEEDED(queryInterfaceStatus) && adapter3Pointer != nullptr)
        {
            DXGI_QUERY_VIDEO_MEMORY_INFO localMemoryInfo{};
            DXGI_QUERY_VIDEO_MEMORY_INFO nonLocalMemoryInfo{};
            const HRESULT localStatus = adapter3Pointer->QueryVideoMemoryInfo(
                0,
                DXGI_MEMORY_SEGMENT_GROUP_LOCAL,
                &localMemoryInfo);
            const HRESULT nonLocalStatus = adapter3Pointer->QueryVideoMemoryInfo(
                0,
                DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL,
                &nonLocalMemoryInfo);
            if (SUCCEEDED(localStatus) && SUCCEEDED(nonLocalStatus))
            {
                // DXGI CurrentUsage 只覆盖当前进程；旧兼容路径仅保留预算信息，
                // 不再把进程级数据伪装成系统显存占用。
                m_gpuDedicatedUsedGiB = 0.0;
                m_gpuDedicatedUsageAvailable = false;
                m_gpuDedicatedBudgetGiB = static_cast<double>(localMemoryInfo.Budget) / oneGiBInBytes;
                m_gpuSharedUsedGiB = 0.0;
                m_gpuSharedUsageAvailable = false;
                m_gpuSharedBudgetGiB = static_cast<double>(nonLocalMemoryInfo.Budget) / oneGiBInBytes;

                // 某些设备 non-local budget 可能返回 0，回退到“物理内存一半”近似值。
                if (m_gpuSharedBudgetGiB <= 0.0)
                {
                    MEMORYSTATUSEX memoryStatus{};
                    memoryStatus.dwLength = sizeof(memoryStatus);
                    if (::GlobalMemoryStatusEx(&memoryStatus) == TRUE)
                    {
                        const double totalMemoryGiB =
                            static_cast<double>(memoryStatus.ullTotalPhys) / oneGiBInBytes;
                        m_gpuSharedBudgetGiB = std::max(0.5, totalMemoryGiB * 0.5);
                    }
                }

                const QString adapterNameText = QString::fromWCharArray(adapterDesc.Description).trimmed();
                if (!adapterNameText.isEmpty())
                {
                    m_gpuAdapterNameText = adapterNameText;
                }
                querySuccess = true;
            }
            adapter3Pointer->Release();
        }

        adapterPointer->Release();
        if (querySuccess)
        {
            break;
        }
    }

    factoryPointer->Release();
    return querySuccess;
}

bool HardwareDock::sampleSystemPerformanceSnapshot(SystemPerformanceSnapshot* snapshotOut) const
{
    if (snapshotOut == nullptr)
    {
        return false;
    }

    PERFORMANCE_INFORMATION perfInfo{};
    perfInfo.cb = sizeof(perfInfo);
    if (::GetPerformanceInfo(&perfInfo, sizeof(perfInfo)) == FALSE)
    {
        return false;
    }

    // pageSizeBytes 用途：把页数指标统一转换为字节单位。
    const std::uint64_t pageSizeBytes = static_cast<std::uint64_t>(perfInfo.PageSize);
    snapshotOut->processCount = static_cast<std::uint32_t>(perfInfo.ProcessCount);
    snapshotOut->threadCount = static_cast<std::uint32_t>(perfInfo.ThreadCount);
    snapshotOut->handleCount = static_cast<std::uint32_t>(perfInfo.HandleCount);
    snapshotOut->commitTotalBytes = static_cast<std::uint64_t>(perfInfo.CommitTotal) * pageSizeBytes;
    snapshotOut->commitLimitBytes = static_cast<std::uint64_t>(perfInfo.CommitLimit) * pageSizeBytes;
    snapshotOut->cachedBytes = static_cast<std::uint64_t>(perfInfo.SystemCache) * pageSizeBytes;
    snapshotOut->pagedPoolBytes = static_cast<std::uint64_t>(perfInfo.KernelPaged) * pageSizeBytes;
    snapshotOut->nonPagedPoolBytes = static_cast<std::uint64_t>(perfInfo.KernelNonpaged) * pageSizeBytes;
    return true;
}

void HardwareDock::updateOverviewText(const double cpuUsagePercent, const double memoryUsagePercent)
{
    if (m_overviewSummaryLabel == nullptr)
    {
        return;
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    ::GlobalMemoryStatusEx(&memoryStatus);

    const QString summaryText = ks::i18n::contextText(
        QStringLiteral("hardware.overview.summary"),
        QStringLiteral("CPU总体利用率: %1%    内存利用率: %2%    可用内存: %3 / 总内存: %4    %5"))
        .arg(cpuUsagePercent, 0, 'f', 1)
        .arg(memoryUsagePercent, 0, 'f', 1)
        .arg(bytesToGiBText(memoryStatus.ullAvailPhys))
        .arg(bytesToGiBText(memoryStatus.ullTotalPhys))
        .arg(m_r0HardwareHealthSummaryText);
    m_overviewSummaryLabel->setText(summaryText);
}

void HardwareDock::updateUtilizationView(
    const std::vector<double>& coreUsageList,
    const double memoryUsagePercent,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    // averageCpuUsage 用途：CPU 平均占用，用于标题和左侧导航卡片。
    double averageCpuUsage = 0.0;
    if (!coreUsageList.empty())
    {
        for (const double usageValue : coreUsageList)
        {
            averageCpuUsage += usageValue;
        }
        averageCpuUsage /= static_cast<double>(coreUsageList.size());
    }

    if (m_utilizationSummaryLabel != nullptr)
    {
        const UtilizationStatisticSnapshot cpuStats = buildStatisticSnapshot(m_cpuUsageHistoryPercent);
        m_utilizationSummaryLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.cpu.summary"),
                QStringLiteral("30 秒内的利用率 %    总体：%1%    均值：%2%    峰值：%3%    趋势：%4    逻辑处理器：%5"))
            .arg(averageCpuUsage, 0, 'f', 1)
            .arg(cpuStats.averageValue, 0, 'f', 1)
            .arg(cpuStats.peakValue, 0, 'f', 1)
            .arg(buildTrendText(cpuStats, true))
            .arg(coreUsageList.size()));
    }

    if (m_cpuModelLabel != nullptr && !m_cpuModelText.isEmpty())
    {
        m_cpuModelLabel->setText(m_cpuModelText);
    }

    const int chartCount = std::min(
        static_cast<int>(m_coreChartEntries.size()),
        static_cast<int>(coreUsageList.size()));
    for (int indexValue = 0; indexValue < chartCount; ++indexValue)
    {
        CoreChartEntry& chartEntry = m_coreChartEntries[static_cast<std::size_t>(indexValue)];
        const double usageValue = coreUsageList[static_cast<std::size_t>(indexValue)];
        chartEntry.titleLabel->setText(
            QStringLiteral("CPU %1  %2%")
            .arg(indexValue, 2, 10, QLatin1Char('0'))
            .arg(usageValue, 5, 'f', 1, QLatin1Char(' ')));
        appendCoreSeriesPoint(chartEntry, usageValue);
    }

    // 内存子页：更新摘要与折线趋势。
    if (m_memoryUtilSummaryLabel != nullptr)
    {
        const UtilizationStatisticSnapshot memoryStats = buildStatisticSnapshot(m_memoryUsageHistoryPercent);
        m_memoryUtilSummaryLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.memory.summary"),
                QStringLiteral("当前内存占用：%1%    均值：%2%    峰值：%3%    趋势：%4    %5"))
            .arg(memoryUsagePercent, 0, 'f', 1)
            .arg(memoryStats.averageValue, 0, 'f', 1)
            .arg(memoryStats.peakValue, 0, 'f', 1)
            .arg(buildTrendText(memoryStats, true))
            .arg(m_r0PhysicalMemorySummaryText));
    }
    if (m_memoryCompositionHistoryWidget != nullptr)
    {
        MemoryCompositionHistoryWidget::CompositionSample memorySample;
        memorySample.usedPercent = memoryUsagePercent;

        SystemPerformanceSnapshot perfSnapshot;
        const bool perfOk = sampleSystemPerformanceSnapshot(&perfSnapshot);
        MEMORYSTATUSEX memoryStatus{};
        memoryStatus.dwLength = sizeof(memoryStatus);
        const bool memoryStatusOk = (::GlobalMemoryStatusEx(&memoryStatus) == TRUE);
        if (perfOk && memoryStatusOk && memoryStatus.ullTotalPhys > 0ULL)
        {
            const double totalPhysicalBytes = static_cast<double>(memoryStatus.ullTotalPhys);
            memorySample.cachedPercent = static_cast<double>(perfSnapshot.cachedBytes) / totalPhysicalBytes * 100.0;
            memorySample.pagedPoolPercent = static_cast<double>(perfSnapshot.pagedPoolBytes) / totalPhysicalBytes * 100.0;
            memorySample.nonPagedPoolPercent = static_cast<double>(perfSnapshot.nonPagedPoolBytes) / totalPhysicalBytes * 100.0;
        }
        m_memoryCompositionHistoryWidget->appendSample(memorySample);
    }

    // 磁盘子页：更新读写速率摘要与折线趋势。
    if (m_diskUtilSummaryLabel != nullptr)
    {
        const UtilizationStatisticSnapshot diskStats = buildStatisticSnapshot(m_diskAggregateHistoryBytesPerSec);
        m_diskUtilSummaryLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.disk.summary"),
                QStringLiteral("读取：%1    写入：%2    合计均值：%3    峰值：%4"))
            .arg(formatRateText(diskReadBytesPerSec))
            .arg(formatRateText(diskWriteBytesPerSec))
            .arg(formatRateText(diskStats.averageValue))
            .arg(formatRateText(diskStats.peakValue)));
    }
    appendFilledSeriesPoint(
        m_diskReadLineSeries,
        m_diskReadBaselineSeries,
        m_diskUtilAxisX,
        m_diskUtilAxisY,
        diskReadBytesPerSec,
        0.0);
    appendFilledSeriesPoint(
        m_diskWriteLineSeries,
        m_diskWriteBaselineSeries,
        m_diskUtilAxisX,
        m_diskUtilAxisY,
        diskWriteBytesPerSec,
        0.0);
    updateSharedSeriesAxisRange(
        m_diskReadLineSeries,
        m_diskWriteLineSeries,
        m_diskUtilAxisX,
        m_diskUtilAxisY,
        0.0);

    // 网络子页：更新上下行速率摘要与折线趋势。
    if (m_networkUtilSummaryLabel != nullptr)
    {
        const UtilizationStatisticSnapshot networkStats = buildStatisticSnapshot(m_networkAggregateHistoryBytesPerSec);
        m_networkUtilSummaryLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.network.summary"),
                QStringLiteral("接收：%1    发送：%2    合计均值：%3    峰值：%4"))
            .arg(formatRateText(networkRxBytesPerSec))
            .arg(formatRateText(networkTxBytesPerSec))
            .arg(formatRateText(networkStats.averageValue))
            .arg(formatRateText(networkStats.peakValue)));
    }
    appendFilledSeriesPoint(
        m_networkRxLineSeries,
        m_networkRxBaselineSeries,
        m_networkUtilAxisX,
        m_networkUtilAxisY,
        networkRxBytesPerSec,
        0.0);
    appendFilledSeriesPoint(
        m_networkTxLineSeries,
        m_networkTxBaselineSeries,
        m_networkUtilAxisX,
        m_networkUtilAxisY,
        networkTxBytesPerSec,
        0.0);
    updateSharedSeriesAxisRange(
        m_networkRxLineSeries,
        m_networkTxLineSeries,
        m_networkUtilAxisX,
        m_networkUtilAxisY,
        0.0);

    // GPU 子页：更新利用率摘要与折线趋势。
    if (m_gpuUtilSummaryLabel != nullptr)
    {
        const UtilizationStatisticSnapshot gpuStats = buildStatisticSnapshot(m_gpuUsageHistoryPercent);
        m_gpuUtilSummaryLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.summary"),
                QStringLiteral("GPU 当前：%1%    均值：%2%    峰值：%3%    3D：%4%    Copy：%5%"))
            .arg(gpuUsagePercent, 0, 'f', 1)
            .arg(gpuStats.averageValue, 0, 'f', 1)
            .arg(gpuStats.peakValue, 0, 'f', 1)
            .arg(m_gpuUsage3DPercent, 0, 'f', 1)
            .arg(m_gpuUsageCopyPercent, 0, 'f', 1));
    }

    for (GpuEngineChartEntry& chartEntry : m_gpuEngineCharts)
    {
        double usagePercent = 0.0;
        if (chartEntry.engineKeyText == QStringLiteral("3d"))
        {
            usagePercent = m_gpuUsage3DPercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("copy"))
        {
            usagePercent = m_gpuUsageCopyPercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_encode"))
        {
            usagePercent = m_gpuUsageVideoEncodePercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_decode"))
        {
            usagePercent = m_gpuUsageVideoDecodePercent;
        }
        appendFilledSeriesPoint(
            chartEntry.lineSeries,
            chartEntry.baselineSeries,
            chartEntry.axisX,
            chartEntry.axisY,
            usagePercent,
            0.0);
        if (chartEntry.titleLabel != nullptr)
        {
            chartEntry.titleLabel->setText(
                QStringLiteral("%1  %2%")
                .arg(chartEntry.displayNameText)
                .arg(usagePercent, 0, 'f', 1));
        }
    }

    appendFilledSeriesPoint(
        m_gpuDedicatedMemoryLineSeries,
        m_gpuDedicatedMemoryBaselineSeries,
        m_gpuDedicatedMemoryAxisX,
        m_gpuDedicatedMemoryAxisY,
        m_gpuDedicatedUsedGiB,
        0.0);
    appendFilledSeriesPoint(
        m_gpuSharedMemoryLineSeries,
        m_gpuSharedMemoryBaselineSeries,
        m_gpuSharedMemoryAxisX,
        m_gpuSharedMemoryAxisY,
        m_gpuSharedUsedGiB,
        0.0);
    if (m_gpuDedicatedMemoryAxisY != nullptr)
    {
        const double dedicatedUpperGiB = std::max(
            0.5,
            (m_gpuDedicatedMemoryGiB > 0.0 ? m_gpuDedicatedMemoryGiB : m_gpuDedicatedBudgetGiB));
        m_gpuDedicatedMemoryAxisY->setRange(0.0, dedicatedUpperGiB);
    }
    if (m_gpuSharedMemoryAxisY != nullptr)
    {
        const double sharedUpperGiB = std::max(
            0.5,
            (m_gpuSharedMemoryGiB > 0.0 ? m_gpuSharedMemoryGiB : m_gpuSharedBudgetGiB));
        m_gpuSharedMemoryAxisY->setRange(0.0, sharedUpperGiB);
    }

    updateUtilizationSidebarCards(
        averageCpuUsage,
        memoryUsagePercent,
        diskReadBytesPerSec,
        diskWriteBytesPerSec,
        networkRxBytesPerSec,
        networkTxBytesPerSec,
        gpuUsagePercent);
}

void HardwareDock::updateUtilizationSidebarCards(
    const double cpuUsagePercent,
    const double memoryUsagePercent,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    if (m_cpuNavCard != nullptr)
    {
        m_cpuNavCard->setSubtitleText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.cpu.summary"),
                QStringLiteral("%1%  %2 GHz"))
            .arg(cpuUsagePercent, 0, 'f', 0)
            .arg(m_lastCpuSpeedGhz, 0, 'f', 2));
        m_cpuNavCard->appendSample(cpuUsagePercent);
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (m_memoryNavCard != nullptr && ::GlobalMemoryStatusEx(&memoryStatus) == TRUE)
    {
        const double totalGiB = static_cast<double>(memoryStatus.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0);
        const double usedGiB =
            static_cast<double>(memoryStatus.ullTotalPhys - memoryStatus.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
        const double cachedPercent = std::clamp(
            100.0 - memoryUsagePercent,
            0.0,
            100.0);
        const int historyCapacity = std::max(1, m_memoryNavCard->sampleCapacity());
        m_memoryNavUsedHistoryPercent.push_back(memoryUsagePercent);
        m_memoryNavCachedHistoryPercent.push_back(cachedPercent);
        while (static_cast<int>(m_memoryNavUsedHistoryPercent.size()) > historyCapacity)
        {
            m_memoryNavUsedHistoryPercent.erase(m_memoryNavUsedHistoryPercent.begin());
        }
        while (static_cast<int>(m_memoryNavCachedHistoryPercent.size()) > historyCapacity)
        {
            m_memoryNavCachedHistoryPercent.erase(m_memoryNavCachedHistoryPercent.begin());
        }

        QVector<double> usedSampleList;
        QVector<double> cachedSampleList;
        usedSampleList.reserve(static_cast<int>(m_memoryNavUsedHistoryPercent.size()));
        cachedSampleList.reserve(static_cast<int>(m_memoryNavCachedHistoryPercent.size()));
        for (const double usedSampleValue : m_memoryNavUsedHistoryPercent)
        {
            usedSampleList.push_back(std::clamp(usedSampleValue, 0.0, 100.0));
        }
        for (const double cachedSampleValue : m_memoryNavCachedHistoryPercent)
        {
            cachedSampleList.push_back(std::clamp(cachedSampleValue, 0.0, 100.0));
        }

        m_memoryNavCard->setSubtitleText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.memory.summary"),
                QStringLiteral("用 %1/%2 GB / 余 %3%"))
            .arg(usedGiB, 0, 'f', 1)
            .arg(totalGiB, 0, 'f', 1)
            .arg(cachedPercent, 0, 'f', 0));
        m_memoryNavCard->setSampleSeries(usedSampleList, cachedSampleList);
    }

    if (m_diskNavCard != nullptr)
    {
        rebuildDualRateNavCard(
            m_diskNavCard,
            &m_diskNavReadHistoryBytesPerSec,
            &m_diskNavWriteHistoryBytesPerSec,
            diskReadBytesPerSec,
            diskWriteBytesPerSec,
            &m_diskNavAutoScaleBytesPerSec,
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.disk.summary"),
                QStringLiteral("读 %1 / 写 %2"))
            .arg(formatRateText(diskReadBytesPerSec))
            .arg(formatRateText(diskWriteBytesPerSec)));
    }

    if (m_networkNavCard != nullptr)
    {
        rebuildDualRateNavCard(
            m_networkNavCard,
            &m_networkNavRxHistoryBytesPerSec,
            &m_networkNavTxHistoryBytesPerSec,
            networkRxBytesPerSec,
            networkTxBytesPerSec,
            &m_networkNavAutoScaleBytesPerSec,
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.network.summary"),
                QStringLiteral("下 %1 / 上 %2"))
            .arg(formatRateText(networkRxBytesPerSec))
            .arg(formatRateText(networkTxBytesPerSec)));
    }

    if (m_gpuNavCard != nullptr)
    {
        m_gpuNavCard->setSubtitleText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.gpu.summary"),
                QStringLiteral("%1%  %2/%3 GB"))
            .arg(gpuUsagePercent, 0, 'f', 0)
            .arg(formatGpuMemoryUsageGiBText(
                m_gpuDedicatedUsedGiB,
                m_gpuDedicatedUsageAvailable,
                1))
            .arg((m_gpuDedicatedMemoryGiB > 0.0 ? m_gpuDedicatedMemoryGiB : m_gpuDedicatedBudgetGiB), 0, 'f', 1));
        m_gpuNavCard->appendSample(gpuUsagePercent);
    }
}

void HardwareDock::updateAdditionalDiskUtilizationDevices(const std::vector<DiskRateSample>& sampleList)
{
    for (int sampleIndex = 0; sampleIndex < static_cast<int>(sampleList.size()); ++sampleIndex)
    {
        const DiskRateSample& sample = sampleList[static_cast<std::size_t>(sampleIndex)];
        const int deviceIndex = ensureDiskUtilizationDevice(sample, sampleIndex);
        if (deviceIndex < 0 || deviceIndex >= static_cast<int>(m_diskUtilDevices.size()))
        {
            continue;
        }
        updateDiskUtilizationDevice(m_diskUtilDevices[static_cast<std::size_t>(deviceIndex)], sample);
    }
}

void HardwareDock::updateAdditionalNetworkUtilizationDevices(const std::vector<NetworkRateSample>& sampleList)
{
    for (int sampleIndex = 0; sampleIndex < static_cast<int>(sampleList.size()); ++sampleIndex)
    {
        const NetworkRateSample& sample = sampleList[static_cast<std::size_t>(sampleIndex)];
        const int deviceIndex = ensureNetworkUtilizationDevice(sample, sampleIndex);
        if (deviceIndex < 0 || deviceIndex >= static_cast<int>(m_networkUtilDevices.size()))
        {
            continue;
        }
        updateNetworkUtilizationDevice(m_networkUtilDevices[static_cast<std::size_t>(deviceIndex)], sample);
    }
}

void HardwareDock::updateAdditionalGpuUtilizationDevices(const std::vector<GpuUsageSample>& sampleList)
{
    for (int sampleIndex = 0; sampleIndex < static_cast<int>(sampleList.size()); ++sampleIndex)
    {
        const GpuUsageSample& sample = sampleList[static_cast<std::size_t>(sampleIndex)];
        const int deviceIndex = ensureGpuUtilizationDevice(sample, sampleIndex);
        if (deviceIndex < 0 || deviceIndex >= static_cast<int>(m_gpuUtilDevices.size()))
        {
            continue;
        }
        updateGpuUtilizationDevice(m_gpuUtilDevices[static_cast<std::size_t>(deviceIndex)], sample);
    }
}

void HardwareDock::updateDiskUtilizationDevice(
    DiskUtilizationDevice& device,
    const DiskRateSample& sample)
{
    if (device.summaryLabel != nullptr)
    {
        device.summaryLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.disk.summary"),
                QStringLiteral("读取：%1    写入：%2"))
            .arg(formatRateText(sample.readBytesPerSec))
            .arg(formatRateText(sample.writeBytesPerSec)));
    }

    appendFilledSeriesPoint(
        device.readLineSeries,
        device.readBaselineSeries,
        device.axisX,
        device.axisY,
        sample.readBytesPerSec,
        0.0);
    appendFilledSeriesPoint(
        device.writeLineSeries,
        device.writeBaselineSeries,
        device.axisX,
        device.axisY,
        sample.writeBytesPerSec,
        0.0);
    updateSharedSeriesAxisRange(
        device.readLineSeries,
        device.writeLineSeries,
        device.axisX,
        device.axisY,
        0.0);

    if (device.navCard != nullptr)
    {
        rebuildDualRateNavCard(
            device.navCard,
            &device.readHistoryBytesPerSec,
            &device.writeHistoryBytesPerSec,
            sample.readBytesPerSec,
            sample.writeBytesPerSec,
            &device.navAutoScaleBytesPerSec,
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.disk.summary"),
                QStringLiteral("读 %1 / 写 %2"))
            .arg(formatRateText(sample.readBytesPerSec))
            .arg(formatRateText(sample.writeBytesPerSec)));
    }

    if (device.detailLabel != nullptr)
    {
        const double totalRate = std::max(0.0, sample.readBytesPerSec)
            + std::max(0.0, sample.writeBytesPerSec);
        const double approxPercent = std::clamp(
            totalRate / std::max(1.0, device.navAutoScaleBytesPerSec) * 100.0,
            0.0,
            100.0);
        device.detailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.disk.detail"),
                QStringLiteral(
                "活动时间(近似): %1%\n"
                "读取速度: %2\n"
                "写入速度: %3\n"
                "性能计数器实例: %4"))
            .arg(approxPercent, 0, 'f', 1)
            .arg(formatRateText(sample.readBytesPerSec))
            .arg(formatRateText(sample.writeBytesPerSec))
            .arg(sample.instanceNameText));
    }
}

void HardwareDock::updateNetworkUtilizationDevice(
    NetworkUtilizationDevice& device,
    const NetworkRateSample& sample)
{
    if (device.summaryLabel != nullptr)
    {
        device.summaryLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.network.summary"),
                QStringLiteral("接收：%1    发送：%2"))
            .arg(formatRateText(sample.rxBytesPerSec))
            .arg(formatRateText(sample.txBytesPerSec)));
    }

    appendFilledSeriesPoint(
        device.rxLineSeries,
        device.rxBaselineSeries,
        device.axisX,
        device.axisY,
        sample.rxBytesPerSec,
        0.0);
    appendFilledSeriesPoint(
        device.txLineSeries,
        device.txBaselineSeries,
        device.axisX,
        device.axisY,
        sample.txBytesPerSec,
        0.0);
    updateSharedSeriesAxisRange(
        device.rxLineSeries,
        device.txLineSeries,
        device.axisX,
        device.axisY,
        0.0);

    if (device.navCard != nullptr)
    {
        rebuildDualRateNavCard(
            device.navCard,
            &device.rxHistoryBytesPerSec,
            &device.txHistoryBytesPerSec,
            sample.rxBytesPerSec,
            sample.txBytesPerSec,
            &device.navAutoScaleBytesPerSec,
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.network.summary"),
                QStringLiteral("下 %1 / 上 %2"))
            .arg(formatRateText(sample.rxBytesPerSec))
            .arg(formatRateText(sample.txBytesPerSec)));
    }

    if (device.detailLabel != nullptr)
    {
        const double linkMbps = static_cast<double>(sample.linkBitsPerSecond) / (1000.0 * 1000.0);
        device.detailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.network.detail"),
                QStringLiteral(
                "适配器: %1\n"
                "发送: %2\n"
                "接收: %3\n"
                "链路速度: %4 Mbps"))
            .arg(sample.displayNameText.isEmpty() ? QStringLiteral("N/A") : sample.displayNameText)
            .arg(formatRateText(sample.txBytesPerSec))
            .arg(formatRateText(sample.rxBytesPerSec))
            .arg(linkMbps > 0.0 ? QString::number(linkMbps, 'f', 1) : QStringLiteral("N/A")));
    }
}

void HardwareDock::updateGpuUtilizationDevice(
    GpuUtilizationDevice& device,
    const GpuUsageSample& sample)
{
    const double dedicatedCapacityGiB = sample.dedicatedMemoryGiB > 0.0
        ? sample.dedicatedMemoryGiB
        : sample.dedicatedBudgetGiB;
    const double sharedCapacityGiB = sample.sharedMemoryGiB > 0.0
        ? sample.sharedMemoryGiB
        : sample.sharedBudgetGiB;
    const QString currentCoreClockText = formatGpuClockMhzText(sample.currentCoreClockMhz);
    const QString maxCoreClockText = formatGpuClockMhzText(sample.maxCoreClockMhz);
    const QString currentMemoryClockText = formatGpuClockMhzText(sample.currentMemoryClockMhz);
    const QString maxMemoryClockText = formatGpuClockMhzText(sample.maxMemoryClockMhz);

    if (device.adapterTitleLabel != nullptr)
    {
        device.adapterTitleLabel->setText(
            sample.displayNameText.isEmpty() ? QStringLiteral("N/A") : sample.displayNameText);
    }
    if (device.summaryLabel != nullptr)
    {
        device.summaryLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.gpu.summary"),
                QStringLiteral("GPU 当前利用率：%1%    3D：%2%    Copy：%3%    核心频率：%4 MHz"))
            .arg(sample.overallUsagePercent, 0, 'f', 1)
            .arg(sample.usage3DPercent, 0, 'f', 1)
            .arg(sample.usageCopyPercent, 0, 'f', 1)
            .arg(currentCoreClockText));
    }

    for (GpuEngineChartEntry& chartEntry : device.engineCharts)
    {
        double usagePercent = 0.0;
        if (chartEntry.engineKeyText == QStringLiteral("3d"))
        {
            usagePercent = sample.usage3DPercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("copy"))
        {
            usagePercent = sample.usageCopyPercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_encode"))
        {
            usagePercent = sample.usageVideoEncodePercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_decode"))
        {
            usagePercent = sample.usageVideoDecodePercent;
        }
        appendFilledSeriesPoint(
            chartEntry.lineSeries,
            chartEntry.baselineSeries,
            chartEntry.axisX,
            chartEntry.axisY,
            usagePercent,
            0.0);
        if (chartEntry.titleLabel != nullptr)
        {
            chartEntry.titleLabel->setText(
                QStringLiteral("%1  %2%")
                .arg(chartEntry.displayNameText)
                .arg(usagePercent, 0, 'f', 1));
        }
    }

    appendFilledSeriesPoint(
        device.dedicatedMemoryLineSeries,
        device.dedicatedMemoryBaselineSeries,
        device.dedicatedMemoryAxisX,
        device.dedicatedMemoryAxisY,
        sample.dedicatedUsedGiB,
        0.0);
    appendFilledSeriesPoint(
        device.sharedMemoryLineSeries,
        device.sharedMemoryBaselineSeries,
        device.sharedMemoryAxisX,
        device.sharedMemoryAxisY,
        sample.sharedUsedGiB,
        0.0);
    if (device.dedicatedMemoryAxisY != nullptr)
    {
        const double dedicatedUpperGiB = std::max(
            0.5,
            dedicatedCapacityGiB);
        device.dedicatedMemoryAxisY->setRange(0.0, dedicatedUpperGiB);
    }
    if (device.sharedMemoryAxisY != nullptr)
    {
        device.sharedMemoryAxisY->setRange(0.0, std::max(0.5, sharedCapacityGiB));
    }
    if (device.dedicatedMemoryChartView != nullptr
        && device.dedicatedMemoryChartView->chart() != nullptr)
    {
        device.dedicatedMemoryChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.dedicated_memory_title"),
                QStringLiteral("专用 GPU 内存利用率  %1 / %2 GiB"))
            .arg(formatGpuMemoryUsageGiBText(
                sample.dedicatedUsedGiB,
                sample.dedicatedUsageAvailable))
            .arg(dedicatedCapacityGiB, 0, 'f', 2));
    }
    if (device.sharedMemoryChartView != nullptr
        && device.sharedMemoryChartView->chart() != nullptr)
    {
        device.sharedMemoryChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.shared_memory_title"),
                QStringLiteral("共享 GPU 内存利用率  %1 / %2 GiB"))
            .arg(formatGpuMemoryUsageGiBText(
                sample.sharedUsedGiB,
                sample.sharedUsageAvailable))
            .arg(sharedCapacityGiB, 0, 'f', 2));
    }
    if (device.detailLabel != nullptr)
    {
        device.detailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.gpu.detail"),
                QStringLiteral(
                "利用率: %1%\n"
                "3D: %2%   Copy: %3%   Video Encode: %4%   Video Decode: %5%\n"
                "核心频率: %6 MHz（最大 %7 MHz）\n"
                "显存频率: %8 MHz（最大 %9 MHz）\n"
                "专用显存: %10 / %11 GiB\n"
                "共享显存: %12 / %13 GiB\n"
                "适配器索引: %14"))
            .arg(sample.overallUsagePercent, 0, 'f', 1)
            .arg(sample.usage3DPercent, 0, 'f', 1)
            .arg(sample.usageCopyPercent, 0, 'f', 1)
            .arg(sample.usageVideoEncodePercent, 0, 'f', 1)
            .arg(sample.usageVideoDecodePercent, 0, 'f', 1)
            .arg(currentCoreClockText)
            .arg(maxCoreClockText)
            .arg(currentMemoryClockText)
            .arg(maxMemoryClockText)
            .arg(formatGpuMemoryUsageGiBText(
                sample.dedicatedUsedGiB,
                sample.dedicatedUsageAvailable))
            .arg(dedicatedCapacityGiB, 0, 'f', 2)
            .arg(formatGpuMemoryUsageGiBText(
                sample.sharedUsedGiB,
                sample.sharedUsageAvailable))
            .arg(sharedCapacityGiB, 0, 'f', 2)
            .arg(sample.adapterIndex));
    }
    if (device.navCard != nullptr)
    {
        device.navCard->setSubtitleText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.gpu.summary"),
                QStringLiteral("%1%  %2/%3 GB"))
            .arg(sample.overallUsagePercent, 0, 'f', 0)
            .arg(formatGpuMemoryUsageGiBText(
                sample.dedicatedUsedGiB,
                sample.dedicatedUsageAvailable,
                1))
            .arg(dedicatedCapacityGiB, 0, 'f', 1));
        device.navCard->appendSample(sample.overallUsagePercent);
    }
}

void HardwareDock::updateTaskManagerDetailLabels(
    const std::vector<double>& coreUsageList,
    const std::vector<CpuPowerSnapshot>& powerInfoList,
    const double memoryUsagePercent,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    // 平均 CPU 利用率用于 CPU 详情页核心统计。
    double averageCpuUsage = 0.0;
    if (!coreUsageList.empty())
    {
        for (const double usageValue : coreUsageList)
        {
            averageCpuUsage += usageValue;
        }
        averageCpuUsage /= static_cast<double>(coreUsageList.size());
    }

    // CallNtPowerInformation 在现代 HWP/CPPC 平台通常只返回基础频率；
    // “速度”优先使用本轮 PDH 有效频率，Power API 仅作为不支持计数器时的回退。
    double currentMhzSum = 0.0;
    double maxMhzSum = 0.0;
    int cpuPowerCount = 0;
    for (const CpuPowerSnapshot& snapshot : powerInfoList)
    {
        if (snapshot.currentMhz > 0)
        {
            currentMhzSum += static_cast<double>(snapshot.currentMhz);
        }
        if (snapshot.maxMhz > 0)
        {
            maxMhzSum += static_cast<double>(snapshot.maxMhz);
        }
        ++cpuPowerCount;
    }
    const double powerApiCurrentCpuGhz = cpuPowerCount > 0
        ? (currentMhzSum / static_cast<double>(cpuPowerCount) / 1000.0)
        : 0.0;
    const double currentCpuGhz = m_lastCpuSpeedGhz > 0.0
        ? m_lastCpuSpeedGhz
        : powerApiCurrentCpuGhz;
    const double baseCpuGhz = cpuPowerCount > 0
        ? (maxMhzSum / static_cast<double>(cpuPowerCount) / 1000.0)
        : 0.0;
    m_lastCpuSpeedGhz = currentCpuGhz;
    const UtilizationStatisticSnapshot cpuStats = buildStatisticSnapshot(m_cpuUsageHistoryPercent);

    // 系统性能快照用于进程/线程/句柄与提交内存统计。
    SystemPerformanceSnapshot perfSnapshot;
    const bool perfOk = sampleSystemPerformanceSnapshot(&perfSnapshot);

    // uptimeSeconds 用途：系统已运行秒数，显示为任务管理器风格时间串。
    const std::uint64_t uptimeSeconds = static_cast<std::uint64_t>(::GetTickCount64() / 1000ULL);
    if (m_cpuUtilPrimaryDetailLabel != nullptr)
    {
        // buildMetricCellHtml 用途：把一个任务管理器式“灰色标签 + 大号数值”生成表格单元格。
        // 输入为已本地化标签、已格式化数值和字号；返回可直接交给 QLabel 的安全富文本。
        const auto buildMetricCellHtml =
            [](const QString& labelText, const QString& valueText, const int valueFontSize)
            {
                return QStringLiteral(
                    "<td style=\"padding-right:18px;vertical-align:top;\">"
                    "<span style=\"color:%1;font-size:13px;\">%2</span><br/>"
                    "<span style=\"color:%3;font-size:%4px;font-weight:400;\">%5</span>"
                    "</td>")
                    // 这里是 QLabel 富文本，不是 QSS：QTextDocument 的 CSS 解析器不认
                    // palette(...)（那是 QSS 专有扩展），动态角色会被整条忽略、颜色退回继承色。
                    // 富文本一律用 *ColorHex() 求出具体色；本单元格每轮采样都会重新生成，
                    // 主题切换后下一次刷新即跟随。
                    .arg(KswordTheme::TextSecondaryColorHex())
                    .arg(labelText.toHtmlEscaped())
                    .arg(KswordTheme::TextPrimaryColorHex())
                    .arg(valueFontSize)
                    .arg(valueText.toHtmlEscaped());
            };

        // primaryHtml 用途：把关键指标按截图分成利用率/速度、计数和运行时间三行。
        const QString primaryHtml =
            QStringLiteral("<table cellspacing=\"0\" cellpadding=\"0\">"
                "<tr>%1%2</tr>"
                "<tr>%3%4%5</tr>"
                "<tr>%6</tr>"
                "</table>")
            .arg(buildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.utilization"),
                    QStringLiteral("利用率")),
                QStringLiteral("%1%").arg(averageCpuUsage, 0, 'f', 0),
                30))
            .arg(buildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.speed"),
                    QStringLiteral("速度")),
                QStringLiteral("%1 GHz").arg(currentCpuGhz, 0, 'f', 2),
                30))
            .arg(buildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.processes"),
                    QStringLiteral("进程")),
                perfOk ? QString::number(perfSnapshot.processCount) : QStringLiteral("N/A"),
                25))
            .arg(buildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.threads"),
                    QStringLiteral("线程")),
                perfOk ? QString::number(perfSnapshot.threadCount) : QStringLiteral("N/A"),
                25))
            .arg(buildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.handles"),
                    QStringLiteral("句柄")),
                perfOk ? QString::number(perfSnapshot.handleCount) : QStringLiteral("N/A"),
                25))
            .arg(buildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.uptime"),
                    QStringLiteral("正常运行时间")),
                formatDurationText(uptimeSeconds),
                25));
        m_cpuUtilPrimaryDetailLabel->setText(primaryHtml);
        m_cpuUtilPrimaryDetailLabel->setToolTip(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.cpu.metric.statistics.tooltip"),
                QStringLiteral("均值：%1% | 峰值：%2% | 趋势：%3"))
            .arg(cpuStats.averageValue, 0, 'f', 1)
            .arg(cpuStats.peakValue, 0, 'f', 1)
            .arg(buildTrendText(cpuStats, true)));
    }

    if (m_cpuUtilSecondaryDetailLabel != nullptr)
    {
        m_cpuUtilSecondaryDetailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.cpu.detail.secondary"),
                QStringLiteral(
                "基准速度: %1 GHz\n"
                "插槽: %2\n"
                "内核: %3\n"
                "逻辑处理器: %4\n"
                "压力等级: %5"))
            .arg(baseCpuGhz, 0, 'f', 2)
            .arg(m_cpuPackageCount > 0 ? QString::number(m_cpuPackageCount) : QStringLiteral("N/A"))
            .arg(m_cpuPhysicalCoreCount > 0 ? QString::number(m_cpuPhysicalCoreCount) : QStringLiteral("N/A"))
            .arg(m_cpuLogicalCoreCount > 0 ? QString::number(m_cpuLogicalCoreCount) : QStringLiteral("N/A"))
            .arg(buildPressureLevelText(averageCpuUsage)));
    }

    if (m_cpuUtilTertiaryDetailLabel != nullptr)
    {
        m_cpuUtilTertiaryDetailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.cpu.detail.tertiary"),
                QStringLiteral(
                "L1缓存: %1\n"
                "L2缓存: %2\n"
                "L3缓存: %3\n"
                "%4\n"
                "%5"))
            .arg(m_cpuL1CacheBytes > 0 ? bytesToReadableText(static_cast<double>(m_cpuL1CacheBytes)) : QStringLiteral("N/A"))
            .arg(m_cpuL2CacheBytes > 0 ? bytesToReadableText(static_cast<double>(m_cpuL2CacheBytes)) : QStringLiteral("N/A"))
            .arg(m_cpuL3CacheBytes > 0 ? bytesToReadableText(static_cast<double>(m_cpuL3CacheBytes)) : QStringLiteral("N/A"))
            .arg(m_r0HardwareHealthSummaryText)
            .arg(m_r0CpuHardwareSummaryText));

        // r0AuditToolTip 用途：保留完整审计文本，同时避免长行重新挤高任务管理器式主视图。
        const QString r0AuditToolTip = m_r0HardwareHealthDetailText
            + QStringLiteral("\n\n")
            + m_r0CpuHardwareDetailText;
        m_cpuUtilSecondaryDetailLabel->setToolTip(r0AuditToolTip);
        m_cpuUtilTertiaryDetailLabel->setToolTip(r0AuditToolTip);
    }

    // CPU 详情标签在首帧只显示一行“采样中”文本，随后会替换为多行实时数据。
    // 此处重新计算图表区与详情区高度，确保图表主动收缩而不是裁切底部文字。
    // 调用方式：两组详情文本均写入后调用；函数内部仅在尺寸变化时更新布局。
    // 返回行为：无返回值，CPU 页面会在当前事件循环内按最新文本高度完成重排。
    adjustUtilizationChartHeights();

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    const bool memoryStatusOk = (::GlobalMemoryStatusEx(&memoryStatus) == TRUE);
    if (memoryStatusOk)
    {
        const double totalGiB = static_cast<double>(memoryStatus.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0);
        const double availableGiB = static_cast<double>(memoryStatus.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
        const double usedGiB = totalGiB - availableGiB;
        if (m_memoryCapacityLabel != nullptr)
        {
            m_memoryCapacityLabel->setText(QStringLiteral("%1 GB").arg(totalGiB, 0, 'f', 1));
        }
        if (m_memoryUtilPrimaryDetailLabel != nullptr)
        {
            const UtilizationStatisticSnapshot memoryStats = buildStatisticSnapshot(m_memoryUsageHistoryPercent);
            m_memoryUtilPrimaryDetailLabel->setText(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.memory.detail.primary"),
                    QStringLiteral(
                    "使用中(含缓存): %1 GB\n"
                    "当前利用率: %2%\n"
                    "均值: %3%   峰值: %4%   趋势: %5\n"
                    "已提交: %6 / %7\n"
                    "已缓存: %8\n"
                    "分页池: %9\n"
                    "非分页池: %10"))
                .arg(usedGiB, 0, 'f', 1)
                .arg(memoryUsagePercent, 0, 'f', 1)
                .arg(memoryStats.averageValue, 0, 'f', 1)
                .arg(memoryStats.peakValue, 0, 'f', 1)
                .arg(buildTrendText(memoryStats, true))
                .arg(perfOk ? bytesToReadableText(static_cast<double>(perfSnapshot.commitTotalBytes)) : QStringLiteral("N/A"))
                .arg(perfOk ? bytesToReadableText(static_cast<double>(perfSnapshot.commitLimitBytes)) : QStringLiteral("N/A"))
                .arg(perfOk ? bytesToReadableText(static_cast<double>(perfSnapshot.cachedBytes)) : QStringLiteral("N/A"))
                .arg(perfOk ? bytesToReadableText(static_cast<double>(perfSnapshot.pagedPoolBytes)) : QStringLiteral("N/A"))
                .arg(perfOk ? bytesToReadableText(static_cast<double>(perfSnapshot.nonPagedPoolBytes)) : QStringLiteral("N/A")));
        }
    }

    if (m_memoryUtilSecondaryDetailLabel != nullptr)
    {
        ULONGLONG installedMemoryKb = 0;
        ::GetPhysicallyInstalledSystemMemory(&installedMemoryKb);
        const double installedBytes = static_cast<double>(installedMemoryKb) * 1024.0;
        const double reservedBytes = memoryStatusOk
            ? std::max(0.0, installedBytes - static_cast<double>(memoryStatus.ullTotalPhys))
            : 0.0;
        m_memoryUtilSecondaryDetailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.memory.detail.secondary"),
                QStringLiteral(
                "速度: %1 MHz\n"
                "已使用插槽: %2/%3\n"
                "外形规格: %4\n"
                "硬件保留内存: %5\n"
                "%6"))
            .arg(m_memorySpeedMhz > 0 ? QString::number(m_memorySpeedMhz) : QStringLiteral("N/A"))
            .arg(m_memorySlotUsed > 0 ? QString::number(m_memorySlotUsed) : QStringLiteral("N/A"))
            .arg(m_memorySlotTotal > 0 ? QString::number(m_memorySlotTotal) : QStringLiteral("N/A"))
            .arg(m_memoryFormFactorText.isEmpty() ? QStringLiteral("N/A") : m_memoryFormFactorText)
            .arg(bytesToReadableText(reservedBytes))
            .arg(m_r0PhysicalMemoryDetailText));
    }

    if ((m_sampleCounter % 15) == 1)
    {
        refreshSystemVolumeInfo();
    }
    if (m_diskUtilDetailLabel != nullptr)
    {
        const double diskTotalRate = std::max(0.0, diskReadBytesPerSec) + std::max(0.0, diskWriteBytesPerSec);
        const double diskApproxPercent = std::clamp(
            diskTotalRate / std::max(1.0, m_diskNavAutoScaleBytesPerSec) * 100.0,
            0.0,
            100.0);
        const UtilizationStatisticSnapshot diskStats = buildStatisticSnapshot(m_diskAggregateHistoryBytesPerSec);
        m_diskUtilDetailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.disk.detail"),
                QStringLiteral(
                "活动时间(近似): %1%\n"
                "当前合计: %2\n"
                "均值: %3\n"
                "峰值: %4\n"
                "趋势: %5\n"
                "系统卷: %6\n"
                "总容量: %7\n"
                "可用: %8"))
            .arg(diskApproxPercent, 0, 'f', 1)
            .arg(formatRateText(diskTotalRate))
            .arg(formatRateText(diskStats.averageValue))
            .arg(formatRateText(diskStats.peakValue))
            .arg(buildTrendText(diskStats, false))
            .arg(m_systemVolumeText.isEmpty() ? QStringLiteral("N/A") : m_systemVolumeText)
            .arg(m_systemVolumeTotalBytes > 0
                ? bytesToReadableText(static_cast<double>(m_systemVolumeTotalBytes))
                : QStringLiteral("N/A"))
            .arg(m_systemVolumeFreeBytes > 0
                ? bytesToReadableText(static_cast<double>(m_systemVolumeFreeBytes))
                : QStringLiteral("N/A")));
    }

    if (m_networkUtilDetailLabel != nullptr)
    {
        const QString adapterText = m_primaryNetworkAdapterName.isEmpty()
            ? QStringLiteral("N/A")
            : m_primaryNetworkAdapterName;
        const double linkMbps = static_cast<double>(m_primaryNetworkLinkBitsPerSecond) / (1000.0 * 1000.0);
        const UtilizationStatisticSnapshot networkStats = buildStatisticSnapshot(m_networkAggregateHistoryBytesPerSec);
        m_networkUtilDetailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.network.detail"),
                QStringLiteral(
                "适配器: %1\n"
                "发送: %2\n"
                "接收: %3\n"
                "合计: %4\n"
                "均值: %5\n"
                "峰值: %6\n"
                "趋势: %7\n"
                "链路速度: %8 Mbps"))
            .arg(adapterText)
            .arg(formatRateText(networkTxBytesPerSec))
            .arg(formatRateText(networkRxBytesPerSec))
            .arg(formatRateText(networkRxBytesPerSec + networkTxBytesPerSec))
            .arg(formatRateText(networkStats.averageValue))
            .arg(formatRateText(networkStats.peakValue))
            .arg(buildTrendText(networkStats, false))
            .arg(linkMbps > 0.0 ? QString::number(linkMbps, 'f', 1) : QStringLiteral("N/A")));
    }

    const double gpuDedicatedCapacityGiB = m_gpuDedicatedMemoryGiB > 0.0
        ? m_gpuDedicatedMemoryGiB
        : m_gpuDedicatedBudgetGiB;
    const double gpuSharedCapacityGiB = m_gpuSharedMemoryGiB > 0.0
        ? m_gpuSharedMemoryGiB
        : m_gpuSharedBudgetGiB;
    const QString gpuCurrentCoreClockText = formatGpuClockMhzText(m_gpuCurrentCoreClockMhz);
    const QString gpuMaxCoreClockText = formatGpuClockMhzText(m_gpuMaxCoreClockMhz);
    const QString gpuCurrentMemoryClockText = formatGpuClockMhzText(m_gpuCurrentMemoryClockMhz);
    const QString gpuMaxMemoryClockText = formatGpuClockMhzText(m_gpuMaxMemoryClockMhz);

    if (m_gpuAdapterTitleLabel != nullptr)
    {
        m_gpuAdapterTitleLabel->setText(
            m_gpuAdapterNameText.isEmpty() ? QStringLiteral("N/A") : m_gpuAdapterNameText);
    }
    if (m_gpuDedicatedMemoryChartView != nullptr
        && m_gpuDedicatedMemoryChartView->chart() != nullptr)
    {
        m_gpuDedicatedMemoryChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.dedicated_memory_title"),
                QStringLiteral("专用 GPU 内存利用率  %1 / %2 GiB"))
            .arg(formatGpuMemoryUsageGiBText(
                m_gpuDedicatedUsedGiB,
                m_gpuDedicatedUsageAvailable))
            .arg(gpuDedicatedCapacityGiB, 0, 'f', 2));
    }
    if (m_gpuSharedMemoryChartView != nullptr
        && m_gpuSharedMemoryChartView->chart() != nullptr)
    {
        m_gpuSharedMemoryChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.shared_memory_title"),
                QStringLiteral("共享 GPU 内存利用率  %1 / %2 GiB"))
            .arg(formatGpuMemoryUsageGiBText(
                m_gpuSharedUsedGiB,
                m_gpuSharedUsageAvailable))
            .arg(gpuSharedCapacityGiB, 0, 'f', 2));
    }

    if (m_gpuUtilDetailLabel != nullptr)
    {
        const UtilizationStatisticSnapshot gpuStats = buildStatisticSnapshot(m_gpuUsageHistoryPercent);
        m_gpuUtilDetailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.detail"),
                QStringLiteral(
                "利用率: %1%\n"
                "均值: %2%   峰值: %3%   趋势: %4\n"
                "3D: %5%   Copy: %6%   Video Encode: %7%   Video Decode: %8%\n"
                "核心频率: %9 MHz（最大 %10 MHz）\n"
                "显存频率: %11 MHz（最大 %12 MHz）\n"
                "专用显存: %13 / %14 GiB\n"
                "共享显存: %15 / %16 GiB\n"
                "驱动版本: %17\n"
                "驱动日期: %18\n"
                "PNP: %19"))
            .arg(gpuUsagePercent, 0, 'f', 1)
            .arg(gpuStats.averageValue, 0, 'f', 1)
            .arg(gpuStats.peakValue, 0, 'f', 1)
            .arg(buildTrendText(gpuStats, true))
            .arg(m_gpuUsage3DPercent, 0, 'f', 1)
            .arg(m_gpuUsageCopyPercent, 0, 'f', 1)
            .arg(m_gpuUsageVideoEncodePercent, 0, 'f', 1)
            .arg(m_gpuUsageVideoDecodePercent, 0, 'f', 1)
            .arg(gpuCurrentCoreClockText)
            .arg(gpuMaxCoreClockText)
            .arg(gpuCurrentMemoryClockText)
            .arg(gpuMaxMemoryClockText)
            .arg(formatGpuMemoryUsageGiBText(
                m_gpuDedicatedUsedGiB,
                m_gpuDedicatedUsageAvailable))
            .arg(gpuDedicatedCapacityGiB, 0, 'f', 2)
            .arg(formatGpuMemoryUsageGiBText(
                m_gpuSharedUsedGiB,
                m_gpuSharedUsageAvailable))
            .arg(gpuSharedCapacityGiB, 0, 'f', 2)
            .arg(m_gpuDriverVersionText.isEmpty() ? QStringLiteral("N/A") : m_gpuDriverVersionText)
            .arg(m_gpuDriverDateText.isEmpty() ? QStringLiteral("N/A") : m_gpuDriverDateText)
            .arg(m_gpuPnpDeviceIdText.isEmpty() ? QStringLiteral("N/A") : m_gpuPnpDeviceIdText));
    }
}

void HardwareDock::updateCpuDetailTable(
    const std::vector<double>& coreUsageList,
    const std::vector<CpuPowerSnapshot>& powerInfoList)
{
    if (m_cpuDetailTable == nullptr)
    {
        return;
    }

    const int rowCount = std::max(
        static_cast<int>(coreUsageList.size()),
        static_cast<int>(powerInfoList.size()));
    m_cpuDetailTable->setRowCount(rowCount);

    const QString sensorText = buildCpuSensorText(false);
    QString temperatureText = QStringLiteral("N/A");
    QString voltageText = QStringLiteral("N/A");
    const QStringList sensorParts = sensorText.split('|');
    if (sensorParts.size() >= 2)
    {
        temperatureText = sensorParts.at(0);
        voltageText = sensorParts.at(1);
    }

    for (int rowIndex = 0; rowIndex < rowCount; ++rowIndex)
    {
        const QString coreName = QStringLiteral("CPU %1").arg(rowIndex);
        const QString usageText = rowIndex < static_cast<int>(coreUsageList.size())
            ? QString::number(coreUsageList[static_cast<std::size_t>(rowIndex)], 'f', 1)
            : QStringLiteral("0.0");

        QString currentMhzText = QStringLiteral("N/A");
        QString maxMhzText = QStringLiteral("N/A");
        QString limitMhzText = QStringLiteral("N/A");
        if (rowIndex < static_cast<int>(powerInfoList.size()))
        {
            const CpuPowerSnapshot& snapshot = powerInfoList[static_cast<std::size_t>(rowIndex)];
            currentMhzText = QString::number(snapshot.currentMhz);
            maxMhzText = QString::number(snapshot.maxMhz);
            limitMhzText = QString::number(snapshot.limitMhz);
        }

        m_cpuDetailTable->setItem(rowIndex, 0, new QTableWidgetItem(coreName));
        m_cpuDetailTable->setItem(rowIndex, 1, new QTableWidgetItem(usageText));
        m_cpuDetailTable->setItem(rowIndex, 2, new QTableWidgetItem(currentMhzText));
        m_cpuDetailTable->setItem(rowIndex, 3, new QTableWidgetItem(maxMhzText));
        m_cpuDetailTable->setItem(rowIndex, 4, new QTableWidgetItem(limitMhzText));
        m_cpuDetailTable->setItem(rowIndex, 5, new QTableWidgetItem(temperatureText));
        m_cpuDetailTable->setItem(rowIndex, 6, new QTableWidgetItem(voltageText));
    }

    if (m_cpuDetailLabel != nullptr)
    {
        m_cpuDetailLabel->setText(
            QStringLiteral("CPU传感器：温度=%1，电压=%2（不可读时显示N/A）")
            .arg(temperatureText)
            .arg(voltageText));
    }
}

void HardwareDock::appendCoreSeriesPoint(CoreChartEntry& chartEntry, const double usagePercent)
{
    if (chartEntry.lineSeries == nullptr
        || chartEntry.baselineSeries == nullptr
        || chartEntry.axisX == nullptr
        || chartEntry.axisY == nullptr)
    {
        return;
    }

    chartEntry.lineSeries->append(m_sampleCounter, usagePercent);
    chartEntry.baselineSeries->append(m_sampleCounter, 0.0);
    while (chartEntry.lineSeries->count() > m_historyLength)
    {
        chartEntry.lineSeries->remove(0);
    }
    while (chartEntry.baselineSeries->count() > m_historyLength)
    {
        chartEntry.baselineSeries->remove(0);
    }

    const QList<QPointF> pointList = chartEntry.lineSeries->points();
    if (!pointList.isEmpty())
    {
        const double firstX = pointList.first().x();
        const double lastX = pointList.last().x();
        if (qFuzzyCompare(firstX, lastX))
        {
            animateLiveValueAxisRange(chartEntry.axisX, firstX - 1.0, lastX + 1.0);
        }
        else
        {
            animateLiveValueAxisRange(chartEntry.axisX, firstX, lastX);
        }
    }
    chartEntry.axisY->setRange(0.0, 100.0);
}

void HardwareDock::appendGeneralSeriesPoint(
    QLineSeries* lineSeries,
    QValueAxis* axisX,
    QValueAxis* axisY,
    const double sampleValue,
    const double minAxisYValue)
{
    if (lineSeries == nullptr || axisX == nullptr || axisY == nullptr)
    {
        return;
    }

    lineSeries->append(m_sampleCounter, sampleValue);
    while (lineSeries->count() > m_historyLength)
    {
        lineSeries->remove(0);
    }

    const QList<QPointF> pointList = lineSeries->points();
    if (pointList.isEmpty())
    {
        return;
    }

    const double firstX = pointList.first().x();
    const double lastX = pointList.last().x();
    if (qFuzzyCompare(firstX, lastX))
    {
        animateLiveValueAxisRange(axisX, firstX - 1.0, lastX + 1.0);
    }
    else
    {
        animateLiveValueAxisRange(axisX, firstX, lastX);
    }
    double maxYValue = minAxisYValue + 1.0;
    for (const QPointF& pointValue : pointList)
    {
        maxYValue = std::max(maxYValue, pointValue.y());
    }
    axisY->setRange(minAxisYValue, maxYValue * 1.15);
}

void HardwareDock::appendFilledSeriesPoint(
    QLineSeries* lineSeries,
    QLineSeries* baselineSeries,
    QValueAxis* axisX,
    QValueAxis* axisY,
    const double sampleValue,
    const double minAxisYValue)
{
    if (lineSeries == nullptr
        || baselineSeries == nullptr
        || axisX == nullptr
        || axisY == nullptr)
    {
        return;
    }

    // lineSeries 用途：保存真实采样曲线；baselineSeries 用途：保存同一 X 坐标上的下边界。
    lineSeries->append(m_sampleCounter, sampleValue);
    baselineSeries->append(m_sampleCounter, minAxisYValue);
    while (lineSeries->count() > m_historyLength)
    {
        lineSeries->remove(0);
    }
    while (baselineSeries->count() > m_historyLength)
    {
        baselineSeries->remove(0);
    }

    const QList<QPointF> pointList = lineSeries->points();
    if (pointList.isEmpty())
    {
        return;
    }

    const double firstX = pointList.first().x();
    const double lastX = pointList.last().x();
    if (qFuzzyCompare(firstX, lastX))
    {
        animateLiveValueAxisRange(axisX, firstX - 1.0, lastX + 1.0);
    }
    else
    {
        animateLiveValueAxisRange(axisX, firstX, lastX);
    }

    // maxYValue 用途：按单条曲线可见历史设置纵轴上限，共轴双线稍后由 updateSharedSeriesAxisRange 再统一。
    double maxYValue = minAxisYValue + 1.0;
    for (const QPointF& pointValue : pointList)
    {
        maxYValue = std::max(maxYValue, pointValue.y());
    }
    axisY->setRange(minAxisYValue, maxYValue * 1.15);
}

void HardwareDock::updateSharedSeriesAxisRange(
    QLineSeries* primaryLineSeries,
    QLineSeries* secondaryLineSeries,
    QValueAxis* axisX,
    QValueAxis* axisY,
    const double minAxisYValue)
{
    if (axisX == nullptr || axisY == nullptr)
    {
        return;
    }

    const QList<QPointF> primaryPointList =
        primaryLineSeries != nullptr ? primaryLineSeries->points() : QList<QPointF>();
    const QList<QPointF> secondaryPointList =
        secondaryLineSeries != nullptr ? secondaryLineSeries->points() : QList<QPointF>();
    if (primaryPointList.isEmpty() && secondaryPointList.isEmpty())
    {
        return;
    }

    // firstXValue 用途：两条曲线可见区域的最左侧采样 X 值。
    double firstXValue = std::numeric_limits<double>::max();
    // lastXValue 用途：两条曲线可见区域的最右侧采样 X 值。
    double lastXValue = std::numeric_limits<double>::lowest();
    // maxYValue 用途：两条曲线当前可见历史中的共同最大值。
    double maxYValue = minAxisYValue + 1.0;

    const auto accumulatePointRange =
        [&firstXValue, &lastXValue, &maxYValue](const QList<QPointF>& pointList)
        {
            if (pointList.isEmpty())
            {
                return;
            }

            firstXValue = std::min(firstXValue, pointList.first().x());
            lastXValue = std::max(lastXValue, pointList.last().x());
            for (const QPointF& pointValue : pointList)
            {
                maxYValue = std::max(maxYValue, pointValue.y());
            }
        };

    accumulatePointRange(primaryPointList);
    accumulatePointRange(secondaryPointList);

    if (qFuzzyCompare(firstXValue, lastXValue))
    {
        animateLiveValueAxisRange(axisX, firstXValue - 1.0, lastXValue + 1.0);
    }
    else
    {
        animateLiveValueAxisRange(axisX, firstXValue, lastXValue);
    }
    axisY->setRange(minAxisYValue, maxYValue * 1.15);
}

void HardwareDock::rebuildDualRateNavCard(
    PerformanceNavCard* navCard,
    std::vector<double>* primaryHistoryOut,
    std::vector<double>* secondaryHistoryOut,
    const double primaryBytesPerSecond,
    const double secondaryBytesPerSecond,
    double* upperBoundBytesPerSecondOut,
    const QString& subtitleText)
{
    if (navCard == nullptr
        || primaryHistoryOut == nullptr
        || secondaryHistoryOut == nullptr
        || upperBoundBytesPerSecondOut == nullptr)
    {
        return;
    }

    // safePrimaryBytesPerSecond 用途：主序列安全速率值，过滤异常负值。
    const double safePrimaryBytesPerSecond = std::max(0.0, primaryBytesPerSecond);
    // safeSecondaryBytesPerSecond 用途：次序列安全速率值，过滤异常负值。
    const double safeSecondaryBytesPerSecond = std::max(0.0, secondaryBytesPerSecond);
    const int historyCapacity = std::max(1, navCard->sampleCapacity());

    primaryHistoryOut->push_back(safePrimaryBytesPerSecond);
    secondaryHistoryOut->push_back(safeSecondaryBytesPerSecond);
    while (static_cast<int>(primaryHistoryOut->size()) > historyCapacity)
    {
        primaryHistoryOut->erase(primaryHistoryOut->begin());
    }
    while (static_cast<int>(secondaryHistoryOut->size()) > historyCapacity)
    {
        secondaryHistoryOut->erase(secondaryHistoryOut->begin());
    }

    // historyPeakBytesPerSecond 用途：缩略图可见历史中的真实峰值。
    double historyPeakBytesPerSecond = 0.0;
    for (const double historyValue : *primaryHistoryOut)
    {
        historyPeakBytesPerSecond = std::max(historyPeakBytesPerSecond, historyValue);
    }
    for (const double historyValue : *secondaryHistoryOut)
    {
        historyPeakBytesPerSecond = std::max(historyPeakBytesPerSecond, historyValue);
    }

    // 加一点顶部留白，避免峰值直接顶到边框。
    *upperBoundBytesPerSecondOut = std::max(1.0, historyPeakBytesPerSecond * 1.08);

    QVector<double> primaryPercentSampleList;
    QVector<double> secondaryPercentSampleList;
    primaryPercentSampleList.reserve(static_cast<int>(primaryHistoryOut->size()));
    secondaryPercentSampleList.reserve(static_cast<int>(secondaryHistoryOut->size()));
    for (const double historyValue : *primaryHistoryOut)
    {
        primaryPercentSampleList.push_back(std::clamp(
            historyValue / *upperBoundBytesPerSecondOut * 100.0,
            0.0,
            100.0));
    }
    for (const double historyValue : *secondaryHistoryOut)
    {
        secondaryPercentSampleList.push_back(std::clamp(
            historyValue / *upperBoundBytesPerSecondOut * 100.0,
            0.0,
            100.0));
    }

    navCard->setSubtitleText(subtitleText);
    navCard->setSampleSeries(primaryPercentSampleList, secondaryPercentSampleList);
}

QString HardwareDock::formatRateText(const double bytesPerSecondValue) const
{
    return bytesPerSecondToText(bytesPerSecondValue);
}

void HardwareDock::pushBoundedHistorySample(
    std::vector<double>* historyList,
    const double sampleValue) const
{
    if (historyList == nullptr)
    {
        return;
    }

    // historyCapacity 用途：复用主图历史长度，保持统计窗口与图表窗口一致。
    const int historyCapacity = std::max(1, m_historyLength);
    historyList->push_back(std::max(0.0, sampleValue));
    while (static_cast<int>(historyList->size()) > historyCapacity)
    {
        historyList->erase(historyList->begin());
    }
}

HardwareDock::UtilizationStatisticSnapshot HardwareDock::buildStatisticSnapshot(
    const std::vector<double>& historyList) const
{
    UtilizationStatisticSnapshot snapshot;
    if (historyList.empty())
    {
        return snapshot;
    }

    // sampleCount/average/peak/min 均基于当前可见历史窗口，而不是进程生命周期累计值。
    snapshot.sampleCount = static_cast<int>(historyList.size());
    snapshot.currentValue = historyList.back();
    snapshot.minValue = std::numeric_limits<double>::max();
    for (const double sampleValue : historyList)
    {
        const double safeSampleValue = std::max(0.0, sampleValue);
        snapshot.averageValue += safeSampleValue;
        snapshot.peakValue = std::max(snapshot.peakValue, safeSampleValue);
        snapshot.minValue = std::min(snapshot.minValue, safeSampleValue);
    }
    snapshot.averageValue /= static_cast<double>(snapshot.sampleCount);
    snapshot.trendDelta = snapshot.currentValue - std::max(0.0, historyList.front());
    if (snapshot.minValue == std::numeric_limits<double>::max())
    {
        snapshot.minValue = 0.0;
    }
    return snapshot;
}

QString HardwareDock::buildTrendText(
    const UtilizationStatisticSnapshot& snapshot,
    const bool percentUnit) const
{
    // threshold 用途：忽略极小波动，避免页面每秒在“上升/下降”之间抖动。
    const double threshold = percentUnit ? 1.0 : 1024.0;
    if (std::abs(snapshot.trendDelta) < threshold)
    {
        return QStringLiteral("平稳");
    }

    const QString directionText = snapshot.trendDelta > 0.0
        ? QStringLiteral("上升")
        : QStringLiteral("下降");
    const double absoluteDelta = std::abs(snapshot.trendDelta);
    if (percentUnit)
    {
        return QStringLiteral("%1 %2%")
            .arg(directionText)
            .arg(absoluteDelta, 0, 'f', 1);
    }
    return QStringLiteral("%1 %2")
        .arg(directionText)
        .arg(formatRateText(absoluteDelta));
}

QString HardwareDock::buildPressureLevelText(const double percentValue) const
{
    const double safePercentValue = std::clamp(percentValue, 0.0, 100.0);
    if (safePercentValue >= 90.0)
    {
        return QStringLiteral("极高");
    }
    if (safePercentValue >= 75.0)
    {
        return QStringLiteral("高");
    }
    if (safePercentValue >= 45.0)
    {
        return QStringLiteral("中");
    }
    if (safePercentValue >= 15.0)
    {
        return QStringLiteral("低");
    }
    return QStringLiteral("空闲");
}

QString HardwareDock::buildR0CpuFeatureBadgeText(const std::uint64_t featureMask) const
{
    // 输入：R0 CPUID 查询返回的 KSWORD_ARK_CPU_FEATURE_* 位图。
    // 处理：按性能/虚拟化/安全能力优先级输出短 badge，避免 UI 直接解析原始 CPUID 寄存器。
    // 返回：逗号分隔的能力文本；无可展示能力时返回 N/A。
    QStringList featureList;
    const auto appendFeatureIfPresent =
        [&featureList, featureMask](const std::uint64_t bitValue, const QString& featureName)
        {
            if ((featureMask & bitValue) != 0ULL)
            {
                featureList.append(featureName);
            }
        };

    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSE, QStringLiteral("SSE"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSE2, QStringLiteral("SSE2"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSE3, QStringLiteral("SSE3"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSSE3, QStringLiteral("SSSE3"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSE41, QStringLiteral("SSE4.1"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSE42, QStringLiteral("SSE4.2"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_AES, QStringLiteral("AES"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_AVX, QStringLiteral("AVX"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_AVX2, QStringLiteral("AVX2"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_AVX512F, QStringLiteral("AVX512F"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_VMX, QStringLiteral("VMX"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_NX, QStringLiteral("NX"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SMEP, QStringLiteral("SMEP"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SMAP, QStringLiteral("SMAP"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_RDTSCP, QStringLiteral("RDTSCP"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_INVARIANT_TSC, QStringLiteral("Invariant TSC"));
    appendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_HYPERVISOR, QStringLiteral("Hypervisor"));

    return featureList.isEmpty() ? QStringLiteral("N/A") : featureList.join(QStringLiteral(", "));
}

QString HardwareDock::buildPercentStatisticLine(
    const QString& labelText,
    const UtilizationStatisticSnapshot& snapshot) const
{
    return QStringLiteral("%1: 当前 %2% / 均值 %3% / 峰值 %4% / 趋势 %5 / 压力 %6 / 样本 %7")
        .arg(labelText)
        .arg(snapshot.currentValue, 0, 'f', 1)
        .arg(snapshot.averageValue, 0, 'f', 1)
        .arg(snapshot.peakValue, 0, 'f', 1)
        .arg(buildTrendText(snapshot, true))
        .arg(buildPressureLevelText(snapshot.currentValue))
        .arg(snapshot.sampleCount);
}

QString HardwareDock::buildRateStatisticLine(
    const QString& labelText,
    const UtilizationStatisticSnapshot& snapshot) const
{
    return QStringLiteral("%1: 当前 %2 / 均值 %3 / 峰值 %4 / 趋势 %5 / 样本 %6")
        .arg(labelText)
        .arg(formatRateText(snapshot.currentValue))
        .arg(formatRateText(snapshot.averageValue))
        .arg(formatRateText(snapshot.peakValue))
        .arg(buildTrendText(snapshot, false))
        .arg(snapshot.sampleCount);
}

void HardwareDock::requestAsyncR0HardwareHealthRefresh()
{
    // expectedFlag 用途：避免多个 R0 采样线程并发。
    bool expectedFlag = false;
    if (!m_r0HardwareHealthRefreshing.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    if (m_lastR0HardwareHealthRefreshMs > 0 && nowMs - m_lastR0HardwareHealthRefreshMs < 10'000)
    {
        m_r0HardwareHealthRefreshing.store(false);
        return;
    }

    QPointer<HardwareDock> safeThis(this);
    std::thread([safeThis, nowMs]() {
        // r0QueryLock 用途：健康查询与按需设备审计共用一条串行 R0 请求通道。
        const std::lock_guard<std::mutex> r0QueryLock(hardwareR0QueryMutex);
        const ksword::ark::DriverClient client;
        const ksword::ark::DriverCapabilitiesQueryResult capabilityResult = client.queryDriverCapabilities();
        const ksword::ark::DynDataCapabilitiesResult dynDataResult = client.queryDynDataCapabilities();
        const ksword::ark::DriverIntegrityResult integrityResult = client.queryKernelCpuIntegrity();
        const ksword::ark::CpuHardwareSnapshotResult cpuHardwareResult = client.queryCpuHardwareSnapshot();
        const ksword::ark::PhysicalMemoryLayoutResult physicalMemoryResult = client.queryPhysicalMemoryLayout();

        if (safeThis.isNull())
        {
            return;
        }

        const bool invokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, nowMs, capabilityResult, dynDataResult, integrityResult, cpuHardwareResult, physicalMemoryResult]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                const int cpuEvidenceCount = static_cast<int>(integrityResult.cpuCount);
                int idtEvidenceCount = 0;
                int msrEvidenceCount = 0;
                int highRiskCount = 0;
                int cpuProtectionRiskCount = 0;
                int unresolvedOwnerRiskCount = 0;
                for (const auto& entry : integrityResult.entries)
                {
                    if (entry.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
                    {
                        ++idtEvidenceCount;
                    }
                    if (entry.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY)
                    {
                        ++msrEvidenceCount;
                    }
                    if (entry.riskFlags != KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE)
                    {
                        ++highRiskCount;
                    }
                    if ((entry.riskFlags
                        & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED
                            | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED
                            | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED
                            | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED)) != 0U)
                    {
                        ++cpuProtectionRiskCount;
                    }
                    if ((entry.riskFlags
                        & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED
                            | KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER
                            | KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID)) != 0U)
                    {
                        ++unresolvedOwnerRiskCount;
                    }
                }

                int availableFeatureCount = 0;
                int degradedFeatureCount = 0;
                int deniedFeatureCount = 0;
                for (const auto& featureEntry : capabilityResult.entries)
                {
                    if (featureEntry.state == KSWORD_ARK_FEATURE_STATE_AVAILABLE)
                    {
                        ++availableFeatureCount;
                    }
                    else if (featureEntry.state == KSWORD_ARK_FEATURE_STATE_DEGRADED)
                    {
                        ++degradedFeatureCount;
                    }
                    else if (featureEntry.state == KSWORD_ARK_FEATURE_STATE_DENIED_BY_POLICY)
                    {
                        ++deniedFeatureCount;
                    }
                }

                int healthScore = 100;
                if (!capabilityResult.io.ok)
                {
                    healthScore -= 25;
                }
                if (!dynDataResult.io.ok || dynDataResult.capabilityMask == 0ULL)
                {
                    healthScore -= 10;
                }
                if (!integrityResult.io.ok)
                {
                    healthScore -= 35;
                }
                healthScore -= std::min(30, highRiskCount * 4);
                healthScore -= std::min(25, cpuProtectionRiskCount * 8);
                healthScore -= std::min(15, unresolvedOwnerRiskCount * 2);
                healthScore -= std::min(10, degradedFeatureCount * 2);
                healthScore -= std::min(10, deniedFeatureCount * 2);
                healthScore = std::clamp(healthScore, 0, 100);

                const QString healthLevelText = healthScore >= 90
                    ? QStringLiteral("优秀")
                    : (healthScore >= 75
                        ? QStringLiteral("良好")
                        : (healthScore >= 55
                            ? QStringLiteral("关注")
                            : QStringLiteral("高风险")));

                safeThis->m_r0HardwareHealthSummaryText = QStringLiteral(
                    "R0硬件健康: %1分/%2 | 风险=%3 保护风险=%4 | CPU=%5 IDT=%6 MSR=%7")
                    .arg(healthScore)
                    .arg(healthLevelText)
                    .arg(highRiskCount)
                    .arg(cpuProtectionRiskCount)
                    .arg(cpuEvidenceCount)
                    .arg(idtEvidenceCount)
                    .arg(msrEvidenceCount);

                const QString lastStatusText = QStringLiteral("0x%1")
                    .arg(static_cast<unsigned long>(integrityResult.lastStatus), 8, 16, QChar('0'))
                    .toUpper();
                safeThis->m_r0HardwareHealthDetailText = QStringLiteral(
                    "R0健康: %1分/%2  CPU=%3  IDT=%4  MSR=%5  风险=%6  保护风险=%7\n"
                    "协议: avail=%8 degraded=%9 denied=%10  |  Last=%11")
                    .arg(healthScore)
                    .arg(healthLevelText)
                    .arg(cpuEvidenceCount)
                    .arg(idtEvidenceCount)
                    .arg(msrEvidenceCount)
                    .arg(highRiskCount)
                    .arg(cpuProtectionRiskCount)
                    .arg(availableFeatureCount)
                    .arg(degradedFeatureCount)
                    .arg(deniedFeatureCount)
                    .arg(integrityResult.io.ok ? lastStatusText : QStringLiteral("N/A"));

                if (cpuHardwareResult.io.ok)
                {
                    const QString vendorText = QString::fromStdString(cpuHardwareResult.vendor).trimmed();
                    const QString brandText = QString::fromStdString(cpuHardwareResult.brand).trimmed();
                    const QString featureBadgeText = safeThis->buildR0CpuFeatureBadgeText(cpuHardwareResult.featureMask);
                    const QString leafText = QStringLiteral("basic=0x%1 ext=0x%2")
                        .arg(cpuHardwareResult.maxBasicLeaf, 0, 16)
                        .arg(cpuHardwareResult.maxExtendedLeaf, 0, 16)
                        .toUpper();
                    safeThis->m_r0CpuHardwareSummaryText = QStringLiteral(
                        "R0 CPU: %1 F%2/M%3/S%4 | 特性: %5")
                        .arg(vendorText.isEmpty() ? QStringLiteral("N/A") : vendorText)
                        .arg(cpuHardwareResult.family)
                        .arg(cpuHardwareResult.model)
                        .arg(cpuHardwareResult.stepping)
                        .arg(featureBadgeText);
                    safeThis->m_r0CpuHardwareDetailText = QStringLiteral(
                        "R0 CPUID: %1\n"
                        "Vendor: %2\n"
                        "Family/Model/Stepping: %3/%4/%5\n"
                        "Logical/Active: %6/%7\n"
                        "CLFLUSH line: %8 bytes\n"
                        "Leaves: %9\n"
                        "FeatureMask: 0x%10\n"
                        "Features: %11")
                        .arg(brandText.isEmpty() ? QStringLiteral("N/A") : brandText)
                        .arg(vendorText.isEmpty() ? QStringLiteral("N/A") : vendorText)
                        .arg(cpuHardwareResult.family)
                        .arg(cpuHardwareResult.model)
                        .arg(cpuHardwareResult.stepping)
                        .arg(cpuHardwareResult.logicalProcessorCount)
                        .arg(cpuHardwareResult.activeProcessorCount)
                        .arg(cpuHardwareResult.clflushLineSize)
                        .arg(leafText)
                        .arg(cpuHardwareResult.featureMask, 16, 16, QChar('0'))
                        .arg(featureBadgeText);
                    if (!brandText.isEmpty())
                    {
                        safeThis->m_cpuModelText = brandText;
                        if (safeThis->m_cpuModelLabel != nullptr)
                        {
                            safeThis->m_cpuModelLabel->setText(brandText);
                        }
                    }
                }
                else
                {
                    const QString readableCpuIoMessage = friendlyHardwareIoMessage(
                        cpuHardwareResult.io.message,
                        cpuHardwareResult.unsupported);
                    safeThis->m_r0CpuHardwareSummaryText = cpuHardwareResult.unsupported
                        ? QStringLiteral("R0 CPU硬件: 当前驱动不支持 CPUID 快照")
                        : QStringLiteral("R0 CPU硬件: 查询失败（Win32=%1）")
                            .arg(cpuHardwareResult.io.win32Error);
                    safeThis->m_r0CpuHardwareDetailText = QStringLiteral(
                        "R0 CPUID 查询不可用\n"
                        "调用状态: %1\n"
                        "兼容性: %2\n"
                        "Win32错误: %3\n"
                        "NTSTATUS/LastStatus: 0x%4\n"
                        "说明: %5")
                        .arg(hardwareIoOkText(cpuHardwareResult.io.ok))
                        .arg(cpuHardwareResult.unsupported ? QStringLiteral("驱动不支持") : QStringLiteral("接口可用但查询失败"))
                        .arg(cpuHardwareResult.io.win32Error)
                        .arg(QString::number(static_cast<std::uint32_t>(cpuHardwareResult.lastStatus), 16).rightJustified(8, QChar('0')).toUpper())
                        .arg(readableCpuIoMessage);
                }

                if (physicalMemoryResult.io.ok)
                {
                    const QString totalText = bytesToReadableText(static_cast<double>(physicalMemoryResult.totalPhysicalBytes));
                    const QString largestText = bytesToReadableText(static_cast<double>(physicalMemoryResult.largestRangeBytes));
                    const QString gapText = bytesToReadableText(static_cast<double>(physicalMemoryResult.estimatedAddressSpaceGapBytes));
                    safeThis->m_r0PhysicalMemorySummaryText = QStringLiteral(
                        "R0物理内存: %1 | ranges=%2 | 最大连续=%3")
                        .arg(totalText)
                        .arg(physicalMemoryResult.rangeCount)
                        .arg(largestText);
                    safeThis->m_r0PhysicalMemoryDetailText = QStringLiteral(
                        "R0物理内存布局\n"
                        "总物理内存: %1\n"
                        "Range数量: %2  零长度: %3\n"
                        "最大连续Range: %4\n"
                        "最小Range: %5\n"
                        "最高物理地址: 0x%6\n"
                        "首Range基址: 0x%7\n"
                        "末Range结束: 0x%8\n"
                        "估算地址空洞: %9")
                        .arg(totalText)
                        .arg(physicalMemoryResult.rangeCount)
                        .arg(physicalMemoryResult.zeroLengthRangeCount)
                        .arg(largestText)
                        .arg(bytesToReadableText(static_cast<double>(physicalMemoryResult.smallestRangeBytes)))
                        .arg(QString::number(physicalMemoryResult.highestPhysicalAddress, 16).toUpper())
                        .arg(QString::number(physicalMemoryResult.firstBaseAddress, 16).toUpper())
                        .arg(QString::number(physicalMemoryResult.lastEndAddress, 16).toUpper())
                        .arg(gapText);
                }
                else
                {
                    const QString readablePhysicalMemoryIoMessage = friendlyHardwareIoMessage(
                        physicalMemoryResult.io.message,
                        physicalMemoryResult.unsupported);
                    safeThis->m_r0PhysicalMemorySummaryText = physicalMemoryResult.unsupported
                        ? QStringLiteral("R0物理内存: 当前驱动不支持布局快照")
                        : QStringLiteral("R0物理内存: 查询失败（Win32=%1）")
                            .arg(physicalMemoryResult.io.win32Error);
                    safeThis->m_r0PhysicalMemoryDetailText = QStringLiteral(
                        "R0物理内存布局查询不可用\n"
                        "调用状态: %1\n"
                        "兼容性: %2\n"
                        "Win32错误: %3\n"
                        "NTSTATUS/LastStatus: 0x%4\n"
                        "说明: %5")
                        .arg(hardwareIoOkText(physicalMemoryResult.io.ok))
                        .arg(physicalMemoryResult.unsupported ? QStringLiteral("驱动不支持") : QStringLiteral("接口可用但查询失败"))
                        .arg(physicalMemoryResult.io.win32Error)
                        .arg(QString::number(static_cast<std::uint32_t>(physicalMemoryResult.lastStatus), 16).rightJustified(8, QChar('0')).toUpper())
                        .arg(readablePhysicalMemoryIoMessage);
                }

                safeThis->m_lastR0HardwareHealthRefreshMs = nowMs;
                safeThis->m_r0HardwareHealthRefreshing.store(false);
            },
            Qt::QueuedConnection);

        if (!invokeOk && !safeThis.isNull())
        {
            safeThis->m_r0HardwareHealthRefreshing.store(false);
        }
    }).detach();
}

void HardwareDock::refreshStaticHardwareTexts(const bool forceRefresh)
{
    const QPointer<HardwareDock> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("hardware-device-audit-tables-refresh"),
        {
            m_deviceStackTable,
            m_keyboardMouseHidTable,
            m_usbTopologyTable
        },
        [safeThis, forceRefresh]()
        {
            if (!safeThis.isNull())
            {
                safeThis->refreshStaticHardwareTexts(forceRefresh);
            }
        }))
    {
        return;
    }

    if (forceRefresh)
    {
        // 当前诊断页只请求自身需要的数据；普通页面仍只更新轻量静态概览。
        // 这样自动刷新不再每 60 秒连续提交 Device/Input/USB 三个大体积 R0 查询。
        std::uint32_t deviceAuditRefreshMask = 0U;
        QWidget* const currentPage = m_sideTabWidget != nullptr
            ? m_sideTabWidget->currentWidget()
            : nullptr;
        if (currentPage == m_deviceStackPage)
        {
            deviceAuditRefreshMask = DeviceStackAuditRefresh;
        }
        else if (currentPage == m_keyboardMouseHidPage)
        {
            deviceAuditRefreshMask = InputStackAuditRefresh;
        }
        else if (currentPage == m_usbTopologyPage)
        {
            deviceAuditRefreshMask = UsbTopologyAuditRefresh;
        }
        else if (currentPage == m_pnpAcpiPciPage)
        {
            deviceAuditRefreshMask = PnpAcpiPciRefresh;
        }

        if (deviceAuditRefreshMask != 0U)
        {
            requestAsyncDeviceAuditRefresh(deviceAuditRefreshMask);
        }
        else
        {
            requestAsyncStaticInfoRefresh();
        }
    }

    if (m_overviewEditor != nullptr && !m_cachedOverviewStaticText.isEmpty())
    {
        m_overviewEditor->setText(m_cachedOverviewStaticText);
    }
    if (m_gpuEditor != nullptr && !m_cachedGpuStaticText.isEmpty())
    {
        m_gpuEditor->setText(m_cachedGpuStaticText);
    }
    if (m_memoryEditor != nullptr && !m_cachedMemoryStaticText.isEmpty())
    {
        m_memoryEditor->setText(m_cachedMemoryStaticText);
    }
    if (m_deviceStackEditor != nullptr && !m_cachedDeviceStackStaticText.isEmpty())
    {
        m_deviceStackEditor->setText(m_cachedDeviceStackStaticText);
    }
    populateDeviceAuditTable(m_deviceStackTable, m_cachedDeviceStackRows);
    if (m_keyboardMouseHidEditor != nullptr && !m_cachedKeyboardMouseHidStaticText.isEmpty())
    {
        m_keyboardMouseHidEditor->setText(m_cachedKeyboardMouseHidStaticText);
    }
    populateDeviceAuditTable(m_keyboardMouseHidTable, m_cachedKeyboardMouseHidRows);
    if (m_usbTopologyEditor != nullptr && !m_cachedUsbTopologyStaticText.isEmpty())
    {
        m_usbTopologyEditor->setText(m_cachedUsbTopologyStaticText);
    }
    populateDeviceAuditTable(m_usbTopologyTable, m_cachedUsbTopologyRows);
    if (m_pnpAcpiPciEditor != nullptr && !m_cachedPnpAcpiPciStaticText.isEmpty())
    {
        m_pnpAcpiPciEditor->setText(m_cachedPnpAcpiPciStaticText);
    }
}

void HardwareDock::requestAsyncStaticInfoRefresh()
{
    // expectedFlag 用途：原子刷新锁 CAS 期望值（false=当前无任务）。
    bool expectedFlag = false;
    if (!m_staticInfoRefreshing.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    QPointer<HardwareDock> safeThis(this);
    std::thread([safeThis]() {
        if (safeThis.isNull())
        {
            return;
        }

        const QString overviewBaseText = buildOverviewStaticTextSnapshot();
        const QString peripheralOverviewText = buildOverviewPeripheralTextSnapshot();
        const QString overviewText = overviewBaseText
            + QStringLiteral("\n[硬件设备总览]\n")
            + peripheralOverviewText;
        const QString gpuWmiText = buildGpuStaticTextSnapshot();
        const QString memoryText = buildMemoryStaticTextSnapshot();
        const MemoryHardwareSummarySnapshot memorySummary = queryMemoryHardwareSummarySnapshot();
        const GpuHardwareSummarySnapshot gpuSummary = queryGpuHardwareSummarySnapshot();

        if (safeThis.isNull())
        {
            return;
        }

        const bool invokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, overviewText, gpuWmiText, memoryText, memorySummary, gpuSummary]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->m_cachedOverviewStaticText = overviewText;
                safeThis->m_cachedGpuStaticText = formatGpuHardwareSummaryText(gpuSummary, gpuWmiText);
                safeThis->m_cachedMemoryStaticText = memoryText;
                safeThis->m_memorySpeedMhz = memorySummary.speedMhz;
                safeThis->m_memorySlotUsed = memorySummary.usedSlots;
                safeThis->m_memorySlotTotal = memorySummary.totalSlots;
                safeThis->m_memoryFormFactorText = memorySummary.formFactorText;
                if (safeThis->m_gpuAdapterNameText.trimmed().isEmpty()
                    || safeThis->m_gpuAdapterNameText == QStringLiteral("N/A"))
                {
                    safeThis->m_gpuAdapterNameText = gpuSummary.adapterNameText;
                }
                safeThis->m_gpuDriverVersionText = gpuSummary.driverVersionText;
                safeThis->m_gpuDriverDateText = gpuSummary.driverDateText;
                safeThis->m_gpuPnpDeviceIdText = gpuSummary.pnpDeviceIdText;
                if (safeThis->m_gpuDedicatedMemoryGiB <= 0.0)
                {
                    safeThis->m_gpuDedicatedMemoryGiB = gpuSummary.dedicatedMemoryGiB;
                }
                emit safeThis->staticOverviewChanged(safeThis->m_cachedOverviewStaticText);
                safeThis->refreshStaticHardwareTexts(false);
                safeThis->m_staticInfoRefreshing.store(false);
            },
            Qt::QueuedConnection);

        if (!invokeOk && !safeThis.isNull())
        {
            safeThis->m_staticInfoRefreshing.store(false);
        }
        }).detach();
}

void HardwareDock::requestAsyncDeviceAuditRefresh(const std::uint32_t refreshMask)
{
    // normalizedMask 用途：剔除调用方意外传入的未知位，避免无意义后台任务。
    const std::uint32_t normalizedMask = refreshMask &
        static_cast<std::uint32_t>(AllDeviceAuditRefresh);
    if (normalizedMask == 0U)
    {
        return;
    }

    // pending mask 先合并再争抢执行权；快速切页不会丢请求，也不会并发启动多个线程。
    m_pendingDeviceAuditRefreshMask.fetch_or(normalizedMask);
    bool expectedFlag = false;
    if (!m_deviceAuditRefreshing.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    // requestedMask 用途：本轮一次性取得已合并页面位；后续重入会留在 pending 等下一轮。
    const std::uint32_t requestedMask =
        m_pendingDeviceAuditRefreshMask.exchange(0U) &
        static_cast<std::uint32_t>(AllDeviceAuditRefresh);
    QObject* const applicationContext = QCoreApplication::instance();
    if (applicationContext == nullptr)
    {
        m_deviceAuditRefreshing.store(false);
        return;
    }

    QPointer<HardwareDock> safeThis(this);
    auto* deviceAuditTask = QRunnable::create(
        [applicationContext, safeThis, requestedMask]()
    {
        DeviceAuditViewSnapshot deviceStackSnapshot;
        DeviceAuditViewSnapshot inputStackSnapshot;
        DeviceAuditViewSnapshot usbTopologySnapshot;
        QString pnpAcpiPciText;

        // 三类 R0 审计共享串行锁，并且只查询当前真正打开过的页面。
        // PnP/ACPI/PCI 是 R3 文本采集，不占用驱动通道。
        {
            const std::lock_guard<std::mutex> r0QueryLock(hardwareR0QueryMutex);
            if ((requestedMask & DeviceStackAuditRefresh) != 0U)
            {
                deviceStackSnapshot = HardwareDock::buildDeviceStackAuditViewSnapshot();
            }
            if ((requestedMask & InputStackAuditRefresh) != 0U)
            {
                inputStackSnapshot = HardwareDock::buildKeyboardMouseHidAuditViewSnapshot();
            }
            if ((requestedMask & UsbTopologyAuditRefresh) != 0U)
            {
                usbTopologySnapshot = HardwareDock::buildUsbTopologyAuditViewSnapshot();
            }
        }
        if ((requestedMask & PnpAcpiPciRefresh) != 0U)
        {
            pnpAcpiPciText = HardwareDock::buildPnpAcpiPciStaticText();
        }

        // applicationContext 与事件循环同寿命；工作线程不读取页面 QPointer，更不解引用页面成员。
        QMetaObject::invokeMethod(
            applicationContext,
            [safeThis,
                requestedMask,
                deviceStackSnapshot = std::move(deviceStackSnapshot),
                inputStackSnapshot = std::move(inputStackSnapshot),
                usbTopologySnapshot = std::move(usbTopologySnapshot),
                pnpAcpiPciText = std::move(pnpAcpiPciText)]() mutable
            {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->applyDeviceAuditRefreshResult(
                    requestedMask,
                    std::move(deviceStackSnapshot),
                    std::move(inputStackSnapshot),
                    std::move(usbTopologySnapshot),
                    std::move(pnpAcpiPciText));
            },
            Qt::QueuedConnection);
    });
    deviceAuditTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(deviceAuditTask);
}

void HardwareDock::applyDeviceAuditRefreshResult(
    const std::uint32_t requestedMask,
    DeviceAuditViewSnapshot deviceStackSnapshot,
    DeviceAuditViewSnapshot inputStackSnapshot,
    DeviceAuditViewSnapshot usbTopologySnapshot,
    QString pnpAcpiPciText)
{
    const QList<QTableView*> deviceAuditTables = {
        m_deviceStackTable,
        m_keyboardMouseHidTable,
        m_usbTopologyTable
    };
    if (ks::ui::IsTableUiCommitBlockedByContextMenu(deviceAuditTables))
    {
        const QPointer<HardwareDock> safeThis(this);
        ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("hardware-device-audit-snapshot-apply"),
            deviceAuditTables,
            [safeThis,
                requestedMask,
                deviceStackSnapshot = std::move(deviceStackSnapshot),
                inputStackSnapshot = std::move(inputStackSnapshot),
                usbTopologySnapshot = std::move(usbTopologySnapshot),
                pnpAcpiPciText = std::move(pnpAcpiPciText)]() mutable
            {
                if (!safeThis.isNull())
                {
                    safeThis->applyDeviceAuditRefreshResult(
                        requestedMask,
                        std::move(deviceStackSnapshot),
                        std::move(inputStackSnapshot),
                        std::move(usbTopologySnapshot),
                        std::move(pnpAcpiPciText));
                }
            });
        return;
    }

    if ((requestedMask & DeviceStackAuditRefresh) != 0U)
    {
        m_cachedDeviceStackStaticText = std::move(deviceStackSnapshot.summaryText);
        m_cachedDeviceStackRows = std::move(deviceStackSnapshot.rows);
    }
    if ((requestedMask & InputStackAuditRefresh) != 0U)
    {
        m_cachedKeyboardMouseHidStaticText = std::move(inputStackSnapshot.summaryText);
        m_cachedKeyboardMouseHidRows = std::move(inputStackSnapshot.rows);
    }
    if ((requestedMask & UsbTopologyAuditRefresh) != 0U)
    {
        m_cachedUsbTopologyStaticText = std::move(usbTopologySnapshot.summaryText);
        m_cachedUsbTopologyRows = std::move(usbTopologySnapshot.rows);
    }
    if ((requestedMask & PnpAcpiPciRefresh) != 0U)
    {
        m_cachedPnpAcpiPciStaticText = std::move(pnpAcpiPciText);
    }

    refreshStaticHardwareTexts(false);
    m_deviceAuditRefreshing.store(false);

    // pendingMask 用途：接住工作线程期间发生的切页请求，下一轮仍保持串行。
    const std::uint32_t pendingMask = m_pendingDeviceAuditRefreshMask.load();
    if (pendingMask != 0U)
    {
        requestAsyncDeviceAuditRefresh(pendingMask);
    }
}

void HardwareDock::requestAsyncSensorRefresh()
{
    // expectedFlag 用途：原子刷新锁 CAS 期望值（false=当前无任务）。
    bool expectedFlag = false;
    if (!m_sensorRefreshing.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    // event 用途：串联本次 CPU 传感器读取与日志输出，便于追踪失败原因。
    kLogEvent event;
    QPointer<HardwareDock> safeThis(this);
    std::thread([safeThis, event]() {
        const SensorProbeResult temperatureProbeResult = queryCpuTemperatureProbeResult();
        const SensorProbeResult voltageProbeResult = queryCpuVoltageProbeResult();
        if (safeThis.isNull())
        {
            return;
        }

        const bool invokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, event, temperatureProbeResult, voltageProbeResult]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                // previousSensorPartList 用途：拆分上一份缓存，分别保留温度/电压的最后有效值。
                const QStringList previousSensorPartList = safeThis->m_cachedSensorText.split('|');
                QString cachedTemperatureText =
                    previousSensorPartList.size() >= 1 ? previousSensorPartList.at(0) : QStringLiteral("N/A");
                QString cachedVoltageText =
                    previousSensorPartList.size() >= 2 ? previousSensorPartList.at(1) : QStringLiteral("N/A");

                if (isReadableSensorValue(temperatureProbeResult.valueText))
                {
                    cachedTemperatureText = temperatureProbeResult.valueText;
                }
                if (isReadableSensorValue(voltageProbeResult.valueText))
                {
                    cachedVoltageText = voltageProbeResult.valueText;
                }
                if (!isReadableSensorValue(cachedTemperatureText))
                {
                    cachedTemperatureText = QStringLiteral("N/A");
                }
                if (!isReadableSensorValue(cachedVoltageText))
                {
                    cachedVoltageText = QStringLiteral("N/A");
                }

                safeThis->m_cachedSensorText = QStringLiteral("%1|%2")
                    .arg(cachedTemperatureText)
                    .arg(cachedVoltageText);

                // previousLogSignatureText 用途：上一轮日志签名，用于控制失败/恢复日志去重。
                const QString previousLogSignatureText = safeThis->m_lastSensorLogSignatureText;
                const QString logSignatureText =
                    buildSensorProbeSignatureText(QStringLiteral("温度"), temperatureProbeResult)
                    + QStringLiteral("||")
                    + buildSensorProbeSignatureText(QStringLiteral("电压"), voltageProbeResult);
                if (logSignatureText != previousLogSignatureText)
                {
                    safeThis->m_lastSensorLogSignatureText = logSignatureText;

                    // hasUnexpectedFailure 用途：只把脚本失败、权限异常、执行超时等真正异常升为 WARN。
                    // allProbeSucceeded 用途：只有温度/电压均恢复可读时才输出恢复日志，避免 N/A 常态被误报。
                    const bool hasUnexpectedFailure =
                        (!temperatureProbeResult.success && !temperatureProbeResult.expectedUnavailable)
                        || (!voltageProbeResult.success && !voltageProbeResult.expectedUnavailable);
                    const bool allProbeSucceeded = temperatureProbeResult.success && voltageProbeResult.success;
                    if (hasUnexpectedFailure)
                    {
                        warn << event
                             << "[HardwareDock] CPU传感器读取失败："
                             << buildSensorProbeLogFragment(QStringLiteral("温度"), temperatureProbeResult)
                             << "；"
                             << buildSensorProbeLogFragment(QStringLiteral("电压"), voltageProbeResult)
                             << eol;
                    }
                    else if (allProbeSucceeded && !previousLogSignatureText.isEmpty())
                    {
                        info << event
                             << "[HardwareDock] CPU传感器读取恢复："
                             << buildSensorProbeLogFragment(QStringLiteral("温度"), temperatureProbeResult)
                             << "；"
                             << buildSensorProbeLogFragment(QStringLiteral("电压"), voltageProbeResult)
                             << eol;
                    }
                }
                safeThis->m_sensorRefreshing.store(false);
            },
            Qt::QueuedConnection);

        if (!invokeOk && !safeThis.isNull())
        {
            warn << event << "[HardwareDock] CPU传感器结果回投UI线程失败。" << eol;
            safeThis->m_sensorRefreshing.store(false);
        }
        }).detach();
}

QString HardwareDock::buildOverviewStaticText() const
{
    return buildOverviewStaticTextSnapshot();
}

QString HardwareDock::buildGpuStaticText() const
{
    return buildGpuStaticTextSnapshot();
}

QString HardwareDock::buildMemoryStaticText() const
{
    return buildMemoryStaticTextSnapshot();
}

QString HardwareDock::buildCpuSensorText(const bool forceRefresh)
{
    // 强制刷新场景改为“异步触发”，保证调用方不阻塞 UI 线程。
    if (forceRefresh)
    {
        requestAsyncSensorRefresh();
    }

    if (!m_cachedSensorText.isEmpty())
    {
        return m_cachedSensorText;
    }
    return QStringLiteral("N/A|N/A");
}

QString HardwareDock::buildDeviceStackStaticText() const
{
    return buildDeviceStackAuditViewSnapshot().summaryText;
}

HardwareDock::DeviceAuditViewSnapshot HardwareDock::buildDeviceStackAuditViewSnapshot()
{
    // scriptText 用途：保留原有 Win32_PnPEntity / PnP cross-view 输出；
    // r0AuditResult 用途：通过 ArkDriverClient 追加 R0 设备栈审计摘要和结构化行。
    const QString scriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "$rows=Get-CimInstance Win32_PnPEntity | Select-Object Name,PNPClass,Service,Status,PNPDeviceID,ConfigManagerErrorCode -First 120; "
        "$text='[DevNode / Device Stack]\\n'; "
        "$text += '说明：上方为 WMI/DevNode 视角；下方结构化表展示 R0 DeviceStack 行、attached/next 关系、风险标记和 PDB/DynData readiness。`n'; "
        "$text += ($rows | Format-Table -AutoSize | Out-String); "
        "$text += \"`n风险标记: 不执行卸载/删除/patch。\"; "
        "Write-Output $text");
    QString text = queryPowerShellTextSync(scriptText, 8000);
    const ksword::ark::DriverClient client;
    const ksword::ark::DeviceAuditResult r0AuditResult = client.queryDeviceStackAudit();
    text += appendDeviceAuditSummaryText(
        QStringLiteral("R0 Device Stack Audit Summary"),
        r0AuditResult,
        KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH);

    DeviceAuditViewSnapshot snapshot;
    snapshot.summaryText = text;
    snapshot.rows = buildDeviceAuditRows(QStringLiteral("DeviceStack"), r0AuditResult);
    return snapshot;
}

QString HardwareDock::buildKeyboardMouseHidStaticText() const
{
    return buildKeyboardMouseHidAuditViewSnapshot().summaryText;
}

HardwareDock::DeviceAuditViewSnapshot HardwareDock::buildKeyboardMouseHidAuditViewSnapshot()
{
    // scriptText 用途：保留原有 Keyboard/Mouse/HIDClass 的 WMI/PnP 输出；
    // r0AuditResult 用途：追加 R0 输入设备链只读审计摘要和结构化行。
    const QString scriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "$rows=Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -in @('Keyboard','Mouse','HIDClass') -or $_.Service -match 'kbdhid|mouhid|hidusb' } | "
        "Select-Object Name,PNPClass,Service,Status,PNPDeviceID -First 160; "
        "$text='[Keyboard / Mouse / HID]\\n'; "
        "$text += '说明：默认不做消息截获、不做输入抓取。`n'; "
        "$text += ($rows | Format-Table -AutoSize | Out-String); "
        "Write-Output $text");
    QString text = queryPowerShellTextSync(scriptText, 8000);
    const ksword::ark::DriverClient client;
    const ksword::ark::DeviceAuditResult r0AuditResult = client.queryInputStackAudit();
    text += appendDeviceAuditSummaryText(
        QStringLiteral("R0 Input Stack Audit Summary"),
        r0AuditResult,
        KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH);

    DeviceAuditViewSnapshot snapshot;
    snapshot.summaryText = text;
    snapshot.rows = buildDeviceAuditRows(QStringLiteral("InputStack"), r0AuditResult);
    return snapshot;
}

QString HardwareDock::buildUsbTopologyStaticText() const
{
    return buildUsbTopologyAuditViewSnapshot().summaryText;
}

HardwareDock::DeviceAuditViewSnapshot HardwareDock::buildUsbTopologyAuditViewSnapshot()
{
    // scriptText 用途：保留 USB controller/hub/link 的 WMI 拓扑输出；
    // r0AuditResult 用途：追加 R0 USB 拓扑只读审计摘要和结构化行。
    const QString scriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "$controllers=Get-CimInstance Win32_USBController | Select-Object Name,Manufacturer,DeviceID,PNPDeviceID,Status; "
        "$hubs=Get-CimInstance Win32_USBHub | Select-Object Name,DeviceID,PNPDeviceID,Status; "
        "$links=Get-CimInstance Win32_USBControllerDevice | Select-Object Antecedent,Dependent -First 80; "
        "$text='[USB Topology]\\n'; "
        "$text += \"[USB控制器]\\n\" + ($controllers | Format-Table -AutoSize | Out-String); "
        "$text += \"`n[USB Hub]\\n\" + ($hubs | Format-Table -AutoSize | Out-String); "
        "$text += \"`n[USB连接]\\n\" + ($links | Format-Table -AutoSize | Out-String); "
        "Write-Output $text");
    QString text = queryPowerShellTextSync(scriptText, 10000);
    const ksword::ark::DriverClient client;
    const ksword::ark::DeviceAuditResult r0AuditResult = client.queryUsbTopologyAudit();
    text += appendDeviceAuditSummaryText(
        QStringLiteral("R0 USB Topology Audit Summary"),
        r0AuditResult,
        KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH);

    DeviceAuditViewSnapshot snapshot;
    snapshot.summaryText = text;
    snapshot.rows = buildDeviceAuditRows(QStringLiteral("UsbTopology"), r0AuditResult);
    return snapshot;
}

QString HardwareDock::buildPnpAcpiPciStaticText()
{
    const QString scriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "$pnp=Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'ACPI*' -or $_.PNPDeviceID -like 'PCI*' } | "
        "Select-Object Name,PNPClass,Service,Status,PNPDeviceID,ConfigManagerErrorCode -First 180; "
        "$board=Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version,SerialNumber; "
        "$bios=Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber; "
        "$text='[PnP / ACPI / PCI]\\n'; "
        "$text += \"[主板/BIOS]\\n\" + ($board | Format-Table -AutoSize | Out-String) + \"`n\" + ($bios | Format-Table -AutoSize | Out-String); "
        "$text += \"`n[PnP节点]\\n\" + ($pnp | Format-Table -AutoSize | Out-String); "
        "$text += \"`n风险标记: 保持只读，不做 patch/remove/disable。\"; "
        "Write-Output $text");
    return queryPowerShellTextSync(scriptText, 10000);
}
