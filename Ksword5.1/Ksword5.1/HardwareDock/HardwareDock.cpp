#include "HardwareDock.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/FloatingScrollbars.h"
#include "../../../shared/ui/KsPainterChart.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "DiskMonitorPage.h"
#include "MemoryCompositionHistoryWidget.h"
#include "../../../shared/ui/MetricChartBinding.h"
#include "HardwarePowerPage.h"
#include "HardwareR0EvidencePage.h"
#include "HardwareOtherDevicesPage.h"
#include "HardwareDeviceManagerPage.h"
#include "HardwareHwidDispatchPage.h"
#include "HardwareI8042AuditPage.h"
#include "../Internationalization/LanguageManager.h"
#include "../SettingsDock/AppearanceSettings.h"

// ============================================================
// HardwareDock.cpp
// 作用：
// 1) 提供利用率优先的硬件监控视图与硬件总览；
// 2) 利用 PDH + Power API 周期采样 CPU/内存/每核频率；
// 3) 显卡与内存模块通过 CIM 结构数据与 DXGI/WDDM 快照展示。
// ============================================================

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../theme.h"
#include "../UI/StructuredFieldView.h"
#include "HardwareFieldDocuments.h"
#include "../UI/PerformanceNavCard.h"

#include <QAbstractScrollArea>
#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QBoxLayout>
#include <QClipboard>
#include <QCoreApplication>
#include <QContextMenuEvent>
#include <QDateTime>
#include <QDialog>
#include <QEasingCurve>
#include <QEvent>
#include <QFrame>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QHash>
#include <QHeaderView>
#include <QIcon>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QList>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QMouseEvent>
#include <QPainter>
#include <QPen>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QRunnable>
#include <QScrollArea>
#include <QScreen>
#include <QSpacerItem>
#include <QScrollBar>
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
#include <QWindow>
#include <QWheelEvent>

#include <algorithm>
#include <atomic>
#include <bit>
#include <cmath>
#include <cstring>
#include <functional>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <windowsx.h>
#include <intrin.h>
#include <Objbase.h>
#include <Pdh.h>
#include <pdhmsg.h>
#include <PowrProf.h>
#include <Psapi.h>
#include <d3dkmthk.h>
#include <dwmapi.h>
#include <dxgi1_6.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <shellscalingapi.h>

#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "PowrProf.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "Dxgi.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Dwmapi.lib")
#pragma comment(lib, "Shcore.lib")

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

    // createReadOnlyFieldPage 作用：
    // - 输入父控件、标题与提示文本；
    // - 处理：创建“标题 + 说明 + StructuredFieldView”标准只读页面；
    // - 返回：已初始化的页面控件。
    QWidget* createReadOnlyFieldPage(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& hintText,
        ks::ui::StructuredFieldView** editorOut)
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

        auto* editor = new ks::ui::StructuredFieldView(pageWidget);
        editor->setPresentation(ks::ui::StructuredFieldView::Presentation::Tree);
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
        // 纯色主题只接管颜色；保留本页按钮尺寸和业务选中状态。
        return ks::ui::BuildFlatButtonStyle(selected ? ks::ui::FlatButtonTone::Accent : ks::ui::FlatButtonTone::Neutral)
            + QStringLiteral("QPushButton{min-width:24px;max-width:24px;padding:3px 0;border-radius:0;font-weight:700;}");

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
    // - 处理：创建“属性摘要 + 完整 R0 行表格”的标准页；
    // - 返回：已初始化页面控件。
    QWidget* createDeviceAuditPage(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& hintText,
        ks::ui::StructuredFieldView** editorOut,
        QTableWidget** tableOut)
    {
        QWidget* pageWidget = createReadOnlyFieldPage(parentWidget, titleText, hintText, editorOut);
        QVBoxLayout* pageLayout = qobject_cast<QVBoxLayout*>(pageWidget->layout());
        if (pageLayout != nullptr)
        {
            QLineEdit* searchEdit = new QLineEdit(pageWidget);
            searchEdit->setClearButtonEnabled(true);
            searchEdit->setPlaceholderText(
                QStringLiteral("搜索 Profile / 行类型 / 风险 / 地址 / FieldFlags / LastStatus / 备注"));
            ks::ui::StyleSearchField(searchEdit);
            QTableWidget* table = createDeviceAuditTable(pageWidget);
            // USB/PCI/磁盘/网络/显示的完整 R0 证据保留跨次对比能力。
            ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Full);

            QHBoxLayout* tableToolLayout = new QHBoxLayout();
            tableToolLayout->setContentsMargins(0, 0, 0, 0);
            tableToolLayout->setSpacing(8);

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
            ks::ui::NormalizeToolbarRow(presetLayout, 0);
            ks::ui::NormalizeToolbarRow(tableToolLayout);
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

    // appendDeviceAuditSummaryFields 作用：
    // - 输入：页面标题、wrapper 返回值和请求深度；
    // - 处理：汇总 returnedCount/totalCount、maxDepth/truncated、IO 状态和风险行；
    // - 返回：直接呈现的设备栈/输入链/USB 拓扑字段快照。
    ks::ui::FieldDocument appendDeviceAuditSummaryFields(
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
            if (entry.riskFlags != KSWORD_ARK_DEVICE_AUDIT_RISK_NONE) ++riskRowCount;
        }
        const bool truncated = (auditResult.responseFlags & KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_TRUNCATED) != 0U
            || auditResult.returnedCount < auditResult.totalCount;
        ks::ui::FieldDocument document;
        document.section(titleText).note(QStringLiteral("以下内容为只读设备证据，不会修改设备状态。"))
            .field(QStringLiteral("调用状态"), hardwareIoOkText(auditResult.io.ok), true)
            .field(QStringLiteral("兼容性"), auditResult.unsupported ? QStringLiteral("驱动不支持") : QStringLiteral("接口可用"), true)
            .field(QStringLiteral("Win32"), QString::number(auditResult.io.win32Error))
            .field(QStringLiteral("NTSTATUS"), formatHardwareAuditHex32(static_cast<std::uint32_t>(auditResult.io.ntStatus)))
            .field(QStringLiteral("返回字节"), QString::number(auditResult.io.bytesReturned))
            .field(QStringLiteral("驱动说明"), friendlyHardwareIoMessage(auditResult.io.message, auditResult.unsupported))
            .field(QStringLiteral("协议版本"), QString::number(auditResult.version))
            .field(QStringLiteral("queryStatus"), deviceAuditStatusText(auditResult.status), true)
            .field(QStringLiteral("lastStatus"), formatHardwareAuditHex32(static_cast<std::uint32_t>(auditResult.lastStatus)))
            .field(QStringLiteral("entrySize"), QString::number(auditResult.entrySize))
            .field(QStringLiteral("returned"), QString::number(auditResult.returnedCount))
            .field(QStringLiteral("total"), QString::number(auditResult.totalCount))
            .field(QStringLiteral("已解析"), QString::number(auditResult.entries.size()))
            .field(QStringLiteral("目标"), QString::number(auditResult.targetCount))
            .field(QStringLiteral("驱动"), QString::number(auditResult.driverCount))
            .field(QStringLiteral("设备"), QString::number(auditResult.deviceCount))
            .field(QStringLiteral("观察最大深度"), QString::number(maxObservedDepth))
            .field(QStringLiteral("请求深度上限"), QString::number(requestedMaxDepth))
            .field(QStringLiteral("是否截断"), truncated ? QStringLiteral("是") : QStringLiteral("否"), true)
            .field(QStringLiteral("响应标志"), formatHardwareAuditHex32(auditResult.responseFlags))
            .field(QStringLiteral("响应标志说明"), deviceAuditResponseFlagText(auditResult.responseFlags), true)
            .field(QStringLiteral("风险行"), QString::number(riskRowCount))
            .field(QStringLiteral("profileFlags"), formatHardwareAuditHex32(auditResult.profileFlags))
            .field(QStringLiteral("处理建议"), riskRowCount == 0U ? QStringLiteral("未发现 R0 风险行") : QStringLiteral("请查看表格中非 Clean 的风险行"), true);
        int shownRows = 0;
        for (const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry : auditResult.entries)
        {
            if (entry.riskFlags == KSWORD_ARK_DEVICE_AUDIT_RISK_NONE && shownRows >= 8) continue;
            const QString driverName = QString::fromWCharArray(entry.driverName).trimmed();
            const QString deviceName = QString::fromWCharArray(entry.deviceName).trimmed();
            document.section(QStringLiteral("行[%1]").arg(shownRows))
                .field(QStringLiteral("角色"), deviceAuditRoleText(entry.roleHint), true)
                .field(QStringLiteral("状态"), deviceAuditStatusText(entry.status), true)
                .field(QStringLiteral("风险"), deviceAuditRiskText(entry.riskFlags), true)
                .field(QStringLiteral("风险标志"), formatHardwareAuditHex32(entry.riskFlags))
                .field(QStringLiteral("置信度"), QString::number(entry.confidence))
                .field(QStringLiteral("链路深度"), QString::number(entry.relationDepth))
                .field(QStringLiteral("附加深度"), QString::number(entry.attachedDepth))
                .field(QStringLiteral("驱动"), driverName.isEmpty() ? QStringLiteral("<unnamed>") : driverName)
                .field(QStringLiteral("设备"), deviceName.isEmpty() ? QStringLiteral("<unnamed>") : deviceName)
                .field(QStringLiteral("DriverObject"), formatHardwareAuditHex64(entry.driverObjectAddress))
                .field(QStringLiteral("DeviceObject"), formatHardwareAuditHex64(entry.deviceObjectAddress))
                .field(QStringLiteral("说明"), friendlyDeviceAuditEntryDetail(QString::fromWCharArray(entry.detail).trimmed()));
            if (++shownRows >= 12) break;
        }
        if (auditResult.entries.empty()) document.note(QStringLiteral("明细行: <无返回行>"));
        return document;
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
            const auto typedColumns = hardware_field_documents::FromDeviceAuditEntry(entry);
            QStringList noteParts;
            if (!detailText.isEmpty())
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
                typedColumns.ownerDriver,
                formatHardwareAuditHex32(entry.deviceType),
                formatHardwareAuditHex32(entry.characteristics),
                QString::number(entry.stackSize),
                QString::number(entry.alignmentRequirement),
                formatHardwareAuditHex32(entry.fieldFlags),
                formatHardwareAuditHex32(static_cast<std::uint32_t>(entry.lastStatus)),
                typedColumns.integrityStatus,
                typedColumns.integrityRows,
                typedColumns.modules,
                typedColumns.integrityFlags,
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

    // GetIfTable2 also contains one row for each bound filter module. IP
    // interfaces identify the adapter rows that can appear in the performance
    // view without depending on localized adapter or filter driver names.
    bool collectNetworkIpInterfaceKeys(std::unordered_set<std::uint64_t>* keys)
    {
        if (keys == nullptr) return false;
        MIB_IPINTERFACE_TABLE* table = nullptr;
        if (::GetIpInterfaceTable(AF_UNSPEC, &table) != NO_ERROR || table == nullptr)
        {
            if (table != nullptr) ::FreeMibTable(table);
            return false;
        }
        keys->clear();
        for (ULONG index = 0; index < table->NumEntries; ++index)
            keys->insert(interfaceLuidToKey(
                static_cast<std::uint64_t>(table->Table[index].InterfaceLuid.Value)));
        ::FreeMibTable(table);
        return !keys->empty();
    }

    bool isMonitoredNetworkInterface(const MIB_IF_ROW2& row,
        const std::unordered_set<std::uint64_t>& ipKeys, const bool hasIpTable)
    {
        if ((row.OperStatus != IfOperStatusUp
                && !row.InterfaceAndOperStatusFlags.HardwareInterface)
            || row.Type == IF_TYPE_SOFTWARE_LOOPBACK
            || row.InterfaceAndOperStatusFlags.FilterInterface)
            return false;
        if (hasIpTable)
            return ipKeys.contains(interfaceLuidToKey(
                static_cast<std::uint64_t>(row.InterfaceLuid.Value)));
        // If the IP table is unavailable, retain usable broadcast adapters
        // while excluding the always-up WAN miniport point-to-point rows.
        return row.AccessType == NET_IF_ACCESS_BROADCAST;
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
    // - 仅组装请求；不能用试调用性能查询来探测支持性，内核故障不会返回 NTSTATUS。
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

    bool supportsGpuPerformanceQueriesOnCurrentSystem()
    {
        static const bool supported = []()
        {
            // 092826-16203-01.dmp：17763.9240 的 GetNodePerfData 解引用空数组。
            // 对整个 17763 及更早系列关闭该可选查询；版本未知时也只用 DXGI/PDH。
            const QStringList versionParts = QSysInfo::kernelVersion().split(QLatin1Char('.'));
            if (versionParts.size() < 3)
            {
                return false;
            }
            bool majorOk = false;
            bool buildOk = false;
            const uint majorVersion = versionParts.at(0).toUInt(&majorOk);
            const uint buildNumber = versionParts.at(2).toUInt(&buildOk);
            return majorOk && buildOk && majorVersion >= 10U && buildNumber > 17763U;
        }();
        return supported;
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

        if (!supportsGpuPerformanceQueriesOnCurrentSystem())
        {
            return false;
        }

        // 静态摘要与周期采样可能同时到达同一适配器，统一串行执行可选遥测。
        static std::mutex gpuTelemetryMutex;
        const std::lock_guard<std::mutex> telemetryLock(gpuTelemetryMutex);

        D3DKMT_OPENADAPTERFROMLUID openInfo{};
        openInfo.AdapterLuid = adapterLuid;
        if (::D3DKMTOpenAdapterFromLuid(&openInfo) < 0 || openInfo.hAdapter == 0)
        {
            return false;
        }

        D3DKMT_DRIVERVERSION driverVersion{};
        if (!queryD3dKmtAdapterInfo(
                openInfo.hAdapter,
                KMTQAITYPE_DRIVERVERSION,
                &driverVersion,
                sizeof(driverVersion))
            || driverVersion < KMT_DRIVERVERSION_WDDM_2_4)
        {
            D3DKMT_CLOSEADAPTER closeInfo{};
            closeInfo.hAdapter = openInfo.hAdapter;
            ::D3DKMTCloseAdapter(&closeInfo);
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

        // 枚举失败不能猜测节点 0 存在，再通过性能查询试探。
        ULONG nodeCount = 0;
        D3DKMT_QUERYSTATISTICS adapterStatistics{};
        adapterStatistics.Type = D3DKMT_QUERYSTATISTICS_ADAPTER;
        adapterStatistics.AdapterLuid = adapterLuid;
        if (::D3DKMTQueryStatistics(&adapterStatistics) >= 0)
        {
            nodeCount = std::clamp(
                adapterStatistics.QueryResult.AdapterInformation.NodeCount,
                0UL,
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

    // buildGpuHardwareSummaryFields 作用：
    // - 在 UI 线程把 DXGI/WDDM 快照格式化到“显卡”信息页；
    // - WMI 仅补充驱动与显示模式，不再承担显存容量识别。
    ks::ui::FieldDocument buildGpuHardwareSummaryFields(
        const GpuHardwareSummarySnapshot& snapshot,
        const ks::ui::FieldDocument& wmiFields)
    {
        ks::ui::FieldDocument document;
        for (const GpuHardwareSummarySnapshot::AdapterSnapshot& adapter : snapshot.adapterList)
        {
            document.section(QStringLiteral("GPU %1 - DXGI/WDDM").arg(adapter.adapterIndex))
                .field(QStringLiteral("名称"), adapter.adapterNameText)
                .field(QStringLiteral("专用显存"), adapter.dedicatedMemoryGiB > 0.0 ? QStringLiteral("%1 GiB").arg(adapter.dedicatedMemoryGiB, 0, 'f', 2) : QStringLiteral("N/A"))
                .field(QStringLiteral("共享 GPU 内存"), adapter.sharedMemoryGiB > 0.0 ? QStringLiteral("%1 GiB").arg(adapter.sharedMemoryGiB, 0, 'f', 2) : QStringLiteral("N/A"))
                .field(QStringLiteral("核心频率"), QStringLiteral("%1 MHz").arg(formatGpuClockMhzText(adapter.currentCoreClockMhz)))
                .field(QStringLiteral("最大核心频率"), QStringLiteral("%1 MHz").arg(formatGpuClockMhzText(adapter.maxCoreClockMhz)))
                .field(QStringLiteral("显存频率"), QStringLiteral("%1 MHz").arg(formatGpuClockMhzText(adapter.currentMemoryClockMhz)))
                .field(QStringLiteral("最大显存频率"), QStringLiteral("%1 MHz").arg(formatGpuClockMhzText(adapter.maxMemoryClockMhz)));
        }
        if (snapshot.adapterList.isEmpty())
            document.section(QStringLiteral("实时 GPU 硬件信息")).note(QStringLiteral("未从 DXGI/WDDM 读取到 GPU 显存与频率信息。"));
        document.nodes += wmiFields.nodes;
        return document;
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

    // CIM uses actual ordered JSON records. Only the complete typed snapshot is cached.
    ks::ui::FieldDocument queryPowerShellFieldsSync(const QString& scriptText, const int timeoutMs)
    {
        const QString payload = queryPowerShellTextSync(scriptText, timeoutMs);
        auto document = hardware_field_documents::FromCimJson(payload);
        if (document) return std::move(*document);
        ks::ui::FieldDocument failure;
        failure.section(QStringLiteral("采集状态"))
            .field(QStringLiteral("状态"), QStringLiteral("失败"), true)
            .note(payload);
        return failure;
    }

    // buildOverviewFieldsSnapshot 作用：
    // - 构建“概览”页系统字段快照；
    // - 仅做轻量 Win32/Qt 系统信息读取，不依赖 UI 对象。
    ks::ui::FieldDocument buildOverviewFieldsSnapshot()
    {
        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);
        MEMORYSTATUSEX memoryStatus{};
        memoryStatus.dwLength = sizeof(memoryStatus);
        ::GlobalMemoryStatusEx(&memoryStatus);
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("系统信息"))
            .field(QStringLiteral("系统名称"), QSysInfo::prettyProductName())
            .field(QStringLiteral("CPU架构"), QSysInfo::currentCpuArchitecture())
            .field(QStringLiteral("内核类型"), QSysInfo::kernelType())
            .field(QStringLiteral("内核版本"), QSysInfo::kernelVersion())
            .field(QStringLiteral("逻辑处理器数量"), QString::number(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)))
            .field(QStringLiteral("处理器组掩码(十六进制)"), QStringLiteral("0x%1").arg(QString::number(static_cast<qulonglong>(systemInfo.dwActiveProcessorMask), 16).toUpper()))
            .field(QStringLiteral("页面大小"), QStringLiteral("%1 字节").arg(systemInfo.dwPageSize))
            .field(QStringLiteral("物理内存总量"), bytesToGiBText(memoryStatus.ullTotalPhys))
            .field(QStringLiteral("当前可用内存"), bytesToGiBText(memoryStatus.ullAvailPhys))
            .field(QStringLiteral("虚拟内存总量"), bytesToGiBText(memoryStatus.ullTotalVirtual))
            .field(QStringLiteral("当前可用虚拟内存"), bytesToGiBText(memoryStatus.ullAvailVirtual))
            .field(QStringLiteral("系统启动时间"), QDateTime::fromMSecsSinceEpoch(
                QDateTime::currentMSecsSinceEpoch() - static_cast<qint64>(::GetTickCount64())).toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
        return document;
    }

    // buildOverviewPeripheralFieldsSnapshot 作用：
    // - 采集“概览”页的外设与硬件设备字段；
    // - 覆盖用户要求的声卡/网卡/摄像头，并补充主板/BIOS/磁盘等信息。
    // 说明：
    // - 该函数会执行 PowerShell + CIM 查询；
    // - 必须在后台线程调用，避免阻塞 UI 线程。
    ks::ui::FieldDocument buildOverviewPeripheralFieldsSnapshot(const bool includeHardwareDetails = true)
    {
        const QString scriptText = QStringLiteral(
            "$includeHardwareDetails = %1; $ErrorActionPreference='SilentlyContinue'; $doc=[ordered]@{}; "
            "$doc['主板']=@(Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version,SerialNumber); "
            "$doc['BIOS']=@(Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber); "
            "$doc['处理器']=@(Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed); "
            "if($includeHardwareDetails){$doc['磁盘设备']=@(Get-CimInstance Win32_DiskDrive | Select-Object Model,InterfaceType,MediaType,Size,SerialNumber)}; "
            "$doc['显卡设备']=@(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM,DriverVersion,VideoProcessor); "
            "if($includeHardwareDetails){$doc['声卡设备']=@(Get-CimInstance Win32_SoundDevice | Select-Object Name,Manufacturer,Status)}; "
            "$doc['网卡设备(物理)']=@(Get-CimInstance Win32_NetworkAdapter | Where-Object {$_.PhysicalAdapter -eq $true} | Select-Object Name,AdapterType,Speed,MACAddress,NetConnectionStatus,Manufacturer); "
            "if($includeHardwareDetails){$doc['摄像头设备']=@(Get-CimInstance Win32_PnPEntity | Where-Object {$_.PNPClass -eq 'Image' -or $_.Service -like '*usbvideo*'} | Select-Object Name,Manufacturer,Status,Service,PNPDeviceID)}; "
            "$doc['显示器设备']=@(Get-CimInstance Win32_DesktopMonitor | Select-Object Name,MonitorType,ScreenWidth,ScreenHeight,Status); "
            "if($includeHardwareDetails){$doc['打印机设备']=@(Get-CimInstance Win32_Printer | Select-Object Name,DriverName,PortName,WorkOffline,Default); "
            "$doc['USB控制器映射(前30条)']=@(Get-CimInstance Win32_USBControllerDevice | Select-Object Dependent -First 30)}; "
            "$doc | ConvertTo-Json -Depth 8 -Compress").arg(includeHardwareDetails ? QStringLiteral("$true") : QStringLiteral("$false"));
        return queryPowerShellFieldsSync(scriptText, 9000);
    }

    // buildGpuFieldsSnapshot 作用：
    // - 通过 WMI 采集显卡信息字段；
    // - 该函数会调用 PowerShell，必须放在后台线程执行。
    ks::ui::FieldDocument buildGpuFieldsSnapshot()
    {
        const QString scriptText = QStringLiteral(
            "$ErrorActionPreference='SilentlyContinue'; $doc=[ordered]@{}; "
            "$doc['WMI 驱动与显示信息']=@(Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,VideoProcessor,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate,PNPDeviceID); "
            "$doc | ConvertTo-Json -Depth 8 -Compress");
        return queryPowerShellFieldsSync(scriptText, 5000);
    }

    // buildMemoryFieldsSnapshot 作用：
    // - 通过 WMI 采集内存条与系统内存字段；
    // - 该函数会调用 PowerShell，必须放在后台线程执行。
    ks::ui::FieldDocument buildMemoryFieldsSnapshot()
    {
        const QString scriptText = QStringLiteral(
            "$ErrorActionPreference='SilentlyContinue'; $doc=[ordered]@{}; "
            "$doc['物理内存条']=@(Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel,Manufacturer,PartNumber,ConfiguredClockSpeed,Capacity,SMBIOSMemoryType); "
            "$doc['操作系统内存']=@(Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory); "
            "$doc | ConvertTo-Json -Depth 8 -Compress");
        return queryPowerShellFieldsSync(scriptText, 6000);
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

namespace
{
    bool utilizationPhysicalWindowRect(HWND window, RECT* rect)
    {
        return window != nullptr && rect != nullptr
            && (SUCCEEDED(::DwmGetWindowAttribute(window, DWMWA_EXTENDED_FRAME_BOUNDS,
                    rect, sizeof(*rect))) || ::GetWindowRect(window, rect) != FALSE);
    }

    UINT utilizationMonitorDpi(HWND window)
    {
        const HMONITOR monitor = ::MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST);
        UINT dpiX = 96, dpiY = 96;
        if (monitor != nullptr
            && SUCCEEDED(::GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &dpiX, &dpiY))
            && dpiX != 0) return dpiX;
        return 96;
    }

    class UtilizationFloatingWindow final : public QWidget
    {
    public:
        explicit UtilizationFloatingWindow(const bool topMost)
            : QWidget(nullptr, Qt::Window | Qt::FramelessWindowHint
                | (topMost ? Qt::WindowStaysOnTopHint : Qt::WindowFlags{}))
        {
            setAttribute(Qt::WA_TranslucentBackground);
            setAutoFillBackground(false);
        }

        void setBackground(const QColor& color, const int opacityPercent)
        {
            m_backgroundColor = color;
            // A fully zero-alpha layered HWND becomes mouse-transparent on Windows.
            // One alpha unit is visually clear while preserving full-window hit testing.
            m_backgroundColor.setAlpha(opacityPercent == 0 ? 1
                : qRound(std::clamp(opacityPercent, 0, 100) * 255.0 / 100.0));
            update();
        }

        void setMoveFinishedHandler(std::function<void(bool)> handler)
        {
            m_moveFinishedHandler = std::move(handler);
        }

    protected:
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            painter.fillRect(rect(), m_backgroundColor);
        }

        bool nativeEvent(const QByteArray& eventType, void* message, qintptr* result) override
        {
            MSG* const nativeMessage = static_cast<MSG*>(message);
            if (nativeMessage != nullptr && nativeMessage->message == WM_ENTERSIZEMOVE)
                m_nativeResized = false;
            if (nativeMessage != nullptr && nativeMessage->message == WM_SIZING)
                m_nativeResized = true;
            if (nativeMessage != nullptr && nativeMessage->message == WM_EXITSIZEMOVE
                && m_moveFinishedHandler)
            {
                const bool resized = m_nativeResized;
                QTimer::singleShot(0, this, [handler = m_moveFinishedHandler, resized]()
                {
                    handler(resized);
                });
            }
            if (nativeMessage != nullptr && nativeMessage->message == WM_NCHITTEST
                && !isMaximized() && result != nullptr)
            {
                RECT windowRect{};
                if (::GetWindowRect(nativeMessage->hwnd, &windowRect) != FALSE)
                {
                    const int border = std::max(10, static_cast<int>(std::round(8.0 * devicePixelRatioF())));
                    const int x = GET_X_LPARAM(nativeMessage->lParam);
                    const int y = GET_Y_LPARAM(nativeMessage->lParam);
                    const bool left = x >= windowRect.left && x < windowRect.left + border;
                    const bool right = x < windowRect.right && x >= windowRect.right - border;
                    const bool top = y >= windowRect.top && y < windowRect.top + border;
                    const bool bottom = y < windowRect.bottom && y >= windowRect.bottom - border;
                    if (top && left) *result = HTTOPLEFT;
                    else if (top && right) *result = HTTOPRIGHT;
                    else if (bottom && left) *result = HTBOTTOMLEFT;
                    else if (bottom && right) *result = HTBOTTOMRIGHT;
                    else if (left) *result = HTLEFT;
                    else if (right) *result = HTRIGHT;
                    else if (top) *result = HTTOP;
                    else if (bottom) *result = HTBOTTOM;
                    else return QWidget::nativeEvent(eventType, message, result);
                    return true;
                }
            }
            return QWidget::nativeEvent(eventType, message, result);
        }

    private:
        QColor m_backgroundColor;
        std::function<void(bool)> m_moveFinishedHandler;
        bool m_nativeResized = false;
    };

    class UtilizationFollowMirror final : public QWidget
    {
    public:
        struct WidgetStyle
        {
            QString sheet;
            int minimumHeight = 0;
            int maximumHeight = QWIDGETSIZE_MAX;
        };
        struct LayoutStyle
        {
            QMargins margins;
            int spacing = 0;
            int horizontalSpacing = 0;
            int verticalSpacing = 0;
        };
        using WidgetStyleLookup = std::function<WidgetStyle(const QWidget*)>;
        using LayoutStyleLookup = std::function<LayoutStyle(const QLayout*)>;

        UtilizationFollowMirror(QWidget* source, QWidget* parent,
            WidgetStyleLookup widgetStyle, LayoutStyleLookup layoutStyle)
            : QWidget(parent), m_source(source), m_widgetStyle(std::move(widgetStyle)),
              m_layoutStyle(std::move(layoutStyle))
        {
            setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
            auto* const layout = new QVBoxLayout(this);
            layout->setContentsMargins(0, 0, 0, 0);
            layout->setSpacing(0);
            rebuild();
        }

        void synchronize()
        {
            QWidget* const source = m_source.data();
            if (source == nullptr) return;
            int sourceChartCount = dynamic_cast<QChartView*>(source) != nullptr ? 1 : 0;
            for (QWidget* const child : source->findChildren<QWidget*>())
                if (dynamic_cast<QChartView*>(child) != nullptr) ++sourceChartCount;
            if (m_sidebarSource == nullptr && sourceChartCount != m_charts.size())
            {
                rebuild();
            }
            for (const auto& [from, to] : m_labels)
            {
                if (from != nullptr && to != nullptr && to->text() != from->text())
                    to->setText(from->text());
            }
            for (const auto& [from, to] : m_memories)
            {
                if (from != nullptr && to != nullptr) to->copyDisplayFrom(*from);
            }
            for (const ChartCopy& chart : m_charts)
            {
                if (chart.from == nullptr || chart.to == nullptr) continue;
                for (const auto& [from, to] : chart.lines)
                {
                    if (from != nullptr && to != nullptr)
                    {
                        ks::ui::MetricChartBinding::MirrorSeries(from, to);
                        to->setPen(from->pen());
                    }
                }
                for (const auto& [from, to] : chart.axes)
                {
                    if (from != nullptr && to != nullptr) to->setRange(from->min(), from->max());
                }
                for (const auto& [from, to] : chart.barSets)
                {
                    if (from == nullptr || to == nullptr) continue;
                    const QVector<qreal> values = from->values();
                    for (int index = 0; index < values.size(); ++index)
                    {
                        if (index < to->count()) to->replace(index, values[index]);
                        else to->append(values[index]);
                    }
                }
                chart.to->chart()->setTitle(chart.from->chart()->title());
                chart.to->chart()->setTitleBrush(QBrush(KswordTheme::TextPrimaryColor()));
                chart.to->chart()->legend()->setLabelColor(KswordTheme::TextSecondaryColor());
            }
            synchronizeSidebar();
        }

    private:
        struct ChartCopy
        {
            QPointer<QChartView> from;
            QPointer<QChartView> to;
            std::vector<std::pair<QPointer<QLineSeries>, QPointer<QLineSeries>>> lines;
            std::vector<std::pair<QPointer<QValueAxis>, QPointer<QValueAxis>>> axes;
            std::vector<std::pair<QPointer<QBarSet>, QPointer<QBarSet>>> barSets;
        };

        QChartView* cloneChartView(QChartView* from, QWidget* parent)
        {
            QChart* const original = from->chart();
            auto* const chart = new QChart();
            chart->setTitle(original->title());
            chart->setTitleBrush(QBrush(KswordTheme::TextPrimaryColor()));
            chart->setTitleFont(original->titleFont());
            chart->setBackgroundVisible(original->isBackgroundVisible());
            chart->setBackgroundRoundness(original->backgroundRoundness());
            chart->setBackgroundBrush(original->backgroundBrush());
            chart->setMargins(original->margins());
            chart->setPlotAreaBackgroundVisible(original->isPlotAreaBackgroundVisible());
            chart->setPlotAreaBackgroundBrush(original->plotAreaBackgroundBrush());
            chart->setPlotAreaBackgroundPen(original->plotAreaBackgroundPen());
            chart->setAnimationOptions(QChart::NoAnimation);
            chart->legend()->setVisible(original->legend()->isVisible());
            chart->legend()->setAlignment(original->legend()->alignment());
            chart->legend()->setLabelColor(KswordTheme::TextSecondaryColor());
            chart->legend()->setFont(original->legend()->font());

            QHash<const QAbstractAxis*, QAbstractAxis*> axes;
            ChartCopy copy;
            for (QAbstractAxis* const fromAxis : original->axes())
            {
                QAbstractAxis* toAxis = nullptr;
                if (auto* const value = dynamic_cast<QValueAxis*>(fromAxis))
                {
                    auto* const clone = new QValueAxis(chart);
                    clone->setRange(value->min(), value->max());
                    copy.axes.emplace_back(value, clone);
                    toAxis = clone;
                }
                else if (auto* const category = dynamic_cast<QBarCategoryAxis*>(fromAxis))
                {
                    auto* const clone = new QBarCategoryAxis(chart);
                    clone->append(category->categories());
                    toAxis = clone;
                }
                if (toAxis == nullptr) continue;
                toAxis->setLabelsVisible(fromAxis->labelsVisible());
                toAxis->setGridLineVisible(fromAxis->isGridLineVisible());
                toAxis->setMinorGridLineVisible(fromAxis->isMinorGridLineVisible());
                toAxis->setLineVisible(fromAxis->isLineVisible());
                toAxis->setLabelsBrush(fromAxis->labelsBrush());
                toAxis->setTitleBrush(fromAxis->titleBrush());
                toAxis->setLinePen(fromAxis->linePen());
                toAxis->setGridLinePen(fromAxis->gridLinePen());
                toAxis->setTitleText(fromAxis->titleText());
                toAxis->setLabelFormat(fromAxis->labelFormat());
                chart->addAxis(toAxis, fromAxis->alignment());
                axes.insert(fromAxis, toAxis);
            }

            QHash<const QLineSeries*, QLineSeries*> lines;
            const auto cloneLine = [&lines, &copy, chart](QLineSeries* sourceLine) -> QLineSeries*
            {
                if (sourceLine == nullptr) return nullptr;
                if (QLineSeries* const existing = lines.value(sourceLine)) return existing;
                auto* const line = new QLineSeries(chart);
                line->setName(sourceLine->name());
                line->setPen(sourceLine->pen());
                line->replace(sourceLine->points());
                lines.insert(sourceLine, line);
                copy.lines.emplace_back(sourceLine, line);
                return line;
            };
            for (QAbstractSeries* const fromSeries : original->series())
            {
                QAbstractSeries* toSeries = nullptr;
                if (auto* const area = dynamic_cast<QAreaSeries*>(fromSeries))
                {
                    auto* const clone = new QAreaSeries(
                        cloneLine(area->upperSeries()), cloneLine(area->lowerSeries()), chart);
                    clone->setPen(area->pen());
                    clone->setBrush(area->brush());
                    toSeries = clone;
                }
                else if (auto* const line = dynamic_cast<QLineSeries*>(fromSeries))
                {
                    toSeries = cloneLine(line);
                }
                else if (auto* const bars = dynamic_cast<QBarSeries*>(fromSeries))
                {
                    auto* const clone = new QBarSeries(chart);
                    for (QBarSet* const fromSet : bars->barSets())
                    {
                        auto* const toSet = new QBarSet(fromSet->label(), clone);
                        for (const qreal value : fromSet->values()) toSet->append(value);
                        toSet->setBrush(fromSet->brush());
                        toSet->setBorderColor(fromSet->borderColor());
                        toSet->setLabelBrush(fromSet->labelBrush());
                        clone->append(toSet);
                        copy.barSets.emplace_back(fromSet, toSet);
                    }
                    toSeries = clone;
                }
                if (toSeries == nullptr) continue;
                toSeries->setName(fromSeries->name());
                chart->addSeries(toSeries);
                for (QAbstractAxis* const attached : fromSeries->attachedAxes())
                {
                    if (QAbstractAxis* const toAxis = axes.value(attached))
                        toSeries->attachAxis(toAxis);
                }
            }
            auto* const view = new QChartView(chart, parent);
            view->setFrameShape(QFrame::NoFrame);
            view->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            view->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            view->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
            view->setRenderHint(QPainter::Antialiasing);
            view->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            copy.from = from;
            copy.to = view;
            m_charts.push_back(std::move(copy));
            return view;
        }

        QWidget* cloneWidget(QWidget* from, QWidget* parent)
        {
            QWidget* to = nullptr;
            if (auto* const label = qobject_cast<QLabel*>(from))
            {
                auto* const copy = new QLabel(label->text(), parent);
                copy->setTextFormat(label->textFormat());
                copy->setAlignment(label->alignment());
                copy->setWordWrap(label->wordWrap());
                copy->setTextInteractionFlags(label->textInteractionFlags());
                m_labels.emplace_back(label, copy);
                to = copy;
            }
            else if (auto* const list = qobject_cast<QListWidget*>(from))
            {
                auto* const copy = new QListWidget(parent);
                copy->setFrameShape(QFrame::NoFrame);
                copy->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
                copy->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
                copy->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
                copy->setSpacing(2);
                copy->setMinimumWidth(140);
                m_sidebarSource = list;
                m_sidebarCopy = copy;
                connect(copy, &QListWidget::currentRowChanged, copy,
                    [source = QPointer<QListWidget>(list)](int row)
                    {
                        if (source != nullptr && row >= 0) source->setCurrentRow(row);
                    });
                to = copy;
            }
            else if (auto* const area = qobject_cast<QScrollArea*>(from))
            {
                auto* const copy = new QScrollArea(parent);
                copy->setWidgetResizable(area->widgetResizable());
                copy->setFrameShape(area->frameShape());
                copy->setHorizontalScrollBarPolicy(area->horizontalScrollBarPolicy());
                copy->setVerticalScrollBarPolicy(area->verticalScrollBarPolicy());
                if (area->widget() != nullptr)
                    copy->setWidget(cloneWidget(area->widget(), copy));
                to = copy;
            }
            else if (auto* const memory = dynamic_cast<MemoryCompositionHistoryWidget*>(from))
            {
                auto* const copy = new MemoryCompositionHistoryWidget(parent);
                m_memories.emplace_back(memory, copy);
                to = copy;
            }
            else if (auto* const chart = dynamic_cast<QChartView*>(from))
            {
                to = cloneChartView(chart, parent);
            }
            else if (auto* const frame = qobject_cast<QFrame*>(from))
            {
                auto* const copy = new QFrame(parent);
                copy->setFrameShape(frame->frameShape());
                to = copy;
            }
            else
            {
                to = new QWidget(parent);
            }
            to->setSizePolicy(from->sizePolicy());
            const WidgetStyle style = m_widgetStyle(from);
            to->setStyleSheet(style.sheet);
            if (qobject_cast<QLabel*>(to) != nullptr && style.minimumHeight == style.maximumHeight
                && style.maximumHeight > 0 && style.maximumHeight < 200)
                to->setFixedHeight(style.maximumHeight);
            if (from->layout() != nullptr)
                to->setLayout(cloneLayout(from->layout(), to));
            return to;
        }

        QLayout* cloneLayout(QLayout* from, QWidget* parent)
        {
            QLayout* to = nullptr;
            if (auto* const grid = dynamic_cast<QGridLayout*>(from))
            {
                auto* const copy = new QGridLayout();
                for (int index = 0; index < grid->count(); ++index)
                {
                    int row = 0, column = 0, rowSpan = 1, columnSpan = 1;
                    grid->getItemPosition(index, &row, &column, &rowSpan, &columnSpan);
                    QLayoutItem* const item = grid->itemAt(index);
                    if (QWidget* const widget = item->widget())
                    {
                        copy->addWidget(cloneWidget(widget, parent),
                            row, column, rowSpan, columnSpan, item->alignment());
                    }
                    else if (QLayout* const nested = item->layout())
                        copy->addLayout(cloneLayout(nested, parent), row, column, rowSpan, columnSpan);
                    else if (QSpacerItem* const spacer = item->spacerItem())
                        copy->addItem(new QSpacerItem(spacer->sizeHint().width(),
                            spacer->sizeHint().height(), spacer->sizePolicy().horizontalPolicy(),
                            spacer->sizePolicy().verticalPolicy()), row, column, rowSpan, columnSpan);
                }
                for (int row = 0; row < grid->rowCount(); ++row)
                    copy->setRowStretch(row, grid->rowStretch(row));
                for (int column = 0; column < grid->columnCount(); ++column)
                    copy->setColumnStretch(column, grid->columnStretch(column));
                to = copy;
            }
            else if (auto* const box = dynamic_cast<QBoxLayout*>(from))
            {
                auto* const copy = new QBoxLayout(box->direction());
                for (int index = 0; index < box->count(); ++index)
                {
                    QLayoutItem* const item = box->itemAt(index);
                    if (QWidget* const widget = item->widget())
                    {
                        copy->addWidget(cloneWidget(widget, parent),
                            box->stretch(index), item->alignment());
                    }
                    else if (QLayout* const nested = item->layout())
                        copy->addLayout(cloneLayout(nested, parent), box->stretch(index));
                    else if (QSpacerItem* const spacer = item->spacerItem())
                        copy->addSpacerItem(new QSpacerItem(spacer->sizeHint().width(),
                            spacer->sizeHint().height(), spacer->sizePolicy().horizontalPolicy(),
                            spacer->sizePolicy().verticalPolicy()));
                }
                to = copy;
            }
            else return new QVBoxLayout();
            const LayoutStyle style = m_layoutStyle(from);
            to->setContentsMargins(style.margins);
            to->setSpacing(style.spacing);
            if (auto* const grid = dynamic_cast<QGridLayout*>(to))
            {
                grid->setHorizontalSpacing(style.horizontalSpacing);
                grid->setVerticalSpacing(style.verticalSpacing);
            }
            return to;
        }

        void synchronizeSidebar()
        {
            QListWidget* const source = m_sidebarSource.data();
            QListWidget* const copy = m_sidebarCopy.data();
            if (source == nullptr || copy == nullptr) return;
            while (copy->count() < source->count())
            {
                auto* const item = new QListWidgetItem();
                auto* const card = new PerformanceNavCard(copy);
                item->setSizeHint(QSize(0, card->sizeHint().height()));
                copy->addItem(item);
                copy->setItemWidget(item, card);
            }
            while (copy->count() > source->count()) delete copy->takeItem(copy->count() - 1);
            for (int row = 0; row < source->count(); ++row)
            {
                auto* const from = dynamic_cast<PerformanceNavCard*>(
                    source->itemWidget(source->item(row)));
                auto* const to = dynamic_cast<PerformanceNavCard*>(
                    copy->itemWidget(copy->item(row)));
                if (from != nullptr && to != nullptr) to->copyDisplayFrom(*from);
            }
            if (copy->currentRow() != source->currentRow()) copy->setCurrentRow(source->currentRow());
        }

        void rebuild()
        {
            QWidget* const source = m_source.data();
            if (source == nullptr) return;
            QLayout* const layout = this->layout();
            while (QLayoutItem* const item = layout->takeAt(0))
            {
                delete item->widget();
                delete item;
            }
            m_labels.clear();
            m_memories.clear();
            m_charts.clear();
            m_sidebarSource = nullptr;
            m_sidebarCopy = nullptr;
            layout->addWidget(cloneWidget(source, this));
            synchronizeSidebar();
        }

        QPointer<QWidget> m_source;
        WidgetStyleLookup m_widgetStyle;
        LayoutStyleLookup m_layoutStyle;
        std::vector<std::pair<QPointer<QLabel>, QPointer<QLabel>>> m_labels;
        std::vector<std::pair<QPointer<MemoryCompositionHistoryWidget>,
            QPointer<MemoryCompositionHistoryWidget>>> m_memories;
        std::vector<ChartCopy> m_charts;
        QPointer<QListWidget> m_sidebarSource;
        QPointer<QListWidget> m_sidebarCopy;
    };

    HHOOK utilizationPickHook = nullptr;
    std::function<void(HWND)> utilizationPickCallback;
    HWND utilizationFollowHookTarget = nullptr;
    HWND utilizationFollowFloatHandle = nullptr;
    std::function<void(DWORD)> utilizationFollowCallback;

    void utilizationRaiseFloatWithTarget()
    {
        const HWND target = utilizationFollowHookTarget;
        const HWND card = utilizationFollowFloatHandle;
        if (target == nullptr || card == nullptr || ::IsWindow(target) == FALSE
            || ::IsWindow(card) == FALSE || ::IsWindowVisible(target) == FALSE
            || ::IsWindowVisible(card) == FALSE || ::IsIconic(target) != FALSE
            || (::GetWindowLongPtrW(target, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0)
            return;
        const HWND preceding = ::GetWindow(target, GW_HWNDPREV);
        if (preceding != card)
            ::SetWindowPos(card, preceding != nullptr ? preceding : HWND_TOP,
                0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    LRESULT CALLBACK utilizationMousePickProc(int code, WPARAM message, LPARAM data)
    {
        if (code == HC_ACTION && message == WM_LBUTTONDOWN && utilizationPickCallback)
        {
            const auto* const mouseData = reinterpret_cast<const MSLLHOOKSTRUCT*>(data);
            const HWND picked = ::WindowFromPoint(mouseData->pt);
            const auto callback = utilizationPickCallback;
            QTimer::singleShot(0, qApp, [callback, picked]() { callback(picked); });
        }
        return ::CallNextHookEx(utilizationPickHook, code, message, data);
    }

    void CALLBACK utilizationFollowEventProc(HWINEVENTHOOK, DWORD event, HWND window,
        LONG objectId, LONG childId, DWORD, DWORD)
    {
        if (window == utilizationFollowHookTarget && objectId == OBJID_WINDOW
            && childId == CHILDID_SELF && utilizationFollowCallback)
        {
            if (event == EVENT_OBJECT_REORDER || event == EVENT_OBJECT_SHOW)
                utilizationRaiseFloatWithTarget();
            const auto callback = utilizationFollowCallback;
            QTimer::singleShot(0, qApp, [callback, event]() { callback(event); });
        }
    }

    void CALLBACK utilizationForegroundEventProc(HWINEVENTHOOK, DWORD, HWND foreground,
        LONG, LONG, DWORD, DWORD)
    {
        if (utilizationFollowCallback)
        {
            if (foreground == utilizationFollowHookTarget)
                utilizationRaiseFloatWithTarget();
            const auto callback = utilizationFollowCallback;
            QTimer::singleShot(0, qApp, [callback]() { callback(EVENT_SYSTEM_FOREGROUND); });
        }
    }

    QString utilizationWindowTitle(HWND window)
    {
        const int length = ::GetWindowTextLengthW(window);
        if (length <= 0) return {};
        std::wstring title(static_cast<std::size_t>(length) + 1, L'\0');
        const int copied = ::GetWindowTextW(window, title.data(), length + 1);
        return copied > 0 ? QString::fromWCharArray(title.data(), copied) : QString();
    }

    QString utilizationWindowExecutable(HWND window)
    {
        DWORD processId = 0;
        ::GetWindowThreadProcessId(window, &processId);
        if (processId == 0) return {};
        const HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (process == nullptr) return {};
        std::wstring path(32768, L'\0');
        DWORD length = static_cast<DWORD>(path.size());
        const bool succeeded = ::QueryFullProcessImageNameW(process, 0, path.data(), &length) != FALSE;
        ::CloseHandle(process);
        return succeeded ? QString::fromWCharArray(path.data(), static_cast<int>(length)) : QString();
    }

    bool utilizationWindowIsTopMost(HWND window)
    {
        return (::GetWindowLongPtrW(window, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0;
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
    m_utilizationPreferencesSaveTimer = new QTimer(this);
    m_utilizationPreferencesSaveTimer->setSingleShot(true);
    m_utilizationPreferencesSaveTimer->setInterval(350);
    connect(m_utilizationPreferencesSaveTimer, &QTimer::timeout,
        this, &HardwareDock::saveUtilizationFloatingPreferences);
    m_utilizationFollowTimer = new QTimer(this);
    m_utilizationFollowTimer->setInterval(250);
    connect(m_utilizationFollowTimer, &QTimer::timeout,
        this, &HardwareDock::synchronizeUtilizationFollow);

    // 启动阶段先填充占位文本，避免首帧等待 PowerShell 导致窗口卡住。
    m_cachedOverviewFields.note(QStringLiteral("硬件概览加载中，请稍候..."));
    m_cachedGpuFields.note(QStringLiteral("显卡信息加载中，请稍候..."));
    m_cachedMemoryFields.note(QStringLiteral("内存信息加载中，请稍候..."));
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
    clearUtilizationFollowHooks();
    delete m_utilizationPickDialog.data();
    m_utilizationPickDialog = nullptr;
    delete m_utilizationFollowMirror.data();
    m_utilizationFollowMirror = nullptr;
    if (m_utilizationPreferencesSaveTimer != nullptr && m_utilizationPreferencesSaveTimer->isActive())
    {
        saveUtilizationFloatingPreferences();
    }
    qApp->removeEventFilter(this);
    // The floating window is parentless so that hiding the main window does not hide it.
    // Its borrowed child must be destroyed with the dock during application shutdown.
    delete m_utilizationFloatingWindow.data();
    m_utilizationFloatingWindow = nullptr;
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
    QWidget* const eventWidget = qobject_cast<QWidget*>(watchedObject);
    // 全局 palette 传播尚在遍历子树时只排队，主题完成后统一刷新性能图和浮窗快照。
    if (eventObject != nullptr
        && (eventObject->type() == QEvent::ApplicationPaletteChange
            || (eventObject->type() == QEvent::PaletteChange && eventWidget == this)))
    {
        scheduleUtilizationThemeRefresh();
    }
    QWidget* const floatingWindow = m_utilizationFloatingWindow.data();
    if (eventObject != nullptr && floatingWindow != nullptr && eventWidget != nullptr
        && (eventWidget == floatingWindow || floatingWindow->isAncestorOf(eventWidget))
        && (m_utilizationPickDialog == nullptr
            || (eventWidget != m_utilizationPickDialog
                && !m_utilizationPickDialog->isAncestorOf(eventWidget))))
    {
        if (eventObject->type() == QEvent::Close && eventWidget == floatingWindow)
        {
            if (m_utilizationFollowTarget != nullptr && m_utilizationFollowClickThrough) return true;
            QTimer::singleShot(0, this, [this]()
            {
                if (m_utilizationFollowTarget != nullptr) stopUtilizationFollow(false, true);
                else restoreUtilizationFloatingWindow();
            });
            return true;
        }
        if (eventObject->type() == QEvent::KeyPress)
        {
            const auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
            if (keyEvent->key() == Qt::Key_Escape)
            {
                if (m_utilizationFollowTarget != nullptr && m_utilizationFollowClickThrough) return true;
                QTimer::singleShot(0, this, [this]()
                {
                    if (m_utilizationFollowTarget != nullptr) stopUtilizationFollow(false, true);
                    else restoreUtilizationFloatingWindow();
                });
                return true;
            }
            if (keyEvent->modifiers() & Qt::ControlModifier)
            {
                const bool shift = keyEvent->modifiers() & Qt::ShiftModifier;
                const int key = keyEvent->key();
                const bool plus = key == Qt::Key_Plus || key == Qt::Key_Equal;
                const bool minus = key == Qt::Key_Minus || key == Qt::Key_Underscore;
                if (key == Qt::Key_0 && !shift)
                {
                    m_utilizationFloatingScalePercent = 100;
                    m_utilizationFloatingBackgroundOpacityPercent = 100;
                    resizeUtilizationFloatingWindow();
                    applyUtilizationFloatingTheme();
                    m_utilizationPreferencesSaveTimer->start();
                    return true;
                }
                if (plus || minus)
                {
                    if (shift)
                    {
                        m_utilizationFloatingBackgroundOpacityPercent = std::clamp(
                            m_utilizationFloatingBackgroundOpacityPercent + (plus ? -5 : 5), 0, 100);
                        applyUtilizationFloatingTheme();
                    }
                    else
                    {
                        m_utilizationFloatingScalePercent = std::clamp(
                            m_utilizationFloatingScalePercent + (plus ? 10 : -10), 25, 300);
                        resizeUtilizationFloatingWindow();
                    }
                    m_utilizationPreferencesSaveTimer->start();
                    return true;
                }
            }
        }
        if (eventObject->type() == QEvent::Wheel)
        {
            const auto* wheelEvent = static_cast<QWheelEvent*>(eventObject);
            if (wheelEvent->modifiers() & Qt::ControlModifier)
            {
                const QPoint wheelDelta = wheelEvent->angleDelta();
                const int delta = wheelDelta.y() != 0 ? wheelDelta.y() : wheelDelta.x();
                if (delta != 0)
                {
                    if (wheelEvent->modifiers() & Qt::ShiftModifier)
                    {
                        m_utilizationFloatingBackgroundOpacityPercent = std::clamp(
                            m_utilizationFloatingBackgroundOpacityPercent + (delta > 0 ? 5 : -5), 0, 100);
                        applyUtilizationFloatingTheme();
                    }
                    else
                    {
                        m_utilizationFloatingScalePercent = std::clamp(
                            m_utilizationFloatingScalePercent + (delta > 0 ? 10 : -10), 25, 300);
                        resizeUtilizationFloatingWindow();
                    }
                    m_utilizationPreferencesSaveTimer->start();
                }
                return true;
            }
        }
        if (eventObject->type() == QEvent::ContextMenu)
        {
            const auto* contextEvent = static_cast<QContextMenuEvent*>(eventObject);
            QMenu menu(floatingWindow);
            const QPalette menuPalette = floatingWindow->palette();
            menu.setPalette(menuPalette);
            menu.setStyleSheet(QStringLiteral(
                "QMenu{color:%1;background-color:%2;border:1px solid %3;}"
                "QMenu::item:selected{color:%1;background-color:%4;}")
                .arg(menuPalette.color(QPalette::Text).name(QColor::HexRgb),
                    menuPalette.color(QPalette::Window).name(QColor::HexRgb),
                    menuPalette.color(QPalette::Mid).name(QColor::HexRgb),
                    menuPalette.color(QPalette::AlternateBase).name(QColor::HexRgb)));
            QAction* const topMostAction = menu.addAction(ks::i18n::contextText(
                QStringLiteral("hardware.utilization.floating.top_most"), QStringLiteral("置顶")));
            topMostAction->setCheckable(true);
            topMostAction->setChecked(m_utilizationFollowTarget == nullptr && m_utilizationFloatingTopMost);
            topMostAction->setEnabled(m_utilizationFollowTarget == nullptr);
            connect(topMostAction, &QAction::toggled, this, [this, floatingWindow](const bool enabled)
            {
                m_utilizationFloatingTopMost = enabled;
                const HWND handle = reinterpret_cast<HWND>(floatingWindow->winId());
                ::SetWindowPos(handle, enabled ? HWND_TOPMOST : HWND_NOTOPMOST,
                    0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                m_utilizationPreferencesSaveTimer->start();
            });
            const bool darkMode = m_utilizationFloatingThemeMode == QStringLiteral("dark")
                || (m_utilizationFloatingThemeMode == QStringLiteral("follow_main")
                    && KswordTheme::IsDarkModeEnabled());
            QAction* const themeAction = menu.addAction(ks::i18n::contextText(
                darkMode ? QStringLiteral("hardware.utilization.floating.switch_light")
                    : QStringLiteral("hardware.utilization.floating.switch_dark"),
                darkMode ? QStringLiteral("切换浅色") : QStringLiteral("切换深色")));
            connect(themeAction, &QAction::triggered, this, [this, darkMode]()
            {
                m_utilizationFloatingThemeMode = darkMode ? QStringLiteral("light") : QStringLiteral("dark");
                applyUtilizationFloatingTheme();
                m_utilizationPreferencesSaveTimer->start();
            });
            if (m_utilizationFollowTarget == nullptr)
            {
                QAction* const followAction = menu.addAction(ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.floating.follow"), QStringLiteral("窗口跟随")));
                connect(followAction, &QAction::triggered, this,
                    &HardwareDock::beginUtilizationWindowPick);
            }
            else
            {
                QAction* const clickThroughAction = menu.addAction(ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.floating.click_through"), QStringLiteral("点击穿透")));
                clickThroughAction->setCheckable(true);
                clickThroughAction->setChecked(m_utilizationFollowClickThrough);
                connect(clickThroughAction, &QAction::toggled, this,
                    &HardwareDock::setUtilizationFollowClickThrough);
                QAction* const detachAction = menu.addAction(ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.floating.stop_follow"), QStringLiteral("取消跟随")));
                connect(detachAction, &QAction::triggered, this,
                    [this]() { stopUtilizationFollow(false, true); });
            }
            menu.exec(contextEvent->globalPos());
            return true;
        }
        if (eventObject->type() == QEvent::MouseButtonDblClick)
        {
            const auto* mouseEvent = static_cast<QMouseEvent*>(eventObject);
            if (mouseEvent->button() == Qt::LeftButton)
            {
                QTimer::singleShot(0, this, [this]()
                {
                    if (m_utilizationFollowTarget != nullptr)
                    {
                        stopUtilizationFollow(false, true);
                    }
                    else
                    {
                        restoreUtilizationFloatingWindow();
                    }
                });
                return true;
            }
        }
        if (eventObject->type() == QEvent::Resize && eventWidget == floatingWindow)
        {
            QTimer::singleShot(0, this, [this]()
            {
                applyUtilizationFloatingContentScale();
                if (m_utilizationFloatingMode == UtilizationFloatingMode::Sidebar)
                {
                    syncUtilizationSidebarCardWidths();
                }
                else if (m_utilizationFloatingMode == UtilizationFloatingMode::Detail)
                {
                    adjustUtilizationChartHeights();
                }
            });
        }
        if (eventObject->type() == QEvent::MouseButtonPress)
        {
            const auto* mouseEvent = static_cast<QMouseEvent*>(eventObject);
            if (mouseEvent->button() == Qt::LeftButton)
            {
                const QPoint globalPosition = mouseEvent->globalPosition().toPoint();
                const QPoint windowPosition = floatingWindow->mapFromGlobal(globalPosition);
                constexpr int kResizeBorder = 12;
                m_utilizationResizeEdges = {};
                if (windowPosition.x() < kResizeBorder) m_utilizationResizeEdges |= Qt::LeftEdge;
                if (windowPosition.x() >= floatingWindow->width() - kResizeBorder) m_utilizationResizeEdges |= Qt::RightEdge;
                if (windowPosition.y() < kResizeBorder) m_utilizationResizeEdges |= Qt::TopEdge;
                if (windowPosition.y() >= floatingWindow->height() - kResizeBorder) m_utilizationResizeEdges |= Qt::BottomEdge;
                m_utilizationDragStartGlobal = globalPosition;
                m_utilizationResizeStartGeometry = floatingWindow->geometry();
                m_utilizationDragArmed = true;
                m_utilizationDragging = false;
            }
        }
        if (eventObject->type() == QEvent::MouseMove && m_utilizationDragArmed)
        {
            const auto* mouseEvent = static_cast<QMouseEvent*>(eventObject);
            if (!(mouseEvent->buttons() & Qt::LeftButton))
            {
                m_utilizationDragArmed = false;
                m_utilizationResizeEdges = {};
            }
            else
            {
                const QPoint delta = mouseEvent->globalPosition().toPoint() - m_utilizationDragStartGlobal;
                if (m_utilizationResizeEdges)
                {
                    QRect nextGeometry = m_utilizationResizeStartGeometry;
                    if (m_utilizationResizeEdges & Qt::LeftEdge) nextGeometry.setLeft(nextGeometry.left() + delta.x());
                    if (m_utilizationResizeEdges & Qt::RightEdge) nextGeometry.setRight(nextGeometry.right() + delta.x());
                    if (m_utilizationResizeEdges & Qt::TopEdge) nextGeometry.setTop(nextGeometry.top() + delta.y());
                    if (m_utilizationResizeEdges & Qt::BottomEdge) nextGeometry.setBottom(nextGeometry.bottom() + delta.y());
                    if (nextGeometry.width() >= floatingWindow->minimumWidth()
                        && nextGeometry.height() >= floatingWindow->minimumHeight())
                    {
                        floatingWindow->setGeometry(nextGeometry);
                    }
                    return true;
                }
                if (!m_utilizationDragging && delta.manhattanLength() >= QApplication::startDragDistance())
                {
                    m_utilizationDragging = true;
                    m_utilizationDragArmed = false;
                    // Qt global mouse positions and QWidget positions are expressed in
                    // different logical coordinate spaces after a per-monitor DPI change.
                    // Let the window manager move the HWND so crossing monitors cannot
                    // feed a rescaled delta back into its geometry on every mouse move.
                    QWindow* const windowHandle = floatingWindow->windowHandle();
                    if (windowHandle != nullptr && windowHandle->startSystemMove())
                    {
                        return true;
                    }
                    const HWND nativeHandle = reinterpret_cast<HWND>(floatingWindow->winId());
                    if (nativeHandle != nullptr && ::IsWindow(nativeHandle) != FALSE)
                    {
                        POINT cursorPosition{};
                        ::GetCursorPos(&cursorPosition);
                        ::ReleaseCapture();
                        ::SendMessageW(nativeHandle, WM_NCLBUTTONDOWN, HTCAPTION,
                            MAKELPARAM(cursorPosition.x, cursorPosition.y));
                        return true;
                    }
                    m_utilizationDragging = false;
                }
            }
        }
        if (eventObject->type() == QEvent::MouseButtonRelease)
        {
            const bool consumeRelease = m_utilizationDragging || m_utilizationResizeEdges;
            if (m_utilizationResizeEdges && !m_utilizationFloatingBaseSize.isEmpty())
            {
                const double widthRatio = static_cast<double>(floatingWindow->width())
                    / m_utilizationFloatingBaseSize.width();
                const double heightRatio = static_cast<double>(floatingWindow->height())
                    / m_utilizationFloatingBaseSize.height();
                m_utilizationFloatingScalePercent = std::clamp(
                    qRound(std::min(widthRatio, heightRatio) * 100.0), 25, 300);
                m_utilizationPreferencesSaveTimer->start();
            }
            if (m_utilizationFollowTarget != nullptr && consumeRelease)
                captureUtilizationFollowOffset();
            m_utilizationDragArmed = false;
            m_utilizationDragging = false;
            m_utilizationResizeEdges = {};
            if (consumeRelease)
            {
                return true;
            }
        }
    }

    if (eventObject != nullptr && eventObject->type() == QEvent::MouseButtonDblClick
        && (m_utilizationFloatingMode == UtilizationFloatingMode::None
            || m_utilizationFollowTarget != nullptr)
        && m_sideTabWidget != nullptr && m_sideTabWidget->currentWidget() == m_utilizationPage
        && eventWidget != nullptr)
    {
        const auto* mouseEvent = static_cast<QMouseEvent*>(eventObject);
        if (mouseEvent->button() == Qt::LeftButton)
        {
            QWidget* const sidebarViewport = m_utilizationSidebarList != nullptr
                ? m_utilizationSidebarList->viewport() : nullptr;
            if (sidebarViewport != nullptr
                && (eventWidget == sidebarViewport || sidebarViewport->isAncestorOf(eventWidget)
                    || eventWidget == m_utilizationFollowMirror
                    || (m_utilizationFollowMirror != nullptr
                        && m_utilizationFollowMirror->isAncestorOf(eventWidget))))
            {
                if (m_utilizationFollowTarget != nullptr)
                {
                    stopUtilizationFollow(m_utilizationFollowClickThrough, true);
                }
                else openUtilizationFloatingWindow(true);
                return true;
            }
            QWidget* const detailPage = m_utilizationDetailStack != nullptr
                ? m_utilizationDetailStack->currentWidget() : nullptr;
            if (detailPage != nullptr
                && (eventWidget == detailPage || detailPage->isAncestorOf(eventWidget)))
            {
                if (m_utilizationFollowTarget != nullptr)
                {
                    stopUtilizationFollow(m_utilizationFollowClickThrough, true);
                }
                else openUtilizationFloatingWindow(false);
                return true;
            }
        }
    }

    if (eventObject != nullptr
        && eventObject->type() == QEvent::Resize
        && eventWidget != nullptr && m_virtualNetworkScrollArea != nullptr
        && eventWidget == m_virtualNetworkScrollArea->viewport())
    {
        QTimer::singleShot(0, this, [this]() { relayoutVirtualNetworkTiles(); });
    }

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

    startPerformanceSampling(SamplingScope::HardwareDetails);

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

void HardwareDock::startPerformanceSampling(const SamplingScope scope)
{
    const bool enableDetails = scope == SamplingScope::HardwareDetails
        && !m_hardwareDetailsSamplingEnabled;
    m_hardwareDetailsSamplingEnabled = m_hardwareDetailsSamplingEnabled
        || scope == SamplingScope::HardwareDetails;
    if (m_initialSamplingStarted)
    {
        if (enableDetails)
        {
            requestAsyncStaticInfoRefresh();
            requestAsyncSensorRefresh();
            requestAsyncR0HardwareHealthRefresh();
        }
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
        if (dockPointer->m_hardwareDetailsSamplingEnabled)
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
    ks::ui::StylePageTabs(m_sideTabWidget);
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

    m_overviewEditor = new ks::ui::StructuredFieldView(m_overviewPage);
    m_overviewEditor->setPresentation(ks::ui::StructuredFieldView::Presentation::Tree);
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
    // 磁盘和 GPU 按设备动态追加；实体网卡独立显示，虚拟网卡共用首次发现时创建的入口。
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
    if (m_utilizationFloatingMode == UtilizationFloatingMode::Sidebar)
    {
        cardPointer->setFloatingScaleFactor(m_utilizationFloatingAppliedContentScale);
        if (QWidget* const floatingWindow = m_utilizationFloatingWindow.data())
        {
            cardPointer->setFloatingThemeSurface(floatingWindow->palette().color(QPalette::Window));
        }
    }
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
    if (m_utilizationDetailStack->currentWidget() == m_virtualNetworkPage)
    {
        QTimer::singleShot(0, this, [this]() { relayoutVirtualNetworkTiles(); });
    }

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

QWidget* HardwareDock::utilizationChartBottomWidget(const UtilizationNavEntry& entry) const
{
    switch (entry.kind)
    {
    case UtilizationDeviceKind::Cpu:
        return m_coreChartScrollArea;
    case UtilizationDeviceKind::Memory:
        return m_memoryCompositionHistoryWidget;
    case UtilizationDeviceKind::Disk:
        return entry.deviceIndex >= 0 && entry.deviceIndex < static_cast<int>(m_diskUtilDevices.size())
            ? m_diskUtilDevices[static_cast<std::size_t>(entry.deviceIndex)].chartView : m_diskUtilChartView;
    case UtilizationDeviceKind::Network:
        return entry.deviceIndex >= 0 && entry.deviceIndex < static_cast<int>(m_networkUtilDevices.size())
            ? m_networkUtilDevices[static_cast<std::size_t>(entry.deviceIndex)].chartView : m_networkUtilChartView;
    case UtilizationDeviceKind::VirtualNetwork:
        return m_virtualNetworkScrollArea;
    case UtilizationDeviceKind::Gpu:
        return entry.deviceIndex >= 0 && entry.deviceIndex < static_cast<int>(m_gpuUtilDevices.size())
            ? m_gpuUtilDevices[static_cast<std::size_t>(entry.deviceIndex)].sharedMemoryChartView
            : m_gpuSharedMemoryChartView;
    }
    return nullptr;
}

std::vector<QWidget*> HardwareDock::utilizationDetailWidgets(const UtilizationNavEntry& entry) const
{
    switch (entry.kind)
    {
    case UtilizationDeviceKind::Cpu:
        return { m_cpuUtilPrimaryDetailLabel, m_cpuUtilSecondaryDetailLabel, m_cpuUtilTertiaryDetailLabel };
    case UtilizationDeviceKind::Memory:
        return { m_memoryUtilPrimaryDetailLabel, m_memoryUtilSecondaryDetailLabel };
    case UtilizationDeviceKind::Disk:
        return { entry.deviceIndex >= 0 && entry.deviceIndex < static_cast<int>(m_diskUtilDevices.size())
            ? m_diskUtilDevices[static_cast<std::size_t>(entry.deviceIndex)].detailLabel : m_diskUtilDetailLabel };
    case UtilizationDeviceKind::Network:
        return { entry.deviceIndex >= 0 && entry.deviceIndex < static_cast<int>(m_networkUtilDevices.size())
            ? m_networkUtilDevices[static_cast<std::size_t>(entry.deviceIndex)].detailLabel : m_networkUtilDetailLabel };
    case UtilizationDeviceKind::VirtualNetwork:
        return {};
    case UtilizationDeviceKind::Gpu:
        return { entry.deviceIndex >= 0 && entry.deviceIndex < static_cast<int>(m_gpuUtilDevices.size())
            ? m_gpuUtilDevices[static_cast<std::size_t>(entry.deviceIndex)].detailLabel : m_gpuUtilDetailLabel };
    }
    return {};
}

void HardwareDock::openUtilizationFloatingWindow(const bool sidebarMode)
{
    if (m_utilizationFloatingMode != UtilizationFloatingMode::None
        || m_utilizationBodySplitter == nullptr || m_utilizationDetailStack == nullptr
        || m_utilizationSidebarList == nullptr || m_utilizationSidebarList->count() == 0)
    {
        return;
    }

    QWidget* const mainWindow = window();
    QWidget* sourceWidget = sidebarMode ? static_cast<QWidget*>(m_utilizationSidebarList)
        : m_utilizationDetailStack->currentWidget();
    if (mainWindow == nullptr || sourceWidget == nullptr)
    {
        return;
    }

    const auto preferences = ks::settings::loadAppearanceSettings();
    m_utilizationFloatingScalePercent = preferences.utilizationFloatingScalePercent;
    m_utilizationFloatingBackgroundOpacityPercent = preferences.utilizationFloatingBackgroundOpacityPercent;
    m_utilizationFloatingTopMost = preferences.utilizationFloatingTopMost;
    m_utilizationFloatingThemeMode = preferences.utilizationFloatingThemeMode;
    m_utilizationFollowTitle = preferences.utilizationFloatingFollowTitle;
    m_utilizationFollowExecutable = preferences.utilizationFloatingFollowExecutable;
    m_utilizationFollowOffset = QPoint(preferences.utilizationFloatingFollowOffsetX,
        preferences.utilizationFloatingFollowOffsetY);
    m_utilizationFollowOffsetLogical = preferences.utilizationFloatingFollowOffsetLogical;
    m_utilizationFollowClickThrough = preferences.utilizationFloatingFollowClickThrough;

    QSize initialSize(220, 320);
    if (!sidebarMode)
    {
        const int selectedRow = m_utilizationSidebarList->currentRow();
        if (selectedRow < 0 || selectedRow >= static_cast<int>(m_utilizationNavEntries.size()))
        {
            return;
        }
        const UtilizationNavEntry& entry = m_utilizationNavEntries[static_cast<std::size_t>(selectedRow)];
        if (entry.detailPage != sourceWidget)
        {
            return;
        }
        QWidget* const bottomWidget = utilizationChartBottomWidget(entry);
        if (bottomWidget == nullptr)
        {
            return;
        }
        const int chartBottom = bottomWidget->mapTo(sourceWidget, QPoint(0, bottomWidget->height())).y();
        const int bottomMargin = sourceWidget->layout() != nullptr
            ? sourceWidget->layout()->contentsMargins().bottom() : 0;
        initialSize = QSize(std::max(320, sourceWidget->width()),
            std::max(160, chartBottom + bottomMargin));
    }

    const QPoint sourceGlobalPosition = sourceWidget->mapToGlobal(QPoint(0, 0));
    QScreen* targetScreen = QGuiApplication::screenAt(sourceGlobalPosition);
    if (targetScreen == nullptr)
    {
        targetScreen = QGuiApplication::primaryScreen();
    }
    m_utilizationFloatingBaseSize = initialSize;
    initialSize = QSize(std::max(1, initialSize.width() * m_utilizationFloatingScalePercent / 100),
        std::max(1, initialSize.height() * m_utilizationFloatingScalePercent / 100));
    if (targetScreen != nullptr)
    {
        const QRect workArea = targetScreen->availableGeometry();
        initialSize = initialSize.boundedTo(workArea.size());
    }

    QWidget* const floatingWindow = new UtilizationFloatingWindow(m_utilizationFloatingTopMost);
    static_cast<UtilizationFloatingWindow*>(floatingWindow)->setMoveFinishedHandler(
        [guard = QPointer<HardwareDock>(this)](const bool resized)
        {
            if (guard == nullptr) return;
            if (resized) guard->captureUtilizationFloatingScale();
            if (guard->m_utilizationFollowTarget != nullptr)
                guard->captureUtilizationFollowOffset();
        });
    floatingWindow->setMinimumSize(
        std::max(sidebarMode ? 1 : 160, m_utilizationFloatingBaseSize.width() / 4),
        std::max(sidebarMode ? 1 : 100, m_utilizationFloatingBaseSize.height() / 4));
    QVBoxLayout* const floatingLayout = new QVBoxLayout(floatingWindow);
    // The borrowed chart page has its own size hints; they must not lock the
    // frameless top-level window to its initial dimensions.
    floatingLayout->setSizeConstraint(QLayout::SetNoConstraint);
    floatingLayout->setContentsMargins(4, 4, 4, 4);
    floatingLayout->setSpacing(0);

    m_utilizationOriginalMainWindow = mainWindow;
    m_utilizationFloatingWindow = floatingWindow;
    m_utilizationFloatingPage = sourceWidget;
    m_utilizationBorrowedPalette = sourceWidget->palette();
    m_utilizationBorrowedThemeColors = ks::ui::CaptureThemeColorSnapshot();
    m_utilizationBorrowedHadPalette = sourceWidget->testAttribute(Qt::WA_SetPalette);
    m_utilizationBorrowedFont = sourceWidget->font();
    m_utilizationBorrowedHadFont = sourceWidget->testAttribute(Qt::WA_SetFont);
    m_utilizationFloatingWidgetStyles.clear();
    m_utilizationFloatingLayoutStyles.clear();
    m_utilizationFloatingAppliedContentScale = 1.0;
    m_utilizationSavedSplitterSizes = m_utilizationBodySplitter->sizes();
    m_utilizationFloatingMode = sidebarMode
        ? UtilizationFloatingMode::Sidebar : UtilizationFloatingMode::Detail;

    if (sidebarMode)
    {
        sourceWidget->setParent(floatingWindow);
        floatingLayout->addWidget(sourceWidget);
        sourceWidget->show();
    }
    else
    {
        const UtilizationNavEntry& entry = m_utilizationNavEntries[static_cast<std::size_t>(
            m_utilizationSidebarList->currentRow())];
        m_utilizationSavedDetailIndex = m_utilizationDetailStack->indexOf(sourceWidget);
        m_utilizationHiddenDetailWidgets.clear();
        for (QWidget* const detailWidget : utilizationDetailWidgets(entry))
        {
            if (detailWidget != nullptr)
            {
                m_utilizationHiddenDetailWidgets.emplace_back(detailWidget, detailWidget->isVisible());
                detailWidget->hide();
            }
        }
        m_utilizationDetailStack->removeWidget(sourceWidget);
        sourceWidget->setParent(floatingWindow);
        floatingLayout->addWidget(sourceWidget);
        sourceWidget->show();
    }

    floatingWindow->resize(initialSize);
    applyUtilizationFloatingTheme();
    applyUtilizationFloatingContentScale();
    QPoint targetPosition = sourceGlobalPosition;
    if (targetScreen != nullptr)
    {
        const QRect workArea = targetScreen->availableGeometry();
        targetPosition.setX(std::clamp(targetPosition.x(), workArea.left(),
            std::max(workArea.left(), workArea.right() - initialSize.width() + 1)));
        targetPosition.setY(std::clamp(targetPosition.y(), workArea.top(),
            std::max(workArea.top(), workArea.bottom() - initialSize.height() + 1)));
    }
    floatingWindow->move(targetPosition);
    floatingWindow->show();
    floatingWindow->raise();
    floatingWindow->activateWindow();
    mainWindow->hide();
    scheduleUtilizationLayoutRefresh();
    if (!m_utilizationFollowTitle.isEmpty() && !m_utilizationFollowExecutable.isEmpty())
    {
        struct MatchContext
        {
            QString title;
            QString executable;
            HWND found = nullptr;
        } match{ m_utilizationFollowTitle, m_utilizationFollowExecutable };
        ::EnumWindows([](HWND candidate, LPARAM parameter) -> BOOL
        {
            auto* const context = reinterpret_cast<MatchContext*>(parameter);
            if (utilizationWindowTitle(candidate) != context->title
                || utilizationWindowExecutable(candidate).compare(
                    context->executable, Qt::CaseInsensitive) != 0)
            {
                return TRUE;
            }
            if (context->found == nullptr || ::IsWindowVisible(candidate) != FALSE)
            {
                context->found = candidate;
            }
            return ::IsWindowVisible(candidate) == FALSE;
        }, reinterpret_cast<LPARAM>(&match));
        if (match.found != nullptr && !utilizationWindowIsTopMost(match.found))
        {
            attachUtilizationWindow(match.found, true);
        }
        else if (match.found != nullptr)
        {
            QMessageBox::warning(floatingWindow,
                ks::i18n::contextText(QStringLiteral("hardware.utilization.floating.follow"),
                    QStringLiteral("窗口跟随")),
                ks::i18n::contextText(QStringLiteral("hardware.utilization.floating.topmost_error"),
                    QStringLiteral("置顶窗口不可跟随")));
        }
    }
}

void HardwareDock::beginUtilizationWindowPick()
{
    if (m_utilizationFloatingWindow == nullptr || m_utilizationFollowTarget != nullptr
        || m_utilizationPickDialog != nullptr)
    {
        return;
    }
    QDialog* const prompt = new QDialog(m_utilizationFloatingWindow.data(),
        Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
    prompt->setAttribute(Qt::WA_DeleteOnClose);
    QVBoxLayout* const layout = new QVBoxLayout(prompt);
    layout->addWidget(new QLabel(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.floating.pick_prompt"),
        QStringLiteral("请点击目标窗口")), prompt));
    QPushButton* const cancel = new QPushButton(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.floating.pick_cancel"),
        QStringLiteral("取消")), prompt);
    layout->addWidget(cancel);
    connect(cancel, &QPushButton::clicked, prompt, &QDialog::reject);
    connect(prompt, &QDialog::finished, this, [this]()
    {
        if (utilizationPickHook != nullptr)
        {
            ::UnhookWindowsHookEx(utilizationPickHook);
            utilizationPickHook = nullptr;
        }
        utilizationPickCallback = {};
        m_utilizationPickDialog = nullptr;
    });
    m_utilizationPickDialog = prompt;
    const QPointer<HardwareDock> guard(this);
    utilizationPickCallback = [guard](HWND picked)
    {
        if (guard != nullptr) guard->finishUtilizationWindowPick(picked);
    };
    utilizationPickHook = ::SetWindowsHookExW(WH_MOUSE_LL, utilizationMousePickProc,
        ::GetModuleHandleW(nullptr), 0);
    if (utilizationPickHook == nullptr)
    {
        utilizationPickCallback = {};
        prompt->deleteLater();
        m_utilizationPickDialog = nullptr;
        return;
    }
    prompt->show();
    prompt->move(m_utilizationFloatingWindow->geometry().center() - prompt->rect().center());
}

void HardwareDock::finishUtilizationWindowPick(void* pickedWindow)
{
    if (m_utilizationPickDialog == nullptr || m_utilizationFloatingWindow == nullptr)
    {
        return;
    }
    HWND target = static_cast<HWND>(pickedWindow);
    if (target == nullptr || ::IsWindow(target) == FALSE) return;
    target = ::GetAncestor(target, GA_ROOT);
    DWORD processId = 0;
    ::GetWindowThreadProcessId(target, &processId);
    if (processId == ::GetCurrentProcessId() || target == ::GetDesktopWindow()) return;
    const QString title = utilizationWindowTitle(target);
    const QString executable = utilizationWindowExecutable(target);
    if (title.isEmpty() || executable.isEmpty()) return;
    if (utilizationWindowIsTopMost(target))
    {
        QMessageBox::warning(m_utilizationPickDialog.data(),
            ks::i18n::contextText(QStringLiteral("hardware.utilization.floating.follow"),
                QStringLiteral("窗口跟随")),
            ks::i18n::contextText(QStringLiteral("hardware.utilization.floating.topmost_error"),
                QStringLiteral("置顶窗口不可跟随")));
        return;
    }
    m_utilizationPickDialog->accept();
    attachUtilizationWindow(target, false);
}

void HardwareDock::attachUtilizationWindow(void* targetWindow, const bool restoreSavedOffset)
{
    HWND target = static_cast<HWND>(targetWindow);
    QWidget* const floatingWindow = m_utilizationFloatingWindow.data();
    QWidget* const source = m_utilizationFloatingPage.data();
    QWidget* const mainWindow = m_utilizationOriginalMainWindow.data();
    if (target == nullptr || ::IsWindow(target) == FALSE || utilizationWindowIsTopMost(target)
        || floatingWindow == nullptr || source == nullptr || mainWindow == nullptr
        || m_utilizationFollowTarget != nullptr)
    {
        return;
    }
    RECT targetRect{}, floatRect{};
    if (!utilizationPhysicalWindowRect(target, &targetRect)
        || !utilizationPhysicalWindowRect(reinterpret_cast<HWND>(floatingWindow->winId()), &floatRect))
    {
        return;
    }
    if (!restoreSavedOffset)
    {
        const double logicalRatio = 96.0 / utilizationMonitorDpi(target);
        m_utilizationFollowOffset = QPoint(
            qRound((floatRect.left - targetRect.left) * logicalRatio),
            qRound((floatRect.top - targetRect.top) * logicalRatio));
        m_utilizationFollowOffsetLogical = true;
    }
    else if (!m_utilizationFollowOffsetLogical)
    {
        // Older settings stored physical pixels. Convert once using the current
        // target monitor so future moves retain the same logical distance.
        const double logicalRatio = 96.0 / utilizationMonitorDpi(target);
        m_utilizationFollowOffset = QPoint(
            qRound(m_utilizationFollowOffset.x() * logicalRatio),
            qRound(m_utilizationFollowOffset.y() * logicalRatio));
        m_utilizationFollowOffsetLogical = true;
    }
    m_utilizationFollowTitle = utilizationWindowTitle(target);
    m_utilizationFollowExecutable = utilizationWindowExecutable(target);
    m_utilizationFollowTarget = target;
    const auto originalWidgetStyle = [this](const QWidget* widget)
        -> UtilizationFollowMirror::WidgetStyle
    {
        for (const FloatingWidgetStyleState& state : m_utilizationFloatingWidgetStyles)
            if (state.widget == widget)
                return { state.styleSheet, state.minimumHeight, state.maximumHeight };
        return { widget->styleSheet(), widget->minimumHeight(), widget->maximumHeight() };
    };
    const auto originalLayoutStyle = [this](const QLayout* layout)
        -> UtilizationFollowMirror::LayoutStyle
    {
        for (const FloatingLayoutStyleState& state : m_utilizationFloatingLayoutStyles)
            if (state.layout == layout)
                return { state.margins, state.spacing,
                    state.horizontalSpacing, state.verticalSpacing };
        return { layout->contentsMargins(), layout->spacing(),
            layout->spacing(), layout->spacing() };
    };
    QWidget* const mirror = new UtilizationFollowMirror(source,
        m_utilizationFloatingMode == UtilizationFloatingMode::Sidebar
            ? static_cast<QWidget*>(m_utilizationBodySplitter)
            : static_cast<QWidget*>(m_utilizationDetailStack),
        originalWidgetStyle, originalLayoutStyle);
    mirror->setFont(m_utilizationBorrowedFont);
    m_utilizationFollowMirror = mirror;
    if (m_utilizationFloatingMode == UtilizationFloatingMode::Sidebar)
    {
        m_utilizationBodySplitter->insertWidget(0, mirror);
        if (m_utilizationSavedSplitterSizes.size() == 2)
        {
            m_utilizationBodySplitter->setSizes(m_utilizationSavedSplitterSizes);
        }
    }
    else
    {
        m_utilizationDetailStack->insertWidget(std::max(0, m_utilizationSavedDetailIndex), mirror);
        m_utilizationDetailStack->setCurrentWidget(mirror);
    }
    mainWindow->show();
    const HWND floatHandle = reinterpret_cast<HWND>(floatingWindow->winId());
    ::SetWindowPos(floatHandle, HWND_NOTOPMOST, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    utilizationFollowHookTarget = target;
    utilizationFollowFloatHandle = floatHandle;
    const QPointer<HardwareDock> guard(this);
    utilizationFollowCallback = [guard, target](DWORD event)
    {
        if (guard == nullptr || guard->m_utilizationFollowTarget != target) return;
        if (event == EVENT_OBJECT_DESTROY) guard->stopUtilizationFollow(true, false);
        else guard->synchronizeUtilizationFollow();
    };
    DWORD processId = 0;
    ::GetWindowThreadProcessId(target, &processId);
    m_utilizationFollowEventHook = ::SetWinEventHook(EVENT_OBJECT_DESTROY,
        EVENT_OBJECT_LOCATIONCHANGE, nullptr, utilizationFollowEventProc,
        processId, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    m_utilizationFollowForegroundHook = ::SetWinEventHook(EVENT_SYSTEM_FOREGROUND,
        EVENT_SYSTEM_FOREGROUND, nullptr, utilizationForegroundEventProc,
        0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    setUtilizationFollowClickThrough(m_utilizationFollowClickThrough);
    m_utilizationFollowTimer->start();
    synchronizeUtilizationFollow();
    m_utilizationPreferencesSaveTimer->start();
}

void HardwareDock::clearUtilizationFollowHooks()
{
    if (utilizationPickHook != nullptr)
    {
        ::UnhookWindowsHookEx(utilizationPickHook);
        utilizationPickHook = nullptr;
    }
    utilizationPickCallback = {};
    if (m_utilizationFollowEventHook != nullptr)
    {
        ::UnhookWinEvent(static_cast<HWINEVENTHOOK>(m_utilizationFollowEventHook));
        m_utilizationFollowEventHook = nullptr;
    }
    if (m_utilizationFollowForegroundHook != nullptr)
    {
        ::UnhookWinEvent(static_cast<HWINEVENTHOOK>(m_utilizationFollowForegroundHook));
        m_utilizationFollowForegroundHook = nullptr;
    }
    utilizationFollowHookTarget = nullptr;
    utilizationFollowFloatHandle = nullptr;
    utilizationFollowCallback = {};
    if (m_utilizationFollowTimer != nullptr) m_utilizationFollowTimer->stop();
}

void HardwareDock::setUtilizationFollowClickThrough(const bool enabled)
{
    if (m_utilizationFollowTarget == nullptr || m_utilizationFloatingWindow == nullptr) return;
    m_utilizationFollowClickThrough = enabled;
    const HWND handle = reinterpret_cast<HWND>(m_utilizationFloatingWindow->winId());
    LONG_PTR style = ::GetWindowLongPtrW(handle, GWL_EXSTYLE);
    if (enabled) style |= WS_EX_TRANSPARENT | WS_EX_LAYERED;
    else style &= ~static_cast<LONG_PTR>(WS_EX_TRANSPARENT);
    ::SetWindowLongPtrW(handle, GWL_EXSTYLE, style);
    ::SetWindowPos(handle, nullptr, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    m_utilizationPreferencesSaveTimer->start();
}

void HardwareDock::synchronizeUtilizationFollow()
{
    HWND target = static_cast<HWND>(m_utilizationFollowTarget);
    QWidget* const floatingWindow = m_utilizationFloatingWindow.data();
    if (target == nullptr || floatingWindow == nullptr) return;
    if (::IsWindow(target) == FALSE)
    {
        stopUtilizationFollow(true, false);
        return;
    }
    if (utilizationWindowIsTopMost(target))
    {
        stopUtilizationFollow(true, false);
        QMessageBox::warning(m_utilizationFloatingWindow.data(),
            ks::i18n::contextText(QStringLiteral("hardware.utilization.floating.follow"),
                QStringLiteral("窗口跟随")),
            ks::i18n::contextText(QStringLiteral("hardware.utilization.floating.topmost_error"),
                QStringLiteral("置顶窗口不可跟随")));
        return;
    }
    if (::IsWindowVisible(target) == FALSE || ::IsIconic(target) != FALSE)
    {
        floatingWindow->hide();
        if (m_utilizationFollowMirror != nullptr)
            static_cast<UtilizationFollowMirror*>(m_utilizationFollowMirror.data())->synchronize();
        return;
    }
    if (m_utilizationDragArmed || m_utilizationDragging)
    {
        if (m_utilizationFollowMirror != nullptr)
            static_cast<UtilizationFollowMirror*>(m_utilizationFollowMirror.data())->synchronize();
        return;
    }
    RECT targetRect{};
    if (!utilizationPhysicalWindowRect(target, &targetRect)) return;
    m_utilizationFollowSyncing = true;
    if (!floatingWindow->isVisible()) floatingWindow->show();
    const HWND floatHandle = reinterpret_cast<HWND>(floatingWindow->winId());
    if (utilizationWindowIsTopMost(floatHandle))
    {
        ::SetWindowPos(floatHandle, HWND_NOTOPMOST, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
    HWND preceding = ::GetWindow(target, GW_HWNDPREV);
    const bool alreadyAboveTarget = preceding == floatHandle;
    const int desiredX = targetRect.left
        + qRound(m_utilizationFollowOffset.x() * utilizationMonitorDpi(target) / 96.0);
    const int desiredY = targetRect.top
        + qRound(m_utilizationFollowOffset.y() * utilizationMonitorDpi(target) / 96.0);
    RECT floatRect{};
    const bool alreadyPositioned = utilizationPhysicalWindowRect(floatHandle, &floatRect)
        && floatRect.left == desiredX && floatRect.top == desiredY;
    if (!alreadyPositioned || !alreadyAboveTarget)
    {
        ::SetWindowPos(floatHandle, alreadyAboveTarget ? nullptr
            : preceding != nullptr ? preceding : HWND_TOP,
            desiredX, desiredY, 0, 0,
            SWP_NOSIZE | SWP_NOACTIVATE | (alreadyAboveTarget ? SWP_NOZORDER : 0)
                | (alreadyPositioned ? SWP_NOMOVE : 0));
    }
    m_utilizationFollowSyncing = false;
    if (m_utilizationFollowMirror != nullptr)
        static_cast<UtilizationFollowMirror*>(m_utilizationFollowMirror.data())->synchronize();
}

void HardwareDock::captureUtilizationFollowOffset()
{
    HWND target = static_cast<HWND>(m_utilizationFollowTarget);
    QWidget* const floatingWindow = m_utilizationFloatingWindow.data();
    if (target == nullptr || floatingWindow == nullptr || m_utilizationFollowSyncing) return;
    RECT targetRect{}, floatRect{};
    if (!utilizationPhysicalWindowRect(target, &targetRect)
        || !utilizationPhysicalWindowRect(reinterpret_cast<HWND>(floatingWindow->winId()), &floatRect))
        return;
    const double logicalRatio = 96.0 / utilizationMonitorDpi(target);
    m_utilizationFollowOffset = QPoint(
        qRound((floatRect.left - targetRect.left) * logicalRatio),
        qRound((floatRect.top - targetRect.top) * logicalRatio));
    m_utilizationFollowOffsetLogical = true;
    m_utilizationPreferencesSaveTimer->start();
}

void HardwareDock::stopUtilizationFollow(const bool showNormalCard, const bool clearSavedTarget)
{
    if (m_utilizationFollowTarget == nullptr) return;
    const bool savedClickThrough = m_utilizationFollowClickThrough;
    clearUtilizationFollowHooks();
    setUtilizationFollowClickThrough(false);
    m_utilizationFollowTarget = nullptr;
    if (!clearSavedTarget) m_utilizationFollowClickThrough = savedClickThrough;
    QWidget* const mirror = m_utilizationFollowMirror.data();
    m_utilizationFollowMirror = nullptr;
    if (mirror != nullptr)
    {
        if (m_utilizationFloatingMode == UtilizationFloatingMode::Sidebar)
        {
            mirror->setParent(nullptr);
        }
        else
        {
            m_utilizationDetailStack->removeWidget(mirror);
        }
        delete mirror;
    }
    if (clearSavedTarget)
    {
        m_utilizationFollowTitle.clear();
        m_utilizationFollowExecutable.clear();
        m_utilizationFollowOffset = {};
        m_utilizationFollowOffsetLogical = true;
        m_utilizationFollowClickThrough = false;
    }
    m_utilizationPreferencesSaveTimer->start();
    if (showNormalCard)
    {
        if (QWidget* const mainWindow = m_utilizationOriginalMainWindow.data()) mainWindow->hide();
        if (QWidget* const floatingWindow = m_utilizationFloatingWindow.data())
        {
            floatingWindow->show();
            ::SetWindowPos(reinterpret_cast<HWND>(floatingWindow->winId()),
                m_utilizationFloatingTopMost ? HWND_TOPMOST : HWND_NOTOPMOST,
                0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            floatingWindow->raise();
            floatingWindow->activateWindow();
        }
    }
    else
    {
        restoreUtilizationFloatingWindow();
    }
}

void HardwareDock::restoreUtilizationFloatingWindow()
{
    if (m_utilizationFloatingMode == UtilizationFloatingMode::None)
    {
        return;
    }
    clearUtilizationFollowHooks();
    delete m_utilizationPickDialog.data();
    m_utilizationPickDialog = nullptr;

    QWidget* const floatingWindow = m_utilizationFloatingWindow.data();
    QWidget* const borrowedWidget = m_utilizationFloatingPage.data();
    QWidget* const mainWindow = m_utilizationOriginalMainWindow.data();
    restoreUtilizationFloatingContentScale();
    if (m_utilizationPreferencesSaveTimer != nullptr && m_utilizationPreferencesSaveTimer->isActive())
    {
        saveUtilizationFloatingPreferences();
    }
    const UtilizationFloatingMode mode = m_utilizationFloatingMode;
    m_utilizationFloatingMode = UtilizationFloatingMode::None;
    m_utilizationDragArmed = false;
    m_utilizationDragging = false;
    m_utilizationResizeEdges = {};

    if (floatingWindow != nullptr && borrowedWidget != nullptr && floatingWindow->layout() != nullptr)
    {
        floatingWindow->layout()->removeWidget(borrowedWidget);
    }
    if (mode == UtilizationFloatingMode::Sidebar && borrowedWidget != nullptr
        && m_utilizationBodySplitter != nullptr)
    {
        m_utilizationBodySplitter->insertWidget(0, borrowedWidget);
        borrowedWidget->show();
        if (m_utilizationSavedSplitterSizes.size() == 2)
        {
            m_utilizationBodySplitter->setSizes(m_utilizationSavedSplitterSizes);
        }
    }
    else if (mode == UtilizationFloatingMode::Detail && borrowedWidget != nullptr
        && m_utilizationDetailStack != nullptr)
    {
        m_utilizationDetailStack->insertWidget(
            std::max(0, m_utilizationSavedDetailIndex), borrowedWidget);
        for (const auto& [detailWidget, wasVisible] : m_utilizationHiddenDetailWidgets)
        {
            if (detailWidget != nullptr)
            {
                detailWidget->setVisible(wasVisible);
            }
        }
        m_utilizationDetailStack->setCurrentWidget(borrowedWidget);
        borrowedWidget->show();
    }

    if (borrowedWidget != nullptr)
    {
        if (m_utilizationBorrowedHadPalette)
        {
            borrowedWidget->setPalette(ks::ui::RemapStaleThemeColorsInPalette(
                m_utilizationBorrowedThemeColors, m_utilizationBorrowedPalette));
        }
        else
        {
            borrowedWidget->setPalette(QPalette());
            borrowedWidget->setAttribute(Qt::WA_SetPalette, false);
        }
        if (mode == UtilizationFloatingMode::Detail)
        {
            const QColor titleColor = KswordTheme::TextPrimaryColor();
            const QColor legendColor = KswordTheme::TextSecondaryColor();
            for (QWidget* const child : borrowedWidget->findChildren<QWidget*>())
            {
                if (auto* const view = dynamic_cast<QChartView*>(child))
                {
                    if (QChart* const chart = view->chart())
                    {
                        chart->setTitleBrush(QBrush(titleColor));
                        chart->legend()->setLabelColor(legendColor);
                    }
                }
            }
        }
    }

    m_utilizationHiddenDetailWidgets.clear();
    m_utilizationFloatingPage = nullptr;
    m_utilizationFloatingWindow = nullptr;
    m_utilizationOriginalMainWindow = nullptr;
    m_utilizationSavedDetailIndex = -1;
    m_utilizationBorrowedHadPalette = false;
    m_utilizationSavedSplitterSizes.clear();
    delete floatingWindow;
    // 图表的画笔不继承 QWidget palette；返回主界面时显式恢复当前主主题角色。
    refreshUtilizationChartThemeColors();

    if (mainWindow != nullptr)
    {
        mainWindow->show();
        mainWindow->raise();
        mainWindow->activateWindow();
    }
    scheduleUtilizationLayoutRefresh();
}

void HardwareDock::resizeUtilizationFloatingWindow()
{
    QWidget* const floatingWindow = m_utilizationFloatingWindow.data();
    if (floatingWindow == nullptr || m_utilizationFloatingBaseSize.isEmpty())
    {
        return;
    }
    QScreen* screen = floatingWindow->screen();
    if (screen == nullptr)
    {
        screen = QGuiApplication::primaryScreen();
    }
    const QSize desiredSize(
        std::max(1, m_utilizationFloatingBaseSize.width() * m_utilizationFloatingScalePercent / 100),
        std::max(1, m_utilizationFloatingBaseSize.height() * m_utilizationFloatingScalePercent / 100));
    const QRect workArea = screen != nullptr ? screen->availableGeometry() : QRect(floatingWindow->geometry());
    const QSize boundedSize = desiredSize.boundedTo(workArea.size()).expandedTo(floatingWindow->minimumSize());
    QRect geometry(QPoint(0, 0), boundedSize);
    geometry.moveCenter(floatingWindow->geometry().center());
    geometry.moveLeft(std::clamp(geometry.left(), workArea.left(),
        std::max(workArea.left(), workArea.right() - geometry.width() + 1)));
    geometry.moveTop(std::clamp(geometry.top(), workArea.top(),
        std::max(workArea.top(), workArea.bottom() - geometry.height() + 1)));
    floatingWindow->setGeometry(geometry);
    applyUtilizationFloatingContentScale();
}

void HardwareDock::captureUtilizationFloatingScale()
{
    QWidget* const floatingWindow = m_utilizationFloatingWindow.data();
    if (floatingWindow == nullptr || m_utilizationFloatingBaseSize.isEmpty()) return;
    const double widthRatio = static_cast<double>(floatingWindow->width())
        / m_utilizationFloatingBaseSize.width();
    const double heightRatio = static_cast<double>(floatingWindow->height())
        / m_utilizationFloatingBaseSize.height();
    m_utilizationFloatingScalePercent = std::clamp(
        qRound(std::min(widthRatio, heightRatio) * 100.0), 25, 300);
    applyUtilizationFloatingContentScale();
    m_utilizationPreferencesSaveTimer->start();
}

void HardwareDock::applyUtilizationFloatingContentScale(const bool forceRestyle)
{
    QWidget* const floatingWindow = m_utilizationFloatingWindow.data();
    QWidget* const page = m_utilizationFloatingPage.data();
    if (floatingWindow == nullptr || page == nullptr || m_utilizationFloatingBaseSize.isEmpty())
    {
        return;
    }

    const double widthRatio = static_cast<double>(floatingWindow->width())
        / m_utilizationFloatingBaseSize.width();
    const double heightRatio = static_cast<double>(floatingWindow->height())
        / m_utilizationFloatingBaseSize.height();
    const double scale = std::clamp(std::min(widthRatio, heightRatio), 0.25, 3.0);
    QList<QWidget*> widgets = page->findChildren<QWidget*>();
    widgets.prepend(page);
    const bool allWidgetsCaptured = std::all_of(widgets.begin(), widgets.end(),
        [this](QWidget* const widget)
        {
            return std::any_of(m_utilizationFloatingWidgetStyles.begin(),
                m_utilizationFloatingWidgetStyles.end(), [widget](const FloatingWidgetStyleState& state)
                {
                    return state.widget == widget;
                });
        });
    if (!forceRestyle && std::abs(scale - m_utilizationFloatingAppliedContentScale) < 0.005
        && allWidgetsCaptured)
    {
        return;
    }
    m_utilizationFloatingAppliedContentScale = scale;

    static const QRegularExpression fontSizePattern(
        QStringLiteral(R"((font-size\s*:\s*)(\d+(?:\.\d+)?)(px|pt))"),
        QRegularExpression::CaseInsensitiveOption);
    auto scaledStyle = [scale](const QString& originalStyle)
    {
        QString result;
        int cursor = 0;
        auto matches = fontSizePattern.globalMatch(originalStyle);
        while (matches.hasNext())
        {
            const auto match = matches.next();
            result += originalStyle.mid(cursor, match.capturedStart(2) - cursor);
            result += QString::number(std::max(1, qRound(match.captured(2).toDouble() * scale)));
            cursor = match.capturedEnd(2);
        }
        result += originalStyle.mid(cursor);
        return result;
    };
    const auto scaledPx = [scale](const int pixels)
    {
        return pixels < 0 ? pixels : qRound(pixels * scale);
    };

    for (QWidget* const widget : widgets)
    {
        // 悬浮条自绘尺寸不依赖 QSS 字号，必须显式跟随利用率浮窗内容倍率。
        if (auto* scrollArea = qobject_cast<QAbstractScrollArea*>(widget))
        {
            ks::ui::SetFloatingScrollbarScale(scrollArea, scale);
        }
        auto existing = std::find_if(m_utilizationFloatingWidgetStyles.begin(),
            m_utilizationFloatingWidgetStyles.end(), [widget](const FloatingWidgetStyleState& state)
            {
                return state.widget == widget;
            });
        if (existing == m_utilizationFloatingWidgetStyles.end())
        {
            m_utilizationFloatingWidgetStyles.push_back({ widget, widget->styleSheet(),
                widget->palette(), widget->testAttribute(Qt::WA_SetPalette),
                widget->minimumHeight(), widget->maximumHeight(), ks::ui::CaptureThemeColorSnapshot() });
            existing = std::prev(m_utilizationFloatingWidgetStyles.end());
        }
        QPalette childPalette = existing->palette;
        const QPalette floatingPalette = floatingWindow->palette();
        for (const QPalette::ColorRole role : {
            QPalette::Window, QPalette::WindowText, QPalette::Base,
            QPalette::AlternateBase, QPalette::Mid, QPalette::Midlight,
            QPalette::Dark, QPalette::Text, QPalette::PlaceholderText,
            QPalette::Button, QPalette::ButtonText, QPalette::ToolTipBase,
            QPalette::ToolTipText })
        {
            childPalette.setColor(role, floatingPalette.color(role));
        }
        widget->setPalette(childPalette);
        QString style = scaledStyle(existing->styleSheet);
        style.replace(QStringLiteral("palette(placeholder-text)"),
            floatingPalette.color(QPalette::PlaceholderText).name(QColor::HexRgb), Qt::CaseInsensitive);
        style.replace(QStringLiteral("palette(window-text)"),
            floatingPalette.color(QPalette::WindowText).name(QColor::HexRgb), Qt::CaseInsensitive);
        style.replace(QStringLiteral("palette(text)"),
            floatingPalette.color(QPalette::Text).name(QColor::HexRgb), Qt::CaseInsensitive);
        if (widget->styleSheet() != style)
        {
            widget->setStyleSheet(style);
        }
        if ((qobject_cast<QLabel*>(widget) != nullptr
                || widget->property("ksword_virtual_network_tile").toBool()
                || (m_virtualNetworkPage != nullptr
                    && m_virtualNetworkPage->isAncestorOf(widget)
                    && dynamic_cast<QChartView*>(widget) != nullptr))
            && existing->minimumHeight == existing->maximumHeight
            && existing->maximumHeight > 0 && existing->maximumHeight < 1000)
        {
            const int height = std::max(1, scaledPx(existing->maximumHeight));
            widget->setFixedHeight(height);
        }
        if (auto* const card = dynamic_cast<PerformanceNavCard*>(widget))
        {
            card->setFloatingScaleFactor(scale);
            card->setFloatingThemeSurface(floatingPalette.color(QPalette::Window));
        }
        if (auto* const memoryChart = dynamic_cast<MemoryCompositionHistoryWidget*>(widget))
        {
            memoryChart->setFloatingScaleFactor(scale);
        }
    }

    QFont scaledFont = m_utilizationBorrowedFont;
    if (scaledFont.pointSizeF() > 0)
    {
        scaledFont.setPointSizeF(std::max(1.0, scaledFont.pointSizeF() * scale));
    }
    else if (scaledFont.pixelSize() > 0)
    {
        scaledFont.setPixelSize(std::max(1, scaledPx(scaledFont.pixelSize())));
    }
    page->setFont(scaledFont);

    for (QObject* const object : page->findChildren<QObject*>())
    {
        auto* const layout = dynamic_cast<QLayout*>(object);
        if (layout == nullptr)
        {
            continue;
        }
        auto existing = std::find_if(m_utilizationFloatingLayoutStyles.begin(),
            m_utilizationFloatingLayoutStyles.end(), [layout](const FloatingLayoutStyleState& state)
            {
                return state.layout == layout;
            });
        if (existing == m_utilizationFloatingLayoutStyles.end())
        {
            int horizontal = layout->spacing();
            int vertical = layout->spacing();
            if (auto* const grid = dynamic_cast<QGridLayout*>(layout))
            {
                horizontal = grid->horizontalSpacing();
                vertical = grid->verticalSpacing();
            }
            m_utilizationFloatingLayoutStyles.push_back({ layout, layout->contentsMargins(),
                layout->spacing(), horizontal, vertical });
            existing = std::prev(m_utilizationFloatingLayoutStyles.end());
        }
        const QMargins& margins = existing->margins;
        layout->setContentsMargins(scaledPx(margins.left()), scaledPx(margins.top()),
            scaledPx(margins.right()), scaledPx(margins.bottom()));
        if (existing->spacing >= 0)
        {
            layout->setSpacing(scaledPx(existing->spacing));
        }
        if (auto* const grid = dynamic_cast<QGridLayout*>(layout))
        {
            grid->setHorizontalSpacing(scaledPx(existing->horizontalSpacing));
            grid->setVerticalSpacing(scaledPx(existing->verticalSpacing));
        }
    }

    if (QLayout* const layout = floatingWindow->layout())
    {
        const int margin = std::max(0, scaledPx(4));
        layout->setContentsMargins(margin, margin, margin, margin);
    }
    if (m_utilizationFloatingMode == UtilizationFloatingMode::Sidebar
        && m_utilizationSidebarList != nullptr)
    {
        m_utilizationSidebarList->setMinimumWidth(std::max(1, scaledPx(140)));
        syncUtilizationSidebarCardWidths();
    }
    else
    {
        if (page == m_virtualNetworkPage)
        {
            relayoutVirtualNetworkTiles();
        }
        adjustUtilizationChartHeights();
    }
}

void HardwareDock::restoreUtilizationFloatingContentScale()
{
    QWidget* const page = m_utilizationFloatingPage.data();
    if (page == nullptr)
    {
        return;
    }
    for (const FloatingWidgetStyleState& state : m_utilizationFloatingWidgetStyles)
    {
        if (QWidget* const widget = state.widget.data())
        {
            // 借出时修改了根页及所有后代滚动区；归还逐项恢复主界面的默认 1 倍。
            // 当前工程只有浮窗缩放会改此倍率，控制器默认值也是 1.0，不改业务滚动几何。
            if (auto* scrollArea = qobject_cast<QAbstractScrollArea*>(widget))
            {
                ks::ui::SetFloatingScrollbarScale(scrollArea, 1.0);
            }
            const QString restoredStyle = ks::ui::RemapStaleThemeColorsInText(
                state.themeColors, state.styleSheet);
            if (widget->styleSheet() != restoredStyle)
            {
                widget->setStyleSheet(restoredStyle);
            }
            if (state.hadPalette)
            {
                widget->setPalette(ks::ui::RemapStaleThemeColorsInPalette(state.themeColors, state.palette));
            }
            else
            {
                // 空 palette 真正清除 resolve mask；仅改 WA_SetPalette 仍可能保留旧继承颜色。
                widget->setPalette(QPalette());
                widget->setAttribute(Qt::WA_SetPalette, false);
            }
            if ((qobject_cast<QLabel*>(widget) != nullptr
                    || widget->property("ksword_virtual_network_tile").toBool()
                    || (m_virtualNetworkPage != nullptr
                        && m_virtualNetworkPage->isAncestorOf(widget)
                        && dynamic_cast<QChartView*>(widget) != nullptr))
                && state.minimumHeight == state.maximumHeight
                && state.maximumHeight > 0 && state.maximumHeight < 1000)
            {
                widget->setMinimumHeight(state.minimumHeight);
                widget->setMaximumHeight(state.maximumHeight);
            }
            if (auto* const card = dynamic_cast<PerformanceNavCard*>(widget))
            {
                card->setFloatingScaleFactor(1.0);
                card->setFloatingThemeSurface(QColor());
            }
            if (auto* const memoryChart = dynamic_cast<MemoryCompositionHistoryWidget*>(widget))
            {
                memoryChart->setFloatingScaleFactor(1.0);
            }
        }
    }
    for (const FloatingLayoutStyleState& state : m_utilizationFloatingLayoutStyles)
    {
        if (QLayout* const layout = state.layout.data())
        {
            layout->setContentsMargins(state.margins);
            layout->setSpacing(state.spacing);
            if (auto* const grid = dynamic_cast<QGridLayout*>(layout))
            {
                grid->setHorizontalSpacing(state.horizontalSpacing);
                grid->setVerticalSpacing(state.verticalSpacing);
            }
        }
    }
    page->setFont(m_utilizationBorrowedFont);
    if (!m_utilizationBorrowedHadFont)
    {
        page->setAttribute(Qt::WA_SetFont, false);
    }
    if (m_utilizationFloatingMode == UtilizationFloatingMode::Sidebar
        && m_utilizationSidebarList != nullptr)
    {
        m_utilizationSidebarList->setMinimumWidth(140);
    }
    m_utilizationFloatingWidgetStyles.clear();
    m_utilizationFloatingLayoutStyles.clear();
    m_utilizationFloatingAppliedContentScale = 1.0;
}

void HardwareDock::applyUtilizationFloatingTheme()
{
    auto* const floatingWindow = static_cast<UtilizationFloatingWindow*>(m_utilizationFloatingWindow.data());
    if (floatingWindow == nullptr)
    {
        return;
    }
    const bool darkMode = m_utilizationFloatingThemeMode == QStringLiteral("dark")
        || (m_utilizationFloatingThemeMode == QStringLiteral("follow_main")
            && KswordTheme::IsDarkModeEnabled());
    const bool followMain = m_utilizationFloatingThemeMode == QStringLiteral("follow_main");
    const QColor backgroundColor = followMain ? KswordTheme::SurfaceColor()
        : KswordTheme::DefaultSurfaceColor(darkMode);
    const QColor textColor = followMain ? KswordTheme::TextPrimaryColor()
        : KswordTheme::DefaultTextPrimaryColor(darkMode);
    const QColor secondaryTextColor = followMain ? KswordTheme::TextSecondaryColor()
        : KswordTheme::DefaultTextSecondaryColor(darkMode);
    QPalette floatingPalette = floatingWindow->palette();
    const bool textPaletteChanged = floatingPalette.color(QPalette::Window) != backgroundColor
        || floatingPalette.color(QPalette::Text) != textColor
        || floatingPalette.color(QPalette::PlaceholderText) != secondaryTextColor;
    floatingPalette.setColor(QPalette::Window, backgroundColor);
    floatingPalette.setColor(QPalette::Base, backgroundColor);
    floatingPalette.setColor(QPalette::AlternateBase, followMain ? KswordTheme::SurfaceAltColor()
        : KswordTheme::DefaultSurfaceAltColor(darkMode));
    floatingPalette.setColor(QPalette::WindowText, textColor);
    floatingPalette.setColor(QPalette::Text, textColor);
    floatingPalette.setColor(QPalette::ButtonText, textColor);
    floatingPalette.setColor(QPalette::PlaceholderText, secondaryTextColor);
    floatingPalette.setColor(QPalette::Mid, followMain ? KswordTheme::BorderColor()
        : KswordTheme::DefaultBorderColor(darkMode));
    floatingPalette.setColor(QPalette::Midlight, followMain ? KswordTheme::BorderStrongColor()
        : KswordTheme::DefaultBorderStrongColor(darkMode));
    floatingPalette.setColor(QPalette::Dark, followMain ? KswordTheme::PaletteDarkColor()
        : KswordTheme::DefaultPaletteDarkColor(darkMode));
    floatingPalette.setColor(QPalette::Button, floatingPalette.color(QPalette::AlternateBase));
    floatingPalette.setColor(QPalette::ToolTipBase, backgroundColor);
    floatingPalette.setColor(QPalette::ToolTipText, textColor);
    floatingWindow->setPalette(floatingPalette);
    floatingWindow->setBackground(backgroundColor, m_utilizationFloatingBackgroundOpacityPercent);
    if (textPaletteChanged || m_utilizationFloatingWidgetStyles.empty())
    {
        applyUtilizationFloatingContentScale(true);
    }
    QWidget* const borrowedWidget = m_utilizationFloatingPage.data();
    if (borrowedWidget != nullptr)
    {
        borrowedWidget->setPalette(floatingPalette);
        borrowedWidget->update();
        // 轴、曲线、网格和 plot 填充也需要本地表面校准，不能只换标题与图例。
        refreshUtilizationChartThemeColors(followMain ? nullptr : &floatingPalette);
    }
}

void HardwareDock::saveUtilizationFloatingPreferences()
{
    if (m_utilizationPreferencesSaveTimer != nullptr)
    {
        m_utilizationPreferencesSaveTimer->stop();
    }
    auto preferences = ks::settings::loadAppearanceSettings();
    preferences.utilizationFloatingScalePercent = m_utilizationFloatingScalePercent;
    preferences.utilizationFloatingBackgroundOpacityPercent = m_utilizationFloatingBackgroundOpacityPercent;
    preferences.utilizationFloatingTopMost = m_utilizationFloatingTopMost;
    preferences.utilizationFloatingThemeMode = m_utilizationFloatingThemeMode;
    preferences.utilizationFloatingFollowTitle = m_utilizationFollowTitle;
    preferences.utilizationFloatingFollowExecutable = m_utilizationFollowExecutable;
    preferences.utilizationFloatingFollowOffsetX = m_utilizationFollowOffset.x();
    preferences.utilizationFloatingFollowOffsetY = m_utilizationFollowOffset.y();
    preferences.utilizationFloatingFollowOffsetLogical = m_utilizationFollowOffsetLogical;
    preferences.utilizationFloatingFollowClickThrough = m_utilizationFollowClickThrough;
    ks::settings::saveAppearanceSettings(preferences);
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
        && m_utilizationFloatingMode != UtilizationFloatingMode::Sidebar
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
    const double sidebarScale = m_utilizationFloatingMode == UtilizationFloatingMode::Sidebar
        ? m_utilizationFloatingAppliedContentScale : 1.0;
    const QSize nextSizeHint(0, std::max(1, qRound(52 * sidebarScale)));
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
    const auto scaledDetailPx = [this](const int pixels)
    {
        return m_utilizationFloatingMode == UtilizationFloatingMode::Detail
            ? std::max(1, qRound(pixels * m_utilizationFloatingAppliedContentScale)) : pixels;
    };
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
        const int cardSpacing = m_utilizationFloatingMode == UtilizationFloatingMode::Sidebar
            ? std::max(0, qRound(2 * m_utilizationFloatingAppliedContentScale)) : 2;
        if (m_utilizationSidebarList->spacing() != cardSpacing)
        {
            m_utilizationSidebarList->setSpacing(cardSpacing);
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
        if (m_utilizationFloatingMode == UtilizationFloatingMode::Detail
            && m_utilizationFloatingPage == m_utilizationCpuSubPage)
        {
            cpuReferenceHeight = m_utilizationCpuSubPage->contentsRect().height();
        }
        else if (m_utilizationDetailStack != nullptr)
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

        const int titleHeight = scaledDetailPx(72);
        const int headerHeight = std::max(
            m_cpuModelLabel != nullptr ? m_cpuModelLabel->height() : 0,
            titleHeight);
        const int summaryHeight = m_utilizationSummaryLabel != nullptr
            ? m_utilizationSummaryLabel->sizeHint().height()
            : 16;
        const int detailHeight = m_utilizationFloatingMode == UtilizationFloatingMode::Detail
            && m_utilizationFloatingPage == m_utilizationCpuSubPage ? 0 : std::max({
            m_cpuUtilPrimaryDetailLabel != nullptr ? m_cpuUtilPrimaryDetailLabel->sizeHint().height() : 0,
            m_cpuUtilSecondaryDetailLabel != nullptr ? m_cpuUtilSecondaryDetailLabel->sizeHint().height() : 0,
            m_cpuUtilTertiaryDetailLabel != nullptr ? m_cpuUtilTertiaryDetailLabel->sizeHint().height() : 0
        });
        // availableChartAreaHeight 用途：核心图可用高度；允许极小高度，保证页面整体不冒滚动条。
        const int availableChartAreaHeight = std::max(
            1,
            cpuReferenceHeight - headerHeight - summaryHeight - detailHeight - scaledDetailPx(42));
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
                    ? std::min(scaledDetailPx(18), std::max(0, chartEntry.titleLabel->sizeHint().height()))
                    : 0;
                const int chartHeight = std::max(1, cellHeight - titleReserveHeight
                    - scaledDetailPx(kCpuCoreChartChromeReservePx));
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
            const int reserveHeightValue,
            const bool floatingDetail)
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
            if (floatingDetail)
            {
                const int chartTop = chartView->mapTo(pageWidget, QPoint(0, 0)).y();
                const int bottomMargin = pageWidget->layout() != nullptr
                    ? pageWidget->layout()->contentsMargins().bottom() : 0;
                const int chartHeight = std::max(1, pageHeight - chartTop - bottomMargin);
                if (chartView->minimumHeight() != chartHeight
                    || chartView->maximumHeight() != chartHeight)
                {
                    chartView->setMinimumHeight(chartHeight);
                    chartView->setMaximumHeight(chartHeight);
                }
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

    adjustMainChartHeight(m_utilizationMemorySubPage, m_memoryCompositionHistoryWidget, 0.36, 24, 116,
        m_utilizationFloatingMode == UtilizationFloatingMode::Detail && m_utilizationFloatingPage == m_utilizationMemorySubPage);
    adjustMainChartHeight(m_utilizationDiskSubPage, m_diskUtilChartView, 0.40, 24, 120,
        m_utilizationFloatingMode == UtilizationFloatingMode::Detail && m_utilizationFloatingPage == m_utilizationDiskSubPage);
    adjustMainChartHeight(m_utilizationNetworkSubPage, m_networkUtilChartView, 0.40, 24, 120,
        m_utilizationFloatingMode == UtilizationFloatingMode::Detail && m_utilizationFloatingPage == m_utilizationNetworkSubPage);

    applyMaxHeightIfChanged(m_memoryUtilPrimaryDetailLabel, std::max(1, m_memoryUtilPrimaryDetailLabel != nullptr ? m_memoryUtilPrimaryDetailLabel->sizeHint().height() : 1));
    applyMaxHeightIfChanged(m_memoryUtilSecondaryDetailLabel, std::max(1, m_memoryUtilSecondaryDetailLabel != nullptr ? m_memoryUtilSecondaryDetailLabel->sizeHint().height() : 1));
    applyMaxHeightIfChanged(m_diskUtilDetailLabel, std::max(1, m_diskUtilDetailLabel != nullptr ? m_diskUtilDetailLabel->sizeHint().height() : 1));
    applyMaxHeightIfChanged(m_networkUtilDetailLabel, std::max(1, m_networkUtilDetailLabel != nullptr ? m_networkUtilDetailLabel->sizeHint().height() : 1));
    for (DiskUtilizationDevice& device : m_diskUtilDevices)
    {
        adjustMainChartHeight(device.pageWidget, device.chartView, 0.40, 24, 120,
            m_utilizationFloatingMode == UtilizationFloatingMode::Detail && m_utilizationFloatingPage == device.pageWidget);
        if (device.detailLabel != nullptr)
        {
            applyMaxHeightIfChanged(device.detailLabel, std::max(1, device.detailLabel->sizeHint().height()));
        }
    }
    for (NetworkUtilizationDevice& device : m_networkUtilDevices)
    {
        if (device.physical)
        {
            adjustMainChartHeight(device.pageWidget, device.chartView, 0.40, 24, 120,
                m_utilizationFloatingMode == UtilizationFloatingMode::Detail && m_utilizationFloatingPage == device.pageWidget);
        }
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
        if (m_utilizationFloatingMode == UtilizationFloatingMode::Detail
            && m_utilizationFloatingPage == m_utilizationGpuSubPage)
        {
            gpuReferenceHeight = m_utilizationGpuSubPage->contentsRect().height();
        }
        else if (m_utilizationDetailStack != nullptr)
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
            scaledDetailPx(58));
        const int summaryHeight = m_gpuUtilSummaryLabel != nullptr
            ? m_gpuUtilSummaryLabel->sizeHint().height()
            : 20;
        const int detailHeight = m_utilizationFloatingMode == UtilizationFloatingMode::Detail
            && m_utilizationFloatingPage == m_utilizationGpuSubPage ? 0 : m_gpuUtilDetailLabel != nullptr
            ? m_gpuUtilDetailLabel->sizeHint().height()
            : 22;
        // reservedHeight 用途：GPU 页非图表区预留高度（含布局间距与上下边距）。
        const int reservedHeight = titleHeight + summaryHeight + detailHeight + scaledDetailPx(38);
        const int availableHeight = std::max(1, gpuReferenceHeight - reservedHeight);

        // engineAreaHeight 用途：分配给 2x2 引擎图区域的高度。
        const int engineAreaHeight = std::max(
            1,
            static_cast<int>(std::round(static_cast<double>(availableHeight) * 0.52)));
        const int memoryAreaEachHeight = std::max(1, (availableHeight - engineAreaHeight - scaledDetailPx(8)) / 2);
        if (m_gpuEngineHostWidget != nullptr && m_gpuEngineGridLayout != nullptr)
        {
            const int rowSpacing = std::max(0, m_gpuEngineGridLayout->verticalSpacing());
            const int cellHeight = std::max(1, (engineAreaHeight - rowSpacing) / 2);
            for (GpuEngineChartEntry& chartEntry : m_gpuEngineCharts)
            {
                if (chartEntry.chartView != nullptr)
                {
                    applyMaxHeightIfChanged(chartEntry.chartView, std::max(1, cellHeight - scaledDetailPx(10)));
                }
                if (chartEntry.titleLabel != nullptr)
                {
                    chartEntry.titleLabel->setMinimumHeight(0);
                    chartEntry.titleLabel->setMaximumHeight(scaledDetailPx(18));
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
        if (m_utilizationFloatingMode == UtilizationFloatingMode::Detail
            && m_utilizationFloatingPage == device.pageWidget)
        {
            gpuReferenceHeight = device.pageWidget->contentsRect().height();
        }
        else if (m_utilizationDetailStack != nullptr)
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

        const int layoutSpacing = scaledDetailPx(6);
        const int headerHeight = scaledDetailPx(58);
        const int summaryHeight = device.summaryLabel != nullptr
            ? device.summaryLabel->sizeHint().height()
            : 0;
        const int detailHeight = m_utilizationFloatingMode == UtilizationFloatingMode::Detail
            && m_utilizationFloatingPage == device.pageWidget ? 0 : device.detailLabel != nullptr
            ? device.detailLabel->sizeHint().height()
            : 0;
        const int reservedHeight = headerHeight + summaryHeight + detailHeight
            + layoutSpacing * 7 + scaledDetailPx(12);
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
                    applyMaxHeightIfChanged(chartEntry.chartView, std::max(1, cellHeight - scaledDetailPx(14)));
                }
                if (chartEntry.titleLabel != nullptr)
                {
                    chartEntry.titleLabel->setMinimumHeight(0);
                    chartEntry.titleLabel->setMaximumHeight(scaledDetailPx(18));
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
    const QColor diskReadColor = KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Read);
    const QColor diskWriteColor = KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Write);
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
    const QColor networkRxColor = KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Read);
    const QColor networkTxColor = KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Write);
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
    // 逐核频率温度摘要已有实时图，复制导出足够，收拢快照对比。
    ks::ui::SetTableActionBarMode(m_cpuDetailTable, ks::ui::TableActionBarMode::Compact);
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

    m_gpuEditor = new ks::ui::StructuredFieldView(m_gpuPage);
    m_gpuEditor->setPresentation(ks::ui::StructuredFieldView::Presentation::Tree);
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

    m_memoryEditor = new ks::ui::StructuredFieldView(m_memoryPage);
    m_memoryEditor->setPresentation(ks::ui::StructuredFieldView::Presentation::Tree);
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
    m_pnpAcpiPciPage = createReadOnlyFieldPage(
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
    // The list and chart pages contain child viewports that receive mouse events directly.
    // A single application filter also covers dynamically discovered device cards.
    qApp->installEventFilter(this);
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
    device.physical = sample.physical;
    device.lastOperational = sample.operational;
    device.lastRxBytes = sample.totalRxBytes;
    device.lastTxBytes = sample.totalTxBytes;
    device.lastSampleMs = QDateTime::currentMSecsSinceEpoch();
    device.hasPreviousSample = true;
    if (!sample.physical)
    {
        ensureVirtualNetworkPage();
    }
    createNetworkUtilizationDevicePage(&device);
    m_networkUtilDevices.push_back(device);

    const int deviceIndex = static_cast<int>(m_networkUtilDevices.size()) - 1;
    NetworkUtilizationDevice& createdDevice = m_networkUtilDevices[static_cast<std::size_t>(deviceIndex)];
    if (sample.physical)
    {
        createdDevice.navCard = addUtilizationSidebarCard(
            createdDevice.pageWidget,
            createdDevice.displayNameText,
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Network),
            UtilizationDeviceKind::Network,
            deviceIndex);
        if (createdDevice.navCard != nullptr)
        {
            createdDevice.navCard->setSeriesColors(
                KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Read),
                KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Write));
        }
    }
    else
    {
        if (m_virtualNetworkGrid != nullptr && createdDevice.pageWidget != nullptr)
        {
            relayoutVirtualNetworkTiles();
        }
    }
    scheduleUtilizationLayoutRefresh();
    if (!sample.physical && m_utilizationFloatingPage == m_virtualNetworkPage)
    {
        QTimer::singleShot(0, this, [this]() { applyUtilizationFloatingContentScale(); });
    }
    return deviceIndex;
}

void HardwareDock::ensureVirtualNetworkPage()
{
    if (m_virtualNetworkPage != nullptr || m_utilizationDetailStack == nullptr)
    {
        return;
    }
    m_virtualNetworkPage = new QWidget(m_utilizationDetailStack);
    configureCompressibleWidget(m_virtualNetworkPage, QSizePolicy::Ignored, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(m_virtualNetworkPage);
    QVBoxLayout* const pageLayout = new QVBoxLayout(m_virtualNetworkPage);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);
    QLabel* const titleLabel = new QLabel(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.card.virtual_network"),
        QStringLiteral("虚拟网络")), m_virtualNetworkPage);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(QStringLiteral("font-size:28px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 8);
    pageLayout->addWidget(titleLabel);

    m_virtualNetworkScrollArea = new QScrollArea(m_virtualNetworkPage);
    m_virtualNetworkScrollArea->setFrameShape(QFrame::NoFrame);
    m_virtualNetworkScrollArea->setWidgetResizable(true);
    m_virtualNetworkScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_virtualNetworkScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    configureCompressibleWidget(m_virtualNetworkScrollArea, QSizePolicy::Ignored, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(m_virtualNetworkScrollArea);
    pageLayout->addWidget(m_virtualNetworkScrollArea, 1);

    m_virtualNetworkGridHost = new QWidget(m_virtualNetworkScrollArea);
    configureCompressibleWidget(m_virtualNetworkGridHost, QSizePolicy::Ignored, QSizePolicy::Preferred);
    appendTransparentBackgroundStyle(m_virtualNetworkGridHost);
    m_virtualNetworkGrid = new QGridLayout(m_virtualNetworkGridHost);
    m_virtualNetworkGrid->setContentsMargins(2, 2, 2, 2);
    m_virtualNetworkGrid->setHorizontalSpacing(10);
    m_virtualNetworkGrid->setVerticalSpacing(10);
    m_virtualNetworkGrid->setAlignment(Qt::AlignTop);
    m_virtualNetworkScrollArea->setWidget(m_virtualNetworkGridHost);
    m_utilizationDetailStack->addWidget(m_virtualNetworkPage);
    m_networkNavCard = addUtilizationSidebarCard(m_virtualNetworkPage,
        titleLabel->text(), KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Network),
        UtilizationDeviceKind::VirtualNetwork, -1);
    if (m_networkNavCard != nullptr)
    {
        m_networkNavCard->setSeriesColors(
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Read),
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Write));
    }
}

void HardwareDock::relayoutVirtualNetworkTiles()
{
    if (m_virtualNetworkGrid == nullptr || m_virtualNetworkScrollArea == nullptr
        || m_virtualNetworkScrollArea->viewport() == nullptr)
    {
        return;
    }
    const int viewportWidth = std::max(360, m_virtualNetworkScrollArea->viewport()->width());
    const int columns = viewportWidth >= 700 ? 2 : 1;
    std::vector<QWidget*> tiles;
    tiles.reserve(m_networkUtilDevices.size());
    for (NetworkUtilizationDevice& device : m_networkUtilDevices)
    {
        if (!device.physical && device.pageWidget != nullptr)
        {
            tiles.push_back(device.pageWidget);
        }
    }
    if (m_virtualNetworkColumnCount == columns
        && m_virtualNetworkTileCount == static_cast<int>(tiles.size()))
    {
        return;
    }
    for (QWidget* const tile : tiles)
    {
        m_virtualNetworkGrid->removeWidget(tile);
    }
    for (int index = 0; index < static_cast<int>(tiles.size()); ++index)
    {
        m_virtualNetworkGrid->addWidget(tiles[static_cast<std::size_t>(index)],
            index / columns, index % columns);
    }
    m_virtualNetworkColumnCount = columns;
    m_virtualNetworkTileCount = static_cast<int>(tiles.size());
    m_virtualNetworkGrid->setColumnStretch(0, 1);
    m_virtualNetworkGrid->setColumnStretch(1, columns == 2 ? 1 : 0);
    m_virtualNetworkGridHost->updateGeometry();
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
    const QColor readColor = KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Read);
    const QColor writeColor = KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Write);
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

    devicePointer->pageWidget = new QWidget(devicePointer->physical
        ? static_cast<QWidget*>(m_utilizationDetailStack) : m_virtualNetworkGridHost);
    configureCompressibleWidget(devicePointer->pageWidget,
        devicePointer->physical ? QSizePolicy::Expanding : QSizePolicy::Ignored,
        devicePointer->physical ? QSizePolicy::Expanding : QSizePolicy::Fixed);
    appendTransparentBackgroundStyle(devicePointer->pageWidget);
    if (!devicePointer->physical)
    {
        devicePointer->pageWidget->setProperty("ksword_virtual_network_tile", true);
        devicePointer->pageWidget->setStyleSheet(QStringLiteral(
            "QWidget[ksword_virtual_network_tile=\"true\"]{background:transparent;"
            "border:1px solid %1;border-radius:6px;}"
            "QWidget[ksword_virtual_network_tile=\"true\"] QLabel{border:none;}")
            .arg(KswordTheme::BorderHex()));
        devicePointer->pageWidget->setFixedHeight(350);
    }
    QVBoxLayout* pageLayout = new QVBoxLayout(devicePointer->pageWidget);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(devicePointer->displayNameText, devicePointer->pageWidget);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:%1px;font-weight:700;color:%2;")
        .arg(devicePointer->physical ? 46 : 18)
        .arg(KswordTheme::TextPrimaryHex()));
    titleLabel->setWordWrap(!devicePointer->physical);
    lockLabelHeightToFont(titleLabel, 14);
    if (!devicePointer->physical)
    {
        titleLabel->setFixedHeight(titleLabel->fontMetrics().height() * 2 + 8);
    }
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
    const QColor rxColor = KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Read);
    const QColor txColor = KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Write);
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
    if (!devicePointer->physical)
    {
        devicePointer->chartView->setFixedHeight(135);
    }
    pageLayout->addWidget(devicePointer->chartView, 1);

    devicePointer->detailLabel = new QLabel(QStringLiteral("网络参数采样中..."), devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->detailLabel);
    devicePointer->detailLabel->setWordWrap(!devicePointer->physical);
    devicePointer->detailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(KswordTheme::TextPrimaryHex()));
    pageLayout->addWidget(devicePointer->detailLabel, 0);

    if (devicePointer->physical)
    {
        m_utilizationDetailStack->addWidget(devicePointer->pageWidget);
    }
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
    m_metricCpuValid = samplePerCoreUsage(&coreUsageList, &totalCpuUsage);
    if (!m_metricCpuValid)
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
    m_metricDiskValid = sampleDiskRates(&diskSampleList);
    if (m_metricDiskValid)
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
    m_metricNetworkValid = sampleNetworkRates(&networkSampleList);
    if (m_metricNetworkValid)
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
    m_metricGpuValid = sampleGpuUsages(&gpuSampleList);
    if (m_metricGpuValid)
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

    m_metricSampleTimeMs = QDateTime::currentMSecsSinceEpoch(); // 本帧图表共用真实采样时刻。
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
    if (m_hardwareDetailsSamplingEnabled)
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
    if (m_utilizationFloatingMode == UtilizationFloatingMode::Detail)
    {
        // Device discovery can add chart views after the page has been floated.
        applyUtilizationFloatingTheme();
    }
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
    coreUsageOut->clear();
    m_metricCoreValid.clear();
    *totalUsageOut = 0.0; // 查询早退也不能保留上一帧的有效性或总值。
    if (m_cpuPerfQueryHandle == nullptr)
    {
        initializePerformanceCounters();
    }
    coreUsageOut->assign(m_coreCounterHandles.size(), 0.0);
    m_metricCoreValid.assign(m_coreCounterHandles.size(), false);
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

    double usageSum = 0.0;
    int validCount = 0;

    for (std::size_t coreIndex = 0; coreIndex < m_coreCounterHandles.size(); ++coreIndex)
    {
        void* counterHandleVoid = m_coreCounterHandles[coreIndex];
        if (counterHandleVoid == nullptr)
        {
            continue;
        }

        PDH_FMT_COUNTERVALUE formattedValue{};
        const PDH_STATUS readStatus = ::PdhGetFormattedCounterValue(
            reinterpret_cast<PDH_HCOUNTER>(counterHandleVoid),
            PDH_FMT_DOUBLE,
            nullptr,
            &formattedValue);
        if (readStatus != ERROR_SUCCESS
            || (formattedValue.CStatus != PDH_CSTATUS_VALID_DATA
                && formattedValue.CStatus != PDH_CSTATUS_NEW_DATA)
            || !std::isfinite(formattedValue.doubleValue))
        {
            continue;
        }

        const double usageValue = std::clamp(formattedValue.doubleValue, 0.0, 100.0);
        (*coreUsageOut)[coreIndex] = usageValue;
        m_metricCoreValid[coreIndex] = true; // 部分失败核的0占位不能成为有效历史样本。
        usageSum += usageValue;
        ++validCount;
    }

    *totalUsageOut = validCount > 0 ? (usageSum / static_cast<double>(validCount)) : 0.0;
    return validCount > 0;
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
    std::unordered_set<std::uint64_t> ipInterfaceKeys;
    const bool hasIpTable = collectNetworkIpInterfaceKeys(&ipInterfaceKeys);
    for (ULONG rowIndex = 0; rowIndex < tablePointer->NumEntries; ++rowIndex)
    {
        const MIB_IF_ROW2& rowValue = tablePointer->Table[rowIndex];
        if (!isMonitoredNetworkInterface(rowValue, ipInterfaceKeys, hasIpTable))
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
    std::unordered_set<std::uint64_t> ipInterfaceKeys;
    const bool hasIpTable = collectNetworkIpInterfaceKeys(&ipInterfaceKeys);
    for (ULONG rowIndex = 0; rowIndex < tablePointer->NumEntries; ++rowIndex)
    {
        const MIB_IF_ROW2& rowValue = tablePointer->Table[rowIndex];
        if (!isMonitoredNetworkInterface(rowValue, ipInterfaceKeys, hasIpTable))
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
        sample.physical = rowValue.InterfaceAndOperStatusFlags.HardwareInterface != 0;
        sample.operational = rowValue.OperStatus == IfOperStatusUp;
        sample.totalRxBytes = static_cast<std::uint64_t>(rowValue.InOctets);
        sample.totalTxBytes = static_cast<std::uint64_t>(rowValue.OutOctets);

        const int deviceIndex = ensureNetworkUtilizationDevice(
            sample,
            static_cast<int>(sampleListOut->size()));
        if (deviceIndex >= 0 && deviceIndex < static_cast<int>(m_networkUtilDevices.size()))
        {
            NetworkUtilizationDevice& device = m_networkUtilDevices[static_cast<std::size_t>(deviceIndex)];
            const qint64 elapsedMs = nowMs - device.lastSampleMs;
            if (sample.operational && device.lastOperational
                && device.hasPreviousSample && elapsedMs > 0)
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
            device.lastOperational = sample.operational;
            device.hasPreviousSample = true;
        }
        const std::uint64_t trafficBytes = sample.totalRxBytes + sample.totalTxBytes;
        if (sample.operational && trafficBytes >= primaryTrafficBytes)
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
        const bool includeGpuClockTelemetry = m_hardwareDetailsSamplingEnabled;
        QThreadPool::globalInstance()->start(
            [samplingStatePointer, includeGpuClockTelemetry]()
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
                        if (includeGpuClockTelemetry
                            && queryGpuAdapterTelemetrySnapshot(adapterDesc.AdapterLuid, &telemetrySnapshot))
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
        const bool coreValid = static_cast<std::size_t>(indexValue) < m_metricCoreValid.size()
            && m_metricCoreValid[static_cast<std::size_t>(indexValue)];
        appendCoreSeriesPoint(chartEntry, usageValue, coreValid);
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
        gpuUsagePercent);
}

void HardwareDock::updateUtilizationSidebarCards(
    const double cpuUsagePercent,
    const double memoryUsagePercent,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
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
    double virtualRxBytesPerSec = 0.0;
    double virtualTxBytesPerSec = 0.0;
    for (int sampleIndex = 0; sampleIndex < static_cast<int>(sampleList.size()); ++sampleIndex)
    {
        const NetworkRateSample& sample = sampleList[static_cast<std::size_t>(sampleIndex)];
        if (!sample.physical)
        {
            virtualRxBytesPerSec += sample.rxBytesPerSec;
            virtualTxBytesPerSec += sample.txBytesPerSec;
        }
        const int deviceIndex = ensureNetworkUtilizationDevice(sample, sampleIndex);
        if (deviceIndex < 0 || deviceIndex >= static_cast<int>(m_networkUtilDevices.size()))
        {
            continue;
        }
        updateNetworkUtilizationDevice(m_networkUtilDevices[static_cast<std::size_t>(deviceIndex)], sample);
    }
    if (m_networkNavCard != nullptr)
    {
        rebuildDualRateNavCard(m_networkNavCard,
            &m_networkNavRxHistoryBytesPerSec, &m_networkNavTxHistoryBytesPerSec,
            virtualRxBytesPerSec, virtualTxBytesPerSec, &m_networkNavAutoScaleBytesPerSec,
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.network.summary"),
                QStringLiteral("下 %1 / 上 %2"))
                .arg(formatRateText(virtualRxBytesPerSec))
                .arg(formatRateText(virtualTxBytesPerSec)));
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
        0.0,
        sample.dedicatedUsageAvailable);
    appendFilledSeriesPoint(
        device.sharedMemoryLineSeries,
        device.sharedMemoryBaselineSeries,
        device.sharedMemoryAxisX,
        device.sharedMemoryAxisY,
        sample.sharedUsedGiB,
        0.0,
        sample.sharedUsageAvailable);
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

void HardwareDock::appendCoreSeriesPoint(CoreChartEntry& chartEntry, const double usagePercent, const bool sampleValid)
{
    if (chartEntry.lineSeries == nullptr || chartEntry.baselineSeries == nullptr
        || chartEntry.axisX == nullptr || chartEntry.axisY == nullptr)
    {
        return;
    }
    // 同一帧身份与时间驱动上/下界模型，失败采样保留缺口而非伪造 0%。
    auto* binding = ks::ui::MetricChartBinding::ForSeries(chartEntry.lineSeries, m_historyLength);
    binding->append({ static_cast<std::uint64_t>(m_sampleCounter), m_metricSampleTimeMs,
        usagePercent, m_metricCpuValid && sampleValid });
    ks::ui::MetricChartBinding::ForSeries(chartEntry.baselineSeries, m_historyLength)->append(
        { static_cast<std::uint64_t>(m_sampleCounter), m_metricSampleTimeMs, 0.0, m_metricCpuValid && sampleValid });
    const auto range = binding->range({ 0.0, 1.0, 1.15, 100.0 });
    animateLiveValueAxisRange(chartEntry.axisX, range.minimumX, range.maximumX);
    chartEntry.axisY->setRange(range.minimumY, range.maximumY);
}

void HardwareDock::appendGeneralSeriesPoint(QLineSeries* lineSeries, QValueAxis* axisX,
    QValueAxis* axisY, const double sampleValue, const double minAxisYValue)
{
    if (lineSeries == nullptr || axisX == nullptr || axisY == nullptr)
    {
        return;
    }
    // 保留现有系列与轴对象；有界缓存、时间和有效值范围统一交给共享模型。
    auto* binding = ks::ui::MetricChartBinding::ForSeries(lineSeries, m_historyLength);
    binding->append({ static_cast<std::uint64_t>(m_sampleCounter), m_metricSampleTimeMs, sampleValue, true });
    const auto range = binding->range({ minAxisYValue, 1.0, 1.15, {} });
    animateLiveValueAxisRange(axisX, range.minimumX, range.maximumX);
    axisY->setRange(range.minimumY, range.maximumY);
}

void HardwareDock::appendFilledSeriesPoint(QLineSeries* lineSeries, QLineSeries* baselineSeries,
    QValueAxis* axisX, QValueAxis* axisY, const double sampleValue, const double minAxisYValue, const bool sampleValid)
{
    if (lineSeries == nullptr || baselineSeries == nullptr || axisX == nullptr || axisY == nullptr)
    {
        return;
    }
    // 聚合磁盘/网络沿用本帧后端有效性；其它专用指标保留自身有限值语义。
    bool valid = sampleValid;
    if (lineSeries == m_diskReadLineSeries || lineSeries == m_diskWriteLineSeries)
    {
        valid = valid && m_metricDiskValid;
    }
    else if (lineSeries == m_networkRxLineSeries || lineSeries == m_networkTxLineSeries)
    {
        valid = valid && m_metricNetworkValid;
    }
    else if (lineSeries == m_gpuDedicatedMemoryLineSeries)
    {
        valid = valid && m_metricGpuValid && m_gpuDedicatedUsageAvailable;
    }
    else if (lineSeries == m_gpuSharedMemoryLineSeries)
    {
        valid = valid && m_metricGpuValid && m_gpuSharedUsageAvailable;
    }
    for (const GpuEngineChartEntry& engine : m_gpuEngineCharts)
    {
        if (lineSeries == engine.lineSeries)
        {
            valid = valid && m_metricGpuValid;
            break;
        }
    }
    auto* binding = ks::ui::MetricChartBinding::ForSeries(lineSeries, m_historyLength);
    binding->append({ static_cast<std::uint64_t>(m_sampleCounter), m_metricSampleTimeMs, sampleValue, valid });
    ks::ui::MetricChartBinding::ForSeries(baselineSeries, m_historyLength)->append(
        { static_cast<std::uint64_t>(m_sampleCounter), m_metricSampleTimeMs, minAxisYValue, valid });
    const auto range = binding->range({ minAxisYValue, 1.0, 1.15, {} });
    animateLiveValueAxisRange(axisX, range.minimumX, range.maximumX);
    axisY->setRange(range.minimumY, range.maximumY);
}

void HardwareDock::updateSharedSeriesAxisRange(QLineSeries* primaryLineSeries,
    QLineSeries* secondaryLineSeries, QValueAxis* axisX, QValueAxis* axisY, const double minAxisYValue)
{
    if (axisX == nullptr || axisY == nullptr)
    {
        return;
    }
    // 同一轴策略读取两份模型的有效历史，不再反向扫描绘制系列的临时坐标。
    const auto range = ks::ui::MetricChartBinding::SharedRange({ primaryLineSeries, secondaryLineSeries },
        ks::ui::MetricXMode::StableId, { minAxisYValue, 1.0, 1.15, {} });
    animateLiveValueAxisRange(axisX, range.minimumX, range.maximumX);
    axisY->setRange(range.minimumY, range.maximumY);
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

    QObject* const applicationContext = QCoreApplication::instance();
    if (applicationContext == nullptr)
    {
        m_r0HardwareHealthRefreshing.store(false);
        return;
    }

    const QPointer<HardwareDock> safeThis(this);
    QThreadPool::globalInstance()->start([applicationContext, safeThis, nowMs]() {
        // r0QueryLock 用途：健康查询与按需设备审计共用一条串行 R0 请求通道。
        const std::lock_guard<std::mutex> r0QueryLock(hardwareR0QueryMutex);
        const ksword::ark::DriverClient client;
        const ksword::ark::DriverCapabilitiesQueryResult capabilityResult = client.queryDriverCapabilities();
        const ksword::ark::DynDataCapabilitiesResult dynDataResult = client.queryDynDataCapabilities();
        const ksword::ark::DriverIntegrityResult integrityResult = client.queryKernelCpuIntegrity();
        const ksword::ark::CpuHardwareSnapshotResult cpuHardwareResult = client.queryCpuHardwareSnapshot();
        const ksword::ark::PhysicalMemoryLayoutResult physicalMemoryResult = client.queryPhysicalMemoryLayout();

        // 页面可在采集期间销毁；只投递到应用线程，页面指针仅在 UI 回调内检查。
        QMetaObject::invokeMethod(
            applicationContext,
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

    });
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

    if (m_overviewEditor != nullptr && !m_cachedOverviewFields.isEmpty())
    {
        m_overviewEditor->setDocument(m_cachedOverviewFields);
    }
    if (m_gpuEditor != nullptr && !m_cachedGpuFields.isEmpty())
    {
        m_gpuEditor->setDocument(m_cachedGpuFields);
    }
    if (m_memoryEditor != nullptr && !m_cachedMemoryFields.isEmpty())
    {
        m_memoryEditor->setDocument(m_cachedMemoryFields);
    }
    if (m_deviceStackEditor != nullptr && !m_cachedDeviceStackFields.isEmpty())
    {
        m_deviceStackEditor->setDocument(m_cachedDeviceStackFields);
    }
    populateDeviceAuditTable(m_deviceStackTable, m_cachedDeviceStackRows);
    if (m_keyboardMouseHidEditor != nullptr && !m_cachedKeyboardMouseHidFields.isEmpty())
    {
        m_keyboardMouseHidEditor->setDocument(m_cachedKeyboardMouseHidFields);
    }
    populateDeviceAuditTable(m_keyboardMouseHidTable, m_cachedKeyboardMouseHidRows);
    if (m_usbTopologyEditor != nullptr && !m_cachedUsbTopologyFields.isEmpty())
    {
        m_usbTopologyEditor->setDocument(m_cachedUsbTopologyFields);
    }
    populateDeviceAuditTable(m_usbTopologyTable, m_cachedUsbTopologyRows);
    if (m_pnpAcpiPciEditor != nullptr && !m_cachedPnpAcpiPciFields.isEmpty())
    {
        m_pnpAcpiPciEditor->setDocument(m_cachedPnpAcpiPciFields);
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

    QObject* const applicationContext = QCoreApplication::instance();
    if (applicationContext == nullptr)
    {
        m_staticInfoRefreshing.store(false);
        return;
    }

    const bool includeHardwareDetails = m_hardwareDetailsSamplingEnabled;
    const QPointer<HardwareDock> safeThis(this);
    QThreadPool::globalInstance()->start([applicationContext, safeThis, includeHardwareDetails]() {
        ks::ui::FieldDocument overviewFields = buildOverviewFieldsSnapshot();
        const ks::ui::FieldDocument peripheralOverviewFields = buildOverviewPeripheralFieldsSnapshot(includeHardwareDetails);
        overviewFields.nodes += peripheralOverviewFields.nodes;
        // 首页只消费 overviewFields；额外的显卡/内存详情查询留给实际打开的硬件页。
        const ks::ui::FieldDocument gpuWmiFields = includeHardwareDetails ? buildGpuFieldsSnapshot() : ks::ui::FieldDocument{};
        const ks::ui::FieldDocument memoryFields = includeHardwareDetails ? buildMemoryFieldsSnapshot() : ks::ui::FieldDocument{};
        const MemoryHardwareSummarySnapshot memorySummary = includeHardwareDetails
            ? queryMemoryHardwareSummarySnapshot() : MemoryHardwareSummarySnapshot{};
        const GpuHardwareSummarySnapshot gpuSummary = includeHardwareDetails
            ? queryGpuHardwareSummarySnapshot() : GpuHardwareSummarySnapshot{};

        // 线程池由 QCoreApplication 析构等待，应用接收器比后台任务活得更久。
        QMetaObject::invokeMethod(
            applicationContext,
            [safeThis, includeHardwareDetails, overviewFields, gpuWmiFields, memoryFields, memorySummary, gpuSummary]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->m_cachedOverviewFields = overviewFields;
                if (includeHardwareDetails)
                {
                    safeThis->m_cachedGpuFields = buildGpuHardwareSummaryFields(gpuSummary, gpuWmiFields);
                    safeThis->m_cachedMemoryFields = memoryFields;
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
                }
                emit safeThis->staticOverviewFieldsChanged(safeThis->m_cachedOverviewFields);
                // 同步信号接收者可能销毁 Dock，不能继续访问已失效的页面。
                if (safeThis.isNull())
                {
                    return;
                }
                safeThis->refreshStaticHardwareTexts(false);
                safeThis->m_staticInfoRefreshing.store(false);
                if (!includeHardwareDetails && safeThis->m_hardwareDetailsSamplingEnabled)
                {
                    // 欢迎页采集期间打开了硬件页：概览回投后补采详情，不能丢掉范围升级。
                    safeThis->requestAsyncStaticInfoRefresh();
                }
            },
            Qt::QueuedConnection);

    });
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
        ks::ui::FieldDocument pnpAcpiPciFields;

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
            pnpAcpiPciFields = HardwareDock::buildPnpAcpiPciFields();
        }

        // applicationContext 与事件循环同寿命；工作线程不读取页面 QPointer，更不解引用页面成员。
        QMetaObject::invokeMethod(
            applicationContext,
            [safeThis,
                requestedMask,
                deviceStackSnapshot = std::move(deviceStackSnapshot),
                inputStackSnapshot = std::move(inputStackSnapshot),
                usbTopologySnapshot = std::move(usbTopologySnapshot),
                pnpAcpiPciFields = std::move(pnpAcpiPciFields)]() mutable
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
                    std::move(pnpAcpiPciFields));
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
    ks::ui::FieldDocument pnpAcpiPciFields)
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
                pnpAcpiPciFields = std::move(pnpAcpiPciFields)]() mutable
            {
                if (!safeThis.isNull())
                {
                    safeThis->applyDeviceAuditRefreshResult(
                        requestedMask,
                        std::move(deviceStackSnapshot),
                        std::move(inputStackSnapshot),
                        std::move(usbTopologySnapshot),
                        std::move(pnpAcpiPciFields));
                }
            });
        return;
    }

    if ((requestedMask & DeviceStackAuditRefresh) != 0U)
    {
        m_cachedDeviceStackFields = std::move(deviceStackSnapshot.summaryFields);
        m_cachedDeviceStackRows = std::move(deviceStackSnapshot.rows);
    }
    if ((requestedMask & InputStackAuditRefresh) != 0U)
    {
        m_cachedKeyboardMouseHidFields = std::move(inputStackSnapshot.summaryFields);
        m_cachedKeyboardMouseHidRows = std::move(inputStackSnapshot.rows);
    }
    if ((requestedMask & UsbTopologyAuditRefresh) != 0U)
    {
        m_cachedUsbTopologyFields = std::move(usbTopologySnapshot.summaryFields);
        m_cachedUsbTopologyRows = std::move(usbTopologySnapshot.rows);
    }
    if ((requestedMask & PnpAcpiPciRefresh) != 0U)
    {
        m_cachedPnpAcpiPciFields = std::move(pnpAcpiPciFields);
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
    if (!m_hardwareDetailsSamplingEnabled)
    {
        return;
    }

    // expectedFlag 用途：原子刷新锁 CAS 期望值（false=当前无任务）。
    bool expectedFlag = false;
    if (!m_sensorRefreshing.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    // event 用途：串联本次 CPU 传感器读取与日志输出，便于追踪失败原因。
    kLogEvent event;
    QObject* const applicationContext = QCoreApplication::instance();
    if (applicationContext == nullptr)
    {
        m_sensorRefreshing.store(false);
        return;
    }

    const QPointer<HardwareDock> safeThis(this);
    QThreadPool::globalInstance()->start([applicationContext, safeThis, event]() {
        const SensorProbeResult temperatureProbeResult = queryCpuTemperatureProbeResult();
        const SensorProbeResult voltageProbeResult = queryCpuVoltageProbeResult();
        const bool invokeOk = QMetaObject::invokeMethod(
            applicationContext,
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

        if (!invokeOk)
        {
            warn << event << "[HardwareDock] CPU传感器结果回投UI线程失败。" << eol;
        }
    });
}

ks::ui::FieldDocument HardwareDock::buildOverviewFields() const
{
    return buildOverviewFieldsSnapshot();
}

ks::ui::FieldDocument HardwareDock::buildGpuFields() const
{
    return buildGpuFieldsSnapshot();
}

ks::ui::FieldDocument HardwareDock::buildMemoryFields() const
{
    return buildMemoryFieldsSnapshot();
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

ks::ui::FieldDocument HardwareDock::buildDeviceStackFields() const
{
    return buildDeviceStackAuditViewSnapshot().summaryFields;
}

HardwareDock::DeviceAuditViewSnapshot HardwareDock::buildDeviceStackAuditViewSnapshot()
{
    const QString scriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; $doc=[ordered]@{}; "
        "$doc['DevNode / Device Stack']=@(Get-CimInstance Win32_PnPEntity | Select-Object Name,PNPClass,Service,Status,PNPDeviceID,ConfigManagerErrorCode -First 120); "
        "$doc | ConvertTo-Json -Depth 8 -Compress");
    DeviceAuditViewSnapshot snapshot;
    snapshot.summaryFields = queryPowerShellFieldsSync(scriptText, 8000);
    snapshot.summaryFields.note(QStringLiteral("说明：上方为 WMI/DevNode 视角；下方结构化表展示 R0 DeviceStack 行、attached/next 关系、风险标记和 PDB/DynData readiness。"))
        .note(QStringLiteral("风险标记: 不执行卸载/删除/patch。"));
    const ksword::ark::DriverClient client;
    const ksword::ark::DeviceAuditResult audit = client.queryDeviceStackAudit();
    snapshot.summaryFields.nodes += appendDeviceAuditSummaryFields(
        QStringLiteral("R0 Device Stack Audit Summary"), audit, KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH).nodes;
    snapshot.rows = buildDeviceAuditRows(QStringLiteral("DeviceStack"), audit);
    return snapshot;
}

ks::ui::FieldDocument HardwareDock::buildKeyboardMouseHidFields() const
{
    return buildKeyboardMouseHidAuditViewSnapshot().summaryFields;
}

HardwareDock::DeviceAuditViewSnapshot HardwareDock::buildKeyboardMouseHidAuditViewSnapshot()
{
    const QString scriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; $doc=[ordered]@{}; "
        "$doc['Keyboard / Mouse / HID']=@(Get-CimInstance Win32_PnPEntity | Where-Object {$_.PNPClass -in @('Keyboard','Mouse','HIDClass') -or $_.Service -match 'kbdhid|mouhid|hidusb'} | Select-Object Name,PNPClass,Service,Status,PNPDeviceID -First 160); "
        "$doc | ConvertTo-Json -Depth 8 -Compress");
    DeviceAuditViewSnapshot snapshot;
    snapshot.summaryFields = queryPowerShellFieldsSync(scriptText, 8000);
    snapshot.summaryFields.note(QStringLiteral("说明：默认不做消息截获、不做输入抓取。"));
    const ksword::ark::DriverClient client;
    const ksword::ark::DeviceAuditResult audit = client.queryInputStackAudit();
    snapshot.summaryFields.nodes += appendDeviceAuditSummaryFields(
        QStringLiteral("R0 Input Stack Audit Summary"), audit, KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH).nodes;
    snapshot.rows = buildDeviceAuditRows(QStringLiteral("InputStack"), audit);
    return snapshot;
}

ks::ui::FieldDocument HardwareDock::buildUsbTopologyFields() const
{
    return buildUsbTopologyAuditViewSnapshot().summaryFields;
}

HardwareDock::DeviceAuditViewSnapshot HardwareDock::buildUsbTopologyAuditViewSnapshot()
{
    const QString scriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; $doc=[ordered]@{}; "
        "$doc['USB控制器']=@(Get-CimInstance Win32_USBController | Select-Object Name,Manufacturer,DeviceID,PNPDeviceID,Status); $doc['USB Hub']=@(Get-CimInstance Win32_USBHub | Select-Object Name,DeviceID,PNPDeviceID,Status); $doc['USB连接']=@(Get-CimInstance Win32_USBControllerDevice | Select-Object Antecedent,Dependent -First 80); "
        "$doc | ConvertTo-Json -Depth 8 -Compress");
    DeviceAuditViewSnapshot snapshot;
    snapshot.summaryFields = queryPowerShellFieldsSync(scriptText, 10000);
    const ksword::ark::DriverClient client;
    const ksword::ark::DeviceAuditResult audit = client.queryUsbTopologyAudit();
    snapshot.summaryFields.nodes += appendDeviceAuditSummaryFields(
        QStringLiteral("R0 USB Topology Audit Summary"), audit, KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH).nodes;
    snapshot.rows = buildDeviceAuditRows(QStringLiteral("UsbTopology"), audit);
    return snapshot;
}

ks::ui::FieldDocument HardwareDock::buildPnpAcpiPciFields()
{
    const QString scriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; $doc=[ordered]@{}; "
        "$doc['主板']=@(Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version,SerialNumber); "
        "$doc['BIOS']=@(Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber); "
        "$doc['PnP节点']=@(Get-CimInstance Win32_PnPEntity | Where-Object {$_.PNPDeviceID -like 'ACPI*' -or $_.PNPDeviceID -like 'PCI*'} | Select-Object Name,PNPClass,Service,Status,PNPDeviceID,ConfigManagerErrorCode -First 180); "
        "$doc | ConvertTo-Json -Depth 8 -Compress");
    auto document = queryPowerShellFieldsSync(scriptText, 10000);
    document.note(QStringLiteral("风险标记: 保持只读，不做 patch/remove/disable。"));
    return document;
}
