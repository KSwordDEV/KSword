#include "RegistryDock/RegistryDock.h"
#include "RegistryDock/RegistryValueEditorWidget.h"
#include "RegistryDock/RegistryWorkbenchAccess.h"
#include "RegistryDock/RegistryDocument.h"
#include "UI/UI_All.h"
#include <QScrollArea>
#include <QTabBar>
#include <QCompleter>
#include "Framework/PrivilegeElevationPrompt.h"
#include "UI/TableInteractionSupport.h"
#include "UI/VisibleTableWidget.h"
#include "Internationalization/LanguageManager.h"

#include "ArkDriverClient/ArkDriverClient.h"
#include "RegistryDock/RegistryOptimizationPage.h"

// ============================================================
// RegistryDock_Themed.cpp
// 说明：
// 1) 提供类 regedit 的键树导航和键值编辑；
// 2) 支持导入/导出 .reg；
// 3) 支持后台搜索，避免阻塞 UI。
// ============================================================

#include "theme.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QThreadPool>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <sddl.h>

namespace
{
    // 统一按钮风格：与主界面保持同一主题。
    QString blueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle()
            .replace(KswordTheme::SurfaceAltHex(), KswordTheme::SurfaceAltColorHex())
            .replace(KswordTheme::TextPrimaryHex(), KswordTheme::TextPrimaryColorHex())
            .replace(KswordTheme::BorderHex(), KswordTheme::BorderColorHex())
            .replace(KswordTheme::TextSecondaryHex(), KswordTheme::TextSecondaryColorHex());
    }

    // 统一输入框风格：路径栏、搜索栏复用同一套样式。
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderColorHex())
            .arg(KswordTheme::SurfaceColorHex())
            .arg(KswordTheme::TextPrimaryColorHex());
    }

    // 表头风格：提升信息密集列表的可读性。
    QString blueHeaderStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;background:transparent;/* %2 */border:0;border-bottom:1px solid %3;font-weight:500;padding:4px 8px;}")
            .arg(KswordTheme::TextPrimaryColorHex())
            .arg(KswordTheme::SurfaceColorHex())
            .arg(KswordTheme::BorderColorHex());
    }

    // TreeItem 角色常量：保存路径和懒加载状态。
    constexpr int kRolePath = Qt::UserRole + 1;
    constexpr int kRoleLoaded = Qt::UserRole + 2;
    constexpr int kRolePlaceholder = Qt::UserRole + 3;
    // kRoleLoadToken：子键懒加载令牌，非 0 表示该节点已有一次后台枚举在途；
    // 后台结果回投 UI 线程时用它淘汰被新请求取代的过期结果。
    constexpr int kRoleLoadToken = Qt::UserRole + 4;

    // 子键懒加载节流：UI 线程每轮事件循环最多创建的子节点数量。
    // HKCR 这类巨型键有上万个子键，一次性构造会让界面冻结数秒。
    constexpr int kSubKeyItemBatchSize = 300;

    // kPendingTreeSelectionProperty：
    // - 作用：把“待定位路径”挂在键树控件的动态属性上；
    // - 说明：子键加载改成异步后，路径定位只能逐级推进，后台落地后凭该属性继续下探；
    //         用动态属性而非成员变量，避免为异步定位额外改动共享头文件。
    constexpr const char* kPendingTreeSelectionProperty = "kswordPendingTreeSelectionPath";

    // g_nextSubKeyLoadToken：
    // - 作用：全局单调递增的懒加载令牌发号器，保证同一节点的新请求总能淘汰旧请求。
    std::atomic<quint64> g_nextSubKeyLoadToken{ 1 };

    // 搜索结果节流：限制后台积压与表格对象数量，保证大量命中时 UI 仍可交互。
    constexpr std::size_t kMaxPendingSearchRows = 4096;
    constexpr std::size_t kSearchFlushBatchSize = 160;
    constexpr int kMaxSearchResultRows = 20000;

    // 搜索结果角色：展示文字会因语言和默认值格式而变化，处置必须使用原始元数据。
    constexpr int kSearchResultRoleTargetKind = Qt::UserRole + 40;
    constexpr int kSearchResultRoleRawValueName = Qt::UserRole + 41;
    constexpr int kSearchResultRoleViewBits = Qt::UserRole + 42; // 搜索行捕获视图。
    constexpr int kSearchResultRoleUseR0 = Qt::UserRole + 43; // 搜索行真实通道。
    constexpr int kSearchResultTargetKey = 1;
    constexpr int kSearchResultTargetValue = 2;

    // 根键映射结构：支持全名与缩写两种输入。
    struct RootEntry
    {
        const wchar_t* fullName = nullptr;
        const wchar_t* shortName = nullptr;
        HKEY root = nullptr;
    };

    const std::array<RootEntry, 5> kRootMap{
        RootEntry{ L"HKEY_CLASSES_ROOT", L"HKCR", HKEY_CLASSES_ROOT },
        RootEntry{ L"HKEY_CURRENT_USER", L"HKCU", HKEY_CURRENT_USER },
        RootEntry{ L"HKEY_LOCAL_MACHINE", L"HKLM", HKEY_LOCAL_MACHINE },
        RootEntry{ L"HKEY_USERS", L"HKU", HKEY_USERS },
        RootEntry{ L"HKEY_CURRENT_CONFIG", L"HKCC", HKEY_CURRENT_CONFIG }
    };

    // buildKernelRegistryPath：
    // - 作用：把 HK*/HKEY_* 形式转换为内核命名空间 \REGISTRY\...；
    // - 返回：可直接用于驱动/内核回调规则的路径文本。
    QString buildKernelRegistryPath(const QString& path)
    {
        return RegistryWorkbenchAccess::kernelPath(path);
    }

    // bytesToHex：把二进制输出为十六进制字符串。
    QString bytesToHex(const QByteArray& bytes, int maxCount)
    {
        QStringList parts;
        const int showCount = std::min<int>(maxCount, bytes.size());
        for (int i = 0; i < showCount; ++i)
        {
            parts << QStringLiteral("%1").arg(static_cast<unsigned char>(bytes.at(i)), 2, 16, QLatin1Char('0')).toUpper();
        }
        if (bytes.size() > showCount)
        {
            parts << QStringLiteral("...");
        }
        return parts.join(' ');
    }

    // formatNtStatus：把 R0 返回的 NTSTATUS 格式化成固定宽度十六进制。
    QString formatNtStatus(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(statusValue)), 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    // registryDataToByteArray：
    // - 作用：把 ArkDriverClient 的字节向量转换为 Qt 原始数据；
    // - 返回：QByteArray，空向量返回空数组。
    QByteArray registryDataToByteArray(const std::vector<std::uint8_t>& dataBytes)
    {
        if (dataBytes.empty())
        {
            return QByteArray();
        }
        return QByteArray(
            reinterpret_cast<const char*>(dataBytes.data()),
            static_cast<int>(dataBytes.size()));
    }

    // byteArrayToRegistryData：
    // - 作用：把 Qt 原始数据转换为 R0 协议需要的 std::vector<uint8_t>；
    // - 返回：逐字节复制后的向量。
    std::vector<std::uint8_t> byteArrayToRegistryData(const QByteArray& rawData)
    {
        if (rawData.isEmpty())
        {
            return {};
        }
        const auto* begin = reinterpret_cast<const std::uint8_t*>(rawData.constData());
        return std::vector<std::uint8_t>(begin, begin + rawData.size());
    }

    // registryIoFailureText：
    // - 作用：把 DeviceIoControl 层失败转换为用户可读文本；
    // - 返回：包含 Win32 错误、NTSTATUS 和 ArkDriverClient 详情。
    QString registryIoMessageText(const std::string& rawMessage)
    {
        // registryIoMessageText：
        // - 输入：ArkDriverClient 返回的原始 io.message；
        // - 处理：把 DeviceIoControl/unsupported/capability 等底层日志归一为中文说明；
        // - 返回：适合 QMessageBox 和状态文本展示的短句。
        const QString rawText = QString::fromStdString(rawMessage).trimmed();
        if (rawText.isEmpty())
        {
            return QStringLiteral("驱动未提供额外说明。");
        }
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动通信失败或 R3/R0 协议不匹配，请确认驱动已加载且版本一致。");
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动或协议暂不支持该注册表 R0 操作。");
        }
        if (rawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动能力或动态偏移未满足，无法完成该注册表 R0 操作。");
        }
        if (rawText.contains(QStringLiteral("version mismatch"), Qt::CaseInsensitive))
        {
            return QStringLiteral("R3/R0/shared 协议版本不一致，请同步后重试。");
        }
        return rawText;
    }

    QString registryIoFailureText(const QString& actionText, const ksword::ark::IoResult& ioResult)
    {
        return QStringLiteral("%1失败：驱动通信失败，Win32=%2，NTSTATUS=%3，详情=%4")
            .arg(actionText)
            .arg(ioResult.win32Error)
            .arg(formatNtStatus(ioResult.ntStatus))
            .arg(registryIoMessageText(ioResult.message));
    }

    // registryReadFailureText：
    // - 作用：把 R0 读取失败转换为统一错误文本；
    // - 返回：包含聚合状态和底层 Zw* 状态。
    QString registryReadFailureText(const QString& actionText, const ksword::ark::RegistryReadResult& result)
    {
        if (!result.io.ok)
        {
            return registryIoFailureText(actionText, result.io);
        }
        return QStringLiteral("%1失败：R0状态=%2，NTSTATUS=%3，详情=%4")
            .arg(actionText)
            .arg(result.status)
            .arg(formatNtStatus(result.lastStatus))
            .arg(registryIoMessageText(result.io.message));
    }

    // resolveTreeItemByPath：
    // - 作用：按注册表路径逐级在键树里定位节点，只查已存在的节点，不触发任何加载；
    // - 入参 treeWidget：键树控件；registryPath：完整注册表路径；
    // - 返回：命中的节点指针；路径上任一级缺失时返回 nullptr。
    //   后台结果回投时用路径而不是裸指针重新定位，可彻底避免节点已被销毁的悬垂访问。
    QTreeWidgetItem* resolveTreeItemByPath(QTreeWidget* treeWidget, const QString& registryPath)
    {
        if (treeWidget == nullptr)
        {
            return nullptr;
        }

        const QStringList segments = registryPath.split(QLatin1Char('\\'), Qt::SkipEmptyParts);
        if (segments.isEmpty())
        {
            return nullptr;
        }

        QTreeWidgetItem* currentItem = nullptr;
        for (int topLevelIndex = 0; topLevelIndex < treeWidget->topLevelItemCount(); ++topLevelIndex)
        {
            QTreeWidgetItem* candidateItem = treeWidget->topLevelItem(topLevelIndex);
            if (candidateItem != nullptr && candidateItem->text(0).compare(segments.first(), Qt::CaseInsensitive) == 0)
            {
                currentItem = candidateItem;
                break;
            }
        }
        if (currentItem == nullptr)
        {
            return nullptr;
        }

        for (int segmentIndex = 1; segmentIndex < segments.size(); ++segmentIndex)
        {
            QTreeWidgetItem* nextItem = nullptr;
            for (int childIndex = 0; childIndex < currentItem->childCount(); ++childIndex)
            {
                QTreeWidgetItem* childItem = currentItem->child(childIndex);
                if (childItem == nullptr || childItem->data(0, kRolePlaceholder).toBool())
                {
                    continue;
                }
                if (childItem->text(0).compare(segments.at(segmentIndex), Qt::CaseInsensitive) == 0)
                {
                    nextItem = childItem;
                    break;
                }
            }
            if (nextItem == nullptr)
            {
                return nullptr;
            }
            currentItem = nextItem;
        }

        return currentItem;
    }

    // appendSubKeyItemsBatched：
    // - 作用：把后台枚举出的子键名分批插入键树，每轮事件循环最多插入 kSubKeyItemBatchSize 个节点，
    //         避免一次性构造上万个 QTreeWidgetItem 触发同等数量的模型信号而冻结界面；
    // - 入参 guardedTree：键树弱引用；parentPath：目标父节点路径；requestToken：本次加载令牌；
    //         subKeyNames：共享的子键名列表；startIndex：本批起始下标；onFinished：全部插入完成后的 UI 线程回调；
    // - 返回：无。父节点已销毁或令牌已过期时直接放弃剩余插入。
    void appendSubKeyItemsBatched(
        const QPointer<QTreeWidget>& guardedTree,
        const QString& parentPath,
        const quint64 requestToken,
        const std::shared_ptr<const QStringList>& subKeyNames,
        const int startIndex,
        const std::function<void()>& onFinished)
    {
        if (guardedTree.isNull() || subKeyNames == nullptr)
        {
            return;
        }

        QTreeWidgetItem* parentItem = resolveTreeItemByPath(guardedTree.data(), parentPath);
        if (parentItem == nullptr)
        {
            return;
        }
        if (parentItem->data(0, kRoleLoadToken).toULongLong() != requestToken)
        {
            return;
        }

        const int totalCount = static_cast<int>(subKeyNames->size());
        const int endIndex = std::min(startIndex + kSubKeyItemBatchSize, totalCount);
        for (int nameIndex = startIndex; nameIndex < endIndex; ++nameIndex)
        {
            const QString& subKeyName = subKeyNames->at(nameIndex);
            QTreeWidgetItem* childItem = new QTreeWidgetItem(parentItem);
            childItem->setText(0, subKeyName);
            childItem->setData(0, kRolePath, parentPath + QStringLiteral("\\") + subKeyName);
            childItem->setData(0, kRoleLoaded, false);
            childItem->setData(0, kRolePlaceholder, false);
            childItem->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
            // 用展开指示器策略代替占位子项：省掉与子键等量的第二批 QTreeWidgetItem。
            childItem->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
        }

        if (endIndex < totalCount)
        {
            QTimer::singleShot(0, guardedTree.data(),
                [guardedTree, parentPath, requestToken, subKeyNames, endIndex, onFinished]()
                {
                    appendSubKeyItemsBatched(guardedTree, parentPath, requestToken, subKeyNames, endIndex, onFinished);
                });
            return;
        }

        parentItem->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
        parentItem->setData(0, kRoleLoaded, true);
        parentItem->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicatorWhenChildless);
        if (onFinished)
        {
            onFinished();
        }
    }

}

RegistryDock::RegistryDock(QWidget* parent)
    : QWidget(parent)
{
    {
        kLogEvent event;
        info << event << "[RegistryDock] 构造开始，准备初始化注册表模块。" << eol;
    }

    m_uiDispatcher = std::make_shared<ks::ui::AsyncUiDispatcher>(qApp);
    initializeUi();
    initializeWorkbenchControls();
    initializeConnections();
    initializeRootItems();
    navigateToPath(QStringLiteral("HKEY_CURRENT_USER"), true);

    {
        kLogEvent event;
        info << event << "[RegistryDock] 构造完成，默认定位到 HKEY_CURRENT_USER。" << eol;
    }
}

RegistryDock::~RegistryDock()
{
    kLogEvent event;
    info << event << "[RegistryDock] 析构开始，准备停止搜索线程。" << eol;

    m_operationsClosed->store(true);
    if (m_documentCancel) m_documentCancel->store(true);
    if (m_uiDispatcher) m_uiDispatcher->close();
    stopSearch(true);
    if (m_searchFlushTimer != nullptr)
    {
        m_searchFlushTimer->stop();
    }

    kLogEvent finishEvent;
    info << finishEvent << "[RegistryDock] 析构完成，后台资源已回收。" << eol;
}

void RegistryDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(4, 4, 4, 4);
    m_rootLayout->setSpacing(6);

    m_registryTabWidget = new QTabWidget(this);
    m_rootLayout->addWidget(m_registryTabWidget, 1);

    m_registryEditorPage = new QWidget(m_registryTabWidget);
    m_registryEditorLayout = new QVBoxLayout(m_registryEditorPage);
    m_registryEditorLayout->setContentsMargins(0, 0, 0, 0);
    m_registryEditorLayout->setSpacing(6);

    m_toolBarWidget = new QWidget(m_registryEditorPage);
    m_toolBarLayout = new QHBoxLayout(m_toolBarWidget);
    m_toolBarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolBarLayout->setSpacing(4);

    // 导航图标与文件管理器保持一致，统一“后退/前进”视觉语义。
    m_backButton = new QPushButton(QIcon(":/Icon/file_nav_back.svg"), QString(), m_toolBarWidget);
    m_forwardButton = new QPushButton(QIcon(":/Icon/file_nav_forward.svg"), QString(), m_toolBarWidget);
    m_refreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_toolBarWidget);
    m_newKeyButton = new QPushButton(QIcon(":/Icon/process_open_folder.svg"), QString(), m_toolBarWidget);
    m_newValueButton = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), m_toolBarWidget);
    m_renameButton = new QPushButton(QIcon(":/Icon/process_priority.svg"), QString(), m_toolBarWidget);
    m_deleteButton = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), m_toolBarWidget);
    m_importButton = new QPushButton(QIcon(":/Icon/reg_import.svg"), QString(), m_toolBarWidget);
    m_exportButton = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), m_toolBarWidget);
    m_searchButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), m_toolBarWidget);
    m_stopSearchButton = new QPushButton(QIcon(":/Icon/process_pause.svg"), QString(), m_toolBarWidget);

    m_backButton->setToolTip(QStringLiteral("后退"));
    m_forwardButton->setToolTip(QStringLiteral("前进"));
    m_refreshButton->setToolTip(QStringLiteral("刷新"));
    m_newKeyButton->setToolTip(QStringLiteral("新建子键"));
    m_newValueButton->setToolTip(QStringLiteral("新建值"));
    m_renameButton->setToolTip(QStringLiteral("重命名"));
    m_deleteButton->setToolTip(QStringLiteral("删除"));
    m_importButton->setToolTip(QStringLiteral("导入 .reg"));
    m_exportButton->setToolTip(QStringLiteral("导出 .reg"));
    m_searchButton->setToolTip(QStringLiteral("开始搜索"));
    m_stopSearchButton->setToolTip(QStringLiteral("停止搜索"));

    for (QPushButton* button : { m_backButton, m_forwardButton, m_refreshButton, m_newKeyButton, m_newValueButton,
            m_renameButton, m_deleteButton, m_importButton, m_exportButton, m_searchButton, m_stopSearchButton })
    {
        button->setStyleSheet(blueButtonStyle());
        KswordTheme::ApplyCompactIconButtonMetrics(button);
    }

    m_pathEdit = new QLineEdit(m_toolBarWidget);
    m_pathEdit->setStyleSheet(blueInputStyle());
    m_pathEdit->setPlaceholderText(QStringLiteral("输入路径后回车，例如 HKEY_LOCAL_MACHINE\\SOFTWARE"));

    m_driverRegistryModeLabel = new QLabel(m_toolBarWidget);
    m_driverRegistryModeLabel->setMinimumWidth(118);
    m_driverRegistryModeLabel->setAlignment(Qt::AlignCenter);
    m_driverRegistryModeLabel->setToolTip(QStringLiteral("驱动可用时启用增强的注册表浏览与编辑。"));

    m_searchEdit = new QLineEdit(m_toolBarWidget);
    m_searchEdit->setStyleSheet(blueInputStyle());
    m_searchEdit->setPlaceholderText(QStringLiteral("搜索键/值/数据"));
    m_searchEdit->setMaximumWidth(320);

    m_toolBarLayout->addWidget(m_backButton);
    m_toolBarLayout->addWidget(m_forwardButton);
    m_toolBarLayout->addWidget(m_refreshButton);
    m_toolBarLayout->addWidget(m_newKeyButton);
    m_toolBarLayout->addWidget(m_newValueButton);
    m_toolBarLayout->addWidget(m_renameButton);
    m_toolBarLayout->addWidget(m_deleteButton);
    m_toolBarLayout->addWidget(m_importButton);
    m_toolBarLayout->addWidget(m_exportButton);
    m_toolBarLayout->addWidget(m_pathEdit, 1);
    m_toolBarLayout->addWidget(m_driverRegistryModeLabel, 0);
    m_toolBarLayout->addWidget(m_searchEdit, 0);
    m_toolBarLayout->addWidget(m_searchButton);
    m_toolBarLayout->addWidget(m_stopSearchButton);

    m_registryEditorLayout->addWidget(m_toolBarWidget, 0);

    m_mainSplitter = new QSplitter(Qt::Horizontal, m_registryEditorPage);
    m_registryEditorLayout->addWidget(m_mainSplitter, 1);

    m_keyTree = new QTreeWidget(m_mainSplitter);
    m_keyTree->setColumnCount(1);
    m_keyTree->setHeaderLabel(QStringLiteral("注册表键"));
    m_keyTree->header()->setStyleSheet(blueHeaderStyle());
    m_keyTree->setContextMenuPolicy(Qt::CustomContextMenu);
    m_keyTree->setMinimumWidth(360);

    m_rightTabWidget = new QTabWidget(m_mainSplitter);

    m_valueTable = new ks::ui::VisibleTableWidget(m_rightTabWidget);
    m_valueTable->setColumnCount(3);
    m_valueTable->setHorizontalHeaderLabels(QStringList{ QStringLiteral("名称"), QStringLiteral("类型"), QStringLiteral("数据") });
    m_valueTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_valueTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_valueTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // 关闭角按钮，避免左上角出现默认白色单元格。
    m_valueTable->setCornerButtonEnabled(false);
    m_valueTable->setAlternatingRowColors(true);
    m_valueTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_valueTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    m_valueTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_valueTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_valueTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    m_searchResultTable = new ks::ui::VisibleTableWidget(m_rightTabWidget);
    m_searchResultTable->setColumnCount(5);
    m_searchResultTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("键路径"), QStringLiteral("值名"), QStringLiteral("类型"), QStringLiteral("数据预览"), QStringLiteral("命中来源")
        });
    m_searchResultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_searchResultTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_searchResultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_searchResultTable->setCornerButtonEnabled(false);
    m_searchResultTable->setAlternatingRowColors(true);
    m_searchResultTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_searchResultTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    m_searchResultTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_searchResultTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_searchResultTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_searchResultTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_searchResultTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);

    m_rightTabWidget->addTab(m_valueTable, QStringLiteral("值列表"));
    m_rightTabWidget->addTab(m_searchResultTable, QStringLiteral("搜索结果"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_rightTabWidget, m_valueTable, QStringLiteral("registry.tab.values"), QStringLiteral("值列表"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_rightTabWidget, m_searchResultTable, QStringLiteral("registry.tab.search_results"), QStringLiteral("搜索结果"));

    m_mainSplitter->setStretchFactor(0, 1);
    m_mainSplitter->setStretchFactor(1, 2);

    m_statusBar = new QStatusBar(m_registryEditorPage);
    m_pathStatusLabel = new QLabel(QStringLiteral("路径: -"), m_statusBar);
    m_summaryStatusLabel = new QLabel(QStringLiteral("状态: 就绪"), m_statusBar);
    m_pathStatusLabel->setTextFormat(Qt::PlainText);
    m_summaryStatusLabel->setTextFormat(Qt::PlainText);
    m_statusBar->addWidget(m_pathStatusLabel, 1);
    m_statusBar->addPermanentWidget(m_summaryStatusLabel, 0);
    m_registryEditorLayout->addWidget(m_statusBar, 0);

    m_searchFlushTimer = new QTimer(this);
    m_searchFlushTimer->setInterval(100);
    m_stopSearchButton->setEnabled(false);
    refreshRegistryDriverModeIndicator();

    m_optimizationPage = new RegistryOptimizationPage(m_registryTabWidget);
    m_registryTabWidget->addTab(m_registryEditorPage, QStringLiteral("注册表编辑"));
    m_registryTabWidget->addTab(m_optimizationPage, QStringLiteral("系统优化"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_registryTabWidget, m_registryEditorPage, QStringLiteral("registry.tab.editor"), QStringLiteral("注册表编辑"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_registryTabWidget, m_optimizationPage, QStringLiteral("registry.tab.optimization"), QStringLiteral("系统优化"));
}

void RegistryDock::initializeConnections()
{
    connect(m_backButton, &QPushButton::clicked, this, [this]() {
        if (m_navigationIndex <= 0 || m_navigationHistory.empty()) return;
        m_navigationIndex -= 1;
        navigateToPath(m_navigationHistory[static_cast<std::size_t>(m_navigationIndex)], false);
    });

    connect(m_forwardButton, &QPushButton::clicked, this, [this]() {
        if (m_navigationHistory.empty()) return;
        const int nextIndex = m_navigationIndex + 1;
        if (nextIndex < 0 || nextIndex >= static_cast<int>(m_navigationHistory.size())) return;
        m_navigationIndex = nextIndex;
        navigateToPath(m_navigationHistory[static_cast<std::size_t>(m_navigationIndex)], false);
    });

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshCurrentKey(true); });
    connect(m_pathEdit, &QLineEdit::returnPressed, this, [this]() { navigateToPath(m_pathEdit->text(), true); });

    connect(m_keyTree, &QTreeWidget::itemClicked, this, [this]() { m_valuesActive = false; });
    connect(m_valueTable, &QTableWidget::itemClicked, this, [this]() { m_valuesActive = true; });
    connect(m_keyTree, &QTreeWidget::itemExpanded, this, [this](QTreeWidgetItem* item) { ensureTreeItemLoaded(item); });
    connect(m_keyTree, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* item, QTreeWidgetItem*) {
        if (item == nullptr || item->data(0, kRolePlaceholder).toBool()) return;
        const QString path = item->data(0, kRolePath).toString();
        if (!path.isEmpty() && path.compare(m_currentPath, Qt::CaseInsensitive) != 0) navigateToPath(path, true);
    });

    connect(m_keyTree, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& pos) { showTreeContextMenu(pos); });
    connect(m_valueTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) { showValueContextMenu(pos); });
    connect(m_valueTable, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem*) { editSelectedValue(); });

    connect(m_newKeyButton, &QPushButton::clicked, this, [this]() { createSubKey(); });
    connect(m_newValueButton, &QPushButton::clicked, this, [this]() { createValue(); });
    connect(m_renameButton, &QPushButton::clicked, this, [this]() { renameSelectedObject(); });
    connect(m_deleteButton, &QPushButton::clicked, this, [this]() { deleteSelectedObject(); });
    connect(m_importButton, &QPushButton::clicked, this, [this]() { importRegFileAsync(); });
    connect(m_exportButton, &QPushButton::clicked, this, [this]() { exportCurrentKeyAsync(); });
    connect(m_searchButton, &QPushButton::clicked, this, [this]() { startSearchAsync(); });
    connect(m_stopSearchButton, &QPushButton::clicked, this, [this]() { stopSearch(false); });
    connect(m_searchEdit, &QLineEdit::returnPressed, this, [this]() { startSearchAsync(); });
    connect(m_searchFlushTimer, &QTimer::timeout, this, [this]() { flushPendingSearchRows(); });

    connect(m_searchResultTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        // 搜索结果菜单：
        // - 输入：用户在搜索结果表中的右键位置；
        // - 处理：同步当前行，支持复制；值命中还可按行保存的原始目标删除值。
        // - 返回：无；删除走既有 R0 优先 / R3 回退路径。
        const QModelIndex hit = m_searchResultTable->indexAt(pos);
        if (hit.isValid()) m_searchResultTable->setCurrentCell(hit.row(), hit.column());

        const int row = m_searchResultTable->currentRow();
        const QTableWidgetItem* pathItem = row >= 0 ? m_searchResultTable->item(row, 0) : nullptr;
        const QTableWidgetItem* valueNameItem = row >= 0 ? m_searchResultTable->item(row, 1) : nullptr;
        const bool isKeyResult = pathItem != nullptr
            && pathItem->data(kSearchResultRoleTargetKind).toInt() == kSearchResultTargetKey;
        const bool isValueResult = pathItem != nullptr
            && pathItem->data(kSearchResultRoleTargetKind).toInt() == kSearchResultTargetValue;

        // 菜单嵌套事件循环之前冻结原始行与上下文，不在返回后使用裸 item。
        const QString targetPath = pathItem ? pathItem->text() : QString();
        const QString rawName = valueNameItem ? valueNameItem->data(kSearchResultRoleRawValueName).toString() : QString();
        const RegistryAccessContext context{pathItem ? pathItem->data(kSearchResultRoleViewBits).toInt() : m_viewBits,
            pathItem ? pathItem->data(kSearchResultRoleUseR0).toBool() : false};
        QStringList fields;
        for (int column = 0; column < m_searchResultTable->columnCount(); ++column)
        {
            const auto* cell = row >= 0 ? m_searchResultTable->item(row, column) : nullptr;
            fields.push_back(cell ? cell->text() : QString());
        }
        const QPointer<RegistryDock> guarded(this);
        QMenu menu(this);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        QAction* copyRowAction = menu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制当前行"));
        copyRowAction->setEnabled(row >= 0);
        QAction* deleteValueAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除该值"));
        deleteValueAction->setEnabled(isValueResult && valueNameItem != nullptr);
        QAction* deleteKeyAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除该键（含子项）"));
        deleteKeyAction->setEnabled(isKeyResult);

        const QAction* action = menu.exec(m_searchResultTable->viewport()->mapToGlobal(pos));
        if (!guarded) return;
        if (action == deleteKeyAction && isKeyResult)
        {
            deleteSearchResultKey(targetPath, &context);
            return;
        }
        if (action == deleteValueAction && isValueResult)
        {
            deleteSearchResultValue(targetPath, rawName, &context);
            return;
        }
        if (action == copyRowAction)
        {
            if (auto* clipboard = QApplication::clipboard()) clipboard->setText(fields.join(QLatin1Char('\t')));
        }
    });

    connect(m_searchResultTable, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* item) {
        if (item == nullptr) return;
        QTableWidgetItem* pathItem = m_searchResultTable->item(item->row(), 0);
        if (pathItem == nullptr) return;
        navigateToPath(pathItem->text(), true);
        m_rightTabWidget->setCurrentWidget(m_valueTable);
    });
}

void RegistryDock::initializeRootItems()
{
    m_keyTree->clear();
    for (const RootEntry& entry : kRootMap)
    {
        QTreeWidgetItem* item = new QTreeWidgetItem(m_keyTree);
        item->setText(0, QString::fromWCharArray(entry.fullName));
        item->setData(0, kRolePath, QString::fromWCharArray(entry.fullName));
        item->setData(0, kRoleLoaded, false);
        item->setData(0, kRolePlaceholder, false);
        item->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
        // 根键一定可展开：用指示器策略代替占位子项，展开时才异步枚举真实子键。
        item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
    }
}
bool RegistryDock::parseRegistryPath(const QString& pathText, HKEY* rootKeyOut, QString* subPathOut)
{
    if (rootKeyOut == nullptr || subPathOut == nullptr) return false;

    QString text = pathText;
    const QString userRoot = RegistryWorkbenchAccess::kernelPath(QStringLiteral("HKEY_CURRENT_USER"));
    auto replaceRoot = [&text](const QString& native, const QString& display) {
        if (text.compare(native, Qt::CaseInsensitive) == 0) text = display;
        else if (text.startsWith(native + QLatin1Char('\\'), Qt::CaseInsensitive)) text = display + text.mid(native.size());
    };
    if (!userRoot.isEmpty()) replaceRoot(userRoot, QStringLiteral("HKEY_CURRENT_USER"));
    replaceRoot(QStringLiteral("\\REGISTRY\\MACHINE"), QStringLiteral("HKEY_LOCAL_MACHINE"));
    replaceRoot(QStringLiteral("\\REGISTRY\\USER"), QStringLiteral("HKEY_USERS"));
    while (text.contains(QStringLiteral("\\\\"))) text.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
    if (text.endsWith('\\')) text.chop(1);
    if (text.isEmpty()) return false;

    const int split = text.indexOf('\\');
    const QString rootText = split < 0 ? text : text.left(split);
    const QString subPath = split < 0 ? QString() : text.mid(split + 1);

    for (const RootEntry& entry : kRootMap)
    {
        const QString full = QString::fromWCharArray(entry.fullName);
        const QString shortName = QString::fromWCharArray(entry.shortName);
        if (rootText.compare(full, Qt::CaseInsensitive) == 0 || rootText.compare(shortName, Qt::CaseInsensitive) == 0)
        {
            *rootKeyOut = entry.root;
            *subPathOut = subPath;
            return true;
        }
    }
    return false;
}

QString RegistryDock::normalizeRegistryPath(const QString& pathText)
{
    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(pathText, &root, &subPath)) return QString();
    QString output = rootKeyToText(root);
    if (!subPath.isEmpty()) output += QStringLiteral("\\") + subPath;
    return output;
}

QString RegistryDock::rootKeyToText(HKEY rootKey)
{
    for (const RootEntry& entry : kRootMap)
    {
        if (entry.root == rootKey) return QString::fromWCharArray(entry.fullName);
    }
    return QStringLiteral("<Unknown>");
}

void RegistryDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if ((event->type() != QEvent::ApplicationPaletteChange && event->type() != QEvent::PaletteChange) || !m_pathEdit) return;
    // Qt caches the palette used by a locally styled widget. Rebuild those
    // small local styles after a global theme change so contrast stays valid.
    const auto rebuild = [](QWidget* widget, const QString& style) {
        widget->setStyleSheet(QString());
        widget->setPalette(QApplication::palette());
        widget->setStyleSheet(style);
    };
    rebuild(m_pathEdit, blueInputStyle());
    rebuild(m_searchEdit, blueInputStyle());
    for (auto* button : {m_backButton, m_forwardButton, m_refreshButton, m_newKeyButton,
        m_newValueButton, m_renameButton, m_deleteButton, m_importButton, m_exportButton,
        m_searchButton, m_stopSearchButton}) rebuild(button, blueButtonStyle());
    rebuild(m_keyTree->header(), blueHeaderStyle());
    rebuild(m_valueTable->horizontalHeader(), blueHeaderStyle());
    rebuild(m_searchResultTable->horizontalHeader(), blueHeaderStyle());
}

QString RegistryDock::valueTypeToText(DWORD type)
{
    switch (type)
    {
    case REG_NONE: return QStringLiteral("REG_NONE");
    case REG_SZ: return QStringLiteral("REG_SZ");
    case REG_EXPAND_SZ: return QStringLiteral("REG_EXPAND_SZ");
    case REG_BINARY: return QStringLiteral("REG_BINARY");
    case REG_DWORD: return QStringLiteral("REG_DWORD");
    case REG_MULTI_SZ: return QStringLiteral("REG_MULTI_SZ");
    case REG_QWORD: return QStringLiteral("REG_QWORD");
    default: return QStringLiteral("REG_%1").arg(type);
    }
}

QString RegistryDock::formatValueData(DWORD type, const QByteArray& data)
{
    if (data.isEmpty()) return QStringLiteral("<empty>");
    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ)
    {
        const qsizetype units = qMin<qsizetype>(data.size() / 2, 256);
        QString preview = QString::fromUtf16(reinterpret_cast<const char16_t*>(data.constData()), units);
        if (type == REG_MULTI_SZ) preview.replace(QChar::Null, QStringLiteral(" | "));
        else preview.remove(QChar::Null);
        preview.replace(QLatin1Char('\n'), QStringLiteral("\\n"));
        preview.replace(QLatin1Char('\r'), QStringLiteral("\\r"));
        if (data.size() > 512) preview += QStringLiteral("…");
        return preview;
    }
    if ((type == REG_DWORD && data.size() == 4) || (type == REG_QWORD && data.size() == 8))
    {
        quint64 number = 0;
        for (qsizetype i = 0; i < data.size(); ++i) number |= static_cast<quint64>(static_cast<unsigned char>(data.at(i))) << (i * 8);
        return QStringLiteral("0x%1 (%2)").arg(number, type == REG_DWORD ? 8 : 16, 16, QLatin1Char('0')).arg(number);
    }
    return bytesToHex(data, 64);
}

QString RegistryDock::winErrorText(LONG code)
{
    wchar_t* buffer = nullptr;
    const DWORD size = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(code),
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    QString text = QStringLiteral("错误码 %1").arg(code);
    if (size > 0 && buffer != nullptr)
    {
        text += QStringLiteral(": ") + QString::fromWCharArray(buffer, static_cast<int>(size)).trimmed();
    }
    if (buffer != nullptr) ::LocalFree(buffer);
    return text;
}

void RegistryDock::refreshRegistryDriverModeIndicator()
{
    if (!m_driverRegistryModeLabel) return;
    const bool r0 = accessContext().useR0;
    m_driverRegistryModeLabel->setText(r0 ? QStringLiteral("R0 / 本机视图")
        : m_viewBits == 32 ? QStringLiteral("Win32 / 32 位视图")
        : m_viewBits == 64 ? QStringLiteral("Win32 / 64 位视图") : QStringLiteral("Win32 / 本机视图"));
    m_driverRegistryModeLabel->setToolTip(r0
        ? QStringLiteral("当前通过驱动访问；超出协议容量会明确拒绝。")
        : QStringLiteral("显式视图与 HKCR 合并视图使用 Win32；操作失败不会切换通道。"));
}

bool RegistryDock::shouldUseRegistryR0() const
{
    if (m_viewBits != 0) return false;
    const ksword::ark::DriverClient client;
    return client.open(GENERIC_READ | GENERIC_WRITE).isValid();
}

void RegistryDock::updateStatusBar(const QString& message)
{
    m_pathStatusLabel->setProperty("ks_i18n_preserve_data_text", true);
    m_pathStatusLabel->setText(m_currentPath);
    m_pathStatusLabel->setToolTip(m_currentPath);
    m_summaryStatusLabel->setText(ks::i18n::packedSourceText(message));
    m_summaryStatusLabel->setToolTip(m_summaryStatusLabel->text());
}

void RegistryDock::navigateToPath(const QString& path, bool recordHistory)
{
    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 导航请求, input="
            << path.toStdString()
            << ", recordHistory="
            << (recordHistory ? "true" : "false")
            << eol;
    }

    const QString normalized = normalizeRegistryPath(path);
    if (normalized.isEmpty())
    {
        kLogEvent event;
        warn << event << "[RegistryDock] 导航失败：无效路径, input=" << path.toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("注册表"), QStringLiteral("无效路径：%1").arg(path));
        return;
    }

    if (!preserveEditorDraft())
    {
        selectTreeItemByPath(m_currentPath);
        if (m_locationTabs) { QSignalBlocker blocked(m_locationTabs); m_locationTabs->setCurrentIndex(m_activeLocationIndex); }
        return;
    }
    m_activeLocationIndex = m_locationTabs ? m_locationTabs->currentIndex() : 0;
    ++m_editorGeneration;
    m_editorReady = false;
    m_valueEditor->hide();
    m_currentPath = normalized;
    m_pathEdit->setText(normalized);
    if (m_locationTabs && m_locationTabs->currentIndex() >= 0)
    {
        const int tab = m_locationTabs->currentIndex();
        const int slash = normalized.lastIndexOf('\\');
        m_locationTabs->setTabText(tab, slash < 0 ? normalized : normalized.mid(slash + 1));
        m_locationTabs->setTabData(tab, normalized);
        m_locationTabs->setTabToolTip(tab, normalized);
    }

    if (recordHistory)
    {
        if (m_navigationIndex + 1 < static_cast<int>(m_navigationHistory.size()))
        {
            m_navigationHistory.erase(m_navigationHistory.begin() + m_navigationIndex + 1, m_navigationHistory.end());
        }
        if (m_navigationHistory.empty() || m_navigationHistory.back().compare(normalized, Qt::CaseInsensitive) != 0)
        {
            m_navigationHistory.push_back(normalized);
        }
        m_navigationIndex = static_cast<int>(m_navigationHistory.size()) - 1;
    }

    if (m_navigationHistory.size() > 100) m_navigationHistory.erase(m_navigationHistory.begin(), m_navigationHistory.end() - 100);
    m_navigationIndex = std::min(m_navigationIndex, static_cast<int>(m_navigationHistory.size()) - 1);
    QStringList completions = m_favoritePaths;
    for (const auto& item : m_navigationHistory) if (!completions.contains(item)) completions.append(item);
    if (m_pathEdit->completer()) delete m_pathEdit->completer();
    auto* completer = new QCompleter(completions, m_pathEdit);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    m_pathEdit->setCompleter(completer);
    m_backButton->setEnabled(m_navigationIndex > 0);
    m_forwardButton->setEnabled(m_navigationIndex >= 0 && (m_navigationIndex + 1) < static_cast<int>(m_navigationHistory.size()));
    refreshRegistryDriverModeIndicator();

    selectTreeItemByPath(normalized);
    refreshCurrentKey(true);

    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 导航成功, normalized="
            << normalized.toStdString()
            << ", historySize="
            << m_navigationHistory.size()
            << ", historyIndex="
            << m_navigationIndex
            << eol;
    }
}

void RegistryDock::selectTreeItemByPath(const QString& path)
{
    const QString normalized = normalizeRegistryPath(path);
    if (normalized.isEmpty()) return;

    const QStringList segments = normalized.split('\\', Qt::SkipEmptyParts);
    if (segments.isEmpty()) return;

    // 记录待定位路径：子键加载已改为异步，本次调用只能走到“已加载”的最深一级，
    // 剩余层级由后台枚举落地后的回调重新进入本函数继续下探。
    m_keyTree->setProperty(kPendingTreeSelectionProperty, normalized);

    QTreeWidgetItem* current = nullptr;
    for (int i = 0; i < m_keyTree->topLevelItemCount(); ++i)
    {
        QTreeWidgetItem* item = m_keyTree->topLevelItem(i);
        if (item->text(0).compare(segments.first(), Qt::CaseInsensitive) == 0)
        {
            current = item;
            break;
        }
    }
    if (current == nullptr)
    {
        m_keyTree->setProperty(kPendingTreeSelectionProperty, QString());
        return;
    }

    bool waitingForSubKeyLoad = false;
    for (int i = 1; i < segments.size(); ++i)
    {
        if (!current->data(0, kRoleLoaded).toBool())
        {
            // 该级还没有子键数据：投递一次后台枚举，本轮先停在这里。
            ensureTreeItemLoaded(current);
            waitingForSubKeyLoad = current->data(0, kRoleLoadToken).toULongLong() != 0;
            break;
        }

        QTreeWidgetItem* next = nullptr;
        for (int childIndex = 0; childIndex < current->childCount(); ++childIndex)
        {
            QTreeWidgetItem* child = current->child(childIndex);
            if (child == nullptr || child->data(0, kRolePlaceholder).toBool()) continue;
            if (child->text(0).compare(segments.at(i), Qt::CaseInsensitive) == 0)
            {
                next = child;
                break;
            }
        }
        if (next == nullptr) break;
        current = next;
    }

    if (!waitingForSubKeyLoad)
    {
        m_keyTree->setProperty(kPendingTreeSelectionProperty, QString());
    }

    QSignalBlocker blocker(m_keyTree);
    m_keyTree->setCurrentItem(current);
    m_keyTree->scrollToItem(current);
}

void RegistryDock::ensureTreeItemLoaded(QTreeWidgetItem* item)
{
    if (item == nullptr || item->data(0, kRolePlaceholder).toBool()) return;
    if (item->data(0, kRoleLoaded).toBool()) return;
    // 已有一次后台枚举在途：不重复投递，等它落地即可。
    if (item->data(0, kRoleLoadToken).toULongLong() != 0) return;

    const QString itemPath = item->data(0, kRolePath).toString();
    {
        kLogEvent event;
        dbg << event << "[RegistryDock] 展开节点并加载子键, path=" << itemPath.toStdString() << eol;
    }

    // 枚举入参在 UI 线程算好后按值带进后台线程：后台只做纯数据采集，不碰任何控件。
    const RegistryAccessContext context = accessContextForPath(itemPath);
    // 后台枚举期间保留一个占位子项，维持展开箭头并给出“正在加载”的视觉反馈。
    qDeleteAll(item->takeChildren());
    QTreeWidgetItem* loadingPlaceholder = new QTreeWidgetItem(item);
    loadingPlaceholder->setText(0, QStringLiteral("..."));
    loadingPlaceholder->setData(0, kRolePlaceholder, true);
    // 占位项不可选中：结果落地时它会被删除，避免删除当前项引发多余的导航。
    loadingPlaceholder->setFlags(Qt::ItemIsEnabled);

    const quint64 requestToken = g_nextSubKeyLoadToken.fetch_add(1, std::memory_order_relaxed);
    item->setData(0, kRoleLoadToken, static_cast<qulonglong>(requestToken));
    item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);

    const QPointer<RegistryDock> guardedSelf(this);
    const QPointer<QTreeWidget> guardedTree(m_keyTree);
    const auto dispatcher = m_uiDispatcher;
    QThreadPool::globalInstance()->start(
        [guardedSelf, guardedTree, dispatcher, requestToken, itemPath, context]()
        {
            RegistryKeyListing collected;
            QString error;
            const bool ok = RegistryWorkbenchAccess::enumerate(itemPath, context, &collected, &error, true);
            dispatcher->post(
                [guardedSelf, guardedTree, requestToken, itemPath, collected, error, ok]()
                {
                    if (guardedTree.isNull()) { return; }

                    // 用路径而不是裸指针重新定位：节点可能已在等待期间被销毁或重建。
                    QTreeWidgetItem* targetItem = resolveTreeItemByPath(guardedTree.data(), itemPath);
                    if (targetItem == nullptr) { return; }
                    if (targetItem->data(0, kRoleLoadToken).toULongLong() != requestToken) { return; }

                    qDeleteAll(targetItem->takeChildren());

                    if (!ok)
                    {
                        {
                            kLogEvent event;
                            warn << event
                                << "[RegistryDock] 加载子键失败, path="
                                << itemPath.toStdString()
                                << ", error="
                                << error.toStdString()
                                << eol;
                        }
                        targetItem->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
                        targetItem->setData(0, kRoleLoaded, true);
                        targetItem->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicatorWhenChildless);
                        return;
                    }

                    targetItem->setToolTip(0, collected.complete ? QString() : ks::i18n::packedSourceText(collected.warning));
                    if (!collected.complete && guardedSelf) guardedSelf->updateStatusBar(collected.warning);

                    const int loadedChildCount = static_cast<int>(collected.subKeys.size());
                    const std::shared_ptr<const QStringList> sharedSubKeyNames =
                        std::make_shared<const QStringList>(collected.subKeys);
                    const std::function<void()> onSubKeysApplied =
                        [guardedSelf, guardedTree, itemPath, loadedChildCount]()
                        {
                            {
                                kLogEvent event;
                                info << event
                                    << "[RegistryDock] 子键加载完成, path="
                                    << itemPath.toStdString()
                                    << ", childCount="
                                    << loadedChildCount
                                    << eol;
                            }

                            // 路径定位是逐级异步推进的：本级子键就位后继续下探待定位路径。
                            if (guardedSelf.isNull() || guardedTree.isNull()) { return; }
                            const QString pendingSelectionPath =
                                guardedTree->property(kPendingTreeSelectionProperty).toString();
                            if (pendingSelectionPath.isEmpty()) { return; }
                            guardedSelf->selectTreeItemByPath(pendingSelectionPath);
                        };

                    appendSubKeyItemsBatched(
                        guardedTree,
                        itemPath,
                        requestToken,
                        sharedSubKeyNames,
                        0,
                        onSubKeysApplied);
                });
        });
}

void RegistryDock::refreshCurrentKey(bool)
{
    if (!preserveEditorDraft()) return;
    refreshRegistryDriverModeIndicator();
    QTreeWidgetItem* current = m_keyTree->currentItem();
    if (current && current->data(0, kRolePath).toString() == m_currentPath)
    {
        QSignalBlocker blocked(m_keyTree);
        qDeleteAll(current->takeChildren());
        current->setData(0, kRoleLoaded, false);
        current->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
        ensureTreeItemLoaded(current);
    }
    refreshValueTable();
}

void RegistryDock::refreshValueTable()
{
    const QPointer<RegistryDock> menuGuard(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(this, QStringLiteral("registry-value-refresh"),
        {m_valueTable}, [menuGuard]() { if (menuGuard) menuGuard->refreshValueTable(); })) return;
    if (!preserveEditorDraft()) return;
    const auto* selected = m_valueTable->item(m_valueTable->currentRow(), 0);
    const QString selectedName = selected ? selected->data(Qt::UserRole).toString() : QString();
    const QString path = m_currentPath;
    const RegistryAccessContext context = accessContext();
    const quint64 generation = ++m_valueLoadGeneration;
    ++m_editorGeneration;
    m_editorReady = false;
    m_valueEditor->hide();
    { QSignalBlocker blocked(m_valueTable); m_valueTable->setRowCount(0); }
    updateStatusBar(QStringLiteral("正在读取值列表…"));
    const QPointer<RegistryDock> guarded(this);
    const auto dispatcher = m_uiDispatcher;
    QThreadPool::globalInstance()->start([guarded, dispatcher, path, context, selectedName, generation]() {
        auto listing = std::make_shared<RegistryKeyListing>();
        QString error;
        const bool ok = RegistryWorkbenchAccess::enumerate(path, context, listing.get(), &error, false);
        dispatcher->post([guarded, listing, path, context, selectedName, generation, error, ok]() {
            if (!guarded || guarded->m_valueLoadGeneration != generation || guarded->m_currentPath != path
                || guarded->m_viewBits != context.viewBits) return;
            if (!ok) { guarded->updateStatusBar(error); return; }
            guarded->appendValueRows(listing, 0, generation, selectedName);
        });
    });
}

void RegistryDock::showTreeContextMenu(const QPoint& pos)
{
    m_keyTree->setFocus();
    m_valuesActive = false;
    QTreeWidgetItem* item = m_keyTree->itemAt(pos);
    if (item != nullptr && !item->data(0, kRolePlaceholder).toBool()) m_keyTree->setCurrentItem(item);

    const QPointer<RegistryDock> guarded(this);
    const QString menuPath = m_currentPath; // 冻结菜单对象来源。
    const int menuView = m_viewBits;
    const quint64 menuGeneration = m_valueLoadGeneration;
    QMenu menu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* newKeyAction = menu.addAction(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("新建子键"));
    QAction* renameAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("重命名"));
    QAction* deleteAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除"));
    menu.addSeparator();
    QAction* copyPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制路径"));
    QAction* copyKernelPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制内核模式地址"));
    QAction* r0ReadDefaultAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("R0读取默认值"));
    QAction* refreshAction = menu.addAction(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新"));
    menu.addSeparator();
    QAction* exportAction = menu.addAction(QIcon(":/Icon/log_export.svg"), QStringLiteral("导出 .reg"));
    QAction* importAction = menu.addAction(QIcon(":/Icon/reg_import.svg"), QStringLiteral("导入 .reg"));

    QAction* action = menu.exec(m_keyTree->viewport()->mapToGlobal(pos));
    if (!guarded || action == nullptr) return;
    if (m_currentPath.compare(menuPath, Qt::CaseInsensitive) != 0
        || m_viewBits != menuView || m_valueLoadGeneration != menuGeneration) return;

    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 树右键动作, action="
            << action->text().toStdString()
            << ", currentPath="
            << m_currentPath.toStdString()
            << eol;
    }
    if (action == newKeyAction) createSubKey();
    else if (action == renameAction) renameSelectedObject();
    else if (action == deleteAction) deleteSelectedObject();
    else if (action == copyPathAction) copyCurrentPathToClipboard();
    else if (action == copyKernelPathAction) copyCurrentKernelPathToClipboard();
    else if (action == r0ReadDefaultAction) readDefaultValueByR0();
    else if (action == refreshAction) refreshCurrentKey(true);
    else if (action == exportAction) exportCurrentKeyAsync();
    else if (action == importAction) importRegFileAsync();
}

void RegistryDock::showValueContextMenu(const QPoint& pos)
{
    m_valueTable->setFocus();
    m_valuesActive = true;
    const QModelIndex hit = m_valueTable->indexAt(pos);
    if (hit.isValid()) m_valueTable->setCurrentCell(hit.row(), hit.column());

    const QPointer<RegistryDock> guarded(this);
    const QString menuPath = m_currentPath; // 冻结菜单对象来源。
    const int menuView = m_viewBits;
    const quint64 menuGeneration = m_valueLoadGeneration;
    QMenu menu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* editAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("修改"));
    QAction* newAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("新建值"));
    QAction* renameAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("重命名"));
    QAction* deleteAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除"));
    QAction* copyPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制路径"));
    QAction* copyKernelPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制内核模式地址"));
    QAction* r0ReadAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("R0读取该值"));
    r0ReadAction->setEnabled(accessContext().useR0);
    copyKernelPathAction->setEnabled(!buildKernelRegistryPath(m_currentPath).isEmpty());

    QAction* action = menu.exec(m_valueTable->viewport()->mapToGlobal(pos));
    if (!guarded || action == nullptr) return;
    if (m_currentPath.compare(menuPath, Qt::CaseInsensitive) != 0
        || m_viewBits != menuView || m_valueLoadGeneration != menuGeneration) return;

    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 值右键动作, action="
            << action->text().toStdString()
            << ", currentPath="
            << m_currentPath.toStdString()
            << eol;
    }
    if (action == editAction) editSelectedValue();
    else if (action == newAction) createValue();
    else if (action == renameAction) renameSelectedObject();
    else if (action == deleteAction) deleteSelectedObject();
    else if (action == copyPathAction) copyCurrentPathToClipboard();
    else if (action == copyKernelPathAction) copySelectedValueKernelPathToClipboard();
    else if (action == r0ReadAction) readSelectedValueByR0();
}

void RegistryDock::createValue()
{
    const QPointer<RegistryDock> guarded(this); // 草稿保存确认也可能销毁页面。
    if (m_applyingChanges || !preserveEditorDraft() || !guarded) return;
    const QString path = m_currentPath;
    const RegistryAccessContext context = accessContext();
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("新建注册表值"));
    auto* layout = new QVBoxLayout(&dialog);
    auto* scroll = new QScrollArea(&dialog);
    scroll->setWidgetResizable(true);
    auto* editor = new RegistryValueEditorWidget;
    editor->setValue(path, QString(), REG_SZ, QByteArray(2, '\0'), true);
    scroll->setWidget(editor);
    layout->addWidget(scroll, 1);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, &dialog);
    buttons->button(QDialogButtonBox::Save)->setText(QStringLiteral("暂存新值"));
    layout->addWidget(buttons);
    RegistryValueDraft draft;
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&]() {
        QString error;
        if (!editor->value(&draft, &error)) { QMessageBox::warning(&dialog, QStringLiteral("新建值"), error); return; }
        dialog.accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    ks::ui::applyResponsiveWindowGeometry(&dialog, this, QSize(820, 620), QSize(420, 320));
    // 模态返回后确认冻结目标未被切换。
    if (dialog.exec() != QDialog::Accepted || !guarded) return;
    if (m_currentPath.compare(path, Qt::CaseInsensitive) != 0 || m_viewBits != context.viewBits) return;
    RegistryValueState original;
    QString error;
    if (!RegistryWorkbenchAccess::read(path, draft.name, context, &original, &error))
    { QMessageBox::warning(this, QStringLiteral("新建值"), error); return; }
    if (original.exists)
    { QMessageBox::warning(this, QStringLiteral("新建值"), QStringLiteral("值已存在，请使用编辑入口。")); return; }
    PendingValueChange change;
    change.keyPath = path; change.name = draft.name;
    change.afterType = draft.type; change.afterData = draft.data;
    change.viewBits = context.viewBits; change.useR0 = context.useR0;
    qsizetype existingIndex = -1;
    qsizetype bytes = change.afterData.size();
    for (qsizetype i = 0; i < m_pendingChanges.size(); ++i)
    {
        const auto& pending = m_pendingChanges.at(i);
        if (pending.keyPath.compare(path, Qt::CaseInsensitive) == 0 && pending.name.compare(change.name, Qt::CaseInsensitive) == 0
            && pending.viewBits == context.viewBits && pending.useR0 == context.useR0) existingIndex = i;
        else bytes += pending.beforeData.size() + pending.afterData.size();
    }
    if ((existingIndex < 0 && m_pendingChanges.size() >= 1024) || bytes > 64 * 1024 * 1024)
    { QMessageBox::warning(this, QStringLiteral("新建值"), QStringLiteral("暂存达到容量上限，请先应用或清空。")); return; }
    if (existingIndex >= 0) m_pendingChanges[existingIndex] = change;
    else m_pendingChanges.push_back(change);
    updatePendingChanges();
    m_rightTabWidget->setCurrentIndex(2);
}

void RegistryDock::deleteSelectedObject()
{
    if (m_applyingChanges || !preserveEditorDraft()) return;
    if (!m_valuesActive || m_keyTree->hasFocus()) { deleteSearchResultKey(m_currentPath); return; }
    const auto* name = m_valueTable->item(m_valueTable->currentRow(), 0);
    if (name) deleteSearchResultValue(m_currentPath, name->data(Qt::UserRole).toString());
}

void RegistryDock::deleteSearchResultValue(const QString& inputPath, const QString& inputName,
    const RegistryAccessContext* capturedContext)
{
    const QPointer<RegistryDock> guarded(this); // 交互前复制可能借用成员/行的参数。
    const QString path = inputPath;
    const QString name = inputName;
    const RegistryAccessContext context = capturedContext ? *capturedContext : accessContextForPath(path);
    if (m_applyingChanges || !preserveEditorDraft() || !guarded) return;
    RegistryValueState original;
    QString error;
    if (!RegistryWorkbenchAccess::read(path, name, context, &original, &error) || !original.exists || !original.complete)
    { QMessageBox::warning(this, QStringLiteral("删除值"), error.isEmpty() ? QStringLiteral("原值不存在或数据不完整。") : error); return; }
    PendingValueChange change;
    change.keyPath = path; change.name = name; change.beforeExists = true;
    change.beforeType = original.type; change.beforeData = original.data; change.deleteValue = true;
    change.viewBits = context.viewBits; change.useR0 = context.useR0;
    qsizetype existing = -1;
    for (qsizetype i = 0; i < m_pendingChanges.size(); ++i)
        if (m_pendingChanges.at(i).keyPath.compare(path, Qt::CaseInsensitive) == 0
            && m_pendingChanges.at(i).name.compare(name, Qt::CaseInsensitive) == 0
            && m_pendingChanges.at(i).viewBits == context.viewBits && m_pendingChanges.at(i).useR0 == context.useR0)
        { existing = i; break; }
    if (existing >= 0)
    {
        if (!m_pendingChanges.at(existing).beforeExists) { m_pendingChanges.removeAt(existing); updatePendingChanges(); return; }
        change.beforeType = m_pendingChanges.at(existing).beforeType;
        change.beforeData = m_pendingChanges.at(existing).beforeData;
        m_pendingChanges[existing] = change;
    }
    else
    {
        qsizetype bytes = change.beforeData.size();
        for (const auto& item : m_pendingChanges) bytes += item.beforeData.size() + item.afterData.size();
        if (m_pendingChanges.size() >= 1024 || bytes > 64 * 1024 * 1024)
        { QMessageBox::warning(this, QStringLiteral("删除值"), QStringLiteral("暂存达到容量上限，请先应用或清空。")); return; }
        m_pendingChanges.push_back(change);
    }
    updatePendingChanges();
    m_rightTabWidget->setCurrentIndex(2);
}

void RegistryDock::editSelectedValue()
{
    const QPointer<RegistryDock> guarded(this); // 草稿保存确认也可能销毁页面。
    if (m_applyingChanges || !preserveEditorDraft() || !guarded) return;
    const auto* nameItem = m_valueTable->item(m_valueTable->currentRow(), 0);
    if (!nameItem) return;
    const QString path = m_currentPath;
    const QString name = nameItem->data(Qt::UserRole).toString();
    const RegistryAccessContext context = accessContext();
    RegistryValueState original;
    QString error;
    if (!RegistryWorkbenchAccess::read(path, name, context, &original, &error) || !original.exists || !original.complete)
    { QMessageBox::warning(this, QStringLiteral("编辑值"), error.isEmpty() ? QStringLiteral("原始数据不完整，无法编辑。") : error); return; }
    RegistryValueState shown = original;
    for (const auto& change : m_pendingChanges)
        if (change.keyPath.compare(path, Qt::CaseInsensitive) == 0 && change.name.compare(name, Qt::CaseInsensitive) == 0
            && change.viewBits == context.viewBits && change.useR0 == context.useR0 && !change.deleteValue)
        { shown.type = change.afterType; shown.data = change.afterData; break; }
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("编辑注册表值"));
    auto* layout = new QVBoxLayout(&dialog);
    auto* scroll = new QScrollArea(&dialog);
    scroll->setWidgetResizable(true);
    auto* editor = new RegistryValueEditorWidget;
    editor->setValue(path, name, shown.type, shown.data);
    scroll->setWidget(editor);
    layout->addWidget(scroll, 1);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, &dialog);
    buttons->button(QDialogButtonBox::Save)->setText(QStringLiteral("暂存修改"));
    layout->addWidget(buttons);
    RegistryValueDraft draft;
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&]() {
        QString validation;
        if (!editor->value(&draft, &validation)) { QMessageBox::warning(&dialog, QStringLiteral("编辑值"), validation); return; }
        dialog.accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    ks::ui::applyResponsiveWindowGeometry(&dialog, this, QSize(900, 680), QSize(420, 320));
    // 换键不能把旧草稿安装到新来源。
    if (dialog.exec() != QDialog::Accepted || !guarded) return;
    if (m_currentPath.compare(path, Qt::CaseInsensitive) != 0 || m_viewBits != context.viewBits) return;
    m_editorPath = path; m_editorName = name; m_editorOriginalType = original.type; m_editorOriginalData = original.data;
    m_editorViewBits = context.viewBits; m_editorUseR0 = context.useR0;
    m_valueEditor->setValue(path, name, draft.type, draft.data);
    m_editorReady = true;
    m_valueEditor->show();
    stageEditorValue();
}

void RegistryDock::copyCurrentPathToClipboard()
{
    QApplication::clipboard()->setText(m_currentPath);

    kLogEvent event;
    info << event << "[RegistryDock] 复制路径到剪贴板, path=" << m_currentPath.toStdString() << eol;
}

void RegistryDock::copyCurrentKernelPathToClipboard()
{
    const QString kernelPath = buildKernelRegistryPath(m_currentPath);
    if (kernelPath.isEmpty())
    {
        return;
    }

    QApplication::clipboard()->setText(kernelPath);

    kLogEvent event;
    info << event
        << "[RegistryDock] 复制内核模式地址到剪贴板, path="
        << m_currentPath.toStdString()
        << ", kernelPath="
        << kernelPath.toStdString()
        << eol;
}

void RegistryDock::copySelectedValueKernelPathToClipboard()
{
    QString targetPath = m_currentPath;
    const int selectedRow = m_valueTable->currentRow();
    if (selectedRow >= 0)
    {
        QTableWidgetItem* valueNameItem = m_valueTable->item(selectedRow, 0);
        if (valueNameItem != nullptr)
        {
            const QString valueName = valueNameItem->data(Qt::UserRole).toString();
            if (!valueName.isEmpty())
            {
                targetPath += QStringLiteral("\\") + valueName;
            }
        }
    }

    const QString kernelPath = buildKernelRegistryPath(targetPath);
    if (kernelPath.isEmpty())
    {
        return;
    }

    QApplication::clipboard()->setText(kernelPath);

    kLogEvent event;
    info << event
        << "[RegistryDock] 复制值内核模式地址到剪贴板, path="
        << targetPath.toStdString()
        << ", kernelPath="
        << kernelPath.toStdString()
        << eol;
}

void RegistryDock::readSelectedValueByR0()
{
    const int selectedRow = m_valueTable->currentRow();
    QString valueName;
    if (selectedRow >= 0)
    {
        QTableWidgetItem* valueNameItem = m_valueTable->item(selectedRow, 0);
        if (valueNameItem != nullptr)
        {
            valueName = valueNameItem->data(Qt::UserRole).toString();
        }
    }

    readRegistryValueByR0(valueName);
}

void RegistryDock::readDefaultValueByR0()
{
    readRegistryValueByR0(QString());
}

void RegistryDock::readRegistryValueByR0(const QString& valueName)
{
    if (m_viewBits != 0) return;
    // 作用：把当前 UI 路径转换为 \REGISTRY\...，然后通过 R0 只读 IOCTL 查询值。
    // 返回：无；结果通过对话框和状态栏展示。
    const QString kernelPath = buildKernelRegistryPath(m_currentPath);
    if (kernelPath.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("R0读取注册表"), QStringLiteral("当前注册表路径无效。"));
        return;
    }

    const ksword::ark::DriverClient driverClient;
    const ksword::ark::RegistryReadResult readResult = driverClient.readRegistryValue(
        kernelPath.toStdWString(),
        valueName.toStdWString(),
        KSWORD_ARK_REGISTRY_DATA_MAX_BYTES);

    QByteArray rawData;
    if (!readResult.data.empty())
    {
        rawData = QByteArray(
            reinterpret_cast<const char*>(readResult.data.data()),
            static_cast<int>(readResult.data.size()));
    }

    const QString valueDisplayName = valueName.isEmpty()
        ? QStringLiteral("(默认)")
        : valueName;
    const QString formattedData = readResult.data.empty()
        ? QStringLiteral("<空>")
        : formatValueData(static_cast<DWORD>(readResult.valueType), rawData);
    const QString statusText = QStringLiteral(
        "路径：%1\n"
        "值名：%2\n"
        "状态：%3\n"
        "类型：%4\n"
        "数据长度：%5 / 需要：%6\n"
        "NTSTATUS：0x%7\n\n"
        "数据：\n%8")
        .arg(kernelPath)
        .arg(valueDisplayName)
        .arg(readResult.io.ok ? QString::number(readResult.status) : QStringLiteral("IOCTL失败"))
        .arg(valueTypeToText(static_cast<DWORD>(readResult.valueType)))
        .arg(readResult.dataBytes)
        .arg(readResult.requiredBytes)
        .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(readResult.lastStatus)), 8, 16, QChar('0'))
        .arg(formattedData);

    kLogEvent event;
    (readResult.io.ok && readResult.status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS ? info : warn)
        << event
        << "[RegistryDock] R0读取注册表完成, path="
        << kernelPath.toStdString()
        << ", valueName="
        << valueName.toStdString()
        << ", ok="
        << (readResult.io.ok ? "true" : "false")
        << ", status="
        << readResult.status
        << ", detail="
        << registryIoMessageText(readResult.io.message).toStdString()
        << eol;

    updateStatusBar(QStringLiteral("R0读取注册表：%1").arg(readResult.io.ok ? QStringLiteral("完成") : QStringLiteral("失败")));
    if (readResult.io.ok && readResult.status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS)
    {
        QMessageBox::information(this, QStringLiteral("R0读取注册表"), statusText);
    }
    else
    {
        QMessageBox::warning(this, QStringLiteral("R0读取注册表"), statusText + QStringLiteral("\n\n详情：%1").arg(registryIoMessageText(readResult.io.message)));
    }
}

void RegistryDock::stopSearch(bool waitForThread)
{
    if (waitForThread) ++m_searchGeneration;
    kLogEvent event;
    info << event
        << "[RegistryDock] 停止搜索请求, waitForThread="
        << (waitForThread ? "true" : "false")
        << eol;

    m_searchStopFlag.store(true);

    if (m_searchThread == nullptr || !m_searchThread->joinable())
    {
        m_searchThread.reset();
        m_searchRunning.store(false);
        m_searchButton->setEnabled(true);
        m_stopSearchButton->setEnabled(false);
        if (m_searchFlushTimer != nullptr) m_searchFlushTimer->stop();
        return;
    }

    if (waitForThread)
    {
        m_searchThread->join();
        m_searchThread.reset();
        m_searchRunning.store(false);
        m_searchButton->setEnabled(true);
        m_stopSearchButton->setEnabled(false);
        if (m_searchFlushTimer != nullptr) m_searchFlushTimer->stop();
        return;
    }

    // 交互停止不能移走唯一的线程所有权：析构路径需要用它同步等待，
    // 才能保证递归搜索不会在 RegistryDock 释放后继续访问成员。
    m_stopSearchButton->setEnabled(false);
    updateStatusBar(QStringLiteral("状态: 搜索已停止"));
}

void RegistryDock::enqueuePendingSearchRow(PendingSearchRow&& row)
{
    std::lock_guard<std::mutex> lock(m_pendingMutex);
    if (m_pendingRows.size() < kMaxPendingSearchRows) m_pendingRows.push_back(std::move(row));
    else ++m_searchDropped;
}

void RegistryDock::flushPendingSearchRows()
{
    // 搜索线程只负责入队；菜单打开时不消费队列，
    // 避免批量扩容让右键动作保存的结果行发生漂移。
    const QPointer<RegistryDock> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("registry-search-result-flush"),
        {m_searchResultTable},
        [safeThis]()
        {
            if (!safeThis.isNull())
            {
                safeThis->flushPendingSearchRows();
            }
        }))
    {
        return;
    }

    std::vector<PendingSearchRow> rows;
    bool hasPendingRows = false;
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        const std::size_t count = std::min<std::size_t>(kSearchFlushBatchSize, m_pendingRows.size());
        rows.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            rows.push_back(std::move(m_pendingRows.front()));
            m_pendingRows.pop_front();
        }
        hasPendingRows = !m_pendingRows.empty();
    }

    const int availableRows = std::max(0, kMaxSearchResultRows - m_searchResultTable->rowCount());
    const int rowsToAppend = std::min(availableRows, static_cast<int>(rows.size()));
    m_searchDropped.fetch_add(rows.size() - static_cast<std::size_t>(rowsToAppend));
    if (rowsToAppend > 0)
    {
        const int firstRow = m_searchResultTable->rowCount();
        const bool updatesEnabled = m_searchResultTable->updatesEnabled();
        m_searchResultTable->setUpdatesEnabled(false);
        m_searchResultTable->setRowCount(firstRow + rowsToAppend);
        for (int index = 0; index < rowsToAppend; ++index)
        {
            const PendingSearchRow& row = rows[static_cast<std::size_t>(index)];
            const int tableRow = firstRow + index;
            QTableWidgetItem* keyPathItem = new QTableWidgetItem(row.keyPathText);
            keyPathItem->setData(kSearchResultRoleViewBits, row.viewBits);
            keyPathItem->setData(kSearchResultRoleUseR0, row.useR0);
            keyPathItem->setData(
                kSearchResultRoleTargetKind,
                row.isKeyResult ? kSearchResultTargetKey : kSearchResultTargetValue);
            QTableWidgetItem* valueNameItem = new QTableWidgetItem(row.isKeyResult ? row.valueNameText
                : row.rawValueName.isEmpty() ? ks::i18n::sourceText(QStringLiteral("(默认)")) : row.rawValueName);
            if (!row.isKeyResult)
            {
                // 默认值展示文本与真实的空 Win32 名称分开保存，避免同名显示值歧义。
                valueNameItem->setData(kSearchResultRoleRawValueName, row.rawValueName);
            }
            m_searchResultTable->setItem(tableRow, 0, keyPathItem);
            m_searchResultTable->setItem(tableRow, 1, valueNameItem);
            m_searchResultTable->setItem(tableRow, 2, new QTableWidgetItem(row.valueTypeText));
            m_searchResultTable->setItem(tableRow, 3, new QTableWidgetItem(row.valueDataPreviewText));
            m_searchResultTable->setItem(tableRow, 4, new QTableWidgetItem(row.hitSourceText));
        }
        m_searchResultTable->setUpdatesEnabled(updatesEnabled);
        if (updatesEnabled) m_searchResultTable->viewport()->update();
    }

    if (!m_searchRunning.load() && !hasPendingRows && m_searchFlushTimer != nullptr)
    {
        m_searchFlushTimer->stop();
        updateStatusBar(QStringLiteral("%1：扫描 %2 键，命中 %3 项，显示 %4 项，跳过 %5 项，未展示 %6 项。")
            .arg(m_lastSearchStopped ? QStringLiteral("搜索已停止") : QStringLiteral("搜索完成"))
            .arg(m_searchScannedKeys).arg(m_searchHitCount).arg(m_searchResultTable->rowCount())
            .arg(m_searchSkipped.load()).arg(m_searchDropped.load()));
    }
}
