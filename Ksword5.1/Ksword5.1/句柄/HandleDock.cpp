#include "HandleDock.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ThemeBinding.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/TableInteractionSupport.h"
#include "../ksword/log/log.h"
#include "../theme.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QHash>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QImage>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QSet>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QSpinBox>
#include <QStringList>
#include <QTabWidget>
#include <QThreadPool>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QVector>

#include <algorithm>
#include <atomic>
#include <memory>
#include <set>
#include <string>
#include <vector>

// 进程图标解析需要直接调用 Win32/Shell/COM 接口，这里在 Qt 头文件之后统一引入。
// WIN32_LEAN_AND_MEAN 与 NOMINMAX 由工程预处理器统一定义，无需在本文件重复声明。
#include <Windows.h>
#include <Shellapi.h>
#include <objbase.h>

namespace
{
    // buildBlueButtonStyle 作用：
    // - 生成项目统一按钮样式，颜色全部来自动态主题角色，深浅色切换实时跟随；
    // - iconOnly=true 时收紧内边距，适合 28x28 图标按钮。
    QString buildBlueButtonStyle(const bool iconOnly)
    {
        QString buttonStyle = ks::ui::BuildFlatButtonStyle() + QStringLiteral("QPushButton,QToolButton{border-radius:3px;padding:4px 10px;font-weight:600;}");
        if (iconOnly)
        {
            buttonStyle += QStringLiteral("QPushButton{padding:4px;}");
        }
        return buttonStyle;
    }

    // installReadOnlyTreeCopyMenu 作用：
    // - 给只读 QTreeWidget 安装“复制当前行”右键菜单；
    // - 输入 treeWidget：Object Header / Object Type 等只读树表；
    // - 处理：点击行时按可见列拼接 TSV，并写入剪贴板；
    // - 返回：无；剪贴板或行为空时静默返回，不触发任何句柄写操作。
    void installReadOnlyTreeCopyMenu(QTreeWidget* treeWidget)
    {
        if (treeWidget == nullptr)
        {
            return;
        }

        treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(treeWidget, &QTreeWidget::customContextMenuRequested, treeWidget, [treeWidget](const QPoint& localPosition)
            {
                QTreeWidgetItem* clickedItem = treeWidget->itemAt(localPosition);
                if (clickedItem != nullptr)
                {
                    treeWidget->setCurrentItem(clickedItem);
                }

                QMenu menu(treeWidget);
                menu.setStyleSheet(KswordTheme::ContextMenuStyle());
                QAction* copyRowAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/handle_copy_row.svg")),
                    QStringLiteral("复制当前行"));
                copyRowAction->setEnabled(clickedItem != nullptr);
                if (menu.exec(treeWidget->viewport()->mapToGlobal(localPosition)) != copyRowAction ||
                    clickedItem == nullptr ||
                    QApplication::clipboard() == nullptr)
                {
                    return;
                }

                QStringList fields;
                fields.reserve(treeWidget->columnCount());
                for (int columnIndex = 0; columnIndex < treeWidget->columnCount(); ++columnIndex)
                {
                    fields.push_back(clickedItem->text(columnIndex));
                }
                QApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
            });
    }

    // buildLineEditStyle 作用：统一过滤输入框视觉风格。
    QString buildLineEditStyle()
    {
        return QStringLiteral(
            "QLineEdit {"
            "  border: 1px solid %1;"
            "  border-radius: 3px;"
            "  background: %2;"
            "  color: %3;"
            "  padding: 3px 6px;"
            "}"
            "QLineEdit:focus {"
            "  border: 1px solid %4;"
            "}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex);
    }

    // buildComboAndSpinStyle 作用：统一下拉框与数字框样式。
    QString buildComboAndSpinStyle()
    {
        return QStringLiteral(
            "QSpinBox {"
            "  border: 1px solid %1;"
            "  border-radius: 3px;"
            "  background: %2;"
            "  color: %3;"
            "  padding: 2px 6px;"
            "}"
            "QSpinBox:hover {"
            "  border-color: %4;"
            "}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex)
            + KswordTheme::ThemedComboBoxStyle();
    }

    // buildHeaderStyle 作用：统一表头样式，保持主题一致。
    QString buildHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{"
            "  color:%1;"
            "  background:transparent; /* %2 */"
            "  border:1px solid %3;"
            "  font-weight:600;"
            "}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex());
    }

    // boolText 作用：把布尔值统一转为中文“是/否”文本。
    QString boolText(const bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }

    // kHandleRenderSplashThreshold 作用：
    // - 控制何时弹出启动页提示“渲染句柄列表”；
    // - 仅在超大数据量渲染时启用，避免小列表频繁闪烁。
    constexpr std::size_t kHandleRenderSplashThreshold = 50000;

    // kHandleRenderProgressStep 作用：
    // - 控制进度回写频率；
    // - 通过分批更新降低额外开销。
    constexpr std::size_t kHandleRenderProgressStep = 4096;

    // HandleRenderSplashScope 作用：
    // - 在超大句柄表渲染期间显示启动页；
    // - 持续回写“渲染句柄列表到图形界面”进度，缓解“程序卡死”感知。
    class HandleRenderSplashScope final
    {
    public:
        explicit HandleRenderSplashScope(const std::size_t totalRowCount)
            : m_totalRowCount(totalRowCount)
        {
            if (m_totalRowCount < kHandleRenderSplashThreshold)
            {
                return;
            }

            m_statusText = ks::i18n::contextText(
                QStringLiteral("handle.splash.render_list"),
                QStringLiteral("渲染句柄列表到图形界面")).toUtf8().toStdString();
            m_visible = kSplash.show(m_statusText);
            if (!m_visible)
            {
                return;
            }

            kSplash.progress(m_statusText, 1);
        }

        ~HandleRenderSplashScope()
        {
            if (m_visible)
            {
                kSplash.hide();
            }
        }

        void update(const std::size_t renderedRowCount) const
        {
            if (!m_visible || m_totalRowCount == 0)
            {
                return;
            }

            const std::size_t normalizedRenderedCount = std::min(renderedRowCount, m_totalRowCount);
            const int progressPercent = std::max(
                1,
                std::min(99, static_cast<int>((normalizedRenderedCount * 100) / m_totalRowCount)));
            kSplash.progress(m_statusText, progressPercent);
        }

        void finish() const
        {
            if (m_visible)
            {
                kSplash.progress(m_statusText, 100);
            }
        }

    private:
        std::size_t m_totalRowCount = 0; // m_totalRowCount：当前渲染总行数。
        std::string m_statusText;        // m_statusText：按当前语言解析后的启动画面文案（UTF-8）。
        bool m_visible = false;          // m_visible：是否成功显示启动页。
    };

    // kHandleProcessIconBatchSize 作用：
    // - 控制后台图标解析一次回投多少个进程实例的结果；
    // - 分批回投让图标逐步出现，同时把跨线程调用与视口重绘次数压在可控范围内。
    constexpr qsizetype kHandleProcessIconBatchSize = 32;

    // kHandleProcessIconCacheLimit 作用：
    // - 限制“进程实例 -> 图标”缓存条目上限；
    // - 防止长时间反复刷新后缓存无限增长。
    constexpr qsizetype kHandleProcessIconCacheLimit = 4096;

    // HandleProcessIconRequest 作用：
    // - 描述一次待解析的进程实例图标请求；
    // - 只含值类型字段，可安全复制到工作线程。
    struct HandleProcessIconRequest
    {
        QString identityKey;                   // identityKey：PID + 创建时间组成的进程实例键。
        std::uint32_t processId = 0;           // processId：目标进程 PID。
        std::uint64_t processCreationTime = 0; // processCreationTime：目标进程创建时间，用于复核 PID 身份。
    };

    // HandleProcessIconResult 作用：
    // - 描述一条已在后台解析完成的进程图标结果；
    // - 只携带 QImage，QPixmap/QIcon 留给 UI 线程构造。
    struct HandleProcessIconResult
    {
        QString identityKey; // identityKey：进程实例键，回填时用于定位缓存与表项。
        QImage iconImage;    // iconImage：Shell 提取到的图标位图；为空表示未解析成功。
    };

    // HandleProcessIconComScope 作用：
    // - 为图标解析工作线程按套间模式初始化 COM，并在析构时配对释放；
    // - Shell 取图标会加载第三方图标处理器，缺少 COM 环境时可能失败。
    // 入参：无。
    // 返回：无（RAII 对象，作用域结束自动释放）。
    class HandleProcessIconComScope final
    {
    public:
        HandleProcessIconComScope()
        {
            // RPC_E_CHANGED_MODE 等失败码表示本线程套间已由他人建立，此时不能配对 CoUninitialize。
            const HRESULT initializeResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            m_shouldUninitialize = SUCCEEDED(initializeResult);
        }

        ~HandleProcessIconComScope()
        {
            if (m_shouldUninitialize)
            {
                ::CoUninitialize();
            }
        }

        HandleProcessIconComScope(const HandleProcessIconComScope&) = delete;
        HandleProcessIconComScope& operator=(const HandleProcessIconComScope&) = delete;

    private:
        bool m_shouldUninitialize = false; // m_shouldUninitialize：COM 是否由本对象初始化。
    };

    // handleProcessPlaceholderIcon 作用：
    // - 提供图标尚未解析或解析失败时统一使用的占位图标；
    // - 只构造一次并全局共享，避免逐行重复读取资源文件。
    // 入参：无。
    // 返回：占位 QIcon 的常量引用。
    const QIcon& handleProcessPlaceholderIcon()
    {
        static const QIcon placeholderIcon(QStringLiteral(":/Icon/process_main.svg"));
        return placeholderIcon;
    }

    // buildHandleProcessIdentityKey 作用：
    // - 用 PID + 创建时间拼出进程实例唯一键；
    // - 键格式与 HandleDock.Icon.cpp 保持一致，两处共用同一份图标缓存。
    // 入参 processId：进程 PID；processCreationTime：进程创建时间。
    // 返回：进程实例键；任一字段为 0 时返回空串，表示无法确认实例。
    QString buildHandleProcessIdentityKey(
        const std::uint32_t processId,
        const std::uint64_t processCreationTime)
    {
        if (processId == 0U || processCreationTime == 0U)
        {
            return {};
        }
        return QStringLiteral("%1|%2")
            .arg(static_cast<qulonglong>(processId))
            .arg(static_cast<qulonglong>(processCreationTime));
    }

    // handleProcessFileTimeToUint64 作用：
    // - 把 FILETIME 折叠成 64 位整数，便于与快照里的创建时间直接比较。
    // 入参 fileTimeValue：Win32 文件时间结构。
    // 返回：对应的 64 位时间值。
    std::uint64_t handleProcessFileTimeToUint64(const FILETIME& fileTimeValue)
    {
        ULARGE_INTEGER convertedValue{};
        convertedValue.LowPart = fileTimeValue.dwLowDateTime;
        convertedValue.HighPart = fileTimeValue.dwHighDateTime;
        return convertedValue.QuadPart;
    }

    // queryHandleProcessImagePathInWorker 作用：
    // - 在工作线程内复核进程实例身份并读取映像路径；
    // - 语义与 HandleDock.Icon.cpp 的同步实现一致，只是搬离了 UI 线程；
    // - 校验与路径查询共用同一个进程句柄，避免 PID 复用导致错配。
    // 入参 processId：目标 PID；expectedCreationTime：快照记录的创建时间。
    // 返回：映像路径；身份不匹配或查询失败时返回空串。
    QString queryHandleProcessImagePathInWorker(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime)
    {
        if (processId == 0U || expectedCreationTime == 0U)
        {
            return {};
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(processId));
        if (processHandle == nullptr)
        {
            return {};
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const bool identityMatches =
            ::GetProcessTimes(
                processHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime) != FALSE
            && handleProcessFileTimeToUint64(creationTime) == expectedCreationTime;
        if (!identityMatches)
        {
            ::CloseHandle(processHandle);
            return {};
        }

        std::vector<wchar_t> imagePathBuffer(32768, L'\0');
        DWORD imagePathLength = static_cast<DWORD>(imagePathBuffer.size());
        QString processImagePath;
        if (::QueryFullProcessImageNameW(
            processHandle,
            0,
            imagePathBuffer.data(),
            &imagePathLength) != FALSE
            && imagePathLength > 0U)
        {
            processImagePath = QString::fromWCharArray(
                imagePathBuffer.data(),
                static_cast<int>(imagePathLength));
        }
        ::CloseHandle(processHandle);
        return processImagePath;
    }

    // extractHandleProcessIconImage 作用：
    // - 在工作线程内通过 Shell 提取可执行文件小图标并转换为 QImage；
    // - QImage 可跨线程传递，不涉及只能在 UI 线程使用的 QPixmap/QIcon/QFileIconProvider。
    // 入参 imagePath：已复核过实例身份的进程映像路径。
    // 返回：图标位图；路径为空或提取失败时返回空 QImage。
    QImage extractHandleProcessIconImage(const QString& imagePath)
    {
        if (imagePath.trimmed().isEmpty())
        {
            return QImage();
        }

        // shellFileInfo 保存 Shell 分配的 HICON，转成 QImage 后必须由调用方销毁。
        SHFILEINFOW shellFileInfo{};
        const DWORD_PTR shellQueryResult = ::SHGetFileInfoW(
            reinterpret_cast<const wchar_t*>(imagePath.utf16()),
            0,
            &shellFileInfo,
            sizeof(shellFileInfo),
            SHGFI_ICON | SHGFI_SMALLICON);
        if (shellQueryResult == 0 || shellFileInfo.hIcon == nullptr)
        {
            return QImage();
        }

        QImage iconImage = QImage::fromHICON(shellFileInfo.hIcon);
        ::DestroyIcon(shellFileInfo.hIcon);
        return iconImage;
    }
}

HandleDock::HandleDock(QWidget* parent)
    : QWidget(parent)
{
    // 配置先于连接加载，避免恢复控件值时触发一次额外枚举。
    initializeUi();
    loadFilterConfiguration();
    applyFilterGlobalSettingsToControls();
    initializeConnections();
    applyLocalHandleFilters(true);
}

void HandleDock::focusProcessId(const std::uint32_t processId, const bool triggerRefresh)
{
    focusProcessIds(QVector<quint32>{ static_cast<quint32>(processId) }, triggerRefresh);
}

void HandleDock::focusProcessIds(const QVector<quint32>& processIds, const bool triggerRefresh)
{
    if (m_tabWidget != nullptr && m_handleListPage != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_handleListPage);
    }
    QVector<std::uint32_t> normalizedIds;
    QSet<quint32> seenPidSet;
    for (const quint32 processId : processIds)
    {
        if (processId != 0U && !seenPidSet.contains(processId))
        {
            seenPidSet.insert(processId);
            normalizedIds.push_back(processId);
        }
    }

    if (normalizedIds.isEmpty())
    {
        returnToSavedFilters();
        return;
    }

    m_temporaryFilterRule = ks::handle::HandleFilterRule{};
    m_temporaryFilterRule.id = QStringLiteral("temporary-") + ks::handle::CreateHandleFilterRuleId();
    m_temporaryFilterRule.name =
        ks::i18n::sourceText(QStringLiteral("临时 PID 筛选"));
    m_temporaryFilterRule.enabled = true;
    m_temporaryFilterRule.processIds = normalizedIds;
    m_temporaryFilterActive = true;
    if (m_returnSavedFilterButton != nullptr)
    {
        m_returnSavedFilterButton->setVisible(true);
    }
    const bool cachedSnapshotCannotServeTemporaryRule =
        m_snapshotScopedToTemporarySinglePid
        && (normalizedIds.size() != 1 || normalizedIds.front() != m_snapshotScopedProcessId);
    if (triggerRefresh || cachedSnapshotCannotServeTemporaryRule)
    {
        requestAsyncRefresh(true);
    }
    else
    {
        applyLocalHandleFilters(true);
    }
}

void HandleDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (m_initialRefreshDone)
    {
        return;
    }

    m_initialRefreshDone = true;
    requestObjectTypeRefreshAsync(true);
    requestAsyncRefresh(true);
}

void HandleDock::initializeUi()
{
    setObjectName(QStringLiteral("HandleDockRoot"));
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(8, 8, 8, 8);
    m_rootLayout->setSpacing(6);

    m_tabWidget = new QTabWidget(this);
    ks::ui::StylePageTabs(m_tabWidget);
    m_rootLayout->addWidget(m_tabWidget, 1);

    initializeHandleListTab();
    initializeObjectHeaderTab();
    initializeObjectTypeTab();
}

void HandleDock::initializeHandleListTab()
{
    m_handleListPage = new QWidget(m_tabWidget);
    m_handleListLayout = new QVBoxLayout(m_handleListPage);
    m_handleListLayout->setContentsMargins(6, 6, 6, 6);
    m_handleListLayout->setSpacing(6);

    m_toolbarLayout = new QHBoxLayout();
    m_toolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolbarLayout->setSpacing(6);

    // 刷新按钮采用“图标+tooltip”模式，符合简短语义按钮图标化规范。
    m_refreshButton = new QPushButton(m_handleListPage);
    m_refreshButton->setIcon(QIcon(":/Icon/handle_refresh.svg"));
    m_refreshButton->setIconSize(QSize(16, 16));
    m_refreshButton->setFixedSize(28, 28);
    m_refreshButton->setToolTip(QStringLiteral("刷新句柄列表"));
    m_refreshButton->setStyleSheet(buildBlueButtonStyle(true));

    m_manageFilterButton = new QPushButton(QStringLiteral("管理规则"), m_handleListPage);
    m_manageFilterButton->setToolTip(QStringLiteral("新建、编辑、复制、启停和排序句柄筛选规则。"));
    m_manageFilterButton->setStyleSheet(buildBlueButtonStyle(false));

    m_importFilterButton = new QPushButton(QStringLiteral("导入配置"), m_handleListPage);
    m_importFilterButton->setToolTip(QStringLiteral("从 JSON 文件导入句柄筛选规则。"));
    m_importFilterButton->setStyleSheet(buildBlueButtonStyle(false));

    m_exportFilterButton = new QPushButton(QStringLiteral("导出配置"), m_handleListPage);
    m_exportFilterButton->setToolTip(QStringLiteral("将当前已保存筛选规则导出为 JSON 文件。"));
    m_exportFilterButton->setStyleSheet(buildBlueButtonStyle(false));

    m_exportResultsButton = new QPushButton(QStringLiteral("导出结果"), m_handleListPage);
    m_exportResultsButton->setToolTip(QStringLiteral("导出全部启用规则的完整命中结果，不受树中加载数量限制。"));
    m_exportResultsButton->setStyleSheet(buildBlueButtonStyle(false));

    m_returnSavedFilterButton = new QPushButton(QStringLiteral("返回已保存筛选器"), m_handleListPage);
    m_returnSavedFilterButton->setToolTip(QStringLiteral("退出临时 PID 筛选并恢复已保存规则。"));
    m_returnSavedFilterButton->setStyleSheet(buildBlueButtonStyle(false));
    m_returnSavedFilterButton->setVisible(false);

    m_enumModeCombo = new QComboBox(m_handleListPage);
    m_enumModeCombo->setToolTip(QStringLiteral("选择句柄枚举来源：用户态快照、DuplicateHandle 增强解析或 R0 HandleTable。"));
    m_enumModeCombo->setStyleSheet(buildComboAndSpinStyle());
    m_enumModeCombo->setMinimumWidth(180);
    m_enumModeCombo->addItem(
        QStringLiteral("User Snapshot"),
        static_cast<int>(ks::handle::FilterEnumMode::UserSnapshot));
    m_enumModeCombo->addItem(
        QStringLiteral("DuplicateHandle"),
        static_cast<int>(ks::handle::FilterEnumMode::DuplicateHandle));
    m_enumModeCombo->addItem(
        QStringLiteral("Kernel HandleTable"),
        static_cast<int>(ks::handle::FilterEnumMode::KernelHandleTable));

    m_resolveNameCheckBox = new QCheckBox(QStringLiteral("解析对象名"), m_handleListPage);
    m_resolveNameCheckBox->setChecked(true);
    m_resolveNameCheckBox->setToolTip(QStringLiteral("启用后会尝试解析对象名称（更耗时）。"));
    m_resolveNameCheckBox->setStyleSheet(
        QStringLiteral("QCheckBox{color:%1;font-weight:600;}").arg(KswordTheme::TextPrimaryHex()));

    m_nameBudgetSpinBox = new QSpinBox(m_handleListPage);
    m_nameBudgetSpinBox->setRange(0, 10000);
    m_nameBudgetSpinBox->setValue(1000);
    m_nameBudgetSpinBox->setSingleStep(100);
    m_nameBudgetSpinBox->setSuffix(QStringLiteral(" 条"));
    m_nameBudgetSpinBox->setToolTip(QStringLiteral("对象名解析预算，预算越大越接近全量解析。"));
    m_nameBudgetSpinBox->setStyleSheet(buildComboAndSpinStyle());

    m_toolbarLayout->addWidget(m_refreshButton);
    m_toolbarLayout->addWidget(m_manageFilterButton);
    m_toolbarLayout->addWidget(m_importFilterButton);
    m_toolbarLayout->addWidget(m_exportFilterButton);
    m_toolbarLayout->addWidget(m_exportResultsButton);
    m_toolbarLayout->addWidget(m_returnSavedFilterButton);
    m_toolbarLayout->addStretch(1);
    m_toolbarLayout->addWidget(new QLabel(QStringLiteral("枚举来源"), m_handleListPage));
    m_toolbarLayout->addWidget(m_enumModeCombo);
    m_toolbarLayout->addWidget(m_resolveNameCheckBox);
    m_toolbarLayout->addWidget(new QLabel(QStringLiteral("名称预算"), m_handleListPage));
    m_toolbarLayout->addWidget(m_nameBudgetSpinBox);
    // 句柄主清单控制行保留所有动作，只统一尺寸和间距。
    m_toolbarLayout->setSpacing(8);
    ks::ui::NormalizeToolbarRow(m_toolbarLayout);

    m_statusLabel = new QLabel(QStringLiteral("● 等待首次刷新"), m_handleListPage);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setMinimumWidth(0);
    m_statusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    m_tableWidget = new QTreeWidget(m_handleListPage);
    initializeHandleTable();

    m_handleListLayout->addLayout(m_toolbarLayout);
    m_handleListLayout->addWidget(m_statusLabel);
    m_handleListLayout->addWidget(m_tableWidget, 1);

    m_tabWidget->addTab(m_handleListPage, QIcon(":/Icon/process_list.svg"), QStringLiteral("Handle Table"));
}

void HandleDock::initializeObjectHeaderTab()
{
    m_objectHeaderPage = new QWidget(m_tabWidget);
    m_objectHeaderLayout = new QVBoxLayout(m_objectHeaderPage);
    m_objectHeaderLayout->setContentsMargins(6, 6, 6, 6);
    m_objectHeaderLayout->setSpacing(6);

    m_handleDetailStatusLabel = new QLabel(QStringLiteral("● 请选择一个句柄查看对象头证据"), m_objectHeaderPage);
    m_handleDetailStatusLabel->setWordWrap(true);
    m_handleDetailStatusLabel->setMinimumWidth(0);
    m_handleDetailStatusLabel->setSizePolicy(
        QSizePolicy::Ignored,
        QSizePolicy::Preferred);
    m_handleDetailStatusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    m_handleDetailTable = new QTreeWidget(m_objectHeaderPage);
    // 单个对象头沿用树形属性证据展示，不新增表格快照/对比栏。
    m_handleDetailTable->setColumnCount(2);
    m_handleDetailTable->setHeaderLabels(QStringList{ QStringLiteral("字段"), QStringLiteral("值") });
    m_handleDetailTable->setRootIsDecorated(false);
    m_handleDetailTable->setItemsExpandable(false);
    m_handleDetailTable->setAlternatingRowColors(true);
    m_handleDetailTable->setSelectionMode(QAbstractItemView::NoSelection);
    m_handleDetailTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    installReadOnlyTreeCopyMenu(m_handleDetailTable);
    if (m_handleDetailTable->header() != nullptr)
    {
        m_handleDetailTable->header()->setStyleSheet(buildHeaderStyle());
        m_handleDetailTable->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        m_handleDetailTable->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    }

    m_objectHeaderLayout->addWidget(m_handleDetailStatusLabel);
    m_objectHeaderLayout->addWidget(m_handleDetailTable, 1);

    m_tabWidget->addTab(m_objectHeaderPage, QIcon(":/Icon/process_critical.svg"), QStringLiteral("Object Header"));
    // Object Header 页只做只读证据展示，不承载关闭/修改类动作；页面职责挂到页签提示上，不再占用版面。
    m_tabWidget->setTabToolTip(
        m_tabWidget->indexOf(m_objectHeaderPage),
        QStringLiteral("展示选中句柄的对象头、对象类型归属、解码状态和风险标记。"));
}

void HandleDock::initializeObjectTypeTab()
{
    m_objectTypePage = new QWidget(m_tabWidget);
    m_objectTypeLayout = new QVBoxLayout(m_objectTypePage);
    m_objectTypeLayout->setContentsMargins(6, 6, 6, 6);
    m_objectTypeLayout->setSpacing(6);

    m_objectTypeToolLayout = new QHBoxLayout();
    m_objectTypeToolLayout->setContentsMargins(0, 0, 0, 0);
    m_objectTypeToolLayout->setSpacing(6);

    m_refreshObjectTypeButton = new QPushButton(m_objectTypePage);
    m_refreshObjectTypeButton->setIcon(QIcon(":/Icon/handle_refresh.svg"));
    m_refreshObjectTypeButton->setIconSize(QSize(16, 16));
    m_refreshObjectTypeButton->setFixedSize(28, 28);
    m_refreshObjectTypeButton->setToolTip(QStringLiteral("刷新对象类型快照"));
    m_refreshObjectTypeButton->setStyleSheet(buildBlueButtonStyle(true));

    m_objectTypeFilterEdit = new QLineEdit(m_objectTypePage);
    // 对象类型结果树的过滤输入，不接管句柄规则编辑中的 PID/名称表单。
    ks::ui::StyleSearchField(m_objectTypeFilterEdit);
    m_objectTypeFilterEdit->setPlaceholderText(QStringLiteral("对象类型过滤（类型名或编号）"));
    m_objectTypeFilterEdit->setClearButtonEnabled(true);
    m_objectTypeFilterEdit->setToolTip(QStringLiteral("输入类型名或编号，过滤对象类型表。"));

    m_objectTypeStatusLabel = new QLabel(QStringLiteral("● 等待首次刷新"), m_objectTypePage);
    m_objectTypeStatusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    m_objectTypeToolLayout->addWidget(m_refreshObjectTypeButton);
    m_objectTypeToolLayout->addWidget(m_objectTypeFilterEdit, 1);
    m_objectTypeToolLayout->addWidget(m_objectTypeStatusLabel);
    m_objectTypeToolLayout->setSpacing(8);
    ks::ui::NormalizeToolbarRow(m_objectTypeToolLayout);

    m_objectTypeTable = new QTreeWidget(m_objectTypePage);
    m_objectTypeDetailTable = new QTreeWidget(m_objectTypePage);
    // 类型清单和字段详情沿用原有树与右键复制，不新增表格操作栏。
    initializeObjectTypeTable();
    installReadOnlyTreeCopyMenu(m_objectTypeTable);
    installReadOnlyTreeCopyMenu(m_objectTypeDetailTable);

    m_objectTypeLayout->addLayout(m_objectTypeToolLayout);
    m_objectTypeLayout->addWidget(m_objectTypeTable, 3);
    m_objectTypeLayout->addWidget(m_objectTypeDetailTable, 2);

    m_tabWidget->addTab(m_objectTypePage, QIcon(":/Icon/process_tree.svg"), QStringLiteral("Object Type"));
}

void HandleDock::initializeHandleTable()
{
    const QStringList headers{
        QStringLiteral("PID"),
        QStringLiteral("进程名"),
        QStringLiteral("句柄"),
        QStringLiteral("TypeIndex/类型"),
        QStringLiteral("对象名"),
        QStringLiteral("对象地址"),
        QStringLiteral("访问掩码"),
        QStringLiteral("属性"),
        QStringLiteral("HandleCount"),
        QStringLiteral("PointerCount"),
        QStringLiteral("来源"),
        QStringLiteral("解码状态"),
        QStringLiteral("差异")
    };

    m_tableWidget->setColumnCount(static_cast<int>(HandleTableColumn::Count));
    m_tableWidget->setHeaderLabels(headers);
    m_tableWidget->setRootIsDecorated(true);
    m_tableWidget->setItemsExpandable(true);
    m_tableWidget->setAlternatingRowColors(true);
    m_tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // 规则摘要必须保持配置顺序，明细排序由 sortLoadedRuleRows 仅作用于规则子节点。
    m_tableWidget->setSortingEnabled(false);
    m_tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);

    QHeaderView* headerView = m_tableWidget->header();
    if (headerView != nullptr)
    {
        headerView->setStyleSheet(buildHeaderStyle());
        headerView->setSectionResizeMode(QHeaderView::Interactive);
        headerView->setStretchLastSection(false);
        headerView->setContextMenuPolicy(Qt::CustomContextMenu);
        headerView->setSectionsClickable(true);
        headerView->setSortIndicatorShown(false);
    }
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::ProcessId), 80);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::ProcessName), 170);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::HandleValue), 100);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::TypeIndex), 180);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::ObjectName), 360);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::ObjectAddress), 130);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::GrantedAccess), 120);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::Attributes), 120);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::HandleCount), 105);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::PointerCount), 110);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::Source), 140);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::DecodeStatus), 140);
    m_tableWidget->setColumnWidth(static_cast<int>(HandleTableColumn::DiffStatus), 120);
}

void HandleDock::initializeObjectTypeTable()
{
    const QStringList headers{
        QStringLiteral("类型编号"),
        QStringLiteral("类型名"),
        QStringLiteral("对象数"),
        QStringLiteral("句柄数"),
        QStringLiteral("访问掩码"),
        QStringLiteral("安全要求"),
        QStringLiteral("维护计数")
    };

    m_objectTypeTable->setColumnCount(static_cast<int>(ObjectTypeTableColumn::Count));
    m_objectTypeTable->setHeaderLabels(headers);
    m_objectTypeTable->setRootIsDecorated(false);
    m_objectTypeTable->setItemsExpandable(false);
    m_objectTypeTable->setAlternatingRowColors(true);
    m_objectTypeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_objectTypeTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_objectTypeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_objectTypeTable->setSortingEnabled(false);
    QHeaderView* typeHeader = m_objectTypeTable->header();
    if (typeHeader != nullptr)
    {
        typeHeader->setStyleSheet(buildHeaderStyle());
        typeHeader->setSectionResizeMode(QHeaderView::ResizeToContents);
        typeHeader->setSectionResizeMode(static_cast<int>(ObjectTypeTableColumn::TypeName), QHeaderView::Stretch);
    }

    // 对象类型详情区使用键值树，方便快速浏览全部字段。
    m_objectTypeDetailTable->setColumnCount(2);
    m_objectTypeDetailTable->setHeaderLabels(QStringList{ QStringLiteral("字段"), QStringLiteral("值") });
    m_objectTypeDetailTable->setRootIsDecorated(false);
    m_objectTypeDetailTable->setItemsExpandable(false);
    m_objectTypeDetailTable->setAlternatingRowColors(true);
    m_objectTypeDetailTable->setSelectionMode(QAbstractItemView::NoSelection);
    m_objectTypeDetailTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    QHeaderView* detailHeader = m_objectTypeDetailTable->header();
    if (detailHeader != nullptr)
    {
        detailHeader->setStyleSheet(buildHeaderStyle());
        detailHeader->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        detailHeader->setSectionResizeMode(1, QHeaderView::Stretch);
    }
}

void HandleDock::initializeConnections()
{
    connect(m_refreshButton, &QPushButton::clicked, this, [this]()
        {
            requestAsyncRefresh(true);
        });

    connect(m_manageFilterButton, &QPushButton::clicked, this, [this]()
        {
            showRuleManagerDialog();
        });

    connect(m_importFilterButton, &QPushButton::clicked, this, [this]()
        {
            importFilterConfiguration();
        });

    connect(m_exportFilterButton, &QPushButton::clicked, this, [this]()
        {
            exportFilterConfiguration();
        });

    connect(m_exportResultsButton, &QPushButton::clicked, this, [this]()
        {
            exportRuleResults();
        });

    connect(m_returnSavedFilterButton, &QPushButton::clicked, this, [this]()
        {
            returnToSavedFilters();
        });

    connect(m_enumModeCombo, &QComboBox::currentTextChanged, this, [this](const QString&)
        {
            collectFilterGlobalSettingsFromControls();
            saveFilterConfiguration();
            requestAsyncRefresh(true);
        });

    connect(m_resolveNameCheckBox, &QCheckBox::toggled, this, [this](const bool)
        {
            collectFilterGlobalSettingsFromControls();
            saveFilterConfiguration();
            requestAsyncRefresh(true);
        });

    connect(m_nameBudgetSpinBox, &QSpinBox::valueChanged, this, [this](const int)
        {
            collectFilterGlobalSettingsFromControls();
            saveFilterConfiguration();
            requestAsyncRefresh(true);
        });

    connect(m_tableWidget, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPoint)
        {
            showHandleTableContextMenu(localPoint);
        });

    connect(m_tableWidget, &QTreeWidget::itemExpanded, this, [this](QTreeWidgetItem* item)
        {
            if (item != nullptr &&
                item->data(0, ks::handle::HandleTreeItemKindRole).toInt() ==
                    static_cast<int>(ks::handle::HandleTreeItemKind::RuleSummary))
            {
                appendNextRuleResultBatch(
                    item->data(0, ks::handle::HandleTreeRuleIdRole).toString());
            }
        });

    const auto activateLoadMore = [this](QTreeWidgetItem* item)
        {
            if (item != nullptr &&
                item->data(0, ks::handle::HandleTreeItemKindRole).toInt() ==
                    static_cast<int>(ks::handle::HandleTreeItemKind::LoadMore))
            {
                appendNextRuleResultBatch(
                    item->data(0, ks::handle::HandleTreeRuleIdRole).toString());
            }
        };
    connect(m_tableWidget, &QTreeWidget::itemClicked, this,
        [activateLoadMore](QTreeWidgetItem* item, int)
        {
            activateLoadMore(item);
        });
    connect(m_tableWidget, &QTreeWidget::itemActivated, this,
        [activateLoadMore](QTreeWidgetItem* item, int)
        {
            activateLoadMore(item);
        });

    connect(m_tableWidget, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem*, QTreeWidgetItem*)
        {
            if (selectedHandleRow() == nullptr)
            {
                ++m_handleDetailRefreshTicket;
                m_handleDetailRefreshInProgress = false;
                if (m_handleDetailOperation)
                {
                    m_handleDetailOperation->cancel();
                }
                showHandleDetailPlaceholder(QStringLiteral("请选择一个句柄查看详情。"));
                return;
            }
            requestHandleDetailRefresh(false);
        });

    if (m_tableWidget->header() != nullptr)
    {
        connect(m_tableWidget->header(), &QHeaderView::customContextMenuRequested, this, [this](const QPoint& localPoint)
            {
                showHandleHeaderContextMenu(localPoint);
            });
        connect(m_tableWidget->header(), &QHeaderView::sectionClicked, this, [this](const int column)
            {
                if (m_handleSortColumn == column)
                {
                    m_handleSortOrder = m_handleSortOrder == Qt::AscendingOrder
                        ? Qt::DescendingOrder
                        : Qt::AscendingOrder;
                }
                else
                {
                    m_handleSortColumn = column;
                    m_handleSortOrder = Qt::AscendingOrder;
                }
                m_tableWidget->header()->setSortIndicatorShown(true);
                m_tableWidget->header()->setSortIndicator(m_handleSortColumn, m_handleSortOrder);
                sortLoadedRuleRows(m_handleSortColumn, m_handleSortOrder);
            });
    }

    connect(m_refreshObjectTypeButton, &QPushButton::clicked, this, [this]()
        {
            requestObjectTypeRefreshAsync(true);
        });

    connect(m_objectTypeFilterEdit, &QLineEdit::textChanged, this, [this](const QString& filterKeyword)
        {
            rebuildObjectTypeTable(filterKeyword.trimmed());
        });

    connect(m_objectTypeTable, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem*, QTreeWidgetItem*)
        {
            showObjectTypeDetailByCurrentRow();
        });
}

void HandleDock::requestAsyncRefresh(const bool forceRefresh)
{
    if (m_refreshInProgress)
    {
        if (forceRefresh)
        {
            m_refreshPending = true;
        }
        return;
    }

    if (m_typeNameMapByIndexFromObjectTab.empty())
    {
        // 句柄对象名解析依赖稳定的 typeIndex->typeName 映射。首次进入页面时如果句柄枚举
        // 和对象类型枚举并行运行，句柄表会先按临时类型渲染一次，随后又因类型映射/对象名补刷
        // 触发第二次重型枚举和第二次表格渲染。这里把句柄刷新降级为待执行请求，等对象类型
        // 快照完成后再开始唯一一次句柄枚举；若类型快照失败，applyObjectTypeRefreshResult 会兜底放行。
        m_refreshPending = true;
        updateHandleStatusLabel(QStringLiteral("● 等待对象类型快照完成后刷新句柄列表..."), true);
        if (!m_objectTypeRefreshInProgress)
        {
            requestObjectTypeRefreshAsync(false);
        }
        return;
    }

    requestAsyncRefreshWithoutTypePrecondition(forceRefresh);
}

void HandleDock::requestAsyncRefreshWithoutTypePrecondition(const bool forceRefresh)
{
    if (m_refreshInProgress)
    {
        if (forceRefresh)
        {
            m_refreshPending = true;
        }
        return;
    }

    const HandleRefreshOptions options = collectHandleRefreshOptions();
    const std::uint64_t currentTicket = ++m_refreshTicket;
    m_refreshInProgress = true;
    updateHandleStatusLabel(QStringLiteral("● 正在刷新句柄列表..."), true);

    if (m_refreshProgressPid <= 0)
    {
        m_refreshProgressPid = kPro.addReusable(this, "句柄枚举", "准备读取系统句柄快照");
    }
    kPro.set(m_refreshProgressPid, "后台枚举系统句柄", 0, 20.0f);

    kLogEvent refreshEvent;
    info << refreshEvent
        << "[HandleDock] requestAsyncRefresh: ticket="
        << currentTicket
        << ", pidFilter="
        << (options.hasPidFilter ? std::to_string(options.pidFilter) : std::string("all"))
        << ", keyword="
        << options.keywordText.toStdString()
        << ", typeFilter="
        << options.typeFilterText.toStdString()
        << ", onlyNamed="
        << (options.onlyNamed ? "true" : "false")
        << ", resolveName="
        << (options.resolveObjectName ? "true" : "false")
        << ", nameBudget="
        << options.nameResolveBudget
        << ", enumMode="
        << static_cast<int>(options.enumMode)
        << ", diffFilter="
        << static_cast<int>(options.diffFilter)
        << ", objectTypeMapSize="
        << options.typeNameMapFromObjectTab.size()
        << eol;

    QPointer<HandleDock> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, currentTicket, options]()
        {
            const HandleRefreshResult refreshResult = buildHandleRefreshResult(options);
            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, currentTicket, refreshResult]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->applyHandleRefreshResult(currentTicket, refreshResult);
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void HandleDock::requestObjectTypeRefreshAsync(const bool forceRefresh)
{
    if (m_objectTypeRefreshInProgress)
    {
        if (forceRefresh)
        {
            m_objectTypeRefreshPending = true;
        }
        return;
    }

    const std::uint64_t currentTicket = ++m_objectTypeRefreshTicket;
    m_objectTypeRefreshInProgress = true;
    updateObjectTypeStatusLabel(QStringLiteral("● 正在刷新对象类型..."), true);

    if (m_objectTypeRefreshProgressPid <= 0)
    {
        m_objectTypeRefreshProgressPid = kPro.addReusable(this, "对象类型", "准备读取对象类型快照");
    }
    kPro.set(m_objectTypeRefreshProgressPid, "后台采集对象类型", 0, 20.0f);

    QPointer<HandleDock> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, currentTicket]()
        {
            const ObjectTypeRefreshResult refreshResult = buildObjectTypeRefreshResult();
            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, currentTicket, refreshResult]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->applyObjectTypeRefreshResult(currentTicket, refreshResult);
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void HandleDock::applyHandleRefreshResult(
    const std::uint64_t refreshTicket,
    const HandleRefreshResult& refreshResult)
{
    if (refreshTicket < m_refreshTicket)
    {
        return;
    }

    const bool scopedResultStillMatchesTemporaryRule =
        m_temporaryFilterActive
        && m_temporaryFilterRule.processIds.size() == 1
        && m_temporaryFilterRule.processIds.front() == refreshResult.scopedProcessId;
    if (refreshResult.snapshotScopedToPid && !scopedResultStillMatchesTemporaryRule)
    {
        // 临时 PID 刷新在途时用户可能已经返回持久规则、导入配置或切换到另一 PID。
        // 该结果不能作为完整快照使用，直接丢弃并按当前状态重新采集。
        m_refreshInProgress = false;
        m_refreshPending = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestAsyncRefresh(true);
            }, Qt::QueuedConnection);
        return;
    }

    if (ks::ui::IsItemViewUiCommitBlockedByContextMenu({ m_tableWidget }))
    {
        const auto refreshSnapshot = std::make_shared<HandleRefreshResult>(refreshResult);
        const QPointer<HandleDock> safeThis(this);
        if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("handle-dock-main-snapshot"),
            { m_tableWidget },
            [safeThis, refreshTicket, refreshSnapshot]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->applyHandleRefreshResult(refreshTicket, *refreshSnapshot);
                }
            }))
        {
            return;
        }
    }

    m_allRows = refreshResult.rows;
    m_snapshotScopedToTemporarySinglePid = refreshResult.snapshotScopedToPid;
    m_snapshotScopedProcessId = refreshResult.scopedProcessId;
    m_lastEnumeratedHandleCount = refreshResult.totalHandleCount;
    m_lastResolvedNameCount = refreshResult.resolvedNameCount;
    m_lastObjectTypeMappedCount = refreshResult.objectTypeMappedCount;
    m_lastKernelHandleCount = refreshResult.kernelHandleCount;
    m_lastRefreshElapsedMs = refreshResult.elapsedMs;
    m_lastRefreshDiagnosticText = refreshResult.diagnosticText;
    m_typeNameCacheByIndex = refreshResult.updatedTypeNameCacheByIndex;
    const bool canRenderAfterTypeMapping = !m_typeNameMapByIndexFromObjectTab.empty();
    const bool canRenderWithoutTypeMapping =
        !canRenderAfterTypeMapping && !m_objectTypeRefreshInProgress;
    if (canRenderAfterTypeMapping)
    {
        // 对象类型映射已经可用时，先把 typeIndex 翻译成稳定类型名，再触发表格渲染。
        // 这样首轮刷新可在后台完成对象名解析后一次性呈现最终行数据。
        for (HandleRow& row : m_allRows)
        {
            const auto typeIt = m_typeNameMapByIndexFromObjectTab.find(row.typeIndex);
            if (typeIt != m_typeNameMapByIndexFromObjectTab.end() && !typeIt->second.empty())
            {
                row.typeName = QString::fromStdString(typeIt->second);
            }
        }
    }
    refreshTypeFilterItemsFromAllRows();
    if (canRenderAfterTypeMapping || canRenderWithoutTypeMapping)
    {
        // 正常路径：对象类型映射已就绪后渲染一次。
        // 兜底路径：对象类型快照已结束但返回空映射时，不再等待第二轮，直接渲染一次。
        m_handleRenderDeferredUntilTypeMap = false;
        applyLocalHandleFilters(true);
    }
    else
    {
        // 仅保留给历史/异常并发路径：句柄枚举已经完成但对象类型快照仍在运行时，
        // 只更新 m_rows 缓存，不重建 QTreeWidget，避免出现两次 UI 渲染。
        m_handleRenderDeferredUntilTypeMap = true;
        applyLocalHandleFilters(false);
    }

    QString statusText = QStringLiteral(
        "● 完成 %1 ms | 总:%2 | 显示:%3 | 名称:%4 | 类型:%5 | R0:%6")
        .arg(refreshResult.elapsedMs)
        .arg(refreshResult.totalHandleCount)
        .arg(m_totalRuleMatchCount)
        .arg(refreshResult.resolvedNameCount)
        .arg(refreshResult.objectTypeMappedCount)
        .arg(refreshResult.kernelHandleCount);
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(" | 有诊断");
    }
    updateHandleStatusLabel(statusText, false);
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setToolTip(QStringLiteral(
            "总句柄:%1\n"
            "当前显示:%2\n"
            "基础信息已读取:%3\n"
            "名称已解析:%4\n"
            "补充解析名称:%5\n"
            "类型已识别:%6\n"
            "内核记录:%7\n"
            "仅用户态发现:%8\n"
            "仅内核发现:%9\n"
            "双来源确认:%10\n"
            "诊断:%11")
            .arg(refreshResult.totalHandleCount)
            .arg(m_totalRuleMatchCount)
            .arg(refreshResult.basicInfoResolvedCount)
            .arg(refreshResult.resolvedNameCount)
            .arg(refreshResult.fallbackNameCount)
            .arg(refreshResult.objectTypeMappedCount)
            .arg(refreshResult.kernelHandleCount)
            .arg(refreshResult.userOnlyCount)
            .arg(refreshResult.kernelOnlyCount)
            .arg(refreshResult.bothCount)
            .arg(refreshResult.diagnosticText.trimmed().isEmpty()
                ? QStringLiteral("无")
                : refreshResult.diagnosticText));
    }
    updateHandleSummaryStatus();

    m_refreshInProgress = false;
    kPro.set(m_refreshProgressPid, "句柄刷新完成", 0, 100.0f);

    kLogEvent refreshDoneEvent;
    info << refreshDoneEvent
        << "[HandleDock] applyHandleRefreshResult: ticket="
        << refreshTicket
        << ", total="
        << refreshResult.totalHandleCount
        << ", visible="
        << refreshResult.visibleHandleCount
        << ", mapped="
        << refreshResult.objectTypeMappedCount
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;

    if (m_refreshPending)
    {
        m_refreshPending = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestAsyncRefresh(true);
            }, Qt::QueuedConnection);
    }
}

void HandleDock::applyObjectTypeRefreshResult(
    const std::uint64_t refreshTicket,
    const ObjectTypeRefreshResult& refreshResult)
{
    if (refreshTicket < m_objectTypeRefreshTicket)
    {
        return;
    }

    const QList<QAbstractItemView*> affectedViews{
        m_objectTypeTable,
        m_objectTypeDetailTable,
        m_tableWidget
    };
    if (ks::ui::IsItemViewUiCommitBlockedByContextMenu(affectedViews))
    {
        const auto refreshSnapshot = std::make_shared<ObjectTypeRefreshResult>(refreshResult);
        const QPointer<HandleDock> safeThis(this);
        if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("handle-dock-object-type-snapshot"),
            affectedViews,
            [safeThis, refreshTicket, refreshSnapshot]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->applyObjectTypeRefreshResult(refreshTicket, *refreshSnapshot);
                }
            }))
        {
            return;
        }
    }

    m_objectTypeRows = refreshResult.rows;
    m_typeNameMapByIndexFromObjectTab = refreshResult.typeNameMapByIndex;
    rebuildObjectTypeTable(m_objectTypeFilterEdit->text().trimmed());

    QString statusText = QStringLiteral("● 刷新完成 %1 ms | 类型数:%2")
        .arg(refreshResult.elapsedMs)
        .arg(refreshResult.rows.size());
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(" | 存在诊断；详情已写入日志。");
        kLogEvent diagnosticEvent;
        warn << diagnosticEvent
            << "[HandleDock] object type refresh completed with diagnostics, rowCount="
            << refreshResult.rows.size()
            << ", detail=" << refreshResult.diagnosticText.toStdString()
            << eol;
    }
    updateObjectTypeStatusLabel(statusText, false);

    m_objectTypeRefreshInProgress = false;
    kPro.set(m_objectTypeRefreshProgressPid, "对象类型刷新完成", 0, 100.0f);

    const bool hasQueuedHandleRefresh = m_refreshPending;
    if (!hasQueuedHandleRefresh)
    {
        // 只有没有等待中的句柄刷新时，才把对象类型映射同步到既有表格缓存。
        // 若已有句柄刷新在排队，后续那一轮会生成最终快照并渲染一次，避免旧缓存先渲染一次。
        syncHandleTypeNamesFromObjectTypeMap();
    }

    if (hasQueuedHandleRefresh)
    {
        // 对象类型刷新是句柄刷新前置步骤。这里消费等待中的句柄刷新请求，保证随后只进行
        // 一次后台枚举和一次句柄表渲染，不再额外安排“对象名补刷”导致第二轮卡顿。
        m_refreshPending = false;
        if (!m_typeNameMapByIndexFromObjectTab.empty())
        {
            QMetaObject::invokeMethod(this, [this]()
                {
                    requestAsyncRefresh(true);
                }, Qt::QueuedConnection);
        }
        else
        {
            kLogEvent typeMapFallbackEvent;
            warn << typeMapFallbackEvent
                << "[HandleDock] applyObjectTypeRefreshResult: object type map is empty, running one fallback handle refresh without type precondition."
                << eol;
            QMetaObject::invokeMethod(this, [this]()
                {
                    requestAsyncRefreshWithoutTypePrecondition(true);
                }, Qt::QueuedConnection);
        }
    }

    if (m_objectTypeRefreshPending)
    {
        m_objectTypeRefreshPending = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestObjectTypeRefreshAsync(true);
            }, Qt::QueuedConnection);
    }
}

void HandleDock::rebuildHandleTable()
{
    rebuildRuleSummaryTree();
    return;

    m_tableWidget->clear();
    // clear() 已经销毁全部旧表项：立刻递增代次淘汰在途的图标回投，并重建“行下标 -> 表项”映射。
    ++m_processIconResolveGeneration;
    const std::uint64_t iconResolveGeneration = m_processIconResolveGeneration;
    m_handleTableItemsByRowIndex.assign(m_rows.size(), nullptr);

    // 上一轮扫描的行下标已经失效，置位取消标志让它尽快退出线程池，避免连续过滤时堆积长任务。
    if (m_processIconResolveCancelFlag != nullptr)
    {
        m_processIconResolveCancelFlag->store(true);
    }
    m_processIconResolveCancelFlag = std::make_shared<std::atomic_bool>(false);
    const std::shared_ptr<std::atomic_bool> iconResolveCancelFlag = m_processIconResolveCancelFlag;

    const std::size_t totalRowCount = m_rows.size();
    HandleRenderSplashScope renderSplashScope(totalRowCount);

    // 建表期间关闭排序：开启排序时每次 addTopLevelItem 都要做一次插入排序，
    // 数万行会退化成整表反复搬移；建完统一恢复排序，Qt 会按当前排序列重排一次。
    const bool sortingEnabledBeforeRebuild = m_tableWidget->isSortingEnabled();
    m_tableWidget->setSortingEnabled(false);

    // 图标请求在建表过程中就地收集，建表结束后一次性交给线程池；
    // UI 线程本轮只做 QHash 查表，不再逐行 OpenProcess + QueryFullProcessImageNameW + Shell 取图标。
    QVector<HandleProcessIconRequest> pendingIconRequests;
    QHash<QString, QVector<int>> pendingIconRowIndicesByIdentity;

    for (std::size_t rowIndex = 0; rowIndex < m_rows.size(); ++rowIndex)
    {
        const HandleRow& row = m_rows[rowIndex];
        // 这张表是本页主力，动辄上万行，却整表按 DisplayRole 字符串排序：
        // PID 排成 1/10/100/11/2，句柄值与对象地址因为十六进制不补零同样乱序，
        // 句柄数/指针数按字符串比更是 9 大于 10。改用带 NumericSortRole 的行，
        // 数值列各自挂真实数值，显示文本保持原样（十六进制仍是十六进制）。
        auto* item = new ks::ui::NumericTreeItem();
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::ProcessId),
            QString::number(row.processId),
            static_cast<qulonglong>(row.processId));
        item->setText(static_cast<int>(HandleTableColumn::ProcessName), row.processName);
        // 进程图标只查内存缓存：未命中先挂占位图并登记异步请求，真实图标由后台解析完成后回填。
        const QString processIdentityKey =
            buildHandleProcessIdentityKey(row.processId, row.processCreationTime);
        const auto cachedIconIt = m_processIconCacheByIdentity.constFind(processIdentityKey);
        if (cachedIconIt != m_processIconCacheByIdentity.constEnd())
        {
            item->setIcon(
                static_cast<int>(HandleTableColumn::ProcessName),
                cachedIconIt.value());
        }
        else
        {
            item->setIcon(
                static_cast<int>(HandleTableColumn::ProcessName),
                handleProcessPlaceholderIcon());
            if (!processIdentityKey.isEmpty())
            {
                // 同一进程实例可能占据成百上千行，这里按实例键聚合行下标，后台只解析一次图标。
                QVector<int>& identityRowIndexList = pendingIconRowIndicesByIdentity[processIdentityKey];
                if (identityRowIndexList.isEmpty())
                {
                    pendingIconRequests.push_back(
                        HandleProcessIconRequest{
                            processIdentityKey,
                            row.processId,
                            row.processCreationTime });
                }
                identityRowIndexList.push_back(static_cast<int>(rowIndex));
            }
        }
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::HandleValue),
            formatHex(row.handleValue, 0),
            static_cast<qulonglong>(row.handleValue));
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::TypeIndex),
            formatTypeIndexDisplayText(row.typeIndex, row.typeName),
            static_cast<qulonglong>(row.typeIndex));
        const QString objectNameDisplayText = formatObjectNameDisplayText(row);
        item->setText(static_cast<int>(HandleTableColumn::ObjectName), objectNameDisplayText);
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::ObjectAddress),
            formatHex(row.objectAddress, 0),
            static_cast<qulonglong>(row.objectAddress));
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::GrantedAccess),
            formatHex(row.grantedAccess, 8),
            static_cast<qulonglong>(row.grantedAccess));
        item->setText(static_cast<int>(HandleTableColumn::Attributes), formatHandleAttributes(row.attributes));
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::HandleCount),
            formatOptionalObjectCount(row.handleCount, row.basicInfoAvailable),
            static_cast<qulonglong>(row.basicInfoAvailable ? row.handleCount : 0));
        item->setNumericCell(
            static_cast<int>(HandleTableColumn::PointerCount),
            formatOptionalObjectCount(row.pointerCount, row.basicInfoAvailable),
            static_cast<qulonglong>(row.basicInfoAvailable ? row.pointerCount : 0));
        item->setText(static_cast<int>(HandleTableColumn::Source), formatHandleSourceText(row.sourceMode));
        item->setText(static_cast<int>(HandleTableColumn::DecodeStatus), formatHandleDecodeStatusText(row.decodeStatus));
        item->setText(static_cast<int>(HandleTableColumn::DiffStatus), formatHandleDiffStatusText(row.diffStatus));
        item->setData(static_cast<int>(HandleTableColumn::ProcessId), Qt::UserRole, static_cast<qulonglong>(rowIndex));
        item->setToolTip(
            static_cast<int>(HandleTableColumn::GrantedAccess),
            decodeGrantedAccessText(row.typeName, row.grantedAccess));
        item->setToolTip(
            static_cast<int>(HandleTableColumn::Source),
            QStringLiteral("Object 地址仅用于展示和差异检测，不可作为后续操作凭据。"));
        item->setToolTip(
            static_cast<int>(HandleTableColumn::DecodeStatus),
            QStringLiteral("EP.ObjectTable=0x%1, HtContention=0x%2, ObDecodeShift=%3, ObAttributesShift=%4, OtName=0x%5, OtIndex=0x%6")
            .arg(static_cast<qulonglong>(row.epObjectTableOffset), 0, 16)
            .arg(static_cast<qulonglong>(row.htHandleContentionEventOffset), 0, 16)
            .arg(row.obDecodeShift)
            .arg(row.obAttributesShift)
            .arg(static_cast<qulonglong>(row.otNameOffset), 0, 16)
            .arg(static_cast<qulonglong>(row.otIndexOffset), 0, 16));

        // 占位状态统一弱化显示，并附带 tooltip 解释来源，避免用户把“无名称”和“未查到”误看成同一种状态。
        if (!row.objectNameAvailable || row.objectName.trimmed().isEmpty())
        {
            const QColor secondaryTextColor = KswordTheme::TextSecondaryColor();
            item->setForeground(
                static_cast<int>(HandleTableColumn::ObjectName),
                secondaryTextColor);
        }
        if (!row.basicInfoAvailable)
        {
            const QColor secondaryTextColor = KswordTheme::TextSecondaryColor();
            item->setForeground(static_cast<int>(HandleTableColumn::HandleCount), secondaryTextColor);
            item->setForeground(static_cast<int>(HandleTableColumn::PointerCount), secondaryTextColor);
            item->setToolTip(static_cast<int>(HandleTableColumn::HandleCount), QStringLiteral("ObjectBasicInformation 未查到。"));
            item->setToolTip(static_cast<int>(HandleTableColumn::PointerCount), QStringLiteral("ObjectBasicInformation 未查到。"));
        }
        if (row.objectNameAvailable)
        {
            if (row.objectName.trimmed().isEmpty())
            {
                item->setToolTip(static_cast<int>(HandleTableColumn::ObjectName), QStringLiteral("对象已查询，但该对象没有名称。"));
            }
        }
        else if (row.objectNameFailed)
        {
            item->setToolTip(static_cast<int>(HandleTableColumn::ObjectName), QStringLiteral("对象名查询失败。"));
        }
        else
        {
            item->setToolTip(static_cast<int>(HandleTableColumn::ObjectName), QStringLiteral("对象名未查询，可能受预算、类型白名单或开关限制。"));
        }
        m_tableWidget->addTopLevelItem(item);
        m_handleTableItemsByRowIndex[rowIndex] = item;

        if (totalRowCount > 0
            && (((rowIndex + 1) % kHandleRenderProgressStep) == 0 || (rowIndex + 1) == totalRowCount))
        {
            renderSplashScope.update(rowIndex + 1);
        }
    }

    if (sortingEnabledBeforeRebuild)
    {
        m_tableWidget->setSortingEnabled(true);
    }

    renderSplashScope.finish();

    if (pendingIconRequests.isEmpty())
    {
        return;
    }

    // 进程图标解析（OpenProcess + GetProcessTimes + QueryFullProcessImageNameW + Shell 取图标）
    // 整体搬到线程池：后台只产出 QImage 值类型，QPixmap/QIcon 构造与表项刷新仍留在 UI 线程。
    const QPointer<HandleDock> guardedSelf(this);
    auto* iconResolveTask = QRunnable::create(
        [guardedSelf,
        iconResolveGeneration,
        iconResolveCancelFlag,
        pendingIconRequests,
        pendingIconRowIndicesByIdentity]()
        {
            // Shell 图标处理器需要 COM 环境，工作线程自行初始化并在本任务结束时配对释放。
            const HandleProcessIconComScope iconWorkerComScope;

            QVector<HandleProcessIconResult> batchedIconResults;
            batchedIconResults.reserve(kHandleProcessIconBatchSize);

            // postBatchedIconResults 作用：把攒够的一批图标结果回投到 UI 线程，并清空批次缓冲。
            // 入参：无（按引用使用外层的批次缓冲与行下标映射）。
            // 返回：无。
            const auto postBatchedIconResults =
                [&guardedSelf, iconResolveGeneration, &pendingIconRowIndicesByIdentity, &batchedIconResults]()
                {
                    if (batchedIconResults.isEmpty())
                    {
                        return;
                    }

                    QCoreApplication* const appInstance = QCoreApplication::instance();
                    if (appInstance == nullptr)
                    {
                        batchedIconResults.clear();
                        return;
                    }

                    QMetaObject::invokeMethod(
                        appInstance,
                        [guardedSelf,
                        iconResolveGeneration,
                        rowIndicesByIdentity = pendingIconRowIndicesByIdentity,
                        iconResults = batchedIconResults]()
                        {
                            if (guardedSelf == nullptr || guardedSelf->m_tableWidget == nullptr)
                            {
                                return;
                            }
                            // 代次一致才说明表格未被重建、登记的行下标与表项指针仍然有效。
                            // 代次不一致时仍然写入图标缓存（进程实例 -> 图标的映射与代次无关），
                            // 只是不再回填表项，下一轮建表可以直接命中缓存。
                            const bool tableItemsStillValid =
                                guardedSelf->m_processIconResolveGeneration == iconResolveGeneration;

                            bool anyIconApplied = false;
                            {
                                // 逐条 setIcon 会触发一次 dataChanged 和一次视图行定位，数万行下会退化成整表扫描；
                                // 这里在批量写回期间屏蔽模型信号，写完统一刷新一次视口。
                                const QSignalBlocker tableModelBlocker(guardedSelf->m_tableWidget->model());
                                for (const HandleProcessIconResult& iconResult : iconResults)
                                {
                                    // QPixmap 只能在 UI 线程构造；解析失败也写入占位图缓存，避免下一轮重复发起系统调用。
                                    const QIcon resolvedProcessIcon = iconResult.iconImage.isNull()
                                        ? handleProcessPlaceholderIcon()
                                        : QIcon(QPixmap::fromImage(iconResult.iconImage));
                                    if (guardedSelf->m_processIconCacheByIdentity.size() >= kHandleProcessIconCacheLimit)
                                    {
                                        guardedSelf->m_processIconCacheByIdentity.erase(
                                            guardedSelf->m_processIconCacheByIdentity.begin());
                                    }
                                    guardedSelf->m_processIconCacheByIdentity.insert(
                                        iconResult.identityKey,
                                        resolvedProcessIcon);
                                    if (!tableItemsStillValid)
                                    {
                                        continue;
                                    }

                                    const auto identityRowIndexIt =
                                        rowIndicesByIdentity.constFind(iconResult.identityKey);
                                    if (identityRowIndexIt == rowIndicesByIdentity.constEnd())
                                    {
                                        continue;
                                    }
                                    for (const int targetRowIndex : identityRowIndexIt.value())
                                    {
                                        if (targetRowIndex < 0 ||
                                            static_cast<std::size_t>(targetRowIndex) >=
                                            guardedSelf->m_handleTableItemsByRowIndex.size())
                                        {
                                            continue;
                                        }
                                        QTreeWidgetItem* const targetItem =
                                            guardedSelf->m_handleTableItemsByRowIndex[
                                                static_cast<std::size_t>(targetRowIndex)];
                                        if (targetItem == nullptr)
                                        {
                                            continue;
                                        }
                                        targetItem->setIcon(
                                            static_cast<int>(HandleTableColumn::ProcessName),
                                            resolvedProcessIcon);
                                        anyIconApplied = true;
                                    }
                                }
                            }

                            if (anyIconApplied && guardedSelf->m_tableWidget->viewport() != nullptr)
                            {
                                guardedSelf->m_tableWidget->viewport()->update();
                            }
                        },
                        Qt::QueuedConnection);
                    batchedIconResults.clear();
                };

            for (const HandleProcessIconRequest& iconRequest : pendingIconRequests)
            {
                if (guardedSelf == nullptr ||
                    iconResolveCancelFlag->load(std::memory_order_relaxed))
                {
                    // 页面已销毁或表格已重建：剩余请求交给新一轮扫描，本任务立刻让出线程池线程。
                    break;
                }

                const QString processImagePath = queryHandleProcessImagePathInWorker(
                    iconRequest.processId,
                    iconRequest.processCreationTime);
                batchedIconResults.push_back(
                    HandleProcessIconResult{
                        iconRequest.identityKey,
                        extractHandleProcessIconImage(processImagePath) });
                if (batchedIconResults.size() >= kHandleProcessIconBatchSize)
                {
                    postBatchedIconResults();
                }
            }
            postBatchedIconResults();
        });
    iconResolveTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(iconResolveTask);
}

QTreeWidgetItem* HandleDock::createHandleTreeRow(const std::size_t sourceRowIndex)
{
    if (sourceRowIndex >= m_allRows.size())
    {
        return nullptr;
    }

    const HandleRow& row = m_allRows[sourceRowIndex];
    auto* item = new ks::ui::NumericTreeItem();
    item->setData(0, ks::handle::HandleTreeItemKindRole,
        static_cast<int>(ks::handle::HandleTreeItemKind::HandleRow));
    item->setData(0, ks::handle::HandleTreeSourceRowIndexRole,
        static_cast<qulonglong>(sourceRowIndex));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::ProcessId),
        QString::number(row.processId),
        static_cast<qulonglong>(row.processId));
    item->setText(static_cast<int>(HandleTableColumn::ProcessName), row.processName);

    const QString processIdentityKey =
        buildHandleProcessIdentityKey(row.processId, row.processCreationTime);
    const auto cachedIconIt = m_processIconCacheByIdentity.constFind(processIdentityKey);
    item->setIcon(
        static_cast<int>(HandleTableColumn::ProcessName),
        cachedIconIt == m_processIconCacheByIdentity.constEnd()
            ? handleProcessPlaceholderIcon()
            : cachedIconIt.value());

    item->setNumericCell(
        static_cast<int>(HandleTableColumn::HandleValue),
        formatHex(row.handleValue, 0),
        static_cast<qulonglong>(row.handleValue));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::TypeIndex),
        formatTypeIndexDisplayText(row.typeIndex, row.typeName),
        static_cast<qulonglong>(row.typeIndex));
    item->setText(
        static_cast<int>(HandleTableColumn::ObjectName),
        formatObjectNameDisplayText(row));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::ObjectAddress),
        formatHex(row.objectAddress, 0),
        static_cast<qulonglong>(row.objectAddress));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::GrantedAccess),
        formatHex(row.grantedAccess, 8),
        static_cast<qulonglong>(row.grantedAccess));
    item->setText(
        static_cast<int>(HandleTableColumn::Attributes),
        formatHandleAttributes(row.attributes));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::HandleCount),
        formatOptionalObjectCount(row.handleCount, row.basicInfoAvailable),
        static_cast<qulonglong>(row.basicInfoAvailable ? row.handleCount : 0));
    item->setNumericCell(
        static_cast<int>(HandleTableColumn::PointerCount),
        formatOptionalObjectCount(row.pointerCount, row.basicInfoAvailable),
        static_cast<qulonglong>(row.basicInfoAvailable ? row.pointerCount : 0));
    item->setText(static_cast<int>(HandleTableColumn::Source), formatHandleSourceText(row.sourceMode));
    item->setText(static_cast<int>(HandleTableColumn::DecodeStatus), formatHandleDecodeStatusText(row.decodeStatus));
    item->setText(static_cast<int>(HandleTableColumn::DiffStatus), formatHandleDiffStatusText(row.diffStatus));
    item->setToolTip(
        static_cast<int>(HandleTableColumn::GrantedAccess),
        decodeGrantedAccessText(row.typeName, row.grantedAccess));
    item->setToolTip(
        static_cast<int>(HandleTableColumn::Source),
        QStringLiteral("Object 地址仅用于展示和差异检测，不可作为后续操作凭据。"));
    item->setToolTip(
        static_cast<int>(HandleTableColumn::DecodeStatus),
        QStringLiteral("EP.ObjectTable=0x%1, HtContention=0x%2, ObDecodeShift=%3, ObAttributesShift=%4, OtName=0x%5, OtIndex=0x%6")
        .arg(static_cast<qulonglong>(row.epObjectTableOffset), 0, 16)
        .arg(static_cast<qulonglong>(row.htHandleContentionEventOffset), 0, 16)
        .arg(row.obDecodeShift)
        .arg(row.obAttributesShift)
        .arg(static_cast<qulonglong>(row.otNameOffset), 0, 16)
        .arg(static_cast<qulonglong>(row.otIndexOffset), 0, 16));

    if (!row.objectNameAvailable || row.objectName.trimmed().isEmpty())
    {
        item->setForeground(
            static_cast<int>(HandleTableColumn::ObjectName),
            KswordTheme::TextSecondaryColor());
    }
    if (!row.basicInfoAvailable)
    {
        item->setForeground(
            static_cast<int>(HandleTableColumn::HandleCount),
            KswordTheme::TextSecondaryColor());
        item->setForeground(
            static_cast<int>(HandleTableColumn::PointerCount),
            KswordTheme::TextSecondaryColor());
        item->setToolTip(
            static_cast<int>(HandleTableColumn::HandleCount),
            QStringLiteral("ObjectBasicInformation 未查到。"));
        item->setToolTip(
            static_cast<int>(HandleTableColumn::PointerCount),
            QStringLiteral("ObjectBasicInformation 未查到。"));
    }
    if (row.objectNameAvailable)
    {
        if (row.objectName.trimmed().isEmpty())
        {
            item->setToolTip(
                static_cast<int>(HandleTableColumn::ObjectName),
                QStringLiteral("对象已查询，但该对象没有名称。"));
        }
    }
    else if (row.objectNameFailed)
    {
        item->setToolTip(
            static_cast<int>(HandleTableColumn::ObjectName),
            QStringLiteral("对象名查询失败。"));
    }
    else
    {
        item->setToolTip(
            static_cast<int>(HandleTableColumn::ObjectName),
            QStringLiteral("对象名未查询，可能受预算、类型白名单或开关限制。"));
    }
    return item;
}

void HandleDock::scheduleProcessIconResolution(
    const QVector<qulonglong>& sourceRowIndices,
    const QVector<QTreeWidgetItem*>& itemList)
{
    if (sourceRowIndices.size() != itemList.size() || sourceRowIndices.isEmpty())
    {
        return;
    }

    QVector<HandleProcessIconRequest> requests;
    QHash<QString, QVector<QTreeWidgetItem*>> itemsByIdentity;
    for (qsizetype itemIndex = 0; itemIndex < sourceRowIndices.size(); ++itemIndex)
    {
        const std::size_t sourceRowIndex =
            static_cast<std::size_t>(sourceRowIndices.at(itemIndex));
        if (sourceRowIndex >= m_allRows.size() || itemList.at(itemIndex) == nullptr)
        {
            continue;
        }
        const HandleRow& row = m_allRows[sourceRowIndex];
        const QString identityKey =
            buildHandleProcessIdentityKey(row.processId, row.processCreationTime);
        if (identityKey.isEmpty() || m_processIconCacheByIdentity.contains(identityKey))
        {
            continue;
        }
        QVector<QTreeWidgetItem*>& targetItems = itemsByIdentity[identityKey];
        if (targetItems.isEmpty())
        {
            requests.push_back(HandleProcessIconRequest{
                identityKey,
                row.processId,
                row.processCreationTime });
        }
        targetItems.push_back(itemList.at(itemIndex));
    }
    if (requests.isEmpty())
    {
        return;
    }

    const std::uint64_t generation = m_processIconResolveGeneration;
    const std::shared_ptr<std::atomic_bool> cancelFlag = m_processIconResolveCancelFlag;
    const QPointer<HandleDock> guardedSelf(this);
    auto* task = QRunnable::create(
        [guardedSelf, generation, cancelFlag, requests, itemsByIdentity]()
        {
            const HandleProcessIconComScope iconWorkerComScope;
            QVector<HandleProcessIconResult> results;
            results.reserve(requests.size());
            for (const HandleProcessIconRequest& request : requests)
            {
                if (guardedSelf == nullptr ||
                    (cancelFlag != nullptr && cancelFlag->load(std::memory_order_relaxed)))
                {
                    return;
                }
                const QString imagePath = queryHandleProcessImagePathInWorker(
                    request.processId,
                    request.processCreationTime);
                results.push_back(HandleProcessIconResult{
                    request.identityKey,
                    extractHandleProcessIconImage(imagePath) });
            }
            QMetaObject::invokeMethod(
                QCoreApplication::instance(),
                [guardedSelf, generation, results, itemsByIdentity]()
                {
                    if (guardedSelf == nullptr ||
                        guardedSelf->m_processIconResolveGeneration != generation)
                    {
                        return;
                    }
                    for (const HandleProcessIconResult& result : results)
                    {
                        const QIcon icon = result.iconImage.isNull()
                            ? handleProcessPlaceholderIcon()
                            : QIcon(QPixmap::fromImage(result.iconImage));
                        if (guardedSelf->m_processIconCacheByIdentity.size() >=
                            kHandleProcessIconCacheLimit)
                        {
                            guardedSelf->m_processIconCacheByIdentity.erase(
                                guardedSelf->m_processIconCacheByIdentity.begin());
                        }
                        guardedSelf->m_processIconCacheByIdentity.insert(result.identityKey, icon);
                        const auto itemIt = itemsByIdentity.constFind(result.identityKey);
                        if (itemIt == itemsByIdentity.constEnd())
                        {
                            continue;
                        }
                        for (QTreeWidgetItem* item : itemIt.value())
                        {
                            if (item != nullptr && item->treeWidget() == guardedSelf->m_tableWidget)
                            {
                                item->setIcon(
                                    static_cast<int>(HandleTableColumn::ProcessName),
                                    icon);
                            }
                        }
                    }
                },
                Qt::QueuedConnection);
        });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}


void HandleDock::rebuildObjectTypeTable(const QString& filterKeyword)
{
    m_objectTypeTable->clear();
    std::size_t visibleCount = 0;
    for (std::size_t sourceIndex = 0; sourceIndex < m_objectTypeRows.size(); ++sourceIndex)
    {
        const HandleObjectTypeEntry& row = m_objectTypeRows[sourceIndex];
        const bool matched = filterKeyword.trimmed().isEmpty()
            || row.typeNameText.contains(filterKeyword, Qt::CaseInsensitive)
            || QString::number(row.typeIndex).contains(filterKeyword, Qt::CaseInsensitive);
        if (!matched)
        {
            continue;
        }

        auto* item = new QTreeWidgetItem();
        item->setText(static_cast<int>(ObjectTypeTableColumn::TypeIndex), QString::number(row.typeIndex));
        item->setText(static_cast<int>(ObjectTypeTableColumn::TypeName), row.typeNameText);
        item->setText(static_cast<int>(ObjectTypeTableColumn::ObjectCount), QString::number(row.totalObjectCount));
        item->setText(static_cast<int>(ObjectTypeTableColumn::HandleCount), QString::number(row.totalHandleCount));
        item->setText(static_cast<int>(ObjectTypeTableColumn::AccessMask), formatHex(row.validAccessMask, 0));
        item->setText(static_cast<int>(ObjectTypeTableColumn::SecurityRequired), boolText(row.securityRequired));
        item->setText(static_cast<int>(ObjectTypeTableColumn::MaintainCount), boolText(row.maintainHandleCount));
        item->setData(static_cast<int>(ObjectTypeTableColumn::TypeIndex), Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        m_objectTypeTable->addTopLevelItem(item);
        ++visibleCount;
    }

    if (m_objectTypeTable->topLevelItemCount() > 0)
    {
        m_objectTypeTable->setCurrentItem(m_objectTypeTable->topLevelItem(0));
    }
    else
    {
        m_objectTypeDetailTable->clear();
    }

    kLogEvent rebuildTypeEvent;
    dbg << rebuildTypeEvent
        << "[HandleDock] rebuildObjectTypeTable: total="
        << m_objectTypeRows.size()
        << ", visible="
        << visibleCount
        << ", filter="
        << filterKeyword.toStdString()
        << eol;
}

HandleDock::HandleRefreshOptions HandleDock::collectHandleRefreshOptions() const
{
    HandleRefreshOptions options{};
    options.resolveObjectName = m_filterDocument.globalSettings.resolveObjectName;
    options.nameResolveBudget = m_filterDocument.globalSettings.nameResolveBudget;
    switch (m_filterDocument.globalSettings.enumMode)
    {
    case ks::handle::FilterEnumMode::UserSnapshot:
        options.enumMode = HandleEnumMode::UserSnapshot;
        break;
    case ks::handle::FilterEnumMode::KernelHandleTable:
        options.enumMode = HandleEnumMode::KernelHandleTable;
        break;
    case ks::handle::FilterEnumMode::DuplicateHandle:
    default:
        options.enumMode = HandleEnumMode::DuplicateHandle;
        break;
    }
    if (options.enumMode == HandleEnumMode::UserSnapshot)
    {
        options.resolveObjectName = false;
        options.nameResolveBudget = 0;
    }
    options.typeNameCacheByIndex = m_typeNameCacheByIndex;
    options.typeNameMapFromObjectTab = m_typeNameMapByIndexFromObjectTab;

    // 仅临时单 PID 筛选下收窄后台枚举范围。持久规则始终共享完整快照，
    // 规则内容变化只重新匹配内存数据，不触发系统枚举。
    if (m_temporaryFilterActive && m_temporaryFilterRule.processIds.size() == 1)
    {
        options.hasPidFilter = true;
        options.pidFilter = m_temporaryFilterRule.processIds.front();
    }

    return options;
}
