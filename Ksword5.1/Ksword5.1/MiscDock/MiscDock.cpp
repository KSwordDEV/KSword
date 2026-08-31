#include "MiscDock.h"

#include "BootEditor/BootEditorTab.h"
#include "ApplicationControlPage.h"
#include "ContextMenuCleaner/ContextMenuCleanerTab.h"
#include "DisableDse/DisableDsePage.h"
#include "Experimental/BugcheckGuardPage.h"
#include "DiskEditor/DiskEditorTab.h"
#include "RenderBenchmark/RenderBenchmarkPage.h"
#include "SoundSource/SoundSourcePage.h"
#include "SystemTime/SystemTimePage.h"
#include "VirtualLocation/VirtualLocationPage.h"

// 扫描器 / 转储分析 / 插件原本是三个顶层 Dock，为精简 dock 栏入口已并入本页。
#include "../MinidumpDock/MinidumpDock.h"
#include "../ScannerDock/ScannerDock.h"
#include "../PluginHost.h"

#include "../Internationalization/LanguageManager.h"
#include <QIcon>
#include <QTabBar>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

namespace
{
    // buildHostLayout：
    // - 作用：为页签占位控件建立统一的承载布局，边距与间距全部归零，
    //   让真实子页占满原来直接作为页签页时的同一块区域；
    // - 入参 hostWidget：页签占位控件，必须非空；
    // - 返回：已挂到占位控件上的垂直布局。
    QVBoxLayout* buildHostLayout(QWidget* hostWidget)
    {
        QVBoxLayout* hostLayout = new QVBoxLayout(hostWidget);
        hostLayout->setContentsMargins(0, 0, 0, 0);
        hostLayout->setSpacing(0);
        return hostLayout;
    }
}

MiscDock::MiscDock(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();

    kLogEvent initEvent;
    info << initEvent << "[MiscDock] 杂项页面初始化完成。" << eol;
}

void MiscDock::initializeUi()
{
    // 根布局负责承载整个“杂项”容器。
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(0, 0, 0, 0);
    m_rootLayout->setSpacing(0);

    // 主 Tab 承载所有杂项工具，保持 Dock 外层只暴露一个统一入口。
    m_mainTabWidget = new QTabWidget(this);
    m_mainTabWidget->setObjectName(QStringLiteral("ksMiscDockMainTab"));
    m_rootLayout->addWidget(m_mainTabWidget, 1);

    // 懒加载策略：
    // - 七个页签先用空占位控件占住，页签顺序、标题与图标与旧实现逐一对齐；
    // - 真实子页在页签第一次被选中时才构造，避免“杂项”页一被创建就把磁盘、
    //   Shell 关联、应用控制等重页面全部建出来（每一个都会自带首轮枚举）。
    m_bootEditorHostWidget = new QWidget(m_mainTabWidget);
    m_soundSourceHostWidget = new QWidget(m_mainTabWidget);
    m_systemTimeHostWidget = new QWidget(m_mainTabWidget);
    m_virtualLocationHostWidget = new QWidget(m_mainTabWidget);
    m_bugcheckGuardHostWidget = new QWidget(m_mainTabWidget);
    m_disableDseHostWidget = new QWidget(m_mainTabWidget);
    m_contextMenuCleanerHostWidget = new QWidget(m_mainTabWidget);
    m_diskEditorHostWidget = new QWidget(m_mainTabWidget);
    m_applicationControlHostWidget = new QWidget(m_mainTabWidget);
    m_renderBenchmarkHostWidget = new QWidget(m_mainTabWidget);
    m_scannerHostWidget = new QWidget(m_mainTabWidget);
    m_minidumpHostWidget = new QWidget(m_mainTabWidget);
    m_pluginHostWidget = new QWidget(m_mainTabWidget);
    // 插件宿主必须能被主题样式单独锚定：Tab 插件用原生子窗口承载，
    // 父链一旦被刷成透明，插件画面就会变成黑块或不刷新。
    m_pluginHostWidget->setObjectName(QStringLiteral("ksMiscPluginHost"));

    m_bootEditorTabIndex = m_mainTabWidget->addTab(
        m_bootEditorHostWidget,
        QStringLiteral("引导"));

    // 声音来源页：
    // - R3 连续采样 Core Audio 输出会话峰值并归因到 PID；
    // - R0 复用进程 Cross-View 与 Runtime Detail 交叉核验候选 PID。
    m_soundSourceTabIndex = m_mainTabWidget->addTab(
        m_soundSourceHostWidget,
        QIcon(QStringLiteral(":/Icon/sound_source.svg")),
        QStringLiteral("声音来源"));

    // 系统全局变速页：
    // - 通过 ArkDriverClient 控制 R0 性能计数器连续倍率映射；
    // - 永久展示失稳风险，并在每次启用前执行双重确认。
    m_systemTimeTabIndex = m_mainTabWidget->addTab(
        m_systemTimeHostWidget,
        QIcon(QStringLiteral(":/Icon/system_time.svg")),
        QStringLiteral("系统变速"));

    // 虚拟定位页：
    // - 把任意坐标写成 Windows 位置服务的“系统默认位置”，R3 被 ACL 拒绝时回退 R0 注册表 IOCTL；
    // - 只影响走 Windows 定位 API 的调用方，页面内长期展示这条生效边界。
    m_virtualLocationTabIndex = m_mainTabWidget->addTab(
        m_virtualLocationHostWidget,
        QIcon(QStringLiteral(":/Icon/virtual_location.svg")),
        QStringLiteral("虚拟定位"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_mainTabWidget,
        m_virtualLocationHostWidget,
        QStringLiteral("misc.virtual_location.tab"),
        QStringLiteral("虚拟定位"));

    // 蓝屏诊断入口默认隐藏。R3 配置自动安装或本次成功安装后，MainWindow 才会显式显示它。
    m_bugcheckGuardTabIndex = m_mainTabWidget->addTab(
        m_bugcheckGuardHostWidget,
        QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
        QStringLiteral("蓝屏诊断"));
    // i18n 绑定挂在占位控件上：LanguageManager 按 QTabWidget::widget(index) 回读属性，
    // 占位控件才是常驻页签页，真实子页只是它的孩子。
    ks::i18n::LanguageManager::instance().bindTab(
        m_mainTabWidget,
        m_bugcheckGuardHostWidget,
        QStringLiteral("misc.bugcheck_diagnostics.tab"),
        QStringLiteral("蓝屏诊断"));
    setBugcheckDiagnosticsVisible(false);

    // 驱动签名强制页：
    // - 运行时反汇编定位 CI.dll!g_CiOptions，用 R0 事务化内核写临时关闭 DSE；
    // - 写入前校验读回值的强制签名位与系统自报状态自洽，
    //   HVCI 开启时直接禁用操作，页面析构还会兜底把原值写回。
    m_disableDseTabIndex = m_mainTabWidget->addTab(
        m_disableDseHostWidget,
        QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
        QStringLiteral("disable dse"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_mainTabWidget,
        m_disableDseHostWidget,
        QStringLiteral("misc.disable_dse.tab"),
        QStringLiteral("disable dse"));

    // Shell 关联管理页：
    // - 覆盖右键菜单、URL 绑定、打开方式和 Explorer 第三方主页项；
    // - 仅在用户确认后删除表格绑定的精确注册表子树或值。
    m_contextMenuCleanerTabIndex = m_mainTabWidget->addTab(
        m_contextMenuCleanerHostWidget,
        QIcon(QStringLiteral(":/Icon/log_track.svg")),
        QStringLiteral("Shell 关联管理"));

    // 磁盘编辑页：
    // - 参考 DiskGenius 类工具布局，提供横向柱形分区图；
    // - 默认只读，用户显式解锁后才允许写回物理磁盘。
    m_diskEditorTabIndex = m_mainTabWidget->addTab(
        m_diskEditorHostWidget,
        QIcon(QStringLiteral(":/Icon/disk_storage.svg")),
        QStringLiteral("磁盘编辑"));

    // 应用控制页：
    // - 第一版仅做 AppLocker / WDAC / Defender / 事件日志只读诊断；
    // - 不修改、不删除、不禁用任何策略。
    m_applicationControlTabIndex = m_mainTabWidget->addTab(
        m_applicationControlHostWidget,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("应用控制"));

    // 渲染基准页：
    // - 量化主窗口整树重绘、拖动掉帧、DWM 合成与目标窗口响应；
    // - 全部测量都在 UI 线程执行，只在用户显式点击时运行。
    m_renderBenchmarkTabIndex = m_mainTabWidget->addTab(
        m_renderBenchmarkHostWidget,
        QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
        QStringLiteral("渲染基准"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_mainTabWidget,
        m_renderBenchmarkHostWidget,
        QStringLiteral("misc.render_benchmark.tab"),
        QStringLiteral("渲染基准"));

    // 以下三页原本是顶层 Dock，为精简 dock 栏入口并入杂项：
    // - 页签顺序沿用它们在原 dock 栏中的相对先后（扫描器 -> 转储分析 -> 插件）；
    // - 三页都保持懒加载，打开“杂项”本身不会把扫描器/转储解析/插件宿主一起建出来。
    m_scannerTabIndex = m_mainTabWidget->addTab(
        m_scannerHostWidget,
        QIcon(QStringLiteral(":/Icon/disk_analyze.svg")),
        QStringLiteral("扫描器"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_mainTabWidget,
        m_scannerHostWidget,
        QStringLiteral("misc.scanner.tab"),
        QStringLiteral("扫描器"));

    m_minidumpTabIndex = m_mainTabWidget->addTab(
        m_minidumpHostWidget,
        QIcon(QStringLiteral(":/Icon/log_track.svg")),
        QStringLiteral("转储分析"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_mainTabWidget,
        m_minidumpHostWidget,
        QStringLiteral("misc.minidump.tab"),
        QStringLiteral("转储分析"));

    m_pluginTabIndex = m_mainTabWidget->addTab(
        m_pluginHostWidget,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("插件"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_mainTabWidget,
        m_pluginHostWidget,
        QStringLiteral("misc.plugin.tab"),
        QStringLiteral("插件"));

    // 页签切换：按需初始化对应子页。
    connect(
        m_mainTabWidget,
        &QTabWidget::currentChanged,
        this,
        [this](const int tabIndex)
        {
            ensureTabInitialized(tabIndex);
        });

    // 首屏页必须同步初始化：
    // - ADS 可能直接把“杂项”恢复为当前 Dock，此时不会再触发一次 currentChanged；
    // - 只初始化当前页，其余页面仍然保持懒加载。
    ensureTabInitialized(m_mainTabWidget->currentIndex());

    // 再补一次 0ms 兜底，覆盖主题/ADS 延迟恢复导致 currentIndex 稍后才变化的情况。
    QTimer::singleShot(0, this, [this]()
        {
            ensureTabInitialized(m_mainTabWidget != nullptr ? m_mainTabWidget->currentIndex() : -1);
        });
}

void MiscDock::ensureTabInitialized(const int tabIndex)
{
    if (tabIndex < 0)
    {
        return;
    }

    if (tabIndex == m_bootEditorTabIndex)
    {
        initializeBootEditorTab();
        return;
    }
    if (tabIndex == m_soundSourceTabIndex)
    {
        initializeSoundSourcePage();
        return;
    }
    if (tabIndex == m_systemTimeTabIndex)
    {
        initializeSystemTimePage();
        return;
    }
    if (tabIndex == m_virtualLocationTabIndex)
    {
        initializeVirtualLocationPage();
        return;
    }
    if (tabIndex == m_bugcheckGuardTabIndex)
    {
        if (m_bugcheckDiagnosticsVisible)
        {
            initializeBugcheckGuardPage();
        }
        return;
    }
    if (tabIndex == m_disableDseTabIndex)
    {
        initializeDisableDsePage();
        return;
    }
    if (tabIndex == m_contextMenuCleanerTabIndex)
    {
        initializeContextMenuCleanerTab();
        return;
    }
    if (tabIndex == m_diskEditorTabIndex)
    {
        initializeDiskEditorTab();
        return;
    }
    if (tabIndex == m_applicationControlTabIndex)
    {
        initializeApplicationControlPage();
        return;
    }
    if (tabIndex == m_renderBenchmarkTabIndex)
    {
        initializeRenderBenchmarkPage();
        return;
    }
    if (tabIndex == m_scannerTabIndex)
    {
        initializeScannerPage();
        return;
    }
    if (tabIndex == m_minidumpTabIndex)
    {
        initializeMinidumpPage();
        return;
    }
    if (tabIndex == m_pluginTabIndex)
    {
        initializePluginPage();
        return;
    }
}

void MiscDock::activateTabByIndex(const int tabIndex)
{
    if (m_mainTabWidget == nullptr || tabIndex < 0 || tabIndex >= m_mainTabWidget->count())
    {
        return;
    }

    // 先构造再切换：currentChanged 在目标已经是当前页时不会触发，
    // 直接 setCurrentIndex 可能让调用方拿到尚未初始化的占位控件。
    ensureTabInitialized(tabIndex);
    m_mainTabWidget->setCurrentIndex(tabIndex);
}

MinidumpDock* MiscDock::activateMinidumpTab()
{
    activateTabByIndex(m_minidumpTabIndex);
    return m_minidumpPage;
}

void MiscDock::setBugcheckDiagnosticsVisible(const bool visible)
{
    m_bugcheckDiagnosticsVisible = visible;
    if (m_mainTabWidget == nullptr || m_bugcheckGuardTabIndex < 0)
    {
        return;
    }

    // 隐藏页签不移除占位控件，索引保持稳定，重新显示后仍可复用已构造的页面状态。
    QTabBar* const tabBar = m_mainTabWidget->tabBar();
    if (tabBar != nullptr)
    {
        tabBar->setTabVisible(m_bugcheckGuardTabIndex, visible);
    }
    if (!visible && m_mainTabWidget->currentIndex() == m_bugcheckGuardTabIndex)
    {
        m_mainTabWidget->setCurrentIndex(m_bootEditorTabIndex);
    }
    if (visible && m_mainTabWidget->currentIndex() == m_bugcheckGuardTabIndex)
    {
        ensureTabInitialized(m_bugcheckGuardTabIndex);
    }
}

void MiscDock::initializeBootEditorTab()
{
    if (m_bootEditorHostWidget == nullptr || m_bootEditorTab != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_bootEditorHostWidget);
    m_bootEditorTab = new BootEditorTab(m_bootEditorHostWidget);
    hostLayout->addWidget(m_bootEditorTab, 1);
}

void MiscDock::initializeSoundSourcePage()
{
    if (m_soundSourceHostWidget == nullptr || m_soundSourcePage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_soundSourceHostWidget);
    m_soundSourcePage = new ks::misc::SoundSourcePage(0U, 0U, m_soundSourceHostWidget);
    hostLayout->addWidget(m_soundSourcePage, 1);
}

void MiscDock::initializeSystemTimePage()
{
    if (m_systemTimeHostWidget == nullptr || m_systemTimePage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_systemTimeHostWidget);
    m_systemTimePage = new ks::misc::SystemTimePage(m_systemTimeHostWidget);
    hostLayout->addWidget(m_systemTimePage, 1);
}

void MiscDock::initializeVirtualLocationPage()
{
    if (m_virtualLocationHostWidget == nullptr || m_virtualLocationPage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_virtualLocationHostWidget);
    m_virtualLocationPage = new ks::misc::VirtualLocationPage(m_virtualLocationHostWidget);
    hostLayout->addWidget(m_virtualLocationPage, 1);
}

void MiscDock::initializeBugcheckGuardPage()
{
    if (m_bugcheckGuardHostWidget == nullptr || m_bugcheckGuardPage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_bugcheckGuardHostWidget);
    m_bugcheckGuardPage = new ks::misc::BugcheckGuardPage(m_bugcheckGuardHostWidget);
    hostLayout->addWidget(m_bugcheckGuardPage, 1);
}

void MiscDock::initializeDisableDsePage()
{
    if (m_disableDseHostWidget == nullptr || m_disableDsePage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_disableDseHostWidget);
    m_disableDsePage = new ks::misc::DisableDsePage(m_disableDseHostWidget);
    hostLayout->addWidget(m_disableDsePage, 1);
}

void MiscDock::initializeContextMenuCleanerTab()
{
    if (m_contextMenuCleanerHostWidget == nullptr || m_contextMenuCleanerTab != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_contextMenuCleanerHostWidget);
    m_contextMenuCleanerTab = new ks::misc::ContextMenuCleanerTab(m_contextMenuCleanerHostWidget);
    hostLayout->addWidget(m_contextMenuCleanerTab, 1);
}

void MiscDock::initializeDiskEditorTab()
{
    if (m_diskEditorHostWidget == nullptr || m_diskEditorTab != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_diskEditorHostWidget);
    m_diskEditorTab = new ks::misc::DiskEditorTab(m_diskEditorHostWidget);
    hostLayout->addWidget(m_diskEditorTab, 1);
}

void MiscDock::initializeApplicationControlPage()
{
    if (m_applicationControlHostWidget == nullptr || m_applicationControlPage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_applicationControlHostWidget);
    m_applicationControlPage = new ks::misc::ApplicationControlPage(m_applicationControlHostWidget);
    hostLayout->addWidget(m_applicationControlPage, 1);
}

void MiscDock::initializeRenderBenchmarkPage()
{
    if (m_renderBenchmarkHostWidget == nullptr || m_renderBenchmarkPage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_renderBenchmarkHostWidget);
    m_renderBenchmarkPage = new ks::misc::RenderBenchmarkPage(m_renderBenchmarkHostWidget);
    hostLayout->addWidget(m_renderBenchmarkPage, 1);
}

void MiscDock::initializeScannerPage()
{
    if (m_scannerHostWidget == nullptr || m_scannerPage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_scannerHostWidget);
    m_scannerPage = new ScannerDock(m_scannerHostWidget);
    hostLayout->addWidget(m_scannerPage, 1);
}

void MiscDock::initializeMinidumpPage()
{
    if (m_minidumpHostWidget == nullptr || m_minidumpPage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_minidumpHostWidget);
    m_minidumpPage = new MinidumpDock(m_minidumpHostWidget);
    hostLayout->addWidget(m_minidumpPage, 1);
}

void MiscDock::initializePluginPage()
{
    if (m_pluginHostWidget == nullptr || m_pluginPage != nullptr)
    {
        return;
    }

    QVBoxLayout* const hostLayout = buildHostLayout(m_pluginHostWidget);
    m_pluginPage = ks::plugin_host::createTabPluginContainer(m_pluginHostWidget);
    hostLayout->addWidget(m_pluginPage, 1);
}
