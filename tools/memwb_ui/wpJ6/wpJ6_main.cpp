// ============================================================
// wpJ6_main.cpp
// 作用：WP-J6 离屏验证夹具的进程入口。构造 QApplication（本包需要真实窗口
//       几何与截图，比 QCoreApplication 更合适；画布/控件渲染仍走
//       QT_QPA_PLATFORM=offscreen，不需要真实显示设备）、依次调用各组测试、
//       按汇总格式打印 "wpJ6_tests: N checks, M failures"。
// ============================================================

#include "wpJ6_common.h"

#include "../../../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"

#include <QAction>
#include <QApplication>
#include <QDir>
#include <QFont>
#include <QFontDatabase>
#include <QLineEdit>
#include <QMenu>
#include <QSettings>
#include <QStackedWidget>
#include <QToolButton>
#include <QThread>

#include <cstdio>

namespace wpj6_test
{
    void RunIdentityTests();
    void RunEmbeddedTests();
    void RunActionsTests();
    void RunGateTests();
    void RunWriteTests();
    void RunNavTests();
    void RunVisualTests();
    // 第二轮独立复核补测（wpJ6_tests.Review2*.cpp）。
    void RunReview2TestsA();
    void RunReview2TestsB();
    void RunReview2TestsC();
    void RunReview2FixTests();
    // 波 4：confirmQuit（主窗口关闭前的最后一次询问）专项测试。
    void RunQuitTests();
    void RunEntry3bTests();
    void RunNarrowTests();
    void RunDarkLabelTests();
    void RunChromeTests();
    // 十六进制自适应（行宽/缩放/视图菜单/持久化）与 Dock 页面自适应。
    // RunRowFitTests 按中文文字找菜单项，必须排在 RunI18nSmokeTest 之前；
    // RunRowFitI18nTests 要在 en-US 下检查无汉字，必须排在 RunI18nSmokeTest 之后。
    void RunRowFitTests();
    void RunRowFitI18nTests();
    void RunDockFillTests();
    // 反汇编/文本/对比三个子页的自动跳转（跟随十六进制选区/起始模块）。
    void RunSubPageTests();
    void RunMemoryDebugTests();

    namespace
    {
        // HasHanCharacter：本函数只服务 RunI18nSmokeTest 的"无汉字"断言，判据
        // 是 Unicode CJK 统一表意文字区（U+4E00-U+9FFF）——够覆盖本文件涉及
        // 的全部简体中文文案，不需要处理扩展区（目标内容/进程名/地址等用户
        // 数据不受本断言约束，调用方自己决定要不要对哪些文本调用本函数）。
        bool HasHanCharacter(const QString& text)
        {
            for (const QChar ch : text)
            {
                const uint codePoint = ch.unicode();
                if (codePoint >= 0x4E00U && codePoint <= 0x9FFFU)
                {
                    return true;
                }
            }
            return false;
        }
    }

    // RunI18nSmokeTest（修复缺陷 6）：链接真实 LanguageManager、
    // initialize("en-US")，对视图的标准控件可见文本（toolTip/占位符/右键
    // 菜单项）断言翻译生效、不含汉字——此前本包全部用 Qt 的 tr()（本项目
    // 不使用 tr()，运行期翻译走 LanguageManager 的整树扫描/ks::i18n::
    // sourceText，不是 Qt 自带的 QTranslator），从未在真实语言包环境下实测
    // 验证过（见实现报告 §7 第 2 条）。
    //
    // 必须整个 main() 的最后一组断言——initialize("en-US") 之后进程里再也
    // 不会切回中文（与 wpG_tests.Review2.cpp 的 N2 i18n smoke test 同一
    // 惯例），任何排在它之后的代码都不能再假定界面文字是中文。
    void RunI18nSmokeTest()
    {
        QString initError;
        const bool initialized =
            ks::i18n::LanguageManager::instance().initialize(QStringLiteral("en-US"), &initError);
        WPJ6_CHECK_NOTE(
            initialized, QStringLiteral("LanguageManager::initialize(en-US) failed: %1").arg(initError));
        if (!initialized)
        {
            return;
        }

        Harness harness;
        harness.AttachProcess();
        PumpUntil([&]() { return true; }, 10);
        auto* view = harness.view.get();
        // LanguageManager 的运行期扫描经 QTimer::singleShot(0, ...) 延后到下一次
        // 事件循环（见 scheduleRuntimeTranslation 的实现），不是同步生效；必须
        // show() + 泵事件循环，让 QEvent::Show/PolishRequest/ActionAdded 真正
        // 触发过一轮扫描之后，才能读到翻译后的值（第一版测试在这一步漏了
        // show()+pump，读到的是扫描还没来得及跑的原始中文，误判成"翻译未生效"
        // ——这是测试本身的缺陷，不是生产代码的缺陷，已修正）。
        view->resize(900, 700);
        view->show();
        PumpFor(150);

        // 工具按钮 toolTip：只查本类自己直接拥有的工具按钮（FindDirectChildrenOnly），
        // 不扫进 Int3PatchPanel/AddressBookPanel/CodeEditorWidget 等其它包自己的
        // 控件——那些不在本任务书允许修改的范围内，混进同一个断言只会制造
        // 测不出真相的噪音（它们是否已翻译与本次修复无关）。
        int checkedToolTips = 0;
        for (auto* button : view->findChildren<QToolButton*>(QString(), Qt::FindDirectChildrenOnly))
        {
            if (button->toolTip().isEmpty())
            {
                continue;
            }
            ++checkedToolTips;
            WPJ6_CHECK_NOTE(
                !HasHanCharacter(button->toolTip()),
                QStringLiteral("按钮 toolTip 翻译后仍含汉字：%1").arg(button->toolTip()));
        }
        WPJ6_CHECK_NOTE(checkedToolTips > 0, QStringLiteral("未找到任何带 toolTip 的工具按钮，断言形同空转"));

        // 地址条占位符：同样只查本类直接拥有的输入框（addressEdit_）。
        int checkedPlaceholders = 0;
        for (auto* edit : view->findChildren<QLineEdit*>(QString(), Qt::FindDirectChildrenOnly))
        {
            if (edit->placeholderText().isEmpty())
            {
                continue;
            }
            ++checkedPlaceholders;
            WPJ6_CHECK_NOTE(
                !HasHanCharacter(edit->placeholderText()),
                QStringLiteral("输入框占位符翻译后仍含汉字：%1").arg(edit->placeholderText()));
        }
        WPJ6_CHECK_NOTE(checkedPlaceholders > 0, QStringLiteral("未找到任何带占位符的输入框，断言形同空转"));

        // 右键菜单：程序化打开（HexCanvas::buildContextMenu，与
        // wpJ5_tests.Wiring.cpp 同一手法）。HexCanvas 自己的既有菜单项（复制
        // 十六进制/ASCII 等）不在本任务书范围内，只检查本类
        // onHexPaneContextMenuAboutToShow 追加在末尾的那几项——它们的 ActionAdded
        // 事件同样需要泵一次事件循环才会被扫描到。
        auto* pane = view->hexPaneForTest();
        WPJ6_CHECK(WaitForStageable(pane, 0x08ULL));
        QMenu* menu = pane->canvas()->buildContextMenu(0x08ULL, true);
        WPJ6_CHECK(menu != nullptr);
        if (menu != nullptr)
        {
            PumpFor(100);
            const auto actions = menu->actions();
            constexpr int kAppendedByThisView = 4; // 添加到地址簿/写入字符串/从此处反汇编/int3 二选一
            const int startIndex = (actions.size() >= kAppendedByThisView)
                ? (actions.size() - kAppendedByThisView)
                : 0;
            int checkedActions = 0;
            for (int i = startIndex; i < actions.size(); ++i)
            {
                QAction* action = actions.at(i);
                if (action == nullptr || action->isSeparator())
                {
                    continue;
                }
                // "写入 int3 补丁"/"还原 int3 补丁"的词条早已登记进两个语言包
                // （第二轮复核核实），所以这里不再跳过它们——此前的跳过恰好把它们
                // 排除在"无汉字"断言之外。
                ++checkedActions;
                WPJ6_CHECK_NOTE(
                    !HasHanCharacter(action->text()),
                    QStringLiteral("右键菜单项翻译后仍含汉字：%1").arg(action->text()));
                if (!action->toolTip().isEmpty())
                {
                    WPJ6_CHECK_NOTE(
                        !HasHanCharacter(action->toolTip()),
                        QStringLiteral("右键菜单项 toolTip 翻译后仍含汉字：%1").arg(action->toolTip()));
                }
            }
            WPJ6_CHECK_NOTE(checkedActions >= 2, QStringLiteral("右键菜单项数量异常：%1").arg(checkedActions));
            delete menu;
        }

        // 第二轮复核 B5：int3 菜单项触发后，状态条"整串文字"（含 int3 反馈）在 en-US
        // 下也不得含汉字——这句话经 onInt3ResultMessage 拼进状态条私有成员，运行期整树
        // 扫描够不到，必须在源头翻译。安装、还原各断言一次。
        {
            const std::uint64_t int3Address = 0xB0ULL;
            WPJ6_CHECK(WaitForStageable(pane, int3Address));
            const auto toggleInt3 = [&]() {
                QMenu* int3Menu = pane->canvas()->buildContextMenu(int3Address, true);
                if (int3Menu == nullptr)
                {
                    return;
                }
                for (auto* action : int3Menu->actions())
                {
                    if (action->text().contains(QStringLiteral("int3")))
                    {
                        emit action->triggered();
                        break;
                    }
                }
                delete int3Menu;
            };
            auto* statusBar = view->statusBarForTest();
            toggleInt3();
            PumpFor(150);
            QString summary = statusBar->summaryText();
            WPJ6_CHECK_NOTE(summary.contains(QStringLiteral("int3")), QStringLiteral("安装后状态条应提到 int3：%1").arg(summary));
            WPJ6_CHECK_NOTE(
                !HasHanCharacter(summary), QStringLiteral("en-US 下 int3 写入反馈仍含汉字：%1").arg(summary));
            toggleInt3();
            PumpFor(150);
            summary = statusBar->summaryText();
            WPJ6_CHECK_NOTE(
                !HasHanCharacter(summary), QStringLiteral("en-US 下 int3 还原反馈仍含汉字：%1").arg(summary));
        }
        view->hide();

        // 状态条 NeedsAttach 提示（原复核补测 T22）：未附加目标时 openAt 返回 NeedsAttach，
        // 状态条整串文字在 en-US 下不含汉字。
        {
            Harness detached;   // 故意不 AttachProcess
            PumpUntil([]() { return true; }, 10);
            detached.view->resize(900, 700);
            detached.view->show();
            PumpFor(150);
            ks::ui::NavRequest request;
            request.address = 0x10ULL;
            WPJ6_CHECK(detached.view->openAt(request) == ks::ui::NavStatus::NeedsAttach);
            const QString summary = detached.view->statusBarForTest()->summaryText();
            WPJ6_CHECK_NOTE(
                !HasHanCharacter(summary), QStringLiteral("en-US 下 NeedsAttach 状态条仍含汉字：%1").arg(summary));
            detached.view->hide();
        }

        // 子页签存在性（自绘 HexViewSegmented 经 ks::i18n::sourceText 翻译，
        // 没有白盒访问器读回段文字，这里只核对页签结构本身没有崩）。
        WPJ6_CHECK(view->subTabStackForTest() != nullptr);
    }
}

int main(int argc, char** argv)
{
    // 本夹具启动的退出测试子进程不创建 GUI，不读取或写入任何其它进程。
    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == QStringLiteral("--memory-debug-worker"))
    {
        QThread::msleep(3000);
        return 0;
    }
    // WorkbenchSettings.cpp 的 QSettings 全部用默认构造（跟随
    // QCoreApplication 的 organizationName/applicationName）；不设置时两者
    // 为空串，QSettings 在某些环境下会报 status()!=NoError 导致读写全部退回
    // 默认值（本包 TestSettingsAuthorityOnlyAuthoritativeSaves 测试实测抓到：
    // SaveSubTab 之后紧接着 LoadSubTab 读不回刚写的值）。这里给一个与生产
    // 应用名不同的测试专用名字，既保证 QSettings 能正常工作，又不会与真实
    // KSword 应用的设置互相污染。
    QCoreApplication::setOrganizationName(QStringLiteral("KSwordWpJ6Fixture"));
    QCoreApplication::setApplicationName(QStringLiteral("wpJ6_tests"));
    QApplication app(argc, argv);

    // 设置存储隔离：QSettings 默认格式是注册表（HKCU），同名夹具的所有进程共享同一份——
    // 并行跑变异重放（或两次运行重叠）时，各进程对 sidebarVisible 等键的读写会互相覆盖，
    // 造成与被测代码无关的假失败（复核补测 TestSaved*Sidebar* 就这样踩过）。改成 exe
    // 同目录下的 ini 文件（每个进程/每份副本各用各的输出目录），启动时先清空，保证
    // 每次运行都从"全部默认值"开始，也不再污染用户注册表。
    {
        const QString settingsDir = QCoreApplication::applicationDirPath() + QStringLiteral("/settings");
        QDir(settingsDir).removeRecursively();
        QDir().mkpath(settingsDir);
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settingsDir);
    }

    // 字体：同 wpJ5/wpG/wpE 的既有修法——offscreen 平台默认没有系统字体，
    // 不显式加载会让截图里的中文全部变成缺字方块。找不到字体文件时只报出
    // 来，不让夹具因此失败（截图任务本身不依赖这个断言通过）。
    const int chineseFontId = QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
    if (chineseFontId < 0)
    {
        std::printf("wpJ6_tests: 警告——未能加载中文字体 C:/Windows/Fonts/msyh.ttc，"
                    "截图中的中文可能显示为缺字方块（已继续运行，不影响断言结果）\n");
    }
    else
    {
        QFont appFont(QStringLiteral("Microsoft YaHei UI"));
        appFont.setPointSize(9);
        app.setFont(appFont);
    }

    wpj6_test::ConfigureSharedOnce();

    wpj6_test::RunIdentityTests();
    wpj6_test::RunEmbeddedTests();
    wpj6_test::RunActionsTests();
    wpj6_test::RunGateTests();
    wpj6_test::RunWriteTests();
    wpj6_test::RunNavTests();
    wpj6_test::RunReview2TestsA();
    wpj6_test::RunReview2TestsB();
    wpj6_test::RunReview2TestsC();
    wpj6_test::RunReview2FixTests();
    wpj6_test::RunQuitTests();
    wpj6_test::RunEntry3bTests();
    wpj6_test::RunNarrowTests();
    wpj6_test::RunDarkLabelTests();
    wpj6_test::RunChromeTests();
    wpj6_test::RunRowFitTests();
    wpj6_test::RunDockFillTests();
    wpj6_test::RunSubPageTests();
    wpj6_test::RunMemoryDebugTests();
    wpj6_test::RunVisualTests();
    // 必须排在最后：initialize("en-US") 之后进程里再也不会切回中文。
    wpj6_test::RunI18nSmokeTest();
    // 依赖 en-US 已经初始化：检查英文界面下视图菜单/徽标/悬停说明里没有汉字。
    wpj6_test::RunRowFitI18nTests();

    std::printf("wpJ6_tests: %d checks, %d failures\n", wpj6_test::g_checks, wpj6_test::g_failures);
    return (wpj6_test::g_failures == 0) ? 0 : 1;
}
