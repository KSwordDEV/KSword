// memwb_ui_tests.cpp
// 作用：HexCanvas 离屏验证夹具的入口。
// 夹具链接真实的 HexCanvas 与 Phase 0 的逻辑类（HexViewport / MemoryDiffOverlay / MemoryTargetSession），
// 用 QTest 模拟真实鼠标与键盘事件离屏驱动画布，断言行为，保存截图，并运行渲染基准。
//
// 用法：memwb_ui_tests.exe [--shots <目录>] [--bench <结果文件>] [--skip-bench]
// 退出码：0 全部通过；1 有断言失败。
//
// 文件分工：
//   memwb_ui_common.*       断言计数、主题、测试数据、记录型提供者
//   memwb_ui_tests.View.cpp 显示/选区/键盘/滚动/页协议/超大地址
//   memwb_ui_tests.Edit.cpp 编辑/粘贴/填充/拒绝/复制/只读/右键菜单/格式化
//   memwb_ui_render.cpp     主题切换、变化着色可读性、截图
//   memwb_ui_bench.cpp      渲染基准与旧机制对照
//   memwb_ui_inspector.cpp / memwb_ui_tests.Inspector*.cpp  解释器面板（显示、编辑、截图与基准）
//   memwb_ui_tests.Signals*.cpp  第二轮接口补全：contentChanged / editableChanged / stageBytes /
//                           视口坐标命中 / 不可读占位符 / 面板无定时器
//   memwb_ui_tests.Segmented.cpp / .CachedRange.cpp / .IconAliases.cpp  Phase 3 WP-0：分段按钮禁用段、
//                           HexCanvas::copyCachedRange、memwb_* 图标别名（见 memwb_ui_common.h 末尾）
//   memwb_ui_hexview.* / memwb_ui_tests.HexView*.cpp  HexView 复合控件（见 memwb_ui_hexview.h）
//   memwb_ui_tests.HexView.Hosts.cpp                原生缓冲宿主的窗口边界和生命周期。
//   memwb_ui_tests.IoMapping.*  M-1：WorkbenchIoMapping 三个纯映射函数（真实端口的结果翻译）的分支覆盖

#include "memwb_ui_common.h"
#include "memwb_ui_hexview.h"
#include "memwb_ui_tests.IoMapping.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFontDatabase>

#include <iostream>

namespace
{
    // Arg：读取命令行里 --name value 形式的参数。
    // 传入：参数个数与数组、参数名、默认值；传出：值。
    QString Arg(int argc, char** argv, const char* name, const QString& defaultValue)
    {
        for (int index = 1; index + 1 < argc; ++index)
        {
            if (QString::fromLocal8Bit(argv[index]) == QString::fromLatin1(name))
            {
                return QString::fromLocal8Bit(argv[index + 1]);
            }
        }
        return defaultValue;
    }

    // Flag：命令行里是否出现某个开关。
    bool Flag(int argc, char** argv, const char* name)
    {
        for (int index = 1; index < argc; ++index)
        {
            if (QString::fromLocal8Bit(argv[index]) == QString::fromLatin1(name))
            {
                return true;
            }
        }
        return false;
    }
}

int main(int argc, char** argv)
{
    // 离屏平台：没有显式指定时强制 offscreen，保证无人值守也能跑。
    if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
    {
        qputenv("QT_QPA_PLATFORM", "offscreen");
    }
    QApplication app(argc, argv);

    // 字体：Windows offscreen 平台默认没有系统字体，需显式加载中文字体与 Consolas，否则缺字或回退成怪字体。
    const int chineseFont = QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
    const int monoFont = QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/consola.ttf"));
    memwb_test::Report(chineseFont >= 0, "Chinese font loaded", __FILE__, __LINE__, QString());
    memwb_test::Report(monoFont >= 0, "Consolas font loaded", __FILE__, __LINE__, QString());
    QFont appFont(QStringLiteral("Microsoft YaHei UI"));
    appFont.setPointSize(9);
    app.setFont(appFont);

    const QString shotsDir = Arg(argc, argv, "--shots", QStringLiteral(".codex-tmp/memwb-ui/shots"));
    const QString benchFile = Arg(argc, argv, "--bench", QStringLiteral(".codex-tmp/memwb-ui/bench.txt"));

    QElapsedTimer total;
    total.start();

    // 基准放在最前面：进程内第一块画布的构造耗时才有"首次"的意义。
    if (!Flag(argc, argv, "--skip-bench"))
    {
        memwb_test::RunBenchmarks(benchFile);
    }
    memwb_test::RunViewTests();
    memwb_test::RunCompareContractTests();
    memwb_test::RunEditTests();
    memwb_test::RunRenderTests(shotsDir);
    memwb_test::RunInspectorTests(shotsDir);
    memwb_test::RunSignalTests(shotsDir);
    // Phase 3 WP-0：分段按钮禁用段、页缓存只读导出、图标别名。
    memwb_test::RunSegmentedTests();
    memwb_test::RunCachedRangeTests();
    memwb_test::RunIconAliasTests();
    // 十六进制自适应行宽（视口宽度驱动、锚点、不重读、手动优先、联动触发）、最小高度与字号缩放。
    memwb_test::RunRowFitTests();
    // HexView 复合控件（工具栏 / 查找 / 跳转 / 导出 / 兼容层）：截图单独放在 shots-hexview 子目录。
    memwb_test::RunHexViewTests(QDir(shotsDir).filePath(QStringLiteral("../shots-hexview")));
    // M-1：WorkbenchIoMapping 三个纯映射函数的分支覆盖（见 memwb_ui_tests.IoMapping.cpp）。
    memwb_test::RunIoMappingTests();

    std::cout << "memwb_ui_tests: " << memwb_test::g_checks << " checks, "
              << memwb_test::g_failures << " failures, "
              << (total.elapsed() / 1000.0) << " s" << std::endl;
    return memwb_test::g_failures == 0 ? 0 : 1;
}
