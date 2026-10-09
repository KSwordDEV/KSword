#pragma once

// ============================================================
// memwb_ui_common.h
// 作用：HexCanvas 离屏验证夹具的公共设施——断言计数、主题切换、测试数据、记录型页提供者、
//       夹具构造与鼠标/键盘输入辅助。各 memwb_ui_*.cpp 共用，本头文件不属于主程序。
// ============================================================

#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexCanvas.h"
#include "../../Ksword5.1/Ksword5.1/theme.h"

#include <QByteArray>
#include <QColor>
#include <QImage>
#include <QPoint>
#include <QSize>
#include <QString>
#include <QtTest/QtTest>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace memwb_test
{
    // 断言计数：夹具自带的轻量断言框架（QTest 只用来模拟输入，不用来报告）。
    extern int g_checks;    // 已执行的断言数
    extern int g_failures;  // 失败的断言数

    // Report：记录一条断言结果，失败时向 stderr 打印位置与表达式。
    void Report(bool ok, const char* expression, const char* file, int line, const QString& note);

    // 断言宏：CHECK 只带表达式，CHECK_NOTE 额外带一段说明（通常是实际值）。
#define CHECK(expression) ::memwb_test::Report(static_cast<bool>(expression), #expression, __FILE__, __LINE__, QString())
#define CHECK_NOTE(expression, note) ::memwb_test::Report(static_cast<bool>(expression), #expression, __FILE__, __LINE__, (note))

    // ApplyTheme：切换深浅主题并同步应用调色板与 Fusion 样式，使滚动条等原生部件也跟随。
    // 传入：是否深色。
    void ApplyTheme(bool dark);

    // MakePattern：生成确定性的测试字节（避免全零，含可见 ASCII 与不可见字节）。
    // 传入：字节数、种子；传出：字节。
    QByteArray MakePattern(int size, int seed = 0);

    // Fixture：一块"画布 + 叠加层 + 静态数据"的夹具。overlay 先于 canvas 声明，保证 canvas 先析构。
    struct Fixture
    {
        ksword::memwb::MemoryDiffOverlay overlay;           // 暂存叠加层
        QByteArray data;                                    // 底层数据
        std::uint64_t base = 0;                             // 数据起始地址
        std::unique_ptr<ks::ui::HexCanvas> canvas;          // 被测画布
    };

    // MakeStaticFixture：构造夹具并显示。
    // 传入：数据起址、数据、是否可编辑、窗口大小、是否把数据载入叠加层基线。
    // 传出：夹具。可见页已由内置静态提供者同步回填。
    std::unique_ptr<Fixture> MakeStaticFixture(
        std::uint64_t base,
        const QByteArray& data,
        bool editable,
        const QSize& size,
        bool loadBaseline = true);

    // RecordingProvider：记录每次页请求，并允许测试在请求回调里检查画布状态。
    class RecordingProvider final : public ks::ui::IHexPageProvider
    {
    public:
        // Request：一次 RequestPages 调用的完整参数。
        struct Request
        {
            std::vector<ks::ui::HexFetchRange> ranges;      // 请求的页范围
            std::uint64_t revision = 0;                     // 请求时的来源代次
        };

        // RequestPages：记录并转发给 onRequest。
        void RequestPages(const std::vector<ks::ui::HexFetchRange>& ranges, std::uint64_t sourceRevision) override;

        // totalPages：到目前为止被请求的页总数（不去重）。
        std::uint64_t totalPages() const;

        std::vector<Request> requests;                      // 全部请求记录
        std::function<void(const Request&)> onRequest;      // 可选：每次请求时的检查回调
    };

    // CellCenter：地址在指定面板里单元格的中心点（视口坐标）。
    QPoint CellCenter(ks::ui::HexCanvas& canvas, std::uint64_t address, ks::ui::HexCanvas::ActivePane pane);

    // Click：在地址的单元格上点击左键。
    void Click(
        ks::ui::HexCanvas& canvas,
        std::uint64_t address,
        ks::ui::HexCanvas::ActivePane pane = ks::ui::HexCanvas::ActivePane::Hex,
        Qt::KeyboardModifiers modifiers = Qt::NoModifier);

    // DragMove：左键按住状态下把鼠标移动到视口坐标 pos（QTest::mouseMove 不携带按下的按钮，故自行构造事件）。
    void DragMove(QWidget* viewportWidget, const QPoint& pos);

    // Key：向画布发送一次按键（按下+释放）。
    void Key(ks::ui::HexCanvas& canvas, Qt::Key key, Qt::KeyboardModifiers modifiers = Qt::NoModifier);

    // Type：向画布逐字符发送文字按键（带 text，走编辑路径）。
    void Type(ks::ui::HexCanvas& canvas, const QString& text);

    // GrabImage：整视口抓图，转成 ARGB32 便于逐像素检查。
    QImage GrabImage(ks::ui::HexCanvas& canvas);

    // ColorsClose：两个颜色逐通道差之和是否不超过容差。
    bool ColorsClose(const QColor& left, const QColor& right, int tolerance);

    // ColorDistance：两个颜色逐通道差之和。
    int ColorDistance(const QColor& left, const QColor& right);

    // 各组测试入口（定义在对应的 .cpp）。
    void RunViewTests();
    void RunCompareContractTests();
    void RunEditTests();
    void RunRenderTests(const QString& shotsDir);
    void RunBenchmarks(const QString& benchFile);

    // RunInspectorTests：HexInspectorPanel（数据解释器面板）的全部验证、截图与基准，定义在 memwb_ui_inspector.cpp。
    void RunInspectorTests(const QString& shotsDir);

    // RunSignalTests：第二轮接口补全的全部验证（contentChanged 合并、editableChanged、stageBytes、
    // 视口坐标命中、不可读占位符、面板无定时器、填充图标）与一张截图，定义在 memwb_ui_tests.Signals.cpp。
    void RunSignalTests(const QString& shotsDir);

    // Phase 3 WP-0 的三组验证（各自单独报告断言数与失败数）：
    //   RunSegmentedTests    HexViewSegmented::setSegmentEnabled 禁用段，定义在 memwb_ui_tests.Segmented.cpp；
    //   RunCachedRangeTests  HexCanvas::copyCachedRange / copyCachedRangeWithMask，定义在 memwb_ui_tests.CachedRange.cpp；
    //   RunIconAliasTests    Ksword5.qrc 新增的 11 个 memwb_* 图标别名，定义在 memwb_ui_tests.IconAliases.cpp。
    void RunSegmentedTests();
    void RunCachedRangeTests();
    void RunIconAliasTests();

    // 十六进制自适应行宽/最小高度/Ctrl+滚轮缩放（画布层），定义在 memwb_ui_tests.RowFit.cpp。
    void RunRowFitTests();
}
