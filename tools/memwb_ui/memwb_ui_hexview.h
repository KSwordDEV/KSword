#pragma once

// ============================================================
// memwb_ui_hexview.h
// 作用：HexView 复合控件（工具栏 / 查找条 / 跳转条 / 状态条 / 导出 / 旧缓冲模型兼容层）离屏夹具的公共设施——
//       设置重定向、事件泵、夹具构造、独立于引擎的朴素查找，以及各组测试的入口。
//       只被 memwb_ui_hexview*.cpp 与 memwb_ui_tests.HexView*.cpp 使用，不属于主程序。
// 文件分工：
//   memwb_ui_hexview.cpp               公共设施 + 总入口 RunHexViewTests
//   memwb_ui_tests.HexView.cpp         布局 / 工具栏 / 菜单 / 显隐 / 解释器持久化 / 快捷键 / 状态条
//   memwb_ui_tests.HexView.Compat.cpp  兼容层：setBuffer / 编辑信号 / setByteQuiet / 导航与访问器
//   memwb_ui_tests.HexView.Reference.cpp 兼容层：setReference / clearReference / 着色
//   memwb_ui_tests.HexView.Find.cpp    查找条：三种模式、通配、回绕、高亮、后台取消与陈旧结果
//   memwb_ui_tests.HexView.FindLogic.cpp 查找纯逻辑：解析、差分测试（对朴素实现）、可见命中
//   memwb_ui_tests.HexView.Goto.cpp    跳转条：解析、三模式、范围外提示、历史与持久化
//   memwb_ui_tests.HexView.Export.cpp  导出：转储格式、写文件、失败路径
//   memwb_ui_tests.HexView.Shots.cpp   截图
// ============================================================

#include "memwb_ui_signals.h"

#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexExport.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexFindBar.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexFindSearch.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexGotoBar.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexView.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexViewSettings.h"

#include <QSettings>
#include <QString>
#include <QTemporaryDir>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace memwb_test
{
    // SettingsRedirect：把默认 QSettings 重定向到一个临时 INI 目录（组织名/应用名也临时设置），
    // 析构时恢复默认格式与名称。HexView 与解释器面板用的都是默认 QSettings，所以一并被重定向，不碰注册表。
    class SettingsRedirect
    {
    public:
        // 构造：创建临时目录、设置 INI 格式与路径、清空全部键。
        SettingsRedirect();

        // 析构：恢复默认格式与组织/应用名。
        ~SettingsRedirect();

        // Reset：清空重定向目录里的全部键（写盘）。
        void Reset();

        // iniPath：当前重定向到的 INI 文件路径。
        QString iniPath() const;

    private:
        QTemporaryDir m_dir;                                        // 临时目录
        QSettings::Format m_previousFormat = QSettings::NativeFormat; // 原默认格式
        QString m_previousOrganization;                             // 原组织名
        QString m_previousApplication;                              // 原应用名
    };

    // PumpUntil：反复处理事件直到条件成立或超时。传入：条件、超时毫秒；传出：条件是否成立。
    bool PumpUntil(const std::function<bool()>& condition, int timeoutMs);

    // PumpFor：处理事件持续指定毫秒（用来验证"这段时间里什么都不会发生"）。
    void PumpFor(int milliseconds);

    // ActivateWindow：显示窗口并等它成为活动窗口（QShortcut 的上下文匹配需要活动窗口）。传出：是否成功激活。
    bool ActivateWindow(QWidget* window);

    // MakeHexView：构造并显示一个 HexView，载入数据。
    // 传入：基址、数据、是否可编辑、窗口大小；传出：已 show、已处理一轮事件的控件。
    std::unique_ptr<ks::ui::HexView> MakeHexView(
        std::uint64_t base,
        const QByteArray& data,
        bool editable,
        const QSize& size);

    // MenuPaintsSurface：弹出菜单并抓图，检查菜单四周内边距处的像素不透明且等于当前主题的表面色。
    // 为什么不查 autoFillBackground：样式表接管背景绘制后 Qt 会把它改回 false，真正的判据是画出来的像素。
    // 传入：菜单；传出：是否不透明且颜色正确。会触发菜单的 aboutToShow（菜单每次弹出前重建样式）。
    bool MenuPaintsSurface(QMenu* menu);

    // CellOf：取画布上某地址的显示状态。
    ks::ui::HexCanvas::CellState CellOf(ks::ui::HexView& view, std::uint64_t address);

    // NaiveMatches：朴素查找（不依赖被测引擎）：返回全部（含重叠）命中的起点，按升序。
    // 判据：(data[i] & mask[j]) == (needle[j] & mask[j])；mask 为空表示全 0xFF。
    std::vector<std::uint64_t> NaiveMatches(
        const QByteArray& data,
        std::uint64_t base,
        const QByteArray& needle,
        const QByteArray& mask = QByteArray());

    // 各组测试入口（定义在对应的 .cpp）。
    void RunHexViewCoreTests();
    void RunHexViewHostTests();
    void RunHexViewCompatTests();
    void RunHexViewReferenceTests();
    void RunHexViewFindTests();
    void RunHexViewFindLogicTests();
    void RunHexViewGotoTests();
    void RunHexViewExportTests();
    void RunHexViewShots(const QString& shotsDir);

    // RunHexViewTests：HexView 全部验证与截图的总入口，由 memwb_ui_tests.cpp 的 main 调用。
    void RunHexViewTests(const QString& shotsDir);
}
