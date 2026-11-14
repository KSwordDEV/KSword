#pragma once

// ============================================================
// WorkbenchActions.h
// 作用：
// - 内存工作台全部快捷键、图标别名字符串、悬停提示的唯一定义处（ux.md 第 8 节）。
//   其它工作包需要某个动作的快捷键/图标时，查这里的 Spec()，不在各自文件里再写
//   一遍 QKeySequence 或裸的图标别名字符串。
// - 全部快捷键固定 Qt::WidgetWithChildrenShortcut 范围：挂在某个子树的根控件上，
//   只在该子树持有焦点时生效，不会跨 Dock 抢别的输入框的 Ctrl+Z。
// - 悬停提示文案是枚举->固定句子的一一对应（不依赖运行期数据），直接写在
//   WorkbenchActions.cpp 的表里；与 WorkbenchMessages 不同，它不需要按运行期参数
//   拼句，因此不经 WorkbenchMessages 转发，但同属"只在一处出现"的中文字面量。
// ============================================================

#include <QKeySequence>
#include <QString>

class QShortcut;
class QWidget;

namespace ks::ui
{
    void RegisterWorkbenchShortcutCatalog();
    // WorkbenchActionId：ux.md 第 8 节快捷键表里的每一行一个取值，顺序与表格一致。
    enum class WorkbenchActionId
    {
        FocusAddressBar,      // Ctrl+G 聚焦地址栏
        GoBack,                // Alt+Left 后退
        GoForward,             // Alt+Right 前进
        Reread,                // F5 重读
        ToggleWriteMode,       // Ctrl+E 切换写入模式
        Find,                  // Ctrl+F 查找
        FindNext,              // F3 下一个
        FindPrevious,          // Shift+F3 上一个
        Undo,                  // Ctrl+Z 撤销
        Redo,                  // Ctrl+Y（或 Ctrl+Shift+Z）重做
        ApplyPending,          // Ctrl+Enter 应用待写入
        DiscardPending,        // Ctrl+Shift+Backspace 丢弃待写入
        AddToAddressBook,      // Ctrl+B 加入地址簿
        ToggleSidebar,         // Ctrl+Shift+B 显隐侧栏
        ToggleInspector,       // Ctrl+I 解释器面板
        OpenInDisasm,          // Ctrl+D 在反汇编页打开插入点
        ToggleInt3Patch,       // Ctrl+Shift+P 写入/还原 int3
        SwitchTabHex,          // Ctrl+1 切到十六进制子页
        SwitchTabDisasm,       // Ctrl+2 切到反汇编子页
        SwitchTabText,         // Ctrl+3 切到文本子页
        SwitchTabCompare,      // Ctrl+4 切到对比子页
        CycleFocusForward,     // F6 地址栏->画布->解释器->侧栏循环
        CycleFocusBackward,    // Shift+F6 反向循环
        EscapeOrCancel,        // Esc 先关查找条/取消半字节输入（具体语义由画布自身决定）
        // Count：哨兵，必须恒排在最后一项。B13——kActionCount 原来由 EscapeOrCancel
        // 反推（"当前谁是最后一个真实动作"这种写法容易漂移：日后在 EscapeOrCancel
        // 之后新增动作，kActionCount 不会跟着增长）。现在改成由 Count 反推，新增
        // 动作只需要插在 Count 前面，不必关心"谁是最后一个真实动作"。
        Count,
    };

    // WorkbenchActionSpec：一个动作的完整描述。iconAlias 为空串表示该动作没有专属
    // 工具栏图标（例如纯键盘的循环焦点）；tooltip 已包含快捷键文字，可直接 setToolTip。
    struct WorkbenchActionSpec
    {
        // shortcut：按键组合。
        QKeySequence shortcut;
        // iconAlias：qrc 里 "/Icon/" 前缀之后的别名（不含扩展名之外的路径），
        // 为空表示没有专属图标。
        QString iconAlias;
        // tooltip：完整悬停提示文案，已含快捷键说明。
        QString tooltip;
        // alternateShortcut：B7/S7——候补按键组合，空值（默认）表示没有候补。
        // QShortcut 一个对象只能带一个 QKeySequence，ux.md 里写的"Ctrl+Y（或
        // Ctrl+Shift+Z）"一类双键承诺必须靠另建一个 QShortcut 兑现，见
        // CreateWorkbenchAlternateShortcut。
        QKeySequence alternateShortcut;
    };

    // Spec：按动作 id 取完整描述；未识别的 id（不应发生）返回一个空快捷键的占位值。
    const WorkbenchActionSpec& WorkbenchActionSpecFor(WorkbenchActionId id);

    // CreateWorkbenchShortcut：按动作 id 在 host 下创建一个 WidgetWithChildrenShortcut
    // 范围的 QShortcut；调用方自行连接 activated() 信号。host 为空时返回 nullptr。
    // S2：EscapeOrCancel 这一项永远返回 nullptr——常驻的 WidgetWithChildren 级 Esc
    // 会先于子控件自己的 keyPressEvent/eventFilter 触发，抢走行内汇编编辑器、
    // 地址簿备注编辑、委托编辑器自己处理 Esc（取消输入）的机会。这一项留在表里
    // 只是为了提供统一的快捷键文案，真正的"关闭查找条/取消输入"由各面板自己处理
    // 原生的 QKeyEvent，不经过本函数注册的全局快捷键。
    QShortcut* CreateWorkbenchShortcut(WorkbenchActionId id, QWidget* host);

    // CreateWorkbenchAlternateShortcut：按动作 id 的候补键（WorkbenchActionSpec::
    // alternateShortcut）在 host 下另建一个 WidgetWithChildrenShortcut；该动作没有
    // 候补键、或 host 为空时返回 nullptr（B7）。调用方需要把它的 activated() 接到
    // 与主快捷键相同的槛上，两个 QShortcut 都要连，才能让"Ctrl+Y 或 Ctrl+Shift+Z"
    // 这种双键承诺真正生效。
    QShortcut* CreateWorkbenchAlternateShortcut(WorkbenchActionId id, QWidget* host);
}
