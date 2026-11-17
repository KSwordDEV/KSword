#include "WorkbenchActions.h"
#include "../ShortcutRegistry.h"

// ============================================================
// WorkbenchActions.cpp
// 作用：见头文件。kSpecs 数组下标直接等于 WorkbenchActionId 的枚举值，
// 顺序必须与头文件枚举声明顺序完全一致。
//
// B13：kActionCount 由 WorkbenchActionId::Count 这个哨兵反推，不再由
// "EscapeOrCancel"（当前谁是最后一个真实动作）反推——后者会在日后新增动作时
// 悄悄漂移。QKeySequence 不是字面类型，进不了 static_assert 比较，编译期测不出
// "某一行被漏写成空快捷键"这件事，真正防住它的是夹具里逐项的非空/去重断言
// （T8：tools/memwb_ui/wpG/wpG_tests.Gaps2.cpp::RunActionsTest），只能靠运行期。
// ============================================================

#include <QShortcut>
#include <QWidget>

#include <array>

namespace ks::ui
{
    namespace
    {
        // kActionCount：动作总数，直接等于哨兵 Count 的数值，恒随枚举增减同步。
        constexpr int kActionCount = static_cast<int>(WorkbenchActionId::Count);
        constexpr const char* kShortcutIds[] = {
            "memory.address", "memory.back", "memory.forward", "memory.reread", "memory.write_mode",
            "memory.find", "memory.find_next", "memory.find_previous", "memory.undo", "memory.redo",
            "memory.apply", "memory.discard", "memory.bookmark", "memory.sidebar", "memory.inspector",
            "memory.disasm", "memory.int3", "memory.tab_hex", "memory.tab_disasm", "memory.tab_text",
            "memory.tab_compare", "memory.focus_next", "memory.focus_previous", "memory.escape"
        };
        static_assert(std::size(kShortcutIds) == kActionCount);

        // kSpecs：动作表。tooltip 里的快捷键文字与 shortcut 字段手动保持一致——
        // 两者都改动才算改完一行，这也是为什么不做成"自动从 QKeySequence 生成文字"：
        // 用户习惯的写法（"Ctrl+Y（或 Ctrl+Shift+Z）"）比 QKeySequence::toString 的
        // 原生格式更可读。
        const std::array<WorkbenchActionSpec, kActionCount>& Specs()
        {
            static const std::array<WorkbenchActionSpec, kActionCount> kSpecs = {{
                // FocusAddressBar
                {QKeySequence(Qt::CTRL | Qt::Key_G), QString(),
                 QStringLiteral("聚焦地址栏（Ctrl+G）")},
                // GoBack
                {QKeySequence(Qt::ALT | Qt::Key_Left), QStringLiteral("file_nav_back"),
                 QStringLiteral("回到上一个地址（Alt+←）")},
                // GoForward
                {QKeySequence(Qt::ALT | Qt::Key_Right), QStringLiteral("file_nav_forward"),
                 QStringLiteral("前进到下一个地址（Alt+→）")},
                // Reread
                {QKeySequence(Qt::Key_F5), QStringLiteral("process_refresh"),
                 QStringLiteral("用「当前通道」重读窗口（F5）；与上次读取不同的字节标青色")},
                // ToggleWriteMode
                {QKeySequence(Qt::CTRL | Qt::Key_E), QString(),
                 QStringLiteral("切换写入模式（Ctrl+E）")},
                // Find
                {QKeySequence(Qt::CTRL | Qt::Key_F), QString(),
                 QStringLiteral("查找（Ctrl+F）")},
                // FindNext
                {QKeySequence(Qt::Key_F3), QString(),
                 QStringLiteral("查找下一个（F3）")},
                // FindPrevious
                {QKeySequence(Qt::SHIFT | Qt::Key_F3), QString(),
                 QStringLiteral("查找上一个（Shift+F3）")},
                // Undo
                {QKeySequence(Qt::CTRL | Qt::Key_Z), QString(),
                 QStringLiteral("撤销（Ctrl+Z）")},
                // Redo（B7：候补键 Ctrl+Shift+Z，兑现 tooltip 里承诺的"或"）
                {QKeySequence(Qt::CTRL | Qt::Key_Y), QString(),
                 QStringLiteral("重做（Ctrl+Y，或 Ctrl+Shift+Z）"),
                 QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_Z)},
                // ApplyPending（S7：候补键 Ctrl+小键盘 Enter——QShortcut 按 Qt::Key_Return
                // 精确匹配键码，不会自动把 Key_Enter 当成同一个键，必须另绑一个）
                {QKeySequence(Qt::CTRL | Qt::Key_Return), QStringLiteral("service_apply"),
                 QStringLiteral("把待写入修改写入目标（Ctrl+Enter），先复核原值、写后回读"),
                 QKeySequence(Qt::CTRL | Qt::Key_Enter)},
                // DiscardPending
                {QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_Backspace), QStringLiteral("log_clear"),
                 QStringLiteral("丢弃待写入修改，目标内存不受影响（Ctrl+Shift+Backspace）")},
                // AddToAddressBook
                {QKeySequence(Qt::CTRL | Qt::Key_B), QStringLiteral("memwb_bookmark_add"),
                 QStringLiteral("把插入点加入地址簿（Ctrl+B）")},
                // ToggleSidebar
                {QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_B), QStringLiteral("memwb_bookmarks"),
                 QStringLiteral("显隐侧栏：地址簿、书签、监视、搜索结果（Ctrl+Shift+B）")},
                // ToggleInspector
                {QKeySequence(Qt::CTRL | Qt::Key_I), QString(),
                 QStringLiteral("数据解释器面板（Ctrl+I）")},
                // OpenInDisasm
                {QKeySequence(Qt::CTRL | Qt::Key_D), QString(),
                 QStringLiteral("在反汇编页打开插入点（Ctrl+D）")},
                // ToggleInt3Patch
                {QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_P), QStringLiteral("disk_tools"),
                 QStringLiteral("在插入点写入 int3（0xCC），记下原字节以便还原（Ctrl+Shift+P）")},
                // SwitchTabHex
                {QKeySequence(Qt::CTRL | Qt::Key_1), QStringLiteral("memwb_tab_hex"),
                 QStringLiteral("十六进制子页（Ctrl+1）")},
                // SwitchTabDisasm
                {QKeySequence(Qt::CTRL | Qt::Key_2), QStringLiteral("memwb_tab_disasm"),
                 QStringLiteral("反汇编子页（Ctrl+2）")},
                // SwitchTabText
                {QKeySequence(Qt::CTRL | Qt::Key_3), QStringLiteral("memwb_tab_text"),
                 QStringLiteral("文本子页（Ctrl+3）")},
                // SwitchTabCompare
                {QKeySequence(Qt::CTRL | Qt::Key_4), QStringLiteral("memwb_tab_compare"),
                 QStringLiteral("对比子页（Ctrl+4）")},
                // CycleFocusForward
                {QKeySequence(Qt::Key_F6), QString(),
                 QStringLiteral("地址栏→画布→解释器→侧栏循环（F6）")},
                // CycleFocusBackward
                {QKeySequence(Qt::SHIFT | Qt::Key_F6), QString(),
                 QStringLiteral("反向循环焦点（Shift+F6）")},
                // EscapeOrCancel
                {QKeySequence(Qt::Key_Escape), QString(),
                 QStringLiteral("先关查找条，再取消半字节输入（Esc）")},
            }};
            // B13：kSpecs 的模板参数直接写的就是 kActionCount，数组长度与它恒等——
            // 这件事由类型系统保证，不需要（也无法用 QKeySequence 这种非字面类型
            // 在 static_assert 里）再加一道编译期检查；真正防"某一行初始化漏写"的
            // 是下面 WorkbenchActionSpecFor 的越界兜底 + 夹具里逐项的非空/去重断言
            // （tools/memwb_ui/wpG/wpG_tests.Gaps2.cpp::RunActionsTest）。
            return kSpecs;
        }
    }

    void RegisterWorkbenchShortcutCatalog()
    {
        auto& registry = ShortcutRegistry::instance();
        for (int i = 0; i < kActionCount; ++i)
        {
            const auto& spec = Specs()[static_cast<std::size_t>(i)];
            ShortcutRegistry::Command command{QString::fromLatin1(kShortcutIds[i]), spec.tooltip,
                QStringLiteral("memory"), {}, spec.shortcut, {}};
            if (i == static_cast<int>(WorkbenchActionId::EscapeOrCancel))
            {
                command.editable = false;
                command.restriction = spec.tooltip;
            }
            registry.define(command);
            if (!spec.alternateShortcut.isEmpty())
            {
                command.id += QStringLiteral(".alternate");
                command.defaults = spec.alternateShortcut;
                registry.define(command);
            }
        }
    }

    // WorkbenchActionSpecFor：按下标取表项；下标用枚举值直接转换，顺序已在表里注释对齐。
    const WorkbenchActionSpec& WorkbenchActionSpecFor(const WorkbenchActionId id)
    {
        const auto& specs = Specs();
        const int index = static_cast<int>(id);
        // 防御：枚举值理论上恒在表范围内，越界时退回最后一项，避免越界访问。
        if (index < 0 || index >= kActionCount)
        {
            return specs.back();
        }
        return specs[static_cast<std::size_t>(index)];
    }

    // CreateWorkbenchShortcut：固定 WidgetWithChildrenShortcut 范围，不在这里连接信号，
    // 调用方拿到指针后自行 connect(activated, ...)。
    QShortcut* CreateWorkbenchShortcut(const WorkbenchActionId id, QWidget* host)
    {
        if (host == nullptr)
        {
            return nullptr;
        }
        // N5（第二轮修复）：Count 是哨兵、不是真实动作；WorkbenchActionSpecFor 对
        // 越界下标"退回最后一项"是那个访问器自己的防御性兜底（给诊断/测试之类
        // 轻量读取用），不代表"这个 id 可以照常拿去建快捷键"。此前这里只特判
        // EscapeOrCancel，id==Count 时既不等于 EscapeOrCancel、下标又越界，会
        // 悄悄把 WorkbenchActionSpecFor 退回的最后一项（Esc）当成"Count 的快捷键"
        // 注册成一个真实生效的 QShortcut——越界必须在这里就显式失败，不能静默
        // 借用别的动作的按键。
        const int index = static_cast<int>(id);
        if (index < 0 || index >= kActionCount)
        {
            return nullptr;
        }
        if (id == WorkbenchActionId::EscapeOrCancel)
        {
            // S2：故意不在这里注册成常驻的 WidgetWithChildrenShortcut。常驻 Esc 的
            // 触发时机早于子控件自己的 keyPressEvent/eventFilter——行内汇编编辑器
            // （"Enter 写入，Esc 取消"）、地址簿备注编辑、委托编辑器都靠自己处理
            // Esc 来取消输入，常驻的全局 Esc 会在那之前把按键吞掉。这一项留在表里
            // 只是为了给其它地方（例如提示文案）一个统一的"Esc 的说明"来源；真正
            // 的"关闭查找条/取消半字节输入"由各面板自己处理原生 QKeyEvent，不经过
            // 本函数注册的快捷键。
            return nullptr;
        }
        const WorkbenchActionSpec& spec = WorkbenchActionSpecFor(id);
        auto* shortcut = new QShortcut(spec.shortcut, host);
        shortcut->setContext(Qt::WidgetWithChildrenShortcut);
        RegisterWorkbenchShortcutCatalog();
        ShortcutRegistry::instance().attach(QString::fromLatin1(kShortcutIds[index]), shortcut,
            [shortcut](const QKeySequence& keys, QString*) { shortcut->setKey(keys); return true; });
        return shortcut;
    }

    // CreateWorkbenchAlternateShortcut：见头文件（B7/S7）。
    QShortcut* CreateWorkbenchAlternateShortcut(const WorkbenchActionId id, QWidget* host)
    {
        // N5：理由同 CreateWorkbenchShortcut——越界 id（含恰好等于 Count）必须显式
        // 失败，不能借 WorkbenchActionSpecFor 的防御性兜底悄悄建出 Esc 的候补快捷键。
        // 本轮自补变异 wpGN2-03 实测过这个边界检查本身在当前数据下是"等价变异"
        // 安全网：Count 越界退回的是 EscapeOrCancel 的 spec，而它的 alternateShortcut
        // 恒为空（kSpecs 里只给了 3 个字段，第 4 个按聚合初始化规则值初始化成空
        // QKeySequence），下面的 isEmpty() 检查会独立兜底返回 nullptr。这条边界检查
        // 不是因此可以删掉——它和 CreateWorkbenchShortcut 的检查是同一份契约（任何
        // 越界 id 都不该被当成合法 id 处理），只是这份数据下恰好有双重保险；一旦
        // 未来表尾（Count 前最后一项）换成带 alternateShortcut 的动作，这里就会从
        // "双重保险"变成"唯一防线"。
        const int index = static_cast<int>(id);
        if (host == nullptr || index < 0 || index >= kActionCount || id == WorkbenchActionId::EscapeOrCancel)
        {
            return nullptr;
        }
        const WorkbenchActionSpec& spec = WorkbenchActionSpecFor(id);
        if (spec.alternateShortcut.isEmpty())
        {
            return nullptr;
        }
        auto* shortcut = new QShortcut(spec.alternateShortcut, host);
        shortcut->setContext(Qt::WidgetWithChildrenShortcut);
        RegisterWorkbenchShortcutCatalog();
        ShortcutRegistry::instance().attach(QString::fromLatin1(kShortcutIds[index]) + QStringLiteral(".alternate"), shortcut,
            [shortcut](const QKeySequence& keys, QString*) { shortcut->setKey(keys); return true; });
        return shortcut;
    }
}
