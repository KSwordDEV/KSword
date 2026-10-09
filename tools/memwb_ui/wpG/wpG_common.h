#pragma once

// ============================================================
// wpG_common.h
// 作用：WP-G（会话条/写入模式/状态条/确认框/动作/设置/消息/字符串写入）离屏
// 验证夹具的公共设施——轻量断言计数、主题切换、假弹框执行器、假诊断抽屉、
// 假字节仓库与审计接口。只服务 tools/memwb_ui/wpG/ 下的测试文件，不被其它
// 工作包的夹具引用，也不修改仓库里已有的 tools/memwb_ui/memwb_ui_common.*。
// ============================================================

#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchConfirmations.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchStatusBar.h"
#include "../../../Ksword5.1/Ksword5.1/UI/StructuredFieldView.h"

#include "../../../shared/evidence/memory_workbench/MemoryWriteTransaction.h"

#include <QImage>
#include <QString>
#include <QWidget>

#include <cstdint>
#include <memory>
#include <vector>

// 全局作用域前置声明：放在任何命名空间之外，避免下面类里的
// "class QPlainTextEdit* m_edit" 在 wpg_test 命名空间内又声明出一个同名
// 但不同的 wpg_test::QPlainTextEdit（那样会和 <QPlainTextEdit> 里的真实
// ::QPlainTextEdit 变成两个不相关的不完整类型，.cpp 里用不了）。
class QPlainTextEdit;

namespace wpg_test
{
    // g_checks / g_failures：全局断言计数，main() 结束时汇总打印。
    extern int g_checks;
    extern int g_failures;

    // Report：记录一条断言结果，失败时打印位置与表达式到 stderr。
    void Report(bool ok, const char* expression, const char* file, int line, const QString& note);

#define WPG_CHECK(expression) ::wpg_test::Report(static_cast<bool>(expression), #expression, __FILE__, __LINE__, QString())
#define WPG_CHECK_NOTE(expression, note) ::wpg_test::Report(static_cast<bool>(expression), #expression, __FILE__, __LINE__, (note))

    // ApplyTheme：切换深浅主题并同步调色板，使控件静态颜色访问器取到对应的主题色。
    void ApplyTheme(bool dark);

    // GrabImage：整控件截图，转成 ARGB32 便于保存。
    QImage GrabImage(QWidget& widget);

    // FakeConfirmPrompter：ks::ui::IConfirmPrompter 的假实现，记录每次调用的参数并
    // 按脚本化队列返回预设答案，不真的弹出任何模态框。
    class FakeConfirmPrompter final : public ks::ui::IConfirmPrompter
    {
    public:
        // 三个队列：测试在调用前把期望的返回值 push 进对应队列；队列空时返回安全默认值
        //（Deny/false/Cancel），这样漏配置脚本的测试会表现成"什么都没同意"而不是崩溃。
        std::vector<bool> uiConfirmAnswers;
        std::vector<bool> uiConfirmDontAskAgain;
        std::vector<ksword::memwb::ApprovalAnswer> approvalAnswers;
        std::vector<ksword::memwb::ModeSwitchDecision> modeSwitchAnswers;
        // leaveWithPendingAnswers（WP-J6 Wave 3 新增，修复缺陷 3 的配套测试）：
        // PromptLeaveWithPending 的脚本化队列，与 modeSwitchAnswers 是两条独立
        // 队列——离开守卫与"切换写入模式"是两个不同场景，不应共用同一个脚本。
        std::vector<ksword::memwb::ModeSwitchDecision> leaveWithPendingAnswers;

        // 调用次数与最近一次参数，供测试断言"到底问了没有、问的内容对不对"。
        int uiConfirmCalls = 0;
        int approvalCalls = 0;
        int modeSwitchCalls = 0;
        // leaveWithPendingCalls/lastLeaveWithPendingBytes/Blocks/ReasonText：
        // PromptLeaveWithPending 的调用次数与最近一次收到的全部参数。
        int leaveWithPendingCalls = 0;
        std::uint64_t lastLeaveWithPendingBytes = 0;
        std::uint64_t lastLeaveWithPendingBlocks = 0;
        QString lastLeaveWithPendingReasonText;
        bool lastOfferDontAskAgain = false;
        bool lastOfferRestOfBatch = false;
        ksword::memwb::UiConfirmRequest lastUiConfirmRequest;
        ksword::memwb::ApprovalRequest lastApprovalRequest;
        // lastUiConfirmScope/Channel/TargetDescription、lastApprovalScope/Channel/
        // TargetDescription：B2 新增参数的最近一次记录，供测试核对
        // WorkbenchConfirmations 是否把 scope/channel/目标描述原样转发给了弹框实现。
        ksword::memwb::Scope lastUiConfirmScope = ksword::memwb::Scope::ProcessVirtual;
        ksword::memwb::Channel lastUiConfirmChannel = ksword::memwb::Channel::UserMode;
        QString lastUiConfirmTargetDescription;
        ksword::memwb::Scope lastApprovalScope = ksword::memwb::Scope::ProcessVirtual;
        ksword::memwb::Channel lastApprovalChannel = ksword::memwb::Channel::UserMode;
        QString lastApprovalTargetDescription;

        bool PromptUiConfirm(
            const ksword::memwb::UiConfirmRequest& request,
            ksword::memwb::Scope scope,
            ksword::memwb::Channel channel,
            const QString& targetDescription,
            bool offerDontAskAgain,
            bool& dontAskAgainChecked) override;

        ksword::memwb::ApprovalAnswer PromptApproval(
            const ksword::memwb::ApprovalRequest& request,
            ksword::memwb::Scope scope,
            ksword::memwb::Channel channel,
            const QString& targetDescription,
            bool offerRestOfBatch) override;

        ksword::memwb::ModeSwitchDecision PromptModeSwitch(
            ksword::memwb::WriteMode fromMode,
            ksword::memwb::WriteMode toMode,
            std::uint64_t pendingBytes,
            std::uint64_t pendingBlocks) override;

        // PromptLeaveWithPending（WP-J6 Wave 3 新增，修复缺陷 3）：覆写基类的
        // 保守默认实现（恒 Cancel），脚本化返回 leaveWithPendingAnswers 队列里
        // 的预设答案并记录调用次数/参数。
        ksword::memwb::ModeSwitchDecision PromptLeaveWithPending(
            std::uint64_t pendingBytes,
            std::uint64_t pendingBlocks,
            const QString& reasonText) override;
    };

    // FakeByteStore：ksword::memwb::IByteStore 的假实现，用脚本化的读写结果驱动
    // MemoryWriteTransaction 的完整管线（无需真实目标内存/驱动）。
    class FakeByteStore final : public ksword::memwb::IByteStore
    {
    public:
        // readBytes：当前"目标真实内存"的镜像，Read 按地址/长度从这里切片返回。
        // 测试直接改它来模拟"写前复核发现目标已变化"。
        std::vector<std::uint8_t> readBytes;
        std::uint64_t baseAddress = 0;

        // nextWriteNeedsApproval：下一次 Write 是否先要求显式同意（之后清零，模拟
        // "同意一次后，同一次写入的重试不再要求"）。
        bool nextWriteNeedsApproval = false;
        // failNextWrite：下一次 Write 直接失败（不写入任何字节）。
        bool failNextWrite = false;
        int writeCalls = 0;

        ksword::memwb::AccessResult Read(std::uint64_t address, std::uint64_t length) override;
        ksword::memwb::AccessResult Write(
            std::uint64_t address, const std::vector<std::uint8_t>& bytes, bool explicitApproval) override;
    };

    // NullAuditSink：ksword::memwb::IAuditSink 的空实现，测试不关心审计内容本身。
    class NullAuditSink final : public ksword::memwb::IAuditSink
    {
    public:
        int recordCalls = 0;
        void Record(const ksword::memwb::AuditRecord& record) override;
    };

    // FakeDiagnosticsHost：ks::ui::IWorkbenchDiagnosticsHost 的假实现，用普通
    // QPlainTextEdit 代替生产环境的 CodeEditorWidget（CodeEditorWidget.cpp 牵连
    // LanguageManager 等主程序专属依赖，无法在本夹具里独立链接，详见
    // WorkbenchStatusBar.cpp 顶部注释与本任务 problems 里的说明）。
    class FakeDiagnosticsHost final : public ks::ui::IWorkbenchDiagnosticsHost
    {
    public:
        explicit FakeDiagnosticsHost(QWidget* parent = nullptr);
        QWidget* HostWidget() override;
        void SetDiagnosticsText(const QString& text) override;
        void SetDiagnosticsDocument(const ks::ui::FieldDocument& document) override;
        QString DiagnosticsText() const override;
        void SetWrapEnabled(bool wrap) override;

        // IsWrapEnabled：供测试核对 SetWrapEnabled 是否真的被调用过、调的值对不对
        //（B12——WorkbenchStatusBar 的换行勾选框原来是个没有任何调用方的死接口）。
        bool IsWrapEnabled() const;

    private:
        QPlainTextEdit* m_edit = nullptr;
        ks::ui::FieldDocument m_document;
        bool m_documentActive = false;
    };

    // 各组测试入口，定义在对应的 wpG_tests.*.cpp，main() 依次调用。
    void RunSessionBarTests();
    void RunStatusBarTests();
    void RunConfirmationsTests();
    void RunShotsTests(const QString& shotsDir);
    // RunGapTests / RunGapTests2：审核报告第 5 节补的"缺口测试"（T1-T16），覆盖
    // Actions/Settings/StringWriteDialog/WriteModeSwitch 四个原来零断言的文件，
    // 以及 B1-B14、S1/S2/S4/S5/S6/S7/S9/S10 的回归断言。单文件 ≤700 行的限制下拆
    // 成两个文件（wpG_tests.Gaps.cpp / wpG_tests.Gaps2.cpp），main() 必须把两个都
    // 调用，否则第二份测试会被静默跳过（犯过一次：忘了调 RunGapTests2 导致 Actions/
    // Settings/StringWriteDialog 的全部新断言从未真正跑过，却仍然报"全部通过"）。
    void RunGapTests();
    void RunGapTests2();
    // RunReview2Tests：第二轮独立审核的补测（wpG_tests.Review2.cpp）——回注幸存体
    // 的加强断言、真实弹框点具体按钮、S4 事件循环重同步、N1-N7 新缺陷的 DEFECT
    // 断言（已并入默认运行，不再靠 R2_DEFECTS 环境变量开关）。main() 必须放在
    // RunShotsTests 之后调用：其中的 i18n 探测会把 LanguageManager 切到
    // en-US（且不会切回去——进程快退出了），放在截图之前会让后续截图的中文
    // 文案变成英文。
    void RunReview2Tests();
}
