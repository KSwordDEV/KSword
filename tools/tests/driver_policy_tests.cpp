#include "../../Ksword5.1/Ksword5.1/Framework/WindowsDriverPolicy.h"
#include "../../Ksword5.1/Ksword5.1/UI/DriverLoadFailureDialog.h"
#include <QApplication>
#include <QElapsedTimer>
#include <QMessageBox>
#include <QPushButton>
#include <QThreadPool>
#include <QTimer>
#include <atomic>
#include <cstdio>
#include <stdexcept>

namespace
{
    int checks = 0; // checks：真实执行的断言数量。
    int failures = 0; // failures：失败断言数量，不吞掉后续覆盖。

    // Check：记录断言和稳定英文标签；返回值无，最终由 main 汇总退出码。
    void Check(const bool condition, const char* label)
    {
        ++checks;
        if (!condition)
        {
            ++failures;
            std::printf("FAIL %s\n", label);
        }
    }

    // Eligible：创建明确可自动处理的值夹具，测试中绝不调用真实移除后端。
    ks::driver_policy::Snapshot Eligible()
    {
        ks::driver_policy::Snapshot snapshot; // snapshot：完全确认的七月更新客户端。
        snapshot.build = 26200;
        snapshot.revision = 8875;
        snapshot.update = ks::driver_policy::UpdateState::July2026OrLater;
        snapshot.policy = ks::driver_policy::PolicyState::Active;
        snapshot.elevated = true;
        snapshot.rebootClear = true;
        snapshot.toolAvailable = true;
        return snapshot;
    }

    // BackendTests：直接运行生产纯函数，覆盖更新分支边界、JSON 状态及组合准入。
    void BackendTests()
    {
        using namespace ks::driver_policy;
        const unsigned long branches[] = {22631, 26100, 26200, 28000}; // branches：已登记客户端。
        const unsigned long revisions[] = {7376, 8875, 8875, 2525}; // revisions：对应七月安全更新 UBR。
        for (int index = 0; index < 4; ++index)
        {
            Check(ClassifyUpdate(branches[index], revisions[index] - 1, false) == UpdateState::BeforeJuly2026,
                "client before July baseline");
            Check(ClassifyUpdate(branches[index], revisions[index], false) == UpdateState::July2026OrLater,
                "client July baseline inclusive");
            Check(ClassifyUpdate(branches[index], revisions[index] + 100, false) == UpdateState::July2026OrLater,
                "superseding cumulative update allowed");
        }
        Check(ClassifyUpdate(26100, 33000, true) == UpdateState::BeforeJuly2026, "server does not use client UBR");
        Check(ClassifyUpdate(26100, 33158, true) == UpdateState::July2026OrLater, "server July baseline");
        // 26H2 单独验证已核实累计更新下界；未知早期版本及同号 Server 均不推断支持。
        Check(ClassifyUpdate(26300, 9549, false) == UpdateState::Unknown, "26H2 earlier unverified revision unknown");
        Check(ClassifyUpdate(26300, 9550, false) == UpdateState::July2026OrLater, "26H2 verified September cumulative baseline");
        Check(ClassifyUpdate(26300, 9711, false) == UpdateState::July2026OrLater, "26H2 October security cumulative update");
        Check(ClassifyUpdate(26300, 9725, false) == UpdateState::July2026OrLater, "26H2 October superseding OOB update");
        Check(ClassifyUpdate(26300, 99999, true) == UpdateState::Unknown, "26H2 client evidence does not authorize server");
        Check(ClassifyUpdate(99999, 99999, false) == UpdateState::Unknown, "future branch fails closed");
        Check(ClassifyUpdate(26200, 99999, true) == UpdateState::Unknown, "unknown server branch fails closed");
        Check(ParsePolicyState("bad JSON") == PolicyState::Unknown, "malformed JSON unknown");
        Check(ParsePolicyState("{}") == PolicyState::Unknown, "missing policy array unknown");
        Check(ParsePolicyState("{\"Policies\":[]}") == PolicyState::Absent, "empty valid policy list absent");
        const QByteArray row = "{\"PolicyID\":\"8f9cb695-5d48-48d6-a329-7202b44607e3\","; // row：固定强制 GUID 无花括号。
        Check(ParsePolicyState("{\"Policies\":[" + row + "\"IsEnforced\":true,\"IsAuthorized\":true}]}")
            == PolicyState::Active, "both enforcement and authorization required");
        Check(ParsePolicyState("{\"Policies\":[" + row + "\"IsEnforced\":\"True\",\"IsAuthorized\":\"true\"}]}")
            == PolicyState::Active, "CiTool string booleans supported");
        Check(ParsePolicyState("{\"Policies\":[" + row + "\"IsEnforced\":true,\"IsAuthorized\":false}]}")
            == PolicyState::Inactive, "unauthorized is not active");
        Check(ParsePolicyState("{\"Policies\":[" + row + "\"IsEnforced\":false,\"IsAuthorized\":true}]}")
            == PolicyState::Inactive, "not enforced is not active");
        Check(ParsePolicyState("{\"Policies\":[" + row + "\"IsEnforced\":true}]}")
            == PolicyState::Unknown, "missing authorization unknown");
        Check(ParsePolicyState("{\"Policies\":[{\"PolicyID\":\"784C4414-79F4-4C32-A6A5-F0FB42A51D0D\","
            "\"IsEnforced\":true,\"IsAuthorized\":true}]}") == PolicyState::Absent, "audit GUID never qualifies");
        Check(ParsePolicyState("{\"Policies\":[" + row + "\"IsEnforced\":true,\"IsAuthorized\":true},"
            + row + "\"IsEnforced\":true,\"IsAuthorized\":true}]}") == PolicyState::Unknown, "duplicate target unknown");
        // 所有前置位组合仅允许一个成功组合；未知更新和未知策略另行验证。
        for (unsigned int mask = 0; mask < 32; ++mask)
        {
            Snapshot snapshot = Eligible(); // snapshot：按位打掉一项已确认资格。
            snapshot.elevated = (mask & 1) != 0;
            snapshot.rebootClear = (mask & 2) != 0;
            snapshot.toolAvailable = (mask & 4) != 0;
            snapshot.policy = (mask & 8) != 0 ? PolicyState::Active : PolicyState::Absent;
            snapshot.update = (mask & 16) != 0 ? UpdateState::July2026OrLater : UpdateState::BeforeJuly2026;
            Check(CanRemove(snapshot) == (mask == 31), "all eligibility combinations");
        }
        Check(!CanRemove(Snapshot{}), "unknown snapshot fails closed");
        Check(RemovalArguments() == QStringList{QStringLiteral("--remove-policy"), EnforcePolicyId()},
            "only fixed enforcement policy removal command");
        Check(ks::ui::IsDriverPolicyLoadFailure(4551), "screenshot error 4551 alone uses new policy popup");
        Check(!ks::ui::IsDriverPolicyLoadFailure(577), "577 retains original signature popup");
        Check(!ks::ui::IsDriverPolicyLoadFailure(1275), "1275 retains original signature popup");
        Check(!ks::ui::IsDriverPolicyLoadFailure(1260), "1260 retains original handling");
        Check(!ks::ui::IsDriverPolicyLoadFailure(5), "access denied retains original path");
        Check(ks::ui::DriverPolicyHelpUrl() == QStringLiteral(
            "https://3304711297.github.io/youshouldknow/%E7%B3%BB%E7%BB%9F%E7%9F%A5%E8%AF%86/"
            "Windows%E6%96%B0%E9%A9%B1%E5%8A%A8%E7%A8%8B%E5%BA%8F%E7%AD%96%E7%95%A5%E4%B8%8E%E5%85%B3%E9%97%AD%E6%96%B9%E6%B3%95/"),
            "help uses the requested blog instead of Microsoft documentation");
    }

    // NonPolicyUiTests：旧错误调用新弹窗入口也必须立即返回，不能查询策略或弹出新窗口。
    void NonPolicyUiTests()
    {
        std::atomic_int queries{0}; // queries：排除错误码不应发起任何后台检查。
        std::atomic_int removals{0}; // removals：排除错误码不应触发任何系统修改。
        bool sawUnexpectedDialog = false; // sawUnexpectedDialog：记录误弹窗并及时关闭，防止回归挂住。
        ks::ui::DriverPolicyOperations operations; // operations：仅记录调用的系统 I/O 替身。
        operations.query = [&queries]()
        {
            ++queries;
            return Eligible();
        };
        operations.remove = [&removals]()
        {
            ++removals;
            return ks::driver_policy::RemovalResult{};
        };
        QTimer closeUnexpected; // closeUnexpected：仅在错误实现进入模态事件循环时触发。
        QObject::connect(&closeUnexpected, &QTimer::timeout, [&sawUnexpectedDialog]()
        {
            auto* box = qobject_cast<QMessageBox*>(QApplication::activeModalWidget()); // box：意外出现的新弹窗。
            if (box != nullptr)
            {
                sawUnexpectedDialog = true;
                box->done(QDialog::Rejected);
            }
        });
        closeUnexpected.start(0);
        for (const unsigned long code : {577UL, 1275UL, 1260UL, 5UL, 4550UL, 4552UL})
        {
            ks::ui::ShowDriverLoadFailureDialog(nullptr, code, operations);
        }
        closeUnexpected.stop();
        QThreadPool::globalInstance()->waitForDone();
        Check(!sawUnexpectedDialog, "legacy and unrelated errors never show new popup");
        Check(queries == 0, "legacy and unrelated errors never query policy");
        Check(removals == 0, "legacy and unrelated errors never submit removal");
    }

    // UiTest：运行生产弹窗和共享异步控制器；action 0=关闭，1=取消确认，2=确认移除。
    // snapshot/accepted 都是注入值；真实 CiTool 移除函数从未被调用。
    void UiTest(const ks::driver_policy::Snapshot& snapshot, const int action, const bool accepted,
        const bool queryThrows = false)
    {
        std::atomic_int removals{0}; // removals：确认后的后台动作次数，取消必须为 0。
        ks::ui::DriverPolicyOperations operations; // operations：唯一测试替身边界是系统策略 I/O。
        operations.query = [snapshot, queryThrows]()
        {
            if (queryThrows)
            {
                throw std::runtime_error("fixture query failure");
            }
            return snapshot;
        };
        operations.remove = [&removals, accepted]()
        {
            ++removals;
            return ks::driver_policy::RemovalResult{accepted, QStringLiteral("fixture receipt")};
        };
        QTimer timer; // timer：单层定时器覆盖嵌套模态流程，不引用已销毁的栈对象。
        QElapsedTimer elapsed; // elapsed：测试失控时有界退出，避免永久挂起。
        bool sawInitial = false; // sawInitial：只对最终预检状态断言一次。
        bool sawConfirmation = false; // sawConfirmation：确认窗口应只在明确点击后出现。
        bool sawReceipt = false; // sawReceipt：回执必须区分提交成功与失败。
        QObject::connect(&timer, &QTimer::timeout, [&]()
        {
            auto* box = qobject_cast<QMessageBox*>(QApplication::activeModalWidget()); // box：当前真实模态消息框。
            if (box == nullptr)
            {
                return;
            }
            if (elapsed.elapsed() > 10000)
            {
                Check(false, "popup workflow timed out");
                box->done(QDialog::Rejected);
                return;
            }
            if (box->objectName() == QStringLiteral("ks_driver_load_failure") && !sawInitial)
            {
                if (box->informativeText().contains(QStringLiteral("正在检查")))
                {
                    return;
                }
                sawInitial = true;
                QPushButton* destructive = nullptr; // destructive：按真实按钮角色检查是否提供自动处理。
                int helpButtons = 0; // helpButtons：更新已确认时不能同时显示备用帮助入口。
                for (QAbstractButton* button : box->buttons())
                {
                    Check(!button->toolTip().isEmpty(), "every popup action has tooltip");
                    if (box->buttonRole(button) == QMessageBox::DestructiveRole)
                    {
                        destructive = qobject_cast<QPushButton*>(button);
                    }
                    if (box->buttonRole(button) == QMessageBox::HelpRole)
                    {
                        ++helpButtons;
                        Check(button->text() == QStringLiteral("查看帮助"), "help label is concise");
                    }
                }
                const bool updated = snapshot.update == ks::driver_policy::UpdateState::July2026OrLater; // updated：仅控制可见操作入口。
                Check((destructive != nullptr) == updated, "installed update chooses disable button");
                Check(helpButtons == (updated ? 0 : 1), "old or unknown update chooses help only");
                Check(box->text().startsWith(QStringLiteral("原因：")) && box->text().contains(QStringLiteral("4551")),
                    "popup explains the actual policy-block cause");
                Check(box->informativeText().startsWith(QStringLiteral("处理方法：")), "popup explains what to do");
                Check(box->detailedText().isEmpty(), "popup does not expose implementation diagnostics");
                Check(!box->text().contains(ks::driver_policy::EnforcePolicyId())
                    && !box->informativeText().contains(QStringLiteral("预检"))
                    && !box->informativeText().contains(QStringLiteral("CiTool")), "popup omits policy GUID and internal instructions");
                if (action != 0 && destructive != nullptr)
                {
                    destructive->click();
                }
                else
                {
                    box->defaultButton()->click();
                }
            }
            else if (box->objectName() == QStringLiteral("ks_driver_policy_confirm") && !sawConfirmation)
            {
                sawConfirmation = true;
                Check(box->buttonRole(box->defaultButton()) == QMessageBox::RejectRole, "confirmation defaults to no change");
                Check(!box->text().contains(ks::driver_policy::EnforcePolicyId())
                    && !box->text().contains(QStringLiteral("CiTool")), "confirmation is a user-facing risk notice only");
                for (QAbstractButton* button : box->buttons())
                {
                    if (box->buttonRole(button) == (action == 2 ? QMessageBox::DestructiveRole : QMessageBox::RejectRole))
                    {
                        button->click();
                        break;
                    }
                }
            }
            else if (box->objectName() == QStringLiteral("ks_driver_policy_result") && !sawReceipt)
            {
                for (QAbstractButton* button : box->buttons())
                {
                    if (button->isEnabled() && box->buttonRole(button) == QMessageBox::RejectRole)
                    {
                        sawReceipt = true;
                        Check(box->text().contains(accepted ? QStringLiteral("重启电脑") : QStringLiteral("未能禁用")),
                            "receipt reflects accepted request versus failure");
                        Check(box->detailedText().isEmpty() && !box->text().contains(QStringLiteral("fixture receipt")),
                            "raw command receipt never leaks into UI");
                        button->click();
                        break;
                    }
                }
            }
        });
        elapsed.start();
        timer.start(5);
        ks::ui::ShowDriverLoadFailureDialog(nullptr, 4551, operations);
        timer.stop();
        QThreadPool::globalInstance()->waitForDone();
        Check(sawInitial, "initial popup inspected");
        Check(removals == (action == 2 ? 1 : 0), "only explicit confirmation invokes action");
        Check(sawConfirmation == (action != 0), "confirmation shown only on user request");
        Check(sawReceipt == (action == 2), "receipt shown only for submitted action");
    }
}

// main：不安装、不加载驱动、不操作真实策略；只执行生产逻辑及注入式弹窗回归。
int main(int argc, char** argv)
{
    QApplication application(argc, argv); // application：真实 Qt Widgets 事件循环。
    BackendTests();
    NonPolicyUiTests();
    UiTest(Eligible(), 0, false);
    UiTest(Eligible(), 1, false);
    UiTest(Eligible(), 2, true);
    UiTest(Eligible(), 2, false);
    UiTest(ks::driver_policy::Snapshot{}, 0, false, true);
    for (int index = 0; index < 6; ++index)
    {
        ks::driver_policy::Snapshot snapshot = Eligible(); // snapshot：逐项否决的弹窗测试。
        switch (index)
        {
        case 0: snapshot.update = ks::driver_policy::UpdateState::BeforeJuly2026; break;
        case 1: snapshot.update = ks::driver_policy::UpdateState::Unknown; break;
        case 2: snapshot.policy = ks::driver_policy::PolicyState::Unknown; break;
        case 3: snapshot.elevated = false; break;
        case 4: snapshot.rebootClear = false; break;
        case 5: snapshot.toolAvailable = false; break;
        }
        UiTest(snapshot, 0, false);
    }
    std::printf("DRIVER_POLICY_CHECKS=%d FAILURES=%d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
