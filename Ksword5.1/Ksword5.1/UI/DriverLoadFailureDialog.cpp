#include "../Framework.h"
#include "DriverLoadFailureDialog.h"
#include "AsyncOperation.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QDesktopServices>
#include <QMessageBox>
#include <QPushButton>
#include <QUrl>

namespace ks::ui
{
    namespace
    {
        using ks::i18n::sourceText;

        // PrepareBox：复用全局 ThemedMessageBox；原生消息/确认框不另造参数页或详情框架。
        void PrepareBox(QMessageBox& box, const QString& objectName)
        {
            box.setObjectName(objectName);
            box.setStyleSheet(KswordTheme::OpaqueDialogStyle(objectName));
            box.setWindowTitle(sourceText(QStringLiteral("驱动被系统策略阻止")));
            box.setTextFormat(Qt::PlainText);
            box.setTextInteractionFlags(Qt::TextSelectableByMouse);
            box.setIcon(QMessageBox::Warning);
        }

        // AddHelpButton：为指定消息框添加博客帮助入口；只打开网页，不修改本机策略。
        void AddHelpButton(QMessageBox& box)
        {
            QPushButton* help = box.addButton(sourceText(QStringLiteral("查看帮助")),
                QMessageBox::HelpRole); // help：未确认更新或操作失败时的恢复入口。
            help->setToolTip(sourceText(QStringLiteral("查看驱动策略的处理方法")));
            QObject::connect(help, &QPushButton::clicked, &box, []()
            {
                QDesktopServices::openUrl(QUrl(DriverPolicyHelpUrl()));
            });
        }

        // RunRemoval：用户二次确认后执行单一事务；取消确认及普通关闭不触发任何写操作。
        void RunRemoval(QWidget* parent, const DriverPolicyOperations& operations)
        {
            QMessageBox confirm(parent); // confirm：明确风险及固定作用范围的二次确认框。
            PrepareBox(confirm, QStringLiteral("ks_driver_policy_confirm"));
            confirm.setText(sourceText(QStringLiteral(
                "禁用此策略会降低系统的驱动保护，重启后生效。是否继续？")));
            QPushButton* accept = confirm.addButton(sourceText(QStringLiteral("禁用策略")),
                QMessageBox::DestructiveRole); // accept：唯一可提交写操作的按钮，保留文字避免歧义。
            QPushButton* cancel = confirm.addButton(sourceText(QStringLiteral("取消")),
                QMessageBox::RejectRole); // cancel：默认焦点和 Escape 都是不修改。
            accept->setToolTip(sourceText(QStringLiteral("禁用此驱动策略，重启后生效")));
            cancel->setToolTip(sourceText(QStringLiteral("不修改系统策略")));
            confirm.setDefaultButton(cancel);
            confirm.setEscapeButton(cancel);
            confirm.exec();
            if (confirm.clickedButton() != accept)
            {
                return;
            }
            // 与 CKS 的 CiTool 调用相同，事务租约让退出等待有界的子进程清理。
            QMessageBox resultBox(parent); // resultBox：执行中及最终回执属于同一窗口。
            PrepareBox(resultBox, QStringLiteral("ks_driver_policy_result"));
            resultBox.setText(sourceText(QStringLiteral("正在禁用驱动策略，请稍候…")));
            QPushButton* close = resultBox.addButton(sourceText(QStringLiteral("关闭")),
                QMessageBox::RejectRole); // close：执行结束才可关闭，不提前显示成功。
            close->setToolTip(sourceText(QStringLiteral("关闭提示")));
            close->setEnabled(false);
            AsyncOperation action(&resultBox); // action：与回执框同寿命的共享后台事务控制器。
            const auto ticket = action.submitTransaction<DriverPolicyOperations, driver_policy::RemovalResult>(
                operations,
                [](const DriverPolicyOperations& request) { return request.remove(); },
                [&resultBox, close](const driver_policy::RemovalResult& result, std::uint64_t)
                {
                    resultBox.setText(result.accepted
                        ? sourceText(QStringLiteral("策略禁用请求已提交。请保存工作并重启电脑，然后重新加载驱动。"))
                        : sourceText(QStringLiteral("未能禁用策略。请以管理员身份运行并完成 Windows 更新后重试，或查看帮助。")));
                    if (!result.accepted)
                    {
                        AddHelpButton(resultBox);
                    }
                    close->setEnabled(true);
                    return true;
                },
                [&resultBox, close](std::exception_ptr)
                {
                    resultBox.setText(sourceText(QStringLiteral("无法确认策略是否已禁用。请查看帮助后重试。")));
                    AddHelpButton(resultBox);
                    close->setEnabled(true);
                }); // ticket：0 表示退出中或控制器拒绝，并不证明执行成功。
            if (ticket == 0)
            {
                resultBox.setText(sourceText(QStringLiteral("暂时无法禁用策略，请稍后重试。")));
                close->setEnabled(true);
            }
            resultBox.exec();
            action.close();
        }
    }

    bool IsDriverPolicyLoadFailure(const unsigned long errorCode)
    {
        // 只匹配 issue 截图中的 4551，不能把 577、1275 或组策略错误 1260 扩成同一流程。
        return errorCode == ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION;
    }

    QString DriverPolicyHelpUrl()
    {
        return QString::fromLatin1(
            "https://3304711297.github.io/youshouldknow/%E7%B3%BB%E7%BB%9F%E7%9F%A5%E8%AF%86/"
            "Windows%E6%96%B0%E9%A9%B1%E5%8A%A8%E7%A8%8B%E5%BA%8F%E7%AD%96%E7%95%A5%E4%B8%8E%E5%85%B3%E9%97%AD%E6%96%B9%E6%B3%95/");
    }

    QString DriverLoadFailureAdvice(const unsigned long errorCode)
    {
        return sourceText(QStringLiteral(
            "原因：Windows 的应用程序控制策略拒绝加载这个驱动，可能与旧交叉签名有关（错误 %1）。"))
            .arg(errorCode);
    }

    void ShowDriverLoadFailureDialog(QWidget* parent, const unsigned long errorCode,
        const DriverPolicyOperations& operations)
    {
        // 新提示只服务 4551；其他错误直接返回，不启动预检、不替代调用方原有报错。
        if (!IsDriverPolicyLoadFailure(errorCode))
        {
            return;
        }
        QMessageBox box(parent); // box：正文只显示原因和处理方法，不显示后台检查或系统命令。
        PrepareBox(box, QStringLiteral("ks_driver_load_failure"));
        box.setText(DriverLoadFailureAdvice(errorCode));
        box.setInformativeText(sourceText(QStringLiteral("处理方法：正在检查可用的处理方式…")));
        QPushButton* close = box.addButton(sourceText(QStringLiteral("关闭")),
            QMessageBox::RejectRole); // close：默认不操作系统；主程序保持当前 R3 会话。
        close->setToolTip(sourceText(QStringLiteral("关闭提示")));
        box.setDefaultButton(close);
        box.setEscapeButton(close);
        QPushButton* remove = nullptr; // remove：确认更新后显示；执行资格仍在用户确认后重新检查。
        AsyncOperation query(&box); // query：后台 CiTool 只读进程纳入现有退出事务管理。
        const auto ticket = query.submitTransaction<DriverPolicyOperations, driver_policy::Snapshot>(operations,
            [](const DriverPolicyOperations& request) { return request.query(); },
            [&box, &remove](const driver_policy::Snapshot& snapshot, std::uint64_t)
            {
                // 按已安装更新选择操作入口；真正执行前仍由后端重新校验全部安全条件。
                if (snapshot.update == driver_policy::UpdateState::July2026OrLater)
                {
                    box.setInformativeText(sourceText(QStringLiteral(
                        "处理方法：禁用此驱动策略后重启电脑，再尝试加载驱动。禁用会降低系统的驱动保护。")));
                    remove = box.addButton(sourceText(QStringLiteral("禁用策略")), QMessageBox::DestructiveRole);
                    remove->setToolTip(sourceText(QStringLiteral("禁用此驱动策略，重启后生效")));
                }
                else
                {
                    box.setInformativeText(sourceText(QStringLiteral("处理方法：请查看帮助，按文中的步骤处理后重试。")));
                    AddHelpButton(box);
                }
                return true;
            },
            [&box](std::exception_ptr)
            {
                box.setInformativeText(sourceText(QStringLiteral("处理方法：请查看帮助，按文中的步骤处理后重试。")));
                AddHelpButton(box);
            }); // ticket：退出期间拒绝请求时也要给出明确的只帮助状态。
        if (ticket == 0)
        {
            box.setInformativeText(sourceText(QStringLiteral("处理方法：请查看帮助，按文中的步骤处理后重试。")));
            AddHelpButton(box);
        }
        box.exec();
        query.close();
        if (remove != nullptr && box.clickedButton() == remove)
        {
            RunRemoval(parent, operations);
        }
    }
}
