#pragma once

#include "../Framework/WindowsDriverPolicy.h"
#include <functional>

class QWidget;

namespace ks::ui
{
    // DriverPolicyOperations：生产默认使用真实后端；回归可注入值回执，绝不修改测试宿主策略。
    struct DriverPolicyOperations
    {
        std::function<driver_policy::Snapshot()> query = driver_policy::QuerySnapshot; // query：只读预检。
        std::function<driver_policy::RemovalResult()> remove = driver_policy::RemovePolicy; // remove：用户确认后的事务。
    };

    // IsDriverPolicyLoadFailure：输入 StartService 的 Win32 错误码，仅 4551 进入新策略弹窗。
    // 577/1275 的旧签名弹窗及其他错误处理不由本模块接管。
    bool IsDriverPolicyLoadFailure(unsigned long errorCode);
    // DriverPolicyHelpUrl：返回 issue 指定博客的固定地址；供帮助按钮使用，不访问网络。
    QString DriverPolicyHelpUrl();
    // DriverLoadFailureAdvice：输入原始错误码，返回日志和弹窗共用的已翻译指导正文。
    QString DriverLoadFailureAdvice(unsigned long errorCode);
    // ShowDriverLoadFailureDialog：UI 线程调用；仅显示原因及处理方法，检查和执行走后台事务。
    // parent：实际失败入口；errorCode：仅接受 4551；operations：默认真实后端，返回值无。
    void ShowDriverLoadFailureDialog(QWidget* parent, unsigned long errorCode,
        const DriverPolicyOperations& operations = {});
}
