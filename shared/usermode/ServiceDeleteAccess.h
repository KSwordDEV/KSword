#pragma once

#include <Windows.h>
#include <winsvc.h>
#include <functional>
#include <string>

namespace ksword::service
{
    // 回退结果：handle 由调用者 CloseServiceHandle；其余字段说明失败阶段和权限恢复结果。
    struct DeleteAccessResult
    {
        SC_HANDLE handle = nullptr; // 已取得最小查询/删除权限的服务句柄。
        DWORD error = ERROR_SUCCESS; // 原始 Win32 错误，不用显示文本推导结果。
        std::wstring stage; // 失败的 API/阶段名称，供日志及诊断使用。
        bool securityChanged = false; // 曾修改 Owner 或 DACL。
        bool securityRestored = false; // 已修改的权限是否恢复到原快照。
        DWORD restoreError = ERROR_SUCCESS; // 恢复失败时保留独立错误码。
    };

    // 仅在普通 OpenService 因权限不足失败后调用；warning 在申请额外权限前同步触发。
    // 输入为本机 SCM、服务名及可选告警回调；返回句柄前恢复原权限，不停止/删除服务。
    DeleteAccessResult OpenDeleteAccessWithTakeover(
        SC_HANDLE manager,
        const std::wstring& name,
        const std::function<void()>& warning = {});
}
