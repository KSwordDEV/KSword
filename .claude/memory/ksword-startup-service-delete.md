# 启动项服务删除权限回退

- `StartupDock` 的删除事务在 SCM `OpenService(DELETE | SERVICE_QUERY_CONFIG)` 返回 `ERROR_ACCESS_DENIED` 时触发同步告警回调；使用同一 `kLogEvent` 输出 `warn` 和最终操作回执，不在工作线程弹窗。
- 主程序 `ksword/startup/startup.cpp` 与共享 R3 `backend/startup/StartupEnumerator.cpp` 共用 `shared/usermode/ServiceDeleteAccess.cpp`，四个消费者工程均登记源码及头文件。
- 回退只启用有效身份复制令牌上的 `SeTakeOwnershipPrivilege`/`SeRestorePrivilege`；先保存 SCM 服务对象 Owner/DACL，再按需接管 Owner、临时追加最小删除/配置查询权限。不是修改服务 EXE 或 Services 注册表键所有者。
- 取得删除句柄后先恢复原 Owner/DACL，再恢复线程身份。原安全描述符恢复失败时关闭删除句柄并报告独立恢复错误，不继续删除。原有服务配置快照校验与 KswordARK 服务生命周期约束仍保留。
- 特权申请必须检查 `ERROR_NOT_ALL_ASSIGNED`；不能把调用成功误报为特权已取得。受保护服务及显式拒绝 ACE 不承诺能通过此回退。
- 回归入口：在 x64 VS 开发环境运行 `tools/Invoke-ServiceDeleteAccessTests.ps1`，使用模拟 SCM/特权写入与真实 SDK ACL 解析，不修改任何真实服务。
- 接管阶段同样可能返回 `ERROR_SERVICE_MARKED_FOR_DELETE (1072)`；仅当未残留权限修改且恢复无错误时按 `NoChange/success` 处理，不能再误报权限不足。服务仍运行或有未关闭句柄时依旧可能被枚举；不得据此宣称实际移除，也不能把恢复阶段的 1072 吞成成功。
