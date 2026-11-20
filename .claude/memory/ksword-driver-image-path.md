# SCM 驱动镜像路径（Issue #236）

- `DriverDock` 的“注册/更新”走 `ks::service::CreateOrUpdateKernelDriverService`，由 `CreateServiceW` / `ChangeServiceConfigW` 持久化。驱动 `ImagePath` 是路径，不是用户态服务的命令行。不要因含空格自动加引号，也不要把驱动规范化套到通用服务配置入口。
- 在 Windows 10 20H2 build 19042，分别向 SCM 传入带空格的含引号 DOS 路径（正斜杠或反斜杠）均原样保存且启动返回 123；无引号时 SCM 将 DOS 路径存为 `\??\C:\…`。应用只去外围引号、规整分隔符，不自行追加前缀或展开系统路径。
- 同一份可卸载测试驱动用旧参数复现 123，再以生产服务层覆盖旧值和全新注册，均回读 `\??\C:\KSword Issue 236\Driver.sys` 且达到 `SERVICE_RUNNING`。临时服务及来宾文件已清除，不改变签名策略。`tools/Invoke-StorageControllerServiceTests.ps1` 覆盖两种写入、已有路径前缀及用户态命令行不变；未进行主程序 GUI 点击测试。
