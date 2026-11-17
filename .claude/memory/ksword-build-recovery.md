# KSword MSVC / WDK 构建恢复

## 用户要求：构建默认低优先级（2026-11-17）

所有项目构建以 BelowNormal 启动，编译与链接子进程继承该优先级。`tools/Invoke-KSwordBuildCheck.ps1` 在启动任何构建工具前降低宿主优先级，并在 finally 恢复调用者原优先级；直接启动 MSBuild/WDK 时同样降低宿主优先级。结果汇报先说结果、原因和测试数据，验证范围与限制统一放在最后。

## 构建脚本结果读回与 Qt 回退（2026-10-01）

- Invoke-KSwordBuildCheck.ps1 在仓库 Qt 缺失时使用约定的备用 Qt 路径，仍校验 x64 MSBuild 与 HostX64；不降级到 32 位入口。
- Windows PowerShell 的 Start-Process -PassThru 对象若未持有底层进程句柄，子进程结束后 ExitCode 可能为空。启动后立即读取 Handle，再等待/刷新/读取 ExitCode；空值必须拒绝，不能转为成功。本轮最终构建明确读回 EXIT_CODE=0。
- 从带 PowerShell 7 环境的终端启动 Windows PowerShell 5.1，继承的 PSModulePath 可能使 Get-FileHash 模块导入失败；使用 pwsh 启动构建助手并先初始化 x64 VS 开发环境可完成构建与产物核验。
- 2026-10-14：安装技能中的旧构建脚本缺少宿主门禁，主程序 LTCG 曾进入 HostX86/x64 链接器并触发 `C1002` 堆不足；链接器自动重启 HostX64 后继续生成代码也不能抹掉整体退出码 1。使用仓库 `tools/Invoke-KSwordBuildCheck.ps1`，其构建前验证 MSBuild 的 x64 PE 身份、`PreferredToolArchitecture=x64` 和 `VC_ExecutablePath_x64` 中的 HostX64；安装技能副本不能覆盖仓库的强制构建约定。

## Qt 运行库部署需要 VS 开发环境

- 直接从普通 PowerShell 调用 MSBuild 可以完成主程序链接，但构建后
  `windeployqt --compiler-runtime` 可能因 `VCINSTALLDIR` 未设置而返回 1，最终报 MSB3073。
  先通过当前 VS 的 `Common7/Tools/VsDevCmd.bat -arch=x64 -host_arch=x64` 初始化环境，
  再运行原有 `/t:Build`；确认 Qt/VC 运行库部署与整个 Build 都成功。不要仅凭 exe 已更新
  宣称完整构建通过，也不要跳过部署来掩盖环境错误。
- 主程序 `DeployQtRuntime` 使用增量 windeployqt，不再默认 `--force`。已经相同的 Qt DLL
  可能被辅助程序占用；强制删除会报 Cannot remove existing file。增量部署仍复制缺失或更新
  的依赖，不关闭部署目标。2026-10-01 现场已确认 Release/Qt6Core.dll 与 Qt 6.9.3 源 DLL
  SHA256 相同，无 `--force` 部署正常通过。

适用范围：`C:\Users\Felix\CLionProjects\KSword` 的主程序 Release/x64 构建与 `KswordARKDriver` WDK 后置验证。

## 主程序 `LNK1000 IMAGE::BuildImage`

- 项目只使用 64 位 MSBuild 与标准 MSVC HostX64 工具、仓库 Qt 与 QtMsBuild；不要切换 LLVM、替代 TargetName，也不要因为一次链接器内部错误自动升级或降级 MSVC。构建入口统一为仓库 `tools/Invoke-KSwordBuildCheck.ps1`。
- 当同一任务出现 `LNK1000`、`IMAGE::BuildImage` 或 `.iobj`，只执行一次 `tools/Invoke-KSwordBuildCheck.ps1 -Action Rebuild -DisableWholeProgramOptimization`。该脚本在临时 props 中关闭 WPO/LTCG，结束后移除该 props，不会改动工程。
- 通过条件必须同时是 `BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`，以及非零 `Ksword5.1\x64\Release\Ksword5.1.exe`。WPO 禁用构建会使普通增量缓存失效；不要紧接着再跑普通 Build，只用 `-VerifyArtifactOnly` 做读回。
- 只有这条构建局部恢复路径仍复现后，才考虑 VS servicing update 或并列 v143 工具集。

## 主程序 `C1002` 与工具架构降级

- Codex 子进程可能同时缺少 `PROCESSOR_ARCHITECTURE` 与 `PROCESSOR_ARCHITEW6432`。MSVC 的 `Microsoft.Cpp.ToolsetLocation.props` 会因此把工程内的 `PreferredToolArchitecture=x64` 改为 x86；大工程的 LTCG 随后可能报 `C1002`，32 位链接器再自行重试 64 位也会留下失败退出码，不能当作完整构建通过。
- 使用仓库构建脚本：它仅选择 `Bin/amd64/MSBuild.exe`，校验入口 PE，并同时传入 `/p:PreferredToolArchitecture=x64`、`/p:PROCESSOR_ARCHITECTURE=AMD64` 与 `/p:PROCESSOR_ARCHITEW6432=AMD64`。构建前读回 `PreferredToolArchitecture` 与 `VC_ExecutablePath_x64`，未解析成 HostX64 即拒绝。
- `ToolsetLocation.props` 的根节点含 `TreatAsLocalProperty="PreferredToolArchitecture"`，会覆盖该全局属性；只传工具偏好仍不够。2026-09-30 的只读 MSBuild 属性输出证实：两项宿主架构为空时工具偏好仍变成 x86。
- 2026-10-12 再次确认：外置同名构建 skill 脚本若漏传三项 x64 属性，可能先使用 HostX86 链接器并在 `KernelDock.KernelHooks.cpp` 的 LTCG 第二遍报 `C1002`；本次改用仓库 `tools/Invoke-KSwordBuildCheck.ps1` 后，脚本回读 HostX64，Release/x64 Build 成功。优先使用仓库脚本，不把这种宿主工具失配归因于新页面源码。
- CE 的发布入口、调试适配 DLL 与项目构建仅使用 x64。

## Qt 部署重复覆盖

- 2026-10-04 合并后 Taskbar Release 同样因 `windeployqt --force` 无法删除已占用的 `Qt6Core.dll` 而报 MSB3073；Release DLL 与 Qt SDK DLL 的 SHA256 一致。`DeployTaskbarQtRuntime` 也改为标准增量部署，保留完整 Qt Multimedia 与媒体插件部署；必须确认整个 Build 退出码为 0，不能只验收已链接的 Taskbar.exe。
- 2026-09-30 观察到 `windeployqt --force` 无法删除已有 `Release/Qt6Core.dll`，其 SHA256 与仓库 Qt SDK 完全相同。标准增量部署成功输出 `Qt6Core.dll is up to date.` 并完成其他依赖；主程序部署目标已移除无条件 `--force`，仍由 windeployqt 更新有变化的依赖，并传入 `VCINSTALLDIR`。
- 编译/链接成功但 Qt 部署失败时，整体 Build 仍是失败，不能以新 exe 已生成替代后置部署通过。

## 驱动 x64 WDK 后置验证

- 要把 `.sys` 的编译/链接、`ApiValidator`、`Inf2Cat`、签名和实际加载分别报告。`ApiValidator` 通过不等于发行或可加载。
- 已观察到 WDK 后置阶段会误选 ARM64 `ApiValidator`/`aitstatic`，或在 `KswordARK.sys` 链接更新后无子进程地卡住。先确认输出 `.sys` 的时间戳/哈希已更新，并确认指定 MSBuild PID 没有活跃的 `cl.exe`、`link.exe`、`ApiValidator.exe` 或 `aitstatic.exe` 子进程，才能停止该唯一的卡住进程。
- 用 `/t:ApiValidator` 配合 `/p:ApiValidator_ApiExtractorExePath='C:\Program Files (x86)\Windows Kits\10\bin\<已安装版本>\x64'` 验证刚链接的 x64 `.sys`；`Driver is 'Universal'.` 是这一独立阶段的成功标志。
- 若失败发生在 `.sys` 链接之前，后置验证不能掩盖它，必须修复真实的编译/链接报错。
