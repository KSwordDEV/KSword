# Contributing to Ksword ARK

## 贡献

项目按 [LICENSE](LICENSE) 的条款发布（当前为 KSword Community Source License 1.6）。提交代码即表示你有权提交，并同意该贡献随项目按对应许可证约束处理。第三方代码请保留其原有许可证文本。

讨论和协作遵守 `COMMUNITY_COVENANT.md`；它是社区约定，不会给许可再加限制。

## 开始开发

先读取本平台可用的用户/历史记忆，以及仓库共享记忆索引 [`.claude/memory/MEMORY.md`](.claude/memory/MEMORY.md)，再按任务主题阅读相关记忆。UI、主题和窗口背景变更先阅读 [UI 架构](.claude/memory/ksword-ui-architecture.md)。

工具链、HostX64 检查、链接器恢复、驱动后置校验、发行包和 Launcher 报告接入见 [构建与发布](docs/构建与发布.md)。主程序构建使用 `tools/Invoke-KSwordBuildCheck.ps1`；构建通过不代表签名、驱动加载或硬件实验通过。

## 模块边界

- 共享 IOCTL 协议只放在 `shared/driver/`。
- 驱动新 IOCTL 先在 `KswordARKDriver/src/dispatch/ioctl_registry.c` 注册，再在 `src/features/<module>/<module>_ioctl.c` 实现 handler。
- 用户态 R0 调用只通过 `Ksword5.1/Ksword5.1/ArkDriverClient/`。Dock UI 不直接调用 KswordARK `DeviceIoControl`。
- 新增源码必须加入对应 `.vcxproj` 和 `.filters`。
- 修改 CLI 命令、别名或参数时，同步 `KswordCLI.cpp` 内置 help 与 [CLI 使用文档](docs/CLI使用文档.md)。
- 修改主程序用户可见文本时，定点更新 `Ksword5.1/Ksword5.1/languages/zh-CN.json`、`en-US.json` 并运行 `tools/i18n_language_pack.py audit`；不要用 JSON 序列化脚本整体重写语言包。
- 第三方代码必须保留原有许可证文本。
- DynData 共享协议只能维护在 `shared/driver/KswordArkDynDataIoctl.h`；驱动侧不要复制结构体定义。
- 统一驱动状态/能力协议只能维护在 `shared/driver/KswordArkCapabilityIoctl.h`；KernelDock 能力页只通过 `ArkDriverClient::queryDriverCapabilities()` 获取状态。
- System Informer DynData 只允许作为 `third_party/systeminformer_dyn/` 数据源接入，禁止顺手搬入 KPH 对象系统、通信层、session token 或 System Informer IOCTL。
- 依赖未公开内核字段的功能必须通过 DynData capability gating 判断，不要在业务功能里散落新增硬编码偏移。
- 新增依赖私有偏移的 IOCTL 必须在 `KswordARKDriver/src/dispatch/ioctl_registry.c` 的 `RequiredCapability` 填写对应 `KSW_CAP_*`；无依赖时才使用 `KSWORD_ARK_IOCTL_CAPABILITY_NONE`（也就是 `0ULL`）。
- 进程扩展信息统一走 `shared/driver/KswordArkProcessIoctl.h` v2；Protection、SignatureLevel、ObjectTable、SectionObject 等 EPROCESS 字段只能来自 DynData/Runtime resolver，并在 UI 展示字段来源。
- PPL 修改属于高风险 R0 写字段动作，必须依赖 `KSW_CAP_PROCESS_PROTECTION_PATCH`，并在用户态二次确认中展示当前值、目标值、签名级别联动和回滚风险。

## 合并冲突控制

- 协议头变更先合并。
- `.vcxproj`/`.filters` 变更由单一 owner 集中合并。
- 不同 owner 避免同时修改同一个 Dock 大文件。
- R3 监控相关施工期间，如果任务只涉及 R0/DynData，请不要编译主程序、Taskbar 或 HUD；确需验证时先和当前 R3 owner 对齐。
