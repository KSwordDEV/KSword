# OS build 上限与 DynData fail-closed

- `shared/KswordArkStartupProtocol.h` 的 `KSWORD_ARK_MAXIMUM_SUPPORTED_OS_BUILD` 必须与 Launcher 支持清单的 `osPolicy.advertisedMaximumBuild` 对齐；当前上限为 26100。
- `KswordArkStartupGetOsBuildNumber` 设置一次启动级支持标志。驱动仍可加载以提供诊断，但 `KswordARKDynDataActivateRuntimeOffsets` 在上限外不得运行 pattern/layout fallback。
- `ioctl_dispatch.c` 在上限外拒绝所有 offset-dependent IOCTL（包括 capability query），只保留 preflight 与静态 IOCTL registry；这样未知 build 不会因为“看起来结构相似”而触发不受支持的内核访问。
- Launcher 的 `allowNewerWindows11=false` 必须在 GUI 启动路径实际生效；内部 upload 模式可继续生成支持收集包。R0 gate 是最终安全边界，Launcher gate 只负责避免普通 GUI 误启动。
