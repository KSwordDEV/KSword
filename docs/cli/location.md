# Windows 默认位置

`system location query [--backend r3|r0] [--json]` 分别读取 Windows 默认位置五个注册表值、位置相关策略、系统和桌面应用位置授权值以及 `lfsvc` 服务状态。每个注册表值保留是否已知、是否存在、类型、原始字节及错误；授权值和服务状态使用 Win32 API。显式选择 R0 只影响默认位置和策略的注册表访问，不自动回退。

`system location set --latitude N --longitude N [--coordinate-system wgs84|gcj02|bd09] [--altitude N] [--accuracy N] [--altitude-accuracy N] --confirm [--backend r3|r0] [--json]` 把输入转为 WGS-84，写入 GUI 使用的五个 `REG_SZ` 值并逐项读取验证。半径和精度单位为米。写入可能在中途失败，输出每项是否尝试以及原始状态；已成功的写入不会自动回滚。`clear --confirm` 只删除这五个值并验证，保留注册表键及其余值。

`system location provider set --state disabled|default --confirm [--backend r3|r0] [--json]` 分别写入 `DisableWindowsLocationProvider=1` 或删除此策略，然后读取确认。这项策略影响整个系统，`default` 只移除该项，不覆盖其他位置策略。

`system location service reset-cache --confirm [--json]` 对 `lfsvc` 发出停止请求，对应 GUI 的缓存刷新行为；Windows 可以按需重新启动服务。查询时仍在停止中返回部分结果。`system location live query [--timeout-ms N] [--json]` 使用当前会话的 WinRT Geolocator，显示位置、精度、来源和 HRESULT；访问权限与系统实际定位结果由 Windows 决定。`system location convert --latitude N --longitude N --from wgs84|gcj02|bd09 --to wgs84|gcj02|bd09 [--json]` 仅做计算，GCJ/BD 换算为近似值。

系统默认位置只是 Windows 位置服务的后备输入，并不保证应用采用该位置。写入、服务停止或定位请求可能需要权限；命令不自动提升权限或切换后端。
