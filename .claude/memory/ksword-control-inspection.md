# 窗口控件检查

- 页面入口在 `OtherDock/OtherDock.cpp` 的 WindowDetailDialog，位于类信息之后；采集、输入、覆盖绘制和页面分为 `WindowControlInspection*.cpp`。
- 绘制层始终 `WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE`。一次性拾取通过临时鼠标低级钩子处理，必须吞掉完整左键 down/up；取消或关闭发生在 down 后，仍保留配对消费状态直到 up，不能提前卸载。Ctrl+Shift+C、Esc 同样保留被消费按键的 key-up，异步回调检查会话代次。
- 悬停与树选中是独立状态。悬停更新右侧完整属性，不改选树；程序恢复选中或完成拾取时不触发用户树选择的属性查询。刷新按 RuntimeId 或 HWND/PID/TID 身份原地更新、删除过期节点，保留展开及选中。
- UIA COM 对象只在 MTA 采集线程创建、查询、订阅和释放；UI 线程轮询值快照邮箱。关闭取消代次，不在 UI 线程 join 外部 Provider 调用。线程绑定调用方桌面，退出前恢复原桌面，避免 HWND 查询跨桌面以及被绑定桌面句柄无法关闭。
- 覆盖坐标统一为物理屏幕像素，按 backing-store DPR 转为绘图坐标。按目标／弹出窗口各自的可见 Z 序区域裁剪，忽略自身及 DWM cloaked 窗口；普通同矩形边框去重，不叠加容器填充。目标移动通过 hostBounds 相对位移即时跟随，属性和结构由事件加定时重采样更新。
- 2026-10-07 可读性修正：普通边框 3 个物理像素、alpha 180；悬停／选中边框 4 像素。悬浮卡片不能直接使用继承的 `QPalette::Base`，主程序透明主题会使该角色 alpha 为零；卡片改用 `SurfaceColor()` 并强制 alpha 255，文字同样不透明且通过 `EnsureTextContrast` 校准。覆盖层其余区域仍透明、点击穿透。
- 关联弹出内容不能只按 PID 纳入，须由 owner/子树或菜单、下拉框、提示所属 GUI 线程的 active/focus 关系确认。
- 已验证：隐藏桌面上的 ElementFromHandle 能读根节点，但 UIA TreeWalker 可能不提供子节点，连显式 Provider 的 Navigate 都不调用；不能据此推断普通桌面遍历失败。真实 UIA 子树回归使用当前桌面的屏幕外、不激活工具窗口。测试 Provider 同时提供稳定的 fragment-root COM 身份及可重复 RuntimeId。
- 回归入口 `tools/Invoke-ControlInspectionTests.cmd --dpi-matrix`，不切换输入桌面；页面图在 `.codex-build-logs/control-inspection-tests/`。输入策略回归不冒充真实低级钩子／物理输入端到端验收。
