# SOS 救援桌面

在 KSword 中选择「工具 → 救援模式」，也可以用真实键盘依次输入 `S O S Enter`。两条路径都从当前 `Ksword5.1.exe` 启动独立监护进程。Taskbar 运行时也能监听同一序列，并把请求交给配套的 `Ksword5.1.exe`。只安装主程序即可使用救援模式。

普通权限的引导进程在原桌面请求一次 UAC，接替进程校验真实提升令牌后创建私有 Win32 Desktop，再以同一令牌启动救援界面。已提升的发起方直接进入监护流程。取消 UAC、提权失败或令牌核验失败时结束本次启动。原窗口留在原桌面，救援窗口使用经过句柄校验的独立实例。

引导进程持有会话门闩并等待高权限监护进程退出，防止两个 SOS 监听器同时建立救援会话。UAC 接替只传原桌面名称，监护进程从当前模块路径确定客户端，待提权后创建桌面及就绪、返回、监护句柄。监护模式在 Qt 初始化及普通实例互斥之前进入。

原桌面名称在请求 UAC 前读取。高权限监护进程按该名称打开原桌面，待它重新接收输入且 KSword 就绪后才切入救援桌面。引导、监护和客户端各自在 exe 同目录写入 `logs/sos-rescue-<PID>.log`。监护日志的 `client.started` 给出客户端 PID，可用它查找参数、句柄和桌面校验阶段。客户端初始化失败会把 Win32 错误作为退出码返回。

救援窗口顶部有返回按钮，点击后恢复原桌面并关闭本次实例。真实键盘 `Ctrl+Alt+Shift+F10` 由监护进程处理，即使 KSword UI 线程正在阻塞也可请求返回。正常退出、子进程退出及监护进程意外退出各有恢复路径。切入前等待主事件循环和输入过滤器就绪，初始化失败不会退回在受干扰桌面启动 KSword。

## 桌面隔离与输入

- 桌面 DACL 不含允许 ACE，并以 OWNER RIGHTS 拒绝 ACE 关闭同账号所有者的隐式改 ACL 权限。普通进程不能按名称重新取得该桌面的窗口、Hook、读取安全描述符或修改 DACL 权限。
- 白名单只继承本次救援桌面、两个未命名事件和监护进程的 `SYNCHRONIZE` 句柄。启动时将 `STARTUPINFO.lpDesktop` 设为空字符串，让 Windows 在首次 USER32 连接时从继承句柄选择桌面。客户端在创建 Qt 或启动页窗口前核对继承句柄和当前线程桌面。线程尚未连接到目标时才调用 `SetThreadDesktop` 并回读桌面名。
- 监护循环在该桌面安装 `WH_MOUSE_LL` 与 `WH_KEYBOARD_LL`，拒绝注入及低完整性注入标志。Hook 回调不启动进程、读写磁盘或进入 Qt；耗时工作在其外部执行。
- KSword 再用 `GetCurrentInputMessageSource` 检查鼠标/键盘消息的设备和硬件来源，拒绝来源未知、系统合成及消息伪造。还拒绝应用队列制造的鼠标点击/滚轮和键盘事件。真实键盘保留。
- `IMO_HARDWARE` 可能包含 UIAccess 注入，因此不能单独作为物理输入证明，仍需低级 Hook 的注入标志。R3 无法鉴别伪装成真实设备的虚拟 HID、驱动级注入或进程被篡改后的输入。
- 退出恢复只针对当前活动的救援桌面，不抢走锁屏、UAC 或用户切换到的其他桌面。自动管理员/缩放重启和权限接管在救援模式下受限，避免丢失私有句柄。退出救援实例不自动停止原实例正在使用的全局 R0 服务。

这是独立的、限制访问的 Win32 桌面，不是 Windows 的 Winlogon/UAC 安全桌面。高级权限或内核代码仍可突破用户态的保护边界。

## 现有窗口能否平移

Windows 的 `SetThreadDesktop` 对已拥有窗口或 Hook 的线程返回 `ERROR_BUSY`。KSword 的 Qt 主线程及其他 UI 线程已有窗口和平台辅助对象，现有 HWND 无法通过公开接口直接搬到另一个桌面。本实现创建新实例，没有迁移旧实例的未保存编辑或内存会话。

参考：[SetThreadDesktop](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setthreaddesktop)、[桌面访问权限](https://learn.microsoft.com/en-us/windows/win32/winstation/desktop-security-and-access-rights)、[输入来源](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ne-winuser-input_message_origin_id)。

UAC 入口使用 [`ShellExecuteEx` 的 `runas`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow)，并在新监护进程中再次查询真实 `TokenElevation`。内部“已尝试提权”标记只防止重复提示，不能代替令牌检查。

## 验证

`tools/Invoke-RescueDesktopTests.ps1` 使用固定的 `Taskbar/x64/Release` 测试输出和 HostX64 编译器。测试创建隐藏的私有桌面，调用正式启动及绑定函数验证初始桌面、句柄白名单、已有窗口的同桌面校验、同账号按名打开的权限限制和输入来源检查。正式 `Ksword5.1.exe` 的探测覆盖会话互斥、无效客户端句柄和未提升令牌，主程序尚未更新时可用 `-NativeOnly` 跑原生回归。只跳过 Taskbar 单例探测时传入 `-SkipTaskbarProbe`。

Release 编译和这些回归不能替代 UAC 批准/取消、救援实例管理员令牌、实机桌面切入、真实鼠标/键盘、中文输入法、跨屏、锁屏/UAC、监护进程退出和焦点骚扰下的操作验收。首次现场验证应先使用正常桌面及可控的自建干扰程序，不运行 SilkMain。

2026-10-03 修正 UAC 原桌面接续后，用户已确认救援窗口正常显示、管理员状态已启用。本次运行日志确认监护进程的提升令牌、客户端就绪、成功切入与返回原桌面，客户端及监护进程均正常退出。锁屏、焦点骚扰及各类真实/模拟输入的完整验收仍需分别记录。
