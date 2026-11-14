# 进程列表无自定义 DLL 强开控制台

- 入口：进程 → 进程列表 → 右键 → 强开控制台，位于 DLL/Shellcode 注入下方。
  `ProcessDock.Console.cpp` 只连接 UI；后端在 `shared/usermode/ProcessConsole.*`、
  `ProcessConsoleRemote.*`，不依赖 Qt，不新增 R0/CLI 入口。
- 按 WindowsMarker `StartConsole` 顺序执行控制台、CONIN$/CONOUT$、SetStdHandle、UTF-8、
  已加载 UCRT 标准流重定向/无缓冲、MSVC14 STL 同步/六流 clear；没有本地 AttachConsole。
  仅使用目标已加载模块，不注入/落地/加载自定义 DLL，不主动 LoadLibrary。
- x64 主程序内置 x86/x64 调用例程。GetLastError/GetProcAddress 引导地址复用
  `ApiMonitorRemoteExports.h` 读取目标 PE；后续在目标调用 GetProcAddress，不复用宿主 RVA。
  x86 同时支持 stdcall/cdecl/thiscall，x64 参数遵守 shadow space/对齐。
- `FILE*` 来自目标 `__acrt_iob_func`；MSVC ostream 的 basic_ios 地址从目标 vbtable 第二项读取，
  不能把导出的 ostream 起始地址直接作为 basic_ios 的 this。静态/私有运行库不猜，日志说明未处理。
- 菜单打开时冻结目标集合，后端在操作句柄再次验证 PID+真实创建时间并检查存活。
  复用已有异步动作执行器，单目标同样异步。超时保留远程代码/参数到目标退出，不提前释放。
- `tools/process_console/Build-ConsoleFixture.ps1 -Architecture x64|x86` 使用 HostX64 `/W4 /WX`。
  x64 宿主对两位数动态/静态四组目标首次/重复调用、错误身份拒绝、Win32 I/O/UTF-8通过；
  动态目标 C stdin 及 Win32/C/C++ 窄宽共九路实际屏幕缓冲区匹配 `0x1ff`。
  真实 Sleep 超时后参数页保留和迟到线程返回后目标可用也已验证。
- 真实 Release 主程序通过现有 MCP 桥执行右键动作，x64/x86 动态夹具均回读 `0x1ff`。
  当前浅色菜单已截图检查。深色/窄窗/DPI/背景模式未验收，不能宣称全页面视觉通过。
- 文档和重复验证入口见 `docs/进程强开控制台.md`；截图/夹具结果在
  `.codex-build-logs/process-console/`。测试临时主程序正常关闭，无遗留夹具进程。
- HostX64 Release 主程序构建最终通过：
  `.codex-build-logs/ksword-build-check-20261113-235357.raw.log`，
  `BUILD_RESULT=SUCCESS` / `EXIT_CODE=0`，语言/主题门禁通过；
  EXE SHA256=`28161BCB302FAC78A69EAAF616EC2591FA9F5AC9755EBACCAAECFDC81E652AAF`。
