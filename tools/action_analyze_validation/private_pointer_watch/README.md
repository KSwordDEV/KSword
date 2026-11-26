# 私有内存指针导出验收夹具

对应 ActionAnalyze 验收清单第 5 项。正式 CLI 以
`analyze breakpoint session --export NAME --watch-write-bytes W --watch-pointer-export`
启动本目录构建的合作目标；目标在映像可写数据节发布一个 8 字节对齐的
`WatchedPointer`，并在启动后分配 `MEM_PRIVATE` 区域写入该指针。

## 协议

1. 目标解析命令行中的 `--ksword-breakpoint-ready` 与 `--ksword-breakpoint-gate`
   继承句柄，不打开任何命名事件作为就绪证据。
2. 初始化私有区域和指针后 `SetEvent(ready)`；宿主必须在 5 秒内观察到，
   否则启动失败。
3. 目标阻塞读取 Gate 管道。只有收到一个字节 `'1'` 才进入业务写入；
   管道 EOF 表示宿主取消启动，目标正常退出。
4. 业务四轮：范围外/同值写、主线程真实变化、首次停点后新建线程写入、
   脱离后写入。每轮完成后置位 `done`。

## 用例模式

环境变量 `KSWORD_PRIVATE_POINTER_MODE`：

| 值 | 含义 |
| --- | --- |
| `valid` | 私有 RW 或 RWX 区域，指针 8 字节对齐 |
| `null` | 指针为 0 |
| `misaligned` | 指针在 8 字节宽度下未对齐 |
| `readonly` | 区域保护改为 `PAGE_READONLY` |
| `image` | 指针指向映像可写数据节，类型不是 `MEM_PRIVATE` |
| `boundary` | 指针位于提交页末端，关注宽度越出区域 |
| `pointer-change` | 首次停点后把选择器改指另一私有分配，再写旧地址 |
| `protect-change` | 首次停点后把区域保护改为 `PAGE_EXECUTE_READWRITE`，写入仍可完成但保护属性已不同 |
| `mapped-reuse` | 释放区域并在同址映射文件视图后写旧地址 |
| `no-ready` | 不置位 Ready，阻塞 Gate；验证 5 秒上限与 EOF 退出 |
| `exit-before-ready` | 在 Ready 前以退出码 7 退出 |

其他环境变量：

- `KSWORD_PRIVATE_POINTER_WIDTH`：1、2、4、8。
- `KSWORD_PRIVATE_POINTER_PROTECT`：`rw` 或 `rwx`。
- `KSWORD_PRIVATE_POINTER_EVENTS`：`trigger`/`done` 事件的本地名前缀。
- `KSWORD_PRIVATE_POINTER_RECEIPT`：目标写入实际指针、分配基址、区域基址、
  区域字节数和保护属性的小型文本回执，仅用于本机验收对账。

## 构建

MSVC 工程 `PrivatePointerWatchChild.vcxproj` 使用固定
`IntDir=<本目录>/x64/Release` 和统一 `OutDir=Ksword5.1/x64/Release`。

本机当前只允许 GCC 构建夹具（MSBuild 目录被运行环境拒绝），验收脚本使用：

```powershell
gcc -O2 -Wall -Wextra -Wno-unused-parameter -o Ksword5.1/x64/Release/ActionAnalyzePrivatePointerWatch.exe `
  tools/action_analyze_validation/private_pointer_watch/PrivatePointerWatchChild.c `
  -Wl,--dynamicbase -Wl,--nxcompat
```

构建与运行统一低于正常优先级，并持有
`Local\KSword.ActionAnalyze.CliValidation` 命名互斥。

## 运行

```powershell
python -B tools/action_analyze_validation/private_pointer_watch/private_pointer_watch.py `
  --expected-cli-sha256 <正式 CLI SHA-256>
```

脚本为每条用例独立启动 CLI 与目标，核对真实地址、区域属性、停点线程、
旧令牌、Continue、Close 脱离和错误模式。证据写入
`.codex-build-logs/behavior-planning/action-analyze-private-pointer-watch-*.log`。
夹具 EXE 和本目录 `x64/Release` 在批结束时清理。

`KSWORD_POINTER_EXPORT_LEGACY_VALUE=1` 只用于尚未重建的旧 CLI；该构建把
`--watch-pointer-export` 误当有值选项。修复源码在
`KswordCLI/CommandRegistry.cpp`，重建后的正式 CLI 不应再设置该变量。
