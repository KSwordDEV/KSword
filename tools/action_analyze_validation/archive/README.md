# CLI Stored 段验证

从仓库根目录运行。脚本使用 HostX64 MSVC 在固定 `KswordCLI/x64/Release/ActionAnalyzeArchiveValidation` 编译独立夹具，执行统一 Release 下的 `ActionAnalyzeArchiveValidation.exe`，结束后清理本次测试产物。

```powershell
pwsh -File tools/action_analyze_validation/archive/Test-SegmentArchive.ps1
```

若本机 VS 不在默认搜索位置，可用 `-VcVars64` 指定 x64 开发环境脚本。验证包含独立编码的字节级比对、每个截断字节端点、损坏后禁止重同步、只读文件保留、身份字节序、显式扫描端点、活动段增长、create-new 及 A0 字节向量。

## A0 正文校验边界

`ScanSegment` 返回 `framedBytes`。`FramingComplete` 表示指定范围内的段头、块、记录封装与 CRC 已通过校验。`RecordView::catalogTypeV1` 仅表示类型编号在目录中且头部声明 v1。所有记录以原字节交给调用方，`interpretedBytes` 保持 `nullopt`。

上层对每块另行校验 RawRecord v1 和 CanonicalEvent v1 的正文，确认必需类型存在适用的解码器，并验证外部引用。按 A0 `base-contract-v1.md` 的口径，在正文失败或必需类型仅能浏览原字节时，保留 `framedBytes`，同时停止推进语义端点。必需的目录内不透明记录也适用此规则。刷盘结果由 `FlushedBytes()` 报告，发布跨流持久水位还需有效 checkpoint。
