# `5ba974a93` Qt/Light 增量与既有归档只读验收

## 结论

**FAIL，首错已保留，不重跑。** 本批不重采、不调用 CLI、不创建新 sample；Qt 由于编译首错没有新二进制，Light 只启动新 Release 一次做既有项目只读回放。

## 范围与构建

| 端 | 结果 | 实际身份与固定目录 |
| --- | --- | --- |
| Qt | FAIL | `Ksword5.1/Ksword5.1/ActionAnalyze/OfflineSegmentBehavior.cpp:51` C2664；`IntDir=Ksword5.1/Ksword5.1/Ksword5.1/x64/Release`，`OutDir=Ksword5.1/x64/Release`，MSVC `HostX64/x64`，BelowNormal；i18n audit PASS（32935） |
| Light | PASS | `KswordARKLight/x64/Release/obj` → `Ksword5.1/x64/Release`；MSVC `HostX64/x64`，BelowNormal；SHA256 `F0AD50F57B911F7C06F9B9E37731986E5F57ED8B3FFAF4020917E709717F2413` |

Qt 失败原因是 `optional<Rules::ArchivedApiMemoryWriteReturn>` 不能转换为生产投影器要求的 `optional<Evidence::ApiMonitorMemoryWriteReturn>`。没有修改产品源码，也没有用旧 Qt 产物冒充新版本验收。

## Light 只读回放首错

- 已保留项目：`desktop_behavior_history/light/archived-project/`。
- 已保留 sample：`18141f17-b514-4526-b9bb-63924ea690bd`。
- 只读原包：218 个；终止 Stored 序号 221。
- 采集：未启动；CLI：未调用；新 sample：未创建。
- 新 Light GUI exit 0，设置恢复，驱动状态 `absent`，本轮自有进程无残留。
- 首个产品侧 GUI 失败：行为树实际句柄名为 `写入与请求候选`，UIA 返回 `rootCount=0`、`itemNames=[]`；没有 `行为规则/Behavior Rules` 根，因此 Enter 原坐标和规则输入详情未执行，不判通过、不重试。
- 该既有项目没有 `NtQueryInformationProcess` 原包（0/218），所以 `process.debugQueryOutputValid`、`process.debugQueryOutputBits`、`process.debugQueryOutput` 只能记为 **NOT COVERED**；没有实时 Hook 覆盖结论。

## 清理与证据

- 用户已有 `Ksword5.1/Ksword-nice/Ksword5.1.exe` PID 28368 未触碰；它不是本轮自有实例。
- Qt/Light 旧主采集的目标与 GUI exit 0、设置/布局恢复证据保留在各自旧回执；旧 Qt/Light hash 不覆盖本批产品范围。
- 本批回执、构建日志、hash、清理清单、BMP/PNG 截图均在本目录；原始 Light 首错 traceback 与 UIA JSON 不改写。
- 未 push；提交只包含验收脚本与本批证据，不包含产品源码和用户夹具。

详细文件：`final-receipt.json`、`qt-build-receipt.json`、`light-build-receipt.json`、`hashes.json`、`cleanup.json`。
