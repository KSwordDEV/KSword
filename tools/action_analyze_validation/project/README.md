# CLI 离线项目验证

首批项目格式要求 `project.ksaproj` 的 `version` 为 JSON 数值 `1`，`requiredFeatures` 恰为 `["cli-offline-project-v1"]`。该能力覆盖项目元数据、调查说明修订和未采集样本的冻结配置。A0 约定项目和采样机器 schema 仍待冻结，当前互读范围为同版本 CLI 实现。

| 文件 | 身份及内容 |
| --- | --- |
| `project.ksaproj` | `kind=action-analyze-project`，包含项目 ID、标题、创建时间、当前修订、journal 头及 catalog 根，`producer=KswordCLI`，`storagePolicy=local-ntfs-offline-metadata` |
| `revisions/<revisionId>.json` | `kind=offline-project-revision`，包含项目 ID、修订 ID、父修订 ID 和原字节 hash、配置语义 hash 与 `config`。初始修订的两个父引用均为 `null` |
| `journal/<generation>.json` | `kind=project-commit`，包含 `previousGeneration`、`previousCommitHash`、操作 `create`／`saveRevision`／`addSample`、变更对象 ID 和 hash、当前修订和 catalog 引用 |
| `journal/previous.ksaproj` | 发布新指针前单独保存的上一个已提交指针，打开时按相同规则验证。主指针损坏时，回退只提供只读访问 |
| `catalog/<generation>/manifest.json`、`catalog/<generation>/<pageId>.json` | `sample-catalog` 根登记样本总量和页的精确 hash，`sample-catalog-page` 按提交顺序每页最多 256 项，页号从 1 开始。每行保存独立快照 ID 及 `sample.json` hash |
| `samples/<sampleId>/sample.json` | `kind=offline-sample`，保存样本身份、创建时间、标题和快照引用。`status=not-collected`，`requestedBackend`、`actualBackend` 和 `initialTarget` 均为 `null` |
| `samples/<sampleId>/snapshots/<snapshotId>.json` | `kind=offline-config-snapshot`，保存项目、样本、快照、修订身份，配置的完整副本及相应 hash |

`config` 的键严格为 `title` 和 `notes`。标题为 1–1024 UTF-8 字节，调查说明上限 65536 字节并允许 LF 和 TAB。时间为 FILETIME 纪元 100ns ticks。时间、代号、页号和数量采用规范十进制 u64 字符串。新 ID 采用小写连字符 UUID，A0 二进制 UUID 按文本从左到右的十六进制字节顺序。文档引用使用包括尾 LF 的文件原字节 SHA-256。配置语义 hash 采用 `aa-cjson-v1`，域为 `cli-offline-config-v1`。

写入要求本地 NTFS，项目上限 4096 个样本和 8192 个提交代号。`Create` 要求专用路径尚未存在。只读和写入打开均识别目录或其中的 `project.ksaproj`。`Save` 接收可选 `expectedRevisionId`，CLI 草稿提交宜提供该值。只读句柄固定打开时的已提交视图。新提交先将文件写入同卷 `.staging`，刷盘并读回后发布不可变文件，最后替换正式指针。未提交的代号和孤立样本目录保留给诊断，持有写锁的调用者可用 `ListOrphans` 列出孤立候选。正常打开从正式指针追溯 journal，并校验目录根及最新样本对应页，其它页和样本内容按需读取。

本能力边界是离线资料元数据。完整采集配置、活会话、归档、包装导入导出、修复和垃圾回收属于独立能力。物理掉电耐久性及不同存储设备行为还需实测。

## 运行

从仓库根目录运行，MSBuild 路径按本机 HostX64 工具链调整。`$fixture` 必须尚未存在，验证结束后确认并清理该目录。

```powershell
(Get-Process -Id $PID).PriorityClass = 'BelowNormal'
$base = 'tools/action_analyze_validation/project'
$fixture = "$base/x64/Release/offline-project-fixture"
& 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe' "$base/ProjectValidation.vcxproj" /t:Build /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 /p:PROCESSOR_ARCHITECTURE=AMD64 /p:PROCESSOR_ARCHITEW6432=AMD64 /m:1 /v:minimal
if ($LASTEXITCODE) { throw 'Build failed' }
& './Ksword5.1/x64/Release/ActionAnalyzeProjectValidation.exe' $fixture
if ($LASTEXITCODE) { throw 'Native assertions failed' }
python "$base/check_offline_format.py" $fixture
if ($LASTEXITCODE) { throw 'Independent format check failed' }
```

独立 Python 校验器输出所检查文件的 SHA-256、能力名与可达 journal 链。每次运行的 UUID 和 FILETIME 由系统生成，因此文件 hash 随夹具变化。

## 指定归档段读取

`ProjectDocument::InspectSegment` 在当前项目的已提交采样中按流和正数段号定位一个文件。`raw`、`records` 和 `control` 使用 20 位十进制段号。`analysis` 需要独立的 `runId` 目录与身份绑定。调用成功后，`SegmentInspection::framingStatus` 描述本次读取的封装检查，`interpretedBytes` 和 `durableBytes` 保持未知。`archiveStreamUnavailable` 与 `archiveSegmentUnavailable` 只说明指定位置的打开失败。可选 `endOffset` 是调用方指定的扫描边界，范围受 Archive 的 1 GiB 段上限约束。

`ProjectArchiveValidation.cpp` 是独立入口，可与四个原 Project 源文件、`ProjectArchive.cpp`、Archive 的 `SegmentFormat.cpp`、`SegmentReader.cpp`、`SegmentWriter.cpp`、`SegmentInspection.cpp`，以及 `EvidenceJson.cpp` 和 `LosslessValue.cpp` 一起编译。它接收一个尚不存在的夹具目录，验证目录与文件缺失、明确扫描端点、采样及段头身份、孤立样本、硬链接和项目文件不变。

## KSword callback archive

`python -B tools/action_analyze_validation/cli/callback_archive_graph.py --create-fixture` uses the existing Release project validator to create three synthetic samples in `tools/action_analyze_validation/project/x64/Release/callback-project-fixture`, then opens them read-only in `Ksword5.1/x64/Release/KswordCLI.exe`. The fixture contains only synthetic in-memory callback records and must not already exist.

Previously validated on the integrated Release working tree: native fixture and CLI both exited `0`. The nonempty sample `7df25ff0-b8ae-4c0d-91da-276dba502214` returned `raw/1 #2`, source sequence `107`, record offset `472`, packet offset `566`, length `1264`, and the notification time `133000000000000123`. The initial page, continuation, and complete empty sample `ebffbb80-7ca6-40ce-b990-ba6754605c2c` matched the raw batch counters. A conflicting batch returned `project-corrupt`; a changed cursor digest returned `stale-revision`. The CLI verified that all source files remained byte-for-byte unchanged. See the recorded `CLI_CALLBACK_ARCHIVE_GRAPH=PASS` in `.codex-build-logs/action-analyze-item4-callback-batch-notification-codebuddy.json`.

This receipt covers synthetic project archive readback. `sourceCoverage` remains `unknown`; callback hints do not identify process or thread instances or establish creation outcome or execution.

## 退役来源

Sysmon 已退出活动验证范围。项目验证器不再登记该来源，也不再提供旧正例生成入口；Light Stored 验证工程同步移除旧来源的源码和头文件登记。历史文件、既有用户档与历史回执保留，不计作当前采集、订阅、回放验收或发行能力。

本次仅检查退役接线，复用第 4 项正式 CLI 的自有回调回执，不重复构建或运行 GUI。实际修改和静态检查范围见[退役验证接线记录](../../../docs/action-analyze-planning/retired-validation-wiring.md)。
