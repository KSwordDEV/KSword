# KSword Agent Notes

## 共享记忆

跨 agent / 开发者共享的项目知识放在 `.claude/memory/`，索引见 `.claude/memory/MEMORY.md`。
任何 Codex、Claude 或其他 agent 开始处理本仓库任务前，必须同时读取两类记忆：

1. 该 agent 在当前平台可用的自身记忆、用户记忆或历史摘要（如果有）；
2. 仓库共享记忆索引 `.claude/memory/MEMORY.md`，并按任务关键词继续读取其中链接的相关主题文件。

`.claude/memory/` 是跨 agent 共享的项目记忆，不是 Claude 专用目录；即使 agent 不是 Claude，也不得因目录名而跳过。某一类自身记忆不可用时，应继续读取另一类可用记忆，不得将“没有自身记忆”作为跳过仓库共享记忆的理由。

改动主程序 UI、主题或窗口背景前，先读 `.claude/memory/ksword-ui-architecture.md`：其中记录了主题 token 体系、
全局样式块链路、透明背景与毛玻璃的平台约束，以及已经踩过的坑。新增可复用经验时请一并更新该目录。

## 发行版制作流程

本流程用于在仓库根目录 `C:\Users\Felix\CLionProjects\KSword` 生成包含完整 `Release\` 目录的 7z 发行包。默认参考旧包布局：`C:\Users\Felix\Downloads\KswordARK评估版本-260427-未签名R0-进程内存监控增强.7z`。

### 1. Release 构建

当前开发机有两套已验证的构建路径：优先使用仓库随附依赖，即 `.deps\Qt\6.9.3\msvc2022_64` 与 `.deps\QtVsTools\msbuild`；MSBuild 使用 `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe`。若该套不可用，再回退到 `D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe` 和 `D:\Software\Qt\6.9.3\msvc2022_64`。先设置 Qt 路径和 QtMsBuild 路径，再依次构建用户态项目。主程序必须重新构建；Taskbar、KswordHUD、APIMonitor_x64 也要构建后覆盖进包。

```powershell
$msbuild='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe'
if (!(Test-Path $msbuild)) { $msbuild='D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe' }
$env:KSWORD_QT_DIR=(Resolve-Path '.deps\Qt\6.9.3\msvc2022_64' -ErrorAction SilentlyContinue).Path
if (!$env:KSWORD_QT_DIR) { $env:KSWORD_QT_DIR='D:\Software\Qt\6.9.3\msvc2022_64' }
$qtMsBuild=(Resolve-Path '.deps\QtVsTools\msbuild').Path

& $msbuild 'Ksword5.1\Ksword5.1\Ksword5.1.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /p:QtMsBuild=$qtMsBuild /m:1 /v:minimal
& $msbuild 'Launcher\Launcher.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /m:1 /v:minimal
& $msbuild 'Taskbar\Taskbar.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /p:QtMsBuild=$qtMsBuild /m:1 /v:minimal
& $msbuild 'KswordHUD\KswordHUD.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /p:QtMsBuild=$qtMsBuild /m:1 /v:minimal
& $msbuild 'APIMonitor_x64\APIMonitor_x64.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /m:1 /v:minimal
```

#### 主程序 `LNK1000` / `IMAGE::BuildImage` 恢复

如果主程序的 MSVC 链接日志包含 `LNK1000`、`IMAGE::BuildImage` 或 `.iobj`，不要改用 LLVM、`amd64\MSBuild.exe`、替代 TargetName，也不要自动升级或降级 MSVC。先且仅执行一次干净重建，并仅对这次构建禁用 Whole Program Optimization：

```powershell
& "$env:USERPROFILE\.codex\skills\ksword-build-check\scripts\Invoke-KSwordBuildCheck.ps1" `
  -RepositoryRoot (Get-Location).Path `
  -Action Rebuild `
  -DisableWholeProgramOptimization
```

该兼容开关只在本次构建使用的临时 props 中关闭 WPO/LTCG，不改动工程文件。成功必须同时满足 `BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`，且 `Ksword5.1\x64\Release\Ksword5.1.exe` 非零；随后不要为了“复查”立刻再跑普通 Build（WPO 禁用会使常规增量缓存失效），需要时只用 `-VerifyArtifactOnly`。只有该恢复路径也复现失败后，才考虑安装 VS servicing update 或并列 v143 工具集。

#### 驱动 WDK x64 `ApiValidator` 后置校验

驱动仍由标准 MSVC/WDK 构建。若 `KswordARK.sys` 已在链接阶段更新、但 WDK 后置阶段因错误选择 ARM64 `ApiValidator`/`aitstatic` 或无子进程的静默卡住，不得把被中止的 `/t:Build` 说成整体成功：先确认实际报错发生在链接之后，记录精确 MSBuild PID/命令行，并确认没有活跃的 `cl.exe`、`link.exe` 或验证器子进程，才可以停止该**唯一**卡住的 MSBuild。

随后以 x64 验证器单独校验刚链接的 `.sys`：

```powershell
$solutionDir=(Resolve-Path 'Ksword5.1').Path + '\'
$apiValidatorX64='C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64'
& $msbuild 'KswordARKDriver\KswordARKDriver.vcxproj' /t:ApiValidator `
  /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=$solutionDir `
  /p:ApiValidator_ApiExtractorExePath=$apiValidatorX64 /m:1 /v:minimal
```

`Driver is 'Universal'.` 是该独立验证的通过标志。它只证明已链接驱动的 API/体系结构合规，不替代完整 Build、INF/CAT、签名或实际加载验证；这些状态必须单独报告。`10.0.26100.0` 应替换为本机已安装的 WDK 版本。若链接前已经失败，修复原始编译/链接错误，而不是使用此后置校验路径。

驱动项目依赖 WDK。如果当前机器无法构建驱动，不要阻塞发行包制作；沿用统一 Release 目录中的已有未签名 R0 产物：`Ksword5.1\x64\Release\KswordARK.sys`、`Ksword5.1\x64\Release\KswordARK.pdb`、`Ksword5.1\x64\Release\KswordARKDriver.inf`。

### 2. 搭建发行目录

推荐从参考包提取完整 Qt 依赖与插件目录，再覆盖最新构建产物。这样能保持 `platforms`、`styles`、`imageformats`、`iconengines`、`generic`、`networkinformation`、`tls`、`translations`、`qtadvanceddocking.dll` 等布局一致。

```powershell
$ref='C:\Users\Felix\Downloads\KswordARK评估版本-260427-未签名R0-进程内存监控增强.7z'
$stageRoot=Join-Path (Get-Location) 'dist\KswordARK-release-work'
$stage=Join-Path $stageRoot 'Release'

if (Test-Path $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }
New-Item -ItemType Directory -Path $stageRoot | Out-Null
tar -xf $ref -C $stageRoot

Copy-Item 'Ksword5.1\x64\Release\Ksword5.1.exe' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\Launcher.exe' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\KswordARKLight.exe' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\Taskbar.exe' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\KswordHUD.exe' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\APIMonitor_x64.dll' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\APIMonitor_x64.pdb' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\KswordARK.sys' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\KswordARK.pdb' $stage -Force
Copy-Item 'Ksword5.1\x64\Release\KswordARKDriver.inf' $stage -Force
Copy-Item 'LICENSE' (Join-Path $stage 'LICENSE') -Force
Copy-Item 'COMMUNITY_COVENANT.md' (Join-Path $stage 'COMMUNITY_COVENANT.md') -Force

$licenseDir=Join-Path $stage 'licenses\third_party'
New-Item -ItemType Directory -Path $licenseDir -Force | Out-Null
Copy-Item 'third_party\systeminformer_dyn\LICENSE.txt' (Join-Path $licenseDir 'systeminformer-LICENSE.txt') -Force
Copy-Item 'third_party\systeminformer_dyn\NOTICE.md' (Join-Path $licenseDir 'systeminformer-NOTICE.md') -Force
Copy-Item 'third_party\easy_hwid_spoofer\LICENSE.txt' (Join-Path $licenseDir 'easy-hwid-spoofer-LICENSE.txt') -Force
Copy-Item 'third_party\easy_hwid_spoofer\NOTICE.md' (Join-Path $licenseDir 'easy-hwid-spoofer-NOTICE.md') -Force
Copy-Item 'third_party\fltk\LICENSE.txt' (Join-Path $licenseDir 'fltk-LICENSE.txt') -Force
Copy-Item 'third_party\qt_advanced_docking_system\LICENSE.txt' (Join-Path $licenseDir 'qt-advanced-docking-system-LICENSE.txt') -Force
Copy-Item 'third_party\zstd\LICENSE.txt' (Join-Path $licenseDir 'zstd-LICENSE.txt') -Force

$profileDir=Join-Path $stage 'profiles'
if (!(Test-Path $profileDir)) { New-Item -ItemType Directory -Path $profileDir | Out-Null }
Copy-Item 'Ksword5.1\x64\Release\profiles\ark_dyndata_pack_v4.json.qz' $profileDir -Force
Copy-Item 'Ksword5.1\x64\Release\profiles\launcher_support_manifest.json' $profileDir -Force
Copy-Item 'Ksword5.1\x64\Release\profiles\registry_optimization_items.json' $profileDir -Force
Copy-Item 'Ksword5.1\x64\Release\profiles\registry_optimization_assets' $profileDir -Recurse -Force

$languageDir=Join-Path $stage 'languages'
if (Test-Path $languageDir) { Remove-Item -LiteralPath $languageDir -Recurse -Force }
Copy-Item 'Ksword5.1\x64\Release\languages' $stage -Recurse -Force

$driverDir=Join-Path $stage 'KswordARKDriver'
if (!(Test-Path $driverDir)) { New-Item -ItemType Directory -Path $driverDir | Out-Null }
Copy-Item 'Ksword5.1\x64\Release\KswordARK.sys' $driverDir -Force
Copy-Item 'Ksword5.1\x64\Release\KswordARKDriver.inf' $driverDir -Force
```

### 3. 生成 7z 包

本机可能没有 `7z.exe` 在 PATH 中；已验证可用工具路径：`C:\Users\Felix\CLionProjects\Wisdom-Weasel\7z.exe`。压缩包建议放在 `dist\` 下，文件名带日期和本次功能描述。

```powershell
$seven='C:\Users\Felix\CLionProjects\Wisdom-Weasel\7z.exe'
$date=Get-Date -Format 'yyMMdd'
$archive=Join-Path (Get-Location) ("dist\KswordARK评估版本-$date-未签名R0-功能描述.7z")

if (Test-Path $archive) { Remove-Item -LiteralPath $archive -Force }
Push-Location 'dist\KswordARK-release-work'
& $seven a -t7z -mx=9 -mmt=on $archive 'Release'
$exit=$LASTEXITCODE
Pop-Location
if ($exit -ne 0) { exit $exit }
```

### 4. 校验发行包

生成后必须测试压缩包完整性，并列出关键文件确认最新 exe/dll/sys 已进入 `Release\`。

```powershell
$seven='C:\Users\Felix\CLionProjects\Wisdom-Weasel\7z.exe'
& $seven t $archive
& $seven l $archive 'Release\Launcher.exe' 'Release\Ksword5.1.exe' 'Release\KswordARKLight.exe' 'Release\Taskbar.exe' 'Release\KswordHUD.exe' 'Release\APIMonitor_x64.dll' 'Release\KswordARK.sys' 'Release\KswordARKDriver\KswordARK.sys' 'Release\LICENSE' 'Release\COMMUNITY_COVENANT.md' 'Release\licenses\third_party\systeminformer-LICENSE.txt' 'Release\licenses\third_party\easy-hwid-spoofer-LICENSE.txt' 'Release\licenses\third_party\fltk-LICENSE.txt' 'Release\licenses\third_party\qt-advanced-docking-system-LICENSE.txt' 'Release\licenses\third_party\zstd-LICENSE.txt' 'Release\profiles\launcher_support_manifest.json' 'Release\profiles\ark_dyndata_pack_v4.json.qz' 'Release\profiles\registry_optimization_items.json.qz' 'Release\profiles\registry_optimization_assets\Config\Data.zip' 'Release\languages\zh-CN.json' 'Release\languages\en-US.json' 'Release\platforms\qwindows.dll'
```

校验通过时，`7z t` 输出应包含 `Everything is Ok`；主程序顶部“许可证”页面从 exe 同目录读取根 `LICENSE`。本流程生成的包根目录必须是 `Release\`，不要把 `dist\KswordARK-release-work\` 或其它临时目录打进包里。

## Launcher 用户报告接入

收到解压后的 Launcher 报告目录时，先只读校验，确认 `valid=true` 后再写入语料库：

```powershell
py -3.12 tools\pdb_offset_generator\launcher_report_intake.py $reportDir
py -3.12 tools\pdb_offset_generator\launcher_report_intake.py $reportDir --corpus-root $corpusRoot --commit
```

工具会校验 SHA256 和 PE/RSDS 身份、下载精确 PDB，并生成 NTOS/NTKRLA57 偏移配置；collection-only 模块只保存 PE/PDB。Wine、非 amd64、无 RSDS 或校验和不匹配的报告不得进入正式矩阵。

导入后运行 `ksword_profile_release_sync.py` 重新生成唯一发布矩阵 `ark_dyndata_pack_v4.json`，再运行 `Launcher/tools/generate_support_manifest.py` 更新支持清单。最后确认新 PDB GUID/Age 在清单中唯一且 `complete=true`，并构建 Launcher Release。重复导入应显示 `existing`。


## Phase -1 协作规范

- 仓库相对根目录为 `H:/Project/Ksword5.1`；文档与规则使用相对路径，不写个人机器路径作为开发落点。
- R0/R3 协议只在 `shared/driver/` 定义。
- 驱动 IOCTL 分发只通过 `KswordARKDriver/src/dispatch/ioctl_registry.c` 注册 handler，`ioctl_dispatch.c` 不再承载业务 switch。
- 用户态 KswordARK 设备访问只通过 `Ksword5.1/Ksword5.1/ArkDriverClient/`，Dock UI 不直接调用 KswordARK `DeviceIoControl`。
- `KswordCLI` 每新增、删除或调整一个命令/别名/参数时，必须同步更新 `KswordCLI` 内置 `help` 命令元数据，并同步更新 `docs/CLI使用文档.md`。
- 新增源码必须同步更新对应 `.vcxproj` 和 `.vcxproj.filters`。
- 语言包（`languages/*.json`）只能定点编辑；禁止用脚本 `json.load`/`json.dump` 整体重写，那会重排键序与缩进并产生数万行无意义 diff。
- 第三方代码接入必须保留原有许可证文本。
- 新增、删除或修改主程序用户可见文本时，必须同步 `Ksword5.1/Ksword5.1/languages/zh-CN.json` 与 `Ksword5.1/Ksword5.1/languages/en-US.json`，并通过 `python tools/i18n_language_pack.py audit --source-root Ksword5.1/Ksword5.1 --zh-pack Ksword5.1/Ksword5.1/languages/zh-CN.json --en-pack Ksword5.1/Ksword5.1/languages/en-US.json`。
