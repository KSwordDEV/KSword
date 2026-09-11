# DWM Order Tool

从 KSword 提取的原生 Win32 独立窗口排序工具，可长期独立使用，也可分发给测试者收集系统兼容性。无需 KSword、Qt、驱动、Python 或单独安装 VC++ 运行库。运行文件只有 `DwmOrderTool.exe` 与同目录的 `KswordDwmZOrder.dll`；请一起分发，不要只复制 EXE。

## 使用

1. 解压到当前用户可写的普通目录，运行 `DwmOrderTool.exe`。首次只读取本机系统文件，不注入 DWM。
2. 实际排序需要管理员权限。点击“管理员重启 / Elevate”，或右键 EXE 以管理员运行。
3. 从下拉列表选择目标窗口，也可直接输入十进制或 `0x` 十六进制 HWND。“创建测试窗口”会生成相互重叠的 A / B，并选好目标和参照。
4. 选择合成最前、最后、参照上方或下方，点击“应用顺序”。“持续保持”默认关闭；勾选后接入 DWM 排序更新，一次仅保持一个窗口。
5. “连接读取”也会加载代理，但不主动调整顺序。“恢复目标”按 Windows 当前窗口顺序恢复目标；“停止全部”会停止本会话该代理的全部保持，包括从 KSword 发起的保持。
6. 关闭工具时，若本工具可能仍在保持窗口，可选择先恢复、保留保持后退出或取消。两个内置测试窗口随工具关闭。异常退出后可重新运行并使用“停止全部”。超时表示操作结果未知，先读取状态，不应反复应用。

改变的是 DWM 合成遮挡顺序，原始 Band、鼠标命中、焦点不变。两个普通测试窗口只能验证普通窗口排序；跨 UIAccess、系统界面、多显示器和动画场景需要额外观察。隐藏、最小化、独占呈现及安全桌面不因排序自动可见。

当前模型覆盖 Win11 24H2 x64 的已审查样本，以及 Win10 19041 组件系列 x64 的实验性样本。文件特征匹配通过不代表实际注入或视觉效果通过；在 DWM 中仍会重新完整校验。详细组件版本与验证边界见导出源码/发行包中的 `SUPPORT.md`（仓库内为 `../docs/DWM窗口序列注入.md`）。不支持的完整模型会拒绝修改。已加载过旧版代理时，需要注销并重新登录才能使用新版 DLL；不能在同一个 DWM 中热替换它。

## 提交兼容性结果

完成测试后，在“实际观察”中选择正常、异常或 DWM 重启，并填写简短现象，点击“导出兼容性报告”。保存对话框用于选择父目录，程序会在该位置创建独立的时间戳文件夹，不覆盖同名文件。将整个报告文件夹压缩后交给维护者。

报告为 UTF-8 `report.txt`，包括工具版本、EXE/DLL SHA256、OS 构建号、DWM 文件版本、SHA256、PDB GUID/Age、显示适配器名称、会话信息、文件模型解析结果，以及最近 200 次操作的参数和完整回执。状态与阶段的数字对应 `core/shared/window/DwmZOrderProtocol.h` 和客户端 `Stage` 枚举；`front_index_zero_based=0` 代表视觉最前。阶段 `0..6` 分别为窗口、代理文件、DWM 进程、副本准备、加载代理、发送请求、回执核对。

窗口标题和进程列表只用于本地选择，不进入报告；不采集用户名、机器名、内存、屏幕截图或令牌。填写的备注会原样进入报告。可选勾选附带本机 `uDWM.dll`，方便维护者针对精确版本生成新模型；默认不附带。程序不联网、不自动上传，也不会下载 PDB。文件诊断与实际操作报告应一起保留；系统更新后的磁盘 DLL 可能与尚未重启的 DWM 已加载版本不同。

建议依次检查：普通窗口置顶/置底、相对顺序、持续激活其它窗口时保持、目标/参照关闭、恢复、停止，以及跨 UIAccess 的实际画面。请分别观察遮挡与鼠标命中。文件校验和链表回读都不能替代实际视觉验收。

只采集文件诊断，无界面、无注入：

```powershell
.\DwmOrderTool.exe --diagnose 'C:\Reports'
```

诊断退出码：`0` 文件模型匹配；`2` 完整读取但模型不支持；`1` 诊断/报告失败；`64` 参数不合法。该命令不用管理员权限。输出目录内生成报告文件夹。

## 独立项目与构建

需要 Windows x64、Visual Studio 2022 / Build Tools 的 C++ 桌面工具、Windows SDK、CMake 3.24+。使用静态 CRT；全部项目（含代理、客户端、测试）由 CMake 生成 `.vcxproj` 与 `.vcxproj.filters`，无需 Qt/WDK。可以在 Visual Studio 中直接打开本目录，或运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\Build.ps1
```

生成 `build/bin/Release/DwmOrderTool.exe` 和 `KswordDwmZOrder.dll`。默认构建并运行复用核心的排序、正式加载、路径部署、CFG、协议回归，以及独立程序的报告导出测试。测试子进程不会注入实际 DWM。`--self-test <目录>` 是维护者使用的本机只读诊断/报告测试，会在指定目录写入测试报告和一份系统 DLL。

可在交互式桌面上运行 `Test-Ui.ps1 -Executable <EXE路径> -ScreenshotPath <PNG路径>` 检查选择器、测试窗口、报告入口及界面截图。它只操作自己启动的工具和测试窗口，不触发 DWM 注入；这些检查不等于实际排序验收。

在 KSword 仓库里，此 CMake 项目直接使用现有核心源码。要作为单独项目移交，先导出完整源码：

```powershell
powershell -ExecutionPolicy Bypass -File .\Export-Source.ps1 -Destination '..\dist\DwmOrderStandalone-source'
```

导出项目的 `core/` 包含按原目录关系保留的核心源码、测试和离线特征生成工具，不再访问父目录或 KSword 仓库。`source-manifest.json` 记录导出时每个源文件 SHA256，可单独建立 Git 仓库继续开发。`core/Ksword5.1/...` 只保留少量纯 Win32 客户端文件，是源文件路径兼容布局，不包含或依赖 KSword 主程序。无需预先下载系统样本或 PDB 即可构建；维护特征模型时才使用 Python 的 pefile / capstone 以及精确离线 PE/PDB 样本。

在导出源码项目中完成 Release 构建后生成两个 ZIP：

```powershell
powershell -ExecutionPolicy Bypass -File .\Build.ps1
powershell -ExecutionPolicy Bypass -File .\Package.ps1 -Destination '..\DwmOrder-release'
```

一个 ZIP 用于直接运行，一个包含完整对应源码。运行包不包含测试 fixture、PDB、系统 DLL、构建缓存或 Python 依赖。源码包不包含 `build/`。打包会核对导出源码清单；修改后应先重新导出生成新清单，再构建打包。请将两个 ZIP 一起保留并按原许可证提供对应源码。

## 来源与许可证

本项目提取自 [KSwordDEV/KSword](https://github.com/KSwordDEV/KSword)，新增独立 Win32 操作界面、文件诊断、报告和源码打包流程。代理、加载器、窗口身份检查及特征模型复用 KSword 核心实现。保留 KSword Community Source License 1.6；完整许可证随导出源码与运行包提供。未另行授权为 MIT/Apache 等许可证。
