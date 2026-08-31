# 蓝屏 BGP 准备与 BPP 哨兵

## 已确认行为

- Windows 10 19042 的 BGP 私有 `GetBpp` 在驱动加载期尚未调用 `InbvAcquireDisplayOwnership` 时可能返回 `1`，同时分辨率返回 `0×0`。这是未取得显示所有权的延迟探测状态，不能直接判定为不支持。
- 加载期仍需在 `PASSIVE_LEVEL` 完成全部资源准备。当前实现同时生成并解析 24 BPP、32 BPP 的 Logo 与黑色/蓝色 ASCII 字形矩形。
- 崩溃回调中的顺序保持为 `InbvAcquireDisplayOwnership → BgpFwAcquireLock → 重新读取分辨率/BPP → BgpClearScreen → BgpGxDrawRectangle → BgpFwReleaseLock`。
- 取得显示所有权后只接受实际 BPP 为 24 或 32。分辨率、BPP、私有特征或节属性不满足时，在清屏前释放锁并退出，保留 Windows 原蓝屏。
- VMware 的 Windows 10 19042 蓝屏显示模式可能固定回落到 `640×480×32`，即使桌面分辨率更高。面板必须保留 `640×480` 紧凑布局；`1024×768` 只能作为完整布局阈值，不能作为 BGP 可用性的最低门槛。
- `640×480`/`800×600` 紧凑页使用左上角 `240×84` Logo 和双栏正文。正文中间需为 Windows 转储进度文字保留空白横带；内部 BGP 阶段、锁状态和回调位图保存在 SecondaryDumpData，不占用户可见页面。

## 诊断依据

- `C:\Windows\Temp\KswordARK-bgp-preparation.log` 用于判断加载期是否成功 Arm。
- 修复前典型状态为 `state=1 (query-only)`、`preparation_stage=2 (read-screen)`、`0xC00000BB`，即回调已注册但绘制不会启动。
- 修复后应看到 `state=3 (armed)`、`preparation_stage=8 (complete)`、`feature_mask=0x000001FF`。加载期完全隐藏模式时，`screen=0x0x1` 与 `last_probe=0x0x1` 属于预期状态。
- 日志中没有 `last_probe=` 时，目标机仍在使用旧驱动。
- 崩溃阶段数据继续通过 GUID `956d0947-326a-4ba7-92f1-4c8b5a5c712d` 写入 `KbCallbackSecondaryDumpData`。
- 阶段序列结束于 `ScreenAfter` 后的 `Rejected|2`，且快照显示真实屏幕 `640×480×32`、要求 `1024×768`、`ClearStatus=STATUS_PENDING` 时，说明回调与 BGP 获取链路均已执行，未清屏仅由尺寸门槛触发。

## 图像资源

- #174 起 Logo 统一采用 qrc 中的 `KswordHome-En.png`（KSwordDEV 版本），不要改回带 KSwordDEV Team 字样的 `MainLogo.png`；BGP 使用离线缩放为 `240x84` 的 `Generated/MainLogoBitmap.h`，SVGA 由主程序上传同一资源。
- 运行时不读取外部 BMP 文件。BMP 头、像素缓冲和 BGP 矩形均在驱动加载期动态建立。
- 当前目标机的 BGP 32 BPP 矩形路径不按 alpha 混合字形背景；`BGRA=00 00 00 00` 会显示成黑色字符块。字形背景必须与当前实色画布完全一致并保持不透明；#174 深色布局使用 `RGB(5,15,33)`。
- 诊断正文恢复使用驱动内置 `8x12` ASCII 字模，不依赖外部字体文件或新增许可证。BGP 在 `PASSIVE_LEVEL` 把字形解析成矩形，VMware SVGA 使用相同字模；崩溃回调不得调用 GDI、DirectWrite 或读取字体文件。
- 右上角幽默判词是独立资源：主程序用当前 Windows 普通 UI 字体预渲染中英文、四种归因类型共 8 张 BGRA 位图，通过版本化 verdict IOCTL 原子上传并固定在非分页内存。该卡片保留白色和系统 UI 字体，不跟随正文的 `8x12` 技术字模。

## 截图基线布局与解析器

- 当前视觉基线沿用提交 `b9f3058e` 的四区几何：深海军蓝底、浅色正文、弱化标签和一像素边框；完整页固定为 `1024x768` 画布，在 `1280x768` 等更宽模式中水平居中；小于该阈值时走 `640x480` 双栏紧凑版，`1280x720` 详细版不再被选择。页眉只建立三层信息：弱化产品名、蓝色 Stop Code 名称、唯一红色信号的数值错误码；右上角保留白色 Windows UI 字体幽默判词。
- 完整页只保留四个框：`CRASH SUMMARY`、`PRIMARY EVIDENCE`、`TECHNICAL EVIDENCE`、`NEXT ACTION`。不要重新引入 `DUMP INFO/STATUS`、渲染器自检、空栈/反汇编/Blackbox/事件面板，也不要为填满空间显示无助于定位的内部状态。解析失败只用 `NO SAFE LIVE ATTRIBUTION` 加转储分析提示占两行，不重复显示 `NOT IDENTIFIED`、`NOT AVAILABLE`、`DUMP REQUIRED` 等失败占位符。
- BGP 的字形、Logo、判词位图与每种固定尺寸的边框矩形都在 `PASSIVE_LEVEL` 解析并保留 backing buffer；崩溃回调只读取固定非分页快照、清屏、绘制预生成矩形并格式化到栈上固定缓冲，不分配内存。
- 驱动在正常运行期通过已有进程创建/退出和系统镜像加载回调维护固定大小的进程、模块缓存；初始化时再用 `PsGetNextProcess` 与 `AuxKlibQueryModuleInformation` 建立基线。写入端使用自旋锁，条目使用奇偶序列号发布；蓝屏路径只做有界无锁快照，不解引用 BugCheck 参数中的任意对象。
- `0xEF CRITICAL_PROCESS_DIED` 的参数 1 是进程对象，参数 2 只区分进程/线程，参数 3/4 保留。若参数 1 命中崩溃前缓存，页面显示关键进程短名、PID、对象与类型；这只标识终止的关键进程，不声称已经找到终止它的代码，最终根因仍需转储。
- 对其他 Stop Code，可显示缓存到的当前崩溃上下文进程，但必须明确标成 `CRASH CONTEXT`，不能把它当成问题进程或模块。候选驱动只允许由微软文档明确指定的代码/例程地址命中模块缓存。
- `bugcheck_decode.c` 负责两类纯解析：为四个原始参数提供 Stop Code/子类型相关语义；对白名单中的直接代码地址给出参数号和置信度。基础白名单包括 `0x0A/0xD1` 参数 4、`0x1E/0x3B/0x7E` 参数 2、`0x50` 参数 3、`0xC5` 参数 4、`0xD5` 参数 3、`0x116/0x117` 参数 2，以及 C4/C9 中文档明确标为驱动代码、回调、ISR、完成或分发例程的子类型。对象指针、IRP、设备对象、保留字段与 C4/C9 未识别子类型绝不参与模块归因。
- `0x9F` 必须按参数 1 的子类型分别标注设备对象、PDO、triage、阻塞 IRP、PnP 锁线程等含义；`0xEA` 标注卡住线程、watchdog、驱动名指针和命中次数。仅标注语义不代表可以在崩溃回调中安全解引用这些值。
- 技术参数只显示有文档语义或值非零的字段：保留字段始终隐藏，未知通用参数为零时隐藏，`PROCESS`、`READ`、`IRQL 0` 等有含义的零值仍需显示。动态文字必须在固定宽度内完整显示，不得因重复模块名或长内部说明出现省略号。完整页和紧凑页都优先显示已解析模块；`0xEF` 次优先显示关键进程；无归因时只补一个最有价值的参数。纯解码和画布边界由 `tools/bugcheck_layout_replay/run.ps1` 回放验证。
- Release x64 驱动链接后，工程必须把最新 `KswordARK.sys/.pdb/.inf` 同步到 `Ksword5.1/x64/Release/KswordARKDriver/`；变体签名完成后再同步最终 `.sys`，避免测试包继续携带旧驱动。
- 替换磁盘上的 `.sys` 不会更新已经加载的内核映像。实体机或虚拟机复测蓝屏重绘前，必须停止/卸载旧服务并重新加载驱动；无法安全卸载时重启系统，再核对目标 `.sys` 的哈希或加载日志。
