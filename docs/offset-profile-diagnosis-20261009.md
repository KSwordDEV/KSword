# KSword 偏移档案未生效排查

2026 年 10 月 9 日，先将 main 快进到 `origin/main` 的 `c7c1886c0664352b9c8281595744529c587f7571`，保留已有语言包改动。当前本地档案存在明确的格式阻断：源码目录和 Release 的三个包都包含旧字段字典，当前 GUI 在匹配系统身份之前就拒绝加载。即使重新生成符合格式的包，现有条目也没有匹配本机磁盘内核的精确身份。

## 档案格式已落后于读取契约

`Ksword5.1/Ksword5.1/KernelDock/KernelDock.DynData.cpp:2310` 要求 `schemaVersion=1`、`packVersion=4`；`:2320` 还要求 `fieldDictionary` 为空、`profiles` 非空。三个现有包虽然声明 v4，但字典仍有 176 项，2070 个 profile 均保留旧 `fields` 和 `legacyItems`。因此会在进入 profile 匹配前返回，`:2322` 的提示“字段字典或 profile 列表为空”也没有正确描述非空旧字典的拒绝原因。

| 现有档案 | profiles | fieldDictionary | 当前 GUI 格式接受 | 本机磁盘 PE 身份命中 |
| --- | ---: | ---: | --- | ---: |
| `Ksword5.1/Ksword5.1/profiles/ark_dyndata_pack_v4.json` | 2070 | 176 | 否 | 0 |
| `Ksword5.1/Ksword5.1/profiles/ark_dyndata_pack_v4.json.qz` | 2070 | 176 | 否 | 0 |
| `Ksword5.1/x64/Release/profiles/ark_dyndata_pack_v4.json.qz` | 2070 | 176 | 否 | 0 |

三个包解压后的 JSON 原始字节 SHA256 完全相同：

`520b999938de144560d31546f2a30a41aee90abb56732c403918c8761a2aeab2`

`Ksword5.1/Ksword5.1/ksword/profile/ProfileJsonLoader.cpp:62` 优先选择 `.qz`。此次 JSON 与 qz 内容一致，未出现压缩包覆盖较新 JSON 的漂移。

当前 `tools/pdb_offset_generator/ksword_profile_release_sync.py:1569` 的生成契约只输出规范 v4 profiles，`:1579` 明确省略旧 offset mirrors，`:1589` 返回值没有 `fieldDictionary`。修复方向是重新生成规范 v4 档案并更新 qz，而不是放开读取端去接受旧镜像。

`.gitignore:46` 忽略源码 profiles 目录，`:6` 忽略 x64 产物目录，所以 Git 拉取只更新读取代码，不更新本地包。`Ksword5.1/Ksword5.1/Ksword5.1.vcxproj:1319` 的构建后动作在 `:1340` 仅压缩既有 JSON，不调用 release sync，也不补充新内核条目。普通 Build 可以继续发布同一个旧包。

## 本机磁盘内核没有精确档案

GUI 在 `KernelDock.DynData.cpp:2120` 按 `moduleClassId`、`machine`、`timeDateStamp`、`sizeOfImage` 精确匹配。三包按这个实际判据的命中数均为 0，按归一化 PDB GUID 和 Age 检查也为 0。

本机 `System32/ntoskrnl.exe` 原始 PE 身份为：

| 字段 | 值 |
| --- | --- |
| moduleClassId | 0，NTOSKRNL |
| machine | `0x8664` |
| timeDateStamp | `0x3ABC2041` |
| sizeOfImage | `0x01450000` |
| PDB | `ntkrnlmp.pdb` |
| PDB GUID | `9DAAB201-5E4C-ABF6-9800-9DBD0548B669` |
| PDB Age | 1 |
| 文件 SHA256 | `CB0603CD0BC46BFB2D94963E8A525C3C78BA90E3739E09DEEB3185FC71613C7B` |

PowerShell 和 Python 都是 64 位进程，两者读取的原始 PE 身份与 SHA256 相同。CIM 报告 OS build 为 26300，而磁盘文件 VersionInfo 的 FileVersion 字符串为 `10.0.26100.9022`；不能用其中一个版本字符串替代实际 PE 身份。上述结论针对磁盘文件，尚需驱动 `dyn status` 回执确认已加载内核的身份。

三包的 NTOS 最高版本标签为 `10.0.26200.5001`，没有 26300 条目。缺项时也不会自动在线补齐：`ArkRuntimeDynData.cpp:7` 将旧在线解析器放在 `#if 0` 中，实际 `:2620` 的实现返回空结果；GUI 当前链路未调用它。需要导入精确 PE/PDB 语料并重新发布，不能用相近 Windows build 的偏移代替。

## 启动重入可能丢失自动下发

此问题限定于 GUI 启动前 R0 服务已运行的路径。`MainWindow.cpp:5195` 先调用 `startR0RuntimeConsumersAfterServiceStart`，其 `:9177` 排入 `singleShot(0)` 刷新；`:5202` 才开始创建 Dock。

`MainWindow.cpp:10832` 的 `new KernelDock` 尚未返回时，KernelDock 构造函数 `KernelDock.cpp:274` 同步初始化首屏页，经 `:1463` 到 `:717` 的 `QApplication::processEvents(ExcludeUserInputEvents)`。排队的刷新因而可能提前执行。此时 `m_kernelWidget` 还未完成赋值，`m_dockKernel` 也未创建，回调在 `MainWindow.cpp:9189` 设置 `m_pendingR0DynDataRefresh=true` 后返回。

当前 KernelDock 立即构造，`:10958` 将 Dock 标为已初始化；待刷新标记唯一的消费点 `:10395` 位于 lazy 初始化尾部，正常立即构造的路径不会经过它。仅打开已初始化的内核 Dock 不能保证补跑。

其它入口可以独立补偿下发：`KernelDock.cpp:1344` 在首次实际显示 DynData 或 PDB Profile 页时自动刷新；`KernelDock.KernelHooks.cpp:2581` 在 Timer/DPC 查询前自动匹配并应用档案；手动刷新偏移页或运行中启动 R0 也能触发。它们不消费 MainWindow 的 pending 标记，因此启动问题的影响限定于尚未触发这些补偿入口的功能路径，不能把它说成所有情况下都不会下发。对于本次旧格式包，这些补偿入口仍会遇到前述格式拒绝。

使用 PySide6 的真实 QCoreApplication 事件循环做最小顺序回放，结果为：

```text
reenter=False pending=False refresh_count=1
reenter=True pending=True refresh_count=0
QT_REPLAY_CONFIRMED=PENDING_NOT_CONSUMED_AFTER_EAGER_INITIALIZATION
```

这是事件顺序和守卫条件的离线模型回放，不是完整生产 GUI 或驱动验收。修复方向是将自动应用安排到 Dock 初始化完成之后，并让立即构造与 lazy 路径都消费 pending；更彻底的做法是让 profile 应用服务独立于 KernelDock 的 UI 生命周期。

## 状态显示也可能误导

`KernelDock.DynData.cpp:2861` 将本次 `found/applied` 初始化为 false，`:2901` 在驱动已完整 active 时跳过重复扫描和应用，却没有回填状态。`:2785` 的摘要仍可显示“找到匹配：否 / 已应用：否”，同时顶部 `:3575` 根据驱动 flag 显示已启用。应区分“本次没有重复应用”和“驱动没有有效档案”。

GUI 匹配成功后实际存在 EX 与 V4 两条下发路径，分别在 `:2942` 和 `:2962`。驱动 `dyndata_v4.c:1561` 的 v4 状态独立于传统字段状态，单看 v4 accepted 不能确认 `NtosActive` 和传统 offsets 已激活；需要一并查看 `dyn status`、`dyn fields` 的来源和 v4 modules/items 回执。

## 复现与验证范围

在仓库根目录运行下面的只读命令即可再次检查格式与磁盘 PE 身份，不写档案、不下载符号、不访问驱动：

```powershell
@'
import json, os, struct, zlib
from pathlib import Path

# 读取磁盘内核原始 PE 身份，避免使用版本字符串推测偏移。
image = (Path(os.environ['SystemRoot']) / 'System32' / 'ntoskrnl.exe').read_bytes()
nt = struct.unpack_from('<I', image, 0x3c)[0]
identity = (
    0,
    struct.unpack_from('<H', image, nt + 4)[0],
    struct.unpack_from('<I', image, nt + 8)[0],
    struct.unpack_from('<I', image, nt + 80)[0],
)

# 在内存中解压 Qt qCompress 格式，并复用 GUI 的四个身份匹配字段。
paths = [
    'Ksword5.1/Ksword5.1/profiles/ark_dyndata_pack_v4.json',
    'Ksword5.1/Ksword5.1/profiles/ark_dyndata_pack_v4.json.qz',
    'Ksword5.1/x64/Release/profiles/ark_dyndata_pack_v4.json.qz',
]
for path in paths:
    raw = Path(path).read_bytes()
    pack = json.loads(zlib.decompress(raw[4:]) if path.endswith('.qz') else raw)
    dictionary = pack.get('fieldDictionary', [])
    profiles = pack.get('profiles', [])
    accepted = (
        pack.get('schemaVersion') == 1 and pack.get('packVersion') == 4
        and not dictionary and bool(profiles)
    )
    keys = ('moduleClassId', 'machine', 'timeDateStamp', 'sizeOfImage')
    def number(value):
        return int(value, 0) if isinstance(value, str) else value
    matches = [entry for entry in profiles if tuple(number(entry.get(key)) for key in keys) == identity]
    print(path, 'dictionary=', len(dictionary), 'accepted=', accepted, 'matches=', len(matches))
'@ | python -B -
```

已执行的三包输出都是 `dictionary=176 accepted=False matches=0`。现有 Release CLI 的只读 `dyn status` 返回 `CreateFileW(\\.\KswordARKLog) failed, win32=2`，当前不能取得驱动回执。此处不把当前设备不存在解释为用户此前现场的根因，也不宣称已验证正在使用的 GUI 二进制行为。

本次没有修改生产源码、生成或覆盖偏移档案、构建、加载或卸载驱动。后续修复需要依次完成规范档案重发、精确身份补齐、启动应用时序调整和状态显示修正；实际生效必须以目标运行环境的驱动回执验收。

## 后续逻辑修复

用户随后授权修改，并最终限定为仅做逻辑修复，不下载 PDB、不测试。上述排查和离线回放记录属于修改前证据；本节记录后续源码改动，不能作为修复后的运行通过证据。

- 主程序构建后调用压缩器的 `--normalize-dyndata-v4`。新辅助模块只读取已有 compact v4 items：先验证原始组计数、重复 ID 和数值格式，移除未被消费者使用的 `1004/1006`，按既有发布生成器的契约省略不完整特殊组，重新计算组计数并移除旧字段镜像。未知 item、非法值及错误计数阻断发布；身份和保留项的偏移值不改动，源 JSON 不被覆盖。此变更在以后构建时生效，本次不生成新档案或 qz。
- MainWindow 将启动消费者的调用移到 `initDockWidgets` 返回后，避开构造期 `processEvents` 重入；实际安排刷新时清除 pending 标记。
- 状态页从最终驱动回读的 PDB 标志和精确 NTOS 的 V4 accepted module 补齐已接受状态，不再将“本轮没有重复应用”展示成“驱动未应用”。定长 profile 名称按边界读取。

本轮没有下载或解析 PDB、补新内核身份、改变 R0 协议、生成发行档案或加载驱动。虚拟机曾因无法分配 8 GB 内存而启动失败；用户随后取消测试，未调整 VM 内存配置。只进行源码差异、Python 语法、工程 XML 和语言包静态核对，不运行测试或构建。当前实体机精确档案仍缺失，逻辑修复不会将其伪装为命中。

## CI 修复

随后用户要求修复 CI 再推送。`c7c1886c` 的 [CI run 37901296101](https://github.com/KSwordDEV/KSword/actions/runs/37901296101) 在 user-mode job 的插件安装回归夹具编译时失败：抽取的 `MarketplacePlugin` 新增了 `ks::plugin_host::UpstreamPlan` 成员，而 `tools/test_plugin_install_layout.py` 生成的入口没有包含类型声明。夹具已增加真实 `PluginHost.Distribution.h`，保留原有安装、校验与回滚回归步骤。

CI 使用空 profiles 占位供 Launcher 生成编译期清单，且此前已禁止将它发布到正式产物。两个主程序 CI 构建入口现显式传入 `KswordSkipDynDataProfilePack=true`，只跳过私有运行时档案的发布 Target；正常构建仍执行严格规范化。CI 占位 v4 JSON 补齐 `schemaVersion=1`，不添加虚假身份或偏移，也不下载 PDB。编译与回归的最终结果需要推送后对应 SHA 的 GitHub Actions 回执确认。
