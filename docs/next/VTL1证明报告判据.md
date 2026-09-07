# VTL1 签名的运行时驱动报告：标定与判据

工具：`tools/attest_probe/attest_probe.c`（用户态、只读、`/MT`）。
本机实测日期 2026-09-06，环境：Windows 11 26300，**VBS status=2（运行中）、
HVCI 运行中、testsigning Off**。

这条路的价值前提与 HVM 相反：**HVM 要求 VBS 关闭，本条要求 VBS 开启。**
两者覆盖的是互补的机群，不是替代关系。

## 一、API 本身的四个坑（都已实测撞过）

| # | 坑 | 表现 | 正确做法 |
|---|---|---|---|
| 1 | 导出在 `kernelbase.dll` | 链 `kernel32.lib` 找不到符号（官方文档 req.dll/req.lib 两行都写 Kernel32，是错的） | `GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), ...)` |
| 2 | 尺寸查询"失败即成功" | 返回 `FALSE` + `GetLastError()==ERROR_INSUFFICIENT_BUFFER(122)` | 按 122 判成功；按"FALSE 即失败"写会在第一步判死整条路 |
| 3 | 包头 sizeof ≠ 字段和 | `RUNTIME_REPORT_PACKAGE_HEADER` 因 UINT64 对齐实际 40 字节，手算字段和是 36 | 一律 `sizeof`/`FIELD_OFFSET`，不手算布局 |
| 4 | `InternalName` 是 `CHAR` | 按 `WCHAR` 读出来是乱码 | 定长 `CHAR` 数组且**不保证 NUL 结尾** |

## 二、本机报告的形态

```
包大小 21281 字节   摘要 SHA512(0x800E)   签名方案 1 (SHA512-RSA-PSS-SHA512, 256 字节)
驱动条数 193
ReportOverflowed=0   PartialReport=0   IncludeBootDrivers=0
已卸载 11 条   启动期 0 条   可热补丁 0 条   带 OEM 名 43 条
每条摘要算法：SHA1 80 条 / SHA256 113 条（**混用，不是全局一种**）
```

`IncludeBootDrivers=0` 是整个判据设计的支配性事实，见第四节。

## 三、两条硬标定

### 3.1 `ImageHash` 是 Authenticode PE image hash，不是文件 flat hash

对 `C:\Windows\System32\drivers\afd.sys`：

```
报告 ImageHash (SHA256) : DECE1DEFD8E7285CEF2892A12B6665FD70F7B39EB8A00443E4DAF96EF721C070
AppLocker 给的哈希      : DECE1DEFD8E7285CEF2892A12B6665FD70F7B39EB8A00443E4DAF96EF721C070   ← 逐字节相同
文件 flat SHA256        : A5395994409E7F688722C1B610B9D3832911F527D6E8A6CCB1EC57CC9BACB209   ← 完全不同
```

即安全内核记的就是 **CI 用来做签名验证的那个哈希**。VTL0 侧要复现它，用
`CryptCATAdminAcquireContext2(..., L"SHA256"/L"SHA1", ...)` +
`CryptCATAdminCalcHashFromFileHandle2`（`wintrust.lib`），**不能**用 `Get-FileHash`
那种 flat hash。

**摘要的有效长度由每条自己的 `ImageHashAlgorithm` 决定，不是
`DRIVER_REPORT_DIGEST_MAX_SIZE`。** 按最大长度打印会把紧跟其后的
`PublisherThumbprint`（SHA1，20 字节）一起打出来，看上去像一个 64 字节摘要，
其实是两个字段 —— 本工具第一版就是这么错的。

### 3.2 `InternalName` 不能当匹配键

它取自 PE 版本资源，是厂商填的自由文本。本机实证的四种形态：

* **可为空** —— 4 条完全空白，1 条只有 `.sys`；
* **可带版本号** —— `rtkvhd64.sys 9430`；
* **可是逗号分隔的多值** —— `nvlddmkm.sys, nv_lddm:10011, nv`；
* **可是产品名而非文件名** —— `intel(r) wireless bluetooth(r)`；
* **会在 32 字节处截断** —— `microsoft.bluetooth.legacy.leen` 实为
  `microsoft.bluetooth.legacy.leenumerator`；
* **与文件名不同** —— `browser.sys` 对应磁盘上的 `bowser.sys`（微软自己的历史拼写差），
  `nvvad.sys`→`nvvad64v.sys`，`klark`→`klupd_k4w-21-26_klark.sys`。

数据：按名字比对，193 条里 27 条"只在报告里"；换成哈希，其中 **20 条当即对上**。
**判据必须只用哈希，不用名字。**

## 四、VTL0 参照面的选择

`EnumDeviceDrivers` 的**条数**是对的（265），但配套的 `GetDeviceDriverBaseName`
在本机把 265 个名字**全部**返回成 `ntoskrnl.exe`。拿它当参照面，差集里会凭空
多出两百多条假阳性。

参照面用 `NtQuerySystemInformation(SystemModuleInformation=11)`，它直接带
`FullPathName`，不需要二次查询。NT 路径要转 Win32（`\SystemRoot\` → 系统目录、
`\??\` → 去前缀）才能 `CreateFile` 算哈希。

## 四点五、TCG Log（WBCL）：把启动期那一批补回来

`IncludeBootDrivers=0` 缺掉的那批驱动，在引导期被度量进 TPM，日志由 Windows 落在
**`%WINDIR%\Logs\MeasuredBoot\<引导计数>-<恢复计数>.log`**。

三条实测结论，都与常见说法不同，值得单独记：

* **普通用户可读，不需要提权**，也**不需要 TBS API**（`Tbsi_Get_TCG_Log`）。
* **不需要机器上真有可用 TPM**：本机 `Get-Tpm` 三个字段全空，日志照样在、照样完整。
* 选文件要按**文件名里的引导计数**取最大，不是按时间戳；并且必须核对它属不属于
  本次开机（拿 `GetTickCount64` 反推开机时刻与文件写入时间比），否则一份上次开机的
  日志会让本次真正新增的启动驱动全部落进告警。

### 结构（本机 Windows 11 26300，日志 95043 字节）

```
首条              legacy TCG_PCClientPCREvent（PCR/类型/SHA1 20 字节/长度/数据）
                  数据是 Spec ID Event03 —— digestSizes 表在这里，摘要长度必须从它读
其后 44 条        TCG_PCR_EVENT2（crypto-agile）
本机摘要表        只有 SHA256(0x000B, 32 字节)  ← 换机器可能 SHA1+SHA256 并存，别写死
EV_EVENT_TAG(6)   10 条，其中 9 条是 SIPAEVENT_TRUSTBOUNDARY (0x40010001) 容器
容器内            212 个 SIPAEVENT_LOADEDMODULE_AGGREGATION (0x40010003)
                    PCR12 106 个：只有摘要与大小
                    PCR13 106 个：带路径、证书、内部名
```

SIPA 事件本身是 `{UINT32 EventID, UINT32 EventSize, BYTE Data[]}`；
`EventID & 0x40000000` 表示这是聚合事件，它的 Data 又是一串 SIPA 事件，要递归。

模块容器里的字段（本机全部出现）：

| ID | 内容 |
|---|---|
| `0x00070001` | 路径，UTF-16，NT 相对（`\WINDOWS\System32\drivers\x.sys`） |
| `0x00070002` | 镜像大小，UINT64 |
| `0x00070003` | 摘要算法，UINT32 CALG（本机恒 `0x800C` = SHA256） |
| `0x00070004` | **镜像摘要** |
| `0x00070005` | 颁发者 CN（`Microsoft Windows Production PCA 2011`） |
| `0x00070006` | 证书序列号 |
| `0x00070008` | 主体（`Microsoft Windows`） |
| `0x00070009` | **证书 SHA1 指纹，20 字节** |
| `0x0007000A` | 标志，1 字节 |
| `0x0007000D` | InternalName，UTF-16 |
| `0x0007000E` | 版本，UINT64 打包四个 UINT16 |

**PCR12 与 PCR13 度量同一批模块，必须按摘要归并**，并让带路径的那份覆盖简版，
否则清单一半条目没有名字。本机归并后 104 条（106 里有两对镜像摘要相同）。

### 两条把三份清单焊在一起的标定

1. **`0x00070004` 就是 Authenticode PE image hash。** 106 个模块里的 74 个 `.sys`
   与磁盘文件的 Authenticode 哈希 **74/74 逐字节一致，零例外**。
2. **`0x00070009` 与 VTL1 运行时报告的 `PublisherThumbprint` 是同一套。**
   `winload.efi` 的指纹 `1C9F651F18DF1C9C653FB960992A5C1A40C3E896` 与
   `afd.sys` 在运行时报告里的指纹逐字节相同。

于是 **VTL1 运行时报告 / TCG 启动清单 / 我们自己对磁盘算的哈希，三者同一键空间**，
可以直接并成一份"已知合法镜像"集合。这正是反向差集此前缺的那块。

## 五、判据（`--verdict`，默认关闭）

**【正向】** 报告里 `Unloaded==0` 的条目，其 Authenticode 摘要在 VTL0
当前全部已加载模块的磁盘文件里找不到。两种成因都算命中，工具不替人区分：
模块对 VTL0 隐身（DKOM 摘链等），或磁盘上的文件已不是当初加载的那一份。

**【反向】** VTL0 此刻加载着的模块，其 Authenticode 摘要在 VTL1 运行时报告
与 TCG 启动度量清单里**都**找不到。

反向方向有**健康门**：启动清单取不到、过期、解析越界、或超容量丢过条目，
任何一条成立就整个方向不判，并明说"**不等于该方向干净**"。

本机数据（这个方向能开的依据）：名字与哈希两维都对不上的 VTL0 模块 79 条，
启动清单补上 **76** 条，剩下 3 条正是磁盘哈希算不出的 `dump_*` 副本，
**三处都找不到的 = 0 条**。

**刻意不做的事**：**名字对上不救**。隐藏驱动完全可以把 `InternalName` 写成某个
合法驱动的名字，所以命中判断里没有名字这一维。

**已知降级**：VTL0 侧有 3 个模块算不出磁盘哈希 —— crashdump 栈的
`dump_dumpstorport.sys` / `dump_stornvme.sys` / `dump_dumpfve.sys`，
它们是内存里的副本，磁盘上没有对应文件。这三个无法参与匹配，对应的报告条目
可能被误报。本机它们都带 `Unloaded` 所以不触发，但换台机器不一定。
**这条降级必须随告警一起显示。**

## 六、本机结果与它的证明力

```
attest_probe --verdict                      → 命中 0 条，退出码 0
attest_probe --verdict --selftest-hide=afd.sys → 命中 1 条（afd.sys，哈希正确），退出码 20
```

"零命中"本身没有证明力 —— 一个永远不命中的判据也是零命中。所以配了
`--selftest-hide=<基名>` 做**变异测试**：它把指定模块从 **VTL0 参照面**里抹掉，
模拟"该模块对 VTL0 隐身"。**注入点在数据侧，判据代码一行不动**，否则测的是
测试桩不是判据。文本输出里会大字标注处于变异模式，防止有人拿自测输出当真实结果。

退出码：`0` 正常 / `20` 判据有命中 / `21` 判据没跑成（VTL0 参照面取不到）。
**21 不等于干净**，与 `2..9` 的错误码刻意不重叠。

## 七、未做的部分

* **TCG Log 解析**，用于补齐 `IncludeBootDrivers=0` 缺掉的启动期驱动。
  补上之后反向差集才谈得上可用。
* **多机基线**。以上全部结论只有一台机器的数据（Windows 11 26300，
  Kaspersky + NVIDIA + Intel + ASUS 的驱动栈）。`noFileHash=3` 这类数字换机器会变。
* **没有接进 GUI**。当前只是命令行工具，接入与否是产品决定。
