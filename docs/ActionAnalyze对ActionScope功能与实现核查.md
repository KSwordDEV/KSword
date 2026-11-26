# ActionAnalyze 对 Action Scope 的功能与实现核查

日期：2026-11-24。状态：用户授权对官方分发包全面静态核实与采集，并行审查各功能族；不运行包内程序、不注入、不加载驱动、不更改系统或目标环境。本研究收集可借鉴机制，不代表KSword已经实现，也不自动扩大首版功能范围。

## 1. 资料、版本和证据口径

研究输入：

- [安天官方工具页](https://www.antiy.com/tools.html)与其[ActionScope分发包](https://www.antiy.com/tools/ActionScope.zip)。本次包为8,607,710字节，SHA256 `e25903af4d8b5612fb8adb8cad764e39bde33046ebf00fac45e215b9d9c9bc3a`。
- 外包有`install.exe`、`package.ready`、激活码文本和`versionInfo.ready`四个条目；版本文本为`version=20191230`。`package.ready`本身是ZIP，SHA256 `0e59bcfa11bedca0e52cda14d1457aa2413cb341ba637f5cb45d260eb40b2bc0`，包含38个非目录文件，其中19个PE；该计数不含外层安装器。下载日期、HTTP修改日期和PE编译时间均不当作当前产品版本。
- [安天《打造一个轻量级分析工具》演示](https://www.antiy.cn/download/Lecture/Lightweight_Analysis_Tool.pdf)，第10页列组件，第13页列HeapSpray／ROP／shellCode，第14页列远程分析／衍生进程与文件，第16页列PowerShell与WMI反虚拟机，第19／20页列网络服务与流量分析。已抽取并人工查看第14／19／20页图像，对照服务端口和流量查看格式；未把截图按钮视为运行验证。
- 包内`actionCN.md`、命令行说明、三套Hook配置、API参数配置、插件与宿主PE。激活码不抄入研究文档，不尝试激活或绕过许可。

| 证据标签 | 本文含义 | 不能据此宣称 |
| --- | --- | --- |
| 代码已核对 | 导入导出、调用点、反汇编／反编译与对应数据互相支持 | 未运行验证，不能承诺兼容性、性能、检测率或控制时机 |
| 配置已绑定 | 当前包配置有非注释入口／插件绑定 | 不证明Hook实际成功安装，也不自动推广到另一架构 |
| 文档明确 | 官方演示或包内文档明确描述 | 不证明该分发包带齐实现、服务端或SDK |
| 仅有线索 | 字符串、导出名、依赖名或未闭环的调用 | 不计作已实现功能，不用猜测补齐机制 |
| 尚未收集 | 本次输入中缺实现或未找到闭环证据 | 不断言产品没有此功能 |

工具已实际使用Python pefile、Capstone、pypdf和Ghidra 12.1.4 headless／DecompInterface。主会话对WMI和反沙箱两架构四个DLL完成Ghidra分析，检测分路对CheckHeap、网络分路对四个日志DLL也完成实际headless分析和相关函数伪码导出；主控分路对update及globalHook解压分析数据完成Ghidra静态导入／有限函数核对，外install只做资源等有限识别。SDK分路以配置、PE及正确入口反汇编核对。没有原始PDB，伪码局部类型／函数签名须回到汇编核对。IDA和REA本机目录存在，但不能因此说已通过它们完成分析；本会话未暴露可直接调用的逆向MCP，使用的是本地headless。

逐文件hash／架构／导出清单和分路研究文本位于`.codex-build-logs/behavior-planning/ActionScope-*-static-*.{json,md}`等诊断文件。第三方二进制、Ghidra项目及生成伪码留在本机批准的临时参考目录，不进入源码树或正式Release；仓库正文只保留机制、RVA和来源标识。

## 2. 分发包功能族与收集边界

| 文件族 | 收集对象与核对方向 |
| --- | --- |
| `daemon.exe`、`globalHook.exe` | 主控、界面、调度、日志归集、远程与派生对象、鉴定器入口 |
| `inject-x86.exe`／`inject-x64.exe` | 位数分工、加载与传播入口、命令与参数 |
| `inlineHookKingDll-x86.dll`／x64 | Hook安装、Before／After、原调用上下文、回调与生命周期 |
| `IHKSDK_plugin_Common-x86.dll`／x64 | 通用API记录、参数元数据、调用方定位、日志／派生进程路径 |
| `CheckHeap_plugin-x86.dll` | ROP／调用点、shellCode／HeapSpray线索、输出与载荷取证；本包没有同名x64 DLL |
| `ATInlineHook_WMI-x86.dll`／x64 | COM方法级查询与属性采集、安装条件、输出替换 |
| `oppose_sandbox-x86.dll`／x64 | 注册表与鼠标结果干预、激活差异及扰动 |
| `tcplog-x86.dll`／x64、`udplog-x86.dll`／`udpLog-x64.dll` | 行为日志传输、格式／队列与交付边界；目标网络字节另查API插件 |
| `config-IHK-x86.txt`、`config-IHK-x86-win10.txt`、`config-IHK-x64.txt` | 插件实际绑定、初始化、注释与架构差异 |
| `api_param-x86.txt`／x64、`log-*.txt`、`lsass.exe.cfg` | 参数定义与目标／日志配置，不能等同实时已捕获字段 |
| `log.mdb`、语言文本、包内说明 | 数据结构、功能目录、工具入口与使用约束 |
| `update.exe`、更新／市场清单 | 更新与插件扩展的入口证据，不访问更新后端或拉取未知插件 |
| `target/notepad.exe`、`target/wmi_query3.ps1` | 随包目标／演示素材，仅静态识别，不运行 |

38个文件均登记身份；“登记／分路审查”不等于每个函数完全还原。本次包未含独立SYS，也未收集到完整Python鉴定器SDK／规则全集，不能把演示宣称的内核引擎和Python SDK写成已还原。

### 2.1 已核对能力总览

| 功能 | 具体机制或入口 | 本包可确认层次 | 主要边界 |
| --- | --- | --- | --- |
| API行为与参数 | 双位数inline Hook＋Common＋参数目录 | 代码与配置 | 精确安装、真实字段有效性与现代系统兼容未测 |
| 线程调用现场 | SDK取原调用返回地址／参数槽／返回位 | 代码 | 单返回地址，不是全指令轨迹或完整调用栈 |
| 进程派生通知 | CreateProcessA/W After→PROCESS | 发送侧代码与配置 | 缺成功门禁、强身份和子目标Ready闭环 |
| 文件派生通知 | CreateFileA/W After→FILE_NEW | 发送侧代码与配置 | 打开调用不等于新建落地，未证明文件正文采集 |
| WMI语义 | ExecQuery／CreateInstanceEnum／Get方法Hook | 两架构代码，x64有触发绑定 | 不是全部WMI接口，Get文本缺发送路径 |
| 环境实验 | WMI属性、注册表结果、鼠标坐标替换 | 代码与不对称架构配置 | 属主动干预，类型／长度／返回及前后取证有缺口 |
| ROP候选 | 特定API入口call字节形态／PE节／声明栈检查 | x86代码与配置 | 当前路径至多一次调用点判断，无完整链与最初写入归因 |
| shellCode候选 | WinINet调用者不在初始模块表 | x86代码与配置 | 不是载荷执行确认，正常晚加载模块可能误报 |
| HeapSpray候选 | 堆块同尺寸／总量／重复内容扫描 | x86扫描代码 | 未闭合命中到告警门控，不能计作默认有效告警 |
| 网络正文 | x86 WinINet读After／写Before分块hex | 代码与配置 | 请求／完成混用、异步、链表offset与动作名问题 |
| 日志运输 | TCP分行JSON／UDP数据报＋共享队列 | 四DLL代码、默认TCP配置 | 不等于流量抓包；没有可靠交付与拥塞隔离保证 |
| 流量查看／代理／远程 | 官方演示的字段查看与四类服务 | 文档／截图；服务端实现另核 | 不据按钮确认PCAP、重组、TLS解密或鉴权 |
| CLI入口 | daemon位置参数＋时限，内部inject选项 | 文档及部分注入器代码 | 公开CLI仅声明PE64，不是长程双向控制 |
| 行为鉴定／插件 | 343条映射／341唯一ID、插件接口及主控入口 | 目录／接口已核，主控受保护 | 标签不等于可执行规则，Python SDK仅安装配置，正文未随包交付 |
| 转储／内核引擎 | 官方组件说明、内部工具选项 | 宣称／局部入口线索 | 检测命中→现场保留／转储未证，内包无SYS |
| 全局辅助宿主 | `globalhook`管道→逗号分隔DLL／导出→动态无参调用 | x64宿主静态代码 | 不能证明主控实际下发、全进程覆盖、停止恢复及协议鉴权 |
| 更新／安装包装 | 配置／版本／包→停止进程服务→备份→解压 | update代码，外install资源与有限静态识别 | 不运行／联网；真实性、掉电恢复及实际安装成功未核 |

这套已见机制主要是“装入监控入口→API／COM回调采字段→插件产生普通日志或异常候选→发送给控制端”。它对特定边界的行为观察有价值；没有证明通用写入来源追踪、全部既有线程执行发现或任意机器指令连续跟踪。

## 3. 已核对的WMI与环境干预

### 3.1 方法级WMI来源

x86 `ATInlineHook_WMI` 的`HookWMI` RVA `0x2380`、x64 `0x2750`，使用`CoCreateInstance`与`ROOT\\CIMV2`连接取得服务／实例虚函数入口，经`getVFnAddr`和`iHK_hookAPI`绑定方法回调。安装过程自己发起`SELECT * FROM Win32_OperatingSystem`取得实例，不只观察样本命令行。

ExecQuery／CreateInstanceEnum回调在x86 `0x1910`／`0x1b10`，x64 `0x1bb0`／`0x1e00`；保存查询或类别、原返回值与调用返回地址，再交日志函数。它提供可参考的COM方法来源，不能据此覆盖所有WMI接口、异步调用、所有对象类型或远程WMI。

配置有实际差异：x64明确绑定`ole32.CoInitializeEx=nofunc,HookWMI`及初始化；当前x86只见WMI插件段名，未见同等触发绑定。因此“x86 DLL里存在安装代码”和“当前配置默认激活”分别记账。

### 3.2 输出改写及自身行为

Get回调在x86 `0x1d00`、x64 `0x2010`；按Name、SMBIOSBIOSVERSION、SerialNumber、TotalPhysicalMemory、NumberOfCores、Manufacturer、Model七种属性名，向VARIANT payload写固定描述、数值或字符串指针。它是主动干预；仅按属性名判断不能保证对象语义正确。

回调函数返回常量0，以及直接写payload的静态路径均已核对。进一步核对x64实际登记与引擎后，**Get的After返回0会覆盖最终整数返回值，HRESULT低32位变为0**：WMI `0x2cff–0x2d20`将`0x2010`登记为默认After；引擎`0x9113`调用用户回调，`0x9118`无条件将RAX写入结果槽，`0x91b1`返回并经`0x95fe→0x9e0a`带入最终现场；WMI在`0x271b`清零EAX后返回。即使属性未命中改写分支，共同返回尾部仍可将原失败改成成功。前提是该Hook成功安装且正常返回，未执行COM运行负控；x86与自定义trampoline／异常展开路径不据此类推。

该引擎x64默认Before的普通C返回值会被后续覆盖，所核路径不把它当跳过原调用的状态；也不能为SDK补造必须调用`setReturnValue`的契约。`getReturnValue`在此实现最终只保留调用时RAX，不是独立保存的结果对象。VARIANT类型、失败后的输出内容、BSTR所有权和目标最终实际所见仍需运行负控，不概括为可靠通用硬件伪装。ExecQuery另有查找小写`where`、截断字符串和转换BSTR的代码，但未证明新字符串回写实际调用参数，不宣称已成功删除查询条件。

Hook安装路径自身的COM初始化／安全配置／WMI查询是工具行为，应与样本操作分开。只登记一次标志也不等于失败后可重试；本次不执行兼容性验证。

属性Get的前后helper还构造`isfilter/wmikey/wmivalue`日志，但不能计作已送出。x86 helper `0x17c0`在`0x18bd`、x64 helper `0x1a10`在`0x1b55`仅调用`makeCommonFormatMSGStr`；SDK与网络分路交叉确认该函数不入队／发送，随后helper即清理返回。对照ExecQuery在x86 `0x1a69/0x1a79`、x64 `0x1d31/0x1d3f`分别执行格式化与sendData，才有发送入队请求。故“存在结果改写”与“完整保存了改写前后”必须分开。

### 3.3 注册表和鼠标

`oppose_sandbox` x86 `after_regEx`／`after_reg`／`after_mouse`分别在`0x13f0`／`0x1690`／`0x1a10`，x64在`0x1560`／`0x1820`／`0x1b30`。通过SDK取得原返回值和调用方输出指针，修改缓冲区后交公共记录器。x86配置实际绑定RegQueryValueExA/W、RegQueryValueA和GetCursorPos；RegQueryValueW被注释，并附旧Office崩溃说明。x64配置未见这些同等绑定。

已核对的Ex回调含SystemBiosVersion／Identifier比较，但末尾还有无条件复制，不能说只修改命中的两类值。鼠标取值helper使用1920／1080常量；两架构写入均未完整覆盖8字节POINT（x86第二坐标写16位，x64复制6字节）。这说明旧实现存在值得避免的局部做法，不是本轮运行失败结论。

### 3.4 可借鉴之处

方法级WMI来源、对样本环境查询的识别、显式环境实验预设有参考价值。若后续选择研究主动干预，必须把系统原始返回、工具干预、样本最终所见与配置修订分别归档；默认不干预，不把替代值当真实硬件，不在历史导入时执行副作用。环境实验是单独候选，不因本次研究自动成为首版实施承诺。

用户随后明确要求深入反反虚拟机并给行动方案，已落实[16类探测面与15项研究／施工任务](ActionAnalyze反反虚拟机与环境实验行动方案.md)。该方案把本节发现的HRESULT覆盖、VARIANT所有权、属性身份、POINT长度及日志未提交作为必须验证的负控，不直接复制本包实现；现有静态结论不当作新方案已运行成功。

## 4. 漏洞检测与载荷取证的真实边界

对象`CheckHeap_plugin-x86.dll`，SHA256 `e68fcc40baf65fa673691a895b6d9b79000d2e61a84f3f4279d9dee696d9a49a`。两个x86配置第89–103行登记该插件、初始化及12个API，x64没有插件文件或绑定。配置中的`kernel32.ZwTerminateProcess`是否解析成功仍需真实安装回执，不能自动按ntdll入口算覆盖。

### 4.1 API边界的ROP候选

| Hook Before | 入口RVA | 实际检测 |
| --- | --- | --- |
| ZwWriteFile | `0x3130` | `ckropcl 0x5ec0` |
| ZwTerminateProcess | `0x3260` | `ckropmd 0x5f30` |
| ExitProcess | `0x3350` | `ckropcl` |
| LoadLibraryExW | `0x3440` | `ckropcl` |
| VirtualProtect | `0x3540` | `ckropmd`，不只在RW→RX时运行 |

SDK的`getReturnAddress`经动态解析进入全局指针槽`0x23658`。`ckropcl`的回调`0x5920`检查这个返回地址：落在当前声明栈范围内可疑；否则查看地址前2–7字节是否像若干常见x86 call编码。没有精确解码既有指令边界、call实际目标或实际执行分支，未匹配只构成启发式候选。

`ckropmd`回调`0x57c0`经PEB链找所属模块，排除工具自身的四个模块名，再在`0x56f0`检查PE节的CODE与EXECUTE属性。它不是当前页保护或真实执行记录；找不到模块时也不自动告警。节边界算法有旧实现假设，不能直接当健壮PE解析器复用。

**本包当前路径没有“10帧跟踪”。** 两个包装器传入数量10，但回调数组都是`{实际回调, NULL}`；`0x5dc0`遇第二个NULL即返回，无法进入后续EBP推进；回调本身也重新取SDK返回地址而不消费逐帧返回槽。因此最多一次调用点判断，不能从循环上限宣传多帧ROP发现。`fs:[4]`／`fs:[8]`的栈界限检查也不提供局部数组边界或最初写入者。

命中只额外发`exploit`／`action=rop`，随后仍记录普通API参数；本分支未见阻断或保存完整异常现场。它展示了无需等待保护异常的API调用现场候选检测，不能代替最初越界写、完整代码复用序列或攻击归因。

### 4.2 shellCode候选与模块身份

七个WinINet Before通过`0x5fe0`判断原调用返回地址是否位于初始化登记的模块区间。非空表全部未匹配时发`action=shellCode`；空表不报。这是模块外调用者启发式，没有验证该地址页保护、载荷内容、最初写入或污染传播。

模块表在初始化构建，未找到该分支后续刷新；LoadLibraryExWAfter为空且未在本插件登记。由此推断正常后加载DLL也可能被旧表标成shellCode；尚未运行验证。KSword可借鉴调用者定位，但必须使用当次模块／区域版本，保留JIT、正常Hook、晚加载模块及地址重用负控。

### 4.3 HeapSpray扫描与输出断点

`init 0x5660`建立工作线程；其中主模块名为powershell.exe时跳过堆扫描循环，不等于关闭其它API Hook。循环每秒看PrivateUsage，变化超过1MiB时创建扫描线程。原实现为无符号减法，下降也可能回绕触发；未见单个在途屏障，不能据此声称低扰动采集。

扫描器`0x4110`经GetProcessHeaps／HeapWalk收集已用且至少32KiB的块，按同尺寸分组。组要求块数大于5且总量至少20MiB；相似性helper `0x44d0`检查同偏移连续768字节相同，`0x4540`固定组合20槽位比较，共190对。每个样本至少与12个其它槽位相似才计入，计入样本不少于10个才判中。它寻找重复大块，不解码shellcode，也不确认攻击；有效指针不足20个时的空槽不是合法样本。

**输出链未闭合。** 命中写入栈局部变量，但`heapSpray`日志读取的是全局字节`0x23648`；其初值为0，本轮仅找到读取和清零的直接引用，未见置1路径。静态可确认扫描器、阈值与日志代码存在；不能宣称此包按正常已见路径会发堆喷告警。有效块不足20槽、采样后块释放、每轮创建扫描线程及句柄生命周期等另有待避免的问题。

### 4.4 输入字节与命中取证

CheckHeap的InternetReadFile／ExA After按缓冲区长度，以256字节分块转hex日志；InternetWriteFile Before保存请求发送字节，不依赖shellCode候选命中。前者未核实所有失败／异步完成，后者不代表成功发送；ExA换buffer后offset未复位，发送日志还存在误标读动作的问题。完整网络插件与这些WinINet采集是不同来源，不能混算为全栈覆盖。

`ZwWriteFileBefore`在本分支只记缓冲区指针与长度，没有复制文件正文。未找到ROP／shellCode／HeapSpray命中直接转储内存、MiniDump或可靠保持现场的闭环；孤立`.dmp`字符串不能作为自动取证证据。该结论仅限检测分支，宿主或其它插件另查，不能否定整个产品的文档导出／转储功能。

## 5. 网络：日志运输、调用缓冲区和代理分别核对

### 5.1 tcpLog／udpLog的实际职责

四个DLL提供`initIPPort/initByFile/initlog/sendData/sendDataEx/makeCommonFormatMSGStr/waitForSendAll`。TCP版创建`AF_INET/SOCK_STREAM/IPPROTO_TCP`连接，输出通用JSON加CRLF；UDP版创建数据报socket，发送不附CRLF的JSON。它们传送的是插件提交的日志文本，本分支没有PCAP写入实现；不能因文件名叫tcpLog而计作目标全机抓包器。

x64 TCP关键RVA：初始化`0xb600`、入队`0xb870`、等待`0xb990`、格式化`0xba80`、发送线程`0xb590`、单次发送`0xbe00`；x86对应`0x9600/0x9850/0x9930/0x9a00/0x9590/0x9d90`。四文件完整hash与UDP对应RVA保留在网络分路报告及总清单。

日志2313与调度2314分别有对象／socket，但Common的两个对象共用同一发送队列和线程。阻塞于日志发送可能拖延调度消息，这是结构推断，未做拥塞实测。发送路径一次`sendto`，未见短写／失败补偿；`waitForSendAll`仅等队列长度归零，最后一条出队后仍可能在发送，不能证明对端收到、解析、应用或落盘。

### 5.2 目标输入输出字节

默认配置把Winsock若干入口接到Common通用处理器；参数目录部分仅写指针／请求长度，甚至把sockaddr按字符串格式处理。尚不能把这些声明当作端点正确解码、实际发送字节、异步完成或完整会话重组。

x86另有CheckHeap的WinINet缓冲区路径，见§4.4：读取After与发送Before有不同事实强度。应用缓冲区有条件观察HTTPS加密前／解密后字节，但本次没有取得通用TLS库Hook、密钥收集、证书代理或稳定TLS会话绑定证据。翻译条目`HTTPS.DECRYPTDATA`也不能独立证明这些实现。x64未带对应CheckHeap插件，不推广x86能力。

### 5.3 演示中的网络服务与流量查看器

官方第19页图像显示日志2313、调度2314、远程2315、强制代理2316及TCP／UDP选择，第20页显示Hex／Int／Str／Unicode／UTF-8与字段宽度查看。由此可确认界面设计与公开功能宣称；代理重定向机制、服务鉴权、流量落盘格式、重组、DNS answers和任意HTTPS解密仍须具体代码或运行证据。

KSword可借鉴同一份字节证据的多种查看方式与按来源分型，但须保留连接／请求代次、方向、entry／submit／complete、实际长度、截断／读取失败、chunk身份与blob引用。运输入队、对端接收和证据提交水位分开，不用队列空代替可靠交付。本研究不启用代理或整机网络隔离，进程断连仍按原规划执行。

## 6. SDK、配置、调用上下文与传播

### 6.1 可审计的职责分工

已核对引擎入口安装、Common具名handler、独立`api_param`格式目录及日志插件解析路径。x64 `iHK_hookAPI 0x20c0`经实际安装函数写入口，`getReturnValue/getReturnAddress`为`0x3bc0/0x3bd0`；Common `0x74c0`读取API名、参数槽、返回位置和返回值，再交日志插件。它是入口Hook与调用现场记录架构，没有证据表明每一步CPU指令都会被记录。

具名handler以`模块.API=Before,After`登记；同一Common处理器既可放Before也可放After。目标专用配置找不到时回退默认配置。适合借鉴的是明确责任、可审查目录和配置分层；KSword已有双位数Agent及强类型目录，继续复用，不新增共同TraceHost、追踪DLL或统一runtime。

### 6.2 参数目录与阶段的局限

两份参数目录各81行，实际是具名printf片段，未表达in/out、输出长度、有效条件和异步阶段。x64若干指针／SIZE_T／HANDLE用`%d`，CreateProcessA部分非字符串参数用`%s`；未知参数数在引擎中回退31槽，但Common还按格式条目数量限制循环，不能说全部31槽都被输出，也不能将回退槽数当函数签名。

通用日志实际有Time、Pid、Tid、Process、Module、ApiName、Details、Return和ReturnAddr。只有单个调用返回地址，Return为`%d`；没有显式阶段、源序号、强实例、配置／覆盖修订。参数目录存在不等于该API配置启用，更不等于安装和实际采集成功。对KSword的落点是继续保留无损强类型与Raw边界，禁止由摘要反推阶段与正文。

### 6.3 配置符号不等于调试控制

引擎解析器把`[break]`当作跳过本节后续条目的标志，到新节重置；导出`pauseNop`最终为`PAUSE; RET`，也不是线程停点。当前未得到参数命中→业务线程停止→外部通知→用户继续／失联恢复的闭环，不能把配置字样升级为条件调试器。

Common的`LOADED`在配置第4行初始化时发送，`HookAll`到x64第108行才请求，因此Loaded不能证明必需Hook与规则／执行探针实际Ready。KSword的逐项安装回执和准入屏障仍必需。

### 6.4 子进程与文件的后置通知

`process_moniter`从CreateProcessA/W第10参数的PROCESS_INFORMATION读取child PID并发送`currentPID:PROCESS:childPID`，x64／x86偏移分别为`+0x10/+8`，布局相符。但通知前未见以原BOOL结果过滤失败路径，也缺子进程创建身份、子TID和Ready回执；不能据此证明首段执行前纳入、快速多跳或既有线程／APC／共享映射传播。

`file_moniter`从CreateFileA/W读取路径并发`FILE_NEW`，未先按返回HANDLE与creation disposition证明新建成功。因此它是附带路径的调用通知，不能直接作为新文件落地事实。通知字串本身没有长度头／CRLF，TCP一次发送也不提供消息边界。

注入器有VirtualAllocEx／WriteProcessMemory、CreateRemoteThread、QueueUserAPC／ResumeThread的调用代码及对应选项，证明工具自身具备注入／恢复相关实现；工具使用某种注入手段不等于它完整监视目标的同类攻击。当前官方daemon哈希与另一份旧目录不同，且有保护节，不能移用旧宿主RVA补成本包控制端闭环。

### 6.5 CLI和行为翻译目录

包内命令行说明明确daemon CLI为一次启动、样本运行毫秒数和参数，公开限制为PE64，PE32用GUI；输出示例为架构／PID／TID文本。内部inject工具选项不等于daemon长程控制。本次未取得持续stdin命令、请求ID／阶段回执／分页／EOF恢复的实现证据；KSword已确定的人工REPL与AI JSONL双向活会话设计保持原要求。

`actionCN.md`是行为ID→中文翻译，共343条映射行、341个唯一行为标识，`PSW.PROTOCOL`和`ABNORMAL_NETWORKDATA`各重复一次；不能当采集／匹配／时序规则全集。可借鉴机器ID与本地化分离。主控分路已完成本轮静态审查，但受保护主控内的事件→匹配→级别→翻译执行链仍未知，不将行为词条数量当规则数。

### 6.6 主控、鉴定器、数据库和辅助宿主

主控`daemon.exe`是原生x86，SHA256 `b2ffd7598cae02881bfbd5e7fb2df82b78374d3fcc7afd55efd583b4c1f674fc`，带`.vmp0/.vmp1/.vmp2`保护段，不能按.NET元数据或另一旧版本RVA补齐业务路径。主控分路登记H01–H24共24个可见／文本入口：样本与打开方式、注入已有进程、衍生树、行为／SQL／调度区、网络服务、扩展应用、全局Hook、多语言及帮助等；这是一份功能证据目录，不是24项代码都已还原。

PDF中的`select * from tbReport`与execSQL按钮证明界面角色。`log.mdb`为958464字节Jet数据库，使用本机Access ODBC只读打开返回“密码无效”，未猜密码／提取口令，未取得schema、记录、索引或恢复策略。不能从SQL截图推导已读出表结构。计划任务标签`CRON`描述目标行为，“调度器”和2314端口也不能证明工具支持预约／周期采样。

`globalHook.exe`为x64，SHA256 `9d6a4298cd09059622dc15bcfddb41c4ca1c34c9845cd88a938d1dc870181e73`。以纯数据方式解NRV2E压缩流，压缩／解压Adler32分别为`0x95515797`／`0x48cec001`，与头一致；分析的是数据与有限反汇编，不执行解压桩或生成可运行重建包。

| 宿主RVA | 静态确认的路径 | 边界 |
| --- | --- | --- |
| `0x2c7170`、`0x2b9640` | 建立`\\.\Pipe\globalhook`对象并到CreateNamedPipeW包装 | 未运行连接、权限或覆盖测试 |
| `0x2b9d60` | 按收到的长度复制消息；`exit`分支；其它消息按逗号分为两项 | 是逗号分隔；具体 framing／长度限制／鉴权未核 |
| `0x2b9e07`、`0x2b9e37`、`0x2b9e4d` | 第一项交LoadLibraryA，第二项GetProcAddress，非空则无参调用 | 只证辅助宿主分派，不能证明主控实际发送哪些命令 |
| `0x2b8870` | `exit`到终止当前辅助宿主的包装 | 不证明目标恢复／挂钩卸载 |

`startHook/stopHook`字符串存在，但主控发送及目标覆盖／清理闭环未恢复。SDK方面，PDF明确声明Python鉴定器SDK，`upmarket.lst`配置`local=app/sdk/`、`mode=install`、`exe=readme.txt`；当前内层没有`.py/.pyc/.pyd`或SDK正文。未访问配置中的更新地址。回调签名、输入类型、状态预算、异常隔离及许可仍未知，不能将SDK宣称写成已收集规则执行器。

### 6.7 更新器和外层安装器

`update.exe`为原生x86／Delphi，SHA256 `d0c47332bbb249ac377690e000ee1df9611eb807e76afcc347100265b6ba911d`。已用实际Ghidra与汇编核对配置／版本／下载／进程服务／备份／ZIP解压链，没有运行程序、脚本或请求上游更新服务。

| 更新器RVA | 已核对事实 | 不能据此推导 |
| --- | --- | --- |
| `0x291e68`、`0x291818` | 解析remote/local/domain/info/exe/backlist/syslist/mode等；列表存在则逐项，否则默认配置 | 不代表配置已生效或所有下载路径相同 |
| `0x290968`、`0x279398`、`0x279594` | 比较版本并取得包路径；所核文本请求构造HTTP URL；包写出及进度回调 | 当前后端可用性、所有产品通道均为HTTP、全路径没有真实性验证 |
| `0x291248`、`0x290df0` | 更新顺序及按配置查找／TerminateProcess目标进程 | 不是调试停止或目标恢复方案 |
| `0x291ab4`、`0x278b84`、`0x278c00` | 对syslist执行OpenServiceW、服务STOP及DeleteService | syslist名称不能证明包内已交付或装载相应驱动 |
| `0x29132c`、`0x29195c` | backlist的`.back`备份及回拷 | 不等于外部系统副作用可回滚 |
| `0x291b98`、`0x293468` | 更新工作线程把安装目录＋package.ready交ZIP对象，到元数据标为ExtractAll的方法 | 不证明路径限制、完整性、掉电事务或实际安装成功 |

外层`install.exe`为834800字节，SHA256 `e058dc297bd3a27e825fc37d864beca470baaf6aa369d0e8fb02dde03717daab`。仅有限PE／资源／纯数据解压识别：Adler32压缩`0x8d41f7a0`／解压`0x11db212a`均与头相符；`TFRMMAIN`资源原布局RVA `0x304640`明确自述“本程序为升级组件”，可独立读取同目录update.conf。有限搜索未发现满足完整PE头条件的直接嵌入PE；不能从孤立MZ／PK常量认定内嵌完整程序，也不能排除其它压缩资源／外部文件／运行时下载方式。

本轮主控分工已经收尾，留下的是明确的证据缺口：保护主控业务、鉴定规则／SDK正文、MDB schema、全局发送端／停止恢复、远程鉴权及更新真实性／故障恢复。静态研究范围完成不表示这些未知项被验证为没有功能；不为闭合报告而运行包、绕保护或请求后端。

## 7. 向KSword规划的具体映射

下表只落实研究所得的设计约束与候选位置，不新增已经完成的产品能力，不把竞品全部入口自动加入首版承诺。

| 研究所得 | KSword落点 | 需要验证的实际判据 |
| --- | --- | --- |
| 具名handler、字段目录、配置分层 | A0目录／能力＋A5既有Agent来源 | 逐入口／架构／阶段有效字段、配置hash与实际安装回执；沿用强类型，不复制printf猜类型；明确回调结果与原返回位的契约 |
| 单调用点异常与便宜指标触发调查 | A5来源＋A7栈完整性＋A8后台调查 | 原始现场与候选判据分开；模块／区域版本、JIT／尾调用／合法切栈负控；无界循环不进入同步谓词 |
| COM方法级来源 | A5候选目录、事件契约 | 接口／对象／命名空间与查询结果身份、同步／异步、工具自身操作及日志真正提交分开 |
| PROCESS／FILE_NEW通知的事实强度 | A5事件语义＋A6传播 | 原调用失败负控、子强身份、初始线程原挂起状态、必需覆盖Ready、快速A→B→C |
| 日志／命令共用资源的阻塞风险 | 既定通信控制施工＋A4／A6 | 独立控制执行路径、目标外恢复责任、真实ACK／Query、暂停／日志背压／失联与清理 |
| 实际网络字节及多种查看方式 | A1 blob／水位＋A5网络来源＋A9投影 | requested／actual／captured、方向／阶段、资源代次、chunk完整性；同一字节源切换解释，不另造副本 |
| 行为翻译与规则执行分开 | A0机器ID＋A2规则manifest | 精确规则来源／授权／hash、依赖字段、阶段、证据和缺口；翻译条目不作为可执行规则 |
| 环境结果改写 | 单独实验候选，暂不纳入默认采集 | 显式授权和一致预设、原始／替代／最终所见、工具干预记录；不以结果伪装替代被动事实 |
| 一次启动CLI的能力限制 | A3既定长程CLI | 同一存活进程内REPL／JSONL真实命令与接受／生效／回读、背压／EOF；不退为启动参数 |
| 全局辅助宿主的DLL／导出分派 | A0方法身份／A4所有权／A5实际覆盖 | 不照搬任意动态导出执行；请求身份、实际生效回读、逐目标停止恢复分别证明 |
| 包级组件声明／安装市场／更新链 | A10依赖与发行清单 | 交付、可安装、已启用分开；版本／包身份及失败结果明确，服务删除／终止循环不当恢复机制 |

已同步主需求、开工总表、栈专项、事件／字段契约、README与共享记忆。更完整的写入归因、受支持迁移前闸门、R0停止恢复责任、共享映射普通store及完整线程门控仍按原规划独立验证，不能由Action Scope的插件名称补齐。

## 8. 研究交付与验收口径

本次运行的是静态分析工具，未执行ActionScope二进制、目标素材、注入、驱动、远程服务或激活；未构建／修改KSword产品、语言包、GUI与Release。headless成功只证明完成静态分析与指定函数伪码输出。

后续任何“值得借鉴”项须映射到KSword现有来源／规则／调查／各端会话工作包，继续遵守[开工总表](ActionAnalyze完整开工审查与实施总表.md)的非虚拟化、三端各自所有、后台调查与R0验收边界。第三方分发形式不构成复制代码或二进制的授权；本轮只保存可追溯研究结论。

### 8.1 本机证据索引

| 资料 | 位置与用途 |
| --- | --- |
| 精确包清单 | `.codex-build-logs/behavior-planning/ActionScope-package-static-manifest.json`：外层4条目、内层38文件、逐文件SHA／架构／导出 |
| SDK分路 | `.codex-build-logs/behavior-planning/ActionScope-sdk-static-review.md`：配置行号、双位数引擎／Common／日志／通知RVA，以及WMI输出交叉核对 |
| 检测分路 | `.codex-build-logs/behavior-planning/ActionScope-detection-static-review.md`：全部检测入口、阈值、x86 call字节判据、输出／取证边界 |
| 网络分路 | `.codex-build-logs/behavior-planning/ActionScope-network-static-review.md`：四DLL发送链、分块字段、服务／流量截图和未知项 |
| 环境分路 | `.codex-build-logs/behavior-planning/ActionScope-environment-static-review.md`：WMI安装／回调、属性、注册表和鼠标干预的双架构证据 |
| 主控分路 | `.codex-build-logs/behavior-planning/ActionScope-host-static-review.md`：24入口、343映射／341唯一ID、Jet只读失败、全局宿主管道／导出链、更新／安装包装与未知项 |
| 静态取证原件 | 本机批准临时参考目录`actionscope-reference/`：官方ZIP／PDF、原始PE、Ghidra项目、日志、反汇编与伪码；保留取证，不进入Release |

诊断目录可能被Git忽略，因此可移交的机制结论、关键RVA、输入hash和边界保留在本文；本机分路报告用于深入复核，不能把未提交文件视为已经随仓库发布。目录登记不代表运行验收，静态工具产生的取证资料按研究需要保留。
