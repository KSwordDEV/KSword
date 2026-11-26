# ActionAnalyze 项目存储格式与恢复设计

[缺口复查G13–G15](ActionAnalyze规划缺口复查与补齐任务.md)补充：归档seal不等于源覆盖完整；CLI项目搬运与证据导出分别登记；project.close不隐式停采，sample.delete仍受writer／活session／query／未决责任约束。新增方法只复用本文既定格式／墓碑／lease，不新增第二套存储或跨端接管。

日期：2026-11-24。状态：首版实施建议，未创建读写器、未冻结机器schema、未做互读／崩溃／掉电／性能验收。产品层级见[项目与多次采样](ActionAnalyze分析项目与多次采样设计.md)，字段类型见[事件身份与协议](ActionAnalyze事件身份与协议契约.md)，查询见[筛选器／规则](ActionAnalyze筛选器与规则语言设计.md)，依赖见[完整开工总表](ActionAnalyze完整开工审查与实施总表.md)。

## 1. 首版方案与依赖取舍

首版建议确定为：**实时目录项目＋严格UTF-8 JSON小文档＋可校验分段记录＋独立证据blob＋可重建索引**。原始字节与规范事件分别保存；控制历史仅为镜像，绝不成为可继续旧目标的凭证。

选择理由来自本仓库源码审阅，不声称依赖已接通：

| 既有实现 | 已有能力 | 新接入必须补齐 |
| --- | --- | --- |
| `shared/evidence/EvidenceJson` | Qt/CLI已登记、有界无损值及重复键拒绝 | Light产品未登记；边界另校验严格UTF-8、前导零、schema类型，不能靠便利转换放宽接受域 |
| `ObjectIdentity`／`EntityGraph` | 身份强弱、证据／覆盖和图投影思路 | EntityGraph未登记三产品、全图常驻无磁盘分页；句柄键缺开闭代次、连接键与owner匹配条件不一致，不直接作持久主键 |
| `WinAPIDiskArchive` | Qt JSONL原包、缓冲写入和停止flush | 收包调用栈同步序列化／写入、无分段CRC／随机索引／恢复；CLI无等价持久档案，不能直接改名共用 |
| Qt ETW档案 | Stored／zstd分块、已有旧格式reader | QDataStream/QString载荷不作三端共同格式；保留旧reader与显式转换 |
| `third_party/zstd` | 已有1.5.7源码／许可、Qt引用 | CLI/Light未引用，现静态工程/MD与Light/MT不一致；按端匹配CRT及固定产物后再开codec1 |
| NIDS `network_nids_state.h` | 系统winsqlite3动态装载的临时状态 | 当前synchronous=OFF／关闭删除不是项目数据库；三端需新增受限cache adapter及导出／版本能力检查 |
| CBOR、ZIP | 未查到三端可直接链接的共同CBOR／ZIP64写入实现 | 首版不依赖CBOR、QtSql或外部7z；不把zlib解压子集当完整archive库 |

首版基本读写**必须支持Stored codec0**；zstd codec1为明确可选能力，写入前按本端链接／CRT／许可证门禁开通。无codec1的端不得改写含codec1的采样，也不得声称可解码；可看manifest及不依赖该段的资料。正式发布若写端默认启用zstd，发布组合必须保证三端reader均有对应codec能力，避免互读伪承诺。

SQLite建议作为**可选系统加速器**，只读顺序扫描与基本块目录是必备回退；同格式／同查询语义不等于同延迟。首版不引入自带SQLite运行DLL、不承诺任意Windows有相同索引性能。若实测查询SLO要求固定版静态SQLite，由独立依赖包完成来源／许可／工程及兼容验证后再切配置，不能暗中用QtSql替代。

离线单文件搬运采用下文`.ksapack`受限顺序容器v1，所有entry直接Stored，不依赖新通用压缩／解包库；内部已压缩segment原样装入。它不是ZIP/7z，也不用于实时采集。目录导出和此容器同为A1正式工作项，不把单文件打包继续留待决定。此选择区别于独立审查的ZIP64候选，原因是当前库未齐、无需实现通用archive兼容；今后ZIP适配另立版本，不偷改容器magic。

## 2. 目录、扩展名与归属

用户选择项目专用目录，打开其`project.ksaproj`。显示名称不作路径；目录移动／改名不改变projectId。全部内部引用为固定布局下的ID和相对路径，不写个人机器绝对路径作为开发／资料落点。

```text
<project>/
  project.ksaproj
  revisions/<revisionId>.json
  drafts/<draftId>.json
  journal/<generation>.json
  catalog/<generation>/manifest.json
  catalog/<generation>/<pageId>.json
  rules/<packHash>/manifest.json
  rules/<packHash>/...
  samples/<sampleId>/
    sample.json
    snapshots/<snapshotId>.json
    raw/00000000000000000001.ksaseg
    records/00000000000000000001.ksaseg
    control/00000000000000000001.ksaseg
    analysis/<analysisRunId>/...ksaseg
    evidence/<evidenceId>.json
    blobs/sha256/<first2>/<hash>
    checkpoints/<generation>.json
    sealed.json
  cache/<sampleId>/<indexVersion>/
  ui/<frontend>.json
  .locks/
  .staging/
  .trash/
```

raw／records／control各自单调序号；analysis每批独立流，输入水位固定。段名统一为流内20位零填充十进制u64序号，从1开始，达到u64上限前结束流，绝不回绕。实际索引按header ordinal，不依赖名字猜身份。每个analysisRun在流描述中固定自己的runId；原始段和分析段不能互相借用序号空间。

稳定UUID使用规范小写带连字符；二进制UUID采用RFC字节顺序，不memcpy Windows GUID。sample内object／mapping／regionVersion／operation／eventOrdinal为u64顺序ID，跨sample必须带sampleId。键值不是文件名；不存在／未知不能用编号0补造对象。原生PID/TID/VA及crossSessionKey只作有来源的属性，不独自作全项目主键。

blob仅**同sample内去重**，避免删一个sample牵动其它sample；不跨项目硬链接。普通1000字节原包集中成块，不每包建一个blob；dump／长脚本／大字段按4 MiB内容chunk分文件，manifest保留逻辑offset、长度及holes。字节洞不补零假装读到；标准`.dmp`可保持原格式文件并以相同hash／manifest登记，导出时不能混称`.bin`。

### 网络流量与通信字节

同一采样同时保存网络观测和实际捕获的通信内容。普通通信记录使用 `raw/` 的 `RawRecord`，每段包含多个块，块内包含多条记录。内容超过内联上限时使用同一采样的 `blobs/sha256/`。保留源记录的字节层级、捕获时间、已存长度、原始长度的已知状态及截断原因。流计数器、连接快照和只有元数据的事件按来源记录。出站目标 IP 汇总从 `records/` 重建，并能跳回证据。

同一 writer 依次保存来源依赖、原始字节和关联事件，再从各流完整块边界发布检查点。段和流内序号以接纳顺序分配。跨流排序使用可比较时钟和稳定事件标识。写入配额、捕获截断和缺失范围随采样归档，读取端分别表示已提交内容、仅元数据和可恢复尾部。验收要求在重新打开项目后逐字节核对本地 TCP／UDP 测试通信，并核对截断和坏尾后的引用。[桌面网络交互与验收](ActionAnalyze总览交互与验收.md#网络记录和原始字节的存盘顺序)

## 3. 小文档、修订与规则快照

所有内部生成文档UTF-8无BOM、LF；外部配置导入可剥一个开头BOM并保留原hash。原目标坏编码／UTF-16／ANSI只以raw字节与编码元数据保存，展示文本不是替换后的原证据。

内部JSON须严格校验重复键、编码、代理项、整数／u64规范、未知requiredFeatures／控制字段和长度。默认单文档4 MiB、深度32、单小字段64 KiB；大内容引用blob。地址固定16位hex，u64／时间／偏移十进制字符串；浮点参数原位保存IEEE754 bit字符串／类型，不借double承载地址，也不要求JSON支持NaN。原字节hash与规范语义hash分别保存，规范序列化使用事件协议的`aa-cjson-v1`，不按缩进或键序判断语义相等。

| 文档 | 最少内容与约束 |
| --- | --- |
| project.ksaproj | kind/version/requiredFeatures、projectId/title/createdUtc、currentRevisionId/hash、journalGeneration/hash、catalog root、producer、storagePolicy；不内嵌全部sample |
| 不可变revision | revisionId/parentRevisionId、目标选择意图、来源／必要覆盖、capture/discovery/breakpoint定义、预算、调查预设、关闭／失联策略、规则包引用；无活句柄 |
| draft | 独立draftId、基于修订／hash、编辑正文和校验状态；保存不应用，打开不执行 |
| sample.json | 不可变创建描述：project/sample、创建端／版本、配置完整快照引用与hash、规则／字段／DSL／adapter、环境／时钟／组件、requested/actual后端及初始目标 |
| snapshot | 配置／能力／覆盖的不可变版本及来源、生效时段、desired/effectiveRevision；用户草稿与实际结果分开 |
| evidence manifest | evidenceId/job/object/regionVersion、请求／实得范围、时段、格式／架构／编码、chunks／holes／长度／hash、错误／partial、采样来源 |
| checkpoint | generation/previousHash、每流精确段／块／字节偏移的已刷前缀、字典／raw／blob依赖及封存目录摘要、已知holes/gaps；不能只存最大序号 |
| sealed | 采集／分析／归档／原生清理分别状态、最终水位、段／blob摘要和缺口、未决责任诊断；sealed不是目标已恢复的证据 |

项目目录正常通过journal及catalog分页读取，建议每页256个sample摘要，不每次递归载入全部sample。journal条目是独立小文档，含generation、previousCommitHash、操作／ID及精确文件hash；catalog为可验证快照页，manifest只指向已提交根。失败保留前一可读generation，不用“最大文件名”猜最新提交。

采样保存实际采用配置的完整副本，不只指向可删的project revision。规则包保存固定来源／commit／文件hash、许可、选用集合／依赖闭包／字段映射／missing；许可不能嵌入正文时保留来源／hash、replayUnavailable，不能宣称完全复算。运行改变配置追加accepted/effective/observed及真实水位，不覆盖初始快照；只读重分析新analysisRun，不覆盖旧behavior。

UI选中sample／列组／折叠／缩放／显示过滤默认存本机用户配置，不进入采集／规则hash；便携`ui`文件只显式保存，需项目写锁。只读打开不自动写ui或cache；本机cache以project/sample内容指纹隔离，项目克隆同ID不同内容不串缓存。

## 4. v1分段二进制格式

以下为待A0黄金文件验证的具体候选布局，区别于驱动ABI。逐字段little-endian编码，禁止直接写C++ struct、Qt对象、指针、size_t／wchar_t。record不跨block，block不跨segment；累计偏移u64，系统调用分片并检查DWORD/size_t缩窄。

### 4.1 段头96字节

| 偏移 | 大小／类型 | 字段 |
| --- | --- | --- |
| 0 | 8 bytes | `KSAASEG`＋NUL（8字节） |
| 8/10 | u16/u16 | major=1/minor=0 |
| 12 | u32 | headerBytes=96 |
| 16/20 | u32/u32 | requiredFlags／streamKind |
| 24 | u64 | segmentOrdinal，从1递增 |
| 32/48 | 16/16 bytes | projectUUID／sampleUUID |
| 64 | u64 | createdUtc100ns，FILETIME纪元 |
| 72 | 20 bytes | reserved，全零 |
| 92 | u32 | headerCRC32C，覆盖0..91 |

streamKind建议raw=1、records=2、control=3、analysis=4；requiredFlags初版0，未知位拒绝。analysisRunId由流描述及sample内目录绑定，不能只靠用户可改路径。catalog记录每段hash／长度／流身份及只写一次的封存摘要，不修改已封存段头。

### 4.2 块头80字节

| 偏移 | 大小／类型 | 字段 |
| --- | --- | --- |
| 0/4/6 | 4 bytes/u16/u16 | `AAB1`／headerBytes=80／blockVersion=1 |
| 8/10 | u16/u16 | codec（0 Stored、1 zstd）／flags |
| 12 | u32 | recordCount |
| 16/24/32 | u64×3 | blockOrdinal／firstRecordSequence／lastRecordSequence |
| 40/44 | u32×2 | decodedBytes／storedBytes |
| 48/56 | u64×2 | minReceiveQpc／maxReceiveQpc |
| 64/68 | u32×2 | decodedCRC32C／storedCRC32C |
| 72 | u32 | reserved=0 |
| 76 | u32 | headerCRC32C，覆盖0..75 |

flags bit0表示QPC范围有效，其余初版0。先验证magic/version/flags/headerCRC及长度再分配。目标block1 MiB，decoded硬限8 MiB、stored9 MiB；Stored两长度相等。zstd每块独立frame、无跨块字典、内容长度与输出窗口均受上限约束，未知codec为unsupported而非corrupt；不依赖codec checksum取代块CRC。块recordCount至少1，最大32768且受长度限；记录序号唯一递增，首末范围不证明中间没有显式gap。

CRC统一CRC32C：反射多项式`0x82f63b78`、init/xorout=`0xffffffff`，little-endian保存；A0向量`123456789`预期`0xe3069283`。SHA-256计算原始内容／封存文件，CRC定位局部损坏；均不等于来源鉴真或防止有写权限者重新计算。

### 4.3 记录头32字节

| 偏移 | 类型 | 字段 |
| --- | --- | --- |
| 0/4/6 | u32/u16/u16 | totalBytes／recordType／recordSchemaVersion |
| 8/12 | u32/u32 | flags／payloadBytes |
| 16 | u64 | recordSequence，按流单调 |
| 24/28 | u32/u32 | payloadCRC32C／headerCRC32C（覆盖0..27） |

totalBytes=32+payloadBytes，无隐式padding；flags bit0=理解此类型为必需，其余初版0。块恰好解出recordCount并耗尽decodedBytes，拒尾随垃圾／溢出／重复或倒退序号。未知可选type可跳过并记unsupported，未知必需type只允许原字节浏览，不作为完整解释的sample。

recordType建议目录：1 SourceDescriptor、2 ClockCalibration、3 RawRecord、4 CanonicalEvent、5 ObjectObservation、6 IdentityResolution、7 MappingObservation、8 RegionVersion、9 Relation、10 Behavior、11 Gap、12 Suppression、13 Enrichment、14 Coverage、15 ConfigChange、16 ControlFact、17 EvidenceRef、18 AnalysisDescriptor、19 AnalysisDelta、20 DecodeFailure、21 StreamStatus、22 DictionaryEntry。枚举在A0存储catalog固定，不借驱动现有编号。

DictionaryEntry为sample作用域append-only映射：dictionaryKind/id/type/value及内容hash；kind至少覆盖source实例／epoch、operation、文档修订、配置修订和coverage引用。同kind/id只能绑定一个值，重复必须同hash，禁止重绑定。引用发布前先写对应字典条目，跨流持久水位不得越过它；缺条目是Missing引用，不能猜字符串。analysis流第一条必需AnalysisDescriptor固定runId／sample／输入水位与规则hash，和目录／catalog交叉核验，不能只凭目录名绑定run。

低频记录payload为严格JSON；raw为u32 metadataJsonBytes＋metadata JSON＋原始字节，长度由元数据／record共同约束，不含宿主指针。大raw写blob引用及实际捕获长度；未经身份校验的外来包不得当合法事件入主流，可留有严格体积限制的拒收诊断，不无限保存攻击者输入。

### 4.4 规范事件核心128字节

| 偏移 | 类型 | 字段 |
| --- | --- | --- |
| 0/8 | u64×2 | eventOrdinal／primaryRawRecordSequence（raw流序号） |
| 16/24 | u64×2 | sourceInstanceDictionaryId／sourceEpochDictionaryId |
| 32/40/48 | u64×3 | producerSequence／sourceTimestamp／receiveQpc |
| 56/64/72 | u64×3 | actorProcessObjectId／targetProcessObjectId／observedThreadObjectId |
| 80 | u64 | operationDictionaryId |
| 88/96/104 | u64×3 | captureRevisionDictionaryId／effectiveRevisionDictionaryId／coverageDictionaryId |
| 112/116/118/119 | u32/u16/u8/u8 | eventKind／category／phase／clockDomain |
| 120/124 | u32×2 | validityBits／fieldJsonBytes |

核心头后紧跟fieldJsonBytes个typed字段JSON，`128+fieldJsonBytes`恰好耗尽payload。额外actorThread/targetThread、多raw引用、原结果／错误、field availability等在字段区，不能因核心头有限丢角色。sourceTimestamp的单位、clockId及校准引用由ClockCalibration／字段区精确绑定，clockDomain枚举不代替clockId。字典ID是采样内u64索引，原source epoch UUID／配置修订另存，禁止截断UUID；无效项字节零但以validityBits区分已知零。validityBits建议bit0..10依次rawRef/sourceSequence/sourceTime/receiveQpc/actor/target/observedThread/operation/captureRevision/effectiveRevision/coverage，未知位拒绝解释；source实例／epoch字典引用是必需字段，没有合法来源的记录只能留DecodeFailure诊断。

eventId为sampleId＋eventOrdinal，独立于raw序号及records流recordSequence；后者也包含对象／覆盖等记录，不能拿它当eventOrdinal。每流一个有序writer负责分配recordSequence；并发解码器通过同一接纳点取得eventOrdinal，未提交预留号不复用，显式记录缺口。一raw可解零到多event。规范化失败写DecodeFailure及raw引用，不伪造空event。多source原本同一调用保存明确operation/wrapper关系，缺证据不按时间自动去重。固定头避免每条重复项目UUID／长路径，JSON区便于落地已有无损工具；实测若编码成为瓶颈，可新增payloadSchema的typed TLV/CBOR，不在同版本暗改字节。

## 5. 提交、刷盘和跨流依赖

### 5.1 小文档事务

1. 同卷`.staging`写唯一临时文件，完整写入、flush、核对长度／hash。
2. 不可变目标采用create-new语义发布；同ID已存在只在精确hash相符时复用，不能覆盖。
3. 写journal提交，保存previousHash和所指文件hash，再更新小manifest指针；保留前一有效manifest。
4. 新sample先提交sample描述／配置／规则引用，再提交项目journal纳入catalog。崩溃留下孤立sample显示orphan，显式恢复，不自动删取证或称完整。

实现用适用的Win32替换／重命名语义并有界重试共享冲突，失败保留旧文件，不退回截断正式文件。默认可写位置建议本地NTFS；网络盘／未知文件系统默认只读或明确未验证，不能照搬本地锁／rename假设。设备掉电、目录项持久性和存储缓存必须实测，上述顺序不宣称跨文件绝对事务。

### 5.2 归档和水位

必要字典／raw／blob先写；规范事件可排队引用，但其durable不得超过依赖durable。一个接收包被主动过滤／解码失败等，推进规范化“已解决前缀”需要明确结果记录或gap，不只用最大eventOrdinal。

至少分别报告received、queued、written、dataDurable、normalized、analysisProcessed、indexed、uiProjected。每流／每source保存连续前缀、holes和unknown tail；不同source sequence不可直接相加成一个全局水位。written只表示完整WriteFile完成，dataDurable为涉及文件flush完成并发布对应checkpoint之后；不承诺设备绝对不丢电。

成块建议1 MiB或有数据250ms，flush建议1秒或8 MiB先到，用户保存／停止／导出执行显式barrier；这些为初值，慢盘可更久，不承诺最多只丢1秒。控制线程／真实恢复不得等待barrier。checkpoint存各流段／块／offset和依赖闭包，新代flush／发布后才淘汰更旧代，至少保留最近两有效代。

每段建议256 MiB或10秒有数据时轮换，先写完当前块再换段；v1单段物理硬限1 GiB，下一完整块会超过时必须先换段，无数据不建空段。关闭后计算封存SHA／长度，写段catalog。先刷所有证据依赖，再写sealed；nativeCleanup独立，不将“文件已封存”显示为“目标全部恢复”。分析尚未完成可另有进行中analysis流，不回写原始段；sample seal与每analysis seal分别记录。

## 6. 崩溃恢复、迁移与旧档案

打开默认只读检查version／requiredFeatures、manifest/journal hash链、sample/checkpoint引用。封存段按需核hash与块CRC，最新活动段从最后有效checkpoint后扫描完整块；完整尾部可读为recovered-uncheckpointed，不倒填此前durable承诺。半头／半payload保留此前完整前缀并标interrupted/tailUnknown，不扫描下一个magic后拼成完整流。封存段中途损坏也在首个坏块停止该流的完整前缀；若另做取证salvage，必须新派生样本、保存每段来源offset和gap，不把后段拼成连续无损历史。

源文件从不因只读恢复而截断。显式修复写新恢复修订／副本，保留原源及conversion report；若恢复发现缺字典／blob／raw，显示Missing(reason)，不补造字段。重新采集创建新sample／epoch，不向旧活动段继续添加活控制事实，不从旧stop记录恢复控制权。

major迁移：独占项目写锁→空间核验→新目录／新修订流式转换→校验所有引用／hash／数量映射→发布新根；取消只留可识别staging，不替换旧manifest。原项目保留，cache版本变更直接重建，不改事实。程序降级只读或拒绝，不能丢未知记录后另存成“完整旧版”。

旧WinAPI JSONL显式导入import sample，流式保留原文件hash与packetBase64原包，缺boot／线程创建身份及尾部就unknown。旧Qt ETW通过匹配布局的显式Qt适配器转换，两原生端无适配器则不支持旧文件，不为格式强带Qt。Light旧文本仅导为外部文本证据，不逆猜typed事件。导入不执行rule／DLL／脚本，也不pause/continue／注入。

## 7. 单写者、并发只读与删除协调

首版每项目一个元数据／活动采样写者、一个活动sample；另端默认只读。`.locks/writer.lock`真实句柄与固定字节范围锁授权写入，PID／创建时间内容仅诊断；文件存在不代表仍有owner，不能删活锁或凭sessionId接管。进程崩溃后锁释放也只允许资料恢复，不接管原生责任。

可写项目创建maintenance.lock，读者以共享维护锁建立具体段／manifest句柄及查询lease；GC用独占维护锁登记删除集合。避免读者注册与删除之间竞态，不持全局锁等待I/O／用户。产品跨进程读者持唯一lease文件的OS锁，GC检查真实锁，不靠本端shared_ptr或超时文件名。query lease建议60秒可续期，超期释放缓存／句柄，旧cursor回staleCursor，不改变事实。

纯只读项目不写lease／cache；若已有维护锁可只读共享打开，否则依靠持有段句柄的禁止删除共享语义保护当前快照，不能保证外部工具删除尚未打开文件；需要一致全集时先显式复制至本机资料位置。GC检查所有产品读者，外部拷贝／强删边界明确，不承诺任意工具间事务。

历史query只读checkpoint发布前缀，不猜writer的当前file size；进程内活尾部另标volatile，不给跨端读者伪造accepted水位。writer/index/query/bulk独立执行且队列有界；hash/压缩/JSON/flush不进ETW回调／Hook／控制锁／GUI。取消仅请求，必须消费I/O完成后释放缓冲。

## 8. 索引和SQLite缓存

**必须实现**基本块目录与有界scanner：eventId→段／块／record、段时间／seq范围、source/object/type、behavior→全部依据分页、图邻接、evidence定位。无索引字段可异步扫描；索引落后只声明到indexedThrough，查询可显式完整扫描，不能空表冒充查无数据。

SQLite每sample独立cache，仅系统DLL／所需导出／版本探测成功才启用；三端各自adapter，不共享数据库句柄。默认不把SQLite作为项目必须feature，丢cache随时按归档重建，原证据不变。cache中的schema／SQL不接受外部项目提供，附带数据库不信任，导入默认重建。

| 表 | 建议列／索引 |
| --- | --- |
| meta | indexSchema/archiveFormat/sampleId/sourceFingerprint/indexedPrefixes |
| blocks | stream/segment/block/offset/size/firstSeq/lastSeq/minTime/maxTime |
| events | eventOrdinal/source/epoch/sequence/time/actor/target/thread/kind/category/phase/availability/rawLocator/canonicalLocator |
| objects/edges | object kind／identity strength／record locator；from/to/kind/certainty分别索引 |
| behavior_evidence | analysisRun/behaviorId/ordinal/eventId，支持完整依据分页 |
| evidence/blobs | ID／hash／size／manifest locator／availability |

u64／地址不cast到SQLite有符号INTEGER；统一8字节大端BLOB存储以保持无损排序，或对本地有界小量明确INT64限制；本设计选择前者，跨SQL绑定不转double。NULL加quality区分未知／已知0。大raw／blob／长文本不复制入每行。SQL仅程序生成、参数绑定，禁止用户SQL、ATTACH、扩展加载和shared-cache；FTS5/JSON1不必需。

一个index worker持writer，每query worker独立reader，短读事务每页结束释放。建议WAL＋synchronous=NORMAL（仅可重建cache）、mmap=0、busy_timeout100ms、page cache16 MiB、事务4096行或4 MiB；设置后必须读回实际journal_mode等再公告。WAL达到64 MiB尝试checkpoint，不能推进则暂停索引／报lagging，不阻塞raw归档或控制恢复。cache总上限取sample软配额10%与1 GiB较小者，含WAL/临时文件；达到停止索引或显式清理重建。

默认分页500/max2000，输出帧256 KiB硬限，内部块与catalog页大小不改变公共分页。cursor绑定sample/queryHash/checkpoint/indexGeneration／最后排序键，采用筛选契约的本控制器有时限不透明游标；索引重建／范围改变／控制器重启后旧cursor报staleCursor。初始排序／聚合／未知值及query→follow交接遵从筛选契约，任意regex搜索不承诺B-tree加速。

## 9. 传输容器`.ksapack` v1

容器只搬运一个project的明确快照，不执行包中任何东西。默认导出封存sample；活sample导出固定checkpoint，manifest标snapshotExport/partial，导出不停止真实目标。锁、staging、cache、运行秘密、当前可消费控制令牌不入包；历史ControlFact只保留审计字段。

设计为**固定头→顺序entry→终端manifest entry→固定footer**，所有内容Stored；无需中央目录可开始写，只有footer校验及manifest闭合后才是完整包。大文件长度／偏移u64，先流式写到目标同目录`.partial`，完成校验后发布，不覆盖旧完整包。

### 9.1 容器头96字节

偏移0 magic[8]=`KSAAPAK`＋NUL；8/10为major/minor u16；12 headerBytes u32=96；16 flags u32=0；20 reserved u32=0；24 packageUUID[16]；40 projectUUID[16]；56 snapshotUUID[16]；72 createdUtc100ns u64；80 reserved[12]=0；92 headerCRC32C覆盖0..91。

### 9.2 entry头64字节与内容

偏移0 magic[4]=`AAE1`；4 headerBytes u16=64；6 entryVersion u16=1；8 kind u16（1文件、2终端manifest）；10 flags u16=0；12 pathBytes u32；16 dataBytes u64；24 contentSha256[32]；56 pathCRC32C u32；60 headerCRC32C覆盖0..59。随后pathBytes个无NUL的UTF-8相对路径，再dataBytes个原始文件字节，无padding。

输出前冻结源文件快照和预计算hash／长度，传输中再次增量核验；长度或hash变化则导出失败，不发完整footer。终端manifest路径固定`_package/manifest.json`、kind2且最后一个entry；它不列自身hash，footer给manifest hash。保留`_package`名称空间不允许项目普通文件占用。

为避免大项目突破4 MiB文档限，文件清单按最多1024项／每页最多1 MiB生成`_package/lists/<20位页号>.json`，条目含kind1相对路径／长度／hash，按规范UTF-8路径字节排序。清单页自身为普通kind1 entry，不在其自身清单中递归列举；终端manifest单列这些页的路径／长度／hash，以及project/sample快照根、快照水位、requiredFeatures、缺失／外部引用及是否自包含。所有实际kind1必须与清单页或manifest登记一一相符，不接受未列文件／重复条目。各层目录清单分页，根仍遵守4 MiB，超出时明确要求分批导出，不能任意抬高parser限额。

kind1 entries按规范路径字节排序，终端manifest固定最后；页文件也参与kind1排序。活sample不将正在增长的segment直接装包：只导出固定checkpoint的完整块前缀，使用导出副本的长度／hash和snapshot描述，保留原project/sample身份及父checkpoint引用，明确snapshotExport／partial，不伪造原作者sealed。所有依赖blob、字典与raw前缀先冻结，缺失则按显式partial策略或拒绝导出。

### 9.3 footer96字节

偏移0 magic[8]=`KSAAEND`＋NUL；8/10 major/minor u16；12 footerBytes u32=96；16 manifestEntryOffset u64；24 manifestDataBytes u64；32 fileEntryCount u64（不含manifest）；40 manifestSha256[32]；72 totalPackageBytes u64（含footer）；80 reserved[12]=0；92 footerCRC32C覆盖0..91。footer后不得有额外字节。

导入先读固定header/footer与有限manifest，再核总长度／条目／配额，逐entry流式写隔离staging并验证hash，最后校验引用及project目录后发布。路径不得依包自行决定绝对落点；只接固定布局白名单。manifest缺失／重复／排序不符／CRC/hash/长度错误或截尾即拒绝完整导入，可只读诊断损坏包，不能当项目写打开。

不支持entry级压缩、软链接／硬链接、权限／可执行位、脚本钩子、加密或可选附加尾数据；均非“解不开就跳过”。chunk文件已有zstd不会被包重新解压。未来通用ZIP/加密适配必须独立版本／feature和测试，不把v1隐式扩成通用解包器。

## 10. 导入、外部资料与路径安全

所有项目标题、原始文件路径、注册表名等只作文本。内部路径从合法ID／hash／固定布局生成；拒绝绝对、盘符、UNC/设备、`.`/`..`、ADS冒号、NUL、尾点／空格、DOS保留名、重复路径、大小写／Unicode等价冲突。拒reparse/junction/软硬链接与源目录逃逸；逐组件及打开后句柄核root／身份，字符串前缀不足。

目录导入默认复制／验证至新目标，不沿外部引用递归复制任意用户文件；外部证据标external/missing，生成自包含包前须显式解决。哈希校验与使用同一持有文件对象，避免“按路径验A后读B”的替换窗口；不能保证被分析目标不篡改其R3报告。

导入默认物理总限10 GiB、条目100000、单文档4 MiB、单段／blob按其格式限制，超限可在显式预算编辑后重试，程序不自动抬限。标准大dump仍使用kind1文件entry，在证据manifest中标格式／允许长度并流式处理，不另造未定义的entry kind。校验声明大小后运行时再次计数，不能只信header。已提交项目ID与现有路径冲突时新副本或只读打开，不覆盖另一项目；同UUID不同hash报告分叉。

项目默认本机离线读取，文件／内存／脚本预览转义、分页；不自动在线符号下载、联网富化或执行rule。在活sample明确启用的后台分析按其已冻结计划运行，历史打开不触发任何副作用。

## 11. 保留、删除、空间与敏感资料

默认不自动删旧sample、不按天滚动清理证据；10 GiB/sample软配额、100 GiB/project软配额、可用空间低于max(1 GiB,卷2%)告警／停止新采集建议统一采用总表初值，用户可修改并写实际配置。预算含raw/records/control/analysis/blob/cache/WAL/staging/trash/包partial，逻辑未压缩量与物理量分开显示。建立新sample前估算可用空间仍不保证后续写成功。

满盘先停止索引／可选bulk，必需归档仍失败则ArchiveDegraded、停止新准入／新采集，尽可能记录最终gap/状态；不得自动转仅内存或删旧sample维持运行。已有用户hold不自动放行，真实恢复不以写盘成功为条件。控制历史镜像满停止新武装，原生恢复槽永不被证据cache借用。

可预留8 MiB应急文件以提高终态记录成功机会，必须计入预算；释放预留也不保证设备仍可用。短写／断盘／quota/flush／共享错误保留原码和最早失败水位，写不了最终记录时重开以缺seal/checkpoint识别interrupted，不假报成功。

删除sample是独立显式动作，清空显示／取消追踪不删资料。活sample、有真实未决责任或query/export/investigation lease不得物理删除；先journal墓碑提交、再移同卷trash、最后显式清理。GC按所有已提交引用标记同sample blob，无引用／无lease且达到用户选定保留条件才删；首版不为局部删事件重写不可变段。staging中未知恢复资料不当cache盲删。

完整证据默认保持原字段，可包含命令行、内存、路径／用户资料；不自动上传。脱敏为显式派生导出，带父hash、去除字段／规则／版本和不可复算说明，原资料不变。首版不自造加密容器，使用用户选择目录及系统现有访问权限；移动／共享包前明确它含原始证据，归档hash不是保密。新UI偏好／诊断日志不默认复制敏感正文。

## 12. 实施包与验收

按本端职责建立ProjectDocument/SampleCatalog、SegmentWriter/Reader、CheckpointWriter、BlobStore、ArchiveQuery/IndexAdapter、PackageWriter/Reader及RecoveryScanner等模块，只在真实需要时拆普通.cpp/.h，不建空基类／公共runtime。已有纯工具可复用，Light工程／CRT缺口逐项登记；新源码／许可同步工程和发行清单。

A0先固定schema、字节布局、CRC/hash／UUID／u64／UTF黄金文件与格式catalog；A1从Stored读写及目录／断电前缀开始，再接cache／codec／容器。后续必须验证：

1. 三端同黄金文件互读、u64最大值／known0/null/缺值、UTF错误／重复键／前导零、未知required feature与codec、头长／offset／解压上限。
2. 每个header/payload/flush/checkpoint/journal/manifest边界失败／杀writer，短写、损坏、断盘、满盘、依赖缺失；进程强杀与真正断电各自报告。
3. raw一对多规范化、水位holes、索引超前／落后／损坏／重建，固定snapshot翻页、跨进程只读、GC和读者登记竞态。
4. 两sample／配置草稿实际修订／断点ASLR重绑，历史加载不调用驱动／Agent，不沿旧stop/session继续。
5. `.ksapack`超过4 GiB、大条目／坏尾／重复与路径逃逸／hash不符／配额／取消／源变化，partial包不覆盖原包；无外部7z／shell依赖。
6. zstd按端CRT、Stored回退与真实codec能力；系统SQLite缺导出／不可用／WAL设置失败、reader阻checkpoint和cache达到限额，均不改变raw事实或恢复责任。
7. 持续洪峰＋query/index/export并行的唯一分配、CPU/RSS、队列age、flush吞吐和真实控制延迟；构建成功不能代替这些测量。

本轮只完成源码审阅和规划；独立报告见 `.codex-build-logs/behavior-planning/action-analyze-preflight-storage.md`。原始机制测试不作为本格式／数据库／打包／崩溃恢复已通过的证据；R0构建／加载／运行继续等待用户环境。

下一层见[施工任务A0.3／A1.1–A1.3](ActionAnalyze施工任务与契约落点.md)，将项目／分段／水位／恢复／查询／搬运／留存分别落实到owner、文件和故障判据。[环境实验](ActionAnalyze反反虚拟机与环境实验行动方案.md)的原始观察、干预attempt、目标所见与冻结profile作为不同记录保存；不改主机真实基线或原事件，禁用实验也不删除历史资料。
