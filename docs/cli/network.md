# 网络 R3 命令

## Windows 防火墙规则详情与管理

```powershell
KswordCLI.exe network firewall rule query --name NAME [--fingerprint SHA256] [--json]
KswordCLI.exe network firewall rule create --name NAME --direction in|out --action allow|block --protocol any|tcp|udp|N --profiles all|MASK --enabled on|off [规则字段] --confirm [--json]
KswordCLI.exe network firewall rule update --name NAME --fingerprint SHA256 [--new-name NAME] [规则字段] --confirm [--json]
KswordCLI.exe network firewall rule enable|disable|delete --name NAME --fingerprint SHA256 --confirm [--json]
```

规则字段为 `--description`、`--grouping`、`--application`、`--service`、`--local-ports`、`--remote-ports`、`--local-addresses`、`--remote-addresses`、`--interface-types`、`--icmp-types`、`--direction`、`--action`、`--protocol`、`--profiles`、`--enabled` 和 `--edge-traversal`。profiles 的域/专用/公用位分别为 1/2/4，也接受 `all`。空文本用于清空指定的字符串字段；端口和 ICMP 字段由 Windows 按协议校验。

查询使用 R3 Windows Firewall COM，返回共同枚举字段、字段可用位和每个同名候选的 SHA-256 快照指纹；`--fingerprint` 可进一步选出其中一项，具有相同完整字段的重复项仍视为歧义。修改前须提供指纹并重新枚举匹配，成功后再次查询核验；同名规则可用指纹选择来更新。Windows 删除 API 以名称操作，因此同名规则不能通过本命令删除。创建要求名称当前不存在；每次写入均要求 `--confirm`。查询/写入保留 HRESULT、前后快照、是否尝试和是否确认等字段；规则属性逐个调用系统 setter，失败可能已经修改部分字段，并非事务或自动回滚。重枚举和写入之间仍存在并发变化窗口。

`tools/test_ksword_cli_r3_firewall_actions.py` 使用模拟数据核对重复名称、过期指纹、缺失确认与回执；`tools/Test-KSwordCliFirewallCanary.ps1 -Cli PATH` 可在隔离测试环境创建唯一名称的临时规则，验证创建、详情、修改、启停和清理。

使用 `help network` 查看直属命令，`help network connections` 查看连接操作，
`help network connections close` 查看精确语法。网络诊断命令默认为 R3；文末托管策略命令分别支持 R3 Windows 防火墙和 R0 驱动后端，具体能力和参数见各命令帮助。

## TCP/UDP 连接（迁移项 01）

```powershell
KswordCLI.exe network connections enum [--pid PID] [--protocol all|tcp4|tcp6|udp4|udp6] [--offset N] [--limit N] [--backend r3] [--json]
KswordCLI.exe network connections close --pid PID --local-address IP --local-port N --remote-address IP --remote-port N --confirm [--backend r3] [--json]
```

枚举通过 IP Helper 读取四种端点表。默认协议 `all`，显示上限 100；`--limit 0`
只显示统计，不影响采集。每行包含协议、PID、进程名、本地／远程地址和端口、
原始 TCP 状态编号与 `canClose`。UDP 的状态为 `null`，远端地址为空、端口为 0。
`--offset` 默认 0，在筛选后跳过指定行；有后续行时输出 `nextOffset`，可用于下一次查询。每次执行均为独立系统快照，连接增删或顺序变化可能导致跨页重复或遗漏。JSON data 包含 `matchedCount`、`returnedCount`、`offset`、`nextOffset`、`truncated`、`entries`。
表读取失败时保留已采集的数据并返回部分完成 6；全部失败返回 3。

关闭要求管理员权限，仅支持 IPv4 TCP 的活动 TCB，不支持监听端点、IPv6 或 UDP。
参数指定的是枚举输出中的 PID 和完整地址／端口元组；执行前重新枚举并匹配所有者，
使用后端保存的原始网络字节序元组调用 SetTcpEntry。成功后重新枚举：连接消失返回 0，
回读不完整或仍存在返回 6。目标已消失返回 3，监听等不支持状态返回 5。
JSON data 包含目标、`requestSucceeded`、`postcheckPresent`、`postcheckComplete`；
系统调用失败时也重新枚举，保留 `win32Error`、`requestSucceeded=false` 与回读结果；
回读不完整时 `postcheckPresent=null`。错误 317 本身不能证明目标已经消失，
失败后独立消失也不会把系统调用失败提升为成功。目标的消失不能证明应用程序不会建立新的连接。

自动测试使用本机回环 TCP／UDP 夹具，与独立 Get-NetTCPConnection 结果核对；
关闭后通过对端 socket 验证实际断开，不以退出码作为唯一证据。默认测试要求成功关闭；
宿主机复查可显式指定 `Test-KSwordCliR3Connections.ps1 -AllowNativeCloseFailure`，
仅当 CLI 返回 317、独立 SetTcpEntry 同样返回 317 且连接保持 Established 时验收失败语义，
报告中的 `closeSuccessMeasured=false` 明确表示没有取得关闭成功实测。

## Ping（迁移项 02）

```powershell
KswordCLI.exe network ping query --target HOST [--count N] [--timeout-ms N] [--backend r3] [--json]
```

仅探测 IPv4，默认 4 次、每次超时 2000ms。count 范围 1–32，timeout-ms 范围 1–60000。
输出解析后的地址、发送／接收数、丢包百分比和逐次 ICMP 回执（原始状态、耗时、TTL、数据长度）。
全部回应返回 0，部分回应返回 6，没有成功回应或解析失败返回 3。未收到回执时耗时和 TTL 为 null。
地址解析或 ICMP 句柄创建错误保留 win32Error；每个探针独立保留系统／IP 状态。
不会自动改用 IPv6，也不需要 KswordARK 驱动。

## 路由跟踪（迁移项 03）

```powershell
KswordCLI.exe network trace-route query --target HOST [--max-hops N] [--timeout-ms N] [--backend r3] [--json]
```

IPv4 ICMP 跟踪，每跳一次探针。max-hops 默认 30、范围 1–64，timeout-ms 默认 2000、范围 1–60000。
输出 resolvedAddress、reached、attemptedHops、win32Error 和 hops；每跳保留地址、原始 IP 状态、是否回应、
往返毫秒数与回复 TTL。超时跳保留原始状态，耗时为 null。
到达目标返回 0；获得部分跃点但未到达目标返回 6；解析失败或没有任何跃点回应返回 3。
不把 TTL 过期当成到达目标，也不自动切换到 IPv6。无需驱动。

## DNS（迁移项 04）

```powershell
KswordCLI.exe network dns query --name NAME [--type A|AAAA|NS|CNAME|SOA|PTR|MX|TXT|SRV|ANY] [--backend r3] [--json]
```

默认 A，通过 Windows DNS resolver 查询，保留系统缓存／hosts／DNS 配置的语义。
输出 name、type、win32Error 和 records。记录含名称、原始类型编号、TTL、数据长度、decoded、fields 和可读 value。
fields 按记录类型提供 address、host、exchange/preference、target/port/priority/weight、
SOA 的服务器与各计数、TXT segments；未解码类型仍保留名称／类型／长度，并标明 decoded=false。
DNS 系统调用成功（包括有效空结果）返回 0；系统／DNS 错误返回 3，win32Error 保留原始 DNS_STATUS。
仅暴露已实现的记录类型选择，不添加自定义服务器、重试或超时参数；时限由系统 resolver 管理。无需驱动。

## 防火墙（迁移项 05）

```powershell
KswordCLI.exe network firewall enum [--name NAME] [--limit N] [--backend r3] [--json]
```

通过 INetFwPolicy2 只读枚举 Windows Firewall 配置，不发布后端尚未实现的规则编辑命令。
name 精确匹配区分大小写的显示名称；limit 默认 100，0 只输出统计。
数据包括三个配置文件的启用状态、profileSummary、hresult、complete、匹配／显示数量、truncated 和 rules。
每条规则输出名称、描述、分组、应用／服务、地址／端口、接口、原始方向／动作／协议／配置文件编号、启用和边缘穿越状态。
属性读取失败时对应字段为 null，避免把未知状态显示为关闭／禁止；complete 指规则集合枚举是否完整。
全部枚举与配置文件查询完成返回 0；部分结果返回 6；COM／防火墙服务调用失败返回 3，并保留 HRESULT。
COM 初始化与释放由后端在同一调用线程完成，不需要 KswordARK 驱动。

## AFD/NSI 公开投影（迁移项 06）

```powershell
KswordCLI.exe network endpoint-audit afd query [--limit N] [--backend r3] [--json]
KswordCLI.exe network endpoint-audit nsi query [--limit N] [--backend r3] [--json]
```

这是 R3 documented IP Helper 投影，source 明确标注没有查询 AFD／NSI 私有对象。
AFD 提供 IPv4 TCP/UDP 所有者元组、状态和表总数；NSI 提供接口原始索引、类型、MTU、速度、名称及 IPv4 地址／路由总数。
接口字段来自旧 GetIfTable/MIB_IFROW，包含未绑定接口；例如回环的兼容 MTU 不等同于现代 IP 接口视图的 NlMtu。
rows 每行保留 available、evidence、win32Error、truncated、结构化 fields 和原后端解释 cells。
边界说明行的 evidence 为 false，不参与成功判定；不通过解析说明文字推导状态。

后端原有采集上限为每种 IPv4 端点表 128 行、接口表 64 行。backendTruncated 标明达到这些上限；
显示 limit 默认 100、0 仅显示统计，displayTruncated 单独说明显示截断。
采集完整返回 0，部分证据或后端截断返回 6，证据全部不可用返回 5。不会执行断连、修改接口或路由。
既有 `network afd` 与 `network nsi` 的默认输出保持兼容；新增路径提供统一 JSON 和共享 Light 后端。

## R0 托管网络策略查询

```powershell
KswordCLI.exe network managed-policies [--limit N]
```

通过既有 CLI 中央驱动传输读取 `IOCTL_KSWORD_ARK_NETWORK_QUERY_MANAGED_POLICIES`，仅需读访问。
查询的是独立托管表，不合并旧端口规则或 Windows Firewall 规则，也不创建、启停、删除阻断策略。
驱动按需准备空的 WFP 管理会话；该准备不添加阻断规则。

先完整校验固定响应长度、版本、数量、能力位、策略唯一 ID、PID/创建时间关系、方向、保留字段及所有地址前缀，再输出任何策略。
默认显示最多 16 条，`--limit 0` 仅输出摘要，但仍校验全部返回条目。
摘要包含协议/原始状态、Win32 返回字节数、策略数、显示数、代数和能力位。
能力位分别为 IPv4 `0x1`、IPv6 `0x2`、CIDR `0x4`、进程实例身份保护 `0x8`。
策略行包含 GUID、PID、创建时间、方向、配置启用状态、进程退出状态及 IPv4/IPv6 CIDR。
`configuredEnabled` 表示规则配置，是否具备实际执行能力还须同时检查摘要中的 WFP 状态及 capabilities。

查询成功返回 0；驱动或 WFP 不可用返回 3/5；响应结构或字段无效返回 4。
通用驱动功能矩阵仅执行此查询，托管控制 IOCTL 始终排除，避免改变宿主网络策略。
## 托管网络策略和 QoS

```text
KswordCLI.exe network policy enum [--backend r3|r0] [--json]
KswordCLI.exe network policy query --id ID [--backend r3|r0] [--json]
KswordCLI.exe network policy create --scope image|process|all [--path PATH] [--pid PID] [--creation-time FILETIME] [--remote PREFIXES] [--direction in|out|both] --confirm [--backend r3|r0] [--json]
KswordCLI.exe network policy enable|disable|remove --id ID --confirm [--backend r3|r0] [--json]
KswordCLI.exe network qos enum [--json]
KswordCLI.exe network qos query --id ID [--json]
KswordCLI.exe network qos save --scope image|all [--path PATH] [--id ID] [--rate BYTES_PER_SEC] [--dscp N] [--priority N] [--protocol any|tcp|udp|tcp-udp] [--source-prefix PREFIX] [--destination-prefix PREFIX] [--source-port-start N] [--source-port-end N] [--destination-port-start N] [--destination-port-end N] [--precedence N] [--enabled on|off] --confirm [--json]
KswordCLI.exe network qos enable|disable|remove --id ID --confirm [--json]
```

`network policy` 默认 `--backend r3`：管理 KSword 拥有的 Windows 防火墙规则，支持映像路径或指定远端地址的全局范围；映像规则作用于该映像的所有实例。`--backend r0` 操作驱动托管策略，支持进程实例或指定远端地址的全局范围；进程实例必须同时提供 PID 和创建时间。两种策略使用各自的身份和能力，不自动切换。`--remote` 用分号分隔数字 IPv4/IPv6 地址或 CIDR；全局范围必须明确指定远端地址。R3 映像范围可选地提供 PID 与创建时间，让后端在创建时复核路径和进程身份。成功后查询同源策略并回读；请求成功但回读不可用或不匹配返回 6。失败可能留下部分效果，应根据返回的策略 ID 与回执复查。

`network qos` 使用 Windows Policy QoS，覆盖 ActiveStore 和 KSword 保存的禁用定义；只对拥有的策略执行修改。QoS 只支持映像或全局范围的**出站**匹配，不支持进程实例或入站限速；ActiveStore 在重启后失效。`--rate` 单位是字节/秒，DSCP 为 0..63、802.1p priority 为 0..7；保存需要至少一个动作。更新时应提供全部期望字段。读取结果直接包含策略的速率、匹配条件、启用状态及归属，不另建重复详情数据。操作回读确认身份存在性和启用状态；实际接受的参数及限制由共享 QoS 后端验证。以上操作都不自动提升权限。
