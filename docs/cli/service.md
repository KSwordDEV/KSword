# 服务 R3 命令（迁移项 07）

```powershell
KswordCLI.exe service enum [--name NAME] [--limit N] [--backend r3] [--json]
KswordCLI.exe service query --name NAME [--backend r3] [--json]
KswordCLI.exe service detail query --name NAME [--backend r3] [--json]
KswordCLI.exe service start --name NAME [--backend r3] [--json]
KswordCLI.exe service stop --name NAME --confirm [--backend r3] [--json]
KswordCLI.exe service pause --name NAME [--backend r3] [--json]
KswordCLI.exe service continue --name NAME [--backend r3] [--json]
KswordCLI.exe service set-start-type --name NAME --type automatic|delayed|manual|disabled --confirm [--backend r3] [--json]
```

`help service` 仅列直属操作，`help service detail` 展示详情子命令，具体叶子 help 解释参数和结果。
name 是 SCM 短名称；枚举筛选采用不区分大小写的精确匹配，显示 limit 默认为 100，0 仅返回统计。
纯 R3，不需要 KswordARK；SCM 权限按实际操作检查，失败保留原始 win32Error。

枚举同时包含 Win32 服务和驱动服务。每项输出名称、显示名、描述、状态、PID、服务类型、启动类型、
二进制命令行、映像路径候选、账户、依赖服务／组、延迟自动启动、服务退出码及诊断。
hasStatus/hasConfig 描述可用性，未知字段为 null。枚举保留无法读取配置的行并返回部分完成 6。
有效空结果为成功，单项不存在／无法查询返回 3。

详情还包含恢复策略（原始动作类型、延迟、重置周期、命令、重启消息、非崩溃触发标志）和直接反向依赖。
两部分独立输出 availability、win32Error 和诊断；部分／不支持的可选信息不隐藏基础服务信息，并返回 6。
不推导传递依赖，也不把不可读的配置项当成 false。

控制操作复用共享后端的 30 秒有界等待，操作后再次通过 SCM 查询。
结果包含 operation、requestSucceeded、win32Error、verified、postcheckWin32Error 与 postcheck。
成功并确认状态返回 0；操作失败返回 3，不支持返回 5；部分配置已生效或回读未确认返回 6。
automatic 会清除延迟标志，delayed 会设置；manual/disabled 不修改与其无关的延迟配置。
启动类型修改不自动启动服务。仅提供后端已实现的动作，未新增服务创建、删除或恢复策略编辑命令。

测试夹具是独立 Win32 服务，支持暂停／继续／停止。仅在虚拟机中创建并修改该服务；
通过 Get-Service、SCM 配置及注册表回读核对状态，最后删除夹具服务。
