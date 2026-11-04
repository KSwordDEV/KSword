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
KswordCLI.exe service config set --name NAME [--service-type N] [--start-type N] [--error-control N] [--binary-path PATH] [--load-order-group GROUP] [--dependencies LIST] [--clear-dependencies 1] [--account NAME] [--password-file PATH] [--display-name NAME] [--description TEXT] [--clear-description 1] [--delayed-auto 0|1] --confirm [--backend r3] [--json]
KswordCLI.exe service recovery set --name NAME [--reset-seconds N] [--actions LIST] [--clear-actions 1] [--command TEXT] [--clear-command 1] [--reboot-message TEXT] [--clear-reboot-message 1] [--non-crash 0|1] --confirm [--backend r3] [--json]
KswordCLI.exe service delete --name NAME [--delete-file 0|1] [--expected-file PATH] --confirm [--backend r3] [--json]
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
启动类型修改不自动启动服务。

`service config set` 只修改给定字段；服务类型、启动类型和错误控制使用 SCM 原始数值，依赖项用分号分隔，可用 `--clear-dependencies 1`、`--clear-description 1` 清除。账户密码从 UTF-8 文件读取，不在结果中输出；SCM 不提供密码回读，含密码的变更返回 6。配置、描述、延迟启动为独立写入，结果分别报告；中途失败不会自动回滚，最终配置会重新读取并比较。

`service recovery set` 先读取完整的现有恢复配置，未指定字段沿用原值；`--actions` 为逗号分隔的 `none:毫秒`、`restart:毫秒`、`reboot:毫秒`、`run:毫秒`，`--clear-actions 1`、`--clear-command 1`、`--clear-reboot-message 1` 清除对应值。清空全部动作后 SCM 可能将重置周期归零，显式指定的重置周期仍须回读匹配。恢复动作与非崩溃标志属于两次 SCM 写入，失败可能已经部分生效，回执与最终回读不会将其报告为完整成功。

`service delete` 默认仅删除服务注册。`--delete-file 1` 还要求 `--expected-file` 指定预期的绝对文件路径：先查询 SCM 与服务注册表中的其他引用，再停止服务、重新核对配置和引用，最后通过已打开并验证身份的文件句柄设置删除；共享引用或读取失败则拒绝组合删除。SCM 明确报告服务不存在时，可删除重新核实仍存在的注册表残留服务键；不可查询或访问拒绝不等同不存在。结果分别报告来源和服务注册、文件删除是否被接受，SCM 或文件可能在其他句柄关闭后才真正消失。检查和系统配置更新之间仍有并发窗口；整个过程没有自动回滚。

测试夹具是独立 Win32 服务，支持暂停／继续／停止。仅在虚拟机中创建并修改该服务；
通过 Get-Service、SCM 配置及注册表回读核对状态，最后删除夹具服务。
