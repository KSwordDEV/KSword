# 文件元数据 R3 命令

`file metadata query --path PATH --json` 返回叶节点本身的卷序列号、文件 ID、属性及创建、访问、写入和变更时间；时间是 UTC FILETIME 的 100ns 计数。`file metadata set --path PATH --volume-serial N --file-id N [--creation-time N] [--access-time N] [--write-time N] [--change-time N] [--attributes MASK] --confirm --json` 使用前次查询的身份，重新打开 `FILE_FLAG_OPEN_REPARSE_POINT` 句柄核对，修改选中字段并以同句柄回读。属性掩码表示六个可编辑位的最终状态：READONLY、HIDDEN、SYSTEM、ARCHIVE、TEMPORARY、NOT_CONTENT_INDEXED；目录、重解析点、压缩等结构位保持原样。不同文件系统可能舍入时间：写入成功但回读不一致时返回 6。

`file metadata streams list --path PATH` 列出数据流及大小；`streams read --path PATH --name NAME [--max-bytes N]` 返回命名流十六进制前缀；`streams write --path PATH --name NAME --volume-serial N --file-id N (--hex HEX | --data-file PATH) --confirm` 和 `streams delete` 写入或移除命名流并回读。NAME 是不含冒号与 `$DATA` 的名称；不允许修改默认流。流枚举与新流创建使用路径，身份检查与路径重绑定并非原子；目标叶节点为重解析点时明确拒绝。新流创建后若发现身份不符，报告部分效果，不推断自动回滚。

`file metadata ea list --path PATH` 列出扩展属性的 UTF-8 名称、NEED_EA 标志与原始值；`ea set --path PATH --name NAME --volume-serial N --file-id N (--hex HEX | --data-file PATH) [--need-ea 0|1] --confirm` 和 `ea delete ... --confirm` 使用同一已校验文件句柄写入并查询回执。值最多 65535 字节；零长度表示删除，因此 set 明确拒绝空值。非 UTF-8 属性名不被静默转换。EA 查询上限为 1 MiB，不支持该能力的文件系统保留系统错误。

`file metadata security query --path PATH [--parts owner,group,dacl,sacl]` 返回选定部分的 SDDL；默认读取 owner、group、dacl。`security set --path PATH --volume-serial N --file-id N --sddl SDDL [--parts LIST] --confirm` 在同一句柄校验身份并更新所选部分，读回比较 SID、ACL 和保护状态。SACL 需要相应权限；系统重新规范化后若无法确认一致，返回 6 并保留实际结果。

`file metadata shell query --path PATH` 查询 title、subject、authors、keywords、comment、copyright 和 rating 等 Shell PropertyStore 字段，逐项返回 available、empty 和 HRESULT。`shell set --path PATH --volume-serial N --file-id N --name NAME --value TEXT --backup PATH --confirm` 更新一个字段；authors 和 keywords 用分号分隔，rating 为 0..99。属性处理程序按文件类型不同，有的字段可能不可写。

`file metadata resource query --path PATH --type TYPE --name NAME [--language N] [--max-bytes N]` 以数据文件方式读取 PE 资源；TYPE 和 NAME 可为名称或 `#整数`。`resource set --path PATH --volume-serial N --file-id N --type TYPE --name NAME (--hex HEX | --data-file PATH) --backup PATH [--language N] --confirm` 与 `resource delete ...` 调用 Windows 资源更新接口，写入后重新读取。资源变更可能使原有签名失效。

Shell 和 PE 资源写入要求提供**尚不存在的备份路径**，先复制原始文件并复核来源身份；提交失败后仅在目标文件身份仍匹配时尝试从备份恢复文件内容，回执给出 backupCreated、rollbackAttempted、rollbackVerified 及其错误。Windows 属性／资源接口按路径操作，不能保证与其他进程的路径替换原子；资源更新本身也可能替换文件身份，因此操作写入后即使内容读取正确，只要新身份不等于预期就返回 6，并提供 afterVolumeSerial/afterFileId。备份恢复不承诺还原 ACL 或命名流。

以上均为 R3 操作，不自动回退或调用驱动。基础信息、命名流、EA 和安全描述符是单项修改，不自动创建 GUI 的多目标事务备份或回滚；每项提供 attempted/written/verified 与系统错误，写成功但验证不全返回 6。R0 的文件查询和删除使用各自现有命令，不以此命令冒充。
