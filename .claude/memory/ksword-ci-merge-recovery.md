---
name: ksword-ci-merge-recovery
description: KSword 合并后 CI 回归的定位与修复边界
metadata:
  type: project
---

# CI 合并回归恢复

- 调试器后端隔离测试在 `DebuggerBackend/tests/BackendTests.cpp` 内手写 `DriverClient` 桩，不链接真实 `ArkDriverClient.cpp`。生产后端改用 `openSilently()` 后，测试桩也必须提供相同签名；否则 x96dbg CI 在 `BackendTests` 链接时出现 LNK2019。静默入口复用测试事件句柄实现，不能为补符号引入真实设备访问；须继续执行后续完整契约测试，不能仅凭源码门禁通过判定整条 CI 成功。
- `validate_kernel_knowledge.py` 的站内路由边界必须按 `openKnowledgeRoute` 自身花括号提取，复用现有源码门禁的注释/字面量感知 helper；不能用下一函数的固定返回类型作结束哨兵。`ensureTabInitialized` 改为 `bool` 后，旧 `void ...` 哨兵会把真实存在的路由误报为缺失。回归入口 `python tools/test_validate_kernel_knowledge.py` 与完整验证在 CI 同一步运行；缺失/额外/重复路由仍必须拒绝。
- 先看最新提交对应的 `Source integrity`、用户态构建和 `Driver CI` 日志；`git diff --check` 失败会跳过后续 JSON、i18n 与 IOCTL 审计，修完空白后必须单独补跑这些检查。
- 跟踪 JSON 路径用 `git ls-files -z` 的原始字节按 NUL 分隔，再用 `utf-8-sig` 严格读取内容。逐行解析默认 Git 输出会把中文路径的 C 风格引号/八进制转义当成文件名，导致文件打开失败；不能靠跳过这些 JSON 或全局改 `core.quotePath` 绕过检查。
- 共享启动项后端拆出 `StartupHidden.cpp`、`StartupText.cpp` 后，CLI、Light 和 `KswordARKLightTests` 都须登记实现及对应 filters/内部头。生产工程能链接不代表测试工程完整；测试仅保留 `StartupEnumerator.cpp` 会缺失隐藏项枚举及 UTF-8/UTF-16、Trim 辅助符号。
- 手工发行的 PDB/Symbols 附件可能拥有比完整包更大的 asset id。模板选择函数先排除符号包后缀，再选最新应用包，保留 `Release/` 根目录和后续完整性校验；awk 须消费全部输入，避免 `pipefail` 下的 SIGPIPE。离线回归执行生产函数原文，覆盖同发行资源排序、大小写、中文名称和大候选列表。
- Actions 的同分支并发取消只适合 PR 更新；`main` push 必须排队完成。否则后续仅改 `.gitignore` 等不命中项目的提交会取消前一条正在构建的有效代码提交，自己又把全部构建标为 skipped，导致最新 `main` 虽显示 workflow success 却没有任何完整 Release 证明。
- 变更范围检测只能在同工作流、同分支的上一条运行明确为 `completed/success` 时启用；上一条失败、取消、超时、仍未完成、查不到或 Actions API 查询失败时都要 fail-safe 为全量测试，避免把上一提交未取得的验证错误地交给路径过滤跳过。
- 自动 CI 预发行版只在 `main` push 的用户态 CI 与同 SHA Driver CI 都成功后创建。发布资产同时提供：一个与手工版一致、顶层为 `Release/` 的聚合 7z，以及主程序、Setup、ARKLight、CE x64、CE Launcher、Driver 各模块的原始 artifact ZIP。聚合 7z 以最新非自动手工 7z 提供 Qt、有效 v4 profiles 与静态资源，再覆盖当前/祖先提交的 CI 二进制并内置来源清单。自动版同时使用 `[CI Build] ` 标题和 `ci-build-` tag 双标记，清理时只匹配两者并保留最新 3 个，不能触碰手工预发行版与正式版。发行说明的风险提示使用 `[!CAUTION]`，聚合 7z 与 Setup ZIP 提供可点击下载按钮，其余说明按用途使用 `[!TIP]`、`[!NOTE]` 和 `[!IMPORTANT]`。
- 2026-10-26 的自动发行在全部构建成功后，因查询同 SHA Driver CI 时 GitHub 返回 HTTP 502 而失败。发布脚本的只读 GitHub API 查询采用最多 4 次尝试和 5/10/20 秒退避；每次缓冲完整输出，避免分页请求失败时的半截数据混入下次结果。重试耗尽仍进入失败诊断，创建或删除 Release 等写操作不盲目重试；同 SHA 驱动与用户态成功门禁不能放宽。`python tools/test_ci_release_template.py` 覆盖瞬时 502、重试耗尽和失败门禁。
- `actions/upload-artifact` 会按上传文件的共同父目录确定 ZIP 根；当同一 artifact 删除其它目录下的产物后，原本保留的仓库相对路径可能变成扁平文件名。消费端不要硬编码 artifact 内的仓库路径，应验证目标文件组合在同一目录且候选唯一，同时兼容旧的分层布局与新的扁平布局。
- QADS 运行时必须来自发布提交的 `Ksword5.1/Ksword5.1/lib/qtadvanceddocking.dll`。`tools/verify_qads_runtime.py` 在主程序 artifact 上传前、Setup 内嵌前、聚合包覆盖前后检查非空与 SHA256；旧手工模板中留存的 DLL 不能作为缺失 QADS 的回退。聚合包来源清单记录头文件版本与 DLL 哈希。
- `ZwQueryAttributesFile` 未在 WDK 10.0.26100 的公共头文件声明，直接调用会在 `/WX` 下触发 `C4013`，同时阻断 Driver CI 和依赖驱动的 ARKLight。按路径复核存在性/只读属性使用 Universal DDI `ZwQueryFullAttributesFile`，输出必须配套 `FILE_NETWORK_OPEN_INFORMATION`，不得仍传 `FILE_BASIC_INFORMATION` 或只关闭警告。
- `shared/driver/` 中的 R0/R3 IOCTL function ID 必须全局唯一。新增统一协议时不能复用仍需兼容的旧 IOCTL 编号；中央注册表也只能登记一次，否则线性查找会让后续 handler 永远不可达。
- 驱动源文件使用 `TOKEN_PRIVILEGES`、`ZwOpenProcessTokenEx`、`ZwQueryInformationToken` 等 NTIFS 声明时，需要显式包含 `<ntifs.h>`；仅包含项目的 `ark_driver.h`（其基础是 `<ntddk.h>`）不够。
- 即使显式包含 `<ntifs.h>`，当前 GitHub Actions WDK 也可能不导出 `PROCESS_QUERY_INFORMATION`；需要该访问掩码的驱动源文件应与相邻实现一致，用 `#ifndef PROCESS_QUERY_INFORMATION` 定义 `0x0400`，否则 Windows runner 会报 `C2065`。
- Windows SDK 的 `FIELD_OFFSET(...)` 在当前 MSVC/SDK 组合下不能用于初始化 C++ `constexpr`，会报 `C2131`；变长结构边界检查应使用局部 `const std::size_t`，或在确认标准布局与包含条件后使用标准 `offsetof`。
- Qt 6.9 且 Release `/WX` 下，`QDateTime::fromMSecsSinceEpoch(..., Qt::UTC)` 的旧 time-spec 重载会因弃用告警报 `C4996`；应改用 `QTimeZone::UTC` 重载并保留原有 UTC/本地转换语义。
- 驱动 Release 把警告视为错误。R0/R3 共享协议头避免匿名 struct/union；如需让同一 ABI 槽位兼容旧 `reserved` 与新动作语义，保留单个具名字段并让旧路径写入确定的零值。
- 多分支合并后不要只修第一个编译错误：对照最近一次两套 CI 都成功的 SHA，检查新增文件、被静默撤销的功能文件、工程引用、重复注册与协议编号，再运行语言包审计和 JSON 解析。
- 身份敏感的异步进程操作必须冻结 `PID + creationTime100ns`。R3 优先复用已校验并持续持有的进程句柄；R0 调整协议必须拒绝零创建时间，并由客户端复核响应中的创建时间与批量应用计数。仅在 UI 状态里保存 PID、稍后重新打开会把操作落到复用后的新进程。
- `TOKEN_PRIVILEGES` 是变长结构。R3 `GetTokenInformation` 和 R0 `ZwQueryInformationToken` 的第二次查询后，都要用实际返回字节数验证 `PrivilegeCount` 能被完整缓冲区覆盖，再遍历条目。
- 合并恢复崩溃处理时必须一起恢复共享 handler、Launcher reporter、两个工程引用、主程序启动挂钩和中英语言键；重复崩溃只能提供退出，不能继续暴露重启按钮形成崩溃循环。内部等待 PID 参数只有在新进程是该 PID 的直接子进程、双方映像路径相同，且确实观察到前一进程退出后，才能绕过单实例检查。
- 2026-10-25 全量 IOCTL 审计发现 FILE_IRP_ENUM_DIRECTORY 与 RXPF_SET_HOOK_POINT 复用 function `0x90A`。旧完整控制码分别为 `0x00226428`（READ）与 `0x0022A428`（WRITE），因此并非完整控制码冲突或错分发；仍违反 function 全局唯一规范。FILE_IRP 枚举迁至已确认空闲的 `0x932`／`0x002264C8`，RXPF 与 FILE_IRP_SUBMIT 编号、请求布局及协议版本保持原样。所有在仓库构建的 R0/R3 调用与注册均引用唯一共享宏，必须配套重建/部署客户端和驱动；不加旧魔数别名规避门禁。历史 `tools/ioctl_audit/out` 是带生成日期的快照，当前结果由 CI 全量扫描确定。
