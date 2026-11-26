# API 内存生命周期字段 AAIM1

AAIM1 使用原 `ApiMonitorEventPacket` 的独立详情槽，包仍为 1000 字节；AAIP1、AAAP1、AACT1、AASM1 不变。源码与严格读侧位于 `shared/evidence/ApiMemoryLifecycleFields.h`。旧 Allocate／Protect／Free 编码保持不变，新增 Unmap 操作值 4；不识别该值的旧读侧拒绝该行，不将它解释为 Free。

| 操作值 | 原 API | 输入 | 成功输出 | 事件语义 |
| --- | --- | --- | --- | --- |
| 1 Allocate | `NtAllocateVirtualMemory` | 原 base、size、AllocationType、初始保护 | 分别带有效位的实际 base、size | 分配调用成功／失败 |
| 2 Protect | `NtProtectVirtualMemory` | 原 base、size、新保护 | 分别带有效位的实际 base、size、旧保护 | 保护调用成功／失败，含可执行保护分类 |
| 3 Free | `NtFreeVirtualMemory` | 原 base、size、FreeType | 无范围输出 | 释放请求成功／失败，不把 size=0 解释成已知全区 |
| 4 Unmap | `NtUnmapViewOfSection` | 直接地址参数、进程句柄 | 无范围输出 | 解除映射请求成功／失败，地址可在视图内部 |

详情为 `AAIM1|` 加 16 个固定宽度、小写十六进制 u64，各字段间用 `|` 分隔。字段顺序：operation、flags、pointerBits、actorCreationFileTime、targetPid、targetCreationFileTime、requestedBase、requestedBytes、outputBase、outputBytes、type、newProtection、oldProtection、inputProcessHandle、enterQpc、returnQpc。type 在 Allocate 为 AllocationType，在 Free 为 FreeType，Protect／Unmap 必须为零。原返回 NTSTATUS 来自包内返回标记，不重复写入详情。

flags 位 0–7 依次为 actor identity、target identity、target stable、requested base、requested bytes、output base、output bytes、old protection。未置位字段须为零；置位允许合法零值。target stable 必须已有完整目标身份。32 位源的地址、长度和句柄不接受高 32 位；QPC 只在非零且来自同一源时具有调用进入／返回次序含义。

Unmap 没有 size 参数，requested bytes 有效位必须缺失；output base／bytes／old protection 均缺失，type／new protection 为零。请求地址按直接参数保存，不访问视图字节、不按地址查询后来的区域、不以读端当前进程的映射补造历史解除范围。发送端沿原句柄查询目标 PID＋创建 FILETIME，并在调用返回后复核同一实例；原函数仅执行一次，观察后恢复 LastError。

原生图保留 `memory-unmap-request` 类别和原始坐标；生命周期目录为 Unmap 保留独立行及 `unmap-request-actual-range-unknown` 原因，不能产生可执行范围草稿，也不能使旧 Allocate／Protect 候选自动失活。CLI／Qt／Light 的显示均区分输入与输出。事件类型为 `memory-unmap-request-succeeded` 或 `memory-unmap-request-failed`；成功只证明原调用接受该请求，不认证被解除的完整范围、映射别名关系、分配代次或后续执行。

本协议扩展及三端接线当前为源码实现；新增操作尚未构建或运行验证。
