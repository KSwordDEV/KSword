# Win32k 窗口 Band 事务

- 用户区分 DWM 画面排序与真实点击顺序，曾明确拒绝导致 Explorer 退出的 IAM/Explorer 注入方案。
- 用户明确要求窗口页、杂项页两处均可直接使用完整功能，不能做成“杂项开启后允许窗口页使用”。两页复用 `WindowInputControl` 和代理管理面板；杂项支持列表选择/输入 HWND，窗口页使用当前目标。没有全局 Win32k 启用门槛，兼容性按钮只读，应用时自动校验。两页都能加载 DWM、调整顺序和恢复。
- R3 只经 `ArkDriverClient::controlWindowBand`；协议 `shared/driver/KswordArkWindowBandIoctl.h`，注册 IOCTL `0x898`，`io_queue.c` 的 `EvtIoInCallerContext` 必须保留原始 GUI 线程。客户端创建同线程的隐藏消息窗口供 R0 核验桌面/线程。
- `window_band.c` 只适配 win32kfull `10.0.26100.9022`，PE `5CD0A4AF/428000`，RSDS `80DB0813-4711-330D-D706-8D826FF8E1B0/1`。匹配身份、前缀、可执行节；不得对写操作套用最近版本回退。DWM 支持 Win10 不代表此后端支持 Win10。
- 使用 `InternalBeginDeferWindowPos` → 九参数 `_DeferWindowPos` → 二参数 `xxxEndDeferWindowPosEx`；后者第二参数为异步许可，这里传 0。不直接写 Band/链表/系统代码、不改令牌。精确 ABI/RVA、Band 顺序表及 CFG 说明见 `docs/窗口输入控制.md`。
- 当前原生 Band 限定 1/2，Band 2 是此版本顺序表最高端。前移含义是在已有 UIAccess 窗口之前，并未创建新的更高 Band。拒绝带所有者的窗口组，窗口所属桌面须与调用者一致；不再用未经 profile 证明的 THREADINFO 偏移猜测 CoreWindow，避免误拒绝活动的普通窗口。
- USER 临界区内核验 HWND 对象、PID/TID、创建时间、线程对象、桌面与有界双向链。私有读取只能用 `KswordARKRuntimeReadMemory`。窗口锁跨原生回调，回调后重新核对对象；系统函数返回 TRUE 不足以成功，必须回读 Band/位置。
- R3 保存原 Band/置顶并在失败时撤销；不完整恢复保留记录，统一恢复也覆盖原生 Band。只恢复原 Band 和置顶状态，不恢复历史相邻窗口；不持续抢占后来窗口的原生顺序。
- 2026-09-11：主程序 Release（build-check SUCCESS/exit 0）、驱动 Release（Universal/API 与目录校验）、恢复事务测试及 25040 项 i18n 审计通过。**未加载新驱动进行真实跨 UIAccess 点击验收**；驱动输出未签名。测试的 R0/DWM 回执是替身，不能宣称已实机通过。普通功能矩阵禁止用其非自建 window.hwnd 执行此写操作。
- IDA 9.3 打开映像时无有效许可证；9.1 可用并成功加载微软精确 PDB。不要把启动 MCP 服务成功当成 IDA 授权可用。
