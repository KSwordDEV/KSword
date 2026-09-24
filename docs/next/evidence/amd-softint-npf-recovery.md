# AMD 软件 INT 在 NPF 后的恢复修复

2026-09-24；对应宿主崩溃记录 `amd-host-crash-20260924.md`。本轮仅修改代码、编译和离线验证，未加载候选、未开启常驻、未启动虚拟机。

## 原因与改动

捕获的 L2 退出为 NPF `0x400`，`EXITINTINFO=0x8000042d`、`RIP=fffff806305fd103`、`NRIP=0`。映射组合和安装已经成功，旧事件恢复函数仍要求软件 INT 有有效 NRIP，返回 2，最终进入 `KswSvmFatal`，触发宿主 `0x20001/0x121`。前一硬件 entry（ordinal 1727261）没有注入事件。

AMD APM Volume 2 §15.7.1 规定 NPF 不提供 next RIP；不能由 NRIP=0 推断这一硬件退出无效。§15.7.2 区分 TYPE4 INTn 与其它异常。参考 [AMD 编写的 APM Rev3.30，大学镜像](https://www.sra.uni-hannover.de/Lehre/SS24/V_BSB/doc/amd64_manual_vol2.pdf)；Linux KVM 对软件事件也单独保留注入返回位置，并处理无法获得 next RIP 时的指令重试，见 [上游 SVM 实现](https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/kvm/svm/svm.c)。本改动没有复制其实现。

- 在最终硬件 entry 准备结束后，以 CPU 私有字段记录实际 EVENTINJ、RIP、NRIP、CS/base、L2 所有权 token；每次 entry 覆盖旧记录。
- 仅在 L0 接受并处理的 NPF 恢复路径使用新函数。原生 INTn 没有软件注入请求时，清 EVENTINJ、保持当前 RIP，让硬件重新执行原指令；不猜指令长度，不跳过 INT。
- 如果该 INTn 是本次 entry 注入的，事件、RIP、CS/base、token 必须匹配，且保存的 next RIP 合法，才恢复其原始返回位置并重新注入。不存在或过期的记录仍拒绝。
- NPT12 故障反射先于这一路径，保留原始 EXITINTINFO/NRIP。RFLAGS、CR2、RSP、interrupt shadow 和原始退出字段不因原生 INT 重试而改写。
- 不修改协议和 metrics v7，不修改汇编退出、页表权限、签名策略或宿主准入条件。

## 验证

`tools/hvm_lab/build-tests.cmd` 的 23 个离线目标通过；nested 5131 检查。新增生产 coordinator → exit routing → MMU resolve → shadow install → event recovery 的连续 NPF 用例，分别覆盖原生 INT 与已注入 INT。纯逻辑检查覆盖空/过期记录、所有权变化、CS/RIP 不匹配、非法/超长 next RIP、重复 NPF、递送完成后清除、原始反射字段及未修改完整 VMCB。均未执行 SVM 硬件指令。

实际转储离线回放读取 `guest-vmcb.bin` 和 `flight.bin` 中的前一次 entry，调用生产恢复函数：

```text
entryOrdinal=1727261 legacy=2 fixed=0 imageUnchanged=1
rip=fffff806305fd103 nrip=0 event=0
```

保存于 `artifacts/host-crash-20260924-0910/replay-fixed-result.txt`，旧回放结果仍保留。此回放验证消除已定位的错误返回分支，不能替代硬件上的 INT 完成和 VM 开机验证。

标准 MSVC/WDK Release x64 编译、链接、x64 ApiValidator（Universal）和 CAT 生成通过，零警告。日志 `tools/hvm_lab/build-softint-npf.log`、`build-softint-npf-tests.log`。

新候选 `tools/hvm_lab/artifacts/softint-npf-v7/KswordARK.sys`，对应 PDB 与沿用的 metrics v7 CLI 同目录。候选未签名、未加载。完整 L2 操作系统正常启动仍未通过验收；此次修复只覆盖已定位的 INTn/NPF 导致宿主致命停止路径。

## 签后加载与环境阻塞（同日 09:38）

用户完成签名并要求实测后，确认签后 SYS/PDB GUID/Age 与候选一致，正常 SCM 加载成功。常驻脚本在任何 prepare/self-test/resident 命令前因 HypervisorPresent=true 停止。当前启动项是原始普通 Windows 10（loader bf214426-63fa-11f1-98a5-ae6e2902c624），hypervisorlaunchtype=Auto，VBS=2，boot ID 2026-09-24T01:10:52.5000000Z；一次性实验启动已在此前崩溃重启后结束。

驱动查询仅 INITIALIZED、prepared/resident=0，能力准入拒绝 SVM_NPT_ASID。完成只读采集后正常 SCM 卸载，确认 Manual/Stopped；没有启动 VMware。证据目录 `artifacts/softint-npf-v7-live-20260924-093828`，包含签后哈希、加载记录、blocked-status、boot-check、BCD/VBS 和卸载后服务状态。签名离线检查仍报告证书有效期问题，实际加载结果只记录 Windows 正常 SCM 接受，没有修改签名策略。需要另行确认重启进入实验项后继续硬件测试，不能记作修复版本常驻或开机通过。
