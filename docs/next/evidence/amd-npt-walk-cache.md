# NPF 外层页表遍历缓存优化

2026-09-24。用户要求优先改善 Windows 自动修复阶段的执行速度。当前 softint-npf-v7 运行现场保持原状；本候选未加载。

## 改动

现有 MMU 在读取、重新校验及原子更新每个 NPT12 页表项时，都重新遍历 NPT01，并提交其 A/D 位。相同外层叶内的多次操作因此反复调用物理窗口。根据现有 e/f 采样，每秒约 26.7 万次 NPF，这种重复工作直接放大退出处理成本；当前证据尚未量化所有跨 VMRUN 缓存失效原因。

新增每次 `KswSvmNestedMmuResolve` 独有的四项外层翻译缓存。在 general 初始化时明确声明 NPT01 映射、权限和属性在本次 resolve 内不可变；这与既有 NPT01 准备后保持不变的生命周期约束一致。只有外层完整写权限检查和 A/D 提交成功后才能填入缓存。缓存保存该已验证叶的输入/输出基址及范围，适用于 4KiB、2MiB、1GiB 叶，命中时仍由原物理回调检查实际 RAM 地址并访问 NPT12。

缓存在每次 resolve 开始置空，最多四项、不分配内存、不跨 CPU/VMRUN/退出使用。NPT12 内容每次仍从物理内存读取、全路径重校验和 CAS 更新。未声明外层不可变的通用调用者及 bounded probe 保持原路径。没有调整跨 VMRUN 缓存键、owner token、TLB_CONTROL 或失效条件。

地址模型依据 [AMD APM Volume 2](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2) 的嵌套页表独立物理地址翻译关系；这里缓存的是 NPT01 对页表地址的翻译，不是来宾虚拟地址或可变 NPT12 内容。

## 离线对照

同样的生产 MMU 输入分别走原路径和优化路径，比较完整翻译结果（排除实际读取计数）及全部测试页表的最终内容：

| NPT01 叶大小 | 物理读取 | 原子更新 |
|---|---:|---:|
| 4KiB | 112 → 48 | 56 → 24 |
| 2MiB | 86 → 20 | 43 → 10 |
| 1GiB | 60 → 16 | 30 → 8 |

读、写操作分别通过；2MiB/1GiB 同时覆盖恒等及非恒等 HPA 映射。测试还覆盖 NPT12 各层读取失败、各层 CAS 并发变更、下一次 resolve 的外层重映射、表页写权限拒绝、实际首次写的 Dirty、UC 属性与不支持缓存类型、NX 执行拒绝。现有软件 INT/NPF 回归仍通过。

这代表上述固定输入下物理回调次数减少约 57%–77%，不是整机或虚拟机性能百分比，也不证明 NPF 总数量减少。

23 个离线目标全部通过，nested 5228 检查。标准 MSVC/WDK Release x64、x64 ApiValidator（Universal）及 CAT 生成通过，零警告。日志 `tools/hvm_lab/build-npt-walk-cache-tests.log` 和 `build-npt-walk-cache.log`。

候选：`tools/hvm_lab/artifacts/npt-walk-cache-v7/KswordARK.sys`，对应 PDB/metrics v7 CLI 在同目录；签名前 identity 记录精确提交和哈希。未签名、未硬件加载。下一步用户签名后，在正常关闭 VM、完整退出旧常驻并卸载后协调换版，比较相同配置下的开机时间及退出计数。当前自动修复仍不等于完整 OS 正常开机验收。
