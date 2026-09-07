# KSword 自动化验收记录

时间(UTC): 2026-09-06T00:24:39.1058206Z → 2026-09-06T00:32:13.0881471Z
机器: Microsoft Windows 11 Pro for Workstations Insider Preview build 26300
CPU: 13th Gen Intel(R) Core(TM) i7-13700F

**总判定: FAIL**

| 段 | 判定 | 说明 |
|---|---|---|
| 离线断言套件 | PASS | 11 个套件 / 4000 条断言 |
| guest 工具 | PASS | hvm_probe + hvm_ctl，/MT 静态链接 |
| 在机验证 | FAIL | 级别 resident |

## 离线套件明细

| 套件 | 通过 | 总数 |
|---|---:|---:|
| F evidence contract | 192 | 192 |
| X cross-view | 180 | 180 |
| G entity graph | 351 | 351 |
| C offline dump facts | 461 | 461 |
| D snapshot compare | 387 | 387 |
| S security state | 442 | 442 |
| N wfp analysis | 545 | 545 |
| T timeline | 381 | 381 |
| I image integrity | 395 | 395 |
| M memory evidence | 199 | 199 |
| HVM ept switch | 467 | 467 |

## 在机步骤

| 步骤 | 结果 | 说明 |
|---|---|---|
| deploy:hvm_ctl | OK |  |
| status | OK |  |
| prepare | OK |  |
| prune:before-self-test-0905-201641 | OK | 自动修剪旧检查点以回收磁盘 |
| prune:before-driver-load-0905-2015 | OK | 自动修剪旧检查点以回收磁盘 |
| checkpoint:self-test | OK |  |
| alive:self-test | OK | 虚拟机仍然响应 |
| self-test | OK |  |
| prune:before-resident-0905-201648 | OK | 自动修剪旧检查点以回收磁盘 |
| checkpoint:resident | OK |  |

### 备注

- 脚本异常：The background process reported an error with the following message: "The Hyper-V socket target process has ended.".
- 收尾 status 查询失败（虚拟机可能已失联）
- 事件环查询失败

---

BLOCKED 表示缺能力/权限/样本，**不等于通过**；NOT_RUN 表示这一段本次没跑。
原始 JSON: `acceptance-autotest-20260905-202439.json`

