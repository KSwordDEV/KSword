# KSword 自动化验收记录

时间(UTC): 2026-09-06T04:35:43.1027098Z → 2026-09-06T04:36:21.0759873Z
机器: Microsoft Windows 11 Pro for Workstations Insider Preview build 26300
CPU: 13th Gen Intel(R) Core(TM) i7-13700F

**总判定: FAIL**

| 段 | 判定 | 说明 |
|---|---|---|
| 离线断言套件 | PASS | 11 个套件 / 4000 条断言 |
| guest 工具 | PASS | hvm_probe + hvm_ctl，/MT 静态链接 |
| 在机验证 | FAIL | 级别 probe-xonly |

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
| prune:before-self-test-0906-003102 | OK | 自动修剪旧检查点以回收磁盘 |
| prune:before-driver-load-0906-0030 | OK | 自动修剪旧检查点以回收磁盘 |
| checkpoint:self-test | OK |  |
| alive:self-test | OK | 虚拟机仍然响应 |
| self-test | OK |  |
| prune:before-resident-0906-003108 | OK | 自动修剪旧检查点以回收磁盘 |
| checkpoint:resident | OK |  |
| alive:resident | OK | 虚拟机仍然响应 |
| resident | OK |  |
| probe-xonly | FAIL | EPT_RULE ADD 失败：status=7 nt=0x80000011 win32=0 |
| cleanup:stop | OK | 计划未跑到 stop 就退出，这里补一次 |

### 备注

- probe-xonly 返回 NO_JSON（lastStatus=?）；后续级别不再执行。

---

BLOCKED 表示缺能力/权限/样本，**不等于通过**；NOT_RUN 表示这一段本次没跑。
原始 JSON: `acceptance-autotest-20260906-003543.json`

