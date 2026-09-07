# KSword 自动化验收记录

时间(UTC): 2026-09-05T22:32:30.1822844Z → 2026-09-05T22:32:45.9856602Z
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

### 备注

- 脚本异常：Checkpoint operation failed.

'KSword-HVM-Target' could not initiate a checkpoint operation.

'KSword-HVM-Target' failed to save RAM contents during a checkpoint operation: 磁盘空间不足。 (0x80070070).

Checkpoint operation for 'KSword-HVM-Target' failed. (Virtual machine ID 01F7B608-BF8F-462D-983B-F6BDA6B5D178)

'KSword-HVM-Target' could not initiate a checkpoint operation: 磁盘空间不足。 (0x80070070). (Virtual machine ID 01F7B608-BF8F-462D-983B-F6BDA6B5D178)

'KSword-HVM-Target' failed to save RAM contents during a checkpoint operation: 磁盘空间不足。 (0x80070070). (Virtual machine ID 01F7B608-BF8F-462D-983B-F6BDA6B5D178)

---

BLOCKED 表示缺能力/权限/样本，**不等于通过**；NOT_RUN 表示这一段本次没跑。
原始 JSON: `acceptance-autotest-20260905-183230.json`

