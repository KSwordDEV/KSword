# KSword 自动化验收记录

时间(UTC): 2026-09-06T16:51:14.2592259Z → 2026-09-06T16:51:24.6711699Z
机器: Microsoft Windows 11 Pro for Workstations Insider Preview build 26300
CPU: 13th Gen Intel(R) Core(TM) i7-13700F

**总判定: PARTIAL**

| 段 | 判定 | 说明 |
|---|---|---|
| 离线断言套件 | PASS | 11 个套件 / 4000 条断言 |
| guest 工具 | PASS | hvm_probe + hvm_ctl，/MT 静态链接 |
| 在机验证 | NOT_RUN | 按 -OfflineOnly 跳过。在机项记 NOT_RUN，不记 PASS 也不记 FAIL。 |

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

---

BLOCKED 表示缺能力/权限/样本，**不等于通过**；NOT_RUN 表示这一段本次没跑。
原始 JSON: `acceptance-autotest-20260906-125114.json`

