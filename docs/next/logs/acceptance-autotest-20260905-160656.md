# KSword 自动化验收记录

时间(UTC): 2026-09-05T20:06:56.3668286Z → 2026-09-05T20:07:27.7080806Z
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
| reset-fault | OK | 状态里带 FAULTED/ROLLBACK_REQUIRED，先清掉否则 resident 必被拒 |
| prepare | SKIP | RESOURCES_READY 已置位；重复 prepare 会返回 ALREADY_PREPARED 并把状态打成 FAULTED |
| checkpoint:self-test | OK |  |
| alive:self-test | OK | 虚拟机仍然响应 |
| self-test | OK |  |
| checkpoint:resident | OK |  |
| alive:resident | OK | 虚拟机仍然响应 |
| resident | FAIL |  |

### 备注

- resident 返回 UNKNOWN（lastStatus=0xC0000184）；后续级别不再执行。
- 原始 stdout: {"kind":"control","command":"resident","status":20,"statusName":"UNKNOWN","lastStatus":"0xC0000184","oldStateFlags":524575,"newStateFlags":524639,"oldStateHex":"0x0008011F","newStateHex":"0x0008015F","newStateNames":["INITIALIZED","RESOURCES_READY","EPT_READY","SELF_TESTED","SELF_TEST_PASSED","FAULTED","GUEST_READY","EVMCS_PARTIAL"],"oldGeneration":9,"newGeneration":10,"preparedProcessorCount":4,"selfTestPassedProcessorCount":4,"failedProcessorCount":0,"residentProcessorCount":0,"residentImplementation":"CAPABILITY_ONLY","eptImplementation":"ACTIVE","nestedImplementation":"CAPABILITY_ONLY","evmcsImplementation":"PARTIAL","eptPointer":"0x0000000207FED05E","eptPageCount":515,"eptRuleCount":0,"mappedRamMiB":8190,"vmExitCount":0,"lastExitReason":4294967295,"lastVmInstructionError":0,"soakElapsedMilliseconds":0,"soakUnexpectedDevirtualizations":0}

---

BLOCKED 表示缺能力/权限/样本，**不等于通过**；NOT_RUN 表示这一段本次没跑。
原始 JSON: `acceptance-autotest-20260905-160656.json`

