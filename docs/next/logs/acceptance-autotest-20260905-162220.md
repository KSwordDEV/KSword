# KSword 自动化验收记录

时间(UTC): 2026-09-05T20:22:20.3653452Z → 2026-09-05T20:26:49.6670108Z
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
| checkpoint:self-test | OK |  |
| alive:self-test | OK | 虚拟机仍然响应 |
| self-test | OK |  |
| checkpoint:resident | OK |  |
| alive:resident | OK | 虚拟机仍然响应 |
| resident | FAIL |  |

### 备注

- resident 返回 LIFECYCLE_GUARD_FAILED（lastStatus=0xC0000184）；后续级别不再执行。
- 当前 DriverObject->DriverUnload = 0xFFFFF8033EAB0360（注册时捕获的是非 0 值，否则 EnableResidentLifecycle 会提前返回）
- 原始 stdout: {"kind":"control","command":"resident","status":20,"statusName":"LIFECYCLE_GUARD_FAILED","lastStatus":"0xC0000184","oldStateFlags":524575,"newStateFlags":524639,"oldStateHex":"0x0008011F","newStateHex":"0x0008015F","newStateNames":["INITIALIZED","RESOURCES_READY","EPT_READY","SELF_TESTED","SELF_TEST_PASSED","FAULTED","GUEST_READY","EVMCS_PARTIAL"],"oldGeneration":3,"newGeneration":4,"preparedProcessorCount":4,"selfTestPassedProcessorCount":4,"failedProcessorCount":0,"residentProcessorCount":0,"residentImplementation":"CAPABILITY_ONLY","eptImplementation":"ACTIVE","nestedImplementation":"CAPABILITY_ONLY","evmcsImplementation":"PARTIAL","eptPointer":"0x0000000207FED05E","eptPageCount":515,"eptRuleCount":0,"mappedRamMiB":8190,"vmExitCount":0,"lastExitReason":4294967295,"lastVmInstructionError":0,"soakElapsedMilliseconds":0,"soakUnexpectedDevirtualizations":0}

---

BLOCKED 表示缺能力/权限/样本，**不等于通过**；NOT_RUN 表示这一段本次没跑。
原始 JSON: `acceptance-autotest-20260905-162220.json`

