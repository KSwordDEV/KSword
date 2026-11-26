option casemap:none
EXTERN StepBlockingCallee:PROC
.code
PUBLIC StepSite, StepAfterCall, StepCalleeEntry
PUBLIC StepSlowSite, StepAfterSlowCall

; 断点站点与被调方都保持无栈帧的叶子函数：地址、指令字节和返回槽完全已知，
; 全部指令均落在 NativeStepRuntime 的白名单解码范围内（nop / call rel32 / ret）。
StepSite PROC
    nop                     ; +0 执行断点落点（90）
    nop                     ; +1（90）
    call StepCallee         ; +2..+6（e8 rel32），返回地址为 +7
StepAfterCall LABEL BYTE    ; +7（90）
    nop
    ret                     ; +8（c3）
StepSite ENDP

StepCallee PROC
StepCalleeEntry LABEL BYTE
    nop                     ; 被调方入口，无栈帧：[rsp] 即已知返回地址。
    ret
StepCallee ENDP

; 慢速站点：被调方是 C 函数，可按测试需要在内部阻塞，用于在途查询与取消。
StepSlowSite PROC
    nop                     ; +0 执行断点落点（90）
    call StepBlockingCallee ; +1..+5（e8 rel32），返回地址为 +6
StepAfterSlowCall LABEL BYTE ; +6（90）
    nop
    ret
StepSlowSite ENDP
END
