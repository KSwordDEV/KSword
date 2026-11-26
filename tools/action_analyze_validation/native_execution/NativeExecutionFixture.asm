option casemap:none

; 固定良性 AMD64 指令序列。所有标签都是已知指令边界，同一映像在每个子进程中
; 具有相同 RVA。函数本身是叶子：不建立栈帧、不调用需要对齐的 C 函数，指令全部
; 落在 NativeStepRuntime 的白名单解码范围内（nop / call rel32 / ret）。
.code

PUBLIC FixtureEnter
PUBLIC FixtureNop
PUBLIC FixtureCall
PUBLIC FixtureAfterCall
PUBLIC FixtureCalleeEntry

FixtureEnter PROC
FixtureNop LABEL BYTE
    nop                     ; +0 执行断点落点（90）
    nop                     ; +1（90）
FixtureCall LABEL BYTE
    call FixtureCallee      ; +2..+6（e8 rel32），返回地址为 +7
FixtureAfterCall LABEL BYTE ; +7（90）
    nop
    ret                     ; +8（c3）
FixtureEnter ENDP

; 被调方入口保持无栈帧：进入时 [rsp] 就是调用方已知返回地址。
FixtureCallee PROC
FixtureCalleeEntry LABEL BYTE
    nop                     ; 入口（90）
    ret                     ; c3
FixtureCallee ENDP

END
