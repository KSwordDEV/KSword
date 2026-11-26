option casemap:none
.code

; Fixed benign AMD64 instruction sequence for native single-step validation.
; Every label is a known instruction boundary inside one image; the RVA of each
; label is stable across processes, so the parent can address the same site in
; its own cooperative child without any target-side patching.
PUBLIC FixtureStepCallRun
PUBLIC FixtureStepCallRunAfter
PUBLIC FixtureStepRun
PUBLIC FixtureStepNop
PUBLIC FixtureStepCall
PUBLIC FixtureStepAfterCall
PUBLIC FixtureStepUnknown
PUBLIC FixtureStepRet
PUBLIC FixtureStepCalleeEntry

EXTERN KswordFixtureCalleeBody:PROC

; Caller frame that gives FixtureStepRun a known return slot.
FixtureStepCallRun PROC
    sub rsp, 8
    call FixtureStepRun
FixtureStepCallRunAfter LABEL BYTE
    add rsp, 8
    ret
FixtureStepCallRun ENDP

; One NOP, one CALL, one NOP, one unsupported instruction and one RET.
FixtureStepRun PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
FixtureStepNop LABEL BYTE
    nop
FixtureStepCall LABEL BYTE
    call FixtureStepCallee
FixtureStepAfterCall LABEL BYTE
    nop
    add rsp, 28h
FixtureStepUnknown LABEL BYTE
    cdq
FixtureStepRet LABEL BYTE
    ret
FixtureStepRun ENDP

; Leaf-like entry: at FixtureStepCalleeEntry the stack slot still holds the
; caller's return address, so a step out can be proven against the real frame.
FixtureStepCallee PROC
FixtureStepCalleeEntry LABEL BYTE
    nop
    sub rsp, 28h
    call KswordFixtureCalleeBody
    add rsp, 28h
    ret
FixtureStepCallee ENDP
END
