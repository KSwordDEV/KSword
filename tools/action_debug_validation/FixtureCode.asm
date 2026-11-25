option casemap:none
.code
PUBLIC FixtureStart, FixtureCall, FixtureAfterCall
PUBLIC FixtureCalleeEntry, FixtureEarly, FixtureFault

FixtureRun PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
FixtureStart LABEL BYTE
    nop
FixtureCall LABEL BYTE
    call FixtureCallee
FixtureAfterCall LABEL BYTE
    nop
    add rsp, 28h
    ret
FixtureRun ENDP

; A leaf with no prologue: [rsp] is the known return address throughout.
FixtureCallee PROC
FixtureCalleeEntry LABEL BYTE
    nop
FixtureEarly LABEL BYTE
    nop
    test ecx, ecx
    jz fixture_no_fault
FixtureFault LABEL BYTE
    db 0fh, 0bh ; UD2: intentional, debugger-observed first-chance exception.
fixture_no_fault:
    mov eax, 42
    ret
FixtureCallee ENDP
END
