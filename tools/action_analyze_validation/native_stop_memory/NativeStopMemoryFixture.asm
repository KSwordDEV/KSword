option casemap:none
.code

; Fixed benign AMD64 site for the real execution breakpoint and the follow-up
; Into step. The RVA of the label is stable across the host and its cooperative
; child because both load the same image; the first instruction is NOP, which
; the production step decoder supports.
PUBLIC KswordStopMemoryStepSite
KswordStopMemoryStepSite PROC
    nop
    nop
    ret
KswordStopMemoryStepSite ENDP

END
