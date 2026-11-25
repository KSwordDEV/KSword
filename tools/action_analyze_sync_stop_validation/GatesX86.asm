.386
.model flat, C
.code

; WOW64 使用与 x64 相同的两字节站点，各有独立地址。
EnterGate PROC
    db 0cch
    ret
EnterGate ENDP

ReturnGate PROC
    db 0cch
    ret
ReturnGate ENDP

ForeignGate PROC
    db 0cch
    ret
ForeignGate ENDP

END
