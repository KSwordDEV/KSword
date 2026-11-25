.code

; 预编译停点。INT3 长度固定为一字节，下一条指令是 RET。
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
