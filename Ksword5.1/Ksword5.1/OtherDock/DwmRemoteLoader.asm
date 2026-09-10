; Position-independent x64 LoadLibraryExW receipt. No imports or global references.
; LoaderPacket offsets are asserted in shared/window/DwmRemoteLoader.h.
; Keep the five-byte prologue in sync with the copied UNWIND_INFO in the client.
PUBLIC KswordDwmLoadStart
PUBLIC KswordDwmLoadEnd

.code
; The client resolves a possible incremental-link thunk before copying this range.
KswordDwmLoadStart LABEL BYTE
KswordDwmLoadRoutine PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 20h
    .allocstack 20h
    .endprolog
    mov rbx, rcx
    mov dword ptr [rbx+60], 1

    lea rcx, [rbx+72]
    mov edx, 1
    mov r8, [rbx+32]
    call qword ptr [rbx+16]       ; RtlAddFunctionTable
    test al, al
    jz registration_failed
    mov dword ptr [rbx+64], 1
    mov dword ptr [rbx+60], 2

    mov rcx, [rbx+40]
    xor edx, edx
    mov r8d, 900h                ; DLL_LOAD_DIR | SYSTEM32, absolute DLL path
    call qword ptr [rbx]         ; LoadLibraryExW
    mov [rbx+48], rax            ; Preserve the complete 64-bit HMODULE.
    test rax, rax
    jnz loaded
    call qword ptr [rbx+8]       ; Same thread, before any other Windows call.
    mov [rbx+56], eax
loaded:
    mov dword ptr [rbx+60], 3
    lea rcx, [rbx+72]
    call qword ptr [rbx+24]      ; RtlDeleteFunctionTable
    test al, al
    jz done                     ; Caller must retain registered metadata/code.
    mov dword ptr [rbx+64], 0
    mov dword ptr [rbx+60], 4
    jmp done
registration_failed:
    mov dword ptr [rbx+56], 50   ; ERROR_NOT_SUPPORTED, loader not called.
done:
    xor eax, eax
    add rsp, 20h
    pop rbx
    ret
KswordDwmLoadRoutine ENDP
KswordDwmLoadEnd LABEL BYTE
END
