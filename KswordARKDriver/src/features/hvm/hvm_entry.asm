;------------------------------------------------------------------------------
;
; Module Name:
;
;     hvm_entry.asm
;
; Abstract:
;
;     Captures selector state, supplies one-shot and resident VM-entry
;     continuations, preserves resident guest registers, and performs INVEPT.
;
;------------------------------------------------------------------------------

OPTION CASEMAP:NONE

KSW_ACTIVE_GUEST_S_CET EQU 60h
KSW_ACTIVE_GUEST_SSP EQU 68h
KSW_ACTIVE_GUEST_INTERRUPT_SSP_TABLE EQU 70h
KSW_ACTIVE_GUEST_DEBUGCTL EQU 88h
KSW_ACTIVE_GUEST_DR7 EQU 90h
KSW_ACTIVE_GUEST_CET_MANAGED EQU 98h
KSW_ACTIVE_GUEST_DEBUG_MANAGED EQU 9Bh
KSW_ACTIVE_GUEST_RFLAGS EQU 0A0h

EXTERN KswordARKHvmVmExitDispatch:PROC
EXTERN KswordARKHvmConfigureResidentVmcsFromAsm:PROC
EXTERN KswordARKHvmResidentVmExitDispatch:PROC
EXTERN KswordARKHvmResidentVmResumeFailure:PROC

PUBLIC KswordARKHvmCaptureSegments
PUBLIC KswordARKHvmAsmReadSsp
PUBLIC KswordARKHvmControlledGuestEntry
PUBLIC KswordARKHvmAsmLaunch
PUBLIC KswordARKHvmVmExitEntry
PUBLIC KswordARKHvmAsmLaunchResident
PUBLIC KswordARKHvmAsmResidentHypercall
PUBLIC KswordARKHvmResidentGuestResume
PUBLIC KswordARKHvmResidentVmExitEntry
PUBLIC KswordARKHvmAsmInveptSingle

.CODE

KswordARKHvmCaptureSegments PROC
    ; Store the packed ten-byte GDTR at snapshot offset zero.
    sgdt FWORD PTR [rcx]
    ; Store the packed ten-byte IDTR at snapshot offset ten.
    sidt FWORD PTR [rcx + 10]
    ; Capture ES into its packed snapshot slot.
    mov ax, es
    ; Publish the captured ES selector.
    mov WORD PTR [rcx + 20], ax
    ; Capture CS into its packed snapshot slot.
    mov ax, cs
    ; Publish the captured CS selector.
    mov WORD PTR [rcx + 22], ax
    ; Capture SS into its packed snapshot slot.
    mov ax, ss
    ; Publish the captured SS selector.
    mov WORD PTR [rcx + 24], ax
    ; Capture DS into its packed snapshot slot.
    mov ax, ds
    ; Publish the captured DS selector.
    mov WORD PTR [rcx + 26], ax
    ; Capture FS into its packed snapshot slot.
    mov ax, fs
    ; Publish the captured FS selector.
    mov WORD PTR [rcx + 28], ax
    ; Capture GS into its packed snapshot slot.
    mov ax, gs
    ; Publish the captured GS selector.
    mov WORD PTR [rcx + 30], ax
    ; Capture the current local-descriptor-table selector.
    sldt ax
    ; Publish the captured LDTR selector.
    mov WORD PTR [rcx + 32], ax
    ; Capture the current task-register selector.
    str ax
    ; Publish the captured task-register selector.
    mov WORD PTR [rcx + 34], ax
    ; Return to the VMCS builder.
    ret
KswordARKHvmCaptureSegments ENDP

; 读取调用者进入本函数前的 CET 影子栈指针。
KswordARKHvmAsmReadSsp PROC
    ; 使用字节编码兼容尚未识别 RDSSPQ 助记符的 MASM 版本。
    db 0F3h, 048h, 00Fh, 01Eh, 0C8h
    ; CALL 已压入一个影子返回地址，补偿该八字节槽位。
    add rax, 8
    ; 返回调用者进入本函数前的 SSP。
    ret
KswordARKHvmAsmReadSsp ENDP

KswordARKHvmControlledGuestEntry PROC
    ; Produce the single expected, deterministic VM-exit reason.
    vmcall
    ; Force a second intercept if a future dispatcher accidentally resumes.
    hlt
    ; Prevent fall-through into adjacent executable bytes.
    jmp KswordARKHvmControlledGuestEntry
KswordARKHvmControlledGuestEntry ENDP

KswordARKHvmAsmLaunch PROC
    ; 保存 VMX 转换前的完整 RFLAGS，尤其是 IF 与 AC。
    pushfq
    pop QWORD PTR [rcx + KSW_ACTIVE_GUEST_RFLAGS]
    ; Save the original wrapper stack pointer in context field zero.
    mov QWORD PTR [rcx], rsp
    ; Attempt the first VM entry for the current clear-state VMCS.
    vmlaunch
    ; Default a returning VMLAUNCH to VMfailInvalid.
    mov eax, 2
    ; Preserve result two when the carry flag reports VMfailInvalid.
    jc KswordARKHvmAsmLaunchComplete
    ; Select result one for a VMfailValid zero-flag result.
    mov eax, 1
    ; Preserve result one when the zero flag reports VMfailValid.
    jz KswordARKHvmAsmLaunchComplete
    ; Retain a defensive zero for an architecturally unreachable flag state.
    xor eax, eax
KswordARKHvmAsmLaunchComplete:
    ; VM-entry 失败返回时同样恢复调用点的完整 RFLAGS。
    push QWORD PTR [rcx + KSW_ACTIVE_GUEST_RFLAGS]
    popfq
    ; Return the VM-entry failure code to the C launch lifecycle.
    ret
KswordARKHvmAsmLaunch ENDP

KswordARKHvmVmExitEntry PROC FRAME
    ; Reserve the Windows x64 caller home area on the dedicated exit stack.
    sub rsp, 20h
    ; Describe the fixed stack allocation to the x64 unwinder.
    .ALLOCSTACK 20h
    ; End the unwindable prologue before the first C call.
    .ENDPROLOG
    ; Transfer the current VMCS to the exit dispatcher.
    call KswordARKHvmVmExitDispatch
    ; Require the dispatcher to return the exact active launch context.
    test rax, rax
    ; Trap if the dispatcher could not recover a launch continuation.
    jz KswordARKHvmVmExitFatal
    ; 保留上下文指针，切回 wrapper stack 后不再依赖 host stack。
    mov r11, rax
    ; Restore the wrapper stack that contains the original C return address.
    mov rsp, QWORD PTR [r11]
    ; 预先读取调试状态，避免恢复断点后继续访问上下文。
    mov r8, QWORD PTR [r11 + KSW_ACTIVE_GUEST_DEBUGCTL]
    mov r9, QWORD PTR [r11 + KSW_ACTIVE_GUEST_DR7]
    ; 在重新启用 CET 前恢复中断影子栈表地址。
    cmp BYTE PTR [r11 + KSW_ACTIVE_GUEST_CET_MANAGED], 0
    je KswordARKHvmVmExitRestoreDebug
    mov ecx, 06A8h
    mov rax, QWORD PTR [r11 + KSW_ACTIVE_GUEST_INTERRUPT_SSP_TABLE]
    mov rdx, rax
    shr rdx, 32
    wrmsr
    ; 仅在原始状态启用影子栈时重建 SSP 恢复令牌。
    mov r10, QWORD PTR [r11 + KSW_ACTIVE_GUEST_S_CET]
    test r10, 1
    jz KswordARKHvmVmExitRestoreExactCet
    mov ecx, 06A2h
    mov rax, r10
    or rax, 2
    mov rdx, rax
    shr rdx, 32
    wrmsr
    mov rax, QWORD PTR [r11 + KSW_ACTIVE_GUEST_SSP]
    sub rax, 8
    mov rdx, QWORD PTR [r11 + KSW_ACTIVE_GUEST_SSP]
    or rdx, 1
    ; WRSSQ [RAX], RDX 写入一个 64 位 SSP 恢复令牌。
    db 048h, 00Fh, 038h, 0F6h, 010h
    ; RSTORSSP [RAX] 选择客户机在 VM-exit 时保存的 SSP。
    db 0F3h, 00Fh, 001h, 028h
KswordARKHvmVmExitRestoreExactCet:
    ; 恢复客户机原始 IA32_S_CET。
    mov ecx, 06A2h
    mov rax, r10
    mov rdx, rax
    shr rdx, 32
    wrmsr
KswordARKHvmVmExitRestoreDebug:
    ; 在恢复调试状态前预取 RFLAGS，之后不再读取上下文。
    mov r10, QWORD PTR [r11 + KSW_ACTIVE_GUEST_RFLAGS]
    cmp BYTE PTR [r11 + KSW_ACTIVE_GUEST_DEBUG_MANAGED], 0
    je KswordARKHvmVmExitStateRestored
    ; 最后恢复调试 MSR 和 DR7，避免断点命中恢复过程本身。
    mov ecx, 01D9h
    mov rax, r8
    mov rdx, rax
    shr rdx, 32
    wrmsr
    mov dr7, r9
KswordARKHvmVmExitStateRestored:
    ; Report successful VM entry and handled VM exit to the C lifecycle.
    xor eax, eax
    ; VM-exit 会重置宿主标志，返回前恢复调用点的完整 RFLAGS。
    push r10
    popfq
    ; Return through the original KswordARKHvmAsmLaunch caller frame.
    ret
KswordARKHvmVmExitFatal:
    ; Trap immediately if the dispatcher violates its context contract.
    int 3
    ; Keep the fallback path bounded even when a debugger continues the trap.
    pause
    ; Never execute bytes outside the fallback loop.
    jmp KswordARKHvmVmExitFatal
KswordARKHvmVmExitEntry ENDP

KswordARKHvmAsmLaunchResident PROC FRAME
    ; Preserve the caller's nonvolatile RBX before using it as context storage.
    push rbx
    ; Describe the saved nonvolatile register to the x64 unwinder.
    .PUSHREG rbx
    ; Reserve the Windows x64 caller home area for the VMCS configuration call.
    sub rsp, 20h
    ; Describe the fixed home-area allocation to the x64 unwinder.
    .ALLOCSTACK 20h
    ; End the unwindable prologue before privileged state changes.
    .ENDPROLOG
    ; Preserve the resident context across the C configuration call.
    mov rbx, rcx
    ; Recover the original wrapper RSP that points at the C return address.
    lea rax, QWORD PTR [rsp + 28h]
    ; Publish the exact guest stack continuation at context offset zero.
    mov QWORD PTR [rbx], rax
    ; Capture guest RFLAGS before the VMCS configuration call changes flags.
    pushfq
    ; Store the captured guest RFLAGS at context offset eight.
    pop QWORD PTR [rbx + 8]
    ; Pass the resident context to the VMCS configuration callback.
    mov rcx, rbx
    ; Program guest and host state after exact RSP/RFLAGS capture.
    call KswordARKHvmConfigureResidentVmcsFromAsm
    ; Preserve the configuration status for validation.
    test eax, eax
    ; Skip VM entry when VMCS programming failed.
    jnz KswordARKHvmAsmLaunchResidentConfigFailed
    ; Release the C caller home area before guest entry.
    add rsp, 20h
    ; Restore the caller's nonvolatile RBX before guest state is captured.
    pop rbx
    ; Attempt first entry for the current clear-state resident VMCS.
    vmlaunch
    ; Default a returning VMLAUNCH to VMfailInvalid.
    mov eax, 2
    ; Preserve result two when carry reports VMfailInvalid.
    jc KswordARKHvmAsmLaunchResidentComplete
    ; Select result one for a VMfailValid zero-flag result.
    mov eax, 1
    ; Preserve result one when zero reports VMfailValid.
    jz KswordARKHvmAsmLaunchResidentComplete
    ; Retain a defensive zero for an architecturally unreachable flag state.
    xor eax, eax
KswordARKHvmAsmLaunchResidentComplete:
    ; Return the resident VM-entry result to the current-processor lifecycle.
    ret
KswordARKHvmAsmLaunchResidentConfigFailed:
    ; Release the C caller home area after configuration failure.
    add rsp, 20h
    ; Restore the caller's nonvolatile RBX after configuration failure.
    pop rbx
    ; Return a distinct never-attempted VM-entry result.
    mov eax, 3
    ; Return to the current-processor lifecycle without VMLAUNCH.
    ret
KswordARKHvmAsmLaunchResident ENDP

KswordARKHvmResidentGuestResume PROC
    ; Report successful VM entry when the guest wrapper resumes.
    xor eax, eax
    ; Return through the exact C caller address on the guest stack.
    ret
KswordARKHvmResidentGuestResume ENDP

KswordARKHvmAsmResidentHypercall PROC
    ; Publish the KSword-private hypercall signature in guest RAX.
    mov rax, 4B53574F52444856h
    ; Enter the resident VM-exit dispatcher with RCX command and RDX argument.
    vmcall
    ; Return the dispatcher-provided result in RAX.
    ret
KswordARKHvmAsmResidentHypercall ENDP

KswordARKHvmResidentVmExitEntry PROC
    ; Preserve guest R15 at the top of the host stack.
    push r15
    ; Preserve guest R14.
    push r14
    ; Preserve guest R13.
    push r13
    ; Preserve guest R12.
    push r12
    ; Preserve guest R11.
    push r11
    ; Preserve guest R10.
    push r10
    ; Preserve guest R9.
    push r9
    ; Preserve guest R8.
    push r8
    ; Preserve guest RDI.
    push rdi
    ; Preserve guest RSI.
    push rsi
    ; Preserve guest RBP.
    push rbp
    ; Preserve guest RBX.
    push rbx
    ; Preserve guest RDX.
    push rdx
    ; Preserve guest RCX.
    push rcx
    ; Preserve guest RAX at register-frame offset zero.
    push rax
    ; Load the anchored resident context above the 120-byte register frame.
    mov rdx, QWORD PTR [rsp + 78h]
    ; Save x87, MMX, MXCSR, and XMM state before any C code can alter it.
    fxsave64 [rdx + 50h]
    ; Pass the fixed register-frame base as the first C argument.
    mov rcx, rsp
    ; Reserve the Windows x64 caller home area.
    sub rsp, 20h
    ; Dispatch the current VMCS without allocation or waiting.
    call KswordARKHvmResidentVmExitDispatch
    ; Release the Windows x64 caller home area.
    add rsp, 20h
    ; Select ordinary VMRESUME for action zero.
    test eax, eax
    ; Restore guest registers before VMRESUME.
    jz KswordARKHvmResidentResume
    ; Select verified devirtualization for action one.
    cmp eax, 1
    ; Restore guest registers before leaving the host stack.
    je KswordARKHvmResidentDevirtualize
    ; Trap when no verified guest continuation exists.
    jmp KswordARKHvmResidentFatal

KswordARKHvmResidentResume:
    ; Reload the anchored context without consuming the saved guest RAX.
    mov rax, QWORD PTR [rsp + 78h]
    ; Restore x87, MMX, MXCSR, and XMM state before returning to the guest.
    fxrstor64 [rax + 50h]
    ; Restore guest RAX.
    pop rax
    ; Restore guest RCX.
    pop rcx
    ; Restore guest RDX.
    pop rdx
    ; Restore guest RBX.
    pop rbx
    ; Restore guest RBP.
    pop rbp
    ; Restore guest RSI.
    pop rsi
    ; Restore guest RDI.
    pop rdi
    ; Restore guest R8.
    pop r8
    ; Restore guest R9.
    pop r9
    ; Restore guest R10.
    pop r10
    ; Restore guest R11.
    pop r11
    ; Restore guest R12.
    pop r12
    ; Restore guest R13.
    pop r13
    ; Restore guest R14.
    pop r14
    ; Restore guest R15.
    pop r15
    ; Resume guest execution with the updated VMCS and GPR state.
    vmresume
    ; Recreate the register frame when VMRESUME fails.
    push r15
    ; Preserve guest R14 after failed VMRESUME.
    push r14
    ; Preserve guest R13 after failed VMRESUME.
    push r13
    ; Preserve guest R12 after failed VMRESUME.
    push r12
    ; Preserve guest R11 after failed VMRESUME.
    push r11
    ; Preserve guest R10 after failed VMRESUME.
    push r10
    ; Preserve guest R9 after failed VMRESUME.
    push r9
    ; Preserve guest R8 after failed VMRESUME.
    push r8
    ; Preserve guest RDI after failed VMRESUME.
    push rdi
    ; Preserve guest RSI after failed VMRESUME.
    push rsi
    ; Preserve guest RBP after failed VMRESUME.
    push rbp
    ; Preserve guest RBX after failed VMRESUME.
    push rbx
    ; Preserve guest RDX after failed VMRESUME.
    push rdx
    ; Preserve guest RCX after failed VMRESUME.
    push rcx
    ; Preserve guest RAX after failed VMRESUME.
    push rax
    ; Default the VMRESUME result to VMfailInvalid.
    mov edx, 2
    ; Preserve result two when carry reports VMfailInvalid.
    jc KswordARKHvmResidentVmResumeResultReady
    ; Select result one for VMfailValid.
    mov edx, 1
    ; Preserve result one when zero reports VMfailValid.
    jz KswordARKHvmResidentVmResumeResultReady
    ; Retain a defensive zero for an unreachable flag state.
    xor edx, edx
KswordARKHvmResidentVmResumeResultReady:
    ; Load the anchored resident context as the first C argument.
    mov rcx, QWORD PTR [rsp + 78h]
    ; Reserve the Windows x64 caller home area.
    sub rsp, 20h
    ; Convert VMRESUME failure into a verified devirtualization continuation.
    call KswordARKHvmResidentVmResumeFailure
    ; Release the Windows x64 caller home area.
    add rsp, 20h
    ; Require a verified devirtualization action.
    cmp eax, 1
    ; Restore guest registers before leaving the host stack.
    je KswordARKHvmResidentDevirtualize
    ; Trap when VMRESUME failure has no verified continuation.
    jmp KswordARKHvmResidentFatal

KswordARKHvmResidentDevirtualize:
    ; Load the anchored context while the host register frame remains intact.
    mov rdx, QWORD PTR [rsp + 78h]
    ; Restore the original extended state after the final VM-exit C call.
    fxrstor64 [rdx + 50h]
    ; Preserve the host register-frame base only until it is copied.
    mov rsi, rsp
    ; Load the verified exact guest stack continuation.
    mov rax, QWORD PTR [rdx + 38h]
    ; Load the verified instruction continuation.
    mov r10, QWORD PTR [rdx + 40h]
    ; Load the verified guest RFLAGS continuation.
    mov r11, QWORD PTR [rdx + 48h]
    ; Switch away from the host stack before publishing resource release.
    mov rsp, rax
    ; Place the continuation so the final RET restores the exact guest RSP.
    push r10
    ; Place guest RFLAGS immediately below the return continuation.
    push r11
    ; Copy original guest R15 from the immutable host register frame.
    push QWORD PTR [rsi + 70h]
    ; Copy original guest R14.
    push QWORD PTR [rsi + 68h]
    ; Copy original guest R13.
    push QWORD PTR [rsi + 60h]
    ; Copy original guest R12.
    push QWORD PTR [rsi + 58h]
    ; Copy original guest R11 without sacrificing it as a jump register.
    push QWORD PTR [rsi + 50h]
    ; Copy original guest R10 without sacrificing it as a flags register.
    push QWORD PTR [rsi + 48h]
    ; Copy original guest R9.
    push QWORD PTR [rsi + 40h]
    ; Copy original guest R8.
    push QWORD PTR [rsi + 38h]
    ; Copy original guest RDI.
    push QWORD PTR [rsi + 30h]
    ; Copy original guest RSI.
    push QWORD PTR [rsi + 28h]
    ; Copy original guest RBP.
    push QWORD PTR [rsi + 20h]
    ; Copy original guest RBX.
    push QWORD PTR [rsi + 18h]
    ; Copy original guest RDX.
    push QWORD PTR [rsi + 10h]
    ; Copy original guest RCX.
    push QWORD PTR [rsi + 8]
    ; Copy the dispatcher-provided guest RAX result.
    push QWORD PTR [rsi]
    ; Cache runtime and processor-row pointers before the final count commit.
    mov r8, QWORD PTR [rdx + 10h]
    mov r9, QWORD PTR [rdx + 18h]
    ; Publish that this row is no longer resident only after stack handoff.
    lock and DWORD PTR [r9 + 4], 0FFFFFEFFh
    ; Publish completed processor-local devirtualization.
    lock or DWORD PTR [r9 + 4], 00000400h
    ; Clear Active exactly once after no host-stack access remains.
    xor eax, eax
    xchg DWORD PTR [rdx + 250h], eax
    ; Skip the count update if another verified path already committed it.
    test eax, eax
    jz KswordARKHvmResidentCommitComplete
    ; Make the final resident-count decrement the last context-related access.
    lock dec DWORD PTR [r8 + 28h]
KswordARKHvmResidentCommitComplete:
    ; Restore guest RAX from the guest-stack continuation frame.
    pop rax
    ; Restore guest RCX.
    pop rcx
    ; Restore guest RDX.
    pop rdx
    ; Restore guest RBX.
    pop rbx
    ; Restore guest RBP.
    pop rbp
    ; Restore guest RSI.
    pop rsi
    ; Restore guest RDI.
    pop rdi
    ; Restore guest R8.
    pop r8
    ; Restore guest R9.
    pop r9
    ; Restore guest R10.
    pop r10
    ; Restore guest R11.
    pop r11
    ; Restore guest R12.
    pop r12
    ; Restore guest R13.
    pop r13
    ; Restore guest R14.
    pop r14
    ; Restore guest R15.
    pop r15
    ; Restore the exact guest RFLAGS from the synthetic continuation frame.
    popfq
    ; Consume the synthetic RIP and leave RSP exactly at DevirtualizeRsp.
    ret

KswordARKHvmResidentFatal:
    ; Trap immediately when no verified guest continuation exists.
    int 3
    ; Keep the fallback path bounded if a debugger continues the trap.
    pause
    ; Never execute bytes outside the fatal fallback loop.
    jmp KswordARKHvmResidentFatal
KswordARKHvmResidentVmExitEntry ENDP

KswordARKHvmAsmInveptSingle PROC
    ; Reserve one 16-byte INVEPT descriptor on the current root stack.
    sub rsp, 10h
    ; Store the caller-provided EPT pointer in descriptor qword zero.
    mov QWORD PTR [rsp], rcx
    ; Clear reserved descriptor qword one.
    mov QWORD PTR [rsp + 8], 0
    ; Select single-context invalidation type one.
    mov rax, 1
    ; Invalidate translations associated with the exact EPT pointer.
    invept rax, OWORD PTR [rsp]
    ; Default the instruction result to VMfailInvalid.
    mov eax, 2
    ; Preserve result two when carry reports VMfailInvalid.
    jc KswordARKHvmAsmInveptSingleComplete
    ; Select result one for VMfailValid.
    mov eax, 1
    ; Preserve result one when zero reports VMfailValid.
    jz KswordARKHvmAsmInveptSingleComplete
    ; Select result zero for successful invalidation.
    xor eax, eax
KswordARKHvmAsmInveptSingleComplete:
    ; Release the local INVEPT descriptor.
    add rsp, 10h
    ; Return the exact VMX instruction result.
    ret
KswordARKHvmAsmInveptSingle ENDP

END
