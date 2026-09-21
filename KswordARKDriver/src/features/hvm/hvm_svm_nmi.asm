; Bounded acknowledgement for a pending physical NMI; no Windows ISR or C callback.
option casemap:none
.code
public KswordSvmAsmAcknowledgeNmi
public KswordSvmAsmCaptureNmi

KswordSvmAsmAcknowledgeNmi proc frame
    sub rsp, 28h               ; Reserve private SIDT scratch with normal x64 alignment.
    .allocstack 28h
    .endprolog
    xor eax, eax               ; Zero always means no proven single acknowledgement.
    test rcx, rcx              ; Reject an absent prepared capture descriptor.
    jz NmiDone                 ; No privileged state changed.
    cmp dword ptr [rcx+28h], 1 ; The complete trusted table must be ready.
    jne NmiDone                ; A partially prepared IDT cannot be installed.
    cmp dword ptr [rcx+4], 0   ; Nested windows would invalidate RCX ownership.
    jne NmiDone                ; Preserve the existing window's counter.
    cmp dword ptr [rcx], 0     ; Previous acknowledgements must first be handed off.
    jne NmiDone                ; Never clear unconsumed hardware evidence here.
    mov dx, cs                 ; Near return from the private leaf requires exactly the interrupted CS.
    cmp dx, [rcx+52h]          ; Private table starts at 30h; vector-two selector is at +22h.
    jne NmiDone                ; A changed root code selector requires fresh preparation.
    pushfq                     ; Verify that physical maskable interrupts stay closed.
    pop rdx                    ; Only volatile registers are used by this leaf.
    test edx, 200h             ; IF must already be zero on entry.
    jnz NmiDone                ; This helper does not create a new CLI/STI policy.
    sidt fword ptr [rsp]        ; Read the currently installed trusted host IDTR.
    mov rdx, [rsp+2]           ; Compare the full base, not just its low dword.
    cmp rdx, [rcx+0ah]         ; A changed root table requires preparation again.
    jne NmiDone                ; Do not restore a stale IDTR after the window.
    mov dx, [rsp]              ; Compare the architectural table limit as well.
    cmp dx, [rcx+8]            ; Same base alone is insufficient ownership evidence.
    jne NmiDone                ; Leave all physical state unchanged on mismatch.
    mov dword ptr [rcx+4], 1   ; RCX remains this descriptor throughout the open-GIF window.
    lidt fword ptr [rcx+18h]   ; Only the copied table's vector two is replaced.
    mov edx, 256               ; Bound the window; absence of NMI never spins indefinitely.
    stgi                       ; GIF opens while IF remains zero and root state is complete.
NmiWait:
    cmp dword ptr [rcx], 0     ; The NMI leaf records actual acknowledgement, not an estimate.
    jne NmiClose               ; Close immediately after at least one observed delivery.
    pause                      ; No allocation, lock, host API or guest memory access.
    dec edx                    ; Consume a fixed processor-local attempt budget.
    jnz NmiWait                 ; A blocked/missing NMI is reported as incomplete.
NmiClose:
    clgi                       ; No NMI may arrive while restoring the original root table.
    lidt fword ptr [rcx+8]     ; Restore exactly the descriptor checked before STGI.
    mov dword ptr [rcx+4], 0   ; RCX may now be reused by the C caller.
    cmp dword ptr [rcx], 1     ; Multiple acknowledgements remain in Count for explicit handling.
    sete al                    ; Only exactly one matches the single-pending-event contract.
    movzx eax, al              ; Return a clean unsigned result.
NmiDone:
    add rsp, 28h               ; Restore the ordinary private root call frame.
    ret                        ; GIF remains clear; IF was never changed.
KswordSvmAsmAcknowledgeNmi endp

; RCX is immutable while this gate is installed. Same-CPL, IST=0, supervisor-CET=0 only.
KswordSvmAsmCaptureNmi proc
    mov [rcx+1030h], rax       ; Save the only scratch GPR before decoding the hardware frame.
    mov rax, [rsp]             ; Long-mode frame: RIP, CS, RFLAGS, RSP, SS (all eight-byte slots).
    mov [rcx+1038h], rax       ; Resume the exact interrupted root instruction.
    mov rax, [rsp+18h]         ; Original RSP precedes hardware's sixteen-byte alignment.
    mov [rcx+1040h], rax       ; Do not guess the original stack by adding a frame size.
    mov rax, [rsp+10h]         ; Original root flags have IF=0 by the entry contract.
    mov [rcx+1048h], rax       ; Retain flags while leaving the interrupt frame.
    cmp dword ptr [rcx], -1    ; Saturation retains a fault marker rather than wrapping to no evidence.
    je NmiSaturated             ; The platform cannot treat saturation as successful handoff.
    inc dword ptr [rcx]        ; One write records one actual NMI acknowledgement; no GPR is clobbered.
NmiSaturated:
    mov ax, [rsp+20h]          ; Restore the same trusted root SS, not a guest selector.
    mov ss, ax                 ; The private gate never changes privilege level or CS.
    mov rsp, [rcx+1040h]       ; Return to the interrupted root window's exact stack.
    push qword ptr [rcx+1038h] ; CET supervisor shadow stacks are excluded by admission.
    push qword ptr [rcx+1048h] ; Restore flags without using IRET (which would unblock NMI early).
    popfq                      ; IF remains zero; GIF is closed by the caller's next bounded step.
    mov rax, [rcx+1030h]       ; Restore the interrupted value before relinquishing RCX ownership.
    ret                        ; Physical NMI stays blocked until the eventual guest's completed IRET.
KswordSvmAsmCaptureNmi endp
end
