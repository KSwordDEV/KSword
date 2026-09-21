; AMD-specific host loop. Offsets are asserted in hvm_svm.h and portable tests.
option casemap:none
extern KswordSvmExit:proc
.code

; Save the non-VMCB general registers. RAX is hardware-saved in the VMCB.
KSW_SAVE_GPRS macro
    mov [rax+50h], rcx              ; Preserve guest RCX before using it as context.
    mov [rax+58h], rdx              ; Preserve guest RDX.
    mov [rax+60h], rbx              ; Preserve guest RBX.
    mov [rax+70h], rbp              ; Preserve guest RBP.
    mov [rax+78h], rsi              ; Preserve guest RSI.
    mov [rax+80h], rdi              ; Preserve guest RDI.
    mov [rax+88h], r8               ; Preserve guest R8.
    mov [rax+90h], r9               ; Preserve guest R9.
    mov [rax+98h], r10              ; Preserve guest R10.
    mov [rax+0a0h], r11             ; Preserve guest R11.
    mov [rax+0a8h], r12             ; Preserve guest R12.
    mov [rax+0b0h], r13             ; Preserve guest R13.
    mov [rax+0b8h], r14             ; Preserve guest R14.
    mov [rax+0c0h], r15             ; Preserve guest R15.
endm

; Restore general registers with RAX as a disposable context anchor.
KSW_LOAD_GPRS macro
    mov rcx, [rax+50h]             ; Restore guest RCX.
    mov rdx, [rax+58h]             ; Restore guest RDX.
    mov rbx, [rax+60h]             ; Restore guest RBX.
    mov rbp, [rax+70h]             ; Restore guest RBP.
    mov rsi, [rax+78h]             ; Restore guest RSI.
    mov rdi, [rax+80h]             ; Restore guest RDI.
    mov r8, [rax+88h]              ; Restore guest R8.
    mov r9, [rax+90h]              ; Restore guest R9.
    mov r10, [rax+98h]             ; Restore guest R10.
    mov r11, [rax+0a0h]            ; Restore guest R11.
    mov r12, [rax+0a8h]            ; Restore guest R12.
    mov r13, [rax+0b0h]            ; Restore guest R13.
    mov r14, [rax+0b8h]            ; Restore guest R14.
    mov r15, [rax+0c0h]            ; Restore guest R15.
endm

; Snapshot guest XSTATE without allowing CR0.TS/EM to generate #NM.
KSW_SAVE_XSTATE macro
    LOCAL StandardSave, Saved
    mov r8, [rcx+28h]             ; Aligned XSAVE area.
    mov rax, [rcx+30h]            ; Low and high enabled component masks.
    mov rdx, rax                 ; Preserve full mask for high dword.
    shr rdx, 32                  ; XSAVE takes EDX:EAX.
    cmp dword ptr [rcx+110h], 0  ; Prepared format is immutable for this CPU lifetime.
    je StandardSave             ; Older VMware CPUs keep their proven standard path.
    xsaves64 [r8]               ; Compacted user plus XSS.CET_U state, including PL3_SSP.
    jmp Saved                   ; Never write both formats into the same buffer.
StandardSave:
    xsave64 [r8]                ; Save standard-format user XSTATE.
Saved:
endm

; Restore the complete currently supported XSTATE mask.
KSW_LOAD_XSTATE macro
    LOCAL StandardLoad, Loaded
    mov r8, [rcx+28h]             ; Aligned XSAVE area.
    mov rax, [rcx+30h]            ; Enabled state components.
    mov rdx, rax                 ; Split high mask for XRSTOR.
    shr rdx, 32                  ; XRSTOR takes EDX:EAX.
    cmp dword ptr [rcx+110h], 0  ; Restore with the exact instruction family used to save.
    je StandardLoad             ; Standard header must never reach XRSTORS.
    xrstors64 [r8]              ; Restore current guest user CET and SIMD state together.
    jmp Loaded                  ; Do not reinterpret the compacted layout as standard.
StandardLoad:
    xrstor64 [r8]               ; Restore guest SIMD/x87/extended state.
Loaded:
endm

; Switch only after saving GPRs; do not execute SIMD until the root mask is restored.
KSW_SWITCH_XCR0 macro TargetOffset
    LOCAL Unchanged
    mov rax, [rcx+118h]          ; Immutable host mask also describes the XSAVE allocation.
    cmp rax, [rcx+120h]          ; Ordinary residency keeps both masks equal.
    je Unchanged                ; Preserve the existing instruction path when no switch is needed.
    mov r9, rcx                 ; XSETBV consumes ECX, so keep the context in a scratch register.
    mov rax, [rcx+TargetOffset]  ; Use only a mask validated before this assembly transition.
    mov rdx, rax                ; Split the mask without touching any SIMD register.
    shr rdx, 32                 ; Upper XCR0 bits.
    xor ecx, ecx                ; XCR0 is the only supported extended control register.
    xsetbv                      ; VMRUN and VMEXIT themselves do not switch XCR0.
    mov rcx, r9                 ; Restore the caller's context anchor.
Unchanged:
endm

; XSS controls saved supervisor components independently from their live feature MSRs.
KSW_SWITCH_XSS macro TargetOffset
    LOCAL Unchanged
    mov rax, [rcx+128h]          ; Root full-mask supervisor save contract.
    cmp rax, [rcx+130h]          ; Zero/zero also skips the MSR on CPUs without XSAVES.
    je Unchanged                ; No register access is needed when both contexts agree.
    mov r9, rcx                 ; WRMSR consumes ECX.
    mov rax, [rcx+TargetOffset]  ; Values are subsets of the prepared XSS mask.
    mov rdx, rax                ; Split the architectural 64-bit value.
    shr rdx, 32                 ; Upper supervisor component mask.
    mov ecx, 0da0h              ; Architectural XSS MSR.
    wrmsr                       ; Execute only outside C and with physical GIF closed.
    mov rcx, r9                 ; Retain the per-CPU context for the next state operation.
Unchanged:
endm

KswordSvmAsmLaunch proc frame
    .endprolog                   ; No permanent allocation on the Windows stack.
    mov [rcx+20h], rsp           ; Record exact CALL continuation stack.
    mov rax, rcx                 ; Establish context for GPR save macro.
    KSW_SAVE_GPRS                ; Preserve all non-VMCB registers.
    mov r15, rcx                 ; Private anchor after saving the caller's R15.
    pushfq                       ; Capture pre-CLI guest flags.
    pop qword ptr [rcx+0d8h]     ; Save launch RFLAGS in fixed prefix.
    cli                          ; Close the TS/EM transition window before XSAVE.
    mov rax, cr0                 ; Record host CR0 before temporary TS/EM clearing.
    mov [rcx+0e0h], rax          ; Preserve exact original CR0.
    and rax, -13                 ; Clear TS and EM for host XSAVE operations.
    mov cr0, rax                 ; Host execution must not fault while saving SIMD.
    KSW_SAVE_XSTATE              ; Preserve guest state before running host C code.
    cli                          ; Keep interrupts blocked until a complete guest/native state exists.
    mov ecx, 0c0000080h          ; EFER ownership MSR.
    mov rax, [r15+38h]           ; Original EFER was validated with SVME clear.
    or rax, 1000h                ; Enable SVM instructions for this CPU.
    mov rdx, rax                 ; Split MSR value into EDX:EAX.
    shr rdx, 32                  ; Upper EFER bits.
    wrmsr                        ; Acquire SVME ownership.
    clgi                         ; Block physical interrupts/NMIs in the SVM host window.
    mov ecx, 0c0010117h          ; Select VM_HSAVE_PA.
    mov rax, [r15+108h]          ; Hardware-private host save physical address.
    mov rdx, rax                 ; Split physical address.
    shr rdx, 32                  ; Upper address dword.
    wrmsr                        ; Install only this processor's save page.
    mov rax, [r15+8]             ; Select explicit host VMLOAD/VMSAVE image.
    vmsave rax                   ; Save current host FS/GS/TR/LDTR and syscall state.
    mov rbx, [r15+10h]           ; Guest VMCB kernel mapping.
    mov rax, [r15+20h]           ; Original CALL return stack.
    mov [rbx+5d8h], rax          ; Guest RSP resumes the original calling chain.
    mov rax, [r15+0d8h]          ; Original Windows RFLAGS.
    mov [rbx+570h], rax          ; Keep guest IF independent of host CLI.
    lea rax, KswordSvmAsmGuestResume ; First successful entry continuation.
    cmp dword ptr [r15+0d4h], 0  ; Select one-shot guest only for actual self-test.
    je KswSvmSetGuestRip          ; Normal resident path uses the Windows continuation.
    cmp dword ptr [r15+0d4h], 2  ; Nested probing has an independent, bounded instruction stream.
    jne KswSvmSelectBasicTest     ; Ordinary self-test remains the existing CPUID marker.
    lea rax, KswordSvmAsmNestedProbe ; Run only the driver-owned nested test operand.
    jmp KswSvmSetGuestRip         ; The builder already populated its starting RAX operand.
KswSvmSelectBasicTest:
    lea rax, KswordSvmAsmTestGuest ; Self-test must execute an observed CPUID exit.
KswSvmSetGuestRip:
    mov [rbx+578h], rax          ; Set final guest RIP close to VMRUN.
    cmp dword ptr [r15+0d4h], 2  ; Preserve the nested probe's prevalidated operand PA.
    je KswSvmOperandReady         ; Only nested probing starts with nonzero guest RAX.
    mov qword ptr [rbx+5f8h], 0  ; First continuation returns success in guest RAX.
KswSvmOperandReady:
    mov rax, [r15+0e8h]          ; System CR3 outlives any user control process.
    mov cr3, rax                 ; Hardware HSAVE must capture a durable host CR3.
    mov rsp, [r15+18h]           ; Switch to this CPU's dedicated host stack.
    mov [rsp+20h], r15           ; Anchor above Windows x64 call shadow space.
KswSvmRun:
    mov rcx, [rsp+20h]           ; Restore processor context after any C call.
    mov rbx, [rcx+10h]           ; VMCB virtual address.
    mov byte ptr [rbx+5ch], 1    ; Full TLB flush on every VMRUN, including first entry.
    mov dword ptr [rbx+0c0h], 0  ; Do not trust clean-bit caching in this first backend.
    KSW_LOAD_XSTATE              ; Undo host C code's SIMD modifications.
    KSW_SWITCH_XSS 130h          ; The guest sees its current supervisor save enablement.
    KSW_SWITCH_XCR0 120h         ; Install guest enablement after restoring the fixed full state image.
    mov rax, [rsp+20h]           ; Context for GPR restoration.
    KSW_LOAD_GPRS                ; Restore all non-VMCB guest registers.
    mov rax, [rax]               ; Physical VMCB operand, not guest RAX.
    vmload rax                   ; Restore guest extended segment/syscall state.
    vmrun rax                    ; Hardware switches RIP/RSP/RAX and core state.
    mov rax, [rsp+20h]           ; VMEXIT restored the hardware host stack.
    KSW_SAVE_GPRS                ; Preserve guest GPRs before using scratch registers.
    mov rcx, rax                 ; Context for XSAVE and exit dispatch.
    mov rdx, [rcx+10h]           ; Guest VMCB virtual address.
    mov rax, [rdx+5f8h]          ; Guest RAX is saved by hardware, not in host RAX.
    mov [rcx+48h], rax           ; Retain it for native stop continuation.
    KSW_SWITCH_XSS 128h          ; Restore fixed XSAVES component ownership before saving guest state.
    KSW_SWITCH_XCR0 118h         ; Reenable prepared components before XSAVE and any root SIMD use.
    KSW_SAVE_XSTATE              ; Save every prepared component in the unchanged full-mask layout.
    mov rcx, [rsp+20h]           ; Reload stable context.
    mov rax, [rcx]               ; Guest physical VMCB operand.
    vmsave rax                   ; Capture current guest FS/GS/TR/LDTR/syscall state.
    mov rax, [rcx+8]             ; Explicit host image.
    vmload rax                   ; C now sees the host's KPCR/GS and segment state.
    cld                          ; Windows C ABI requires forward string operations.
    call KswordSvmExit           ; Returns zero to resume, one to return natively.
    test eax, eax                ; Dispatchers never silently ignore unknown exits.
    jz KswSvmRun                 ; Resume the same guest VMCB.
    mov r15, [rsp+20h]           ; Native continuation anchor; no further C calls.
    mov rcx, r15                 ; Restore all guest XSTATE first.
    KSW_LOAD_XSTATE              ; Guest CR0.TS/EM is restored only after XRSTOR.
    KSW_SWITCH_XSS 130h          ; Native return preserves current guest XSS rather than a launch snapshot.
    KSW_SWITCH_XCR0 120h         ; Native continuation inherits current guest enablement, not root policy.
    mov rbx, [r15+10h]           ; Guest state image for native restoration.
    mov rax, [rbx+5d8h]          ; Exact current guest RSP, not launch-time RSP.
    mov [r15+0f0h], rax          ; Retain until final stack switch.
    mov rax, [rbx+578h]          ; Exact continuation RIP selected by the dispatcher.
    mov [r15+0f8h], rax          ; Retain native return target.
    mov rax, [rbx+570h]          ; Current guest RFLAGS.
    mov [r15+100h], rax          ; Retain until native flags restoration.
    mov rax, [rbx+5f8h]          ; Current guest RAX/result.
    mov [r15+48h], rax           ; Feed final GPR restoration.
    mov ax, [rbx+464h]           ; GDTR limit low word.
    mov [rsp], ax                ; Build packed ten-byte descriptor register.
    mov rax, [rbx+468h]          ; Guest GDTR base.
    mov [rsp+2], rax             ; Store packed GDTR base.
    lgdt fword ptr [rsp]         ; Restore guest descriptor-table identity.
    mov ax, [rbx+484h]           ; Guest IDTR limit.
    mov [rsp], ax                ; Reuse shadow-space scratch.
    mov rax, [rbx+488h]          ; Guest IDTR base.
    mov [rsp+2], rax             ; Complete packed IDTR.
    lidt fword ptr [rsp]         ; Restore guest interrupt-table identity.
    mov rax, cr3                 ; Clear PCID bits before a possible PCIDE transition.
    and rax, -4096               ; Keep the host page-table base.
    mov cr3, rax                 ; Establish a PCID-neutral intermediate CR3.
    mov rax, [rbx+548h]          ; Current guest CR4.
    mov cr4, rax                 ; Restore guest paging/control features.
    mov rax, [rbx+550h]          ; Current guest CR3.
    mov cr3, rax                 ; Switch back to the current Windows process.
    mov rax, [rbx+640h]          ; Current guest page-fault address.
    mov cr2, rax                 ; Preserve CR2 continuity.
    mov rax, [rbx+568h]          ; Guest DR6.
    mov dr6, rax                 ; Restore debug status.
    mov rax, [rbx+560h]          ; Guest DR7.
    mov dr7, rax                 ; Restore debug controls.
    mov ecx, 1d9h                ; DEBUGCTL is not restored by VMLOAD.
    mov rax, [rbx+670h]          ; Guest DEBUGCTL value.
    mov rdx, rax                 ; Split MSR operand.
    shr rdx, 32                  ; Upper DEBUGCTL dword.
    wrmsr                        ; Restore current guest debug MSR.
    mov rax, [r15]               ; Guest VMLOAD image physical address.
    vmload rax                   ; Restore current guest FS/GS/TR/LDTR/syscall state.
    cmp dword ptr [r15+114h], 0  ; Do not access CET registers on unsupported processors.
    je KswSvmNativeCetDone        ; Preserve the original non-CET VMware return path.
    mov ecx, 6a8h               ; ISST_ADDR is VMRUN state, not VMLOAD or XSAVES state.
    mov rax, [rbx+5f0h]         ; Restore the current guest table, not the launch snapshot.
    mov rdx, rax                ; Split the MSR value.
    shr rdx, 32                 ; Upper address bits.
    wrmsr                       ; Restore before any native interrupt can arrive.
    mov ecx, 6a2h               ; Supervisor CET was held at zero by admission/MSRPM.
    mov rax, [rbx+5e0h]         ; VMCB holds the current architecturally saved S_CET.
    mov rdx, rax                ; Split the control value.
    shr rdx, 32                 ; Upper control bits.
    wrmsr                       ; No active supervisor shadow stack is admitted here.
KswSvmNativeCetDone:
    mov ax, [rbx+400h]           ; Current guest ES selector.
    mov es, ax                   ; Restore ES.
    mov ax, [rbx+430h]           ; Current guest DS selector.
    mov ds, ax                   ; Restore DS.
    mov ax, [rbx+420h]           ; Kernel stop requires CPL0; restore its SS.
    mov ss, ax                   ; Restore SS with IF still clear.
    mov ecx, 0c0010117h          ; Restore pre-entry HSAVE ownership.
    mov rax, [r15+40h]           ; Saved original MSR value.
    mov rdx, rax                 ; Split address for WRMSR.
    shr rdx, 32                  ; Upper HSAVE dword.
    wrmsr                        ; No live VMRUN remains on this CPU.
    stgi                         ; STGI requires SVME; host IF remains clear here.
    mov ecx, 0c0000080h          ; Restore native EFER last among SVM ownership MSRs.
    mov rax, [rbx+4d0h]          ; Preserve guest changes to non-owned EFER bits.
    and rax, -4097               ; Clear only the backend-owned SVME bit.
    mov rdx, rax                 ; Split EFER value.
    shr rdx, 32                  ; Upper EFER dword.
    wrmsr                        ; Leave SVM before acknowledging native completion.
    mov rax, [rbx+558h]          ; Current guest CR0, including TS/EM.
    mov cr0, rax                 ; No more SIMD instructions follow.
    mov rax, [r15+0f0h]          ; Guest RSP points at the original CALL return address.
    sub rax, 8                   ; Synthetic RET is safe only with admitted S_CET=0.
    mov rdx, [r15+0f8h]          ; Exact guest continuation.
    mov [rax], rdx               ; Synthetic return consumes only the temporary slot.
    mov rsp, rax                 ; Switch onto the complete native guest stack.
    push qword ptr [r15+100h]    ; Restore original/current guest RFLAGS.
    popfq                       ; IF opens only after native tables, MSRs and stack exist.
    mov rax, r15                 ; Context for last GPR restoration.
    KSW_LOAD_GPRS                ; Restore caller's non-VMCB registers.
    mov rax, [rax+48h]           ; Restore guest RAX after losing the context anchor.
    ret                         ; Return to current guest RIP with original guest RSP.
KswordSvmAsmLaunch endp

; Capture selectors and descriptor-table registers without changing processor state.
KswordSvmAsmCaptureSegments proc frame
    sub rsp, 18h                 ; Temporary packed descriptor-table register.
    .allocstack 18h              ; Describe stack allocation to the unwinder.
    .endprolog                   ; Finish conventional helper prologue.
    mov ax, es                   ; Read ES selector.
    mov [rcx+400h], ax           ; Store ES selector in AMD save area.
    mov ax, cs                   ; Read CS selector.
    mov [rcx+410h], ax           ; Store CS selector.
    mov ax, ss                   ; Read SS selector.
    mov [rcx+420h], ax           ; Store SS selector.
    mov ax, ds                   ; Read DS selector.
    mov [rcx+430h], ax           ; Store DS selector.
    mov ax, fs                   ; Read FS selector.
    mov [rcx+440h], ax           ; Store FS selector.
    mov ax, gs                   ; Read GS selector.
    mov [rcx+450h], ax           ; Store GS selector.
    sldt ax                      ; Read LDTR selector.
    mov [rcx+470h], ax           ; Store LDTR selector.
    str ax                       ; Read TR selector.
    mov [rcx+490h], ax           ; Store TR selector.
    sgdt fword ptr [rsp]         ; Read ten-byte long-mode GDTR.
    movzx eax, word ptr [rsp]    ; Expand its limit to the AMD dword field.
    mov [rcx+464h], eax          ; Store GDTR limit.
    mov rax, [rsp+2]             ; Read 64-bit GDTR base.
    mov [rcx+468h], rax          ; Store GDTR base.
    sidt fword ptr [rsp]         ; Read ten-byte long-mode IDTR.
    movzx eax, word ptr [rsp]    ; Expand IDTR limit.
    mov [rcx+484h], eax          ; Store IDTR limit.
    mov rax, [rsp+2]             ; Read IDTR base.
    mov [rcx+488h], rax          ; Store IDTR base.
    add rsp, 18h                 ; Restore helper stack.
    ret                          ; Return without modifying descriptor registers.
KswordSvmAsmCaptureSegments endp

; Guest first-entry continuation returns to the pinned Windows IPI worker.
KswordSvmAsmGuestResume proc
    xor eax, eax                ; Return STATUS_SUCCESS from a real guest continuation.
    ret                         ; Resume the original Windows CALL chain.
KswordSvmAsmGuestResume endp

; One-shot code uses an intercepted CPUID, so it cannot fall into arbitrary memory.
KswordSvmAsmTestGuest proc
    mov eax, 4b535753h           ; Unique self-test CPUID leaf.
    cpuid                       ; Exit before the instruction executes natively.
    ud2                         ; Unexpected fallthrough is never accepted as success.
KswordSvmAsmTestGuest endp

; Bounded L1 test: every SVM ownership operation is intercepted by the monitor.
KswordSvmAsmNestedProbe proc
    mov rcx, 4b535753564d3031h    ; Begin with no nonvolatile register changes.
    mov edx, 3                  ; Private nested-probe begin operation.
    vmmcall                     ; Capture the executable Windows return image and original GPRs.
    cli                         ; The probe never opens a maskable-interrupt window.
    push rbx                    ; Preserve the Windows caller's nonvolatile scratch register.
    push rsi                    ; Retain the caller's second nonvolatile register.
    push r12                    ; Keep the original XCR0 across intercepted instructions.
    mov rsi, rdx                ; Begin returned the owned VMCB's guest virtual mapping.
    mov rbx, rax                ; Keep the prevalidated VMCB12 physical operand.
    xor ecx, ecx                ; Read the real guest-visible XCR0 before changing it.
    xgetbv                      ; This instruction runs in guest hardware, not a simulated query.
    shl rdx, 32                 ; Reconstruct all enabled state bits.
    or rax, rdx                 ; Combine the high and low halves.
    mov r12, rax                ; Retain the original native mask for final restoration.
    mov eax, 1                  ; Exercise guest execution with SSE and AVX disabled.
    xor edx, edx                ; All high components stay disabled for the bounded inner marker.
    xsetbv                      ; L0 validates the request and installs it immediately before entry.
    xgetbv                      ; Prove the hardware mask changed, not just a software variable.
    cmp eax, 1                  ; No SSE/AVX component may remain enabled in this guest window.
    jne KswSvmNestedBadReturn   ; Wrong hardware enablement fails through the intercepted marker.
    test edx, edx               ; The high half must also match x87-only.
    jne KswSvmNestedBadReturn   ; Preserve failure evidence instead of entering the inner guest.
    push rbx                    ; CPUID uses EBX, which currently retains the owned operand PA.
    mov eax, 0dh                ; Ask for the guest's current standard save-area requirement.
    xor ecx, ecx                ; Subleaf zero reports XCR0-managed user components.
    cpuid                       ; L0 must synthesize EBX from guest XCR0, not its own full mask.
    cmp ebx, 576                ; x87-only uses the legacy area and header without AVX/ZMM payload.
    pop rbx                     ; Restore the operand without changing the comparison flags.
    jne KswSvmNestedBadReturn   ; Reporting the root allocation size fails this executable probe.
    mov ecx, 0c0000080h          ; Read the virtual EFER image.
    rdmsr                       ; Must be handled as virtual ownership, not physical host state.
    or eax, 1000h               ; Request virtual SVM ownership.
    wrmsr                       ; The real EFER/HSAVE remain owned by the outer assembly loop.
    lea rax, [rbx+1000h]         ; The adjacent driver-owned page is the virtual HSAVE declaration.
    mov rdx, rax                ; Split the virtual physical address for WRMSR.
    shr rdx, 32                 ; Upper address dword.
    mov ecx, 0c0010117h          ; Virtual VM_HSAVE_PA.
    wrmsr                       ; Record software ownership without installing real hardware state.
    mov rax, rbx                ; VMCB12 contains the exact supported test state.
    vmload rax                  ; Exercise the separately virtualized extended state subset.
    mov dword ptr [rsi+58h], 0  ; ASID zero must return architectural VMEXIT_INVALID.
    vmrun rax                   ; Software rejection must resume this exact L1 continuation.
    cmp qword ptr [rsi+70h], -1 ; Verify the returned full-width INVALID exit in guest RAM.
    jne KswSvmNestedBadReturn   ; A stale/missing output is a failed probe, never a PASS.
    mov dword ptr [rsi+58h], 1  ; Correct the same VMCB without restarting the monitor.
    stgi                        ; Exercise virtual GIF release after the invalid-entry return.
    vmrun rax                   ; Intercept, build VMCB02, enter the inner marker and reflect its exit.
    mov rax, r12                ; Restore the real pre-probe native XCR0 after nested reflection.
    mov rdx, rax                ; Split all enabled components.
    shr rdx, 32                 ; High XCR0 half.
    xor ecx, ecx                ; Select XCR0, independently of the reflected inner CPUID registers.
    xsetbv                      ; This is a second validated transition, never a root C write.
    xgetbv                      ; Confirm hardware returned to the full original mask.
    shl rdx, 32                 ; Reconstruct the readback value.
    or rax, rdx                 ; Join low and high halves.
    cmp rax, r12                ; Software bookkeeping alone cannot pass this assertion.
    jne KswSvmNestedBadReturn   ; Report failed restoration before any native Windows return.
    mov rax, rbx                ; VMSAVE still needs its VMCB physical operand.
    vmsave rax                  ; Exercise state persistence across a virtual VMEXIT.
    stgi                        ; Complete the virtual host's GIF transition in this IF=0 test.
    xor eax, eax                ; Release the virtual HSAVE declaration.
    xor edx, edx                ; Upper half must also be zero.
    mov ecx, 0c0010117h          ; Virtual HSAVE register.
    wrmsr                       ; No real save-area ownership changes here.
    mov ecx, 0c0000080h          ; Read back the current virtual EFER.
    rdmsr                       ; Preserve every non-SVME guest bit.
    and eax, 0ffffefffh          ; Release only the virtual SVM owner.
    wrmsr                       ; The dispatcher checks cleanup before final success.
    pop r12                     ; Restore the Windows caller's nonvolatile XCR0 scratch register.
    pop rsi                     ; Restore the extra mapping register after all ownership cleanup.
    pop rbx                     ; Restore the Windows caller's nonvolatile register.
    mov eax, 4b534e32h           ; Unique outer continuation marker, not the inner CPUID marker.
    cpuid                       ; Native return is permitted only after the complete nested round trip.
KswSvmNestedBadReturn:
    mov eax, 4b534e00h           ; An unexpected return is an intercepted probe failure.
    cpuid                       ; Preserve diagnostics and restore the known bounded caller.
    ud2                         ; A successful dispatcher never returns past the final marker.
KswordSvmAsmNestedProbe endp

; The inner guest checks hardware XCR0 before exiting at its bounded marker.
KswordSvmAsmNestedPayload proc
    xor ecx, ecx                ; XCR0 is shared across virtual VMRUN, not an automatic VMCB field.
    xgetbv                      ; Verify the inner guest also observes the reduced hardware mask.
    cmp eax, 1                  ; SSE/AVX must remain disabled through NPT faults and inner entry.
    jne KswSvmInnerBadXcr0      ; A software-only mask update cannot count as success.
    test edx, edx               ; Upper enablement bits must stay clear.
    jne KswSvmInnerBadXcr0      ; Reject an inconsistent inner hardware mask.
    mov eax, 4b534e31h           ; Prove that this inner instruction stream actually executed.
    cpuid                       ; Reflect this intercepted exit into the virtual host VMCB12.
    ud2                         ; Missing interception is a test failure, not a success continuation.
KswSvmInnerBadXcr0:
    mov eax, 4b534e00h           ; Distinguish the failed hardware check from the passing marker.
    cpuid                       ; The bounded dispatcher preserves evidence and returns failure.
    ud2                         ; There is no accepted continuation after a failed inner marker.
KswordSvmAsmNestedPayload endp

; Private kernel-only hypercall; RCX argument becomes RDX operation.
KswordSvmAsmCall proc
    mov rdx, rcx                ; Pass the operation independently of the signature.
    mov rcx, 4b535753564d3031h    ; Exact KSword SVM signature.
    vmmcall                     ; The current CPU's dispatcher handles the request.
    ret                         ; Return only after query or native stop completes.
KswordSvmAsmCall endp
end
