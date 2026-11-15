.intel_syntax noprefix
.text
.globl wf_native_first_entry
.p2align 4
wf_native_first_entry:
    # Mid-function at W890 0603 RVA 19463: RSP is 16-byte aligned.
    # Preserve all volatile GPRs, flags, XMM0..5 and Win64 shadow space.
    pushfq
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    sub rsp, 0x80
    movdqu [rsp+0x20], xmm0
    movdqu [rsp+0x30], xmm1
    movdqu [rsp+0x40], xmm2
    movdqu [rsp+0x50], xmm3
    movdqu [rsp+0x60], xmm4
    movdqu [rsp+0x70], xmm5
    mov rcx, qword ptr [rip+wf_binding_pointer]
    test rcx, rcx
    jz .Lreject
    cmp qword ptr [rip+wf_first_function], 0
    je .Lreject
    call qword ptr [rip+wf_first_function]
    cmp eax, 1
    ja .Lreject
    movdqu xmm0, [rsp+0x20]
    movdqu xmm1, [rsp+0x30]
    movdqu xmm2, [rsp+0x40]
    movdqu xmm3, [rsp+0x50]
    movdqu xmm4, [rsp+0x60]
    movdqu xmm5, [rsp+0x70]
    add rsp, 0x80
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    popfq
    # Replay exactly the two original instructions stolen at RVA 19463.
    mov edi, dword ptr [rcx+0x28]
    mov edx, 0x03050006
    jmp qword ptr [rip+wf_native_resume]
.Lreject:
    movdqu xmm0, [rsp+0x20]
    movdqu xmm1, [rsp+0x30]
    movdqu xmm2, [rsp+0x40]
    movdqu xmm3, [rsp+0x50]
    movdqu xmm4, [rsp+0x60]
    movdqu xmm5, [rsp+0x70]
    add rsp, 0x80
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    popfq
    # This unbound component cannot choose a safe ASUS error UI. The installer
    # must supply a proven fail-closed continuation. Zero intentionally traps;
    # it must never silently continue to a protected page or force Setup exit.
    cmp qword ptr [rip+wf_fail_closed], 0
    je .Lunbound
    jmp qword ptr [rip+wf_fail_closed]
.Lunbound:
    ud2
.data
.p2align 3
.globl wf_binding_pointer
wf_binding_pointer: .quad 0
.globl wf_first_function
wf_first_function: .quad 0
.globl wf_native_resume
wf_native_resume: .quad 0
.globl wf_fail_closed
wf_fail_closed: .quad 0
