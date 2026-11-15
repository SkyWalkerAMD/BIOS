.intel_syntax noprefix
.text
.globl ws05_provider_request_call
.globl ws05_provider_request_return
ws05_provider_request_call:
    sub rsp,40
    lea rcx,[rip+w890_provider]
    call qword ptr [rip+w890_provider+40]
ws05_provider_request_return:
    add rsp,40
    ret
    .fill 16,1,0x90
.globl ws05_save_mid_thunk
ws05_save_mid_thunk:
    # Native1FCB4 interior has RSP%16==0. Preserve all volatile GPR/XMM/flags.
    pushfq
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    sub rsp, 128
    movdqu [rsp+32], xmm0
    movdqu [rsp+48], xmm1
    movdqu [rsp+64], xmm2
    movdqu [rsp+80], xmm3
    movdqu [rsp+96], xmm4
    movdqu [rsp+112], xmm5
    call ws05_before_save
    test eax, eax
    jz .Ldeny
    movdqu xmm0, [rsp+32]
    movdqu xmm1, [rsp+48]
    movdqu xmm2, [rsp+64]
    movdqu xmm3, [rsp+80]
    movdqu xmm4, [rsp+96]
    movdqu xmm5, [rsp+112]
    add rsp, 128
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    popfq
    jmp qword ptr [rip+ws05_save_replay]
.Ldeny:
    movdqu xmm0, [rsp+32]
    movdqu xmm1, [rsp+48]
    movdqu xmm2, [rsp+64]
    movdqu xmm3, [rsp+80]
    movdqu xmm4, [rsp+96]
    movdqu xmm5, [rsp+112]
    add rsp, 128
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    popfq
    # Original AL=0 + exact native frame cleanup, not a reset/exit shortcut.
    jmp qword ptr [rip+ws05_save_cancel]
