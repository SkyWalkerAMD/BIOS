.intel_syntax noprefix
.text
.globl n07_loop_body_call
n07_loop_body_call:
 sub rsp,40
 call rcx
.globl n07_loop_body_return
n07_loop_body_return:
 add rsp,40
 ret

.globl n07_native_tail
n07_native_tail:
 pushfq
 push rax
 push rcx
 push rdx
 push r8
 push r9
 push r10
 push r11
 sub rsp,256
 movdqu [rsp+32],xmm0
 movdqu [rsp+48],xmm1
 movdqu [rsp+64],xmm2
 movdqu [rsp+80],xmm3
 movdqu [rsp+96],xmm4
 movdqu [rsp+112],xmm5
 lea rax,[rsp+320]
 mov [rsp+128],rax
 mov [rsp+136],rbp
 mov [rsp+144],rbx
 mov [rsp+152],rsi
 mov [rsp+160],rdi
 mov [rsp+168],r12
 mov [rsp+176],r13
 mov [rsp+184],r14
 mov [rsp+192],r15
 lea rax,[rsp+256]
 mov [rsp+200],rax
n07_retry:
 lea rcx,[rsp+128]
 call n07_exit_dispatch
.globl n07_dispatch_return
n07_dispatch_return:
 test eax,eax
 jnz n07_continue
n07_wait:
 call n07_fault_wait
 cmp eax,1
 je n07_retry
 test eax,eax
 jz n07_wait
 jmp n05_recovery_terminal
n07_continue:
 movdqu xmm0,[rsp+32]
 movdqu xmm1,[rsp+48]
 movdqu xmm2,[rsp+64]
 movdqu xmm3,[rsp+80]
 movdqu xmm4,[rsp+96]
 movdqu xmm5,[rsp+112]
 add rsp,256
 pop r11
 pop r10
 pop r9
 pop r8
 pop rdx
 pop rcx
 pop rax
 popfq
 # Proven native BL=0, App.exit=0. Exact arithmetic flags of original CMP.
 cmp bl,bl
 jmp qword ptr [rip+n07_resume]
