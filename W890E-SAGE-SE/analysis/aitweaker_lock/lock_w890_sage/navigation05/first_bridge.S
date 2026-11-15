.intel_syntax noprefix
.text
.globl n05_native_first
n05_native_first:
 pushfq
 push rax
 push rcx
 push rdx
 push r8
 push r9
 push r10
 push r11
 sub rsp,128
 movdqu [rsp+32],xmm0
 movdqu [rsp+48],xmm1
 movdqu [rsp+64],xmm2
 movdqu [rsp+80],xmm3
 movdqu [rsp+96],xmm4
 movdqu [rsp+112],xmm5
 call n05_first_dispatch
 movdqu xmm0,[rsp+32]
 movdqu xmm1,[rsp+48]
 movdqu xmm2,[rsp+64]
 movdqu xmm3,[rsp+80]
 movdqu xmm4,[rsp+96]
 movdqu xmm5,[rsp+112]
 add rsp,128
 pop r11
 pop r10
 pop r9
 pop r8
 pop rdx
 pop rcx
 pop rax
 popfq
 mov edi,dword ptr [rcx+0x28]
 mov edx,0x03050006
 jmp qword ptr [rip+n05_first_resume]
.globl n05_recovery_terminal
n05_recovery_terminal:
 # No UEFI calls, ResetSystem, writes or protected native continuation after
 # EBS/service loss. Sleep the processor until external platform recovery.
 hlt
 jmp n05_recovery_terminal
