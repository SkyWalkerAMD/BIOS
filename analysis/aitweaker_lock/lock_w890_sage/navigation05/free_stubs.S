.intel_syntax noprefix
.text
.macro PRESERVE
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
.endm
.macro RESTORE
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
.endm
.globl n05_menu_free_stub,n05_menu_forget_return
n05_menu_free_stub:
 PRESERVE
 call n05_forget_history
n05_menu_forget_return:
 RESTORE
 call qword ptr [rax+72]
 push r11
 mov r11,qword ptr [rip+n05_history_global]
 and qword ptr [r11],0
 pop r11
 jmp qword ptr [rip+n05_menu_free_resume]
.globl n05_loop_free_stub,n05_loop_forget_return
n05_loop_free_stub:
 PRESERVE
 call n05_forget_history
n05_loop_forget_return:
 RESTORE
 call qword ptr [rax+72]
 push r11
 mov r11,qword ptr [rip+n05_history_global]
 mov qword ptr [r11],rdi
 pop r11
 jmp qword ptr [rip+n05_loop_free_resume]
