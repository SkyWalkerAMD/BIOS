.intel_syntax noprefix
.text
.globl no_provider_begin_call
.globl no_provider_begin_return
no_provider_begin_call:
 sub rsp, 40
 call qword ptr [rcx+16]
no_provider_begin_return:
 add rsp, 40
 ret
.globl no_provider_end_call
.globl no_provider_end_return
no_provider_end_call:
 sub rsp, 40
 call qword ptr [rcx+24]
no_provider_end_return:
 add rsp, 40
 ret
