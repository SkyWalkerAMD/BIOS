.intel_syntax noprefix
.text
.globl mp_call_provider
.globl mp_call_provider_return
mp_call_provider:
 sub rsp,56
 mov rax,qword ptr [rsp+96]
 mov qword ptr [rsp+40],rax
 mov qword ptr [rsp+32],r9
 mov r9,r8
 mov r8,rdx
 mov rdx,rcx
 lea rcx,[rip+w890_management_config]
 call w890_config_callback
mp_call_provider_return:
 add rsp,56
 ret
.globl i05_profile_gate
.globl i05_profile_gate_return
i05_profile_gate:
 sub rsp,72
 mov rax,qword ptr [rsp+112]
 mov qword ptr [rsp+32],rax
 mov rax,qword ptr [rsp+120]
 mov qword ptr [rsp+40],rax
 mov rax,qword ptr [rsp+128]
 mov qword ptr [rsp+48],rax
 call ws05_profile_callback_gate
i05_profile_gate_return:
 add rsp,72
 ret
