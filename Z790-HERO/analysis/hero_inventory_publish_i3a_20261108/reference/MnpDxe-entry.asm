55c: push rbx
55e: sub rsp, 0x30
562: mov rax, qword ptr [rdx + 0x60]
566: lea r9, [rsp + 0x40]
56b: and qword ptr [rsp + 0x20], 0
571: mov rbx, rcx
574: mov qword ptr [rip + 0x62a5], rax
57b: xor r8d, r8d
57e: mov rax, qword ptr [rdx + 0x58]
582: mov qword ptr [rip + 0x628f], rdx
589: xor edx, edx
58b: mov qword ptr [rip + 0x6296], rax
592: lea ecx, [rdx + 1]
595: call 0x370
59a: mov rax, qword ptr [rip + 0x627f]
5a1: lea r8, [rip + 0x6290]
5a8: xor edx, edx
5aa: lea rcx, [rip + 0x5bef]
5b1: call qword ptr [rax + 0x140]
5b7: mov rax, qword ptr [rip + 0x6262]
5be: lea r8, [rsp + 0x48]
5c3: lea rdx, [rip + 0x5b36]
5ca: mov rcx, rbx
5cd: call qword ptr [rax + 0x98]
5d3: mov rax, qword ptr [rsp + 0x48]
5d8: lea rcx, [rip - 0x207]
5df: mov qword ptr [rax + 0x58], rcx
5e3: mov rcx, rbx
5e6: call 0x5f4
5eb: add rsp, 0x30
5ef: pop rbx
5f0: ret 
5f1: int3 
5f2: int3 
5f3: int3 
5f4: mov r11, rsp
5f7: mov qword ptr [r11 + 0x10], rdx
5fb: push rbx
5fc: sub rsp, 0x40
600: lea rax, [r11 + 0x18]
604: mov qword ptr [r11 + 0x10], 8
60c: mov qword ptr [r11 - 0x28], rax
610: lea r9, [r11 + 0x10]
614: mov rax, qword ptr [rip + 0x620d]
61b: lea rdx, [rip + 0x5b8e]
622: mov rbx, rcx
625: xor r8d, r8d
628: lea rcx, [rip + 0x6199]
62f: call qword ptr [rax + 0x48]
632: test rax, rax
635: jne 0x69f
637: cmp byte ptr [rsp + 0x60], al
63b: je 0x69f
63d: and qword ptr [rsp + 0x38], rax
642: lea r9, [rip + 0x5b47]
649: lea rax, [rip + 0x5bc8]
650: mov qword ptr [rip + 0x5b99], rbx
657: mov qword ptr [rsp + 0x30], rax
65c: lea r8, [rip + 0x5b6d]
663: lea rax, [rip + 0x5aa6]
66a: mov qword ptr [rip + 0x5b87], rbx
671: mov qword ptr [rsp + 0x28], rax
676: lea rdx, [rip + 0x5b03]
67d: lea rax, [rip + 0x5b7c]
684: mov qword ptr [rsp + 0x20], rax
689: lea rcx, [rip + 0x5b68]
690: mov rax, qword ptr [rip + 0x6189]
697: call qword ptr [rax + 0x148]
69d: jmp 0x6a9
69f: movabs rax, 0x8000000000000003
6a9: add rsp, 0x40
6ad: pop rbx
6ae: ret 
6af: int3 
6b0: add rcx, -8
6b4: jmp 0x19e8
6b9: int3 
6ba: int3 
6bb: int3 
6bc: add rcx, -8
6c0: jmp 0x1ad8
6c5: int3 
6c6: int3 
6c7: int3 
6c8: mov rax, rsp
6cb: mov qword ptr [rax + 0x10], rbx
6cf: push rdi
6d0: sub rsp, 0x30
6d4: mov r9, qword ptr [rcx + 0x28]
6d8: lea r8, [rax + 8]
6dc: mov dword ptr [rax - 0x10], 0x10
6e3: mov rbx, rdx
6e6: mov qword ptr [rax - 0x18], rdx
6ea: mov rdi, rcx
6ed: mov rax, qword ptr [rip + 0x612c]
6f4: lea rdx, [rip + 0x5a55]
6fb: mov rcx, rbx
6fe: call qword ptr [rax + 0x118]
704: test rax, rax
707: js 0x729
709: mov rax, qword ptr [rip + 0x6110]
710: lea rdx, [rip + 0x5a39]
717: mov r8, qword ptr [rdi + 0x28]
71b: mov r9, rbx
71e: mov rcx, rbx
721: call qword ptr [rax + 0x120]
727: xor eax, eax
729: mov rbx, qword ptr [rsp + 0x48]
72e: add rsp, 0x30
732: pop rdi
733: ret 
734: mov rax, rsp
737: mov qword ptr [rax + 8], rbx
73b: mov qword ptr [rax + 0x18], rbp
73f: mov qword ptr [rax + 0x10], rdx
743: push rsi
744: push rdi
745: push r13
747: push r14
749: push r15
74b: sub rsp, 0x40
74f: and qword ptr [rax + 0x20], 0
754: mov r13, rcx
757: mov ecx, 0x120