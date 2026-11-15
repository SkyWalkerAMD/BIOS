578: push rbx
57a: sub rsp, 0x20
57e: mov rbx, rcx
581: call 0x5c0
586: mov rax, qword ptr [rip + 0xbf13]
58d: lea r8, [rsp + 0x40]
592: lea rdx, [rip + 0xb667]
599: mov rcx, rbx
59c: call qword ptr [rax + 0x98]
5a2: mov rax, qword ptr [rsp + 0x40]
5a7: lea rcx, [rip - 0x1ba]
5ae: mov qword ptr [rax + 0x58], rcx
5b2: mov rcx, rbx
5b5: call 0x6b4
5ba: add rsp, 0x20
5be: pop rbx
5bf: ret 
5c0: mov qword ptr [rsp + 8], rcx
5c5: sub rsp, 0x38
5c9: mov rax, qword ptr [rdx + 0x60]
5cd: lea r9, [rsp + 0x40]
5d2: and qword ptr [rsp + 0x20], 0
5d8: xor r8d, r8d
5db: mov qword ptr [rip + 0xbebe], rax
5e2: mov rax, qword ptr [rdx + 0x58]
5e6: mov qword ptr [rip + 0xbeab], rdx
5ed: xor edx, edx
5ef: mov qword ptr [rip + 0xbeb2], rax
5f6: lea ecx, [rdx + 1]
5f9: call 0x380
5fe: mov rax, qword ptr [rip + 0xbe9b]
605: lea r8, [rip + 0xbeac]
60c: xor edx, edx
60e: lea rcx, [rip + 0xb6bb]
615: call qword ptr [rax + 0x140]
61b: mov rax, qword ptr [rip + 0xbe7e]
622: lea r8, [rip + 0xbea7]
629: xor edx, edx
62b: lea rcx, [rip + 0xb68e]
632: call qword ptr [rax + 0x140]
638: mov rax, qword ptr [rip + 0xbe61]
63f: lea r8, [rip + 0xbe6a]
646: xor edx, edx
648: lea rcx, [rip + 0xb621]
64f: call qword ptr [rax + 0x140]
655: mov rax, qword ptr [rip + 0xbe44]
65c: lea r8, [rip + 0xbe5d]
663: xor edx, edx
665: lea rcx, [rip + 0xb724]
66c: call qword ptr [rax + 0x140]
672: mov rax, qword ptr [rip + 0xbe27]
679: lea r8, [rip + 0xbe48]
680: xor edx, edx
682: lea rcx, [rip + 0xb617]
689: call qword ptr [rax + 0x140]
68f: mov rax, qword ptr [rip + 0xbe0a]
696: lea r8, [rip + 0xbe3b]
69d: xor edx, edx
69f: lea rcx, [rip + 0xb69a]
6a6: add rsp, 0x38
6aa: jmp qword ptr [rax + 0x140]
6b1: int3 
6b2: int3 
6b3: int3 
6b4: mov r11, rsp
6b7: mov qword ptr [r11 + 0x10], rdx
6bb: push rbx
6bc: sub rsp, 0x40
6c0: lea rax, [r11 + 0x18]
6c4: mov qword ptr [r11 + 0x10], 8
6cc: mov qword ptr [r11 - 0x28], rax
6d0: lea r9, [r11 + 0x10]
6d4: mov rax, qword ptr [rip + 0xbdcd]
6db: lea rdx, [rip + 0xb67e]
6e2: mov rbx, rcx
6e5: xor r8d, r8d
6e8: lea rcx, [rip + 0xbd39]
6ef: call qword ptr [rax + 0x48]
6f2: test rax, rax
6f5: jne 0x788
6fb: cmp byte ptr [rsp + 0x60], al
6ff: je 0x788
705: lea rax, [rsp + 0x68]
70a: xor r9d, r9d
70d: lea r8, [rip + 0x84]
714: mov qword ptr [rsp + 0x20], rax
719: lea rcx, [rip + 0xb540]
720: call 0xa1e0
725: and qword ptr [rsp + 0x38], 0
72b: lea rax, [rip + 0xb706]
732: mov qword ptr [rsp + 0x30], rax
737: lea r9, [rip + 0xb5f2]
73e: lea rax, [rip + 0xb4cb]
745: mov qword ptr [rip + 0xb674], rbx
74c: mov qword ptr [rsp + 0x28], rax
751: lea r8, [rip + 0xb648]
758: lea rax, [rip + 0xb6c1]
75f: mov qword ptr [rip + 0xb662], rbx
766: mov qword ptr [rsp + 0x20], rax
76b: lea rdx, [rip + 0xb59e]