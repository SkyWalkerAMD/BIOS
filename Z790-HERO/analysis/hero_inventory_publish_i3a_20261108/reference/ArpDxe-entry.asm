55c: push rbx
55e: sub rsp, 0x30
562: mov rax, qword ptr [rdx + 0x60]
566: lea r9, [rsp + 0x40]
56b: and qword ptr [rsp + 0x20], 0
571: mov rbx, rcx
574: mov qword ptr [rip + 0x2a3d], rax
57b: xor r8d, r8d
57e: mov rax, qword ptr [rdx + 0x58]
582: mov qword ptr [rip + 0x2a27], rdx
589: xor edx, edx
58b: mov qword ptr [rip + 0x2a2e], rax
592: lea ecx, [rdx + 1]
595: call 0x360
59a: mov rax, qword ptr [rip + 0x2a17]
5a1: lea r8, [rip + 0x2a20]
5a8: xor edx, edx
5aa: lea rcx, [rip + 0x282f]
5b1: call qword ptr [rax + 0x140]
5b7: mov rax, qword ptr [rip + 0x29fa]
5be: lea r8, [rsp + 0x48]
5c3: lea rdx, [rip + 0x27b6]
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
614: mov rax, qword ptr [rip + 0x29a5]
61b: lea rdx, [rip + 0x27ce]
622: mov rbx, rcx
625: xor r8d, r8d
628: lea rcx, [rip + 0x2939]
62f: call qword ptr [rax + 0x48]
632: test rax, rax
635: jne 0x69f
637: cmp byte ptr [rsp + 0x60], al
63b: je 0x69f
63d: and qword ptr [rsp + 0x38], rax
642: lea r9, [rip + 0x2787]
649: lea rax, [rip + 0x2800]
650: mov qword ptr [rip + 0x27e9], rbx
657: mov qword ptr [rsp + 0x30], rax
65c: lea r8, [rip + 0x27bd]
663: lea rax, [rip + 0x2726]
66a: mov qword ptr [rip + 0x27d7], rbx
671: mov qword ptr [rsp + 0x28], rax
676: lea rdx, [rip + 0x2733]
67d: lea rax, [rip + 0x27e4]
684: mov qword ptr [rsp + 0x20], rax
689: lea rcx, [rip + 0x27b8]
690: mov rax, qword ptr [rip + 0x2921]
697: call qword ptr [rax + 0x148]
69d: jmp 0x6a9
69f: movabs rax, 0x8000000000000003
6a9: add rsp, 0x40
6ad: pop rbx
6ae: ret 
6af: int3 
6b0: mov r11, rsp
6b3: mov qword ptr [r11 + 0x10], rbx
6b7: mov qword ptr [r11 + 0x18], rbp
6bb: mov qword ptr [r11 + 0x20], rsi
6bf: push rdi
6c0: sub rsp, 0x30
6c4: mov dword ptr [r8], 0x53505241
6cb: lea rax, [r8 + 0x300]
6d2: mov qword ptr [rax], rax
6d5: mov rsi, rdx
6d8: mov qword ptr [rax + 8], rax
6dc: mov rbx, r8
6df: lea rax, [r8 + 0x310]
6e6: mov dword ptr [rsp + 0x28], 2
6ee: mov qword ptr [rax], rax
6f1: mov rbp, rcx
6f4: mov qword ptr [rax + 8], rax
6f8: mov r9, rcx
6fb: lea rax, [r8 + 0x320]
702: mov qword ptr [r11 - 0x18], rdx
706: mov qword ptr [rax], rax
709: mov qword ptr [rax + 8], rax
70d: lea rax, [r8 + 0x330]
714: mov qword ptr [rax], rax
717: mov qword ptr [rax + 8], rax
71b: lea rax, [rip + 0x4ce]
722: mov qword ptr [r8 + 8], rax
726: lea rax, [rip + 0x67f]
72d: mov qword ptr [r8 + 0x10], rax
731: mov rax, qword ptr [rip + 0x2880]
738: mov qword ptr [r8 + 0x20], rcx
73c: mov rcx, rsi
73f: mov qword ptr [r8 + 0x28], rdx
743: lea r8, [r11 + 8]
747: lea rdx, [rip + 0x2652]
74e: call qword ptr [rax + 0x118]
754: test rax, rax