558: push rbx
55a: sub rsp, 0x30
55e: mov rax, qword ptr [rdx + 0x60]
562: lea r9, [rsp + 0x40]
567: and qword ptr [rsp + 0x20], 0
56d: mov rbx, rcx
570: mov qword ptr [rip + 0x4b81], rax
577: xor r8d, r8d
57a: mov rax, qword ptr [rdx + 0x58]
57e: mov qword ptr [rip + 0x4b6b], rdx
585: xor edx, edx
587: mov qword ptr [rip + 0x4b72], rax
58e: lea ecx, [rdx + 1]
591: call 0x360
596: mov rax, qword ptr [rip + 0x4b5b]
59d: lea r8, [rsp + 0x48]
5a2: lea rdx, [rip + 0x4537]
5a9: mov rcx, rbx
5ac: call qword ptr [rax + 0x98]
5b2: mov rax, qword ptr [rsp + 0x48]
5b7: lea rcx, [rip - 0x1ea]
5be: mov qword ptr [rax + 0x58], rcx
5c2: mov rcx, rbx
5c5: call 0x5d0
5ca: add rsp, 0x30
5ce: pop rbx
5cf: ret 
5d0: mov r11, rsp
5d3: mov qword ptr [r11 + 0x10], rdx
5d7: push rbx
5d8: sub rsp, 0x40
5dc: lea rax, [r11 + 0x18]
5e0: mov qword ptr [r11 + 0x10], 8
5e8: mov qword ptr [r11 - 0x28], rax
5ec: lea r9, [r11 + 0x10]
5f0: mov rax, qword ptr [rip + 0x4b09]
5f7: lea rdx, [rip + 0x4592]
5fe: mov rbx, rcx
601: xor r8d, r8d
604: lea rcx, [rip + 0x4a95]
60b: call qword ptr [rax + 0x48]
60e: test rax, rax
611: jne 0x67b
613: cmp byte ptr [rsp + 0x60], al
617: je 0x67b
619: and qword ptr [rsp + 0x38], rax
61e: lea r9, [rip + 0x455b]
625: lea rax, [rip + 0x45a4]
62c: mov qword ptr [rip + 0x458d], rbx
633: mov qword ptr [rsp + 0x30], rax
638: lea r8, [rip + 0x4561]
63f: lea rax, [rip + 0x44ca]
646: mov qword ptr [rip + 0x457b], rbx
64d: mov qword ptr [rsp + 0x28], rax
652: lea rdx, [rip + 0x4507]
659: lea rax, [rip + 0x4588]
660: mov qword ptr [rsp + 0x20], rax
665: lea rcx, [rip + 0x455c]
66c: mov rax, qword ptr [rip + 0x4a85]
673: call qword ptr [rax + 0x148]
679: jmp 0x685
67b: movabs rax, 0x8000000000000003
685: add rsp, 0x40
689: pop rbx
68a: ret 
68b: int3 
68c: mov rax, rsp
68f: mov qword ptr [rax + 8], rbx
693: mov qword ptr [rax + 0x10], rbp
697: mov qword ptr [rax + 0x18], rsi
69b: mov qword ptr [rax + 0x20], rdi
69f: push r12
6a1: push r14
6a3: push r15
6a5: sub rsp, 0x30
6a9: mov r14d, dword ptr [rdx + 0xb8]
6b0: xor esi, esi
6b2: mov r12d, dword ptr [rdx + 0xbc]
6b9: mov rbx, rdx
6bc: mov ebp, dword ptr [rdx + 0xc4]
6c2: xor r14d, r12d
6c5: mov r15b, 1
6c8: test ebp, ebp
6ca: je 0x6e4
6cc: lea r8, [rdx + 0xc8]
6d3: mov edx, ebp
6d5: shl rdx, 5
6d9: call 0x45f0
6de: mov rsi, rax
6e1: xor r15b, r15b
6e4: lea rdi, [rbx + 0x20]
6e8: mov rcx, rdi
6eb: call 0x2b10
6f0: test rax, rax
6f3: js 0x730
6f5: xor r8d, r8d
6f8: xor edx, edx
6fa: mov rcx, rdi
6fd: call 0x2698
702: test rax, rax
705: js 0x730
707: cmp dword ptr [rbx + 0xa0], 2
70e: jne 0x72b
710: mov qword ptr [rsp + 0x28], rsi
715: mov r9b, r15b
718: mov r8d, r14d
71b: mov qword ptr [rsp + 0x20], rbp
720: mov edx, r12d
723: mov rcx, rdi
726: call 0x2f88
72b: test rax, rax
72e: jns 0x740
730: mov rcx, rdi
733: call 0x2210
738: mov rcx, rdi
73b: call 0x1afc
740: test rsi, rsi
743: je 0x752
745: mov rax, qword ptr [rip + 0x49ac]
74c: mov rcx, rsi
74f: call qword ptr [rax + 0x48]
752: mov rbx, qword ptr [rsp + 0x50]