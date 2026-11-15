558: push rbx
55a: sub rsp, 0x30
55e: mov rax, qword ptr [rdx + 0x60]
562: lea r9, [rsp + 0x40]
567: and qword ptr [rsp + 0x20], 0
56d: mov rbx, rcx
570: mov qword ptr [rip + 0xb179], rax
577: xor r8d, r8d
57a: mov rax, qword ptr [rdx + 0x58]
57e: mov qword ptr [rip + 0xb163], rdx
585: xor edx, edx
587: mov qword ptr [rip + 0xb16a], rax
58e: lea ecx, [rdx + 1]
591: call 0x360
596: mov rax, qword ptr [rip + 0xb153]
59d: lea r8, [rip + 0xb164]
5a4: xor edx, edx
5a6: lea rcx, [rip + 0xa783]
5ad: call qword ptr [rax + 0x140]
5b3: mov rax, qword ptr [rip + 0xb136]
5ba: lea r8, [rsp + 0x48]
5bf: lea rdx, [rip + 0xa6ba]
5c6: mov rcx, rbx
5c9: call qword ptr [rax + 0x98]
5cf: mov rax, qword ptr [rsp + 0x48]
5d4: lea rcx, [rip - 0x207]
5db: mov qword ptr [rax + 0x58], rcx
5df: mov rcx, rbx
5e2: call 0x640
5e7: add rsp, 0x30
5eb: pop rbx
5ec: ret 
5ed: int3 
5ee: int3 
5ef: int3 
5f0: sub rsp, 0x28
5f4: mov rax, qword ptr [rip + 0xb0dd]
5fb: dec rax
5fe: mov qword ptr [rip + 0xb0d3], rax
605: test rax, rax
608: jg 0x639
60a: mov rax, qword ptr [rip + 0xb0df]
611: xor r8d, r8d
614: mov rcx, qword ptr [rip + 0xb0b5]
61b: xor edx, edx
61d: call qword ptr [rax + 0x58]
620: mov rax, qword ptr [rip + 0xb0c9]
627: mov rcx, qword ptr [rip + 0xb0a2]
62e: call qword ptr [rax + 0x70]
631: and qword ptr [rip + 0xb097], 0
639: add rsp, 0x28
63d: ret 
63e: int3 
63f: int3 
640: mov qword ptr [rsp + 8], rbx
645: mov qword ptr [rsp + 0x10], rdx
64a: push rbp
64b: mov rbp, rsp
64e: sub rsp, 0x50
652: lea rax, [rbp + 0x20]
656: mov qword ptr [rbp + 0x18], 8
65e: mov qword ptr [rsp + 0x20], rax
663: lea r9, [rbp + 0x18]
667: mov rax, qword ptr [rip + 0xb08a]
66e: lea rdx, [rip + 0xa6db]
675: mov rbx, rcx
678: xor r8d, r8d
67b: lea rcx, [rip + 0xb006]
682: call qword ptr [rax + 0x48]
685: test rax, rax
688: jne 0x7d7
68e: cmp byte ptr [rbp + 0x20], al
691: je 0x7d7
697: mov r9, rbx
69a: lea r8, [rip + 0xa81f]
6a1: mov rcx, rbx
6a4: call 0x8bb4
6a9: test rax, rax
6ac: js 0x7e1
6b2: xor r9d, r9d
6b5: lea r8, [rip + 0xa6c4]
6bc: mov rcx, rbx
6bf: call 0x8bb4
6c4: mov rbx, rax
6c7: test rax, rax
6ca: jns 0x727
6cc: and qword ptr [rsp + 0x38], 0
6d2: lea rax, [rip + 0xa857]
6d9: mov rcx, qword ptr [rip + 0xa808]
6e0: lea r9, [rip + 0xa639]
6e7: mov qword ptr [rsp + 0x30], rax
6ec: lea r8, [rip + 0xa7cd]
6f3: lea rax, [rip + 0xa596]
6fa: mov qword ptr [rsp + 0x28], rax
6ff: lea rdx, [rip + 0xa5ea]
706: lea rax, [rip + 0xa80b]
70d: mov qword ptr [rsp + 0x20], rax
712: mov rax, qword ptr [rip + 0xafd7]
719: call qword ptr [rax + 0x150]
71f: mov rax, rbx
722: jmp 0x7e1
727: xor ebx, ebx
729: lea rcx, [rbp + 0x18]
72d: call 0x3a2
732: test al, al
734: jne 0x78e
736: inc ebx
738: cmp ebx, 0xa
73b: jb 0x729
73d: mov rax, qword ptr [rip + 0xafb4]
744: lea rcx, [rbp - 0x10]
748: xor edx, edx
74a: call qword ptr [rax + 0x18]
74d: movzx eax, byte ptr [rbp - 0xd]
751: lea rcx, [rbp + 0x20]