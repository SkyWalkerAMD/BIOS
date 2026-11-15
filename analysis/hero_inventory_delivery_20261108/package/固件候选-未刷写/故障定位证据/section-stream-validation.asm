0000E55C 0000                     add byte ptr [rax], al
0000E55E 498d43c8                 lea rax, [r11 - 0x38]
0000E562 49895bb8                 mov qword ptr [r11 - 0x48], rbx
0000E566 4d8d4bd0                 lea r9, [r11 - 0x30]
0000E56A 498943b0                 mov qword ptr [r11 - 0x50], rax
0000E56E 4533c0                   xor r8d, r8d
0000E571 498d4310                 lea rax, [r11 + 0x10]
0000E575 498943a8                 mov qword ptr [r11 - 0x58], rax
0000E579 e8aefdffff               call 0xe32c
0000E57E 488b7768                 mov rsi, qword ptr [rdi + 0x68]
0000E582 4885c0                   test rax, rax
0000E585 0f8832010000             js 0xe6bd
0000E58B 488b4610                 mov rax, qword ptr [rsi + 0x10]
0000E58F f6401301                 test byte ptr [rax + 0x13], 1
0000E593 4c8d5820                 lea r11, [rax + 0x20]
0000E597 7504                     jne 0xe59d
0000E599 4c8d5818                 lea r11, [rax + 0x18]
0000E59D 80bc248800000001         cmp byte ptr [rsp + 0x88], 1
0000E5A5 750f                     jne 0xe5b6
0000E5A7 48b90e00000000000080     movabs rcx, 0x800000000000000e
0000E5B1 e9f8000000               jmp 0xe6ae
0000E5B6 4883c618                 add rsi, 0x18
0000E5BA 48833e00                 cmp qword ptr [rsi], 0
0000E5BE 0f8590000000             jne 0xe654
0000E5C4 4c8b542448               mov r10, qword ptr [rsp + 0x48]
0000E5C9 33d2                     xor edx, edx
0000E5CB 498bcb                   mov rcx, r11
0000E5CE 4d85d2                   test r10, r10
0000E5D1 7457                     je 0xe62a
0000E5D3 440fb64102               movzx r8d, byte ptr [rcx + 2]
0000E5D8 440fb64901               movzx r9d, byte ptr [rcx + 1]
0000E5DD 418bc0                   mov eax, r8d
0000E5E0 440fb631                 movzx r14d, byte ptr [rcx]
0000E5E4 c1e008                   shl eax, 8
0000E5E7 410bc1                   or eax, r9d
0000E5EA c1e008                   shl eax, 8
0000E5ED 410bc6                   or eax, r14d
0000E5F0 3dffffff00               cmp eax, 0xffffff
0000E5F5 7506                     jne 0xe5fd
0000E5F7 448b4104                 mov r8d, dword ptr [rcx + 4]
0000E5FB eb0e                     jmp 0xe60b
0000E5FD 49c1e008                 shl r8, 8
0000E601 4d0bc1                   or r8, r9
0000E604 49c1e008                 shl r8, 8
0000E608 4d0bc6                   or r8, r14
0000E60B 4903d0                   add rdx, r8
0000E60E 493bd2                   cmp rdx, r10
0000E611 7423                     je 0xe636
0000E613 4903c8                   add rcx, r8
0000E616 488bc1                   mov rax, rcx
0000E619 48f7d8                   neg rax
0000E61C 83e003                   and eax, 3
0000E61F 4803d0                   add rdx, rax
0000E622 4803c8                   add rcx, rax
0000E625 493bd2                   cmp rdx, r10
0000E628 72a9                     jb 0xe5d3
0000E62A 48b90200000000000080     movabs rcx, 0x8000000000000002
0000E634 eb78                     jmp 0xe6ae
0000E636 4533c9                   xor r9d, r9d
0000E639 4889742420               mov qword ptr [rsp + 0x20], rsi
0000E63E 4533c0                   xor r8d, r8d
0000E641 498bd3                   mov rdx, r11
0000E644 498bca                   mov rcx, r10
0000E647 e8c4c7ffff               call 0xae10
0000E64C 488bc8                   mov rcx, rax
0000E64F 4885c0                   test rax, rax
0000E652 785a                     js 0xe6ae
0000E654 8a942490000000           mov dl, byte ptr [rsp + 0x90]
0000E65B 488b0e                   mov rcx, qword ptr [rsi]
0000E65E 8ac2                     mov al, dl
0000E660 f6d8                     neg al
0000E662 488d842490000000         lea rax, [rsp + 0x90]
0000E66A 4d1bc9                   sbb r9, r9
0000E66D 4d23cf                   and r9, r15
0000E670 f6da                     neg dl
0000E672 481bd2                   sbb rdx, rdx
0000E675 4823d0                   and rdx, rax
0000E678 8a8785000000             mov al, byte ptr [rdi + 0x85]
0000E67E 88442438                 mov byte ptr [rsp + 0x38], al
0000E682 488b8424a8000000         mov rax, qword ptr [rsp + 0xa8]
0000E68A 48895c2430               mov qword ptr [rsp + 0x30], rbx
0000E68F 4889442428               mov qword ptr [rsp + 0x28], rax
0000E694 48896c2420               mov qword ptr [rsp + 0x20], rbp
