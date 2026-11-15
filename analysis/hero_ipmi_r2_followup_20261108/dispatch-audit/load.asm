000075B8 488bc4                   mov rax, rsp
000075BB 48895808                 mov qword ptr [rax + 8], rbx
000075BF 48896810                 mov qword ptr [rax + 0x10], rbp
000075C3 48897018                 mov qword ptr [rax + 0x18], rsi
000075C7 48897820                 mov qword ptr [rax + 0x20], rdi
000075CB 4157                     push r15
000075CD 4883ec50                 sub rsp, 0x50
000075D1 498bf1                   mov rsi, r9
000075D4 488bea                   mov rbp, rdx
000075D7 408af9                   mov dil, cl
000075DA 41bf01000000             mov r15d, 1
000075E0 4d85c0                   test r8, r8
000075E3 747c                     je 0x7661
000075E5 4d8bd0                   mov r10, r8
000075E8 4533db                   xor r11d, r11d
000075EB 418a12                   mov dl, byte ptr [r10]
000075EE 80fa7f                   cmp dl, 0x7f
000075F1 740b                     je 0x75fe
000075F3 80faff                   cmp dl, 0xff
000075F6 750d                     jne 0x7605
000075F8 41385201                 cmp byte ptr [r10 + 1], dl
000075FC 7507                     jne 0x7605
000075FE 41807a01ff               cmp byte ptr [r10 + 1], 0xff
00007603 745c                     je 0x7661
00007605 450fb64a03               movzx r9d, byte ptr [r10 + 3]
0000760A 410fb65a02               movzx ebx, byte ptr [r10 + 2]
0000760F 418bc9                   mov ecx, r9d
00007612 c1e108                   shl ecx, 8
00007615 03cb                     add ecx, ebx
00007617 4883f904                 cmp rcx, 4
0000761B 7238                     jb 0x7655
0000761D 4c03d9                   add r11, rcx
00007620 33c0                     xor eax, eax
00007622 488d0d73040100           lea rcx, [rip + 0x10473]
00007629 3a1408                   cmp dl, byte ptr [rax + rcx]
0000762C 7409                     je 0x7637
0000762E 4903c7                   add rax, r15
00007631 4883f806                 cmp rax, 6
00007635 72eb                     jb 0x7622
00007637 4883f806                 cmp rax, 6
0000763B 7418                     je 0x7655
0000763D 4981fb00000100           cmp r11, 0x10000
00007644 770f                     ja 0x7655
00007646 498bc9                   mov rcx, r9
00007649 4c03d3                   add r10, rbx
0000764C 48c1e108                 shl rcx, 8
00007650 4c03d1                   add r10, rcx
00007653 eb96                     jmp 0x75eb
00007655 48b80200000000000080     movabs rax, 0x8000000000000002
0000765F eb3c                     jmp 0x769d
00007661 0fb60550050100           movzx eax, byte ptr [rip + 0x10550]
00007668 4084ff                   test dil, dil
0000766B 4c8bce                   mov r9, rsi
0000766E 488bd5                   mov rdx, rbp
00007671 410f45c7                 cmovne eax, r15d
00007675 408acf                   mov cl, dil
00007678 88053a050100             mov byte ptr [rip + 0x1053a], al
0000767E 488b842488000000         mov rax, qword ptr [rsp + 0x88]
00007686 4889442438               mov qword ptr [rsp + 0x38], rax
0000768B 488b842480000000         mov rax, qword ptr [rsp + 0x80]
00007693 4889442420               mov qword ptr [rsp + 0x20], rax
00007698 e8cffaffff               call 0x716c
0000769D 488b5c2460               mov rbx, qword ptr [rsp + 0x60]
000076A2 488b6c2468               mov rbp, qword ptr [rsp + 0x68]
000076A7 488b742470               mov rsi, qword ptr [rsp + 0x70]
000076AC 488b7c2478               mov rdi, qword ptr [rsp + 0x78]
000076B1 4883c450                 add rsp, 0x50
000076B5 415f                     pop r15
000076B7 c3                       ret 
