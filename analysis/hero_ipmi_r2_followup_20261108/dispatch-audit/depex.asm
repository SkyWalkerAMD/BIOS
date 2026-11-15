00008824 4c8bdc                   mov r11, rsp
00008827 49895b10                 mov qword ptr [r11 + 0x10], rbx
0000882B 49897318                 mov qword ptr [r11 + 0x18], rsi
0000882F 57                       push rdi
00008830 4883ec40                 sub rsp, 0x40
00008834 4c8b5148                 mov r10, qword ptr [rcx + 0x48]
00008838 488d7950                 lea rdi, [rcx + 0x50]
0000883C 488d4158                 lea rax, [rcx + 0x58]
00008840 488bd9                   mov rbx, rcx
00008843 488d5130                 lea rdx, [rcx + 0x30]
00008847 4533c9                   xor r9d, r9d
0000884A 498d4b08                 lea rcx, [r11 + 8]
0000884E 41b013                   mov r8b, 0x13
00008851 49894be8                 mov qword ptr [r11 - 0x18], rcx
00008855 498bca                   mov rcx, r10
00008858 498943e0                 mov qword ptr [r11 - 0x20], rax
0000885C 49897bd8                 mov qword ptr [r11 - 0x28], rdi
00008860 41ff5218                 call qword ptr [r10 + 0x18]
00008864 488bf0                   mov rsi, rax
00008867 4885c0                   test rax, rax
0000886A 791f                     jns 0x888b
0000886C 48b81800000000000080     movabs rax, 0x8000000000000018
00008876 483bf0                   cmp rsi, rax
00008879 7506                     jne 0x8881
0000887B c6437901                 mov byte ptr [rbx + 0x79], 1
0000887F eb58                     jmp 0x88d9
00008881 48832700                 and qword ptr [rdi], 0
00008885 c6437401                 mov byte ptr [rbx + 0x74], 1
00008889 eb4a                     jmp 0x88d5
0000888B 488b07                   mov rax, qword ptr [rdi]
0000888E 803809                   cmp byte ptr [rax], 9
00008891 7506                     jne 0x8899
00008893 c6437501                 mov byte ptr [rbx + 0x75], 1
00008897 eb04                     jmp 0x889d
00008899 c6437401                 mov byte ptr [rbx + 0x74], 1
0000889D 803800                   cmp byte ptr [rax], 0
000088A0 7506                     jne 0x88a8
000088A2 c6436001                 mov byte ptr [rbx + 0x60], 1
000088A6 eb09                     jmp 0x88b1
000088A8 803801                   cmp byte ptr [rax], 1
000088AB 7504                     jne 0x88b1
000088AD c6436101                 mov byte ptr [rbx + 0x61], 1
000088B1 807b6000                 cmp byte ptr [rbx + 0x60], 0
000088B5 7506                     jne 0x88bd
000088B7 807b6100                 cmp byte ptr [rbx + 0x61], 0
000088BB 7418                     je 0x88d5
000088BD 488d5001                 lea rdx, [rax + 1]
000088C1 488d4b64                 lea rcx, [rbx + 0x64]
000088C5 483bca                   cmp rcx, rdx
000088C8 740b                     je 0x88d5
000088CA 41b810000000             mov r8d, 0x10
000088D0 e85b7bffff               call 0x430
000088D5 c6437900                 mov byte ptr [rbx + 0x79], 0
000088D9 488b5c2458               mov rbx, qword ptr [rsp + 0x58]
000088DE 488bc6                   mov rax, rsi
000088E1 488b742460               mov rsi, qword ptr [rsp + 0x60]
000088E6 4883c440                 add rsp, 0x40
000088EA 5f                       pop rdi
000088EB c3                       ret 
