00008FA4 488bc4                   mov rax, rsp
00008FA7 48895808                 mov qword ptr [rax + 8], rbx
00008FAB 48896810                 mov qword ptr [rax + 0x10], rbp
00008FAF 48897018                 mov qword ptr [rax + 0x18], rsi
00008FB3 48897820                 mov qword ptr [rax + 0x20], rdi
00008FB7 4156                     push r14
00008FB9 4883ec20                 sub rsp, 0x20
00008FBD 488bea                   mov rbp, rdx
00008FC0 4c8bf1                   mov r14, rcx
00008FC3 ba90000000               mov edx, 0x90
00008FC8 b904000000               mov ecx, 4
00008FCD 418ad9                   mov bl, r9b
00008FD0 498bf0                   mov rsi, r8
00008FD3 e85c690000               call 0xf934
00008FD8 488bf8                   mov rdi, rax
00008FDB 80fb0b                   cmp bl, 0xb
00008FDE 7507                     jne 0x8fe7
00008FE0 c6808800000001           mov byte ptr [rax + 0x88], 1
00008FE7 48c70064727672           mov qword ptr [rax], 0x72767264
00008FEE 4c8bc6                   mov r8, rsi
00008FF1 488b0e                   mov rcx, qword ptr [rsi]
00008FF4 488bd5                   mov rdx, rbp
00008FF7 48894830                 mov qword ptr [rax + 0x30], rcx
00008FFB 488b4e08                 mov rcx, qword ptr [rsi + 8]
00008FFF 48894838                 mov qword ptr [rax + 0x38], rcx
00009003 48896828                 mov qword ptr [rax + 0x28], rbp
00009007 4c897048                 mov qword ptr [rax + 0x48], r14
0000900B e8fcfeffff               call 0x8f0c
00009010 488bcf                   mov rcx, rdi
00009013 48894740                 mov qword ptr [rdi + 0x40], rax
00009017 e808f8ffff               call 0x8824
0000901C 488d0db5db0000           lea rcx, [rip + 0xdbb5]
00009023 e854460000               call 0xd67c
00009028 488d4f08                 lea rcx, [rdi + 8]
0000902C 488d05dddb0000           lea rax, [rip + 0xdbdd]
00009033 488901                   mov qword ptr [rcx], rax
00009036 488b05dbdb0000           mov rax, qword ptr [rip + 0xdbdb]
0000903D 48894108                 mov qword ptr [rcx + 8], rax
00009041 488b05d0db0000           mov rax, qword ptr [rip + 0xdbd0]
00009048 488908                   mov qword ptr [rax], rcx
0000904B 48890dc6db0000           mov qword ptr [rip + 0xdbc6], rcx
00009052 488b0d87db0000           mov rcx, qword ptr [rip + 0xdb87]
00009059 c70585db000001000000     mov dword ptr [rip + 0xdb85], 1
00009063 e8c82b0000               call 0xbc30
00009068 488b5c2430               mov rbx, qword ptr [rsp + 0x30]
0000906D 33c0                     xor eax, eax
0000906F 488b6c2438               mov rbp, qword ptr [rsp + 0x38]
00009074 488b742440               mov rsi, qword ptr [rsp + 0x40]
00009079 488b7c2448               mov rdi, qword ptr [rsp + 0x48]
0000907E 4883c420                 add rsp, 0x20
00009082 415e                     pop r14
00009084 c3                       ret 
00009085 cc                       int3 
00009086 cc                       int3 
00009087 cc                       int3 
