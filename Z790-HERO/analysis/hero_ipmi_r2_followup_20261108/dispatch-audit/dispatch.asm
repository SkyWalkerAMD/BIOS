00008A0C 48895c2410               mov qword ptr [rsp + 0x10], rbx
00008A11 48896c2418               mov qword ptr [rsp + 0x18], rbp
00008A16 56                       push rsi
00008A17 57                       push rdi
00008A18 4154                     push r12
00008A1A 4155                     push r13
00008A1C 4156                     push r14
00008A1E 4883ec40                 sub rsp, 0x40
00008A22 4533f6                   xor r14d, r14d
00008A25 443835acf10000           cmp byte ptr [rip + 0xf1ac], r14b
00008A2C 740f                     je 0x8a3d
00008A2E 48b81400000000000080     movabs rax, 0x8000000000000014
00008A38 e96f010000               jmp 0x8bac
00008A3D 4533c9                   xor r9d, r9d
00008A40 c60591f1000001           mov byte ptr [rip + 0xf191], 1
00008A47 488d442470               lea rax, [rsp + 0x70]
00008A4C b900020000               mov ecx, 0x200
00008A51 4889442428               mov qword ptr [rsp + 0x28], rax
00008A56 4c8d0567710000           lea r8, [rip + 0x7167]
00008A5D 488d05acd10000           lea rax, [rip + 0xd1ac]
00008A64 418d5110                 lea edx, [r9 + 0x10]
00008A68 4889442420               mov qword ptr [rsp + 0x20], rax
00008A6D e87af8ffff               call 0x82ec
00008A72 4885c0                   test rax, rax
00008A75 0f8831010000             js 0x8bac
00008A7B 48be0e00000000000080     movabs rsi, 0x800000000000000e
00008A85 4c8d2d64e10000           lea r13, [rip + 0xe164]
00008A8C 4c8d257de10000           lea r12, [rip + 0xe17d]
00008A93 e996000000               jmp 0x8b2e
00008A98 488d4368                 lea rax, [rbx + 0x68]
00008A9C 4c3930                   cmp qword ptr [rax], r14
00008A9F 0f8520010000             jne 0x8bc5
00008AA5 44387370                 cmp byte ptr [rbx + 0x70], r14b
00008AA9 0f8516010000             jne 0x8bc5
00008AAF 4c8b4328                 mov r8, qword ptr [rbx + 0x28]
00008AB3 4533c9                   xor r9d, r9d
00008AB6 488b1583f00000           mov rdx, qword ptr [rip + 0xf083]
00008ABD 33c9                     xor ecx, ecx
00008ABF 4889442428               mov qword ptr [rsp + 0x28], rax
00008AC4 4c89742420               mov qword ptr [rsp + 0x20], r14
00008AC9 e8eaeaffff               call 0x75b8
00008ACE 488bf8                   mov rdi, rax
00008AD1 4885c0                   test rax, rax
00008AD4 0f89eb000000             jns 0x8bc5
00008ADA 488d0df7e00000           lea rcx, [rip + 0xe0f7]
00008AE1 e8964b0000               call 0xd67c
00008AE6 48b81a00000000000080     movabs rax, 0x800000000000001a
00008AF0 483bf8                   cmp rdi, rax
00008AF3 7506                     jne 0x8afb
00008AF5 c6435f01                 mov byte ptr [rbx + 0x5f], 1
00008AF9 eb04                     jmp 0x8aff
00008AFB c6436001                 mov byte ptr [rbx + 0x60], 1
00008AFF 4488735e                 mov byte ptr [rbx + 0x5e], r14b
00008B03 488b0b                   mov rcx, qword ptr [rbx]
00008B06 488b4308                 mov rax, qword ptr [rbx + 8]
00008B0A 48894108                 mov qword ptr [rcx + 8], rax
00008B0E 488b4b08                 mov rcx, qword ptr [rbx + 8]
00008B12 488b03                   mov rax, qword ptr [rbx]
00008B15 488901                   mov qword ptr [rcx], rax
00008B18 488b0dc1e00000           mov rcx, qword ptr [rip + 0xe0c1]
00008B1F c705bfe0000001000000     mov dword ptr [rip + 0xe0bf], 1
00008B29 e802310000               call 0xbc30
00008B2E 488b1dbbe00000           mov rbx, qword ptr [rip + 0xe0bb]
00008B35 493bdd                   cmp rbx, r13
00008B38 0f855affffff             jne 0x8a98
00008B3E 4885f6                   test rsi, rsi
00008B41 780a                     js 0x8b4d
00008B43 488b4c2470               mov rcx, qword ptr [rsp + 0x70]
00008B48 e8abf9ffff               call 0x84f8
00008B4D 488b3dbce00000           mov rdi, qword ptr [rip + 0xe0bc]
00008B54 418aee                   mov bpl, r14b
00008B57 493bfc                   cmp rdi, r12
00008B5A 743c                     je 0x8b98
00008B5C 488d5ff8                 lea rbx, [rdi - 8]
00008B60 44387379                 cmp byte ptr [rbx + 0x79], r14b
00008B64 7408                     je 0x8b6e
00008B66 488bcb                   mov rcx, rbx
00008B69 e8b6fcffff               call 0x8824
00008B6E 44387374                 cmp byte ptr [rbx + 0x74], r14b
00008B72 7417                     je 0x8b8b
00008B74 488bcb                   mov rcx, rbx
00008B77 e818540000               call 0xdf94
00008B7C 84c0                     test al, al
00008B7E 740b                     je 0x8b8b
00008B80 488bcb                   mov rcx, rbx
00008B83 e8dc000000               call 0x8c64
00008B88 40b501                   mov bpl, 1
00008B8B 488b3f                   mov rdi, qword ptr [rdi]
00008B8E 493bfc                   cmp rdi, r12
00008B91 75c9                     jne 0x8b5c
00008B93 4084ed                   test bpl, bpl
00008B96 7596                     jne 0x8b2e
00008B98 488b4c2470               mov rcx, qword ptr [rsp + 0x70]
00008B9D e856fbffff               call 0x86f8
00008BA2 488bc6                   mov rax, rsi
00008BA5 4488352cf00000           mov byte ptr [rip + 0xf02c], r14b
00008BAC 4c8d5c2440               lea r11, [rsp + 0x40]
00008BB1 498b5b38                 mov rbx, qword ptr [r11 + 0x38]
00008BB5 498b6b40                 mov rbp, qword ptr [r11 + 0x40]
00008BB9 498be3                   mov rsp, r11
00008BBC 415e                     pop r14
00008BBE 415d                     pop r13
00008BC0 415c                     pop r12
00008BC2 5f                       pop rdi
00008BC3 5e                       pop rsi
00008BC4 c3                       ret 
00008BC5 488d0d0ce00000           lea rcx, [rip + 0xe00c]
00008BCC e8ab4a0000               call 0xd67c
00008BD1 4488735e                 mov byte ptr [rbx + 0x5e], r14b
00008BD5 c6436001                 mov byte ptr [rbx + 0x60], 1
00008BD9 488b0b                   mov rcx, qword ptr [rbx]
00008BDC 488b4308                 mov rax, qword ptr [rbx + 8]
00008BE0 48894108                 mov qword ptr [rcx + 8], rax
00008BE4 488b4b08                 mov rcx, qword ptr [rbx + 8]
00008BE8 488b03                   mov rax, qword ptr [rbx]
00008BEB 488901                   mov qword ptr [rcx], rax
00008BEE 488b0debdf0000           mov rcx, qword ptr [rip + 0xdfeb]
00008BF5 c705e9df000001000000     mov dword ptr [rip + 0xdfe9], 1
00008BFF e82c300000               call 0xbc30
00008C04 44387370                 cmp byte ptr [rbx + 0x70], r14b
00008C08 7413                     je 0x8c1d
00008C0A 488b5310                 mov rdx, qword ptr [rbx + 0x10]
00008C0E 4c8d4318                 lea r8, [rbx + 0x18]
00008C12 488b4b30                 mov rcx, qword ptr [rbx + 0x30]
00008C16 e86d040000               call 0x9088
00008C1B eb3f                     jmp 0x8c5c
00008C1D 4883c368                 add rbx, 0x68
00008C21 4533c9                   xor r9d, r9d
00008C24 48895c2428               mov qword ptr [rsp + 0x28], rbx
00008C29 ba02000403               mov edx, 0x3040002
00008C2E 4c89742420               mov qword ptr [rsp + 0x20], r14
00008C33 e80c690000               call 0xf544
00008C38 488b0b                   mov rcx, qword ptr [rbx]
00008C3B 4533c0                   xor r8d, r8d
00008C3E 33d2                     xor edx, edx
00008C40 e873eaffff               call 0x76b8
00008C45 4533c9                   xor r9d, r9d
00008C48 48895c2428               mov qword ptr [rsp + 0x28], rbx
00008C4D ba03000403               mov edx, 0x3040003
00008C52 4c89742420               mov qword ptr [rsp + 0x20], r14
00008C57 e8e8680000               call 0xf544
00008C5C 498bf6                   mov rsi, r14
00008C5F e9cafeffff               jmp 0x8b2e
00008C64 48895c2408               mov qword ptr [rsp + 8], rbx
00008C69 48896c2410               mov qword ptr [rsp + 0x10], rbp
00008C6E 57                       push rdi
00008C6F 4883ec20                 sub rsp, 0x20
00008C73 488b3d96df0000           mov rdi, qword ptr [rip + 0xdf96]
00008C7A 488d2d8fdf0000           lea rbp, [rip + 0xdf8f]
00008C81 488bd9                   mov rbx, rcx
00008C84 eb31                     jmp 0x8cb7
00008C86 488d4ff8                 lea rcx, [rdi - 8]
00008C8A 80796000                 cmp byte ptr [rcx + 0x60], 0
00008C8E 7424                     je 0x8cb4
00008C90 80797400                 cmp byte ptr [rcx + 0x74], 0
00008C94 741e                     je 0x8cb4
00008C96 483bcb                   cmp rcx, rbx
00008C99 7419                     je 0x8cb4
00008C9B 488b4164                 mov rax, qword ptr [rcx + 0x64]
00008C9F 48394330                 cmp qword ptr [rbx + 0x30], rax
00008CA3 750f                     jne 0x8cb4
00008CA5 488b416c                 mov rax, qword ptr [rcx + 0x6c]
00008CA9 48394338                 cmp qword ptr [rbx + 0x38], rax
00008CAD 7505                     jne 0x8cb4
00008CAF e8b0ffffff               call 0x8c64
00008CB4 488b3f                   mov rdi, qword ptr [rdi]
00008CB7 483bfd                   cmp rdi, rbp
00008CBA 75ca                     jne 0x8c86
00008CBC 488d0d15df0000           lea rcx, [rip + 0xdf15]
00008CC3 e8b4490000               call 0xd67c
00008CC8 c6437400                 mov byte ptr [rbx + 0x74], 0
00008CCC 488d4b18                 lea rcx, [rbx + 0x18]
00008CD0 c6437601                 mov byte ptr [rbx + 0x76], 1
00008CD4 488d0515df0000           lea rax, [rip + 0xdf15]
00008CDB 488901                   mov qword ptr [rcx], rax
00008CDE 488b0513df0000           mov rax, qword ptr [rip + 0xdf13]
00008CE5 48894108                 mov qword ptr [rcx + 8], rax
00008CE9 488908                   mov qword ptr [rax], rcx
00008CEC 48890d05df0000           mov qword ptr [rip + 0xdf05], rcx
00008CF3 488b0de6de0000           mov rcx, qword ptr [rip + 0xdee6]
00008CFA c705e4de000001000000     mov dword ptr [rip + 0xdee4], 1
00008D04 e8272f0000               call 0xbc30
00008D09 488b3d00df0000           mov rdi, qword ptr [rip + 0xdf00]
00008D10 eb31                     jmp 0x8d43
00008D12 488d4ff8                 lea rcx, [rdi - 8]
00008D16 80796100                 cmp byte ptr [rcx + 0x61], 0
00008D1A 7424                     je 0x8d40
00008D1C 80797400                 cmp byte ptr [rcx + 0x74], 0
00008D20 741e                     je 0x8d40
00008D22 483bcb                   cmp rcx, rbx
00008D25 7419                     je 0x8d40
00008D27 488b4164                 mov rax, qword ptr [rcx + 0x64]
00008D2B 48394330                 cmp qword ptr [rbx + 0x30], rax
00008D2F 750f                     jne 0x8d40
00008D31 488b416c                 mov rax, qword ptr [rcx + 0x6c]
00008D35 48394338                 cmp qword ptr [rbx + 0x38], rax
00008D39 7505                     jne 0x8d40
00008D3B e824ffffff               call 0x8c64
00008D40 488b3f                   mov rdi, qword ptr [rdi]
00008D43 483bfd                   cmp rdi, rbp
00008D46 75ca                     jne 0x8d12
00008D48 488b5c2430               mov rbx, qword ptr [rsp + 0x30]
00008D4D 488b6c2438               mov rbp, qword ptr [rsp + 0x38]
00008D52 4883c420                 add rsp, 0x20
00008D56 5f                       pop rdi
00008D57 c3                       ret 
00008D58 4055                     push rbp
00008D5A 53                       push rbx
00008D5B 56                       push rsi
00008D5C 57                       push rdi
00008D5D 4154                     push r12
00008D5F 4156                     push r14
00008D61 4157                     push r15
00008D63 488bec                   mov rbp, rsp
00008D66 4883ec40                 sub rsp, 0x40
00008D6A 4c8b0dcfed0000           mov r9, qword ptr [rip + 0xedcf]
00008D71 4c8d4558                 lea r8, [rbp + 0x58]
00008D75 4533f6                   xor r14d, r14d
00008D78 488d15c1cc0000           lea rdx, [rip + 0xccc1]
00008D7F 488bf1                   mov rsi, rcx
00008D82 4c897548                 mov qword ptr [rbp + 0x48], r14
