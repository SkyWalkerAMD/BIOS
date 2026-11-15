0464 mov        qword ptr [rsp + 8], rbx
0469 mov        qword ptr [rsp + 0x10], rdi
046e push       rbp
046f lea        rbp, [rsp - 0xd20]
0477 sub        rsp, 0xe20
047e xor        ebx, ebx
0480 mov        dword ptr [rsp + 0x30], 0xec87d643
0488 cmp        qword ptr [rip + 0x1f59], rbx
048f mov        rdi, rcx
0492 mov        dword ptr [rsp + 0x34], 0x4bb5eba4
049a mov        dword ptr [rsp + 0x38], 0x3e3fe5a1
04a2 mov        dword ptr [rsp + 0x3c], 0xa90db236
04aa mov        qword ptr [rbp + 0xd48], 0xddb
04b5 jne        0x4cb
04b7 mov        qword ptr [rip + 0x1f2a], rdx
04be mov        rax, qword ptr [rdx + 0x58]
04c2 mov        qword ptr [rip + 0x1f17], rax
04c9 jmp        0x4d2
04cb mov        rax, qword ptr [rip + 0x1f0e]
04d2 lea        rcx, [rsp + 0x40]
04d7 mov        qword ptr [rsp + 0x20], rcx
04dc lea        r9, [rbp + 0xd48]
04e3 lea        rcx, [rip + 0x1e66]
04ea lea        r8, [rbp + 0xd40]
04f1 lea        rdx, [rsp + 0x30]
04f6 call       qword ptr [rax + 0x48]
04f9 test       rax, rax
04fc js         0x566
04fe call       0x2038
0503 cmp        eax, 0x20
0506 je         0x566
0508 call       0x2038
050d cmp        eax, 0x12
0510 je         0x566
0512 cmp        byte ptr [rbp + 0xb35], 1
0519 jne        0x566
051b lea        rax, [rip + 0x1dee]
0522 mov        qword ptr [rsp + 0x28], rbx
0527 mov        qword ptr [rsp + 0x20], rax
052c lea        r9, [rip + 0x1d4d]
0533 mov        rax, qword ptr [rip + 0x1e96]
053a lea        r8, [rip + 0x1d9f]
0541 lea        rdx, [rip + 0x1d78]
0548 mov        qword ptr [rip + 0x1db9], rdi
054f lea        rcx, [rip + 0x1db2]
0556 mov        qword ptr [rip + 0x1da3], rdi
055d call       qword ptr [rax + 0x148]
0563 mov        rbx, rax
0566 lea        r11, [rsp + 0xe20]
056e mov        rax, rbx
0571 mov        rbx, qword ptr [r11 + 0x10]
0575 mov        rdi, qword ptr [r11 + 0x18]
0579 mov        rsp, r11
057c pop        rbp
057d ret        
057e int3       
057f int3       
0580 mov        qword ptr [rsp + 8], rbx
0585 push       rdi
0586 sub        rsp, 0x20
058a mov        rdi, rdx
058d mov        rbx, rcx
0590 movzx      eax, word ptr [rbx + 2]
0594 cmp        byte ptr [rax + rbx], 0x7f
0598 jne        0x5a1
059a cmp        byte ptr [rax + rbx + 1], 0xff
059f je         0x5cc
05a1 cmp        rdi, rbx
05a4 je         0x5bc
05a6 mov        r8d, 4
05ac mov        rdx, rbx
05af mov        rcx, rdi
05b2 call       0x2a0
05b7 test       rax, rax
05ba jne        0x5e6
05bc movzx      eax, word ptr [rbx + 2]
05c0 add        rbx, rax
05c3 movzx      eax, word ptr [rdi + 2]
05c7 add        rdi, rax
05ca jmp        0x590
05cc mov        al, byte ptr [rbx + 4]
05cf movabs     rcx, 0x8000000000000003
05d9 sub        al, byte ptr [rdi + 4]
05dc neg        al
05de sbb        rax, rax
05e1 and        rax, rcx
05e4 jmp        0x5f0
05e6 movabs     rax, 0x8000000000000003
05f0 mov        rbx, qword ptr [rsp + 0x30]
05f5 add        rsp, 0x20
05f9 pop        rdi
05fa ret        
05fb int3       
0960 mov        rax, rsp
0963 mov        qword ptr [rax + 0x10], rbx
0967 mov        qword ptr [rax + 0x18], rsi
096b push       rdi
096c sub        rsp, 0x40
0970 mov        r9, qword ptr [rcx + 0x28]
0974 lea        r8, [rax + 8]
0978 mov        dword ptr [rax - 0x20], 0x10
097f mov        rdi, rdx
0982 mov        qword ptr [rax - 0x28], rdx
0986 mov        rsi, rcx
0989 xor        ebx, ebx
098b lea        rdx, [rip + 0x190e]
0992 mov        qword ptr [rax + 8], rbx
0996 mov        rcx, rdi
0999 mov        rax, qword ptr [rip + 0x1a30]
09a0 call       qword ptr [rax + 0x118]
09a6 test       rax, rax
09a9 js         0xa29
09ab mov        rax, qword ptr [rsp + 0x50]
09b0 lea        rdx, [rsp + 0x30]
09b5 mov        rcx, rax
09b8 call       qword ptr [rax + 0x40]
09bb test       rax, rax
09be js         0x9f6
09c0 mov        dl, byte ptr [rsp + 0x35]
09c4 mov        al, byte ptr [rsp + 0x37]
09c8 mov        cl, byte ptr [rsp + 0x36]
09cc cmp        dl, 2
09cf jne        0x9d9
09d1 cmp        cl, dl
09d3 jne        0x9f6
09d5 cmp        al, 0xff
09d7 je         0x9f4
09d9 cmp        dl, 0xef
09dc jne        0x9e7
09de cmp        cl, 4
09e1 jne        0x9f6
09e3 cmp        al, 1
09e5 je         0x9f4
09e7 cmp        dl, 0xa
09ea jne        0x9f6
09ec test       cl, cl
09ee jne        0x9f6
09f0 test       al, al
09f2 jne        0x9f6
09f4 mov        bl, 1
09f6 mov        rax, qword ptr [rip + 0x19d3]
09fd lea        rdx, [rip + 0x189c]
0a04 mov        r8, qword ptr [rsi + 0x28]
0a08 mov        r9, rdi
0a0b mov        rcx, rdi
0a0e call       qword ptr [rax + 0x120]
0a14 neg        bl
0a16 movabs     rcx, 0x8000000000000003
0a20 sbb        rax, rax
0a23 not        rax
0a26 and        rax, rcx
0a29 mov        rbx, qword ptr [rsp + 0x58]
0a2e mov        rsi, qword ptr [rsp + 0x60]
0a33 add        rsp, 0x40
0a37 pop        rdi
0a38 ret        
0a39 int3       
0a3a int3       
0a3b int3       
0e68 mov        rax, rsp
0e6b mov        qword ptr [rax + 0x10], rbx
0e6f mov        qword ptr [rax + 0x18], rsi
0e73 push       rdi
0e74 sub        rsp, 0x50
0e78 mov        r9, qword ptr [rcx + 0x28]
0e7c lea        r8, [rax + 8]
0e80 mov        rbx, rdx
0e83 mov        rdi, rcx
0e86 mov        esi, 2
0e8b mov        rcx, rbx
0e8e mov        dword ptr [rax - 0x30], esi
0e91 mov        qword ptr [rax - 0x38], rdx
0e95 lea        rdx, [rip + 0x1434]
0e9c mov        rax, qword ptr [rip + 0x152d]
0ea3 call       qword ptr [rax + 0x118]
0ea9 test       rax, rax
0eac lea        rdx, [rip + 0x13ed]
0eb3 mov        rax, qword ptr [rip + 0x1516]
0eba jns        0xf39
0ebc mov        r9, qword ptr [rdi + 0x28]
0ec0 lea        r8, [rsp + 0x30]
0ec5 mov        dword ptr [rsp + 0x28], esi
0ec9 mov        rcx, rbx
0ecc mov        qword ptr [rsp + 0x20], rbx
0ed1 call       qword ptr [rax + 0x118]
0ed7 test       rax, rax
0eda js         0xfb6
0ee0 mov        rax, qword ptr [rsp + 0x30]
0ee5 lea        rdx, [rsp + 0x38]
0eea mov        rcx, rax
0eed call       qword ptr [rax + 0x40]
0ef0 test       rax, rax
0ef3 js         0xf2d
0ef5 cmp        byte ptr [rsp + 0x3d], sil
0efa jne        0xf2d
0efc cmp        byte ptr [rsp + 0x3e], sil
0f01 jne        0xf2d
0f03 cmp        byte ptr [rsp + 0x3f], 0xff
0f08 jne        0xf2d
0f0a mov        rax, qword ptr [rip + 0x14bf]
0f11 lea        rdx, [rip + 0x1388]
0f18 mov        r8, qword ptr [rdi + 0x28]
0f1c mov        r9, rbx
0f1f mov        rcx, rbx
0f22 call       qword ptr [rax + 0x120]
0f28 jmp        0xfb6
0f2d movabs     rax, 0x8000000000000003
0f37 jmp        0xfb6
0f39 mov        rsi, qword ptr [rsp + 0x60]
0f3e mov        r8, qword ptr [rdi + 0x28]
0f42 mov        rcx, qword ptr [rsi + 0x108]
0f49 mov        r9, rcx
0f4c call       qword ptr [rax + 0x120]
0f52 mov        rax, qword ptr [rip + 0x1477]
0f59 lea        rdx, [rip + 0x1370]
0f60 mov        r8, qword ptr [rsp + 0x60]
0f65 mov        rcx, rbx
0f68 call       qword ptr [rax + 0x90]
0f6e test       rax, rax
0f71 js         0xfb6
0f73 mov        rax, qword ptr [rip + 0x1456]
0f7a lea        rdx, [rip + 0x131f]
0f81 mov        r8, qword ptr [rdi + 0x28]
0f85 mov        r9, rbx
0f88 mov        rcx, rbx
0f8b call       qword ptr [rax + 0x120]
0f91 mov        rdx, qword ptr [rip + 0x1438]
0f98 mov        rbx, rax
0f9b mov        rcx, qword ptr [rsi + 0x128]
0fa2 call       qword ptr [rdx + 0x48]
0fa5 mov        rdx, qword ptr [rip + 0x1424]
0fac lea        rcx, [rsi - 8]
0fb0 call       qword ptr [rdx + 0x48]
0fb3 mov        rax, rbx
0fb6 mov        rbx, qword ptr [rsp + 0x68]
0fbb mov        rsi, qword ptr [rsp + 0x70]
0fc0 add        rsp, 0x50
0fc4 pop        rdi
0fc5 ret        
0fc6 int3       
0fc7 int3       