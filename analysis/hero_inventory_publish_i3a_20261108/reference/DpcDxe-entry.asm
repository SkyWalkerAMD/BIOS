2e0: sub rsp, 0x28
2e4: mov r10, qword ptr [rdx + 0x60]
2e8: lea rax, [rip + 0x3b1]
2ef: mov qword ptr [rip + 0x38a], r10
2f6: mov ecx, 0x20
2fb: mov qword ptr [rip + 0x376], rdx
302: mov qword ptr [rax], rax
305: mov qword ptr [rax + 8], rax
309: add rax, 0x10
30d: sub rcx, 1
311: jne 0x302
313: xor r9d, r9d
316: lea r8, [rip + 0x2f3]
31d: lea rdx, [rip + 0x2dc]
324: lea rcx, [rip + 0x33d]
32b: call qword ptr [r10 + 0x148]
332: add rsp, 0x28
336: ret 
337: int3 
338: mov qword ptr [rsp + 8], rbx
33d: mov qword ptr [rsp + 0x10], rbp
342: mov qword ptr [rsp + 0x18], rsi
347: push rdi
348: push r12
34a: push r13
34c: push r14
34e: push r15
350: sub rsp, 0x20
354: lea rax, [rdx - 4]
358: mov r12, r9
35b: mov r15, r8
35e: mov rbp, rdx
361: cmp rax, 0x1b
365: ja 0x487
36b: xor ebx, ebx
36d: test r8, r8
370: je 0x487
376: mov rax, qword ptr [rip + 0x303]
37d: lea ecx, [rbx + 0x1f]
380: call qword ptr [rax + 0x18]
383: mov rdx, qword ptr [rip + 0x296]
38a: lea r13, [rip + 0x28f]
391: mov rsi, rax
394: cmp rdx, r13
397: jne 0x412
399: cmp rax, 0x10
39d: jbe 0x3ae
39f: movabs rbx, 0x8000000000000009
3a9: jmp 0x475
3ae: mov r14, rbx
3b1: mov rax, qword ptr [rip + 0x2c8]
3b8: mov rcx, rsi
3bb: call qword ptr [rax + 0x20]
3be: call 0x5b4
3c3: mov rdx, qword ptr [rip + 0x2b6]
3ca: mov ecx, 0x1f
3cf: mov rdi, rax
3d2: call qword ptr [rdx + 0x18]
3d5: test rdi, rdi
3d8: jne 0x3e3
3da: cmp qword ptr [rip + 0x23f], r13
3e1: je 0x39f
3e3: mov qword ptr [rdi], r13
3e6: inc r14
3e9: mov rax, qword ptr [rip + 0x238]
3f0: mov qword ptr [rdi + 8], rax
3f4: mov rax, qword ptr [rip + 0x22d]
3fb: mov qword ptr [rax], rdi
3fe: mov qword ptr [rip + 0x223], rdi
405: cmp r14, 0x40
409: jb 0x3b1
40b: mov rdx, qword ptr [rip + 0x20e]
412: mov rcx, qword ptr [rdx]
415: mov rax, qword ptr [rdx + 8]
419: shl rbp, 4
41d: mov qword ptr [rcx + 8], rax
421: mov rcx, qword ptr [rdx + 8]
425: mov rax, qword ptr [rdx]
428: mov qword ptr [rcx], rax
42b: lea rax, [rip + 0x26e]
432: mov rcx, qword ptr [rip + 0x237]
439: add rbp, rax
43c: mov qword ptr [rdx + 0x10], r15
440: mov qword ptr [rdx + 0x18], r12
444: mov qword ptr [rdx], rbp
447: mov rax, qword ptr [rbp + 8]
44b: mov qword ptr [rdx + 8], rax
44f: mov qword ptr [rax], rdx
452: mov qword ptr [rbp + 8], rdx
456: mov rdx, qword ptr [rip + 0x203]
45d: inc rdx
460: cmp rdx, rcx
463: mov qword ptr [rip + 0x1f6], rdx
46a: cmova rcx, rdx
46e: mov qword ptr [rip + 0x1fb], rcx
475: mov rdx, qword ptr [rip + 0x204]
47c: mov rcx, rsi
47f: call qword ptr [rdx + 0x20]
482: mov rax, rbx
485: jmp 0x491
487: movabs rax, 0x8000000000000002
491: mov rbx, qword ptr [rsp + 0x50]
496: mov rbp, qword ptr [rsp + 0x58]
49b: mov rsi, qword ptr [rsp + 0x60]
4a0: add rsp, 0x20
4a4: pop r15
4a6: pop r14
4a8: pop r13
4aa: pop r12
4ac: pop rdi
4ad: ret 
4ae: int3 
4af: int3 
4b0: mov qword ptr [rsp + 8], rbx
4b5: mov qword ptr [rsp + 0x10], rbp
4ba: mov qword ptr [rsp + 0x18], rsi
4bf: push rdi
4c0: push r14
4c2: push r15
4c4: sub rsp, 0x20
4c8: mov rax, qword ptr [rip + 0x1b1]
4cf: mov r15d, 0x1f
4d5: mov ecx, r15d