004731: mov      rbp, qword ptr [rsp + 0x40]                   
004736: mov      rsi, qword ptr [rsp + 0x48]                   
00473b: add      rsp, 0x20                                     
00473f: pop      rdi                                           
004740: ret                                                    
004741: int3                                                   
004742: int3                                                   
004743: int3                                                   
004744: and      qword ptr [rdx], 0                            
004748: lea      r11, [rip + 0x6e8e1]                          [73030] 0100ffff00000000dc4800000000000064f3030000000000ccfa030000000000f0cb0300000000000200ffff00000000f048000000000000589b030000000000
00474f: xor      r10d, r10d                                    
004752: mov      eax, 0xffff0001                               
004757: xor      r9d, r9d                                      
00475a: cmp      rcx, rax                                      
00475d: je       0x476f                                        
00475f: inc      r9                                            
004762: inc      r10d                                          
004765: mov      rax, qword ptr [r11 + r9*8]                   
004769: test     rax, rax                                      
00476c: jne      0x475a                                        
00476e: ret                                                    
00476f: movsxd   rax, r10d                                     
004772: add      rax, 2                                        
004776: mov      qword ptr [rdx], rax                          
004779: mov      rcx, rax                                      
00477c: mov      rdx, qword ptr [r11 + rax*8]                  
004780: test     rdx, rdx                                      
004783: je       0x479f                                        
004785: mov      r9d, 0xffff0000                               
00478b: and      rdx, r9                                       
00478e: cmp      rdx, r9                                       
004791: je       0x479f                                        
004793: inc      rcx                                           
004796: mov      rdx, qword ptr [r11 + rcx*8]                  
00479a: test     rdx, rdx                                      
00479d: jne      0x478b                                        
00479f: dec      rcx                                           
0047a2: mov      qword ptr [r8], rcx                           
0047a5: ret                                                    
0047a6: int3                                                   
0047a7: int3                                                   
0047a8: mov      rax, rsp                                      
0047ab: push     rbx                                           
0047ac: sub      rsp, 0x20                                     
0047b0: and      qword ptr [rax + 0x20], 0                     
0047b5: lea      r8, [rax + 0x18]                              
0047b9: and      qword ptr [rax + 0x18], 0                     
0047be: mov      rbx, rdx                                      
0047c1: lea      rdx, [rax + 0x20]                             
0047c5: call     0x4744                                        
0047ca: test     rax, rax                                      
0047cd: je       0x47f0                                        
0047cf: mov      rbx, qword ptr [rsp + 0x48]                   
0047d4: jmp      0x47e3                                        
0047d6: lea      rax, [rip + 0x6e853]                          [73030] 0100ffff00000000dc4800000000000064f3030000000000ccfa030000000000f0cb0300000000000200ffff00000000f048000000000000589b030000000000
0047dd: call     qword ptr [rax + rbx*8]                       
0047e0: inc      rbx                                           
0047e3: cmp      rbx, qword ptr [rsp + 0x40]                   
0047e8: jbe      0x47d6                                        
0047ea: add      rsp, 0x20                                     
0047ee: pop      rbx                                           
0047ef: ret                                                    
0047f0: mov      rax, rbx                                      
0047f3: add      rsp, 0x20                                     
0047f7: pop      rbx                                           
0047f8: jmp      rax                                           
0047fb: int3                                                   
0047fc: mov      rax, rsp                                      
0047ff: mov      qword ptr [rax + 8], rbx                      
004803: mov      qword ptr [rax + 0x10], rsi                   
004807: push     rdi                                           
004808: sub      rsp, 0x30                                     
00480c: and      qword ptr [rax - 0x10], 0                     
004811: mov      rbx, rdx                                      
004814: and      qword ptr [rax - 0x18], 0                     
004819: lea      rdx, [rax - 0x10]                             
00481d: mov      rsi, r8                                       
004820: mov      rdi, r9                                       
004823: lea      r8, [rax - 0x18]                              
004827: call     0x4744                                        
00482c: test     rax, rax                                      
00482f: je       0x4854                                        
004831: mov      rbx, qword ptr [rsp + 0x28]                   
004836: jmp      0x484b                                        
004838: lea      rax, [rip + 0x6e7f1]                          [73030] 0100ffff00000000dc4800000000000064f3030000000000ccfa030000000000f0cb0300000000000200ffff00000000f048000000000000589b030000000000
00483f: mov      rdx, rdi                                      
004842: mov      rcx, rsi                                      
004845: call     qword ptr [rax + rbx*8]                       
004848: inc      rbx                                           
00484b: cmp      rbx, qword ptr [rsp + 0x20]                   
004850: jbe      0x4838                                        
004852: jmp      0x485c                                        
004854: mov      rdx, rdi                                      
004857: mov      rcx, rsi                                      
00485a: call     rbx                                           
00485c: mov      rbx, qword ptr [rsp + 0x40]                   
004861: mov      rsi, qword ptr [rsp + 0x48]                   
004866: add      rsp, 0x30                                     
00486a: pop      rdi                                           
00486b: ret                                                    
00486c: mov      rax, rsp                                      
00486f: mov      qword ptr [rax + 8], rbx                      
004873: mov      qword ptr [rax + 0x10], rsi                   
004877: push     rdi                                           
004878: sub      rsp, 0x30                                     
00487c: mov      rbx, rdx                                      
00487f: xor      edi, edi                                      
004881: mov      rsi, r8                                       
004884: mov      qword ptr [rax - 0x18], rdi                   
004888: lea      r8, [rax + 0x20]                              
00488c: mov      qword ptr [rax + 0x20], rdi                   
004890: lea      rdx, [rax - 0x18]                             
004894: call     0x4744                                        
004899: test     rax, rax                                      
00489c: je       0x48c1                                        
00489e: mov      rbx, qword ptr [rsp + 0x20]                   
0048a3: jmp      0x48b8                                        
0048a5: lea      rax, [rip + 0x6e784]                          [73030] 0100ffff00000000dc4800000000000064f3030000000000ccfa030000000000f0cb0300000000000200ffff00000000f048000000000000589b030000000000
0048ac: mov      rcx, rsi                                      
0048af: call     qword ptr [rax + rbx*8]                       
0048b2: mov      rdi, rax                                      
0048b5: inc      rbx                                           
0048b8: cmp      rbx, qword ptr [rsp + 0x58]                   
0048bd: jbe      0x48a5                                        
0048bf: jmp      0x48c9                                        
0048c1: mov      rcx, rsi                                      
0048c4: call     rbx                                           
0048c6: mov      rdi, rax                                      
0048c9: mov      rbx, qword ptr [rsp + 0x40]                   
0048ce: mov      rax, rdi                                      
0048d1: mov      rsi, qword ptr [rsp + 0x48]                   
0048d6: add      rsp, 0x30                                     
0048da: pop      rdi                                           
0048db: ret                                                    
0048dc: lea      rdx, [rip + 0x33f99]                          [3887c] 4055535657488bec4883ec6833f6c745e8998bb27b488d45384889752848894424204c8d4d40488b051ffe0300488d15103d03004533c0488975308d4e02c745
0048e3: mov      ecx, 0xffff0001                               
0048e8: jmp      0x47a8                                        
0048ed: int3                                                   
0048ee: int3                                                   
0048ef: int3                                                   
0048f0: mov      rax, rsp                                      
0048f3: mov      qword ptr [rax + 0x18], rbx                   
0048f7: push     rdi                                           
0048f8: sub      rsp, 0x20                                     
0048fc: xor      ebx, ebx                                      
0048fe: lea      r8, [rax + 8]                                 
004902: lea      rdx, [rax + 0x10]                             
004906: mov      qword ptr [rax + 0x10], rbx                   
00490a: mov      ecx, 0xffff0002                               
00490f: mov      qword ptr [rax + 8], rbx                      
004913: call     0x4744                                        
004918: test     rax, rax                                      
00491b: je       0x493c                                        
00491d: mov      rdi, qword ptr [rsp + 0x38]                   
004922: jmp      0x4933                                        
004924: lea      rax, [rip + 0x6e705]                          [73030] 0100ffff00000000dc4800000000000064f3030000000000ccfa030000000000f0cb0300000000000200ffff00000000f048000000000000589b030000000000
00492b: call     qword ptr [rax + rdi*8]                       
00492e: or       bl, al                                        
004930: inc      rdi                                           
004933: cmp      rdi, qword ptr [rsp + 0x30]                   
004938: jbe      0x4924                                        
00493a: jmp      0x4943                                        
00493c: call     0x389e0                                       
004941: mov      bl, al                                        
004943: mov      al, bl                                        
004945: mov      rbx, qword ptr [rsp + 0x40]                   
00494a: add      rsp, 0x20                                     
00494e: pop      rdi                                           
00494f: ret                                                    
004950: lea      rdx, [rip + 0x34171]                          [38ac8] 4053574883ec4833ff393db1fc03007555e8caebffff4c8b152b0104004c8d4c24788bd848c744247804000000488d4424604c8d4424684889442420488d155d
004957: mov      ecx, 0xffff0003                               
00495c: jmp      0x47a8                                        
004961: int3                                                   
004962: int3                                                   
004963: int3                                                   
004964: lea      rdx, [rip + 0x34241]                          [38bac] 4055488bec4883ec30488d4df0c745f081ac1e45c745f40d7d4d4bc745f8a3d01cb3c745fcfe1d6666e862c6fcff4883c4305dc3488bc4488958084889681048
00496b: mov      ecx, 0xffff0004                               
004970: jmp      0x47a8                                        
004975: int3                                                   
004976: int3                                                   
004977: int3                                                   
004978: lea      rdx, [rip + 0x344f1]                          [38e70] 4883ec2833d233c9448d4a50448d4218e823cffcff4883c428e936feffffcccc488bc448895810488970184889782041574883ec20488360080033db48391d6d
00497f: mov      ecx, 0xffff0005                               
004984: jmp      0x47a8                                        
004989: int3                                                   
00498a: int3                                                   
00498b: int3                                                   
00498c: lea      rdx, [rip + 0x641]                            [4fd4] c20000cc40534883ec20488b05233c07004c8d442438488364243800488bd9488bd1b904000000ff5040488b4424384885c0741b488bc84533c0488b05f33b07
004993: mov      ecx, 0xffff0006                               
004998: jmp      0x47a8                                        
00499d: int3                                                   
00499e: int3                                                   
00499f: int3                                                   
0049a0: mov      qword ptr [rsp + 0x18], rbx                   
0049a5: push     rbp                                           
0049a6: push     rsi                                           
0049a7: push     rdi                                           
0049a8: mov      rbp, rsp                                      
0049ab: sub      rsp, 0x50                                     
0049af: movups   xmm0, xmmword ptr [rcx]                       
0049b2: mov      esi, dword ptr [rcx + 0x10]                   
0049b5: lea      r8, [rbp + 0x20]                              
0049b9: xor      edi, edi                                      
0049bb: lea      rdx, [rbp + 0x28]                             
0049bf: mov      ecx, 0xffff0007                               
0049c4: movaps   xmmword ptr [rbp - 0x30], xmm0                
0049c8: mov      qword ptr [rbp + 0x28], rdi                   
0049cc: mov      qword ptr [rbp + 0x20], rdi                   
0049d0: call     0x4744                                        
0049d5: test     rax, rax                                      
0049d8: je       0x4a06                                        
0049da: mov      rbx, qword ptr [rbp + 0x28]                   
0049de: jmp      0x49fe                                        
0049e0: lea      rax, [rip + 0x6e649]                          [73030] 0100ffff00000000dc4800000000000064f3030000000000ccfa030000000000f0cb0300000000000200ffff00000000f048000000000000589b030000000000
0049e7: movaps   xmmword ptr [rbp - 0x20], xmm0                
0049eb: lea      rcx, [rbp - 0x20]                             
0049ef: mov      dword ptr [rbp - 0x10], esi                   
0049f2: call     qword ptr [rax + rbx*8]                       
0049f5: movaps   xmm0, xmmword ptr [rbp - 0x30]                
0049f9: inc      rbx                                           
0049fc: mov      edi, eax                                      
0049fe: cmp      rbx, qword ptr [rbp + 0x20]                   
004a02: jbe      0x49e0                                        
004a04: jmp      0x4a18                                        
004a06: lea      rcx, [rbp - 0x20]                             
004a0a: movaps   xmmword ptr [rbp - 0x20], xmm0                
004a0e: mov      dword ptr [rbp - 0x10], esi                   
004a11: call     0x38be0                                       
004a16: mov      edi, eax                                      
004a18: mov      eax, edi                                      
004a1a: mov      rbx, qword ptr [rsp + 0x80]                   
004a22: add      rsp, 0x50                                     
004a26: pop      rdi                                           
004a27: pop      rsi                                           