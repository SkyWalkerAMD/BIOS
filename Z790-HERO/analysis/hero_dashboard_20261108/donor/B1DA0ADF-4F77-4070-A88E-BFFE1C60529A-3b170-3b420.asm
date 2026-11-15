03b174: lea      r8, [rbp + 0x30]                              
03b178: mov      edx, edi                                      
03b17a: mov      rcx, rsi                                      
03b17d: call     qword ptr [rax + 0x158]                       
03b183: lea      rdx, [rbp + 0x38]                             
03b187: mov      cl, r14b                                      
03b18a: call     0x39f88                                       
03b18f: mov      eax, dword ptr [rbp + 0x38]                   
03b192: cmp      dword ptr [rbp + 0x30], eax                   
03b195: je       0x3b1cf                                       
03b197: xor      edi, edi                                      
03b199: and      qword ptr [rsp + 0x20], 0                     
03b19f: xor      r9d, r9d                                      
03b1a2: mov      r8b, 0xe                                      
03b1a5: mov      byte ptr [rsi], dil                           
03b1a8: mov      rdx, rsi                                      
03b1ab: mov      cl, 0x4a                                      
03b1ad: call     0x39d1c                                       
03b1b2: test     rax, rax                                      
03b1b5: js       0x3b1d1                                       
03b1b7: add      rdi, rbx                                      
03b1ba: add      rsi, 0xe                                      
03b1be: cmp      rdi, 4                                        
03b1c2: jb       0x3b199                                       
03b1c4: mov      edx, dword ptr [rbp + 0x30]                   
03b1c7: mov      cl, r14b                                      
03b1ca: call     0x39f54                                       
03b1cf: xor      eax, eax                                      
03b1d1: add      rsp, 0x70                                     
03b1d5: pop      r14                                           
03b1d7: pop      rdi                                           
03b1d8: pop      rsi                                           
03b1d9: pop      rbx                                           
03b1da: pop      rbp                                           
03b1db: ret                                                    
03b1dc: push     rbx                                           
03b1de: sub      rsp, 0x20                                     
03b1e2: mov      rax, qword ptr [rip + 0x3d4df]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b1e9: lea      r8, [rip + 0x3d940]                           [78b30] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b1f0: xor      edx, edx                                      
03b1f2: lea      rcx, [rip + 0x31587]                          [6c780] 660e1d4a7152224e83fe90921b748213e1b1918ac756dc4aabeb1c2ca1729effffbe6cbb72e0d240a6ebbab75bde87e7397ba9c0729ed947a664b88051052f1f
03b1f9: call     qword ptr [rax + 0x140]                       
03b1ff: test     rax, rax                                      
03b202: js       0x3b295                                       
03b208: mov      rax, qword ptr [rip + 0x3d4b9]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b20f: lea      r8, [rip + 0x4b0c2]                           [862d8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b216: xor      edx, edx                                      
03b218: lea      rcx, [rip + 0x313c1]                          [6c5e0] f63f580336cb4049947eb9b39f4afaf71c865fbced867e41bb7b6c026bcd755b5c93aef7cfe0c642a634e92d73aeb107d7727e5850cc794f8209ca291fc1a10f
03b21f: call     qword ptr [rax + 0x140]                       
03b225: test     rax, rax                                      
03b228: js       0x3b26e                                       
03b22a: xor      bl, bl                                        
03b22c: movzx    eax, bl                                       
03b22f: imul     rcx, rax, 0x1d                                
03b233: lea      rax, [rip + 0x32fb6]                          [6e1f0] f4a003000000000000000000000000000100000040360700000000000100a4030000000000005a0800000000000200000050360700000000000134a503000000
03b23a: add      rcx, rax                                      
03b23d: mov      rax, qword ptr [rcx]                          
03b240: test     rax, rax                                      
03b243: je       0x3b25d                                       
03b245: cmp      byte ptr [rcx + 0x1c], 1                      
03b249: jne      0x3b254                                       
03b24b: call     rax                                           
03b24d: mov      qword ptr [rip + 0x3d8e4], rax                [78b38] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b254: inc      bl                                            
03b256: cmp      bl, 7                                         
03b259: jb       0x3b22c                                       
03b25b: jmp      0x3b26e                                       
03b25d: movabs   rax, 0x8000000000000002                       
03b267: mov      qword ptr [rip + 0x3d8ca], rax                [78b38] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b26e: mov      rax, qword ptr [rip + 0x3d453]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b275: xor      r8d, r8d                                      
03b278: mov      rcx, qword ptr [rip + 0x4b061]                [862e0] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b27f: xor      edx, edx                                      
03b281: call     qword ptr [rax + 0x58]                        
03b284: mov      rax, qword ptr [rip + 0x3d43d]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b28b: mov      rcx, qword ptr [rip + 0x4b04e]                [862e0] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b292: call     qword ptr [rax + 0x68]                        
03b295: add      rsp, 0x20                                     
03b299: pop      rbx                                           
03b29a: ret                                                    
03b29b: int3                                                   
03b29c: push     rbp                                           
03b29e: mov      rbp, rsp                                      
03b2a1: sub      rsp, 0x50                                     
03b2a5: and      dword ptr [rbp + 0x28], 0                     
03b2a9: cmp      byte ptr [rip + 0x3d891], 0                   [78b41] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b2b0: mov      dword ptr [rbp - 0x18], 0x1d5e9bbe            
03b2b7: mov      dword ptr [rbp - 0x14], 0x4c8047bd            
03b2be: mov      dword ptr [rbp - 0x10], 0x8a935699            
03b2c5: mov      dword ptr [rbp - 0xc], 0x7edc65ad             
03b2cc: jne      0x3b317                                       
03b2ce: lea      rax, [rbp + 0x20]                             
03b2d2: mov      qword ptr [rbp - 0x20], 1                     
03b2da: mov      qword ptr [rsp + 0x20], rax                   
03b2df: lea      r9, [rbp - 0x20]                              
03b2e3: mov      rax, qword ptr [rip + 0x3d3ee]                [786d8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b2ea: lea      r8, [rbp + 0x28]                              
03b2ee: lea      rdx, [rbp - 0x18]                             
03b2f2: lea      rcx, [rip + 0x383ff]                          [736f8] 540072007500730074006500640044006500760069006300650053007500700070006f0072007400650064000000000053006500720076006500720053006500
03b2f9: call     qword ptr [rax + 0x48]                        
03b2fc: movzx    ecx, byte ptr [rbp + 0x20]                    
03b300: xor      edx, edx                                      
03b302: test     rax, rax                                      
03b305: mov      byte ptr [rip + 0x3d835], 1                   [78b41] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b30c: cmovns   edx, ecx                                      
03b30f: mov      byte ptr [rip + 0x3d82b], dl                  [78b40] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b315: jmp      0x3b31d                                       
03b317: mov      dl, byte ptr [rip + 0x3d823]                  [78b40] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b31d: test     dl, dl                                        
03b31f: je       0x3b334                                       
03b321: mov      al, byte ptr [rip + 0x3d47a]                  [787a1] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b327: mov      byte ptr [rip + 0x464db], al                  [81808] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b32d: mov      byte ptr [rip + 0x3d46d], 1                   [787a1] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b334: add      rsp, 0x50                                     
03b338: pop      rbp                                           
03b339: ret                                                    
03b33a: int3                                                   
03b33b: int3                                                   
03b33c: movzx    ecx, byte ptr [rip + 0x3d45e]                 [787a1] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b343: cmp      byte ptr [rip + 0x3d7f6], 0                   [78b40] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b34a: movzx    eax, byte ptr [rip + 0x464b7]                 [81808] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b351: cmovne   ecx, eax                                      
03b354: mov      byte ptr [rip + 0x3d447], cl                  [787a1] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b35a: ret                                                    
03b35b: int3                                                   
03b35c: mov      qword ptr [rsp + 8], rcx                      
03b361: push     rbp                                           
03b362: push     rbx                                           
03b363: push     rsi                                           
03b364: push     rdi                                           
03b365: push     r14                                           
03b367: mov      rbp, rsp                                      
03b36a: sub      rsp, 0x70                                     
03b36e: mov      rsi, qword ptr [rip + 0x3d8ab]                [78c20] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b375: lea      rax, [rbp - 0x30]                             
03b379: and      qword ptr [rbp - 0x28], 0                     
03b37e: lea      r9, [rbp - 0x20]                              
03b382: and      qword ptr [rbp - 0x18], 0                     
03b387: xor      edi, edi                                      
03b389: and      qword ptr [rbp - 0x30], rdi                   
03b38d: mov      r14, rdx                                      
03b390: mov      qword ptr [rsp + 0x20], rax                   
03b395: lea      rdx, [rip + 0x31224]                          [6c5c0] b6730e22db6b13448405b974b108619a63bf6d440225da4cbcfa2465d2b0fe9df63f580336cb4049947eb9b39f4afaf71c865fbced867e41bb7b6c026bcd755b
03b39c: mov      rax, qword ptr [rip + 0x3d865]                [78c08] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b3a3: xor      r8d, r8d                                      
03b3a6: lea      ecx, [rdi + 2]                                
03b3a9: call     qword ptr [rax + 0x138]                       
03b3af: test     rax, rax                                      
03b3b2: js       0x3b52f                                       
03b3b8: xor      ebx, ebx                                      
03b3ba: cmp      qword ptr [rbp - 0x20], rbx                   
03b3be: jbe      0x3b4b7                                       
03b3c4: mov      rcx, qword ptr [rbp - 0x30]                   
03b3c8: lea      r8, [rbp - 0x28]                              
03b3cc: mov      rax, qword ptr [rip + 0x3d835]                [78c08] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03b3d3: lea      rdx, [rip + 0x311e6]                          [6c5c0] b6730e22db6b13448405b974b108619a63bf6d440225da4cbcfa2465d2b0fe9df63f580336cb4049947eb9b39f4afaf71c865fbced867e41bb7b6c026bcd755b
03b3da: mov      dword ptr [rsp + 0x28], 1                     
03b3e2: mov      r9, rsi                                       
03b3e5: and      qword ptr [rsp + 0x20], rdi                   
03b3ea: mov      rcx, qword ptr [rcx + rbx*8]                  
03b3ee: call     qword ptr [rax + 0x118]                       
03b3f4: test     rax, rax                                      
03b3f7: js       0x3b462                                       
03b3f9: lea      rax, [rbp + 0x40]                             
03b3fd: xor      r8d, r8d                                      
03b400: mov      qword ptr [rsp + 0x30], rax                   
03b405: lea      r9, [rbp - 8]                                 
03b409: lea      rax, [rbp + 0x48]                             
03b40d: mov      rdx, r14                                      
03b410: mov      qword ptr [rsp + 0x28], rax                   
03b415: lea      rax, [rbp + 0x30]                             
03b419: mov      qword ptr [rsp + 0x20], rax                   
03b41e: mov      rax, qword ptr [rbp - 0x28]                   