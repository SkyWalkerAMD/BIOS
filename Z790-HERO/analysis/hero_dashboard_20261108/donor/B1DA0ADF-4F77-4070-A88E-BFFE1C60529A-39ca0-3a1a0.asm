039ca0: or       eax, 0x3995b                                  
039ca5: call     qword ptr [rax + 0x48]                        
039ca8: test     rax, rax                                      
039cab: js       0x39d0e                                       
039cad: mov      bl, byte ptr [rbp - 0x23]                     
039cb0: shr      bl, 3                                         
039cb3: call     0x376a8                                       
039cb8: test     bl, 1                                         
039cbb: je       0x39d0e                                       
039cbd: test     al, 1                                         
039cbf: je       0x39d0e                                       
039cc1: mov      r8d, 2                                        
039cc7: cmp      al, 1                                         
039cc9: jne      0x39cd8                                       
039ccb: mov      dword ptr [rip + 0x3eab6], r8d                [78788] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039cd2: mov      byte ptr [rbp + 0x18], 0                      
039cd6: jmp      0x39ce6                                       
039cd8: mov      dword ptr [rip + 0x3eaa6], 1                  [78788] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039ce2: mov      byte ptr [rbp + 0x18], 1                      
039ce6: lea      rax, [rbp + 0x18]                             
039cea: mov      r9d, 1                                        
039cf0: mov      qword ptr [rsp + 0x20], rax                   
039cf5: lea      rdx, [rbp - 0x18]                             
039cf9: mov      rax, qword ptr [rip + 0x3e9d8]                [786d8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039d00: lea      rcx, [rip + 0x39919]                          [73620] 530079007300740065006d004100630063006500730073000000000000000000446d6920696e666f726d6174696f6e0043707520696e666f726d6174696f6e00
039d07: call     qword ptr [rax + 0x58]                        
039d0a: xor      al, al                                        
039d0c: jmp      0x39d13                                       
039d0e: call     0x389e0                                       
039d13: add      rsp, 0x78                                     
039d17: pop      rbx                                           
039d18: pop      rbp                                           
039d19: ret                                                    
039d1a: int3                                                   
039d1b: int3                                                   
039d1c: mov      rax, rsp                                      
039d1f: mov      qword ptr [rax + 8], rbx                      
039d23: mov      qword ptr [rax + 0x10], rbp                   
039d27: mov      qword ptr [rax + 0x18], rsi                   
039d2b: mov      qword ptr [rax + 0x20], r9                    
039d2f: push     rdi                                           
039d30: push     r14                                           
039d32: push     r15                                           
039d34: sub      rsp, 0x40                                     
039d38: mov      rax, qword ptr [rip + 0x3edf1]                [78b30] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039d3f: xor      r15d, r15d                                    
039d42: mov      sil, r8b                                      
039d45: mov      rbp, rdx                                      
039d48: mov      r14b, cl                                      
039d4b: mov      dil, r15b                                     
039d4e: test     rax, rax                                      
039d51: jne      0x39d96                                       
039d53: mov      rax, qword ptr [rip + 0x3e96e]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039d5a: lea      r8, [rip + 0x3edcf]                           [78b30] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039d61: xor      edx, edx                                      
039d63: lea      rcx, [rip + 0x32a16]                          [6c780] 660e1d4a7152224e83fe90921b748213e1b1918ac756dc4aabeb1c2ca1729effffbe6cbb72e0d240a6ebbab75bde87e7397ba9c0729ed947a664b88051052f1f
039d6a: call     qword ptr [rax + 0x140]                       
039d70: mov      rbx, rax                                      
039d73: mov      rax, qword ptr [rip + 0x3edb6]                [78b30] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039d7a: test     rbx, rbx                                      
039d7d: cmovs    rax, r15                                      
039d81: mov      qword ptr [rip + 0x3eda8], rax                [78b30] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039d88: test     rax, rax                                      
039d8b: je       0x39e64                                       
039d91: mov      r9, qword ptr [rsp + 0x78]                    
039d96: test     r9, r9                                        
039d99: je       0x39da8                                       
039d9b: mov      rcx, qword ptr [rsp + 0x80]                   
039da3: test     rcx, rcx                                      
039da6: jne      0x39e19                                       
039da8: mov      rax, qword ptr [rip + 0x3e919]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039daf: lea      r8, [rsp + 0x80]                              
039db7: mov      edi, 1                                        
039dbc: mov      edx, edi                                      
039dbe: lea      ebx, [rdi + 3]                                
039dc1: mov      ecx, ebx                                      
039dc3: call     qword ptr [rax + 0x40]                        
039dc6: test     rax, rax                                      
039dc9: js       0x39e73                                       
039dcf: mov      rax, qword ptr [rip + 0x3e8f2]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039dd6: lea      r8, [rsp + 0x78]                              
039ddb: mov      edx, 0xff                                     
039de0: mov      ecx, ebx                                      
039de2: call     qword ptr [rax + 0x40]                        
039de5: test     rax, rax                                      
039de8: js       0x39e73                                       
039dee: cmp      qword ptr [rsp + 0x78], r15                   
039df3: je       0x39e69                                       
039df5: mov      rax, qword ptr [rsp + 0x80]                   
039dfd: test     rax, rax                                      
039e00: je       0x39e69                                       
039e02: mov      byte ptr [rax], 0xff                          
039e05: mov      rcx, qword ptr [rsp + 0x80]                   
039e0d: mov      r9, qword ptr [rsp + 0x78]                    
039e12: mov      rax, qword ptr [rip + 0x3ed17]                [78b30] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039e19: mov      qword ptr [rsp + 0x38], rcx                   
039e1e: xor      r8d, r8d                                      
039e21: mov      qword ptr [rsp + 0x30], r9                    
039e26: mov      dl, 0x30                                      
039e28: mov      byte ptr [rsp + 0x28], sil                    
039e2d: mov      r9b, r14b                                     
039e30: mov      rcx, rax                                      
039e33: mov      qword ptr [rsp + 0x20], rbp                   
039e38: call     qword ptr [rax + 8]                           
039e3b: mov      rbx, rax                                      
039e3e: test     dil, dil                                      
039e41: je       0x39e64                                       
039e43: mov      rax, qword ptr [rip + 0x3e87e]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039e4a: mov      rcx, qword ptr [rsp + 0x80]                   
039e52: call     qword ptr [rax + 0x48]                        
039e55: mov      rax, qword ptr [rip + 0x3e86c]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039e5c: mov      rcx, qword ptr [rsp + 0x78]                   
039e61: call     qword ptr [rax + 0x48]                        
039e64: mov      rax, rbx                                      
039e67: jmp      0x39e73                                       
039e69: movabs   rax, 0x8000000000000004                       
039e73: mov      rbx, qword ptr [rsp + 0x60]                   
039e78: mov      rbp, qword ptr [rsp + 0x68]                   
039e7d: mov      rsi, qword ptr [rsp + 0x70]                   
039e82: add      rsp, 0x40                                     
039e86: pop      r15                                           
039e88: pop      r14                                           
039e8a: pop      rdi                                           
039e8b: ret                                                    
039e8c: test     rcx, rcx                                      
039e8f: je       0x39f53                                       
039e95: mov      rax, rsp                                      
039e98: mov      qword ptr [rax + 8], rbx                      
039e9c: mov      qword ptr [rax + 0x10], rbp                   
039ea0: mov      qword ptr [rax + 0x18], rsi                   
039ea4: mov      qword ptr [rax + 0x20], rdi                   
039ea8: push     r14                                           
039eaa: sub      rsp, 0x120                                    
039eb1: xor      ebx, ebx                                      
039eb3: mov      bpl, dl                                       
039eb6: mov      rsi, rcx                                      
039eb9: mov      edi, ebx                                      
039ebb: cmp      byte ptr [rcx], bl                            
039ebd: je       0x39ec7                                       
039ebf: inc      rdi                                           
039ec2: cmp      byte ptr [rdi + rcx], bl                      
039ec5: jne      0x39ebf                                       
039ec7: mov      rax, qword ptr [rip + 0x3e7fa]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039ece: lea      rcx, [rsp + 0x20]                             
039ed3: xor      r8d, r8d                                      
039ed6: mov      edx, 0xff                                     
039edb: call     qword ptr [rax + 0x168]                       
039ee1: movzx    r8d, bpl                                      
039ee5: mov      rdx, rsi                                      
039ee8: lea      rcx, [rsp + 0x20]                             
039eed: cmp      dil, bpl                                      
039ef0: jbe      0x39f01                                       
039ef2: mov      rax, qword ptr [rip + 0x3e7cf]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039ef9: call     qword ptr [rax + 0x160]                       
039eff: jmp      0x39f36                                       
039f01: movzx    eax, dil                                      
039f05: lea      r14, [rsp + 0x20]                             
039f0a: add      r14, rax                                      
039f0d: mov      rax, qword ptr [rip + 0x3e7b4]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039f14: call     qword ptr [rax + 0x160]                       
039f1a: movzx    eax, dil                                      
039f1e: movzx    ecx, bpl                                      
039f22: sub      ecx, eax                                      
039f24: js       0x39f36                                       
039f26: inc      bl                                            
039f28: mov      byte ptr [r14], 0x20                          
039f2c: movzx    eax, bl                                       
039f2f: inc      r14                                           
039f32: cmp      eax, ecx                                      
039f34: jle      0x39f26                                       
039f36: lea      r11, [rsp + 0x120]                            
039f3e: mov      rbx, qword ptr [r11 + 0x10]                   
039f42: mov      rbp, qword ptr [r11 + 0x18]                   
039f46: mov      rsi, qword ptr [r11 + 0x20]                   
039f4a: mov      rdi, qword ptr [r11 + 0x28]                   
039f4e: mov      rsp, r11                                      
039f51: pop      r14                                           
039f53: ret                                                    
039f54: mov      rax, rsp                                      
039f57: sub      rsp, 0x38                                     
039f5b: mov      byte ptr [rax + 0x18], cl                     
039f5e: lea      r9, [rsp + 0x48]                              
039f63: mov      dword ptr [rax + 0x19], edx                   
039f66: mov      r8b, 5                                        
039f69: mov      byte ptr [rax + 8], 1                         
039f6d: lea      rax, [rax + 8]                                
039f71: lea      rdx, [rsp + 0x50]                             
039f76: mov      qword ptr [rsp + 0x20], rax                   
039f7b: mov      cl, 0x4e                                      
039f7d: call     0x39d1c                                       
039f82: add      rsp, 0x38                                     
039f86: ret                                                    
039f87: int3                                                   
039f88: mov      byte ptr [rsp + 8], cl                        
039f8c: mov      r11, rsp                                      
039f8f: push     rbx                                           
039f90: sub      rsp, 0x30                                     
039f94: mov      rbx, rdx                                      
039f97: mov      byte ptr [rsp + 0x48], 5                      
039f9c: lea      rax, [r11 + 0x10]                             
039fa0: mov      r8b, 1                                        
039fa3: lea      rdx, [r11 + 8]                                
039fa7: mov      qword ptr [r11 - 0x18], rax                   
039fab: lea      r9, [r11 + 0x18]                              
039faf: mov      cl, 0x4f                                      
039fb1: call     0x39d1c                                       
039fb6: mov      ecx, dword ptr [rsp + 0x51]                   
039fba: mov      dword ptr [rbx], ecx                          
039fbc: add      rsp, 0x30                                     
039fc0: pop      rbx                                           
039fc1: ret                                                    
039fc2: int3                                                   
039fc3: int3                                                   
039fc4: mov      rax, rsp                                      
039fc7: mov      qword ptr [rax + 8], rbx                      
039fcb: mov      qword ptr [rax + 0x18], rsi                   
039fcf: mov      byte ptr [rax + 0x10], dl                     
039fd2: push     rdi                                           
039fd3: sub      rsp, 0x40                                     
039fd7: xor      esi, esi                                      
039fd9: mov      byte ptr [rax - 0x18], 7                      
039fdd: mov      word ptr [rax + 0x10], si                     
039fe1: mov      rbx, r8                                       
039fe4: movzx    edi, cx                                       
039fe7: mov      r9, r8                                        
039fea: jmp      0x39ff8                                       
039fec: mov      rax, qword ptr [rbx]                          
039fef: cmp      word ptr [rax + 2], di                        
039ff3: je       0x3a033                                       
039ff5: mov      r9, rbx                                       
039ff8: mov      rax, qword ptr [rip + 0x4c2d9]                [862d8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
039fff: lea      r8, [rsp + 0x30]                              
03a004: lea      rdx, [rsp + 0x58]                             
03a009: mov      qword ptr [rsp + 0x20], rsi                   
03a00e: mov      rcx, rax                                      
03a011: call     qword ptr [rax + 0x18]                        
03a014: test     rax, rax                                      
03a017: jns      0x39fec                                       
03a019: movabs   rax, 0x800000000000000e                       
03a023: mov      rbx, qword ptr [rsp + 0x50]                   
03a028: mov      rsi, qword ptr [rsp + 0x60]                   
03a02d: add      rsp, 0x40                                     
03a031: pop      rdi                                           
03a032: ret                                                    
03a033: xor      eax, eax                                      
03a035: jmp      0x3a023                                       
03a037: int3                                                   
03a038: xor      r9d, r9d                                      
03a03b: mov      eax, r9d                                      
03a03e: test     dl, dl                                        
03a040: je       0x3a08d                                       
03a042: add      rcx, rax                                      
03a045: add      dl, 0xff                                      
03a048: mov      rax, r9                                       
03a04b: cmp      byte ptr [rcx], r9b                           
03a04e: je       0x3a059                                       
03a050: inc      rax                                           
03a053: cmp      byte ptr [rax + rcx], r9b                     
03a057: jne      0x3a050                                       
03a059: inc      rax                                           
03a05c: cmp      byte ptr [rax + rcx], r9b                     
03a060: je       0x3a066                                       
03a062: test     dl, dl                                        
03a064: jne      0x3a042                                       
03a066: test     dl, dl                                        
03a068: jne      0x3a08d                                       
03a06a: cmp      rax, 1                                        
03a06e: je       0x3a08d                                       
03a070: mov      al, byte ptr [rcx]                            
03a072: test     al, al                                        
03a074: je       0x3a087                                       
03a076: sub      rcx, r8                                       
03a079: mov      byte ptr [r8], al                             
03a07c: inc      r8                                            
03a07f: mov      al, byte ptr [rcx + r8]                       
03a083: test     al, al                                        
03a085: jne      0x3a079                                       
03a087: mov      byte ptr [r8], r9b                            
03a08a: xor      eax, eax                                      
03a08c: ret                                                    
03a08d: movabs   rax, 0x8000000000000002                       
03a097: ret                                                    
03a098: mov      r8, qword ptr [rsp + 0x28]                    
03a09d: mov      byte ptr [r8], r9b                            
03a0a0: inc      r8                                            
03a0a3: test     cl, cl                                        
03a0a5: je       0x3a0f3                                       
03a0a7: mov      r10, qword ptr [rsp + 0x30]                   
03a0ac: movzx    r11d, cl                                      
03a0b0: mov      r9b, byte ptr [r10]                           
03a0b3: xor      cl, cl                                        
03a0b5: mov      al, byte ptr [rdx]                            
03a0b7: test     al, al                                        
03a0b9: je       0x3a0cb                                       
03a0bb: mov      byte ptr [r8], al                             
03a0be: inc      cl                                            
03a0c0: inc      r8                                            
03a0c3: inc      rdx                                           
03a0c6: cmp      cl, 0x64                                      
03a0c9: jb       0x3a0b5                                       
03a0cb: lea      eax, [rcx + 1]                                
03a0ce: add      r9b, al                                       
03a0d1: cmp      cl, 0x64                                      
03a0d4: jae      0x3a0e3                                       
03a0d6: mov      eax, 0x64                                     
03a0db: sub      al, cl                                        
03a0dd: movzx    eax, al                                       
03a0e0: add      rdx, rax                                      
03a0e3: mov      byte ptr [r8], 0                              
03a0e7: inc      r8                                            
03a0ea: sub      r11, 1                                        
03a0ee: jne      0x3a0b3                                       
03a0f0: mov      byte ptr [r10], r9b                           
03a0f3: ret                                                    
03a0f4: push     rbp                                           
03a0f6: push     rbx                                           
03a0f7: push     rdi                                           
03a0f8: lea      rbp, [rsp - 0x140]                            
03a100: sub      rsp, 0x240                                    
03a107: and      qword ptr [rsp + 0x20], 0                     
03a10d: lea      r9, [rsp + 0x38]                              
03a112: mov      eax, 0xfffe                                   
03a117: mov      byte ptr [rbp + 0x170], 0                     
03a11e: mov      word ptr [rsp + 0x34], ax                     
03a123: lea      r8, [rbp + 0x170]                             
03a12a: mov      rax, qword ptr [rip + 0x4c1a7]                [862d8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a131: lea      rdx, [rsp + 0x34]                             
03a136: mov      rdi, rcx                                      
03a139: mov      byte ptr [rsp + 0x30], 2                      
03a13e: mov      ebx, 1                                        
03a143: mov      byte ptr [rbp + 0x168], 0                     
03a14a: mov      rcx, rax                                      
03a14d: mov      byte ptr [rbp + 0x178], bl                    
03a153: call     qword ptr [rax + 0x18]                        
03a156: mov      rdx, rax                                      
03a159: test     rax, rax                                      
03a15c: jns      0x3a171                                       
03a15e: mov      ecx, dword ptr [rdi + 0x10]                   
03a161: add      ecx, 0x10                                     
03a164: shl      ebx, cl                                       
03a166: movsxd   rax, ebx                                      
03a169: or       rax, rdx                                      
03a16c: jmp      0x3a3f3                                       
03a171: mov      r10, qword ptr [rsp + 0x38]                   
03a176: lea      r8, [rbp - 0x50]                              
03a17a: movzx    ecx, byte ptr [r10 + 1]                       
03a17f: mov      dl, byte ptr [r10 + 5]                        
03a183: add      rcx, r10                                      
03a186: call     0x3a038                                       
03a18b: movzx    ecx, byte ptr [r10 + 1]                       
03a190: lea      r8, [rbp + 0x14]                              
03a194: mov      dl, byte ptr [r10 + 8]                        
03a198: add      rcx, r10                                      
03a19b: call     0x3a038                                       