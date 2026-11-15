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
03a1a0: lea      r10, [rbp + 0x168]                            
03a1a7: xor      r9d, r9d                                      
03a1aa: lea      rax, [rsp + 0x40]                             
03a1af: mov      qword ptr [rsp + 0x28], r10                   
03a1b4: lea      rdx, [rbp - 0x50]                             
03a1b8: mov      qword ptr [rsp + 0x20], rax                   
03a1bd: mov      cl, 2                                         
03a1bf: call     0x3a098                                       
03a1c4: mov      r8b, byte ptr [rbp + 0x168]                   
03a1cb: lea      rdx, [rsp + 0x40]                             
03a1d0: and      qword ptr [rsp + 0x20], 0                     
03a1d6: add      r8b, bl                                       
03a1d9: xor      r9d, r9d                                      
03a1dc: mov      cl, 4                                         
03a1de: call     0x39d1c                                       
03a1e3: mov      rax, qword ptr [rip + 0x3e4de]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a1ea: lea      rcx, [rsp + 0x40]                             
03a1ef: xor      r8d, r8d                                      
03a1f2: lea      edx, [r8 + 0x64]                              
03a1f6: call     qword ptr [rax + 0x168]                       
03a1fc: mov      rax, qword ptr [rip + 0x3e4c5]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a203: lea      rcx, [rbp - 0x50]                             
03a207: xor      r8d, r8d                                      
03a20a: mov      edx, 0x190                                    
03a20f: call     qword ptr [rax + 0x168]                       
03a215: mov      rax, qword ptr [rip + 0x4c0bc]                [862d8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a21c: lea      r9, [rsp + 0x38]                              
03a221: and      qword ptr [rsp + 0x20], 0                     
03a227: lea      r8, [rbp + 0x178]                             
03a22e: lea      rdx, [rsp + 0x34]                             
03a233: mov      byte ptr [rbp + 0x168], 0                     
03a23a: mov      rcx, rax                                      
03a23d: call     qword ptr [rax + 0x18]                        
03a240: mov      rdx, rax                                      
03a243: test     rax, rax                                      
03a246: js       0x3a15e                                       
03a24c: mov      r10, qword ptr [rsp + 0x38]                   
03a251: lea      r8, [rbp - 0x50]                              
03a255: movzx    ecx, byte ptr [r10 + 1]                       
03a25a: mov      dl, byte ptr [r10 + 4]                        
03a25e: add      rcx, r10                                      
03a261: call     0x3a038                                       
03a266: movzx    ecx, byte ptr [r10 + 1]                       
03a26b: lea      r8, [rbp + 0x14]                              
03a26f: mov      dl, byte ptr [r10 + 5]                        
03a273: add      rcx, r10                                      
03a276: call     0x3a038                                       
03a27b: movzx    ecx, byte ptr [r10 + 1]                       
03a280: lea      r8, [rbp + 0x78]                              
03a284: mov      dl, byte ptr [r10 + 6]                        
03a288: add      rcx, r10                                      
03a28b: call     0x3a038                                       
03a290: movzx    ecx, byte ptr [r10 + 1]                       
03a295: lea      r8, [rbp + 0xdc]                              
03a29c: mov      dl, byte ptr [r10 + 7]                        
03a2a0: add      rcx, r10                                      
03a2a3: call     0x3a038                                       
03a2a8: lea      r10, [rbp + 0x168]                            
03a2af: mov      r9b, bl                                       
03a2b2: lea      rax, [rsp + 0x40]                             
03a2b7: mov      qword ptr [rsp + 0x28], r10                   
03a2bc: lea      rdx, [rbp - 0x50]                             
03a2c0: mov      qword ptr [rsp + 0x20], rax                   
03a2c5: mov      cl, 4                                         
03a2c7: call     0x3a098                                       
03a2cc: mov      r8b, byte ptr [rbp + 0x168]                   
03a2d3: lea      rdx, [rsp + 0x40]                             
03a2d8: and      qword ptr [rsp + 0x20], 0                     
03a2de: add      r8b, bl                                       
03a2e1: xor      r9d, r9d                                      
03a2e4: mov      cl, 4                                         
03a2e6: call     0x39d1c                                       
03a2eb: mov      rax, qword ptr [rip + 0x3e3d6]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a2f2: lea      rcx, [rsp + 0x40]                             
03a2f7: xor      r8d, r8d                                      
03a2fa: lea      edx, [r8 + 0x64]                              
03a2fe: call     qword ptr [rax + 0x168]                       
03a304: mov      rax, qword ptr [rip + 0x3e3bd]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a30b: lea      rcx, [rbp - 0x50]                             
03a30f: xor      r8d, r8d                                      
03a312: mov      edx, 0x190                                    
03a317: call     qword ptr [rax + 0x168]                       
03a31d: mov      rax, qword ptr [rip + 0x4bfb4]                [862d8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a324: lea      r9, [rsp + 0x38]                              
03a329: and      qword ptr [rsp + 0x20], 0                     
03a32f: lea      r8, [rsp + 0x30]                              
03a334: lea      rdx, [rsp + 0x34]                             
03a339: mov      byte ptr [rbp + 0x168], 0                     
03a340: mov      rcx, rax                                      
03a343: call     qword ptr [rax + 0x18]                        
03a346: mov      rdx, rax                                      
03a349: test     rax, rax                                      
03a34c: js       0x3a15e                                       
03a352: mov      r10, qword ptr [rsp + 0x38]                   
03a357: lea      r8, [rbp - 0x50]                              
03a35b: movzx    ecx, byte ptr [r10 + 1]                       
03a360: mov      dl, byte ptr [r10 + 4]                        
03a364: add      rcx, r10                                      
03a367: call     0x3a038                                       
03a36c: movzx    ecx, byte ptr [r10 + 1]                       
03a371: lea      r8, [rbp + 0x14]                              
03a375: mov      dl, byte ptr [r10 + 5]                        
03a379: add      rcx, r10                                      
03a37c: call     0x3a038                                       
03a381: movzx    ecx, byte ptr [r10 + 1]                       
03a386: lea      r8, [rbp + 0x78]                              
03a38a: mov      dl, byte ptr [r10 + 6]                        
03a38e: add      rcx, r10                                      
03a391: call     0x3a038                                       
03a396: movzx    ecx, byte ptr [r10 + 1]                       
03a39b: lea      r8, [rbp + 0xdc]                              
03a3a2: mov      dl, byte ptr [r10 + 7]                        
03a3a6: add      rcx, r10                                      
03a3a9: call     0x3a038                                       
03a3ae: lea      r10, [rbp + 0x168]                            
03a3b5: mov      r9b, 2                                        
03a3b8: lea      rax, [rsp + 0x40]                             
03a3bd: mov      qword ptr [rsp + 0x28], r10                   
03a3c2: lea      rdx, [rbp - 0x50]                             
03a3c6: mov      qword ptr [rsp + 0x20], rax                   
03a3cb: mov      cl, 4                                         
03a3cd: call     0x3a098                                       
03a3d2: mov      r8b, byte ptr [rbp + 0x168]                   
03a3d9: lea      rdx, [rsp + 0x40]                             
03a3de: and      qword ptr [rsp + 0x20], 0                     
03a3e4: add      r8b, bl                                       
03a3e7: xor      r9d, r9d                                      
03a3ea: mov      cl, 4                                         
03a3ec: call     0x39d1c                                       
03a3f1: xor      eax, eax                                      
03a3f3: add      rsp, 0x240                                    
03a3fa: pop      rdi                                           
03a3fb: pop      rbx                                           
03a3fc: pop      rbp                                           
03a3fd: ret                                                    
03a3fe: int3                                                   
03a3ff: int3                                                   
03a400: push     rbx                                           
03a402: push     rbp                                           
03a403: push     rsi                                           
03a404: push     rdi                                           
03a405: sub      rsp, 0x48                                     
03a409: mov      rsi, qword ptr [rcx + 8]                      
03a40d: mov      eax, 0xfffe                                   
03a412: mov      bpl, byte ptr [rcx + 0x10]                    
03a416: mov      rbx, rsi                                      
03a419: mov      word ptr [rsp + 0x78], ax                     
03a41e: xor      edi, edi                                      
03a420: mov      byte ptr [rsp + 0x70], 4                      
03a425: mov      rax, qword ptr [rip + 0x3e29c]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a42c: xor      r8d, r8d                                      
03a42f: mov      rcx, rbx                                      
03a432: lea      edx, [r8 + 0x46]                              
03a436: call     qword ptr [rax + 0x168]                       
03a43c: mov      rax, qword ptr [rip + 0x4be95]                [862d8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a443: lea      r9, [rsp + 0x30]                              
03a448: and      qword ptr [rsp + 0x20], 0                     
03a44e: lea      r8, [rsp + 0x70]                              
03a453: lea      rdx, [rsp + 0x78]                             
03a458: mov      rcx, rax                                      
03a45b: call     qword ptr [rax + 0x18]                        
03a45e: test     rax, rax                                      
03a461: js       0x3a497                                       
03a463: mov      rdx, qword ptr [rsp + 0x30]                   
03a468: mov      rcx, rbx                                      
03a46b: call     0x3fd98                                       
03a470: test     rax, rax                                      
03a473: js       0x3a480                                       
03a475: lea      eax, [rdi + 1]                                
03a478: mov      byte ptr [rbx + 1], 1                         
03a47c: mov      byte ptr [rbx], al                            
03a47e: jmp      0x3a497                                       
03a480: mov      rax, qword ptr [rip + 0x3e241]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a487: xor      r8d, r8d                                      
03a48a: mov      rcx, rbx                                      
03a48d: lea      edx, [r8 + 0x46]                              
03a491: call     qword ptr [rax + 0x168]                       
03a497: lea      rcx, [rbx + 2]                                
03a49b: mov      dl, 0x40                                      
03a49d: call     0x39e8c                                       
03a4a2: inc      edi                                           
03a4a4: add      rbx, 0x46                                     
03a4a8: cmp      edi, 2                                        
03a4ab: jb       0x3a425                                       
03a4b1: mov      rax, qword ptr [rip + 0x3e210]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a4b8: lea      r8, [rsp + 0x80]                              
03a4c0: mov      edx, 0x8c                                     
03a4c5: mov      rcx, rsi                                      
03a4c8: call     qword ptr [rax + 0x158]                       
03a4ce: lea      rdx, [rsp + 0x88]                             
03a4d6: mov      cl, bpl                                       
03a4d9: call     0x39f88                                       
03a4de: mov      eax, dword ptr [rsp + 0x88]                   
03a4e5: cmp      dword ptr [rsp + 0x80], eax                   
03a4ec: je       0x3a529                                       
03a4ee: xor      ebx, ebx                                      
03a4f0: and      qword ptr [rsp + 0x20], 0                     
03a4f6: xor      r9d, r9d                                      
03a4f9: mov      eax, ebx                                      
03a4fb: mov      r8b, 0x46                                     
03a4fe: imul     rdx, rax, 0x46                                
03a502: mov      cl, 0x40                                      
03a504: add      rdx, rsi                                      
03a507: mov      byte ptr [rdx], bl                            
03a509: call     0x39d1c                                       
03a50e: test     rax, rax                                      
03a511: js       0x3a52b                                       
03a513: inc      ebx                                           
03a515: cmp      ebx, 2                                        
03a518: jb       0x3a4f0                                       
03a51a: mov      edx, dword ptr [rsp + 0x80]                   
03a521: mov      cl, bpl                                       
03a524: call     0x39f54                                       
03a529: xor      eax, eax                                      
03a52b: add      rsp, 0x48                                     
03a52f: pop      rdi                                           
03a530: pop      rsi                                           
03a531: pop      rbp                                           
03a532: pop      rbx                                           
03a533: ret                                                    
03a534: push     rbp                                           
03a536: push     rbx                                           
03a537: push     rsi                                           
03a538: push     rdi                                           
03a539: push     r14                                           
03a53b: push     r15                                           
03a53d: lea      rbp, [rsp - 8]                                
03a542: sub      rsp, 0x108                                    
03a549: mov      rsi, qword ptr [rcx + 8]                      
03a54d: mov      eax, 0xfffe                                   
03a552: mov      r14b, byte ptr [rcx + 0x10]                   
03a556: xor      r15d, r15d                                    
03a559: mov      word ptr [rbp + 0x48], ax                     
03a55d: mov      dil, r15b                                     
03a560: mov      byte ptr [rbp + 0x40], 0x11                   
03a564: mov      rax, qword ptr [rip + 0x3e15d]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a56b: xor      r8d, r8d                                      
03a56e: movzx    ebx, dil                                      
03a572: shl      rbx, 6                                        
03a576: add      rbx, rsi                                      
03a579: mov      rcx, rbx                                      
03a57c: lea      edx, [r8 + 0x40]                              
03a580: call     qword ptr [rax + 0x168]                       
03a586: mov      rax, qword ptr [rip + 0x4bd4b]                [862d8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a58d: lea      r9, [rsp + 0x30]                              
03a592: lea      r8, [rbp + 0x40]                              
03a596: mov      qword ptr [rsp + 0x20], r15                   
03a59b: lea      rdx, [rbp + 0x48]                             
03a59f: mov      rcx, rax                                      
03a5a2: call     qword ptr [rax + 0x18]                        
03a5a5: test     rax, rax                                      
03a5a8: js       0x3a776                                       
03a5ae: mov      rax, qword ptr [rsp + 0x30]                   
03a5b3: lea      r8, [rbp - 0x10]                              
03a5b7: movzx    ecx, byte ptr [rax + 1]                       
03a5bb: mov      dl, byte ptr [rax + 0x10]                     
03a5be: add      rcx, rax                                      
03a5c1: call     0x3a038                                       
03a5c6: test     rax, rax                                      
03a5c9: jne      0x3a5d3                                       
03a5cb: mov      al, dil                                       
03a5ce: shr      al, 4                                         
03a5d1: mov      byte ptr [rbx], al                            
03a5d3: movzx    eax, byte ptr [rbx]                           
03a5d6: shl      eax, 4                                        
03a5d9: movzx    ecx, dil                                      
03a5dd: sub      ecx, eax                                      
03a5df: mov      eax, ecx                                      
03a5e1: cdq                                                    
03a5e2: sub      eax, edx                                      
03a5e4: sar      eax, 1                                        
03a5e6: mov      byte ptr [rbx + 1], al                        
03a5e9: and      ecx, 0x80000001                               
03a5ef: jge      0x3a5f8                                       
03a5f1: dec      ecx                                           
03a5f3: or       ecx, 0xfffffffe                               
03a5f6: inc      ecx                                           
03a5f8: mov      byte ptr [rbx + 2], cl                        
03a5fb: mov      rax, qword ptr [rsp + 0x30]                   
03a600: cmp      word ptr [rax + 0xc], r15w                    
03a605: je       0x3a741                                       
03a60b: mov      word ptr [rbx + 3], 0x401                     
03a611: mov      dl, r15b                                      
03a614: mov      byte ptr [rbx + 0x37], 1                      
03a618: mov      cl, r15b                                      
03a61b: mov      rax, qword ptr [rsp + 0x30]                   
03a620: mov      qword ptr [rsp + 0x40], r15                   
03a625: mov      qword ptr [rsp + 0x48], 0x42b                 
03a62e: mov      qword ptr [rsp + 0x50], 0x535                 
03a637: movzx    r8d, word ptr [rax + 0x15]                    
03a63c: mov      qword ptr [rsp + 0x58], 0x640                 
03a645: mov      qword ptr [rsp + 0x60], 0x74b                 
03a64e: mov      qword ptr [rsp + 0x68], 0x855                 
03a657: mov      qword ptr [rsp + 0x70], 0x960                 
03a660: mov      qword ptr [rsp + 0x78], 0xa6a                 
03a669: mov      qword ptr [rbp - 0x80], 0xaf0                 
03a671: mov      qword ptr [rbp - 0x78], 0xb75                 
03a679: mov      qword ptr [rbp - 0x70], 0xbb8                 
03a681: mov      qword ptr [rbp - 0x68], 0xc80                 
03a689: mov      qword ptr [rbp - 0x60], 0xd48                 
03a691: mov      qword ptr [rbp - 0x58], 0xd8a                 
03a699: mov      qword ptr [rbp - 0x50], 0xe10                 
03a6a1: mov      qword ptr [rbp - 0x48], 0xe95                 
03a6a9: mov      qword ptr [rbp - 0x40], 0xed8                 
03a6b1: mov      qword ptr [rbp - 0x38], 0xfa0                 
03a6b9: mov      qword ptr [rbp - 0x30], 0x1068                
03a6c1: mov      qword ptr [rbp - 0x28], 0x10aa                
03a6c9: mov      qword ptr [rbp - 0x20], 0x1130                
03a6d1: movzx    eax, cl                                       
03a6d4: cmp      r8, qword ptr [rsp + rax*8 + 0x40]            
03a6d9: je       0x3a6e4                                       
03a6db: inc      cl                                            
03a6dd: cmp      cl, 0x15                                      
03a6e0: jb       0x3a6d1                                       
03a6e2: jmp      0x3a6e6                                       
03a6e4: mov      dl, cl                                        
03a6e6: mov      byte ptr [rbx + 5], dl                        
03a6e9: lea      r8, [rbx + 7]                                 
03a6ed: mov      rax, qword ptr [rsp + 0x30]                   
03a6f2: movzx    ecx, word ptr [rax + 0xc]                     
03a6f6: shr      cx, 0xa                                       
03a6fa: mov      byte ptr [rbx + 6], cl                        
03a6fd: mov      rax, qword ptr [rsp + 0x30]                   
03a702: movzx    ecx, byte ptr [rax + 1]                       
03a706: mov      dl, byte ptr [rax + 0x17]                     
03a709: add      rcx, rax                                      
03a70c: call     0x3a038                                       
03a711: mov      rax, qword ptr [rsp + 0x30]                   
03a716: lea      r8, [rbx + 0x17]                              
03a71a: movzx    ecx, byte ptr [rax + 1]                       
03a71e: mov      dl, byte ptr [rax + 0x1a]                     
03a721: add      rcx, rax                                      
03a724: call     0x3a038                                       
03a729: mov      rax, qword ptr [rsp + 0x30]                   
03a72e: lea      r8, [rbx + 0x38]                              
03a732: movzx    ecx, byte ptr [rax + 1]                       
03a736: mov      dl, byte ptr [rax + 0x18]                     
03a739: add      rcx, rax                                      
03a73c: call     0x3a038                                       
03a741: mov      dl, 7                                         
03a743: lea      rcx, [rbp - 0x10]                             
03a747: call     0x39e8c                                       
03a74c: cmp      byte ptr [rbx + 3], 1                         
03a750: lea      rax, [rip + 0x38f75]                          [736cc] 547275650000000046616c73650000004944450041484349000000005241494400000000554e4b4e4f574e005400720075007300740065006400440065007600
03a757: lea      rcx, [rip + 0x38f76]                          [736d4] 46616c73650000004944450041484349000000005241494400000000554e4b4e4f574e0054007200750073007400650064004400650076006900630065005300
03a75e: mov      dl, 7                                         
03a760: cmove    rcx, rax                                      
03a764: call     0x39e8c                                       
03a769: inc      dil                                           
03a76c: cmp      dil, 0x20                                     
03a770: jb       0x3a564                                       
03a776: mov      rax, qword ptr [rip + 0x3df4b]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a77d: lea      r8, [rbp + 0x50]                              
03a781: mov      edx, 0x800                                    
03a786: mov      rcx, rsi                                      
03a789: call     qword ptr [rax + 0x158]                       
03a78f: lea      rdx, [rbp + 0x58]                             
03a793: mov      cl, r14b                                      
03a796: call     0x39f88                                       
03a79b: mov      eax, dword ptr [rbp + 0x58]                   
03a79e: cmp      dword ptr [rbp + 0x50], eax                   
03a7a1: je       0x3a7d9                                       
03a7a3: mov      bl, r15b                                      
03a7a6: movzx    edx, bl                                       
03a7a9: xor      r9d, r9d                                      
03a7ac: shl      rdx, 6                                        
03a7b0: mov      r8b, 0x40                                     
03a7b3: add      rdx, rsi                                      
03a7b6: mov      qword ptr [rsp + 0x20], r15                   
03a7bb: mov      cl, 0x42                                      
03a7bd: call     0x39d1c                                       
03a7c2: test     rax, rax                                      
03a7c5: js       0x3a7db                                       
03a7c7: inc      bl                                            
03a7c9: cmp      bl, 0x20                                      
03a7cc: jb       0x3a7a6                                       
03a7ce: mov      edx, dword ptr [rbp + 0x50]                   
03a7d1: mov      cl, r14b                                      
03a7d4: call     0x39f54                                       
03a7d9: xor      eax, eax                                      
03a7db: add      rsp, 0x108                                    
03a7e2: pop      r15                                           
03a7e4: pop      r14                                           
03a7e6: pop      rdi                                           
03a7e7: pop      rsi                                           
03a7e8: pop      rbx                                           
03a7e9: pop      rbp                                           
03a7ea: ret                                                    
03a7eb: int3                                                   
03a7ec: push     rbp                                           
03a7ee: push     rbx                                           
03a7ef: push     rsi                                           
03a7f0: push     rdi                                           
03a7f1: push     r14                                           
03a7f3: mov      rbp, rsp                                      
03a7f6: sub      rsp, 0x70                                     
03a7fa: mov      rsi, qword ptr [rcx + 8]                      
03a7fe: lea      rax, [rbp - 0x40]                             
03a802: mov      r14b, byte ptr [rcx + 0x10]                   
03a806: lea      r9, [rbp + 0x48]                              
03a80a: and      qword ptr [rbp + 0x48], 0                     
03a80f: lea      rdx, [rip + 0x31d9a]                          [6c5b0] 00b2f54cb868a54c9eecb23e3f50029ab6730e22db6b13448405b974b108619a63bf6d440225da4cbcfa2465d2b0fe9df63f580336cb4049947eb9b39f4afaf7
03a816: and      qword ptr [rbp - 0x40], 0                     
03a81b: xor      r8d, r8d                                      
03a81e: and      qword ptr [rbp + 0x40], 0                     
03a823: mov      rbx, rcx                                      
03a826: mov      qword ptr [rsp + 0x20], rax                   
03a82b: mov      rax, qword ptr [rip + 0x3de96]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a832: lea      ecx, [r8 + 2]                                 
03a836: call     qword ptr [rax + 0x138]                       
03a83c: mov      rdx, rax                                      
03a83f: test     rax, rax                                      
03a842: jns      0x3a85b                                       
03a844: mov      ecx, dword ptr [rbx + 0x10]                   
03a847: mov      eax, 1                                        
03a84c: add      ecx, 0x10                                     
03a84f: shl      eax, cl                                       
03a851: cdqe                                                   
03a853: or       rax, rdx                                      
03a856: jmp      0x3a982                                       
03a85b: xor      edi, edi                                      
03a85d: lea      ebx, [rdi + 1]                                
03a860: cmp      qword ptr [rbp + 0x48], rdi                   
03a864: jbe      0x3a8f1                                       
03a86a: mov      rcx, qword ptr [rbp - 0x40]                   
03a86e: lea      r8, [rbp + 0x40]                              
03a872: mov      rax, qword ptr [rip + 0x3de4f]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a879: lea      rdx, [rip + 0x31d30]                          [6c5b0] 00b2f54cb868a54c9eecb23e3f50029ab6730e22db6b13448405b974b108619a63bf6d440225da4cbcfa2465d2b0fe9df63f580336cb4049947eb9b39f4afaf7
03a880: mov      rcx, qword ptr [rcx + rdi*8]                  
03a884: call     qword ptr [rax + 0x98]                        
03a88a: test     rax, rax                                      
03a88d: js       0x3a8e4                                       
03a88f: mov      rax, qword ptr [rbp + 0x40]                   
03a893: mov      r10, qword ptr [rax + 0xc0]                   
03a89a: test     r10, r10                                      
03a89d: je       0x3a8e4                                       
03a89f: cmp      dword ptr [r10 + 0xe8], 0                     
03a8a7: je       0x3a8e4                                       
03a8a9: lea      rax, [rbp + 0x38]                             
03a8ad: mov      rcx, r10                                      
03a8b0: lea      r9, [rbp - 0x38]                              
03a8b4: mov      qword ptr [rsp + 0x20], rax                   
03a8b9: lea      r8, [rbp - 0x30]                              
03a8bd: lea      rdx, [rbp - 0x28]                             
03a8c1: call     qword ptr [r10 + 0x70]                        
03a8c5: lea      rax, [rbp - 0x20]                             
03a8c9: mov      qword ptr [rsp + 0x20], rax                   
03a8ce: lea      r9, [rbp - 0x18]                              
03a8d2: mov      rax, qword ptr [rbp + 0x40]                   
03a8d6: lea      r8, [rbp - 0x10]                              
03a8da: lea      rdx, [rbp - 8]                                
03a8de: mov      rcx, rax                                      
03a8e1: call     qword ptr [rax + 0x70]                        
03a8e4: add      rdi, rbx                                      
03a8e7: cmp      rdi, qword ptr [rbp + 0x48]                   
03a8eb: jb       0x3a86a                                       
03a8f1: mov      rcx, qword ptr [rbp - 0x40]                   
03a8f5: test     rcx, rcx                                      
03a8f8: je       0x3a904                                       
03a8fa: mov      rax, qword ptr [rip + 0x3ddc7]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a901: call     qword ptr [rax + 0x48]                        
03a904: mov      rax, qword ptr [rip + 0x3ddbd]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a90b: lea      r8, [rbp + 0x30]                              
03a90f: mov      edx, 0x1e0                                    
03a914: mov      rcx, rsi                                      
03a917: call     qword ptr [rax + 0x158]                       
03a91d: lea      rdx, [rbp + 0x38]                             
03a921: mov      cl, r14b                                      
03a924: call     0x39f88                                       
03a929: mov      eax, dword ptr [rbp + 0x38]                   
03a92c: cmp      dword ptr [rbp + 0x30], eax                   
03a92f: je       0x3a980                                       
03a931: xor      edi, edi                                      
03a933: mov      rax, qword ptr [rip + 0x3dd8e]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a93a: xor      r8d, r8d                                      
03a93d: mov      rcx, rsi                                      
03a940: lea      edx, [r8 + 0xc]                               
03a944: call     qword ptr [rax + 0x168]                       
03a94a: and      qword ptr [rsp + 0x20], 0                     
03a950: xor      r9d, r9d                                      
03a953: mov      r8b, 0xc                                      
03a956: mov      byte ptr [rsi], dil                           
03a959: mov      rdx, rsi                                      
03a95c: mov      cl, 0x44                                      
03a95e: call     0x39d1c                                       
03a963: test     rax, rax                                      
03a966: js       0x3a982                                       
03a968: add      rdi, rbx                                      
03a96b: add      rsi, 0xc                                      
03a96f: cmp      rdi, 0x28                                     
03a973: jb       0x3a933                                       
03a975: mov      edx, dword ptr [rbp + 0x30]                   
03a978: mov      cl, r14b                                      
03a97b: call     0x39f54                                       
03a980: xor      eax, eax                                      
03a982: add      rsp, 0x70                                     
03a986: pop      r14                                           
03a988: pop      rdi                                           
03a989: pop      rsi                                           
03a98a: pop      rbx                                           
03a98b: pop      rbp                                           
03a98c: ret                                                    
03a98d: int3                                                   
03a98e: int3                                                   
03a98f: int3                                                   
03a990: push     rbp                                           
03a992: push     rbx                                           
03a993: push     rsi                                           
03a994: push     rdi                                           
03a995: push     r14                                           
03a997: push     r15                                           
03a999: mov      rbp, rsp                                      
03a99c: sub      rsp, 0x58                                     
03a9a0: mov      rsi, qword ptr [rcx + 8]                      
03a9a4: lea      rax, [rbp + 0x50]                             
03a9a8: mov      r15b, byte ptr [rcx + 0x10]                   
03a9ac: lea      r9, [rbp + 0x48]                              
03a9b0: and      qword ptr [rbp + 0x48], 0                     
03a9b5: lea      rdx, [rip + 0x31bf4]                          [6c5b0] 00b2f54cb868a54c9eecb23e3f50029ab6730e22db6b13448405b974b108619a63bf6d440225da4cbcfa2465d2b0fe9df63f580336cb4049947eb9b39f4afaf7
03a9bc: and      qword ptr [rbp + 0x50], 0                     
03a9c1: xor      r8d, r8d                                      
03a9c4: and      qword ptr [rbp - 0x28], 0                     
03a9c9: mov      r14, rcx                                      
03a9cc: mov      qword ptr [rsp + 0x20], rax                   
03a9d1: mov      rax, qword ptr [rip + 0x3dcf0]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03a9d8: lea      ecx, [r8 + 2]                                 
03a9dc: call     qword ptr [rax + 0x138]                       
03a9e2: mov      rdx, rax                                      
03a9e5: test     rax, rax                                      
03a9e8: jns      0x3aa02                                       
03a9ea: mov      ecx, dword ptr [r14 + 0x10]                   
03a9ee: mov      eax, 1                                        
03a9f3: add      ecx, 0x10                                     
03a9f6: shl      eax, cl                                       
03a9f8: cdqe                                                   
03a9fa: or       rax, rdx                                      
03a9fd: jmp      0x3aaf4                                       
03aa02: mov      rax, qword ptr [rip + 0x3dcbf]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03aa09: xor      r8d, r8d                                      
03aa0c: mov      rcx, rsi                                      
03aa0f: lea      edx, [r8 + 0x34]                              
03aa13: call     qword ptr [rax + 0x168]                       
03aa19: xor      edi, edi                                      
03aa1b: lea      ebx, [rdi + 1]                                
03aa1e: cmp      qword ptr [rbp + 0x48], rdi                   
03aa22: jbe      0x3aa7a                                       
03aa24: mov      rcx, qword ptr [rbp + 0x50]                   
03aa28: lea      r8, [rbp - 0x28]                              
03aa2c: mov      rax, qword ptr [rip + 0x3dc95]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03aa33: lea      rdx, [rip + 0x31b76]                          [6c5b0] 00b2f54cb868a54c9eecb23e3f50029ab6730e22db6b13448405b974b108619a63bf6d440225da4cbcfa2465d2b0fe9df63f580336cb4049947eb9b39f4afaf7
03aa3a: mov      rcx, qword ptr [rcx + rdi*8]                  
03aa3e: call     qword ptr [rax + 0x98]                        
03aa44: test     rax, rax                                      
03aa47: js       0x3aa71                                       
03aa49: lea      rax, [rbp + 0x40]                             
03aa4d: mov      qword ptr [rsp + 0x20], rax                   
03aa52: lea      r9, [rbp - 0x20]                              
03aa56: mov      rax, qword ptr [rbp - 0x28]                   
03aa5a: lea      r8, [rbp - 0x18]                              
03aa5e: lea      rdx, [rbp - 0x10]                             
03aa62: mov      rcx, rax                                      
03aa65: call     qword ptr [rax + 0x70]                        
03aa68: test     rax, rax                                      
03aa6b: js       0x3ab01                                       
03aa71: add      rdi, rbx                                      
03aa74: cmp      rdi, qword ptr [rbp + 0x48]                   
03aa78: jb       0x3aa24                                       
03aa7a: mov      rcx, qword ptr [rbp + 0x50]                   
03aa7e: test     rcx, rcx                                      
03aa81: je       0x3aa8d                                       
03aa83: mov      rax, qword ptr [rip + 0x3dc3e]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03aa8a: call     qword ptr [rax + 0x48]                        
03aa8d: mov      rax, qword ptr [rip + 0x3dc34]                [786c8] 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
03aa94: lea      r8, [rbp + 0x38]                              
03aa98: mov      edx, 0x34                                     
03aa9d: mov      rcx, rsi                                      
03aaa0: call     qword ptr [rax + 0x158]                       
03aaa6: lea      rdx, [rbp + 0x40]                             
03aaaa: mov      cl, r15b                                      
03aaad: call     0x39f88                                       
03aab2: mov      eax, dword ptr [rbp + 0x40]                   
03aab5: cmp      dword ptr [rbp + 0x38], eax                   
03aab8: je       0x3aaf2                                       
03aaba: xor      edi, edi                                      
03aabc: and      qword ptr [rsp + 0x20], 0                     
03aac2: xor      r9d, r9d                                      
03aac5: mov      r8b, 0xd                                      
03aac8: mov      byte ptr [rsi], dil                           
03aacb: mov      rdx, rsi                                      
03aace: mov      cl, 0x46                                      
03aad0: call     0x39d1c                                       
03aad5: test     rax, rax                                      
03aad8: js       0x3aaf4                                       
03aada: add      rdi, rbx                                      
03aadd: add      rsi, 0xd                                      
03aae1: cmp      rdi, 4                                        
03aae5: jb       0x3aabc                                       
03aae7: mov      edx, dword ptr [rbp + 0x38]                   
03aaea: mov      cl, r15b                                      
03aaed: call     0x39f54                                       
03aaf2: xor      eax, eax                                      
03aaf4: add      rsp, 0x58                                     
03aaf8: pop      r15                                           
03aafa: pop      r14                                           
03aafc: pop      rdi                                           
03aafd: pop      rsi                                           
03aafe: pop      rbx                                           
03aaff: pop      rbp                                           
03ab00: ret                                                    
03ab01: mov      ecx, dword ptr [r14 + 0x10]                   
03ab05: add      ecx, 0x10                                     
03ab08: shl      ebx, cl                                       
03ab0a: movabs   rcx, 0x8000000000000007                       
03ab14: movsxd   rax, ebx                                      
03ab17: or       rax, rcx                                      
03ab1a: jmp      0x3aaf4                                       