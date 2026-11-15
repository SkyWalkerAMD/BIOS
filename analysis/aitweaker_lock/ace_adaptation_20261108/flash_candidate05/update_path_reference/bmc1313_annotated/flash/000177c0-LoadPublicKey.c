/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00017a5c": {
    "elf_va": "0x7a5c",
    "file_offset": "0x7a5c",
    "raw_u32": "0x9fb8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x9fb8",
    "target_string": "/dev/mtd0"
  },
  "00017a60": {
    "elf_va": "0x7a60",
    "file_offset": "0x7a60",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_coremacros",
      "symbol_va": 115484,
      "symbol_defined": true
    },
    "target_elf_va": "0x1c31c"
  },
  "00017a64": {
    "elf_va": "0x7a64",
    "file_offset": "0x7a64",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_corefeatures",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "00017a68": {
    "elf_va": "0x7a68",
    "file_offset": "0x7a68",
    "raw_u32": "0xaca0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0xaca0",
    "target_string": "$SHPKIDF$"
  },
  "00017a6c": {
    "elf_va": "0x7a6c",
    "file_offset": "0x7a6c",
    "raw_u32": "0xa634",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0xa634",
    "target_string": "w"
  },
  "00017a70": {
    "elf_va": "0x7a70",
    "file_offset": "0x7a70",
    "raw_u32": "0xabc8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0xabc8",
    "target_string": "/tmp/public.pem"
  },
  "00017a74": {
    "elf_va": "0x7a74",
    "file_offset": "0x7a74",
    "raw_u32": "0xbe8",
    "target_elf_va": "0xbe8"
  },
  "00017a78": {
    "elf_va": "0x7a78",
    "file_offset": "0x7a78",
    "raw_u32": "0xace8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0xace8",
    "target_string": "[%s:%d]unable to open temp public key %d\n"
  },
  "00017a7c": {
    "elf_va": "0x7a7c",
    "file_offset": "0x7a7c",
    "raw_u32": "0x91ec",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x91ec",
    "target_string": "flashlib.c"
  },
  "00017a80": {
    "elf_va": "0x7a80",
    "file_offset": "0x7a80",
    "raw_u32": "0xbd6",
    "target_elf_va": "0xbd6"
  },
  "00017a84": {
    "elf_va": "0x7a84",
    "file_offset": "0x7a84",
    "raw_u32": "0xacac",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0xacac",
    "target_string": "[%s:%d]public key not found\n"
  },
  "00017a88": {
    "elf_va": "0x7a88",
    "file_offset": "0x7a88",
    "raw_u32": "0xaccc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0xaccc",
    "target_string": "key length exceeded %d \n"
  },
  "00017a8c": {
    "elf_va": "0x7a8c",
    "file_offset": "0x7a8c",
    "raw_u32": "0xba8",
    "target_elf_va": "0xba8"
  },
  "00017a90": {
    "elf_va": "0x7a90",
    "file_offset": "0x7a90",
    "raw_u32": "0x9fc4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x9fc4",
    "target_string": "[%s:%d]Cannot open mtd raw device %s. Exiting...\n"
  },
  "00017a94": {
    "elf_va": "0x7a94",
    "file_offset": "0x7a94",
    "raw_u32": "0xbaf",
    "target_elf_va": "0xbaf"
  },
  "00017a98": {
    "elf_va": "0x7a98",
    "file_offset": "0x7a98",
    "raw_u32": "0xac6c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0xac6c",
    "target_string": "[%s:%d]Memory allocation fails for required size"
  }
}
*/

undefined4 LoadPublicKey(void)

{
  int __fd;
  void *__s;
  __off_t _Var1;
  int iVar2;
  int iVar3;
  FILE *__s_00;
  int *piVar4;
  int __offset;
  size_t sVar5;
  int iVar6;
  undefined4 uVar7;
  size_t local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined2 local_24;
  
  uVar7 = DAT_00017a5c;
  local_2c = 0;
  local_30 = 0;
  local_28 = 0;
  local_24 = 0;
  __fd = sigwrap_open(DAT_00017a5c,0);
  iVar3 = DAT_00017a60;
  if (__fd < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017a90,DAT_00017a7c,DAT_00017a8c,uVar7);
    sigwrap_close(__fd);
    uVar7 = 0xffffffff;
  }
  else {
    sVar5 = *(size_t *)(DAT_00017a60 + 0x1c);
    __s = malloc(sVar5);
    if (__s == (void *)0x0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017a98,DAT_00017a7c,DAT_00017a94);
      if (__fd != 0) {
        sigwrap_close(__fd);
      }
LAB_000179d0:
      uVar7 = 0xffffffff;
    }
    else {
      iVar6 = *(int *)(iVar3 + 0x14);
      if (*(int *)(DAT_00017a64 + 0xc) == 1) {
        iVar6 = iVar6 << 1;
      }
      if (0 < iVar6) {
        __offset = 0;
        do {
          memset(__s,0,sVar5);
          _Var1 = lseek(__fd,__offset,0);
          if ((_Var1 == -1) ||
             (iVar2 = sigwrap_read(__fd,__s,*(undefined4 *)(iVar3 + 0x1c)),
             iVar2 != *(int *)(iVar3 + 0x1c))) {
joined_r0x00017a04:
            if (__fd == 0) {
              uVar7 = 0xffffffff;
              goto LAB_00017990;
            }
            sigwrap_close(__fd);
            free(__s);
            goto LAB_000179d0;
          }
          iVar2 = ScanforFMH(__s,iVar2);
          if ((iVar2 != 0) && (*(short *)(iVar2 + 0x22) == 2)) {
            iVar6 = *(int *)(iVar3 + 0x1c);
            memcpy(&local_2c,(void *)((int)__s + iVar6 + -0x2000),10);
            iVar3 = strcmp((char *)&local_2c,DAT_00017a68);
            if (iVar3 == 0) {
              memcpy(&local_30,(void *)((int)__s + iVar6 + -0x1ff6),4);
              sVar5 = local_30;
              if ((int)local_30 < 0x321) {
                __s_00 = fopen(DAT_00017a70,DAT_00017a6c);
                if (__s_00 != (FILE *)0x0) {
                  fwrite((void *)((int)__s + iVar6 + -0x1ff2),1,sVar5,__s_00);
                  if (__fd != 0) {
                    sigwrap_close(__fd);
                  }
                  free(__s);
                  fclose(__s_00);
                  return 0;
                }
                piVar4 = __errno_location();
                IDBG_LINUXAPP_DbgOut(0x82,DAT_00017a78,DAT_00017a7c,DAT_00017a74,*piVar4);
              }
              else {
                IDBG_LINUXAPP_DbgOut(0x86,DAT_00017a88,local_30);
              }
            }
            else {
              IDBG_LINUXAPP_DbgOut(0x82,DAT_00017a84,DAT_00017a7c,DAT_00017a80);
            }
            goto joined_r0x00017a04;
          }
          sVar5 = *(size_t *)(iVar3 + 0x1c);
          __offset = __offset + sVar5;
        } while (__offset < iVar6);
      }
      if (__fd == 0) {
        uVar7 = 0;
LAB_00017990:
        free(__s);
        return uVar7;
      }
      sigwrap_close(__fd);
      free(__s);
      uVar7 = 0;
    }
  }
  return uVar7;
}

