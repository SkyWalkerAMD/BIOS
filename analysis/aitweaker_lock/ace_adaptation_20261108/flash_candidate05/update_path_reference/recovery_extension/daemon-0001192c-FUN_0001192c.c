/* Exact ELF literal/relocation map. */
{
  "00011a88": {
    "elf_va": "0x11a88",
    "file_offset": "0x1a88",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00011a8c": {
    "elf_va": "0x11a8c",
    "file_offset": "0x1a8c",
    "raw_u32": "0x120e4",
    "target_elf_va": "0x120e4",
    "target_string": "/var/FWmode"
  },
  "00011a90": {
    "elf_va": "0x11a90",
    "file_offset": "0x1a90",
    "raw_u32": "0x120f0",
    "target_elf_va": "0x120f0",
    "target_string": "Other user is in firmware update mode \n"
  },
  "00011a94": {
    "elf_va": "0x11a94",
    "file_offset": "0x1a94",
    "raw_u32": "0x12118",
    "target_elf_va": "0x12118",
    "target_string": "w"
  },
  "00011a98": {
    "elf_va": "0x11a98",
    "file_offset": "0x1a98",
    "raw_u32": "0x239a0",
    "target_elf_va": "0x239a0"
  },
  "00011a9c": {
    "elf_va": "0x11a9c",
    "file_offset": "0x1a9c",
    "raw_u32": "0x12158",
    "target_elf_va": "0x12158",
    "target_string": "Error in writing the file.. %s"
  },
  "00011aa0": {
    "elf_va": "0x11aa0",
    "file_offset": "0x1aa0",
    "raw_u32": "0x1211c",
    "target_elf_va": "0x1211c",
    "target_string": "Error in creating file %s \n"
  },
  "00011aa4": {
    "elf_va": "0x11aa4",
    "file_offset": "0x1aa4",
    "raw_u32": "0x12138",
    "target_elf_va": "0x12138",
    "target_string": "Error in generating random no.\n"
  }
}

undefined4 FUN_0001192c(undefined2 param_1)

{
  int iVar1;
  FILE *__s;
  size_t sVar2;
  uint uStack_10038;
  undefined2 auStack_10034 [2];
  undefined4 uStack_10030;
  undefined2 uStack_1002c;
  undefined1 auStack_1002a [65542];
  
  uStack_10038 = 0xffffffff;
  memset(auStack_10034,0,DAT_00011a88);
  iVar1 = access(DAT_00011a8c,0);
  if (iVar1 == 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00011a90);
    uStack_10030 = 0xffffffff;
  }
  else {
    __s = fopen(DAT_00011a8c,DAT_00011a94);
    if (__s == (FILE *)0x0) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00011aa0,DAT_00011a8c);
      uStack_10030 = 0xffffffff;
    }
    else {
      iVar1 = generate_random_number(&uStack_10038,4);
      if (iVar1 == -1) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00011aa4);
        uStack_10030 = 0xffffffff;
      }
      else {
        uStack_10038 = uStack_10038 & 0x7fffffff;
        sVar2 = fwrite(&uStack_10038,1,4,__s);
        if (sVar2 == 4) {
          *DAT_00011a98 = uStack_10038;
        }
        else {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00011a9c,DAT_00011a8c);
          uStack_10030 = 0xffffffff;
        }
      }
      fclose(__s);
    }
  }
  uStack_1002c = 4;
  memcpy(auStack_1002a,&uStack_10038,4);
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

