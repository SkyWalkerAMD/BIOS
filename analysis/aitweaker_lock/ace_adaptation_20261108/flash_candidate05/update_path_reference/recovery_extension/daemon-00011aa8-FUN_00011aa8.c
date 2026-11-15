/* Exact ELF literal/relocation map. */
{
  "00011bac": {
    "elf_va": "0x11bac",
    "file_offset": "0x1bac",
    "raw_u32": "0x120e4",
    "target_elf_va": "0x120e4",
    "target_string": "/var/FWmode"
  },
  "00011bb0": {
    "elf_va": "0x11bb0",
    "file_offset": "0x1bb0",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00011bb4": {
    "elf_va": "0x11bb4",
    "file_offset": "0x1bb4",
    "raw_u32": "0x12178",
    "target_elf_va": "0x12178",
    "target_string": "Not in Firmware update mode.... \n"
  },
  "00011bb8": {
    "elf_va": "0x11bb8",
    "file_offset": "0x1bb8",
    "raw_u32": "0x239a0",
    "target_elf_va": "0x239a0"
  },
  "00011bbc": {
    "elf_va": "0x11bbc",
    "file_offset": "0x1bbc",
    "raw_u32": "0x1219c",
    "target_elf_va": "0x1219c",
    "target_string": "Invalid Firmware ID..."
  },
  "00011bc0": {
    "elf_va": "0x11bc0",
    "file_offset": "0x1bc0",
    "raw_u32": "0x131",
    "target_elf_va": "0x131"
  },
  "00011bc4": {
    "elf_va": "0x11bc4",
    "file_offset": "0x1bc4",
    "raw_u32": "0x11f94",
    "target_elf_va": "0x11f94",
    "target_string": "compmanager.c"
  },
  "00011bc8": {
    "elf_va": "0x11bc8",
    "file_offset": "0x1bc8",
    "raw_u32": "0x121b4",
    "target_elf_va": "0x121b4",
    "target_string": "[%s:%d]Unlinking %s failing"
  }
}

undefined4 FUN_00011aa8(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  char *__name;
  int iVar1;
  int iStack_10030;
  undefined2 auStack_1002c [2];
  undefined4 uStack_10028;
  undefined2 uStack_10024;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  __name = DAT_00011bac;
  iStack_10030 = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  memset(auStack_1002c,0,DAT_00011bb0);
  iVar1 = access(__name,0);
  if (iVar1 == 0) {
    memcpy(&iStack_10030,(void *)((int)&uStack_8 + 2),4);
    if (iStack_10030 == *DAT_00011bb8) {
      iVar1 = unlink(__name);
      if (iVar1 == -1) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00011bc8,DAT_00011bc4,DAT_00011bc0,__name);
      }
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00011bbc);
      uStack_10028 = 6;
    }
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00011bb4);
    uStack_10028 = 0xffffffff;
  }
  uStack_10024 = 0;
  auStack_1002c[0] = param_1;
  send_compmngr_response(auStack_1002c);
  return 0;
}

