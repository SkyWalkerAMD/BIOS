/* Exact ELF literal/relocation map. */
{
  "00012a28": {
    "elf_va": "0x2a28",
    "file_offset": "0x2a28",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00012a2c": {
    "elf_va": "0x2a2c",
    "file_offset": "0x2a2c",
    "raw_u32": "0x4d88",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4d88",
    "target_string": "/var/block_chassis_ops"
  },
  "00012a30": {
    "elf_va": "0x2a30",
    "file_offset": "0x2a30",
    "raw_u32": "0x4dc8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4dc8",
    "target_string": "Error while exiting into fimware update mode\n"
  },
  "00012a34": {
    "elf_va": "0x2a34",
    "file_offset": "0x2a34",
    "raw_u32": "0xffff",
    "target_elf_va": "0xffff"
  }
}

void * CMD_Exit_FW_Update_mode(void *param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uStack_20024;
  undefined2 auStack_20020 [4];
  undefined2 uStack_20018;
  undefined1 auStack_20016 [65538];
  undefined1 auStack_10014 [4];
  int iStack_10010;
  
  uStack_20024 = param_2;
  memset(auStack_20020,0,DAT_00012a28);
  memset(auStack_10014,0,DAT_00012a28);
  auStack_20020[0] = 2;
  uStack_20018 = 4;
  memcpy(auStack_20016,&uStack_20024,4);
  iVar1 = send_compmngr_command(auStack_20020,auStack_10014,0x3c);
  if (iVar1 == 0) {
    if (iStack_10010 == 0) {
      unlink(DAT_00012a2c);
    }
    memcpy(param_1,auStack_10014,DAT_00012a28);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00012a30);
  iStack_10010 = DAT_00012a34;
  memcpy(param_1,auStack_10014,DAT_00012a28);
  return param_1;
}

