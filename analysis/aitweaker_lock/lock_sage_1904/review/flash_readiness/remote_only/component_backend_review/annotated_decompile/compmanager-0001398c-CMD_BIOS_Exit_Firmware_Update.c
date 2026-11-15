/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00013a50": {
    "elf_va": "0x3a50",
    "file_offset": "0x3a50",
    "raw_u32": "0x5180",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5180",
    "target_string": "CMD_BIOS_Exit_Firmware_Update"
  },
  "DAT_or_PTR_00013a54": {
    "elf_va": "0x3a54",
    "file_offset": "0x3a54",
    "raw_u32": "0x3d3",
    "target_elf_va": "0x3d3"
  },
  "DAT_or_PTR_00013a58": {
    "elf_va": "0x3a58",
    "file_offset": "0x3a58",
    "raw_u32": "0x51c0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x51c0",
    "target_string": "compmngrhelper.c"
  },
  "DAT_or_PTR_00013a5c": {
    "elf_va": "0x3a5c",
    "file_offset": "0x3a5c",
    "raw_u32": "0x57b8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x57b8",
    "target_string": "[%s:%d][%s]\n"
  },
  "DAT_or_PTR_00013a60": {
    "elf_va": "0x3a60",
    "file_offset": "0x3a60",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00013a64": {
    "elf_va": "0x3a64",
    "file_offset": "0x3a64",
    "raw_u32": "0x57c8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x57c8",
    "target_string": " Error while send BIOS exit firmware update..\n"
  },
  "DAT_or_PTR_00013a68": {
    "elf_va": "0x3a68",
    "file_offset": "0x3a68",
    "raw_u32": "0xffff",
    "target_elf_va": "0xffff"
  }
}
*/

void * CMD_BIOS_Exit_Firmware_Update(void *param_1)

{
  int iVar1;
  undefined2 uStack_20020;
  undefined1 uStack_2001e;
  undefined2 uStack_20018;
  undefined1 auStack_10014 [4];
  undefined4 uStack_10010;
  
  uStack_20020 = 0xe;
  uStack_2001e = 2;
  uStack_20018 = 0;
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013a5c,DAT_00013a58,DAT_00013a54,DAT_00013a50);
  iVar1 = send_compmngr_command(&uStack_20020,auStack_10014,0x3c);
  if (iVar1 == 0) {
    memcpy(param_1,auStack_10014,DAT_00013a60);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00013a64);
  uStack_10010 = DAT_00013a68;
  memcpy(param_1,auStack_10014,DAT_00013a60);
  return param_1;
}

