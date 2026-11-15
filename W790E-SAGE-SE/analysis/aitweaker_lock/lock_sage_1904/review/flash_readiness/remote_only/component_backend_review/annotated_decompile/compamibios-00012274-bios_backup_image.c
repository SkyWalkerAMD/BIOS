/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_0001235c": {
    "elf_va": "0x235c",
    "file_offset": "0x235c",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_coremacros",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "DAT_or_PTR_00012360": {
    "elf_va": "0x2360",
    "file_offset": "0x2360",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00012364": {
    "elf_va": "0x2364",
    "file_offset": "0x2364",
    "raw_u32": "0x43f0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x43f0",
    "target_string": "/mnt/sdmmc0p%d/recovery_bios.bin_tmp"
  },
  "DAT_or_PTR_00012368": {
    "elf_va": "0x2368",
    "file_offset": "0x2368",
    "raw_u32": "0x4418",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4418",
    "target_string": "/mnt/sdmmc0p%d/recovery_bios.bin"
  },
  "DAT_or_PTR_0001236c": {
    "elf_va": "0x236c",
    "file_offset": "0x236c",
    "raw_u32": "0x443c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x443c",
    "target_string": "Error while taking the BIOS Recovery Image"
  }
}
*/

undefined4 bios_backup_image(undefined2 param_1)

{
  int iVar1;
  char acStack_100ac [64];
  char acStack_1006c [64];
  undefined2 auStack_1002c [2];
  undefined4 uStack_10028;
  undefined2 uStack_10024;
  
  memset(acStack_100ac,0,0x40);
  iVar1 = DAT_0001235c;
  memset(acStack_1006c,0,0x40);
  memset(auStack_1002c,0,DAT_00012360);
  snprintf(acStack_100ac,0x40,DAT_00012364,*(undefined4 *)(iVar1 + 0x160));
  snprintf(acStack_1006c,0x40,DAT_00012368,*(undefined4 *)(iVar1 + 0x160));
  iVar1 = rename(acStack_100ac,acStack_1006c);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_0001236c);
    uStack_10028 = 0xff;
  }
  uStack_10024 = 0;
  auStack_1002c[0] = param_1;
  send_compmngr_response(auStack_1002c);
  return 0;
}

