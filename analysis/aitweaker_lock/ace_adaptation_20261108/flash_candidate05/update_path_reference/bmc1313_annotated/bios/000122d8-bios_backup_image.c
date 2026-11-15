/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "000123c0": {
    "elf_va": "0x23c0",
    "file_offset": "0x23c0",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_coremacros",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "000123c4": {
    "elf_va": "0x23c4",
    "file_offset": "0x23c4",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "000123c8": {
    "elf_va": "0x23c8",
    "file_offset": "0x23c8",
    "raw_u32": "0x4548",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4548",
    "target_string": "/mnt/sdmmc0p%d/recovery_bios.bin_tmp"
  },
  "000123cc": {
    "elf_va": "0x23cc",
    "file_offset": "0x23cc",
    "raw_u32": "0x4570",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4570",
    "target_string": "/mnt/sdmmc0p%d/recovery_bios.bin"
  },
  "000123d0": {
    "elf_va": "0x23d0",
    "file_offset": "0x23d0",
    "raw_u32": "0x4594",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4594",
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
  iVar1 = DAT_000123c0;
  memset(acStack_1006c,0,0x40);
  memset(auStack_1002c,0,DAT_000123c4);
  snprintf(acStack_100ac,0x40,DAT_000123c8,*(undefined4 *)(iVar1 + 0x160));
  snprintf(acStack_1006c,0x40,DAT_000123cc,*(undefined4 *)(iVar1 + 0x160));
  iVar1 = rename(acStack_100ac,acStack_1006c);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000123d0);
    uStack_10028 = 0xff;
  }
  uStack_10024 = 0;
  auStack_1002c[0] = param_1;
  send_compmngr_response(auStack_1002c);
  return 0;
}

