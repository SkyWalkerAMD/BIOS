/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "000122c0": {
    "elf_va": "0x22c0",
    "file_offset": "0x22c0",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "000122c4": {
    "elf_va": "0x22c4",
    "file_offset": "0x22c4",
    "raw_u32": "0x43b4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x43b4",
    "target_string": "bios_activate_update"
  },
  "000122c8": {
    "elf_va": "0x22c8",
    "file_offset": "0x22c8",
    "raw_u32": "0x44d",
    "target_elf_va": "0x44d"
  },
  "000122cc": {
    "elf_va": "0x22cc",
    "file_offset": "0x22cc",
    "raw_u32": "0x449c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x449c",
    "target_string": "[%s:%d][%s]\n"
  },
  "000122d0": {
    "elf_va": "0x22d0",
    "file_offset": "0x22d0",
    "raw_u32": "0x4488",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4488",
    "target_string": "compmngramibios.c"
  },
  "000122d4": {
    "elf_va": "0x22d4",
    "file_offset": "0x22d4",
    "raw_u32": "0x4528",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4528",
    "target_string": "Error in rebooting the host\n"
  }
}
*/

undefined4 bios_activate_update(undefined2 param_1)

{
  int iVar1;
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  
  memset(auStack_10024,0,DAT_000122c0);
  IDBG_LINUXAPP_DbgOut(0x82,DAT_000122cc,DAT_000122d0,DAT_000122c8,DAT_000122c4);
  iVar1 = RebootHost();
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000122d4);
    uStack_10020 = 0xff;
  }
  uStack_1001c = 0;
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

