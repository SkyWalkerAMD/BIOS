/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_0001225c": {
    "elf_va": "0x225c",
    "file_offset": "0x225c",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00012260": {
    "elf_va": "0x2260",
    "file_offset": "0x2260",
    "raw_u32": "0x420c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x420c",
    "target_string": "bios_activate_update"
  },
  "DAT_or_PTR_00012264": {
    "elf_va": "0x2264",
    "file_offset": "0x2264",
    "raw_u32": "0x3fa",
    "target_elf_va": "0x3fa"
  },
  "DAT_or_PTR_00012268": {
    "elf_va": "0x2268",
    "file_offset": "0x2268",
    "raw_u32": "0x4344",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4344",
    "target_string": "[%s:%d][%s]\n"
  },
  "DAT_or_PTR_0001226c": {
    "elf_va": "0x226c",
    "file_offset": "0x226c",
    "raw_u32": "0x4330",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4330",
    "target_string": "compmngramibios.c"
  },
  "DAT_or_PTR_00012270": {
    "elf_va": "0x2270",
    "file_offset": "0x2270",
    "raw_u32": "0x43d0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x43d0",
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
  
  memset(auStack_10024,0,DAT_0001225c);
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00012268,DAT_0001226c,DAT_00012264,DAT_00012260);
  iVar1 = RebootHost();
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00012270);
    uStack_10020 = 0xff;
  }
  uStack_1001c = 0;
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

