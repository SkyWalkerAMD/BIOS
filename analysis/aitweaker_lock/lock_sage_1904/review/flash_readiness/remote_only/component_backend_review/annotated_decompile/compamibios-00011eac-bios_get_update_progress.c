/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00011f80": {
    "elf_va": "0x1f80",
    "file_offset": "0x1f80",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00011f84": {
    "elf_va": "0x1f84",
    "file_offset": "0x1f84",
    "raw_u32": "0x430c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x430c",
    "target_string": "GetProgress : Invalid Data length"
  },
  "DAT_or_PTR_00011f88": {
    "elf_va": "0x1f88",
    "file_offset": "0x1f88",
    "raw_u32": "0x16464",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x16464"
  },
  "DAT_or_PTR_00011f8c": {
    "elf_va": "0x1f8c",
    "file_offset": "0x1f8c",
    "raw_u32": "0x16460",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x16460"
  }
}
*/

undefined4 bios_get_update_progress(undefined2 param_1,undefined4 param_2,uint param_3)

{
  void *__src;
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  undefined1 auStack_1001a [65538];
  char local_6;
  
  memset(auStack_10024,0,DAT_00011f80);
  if ((param_3 & 0xffff) == 1) {
    local_6 = (char)(param_3 >> 0x10);
    __src = DAT_00011f8c;
    if ((local_6 == '\x01') || (__src = DAT_00011f88, local_6 == '\x02')) {
      memcpy(auStack_1001a,__src,4);
      uStack_1001c = 4;
    }
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00011f84);
    uStack_1001c = 0;
    uStack_10020 = 0xff;
  }
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

