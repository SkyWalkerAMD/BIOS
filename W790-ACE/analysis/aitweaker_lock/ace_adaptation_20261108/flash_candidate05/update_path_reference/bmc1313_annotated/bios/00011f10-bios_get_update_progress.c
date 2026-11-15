/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00011fe4": {
    "elf_va": "0x1fe4",
    "file_offset": "0x1fe4",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00011fe8": {
    "elf_va": "0x1fe8",
    "file_offset": "0x1fe8",
    "raw_u32": "0x4464",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4464",
    "target_string": "GetProgress : Invalid Data length"
  },
  "00011fec": {
    "elf_va": "0x1fec",
    "file_offset": "0x1fec",
    "raw_u32": "0x164a4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x164a4"
  },
  "00011ff0": {
    "elf_va": "0x1ff0",
    "file_offset": "0x1ff0",
    "raw_u32": "0x164a0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x164a0"
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
  
  memset(auStack_10024,0,DAT_00011fe4);
  if ((param_3 & 0xffff) == 1) {
    local_6 = (char)(param_3 >> 0x10);
    __src = DAT_00011ff0;
    if ((local_6 == '\x01') || (__src = DAT_00011fec, local_6 == '\x02')) {
      memcpy(auStack_1001a,__src,4);
      uStack_1001c = 4;
    }
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00011fe8);
    uStack_1001c = 0;
    uStack_10020 = 0xff;
  }
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

