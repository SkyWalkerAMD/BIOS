/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00012000": {
    "elf_va": "0x2000",
    "file_offset": "0x2000",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00012004": {
    "elf_va": "0x2004",
    "file_offset": "0x2004",
    "raw_u32": "0x163e8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x163e8"
  }
}
*/

undefined4 bios_recovery_status(undefined2 param_1)

{
  undefined2 auStack_10024 [4];
  undefined2 uStack_1001c;
  undefined1 uStack_1001a;
  
  memset(auStack_10024,0,DAT_00012000);
  uStack_1001c = 1;
  uStack_1001a = (undefined1)*(undefined4 *)(DAT_00012004 + 0x70);
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

