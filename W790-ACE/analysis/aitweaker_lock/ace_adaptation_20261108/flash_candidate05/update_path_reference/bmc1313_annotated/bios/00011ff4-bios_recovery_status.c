/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00012064": {
    "elf_va": "0x2064",
    "file_offset": "0x2064",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00012068": {
    "elf_va": "0x2068",
    "file_offset": "0x2068",
    "raw_u32": "0x163f0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x163f0"
  }
}
*/

undefined4 bios_recovery_status(undefined2 param_1)

{
  undefined2 auStack_10024 [4];
  undefined2 uStack_1001c;
  undefined1 uStack_1001a;
  
  memset(auStack_10024,0,DAT_00012064);
  uStack_1001c = 1;
  uStack_1001a = (undefined1)*(undefined4 *)(DAT_00012068 + 0x60);
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

