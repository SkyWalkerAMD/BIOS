/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00011e74": {
    "elf_va": "0x1e74",
    "file_offset": "0x1e74",
    "raw_u32": "0x160f0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x160f0"
  }
}
*/

undefined4 GetCompMngrMetaLibInfo(undefined4 *param_1)

{
  *param_1 = DAT_00011e74;
  return 1;
}

