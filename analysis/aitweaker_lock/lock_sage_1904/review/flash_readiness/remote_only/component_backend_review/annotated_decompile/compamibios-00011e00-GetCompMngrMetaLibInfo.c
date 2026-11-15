/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00011e10": {
    "elf_va": "0x1e10",
    "file_offset": "0x1e10",
    "raw_u32": "0x160e8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x160e8"
  }
}
*/

undefined4 GetCompMngrMetaLibInfo(undefined4 *param_1)

{
  *param_1 = DAT_00011e10;
  return 1;
}

