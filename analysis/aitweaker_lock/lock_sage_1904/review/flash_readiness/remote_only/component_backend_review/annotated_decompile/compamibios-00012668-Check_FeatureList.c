/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_000126b0": {
    "elf_va": "0x26b0",
    "file_offset": "0x26b0",
    "raw_u32": "0x45bc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x45bc",
    "target_string": "rb"
  },
  "DAT_or_PTR_000126b4": {
    "elf_va": "0x26b4",
    "file_offset": "0x26b4",
    "raw_u32": "0x45c0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x45c0",
    "target_string": "/conf/FeatureList.dat"
  }
}
*/

undefined1 Check_FeatureList(void)

{
  FILE *__stream;
  undefined1 uStack_20;
  undefined1 local_1f;
  
  __stream = fopen(DAT_000126b4,DAT_000126b0);
  if (__stream == (FILE *)0x0) {
    local_1f = 1;
  }
  else {
    fread(&uStack_20,0x15,1,__stream);
    fclose(__stream);
  }
  return local_1f;
}

