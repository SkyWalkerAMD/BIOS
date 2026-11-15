/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00012714": {
    "elf_va": "0x2714",
    "file_offset": "0x2714",
    "raw_u32": "0x4714",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4714",
    "target_string": "rb"
  },
  "00012718": {
    "elf_va": "0x2718",
    "file_offset": "0x2718",
    "raw_u32": "0x4718",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4718",
    "target_string": "/conf/FeatureList.dat"
  }
}
*/

undefined1 Check_FeatureList(void)

{
  FILE *__stream;
  undefined1 uStack_20;
  undefined1 local_1f;
  
  __stream = fopen(DAT_00012718,DAT_00012714);
  if (__stream == (FILE *)0x0) {
    local_1f = 1;
  }
  else {
    fread(&uStack_20,0x15,1,__stream);
    fclose(__stream);
  }
  return local_1f;
}

