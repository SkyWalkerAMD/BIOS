/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00013f9c": {
    "elf_va": "0x3f9c",
    "file_offset": "0x3f9c",
    "raw_u32": "0x4f80",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4f80",
    "target_string": "w+"
  },
  "DAT_or_PTR_00013fa0": {
    "elf_va": "0x3fa0",
    "file_offset": "0x3fa0",
    "raw_u32": "0x4f84",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4f84",
    "target_string": "/var/tmp/forcedUpdate_flag.txt"
  },
  "DAT_or_PTR_00013fa4": {
    "elf_va": "0x3fa4",
    "file_offset": "0x3fa4",
    "raw_u32": "0x4fa4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4fa4",
    "target_string": "Error in opening %s"
  }
}
*/

undefined4 write_forcedUpdate_flag(void)

{
  FILE *__stream;
  
  __stream = fopen(DAT_00013fa0,DAT_00013f9c);
  if (__stream != (FILE *)0x0) {
    fputc(0x31,__stream);
    fclose(__stream);
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fa4,DAT_00013fa0);
  return 0xffffffff;
}

