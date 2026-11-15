/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00014048": {
    "elf_va": "0x4048",
    "file_offset": "0x4048",
    "raw_u32": "0x51a4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x51a4",
    "target_string": "w+"
  },
  "0001404c": {
    "elf_va": "0x404c",
    "file_offset": "0x404c",
    "raw_u32": "0x51a8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x51a8",
    "target_string": "/var/tmp/forcedUpdate_flag.txt"
  },
  "00014050": {
    "elf_va": "0x4050",
    "file_offset": "0x4050",
    "raw_u32": "0x51c8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x51c8",
    "target_string": "Error in opening %s"
  }
}
*/

undefined4 write_forcedUpdate_flag(void)

{
  FILE *__stream;
  
  __stream = fopen(DAT_0001404c,DAT_00014048);
  if (__stream != (FILE *)0x0) {
    fputc(0x31,__stream);
    fclose(__stream);
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00014050,DAT_0001404c);
  return 0xffffffff;
}

