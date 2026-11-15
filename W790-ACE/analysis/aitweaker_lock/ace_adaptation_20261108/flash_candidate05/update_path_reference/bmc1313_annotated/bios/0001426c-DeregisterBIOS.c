/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "0001428c": {
    "elf_va": "0x428c",
    "file_offset": "0x428c",
    "raw_u32": "0x55e",
    "target_elf_va": "0x55e"
  },
  "00014290": {
    "elf_va": "0x4290",
    "file_offset": "0x4290",
    "raw_u32": "0x4488",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4488",
    "target_string": "compmngramibios.c"
  },
  "00014294": {
    "elf_va": "0x4294",
    "file_offset": "0x4294",
    "raw_u32": "0x5268",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5268",
    "target_string": "[%s:%d]COMP_MNGR : De-Registering the BIOS component"
  }
}
*/

undefined4 DeregisterBIOS(void)

{
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00014294,DAT_00014290,DAT_0001428c);
  return 0;
}

