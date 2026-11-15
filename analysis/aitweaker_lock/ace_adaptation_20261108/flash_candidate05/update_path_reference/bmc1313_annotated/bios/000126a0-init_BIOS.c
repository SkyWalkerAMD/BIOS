/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "000126c0": {
    "elf_va": "0x26c0",
    "file_offset": "0x26c0",
    "raw_u32": "0x54f",
    "target_elf_va": "0x54f"
  },
  "000126c4": {
    "elf_va": "0x26c4",
    "file_offset": "0x26c4",
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
  "000126c8": {
    "elf_va": "0x26c8",
    "file_offset": "0x26c8",
    "raw_u32": "0x46e0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x46e0",
    "target_string": "[%s:%d]COMP_MNGR : Initializing the BIOS Component"
  }
}
*/

undefined4 init_BIOS(void)

{
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000126c8,DAT_000126c4,DAT_000126c0);
  return 0;
}

