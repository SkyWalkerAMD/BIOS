/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00012e14": {
    "elf_va": "0x2e14",
    "file_offset": "0x2e14",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_mtdASUSBiosHeader",
      "symbol_va": 91568,
      "symbol_defined": true
    },
    "target_elf_va": "0x165b0"
  },
  "00012e18": {
    "elf_va": "0x2e18",
    "file_offset": "0x2e18",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_ASUSBiosHeader",
      "symbol_va": 91332,
      "symbol_defined": true
    },
    "target_elf_va": "0x164c4"
  }
}
*/

void ClearASUSBiosHeader(void)

{
  if (*(void **)((int)DAT_00012e14 + 0xcb) != (void *)0x0) {
    free(*(void **)((int)DAT_00012e14 + 0xcb));
  }
  memset(DAT_00012e14,0,0xd7);
  if (*(void **)((int)DAT_00012e18 + 0xcb) != (void *)0x0) {
    free(*(void **)((int)DAT_00012e18 + 0xcb));
  }
  memset(DAT_00012e18,0,0xd7);
  return;
}

