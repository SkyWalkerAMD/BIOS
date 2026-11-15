/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00012edc": {
    "elf_va": "0x2edc",
    "file_offset": "0x2edc",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_mtdASUSBiosHeader",
      "symbol_va": 91504,
      "symbol_defined": true
    },
    "target_elf_va": "0x16570"
  },
  "DAT_or_PTR_00012ee0": {
    "elf_va": "0x2ee0",
    "file_offset": "0x2ee0",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_ASUSBiosHeader",
      "symbol_va": 91268,
      "symbol_defined": true
    },
    "target_elf_va": "0x16484"
  }
}
*/

void ClearASUSBiosHeader(void)

{
  if (*(void **)((int)DAT_00012edc + 0xcb) != (void *)0x0) {
    free(*(void **)((int)DAT_00012edc + 0xcb));
  }
  memset(DAT_00012edc,0,0xd7);
  if (*(void **)((int)DAT_00012ee0 + 0xcb) != (void *)0x0) {
    free(*(void **)((int)DAT_00012ee0 + 0xcb));
  }
  memset(DAT_00012ee0,0,0xd7);
  return;
}

