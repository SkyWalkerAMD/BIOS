/* Exact ELF literal/relocation map. */
{
  "000111d4": {
    "elf_va": "0x111d4",
    "file_offset": "0x11d4",
    "raw_u32": "0x230b4",
    "target_elf_va": "0x230b4"
  },
  "000111d8": {
    "elf_va": "0x111d8",
    "file_offset": "0x11d8",
    "raw_u32": "0x230b4",
    "target_elf_va": "0x230b4"
  },
  "000111dc": {
    "elf_va": "0x111dc",
    "file_offset": "0x11dc",
    "raw_u32": "0x0",
    "target_elf_va": "0x0"
  }
}

void FUN_000111b4(void)

{
  if (DAT_000111d8 == DAT_000111d4) {
    return;
  }
  if (DAT_000111dc == (code *)0x0) {
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x000111d0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*DAT_000111dc)();
  return;
}

