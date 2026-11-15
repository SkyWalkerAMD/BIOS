/* Exact ELF literal/relocation map. */
{
  "000111ac": {
    "elf_va": "0x111ac",
    "file_offset": "0x11ac",
    "raw_u32": "0x11e60",
    "target_elf_va": "0x11e60"
  },
  "000111b0": {
    "elf_va": "0x111b0",
    "file_offset": "0x11b0",
    "raw_u32": "0xa8",
    "target_elf_va": "0xa8"
  }
}

void FUN_00011190(void)

{
  if (*(int *)(DAT_000111ac + 0x111a0 + DAT_000111b0) == 0) {
    return;
  }
  (*(code *)PTR___gmon_start___000230a0)();
  return;
}

