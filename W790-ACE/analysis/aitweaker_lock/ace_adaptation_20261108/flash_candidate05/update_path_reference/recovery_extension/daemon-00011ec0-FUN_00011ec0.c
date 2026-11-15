/* Exact ELF literal/relocation map. */
{
  "00011ef8": {
    "elf_va": "0x11ef8",
    "file_offset": "0x1ef8",
    "raw_u32": "0x112d8",
    "target_elf_va": "0x112d8"
  },
  "00011efc": {
    "elf_va": "0x11efc",
    "file_offset": "0x1efc",
    "raw_u32": "0x113bc",
    "target_elf_va": "0x113bc"
  },
  "00011f00": {
    "elf_va": "0x11f00",
    "file_offset": "0x1f00",
    "raw_u32": "0x11348",
    "target_elf_va": "0x11348"
  },
  "00011f04": {
    "elf_va": "0x11f04",
    "file_offset": "0x1f04",
    "raw_u32": "0x11244",
    "target_elf_va": "0x11244"
  }
}

void FUN_00011ec0(void)

{
  FUN_0001142c(0xf,DAT_00011ef8);
  FUN_0001142c(7,DAT_00011efc);
  FUN_0001142c(0xb,DAT_00011f00);
  FUN_0001142c(1,DAT_00011f04);
  return;
}

