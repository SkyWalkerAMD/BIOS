/* Exact ELF literal/relocation map. */
{
  "0001120c": {
    "elf_va": "0x1120c",
    "file_offset": "0x120c",
    "raw_u32": "0x230b4",
    "target_elf_va": "0x230b4"
  },
  "00011210": {
    "elf_va": "0x11210",
    "file_offset": "0x1210",
    "raw_u32": "0x230b4",
    "target_elf_va": "0x230b4"
  },
  "00011214": {
    "elf_va": "0x11214",
    "file_offset": "0x1214",
    "raw_u32": "0x0",
    "target_elf_va": "0x0"
  }
}

void FUN_000111e0(void)

{
  if ((DAT_00011210 - DAT_0001120c >> 2) / 2 == 0) {
    return;
  }
  if (DAT_00011214 == (code *)0x0) {
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x00011208. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*DAT_00011214)();
  return;
}

