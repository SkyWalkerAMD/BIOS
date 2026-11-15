/* Exact ELF literal/relocation map. */
{
  "00011184": {
    "elf_va": "0x11184",
    "file_offset": "0x1184",
    "raw_u32": "0x11f68",
    "target_elf_va": "0x11f68"
  },
  "00011188": {
    "elf_va": "0x11188",
    "file_offset": "0x1188",
    "raw_u32": "0x10f2c",
    "target_elf_va": "0x10f2c"
  },
  "0001118c": {
    "elf_va": "0x1118c",
    "file_offset": "0x118c",
    "raw_u32": "0x11f08",
    "target_elf_va": "0x11f08"
  }
}

void processEntry entry(undefined4 param_1,undefined4 param_2)

{
  __libc_start_main(DAT_00011188,param_2,&stack0x00000004,DAT_0001118c,DAT_00011184,param_1);
                    /* WARNING: Subroutine does not return */
  abort();
}

