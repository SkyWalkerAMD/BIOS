/* Exact ELF literal/relocation map. */
{
  "0001123c": {
    "elf_va": "0x1123c",
    "file_offset": "0x123c",
    "raw_u32": "0x23994",
    "target_elf_va": "0x23994"
  }
}

void _FINI_0(void)

{
  char *pcVar1;
  
  pcVar1 = DAT_0001123c;
  if (*DAT_0001123c != '\0') {
    return;
  }
  FUN_000111b4();
  *pcVar1 = '\x01';
  return;
}

