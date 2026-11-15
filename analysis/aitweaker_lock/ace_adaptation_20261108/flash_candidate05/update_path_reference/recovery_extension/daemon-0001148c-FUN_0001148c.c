/* Exact ELF literal/relocation map. */
{
  "000114d0": {
    "elf_va": "0x114d0",
    "file_offset": "0x14d0",
    "raw_u32": "0x23998",
    "target_elf_va": "0x23998"
  },
  "000114d4": {
    "elf_va": "0x114d4",
    "file_offset": "0x14d4",
    "raw_u32": "0x239e0",
    "target_elf_va": "0x239e0"
  }
}

void FUN_0001148c(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  piVar1 = DAT_000114d0;
  if (*DAT_000114d0 < 1) {
    return;
  }
  iVar3 = 0;
  iVar2 = DAT_000114d4;
  do {
    iVar3 = iVar3 + 1;
    if (*(code **)(iVar2 + 0x108) != (code *)0x0) {
      (**(code **)(iVar2 + 0x108))();
    }
    iVar2 = iVar2 + 0x114;
  } while (iVar3 < *piVar1);
  return;
}

