/* Exact ELF literal/relocation map. */
{
  "00011f60": {
    "elf_va": "0x11f60",
    "file_offset": "0x1f60",
    "raw_u32": "0x10f90",
    "target_elf_va": "0x10f90"
  },
  "00011f64": {
    "elf_va": "0x11f64",
    "file_offset": "0x1f64",
    "raw_u32": "0x10f88",
    "target_elf_va": "0x10f88"
  }
}

void FUN_00011f08(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  
  iVar3 = DAT_00011f60 + 0x11f1c;
  puVar2 = (undefined4 *)(DAT_00011f64 + 0x11f20);
  _DT_INIT();
  iVar3 = iVar3 - (int)puVar2 >> 2;
  if (iVar3 == 0) {
    return;
  }
  iVar1 = 0;
  do {
    iVar1 = iVar1 + 1;
    (*(code *)*puVar2)(param_1,param_2,param_3);
    puVar2 = puVar2 + 1;
  } while (iVar3 != iVar1);
  return;
}

