/* Exact ELF literal/relocation map. */
{
  "00011534": {
    "elf_va": "0x11534",
    "file_offset": "0x1534",
    "raw_u32": "0x1ff",
    "target_elf_va": "0x1ff"
  },
  "00011538": {
    "elf_va": "0x11538",
    "file_offset": "0x1538",
    "raw_u32": "0x11f94",
    "target_elf_va": "0x11f94",
    "target_string": "compmanager.c"
  },
  "0001153c": {
    "elf_va": "0x1153c",
    "file_offset": "0x153c",
    "raw_u32": "0x12018",
    "target_elf_va": "0x12018",
    "target_string": "[%s:%d]Error creating named pipe %s\n"
  }
}

undefined4 FUN_000114d8(char *param_1)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  
  iVar1 = mkfifo(param_1,DAT_00011534);
  if ((iVar1 == -1) && (piVar2 = __errno_location(), *piVar2 != 0x11)) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001153c,DAT_00011538,0x43,param_1);
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}

