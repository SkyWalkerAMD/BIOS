/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00011ea4": {
    "elf_va": "0x1ea4",
    "file_offset": "0x1ea4",
    "raw_u32": "0x163e8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x163e8"
  },
  "DAT_or_PTR_00011ea8": {
    "elf_va": "0x1ea8",
    "file_offset": "0x1ea8",
    "raw_u32": "0xfffc",
    "target_elf_va": "0xfffc"
  }
}
*/

undefined4
Amibios_Command_Process(uint param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  undefined4 uVar2;
  code *pcVar3;
  int iVar4;
  undefined1 auStack_10020 [65540];
  
  iVar4 = 0;
  do {
    iVar1 = iVar4 * 8;
    iVar4 = iVar4 + 1;
    if ((uint)*(ushort *)(DAT_00011ea4 + iVar1) == (param_1 & 0xffff)) {
      pcVar3 = *(code **)(DAT_00011ea4 + iVar1 + 4);
      if (pcVar3 != (code *)0x0) {
        memcpy(auStack_10020,&stack0x00000000,DAT_00011ea8);
        uVar2 = (*pcVar3)(param_1,param_2,param_3,param_4);
        return uVar2;
      }
      return 0;
    }
  } while (iVar4 != 0xe);
  return 0;
}

