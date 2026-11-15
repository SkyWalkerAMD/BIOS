
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
    if ((uint)*(ushort *)(DAT_00011f08 + iVar1) == (param_1 & 0xffff)) {
      pcVar3 = *(code **)(DAT_00011f08 + iVar1 + 4);
      if (pcVar3 != (code *)0x0) {
        memcpy(auStack_10020,&stack0x00000000,DAT_00011f0c);
        uVar2 = (*pcVar3)(param_1,param_2,param_3,param_4);
        return uVar2;
      }
      return 0;
    }
  } while (iVar4 != 0xc);
  return 0;
}

