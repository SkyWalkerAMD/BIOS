
undefined8 FUN_00001e74(longlong param_1,undefined8 *param_2)

{
  short sVar1;
  undefined8 uVar2;
  short *psVar3;
  longlong lVar4;
  
  if (param_2 == (undefined8 *)0x0) {
    uVar2 = 0x8000000000000002;
  }
  else {
    uVar2 = 0x800000000000000e;
    psVar3 = (short *)FUN_00002514(param_1);
    if (psVar3 != (short *)0x0) {
      do {
        sVar1 = *psVar3;
        while( true ) {
          if (sVar1 == -1) {
            return 0x800000000000000e;
          }
          psVar3 = (short *)((longlong)psVar3 + (ulonglong)(ushort)psVar3[1]);
          if (*psVar3 == 4) break;
          sVar1 = *psVar3;
        }
        lVar4 = FUN_0000249c((longlong *)(psVar3 + 4),(longlong *)&DAT_0000e0c0,0x10);
      } while (lVar4 != 0);
      uVar2 = 0;
      param_2[3] = psVar3 + 0x1a;
      *(undefined4 *)(param_2 + 2) = *(undefined4 *)(psVar3 + 0x18);
      *param_2 = *(undefined8 *)(psVar3 + 0xc);
      param_2[1] = *(undefined8 *)(psVar3 + 0x10);
    }
  }
  return uVar2;
}

