
void FUN_00008920(void)

{
  short sVar1;
  byte *pbVar2;
  byte *pbVar3;
  longlong lVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  byte *local_res10;
  byte *local_res18;
  byte *local_res20;
  
  uVar7 = 0;
  local_res10 = (byte *)0x0;
  uVar6 = uVar7;
  uVar8 = uVar7;
  if (DAT_00193888 != 0) {
    do {
      pbVar2 = (byte *)FUN_000484c8(DAT_00193900,4,*(short **)(uVar6 + 8 + DAT_00193890));
      pbVar3 = pbVar2;
      uVar5 = uVar7;
      if (pbVar2 == (byte *)0x0) {
        return;
      }
      for (; *(short *)pbVar3 != 0; pbVar3 = pbVar3 + 2) {
        uVar5 = uVar5 + 1;
      }
      local_res20 = pbVar2;
      pbVar3 = (byte *)FUN_000014c8(uVar5 * 2 + 0x14);
      local_res18 = pbVar3;
      if (pbVar3 != (byte *)0x0) {
        FUN_000b23b4((short *)pbVar3,(short *)pbVar2);
        lVar4 = FUN_00008790(pbVar3);
        if (lVar4 < 0) {
          sVar1 = *(short *)pbVar2;
          pbVar3 = pbVar2;
          uVar5 = uVar7;
          while (sVar1 != 0) {
            pbVar3 = pbVar3 + 2;
            uVar5 = uVar5 + 1;
            sVar1 = *(short *)pbVar3;
          }
          uVar5 = uVar5 * 2 + 0x14;
          pbVar3 = (byte *)FUN_000014c8(uVar5);
          local_res10 = pbVar3;
          if (pbVar3 != (byte *)0x0) {
            FUN_00009d1c((char *)pbVar3,uVar5,pbVar2,2);
            goto LAB_00008a68;
          }
        }
        else {
LAB_00008a68:
          FUN_000497e8(DAT_00193900,4,*(short **)(uVar6 + 8 + DAT_00193890),(longlong)pbVar3);
        }
        FUN_000013d0((longlong *)&local_res18);
      }
      FUN_000013d0((longlong *)&local_res10);
      FUN_000013d0((longlong *)&local_res20);
      uVar8 = uVar8 + 1;
      uVar6 = uVar6 + 0x20;
    } while (uVar8 < DAT_00193888);
  }
  return;
}

