uint FUN_0002d160(int param_1,longlong param_2,byte *param_3)
{
  short *psVar1;
  int *piVar2;
  short sVar3;
  uint uVar4;
  short *psVar5;
  short *psVar6;
  short *psVar7;
  longlong lVar8;
  short *local_res20;
  undefined4 local_98 [4];
  short local_88 [52];
  short local_20;
  psVar7 = (short *)0x0;
  piVar2 = DAT_001936d0;
  if (param_1 == 0) {
    uVar4 = FUN_00031bac(param_2,param_3);
  }
  else {
    for (; piVar2 != (int *)0x0; piVar2 = *(int **)(piVar2 + 4)) {
      if (((*piVar2 == param_1) && (*(longlong *)(piVar2 + 2) == param_2)) &&
         (lVar8 = (ulonglong)*(uint *)(DAT_00193658 + 4 + (ulonglong)*(ushort *)(piVar2 + 1) * 4) +
                  DAT_00193670, lVar8 != 0)) {
        if ((*(uint *)(lVar8 + 0x68) & 0x2000) == 0) goto LAB_0002d2e0;
        psVar5 = psVar7;
        if (*(short *)(param_3 + 10) != -1) {
          psVar5 = (short *)FUN_000484c8(*(longlong *)(lVar8 + 0x70),*(short *)(param_3 + 10),
                                         (short *)0x0);
        }
        local_res20 = psVar5;
        sVar3 = FUN_00026d98((char *)param_3);
        if (psVar5 == (short *)0x0) goto LAB_0002d2e0;
        psVar1 = (short *)(lVar8 + 0x10);
        psVar6 = psVar1;
        if (*psVar1 == 0) goto LAB_0002d2bf;
        do {
          psVar6 = psVar6 + 1;
          psVar7 = (short *)((longlong)psVar7 + 1);
        } while (*psVar6 != 0);
        if (psVar7 == (short *)0x0) {
LAB_0002d2bf:
          *(short *)(lVar8 + 0x78) = sVar3;
          FUN_000b07bc(psVar1,0x28,psVar5);
        }
        else {
          FUN_0010749e(local_98,0x80,0);
          (**(code **)(DAT_00180188 + 0x160))(local_98,lVar8,0x80);
          local_20 = sVar3;
          FUN_000b07bc(local_88,0x28,psVar5);
          lVar8 = FUN_0003048c(local_98);
          if (-1 < lVar8) {
            FUN_000013d0((longlong *)&local_res20);
            return DAT_0018f14c;
          }
        }
        FUN_000013d0((longlong *)&local_res20);
LAB_0002d2e0:
        return (uint)*(ushort *)(piVar2 + 1);
      }
    }
    uVar4 = 0;
  }
  return uVar4;
}
