
undefined8 FUN_0001012c(ushort param_1,undefined2 *param_2,int *param_3)

{
  longlong lVar1;
  longlong lVar2;
  longlong lVar3;
  uint uVar4;
  ulonglong uVar5;
  
  uVar5 = 0;
  if (DAT_000835b8 != 0) {
    lVar1 = *(longlong *)(DAT_00083588 + 0x30);
    lVar3 = *(longlong *)(lVar1 + (ulonglong)param_1 * 8);
    do {
      if ((*(uint *)(uVar5 * 0x20 + 8 + DAT_000835a0) == (uint)*(ushort *)(lVar3 + 0x2a)) &&
         (*(longlong *)(uVar5 * 0x20 + DAT_000835a0) == *(longlong *)(lVar3 + 0x20))) {
        lVar3 = uVar5 * 0x20;
        uVar4 = DAT_00083594;
        if ((*(int *)(lVar3 + 0x18 + DAT_000835a0) == 0) &&
           (*(longlong *)(lVar3 + 0x10 + DAT_000835a0) == 0)) {
          *param_3 = 0;
          return 0x800000000000000e;
        }
        while( true ) {
          if (*(uint *)(DAT_00083588 + 0x2c) <= uVar4) {
            return 0x800000000000000e;
          }
          lVar2 = *(longlong *)(lVar1 + (ulonglong)uVar4 * 8);
          if (((lVar2 != 0) && (*(short *)(lVar2 + 0x2a) == *(short *)(lVar3 + 0x18 + DAT_000835a0))
              ) && (*(longlong *)(lVar2 + 0x20) == *(longlong *)(lVar3 + 0x10 + DAT_000835a0)))
          break;
          uVar4 = uVar4 + 1;
        }
        *param_3 = (int)uVar5;
        *param_2 = *(undefined2 *)(*(longlong *)(lVar1 + (ulonglong)uVar4 * 8) + 0x30);
        return 0;
      }
      uVar4 = (int)uVar5 + 1;
      uVar5 = (ulonglong)uVar4;
    } while (uVar4 < DAT_000835b8);
  }
  return 0x800000000000000e;
}

