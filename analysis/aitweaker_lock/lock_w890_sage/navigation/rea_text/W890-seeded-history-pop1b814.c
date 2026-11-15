
undefined8 Observed_HistoryLookup(ushort param_1,undefined2 *param_2,uint *param_3)

{
  longlong lVar1;
  longlong lVar2;
  longlong lVar3;
  uint uVar4;
  longlong lVar5;
  undefined8 uVar6;
  uint uVar7;
  
  lVar3 = DAT_000afdd0;
  *param_3 = 0xffffffff;
  lVar1 = *(longlong *)(lVar3 + 0x30);
  lVar5 = *(longlong *)(lVar1 + (ulonglong)param_1 * 8);
  if (lVar5 == 0) {
    uVar6 = 0x8000000000000015;
  }
  else {
    uVar7 = 0;
    uVar6 = 0x800000000000000e;
    if (DAT_000afe00 != 0) {
      do {
        if ((*(uint *)((ulonglong)uVar7 * 0x20 + 8 + DAT_000afde8) ==
             (uint)*(ushort *)(lVar5 + 0x2a)) &&
           (*(longlong *)((ulonglong)uVar7 * 0x20 + DAT_000afde8) ==
            *(longlong *)(*(longlong *)(lVar1 + (ulonglong)param_1 * 8) + 0x20))) {
          lVar5 = (ulonglong)uVar7 * 0x20;
          uVar4 = DAT_000afddc;
          if ((*(int *)(lVar5 + 0x18 + DAT_000afde8) == 0) &&
             (*(longlong *)(lVar5 + 0x10 + DAT_000afde8) == 0)) {
            *param_3 = 0;
            return 0x800000000000000e;
          }
          while( true ) {
            if (*(uint *)(lVar3 + 0x2c) <= uVar4) {
              return 0x800000000000000e;
            }
            lVar2 = *(longlong *)(lVar1 + (ulonglong)uVar4 * 8);
            if (((lVar2 != 0) &&
                (*(short *)(lVar2 + 0x2a) == *(short *)(lVar5 + 0x18 + DAT_000afde8))) &&
               (*(longlong *)(lVar2 + 0x20) == *(longlong *)(lVar5 + 0x10 + DAT_000afde8))) break;
            uVar4 = uVar4 + 1;
          }
          *param_2 = *(undefined2 *)(lVar2 + 0x30);
          *param_3 = uVar7;
          return 0;
        }
        uVar7 = uVar7 + 1;
      } while (uVar7 < DAT_000afe00);
    }
  }
  return uVar6;
}

