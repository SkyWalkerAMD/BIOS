
longlong Observed_HistoryUpdate(ushort param_1,ushort param_2)

{
  longlong lVar1;
  longlong lVar2;
  undefined8 *puVar3;
  uint uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  short local_res8 [4];
  uint local_res10 [2];
  
  local_res10[0] = 0xffffffff;
  uVar5 = (ulonglong)param_2;
  local_res8[0] = 0;
  if (param_1 == param_2) {
    return 0;
  }
  if (DAT_000afde8 == (undefined8 *)0x0) {
    lVar2 = *(longlong *)(*(longlong *)(DAT_000afdd0 + 0x30) + uVar5 * 8);
    if (*(short *)(lVar2 + 0x32) != 0) {
      return 0;
    }
    DAT_000afde0 = *(int *)(DAT_000afdd0 + 0x2c) + 0x14;
    DAT_000afde8 = FUN_00059b50(lVar2,(ulonglong)DAT_000afde0 << 5);
    if (DAT_000afde8 == (undefined8 *)0x0) {
      return -0x7ffffffffffffff7;
    }
    DAT_000afddc = (uint)param_2;
  }
  puVar3 = DAT_000afde8;
  lVar2 = Observed_HistoryLookup(param_2,local_res8,local_res10);
  if (lVar2 == -0x7fffffffffffffeb) {
    return -0x7fffffffffffffeb;
  }
  if (lVar2 == 0) {
    if (DAT_000afde0 <= local_res10[0]) {
LAB_0001ba59:
      if (DAT_000afde0 <= DAT_000afe00) {
        uVar4 = DAT_000afde0 + 0x14;
        uVar6 = (ulonglong)DAT_000afde0;
        DAT_000afde0 = uVar4;
        puVar3 = FUN_0000fc40((longlong)puVar3,uVar6,(ulonglong)uVar4);
        DAT_000afde8 = puVar3;
        if (puVar3 == (undefined8 *)0x0) {
          DAT_000afe00 = 0;
          return -0x7ffffffffffffff7;
        }
      }
      lVar1 = *(longlong *)(*(longlong *)(DAT_000afdd0 + 0x30) + uVar5 * 8);
      if (lVar1 != 0) {
        uVar6 = (ulonglong)DAT_000afe00;
        puVar3[uVar6 * 4] = *(undefined8 *)(lVar1 + 0x20);
        *(uint *)(DAT_000afde8 + uVar6 * 4 + 1) =
             (uint)*(ushort *)(*(longlong *)(*(longlong *)(DAT_000afdd0 + 0x30) + uVar5 * 8) + 0x2a)
        ;
        if (DAT_000afe00 != 0) {
          DAT_000afde8[uVar6 * 4 + 2] = DAT_000afde8[(ulonglong)(DAT_000afe00 - 1) * 4];
          *(undefined4 *)(DAT_000afde8 + uVar6 * 4 + 3) =
               *(undefined4 *)(DAT_000afde8 + (ulonglong)(DAT_000afe00 - 1) * 4 + 1);
        }
        DAT_000afe00 = DAT_000afe00 + 1;
        return lVar2;
      }
      return -0x7fffffffffffffeb;
    }
    DAT_000afe00 = local_res10[0] + 1;
    if (DAT_000afde0 <= DAT_000afe00) {
      return 0;
    }
    uVar5 = (ulonglong)(DAT_000afde0 - DAT_000afe00);
    if (uVar5 == 0) {
      return 0;
    }
    puVar3 = puVar3 + (ulonglong)DAT_000afe00 * 4;
  }
  else {
    if ((DAT_000afde0 <= local_res10[0]) || (local_res8[0] != 0)) goto LAB_0001ba59;
    DAT_000afe00 = 1;
    if (DAT_000afde0 < 2) {
      DAT_000afe00 = 1;
      return lVar2;
    }
    uVar5 = (ulonglong)(DAT_000afde0 - 1);
    if (uVar5 == 0) {
      DAT_000afe00 = 1;
      return lVar2;
    }
    puVar3 = puVar3 + 4;
  }
  FUN_00001600((undefined1 *)puVar3,uVar5 << 5,0);
  return lVar2;
}

