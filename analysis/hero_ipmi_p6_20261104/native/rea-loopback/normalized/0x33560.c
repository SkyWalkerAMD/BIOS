undefined8 FUN_00033560(undefined8 param_1,ulonglong param_2)
{
  undefined8 *puVar1;
  ulonglong uVar2;
  ushort uVar3;
  undefined8 uVar4;
  ushort uVar5;
  longlong local_res8;
  undefined8 *local_res10;
  uVar4 = 0;
  puVar1 = DAT_00193728;
  uVar3 = (ushort)DAT_00193730;
  if (DAT_00193728 == (undefined8 *)0x0) {
    puVar1 = (undefined8 *)FUN_0003373c((undefined2 *)&local_res8);
    uVar3 = (ushort)local_res8;
  }
  local_res10 = puVar1;
  if (puVar1 != (undefined8 *)0x0) {
    uVar2 = (ulonglong)uVar3;
    DAT_00183788 = FUN_0000151c(uVar2 * 8 + 8);
    if (DAT_00183788 != 0) {
      uVar5 = 0;
      if (uVar3 != 0) {
        do {
          local_res8 = FUN_00031e04(*puVar1,param_2,(undefined8 *)0x0);
          if (local_res8 != 0) {
            param_2 = (ulonglong)uVar5;
            uVar5 = uVar5 + 1;
            *(undefined8 *)(DAT_00183788 + param_2 * 8) = *puVar1;
            FUN_000013d0(&local_res8);
          }
          puVar1 = puVar1 + 1;
          uVar2 = uVar2 - 1;
        } while (uVar2 != 0);
      }
      DAT_0018f190 = (ulonglong)uVar5 + 1;
      goto LAB_00033636;
    }
  }
  uVar4 = 0x8000000000000009;
LAB_00033636:
  if (DAT_00193728 == (undefined8 *)0x0) {
    FUN_000013d0((longlong *)&local_res10);
  }
  return uVar4;
}
