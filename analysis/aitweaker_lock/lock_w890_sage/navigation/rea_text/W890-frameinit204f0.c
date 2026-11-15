
undefined8 Observed_FrameInitialize(longlong param_1,longlong param_2)

{
  undefined8 *puVar1;
  longlong lVar2;
  ulonglong uVar3;
  
  if (param_2 != 0) {
    lVar2 = param_1 + 0x20;
    (**(code **)(DAT_000afbc8 + 0x160))(lVar2,param_2,0x18);
    if (*(int *)(param_1 + 0x38) != 0) {
      puVar1 = FUN_00059b50(lVar2,(ulonglong)*(ushort *)(param_2 + 8) * 2 + 2);
      *(undefined8 **)(param_1 + 0x50) = puVar1;
      if ((puVar1 != (undefined8 *)0x0) && (uVar3 = (ulonglong)*(ushort *)(param_2 + 8), uVar3 != 0)
         ) {
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          *(undefined2 *)puVar1 = 0x20;
          puVar1 = (undefined8 *)((longlong)puVar1 + 2);
        }
      }
    }
  }
  *(undefined4 *)(param_1 + 0x5c) = 0;
  return 0;
}

