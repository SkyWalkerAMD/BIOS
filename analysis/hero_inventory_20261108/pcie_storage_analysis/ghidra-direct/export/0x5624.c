
ushort * FUN_00005624(undefined8 *param_1,longlong param_2,longlong param_3,longlong param_4)

{
  longlong lVar1;
  ushort *puVar2;
  undefined1 *puVar3;
  longlong *plVar4;
  int iVar5;
  ulonglong uVar6;
  undefined8 **local_28;
  undefined8 **local_20;
  
  local_28 = &local_28;
  local_20 = &local_28;
  uVar6 = 0;
  puVar2 = (ushort *)FUN_00009b8c(param_3,(longlong)&local_28);
  if (-1 < (longlong)puVar2) {
    puVar3 = FUN_00016b80();
    if (puVar3 == (undefined1 *)0x0) {
      puVar2 = (ushort *)0x8000000000000009;
    }
    else {
      *(undefined4 *)(puVar3 + 0x18) = 5;
      if (*(longlong *)(param_3 + 0x330) != 0) {
        do {
          lVar1 = *(longlong *)(*(longlong *)(param_3 + 0x338) + uVar6 * 8);
          if (*(char *)(lVar1 + 0x18) == '\t') {
            puVar2 = FUN_000051b4(param_1,param_2,lVar1 + 0x28,*(longlong *)(lVar1 + 0x10),param_3,
                                  (longlong)puVar3,(longlong *)&local_28);
            if ((longlong)puVar2 < 0) goto LAB_0000572d;
          }
          uVar6 = uVar6 + 1;
        } while (uVar6 < *(ulonglong *)(param_3 + 0x330));
      }
      plVar4 = *(longlong **)(puVar3 + 0x10);
      iVar5 = 0;
      if (plVar4 != (longlong *)0x0) {
        do {
          plVar4 = (longlong *)*plVar4;
          iVar5 = iVar5 + 1;
        } while (plVar4 != (longlong *)0x0);
        if (0 < iVar5) {
          FUN_00018744(param_4,s_Redundancy_0001ac80,(longlong)puVar3);
        }
      }
      puVar2 = (ushort *)FUN_000054d0(param_1,param_2,param_3);
    }
  }
LAB_0000572d:
  FUN_00000de0((longlong *)&local_28);
  return puVar2;
}

