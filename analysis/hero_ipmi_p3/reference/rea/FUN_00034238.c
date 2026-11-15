
undefined8 * FUN_00034238(longlong param_1,uint *param_2)

{
  longlong *plVar1;
  uint uVar2;
  uint *puVar3;
  longlong lVar4;
  uint *puVar5;
  undefined8 *puVar6;
  undefined8 uVar7;
  longlong lVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  undefined8 local_res10;
  uint *local_res18;
  
  local_res10 = 0;
  uVar2 = *DAT_001937f0;
  if (DAT_0018f190 == 0) {
    return (undefined8 *)0x800000000000000e;
  }
  puVar5 = param_2;
  if ((param_2 == (uint *)0x0) &&
     (local_res18 = param_2, puVar5 = (uint *)FUN_00031e04(param_1,0,&local_res10),
     puVar5 == (uint *)0x0)) {
    return (undefined8 *)0x800000000000000e;
  }
  local_res18 = puVar5;
  puVar6 = (undefined8 *)FUN_00031ac4(puVar5);
  if (puVar6 == (undefined8 *)0x0) {
    local_res18 = (uint *)FUN_00031e04(param_1,param_2,&local_res10);
    if (local_res18 == (uint *)0x0) {
      return (undefined8 *)0x0;
    }
    uVar7 = FUN_0004bd54((longlong)(local_res18 + 1));
    if ((char)uVar7 != '\0') {
      FUN_000013d0((longlong *)&local_res18);
      lVar4 = DAT_0018f1a0;
      uVar9 = 0;
      if (DAT_0018f190 != 0) {
        do {
          if (*(longlong *)(DAT_00183788 + uVar9 * 8) == param_1) break;
          uVar9 = uVar9 + 1;
        } while (uVar9 < DAT_0018f190);
      }
      if (uVar9 == DAT_0018f190) {
        puVar6 = FUN_00033c14(param_1,puVar5);
        return puVar6;
      }
      if (puVar5 != (uint *)0x0) {
        puVar3 = *(uint **)(DAT_0018f1a0 + uVar9 * 0x30);
        if (puVar3 != (uint *)0x0) {
          param_2 = (uint *)0xffffff;
          uVar10 = ((ulonglong)*puVar3 & 0xffffff) - 4;
          if ((((ulonglong)*puVar5 & 0xffffff) - 4 == uVar10) &&
             (param_2 = puVar5, lVar8 = FUN_000b1b20((longlong *)puVar3,(longlong *)puVar5,uVar10),
             lVar8 == 0)) {
            return (undefined8 *)0x800000000000000e;
          }
        }
        *(uint **)(lVar4 + uVar9 * 0x30) = puVar5;
        *(undefined8 *)(DAT_0018f1a0 + 0x18 + uVar9 * 0x30) = local_res10;
      }
      plVar1 = (longlong *)(DAT_0018f1a0 + uVar9 * 0x30);
      if (*plVar1 != 0) {
        FUN_00031f6c(plVar1);
      }
      puVar6 = FUN_00034480((undefined8 *)(DAT_0018f1a0 + uVar9 * 0x30),(longlong *)param_2);
      FUN_00043978(param_1,uVar2);
      return puVar6;
    }
  }
  FUN_000013d0((longlong *)&local_res18);
  return puVar6;
}

