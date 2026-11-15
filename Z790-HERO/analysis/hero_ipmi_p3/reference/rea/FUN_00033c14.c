
undefined8 * FUN_00033c14(longlong param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  longlong lVar4;
  ulonglong uVar5;
  uint *puVar6;
  undefined8 *puVar7;
  undefined8 uVar8;
  longlong lVar9;
  longlong *plVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  undefined8 local_res10;
  uint *local_res18 [2];
  
  local_res10 = 0;
  uVar1 = *DAT_001937f0;
  if (DAT_0018f190 == 0) {
    return (undefined8 *)0x0;
  }
  puVar6 = param_2;
  if ((param_2 == (uint *)0x0) &&
     (local_res18[0] = param_2, puVar6 = (uint *)FUN_00031e04(param_1,0,&local_res10),
     puVar6 == (uint *)0x0)) {
    return (undefined8 *)0x0;
  }
  local_res18[0] = puVar6;
  puVar7 = (undefined8 *)FUN_00031ac4(puVar6);
  if (puVar7 == (undefined8 *)0x0) {
    local_res18[0] = (uint *)FUN_00031e04(param_1,param_2,&local_res10);
    if (local_res18[0] == (uint *)0x0) {
      return (undefined8 *)0x0;
    }
    uVar8 = FUN_0004bd54((longlong)(local_res18[0] + 1));
    if ((char)uVar8 != '\0') {
      FUN_000013d0((longlong *)local_res18);
      uVar5 = DAT_0018f190;
      lVar4 = DAT_00183788;
      if (puVar6 != (uint *)0x0) {
        uVar2 = *puVar6;
        uVar12 = 0;
        puVar7 = DAT_0018f1a0;
        if (DAT_0018f190 != 0) {
          do {
            if ((((*(longlong *)(lVar4 + uVar12 * 8) == param_1) &&
                 (puVar3 = (uint *)*puVar7, puVar3 != (uint *)0x0)) &&
                (uVar11 = (ulonglong)(*puVar3 & 0xffffff) - 4,
                uVar11 == (ulonglong)(uVar2 & 0xffffff) - 4)) &&
               (lVar9 = FUN_000b1b20((longlong *)puVar3,(longlong *)puVar6,uVar11), lVar9 == 0)) {
              return (undefined8 *)0x800000000000000e;
            }
            uVar12 = uVar12 + 1;
            puVar7 = puVar7 + 6;
          } while (uVar12 < uVar5);
        }
      }
      DAT_0018f190 = uVar5 + 1;
      DAT_00183788 = FUN_00001450(lVar4,uVar5 * 8,DAT_0018f190 * 8);
      if (DAT_00183788 != 0) {
        *(longlong *)(uVar5 * 8 + DAT_00183788) = param_1;
        DAT_0018f1a0 = (undefined8 *)
                       FUN_00001450((longlong)DAT_0018f1a0,uVar5 * 0x30,DAT_0018f190 * 0x30);
        if (DAT_0018f1a0 != (undefined8 *)0x0) {
          plVar10 = DAT_0018f1a0 + uVar5 * 6 + -6;
          (**(code **)(DAT_00180188 + 0x160))(DAT_0018f1a0 + DAT_0018f190 * 6 + -6,plVar10,0x30);
          lVar4 = DAT_0018f190;
          DAT_0018f1a0[DAT_0018f190 * 6 + -6] = puVar6;
          DAT_0018f1a0[lVar4 * 6 + -5] = param_1;
          DAT_0018f1a0[lVar4 * 6 + -3] = local_res10;
          if (DAT_0018f1a0[lVar4 * 6 + -6] != 0) {
            FUN_00031f6c(DAT_0018f1a0 + lVar4 * 6 + -6);
          }
          puVar7 = FUN_00034480(DAT_0018f1a0 + lVar4 * 6 + -6,plVar10);
          FUN_00043978(param_1,uVar1);
          FUN_00036660(param_1);
          return puVar7;
        }
      }
      return (undefined8 *)0x8000000000000009;
    }
  }
  FUN_000013d0((longlong *)local_res18);
  return puVar7;
}

