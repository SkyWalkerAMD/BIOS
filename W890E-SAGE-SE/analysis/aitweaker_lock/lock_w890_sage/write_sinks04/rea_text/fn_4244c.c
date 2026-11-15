
byte * FUN_0004244c(longlong param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  byte *pbVar5;
  undefined8 *puVar6;
  undefined8 uVar7;
  ulonglong uVar8;
  longlong lVar9;
  ulonglong uVar10;
  longlong lVar11;
  ulonglong local_res10;
  
  pbVar5 = (byte *)0x0;
  local_res10 = 0;
  uVar1 = *DAT_000baaf8;
  if ((DAT_000aff68 != 0) &&
     ((puVar4 = param_2, param_2 != (uint *)0x0 ||
      (puVar4 = (uint *)FUN_00040434(param_1,0,&local_res10), puVar4 != (uint *)0x0)))) {
    pbVar5 = (byte *)FUN_0003e0ec(puVar4);
    if (pbVar5 == (byte *)0x0) {
      puVar6 = FUN_00040434(param_1,param_2,&local_res10);
      if (puVar6 != (undefined8 *)0x0) {
        uVar7 = FUN_0004f8ac((longlong)puVar6 + 4);
        if ((char)uVar7 == '\0') {
          (**(code **)(DAT_000afbc8 + 0x48))();
        }
        else {
          (**(code **)(DAT_000afbc8 + 0x48))(puVar6);
          uVar8 = DAT_000aff68;
          if (puVar4 != (uint *)0x0) {
            uVar2 = *puVar4;
            uVar10 = 0;
            if (DAT_000aff68 != 0) {
              lVar11 = 0;
              do {
                if ((((DAT_000b8d28[uVar10] == param_1) &&
                     (puVar3 = *(uint **)(lVar11 + (longlong)DAT_000aff80), puVar3 != (uint *)0x0))
                    && (lVar9 = (ulonglong)(*puVar3 & 0xffffff) - 4,
                       lVar9 == (ulonglong)(uVar2 & 0xffffff) - 4)) &&
                   (((lVar9 == 0 || (puVar3 == puVar4)) ||
                    (lVar9 = FUN_000015e0((char *)puVar3,(char *)puVar4,lVar9), uVar8 = DAT_000aff68
                    , lVar9 == 0)))) {
                  return (byte *)0x800000000000000e;
                }
                uVar10 = uVar10 + 1;
                lVar11 = lVar11 + 0x30;
              } while (uVar10 < uVar8);
            }
          }
          DAT_000aff68 = uVar8 + 1;
          DAT_000b8d28 = FUN_0000fc40((longlong)DAT_000b8d28,uVar8 * 8,DAT_000aff68 * 8);
          if (DAT_000b8d28 != (undefined8 *)0x0) {
            DAT_000b8d28[uVar8] = param_1;
            DAT_000aff80 = FUN_0000fc40((longlong)DAT_000aff80,uVar8 * 0x30,DAT_000aff68 * 0x30);
            if (DAT_000aff80 != (undefined8 *)0x0) {
              (**(code **)(DAT_000afbc8 + 0x160))
                        (DAT_000aff80 + DAT_000aff68 * 6 + -6,DAT_000aff80 + uVar8 * 6 + -6,0x30);
              uVar8 = DAT_000aff68;
              DAT_000aff80[DAT_000aff68 * 6 + -6] = puVar4;
              DAT_000aff80[uVar8 * 6 + -5] = param_1;
              DAT_000aff80[uVar8 * 6 + -3] = local_res10;
              FUN_0004060c(DAT_000aff80 + uVar8 * 6 + -6);
              pbVar5 = FUN_00042c14(DAT_000aff80 + uVar8 * 6 + -6);
              FUN_0001b1b0(param_1,uVar1);
              FUN_000455b8(param_1);
              return pbVar5;
            }
          }
          pbVar5 = (byte *)0x8000000000000009;
        }
      }
    }
    else if (puVar4 != (uint *)0x0) {
      (**(code **)(DAT_000afbc8 + 0x48))(puVar4);
    }
  }
  return pbVar5;
}

