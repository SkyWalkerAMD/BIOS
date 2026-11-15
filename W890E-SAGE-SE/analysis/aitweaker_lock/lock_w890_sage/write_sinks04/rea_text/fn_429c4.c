
byte * FUN_000429c4(longlong param_1,uint *param_2)

{
  uint uVar1;
  uint *puVar2;
  uint *puVar3;
  undefined8 *puVar4;
  undefined8 uVar5;
  ulonglong uVar6;
  byte *pbVar7;
  longlong lVar8;
  longlong lVar9;
  ulonglong local_res10;
  
  local_res10 = 0;
  pbVar7 = (byte *)0x800000000000000e;
  uVar1 = *DAT_000baaf8;
  if ((DAT_000aff68 != 0) &&
     ((puVar3 = param_2, param_2 != (uint *)0x0 ||
      (puVar3 = (uint *)FUN_00040434(param_1,0,&local_res10), puVar3 != (uint *)0x0)))) {
    pbVar7 = (byte *)FUN_0003e0ec(puVar3);
    if (pbVar7 == (byte *)0x0) {
      puVar4 = FUN_00040434(param_1,param_2,&local_res10);
      if (puVar4 != (undefined8 *)0x0) {
        uVar5 = FUN_0004f8ac((longlong)puVar4 + 4);
        if ((char)uVar5 == '\0') {
          (**(code **)(DAT_000afbc8 + 0x48))();
        }
        else {
          (**(code **)(DAT_000afbc8 + 0x48))(puVar4);
          uVar6 = 0;
          if (DAT_000aff68 != 0) {
            do {
              if (*(longlong *)(DAT_000b8d28 + uVar6 * 8) == param_1) break;
              uVar6 = uVar6 + 1;
            } while (uVar6 < DAT_000aff68);
          }
          if (uVar6 == DAT_000aff68) {
            pbVar7 = FUN_0004244c(param_1,puVar3);
          }
          else {
            lVar8 = uVar6 * 0x30;
            if (puVar3 != (uint *)0x0) {
              puVar2 = *(uint **)(lVar8 + DAT_000aff80);
              if (((puVar2 != (uint *)0x0) &&
                  (lVar9 = ((ulonglong)*puVar2 & 0xffffff) - 4,
                  ((ulonglong)*puVar3 & 0xffffff) - 4 == lVar9)) &&
                 ((lVar9 == 0 ||
                  ((puVar2 == puVar3 ||
                   (lVar9 = FUN_000015e0((char *)puVar2,(char *)puVar3,lVar9), lVar9 == 0)))))) {
                return (byte *)0x800000000000000e;
              }
              *(uint **)(lVar8 + DAT_000aff80) = puVar3;
              *(ulonglong *)(lVar8 + 0x18 + DAT_000aff80) = local_res10;
            }
            FUN_0004060c((longlong *)(DAT_000aff80 + lVar8));
            pbVar7 = FUN_00042c14((undefined8 *)(DAT_000aff80 + lVar8));
            FUN_0001b1b0(param_1,uVar1);
          }
        }
      }
    }
    else if (puVar3 != (uint *)0x0) {
      (**(code **)(DAT_000afbc8 + 0x48))(puVar3);
    }
  }
  return pbVar7;
}

