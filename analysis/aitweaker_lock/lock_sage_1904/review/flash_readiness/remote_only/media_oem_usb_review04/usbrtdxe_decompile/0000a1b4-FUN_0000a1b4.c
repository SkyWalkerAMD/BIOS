
/* WARNING: Enum "SectionFlags": Some values do not have unique names */

undefined8 FUN_0000a1b4(byte *param_1,ulonglong param_2,undefined2 *param_3)

{
  longlong lVar1;
  char cVar2;
  undefined2 uVar3;
  undefined7 extraout_var;
  ulonglong uVar4;
  undefined7 extraout_var_00;
  undefined8 uVar5;
  uint *puVar6;
  byte bVar7;
  byte bVar8;
  undefined8 *puVar9;
  undefined8 local_18;
  uint local_10;
  
  FUN_00000300(&local_18,0x10);
  uVar5 = *(undefined8 *)(DAT_0001ab98 + 0x6a);
  cVar2 = FUN_00009f6c(param_1,0,uVar5);
  uVar4 = CONCAT71(extraout_var,cVar2);
  if (cVar2 == -1) {
LAB_0000a1fb:
    return CONCAT71((int7)(uVar4 >> 8),0xff);
  }
  param_1[0x5c] = 0;
  lVar1 = *(longlong *)(DAT_0001ab98 + 0x6a);
  if (*(short *)(lVar1 + 0x1fe) != -0x55ab) {
    uVar4 = FUN_0000a414((longlong)param_1,param_2);
    goto LAB_0000a1fb;
  }
  bVar8 = 0;
  if ((((*(int *)(lVar1 + 0x1ca) == 0) && (*(int *)(lVar1 + 0x1da) == 0)) &&
      (*(int *)(lVar1 + 0x1ea) == 0)) && (*(int *)(lVar1 + 0x1fa) == 0)) {
LAB_0000a372:
    uVar3 = 0x403;
    if (param_1[0x58] == 4) {
      uVar3 = 0x103;
    }
    *param_3 = uVar3;
    uVar5 = FUN_0000a06c((longlong)param_1,param_2,lVar1);
    if ((char)uVar5 != '\0') {
      FUN_0000a414((longlong)param_1,param_2);
      puVar6 = DAT_0001b2c0;
      if ((*(ulonglong *)((longlong)DAT_0001b2c0 + 0x71b) <= param_2 >> 0xb) &&
         ((*DAT_0001b2c0 & 0x1000) == 0)) {
        if (param_1[0x58] != 4) {
          puVar6 = (uint *)((longlong)&IMAGE_SECTION_HEADER_000001e0.NumberOfRelocations + 1);
          *param_3 = 0x201;
        }
        param_1[0x5c] = 0;
      }
      goto LAB_0000a3fb;
    }
    puVar6 = DAT_0001b2c0;
    if ((((*DAT_0001b2c0 & 0x20000) == 0) || (param_1[0x58] == 4)) ||
       (param_2 >> 0xb < *(ulonglong *)((longlong)DAT_0001b2c0 + 0x71b))) goto LAB_0000a3fb;
    puVar6 = (uint *)((longlong)&IMAGE_SECTION_HEADER_000001e0.NumberOfRelocations + 1);
  }
  else {
    uVar4 = 0;
    do {
      bVar7 = *(byte *)(lVar1 + 0x1be + uVar4 * 0x10);
      if (((bVar7 & 0x7f) != 0) || (param_2 < *(uint *)(lVar1 + 0x1c6 + uVar4 * 0x10)))
      goto LAB_0000a372;
      if ((char)bVar7 < '\0') {
        bVar8 = (byte)uVar4;
      }
      bVar7 = (byte)uVar4 + 1;
      uVar4 = (ulonglong)bVar7;
    } while (bVar7 < 4);
    puVar9 = (undefined8 *)(lVar1 + 0x1be + (ulonglong)bVar8 * 0x10);
    if (&local_18 != puVar9) {
      FUN_00000280(&local_18,puVar9,0x10);
    }
    param_1[0x5c] = (byte)local_10;
    cVar2 = FUN_00009f6c(param_1,local_10,uVar5);
    uVar4 = CONCAT71(extraout_var_00,cVar2);
    if (cVar2 == -1) goto LAB_0000a1fb;
    uVar5 = FUN_0000a06c((longlong)param_1,param_2,*(longlong *)(DAT_0001ab98 + 0x6a));
    if ((char)uVar5 == '\0') {
      puVar6 = DAT_0001b2c0;
      if (((*(ulonglong *)((longlong)DAT_0001b2c0 + 0x71b) <= param_2 >> 0xb) ||
          ((*DAT_0001b2c0 & 0x1000) != 0)) || (param_1[0x58] == 4)) goto LAB_0000a3fb;
    }
    else {
      FUN_0000a414((longlong)param_1,param_2);
      param_1[0x5c] = 0;
      puVar6 = DAT_0001b2c0;
      if ((((*DAT_0001b2c0 & 0x20000) == 0) || (param_1[0x58] == 4)) ||
         (*(ulonglong *)((longlong)DAT_0001b2c0 + 0x71b) <= param_2 >> 0xb)) goto LAB_0000a3fb;
    }
    puVar6 = (uint *)0x403;
  }
  *param_3 = (short)puVar6;
LAB_0000a3fb:
  return (ulonglong)puVar6 & 0xffffffffffffff00;
}

