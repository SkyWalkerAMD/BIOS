
undefined8 FUN_00000af8(longlong param_1,char *param_2,byte *param_3)

{
  byte bVar1;
  longlong lVar2;
  char *pcVar3;
  undefined8 uVar4;
  ulonglong uVar5;
  byte bVar6;
  byte local_res10 [8];
  undefined1 local_res20 [8];
  char local_38 [2];
  byte local_36;
  
  bVar6 = 0;
  local_res10[0] = 0;
  if (((param_2 == (char *)0x0) || (param_3 == (byte *)0x0)) || (*param_3 == 0)) {
    return 0x8000000000000002;
  }
  lVar2 = FUN_00000c44();
  pcVar3 = (char *)(**(code **)(lVar2 + 0x28))(0xc);
  lVar2 = FUN_00000c44();
  bVar1 = (**(code **)(lVar2 + 0x38))(0xc);
  if ((pcVar3 == (char *)0x0) || (bVar1 == 0)) {
LAB_00000c12:
    uVar4 = 0x800000000000000e;
  }
  else {
    if (*pcVar3 == '\0') {
      local_res10[0] = 1;
      do {
        local_res20[0] = 10;
        lVar2 = (**(code **)(param_1 + 8))(param_1,6,0,0x42,local_res10,1,local_38,local_res20);
        if (((-1 < lVar2) && (local_38[0] == '\0')) && (((local_36 & 0x7f) == 4 && (bVar6 < bVar1)))
           ) {
          uVar5 = (ulonglong)bVar6;
          bVar6 = bVar6 + 1;
          pcVar3[uVar5] = local_res10[0];
        }
        local_res10[0] = local_res10[0] + 1;
      } while (local_res10[0] < 0xc);
      if (bVar6 == 0) goto LAB_00000be9;
    }
    else {
LAB_00000be9:
      if (0xb < local_res10[0]) goto LAB_00000c12;
    }
    if (bVar1 < *param_3) {
      *param_3 = bVar1;
    }
    if (((ulonglong)*param_3 != 0) && (param_2 != pcVar3)) {
      FUN_00000260((undefined8 *)param_2,(undefined8 *)pcVar3,(ulonglong)*param_3);
    }
    uVar4 = 0;
  }
  return uVar4;
}

