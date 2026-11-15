
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong FUN_00000580(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  longlong lVar2;
  ulonglong uVar3;
  undefined *puVar4;
  undefined4 local_res18 [2];
  longlong local_res20;
  undefined8 local_38;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  local_res20 = 0;
  local_res18[0] = 0;
  local_30 = 0xec87d643;
  local_2c = 0x4bb5eba4;
  local_28 = 0x3e3fe5a1;
  local_24 = 0xa90db236;
  lVar2 = FUN_00001d44(param_1,&local_30,local_res18,&local_38,&local_res20);
  lVar1 = local_res20;
  if ((lVar2 < 0) || (*(char *)(local_res20 + 0xbf5) != '\0')) {
    if (DAT_00007b58 == 0) {
      _DAT_00007b50 = *(undefined8 *)(param_2 + 0x58);
      DAT_00007b58 = param_2;
    }
    uVar3 = FUN_00005634();
    if ((int)uVar3 != 0x20) {
      uVar3 = FUN_00005634();
      if ((int)uVar3 != 0x12) {
        puVar4 = &DAT_00007178;
        _DAT_00007170 = param_1;
        lVar2 = (**(code **)(DAT_00007b28 + 0x148))(&DAT_00007178,&DAT_00007140,&PTR_FUN_00007150,0)
        ;
        if (-1 < lVar2) {
          FUN_00000688(puVar4);
        }
      }
    }
  }
  if (lVar1 != 0) {
    (**(code **)(DAT_00007b28 + 0x48))(lVar1);
  }
  return lVar2;
}



longlong FUN_00003348(undefined8 *param_1,int param_2,short *param_3,undefined8 *param_4,
                     longlong param_5,undefined8 param_6,ulonglong *param_7,longlong *param_8,
                     undefined8 *param_9,undefined4 *param_10)

{
  bool bVar1;
  short *psVar2;
  char *pcVar3;
  longlong lVar4;
  longlong local_res18;
  undefined4 *local_a8;
  ulonglong local_a0;
  ulonglong local_98;
  undefined8 local_90;
  longlong local_88;
  undefined1 local_80 [8];
  undefined1 local_78 [8];
  undefined1 local_70 [8];
  int *local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  longlong local_48;
  ulonglong local_40;
  ulonglong local_38;
  
  bVar1 = false;
  if ((param_3 == (short *)0x0) || (lVar4 = 0, psVar2 = param_3, *param_3 == 0)) {
    return -0x7ffffffffffffffe;
  }
  do {
    psVar2 = psVar2 + 1;
    lVar4 = lVar4 + 1;
  } while (*psVar2 != 0);
  if (lVar4 == 0) {
    return -0x7ffffffffffffffe;
  }
  FUN_000002e0(&local_a8,0x28);
  FUN_000002e0(&local_68,0x28);
  local_68 = (int *)FUN_00004ad0(0x10);
  if (local_68 == (int *)0x0) {
    lVar4 = -0x7ffffffffffffff7;
  }
  else {
    *local_68 = param_2;
    *(short **)(local_68 + 2) = param_3;
    if (param_4 != (undefined8 *)0x0) {
      local_60 = *param_4;
      local_58 = param_4[1];
    }
    if (param_5 != 0) {
      local_50 = param_6;
      local_48 = param_5;
    }
    local_a8 = (undefined4 *)FUN_00004aa0(param_5,4);
    if (local_a8 == (undefined4 *)0x0) {
      lVar4 = -0x7ffffffffffffff7;
      goto LAB_0000340c;
    }
    lVar4 = (**(code **)(DAT_00007b28 + 0x140))(&DAT_000070e0,0,&local_res18);
    if (-1 < lVar4) {
      lVar4 = (**(code **)(local_res18 + 0x30))(local_res18,0,local_70,local_80);
      bVar1 = false;
      if (-1 < lVar4) {
        bVar1 = true;
      }
    }
    lVar4 = (*(code *)*param_1)(param_1,&local_68,&local_a8);
    if (bVar1) {
      lVar4 = (**(code **)(local_res18 + 0x30))(local_res18,0,local_78,local_80);
      if (lVar4 < 0) goto LAB_000033f6;
      pcVar3 = FUN_00004f74(param_2);
      FUN_00004a3c(0xffffffffffffffff,s_Time_for__a____s_operation____ld_000074f0,pcVar3,param_3);
    }
    if (-1 < lVar4) {
      if (param_7 != (ulonglong *)0x0) {
        *param_7 = local_a0;
        param_7[1] = local_98;
      }
      if (param_8 != (longlong *)0x0) {
        *param_8 = local_88;
        *param_9 = local_90;
      }
      *param_10 = *local_a8;
    }
  }
LAB_000033f6:
  if (local_a8 != (undefined4 *)0x0) {
    (**(code **)(DAT_00007b28 + 0x48))(local_a8);
    local_a8 = (undefined4 *)0x0;
  }
LAB_0000340c:
  if ((param_7 == (ulonglong *)0x0) && (local_98 != 0)) {
    local_38 = local_98;
    local_40 = local_a0;
    FUN_00004d00(&local_40);
    local_a0 = 0;
    local_98 = 0;
  }
  if ((param_8 == (longlong *)0x0) && (local_88 != 0)) {
    (**(code **)(DAT_00007b28 + 0x48))();
    local_90 = 0;
    local_88 = 0;
  }
  if (local_68 != (int *)0x0) {
    (**(code **)(DAT_00007b28 + 0x48))(local_68);
    return lVar4;
  }
  return lVar4;
}

