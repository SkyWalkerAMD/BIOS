
longlong FUN_00018af0(undefined8 *param_1,int param_2,short *param_3,undefined8 *param_4,
                     longlong param_5,ulonglong param_6,ulonglong *param_7,longlong *param_8,
                     ulonglong *param_9,undefined4 *param_10)

{
  bool bVar1;
  short *psVar2;
  ulonglong uVar3;
  undefined8 *puVar4;
  longlong lVar5;
  char *pcVar6;
  undefined8 *local_res8;
  undefined4 *local_b8;
  ulonglong local_b0;
  ulonglong local_a8;
  ulonglong local_a0;
  longlong local_98;
  longlong local_90;
  undefined1 local_88 [8];
  int *local_80;
  undefined8 local_78;
  undefined8 local_70;
  ulonglong local_68;
  longlong local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined1 local_48 [8];
  undefined1 local_40 [8];
  ulonglong local_38;
  ulonglong local_30;
  
  *param_10 = 0;
  if (((param_1 == (undefined8 *)0x0) || (param_3 == (short *)0x0)) ||
     (lVar5 = 0, psVar2 = param_3, *param_3 == 0)) {
    return -0x7ffffffffffffffe;
  }
  do {
    psVar2 = psVar2 + 1;
    lVar5 = lVar5 + 1;
  } while (*psVar2 != 0);
  if (lVar5 == 0) {
    return -0x7ffffffffffffffe;
  }
  FUN_000002c0(&local_b8,0x28);
  FUN_000002c0(&local_80,0x28);
  local_80 = (int *)FUN_00015ad4(0x10);
  if (local_80 == (int *)0x0) {
    lVar5 = -0x7ffffffffffffff7;
  }
  else {
    *local_80 = param_2;
    *(short **)(local_80 + 2) = param_3;
    if (param_4 != (undefined8 *)0x0) {
      local_78 = *param_4;
      local_70 = param_4[1];
    }
    if (param_5 != 0) {
      local_68 = param_6;
      local_60 = param_5;
    }
    local_b8 = (undefined4 *)FUN_00015aa4(param_5,4);
    if (local_b8 == (undefined4 *)0x0) {
      lVar5 = -0x7ffffffffffffff7;
      goto LAB_00018e92;
    }
    uVar3 = 0;
    if ((local_60 != 0) && (local_68 != 0)) {
      do {
        uVar3 = uVar3 + 500;
        if (local_68 < uVar3) break;
      } while (uVar3 < local_68);
    }
    local_res8 = (undefined8 *)0x0;
    local_58 = 8;
    lVar5 = (**(code **)(DAT_0001e070 + 0xb0))(2,&DAT_00019910,0,&local_58,&local_50);
    if ((lVar5 < 0) ||
       (lVar5 = (**(code **)(DAT_0001e070 + 0x98))(local_50,&DAT_00019850,&local_res8),
       puVar4 = local_res8, lVar5 < 0)) {
      puVar4 = (undefined8 *)0x0;
    }
    if (param_1 == puVar4) {
      lVar5 = (**(code **)(DAT_0001e070 + 0x140))(&DAT_000198b0,0,&local_90);
      bVar1 = false;
      if (-1 < lVar5) {
        lVar5 = (**(code **)(local_90 + 0x30))(local_90,0,local_40,local_88);
        bVar1 = false;
        if (-1 < lVar5) {
          bVar1 = true;
        }
      }
      lVar5 = (*(code *)*param_1)(param_1,&local_80,&local_b8);
      uVar3 = 0;
      if ((bVar1) &&
         (lVar5 = (**(code **)(local_90 + 0x30))(local_90,0,local_48,local_88), -1 < lVar5)) {
        if (param_2 < 6) {
          if (param_2 == 5) {
            pcVar6 = &DAT_0001dfc0;
          }
          else if (param_2 == 0) {
            pcVar6 = &DAT_0001df9c;
          }
          else if (param_2 == 1) {
            pcVar6 = &DAT_0001dfa0;
          }
          else if (param_2 == 2) {
            pcVar6 = s_PATCH_0001dfa8;
          }
          else if (param_2 == 3) {
            pcVar6 = s_OPTIONS_0001dfb0;
          }
          else {
            if (param_2 != 4) goto LAB_00018d99;
            pcVar6 = s_CONNECT_0001dfb8;
          }
        }
        else if (param_2 == 6) {
          pcVar6 = &DAT_0001dfc8;
        }
        else if (param_2 == 7) {
          pcVar6 = s_DELETE_0001dfcc;
        }
        else if (param_2 == 8) {
          pcVar6 = s_TRACE_0001dfd4;
        }
        else if (param_2 == 9) {
          pcVar6 = &DAT_0001dfdc;
        }
        else {
LAB_00018d99:
          pcVar6 = s_Unknown_00019a70;
        }
        FUN_000197dc(0xffffffffffffffff,s_Time_for__a____s_operation____ld_0001dfe0,pcVar6,param_3);
      }
      if ((local_98 != 0) && (local_a0 != 0)) {
        do {
          uVar3 = uVar3 + 500;
          if (local_a0 < uVar3) break;
        } while (uVar3 < local_a0);
      }
      if (-1 < lVar5) {
        if (param_7 != (ulonglong *)0x0) {
          *param_7 = local_b0;
          param_7[1] = local_a8;
        }
        if (param_8 != (longlong *)0x0) {
          *param_8 = local_98;
          *param_9 = local_a0;
        }
        *param_10 = *local_b8;
      }
    }
    else {
      lVar5 = -0x7fffffffffffffed;
    }
  }
  if (local_b8 != (undefined4 *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))();
    local_b8 = (undefined4 *)0x0;
  }
LAB_00018e92:
  if ((param_7 == (ulonglong *)0x0) && (local_a8 != 0)) {
    local_30 = local_a8;
    local_38 = local_b0;
    FUN_000188d4(&local_38);
    local_b0 = 0;
    local_a8 = 0;
  }
  if ((param_8 == (longlong *)0x0) && (local_98 != 0)) {
    (**(code **)(DAT_0001e070 + 0x48))();
    local_a0 = 0;
    local_98 = 0;
  }
  if (local_80 != (int *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))(local_80);
    return lVar5;
  }
  return lVar5;
}

