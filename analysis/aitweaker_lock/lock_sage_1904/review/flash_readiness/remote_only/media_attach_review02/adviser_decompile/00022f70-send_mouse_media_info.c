
void send_mouse_media_info(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined1 *puVar2;
  undefined4 *puVar3;
  undefined2 uVar4;
  char local_d5;
  undefined2 local_d4;
  undefined2 local_d2;
  undefined2 local_d0;
  undefined2 local_ce;
  undefined1 local_cc [12];
  undefined1 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined1 auStack_b4 [44];
  undefined4 local_88;
  undefined4 uStack_84;
  undefined4 uStack_80;
  undefined4 uStack_7c;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 uStack_4c;
  undefined4 uStack_48;
  undefined4 uStack_44;
  undefined4 local_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  undefined4 local_30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  
  iVar1 = DAT_000230ec;
  local_d5 = '\x02';
  memset(&local_88,0,0x2e);
  GetVMediaCfg(auStack_b4,*(undefined4 *)(iVar1 + 0x68),*(undefined4 *)(iVar1 + 0x74),
               *(undefined4 *)(iVar1 + 0x180));
  GetAdviserCfg(local_cc);
  puVar2 = DAT_000230f4;
  *DAT_000230f0 = local_cc[0];
  local_88._0_2_ = CONCAT11(local_c0,local_cc[0]);
  *puVar2 = local_c0;
  memcpy((void *)((int)&local_88 + 2),auStack_b4,0x2c);
  puVar3 = DAT_000230fc;
  if (*(int *)(iVar1 + 0x324) == 1) {
    uVar4 = 0x36;
    local_50 = local_88;
    uStack_4c = uStack_84;
    uStack_48 = uStack_80;
    uStack_44 = uStack_7c;
    local_40 = local_78;
    uStack_3c = uStack_74;
    uStack_38 = uStack_70;
    uStack_34 = uStack_6c;
    local_54 = local_b8;
    local_58 = local_bc;
    local_30 = local_68;
    uStack_2c = uStack_64;
    uStack_28 = uStack_60;
    *DAT_000230f8 = local_b8;
    *puVar3 = local_bc;
  }
  else {
    uVar4 = 0x2e;
  }
  local_d0 = 0;
  local_d4 = 0x26;
  local_ce = 0;
  local_d2 = uVar4;
  sm_build_send_list(param_1,param_2);
  if (*(int *)(iVar1 + 0x324) == 1) {
    puVar3 = &local_58;
  }
  else {
    puVar3 = &local_88;
  }
  send_control_pkt(&local_d4,param_1,puVar3,uVar4,0);
  Onhostlock_status(&local_d5);
  if (local_d5 == '\x04') {
    *DAT_00023100 = 0;
    sm_set_host_lock_status();
    return;
  }
  if (local_d5 == '\x05') {
    *DAT_00023100 = 1;
    sm_set_host_lock_status();
    return;
  }
  return;
}

