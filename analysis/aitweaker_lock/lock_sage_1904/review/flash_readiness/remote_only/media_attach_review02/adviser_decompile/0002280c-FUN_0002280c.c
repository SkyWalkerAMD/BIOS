
void FUN_0002280c(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  undefined4 local_78;
  undefined4 local_74;
  uint local_70;
  uint local_6c;
  undefined1 auStack_68 [17];
  byte local_57;
  byte local_55;
  byte local_54;
  byte local_52;
  undefined1 auStack_3c [12];
  int local_30;
  int local_2c;
  uint local_18;
  uint local_14;
  
  iVar1 = DAT_00022998;
  local_70 = 0;
  local_78 = 0;
  local_6c = 0;
  local_74 = 0;
  sm_build_send_list();
  iVar2 = GetVMediaCfg(auStack_3c,*(undefined4 *)(iVar1 + 0x68),*(undefined4 *)(iVar1 + 0x74),
                       *(undefined4 *)(iVar1 + 0x180));
  if (iVar2 != 0) {
    return;
  }
  iVar2 = racsessinfo_getsessionhdr(auStack_68);
  if (iVar2 != 0) {
    local_74 = 0;
    local_78 = DAT_0002299c;
    send_control_pkt(&local_78,param_1,&local_70,8,0);
    return;
  }
  if ((local_30 != 0) && (local_18 != 0)) {
    local_70 = local_30 - ((uint)local_57 + (uint)local_54);
    if ((local_70 != 0) && (*(int *)(iVar1 + 900) != 0)) {
      if (local_18 < local_70) {
        local_70 = local_18;
      }
      else if (local_18 != local_70) {
        local_70 = (local_18 - local_30) + (uint)local_57 + (uint)local_54;
      }
    }
  }
  if ((local_2c != 0) && (local_14 != 0)) {
    local_6c = local_2c - ((uint)local_55 + (uint)local_52);
    if ((local_6c != 0) && (*(int *)(iVar1 + 900) != 0)) {
      if (local_14 < local_6c) {
        local_6c = local_14;
      }
      else if (local_14 != local_6c) {
        local_6c = (local_14 - local_2c) + (uint)local_55 + (uint)local_52;
      }
    }
  }
  local_74 = 0;
  local_78 = DAT_0002299c;
  send_control_pkt(&local_78,param_1,&local_70,8,0);
  return;
}

