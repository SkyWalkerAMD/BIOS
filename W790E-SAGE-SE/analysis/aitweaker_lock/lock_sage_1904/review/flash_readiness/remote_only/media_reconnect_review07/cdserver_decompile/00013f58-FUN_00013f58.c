
undefined4 FUN_00013f58(uint param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  char local_1f5;
  undefined4 local_1f4;
  byte local_1f0 [132];
  undefined4 local_16c;
  uint local_168;
  
  iVar7 = DAT_000143e4;
  iVar4 = DAT_000143e0;
  if (*(int *)(DAT_000143e0 + 0x10) <= (int)param_1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00014414,DAT_000143fc,DAT_00014428);
    return 1;
  }
  iVar1 = param_1 * 4;
  *(undefined4 *)(DAT_000143e4 + iVar1 + 0x10) = 0xffffffff;
  memset(&local_16c,0,DAT_000143e8);
  iVar3 = GetRedirectedMediaInfo(1,param_1,&local_16c);
  if (iVar3 == 0) {
    iVar3 = *(int *)(iVar4 + param_1 * 4);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001441c,DAT_000143fc,DAT_00014418,iVar3);
    iVar3 = *(int *)(iVar4 + param_1 * 4);
  }
  if (iVar3 != 0) {
    updateProcessPriority(0,local_16c);
    *(undefined4 *)(iVar4 + param_1 * 4) = 0;
  }
  memset(&local_16c,0,DAT_000143e8);
  local_16c = 0xffffffff;
  local_168 = param_1;
  iVar3 = setRedirectedMediaInfo(1,&local_16c);
  if (iVar3 != 0) {
    IDBG_LINUXAPP_DbgOut(0x84,DAT_00014424,DAT_000143fc,DAT_00014420,local_168);
  }
  iVar7 = iVar7 + iVar1;
  iVar8 = iVar4 + iVar1;
  iVar3 = *(int *)(iVar7 + 0x20);
  *(undefined4 *)(iVar8 + 0xb4) = 0;
  *(undefined4 *)(iVar8 + 0x94) = 0;
  shutdown(iVar3,2);
  sigwrap_close(*(undefined4 *)(iVar7 + 0x20));
  iVar3 = *(int *)(iVar8 + 0xa4);
  *(undefined4 *)(iVar7 + 0x20) = 0xffffffff;
  if (iVar3 == 1) {
    uVar6 = param_1;
    IDBG_LINUXAPP_DbgOut(0x84,DAT_00014408,DAT_000143fc,DAT_00014404,param_1);
    memcpy(*(void **)(DAT_0001440c + param_1 * 4),*(void **)(DAT_0001440c + iVar1 + 0x10),0x3e);
    iVar7 = FUN_000133cc(param_1);
    if (iVar7 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00014414,DAT_000143fc,DAT_00014410,uVar6);
      return 1;
    }
  }
  iVar7 = iVar4 + iVar1;
  *(undefined4 *)(iVar7 + 0x40) = 0;
  pthread_join(*(pthread_t *)(iVar7 + 0xc4),(void **)0x0);
  if (*(int *)(iVar7 + 0x80) == 1) {
    IDBG_LINUXAPP_DbgOut(0x84,DAT_00014430,DAT_000143fc,DAT_0001442c,param_1);
    FUN_000133cc(param_1);
  }
  iVar3 = iVar4 + iVar1;
  *(undefined4 *)(iVar3 + 0xd4) = 0;
  memset(local_1f0,0,0x81);
  iVar7 = DAT_000143ec;
  uVar6 = *(uint *)(iVar3 + 0x50);
  local_1f4 = 0;
  local_1f5 = '\0';
  if (uVar6 == 0) {
LAB_0001409c:
    iVar3 = reset_cdrom_redir(DAT_000143f0 + param_1 * 0x81,&local_1f4,&local_1f5);
    if (iVar3 != 0) goto LAB_0001410c;
    if (*(int *)(iVar7 + 0x1e4) == 1) {
      iVar3 = racsessinfo_unregister_session(*(undefined4 *)(iVar4 + iVar1 + 0x60),param_2);
      if (iVar3 != 0) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00014448,DAT_000143fc,DAT_00014444);
      }
      if (param_2 == 1) {
        On_send_Vmedia_Session_Update();
      }
      *(undefined4 *)(iVar4 + iVar1 + 0x60) = 0;
    }
    if (local_1f0[0] != 0) {
      InValidateToken(local_1f0);
    }
    if ((local_1f5 != '\0') && (*(char *)(DAT_000143f4 + param_1 * 9) == '\"')) goto LAB_0001410c;
    iVar3 = FUN_00012e7c();
    if ((iVar3 != 0) &&
       (iVar3 = Checkanyinstancerunning(DAT_00014434,*(undefined4 *)(iVar4 + 0x10)), iVar3 == 0)) {
      FUN_00017564();
    }
    if ((*(int *)(iVar7 + 0x180) != 1) || (*(int *)(iVar4 + iVar1 + 0x50) != 0)) goto LAB_0001410c;
  }
  else {
    if (*(int *)(DAT_000143ec + 0x1e4) == 1) {
      iVar3 = racsessinfo_unregister_session(*(undefined4 *)(iVar3 + 0x60),param_2);
      if (iVar3 != 0) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00014448,DAT_000143fc,DAT_0001444c);
      }
      if (param_2 == 1) {
        On_send_Vmedia_Session_Update();
      }
      uVar6 = *(uint *)(iVar4 + iVar1 + 0x50);
      *(undefined4 *)(iVar4 + iVar1 + 0x60) = 0;
    }
    if (param_1 != (uVar6 & 0xff)) goto LAB_0001409c;
    IDBG_LINUXAPP_DbgOut(0x84,DAT_00014440,DAT_000143fc,DAT_0001443c);
    uVar2 = DAT_00014434;
    uVar5 = *(undefined4 *)(iVar4 + 0x10);
    *(undefined4 *)(iVar4 + iVar1 + 0x50) = 0;
    iVar4 = Checkanyinstancerunning(uVar2,uVar5);
    if ((iVar4 == 0) &&
       ((iVar4 = FUN_00012e7c(), iVar4 != 0 && (iVar4 = IsLmediaRmediaRunning(), iVar4 == 0)))) {
      FUN_00017564();
    }
    if (*(int *)(iVar7 + 0x180) != 1) goto LAB_0001410c;
  }
  FUN_00013e0c();
LAB_0001410c:
  if (*(int *)(iVar7 + 0x1e4) != 1) {
    local_1f0[0] = 0;
    iVar4 = get_active_session(2,local_1f0);
    if (iVar4 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00014400,DAT_000143fc,DAT_00014438);
    }
    local_1f0[0] = local_1f0[0] - 1;
    if (((local_1f0[0] & 0x80) == 0) && (iVar4 = set_active_session(2), iVar4 != 0)) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00014400,DAT_000143fc,DAT_000143f8);
    }
  }
  return 0;
}

