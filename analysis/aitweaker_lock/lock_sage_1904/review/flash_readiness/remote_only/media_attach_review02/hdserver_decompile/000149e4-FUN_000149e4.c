
undefined4 FUN_000149e4(uint param_1,int param_2)

{
  size_t __n;
  undefined4 uVar1;
  int iVar2;
  pthread_t __th;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  uint uVar7;
  byte local_1fe [2];
  undefined4 local_1fc;
  char local_1f8 [132];
  undefined4 local_174;
  uint local_170;
  
  __n = DAT_00014e34;
  iVar6 = DAT_00014e30;
  iVar3 = DAT_00014e2c;
  if (*(int *)(DAT_00014e2c + 0x130) <= (int)param_1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00014e60,DAT_00014e44,DAT_00014e5c);
    return 1;
  }
  iVar4 = param_1 * 4;
  *(undefined4 *)(DAT_00014e30 + iVar4 + 0x30) = 0xffffffff;
  memset(&local_174,0,__n);
  local_174 = 0xffffffff;
  local_170 = param_1;
  iVar2 = setRedirectedMediaInfo(4,&local_174);
  if (iVar2 != 0) {
    IDBG_LINUXAPP_DbgOut(0x84,DAT_00014e50,DAT_00014e44,DAT_00014e4c,local_170);
  }
  iVar2 = *(int *)(iVar6 + iVar4 + 0x20);
  *(undefined4 *)(iVar3 + iVar4 + 0x1fc) = 0;
  shutdown(iVar2,2);
  sigwrap_close(iVar2);
  iVar2 = *(int *)(iVar3 + iVar4 + 0x20c);
  local_1fe[0] = 0;
  *(undefined4 *)(iVar6 + iVar4 + 0x20) = 0xffffffff;
  if (iVar2 == 1) {
    uVar7 = param_1;
    IDBG_LINUXAPP_DbgOut(0x84,DAT_00014e80,DAT_00014e44,DAT_00014e7c,param_1);
    memcpy(*(void **)(DAT_00014e84 + param_1 * 4),*(void **)(DAT_00014e84 + iVar4 + 0x10),0x3e);
    iVar6 = FUN_00013770(param_1);
    if (iVar6 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00014e70,DAT_00014e44,DAT_00014e9c,uVar7);
      return 1;
    }
    FUN_00012e68(param_1);
  }
  if (*(int *)(iVar3 + iVar4 + 0x144) == 1) {
    uVar7 = param_1;
    IDBG_LINUXAPP_DbgOut(0x84,DAT_00014e58,DAT_00014e44,DAT_00014e54,param_1);
    iVar6 = FUN_00013770(param_1);
    if (iVar6 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00014e70,DAT_00014e44,DAT_00014e6c,uVar7);
      return 1;
    }
    FUN_00012e68(param_1);
  }
  iVar2 = iVar3 + iVar4;
  __th = *(pthread_t *)(iVar2 + 0x224);
  *(undefined4 *)(iVar3 + 0x220) = 1;
  pthread_cancel(__th);
  *(undefined4 *)(iVar2 + 0x1cc) = 0;
  pthread_join(*(pthread_t *)(iVar2 + 0x224),(void **)0x0);
  *(undefined4 *)(iVar2 + 0x154) = 0;
  memset(local_1f8,0,0x81);
  iVar6 = DAT_00014e38;
  uVar7 = *(uint *)(iVar2 + 0x1dc);
  local_1fc = 0;
  local_1fe[1] = 0;
  if (uVar7 == 0) {
LAB_00014b00:
    iVar2 = reset_hdisk_redir(DAT_00014e3c + param_1 * 0x81,&local_1fc,local_1fe + 1);
    if (iVar2 != 0) goto LAB_00014b60;
    if (*(int *)(iVar6 + 0x1e4) == 1) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00014e78,DAT_00014e44,DAT_00014e74);
      iVar2 = racsessinfo_unregister_session(*(undefined4 *)(iVar3 + iVar4 + 0x1ec),param_2);
      if (iVar2 != 0) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00014e94,DAT_00014e44,DAT_00014e98);
      }
      if (param_2 == 1) {
        On_send_Vmedia_Session_Update();
      }
      *(undefined4 *)(iVar3 + iVar4 + 0x1ec) = 0xffffffff;
    }
    if (local_1f8[0] != '\0') {
      InValidateToken(local_1f8);
    }
    iVar2 = FUN_000130b4();
    if ((iVar2 != 0) &&
       (iVar2 = Checkanyinstancerunning(DAT_00014e68,*(undefined4 *)(iVar3 + 0x130)), iVar2 == 0)) {
      FUN_00017de0();
    }
    if ((*(int *)(iVar6 + 0x180) != 1) || (*(int *)(iVar3 + iVar4 + 0x1dc) != 0)) goto LAB_00014b60;
  }
  else {
    if (*(int *)(DAT_00014e38 + 0x1e4) == 1) {
      iVar2 = racsessinfo_unregister_session(*(undefined4 *)(iVar2 + 0x1ec),param_2);
      if (iVar2 != 0) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00014e94,DAT_00014e44,DAT_00014e90);
      }
      if (param_2 == 1) {
        On_send_Vmedia_Session_Update();
      }
      uVar7 = *(uint *)(iVar3 + iVar4 + 0x1dc);
      *(undefined4 *)(iVar3 + iVar4 + 0x1ec) = 0xffffffff;
    }
    if (param_1 != (uVar7 & 0xff)) goto LAB_00014b00;
    IDBG_LINUXAPP_DbgOut(0x84,DAT_00014e8c,DAT_00014e44,DAT_00014e88);
    uVar1 = DAT_00014e68;
    uVar5 = *(undefined4 *)(iVar3 + 0x130);
    *(undefined4 *)(iVar3 + iVar4 + 0x1dc) = 0;
    iVar4 = Checkanyinstancerunning(uVar1,uVar5);
    if ((iVar4 == 0) &&
       ((iVar4 = FUN_000130b4(), iVar4 != 0 && (iVar4 = IsLmediaRmediaRunning(), iVar4 == 0)))) {
      FUN_00017de0();
    }
    if (*(int *)(iVar6 + 0x180) != 1) goto LAB_00014b60;
  }
  FUN_00014898();
LAB_00014b60:
  iVar6 = *(int *)(iVar6 + 0x1e4);
  *(undefined4 *)(iVar3 + 0x220) = 0;
  if (iVar6 != 1) {
    local_1fe[0] = 0;
    iVar3 = get_active_session(4,local_1fe);
    if (iVar3 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00014e48,DAT_00014e44,DAT_00014e64);
    }
    local_1fe[0] = local_1fe[0] - 1;
    if (((local_1fe[0] & 0x80) == 0) && (iVar3 = set_active_session(4), iVar3 != 0)) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00014e48,DAT_00014e44,DAT_00014e40);
    }
  }
  return 0;
}

