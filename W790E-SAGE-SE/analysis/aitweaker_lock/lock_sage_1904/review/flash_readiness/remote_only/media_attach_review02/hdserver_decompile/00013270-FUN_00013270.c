
undefined4
FUN_00013270(undefined4 param_1,char *param_2,void *param_3,undefined1 *param_4,undefined1 *param_5)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  size_t sVar4;
  size_t sVar5;
  int iVar6;
  void *pvVar7;
  int iVar8;
  int iVar9;
  undefined1 uStack_20131;
  undefined4 uStack_20130;
  undefined4 uStack_2012c;
  byte abStack_20128 [8];
  undefined4 uStack_20120;
  undefined1 auStack_2011c [4];
  int iStack_20118;
  char acStack_200f0 [68];
  char acStack_200ac [68];
  undefined1 auStack_20068 [22];
  undefined1 uStack_20052;
  byte bStack_20051;
  char cStack_2003f;
  
  iVar9 = DAT_00013700;
  uStack_20131 = 0;
  memset(acStack_200f0,0,0x41);
  memset(acStack_200ac,0,0x41);
  uStack_20130 = 0;
  iVar8 = *(int *)(iVar9 + 0x130);
  iVar1 = FUN_00017054(param_1,auStack_20068,0x14);
  iVar6 = DAT_00013704;
  if (iVar1 != 0) {
    return 6;
  }
  if (*(int *)(DAT_00013704 + 0x1c8) == 0) {
LAB_00013328:
    uVar2 = getcdfreeinstance_array(DAT_00013708,iVar8);
    uVar2 = uVar2 & 0xff;
  }
  else {
    if ((cStack_2003f != -0xd) || (iVar1 = strncmp(param_2,DAT_00013724,9), iVar1 != 0)) {
      if ((*(int *)(iVar6 + 0x68) != 0) && (*(int *)(iVar9 + 0x1b4) != 0)) {
        iVar8 = iVar8 + -1;
      }
      if ((*(int *)(iVar6 + 0x74) != 0) && (*(int *)(iVar9 + 0x1b8) != 0)) {
        iVar8 = iVar8 + -1;
      }
      goto LAB_00013328;
    }
    uVar2 = (uint)bStack_20051;
    if (uVar2 == 0) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00013730,0);
      return 6;
    }
  }
  if (uVar2 == 8) {
    return 8;
  }
  pvVar7 = *(void **)(DAT_0001370c + uVar2 * 4);
  *param_4 = (char)uVar2;
  *param_5 = uStack_20052;
  pvVar7 = memcpy(pvVar7,auStack_20068,DAT_00013710);
  if (*(char *)((int)pvVar7 + 0x29) == -0xd) {
    iVar1 = strncmp(param_2,DAT_00013724,9);
    if (iVar1 != 0) goto LAB_000134a0;
    IDBG_LINUXAPP_DbgOut(0x86,DAT_0001374c);
    iVar6 = *(int *)(iVar6 + 0x1e4);
    iVar9 = iVar9 + uVar2 * 4;
    *(uint *)(iVar9 + 0x1dc) = uVar2 + 0x100;
    if (iVar6 == 1) {
      sVar4 = strlen(param_2);
      iVar6 = racsessinfo_register_session
                        (0xc,param_2,sVar4 & 0xff,1,DAT_00013750,5,0,0,&uStack_20130);
      if (iVar6 != 0) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00013758,DAT_0001371c,DAT_00013754);
        return 1;
      }
      *(undefined4 *)(iVar9 + 0x1ec) = uStack_20130;
      On_send_Vmedia_Session_Update();
      return 1;
    }
  }
  else {
    if (*(char *)((int)pvVar7 + 0x29) != -0xe) {
LAB_000134a0:
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001372c,DAT_0001371c,DAT_00013728);
      return 6;
    }
    pvVar7 = (void *)((int)pvVar7 + 0x3f);
    uStack_2012c = 0;
    iVar1 = ValidateToken(pvVar7,&uStack_2012c,acStack_200f0,acStack_200ac,2);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00013748,DAT_0001371c,DAT_00013744);
      return 3;
    }
    if ((((*(int *)(iVar6 + 0x13c) == 1) &&
         (iVar1 = GetUsrPriv(acStack_200f0,abStack_20128), iVar1 == 0)) &&
        (iVar1 = FUN_00017638(uStack_20120,2), iVar1 == 0)) &&
       (iVar1 = IsTokenVmediaRunning(pvVar7), iVar1 != 1)) {
      return 5;
    }
    iVar1 = GetVMediaCfg(auStack_2011c,*(undefined4 *)(iVar6 + 0x68),*(undefined4 *)(iVar6 + 0x74),
                         *(undefined4 *)(iVar6 + 0x180));
    if ((iVar1 == 0) && (iStack_20118 == 2)) {
      IDBG_LINUXAPP_DbgOut(0x84,DAT_00013740,DAT_0001371c,DAT_0001373c);
      return 7;
    }
    memset(param_2,0,0x40);
    iVar1 = snprintf(param_2,0x40,DAT_00013714,acStack_200ac);
    if (iVar1 == 0x40) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00013738,DAT_0001371c,DAT_00013734);
    }
    uVar3 = MapUid_to_SELUid(acStack_200f0,0);
    iVar1 = set_hdisk_redir(pvVar7,param_2,&uStack_20131);
    memcpy(param_3,pvVar7,0x80);
    *(undefined1 *)((int)param_3 + 0x7f) = 0;
    if (iVar1 != 0) {
      if (iVar1 != 2) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00013720,DAT_0001371c,DAT_00013718);
        return 6;
      }
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001376c,DAT_0001371c,DAT_00013768,param_2);
      return 4;
    }
    if (*(int *)(iVar6 + 0x1e4) == 1) {
      LoginLogoutAudit(0,DAT_00013760,DAT_0001375c,acStack_200ac,0);
      sVar4 = strlen(acStack_200ac);
      sVar5 = strlen(acStack_200f0);
      iVar6 = racsessinfo_register_session
                        (9,acStack_200ac,sVar4 & 0xff,1,acStack_200f0,sVar5 & 0xff,
                         (int)((uint)abStack_20128[0] << 0x1c) >> 0x1c & 0xff,uVar3,&uStack_20130);
      if (iVar6 != 0) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00013758,DAT_0001371c,DAT_00013764);
        return 1;
      }
      *(undefined4 *)(iVar9 + uVar2 * 4 + 0x1ec) = uStack_20130;
      On_send_Vmedia_Session_Update();
      return 1;
    }
  }
  return 1;
}

