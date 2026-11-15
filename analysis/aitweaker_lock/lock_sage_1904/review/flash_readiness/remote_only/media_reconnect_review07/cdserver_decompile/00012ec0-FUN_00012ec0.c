
undefined4 FUN_00012ec0(undefined4 param_1,char *param_2,void *param_3,undefined1 *param_4)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  size_t sVar5;
  size_t sVar6;
  int iVar7;
  int iVar8;
  void *__dest;
  void *pvVar9;
  undefined1 uStack_20131;
  undefined4 uStack_20130;
  undefined4 uStack_2012c;
  byte abStack_20128 [8];
  undefined4 uStack_20120;
  int aiStack_2011c [11];
  char acStack_200f0 [68];
  char acStack_200ac [68];
  undefined1 auStack_20068 [23];
  byte bStack_20051;
  char cStack_2003f;
  
  iVar1 = DAT_00013360;
  uStack_20131 = 0;
  memset(acStack_200f0,0,0x41);
  memset(acStack_200ac,0,0x41);
  uStack_20130 = 0;
  iVar8 = *(int *)(iVar1 + 0x10);
  iVar2 = FUN_000167e0(param_1,auStack_20068,0x14);
  iVar7 = DAT_00013364;
  if (iVar2 != 0) {
    return 6;
  }
  if (*(int *)(DAT_00013364 + 0x1c8) == 0) {
LAB_00012f78:
    uVar3 = getcdfreeinstance_array(DAT_00013368,iVar8);
    uVar3 = uVar3 & 0xff;
  }
  else {
    if ((cStack_2003f != -0xd) || (iVar2 = strncmp(param_2,DAT_00013394,9), iVar2 != 0)) {
      if ((*(int *)(iVar7 + 0x68) != 0) && (*(int *)(iVar1 + 0x28) != 0)) {
        iVar8 = iVar8 + -1;
      }
      if ((*(int *)(iVar7 + 0x74) != 0) && (*(int *)(iVar1 + 0x2c) != 0)) {
        iVar8 = iVar8 + -1;
      }
      goto LAB_00012f78;
    }
    uVar3 = (uint)bStack_20051;
    if (uVar3 == 0) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000133a0,0);
      return 6;
    }
  }
  iVar2 = DAT_0001336c;
  if (uVar3 == 8) {
    return 8;
  }
  *param_4 = (char)uVar3;
  __dest = *(void **)(iVar2 + uVar3 * 4);
  memcpy(__dest,auStack_20068,DAT_00013370);
  if (*(char *)((int)__dest + 0x29) == -0xd) {
    iVar2 = strncmp(param_2,DAT_00013394,9);
    if (iVar2 != 0) goto LAB_0001318c;
    pvVar9 = (void *)IDBG_LINUXAPP_DbgOut(0x86,DAT_000133ac);
    iVar7 = *(int *)(iVar7 + 0x1e4);
    iVar2 = iVar1 + uVar3 * 4;
    *(uint *)(iVar2 + 0x50) = uVar3 + 0x100;
    if (iVar7 == 1) {
      sVar5 = strlen(param_2);
      iVar7 = racsessinfo_register_session
                        (10,param_2,sVar5 & 0xff,1,DAT_000133bc,5,0,0,&uStack_20130);
      if (iVar7 == 0) {
        *(undefined4 *)(iVar2 + 0x60) = uStack_20130;
        pvVar9 = (void *)On_send_Vmedia_Session_Update();
      }
      else {
        pvVar9 = (void *)IDBG_LINUXAPP_DbgOut(0x84,DAT_00013388,DAT_00013384,DAT_000133c0);
      }
    }
  }
  else {
    if (*(char *)((int)__dest + 0x29) != -0xe) {
LAB_0001318c:
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001339c,DAT_00013384,DAT_00013398);
      return 6;
    }
    pvVar9 = (void *)((int)__dest + 0x3f);
    uStack_2012c = 0;
    iVar2 = ValidateToken(pvVar9,&uStack_2012c,acStack_200f0,acStack_200ac,2);
    if (iVar2 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000133a8,DAT_00013384,DAT_000133a4);
      return 3;
    }
    iVar2 = GetUsrPriv(acStack_200f0,abStack_20128);
    if ((((iVar2 == 0) && (*(int *)(iVar7 + 0x13c) == 1)) &&
        (iVar2 = FUN_00016de0(uStack_20120,2), iVar2 == 0)) &&
       (iVar2 = IsTokenVmediaRunning(pvVar9), iVar2 != 1)) {
      return 5;
    }
    iVar2 = GetVMediaCfg(aiStack_2011c,*(undefined4 *)(iVar7 + 0x68),*(undefined4 *)(iVar7 + 0x74),
                         *(undefined4 *)(iVar7 + 0x180));
    if ((iVar2 == 0) && (aiStack_2011c[0] == 2)) {
      IDBG_LINUXAPP_DbgOut(0x84,DAT_000133b0,DAT_00013384,0x9e0);
      return 7;
    }
    memset(param_2,0,0x40);
    iVar2 = snprintf(param_2,0x40,DAT_00013374,acStack_200ac);
    if (iVar2 == 0x40) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000133b8,DAT_00013384,DAT_000133b4);
      return 6;
    }
    uVar4 = MapUid_to_SELUid(acStack_200f0,0);
    iVar2 = set_cdrom_redir(pvVar9,param_2,&uStack_20131);
    pvVar9 = memcpy(param_3,pvVar9,0x80);
    *(undefined1 *)((int)param_3 + 0x7f) = 0;
    if (iVar2 != 0) {
      if (iVar2 != 2) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00013390,DAT_00013384,DAT_0001338c);
        return 6;
      }
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000133c8,DAT_00013384,DAT_000133c4,param_2);
      return 4;
    }
    if (*(int *)(iVar7 + 0x1e4) == 1) {
      LoginLogoutAudit(0,DAT_0001337c,DAT_00013378,acStack_200ac,0);
      sVar5 = strlen(acStack_200ac);
      sVar6 = strlen(acStack_200f0);
      iVar7 = racsessinfo_register_session
                        (7,acStack_200ac,sVar5 & 0xff,1,acStack_200f0,sVar6 & 0xff,
                         (int)((uint)abStack_20128[0] << 0x1c) >> 0x1c & 0xff,uVar4,&uStack_20130);
      if (iVar7 == 0) {
        *(undefined4 *)(iVar1 + uVar3 * 4 + 0x60) = uStack_20130;
        pvVar9 = (void *)On_send_Vmedia_Session_Update();
      }
      else {
        pvVar9 = (void *)IDBG_LINUXAPP_DbgOut(0x84,DAT_00013388,DAT_00013384,DAT_00013380);
      }
    }
  }
  if (*(char *)((int)__dest + 0x3d) == '\x01') {
    iVar7 = FUN_00012e0c(pvVar9);
    if (iVar7 == 1) {
      uVar4 = 0x1b;
    }
    else {
      uVar4 = 0x1c;
    }
    *(undefined4 *)(iVar1 + uVar3 * 4) = uVar4;
  }
  else {
    uVar4 = 1;
  }
  return uVar4;
}

