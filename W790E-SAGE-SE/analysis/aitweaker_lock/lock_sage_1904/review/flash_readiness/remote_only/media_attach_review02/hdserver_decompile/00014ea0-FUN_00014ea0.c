
void FUN_00014ea0(void)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  void *__s;
  int *piVar10;
  undefined4 uVar11;
  undefined4 *puVar12;
  
  iVar4 = DAT_00015040;
  if ((*(int *)(DAT_00015040 + 0x2b0) == 1) && (iVar6 = getLicenseStatus(DAT_00015068), iVar6 != 1))
  {
    uVar11 = 0xf5;
  }
  else {
    uVar11 = 0xf7;
  }
  uVar3 = DAT_0001504c;
  iVar2 = DAT_00015048;
  iVar6 = DAT_00015044;
  bVar1 = true;
  uVar7 = 0;
  do {
    iVar5 = uVar7 * 4;
    uVar9 = uVar7 + 1;
    uVar8 = uVar7;
    if (*(int *)(iVar6 + iVar5 + 0x1dc) == 0) {
LAB_00014fe4:
      iVar5 = *(int *)(iVar2 + iVar5 + 0x20);
      if (iVar5 != -1) {
        FUN_00013960(iVar5,uVar8 & 0xff,uVar11);
      }
    }
    else if (bVar1) {
      WriteCmdInMediaPipe(uVar3,300);
      WriteCmdInMediaPipe(DAT_0001505c,300);
      if (uVar9 == 4) break;
      if (*(int *)(iVar6 + uVar9 * 4 + 0x1dc) == 0) {
        iVar5 = uVar9 * 4;
        bVar1 = false;
        uVar8 = uVar9;
        uVar9 = uVar7 + 2;
        goto LAB_00014fe4;
      }
      bVar1 = false;
      uVar9 = uVar7 + 2;
    }
    uVar7 = uVar9;
  } while (uVar9 != 4);
  uVar7 = 0;
  __s = DAT_00015050;
  piVar10 = DAT_00015054;
  puVar12 = (undefined4 *)((int)DAT_00015050 + -0x48);
  do {
    if (*piVar10 != -1) {
      FUN_000149e4(uVar7 & 0xff,0);
    }
    uVar7 = uVar7 + 1;
    memset(__s,0,0x80);
    *puVar12 = 0;
    __s = (void *)((int)__s + 0x81);
    piVar10 = piVar10 + 1;
    puVar12 = puVar12 + 1;
  } while (uVar7 != 4);
  if (*(int *)(iVar2 + 0x40) != -1) {
    ShutDownServer();
  }
  if (*(int *)(iVar2 + 0x44) != -1) {
    ShutDownServer();
  }
  if (*(int *)(iVar4 + 0x1e4) == 1) {
    On_send_Vmedia_Session_Update();
  }
  else {
    FUN_00014860();
  }
  iVar4 = removeTOCFile(4);
  if (iVar4 != 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00015064,DAT_00015060,0xdd);
  }
  FUN_00017cc4();
  ProcMonitorDeRegister(DAT_00015058);
                    /* WARNING: Subroutine does not return */
  exit(0);
}

