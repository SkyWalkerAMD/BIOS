
void FUN_00014450(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 in_r3;
  uint uVar5;
  int *piVar6;
  void *__s;
  undefined4 *puVar7;
  undefined4 uVar8;
  int *piVar9;
  undefined4 uVar10;
  
  iVar4 = DAT_000145e0;
  if (*(int *)(DAT_000145e0 + 0x2b0) == 1) {
    iVar3 = getLicenseStatus(DAT_00014608);
    if (iVar3 == 1) {
      uVar10 = 0xf7;
    }
    else {
      uVar10 = 0xf5;
    }
  }
  else {
    uVar10 = 0xf7;
    iVar3 = 1;
  }
  piVar9 = DAT_000145e8;
  iVar2 = DAT_000145e4;
  if (0 < *(int *)(DAT_000145e4 + 0x10)) {
    if (iVar3 == 1) {
      uVar8 = 100;
    }
    else {
      uVar8 = 500;
    }
    bVar1 = true;
    uVar5 = 0;
    piVar6 = (int *)(DAT_000145e4 + 0x50);
    do {
      if (*piVar6 == 0) {
        if (piVar9[uVar5] != -1) {
          FUN_00013a74(piVar9[uVar5],uVar5 & 0xff,uVar10,0,in_r3);
        }
      }
      else if (bVar1) {
        WriteCmdInMediaPipe(DAT_000145ec,uVar8);
        WriteCmdInMediaPipe(DAT_000145f0,uVar8);
        bVar1 = false;
      }
      iVar3 = *(int *)(iVar2 + 0x10);
      uVar5 = uVar5 + 1;
      piVar6 = piVar6 + 1;
    } while ((int)uVar5 < iVar3);
    if (0 < iVar3) {
      uVar5 = 0;
      __s = DAT_000145f4;
      puVar7 = (undefined4 *)((int)DAT_000145f4 + -0x84);
      piVar9 = DAT_000145e8;
      do {
        if (*piVar9 != -1) {
          FUN_00013f58(uVar5 & 0xff,0);
        }
        memset(__s,0,0x80);
        iVar3 = *(int *)(iVar2 + 0x10);
        uVar5 = uVar5 + 1;
        *puVar7 = 0;
        __s = (void *)((int)__s + 0x81);
        puVar7 = puVar7 + 1;
        piVar9 = piVar9 + 1;
      } while ((int)uVar5 < iVar3);
    }
  }
  iVar3 = DAT_000145f8;
  if (*(int *)(DAT_000145f8 + 0x30) != -1) {
    ShutDownServer();
  }
  if (*(int *)(iVar3 + 0x34) != -1) {
    ShutDownServer();
  }
  if (*(int *)(iVar4 + 0x1e4) == 1) {
    On_send_Vmedia_Session_Update();
  }
  else {
    FUN_00013dd4();
  }
  iVar4 = removeTOCFile(1);
  if (iVar4 != 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00014604,DAT_00014600,0xe0);
  }
  FUN_00017444();
  ProcMonitorDeRegister(DAT_000145fc);
                    /* WARNING: Subroutine does not return */
  exit(0);
}

