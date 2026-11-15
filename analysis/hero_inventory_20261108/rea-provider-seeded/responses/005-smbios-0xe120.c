
void FUN_0000e120(longlong param_1)

{
  byte bVar1;
  byte bVar2;
  char cVar3;
  longlong lVar4;
  longlong lVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  char *pcVar8;
  int iVar9;
  uint uVar10;
  ulonglong uVar11;
  int iVar12;
  short sVar13;
  undefined1 local_res8 [8];
  undefined2 local_res10 [4];
  char *local_res18;
  longlong local_res20;
  int local_1048 [1026];
  
  uVar7 = 0;
  iVar9 = 0;
  uVar11 = 0;
  sVar13 = 1;
  FUN_000002c0((undefined8 *)local_1048,0x1000);
  local_res8[0] = 3;
  local_res10[0] = 0xfffe;
  lVar4 = (**(code **)(DAT_000189c0 + 0x18))(DAT_000189c0,local_res10,local_res8,&local_res20,0);
  if (-1 < lVar4) {
    bVar1 = *(byte *)(local_res20 + 5);
    *(byte *)(param_1 + 0x1b9) = *(byte *)(param_1 + 0x1b9) | 4;
    bVar2 = *(byte *)(param_1 + 0x1b9);
    *(uint *)(param_1 + 0x170) = (uint)bVar1;
    if (*(char *)(local_res20 + 4) == '\0') {
      local_res18 = (char *)0x0;
      uVar11 = uVar7;
      lVar4 = local_res20;
    }
    else {
      lVar5 = FUN_0001598c((char *)((ulonglong)*(byte *)(local_res20 + 1) + local_res20),
                           *(char *)(local_res20 + 4),&local_res18);
      lVar4 = local_res20;
      if (-1 < lVar5) {
        pcVar8 = local_res18;
        uVar11 = uVar7;
        if (local_res18 != (char *)0x0) {
          uVar11 = FUN_000124e0(local_res18,0x200);
          uVar11 = uVar11 + 1;
          lVar4 = local_res20;
        }
        FUN_0001250c((char *)local_1048,uVar11 & 0xffffffff,pcVar8);
        *(byte *)(param_1 + 0x1b8) = *(byte *)(param_1 + 0x1b8) | 0x10;
        sVar13 = 2;
        *(undefined2 *)(param_1 + 0x2d0) = 1;
      }
    }
    if (*(char *)(lVar4 + 7) == '\0') {
      local_res18 = (char *)0x0;
    }
    else {
      lVar5 = FUN_0001598c((char *)((ulonglong)*(byte *)(lVar4 + 1) + lVar4),*(char *)(lVar4 + 7),
                           &local_res18);
      if (-1 < lVar5) {
        pcVar8 = local_res18;
        uVar6 = uVar7;
        if (local_res18 != (char *)0x0) {
          uVar6 = FUN_000124e0(local_res18,0x200);
          uVar6 = uVar6 + 1;
        }
        FUN_0001250c((char *)((longlong)local_1048 + (uVar11 & 0xffffffff)),uVar6 & 0xffffffff,
                     pcVar8);
        uVar11 = (ulonglong)(uint)((int)uVar11 + (int)uVar6);
        *(short *)(param_1 + 0x2d6) = sVar13;
        sVar13 = sVar13 + 1;
        *(byte *)(param_1 + 0x1b8) = *(byte *)(param_1 + 0x1b8) | 0x80;
      }
    }
    cVar3 = *(char *)(lVar4 + ((ulonglong)*(byte *)(lVar4 + 0x14) *
                               (ulonglong)*(byte *)(lVar4 + 0x13) + 7) * 3);
    if ((cVar3 != '\0') &&
       (lVar4 = FUN_0001598c((char *)((ulonglong)*(byte *)(lVar4 + 1) + lVar4),cVar3,&local_res18),
       -1 < lVar4)) {
      pcVar8 = local_res18;
      if (local_res18 != (char *)0x0) {
        uVar7 = FUN_000124e0(local_res18,0x200);
        uVar7 = uVar7 + 1;
      }
      iVar12 = (int)uVar7;
      FUN_0001250c((char *)((longlong)local_1048 + (uVar11 & 0xffffffff)),uVar7 & 0xffffffff,pcVar8)
      ;
      *(short *)(param_1 + 0x2d8) = sVar13;
      uVar11 = (ulonglong)(uint)((int)uVar11 + iVar12);
      sVar13 = sVar13 + 1;
      *(byte *)(param_1 + 0x1b9) = bVar2 | 1;
    }
    pcVar8 = (char *)((longlong)local_1048 + (uVar11 & 0xffffffff));
    FUN_00012658(pcVar8,0x200,(byte *)s_PcieSlot__X_000169c0,0);
    iVar12 = iVar9;
    if (pcVar8 != (char *)0x0) {
      uVar7 = FUN_000124e0(pcVar8,0x200);
      iVar12 = (int)uVar7 + 1;
    }
    *(byte *)(param_1 + 0x2a8) = *(byte *)(param_1 + 0x2a8) | 1;
    uVar10 = (int)uVar11 + iVar12;
    *(short *)(param_1 + 0x2aa) = sVar13;
    pcVar8 = (char *)((longlong)local_1048 + (ulonglong)uVar10);
    FUN_00012658(pcVar8,0x200,(byte *)s_PcieSlot__X_000169c0,0);
    if (pcVar8 != (char *)0x0) {
      uVar11 = FUN_000124e0(pcVar8,0x200);
      iVar9 = (int)uVar11 + 1;
    }
    *(byte *)(param_1 + 0x2a8) = *(byte *)(param_1 + 0x2a8) | 2;
    *(short *)(param_1 + 0x2ac) = sVar13 + 1;
    FUN_00012658((char *)((longlong)local_1048 + (ulonglong)(iVar9 + uVar10)),0x200,
                 (byte *)s_PcieSlot__X_000169c0,0);
    *(byte *)(param_1 + 0x2a8) = *(byte *)(param_1 + 0x2a8) | 4;
    *(short *)(param_1 + 0x2ae) = sVar13 + 2;
    FUN_00015ebc(param_1,(int *)(param_1 + 0x1c4),local_1048);
  }
  return;
}

