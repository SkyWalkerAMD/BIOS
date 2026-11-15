
void FUN_0000de54(longlong param_1)

{
  byte bVar1;
  longlong lVar2;
  longlong lVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  char *pcVar6;
  ulonglong uVar7;
  short sVar8;
  undefined1 local_res8 [8];
  undefined2 local_res10 [4];
  char *local_res18;
  longlong local_res20;
  longlong local_1058 [2];
  int local_1048 [1026];
  
  uVar5 = 0;
  uVar7 = 0;
  sVar8 = 1;
  FUN_000002c0((undefined8 *)local_1048,0x1000);
  local_res8[0] = 0;
  local_res10[0] = 0xfffe;
  lVar2 = (**(code **)(DAT_000189c0 + 0x18))(DAT_000189c0,local_res10,local_res8,&local_res20,0);
  if (-1 < lVar2) {
    if (*(char *)(local_res20 + 5) == '\0') {
      local_res18 = (char *)0x0;
      uVar7 = uVar5;
    }
    else {
      lVar2 = FUN_0001598c((char *)((ulonglong)*(byte *)(local_res20 + 1) + local_res20),
                           *(char *)(local_res20 + 5),&local_res18);
      if (-1 < lVar2) {
        pcVar6 = local_res18;
        uVar7 = uVar5;
        if (local_res18 != (char *)0x0) {
          uVar7 = FUN_000124e0(local_res18,0x200);
          uVar7 = uVar7 + 1;
        }
        FUN_0001250c((char *)local_1048,uVar7 & 0xffffffff,pcVar6);
        sVar8 = 2;
        *(undefined2 *)(param_1 + 0xea) = 1;
        *(byte *)(param_1 + 0xc1) = *(byte *)(param_1 + 0xc1) | 2;
      }
    }
    local_res10[0] = 0xfffe;
    local_res8[0] = 1;
    lVar2 = (**(code **)(DAT_000189c0 + 0x18))(DAT_000189c0,local_res10,local_res8,local_1058,0);
    if (-1 < lVar2) {
      *(undefined8 *)(param_1 + 0x50) = *(undefined8 *)(local_1058[0] + 8);
      *(undefined8 *)(param_1 + 0x58) = *(undefined8 *)(local_1058[0] + 0x10);
      *(byte *)(param_1 + 0xc1) = *(byte *)(param_1 + 0xc1) | 0x10;
      bVar1 = *(byte *)(param_1 + 0xc1);
      if (*(char *)(local_1058[0] + 4) == '\0') {
        local_res18 = (char *)0x0;
        lVar2 = local_1058[0];
      }
      else {
        lVar3 = FUN_0001598c((char *)((ulonglong)*(byte *)(local_1058[0] + 1) + local_1058[0]),
                             *(char *)(local_1058[0] + 4),&local_res18);
        lVar2 = local_1058[0];
        if (-1 < lVar3) {
          pcVar6 = local_res18;
          uVar4 = uVar5;
          if (local_res18 != (char *)0x0) {
            uVar4 = FUN_000124e0(local_res18,0x200);
            lVar2 = local_1058[0];
            uVar4 = uVar4 + 1;
          }
          FUN_0001250c((char *)((longlong)local_1048 + (uVar7 & 0xffffffff)),uVar4 & 0xffffffff,
                       pcVar6);
          uVar7 = (ulonglong)(uint)((int)uVar7 + (int)uVar4);
          *(short *)(param_1 + 0xe0) = sVar8;
          sVar8 = sVar8 + 1;
          *(byte *)(param_1 + 0xc0) = *(byte *)(param_1 + 0xc0) | 0x10;
        }
      }
      if (*(char *)(lVar2 + 7) == '\0') {
        local_res18 = (char *)0x0;
      }
      else {
        lVar3 = FUN_0001598c((char *)((ulonglong)*(byte *)(lVar2 + 1) + lVar2),*(char *)(lVar2 + 7),
                             &local_res18);
        if (-1 < lVar3) {
          pcVar6 = local_res18;
          uVar4 = uVar5;
          if (local_res18 != (char *)0x0) {
            uVar4 = FUN_000124e0(local_res18,0x200);
            uVar4 = uVar4 + 1;
          }
          FUN_0001250c((char *)((longlong)local_1048 + (uVar7 & 0xffffffff)),uVar4 & 0xffffffff,
                       pcVar6);
          *(short *)(param_1 + 0xe8) = sVar8;
          uVar7 = (ulonglong)(uint)((int)uVar7 + (int)uVar4);
          sVar8 = sVar8 + 1;
          *(byte *)(param_1 + 0xc1) = bVar1 | 1;
        }
      }
      if ((*(char *)(lVar2 + 0x19) != '\0') &&
         (lVar2 = FUN_0001598c((char *)((ulonglong)*(byte *)(lVar2 + 1) + lVar2),
                               *(char *)(lVar2 + 0x19),&local_res18), -1 < lVar2)) {
        pcVar6 = local_res18;
        if (local_res18 != (char *)0x0) {
          uVar5 = FUN_000124e0(local_res18,0x200);
          uVar5 = uVar5 + 1;
        }
        FUN_0001250c((char *)((longlong)local_1048 + (uVar7 & 0xffffffff)),uVar5 & 0xffffffff,pcVar6
                    );
        *(byte *)(param_1 + 0xc1) = *(byte *)(param_1 + 0xc1) | 4;
        *(short *)(param_1 + 0xec) = sVar8;
      }
      FUN_00015ebc(param_1,(int *)(param_1 + 0xcc),local_1048);
    }
  }
  return;
}

