
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */
/* WARNING: Type propagation algorithm not settling */

int FUN_1800028f0(longlong *param_1,undefined8 *param_2,undefined8 *param_3,undefined4 *param_4)

{
  uint uVar1;
  ushort uVar2;
  int iVar3;
  undefined8 uVar4;
  uint uVar5;
  int *piVar6;
  uint *puVar7;
  byte bVar8;
  byte bVar9;
  undefined1 auStack_8a8 [32];
  undefined1 *local_888;
  undefined4 local_878;
  int local_874;
  uint local_870 [2];
  undefined4 *local_868;
  undefined1 local_858 [24];
  byte local_840;
  byte local_83e;
  ulonglong local_58;
  
  local_58 = DAT_1800181d0 ^ (ulonglong)auStack_8a8;
  *param_3 = *param_2;
  iVar3 = 0;
  param_3[1] = param_2[1];
  param_3[2] = param_2[2];
  param_3[3] = param_2[3];
  param_3[4] = param_2[4];
  local_878 = 0;
  param_3[5] = param_2[5];
  param_3[6] = param_2[6];
  *(undefined4 *)(param_3 + 7) = *(undefined4 *)(param_2 + 7);
  *(undefined2 *)((longlong)param_3 + 0x3c) = *(undefined2 *)((longlong)param_2 + 0x3c);
  local_868 = param_4;
  if ((char)param_1[3] == '\0') {
    FUN_180004400("ExecuteSCSICmd called before using OpenDevice\n",param_2,param_3,param_4);
    iVar3 = -5;
  }
  else if (*(char *)((longlong)param_1 + 0x24) != '\0') {
    iVar3 = -3;
    *(undefined1 *)((longlong)param_1 + 0x24) = 0;
  }
  if (DAT_1800195e0 != '\0') {
    iVar3 = -3;
    DAT_1800195e0 = '\0';
    goto LAB_180002e4e;
  }
  if (iVar3 != 0) goto LAB_180002e4e;
  switch(*(char *)((longlong)param_2 + 0x29)) {
  case '\0':
    iVar3 = (**(code **)(*param_1 + 0x38))(param_1);
    break;
  default:
switchD_1800029fa_caseD_1:
    iVar3 = -9;
    break;
  case '\x04':
  case '\x1b':
  case '\x1e':
    iVar3 = 0;
    break;
  case '\x1a':
    puVar7 = local_870;
    piVar6 = &local_874;
    local_874 = 0;
    local_870[0] = 0;
    local_878 = 0;
    iVar3 = (**(code **)(*param_1 + 0x40))(param_1);
    if (iVar3 != 0) goto switchD_1800029fa_caseD_1;
    *(undefined4 *)((longlong)param_3 + 0x3d) = 0;
    *(undefined1 *)((longlong)param_3 + 0x3d) = 3;
    uVar4 = FUN_1800026e0((longlong)param_1);
    if ((int)uVar4 == -0xd) {
      *(undefined1 *)((longlong)param_3 + 0x3f) = 0x80;
    }
    else {
      *(undefined1 *)((longlong)param_3 + 0x3f) = 0;
    }
    if ((char)param_1[0x1e] == '\0') {
      *(undefined1 *)((longlong)param_3 + 0x3f) = 0x80;
      FUN_180004400("SETTING WRITE PROTECT DEVICE\n",piVar6,puVar7,param_4);
    }
    iVar3 = 0;
    if ((local_874 == 0x200) && (local_870[0] == 0xb40)) {
      *(undefined1 *)((longlong)param_3 + 0x3e) = 0x94;
      local_878 = 4;
    }
    else {
      *(undefined1 *)((longlong)param_3 + 0x3e) = 0;
      local_878 = 4;
    }
    break;
  case '#':
    *(undefined1 *)(param_3 + 8) = 8;
    iVar3 = (**(code **)(*param_1 + 0x40))
                      (param_1,(longlong)param_3 + 0x45,(longlong)param_3 + 0x41);
    if (iVar3 == -3) {
      DAT_1800195e0 = '\x01';
LAB_180002a3f:
      *(undefined4 *)((longlong)param_3 + 0x45) = 0x3000200;
      *(undefined4 *)((longlong)param_3 + 0x41) = 0xb40;
    }
    else {
      if (iVar3 != 0) goto LAB_180002a3f;
      *(uint *)((longlong)param_3 + 0x45) = *(uint *)((longlong)param_3 + 0x45) | 0x2000000;
    }
    iVar3 = 0;
    uVar1 = *(uint *)((longlong)param_3 + 0x45);
    local_878 = 0xc;
    uVar5 = *(uint *)((longlong)param_3 + 0x41);
    *(uint *)((longlong)param_3 + 0x45) =
         (uVar1 & 0xff0000 | uVar1 >> 0x10) >> 8 | (uVar1 << 0x10 | uVar1 & 0xff00) << 8;
    *(uint *)((longlong)param_3 + 0x41) =
         (uVar5 & 0xff0000 | uVar5 >> 0x10) >> 8 | (uVar5 << 0x10 | uVar5 & 0xff00) << 8;
    break;
  case '%':
    iVar3 = (**(code **)(*param_1 + 0x40))
                      (param_1,(longlong)param_3 + 0x41,(longlong)param_3 + 0x3d);
    if (iVar3 == 0) {
      uVar1 = *(uint *)((longlong)param_3 + 0x41);
      local_878 = 8;
      uVar5 = *(int *)((longlong)param_3 + 0x3d) - 1;
      *(uint *)((longlong)param_3 + 0x41) =
           (uVar1 & 0xff0000 | uVar1 >> 0x10) >> 8 | (uVar1 << 0x10 | uVar1 & 0xff00) << 8;
      *(uint *)((longlong)param_3 + 0x3d) =
           (uVar5 & 0xff0000 | uVar5 >> 0x10) >> 8 | (uVar5 * 0x10000 | uVar5 & 0xff00) << 8;
    }
    else {
      local_878 = 0;
    }
    break;
  case '(':
  case -0x58:
    uVar1 = *(uint *)((longlong)param_2 + 0x2b);
    if (*(char *)((longlong)param_2 + 0x29) == '(') {
      uVar2 = *(ushort *)(param_2 + 6);
    }
    else {
      uVar2 = (ushort)*(undefined4 *)((longlong)param_2 + 0x2f);
    }
    uVar2 = uVar2 << 8 | uVar2 >> 8;
    if (uVar2 < 0x101) {
      local_888 = (undefined1 *)((longlong)param_3 + 0x3d);
      iVar3 = (**(code **)(*param_1 + 0x48))
                        (param_1,(uVar1 & 0xff0000 | uVar1 >> 0x10) >> 8 |
                                 (uVar1 & 0xff00 | uVar1 << 0x10) << 8,uVar2,&local_878);
    }
    else {
LAB_180002c20:
      iVar3 = -6;
    }
    break;
  case '*':
    uVar1 = *(uint *)((longlong)param_2 + 0x2b);
    uVar2 = *(ushort *)(param_2 + 6) << 8 | *(ushort *)(param_2 + 6) >> 8;
    if (0x100 < uVar2) goto LAB_180002c20;
    iVar3 = (**(code **)(*param_1 + 0x50))
                      (param_1,(uVar1 & 0xff0000 | uVar1 >> 0x10) >> 8 |
                               (uVar1 & 0xff00 | uVar1 << 0x10) << 8,uVar2,(longlong)param_2 + 0x3d)
    ;
    break;
  case '/':
    break;
  case 'Z':
    local_878 = 0;
    if ((*(byte *)((longlong)param_2 + 0x2b) & 0x3f) != 5) goto switchD_1800029fa_caseD_1;
    local_874 = 0;
    local_870[0] = 0;
    FUN_180004f80((ulonglong *)((longlong)param_3 + 0x3d),0,0x50);
    iVar3 = (**(code **)(*param_1 + 0x40))(param_1,&local_874,local_870);
    if (iVar3 == 0) {
      local_888 = local_858;
      local_870[1] = 0;
      iVar3 = (**(code **)(*param_1 + 0x48))(param_1,0,1,local_870 + 1);
      uVar1 = local_870[0];
      if (iVar3 == 0) {
        if (local_870[0] < 0x3ec1) {
          bVar8 = local_840;
          if (local_840 == 0) {
            bVar8 = 1;
          }
          bVar9 = local_83e;
          if (local_83e == 0) {
            bVar9 = 1;
          }
        }
        else {
          bVar8 = 0x3f;
          bVar9 = 0xff;
        }
        FUN_180004f80((ulonglong *)((longlong)param_3 + 0x3d),0,0x50);
        *(undefined2 *)((longlong)param_3 + 0x3d) = 0x2600;
        if ((local_874 == 0x200) && (uVar1 == 0xb40)) {
          *(undefined1 *)((longlong)param_3 + 0x3f) = 0x94;
        }
        else {
          *(undefined1 *)((longlong)param_3 + 0x3f) = 0;
        }
        *(undefined2 *)((longlong)param_3 + 0x45) = 0x1e05;
        *(byte *)((longlong)param_3 + 0x49) = bVar9;
        *(byte *)((longlong)param_3 + 0x4a) = bVar8;
        if ((local_874 == 0x200) && (uVar1 == 0xb40)) {
          *(undefined2 *)(param_3 + 0xb) = 0x1e05;
          *(undefined2 *)((longlong)param_3 + 0x47) = 0xf401;
          *(undefined2 *)((longlong)param_3 + 0x61) = 0x2c01;
        }
        else {
          *(undefined2 *)((longlong)param_3 + 0x47) = 0xf0;
        }
        local_878 = 0x28;
        uVar2 = (ushort)(uVar1 / ((uint)bVar8 * (uint)bVar9));
        *(ushort *)((longlong)param_3 + 0x4b) = (ushort)local_874 << 8 | (ushort)local_874 >> 8;
        *(ushort *)((longlong)param_3 + 0x4d) = uVar2 << 8 | uVar2 >> 8;
      }
    }
  }
LAB_180002e4e:
  (**(code **)(*param_1 + 0x58))(param_1,iVar3,param_3);
  *(undefined4 *)((longlong)param_3 + 0x39) = local_878;
  *local_868 = local_878;
  return iVar3;
}

