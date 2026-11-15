
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

int FUN_1800038a0(undefined8 *param_1,undefined8 *param_2,uint *param_3,LPCSTR param_4)

{
  int iVar1;
  ushort uVar2;
  uint uVar3;
  undefined8 uVar4;
  undefined8 *puVar5;
  void *pvVar6;
  longlong lVar7;
  char cVar8;
  int iVar9;
  uint uVar10;
  undefined1 uVar11;
  byte bVar12;
  uint uVar13;
  byte bVar14;
  undefined1 auStackY_a98 [32];
  uint local_a68 [2];
  uint *local_a60;
  undefined1 local_a58 [24];
  undefined2 local_a40;
  undefined2 local_a3e;
  undefined4 local_a3c;
  undefined1 local_a34;
  undefined1 local_a18;
  undefined1 local_858 [24];
  byte local_840;
  byte local_83e;
  ulonglong local_58;
  
  local_58 = DAT_1800181d0 ^ (ulonglong)auStackY_a98;
  *param_2 = *param_1;
  param_2[1] = param_1[1];
  param_2[2] = param_1[2];
  param_2[3] = param_1[3];
  uVar10 = 0;
  uVar3 = 0;
  param_2[4] = param_1[4];
  local_a68[0] = 0;
  param_2[5] = param_1[5];
  param_2[6] = param_1[6];
  *(undefined4 *)(param_2 + 7) = *(undefined4 *)(param_1 + 7);
  *(undefined2 *)((longlong)param_2 + 0x3c) = *(undefined2 *)((longlong)param_1 + 0x3c);
  uVar11 = 0;
  local_a60 = param_3;
  if (param_4[0x121] == '\0') {
    FUN_180004400("ExecuteSCSICmd called before using OpenDevice\n",param_2,param_3,param_4);
    iVar9 = -5;
    goto LAB_180003e72;
  }
  if (param_4[0x120] == '\x01') {
    iVar9 = -3;
    param_4[0x120] = '\0';
    goto LAB_180003e72;
  }
  if (param_4[0x123] == '\x01') {
    if (*(int *)(param_4 + 0x110) < 1) {
LAB_180003975:
      uVar4 = FUN_180003270(param_4);
      iVar9 = (int)uVar4;
      if (iVar9 != 0) goto LAB_180003e72;
    }
  }
  else if (*(longlong *)(param_4 + 0x108) == 0) goto LAB_180003975;
  cVar8 = *(char *)((longlong)param_1 + 0x29);
  uVar10 = uVar3;
  switch(cVar8) {
  case '\0':
    uVar4 = thunk_FUN_1800034e0((longlong)param_4);
    iVar9 = (int)uVar4;
    break;
  default:
    goto switchD_1800039bb_caseD_1;
  case '\x04':
  case '\x1b':
  case '\x1e':
    iVar9 = 0;
    break;
  case '\x1a':
    uVar4 = FUN_1800034e0((longlong)param_4);
    if ((int)uVar4 == 0) {
      *(undefined4 *)((longlong)param_2 + 0x3d) = 0;
      *(undefined1 *)((longlong)param_2 + 0x3d) = 3;
      cVar8 = param_4[0x122];
      *(undefined1 *)((longlong)param_2 + 0x3e) = 0;
      if (cVar8 == '\x01') {
        uVar11 = 0x80;
      }
      *(undefined1 *)((longlong)param_2 + 0x3f) = uVar11;
      iVar9 = 0;
      uVar10 = 4;
      break;
    }
    goto switchD_1800039bb_caseD_1;
  case '#':
    *(undefined1 *)(param_2 + 8) = 8;
    uVar4 = FUN_1800034e0((longlong)param_4);
    iVar9 = (int)uVar4;
    if (iVar9 == 0) {
      *(uint *)((longlong)param_2 + 0x45) = *(uint *)(param_4 + 0x118) | 0x2000000;
      *(undefined4 *)((longlong)param_2 + 0x41) = *(undefined4 *)(param_4 + 0x11c);
    }
    else {
      *(undefined4 *)((longlong)param_2 + 0x45) = 0x3000200;
      *(undefined4 *)((longlong)param_2 + 0x41) = 0xb40;
    }
    if (*(int *)(param_4 + 0x114) == 0) {
      uVar10 = *(uint *)((longlong)param_2 + 0x45);
      uVar3 = *(uint *)((longlong)param_2 + 0x41);
      *(uint *)((longlong)param_2 + 0x45) =
           (uVar10 & 0xff0000 | uVar10 >> 0x10) >> 8 | (uVar10 << 0x10 | uVar10 & 0xff00) << 8;
      *(uint *)((longlong)param_2 + 0x41) =
           (uVar3 & 0xff0000 | uVar3 >> 0x10) >> 8 | (uVar3 << 0x10 | uVar3 & 0xff00) << 8;
    }
    uVar10 = 0xc;
    break;
  case '%':
    uVar4 = FUN_1800034e0((longlong)param_4);
    iVar9 = (int)uVar4;
    if (iVar9 == 0) {
      if (*(int *)(param_4 + 0x114) == 0) {
        uVar10 = *(uint *)(param_4 + 0x118);
        *(uint *)((longlong)param_2 + 0x41) =
             (uVar10 & 0xff0000 | uVar10 >> 0x10) >> 8 | (uVar10 << 0x10 | uVar10 & 0xff00) << 8;
        uVar10 = *(int *)(param_4 + 0x11c) - 1;
        *(uint *)((longlong)param_2 + 0x3d) =
             (uVar10 & 0xff0000 | uVar10 >> 0x10) >> 8 | (uVar10 * 0x10000 | uVar10 & 0xff00) << 8;
        uVar10 = 8;
      }
      else {
        *(undefined4 *)((longlong)param_2 + 0x41) = *(undefined4 *)(param_4 + 0x118);
        *(int *)((longlong)param_2 + 0x3d) = *(int *)(param_4 + 0x11c) + -1;
        uVar10 = 8;
      }
    }
    break;
  case '(':
  case -0x58:
    uVar3 = FUN_180003190((undefined4 *)((longlong)param_1 + 0x2b));
    puVar5 = param_1 + 6;
    if (cVar8 != '(') {
      puVar5 = (undefined8 *)((longlong)param_1 + 0x2f);
    }
    uVar2 = FUN_180003180((undefined2 *)puVar5);
    uVar13 = (uint)(short)uVar2;
    if (*(int *)(param_4 + 0x114) == 0) {
      uVar3 = (uVar3 & 0xff0000 | uVar3 >> 0x10) >> 8 | (uVar3 & 0xff00 | uVar3 << 0x10) << 8;
      uVar13 = (uint)(ushort)(uVar2 << 8 | uVar2 >> 8);
    }
    if (uVar13 < 0x101) {
      pvVar6 = (void *)((longlong)param_2 + 0x3d);
      iVar9 = FUN_180003520((longlong)param_4,(ulonglong)uVar3,uVar13,local_a68,pvVar6);
      uVar10 = local_a68[0];
      if (((iVar9 == 0) && (uVar3 == 0)) && (0x3ec0 < *(uint *)(param_4 + 0x11c))) {
        uVar4 = FUN_180003130((longlong)pvVar6);
        if ((int)uVar4 == 0) {
          uVar4 = FUN_180003150((longlong)pvVar6);
          uVar10 = local_a68[0];
          if ((int)uVar4 == 0) break;
          *(undefined1 *)((longlong)param_2 + 0x61) = 0;
        }
        else {
          *(undefined1 *)((longlong)param_2 + 0x7d) = 0;
        }
        *(undefined4 *)((longlong)param_2 + 0x59) = 0;
        *(undefined2 *)((longlong)param_2 + 0x55) = 0x3f;
        *(undefined2 *)((longlong)param_2 + 0x57) = 0xff;
        uVar10 = local_a68[0];
      }
    }
    else {
      iVar9 = -6;
    }
    break;
  case '*':
    uVar4 = FUN_180003390(param_4);
    iVar9 = (int)uVar4;
    if (iVar9 == 0) {
      uVar10 = *(uint *)((longlong)param_1 + 0x2b);
      uVar2 = *(ushort *)(param_1 + 6);
      if (*(int *)(param_4 + 0x114) == 0) {
        uVar10 = (uVar10 & 0xff0000 | uVar10 >> 0x10) >> 8 | (uVar10 & 0xff00 | uVar10 << 0x10) << 8
        ;
        uVar2 = uVar2 << 8 | uVar2 >> 8;
      }
      if (uVar2 < 0x101) {
        if (((uVar10 == 0) &&
            (iVar9 = FUN_180003520((longlong)param_4,0,1,local_a68,local_a58), iVar9 == 0)) &&
           (0x3ec0 < *(uint *)(param_4 + 0x11c))) {
          lVar7 = (longlong)param_2 + 0x3d;
          uVar4 = FUN_180003130(lVar7);
          if ((int)uVar4 == 0) {
            uVar4 = FUN_180003150(lVar7);
            if ((int)uVar4 == 0) goto LAB_180003cd2;
            *(undefined4 *)(lVar7 + 0x1c) = local_a3c;
            *(undefined1 *)(lVar7 + 0x24) = local_a34;
          }
          else {
            *(undefined4 *)(lVar7 + 0x1c) = local_a3c;
            *(undefined1 *)(lVar7 + 0x40) = local_a18;
          }
          *(undefined2 *)(lVar7 + 0x18) = local_a40;
          *(undefined2 *)(lVar7 + 0x1a) = local_a3e;
        }
LAB_180003cd2:
        iVar9 = FUN_180003620((longlong)param_4,(ulonglong)uVar10,(uint)uVar2,
                              (void *)((longlong)param_1 + 0x3d));
        uVar10 = 0;
        break;
      }
      iVar9 = -6;
    }
    uVar10 = 0;
    break;
  case 'Z':
    if ((*(byte *)((longlong)param_1 + 0x2b) & 0x3f) == 5) {
      uVar4 = FUN_1800034e0((longlong)param_4);
      iVar9 = (int)uVar4;
      if (iVar9 == 0) {
        iVar1 = *(int *)(param_4 + 0x118);
        uVar3 = *(uint *)(param_4 + 0x11c);
        iVar9 = FUN_180003520((longlong)param_4,0,1,local_a68,local_858);
        if (iVar9 == 0) {
          if (uVar3 < 0x3ec1) {
            bVar12 = local_83e;
            if (local_83e == 0) {
              bVar12 = 1;
            }
            bVar14 = local_840;
            if (local_840 == 0) {
              bVar14 = 1;
            }
          }
          else {
            bVar12 = 0xff;
            bVar14 = 0x3f;
          }
          FUN_180004f80((ulonglong *)((longlong)param_2 + 0x3d),0,0x50);
          *(undefined2 *)((longlong)param_2 + 0x3d) = 0x2600;
          if ((iVar1 == 0x200) && (uVar3 == 0xb40)) {
            *(undefined1 *)((longlong)param_2 + 0x3f) = 0x94;
          }
          else {
            *(undefined1 *)((longlong)param_2 + 0x3f) = 0;
          }
          *(undefined2 *)((longlong)param_2 + 0x45) = 0x1e05;
          *(byte *)((longlong)param_2 + 0x49) = bVar12;
          *(byte *)((longlong)param_2 + 0x4a) = bVar14;
          if ((iVar1 == 0x200) && (uVar3 == 0xb40)) {
            *(undefined2 *)(param_2 + 0xb) = 0x1e05;
            *(undefined2 *)((longlong)param_2 + 0x47) = 0xf401;
            *(undefined2 *)((longlong)param_2 + 0x61) = 0x2c01;
          }
          else {
            *(undefined2 *)((longlong)param_2 + 0x47) = 0xf0;
          }
          uVar2 = (ushort)(uVar3 / ((uint)bVar14 * (uint)bVar12));
          *(ushort *)((longlong)param_2 + 0x4b) = (ushort)iVar1 << 8 | (ushort)iVar1 >> 8;
          *(ushort *)((longlong)param_2 + 0x4d) = uVar2 << 8 | uVar2 >> 8;
          uVar10 = 0x28;
        }
      }
      break;
    }
switchD_1800039bb_caseD_1:
    iVar9 = -9;
    uVar10 = 0;
  }
LAB_180003e72:
  FUN_1800031b0(iVar9,(longlong)param_2);
  *local_a60 = uVar10;
  FUN_1800031a0((undefined4 *)((longlong)param_2 + 0x39),uVar10);
  return iVar9;
}

