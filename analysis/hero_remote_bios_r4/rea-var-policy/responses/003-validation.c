/* 0x62b8 */

char * FUN_000062b8(ushort *param_1,longlong *param_2,uint param_3,undefined *param_4,char *param_5)

{
  ushort uVar1;
  longlong lVar2;
  undefined8 uVar3;
  char *pcVar4;
  longlong lVar5;
  ushort *puVar6;
  ulonglong uVar7;
  uint uVar8;
  undefined *puVar9;
  
  lVar5 = 0;
  if (param_1 == (ushort *)0x0) {
    return (char *)0x8000000000000002;
  }
  if (*param_1 == 0) {
    return (char *)0x8000000000000002;
  }
  if (param_2 == (longlong *)0x0) {
    return (char *)0x8000000000000002;
  }
  if ((param_3 & 0xffffff80) != 0) {
    return (char *)0x8000000000000002;
  }
  if (((byte)param_3 & 6) == 4) {
    return (char *)0x8000000000000002;
  }
  if ((param_4 != (undefined *)0x0) && (param_5 == (char *)0x0)) {
    return (char *)0x8000000000000002;
  }
  if ((DAT_000130e1 != '\0') && (param_3 != 0)) {
    if ((param_3 & 1) == 0) {
      return (char *)0x8000000000000002;
    }
    if ((param_3 & 4) == 0) {
      return (char *)0x8000000000000002;
    }
  }
  uVar8 = param_3;
  if ((((param_3 & 0x40) != 0) || (param_4 != (undefined *)0x0)) && ((param_3 & 2) != 0)) {
    uVar8 = param_3 & 0xffffffbf;
    uVar7 = (ulonglong)uVar8;
    lVar2 = FUN_0000b1ac(param_2,&DAT_00011010,0x10);
    if (lVar2 == 0) {
      uVar3 = FUN_00004dcc(param_1,uVar8);
      if ((char)uVar3 != '\0') {
        return (char *)0x8000000000000002;
      }
      pcVar4 = FUN_00004ee8((short *)param_1,uVar7,(ulonglong)param_4,param_5);
      if ((longlong)pcVar4 < 0) {
        return pcVar4;
      }
    }
    else {
      lVar2 = FUN_0000b1ac(param_2,(longlong *)&DAT_00011090,0x10);
      if (lVar2 == 0) {
        lVar5 = FUN_00004d5c(&PTR_DAT_00011340,(short *)param_1,uVar8);
        if ((char)lVar5 != '\0') {
          return (char *)0x8000000000000002;
        }
      }
      else if ((param_3 & 8) != 0) {
        lVar2 = FUN_0000b1ac(param_2,(longlong *)&DAT_00011080,0x10);
        puVar6 = param_1;
        if (lVar2 == 0) {
          do {
            puVar6 = puVar6 + 1;
            lVar5 = lVar5 + 1;
          } while (*puVar6 != 0);
          if (((lVar5 == 0xc) &&
              (lVar5 = FUN_0000b1ac((longlong *)param_1,(longlong *)u_HwErrRec_000126a0,0x10),
              lVar5 == 0)) && (puVar6 = param_1 + 8, puVar6 != (ushort *)0x0)) {
            for (; *puVar6 != 0; puVar6 = puVar6 + 1) {
              uVar1 = *puVar6 - 0x30;
              if (0x36 < uVar1) {
                return (char *)0x8000000000000002;
              }
              if ((0x7e0000007e03ffU >> ((ulonglong)uVar1 & 0x3f) & 1) == 0) {
                return (char *)0x8000000000000002;
              }
            }
            goto LAB_00006492;
          }
        }
        return (char *)0x8000000000000002;
      }
    }
  }
LAB_00006492:
  puVar9 = param_4;
  if ((uVar8 & 0x10) != 0) {
    puVar9 = param_4 + (-0x10 - (ulonglong)*(uint *)(param_5 + 0x10));
  }
  pcVar4 = (char *)FUN_0000b91c(param_1,param_2,uVar8,puVar9,
                                param_5 + ((longlong)param_4 - (longlong)puVar9),
                                (DAT_000130e0 != '\0') + 2);
  if ((-1 < (longlong)pcVar4) || (pcVar4 == (char *)0x8000000000000006)) {
    pcVar4 = (char *)0x0;
  }
  return pcVar4;
}


/* 0x1754 */

undefined8 FUN_00001754(undefined *param_1)

{
  longlong lVar1;
  undefined8 uVar2;
  longlong local_res8 [4];
  
  local_res8[0] = 0;
  lVar1 = (*(code *)param_1)(u_Setup_00012060,&DAT_00011330,0,local_res8,0);
  if (lVar1 == -0x7ffffffffffffffb) {
    uVar2 = CONCAT71(0x80000000000000,local_res8[0] == 0xd46);
  }
  else {
    uVar2 = CONCAT71((int7)((ulonglong)lVar1 >> 8),1);
  }
  return uVar2;
}


/* 0xcc6c */

void FUN_0000cc6c(undefined8 param_1)

{
  DAT_00011b38 = 0;
  VariableSetCore((ushort *)u_AuthVarPreBootPhase_00012d20,(longlong *)&DAT_00011b48,6,
                  IMAGE_DOS_HEADER_00000000.e_magic + 1,(longlong *)&DAT_00011b38);
                    /* WARNING: Could not recover jumptable at 0x0000ccb4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(DAT_000131d0 + 0x70))(param_1);
  return;
}


/* 0xc46c */

undefined1 FUN_0000d04c(longlong *param_1,longlong *param_2)

{
  longlong lVar1;
  undefined1 uVar2;
  
  lVar1 = FUN_0000b1ac(param_2,&DAT_00011010,0x10);
  uVar2 = 0;
  if (lVar1 == 0) {
    lVar1 = FUN_0000cf9c(param_1,(longlong *)&DAT_000120b8);
    uVar2 = 0;
    if (lVar1 == 0) {
      uVar2 = 1;
    }
  }
  return uVar2;
}


/* 0x13f0 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_0000117c(longlong *param_1,longlong param_2)

{
  longlong *plVar1;
  longlong *plVar2;
  undefined8 *puVar3;
  byte bVar4;
  char cVar5;
  undefined1 uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  longlong lVar10;
  ulonglong uVar11;
  byte *pbVar12;
  longlong *plVar13;
  undefined8 local_res8;
  longlong local_res10;
  ulonglong local_res18;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  
  DAT_00013168 = *(longlong *)(param_2 + 0x58);
  DAT_00013160 = *(longlong *)(param_2 + 0x60);
  DAT_00013158 = param_2;
  DAT_00013170 = DAT_00013168;
  DAT_00013188 = DAT_00013160;
  local_res8 = param_1;
  (**(code **)(DAT_00013160 + 0x50))(0x201,8,&LAB_0000a90c,0,&DAT_00013178);
  (**(code **)(DAT_00013188 + 0x50))(0x60000202,8,FUN_0000a918,0,&DAT_00013180);
  FUN_0000a9a0();
  lVar10 = FUN_0000a9d0((longlong *)&DAT_00011910);
  plVar13 = (longlong *)0x0;
  if (lVar10 == 0) {
    uVar11 = FUN_000010a0();
    FUN_00001090();
    uVar7 = in(0x1808);
    FUN_00001070();
    while (iVar8 = in(0x1808), (((uVar7 & 0xffffff) + 0x16b) - iVar8 >> 0x17 & 1) == 0) {
      FUN_00001060();
    }
    FUN_00001070();
    if ((uVar11 >> 9 & 1) == 0) {
      FUN_00001090();
    }
    else {
      FUN_00001080();
    }
  }
  _DAT_000133d0 = DAT_00013168;
  (**(code **)(DAT_00013160 + 0x50))(0x60000202,0x10,&LAB_0000aa20,0,&DAT_000133c8);
  (**(code **)(DAT_00013160 + 0x50))(0x201,0x10,&DAT_0000aa1c,0,&DAT_000133d8);
  FUN_0000aa34();
  (**(code **)(DAT_00013160 + 0x170))(0x200,0x10,&LAB_0000aa94,0,&DAT_00011270,&DAT_000133b8);
  (**(code **)(DAT_00013160 + 0x170))(0x200,0x10,&LAB_0000aabc,0,&DAT_00011220,&DAT_000133c0);
  DAT_000131c0 = 0x10000;
  if (DAT_000131b0 == (longlong *)0x0) {
    lVar10 = (**(code **)(DAT_00013160 + 0x40))(6,0x10000,&local_res8);
    DAT_000131b0 = local_res8;
    if (lVar10 < 0) {
      DAT_000131b0 = plVar13;
    }
    local_res8 = DAT_000131b0;
    if (DAT_000131b0 == (longlong *)0x0) goto LAB_000013c3;
  }
  uVar11 = DAT_000131c0;
  plVar2 = DAT_000131b0;
  if (0x37 < DAT_000131c0) {
    plVar1 = DAT_000131b0 + 5;
    DAT_000131b0[2] = 0;
    *plVar2 = (longlong)plVar1;
    plVar2[4] = (longlong)plVar1;
    plVar2[1] = uVar11 - 0x28;
    plVar2[3] = (longlong)plVar2 + (uVar11 - 0x10);
  }
LAB_000013c3:
  (**(code **)(DAT_00013168 + 0x18))(&local_38,0);
  FUN_00001000((undefined8 *)&DAT_00011920,(undefined8 *)&local_38,0x10);
  (**(code **)(DAT_00013160 + 0x50))(0x60000202,8,FUN_0000aad4,0,&DAT_000131b8);
  lVar10 = (**(code **)(DAT_00013160 + 0x140))(&DAT_00011260,0,&DAT_00013250);
  if (((lVar10 < 0) || ((*(code *)*DAT_00013250)(DAT_00013250,&DAT_00013240), DAT_00013240 == '\0'))
     || (lVar10 = (*(code *)DAT_00013250[1])(DAT_00013250,&DAT_00013330), lVar10 < 0)) {
    (**(code **)(DAT_00013160 + 0x50))(0x201,8,&LAB_0000b4b0,0,&DAT_00013238);
    (**(code **)(DAT_00013160 + 0x50))(0x60000202,8,&LAB_0000b4cc,0,&DAT_00013228);
  }
  else {
    local_res10 = 0;
    (**(code **)(DAT_00013330 + 0xc0))(&DAT_00011100,&LAB_0000b494,&local_res10);
  }
  FUN_0000a940((longlong *)&DAT_00011290,&DAT_00013258);
  puVar3 = DAT_000133a0;
  (**(code **)(DAT_00013160 + 0x50))(0x200,0x10,FUN_0000c848,0,&local_res18);
  local_res8 = &local_res8;
  if (puVar3 != (undefined8 *)0x0) {
    local_res8 = puVar3;
  }
  (**(code **)(DAT_00013160 + 0xa8))(&DAT_000110a0,local_res18);
  local_res10 = 0;
  lVar10 = FUN_0000ae60(DAT_00013158);
  iVar8 = *(int *)(lVar10 + 0xc);
  lVar10 = FUN_0000eae4();
  iVar9 = (**(code **)(lVar10 + 0x18))(0x229);
  if (iVar9 == 1) {
    out(0x70,0xe);
    bVar4 = in(0x71);
    bVar4 = bVar4 & 0xc0;
  }
  else {
    lVar10 = FUN_0000eae4();
    iVar9 = (**(code **)(lVar10 + 0x18))(0x229);
    if (iVar9 != 2) {
      return;
    }
    lVar10 = FUN_0000eae4();
    cVar5 = (**(code **)(lVar10 + 0x30))(0x22b);
    if (cVar5 == '\0') {
      return;
    }
    local_38 = 0xc89dc9c7;
    local_34 = 0x472c5105;
    local_30 = 0x62b143a7;
    local_2c = 0x412b141e;
    local_res18 = 2;
    lVar10 = FUN_0000618c((ushort *)u_CMOSfailflag_00012eb0,(longlong *)&local_38,(uint *)0x0,
                          &local_res18,&local_res8);
    bVar4 = 0;
    if (-1 < lVar10) {
      bVar4 = 0;
      if (local_res8._1_1_ == '\x01') {
        bVar4 = 1;
      }
    }
    lVar10 = FUN_0000eae4();
    uVar6 = (**(code **)(lVar10 + 0x18))(0x222);
    out(0x72,uVar6);
    cVar5 = in(0x73);
    if (cVar5 == 'U') {
      bVar4 = 1;
    }
  }
  if ((bVar4 != 0) && (iVar8 == 4)) {
    (**(code **)(DAT_00013160 + 0x140))(&DAT_000111e0,0,&local_res10);
    pbVar12 = &DAT_00011b64;
    do {
      if (*(longlong *)(pbVar12 + 0x14) == 0) {
        return;
      }
      if ((*pbVar12 & 1) != 0) {
        (**(code **)(local_res10 + 0x18))(pbVar12 + -4);
      }
      plVar13 = plVar13 + 6;
      pbVar12 = pbVar12 + 0x30;
    } while (plVar13 < (longlong *)0x420);
  }
  return;
}

