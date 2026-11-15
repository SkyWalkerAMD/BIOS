
/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_000b4e5c(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  longlong *plVar4;
  undefined8 *puVar5;
  longlong *plVar6;
  longlong *plVar7;
  undefined8 *puVar8;
  longlong lVar9;
  longlong lVar10;
  ulonglong *puVar11;
  char *pcVar12;
  ulonglong in_RCX;
  undefined *puVar13;
  undefined4 *puVar14;
  wchar_t *pwVar15;
  ulonglong *puVar16;
  undefined8 uVar17;
  word *pwVar18;
  ulonglong uVar19;
  longlong *plVar20;
  ulonglong local_res8;
  longlong local_res10 [2];
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  word local_58 [8];
  undefined **local_48;
  undefined4 local_40;
  
  plVar20 = (longlong *)0x0;
  local_68 = 0x8a91b1e1;
  local_res10[0] = 0;
  local_res8 = in_RCX & 0xffffffffffffff00;
  local_64 = 0x4adc56c7;
  local_60 = 0x2c1cebab;
  local_5c = 0xff9e72a1;
  local_58[0] = 0x9704;
  local_58[1] = 0x9656;
  local_58[2] = 0xfcf8;
  local_58[3] = 0x4d11;
  local_58[4] = 0x7299;
  local_58[5] = 0xc095;
  local_58[6] = 0xffe1;
  local_58[7] = 0xb765;
  plVar4 = FUN_000f2f58();
  uVar2 = DAT_001807b4;
  uVar1 = DAT_001807b0;
  puVar5 = (undefined8 *)FUN_00051024(0x198);
  plVar6 = plVar20;
  if (puVar5 != (undefined8 *)0x0) {
    plVar6 = FUN_00080ea8(puVar5,(longlong *)0x0);
  }
  plVar4[4] = (longlong)plVar6;
  (**(code **)(*plVar6 + 0x318))(plVar6,uVar1);
  (**(code **)(*(longlong *)plVar4[4] + 0x328))((longlong *)plVar4[4],uVar2);
  (**(code **)(*(longlong *)plVar4[4] + 0x528))((longlong *)plVar4[4],0);
  *(uint *)(plVar4 + 7) = uVar1;
  *(uint *)((longlong)plVar4 + 0x3c) = uVar2;
  puVar5 = (undefined8 *)FUN_00051024(0x198);
  plVar6 = plVar20;
  if (puVar5 != (undefined8 *)0x0) {
    plVar6 = FUN_00080ea8(puVar5,(longlong *)plVar4[4]);
  }
  plVar4[2] = (longlong)plVar6;
  (**(code **)(*plVar6 + 0x318))(plVar6,(int)plVar4[7]);
  (**(code **)(*(longlong *)plVar4[2] + 0x328))
            ((longlong *)plVar4[2],*(undefined4 *)((longlong)plVar4 + 0x3c));
  plVar6 = (longlong *)plVar4[4];
  puVar5 = (undefined8 *)FUN_00051024(0x30);
  plVar7 = plVar20;
  if (puVar5 != (undefined8 *)0x0) {
    plVar7 = FUN_0007f8d8(puVar5,plVar6);
  }
  plVar6 = plVar7 + 3;
  *(int *)plVar6 = (int)*plVar6 + -1;
  if ((int)*plVar6 == 0) {
    (**(code **)(*plVar7 + 0x120))(plVar7,1);
  }
  plVar4[6] = (longlong)plVar7;
  plVar6 = (longlong *)plVar4[4];
  puVar5 = (undefined8 *)FUN_00051024(0x20);
  plVar7 = plVar20;
  if (puVar5 != (undefined8 *)0x0) {
    plVar7 = FUN_000f37b8(puVar5,plVar6);
  }
  plVar6 = plVar7 + 3;
  *(int *)plVar6 = (int)*plVar6 + -1;
  if ((int)*plVar6 == 0) {
    (**(code **)(*plVar7 + 0x120))(plVar7,1);
  }
  plVar4[5] = (longlong)plVar7;
  (**(code **)(*(longlong *)plVar4[2] + 0x48))((longlong *)plVar4[2],plVar4);
  plVar6 = (longlong *)plVar4[4];
  puVar5 = FUN_0007f350();
  puVar5[3] = plVar6;
  puVar8 = (undefined8 *)(**(code **)(*plVar6 + 0xe8))(plVar6,&local_48);
  uVar17 = puVar8[1];
  *(undefined8 *)((longlong)puVar5 + 0x484) = *puVar8;
  *(undefined8 *)((longlong)puVar5 + 0x48c) = uVar17;
  puVar8 = FUN_0007f350();
  plVar6 = (longlong *)puVar8[3];
  puVar5 = puVar8 + 7;
  uVar1 = (**(code **)(*plVar6 + 800))();
  uVar2 = (**(code **)(*plVar6 + 0x310))(plVar6);
  FUN_00090d58(puVar5,6,uVar2,uVar1,0);
  local_40 = 1;
  local_48 = &PTR_FUN_00174878;
  FUN_00091110(&local_48,puVar5,0);
  FUN_0008e058((longlong)(puVar8 + 0x10),puVar5);
  lVar9 = FUN_0007e810();
  iVar3 = FUN_0007ea30(lVar9,puVar8,1,0);
  *(int *)((longlong)puVar8 + 0xc) = iVar3;
  lVar9 = FUN_0007e810();
  iVar3 = FUN_0007ea30(lVar9,puVar8,2,1);
  *(int *)(puVar8 + 2) = iVar3;
  uVar17 = *(undefined8 *)(plVar4[6] + 0x10);
  puVar5 = FUN_0007f350();
  puVar5[5] = uVar17;
  uVar17 = *(undefined8 *)(plVar4[5] + 0x10);
  puVar5 = FUN_0007f350();
  puVar5[4] = uVar17;
  puVar5 = FUN_0007f350();
  (**(code **)(*(longlong *)puVar5[4] + 0x2f8))((longlong *)puVar5[4],DAT_001807b0 >> 1);
  puVar5 = FUN_0007f350();
  (**(code **)(*(longlong *)puVar5[4] + 0x308))((longlong *)puVar5[4],DAT_001807b4 >> 1);
  lVar9 = plVar4[2];
  lVar10 = FUN_00086ad8();
  plVar6 = *(longlong **)(lVar10 + 0x18);
  puVar5 = (undefined8 *)((longlong)(int)plVar6[1] + *plVar6);
  *puVar5 = *(undefined8 *)(lVar10 + 0x20);
  *(int *)(plVar6 + 1) = (int)plVar6[1] + 8;
  *(longlong *)(lVar10 + 0x20) = lVar9;
  FUN_00059fd8(puVar5);
  plVar6 = DAT_001908a8;
  FUN_000ba230(DAT_001908a8);
  FUN_000ba1d8(plVar6,'\x01');
  FUN_000590b4((ulonglong)plVar6);
  plVar6 = DAT_001803d0;
  FUN_000ba230(DAT_001803d0);
  FUN_000ba1d8(plVar6,'\x01');
  FUN_0005a574();
  plVar6 = DAT_001908f8;
  FUN_000ba230(DAT_001908f8);
  FUN_000ba1d8(plVar6,'\x01');
  FUN_000dd524((ulonglong)plVar6);
  plVar6 = DAT_00182720;
  FUN_000ba230(DAT_00182720);
  FUN_000ba1d8(plVar6,'\x01');
  FUN_00059cc8();
  plVar6 = DAT_00190898;
  FUN_000ba230(DAT_00190898);
  FUN_000ba1d8(plVar6,'\x01');
  FUN_000579d8(plVar6);
  plVar6 = DAT_00190860;
  FUN_000ba230(DAT_00190860);
  FUN_000ba1d8(plVar6,'\x01');
  FUN_00058a3c((ulonglong)plVar6);
  plVar6 = DAT_001803c0;
  FUN_000ba230(DAT_001803c0);
  FUN_000ba1d8(plVar6,'\x01');
  _DAT_00119e70 = FUN_000b1010(plVar6,0x50);
  puVar13 = &DAT_00119e70;
  *_DAT_00119e70 = 0x1001;
  _DAT_00119e70[2] = 0;
  _DAT_00119e88 = 0;
  _DAT_00119e90 = 0;
  FUN_0006da0c(0x119e70,(int *)&DAT_00119ed0);
  FUN_000b46f8(puVar13);
  plVar6 = local_res10;
  uVar17 = 0;
  puVar14 = &local_68;
  lVar9 = (**(code **)(DAT_00180188 + 0x140))();
  if (lVar9 == 0) {
    *(code **)(local_res10[0] + 0x68) = FUN_00058280;
    *(code **)(local_res10[0] + 0x20) = FUN_00058564;
    *(code **)(local_res10[0] + 0x40) = FUN_000103ac;
    *(code **)(local_res10[0] + 0x48) = FUN_000103ac;
    puVar14 = (undefined4 *)&LAB_000589f0;
    *(undefined1 **)(local_res10[0] + 0x78) = &LAB_000589f0;
  }
  if (DAT_001801a0 == 6) {
    DAT_001801c9 = 0;
    FUN_000b563c();
    DAT_001801c9 = 1;
  }
  DAT_001801a0 = 5;
  lVar9 = FUN_0000ff9c();
  if ((*(int *)(lVar9 + 0xc) == 0x12) || (lVar9 = FUN_0000ff9c(), *(int *)(lVar9 + 0xc) == 0x20)) {
    FUN_0005af88(puVar14,uVar17,(ulonglong)plVar6);
  }
  else {
    FUN_0006c610();
  }
  local_res10[1] = 1;
  pwVar18 = local_58;
  uVar19 = 0;
  pwVar15 = u_EnterEzUpdate_0016d8c0;
  lVar9 = (**(code **)(*(longlong *)(DAT_00180180 + 0x58) + 0x48))
                    (u_EnterEzUpdate_0016d8c0,pwVar18,0,local_res10 + 1,&local_res8);
  if ((char)local_res8 == '\x01') {
    FUN_0005af88(pwVar15,pwVar18,uVar19);
  }
  puVar11 = (ulonglong *)FUN_0007e810();
  *(char *)puVar11 = '\0';
  do {
    if (*(char *)((longlong)puVar11 + 0x44) == '\0') {
      puVar5 = (undefined8 *)FUN_00051024(0x1d8);
      plVar6 = plVar20;
      if (puVar5 != (undefined8 *)0x0) {
        uVar19 = 200;
        pwVar18 = (word *)(IMAGE_DOS_HEADER_00000000.e_program + 0x88);
        plVar6 = FUN_00087628(puVar5,200,200);
      }
      if (plVar6 != (longlong *)0x0) {
        if (plVar6[0x39] != 0) {
          _DAT_00190bd8 = _DAT_00190bd8 - *(int *)((longlong)plVar6 + 0x1d4) * (int)plVar6[0x3a] * 4
          ;
          (**(code **)(DAT_00180188 + 0x48))();
        }
        FUN_00091048(plVar6 + 0x30);
        FUN_0008dd4c(plVar6);
        (**(code **)(DAT_00180188 + 0x48))(plVar6);
      }
    }
    else {
      pwVar18 = (word *)(IMAGE_DOS_HEADER_00000000.e_magic + 1);
      *(char *)((longlong)puVar11 + 0x44) = '\0';
      FUN_0007f144((longlong)puVar11,1);
    }
    if (*(char *)((longlong)puVar11 + 0x45) != '\0') {
      pwVar18 = &IMAGE_DOS_HEADER_00000000.e_cblp;
      *(char *)((longlong)puVar11 + 0x45) = '\0';
      FUN_0007f144((longlong)puVar11,2);
    }
    if (*(char *)((longlong)puVar11 + 0x46) != '\0') {
      pwVar18 = (word *)((longlong)&IMAGE_DOS_HEADER_00000000.e_cblp + 1);
      *(char *)((longlong)puVar11 + 0x46) = '\0';
      FUN_0007f144((longlong)puVar11,3);
    }
    FUN_0007eba4((longlong)puVar11);
    FUN_0007ec6c((longlong)puVar11);
    puVar16 = puVar11;
    FUN_0007ecd0((longlong)puVar11);
    if (DAT_00190c98._1_1_ != '\0') {
      puVar16 = DAT_00180758;
      pwVar18 = DAT_00190aa0;
      FUN_000ba458(DAT_00180758,(longlong)DAT_00190aa0);
      DAT_00190c98._1_1_ = '\0';
    }
    if ((DAT_00190640 == '\0') || (DAT_0018f1d9 == '\0')) {
      FUN_000392c8(puVar16,pwVar18,uVar19);
    }
    pcVar12 = (char *)FUN_0007fdb8();
    FUN_0007fde8(pcVar12);
    lVar10 = FUN_0007e810();
    if (*(longlong *)(lVar10 + 0x348) != 0) {
      lVar10 = FUN_0007e810();
      (**(code **)(*(longlong *)(*(longlong *)(lVar10 + 0x348) + 8) + 0xa0))();
    }
  } while ((char)*puVar11 == '\0');
  if (lVar9 == 0) {
    *(code **)(local_res10[0] + 0x68) = FUN_00007050;
    *(code **)(local_res10[0] + 0x20) = FUN_000064ec;
    *(undefined1 **)(local_res10[0] + 0x40) = &LAB_000062c4;
    *(code **)(local_res10[0] + 0x48) = FUN_0000643c;
    *(undefined **)(local_res10[0] + 0x78) = &DAT_00006edc;
  }
  return;
}

