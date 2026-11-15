
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void Candidate_ACE1904_core_initialization_body(short *param_1)

{
  undefined8 uVar1;
  uint uVar2;
  int iVar3;
  short *psVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  int *piVar7;
  longlong lVar8;
  int *piVar9;
  short *psVar10;
  ulonglong uVar11;
  undefined *puVar12;
  undefined8 *puVar13;
  longlong *plVar14;
  undefined **ppuVar15;
  uint *puVar16;
  code *pcVar17;
  code *pcVar18;
  undefined4 uVar19;
  short *local_res8;
  undefined8 *local_res10;
  longlong local_res18;
  undefined *local_res20;
  ushort local_138;
  longlong local_136;
  ulonglong local_128;
  longlong local_120;
  longlong local_118;
  undefined8 local_110;
  undefined8 local_108;
  undefined8 local_100;
  undefined8 local_f8;
  longlong local_f0 [3];
  int *local_d8 [4];
  code *local_b8;
  undefined *local_b0;
  int *local_88;
  ulonglong local_80;
  
  local_res8 = param_1;
  psVar4 = FUN_00010be0((longlong *)&DAT_00015ad0,param_1);
  puVar12 = PTR_DAT_00016e80;
  puVar16 = (uint *)(-(ulonglong)(psVar4 != (short *)0x0) & (ulonglong)(psVar4 + 0xc));
  _DAT_00016e78 = 1;
  if (DAT_00016e70 * 0x60 != 0) {
    FUN_000004b0((undefined8 *)PTR_DAT_00016e80,DAT_00016e70 * 0x60,0xff);
  }
  uVar11 = DAT_00016e70;
  if (puVar16 != (uint *)0x0) {
    for (; uVar2 = puVar16[1], uVar2 != 0x80000000; puVar16 = puVar16 + 6) {
      if (2 < uVar2) goto LAB_00001d2b;
      if (*puVar16 < uVar11) {
        *(uint *)(puVar12 + (ulonglong)*puVar16 * 0x60 + 0xc) = uVar2;
      }
    }
  }
  FUN_00001b10((undefined8 *)&local_138);
  uVar11 = (ulonglong)local_138 + 1 >> 4;
  if (uVar11 < DAT_00016e70) {
    DAT_00016e70 = uVar11;
  }
  FUN_000019aa(local_f0);
  FUN_00013604(local_136,local_f0,&DAT_00016e70);
LAB_00001d2b:
  FUN_00003b38((longlong *)&local_res8,&local_128,(ulonglong *)&local_res20);
  DAT_00017a68 = FUN_0001089c(6,0x78,(undefined8 *)s_IBI_SYSTZ_00015cd0);
  PTR_s_RUNTSERVZ_00015e88 = (undefined *)FUN_0001089c(6,0x88,(undefined8 *)s_RUNTSERVZ_00015e00);
  _DAT_000169d8 = DAT_00017a68;
  DAT_00017a68[0xb] = PTR_s_RUNTSERVZ_00015e88;
  if (DAT_00017c08 == (undefined8 *)0x0) {
    DAT_00017c08 = _DAT_000169d8;
    _DAT_00017c00 = _DAT_000169d8[0xb];
  }
  do {
    if (*param_1 == -1) {
      param_1 = (short *)0x0;
LAB_00001dcc:
      if ((param_1 == (short *)0x0) ||
         ((*(longlong *)(param_1 + 4) == DAT_00015a60 &&
          (*(longlong *)(param_1 + 8) == DAT_00015a68)))) break;
    }
    else if (*param_1 == 2) goto LAB_00001dcc;
    param_1 = (short *)((longlong)param_1 + (ulonglong)(ushort)param_1[1]);
  } while( true );
  _DAT_00016a10 = *(ulonglong *)(param_1 + 0x10);
  _DAT_000169c0 = *(undefined8 *)(param_1 + 0x20);
  DAT_00016a08 = *(undefined8 *)(param_1 + 0xc);
  _DAT_00017c10 = *(undefined8 *)(param_1 + 0x18);
  uRam0000000000017c18 = *(undefined8 *)(param_1 + 0x1c);
  DAT_0001f6e0 = &DAT_00017c10;
  _DAT_00016a30 = (ulonglong)((_DAT_00016a10 & 0xfff) != 0) + (_DAT_00016a10 >> 0xc);
  _DAT_00016a40 = DAT_00016b30;
  _DAT_00016a28 = DAT_00016a08;
  FUN_000048b4(&DAT_000169a8,(longlong *)&DAT_00015aa0,0,&PTR_DAT_000169c8,'\x01');
  DAT_0001f6e8 = &PTR_DAT_000169c8;
  DAT_00017b08 = &DAT_000169a0;
  DAT_00017a80 = DAT_000169a8;
  FUN_000092e4(0x200,8,0x79ac,0,&DAT_00017c30);
  FUN_00008fc8((longlong *)&DAT_00015990,DAT_00017c30,&DAT_00017c38);
  DAT_00017c20 = &DAT_00017c20;
  DAT_00017c28 = &DAT_00017c20;
  FUN_00008c18(0x169c8,DAT_00016a88);
  FUN_00003f0c((ulonglong *)&local_res8,local_128,local_res20);
  uVar1 = DAT_00017a80;
  puVar13 = DAT_00017a68;
  _DAT_00017bc0 = DAT_00017a80;
  DAT_00017bb8 = DAT_00017a68;
  DAT_00017bb0 = DAT_00017a68[0xc];
  _DAT_00017bc8 = DAT_00017a68[0xb];
  FUN_0000f810();
  psVar4 = FUN_00010be0(&DAT_00016e58,DAT_00017a60);
  if (psVar4 == (short *)0x0) {
    uVar11 = FUN_00015620();
    uVar2 = in(0x508);
    uVar5 = FUN_000019d0();
    while (iVar3 = in(0x508), (((uVar2 & 0xffffff) + 0x16b) - iVar3 >> 0x17 & 1) == 0) {
      FUN_00000350();
    }
    uVar6 = FUN_000019d0();
    lVar8 = (uVar6 - uVar5) * 0x2685;
    if ((char)uVar11 == '\0') {
      FUN_00001b00();
      _DAT_00017bd0 = lVar8;
    }
    else {
      FUN_00001a70();
      _DAT_00017bd0 = lVar8;
    }
  }
  else {
    _DAT_00017bd0 = *(longlong *)(psVar4 + 0xc);
  }
  FUN_000114b4();
  local_110 = uVar1;
  *(code **)(puVar13[0xb] + 0x68) = FUN_00013a98;
  FUN_00011598(&DAT_00015b40,&LAB_00013ac8,&LAB_00013bc4);
  pcVar17 = FUN_000154e0;
  FUN_00011598(&DAT_00015c90,&LAB_00015434,FUN_000154e0);
  FUN_00000490(local_d8,0x98);
  ppuVar15 = DAT_0001f6e8;
  piVar9 = (int *)DAT_0001f6e8[8];
  local_d8[0] = piVar9;
  local_88 = FUN_00011394(piVar9);
  piVar7 = piVar9;
  if ((short)*piVar9 == 0x5a4d) {
    piVar7 = (int *)((ulonglong)*(ushort *)(piVar9 + 0xf) + (longlong)piVar9);
  }
  if ((short)*piVar7 == 0x5a56) {
    local_80 = ((ulonglong)(uint)piVar7[3] - (ulonglong)*(ushort *)((longlong)piVar7 + 6)) + 0x28;
  }
  else if (*piVar7 == 0x4550) {
    local_80 = (ulonglong)(uint)piVar7[0x15];
  }
  else {
    local_80 = 0;
  }
  local_80 = local_80 & 0xffffffff;
  FUN_00011338(piVar9,&local_120);
  local_b0 = ppuVar15[8];
  local_b8 = FUN_00013308;
  FUN_0000e4fc((longlong *)&DAT_00015c60,0x15d50);
  FUN_0000e4fc((longlong *)&DAT_00015bb0,(longlong)local_res8);
  FUN_0000e4fc((longlong *)&DAT_00015950,0x165c0);
  FUN_000111b8(1,0x3041000,pcVar17,&DAT_00015c80,0);
  local_res10 = (undefined8 *)0xffffffffffffffff;
  lVar8 = FUN_00007104(1,4,0x401,(ulonglong *)&local_res10);
  if (lVar8 < 0) {
    puVar12 = (undefined *)0x0;
    lVar8 = FUN_00007104(0,4,0x401,(ulonglong *)&local_res10);
    if (lVar8 < 0) goto LAB_000021d4;
  }
  puVar13 = (undefined8 *)((longlong)local_res10 + 0x3fffffU & 0xffffffffffc00000);
  uVar11 = (ulonglong)(((longlong)puVar13 - (longlong)local_res10 & 0xfffU) != 0) +
           ((ulonglong)((longlong)puVar13 - (longlong)local_res10) >> 0xc);
  if (uVar11 != 0) {
    FUN_00007178((undefined *)local_res10,uVar11);
  }
  local_res10 = puVar13 + 0x200;
  if (0x400 - uVar11 != 0) {
    FUN_00007178((undefined *)local_res10,0x400 - uVar11);
  }
  *(undefined4 *)(puVar13 + 2) = 0;
  DAT_00017b40 = puVar13;
  *puVar13 = 0x5453595320494249;
  puVar12 = &DAT_00015b30;
  puVar13[1] = DAT_00017a68;
  FUN_0000e4fc((longlong *)&DAT_00015b30,0x17b30);
LAB_000021d4:
  FUN_0000adf0(puVar12,DAT_0001f6e8,DAT_00017a80);
  lVar8 = 0x20;
  puVar13 = &DAT_0001f340;
  do {
    *puVar13 = puVar13;
    puVar13[1] = puVar13;
    puVar13 = puVar13 + 2;
    lVar8 = lVar8 + -1;
  } while (lVar8 != 0);
  FUN_00009354(0x200,0x1e,0xb3b8,0,(longlong *)0x0,&DAT_00017b58);
  FUN_00009354(0x200,0x10,0xf788,0,(longlong *)&DAT_00015960,&DAT_00017b18);
  FUN_00009354(0x200,8,0xcf64,0,(longlong *)&DAT_000159f0,&local_108);
  FUN_00009354(0x200,0x10,0xcf7c,0,(longlong *)&DAT_00015c10,&local_100);
  DAT_0001f540 = 2;
  DAT_00017c40 = &DAT_00017c40;
  DAT_00017c48 = &DAT_00017c40;
  FUN_000092e4(0x200,8,0x8e6c,0,&local_118);
  FUN_00008fc8((longlong *)&DAT_00015b10,local_118,&local_f8);
  psVar4 = FUN_00010be0((longlong *)&DAT_00015ad0,local_res8);
  if (psVar4 != (short *)0x0) {
    lVar8 = 1;
    for (piVar9 = (int *)(psVar4 + 0xe); *piVar9 != -0x80000000; piVar9 = piVar9 + 6) {
      lVar8 = lVar8 + 1;
    }
    puVar13 = FUN_0001089c(4,lVar8 * 0x18,(undefined8 *)(psVar4 + 0xc));
    FUN_0000e4fc((longlong *)&DAT_00015ba0,(longlong)puVar13);
  }
  FUN_00004ac0((undefined8 *)&DAT_00017a78,&DAT_00015c70,&PTR_LAB_00016060,0);
  ppuVar15 = &PTR_DAT_000162e0;
  FUN_00004604((longlong *)&PTR_DAT_000162e0);
  FUN_00004604((longlong *)&PTR_DAT_00016510);
  psVar4 = DAT_00017a60;
LAB_000023ad:
  for (; *psVar4 != -1; psVar4 = (short *)((longlong)psVar4 + (ulonglong)(ushort)psVar4[1])) {
    if (*psVar4 == 5) goto LAB_000023b7;
  }
  psVar4 = (short *)0x0;
LAB_000023b7:
  if (psVar4 != (short *)0x0) {
    uVar19 = 0;
    psVar10 = DAT_00017a60;
    do {
      if (*psVar10 == -1) {
        psVar10 = (short *)0x0;
LAB_000023d8:
        if (psVar10 == (short *)0x0) goto LAB_000023f5;
        if ((*(longlong *)(psVar10 + 4) == *(longlong *)(psVar4 + 4)) &&
           (*(longlong *)(psVar10 + 8) == *(longlong *)(psVar4 + 8))) goto code_r0x000023f1;
      }
      else if (*psVar10 == 0xc) goto LAB_000023d8;
      psVar10 = (short *)((longlong)psVar10 + (ulonglong)(ushort)psVar10[1]);
    } while( true );
  }
  FUN_00010c7c(&DAT_000159a0,8,&LAB_0000e2f8,0,&DAT_0001e460);
  uVar11 = (ulonglong)DAT_00017be0;
  if (uVar11 != 0) {
    plVar14 = (longlong *)(uVar11 * 0x10 + DAT_00017bf0);
    do {
      plVar14 = plVar14 + -2;
      FUN_000048b4((undefined8 *)&DAT_00017b60,plVar14,0,&PTR_LAB_00016cd0,'\x01');
      uVar11 = uVar11 - 1;
    } while (uVar11 != 0);
  }
  pcVar18 = FUN_0000a344;
  FUN_00010c7c(&DAT_00015ab0,8,FUN_0000a344,0,&DAT_0001f300);
  uVar1 = DAT_00017a80;
  puVar13 = DAT_00017a68;
  lVar8 = 0;
  pcVar17 = DAT_00017ab0;
  while (pcVar17 != (code *)0x0) {
    (*pcVar17)(uVar1,puVar13);
    lVar8 = lVar8 + 1;
    pcVar17 = (&DAT_00017ab0)[lVar8];
  }
  FUN_00009a74();
  puVar12 = PTR_DAT_000162e0;
  do {
    if (puVar12 == (undefined *)0x0) {
LAB_0000250d:
      FUN_000111b8(1,0x3041001,pcVar18,&DAT_00015c80,0);
      (*(code *)*DAT_00017a70)(DAT_00017a70);
      local_res18 = 0;
      while (local_res18 == 0) {
        FUN_00000350();
      }
      return;
    }
    if (*(char *)(ppuVar15 + 4) == '\0') {
      FUN_000111b8(0x80000002,0x3041000,pcVar18,&DAT_00015c80,0);
      goto LAB_0000250d;
    }
    ppuVar15 = ppuVar15 + 5;
    puVar12 = *ppuVar15;
  } while( true );
code_r0x000023f1:
  uVar19 = *(undefined4 *)(psVar10 + 0xc);
LAB_000023f5:
  FUN_0000b02c(*(ulonglong *)(psVar4 + 4),0xffff,0,uVar19,(undefined8 *)0x0);
  psVar4 = (short *)((longlong)psVar4 + (ulonglong)(ushort)psVar4[1]);
  goto LAB_000023ad;
}

