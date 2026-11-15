
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00000e2c(short *param_1)

{
  undefined8 uVar1;
  short *psVar2;
  int *piVar3;
  longlong lVar4;
  int *piVar5;
  code *pcVar6;
  undefined *puVar7;
  undefined8 *puVar8;
  short *psVar9;
  longlong *plVar10;
  undefined **ppuVar11;
  ulonglong uVar12;
  code *pcVar13;
  undefined4 uVar14;
  short *local_res8;
  undefined8 *local_res10;
  longlong local_res18;
  undefined *local_res20;
  ulonglong local_f8;
  longlong local_f0;
  longlong local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  int *local_c8 [4];
  code *local_a8;
  undefined8 local_a0;
  int *local_78;
  ulonglong local_70;
  
  local_res8 = param_1;
  psVar2 = FUN_0000fbc8((longlong *)&DAT_00015b70,param_1);
  FUN_00012078(-(ulonglong)(psVar2 != (short *)0x0) & (ulonglong)(psVar2 + 0xc));
  FUN_00002b80((longlong *)&local_res8,&local_f8,(ulonglong *)&local_res20);
  DAT_00017b28 = FUN_0000f984(6,0x78,(undefined8 *)s_IBI_SYSTP_00015d80);
  PTR_s_RUNTSERVP_00015f38 = (undefined *)FUN_0000f984(6,0x88,(undefined8 *)s_RUNTSERVP_00015eb0);
  _DAT_00016a58 = DAT_00017b28;
  DAT_00017b28[0xb] = PTR_s_RUNTSERVP_00015f38;
  if (DAT_00017cc8 == (undefined8 *)0x0) {
    DAT_00017cc8 = _DAT_00016a58;
    DAT_00017cc0 = _DAT_00016a58[0xb];
  }
  do {
    if (*param_1 == -1) {
      param_1 = (short *)0x0;
LAB_00000f0f:
      if ((param_1 == (short *)0x0) ||
         ((*(longlong *)(param_1 + 4) == DAT_00015b00 &&
          (*(longlong *)(param_1 + 8) == DAT_00015b08)))) break;
    }
    else if (*param_1 == 2) goto LAB_00000f0f;
    param_1 = (short *)((longlong)param_1 + (ulonglong)(ushort)param_1[1]);
  } while( true );
  _DAT_00016a90 = *(ulonglong *)(param_1 + 0x10);
  _DAT_00016a40 = *(undefined8 *)(param_1 + 0x20);
  DAT_00016a88 = *(undefined8 *)(param_1 + 0xc);
  _DAT_00017e48 = *(undefined8 *)(param_1 + 0x18);
  uRam0000000000017e50 = *(undefined8 *)(param_1 + 0x1c);
  DAT_00019c40 = &DAT_00017e48;
  _DAT_00016ab0 = (ulonglong)((_DAT_00016a90 & 0xfff) != 0) + (_DAT_00016a90 >> 0xc);
  _DAT_00016ac0 = DAT_00016ba8;
  _DAT_00016aa8 = DAT_00016a88;
  FUN_000038a4(&DAT_00016a28,(longlong *)&DAT_00015b40,0,&DAT_00016a48,'\x01');
  DAT_00017b40 = DAT_00016a28;
  DAT_00017bc0 = &DAT_00016a20;
  DAT_00019c48 = &DAT_00016a48;
  FUN_0000827c(0x200,8,0x695c,0,&DAT_00017e68);
  FUN_00007f60((longlong *)&DAT_00015a30,DAT_00017e68,&DAT_00017e70);
  DAT_00017e58 = &DAT_00017e58;
  DAT_00017e60 = &DAT_00017e58;
  FUN_00007bb0(0x16a48,DAT_00016b08);
  FUN_00002f50((ulonglong *)&local_res8,local_f8,local_res20);
  FUN_00000c20();
  FUN_00000470(local_c8,0x90);
  puVar7 = DAT_00019c48;
  piVar5 = *(int **)(DAT_00019c48 + 0x40);
  local_c8[0] = piVar5;
  local_78 = FUN_00010280(piVar5);
  piVar3 = piVar5;
  if ((short)*piVar5 == 0x5a4d) {
    piVar3 = (int *)((ulonglong)*(ushort *)(piVar5 + 0xf) + (longlong)piVar5);
  }
  if ((short)*piVar3 == 0x5a56) {
    local_70 = ((ulonglong)(uint)piVar3[3] - (ulonglong)*(ushort *)((longlong)piVar3 + 6)) + 0x28;
  }
  else if (*piVar3 == 0x4550) {
    local_70 = (ulonglong)(uint)piVar3[0x15];
  }
  else {
    local_70 = 0;
  }
  local_70 = local_70 & 0xffffffff;
  FUN_00010224(piVar5,&local_f0);
  local_a0 = *(undefined8 *)(puVar7 + 0x40);
  local_a8 = FUN_00012044;
  FUN_0000d48c((longlong *)&DAT_00015d00,0x15e00);
  FUN_0000d48c(&DAT_00015c50,(longlong)local_res8);
  FUN_0000d48c((longlong *)&DAT_000159f0,0x16670);
  FUN_0000f494(1,0x3041000,local_res20,&DAT_00015d20,0);
  local_res10 = (undefined8 *)0xffffffffffffffff;
  lVar4 = FUN_000060ec(1,4,0x401,(ulonglong *)&local_res10);
  if (lVar4 < 0) {
    puVar7 = (undefined *)0x0;
    lVar4 = FUN_000060ec(0,4,0x401,(ulonglong *)&local_res10);
    if (lVar4 < 0) goto LAB_00001218;
  }
  puVar8 = (undefined8 *)((longlong)local_res10 + 0x3fffffU & 0xffffffffffc00000);
  uVar12 = (ulonglong)(((longlong)puVar8 - (longlong)local_res10 & 0xfffU) != 0) +
           ((ulonglong)((longlong)puVar8 - (longlong)local_res10) >> 0xc);
  if (uVar12 != 0) {
    FUN_00006160((undefined *)local_res10,uVar12);
  }
  local_res10 = puVar8 + 0x200;
  if (0x400 - uVar12 != 0) {
    FUN_00006160((undefined *)local_res10,0x400 - uVar12);
  }
  *(undefined4 *)(puVar8 + 2) = 0;
  DAT_00017bf8 = puVar8;
  *puVar8 = 0x5453595320494249;
  puVar7 = &DAT_00015bd0;
  puVar8[1] = DAT_00017b28;
  FUN_0000d48c((longlong *)&DAT_00015bd0,0x17be8);
LAB_00001218:
  FUN_00009d88(puVar7,DAT_00019c48,DAT_00017b40);
  lVar4 = 0x20;
  puVar8 = &DAT_000198a0;
  do {
    *puVar8 = puVar8;
    puVar8[1] = puVar8;
    puVar8 = puVar8 + 2;
    lVar4 = lVar4 + -1;
  } while (lVar4 != 0);
  FUN_000082ec(0x200,0x1e,0xa350,0,(longlong *)0x0,&DAT_00017c10);
  FUN_000082ec(0x200,0x10,0xfbc4,0,(longlong *)&DAT_00015a00,&DAT_00017bd0);
  FUN_000082ec(0x200,8,0xbef4,0,(longlong *)&DAT_00015a90,&local_e0);
  FUN_000082ec(0x200,0x10,0xbf0c,0,(longlong *)&DAT_00015cc0,&local_d8);
  DAT_00019aa0 = 2;
  DAT_00017e78 = &DAT_00017e78;
  DAT_00017e80 = &DAT_00017e78;
  FUN_0000827c(0x200,8,0x7e04,0,&local_e8);
  FUN_00007f60((longlong *)&DAT_00015bb0,local_e8,&local_d0);
  psVar2 = FUN_0000fbc8((longlong *)&DAT_00015b70,local_res8);
  if (psVar2 != (short *)0x0) {
    lVar4 = 1;
    for (piVar5 = (int *)(psVar2 + 0xe); *piVar5 != -0x80000000; piVar5 = piVar5 + 6) {
      lVar4 = lVar4 + 1;
    }
    puVar8 = FUN_0000f984(4,lVar4 * 0x18,(undefined8 *)(psVar2 + 0xc));
    FUN_0000d48c((longlong *)&DAT_00015c40,(longlong)puVar8);
  }
  puVar7 = &DAT_00015d10;
  FUN_00003ab0((undefined8 *)&DAT_00017b38,&DAT_00015d10,&PTR_DAT_00016110,0);
  ppuVar11 = &PTR_DAT_00016390;
  FUN_00003640((longlong *)&PTR_DAT_00016390);
  FUN_00003640((longlong *)&PTR_DAT_000165c0);
  psVar2 = DAT_00017b20;
  psVar9 = DAT_00017b20;
LAB_000013ea:
  for (; *psVar9 != -1; psVar9 = (short *)((longlong)psVar9 + (ulonglong)(ushort)psVar9[1])) {
    if (*psVar9 == 5) goto LAB_000013f5;
  }
  psVar9 = (short *)0x0;
LAB_000013f5:
  if (psVar9 != (short *)0x0) {
    uVar14 = 0;
    do {
      if (*psVar2 == -1) {
        psVar2 = (short *)0x0;
LAB_00001417:
        if (psVar2 == (short *)0x0) goto LAB_00001434;
        if ((*(longlong *)(psVar2 + 4) == *(longlong *)(psVar9 + 4)) &&
           (*(longlong *)(psVar2 + 8) == *(longlong *)(psVar9 + 8))) goto code_r0x00001430;
      }
      else if (*psVar2 == 0xc) goto LAB_00001417;
      psVar2 = (short *)((longlong)psVar2 + (ulonglong)(ushort)psVar2[1]);
    } while( true );
  }
  FUN_0000fce8(&DAT_00015a40,8,&LAB_0000d288,0,&DAT_00018ac0);
  uVar12 = (ulonglong)DAT_00017c98;
  if (uVar12 != 0) {
    plVar10 = (longlong *)(uVar12 * 0x10 + DAT_00017ca8);
    do {
      plVar10 = plVar10 + -2;
      FUN_000038a4((undefined8 *)&DAT_00017c18,plVar10,0,&PTR_LAB_00016d40,'\x01');
      uVar12 = uVar12 - 1;
    } while (uVar12 != 0);
  }
  pcVar13 = FUN_000092dc;
  FUN_0000fce8(&DAT_00015b50,8,FUN_000092dc,0,&DAT_00019878);
  uVar1 = DAT_00017b40;
  puVar8 = DAT_00017b28;
  lVar4 = 0;
  pcVar6 = FUN_00014858;
  while (pcVar6 != (code *)0x0) {
    (*pcVar6)(uVar1,puVar8);
    lVar4 = lVar4 + 1;
    pcVar6 = (code *)(&PTR_FUN_00016f50)[lVar4];
  }
  FUN_00008a0c();
  puVar7 = PTR_DAT_00016390;
  do {
    if (puVar7 == (undefined *)0x0) {
LAB_00001550:
      FUN_0000f494(1,0x3041001,pcVar13,&DAT_00015d20,0);
      (*(code *)*DAT_00017b30)(DAT_00017b30);
      local_res18 = 0;
      while (local_res18 == 0) {
        FUN_000002a0();
      }
      return;
    }
    if (*(char *)(ppuVar11 + 4) == '\0') {
      FUN_0000f494(0x80000002,0x3041000,pcVar13,&DAT_00015d20,0);
      goto LAB_00001550;
    }
    ppuVar11 = ppuVar11 + 5;
    puVar7 = *ppuVar11;
  } while( true );
code_r0x00001430:
  uVar14 = *(undefined4 *)(psVar2 + 0xc);
LAB_00001434:
  FUN_00009fc4(*(ulonglong *)(psVar9 + 4),puVar7,0,uVar14,(undefined8 *)0x0);
  psVar9 = (short *)((longlong)psVar9 + (ulonglong)(ushort)psVar9[1]);
  psVar2 = DAT_00017b20;
  goto LAB_000013ea;
}

