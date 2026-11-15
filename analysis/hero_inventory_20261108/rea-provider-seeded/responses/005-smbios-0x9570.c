
void FUN_00009570(longlong param_1)

{
  byte *pbVar1;
  ushort uVar2;
  char *pcVar3;
  undefined8 *puVar4;
  char cVar5;
  undefined4 uVar6;
  uint uVar7;
  longlong lVar8;
  ulonglong uVar9;
  short *psVar10;
  longlong lVar11;
  longlong lVar12;
  code *pcVar13;
  int *piVar14;
  ulonglong uVar15;
  short sVar16;
  short sVar17;
  short sVar18;
  byte bVar19;
  uint uVar20;
  char cVar21;
  byte local_res10;
  undefined1 local_res18 [8];
  undefined1 local_res20 [8];
  longlong local_2ae8;
  char *local_2ae0;
  undefined2 local_2ad8 [2];
  undefined2 local_2ad4 [2];
  longlong local_2ad0;
  char *local_2ac8 [2];
  char local_2ab8 [512];
  undefined2 local_28b8 [4];
  undefined8 local_28b0;
  ulonglong local_28a8;
  ushort local_28a0;
  undefined1 local_289e;
  short *local_2898;
  char local_288d;
  undefined1 local_288b;
  undefined1 local_288a;
  undefined1 local_2889;
  char local_2888;
  undefined2 local_2886;
  undefined2 local_2880;
  undefined2 local_287e;
  undefined2 local_2870;
  undefined2 local_286e;
  uint local_286c;
  ulonglong local_2850;
  ulonglong local_2848;
  ulonglong local_2810;
  ulonglong local_2808;
  undefined2 local_2800;
  byte local_27fe;
  byte local_27fd;
  byte local_27fc;
  byte local_27fb;
  byte local_27fa;
  char local_27e4;
  undefined4 local_27e0;
  undefined1 local_27a8;
  undefined2 local_27a7;
  byte local_2790;
  undefined4 local_2780;
  short local_2778;
  byte local_2776;
  byte local_2770;
  byte local_276f;
  byte local_276e;
  byte local_276d;
  byte local_276c;
  byte local_276b;
  int local_2754 [3];
  undefined8 *local_2748;
  byte local_26f4;
  short local_26ec;
  short local_26ea;
  short local_254e;
  short local_254c;
  short local_254a;
  short local_2548;
  short local_2546;
  short local_2544;
  short local_2542;
  short local_2540;
  short local_253e;
  ushort local_253c;
  short local_253a;
  short local_448 [516];
  
  uVar9 = 0;
  local_res10 = 0;
  FUN_0000935c();
  local_res20[0] = 0x11;
  local_2ad4[0] = 0xfffe;
  lVar8 = (**(code **)(DAT_000189c0 + 0x18))(DAT_000189c0,local_2ad4,local_res20,&local_2ae8,0);
  do {
    uVar15 = 0;
    if (lVar8 < 0) {
      *(undefined1 *)(param_1 + 0xf) = 1;
      return;
    }
    FUN_000002c0((undefined8 *)local_28b8,0x2470);
    DAT_00018a80 = (int *)FUN_00013570(4,DAT_00016538);
    if (DAT_00018a80 == (int *)0x0) {
      return;
    }
    local_28b8[0] = 0x4544;
    sVar17 = 1;
    local_28a0 = 2;
    local_28b0 = 0x3c8;
    local_27fe = (char)(uVar9 >> 1) + (char)((uVar9 >> 1) / 6) * -6;
    local_2778 = *(short *)(local_2ae8 + 2);
    local_276b = local_276b | 0x10;
    local_2870 = *(undefined2 *)(local_2ae8 + 4);
    local_276f = local_276f | 8;
    local_27fb = (byte)(uVar9 / 0xc);
    local_27fa = local_27fa | 9;
    local_res18[0] = 0x14;
    local_2ad8[0] = 0xfffe;
    local_28a8 = uVar9;
    while (lVar8 = (**(code **)(DAT_000189c0 + 0x18))
                             (DAT_000189c0,local_2ad8,local_res18,&local_2ad0,0),
          puVar4 = local_2748, -1 < lVar8) {
      if (local_2778 == *(short *)(local_2ad0 + 0xc)) {
        if (local_2748 == (undefined8 *)0x0) {
          local_2748 = FUN_00013570(0,0x20);
          if (local_2748 == (undefined8 *)0x0) break;
        }
        else {
          local_2748 = FUN_00013570(0,((ulonglong)local_2776 + 1) * 0x20);
          if (local_2748 == (undefined8 *)0x0) break;
          if (((ulonglong)local_2776 != 0) && (local_2748 != puVar4)) {
            FUN_00000280(local_2748,puVar4,(ulonglong)local_2776 << 5);
          }
          (**(code **)(DAT_00018a28 + 0x48))(puVar4);
        }
        if (*(uint *)(local_2ad0 + 4) == 0xffffffff) {
          local_2748[(ulonglong)local_2776 * 4 + 1] = *(undefined8 *)(local_2ad0 + 0x13);
        }
        else {
          local_2748[(ulonglong)local_2776 * 4 + 1] = (ulonglong)*(uint *)(local_2ad0 + 4);
        }
        pbVar1 = (byte *)((ulonglong)local_2776 * 0x20 + 0x1c + (longlong)local_2748);
        *pbVar1 = *pbVar1 | 4;
        if (*(uint *)(local_2ad0 + 8) == 0xffffffff) {
          local_2748[(ulonglong)local_2776 * 4 + 2] = *(undefined8 *)(local_2ad0 + 0x1b);
        }
        else {
          local_2748[(ulonglong)local_2776 * 4 + 2] = (ulonglong)*(uint *)(local_2ad0 + 8);
        }
        pbVar1 = (byte *)((ulonglong)local_2776 * 0x20 + 0x1c + (longlong)local_2748);
        *pbVar1 = *pbVar1 | 8;
        local_2776 = local_2776 + 1;
      }
    }
    local_27fa = local_27fa | 4;
    if (*(short *)(local_2ae8 + 0xc) == 0) {
      local_289e = 6;
      local_2780 = 6;
    }
    else {
      local_28a0 = local_28a0 | 0x100;
      local_289e = 0;
      local_2780 = 0;
    }
    local_276b = local_276b | 4;
    local_27fc = (byte)uVar9 & 1;
    FUN_00012628((char *)local_448,0x200,(byte *)u__CPU__1d_____Channel__c_____Chan_00016870,
                 uVar9 / 0xc);
    uVar9 = FUN_0001240c(local_448,0x200);
    psVar10 = (short *)FUN_00013570(0,uVar9 * 2 + 2);
    uVar20 = 0;
    lVar8 = 0;
    local_2898 = psVar10;
    if (psVar10 != (short *)0x0) {
      uVar9 = FUN_0001240c(local_448,0x200);
      FUN_00012440(psVar10,uVar9 * 2 + 2,local_448);
    }
    lVar11 = FUN_00012658(local_2ab8,0x200,(byte *)s_DevType_X_DIMM_d_000168d8,
                          (ulonglong)(byte)local_28a0);
    piVar14 = DAT_00018a80;
    if ((lVar11 != 0) &&
       (FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar11,0), piVar14 = DAT_00018a80,
       DAT_00018a80 != (int *)0x0)) {
      uVar9 = 0x200;
      FUN_0001250c((char *)DAT_00018a80,0x200,local_2ab8);
      piVar14 = DAT_00018a80;
      uVar7 = uVar20;
      if (DAT_00018a80 != (int *)0x0) {
        uVar9 = FUN_000124e0((char *)DAT_00018a80,uVar9);
        uVar7 = (int)uVar9 + 1;
      }
      local_276e = local_276e | 0x40;
      sVar17 = 2;
      uVar15 = (ulonglong)uVar7;
      local_253c = 1;
    }
    cVar21 = (char)*piVar14;
    lVar11 = lVar8;
    while (cVar21 != '\0') {
      lVar11 = lVar11 + 1;
      cVar21 = *(char *)(lVar11 + (longlong)piVar14);
    }
    FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar11,uVar15);
    piVar14 = DAT_00018a80;
    sVar16 = sVar17;
    if (DAT_00018a80 != (int *)0x0) {
      uVar9 = 0x200;
      FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),0x200,(char *)DAT_00018a80);
      piVar14 = DAT_00018a80;
      uVar7 = uVar20;
      if ((char *)((longlong)DAT_00018a80 + uVar15) != (char *)0x0) {
        uVar9 = FUN_000124e0((char *)((longlong)DAT_00018a80 + uVar15),uVar9);
        uVar7 = (int)uVar9 + 1;
      }
      uVar15 = uVar15 + uVar7;
      sVar16 = sVar17 + 1;
      local_276e = local_276e | 0x80;
      local_253a = sVar17;
    }
    cVar21 = '\x01';
    local_2880 = *(undefined2 *)(local_2ae8 + 8);
    local_287e = *(undefined2 *)(local_2ae8 + 10);
    local_276f = local_276f | 0x13;
    local_2886 = *(undefined2 *)(local_2ae8 + 0x15);
    local_286e = *(undefined2 *)(local_2ae8 + 0x20);
    local_288b = *(undefined1 *)(local_2ae8 + 0x12);
    local_288a = *(undefined1 *)(local_2ae8 + 0x1b);
    local_2770 = local_2770 | 0x60;
    local_2800 = *(undefined2 *)(local_2ae8 + 0x13);
    local_276c = local_276c | 0x80;
    if (*(ushort *)(local_2ae8 + 0xc) < 0x7fff) {
      local_286c = (uint)*(ushort *)(local_2ae8 + 0xc);
    }
    else {
      local_286c = *(uint *)(local_2ae8 + 0x1c);
    }
    local_276d = local_276d | 4;
    lVar11 = local_2ae8;
    sVar17 = sVar16;
    local_2888 = cVar21;
    if (*(char *)(local_2ae8 + 0x17) == '\0') {
      local_2ae0 = (char *)0x0;
    }
    else {
      lVar12 = FUN_0001598c((char *)((ulonglong)*(byte *)(local_2ae8 + 1) + local_2ae8),
                            *(char *)(local_2ae8 + 0x17),&local_2ae0);
      pcVar3 = local_2ae0;
      if (-1 < lVar12) {
        uVar7 = uVar20;
        if (local_2ae0 != (char *)0x0) {
          uVar9 = FUN_000124e0(local_2ae0,0x200);
          uVar7 = (int)uVar9 + 1;
        }
        FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,(ulonglong)uVar7,uVar15);
        piVar14 = DAT_00018a80;
        lVar11 = local_2ae8;
        if (DAT_00018a80 != (int *)0x0) {
          FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),(ulonglong)uVar7,pcVar3);
          uVar15 = uVar15 + uVar7;
          sVar17 = sVar16 + 1;
          local_276e = local_276e | 0x10;
          piVar14 = DAT_00018a80;
          lVar11 = local_2ae8;
          local_2540 = sVar16;
        }
      }
    }
    sVar16 = sVar17;
    if (*(char *)(lVar11 + 0x18) == '\0') {
      local_2ae0 = (char *)0x0;
    }
    else {
      lVar12 = FUN_0001598c((char *)((ulonglong)*(byte *)(lVar11 + 1) + lVar11),
                            *(char *)(lVar11 + 0x18),&local_2ae0);
      pcVar3 = local_2ae0;
      if (-1 < lVar12) {
        uVar7 = uVar20;
        if (local_2ae0 != (char *)0x0) {
          uVar9 = FUN_000124e0(local_2ae0,0x200);
          uVar7 = (int)uVar9 + 1;
        }
        FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,(ulonglong)uVar7,uVar15);
        piVar14 = DAT_00018a80;
        lVar11 = local_2ae8;
        if (DAT_00018a80 != (int *)0x0) {
          FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),(ulonglong)uVar7,pcVar3);
          uVar15 = uVar15 + uVar7;
          sVar16 = sVar17 + 1;
          local_276e = local_276e | 0x20;
          piVar14 = DAT_00018a80;
          lVar11 = local_2ae8;
          local_253e = sVar17;
        }
      }
    }
    sVar17 = sVar16;
    if (*(char *)(lVar11 + 0x1a) == '\0') {
      local_2ae0 = (char *)0x0;
    }
    else {
      lVar12 = FUN_0001598c((char *)((ulonglong)*(byte *)(lVar11 + 1) + lVar11),
                            *(char *)(lVar11 + 0x1a),&local_2ae0);
      pcVar3 = local_2ae0;
      if (-1 < lVar12) {
        uVar7 = uVar20;
        if (local_2ae0 != (char *)0x0) {
          uVar9 = FUN_000124e0(local_2ae0,0x200);
          uVar7 = (int)uVar9 + 1;
        }
        FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,(ulonglong)uVar7,uVar15);
        piVar14 = DAT_00018a80;
        lVar11 = local_2ae8;
        if (DAT_00018a80 != (int *)0x0) {
          FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),(ulonglong)uVar7,pcVar3);
          uVar15 = uVar15 + uVar7;
          sVar17 = sVar16 + 1;
          local_276e = local_276e | 8;
          piVar14 = DAT_00018a80;
          lVar11 = local_2ae8;
          local_2542 = sVar16;
        }
      }
    }
    sVar16 = sVar17;
    if (*(char *)(lVar11 + 0x10) == '\0') {
      local_2ae0 = (char *)0x0;
    }
    else {
      lVar12 = FUN_0001598c((char *)((ulonglong)*(byte *)(lVar11 + 1) + lVar11),
                            *(char *)(lVar11 + 0x10),&local_2ae0);
      pcVar3 = local_2ae0;
      if (-1 < lVar12) {
        uVar7 = uVar20;
        if (local_2ae0 != (char *)0x0) {
          uVar9 = FUN_000124e0(local_2ae0,0x200);
          uVar7 = (int)uVar9 + 1;
        }
        FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,(ulonglong)uVar7,uVar15);
        piVar14 = DAT_00018a80;
        lVar11 = local_2ae8;
        if (DAT_00018a80 != (int *)0x0) {
          FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),(ulonglong)uVar7,pcVar3);
          uVar15 = uVar15 + uVar7;
          sVar16 = sVar17 + 1;
          local_276e = local_276e | 4;
          piVar14 = DAT_00018a80;
          lVar11 = local_2ae8;
          local_2544 = sVar17;
        }
      }
    }
    cVar5 = local_27e4;
    uVar6 = local_27e0;
    if (0x33 < *(byte *)(lVar11 + 1)) {
      sVar17 = sVar16;
      if (*(char *)(lVar11 + 0x2b) == '\0') {
        local_2ae0 = (char *)0x0;
      }
      else {
        lVar12 = FUN_0001598c((char *)((ulonglong)*(byte *)(lVar11 + 1) + lVar11),
                              *(char *)(lVar11 + 0x2b),&local_2ae0);
        pcVar3 = local_2ae0;
        if (-1 < lVar12) {
          uVar7 = uVar20;
          if (local_2ae0 != (char *)0x0) {
            uVar9 = FUN_000124e0(local_2ae0,0x200);
            uVar7 = (int)uVar9 + 1;
          }
          FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,(ulonglong)uVar7,uVar15);
          lVar11 = local_2ae8;
          if (DAT_00018a80 != (int *)0x0) {
            FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),(ulonglong)uVar7,pcVar3);
            uVar15 = uVar15 + uVar7;
            sVar17 = sVar16 + 1;
            local_276f = local_276f | 0x40;
            lVar11 = local_2ae8;
            local_254c = sVar16;
          }
        }
      }
      lVar11 = FUN_00012658(local_2ab8,0x200,(byte *)s_0x_4X_000168ec,
                            (ulonglong)*(ushort *)(lVar11 + 0x2c));
      sVar16 = sVar17;
      if ((lVar11 != 0) &&
         (FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar11,uVar15),
         DAT_00018a80 != (int *)0x0)) {
        uVar9 = 0x200;
        FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),0x200,local_2ab8);
        uVar7 = uVar20;
        if ((char *)((longlong)DAT_00018a80 + uVar15) != (char *)0x0) {
          uVar9 = FUN_000124e0((char *)((longlong)DAT_00018a80 + uVar15),uVar9);
          uVar7 = (int)uVar9 + 1;
        }
        uVar15 = uVar15 + uVar7;
        sVar16 = sVar17 + 1;
        local_276f = local_276f | 0x20;
        local_254e = sVar17;
      }
      lVar11 = FUN_00012658(local_2ab8,0x200,(byte *)s_0x_4X_000168ec,
                            (ulonglong)*(ushort *)(local_2ae8 + 0x2e));
      sVar17 = sVar16;
      if ((lVar11 != 0) &&
         (FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar11,uVar15),
         DAT_00018a80 != (int *)0x0)) {
        uVar9 = 0x200;
        FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),0x200,local_2ab8);
        uVar7 = uVar20;
        if ((char *)((longlong)DAT_00018a80 + uVar15) != (char *)0x0) {
          uVar9 = FUN_000124e0((char *)((longlong)DAT_00018a80 + uVar15),uVar9);
          uVar7 = (int)uVar9 + 1;
        }
        uVar15 = uVar15 + uVar7;
        sVar17 = sVar16 + 1;
        local_276f = local_276f | 0x80;
        local_254a = sVar16;
      }
      lVar11 = FUN_00012658(local_2ab8,0x200,(byte *)s_0x_4X_000168ec,
                            (ulonglong)*(ushort *)(local_2ae8 + 0x30));
      sVar18 = sVar17;
      if ((lVar11 != 0) &&
         (FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar11,uVar15),
         DAT_00018a80 != (int *)0x0)) {
        uVar9 = 0x200;
        FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),0x200,local_2ab8);
        uVar7 = uVar20;
        if ((char *)((longlong)DAT_00018a80 + uVar15) != (char *)0x0) {
          uVar9 = FUN_000124e0((char *)((longlong)DAT_00018a80 + uVar15),uVar9);
          uVar7 = (int)uVar9 + 1;
        }
        uVar15 = uVar15 + uVar7;
        sVar18 = sVar17 + 1;
        local_276e = local_276e | 1;
        local_2548 = sVar17;
      }
      lVar11 = FUN_00012658(local_2ab8,0x200,(byte *)s_0x_4X_000168ec,
                            (ulonglong)*(ushort *)(local_2ae8 + 0x32));
      piVar14 = DAT_00018a80;
      sVar16 = sVar18;
      if ((lVar11 != 0) &&
         (FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar11,uVar15),
         piVar14 = DAT_00018a80, DAT_00018a80 != (int *)0x0)) {
        uVar9 = 0x200;
        FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),0x200,local_2ab8);
        piVar14 = DAT_00018a80;
        uVar7 = uVar20;
        if ((char *)((longlong)DAT_00018a80 + uVar15) != (char *)0x0) {
          uVar9 = FUN_000124e0((char *)((longlong)DAT_00018a80 + uVar15),uVar9);
          uVar7 = (int)uVar9 + 1;
        }
        uVar15 = uVar15 + uVar7;
        local_276e = local_276e | 2;
        sVar16 = sVar18 + 1;
        local_2546 = sVar18;
      }
      local_2889 = *(undefined1 *)(local_2ae8 + 0x28);
      local_2770 = local_2770 | 0x80;
      local_2850 = *(ulonglong *)(local_2ae8 + 0x3c) >> 0x14;
      local_276c = local_276c | 1;
      local_2848 = *(ulonglong *)(local_2ae8 + 0x34) >> 0x14;
      local_2808 = *(ulonglong *)(local_2ae8 + 0x4c) >> 0x14;
      local_276d = local_276d | 0x8a;
      local_2810 = *(ulonglong *)(local_2ae8 + 0x44) >> 0x14;
      cVar5 = cVar21;
      if ((*(byte *)(local_2ae8 + 0x29) & 8) == 0) {
        uVar6 = 1;
        if (((*(byte *)(local_2ae8 + 0x29) & 0x10) == 0) &&
           (cVar5 = local_27e4, uVar6 = local_27e0, (*(byte *)(local_2ae8 + 0x29) & 0x20) != 0)) {
          local_27e0 = 2;
          cVar5 = cVar21;
          uVar6 = local_27e0;
        }
      }
      else {
        local_27e0 = 0;
        uVar6 = local_27e0;
      }
    }
    local_27e0 = uVar6;
    local_27e4 = cVar5;
    uVar9 = 0;
    if (DAT_000189da != 0) {
      do {
        if ((DAT_000189e0 != 0) &&
           (((((uVar7 = *(uint *)(DAT_000189e0 + 4 + uVar9 * 0x30),
               local_27fb == ((byte)(uVar7 >> 0xc) & 0xf) &&
               (local_27fd == ((byte)(uVar7 >> 8) & 0xf))) &&
              (local_27fe == ((byte)(uVar7 >> 4) & 0xf))) && (local_27fc == ((byte)uVar7 & 0xf))) ||
            (local_2778 == *(short *)(DAT_000189e0 + 8 + uVar9 * 0x30))))) {
          local_2770 = local_2770 | 8;
          uVar2 = *(ushort *)(DAT_000189e0 + 0xe + uVar9 * 0x30);
          local_288d = cVar21;
          if ((DAT_00018a88 != 0) &&
             (uVar2 == *(ushort *)(DAT_00018a88 + 4 + (longlong)(int)(uVar2 - 1) * 0x50))) {
            lVar11 = (longlong)(int)(uVar2 - 1);
            lVar12 = FUN_00012658(local_2ab8,0x200,(byte *)s_0x_4X_000168ec,
                                  (ulonglong)*(ushort *)(DAT_00018a88 + 6 + lVar11 * 0x50));
            sVar17 = sVar16;
            if ((lVar12 != 0) &&
               (FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar12,uVar15),
               DAT_00018a80 != (int *)0x0)) {
              uVar9 = 0x200;
              FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),0x200,local_2ab8);
              uVar7 = uVar20;
              if ((char *)((longlong)DAT_00018a80 + uVar15) != (char *)0x0) {
                uVar9 = FUN_000124e0((char *)((longlong)DAT_00018a80 + uVar15),uVar9);
                uVar7 = (int)uVar9 + 1;
              }
              uVar15 = uVar15 + uVar7;
              sVar17 = sVar16 + 1;
              local_276f = local_276f | 0x20;
              local_254e = sVar16;
            }
            lVar12 = FUN_00012658(local_2ab8,0x200,(byte *)s_0x_4X_000168ec,
                                  (ulonglong)*(ushort *)(DAT_00018a88 + 8 + lVar11 * 0x50));
            sVar16 = sVar17;
            if ((lVar12 != 0) &&
               (FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar12,uVar15),
               DAT_00018a80 != (int *)0x0)) {
              uVar9 = 0x200;
              FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),0x200,local_2ab8);
              uVar7 = uVar20;
              if ((char *)((longlong)DAT_00018a80 + uVar15) != (char *)0x0) {
                uVar9 = FUN_000124e0((char *)((longlong)DAT_00018a80 + uVar15),uVar9);
                uVar7 = (int)uVar9 + 1;
              }
              uVar15 = uVar15 + uVar7;
              sVar16 = sVar17 + 1;
              local_276f = local_276f | 0x80;
              local_254a = sVar17;
            }
            lVar12 = FUN_00012658(local_2ab8,0x200,(byte *)s_0x_4X_000168ec,
                                  (ulonglong)*(ushort *)(DAT_00018a88 + 0xc + lVar11 * 0x50));
            sVar17 = sVar16;
            if ((lVar12 != 0) &&
               (FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar12,uVar15),
               DAT_00018a80 != (int *)0x0)) {
              uVar9 = 0x200;
              FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),0x200,local_2ab8);
              uVar7 = uVar20;
              if ((char *)((longlong)DAT_00018a80 + uVar15) != (char *)0x0) {
                uVar9 = FUN_000124e0((char *)((longlong)DAT_00018a80 + uVar15),uVar9);
                uVar7 = (int)uVar9 + 1;
              }
              uVar15 = uVar15 + uVar7;
              sVar17 = sVar16 + 1;
              local_276e = local_276e | 1;
              local_2548 = sVar16;
            }
            lVar11 = FUN_00012658(local_2ab8,0x200,(byte *)s_0x_4X_000168ec,
                                  (ulonglong)*(ushort *)(DAT_00018a88 + 0xe + lVar11 * 0x50));
            piVar14 = DAT_00018a80;
            sVar16 = sVar17;
            if ((lVar11 != 0) &&
               (FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar11,uVar15),
               piVar14 = DAT_00018a80, DAT_00018a80 != (int *)0x0)) {
              uVar9 = 0x200;
              FUN_0001250c((char *)((longlong)DAT_00018a80 + uVar15),0x200,local_2ab8);
              piVar14 = DAT_00018a80;
              uVar7 = uVar20;
              if ((char *)((longlong)DAT_00018a80 + uVar15) != (char *)0x0) {
                uVar9 = FUN_000124e0((char *)((longlong)DAT_00018a80 + uVar15),uVar9);
                uVar7 = (int)uVar9 + 1;
              }
              uVar15 = uVar15 + uVar7;
              local_276e = local_276e | 2;
              sVar16 = sVar17 + 1;
              local_2546 = sVar17;
            }
            break;
          }
        }
        bVar19 = (char)uVar9 + 1;
        uVar9 = (ulonglong)bVar19;
      } while (bVar19 < DAT_000189da);
    }
    if (local_288d == '\0') {
      local_27a7 = 0;
      local_27a8 = 0;
      local_2790 = local_2790 | 7;
    }
    if (local_253c == 0) {
      local_2ac8[0] = (char *)0x0;
    }
    else {
      lVar11 = FUN_00015c48((char *)piVar14,local_253c,(longlong *)local_2ac8);
      pcVar3 = local_2ac8[0];
      if (-1 < lVar11) {
        cVar21 = *local_2ac8[0];
        lVar11 = lVar8;
        while (cVar21 != '\0') {
          lVar11 = lVar11 + 1;
          cVar21 = local_2ac8[0][lVar11];
        }
        FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar11,uVar15);
        sVar17 = sVar16;
        if (DAT_00018a80 != (int *)0x0) {
          FUN_00012658((char *)((longlong)DAT_00018a80 + uVar15),0x200,(byte *)&DAT_000165cc,
                       (ulonglong)pcVar3);
          if ((char *)((longlong)DAT_00018a80 + uVar15) != (char *)0x0) {
            uVar9 = FUN_000124e0((char *)((longlong)DAT_00018a80 + uVar15),0x200);
            uVar20 = (int)uVar9 + 1;
          }
          uVar15 = uVar15 + uVar20;
          sVar17 = sVar16 + 1;
          local_26f4 = local_26f4 | 1;
          local_26ec = sVar16;
        }
        cVar21 = *pcVar3;
        while (cVar21 != '\0') {
          lVar8 = lVar8 + 1;
          cVar21 = pcVar3[lVar8];
        }
        FUN_000161bc((longlong *)&DAT_00018a80,&DAT_00016538,lVar8,uVar15);
        piVar14 = DAT_00018a80;
        if (DAT_00018a80 != (int *)0x0) {
          FUN_00012658((char *)((longlong)DAT_00018a80 + uVar15),0x200,(byte *)s__a_Metric_00016860,
                       (ulonglong)pcVar3);
          local_26f4 = local_26f4 | 2;
          piVar14 = DAT_00018a80;
          local_26ea = sVar17;
        }
      }
    }
    lVar8 = FUN_00015ebc(param_1,local_2754,piVar14);
    if (DAT_00018a80 != (int *)0x0) {
      (**(code **)(DAT_00018a28 + 0x48))();
      DAT_00018a80 = (int *)0x0;
      DAT_00016538 = 0x2000;
    }
    if (-1 < lVar8) {
      uVar9 = 0;
      pcVar13 = FUN_0000049c;
      do {
        (*pcVar13)(param_1,local_28b8);
        uVar9 = (ulonglong)((int)uVar9 + 1);
        pcVar13 = *(code **)(&DAT_00018580 + uVar9 * 8);
      } while (pcVar13 != (code *)0x0);
      if ((ulonglong *)(param_1 + 0x328) != (ulonglong *)0x0) {
        FUN_000158e0((ulonglong *)(param_1 + 0x328),(undefined8 *)local_28b8,0x2470);
      }
      local_res10 = local_res10 + 1;
    }
    uVar9 = (ulonglong)local_res10;
    lVar8 = (**(code **)(DAT_000189c0 + 0x18))(DAT_000189c0,local_2ad4,local_res20,&local_2ae8,0);
  } while( true );
}

