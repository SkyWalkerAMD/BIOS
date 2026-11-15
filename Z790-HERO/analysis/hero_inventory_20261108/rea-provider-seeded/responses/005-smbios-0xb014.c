
void FUN_0000b014(longlong param_1)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  longlong lVar4;
  ulonglong uVar5;
  short *psVar6;
  longlong lVar7;
  code *pcVar8;
  int *piVar9;
  ulonglong uVar10;
  byte bVar11;
  short sVar12;
  short sVar13;
  int iVar14;
  uint uVar15;
  ulonglong uVar16;
  ulonglong uVar17;
  undefined1 local_res10 [8];
  short local_res18 [4];
  undefined2 local_res20 [4];
  char *local_2ad8;
  ulonglong local_2ad0;
  longlong local_2ac8;
  undefined8 *local_2ac0;
  undefined1 local_2ab8 [8];
  undefined1 local_2ab0 [8];
  undefined8 local_2aa8;
  undefined8 local_2aa0;
  ulonglong local_2a98;
  ushort local_2a90;
  undefined1 local_2a8e;
  short *local_2a88;
  byte local_2a80;
  byte local_2a7f;
  byte local_2a7e;
  undefined1 local_2a7d;
  undefined1 local_2a7c;
  undefined1 local_2a7b;
  uint local_2a78;
  uint local_2a74;
  undefined1 local_2a60;
  undefined8 local_2a58 [19];
  undefined4 local_29c0;
  byte local_29bc;
  byte local_29bb;
  byte local_29ba;
  byte local_29b9;
  int local_29b0 [2022];
  byte local_a18;
  short local_a10;
  short local_9ce;
  short local_9cc;
  undefined2 local_9c8;
  short local_9c6;
  short local_9c2;
  undefined8 *local_9c0;
  char local_638 [512];
  short local_438 [512];
  
  uVar16 = 0;
  local_res10[0] = 4;
  local_2ac0 = (undefined8 *)0x0;
  local_res20[0] = 0xfffe;
  uVar15 = 0;
  lVar4 = (**(code **)(DAT_000189c0 + 0x18))(DAT_000189c0,local_res20,local_res10,&local_2ac8,0);
  uVar17 = uVar16;
  if (-1 < lVar4) {
    do {
      FUN_000002c0(&local_2aa8,0x2470);
      DAT_000189e8 = (int *)FUN_00013570(4,DAT_00016540);
      if (DAT_000189e8 == (int *)0x0) {
        return;
      }
      sVar13 = 1;
      local_res18[0] = 1;
      uVar10 = 0;
      local_2aa8._0_2_ = 0x4544;
      local_2ad0 = 0;
      local_2a90 = 1;
      local_2aa0 = 0x2108;
      local_2a98 = uVar17;
      FUN_00012628((char *)local_438,0x200,(byte *)u__CPU__d__00016918,uVar17);
      uVar5 = FUN_0001240c(local_438,0x200);
      psVar6 = (short *)FUN_00013570(0,uVar5 * 2 + 2);
      local_2a88 = psVar6;
      if (psVar6 != (short *)0x0) {
        uVar5 = FUN_0001240c(local_438,0x200);
        FUN_00012440(psVar6,uVar5 * 2 + 2,local_438);
      }
      lVar4 = FUN_00012658(local_638,0x200,(byte *)s_DevType_X_CPU_d_00016930,
                           (ulonglong)(byte)local_2a90);
      piVar9 = DAT_000189e8;
      if ((lVar4 != 0) &&
         (FUN_000161bc((longlong *)&DAT_000189e8,&DAT_00016540,lVar4,0), piVar9 = DAT_000189e8,
         uVar10 = uVar16, DAT_000189e8 != (int *)0x0)) {
        uVar10 = 0x200;
        FUN_0001250c((char *)DAT_000189e8,0x200,local_638);
        piVar9 = DAT_000189e8;
        uVar3 = uVar15;
        if (DAT_000189e8 != (int *)0x0) {
          uVar10 = FUN_000124e0((char *)DAT_000189e8,uVar10);
          uVar3 = (int)uVar10 + 1;
        }
        local_29bb = local_29bb | 0x40;
        sVar13 = 2;
        uVar10 = (ulonglong)uVar3;
        local_res18[0] = 2;
        local_9c8 = 1;
        local_2ad0 = uVar10;
      }
      cVar1 = (char)*piVar9;
      uVar5 = uVar16;
      while (cVar1 != '\0') {
        uVar5 = uVar5 + 1;
        cVar1 = *(char *)(uVar5 + (longlong)piVar9);
      }
      FUN_000161bc((longlong *)&DAT_000189e8,&DAT_00016540,uVar5,uVar10);
      piVar9 = DAT_000189e8;
      sVar12 = sVar13;
      if (DAT_000189e8 != (int *)0x0) {
        uVar5 = 0x200;
        FUN_0001250c((char *)((longlong)DAT_000189e8 + uVar10),0x200,(char *)DAT_000189e8);
        piVar9 = DAT_000189e8;
        uVar3 = uVar15;
        if ((char *)((longlong)DAT_000189e8 + uVar10) != (char *)0x0) {
          uVar5 = FUN_000124e0((char *)((longlong)DAT_000189e8 + uVar10),uVar5);
          uVar3 = (int)uVar5 + 1;
        }
        uVar10 = uVar10 + uVar3;
        local_res18[0] = sVar13 + 1;
        local_29bb = local_29bb | 0x80;
        sVar12 = local_res18[0];
        local_2ad0 = uVar10;
        local_9c6 = sVar13;
      }
      if ((*(byte *)(local_2ac8 + 0x18) & 0x40) == 0) {
        local_29ba = local_29ba | 0x40;
        local_2a8e = 6;
        local_29c0 = 6;
      }
      else {
        local_29bb = local_29bb | 1;
        local_2a90 = local_2a90 | 0x100;
        local_29ba = local_29ba | 0x40;
        local_2a8e = 0;
        local_29c0 = 0;
        local_2a7b = (undefined1)uVar17;
        local_2a80 = *(byte *)(local_2ac8 + 0x23);
        local_2a7f = *(byte *)(local_2ac8 + 0x24);
        local_2a7e = *(byte *)(local_2ac8 + 0x25);
        local_2a78 = (uint)*(ushort *)(local_2ac8 + 0x14);
        local_2a74 = (uint)*(ushort *)(local_2ac8 + 0x16);
        local_2a7c = *(undefined1 *)(local_2ac8 + 5);
        local_29bc = local_29bc | 0xbf;
        local_2a7d = *(undefined1 *)(local_2ac8 + 6);
        if (local_2a58 != (undefined8 *)(local_2ac8 + 8)) {
          FUN_00000280(local_2a58,(undefined8 *)(local_2ac8 + 8),8);
        }
        local_29b9 = local_29b9 | 1;
        local_29ba = local_29ba | 0x80;
        lVar4 = (**(code **)(DAT_00018a28 + 0x140))(&DAT_00016290,0,&local_2ac0);
        if (-1 < lVar4) {
          (*(code *)*local_2ac0)(local_2ac0,local_2ab8,local_2ab0);
        }
        if (*(char *)(local_2ac8 + 0x10) == '\0') {
          local_2ad8 = (char *)0x0;
        }
        else {
          FUN_0001598c((char *)((ulonglong)*(byte *)(local_2ac8 + 1) + local_2ac8),
                       *(char *)(local_2ac8 + 0x10),&local_2ad8);
        }
        lVar4 = FUN_00012658(local_638,0x200,(byte *)s__a___d_Core_s____d_Logical_Proce_00016940,
                             (ulonglong)local_2ad8);
        sVar13 = sVar12;
        if ((lVar4 != 0) &&
           (FUN_000161bc((longlong *)&DAT_000189e8,&DAT_00016540,lVar4,uVar10),
           DAT_000189e8 != (int *)0x0)) {
          FUN_0001250c((char *)((longlong)DAT_000189e8 + uVar10),0x200,local_638);
          if ((char *)((longlong)DAT_000189e8 + uVar10) == (char *)0x0) {
            uVar3 = 0;
          }
          else {
            uVar5 = FUN_000124e0((char *)((longlong)DAT_000189e8 + uVar10),0x200);
            uVar3 = (int)uVar5 + 1;
          }
          uVar10 = uVar10 + uVar3;
          sVar13 = sVar12 + 1;
          local_29ba = local_29ba | 2;
          local_res18[0] = sVar13;
          local_2ad0 = uVar10;
          local_9c2 = sVar12;
        }
        lVar4 = local_2ac8;
        sVar12 = sVar13;
        if (*(char *)(local_2ac8 + 7) == '\0') {
          local_2ad8 = (char *)0x0;
        }
        else {
          lVar7 = FUN_0001598c((char *)((ulonglong)*(byte *)(local_2ac8 + 1) + local_2ac8),
                               *(char *)(local_2ac8 + 7),&local_2ad8);
          pcVar2 = local_2ad8;
          if (-1 < lVar7) {
            uVar3 = uVar15;
            if (local_2ad8 != (char *)0x0) {
              uVar5 = FUN_000124e0(local_2ad8,0x200);
              uVar3 = (int)uVar5 + 1;
            }
            FUN_000161bc((longlong *)&DAT_000189e8,&DAT_00016540,(ulonglong)uVar3,uVar10);
            lVar4 = local_2ac8;
            if (DAT_000189e8 != (int *)0x0) {
              FUN_0001250c((char *)((longlong)DAT_000189e8 + uVar10),(ulonglong)uVar3,pcVar2);
              uVar10 = uVar10 + uVar3;
              local_res18[0] = sVar13 + 1;
              local_29bb = local_29bb | 0x10;
              lVar4 = local_2ac8;
              sVar12 = local_res18[0];
              local_2ad0 = uVar10;
              local_9cc = sVar13;
            }
          }
        }
        sVar13 = sVar12;
        if (*(char *)(lVar4 + 0x10) == '\0') {
          local_2ad8 = (char *)0x0;
        }
        else {
          lVar7 = FUN_0001598c((char *)((ulonglong)*(byte *)(lVar4 + 1) + lVar4),
                               *(char *)(lVar4 + 0x10),&local_2ad8);
          pcVar2 = local_2ad8;
          if (-1 < lVar7) {
            uVar3 = uVar15;
            if (local_2ad8 != (char *)0x0) {
              uVar5 = FUN_000124e0(local_2ad8,0x200);
              uVar3 = (int)uVar5 + 1;
            }
            FUN_000161bc((longlong *)&DAT_000189e8,&DAT_00016540,(ulonglong)uVar3,uVar10);
            lVar4 = local_2ac8;
            if (DAT_000189e8 != (int *)0x0) {
              FUN_0001250c((char *)((longlong)DAT_000189e8 + uVar10),(ulonglong)uVar3,pcVar2);
              uVar10 = uVar10 + uVar3;
              local_res18[0] = sVar12 + 1;
              local_a18 = local_a18 | 1;
              lVar4 = local_2ac8;
              sVar13 = local_res18[0];
              local_2ad0 = uVar10;
              local_a10 = sVar12;
            }
          }
        }
        iVar14 = 1;
        if (*(char *)(lVar4 + 4) == '\0') {
          local_2ad8 = (char *)0x0;
        }
        else {
          lVar4 = FUN_0001598c((char *)((ulonglong)*(byte *)(lVar4 + 1) + lVar4),
                               *(char *)(lVar4 + 4),&local_2ad8);
          pcVar2 = local_2ad8;
          if (-1 < lVar4) {
            uVar3 = uVar15;
            if (local_2ad8 != (char *)0x0) {
              uVar5 = FUN_000124e0(local_2ad8,0x200);
              uVar3 = (int)uVar5 + iVar14;
            }
            FUN_000161bc((longlong *)&DAT_000189e8,&DAT_00016540,(ulonglong)uVar3,uVar10);
            if (DAT_000189e8 != (int *)0x0) {
              FUN_0001250c((char *)((longlong)DAT_000189e8 + uVar10),(ulonglong)uVar3,pcVar2);
              local_2ad0 = uVar10 + uVar3;
              local_res18[0] = sVar13 + 1;
              local_29bb = local_29bb | 8;
              local_9ce = sVar13;
            }
          }
        }
        local_9c0 = FUN_00013570(0,(ulonglong)local_2a80 << 7);
        piVar9 = DAT_000189e8;
        if (local_9c0 != (undefined8 *)0x0) {
          if ((uint)local_2a7e == (uint)local_2a7f * 2) {
            local_29ba = local_29ba | 4;
            local_2a60 = 1;
          }
          bVar11 = 0;
          if (local_2a7f != 0) {
            do {
              FUN_0000ab50((longlong)&local_2a80,0,bVar11,&local_2ad0,local_res18);
              bVar11 = bVar11 + 1;
            } while (bVar11 < local_2a7f);
          }
          piVar9 = DAT_000189e8;
          bVar11 = local_2a7f;
          if (local_2a80 != local_2a7f) {
            for (; piVar9 = DAT_000189e8, bVar11 < local_2a80; bVar11 = bVar11 + 1) {
              FUN_0000ab50((longlong)&local_2a80,1,bVar11,&local_2ad0,local_res18);
            }
          }
        }
      }
      lVar4 = FUN_00015ebc(param_1,local_29b0,piVar9);
      if (DAT_000189e8 != (int *)0x0) {
        (**(code **)(DAT_00018a28 + 0x48))();
        DAT_000189e8 = (int *)0x0;
        DAT_00016540 = 0x2000;
      }
      if (-1 < lVar4) {
        pcVar8 = FUN_0000049c;
        uVar10 = uVar16;
        do {
          (*pcVar8)(param_1,&local_2aa8);
          uVar10 = (ulonglong)((int)uVar10 + 1);
          pcVar8 = *(code **)(&DAT_00018580 + uVar10 * 8);
        } while (pcVar8 != (code *)0x0);
        if ((ulonglong *)(param_1 + 0x328) != (ulonglong *)0x0) {
          FUN_000158e0((ulonglong *)(param_1 + 0x328),&local_2aa8,0x2470);
        }
        uVar17 = uVar17 + 1;
      }
      lVar4 = (**(code **)(DAT_000189c0 + 0x18))(DAT_000189c0,local_res20,local_res10,&local_2ac8,0)
      ;
    } while (-1 < lVar4);
    if (uVar17 != 0) {
      *(undefined1 *)(param_1 + 0xe) = 1;
    }
  }
  return;
}

