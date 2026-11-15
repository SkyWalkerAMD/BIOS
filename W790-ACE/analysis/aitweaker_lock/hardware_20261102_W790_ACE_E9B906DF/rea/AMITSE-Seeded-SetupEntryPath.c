
ulonglong Candidate_SetupEntryPath(longlong param_1)

{
  char *pcVar1;
  ushort *puVar2;
  char cVar3;
  bool bVar4;
  undefined8 uVar5;
  ulonglong uVar6;
  longlong lVar7;
  longlong extraout_RAX;
  undefined8 *puVar8;
  undefined8 *puVar9;
  undefined8 *puVar10;
  word *pwVar11;
  ulonglong uVar12;
  short *psVar13;
  word *pwVar14;
  longlong *plVar15;
  uint uVar16;
  byte bVar17;
  ulonglong uVar18;
  longlong lVar19;
  longlong lVar20;
  undefined8 *local_res10;
  ulonglong local_res18;
  ulonglong local_res20;
  word *local_68;
  short *local_60;
  undefined8 local_58;
  longlong local_50;
  undefined8 *local_48;
  
  uVar18 = 0;
  local_60 = (short *)0x0;
  local_res18 = 0;
  local_68 = (word *)0x0;
  local_res10 = (undefined8 *)0x0;
  local_res20 = 0;
  DAT_0008b440 = '\x01';
  uVar5 = (**(code **)(DAT_000824c8 + 0x18))(0x1f);
  pwVar11 = &IMAGE_DOS_HEADER_00000000.e_cp;
  local_58 = uVar5;
  (**(code **)(DAT_000824c8 + 0x20))();
  cVar3 = FUN_00056d0c();
  if (cVar3 == '\0') {
    FUN_00058b98(&local_68,&local_res10);
    pwVar14 = local_68;
    pwVar11 = local_68;
    uVar6 = FUN_00056a88((longlong)local_68,(longlong)local_res10 + 1);
    if (pwVar14 != (word *)0x0) {
      (**(code **)(DAT_000824c8 + 0x48))();
      pwVar11 = pwVar14;
    }
    if (DAT_0008b440 == '\0') goto LAB_00057c86;
  }
  if ((DAT_00092b08 == 0) || (DAT_00092278 == 0)) {
    if (DAT_00082a78 == (word *)0x0) {
      DAT_00082a78 = DAT_000824c0;
      DAT_00082a68 = *(undefined8 *)(DAT_000824c0 + 0x30);
      DAT_00082a80 = *(undefined8 *)(DAT_000824c0 + 0x2c);
      DAT_00082a70 = DAT_000824d0;
      pwVar11 = DAT_000824c0;
    }
    lVar7 = FUN_00044b58((longlong)pwVar11);
    if (-1 < lVar7) {
      FUN_0000ebf4();
      goto LAB_00057968;
    }
  }
  else {
LAB_00057968:
    uVar6 = 0;
    lVar7 = FUN_00010a94(pwVar11,0);
    if ((((-1 < lVar7) && (uVar6 = FUN_0002a57c((undefined8 **)pwVar11,uVar6), -1 < (longlong)uVar6)
         ) && (lVar7 = FUN_00010cc8(), -1 < lVar7)) &&
       ((FUN_00056bd8(), -1 < extraout_RAX && (DAT_0008b440 != '\0')))) {
      lVar7 = (ulonglong)*(uint *)(param_1 + 0x10) + param_1;
      local_50 = lVar7;
      puVar8 = FUN_00065250((byte *)(lVar7 + 0xc));
      local_48 = puVar8;
      if ((puVar8 == (undefined8 *)0x0) ||
         ((puVar9 = FUN_00066278((longlong)puVar8,s_ConfigurationData_0007f2d8),
          puVar9 == (undefined8 *)0x0 ||
          (plVar15 = (longlong *)puVar9[2], uVar6 = uVar18, plVar15 == (longlong *)0x0)))) {
LAB_00057c6e:
        uVar6 = 0x8000000000000002;
        puVar8 = (undefined8 *)0x0;
      }
      else {
        do {
          plVar15 = (longlong *)*plVar15;
          uVar16 = (int)uVar6 + 1;
          uVar6 = (ulonglong)uVar16;
        } while (plVar15 != (longlong *)0x0);
        if (uVar16 == 0) goto LAB_00057c6e;
        if ((DAT_0008f9d8 != 0) && (DAT_0008f9c8 != 0)) {
          puVar10 = puVar9;
          FUN_00057754((longlong)puVar9,0x8000000000000003);
          FUN_00057dfc(puVar10);
          if ((*(int *)(puVar9 + 3) == 6) &&
             (puVar10 = FUN_000567c0((longlong)puVar9,&local_res20), uVar5 = local_58,
             local_res20 != 0)) {
            bVar17 = 0;
            uVar6 = uVar18;
            do {
              pcVar1 = (char *)puVar10[uVar18];
              puVar8 = puVar9;
              local_res10 = FUN_00066278((longlong)puVar9,pcVar1);
              lVar7 = 0;
              cVar3 = *pcVar1;
              while (cVar3 != '\0') {
                lVar7 = lVar7 + 1;
                cVar3 = pcVar1[lVar7];
              }
              pwVar11 = (word *)FUN_0003eea8(puVar8,lVar7 * 2 + 2);
              puVar2 = (ushort *)puVar10[uVar18];
              lVar7 = 0;
              cVar3 = (char)*puVar2;
              while (cVar3 != '\0') {
                lVar7 = lVar7 + 1;
                cVar3 = *(char *)((longlong)puVar2 + lVar7);
              }
              local_68 = pwVar11;
              FUN_0003ea9c(puVar2,pwVar11,lVar7 + 1);
              if (pwVar11 == (word *)0x0) {
                uVar12 = 0x8000000000000002;
              }
              else {
                uVar12 = FUN_00058374((short *)pwVar11,&local_res18);
                uVar6 = local_res18;
              }
              if ((longlong)uVar12 < 0) {
                FUN_000580c0(-1,(char *)puVar10[uVar18],uVar12);
              }
              else {
                lVar19 = uVar6 * 0x30;
                lVar20 = DAT_0008f9d8 + lVar19;
                lVar7 = lVar20;
                bVar4 = FUN_00056d70(lVar20,(longlong)local_res10);
                if (bVar4) {
                  psVar13 = (short *)FUN_0003eea8(lVar7,*(ulonglong *)(lVar20 + 0x18));
                  uVar6 = local_res18;
                  local_60 = psVar13;
                  if (psVar13 != (short *)0x0) {
                    uVar6 = FUN_000572dc((longlong)local_res10,psVar13,DAT_0008f9d8 + lVar19);
                    if ((longlong)uVar6 < 0) {
                      uVar6 = 0x800000000000000e;
                      goto LAB_00057bc7;
                    }
                    lVar7 = *(longlong *)
                             (DAT_0008fa08 + *(longlong *)(lVar19 + 8 + DAT_0008f9d8) * 0x10);
                    if (lVar7 == 0) goto LAB_00057bc4;
                    (**(code **)(DAT_000824c8 + 0x160))
                              (*(longlong *)(lVar19 + 0x10 + DAT_0008f9d8) + lVar7,psVar13);
                    uVar6 = local_res18;
                    FUN_000580c0(local_res18,(char *)puVar10[uVar18],0);
                  }
                }
                else {
LAB_00057bc4:
                  uVar6 = 0x8000000000000002;
LAB_00057bc7:
                  FUN_000580c0(-1,(char *)puVar10[uVar18],uVar6);
                  uVar6 = local_res18;
                }
              }
              FUN_00005958((longlong *)&local_68);
              FUN_00005958((longlong *)&local_60);
              bVar17 = bVar17 + 1;
              uVar18 = (ulonglong)bVar17;
              lVar7 = local_50;
              puVar8 = local_48;
              uVar5 = local_58;
            } while (uVar18 < local_res20);
          }
          FUN_000064e4(&DAT_0006a230);
          FUN_00057f8c();
          uVar6 = FUN_000575dc(0,*(undefined4 *)(lVar7 + 4));
          if (DAT_0008fa08 != 0) {
            FUN_000595a4();
          }
          FUN_000648a0(puVar8);
          FUN_000648a0(DAT_0008f9e8);
          goto LAB_00057c86;
        }
        uVar6 = 0x8000000000000003;
      }
      FUN_00057754((longlong)puVar8,uVar6);
      FUN_000575dc(uVar6,*(undefined4 *)(lVar7 + 4));
      goto LAB_00057c86;
    }
  }
  uVar6 = 0x8000000000000002;
LAB_00057c86:
  if (DAT_0008f9e0 != (undefined8 *)0x0) {
    FUN_000648a0(DAT_0008f9e0);
    DAT_0008f9e0 = (undefined8 *)0x0;
  }
  (**(code **)(DAT_000824c8 + 0x18))(0x1f);
  (**(code **)(DAT_000824c8 + 0x20))(uVar5);
  return uVar6;
}

