
short * FUN_00001f7c(undefined8 *param_1,longlong param_2,longlong param_3,char *param_4)

{
  longlong lVar1;
  longlong lVar2;
  longlong lVar3;
  longlong lVar4;
  short *psVar5;
  short *psVar6;
  short *psVar7;
  ulonglong uVar8;
  byte *pbVar9;
  ulonglong uVar10;
  ushort *puVar11;
  byte bVar12;
  byte bVar13;
  short *psVar14;
  short *psVar15;
  short *psVar16;
  bool bVar17;
  longlong local_res10;
  longlong local_res18;
  short *local_res20;
  short *local_68;
  short *local_60;
  short *local_58;
  short *local_50;
  ulonglong *local_48 [2];
  
  psVar7 = (short *)0x0;
  local_res20 = (short *)0x0;
  local_60 = (short *)0x0;
  local_68 = (short *)0x0;
  local_50 = (short *)0x0;
  psVar15 = (short *)0x0;
  local_res10 = 0;
  local_res18 = param_3;
  (**(code **)(DAT_0001e070 + 0x140))(&DAT_000198e0,0,&local_res10);
  local_58 = (short *)0x0;
  lVar2 = (**(code **)(DAT_0001e070 + 0x140))(&DAT_000198d0,0,&local_58);
  if (-1 < lVar2) {
    (**(code **)(local_58 + 0xc))(local_58);
  }
  lVar2 = (**(code **)(param_2 + 0x10))(param_2,0,&local_68);
  psVar6 = psVar7;
  psVar5 = psVar7;
  psVar14 = psVar7;
  psVar16 = psVar7;
  if (lVar2 < 0) goto LAB_00002389;
  lVar3 = (**(code **)(param_2 + 8))(param_2,0,&local_50);
  lVar2 = 0;
  psVar6 = (short *)0x0;
  psVar5 = (short *)0x0;
  psVar14 = (short *)0x0;
  psVar16 = psVar15;
  if (lVar3 < 0) goto LAB_00002389;
  lVar3 = lVar2;
  for (psVar5 = local_68; *psVar5 != 0; psVar5 = psVar5 + 1) {
    lVar3 = lVar3 + 1;
  }
  do {
    lVar4 = lVar2 + 1;
    lVar1 = lVar2 + 1;
    lVar2 = lVar4;
  } while (s_PCIeDevices_0001a120[lVar1] != '\0');
  uVar8 = (lVar4 + lVar3) * 2 + 4;
  psVar5 = (short *)FUN_00015ad4(uVar8);
  local_58 = psVar5;
  if (psVar5 == (short *)0x0) goto LAB_00002386;
  FUN_00015bfc((char *)psVar5,uVar8,(byte *)u__s__a_0001a130,(ulonglong)local_68);
  psVar6 = (short *)FUN_00016b80();
  if (psVar6 != (short *)0x0) {
    psVar6[0xc] = 6;
    psVar6[0xd] = 0;
    psVar7 = (short *)FUN_00016b80();
    if (psVar7 != (short *)0x0) {
      psVar7[0xc] = 6;
      psVar7[0xd] = 0;
      lVar2 = FUN_00001a64(local_res18,(longlong)psVar7);
      psVar15 = psVar7;
      if (-1 < lVar2) {
        FUN_00001ea4(param_1,param_2,local_res18);
        lVar2 = FUN_000011cc(local_res18,(longlong)psVar6);
        if (-1 < lVar2) {
          local_48[0] = (ulonglong *)0x0;
          lVar2 = (**(code **)(DAT_0001e070 + 0x140))(&DAT_00019920,0,local_48);
          if (-1 < lVar2) {
            if (1 < *local_48[0]) {
              lVar2 = (*(code *)local_48[0][2])(local_48[0],psVar6);
            }
            psVar14 = local_res20;
            psVar16 = psVar7;
            if (-1 < lVar2) {
              if (param_4[1] != '\0') {
                FUN_00000d64(local_res10,0x1a140);
                uVar8 = FUN_000068cc(param_1,param_2);
                if (-1 < (longlong)uVar8) {
                  FUN_00000d64(local_res10,0x1a180);
                  pbVar9 = FUN_00006014(param_1,param_2,local_res18,(longlong)psVar6);
                  if (-1 < (longlong)pbVar9) {
                    param_4[1] = '\0';
                  }
                }
              }
              if ((*param_4 != '\0') &&
                 (lVar2 = (**(code **)(param_2 + 8))(param_2,s_Processors_0001a1c0,&local_60),
                 -1 < lVar2)) {
                FUN_00000d64(local_res10,0x1a1d0);
                uVar8 = FUN_00019114(param_1,local_60);
                if ((-1 < (longlong)uVar8) ||
                   (uVar8 = FUN_0000ec28(param_1,local_60), -1 < (longlong)uVar8)) {
                  FUN_00000d64(local_res10,0x1a208);
                  uVar8 = FUN_0000f554(param_1,local_res18,local_60,(longlong)psVar6);
                }
                (**(code **)(DAT_0001e070 + 0x48))(local_60);
                psVar5 = local_58;
                if (-1 < (longlong)uVar8) {
                  *param_4 = '\0';
                }
              }
              if (param_4[2] != '\0') {
                FUN_00000d64(local_res10,0x1a240);
                uVar8 = FUN_00019114(param_1,psVar5);
                if ((-1 < (longlong)uVar8) ||
                   (uVar8 = FUN_00007270(param_1,local_50), -1 < (longlong)uVar8)) {
                  FUN_00000d64(local_res10,0x1a278);
                  uVar8 = FUN_000073e0(param_1,local_res18,(longlong)psVar6,(longlong)psVar7,
                                       (ulonglong)local_68);
                }
                FUN_00000d64(local_res10,0x1a2b0);
                uVar10 = FUN_00004654(param_1,param_2);
                bVar17 = (longlong)uVar10 < 0;
                if (!bVar17) {
                  FUN_00000d64(local_res10,0x1a2f0);
                  puVar11 = FUN_00005624(param_1,param_2,local_res18,(longlong)psVar6);
                  bVar17 = (longlong)puVar11 < 0;
                }
                bVar12 = (byte)(uVar8 >> 0x3f);
                if (bVar17) {
                  bVar12 = 1;
                }
                FUN_00000d64(local_res10,0x1a330);
                puVar11 = (ushort *)FUN_0000794c(param_1,param_2);
                if (-1 < (longlong)puVar11) {
                  FUN_00000d64(local_res10,0x1a370);
                  puVar11 = FUN_000085d8(param_1,param_2,local_res18);
                }
                bVar13 = 1;
                if (-1 < (longlong)puVar11) {
                  bVar13 = bVar12;
                }
                param_4[2] = bVar13;
              }
              FUN_00003428(param_1,local_68,(longlong)psVar7);
              FUN_00003428(param_1,local_50,(longlong)psVar6);
              psVar5 = local_58;
              psVar14 = local_res20;
            }
            goto LAB_00002389;
          }
          goto LAB_00002413;
        }
      }
LAB_00002386:
      psVar14 = (short *)0x0;
      psVar16 = psVar15;
      goto LAB_00002389;
    }
  }
LAB_00002413:
  psVar14 = (short *)0x0;
  psVar16 = psVar7;
LAB_00002389:
  if (((*param_4 != '\0') || (param_4[1] != '\0')) || (param_4[2] != '\0')) {
    psVar14 = (short *)0x8000000000000001;
  }
  if (psVar16 != (short *)0x0) {
    FUN_00016bcc((undefined8 *)psVar16);
  }
  if (psVar6 != (short *)0x0) {
    FUN_00016bcc((undefined8 *)psVar6);
  }
  if (local_68 != (short *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))();
  }
  if (local_50 != (short *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))();
  }
  if (psVar5 != (short *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))(psVar5);
  }
  return psVar14;
}

