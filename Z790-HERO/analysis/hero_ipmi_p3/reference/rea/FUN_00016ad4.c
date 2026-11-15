
void FUN_00016ad4(longlong *param_1)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  short sVar4;
  undefined2 uVar5;
  longlong lVar6;
  short *psVar7;
  ulonglong uVar8;
  undefined1 *puVar9;
  short *psVar10;
  short *psVar11;
  short *local_res8;
  longlong local_res10;
  
  pbVar2 = (byte *)param_1[5];
  local_res10 = param_1[6];
  bVar1 = pbVar2[1];
  lVar6 = FUN_00028694((longlong)DAT_00193888,(longlong)param_1);
  psVar7 = (short *)0x0;
  if (lVar6 != 0) {
    puVar9 = (undefined1 *)((ulonglong)(bVar1 & 0x7f) + lVar6);
    uVar8 = (ulonglong)((pbVar2 + (bVar1 & 0x7f))[1] & 0x7f);
    psVar10 = psVar7;
    psVar11 = psVar7;
    if (DAT_00193888 != (short *)0x0) {
      do {
        (**(code **)(DAT_00180188 + 0x160))(puVar9,pbVar2 + (bVar1 & 0x7f),uVar8);
        sVar4 = FUN_00033b88(DAT_00193900,*(short *)((longlong)psVar11 + DAT_00193890 + 0x18),
                             *(longlong *)((longlong)psVar11 + DAT_00193890 + 0x10));
        *(short *)((longlong)psVar11 + DAT_00193890 + 0x18) = sVar4;
        *(short *)(puVar9 + 6) = (short)psVar10;
        psVar10 = (short *)((longlong)psVar10 + 1);
        puVar9[4] = 1;
        *(short *)(puVar9 + 2) = sVar4;
        puVar9 = puVar9 + uVar8;
        psVar11 = psVar11 + 0x10;
      } while (psVar10 < DAT_00193888);
    }
    puVar9[1] = puVar9[1] & 0x82;
    puVar9[1] = puVar9[1] | 2;
    *puVar9 = 0x29;
    sVar4 = FUN_00026be4(pbVar2);
    local_res8 = psVar7;
    if (sVar4 != -1) {
      local_res8 = (short *)FUN_000484c8(*param_1,sVar4,(short *)0x0);
    }
    uVar5 = FUN_00017624(DAT_00193900,local_res8);
    pbVar3 = (byte *)param_1[5];
    if ((4 < *pbVar3) &&
       ((((*pbVar3 < 9 || (*pbVar3 == 0xf)) || ((byte)(*pbVar3 - 0x1a) < 3)) || (*pbVar3 == 0x23))))
    {
      *(undefined2 *)(pbVar3 + 2) = uVar5;
    }
    FUN_000013d0((longlong *)&local_res8);
    sVar4 = FUN_00026b90(pbVar2);
    if (sVar4 != -1) {
      psVar7 = (short *)FUN_000484c8(*param_1,sVar4,(short *)0x0);
    }
    local_res8 = psVar7;
    uVar5 = FUN_00017624(DAT_00193900,psVar7);
    *(undefined2 *)(param_1 + 4) = uVar5;
    *param_1 = DAT_00193900;
    FUN_000013d0((longlong *)&local_res8);
    FUN_000013d0(&local_res10);
  }
  return;
}

