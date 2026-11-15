
ulonglong FUN_00002780(undefined8 *param_1,short *param_2)

{
  byte bVar1;
  short sVar2;
  longlong lVar3;
  char *pcVar4;
  longlong *plVar5;
  longlong lVar6;
  ulonglong uVar7;
  wchar_t *pwVar8;
  short *psVar9;
  undefined8 *puVar10;
  undefined1 *puVar11;
  undefined1 *puVar12;
  byte *pbVar13;
  longlong *plVar14;
  byte *pbVar15;
  byte *pbVar16;
  int local_res18 [2];
  undefined4 local_res20 [2];
  undefined8 local_48 [2];
  
  pbVar16 = (byte *)0x0;
  local_res18[0] = 0;
  lVar6 = FUN_00015a68();
  lVar6 = (**(code **)(lVar6 + 0x20))(599);
  if ((lVar6 == 0) || (lVar3 = *(longlong *)(lVar6 + 0xc), lVar3 == 0)) {
    return 0x800000000000000e;
  }
  if (*(longlong *)(lVar3 + 8) == 0) {
    return 0;
  }
  local_48[0] = 4;
  uVar7 = (**(code **)(DAT_0001e078 + 0x48))
                    (u_RfPcieFunListCrc_0001a598,&DAT_00019930,0,local_48,local_res18);
  if ((-1 < (longlong)uVar7) && (*(int *)(lVar6 + 8) == local_res18[0])) {
    return uVar7;
  }
  sVar2 = *param_2;
  psVar9 = param_2;
  pbVar15 = pbVar16;
  while (sVar2 != 0) {
    psVar9 = psVar9 + 1;
    pbVar15 = pbVar15 + 1;
    sVar2 = *psVar9;
  }
  pwVar8 = u__Oem_Ami_MapoutPorting_0001a5c0;
  pbVar13 = pbVar16;
  do {
    pwVar8 = pwVar8 + 1;
    pbVar13 = pbVar13 + 1;
  } while (*pwVar8 != L'\0');
  uVar7 = (longlong)(pbVar13 + (longlong)pbVar15) * 2 + 2;
  psVar9 = (short *)FUN_00015ad4(uVar7);
  if (psVar9 == (short *)0x0) {
    return 0x8000000000000009;
  }
  FUN_00015bfc((char *)psVar9,uVar7,(byte *)u__s_s_0001a5f0,(ulonglong)param_2);
  puVar10 = (undefined8 *)FUN_00016b80();
  if (puVar10 == (undefined8 *)0x0) {
    uVar7 = 0x8000000000000009;
    goto LAB_000029f0;
  }
  *(undefined4 *)(puVar10 + 3) = 6;
  puVar11 = FUN_00016b80();
  if (puVar11 == (undefined1 *)0x0) {
LAB_000029c0:
    uVar7 = 0x8000000000000009;
  }
  else {
    *(undefined4 *)(puVar11 + 0x18) = 5;
    FUN_00018744((longlong)puVar10,s_PcieFunctionList_0001a600,(longlong)puVar11);
    if (*(longlong *)(lVar3 + 8) != 0) {
      do {
        pcVar4 = *(char **)(*(longlong *)(lVar3 + 0x10) + (longlong)pbVar16 * 8);
        if (pcVar4 != (char *)0x0) {
          puVar12 = FUN_0001880c(pcVar4);
          if (puVar12 != (undefined1 *)0x0) {
            plVar5 = *(longlong **)(puVar11 + 0x10);
            if (*(longlong **)(puVar11 + 0x10) == (longlong *)0x0) {
              *(undefined1 **)(puVar11 + 0x10) = puVar12;
            }
            else {
              do {
                plVar14 = plVar5;
                plVar5 = (longlong *)*plVar14;
              } while ((longlong *)*plVar14 != (longlong *)0x0);
              *plVar14 = (longlong)puVar12;
              *(longlong **)(puVar12 + 8) = plVar14;
            }
          }
          pbVar16 = pbVar16 + 1;
        }
      } while (pbVar16 < *(byte **)(lVar3 + 8));
    }
    pbVar16 = FUN_0001784c((longlong)puVar10,0,1,(longlong *)0x0);
    if (pbVar16 == (byte *)0x0) goto LAB_000029c0;
    uVar7 = 0;
    bVar1 = *pbVar16;
    while (bVar1 != 0) {
      uVar7 = uVar7 + 1;
      bVar1 = pbVar16[uVar7];
    }
    uVar7 = FUN_00019384(param_1,psVar9,(char *)pbVar16,uVar7,(undefined8 *)0x0);
    if (-1 < (longlong)uVar7) {
      local_res20[0] = *(undefined4 *)(lVar6 + 8);
      uVar7 = (**(code **)(DAT_0001e078 + 0x58))
                        (u_RfPcieFunListCrc_0001a598,&DAT_00019930,3,4,local_res20);
    }
  }
  FUN_00016bcc(puVar10);
  if (pbVar16 != (byte *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))(pbVar16);
  }
LAB_000029f0:
  (**(code **)(DAT_0001e070 + 0x48))(psVar9);
  return uVar7;
}

