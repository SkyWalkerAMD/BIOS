
longlong FUN_000089c4(undefined8 param_1,ulonglong param_2)

{
  ulonglong uVar1;
  char cVar2;
  char *pcVar3;
  longlong lVar4;
  longlong lVar5;
  short *psVar6;
  short *local_res10;
  longlong local_res18;
  
  uVar1 = param_2 + 0x100;
  local_res18 = 0;
  local_res10 = (short *)0x0;
  pcVar3 = (char *)FUN_000041f4(uVar1);
  if (pcVar3 == (char *)0x0) {
    lVar4 = -0x7ffffffffffffff7;
  }
  else {
    if (DAT_000168b0 == 0) {
      FUN_00002e48(pcVar3,uVar1,(byte *)s_POST__redfish_v1_Systems_Self_Bi_00015a70,param_2);
    }
    else {
      FUN_00002e48(pcVar3,uVar1,(byte *)s_POST__a_Bios_HTTP_1_1_Content_le_00015a10,DAT_000168b0);
    }
    lVar4 = 0;
    cVar2 = *pcVar3;
    while (cVar2 != '\0') {
      lVar4 = lVar4 + 1;
      cVar2 = pcVar3[lVar4];
    }
    lVar5 = (**(code **)(DAT_00016980 + 0x98))(DAT_00018288,&DAT_00013a10,&DAT_000168d8);
    if (lVar5 < 0) {
      lVar4 = -0x7ffffffffffffff9;
      psVar6 = (short *)0x0;
    }
    else {
      lVar4 = FUN_00008288(pcVar3,(uint)lVar4,&local_res10,&local_res18);
      lVar5 = local_res18;
      psVar6 = local_res10;
      if ((local_res18 != 0) &&
         (cVar2 = FUN_00003cbc(&DAT_00013b00,1), psVar6 = local_res10, cVar2 != '\0')) {
        FUN_00002d80('\0',0x15ae8,local_res10,lVar5);
      }
    }
    (**(code **)(DAT_00016838 + 0x48))(pcVar3);
    if (psVar6 != (short *)0x0) {
      (**(code **)(DAT_00016838 + 0x48))(psVar6);
    }
  }
  return lVar4;
}



/* WARNING: Type propagation algorithm not settling */

longlong FUN_000022e0(void)

{
  char cVar1;
  longlong lVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  short *psVar5;
  longlong lVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  byte *pbVar10;
  byte *local_res8;
  longlong local_res10 [2];
  char local_d8 [80];
  char local_88 [80];
  
  uVar7 = 0;
  local_res10[1] = 0;
  lVar2 = (**(code **)(DAT_00016980 + 0x140))(&DAT_00013b40,0,&DAT_000168f0);
  if (lVar2 < 0) {
    return lVar2;
  }
  lVar2 = (*(code *)*DAT_000168f0)(local_res10 + 1);
  if (-1 < lVar2) {
    return lVar2;
  }
  local_res8 = (byte *)0x0;
  local_res10[0] = 0;
  lVar2 = FUN_00008850(&local_res8,local_res10);
  pbVar10 = local_res8;
  if (lVar2 < 0) {
    return lVar2;
  }
  if (local_res10[0] == 0) {
    return lVar2;
  }
  if (local_res8 == (byte *)0x0) {
    return lVar2;
  }
  puVar3 = FUN_00004e84(local_res8);
  if (puVar3 == (undefined8 *)0x0) {
    lVar2 = -0x7fffffffffffffff;
    goto LAB_000024a6;
  }
  puVar4 = FUN_00005e54((longlong)puVar3,s_Attributes_00014e78);
  if (puVar4 != (undefined8 *)0x0) {
    puVar4 = FUN_00005e54((longlong)puVar4,s_MAPIDS_00014e84);
    if (puVar4 != (undefined8 *)0x0) {
      cVar1 = *(char *)puVar4[5];
      uVar9 = uVar7;
      while (cVar1 != '\0') {
        uVar9 = uVar9 + 1;
        cVar1 = ((char *)puVar4[5])[uVar9];
      }
      DAT_00016898 = 0;
      uVar8 = uVar7;
      if (uVar9 == 0) goto LAB_00002492;
      do {
        lVar6 = 0;
        cVar1 = *(char *)(uVar8 + puVar4[5]);
        pbVar10 = local_res8;
        if (cVar1 == '\0') break;
        if (cVar1 == ',') {
          local_d8[uVar7] = '\0';
          cVar1 = local_d8[0];
          for (; (cVar1 != '\0' && (local_d8[lVar6] != ':')); lVar6 = lVar6 + 1) {
            local_88[lVar6] = local_d8[lVar6];
            cVar1 = local_d8[lVar6 + 1];
          }
          local_88[lVar6] = '\0';
          psVar5 = (short *)FUN_00002578(local_88);
          if (psVar5 != (short *)0x0) {
            FUN_000008c4(psVar5,local_d8[lVar6 + 1] != '0');
            (**(code **)(DAT_00016838 + 0x48))(psVar5);
          }
          uVar7 = 0;
        }
        else {
          local_d8[uVar7] = cVar1;
          uVar7 = uVar7 + 1;
        }
        uVar8 = (ulonglong)((int)uVar8 + 1);
        pbVar10 = local_res8;
      } while (uVar8 < uVar9);
    }
    if (DAT_00016898 != 0) {
      (*(code *)DAT_000168f0[1])();
    }
  }
LAB_00002492:
  FUN_000043f4(puVar3);
LAB_000024a6:
  (**(code **)(DAT_00016838 + 0x48))(pbVar10);
  return lVar2;
}



longlong FUN_00007f7c(longlong *param_1,undefined8 *param_2)

{
  longlong lVar1;
  undefined *puVar2;
  longlong lVar3;
  char *pcVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  char *local_res8;
  char local_1018 [4096];
  
  lVar1 = 0;
  if ((param_1 == (longlong *)0x0) && (param_2 == (undefined8 *)0x0)) {
    lVar1 = -0x7ffffffffffffffe;
  }
  else {
    *param_2 = 0;
    lVar3 = DAT_00014648;
    *param_1 = 0;
    if (lVar3 == 0) {
      uVar5 = 1;
      local_res8 = FUN_00005e90(0,1,(char *)0x0,(char *)0x0);
      FUN_00008134((longlong *)&local_res8,uVar5);
      FUN_00013730((undefined4 *)local_1018,0,0x1000);
      FUN_000066cc();
      FUN_00006688();
      FUN_00006644();
      puVar2 = FUN_00006600();
      uVar5 = 0x1000;
      pcVar4 = local_1018;
      FUN_00002e48(pcVar4,0x1000,(byte *)s___odata_context_____redfish_v1___00015550,
                   (ulonglong)puVar2);
      FUN_000062fc(pcVar4,uVar5,local_1018);
      uVar5 = 2;
      local_res8 = FUN_00005e90(0,2,s_Attributes_00014e78,(char *)0x0);
      FUN_00008134((longlong *)&local_res8,uVar5);
      lVar1 = FUN_00007630();
      uVar5 = 2;
      uVar6 = 1;
      local_res8 = FUN_00005e90(1,2,(char *)0x0,(char *)0x0);
      FUN_00008134((longlong *)&local_res8,uVar5);
      if (DAT_000168e8 != 0) {
        FUN_00007470();
      }
      FUN_00008134((longlong *)&local_res8,uVar5);
      local_res8 = FUN_00005e90(1,1,(char *)0x0,(char *)0x0);
      FUN_00008134((longlong *)&local_res8,uVar6);
      lVar3 = DAT_00014648;
      if (DAT_00014648 == 0) {
        return lVar1;
      }
    }
    *param_1 = lVar3;
    *param_2 = DAT_00014650;
    DAT_00014648 = 0;
    DAT_00014650 = 0;
  }
  return lVar1;
}

