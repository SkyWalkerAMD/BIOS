
undefined8 FUN_00001a64(longlong param_1,longlong param_2)

{
  int iVar1;
  undefined1 *puVar2;
  undefined1 *puVar3;
  longlong lVar4;
  undefined8 uVar5;
  char *pcVar6;
  char *pcVar7;
  char local_38 [48];
  
  if ((*(byte *)(param_1 + 0x1b8) & 2) != 0) {
    puVar2 = FUN_0001880c(*(char **)(param_1 + 0x2e8));
    FUN_00018744(param_2,s_AssetTag_00019f10,(longlong)puVar2);
  }
  if ((*(byte *)(param_1 + 0x1b8) & 8) != 0) {
    puVar2 = FUN_0001880c(*(char **)(param_1 + 0x2f8));
    FUN_00018744(param_2,s_Description_00019f20,(longlong)puVar2);
  }
  if ((*(byte *)(param_1 + 0x1b8) & 0x10) != 0) {
    puVar2 = FUN_0001880c(*(char **)(param_1 + 0x300));
    FUN_00018744(param_2,s_Manufacturer_00019f30,(longlong)puVar2);
  }
  if ((*(byte *)(param_1 + 0x1b8) & 0x20) != 0) {
    puVar2 = FUN_0001880c(*(char **)(param_1 + 0x308));
    FUN_00018744(param_2,s_Model_00019f40,(longlong)puVar2);
  }
  if ((*(byte *)(param_1 + 0x1b8) & 0x40) != 0) {
    puVar2 = FUN_0001880c(*(char **)(param_1 + 0x310));
    FUN_00018744(param_2,s_PartNumber_00019f58,(longlong)puVar2);
  }
  if (0x7f < *(byte *)(param_1 + 0x1b8)) {
    puVar2 = FUN_0001880c(*(char **)(param_1 + 0x318));
    FUN_00018744(param_2,s_SerialNumber_00019f68,(longlong)puVar2);
  }
  if ((*(byte *)(param_1 + 0x1b9) & 1) != 0) {
    puVar2 = FUN_0001880c(*(char **)(param_1 + 800));
    FUN_00018744(param_2,&DAT_00019f84,(longlong)puVar2);
  }
  pcVar7 = &DAT_00019a68;
  if ((*(byte *)(param_1 + 0x1b9) & 2) != 0) {
    iVar1 = *(int *)(param_1 + 0x150);
    if (iVar1 == 0) {
      pcVar6 = &DAT_00019a68;
    }
    else if (iVar1 == 1) {
LAB_00001bca:
      pcVar6 = &DAT_00019aa4;
    }
    else if (iVar1 == 2) {
      pcVar6 = s_PoweringOff_00019aa8;
    }
    else {
      if (iVar1 != 3) goto LAB_00001bca;
      pcVar6 = s_PoweringOn_00019ab8;
    }
    puVar2 = FUN_0001880c(pcVar6);
    FUN_00018744(param_2,s_PowerState_00019fe8,(longlong)puVar2);
  }
  if ((*(byte *)(param_1 + 0x1b9) & 8) != 0) {
    FUN_00015c2c(local_38,0x25,&DAT_00019f88,param_1 + 0x154);
    puVar2 = FUN_0001880c(local_38);
    FUN_00018744(param_2,&DAT_00019f8c,(longlong)puVar2);
  }
  puVar2 = FUN_00016b80();
  if (puVar2 == (undefined1 *)0x0) {
    return 0x8000000000000009;
  }
  *(undefined4 *)(puVar2 + 0x18) = 6;
  FUN_00018744(param_2,s_Status_00019fc8,(longlong)puVar2);
  if ((*(byte *)(param_1 + 0x1b9) & 0x40) == 0) {
    pcVar6 = s_Enabled_00019ca8;
  }
  else {
    pcVar6 = FUN_00000b8c(*(int *)(param_1 + 0x16c));
  }
  puVar3 = FUN_0001880c(pcVar6);
  FUN_00018744((longlong)puVar2,s_State_00019fa8,(longlong)puVar3);
  if ((*(byte *)(param_1 + 0x1b9) & 0x10) == 0) {
    pcVar6 = &DAT_00019d2c;
  }
  else {
    pcVar6 = FUN_00000b8c(*(int *)(param_1 + 0x164));
  }
  puVar3 = FUN_0001880c(pcVar6);
  FUN_00018744((longlong)puVar2,s_Health_00019fb0,(longlong)puVar3);
  if ((*(byte *)(param_1 + 0x1b9) & 0x20) == 0) {
    pcVar6 = &DAT_00019d2c;
  }
  else {
    pcVar6 = FUN_00000b8c(*(int *)(param_1 + 0x168));
  }
  puVar3 = FUN_0001880c(pcVar6);
  FUN_00018744((longlong)puVar2,s_HealthRollup_00019fb8,(longlong)puVar3);
  if ((*(byte *)(param_1 + 0x1b9) & 4) != 0) {
    pcVar6 = FUN_00000a70(*(int *)(param_1 + 0x170));
    puVar2 = FUN_0001880c(pcVar6);
    FUN_00018744(param_2,s_ChassisType_0001a0b8,(longlong)puVar2);
  }
  if (0x7f < *(byte *)(param_1 + 0x1b9)) {
    lVar4 = FUN_000187d8(*(undefined8 *)(param_1 + 0x178));
    FUN_00018744(param_2,s_DepthMm_0001a0c8,lVar4);
  }
  if ((*(byte *)(param_1 + 0x1ba) & 1) != 0) {
    lVar4 = FUN_000187d8(*(undefined8 *)(param_1 + 0x180));
    FUN_00018744(param_2,s_HeightMm_0001a0d0,lVar4);
  }
  if ((*(byte *)(param_1 + 0x1ba) & 2) != 0) {
    lVar4 = FUN_000187d8(*(undefined8 *)(param_1 + 0x188));
    FUN_00018744(param_2,s_WeightKg_0001a0e0,lVar4);
  }
  if ((*(byte *)(param_1 + 0x1ba) & 4) != 0) {
    lVar4 = FUN_000187d8(*(undefined8 *)(param_1 + 400));
    FUN_00018744(param_2,s_WidthMm_0001a0f0,lVar4);
  }
  if ((*(byte *)(param_1 + 0x1ba) & 8) == 0) goto LAB_00001e23;
  iVar1 = *(int *)(param_1 + 0x198);
  if (iVar1 == 0) {
LAB_00001e05:
    pcVar6 = &DAT_00019a44;
  }
  else if (iVar1 == 1) {
    pcVar6 = &DAT_00019a48;
  }
  else if (iVar1 == 2) {
    pcVar6 = &DAT_00019a4c;
  }
  else {
    if (iVar1 != 3) goto LAB_00001e05;
    pcVar6 = &DAT_00019a50;
  }
  puVar2 = FUN_0001880c(pcVar6);
  FUN_00018744(param_2,s_EnvironmentalClass_0001a0f8,(longlong)puVar2);
LAB_00001e23:
  if ((*(byte *)(param_1 + 0x1ba) & 0x10) != 0) {
    iVar1 = *(int *)(param_1 + 0x19c);
    if (iVar1 == 0) {
      pcVar7 = &DAT_00019a64;
    }
    else if (iVar1 == 1) {
      pcVar7 = s_Blinking_00019a58;
    }
    else if (iVar1 != 2) {
      pcVar7 = s_Unknown_00019a70;
    }
    puVar2 = FUN_0001880c(pcVar7);
    FUN_00018744(param_2,s_IndicatorLED_00019f98,(longlong)puVar2);
  }
  uVar5 = FUN_00001700((int *)(param_1 + 0x1a0),param_2);
  return uVar5;
}

