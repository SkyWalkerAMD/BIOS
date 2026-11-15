
longlong FUN_0000e374(longlong param_1,longlong param_2,uint param_3)

{
  undefined1 *puVar1;
  longlong lVar2;
  char *pcVar3;
  char local_48 [64];
  
  if ((param_2 == 0) || (param_1 == 0)) {
    return -0x7ffffffffffffffe;
  }
  if (*(short *)(param_2 + 0x74) == 0) {
    return 0;
  }
  if ((*(byte *)(param_2 + 0x74) & 6) != 6) {
    return -0x7ffffffffffffffe;
  }
  puVar1 = FUN_0001880c(*(char **)(param_2 + 0x170));
  FUN_00018744(param_1,&DAT_0001a078,(longlong)puVar1);
  puVar1 = FUN_0001880c(*(char **)(param_2 + 0x178));
  FUN_00018744(param_1,&DAT_00019eb4,(longlong)puVar1);
  if ((*(byte *)(param_2 + 0x74) & 0x40) == 0) {
    if ((*(byte *)(param_2 + 0x3a) & 0x60) == 0x60) {
      FUN_00015c2c(local_48,0x32,(byte *)s__02x_02x_0001c4f8,(ulonglong)*(ushort *)(param_2 + 0x30))
      ;
      pcVar3 = local_48;
      goto LAB_0000e441;
    }
  }
  else {
    pcVar3 = *(char **)(param_2 + 0x198);
LAB_0000e441:
    puVar1 = FUN_0001880c(pcVar3);
    FUN_00018744(param_1,s_Manufacturer_00019f30,(longlong)puVar1);
  }
  if ((*(byte *)(param_2 + 0x74) & 8) == 0) {
    if (*(char *)(param_2 + 9) == -1) {
      FUN_00015c2c(local_48,0x32,(byte *)s__04x__a_Onboard_0001c440,
                   (ulonglong)*(ushort *)(param_2 + 0x30));
    }
    else {
      FUN_00015c2c(local_48,0x32,(byte *)s__04x__a_Slot__d_0001c430,
                   (ulonglong)*(ushort *)(param_2 + 0x30));
    }
    pcVar3 = local_48;
  }
  else {
    pcVar3 = *(char **)(param_2 + 0x180);
  }
  puVar1 = FUN_0001880c(pcVar3);
  FUN_00018744(param_1,s_Description_00019f20,(longlong)puVar1);
  if ((*(byte *)(param_2 + 0x74) & 0x10) != 0) {
    puVar1 = FUN_0001880c(*(char **)(param_2 + 0x188));
    FUN_00018744(param_1,s_AssetTag_00019f10,(longlong)puVar1);
  }
  if ((*(byte *)(param_2 + 0x74) & 0x20) != 0) {
    puVar1 = FUN_0001880c(*(char **)(param_2 + 400));
    FUN_00018744(param_1,s_Model_00019f40,(longlong)puVar1);
  }
  if (0x7f < *(byte *)(param_2 + 0x74)) {
    puVar1 = FUN_0001880c(*(char **)(param_2 + 0x1a0));
    FUN_00018744(param_1,s_PartNumber_00019f58,(longlong)puVar1);
  }
  if ((*(byte *)(param_2 + 0x75) & 1) != 0) {
    puVar1 = FUN_0001880c(*(char **)(param_2 + 0x1a8));
    FUN_00018744(param_1,s_SerialNumber_00019f68,(longlong)puVar1);
  }
  if ((*(byte *)(param_2 + 0x75) & 2) != 0) {
    puVar1 = FUN_0001880c(*(char **)(param_2 + 0x1b0));
    FUN_00018744(param_1,&DAT_00019f84,(longlong)puVar1);
  }
  if ((*(byte *)(param_2 + 0x3a) & 2) != 0) {
    puVar1 = FUN_0001880c(*(char **)(param_2 + 0x460));
    FUN_00018744(param_1,s_FirmwareVersion_0001b568,(longlong)puVar1);
  }
  if ((*(byte *)(param_2 + 0x75) & 0x20) == 0) {
    if (param_3 != 1) {
      pcVar3 = s_MultiFunction_0001c3d0;
      if (param_3 < 2) {
        pcVar3 = s_Simulated_0001c3e0;
      }
      goto LAB_0000e635;
    }
  }
  else {
    if (*(int *)(param_2 + 0x5c) == 0) {
      pcVar3 = s_MultiFunction_0001c3d0;
      goto LAB_0000e635;
    }
    if (*(int *)(param_2 + 0x5c) == 1) {
      pcVar3 = s_Simulated_0001c3e0;
      goto LAB_0000e635;
    }
  }
  pcVar3 = s_SingleFunction_0001c3f0;
LAB_0000e635:
  puVar1 = FUN_0001880c(pcVar3);
  FUN_00018744(param_1,s_DeviceType_0001c508,(longlong)puVar1);
  lVar2 = FUN_00003dc4(*(byte *)(param_2 + 0x75) >> 4 & 1,*(byte *)(param_2 + 0x75) >> 2 & 1,
                       (int *)(param_2 + 0x50),param_1);
  if (-1 < lVar2) {
    lVar2 = FUN_00000c5c((uint *)(param_2 + 0x60),param_1,s_PCIeInterface_0001b588);
  }
  return lVar2;
}

