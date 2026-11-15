
longlong FUN_0000ce60(longlong param_1,byte *param_2,longlong *param_3)

{
  undefined1 *puVar1;
  longlong lVar2;
  undefined8 *puVar3;
  longlong *plVar4;
  longlong lVar5;
  int iVar6;
  char *pcVar7;
  
  if ((((param_2 == (byte *)0x0) || (param_1 == 0)) || ((param_2[0xc5] & 0x40) == 0)) ||
     (param_2[0xc5] < 0x80)) {
    return -0x7ffffffffffffffe;
  }
  puVar1 = FUN_0001880c(*(char **)(param_2 + 0x20e8));
  FUN_00018744(param_1,&DAT_0001a078,(longlong)puVar1);
  puVar1 = FUN_0001880c(*(char **)(param_2 + 0x20f0));
  FUN_00018744(param_1,&DAT_00019eb4,(longlong)puVar1);
  if ((param_2[0xc6] & 1) != 0) {
    puVar1 = FUN_0001880c(*(char **)(param_2 + 0x20f8));
    FUN_00018744(param_1,s_Description_00019f20,(longlong)puVar1);
  }
  if ((param_2[0xc5] & 8) != 0) {
    puVar1 = FUN_0001880c(*(char **)(param_2 + 0x20d0));
    FUN_00018744(param_1,s_Socket_0001bfcc,(longlong)puVar1);
  }
  if ((param_2[0xc4] & 0x10) != 0) {
    if ((byte)(param_2[4] - 1) < 6) {
      pcVar7 = (&PTR_DAT_0001c100)[param_2[4]];
    }
    else {
      pcVar7 = &DAT_0001ba41;
    }
    puVar1 = FUN_0001880c(pcVar7);
    FUN_00018744(param_1,s_ProcessorType_0001bfd8,(longlong)puVar1);
  }
  if ((param_2[0xc6] & 2) == 0) {
    if (*param_3 == 0) {
      FUN_0000cdf0(s_Undefined_0001bfe8,param_3);
    }
    pcVar7 = (char *)*param_3;
  }
  else {
    FUN_0000cdf0(*(char **)(param_2 + 0x2100),param_3);
    pcVar7 = *(char **)(param_2 + 0x2100);
  }
  puVar1 = FUN_0001880c(pcVar7);
  FUN_00018744(param_1,s_Model_00019f40,(longlong)puVar1);
  lVar2 = FUN_0000b914((longlong)param_2,param_1);
  if (lVar2 < 0) {
    return lVar2;
  }
  if ((param_2[0xc6] & 8) != 0) {
    iVar6 = *(int *)(param_2 + 0x24);
    if (iVar6 == 0) {
      pcVar7 = &DAT_0001ba50;
    }
    else if (iVar6 == 1) {
      pcVar7 = s_x86_64_0001ba94;
    }
    else if (iVar6 == 2) {
      pcVar7 = &DAT_0001ba70;
    }
    else if (iVar6 == 3) {
      pcVar7 = s_ARM_A32_0001ba60;
    }
    else if (iVar6 == 4) {
      pcVar7 = s_ARM_A64_0001ba68;
    }
    else if (iVar6 == 5) {
      pcVar7 = s_MIPS32_0001ba78;
    }
    else if (iVar6 == 6) {
      pcVar7 = s_MIPS64_0001ba80;
    }
    else if (iVar6 == 7) {
      pcVar7 = s_PowerISA_0001ba88;
    }
    else {
      pcVar7 = &DAT_00019d98;
    }
    puVar1 = FUN_0001880c(pcVar7);
    FUN_00018744(param_1,s_InstructionSet_0001bff8,(longlong)puVar1);
  }
  if ((param_2[0xc5] & 0x10) != 0) {
    puVar1 = FUN_0001880c(*(char **)(param_2 + 0x20d8));
    FUN_00018744(param_1,s_Manufacturer_00019f30,(longlong)puVar1);
  }
  if (0x7f < param_2[0xc4]) {
    lVar2 = FUN_000187d8((ulonglong)*(uint *)(param_2 + 8));
    FUN_00018744(param_1,s_MaxSpeedMHz_0001c008,lVar2);
  }
  if ((param_2[0xc4] & 1) != 0) {
    lVar2 = FUN_000187d8((ulonglong)*param_2);
    FUN_00018744(param_1,s_TotalCores_0001c018,lVar2);
  }
  if ((param_2[0xc4] & 4) != 0) {
    lVar2 = FUN_000187d8((ulonglong)param_2[2]);
    FUN_00018744(param_1,s_TotalThreads_0001c028,lVar2);
  }
  puVar1 = FUN_0001880c(&DAT_0001ba50);
  FUN_00018744(param_1,s_ProcessorArchitecture_0001c038,(longlong)puVar1);
  lVar2 = FUN_00003dc4(param_2[0xc6] >> 6 & 1,param_2[0xc6] >> 4 & 1,(int *)(param_2 + 0xb8),param_1
                      );
  if (lVar2 < 0) {
    return lVar2;
  }
  puVar3 = (undefined8 *)FUN_00016b80();
  if (puVar3 == (undefined8 *)0x0) {
    return -0x7ffffffffffffff7;
  }
  *(undefined4 *)(puVar3 + 3) = 5;
  lVar2 = FUN_0000c294((longlong)param_2,param_1,(longlong)puVar3);
  if (lVar2 < 0) {
    return lVar2;
  }
  plVar4 = (longlong *)puVar3[2];
  iVar6 = 0;
  if (plVar4 != (longlong *)0x0) {
    do {
      plVar4 = (longlong *)*plVar4;
      iVar6 = iVar6 + 1;
    } while (plVar4 != (longlong *)0x0);
    if (0 < iVar6) {
      FUN_00018744(param_1,s_AccelerationFunctions_0001c050,(longlong)puVar3);
      goto LAB_0000d1bc;
    }
  }
  FUN_00016bcc(puVar3);
LAB_0000d1bc:
  if ((param_2[0xc5] & 4) != 0) {
    lVar2 = FUN_000187d8(*(undefined8 *)(param_2 + 0x18));
    FUN_00018744(param_1,s_MaxTDPWatts_0001c068,lVar2);
  }
  lVar2 = FUN_0000c9b8((longlong)(param_2 + 0x38),param_1,(ulonglong)param_2[0x30]);
  if (-1 < lVar2) {
    if ((param_2[0xc5] & 2) != 0) {
      lVar5 = FUN_000187d8(*(undefined8 *)(param_2 + 0x10));
      FUN_00018744(param_1,s_TDPWatts_0001c088,lVar5);
    }
    if ((param_2[0xc5] & 0x20) != 0) {
      puVar1 = FUN_0001880c(*(char **)(param_2 + 0x20e0));
      FUN_00018744(param_1,&DAT_00019f8c,(longlong)puVar1);
    }
    if ((param_2[0xc4] & 2) != 0) {
      lVar5 = FUN_000187d8((ulonglong)param_2[1]);
      FUN_00018744(param_1,s_TotalEnabledCores_0001c098,lVar5);
    }
  }
  return lVar2;
}

