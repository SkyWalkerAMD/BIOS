
ulonglong FUN_000102c0(byte *param_1,longlong *param_2,longlong *param_3,longlong param_4)

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  undefined1 *puVar4;
  ulonglong uVar5;
  longlong lVar6;
  char *pcVar7;
  longlong lVar8;
  longlong lVar9;
  
  lVar8 = 0;
  lVar9 = 0;
  if (param_4 == 0) {
    return 0x8000000000000002;
  }
  if (*(longlong *)(param_1 + 0x120) == 0) {
    return 0;
  }
  if ((param_1[0x122] & 0x40) == 0) {
    return 0x8000000000000002;
  }
  if (-1 < (char)param_1[0x122]) {
    return 0x8000000000000002;
  }
  puVar4 = FUN_0001880c(*(char **)(param_1 + 0x3b0));
  FUN_00018744(param_4,&DAT_0001a078,(longlong)puVar4);
  puVar4 = FUN_0001880c(*(char **)(param_1 + 0x3b8));
  FUN_00018744(param_4,&DAT_00019eb4,(longlong)puVar4);
  if ((param_1[0x123] & 1) != 0) {
    puVar4 = FUN_0001880c(*(char **)(param_1 + 0x3c0));
    FUN_00018744(param_4,s_Description_00019f20,(longlong)puVar4);
  }
  if ((param_1[0x120] & 0x80) != 0) {
    bVar1 = param_1[7];
    if (bVar1 == 3) {
LAB_000103ca:
      pcVar7 = &DAT_0001c734;
    }
    else if (bVar1 == 4) {
      pcVar7 = s_NVDIMM_N_0001c740;
    }
    else if (bVar1 == 5) {
      pcVar7 = s_NVDIMM_F_0001c750;
    }
    else if (bVar1 == 6) {
      pcVar7 = s_NVDIMM_P_0001c760;
    }
    else {
      if (bVar1 != 7) goto LAB_000103ca;
      pcVar7 = s_IntelOptane_0001c770;
    }
    puVar4 = FUN_0001880c(pcVar7);
    FUN_00018744(param_4,s_MemoryType_0001be88,(longlong)puVar4);
  }
  if ((param_1[0x120] & 0x20) != 0) {
    bVar1 = param_1[5];
    if (bVar1 < 0x19) {
      if (bVar1 == 0x18) {
        pcVar7 = &DAT_0001bac8;
      }
      else if (bVar1 == 8) {
        pcVar7 = &DAT_0001c6a8;
      }
      else if (bVar1 == 0xf) {
        pcVar7 = s_SDRAM_0001bb70;
      }
      else if (bVar1 == 0x12) {
        pcVar7 = &DAT_0001babc;
      }
      else if (bVar1 == 0x13) {
        pcVar7 = &DAT_0001bac0;
      }
      else {
        if (bVar1 != 0x14) goto LAB_00010468;
        pcVar7 = s_DDR2_SDRAM_FB_DIMM_0001c6b0;
      }
    }
    else if (bVar1 == 0x1a) {
      pcVar7 = &DAT_0001bad0;
    }
    else if (bVar1 == 0x1d) {
      pcVar7 = s_LPDDR3_SDRAM_0001c6c8;
    }
    else if (bVar1 == 0x1e) {
      pcVar7 = s_LPDDR4_SDRAM_0001c6d8;
    }
    else if (bVar1 == 0x22) {
      pcVar7 = &DAT_0001bad8;
    }
    else if (bVar1 == 0x23) {
      pcVar7 = s_LPDDR5_SDRAM_0001c6e8;
    }
    else {
LAB_00010468:
      pcVar7 = &DAT_0001c6f8;
    }
    puVar4 = FUN_0001880c(pcVar7);
    FUN_00018744(param_4,s_MemoryDeviceType_0001cab8,(longlong)puVar4);
  }
  if ((param_1[0x124] & 0x80) != 0) {
    uVar2 = *(ushort *)(param_1 + 0x90);
    if ((uVar2 & 0x2000) == 0) {
      if ((uVar2 & 0x4000) == 0) {
        pcVar7 = s_LRDIMM_0001c78c;
        if ((uVar2 & 0x8000) == 0) {
          pcVar7 = s_RDIMM_0001c77c;
        }
      }
      else {
        pcVar7 = s_UDIMM_0001c784;
      }
    }
    else {
      pcVar7 = s_RDIMM_0001c77c;
    }
    puVar4 = FUN_0001880c(pcVar7);
    FUN_00018744(param_4,s_BaseModuleType_0001cad0,(longlong)puVar4);
  }
  uVar5 = FUN_0000f65c((longlong)(param_1 + 0x98),param_4,(ulonglong)param_1[0x97]);
  if ((longlong)uVar5 < 0) {
    return uVar5;
  }
  if ((param_1[0x121] & 0x40) != 0) {
    puVar4 = FUN_0001880c(*(char **)(param_1 + 0x370));
    FUN_00018744(param_4,s_FirmwareRevision_0001caf0,(longlong)puVar4);
  }
  if ((param_1[0x121] & 4) != 0) {
    puVar4 = FUN_0001880c(*(char **)(param_1 + 0x360));
    FUN_00018744(param_4,s_FirmwareApiVersion_0001cb08,(longlong)puVar4);
  }
  if ((param_1[0x121] & 0x20) != 0) {
    puVar4 = FUN_0001880c(*(char **)(param_1 + 0x368));
    FUN_00018744(param_4,s_ModuleManufacturerID_0001cb20,(longlong)puVar4);
  }
  if ((param_1[0x121] & 0x80) != 0) {
    puVar4 = FUN_0001880c(*(char **)(param_1 + 0x378));
    FUN_00018744(param_4,s_ModuleProductID_0001cb38,(longlong)puVar4);
  }
  if ((param_1[0x122] & 1) != 0) {
    puVar4 = FUN_0001880c(*(char **)(param_1 + 0x380));
    FUN_00018744(param_4,s_MemorySubsystemControllerManufac_0001cb48,(longlong)puVar4);
  }
  if ((param_1[0x122] & 2) != 0) {
    puVar4 = FUN_0001880c(*(char **)(param_1 + 0x388));
    FUN_00018744(param_4,s_MemorySubsystemControllerProduct_0001cb70,(longlong)puVar4);
  }
  uVar5 = FUN_0000359c((longlong)(param_1 + 0x16),(ulonglong)param_1[0x14],param_4,
                       s_MaxTDPMilliWatts_0001ca60);
  if ((longlong)uVar5 < 0) {
    return uVar5;
  }
  uVar5 = FUN_0000ff74((longlong)param_1,param_4);
  if ((longlong)uVar5 < 0) {
    return uVar5;
  }
  if ((param_1[0x120] & 1) != 0) {
    lVar6 = FUN_000187b4((uint)*param_1);
    FUN_00018744(param_4,s_ConfigurationLocked_0001cb98,lVar6);
  }
  if ((param_1[0x120] & 2) != 0) {
    lVar6 = FUN_000187b4((uint)param_1[1]);
    FUN_00018744(param_4,s_IsRankSpareEnabled_0001cbb0,lVar6);
  }
  if ((param_1[0x120] & 4) != 0) {
    lVar6 = FUN_000187b4((uint)param_1[2]);
    FUN_00018744(param_4,s_IsSpareDeviceEnabled_0001cbc8,lVar6);
  }
  if ((param_1[0x120] & 0x40) != 0) {
    lVar6 = FUN_000187d8((ulonglong)param_1[6]);
    FUN_00018744(param_4,s_RankCount_0001cbe0,lVar6);
  }
  uVar5 = FUN_000100a8((longlong)param_1,param_4);
  if ((longlong)uVar5 < 0) {
    return uVar5;
  }
  if ((param_1[0x123] & 0x80) != 0) {
    lVar8 = *(longlong *)(param_1 + 0x40);
    lVar6 = FUN_000187d8(lVar8);
    FUN_00018744(param_4,s_VolatileSizeMiB_0001cbf0,lVar6);
  }
  if ((param_1[0x124] & 1) != 0) {
    lVar9 = *(longlong *)(param_1 + 0x48);
    lVar6 = FUN_000187d8(lVar9);
    FUN_00018744(param_4,s_NonVolatileSizeMiB_0001cc00,lVar6);
  }
  if ((param_1[0x123] & 8) != 0) {
    lVar6 = FUN_000187d8(*(undefined8 *)(param_1 + 0x88));
    FUN_00018744(param_4,s_LogicalSizeMiB_0001cc18,lVar6);
  }
  if ((param_1[0x123] & 2) != 0) {
    lVar6 = FUN_000187d8(*(undefined8 *)(param_1 + 0x80));
    FUN_00018744(param_4,s_CacheSizeMiB_0001cc28,lVar6);
  }
  if ((param_1[0x124] & 0x40) != 0) {
    lVar6 = FUN_000187d8(*(undefined8 *)(param_1 + 0x78));
    FUN_00018744(param_4,s_VolatileRegionSizeLimitMiB_0001cc38,lVar6);
  }
  if ((param_1[0x124] & 0x20) != 0) {
    lVar6 = FUN_000187d8(*(undefined8 *)(param_1 + 0x70));
    FUN_00018744(param_4,s_PersistentRegionSizeLimitMiB_0001cc58,lVar6);
  }
  uVar5 = FUN_0000f778((longlong)(param_1 + 0xb0),param_4,(ulonglong)param_1[0xac]);
  if ((longlong)uVar5 < 0) {
    return uVar5;
  }
  uVar5 = FUN_000101b4((longlong)param_1,param_4);
  if ((longlong)uVar5 < 0) {
    return uVar5;
  }
  if ((param_1[0x124] & 4) != 0) {
    lVar6 = FUN_000187d8(*(undefined8 *)(param_1 + 0x58));
    FUN_00018744(param_4,s_VolatileRegionNumberLimit_0001cc90,lVar6);
  }
  if ((param_1[0x124] & 2) != 0) {
    lVar6 = FUN_000187d8(*(undefined8 *)(param_1 + 0x50));
    FUN_00018744(param_4,s_PersistentRegionNumberLimit_0001ccb0,lVar6);
  }
  if ((param_1[0x124] & 8) != 0) {
    lVar6 = FUN_000187d8(*(undefined8 *)(param_1 + 0x60));
    FUN_00018744(param_4,s_VolatileRegionSizeMaxMiB_0001ccd0,lVar6);
  }
  if ((param_1[0x124] & 0x10) != 0) {
    lVar6 = FUN_000187d8(*(undefined8 *)(param_1 + 0x68));
    FUN_00018744(param_4,s_PersistentRegionSizeMaxMiB_0001ccf0,lVar6);
  }
  if ((param_1[0x123] & 0x20) != 0) {
    lVar6 = FUN_000187d8(*(undefined8 *)(param_1 + 0x30));
    FUN_00018744(param_4,s_AllocationIncrementMiB_0001cd10,lVar6);
  }
  if ((param_1[0x123] & 0x10) != 0) {
    lVar6 = FUN_000187d8(*(undefined8 *)(param_1 + 0x28));
    FUN_00018744(param_4,s_AllocationAlignmentMiB_0001cd28,lVar6);
  }
  if ((param_1[0x123] & 4) != 0) {
    lVar6 = FUN_000187d8((ulonglong)*(uint *)(param_1 + 0x24));
    FUN_00018744(param_4,s_CapacityMiB_0001be98,lVar6);
  }
  if ((param_1[0x121] & 2) != 0) {
    lVar6 = FUN_000187d8((ulonglong)*(ushort *)(param_1 + 0x12));
    FUN_00018744(param_4,s_DataWidthBits_0001cd40,lVar6);
  }
  if ((param_1[0x121] & 1) != 0) {
    lVar6 = FUN_000187d8((ulonglong)*(ushort *)(param_1 + 0x10));
    FUN_00018744(param_4,s_BusWidthBits_0001cd50,lVar6);
  }
  if ((param_1[0x122] & 0x10) != 0) {
    puVar4 = FUN_0001880c(*(char **)(param_1 + 0x3a0));
    FUN_00018744(param_4,s_Manufacturer_00019f30,(longlong)puVar4);
  }
  if ((param_1[0x122] & 0x20) != 0) {
    puVar4 = FUN_0001880c(*(char **)(param_1 + 0x3a8));
    FUN_00018744(param_4,s_SerialNumber_00019f68,(longlong)puVar4);
  }
  if ((param_1[0x122] & 8) != 0) {
    puVar4 = FUN_0001880c(*(char **)(param_1 + 0x398));
    FUN_00018744(param_4,s_PartNumber_00019f58,(longlong)puVar4);
  }
  uVar5 = FUN_0000359c((longlong)(param_1 + 10),(ulonglong)param_1[8],param_4,
                       s_AllowedSpeedsMHz_0001cd60);
  if ((longlong)uVar5 < 0) {
    return uVar5;
  }
  if ((param_1[0x123] & 0x40) != 0) {
    lVar6 = FUN_000187d8(*(undefined8 *)(param_1 + 0x38));
    FUN_00018744(param_4,s_SpareDeviceCount_0001cd78,lVar6);
  }
  uVar5 = FUN_00003dc4(param_1[0x125] >> 2 & 1,param_1[0x125] & 1,(int *)(param_1 + 0x108),param_4);
  if ((longlong)uVar5 < 0) {
    return uVar5;
  }
  if ((param_1[0x122] & 4) != 0) {
    puVar4 = FUN_0001880c(*(char **)(param_1 + 0x390));
    FUN_00018744(param_4,s_DeviceLocator_0001cd90,(longlong)puVar4);
  }
  if ((param_1[0x121] & 0x10) != 0) {
    lVar6 = FUN_000187d8((ulonglong)*(ushort *)(param_1 + 0x22));
    FUN_00018744(param_4,s_OperatingSpeedMhz_0001cda0,lVar6);
  }
  if ((param_1[0x120] & 0x10) != 0) {
    if ((byte)(param_1[4] - 1) < 7) {
      pcVar7 = (&PTR_s_NoECC_0001cf10)[param_1[4]];
    }
    else {
      pcVar7 = s_NoECC_0001c6fc;
    }
    puVar4 = FUN_0001880c(pcVar7);
    FUN_00018744(param_4,s_ErrorCorrection_0001cdb8,(longlong)puVar4);
  }
  uVar5 = FUN_0000fd68((longlong)param_1,param_4);
  if ((longlong)uVar5 < 0) {
    return uVar5;
  }
  if ((param_1[0x125] & 8) == 0) goto LAB_00010b4d;
  iVar3 = *(int *)(param_1 + 0x114);
  if (iVar3 == 0) {
LAB_00010b2f:
    pcVar7 = s_Enabled_00019ca8;
  }
  else if (iVar3 == 1) {
    pcVar7 = s_Disabled_00019c98;
  }
  else if (iVar3 == 2) {
    pcVar7 = s_Locked_0001ab30;
  }
  else {
    if (iVar3 != 3) goto LAB_00010b2f;
    pcVar7 = s_Passphraselimit_0001c7c0;
  }
  puVar4 = FUN_0001880c(pcVar7);
  FUN_00018744(param_4,s_SecurityState_0001cdc8,(longlong)puVar4);
LAB_00010b4d:
  if (param_2 != (longlong *)0x0) {
    *param_2 = *param_2 + lVar8;
  }
  if (param_3 != (longlong *)0x0) {
    *param_3 = *param_3 + lVar9;
    return uVar5;
  }
  return uVar5;
}

