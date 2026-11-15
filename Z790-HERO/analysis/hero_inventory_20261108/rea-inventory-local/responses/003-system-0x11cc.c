
undefined8 FUN_000011cc(longlong param_1,longlong param_2)

{
  int iVar1;
  longlong *plVar2;
  undefined1 *puVar3;
  undefined1 *puVar4;
  longlong lVar5;
  undefined8 *puVar6;
  char *pcVar7;
  longlong *plVar8;
  int *piVar9;
  char *pcVar10;
  ulonglong uVar11;
  longlong local_res8;
  char local_48 [48];
  
  if ((*(byte *)(param_1 + 0xc0) & 2) != 0) {
    puVar3 = FUN_0001880c(*(char **)(param_1 + 0xf8));
    FUN_00018744(param_2,s_AssetTag_00019f10,(longlong)puVar3);
  }
  if ((*(byte *)(param_1 + 0xc0) & 8) != 0) {
    puVar3 = FUN_0001880c(*(char **)(param_1 + 0x108));
    FUN_00018744(param_2,s_Description_00019f20,(longlong)puVar3);
  }
  if ((*(byte *)(param_1 + 0xc0) & 0x10) != 0) {
    puVar3 = FUN_0001880c(*(char **)(param_1 + 0x110));
    FUN_00018744(param_2,s_Manufacturer_00019f30,(longlong)puVar3);
  }
  if ((*(byte *)(param_1 + 0xc0) & 0x20) != 0) {
    puVar3 = FUN_0001880c(*(char **)(param_1 + 0x118));
    FUN_00018744(param_2,s_Model_00019f40,(longlong)puVar3);
  }
  if ((*(byte *)(param_1 + 0xc0) & 0x40) != 0) {
    puVar3 = FUN_0001880c(*(char **)(param_1 + 0x120));
    FUN_00018744(param_2,s_SubModel_00019f48,(longlong)puVar3);
  }
  if (0x7f < *(byte *)(param_1 + 0xc0)) {
    puVar3 = FUN_0001880c(*(char **)(param_1 + 0x128));
    FUN_00018744(param_2,s_PartNumber_00019f58,(longlong)puVar3);
  }
  if ((*(byte *)(param_1 + 0xc1) & 1) != 0) {
    puVar3 = FUN_0001880c(*(char **)(param_1 + 0x130));
    FUN_00018744(param_2,s_SerialNumber_00019f68,(longlong)puVar3);
  }
  if ((*(byte *)(param_1 + 0xc1) & 2) != 0) {
    puVar3 = FUN_0001880c(*(char **)(param_1 + 0x138));
    FUN_00018744(param_2,s_BiosVersion_00019f78,(longlong)puVar3);
  }
  if ((*(byte *)(param_1 + 0xc1) & 4) != 0) {
    puVar3 = FUN_0001880c(*(char **)(param_1 + 0x140));
    FUN_00018744(param_2,&DAT_00019f84,(longlong)puVar3);
  }
  if ((*(byte *)(param_1 + 0xc1) & 0x10) != 0) {
    FUN_00015c2c(local_48,0x25,&DAT_00019f88,param_1 + 0x50);
    puVar3 = FUN_0001880c(local_48);
    FUN_00018744(param_2,&DAT_00019f8c,(longlong)puVar3);
  }
  pcVar10 = &DAT_00019a68;
  if ((*(byte *)(param_1 + 0xc2) & 1) != 0) {
    iVar1 = *(int *)(param_1 + 0x60);
    if (iVar1 == 0) {
      pcVar7 = &DAT_00019a64;
    }
    else if (iVar1 == 1) {
      pcVar7 = s_Blinking_00019a58;
    }
    else if (iVar1 == 2) {
      pcVar7 = &DAT_00019a68;
    }
    else {
      pcVar7 = s_Unknown_00019a70;
    }
    puVar3 = FUN_0001880c(pcVar7);
    FUN_00018744(param_2,s_IndicatorLED_00019f98,(longlong)puVar3);
  }
  puVar3 = FUN_00016b80();
  if (puVar3 != (undefined1 *)0x0) {
    *(undefined4 *)(puVar3 + 0x18) = 6;
    if (*(byte *)(param_1 + 0xc1) < 0x80) {
      pcVar7 = s_Enabled_00019ca8;
    }
    else {
      pcVar7 = FUN_00000b8c(*(int *)(param_1 + 0x6c));
    }
    puVar4 = FUN_0001880c(pcVar7);
    FUN_00018744((longlong)puVar3,s_State_00019fa8,(longlong)puVar4);
    if ((*(byte *)(param_1 + 0xc1) & 0x20) == 0) {
      pcVar7 = &DAT_00019d2c;
    }
    else {
      pcVar7 = FUN_00000b8c(*(int *)(param_1 + 100));
    }
    puVar4 = FUN_0001880c(pcVar7);
    FUN_00018744((longlong)puVar3,s_Health_00019fb0,(longlong)puVar4);
    if ((*(byte *)(param_1 + 0xc1) & 0x40) == 0) {
      pcVar7 = &DAT_00019d2c;
    }
    else {
      pcVar7 = FUN_00000b8c(*(int *)(param_1 + 0x68));
    }
    puVar4 = FUN_0001880c(pcVar7);
    FUN_00018744((longlong)puVar3,s_HealthRollup_00019fb8,(longlong)puVar4);
    FUN_00018744(param_2,s_Status_00019fc8,(longlong)puVar3);
  }
  if ((*(byte *)(param_1 + 0xc2) & 2) != 0) {
    if (*(int *)(param_1 + 0x70) == 0) {
      pcVar7 = s_AlwaysOff_00019a78;
    }
    else if (*(int *)(param_1 + 0x70) == 1) {
      pcVar7 = s_AlwaysOn_00019a88;
    }
    else {
      pcVar7 = s_LastState_00019a98;
    }
    puVar3 = FUN_0001880c(pcVar7);
    FUN_00018744(param_2,s_PowerRestorePolicy_00019fd0,(longlong)puVar3);
  }
  if ((*(byte *)(param_1 + 0xc2) & 4) != 0) {
    iVar1 = *(int *)(param_1 + 0x74);
    if (iVar1 != 0) {
      if (iVar1 == 1) {
LAB_00001519:
        pcVar10 = &DAT_00019aa4;
      }
      else if (iVar1 == 2) {
        pcVar10 = s_PoweringOff_00019aa8;
      }
      else {
        if (iVar1 != 3) goto LAB_00001519;
        pcVar10 = s_PoweringOn_00019ab8;
      }
    }
    puVar3 = FUN_0001880c(pcVar10);
    FUN_00018744(param_2,s_PowerState_00019fe8,(longlong)puVar3);
  }
  if ((*(byte *)(param_1 + 0xc2) & 8) == 0) goto LAB_000015ae;
  iVar1 = *(int *)(param_1 + 0x78);
  if (iVar1 == 0) {
    pcVar10 = s_Composed_00019ac8;
  }
  else if (iVar1 == 1) {
    pcVar10 = s_TypeOS_00019ad4;
  }
  else if (iVar1 == 2) {
LAB_0000157e:
    pcVar10 = s_Physical_00019ae0;
  }
  else if (iVar1 == 3) {
    pcVar10 = s_Partitioned_00019af0;
  }
  else if (iVar1 == 4) {
    pcVar10 = s_Virtual_00019b00;
  }
  else {
    if (iVar1 != 5) goto LAB_0000157e;
    pcVar10 = s_VirtuallyPartitioned_00019b08;
  }
  puVar3 = FUN_0001880c(pcVar10);
  FUN_00018744(param_2,s_SystemType_00019ff8,(longlong)puVar3);
LAB_000015ae:
  if ((*(byte *)(param_1 + 0xc1) & 8) != 0) {
    puVar3 = FUN_0001880c(*(char **)(param_1 + 0x148));
    FUN_00018744(param_2,s_HostName_0001a008,(longlong)puVar3);
  }
  uVar11 = (ulonglong)*(uint *)(param_1 + 0x7c);
  if (uVar11 != 0) {
    puVar3 = FUN_00016b80();
    if (puVar3 == (undefined1 *)0x0) {
      return 0x8000000000000009;
    }
    *(undefined4 *)(puVar3 + 0x18) = 5;
    FUN_00018744(param_2,s_HostingRoles_00019f00,(longlong)puVar3);
    if (uVar11 != 0) {
      piVar9 = (int *)(param_1 + 0x80);
      do {
        iVar1 = *piVar9;
        if (iVar1 == 0) {
LAB_00001637:
          pcVar10 = s_ApplicationServer_000199c8;
        }
        else if (iVar1 == 1) {
          pcVar10 = s_StorageServer_000199e0;
        }
        else {
          if (iVar1 != 2) goto LAB_00001637;
          pcVar10 = s_Switch_000199f0;
        }
        puVar4 = FUN_0001880c(pcVar10);
        if (puVar4 != (undefined1 *)0x0) {
          plVar2 = *(longlong **)(puVar3 + 0x10);
          if (*(longlong **)(puVar3 + 0x10) == (longlong *)0x0) {
            *(undefined1 **)(puVar3 + 0x10) = puVar4;
          }
          else {
            do {
              plVar8 = plVar2;
              plVar2 = (longlong *)*plVar8;
            } while ((longlong *)*plVar8 != (longlong *)0x0);
            *plVar8 = (longlong)puVar4;
            *(longlong **)(puVar4 + 8) = plVar8;
          }
        }
        piVar9 = piVar9 + 1;
        uVar11 = uVar11 - 1;
      } while (uVar11 != 0);
    }
  }
  lVar5 = (**(code **)(DAT_0001e070 + 0x140))(&DAT_000198a0,0,&local_res8);
  if ((-1 < lVar5) && (puVar6 = (undefined8 *)FUN_00016b80(), puVar6 != (undefined8 *)0x0)) {
    *(undefined4 *)(puVar6 + 3) = 5;
    lVar5 = (**(code **)(local_res8 + 8))(local_res8,puVar6);
    if (lVar5 < 0) {
      FUN_00016bcc(puVar6);
    }
    else {
      FUN_00018744(param_2,s_TrustedModules_00019e88,(longlong)puVar6);
    }
  }
  return 0;
}

