
undefined4 ActiveHostSPIDriver(int param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  FILE *__stream;
  int iVar3;
  char *pcVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  char local_a4 [12];
  undefined4 local_98;
  undefined4 uStack_94;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined4 local_88;
  undefined4 uStack_84;
  undefined4 uStack_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  
  memset(&local_98,0,0x80);
  local_a4[0] = '\0';
  local_a4[1] = '\0';
  local_a4[2] = '\0';
  local_a4[3] = '\0';
  local_a4[4] = '\0';
  local_a4[5] = '\0';
  local_a4[6] = '\0';
  local_a4[7] = '\0';
  local_a4[8] = 0;
  IDBG_LINUXAPP_DbgOut(0x82,DAT_000131bc,DAT_000131b8,0xdc,param_1);
  puVar2 = DAT_000131c4;
  puVar1 = DAT_000131c0;
  if (param_1 != 0) {
    local_98 = *DAT_000131c0;
    uStack_94 = DAT_000131c0[1];
    uStack_90 = DAT_000131c0[2];
    uStack_8c = DAT_000131c0[3];
    local_88 = DAT_000131c0[4];
    uStack_84 = DAT_000131c0[5];
    uStack_80 = DAT_000131c0[6];
    local_7c = CONCAT22(local_7c._2_2_,(short)DAT_000131c0[7]);
    safe_system(&local_98);
    SwitchGPIO(1);
    ClearASUSBiosHeader();
    return 0;
  }
  local_98 = *DAT_000131c0;
  uStack_94 = DAT_000131c0[1];
  uStack_90 = DAT_000131c0[2];
  uStack_8c = DAT_000131c0[3];
  puVar7 = DAT_000131c0 + 4;
  local_88 = *puVar7;
  uStack_84 = DAT_000131c0[5];
  uStack_80 = DAT_000131c0[6];
  local_7c = CONCAT22(local_7c._2_2_,(short)DAT_000131c0[7]);
  safe_system(&local_98);
  sleep(2);
  SwitchGPIO(0);
  sleep(1);
  safe_system(DAT_000131c8);
  local_98 = *puVar2;
  uStack_94 = puVar2[1];
  uStack_90 = puVar2[2];
  uStack_8c = puVar2[3];
  local_88 = puVar2[4];
  uStack_84 = puVar2[5];
  uStack_80 = puVar2[6];
  local_7c = puVar2[7];
  local_78 = puVar2[8];
  uStack_74 = puVar2[9];
  uStack_70 = puVar2[10];
  uStack_6c = puVar2[0xb];
  local_68 = puVar2[0xc];
  uStack_64 = puVar2[0xd];
  uStack_60 = puVar2[0xe];
  safe_system(&local_98);
  sleep(2);
  __stream = fopen(DAT_000131d0,DAT_000131cc);
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000131e8);
  }
  else {
    fread(local_a4,1,9,__stream);
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000131d4,local_a4);
    iVar3 = strncmp(local_a4,DAT_000131d8,8);
    if (iVar3 != 0) {
      iVar3 = 1;
      goto LAB_00012fdc;
    }
    fclose(__stream);
    safe_system(DAT_000131c8);
  }
  local_98 = *puVar1;
  uStack_94 = puVar1[1];
  uStack_90 = puVar1[2];
  uStack_8c = puVar1[3];
  local_88 = *puVar7;
  uStack_84 = puVar1[5];
  uStack_80 = puVar1[6];
  local_7c = CONCAT22(local_7c._2_2_,(short)puVar1[7]);
  safe_system(&local_98);
  sleep(2);
  SwitchGPIO(2);
  local_98 = *puVar2;
  uStack_94 = puVar2[1];
  uStack_90 = puVar2[2];
  uStack_8c = puVar2[3];
  local_88 = puVar2[4];
  uStack_84 = puVar2[5];
  uStack_80 = puVar2[6];
  local_7c = puVar2[7];
  local_78 = puVar2[8];
  uStack_74 = puVar2[9];
  uStack_70 = puVar2[10];
  uStack_6c = puVar2[0xb];
  local_68 = puVar2[0xc];
  uStack_64 = puVar2[0xd];
  uStack_60 = puVar2[0xe];
  safe_system(&local_98);
  sleep(2);
  __stream = fopen(DAT_000131d0,DAT_000131cc);
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000131f0);
    return 0;
  }
  fread(local_a4,1,9,__stream);
  IDBG_LINUXAPP_DbgOut(0x86,DAT_000131ec,local_a4);
  iVar3 = 2;
LAB_00012fdc:
  iVar5 = DAT_000131dc;
  fclose(__stream);
  iVar6 = iVar5 + 0x48;
  do {
    pcVar4 = strstr(local_a4,*(char **)(iVar5 + 4));
    if (pcVar4 != (char *)0x0) {
      iVar5 = FUN_00014330(*(undefined4 *)(iVar5 + 8),DAT_000131e0);
      if (iVar5 == 0 || iVar3 == 2) {
        return 0;
      }
      local_98 = *DAT_000131c0;
      uStack_94 = DAT_000131c0[1];
      uStack_90 = DAT_000131c0[2];
      uStack_8c = DAT_000131c0[3];
      local_88 = DAT_000131c0[4];
      uStack_84 = DAT_000131c0[5];
      uStack_80 = DAT_000131c0[6];
      local_7c = CONCAT22(local_7c._2_2_,(short)DAT_000131c0[7]);
      safe_system(&local_98);
      sleep(2);
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000131e4);
      SwitchGPIO(2);
      local_98 = *DAT_000131c4;
      uStack_94 = DAT_000131c4[1];
      uStack_90 = DAT_000131c4[2];
      uStack_8c = DAT_000131c4[3];
      local_88 = DAT_000131c4[4];
      uStack_84 = DAT_000131c4[5];
      uStack_80 = DAT_000131c4[6];
      local_7c = DAT_000131c4[7];
      local_78 = DAT_000131c4[8];
      uStack_74 = DAT_000131c4[9];
      uStack_70 = DAT_000131c4[10];
      uStack_6c = DAT_000131c4[0xb];
      local_68 = DAT_000131c4[0xc];
      uStack_64 = DAT_000131c4[0xd];
      uStack_60 = DAT_000131c4[0xe];
      safe_system(&local_98);
      sleep(2);
      return 0;
    }
    iVar5 = iVar5 + 0xc;
  } while (iVar6 != iVar5);
  return 0;
}

